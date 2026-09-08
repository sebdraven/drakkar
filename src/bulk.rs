//! Mode bulk : analyse un répertoire d'APK en parallèle (rayon), un JSON de
//! détections par APK.
//!
//! L'`Engine` (catalogue MITRE) est chargé **une seule fois** par l'appelant et
//! partagé en lecture entre les workers — `Engine::run` prend `&self` et ne mute
//! rien, donc pas de rechargement du STIX par APK. Chaque worker ne construit que
//! son propre `ParsedApk` (features + CFG), thread-local par nature.

use crate::parser;
use crate::rules::Engine;
use anyhow::Result;
use rayon::prelude::*;
use serde::Serialize;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

pub struct BulkOptions {
    /// Répertoire de sortie (créé si absent). La valeur `-` redirige tout sur
    /// stdout et n'écrit aucun fichier.
    pub out_dir: PathBuf,
    /// Parcours récursif des sous-répertoires.
    pub recursive: bool,
    /// Ré-analyse même si le JSON de sortie existe déjà (sans effet en CSV).
    pub overwrite: bool,
    /// Forme de la sortie du lot. Voir [`BulkFormat`].
    pub format: BulkFormat,
}

/// Forme de la sortie d'un lot d'inventaires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulkFormat {
    /// Un fichier JSON par APK dans `out_dir` — contenu identique au mode single.
    /// C'est le seul format qui préserve l'intégralité du rapport (intent-filters,
    /// meta-data, listes de permissions), qu'un tableau à plat ne peut pas porter.
    Json,
    /// Un unique fichier CSV pour tout le lot, une ligne par échantillon.
    /// Vue de synthèse destinée au tri et au regroupement (pandas, tableur).
    Csv,
}

/// Inventaire produit par [`run_inventory`] — ne charge ni DEX ni catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inventory {
    /// Rapport `manifest_info::ManifestReport`, suffixe `.manifest.json`.
    Manifest,
    /// Rapport `cert::SigningReport`, suffixe `.cert.json`.
    Cert,
    /// Rapport `dating::DatingReport`, suffixe `.dating.json`.
    Dating,
}

impl Inventory {
    /// Suffixe du fichier de sortie, après le nom de base de l'APK.
    fn suffix(&self) -> &'static str {
        match self {
            Inventory::Manifest => "manifest.json",
            Inventory::Cert => "cert.json",
            Inventory::Dating => "dating.json",
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Inventory::Manifest => "manifest",
            Inventory::Cert => "signature",
            Inventory::Dating => "datation",
        }
    }

    /// Nom du CSV unique produit en [`BulkFormat::Csv`].
    fn csv_name(&self) -> &'static str {
        match self {
            Inventory::Manifest => "manifests.csv",
            Inventory::Cert => "certificates.csv",
            Inventory::Dating => "dating.csv",
        }
    }
}

/// Analyse tous les `.apk` de `input_dir` et écrit un `<stem>.json` par APK dans
/// `opts.out_dir`. Le nom de sortie reprend le nom de fichier de l'APK sans
/// extension : pour un dataset nommé par hash, `<sha256>.apk` -> `<sha256>.json`.
///
/// Le contenu de chaque JSON est identique au mode single (`Vec<Match>` sérialisé),
/// pour que les scripts de post-traitement voient le même format dans les deux modes.
pub fn run(input_dir: &Path, engine: &Engine, opts: &BulkOptions) -> Result<()> {
    std::fs::create_dir_all(&opts.out_dir)?;

    let found = collect_apks(input_dir, opts.recursive)?;
    let apks = found.apks;
    if apks.is_empty() && found.rejected.is_empty() {
        anyhow::bail!("aucun APK trouvé dans {}", input_dir.display());
    }
    tracing::info!(
        count = apks.len(),
        rejected = found.rejected.len(),
        out = %opts.out_dir.display(),
        "bulk: démarrage"
    );

    let ok = AtomicUsize::new(0);
    let failed = AtomicUsize::new(found.rejected.len());
    let skipped = AtomicUsize::new(0);

    for (path, why) in &found.rejected {
        eprintln!("[FAIL]  {}  — non reconnu comme APK : {why}", path.display());
    }

    apks.par_iter().for_each(|apk| {
        let stem = apk
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());
        let out_path = opts.out_dir.join(format!("{stem}.json"));

        if out_path.exists() && !opts.overwrite {
            skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // parse_apk s'appuie sur des crates (dex, dex-bytecode, axmldecoder) qui
        // peuvent paniquer sur un DEX/manifest malformé — courant sur des samples
        // sideloadés. On isole le panic pour qu'un APK pourri ne tue pas le batch.
        let outcome = catch_unwind(AssertUnwindSafe(|| -> Result<usize> {
            let parsed = parser::parse_apk(apk)?;
            let matches = engine.run(&parsed.features, &parsed.call_graph);
            let json = serde_json::to_string_pretty(&matches)?;
            std::fs::write(&out_path, json)?;
            Ok(matches.len())
        }));

        match outcome {
            Ok(Ok(n)) => {
                ok.fetch_add(1, Ordering::Relaxed);
                eprintln!("[OK]    {}  ({n} détections)", apk.display());
            }
            Ok(Err(e)) => {
                failed.fetch_add(1, Ordering::Relaxed);
                eprintln!("[FAIL]  {}  — {e:#}", apk.display());
            }
            Err(_) => {
                failed.fetch_add(1, Ordering::Relaxed);
                eprintln!("[PANIC] {}  — parsing abandonné", apk.display());
            }
        }
    });

    eprintln!(
        "\n[*] bulk terminé — OK: {}  SKIP: {}  FAIL: {}",
        ok.load(Ordering::Relaxed),
        skipped.load(Ordering::Relaxed),
        failed.load(Ordering::Relaxed),
    );
    Ok(())
}

/// Ce qu'a donné la collecte d'un répertoire.
pub struct Collected {
    /// APK confirmés, triés.
    pub apks: Vec<PathBuf>,
    /// Fichiers à signature ZIP dont aucun lecteur n'a tiré d'AndroidManifest.xml.
    /// Ils sont comptés en échec plutôt qu'écartés en silence : sur un corpus
    /// nommé par hachage, une exclusion muette est indiscernable d'une absence.
    pub rejected: Vec<(PathBuf, String)>,
}

/// Collecte les APK d'un répertoire (récursif optionnel), triés pour un ordre de
/// traitement déterministe.
///
/// La sélection se fait sur le **contenu**, jamais sur l'extension : les corpus
/// nommés par hash n'en ont pas, et un `.apk` peut être n'importe quoi. Voir
/// [`recognize`].
pub fn collect_apks(dir: &Path, recursive: bool) -> Result<Collected> {
    let mut apks = Vec::new();
    let mut rejected = Vec::new();

    let mut consider = |p: PathBuf| match recognize(&p) {
        Recognition::Apk => apks.push(p),
        Recognition::ZipWithoutManifest(why) => rejected.push((p, why)),
        Recognition::NotZip => {}
    };

    if recursive {
        for entry in walkdir::WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            let p = entry.path();
            if p.is_file() {
                consider(p.to_path_buf());
            }
        }
    } else {
        for entry in std::fs::read_dir(dir)? {
            let p = entry?.path();
            if p.is_file() {
                consider(p);
            }
        }
    }
    apks.sort();
    rejected.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(Collected { apks, rejected })
}

/// Verdict de reconnaissance d'un fichier.
enum Recognition {
    Apk,
    /// Archive ZIP sans manifeste exploitable — porte la raison, à afficher.
    ZipWithoutManifest(String),
    /// Ni ZIP ni APK : DEX, ELF, image, résidu de corpus. Écarté sans bruit.
    NotZip,
}

/// Reconnaît un APK à son contenu, en trois étapes de coût croissant :
///
///  1. signature zip `PK\x03\x04` sur les 4 premiers octets — élimine d'emblée
///     les DEX, ELF, images et autres résidus qui traînent dans un corpus ;
///  2. présence d'une entrée `AndroidManifest.xml` — ce qui distingue un APK
///     d'un JAR, d'un ZIP quelconque ou d'un document Office ;
///  3. si le crate `zip` refuse l'archive, même recherche via le lecteur
///     tolérant : les archives trafiquées sont précisément celles qu'il sait
///     lire, et les rejeter ici priverait `extract_apk` de son repli.
///
/// L'extension n'entre jamais en compte : `.apk` ne garantit rien et son absence
/// n'exclut rien.
fn recognize(p: &Path) -> Recognition {
    use std::io::Read;

    let Ok(mut f) = std::fs::File::open(p) else {
        return Recognition::NotZip;
    };
    let mut magic = [0u8; 4];
    if f.read_exact(&mut magic).is_err() || magic != [0x50, 0x4b, 0x03, 0x04] {
        return Recognition::NotZip;
    }

    // Lecture du central directory uniquement : le contenu n'est pas décompressé.
    let nominal = match zip::ZipArchive::new(f) {
        Ok(mut zip) => {
            if zip.by_name("AndroidManifest.xml").is_ok() {
                return Recognition::Apk;
            }
            "pas d'AndroidManifest.xml".to_string()
        }
        Err(e) => format!("crate zip : {e}"),
    };

    match parser::apkzip::TolerantZip::open(p) {
        Ok(zip) => {
            if zip.entries().iter().any(|e| e.name == "AndroidManifest.xml") {
                Recognition::Apk
            } else {
                Recognition::ZipWithoutManifest(format!(
                    "{nominal} ; lecteur tolérant : {} entrée(s), aucune AndroidManifest.xml",
                    zip.len()
                ))
            }
        }
        Err(e) => Recognition::ZipWithoutManifest(format!(
            "{nominal} ; lecteur tolérant : {e:#}"
        )),
    }
}

/// Extrait le manifest ou la signature de tous les APK de `input_dir` et écrit un
/// `<stem>.manifest.json` / `<stem>.cert.json` par échantillon dans `opts.out_dir`.
///
/// Contrairement à [`run`], aucun DEX n'est parsé et le catalogue MITRE n'est pas
/// chargé : le coût par APK se limite à la lecture de l'archive zip. Le contenu
/// des JSON est strictement identique à celui du mode single.
pub fn run_inventory(input_dir: &Path, what: Inventory, opts: &BulkOptions) -> Result<()> {
    let to_stdout = opts.out_dir.as_os_str() == "-";
    if !to_stdout {
        std::fs::create_dir_all(&opts.out_dir)?;
    }

    let found = collect_apks(input_dir, opts.recursive)?;
    let apks = found.apks;
    if apks.is_empty() && found.rejected.is_empty() {
        anyhow::bail!("aucun APK trouvé dans {}", input_dir.display());
    }
    tracing::info!(
        count = apks.len(),
        rejected = found.rejected.len(),
        kind = what.label(),
        out = %opts.out_dir.display(),
        "bulk inventaire: démarrage"
    );

    let ok = AtomicUsize::new(0);
    let failed = AtomicUsize::new(found.rejected.len());
    let skipped = AtomicUsize::new(0);

    for (path, why) in &found.rejected {
        eprintln!("[FAIL]  {}  — non reconnu comme APK : {why}", path.display());
    }
    let csv_mode = opts.format == BulkFormat::Csv;
    // Un rendu groupé (CSV, ou JSON vers stdout) impose d'accumuler les rapports
    // en mémoire ; le JSON vers fichier les écrit au fil de l'eau.
    let collect = csv_mode || to_stdout;
    // Rapports accumulés pour le rendu groupé. Vides sinon.
    let certs: Mutex<Vec<(String, parser::cert::SigningReport)>> = Mutex::new(Vec::new());
    let manifests: Mutex<Vec<(String, parser::manifest_info::ManifestReport)>> =
        Mutex::new(Vec::new());
    let datings: Mutex<Vec<(String, parser::dating::DatingReport)>> = Mutex::new(Vec::new());

    apks.par_iter().for_each(|apk| {
        let stem = apk
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());
        let out_path = opts.out_dir.join(format!("{stem}.{}", what.suffix()));

        // La reprise ne vaut que pour le JSON vers fichier : ailleurs il n'y a pas
        // de fichier par échantillon à retrouver, et une ligne manquante fausserait
        // le lot.
        if !collect && out_path.exists() && !opts.overwrite {
            skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // Même protection que `run` : `axmldecoder` peut paniquer sur un AXML
        // malformé, fréquent sur les échantillons trafiqués.
        let outcome = catch_unwind(AssertUnwindSafe(|| -> Result<String> {
            match what {
                Inventory::Manifest => {
                    let r = parser::manifest_info::extract(apk)?;
                    let summary = format!(
                        "{} — {} composants, {} points d'entrée",
                        r.package,
                        r.components.total(),
                        r.entrypoints.len()
                    );
                    if collect {
                        push_collected(&manifests, stem.clone(), r);
                    } else {
                        std::fs::write(&out_path, serde_json::to_string_pretty(&r)?)?;
                    }
                    Ok(summary)
                }
                Inventory::Cert => {
                    let r = parser::cert::extract(apk)?;
                    let sha = r
                        .certificates
                        .first()
                        .map(|c| c.fingerprints.sha256.clone())
                        .unwrap_or_else(|| "-".into());
                    let summary = format!("{} — {}", r.schemes.labels().join("+"), sha);
                    if collect {
                        push_collected(&certs, stem.clone(), r);
                    } else {
                        std::fs::write(&out_path, serde_json::to_string_pretty(&r)?)?;
                    }
                    Ok(summary)
                }
                Inventory::Dating => {
                    let r = parser::dating::extract(apk)?;
                    let summary = format!(
                        "target={} compile={} écart={} archive={}",
                        opt_u32(r.sdk.target_sdk),
                        opt_u32(r.sdk.compile_sdk),
                        r.sdk
                            .compile_minus_target
                            .map(|d| d.to_string())
                            .unwrap_or_else(|| "?".into()),
                        r.archive.latest.clone().unwrap_or_else(|| "?".into())
                    );
                    if collect {
                        push_collected(&datings, stem.clone(), r);
                    } else {
                        std::fs::write(&out_path, serde_json::to_string_pretty(&r)?)?;
                    }
                    Ok(summary)
                }
            }
        }));

        match outcome {
            Ok(Ok(summary)) => {
                ok.fetch_add(1, Ordering::Relaxed);
                eprintln!("[OK]    {}  {summary}", apk.display());
            }
            Ok(Err(e)) => {
                failed.fetch_add(1, Ordering::Relaxed);
                eprintln!("[FAIL]  {}  — {e:#}", apk.display());
            }
            Err(_) => {
                failed.fetch_add(1, Ordering::Relaxed);
                eprintln!("[PANIC] {}  — extraction abandonnée", apk.display());
            }
        }
    });

    eprintln!(
        "\n[*] bulk {} terminé — OK: {}  SKIP: {}  FAIL: {}",
        what.label(),
        ok.load(Ordering::Relaxed),
        skipped.load(Ordering::Relaxed),
        failed.load(Ordering::Relaxed),
    );

    if collect {
        let rendered = match (what, csv_mode) {
            (Inventory::Cert, true) => cert_csv(into_inner(certs)),
            (Inventory::Cert, false) => json_array(into_inner(certs))?,
            (Inventory::Manifest, true) => manifest_csv(into_inner(manifests)),
            (Inventory::Manifest, false) => json_array(into_inner(manifests))?,
            (Inventory::Dating, true) => dating_csv(into_inner(datings)),
            (Inventory::Dating, false) => json_array(into_inner(datings))?,
        };

        if to_stdout {
            print!("{rendered}");
        } else {
            let path = opts.out_dir.join(what.csv_name());
            std::fs::write(&path, rendered)
                .map_err(|e| anyhow::anyhow!("écriture {} : {e}", path.display()))?;
            eprintln!("[*] CSV écrit dans {}", path.display());
        }
    }

    Ok(())
}

/// Un rapport et l'échantillon dont il provient, pour le rendu JSON groupé.
#[derive(Serialize)]
struct Sampled<T> {
    /// Nom de base du fichier analysé.
    sample: String,
    report: T,
}

/// Sérialise le lot en un tableau JSON unique — rendu de `--format json --out -`.
/// Chaque élément porte le rapport intégral, identique au JSON par fichier.
fn json_array<T: Serialize>(rows: Vec<(String, T)>) -> Result<String> {
    let wrapped: Vec<Sampled<T>> = rows
        .into_iter()
        .map(|(sample, report)| Sampled { sample, report })
        .collect();
    Ok(serde_json::to_string_pretty(&wrapped)?)
}

/// Récupère le contenu d'un accumulateur, trié par nom d'échantillon — les workers
/// rayon terminent dans un ordre arbitraire.
fn into_inner<T>(store: Mutex<Vec<(String, T)>>) -> Vec<(String, T)> {
    let mut v = store
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

/// Ajoute un rapport à l'accumulateur partagé entre workers rayon.
fn push_collected<T>(store: &Mutex<Vec<(String, T)>>, stem: String, report: T) {
    match store.lock() {
        Ok(mut v) => v.push((stem, report)),
        Err(poisoned) => poisoned.into_inner().push((stem, report)),
    }
}

/// CSV du lot de signatures : une ligne par (échantillon × certificat).
///
/// Un APK peut porter plusieurs certificats (rotation de clé v3, signature
/// multiple), d'où la possibilité de plusieurs lignes pour un même `sample`.
/// Les échantillons dont aucun certificat n'a pu être extrait produisent une
/// ligne aux colonnes de certificat vides : un lot ne perd jamais une entrée en
/// silence.
///
/// `cert_sha256` est la clé de regroupement — deux échantillons qui la partagent
/// ont été signés avec la même clé, donc produits par la même chaîne de build,
/// y compris sous des marques différentes.
fn cert_csv(rows: Vec<(String, parser::cert::SigningReport)>) -> String {
    let mut out = String::from(
        "sample,schemes,cert_sha256,subject_cn,subject_o,issuer_cn,self_signed,\
not_before,not_after,validity_years,signature_algorithm,key_algorithm,\
key_bits,public_key_sha256,anomalies\n",
    );

    for (stem, report) in &rows {
        let schemes = report.schemes.labels().join("+");
        let anomalies = report.anomalies.len();

        if report.certificates.is_empty() {
            out.push_str(&format!(
                "{},{},,,,,,,,,,,,,{anomalies}\n",
                csv_field(stem),
                csv_field(&schemes)
            ));
            continue;
        }

        for c in &report.certificates {
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{:.2},{},{},{},{},{anomalies}\n",
                csv_field(stem),
                csv_field(&schemes),
                csv_field(&c.fingerprints.sha256),
                csv_field(c.subject_cn.as_deref().unwrap_or_default()),
                csv_field(c.subject_o.as_deref().unwrap_or_default()),
                csv_field(c.issuer_cn.as_deref().unwrap_or_default()),
                c.self_signed,
                csv_field(&c.not_before),
                csv_field(&c.not_after),
                c.validity_years,
                csv_field(&c.signature_algorithm),
                csv_field(&c.public_key.algorithm),
                c.public_key
                    .size_bits
                    .map(|b| b.to_string())
                    .unwrap_or_default(),
                csv_field(&c.public_key_sha256),
            ));
        }
    }
    out
}

/// CSV du lot de manifests : une ligne par échantillon.
///
/// Les structures imbriquées (intent-filters, meta-data, liste nominative des
/// permissions) ne sont pas représentables à plat et sont réduites à des
/// compteurs ; `triggers` donne les types de points d'entrée présents, séparés
/// par `|`. Pour le détail complet d'un échantillon, repasser en `--format json`.
fn manifest_csv(rows: Vec<(String, parser::manifest_info::ManifestReport)>) -> String {
    let mut out = String::from(
        "sample,package,version_name,version_code,min_sdk,target_sdk,\
permissions,components,activities,services,receivers,providers,\
entrypoints,triggers,application_class,anomalies\n",
    );

    for (stem, r) in &rows {
        // Types de déclencheurs distincts, dans l'ordre de première apparition.
        let mut triggers: Vec<&str> = Vec::new();
        for e in &r.entrypoints {
            let label = e.trigger.label();
            if !triggers.contains(&label) {
                triggers.push(label);
            }
        }

        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            csv_field(stem),
            csv_field(&r.package),
            csv_field(r.version_name.as_deref().unwrap_or_default()),
            csv_field(r.version_code.as_deref().unwrap_or_default()),
            opt_u32(r.sdk.min_sdk),
            opt_u32(r.sdk.target_sdk),
            r.uses_permissions.len(),
            r.components.total(),
            r.components.activities.len(),
            r.components.services.len(),
            r.components.receivers.len(),
            r.components.providers.len(),
            r.entrypoints.len(),
            csv_field(&triggers.join("|")),
            csv_field(r.application.name.as_deref().unwrap_or_default()),
            r.anomalies.len(),
        ));
    }
    out
}

fn opt_u32(v: Option<u32>) -> String {
    v.map(|n| n.to_string()).unwrap_or_default()
}

/// CSV du lot de datation : une ligne par échantillon, toutes sources confondues.
///
/// C'est la table de corrélation : chaque colonne est un indicateur brut, avec sa
/// nature propre (borne basse, valeur exacte falsifiable, simple indice). Aucune
/// date de build n'est estimée ici — voir `dating::legend()` pour la nature de
/// chaque champ. Les champs multivalués sont joints par `|`.
fn dating_csv(rows: Vec<(String, parser::dating::DatingReport)>) -> String {
    use parser::dating::{library_version, DATING_LIBRARIES};

    let lib_headers = DATING_LIBRARIES
        .iter()
        .map(|(col, _)| *col)
        .collect::<Vec<_>>()
        .join(",");

    let mut out = format!(
        "sample,file_sha256,package,version_name,version_code,\
min_sdk,target_sdk,compile_sdk,compile_minus_target,platform_build_version,\
cert_count,cert_not_before,cert_not_after,cert_sha256,signing_schemes,\
dex_count,dex_versions,toolchain_floor_api,\
archive_entries,archive_dated,archive_earliest,archive_latest,archive_distinct,\
archive_normalized,archive_sentinel,\
code_date_min,code_date_max,code_date_count,\
lib_count,{lib_headers},build_metadata\n"
    );

    for (stem, r) in &rows {
        // Le certificat le plus ancien : borne basse la plus défendable.
        let cert = r
            .signatures
            .iter()
            .min_by(|a, b| a.not_before.cmp(&b.not_before));

        let dex_versions = r
            .dex_files
            .iter()
            .map(|d| d.format_version.clone())
            .collect::<Vec<_>>()
            .join("|");

        // Bibliothèques retenues, une colonne chacune. La liste complète reste
        // dans le JSON : 2 000 caractères dans une cellule sont inexploitables.
        let libs = DATING_LIBRARIES
            .iter()
            .map(|(_, module)| {
                csv_field(&library_version(&r.library_versions, module).unwrap_or_default())
            })
            .collect::<Vec<_>>()
            .join(",");

        let metadata = r
            .build_metadata
            .iter()
            .map(|m| m.entry.clone())
            .collect::<Vec<_>>()
            .join("|");

        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            csv_field(stem),
            csv_field(&r.file_sha256),
            csv_field(&r.package),
            csv_field(r.version_name.as_deref().unwrap_or_default()),
            csv_field(r.version_code.as_deref().unwrap_or_default()),
            opt_u32(r.sdk.min_sdk),
            opt_u32(r.sdk.target_sdk),
            opt_u32(r.sdk.compile_sdk),
            r.sdk
                .compile_minus_target
                .map(|d| d.to_string())
                .unwrap_or_default(),
            csv_field(
                r.sdk
                    .platform_build_version_code
                    .as_deref()
                    .unwrap_or_default()
            ),
            r.signatures.len(),
            csv_field(cert.map(|c| c.not_before.as_str()).unwrap_or_default()),
            csv_field(cert.map(|c| c.not_after.as_str()).unwrap_or_default()),
            csv_field(cert.map(|c| c.sha256.as_str()).unwrap_or_default()),
            csv_field(&r.signing_schemes.join("+")),
            r.dex_files.len(),
            csv_field(&dex_versions),
            r.toolchain_floor_api
                .map(|a| a.to_string())
                .unwrap_or_default(),
            r.archive.entry_count,
            r.archive.dated_entry_count,
            csv_field(r.archive.earliest.as_deref().unwrap_or_default()),
            csv_field(r.archive.latest.as_deref().unwrap_or_default()),
            r.archive.distinct_count,
            r.archive.normalized,
            csv_field(r.archive.sentinel.as_deref().unwrap_or_default()),
            csv_field(
                r.code_dates
                    .first()
                    .map(|d| d.value.as_str())
                    .unwrap_or_default()
            ),
            csv_field(
                r.code_dates
                    .last()
                    .map(|d| d.value.as_str())
                    .unwrap_or_default()
            ),
            r.code_dates.len(),
            r.library_versions.len(),
            libs,
            csv_field(&metadata),
        ));
    }
    out
}

/// Échappe un champ CSV (RFC 4180) : guillemets doublés, encadrement si le champ
/// contient une virgule, un guillemet ou un saut de ligne. Les DN de certificat
/// contiennent régulièrement des virgules.
fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
