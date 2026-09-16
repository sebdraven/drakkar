//! Mode bulk : analyse un répertoire d'APK en parallèle (rayon), un JSON de
//! détections par APK.
//!
//! L'`Engine` (catalogue MITRE) est chargé **une seule fois** par l'appelant et
//! partagé en lecture entre les workers — `Engine::run` prend `&self` et ne mute
//! rien, donc pas de rechargement du STIX par APK. Chaque worker ne construit que
//! son propre `ParsedApk` (features + CFG), thread-local par nature.

use crate::parser;
use crate::rules::Engine;
use petgraph::graph::NodeIndex;
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
    collect_with(dir, recursive, false)
}

/// Variante pour l'audit d'orphelins : accepte AUSSI les **DEX bruts** déballés
/// (`classes_unpacked.dex`, dumps mémoire), reconnus au contenu. Les archives
/// zip sans AndroidManifest.xml restent rejetées avec leur raison, comme dans
/// [`collect_apks`] — c'est le seul cas où une entrée est comptée en échec.
pub fn collect_orphan_inputs(dir: &Path, recursive: bool) -> Result<Collected> {
    collect_with(dir, recursive, true)
}

fn collect_with(dir: &Path, recursive: bool, keep_raw_dex: bool) -> Result<Collected> {
    use crate::parser::dyn_entrypoints::{sniff, InputKind};

    let mut apks = Vec::new();
    let mut rejected = Vec::new();

    let mut consider = |p: PathBuf| match recognize(&p) {
        Recognition::Apk => apks.push(p),
        Recognition::ZipWithoutManifest(why) => rejected.push((p, why)),
        Recognition::NotZip => {
            if keep_raw_dex && sniff(&p) == Some(InputKind::Dex) {
                apks.push(p);
            }
        }
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

        // Même protection que `run` : `parser::axml` rattrape le panic
        // d'`axmldecoder`, mais les autres inventaires n'ont pas leur propre
        // filet.
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

// ───────────────── Audit d'orphelins en lot ─────────────────

/// Régime sous lequel les racines ont été construites. À reporter avec CHAQUE
/// mesure : un taux d'orphelins obtenu sous `heuristic` ne se compare pas à un
/// taux obtenu sous `manifest`, la sur-approximation des racines n'étant pas la
/// même.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RootsMode {
    /// Composants déclarés au manifeste × callbacks de cycle de vie.
    Manifest,
    /// Aucun composant exploitable — DEX brut déballé, ou APK dont le manifeste
    /// n'a rien donné : tout callback de cycle de vie du graphe devient racine.
    Heuristic,
}

impl RootsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            RootsMode::Manifest => "manifest",
            RootsMode::Heuristic => "heuristic",
        }
    }
}

/// Les quatre étages CUMULATIFS de racines de l'audit d'orphelins. La courbe
/// `base -> with_dyn -> with_ui -> all` est la mesure de saturation : ce qu'un
/// étage rattrape n'était pas orphelin, juste non semé.
pub struct OrphanRoots {
    pub mode: RootsMode,
    pub base: Vec<NodeIndex>,
    pub with_dyn: Vec<NodeIndex>,
    pub with_ui: Vec<NodeIndex>,
    pub all: Vec<NodeIndex>,
}

/// Construit les racines de l'audit pour un APK **ou** un DEX brut — source de
/// vérité unique pour le mode single et le mode bulk.
///
/// `path` sert aux passes qui relisent le binaire (dyn, ui) ; elles routent
/// elles-mêmes sur le contenu via `extract_any`. Le régime est déduit de la
/// présence de composants dans `parsed.features` : un DEX brut n'a pas de
/// manifeste, donc pas de composant, donc pas de racine à l'étage 1 — d'où le
/// repli heuristique.
pub fn build_orphan_roots(path: &Path, parsed: &parser::ParsedApk) -> Result<OrphanRoots> {
    let cg = &parsed.call_graph;

    // Étage 1 : composants du manifeste, ou repli heuristique.
    let (mode, base) = if parsed.features.components.is_empty() {
        (RootsMode::Heuristic, cg.heuristic_entrypoints())
    } else {
        (RootsMode::Manifest, cg.entrypoints(&parsed.features.components))
    };

    // Étage 2 : + classes atteintes dynamiquement (registerReceiver, Intent…).
    // Sous le régime heuristique l'étage est neutre par construction (les nœuds
    // qu'il désignerait sont déjà tous racines) : la colonne le montrera.
    let dyn_classes = parser::dyn_entrypoints::extract_any(path)?.classes();
    let mut with_dyn = base.clone();
    with_dyn.extend(cg.entrypoints(&dyn_classes));
    with_dyn.sort();
    with_dyn.dedup();

    // Étage 3 : + handlers UI (onClick & cie) résolus en nœuds.
    let ui_roots = parser::ui_callbacks::extract_any(path)?.roots();
    let mut with_ui = with_dyn.clone();
    with_ui.extend(cg.nodes_for(&ui_roots));
    with_ui.sort();
    with_ui.dedup();

    // Étage 4 : + <clinit> (initialiseurs statiques : racines implicites).
    let mut all = with_ui.clone();
    all.extend(cg.clinit_nodes());
    all.sort();
    all.dedup();

    Ok(OrphanRoots { mode, base, with_dyn, with_ui, all })
}

/// Sous-chaînes `class->name` des sinks sondés en colonnes. Vocabulaire aligné
/// sur `rules/catalog.rs` ; volontairement partielles pour absorber les variantes
/// (`DexClassLoader;-><init>` matche aussi `InMemoryDexClassLoader` et
/// `BaseDexClassLoader`).
const SINK_LOADLIB: &str = "System;->loadLibrary";
const SINK_INVOKE: &str = "reflect/Method;->invoke";
const SINK_EXEC: &str = "Runtime;->exec";
const SINK_DEXLOAD: &str = "DexClassLoader;-><init>";
const SINK_CRYPTO: &str = "Cipher;->doFinal";
const SINK_NET: &str = "HttpURLConnection;->connect";

/// Les quatre mesures d'un sink : présent ? atteignable ? à combien de sauts ?
/// appelé depuis combien de call-sites ? Structure interne — chaque sink est
/// aplati en colonnes nommées dans `OrphanSample`, le CSV restant plat.
struct SinkProbe {
    node: bool,
    reach: bool,
    /// Sauts minimaux racine -> sink ; -1 si non atteignable (colonne numérique).
    depth: i64,
    fanin: usize,
}

/// Sonde un sink contre le graphe depuis `roots`.
///
/// `reach` est dérivé de `min_depth` et non d'un appel à `reachability` : les
/// deux décrivent la même atteignabilité dirigée depuis les mêmes racines
/// (`Some(_)` ⟺ `reachable`), mais `reachability` reconstruit en plus un chemin
/// de signatures PAR racine — inutile ici, et coûteux quand les racines se
/// comptent en centaines et qu'on sonde six sinks par échantillon.
fn probe_sink(cg: &crate::cfg::CallGraph, api: &str, roots: &[NodeIndex]) -> SinkProbe {
    let depth = cg.min_depth(api, roots);
    SinkProbe {
        node: cg.has_api(api),
        reach: depth.is_some(),
        depth: depth.map_or(-1, |d| d as i64),
        fanin: cg.fan_in(api),
    }
}

/// Ligne de synthèse d'un échantillon pour l'audit d'orphelins. Les scalaires
/// alimentent le CSV de corpus ; `report` (îlots complets) n'est sérialisé qu'en
/// sortie JSON. `loadlib_*` / `invoke_*` sont les deux atteignabilités qu'on
/// sondait à la main, ici en colonnes : franchissement natif câblé ? dispatch
/// par réflexion câblé ? `*_depth` / `*_fanin` caractérisent COMMENT : à combien
/// de sauts d'une racine le sink est armé, et combien de call-sites l'appellent
/// directement. `exec_*` / `dexload_*` / `crypto_*` / `net_*` étendent les mêmes
/// quatre mesures aux autres capacités sensibles du catalogue.
#[derive(Serialize)]
pub struct OrphanSample {
    pub sample: String,
    /// Régime de construction des racines — conditionne la comparabilité.
    pub roots_mode: RootsMode,
    pub nodes: usize,
    pub roots_manifest: usize,
    pub roots_dyn: usize,
    pub roots_ui: usize,
    pub roots_clinit: usize,
    pub reach_manifest: usize,
    pub reach_dyn: usize,
    pub reach_ui: usize,
    pub reach_clinit: usize,
    pub orphans: usize,
    pub islands: usize,
    pub biggest_size: usize,
    pub biggest_author_pct: u32,
    pub loadlib_node: bool,
    pub loadlib_reach: bool,
    pub invoke_node: bool,
    pub invoke_reach: bool,
    /// Sauts minimaux racine -> sink ; -1 si non atteignable (colonne numérique).
    pub loadlib_depth: i64,
    /// Call-sites appelant directement le sink (arêtes entrantes).
    pub loadlib_fanin: usize,
    pub invoke_depth: i64,
    pub invoke_fanin: usize,
    pub exec_node: bool,
    pub exec_reach: bool,
    pub exec_depth: i64,
    pub exec_fanin: usize,
    pub dexload_node: bool,
    pub dexload_reach: bool,
    pub dexload_depth: i64,
    pub dexload_fanin: usize,
    pub crypto_node: bool,
    pub crypto_reach: bool,
    pub crypto_depth: i64,
    pub crypto_fanin: usize,
    pub net_node: bool,
    pub net_reach: bool,
    pub net_depth: i64,
    pub net_fanin: usize,
    /// Rapport complet (îlots + racines). Skippé en CSV, gardé en JSON.
    pub report: crate::cfg::OrphanReport,
}

/// Calcule l'audit d'orphelins d'UN échantillon — APK ou DEX brut, reconnu au
/// contenu. Racines à quatre étages (cf. [`build_orphan_roots`]) plus les deux
/// sondes d'atteignabilité.
pub fn orphan_audit_sample(apk: &Path) -> Result<OrphanSample> {
    let sample = apk
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".into());

    let parsed = parser::parse_any(apk)?;
    let cg = &parsed.call_graph;
    let roots = build_orphan_roots(apk, &parsed)?;
    let OrphanRoots { mode, base, with_dyn, with_ui, all } = &roots;

    let report = cg.orphan_audit(all, "loadLibrary");

    let reach_manifest = cg.reachable_set(base).len();
    let reach_dyn = cg.reachable_set(with_dyn).len();
    let reach_ui = cg.reachable_set(with_ui).len();

    // Les îlots sont triés (franchissement puis taille) : le plus gros n'est pas
    // forcément le premier, on le prend explicitement.
    let biggest = report.islands.iter().max_by_key(|i| i.size);
    let biggest_size = biggest.map(|i| i.size).unwrap_or(0);
    let biggest_author_pct = biggest
        .map(|i| if i.size > 0 { (100 * i.author_nodes / i.size) as u32 } else { 0 })
        .unwrap_or(0);

    let loadlib = probe_sink(cg, SINK_LOADLIB, all);
    let invoke = probe_sink(cg, SINK_INVOKE, all);
    let exec = probe_sink(cg, SINK_EXEC, all);
    let dexload = probe_sink(cg, SINK_DEXLOAD, all);
    let crypto = probe_sink(cg, SINK_CRYPTO, all);
    let net = probe_sink(cg, SINK_NET, all);

    Ok(OrphanSample {
        sample,
        roots_mode: *mode,
        nodes: report.total_nodes,
        roots_manifest: base.len(),
        roots_dyn: with_dyn.len(),
        roots_ui: with_ui.len(),
        roots_clinit: all.len(),
        reach_manifest,
        reach_dyn,
        reach_ui,
        reach_clinit: report.reachable,
        orphans: report.orphan,
        islands: report.islands.len(),
        biggest_size,
        biggest_author_pct,
        loadlib_node: loadlib.node,
        loadlib_reach: loadlib.reach,
        invoke_node: invoke.node,
        invoke_reach: invoke.reach,
        loadlib_depth: loadlib.depth,
        loadlib_fanin: loadlib.fanin,
        invoke_depth: invoke.depth,
        invoke_fanin: invoke.fanin,
        exec_node: exec.node,
        exec_reach: exec.reach,
        exec_depth: exec.depth,
        exec_fanin: exec.fanin,
        dexload_node: dexload.node,
        dexload_reach: dexload.reach,
        dexload_depth: dexload.depth,
        dexload_fanin: dexload.fanin,
        crypto_node: crypto.node,
        crypto_reach: crypto.reach,
        crypto_depth: crypto.depth,
        crypto_fanin: crypto.fanin,
        net_node: net.node,
        net_reach: net.reach,
        net_depth: net.depth,
        net_fanin: net.fanin,
        report,
    })
}

/// Audit d'orphelins sur tout un répertoire, en parallèle : une ligne CSV par
/// échantillon (ou un tableau JSON en `--format json`). C'est la table de corpus.
pub fn run_orphan_audit(input_dir: &Path, opts: &BulkOptions) -> Result<()> {
    let to_stdout = opts.out_dir.as_os_str() == "-";
    if !to_stdout {
        std::fs::create_dir_all(&opts.out_dir)?;
    }

    let found = collect_orphan_inputs(input_dir, opts.recursive)?;
    let apks = found.apks;
    if apks.is_empty() && found.rejected.is_empty() {
        anyhow::bail!("aucun APK ni DEX brut trouvé dans {}", input_dir.display());
    }
    tracing::info!(
        count = apks.len(),
        rejected = found.rejected.len(),
        out = %opts.out_dir.display(),
        "bulk orphan-audit: démarrage"
    );

    let ok = AtomicUsize::new(0);
    let failed = AtomicUsize::new(found.rejected.len());
    for (path, why) in &found.rejected {
        eprintln!("[FAIL]  {}  — non reconnu comme APK : {why}", path.display());
    }

    let rows: Mutex<Vec<OrphanSample>> = Mutex::new(Vec::new());

    apks.par_iter().for_each(|apk| {
        let outcome = catch_unwind(AssertUnwindSafe(|| orphan_audit_sample(apk)));
        match outcome {
            Ok(Ok(s)) => {
                ok.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "[OK]    {}  — {}/{} orphelins (roots={}, loadlib_reach={}, invoke_reach={})",
                    apk.display(),
                    s.orphans,
                    s.nodes,
                    s.roots_mode.as_str(),
                    s.loadlib_reach,
                    s.invoke_reach
                );
                match rows.lock() {
                    Ok(mut v) => v.push(s),
                    Err(p) => p.into_inner().push(s),
                }
            }
            Ok(Err(e)) => {
                failed.fetch_add(1, Ordering::Relaxed);
                eprintln!("[FAIL]  {}  — {e:#}", apk.display());
            }
            Err(_) => {
                failed.fetch_add(1, Ordering::Relaxed);
                eprintln!("[PANIC] {}  — audit abandonné", apk.display());
            }
        }
    });

    eprintln!(
        "\n[*] bulk orphan-audit terminé — OK: {}  FAIL: {}",
        ok.load(Ordering::Relaxed),
        failed.load(Ordering::Relaxed),
    );

    let mut rows = rows.into_inner().unwrap_or_else(|p| p.into_inner());
    rows.sort_by(|a, b| a.sample.cmp(&b.sample));

    let rendered = if opts.format == BulkFormat::Csv {
        orphan_csv(&rows)
    } else {
        serde_json::to_string_pretty(&rows)?
    };

    if to_stdout {
        print!("{rendered}");
    } else {
        let name = if opts.format == BulkFormat::Csv {
            "orphan_audit.csv"
        } else {
            "orphan_audit.json"
        };
        let path = opts.out_dir.join(name);
        std::fs::write(&path, rendered)
            .map_err(|e| anyhow::anyhow!("écriture {} : {e}", path.display()))?;
        eprintln!("[*] écrit dans {}", path.display());
    }

    Ok(())
}

/// CSV de l'audit d'orphelins : une ligne par échantillon, scalaires seuls (le
/// détail des îlots reste dans le JSON). C'est la table à charger dans pandas.
/// `roots_mode` dit sous quel régime la ligne a été mesurée : ne comparer que
/// des lignes de même régime (cf. [`RootsMode`]).
fn orphan_csv(rows: &[OrphanSample]) -> String {
    let mut out = String::from(
        "sample,roots_mode,nodes,roots_manifest,roots_dyn,roots_ui,roots_clinit,\
reach_manifest,reach_dyn,reach_ui,reach_clinit,orphans,islands,\
biggest_size,biggest_author_pct,loadlib_node,loadlib_reach,invoke_node,invoke_reach,\
loadlib_depth,loadlib_fanin,invoke_depth,invoke_fanin,\
exec_node,exec_reach,exec_depth,exec_fanin,\
dexload_node,dexload_reach,dexload_depth,dexload_fanin,\
crypto_node,crypto_reach,crypto_depth,crypto_fanin,\
net_node,net_reach,net_depth,net_fanin\n",
    );
    for s in rows {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},\
{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            csv_field(&s.sample),
            s.roots_mode.as_str(),
            s.nodes,
            s.roots_manifest,
            s.roots_dyn,
            s.roots_ui,
            s.roots_clinit,
            s.reach_manifest,
            s.reach_dyn,
            s.reach_ui,
            s.reach_clinit,
            s.orphans,
            s.islands,
            s.biggest_size,
            s.biggest_author_pct,
            s.loadlib_node,
            s.loadlib_reach,
            s.invoke_node,
            s.invoke_reach,
            s.loadlib_depth,
            s.loadlib_fanin,
            s.invoke_depth,
            s.invoke_fanin,
            s.exec_node,
            s.exec_reach,
            s.exec_depth,
            s.exec_fanin,
            s.dexload_node,
            s.dexload_reach,
            s.dexload_depth,
            s.dexload_fanin,
            s.crypto_node,
            s.crypto_reach,
            s.crypto_depth,
            s.crypto_fanin,
            s.net_node,
            s.net_reach,
            s.net_depth,
            s.net_fanin,
        ));
    }
    out
}
