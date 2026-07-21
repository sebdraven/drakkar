//! Collecte des **indicateurs de datation** d'un APK, destinés à être corrélés
//! entre eux à l'échelle d'un corpus.
//!
//! Le module ne produit **aucun score et aucune date estimée** : il expose des
//! grandeurs brutes, chacune avec sa nature propre (borne basse, borne haute,
//! valeur exacte, valeur potentiellement falsifiée). L'agrégation est un choix
//! d'analyse, pas d'extraction — elle se fait en aval, sur le CSV.
//!
//! Quatre familles de sources, de fiabilité décroissante :
//!
//!  1. **Signature** — `notBefore` / `notAfter` des certificats. Date la
//!     *génération de la clé*, pas le build : borne basse, souvent antérieure de
//!     plusieurs années, et commune à tous les échantillons d'un même éditeur.
//!  2. **Chaîne de build** — `compileSdkVersion`, `platformBuildVersion`,
//!     version de format DEX, schémas de signature présents, versions de
//!     bibliothèques dans `META-INF/*.version`. Ce sont des **planchers** : le
//!     build est postérieur à la sortie de l'outil ou de la bibliothèque.
//!  3. **Horodatages de l'archive** — dates DOS du central directory. Exactes
//!     quand elles sont authentiques, mais couramment normalisées par les
//!     chaînes de build reproductibles : le drapeau `normalized` dit lequel des
//!     deux cas s'applique.
//!  4. **Littéraux du code** — chaînes de forme `AAAA-MM-JJ` du pool de chaînes
//!     DEX. Non contraintes, potentiellement décoratives ; à traiter comme
//!     indice, jamais comme preuve.
//!
//! Toutes les étiquettes et la nature de chaque champ sont définies dans
//! [`legend`] (légende autonome).

use crate::parser::{cert, manifest_info};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

// ---------------------------------------------------------------------------
// Modèle
// ---------------------------------------------------------------------------

/// Ensemble des indicateurs de datation d'un APK.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DatingReport {
    /// SHA-256 du fichier APK lui-même — clé de jointure du corpus et des
    /// services d'enrichissement (VirusTotal, Koodous).
    pub file_sha256: String,
    pub package: String,
    pub version_name: Option<String>,
    pub version_code: Option<String>,
    /// Niveaux d'API visés et marqueurs de build du manifest.
    pub sdk: SdkTargets,
    /// Certificats de signature, avec leurs bornes de validité.
    pub signatures: Vec<SignatureDate>,
    /// Schémas de signature détectés (v1, v2, v3, v3.1).
    pub signing_schemes: Vec<String>,
    /// Horodatages des entrées de l'archive.
    pub archive: ArchiveTimestamps,
    /// Un enregistrement par `classes*.dex`.
    pub dex_files: Vec<DexFormat>,
    /// Versions de bibliothèques lues dans `META-INF/*.version`.
    pub library_versions: Vec<LibraryVersion>,
    /// Fichiers de métadonnées de build présents dans l'archive (contenu brut).
    pub build_metadata: Vec<BuildMetadata>,
    /// Littéraux de date trouvés dans le pool de chaînes DEX.
    pub code_dates: Vec<CodeDate>,
    /// Plancher d'API déduit des seuls marqueurs de format (jamais du contenu) :
    /// le build est nécessairement postérieur à cette version de plateforme.
    pub toolchain_floor_api: Option<u32>,
}

/// Niveaux d'API et marqueurs de build issus du manifest.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SdkTargets {
    pub min_sdk: Option<u32>,
    pub target_sdk: Option<u32>,
    pub max_sdk: Option<u32>,
    pub compile_sdk: Option<u32>,
    pub compile_sdk_codename: Option<String>,
    pub platform_build_version_code: Option<String>,
    pub platform_build_version_name: Option<String>,
    /// `compile_sdk - target_sdk`. Les deux valeurs viennent de la même config de
    /// build : l'écart mesure un choix, pas une inférence inter-sources. `None`
    /// si l'un des deux manque.
    pub compile_minus_target: Option<i64>,
}

/// Bornes de validité d'un certificat de signature.
///
/// `not_before` date la génération de la clé. Une même clé servant des années
/// sur de nombreuses versions, c'est une **borne basse** du build, parfois très
/// éloignée — et identique pour tous les échantillons d'un même éditeur.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureDate {
    /// `v1:<fichier>`, `v2`, `v3` ou `v3.1`.
    pub source: String,
    pub subject_cn: Option<String>,
    pub sha256: String,
    pub not_before: String,
    pub not_after: String,
    pub validity_years: f64,
}

/// Horodatages des entrées de l'archive.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArchiveTimestamps {
    /// Nombre total d'entrées dans l'archive.
    pub entry_count: usize,
    /// Nombre d'entrées portant effectivement un horodatage. Un écart avec
    /// `entry_count` signifie que le producteur a omis les dates, ce qui est en
    /// soi une information sur la chaîne de build.
    pub dated_entry_count: usize,
    /// Horodatage le plus ancien (les dates DOS n'ont pas de fuseau).
    pub earliest: Option<String>,
    /// Le plus récent — le meilleur proxy de date de build quand les
    /// horodatages sont authentiques.
    pub latest: Option<String>,
    /// Nombre de valeurs distinctes. À 1, l'archive est horodatée uniformément.
    pub distinct_count: usize,
    /// Vrai si toutes les entrées datées partagent le même horodatage : build
    /// reproductible, l'horodatage ne date alors plus rien.
    pub normalized: bool,
    /// Valeur sentinelle reconnue le cas échéant (époque zip 1980-01-01,
    /// constante 1981-01-01T01:01:02 d'AGP, etc.).
    pub sentinel: Option<String>,
}

/// Version de format d'un fichier DEX.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexFormat {
    pub entry: String,
    /// Trois chiffres du nombre magique : 035, 037, 038, 039, 040...
    pub format_version: String,
    /// Niveau d'API à partir duquel ce format existe — plancher de build.
    pub api_floor: Option<u32>,
    pub string_count: usize,
}

/// Version d'une bibliothèque, lue dans `META-INF/<groupe>_<module>.version`.
///
/// Ces fichiers sont écrits par AndroidX et les SDK Google. Ils donnent la
/// version **exacte** de la dépendance, donc un plancher de build étroit une
/// fois croisé avec sa date de publication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryVersion {
    /// Nom du module, déduit du nom de fichier.
    pub module: String,
    pub version: String,
}

/// Fichier de métadonnées de build embarqué dans l'archive.
///
/// `kotlin-tooling-metadata.json` porte les versions exactes d'AGP, de Kotlin et
/// du JDK de build — l'indicateur le plus précis quand il est présent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildMetadata {
    pub entry: String,
    /// Contenu brut, tronqué à 4 Ko. Non interprété : à exploiter en aval.
    pub content: String,
}

/// Littéral de date trouvé dans le pool de chaînes d'un DEX.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeDate {
    /// Date au format `AAAA-MM-JJ`.
    pub value: String,
    /// Nombre de chaînes distinctes où elle apparaît.
    pub occurrences: usize,
}

// ---------------------------------------------------------------------------
// Tables de correspondance
// ---------------------------------------------------------------------------

/// Version de format DEX -> niveau d'API introduisant ce format.
fn dex_api_floor(version: &str) -> Option<u32> {
    match version {
        "035" => Some(1),  // format historique
        "036" => Some(24), // jamais publié officiellement
        "037" => Some(24), // Android 7.0
        "038" => Some(26), // Android 8.0
        "039" => Some(28), // Android 9
        "040" => Some(30), // Android 11
        _ => None,
    }
}

/// Schéma de signature -> niveau d'API du build-tools qui l'a introduit.
fn scheme_api_floor(scheme: &str) -> Option<u32> {
    match scheme {
        "v1" => None, // pas de plancher : schéma d'origine
        "v2" => Some(24),
        "v3" => Some(28),
        "v3.1" => Some(33),
        _ => None,
    }
}

/// Horodatages sentinelles employés par les chaînes de build reproductibles.
///
/// Repérés par leur préfixe date+heure exact : ces constantes sont écrites à la
/// seconde près par l'outil, contrairement à un horodatage authentique.
const SENTINELS: &[(&str, &str)] = &[
    ("1980-01-01T00:00:00", "époque zip (aucune date conservée)"),
    ("1980-02-01T00:00:00", "constante Gradle / Bazel"),
    ("1981-01-01T01:01:02", "constante AGP (zipflinger)"),
    ("2008-01-01T00:00:00", "constante de build alternative"),
    ("2010-01-01T00:00:00", "constante des outils Android"),
];

// ---------------------------------------------------------------------------
// Point d'entrée
// ---------------------------------------------------------------------------

/// Rassemble tous les indicateurs de datation d'un APK.
///
/// Aucune étape ne fait échouer les autres : une source illisible laisse son
/// champ vide plutôt que d'interrompre l'extraction — sur un corpus, une valeur
/// manquante est exploitable, une ligne absente ne l'est pas.
pub fn extract(apk_path: &Path) -> Result<DatingReport> {
    let mut r = DatingReport::default();

    // Empreinte du fichier : clé de jointure.
    match file_sha256(apk_path) {
        Ok(h) => r.file_sha256 = h,
        Err(e) => tracing::warn!(error = %e, "empreinte du fichier illisible"),
    }

    // Manifest : cibles d'API et marqueurs de build.
    match manifest_info::extract(apk_path) {
        Ok(m) => {
            r.package = m.package;
            r.version_name = m.version_name;
            r.version_code = m.version_code;
            r.sdk = SdkTargets {
                min_sdk: m.sdk.min_sdk,
                target_sdk: m.sdk.target_sdk,
                max_sdk: m.sdk.max_sdk,
                compile_sdk: m.sdk.compile_sdk,
                compile_sdk_codename: m.sdk.compile_sdk_codename,
                platform_build_version_code: m.sdk.platform_build_version_code,
                platform_build_version_name: m.sdk.platform_build_version_name,
                compile_minus_target: match (m.sdk.compile_sdk, m.sdk.target_sdk) {
                    (Some(c), Some(t)) => Some(c as i64 - t as i64),
                    _ => None,
                },
            };
        }
        Err(e) => tracing::warn!(error = %e, "manifest illisible, cibles d'API absentes"),
    }

    // Signature : bornes de validité des certificats.
    match cert::extract(apk_path) {
        Ok(c) => {
            r.signing_schemes = c.schemes.labels().iter().map(|s| s.to_string()).collect();
            for certificate in &c.certificates {
                r.signatures.push(SignatureDate {
                    source: certificate
                        .sources
                        .first()
                        .map(|s| s.label())
                        .unwrap_or_else(|| "?".into()),
                    subject_cn: certificate.subject_cn.clone(),
                    sha256: certificate.fingerprints.sha256.clone(),
                    not_before: certificate.not_before.clone(),
                    not_after: certificate.not_after.clone(),
                    validity_years: certificate.validity_years,
                });
            }
        }
        Err(e) => tracing::warn!(error = %e, "signature illisible, dates de cle absentes"),
    }

    // Archive : horodatages, DEX, versions de bibliothèques, métadonnées.
    match scan_archive(apk_path) {
        Ok(scan) => {
            r.archive = scan.timestamps;
            r.dex_files = scan.dex_files;
            r.library_versions = scan.library_versions;
            r.build_metadata = scan.build_metadata;
            r.code_dates = scan.code_dates;
        }
        Err(e) => tracing::warn!(error = %e, "archive illisible, horodatages absents"),
    }

    // Plancher de build, marqueurs de format uniquement.
    let mut floor: Option<u32> = None;
    for s in &r.signing_schemes {
        if let Some(a) = scheme_api_floor(s) {
            floor = Some(floor.map_or(a, |f: u32| f.max(a)));
        }
    }
    for d in &r.dex_files {
        if let Some(a) = d.api_floor {
            floor = Some(floor.map_or(a, |f: u32| f.max(a)));
        }
    }
    if let Some(c) = r.sdk.compile_sdk {
        floor = Some(floor.map_or(c, |f: u32| f.max(c)));
    }
    r.toolchain_floor_api = floor;

    tracing::info!(
        package = %r.package,
        target = ?r.sdk.target_sdk,
        compile = ?r.sdk.compile_sdk,
        floor = ?r.toolchain_floor_api,
        code_dates = r.code_dates.len(),
        "datation extraite"
    );
    Ok(r)
}

// ---------------------------------------------------------------------------
// Balayage de l'archive
// ---------------------------------------------------------------------------

struct ArchiveScan {
    timestamps: ArchiveTimestamps,
    dex_files: Vec<DexFormat>,
    library_versions: Vec<LibraryVersion>,
    build_metadata: Vec<BuildMetadata>,
    code_dates: Vec<CodeDate>,
}

/// Fichiers de métadonnées de build reconnus dans l'archive.
const BUILD_METADATA_ENTRIES: &[&str] = &[
    "kotlin-tooling-metadata.json",
    "META-INF/MANIFEST.MF",
    "META-INF/com/android/build/gradle/app-metadata.properties",
];

/// Taille max de contenu conservé pour un fichier de métadonnées.
const METADATA_MAX: usize = 4096;

fn scan_archive(apk_path: &Path) -> Result<ArchiveScan> {
    let file = std::fs::File::open(apk_path)
        .with_context(|| format!("ouverture {}", apk_path.display()))?;
    let mut zip = zip::ZipArchive::new(file).context("lecture de l'APK comme zip")?;

    let timestamps = archive_timestamps(&mut zip);

    let names: Vec<String> = (0..zip.len())
        .filter_map(|i| zip.by_index(i).ok().map(|e| e.name().to_string()))
        .collect();

    let mut dex_files = Vec::new();
    let mut library_versions = Vec::new();
    let mut build_metadata = Vec::new();
    // Dates agrégées sur l'ensemble des DEX, dédoublonnées.
    let mut date_counts: BTreeMap<String, usize> = BTreeMap::new();

    for name in &names {
        let is_dex = name.starts_with("classes") && name.ends_with(".dex");
        let is_lib_version = name.starts_with("META-INF/") && name.ends_with(".version");
        let is_metadata = BUILD_METADATA_ENTRIES.contains(&name.as_str());
        if !is_dex && !is_lib_version && !is_metadata {
            continue;
        }

        let mut buf = Vec::new();
        {
            let Ok(mut entry) = zip.by_name(name) else {
                continue;
            };
            if entry.read_to_end(&mut buf).is_err() {
                continue;
            }
        }

        if is_dex {
            if let Some(info) = dex_format(name, &buf, &mut date_counts) {
                dex_files.push(info);
            }
        } else if is_lib_version {
            let module = name
                .trim_start_matches("META-INF/")
                .trim_end_matches(".version")
                .to_string();
            let version = String::from_utf8_lossy(&buf).trim().to_string();
            if !version.is_empty() {
                library_versions.push(LibraryVersion { module, version });
            }
        } else {
            let mut content = String::from_utf8_lossy(&buf).to_string();
            content.truncate(METADATA_MAX);
            build_metadata.push(BuildMetadata {
                entry: name.clone(),
                content,
            });
        }
    }

    dex_files.sort_by(|a, b| a.entry.cmp(&b.entry));
    library_versions.sort_by(|a, b| a.module.cmp(&b.module));

    let mut code_dates: Vec<CodeDate> = date_counts
        .into_iter()
        .map(|(value, occurrences)| CodeDate { value, occurrences })
        .collect();
    code_dates.sort_by(|a, b| a.value.cmp(&b.value));

    Ok(ArchiveScan {
        timestamps,
        dex_files,
        library_versions,
        build_metadata,
        code_dates,
    })
}

// ---------------------------------------------------------------------------
// DEX : version de format et littéraux de date
// ---------------------------------------------------------------------------

/// Lit l'en-tête DEX et balaie le pool de chaînes.
///
/// Le pool est parcouru directement depuis l'en-tête (`string_ids_off`), sans
/// passer par un décodeur de bytecode : on ne cherche que des littéraux.
fn dex_format(
    entry: &str,
    buf: &[u8],
    date_counts: &mut BTreeMap<String, usize>,
) -> Option<DexFormat> {
    if buf.len() < 0x70 || &buf[0..4] != b"dex\n" {
        return None;
    }
    let format_version = String::from_utf8_lossy(&buf[4..7]).to_string();

    let string_ids_size = u32_le(buf, 0x38)? as usize;
    let string_ids_off = u32_le(buf, 0x3C)? as usize;

    let mut count = 0usize;
    for i in 0..string_ids_size {
        let Some(off) = u32_le(buf, string_ids_off + i * 4) else {
            break;
        };
        let Some(s) = read_dex_string(buf, off as usize) else {
            continue;
        };
        count += 1;
        if let Some(date) = find_iso_date(&s) {
            *date_counts.entry(date).or_insert(0) += 1;
        }
    }

    Some(DexFormat {
        entry: entry.to_string(),
        api_floor: dex_api_floor(&format_version),
        format_version,
        string_count: count,
    })
}

/// Lit un `string_data_item` : longueur ULEB128 en UTF-16, puis MUTF-8 terminé
/// par NUL. Le décodage est tolérant — on ne cherche que des motifs ASCII.
fn read_dex_string(buf: &[u8], off: usize) -> Option<String> {
    if off >= buf.len() {
        return None;
    }
    // Saut de la longueur ULEB128.
    let mut i = off;
    loop {
        let b = *buf.get(i)?;
        i += 1;
        if b & 0x80 == 0 {
            break;
        }
        if i - off > 5 {
            return None;
        }
    }
    let start = i;
    while *buf.get(i)? != 0 {
        i += 1;
        // Les littéraux utiles sont courts ; au-delà on abandonne.
        if i - start > 4096 {
            return None;
        }
    }
    Some(String::from_utf8_lossy(&buf[start..i]).to_string())
}

/// Cherche un motif `AAAA-MM-JJ` plausible dans une chaîne.
///
/// Bornes volontairement larges (2005-2035) : il s'agit d'écarter le bruit,
/// pas de valider une date. Le premier motif trouvé est retenu.
fn find_iso_date(s: &str) -> Option<String> {
    let b = s.as_bytes();
    if b.len() < 10 {
        return None;
    }
    for i in 0..=(b.len() - 10) {
        let w = &b[i..i + 10];
        if w[4] != b'-' || w[7] != b'-' {
            continue;
        }
        if !w[0..4].iter().all(u8::is_ascii_digit)
            || !w[5..7].iter().all(u8::is_ascii_digit)
            || !w[8..10].iter().all(u8::is_ascii_digit)
        {
            continue;
        }
        let year: u32 = std::str::from_utf8(&w[0..4]).ok()?.parse().ok()?;
        let month: u32 = std::str::from_utf8(&w[5..7]).ok()?.parse().ok()?;
        let day: u32 = std::str::from_utf8(&w[8..10]).ok()?.parse().ok()?;
        if !(2005..=2035).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day)
        {
            continue;
        }
        return Some(String::from_utf8_lossy(w).to_string());
    }
    None
}

/// Renvoie la version d'un module donné, si l'archive la porte.
///
/// Sert à extraire les quelques bibliothèques à fort pouvoir datant vers des
/// colonnes propres : la liste complète est illisible en tableur et reste
/// réservée au JSON.
pub fn library_version(libs: &[LibraryVersion], module: &str) -> Option<String> {
    libs.iter()
        .find(|l| l.module == module)
        .map(|l| l.version.clone())
}

/// Modules retenus comme proxys de datation, du plus au moins discriminant.
///
/// `androidx.core` et `material` suivent un cycle de publication régulier et
/// bornent bien le build ; `kotlinx-coroutines` distingue les builds récents.
pub const DATING_LIBRARIES: &[(&str, &str)] = &[
    ("lib_androidx_core", "androidx.core_core"),
    ("lib_appcompat", "androidx.appcompat_appcompat"),
    ("lib_material", "com.google.android.material_material"),
    ("lib_kotlinx_coroutines", "kotlinx_coroutines_core"),
];

fn u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let slice = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

/// SHA-256 du fichier entier, lu par blocs pour ne pas charger l'APK en mémoire.
fn file_sha256(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};

    let mut f =
        std::fs::File::open(path).with_context(|| format!("ouverture {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// Horodatages de l'archive
// ---------------------------------------------------------------------------

/// Agrège les horodatages des entrées de l'archive.
///
/// La lecture passe par le décodeur zip plutôt que par un parcours manuel du
/// central directory : les APK packés portent des variations d'en-tête qu'un
/// parcours naïf interprète mal, et un lot ne doit pas perdre silencieusement
/// une colonne parce qu'un octet ne se trouvait pas à la place attendue.
///
/// `entry_count` compte toutes les entrées, `dated_entry_count` seulement celles
/// qui portent une date. L'écart entre les deux distingue « rien lu » de
/// « dates volontairement omises » — deux situations qui se ressemblent dans un
/// CSV mais ne veulent pas dire la même chose.
fn archive_timestamps<R: std::io::Read + std::io::Seek>(
    zip: &mut zip::ZipArchive<R>,
) -> ArchiveTimestamps {
    let entry_count = zip.len();
    let mut stamps: Vec<String> = Vec::with_capacity(entry_count);

    for i in 0..entry_count {
        let Ok(entry) = zip.by_index(i) else {
            continue;
        };
        if let Some(dt) = entry.last_modified() {
            stamps.push(format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
                dt.year(),
                dt.month(),
                dt.day(),
                dt.hour(),
                dt.minute(),
                dt.second()
            ));
        }
    }

    let dated_entry_count = stamps.len();
    let mut distinct = stamps;
    distinct.sort();
    distinct.dedup();

    let earliest = distinct.first().cloned();
    let latest = distinct.last().cloned();
    let normalized = dated_entry_count > 1 && distinct.len() == 1;
    let sentinel = distinct
        .first()
        .and_then(|d| {
            SENTINELS
                .iter()
                .find(|(prefix, _)| d.starts_with(prefix))
                .map(|(_, desc)| (*desc).to_string())
        })
        .filter(|_| distinct.len() <= 2);

    ArchiveTimestamps {
        entry_count,
        dated_entry_count,
        earliest,
        latest,
        distinct_count: distinct.len(),
        normalized,
        sentinel,
    }
}

// ---------------------------------------------------------------------------
// Légende
// ---------------------------------------------------------------------------

/// Légende autonome : nature exacte de chaque indicateur, et ce qu'il borne.
pub fn legend() -> String {
    let mut s = String::new();
    s.push_str("Legende - indicateurs de datation\n");
    s.push_str("  Aucun champ n'est une date de build estimee. Chacun est une grandeur\n");
    s.push_str("  brute d'une nature precise, a correler en aval :\n\n");
    s.push_str("  BORNE BASSE (le build est posterieur)\n");
    s.push_str("    signatures[].not_before   generation de la CLE, pas du build ; une cle\n");
    s.push_str("                              sert des annees et couvre tout un editeur\n");
    s.push_str("    dex_files[].api_floor     API introduisant ce format DEX\n");
    s.push_str("                              (035:1, 037:24, 038:26, 039:28, 040:30)\n");
    s.push_str("    signing_schemes           v2:API 24, v3:API 28, v3.1:API 33\n");
    s.push_str("    sdk.compile_sdk           SDK effectivement installe au build\n");
    s.push_str("    library_versions[]        version exacte de la dependance ; croiser\n");
    s.push_str("                              avec sa date de publication\n");
    s.push_str("    toolchain_floor_api       maximum des planchers ci-dessus\n\n");
    s.push_str("  VALEUR EXACTE, MAIS FALSIFIABLE\n");
    s.push_str("    archive.latest            horodatage d'entree le plus recent - meilleur\n");
    s.push_str("                              proxy de build SI non normalise\n");
    s.push_str("    archive.normalized        vrai = toutes les entrees au meme horodatage\n");
    s.push_str("                              (build reproductible) : ne date plus rien\n");
    s.push_str("    archive.sentinel          constante reconnue (1980-01-01 = epoque zip,\n");
    s.push_str("                              2010-01-01 = outils Android)\n");
    s.push_str("    build_metadata[]          contenu brut, non interprete ; kotlin-tooling-\n");
    s.push_str("                              metadata.json porte AGP + Kotlin + JDK exacts\n\n");
    s.push_str("  INDICE SEULEMENT\n");
    s.push_str("    code_dates[]              litteraux AAAA-MM-JJ du pool de chaines DEX,\n");
    s.push_str("                              non contraints : jamais une preuve\n\n");
    s.push_str("  CIBLE DECLAREE (pas une date)\n");
    s.push_str("    sdk.target_sdk            niveau d'API dont les comportements s'appliquent\n");
    s.push_str("    sdk.compile_minus_target  compile_sdk - target_sdk ; les deux viennent de\n");
    s.push_str("                              la meme config de build, l'ecart mesure un choix\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn litteral_iso() {
        assert_eq!(
            find_iso_date("built on 2021-06-15 by ci").as_deref(),
            Some("2021-06-15")
        );
        assert_eq!(find_iso_date("version 1.2.3").as_deref(), None);
        // Hors bornes plausibles.
        assert_eq!(find_iso_date("1999-01-01").as_deref(), None);
        // Mois invalide.
        assert_eq!(find_iso_date("2021-13-01").as_deref(), None);
    }

    #[test]
    fn planchers_dex() {
        assert_eq!(dex_api_floor("039"), Some(28));
        assert_eq!(dex_api_floor("040"), Some(30));
        assert_eq!(dex_api_floor("zzz"), None);
    }

    #[test]
    fn selection_de_bibliotheque() {
        let libs = vec![
            LibraryVersion {
                module: "androidx.core_core".into(),
                version: "1.13.0".into(),
            },
            LibraryVersion {
                module: "androidx.appcompat_appcompat".into(),
                version: "1.7.1".into(),
            },
        ];
        assert_eq!(
            library_version(&libs, "androidx.core_core").as_deref(),
            Some("1.13.0")
        );
        assert_eq!(library_version(&libs, "absent"), None);
    }
}
