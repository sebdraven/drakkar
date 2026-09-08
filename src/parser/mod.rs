//! Parsing APK -> ApkFeatures + CallGraph.
//!
//! Un APK est une archive zip : on extrait les `classes*.dex` (parsés par le
//! crate `dex` + `dex-bytecode`) et les `lib/*/*.so` (parsés par LIEF, derrière
//! la feature `lief-backend`). Le manifest binaire est traité par `manifest`.
//!
//! Certaines familles trafiquent la structure ZIP pour casser les outils sans
//! gêner l'installation par Android. Quand le crate `zip` refuse l'archive, on
//! bascule sur `apkzip`, un lecteur tolérant calqué sur le chargeur d'APK.
pub mod apkzip;
pub mod cert;
pub mod dating;
pub mod dex;
pub mod dex_strings;
pub mod diff_dex;
pub mod diff_explain;
pub mod diff_matrix;
pub mod diff_strings;
pub mod disasm;
pub mod dyn_entrypoints;
pub mod elf;
pub mod entry_extract;
pub mod manifest;
pub mod manifest_info;
pub mod native_arch;
pub mod native_extract;

use crate::cfg::CallGraph;
use crate::model::ApkFeatures;
use anyhow::{Context, Result};
use std::io::Read;
use std::path::Path;

/// Résultat complet du parsing d'un APK.
pub struct ParsedApk {
    pub features: ApkFeatures,
    pub call_graph: CallGraph,
}

/// Point d'entrée : parse un APK et construit features + CFG inter-proc.
pub fn parse_apk(path: &Path) -> Result<ParsedApk> {
    tracing::info!(apk = %path.display(), "parsing APK");

    let mut features = ApkFeatures::default();
    let mut call_graph = CallGraph::new();

    // Tempdir pour matérialiser les .dex et .so extraits de l'archive.
    let tmp = tempfile::tempdir().context("create tempdir")?;
    let entries = extract_apk(path, tmp.path())?;

    // Manifest (axml) — opère directement sur l'APK.
    manifest::extract(path, &mut features)?;

    // DEX : chaque classes*.dex -> edges inter-proc accumulés dans le même graphe.
    for dex_path in &entries.dex_files {
        let edges = dex::extract(dex_path, &mut features)
            .with_context(|| format!("parse {}", dex_path.display()))?;
        for e in edges {
            call_graph.add_call(e.caller, e.callee, e.site);
        }
    }

    // ELF natifs : symboles des .so.
    for so_path in &entries.so_files {
        elf::extract(so_path, &mut features)
            .with_context(|| format!("parse {}", so_path.display()))?;
    }

    // Architecture native (pur en-tête ELF, en mémoire — indépendant de LIEF).
    // Conditionne la convention d'appel côté SE (Kharon) : arm=AArch32/Thumb,
    // arm64=AAPCS64. Deuxième passe zip header-only, coût négligeable.
    features.native_arch = native_arch::scan_apk_file(path).context("scan arch native")?;
    tracing::info!(
        abis = ?features.native_arch.abis,
        fat = features.native_arch.is_fat,
        anomalies = features.native_arch.anomalies.len(),
        "native arch"
    );

    Ok(ParsedApk { features, call_graph })
}

/// Fichiers d'intérêt extraits de l'APK.
struct ApkEntries {
    dex_files: Vec<std::path::PathBuf>,
    so_files: Vec<std::path::PathBuf>,
}

/// Vrai si l'entrée nous intéresse : un `classes*.dex` ou un `lib/**/*.so`.
fn wanted(name: &str) -> (bool, bool) {
    let is_dex = name.starts_with("classes") && name.ends_with(".dex");
    let is_so = name.starts_with("lib/") && name.ends_with(".so");
    (is_dex, is_so)
}

/// Dézippe l'APK : écrit les classes*.dex et lib/**/*.so dans `out_dir`.
///
/// Chemin nominal via le crate `zip`. On retombe sur le lecteur tolérant dès
/// qu'il refuse quoi que ce soit — l'archive à l'ouverture, mais aussi une
/// entrée à la lecture : le drapeau de chiffrement et la méthode de compression
/// ne sont contrôlés qu'à ce moment, et c'est là que le trafiquage frappe.
fn extract_apk(apk: &Path, out_dir: &Path) -> Result<ApkEntries> {
    let file = std::fs::File::open(apk).with_context(|| format!("open {}", apk.display()))?;
    let mut zip = match zip::ZipArchive::new(file) {
        Ok(z) => z,
        Err(e) => {
            tracing::warn!(
                apk = %apk.display(),
                error = %e,
                "crate zip en échec, repli sur le lecteur tolérant"
            );
            return extract_apk_tolerant(apk, out_dir);
        }
    };

    let mut dex_files = Vec::new();
    let mut so_files = Vec::new();

    for i in 0..zip.len() {
        let mut entry = match zip.by_index(i) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    apk = %apk.display(),
                    index = i,
                    error = %e,
                    "entrée refusée par le crate zip, repli sur le lecteur tolérant"
                );
                return extract_apk_tolerant(apk, out_dir);
            }
        };
        let name = entry.name().to_string();

        let (is_dex, is_so) = wanted(&name);
        if !is_dex && !is_so {
            continue;
        }

        // Nom de fichier de sortie aplati (lib/arm64-v8a/foo.so -> arm64-v8a__foo.so).
        let flat = name.replace('/', "__");
        let dest = out_dir.join(&flat);
        let mut buf = Vec::with_capacity(entry.size() as usize);
        let read = entry.read_to_end(&mut buf);
        drop(entry);
        if let Err(e) = read {
            tracing::warn!(
                apk = %apk.display(),
                entry = %name,
                error = %e,
                "lecture d'entrée en échec, repli sur le lecteur tolérant"
            );
            return extract_apk_tolerant(apk, out_dir);
        }
        std::fs::write(&dest, &buf)?;

        if is_dex {
            dex_files.push(dest);
        } else {
            so_files.push(dest);
        }
    }

    tracing::info!(
        dex = dex_files.len(),
        so = so_files.len(),
        "APK extracted"
    );
    Ok(ApkEntries { dex_files, so_files })
}

/// Repli quand le crate `zip` refuse l'archive : lecteur calqué sur le
/// chargeur d'APK d'Android (cf. `apkzip`). Une entrée illisible est ignorée
/// plutôt que de faire échouer l'extraction complète.
fn extract_apk_tolerant(apk: &Path, out_dir: &Path) -> Result<ApkEntries> {
    let zip = apkzip::TolerantZip::open(apk)
        .with_context(|| format!("lecteur tolérant sur {}", apk.display()))?;
    tracing::warn!(
        entries = zip.len(),
        tampered = zip.tampered_count(),
        "lecteur tolérant actif"
    );

    let mut dex_files = Vec::new();
    let mut so_files = Vec::new();

    for (i, entry) in zip.entries().iter().enumerate() {
        let name = &entry.name;
        let (is_dex, is_so) = wanted(name);
        if !is_dex && !is_so {
            continue;
        }

        // Les noms trafiqués peuvent contenir n'importe quoi : on aplatit et on
        // refuse toute tentative de sortie du répertoire de destination.
        let flat = name.replace('/', "__").replace("..", "__");
        if flat.is_empty() || flat.starts_with('/') {
            tracing::warn!(entry = %name, "nom d'entrée refusé");
            continue;
        }

        let buf = match zip.read(i) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(entry = %name, error = %e, "entrée illisible, ignorée");
                continue;
            }
        };

        let dest = out_dir.join(&flat);
        std::fs::write(&dest, &buf)?;

        if is_dex {
            dex_files.push(dest);
        } else {
            so_files.push(dest);
        }
    }

    tracing::info!(
        dex = dex_files.len(),
        so = so_files.len(),
        "APK extracted (lecteur tolérant)"
    );
    Ok(ApkEntries { dex_files, so_files })
}
