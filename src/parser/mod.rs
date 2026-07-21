//! Parsing APK -> ApkFeatures + CallGraph.
//!
//! Un APK est une archive zip : on extrait les `classes*.dex` (parsés par le
//! crate `dex` + `dex-bytecode`) et les `lib/*/*.so` (parsés par LIEF, derrière
//! la feature `lief-backend`). Le manifest binaire est traité par `manifest`.
pub mod cert;
pub mod dex;
pub mod elf;
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

/// Dézippe l'APK : écrit les classes*.dex et lib/**/*.so dans `out_dir`.
fn extract_apk(apk: &Path, out_dir: &Path) -> Result<ApkEntries> {
    let file = std::fs::File::open(apk).with_context(|| format!("open {}", apk.display()))?;
    let mut zip = zip::ZipArchive::new(file).context("read apk as zip")?;

    let mut dex_files = Vec::new();
    let mut so_files = Vec::new();

    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name().to_string();

        let is_dex = name.starts_with("classes") && name.ends_with(".dex");
        let is_so = name.starts_with("lib/") && name.ends_with(".so");
        if !is_dex && !is_so {
            continue;
        }

        // Nom de fichier de sortie aplati (lib/arm64-v8a/foo.so -> arm64-v8a__foo.so).
        let flat = name.replace('/', "__");
        let dest = out_dir.join(&flat);
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf)?;
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
