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
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct BulkOptions {
    /// Répertoire de sortie des `<stem>.json` (créé si absent).
    pub out_dir: PathBuf,
    /// Parcours récursif des sous-répertoires.
    pub recursive: bool,
    /// Ré-analyse même si le JSON de sortie existe déjà.
    pub overwrite: bool,
}

/// Analyse tous les `.apk` de `input_dir` et écrit un `<stem>.json` par APK dans
/// `opts.out_dir`. Le nom de sortie reprend le nom de fichier de l'APK sans
/// extension : pour un dataset nommé par hash, `<sha256>.apk` -> `<sha256>.json`.
///
/// Le contenu de chaque JSON est identique au mode single (`Vec<Match>` sérialisé),
/// pour que les scripts de post-traitement voient le même format dans les deux modes.
pub fn run(input_dir: &Path, engine: &Engine, opts: &BulkOptions) -> Result<()> {
    std::fs::create_dir_all(&opts.out_dir)?;

    let apks = collect_apks(input_dir, opts.recursive)?;
    if apks.is_empty() {
        anyhow::bail!("aucun .apk trouvé dans {}", input_dir.display());
    }
    tracing::info!(count = apks.len(), out = %opts.out_dir.display(), "bulk: démarrage");

    let ok = AtomicUsize::new(0);
    let failed = AtomicUsize::new(0);
    let skipped = AtomicUsize::new(0);

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

/// Collecte les fichiers `.apk` d'un répertoire (récursif optionnel), triés pour
/// un ordre de traitement déterministe.
fn collect_apks(dir: &Path, recursive: bool) -> Result<Vec<PathBuf>> {
    let mut apks = Vec::new();
    if recursive {
        for entry in walkdir::WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            let p = entry.path();
            if p.is_file() && has_apk_ext(p) {
                apks.push(p.to_path_buf());
            }
        }
    } else {
        for entry in std::fs::read_dir(dir)? {
            let p = entry?.path();
            if p.is_file() && has_apk_ext(&p) {
                apks.push(p);
            }
        }
    }
    apks.sort();
    Ok(apks)
}

fn has_apk_ext(p: &Path) -> bool {
    p.extension()
        .map_or(false, |e| e.eq_ignore_ascii_case("apk"))
}
