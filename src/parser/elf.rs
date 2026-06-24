//! Parsing des .so natifs (lib/*/*.so) via LIEF ELF : symboles exportés/importés.
use crate::model::ApkFeatures;
use anyhow::Result;
use std::path::Path;

#[cfg(not(feature = "lief-backend"))]
pub fn extract(_path: &Path, features: &mut ApkFeatures) -> Result<()> {
    tracing::warn!("ELF stub — 0 symbole natif");
    features.native_symbols.clear();
    Ok(())
}

#[cfg(feature = "lief-backend")]
pub fn extract(path: &Path, features: &mut ApkFeatures) -> Result<()> {
    // TODO(lief): unzip lib/**/*.so -> lief::elf::parse -> dynamic_symbols()
    // pousser les Java_* et symboles d'intérêt dans features.native_symbols.
    tracing::info!(apk = %path.display(), "ELF extract (lief-backend) — à implémenter");
    let _ = features;
    Ok(())
}
