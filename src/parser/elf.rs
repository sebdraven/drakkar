//! Parsing des .so natifs (extraits de lib/*/*.so) via LIEF ELF :
//! symboles exportés/importés -> features.native_symbols.
//!
//! Sans la feature `lief-backend`, c'est un no-op (les .so sont ignorés).
use crate::model::ApkFeatures;
use anyhow::Result;
use std::path::Path;

#[cfg(not(feature = "lief-backend"))]
pub fn extract(_so_path: &Path, _features: &mut ApkFeatures) -> Result<()> {
    tracing::debug!("ELF stub (compile sans lief-backend) — .so ignoré");
    Ok(())
}

#[cfg(feature = "lief-backend")]
pub fn extract(so_path: &Path, features: &mut ApkFeatures) -> Result<()> {
    // TODO(lief): lief::elf::Binary::parse(so_path) -> dynamic_symbols()
    // pousser les Java_* et symboles d'intérêt dans features.native_symbols.
    tracing::info!(so = %so_path.display(), "ELF extract (lief-backend) — à implémenter");
    let _ = features;
    Ok(())
}
