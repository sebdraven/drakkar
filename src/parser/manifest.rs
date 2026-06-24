//! Parsing AndroidManifest.xml (binaire) via LIEF Android : permissions,
//! intent filters, services (dont accessibility).
use crate::model::ApkFeatures;
use anyhow::Result;
use std::path::Path;

#[cfg(not(feature = "lief-backend"))]
pub fn extract(_path: &Path, features: &mut ApkFeatures) -> Result<()> {
    tracing::warn!("manifest stub — features vides");
    features.package = "com.example.stub".into();
    Ok(())
}

#[cfg(feature = "lief-backend")]
pub fn extract(path: &Path, features: &mut ApkFeatures) -> Result<()> {
    // TODO(lief): décoder le manifest binaire (axml) -> permissions,
    // <intent-filter><action>, <service> + flag accessibilityService.
    tracing::info!(apk = %path.display(), "manifest extract (lief-backend) — à implémenter");
    let _ = features;
    Ok(())
}
