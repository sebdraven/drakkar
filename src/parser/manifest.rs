//! Parsing AndroidManifest.xml (format binaire AXML) depuis l'APK :
//! permissions, intent filters, services (dont accessibility) -> ApkFeatures.
//!
//! Implémentation à venir via un décodeur AXML dédié (ex. crate `axmldecoder`),
//! le manifest binaire n'étant couvert ni par `dex` ni nécessairement par LIEF.
use crate::model::ApkFeatures;
use anyhow::Result;
use std::path::Path;

pub fn extract(apk_path: &Path, features: &mut ApkFeatures) -> Result<()> {
    // TODO(axml): ouvrir l'entrée "AndroidManifest.xml" du zip APK, décoder l'AXML,
    // extraire <uses-permission>, <intent-filter><action>, <service> (+ flag
    // android:permission=BIND_ACCESSIBILITY_SERVICE) vers `features`.
    tracing::debug!(apk = %apk_path.display(), "manifest stub — features manifest vides");
    let _ = features;
    Ok(())
}
