//! Parsing AndroidManifest.xml (format binaire AXML) depuis l'APK via
//! `parser::axml` : permissions, intent actions, services (dont accessibility)
//! -> ApkFeatures.
use crate::model::{ApkFeatures, ServiceDecl};
use crate::parser::axml::{self, Element};
use anyhow::{Context, Result};
use std::io::Read;
use std::path::Path;

const MANIFEST: &str = "AndroidManifest.xml";

/// Une archive sans `AndroidManifest.xml` (JAR, APK amputé) laisse les features
/// du manifest vides : les règles tournent quand même, sans entrypoint validé.
pub fn extract(apk_path: &Path, features: &mut ApkFeatures) -> Result<()> {
    let Some(raw) = read_manifest_bytes(apk_path)? else {
        tracing::warn!(
            apk = %apk_path.display(),
            "AndroidManifest.xml absent de l'archive — manifest features vides"
        );
        return Ok(());
    };
    let root = match axml::decode(&raw) {
        Ok(decoded) => decoded.root,
        Err(e) => {
            tracing::warn!(
                apk = %apk_path.display(),
                error = %e,
                "AXML illisible, y compris par le décodeur tolérant — manifest features vides"
            );
            return Ok(());
        }
    };
    walk(&root, features);

    tracing::info!(
        package = %features.package,
        permissions = features.permissions.len(),
        services = features.services.len(),
        intent_actions = features.intent_actions.len(),
        "manifest extracted"
    );
    Ok(())
}

/// Extrait les octets de l'entrée AndroidManifest.xml de l'archive APK.
///
/// Même repli que `parser::extract_apk` : le crate `zip` ne contrôle le drapeau
/// de chiffrement et la méthode de compression qu'à la lecture de l'entrée, pas
/// à l'ouverture de l'archive. Sur les APK trafiqués, l'ouverture passe et c'est
/// `by_name` ou `read_to_end` qui échoue. `None` : le central directory, lu par
/// le lecteur tolérant, ne porte aucune entrée de ce nom.
fn read_manifest_bytes(apk_path: &Path) -> Result<Option<Vec<u8>>> {
    let file =
        std::fs::File::open(apk_path).with_context(|| format!("open {}", apk_path.display()))?;

    let nominal = (|| -> Result<Vec<u8>> {
        let mut zip = zip::ZipArchive::new(file).context("read apk as zip")?;
        let mut entry = zip
            .by_name(MANIFEST)
            .context("AndroidManifest.xml not found in APK")?;
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf)?;
        Ok(buf)
    })();

    match nominal {
        Ok(buf) => Ok(Some(buf)),
        Err(e) => {
            tracing::warn!(
                apk = %apk_path.display(),
                error = %e,
                "manifest illisible par le crate zip, repli sur le lecteur tolérant"
            );
            let zip = super::apkzip::TolerantZip::open(apk_path)?;
            if !zip.entries().iter().any(|entry| entry.name == MANIFEST) {
                return Ok(None);
            }
            zip.read_by_name(MANIFEST)
                .map(Some)
                .context("AndroidManifest.xml illisible, y compris par le lecteur tolérant")
        }
    }
}

/// Parcours récursif de l'arbre XML pour collecter les features.
fn walk(elem: &Element, features: &mut ApkFeatures) {
    match elem.get_tag() {
        "manifest" => {
            if let Some(pkg) = elem.attr("package") {
                features.package = pkg;
            }
        }
        "uses-permission" | "uses-permission-sdk-23" => {
            if let Some(name) = elem.attr("name") {
                features.permissions.push(name);
            }
        }
        "action" => {
            if let Some(name) = elem.attr("name") {
                features.intent_actions.push(name);
            }
        }
        "service" => {
            features.services.push(parse_service(elem));
            if let Some(cls) = component_class(elem, &features.package) {
                features.components.push(cls);
            }
        }
        "activity" | "activity-alias" | "receiver" | "provider" | "application" => {
            if let Some(cls) = component_class(elem, &features.package) {
                features.components.push(cls);
            }
        }
        _ => {}
    }

    for child in elem.get_children() {
        walk(child, features);
    }
}

/// Résout le `android:name` d'un composant en descripteur Dalvik `Lcom/foo/Bar;`.
/// Gère les noms relatifs (`.MyService` ou `MyService` -> package + nom).
fn component_class(elem: &Element, package: &str) -> Option<String> {
    let name = elem.attr("name")?;
    let fqcn = if let Some(stripped) = name.strip_prefix('.') {
        format!("{package}.{stripped}")
    } else if name.contains('.') {
        name
    } else {
        // Nom simple sans point : relatif au package (cas application/activity courts).
        format!("{package}.{name}")
    };
    Some(format!("L{};", fqcn.replace('.', "/")))
}

/// Construit un ServiceDecl, en détectant le binding accessibility.
fn parse_service(elem: &Element) -> ServiceDecl {
    let name = elem.attr("name").unwrap_or_default();
    let permission = elem.attr("permission");
    let is_accessibility = permission
        .as_deref()
        .map(|p| p.contains("BIND_ACCESSIBILITY_SERVICE"))
        .unwrap_or(false);

    // Actions des intent-filters enfants (ex. BIND d'accessibility / notification listener).
    let mut intent_actions = Vec::new();
    collect_child_actions(elem, &mut intent_actions);
    let is_accessibility = is_accessibility
        || intent_actions
            .iter()
            .any(|a| a.contains("accessibilityservice.AccessibilityService"));

    ServiceDecl {
        name,
        permission,
        is_accessibility,
        intent_actions,
    }
}

/// Collecte les <action> sous un élément (via ses intent-filters).
fn collect_child_actions(elem: &Element, out: &mut Vec<String>) {
    for child in elem.get_children() {
        if child.get_tag() == "action" {
            if let Some(name) = child.attr("name") {
                out.push(name);
            }
        }
        collect_child_actions(child, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    #[test]
    fn archive_without_manifest_leaves_features_empty() {
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("sample.jar");
        let mut zw = zip::ZipWriter::new(std::fs::File::create(&jar).unwrap());
        zw.start_file("classes.dex", SimpleFileOptions::default())
            .unwrap();
        zw.write_all(b"dex\n035\0").unwrap();
        zw.finish().unwrap();

        let mut features = ApkFeatures::default();
        extract(&jar, &mut features).unwrap();
        assert!(features.package.is_empty());
        assert!(features.components.is_empty());
        assert!(features.permissions.is_empty());
    }
}
