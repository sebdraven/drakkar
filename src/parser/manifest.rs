//! Parsing AndroidManifest.xml (format binaire AXML) depuis l'APK via `axmldecoder` :
//! permissions, intent actions, services (dont accessibility) -> ApkFeatures.
use crate::model::{ApkFeatures, ServiceDecl};
use anyhow::{Context, Result};
use axmldecoder::{Element, Node, XmlDocument};
use std::io::Read;
use std::path::Path;

pub fn extract(apk_path: &Path, features: &mut ApkFeatures) -> Result<()> {
    let raw = read_manifest_bytes(apk_path)?;
    let doc: XmlDocument = match axmldecoder::parse(&raw) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "AXML parse failed — manifest features vides");
            return Ok(());
        }
    };

    if let Some(root) = doc.get_root() {
        if let Node::Element(root_elem) = root {
            walk(root_elem, features);
        }
    }

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
fn read_manifest_bytes(apk_path: &Path) -> Result<Vec<u8>> {
    let file = std::fs::File::open(apk_path)
        .with_context(|| format!("open {}", apk_path.display()))?;
    let mut zip = zip::ZipArchive::new(file).context("read apk as zip")?;
    let mut entry = zip
        .by_name("AndroidManifest.xml")
        .context("AndroidManifest.xml not found in APK")?;
    let mut buf = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Parcours récursif de l'arbre XML pour collecter les features.
fn walk(elem: &Element, features: &mut ApkFeatures) {
    match elem.get_tag() {
        "manifest" => {
            if let Some(pkg) = attr(elem, "package") {
                features.package = pkg;
            }
        }
        "uses-permission" | "uses-permission-sdk-23" => {
            if let Some(name) = attr_name(elem) {
                features.permissions.push(name);
            }
        }
        "action" => {
            if let Some(name) = attr_name(elem) {
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
        if let Node::Element(child_elem) = child {
            walk(child_elem, features);
        }
    }
}

/// Résout le `android:name` d'un composant en descripteur Dalvik `Lcom/foo/Bar;`.
/// Gère les noms relatifs (`.MyService` ou `MyService` -> package + nom).
fn component_class(elem: &Element, package: &str) -> Option<String> {
    let name = attr_name(elem)?;
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
    let name = attr_name(elem).unwrap_or_default();
    let permission = attr(elem, "permission");
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
        if let Node::Element(child_elem) = child {
            if child_elem.get_tag() == "action" {
                if let Some(name) = attr_name(child_elem) {
                    out.push(name);
                }
            }
            collect_child_actions(child_elem, out);
        }
    }
}

/// Récupère un attribut par nom exact ou suffixe (gère le préfixe `android:`).
fn attr(elem: &Element, key: &str) -> Option<String> {
    let attrs = elem.get_attributes();
    if let Some(v) = attrs.get(key) {
        return Some(v.clone());
    }
    attrs
        .iter()
        .find(|(k, _)| k.split(':').last() == Some(key))
        .map(|(_, v)| v.clone())
}

/// Raccourci pour l'attribut `name` (souvent `android:name`).
fn attr_name(elem: &Element) -> Option<String> {
    attr(elem, "name")
}
