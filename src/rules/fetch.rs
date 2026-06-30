//! Auto-update du catalogue MITRE ATT&CK Mobile.
//!
//! Au premier lancement (cache absent) ou sur `--refresh`, télécharge le bundle
//! STIX 2.1 le plus récent depuis le dépôt officiel, en extrait les techniques
//! Android, fusionne chaque technique avec sa logique de détection embarquée
//! (`catalog::detection_for`), et écrit un fichier YAML par technique dans le
//! cache local. Les lancements suivants lisent directement le cache.
use super::catalog;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// URL du bundle STIX Mobile sans marquage de version : suit toujours la
/// dernière release publiée par MITRE.
const STIX_URL: &str =
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json";

/// Répertoire de cache des règles : ~/.cache/drakkar/rules/
pub fn cache_dir() -> Result<PathBuf> {
    let base = dirs::cache_dir().context("cannot resolve user cache dir")?;
    Ok(base.join("drakkar").join("rules"))
}

/// S'assure que le cache existe ; le génère s'il est absent ou si `refresh`.
/// Retourne le répertoire des règles prêt à charger.
pub fn ensure_cache(refresh: bool) -> Result<PathBuf> {
    let dir = cache_dir()?;
    let populated = dir.is_dir()
        && std::fs::read_dir(&dir)
            .map(|mut it| it.any(|e| {
                e.ok()
                    .map(|e| e.path().extension().and_then(|x| x.to_str()) == Some("yaml"))
                    .unwrap_or(false)
            }))
            .unwrap_or(false);

    if populated && !refresh {
        tracing::info!(dir = %dir.display(), "rules cache hit");
        return Ok(dir);
    }

    tracing::info!(refresh, "generating rules cache from MITRE STIX");
    generate_cache(&dir)?;
    Ok(dir)
}

/// Télécharge le STIX, fusionne avec le catalogue, écrit les YAML.
fn generate_cache(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;

    tracing::info!(url = STIX_URL, "downloading MITRE ATT&CK Mobile STIX");
    let bundle: StixBundle = ureq::get(STIX_URL)
        .call()
        .context("download STIX bundle")?
        .into_json()
        .context("parse STIX JSON")?;

    let techniques = extract_android_techniques(&bundle);
    let mut static_count = 0usize;
    let mut oos_count = 0usize;

    for t in &techniques {
        let detectability;
        let features_block;
        if let Some(block) = catalog::detection_for(&t.id) {
            detectability = "static";
            features_block = block.to_string();
            static_count += 1;
        } else {
            detectability = "out-of-scope";
            features_block = format!(
                "  unsupported: \"Not statically detectable from APK package contents\""
            );
            oos_count += 1;
        }

        let yaml = render_rule_yaml(t, detectability, &features_block);
        let fname = format!("{}.yaml", t.id.replace('.', "_"));
        std::fs::write(dir.join(&fname), yaml)
            .with_context(|| format!("write {fname}"))?;
    }

    tracing::info!(
        total = techniques.len(),
        static_rules = static_count,
        out_of_scope = oos_count,
        version = %bundle.version_label(),
        "rules cache generated"
    );
    Ok(())
}

/// Sérialise une règle au format YAML attendu par le loader.
fn render_rule_yaml(t: &Technique, detectability: &str, features_block: &str) -> String {
    let all_tactics = t.tactics.join(", ");
    let platforms = t.platforms.join(", ");
    let primary = t.tactics.first().map(String::as_str).unwrap_or("unknown");
    format!(
        "meta:\n  id: {id}\n  name: \"{name}\"\n  tactic: {primary}\n  \
         all_tactics: [{all_tactics}]\n  platforms: [{platforms}]\n  \
         detectability: {detectability}\n  references:\n    - {url}\n  \
         authors:\n    - sebastien.larinier\nfeatures:\n{features}\n",
        id = t.id,
        name = t.name.replace('"', "'"),
        primary = primary,
        all_tactics = all_tactics,
        platforms = platforms,
        detectability = detectability,
        url = t.url,
        features = features_block,
    )
}

// ───────────────────────────── STIX parsing ─────────────────────────────

#[derive(Debug, Deserialize)]
struct StixBundle {
    objects: Vec<StixObject>,
}

impl StixBundle {
    /// Extrait un label de version depuis l'objet x-mitre-collection, si présent.
    fn version_label(&self) -> String {
        self.objects
            .iter()
            .find(|o| o.obj_type == "x-mitre-collection")
            .and_then(|o| o.version.clone())
            .unwrap_or_else(|| "unknown".into())
    }
}

#[derive(Debug, Deserialize)]
struct StixObject {
    #[serde(rename = "type")]
    obj_type: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    revoked: bool,
    #[serde(default, rename = "x_mitre_deprecated")]
    deprecated: bool,
    #[serde(default, rename = "x_mitre_platforms")]
    platforms: Vec<String>,
    #[serde(default, rename = "x_mitre_version")]
    version: Option<String>,
    #[serde(default)]
    kill_chain_phases: Vec<KillChainPhase>,
    #[serde(default)]
    external_references: Vec<ExternalRef>,
}

#[derive(Debug, Deserialize)]
struct KillChainPhase {
    phase_name: String,
}

#[derive(Debug, Deserialize)]
struct ExternalRef {
    #[serde(default)]
    source_name: String,
    #[serde(default)]
    external_id: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

/// Technique Android normalisée, prête à rendre en YAML.
struct Technique {
    id: String,
    name: String,
    tactics: Vec<String>,
    platforms: Vec<String>,
    url: String,
}

/// Filtre les attack-patterns Android actifs et les normalise.
fn extract_android_techniques(bundle: &StixBundle) -> Vec<Technique> {
    let mut out = Vec::new();
    for obj in &bundle.objects {
        if obj.obj_type != "attack-pattern" || obj.revoked || obj.deprecated {
            continue;
        }
        if !obj.platforms.iter().any(|p| p == "Android") {
            continue;
        }
        let mitre_ref = obj
            .external_references
            .iter()
            .find(|r| r.source_name == "mitre-attack");
        let (id, url) = match mitre_ref {
            Some(r) => match (&r.external_id, &r.url) {
                (Some(id), Some(url)) => (id.clone(), url.clone()),
                (Some(id), None) => (id.clone(), String::new()),
                _ => continue,
            },
            None => continue,
        };
        out.push(Technique {
            id,
            name: obj.name.clone().unwrap_or_default(),
            tactics: obj.kill_chain_phases.iter().map(|p| p.phase_name.clone()).collect(),
            platforms: obj.platforms.clone(),
            url,
        });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}
