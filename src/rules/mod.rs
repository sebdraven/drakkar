//! Moteur de règles MITRE (DSL composable style capa).
pub mod schema;

use crate::cfg::CallGraph;
use crate::model::ApkFeatures;
use anyhow::{Context, Result};
use schema::{Feature, Rule};
use std::fs;
use std::path::Path;

#[derive(Debug, serde::Serialize)]
pub struct Match {
    pub id: String,
    pub name: String,
    pub tactic: String,
    /// Ce qui a effectivement déclenché la détection (permissions, API, strings…).
    pub evidence: Vec<Evidence>,
}

/// Une preuve atomique : le type de feature qui a maté et la valeur observée
/// dans l'APK. Permet de justifier chaque détection (traçabilité, anti-boîte-noire).
#[derive(Debug, Clone, serde::Serialize)]
pub struct Evidence {
    /// Type de preuve : "permission", "api", "string", "intent-action",
    /// "service", "accessibility-service", "native-symbol".
    pub kind: String,
    /// Valeur exacte trouvée dans l'APK (la permission déclarée, l'API résolue…).
    pub value: String,
    /// Pour les preuves de type API : atteignabilité depuis un entrypoint manifest.
    /// None pour les preuves non-API (permission, string…).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachable: Option<bool>,
    /// Chemins entrypoint -> ... -> API (vide si non atteignable ou non-API).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<Vec<String>>,
}

impl Evidence {
    /// Preuve non-API (permission, string, service…) : pas de reachability.
    fn simple(kind: &str, value: String) -> Self {
        Evidence { kind: kind.into(), value, reachable: None, paths: Vec::new() }
    }
    /// Preuve API : reachability calculée ultérieurement (enrich_reachability).
    fn api(value: String) -> Self {
        Evidence { kind: "api".into(), value, reachable: None, paths: Vec::new() }
    }
}

pub struct Engine {
    rules: Vec<Rule>,
}

impl Engine {
    /// Charge tous les *.yaml d'un répertoire de règles.
    pub fn load(dir: &Path) -> Result<Self> {
        let mut rules = Vec::new();
        for entry in fs::read_dir(dir).with_context(|| format!("read_dir {}", dir.display()))? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                let raw = fs::read_to_string(&path)?;
                let r: Rule = serde_yaml::from_str(&raw)
                    .with_context(|| format!("parse rule {}", path.display()))?;
                tracing::info!(rule = %r.meta.id, "rule loaded");
                rules.push(r);
            }
        }
        Ok(Self { rules })
    }

    pub fn run(&self, features: &ApkFeatures, cg: &CallGraph) -> Vec<Match> {
        self.rules
            .iter()
            .filter(|r| eval(&r.features, features, cg))
            .map(|r| Match {
                id: r.meta.id.clone(),
                name: r.meta.name.clone(),
                tactic: r.meta.tactic.clone(),
                confirmed: false,
            })
            .collect()
    }
}

fn eval(f: &Feature, feat: &ApkFeatures, cg: &CallGraph) -> bool {
    match f {
        Feature::And(xs) => xs.iter().all(|x| eval(x, feat, cg)),
        Feature::Or(xs) => xs.iter().any(|x| eval(x, feat, cg)),
        Feature::Not(x) => !eval(x, feat, cg),
        Feature::Count { feature, min } => {
            count_matches(feature, feat, cg) >= *min
        }
        Feature::Sequence(xs) => eval_sequence(xs, cg),
        Feature::Api(a) => cg.has_api(a) || feat.methods.iter().any(|m| m.api().contains(a)),
        Feature::String(s) => feat.strings.iter().any(|x| x.contains(s)),
        Feature::Permission(p) => feat.permissions.iter().any(|x| x == p),
        Feature::IntentAction(a) => feat.intent_actions.iter().any(|x| x == a),
        Feature::NativeSymbol(s) => feat.native_symbols.iter().any(|x| x.contains(s)),
    }
}

/// Séquence ordonnée : chaque étape (api) doit être atteignable depuis la précédente.
fn eval_sequence(steps: &[Feature], cg: &CallGraph) -> bool {
    let apis: Vec<&str> = steps
        .iter()
        .filter_map(|s| match s {
            Feature::Api(a) => Some(a.as_str()),
            _ => None,
        })
        .collect();
    if apis.len() < 2 {
        return apis.iter().all(|a| cg.has_api(a));
    }
    apis.windows(2).all(|w| cg.reaches(w[0], w[1]))
}

fn count_matches(f: &Feature, feat: &ApkFeatures, cg: &CallGraph) -> usize {
    match f {
        Feature::Permission(p) => feat.permissions.iter().filter(|x| *x == p).count(),
        Feature::Api(a) => feat.methods.iter().filter(|m| m.api().contains(a)).count(),
        other => eval(other, feat, cg) as usize,
    }
}
