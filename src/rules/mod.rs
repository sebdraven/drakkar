//! Moteur de règles MITRE (DSL composable style capa).
pub mod catalog;
pub mod fetch;
pub mod schema;

use crate::cfg::{CallGraph, PivotConstraints};
use crate::model::ApkFeatures;
use anyhow::{Context, Result};
use petgraph::graph::NodeIndex;
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
    /// "service", "accessibility-service", "native-symbol", "co-reachable",
    /// "intimacy".
    pub kind: String,
    /// Valeur exacte trouvée dans l'APK (la permission déclarée, l'API résolue…).
    pub value: String,
    /// Pour les preuves de type API : atteignabilité depuis un entrypoint manifest.
    /// None pour les preuves non-API (permission, string…).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachable: Option<bool>,
    /// Score continu pour les preuves "intimacy" (None sinon). Exposé pour tri et
    /// calibration de seuil en post-traitement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    /// Pour les preuves API : sauts min entrypoint -> API (-1 si non atteignable).
    /// None pour les preuves non-API.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<i64>,
    /// Pour les preuves API : nombre de call-sites appelant directement l'API.
    /// None pour les preuves non-API.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fanin: Option<usize>,
    /// Chemins entrypoint -> ... -> API (vide si non atteignable ou non-API).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<Vec<String>>,
}

impl Evidence {
    /// Preuve non-API (permission, string, service…) : pas de reachability.
    fn simple(kind: &str, value: String) -> Self {
        Evidence {
            kind: kind.into(),
            value,
            reachable: None,
            score: None,
            depth: None,
            fanin: None,
            paths: Vec::new(),
        }
    }
    /// Preuve API : reachability calculée ultérieurement (enrich_reachability).
    fn api(value: String) -> Self {
        Evidence {
            kind: "api".into(),
            value,
            reachable: None,
            score: None,
            depth: None,
            fanin: None,
            paths: Vec::new(),
        }
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
                rules.push(r);
            }
        }
        tracing::info!(count = rules.len(), "rules loaded");
        Ok(Self { rules })
    }

    /// Charge depuis le cache auto-généré (DL du STIX au 1er lancement ou si refresh).
    pub fn load_cached(refresh: bool) -> Result<Self> {
        let dir = fetch::ensure_cache(refresh)?;
        Self::load(&dir)
    }

    pub fn run(&self, features: &ApkFeatures, cg: &CallGraph) -> Vec<Match> {
        // Entrypoints validés par le manifest, calculés une fois pour tout le batch.
        let entrypoints = cg.entrypoints(&features.components);
        tracing::info!(
            entrypoints = entrypoints.len(),
            components = features.components.len(),
            "manifest-validated entrypoints"
        );

        let mut out = Vec::new();
        for r in &self.rules {
            let mut evidence = Vec::new();
            if eval(&r.features, features, cg, &entrypoints, &mut evidence) {
                dedup_evidence(&mut evidence);
                // Enrichit les preuves API avec leur atteignabilité depuis un entrypoint.
                // (Les preuves "co-reachable"/"intimacy" portent déjà leurs chemins.)
                for e in evidence.iter_mut() {
                    if e.kind == "api" {
                        let reach = cg.reachability(&e.value, &entrypoints);
                        e.reachable = Some(reach.reachable);
                        e.paths = reach.paths;
                        // Profondeur min racine->API (-1 si non atteignable) et fan-in
                        // call-site : à combien de sauts et depuis combien d'appels.
                        e.depth = Some(
                            cg.min_depth(&e.value, &entrypoints)
                                .map_or(-1, |d| d as i64),
                        );
                        e.fanin = Some(cg.fan_in(&e.value));
                    }
                }
                out.push(Match {
                    id: r.meta.id.clone(),
                    name: r.meta.name.clone(),
                    tactic: r.meta.tactic.clone(),
                    evidence,
                });
            }
        }
        out
    }
}

/// Évalue une feature et collecte les preuves atomiques qui l'ont satisfaite.
/// Les preuves ne sont conservées que pour les branches réellement vraies.
/// `eps` = entrypoints validés par le manifest (nécessaires au garde-fou pivot
/// de `co-reachable` / `intimacy`) ; ignoré par les autres variants.
fn eval(
    f: &Feature,
    feat: &ApkFeatures,
    cg: &CallGraph,
    eps: &[NodeIndex],
    ev: &mut Vec<Evidence>,
) -> bool {
    match f {
        Feature::And(xs) => {
            // Tous vrais : on évalue tout et on garde les preuves de chaque sous-feature.
            let mut local = Vec::new();
            let ok = xs.iter().all(|x| eval(x, feat, cg, eps, &mut local));
            if ok {
                ev.append(&mut local);
            }
            ok
        }
        Feature::Or(xs) => {
            // Au moins un vrai : on garde les preuves des branches vraies uniquement.
            let mut any = false;
            for x in xs {
                let mut local = Vec::new();
                if eval(x, feat, cg, eps, &mut local) {
                    any = true;
                    ev.append(&mut local);
                }
            }
            any
        }
        Feature::Not(x) => {
            // Une absence n'est pas une preuve positive : on ne propage rien.
            let mut sink = Vec::new();
            !eval(x, feat, cg, eps, &mut sink)
        }
        Feature::Count { feature, min } => {
            let mut local = Vec::new();
            let n = count_matches(feature, feat, cg, eps, &mut local);
            if n >= *min {
                ev.append(&mut local);
                true
            } else {
                false
            }
        }
        Feature::Sequence(xs) => eval_sequence(xs, cg, ev),
        Feature::CoReachable {
            first,
            second,
            exclude_entrypoints,
            max_dist,
            exclude_allowlisted,
        } => {
            let constraints = PivotConstraints {
                exclude_entrypoints: *exclude_entrypoints,
                max_dist: (*max_dist).map(|d| d as u32),
                exclude_allowlisted: *exclude_allowlisted,
            };
            let cr = cg.reaches_both(first, second, eps, &constraints);
            if cr.reachable {
                ev.push(Evidence {
                    kind: "co-reachable".into(),
                    value: match &cr.pivot {
                        Some(p) => format!("{first} + {second} @ {p}"),
                        None => format!("{first} + {second}"),
                    },
                    reachable: Some(true),
                    depth: None,
                    fanin: None,
                    score: None,
                    paths: vec![cr.path_first, cr.path_second]
                        .into_iter()
                        .filter(|p| !p.is_empty())
                        .collect(),
                });
                true
            } else {
                false
            }
        }
        Feature::Intimacy {
            first,
            second,
            label,
            exclude_entrypoints,
            max_dist,
            exclude_allowlisted,
            min_score,
        } => {
            let constraints = PivotConstraints {
                exclude_entrypoints: *exclude_entrypoints,
                max_dist: (*max_dist).map(|d| d as u32),
                exclude_allowlisted: *exclude_allowlisted,
            };
            let intim = cg.intimacy(first, second, eps, &constraints);
            // Matche si le score normalisé dépasse le seuil (défaut 0.0 => tout pivot
            // qualifié). `score` = normalisé par diamètre effectif ; on expose aussi
            // n, ad, eff et le score brut dans la value pour calibration en Python.
            if intim.score > *min_score {
                let tag = label.clone().unwrap_or_else(|| "coupling".to_string());
                ev.push(Evidence {
                    kind: "intimacy".into(),
                    value: match &intim.pivot {
                        Some(p) => format!(
                            "{tag} @ {p} (n={}, ad={:.1}, eff={:.1}, raw={:.3})",
                            intim.n_pivots, intim.avg_dist, intim.eff_diam, intim.score_raw
                        ),
                        None => format!(
                            "{tag} (n={}, ad={:.1}, eff={:.1}, raw={:.3})",
                            intim.n_pivots, intim.avg_dist, intim.eff_diam, intim.score_raw
                        ),
                    },
                    reachable: Some(true),
                    depth: None,
                    fanin: None,
                    score: Some(intim.score),
                    paths: vec![intim.path_first, intim.path_second]
                        .into_iter()
                        .filter(|p| !p.is_empty())
                        .collect(),
                });
                true
            } else {
                false
            }
        }
        Feature::Api(a) => {
            // Preuve = la signature résolue qui contient l'API recherchée.
            if let Some(m) = feat.methods.iter().find(|m| m.api().contains(a)) {
                ev.push(Evidence::api(m.api()));
                true
            } else if cg.has_api(a) {
                ev.push(Evidence::api(a.clone()));
                true
            } else {
                false
            }
        }
        Feature::String(s) => {
            if let Some(found) = feat.strings.iter().find(|x| x.contains(s)) {
                ev.push(Evidence::simple("string", found.clone()));
                true
            } else {
                false
            }
        }
        Feature::Permission(p) => {
            if feat.permissions.iter().any(|x| x == p) {
                ev.push(Evidence::simple("permission", p.clone()));
                true
            } else {
                false
            }
        }
        Feature::IntentAction(a) => {
            if feat.intent_actions.iter().any(|x| x == a) {
                ev.push(Evidence::simple("intent-action", a.clone()));
                true
            } else {
                false
            }
        }
        Feature::NativeSymbol(s) => {
            if let Some(found) = feat.native_symbols.iter().find(|x| x.contains(s)) {
                ev.push(Evidence::simple("native-symbol", found.clone()));
                true
            } else {
                false
            }
        }
        Feature::AccessibilityService(want) => {
            let has = feat.services.iter().any(|s| s.is_accessibility);
            if has == *want {
                if let Some(svc) = feat.services.iter().find(|s| s.is_accessibility) {
                    ev.push(Evidence::simple("accessibility-service", svc.name.clone()));
                }
                true
            } else {
                false
            }
        }
        Feature::Service(name) => {
            if let Some(svc) = feat.services.iter().find(|s| s.name.contains(name)) {
                ev.push(Evidence::simple("service", svc.name.clone()));
                true
            } else {
                false
            }
        }
        // Technique hors périmètre de l'analyse statique : ne matche jamais.
        Feature::Unsupported(_) => false,
    }
}

/// Séquence ordonnée : chaque étape (api) doit être atteignable depuis la précédente.
fn eval_sequence(steps: &[Feature], cg: &CallGraph, ev: &mut Vec<Evidence>) -> bool {
    let apis: Vec<&str> = steps
        .iter()
        .filter_map(|s| match s {
            Feature::Api(a) => Some(a.as_str()),
            _ => None,
        })
        .collect();
    let ok = if apis.len() < 2 {
        apis.iter().all(|a| cg.has_api(a))
    } else {
        apis.windows(2).all(|w| cg.reaches(w[0], w[1]))
    };
    if ok {
        for a in &apis {
            ev.push(Evidence::simple("sequence-api", (*a).to_string()));
        }
    }
    ok
}

fn count_matches(
    f: &Feature,
    feat: &ApkFeatures,
    cg: &CallGraph,
    eps: &[NodeIndex],
    ev: &mut Vec<Evidence>,
) -> usize {
    match f {
        Feature::Permission(p) => {
            let n = feat.permissions.iter().filter(|x| *x == p).count();
            if n > 0 {
                ev.push(Evidence::simple("permission", p.clone()));
            }
            n
        }
        Feature::Api(a) => {
            let hits: Vec<String> = feat
                .methods
                .iter()
                .filter(|m| m.api().contains(a))
                .map(|m| m.api())
                .collect();
            for h in &hits {
                ev.push(Evidence::api(h.clone()));
            }
            hits.len()
        }
        other => eval(other, feat, cg, eps, ev) as usize,
    }
}

/// Dédoublonne les preuves (kind+value identiques) en préservant l'ordre.
fn dedup_evidence(ev: &mut Vec<Evidence>) {
    let mut seen = std::collections::HashSet::new();
    ev.retain(|e| seen.insert((e.kind.clone(), e.value.clone())));
}
