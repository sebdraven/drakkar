//! Schéma des règles (YAML), DSL composable style capa.
//!
//! serde_yaml 0.9 ne désérialise plus les enums externally-tagged depuis des
//! maps à clé unique (`and:` …) — il exige des tags `!and`. Pour garder un YAML
//! de règles lisible (maps à clé unique), on désérialise `Feature` à la main
//! depuis une map générique.
//!
//! `Serialize` sert à `Engine::rules_hash` : la règle telle que lue, champs dans
//! l'ordre de déclaration.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub meta: Meta,
    pub features: Feature,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Meta {
    pub id: String,
    pub name: String,
    pub tactic: String,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub authors: Vec<String>,
    /// Détectabilité par analyse statique Drakkar :
    /// `static` (permissions/API/CFG suffisent), `partial` (heuristique faible),
    /// `out-of-scope` (réseau/serveur/hardware, non observable dans l'APK).
    #[serde(default = "default_detectability")]
    pub detectability: String,
    #[serde(default)]
    pub platforms: Vec<String>,
}

fn default_detectability() -> String {
    "static".to_string()
}

/// Expression de feature. Chaque variante est une map à clé unique en YAML :
///   and: [ ... ] | or: [ ... ] | not: { ... }
///   count: { feature: {...}, min: 2 }
///   sequence: [ {api: ...}, {api: ...} ]
///   api / string / permission / intent-action / native-symbol : scalaire
#[derive(Debug, Clone, Serialize)]
pub enum Feature {
    And(Vec<Feature>),
    Or(Vec<Feature>),
    Not(Box<Feature>),
    Count {
        feature: Box<Feature>,
        min: usize,
    },
    Sequence(Vec<Feature>),
    /// Co-atteignabilité depuis un pivot commun : `first` ET `second` (deux API)
    /// sont atteintes depuis un même nœud du CFG, qualifié par les trois garde-fous.
    /// Exprime « une même région de code enchaîne ces deux primitifs » (ex. crypto
    /// puis réseau), bien plus fort qu'une simple co-présence.
    CoReachable {
        first: String,
        second: String,
        exclude_entrypoints: bool,
        max_dist: Option<usize>,
        exclude_allowlisted: bool,
    },
    /// Score d'intimité (à la IntDroid) entre deux GROUPES de primitifs via leurs
    /// pivots communs : `n_pivots / (avg_dist + 1)`. `first` et `second` sont des
    /// listes d'API équivalentes (ex. tous les sinks réseau système) ; un nœud
    /// compte s'il matche l'un des membres du groupe. Matche si le score normalisé
    /// dépasse `min_score` (défaut 0.0). Le score est toujours écrit dans l'evidence
    /// pour tri/calibration en post-traitement. `label` nomme le couplage mesuré.
    Intimacy {
        first: Vec<String>,
        second: Vec<String>,
        label: Option<String>,
        exclude_entrypoints: bool,
        max_dist: Option<usize>,
        exclude_allowlisted: bool,
        min_score: f64,
    },
    Api(String),
    String(String),
    Permission(String),
    IntentAction(String),
    NativeSymbol(String),
    /// Vrai si l'APK déclare un service lié à l'accessibility (BIND_ACCESSIBILITY_SERVICE).
    AccessibilityService(bool),
    /// Match sur le nom d'un service déclaré (sous-chaîne).
    Service(String),
    /// Marqueur explicite : technique non détectable statiquement (toujours faux).
    /// Documente l'out-of-scope au lieu de laisser un trou dans la couverture.
    Unsupported(String),
}

impl<'de> Deserialize<'de> for Feature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        use serde_yaml::Value;

        let value = Value::deserialize(deserializer)?;
        let map = value
            .as_mapping()
            .ok_or_else(|| D::Error::custom("feature must be a single-key map"))?;
        let (key, val) = map
            .iter()
            .next()
            .ok_or_else(|| D::Error::custom("empty feature map"))?;
        let key = key
            .as_str()
            .ok_or_else(|| D::Error::custom("feature key must be a string"))?;

        // Helper : parse une liste de sous-features.
        let parse_list = |v: &Value| -> Result<Vec<Feature>, D::Error> {
            let seq = v
                .as_sequence()
                .ok_or_else(|| D::Error::custom(format!("`{key}` expects a list")))?;
            seq.iter()
                .map(|item| Feature::deserialize(item.clone()).map_err(D::Error::custom))
                .collect()
        };

        // Helper : parse une feature scalaire (string).
        let as_string = |v: &Value| -> Result<String, D::Error> {
            v.as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| D::Error::custom(format!("`{key}` expects a string")))
        };

        let feature = match key {
            "and" => Feature::And(parse_list(val)?),
            "or" => Feature::Or(parse_list(val)?),
            "not" => {
                // `not` accepte soit une feature unique (map à clé unique), soit une
                // liste (négation de la conjonction des sous-features).
                let inner = if val.is_sequence() {
                    Feature::And(parse_list(val)?)
                } else {
                    Feature::deserialize(val.clone()).map_err(D::Error::custom)?
                };
                Feature::Not(Box::new(inner))
            }
            "sequence" => Feature::Sequence(parse_list(val)?),
            "count" => {
                let m = val
                    .as_mapping()
                    .ok_or_else(|| D::Error::custom("`count` expects a map"))?;
                let feature = m
                    .get(Value::from("feature"))
                    .ok_or_else(|| D::Error::custom("`count` missing `feature`"))?;
                let min = m
                    .get(Value::from("min"))
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| D::Error::custom("`count` missing `min`"))?;
                Feature::Count {
                    feature: Box::new(
                        Feature::deserialize(feature.clone()).map_err(D::Error::custom)?,
                    ),
                    min: min as usize,
                }
            }
            "co-reachable" => {
                let m = val
                    .as_mapping()
                    .ok_or_else(|| D::Error::custom("`co-reachable` expects a map"))?;
                let req_str = |k: &str| -> Result<String, D::Error> {
                    m.get(Value::from(k))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .ok_or_else(|| D::Error::custom(format!("`co-reachable` missing `{k}`")))
                };
                let first = req_str("first")?;
                let second = req_str("second")?;
                // Garde-fous optionnels ; défauts = exclude-entrypoints activé seul.
                let exclude_entrypoints = m
                    .get(Value::from("exclude-entrypoints"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let max_dist = m
                    .get(Value::from("max-dist"))
                    .and_then(|v| v.as_u64())
                    .map(|d| d as usize);
                let exclude_allowlisted = m
                    .get(Value::from("exclude-allowlisted"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                Feature::CoReachable {
                    first,
                    second,
                    exclude_entrypoints,
                    max_dist,
                    exclude_allowlisted,
                }
            }
            "intimacy" => {
                let m = val
                    .as_mapping()
                    .ok_or_else(|| D::Error::custom("`intimacy` expects a map"))?;
                // `first`/`second` acceptent une string unique OU une liste de strings
                // (groupe d'API équivalentes, ex. tous les sinks réseau).
                let as_list = |k: &str| -> Result<Vec<String>, D::Error> {
                    match m.get(Value::from(k)) {
                        Some(Value::String(s)) => Ok(vec![s.clone()]),
                        Some(Value::Sequence(seq)) => {
                            let v: Vec<String> = seq
                                .iter()
                                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                                .collect();
                            if v.is_empty() {
                                Err(D::Error::custom(format!("`intimacy` `{k}` is empty")))
                            } else {
                                Ok(v)
                            }
                        }
                        _ => Err(D::Error::custom(format!(
                            "`intimacy` missing `{k}` (string or list)"
                        ))),
                    }
                };
                let first = as_list("first")?;
                let second = as_list("second")?;
                let label = m
                    .get(Value::from("label"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let exclude_entrypoints = m
                    .get(Value::from("exclude-entrypoints"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let max_dist = m
                    .get(Value::from("max-dist"))
                    .and_then(|v| v.as_u64())
                    .map(|d| d as usize);
                let exclude_allowlisted = m
                    .get(Value::from("exclude-allowlisted"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                // min-score accepte un entier ou un flottant YAML ; défaut 0.0.
                let min_score = m
                    .get(Value::from("min-score"))
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                Feature::Intimacy {
                    first,
                    second,
                    label,
                    exclude_entrypoints,
                    max_dist,
                    exclude_allowlisted,
                    min_score,
                }
            }
            "api" => Feature::Api(as_string(val)?),
            "string" => Feature::String(as_string(val)?),
            "permission" => Feature::Permission(as_string(val)?),
            "intent-action" => Feature::IntentAction(as_string(val)?),
            "native-symbol" => Feature::NativeSymbol(as_string(val)?),
            "accessibility-service" => Feature::AccessibilityService(
                val.as_bool()
                    .ok_or_else(|| D::Error::custom("`accessibility-service` expects a bool"))?,
            ),
            "service" => Feature::Service(as_string(val)?),
            "unsupported" => Feature::Unsupported(as_string(val)?),
            other => return Err(D::Error::custom(format!("unknown feature `{other}`"))),
        };
        Ok(feature)
    }
}
