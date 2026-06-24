//! Schéma des règles (YAML), DSL composable style capa.
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub meta: Meta,
    pub features: Feature,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Meta {
    pub id: String,
    pub name: String,
    pub tactic: String,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub authors: Vec<String>,
}

/// Expression de feature. Représentation YAML externally-tagged :
///   and:   [ ... ]
///   or:    [ ... ]
///   not:   { ... }
///   count: { feature: {...}, min: 2 }
///   sequence: [ {api: ...}, {api: ...} ]
///   api / string / permission / intent-action / native-symbol : scalaire
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Feature {
    And(Vec<Feature>),
    Or(Vec<Feature>),
    Not(Box<Feature>),
    Count { feature: Box<Feature>, min: usize },
    Sequence(Vec<Feature>),
    Api(String),
    String(String),
    Permission(String),
    IntentAction(String),
    NativeSymbol(String),
}
