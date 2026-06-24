//! Modèle commun : features statiques extraites de l'APK.
use serde::{Deserialize, Serialize};

/// Référence de méthode au format smali-like : Lcom/foo/Bar;->baz(I)V
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MethodRef {
    pub class: String,
    pub name: String,
    pub descriptor: String,
}

impl MethodRef {
    /// Signature canonique : Lcom/foo/Bar;->baz(I)V
    pub fn signature(&self) -> String {
        format!("{}->{}{}", self.class, self.name, self.descriptor)
    }
    /// Forme courte pour matching API : Lcom/foo/Bar;->baz
    pub fn api(&self) -> String {
        format!("{}->{}", self.class, self.name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDecl {
    pub name: String,
    pub permission: Option<String>,
    pub is_accessibility: bool,
    pub intent_actions: Vec<String>,
}

/// Tout ce qu'on extrait statiquement, consommé par le moteur de règles.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApkFeatures {
    pub package: String,
    pub permissions: Vec<String>,
    pub intent_actions: Vec<String>,
    pub services: Vec<ServiceDecl>,
    pub methods: Vec<MethodRef>,
    pub strings: Vec<String>,
    pub native_symbols: Vec<String>,
}
