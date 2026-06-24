//! Bridge Kharon : confirmation dynamique (DSE) des candidats statiques.
//!
//! On lit le summary JSON de Kharon et on confirme un Match si le chemin
//! candidat correspond à des call chains effectivement observées/faisables.
use crate::rules::Match;
use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

/// Vue minimale du summary Kharon (à aligner sur le schéma v2.1).
#[derive(Debug, Deserialize, Default)]
pub struct KharonSummary {
    #[serde(default)]
    pub observed_apis: Vec<String>,
    #[serde(default)]
    pub triage_profile: Option<String>,
}

pub fn load_summary(path: &Path) -> Result<KharonSummary> {
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

/// Passe les candidats à `confirmed=true` si Kharon les corrobore.
pub fn confirm(matches: &mut [Match], summary: &KharonSummary) {
    for m in matches.iter_mut() {
        // Heuristique provisoire : confirmé si Kharon a observé une API
        // mentionnant l'ID de technique (à raffiner avec un mapping règle->API).
        if summary.observed_apis.iter().any(|a| a.contains(&m.id)) {
            m.confirmed = true;
        }
    }
}
