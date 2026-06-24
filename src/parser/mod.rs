//! Parsing APK -> ApkFeatures + CallGraph.
//!
//! Backend par défaut = stub (compile sans LIEF). Backend réel derrière
//! la feature `lief-backend`.
pub mod dex;
pub mod elf;
pub mod manifest;

use crate::cfg::CallGraph;
use crate::model::ApkFeatures;
use anyhow::Result;
use std::path::Path;

/// Résultat complet du parsing d'un APK.
pub struct ParsedApk {
    pub features: ApkFeatures,
    pub call_graph: CallGraph,
}

/// Point d'entrée : parse un APK et construit features + CFG inter-proc.
pub fn parse_apk(path: &Path) -> Result<ParsedApk> {
    tracing::info!(apk = %path.display(), "parsing APK");

    let mut features = ApkFeatures::default();
    manifest::extract(path, &mut features)?;
    let methods = dex::extract(path, &mut features)?;
    elf::extract(path, &mut features)?;

    let call_graph = cfg_from_methods(methods);
    Ok(ParsedApk { features, call_graph })
}

/// Construit le call graph inter-proc à partir des edges DEX résolus.
fn cfg_from_methods(edges: Vec<dex::CallEdge>) -> CallGraph {
    let mut g = CallGraph::new();
    for e in edges {
        g.add_call(e.caller, e.callee, e.site);
    }
    g
}
