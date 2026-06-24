//! DEX parsing via LIEF (Android module). Construit la liste des call edges
//! inter-procéduraux + collecte methods/strings dans ApkFeatures.
use crate::model::{ApkFeatures, MethodRef};
use anyhow::Result;
use std::path::Path;

/// Un appel résolu : caller -> callee, avec l'offset du call site.
pub struct CallEdge {
    pub caller: MethodRef,
    pub callee: MethodRef,
    pub site: u64,
}

#[cfg(not(feature = "lief-backend"))]
pub fn extract(_path: &Path, features: &mut ApkFeatures) -> Result<Vec<CallEdge>> {
    tracing::warn!("DEX stub (compile sans lief-backend) — 0 méthode extraite");
    // Placeholder pour valider le pipeline end-to-end sans LIEF.
    features.methods.clear();
    Ok(Vec::new())
}

#[cfg(feature = "lief-backend")]
pub fn extract(path: &Path, features: &mut ApkFeatures) -> Result<Vec<CallEdge>> {
    // TODO(lief): ouvrir le(s) classes*.dex de l'APK via lief::dex::parse,
    // itérer les classes -> méthodes -> instructions invoke-* pour résoudre
    // les call edges, peupler features.methods et features.strings.
    //
    // Esquisse (API à confirmer sur la version du crate lief retenue) :
    //   let dex = lief::dex::parse(path)?;
    //   for class in dex.classes() {
    //       for method in class.methods() {
    //           let caller = MethodRef { ... };
    //           features.methods.push(caller.clone());
    //           for insn in method.bytecode_invokes() {
    //               edges.push(CallEdge { caller: caller.clone(), callee, site });
    //           }
    //       }
    //   }
    tracing::info!(dex = %path.display(), "DEX extract (lief-backend) — à implémenter");
    let _ = features;
    Ok(Vec::new())
}
