//! DEX parsing : `dex_facade` (structure) + `dex-bytecode` (décodage invoke-*).
//!
//! Pipeline :
//!   DexBin -> classes -> methods -> Code.insns (&[u8])
//!     -> dex_bytecode::decode_all -> instructions
//!       -> filtrer invoke-* -> résoudre method@idx -> CallEdge (inter-proc)
use crate::model::{ApkFeatures, MethodRef};
use crate::parser::dex_facade::{DexBin, DexMethod};
use anyhow::{Context, Result};
use std::path::Path;

/// Un appel résolu : caller -> callee, avec l'offset (en unités de code) du call site.
pub struct CallEdge {
    pub caller: MethodRef,
    pub callee: MethodRef,
    pub site: u64,
}

/// Parse le DEX et construit la liste des call edges inter-procéduraux.
/// Peuple aussi `features.methods` et `features.strings`.
pub fn extract(path: &Path, features: &mut ApkFeatures) -> Result<Vec<CallEdge>> {
    let dex = DexBin::open(path)?;

    // Strings globales du DEX -> features (utile pour les règles `string:`).
    for s in dex.strings() {
        features.strings.push(s.to_string());
    }

    let mut edges = Vec::new();

    for class in dex.classes() {
        let class = match class {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "skip unreadable class");
                continue;
            }
        };
        let class_name = class.descriptor.to_string();

        // Hiérarchie : absente pour `Ljava/lang/Object;` seulement.
        if let Some(sup) = class.superclass {
            features
                .superclasses
                .insert(class_name.clone(), sup.to_string());
        }

        for method in &class.methods {
            let caller = MethodRef {
                class: class_name.clone(),
                name: method.name.to_string(),
                descriptor: descriptor_of(method),
            };
            features.methods.push(caller.clone());

            // Pas de code pour abstract / native.
            let Some(code) = &method.code else { continue };

            let instructions = match dex_bytecode::decode_all(code.insns, 0) {
                Ok(i) => i,
                Err(e) => {
                    tracing::warn!(method = %caller.signature(), error = %e, "decode failed");
                    continue;
                }
            };

            for ins in &instructions {
                if !is_invoke(ins) {
                    continue;
                }
                if let Some(midx) = invoke_method_index(ins) {
                    match resolve_method(&dex, midx) {
                        Ok(callee) => edges.push(CallEdge {
                            caller: caller.clone(),
                            callee,
                            site: instruction_offset(ins),
                        }),
                        Err(e) => tracing::debug!(idx = midx, error = %e, "unresolved method ref"),
                    }
                }
            }
        }
    }

    tracing::info!(
        edges = edges.len(),
        methods = features.methods.len(),
        strings = features.strings.len(),
        classes = features.superclasses.len(),
        "DEX extracted"
    );
    Ok(edges)
}

/// Descripteur Dalvik complet du caller : (params)return, paramètres EXACTS.
/// Ex. (Landroid/content/Context;I)V
fn descriptor_of(method: &DexMethod<'_>) -> String {
    let mut d = String::from("(");
    for p in method.params {
        d.push_str(p);
    }
    d.push(')');
    d.push_str(method.return_type);
    d
}

/// true si l'instruction est un invoke-* (virtual/super/direct/static/interface, +/range).
fn is_invoke(ins: &dex_bytecode::Instruction) -> bool {
    ins.mnemonic().starts_with("invoke-")
}

/// Offset de l'instruction dans la méthode (en octets/units selon dex-bytecode).
fn instruction_offset(ins: &dex_bytecode::Instruction) -> u64 {
    ins.offset as u64
}

/// Extrait l'index `method@idx` d'une instruction invoke-*.
/// dex-bytecode formate les opérandes en texte (ex. "method@5") et n'expose
/// pas d'accès structuré, y compris à l'amont.
fn invoke_method_index(ins: &dex_bytecode::Instruction) -> Option<u64> {
    let ops = ins.operands();
    let tag = "method@";
    let pos = ops.find(tag)? + tag.len();
    let rest: String = ops[pos..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    rest.parse().ok()
}

/// Résout un index dans la table method_ids vers un MethodRef (class + name + proto).
/// Le descripteur du callee porte ses paramètres en shorty : c'est la forme
/// historique, reproduite par la façade (cf. `dex_facade::shorty_params`).
fn resolve_method(dex: &DexBin, idx: u64) -> Result<MethodRef> {
    let item = u32::try_from(idx)
        .ok()
        .and_then(|i| dex.method_item(i))
        .with_context(|| format!("method_ids[{idx}] out of range"))?;
    Ok(MethodRef {
        class: item.class.to_string(),
        name: item.name.to_string(),
        descriptor: item.descriptor.to_string(),
    })
}
