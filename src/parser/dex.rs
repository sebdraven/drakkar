//! DEX parsing : crate `dex` (structure) + `dex-bytecode` (décodage invoke-*).
//!
//! Pipeline :
//!   dex::DexReader -> classes -> methods -> CodeItem.insns (&[u16])
//!     -> u16->bytes -> dex_bytecode::decode_all -> instructions
//!       -> filtrer invoke-* -> résoudre method@idx -> CallEdge (inter-proc)
use crate::model::{ApkFeatures, MethodRef};
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
    let dex = dex::DexReader::from_file(path)
        .with_context(|| format!("open dex {}", path.display()))?;

    // Strings globales du DEX -> features (utile pour les règles `string:`).
    for s in dex.strings() {
        if let Ok(s) = s {
            features.strings.push(s.to_string());
        }
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
        let class_name = class.jtype().type_descriptor().to_string();

        // Hiérarchie : `super_class()` rend un ClassId, qui indexe les TypeId
        // (mêmes alias d'entier) — d'où le `get_type` direct. Absent pour
        // `Ljava/lang/Object;` seulement.
        if let Some(sup) = class.super_class() {
            if let Ok(t) = dex.get_type(sup) {
                features
                    .superclasses
                    .insert(class_name.clone(), t.type_descriptor().to_string());
            }
        }

        for method in class.methods() {
            let caller = MethodRef {
                class: class_name.clone(),
                name: method.name().to_string(),
                descriptor: descriptor_of(&method),
            };
            features.methods.push(caller.clone());

            // Pas de code pour abstract / native.
            let code = match method.code() {
                Some(c) => c,
                None => continue,
            };

            let bytes = u16_to_le_bytes(code.insns());
            let instructions = match dex_bytecode::decode_all(&bytes, 0) {
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
                // TODO(api): adapter `invoke_method_index` au champ réel de
                // dex_bytecode::Instruction exposant l'index method@.
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

/// Code units (u16) -> buffer d'octets little-endian (format attendu par dex-bytecode).
fn u16_to_le_bytes(insns: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(insns.len() * 2);
    for &u in insns {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// Descripteur Dalvik complet du caller : (params)return.
/// Ex. (Landroid/content/Context;I)V — reconstruit depuis params() + return_type().
fn descriptor_of(method: &dex::method::Method) -> String {
    let mut d = String::from("(");
    for p in method.params() {
        d.push_str(p.type_descriptor());
    }
    d.push(')');
    d.push_str(method.return_type().type_descriptor());
    d
}

/// true si l'instruction est un invoke-* (virtual/super/direct/static/interface, +/range).
fn is_invoke(ins: &dex_bytecode::Instruction) -> bool {
    ins.mnemonic().starts_with("invoke-")
}

/// Offset de l'instruction dans la méthode (en octets/units selon dex-bytecode).
/// TODO(api): confirmer le nom du champ (`offset`) sur dex_bytecode::Instruction.
fn instruction_offset(ins: &dex_bytecode::Instruction) -> u64 {
    ins.offset as u64
}

/// Extrait l'index `method@idx` d'une instruction invoke-*.
/// TODO(api): dex-bytecode formate les opérandes en texte (ex. "method@5").
/// On parse l'opérande ; à remplacer par l'accès structuré si l'API l'expose.
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
/// Les getters du crate `dex` attendent des type-alias précis (MethodId/TypeId/
/// StringId/ProtoId), tous des alias d'entiers : on caste explicitement.
fn resolve_method(dex: &dex::Dex<impl AsRef<[u8]>>, idx: u64) -> Result<MethodRef> {
    use dex::jtype::TypeId;
    use dex::method::{MethodId, ProtoId};
    use dex::string::StringId;

    let item = dex
        .get_method_item(idx as MethodId)
        .with_context(|| format!("method_ids[{idx}] out of range"))?;
    let class = dex
        .get_type(item.class_idx() as TypeId)?
        .type_descriptor()
        .to_string();
    let name = dex
        .get_string(item.name_idx() as StringId)?
        .to_string();
    let descriptor = resolve_proto_descriptor(dex, item.proto_idx() as ProtoId);
    Ok(MethodRef { class, name, descriptor })
}

/// Reconstruit un descripteur lisible pour le callee depuis son ProtoIdItem.
/// return_type est résolu exactement (TypeId -> descripteur) ; les params sont
/// approximés via le shorty (formes courtes : L pour tout objet, types primitifs
/// exacts). Suffisant pour le matching MITRE par class->name.
fn resolve_proto_descriptor(dex: &dex::Dex<impl AsRef<[u8]>>, proto: dex::method::ProtoId) -> String {
    let proto = match dex.get_proto_item(proto) {
        Ok(p) => p,
        Err(_) => return String::new(),
    };
    // shorty : 1er char = return, le reste = params (formes courtes).
    let shorty = dex
        .get_string(proto.shorty())
        .map(|s| s.to_string())
        .unwrap_or_default();
    let params: String = shorty.chars().skip(1).collect();
    let ret = dex
        .get_type(proto.return_type())
        .map(|t| t.type_descriptor().to_string())
        .unwrap_or_else(|_| "V".into());
    format!("({params}){ret}")
}
