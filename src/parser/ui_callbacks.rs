//! Handlers d'événements UI — arêtes de reconnexion pour l'audit d'orphelins.
//!
//! Un `onClick` n'est jamais appelé par le code : le composant fait
//! `view.setOnClickListener(listener)` — un appel SORTANT vers le framework —
//! et le framework rappelle `listener.onClick(v)` à l'exécution. Le handler
//! reste donc orphelin dans le graphe alors qu'il est atteignable par un clic.
//! Ce module retrouve, pour chaque enregistrement de listener, la CLASSE du
//! listener, donc son handler (`Lcom/x/Foo$1;->onClick`), à réinjecter comme
//! racine avant `CallGraph::orphan_audit`.
//!
//! Deux motifs couverts, via les primitives de `dyn_entrypoints` :
//!   - listener anonyme `setOnClickListener(new OnClickListener(){…})`
//!     -> `new-instance Foo$1`, résolu par `backtrack_new_instance` ;
//!   - `this` : l'Activity implémente le listener et se passe elle-même.
//!
//! Trous nommés, PAS couverts ici :
//!   - listener détenu en champ (`iget-object`) -> à brancher sur
//!     `index_field_assignments` (comme le fait `dyn_entrypoints`) ;
//!   - `android:onClick="foo"` en res/layout/*.xml -> lecteur `axml` +
//!     resources.arsc ; le lien n'est pas dans le bytecode du tout.

use crate::model::MethodRef;
use crate::parser::dyn_entrypoints::{
    backtrack_new_instance, operand_index, registers, u16_to_le_bytes, Provenance,
};
use anyhow::{Context, Result};
use std::path::Path;

/// Setters de listener -> handler que le framework rappellera. Tous sont des
/// `invoke-virtual {vWidget, vListener}` : le listener est à l'index 1.
const UI_SINKS: &[(&str, &str)] = &[
    ("setOnClickListener", "onClick"),
    ("setOnLongClickListener", "onLongClick"),
    ("setOnTouchListener", "onTouch"),
    ("setOnKeyListener", "onKey"),
    ("setOnFocusChangeListener", "onFocusChange"),
    ("setOnItemClickListener", "onItemClick"),
    ("setOnItemLongClickListener", "onItemLongClick"),
    ("setOnCheckedChangeListener", "onCheckedChanged"),
];

/// Un handler UI atteignable par événement, absent du graphe d'appels statique.
#[derive(Debug, Clone)]
pub struct UiHandler {
    /// Classe du listener (souvent une classe anonyme `Lcom/x/Foo$1;`).
    pub class: String,
    /// Handler rappelé par le framework (`onClick`, …).
    pub method: String,
    /// Setter par lequel le listener est enregistré.
    pub via: String,
    pub caller: MethodRef,
    pub site: u64,
    pub provenance: Provenance,
}

#[derive(Debug, Default)]
pub struct UiHandlerReport {
    pub handlers: Vec<UiHandler>,
}

impl UiHandlerReport {
    /// Racines (classe, méthode) dédoublonnées, à réinjecter dans le set
    /// d'entrypoints avant `orphan_audit` (résolues en nœuds par l'appelant).
    pub fn roots(&self) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = self
            .handlers
            .iter()
            .map(|h| (h.class.clone(), h.method.clone()))
            .collect();
        v.sort();
        v.dedup();
        v
    }
}

/// Scanne un DEX brut (déjà déballé) et renvoie les handlers UI résolus.
pub fn extract(path: &Path) -> Result<UiHandlerReport> {
    let dex = dex::DexReader::from_file(path)
        .with_context(|| format!("open dex {}", path.display()))?;

    let mut report = UiHandlerReport::default();

    for class in dex.classes() {
        let class = match class {
            Ok(c) => c,
            Err(_) => continue,
        };
        let class_name = class.jtype().type_descriptor().to_string();

        for method in class.methods() {
            let code = match method.code() {
                Some(c) => c,
                None => continue,
            };
            let caller = MethodRef {
                class: class_name.clone(),
                name: method.name().to_string(),
                descriptor: String::new(),
            };

            let bytes = u16_to_le_bytes(code.insns());
            let instructions = match dex_bytecode::decode_all(&bytes, 0) {
                Ok(i) => i,
                Err(_) => continue,
            };

            // Registre de `this` : en Dalvik les paramètres occupent les
            // registres hauts `[regs - ins, regs)`, `this` en tête. Si `ins`
            // dépasse la largeur des paramètres déclarés d'un mot, ce mot est
            // `this`. (`J`/`D` = deux mots.) Même calcul que `dyn_entrypoints`.
            let params_width: u32 = method
                .params()
                .iter()
                .map(|p| match p.type_descriptor().to_string().as_str() {
                    "J" | "D" => 2u32,
                    _ => 1u32,
                })
                .sum();
            let regs = code.registers_size() as u32;
            let ins_sz = code.ins_size() as u32;
            let this_reg = if ins_sz > params_width && regs >= ins_sz {
                Some(regs - ins_sz)
            } else {
                None
            };

            scan_method(&dex, &instructions, &caller, this_reg, &class_name, &mut report);
        }
    }

    tracing::info!(handlers = report.handlers.len(), "ui handlers extracted");
    Ok(report)
}

fn scan_method(
    dex: &dex::Dex<impl AsRef<[u8]>>,
    instructions: &[dex_bytecode::Instruction],
    caller: &MethodRef,
    this_reg: Option<u32>,
    caller_class: &str,
    report: &mut UiHandlerReport,
) {
    for (i, ins) in instructions.iter().enumerate() {
        if !ins.mnemonic().starts_with("invoke-") {
            continue;
        }
        let (via, handler) = match ui_sink(dex, ins) {
            Some(v) => v,
            None => continue,
        };
        // {vWidget, vListener} -> le listener est à l'index 1.
        let target = match registers(ins).get(1).copied() {
            Some(r) => r,
            None => continue,
        };

        // 1) listener construit sur place (classe anonyme, cas majoritaire).
        if let Some(class) = backtrack_new_instance(dex, &instructions[..i], target) {
            report.handlers.push(UiHandler {
                class,
                method: handler.to_string(),
                via,
                caller: caller.clone(),
                site: ins.offset as u64,
                provenance: Provenance::NewInstance,
            });
            continue;
        }

        // 2) l'objet courant EST le listener (Activity implements OnClickListener).
        if Some(target) == this_reg {
            report.handlers.push(UiHandler {
                class: caller_class.to_string(),
                method: handler.to_string(),
                via,
                caller: caller.clone(),
                site: ins.offset as u64,
                provenance: Provenance::ThisSelf,
            });
        }
        // Sinon : listener détenu en champ ou reçu en paramètre — trou assumé.
    }
}

/// Si l'invoke cible un setter de listener, renvoie (setter, handler attendu).
fn ui_sink(
    dex: &dex::Dex<impl AsRef<[u8]>>,
    ins: &dex_bytecode::Instruction,
) -> Option<(String, &'static str)> {
    use dex::method::MethodId;
    use dex::string::StringId;

    let idx = operand_index(ins, "method@")?;
    let item = dex.get_method_item(idx as MethodId).ok()?;
    let name = dex.get_string(item.name_idx() as StringId).ok()?.to_string();

    for &(setter, handler) in UI_SINKS {
        if setter == name.as_str() {
            return Some((name, handler));
        }
    }
    None
}

/// Variante APK : dézippe les `classes*.dex` et agrège, via
/// `parser::extract_dex_files` (donc avec le repli `TolerantZip`).
pub fn extract_from_apk(apk: &Path) -> Result<UiHandlerReport> {
    let tmp = tempfile::tempdir().context("create tempdir")?;
    let dex_files = crate::parser::extract_dex_files(apk, tmp.path())?;
    let mut merged = UiHandlerReport::default();

    for dex in &dex_files {
        let r = extract(dex).with_context(|| format!("scan {}", dex.display()))?;
        merged.handlers.extend(r.handlers);
    }

    Ok(merged)
}

/// Accepte un APK ou un DEX brut, reconnu au contenu (réutilise le renifleur de
/// `dyn_entrypoints`).
pub fn extract_any(path: &Path) -> Result<UiHandlerReport> {
    use crate::parser::dyn_entrypoints::{sniff, InputKind};
    match sniff(path) {
        Some(InputKind::Apk) => extract_from_apk(path),
        Some(InputKind::Dex) => extract(path),
        None => anyhow::bail!("{} n'est ni un APK ni un DEX (reconnu au contenu)", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_dedup() {
        let mut r = UiHandlerReport::default();
        for _ in 0..2 {
            r.handlers.push(UiHandler {
                class: "Lcom/x/Foo$1;".into(),
                method: "onClick".into(),
                via: "setOnClickListener".into(),
                caller: MethodRef {
                    class: "Lcom/x/Foo;".into(),
                    name: "onCreate".into(),
                    descriptor: String::new(),
                },
                site: 0,
                provenance: Provenance::NewInstance,
            });
        }
        assert_eq!(r.roots(), vec![("Lcom/x/Foo$1;".to_string(), "onClick".to_string())]);
    }
}
