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
//! Quatre motifs couverts, via les primitives de `dyn_entrypoints` :
//!   - listener anonyme `setOnClickListener(new OnClickListener(){…})`
//!     -> `new-instance Foo$1`, résolu par `backtrack_new_instance` ;
//!   - `this` : l'Activity implémente le listener et se passe elle-même ;
//!   - listener détenu en CHAMP (`iget-object`/`sget-object`) -> classe concrète
//!     assignée au champ ailleurs dans le DEX, via `index_field_assignments` ;
//!   - `android:onClick="foo"` déclaré en XML de ressources — le lien n'est pas
//!     dans le bytecode du tout (cf. `xml_on_click_names`).
//!
//! Trou restant : un listener reçu en PARAMÈTRE. Il faudrait remonter aux
//! appelants (interprocédural), hors de portée de ce scan intra-méthode.

use crate::model::MethodRef;
use crate::parser::axml::Element;
use crate::parser::dex_facade::{DexBin, DexMethod};
use crate::parser::dyn_entrypoints::{
    backtrack_new_instance, dest_register, index_field_assignments, operand_index, registers,
    this_register, writes_register, FieldAssignments, Provenance,
};
use anyhow::{Context, Result};
use std::collections::HashSet;
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
///
/// Sans archive il n'y a pas de layout : le volet `android:onClick` est
/// silencieusement vide. C'est `extract_from_apk` qui l'alimente.
pub fn extract(path: &Path) -> Result<UiHandlerReport> {
    extract_with_layouts(path, &HashSet::new())
}

/// Variante interne : `xml_on_click` porte les noms de handlers cités par les
/// layouts de l'APK d'origine. Une méthode du DEX qui porte l'un de ces noms
/// ET la signature exigée par Android (`(Landroid/view/View;)V`) est retenue.
fn extract_with_layouts(path: &Path, xml_on_click: &HashSet<String>) -> Result<UiHandlerReport> {
    let dex = DexBin::open(path)?;

    let mut report = UiHandlerReport::default();

    // Passe 1 : classe CONCRÈTE assignée à chaque champ — c'est elle qui donne
    // le listener détenu en champ, dont le type déclaré n'est presque toujours
    // que l'interface. Seconde passe de décodage sur tout le DEX, même coût
    // assumé que dans `dyn_entrypoints`.
    let assignments = index_field_assignments(&dex);

    for class in dex.classes() {
        let class = match class {
            Ok(c) => c,
            Err(_) => continue,
        };
        let class_name = class.descriptor.to_string();

        for method in &class.methods {
            // Volet XML : le handler n'est appelé par personne dans le bytecode,
            // il n'y a donc rien à chercher dans son code — la déclaration suffit.
            let method_name = method.name.to_string();
            if xml_on_click.contains(&method_name) && takes_view_returns_void(method) {
                report.handlers.push(UiHandler {
                    class: class_name.clone(),
                    method: method_name.clone(),
                    via: "android:onClick".into(),
                    // Pas de call site bytecode : le lien est dans le layout.
                    caller: MethodRef {
                        class: class_name.clone(),
                        name: method_name,
                        descriptor: String::new(),
                    },
                    site: 0,
                    provenance: Provenance::XmlOnClick,
                });
            }

            let code = match &method.code {
                Some(c) => c,
                None => continue,
            };
            let caller = MethodRef {
                class: class_name.clone(),
                name: method.name.to_string(),
                descriptor: String::new(),
            };

            let instructions = match dex_bytecode::decode_all(code.insns, 0) {
                Ok(i) => i,
                Err(_) => continue,
            };

            let this_reg = this_register(method.is_static, code.registers_size, code.ins_size);

            scan_method(
                &dex,
                &instructions,
                &caller,
                this_reg,
                &class_name,
                &assignments,
                &mut report,
            );
        }
    }

    tracing::info!(handlers = report.handlers.len(), "ui handlers extracted");
    Ok(report)
}

fn scan_method(
    dex: &DexBin,
    instructions: &[dex_bytecode::Instruction],
    caller: &MethodRef,
    this_reg: Option<u32>,
    caller_class: &str,
    assignments: &FieldAssignments,
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
            continue;
        }

        // 3) listener détenu en CHAMP : `iget-object vListener, vThis, field@N`.
        if let Some((class, provenance)) = backtrack_field(dex, &instructions[..i], target, assignments)
        {
            report.handlers.push(UiHandler {
                class,
                method: handler.to_string(),
                via,
                caller: caller.clone(),
                site: ins.offset as u64,
                provenance,
            });
        }
        // Sinon : listener reçu en paramètre — trou assumé (interprocédural).
    }
}

/// Si l'invoke cible un setter de listener, renvoie (setter, handler attendu).
fn ui_sink(
    dex: &DexBin,
    ins: &dex_bytecode::Instruction,
) -> Option<(String, &'static str)> {
    let idx = operand_index(ins, "method@")?;
    let name = dex.method_item(idx as u32)?.name.to_string();

    for &(setter, handler) in UI_SINKS {
        if setter == name.as_str() {
            return Some((name, handler));
        }
    }
    None
}

/// Remonte `target` jusqu'au `iget-object`/`sget-object` qui l'a chargé et rend
/// la classe du listener. Deux qualités, distinguées par la provenance :
/// classe CONCRÈTE assignée au champ ailleurs dans le DEX (exacte), à défaut
/// type DÉCLARÉ du champ (borne supérieure).
///
/// Le type déclaré n'est retenu que s'il n'est pas du framework : il vaut
/// `Landroid/view/View$OnClickListener;` dans l'écrasante majorité des cas —
/// une interface, qui ne désigne aucun corps de méthode et ne reconnecterait
/// rien dans le graphe.
fn backtrack_field(
    dex: &DexBin,
    window: &[dex_bytecode::Instruction],
    target: u32,
    assignments: &FieldAssignments,
) -> Option<(String, Provenance)> {
    let mut target = target;
    for ins in window.iter().rev() {
        // Traverser tout ce qui n'écrit pas le registre suivi.
        if !writes_register(ins) || dest_register(ins) != Some(target) {
            continue;
        }
        let m = ins.mnemonic();
        if m.starts_with("move-object") && !m.starts_with("move-result-object") {
            if let Some(&src) = registers(ins).get(1) {
                target = src;
            }
            continue;
        }
        if m.starts_with("iget-object") || m.starts_with("sget-object") {
            let idx = operand_index(ins, "field@")?;
            if let Some(Some(concrete)) = assignments.get(&idx) {
                return Some((concrete.clone(), Provenance::FieldAssign));
            }
            let declared = dex.field_item(idx as u32)?.typ.to_string();
            if declared.starts_with("Landroid/") || declared.starts_with("Ljava") {
                return None;
            }
            return Some((declared, Provenance::FieldType));
        }
        // Écriture d'une autre nature : la piste s'arrête.
        return None;
    }
    None
}

/// Signature qu'Android exige d'un handler `android:onClick` : `void foo(View)`.
/// Sans ce filtre, toute homonyme du DEX serait promue racine.
fn takes_view_returns_void(method: &DexMethod<'_>) -> bool {
    method.params.len() == 1
        && method.params[0] == "Landroid/view/View;"
        && method.return_type == "V"
}

/// Noms de méthodes cités par `android:onClick` dans les XML de ressources
/// (layouts, menus). Jamais fatal : un APK illisible rend un ensemble vide.
///
/// APPROXIMATION ASSUMÉE : on ne résout pas quel layout est gonflé par quelle
/// Activity (il faudrait suivre `setContentView(R.layout.X)` ET résoudre l'id
/// via `resources.arsc`). On retient donc le NOM du handler, et la classe est
/// celle qui déclare une méthode de ce nom et de la bonne signature — toutes
/// les déclarantes si elles sont plusieurs. Sur-approximation bornée par la
/// signature, et jamais silencieuse : provenance `xml`.
fn xml_on_click_names(apk: &Path) -> HashSet<String> {
    let mut names = HashSet::new();
    for raw in read_res_xml(apk) {
        match crate::parser::axml::decode(&raw) {
            Ok(decoded) => collect_on_click(&decoded.root, &mut names),
            Err(e) => tracing::debug!(error = %e, "XML de ressource illisible, ignoré"),
        }
    }
    tracing::info!(handlers = names.len(), "android:onClick relevés dans les ressources");
    names
}

fn collect_on_click(elem: &Element, out: &mut HashSet<String>) {
    if let Some(v) = elem.attr("onClick") {
        let v = v.trim();
        if looks_like_method_name(v) {
            out.insert(v.to_string());
        }
    }
    for child in elem.get_children() {
        collect_on_click(child, out);
    }
}

/// Écarte ce qui ne peut pas être un nom de méthode Java — au premier chef les
/// références de ressources non résolues (`@0x7f0a0001`), qu'`axml` rend telles
/// quelles faute de `resources.arsc`.
fn looks_like_method_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// Contenu brut des `res/**/*.xml`. Même repli que le manifeste : crate `zip`
/// d'abord, `apkzip::TolerantZip` dès qu'il refuse quoi que ce soit — c'est à
/// la lecture d'entrée que le bit de chiffrement trafiqué frappe.
fn read_res_xml(apk: &Path) -> Vec<Vec<u8>> {
    use std::io::Read;

    let nominal = (|| -> Result<Vec<Vec<u8>>> {
        let file = std::fs::File::open(apk)?;
        let mut zip = zip::ZipArchive::new(file)?;
        let mut out = Vec::new();
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i)?;
            if !is_res_xml(entry.name()) {
                continue;
            }
            let mut buf = Vec::with_capacity(entry.size() as usize);
            entry.read_to_end(&mut buf)?;
            out.push(buf);
        }
        Ok(out)
    })();

    match nominal {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                apk = %apk.display(),
                error = %e,
                "res/*.xml refusés par le crate zip, repli sur le lecteur tolérant"
            );
            read_res_xml_tolerant(apk)
        }
    }
}

fn read_res_xml_tolerant(apk: &Path) -> Vec<Vec<u8>> {
    let zip = match crate::parser::apkzip::TolerantZip::open(apk) {
        Ok(z) => z,
        Err(e) => {
            tracing::warn!(
                apk = %apk.display(),
                error = %e,
                "lecteur tolérant en échec, volet android:onClick abandonné"
            );
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for (i, entry) in zip.entries().iter().enumerate() {
        if !is_res_xml(&entry.name) {
            continue;
        }
        match zip.read(i) {
            Ok(b) => out.push(b),
            Err(e) => tracing::debug!(entry = %entry.name, error = %e, "entrée illisible, ignorée"),
        }
    }
    out
}

fn is_res_xml(name: &str) -> bool {
    name.starts_with("res/") && name.ends_with(".xml")
}

/// Variante APK : relève les `android:onClick` des ressources, puis dézippe les
/// `classes*.dex` via `parser::extract_dex_files` (donc avec le repli
/// `TolerantZip`) et agrège.
pub fn extract_from_apk(apk: &Path) -> Result<UiHandlerReport> {
    // Relevé des layouts d'abord : les noms alimentent le scan de chaque DEX.
    let xml_on_click = xml_on_click_names(apk);

    let tmp = tempfile::tempdir().context("create tempdir")?;
    let dex_files = crate::parser::extract_dex_files(apk, tmp.path())?;
    let mut merged = UiHandlerReport::default();

    for dex in &dex_files {
        let r = extract_with_layouts(dex, &xml_on_click)
            .with_context(|| format!("scan {}", dex.display()))?;
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
    fn method_name_filter() {
        assert!(looks_like_method_name("onClickBouton"));
        assert!(looks_like_method_name("_handler$1"));
        // Référence de ressource non résolue, faute de resources.arsc.
        assert!(!looks_like_method_name("@0x7f0a0001"));
        assert!(!looks_like_method_name(""));
        assert!(!looks_like_method_name("com.x.Foo"));
        assert!(!looks_like_method_name("2foo"));
    }

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
