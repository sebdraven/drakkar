//! MESURE : d'où vient le NOM des cibles de réflexion ?
//!
//! LA QUESTION
//! -----------
//! Sur le résidu de réflexion du corpus, quelle proportion des cibles de
//! `Method.invoke` / `Class.forName` / `Class.getMethod` provient d'un INPUT
//! CONSTANT — donc résoluble en rejouant le déchiffreur localement — plutôt que
//! d'un INPUT RUNTIME, irréductiblement symbolique ? Ce ratio décide si un
//! mini-interpréteur Dalvik de déobfuscation de strings vaut le coup.
//!
//! Ce n'est PAS une feature de production : sortie TSV, lue à la main, aucune
//! intégration au CSV d'orphelins ni au JSON.
//!
//! COMMENT
//! -------
//! Même remontée de registre que `dyn_entrypoints::backtrack_literal` (helpers
//! partagés : `writes_register`, `dest_register`, `registers`, `operand_index`),
//! mais poussée d'un cran : quand le registre-nom vient d'un `move-result-object`,
//! on ne s'arrête plus à « call-result » — on regarde D'OÙ VIENNENT LES ARGUMENTS
//! de cet appel. C'est là que se joue la distinction qui répond à la question :
//!   - un argument littéral  -> déchiffreur à input constant  -> `decrypt-const`
//!   - que des inconnus      -> input runtime                 -> `runtime`
//!
//! DEUX CRANS POUR `Method.invoke`
//! -------------------------------
//! `invoke` ne porte pas de nom : son receveur est un objet `Method`. On remonte
//! donc d'abord au `getMethod`/`getDeclaredMethod` qui l'a produit (cran 1), puis
//! au registre-nom de CE call site (cran 2). Si le cran 1 n'aboutit pas à un
//! `getMethod` (Method reçu en paramètre, stocké en champ, tiré d'un tableau),
//! le site est classé `indirect` — trou nommé plutôt que trou muet.
//!
//! LIMITES ASSUMÉES (elles biaisent le ratio, il faut les lire avec lui)
//! --------------------------------------------------------------------
//!   - Intra-méthode seulement : un nom passé en paramètre sort en `param`, pas
//!     en `const`, même si tous les appelants le passent en dur.
//!   - `index_field_assignments` ne reconnaît que `new-instance`/`const-class` :
//!     il ne dit rien d'un champ String. On indexe donc EN PLUS, localement, les
//!     champs dont toutes les assignations sont des `const-*` (`const_fields`) —
//!     sans quoi tout champ-source tomberait mécaniquement en `runtime`.
//!   - `invoke-*/range` : `registers()` rend les deux bornes, pas la plage. Les
//!     arguments d'un appel `/range` sont donc mal lus (sous-estime `decrypt-const`).
//!   - Trois passes de décodage par DEX (assignations de classes, assignations
//!     constantes, scan). Assumé pour une mesure jetable.

use crate::model::MethodRef;
use crate::parser::dyn_entrypoints::{
    dest_register, index_field_assignments, operand_index, registers, u16_to_le_bytes,
    writes_register, FieldAssignments,
};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

/// Profondeur de remontée dans les arguments d'un call-result. 3 couvre les
/// déchiffreurs enchaînés (`decrypt(unwrap(CONST))`) sans partir en vrille.
const MAX_ARG_DEPTH: usize = 3;

/// Provenance du nom de la cible de réflexion. C'est LA sortie de la mesure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    /// `const-string` littéral : nom en clair, aucune obfuscation.
    Const,
    /// Le nom sort d'un appel dont AU MOINS un argument est un littéral :
    /// déchiffreur à input constant, RÉSOLUBLE par exécution concrète locale.
    DecryptConst,
    /// Le nom sort d'un appel dont aucun argument ne remonte à un littéral
    /// (paramètre, champ mutable, lecture d'API) : input inconnu statiquement.
    Runtime,
    /// Le nom est un paramètre de la méthode (ou `this`) : demanderait de
    /// remonter aux appelants.
    Param,
    /// `Method.invoke` dont le receveur ne remonte pas à un `getMethod` :
    /// le nom n'est pas observable depuis ce call site.
    Indirect,
    /// Écriture d'une nature non traitée (tableau, phi de branche…).
    Unknown,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Const => "const",
            Self::DecryptConst => "decrypt-const",
            Self::Runtime => "runtime",
            Self::Param => "param",
            Self::Indirect => "indirect",
            Self::Unknown => "unknown",
        }
    }
}

/// Ordre stable de sortie : les colonnes restent comparables d'un échantillon à
/// l'autre même quand un compte est nul.
pub const CATEGORIES: &[Category] = &[
    Category::Const,
    Category::DecryptConst,
    Category::Runtime,
    Category::Param,
    Category::Indirect,
    Category::Unknown,
];

/// Un site de réflexion classé.
#[derive(Debug, Clone)]
pub struct ReflectionSite {
    pub caller: MethodRef,
    pub site: u64,
    /// `forName`, `getMethod`, `getDeclaredMethod` ou `invoke`.
    pub sink: String,
    pub category: Category,
}

#[derive(Debug, Default)]
pub struct ReflectionInputReport {
    pub counts: HashMap<Category, usize>,
    pub sites: Vec<ReflectionSite>,
}

impl ReflectionInputReport {
    pub fn count(&self, c: Category) -> usize {
        self.counts.get(&c).copied().unwrap_or(0)
    }
    pub fn total(&self) -> usize {
        self.sites.len()
    }
    fn push(&mut self, site: ReflectionSite) {
        *self.counts.entry(site.category).or_insert(0) += 1;
        self.sites.push(site);
    }
    fn merge(&mut self, other: ReflectionInputReport) {
        for (k, v) in other.counts {
            *self.counts.entry(k).or_insert(0) += v;
        }
        self.sites.extend(other.sites);
    }
}

/// Les quatre sinks de réflexion retenus.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Sink {
    /// `Class.forName(String)` — statique, le nom est l'argument 0.
    ForName,
    /// `Class.getMethod(String, Class[])` — virtuel, le nom est l'argument 1.
    GetMethod,
    /// `Class.getDeclaredMethod(String, Class[])` — idem.
    GetDeclaredMethod,
    /// `Method.invoke(Object, Object[])` — le nom n'est pas ici : deux crans.
    Invoke,
}

impl Sink {
    fn as_str(self) -> &'static str {
        match self {
            Self::ForName => "forName",
            Self::GetMethod => "getMethod",
            Self::GetDeclaredMethod => "getDeclaredMethod",
            Self::Invoke => "invoke",
        }
    }
    /// Index, dans les opérandes de l'invoke, du registre portant le nom.
    /// `None` pour `Method.invoke` : il faut passer par `getMethod`.
    fn name_reg_index(self) -> Option<usize> {
        match self {
            Self::ForName => Some(0),
            Self::GetMethod | Self::GetDeclaredMethod => Some(1),
            Self::Invoke => None,
        }
    }
}

/// D'où vient un registre. Même axe que `dyn_entrypoints::UnresolvedReason`,
/// mais `CallResult` porte l'INDEX de l'invoke producteur — c'est ce qui permet
/// d'aller regarder ses arguments.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Source {
    /// `const-string` : le nom est en clair.
    ConstString,
    /// Autre littéral (`const-class`, `const/4`, tableau rempli par
    /// `fill-array-data`…) : constant tout de même.
    ConstOther,
    /// Résultat d'un appel, à l'index donné dans la fenêtre.
    CallResult(usize),
    /// `iget`/`sget` sur le champ donné.
    Field(u64),
    /// Paramètre de la méthode (ou `this`) : aucune écriture dans la méthode.
    Param,
    /// Écriture d'une nature non traitée.
    Unknown,
}

/// Champs dont TOUTES les assignations sont des littéraux (`true`), ou au moins
/// une ne l'est pas (`false`). Complète `index_field_assignments`, qui ne
/// reconnaît que les champs porteurs d'une classe.
type ConstFields = HashMap<u64, bool>;

/// Les deux index de champs, passés ensemble à la classification.
struct Fields<'a> {
    assign: &'a FieldAssignments,
    consts: &'a ConstFields,
}

impl Fields<'_> {
    /// Le champ est-il constant-initialisé ?
    fn is_const(&self, field: u64) -> bool {
        matches!(self.consts.get(&field), Some(true))
            || matches!(self.assign.get(&field), Some(Some(_)))
    }
}

/// Passe : indexe les champs assignés uniquement depuis des littéraux.
///
/// Même forme que `index_field_assignments` (dont on ne peut pas se servir ici :
/// il remonte à `new-instance`/`const-class`, pas aux chaînes). Un champ vu une
/// fois assigné depuis autre chose qu'un littéral est invalidé définitivement.
fn index_const_fields(dex: &dex::Dex<impl AsRef<[u8]>>) -> ConstFields {
    let mut map: ConstFields = HashMap::new();

    for class in dex.classes() {
        let class = match class {
            Ok(c) => c,
            Err(_) => continue,
        };
        for method in class.methods() {
            let code = match method.code() {
                Some(c) => c,
                None => continue,
            };
            let bytes = u16_to_le_bytes(code.insns());
            let instructions = match dex_bytecode::decode_all(&bytes, 0) {
                Ok(i) => i,
                Err(_) => continue,
            };

            for (i, ins) in instructions.iter().enumerate() {
                let m = ins.mnemonic();
                if !(m.starts_with("iput") || m.starts_with("sput")) {
                    continue;
                }
                let field_id = match operand_index(ins, "field@") {
                    Some(f) => f,
                    None => continue,
                };
                // Comme pour `iput-object` : la valeur assignée est le PREMIER
                // registre de l'instruction.
                let src = match registers(ins).first().copied() {
                    Some(r) => r,
                    None => continue,
                };
                let is_const = matches!(
                    trace(&instructions[..i], src),
                    Source::ConstString | Source::ConstOther
                );
                let entry = map.entry(field_id).or_insert(is_const);
                *entry = *entry && is_const;
            }
        }
    }

    tracing::debug!(fields = map.len(), "const fields indexed");
    map
}

/// Scanne un DEX et classe chaque site de réflexion.
pub fn extract(path: &Path) -> Result<ReflectionInputReport> {
    let dex = dex::DexReader::from_file(path)
        .with_context(|| format!("open dex {}", path.display()))?;

    let assign = index_field_assignments(&dex);
    let consts = index_const_fields(&dex);
    let fields = Fields { assign: &assign, consts: &consts };

    let mut report = ReflectionInputReport::default();

    for class in dex.classes() {
        let class = match class {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "skip unreadable class");
                continue;
            }
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
                Err(e) => {
                    tracing::debug!(method = %caller.api(), error = %e, "decode failed");
                    continue;
                }
            };

            scan_method(&dex, &instructions, &caller, &fields, &mut report);
        }
    }

    tracing::info!(sites = report.sites.len(), "reflection inputs classified");
    Ok(report)
}

fn scan_method(
    dex: &dex::Dex<impl AsRef<[u8]>>,
    instructions: &[dex_bytecode::Instruction],
    caller: &MethodRef,
    fields: &Fields,
    report: &mut ReflectionInputReport,
) {
    for (i, ins) in instructions.iter().enumerate() {
        if !ins.mnemonic().starts_with("invoke-") {
            continue;
        }
        let sink = match reflection_sink(dex, ins) {
            Some(s) => s,
            None => continue,
        };

        // Fenêtre : TOUTE la méthode en amont. Dès qu'on suit un registre précis
        // il n'y a plus de risque de confusion de proximité (même choix que
        // `dyn_entrypoints` quand `arg_reg` est connu).
        let window = &instructions[..i];
        let category = match sink.name_reg_index() {
            Some(idx) => match registers(ins).get(idx).copied() {
                Some(reg) => classify(window, trace(window, reg), fields, MAX_ARG_DEPTH),
                // Moins de registres que l'argument visé : surcharge inattendue.
                None => Category::Unknown,
            },
            // `Method.invoke` : deux crans.
            None => classify_invoke(dex, window, ins, fields),
        };

        report.push(ReflectionSite {
            caller: caller.clone(),
            site: ins.offset as u64,
            sink: sink.as_str().to_string(),
            category,
        });
    }
}

/// `Method.invoke` : le receveur (index 0) est l'objet `Method`. Cran 1, remonter
/// au `getMethod`/`getDeclaredMethod` qui l'a produit ; cran 2, classer SON
/// registre-nom. Tout ce qui n'aboutit pas au cran 1 est `indirect`.
fn classify_invoke(
    dex: &dex::Dex<impl AsRef<[u8]>>,
    window: &[dex_bytecode::Instruction],
    invoke: &dex_bytecode::Instruction,
    fields: &Fields,
) -> Category {
    let recv = match registers(invoke).first().copied() {
        Some(r) => r,
        None => return Category::Indirect,
    };
    let producer = match trace(window, recv) {
        Source::CallResult(k) => k,
        _ => return Category::Indirect,
    };
    match reflection_sink(dex, &window[producer]) {
        Some(Sink::GetMethod) | Some(Sink::GetDeclaredMethod) => {}
        _ => return Category::Indirect,
    }
    let inner = &window[..producer];
    match registers(&window[producer]).get(1).copied() {
        Some(reg) => classify(inner, trace(inner, reg), fields, MAX_ARG_DEPTH),
        None => Category::Unknown,
    }
}

/// LE CŒUR DE LA MESURE : traduire une provenance de registre en catégorie.
///
/// Un `call-result` n'est pas une réponse en soi — c'est la question. On regarde
/// les ARGUMENTS de l'appel : au moins un littéral (éventuellement à travers un
/// appel imbriqué, d'où `depth`) et le déchiffreur est rejouable localement.
fn classify(
    window: &[dex_bytecode::Instruction],
    source: Source,
    fields: &Fields,
    depth: usize,
) -> Category {
    match source {
        Source::ConstString | Source::ConstOther => Category::Const,
        Source::Param => Category::Param,
        Source::Field(f) => {
            if fields.is_const(f) {
                Category::Const
            } else {
                Category::Runtime
            }
        }
        Source::CallResult(k) => {
            // Budget épuisé : on ne conclut pas au constant sans l'avoir vu.
            if depth == 0 {
                return Category::Runtime;
            }
            let call = &window[k];
            let inner = &window[..k];
            let constant = arg_registers(call).into_iter().any(|r| {
                matches!(
                    classify(inner, trace(inner, r), fields, depth - 1),
                    Category::Const | Category::DecryptConst
                )
            });
            if constant {
                Category::DecryptConst
            } else {
                Category::Runtime
            }
        }
        Source::Unknown => Category::Unknown,
    }
}

/// Remonte `target` dans `window` et CLASSE sa source. Même parcours que
/// `dyn_entrypoints::backtrack_literal` : on traverse tout ce qui n'écrit pas
/// (dont `check-cast`, omniprésent après un déchiffreur) et on suit `move-object`.
fn trace(window: &[dex_bytecode::Instruction], target: u32) -> Source {
    let mut target = target;

    for (i, ins) in window.iter().enumerate().rev() {
        // `filled-new-array` passe le filtre de `writes_register` alors que son
        // premier registre est un ÉLÉMENT, pas une destination (le résultat
        // sort par `move-result-object`). Le traverser, sinon il vole la cible.
        if ins.mnemonic().starts_with("filled-new-array") {
            continue;
        }
        if !writes_register(ins) || dest_register(ins) != Some(target) {
            continue;
        }
        let m = ins.mnemonic();

        if m.starts_with("move-result") {
            // Un `move-result*` suit TOUJOURS immédiatement son producteur.
            return match i.checked_sub(1) {
                Some(p)
                    if window[p].mnemonic().starts_with("invoke-")
                        || window[p].mnemonic().starts_with("filled-new-array") =>
                {
                    Source::CallResult(p)
                }
                _ => Source::Unknown,
            };
        }
        if m.starts_with("move") {
            // `move`, `move-object`, `move-wide` (+ `/from16`, `/16`).
            match registers(ins).get(1).copied() {
                Some(src) => {
                    target = src;
                    continue;
                }
                None => return Source::Unknown,
            }
        }
        if m.starts_with("const-string") {
            return Source::ConstString;
        }
        if m.starts_with("const") {
            // `const-class`, `const/4`, `const/16`, `const-wide`, `const/high16`…
            return Source::ConstOther;
        }
        if m.starts_with("new-array") {
            // Un tableau n'est constant que s'il est rempli par un bloc de
            // données littéral — motif des clés d'un déchiffreur.
            return if filled_with_data(&window[i + 1..], target) {
                Source::ConstOther
            } else {
                Source::Unknown
            };
        }
        if m.starts_with("iget") || m.starts_with("sget") {
            return match operand_index(ins, "field@") {
                Some(f) => Source::Field(f),
                None => Source::Unknown,
            };
        }
        return Source::Unknown;
    }

    // Aucune écriture dans toute la méthode : paramètre ou `this`.
    Source::Param
}

/// Le tableau `array` est-il rempli par un `fill-array-data` en aval ?
fn filled_with_data(after: &[dex_bytecode::Instruction], array: u32) -> bool {
    after.iter().any(|ins| {
        ins.mnemonic().starts_with("fill-array-data")
            && registers(ins).first().copied() == Some(array)
    })
}

/// Registres d'ARGUMENTS d'un appel : pour un invoke non statique, l'index 0 est
/// le receveur et n'est pas un input du calcul.
fn arg_registers(ins: &dex_bytecode::Instruction) -> Vec<u32> {
    let regs = registers(ins);
    let m = ins.mnemonic();
    if m.starts_with("invoke-static") || m.starts_with("filled-new-array") {
        regs
    } else if m.starts_with("invoke-") {
        regs.into_iter().skip(1).collect()
    } else {
        regs
    }
}

/// L'invoke cible-t-il un des quatre sinks de réflexion ? Matching sur le
/// couple (propriétaire, nom) : `invoke` et `forName` sont trop communs pour
/// être reconnus au nom seul.
fn reflection_sink(
    dex: &dex::Dex<impl AsRef<[u8]>>,
    ins: &dex_bytecode::Instruction,
) -> Option<Sink> {
    use dex::jtype::TypeId;
    use dex::method::MethodId;
    use dex::string::StringId;

    if !ins.mnemonic().starts_with("invoke-") {
        return None;
    }
    let idx = operand_index(ins, "method@")?;
    let item = dex.get_method_item(idx as MethodId).ok()?;
    let name = dex.get_string(item.name_idx() as StringId).ok()?.to_string();
    let owner = dex.get_type(item.class_idx() as TypeId).ok()?.type_descriptor().to_string();

    match (owner.as_str(), name.as_str()) {
        ("Ljava/lang/reflect/Method;", "invoke") => Some(Sink::Invoke),
        ("Ljava/lang/Class;", "forName") => Some(Sink::ForName),
        ("Ljava/lang/Class;", "getMethod") => Some(Sink::GetMethod),
        ("Ljava/lang/Class;", "getDeclaredMethod") => Some(Sink::GetDeclaredMethod),
        _ => None,
    }
}

/// Variante APK : agrège sur tous les `classes*.dex`.
pub fn extract_from_apk(apk: &Path) -> Result<ReflectionInputReport> {
    let tmp = tempfile::tempdir().context("create tempdir")?;
    let dex_files = crate::parser::extract_dex_files(apk, tmp.path())?;

    let mut merged = ReflectionInputReport::default();
    for dex in &dex_files {
        let r = extract(dex).with_context(|| format!("scan {}", dex.display()))?;
        merged.merge(r);
    }
    Ok(merged)
}

/// Accepte un APK ou un DEX brut, reconnu au CONTENU — même routage que
/// `dyn_entrypoints::extract_any`, pour rester utilisable sur les DEX déballés.
pub fn extract_any(path: &Path) -> Result<ReflectionInputReport> {
    use crate::parser::dyn_entrypoints::{sniff, InputKind};

    match sniff(path) {
        Some(InputKind::Apk) => extract_from_apk(path),
        Some(InputKind::Dex) => extract(path),
        None => anyhow::bail!(
            "{} n'est ni un APK (PK\\x03\\x04) ni un DEX (dex\\n) — reconnu au contenu, \
             l'extension n'entre pas en compte",
            path.display()
        ),
    }
}
