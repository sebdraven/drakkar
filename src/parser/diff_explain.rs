//! Diff EXPLIQUÉ de deux DEX (ou APK), en mémoire, avec sortie colorée.
//!
//! POURQUOI CE MODULE
//! ------------------
//! `--diff-dex` mesure la similarité de STRUCTURE : son empreinte ne hache que
//! les mnémoniques, donc deux méthodes qui ne diffèrent que par une chaîne
//! littérale ou par la méthode appelée sont pour lui IDENTIQUES. Sur le corpus
//! ça veut dire qu'un changement d'hôte C2 passerait à 1.0 — l'angle mort est
//! exactement à l'endroit qui compte.
//!
//! Ce module ferme cet angle mort, et il le fait SANS aligneur de séquences.
//!
//! LE POINT DE CONCEPTION
//! ----------------------
//! Deux méthodes de même empreinte ont, par construction, la MÊME séquence de
//! mnémoniques. L'alignement est donc trivial : instruction `i` face à
//! instruction `i`. Aucun LCS, aucun Myers, aucune heuristique. Il ne reste qu'à
//! comparer les opérandes résolues, index par index.
//!
//! C'est aussi pourquoi on travaille en mémoire plutôt que par `diff` textuel :
//! un `diff` de désassemblage est dominé par la DÉRIVE DES OFFSETS — une
//! instruction insérée en tête décale tout le reste et la méthode entière
//! ressort comme divergente. Ici le problème n'existe pas.
//!
//! CE QU'IL SAIT ET NE SAIT PAS
//! ----------------------------
//! Traité : les paires de méthodes à empreinte ÉGALE (la quasi-totalité — 299
//! classes sur 300 sur safespy lot A ↔ lot B).
//!
//! Non traité : les paires à empreinte DIFFÉRENTE, qui demanderaient un vrai
//! aligneur. Elles sont listées et renvoyées vers `--disasm`, à lire à l'œil.
//! Décision assumée : sur le couple de référence ça ne concerne qu'UNE classe,
//! et coder un aligneur pour un cas unique est le mauvais calcul.
//!
//! LA CATÉGORISATION EST L'APPORT RÉEL
//! -----------------------------------
//! Un `diff` brut ne sait pas distinguer un remapping ProGuard d'un changement
//! de contenu. Ici, sur une paire d'instructions au même opcode, on sait dire
//! laquelle des quatre composantes a bougé — et donc classer :
//!   - une CHAÎNE qui change → contenu, c'est là que se voit un endpoint ;
//!   - un CHAMP dont seul le nom change, owner et type égaux → remapping, bruit ;
//!   - une CIBLE DE MÉTHODE ou un TYPE qui change → divergence réelle.
//! Sans cette distinction, la réserve sur `Lcom/dy/MyApplication;->a` reste un
//! problème de lecture. Avec, elle devient une catégorie comptée.
//!
//! ⚠️ Une opérande n'est pas la seule porteuse de contenu : un `static final
//! String` initialisé par une constante de compilation n'est écrit par AUCUNE
//! instruction, sa valeur vit dans `encoded_static_values`. D'où la catégorie
//! `valeur-statique`, lue dans le `class_def_item` et non dans le code.

use crate::parser::dex_facade::DexValue;
use crate::parser::disasm::{escape, normalize, resolve, Operand};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};

// ── Couleur ──────────────────────────────────────────────────────────────────

/// Quand émettre des séquences ANSI.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ColorMode {
    /// Couleur si stdout est un terminal et que `NO_COLOR` est absent.
    Auto,
    Always,
    Never,
}

impl ColorMode {
    /// `pub` : `diff_strings` s'en sert aussi — une seule définition du
    /// comportement `auto` pour toutes les sorties colorées de l'outil.
    pub fn enabled(self) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            // Redirigé vers un fichier ou un pipe -> pas d'ANSI, sinon la sortie
            // est illisible et ingrep-able. `NO_COLOR` est respecté (no-color.org).
            Self::Auto => {
                std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
            }
        }
    }
}

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const CYAN: &str = "\x1b[36m";

/// Enrobe `s` dans un code ANSI, ou le rend tel quel si la couleur est éteinte.
fn paint(on: bool, code: &str, s: &str) -> String {
    if on {
        format!("{code}{s}{RESET}")
    } else {
        s.to_string()
    }
}

// ── Catégories de divergence ─────────────────────────────────────────────────

/// Nature d'une divergence d'opérande à mnémonique identique.
///
/// L'ordre de déclaration est l'ordre de GRAVITÉ : `StringValue` en tête parce
/// que c'est là que se lisent les endpoints et les clés, `FieldRename` en queue
/// parce que c'est du bruit d'obfuscation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum Divergence {
    /// Une chaîne littérale change. **La catégorie qui compte** : hôte C2, clé
    /// d'API, chemin d'endpoint, message de debug.
    StringValue,
    /// La valeur initiale d'un champ statique change. Lue dans
    /// `encoded_static_values`, pas dans les instructions — c'est la seule
    /// catégorie qui ne vient pas du bytecode, et elle porte les mêmes enjeux
    /// que `StringValue`.
    StaticValue,
    /// La méthode appelée change (owner ou nom).
    MethodTarget,
    /// Un descripteur de type change.
    TypeRef,
    /// Un champ change d'owner ou de type — divergence réelle.
    FieldTarget,
    /// Un champ garde owner ET type, seul son NOM change : remapping ProGuard.
    /// Attendu en masse entre deux lots obfusqués séparément — à ne PAS lire
    /// comme une modification du produit.
    FieldRename,
    /// Une opérande résolue d'un côté, absente de l'autre. Ne devrait pas se
    /// produire à mnémonique égal ; signalé plutôt que masqué.
    Presence,
}

impl Divergence {
    pub fn label(self) -> &'static str {
        match self {
            Self::StringValue => "chaîne",
            Self::StaticValue => "valeur-statique",
            Self::MethodTarget => "cible-méthode",
            Self::TypeRef => "type",
            Self::FieldTarget => "champ-réel",
            Self::FieldRename => "champ-renommé",
            Self::Presence => "présence",
        }
    }

    fn color(self) -> &'static str {
        match self {
            // Rouge : contenu. C'est ce qu'on cherche.
            Self::StringValue | Self::StaticValue => RED,
            Self::MethodTarget | Self::TypeRef | Self::FieldTarget => YELLOW,
            // Atténué : bruit d'obfuscation attendu.
            Self::FieldRename => DIM,
            Self::Presence => BLUE,
        }
    }

    /// Cette divergence dit-elle quelque chose du PRODUIT, ou seulement de la
    /// chaîne d'obfuscation ? Sert au verdict final.
    pub fn is_substantive(self) -> bool {
        self != Self::FieldRename
    }
}

// ── Structures ───────────────────────────────────────────────────────────────

/// Une instruction réduite à ce qui sert la comparaison.
struct Slot {
    offset: u64,
    mnemonic: String,
    operand: Option<Operand>,
}

struct MethodRich {
    name: String,
    fingerprint: u64,
    slots: Vec<Slot>,
}

struct ClassRich {
    descriptor: String,
    methods: Vec<MethodRich>,
    /// Hash du multiset trié des empreintes de méthodes — identique au calcul de
    /// `diff_dex.rs`, pour que l'appariement de classes soit le même.
    ///
    /// ⚠️ N'inclut PAS les valeurs statiques, et ne doit pas les inclure : il
    /// pilote l'appariement, donc le toucher déplacerait `identical_*`, `near`
    /// et `only_in_*` de `--diff-dex`.
    class_hash: u64,
    /// Champs statiques et leur valeur initiale, déjà normalisées. Vecteur vide
    /// si la classe n'en porte aucun.
    statics: Vec<(String, Option<DexValue>)>,
}

/// Une divergence localisée.
#[derive(Serialize)]
pub struct Finding {
    pub class_a: String,
    pub class_b: String,
    pub method: String,
    /// Nom du champ, pour les divergences de valeur statique. Absent pour les
    /// divergences d'opérande, qui n'en ont pas — d'où le `skip` : le schéma
    /// JSON des `findings` existants ne bouge pas.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub offset: u64,
    pub mnemonic: String,
    pub kind: Divergence,
    pub value_a: String,
    pub value_b: String,
}

/// Une paire de classes appariées dont les empreintes de méthodes ne coïncident
/// pas : alignées par LCS plutôt qu'index par index.
#[derive(Serialize)]
pub struct Unaligned {
    pub class_a: String,
    pub class_b: String,
    pub methods_a: usize,
    pub methods_b: usize,
}

/// Une ligne du rendu aligné.
///
/// `kind` : `=` identique · `~` même opcode, opérande différente · `-` présent
/// seulement dans A · `+` présent seulement dans B.
#[derive(Serialize)]
pub struct AlignedLine {
    pub kind: &'static str,
    pub offset_a: Option<u64>,
    pub offset_b: Option<u64>,
    pub mnemonic: String,
    pub value_a: Option<String>,
    pub value_b: Option<String>,
}

impl AlignedLine {
    fn is_change(&self) -> bool {
        self.kind != "="
    }
}

#[derive(Serialize)]
pub struct AlignedMethod {
    pub name: String,
    /// Empreintes d'opcodes des deux côtés, en hexadécimal. Égales = structure
    /// identique, la divergence est ailleurs (ou nulle part).
    pub fp_a: String,
    pub fp_b: String,
    pub insns_a: usize,
    pub insns_b: usize,
    /// Nombre de lignes qui ne sont pas `=`.
    pub changed: usize,
    pub lines: Vec<AlignedLine>,
    /// Vrai si la méthode dépassait le plafond d'alignement.
    pub skipped: bool,
}

#[derive(Serialize)]
pub struct AlignedClass {
    pub class_a: String,
    pub class_b: String,
    pub methods: Vec<AlignedMethod>,
    /// Méthodes présentes d'un seul côté (appariement par nom).
    pub only_a: Vec<String>,
    pub only_b: Vec<String>,
}

#[derive(Serialize)]
pub struct ExplainReport {
    pub input_a: String,
    pub input_b: String,
    pub classes_paired: usize,
    /// Paires obtenues par NOM identique + empreinte identique. Le cas normal.
    pub paired_by_name: usize,
    /// Paires obtenues par empreinte seule, noms différents = renommage réel de
    /// classe. À regarder : c'est là que se lisent les vrais renommages.
    pub paired_by_hash: usize,
    pub methods_compared: usize,
    /// Méthodes appariées dont TOUTES les opérandes coïncident.
    pub methods_clean: usize,
    /// Champs statiques appariés par NOM entre deux classes appariées.
    pub statics_compared: usize,
    /// Champs statiques sans homonyme en face. Comptés, jamais remontés en
    /// divergence : entre deux lots obfusqués séparément, un remapping de noms
    /// de champs en produirait en masse, ce qui noierait le signal.
    pub statics_unpaired: usize,
    /// Classes retenues pour leurs SEULES valeurs statiques, côté A puis B :
    /// aucune méthode porteuse de code. Une classe de constantes pures n'a pas
    /// de `<clinit>`, elle était donc écartée avant que ce mode lise
    /// `encoded_static_values`. Ce compteur rend le déplacement de
    /// `classes_paired` lisible.
    pub classes_without_code_a: usize,
    pub classes_without_code_b: usize,
    pub findings: Vec<Finding>,
    /// Comptes par catégorie, ordonnés par gravité.
    pub by_kind: Vec<(String, usize)>,
    pub unaligned: Vec<Unaligned>,
    /// Rendu aligné par LCS des paires ci-dessus. C'est ici que se lit une
    /// divergence de STRUCTURE, là où `findings` ne couvre que les opérandes.
    pub aligned: Vec<AlignedClass>,
    pub only_in_a: Vec<String>,
    pub only_in_b: Vec<String>,
}

/// Options.
pub struct ExplainOptions {
    /// Préfixes de descripteurs à INCLURE (condition de validité : sans filtre,
    /// les libs tierces communes noient le signal).
    pub include_prefixes: Vec<String>,
    /// Substitutions appliquées AVANT comparaison — c'est la différence avec
    /// `--disasm-normalize`, qui n'agit qu'à l'affichage. Ici il FAUT normaliser
    /// avant, sinon `com/duiyun` ↔ `com/dy` fait diverger chaque opérande.
    pub normalize: Vec<(String, String)>,
    pub color: ColorMode,
    /// Longueur max d'une valeur affichée. Les chaînes du corpus peuvent être
    /// longues ; tronquer garde le tableau lisible.
    pub max_value: usize,
    /// Lignes de contexte identiques affichées autour de chaque changement dans
    /// le rendu aligné. `usize::MAX` = tout afficher.
    pub context: usize,
    /// Plafond d'instructions par méthode pour l'alignement LCS. Au-delà, la
    /// méthode est signalée mais pas alignée — la table DP est en O(n·m).
    pub align_cap: usize,
}

impl Default for ExplainOptions {
    fn default() -> Self {
        Self {
            include_prefixes: Vec::new(),
            normalize: Vec::new(),
            color: ColorMode::Auto,
            max_value: 72,
            context: 3,
            align_cap: 2000,
        }
    }
}

// ── Traitement ───────────────────────────────────────────────────────────────

pub fn run(input_a: &Path, input_b: &Path, opts: &ExplainOptions) -> Result<ExplainReport> {
    let (a, _ta) = load(input_a, opts)?;
    let (b, _tb) = load(input_b, opts)?;

    let mut report = ExplainReport {
        input_a: input_a.display().to_string(),
        input_b: input_b.display().to_string(),
        classes_paired: 0,
        paired_by_name: 0,
        paired_by_hash: 0,
        methods_compared: 0,
        methods_clean: 0,
        statics_compared: 0,
        statics_unpaired: 0,
        classes_without_code_a: a.iter().filter(|c| c.methods.is_empty()).count(),
        classes_without_code_b: b.iter().filter(|c| c.methods.is_empty()).count(),
        findings: Vec::new(),
        by_kind: Vec::new(),
        unaligned: Vec::new(),
        aligned: Vec::new(),
        only_in_a: Vec::new(),
        only_in_b: Vec::new(),
    };

    // ── Appariement des classes, en QUATRE passes ordonnées ──
    //
    // 🔴 Le NOM passe AVANT l'empreinte, et c'est le point critique. Les DTO
    // (`<init>` + `getX` + `setX`) ont tous la MÊME séquence de mnémoniques,
    // donc la même empreinte de classe. Un appariement glouton par empreinte
    // seule les chaîne alors en CYCLE DE PERMUTATION et compare des classes
    // sans aucun rapport — mesuré sur safespy lot A ↔ lot B : trois cycles
    // disjoints de 5, 12 et 3 classes dans `com.dy.json`, 54 fausses
    // divergences. L'empreinte ne discrimine que si elle est discriminante.
    let mut b_taken = vec![false; b.len()];
    let mut a_taken = vec![false; a.len()];

    let mut b_by_hash: HashMap<u64, Vec<usize>> = HashMap::new();
    let mut b_by_name: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, c) in b.iter().enumerate() {
        // 🔴 Les classes SANS méthode à code ont toutes la même empreinte —
        // celle du multiset vide. Les laisser entrer dans l'index par empreinte
        // les chaînerait en cycle de permutation en PASSE 2, exactement le
        // défaut corrigé pour les POJO. Elles s'apparient par NOM ou pas du tout.
        if !c.methods.is_empty() {
            b_by_hash.entry(c.class_hash).or_default().push(i);
        }
        b_by_name.entry(c.descriptor.clone()).or_default().push(i);
    }

    // PASSE 1 — même nom ET même empreinte. Le cas normal, prioritaire.
    for (ia, ca) in a.iter().enumerate() {
        let found = b_by_name.get(&ca.descriptor).and_then(|v| {
            v.iter()
                .copied()
                .find(|&i| !b_taken[i] && b[i].class_hash == ca.class_hash)
        });
        if let Some(ib) = found {
            a_taken[ia] = true;
            b_taken[ib] = true;
            report.classes_paired += 1;
            report.paired_by_name += 1;
            compare_class(ca, &b[ib], opts, &mut report);
        }
    }

    // PASSE 2 — même empreinte, nom différent : renommage RÉEL de classe.
    // Les opérandes restent comparables (même séquence de mnémoniques).
    for (ia, ca) in a.iter().enumerate() {
        if a_taken[ia] || ca.methods.is_empty() {
            continue;
        }
        let found = b_by_hash
            .get(&ca.class_hash)
            .and_then(|v| v.iter().copied().find(|&i| !b_taken[i]));
        if let Some(ib) = found {
            a_taken[ia] = true;
            b_taken[ib] = true;
            report.classes_paired += 1;
            report.paired_by_hash += 1;
            compare_class(ca, &b[ib], opts, &mut report);
        }
    }

    // PASSE 3 — même nom, empreinte différente : appariées mais NON alignables
    // index par index. C'est le seul cas qui demande un aligneur.
    for (ia, ca) in a.iter().enumerate() {
        if a_taken[ia] {
            continue;
        }
        let found = b_by_name
            .get(&ca.descriptor)
            .and_then(|v| v.iter().copied().find(|&i| !b_taken[i]));
        if let Some(ib) = found {
            a_taken[ia] = true;
            b_taken[ib] = true;
            report.unaligned.push(Unaligned {
                class_a: ca.descriptor.clone(),
                class_b: b[ib].descriptor.clone(),
                methods_a: ca.methods.len(),
                methods_b: b[ib].methods.len(),
            });
            // Alignement LCS : c'est le seul cas qui en a besoin, et il est
            // rare par construction (les empreintes diffèrent). Le coût O(n·m)
            // est donc payé sur une poignée de méthodes, pas sur le corpus.
            let ac = align_class(ca, &b[ib], opts);
            report.aligned.push(ac);
            // Les valeurs statiques ne dépendent d'aucun alignement d'opcodes :
            // elles se comparent ici aussi.
            compare_statics(ca, &b[ib], opts, &mut report);
        }
    }

    // PASSE 4 — sans contrepartie d'aucune sorte.
    for (ia, ca) in a.iter().enumerate() {
        if !a_taken[ia] {
            report.only_in_a.push(ca.descriptor.clone());
        }
    }

    report.only_in_b = b
        .iter()
        .enumerate()
        .filter(|(i, _)| !b_taken[*i])
        .map(|(_, c)| c.descriptor.clone())
        .collect();

    // Comptes par catégorie, ordonnés par gravité.
    let mut counts: HashMap<Divergence, usize> = HashMap::new();
    for f in &report.findings {
        *counts.entry(f.kind).or_insert(0) += 1;
    }
    let mut kinds: Vec<(Divergence, usize)> = counts.into_iter().collect();
    kinds.sort_by_key(|(k, _)| *k);
    report.by_kind = kinds.into_iter().map(|(k, n)| (k.label().to_string(), n)).collect();

    Ok(report)
}

/// Compare deux classes de même empreinte : apparie les méthodes par empreinte,
/// puis les opérandes index par index.
fn compare_class(a: &ClassRich, b: &ClassRich, opts: &ExplainOptions, out: &mut ExplainReport) {
    compare_statics(a, b, opts, out);

    // Index des méthodes B par empreinte. Plusieurs méthodes peuvent partager la
    // même (accesseurs triviaux) : on consomme dans l'ordre.
    let mut pool: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, m) in b.methods.iter().enumerate() {
        pool.entry(m.fingerprint).or_default().push(i);
    }

    for ma in &a.methods {
        let Some(list) = pool.get_mut(&ma.fingerprint) else {
            continue;
        };
        if list.is_empty() {
            continue;
        }
        let mb = &b.methods[list.remove(0)];

        // Empreintes égales => mêmes mnémoniques, même longueur. On garde une
        // garde : un DEX corrompu ou un dump partiel ne doit pas paniquer.
        if ma.slots.len() != mb.slots.len() {
            continue;
        }
        out.methods_compared += 1;

        let before = out.findings.len();
        for (sa, sb) in ma.slots.iter().zip(mb.slots.iter()) {
            if sa.mnemonic != sb.mnemonic {
                continue;
            }
            if let Some(kind) = classify(sa.operand.as_ref(), sb.operand.as_ref()) {
                out.findings.push(Finding {
                    class_a: a.descriptor.clone(),
                    class_b: b.descriptor.clone(),
                    method: ma.name.clone(),
                    field: None,
                    offset: sa.offset,
                    mnemonic: sa.mnemonic.clone(),
                    kind,
                    value_a: truncate(&render(sa.operand.as_ref()), opts.max_value),
                    value_b: truncate(&render(sb.operand.as_ref()), opts.max_value),
                });
            }
        }
        if out.findings.len() == before {
            out.methods_clean += 1;
        }
    }
}

/// Compare les valeurs initiales des champs statiques de deux classes appariées.
///
/// Appariement par NOM de champ. Un champ sans homonyme en face est COMPTÉ mais
/// pas remonté : entre deux lots obfusqués séparément le remapping de noms en
/// produirait en masse, et ce bruit noierait la poignée de valeurs qui compte.
fn compare_statics(a: &ClassRich, b: &ClassRich, opts: &ExplainOptions, out: &mut ExplainReport) {
    if a.statics.is_empty() && b.statics.is_empty() {
        return;
    }
    let b_by_name: HashMap<&str, &Option<DexValue>> =
        b.statics.iter().map(|(n, v)| (n.as_str(), v)).collect();

    for (name, va) in &a.statics {
        let Some(vb) = b_by_name.get(name.as_str()).copied() else {
            out.statics_unpaired += 1;
            continue;
        };
        out.statics_compared += 1;
        if va == vb {
            continue;
        }
        out.findings.push(Finding {
            class_a: a.descriptor.clone(),
            class_b: b.descriptor.clone(),
            method: STATIC_SLOT.to_string(),
            field: Some(name.clone()),
            offset: 0,
            mnemonic: STATIC_SLOT.to_string(),
            kind: Divergence::StaticValue,
            value_a: truncate(&render_static(va.as_ref()), opts.max_value),
            value_b: truncate(&render_static(vb.as_ref()), opts.max_value),
        });
    }

    let a_names: HashSet<&str> = a.statics.iter().map(|(n, _)| n.as_str()).collect();
    out.statics_unpaired += b
        .statics
        .iter()
        .filter(|(n, _)| !a_names.contains(n.as_str()))
        .count();
}

/// Pseudo-méthode sous laquelle les divergences de valeur statique sont
/// regroupées : elles n'appartiennent à aucun corps de méthode.
const STATIC_SLOT: &str = "<static>";

/// Rendu d'une valeur statique. `None` = le `encoded_array` s'arrêtait avant ce
/// champ, ce qui est une information en soi et non une valeur nulle.
fn render_static(v: Option<&DexValue>) -> String {
    let Some(v) = v else {
        return "(pas de valeur initiale)".to_string();
    };
    match v {
        DexValue::Str(s) => format!("\"{}\"", escape(s)),
        DexValue::Type(t) => t.clone(),
        DexValue::Field(f) | DexValue::Enum(f) => f.clone(),
        DexValue::Method(m) => format!("{m}()"),
        DexValue::Byte(n) => n.to_string(),
        DexValue::Short(n) => n.to_string(),
        DexValue::Char(n) => format!("u+{n:04x}"),
        DexValue::Int(n) => n.to_string(),
        DexValue::Long(n) => n.to_string(),
        DexValue::Float(n) => n.to_string(),
        DexValue::Double(n) => n.to_string(),
        DexValue::Bool(b) => b.to_string(),
        DexValue::Null => "null".to_string(),
        DexValue::Array(v) => format!(
            "[{}]",
            v.iter().map(|x| render_static(Some(x))).collect::<Vec<_>>().join(", ")
        ),
        DexValue::Opaque(k) => format!("<{k}>"),
    }
}

/// Classe la divergence entre deux opérandes, ou `None` si elles coïncident.
fn classify(a: Option<&Operand>, b: Option<&Operand>) -> Option<Divergence> {
    match (a, b) {
        (None, None) => None,
        (Some(_), None) | (None, Some(_)) => Some(Divergence::Presence),
        (Some(x), Some(y)) if x == y => None,
        (Some(Operand::Str(_)), Some(Operand::Str(_))) => Some(Divergence::StringValue),
        (Some(Operand::Type(_)), Some(Operand::Type(_))) => Some(Divergence::TypeRef),
        (Some(Operand::Method(..)), Some(Operand::Method(..))) => Some(Divergence::MethodTarget),
        (Some(Operand::Field(oa, _, ta)), Some(Operand::Field(ob, _, tb))) => {
            // Owner et type identiques, seul le nom bouge -> ProGuard a
            // renommé le champ. Le produit n'a pas changé.
            if oa == ob && ta == tb {
                Some(Divergence::FieldRename)
            } else {
                Some(Divergence::FieldTarget)
            }
        }
        // Natures différentes à mnémonique égal : anormal, on le signale.
        _ => Some(Divergence::Presence),
    }
}

fn render(o: Option<&Operand>) -> String {
    o.map(|x| x.render()).unwrap_or_else(|| "-".to_string())
}

fn truncate(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        return s.to_string();
    }
    format!("{}…", s.chars().take(max.saturating_sub(1)).collect::<String>())
}

// ── Alignement LCS ──────────────────────────────────────────────────

/// Aligne deux classes dont les empreintes diffèrent.
///
/// Les méthodes sont appariées par **NOM** — pas par empreinte, qui par
/// définition ne coïncide pas ici. Une surcharge multiple consomme dans l'ordre
/// de déclaration ; c'est une approximation assumée, et elle se voit à la
/// lecture (les deux signatures sont affichées).
fn align_class(a: &ClassRich, b: &ClassRich, opts: &ExplainOptions) -> AlignedClass {
    let mut pool: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, m) in b.methods.iter().enumerate() {
        pool.entry(m.name.as_str()).or_default().push(i);
    }

    let mut methods = Vec::new();
    let mut only_a = Vec::new();
    let mut taken = vec![false; b.methods.len()];

    for ma in &a.methods {
        let ib = pool
            .get(ma.name.as_str())
            .and_then(|v| v.iter().copied().find(|&i| !taken[i]));
        let Some(ib) = ib else {
            only_a.push(ma.name.clone());
            continue;
        };
        taken[ib] = true;
        methods.push(align_method(ma, &b.methods[ib], opts));
    }

    let only_b = b
        .methods
        .iter()
        .enumerate()
        .filter(|(i, _)| !taken[*i])
        .map(|(_, m)| m.name.clone())
        .collect();

    AlignedClass {
        class_a: a.descriptor.clone(),
        class_b: b.descriptor.clone(),
        methods,
        only_a,
        only_b,
    }
}

fn align_method(ma: &MethodRich, mb: &MethodRich, opts: &ExplainOptions) -> AlignedMethod {
    let mut out = AlignedMethod {
        name: ma.name.clone(),
        fp_a: format!("{:016x}", ma.fingerprint),
        fp_b: format!("{:016x}", mb.fingerprint),
        insns_a: ma.slots.len(),
        insns_b: mb.slots.len(),
        changed: 0,
        lines: Vec::new(),
        skipped: false,
    };

    let Some(pairs) = lcs(&ma.slots, &mb.slots, opts.align_cap) else {
        out.skipped = true;
        return out;
    };

    for (ia, ib) in pairs {
        let line = match (ia, ib) {
            (Some(i), Some(j)) => {
                let sa = &ma.slots[i];
                let sb = &mb.slots[j];
                let same = sa.operand == sb.operand;
                AlignedLine {
                    kind: if same { "=" } else { "~" },
                    offset_a: Some(sa.offset),
                    offset_b: Some(sb.offset),
                    mnemonic: sa.mnemonic.clone(),
                    value_a: sa
                        .operand
                        .as_ref()
                        .map(|o| truncate(&o.render(), opts.max_value)),
                    value_b: sb
                        .operand
                        .as_ref()
                        .map(|o| truncate(&o.render(), opts.max_value)),
                }
            }
            (Some(i), None) => {
                let sa = &ma.slots[i];
                AlignedLine {
                    kind: "-",
                    offset_a: Some(sa.offset),
                    offset_b: None,
                    mnemonic: sa.mnemonic.clone(),
                    value_a: sa
                        .operand
                        .as_ref()
                        .map(|o| truncate(&o.render(), opts.max_value)),
                    value_b: None,
                }
            }
            (None, Some(j)) => {
                let sb = &mb.slots[j];
                AlignedLine {
                    kind: "+",
                    offset_a: None,
                    offset_b: Some(sb.offset),
                    mnemonic: sb.mnemonic.clone(),
                    value_a: None,
                    value_b: sb
                        .operand
                        .as_ref()
                        .map(|o| truncate(&o.render(), opts.max_value)),
                }
            }
            (None, None) => unreachable!("lcs ne produit jamais (None, None)"),
        };
        if line.is_change() {
            out.changed += 1;
        }
        out.lines.push(line);
    }
    out
}

/// Plus longue sous-séquence commune sur les MNÉMONIQUES, rendue comme une
/// suite d'appariements. `None` si l'une des séquences dépasse `cap` — la table
/// DP est en O(n·m) en temps ET en mémoire.
///
/// On aligne sur les mnémoniques SEULS, jamais sur les opérandes : sinon un
/// simple changement de constante empêcherait l'appariement et ferait ressortir
/// la méthode entière comme réécrite. C'est la même raison qui fait qu'on ne
/// diffe pas le texte du désassemblage.
fn lcs(a: &[Slot], b: &[Slot], cap: usize) -> Option<Vec<(Option<usize>, Option<usize>)>> {
    let (n, m) = (a.len(), b.len());
    if n > cap || m > cap {
        return None;
    }

    // dp[i][j] = longueur de la LCS de a[i..] et b[j..].
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if a[i].mnemonic == b[j].mnemonic {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }

    let mut out = Vec::with_capacity(n.max(m));
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if a[i].mnemonic == b[j].mnemonic {
            out.push((Some(i), Some(j)));
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            out.push((Some(i), None));
            i += 1;
        } else {
            out.push((None, Some(j)));
            j += 1;
        }
    }
    while i < n {
        out.push((Some(i), None));
        i += 1;
    }
    while j < m {
        out.push((None, Some(j)));
        j += 1;
    }
    Some(out)
}

/// Indices des lignes à afficher : les changements, plus `ctx` lignes de
/// contexte de part et d'autre. Rend aussi les ruptures pour insérer un `…`.
fn visible(lines: &[AlignedLine], ctx: usize) -> Vec<usize> {
    if ctx == usize::MAX {
        return (0..lines.len()).collect();
    }
    let mut keep = vec![false; lines.len()];
    for (i, l) in lines.iter().enumerate() {
        if l.is_change() {
            let lo = i.saturating_sub(ctx);
            let hi = (i + ctx + 1).min(lines.len());
            for k in lo..hi {
                keep[k] = true;
            }
        }
    }
    keep.iter()
        .enumerate()
        .filter(|(_, &k)| k)
        .map(|(i, _)| i)
        .collect()
}

// ── Chargement ───────────────────────────────────────────────────────────────

fn load(input: &Path, opts: &ExplainOptions) -> Result<(Vec<ClassRich>, Option<tempfile::TempDir>)> {
    let (paths, tmp) = collect_dex_paths(input)?;
    let mut out = Vec::new();
    for p in &paths {
        collect_from_dex(p, opts, &mut out).with_context(|| format!("parse {}", p.display()))?;
    }
    if out.is_empty() {
        bail!(
            "aucune classe applicative retenue dans {} — vérifie --explain-include \
             (préfixes au format descripteur Dalvik, ex. Lcom/dy/)",
            input.display()
        );
    }
    Ok((out, tmp))
}

fn collect_from_dex(path: &Path, opts: &ExplainOptions, out: &mut Vec<ClassRich>) -> Result<()> {
    let dex = crate::parser::dex_facade::DexBin::open(path)?;

    for class in dex.classes() {
        let class = match class {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "skip unreadable class");
                continue;
            }
        };
        let raw = class.descriptor.to_string();
        if !included(&raw, &opts.include_prefixes) {
            continue;
        }

        let mut methods = Vec::new();
        for method in &class.methods {
            let Some(code) = &method.code else { continue };

            let instructions = match dex_bytecode::decode_all(code.insns, 0) {
                Ok(i) => i,
                Err(e) => {
                    tracing::warn!(class = %raw, error = %e, "decode failed");
                    continue;
                }
            };

            // Empreinte : mnémoniques seuls. MÊME calcul que diff_dex.
            let fingerprint = {
                let mut h = DefaultHasher::new();
                for ins in &instructions {
                    ins.mnemonic().hash(&mut h);
                }
                h.finish()
            };

            let slots = instructions
                .iter()
                .map(|ins| Slot {
                    offset: ins.offset as u64,
                    mnemonic: ins.mnemonic().to_string(),
                    // Normalisation AVANT comparaison : c'est le point clé.
                    operand: resolve(&dex, ins).map(|o| o.normalized(&opts.normalize)),
                })
                .collect();

            methods.push(MethodRich {
                name: method.name.to_string(),
                fingerprint,
                slots,
            });
        }

        // Valeurs statiques : lues dans `encoded_static_values`, jamais dans
        // les instructions. Normalisées comme les opérandes, sans quoi un
        // endpoint de marque divergerait sur le seul namespace.
        let statics: Vec<(String, Option<DexValue>)> = match dex.static_fields(&class) {
            Ok(fields) => fields
                .into_iter()
                .map(|f| {
                    let value = f.value.map(|v| v.normalized(&opts.normalize));
                    (normalize(&f.name, &opts.normalize), value)
                })
                .collect(),
            Err(e) => {
                tracing::warn!(class = %raw, error = %e, "valeurs statiques illisibles");
                Vec::new()
            }
        };

        // Une classe qui ne porte QUE des constantes de compilation n'a pas de
        // `<clinit>` : zéro méthode avec code. L'écarter ici reviendrait à
        // rendre invisible exactement ce que la catégorie `valeur-statique`
        // cherche.
        if methods.is_empty() && statics.is_empty() {
            continue;
        }

        let class_hash = {
            let mut fps: Vec<u64> = methods.iter().map(|m| m.fingerprint).collect();
            fps.sort_unstable();
            let mut h = DefaultHasher::new();
            fps.hash(&mut h);
            h.finish()
        };

        out.push(ClassRich {
            descriptor: normalize(&raw, &opts.normalize),
            methods,
            class_hash,
            statics,
        });
    }
    Ok(())
}

/// Filtre d'inclusion. Sans préfixe, exclusion best-effort des libs — même liste
/// que `diff_dex`, pour que les deux outils voient le même périmètre.
fn included(descriptor: &str, prefixes: &[String]) -> bool {
    if !prefixes.is_empty() {
        return prefixes.iter().any(|p| descriptor.starts_with(p));
    }
    const LIB_PREFIXES: &[&str] = &[
        "Landroid/", "Landroidx/", "Ljava/", "Ljavax/", "Lkotlin/", "Lkotlinx/",
        "Ldalvik/", "Lrx/", "Lio/reactivex/", "Lokhttp3/", "Lokio/", "Lretrofit2/",
        "Lcom/google/", "Lcom/alibaba/", "Lcom/umeng/", "Lorg/apache/", "Lorg/json/",
        "Lorg/xmlpull/", "Luk/co/chrisjenx/", "Lgov/nist/",
    ];
    !LIB_PREFIXES.iter().any(|p| descriptor.starts_with(p))
}

fn collect_dex_paths(input: &Path) -> Result<(Vec<PathBuf>, Option<tempfile::TempDir>)> {
    let mut magic = [0u8; 8];
    {
        let mut f = std::fs::File::open(input)
            .with_context(|| format!("open {}", input.display()))?;
        if f.read(&mut magic)? < 4 {
            bail!("{} trop court pour être un DEX ou un APK", input.display());
        }
    }
    if &magic[0..4] == b"dex\n" {
        return Ok((vec![input.to_path_buf()], None));
    }
    if magic[0..4] == [0x50, 0x4b, 0x03, 0x04] {
        let tmp = tempfile::tempdir().context("create tempdir")?;
        let file = std::fs::File::open(input)?;
        let mut zip = zip::ZipArchive::new(file).context("read apk as zip")?;
        let mut paths = Vec::new();
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i)?;
            let name = entry.name().to_string();
            if !(name.starts_with("classes") && name.ends_with(".dex")) {
                continue;
            }
            let dest = tmp.path().join(name.replace('/', "__"));
            let mut buf = Vec::with_capacity(entry.size() as usize);
            entry.read_to_end(&mut buf)?;
            std::fs::write(&dest, &buf)?;
            paths.push(dest);
        }
        if paths.is_empty() {
            bail!("aucun classes*.dex dans l'APK {}", input.display());
        }
        return Ok((paths, Some(tmp)));
    }
    bail!(
        "{} n'est ni un DEX (dex\\n) ni un APK (PK) — magic {:02x?}",
        input.display(),
        &magic[0..4]
    )
}

// ── Rendu ────────────────────────────────────────────────────────────────────

pub fn render_report(r: &ExplainReport, opts: &ExplainOptions) -> String {
    let c = opts.color.enabled();
    let mut s = String::new();

    s.push_str(&format!("{}\n", paint(c, BOLD, "== Diff expliqué ==")));
    s.push_str(&format!("A  {}\n", r.input_a));
    s.push_str(&format!("B  {}\n\n", r.input_b));

    s.push_str(&format!(
        "Classes appariées {}   (par nom {}, par empreinte seule {})\n\
         Méthodes comparées {}   dont sans divergence {}\n\
         Champs statiques comparés {}   sans homonyme en face {}\n",
        paint(c, CYAN, &r.classes_paired.to_string()),
        r.paired_by_name,
        paint(c, if r.paired_by_hash > 0 { YELLOW } else { DIM }, &r.paired_by_hash.to_string()),
        paint(c, CYAN, &r.methods_compared.to_string()),
        paint(c, GREEN, &r.methods_clean.to_string()),
        paint(c, CYAN, &r.statics_compared.to_string()),
        paint(c, DIM, &r.statics_unpaired.to_string()),
    ));

    if r.classes_without_code_a > 0 || r.classes_without_code_b > 0 {
        s.push_str(&format!(
            "  {} A={} B={}\n",
            paint(c, DIM, "dont classes sans méthode à code, retenues pour leurs valeurs statiques :"),
            r.classes_without_code_a,
            r.classes_without_code_b,
        ));
    }

    // ── Divergences, regroupées par classe puis méthode ──
    if r.findings.is_empty() {
        s.push_str(&format!(
            "\n{}\n",
            paint(
                c,
                GREEN,
                "Aucune divergence d'opérande sur les paires alignées : l'identité est \
                 SÉMANTIQUE, pas seulement structurelle."
            )
        ));
    } else {
        s.push_str(&format!("\n{}\n", paint(c, BOLD, "Divergences :")));
        let mut current = String::new();
        for f in &r.findings {
            let head = format!("{} ↔ {} :: {}", f.class_a, f.class_b, f.method);
            if head != current {
                s.push_str(&format!("\n  {}\n", paint(c, BOLD, &head)));
                current = head;
            }
            if f.kind == Divergence::StaticValue {
                // Pas d'offset ni de mnémonique : la valeur ne vient d'aucune
                // instruction. La colonne porte le nom du champ.
                s.push_str(&format!(
                    "    {:<28} {:<14}\n           {} {}\n           {} {}\n",
                    f.field.as_deref().unwrap_or("?"),
                    paint(c, f.kind.color(), f.kind.label()),
                    paint(c, DIM, "A"),
                    paint(c, f.kind.color(), &f.value_a),
                    paint(c, DIM, "B"),
                    paint(c, f.kind.color(), &f.value_b),
                ));
                continue;
            }
            s.push_str(&format!(
                "    {:04x}  {:<22} {:<14} {}\n           {} {}\n           {} {}\n",
                f.offset,
                f.mnemonic,
                paint(c, f.kind.color(), f.kind.label()),
                "",
                paint(c, DIM, "A"),
                paint(c, f.kind.color(), &f.value_a),
                paint(c, DIM, "B"),
                paint(c, f.kind.color(), &f.value_b),
            ));
        }
    }

    // ── Récapitulatif par catégorie ──
    if !r.by_kind.is_empty() {
        s.push_str(&format!("\n{}\n", paint(c, BOLD, "Par catégorie :")));
        for (label, n) in &r.by_kind {
            s.push_str(&format!("  {:<16} {}\n", label, n));
        }
    }

    // ── Classes à structure différente : rendu aligné par LCS ──
    if !r.aligned.is_empty() {
        s.push_str(&format!(
            "\n{}\n",
            paint(
                c,
                YELLOW,
                "Structures différentes — alignées par LCS sur les mnémoniques :"
            )
        ));
        s.push_str(&format!(
            "  {}\n",
            paint(c, DIM, "= identique   ~ même opcode, opérande différente   - seulement A   + seulement B")
        ));

        for ac in &r.aligned {
            s.push_str(&format!(
                "\n  {} ↔ {}\n",
                paint(c, BOLD, &ac.class_a),
                paint(c, BOLD, &ac.class_b)
            ));

            for m in &ac.methods {
                let fp_same = m.fp_a == m.fp_b;
                s.push_str(&format!(
                    "\n    {}   fp {} {} {}   insn {} / {}   {}\n",
                    paint(c, BOLD, &m.name),
                    &m.fp_a[..8],
                    if fp_same { "==" } else { "!=" },
                    &m.fp_b[..8],
                    m.insns_a,
                    m.insns_b,
                    if m.changed == 0 {
                        paint(c, GREEN, "identique")
                    } else {
                        paint(c, RED, &format!("{} ligne(s) divergente(s)", m.changed))
                    }
                ));

                if m.skipped {
                    s.push_str(&format!(
                        "      {}\n",
                        paint(c, DIM, "méthode trop longue pour l'alignement (--explain-align-cap)")
                    ));
                    continue;
                }
                if m.changed == 0 {
                    continue;
                }

                let idx = visible(&m.lines, opts.context);
                let mut prev: Option<usize> = None;
                for &i in &idx {
                    if let Some(p) = prev {
                        if i > p + 1 {
                            s.push_str(&format!("      {}\n", paint(c, DIM, "…")));
                        }
                    }
                    prev = Some(i);

                    let l = &m.lines[i];
                    let col = match l.kind {
                        "=" => DIM,
                        "~" => YELLOW,
                        "-" => RED,
                        _ => GREEN,
                    };
                    let off = match (l.offset_a, l.offset_b) {
                        (Some(x), _) => format!("{x:04x}"),
                        (None, Some(y)) => format!("{y:04x}"),
                        _ => "    ".into(),
                    };
                    s.push_str(&format!(
                        "      {} {}  {}\n",
                        paint(c, col, l.kind),
                        paint(c, DIM, &off),
                        paint(c, col, &l.mnemonic)
                    ));
                    // Les valeurs ne sont détaillées que si elles apportent
                    // quelque chose : inutile de répéter deux fois la même.
                    match l.kind {
                        "~" => {
                            s.push_str(&format!(
                                "             {} {}\n             {} {}\n",
                                paint(c, DIM, "A"),
                                paint(c, YELLOW, l.value_a.as_deref().unwrap_or("-")),
                                paint(c, DIM, "B"),
                                paint(c, YELLOW, l.value_b.as_deref().unwrap_or("-")),
                            ));
                        }
                        "-" | "+" => {
                            let v = l.value_a.as_deref().or(l.value_b.as_deref());
                            if let Some(v) = v {
                                s.push_str(&format!("             {}\n", paint(c, col, v)));
                            }
                        }
                        _ => {}
                    }
                }
            }

            for (title, list) in [("méthodes seulement dans A", &ac.only_a), ("méthodes seulement dans B", &ac.only_b)] {
                if !list.is_empty() {
                    s.push_str(&format!("    {} : {}\n", title, list.join(", ")));
                }
            }
        }
    }

    for (title, list) in [("Propres à A", &r.only_in_a), ("Propres à B", &r.only_in_b)] {
        if !list.is_empty() {
            s.push_str(&format!("\n{} ({}) :\n", paint(c, BOLD, title), list.len()));
            for x in list {
                s.push_str(&format!("  {x}\n"));
            }
        }
    }

    // ── Verdict ──
    let substantive: usize = r
        .findings
        .iter()
        .filter(|f| f.kind.is_substantive())
        .count();
    let noise = r.findings.len() - substantive;
    let structural: usize = r
        .aligned
        .iter()
        .flat_map(|ac| ac.methods.iter())
        .map(|m| m.changed)
        .sum();
    s.push_str(&format!("\n{}\n", paint(c, BOLD, "Verdict :")));
    s.push_str(&format!(
        "  {} divergence(s) d'opérande de fond, {} de renommage ProGuard (bruit).\n",
        paint(c, if substantive == 0 { GREEN } else { RED }, &substantive.to_string()),
        paint(c, DIM, &noise.to_string()),
    ));
    s.push_str(&format!(
        "  {} ligne(s) de divergence STRUCTURELLE sur les classes alignées par LCS.\n",
        paint(c, if structural == 0 { GREEN } else { RED }, &structural.to_string()),
    ));
    if substantive == 0 && structural == 0 {
        s.push_str(&format!(
            "  {}\n",
            paint(c, GREEN, "Rien ne distingue les deux binaires au-delà de l'obfuscation.")
        ));
    }

    s
}

/// Légende (`--diff-explain --legend`).
pub fn legend() -> String {
    format!(
        "\
== Diff expliqué (--diff-explain) — légende ==

PRINCIPE : deux méthodes de même empreinte d'opcodes ont la MÊME séquence de
mnémoniques. L'alignement est donc trivial (instruction i face à instruction i)
et il ne reste qu'à comparer les opérandes RÉSOLUES. C'est ce que --diff-dex ne
peut pas voir : son empreinte jette les index de chaîne, de type et de méthode.

Pas de `diff` textuel : un diff de désassemblage est dominé par la dérive des
offsets — une instruction insérée décale tout et la méthode entière ressort
comme divergente. En mémoire, le problème n'existe pas.

Options :
  --explain-include <PREFIXE>   Ne comparer que ce préfixe de descripteur
                                Dalvik. Répétable, passer les DEUX côtés.
                                Sans lui : exclusion best-effort des libs.
  --explain-normalize A=B       Substitution appliquée AVANT comparaison
                                (ex. com/duiyun=com/dy). Répétable.
                                ⚠️ Différent de --disasm-normalize, qui n'agit
                                qu'à l'affichage. Ici c'est indispensable :
                                sans ça chaque opérande diverge sur le
                                namespace.
  --color auto|always|never     Défaut auto : couleur si stdout est un terminal
                                et NO_COLOR absent. Redirigé vers un fichier,
                                la sortie est propre.

Catégories, par gravité décroissante :
  {chaine:<15} Une chaîne littérale change. LA catégorie qui compte —
                  hôte C2, clé d'API, chemin d'endpoint.            [rouge]
  {stat:<15} La valeur initiale d'un champ statique change. Lue dans
                  `encoded_static_values` du class_def_item, PAS dans les
                  instructions : un `static final String` initialisé par une
                  constante de compilation n'est écrit par aucun opcode. C'est
                  pourquoi elle est comptée à part — l'empreinte d'opcodes ne
                  peut structurellement pas la voir, et --diff-dex non plus.
                  Ligne sans offset ni mnémonique : la colonne porte le NOM du
                  champ.                                            [rouge]
  {meth:<15} La méthode appelée change (owner ou nom).          [jaune]
  {typ:<15} Un descripteur de type change.                     [jaune]
  {freal:<15} Un champ change d'owner ou de type.                [jaune]
  {fren:<15} Un champ garde owner ET type, seul son nom bouge :
                  remapping ProGuard, PAS une modification du
                  produit. Attendu en masse entre deux lots
                  obfusqués séparément.                          [atténué]
  {pres:<15} Opérande d'un côté, absente de l'autre. Anormal à
                  mnémonique égal — signalé plutôt que masqué.      [bleu]

Champs statiques :
  Appariement par NOM de champ, au sein d'une paire de classes déjà appariée.
  Un champ sans homonyme en face est COMPTÉ (« sans homonyme ») et jamais
  remonté en divergence : entre deux lots obfusqués séparément, le remapping de
  noms en produirait en masse et noierait la poignée de valeurs qui compte.
  Une classe qui ne porte QUE des constantes n'a pas de <clinit>, donc aucune
  méthode à code ; elle est retenue quand même, et comptée séparément.
  ⚠️ ANGLE MORT : les valeurs de type method-type, method-handle et annotation
  sont rendues `<...>` et tenues pour ÉGALES entre elles. Leurs charges utiles
  sont des index de pool, incomparables d'un DEX à l'autre ; les comparer
  fabriquerait des faux positifs. Faux négatif choisi contre faux positif.

CONTRE-ÉPREUVE : toute valeur-statique divergente doit AUSSI apparaître dans
--diff-strings sur le même couple, qui lit le pool de chaînes et voit donc tout.
Une valeur-statique absente du diff de chaînes est un faux positif — très
probablement un décalage de l'appariement positionnel champ ↔ valeur.

Le VERDICT sépare les divergences « de fond » (toutes sauf champ-renommé) du
bruit d'obfuscation. Zéro divergence de fond ET aucune classe non alignée =
identité sémantique, et non plus seulement structurelle.

LIMITE : les paires de classes dont les empreintes diffèrent ne sont PAS
expliquées — il faudrait un aligneur de séquences (LCS/Myers). Elles sont
appariées par nom, signalées, et renvoyées vers --disasm. Choix assumé : sur le
couple de référence ça ne concerne qu'une classe.",
        chaine = Divergence::StringValue.label(),
        stat = Divergence::StaticValue.label(),
        meth = Divergence::MethodTarget.label(),
        typ = Divergence::TypeRef.label(),
        freal = Divergence::FieldTarget.label(),
        fren = Divergence::FieldRename.label(),
        pres = Divergence::Presence.label(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(o: &str, n: &str, t: &str) -> Operand {
        Operand::Field(o.into(), n.into(), t.into())
    }

    #[test]
    fn identical_operands_are_not_findings() {
        let a = Operand::Str("x".into());
        assert_eq!(classify(Some(&a), Some(&a.clone())), None);
        assert_eq!(classify(None, None), None);
    }

    #[test]
    fn string_change_is_the_top_category() {
        let a = Operand::Str("https://i.safespy.com/api/".into());
        let b = Operand::Str("https://i.spyzie.io/api/".into());
        assert_eq!(classify(Some(&a), Some(&b)), Some(Divergence::StringValue));
        assert!(Divergence::StringValue.is_substantive());
    }

    #[test]
    fn field_rename_is_noise_but_owner_change_is_not() {
        // Même owner, même type, nom remappé -> bruit ProGuard.
        let a = f("Lcom/dy/MyApplication;", "a", "Landroid/content/Context;");
        let b = f("Lcom/dy/MyApplication;", "b", "Landroid/content/Context;");
        assert_eq!(classify(Some(&a), Some(&b)), Some(Divergence::FieldRename));
        assert!(!Divergence::FieldRename.is_substantive());

        // Owner différent -> divergence réelle.
        let c = f("Lcom/dy/Autre;", "a", "Landroid/content/Context;");
        assert_eq!(classify(Some(&a), Some(&c)), Some(Divergence::FieldTarget));
    }

    #[test]
    fn missing_on_one_side_is_flagged() {
        let a = Operand::Type("Lx;".into());
        assert_eq!(classify(Some(&a), None), Some(Divergence::Presence));
    }

    #[test]
    fn gravity_ordering_puts_strings_first() {
        let mut v = vec![Divergence::FieldRename, Divergence::StringValue, Divergence::TypeRef];
        v.sort();
        assert_eq!(v[0], Divergence::StringValue);
        assert_eq!(v[2], Divergence::FieldRename);
    }

    #[test]
    fn truncate_keeps_char_boundaries() {
        assert_eq!(truncate("三星浏览器", 3), "三星…");
        assert_eq!(truncate("court", 40), "court");
    }
}
