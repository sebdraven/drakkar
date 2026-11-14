//! Banc de fidélité du bundle : défauts détectables dans le Java de chaque
//! méthode de `classes/<id>.java`, et comparaison de deux bundles d'une même
//! entrée (`--bench-diff`).
//!
//! Le Java est relu par tree-sitter-java, qui tolère les erreurs. Une méthode y
//! est retrouvée par ses `java_lines`, écrites par Drakkar à la génération, et
//! contrôlée par son nom. Les détecteurs sont syntaxiques : ils signalent, ils
//! ne prouvent pas (`--bundle --legend`, Fidélité du Java). lost_call et
//! lost_string confrontent en plus le Java aux appels et chaînes du bytecode.

use anyhow::{bail, Context, Result};
use dex_bytecode::Instruction;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use tree_sitter::{Node, Parser};

use crate::parser::dex_facade::{Code, DexBin};
use crate::parser::disasm::{self, Operand};

/// Ouverture de la classe factice qui rend `classes/<id>.java` analysable :
/// sur la première ligne, donc sans décaler la numérotation.
const WRAP_OPEN: &str = "class DrakkarFidelity { ";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    LiteralReceiver,
    UndefinedVar,
    DeadAfterReturn,
    TypeMismatch,
    NullOnPrimitive,
    InvalidIdent,
    EmptyHandler,
    SwitchCaseLost,
    LostCall,
    LostString,
}

impl Kind {
    pub const ALL: [Kind; 10] = [
        Kind::LiteralReceiver,
        Kind::UndefinedVar,
        Kind::DeadAfterReturn,
        Kind::TypeMismatch,
        Kind::NullOnPrimitive,
        Kind::InvalidIdent,
        Kind::EmptyHandler,
        Kind::SwitchCaseLost,
        Kind::LostCall,
        Kind::LostString,
    ];

    /// Ce que le Java a perdu du bytecode, par opposition à ce qu'il a de faux.
    pub fn is_loss(self) -> bool {
        matches!(self, Kind::LostCall | Kind::LostString)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::LiteralReceiver => "literal_receiver",
            Kind::UndefinedVar => "undefined_var",
            Kind::DeadAfterReturn => "dead_after_return",
            Kind::TypeMismatch => "type_mismatch",
            Kind::NullOnPrimitive => "null_on_primitive",
            Kind::InvalidIdent => "invalid_ident",
            Kind::EmptyHandler => "empty_handler",
            Kind::SwitchCaseLost => "switch_case_lost",
            Kind::LostCall => "lost_call",
            Kind::LostString => "lost_string",
        }
    }
}

/// Un défaut signalé ; `line` est la ligne dans `classes/<id>.java`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Suspect {
    pub kind: Kind,
    pub line: usize,
    /// Élément perdu (lost_call, lost_string) : nom de méthode ou chaîne.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Suspect {
    pub fn at(kind: Kind, line: usize) -> Self {
        Self {
            kind,
            line,
            detail: None,
        }
    }
}

/// Au-delà, une chaîne perdue est tronquée dans `detail`.
const DETAIL_MAX_CHARS: usize = 120;

fn truncated(s: &str) -> String {
    let total = s.chars().count();
    if total <= DETAIL_MAX_CHARS {
        return s.to_string();
    }
    let head: String = s.chars().take(DETAIL_MAX_CHARS).collect();
    format!("{head}… [tronquée, {total} caractères]")
}

/// Un handler du bytecode.
#[derive(Debug)]
pub struct HandlerFact {
    /// Nom simple du type attrapé ; `None` pour le catch-all.
    pub catch_type: Option<String>,
    /// Adresse, en unités de code de 16 bits.
    pub addr: u32,
    /// Une instruction autre que move-exception, nop, goto*, return-void
    /// précède le premier saut.
    pub has_code: bool,
}

/// Ce que le bytecode d'une méthode dit de ses handlers et de ses switch.
#[derive(Debug, Default)]
pub struct MethodFacts {
    pub handlers: Vec<HandlerFact>,
    /// Valeur de case → vrai si chaque cible portant cette valeur, dans tous
    /// les switch de la méthode, a du code.
    pub cases: HashMap<i64, bool>,
    /// Noms simples des méthodes appelées par un invoke-*, sans <init>,
    /// <clinit> ni les appels que dex-decompiler réécrit (`rewritten_call`).
    pub calls: BTreeSet<String>,
    /// Littéraux const-string non vides.
    pub strings: BTreeSet<String>,
}

impl MethodFacts {
    pub fn from_code(bin: &DexBin, code: &Code<'_>, instructions: &[Instruction]) -> Self {
        let carries_code = |off: i64| -> bool {
            let Ok(off) = u32::try_from(off) else {
                return false;
            };
            let Ok(mut k) = instructions.binary_search_by_key(&off, |ins| ins.offset) else {
                return false;
            };
            while let Some(ins) = instructions.get(k) {
                match ins.mnemonic() {
                    "move-exception" | "nop" => k += 1,
                    m => return !(m.starts_with("goto") || m == "return-void"),
                }
            }
            false
        };
        let mut facts = MethodFacts::default();
        for block in code.tries.iter().flatten() {
            for h in &block.handlers {
                let catch_type = match (h.catch_all, h.catch_type) {
                    (true, _) => None,
                    (false, Some(desc)) => Some(simple_type_name(desc)),
                    (false, None) => continue,
                };
                facts.handlers.push(HandlerFact {
                    catch_type,
                    addr: h.addr,
                    has_code: carries_code(i64::from(h.addr) * 2),
                });
            }
        }
        for ins in instructions {
            let m = ins.mnemonic();
            if m.starts_with("invoke-") || matches!(m, "const-string" | "const-string/jumbo") {
                match disasm::resolve(bin, ins) {
                    Some(Operand::Method(owner, name))
                        if m.starts_with("invoke-")
                            && name != "<init>"
                            && name != "<clinit>"
                            && !rewritten_call(&owner, &name) =>
                    {
                        facts.calls.insert(name);
                    }
                    Some(Operand::Str(s)) if !s.is_empty() => {
                        facts.strings.insert(s);
                    }
                    _ => {}
                }
                continue;
            }
            if !matches!(m, "packed-switch" | "sparse-switch") {
                continue;
            }
            let base = i64::from(ins.offset);
            let fallthrough = base + i64::from(ins.length);
            for (key, rel) in switch_cases(code.insns, ins.offset as usize).unwrap_or_default() {
                let target = base + i64::from(rel) * 2;
                let has_code = target != fallthrough && carries_code(target);
                facts
                    .cases
                    .entry(i64::from(key))
                    .and_modify(|all| *all &= has_code)
                    .or_insert(has_code);
            }
        }
        facts
    }
}

/// Appels que dex-decompiler fait disparaître en réécrivant le Java : chaîne
/// StringBuilder repliée en `+`, null-checks et boxing de littéraux retirés,
/// switch sur chaîne (hashCode, equals) et sur énumération (ordinal) restaurés.
fn rewritten_call(owner: &str, name: &str) -> bool {
    match (owner, name) {
        ("Ljava/lang/StringBuilder;", "append" | "toString")
        | ("Ljava/util/Objects;", "requireNonNull")
        | (
            "Lkotlin/jvm/internal/Intrinsics;",
            "checkNotNull" | "checkNotNullParameter" | "checkNotNullExpressionValue",
        )
        | ("Ljava/lang/String;", "hashCode" | "equals")
        | (_, "ordinal") => true,
        (
            "Ljava/lang/Integer;" | "Ljava/lang/Long;" | "Ljava/lang/Boolean;"
            | "Ljava/lang/Double;" | "Ljava/lang/Float;",
            "valueOf",
        ) => true,
        _ => false,
    }
}

/// `(clé, cible relative en unités de 16 bits)` du payload d'un switch 31t.
fn switch_cases(insns: &[u8], at: usize) -> Option<Vec<(i32, i32)>> {
    let rel = read_i32(insns, at + 2)?;
    let payload = usize::try_from(at as i64 + i64::from(rel) * 2).ok()?;
    let ident = read_u16(insns, payload)?;
    let size = read_u16(insns, payload + 2)? as usize;
    let mut out = Vec::with_capacity(size);
    match ident {
        0x0100 => {
            let first = read_i32(insns, payload + 4)?;
            for i in 0..size {
                let target = read_i32(insns, payload + 8 + 4 * i)?;
                out.push((first.wrapping_add(i as i32), target));
            }
        }
        0x0200 => {
            for i in 0..size {
                let key = read_i32(insns, payload + 4 + 4 * i)?;
                let target = read_i32(insns, payload + 4 + 4 * size + 4 * i)?;
                out.push((key, target));
            }
        }
        _ => return None,
    }
    Some(out)
}

fn read_u16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn read_i32(b: &[u8], at: usize) -> Option<i32> {
    Some(i32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// `Ljava/io/IOException;` → `IOException`, `La/B$C;` → `C`.
fn simple_type_name(descriptor: &str) -> String {
    let inner = descriptor
        .strip_prefix('L')
        .and_then(|d| d.strip_suffix(';'))
        .unwrap_or(descriptor);
    let last = inner.rsplit('/').next().unwrap_or(inner);
    last.rsplit('$').next().unwrap_or(last).to_string()
}

/// Une méthode de `classes/<id>.json` vue par le banc.
pub struct MethodSpan<'a> {
    /// Nom Dalvik (`<init>`, `<clinit>` compris).
    pub name: &'a str,
    pub java_lines: Option<[usize; 2]>,
    pub facts: &'a MethodFacts,
}

#[derive(Debug, Default)]
pub struct MethodFidelity {
    pub syntax_errors: usize,
    pub suspect: Vec<Suspect>,
}

#[derive(Debug, Default)]
pub struct ClassFidelity {
    /// Dans l'ordre des méthodes passées à `analyze_class`.
    pub methods: Vec<MethodFidelity>,
    pub syntax_errors_outside_methods: usize,
}

/// Analyse `classes/<id>.java`. `fields` : champs déclarés par la classe.
pub fn analyze_class(
    java: &str,
    methods: &[MethodSpan<'_>],
    fields: &HashSet<String>,
) -> Result<ClassFidelity> {
    let source = format!("{WRAP_OPEN}{java}\n}}\n");
    let src = source.as_bytes();
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .context("grammaire tree-sitter-java")?;
    let tree = parser
        .parse(&source, None)
        .context("tree-sitter-java n'a rendu aucun arbre")?;
    let nodes = preorder(tree.root_node());

    let mut out = ClassFidelity {
        methods: methods.iter().map(|_| MethodFidelity::default()).collect(),
        syntax_errors_outside_methods: 0,
    };
    let owner = |line: usize| {
        methods
            .iter()
            .position(|m| m.java_lines.is_some_and(|[a, b]| a <= line && line <= b))
    };
    for n in &nodes {
        if n.is_error() || n.is_missing() {
            match owner(line_of(*n)) {
                Some(i) => out.methods[i].syntax_errors += 1,
                None => out.syntax_errors_outside_methods += 1,
            }
        }
    }
    for (i, m) in methods.iter().enumerate() {
        let Some([a, b]) = m.java_lines else {
            continue;
        };
        let decl = nodes.iter().copied().find(|n| {
            matches!(
                n.kind(),
                "method_declaration" | "constructor_declaration" | "static_initializer"
            ) && (a..=b).contains(&line_of(*n))
                && declares(*n, m.name, src)
        });
        if let Some(decl) = decl {
            let mut found = analyze_method(decl, src, fields, m.facts);
            found.extend(losses(decl, src, m.facts, a));
            out.methods[i].suspect = found;
        }
    }
    Ok(out)
}

/// Appels et chaînes du bytecode absents du Java de la méthode, un suspect par
/// élément, à la ligne `line`. Les lambdas et classes anonymes inlinées
/// n'ajoutent que du texte : elles ne masquent aucune perte.
fn losses(decl: Node<'_>, src: &[u8], facts: &MethodFacts, line: usize) -> Vec<Suspect> {
    let mut called: HashSet<&str> = HashSet::new();
    let mut literals: Vec<String> = Vec::new();
    for n in preorder(decl) {
        match n.kind() {
            "method_invocation" => {
                if let Some(name) = n.child_by_field_name("name") {
                    called.insert(text(name, src));
                }
            }
            "method_reference" => {
                if let Some(name) = named_children(n).into_iter().rev().find(|c| c.kind() == "identifier") {
                    called.insert(text(name, src));
                }
            }
            "string_literal" => {
                if let Some(value) = java_string_value(text(n, src)) {
                    literals.push(value);
                }
            }
            _ => {}
        }
    }
    let lost = |kind: Kind, detail: String| Suspect {
        kind,
        line,
        detail: Some(detail),
    };
    let mut out: Vec<Suspect> = facts
        .calls
        .iter()
        .filter(|name| !called.contains(name.as_str()))
        .map(|name| lost(Kind::LostCall, name.clone()))
        .collect();
    out.extend(
        facts
            .strings
            .iter()
            .filter(|s| !literals.iter().any(|l| l.contains(s.as_str())))
            .map(|s| lost(Kind::LostString, truncated(s))),
    );
    out
}

/// Valeur d'un littéral chaîne Java tel qu'écrit dans le source : guillemets
/// (ou `"""` d'un bloc de texte) retirés, échappements décodés. Un bloc de
/// texte n'est pas désindenté.
fn java_string_value(literal: &str) -> Option<String> {
    let body = match literal.strip_prefix("\"\"\"").and_then(|s| s.strip_suffix("\"\"\"")) {
        Some(block) => block.strip_prefix('\n').unwrap_or(block),
        None => literal.strip_prefix('"')?.strip_suffix('"')?,
    };
    Some(unescape_java(body))
}

/// Échappements Java : `\b \t \n \f \r \s \" \' \\`, octal `\0`–`\377`,
/// `\uXXXX` (un ou plusieurs `u`, paires de substitution recomposées), `\`
/// suivi d'un saut de ligne (bloc de texte). Un échappement inconnu est gardé
/// tel quel.
fn unescape_java(s: &str) -> String {
    let mut units: Vec<u16> = Vec::with_capacity(s.len());
    let push = |units: &mut Vec<u16>, c: char| {
        let mut buf = [0u16; 2];
        units.extend_from_slice(c.encode_utf16(&mut buf));
    };
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        if c != '\\' || i >= chars.len() {
            push(&mut units, c);
            continue;
        }
        let e = chars[i];
        i += 1;
        match e {
            'b' => push(&mut units, '\u{8}'),
            't' => push(&mut units, '\t'),
            'n' => push(&mut units, '\n'),
            'f' => push(&mut units, '\u{c}'),
            'r' => push(&mut units, '\r'),
            's' => push(&mut units, ' '),
            '"' | '\'' | '\\' => push(&mut units, e),
            '\n' => {}
            'u' => {
                while chars.get(i) == Some(&'u') {
                    i += 1;
                }
                let hex: String = chars.iter().skip(i).take(4).collect();
                match u16::from_str_radix(&hex, 16) {
                    Ok(unit) if hex.len() == 4 => {
                        units.push(unit);
                        i += 4;
                    }
                    _ => {
                        push(&mut units, '\\');
                        push(&mut units, 'u');
                    }
                }
            }
            '0'..='7' => {
                let max = if e <= '3' { 2 } else { 1 };
                let mut value = e as u32 - '0' as u32;
                let mut taken = 0;
                while taken < max {
                    match chars.get(i) {
                        Some(d @ '0'..='7') => {
                            value = value * 8 + (*d as u32 - '0' as u32);
                            i += 1;
                            taken += 1;
                        }
                        _ => break,
                    }
                }
                units.push(value as u16);
            }
            other => {
                push(&mut units, '\\');
                push(&mut units, other);
            }
        }
    }
    String::from_utf16_lossy(&units)
}

fn declares(decl: Node<'_>, name: &str, src: &[u8]) -> bool {
    match decl.kind() {
        "constructor_declaration" => name == "<init>",
        "static_initializer" => name == "<clinit>",
        _ => decl.child_by_field_name("name").map(|n| text(n, src)) == Some(name),
    }
}

const NUMERIC_LITERALS: [&str; 6] = [
    "decimal_integer_literal",
    "hex_integer_literal",
    "octal_integer_literal",
    "binary_integer_literal",
    "decimal_floating_point_literal",
    "hex_floating_point_literal",
];

const PRIMITIVES: [&str; 8] = [
    "int", "long", "short", "byte", "char", "boolean", "float", "double",
];

fn analyze_method(
    decl: Node<'_>,
    src: &[u8],
    fields: &HashSet<String>,
    facts: &MethodFacts,
) -> Vec<Suspect> {
    let nodes = preorder(decl);

    let mut declared: HashSet<&str> = HashSet::new();
    let mut types: HashMap<&str, &str> = HashMap::new();
    let mut strings: HashSet<&str> = HashSet::new();
    for &n in &nodes {
        match n.kind() {
            "variable_declarator" => {
                let Some(name) = n.child_by_field_name("name") else {
                    continue;
                };
                let name = text(name, src);
                declared.insert(name);
                let ty = n
                    .parent()
                    .filter(|p| p.kind() == "local_variable_declaration")
                    .and_then(|p| p.child_by_field_name("type"));
                if let Some(ty) = ty {
                    types.insert(name, text(ty, src));
                }
                if n.child_by_field_name("value").is_some_and(is_string_literal) {
                    strings.insert(name);
                }
            }
            "formal_parameter" | "catch_formal_parameter" | "resource" | "enhanced_for_statement"
            | "instanceof_expression" => {
                let Some(name) = n.child_by_field_name("name") else {
                    continue;
                };
                if name.kind() != "identifier" {
                    continue;
                }
                declared.insert(text(name, src));
                if let Some(ty) = n.child_by_field_name("type") {
                    types.insert(text(name, src), text(ty, src));
                }
            }
            "lambda_expression" => {
                if let Some(p) = n.child_by_field_name("parameters") {
                    if p.kind() == "identifier" {
                        declared.insert(text(p, src));
                    }
                }
            }
            "inferred_parameters" => {
                for c in named_children(n) {
                    declared.insert(text(c, src));
                }
            }
            "assignment_expression" => {
                let left = n.child_by_field_name("left");
                let right = n.child_by_field_name("right");
                if let (Some(l), Some(r)) = (left, right) {
                    if l.kind() == "identifier" && is_string_literal(r) {
                        strings.insert(text(l, src));
                    }
                }
            }
            _ => {}
        }
    }
    for (name, ty) in &types {
        if is_string_type(ty) {
            strings.insert(*name);
        }
    }
    let is_primitive_var = |n: Node<'_>| {
        n.kind() == "identifier"
            && types
                .get(text(n, src))
                .is_some_and(|ty| PRIMITIVES.contains(ty))
    };

    let mut out = Vec::new();
    let mut push = |kind: Kind, n: Node<'_>| out.push(Suspect::at(kind, line_of(n)));
    for &n in &nodes {
        match n.kind() {
            "method_invocation" | "field_access" => {
                if let Some(obj) = n.child_by_field_name("object") {
                    let inner = unparen(obj);
                    if NUMERIC_LITERALS.contains(&inner.kind())
                        || matches!(
                            inner.kind(),
                            "null_literal" | "true" | "false" | "character_literal"
                        )
                    {
                        push(Kind::LiteralReceiver, obj);
                    }
                }
            }
            "identifier" => {
                let name = text(n, src);
                if name.starts_with(|c: char| c.is_ascii_digit()) {
                    push(Kind::InvalidIdent, n);
                } else if in_expression(n) && !declared.contains(name) && !fields.contains(name) {
                    push(Kind::UndefinedVar, n);
                }
            }
            "block" | "constructor_body" => {
                if let Some(dead) = first_dead_statement(n) {
                    push(Kind::DeadAfterReturn, dead);
                }
            }
            "switch_block_statement_group" => {
                if let Some(dead) = first_dead_statement(n) {
                    push(Kind::DeadAfterReturn, dead);
                }
                let kids = named_children(n);
                let empty = kids
                    .iter()
                    .filter(|c| c.kind() != "switch_label" && !is_comment(**c))
                    .all(|c| c.kind() == "break_statement");
                if empty {
                    for label in kids.iter().filter(|c| c.kind() == "switch_label") {
                        if lost_case(*label, facts, src) {
                            push(Kind::SwitchCaseLost, *label);
                        }
                    }
                }
            }
            "switch_rule" => {
                let kids = named_children(n);
                let empty = kids
                    .iter()
                    .find(|c| c.kind() == "block")
                    .is_some_and(|b| named_children(*b).iter().all(|c| is_comment(*c)));
                if empty {
                    for label in kids.iter().filter(|c| c.kind() == "switch_label") {
                        if lost_case(*label, facts, src) {
                            push(Kind::SwitchCaseLost, *label);
                        }
                    }
                }
            }
            "local_variable_declaration" => {
                let Some(ty) = n.child_by_field_name("type") else {
                    continue;
                };
                let ty = text(ty, src);
                for d in named_children(n) {
                    if d.kind() != "variable_declarator" {
                        continue;
                    }
                    if let Some(v) = d.child_by_field_name("value") {
                        if mismatched(ty, v, &strings, src) {
                            push(Kind::TypeMismatch, d);
                        }
                    }
                }
            }
            "assignment_expression" => {
                if operator(n, src) != Some("=") {
                    continue;
                }
                let (Some(l), Some(r)) = (n.child_by_field_name("left"), n.child_by_field_name("right"))
                else {
                    continue;
                };
                if l.kind() != "identifier" {
                    continue;
                }
                if let Some(ty) = types.get(text(l, src)) {
                    if PRIMITIVES.contains(ty) && mismatched(ty, r, &strings, src) {
                        push(Kind::TypeMismatch, n);
                    }
                }
            }
            "binary_expression" => {
                if !matches!(operator(n, src), Some("==" | "!=")) {
                    continue;
                }
                let (Some(l), Some(r)) = (n.child_by_field_name("left"), n.child_by_field_name("right"))
                else {
                    continue;
                };
                let (l, r) = (unparen(l), unparen(r));
                let var = if l.kind() == "null_literal" {
                    r
                } else if r.kind() == "null_literal" {
                    l
                } else {
                    continue;
                };
                if is_primitive_var(var) {
                    push(Kind::NullOnPrimitive, n);
                }
            }
            "catch_clause" => {
                let Some(body) = n.child_by_field_name("body") else {
                    continue;
                };
                let body = named_children(body);
                if !body.iter().all(|c| is_comment(*c)) {
                    continue;
                }
                // `// handler at code unit N` (repli de dex-decompiler) désigne le
                // handler exact ; sinon, rapprochement par type.
                let addrs: Vec<u32> = body
                    .iter()
                    .filter_map(|c| handler_addr(text(*c, src)))
                    .collect();
                let caught = caught_types(n, src);
                let matching: Vec<bool> = facts
                    .handlers
                    .iter()
                    .filter(|h| {
                        if !addrs.is_empty() {
                            return addrs.contains(&h.addr);
                        }
                        match &h.catch_type {
                            Some(ty) => caught.contains(ty.as_str()),
                            None => caught.contains("Throwable"),
                        }
                    })
                    .map(|h| h.has_code)
                    .collect();
                if !matching.is_empty() && matching.iter().all(|code| *code) {
                    push(Kind::EmptyHandler, n);
                }
            }
            _ => {}
        }
    }

    // `2131230978.edit()` se lit comme le flottant `2131230978.` suivi de
    // `edit` ; `2abc`, comme l'entier `2` suivi de `abc`.
    let leaves: Vec<Node<'_>> = nodes.iter().copied().filter(|n| n.child_count() == 0).collect();
    for w in leaves.windows(2) {
        let (num, next) = (w[0], w[1]);
        if !NUMERIC_LITERALS.contains(&num.kind())
            || next.kind() != "identifier"
            || num.end_byte() != next.start_byte()
        {
            continue;
        }
        if text(num, src).ends_with('.') {
            push(Kind::LiteralReceiver, num);
        } else {
            push(Kind::InvalidIdent, num);
        }
    }

    out.sort();
    out.dedup();
    out
}

/// Position où un identifiant est lu ou écrit comme variable : jamais nom de
/// méthode, de champ, de type, d'étiquette, ni objet d'un accès (`x.` est peut-
/// être une classe).
fn in_expression(n: Node<'_>) -> bool {
    let Some(p) = n.parent() else {
        return false;
    };
    let is = |field: &str| p.child_by_field_name(field) == Some(n);
    match p.kind() {
        "binary_expression"
        | "unary_expression"
        | "update_expression"
        | "argument_list"
        | "parenthesized_expression"
        | "array_access"
        | "ternary_expression"
        | "return_statement"
        | "throw_statement"
        | "expression_statement"
        | "array_initializer"
        | "dimensions_expr"
        | "assert_statement"
        | "yield_statement"
        | "assignment_expression" => true,
        "variable_declarator" | "cast_expression" => is("value"),
        "instanceof_expression" => is("left"),
        "enhanced_for_statement" => is("value"),
        "lambda_expression" => is("body"),
        _ => false,
    }
}

fn first_dead_statement(n: Node<'_>) -> Option<Node<'_>> {
    let mut ended = false;
    for c in named_children(n) {
        match c.kind() {
            "switch_label" => continue,
            _ if is_comment(c) => continue,
            _ if ended => return Some(c),
            "return_statement" | "throw_statement" | "break_statement" | "continue_statement" => {
                ended = true
            }
            _ => {}
        }
    }
    None
}

fn lost_case(label: Node<'_>, facts: &MethodFacts, src: &[u8]) -> bool {
    named_children(label)
        .into_iter()
        .filter_map(|v| case_value(v, src))
        .any(|v| facts.cases.get(&v) == Some(&true))
}

/// Valeur entière d'un label de case : entier (décimal, hexadécimal, octal,
/// binaire, signe moins compris) ou caractère. `None` pour une chaîne ou une
/// constante d'énumération.
fn case_value(n: Node<'_>, src: &[u8]) -> Option<i64> {
    let n = unparen(n);
    let t = text(n, src).replace('_', "");
    match n.kind() {
        "unary_expression" if t.starts_with('-') => {
            let operand = n.child_by_field_name("operand")?;
            case_value(operand, src).map(|v| -v)
        }
        "decimal_integer_literal" => t.trim_end_matches(['l', 'L']).parse().ok(),
        "hex_integer_literal" | "octal_integer_literal" | "binary_integer_literal" => {
            let t = t.trim_end_matches(['l', 'L']).to_ascii_lowercase();
            let (digits, radix) = if let Some(h) = t.strip_prefix("0x") {
                (h.to_string(), 16)
            } else if let Some(b) = t.strip_prefix("0b") {
                (b.to_string(), 2)
            } else {
                (t.trim_start_matches("0o").to_string(), 8)
            };
            let v = u64::from_str_radix(&digits, radix).ok()?;
            Some(u32::try_from(v).map_or(v as i64, |v| i64::from(v as i32)))
        }
        "character_literal" => {
            let inner = t.strip_prefix('\'')?.strip_suffix('\'')?;
            let c = match inner {
                "\\n" => '\n',
                "\\t" => '\t',
                "\\r" => '\r',
                "\\b" => '\u{8}',
                "\\f" => '\u{c}',
                "\\0" => '\0',
                "\\'" => '\'',
                "\\\"" => '"',
                "\\\\" => '\\',
                s if s.starts_with("\\u") => char::from_u32(u32::from_str_radix(&s[2..], 16).ok()?)?,
                s => {
                    let mut it = s.chars();
                    let c = it.next()?;
                    if it.next().is_some() {
                        return None;
                    }
                    c
                }
            };
            Some(i64::from(c as u32))
        }
        _ => None,
    }
}

/// `N` de `// handler at code unit N` ou `// catch-all handler at code unit N`.
fn handler_addr(comment: &str) -> Option<u32> {
    let (_, rest) = comment.split_once("handler at code unit ")?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Noms simples des types d'une clause catch (`A | b.B` → {A, B}).
fn caught_types<'s>(clause: Node<'_>, src: &'s [u8]) -> HashSet<&'s str> {
    let mut out = HashSet::new();
    for p in named_children(clause) {
        if p.kind() != "catch_formal_parameter" {
            continue;
        }
        for c in named_children(p) {
            if c.kind() != "catch_type" {
                continue;
            }
            for ty in named_children(c) {
                let t = text(ty, src);
                let last = t.rsplit('.').next().unwrap_or(t);
                out.insert(last.rsplit('$').next().unwrap_or(last));
            }
        }
    }
    out
}

/// Type primitif initialisé ou réaffecté par une chaîne ou `null` ; String
/// initialisé par un nombre ou un booléen.
fn mismatched(ty: &str, value: Node<'_>, strings: &HashSet<&str>, src: &[u8]) -> bool {
    let v = unparen(value);
    if PRIMITIVES.contains(&ty) {
        return v.kind() == "null_literal" || stringish(v, strings, src);
    }
    if is_string_type(ty) {
        let v = if v.kind() == "unary_expression" {
            v.child_by_field_name("operand").map(unparen).unwrap_or(v)
        } else {
            v
        };
        return NUMERIC_LITERALS.contains(&v.kind()) || matches!(v.kind(), "true" | "false");
    }
    false
}

/// Expression qui vaut une chaîne : littéral, variable de type ou de valeur
/// String, concaténation `+` qui en contient une.
fn stringish(n: Node<'_>, strings: &HashSet<&str>, src: &[u8]) -> bool {
    let mut stack = vec![n];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "string_literal" => return true,
            "identifier" if strings.contains(text(n, src)) => return true,
            "parenthesized_expression" => stack.extend(named_children(n)),
            "binary_expression" if operator(n, src) == Some("+") => {
                stack.extend(n.child_by_field_name("left"));
                stack.extend(n.child_by_field_name("right"));
            }
            _ => {}
        }
    }
    false
}

fn is_string_literal(n: Node<'_>) -> bool {
    unparen(n).kind() == "string_literal"
}

fn is_string_type(ty: &str) -> bool {
    matches!(ty, "String" | "java.lang.String")
}

fn is_comment(n: Node<'_>) -> bool {
    matches!(n.kind(), "line_comment" | "block_comment")
}

fn operator<'s>(n: Node<'_>, src: &'s [u8]) -> Option<&'s str> {
    n.child_by_field_name("operator").map(|o| text(o, src))
}

fn unparen(mut n: Node<'_>) -> Node<'_> {
    while n.kind() == "parenthesized_expression" {
        match named_children(n).into_iter().find(|c| !is_comment(*c)) {
            Some(inner) => n = inner,
            None => break,
        }
    }
    n
}

fn text<'s>(n: Node<'_>, src: &'s [u8]) -> &'s str {
    n.utf8_text(src).unwrap_or("")
}

fn line_of(n: Node<'_>) -> usize {
    n.start_position().row + 1
}

fn named_children(n: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = n.walk();
    n.named_children(&mut cursor).collect()
}

/// Parcours préfixe itératif : pas de récursion sur les longues concaténations.
fn preorder(root: Node<'_>) -> Vec<Node<'_>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        out.push(n);
        let mut cursor = n.walk();
        let kids: Vec<Node<'_>> = n.children(&mut cursor).collect();
        stack.extend(kids.into_iter().rev());
    }
    out
}

/// Compteurs de `fidelity.json`, cumulés sur les classes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Totals {
    pub methods_total: usize,
    /// Méthodes dont le Java a été lu : `java_lines` non null.
    pub methods_analyzed: usize,
    pub methods_clean: usize,
    pub syntax_errors_total: usize,
    pub syntax_errors_outside_methods: usize,
    /// Méthodes ayant au moins un lost_call ou un lost_string. Absent d'un
    /// fidelity.json antérieur aux kinds de perte : lu comme 0.
    #[serde(default)]
    pub methods_with_loss: usize,
    /// Total par kind, chaque kind présent même à 0.
    pub suspect: BTreeMap<String, usize>,
}

impl Default for Totals {
    fn default() -> Self {
        Self {
            methods_total: 0,
            methods_analyzed: 0,
            methods_clean: 0,
            syntax_errors_total: 0,
            syntax_errors_outside_methods: 0,
            methods_with_loss: 0,
            suspect: Kind::ALL.iter().map(|k| (k.as_str().to_string(), 0)).collect(),
        }
    }
}

impl Totals {
    pub fn add_method(&mut self, analyzed: bool, syntax_errors: usize, suspect: &[Suspect]) {
        self.methods_total += 1;
        if analyzed {
            self.methods_analyzed += 1;
            if syntax_errors == 0 && suspect.is_empty() {
                self.methods_clean += 1;
            }
        }
        if suspect.iter().any(|s| s.kind.is_loss()) {
            self.methods_with_loss += 1;
        }
        self.syntax_errors_total += syntax_errors;
        for s in suspect {
            *self.suspect.entry(s.kind.as_str().to_string()).or_insert(0) += 1;
        }
    }

    pub fn add_outside(&mut self, n: usize) {
        self.syntax_errors_total += n;
        self.syntax_errors_outside_methods += n;
    }

    pub fn merge(&mut self, other: &Totals) {
        self.methods_total += other.methods_total;
        self.methods_analyzed += other.methods_analyzed;
        self.methods_clean += other.methods_clean;
        self.syntax_errors_total += other.syntax_errors_total;
        self.syntax_errors_outside_methods += other.syntax_errors_outside_methods;
        self.methods_with_loss += other.methods_with_loss;
        for (k, n) in &other.suspect {
            *self.suspect.entry(k.clone()).or_insert(0) += n;
        }
    }
}

/// Contenu de `fidelity.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub sha256: String,
    pub decompiler: DecompilerRev,
    #[serde(flatten)]
    pub totals: Totals,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecompilerRev {
    #[serde(rename = "crate")]
    pub krate: String,
    pub rev: Option<String>,
}

impl Report {
    pub fn new(sha256: &str, rev: Option<&str>, totals: Totals) -> Self {
        Self {
            sha256: sha256.to_string(),
            decompiler: DecompilerRev {
                krate: "dex-decompiler".to_string(),
                rev: rev.map(str::to_string),
            },
            totals,
        }
    }
}

#[derive(Deserialize)]
struct IndexRow {
    id: usize,
    #[serde(default)]
    suspect_methods: usize,
}

#[derive(Deserialize)]
struct MethodRow {
    signature: String,
    #[serde(default)]
    syntax_errors: usize,
    #[serde(default)]
    suspect: Vec<SuspectRow>,
}

#[derive(Deserialize)]
struct SuspectRow {
    kind: String,
    line: usize,
    #[serde(default)]
    detail: Option<String>,
}

/// `(id de classe, nom, descripteur)`.
type MethodKey = (usize, String, String);
/// kind → lignes ; `syntax_errors` y figure sans ligne.
type Defects = BTreeMap<String, Vec<(Option<usize>, Option<String>)>>;

/// Ligne du tableau des compteurs.
#[derive(Debug, Serialize)]
pub struct CounterRow {
    pub counter: String,
    pub a: usize,
    pub b: usize,
    pub delta: i64,
}

/// Une méthode qui gagne (régression) ou perd (correction) des défauts d'un kind.
#[derive(Debug, Serialize)]
pub struct MethodChange {
    pub class_id: usize,
    pub method: String,
    pub descriptor: String,
    pub kind: String,
    pub a: usize,
    pub b: usize,
    /// Lignes du kind dans B pour une régression, dans A pour une correction.
    pub lines: Vec<usize>,
    /// `detail` des suspects du même côté (lost_call, lost_string).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
}

/// Rapport de `--bench-diff`.
#[derive(Debug, Serialize)]
pub struct BenchDiff {
    pub sha256: String,
    pub rev_a: Option<String>,
    pub rev_b: Option<String>,
    pub same_rev: bool,
    pub counters: Vec<CounterRow>,
    pub regressions: Vec<MethodChange>,
    pub corrections: Vec<MethodChange>,
    /// Un compteur de défauts augmente, ou methods_clean baisse.
    pub worse: bool,
}

impl BenchDiff {
    pub fn exit_code(&self) -> i32 {
        i32::from(self.worse)
    }

    pub fn render(&self) -> String {
        let mut s = String::from("== Bench-diff fidélité ==\n\n");
        s.push_str(&format!("sha256  {}\n", self.sha256));
        s.push_str(&format!("A       {}\n", self.rev_a.as_deref().unwrap_or("rev inconnu")));
        s.push_str(&format!("B       {}\n\n", self.rev_b.as_deref().unwrap_or("rev inconnu")));
        s.push_str(&format!("{:<22} {:>8} {:>8} {:>8}\n", "kind", "A", "B", "écart"));
        for c in &self.counters {
            s.push_str(&format!("{:<22} {:>8} {:>8} {:>+8}\n", c.counter, c.a, c.b, c.delta));
        }
        for (title, list) in [
            ("Régressions", &self.regressions),
            ("Corrections", &self.corrections),
        ] {
            s.push_str(&format!("\n{title} ({})\n", list.len()));
            for m in list {
                let lines: Vec<String> = m.lines.iter().map(usize::to_string).collect();
                s.push_str(&format!(
                    "  {:06}  {}{}  {}  {} → {}  lignes {}\n",
                    m.class_id,
                    m.method,
                    m.descriptor,
                    m.kind,
                    m.a,
                    m.b,
                    if lines.is_empty() { "-".to_string() } else { lines.join(", ") }
                ));
                for d in &m.details {
                    s.push_str(&format!("          {}\n", disasm::escape(d)));
                }
            }
        }
        s
    }
}

/// Compare deux bundles `OUT/<sha256>` de la même entrée.
pub fn bench_diff(a: &Path, b: &Path) -> Result<BenchDiff> {
    let report_a = read_report(a)?;
    let report_b = read_report(b)?;
    if report_a.sha256 != report_b.sha256 {
        bail!(
            "les deux bundles ne décrivent pas la même entrée : {} (A) ≠ {} (B). --bench-diff \
             compare deux révisions du décompilateur sur le MÊME échantillon",
            report_a.sha256,
            report_b.sha256
        );
    }

    let mut counters = Vec::new();
    let mut worse = false;
    let mut kinds: Vec<String> = Kind::ALL.iter().map(|k| k.as_str().to_string()).collect();
    for k in report_a.totals.suspect.keys().chain(report_b.totals.suspect.keys()) {
        if !kinds.contains(k) {
            kinds.push(k.clone());
        }
    }
    let row = |counter: &str, a: usize, b: usize| CounterRow {
        counter: counter.to_string(),
        a,
        b,
        delta: b as i64 - a as i64,
    };
    for k in &kinds {
        let ka = report_a.totals.suspect.get(k).copied().unwrap_or(0);
        let kb = report_b.totals.suspect.get(k).copied().unwrap_or(0);
        worse |= kb > ka;
        counters.push(row(k, ka, kb));
    }
    let (sa, sb) = (report_a.totals.syntax_errors_total, report_b.totals.syntax_errors_total);
    worse |= sb > sa;
    counters.push(row("syntax_errors", sa, sb));
    let (ca, cb) = (report_a.totals.methods_clean, report_b.totals.methods_clean);
    worse |= cb < ca;
    counters.push(row("methods_clean", ca, cb));
    let (wa, wb) = (
        report_a.totals.methods_with_loss,
        report_b.totals.methods_with_loss,
    );
    worse |= wb > wa;
    counters.push(row("methods_with_loss", wa, wb));

    let ids: BTreeSet<usize> = flagged_classes(a)?
        .into_iter()
        .chain(flagged_classes(b)?)
        .collect();
    let defects_a = method_defects(a, &ids)?;
    let defects_b = method_defects(b, &ids)?;
    let keys: BTreeSet<&MethodKey> = defects_a.keys().chain(defects_b.keys()).collect();
    let empty = Defects::new();
    let mut regressions = Vec::new();
    let mut corrections = Vec::new();
    for key in keys {
        let da = defects_a.get(key).unwrap_or(&empty);
        let db = defects_b.get(key).unwrap_or(&empty);
        let kinds: BTreeSet<&String> = da.keys().chain(db.keys()).collect();
        for kind in kinds {
            let la = da.get(kind).map_or(&[][..], Vec::as_slice);
            let lb = db.get(kind).map_or(&[][..], Vec::as_slice);
            let change = |side: &[(Option<usize>, Option<String>)]| MethodChange {
                class_id: key.0,
                method: key.1.clone(),
                descriptor: key.2.clone(),
                kind: kind.clone(),
                a: la.len(),
                b: lb.len(),
                lines: side.iter().filter_map(|(line, _)| *line).collect(),
                details: side.iter().filter_map(|(_, d)| d.clone()).collect(),
            };
            if lb.len() > la.len() {
                regressions.push(change(lb));
            } else if lb.len() < la.len() {
                corrections.push(change(la));
            }
        }
    }

    Ok(BenchDiff {
        sha256: report_a.sha256,
        same_rev: report_a.decompiler.rev == report_b.decompiler.rev,
        rev_a: report_a.decompiler.rev,
        rev_b: report_b.decompiler.rev,
        counters,
        regressions,
        corrections,
        worse,
    })
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let raw = std::fs::read(path).with_context(|| format!("lecture {}", path.display()))?;
    serde_json::from_slice(&raw).with_context(|| format!("JSON invalide : {}", path.display()))
}

fn read_report(dir: &Path) -> Result<Report> {
    let path = dir.join("fidelity.json");
    if !path.is_file() {
        bail!(
            "{} absent : {} n'est pas un bundle, ou il est antérieur au banc de fidélité \
             (à régénérer avec --bundle)",
            path.display(),
            dir.display()
        );
    }
    read_json(&path)
}

/// Classes dont index.json compte au moins une méthode suspecte.
fn flagged_classes(dir: &Path) -> Result<Vec<usize>> {
    let rows: Vec<IndexRow> = read_json(&dir.join("index.json"))?;
    Ok(rows
        .into_iter()
        .filter(|r| r.suspect_methods > 0)
        .map(|r| r.id)
        .collect())
}

fn method_defects(dir: &Path, ids: &BTreeSet<usize>) -> Result<BTreeMap<MethodKey, Defects>> {
    let mut out = BTreeMap::new();
    for &id in ids {
        let path = dir.join("classes").join(format!("{id:06}.json"));
        if !path.is_file() {
            continue;
        }
        let rows: Vec<MethodRow> = read_json(&path)?;
        for row in rows {
            let Some((name, descriptor)) = split_signature(&row.signature) else {
                continue;
            };
            let defects: &mut Defects = out.entry((id, name, descriptor)).or_default();
            for s in &row.suspect {
                defects
                    .entry(s.kind.clone())
                    .or_default()
                    .push((Some(s.line), s.detail.clone()));
            }
            if row.syntax_errors > 0 {
                defects
                    .entry("syntax_errors".to_string())
                    .or_default()
                    .extend(std::iter::repeat((None, None)).take(row.syntax_errors));
            }
        }
    }
    Ok(out)
}

/// `Lowner;->nom(params)retour` → `(nom, (params)retour)`.
fn split_signature(signature: &str) -> Option<(String, String)> {
    let (_, rest) = signature.split_once("->")?;
    let at = rest.find('(')?;
    Some((rest[..at].to_string(), rest[at..].to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class_of(java: &str, name: &str, facts: &MethodFacts, fields: &[&str]) -> ClassFidelity {
        let span = [1, java.lines().count()];
        let methods = [MethodSpan {
            name,
            java_lines: Some(span),
            facts,
        }];
        let fields: HashSet<String> = fields.iter().map(|f| f.to_string()).collect();
        analyze_class(java, &methods, &fields).expect("analyse")
    }

    fn kinds_in(java: &str) -> Vec<Kind> {
        let class = class_of(java, "f", &MethodFacts::default(), &[]);
        class.methods[0].suspect.iter().map(|s| s.kind).collect()
    }

    #[test]
    fn litteral_numerique_en_recepteur() {
        let java = "    public void f() {\n        2131230978.edit();\n        null.toString();\n    }\n";
        let class = class_of(java, "f", &MethodFacts::default(), &[]);
        let found = &class.methods[0].suspect;
        assert!(found.contains(&Suspect::at(Kind::LiteralReceiver, 2)), "{found:?}");
        assert!(found.contains(&Suspect::at(Kind::LiteralReceiver, 3)), "{found:?}");
    }

    #[test]
    fn litteral_chaine_en_recepteur_n_est_pas_suspect() {
        let java = "    public void f(String s) {\n        \"RESP:\".concat(s);\n    }\n";
        assert!(kinds_in(java).is_empty(), "{:?}", kinds_in(java));
    }

    #[test]
    fn variable_jamais_declaree() {
        let java = "    public void f() {\n        this.g(v3, count);\n    }\n";
        let class = class_of(java, "f", &MethodFacts::default(), &["count"]);
        let found = &class.methods[0].suspect;
        assert_eq!(found, &[Suspect::at(Kind::UndefinedVar, 2)]);
    }

    #[test]
    fn instruction_apres_return() {
        let java = "    public void f() {\n        return;\n        android.util.Log.e(\"T\", \"x\");\n    }\n";
        let class = class_of(java, "f", &MethodFacts::default(), &[]);
        assert_eq!(
            class.methods[0].suspect,
            [Suspect::at(Kind::DeadAfterReturn, 3)]
        );
    }

    #[test]
    fn concatenation_de_chaines_dans_un_int() {
        let java = "    public void f() {\n        String s3 = \"x\";\n        int s5 = 1;\n        int s3_r0 = s3 + s5;\n    }\n";
        let class = class_of(java, "f", &MethodFacts::default(), &[]);
        assert_eq!(
            class.methods[0].suspect,
            [Suspect::at(Kind::TypeMismatch, 4)]
        );
    }

    #[test]
    fn null_compare_a_un_int() {
        let java = "    public void f(int[] a) {\n        int length = a.length;\n        if (length == null) {\n            this.g();\n        }\n    }\n";
        let class = class_of(java, "f", &MethodFacts::default(), &[]);
        assert_eq!(
            class.methods[0].suspect,
            [Suspect::at(Kind::NullOnPrimitive, 3)]
        );
    }

    #[test]
    fn identifiant_commencant_par_un_chiffre() {
        let java = "    public void f() {\n        this.g(2abc);\n    }\n";
        assert!(kinds_in(java).contains(&Kind::InvalidIdent), "{:?}", kinds_in(java));
    }

    #[test]
    fn catch_vide_alors_que_le_handler_a_du_code() {
        let java = "    public void f() {\n        try {\n            this.g();\n        } catch (java.io.IOException e) {\n        }\n    }\n";
        let mut facts = MethodFacts::default();
        facts.handlers.push(handler(Some("IOException"), 12, true));
        let class = class_of(java, "f", &facts, &[]);
        assert_eq!(
            class.methods[0].suspect,
            [Suspect::at(Kind::EmptyHandler, 4)]
        );
        facts.handlers[0].has_code = false;
        let class = class_of(java, "f", &facts, &[]);
        assert!(class.methods[0].suspect.is_empty());
    }

    fn handler(catch_type: Option<&str>, addr: u32, has_code: bool) -> HandlerFact {
        HandlerFact {
            catch_type: catch_type.map(str::to_string),
            addr,
            has_code,
        }
    }

    /// Forme de repli de dex-decompiler : le corps ne porte qu'un commentaire.
    const CATCH_COMMENT_ONLY: &str = "    public void f() {\n        try {\n            this.g();\n        } catch (Exception e) {\n            // handler at code unit 65\n        }\n    }\n";

    #[test]
    fn catch_qui_ne_contient_qu_un_commentaire_est_vide() {
        let mut facts = MethodFacts::default();
        facts.handlers.push(handler(Some("Exception"), 65, true));
        let class = class_of(CATCH_COMMENT_ONLY, "f", &facts, &[]);
        assert_eq!(
            class.methods[0].suspect,
            [Suspect::at(Kind::EmptyHandler, 4)]
        );
    }

    /// Un autre handler Exception, vide, ne masque plus celui que le
    /// commentaire désigne.
    #[test]
    fn adresse_du_commentaire_designe_le_handler() {
        let mut facts = MethodFacts::default();
        facts.handlers.push(handler(Some("Exception"), 65, true));
        facts.handlers.push(handler(Some("Exception"), 90, false));
        let class = class_of(CATCH_COMMENT_ONLY, "f", &facts, &[]);
        assert_eq!(
            class.methods[0].suspect,
            [Suspect::at(Kind::EmptyHandler, 4)]
        );
        facts.handlers[0].has_code = false;
        let class = class_of(CATCH_COMMENT_ONLY, "f", &facts, &[]);
        assert!(class.methods[0].suspect.is_empty());
    }

    #[test]
    fn case_avec_commentaire_puis_break_est_sans_corps() {
        let java = "    public void f(int i) {\n        switch (i) {\n            case 1:\n                this.g();\n                break;\n            case 2:\n                // rien\n                break;\n        }\n    }\n";
        let mut facts = MethodFacts::default();
        facts.cases.insert(1, true);
        facts.cases.insert(2, true);
        let class = class_of(java, "f", &facts, &[]);
        assert_eq!(
            class.methods[0].suspect,
            [Suspect::at(Kind::SwitchCaseLost, 6)]
        );
    }

    #[test]
    fn commentaire_apres_return_n_est_pas_du_code_mort() {
        let java = "    public void f() {\n        return;\n        // fin\n    }\n";
        assert!(kinds_in(java).is_empty(), "{:?}", kinds_in(java));
    }

    fn lost(kind: Kind, detail: &str) -> Suspect {
        Suspect {
            kind,
            line: 1,
            detail: Some(detail.to_string()),
        }
    }

    #[test]
    fn appel_du_bytecode_absent_du_java() {
        let java = "    public void m() {\n        this.f();\n    }\n";
        let mut facts = MethodFacts::default();
        facts.calls.extend(["f".to_string(), "g".to_string()]);
        let class = class_of(java, "m", &facts, &[]);
        assert_eq!(class.methods[0].suspect, [lost(Kind::LostCall, "g")]);
    }

    #[test]
    fn chaine_echappee_retrouvee_dans_le_java() {
        let java = r#"    public void m() {
        this.f("a\"b\\c\né\101");
    }
"#;
        let mut facts = MethodFacts::default();
        facts.calls.insert("f".to_string());
        facts.strings.insert("a\"b\\c\néA".to_string());
        let class = class_of(java, "m", &facts, &[]);
        assert!(class.methods[0].suspect.is_empty(), "{:?}", class.methods[0].suspect);
    }

    #[test]
    fn chaine_du_bytecode_absente_du_java() {
        let java = "    public void m() {\n        this.f(\"Display Over Other Apps\");\n    }\n";
        let long = "x".repeat(130);
        let mut facts = MethodFacts::default();
        facts.calls.insert("f".to_string());
        facts
            .strings
            .insert("android.settings.action.MANAGE_OVERLAY_PERMISSION".to_string());
        facts.strings.insert(long.clone());
        let class = class_of(java, "m", &facts, &[]);
        let found = &class.methods[0].suspect;
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(
            found[0],
            lost(Kind::LostString, "android.settings.action.MANAGE_OVERLAY_PERMISSION")
        );
        let detail = found[1].detail.as_deref().unwrap();
        assert!(detail.starts_with(&"x".repeat(120)), "{detail}");
        assert!(detail.ends_with("[tronquée, 130 caractères]"), "{detail}");
    }

    #[test]
    fn appels_reecrits_par_le_decompilateur_ne_comptent_pas() {
        assert!(rewritten_call("Ljava/lang/StringBuilder;", "append"));
        assert!(rewritten_call("Lkotlin/jvm/internal/Intrinsics;", "checkNotNullParameter"));
        assert!(!rewritten_call("Landroid/provider/Settings;", "canDrawOverlays"));
    }

    #[test]
    fn case_sans_corps_alors_que_la_cible_a_du_code() {
        let java = "    public void f(int i) {\n        switch (i) {\n            case 1:\n                this.g();\n                break;\n            case 2:\n                break;\n        }\n    }\n";
        let mut facts = MethodFacts::default();
        facts.cases.insert(1, true);
        facts.cases.insert(2, true);
        let class = class_of(java, "f", &facts, &[]);
        assert_eq!(
            class.methods[0].suspect,
            [Suspect::at(Kind::SwitchCaseLost, 6)]
        );
    }

    #[test]
    fn accolades_cassees_comptees_dans_la_methode() {
        let java = "    public void f(boolean x) {\n        if (x) }\n        this.g();\n    }\n";
        let class = class_of(java, "f", &MethodFacts::default(), &[]);
        assert!(class.methods[0].syntax_errors > 0);
    }

    #[test]
    fn totaux_comptent_les_methodes_propres() {
        let mut t = Totals::default();
        t.add_method(true, 0, &[]);
        t.add_method(true, 1, &[]);
        t.add_method(false, 0, &[]);
        t.add_method(true, 0, &[Suspect::at(Kind::UndefinedVar, 3)]);
        t.add_outside(2);
        assert_eq!(t.methods_total, 4);
        assert_eq!(t.methods_analyzed, 3);
        assert_eq!(t.methods_clean, 1);
        assert_eq!(t.syntax_errors_total, 3);
        assert_eq!(t.suspect["undefined_var"], 1);
        assert_eq!(t.suspect["switch_case_lost"], 0);
    }

    fn write_bundle(dir: &Path, rev: &str, kind: &str, line: usize) {
        let mut totals = Totals::default();
        totals.add_method(true, 0, &[]);
        totals.add_method(true, 0, &[]);
        *totals.suspect.get_mut(kind).unwrap() += 1;
        totals.methods_clean -= 1;
        let report = Report::new(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            Some(rev),
            totals,
        );
        std::fs::create_dir_all(dir.join("classes")).unwrap();
        std::fs::write(dir.join("fidelity.json"), serde_json::to_vec(&report).unwrap()).unwrap();
        let index = serde_json::json!([{ "id": 0, "suspect_methods": 1 }]);
        std::fs::write(dir.join("index.json"), index.to_string()).unwrap();
        let methods = serde_json::json!([
            { "signature": "La;->f(I)V", "syntax_errors": 0, "suspect": [{ "kind": kind, "line": line }] },
            { "signature": "La;->g()V", "syntax_errors": 0, "suspect": [] },
        ]);
        std::fs::write(dir.join("classes/000000.json"), methods.to_string()).unwrap();
    }

    #[test]
    fn bench_diff_liste_regression_et_correction() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        write_bundle(&a, "1111111111111111111111111111111111111111", "undefined_var", 3);
        write_bundle(&b, "2222222222222222222222222222222222222222", "literal_receiver", 4);
        let diff = bench_diff(&a, &b).unwrap();
        assert!(!diff.same_rev);
        assert_eq!(diff.regressions.len(), 1);
        assert_eq!(diff.regressions[0].kind, "literal_receiver");
        assert_eq!(diff.regressions[0].method, "f");
        assert_eq!(diff.regressions[0].descriptor, "(I)V");
        assert_eq!(diff.regressions[0].lines, [4]);
        assert_eq!(diff.corrections.len(), 1);
        assert_eq!(diff.corrections[0].kind, "undefined_var");
        assert_eq!(diff.corrections[0].lines, [3]);
        assert_eq!(diff.exit_code(), 1);
    }

    #[test]
    fn bench_diff_refuse_deux_entrees_differentes() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        write_bundle(&a, "1111111111111111111111111111111111111111", "undefined_var", 3);
        write_bundle(&b, "2222222222222222222222222222222222222222", "undefined_var", 3);
        let mut other: Report = read_json(&b.join("fidelity.json")).unwrap();
        other.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into();
        std::fs::write(b.join("fidelity.json"), serde_json::to_vec(&other).unwrap()).unwrap();
        assert!(bench_diff(&a, &b).is_err());
    }
}
