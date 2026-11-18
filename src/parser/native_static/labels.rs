//! `--native --native-labels` : pour chaque fonction d'un ELF AArch64, les
//! chaînes qu'elle référence et une étiquette de lecture tirée d'elles. Index
//! inverse des xrefs de `--native-strings`. Rien n'est exécuté. Étiquettes
//! définies dans [`super::legend`].

use std::collections::{BTreeMap, HashMap, HashSet};
use std::panic::AssertUnwindSafe;

use serde::Serialize;

use super::decode::Arch;
use super::disasm::context;
use super::native_strings::{code_addresses, referenced, FnBound, Referenced};
use super::xrefs::{branch, KIND_CALL, KIND_JUMP};
use super::{hex, parse_elf, ElfReport};

pub const DEFAULT_LABELS_MAX: usize = 2000;
pub const DEFAULT_LABELS_STRINGS_MAX: usize = 50;
pub const DEFAULT_LABELS_FRAGMENT_FANOUT: usize = 8;
const FRAGMENT_MAX: u64 = 64;
const TAG_WINDOW: usize = 80;
const VALUE_MAX: usize = 200;
const NAME_MIN: usize = 3;

const LABEL_FN_NAME: &str = "fn_name";
const LABEL_LOG_TAG: &str = "log_tag";
const LABEL_SOURCE_PATH: &str = "source_path";
const LABEL_NONE: &str = "none";

/// `--native-labels <elf|*>` et ses filtres.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelsOptions {
    /// Chemin de l'ELF ; `None` pour `*`.
    pub elf: Option<String>,
    pub functions: Vec<u64>,
    pub patterns: Vec<String>,
    pub max: usize,
    pub strings_max: usize,
    pub fragment_fanout: usize,
}

impl Default for LabelsOptions {
    fn default() -> Self {
        LabelsOptions {
            elf: None,
            functions: Vec::new(),
            patterns: Vec::new(),
            max: DEFAULT_LABELS_MAX,
            strings_max: DEFAULT_LABELS_STRINGS_MAX,
            fragment_fanout: DEFAULT_LABELS_FRAGMENT_FANOUT,
        }
    }
}

/// Motifs non vides ; doublons retirés.
pub fn parse_labels_patterns(items: &[String]) -> Result<Vec<String>, String> {
    let mut found: Vec<String> = Vec::new();
    for item in items {
        if item.is_empty() {
            return Err(format!("élément {item:?} : motif vide"));
        }
        if !found.contains(item) {
            found.push(item.clone());
        }
    }
    Ok(found)
}

#[derive(Debug, Clone, Serialize)]
pub struct LabelsReport {
    pub elf: String,
    pub functions_total: usize,
    pub functions_shared_only: usize,
    pub functions_matched: usize,
    pub truncated: bool,
    pub functions: Vec<LabeledFunction>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LabeledFunction {
    pub fn_start: String,
    pub fn_end: Option<String>,
    pub bound: &'static str,
    pub label: Option<String>,
    pub label_kind: &'static str,
    pub names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    pub all_tags: Vec<String>,
    pub strings_total: usize,
    pub strings_shared: usize,
    pub strings_truncated: bool,
    pub strings: Vec<LabeledString>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LabeledString {
    pub vaddr: String,
    pub value: String,
    pub value_truncated: bool,
    pub boundary: &'static str,
    pub insn_addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via_fragment: Option<String>,
    pub shared: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment_callers: Option<usize>,
}

/// Chaîne `string` (index dans les chaînes référencées) rattachée par
/// l'instruction `insn`, directement ou par le fragment `via`, qu'appellent
/// `callers` fonctions distinctes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Hit {
    insn: u64,
    string: usize,
    via: Option<u64>,
    callers: usize,
}

struct Attached {
    bound: FnBound,
    hits: Vec<Hit>,
}

/// Les fonctions de l'ELF `bytes` que décrit `elf` qui référencent une chaîne,
/// filtrées par `options`.
pub(super) fn run(
    bytes: &[u8],
    elf: &ElfReport,
    options: &LabelsOptions,
) -> Result<LabelsReport, String> {
    let parsed = parse_elf(bytes).map_err(|e| format!("ELF illisible ({e})"))?;
    let dynamic = parsed.dynamic.as_deref();
    let (symbols, local_symbols) = (&parsed.symbols, &parsed.local_symbols);
    let ctx = context(parsed.image, dynamic, symbols, local_symbols);
    if ctx.arch != Some(Arch::Aarch64) {
        return Err(format!("machine {} : AArch64 seulement", elf.machine));
    }
    let job = || -> Result<LabelsReport, String> {
        let (strings, bounds) = referenced(bytes)?;
        let callers = |fragments: &HashSet<u64>| {
            let mut calls: HashMap<u64, Vec<u64>> = HashMap::new();
            let each = |pc, w| {
                let Some((to, kind, _)) = branch(pc, w) else {
                    return;
                };
                if (kind == KIND_CALL || kind == KIND_JUMP) && fragments.contains(&to) {
                    calls.entry(to).or_default().push(pc);
                }
            };
            code_addresses(&ctx.image, &ctx.slots, symbols, local_symbols, each);
            calls
        };
        let span = |at| bounds.bound(at);
        Ok(labels(&elf.path, &strings, span, callers, options))
    };
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(job));
    outcome.map_err(|_| "panique pendant la recherche".to_string())?
}

/// `span` : fonction bornée qui contient une adresse. `callers` : pour des
/// débuts de fragment, les bl et b qui y mènent.
fn labels(
    elf: &str,
    strings: &[Referenced],
    span: impl Fn(u64) -> Option<FnBound>,
    callers: impl FnOnce(&HashSet<u64>) -> HashMap<u64, Vec<u64>>,
    options: &LabelsOptions,
) -> LabelsReport {
    let attached = attach(strings, &span, callers);
    let fanout = options.fragment_fanout;
    let shared_only = |a: &&Attached| a.hits.iter().all(|h| is_shared(h, fanout));
    let functions_shared_only = attached.values().filter(shared_only).count();
    let functions_total = attached.len() - functions_shared_only;
    let starts = options.functions.iter().filter_map(|&at| span(at));
    let wanted: HashSet<u64> = starts.map(|b| b.start).collect();
    let needles: Vec<String> = options.patterns.iter().map(|p| p.to_lowercase()).collect();
    let matching = |hit: &Hit| {
        if is_shared(hit, fanout) {
            return false;
        }
        let value = strings[hit.string].value.to_lowercase();
        needles.iter().any(|n| value.contains(n.as_str()))
    };
    let kept = |a: &&Attached| {
        let by_function = if options.functions.is_empty() {
            !shared_only(a)
        } else {
            wanted.contains(&a.bound.start)
        };
        by_function && (needles.is_empty() || a.hits.iter().any(matching))
    };
    let matched: Vec<&Attached> = attached.values().filter(kept).collect();
    let functions_matched = matched.len();
    let mut functions = Vec::new();
    for a in matched.into_iter().take(options.max) {
        functions.push(render(a, strings, options));
    }
    LabelsReport {
        elf: elf.to_string(),
        functions_total,
        functions_shared_only,
        functions_matched,
        truncated: functions.len() < functions_matched,
        functions,
    }
}

/// Chaque instruction à sa fonction bornée, puis les chaînes de chaque
/// fonction d'au plus FRAGMENT_MAX octets à chacun de ses appelants. Triées par
/// début ; dans chaque fonction, par instruction puis par adresse de chaîne.
fn attach(
    strings: &[Referenced],
    span: impl Fn(u64) -> Option<FnBound>,
    callers: impl FnOnce(&HashSet<u64>) -> HashMap<u64, Vec<u64>>,
) -> BTreeMap<u64, Attached> {
    let mut attached = BTreeMap::new();
    for (string, s) in strings.iter().enumerate() {
        for &insn in &s.insns {
            if let Some(bound) = span(insn) {
                let hit = Hit {
                    insn,
                    string,
                    via: None,
                    callers: 0,
                };
                add(&mut attached, bound, hit);
            }
        }
    }
    let is_fragment = |a: &&Attached| {
        let size = a.bound.end.map(|end| end.saturating_sub(a.bound.start));
        size.is_some_and(|size| size <= FRAGMENT_MAX)
    };
    let small = attached.values().filter(is_fragment);
    let fragments: HashSet<u64> = small.map(|a| a.bound.start).collect();
    if !fragments.is_empty() {
        let mut relayed = Vec::new();
        for (fragment, calls) in callers(&fragments) {
            let Some(direct) = attached.get(&fragment) else {
                continue;
            };
            let mut distinct = BTreeMap::new();
            for call in calls {
                if let Some(caller) = span(call).filter(|c| c.start != fragment) {
                    distinct.insert(caller.start, caller);
                }
            }
            let count = distinct.len();
            for caller in distinct.into_values() {
                for hit in &direct.hits {
                    let hit = Hit {
                        via: Some(fragment),
                        callers: count,
                        ..*hit
                    };
                    relayed.push((caller, hit));
                }
            }
        }
        for (caller, hit) in relayed {
            add(&mut attached, caller, hit);
        }
    }
    for a in attached.values_mut() {
        a.hits.sort_unstable();
        a.hits.dedup();
    }
    attached
}

fn add(attached: &mut BTreeMap<u64, Attached>, bound: FnBound, hit: Hit) {
    let empty = || Attached {
        bound,
        hits: Vec::new(),
    };
    let entry = attached.entry(bound.start).or_insert_with(empty);
    entry.hits.push(hit);
}

/// Rattachée par un fragment qu'appellent plus de `fanout` fonctions.
fn is_shared(hit: &Hit, fanout: usize) -> bool {
    hit.via.is_some() && hit.callers > fanout
}

/// Noms, tags et étiquette sur les chaînes non partagées ; rendues d'abord
/// celles-ci, puis les partagées, jusqu'à `strings_max`.
fn render(entry: &Attached, strings: &[Referenced], options: &LabelsOptions) -> LabeledFunction {
    let fanout = options.fragment_fanout;
    let hits = entry.hits.iter().copied();
    let (own, common): (Vec<Hit>, Vec<Hit>) = hits.partition(|h| !is_shared(h, fanout));
    let mut values: Vec<&str> = Vec::new();
    for hit in &own {
        values.push(strings[hit.string].value.as_str());
    }
    let mut names: Vec<String> = Vec::new();
    let mut all_tags: Vec<String> = Vec::new();
    for &value in &values {
        if let Some(name) = leading_name(value) {
            push_new(&mut names, name);
        }
        for tag in tags_of(value) {
            if is_name_tag(tag) {
                push_new(&mut names, tag);
            }
            push_new(&mut all_tags, tag);
        }
    }
    let (label, label_kind) = label_of(&names, &all_tags, &values);
    let module = all_tags.iter().find(|t| !names.contains(t)).cloned();
    let mut shown = Vec::new();
    for hit in own.iter().chain(&common).take(options.strings_max) {
        let s = &strings[hit.string];
        let (value, value_truncated) = cut(&s.value);
        let shared = is_shared(hit, fanout);
        shown.push(LabeledString {
            vaddr: hex(s.vaddr),
            value,
            value_truncated,
            boundary: s.boundary,
            insn_addr: hex(hit.insn),
            via_fragment: hit.via.map(hex),
            shared,
            fragment_callers: shared.then_some(hit.callers),
        });
    }
    let bound = entry.bound;
    let total = entry.hits.len();
    LabeledFunction {
        fn_start: hex(bound.start),
        fn_end: bound.end.map(hex),
        bound: bound.source,
        label,
        label_kind,
        names,
        module,
        all_tags,
        strings_total: total,
        strings_shared: common.len(),
        strings_truncated: shown.len() < total,
        strings: shown,
    }
}

fn push_new(list: &mut Vec<String>, item: &str) {
    if !list.iter().any(|known| known == item) {
        list.push(item.to_string());
    }
}

/// fn_name, sinon log_tag, sinon source_path, sinon none ; `values` dans
/// l'ordre des instructions.
fn label_of(names: &[String], tags: &[String], values: &[&str]) -> (Option<String>, &'static str) {
    if let Some(name) = names.first() {
        return (Some(name.clone()), LABEL_FN_NAME);
    }
    if let Some(tag) = tags.first() {
        return (Some(tag.clone()), LABEL_LOG_TAG);
    }
    match values.iter().copied().find(|v| v.ends_with(".rs")) {
        Some(path) => (Some(path.to_string()), LABEL_SOURCE_PATH),
        None => (None, LABEL_NONE),
    }
}

/// Groupes entre crochets qui se suivent en tête de chaîne, chacun fermé dans
/// les TAG_WINDOW premiers caractères : « [ » consécutifs sautés, contenu
/// jusqu'au premier « ] », ignoré s'il est vide ou contient encore « [ ».
fn tags_of(value: &str) -> Vec<&str> {
    let mut tags = Vec::new();
    let mut rest = value;
    while rest.starts_with('[') {
        let inner = rest.trim_start_matches('[');
        let Some(close) = inner.find(']') else {
            break;
        };
        let at = value.len() - inner.len() + close;
        if value[..at].chars().count() >= TAG_WINDOW {
            break;
        }
        let tag = &inner[..close];
        if !tag.is_empty() && !tag.contains('[') {
            tags.push(tag);
        }
        rest = &inner[close + 1..];
    }
    tags
}

/// Identifiant qui suit « ] » et une espace en tête de chaîne.
fn leading_name(value: &str) -> Option<&str> {
    let rest = value.strip_prefix("] ")?;
    let end = rest.find(|c: char| !is_ident_char(c));
    let name = &rest[..end.unwrap_or(rest.len())];
    is_identifier(name).then_some(name)
}

/// Contenu entre crochets qui est un identifiant en minuscule initiale avec
/// au moins un « _ ».
fn is_name_tag(tag: &str) -> bool {
    let lower = tag.starts_with(|c: char| c.is_ascii_lowercase());
    lower && tag.contains('_') && is_identifier(tag)
}

/// Lettre ASCII ou « _ », puis lettres, chiffres ou « _ », au moins NAME_MIN
/// caractères.
fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    let first = chars.next();
    let starts = first.is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    starts && chars.all(is_ident_char) && text.len() >= NAME_MIN
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn cut(value: &str) -> (String, bool) {
    match value.char_indices().nth(VALUE_MAX) {
        Some((at, _)) => (value[..at].to_string(), true),
        None => (value.to_string(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAGMENT: u64 = 0x1200;
    const SHARED: u64 = 0x1280;
    const GENERATED: u64 = 0x10000;
    const GENERATED_COUNT: u64 = 17;
    const PANIC: &str = "[panic] index out of bounds";
    const RANGE: &str = "[core] range end index";
    const PROFILE: &str = "[internal_find_user_profile] Finding user profile";

    /// A [0x1000, 0x1100), B [0x1100, 0x1200), fragments F [0x1200, 0x1220) et
    /// G [0x1280, 0x12c0), C [0x1300, 0x1400), D [0x1400, 0x1500),
    /// E [0x1500, 0x1600), H [0x1600, 0x1700) ; puis GENERATED_COUNT fonctions
    /// de 0x100 octets à partir de GENERATED.
    const BOUNDS: [(u64, u64); 8] = [
        (0x1000, 0x1100),
        (0x1100, 0x1200),
        (FRAGMENT, FRAGMENT + 0x20),
        (SHARED, SHARED + 0x40),
        (0x1300, 0x1400),
        (0x1400, 0x1500),
        (0x1500, 0x1600),
        (0x1600, 0x1700),
    ];

    fn span(at: u64) -> Option<FnBound> {
        let mut bounds = BOUNDS.to_vec();
        for i in 0..GENERATED_COUNT {
            let start = GENERATED + 0x100 * i;
            bounds.push((start, start + 0x100));
        }
        for (start, end) in bounds {
            if (start..end).contains(&at) {
                return Some(FnBound {
                    start,
                    end: Some(end),
                    source: "eh_frame",
                });
            }
        }
        None
    }

    fn string(vaddr: u64, value: &str, insns: &[u64]) -> Referenced {
        Referenced {
            vaddr,
            value: value.to_string(),
            boundary: "nul",
            insns: insns.to_vec(),
        }
    }

    /// Triées par adresse, comme [`referenced`]. 0x9000 n'est dans aucune
    /// fonction.
    fn strings() -> Vec<Referenced> {
        let long = format!("[{}]", "a".repeat(248));
        vec![
            string(0x2000, "src/net/conn.rs", &[0x1010]),
            string(0x2010, "[Messenger][E2EE] connect", &[0x1020]),
            string(0x2030, "] should_create_e2ee_channel for", &[0x1030]),
            string(0x2060, "[Messenger] retry", &[0x1040]),
            string(0x2070, "src/storage/db.rs", &[0x1110]),
            string(0x2090, &long, &[0x1108]),
            string(0x2200, PANIC, &[0x1204]),
            string(0x2220, RANGE, &[0x1284]),
            string(0x2240, "plain text", &[0x1310]),
            string(0x2250, "hello world", &[0x1410]),
            string(0x2260, PROFILE, &[0x1510]),
            string(0x22a0, "[[LogUtil] x", &[0x1520]),
            string(0x22c0, "orphan", &[0x9000]),
        ]
    }

    /// F : appelé depuis A, C et H, et par lui-même, soit 3 appelants. G :
    /// appelé depuis A, C, D et les GENERATED_COUNT fonctions, soit 20.
    fn calls() -> HashMap<u64, Vec<u64>> {
        let mut shared = vec![0x1060, 0x1360, 0x1460];
        shared.extend((0..GENERATED_COUNT).map(|i| GENERATED + 0x100 * i + 0x10));
        HashMap::from([
            (FRAGMENT, vec![0x1050, 0x1350, 0x1650, 0x1210]),
            (SHARED, shared),
        ])
    }

    fn labeled(options: &LabelsOptions) -> LabelsReport {
        let callers = |fragments: &HashSet<u64>| {
            assert_eq!(fragments, &HashSet::from([FRAGMENT, SHARED]));
            calls()
        };
        labels("libt.so", &strings(), span, callers, options)
    }

    fn label(f: &LabeledFunction) -> (Option<&str>, &str) {
        (f.label.as_deref(), f.label_kind)
    }

    fn sharing(s: &LabeledString) -> (bool, Option<usize>) {
        (s.shared, s.fragment_callers)
    }

    fn function<'r>(report: &'r LabelsReport, start: &str) -> &'r LabeledFunction {
        let found = report.functions.iter().find(|f| f.fn_start == start);
        found.expect(start)
    }

    fn row(s: &LabeledString) -> (&str, &str, Option<&str>) {
        let via = s.via_fragment.as_deref();
        (s.insn_addr.as_str(), s.value.as_str(), via)
    }

    fn rows(f: &LabeledFunction) -> Vec<(&str, &str, Option<&str>)> {
        f.strings.iter().map(row).collect()
    }

    fn starts(report: &LabelsReport) -> Vec<&str> {
        report
            .functions
            .iter()
            .map(|f| f.fn_start.as_str())
            .collect()
    }

    #[test]
    fn a_name_after_a_closing_bracket_is_the_label_and_another_tag_the_module() {
        let report = labeled(&LabelsOptions::default());
        let a = function(&report, "0x1000");
        let name = "should_create_e2ee_channel";
        assert_eq!(a.names, [name]);
        assert_eq!(label(a), (Some(name), LABEL_FN_NAME));
        assert_eq!(a.module.as_deref(), Some("Messenger"));
        assert_eq!(a.all_tags, ["Messenger", "E2EE", "panic"]);
        assert_eq!((a.fn_end.as_deref(), a.bound), (Some("0x1100"), "eh_frame"));
        let expected = [
            ("0x1010", "src/net/conn.rs", None),
            ("0x1020", "[Messenger][E2EE] connect", None),
            ("0x1030", "] should_create_e2ee_channel for", None),
            ("0x1040", "[Messenger] retry", None),
            ("0x1204", PANIC, Some("0x1200")),
            ("0x1284", RANGE, Some("0x1280")),
        ];
        assert_eq!(rows(a), expected);
        assert_eq!((a.strings_total, a.strings_shared), (6, 1));
        assert!(!a.strings_truncated);
        assert_eq!(a.strings[1].vaddr, "0x2010");
        assert_eq!(a.strings[1].boundary, "nul");
    }

    #[test]
    fn a_lowercase_bracketed_identifier_is_a_name_and_doubled_brackets_are_skipped() {
        let report = labeled(&LabelsOptions::default());
        let e = function(&report, "0x1500");
        let name = "internal_find_user_profile";
        assert_eq!(e.names, [name]);
        assert_eq!(label(e), (Some(name), LABEL_FN_NAME));
        assert_eq!(e.all_tags, [name, "LogUtil"]);
        assert_eq!(e.module.as_deref(), Some("LogUtil"));
    }

    #[test]
    fn label_kind_follows_name_then_tag_then_source_path_then_none() {
        let report = labeled(&LabelsOptions::default());
        assert_eq!(function(&report, "0x1000").label_kind, LABEL_FN_NAME);
        let fragment = function(&report, "0x1200");
        assert_eq!(label(fragment), (Some("panic"), LABEL_LOG_TAG));
        assert!(fragment.names.is_empty());
        assert_eq!(fragment.module.as_deref(), Some("panic"));
        let b = function(&report, "0x1100");
        assert_eq!(label(b), (Some("src/storage/db.rs"), LABEL_SOURCE_PATH));
        assert!(b.all_tags.is_empty());
        let long = &b.strings[0];
        assert_eq!(long.insn_addr, "0x1108");
        assert_eq!(long.value.chars().count(), VALUE_MAX);
        assert!(long.value_truncated);
        assert!(!b.strings[1].value_truncated);
        let d = function(&report, "0x1400");
        assert_eq!(label(d), (None, LABEL_NONE));
        let json = serde_json::to_value(&report).unwrap();
        let d = &json["functions"][5];
        assert!(d["label"].is_null());
        assert_eq!(d["label_kind"], LABEL_NONE);
        assert!(d.get("module").is_none());
        assert_eq!(d["names"], serde_json::json!([]));
    }

    #[test]
    fn a_fragment_with_three_callers_keeps_its_string_and_one_with_twenty_shares_it() {
        let report = labeled(&LabelsOptions::default());
        let fragment = function(&report, "0x1200");
        assert_eq!(rows(fragment), [("0x1204", PANIC, None)]);
        let c = function(&report, "0x1300");
        let expected = [
            ("0x1204", PANIC, Some("0x1200")),
            ("0x1310", "plain text", None),
            ("0x1284", RANGE, Some("0x1280")),
        ];
        assert_eq!(rows(c), expected);
        let flags: Vec<_> = c.strings.iter().map(sharing).collect();
        assert_eq!(flags, [(false, None), (false, None), (true, Some(20))]);
        assert_eq!((c.strings_total, c.strings_shared), (3, 1));
        assert_eq!(label(c), (Some("panic"), LABEL_LOG_TAG));
        assert_eq!(c.all_tags, ["panic"]);
        let d = function(&report, "0x1400");
        assert_eq!(label(d), (None, LABEL_NONE));
        assert!(d.all_tags.is_empty());
        let h = function(&report, "0x1600");
        assert_eq!(rows(h), [("0x1204", PANIC, Some("0x1200"))]);
        let json = serde_json::to_value(&report).unwrap();
        let strings = &json["functions"][4]["strings"];
        assert_eq!(strings[0]["via_fragment"], "0x1200");
        assert_eq!(strings[0]["shared"], false);
        assert!(strings[0].get("fragment_callers").is_none());
        assert_eq!(strings[2]["shared"], true);
        assert_eq!(strings[2]["fragment_callers"], 20);
        let direct = &json["functions"][2]["strings"][0];
        assert!(direct.get("via_fragment").is_none());
    }

    #[test]
    fn a_function_with_only_shared_strings_is_left_out_unless_asked_by_address() {
        let report = labeled(&LabelsOptions::default());
        let counts = (report.functions_total, report.functions_shared_only);
        assert_eq!(counts, (8, 17));
        assert!(!starts(&report).contains(&"0x10000"));
        let options = LabelsOptions {
            functions: vec![GENERATED + 0x20],
            ..LabelsOptions::default()
        };
        let report = labeled(&options);
        assert_eq!(starts(&report), ["0x10000"]);
        assert_eq!((report.functions_total, report.functions_matched), (8, 1));
        let g = &report.functions[0];
        assert_eq!(rows(g), [("0x1284", RANGE, Some("0x1280"))]);
        assert_eq!((g.strings_total, g.strings_shared), (1, 1));
        assert_eq!(label(g), (None, LABEL_NONE));
        assert!(g.all_tags.is_empty());
    }

    #[test]
    fn every_function_with_an_unshared_string_is_counted_and_sorted_by_start() {
        let report = labeled(&LabelsOptions::default());
        let expected = [
            "0x1000", "0x1100", "0x1200", "0x1280", "0x1300", "0x1400", "0x1500", "0x1600",
        ];
        assert_eq!(starts(&report), expected);
        assert_eq!((report.functions_total, report.functions_matched), (8, 8));
        assert_eq!(report.functions_shared_only, 17);
        assert!(!report.truncated);
        assert_eq!(report.elf, "libt.so");
    }

    #[test]
    fn the_function_filter_keeps_the_functions_that_contain_an_address() {
        let options = LabelsOptions {
            functions: vec![0x1404, 0x1100, 0x9000],
            ..LabelsOptions::default()
        };
        let report = labeled(&options);
        assert_eq!(starts(&report), ["0x1100", "0x1400"]);
        assert_eq!((report.functions_total, report.functions_matched), (8, 2));
    }

    #[test]
    fn the_match_filter_ignores_case_and_shared_strings() {
        let matching = |pattern: &str| {
            let options = LabelsOptions {
                patterns: vec![pattern.to_string()],
                ..LabelsOptions::default()
            };
            labeled(&options)
        };
        let panic = matching("PANIC");
        assert_eq!(starts(&panic), ["0x1000", "0x1200", "0x1300", "0x1600"]);
        assert_eq!((panic.functions_total, panic.functions_matched), (8, 4));
        let range = matching("range");
        assert_eq!(starts(&range), ["0x1280"]);
        assert_eq!(range.functions_matched, 1);
    }

    #[test]
    fn filters_combine_with_and() {
        let both = |functions: Vec<u64>| LabelsOptions {
            functions,
            patterns: vec!["panic".to_string()],
            ..LabelsOptions::default()
        };
        assert_eq!(starts(&labeled(&both(vec![0x1000]))), ["0x1000"]);
        let none = labeled(&both(vec![0x1100]));
        assert!(none.functions.is_empty());
        assert_eq!((none.functions_total, none.functions_matched), (8, 0));
        assert!(!none.truncated);
    }

    #[test]
    fn caps_keep_exact_totals_and_cut_unshared_strings_first() {
        let options = LabelsOptions {
            max: 2,
            strings_max: 1,
            ..LabelsOptions::default()
        };
        let report = labeled(&options);
        assert_eq!(starts(&report), ["0x1000", "0x1100"]);
        assert_eq!((report.functions_total, report.functions_matched), (8, 8));
        assert!(report.truncated);
        let a = function(&report, "0x1000");
        assert_eq!(rows(a), [("0x1010", "src/net/conn.rs", None)]);
        assert_eq!((a.strings_total, a.strings_truncated), (6, true));
        assert_eq!(a.label_kind, LABEL_FN_NAME);
        assert_eq!(a.all_tags, ["Messenger", "E2EE", "panic"]);
        let b = function(&report, "0x1100");
        assert_eq!((b.strings_total, b.strings_truncated), (2, true));
        let options = LabelsOptions {
            strings_max: 5,
            ..LabelsOptions::default()
        };
        let report = labeled(&options);
        let a = function(&report, "0x1000");
        assert_eq!(a.strings.len(), 5);
        assert!(a.strings.iter().all(|s| !s.shared));
        assert!(a.strings_truncated);
    }

    #[test]
    fn bracket_groups_skip_doubled_brackets_and_close_within_80_characters() {
        assert_eq!(tags_of("[net] up"), ["net"]);
        assert_eq!(tags_of("[[LogUtil] x"), ["LogUtil"]);
        assert_eq!(tags_of("[Messenger][E2EE] y"), ["Messenger", "E2EE"]);
        assert_eq!(tags_of("[a] [b]"), ["a"]);
        assert!(tags_of("[] empty").is_empty());
        assert!(tags_of("[a[b] c").is_empty());
        assert!(tags_of("net] up").is_empty());
        let inside = format!("[{}]", "a".repeat(TAG_WINDOW - 2));
        assert_eq!(tags_of(&inside)[0].len(), TAG_WINDOW - 2);
        let outside = format!("[{}]", "a".repeat(TAG_WINDOW - 1));
        assert!(tags_of(&outside).is_empty());
    }

    #[test]
    fn names_follow_a_closing_bracket_or_are_lowercase_snake_tags() {
        let text = "] should_create_e2ee_channel for";
        assert_eq!(leading_name(text), Some("should_create_e2ee_channel"));
        assert_eq!(leading_name("] _run now"), Some("_run"));
        assert_eq!(leading_name("] ab for"), None);
        assert_eq!(leading_name("]  name"), None);
        assert_eq!(leading_name("] 9abc"), None);
        assert_eq!(leading_name("[x] name"), None);
        assert!(is_name_tag("internal_find_user_profile"));
        assert!(!is_name_tag("Messenger"));
        assert!(!is_name_tag("Log_Util"));
        assert!(!is_name_tag("lowercase"));
        assert!(!is_name_tag("a_"));
        assert!(!is_name_tag("bad-name_x"));
    }

    #[test]
    fn match_patterns_are_parsed_or_refused_with_the_item() {
        let items = ["net".to_string(), "TLS".to_string(), "net".to_string()];
        assert_eq!(parse_labels_patterns(&items).unwrap(), ["net", "TLS"]);
        let items = ["net".to_string(), String::new()];
        let why = parse_labels_patterns(&items).unwrap_err();
        assert!(why.contains("élément \"\""), "{why}");
    }

    #[test]
    fn legend_defines_every_labels_label() {
        let legend = super::super::legend();
        let labels = [
            "LABELS (labels[])",
            "functions_total",
            "functions_shared_only",
            "functions_matched",
            "fn_start, fn_end, bound",
            "label_kind",
            "names",
            "module",
            "all_tags",
            "strings_total",
            "strings_shared",
            "strings_truncated",
            "value_truncated",
            "insn_addr",
            "via_fragment",
            "shared",
            "fragment_callers",
            "--native-labels-fn",
            "--native-labels-match",
            "--native-labels-max",
            "--native-labels-strings-max",
            "--native-labels-fragment-fanout",
            LABEL_FN_NAME,
            LABEL_LOG_TAG,
            LABEL_SOURCE_PATH,
            LABEL_NONE,
        ];
        for label in labels {
            assert!(legend.contains(label), "{label}");
        }
    }
}
