//! `--native --native-fields` : par fonction d'un ELF AArch64, les noms de
//! champs que référence un désérialiseur généré (serde, prost), d'où la liste
//! des structures que le binaire lit depuis du JSON ou du protobuf. Rien n'est
//! exécuté. Étiquettes définies dans [`super::legend`].

use std::collections::{BTreeMap, HashMap, HashSet};
use std::panic::AssertUnwindSafe;

use serde::Serialize;

use super::decode::Arch;
use super::disasm::context;
use super::labels::{attach, is_shared, Attached, Hit};
use super::native_strings::{
    code_addresses, referenced_from, FnBound, Referenced, BOUNDARY_CODE, BOUNDARY_FATPTR,
};
use super::xrefs::{branch, KIND_CALL, KIND_JUMP};
use super::{hex, parse_elf, ElfReport};

pub const DEFAULT_FIELDS_MIN: usize = 3;
pub const DEFAULT_FIELDS_FRAGMENT_FANOUT: usize = 8;
pub const DEFAULT_FIELDS_MAX: usize = 1000;
const NAME_MIN: usize = 2;
const NAME_MAX: usize = 64;

/// `--native-fields <elf|*>` et ses filtres.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldsOptions {
    /// Chemin de l'ELF ; `None` pour `*`.
    pub elf: Option<String>,
    pub functions: Vec<u64>,
    pub names: Vec<String>,
    pub min: usize,
    pub fragment_fanout: usize,
    pub max: usize,
}

impl Default for FieldsOptions {
    fn default() -> Self {
        FieldsOptions {
            elf: None,
            functions: Vec::new(),
            names: Vec::new(),
            min: DEFAULT_FIELDS_MIN,
            fragment_fanout: DEFAULT_FIELDS_FRAGMENT_FANOUT,
            max: DEFAULT_FIELDS_MAX,
        }
    }
}

/// Noms exacts non vides ; doublons retirés.
pub fn parse_fields_names(items: &[String]) -> Result<Vec<String>, String> {
    let mut found: Vec<String> = Vec::new();
    for item in items {
        if item.is_empty() {
            return Err(format!("élément {item:?} : nom vide"));
        }
        if !found.contains(item) {
            found.push(item.clone());
        }
    }
    Ok(found)
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldsReport {
    pub elf: String,
    pub functions_total: usize,
    pub functions_matched: usize,
    pub truncated: bool,
    pub functions: Vec<FieldsFunction>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldsFunction {
    pub fn_start: String,
    pub fn_end: Option<String>,
    pub bound: &'static str,
    pub struct_names: Vec<String>,
    pub fields_count: usize,
    pub fields: Vec<Field>,
    pub callers: Vec<FieldsCaller>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Field {
    pub name: String,
    pub vaddr: String,
    pub boundary: &'static str,
    pub sites: Vec<String>,
    pub sites_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via_fragment: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldsCaller {
    pub insn_addr: String,
    pub function: Option<FieldsBound>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldsBound {
    pub fn_start: String,
    pub fn_end: Option<String>,
    pub bound: &'static str,
}

impl From<FnBound> for FieldsBound {
    fn from(bound: FnBound) -> Self {
        FieldsBound {
            fn_start: hex(bound.start),
            fn_end: bound.end.map(hex),
            bound: bound.source,
        }
    }
}

/// Les désérialiseurs candidats de l'ELF `bytes` que décrit `elf`, filtrés
/// par `options`.
pub(super) fn run(
    bytes: &[u8],
    elf: &ElfReport,
    options: &FieldsOptions,
) -> Result<FieldsReport, String> {
    let parsed = parse_elf(bytes).map_err(|e| format!("ELF illisible ({e})"))?;
    let dynamic = parsed.dynamic.as_deref();
    let (symbols, local_symbols) = (&parsed.symbols, &parsed.local_symbols);
    let ctx = context(parsed.image, dynamic, symbols, local_symbols);
    if ctx.arch != Some(Arch::Aarch64) {
        return Err(format!("machine {} : AArch64 seulement", elf.machine));
    }
    let job = || -> Result<FieldsReport, String> {
        let (strings, bounds) = referenced_from(bytes, NAME_MIN)?;
        let mut calls = Vec::new();
        let each = |pc, w| {
            if let Some((to, kind, _)) = branch(pc, w) {
                if kind == KIND_CALL || kind == KIND_JUMP {
                    calls.push((pc, to));
                }
            }
        };
        code_addresses(&ctx.image, &ctx.slots, symbols, local_symbols, each);
        let span = |at| bounds.bound(at);
        fields(&elf.path, &strings, span, &calls, options)
    };
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(job));
    outcome.map_err(|_| "panique pendant la recherche".to_string())?
}

/// 2 à 64 caractères, lettre ASCII ou « _ », puis lettres, chiffres ou « _ ».
fn is_field_name(value: &str) -> bool {
    let mut chars = value.chars();
    let first = chars.next();
    let starts = first.is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    let rest = chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    starts && rest && (NAME_MIN..=NAME_MAX).contains(&value.len())
}

/// 2 à 64 caractères, majuscule ASCII, puis lettres et chiffres.
fn is_type_name(value: &str) -> bool {
    let mut chars = value.chars();
    let starts = chars.next().is_some_and(|c| c.is_ascii_uppercase());
    let rest = chars.all(|c| c.is_ascii_alphanumeric());
    starts && rest && (NAME_MIN..=NAME_MAX).contains(&value.len())
}

fn is_candidate(s: &Referenced) -> bool {
    let proven = s.boundary == BOUNDARY_FATPTR || s.boundary == BOUNDARY_CODE;
    proven && is_field_name(&s.value)
}

/// `span` : fonction bornée qui contient une adresse. `calls` : (bl ou b,
/// destination). Erreur : adresse de `options.functions` hors de toute
/// fonction bornée.
fn fields(
    elf: &str,
    strings: &[Referenced],
    span: impl Fn(u64) -> Option<FnBound>,
    calls: &[(u64, u64)],
    options: &FieldsOptions,
) -> Result<FieldsReport, String> {
    let relay = |fragments: &HashSet<u64>| {
        let mut found: HashMap<u64, Vec<u64>> = HashMap::new();
        for &(pc, to) in calls {
            if fragments.contains(&to) {
                found.entry(to).or_default().push(pc);
            }
        }
        found
    };
    let attached = attach(strings, &span, relay);
    let fanout = options.fragment_fanout;
    let own = |a: &Attached| -> Vec<Hit> {
        let kept = a.hits.iter().filter(|h| !is_shared(h, fanout));
        kept.filter(|h| is_candidate(&strings[h.string]))
            .copied()
            .collect()
    };
    let mut functions_total = 0;
    let mut selected: BTreeMap<u64, FnBound> = BTreeMap::new();
    for a in attached.values() {
        if distinct(&own(a), strings).len() >= options.min {
            functions_total += 1;
            if options.functions.is_empty() {
                selected.insert(a.bound.start, a.bound);
            }
        }
    }
    for &at in &options.functions {
        let why = || {
            format!(
                "élément {} : adresse hors de toute fonction bornée",
                hex(at)
            )
        };
        let bound = span(at).ok_or_else(why)?;
        selected.insert(bound.start, bound);
    }
    if !options.names.is_empty() {
        selected.retain(|start, _| {
            let hits = attached.get(start).map(own).unwrap_or_default();
            let found = distinct(&hits, strings);
            options.names.iter().any(|n| found.contains(n.as_str()))
        });
    }
    let functions_matched = selected.len();
    let mut functions = Vec::new();
    for (start, bound) in selected.into_iter().take(options.max) {
        let entry = attached.get(&start);
        let hits = entry.map(own).unwrap_or_default();
        let unshared = entry.map_or(Vec::new(), |a| {
            a.hits
                .iter()
                .filter(|h| !is_shared(h, fanout))
                .copied()
                .collect()
        });
        functions.push(render(bound, &hits, &unshared, strings, &span, calls));
    }
    Ok(FieldsReport {
        elf: elf.to_string(),
        functions_total,
        functions_matched,
        truncated: functions.len() < functions_matched,
        functions,
    })
}

fn distinct<'s>(hits: &[Hit], strings: &'s [Referenced]) -> HashSet<&'s str> {
    hits.iter()
        .map(|h| strings[h.string].value.as_str())
        .collect()
}

/// `hits` : rattachements de noms candidats ; `unshared` : tous les
/// rattachements non partagés, pour struct_names.
fn render(
    bound: FnBound,
    hits: &[Hit],
    unshared: &[Hit],
    strings: &[Referenced],
    span: &impl Fn(u64) -> Option<FnBound>,
    calls: &[(u64, u64)],
) -> FieldsFunction {
    let mut grouped: BTreeMap<(usize, Option<u64>), Vec<u64>> = BTreeMap::new();
    for hit in hits {
        grouped
            .entry((hit.string, hit.via))
            .or_default()
            .push(hit.insn);
    }
    let mut rendered = Vec::new();
    for ((string, via), mut sites) in grouped {
        sites.sort_unstable();
        sites.dedup();
        let s = &strings[string];
        rendered.push((sites[0], s.vaddr, string, via, sites));
    }
    rendered.sort();
    let fields: Vec<Field> = rendered
        .into_iter()
        .map(|(_, _, string, via, sites)| {
            let s = &strings[string];
            Field {
                name: s.value.clone(),
                vaddr: hex(s.vaddr),
                boundary: s.boundary,
                sites_count: sites.len(),
                sites: sites.into_iter().map(hex).collect(),
                via_fragment: via.map(hex),
            }
        })
        .collect();
    let mut struct_names: Vec<String> = Vec::new();
    for hit in unshared {
        let value = &strings[hit.string].value;
        if is_type_name(value) && !struct_names.contains(value) {
            struct_names.push(value.clone());
        }
    }
    let mut callers: Vec<u64> = calls
        .iter()
        .filter(|&&(_, to)| to == bound.start)
        .map(|&(pc, _)| pc)
        .collect();
    callers.sort_unstable();
    callers.dedup();
    FieldsFunction {
        fn_start: hex(bound.start),
        fn_end: bound.end.map(hex),
        bound: bound.source,
        struct_names,
        fields_count: fields.len(),
        fields,
        callers: callers
            .into_iter()
            .map(|pc| FieldsCaller {
                insn_addr: hex(pc),
                function: span(pc).map(FieldsBound::from),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: u64 = 0x1000;
    const B: u64 = 0x1100;
    const FRAGMENT: u64 = 0x1200;
    const SHARED: u64 = 0x1280;
    const C: u64 = 0x1300;
    const D: u64 = 0x1400;
    const GENERATED: u64 = 0x10000;
    const GENERATED_COUNT: u64 = 8;

    fn span(at: u64) -> Option<FnBound> {
        let mut bounds = vec![
            (A, A + 0x100),
            (B, B + 0x100),
            (FRAGMENT, FRAGMENT + 0x20),
            (SHARED, SHARED + 0x40),
            (C, C + 0x100),
            (D, D + 0x100),
        ];
        for i in 0..GENERATED_COUNT {
            let start = GENERATED + 0x100 * i;
            bounds.push((start, start + 0x100));
        }
        let (start, end) = bounds.into_iter().find(|&(s, e)| (s..e).contains(&at))?;
        Some(FnBound {
            start,
            end: Some(end),
            source: "eh_frame",
        })
    }

    fn string(vaddr: u64, value: &str, boundary: &'static str, insns: &[u64]) -> Referenced {
        Referenced {
            vaddr,
            value: value.to_string(),
            boundary,
            insns: insns.to_vec(),
        }
    }

    /// Triées par adresse, comme [`referenced_from`].
    fn strings() -> Vec<Referenced> {
        vec![
            string(0x2000, "user_id", BOUNDARY_FATPTR, &[0x1010, 0x1040]),
            string(0x2010, "name", BOUNDARY_CODE, &[0x1008]),
            string(0x2020, "createdAt", BOUNDARY_FATPTR, &[0x1018]),
            string(0x2030, "is_admin", BOUNDARY_FATPTR, &[0x1020]),
            string(0x2040, "hello world", BOUNDARY_FATPTR, &[0x1028]),
            string(0x2050, "BabaAccountPb", "nul", &[0x1030]),
            string(0x2060, "x", BOUNDARY_FATPTR, &[0x1038]),
            string(0x2070, "id", BOUNDARY_FATPTR, &[0x1108]),
            string(0x2080, "kind", BOUNDARY_FATPTR, &[0x1110]),
            string(0x2090, "token", BOUNDARY_FATPTR, &[0x1204]),
            string(0x20a0, "scope", BOUNDARY_FATPTR, &[0x1320]),
            string(0x20b0, "expires_in", BOUNDARY_CODE, &[0x1330]),
            string(0x20c0, "value", BOUNDARY_FATPTR, &[0x1284]),
            string(0x20d0, "alpha", BOUNDARY_FATPTR, &[0x1420]),
            string(0x20e0, "beta", BOUNDARY_FATPTR, &[0x1430]),
            string(0x20f0, "1st_place", BOUNDARY_FATPTR, &[0x1040]),
        ]
    }

    /// C appelle FRAGMENT et A ; D et les GENERATED_COUNT fonctions appellent
    /// SHARED, soit 9 appelants ; 0x9000, hors fonction, saute à A.
    fn calls() -> Vec<(u64, u64)> {
        let mut calls = vec![
            (0x1310, FRAGMENT),
            (0x1350, A),
            (0x9000, A),
            (0x1410, SHARED),
        ];
        calls.extend((0..GENERATED_COUNT).map(|i| (GENERATED + 0x100 * i + 0x10, SHARED)));
        calls
    }

    fn found(tune: impl FnOnce(&mut FieldsOptions)) -> FieldsReport {
        let mut options = FieldsOptions::default();
        tune(&mut options);
        fields("libt.so", &strings(), span, &calls(), &options).unwrap()
    }

    #[test]
    fn an_address_outside_every_function_is_refused() {
        let options = FieldsOptions {
            functions: vec![A, 0x9999],
            ..FieldsOptions::default()
        };
        let why = fields("libt.so", &strings(), span, &calls(), &options).unwrap_err();
        assert_eq!(
            why,
            "élément 0x9999 : adresse hors de toute fonction bornée"
        );
    }

    fn starts(report: &FieldsReport) -> Vec<&str> {
        report
            .functions
            .iter()
            .map(|f| f.fn_start.as_str())
            .collect()
    }

    fn names(f: &FieldsFunction) -> Vec<&str> {
        f.fields.iter().map(|x| x.name.as_str()).collect()
    }

    #[test]
    fn a_deserializer_with_four_fields() {
        let report = found(|_| {});
        let a = &report.functions[0];
        assert_eq!(a.fn_start, "0x1000");
        assert_eq!(names(a), ["name", "user_id", "createdAt", "is_admin"]);
        assert_eq!(a.fields_count, 4);
        let user_id = &a.fields[1];
        assert_eq!(user_id.sites, ["0x1010", "0x1040"]);
        assert_eq!((user_id.sites_count, user_id.vaddr.as_str()), (2, "0x2000"));
        assert_eq!(user_id.boundary, BOUNDARY_FATPTR);
        assert_eq!(a.fields[0].boundary, BOUNDARY_CODE);
        let json = serde_json::to_value(user_id).unwrap();
        assert!(json.get("via_fragment").is_none());
        assert_eq!((a.fn_end.as_deref(), a.bound), (Some("0x1100"), "eh_frame"));
    }

    #[test]
    fn strings_that_are_not_proven_identifiers_are_ignored() {
        let report = found(|_| {});
        let a = &report.functions[0];
        for absent in ["hello world", "BabaAccountPb", "x", "1st_place"] {
            assert!(!names(a).contains(&absent), "{absent}");
        }
    }

    #[test]
    fn struct_names_have_the_shape_of_a_type_name() {
        let report = found(|_| {});
        assert_eq!(report.functions[0].struct_names, ["BabaAccountPb"]);
        assert!(report.functions[1].struct_names.is_empty());
    }

    #[test]
    fn a_function_with_two_names_is_left_out_unless_asked_by_address() {
        let report = found(|_| {});
        assert_eq!(starts(&report), ["0x1000", "0x1300"]);
        assert_eq!((report.functions_total, report.functions_matched), (2, 2));
        let asked = found(|o| o.functions = vec![0x1104]);
        assert_eq!(starts(&asked), ["0x1100"]);
        assert_eq!(names(&asked.functions[0]), ["id", "kind"]);
        assert_eq!((asked.functions_total, asked.functions_matched), (2, 1));
        let lowered = found(|o| o.min = 2);
        assert!(starts(&lowered).contains(&"0x1100"));
    }

    #[test]
    fn a_name_in_a_fragment_is_given_to_its_caller() {
        let report = found(|_| {});
        let c = &report.functions[1];
        assert_eq!(names(c), ["token", "scope", "expires_in"]);
        let token = &c.fields[0];
        assert_eq!(token.via_fragment.as_deref(), Some("0x1200"));
        assert_eq!(token.sites, ["0x1204"]);
    }

    #[test]
    fn a_widely_shared_fragment_is_left_out() {
        let report = found(|_| {});
        assert!(!starts(&report).contains(&"0x1400"));
        let wider = found(|o| o.fragment_fanout = 9);
        assert_eq!(starts(&wider), ["0x1000", "0x1300", "0x1400"]);
        let d = &wider.functions[2];
        assert_eq!(names(d), ["value", "alpha", "beta"]);
        assert_eq!(d.fields[0].via_fragment.as_deref(), Some("0x1280"));
        let asked = found(|o| o.functions = vec![D]);
        assert_eq!(names(&asked.functions[0]), ["alpha", "beta"]);
    }

    #[test]
    fn the_name_filter_is_exact_and_case_sensitive() {
        let token = found(|o| o.names = vec!["token".to_string()]);
        assert_eq!(starts(&token), ["0x1300"]);
        assert_eq!((token.functions_total, token.functions_matched), (2, 1));
        let upper = found(|o| o.names = vec!["Token".to_string()]);
        assert!(upper.functions.is_empty());
        let partial = found(|o| o.names = vec!["user".to_string()]);
        assert!(partial.functions.is_empty());
        let both = found(|o| {
            o.names = vec!["id".to_string()];
            o.functions = vec![B, A];
        });
        assert_eq!(starts(&both), ["0x1100"]);
    }

    #[test]
    fn callers_of_the_function_start_are_listed() {
        let report = found(|_| {});
        let callers = &report.functions[0].callers;
        let rows: Vec<_> = callers
            .iter()
            .map(|c| {
                (
                    c.insn_addr.as_str(),
                    c.function.as_ref().map(|f| f.fn_start.as_str()),
                )
            })
            .collect();
        assert_eq!(rows, [("0x1350", Some("0x1300")), ("0x9000", None)]);
        assert!(report.functions[1].callers.is_empty());
    }

    #[test]
    fn the_cap_keeps_exact_totals() {
        let report = found(|o| o.max = 1);
        assert_eq!(starts(&report), ["0x1000"]);
        assert_eq!((report.functions_total, report.functions_matched), (2, 2));
        assert!(report.truncated);
        assert!(!found(|_| {}).truncated);
    }

    #[test]
    fn names_are_parsed_or_refused_with_the_item() {
        let items = ["token".to_string(), "Id".to_string(), "token".to_string()];
        assert_eq!(parse_fields_names(&items).unwrap(), ["token", "Id"]);
        let why = parse_fields_names(&["id".to_string(), String::new()]).unwrap_err();
        assert!(why.contains("élément \"\""), "{why}");
        assert!(is_field_name("_x"));
        assert!(!is_field_name("a-b"));
        assert!(!is_field_name(&"a".repeat(65)));
        assert!(is_type_name("BabaAccountPb"));
        assert!(!is_type_name("Baba_Account"));
        assert!(!is_type_name("babaAccount"));
    }

    #[test]
    fn legend_defines_every_fields_field_and_option() {
        let legend = super::super::legend();
        let labels = [
            "FIELDS (fields[])",
            "functions_total",
            "functions_matched",
            "truncated",
            "functions[]",
            "fn_start, fn_end, bound",
            "struct_names",
            "fields_count",
            "fields[]",
            "name",
            "vaddr",
            "boundary",
            "sites[]",
            "sites_count",
            "via_fragment",
            "callers[]",
            "nom de champ candidat",
            "désérialiseur candidat",
            "--native-fields-fn",
            "--native-fields-name",
            "--native-fields-min",
            "--native-fields-fragment-fanout",
            "--native-fields-max",
            BOUNDARY_FATPTR,
            BOUNDARY_CODE,
        ];
        for label in labels {
            assert!(legend.contains(label), "{label}");
        }
    }
}
