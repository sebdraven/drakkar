//! `--native --native-find` : dans tout le code d'un ELF AArch64, les
//! instructions qui accèdent à un champ de structure par son décalage depuis un
//! registre de base, ou qui forment l'adresse de ce champ. Rien n'est exécuté.
//! Étiquettes définies dans [`super::legend`].

use std::collections::{BTreeMap, HashSet};
use std::panic::AssertUnwindSafe;

use serde::Serialize;

use super::decode::{decode, Arch};
use super::disasm::context;
use super::native_strings::{code_addresses, code_bounds, FnBound};
use super::{hex, parse_elf, ElfReport};

pub const DEFAULT_FIND_MAX: usize = 2000;
pub const MAX_FIND_OFFSETS: usize = 16;

const ACCESS_LOAD: &str = "load";
const ACCESS_STORE: &str = "store";
const ACCESS_ADDR: &str = "addr";
/// Dans l'ordre des colonnes loads, stores, addrs.
const ACCESSES: [&str; 3] = [ACCESS_LOAD, ACCESS_STORE, ACCESS_ADDR];
const SIZES: [u64; 5] = [1, 2, 4, 8, 16];
const SP: u8 = 31;

/// Registre de base admis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FindBase {
    Any,
    Sp,
    #[default]
    NoSp,
}

impl FindBase {
    fn admits(self, base: u8) -> bool {
        match self {
            FindBase::Any => true,
            FindBase::Sp => base == SP,
            FindBase::NoSp => base != SP,
        }
    }
}

/// `--native-find <elf|*>` et ses filtres.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindOptions {
    /// Chemin de l'ELF ; `None` pour `*`.
    pub elf: Option<String>,
    pub offsets: Vec<i64>,
    pub access: Vec<&'static str>,
    /// Vide : toutes les largeurs.
    pub sizes: Vec<u64>,
    pub base: FindBase,
    pub functions: Vec<u64>,
    pub max: usize,
}

impl Default for FindOptions {
    fn default() -> Self {
        FindOptions {
            elf: None,
            offsets: Vec::new(),
            access: ACCESSES.to_vec(),
            sizes: Vec::new(),
            base: FindBase::default(),
            functions: Vec::new(),
            max: DEFAULT_FIND_MAX,
        }
    }
}

/// Hexadécimaux, préfixe `0x` facultatif, signe `-` admis, de 1 à 16 ;
/// doublons retirés.
pub fn parse_find_offsets(items: &[String]) -> Result<Vec<i64>, String> {
    let mut found = Vec::new();
    for item in items {
        let cite = |why: String| format!("élément {item:?} : {why}");
        let offset = parse_offset(item).map_err(cite)?;
        if !found.contains(&offset) {
            found.push(offset);
        }
    }
    if found.is_empty() || found.len() > MAX_FIND_OFFSETS {
        let count = found.len();
        return Err(format!("{count} décalages : de 1 à {MAX_FIND_OFFSETS}"));
    }
    Ok(found)
}

fn parse_offset(item: &str) -> Result<i64, String> {
    let (negative, digits) = match item.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, item),
    };
    let digits = digits.strip_prefix("0x").unwrap_or(digits);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("hexadécimal attendu, préfixe 0x facultatif, signe - admis".into());
    }
    let value = u64::from_str_radix(digits, 16).ok();
    let Some(value) = value.and_then(|v| i64::try_from(v).ok()) else {
        return Err("hors des entiers signés de 64 bits".into());
    };
    Ok(if negative { -value } else { value })
}

/// Sous-ensemble de load, store, addr ; doublons retirés.
pub fn parse_find_access(items: &[String]) -> Result<Vec<&'static str>, String> {
    let mut found = Vec::new();
    for item in items {
        let Some(&access) = ACCESSES.iter().find(|a| **a == item.as_str()) else {
            return Err(format!("élément {item:?} : load, store ou addr"));
        };
        if !found.contains(&access) {
            found.push(access);
        }
    }
    Ok(found)
}

/// Largeurs en octets parmi 1, 2, 4, 8, 16 ; doublons retirés.
pub fn parse_find_sizes(items: &[String]) -> Result<Vec<u64>, String> {
    let mut found = Vec::new();
    for item in items {
        let size = item.parse::<u64>().ok().filter(|s| SIZES.contains(s));
        let Some(size) = size else {
            return Err(format!("élément {item:?} : 1, 2, 4, 8 ou 16"));
        };
        if !found.contains(&size) {
            found.push(size);
        }
    }
    Ok(found)
}

pub fn parse_find_base(text: &str) -> Result<FindBase, String> {
    match text {
        "any" => Ok(FindBase::Any),
        "sp" => Ok(FindBase::Sp),
        "nosp" => Ok(FindBase::NoSp),
        _ => Err(format!("élément {text:?} : any, sp ou nosp")),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FindReport {
    pub elf: String,
    pub matches_total: usize,
    pub functions_total: usize,
    pub truncated: bool,
    pub functions: Vec<FindFunction>,
    pub matches: Vec<FindMatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindFunction {
    pub fn_start: String,
    pub fn_end: Option<String>,
    pub bound: &'static str,
    pub counts: Vec<FindCount>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindCount {
    pub offset: String,
    pub loads: usize,
    pub stores: usize,
    pub addrs: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindMatch {
    pub insn_addr: String,
    pub mnemonic: String,
    pub operands: String,
    pub access: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    pub base: String,
    pub offset: String,
    pub function: Option<FindBound>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindBound {
    pub fn_start: String,
    pub fn_end: Option<String>,
    pub bound: &'static str,
}

impl From<FnBound> for FindBound {
    fn from(bound: FnBound) -> Self {
        FindBound {
            fn_start: hex(bound.start),
            fn_end: bound.end.map(hex),
            bound: bound.source,
        }
    }
}

/// Accès `[base, #offset]` d'une instruction, ou adresse `base + offset`
/// formée. `size` : largeur d'un emplacement, 0 pour addr. `pair` : second
/// emplacement à `offset + size`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Form {
    access: &'static str,
    size: u64,
    base: u8,
    offset: i64,
    pair: bool,
}

/// Emplacement retenu de l'instruction `insn`.
#[derive(Clone, Debug)]
struct Hit {
    insn: u64,
    form: Form,
    offset: i64,
    mnemonic: String,
    operands: String,
}

/// Les accès de l'ELF `bytes` que décrit `elf` aux décalages de `options`.
pub(super) fn run(
    bytes: &[u8],
    elf: &ElfReport,
    options: &FindOptions,
) -> Result<FindReport, String> {
    let parsed = parse_elf(bytes).map_err(|e| format!("ELF illisible ({e})"))?;
    let dynamic = parsed.dynamic.as_deref();
    let (symbols, local_symbols) = (&parsed.symbols, &parsed.local_symbols);
    let ctx = context(parsed.image, dynamic, symbols, local_symbols);
    if ctx.arch != Some(Arch::Aarch64) {
        return Err(format!("machine {} : AArch64 seulement", elf.machine));
    }
    let job = || {
        let bounds = code_bounds(&ctx.image, symbols, local_symbols);
        let mut hits = Vec::new();
        let each = |pc, w| hits.extend(accesses(pc, w, options));
        code_addresses(&ctx.image, &ctx.slots, symbols, local_symbols, each);
        report(&elf.path, hits, |at| bounds.bound(at), options)
    };
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(job));
    outcome.map_err(|_| "panique pendant la recherche".to_string())
}

/// Emplacements du mot `w` en `pc` qui passent les filtres de décalage,
/// d'accès, de largeur et de base ; texte du décodeur.
fn accesses(pc: u64, w: u32, options: &FindOptions) -> Vec<Hit> {
    let Some(form) = form(w) else {
        return Vec::new();
    };
    let sized = form.access == ACCESS_ADDR
        || options.sizes.is_empty()
        || options.sizes.contains(&form.size);
    if !sized || !options.access.contains(&form.access) || !options.base.admits(form.base) {
        return Vec::new();
    }
    let slots: &[i64] = if form.pair { &[0, 1] } else { &[0] };
    let width = form.size as i64;
    let offsets = slots.iter().map(|slot| form.offset + slot * width);
    let wanted: Vec<i64> = offsets.filter(|o| options.offsets.contains(o)).collect();
    if wanted.is_empty() {
        return Vec::new();
    }
    let Ok(insn) = decode(Arch::Aarch64, &w.to_le_bytes(), pc, false) else {
        return Vec::new();
    };
    let hit = |offset| Hit {
        insn: pc,
        form,
        offset,
        mnemonic: insn.mnemonic.clone(),
        operands: insn.operands.clone(),
    };
    wanted.into_iter().map(hit).collect()
}

fn form(w: u32) -> Option<Form> {
    single(w).or_else(|| pair(w)).or_else(|| address(w))
}

/// Un registre, entier ou SIMD : décalage non signé mis à l'échelle (ldr,
/// str…), immédiat signé de 9 bits (ldur, stur, ldtr, sttr, pré-indexé) ;
/// post-indexé, l'accès est à décalage nul. `[base, xN]` refusé.
fn single(w: u32) -> Option<Form> {
    if (w >> 27) & 0b111 != 0b111 {
        return None;
    }
    let size = (w >> 30) & 0b11;
    let simd = (w >> 26) & 1 == 1;
    let opc = (w >> 22) & 0b11;
    let width = 1u64 << size;
    let (load, width) = match (simd, opc, size) {
        (false, 0, _) => (false, width),
        (false, 1, _) | (false, 2, 0..=2) | (false, 3, 0..=1) => (true, width),
        (true, 0, _) => (false, width),
        (true, 1, _) => (true, width),
        (true, 2, 0) => (false, 16),
        (true, 3, 0) => (true, 16),
        _ => return None,
    };
    let offset = match (w >> 24) & 0b11 {
        0b01 => i64::from((w >> 10) & 0xfff) * width as i64,
        0b00 if (w >> 21) & 1 == 0 => match (w >> 10) & 0b11 {
            0b01 => 0,
            0b10 if simd => return None,
            _ => imm9(w),
        },
        _ => return None,
    };
    Some(Form {
        access: kind(load),
        size: width,
        base: base(w),
        offset,
        pair: false,
    })
}

/// ldp, stp, ldnp, stnp, ldpsw, entiers ou SIMD : immédiat signé de 7 bits mis
/// à l'échelle ; post-indexé, l'accès est à décalage nul.
fn pair(w: u32) -> Option<Form> {
    if (w >> 27) & 0b111 != 0b101 || (w >> 25) & 1 != 0 {
        return None;
    }
    let simd = (w >> 26) & 1 == 1;
    let load = (w >> 22) & 1 == 1;
    let index = (w >> 23) & 0b11;
    let width: u64 = match (simd, w >> 30) {
        (_, 0) => 4,
        (false, 1) if load && index != 0 => 4,
        (false, 2) | (true, 1) => 8,
        (true, 2) => 16,
        _ => return None,
    };
    let offset = if index == 0b01 {
        0
    } else {
        imm7(w) * width as i64
    };
    Some(Form {
        access: kind(load),
        size: width,
        base: base(w),
        offset,
        pair: true,
    })
}

/// add, sub à immédiat, 64 bits, sans drapeaux : base + décalage, négatif pour
/// sub.
fn address(w: u32) -> Option<Form> {
    if w & 0xbf80_0000 != 0x9100_0000 {
        return None;
    }
    let imm = i64::from((w >> 10) & 0xfff) << (12 * ((w >> 22) & 1));
    let offset = if (w >> 30) & 1 == 1 { -imm } else { imm };
    Some(Form {
        access: ACCESS_ADDR,
        size: 0,
        base: base(w),
        offset,
        pair: false,
    })
}

fn kind(load: bool) -> &'static str {
    if load {
        ACCESS_LOAD
    } else {
        ACCESS_STORE
    }
}

fn base(w: u32) -> u8 {
    ((w >> 5) & 0x1f) as u8
}

fn imm9(w: u32) -> i64 {
    i64::from(((w >> 12) as i32) << 23 >> 23)
}

fn imm7(w: u32) -> i64 {
    i64::from(((w >> 15) as i32) << 25 >> 25)
}

fn register(base: u8) -> String {
    if base == SP {
        "sp".to_string()
    } else {
        format!("x{base}")
    }
}

fn signed_hex(value: i64) -> String {
    if value < 0 {
        format!("-{}", hex(value.unsigned_abs()))
    } else {
        hex(value as u64)
    }
}

/// `span` : fonction bornée qui contient une adresse. Totaux et `functions`
/// sur tous les emplacements retenus, `matches` coupée à `max`.
fn report(
    elf: &str,
    mut hits: Vec<Hit>,
    span: impl Fn(u64) -> Option<FnBound>,
    options: &FindOptions,
) -> FindReport {
    let starts = options.functions.iter().filter_map(|&at| span(at));
    let wanted: HashSet<u64> = starts.map(|b| b.start).collect();
    hits.sort_by_key(|h| (h.insn, h.offset));
    let mut kept = Vec::new();
    for hit in hits {
        let bound = span(hit.insn);
        let inside = bound.is_some_and(|b| wanted.contains(&b.start));
        if options.functions.is_empty() || inside {
            kept.push((hit, bound));
        }
    }
    let mut counted: BTreeMap<u64, (FnBound, Vec<[usize; 3]>)> = BTreeMap::new();
    for (hit, bound) in &kept {
        let Some(bound) = bound else {
            continue;
        };
        let Some(row) = options.offsets.iter().position(|&o| o == hit.offset) else {
            continue;
        };
        let column = ACCESSES.iter().position(|&a| a == hit.form.access);
        let blank = || (*bound, vec![[0; 3]; options.offsets.len()]);
        let entry = counted.entry(bound.start).or_insert_with(blank);
        entry.1[row][column.unwrap_or(0)] += 1;
    }
    let mut functions = Vec::new();
    for (bound, rows) in counted.into_values() {
        let mut counts = Vec::new();
        for (&offset, [loads, stores, addrs]) in options.offsets.iter().zip(rows) {
            if loads + stores + addrs > 0 {
                counts.push(FindCount {
                    offset: signed_hex(offset),
                    loads,
                    stores,
                    addrs,
                });
            }
        }
        let place = FindBound::from(bound);
        functions.push(FindFunction {
            fn_start: place.fn_start,
            fn_end: place.fn_end,
            bound: place.bound,
            counts,
        });
    }
    let matches_total = kept.len();
    let mut matches = Vec::new();
    for (hit, bound) in kept.into_iter().take(options.max) {
        let addr = hit.form.access == ACCESS_ADDR;
        matches.push(FindMatch {
            insn_addr: hex(hit.insn),
            mnemonic: hit.mnemonic,
            operands: hit.operands,
            access: hit.form.access,
            size: (!addr).then_some(hit.form.size),
            base: register(hit.form.base),
            offset: signed_hex(hit.offset),
            function: bound.map(FindBound::from),
        });
    }
    FindReport {
        elf: elf.to_string(),
        matches_total,
        functions_total: functions.len(),
        truncated: matches.len() < matches_total,
        functions,
        matches,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGISTER_OFFSET: u32 = 0x38626820;

    /// Fonction A en [0x1000, 0x1040), B en [0x1040, 0x1080) ; 0x2000 hors de
    /// toute fonction bornée.
    const PROGRAM: [(u64, u32, &str); 10] = [
        (0x1000, 0x3945a801, "ldrb  w1, [x0, #0x16a]"),
        (0x1004, 0x39070c62, "strb  w2, [x3, #0x1c3]"),
        (0x1008, 0x9105a98b, "add   x11, x12, #0x16a"),
        (0x100c, REGISTER_OFFSET, "ldrb  w0, [x1, x2]"),
        (0x1010, 0xf9400be0, "ldr   x0, [sp, #0x10]"),
        (0x1040, 0xb85f80a4, "ldur  w4, [x5, #-0x8]"),
        (0x1044, 0xa9411d06, "ldp   x6, x7, [x8, #0x10]"),
        (0x1048, 0xf8420d49, "ldr   x9, [x10, #0x20]!"),
        (0x104c, 0xd1002020, "sub   x0, x1, #0x8"),
        (0x2000, 0x3945a801, "ldrb  w1, [x0, #0x16a]"),
    ];

    const BOUNDS: [FnBound; 2] = [
        FnBound {
            start: 0x1000,
            end: Some(0x1040),
            source: "symtab",
        },
        FnBound {
            start: 0x1040,
            end: Some(0x1080),
            source: "eh_frame",
        },
    ];

    fn span(at: u64) -> Option<FnBound> {
        let inside = |b: &FnBound| b.start <= at && b.end.is_some_and(|end| at < end);
        BOUNDS.iter().copied().find(inside)
    }

    fn searched(offsets: &[i64], tune: impl FnOnce(&mut FindOptions)) -> FindReport {
        let mut options = FindOptions {
            offsets: offsets.to_vec(),
            ..FindOptions::default()
        };
        tune(&mut options);
        let mut hits = Vec::new();
        for &(pc, w, _) in &PROGRAM {
            hits.extend(accesses(pc, w, &options));
        }
        report("lib/arm64-v8a/libt.so", hits, span, &options)
    }

    fn row(m: &FindMatch) -> (&str, &str, Option<u64>, &str, &str) {
        let (insn, base, offset) = (m.insn_addr.as_str(), m.base.as_str(), m.offset.as_str());
        (insn, m.access, m.size, base, offset)
    }

    fn rows(r: &FindReport) -> Vec<(&str, &str, Option<u64>, &str, &str)> {
        r.matches.iter().map(row).collect()
    }

    fn mnemonics(r: &FindReport) -> Vec<&str> {
        r.matches.iter().map(|m| m.mnemonic.as_str()).collect()
    }

    fn insns(r: &FindReport) -> Vec<&str> {
        r.matches.iter().map(|m| m.insn_addr.as_str()).collect()
    }

    fn offsets(r: &FindReport) -> Vec<&str> {
        r.matches.iter().map(|m| m.offset.as_str()).collect()
    }

    fn texts(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn ldrb_and_strb_with_an_immediate_offset_are_a_load_and_a_store() {
        let found = searched(&[0x16a, 0x1c3], |_| {});
        let expected = vec![
            ("0x1000", ACCESS_LOAD, Some(1), "x0", "0x16a"),
            ("0x1004", ACCESS_STORE, Some(1), "x3", "0x1c3"),
            ("0x1008", ACCESS_ADDR, None, "x12", "0x16a"),
            ("0x2000", ACCESS_LOAD, Some(1), "x0", "0x16a"),
        ];
        assert_eq!(rows(&found), expected);
        assert_eq!(mnemonics(&found), ["ldrb", "strb", "add", "ldrb"]);
        let function = found.matches[0].function.as_ref();
        assert_eq!(function.map(|f| f.fn_start.as_str()), Some("0x1000"));
        assert!(found.matches[3].function.is_none());
    }

    #[test]
    fn ldur_takes_a_negative_offset_and_sub_forms_one() {
        let found = searched(&[-8], |_| {});
        let expected = vec![
            ("0x1040", ACCESS_LOAD, Some(4), "x5", "-0x8"),
            ("0x104c", ACCESS_ADDR, None, "x1", "-0x8"),
        ];
        assert_eq!(rows(&found), expected);
        assert_eq!(mnemonics(&found), ["ldur", "sub"]);
    }

    #[test]
    fn the_second_slot_of_ldp_matches_at_offset_plus_width() {
        let second = searched(&[0x18], |_| {});
        let expected = vec![("0x1044", ACCESS_LOAD, Some(8), "x8", "0x18")];
        assert_eq!(rows(&second), expected);
        assert_eq!(mnemonics(&second), ["ldp"]);
        let both = searched(&[0x10, 0x18], |_| {});
        assert_eq!(insns(&both), ["0x1044", "0x1044"]);
        assert_eq!(offsets(&both), ["0x10", "0x18"]);
    }

    #[test]
    fn a_pre_indexed_load_matches_its_offset() {
        let found = searched(&[0x20], |_| {});
        let expected = vec![("0x1048", ACCESS_LOAD, Some(8), "x10", "0x20")];
        assert_eq!(rows(&found), expected);
        assert_eq!(form(0xf8420d49).map(|f| f.offset), Some(0x20));
    }

    #[test]
    fn add_forms_an_address_and_the_access_filter_keeps_it_alone() {
        let found = searched(&[0x16a, 0x1c3], |o| o.access = vec![ACCESS_ADDR]);
        let expected = vec![("0x1008", ACCESS_ADDR, None, "x12", "0x16a")];
        assert_eq!(rows(&found), expected);
        let json = serde_json::to_value(&found.matches[0]).unwrap();
        assert!(json.get("size").is_none());
        assert_eq!(json["function"]["fn_start"], "0x1000");
        assert_eq!(json["function"]["bound"], "symtab");

        let stores = searched(&[0x16a, 0x1c3], |o| o.access = vec![ACCESS_STORE]);
        let expected = vec![("0x1004", ACCESS_STORE, Some(1), "x3", "0x1c3")];
        assert_eq!(rows(&stores), expected);
    }

    #[test]
    fn the_size_filter_keeps_addresses() {
        let found = searched(&[0x16a, 0x1c3, -8], |o| o.sizes = vec![4]);
        let expected = vec![
            ("0x1008", ACCESS_ADDR, None, "x12", "0x16a"),
            ("0x1040", ACCESS_LOAD, Some(4), "x5", "-0x8"),
            ("0x104c", ACCESS_ADDR, None, "x1", "-0x8"),
        ];
        assert_eq!(rows(&found), expected);
    }

    #[test]
    fn sp_bases_are_left_out_by_default_and_kept_with_any() {
        assert_eq!(insns(&searched(&[0x10], |_| {})), ["0x1044"]);
        let any = searched(&[0x10], |o| o.base = FindBase::Any);
        assert_eq!(insns(&any), ["0x1010", "0x1044"]);
        assert_eq!(any.matches[0].base, "sp");
        let sp = searched(&[0x10], |o| o.base = FindBase::Sp);
        assert_eq!(insns(&sp), ["0x1010"]);
    }

    #[test]
    fn the_in_filter_keeps_the_functions_that_contain_an_address() {
        let found = searched(&[0x16a, -8], |o| o.functions = vec![0x1048]);
        assert_eq!(insns(&found), ["0x1040", "0x104c"]);
        assert_eq!((found.matches_total, found.functions_total), (2, 1));
        assert_eq!(found.functions[0].fn_start, "0x1040");
    }

    #[test]
    fn an_offset_held_in_a_register_is_not_recognised() {
        assert_eq!(form(REGISTER_OFFSET), None);
        let found = searched(&[0], |o| o.base = FindBase::Any);
        assert!(!insns(&found).contains(&"0x100c"));
    }

    #[test]
    fn functions_count_each_requested_offset_they_hold() {
        let found = searched(&[0x16a, 0x1c3, 0x20], |_| {});
        assert_eq!((found.matches_total, found.functions_total), (5, 2));
        let counts = |f: &FindFunction| -> Vec<(String, usize, usize, usize)> {
            let row = |c: &FindCount| (c.offset.clone(), c.loads, c.stores, c.addrs);
            f.counts.iter().map(row).collect()
        };
        let a = &found.functions[0];
        assert_eq!((a.fn_start.as_str(), a.bound), ("0x1000", "symtab"));
        let expected = vec![
            ("0x16a".to_string(), 1, 0, 1),
            ("0x1c3".to_string(), 0, 1, 0),
        ];
        assert_eq!(counts(a), expected);
        let b = &found.functions[1];
        assert_eq!(b.fn_start, "0x1040");
        assert_eq!(counts(b), vec![("0x20".to_string(), 1, 0, 0)]);
    }

    #[test]
    fn the_cap_keeps_exact_totals_and_every_function() {
        let found = searched(&[0x16a, 0x1c3, 0x20], |o| o.max = 2);
        assert_eq!(insns(&found), ["0x1000", "0x1004"]);
        assert!(found.truncated);
        assert_eq!((found.matches_total, found.functions_total), (5, 2));
        assert_eq!(found.functions.len(), 2);
        assert!(!searched(&[0x16a, 0x1c3, 0x20], |_| {}).truncated);
    }

    #[test]
    fn offsets_and_lists_are_parsed_or_refused_with_the_item() {
        let items = texts(&["16a", "0x1C3", "-0x8", "-8", "0x16a"]);
        assert_eq!(parse_find_offsets(&items), Ok(vec![0x16a, 0x1c3, -8]));
        for bad in ["zz", "-", "0x", "--8", "0x-8", "+8", "1_0"] {
            let why = parse_find_offsets(&texts(&["0x16a", bad])).unwrap_err();
            assert!(why.contains(&format!("{bad:?}")), "{why}");
        }
        let huge = texts(&["8000000000000000"]);
        let why = parse_find_offsets(&huge).unwrap_err();
        assert!(why.contains("\"8000000000000000\""), "{why}");
        assert!(parse_find_offsets(&[]).is_err());
        let many: Vec<String> = (1..=17).map(|i| format!("{i:x}")).collect();
        let why = parse_find_offsets(&many).unwrap_err();
        assert!(why.contains("17 décalages"), "{why}");

        let access = texts(&["store", "load", "store"]);
        let expected = Ok(vec![ACCESS_STORE, ACCESS_LOAD]);
        assert_eq!(parse_find_access(&access), expected);
        let why = parse_find_access(&texts(&["load", "read"])).unwrap_err();
        assert!(why.contains("\"read\""), "{why}");

        assert_eq!(parse_find_sizes(&texts(&["16", "1", "1"])), Ok(vec![16, 1]));
        let why = parse_find_sizes(&texts(&["4", "3"])).unwrap_err();
        assert!(why.contains("\"3\""), "{why}");

        assert_eq!(parse_find_base("any"), Ok(FindBase::Any));
        assert_eq!(parse_find_base("sp"), Ok(FindBase::Sp));
        assert_eq!(parse_find_base("nosp"), Ok(FindBase::NoSp));
        assert!(parse_find_base("stack").unwrap_err().contains("\"stack\""));
    }

    #[test]
    fn legend_defines_every_find_label() {
        let legend = super::super::legend();
        let labels = [
            "FIND (find[])",
            "matches_total",
            "functions_total",
            "truncated",
            "functions[]",
            "counts[]",
            "loads, stores, addrs",
            "matches[]",
            "insn_addr",
            "mnemonic, operands",
            "post-indexé",
            "emplacement",
            "function",
            "--native-find-off",
            "--native-find-access",
            "--native-find-size",
            "--native-find-base",
            "--native-find-in",
            "--native-find-max",
            ACCESS_LOAD,
            ACCESS_STORE,
            ACCESS_ADDR,
        ];
        for label in labels {
            assert!(legend.contains(label), "{label}");
        }
    }
}
