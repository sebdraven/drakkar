//! `--native --native-vtables` : tables de méthodes Rust d'un ELF AArch64,
//! reconnues à leur forme, filtrées, et sur demande les instructions et les
//! mots qui portent leur adresse. Rien n'est exécuté. Étiquettes définies dans
//! [`super::legend`].

use std::collections::HashSet;
use std::panic::AssertUnwindSafe;

use object::elf;
use serde::Serialize;

use super::decode::Arch;
use super::disasm::{context, Ctx};
use super::native_strings::fde_ranges;
use super::words::{read_word, Word};
use super::xrefs::{
    is_link_metadata, relocation_tables, search, AddrRef, DataRef, XrefFunction, XrefList,
    DEFAULT_XREFS_MAX,
};
use super::{hex, parse_elf, parse_symex_address, DynSymbol, ElfReport, Image, Segment};

pub const DEFAULT_VTABLES_MAX: usize = 500;
pub const MAX_VTABLES_ADDRESSES: usize = 64;
const MAX_SIZE: u64 = 0x100_0000;
const MAX_ALIGN: u64 = 4096;
const FIRST_METHOD: u64 = 0x18;

/// `--native-vtables <elf|*>` et ses filtres.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtablesOptions {
    /// Chemin de l'ELF ; `None` pour `*`.
    pub elf: Option<String>,
    pub functions: Vec<u64>,
    pub slot: Option<u64>,
    pub size: Option<u64>,
    pub at: Vec<u64>,
    pub max: usize,
    pub refs: bool,
}

impl Default for VtablesOptions {
    fn default() -> Self {
        VtablesOptions {
            elf: None,
            functions: Vec::new(),
            slot: None,
            size: None,
            at: Vec::new(),
            max: DEFAULT_VTABLES_MAX,
            refs: false,
        }
    }
}

/// `<elf|*>`.
pub fn parse_vtables_elf(spec: &str) -> Result<Option<String>, String> {
    match spec {
        "" => Err("chemin d'ELF vide (passer * pour tous les ELF)".into()),
        "*" => Ok(None),
        path => Ok(Some(path.to_string())),
    }
}

/// Adresses hexadécimales, préfixe `0x` facultatif, de 1 à 64 ; doublons
/// retirés.
pub fn parse_vtables_addresses(items: &[String]) -> Result<Vec<u64>, String> {
    let mut found = Vec::new();
    for item in items {
        let cite = |why: String| format!("élément {item:?} : {why}");
        let at = parse_symex_address(item).map_err(cite)?;
        if !found.contains(&at) {
            found.push(at);
        }
    }
    if found.len() > MAX_VTABLES_ADDRESSES {
        let count = found.len();
        return Err(format!("{count} adresses : de 1 à {MAX_VTABLES_ADDRESSES}"));
    }
    Ok(found)
}

/// Hexadécimal avec `0x`, sinon décimal.
pub fn parse_vtables_number(text: &str) -> Result<u64, String> {
    let trimmed = text.trim();
    let parsed = match trimmed.strip_prefix("0x") {
        Some(digits) => u64::from_str_radix(digits, 16).ok(),
        None => trimmed.parse::<u64>().ok(),
    };
    parsed.ok_or_else(|| format!("élément {text:?} : 0x hexadécimal ou décimal"))
}

/// Décalage depuis le début d'une table : multiple de 8, au moins 0x18.
pub fn parse_vtables_slot(text: &str) -> Result<u64, String> {
    let slot = parse_vtables_number(text)?;
    if slot % 8 != 0 || slot < FIRST_METHOD {
        return Err(format!("élément {text:?} : multiple de 8, au moins 0x18"));
    }
    Ok(slot)
}

#[derive(Debug, Clone, Serialize)]
pub struct VtablesReport {
    pub elf: String,
    pub tables_total: usize,
    pub tables_matched: usize,
    pub truncated: bool,
    pub tables: Vec<Vtable>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Vtable {
    pub vaddr: String,
    pub section: Option<String>,
    pub drop: Option<String>,
    pub size: String,
    pub align: String,
    pub methods_count: usize,
    pub methods: Vec<VtableMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr_refs: Option<XrefList<AddrRef>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_refs: Option<XrefList<DataRef>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VtableMethod {
    pub offset: String,
    pub value: String,
    pub function: XrefFunction,
}

/// Table détectée, avant filtres.
struct Found {
    vaddr: u64,
    section: Option<String>,
    dtor: Option<u64>,
    size: u64,
    align: u64,
    /// Valeurs des méthodes, à partir de +0x18.
    methods: Vec<u64>,
}

/// Ce que [`header`] lit d'un mot classé par [`read_word`].
#[derive(Clone, Copy)]
struct Cell {
    value: Option<u64>,
    relocated: bool,
    entry: bool,
}

impl Cell {
    fn of(word: &Word) -> Self {
        Cell {
            value: word.number(),
            relocated: word.relocated,
            entry: word.is_function_start(),
        }
    }

    fn is_method(&self) -> bool {
        self.relocated && self.entry
    }

    fn fixed(&self) -> Option<u64> {
        self.value.filter(|_| !self.relocated)
    }
}

/// Les tables de l'ELF `bytes` que décrit `elf`, filtrées par `options`.
pub(super) fn run(
    bytes: &[u8],
    elf: &ElfReport,
    options: &VtablesOptions,
) -> Result<VtablesReport, String> {
    let parsed = parse_elf(bytes).map_err(|e| format!("ELF illisible ({e})"))?;
    let pie = parsed.e_type == elf::ET_DYN;
    let dynamic = parsed.dynamic.as_deref();
    let (symbols, local_symbols) = (&parsed.symbols, &parsed.local_symbols);
    let ctx = context(parsed.image, dynamic, symbols, local_symbols);
    if ctx.arch != Some(Arch::Aarch64) {
        return Err(format!("machine {} : AArch64 seulement", elf.machine));
    }
    let fdes = fde_ranges(&ctx.image);
    let tables = relocation_tables(&ctx.image, dynamic);
    let job = || {
        let found = detect(&ctx, &fdes, pie);
        let symbols = (symbols.as_slice(), local_symbols.as_slice());
        report(&ctx, &fdes, &tables, symbols, &elf.path, found, options)
    };
    std::panic::catch_unwind(AssertUnwindSafe(job))
        .map_err(|_| "panique pendant la recherche".to_string())
}

/// Tables de toutes les zones de [`scanned`], triées par adresse.
fn detect(ctx: &Ctx, fdes: &[(u64, u64)], pie: bool) -> Vec<Found> {
    let mut found = Vec::new();
    for (section, first, count) in scanned(&ctx.image) {
        let cell = |index| Cell::of(&read_word(ctx, fdes, pie, first, index));
        let cells: Vec<Cell> = (0..count).map(cell).collect();
        let header_at = |i: usize| Some((i, header(&cells[i..])?));
        let headers: Vec<_> = (0..count).filter_map(header_at).collect();
        let starts: HashSet<usize> = headers.iter().map(|&(i, _)| i).collect();
        for (i, (dtor, size, align)) in headers {
            let method = |j: &usize| !starts.contains(j) && cells[*j].is_method();
            let slots = (i + 3..count).take_while(method);
            let methods: Vec<u64> = slots.filter_map(|j| cells[j].value).collect();
            if methods.is_empty() {
                continue;
            }
            found.push(Found {
                vaddr: first + 8 * i as u64,
                section: section.clone(),
                dtor,
                size,
                align,
                methods,
            });
        }
    }
    found.sort_by_key(|f| f.vaddr);
    found
}

/// (destructeur, taille, alignement) si `cells` commence par un en-tête de
/// table suivi d'une méthode.
fn header(cells: &[Cell]) -> Option<(Option<u64>, u64, u64)> {
    let [dtor, size, align, first, ..] = cells else {
        return None;
    };
    let valid_drop = dtor.is_method() || dtor.fixed() == Some(0);
    if !valid_drop || !first.is_method() {
        return None;
    }
    let size = size.fixed().filter(|&n| n <= MAX_SIZE)?;
    let aligned = |n: &u64| n.is_power_of_two() && *n <= MAX_ALIGN;
    let align = align.fixed().filter(aligned)?;
    Some((dtor.value.filter(|_| dtor.is_method()), size, align))
}

/// (section, premier mot aligné sur 8, nombre de mots) : sections allouées non
/// exécutables présentes dans le fichier, en lecture seule ou dans
/// PT_GNU_RELRO, hors [`is_link_metadata`] ; sans section headers, segments
/// LOAD ni inscriptibles ni exécutables, et PT_GNU_RELRO.
fn scanned(image: &Image) -> Vec<(Option<String>, u64, usize)> {
    let is_relro = |s: &&Segment| s.p_type == elf::PT_GNU_RELRO;
    let relro: Vec<&Segment> = image.segments.iter().filter(is_relro).collect();
    let mut zones = Vec::new();
    for s in &image.sections {
        let data = s.has(elf::SHF_ALLOC) && !s.has(elf::SHF_EXECINSTR) && s.has_file_data();
        let end = s.addr.saturating_add(s.size);
        let in_relro = relro.iter().any(|r| covers(r, s.addr, end));
        if data && !is_link_metadata(s) && (!s.has(elf::SHF_WRITE) || in_relro) {
            zones.push((Some(s.name.clone()), s.addr, end));
        }
    }
    if image.sections.is_empty() {
        for s in &image.segments {
            let read_only = !s.has(elf::PF_X) && !s.has(elf::PF_W);
            if (s.p_type == elf::PT_LOAD && read_only) || s.p_type == elf::PT_GNU_RELRO {
                zones.push((None, s.vaddr, s.vaddr.saturating_add(s.memsz)));
            }
        }
    }
    let words = |(name, start, end): (Option<String>, u64, u64)| {
        let first = start.checked_next_multiple_of(8)?;
        let count = end.checked_sub(first)? / 8;
        Some((name, first, usize::try_from(count).ok()?))
    };
    zones.into_iter().filter_map(words).collect()
}

fn covers(segment: &Segment, start: u64, end: u64) -> bool {
    segment.vaddr <= start && end <= segment.vaddr.saturating_add(segment.memsz)
}

/// Filtres, plafond, puis références des tables rendues en une passe.
fn report(
    ctx: &Ctx,
    fdes: &[(u64, u64)],
    tables: &[(u64, u64)],
    symbols: (&[DynSymbol], &[DynSymbol]),
    elf: &str,
    found: Vec<Found>,
    options: &VtablesOptions,
) -> VtablesReport {
    let tables_total = found.len();
    let filtered = |f: Found| Some((matched(&f, options)?, f));
    let mut kept: Vec<(Vec<u64>, Found)> = found.into_iter().filter_map(filtered).collect();
    let tables_matched = kept.len();
    kept.truncate(options.max);
    let mut refs = Vec::new();
    if options.refs && !kept.is_empty() {
        let targets: Vec<u64> = kept.iter().map(|(_, f)| f.vaddr).collect();
        let (symbols, local_symbols) = symbols;
        refs = search(
            ctx,
            fdes,
            tables,
            symbols,
            local_symbols,
            elf,
            &targets,
            DEFAULT_XREFS_MAX,
        );
    }
    let mut refs = refs.into_iter();
    let mut rendered = Vec::new();
    for (offsets, f) in kept {
        let method = |(i, &value): (usize, &u64)| VtableMethod {
            offset: hex(FIRST_METHOD + 8 * i as u64),
            value: hex(value),
            function: XrefFunction::of(ctx, fdes, value),
        };
        let (addr_refs, data_refs) = match refs.next() {
            Some(xrefs) => (Some(xrefs.addr_refs), Some(xrefs.data_refs)),
            None => (None, None),
        };
        let by_function = !options.functions.is_empty();
        rendered.push(Vtable {
            vaddr: hex(f.vaddr),
            section: f.section,
            drop: f.dtor.map(hex),
            size: hex(f.size),
            align: hex(f.align),
            methods_count: f.methods.len(),
            methods: f.methods.iter().enumerate().map(method).collect(),
            matched: by_function.then(|| offsets.into_iter().map(hex).collect()),
            addr_refs,
            data_refs,
        });
    }
    VtablesReport {
        elf: elf.to_string(),
        tables_total,
        tables_matched,
        truncated: rendered.len() < tables_matched,
        tables: rendered,
    }
}

/// Décalages où figure une adresse de `--native-vtables-fn` (0x0 pour le
/// destructeur) ; `None` si un filtre écarte la table.
fn matched(f: &Found, options: &VtablesOptions) -> Option<Vec<u64>> {
    if options.size.is_some_and(|n| n != f.size) {
        return None;
    }
    if !options.at.is_empty() && !options.at.contains(&f.vaddr) {
        return None;
    }
    if options
        .slot
        .is_some_and(|slot| method_at(f, slot).is_none())
    {
        return None;
    }
    let wanted = |v: &u64| options.functions.contains(v);
    let mut offsets: Vec<u64> = f.dtor.filter(wanted).map(|_| 0).into_iter().collect();
    for (i, value) in f.methods.iter().enumerate() {
        if wanted(value) {
            offsets.push(FIRST_METHOD + 8 * i as u64);
        }
    }
    if !options.functions.is_empty() && offsets.is_empty() {
        return None;
    }
    Some(offsets)
}

fn method_at(f: &Found, offset: u64) -> Option<u64> {
    let index = usize::try_from(offset.checked_sub(FIRST_METHOD)? / 8).ok()?;
    f.methods.get(index).copied()
}

#[cfg(test)]
mod tests {
    use super::super::Section;
    use super::*;

    const F1: u64 = 0x1000;
    const F2: u64 = 0x1040;
    const F3: u64 = 0x1080;
    const F4: u64 = 0x10c0;
    const F5: u64 = 0x1100;
    const RELRO: u64 = 0x2000;
    const DATA: u64 = 0x2100;
    const A: u64 = 0x2000;
    const B: u64 = 0x2030;
    const C: u64 = 0x2058;
    const D: u64 = 0x2080;
    const FDES: [(u64, u64); 5] = [(F1, F2), (F2, F3), (F3, F4), (F4, F5), (F5, F5 + 0x40)];

    /// adrp x1, 0x2000 ; add x1, x1, #0x30 (B) ; ret, en F1.
    const PROGRAM: [u32; 3] = [0xb0000001, 0x9100c021, 0xd65f03c0];

    fn segment(p_type: u32, flags: u32, vaddr: u64, size: u64) -> Segment {
        Segment {
            p_type,
            flags,
            vaddr,
            memsz: size,
            offset: vaddr,
            filesz: size,
        }
    }

    fn section(name: &str, flags: u32, addr: u64, size: u64) -> Section {
        Section {
            name: name.to_string(),
            sh_type: elf::SHT_PROGBITS,
            flags: u64::from(flags),
            addr,
            offset: addr,
            size,
        }
    }

    /// .text [F1, F1 + 0x200) ; .data.rel.ro en RELRO, couverte par
    /// PT_GNU_RELRO ; .data en DATA, inscriptible hors RELRO.
    fn image(data: &[u8]) -> Image<'_> {
        let exec = elf::SHF_ALLOC | elf::SHF_EXECINSTR;
        let write = elf::SHF_ALLOC | elf::SHF_WRITE;
        Image {
            data,
            ptr_size: 8,
            big_endian: false,
            machine: elf::EM_AARCH64,
            segments: vec![
                segment(elf::PT_LOAD, elf::PF_R | elf::PF_X, 0, RELRO),
                segment(elf::PT_LOAD, elf::PF_R | elf::PF_W, RELRO, 0x1000),
                segment(elf::PT_GNU_RELRO, elf::PF_R, RELRO, 0x100),
            ],
            sections: vec![
                section(".text", exec, F1, 0x200),
                section(".data.rel.ro", write, RELRO, 0x100),
                section(".data", write, DATA, 0x40),
            ],
        }
    }

    fn put(data: &mut [u8], at: u64, value: u64) {
        let at = at as usize;
        data[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// A : F1 ; 0x20 ; 0x8 ; F2, F3, F4 ; puis 0.
    /// B : 0 ; 0x10 ; 0x8 ; F5, F2 ; collée à C.
    /// C : F3 ; 0x30 ; 0x10 ; F4 ; puis 0.
    /// D : 0 ; 0x8 ; 0x8 ; F1 ; puis F1 + 8, milieu de fonction.
    /// En .data, hors RELRO, un en-tête F1 ; 0x8 ; 0x8 ; F2, et un pointeur
    /// relogé vers B.
    fn listed(options: &VtablesOptions) -> VtablesReport {
        let mut data = vec![0u8; 0x3000];
        for (i, word) in PROGRAM.iter().enumerate() {
            let at = (F1 + 4 * i as u64) as usize;
            data[at..at + 4].copy_from_slice(&word.to_le_bytes());
        }
        let fixed = [
            (A + 0x08, 0x20),
            (A + 0x10, 0x8),
            (B + 0x08, 0x10),
            (B + 0x10, 0x8),
            (C + 0x08, 0x30),
            (C + 0x10, 0x10),
            (D + 0x08, 0x8),
            (D + 0x10, 0x8),
            (DATA + 0x08, 0x8),
            (DATA + 0x10, 0x8),
        ];
        for (at, value) in fixed {
            put(&mut data, at, value);
        }
        let mut ctx = context(image(&data), None, &[], &[]);
        let relocated = [
            (A, F1),
            (A + 0x18, F2),
            (A + 0x20, F3),
            (A + 0x28, F4),
            (B + 0x18, F5),
            (B + 0x20, F2),
            (C, F3),
            (C + 0x18, F4),
            (D + 0x18, F1),
            (D + 0x20, F1 + 8),
            (DATA, F1),
            (DATA + 0x18, F2),
            (DATA + 0x28, B),
        ];
        for (at, value) in relocated {
            ctx.slots.insert(at, value);
        }
        let found = detect(&ctx, &FDES, true);
        let symbols: (&[DynSymbol], &[DynSymbol]) = (&[], &[]);
        report(&ctx, &FDES, &[], symbols, "libtest.so", found, options)
    }

    fn starts(report: &VtablesReport) -> Vec<&str> {
        report.tables.iter().map(|t| t.vaddr.as_str()).collect()
    }

    fn methods(table: &Vtable) -> Vec<(&str, &str)> {
        table
            .methods
            .iter()
            .map(|m| (m.offset.as_str(), m.value.as_str()))
            .collect()
    }

    #[test]
    fn a_table_with_a_destructor_and_three_methods() {
        let report = listed(&VtablesOptions::default());
        assert_eq!(report.elf, "libtest.so");
        assert_eq!(starts(&report), ["0x2000", "0x2030", "0x2058", "0x2080"]);
        assert_eq!((report.tables_total, report.tables_matched), (4, 4));
        assert!(!report.truncated);
        let a = &report.tables[0];
        assert_eq!(a.section.as_deref(), Some(".data.rel.ro"));
        assert_eq!(a.drop.as_deref(), Some("0x1000"));
        assert_eq!((a.size.as_str(), a.align.as_str()), ("0x20", "0x8"));
        assert_eq!(a.methods_count, 3);
        let rows = methods(a);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0], ("0x18", "0x1040"));
        assert_eq!(rows[1], ("0x20", "0x1080"));
        assert_eq!(rows[2], ("0x28", "0x10c0"));
        let function = &a.methods[2].function;
        assert_eq!(function.fn_start, "0x10c0");
        assert_eq!(function.fn_end.as_deref(), Some("0x1100"));
        assert_eq!(function.bound, "eh_frame");
        let json = serde_json::to_value(a).unwrap();
        assert!(json.get("matched").is_none());
        assert!(json.get("addr_refs").is_none());
    }

    #[test]
    fn a_table_without_destructor_has_a_null_drop() {
        let report = listed(&VtablesOptions::default());
        let b = &report.tables[1];
        assert_eq!(b.drop, None);
        assert_eq!(methods(b), [("0x18", "0x1100"), ("0x20", "0x1040")]);
        let json = serde_json::to_value(b).unwrap();
        assert!(json["drop"].is_null());
    }

    #[test]
    fn two_adjacent_tables_are_split_at_the_second_header() {
        let report = listed(&VtablesOptions::default());
        let (b, c) = (&report.tables[1], &report.tables[2]);
        assert_eq!(b.methods_count, 2);
        assert_eq!(c.vaddr, "0x2058");
        assert_eq!(c.drop.as_deref(), Some("0x1080"));
        assert_eq!((c.size.as_str(), c.align.as_str()), ("0x30", "0x10"));
        assert_eq!(methods(c), [("0x18", "0x10c0")]);
    }

    #[test]
    fn a_pointer_into_the_middle_of_a_function_ends_the_methods() {
        let report = listed(&VtablesOptions::default());
        assert_eq!(methods(&report.tables[3]), [("0x18", "0x1000")]);
    }

    #[test]
    fn writable_data_outside_relro_is_not_scanned() {
        let report = listed(&VtablesOptions::default());
        assert!(!starts(&report).contains(&"0x2100"));
    }

    #[test]
    fn the_function_filter_lists_where_each_address_was_found() {
        let options = VtablesOptions {
            functions: vec![F1, F4],
            ..VtablesOptions::default()
        };
        let report = listed(&options);
        assert_eq!(report.tables_total, 4);
        assert_eq!(starts(&report), ["0x2000", "0x2058", "0x2080"]);
        let matched = |i: usize| report.tables[i].matched.clone().expect("matched");
        assert_eq!(matched(0), ["0x0", "0x28"]);
        assert_eq!(matched(1), ["0x18"]);
        assert_eq!(matched(2), ["0x18"]);
    }

    #[test]
    fn slot_size_and_start_filters_combine() {
        let slot = VtablesOptions {
            slot: Some(0x20),
            ..VtablesOptions::default()
        };
        assert_eq!(starts(&listed(&slot)), ["0x2000", "0x2030"]);
        let size = VtablesOptions {
            size: Some(0x30),
            ..VtablesOptions::default()
        };
        assert_eq!(starts(&listed(&size)), ["0x2058"]);
        let both = VtablesOptions {
            slot: Some(0x20),
            functions: vec![F2],
            at: vec![B, D],
            ..VtablesOptions::default()
        };
        let report = listed(&both);
        assert_eq!(starts(&report), ["0x2030"]);
        assert_eq!((report.tables_total, report.tables_matched), (4, 1));
    }

    #[test]
    fn the_cap_keeps_the_exact_totals() {
        let options = VtablesOptions {
            max: 1,
            ..VtablesOptions::default()
        };
        let report = listed(&options);
        assert_eq!(starts(&report), ["0x2000"]);
        assert_eq!((report.tables_total, report.tables_matched), (4, 4));
        assert!(report.truncated);
    }

    #[test]
    fn refs_list_the_instructions_and_words_that_carry_a_table() {
        let options = VtablesOptions {
            at: vec![B],
            refs: true,
            ..VtablesOptions::default()
        };
        let report = listed(&options);
        let b = &report.tables[0];
        let addr = b.addr_refs.as_ref().expect("refs");
        assert_eq!((addr.total, addr.truncated), (1, false));
        let insn = &addr.items[0];
        assert_eq!(insn.insn_addr, "0x1004");
        assert_eq!(insn.adrp_addr.as_deref(), Some("0x1000"));
        assert_eq!(insn.kind, "address");
        assert_eq!(insn.function.fn_start, "0x1000");
        let data = b.data_refs.as_ref().expect("refs");
        assert_eq!(data.total, 1);
        assert_eq!(data.items[0].vaddr, "0x2128");
        assert_eq!(data.items[0].section.as_deref(), Some(".data"));
        assert!(data.items[0].relocated);
    }

    #[test]
    fn vtables_options_are_parsed_or_refused_with_the_item() {
        assert_eq!(parse_vtables_elf("*"), Ok(None));
        assert_eq!(parse_vtables_elf("lib/x.so"), Ok(Some("lib/x.so".into())));
        assert!(parse_vtables_elf("").is_err());
        let items: Vec<String> = ["1040", "0x10c0", "1040"].map(String::from).to_vec();
        assert_eq!(parse_vtables_addresses(&items), Ok(vec![0x1040, 0x10c0]));
        let bad = ["1040".to_string(), "zz".to_string()];
        let why = parse_vtables_addresses(&bad).unwrap_err();
        assert!(why.contains("élément \"zz\""), "{why}");
        let item = |i: usize| i.to_string();
        let many: Vec<String> = (0..=MAX_VTABLES_ADDRESSES).map(item).collect();
        assert!(parse_vtables_addresses(&many).is_err());
        assert_eq!(parse_vtables_slot("0x38"), Ok(0x38));
        assert_eq!(parse_vtables_slot("56"), Ok(0x38));
        for refused in ["0x10", "0x3c", "38h", ""] {
            let why = parse_vtables_slot(refused).unwrap_err();
            assert!(why.contains(&format!("élément {refused:?}")), "{why}");
        }
        assert_eq!(parse_vtables_number("0x430"), Ok(0x430));
        assert_eq!(parse_vtables_number("1072"), Ok(0x430));
    }

    #[test]
    fn legend_defines_every_vtables_label() {
        let legend = super::super::legend();
        let labels = [
            "VTABLES (vtables[])",
            "tables_total",
            "tables_matched",
            "methods_count",
            "matched",
            "drop",
            "--native-vtables-fn",
            "--native-vtables-slot",
            "--native-vtables-size",
            "--native-vtables-at",
            "--native-vtables-max",
            "--native-vtables-refs",
            "détection structurelle",
        ];
        for label in labels {
            assert!(legend.contains(label), "{label}");
        }
    }
}
