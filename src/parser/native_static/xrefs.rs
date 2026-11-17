//! `--native --native-xrefs` : pour des adresses d'un ELF AArch64, la fonction
//! qui les contient, les branchements directs qui y mènent, les instructions
//! qui forment ou accèdent à l'adresse et les mots de données qui la portent.
//! Rien n'est exécuté. Étiquettes définies dans [`super::legend`].

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;

use object::elf;
use serde::Serialize;

use super::decode::{decode, Arch, Flow};
use super::disasm::{context, Ctx};
use super::native_strings::{code_addresses, data_areas, fde_ranges, Access};
use super::symex::Bound;
use super::{hex, parse_elf, parse_symex_address, read_uint, DynSymbol, ElfReport, Image, Section};

pub const DEFAULT_XREFS_MAX: usize = 2000;
pub const MAX_XREFS_TARGETS: usize = 64;

const KIND_CALL: &str = "call";
const KIND_JUMP: &str = "jump";
const KIND_COND_JUMP: &str = "cond_jump";
const KIND_ADDRESS: &str = "address";
const KIND_LOAD: &str = "load";
const KIND_STORE: &str = "store";

/// Par cible, dans l'ordre des cibles : (adresse, détail), avant tri et coupe.
type Found<T> = Vec<Vec<(u64, T)>>;

/// `--native-xrefs <elf|*>@<adresse>[,<adresse>...]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrefsSpec {
    /// Chemin de l'ELF ; `None` pour `*`.
    pub elf: Option<String>,
    pub targets: Vec<u64>,
}

impl std::fmt::Display for XrefsSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let targets: Vec<String> = self.targets.iter().map(|&at| hex(at)).collect();
        let elf = self.elf.as_deref().unwrap_or("*");
        write!(f, "{elf}@{}", targets.join(","))
    }
}

/// Adresses hexadécimales, préfixe `0x` facultatif ; doublons retirés.
pub fn parse_xrefs_spec(spec: &str) -> Result<XrefsSpec, String> {
    let Some((elf, list)) = spec.rsplit_once('@') else {
        return Err("forme attendue : <elf|*>@<adresse>[,<adresse>...]".into());
    };
    let elf = match elf {
        "" => return Err("chemin d'ELF vide (passer * pour tous les ELF)".into()),
        "*" => None,
        path => Some(path.to_string()),
    };
    let mut targets = Vec::new();
    for item in list.split(',') {
        let cite = |why: String| format!("élément {item:?} : {why}");
        let at = parse_symex_address(item).map_err(cite)?;
        if !targets.contains(&at) {
            targets.push(at);
        }
    }
    if targets.len() > MAX_XREFS_TARGETS {
        let count = targets.len();
        return Err(format!("{count} adresses : de 1 à {MAX_XREFS_TARGETS}"));
    }
    Ok(XrefsSpec { elf, targets })
}

#[derive(Debug, Clone, Serialize)]
pub struct XrefReport {
    pub elf: String,
    pub target: String,
    pub section: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<XrefFunction>,
    pub code_refs: XrefList<CodeRef>,
    pub addr_refs: XrefList<AddrRef>,
    pub data_refs: XrefList<DataRef>,
}

#[derive(Debug, Clone, Serialize)]
pub struct XrefFunction {
    pub fn_start: String,
    pub fn_end: Option<String>,
    pub bound: &'static str,
}

impl XrefFunction {
    /// Par [`Bound::of`], comme `--native-symex`.
    fn of(ctx: &Ctx, fdes: &[(u64, u64)], at: u64) -> Self {
        let bound = Bound::of(ctx, fdes, at);
        XrefFunction {
            fn_start: hex(bound.start),
            fn_end: bound.end.map(hex),
            bound: bound.source,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct XrefList<T> {
    pub total: usize,
    pub truncated: bool,
    pub items: Vec<T>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeRef {
    pub insn_addr: String,
    pub mnemonic: String,
    pub kind: &'static str,
    pub function: XrefFunction,
}

#[derive(Debug, Clone, Serialize)]
pub struct AddrRef {
    pub insn_addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adrp_addr: Option<String>,
    pub kind: &'static str,
    pub function: XrefFunction,
}

#[derive(Debug, Clone, Serialize)]
pub struct DataRef {
    pub vaddr: String,
    pub section: Option<String>,
    pub relocated: bool,
}

/// Les cibles de `targets` dans l'ELF `bytes` que décrit `elf` : toutes si
/// `every`, sinon celles qu'il contient (voir [`holds`]).
pub(super) fn run(
    bytes: &[u8],
    elf: &ElfReport,
    targets: &[u64],
    every: bool,
    max: usize,
) -> Result<Vec<XrefReport>, String> {
    let parsed = parse_elf(bytes).map_err(|e| format!("ELF illisible ({e})"))?;
    let dynamic = parsed.dynamic.as_deref();
    let (symbols, local_symbols) = (&parsed.symbols, &parsed.local_symbols);
    let ctx = context(parsed.image, dynamic, symbols, local_symbols);
    if ctx.arch != Some(Arch::Aarch64) {
        return Err(format!("machine {} : AArch64 seulement", elf.machine));
    }
    let held = |at: &u64| every || holds(&ctx.image, *at);
    let kept: Vec<u64> = targets.iter().copied().filter(held).collect();
    if kept.is_empty() {
        return Ok(Vec::new());
    }
    let fdes = fde_ranges(&ctx.image);
    let job = || search(&ctx, &fdes, symbols, local_symbols, &elf.path, &kept, max);
    std::panic::catch_unwind(AssertUnwindSafe(job))
        .map_err(|_| "panique pendant la recherche".to_string())
}

/// Une seule passe sur le code pour toutes les cibles.
fn search(
    ctx: &Ctx,
    fdes: &[(u64, u64)],
    symbols: &[DynSymbol],
    local_symbols: &[DynSymbol],
    elf: &str,
    targets: &[u64],
    max: usize,
) -> Vec<XrefReport> {
    let ranked = targets.iter().enumerate().map(|(i, &at)| (at, i));
    let index: HashMap<u64, usize> = ranked.collect();
    let mut code: Found<(&'static str, String)> = vec![Vec::new(); targets.len()];
    let each = |pc: u64, w: u32| {
        if let Some((to, kind, mnemonic)) = branch(pc, w) {
            if let Some(&i) = index.get(&to) {
                code[i].push((pc, (kind, mnemonic)));
            }
        }
    };
    let found = code_addresses(&ctx.image, &ctx.slots, symbols, local_symbols, each);
    let mut addr: Found<(Option<u64>, &'static str)> = vec![Vec::new(); targets.len()];
    for f in found {
        if let Some(&i) = index.get(&f.target) {
            addr[i].push((f.insn, (f.adrp, access_kind(f.access))));
        }
    }
    let data = data_words(ctx, &index);
    let function = |at: u64| XrefFunction::of(ctx, fdes, at);
    let mut reports = Vec::new();
    let lists = code.into_iter().zip(addr).zip(data);
    for (&target, ((code, addr), data)) in targets.iter().zip(lists) {
        let code_refs = capped(code, max, |at, (kind, mnemonic)| CodeRef {
            insn_addr: hex(at),
            mnemonic,
            kind,
            function: function(at),
        });
        let addr_refs = capped(addr, max, |at, (adrp, kind)| AddrRef {
            insn_addr: hex(at),
            adrp_addr: adrp.map(hex),
            kind,
            function: function(at),
        });
        let data_refs = capped(data, max, |at, (section, relocated)| DataRef {
            vaddr: hex(at),
            section,
            relocated,
        });
        let in_code = ctx.image.is_exec(target);
        reports.push(XrefReport {
            elf: elf.to_string(),
            target: hex(target),
            section: section_of(&ctx.image, target),
            function: in_code.then(|| function(target)),
            code_refs,
            addr_refs,
            data_refs,
        });
    }
    reports
}

/// bl, b, b.cond, bc.cond, cbz, cbnz, tbz, tbnz : (destination, kind, mnémonique).
fn branch(pc: u64, w: u32) -> Option<(u64, &'static str, String)> {
    if w & 0x1c00_0000 != 0x1400_0000 {
        return None;
    }
    let insn = decode(Arch::Aarch64, &w.to_le_bytes(), pc, false).ok()?;
    let (to, kind) = match insn.flow {
        Flow::Call(to, _) => (to, KIND_CALL),
        Flow::Jump(to, _) => (to, KIND_JUMP),
        Flow::Branch(to, _) => (to, KIND_COND_JUMP),
        _ => return None,
    };
    Some((to, kind, insn.mnemonic))
}

fn access_kind(access: Access) -> &'static str {
    match access {
        Access::Address => KIND_ADDRESS,
        Access::Load => KIND_LOAD,
        Access::Store => KIND_STORE,
    }
}

/// Mots de 8 octets alignés sur 8 des zones de données, égaux à une cible tels
/// quels dans le fichier, ou après relocation relative : (section, relogé).
fn data_words(ctx: &Ctx, index: &HashMap<u64, usize>) -> Found<(Option<String>, bool)> {
    let mut found = vec![Vec::new(); index.len()];
    let (areas, _) = data_areas(&ctx.image);
    for area in areas.iter().filter(|a| !a.exec) {
        let Some(bytes) = ctx.image.bytes_at(area.offset, area.size) else {
            continue;
        };
        let Some(first) = area.vaddr.checked_next_multiple_of(8) else {
            continue;
        };
        let Some(bytes) = bytes.get((first - area.vaddr) as usize..) else {
            continue;
        };
        for (i, word) in bytes.as_chunks::<8>().0.iter().enumerate() {
            let at = first + 8 * i as u64;
            let slot = ctx.slots.get(&at).copied();
            let raw = read_uint(word, ctx.image.big_endian);
            let raw = raw.filter(|&v| slot != Some(v));
            for (value, relocated) in [(slot, true), (raw, false)] {
                if let Some(&t) = value.and_then(|v| index.get(&v)) {
                    found[t].push((at, (area.name.clone(), relocated)));
                }
            }
        }
    }
    found
}

/// Triés par adresse croissante, coupés à `max` ; `total` les compte tous.
fn capped<T, U>(mut found: Vec<(u64, T)>, max: usize, build: impl Fn(u64, T) -> U) -> XrefList<U> {
    found.sort_by_key(|&(at, _)| at);
    let total = found.len();
    found.truncate(max);
    let items: Vec<U> = found.into_iter().map(|(at, t)| build(at, t)).collect();
    XrefList {
        total,
        truncated: items.len() < total,
        items,
    }
}

fn section_of(image: &Image, at: u64) -> Option<String> {
    let inside = |s: &&Section| at.checked_sub(s.addr).is_some_and(|d| d < s.size);
    let mut allocated = image.sections.iter().filter(|s| s.has(elf::SHF_ALLOC));
    allocated.find(inside).map(|s| s.name.clone())
}

/// Une section allouée contient `at` ; sans section headers, un segment LOAD.
fn holds(image: &Image, at: u64) -> bool {
    if image.sections.is_empty() {
        let mut loads = image.segments.iter().filter(|s| s.p_type == elf::PT_LOAD);
        loads.any(|s| s.in_memory(at))
    } else {
        section_of(image, at).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::super::Segment;
    use super::*;

    const TEXT: u64 = 0x1000;
    const DATA: u64 = 0x2000;
    const CALLEE: u64 = 0x1040;
    const SLOT: u64 = 0x2010;

    const PROGRAM: [(u32, &str); 10] = [
        (0x94000010, "1000  bl    0x1040"),
        (0x1400000f, "1004  b     0x1040"),
        (0x540001c0, "1008  b.eq  0x1040"),
        (0xb40001a0, "100c  cbz   x0, 0x1040"),
        (0xb0000001, "1010  adrp  x1, 0x2000"),
        (0x91004021, "1014  add   x1, x1, #0x10"),
        (0xb0000003, "1018  adrp  x3, 0x2000"),
        (0xf9400864, "101c  ldr   x4, [x3, #0x10]"),
        (0xf9000865, "1020  str   x5, [x3, #0x10]"),
        (0xd65f03c0, "1024  ret"),
    ];

    fn segment(flags: u32, vaddr: u64, size: u64) -> Segment {
        Segment {
            p_type: elf::PT_LOAD,
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

    /// .text en 0x1000 (R+X), .data.rel.ro en 0x2000 (R+W), chacun chargé à
    /// l'adresse de son offset.
    fn image(data: &[u8]) -> Image<'_> {
        let exec = elf::SHF_ALLOC | elf::SHF_EXECINSTR;
        let write = elf::SHF_ALLOC | elf::SHF_WRITE;
        Image {
            data,
            ptr_size: 8,
            big_endian: false,
            machine: elf::EM_AARCH64,
            segments: vec![
                segment(elf::PF_R | elf::PF_X, 0, DATA),
                segment(elf::PF_R | elf::PF_W, DATA, 0x1000),
            ],
            sections: vec![
                section(".text", exec, TEXT, 0x100),
                section(".data.rel.ro", write, DATA, 0x40),
            ],
        }
    }

    fn put(data: &mut [u8], at: u64, bytes: &[u8]) {
        let at = at as usize;
        data[at..at + bytes.len()].copy_from_slice(bytes);
    }

    /// PROGRAM ; en DATA + 0x20, CALLEE tel quel dans le fichier ; en
    /// DATA + 0x28, un mot nul relogé vers CALLEE. FDE : [TEXT, CALLEE) et
    /// [CALLEE, CALLEE + 0x10).
    fn searched(targets: &[u64], max: usize) -> Vec<XrefReport> {
        let mut data = vec![0u8; 0x3000];
        for (i, (word, _)) in PROGRAM.iter().enumerate() {
            put(&mut data, TEXT + 4 * i as u64, &word.to_le_bytes());
        }
        put(&mut data, DATA + 0x20, &CALLEE.to_le_bytes());
        let mut ctx = context(image(&data), None, &[], &[]);
        ctx.slots.insert(DATA + 0x28, CALLEE);
        let fdes = [(TEXT, CALLEE), (CALLEE, CALLEE + 0x10)];
        search(&ctx, &fdes, &[], &[], "libtest.so", targets, max)
    }

    fn rows<'a, T, R>(list: &'a XrefList<T>, row: impl Fn(&'a T) -> R) -> Vec<R> {
        list.items.iter().map(row).collect()
    }

    fn code_row(r: &CodeRef) -> (&str, &str, &str) {
        (r.insn_addr.as_str(), r.mnemonic.as_str(), r.kind)
    }

    fn addr_row(r: &AddrRef) -> (&str, Option<&str>, &str) {
        (r.insn_addr.as_str(), r.adrp_addr.as_deref(), r.kind)
    }

    fn data_row(r: &DataRef) -> (&str, bool) {
        (r.vaddr.as_str(), r.relocated)
    }

    #[test]
    fn a_target_reached_by_bl_and_b_lists_both_with_their_function() {
        let reports = searched(&[CALLEE], DEFAULT_XREFS_MAX);
        assert_eq!(reports.len(), 1);
        let callee = &reports[0];
        assert_eq!(callee.elf, "libtest.so");
        assert_eq!(callee.target, "0x1040");
        assert_eq!(callee.section.as_deref(), Some(".text"));
        let function = callee.function.as_ref().expect("cible dans le code");
        assert_eq!(function.fn_start, "0x1040");
        assert_eq!(function.fn_end.as_deref(), Some("0x1050"));
        assert_eq!(function.bound, "eh_frame");

        let refs = &callee.code_refs;
        assert_eq!((refs.total, refs.truncated), (4, false));
        let found = rows(refs, code_row);
        assert_eq!(found[0], ("0x1000", "bl", KIND_CALL));
        assert_eq!(found[1], ("0x1004", "b", KIND_JUMP));
        let caller = &refs.items[0].function;
        assert_eq!(caller.fn_start, "0x1000");
        assert_eq!(caller.fn_end.as_deref(), Some("0x1040"));
        assert_eq!(callee.addr_refs.total, 0);
    }

    #[test]
    fn conditional_branches_are_cond_jumps() {
        let reports = searched(&[CALLEE], DEFAULT_XREFS_MAX);
        let found = rows(&reports[0].code_refs, code_row);
        assert_eq!((found[2].0, found[2].2), ("0x1008", KIND_COND_JUMP));
        assert_eq!(found[3], ("0x100c", "cbz", KIND_COND_JUMP));
    }

    #[test]
    fn adrp_add_forms_the_address_and_adrp_ldr_str_access_it() {
        let reports = searched(&[SLOT], DEFAULT_XREFS_MAX);
        let slot = &reports[0];
        assert_eq!(slot.section.as_deref(), Some(".data.rel.ro"));
        assert!(slot.function.is_none());
        assert_eq!(slot.code_refs.total, 0);
        let expected = [
            ("0x1014", Some("0x1010"), KIND_ADDRESS),
            ("0x101c", Some("0x1018"), KIND_LOAD),
            ("0x1020", Some("0x1018"), KIND_STORE),
        ];
        assert_eq!(rows(&slot.addr_refs, addr_row), expected);
        assert_eq!(slot.addr_refs.items[0].function.fn_start, "0x1000");
    }

    #[test]
    fn data_words_match_in_the_file_and_after_relative_relocation() {
        let reports = searched(&[CALLEE], DEFAULT_XREFS_MAX);
        let words = &reports[0].data_refs;
        assert_eq!(words.total, 2);
        assert_eq!(rows(words, data_row), [("0x2020", false), ("0x2028", true)]);
        assert_eq!(words.items[0].section.as_deref(), Some(".data.rel.ro"));
    }

    #[test]
    fn the_cap_keeps_the_exact_total() {
        let reports = searched(&[CALLEE, SLOT], 2);
        let refs = &reports[0].code_refs;
        assert_eq!((refs.total, refs.truncated), (4, true));
        let expected = [("0x1000", "bl", KIND_CALL), ("0x1004", "b", KIND_JUMP)];
        assert_eq!(rows(refs, code_row), expected);
        let slot = &reports[1].addr_refs;
        assert_eq!((slot.total, slot.truncated, slot.items.len()), (3, true, 2));
        let json = serde_json::to_value(&reports[1]).unwrap();
        assert_eq!(json["addr_refs"]["total"], 3);
        assert!(json.get("function").is_none());
    }

    #[test]
    fn xrefs_specs_are_parsed_or_refused_with_the_item() {
        let text = "lib/arm64-v8a/libx.so@36ffbd0,0x1040,1040";
        let spec = parse_xrefs_spec(text).unwrap();
        assert_eq!(spec.elf.as_deref(), Some("lib/arm64-v8a/libx.so"));
        assert_eq!(spec.targets, [0x36ffbd0, 0x1040]);
        assert_eq!(spec.to_string(), "lib/arm64-v8a/libx.so@0x36ffbd0,0x1040");
        assert_eq!(parse_xrefs_spec("*@1000").unwrap().elf, None);
        for (spec, item) in [("*@1000,zz", "zz"), ("*@", ""), ("*@1000,,2000", "")] {
            let why = parse_xrefs_spec(spec).unwrap_err();
            assert!(why.contains(&format!("élément {item:?}")), "{why}");
        }
        assert!(parse_xrefs_spec("1000").is_err());
        assert!(parse_xrefs_spec("@1000").is_err());
        let many: Vec<String> = (0..=MAX_XREFS_TARGETS).map(|i| i.to_string()).collect();
        let all = format!("*@{}", many.join(","));
        assert!(parse_xrefs_spec(&all).is_err());
    }

    #[test]
    fn legend_defines_every_xrefs_label() {
        let legend = super::super::legend();
        let labels = [
            "XREFS (xrefs[])",
            "code_refs",
            "addr_refs",
            "data_refs",
            "adrp_addr",
            "relocated",
            "truncated",
            "--native-xrefs-max",
            KIND_CALL,
            KIND_JUMP,
            KIND_COND_JUMP,
            KIND_ADDRESS,
            KIND_LOAD,
            KIND_STORE,
        ];
        for label in labels {
            assert!(legend.contains(label), "{label}");
        }
    }
}
