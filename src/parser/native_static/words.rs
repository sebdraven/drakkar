//! `--native --native-words` : mots de 8 octets lus à des adresses d'un ELF
//! AArch64, relocations relatives appliquées, et ce que chacun désigne. Rien
//! n'est exécuté. Étiquettes définies dans [`super::legend`].

use std::panic::AssertUnwindSafe;

use object::elf;
use serde::Serialize;

use super::decode::Arch;
use super::disasm::{context, Ctx};
use super::native_strings::{fde_ranges, is_text_char};
use super::symex::Bound;
use super::xrefs::{allocated_section, holds, is_link_metadata, XrefFunction};
use super::{hex, parse_elf, parse_symex_address, ElfReport, Image};

pub const MAX_WORDS_COUNT: usize = 512;
pub const MAX_WORDS_RANGES: usize = 64;
pub const MAX_WORDS_TEXT: usize = 96;
const VTABLE_MAX_SIZE: u64 = 0x10_0000;
const VTABLE_MAX_ALIGN: u64 = 4096;

const WORDS_FORM: &str = "<elf|*>@<adresse>:<nombre>[,<adresse>:<nombre>...]";

const KIND_CODE: &str = "code";
const KIND_DATA: &str = "data";
const KIND_INT: &str = "int";
const KIND_NONE: &str = "none";

/// `--native-words <elf|*>@<adresse>:<nombre>[,<adresse>:<nombre>...]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WordsSpec {
    /// Chemin de l'ELF ; `None` pour `*`.
    pub elf: Option<String>,
    /// (adresse, nombre de mots).
    pub ranges: Vec<(u64, usize)>,
}

impl std::fmt::Display for WordsSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ranges: Vec<String> = self
            .ranges
            .iter()
            .map(|&(at, count)| format!("{}:{count}", hex(at)))
            .collect();
        let elf = self.elf.as_deref().unwrap_or("*");
        write!(f, "{elf}@{}", ranges.join(","))
    }
}

/// Adresse hexadécimale, préfixe `0x` facultatif, alignée sur 8 ; nombre
/// décimal de mots.
pub fn parse_words_spec(spec: &str) -> Result<WordsSpec, String> {
    let Some((elf, list)) = spec.rsplit_once('@') else {
        return Err(format!("forme attendue : {WORDS_FORM}"));
    };
    let elf = match elf {
        "" => return Err("chemin d'ELF vide (passer * pour tous les ELF)".into()),
        "*" => None,
        path => Some(path.to_string()),
    };
    let mut ranges = Vec::new();
    for item in list.split(',') {
        let cite = |why: String| format!("élément {item:?} : {why}");
        let Some((at, count)) = item.split_once(':') else {
            return Err(cite("attendu <adresse>:<nombre>".into()));
        };
        let at = parse_symex_address(at).map_err(cite)?;
        if at % 8 != 0 {
            return Err(cite(format!("{} n'est pas alignée sur 8", hex(at))));
        }
        let parsed = count.trim().parse::<usize>().ok();
        let Some(count) = parsed.filter(|n| (1..=MAX_WORDS_COUNT).contains(n)) else {
            let why = format!("nombre {count:?} : entier décimal de 1 à {MAX_WORDS_COUNT}");
            return Err(cite(why));
        };
        if at.checked_add(8 * count as u64).is_none() {
            return Err(cite("la plage dépasse l'espace d'adressage".into()));
        }
        ranges.push((at, count));
    }
    if ranges.len() > MAX_WORDS_RANGES {
        let count = ranges.len();
        return Err(format!("{count} plages : de 1 à {MAX_WORDS_RANGES}"));
    }
    Ok(WordsSpec { elf, ranges })
}

#[derive(Debug, Clone, Serialize)]
pub struct WordsReport {
    pub elf: String,
    pub start: String,
    pub count: usize,
    pub vtable_like: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub align: Option<String>,
    pub items: Vec<Word>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Word {
    pub index: usize,
    pub offset: String,
    pub vaddr: String,
    pub section: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub relocated: bool,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<XrefFunction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_start: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_section: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_truncated: Option<bool>,
    #[serde(skip)]
    number: Option<u64>,
}

impl Word {
    pub(super) fn number(&self) -> Option<u64> {
        self.number
    }

    /// kind code et at_start vrai.
    pub(super) fn is_function_start(&self) -> bool {
        self.kind == KIND_CODE && self.at_start == Some(true)
    }
}

/// Les plages `ranges` de l'ELF `bytes` que décrit `elf` : toutes si `every`,
/// sinon celles dont le début est dans l'ELF (voir [`holds`]).
pub(super) fn run(
    bytes: &[u8],
    elf: &ElfReport,
    ranges: &[(u64, usize)],
    every: bool,
) -> Result<Vec<WordsReport>, String> {
    let parsed = parse_elf(bytes).map_err(|e| format!("ELF illisible ({e})"))?;
    let pie = parsed.e_type == elf::ET_DYN;
    let dynamic = parsed.dynamic.as_deref();
    let (symbols, local_symbols) = (&parsed.symbols, &parsed.local_symbols);
    let ctx = context(parsed.image, dynamic, symbols, local_symbols);
    if ctx.arch != Some(Arch::Aarch64) {
        return Err(format!("machine {} : AArch64 seulement", elf.machine));
    }
    let held = |&(start, _): &(u64, usize)| every || holds(&ctx.image, start);
    let kept: Vec<(u64, usize)> = ranges.iter().copied().filter(held).collect();
    if kept.is_empty() {
        return Ok(Vec::new());
    }
    let fdes = fde_ranges(&ctx.image);
    let read = |range: &(u64, usize)| read_range(&ctx, &fdes, pie, &elf.path, *range);
    let job = || kept.iter().map(read).collect::<Vec<_>>();
    std::panic::catch_unwind(AssertUnwindSafe(job))
        .map_err(|_| "panique pendant la lecture".to_string())
}

/// `pie` : ELF de type ET_DYN.
fn read_range(
    ctx: &Ctx,
    fdes: &[(u64, u64)],
    pie: bool,
    elf: &str,
    range: (u64, usize),
) -> WordsReport {
    let (start, count) = range;
    let read = |index| read_word(ctx, fdes, pie, start, index);
    let items: Vec<Word> = (0..count).map(read).collect();
    let header = vtable_header(&items);
    WordsReport {
        elf: elf.to_string(),
        start: hex(start),
        count,
        vtable_like: header.is_some(),
        size: header.map(|(size, _)| hex(size)),
        align: header.map(|(_, align)| hex(align)),
        items,
    }
}

pub(super) fn read_word(
    ctx: &Ctx,
    fdes: &[(u64, u64)],
    pie: bool,
    start: u64,
    index: usize,
) -> Word {
    let image = &ctx.image;
    let offset = 8 * index as u64;
    let at = start + offset;
    let section = allocated_section(image, at);
    let stored = image.sections.is_empty() || section.is_some_and(|s| s.has_file_data());
    let raw = if stored { image.word_at(at) } else { None };
    let slot = raw.and(ctx.slots.get(&at).copied());
    let value = slot.or(raw);
    let mut word = Word {
        index,
        offset: hex(offset),
        vaddr: hex(at),
        section: section.map(|s| s.name.clone()),
        raw: raw.map(hex),
        value: value.map(hex),
        relocated: slot.is_some(),
        kind: KIND_NONE,
        function: None,
        at_start: None,
        target_section: None,
        text: None,
        text_truncated: None,
        number: value,
    };
    let Some(value) = value else {
        return word;
    };
    if pie && slot.is_none() {
        word.kind = KIND_INT;
        return word;
    }
    match target(image, value) {
        Some((true, _)) => {
            let bound = Bound::of(ctx, fdes, value);
            let known = bound.end.is_some() && bound.start == value;
            word.kind = KIND_CODE;
            word.at_start = Some(known || ctx.starts.contains(&value));
            word.function = Some(bound.into());
        }
        Some((false, target_section)) => {
            word.kind = KIND_DATA;
            word.target_section = target_section;
            if let Some((text, truncated)) = text_at(image, value) {
                word.text = Some(text);
                word.text_truncated = Some(truncated);
            }
        }
        None => word.kind = KIND_INT,
    }
    word
}

/// (exécutable, section) de la section allouée qui contient `at`, aucune si
/// c'est une section de [`is_link_metadata`] ; sans section headers, du
/// segment LOAD, section absente.
fn target(image: &Image, at: u64) -> Option<(bool, Option<String>)> {
    if !image.sections.is_empty() {
        let s = allocated_section(image, at)?;
        if is_link_metadata(s) {
            return None;
        }
        return Some((s.has(elf::SHF_EXECINSTR), Some(s.name.clone())));
    }
    let mut loads = image.segments.iter().filter(|s| s.p_type == elf::PT_LOAD);
    let s = loads.find(|s| s.in_memory(at))?;
    Some((s.has(elf::PF_X), None))
}

/// Au plus [`MAX_WORDS_TEXT`] octets du fichier à `at`, coupés au premier nul :
/// texte UTF-8 non vide sans caractère de contrôle autre que `\t`, `\n`, `\r`.
/// (texte, aucun nul dans la fenêtre ni juste après).
fn text_at(image: &Image, at: u64) -> Option<(String, bool)> {
    let start = usize::try_from(image.offset_of(at)?).ok()?;
    let tail = image.data.get(start..)?;
    let window = &tail[..tail.len().min(MAX_WORDS_TEXT)];
    let (bytes, truncated) = match window.iter().position(|&b| b == 0) {
        Some(end) => (&window[..end], false),
        None => (window, tail.get(MAX_WORDS_TEXT) != Some(&0)),
    };
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(e) if truncated && e.error_len().is_none() => {
            std::str::from_utf8(&bytes[..e.valid_up_to()]).ok()?
        }
        Err(_) => return None,
    };
    if text.is_empty() || !text.chars().all(is_text_char) {
        return None;
    }
    Some((text.to_string(), truncated))
}

/// (taille, alignement) si les trois premiers mots ont la forme d'un en-tête
/// de table de méthodes Rust : destructeur, taille, alignement.
fn vtable_header(items: &[Word]) -> Option<(u64, u64)> {
    let [first, second, third, ..] = items else {
        return None;
    };
    let entry = first.kind == KIND_CODE && first.at_start == Some(true);
    if !entry && first.number != Some(0) {
        return None;
    }
    let int = |w: &Word| w.number.filter(|_| w.kind == KIND_INT);
    let aligned = |n: u64| n.is_power_of_two() && n <= VTABLE_MAX_ALIGN;
    let size = int(second).filter(|&n| n < VTABLE_MAX_SIZE)?;
    let align = int(third).filter(|&n| aligned(n))?;
    Some((size, align))
}

#[cfg(test)]
mod tests {
    use super::super::{Section, Segment};
    use super::*;

    const TEXT: u64 = 0x1000;
    const FUNCTION: u64 = 0x1040;
    const RODATA: u64 = 0x1800;
    const LONG: u64 = 0x1900;
    const TABLE: u64 = 0x1980;
    const DYNSYM: u64 = 0x200;
    const DATA: u64 = 0x2000;
    const BSS: u64 = 0x2040;

    fn segment(flags: u32, vaddr: u64, memsz: u64, filesz: u64) -> Segment {
        Segment {
            p_type: elf::PT_LOAD,
            flags,
            vaddr,
            memsz,
            offset: vaddr,
            filesz,
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

    /// Segment R+X [0, DATA) : .dynsym, .text, .rodata. Segment R+W en DATA,
    /// 0x40 octets dans le fichier : .data.rel.ro, puis .bss [BSS, BSS + 0x10).
    fn image(data: &[u8]) -> Image<'_> {
        let exec = elf::SHF_ALLOC | elf::SHF_EXECINSTR;
        let write = elf::SHF_ALLOC | elf::SHF_WRITE;
        Image {
            data,
            ptr_size: 8,
            big_endian: false,
            machine: elf::EM_AARCH64,
            segments: vec![
                segment(elf::PF_R | elf::PF_X, 0, DATA, DATA),
                segment(elf::PF_R | elf::PF_W, DATA, 0x1000, 0x40),
            ],
            sections: vec![
                Section {
                    sh_type: elf::SHT_DYNSYM,
                    ..section(".dynsym", elf::SHF_ALLOC, DYNSYM, 0x100)
                },
                section(".text", exec, TEXT, 0x100),
                section(".rodata", elf::SHF_ALLOC, RODATA, 0x200),
                section(".data.rel.ro", write, DATA, 0x40),
                Section {
                    sh_type: elf::SHT_NOBITS,
                    ..section(".bss", write, BSS, 0x10)
                },
            ],
        }
    }

    fn put(data: &mut [u8], at: u64, bytes: &[u8]) {
        let at = at as usize;
        data[at..at + bytes.len()].copy_from_slice(bytes);
    }

    /// ELF ET_DYN, voir [`read_as`].
    fn read(start: u64, count: usize) -> WordsReport {
        read_as(true, start, count)
    }

    /// En DATA : FUNCTION relogé, 0x18, 0x8, FUNCTION + 8 relogé, RODATA
    /// relogé, 0x12345678 tel quel, LONG relogé, 0. En TABLE : FUNCTION
    /// relogé, DYNSYM + 0x30, 0x8, RODATA tel quel. FDE [FUNCTION,
    /// FUNCTION + 0x10). "hello" en RODATA, 120 « a » en LONG.
    fn read_as(pie: bool, start: u64, count: usize) -> WordsReport {
        let mut data = vec![0u8; 0x3000];
        put(&mut data, DATA + 0x08, &0x18u64.to_le_bytes());
        put(&mut data, DATA + 0x10, &0x8u64.to_le_bytes());
        put(&mut data, DATA + 0x28, &0x1234_5678u64.to_le_bytes());
        put(&mut data, RODATA, b"hello\0");
        put(&mut data, LONG, &[b'a'; 120]);
        put(&mut data, TABLE + 0x08, &(DYNSYM + 0x30).to_le_bytes());
        put(&mut data, TABLE + 0x10, &0x8u64.to_le_bytes());
        put(&mut data, TABLE + 0x18, &RODATA.to_le_bytes());
        let mut ctx = context(image(&data), None, &[], &[]);
        let slots = [
            (DATA, FUNCTION),
            (DATA + 0x18, FUNCTION + 8),
            (DATA + 0x20, RODATA),
            (DATA + 0x30, LONG),
            (TABLE, FUNCTION),
        ];
        for (at, value) in slots {
            ctx.slots.insert(at, value);
        }
        let fdes = [(FUNCTION, FUNCTION + 0x10)];
        read_range(&ctx, &fdes, pie, "libtest.so", (start, count))
    }

    #[test]
    fn a_relocated_word_to_a_function_start_is_code_at_start() {
        let word = &read(DATA, 1).items[0];
        assert_eq!(word.vaddr, "0x2000");
        assert_eq!(word.section.as_deref(), Some(".data.rel.ro"));
        assert_eq!(word.raw.as_deref(), Some("0x0"));
        assert_eq!(word.value.as_deref(), Some("0x1040"));
        assert!(word.relocated);
        assert_eq!(word.kind, KIND_CODE);
        assert_eq!(word.at_start, Some(true));
        let function = word.function.as_ref().expect("code");
        assert_eq!(function.fn_start, "0x1040");
        assert_eq!(function.fn_end.as_deref(), Some("0x1050"));
        assert_eq!(function.bound, "eh_frame");
    }

    #[test]
    fn a_word_into_the_middle_of_a_function_is_not_at_start() {
        let word = &read(DATA + 0x18, 1).items[0];
        assert_eq!(word.kind, KIND_CODE);
        assert_eq!(word.at_start, Some(false));
        assert_eq!(word.function.as_ref().unwrap().fn_start, "0x1040");
    }

    #[test]
    fn a_word_to_text_carries_the_text_cut_at_nul_or_at_96_bytes() {
        let words = read(DATA + 0x20, 3).items;
        assert_eq!(words[0].kind, KIND_DATA);
        assert_eq!(words[0].target_section.as_deref(), Some(".rodata"));
        assert_eq!(words[0].text.as_deref(), Some("hello"));
        assert_eq!(words[0].text_truncated, Some(false));
        let long = &words[2];
        assert_eq!(long.text.as_deref().map(str::len), Some(MAX_WORDS_TEXT));
        assert_eq!(long.text_truncated, Some(true));
        let json = serde_json::to_value(&words[0]).unwrap();
        assert!(json.get("function").is_none());
        assert!(json.get("number").is_none());
    }

    #[test]
    fn a_plain_integer_is_int() {
        let word = &read(DATA + 0x28, 1).items[0];
        assert_eq!(word.raw.as_deref(), Some("0x12345678"));
        assert_eq!(word.value, word.raw);
        assert!(!word.relocated);
        assert_eq!(word.kind, KIND_INT);
        let json = serde_json::to_value(word).unwrap();
        assert!(json.get("at_start").is_none());
        assert!(json.get("target_section").is_none());
    }

    #[test]
    fn a_rust_vtable_header_is_recognised_with_size_and_align() {
        let table = read(DATA, 4);
        assert!(table.vtable_like);
        assert_eq!(table.size.as_deref(), Some("0x18"));
        assert_eq!(table.align.as_deref(), Some("0x8"));
        let offsets: Vec<&str> = table.items.iter().map(|w| w.offset.as_str()).collect();
        assert_eq!(offsets, ["0x0", "0x8", "0x10", "0x18"]);
    }

    #[test]
    fn a_range_without_the_header_shape_is_not_a_vtable() {
        let middle = read(DATA + 0x18, 3);
        assert!(!middle.vtable_like);
        assert!(middle.size.is_none() && middle.align.is_none());
        let json = serde_json::to_value(&middle).unwrap();
        assert!(json.get("size").is_none());
        assert!(!read(DATA, 2).vtable_like);
    }

    #[test]
    fn a_vtable_size_inside_a_link_metadata_section_is_still_an_int() {
        for pie in [true, false] {
            let table = read_as(pie, TABLE, 3);
            assert_eq!(table.items[1].kind, KIND_INT, "pie {pie}");
            assert!(table.items[1].target_section.is_none());
            assert!(table.vtable_like, "pie {pie}");
            assert_eq!(table.size.as_deref(), Some("0x230"));
            assert_eq!(table.align.as_deref(), Some("0x8"));
        }
    }

    #[test]
    fn an_unrelocated_word_of_an_et_dyn_into_rodata_stays_int() {
        let word = &read_as(true, TABLE + 0x18, 1).items[0];
        assert_eq!(word.value.as_deref(), Some("0x1800"));
        assert!(!word.relocated);
        assert_eq!(word.kind, KIND_INT);
        assert!(word.target_section.is_none() && word.text.is_none());
        let fixed = &read_as(false, TABLE + 0x18, 1).items[0];
        assert_eq!(fixed.kind, KIND_DATA);
    }

    #[test]
    fn a_relocated_word_of_an_et_dyn_into_rodata_stays_data_with_its_text() {
        let word = &read_as(true, DATA + 0x20, 1).items[0];
        assert!(word.relocated);
        assert_eq!(word.kind, KIND_DATA);
        assert_eq!(word.target_section.as_deref(), Some(".rodata"));
        assert_eq!(word.text.as_deref(), Some("hello"));
    }

    #[test]
    fn a_range_past_its_section_reads_bss_and_beyond_as_none() {
        let words = read(DATA + 0x38, 4).items;
        assert_eq!(words[0].kind, KIND_INT);
        assert_eq!(words[0].value.as_deref(), Some("0x0"));
        for word in &words[1..] {
            assert_eq!(word.kind, KIND_NONE, "{}", word.vaddr);
            assert!(word.raw.is_none() && word.value.is_none());
            assert!(!word.relocated);
        }
        assert_eq!(words[1].section.as_deref(), Some(".bss"));
        assert_eq!(words[2].section.as_deref(), Some(".bss"));
        assert_eq!(words[3].vaddr, "0x2050");
        assert_eq!(words[3].section, None);
        let json = serde_json::to_value(&words[3]).unwrap();
        assert!(json.get("value").is_none());
        assert!(json["section"].is_null());
    }

    #[test]
    fn words_specs_are_parsed_or_refused_with_the_item() {
        let text = "lib/arm64-v8a/libx.so@36ffbd0:4,0x1040:1";
        let spec = parse_words_spec(text).unwrap();
        assert_eq!(spec.elf.as_deref(), Some("lib/arm64-v8a/libx.so"));
        assert_eq!(spec.ranges, [(0x36ffbd0, 4), (0x1040, 1)]);
        assert_eq!(
            spec.to_string(),
            "lib/arm64-v8a/libx.so@0x36ffbd0:4,0x1040:1"
        );
        assert_eq!(parse_words_spec("*@1000:1").unwrap().elf, None);
        let refused = [
            ("*@1004:2", "1004:2"),
            ("*@1000:0", "1000:0"),
            ("*@1000:513", "1000:513"),
            ("*@1000:0x10", "1000:0x10"),
            ("*@1000", "1000"),
            ("*@zz:1", "zz:1"),
            ("*@1000:1,,2000:1", ""),
        ];
        for (spec, item) in refused {
            let why = parse_words_spec(spec).unwrap_err();
            assert!(why.contains(&format!("élément {item:?}")), "{why}");
        }
        let why = parse_words_spec("*@1004:2").unwrap_err();
        assert!(why.contains("alignée sur 8"), "{why}");
        assert!(parse_words_spec("1000:1").is_err());
        assert!(parse_words_spec("@1000:1").is_err());
        let range = |i: usize| format!("{:x}:1", 8 * i);
        let many: Vec<String> = (0..=MAX_WORDS_RANGES).map(range).collect();
        assert!(parse_words_spec(&format!("*@{}", many.join(","))).is_err());
    }

    #[test]
    fn legend_defines_every_words_label() {
        let legend = super::super::legend();
        let labels = [
            "WORDS (words[])",
            "vtable_like",
            "at_start",
            "target_section",
            "text_truncated",
            "relocated",
            "raw",
            KIND_CODE,
            KIND_DATA,
            KIND_INT,
            KIND_NONE,
            "indice, pas une preuve",
        ];
        for label in labels {
            assert!(legend.contains(label), "{label}");
        }
    }
}
