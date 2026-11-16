//! `--native-strings` : chaînes de chaque ELF d'un APK, d'un XAPK ou d'un ELF
//! brut, avec la manière dont leur borne a été trouvée, les instructions qui
//! forment leur adresse, les crates Rust nommées par les chemins de source et
//! les constantes cryptographiques reconnues au contenu. Rien n'est exécuté.
//!
//! Un `&str` Rust est un couple (pointeur, longueur) sans octet nul : un
//! balayage de texte seul rend des blocs concaténés. Les bornes sont donc
//! prouvées d'abord, par les couples relogés des données et par les longueurs
//! immédiates du code AArch64, et le texte qu'elles ne couvrent pas est
//! découpé ensuite.
//!
//! Le rapport est écrit en flux, ELF après ELF, chaîne après chaîne.
//! Étiquettes définies dans [`legend`].

use std::collections::BTreeMap;
use std::io::{BufWriter, Write};

use super::*;

pub const DEFAULT_MIN_LENGTH: usize = 4;
/// Plafond, en octets, d'une borne rust_fatptr ou rust_code.
pub const MAX_STRING_LEN: u64 = 1 << 20;
/// Instructions pendant lesquelles une page ADRP, une adresse formée ou une
/// longueur immédiate restent appariables.
pub const CODE_WINDOW: usize = 8;
/// Nombre maximal de couples d'un tableau dont les références sont recopiées
/// sur chaque morceau.
pub const MAX_PROPAGATED_ARRAY: usize = 16;
/// Sections allouées jamais découpées en chaînes.
pub const SECTIONS_NOT_SCANNED: &str =
    ".eh_frame .eh_frame_hdr .gcc_except_table .got .got.plt .data.rel.ro";

const BOUNDARY_NUL: &str = "nul";
const BOUNDARY_FATPTR: &str = "rust_fatptr";
const BOUNDARY_CODE: &str = "rust_code";
const BOUNDARY_HEURISTIC: &str = "heuristic";

const ENCODING_ASCII: &str = "ascii";
const ENCODING_UTF8: &str = "utf8";
const ENCODING_UTF16LE: &str = "utf16le";

const KIND_ADRP_ADD: &str = "adrp_add";
const KIND_ADR: &str = "adr";
const KIND_LDR_LITERAL: &str = "ldr_literal";
const KIND_FATPTR: &str = "fatptr";
const KIND_FATPTR_ARRAY: &str = "fatptr_array";

const SOURCE_SYMTAB: &str = "symtab";
const SOURCE_EH_FRAME: &str = "eh_frame";

const AREAS_SECTIONS: &str = "sections";
const AREAS_SEGMENTS: &str = "segments";
const CODE_SCAN_AARCH64: &str = "aarch64";

const ORDER_LE: &str = "le";
const ORDER_BE: &str = "be";

const UNREADABLE: &str = "elf_unreadable";

/// `AAAA-MM-JJ HH:MM:SS ` d'un `SQLITE_SOURCE_ID` ; `0` = un chiffre.
const SOURCE_ID: &[u8] = b"0000-00-00 00:00:00 ";
const SOURCE_ID_HASH: usize = 40;

/// (bibliothèque, préfixe, chiffre exigé juste après le préfixe, texte exigé
/// plus loin dans la même chaîne).
const C_BANNERS: &[(&str, &str, bool, Option<&str>)] = &[
    ("OpenSSL", "OpenSSL ", true, None),
    ("LibreSSL", "LibreSSL ", true, None),
    ("BoringSSL", "BoringSSL", false, None),
    ("SQLite", "SQLite format 3", false, None),
    ("zlib", "deflate ", true, Some("Jean-loup Gailly")),
    ("zlib", "inflate ", true, Some("Mark Adler")),
    ("libpng", "libpng version ", true, None),
    ("libcurl", "libcurl/", true, None),
    ("Mbed TLS", "mbed TLS ", true, None),
    ("Mbed TLS", "Mbed TLS ", true, None),
];

const SHA256_K_HEAD: [u32; 8] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
];
const SHA512_K_HEAD: [u64; 4] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
];
const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const SHA1_IV: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
const POLY1305_CLAMP: [u8; 16] = [
    0xff, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f,
];
const SM4_SBOX_HEAD: [u8; 16] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
];

/// Réglages de `--native-strings`.
#[derive(Debug, Clone, Serialize)]
pub struct Options {
    /// Sous-chaînes cherchées, casse ignorée ; vide = toutes les chaînes.
    pub patterns: Vec<String>,
    pub min_length: usize,
    /// `--elf` : chemin d'entrée, ou `<split>!<entrée>`.
    pub elf: Option<String>,
    pub xrefs: bool,
    pub crates: bool,
}

/// Ce qui reste du rapport une fois écrit : de quoi rendre compte sur stderr.
#[derive(Debug, Default)]
pub struct Outcome {
    pub elfs: Vec<ElfOutcome>,
    pub not_selected: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug)]
pub struct ElfOutcome {
    pub label: String,
    pub machine: String,
    pub summary: ElfSummary,
}

/// Résumé d'un ELF, écrit en tête de son entrée.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ElfSummary {
    pub areas: Option<&'static str>,
    pub strings_found: usize,
    pub strings_emitted: usize,
    pub by_boundary: BoundaryCounts,
    pub by_encoding: EncodingCounts,
    pub fatptr_pairs: usize,
    pub format_arrays: usize,
    pub pairs_in_arrays: usize,
    pub arrays_with_xrefs: usize,
    pub arrays_without_xrefs: usize,
    pub arrays_not_propagated: usize,
    pub rust_code_dropped_prefixes: usize,
    pub blocks_split: usize,
    pub pieces_from_split: usize,
    pub code_scan: Option<&'static str>,
    pub functions: FunctionCounts,
    pub xrefs: Option<XrefCounts>,
    pub crypto_constants: usize,
    pub anomalies: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct BoundaryCounts {
    pub nul: usize,
    pub rust_fatptr: usize,
    pub rust_code: usize,
    pub heuristic: usize,
}

impl BoundaryCounts {
    pub fn pairs(&self) -> [(&'static str, usize); 4] {
        [
            (BOUNDARY_NUL, self.nul),
            (BOUNDARY_FATPTR, self.rust_fatptr),
            (BOUNDARY_CODE, self.rust_code),
            (BOUNDARY_HEURISTIC, self.heuristic),
        ]
    }

    fn count(&mut self, boundary: &str) {
        match boundary {
            BOUNDARY_NUL => self.nul += 1,
            BOUNDARY_FATPTR => self.rust_fatptr += 1,
            BOUNDARY_CODE => self.rust_code += 1,
            _ => self.heuristic += 1,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct EncodingCounts {
    pub ascii: usize,
    pub utf8: usize,
    pub utf16le: usize,
}

impl EncodingCounts {
    pub fn pairs(&self) -> [(&'static str, usize); 3] {
        [
            (ENCODING_ASCII, self.ascii),
            (ENCODING_UTF8, self.utf8),
            (ENCODING_UTF16LE, self.utf16le),
        ]
    }

    fn count(&mut self, encoding: &str) {
        match encoding {
            ENCODING_ASCII => self.ascii += 1,
            ENCODING_UTF8 => self.utf8 += 1,
            _ => self.utf16le += 1,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct FunctionCounts {
    pub symtab: usize,
    pub eh_frame: usize,
    pub eh_frame_present: bool,
    pub eh_frame_unread: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct XrefCounts {
    pub total: usize,
    pub unresolved_text: usize,
    pub non_text_targets: usize,
    pub without_function: usize,
    pub fatptr_array: usize,
}

/// Adresses formées qui ne désignent rien, selon l'octet visé.
#[derive(Default)]
struct TargetCounts {
    unresolved_text: usize,
    non_text_targets: usize,
}

#[derive(Serialize)]
struct Limits {
    min_length: usize,
    max_string_len: u64,
    code_window: usize,
    max_propagated_array: usize,
    sections_not_scanned: Vec<&'static str>,
}

#[derive(Serialize)]
struct Row<'a> {
    elf: &'a str,
    elf_sha256: &'a str,
    vaddr: String,
    file_offset: String,
    section: Option<&'a str>,
    length: u64,
    encoding: &'static str,
    value: &'a str,
    boundary: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    split_from: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    patterns: Vec<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pairs: Vec<PairRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    xrefs: Option<Vec<XrefRow<'a>>>,
}

#[derive(Serialize)]
struct PairRow {
    pair_vaddr: String,
    array_vaddr: String,
    array_index: usize,
    array_len: usize,
}

#[derive(Serialize)]
struct XrefRow<'a> {
    fn_start: Option<String>,
    insn_addr: String,
    kind: &'static str,
    offset: u64,
    nearest_export: Option<NearestExport<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    array_vaddr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_index: Option<usize>,
}

#[derive(Serialize)]
struct FormatArrayRow<'a> {
    array_vaddr: String,
    section: Option<&'a str>,
    len: usize,
    propagated: bool,
    pieces: Vec<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    patterns: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    xrefs: Option<Vec<XrefRow<'a>>>,
}

#[derive(Serialize)]
struct NearestExport<'a> {
    name: &'a str,
    distance: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CrateUse {
    #[serde(rename = "crate")]
    name: String,
    version: Option<String>,
    registry: Option<String>,
    occurrences: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CLibrary {
    library: &'static str,
    banner: String,
    vaddr: String,
}

#[derive(Serialize)]
struct CryptoRow<'a> {
    name: &'static str,
    byte_order: Option<&'static str>,
    length: usize,
    vaddr: String,
    file_offset: String,
    section: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    xrefs: Option<Vec<XrefRow<'a>>>,
}

/// Section allouée présente dans le fichier ou, sans section headers, segment
/// LOAD.
struct Area {
    name: Option<String>,
    vaddr: u64,
    offset: u64,
    size: u64,
    read_only: bool,
    exec: bool,
    /// Découpée en chaînes.
    strings: bool,
}

impl Area {
    fn contains(&self, at: u64) -> bool {
        at.checked_sub(self.vaddr).is_some_and(|d| d < self.size)
    }

    fn end(&self) -> u64 {
        self.vaddr.saturating_add(self.size)
    }

    fn file_offset(&self, at: u64) -> u64 {
        self.offset.wrapping_add(at.wrapping_sub(self.vaddr))
    }
}

#[derive(Clone, Copy)]
struct Proven {
    vaddr: u64,
    len: u64,
    boundary: &'static str,
}

struct Found {
    area: usize,
    vaddr: u64,
    len: u64,
    value: String,
    boundary: &'static str,
    encoding: &'static str,
    /// Adresse du bloc nul ou heuristic dont la chaîne est un morceau.
    split_from: Option<u64>,
    /// Index dans `Options::patterns`.
    patterns: Vec<usize>,
    refs: Vec<Ref>,
    /// Couples qui désignent la chaîne : (index du tableau, rang).
    places: Vec<(usize, usize)>,
}

impl Found {
    fn new(area: usize, vaddr: u64, len: u64, value: String, boundary: &'static str) -> Self {
        let encoding = if value.is_ascii() {
            ENCODING_ASCII
        } else {
            ENCODING_UTF8
        };
        Found {
            area,
            vaddr,
            len,
            value,
            boundary,
            encoding,
            split_from: None,
            patterns: Vec::new(),
            refs: Vec::new(),
            places: Vec::new(),
        }
    }

    /// Coupes aux cibles qui tombent strictement à l'intérieur de la chaîne :
    /// (index dans `value`, adresse). Une cible au milieu d'un caractère ne
    /// coupe pas.
    fn cuts(&self, targets: &[u64]) -> Vec<(usize, u64)> {
        let end = self.vaddr + self.len;
        let first = targets.partition_point(|&t| t <= self.vaddr);
        let mut cuts = Vec::new();
        for &target in targets[first..].iter().take_while(|&&t| t < end) {
            if let Some(index) = self.index_of((target - self.vaddr) as usize) {
                cuts.push((index, target));
            }
        }
        cuts
    }

    /// Index dans `value` de l'octet `offset` de la chaîne ; `None` au milieu
    /// d'un caractère UTF-8 ou d'une unité UTF-16.
    fn index_of(&self, offset: usize) -> Option<usize> {
        if self.encoding != ENCODING_UTF16LE {
            return self.value.is_char_boundary(offset).then_some(offset);
        }
        offset.is_multiple_of(2).then_some(offset / 2)
    }

    /// Morceaux de la chaîne coupée à `cuts` : tous heuristic, sauf le dernier
    /// d'un bloc nul, qui garde nul.
    fn split(self, cuts: &[(usize, u64)]) -> Vec<Found> {
        let mut starts = vec![(0, self.vaddr)];
        starts.extend_from_slice(cuts);
        let mut pieces = Vec::with_capacity(starts.len());
        for (k, &(from, vaddr)) in starts.iter().enumerate() {
            let (to, next, last) = match starts.get(k + 1) {
                Some(&(to, next)) => (to, next, false),
                None => (self.value.len(), self.vaddr + self.len, true),
            };
            let nul = last && self.boundary == BOUNDARY_NUL;
            let value = self.value[from..to].to_string();
            let mut piece = Found::new(self.area, vaddr, next - vaddr, value, boundary_of(nul));
            if self.encoding == ENCODING_UTF16LE {
                piece.encoding = ENCODING_UTF16LE;
            }
            piece.split_from = Some(self.vaddr);
            pieces.push(piece);
        }
        pieces
    }

    fn banner(&self, library: &'static str, at: usize) -> CLibrary {
        let wide = self.encoding == ENCODING_UTF16LE;
        let scale: u64 = if wide { 2 } else { 1 };
        CLibrary {
            library,
            banner: self.value[at..].to_string(),
            vaddr: hex(self.vaddr + scale * at as u64),
        }
    }
}

#[derive(Clone, Copy)]
struct Ref {
    insn: u64,
    kind: &'static str,
    offset: u64,
    /// fatptr_array : (adresse du tableau, rang du couple visé).
    array: Option<(u64, usize)>,
}

/// Adresse formée par l'instruction `insn`.
#[derive(Clone, Copy)]
struct Formed {
    insn: u64,
    target: u64,
    kind: &'static str,
    /// Emplacement du couple dont `target` est le pointeur.
    pair: Option<u64>,
}

#[derive(Clone, Copy)]
struct FatPair {
    slot: u64,
    ptr: u64,
    len: u64,
}

/// Couples rust_fatptr d'une même zone, aux emplacements consécutifs.
struct FatArray {
    area: Option<usize>,
    vaddr: u64,
    pairs: Vec<FatPair>,
    pieces: Vec<String>,
    /// Index dans `Options::patterns`.
    patterns: Vec<usize>,
    refs: Vec<Ref>,
}

impl FatArray {
    fn emitted(&self, options: &Options) -> bool {
        options.patterns.is_empty() || !self.patterns.is_empty()
    }

    fn propagated(&self) -> bool {
        self.pairs.len() <= MAX_PROPAGATED_ARRAY
    }
}

struct CryptoHit {
    name: &'static str,
    byte_order: Option<&'static str>,
    length: usize,
    area: usize,
    vaddr: u64,
    refs: Vec<Ref>,
}

struct Constant {
    name: &'static str,
    byte_order: Option<&'static str>,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct Bounds {
    /// Triées par début, un début au plus une fois.
    entries: Vec<FnBound>,
}

impl Bounds {
    fn owner(&self, at: u64) -> Option<u64> {
        let index = self.entries.partition_point(|e| e.start <= at);
        let entry = self.entries.get(index.checked_sub(1)?)?;
        match entry.end {
            Some(end) if at >= end => None,
            _ => Some(entry.start),
        }
    }
}

#[derive(Clone, Copy)]
struct FnBound {
    start: u64,
    end: Option<u64>,
    source: &'static str,
}

struct ElfStrings {
    path: String,
    split: Option<String>,
    sha256: String,
    machine: String,
    summary: ElfSummary,
    areas: Vec<Area>,
    /// Chaînes rendues, triées par adresse.
    strings: Vec<Found>,
    /// Tous les tableaux, triés par adresse ; les motifs filtrent à l'écriture.
    arrays: Vec<FatArray>,
    /// Exports STT_FUNC définis, triés par adresse.
    exports: Vec<(u64, String)>,
    bounds: Bounds,
    crates: Option<Vec<CrateUse>>,
    c_libraries: Option<Vec<CLibrary>>,
    crypto: Vec<CryptoHit>,
}

enum Container {
    Elf(String, Vec<u8>),
    Archive(TolerantZip),
}

/// Analyse `input` (APK, base d'un XAPK, ou ELF brut reconnu à son magic) et
/// écrit le rapport JSON en flux dans `dest`. `splits` : splits du XAPK, dont
/// seuls les splits ABI sont lus. Une entrée qui n'est ni un ELF ni une archive
/// lisible fait échouer le mode avant que `dest` soit créé.
pub fn run(
    input: &Source,
    splits: &[crate::parser::xapk::Split],
    options: &Options,
    dest: &Path,
) -> Result<Outcome> {
    let sha256 = input.sha256()?;
    let container = match input.as_path().filter(|p| is_elf_file(p)) {
        Some(path) => {
            let what = format!("lecture {}", path.display());
            let bytes = std::fs::read(path).context(what)?;
            let name = match path.file_name() {
                Some(name) => name.to_string_lossy().into_owned(),
                None => path.display().to_string(),
            };
            Container::Elf(name, bytes)
        }
        None => Container::Archive(input.tolerant()?),
    };
    if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
        let what = format!("création {}", parent.display());
        std::fs::create_dir_all(parent).context(what)?;
    }
    let what = format!("écriture {}", dest.display());
    let file = std::fs::File::create(dest).context(what)?;
    let label = input.to_string();
    let out = BufWriter::new(file);
    write_report(out, &sha256, &label, container, splits, options)
}

fn write_report<W: Write>(
    out: W,
    sha256: &str,
    input: &str,
    container: Container,
    splits: &[crate::parser::xapk::Split],
    options: &Options,
) -> Result<Outcome> {
    let mut stream = Stream::begin(out, sha256, input, options)?;
    let mut outcome = Outcome::default();
    match container {
        Container::Elf(name, bytes) => {
            if selected(options, &name, &name) {
                stream.elf(&mut outcome, &name, None, &bytes, options)?;
            } else {
                outcome.not_selected.push(name);
            }
        }
        Container::Archive(zip) => {
            stream.archive(&mut outcome, &zip, None, options)?;
            for split in splits.iter().filter(|s| s.native) {
                match split.source.tolerant() {
                    Ok(zip) => {
                        let id = Some(split.id.as_str());
                        stream.archive(&mut outcome, &zip, id, options)?;
                    }
                    Err(e) => {
                        let error = format!("split {} : illisible ({e:#})", split.id);
                        outcome.errors.push(error);
                    }
                }
            }
        }
    }
    let unmatched = options.elf.as_deref().filter(|_| outcome.elfs.is_empty());
    if let Some(wanted) = unmatched {
        let error = format!("--elf {wanted} : aucun ELF de ce chemin");
        outcome.errors.push(error);
    }
    stream.end(&outcome)?;
    Ok(outcome)
}

/// `<split>!<entrée>` pour un ELF de split, l'entrée sinon.
fn elf_label(split: Option<&str>, path: &str) -> String {
    match split {
        Some(split) => format!("{split}!{path}"),
        None => path.to_string(),
    }
}

fn selected(options: &Options, path: &str, label: &str) -> bool {
    match options.elf.as_deref() {
        Some(wanted) => wanted == path || wanted == label,
        None => true,
    }
}

struct Stream<W: Write> {
    out: W,
    elfs: usize,
}

impl<W: Write> Stream<W> {
    fn begin(mut out: W, sha256: &str, input: &str, options: &Options) -> Result<Self> {
        let limits = Limits {
            min_length: options.min_length,
            max_string_len: MAX_STRING_LEN,
            code_window: CODE_WINDOW,
            max_propagated_array: MAX_PROPAGATED_ARRAY,
            sections_not_scanned: SECTIONS_NOT_SCANNED.split_whitespace().collect(),
        };
        out.write_all(b"{\"sha256\":")?;
        serde_json::to_writer(&mut out, sha256)?;
        field(&mut out, "input", input)?;
        field(&mut out, "options", options)?;
        field(&mut out, "limits", &limits)?;
        out.write_all(b",\"elfs\":[")?;
        Ok(Stream { out, elfs: 0 })
    }

    fn archive(
        &mut self,
        outcome: &mut Outcome,
        zip: &TolerantZip,
        split: Option<&str>,
        options: &Options,
    ) -> Result<()> {
        for (index, entry) in zip.entries().iter().enumerate() {
            let label = elf_label(split, &entry.name);
            let bytes = match zip.read(index) {
                Ok(bytes) => bytes,
                Err(e) => {
                    let error = format!("{label}: entrée illisible ({e:#})");
                    outcome.errors.push(error);
                    continue;
                }
            };
            if !bytes.starts_with(ELF_MAGIC) {
                continue;
            }
            if !selected(options, &entry.name, &label) {
                outcome.not_selected.push(label);
                continue;
            }
            self.elf(outcome, &entry.name, split, &bytes, options)?;
        }
        Ok(())
    }

    fn elf(
        &mut self,
        outcome: &mut Outcome,
        path: &str,
        split: Option<&str>,
        bytes: &[u8],
        options: &Options,
    ) -> Result<()> {
        let elf = analyze_guarded(path, split, bytes, options);
        let out = &mut self.out;
        if self.elfs > 0 {
            out.write_all(b",")?;
        }
        self.elfs += 1;
        out.write_all(b"\n{\"elf\":")?;
        serde_json::to_writer(&mut *out, &elf.path)?;
        field(out, "split", &elf.split)?;
        field(out, "elf_sha256", &elf.sha256)?;
        field(out, "machine", &elf.machine)?;
        field(out, "summary", &elf.summary)?;
        out.write_all(b",\"strings\":[")?;
        for (index, found) in elf.strings.iter().enumerate() {
            if index > 0 {
                out.write_all(b",")?;
            }
            out.write_all(b"\n")?;
            serde_json::to_writer(&mut *out, &elf.row(found, options))?;
        }
        out.write_all(b"\n]")?;
        if let Some(crates) = &elf.crates {
            field(out, "crates", crates)?;
        }
        if let Some(libraries) = &elf.c_libraries {
            field(out, "c_libraries", libraries)?;
        }
        field(out, "crypto_constants", &elf.crypto_rows(options))?;
        out.write_all(b",\"format_arrays\":[")?;
        let arrays = elf.arrays.iter().filter(|a| a.emitted(options));
        for (index, array) in arrays.enumerate() {
            if index > 0 {
                out.write_all(b",")?;
            }
            out.write_all(b"\n")?;
            serde_json::to_writer(&mut *out, &elf.array_row(array, options))?;
        }
        out.write_all(b"\n]")?;
        out.write_all(b"}")?;
        outcome.elfs.push(ElfOutcome {
            label: elf_label(split, path),
            machine: elf.machine,
            summary: elf.summary,
        });
        Ok(())
    }

    fn end(mut self, outcome: &Outcome) -> Result<()> {
        self.out.write_all(b"\n]")?;
        field(&mut self.out, "elfs_not_selected", &outcome.not_selected)?;
        field(&mut self.out, "errors", &outcome.errors)?;
        self.out.write_all(b"}\n")?;
        self.out.flush()?;
        Ok(())
    }
}

fn field<W: Write, T: Serialize + ?Sized>(out: &mut W, key: &str, value: &T) -> Result<()> {
    write!(out, ",\"{key}\":")?;
    serde_json::to_writer(out, value)?;
    Ok(())
}

impl Outcome {
    /// Une ligne `[OK]` ou `[FAIL]` par ELF, `[AVERT]` quand des xrefs demandées
    /// n'ont ni bornes de fonction ni code balayé, `[FAIL]` par erreur.
    pub fn stderr_lines(&self, input: &str) -> Vec<String> {
        let mut lines = Vec::new();
        for elf in &self.elfs {
            lines.extend(elf.stderr_lines());
        }
        if self.elfs.is_empty() && self.not_selected.is_empty() {
            lines.push(format!("[AVERT] {input} — aucun ELF"));
        }
        for error in &self.errors {
            lines.push(format!("[FAIL]  {error}"));
        }
        lines
    }
}

impl ElfOutcome {
    fn stderr_lines(&self) -> Vec<String> {
        let label = &self.label;
        let s = &self.summary;
        let unreadable = s.anomalies.iter().find(|a| a.starts_with(UNREADABLE));
        if let Some(reason) = unreadable {
            return vec![format!("[FAIL]  {label} — {reason}")];
        }
        let emitted = s.strings_emitted;
        let found = s.strings_found;
        let boundaries = joined(&s.by_boundary.pairs());
        let encodings = joined(&s.by_encoding.pairs());
        let symtab = s.functions.symtab;
        let eh_frame = s.functions.eh_frame;
        let mut ok = format!(
            "[OK]    {label} — {emitted} chaînes rendues sur {found} extraites ({boundaries} ; \
             {encodings}), fonctions bornées : symtab {symtab}, eh_frame {eh_frame}"
        );
        let mut warnings = Vec::new();
        if let Some(xrefs) = &s.xrefs {
            let total = xrefs.total;
            let text = xrefs.unresolved_text;
            let non_text = xrefs.non_text_targets;
            let refs = format!(
                ", {total} références, {text} cibles de texte non résolues, {non_text} cibles \
                 hors texte"
            );
            ok.push_str(&refs);
            if symtab == 0 && !s.functions.eh_frame_present {
                warnings.push(format!(
                    "[AVERT] {label} — ni symboles ni .eh_frame : xrefs sans bornes de \
                     fonction, fn_start toujours null"
                ));
            }
            if s.code_scan.is_none() {
                let machine = &self.machine;
                warnings.push(format!(
                    "[AVERT] {label} — machine {machine} : code non balayé, xrefs vides et \
                     aucune borne rust_code"
                ));
            }
        }
        let mut lines = vec![ok];
        lines.extend(warnings);
        lines
    }
}

fn joined(pairs: &[(&str, usize)]) -> String {
    let mut parts = Vec::new();
    for (name, n) in pairs {
        parts.push(format!("{name} {n}"));
    }
    parts.join(", ")
}

/// Une panique devient l'anomalie `elf_unreadable`, jamais un échec du mode.
fn analyze_guarded(path: &str, split: Option<&str>, bytes: &[u8], options: &Options) -> ElfStrings {
    let job = AssertUnwindSafe(|| analyze(path, split, bytes, options));
    match std::panic::catch_unwind(job) {
        Ok(elf) => elf,
        Err(_) => {
            let mut elf = ElfStrings::new(path, split, bytes, options);
            let anomalies = &mut elf.summary.anomalies;
            note(anomalies, UNREADABLE, "panique pendant l'analyse");
            elf
        }
    }
}

fn analyze(path: &str, split: Option<&str>, bytes: &[u8], options: &Options) -> ElfStrings {
    let mut elf = ElfStrings::new(path, split, bytes, options);
    if let Err(e) = elf.fill(bytes, options) {
        note(&mut elf.summary.anomalies, UNREADABLE, e);
    }
    elf
}

impl ElfStrings {
    fn new(path: &str, split: Option<&str>, bytes: &[u8], options: &Options) -> Self {
        let machine = match parse_elf_header(bytes) {
            Some(arch) => arch.machine.label(),
            None => "unknown".to_string(),
        };
        let summary = ElfSummary {
            xrefs: options.xrefs.then(XrefCounts::default),
            ..ElfSummary::default()
        };
        ElfStrings {
            path: path.to_string(),
            split: split.map(str::to_string),
            sha256: format!("{:x}", Sha256::digest(bytes)),
            machine,
            summary,
            areas: Vec::new(),
            strings: Vec::new(),
            arrays: Vec::new(),
            exports: Vec::new(),
            bounds: Bounds::default(),
            crates: None,
            c_libraries: None,
            crypto: Vec::new(),
        }
    }

    fn fill(&mut self, bytes: &[u8], options: &Options) -> object::read::Result<()> {
        let Parsed {
            image,
            dynamic,
            symbols,
            local_symbols,
            anomalies,
            ..
        } = parse_elf(bytes)?;
        let notes = &mut self.summary.anomalies;
        notes.extend(anomalies);
        let tables = match &dynamic {
            Some(entries) => dynamic_relocs(&image, entries, notes),
            None => section_relocs(&image, notes),
        };
        let slots = relocated_slots(&image, &tables, notes);
        let (areas, source) = data_areas(&image);
        let (bounds, functions) = function_bounds(&image, &areas, &symbols, &local_symbols);
        let (mut proven, pairs) = fatptr_strings(&image, &slots, &areas);
        let mut arrays = fatptr_arrays(&image, &areas, &pairs);
        let mut formed = Vec::new();
        let mut code_scan = None;
        if is_aarch64(&image) {
            let (refs, lengths) = scan_code(&image, &slots, &areas, &pairs, &bounds);
            for (at, len) in lengths {
                if proven_text(&image, &areas, at, len).is_some() {
                    proven.push(Proven {
                        vaddr: at,
                        len,
                        boundary: BOUNDARY_CODE,
                    });
                }
            }
            formed = refs;
            code_scan = Some(CODE_SCAN_AARCH64);
        }
        proven.sort_by_key(|p| (p.vaddr, p.len, p.boundary != BOUNDARY_FATPTR));
        proven.dedup_by_key(|p| (p.vaddr, p.len));
        let dropped_prefixes = drop_code_prefixes(&mut proven);
        array_refs(&mut arrays, &formed);
        formed.retain(|f| areas.iter().any(|a| !a.exec && a.contains(f.target)));
        let mut targets: Vec<u64> = formed.iter().map(|f| f.target).collect();
        targets.sort_unstable();
        targets.dedup();
        let min = options.min_length;
        let blocks = extract(&image, &areas, &proven, min, &targets);
        if options.crates {
            self.crates = Some(crates_of(&blocks));
            self.c_libraries = Some(c_libraries_of(&blocks));
        }
        let (mut found, blocks_split, pieces) = split_at_targets(blocks, &targets, min);
        let mut crypto = crypto_hits(&image, &areas, &crypto_constants());
        let unresolved = attribute(&image, &mut found, &mut crypto, &formed, &areas);

        for f in &found {
            self.summary.by_boundary.count(f.boundary);
            self.summary.by_encoding.count(f.encoding);
        }
        let mut total = 0;
        let mut without_function = 0;
        let string_refs = found.iter().flat_map(|f| &f.refs);
        for r in string_refs.chain(crypto.iter().flat_map(|c| &c.refs)) {
            total += 1;
            if bounds.owner(r.insn).is_none() {
                without_function += 1;
            }
        }
        let fatptr_array = attach_array_refs(&mut found, &arrays);
        if let Some(counts) = &mut self.summary.xrefs {
            *counts = XrefCounts {
                total,
                unresolved_text: unresolved.unresolved_text,
                non_text_targets: unresolved.non_text_targets,
                without_function,
                fatptr_array,
            };
        }
        self.summary.strings_found = found.len();
        filter_patterns(&mut found, &options.patterns);
        mark_array_patterns(&mut arrays, &options.patterns);
        self.summary.strings_emitted = found.len();
        self.summary.areas = Some(source);
        self.summary.fatptr_pairs = pairs.len();
        let with_xrefs = arrays.iter().filter(|a| !a.refs.is_empty()).count();
        self.summary.format_arrays = arrays.len();
        let multi = arrays.iter().filter(|a| a.pairs.len() > 1);
        self.summary.pairs_in_arrays = multi.map(|a| a.pairs.len()).sum();
        self.summary.arrays_with_xrefs = with_xrefs;
        self.summary.arrays_without_xrefs = arrays.len() - with_xrefs;
        let referenced = arrays.iter().filter(|a| !a.refs.is_empty());
        self.summary.arrays_not_propagated = referenced.filter(|a| !a.propagated()).count();
        self.summary.rust_code_dropped_prefixes = dropped_prefixes;
        self.summary.blocks_split = blocks_split;
        self.summary.pieces_from_split = pieces;
        self.summary.code_scan = code_scan;
        self.summary.functions = functions;
        self.summary.crypto_constants = crypto.len();
        self.exports = exports(&image, &symbols);
        self.areas = areas;
        self.bounds = bounds;
        self.strings = found;
        self.arrays = arrays;
        self.crypto = crypto;
        Ok(())
    }

    fn row<'s>(&'s self, found: &'s Found, options: &'s Options) -> Row<'s> {
        let area = &self.areas[found.area];
        let names = &options.patterns;
        let patterns = found.patterns.iter().map(|&i| names[i].as_str());
        let pairs = found.places.iter().map(|&(index, rank)| {
            let array = &self.arrays[index];
            PairRow {
                pair_vaddr: hex(array.pairs[rank].slot),
                array_vaddr: hex(array.vaddr),
                array_index: rank,
                array_len: array.pairs.len(),
            }
        });
        Row {
            elf: &self.path,
            elf_sha256: &self.sha256,
            vaddr: hex(found.vaddr),
            file_offset: hex(area.file_offset(found.vaddr)),
            section: area.name.as_deref(),
            length: found.len,
            encoding: found.encoding,
            value: &found.value,
            boundary: found.boundary,
            split_from: found.split_from.map(hex),
            patterns: patterns.collect(),
            pairs: pairs.collect(),
            xrefs: options.xrefs.then(|| self.xref_rows(&found.refs)),
        }
    }

    fn array_row<'s>(&'s self, array: &'s FatArray, options: &'s Options) -> FormatArrayRow<'s> {
        let names = &options.patterns;
        let patterns = array.patterns.iter().map(|&i| names[i].as_str());
        FormatArrayRow {
            array_vaddr: hex(array.vaddr),
            section: array.area.and_then(|a| self.areas[a].name.as_deref()),
            len: array.pairs.len(),
            propagated: array.propagated(),
            pieces: array.pieces.iter().map(String::as_str).collect(),
            patterns: patterns.collect(),
            xrefs: options.xrefs.then(|| self.xref_rows(&array.refs)),
        }
    }

    fn crypto_rows(&self, options: &Options) -> Vec<CryptoRow<'_>> {
        let mut rows = Vec::with_capacity(self.crypto.len());
        for hit in &self.crypto {
            let area = &self.areas[hit.area];
            rows.push(CryptoRow {
                name: hit.name,
                byte_order: hit.byte_order,
                length: hit.length,
                vaddr: hex(hit.vaddr),
                file_offset: hex(area.file_offset(hit.vaddr)),
                section: area.name.as_deref(),
                xrefs: options.xrefs.then(|| self.xref_rows(&hit.refs)),
            });
        }
        rows
    }

    fn xref_rows(&self, refs: &[Ref]) -> Vec<XrefRow<'_>> {
        let mut rows = Vec::with_capacity(refs.len());
        for r in refs {
            rows.push(XrefRow {
                fn_start: self.bounds.owner(r.insn).map(hex),
                insn_addr: hex(r.insn),
                kind: r.kind,
                offset: r.offset,
                nearest_export: nearest_export(&self.exports, r.insn),
                array_vaddr: r.array.map(|(at, _)| hex(at)),
                target_index: r.array.map(|(_, rank)| rank),
            });
        }
        rows
    }
}

fn is_aarch64(image: &Image) -> bool {
    image.machine == elf::EM_AARCH64 && image.ptr_size == 8 && !image.big_endian
}

fn data_areas(image: &Image) -> (Vec<Area>, &'static str) {
    let skipped: Vec<&str> = SECTIONS_NOT_SCANNED.split_whitespace().collect();
    let mut areas = Vec::new();
    for s in &image.sections {
        if !s.has(elf::SHF_ALLOC) || !s.has_file_data() || s.size == 0 {
            continue;
        }
        if image.bytes_at(s.offset, s.size).is_none() {
            continue;
        }
        let exec = s.has(elf::SHF_EXECINSTR);
        let typed = matches!(s.sh_type, elf::SHT_PROGBITS | elf::SHT_STRTAB);
        areas.push(Area {
            name: Some(s.name.clone()),
            vaddr: s.addr,
            offset: s.offset,
            size: s.size,
            read_only: !s.has(elf::SHF_WRITE),
            exec,
            strings: typed && !exec && !skipped.contains(&s.name.as_str()),
        });
    }
    if !areas.is_empty() {
        return (areas, AREAS_SECTIONS);
    }
    for s in &image.segments {
        if s.p_type != elf::PT_LOAD || s.filesz == 0 {
            continue;
        }
        if image.bytes_at(s.offset, s.filesz).is_none() {
            continue;
        }
        let read_only = !s.has(elf::PF_W);
        areas.push(Area {
            name: None,
            vaddr: s.vaddr,
            offset: s.offset,
            size: s.filesz,
            read_only,
            exec: s.has(elf::PF_X),
            strings: read_only,
        });
    }
    (areas, AREAS_SEGMENTS)
}

/// `[at, at + len)` tient dans une zone découpée en chaînes et en lecture
/// seule, et c'est de l'UTF-8 valide sans caractère de contrôle autre que
/// `\t`, `\n`, `\r`.
fn proven_text<'i>(image: &'i Image, areas: &[Area], at: u64, len: u64) -> Option<&'i str> {
    if len == 0 || len > MAX_STRING_LEN {
        return None;
    }
    let area = areas
        .iter()
        .find(|a| a.strings && a.read_only && a.contains(at))?;
    if at.checked_add(len)? > area.end() {
        return None;
    }
    let bytes = image.bytes_at(area.file_offset(at), len)?;
    let text = std::str::from_utf8(bytes).ok()?;
    text.chars().all(is_text_char).then_some(text)
}

fn is_text_char(c: char) -> bool {
    !c.is_control() || matches!(c, '\t' | '\n' | '\r')
}

/// `\t`, `\n`, `\r`, ASCII imprimable, ou octet possible en UTF-8 : 0xC0, 0xC1
/// et 0xF5 à 0xFF n'y figurent jamais.
fn is_string_byte(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | b'\r' | 0x20..=0x7e | 0x80..=0xbf | 0xc2..=0xf4)
}

/// Couples {ptr, len} des données : `ptr` relogé, `len` non relogé et le
/// texte validé par [`proven_text`]. Rend aussi emplacement du couple → `ptr`.
fn fatptr_strings(
    image: &Image,
    slots: &HashMap<u64, u64>,
    areas: &[Area],
) -> (Vec<Proven>, HashMap<u64, u64>) {
    let mut proven = Vec::new();
    let mut pairs = HashMap::new();
    for (&slot, &ptr) in slots {
        let len_at = slot.wrapping_add(image.ptr_size);
        if slots.contains_key(&len_at) {
            continue;
        }
        let Some(len) = image.word_at(len_at) else {
            continue;
        };
        if proven_text(image, areas, ptr, len).is_some() {
            proven.push(Proven {
                vaddr: ptr,
                len,
                boundary: BOUNDARY_FATPTR,
            });
            pairs.insert(slot, ptr);
        }
    }
    (proven, pairs)
}

/// Couples de `pairs` regroupés en tableaux : même zone, emplacements
/// consécutifs au pas de deux mots. Triés par adresse.
fn fatptr_arrays(image: &Image, areas: &[Area], pairs: &HashMap<u64, u64>) -> Vec<FatArray> {
    let stride = 2 * image.ptr_size;
    let mut slots: Vec<(u64, u64)> = pairs.iter().map(|(&slot, &ptr)| (slot, ptr)).collect();
    slots.sort_unstable();
    let mut arrays: Vec<FatArray> = Vec::new();
    for (slot, ptr) in slots {
        let Some(len) = image.word_at(slot.wrapping_add(image.ptr_size)) else {
            continue;
        };
        let Some(text) = proven_text(image, areas, ptr, len) else {
            continue;
        };
        let area = areas.iter().position(|a| a.contains(slot));
        let follows = arrays.last().is_some_and(|a| {
            let last = a.pairs.last().map(|p| p.slot.wrapping_add(stride));
            a.area == area && last == Some(slot)
        });
        if !follows {
            arrays.push(FatArray {
                area,
                vaddr: slot,
                pairs: Vec::new(),
                pieces: Vec::new(),
                patterns: Vec::new(),
                refs: Vec::new(),
            });
        }
        if let Some(array) = arrays.last_mut() {
            array.pairs.push(FatPair { slot, ptr, len });
            array.pieces.push(text.to_string());
        }
    }
    arrays
}

/// Rattache à son tableau chaque adresse formée sur l'emplacement d'un couple.
fn array_refs(arrays: &mut [FatArray], formed: &[Formed]) {
    let mut rank_of: HashMap<u64, (usize, usize)> = HashMap::new();
    for (index, array) in arrays.iter().enumerate() {
        for (rank, pair) in array.pairs.iter().enumerate() {
            rank_of.insert(pair.slot, (index, rank));
        }
    }
    for f in formed {
        let Some(&(index, rank)) = f.pair.and_then(|slot| rank_of.get(&slot)) else {
            continue;
        };
        let array = &mut arrays[index];
        let vaddr = array.vaddr;
        array.refs.push(Ref {
            insn: f.insn,
            kind: KIND_FATPTR_ARRAY,
            offset: 0,
            array: Some((vaddr, rank)),
        });
    }
}

/// Pose sur chaque chaîne rust_fatptr tous ses couples, et les références de
/// ceux de ses tableaux qui sont propagés, sauf instruction déjà rattachée à
/// la chaîne. Rend le nombre de références posées.
fn attach_array_refs(found: &mut [Found], arrays: &[FatArray]) -> usize {
    let mut places: HashMap<(u64, u64), Vec<(usize, usize)>> = HashMap::new();
    for (index, array) in arrays.iter().enumerate() {
        for (rank, pair) in array.pairs.iter().enumerate() {
            let key = (pair.ptr, pair.len);
            places.entry(key).or_default().push((index, rank));
        }
    }
    let mut added = 0;
    for f in found.iter_mut().filter(|f| f.boundary == BOUNDARY_FATPTR) {
        let Some(at) = places.get(&(f.vaddr, f.len)) else {
            continue;
        };
        f.places = at.clone();
        let mut seen: HashSet<u64> = f.refs.iter().map(|r| r.insn).collect();
        for &(index, _) in at {
            let array = &arrays[index];
            if !array.propagated() {
                continue;
            }
            for r in &array.refs {
                if seen.insert(r.insn) {
                    f.refs.push(*r);
                    added += 1;
                }
            }
        }
    }
    added
}

/// Motifs contenus dans au moins un morceau de chaque tableau.
fn mark_array_patterns(arrays: &mut [FatArray], patterns: &[String]) {
    if patterns.is_empty() {
        return;
    }
    let needles: Vec<String> = patterns.iter().map(|p| p.to_lowercase()).collect();
    for array in arrays {
        let pieces: Vec<String> = array.pieces.iter().map(|p| p.to_lowercase()).collect();
        for (index, needle) in needles.iter().enumerate() {
            if pieces.iter().any(|p| p.contains(needle.as_str())) {
                array.patterns.push(index);
            }
        }
    }
}

struct Piece<'a> {
    at: usize,
    text: &'a str,
    nul: bool,
}

impl Piece<'_> {
    fn found(&self, area: usize, base: u64) -> Found {
        let vaddr = base + self.at as u64;
        let len = self.text.len() as u64;
        let value = self.text.to_string();
        Found::new(area, vaddr, len, value, boundary_of(self.nul))
    }
}

fn boundary_of(nul: bool) -> &'static str {
    if nul {
        BOUNDARY_NUL
    } else {
        BOUNDARY_HEURISTIC
    }
}

/// Chaînes de chaque zone découpée : plages prouvées d'abord, puis texte des
/// octets qu'elles ne couvrent pas, puis UTF-16LE. Triées par adresse. Un bloc
/// nul ou heuristic plus court que `min_length` est gardé s'il contient une
/// cible : [`split_at_targets`] en tranche.
fn extract(
    image: &Image,
    areas: &[Area],
    proven: &[Proven],
    min_length: usize,
    targets: &[u64],
) -> Vec<Found> {
    let mut found = Vec::new();
    for (index, area) in areas.iter().enumerate() {
        if !area.strings {
            continue;
        }
        let Some(data) = image.bytes_at(area.offset, area.size) else {
            continue;
        };
        let mut keep = |f: Found| {
            let interior = !is_proven(f.boundary) && has_interior(targets, f.vaddr, f.len);
            if interior || f.value.chars().count() >= min_length {
                found.push(f);
            }
        };
        let first = proven.partition_point(|p| p.vaddr < area.vaddr);
        let mut from = 0;
        for p in proven[first..].iter().take_while(|p| p.vaddr < area.end()) {
            let start = (p.vaddr - area.vaddr) as usize;
            let end = start.saturating_add(p.len as usize);
            let text = match data.get(start..end).map(std::str::from_utf8) {
                Some(Ok(text)) => text,
                _ => continue,
            };
            if start > from {
                for piece in text_pieces(data, from, start) {
                    keep(piece.found(index, area.vaddr));
                }
            }
            from = from.max(end);
            let f = Found::new(index, p.vaddr, p.len, text.to_string(), p.boundary);
            keep(f);
        }
        for piece in text_pieces(data, from, data.len()) {
            keep(piece.found(index, area.vaddr));
        }
        for (at, value, nul) in utf16_pieces(data, min_length) {
            let len = 2 * value.len() as u64;
            let mut f = Found::new(index, area.vaddr + at as u64, len, value, boundary_of(nul));
            f.encoding = ENCODING_UTF16LE;
            keep(f);
        }
    }
    found.sort_by_key(|f| (f.vaddr, f.len));
    found
}

/// Suites d'octets de texte de `data[from..to]`, coupées en pièces UTF-8
/// valides ; `nul` pour la dernière pièce d'une suite suivie d'un octet nul.
fn text_pieces(data: &[u8], from: usize, to: usize) -> Vec<Piece<'_>> {
    let mut pieces = Vec::new();
    let mut i = from;
    while i < to {
        if !is_string_byte(data[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < to && is_string_byte(data[i]) {
            i += 1;
        }
        let nul = i < to && data[i] == 0;
        let chunks: Vec<_> = data[start..i].utf8_chunks().collect();
        let mut at = start;
        for (k, chunk) in chunks.iter().enumerate() {
            let text = chunk.valid();
            let last = k + 1 == chunks.len() && chunk.invalid().is_empty();
            if !text.is_empty() {
                pieces.push(Piece {
                    at,
                    text,
                    nul: nul && last,
                });
            }
            at += text.len() + chunk.invalid().len();
        }
    }
    pieces
}

/// Suites d'au moins `min_length` unités UTF-16LE de code ASCII imprimable,
/// `\t`, `\n` ou `\r` : (position, texte, suivie de `00 00`). Une suite qui suit
/// un octet de texte perd sa première unité : c'est la fin `x 00` d'une chaîne
/// ASCII.
fn utf16_pieces(data: &[u8], min_length: usize) -> Vec<(usize, String, bool)> {
    let mut pieces = Vec::new();
    let mut i = 0;
    while i + 1 < data.len() {
        if !is_utf16_unit(data, i) {
            i += 1;
            continue;
        }
        let mut start = i;
        while is_utf16_unit(data, i) {
            i += 2;
        }
        if start > 0 && is_string_byte(data[start - 1]) {
            start += 2;
        }
        if (i - start) / 2 >= min_length {
            let text = data[start..i].iter().step_by(2).map(|&b| char::from(b));
            let nul = data.get(i..i + 2) == Some(&[0, 0][..]);
            pieces.push((start, text.collect(), nul));
        }
    }
    pieces
}

fn is_utf16_unit(data: &[u8], i: usize) -> bool {
    match data.get(i..i + 2) {
        Some(&[low, 0]) => matches!(low, b'\t' | b'\n' | b'\r' | 0x20..=0x7e),
        _ => false,
    }
}

fn is_proven(boundary: &str) -> bool {
    boundary == BOUNDARY_FATPTR || boundary == BOUNDARY_CODE
}

/// Écarte chaque rust_code qu'un intervalle prouvé plus long prolonge depuis la
/// même adresse. `proven` trié par adresse ; rend le nombre d'écartés.
fn drop_code_prefixes(proven: &mut Vec<Proven>) -> usize {
    let mut longest: HashMap<u64, u64> = HashMap::new();
    for p in proven.iter() {
        let len = longest.entry(p.vaddr).or_insert(p.len);
        *len = (*len).max(p.len);
    }
    let before = proven.len();
    proven.retain(|p| p.boundary != BOUNDARY_CODE || longest.get(&p.vaddr) == Some(&p.len));
    before - proven.len()
}

/// Une cible tombe strictement à l'intérieur de `[vaddr, vaddr + len)`.
fn has_interior(targets: &[u64], vaddr: u64, len: u64) -> bool {
    let index = targets.partition_point(|&t| t <= vaddr);
    targets.get(index).is_some_and(|&t| t < vaddr + len)
}

/// Coupe chaque bloc nul ou heuristic aux cibles qui tombent strictement à
/// l'intérieur. Un morceau plus court que `min_length` n'est gardé que s'il
/// commence à une cible. Rend aussi le nombre de blocs coupés et de morceaux
/// gardés.
fn split_at_targets(
    found: Vec<Found>,
    targets: &[u64],
    min_length: usize,
) -> (Vec<Found>, usize, usize) {
    let mut out = Vec::with_capacity(found.len());
    let mut blocks = 0;
    let mut pieces = 0;
    for f in found {
        if is_proven(f.boundary) {
            out.push(f);
            continue;
        }
        let cuts = f.cuts(targets);
        if cuts.is_empty() {
            if kept(&f, targets, min_length) {
                out.push(f);
            }
            continue;
        }
        blocks += 1;
        for piece in f.split(&cuts) {
            if kept(&piece, targets, min_length) {
                pieces += 1;
                out.push(piece);
            }
        }
    }
    out.sort_by_key(|f| (f.vaddr, f.len));
    (out, blocks, pieces)
}

fn kept(f: &Found, targets: &[u64], min_length: usize) -> bool {
    targets.binary_search(&f.vaddr).is_ok() || f.value.chars().count() >= min_length
}

/// Rattache chaque adresse formée aux constantes et aux chaînes qui commencent
/// à cette adresse ou, à défaut, aux chaînes qui la contiennent. Compte les
/// adresses qui tombent dans une zone de chaînes en lecture seule sans rien y
/// désigner, selon l'octet visé.
fn attribute(
    image: &Image,
    found: &mut [Found],
    crypto: &mut [CryptoHit],
    formed: &[Formed],
    areas: &[Area],
) -> TargetCounts {
    let mut starts: HashMap<u64, Vec<usize>> = HashMap::new();
    for (index, f) in found.iter().enumerate() {
        starts.entry(f.vaddr).or_default().push(index);
    }
    let mut reach = Vec::with_capacity(found.len());
    let mut furthest = 0u64;
    for f in found.iter() {
        furthest = furthest.max(f.vaddr + f.len);
        reach.push(furthest);
    }
    let mut constants: HashMap<u64, Vec<usize>> = HashMap::new();
    for (index, hit) in crypto.iter().enumerate() {
        constants.entry(hit.vaddr).or_default().push(index);
    }
    let mut counts = TargetCounts::default();
    for f in formed {
        let reference = |offset| Ref {
            insn: f.insn,
            kind: f.kind,
            offset,
            array: None,
        };
        let mut hit = false;
        for &i in constants.get(&f.target).into_iter().flatten() {
            crypto[i].refs.push(reference(0));
            hit = true;
        }
        if let Some(indices) = starts.get(&f.target) {
            for &i in indices {
                found[i].refs.push(reference(0));
            }
            hit = true;
        } else {
            for i in covering(found, &reach, f.target) {
                let offset = f.target - found[i].vaddr;
                found[i].refs.push(reference(offset));
                hit = true;
            }
        }
        if hit {
            continue;
        }
        let area = areas
            .iter()
            .find(|a| a.strings && a.read_only && a.contains(f.target));
        let byte = area.and_then(|a| image.bytes_at(a.file_offset(f.target), 1));
        match byte {
            Some(&[b]) if is_string_byte(b) => counts.unresolved_text += 1,
            Some(_) => counts.non_text_targets += 1,
            None => {}
        }
    }
    counts
}

/// Chaînes qui contiennent `at` sans y commencer. `found` trié par adresse ;
/// `reach[k]` : fin la plus lointaine de `found[..=k]`.
fn covering(found: &[Found], reach: &[u64], at: u64) -> Vec<usize> {
    let mut covers = Vec::new();
    let mut k = found.partition_point(|f| f.vaddr < at);
    while k > 0 && reach[k - 1] > at {
        k -= 1;
        if at < found[k].vaddr + found[k].len {
            covers.push(k);
        }
    }
    covers
}

fn filter_patterns(found: &mut Vec<Found>, patterns: &[String]) {
    if patterns.is_empty() {
        return;
    }
    let needles: Vec<String> = patterns.iter().map(|p| p.to_lowercase()).collect();
    found.retain_mut(|f| {
        let value = f.value.to_lowercase();
        for (index, needle) in needles.iter().enumerate() {
            if value.contains(needle.as_str()) {
                f.patterns.push(index);
            }
        }
        !f.patterns.is_empty()
    });
}

fn exports(image: &Image, symbols: &[DynSymbol]) -> Vec<(u64, String)> {
    let arm = image.machine == elf::EM_ARM;
    let mut exports = Vec::new();
    for sym in symbols {
        let exported = matches!(sym.bind, elf::STB_GLOBAL | elf::STB_WEAK);
        if !sym.defined || !sym.func || sym.value == 0 || !exported {
            continue;
        }
        let value = if arm { sym.value & !1 } else { sym.value };
        exports.push((value, sym.name.clone()));
    }
    exports.sort();
    exports
}

fn nearest_export(exports: &[(u64, String)], at: u64) -> Option<NearestExport<'_>> {
    let index = exports.partition_point(|(value, _)| *value <= at);
    let (value, name) = exports.get(index.checked_sub(1)?)?;
    Some(NearestExport {
        name,
        distance: at - value,
    })
}

// ---------------------------------------------------------------------------
// Bornes de fonction : symboles, puis FDE de .eh_frame.

struct EhFrame {
    present: bool,
    fdes: Vec<(u64, u64)>,
    unread: usize,
}

fn function_bounds(
    image: &Image,
    areas: &[Area],
    symbols: &[DynSymbol],
    local_symbols: &[DynSymbol],
) -> (Bounds, FunctionCounts) {
    let arm = image.machine == elf::EM_ARM;
    let mut entries = Vec::new();
    for sym in symbols.iter().chain(local_symbols) {
        if !sym.defined || !sym.func || sym.value == 0 {
            continue;
        }
        let start = if arm { sym.value & !1 } else { sym.value };
        let end = (sym.size > 0).then_some(start.saturating_add(sym.size));
        entries.push(FnBound {
            start,
            end,
            source: SOURCE_SYMTAB,
        });
    }
    let eh = eh_frame_fdes(image, areas);
    for &(start, end) in &eh.fdes {
        entries.push(FnBound {
            start,
            end: Some(end),
            source: SOURCE_EH_FRAME,
        });
    }
    entries.sort_by_key(|e| (e.start, e.source != SOURCE_SYMTAB));
    entries.dedup_by(|later, kept| {
        if later.start != kept.start {
            return false;
        }
        if kept.end.is_none() {
            kept.end = later.end;
        }
        true
    });
    let symtab = entries.iter().filter(|e| e.source == SOURCE_SYMTAB).count();
    let counts = FunctionCounts {
        symtab,
        eh_frame: entries.len() - symtab,
        eh_frame_present: eh.present,
        eh_frame_unread: eh.unread,
    };
    (Bounds { entries }, counts)
}

fn eh_frame_fdes(image: &Image, areas: &[Area]) -> EhFrame {
    let section = areas
        .iter()
        .find(|a| a.name.as_deref() == Some(".eh_frame"));
    let located = match section {
        Some(a) => image
            .bytes_at(a.offset, a.size)
            .map(|bytes| (a.vaddr, bytes)),
        None => eh_frame_from_header(image),
    };
    let Some((vaddr, bytes)) = located else {
        return EhFrame {
            present: false,
            fdes: Vec::new(),
            unread: 0,
        };
    };
    let (mut fdes, mut unread) = parse_eh_frame(image, vaddr, bytes);
    let before = fdes.len();
    fdes.retain(|&(start, _)| image.is_exec(start));
    unread += before - fdes.len();
    EhFrame {
        present: true,
        fdes,
        unread,
    }
}

/// `.eh_frame` désigné par `PT_GNU_EH_FRAME`, lu jusqu'à la fin de son segment
/// LOAD.
fn eh_frame_from_header<'i>(image: &'i Image) -> Option<(u64, &'i [u8])> {
    let header = image
        .segments
        .iter()
        .find(|s| s.p_type == elf::PT_GNU_EH_FRAME)?;
    let bytes = image.bytes_at(header.offset, header.filesz)?;
    let mut reader = Reader::new(image, header.vaddr, bytes);
    if reader.uint(1)? != 1 {
        return None;
    }
    let encoding = reader.uint(1)? as u8;
    reader.take(2)?;
    let at = reader.encoded(encoding)?;
    let load = image
        .segments
        .iter()
        .find(|s| s.p_type == elf::PT_LOAD && s.in_file(at))?;
    let start = load.offset.checked_add(at - load.vaddr)?;
    let size = load.filesz - (at - load.vaddr);
    Some((at, image.bytes_at(start, size)?))
}

/// FDE de `.eh_frame` : (début, fin) de chaque fonction décrite, et nombre de
/// FDE illisibles (CIE introuvable, codage d'adresse non modélisé).
fn parse_eh_frame(image: &Image, vaddr: u64, bytes: &[u8]) -> (Vec<(u64, u64)>, usize) {
    let mut fdes = Vec::new();
    let mut unread = 0;
    let mut cies: HashMap<usize, Option<u8>> = HashMap::new();
    let mut reader = Reader::new(image, vaddr, bytes);
    while reader.pos < bytes.len() {
        let record = reader.pos;
        let length = match reader.uint(4) {
            Some(0) | None => break,
            Some(0xffff_ffff) => match reader.uint(8) {
                Some(length) => length,
                None => break,
            },
            Some(length) => length,
        };
        let body = reader.pos;
        let end = usize::try_from(length).ok();
        let end = end.and_then(|n| body.checked_add(n));
        let Some(end) = end.filter(|&end| end <= bytes.len()) else {
            break;
        };
        match reader.uint(4) {
            Some(0) => {
                cies.insert(record, cie_encoding(&mut reader));
            }
            Some(back) => {
                let cie = body.checked_sub(back as usize);
                let encoding = cie.and_then(|at| cies.get(&at).copied().flatten());
                match encoding.and_then(|e| fde_range(&mut reader, e)) {
                    Some(range) => fdes.push(range),
                    None => unread += 1,
                }
            }
            None => break,
        }
        reader.pos = end;
    }
    (fdes, unread)
}

/// Codage des adresses des FDE d'une CIE (`R` de l'augmentation, absptr par
/// défaut) ; `None` si l'augmentation n'est pas lisible.
fn cie_encoding(reader: &mut Reader) -> Option<u8> {
    let version = reader.uint(1)?;
    let augmentation = reader.cstr()?;
    if augmentation.windows(2).any(|w| w == b"eh") {
        return None;
    }
    reader.leb(false)?;
    reader.leb(true)?;
    if version == 1 {
        reader.uint(1)?;
    } else {
        reader.leb(false)?;
    }
    let Some(letters) = augmentation.strip_prefix(b"z") else {
        return augmentation.is_empty().then_some(0);
    };
    reader.leb(false)?;
    let mut encoding = 0;
    for &letter in letters {
        match letter {
            b'R' => encoding = reader.uint(1)? as u8,
            b'P' => {
                let personality = reader.uint(1)? as u8;
                reader.encoded(personality & 0x0f)?;
            }
            b'L' => {
                reader.uint(1)?;
            }
            b'S' | b'B' | b'G' => {}
            _ => return None,
        }
    }
    Some(encoding)
}

fn fde_range(reader: &mut Reader, encoding: u8) -> Option<(u64, u64)> {
    let start = reader.encoded(encoding)?;
    let len = reader.encoded(encoding & 0x0f)?;
    let end = start.checked_add(len)?;
    (end > start).then_some((start, end))
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    /// Adresse virtuelle de `bytes[0]`.
    vaddr: u64,
    ptr_size: u64,
    big_endian: bool,
}

impl<'a> Reader<'a> {
    fn new(image: &Image, vaddr: u64, bytes: &'a [u8]) -> Self {
        Reader {
            bytes,
            pos: 0,
            vaddr,
            ptr_size: image.ptr_size,
            big_endian: image.big_endian,
        }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let bytes = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(bytes)
    }

    fn uint(&mut self, n: usize) -> Option<u64> {
        let bytes = self.take(n)?;
        let mut value = 0u64;
        if self.big_endian {
            for &b in bytes {
                value = (value << 8) | u64::from(b);
            }
        } else {
            for &b in bytes.iter().rev() {
                value = (value << 8) | u64::from(b);
            }
        }
        Some(value)
    }

    fn leb(&mut self, signed: bool) -> Option<u64> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.uint(1)?;
            if shift < 64 {
                value |= (byte & 0x7f) << shift;
            }
            shift = shift.saturating_add(7);
            if byte & 0x80 == 0 {
                if signed && shift < 64 && byte & 0x40 != 0 {
                    value |= u64::MAX << shift;
                }
                return Some(value);
            }
        }
    }

    fn cstr(&mut self) -> Option<&'a [u8]> {
        let rest = self.bytes.get(self.pos..)?;
        let len = rest.iter().position(|&b| b == 0)?;
        self.pos += len + 1;
        Some(&rest[..len])
    }

    /// Valeur codée `DW_EH_PE_*` : formats absptr, uleb128, udata2/4/8,
    /// sleb128, sdata2/4/8 ; application absolue ou relative à l'adresse du
    /// champ. `None` pour le reste, indirection et omission comprises.
    fn encoded(&mut self, encoding: u8) -> Option<u64> {
        if encoding & 0x80 != 0 {
            return None;
        }
        let at = self.vaddr.wrapping_add(self.pos as u64);
        let value = match encoding & 0x0f {
            0x00 => self.uint(self.ptr_size as usize)?,
            0x01 => self.leb(false)?,
            0x02 => self.uint(2)?,
            0x03 => self.uint(4)?,
            0x04 | 0x0c => self.uint(8)?,
            0x09 => self.leb(true)?,
            0x0a => self.uint(2)? as i16 as u64,
            0x0b => self.uint(4)? as i32 as u64,
            _ => return None,
        };
        match encoding & 0x70 {
            0x00 => Some(value),
            0x10 => Some(at.wrapping_add(value)),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Balayage linéaire du code AArch64.

#[derive(Clone, Copy)]
enum Held {
    Page(u64),
    Addr(u64),
    Imm(u64),
}

#[derive(Clone, Copy)]
struct Slot {
    base: u32,
    offset: i64,
    held: Held,
    at: usize,
}

impl Slot {
    fn is(&self, base: u32, offset: i64) -> bool {
        self.base == base && self.offset == offset
    }
}

/// Valeur suivie de chaque registre et index de l'instruction qui l'a posée,
/// derniers emplacements mémoire écrits.
struct Sweep {
    regs: [Option<(Held, usize)>; 32],
    stores: Vec<Slot>,
    index: usize,
    formed: Vec<Formed>,
    /// Couples (adresse, longueur immédiate) candidats à rust_code.
    lengths: Vec<(u64, u64)>,
}

/// Toutes les zones exécutables, quatre octets par quatre octets : adresses
/// formées et couples (adresse, longueur) candidats.
fn scan_code(
    image: &Image,
    slots: &HashMap<u64, u64>,
    areas: &[Area],
    pairs: &HashMap<u64, u64>,
    bounds: &Bounds,
) -> (Vec<Formed>, Vec<(u64, u64)>) {
    let mut sweep = Sweep::new();
    let starts = &bounds.entries;
    for area in areas.iter().filter(|a| a.exec) {
        let Some(code) = image.bytes_at(area.offset, area.size) else {
            continue;
        };
        let aligned = area.vaddr.checked_next_multiple_of(4).unwrap_or(u64::MAX);
        let skip = aligned.saturating_sub(area.vaddr);
        let Some(code) = code.get(skip as usize..) else {
            continue;
        };
        let mut next = starts.partition_point(|e| e.start < aligned);
        sweep.reset();
        for (i, word) in code.as_chunks::<4>().0.iter().enumerate() {
            let pc = aligned + 4 * i as u64;
            while starts.get(next).is_some_and(|e| e.start < pc) {
                next += 1;
            }
            if starts.get(next).is_some_and(|e| e.start == pc) {
                sweep.reset();
            }
            sweep.index += 1;
            sweep.step(pc, u32::from_le_bytes(*word), image, slots, pairs);
        }
    }
    (sweep.formed, sweep.lengths)
}

impl Sweep {
    fn new() -> Self {
        Sweep {
            regs: [None; 32],
            stores: Vec::new(),
            index: 0,
            formed: Vec::new(),
            lengths: Vec::new(),
        }
    }

    fn reset(&mut self) {
        self.regs = [None; 32];
        self.stores.clear();
    }

    fn get(&self, reg: u32) -> Option<Held> {
        let (held, at) = self.regs.get(reg as usize).copied().flatten()?;
        (self.index - at <= CODE_WINDOW).then_some(held)
    }

    /// Registre 31 (sp ou xzr) jamais suivi.
    fn put(&mut self, reg: u32, held: Option<Held>) {
        if reg >= 31 {
            return;
        }
        self.regs[reg as usize] = held.map(|h| (h, self.index));
        match held {
            Some(Held::Addr(_)) => self.pair(reg, reg + 1),
            Some(Held::Imm(_)) if reg > 0 => self.pair(reg - 1, reg),
            _ => {}
        }
    }

    fn pair(&mut self, ptr: u32, len: u32) {
        if let (Some(Held::Addr(at)), Some(Held::Imm(n))) = (self.get(ptr), self.get(len)) {
            self.lengths.push((at, n));
        }
    }

    fn clobber_call(&mut self) {
        self.regs[..19].fill(None);
        self.regs[30] = None;
    }

    fn forget_base(&mut self, base: u32) {
        self.stores.retain(|s| s.base != base);
        self.put(base, None);
    }

    /// `reg` rangé à `[base, #offset]` : une adresse et une longueur rangées à
    /// huit octets d'écart forment un couple, comme dans deux registres
    /// consécutifs.
    fn store(&mut self, base: u32, offset: i64, reg: u32) {
        let now = self.index;
        self.stores.retain(|s| now - s.at <= CODE_WINDOW);
        self.stores.retain(|s| !s.is(base, offset));
        let held = match self.get(reg) {
            Some(held) => held,
            None => return,
        };
        let partner = |delta: i64| {
            let at = offset.wrapping_add(delta);
            self.stores.iter().find(|s| s.is(base, at)).map(|s| s.held)
        };
        let pair = match (held, partner(8), partner(-8)) {
            (Held::Addr(at), Some(Held::Imm(n)), _) => Some((at, n)),
            (Held::Imm(n), _, Some(Held::Addr(at))) => Some((at, n)),
            _ => None,
        };
        self.lengths.extend(pair);
        self.stores.push(Slot {
            base,
            offset,
            held,
            at: now,
        });
    }

    fn address(
        &mut self,
        pc: u64,
        rd: u32,
        target: u64,
        kind: &'static str,
        pairs: &HashMap<u64, u64>,
    ) {
        let formed = match pairs.get(&target) {
            Some(&string) => Formed {
                insn: pc,
                target: string,
                kind: KIND_FATPTR,
                pair: Some(target),
            },
            None => Formed {
                insn: pc,
                target,
                kind,
                pair: None,
            },
        };
        self.formed.push(formed);
        self.put(rd, Some(Held::Addr(target)));
    }

    fn step(
        &mut self,
        pc: u64,
        w: u32,
        image: &Image,
        slots: &HashMap<u64, u64>,
        pairs: &HashMap<u64, u64>,
    ) {
        let rd = w & 31;
        let rn = (w >> 5) & 31;
        if w & 0x9f00_0000 == 0x9000_0000 {
            let page = (pc & !0xfff).wrapping_add_signed(adr_offset(w) << 12);
            self.put(rd, Some(Held::Page(page)));
        } else if w & 0x9f00_0000 == 0x1000_0000 {
            let target = pc.wrapping_add_signed(adr_offset(w));
            self.address(pc, rd, target, KIND_ADR, pairs);
        } else if w & 0xff80_0000 == 0x9100_0000 {
            let shift = if w & (1 << 22) != 0 { 12 } else { 0 };
            let imm = u64::from((w >> 10) & 0xfff) << shift;
            match self.get(rn) {
                Some(Held::Page(page)) => {
                    let target = page.wrapping_add(imm);
                    self.address(pc, rd, target, KIND_ADRP_ADD, pairs);
                }
                _ => self.put(rd, None),
            }
        } else if w & 0xff00_0000 == 0x5800_0000 {
            let words = sext(u64::from((w >> 5) & 0x7ffff), 19);
            let at = pc.wrapping_add_signed(words * 4);
            match pointer(image, slots, at) {
                Some(value) => self.address(pc, rd, value, KIND_LDR_LITERAL, pairs),
                None => self.put(rd, None),
            }
        } else if w & 0xffc0_0000 == 0xf940_0000 {
            let offset = u64::from((w >> 10) & 0xfff) * 8;
            if let Some(Held::Page(page)) = self.get(rn) {
                let slot = page.wrapping_add(offset);
                if let Some(&target) = pairs.get(&slot) {
                    self.formed.push(Formed {
                        insn: pc,
                        target,
                        kind: KIND_FATPTR,
                        pair: Some(slot),
                    });
                }
            }
            self.put(rd, None);
        } else if w & 0x7f80_0000 == 0x5280_0000 {
            let hw = (w >> 21) & 3;
            let value = u64::from((w >> 5) & 0xffff) << (16 * hw);
            self.put(rd, Some(Held::Imm(value)));
        } else if w & 0x7f80_0000 == 0x3200_0000 && rn == 31 {
            self.put(rd, bitmask_imm(w).map(Held::Imm));
        } else if let Some((base, offset)) = str_x(w) {
            self.store(base, offset, rd);
        } else if let Some((base, offset)) = stp_x(w) {
            self.store(base, offset, rd);
            self.store(base, offset + 8, (w >> 10) & 31);
        } else {
            self.other(w);
        }
    }

    fn other(&mut self, w: u32) {
        let rd = w & 31;
        if w & 0x1c00_0000 == 0x1400_0000 {
            self.branch(w);
        } else if w & 0x0a00_0000 == 0x0800_0000 {
            self.load_or_store(w);
        } else {
            if w & 0x3f80_0000 == 0x1100_0000 && rd == 31 {
                self.forget_base(31);
            }
            self.put(rd, None);
        }
    }

    fn branch(&mut self, w: u32) {
        let opcode = w & 0xfc00_0000;
        let register = w & 0xffff_fc1f;
        if opcode == 0x1400_0000 || register == 0xd61f_0000 || register == 0xd65f_0000 {
            self.reset();
        } else if opcode == 0x9400_0000 || register == 0xd63f_0000 {
            self.clobber_call();
        } else if w & 0xfff0_0000 == 0xd530_0000 {
            self.put(w & 31, None);
        }
    }

    fn load_or_store(&mut self, w: u32) {
        let pair = w & 0x3800_0000 == 0x2800_0000;
        let single = w & 0x3800_0000 == 0x3800_0000 && w & (1 << 24) == 0;
        let pair_writeback = pair && w & (1 << 23) != 0;
        let single_writeback = single && w & 0x0020_0400 == 0x0000_0400;
        if pair_writeback || single_writeback {
            self.forget_base((w >> 5) & 31);
        }
        let load = if pair {
            w & (1 << 22) != 0
        } else {
            w & 0x00c0_0000 != 0
        };
        if load {
            self.put(w & 31, None);
            if pair {
                self.put((w >> 10) & 31, None);
            }
        }
    }
}

fn sext(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

/// Immédiat signé d'ADR ou d'ADRP, en octets ou en pages.
fn adr_offset(w: u32) -> i64 {
    let immhi = u64::from((w >> 5) & 0x7ffff);
    let immlo = u64::from((w >> 29) & 3);
    sext((immhi << 2) | immlo, 21)
}

/// `str xT, [xN, #imm]` ou `stur xT, [xN, #simm]` : (N, décalage).
fn str_x(w: u32) -> Option<(u32, i64)> {
    let base = (w >> 5) & 31;
    if w & 0xffc0_0000 == 0xf900_0000 {
        Some((base, i64::from((w >> 10) & 0xfff) * 8))
    } else if w & 0xffe0_0c00 == 0xf800_0000 {
        Some((base, sext(u64::from((w >> 12) & 0x1ff), 9)))
    } else {
        None
    }
}

/// `stp xT, xT2, [xN, #imm]` sans écriture de la base : (N, décalage).
fn stp_x(w: u32) -> Option<(u32, i64)> {
    if w & 0xffc0_0000 != 0xa900_0000 {
        return None;
    }
    let base = (w >> 5) & 31;
    Some((base, sext(u64::from((w >> 15) & 0x7f), 7) * 8))
}

/// Immédiat logique d'ORR (DecodeBitMasks de l'architecture ARMv8-A).
fn bitmask_imm(w: u32) -> Option<u64> {
    let wide = w >> 31 == 1;
    let n = (w >> 22) & 1;
    let immr = (w >> 16) & 0x3f;
    let imms = (w >> 10) & 0x3f;
    if !wide && n == 1 {
        return None;
    }
    let combined = (n << 6) | (!imms & 0x3f);
    if combined < 2 {
        return None;
    }
    let size = 1u32 << (31 - combined.leading_zeros());
    let levels = size - 1;
    let s = imms & levels;
    let r = immr & levels;
    if s == levels {
        return None;
    }
    let mask = u64::MAX >> (64 - size);
    let ones = (1u64 << (s + 1)) - 1;
    let element = if r == 0 {
        ones
    } else {
        ((ones >> r) | (ones << (size - r))) & mask
    };
    let mut value = 0u64;
    let mut at = 0;
    while at < 64 {
        value |= element << at;
        at += size;
    }
    Some(if wide { value } else { value & 0xffff_ffff })
}

// ---------------------------------------------------------------------------
// Crates Rust et bibliothèques C.

type CrateKey = (String, Option<String>, Option<String>);

fn crates_of(found: &[Found]) -> Vec<CrateUse> {
    let mut counts: BTreeMap<CrateKey, usize> = BTreeMap::new();
    for f in found {
        if !f.value.contains("src") {
            continue;
        }
        let path = f.value.replace('\\', "/");
        for key in crate_paths(&path) {
            *counts.entry(key).or_default() += 1;
        }
    }
    let mut crates = Vec::new();
    for ((name, version, registry), occurrences) in counts {
        crates.push(CrateUse {
            name,
            version,
            registry,
            occurrences,
        });
    }
    crates
}

/// Crates nommées dans `path`, séparateurs déjà normalisés en `/` :
/// `…/registry/src/<registre>/<crate>-<version>/…`, puis tout
/// `<crate>/src/….rs` qui n'est pas sous un registre.
fn crate_paths(path: &str) -> Vec<CrateKey> {
    const REGISTRY: &str = "registry/src/";
    const SRC: &str = "/src/";
    let mut keys = Vec::new();
    let mut registry_dirs = Vec::new();
    let mut registry_srcs = Vec::new();
    for (at, _) in path.match_indices(REGISTRY) {
        registry_srcs.push(at + "registry".len());
        let start = at + REGISTRY.len();
        let Some((registry, rest)) = path[start..].split_once('/') else {
            continue;
        };
        let Some((dir, _)) = rest.split_once('/') else {
            continue;
        };
        let Some((name, version)) = split_version(dir) else {
            continue;
        };
        if registry.is_empty() || !is_crate_name(name) {
            continue;
        }
        registry_dirs.push(start + registry.len() + 1);
        let version = Some(version.to_string());
        let registry = Some(registry.to_string());
        keys.push((name.to_string(), version, registry));
    }
    for (at, _) in path.match_indices(SRC) {
        let head = &path[..at];
        let start = head.trim_end_matches(is_crate_char).len();
        let tail = &path[at + SRC.len()..];
        let file = tail.split(|c: char| !is_path(c)).next().unwrap_or("");
        let skipped = registry_srcs.contains(&at) || registry_dirs.contains(&start);
        if skipped || !file.contains(".rs") {
            continue;
        }
        let component = &head[start..];
        let (name, version) = match split_version(component) {
            Some((name, version)) => (name, Some(version.to_string())),
            None => (component, None),
        };
        if is_crate_name(name) {
            keys.push((name.to_string(), version, None));
        }
    }
    keys
}

/// `<crate>-<version>` coupé au premier `-` suivi d'une version.
fn split_version(dir: &str) -> Option<(&str, &str)> {
    for (at, _) in dir.match_indices('-') {
        let (name, version) = (&dir[..at], &dir[at + 1..]);
        if !name.is_empty() && is_version(version) {
            return Some((name, version));
        }
    }
    None
}

/// `MAJEUR.MINEUR.CORRECTIF`, suivi ou non de `-…` ou `+…`.
fn is_version(text: &str) -> bool {
    let core = text.split(['-', '+']).next().unwrap_or_default();
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| is_number(p))
}

fn is_number(part: &str) -> bool {
    !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())
}

fn is_crate_name(name: &str) -> bool {
    let first = name.chars().next();
    let leading = first.is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    leading && name.len() <= 64 && name.chars().all(is_crate_char) && !name.contains('.')
}

fn is_crate_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
}

fn is_path(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/')
}

fn c_libraries_of(found: &[Found]) -> Vec<CLibrary> {
    let mut libraries = Vec::new();
    for f in found {
        for &(library, prefix, digit, also) in C_BANNERS {
            for (at, _) in f.value.match_indices(prefix) {
                let banner = &f.value[at..];
                let next = banner[prefix.len()..].chars().next();
                let digit_next = next.is_some_and(|c| c.is_ascii_digit());
                if digit && !digit_next {
                    continue;
                }
                if also.is_some_and(|text| !banner.contains(text)) {
                    continue;
                }
                libraries.push(f.banner(library, at));
            }
        }
        if let Some(at) = sqlite_source_id(&f.value) {
            libraries.push(f.banner("SQLite", at));
        }
    }
    libraries
}

/// Position d'un `SQLITE_SOURCE_ID` : date, heure, puis au moins 40 chiffres
/// hexadécimaux.
fn sqlite_source_id(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let span = SOURCE_ID.len() + SOURCE_ID_HASH;
    let last = bytes.len().checked_sub(span)?;
    (0..=last).find(|&at| is_source_id(&bytes[at..at + span]))
}

fn is_source_id(window: &[u8]) -> bool {
    let (head, hash) = window.split_at(SOURCE_ID.len());
    let dated = head.iter().zip(SOURCE_ID).all(|(&b, &s)| shape_byte(b, s));
    dated && hash.iter().all(u8::is_ascii_hexdigit)
}

fn shape_byte(byte: u8, shape: u8) -> bool {
    match shape {
        b'0' => byte.is_ascii_digit(),
        _ => byte == shape,
    }
}

// ---------------------------------------------------------------------------
// Constantes cryptographiques.

fn crypto_constants() -> Vec<Constant> {
    let sbox = aes_sbox();
    let mut inverse = [0u8; 256];
    for (x, &s) in sbox.iter().enumerate() {
        inverse[usize::from(s)] = x as u8;
    }
    let te0: Vec<u32> = sbox.iter().map(|&s| te0_word(s)).collect();
    let td0: Vec<u32> = inverse.iter().map(|&s| td0_word(s)).collect();
    let mut poly1305_prime = vec![0xff; 17];
    poly1305_prime[0] = 0xfb;
    poly1305_prime[16] = 0x03;
    let mut curve25519_prime = vec![0xff; 32];
    curve25519_prime[0] = 0xed;
    curve25519_prime[31] = 0x7f;
    let mut base_point = vec![0x66; 32];
    base_point[0] = 0x58;
    let mut out = vec![
        sequence("aes_sbox", sbox.to_vec()),
        sequence("aes_inv_sbox", inverse.to_vec()),
        sequence("chacha_sigma", b"expand 32-byte k".to_vec()),
        sequence("poly1305_clamp", POLY1305_CLAMP.to_vec()),
        sequence("poly1305_prime", poly1305_prime),
        sequence("curve25519_prime", curve25519_prime),
        sequence("ed25519_base_point", base_point),
        sequence("sm4_sbox", SM4_SBOX_HEAD.to_vec()),
    ];
    words32(&mut out, "aes_te0", &te0);
    words32(&mut out, "aes_td0", &td0);
    words32(&mut out, "sha256_k", &SHA256_K_HEAD);
    words32(&mut out, "sha256_iv", &SHA256_IV);
    words32(&mut out, "sha1_iv", &SHA1_IV);
    let le = SHA512_K_HEAD.iter().flat_map(|w| w.to_le_bytes()).collect();
    let be = SHA512_K_HEAD.iter().flat_map(|w| w.to_be_bytes()).collect();
    out.push(ordered("sha512_k", ORDER_LE, le));
    out.push(ordered("sha512_k", ORDER_BE, be));
    out
}

fn sequence(name: &'static str, bytes: Vec<u8>) -> Constant {
    Constant {
        name,
        byte_order: None,
        bytes,
    }
}

fn ordered(name: &'static str, order: &'static str, bytes: Vec<u8>) -> Constant {
    Constant {
        name,
        byte_order: Some(order),
        bytes,
    }
}

fn words32(out: &mut Vec<Constant>, name: &'static str, words: &[u32]) {
    let le = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let be = words.iter().flat_map(|w| w.to_be_bytes()).collect();
    out.push(ordered(name, ORDER_LE, le));
    out.push(ordered(name, ORDER_BE, be));
}

fn xtime(b: u8) -> u8 {
    let carry = if b & 0x80 != 0 { 0x1b } else { 0 };
    (b << 1) ^ carry
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    product
}

/// Inverse multiplicatif dans GF(2^8), puis transformation affine.
fn aes_sbox() -> [u8; 256] {
    let mut sbox = [0u8; 256];
    for (x, slot) in sbox.iter_mut().enumerate() {
        let x = x as u8;
        let inverse = (1..=255).find(|&y| gf_mul(x, y) == 1).unwrap_or(0);
        let mut value = inverse ^ 0x63;
        for k in 1..=4 {
            value ^= inverse.rotate_left(k);
        }
        *slot = value;
    }
    sbox
}

fn te0_word(s: u8) -> u32 {
    u32::from_be_bytes([xtime(s), s, s, xtime(s) ^ s])
}

fn td0_word(s: u8) -> u32 {
    u32::from_be_bytes([gf_mul(s, 14), gf_mul(s, 9), gf_mul(s, 13), gf_mul(s, 11)])
}

fn crypto_hits(image: &Image, areas: &[Area], constants: &[Constant]) -> Vec<CryptoHit> {
    let mut by_first: [Vec<usize>; 256] = std::array::from_fn(|_| Vec::new());
    for (index, constant) in constants.iter().enumerate() {
        by_first[usize::from(constant.bytes[0])].push(index);
    }
    let mut hits = Vec::new();
    for (index, area) in areas.iter().enumerate() {
        let Some(data) = image.bytes_at(area.offset, area.size) else {
            continue;
        };
        for (at, &byte) in data.iter().enumerate() {
            for &c in &by_first[usize::from(byte)] {
                let constant = &constants[c];
                if data[at..].starts_with(&constant.bytes) {
                    hits.push(CryptoHit {
                        name: constant.name,
                        byte_order: constant.byte_order,
                        length: constant.bytes.len(),
                        area: index,
                        vaddr: area.vaddr + at as u64,
                        refs: Vec::new(),
                    });
                }
            }
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// Légende.

const LEGEND: &str = "\
--native-strings [MOTIF…] : chaînes de chaque ELF, avec la manière dont leur borne a
été trouvée, les instructions qui forment leur adresse (--xrefs), l'inventaire des
crates Rust et des bibliothèques C liées statiquement (--crates) et les constantes
cryptographiques reconnues au contenu. Ni exécution, ni émulation.
Entrée : APK, split, XAPK (base et splits ABI, comme --native) ou ELF brut reconnu à
ses quatre premiers octets 7F 45 4C 46. Dans une archive, toute entrée qui commence
par ce magic est un ELF, quel que soit son chemin. --elf <chemin> restreint l'analyse
à un ELF : chemin d'entrée (lib/arm64-v8a/libfoo.so), <split>!<entrée> pour un ELF de
split, nom du fichier pour un ELF brut.
Motifs : sous-chaîne, casse ignorée, même sémantique que --strings ; sans motif,
toutes les chaînes. Les motifs ne filtrent que strings[] et format_arrays[] :
comptes, crates, bibliothèques C et constantes portent sur toutes les chaînes
extraites.
Sortie : JSON écrit en flux dans --json-out (obligatoire), ELF après ELF et chaîne
après chaîne ; rien sur stdout. Aucune chaîne, aucun tableau n'est tronqué.

RAPPORT
  sha256          SHA-256 complet de l'entrée : APK, base d'un XAPK, ou ELF brut.
  input           Chemin de l'entrée ; <chemin du .xapk>!<entrée du base> pour un XAPK.
  options         patterns, min_length, elf, xrefs, crates tels que reçus.
  limits          Toutes les limites appliquées :
                  min_length = longueur minimale, en caractères, de toute chaîne
                  extraite, quelle que soit sa borne (--min-length, défaut 4), sauf
                  un morceau de découpe qui commence à une adresse formée ;
                  max_string_len = longueur maximale, en octets, d'une borne
                  rust_fatptr ou rust_code ; un couple plus long est ignoré ;
                  code_window = instructions pendant lesquelles une page ADRP, une
                  adresse formée ou une longueur immédiate restent appariables ;
                  max_propagated_array = nombre maximal de couples d'un tableau
                  dont les références sont recopiées sur chaque morceau (section
                  TABLEAUX) ;
                  sections_not_scanned = sections allouées jamais découpées en
                  chaînes.
  elfs[]          Un objet par ELF retenu, dans l'ordre de l'archive : base, puis
                  splits ABI.
  elfs_not_selected  ELF écartés par --elf : entrée, ou <split>!<entrée>.
  errors          Ce qui n'a pas pu être lu : entrée d'archive illisible (on ignore
                  alors si c'était un ELF), split illisible, --elf sans ELF de ce
                  chemin.

ELF (elfs[])
  elf             Chemin de l'entrée dans l'archive ; nom du fichier en mode brut.
  split           Id du split XAPK porteur ; null pour le base ou un APK simple.
  elf_sha256      SHA-256 complet du contenu décompressé de l'ELF, jamais tronqué.
  machine         e_machine : aarch64, arm, x86, x86_64, mips, riscv, unknown(0x..).
  summary         Écrit en tête de l'objet, avant les chaînes (section RÉSUMÉ).
  strings[]       Chaînes retenues, triées par vaddr (section CHAÎNE).
  crates[], c_libraries[]  Avec --crates seulement (section CRATES).
  crypto_constants[]  Section CONSTANTES.
  format_arrays[] Tableaux de couples rust_fatptr, triés par adresse (section
                  TABLEAUX).

RÉSUMÉ (elfs[].summary)
  areas           sections = zones lues d'après les section headers ; segments = sans
                  section headers, d'après les segments LOAD ; null si l'ELF est
                  illisible (section ZONES).
  strings_found   Chaînes extraites, toutes bornes confondues.
  strings_emitted Chaînes de strings[] : celles qui contiennent un motif, ou toutes
                  sans motif.
  by_boundary     strings_found par boundary : nul, rust_fatptr, rust_code,
                  heuristic.
  by_encoding     strings_found par encoding : ascii, utf8, utf16le.
  fatptr_pairs    Couples {ptr, len} retenus dans les données.
  format_arrays   Tableaux de couples (section TABLEAUX), tableaux d'un seul couple
                  compris, avant filtre des motifs.
  pairs_in_arrays Couples qui appartiennent à un tableau d'au moins deux couples ;
                  fatptr_pairs - pairs_in_arrays = couples isolés.
  arrays_with_xrefs  Tableaux dont au moins un couple a son adresse formée par une
                  instruction (kind fatptr_array). Calculé avec ou sans --xrefs ;
                  toujours 0 quand code_scan est null.
  arrays_without_xrefs  format_arrays - arrays_with_xrefs. Même limite que xrefs vide
                  (section RÉFÉRENCES) : ce n'est pas une preuve de non-usage.
  arrays_not_propagated  Tableaux de plus de max_propagated_array couples qui ont au
                  moins une référence : leurs références restent dans
                  format_arrays[].xrefs, aucune n'est posée sur leurs morceaux.
  rust_code_dropped_prefixes  Candidats rust_code écartés parce qu'un intervalle
                  prouvé plus long (rust_fatptr ou rust_code) commence à la même
                  adresse (section BORNES).
  blocks_split    Blocs nul ou heuristic coupés aux adresses formées (section
                  DÉCOUPE).
  pieces_from_split  Morceaux de ces blocs retenus dans strings_found.
  code_scan       aarch64 = code balayé ; null = machine autre qu'AArch64 64 bits
                  petit-boutiste : ni rust_code ni xrefs n'existent alors.
  functions       symtab = fonctions bornées par un symbole STT_FUNC défini de
                  .symtab ou .dynsym (fin = début + st_size quand st_size est non
                  nul, sinon jusqu'à la fonction suivante) ;
                  eh_frame = fonctions bornées par un FDE de .eh_frame à une adresse
                  qu'aucun symbole ne borne ;
                  eh_frame_present = .eh_frame trouvé, par sa section ou, sans
                  section headers, par PT_GNU_EH_FRAME ;
                  eh_frame_unread = FDE non lus : CIE introuvable, codage d'adresse
                  non modélisé, début hors du code.
  xrefs           Avec --xrefs, null sinon. total = références rattachées à une
                  chaîne ou à une constante, fatptr_array exclues ;
                  unresolved_text = adresses formées qui tombent dans une zone de
                  chaînes en lecture seule, sur un octet de texte (section BORNES)
                  qu'aucune chaîne extraite ne couvre et où ne commence aucune
                  constante : typiquement une chaîne plus courte que min_length, que
                  rien ne rattache ;
                  non_text_targets = mêmes adresses, mais sur un octet qui n'est pas
                  du texte : tables numériques, données binaires de .rodata ;
                  without_function = références dont l'instruction n'est dans
                  aucune fonction bornée, fatptr_array exclues ;
                  fatptr_array = références de kind fatptr_array effectivement posées
                  sur les chaînes de strings_found, une par instruction et par
                  chaîne, donc venues des seuls tableaux propagés ; comptées à part,
                  ni dans total ni dans without_function.
  crypto_constants  Nombre de constantes reconnues.
  anomalies       Relocations illisibles ou non modélisées, même vocabulaire que
                  --native ; elf_unreadable: <raison> quand l'ELF n'a pas pu être lu
                  (ses tableaux sont alors vides).

ZONES
  Avec section headers : sections allouées présentes dans le fichier. Sont découpées
  en chaînes celles de type PROGBITS ou STRTAB, non exécutables, hors
  sections_not_scanned : .rodata, .dynstr, .data, … Sans section headers : segments
  LOAD sans w, exécutables compris (du code y produit des blocs heuristic). Les
  constantes sont cherchées dans toutes les zones, code compris. Une borne prouvée
  doit tomber dans une zone découpée en lecture seule.

CHAÎNE (elfs[].strings[])
  elf, elf_sha256 ELF porteur, répétés sur chaque chaîne.
  vaddr           Adresse virtuelle du premier octet, base de chargement 0.
  file_offset     Offset du premier octet dans le fichier ELF.
  section         Section porteuse ; null sans section headers.
  length          Longueur en octets, sans le nul final ; deux octets par caractère
                  en utf16le.
  encoding        ascii = octets < 0x80 seulement ;
                  utf8 = UTF-8 valide avec au moins un octet >= 0x80 ;
                  utf16le = unités de 16 bits petit-boutistes dont l'octet haut est
                  nul et l'octet bas un caractère ASCII imprimable, \\t, \\n ou \\r.
                  L'UTF-16 hors ASCII n'est pas cherché. Une suite qui suit
                  immédiatement un octet de texte perd sa première unité : c'est le
                  dernier caractère et le nul d'une chaîne ASCII.
  value           Le texte décodé, entier.
  boundary        Comment la borne a été trouvée (section BORNES).
  split_from      vaddr du bloc nul ou heuristic dont la chaîne est un morceau
                  (section DÉCOUPE) ; absent pour une chaîne non découpée.
  patterns        Motifs contenus, tels que passés ; absent sans motif.
  pairs[]         rust_fatptr seulement, absent pour les autres bornes. Un objet par
                  couple {ptr, len} qui désigne exactement cette chaîne (même ptr,
                  même len), triés par adresse du couple : une chaîne désignée par
                  plusieurs couples sort une fois, avec un objet par couple.
                  pair_vaddr = adresse du couple ;
                  array_vaddr = adresse du premier couple de son tableau (section
                  TABLEAUX) ;
                  array_index = rang du couple dans le tableau, à partir de 0 ;
                  array_len = nombre de couples du tableau, 1 pour un couple isolé.
  xrefs[]         Avec --xrefs seulement (section RÉFÉRENCES).

BORNES (boundary)
  rust_fatptr     Couple {ptr, len} d'un &str Rust lu dans les données : un mot relogé
                  par une relocation relative (R_AARCH64_RELATIVE sur AArch64, le type
                  RELATIVE de la machine ailleurs ; RELA, REL, RELR, comme --native)
                  pointe dans une zone découpée en lecture seule ; le mot suivant
                  n'est pas relogé et vaut une longueur de 1 à max_string_len ;
                  [ptr, ptr+len) tient dans cette zone et est de l'UTF-8 valide sans
                  caractère de contrôle autre que \\t, \\n, \\r. Début et fin prouvés.
  rust_code       Adresse formée dans le code (ADRP+ADD, ADR, LDR littéral) et, à
                  moins de code_window instructions, longueur immédiate (MOVZ, ou ORR
                  d'un immédiat logique sur xzr) posée dans le registre suivant
                  (adresse dans x1, longueur dans x2 : un &str passé en argument), ou
                  rangée par STR, STUR ou STP huit octets après l'adresse, sur la même
                  base. Même validation du texte que rust_fatptr.
                  Faux positifs : tout couple (adresse de données en lecture seule,
                  petite constante) dans deux registres consécutifs ou deux mots
                  adjacents passe, par exemple la source et la taille d'un memcpy ;
                  la validation du texte en écarte la plupart, pas tous. Une longueur
                  mal appariée donne une chaîne trop longue ou trop courte, rendue
                  quand même. Préfixes : un candidat rust_code est écarté quand un
                  intervalle prouvé plus long (rust_fatptr ou rust_code) commence à
                  la même adresse ; « fals » cède devant « false ». Les écartés sont
                  comptés dans rust_code_dropped_prefixes.
  nul             Suite d'octets de texte qui finit sur un octet nul et qu'aucune
                  borne prouvée ne couvre. Seule la fin est prouvée : le début est le
                  premier octet de texte après un octet qui n'en est pas un, ou après
                  la fin d'une plage prouvée.
  heuristic       Suite d'octets de texte sans borne prouvée : aucun nul ne la
                  termine, elle bute sur une plage prouvée, un octet non textuel ou la
                  fin de la zone ; ou morceau de découpe (section DÉCOUPE).
                  Typiquement un bloc de &str concaténés dont aucun couple n'a été
                  trouvé.
  Octets de texte : \\t, \\n, \\r, 0x20 à 0x7E, et tout octet de 0x80 à 0xF4 sauf 0xC0
  et 0xC1 (ceux qui peuvent figurer en UTF-8). Une suite qui n'est pas de l'UTF-8
  valide est coupée en ses pièces valides ; seule la dernière peut être nul. Une plage
  couverte par rust_fatptr ou rust_code n'est jamais rendue en plus dans un bloc nul
  ou heuristic. Deux plages prouvées qui se chevauchent sont rendues toutes deux ; une
  plage prouvée des deux façons l'est une fois, en rust_fatptr.

DÉCOUPE AUX ADRESSES FORMÉES (AArch64, avec ou sans --xrefs)
  Un bloc nul ou heuristic est coupé à chaque adresse formée par le code (ADRP+ADD,
  ADR, LDR littéral, fatptr) qui tombe strictement à l'intérieur : vaddr < cible <
  vaddr + length. Une cible au milieu d'un caractère UTF-8 ou d'une unité UTF-16 ne
  coupe pas. Le premier morceau, avant la première coupe, est heuristic ; chaque
  morceau qui commence à une cible est heuristic, sauf le dernier morceau d'un bloc
  nul, qui garde nul : sa fin est prouvée par l'octet nul. Chaque morceau porte
  split_from = vaddr du bloc d'origine. Un morceau plus court que min_length reste
  rendu s'il commence à une cible (une chaîne référencée n'est jamais jetée) ; sinon
  il suit min_length. Un bloc plus court que min_length n'est gardé que pour être
  coupé. Seule la fin d'un morceau qui précède une coupe est déduite d'une adresse
  formée : rien ne prouve qu'une chaîne s'y arrête. La découpe a lieu avant les
  comptes du résumé et avant le filtre des motifs ; crates[] et c_libraries[] sont
  lus sur les blocs entiers, avant découpe. Un bloc que rien ne référence en son
  milieu reste heuristic, entier.

RÉFÉRENCES (strings[].xrefs[], crypto_constants[].xrefs[], format_arrays[].xrefs[] ;
--xrefs, AArch64 seulement)
  Balayage linéaire de toutes les zones exécutables, pas seulement des fonctions
  atteintes depuis JNI. L'état des registres est remis à zéro au début de chaque
  fonction bornée et après B, BR, RET ; x0 à x18 et x30 sont oubliés après BL et BLR.
  fn_start        Début de la fonction bornée qui contient l'instruction ; null si
                  aucune ne la contient (RÉSUMÉ, functions).
  insn_addr       Instruction qui achève l'adresse : ADD de la paire ADRP+ADD, ADR,
                  LDR littéral, ou LDR [xN, #imm] après ADRP pour fatptr.
  kind            adrp_add = ADRP puis ADD immédiat 64 bits sur le registre de la
                  page ;
                  adr = ADR ;
                  ldr_literal = LDR littéral 64 bits dont le mot chargé, relogé s'il
                  l'est, est l'adresse ;
                  fatptr = l'adresse formée (ADRP+ADD, ADR, LDR littéral, ou ADRP puis
                  LDR [xN, #imm]) est l'emplacement d'un couple rust_fatptr : la
                  référence va à la chaîne du couple ;
                  fatptr_array = la même instruction que fatptr, vue depuis le
                  tableau du couple visé (section TABLEAUX) : la référence va à
                  chaque morceau du tableau, sauf à une chaîne qui porte déjà cette
                  instruction, en fatptr ou sous un autre kind. Une instruction ne
                  compte qu'une fois par chaîne : le morceau visé garde fatptr, les
                  autres reçoivent fatptr_array. Seulement depuis un tableau d'au
                  plus max_propagated_array couples : au-delà, la référence reste
                  dans format_arrays[].xrefs, et une entrée de ce tableau peut avoir
                  xrefs vide alors que sa table est référencée (section TABLEAUX).
  offset          Écart en octets entre l'adresse formée et vaddr : 0 quand elle
                  désigne le début, donc pour tout morceau de découpe ; non nul pour
                  une adresse au milieu d'une chaîne qui n'a pas été coupée (chaîne
                  prouvée, ou milieu d'un caractère). Toujours 0 pour fatptr_array.
  array_vaddr     fatptr_array seulement : adresse du premier couple du tableau.
  target_index    fatptr_array seulement : rang, à partir de 0, du couple dont
                  l'instruction forme l'adresse ; 0 quand elle vise le tableau par
                  son début.
  nearest_export  Export de .dynsym (STT_FUNC défini, STB_GLOBAL ou STB_WEAK) de plus
                  haute adresse inférieure ou égale à insn_addr : name, et distance =
                  insn_addr - adresse de l'export, en octets. null si aucun ne précède.
  xrefs vide      Aucune référence trouvée. Ce n'est PAS une preuve de non-usage.
                  Échappent au balayage : les adresses calculées indirectement (table
                  de pointeurs, arithmétique sur l'adresse, registre rechargé depuis la
                  pile ou reçu d'une autre fonction), un ADRP et son ADD séparés de
                  plus de code_window instructions ou par un branchement, le code
                  d'une autre machine qu'AArch64, le code chiffré ou produit à
                  l'exécution, les données lues par une autre bibliothèque.

TABLEAUX (elfs[].format_arrays[])
  Les morceaux littéraux d'une chaîne de format Rust (fmt::Arguments) forment un
  tableau de couples {ptr, len} contigus, et le code ne forme que l'adresse du
  tableau : sans regroupement, les morceaux autres que le premier n'ont aucune
  référence. Les couples rust_fatptr sont regroupés en tableaux : même zone,
  emplacements consécutifs au pas de deux mots (16 octets en 64 bits, 8 en 32 bits),
  chacun validé comme rust_fatptr. Un couple isolé est un tableau de longueur 1. Tous
  les tableaux sont rendus.
  array_vaddr     Adresse du premier couple.
  section         Section qui porte les couples ; null sans section headers.
  len             Nombre de couples.
  propagated      true quand len <= max_propagated_array : les références du tableau
                  sont aussi posées sur ses morceaux, en fatptr_array ; false sinon,
                  elles ne sont que dans xrefs[] ci-dessous.
  pieces[]        Valeur de chaque morceau, dans l'ordre des couples, quelle que soit
                  sa longueur : un morceau plus court que min_length figure ici et
                  dans aucun strings[]. Les arguments interpolés entre les morceaux ne
                  sont pas reconstitués.
  patterns        Motifs contenus dans au moins un morceau ; absent sans motif. Avec
                  des motifs, seuls les tableaux qui en contiennent un sont rendus ;
                  un motif à cheval sur deux morceaux n'est pas trouvé.
  xrefs[]         Avec --xrefs : instructions qui forment l'adresse d'un couple du
                  tableau, kind fatptr_array, array_vaddr, target_index. Rendues que
                  le tableau soit propagé ou non.
  Propagation. Une instruction qui forme l'adresse d'une table de &str la charge ;
  elle ne lit pas pour autant chacune de ses entrées (table de versions Unicode,
  d'alias de propriétés, de jetons d'un lexer : le code qui la reçoit peut n'en lire
  qu'une partie). Recopier sa référence sur chaque entrée ferait passer pour lue
  chacune d'elles. Elle n'est donc recopiée sur les morceaux que pour un tableau
  d'au plus max_propagated_array couples ; ce seuil est un paramètre de l'outil, pas
  une taille mesurée des chaînes de format. Au-delà, propagated = false, la
  référence reste dans format_arrays[].xrefs, et une entrée peut avoir xrefs vide
  dans strings[] alors que sa table est référencée : lire format_arrays[], que
  pairs[] de la chaîne désigne par array_vaddr. pairs[] est renseigné pour tous les
  tableaux, propagés ou non : il dit où est la chaîne, pas qui la lit. Une chaîne de
  format de plus de max_propagated_array morceaux est traitée comme une table.
  Limites. Deux tableaux rangés bout à bout, sans mot intercalé, sont fusionnés en un
  seul : rien dans les octets ne marque leur frontière, et les références de l'un vont
  aussi aux morceaux de l'autre. Un couple non validé (longueur 0 ou supérieure à
  max_string_len, pointeur hors d'une zone de chaînes en lecture seule, texte
  invalide) coupe le tableau en deux à cet endroit. Le regroupement ne prouve pas
  qu'un tableau est une chaîne de format : toute table de &str contiguë (liste de
  noms, de champs) est regroupée de la même façon.

CRATES (--crates)
  crates[]        Chemins de source trouvés dans les chaînes extraites, \\ normalisé en
                  / : …/registry/src/<registre>/<crate>-<version>/… (cargo), et
                  <crate>/src/….rs hors registre (crate du projet ; std, core, alloc
                  sous /rustc/<commit>/library/…). crate ; version, null si absente du
                  chemin ; registry = répertoire du registre, null hors registre ;
                  occurrences = nombre de chemins trouvés. <crate>-<version> est coupé
                  au premier - suivi de MAJEUR.MINEUR.CORRECTIF.
  c_libraries[]   Bannières de bibliothèques C (table BANNIÈRES) : library ; banner =
                  texte de la chaîne depuis la bannière jusqu'à la fin de la chaîne ;
                  vaddr = adresse du premier octet de la bannière.
  Rien n'est conclu sur l'usage : une crate citée par un chemin de panique est liée,
  pas nécessairement appelée.

CONSTANTES (elfs[].crypto_constants[])
  Reconnues au contenu, octet pour octet, dans toutes les zones, code compris.
  name            Nom stable (table CONSTANTES CRYPTOGRAPHIQUES).
  byte_order      le ou be : ordre des octets de chaque mot d'une table de mots ; null
                  pour une suite d'octets.
  length          Octets comparés.
  vaddr, file_offset, section  Comme pour une chaîne.
  xrefs[]         Avec --xrefs : adresses formées égales à vaddr.
  Aucune conclusion sur l'usage : une table présente peut ne jamais être lue, et une
  primitive implantée sans table (instructions AES, constantes en immédiats) reste
  invisible ici.

STDERR
  [OK]    <elf> — chaînes rendues sur chaînes extraites, par boundary puis par
          encoding, fonctions bornées par source ; avec --xrefs, références
          rattachées, unresolved_text et non_text_targets.
  [AVERT] <elf> — avec --xrefs : ni symboles ni .eh_frame (fn_start toujours null) ;
          ou machine sans balayage du code (xrefs vides, aucune borne rust_code).
  [AVERT] <entrée> — aucun ELF.
  [FAIL]  <elf> — ELF illisible ; [FAIL] <erreur> pour chaque entrée de errors.

CONSTANTES CRYPTOGRAPHIQUES
  aes_sbox            S-box AES, 256 octets.
  aes_inv_sbox        S-box inverse AES, 256 octets.
  aes_te0             Table Te0 : 256 mots de 32 bits (2·S[x], S[x], S[x], 3·S[x]),
                      le et be.
  aes_td0             Table Td0 : 256 mots de 32 bits (14·Si[x], 9·Si[x], 13·Si[x],
                      11·Si[x]), Si = S-box inverse, le et be.
  sha256_k            8 premiers mots des constantes K de SHA-256, le et be.
  sha512_k            4 premiers mots des constantes K de SHA-512, le et be.
  sha256_iv           Les 8 mots de la valeur initiale de SHA-256, le et be.
  sha1_iv             Les 5 mots de la valeur initiale de SHA-1, le et be. Les quatre
                      premiers sont aussi ceux de MD5 : seul le cinquième les distingue,
                      MD5 n'est donc pas reconnu par cette entrée.
  chacha_sigma        \"expand 32-byte k\".
  poly1305_clamp      Masque de r, 0x0ffffffc0ffffffc0ffffffc0fffffff, 16 octets le.
  poly1305_prime      2^130 - 5, 17 octets le.
  curve25519_prime    2^255 - 19, 32 octets le.
  ed25519_base_point  Point de base de Curve25519 en coordonnées d'Edwards, compressé
                      (y = 4/5), 32 octets. Le point de base de Montgomery (u = 9 :
                      09 suivi de 31 octets nuls) n'est pas cherché, faute d'être
                      distinctif.
  sm4_sbox            16 premiers octets de la S-box SM4.
";

/// Légende autonome de `--native-strings`.
pub fn legend() -> String {
    let mut out = String::from(LEGEND);
    out.push_str("\nBANNIÈRES (c_libraries)\n");
    for &(library, prefix, digit, also) in C_BANNERS {
        let digit = if digit { " suivi d'un chiffre" } else { "" };
        let also = match also {
            Some(text) => format!(", avec {text:?} plus loin"),
            None => String::new(),
        };
        out.push_str(&format!("  {library:<15} {prefix:?}{digit}{also}\n"));
    }
    out.push_str("  SQLite          SQLITE_SOURCE_ID : AAAA-MM-JJ HH:MM:SS puis 40 hex\n");
    let sections = format!("\nSECTIONS NON DÉCOUPÉES\n  {SECTIONS_NOT_SCANNED}\n");
    out.push_str(&sections);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::elf::{self, SHT_PROGBITS, SHT_RELA, SHT_STRTAB};

    const TEXT: u64 = 0x1000;
    const RODATA: u64 = 0x2000;
    const RELRO: u64 = 0x3000;
    const RELA: u64 = 0x4000;
    const EH_FRAME: u64 = 0x5000;
    const SHSTRTAB: u64 = 0x6000;
    const RET: u32 = 0xd65f_03c0;

    struct Spec {
        name: &'static str,
        sh_type: u32,
        flags: u64,
        addr: u64,
        data: Vec<u8>,
    }

    fn spec(name: &'static str, sh_type: u32, flags: u64, addr: u64, data: Vec<u8>) -> Spec {
        Spec {
            name,
            sh_type,
            flags,
            addr,
            data,
        }
    }

    fn put(buf: &mut [u8], at: u64, bytes: &[u8]) {
        let at = at as usize;
        buf[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn section_header(buf: &mut [u8], at: u64, name: u32, spec: &Spec, offset: u64) {
        put(buf, at, &name.to_le_bytes());
        put(buf, at + 4, &spec.sh_type.to_le_bytes());
        put(buf, at + 8, &spec.flags.to_le_bytes());
        put(buf, at + 16, &spec.addr.to_le_bytes());
        put(buf, at + 24, &offset.to_le_bytes());
        put(buf, at + 32, &(spec.data.len() as u64).to_le_bytes());
        put(buf, at + 48, &1u64.to_le_bytes());
    }

    /// ELF64 AArch64 : chaque section à l'offset égal à son adresse, sous un seul
    /// segment LOAD rwx.
    fn elf_with(sections: &[Spec]) -> Vec<u8> {
        let mut names = b"\0.shstrtab\0".to_vec();
        let mut name_offsets = Vec::new();
        for s in sections {
            name_offsets.push(names.len() as u32);
            names.extend_from_slice(s.name.as_bytes());
            names.push(0);
        }
        let shoff = SHSTRTAB + 0x1000;
        let shnum = sections.len() + 2;
        let mut buf = vec![0u8; shoff as usize + 64 * shnum];
        put(&mut buf, 0, b"\x7FELF\x02\x01\x01");
        put(&mut buf, 16, &elf::ET_DYN.to_le_bytes());
        put(&mut buf, 18, &elf::EM_AARCH64.to_le_bytes());
        put(&mut buf, 20, &1u32.to_le_bytes());
        put(&mut buf, 32, &64u64.to_le_bytes());
        put(&mut buf, 40, &shoff.to_le_bytes());
        put(&mut buf, 52, &64u16.to_le_bytes());
        put(&mut buf, 54, &56u16.to_le_bytes());
        put(&mut buf, 56, &1u16.to_le_bytes());
        put(&mut buf, 58, &64u16.to_le_bytes());
        put(&mut buf, 60, &(shnum as u16).to_le_bytes());
        put(&mut buf, 62, &1u16.to_le_bytes());

        let flags = elf::PF_R | elf::PF_W | elf::PF_X;
        put(&mut buf, 64, &elf::PT_LOAD.to_le_bytes());
        put(&mut buf, 68, &flags.to_le_bytes());
        put(&mut buf, 96, &shoff.to_le_bytes());
        put(&mut buf, 104, &shoff.to_le_bytes());
        put(&mut buf, 112, &0x1000u64.to_le_bytes());

        put(&mut buf, SHSTRTAB, &names);
        let shstrtab = spec(".shstrtab", SHT_STRTAB, 0, 0, names.clone());
        section_header(&mut buf, shoff + 64, 1, &shstrtab, SHSTRTAB);
        for (i, s) in sections.iter().enumerate() {
            put(&mut buf, s.addr, &s.data);
            let at = shoff + 64 * (i as u64 + 2);
            section_header(&mut buf, at, name_offsets[i], s, s.addr);
        }
        buf
    }

    fn text(code: &[u32]) -> Spec {
        let bytes = code.iter().flat_map(|w| w.to_le_bytes()).collect();
        spec(".text", SHT_PROGBITS, 6, TEXT, bytes)
    }

    fn rodata(data: &[u8]) -> Spec {
        spec(".rodata", SHT_PROGBITS, 2, RODATA, data.to_vec())
    }

    /// Couples {ptr, len} contigus dans .data.rel.ro, `ptr` relogé par
    /// R_AARCH64_RELATIVE.
    fn fat_pointers(pairs: &[(u64, u64)]) -> [Spec; 2] {
        let mut placed = Vec::new();
        for (i, &(ptr, len)) in pairs.iter().enumerate() {
            placed.push((16 * i as u64, ptr, len));
        }
        fat_pointers_at(&placed)
    }

    /// (décalage dans .data.rel.ro, ptr, len) ; les mots non écrits restent nuls.
    fn fat_pointers_at(pairs: &[(u64, u64, u64)]) -> [Spec; 2] {
        let size = pairs.iter().map(|p| p.0 + 16).max().unwrap_or(0);
        let mut relro = vec![0u8; size as usize];
        let mut rela = Vec::new();
        let info = u64::from(elf::R_AARCH64_RELATIVE);
        for &(at, ptr, len) in pairs {
            put(&mut relro, at + 8, &len.to_le_bytes());
            rela.extend_from_slice(&(RELRO + at).to_le_bytes());
            rela.extend_from_slice(&info.to_le_bytes());
            rela.extend_from_slice(&ptr.to_le_bytes());
        }
        [
            spec(".data.rel.ro", SHT_PROGBITS, 3, RELRO, relro),
            spec(".rela.dyn", SHT_RELA, 2, RELA, rela),
        ]
    }

    /// Une CIE `zR` (FDE en pcrel|sdata4) et une FDE qui couvre
    /// `[start, start + len)`.
    fn eh_frame(start: u64, len: u32) -> Spec {
        let mut data = Vec::new();
        data.extend_from_slice(&16u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&[1, b'z', b'R', 0, 1, 0x78, 30, 1, 0x1b, 0, 0, 0]);
        data.extend_from_slice(&16u32.to_le_bytes());
        data.extend_from_slice(&24u32.to_le_bytes());
        let field = EH_FRAME + 28;
        data.extend_from_slice(&((start as i64 - field as i64) as i32).to_le_bytes());
        data.extend_from_slice(&len.to_le_bytes());
        data.extend_from_slice(&[0, 0, 0, 0]);
        data.extend_from_slice(&0u32.to_le_bytes());
        spec(".eh_frame", SHT_PROGBITS, 2, EH_FRAME, data)
    }

    fn adrp(rd: u32, pc: u64, target: u64) -> u32 {
        let pages = ((target >> 12) as i64 - (pc >> 12) as i64) as u32;
        0x9000_0000 | ((pages & 3) << 29) | (((pages >> 2) & 0x7ffff) << 5) | rd
    }

    fn add_imm(rd: u32, rn: u32, imm: u32) -> u32 {
        0x9100_0000 | (imm << 10) | (rn << 5) | rd
    }

    fn mov_w(rd: u32, imm: u32) -> u32 {
        0x5280_0000 | (imm << 5) | rd
    }

    fn ldr_literal(rt: u32, pc: u64, target: u64) -> u32 {
        let words = ((target - pc) / 4) as u32;
        0x5800_0000 | ((words & 0x7ffff) << 5) | rt
    }

    fn options() -> Options {
        Options {
            patterns: Vec::new(),
            min_length: DEFAULT_MIN_LENGTH,
            elf: None,
            xrefs: true,
            crates: true,
        }
    }

    fn strings_of(report: &ElfStrings) -> Vec<(&str, &str)> {
        let rows = report.strings.iter();
        rows.map(|f| (f.value.as_str(), f.boundary)).collect()
    }

    #[test]
    fn encoders_match_known_instructions() {
        assert_eq!(add_imm(1, 1, 5), 0x9100_1421);
        assert_eq!(mov_w(2, 4), 0x5280_0082);
        assert_eq!(adrp(0, 0, 0x1000), 0xb000_0000);
        assert_eq!(ldr_literal(0, 0, 8), 0x5800_0040);
    }

    #[test]
    fn fat_pointers_split_a_concatenated_block() {
        let data = b"cipher_suitecompression_methodCertificatePayload\0";
        let [relro, rela] = fat_pointers(&[(RODATA, 12), (RODATA + 12, 18)]);
        let bytes = elf_with(&[rodata(data), relro, rela]);
        let report = analyze("libt.so", None, &bytes, &options());
        let anomalies = &report.summary.anomalies;
        assert!(anomalies.is_empty(), "{anomalies:?}");
        let expected = vec![
            ("cipher_suite", BOUNDARY_FATPTR),
            ("compression_method", BOUNDARY_FATPTR),
            ("CertificatePayload", BOUNDARY_NUL),
        ];
        assert_eq!(strings_of(&report), expected);
        assert_eq!(report.summary.fatptr_pairs, 2);
        assert_eq!(report.summary.by_boundary.heuristic, 0);
    }

    #[test]
    fn a_relocated_word_is_not_a_length() {
        let info = u64::from(elf::R_AARCH64_RELATIVE);
        let mut rela = Vec::new();
        for slot in [RELRO, RELRO + 8] {
            rela.extend_from_slice(&slot.to_le_bytes());
            rela.extend_from_slice(&info.to_le_bytes());
            rela.extend_from_slice(&RODATA.to_le_bytes());
        }
        let relro = [0u64, 12].iter().flat_map(|w| w.to_le_bytes()).collect();
        let bytes = elf_with(&[
            rodata(b"cipher_suitecompression_method"),
            spec(".data.rel.ro", SHT_PROGBITS, 3, RELRO, relro),
            spec(".rela.dyn", SHT_RELA, 2, RELA, rela),
        ]);
        let report = analyze("libt.so", None, &bytes, &options());
        assert_eq!(report.summary.fatptr_pairs, 0);
    }

    #[test]
    fn an_immediate_length_bounds_a_string_and_adrp_add_references_it() {
        let target = RODATA + 5;
        let code = [
            adrp(1, TEXT, target),
            add_imm(1, 1, (target & 0xfff) as u32),
            mov_w(2, 4),
            RET,
        ];
        let sections = [text(&code), rodata(b"alphabetagamma\0"), eh_frame(TEXT, 16)];
        let bytes = elf_with(&sections);
        let report = analyze("libt.so", None, &bytes, &options());
        let expected = vec![
            ("alpha", BOUNDARY_HEURISTIC),
            ("beta", BOUNDARY_CODE),
            ("gamma", BOUNDARY_NUL),
        ];
        assert_eq!(strings_of(&report), expected);
        assert_eq!(report.summary.functions.eh_frame, 1);
        let rows = report.xref_rows(&report.strings[1].refs);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].fn_start.as_deref(), Some("0x1000"));
        assert_eq!(rows[0].insn_addr, "0x1004");
        assert_eq!(rows[0].kind, KIND_ADRP_ADD);
        assert_eq!(rows[0].offset, 0);
    }

    #[test]
    fn a_length_stored_next_to_the_address_bounds_a_string() {
        let target = RODATA + 5;
        let code = [
            adrp(8, TEXT, target),
            add_imm(8, 8, (target & 0xfff) as u32),
            mov_w(10, 4),
            0xa900_2be8,
            RET,
        ];
        let bytes = elf_with(&[text(&code), rodata(b"alphabetagamma\0")]);
        let report = analyze("libt.so", None, &bytes, &options());
        assert_eq!(strings_of(&report)[1], ("beta", BOUNDARY_CODE));
    }

    #[test]
    fn nul_terminated_strings_and_their_encodings() {
        let mut data = b"hello world\0caf\xc3\xa9 au lait\0".to_vec();
        data.extend_from_slice(b"w\0i\0d\0e\0\0\0");
        let bytes = elf_with(&[rodata(&data)]);
        let report = analyze("libt.so", None, &bytes, &options());
        let rows: Vec<(&str, &str, &str)> = report
            .strings
            .iter()
            .map(|f| (f.value.as_str(), f.boundary, f.encoding))
            .collect();
        let expected = vec![
            ("hello world", BOUNDARY_NUL, ENCODING_ASCII),
            ("café au lait", BOUNDARY_NUL, ENCODING_UTF8),
            ("wide", BOUNDARY_NUL, ENCODING_UTF16LE),
        ];
        assert_eq!(rows, expected);
        assert_eq!(report.strings[2].len, 8);
    }

    #[test]
    fn ldr_literal_references_the_string_its_word_points_to() {
        let code = [ldr_literal(0, TEXT, TEXT + 8), RET];
        let mut text = text(&code);
        text.data.extend_from_slice(&RODATA.to_le_bytes());
        let bytes = elf_with(&[text, rodata(b"hello world\0")]);
        let report = analyze("libt.so", None, &bytes, &options());
        let hello = &report.strings[0];
        assert_eq!(hello.value, "hello world");
        let refs: Vec<(u64, &str)> = hello.refs.iter().map(|r| (r.insn, r.kind)).collect();
        assert_eq!(refs, vec![(TEXT, KIND_LDR_LITERAL)]);
        let orphans = report.summary.xrefs.as_ref().map(|x| x.without_function);
        assert_eq!(orphans, Some(1));
    }

    #[test]
    fn crate_paths_name_registry_and_local_crates() {
        let registry = "/home/u/.cargo/registry/src/index.crates.io-6f17d22bba15001f/\
                        windows-sys-0.52.0/src/lib.rs";
        let expected = (
            "windows-sys".to_string(),
            Some("0.52.0".to_string()),
            Some("index.crates.io-6f17d22bba15001f".to_string()),
        );
        assert_eq!(crate_paths(registry), vec![expected]);

        let core = "/rustc/90b35a6239c3d8bdabc530a6a0816f7ff89a0aaf/library/core/src/fmt/mod.rs";
        assert_eq!(crate_paths(core), vec![("core".to_string(), None, None)]);

        let block = format!("{registry}called `Option::unwrap()`mycrate/src/main.rs");
        let names: Vec<String> = crate_paths(&block).into_iter().map(|k| k.0).collect();
        assert_eq!(names, vec!["windows-sys", "mycrate"]);

        assert!(crate_paths("/build/openssl/src/ssl.c").is_empty());
    }

    fn nul_string(vaddr: u64, value: &str) -> Found {
        let len = value.len() as u64;
        Found::new(0, vaddr, len, value.to_string(), BOUNDARY_NUL)
    }

    #[test]
    fn c_library_banners_and_sqlite_source_id() {
        let source_id = "2023-11-24 11:41:44 ebe9de66c9ed1a2bc5fb5f5ce2ad5f6a1e2b0f2a";
        let found = [
            nul_string(0x100, "OpenSSL 1.1.1w  11 Sep 2023"),
            nul_string(0x200, "OpenSSL support"),
            nul_string(0x300, source_id),
        ];
        let libraries: Vec<(&str, String)> = c_libraries_of(&found)
            .into_iter()
            .map(|l| (l.library, l.vaddr))
            .collect();
        let expected = vec![
            ("OpenSSL", "0x100".to_string()),
            ("SQLite", "0x300".to_string()),
        ];
        assert_eq!(libraries, expected);
    }

    #[test]
    fn aes_sbox_is_found_at_its_address() {
        let sbox = aes_sbox();
        let head = u128::from_be_bytes(sbox[..16].try_into().unwrap());
        assert_eq!(head, 0x637c777bf26b6fc53001672bfed7ab76);
        assert_eq!(sbox[0x53], 0xed);
        assert_eq!(te0_word(sbox[0]), 0xc66363a5);
        let mut data = vec![0u8; 8];
        data.extend_from_slice(&sbox);
        let bytes = elf_with(&[rodata(&data)]);
        let report = analyze("libt.so", None, &bytes, &options());
        let hits: Vec<(&str, u64)> = report.crypto.iter().map(|c| (c.name, c.vaddr)).collect();
        assert_eq!(hits, vec![("aes_sbox", RODATA + 8)]);
    }

    #[test]
    fn logical_immediates_decode() {
        assert_eq!(bitmask_imm(0x321c_03e2), Some(0x10));
        assert_eq!(bitmask_imm(0xb240_1fe0), Some(0xff));
    }

    #[test]
    fn the_report_is_json_with_the_summary_before_the_strings() {
        let bytes = elf_with(&[rodata(b"hello world\0")]);
        let mut out = Vec::new();
        let container = Container::Elf("libt.so".into(), bytes);
        let outcome = write_report(&mut out, "00", "libt.so", container, &[], &options()).unwrap();
        assert_eq!(outcome.elfs.len(), 1);
        let text = String::from_utf8(out).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["elfs"][0]["strings"][0]["value"], "hello world");
        assert_eq!(json["limits"]["min_length"], DEFAULT_MIN_LENGTH);
        let summary = text.find("\"summary\"").unwrap();
        assert!(summary < text.find("\"strings\"").unwrap());
    }

    #[test]
    fn elf_not_selected_is_listed_not_analyzed() {
        let bytes = elf_with(&[rodata(b"hello world\0")]);
        let mut out = Vec::new();
        let options = Options {
            elf: Some("libother.so".into()),
            ..options()
        };
        let container = Container::Elf("libt.so".into(), bytes);
        let outcome = write_report(&mut out, "00", "libt.so", container, &[], &options).unwrap();
        assert!(outcome.elfs.is_empty());
        assert_eq!(outcome.not_selected, vec!["libt.so"]);
        assert_eq!(outcome.errors.len(), 1);
    }

    #[test]
    fn a_block_is_split_at_the_addresses_formed_inside_it() {
        let code = [
            adrp(0, TEXT, RODATA + 4),
            add_imm(0, 0, 4),
            adrp(3, TEXT + 8, RODATA + 8),
            add_imm(3, 3, 8),
            RET,
        ];
        let bytes = elf_with(&[text(&code), rodata(b"AAAABBBBCCCC\0")]);
        let report = analyze("libt.so", None, &bytes, &options());
        let expected = vec![
            ("AAAA", BOUNDARY_HEURISTIC),
            ("BBBB", BOUNDARY_HEURISTIC),
            ("CCCC", BOUNDARY_NUL),
        ];
        assert_eq!(strings_of(&report), expected);
        for piece in &report.strings {
            assert_eq!(piece.split_from, Some(RODATA));
        }
        let refs: Vec<(usize, u64)> = report
            .strings
            .iter()
            .map(|f| (f.refs.len(), f.refs.first().map_or(1, |r| r.offset)))
            .collect();
        assert_eq!(refs, vec![(0, 1), (1, 0), (1, 0)]);
        assert_eq!(report.summary.blocks_split, 1);
        assert_eq!(report.summary.pieces_from_split, 3);
    }

    #[test]
    fn an_address_formed_on_the_first_byte_does_not_split() {
        let code = [adrp(0, TEXT, RODATA), add_imm(0, 0, 0), RET];
        let bytes = elf_with(&[text(&code), rodata(b"AAAABBBB\0")]);
        let report = analyze("libt.so", None, &bytes, &options());
        assert_eq!(strings_of(&report), vec![("AAAABBBB", BOUNDARY_NUL)]);
        assert_eq!(report.strings[0].split_from, None);
        assert_eq!(report.strings[0].refs.len(), 1);
        assert_eq!(report.summary.blocks_split, 0);
    }

    #[test]
    fn a_shorter_rust_code_at_the_same_address_is_dropped() {
        let code = [
            adrp(1, TEXT, RODATA),
            add_imm(1, 1, 0),
            mov_w(2, 4),
            adrp(3, TEXT + 12, RODATA),
            add_imm(3, 3, 0),
            mov_w(4, 5),
            RET,
        ];
        let bytes = elf_with(&[text(&code), rodata(b"false\0")]);
        let report = analyze("libt.so", None, &bytes, &options());
        assert_eq!(strings_of(&report), vec![("false", BOUNDARY_CODE)]);
        assert_eq!(report.summary.rust_code_dropped_prefixes, 1);
    }

    #[test]
    fn an_address_formed_on_a_non_text_byte_is_not_unresolved_text() {
        let code = [adrp(0, TEXT, RODATA), add_imm(0, 0, 0), RET];
        let bytes = elf_with(&[text(&code), rodata(&[0xff, 0, 0, 0])]);
        let report = analyze("libt.so", None, &bytes, &options());
        let xrefs = report.summary.xrefs.as_ref().unwrap();
        assert_eq!(xrefs.non_text_targets, 1);
        assert_eq!(xrefs.unresolved_text, 0);
    }

    const PIECES: &[u8] = b"alphabravocharliedelta\0";

    fn arrays_of(report: &ElfStrings) -> Vec<(u64, usize)> {
        let arrays = report.arrays.iter();
        arrays.map(|a| (a.vaddr, a.pairs.len())).collect()
    }

    fn refs_of(found: &Found) -> Vec<(u64, &'static str, Option<(u64, usize)>)> {
        let refs = found.refs.iter();
        refs.map(|r| (r.insn, r.kind, r.array)).collect()
    }

    /// (pair_vaddr, array_index, array_len) de chaque couple de la ligne.
    fn pairs_of<'r>(row: &'r Row<'_>) -> Vec<(&'r str, usize, usize)> {
        let pairs = row.pairs.iter();
        pairs
            .map(|p| (p.pair_vaddr.as_str(), p.array_index, p.array_len))
            .collect()
    }

    #[test]
    fn an_array_referenced_on_its_first_pair_gives_the_reference_to_every_piece() {
        let options = options();
        let code = [adrp(0, TEXT, RELRO), add_imm(0, 0, 0), RET];
        let [relro, rela] = fat_pointers(&[
            (RODATA, 5),
            (RODATA + 5, 5),
            (RODATA + 10, 7),
            (RODATA + 17, 5),
        ]);
        let bytes = elf_with(&[text(&code), rodata(PIECES), relro, rela]);
        let report = analyze("libt.so", None, &bytes, &options);
        assert_eq!(arrays_of(&report), vec![(RELRO, 4)]);
        let pieces = &report.arrays[0].pieces;
        assert_eq!(pieces, &["alpha", "bravo", "charlie", "delta"]);

        let add = TEXT + 4;
        let array = Some((RELRO, 0));
        let refs: Vec<_> = report.strings.iter().map(refs_of).collect();
        let expected = vec![
            vec![(add, KIND_FATPTR, None)],
            vec![(add, KIND_FATPTR_ARRAY, array)],
            vec![(add, KIND_FATPTR_ARRAY, array)],
            vec![(add, KIND_FATPTR_ARRAY, array)],
        ];
        assert_eq!(refs, expected);

        let row = report.row(&report.strings[2], &options);
        assert_eq!(pairs_of(&row), vec![("0x3020", 2, 4)]);
        assert_eq!(row.pairs[0].array_vaddr, "0x3000");
        let xref = &row.xrefs.as_ref().unwrap()[0];
        assert_eq!(xref.array_vaddr.as_deref(), Some("0x3000"));
        assert_eq!(xref.target_index, Some(0));

        let s = &report.summary;
        assert_eq!(s.format_arrays, 1);
        assert_eq!(s.pairs_in_arrays, 4);
        assert_eq!((s.arrays_with_xrefs, s.arrays_without_xrefs), (1, 0));
        let xrefs = s.xrefs.as_ref().unwrap();
        assert_eq!((xrefs.total, xrefs.fatptr_array), (1, 3));
    }

    #[test]
    fn a_word_between_two_arrays_keeps_them_apart() {
        let [relro, rela] = fat_pointers_at(&[
            (0, RODATA, 5),
            (16, RODATA + 5, 5),
            (40, RODATA + 10, 7),
            (56, RODATA + 17, 5),
        ]);
        let bytes = elf_with(&[rodata(PIECES), relro, rela]);
        let report = analyze("libt.so", None, &bytes, &options());
        assert_eq!(arrays_of(&report), vec![(RELRO, 2), (RELRO + 40, 2)]);
        assert_eq!(report.arrays[1].pieces, ["charlie", "delta"]);
        let s = &report.summary;
        assert_eq!((s.format_arrays, s.pairs_in_arrays), (2, 4));
        assert_eq!((s.arrays_with_xrefs, s.arrays_without_xrefs), (0, 2));
    }

    #[test]
    fn a_string_named_by_two_pairs_is_emitted_once_with_both_pairs() {
        let options = options();
        let code = [
            adrp(0, TEXT, RELRO + 16),
            add_imm(0, 0, 16),
            adrp(1, TEXT + 8, RELRO + 40),
            add_imm(1, 1, 40),
            RET,
        ];
        let [relro, rela] = fat_pointers_at(&[
            (0, RODATA, 5),
            (16, RODATA + 5, 5),
            (40, RODATA, 5),
        ]);
        let bytes = elf_with(&[text(&code), rodata(PIECES), relro, rela]);
        let report = analyze("libt.so", None, &bytes, &options);
        assert_eq!(arrays_of(&report), vec![(RELRO, 2), (RELRO + 40, 1)]);
        let alphas = report.strings.iter().filter(|f| f.value == "alpha");
        let alphas: Vec<&Found> = alphas.collect();
        assert_eq!(alphas.len(), 1);
        assert_eq!(alphas[0].places, vec![(0, 0), (1, 0)]);

        let row = report.row(alphas[0], &options);
        assert_eq!(pairs_of(&row), vec![("0x3000", 0, 2), ("0x3028", 0, 1)]);

        let expected = vec![
            (TEXT + 12, KIND_FATPTR, None),
            (TEXT + 4, KIND_FATPTR_ARRAY, Some((RELRO, 1))),
        ];
        assert_eq!(refs_of(alphas[0]), expected);
    }

    #[test]
    fn a_one_character_piece_is_in_format_arrays_not_in_strings() {
        let piece = "] should_create_e2ee_channel for ";
        let data = format!("[{piece}\0");
        let len = piece.len() as u64;
        let [relro, rela] = fat_pointers(&[(RODATA, 1), (RODATA + 1, len)]);
        let bytes = elf_with(&[rodata(data.as_bytes()), relro, rela]);
        let mut out = Vec::new();
        let container = Container::Elf("libt.so".into(), bytes);
        write_report(&mut out, "00", "libt.so", container, &[], &options()).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let elf = &json["elfs"][0];
        let values: Vec<&str> = elf["strings"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|s| s["value"].as_str())
            .collect();
        assert_eq!(values, vec![piece]);
        assert_eq!(elf["strings"][0]["pairs"][0]["array_index"], 1);
        assert_eq!(elf["format_arrays"][0]["array_vaddr"], "0x3000");
        assert_eq!(elf["format_arrays"][0]["section"], ".data.rel.ro");
        assert_eq!(elf["format_arrays"][0]["len"], 2);
        let pieces = &elf["format_arrays"][0]["pieces"];
        assert_eq!(*pieces, serde_json::json!(["[", piece]));
    }

    #[test]
    fn patterns_keep_an_array_when_one_piece_matches() {
        let [relro, rela] = fat_pointers(&[(RODATA, 5), (RODATA + 5, 5)]);
        let bytes = elf_with(&[rodata(PIECES), relro, rela]);
        for (pattern, kept) in [("BRAVO", 1), ("alphabravo", 0)] {
            let options = Options {
                patterns: vec![pattern.to_string()],
                ..options()
            };
            let mut out = Vec::new();
            let container = Container::Elf("libt.so".into(), bytes.clone());
            write_report(&mut out, "00", "libt.so", container, &[], &options).unwrap();
            let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
            let arrays = json["elfs"][0]["format_arrays"].as_array().unwrap();
            assert_eq!(arrays.len(), kept, "{pattern}");
        }
    }

    /// Tableau de `n` couples sur des morceaux de 4 caractères, `p000`, `p001`…,
    /// référencé par ADRP+ADD sur son premier couple.
    fn referenced_array(n: usize) -> ElfStrings {
        let mut data = Vec::new();
        let mut pairs = Vec::new();
        for i in 0..n {
            pairs.push((RODATA + data.len() as u64, 4));
            data.extend_from_slice(format!("p{i:03}").as_bytes());
        }
        data.push(0);
        let code = [adrp(0, TEXT, RELRO), add_imm(0, 0, 0), RET];
        let [relro, rela] = fat_pointers(&pairs);
        let bytes = elf_with(&[text(&code), rodata(&data), relro, rela]);
        analyze("libt.so", None, &bytes, &options())
    }

    #[test]
    fn a_short_array_gives_its_reference_to_every_piece() {
        let options = options();
        let report = referenced_array(3);
        let add = TEXT + 4;
        let array = Some((RELRO, 0));
        let refs: Vec<_> = report.strings.iter().map(refs_of).collect();
        let expected = vec![
            vec![(add, KIND_FATPTR, None)],
            vec![(add, KIND_FATPTR_ARRAY, array)],
            vec![(add, KIND_FATPTR_ARRAY, array)],
        ];
        assert_eq!(refs, expected);
        for f in &report.strings {
            let row = report.row(f, &options);
            assert_eq!(row.pairs.len(), 1);
            assert_eq!(row.pairs[0].array_len, 3);
        }
        assert!(report.array_row(&report.arrays[0], &options).propagated);
        let s = &report.summary;
        assert_eq!(s.arrays_not_propagated, 0);
        assert_eq!(s.xrefs.as_ref().unwrap().fatptr_array, 2);
    }

    #[test]
    fn a_long_array_keeps_its_reference_in_format_arrays() {
        let options = options();
        let report = referenced_array(MAX_PROPAGATED_ARRAY + 1);
        assert_eq!(report.strings.len(), 17);
        let first = refs_of(&report.strings[0]);
        assert_eq!(first, vec![(TEXT + 4, KIND_FATPTR, None)]);
        for f in &report.strings[1..] {
            assert!(f.refs.is_empty(), "{}", f.value);
        }
        for f in &report.strings {
            let row = report.row(f, &options);
            assert_eq!(row.pairs.len(), 1);
            assert_eq!(row.pairs[0].array_len, 17);
        }
        let row = report.array_row(&report.arrays[0], &options);
        assert!(!row.propagated);
        let xrefs = row.xrefs.as_ref().unwrap();
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].kind, KIND_FATPTR_ARRAY);
        assert_eq!(xrefs[0].target_index, Some(0));
        let s = &report.summary;
        assert_eq!(s.arrays_not_propagated, 1);
        assert_eq!(s.xrefs.as_ref().unwrap().fatptr_array, 0);
    }
}
