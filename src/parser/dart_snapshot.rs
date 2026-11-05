//! Instantané Dart AOT d'une application Flutter (mode `--dart-snapshot`) : ce
//! que le pool DEX ne contient pas.
//!
//! Lecture seule, rien n'est écrit sur disque. Dans un APK : chaque
//! `lib/<abi>/libapp.so` du base et des splits ABI d'un XAPK. Un ELF brut,
//! reconnu à son magic, est lu seul, quel que soit son nom. Les ELF passent par
//! le parseur de [`super::native_static`].
//!
//! Trois étapes, par blob de données : localisation (par `.dynsym`, à défaut par
//! balayage du magic), en-tête et découpage en partie sérialisée / image de
//! données ; calibration facultative de la disposition des chaînes sur des
//! témoins (`--dart-calibrate`) ; énumération HEURISTIQUE des `OneByteString` /
//! `TwoByteString` de l'image de données, avec la disposition calibrée, à défaut
//! celle de [`KNOWN_VERSIONS`], sinon pas du tout.
//!
//! Toutes les étiquettes produites sont définies dans [`legend`].

use anyhow::{Context, Result};
use object::elf;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::ops::Range;
use std::panic::AssertUnwindSafe;
use std::path::Path;

use super::native_static::{parse_elf, DynSymbol, Image, Section};
use super::source::Source;
use super::xapk::Split;

pub const VM_DATA: &str = "_kDartVmSnapshotData";
pub const VM_INSTRUCTIONS: &str = "_kDartVmSnapshotInstructions";
pub const ISOLATE_DATA: &str = "_kDartIsolateSnapshotData";
pub const ISOLATE_INSTRUCTIONS: &str = "_kDartIsolateSnapshotInstructions";
pub const HEURISTIC: &str = "heuristic";
const SYMBOLS: [&str; 4] = [VM_DATA, VM_INSTRUCTIONS, ISOLATE_DATA, ISOLATE_INSTRUCTIONS];

pub const DEFAULT_MAX_ROWS: usize = 0;

const LIBAPP: &str = "libapp.so";
const ELF_MAGIC: &[u8] = b"\x7FELF";

const MAGIC: [u8; 4] = [0xf5, 0xf5, 0xdc, 0xdc];
const MAGIC_SIZE: usize = 4;
const MAGIC_ALIGN: u64 = 8;
const LENGTH_OFFSET: usize = 4;
const KIND_OFFSET: usize = 12;
const HEADER_SIZE: usize = 20;
const VERSION_HASH_LEN: usize = 32;
const FEATURES_OFFSET: usize = HEADER_SIZE + VERSION_HASH_LEN;
/// `kObjectStartAlignment`, `runtime/vm/pointer_tagging.h`, tag 3.5.0.
const OBJECT_START_ALIGNMENT: u64 = 64;
const COMPRESSED_POINTERS: &str = "compressed-pointers";
const NO_COMPRESSED_POINTERS: &str = "no-compressed-pointers";

const KINDS_WITH_FULL_CORE: [&str; 5] = ["full", "full_core", "full_jit", "full_aot", "none"];
const KINDS_WITH_MODULE: [&str; 4] = ["full", "full_jit", "full_aot", "module"];
const MAX_KIND: u64 = (KINDS_WITH_FULL_CORE.len() - 1) as u64;

pub const TRUNCATED_AT_MAGIC: &str = "truncated_at_magic";
pub const MAGIC_MISMATCH: &str = "magic_mismatch";
pub const TRUNCATED_AT_LENGTH: &str = "truncated_at_length";
pub const TRUNCATED_AT_KIND: &str = "truncated_at_kind";
pub const TRUNCATED_AT_VERSION_HASH: &str = "truncated_at_version_hash";
pub const VERSION_HASH_NOT_HEX: &str = "version_hash_not_hex";
pub const FEATURES_OFFSET_UNKNOWN: &str = "features_offset_unknown";
pub const FEATURES_UNTERMINATED: &str = "features_unterminated";
pub const FEATURES_NOT_UTF8: &str = "features_not_utf8";
pub const COMPRESSED_POINTERS_CONTRADICTORY: &str = "compressed_pointers_contradictory";

pub const ELF_UNREADABLE: &str = "elf_unreadable";
pub const DATA_BLOB_NOT_FOUND: &str = "data_blob_not_found";
pub const DATA_BLOB_UNBOUNDED: &str = "data_blob_unbounded";
pub const DATA_BLOB_SIZE_UNKNOWN: &str = "data_blob_size_unknown";
pub const DATA_IMAGE_EMPTY: &str = "data_image_empty";
pub const VERSION_HASH_UNREADABLE: &str = "version_hash_unreadable";
pub const UNSUPPORTED_SNAPSHOT_VERSION: &str = "unsupported_snapshot_version";
pub const INVALID_HEAP_LAYOUT: &str = "invalid_heap_layout";

pub const BOUND_SYMBOL_SIZE: &str = "symbol_size";
pub const BOUND_NEXT_SYMBOL: &str = "next_symbol";
pub const BOUND_SECTION_END: &str = "section_end";
pub const BOUND_NEXT_MAGIC: &str = "next_magic";
pub const BOUND_HEADER_LENGTH: &str = "header_length";

pub const LAYOUT_CALIBRATED: &str = "calibrated";
pub const LAYOUT_TABLE: &str = "table";

pub const CALIBRATED: &str = "calibrated";
pub const INSUFFICIENT_WITNESSES: &str = "insufficient_witnesses";
pub const AMBIGUOUS_LAYOUT: &str = "ambiguous_layout";
pub const NO_LAYOUT_EXPLAINS_WITNESSES: &str = "no_layout_explains_witnesses";
pub const WITNESS_NOT_FOUND: &str = "witness_not_found";
pub const WITNESSES_NOT_ALL_FOUND: &str = "witnesses_not_all_found";
pub const WITNESSES_OUTSIDE_DATA_IMAGE: &str = "witnesses_outside_data_image";
pub const NOT_RUN: &str = "not_run";

pub const VERDICT_ALL_IN_DATA_IMAGE: &str = "all_in_data_image";
pub const VERDICT_PARTLY_IN_DATA_IMAGE: &str = "partly_in_data_image";
pub const VERDICT_NONE_IN_DATA_IMAGE: &str = "none_in_data_image";
pub const VERDICT_NO_WITNESS_FOUND: &str = "no_witness_found";

pub const ONE_BYTE: &str = "one_byte";
pub const TWO_BYTE: &str = "two_byte";
pub const REJECT_TRUNCATED_FIELDS: &str = "truncated_fields";
pub const REJECT_LENGTH_NOT_SMI: &str = "length_not_smi";
pub const REJECT_LENGTH_NEGATIVE: &str = "length_negative";
pub const REJECT_LENGTH_OUT_OF_BLOB: &str = "length_out_of_blob";
pub const REJECT_SIZE_TAG_MISMATCH: &str = "size_tag_mismatch";
pub const REJECT_UNDECODABLE_UTF16: &str = "undecodable_utf16";
const REJECT_REASONS: [&str; 6] = [
    REJECT_TRUNCATED_FIELDS,
    REJECT_LENGTH_NOT_SMI,
    REJECT_LENGTH_NEGATIVE,
    REJECT_LENGTH_OUT_OF_BLOB,
    REJECT_SIZE_TAG_MISMATCH,
    REJECT_UNDECODABLE_UTF16,
];
const SCAN_METHOD: &str = "aligned_object_scan";

const MIN_WITNESSES: usize = 3;
const HEADER_WINDOW: usize = 64;
const MAX_EXAMINED_OCCURRENCES: usize = 4096;
const LENGTH_FIELDS: [(usize, usize); 5] = [(4, 4), (8, 4), (8, 8), (12, 4), (16, 8)];
const OBJECT_ALIGNMENTS: [usize; 2] = [8, 16];
pub const TAG_SOURCE_READ: &str = "read_sdk_3_5_0";
pub const TAG_SOURCE_GUESSED: &str = "guessed";
const TAG_LAYOUTS: [TagLayout; 2] = [
    TagLayout {
        size_tag_pos: 8,
        size_tag_bits: 4,
        class_id_tag_pos: 12,
        class_id_tag_bits: 20,
        source: TAG_SOURCE_READ,
    },
    TagLayout {
        size_tag_pos: 8,
        size_tag_bits: 8,
        class_id_tag_pos: 16,
        class_id_tag_bits: 16,
        source: TAG_SOURCE_GUESSED,
    },
];

/// Numérotation de `Snapshot::Kind`, qui a changé entre versions du SDK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KindLayout {
    /// `runtime/vm/snapshot.h`, tag 3.5.0.
    WithFullCore,
    /// `runtime/vm/snapshot.h`, branche main.
    WithModule,
}

impl KindLayout {
    fn labels(self) -> &'static [&'static str] {
        match self {
            KindLayout::WithFullCore => &KINDS_WITH_FULL_CORE,
            KindLayout::WithModule => &KINDS_WITH_MODULE,
        }
    }

    fn label(self, raw: u64) -> String {
        match usize::try_from(raw).ok().and_then(|i| self.labels().get(i)) {
            Some(label) => (*label).to_string(),
            None => unknown_kind(raw),
        }
    }
}

/// Disposition d'un objet chaîne dans le tas, pour une version donnée. Offsets
/// en octets depuis le début de l'objet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct HeapLayout {
    pub word_size: usize,
    pub object_alignment: usize,
    pub size_tag_pos: u32,
    pub size_tag_bits: u32,
    pub class_id_tag_pos: u32,
    pub class_id_tag_bits: u32,
    pub one_byte_string_cid: u64,
    pub two_byte_string_cid: u64,
    pub length_offset: usize,
    /// 4 avec pointeurs compressés, sinon `word_size`.
    pub length_width: usize,
    pub data_offset: usize,
}

impl HeapLayout {
    /// Règles violées ; vide = disposition utilisable par le balayage.
    pub fn violations(&self) -> Vec<String> {
        let HeapLayout {
            word_size,
            object_alignment,
            size_tag_pos,
            size_tag_bits,
            class_id_tag_pos,
            class_id_tag_bits,
            one_byte_string_cid,
            two_byte_string_cid,
            length_offset,
            length_width,
            data_offset,
        } = *self;
        let mut out = Vec::new();
        if !matches!(word_size, 4 | 8) {
            out.push(format!("word_size {word_size} hors de {{4, 8}}"));
        }
        if !matches!(length_width, 4 | 8) {
            out.push(format!("length_width {length_width} hors de {{4, 8}}"));
        }
        if length_width > word_size {
            out.push(format!(
                "length_width {length_width} > word_size {word_size}"
            ));
        }
        if !object_alignment.is_power_of_two() {
            out.push(format!(
                "object_alignment {object_alignment} n'est pas une puissance de deux non nulle"
            ));
        }
        let word_bits = if matches!(word_size, 4 | 8) {
            8 * word_size as u64
        } else {
            64
        };
        let fields = [
            ("size_tag", size_tag_pos, size_tag_bits),
            ("class_id_tag", class_id_tag_pos, class_id_tag_bits),
        ];
        for (field, pos, bits) in fields {
            if bits == 0 {
                out.push(format!("{field}_bits nul"));
            }
            let end = u64::from(pos) + u64::from(bits);
            if end > word_bits {
                out.push(format!("{field}_pos + {field}_bits = {end} > {word_bits}"));
            }
        }
        if length_offset < word_size {
            out.push(format!(
                "length_offset {length_offset} < word_size {word_size} (chevauche tags)"
            ));
        }
        if length_offset.saturating_add(length_width) > data_offset {
            out.push(format!(
                "length_offset + length_width = {} > data_offset {data_offset}",
                length_offset.saturating_add(length_width)
            ));
        }
        if data_offset > HEADER_WINDOW {
            out.push(format!("data_offset {data_offset} > {HEADER_WINDOW}"));
        }
        if one_byte_string_cid == two_byte_string_cid {
            out.push(format!(
                "one_byte_string_cid = two_byte_string_cid = {one_byte_string_cid}"
            ));
        }
        let cid_mask = mask(class_id_tag_bits);
        for (field, cid) in [
            ("one_byte_string_cid", one_byte_string_cid),
            ("two_byte_string_cid", two_byte_string_cid),
        ] {
            if cid == 0 {
                out.push(format!("{field} = 0 (kIllegalCid)"));
            }
            if cid > cid_mask {
                out.push(format!("{field} {cid} ne tient pas dans class_id_tag_bits"));
            }
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownVersion {
    pub version_hash: &'static str,
    pub label: &'static str,
    /// `None` : numérotation de `kind` inconnue, rendue `unknown(<valeur>)`.
    pub kinds: Option<KindLayout>,
    pub heap: HeapLayout,
}

/// Vide : aucune disposition n'a encore été vérifiée sur échantillon.
pub const KNOWN_VERSIONS: &[KnownVersion] = &[];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TagLayout {
    pub size_tag_pos: u32,
    pub size_tag_bits: u32,
    pub class_id_tag_pos: u32,
    pub class_id_tag_bits: u32,
    pub source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DartOptions {
    /// 0 = toutes.
    pub max_rows: usize,
    /// `Some` dès que `--dart-calibrate*` est passé, même sans témoin.
    pub witnesses: Option<Vec<String>>,
}

impl Default for DartOptions {
    fn default() -> Self {
        DartOptions {
            max_rows: DEFAULT_MAX_ROWS,
            witnesses: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DartSnapshotReport {
    pub sha256: String,
    pub summary: Summary,
    pub libraries: Vec<LibReport>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub libraries: usize,
    pub sections_found: usize,
    pub located_by_symbol: usize,
    pub located_by_heuristic: usize,
    pub headers_parsed: usize,
    pub headers_magic_ok: usize,
    pub data_blobs: usize,
    pub version_hashes: Vec<String>,
    pub unknown_version_hashes: Vec<String>,
    pub libraries_calibrated: usize,
    pub libraries_with_strings: usize,
    pub libraries_without_strings: usize,
    pub string_candidates: u64,
    pub strings_accepted: u64,
    pub strings_rejected: u64,
    pub strings_returned: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LibReport {
    pub path: String,
    /// Split XAPK porteur (`xapk::Split::id`) ; absent pour le base ou un APK.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub split: Option<String>,
    pub sha256: String,
    pub size: u64,
    pub sections: Vec<SnapshotSection>,
    pub missing_symbols: Vec<&'static str>,
    /// Aucun blob de données balayable dans la bibliothèque ; null sinon.
    pub strings_unavailable: Option<&'static str>,
    pub anomalies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotSection {
    pub symbol: String,
    /// Rang par file_offset croissant ; `None` si non projeté.
    pub blob_index: Option<usize>,
    pub file_offset: Option<u64>,
    pub vaddr: u64,
    pub size: Option<u64>,
    pub elf_section: Option<String>,
    pub header: Option<SnapshotHeader>,
    pub serialized: Option<Span>,
    pub data_image: Option<DataImage>,
    /// Blobs de données seulement.
    #[serde(flatten)]
    pub scan: Option<BlobScan>,
}

/// Plage d'offsets de fichier `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Span {
    pub start: u64,
    pub end: u64,
    pub size: u64,
}

impl Span {
    fn new(start: u64, end: u64) -> Self {
        Span {
            start,
            end,
            size: end - start,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DataImage {
    pub start: u64,
    pub end: u64,
    pub size: u64,
    pub end_bound: &'static str,
    pub start_alignment: u64,
    pub start_alignment_source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlobScan {
    /// Présent avec `--dart-calibrate*` seulement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calibration: Option<Calibration>,
    pub strings: Option<StringScan>,
    pub strings_unavailable: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotHeader {
    pub magic: Option<String>,
    pub magic_ok: bool,
    pub length: Option<u64>,
    pub kind_raw: Option<u64>,
    pub kind: Option<String>,
    pub version_hash: Option<String>,
    pub known_version: Option<&'static str>,
    pub features: Option<String>,
    pub compressed_pointers: Option<bool>,
    pub errors: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StringScan {
    pub heuristic: bool,
    pub method: &'static str,
    pub blob_bound: &'static str,
    pub layout_source: &'static str,
    pub layout: HeapLayout,
    pub stride: usize,
    pub candidates: u64,
    pub accepted: u64,
    pub rejected: BTreeMap<&'static str, u64>,
    pub entries_total: u64,
    pub entries_returned: u64,
    pub truncated: bool,
    pub entries: Vec<StringEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StringEntry {
    pub image_offset: u64,
    pub file_offset: u64,
    pub encoding: &'static str,
    pub length: u64,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Calibration {
    pub outcome: &'static str,
    pub not_run_reason: Option<&'static str>,
    pub witnesses_total: usize,
    pub witnesses_found: Option<usize>,
    pub witnesses_in_data_image: Option<usize>,
    pub witnesses_explained: Option<usize>,
    pub data_image_verdict: Option<&'static str>,
    pub witnesses: Vec<Witness>,
    pub word_size: Option<usize>,
    pub compressed_pointers: Option<bool>,
    pub length_fields_tried: Vec<LengthField>,
    pub object_alignments_tried: Vec<usize>,
    pub tag_layouts_tried: Vec<TagLayout>,
    pub inferred: Vec<InferredLayout>,
    pub known_version_literal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Witness {
    pub value: String,
    pub encoding: &'static str,
    pub length: u64,
    pub occurrences: Option<usize>,
    pub occurrences_examined: Option<usize>,
    pub zones: Option<Zones>,
    pub explained: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Zones {
    pub serialized: ZoneCount,
    pub data_image: ZoneCount,
    pub outside: ZoneCount,
}

impl Zones {
    fn total(&self) -> usize {
        self.serialized.count + self.data_image.count + self.outside.count
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ZoneCount {
    pub count: usize,
    pub first_offset: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LengthField {
    pub offset: usize,
    pub width: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InferredLayout {
    pub layout: HeapLayout,
    pub derived_cid: Option<&'static str>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Evidence {
    pub witness: String,
    pub image_offset: u64,
    pub file_offset: u64,
}

struct Blob {
    section: SnapshotSection,
    /// `[début, fin)` du blob dans le fichier ; fin désignée par `bound`.
    range: Option<Range<usize>>,
    bound: Option<&'static str>,
    /// Section ELF porteuse, dans le fichier.
    container: Option<Range<usize>>,
}

/// Une section et les deux zones d'un blob, en offsets de fichier.
struct Zoning<'a> {
    bytes: &'a [u8],
    start: u64,
    serialized: Range<u64>,
    image: Option<Range<u64>>,
}

impl<'a> Zoning<'a> {
    fn image_bytes(&self) -> &'a [u8] {
        let Some(image) = &self.image else {
            return &[];
        };
        let at = |o: u64| -> Option<usize> { usize::try_from(o.checked_sub(self.start)?).ok() };
        match (at(image.start), at(image.end)) {
            (Some(a), Some(b)) => self.bytes.get(a..b).unwrap_or(&[]),
            _ => &[],
        }
    }

    /// Chaque occurrence est rangée dans la zone de son premier octet.
    fn zones(&self, needle: &[u8]) -> Zones {
        let mut zones = Zones::default();
        for at in occurrences(self.bytes, needle) {
            let offset = self.start + at as u64;
            let zone = if self.serialized.contains(&offset) {
                &mut zones.serialized
            } else if self.image.as_ref().is_some_and(|r| r.contains(&offset)) {
                &mut zones.data_image
            } else {
                &mut zones.outside
            };
            zone.count += 1;
            zone.first_offset = zone.first_offset.or(Some(offset));
        }
        zones
    }
}

struct End {
    at: u64,
    bound: &'static str,
    detail: String,
}

/// Lit chaque `lib/<abi>/libapp.so` de l'APK, puis des splits ABI d'un XAPK
/// dont il est le base. Seule une archive de base illisible fait échouer le
/// mode : une entrée ou un split illisible devient une erreur.
pub fn analyze_apk(
    src: impl Into<Source>,
    splits: &[Split],
    options: &DartOptions,
) -> Result<DartSnapshotReport> {
    let src = src.into();
    let sha256 = src.sha256()?;
    let mut errors = Vec::new();
    let mut libraries = Vec::new();
    let native = splits.iter().filter(|s| s.native);
    let archives =
        std::iter::once((&src, None)).chain(native.map(|s| (&s.source, Some(s.id.as_str()))));
    for (archive, split) in archives {
        let entries = match (read_libapps(archive), split) {
            (Ok(entries), _) => entries,
            (Err(e), None) => return Err(e),
            (Err(e), Some(id)) => {
                errors.push(format!("split {id} : illisible ({e:#})"));
                continue;
            }
        };
        for (name, bytes) in entries {
            match bytes {
                Ok(bytes) => {
                    let mut lib = analyze_lib(&name, &bytes, KNOWN_VERSIONS, options);
                    lib.split = split.map(str::to_string);
                    libraries.push(lib);
                }
                Err(why) => {
                    let at = match split {
                        Some(id) => format!("{id}!{name}"),
                        None => name,
                    };
                    errors.push(format!("{at}: entrée illisible ({why})"));
                }
            }
        }
    }
    Ok(DartSnapshotReport::build(sha256, libraries, errors))
}

/// ELF brut, reconnu à son magic.
pub fn analyze_elf_file(path: &Path, options: &DartOptions) -> Result<DartSnapshotReport> {
    let bytes = std::fs::read(path).with_context(|| format!("lecture {}", path.display()))?;
    if !bytes.starts_with(ELF_MAGIC) {
        anyhow::bail!("{} : magic ELF 7F 45 4C 46 absent", path.display());
    }
    let name = match path.file_name() {
        Some(name) => name.to_string_lossy().into_owned(),
        None => path.display().to_string(),
    };
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    let lib = analyze_lib(&name, &bytes, KNOWN_VERSIONS, options);
    Ok(DartSnapshotReport::build(sha256, vec![lib], Vec::new()))
}

type Entries = Vec<(String, std::result::Result<Vec<u8>, String>)>;

fn read_libapps(src: &Source) -> Result<Entries> {
    match read_libapps_nominal(src) {
        Ok(entries) => Ok(entries),
        Err(e) => {
            tracing::warn!(
                apk = %src,
                error = %e,
                "lecture de libapp.so en échec par le crate zip, repli sur le lecteur tolérant"
            );
            read_libapps_tolerant(src)
        }
    }
}

fn read_libapps_nominal(src: &Source) -> Result<Entries> {
    let file = src.reader().with_context(|| format!("ouverture {src}"))?;
    let mut archive = zip::ZipArchive::new(file).context("lecture APK (zip)")?;
    let names: Vec<String> = archive
        .file_names()
        .filter(|name| is_libapp(name))
        .map(str::to_string)
        .collect();
    let mut entries = Vec::new();
    for name in names {
        let mut entry = archive
            .by_name(&name)
            .with_context(|| format!("{name} (zip)"))?;
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .with_context(|| format!("{name} (zip)"))?;
        entries.push((name, Ok(bytes)));
    }
    Ok(entries)
}

fn read_libapps_tolerant(src: &Source) -> Result<Entries> {
    let zip = src.tolerant()?;
    let mut entries = Vec::new();
    for (index, entry) in zip.entries().iter().enumerate() {
        if is_libapp(&entry.name) {
            let bytes = zip.read(index).map_err(|e| format!("{e:#}"));
            entries.push((entry.name.clone(), bytes));
        }
    }
    Ok(entries)
}

fn is_libapp(name: &str) -> bool {
    let mut parts = name.split('/');
    parts.next() == Some("lib")
        && parts.next().is_some_and(|abi| !abi.is_empty())
        && parts.next() == Some(LIBAPP)
        && parts.next().is_none()
}

fn analyze_lib(
    path: &str,
    bytes: &[u8],
    known: &[KnownVersion],
    options: &DartOptions,
) -> LibReport {
    let mut lib = LibReport {
        path: path.to_string(),
        split: None,
        sha256: format!("{:x}", Sha256::digest(bytes)),
        size: bytes.len() as u64,
        sections: Vec::new(),
        missing_symbols: Vec::new(),
        strings_unavailable: None,
        anomalies: Vec::new(),
    };
    if !bytes.starts_with(ELF_MAGIC) {
        note(&mut lib.anomalies, "not_elf", "magic 7F 45 4C 46 absent");
        lib.strings_unavailable = Some(ELF_UNREADABLE);
    } else {
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            inspect(bytes, known, options, &mut lib)
        }));
        let failure = match outcome {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(e.to_string()),
            Err(_) => {
                note(
                    &mut lib.anomalies,
                    "partial_after_panic",
                    "sections, missing_symbols et anomalies peuvent être incomplets",
                );
                Some("panique pendant l'analyse".to_string())
            }
        };
        if let Some(reason) = failure {
            note(&mut lib.anomalies, ELF_UNREADABLE, reason);
            lib.strings_unavailable = Some(ELF_UNREADABLE);
        }
    }
    lib
}

fn inspect(
    bytes: &[u8],
    known: &[KnownVersion],
    options: &DartOptions,
    lib: &mut LibReport,
) -> object::read::Result<()> {
    let parsed = parse_elf(bytes)?;
    lib.anomalies.extend(parsed.anomalies.iter().cloned());
    let image = &parsed.image;
    let word_size = image.ptr_size as usize;
    let defined: Vec<(&str, u64)> = parsed
        .symbols
        .iter()
        .chain(&parsed.local_symbols)
        .filter(|s| s.defined)
        .map(|s| (s.name.as_str(), s.value))
        .collect();
    let mut blobs = Vec::new();
    for name in SYMBOLS {
        match parsed.symbols.iter().find(|s| s.defined && s.name == name) {
            Some(symbol) => {
                let blob = from_symbol(image, symbol, &defined, known, &mut lib.anomalies);
                blobs.push(blob);
            }
            None => lib.missing_symbols.push(name),
        }
    }
    if !blobs.iter().any(|b| is_data(&b.section.symbol)) {
        blobs.extend(scan_magic(image, known, &mut lib.anomalies));
    }
    index_blobs(&mut blobs);
    for blob in &mut blobs {
        if !is_data(&blob.section.symbol) && blob.section.symbol != HEURISTIC {
            continue;
        }
        frame(blob, &mut lib.anomalies);
        let scan = scan_blob(image.data, blob, known, options, word_size, &mut lib.anomalies);
        blob.section.scan = Some(scan);
    }
    if !blobs.iter().any(|b| b.section.scan.is_some()) {
        lib.strings_unavailable = Some(DATA_BLOB_NOT_FOUND);
    }
    lib.sections = blobs.into_iter().map(|b| b.section).collect();
    Ok(())
}

fn is_data(symbol: &str) -> bool {
    symbol == VM_DATA || symbol == ISOLATE_DATA
}

fn index_blobs(blobs: &mut [Blob]) {
    let mut order: Vec<usize> = (0..blobs.len())
        .filter(|&i| blobs[i].section.file_offset.is_some())
        .collect();
    order.sort_by_key(|&i| blobs[i].section.file_offset);
    for (rank, i) in order.into_iter().enumerate() {
        blobs[i].section.blob_index = Some(rank);
    }
}

/// `serialized` et `data_image` d'un blob de données, d'après son en-tête :
/// `Snapshot::length()` = length + 4 depuis le magic, puis
/// `Snapshot::DataImage()` = magic + RoundUp(length(), kObjectStartAlignment),
/// jusqu'à la fin du blob.
fn frame(blob: &mut Blob, anomalies: &mut Vec<String>) {
    let (Some(range), Some(header), Some(bound)) =
        (&blob.range, &blob.section.header, blob.bound)
    else {
        return;
    };
    let Some(length) = header.length.filter(|_| header.magic_ok) else {
        return;
    };
    let (start, end) = (range.start as u64, range.end as u64);
    let Some(serialized_len) = length.checked_add(MAGIC_SIZE as u64) else {
        return;
    };
    let Some(serialized_end) = start.checked_add(serialized_len) else {
        return;
    };
    blob.section.serialized = Some(Span::new(start, serialized_end));
    if serialized_end > end {
        let detail = format!("{} @ {start:#x}", blob.section.symbol);
        note(anomalies, "serialized_past_blob_end", detail);
        return;
    }
    let image_start = serialized_len
        .checked_next_multiple_of(OBJECT_START_ALIGNMENT)
        .and_then(|n| start.checked_add(n))
        .filter(|&s| s <= end);
    if let Some(image_start) = image_start {
        blob.section.data_image = Some(DataImage {
            start: image_start,
            end,
            size: end - image_start,
            end_bound: bound,
            start_alignment: OBJECT_START_ALIGNMENT,
            start_alignment_source: TAG_SOURCE_READ,
        });
    }
}

fn scan_blob(
    data: &[u8],
    blob: &Blob,
    known: &[KnownVersion],
    options: &DartOptions,
    word_size: usize,
    anomalies: &mut Vec<String>,
) -> BlobScan {
    let mut calibration = None;
    let result = strings_of(
        data,
        blob,
        known,
        options,
        word_size,
        &mut calibration,
        anomalies,
    );
    let (strings, strings_unavailable) = match result {
        Ok(scan) => (Some(scan), None),
        Err(reason) => (None, Some(reason)),
    };
    let not_run = match (&calibration, &options.witnesses, strings_unavailable) {
        (None, Some(values), Some(reason)) => {
            let zoning = zoning_of(data, blob);
            Some(Calibration::not_run(values, reason, zoning.as_ref()))
        }
        _ => None,
    };
    BlobScan {
        calibration: calibration.or(not_run),
        strings,
        strings_unavailable,
    }
}

/// Section porteuse (étendue au blob s'il en déborde), partie sérialisée et
/// image de données. `None` sans partie sérialisée.
fn zoning_of<'a>(data: &'a [u8], blob: &Blob) -> Option<Zoning<'a>> {
    let serialized = blob.section.serialized?;
    let range = blob.range.as_ref()?;
    let hull = match &blob.container {
        Some(c) => c.start.min(range.start)..c.end.max(range.end),
        None => range.clone(),
    };
    Some(Zoning {
        bytes: data.get(hull.clone())?,
        start: hull.start as u64,
        serialized: serialized.start..serialized.end,
        image: blob.section.data_image.map(|d| d.start..d.end),
    })
}

fn from_symbol(
    image: &Image,
    symbol: &DynSymbol,
    defined: &[(&str, u64)],
    known: &[KnownVersion],
    anomalies: &mut Vec<String>,
) -> Blob {
    let name = symbol.name.as_str();
    let section = containing_section(image, symbol.value);
    let file_offset = image.offset_of(symbol.value);
    let size = (symbol.size != 0).then_some(symbol.size);
    if file_offset.is_none() {
        note(
            anomalies,
            "symbol_unmapped",
            format!("{name} @ {:#x}", symbol.value),
        );
    }
    let end =
        file_offset.and_then(|start| blob_end(start, symbol.value, symbol.size, section, defined));
    if size.is_none() {
        let bound = match &end {
            Some(end) => format!("{} ({})", end.bound, end.detail),
            None => "aucune".to_string(),
        };
        note(
            anomalies,
            "symbol_size_zero",
            format!("{name}, borne {bound}"),
        );
    }
    let range = match (file_offset, &end) {
        (Some(start), Some(end)) => bounded(image.data.len(), start, end.at, name, anomalies),
        _ => None,
    };
    if range.is_none() && is_data(name) {
        note(anomalies, "blob_unbounded", name);
    }
    let header = match &range {
        Some(range) if is_data(name) => Some(parse_header(&image.data[range.clone()], known)),
        _ => None,
    };
    let container = section
        .filter(|s| s.has_file_data())
        .and_then(|s| file_range(image.data.len(), s.offset, s.size));
    Blob {
        section: SnapshotSection {
            symbol: name.to_string(),
            blob_index: None,
            file_offset,
            vaddr: symbol.value,
            size,
            elf_section: section.map(|s| s.name.clone()),
            header,
            serialized: None,
            data_image: None,
            scan: None,
        },
        range,
        bound: end.map(|e| e.bound),
        container,
    }
}

/// `[offset, offset + size)` coupé à la fin du fichier, sans anomalie.
fn file_range(len: usize, offset: u64, size: u64) -> Option<Range<usize>> {
    let start = usize::try_from(offset).ok().filter(|&s| s < len)?;
    let end = usize::try_from(offset.checked_add(size)?).unwrap_or(usize::MAX);
    Some(start..end.min(len))
}

/// Fin du blob, en offset de fichier : `st_size` s'il est non nul ; sinon
/// l'adresse du symbole défini suivant dans la même section ; sinon la fin de
/// la section.
fn blob_end(
    start: u64,
    vaddr: u64,
    size: u64,
    section: Option<&Section>,
    defined: &[(&str, u64)],
) -> Option<End> {
    if size != 0 {
        return Some(End {
            at: start.checked_add(size)?,
            bound: BOUND_SYMBOL_SIZE,
            detail: format!("st_size {size:#x}"),
        });
    }
    let section = section.filter(|s| s.has_file_data())?;
    let next = defined
        .iter()
        .filter(|&&(_, v)| {
            v > vaddr
                && v.checked_sub(section.addr)
                    .is_some_and(|d| d < section.size)
        })
        .min_by_key(|&&(_, v)| v);
    match next {
        Some(&(next, at)) => Some(End {
            at: start.checked_add(at - vaddr)?,
            bound: BOUND_NEXT_SYMBOL,
            detail: format!("{next} @ {at:#x}"),
        }),
        None => Some(End {
            at: section.offset.checked_add(section.size)?,
            bound: BOUND_SECTION_END,
            detail: section.name.clone(),
        }),
    }
}

fn containing_section<'a>(image: &'a Image, vaddr: u64) -> Option<&'a Section> {
    image
        .sections
        .iter()
        .find(|s| s.has(elf::SHF_ALLOC) && vaddr.checked_sub(s.addr).is_some_and(|d| d < s.size))
}

fn bounded(
    len: usize,
    start: u64,
    end: u64,
    name: &str,
    anomalies: &mut Vec<String>,
) -> Option<Range<usize>> {
    let start = usize::try_from(start).ok().filter(|&s| s < len)?;
    let end = usize::try_from(end).unwrap_or(usize::MAX);
    if end > len {
        note(anomalies, "blob_past_eof", name);
    }
    Some(start..end.min(len))
}

fn scan_magic(image: &Image, known: &[KnownVersion], anomalies: &mut Vec<String>) -> Vec<Blob> {
    let mut found = Vec::new();
    let mut rejected = 0usize;
    for s in &image.sections {
        if !s.has(elf::SHF_ALLOC) || s.has(elf::SHF_WRITE) || !s.has_file_data() {
            continue;
        }
        let (blobs, n) = magic_blobs(image.data, s, known, anomalies);
        found.extend(blobs);
        rejected += n;
    }
    if rejected > 0 {
        note(anomalies, "heuristic_magic_rejected", rejected);
    }
    found
}

/// Blobs à en-tête cohérent d'une section, chacun borné par le magic du
/// suivant, le dernier par la fin de la section ; et le nombre de magics écartés.
fn magic_blobs(
    data: &[u8],
    s: &Section,
    known: &[KnownVersion],
    anomalies: &mut Vec<String>,
) -> (Vec<Blob>, usize) {
    let Some(end) = s.offset.checked_add(s.size) else {
        return (Vec::new(), 0);
    };
    let Some(range) = bounded(data.len(), s.offset, end, &s.name, anomalies) else {
        return (Vec::new(), 0);
    };
    let bytes = &data[range.clone()];
    let mut starts = Vec::new();
    let mut rejected = 0usize;
    let mut at = ((MAGIC_ALIGN - s.addr % MAGIC_ALIGN) % MAGIC_ALIGN) as usize;
    while at + MAGIC_SIZE <= bytes.len() {
        if bytes[at..at + MAGIC_SIZE] == MAGIC {
            let header = parse_header(&bytes[at..], known);
            if is_coherent(&header, bytes.len() - at) {
                starts.push((at, header));
            } else {
                rejected += 1;
            }
        }
        at += MAGIC_ALIGN as usize;
    }
    let nexts: Vec<Option<usize>> = starts.iter().skip(1).map(|(at, _)| Some(*at)).collect();
    let blobs = starts
        .into_iter()
        .zip(nexts.into_iter().chain(std::iter::once(None)))
        .map(|((at, header), next)| {
            let (end, bound) = match next {
                Some(next) => (next, BOUND_NEXT_MAGIC),
                None => (bytes.len(), BOUND_SECTION_END),
            };
            Blob {
                section: SnapshotSection {
                    symbol: HEURISTIC.to_string(),
                    blob_index: None,
                    file_offset: Some((range.start + at) as u64),
                    vaddr: s.addr + at as u64,
                    size: None,
                    elf_section: Some(s.name.clone()),
                    header: Some(header),
                    serialized: None,
                    data_image: None,
                    scan: None,
                },
                range: Some(range.start + at..range.start + end),
                bound: Some(bound),
                container: Some(range.clone()),
            }
        })
        .collect();
    (blobs, rejected)
}

fn is_coherent(header: &SnapshotHeader, remaining: usize) -> bool {
    let (Some(length), Some(kind), Some(_), Some(features)) = (
        header.length,
        header.kind_raw,
        &header.version_hash,
        &header.features,
    ) else {
        return false;
    };
    let consumed = (FEATURES_OFFSET + features.len() + 1) as u64;
    let total = length.checked_add(MAGIC_SIZE as u64);
    header.magic_ok
        && kind <= MAX_KIND
        && total.is_some_and(|t| t >= consumed && t <= remaining as u64)
}

/// En-tête d'un blob de données. Chaque champ est lu indépendamment : un champ
/// illisible vaut `None` et laisse son code dans `errors`.
pub fn parse_header(blob: &[u8], known: &[KnownVersion]) -> SnapshotHeader {
    let mut errors = Vec::new();
    let magic = read_u32(blob, 0);
    let magic_ok = blob.get(..MAGIC_SIZE) == Some(&MAGIC[..]);
    match magic {
        None => errors.push(TRUNCATED_AT_MAGIC),
        Some(_) if !magic_ok => errors.push(MAGIC_MISMATCH),
        Some(_) => {}
    }
    let length = read_u64(blob, LENGTH_OFFSET);
    if length.is_none() {
        errors.push(TRUNCATED_AT_LENGTH);
    }
    let kind_raw = read_u64(blob, KIND_OFFSET);
    if kind_raw.is_none() {
        errors.push(TRUNCATED_AT_KIND);
    }
    let version_hash = match blob.get(HEADER_SIZE..FEATURES_OFFSET) {
        None => {
            errors.push(TRUNCATED_AT_VERSION_HASH);
            None
        }
        Some(raw) if raw.iter().all(u8::is_ascii_hexdigit) => {
            Some(String::from_utf8_lossy(raw).into_owned())
        }
        Some(_) => {
            errors.push(VERSION_HASH_NOT_HEX);
            None
        }
    };
    let features = match version_hash {
        Some(_) => parse_features(blob, &mut errors),
        None => {
            errors.push(FEATURES_OFFSET_UNKNOWN);
            None
        }
    };
    let compressed_pointers = features
        .as_deref()
        .and_then(|f| compressed_pointers(f, &mut errors));
    let version = version_hash.as_deref().and_then(|h| lookup(known, h));
    let kind = kind_raw.map(|raw| match version.and_then(|v| v.kinds) {
        Some(kinds) => kinds.label(raw),
        None => unknown_kind(raw),
    });
    SnapshotHeader {
        magic: magic.map(|m| format!("{m:#010x}")),
        magic_ok,
        length,
        kind_raw,
        kind,
        version_hash,
        known_version: version.map(|v| v.label),
        features,
        compressed_pointers,
        errors,
    }
}

/// Seuls les mots exacts `compressed-pointers` / `no-compressed-pointers` comptent.
fn compressed_pointers(features: &str, errors: &mut Vec<&'static str>) -> Option<bool> {
    let has = |marker: &str| features.split_ascii_whitespace().any(|w| w == marker);
    match (has(COMPRESSED_POINTERS), has(NO_COMPRESSED_POINTERS)) {
        (true, false) => Some(true),
        (false, true) => Some(false),
        (true, true) => {
            errors.push(COMPRESSED_POINTERS_CONTRADICTORY);
            None
        }
        (false, false) => None,
    }
}

fn parse_features(blob: &[u8], errors: &mut Vec<&'static str>) -> Option<String> {
    let tail = blob.get(FEATURES_OFFSET..).unwrap_or(&[]);
    let Some(end) = tail.iter().position(|&b| b == 0) else {
        errors.push(FEATURES_UNTERMINATED);
        return None;
    };
    match std::str::from_utf8(&tail[..end]) {
        Ok(features) => Some(features.to_string()),
        Err(_) => {
            errors.push(FEATURES_NOT_UTF8);
            None
        }
    }
}

fn lookup<'a>(known: &'a [KnownVersion], hash: &str) -> Option<&'a KnownVersion> {
    known.iter().find(|v| v.version_hash == hash)
}

fn unknown_kind(raw: u64) -> String {
    format!("unknown({raw})")
}

/// Garde-fous d'un blob de données, calibration, choix de la disposition, puis
/// balayage de son image de données. `calibration` reçoit le bloc de
/// calibration dès qu'elle a tourné.
fn strings_of(
    data: &[u8],
    blob: &Blob,
    known: &[KnownVersion],
    options: &DartOptions,
    word_size: usize,
    calibration: &mut Option<Calibration>,
    anomalies: &mut Vec<String>,
) -> std::result::Result<StringScan, &'static str> {
    let (Some(_), Some(header), Some(bound)) = (&blob.range, &blob.section.header, blob.bound)
    else {
        return Err(DATA_BLOB_UNBOUNDED);
    };
    if !header.magic_ok {
        return Err(MAGIC_MISMATCH);
    }
    let blob_bound = if blob.section.symbol == HEURISTIC {
        BOUND_HEADER_LENGTH
    } else {
        bound
    };
    if blob_bound == BOUND_SECTION_END {
        return Err(DATA_BLOB_SIZE_UNKNOWN);
    }
    let Some(image) = blob.section.data_image.filter(|d| d.size > 0) else {
        return Err(DATA_IMAGE_EMPTY);
    };
    let Some(zoning) = zoning_of(data, blob) else {
        return Err(DATA_IMAGE_EMPTY);
    };
    if let Some(values) = &options.witnesses {
        let hash = header.version_hash.as_deref();
        let compressed = header.compressed_pointers;
        *calibration = Some(calibrate(&zoning, word_size, compressed, values, hash));
    }
    let calibrated = calibration.as_ref().and_then(Calibration::layout);
    let table = header
        .version_hash
        .as_deref()
        .and_then(|h| lookup(known, h));
    let (heap, source) = match (calibrated, table) {
        (Some(c), Some(t)) => {
            if c != t.heap {
                let detail = format!("calibrated {c:?} ; table {:?}", t.heap);
                note(anomalies, "layout_disagreement", detail);
            }
            (c, LAYOUT_CALIBRATED)
        }
        (Some(c), None) => (c, LAYOUT_CALIBRATED),
        (None, Some(t)) => (t.heap, LAYOUT_TABLE),
        (None, None) if header.version_hash.is_none() => return Err(VERSION_HASH_UNREADABLE),
        (None, None) => return Err(UNSUPPORTED_SNAPSHOT_VERSION),
    };
    let mut violations = heap.violations();
    if heap.word_size != word_size {
        violations.push(format!(
            "word_size {} ≠ taille de pointeur de l'ELF {word_size}",
            heap.word_size
        ));
    }
    if !violations.is_empty() {
        let detail = format!("{source} : {}", violations.join(" ; "));
        note(anomalies, INVALID_HEAP_LAYOUT, detail);
        return Err(INVALID_HEAP_LAYOUT);
    }
    Ok(scan_strings(
        zoning.image_bytes(),
        image.start,
        &heap,
        source,
        blob_bound,
        options.max_rows,
    ))
}

/// `heap` doit avoir passé [`HeapLayout::violations`]. `blob` est l'image de
/// données, qui commence à l'offset de fichier `image_file_offset`.
fn scan_strings(
    blob: &[u8],
    image_file_offset: u64,
    heap: &HeapLayout,
    layout_source: &'static str,
    blob_bound: &'static str,
    max_rows: usize,
) -> StringScan {
    let mut scan = StringScan {
        heuristic: true,
        method: SCAN_METHOD,
        blob_bound,
        layout_source,
        layout: *heap,
        stride: heap.word_size,
        candidates: 0,
        accepted: 0,
        rejected: REJECT_REASONS.iter().map(|&r| (r, 0)).collect(),
        entries_total: 0,
        entries_returned: 0,
        truncated: false,
        entries: Vec::new(),
    };
    let cid_mask = mask(heap.class_id_tag_bits);
    let mut at = 0usize;
    while let Some(tags) = slice(blob, at, heap.word_size).and_then(read_le) {
        let cid = (tags >> heap.class_id_tag_pos) & cid_mask;
        let encoding = if cid == heap.one_byte_string_cid {
            Some((ONE_BYTE, 1))
        } else if cid == heap.two_byte_string_cid {
            Some((TWO_BYTE, 2))
        } else {
            None
        };
        if let Some((encoding, unit)) = encoding {
            scan.candidates += 1;
            match string_at(blob, at, tags, unit, heap) {
                Ok((length, value)) => {
                    scan.accepted += 1;
                    if max_rows == 0 || scan.entries.len() < max_rows {
                        scan.entries.push(StringEntry {
                            image_offset: at as u64,
                            file_offset: image_file_offset + at as u64,
                            encoding,
                            length,
                            value,
                        });
                    }
                }
                Err(reason) => *scan.rejected.entry(reason).or_default() += 1,
            }
        }
        at += heap.word_size;
    }
    scan.entries_total = scan.accepted;
    scan.entries_returned = scan.entries.len() as u64;
    scan.truncated = scan.entries_total > scan.entries_returned;
    scan
}

fn string_at(
    blob: &[u8],
    at: usize,
    tags: u64,
    unit: usize,
    heap: &HeapLayout,
) -> std::result::Result<(u64, String), &'static str> {
    let field = at
        .checked_add(heap.length_offset)
        .and_then(|start| slice(blob, start, heap.length_width))
        .and_then(read_le)
        .ok_or(REJECT_TRUNCATED_FIELDS)?;
    if field & 1 != 0 {
        return Err(REJECT_LENGTH_NOT_SMI);
    }
    let length = smi_value(field, heap.length_width);
    let length = u64::try_from(length).map_err(|_| REJECT_LENGTH_NEGATIVE)?;
    let data_len = usize::try_from(length)
        .ok()
        .and_then(|n| n.checked_mul(unit))
        .ok_or(REJECT_LENGTH_OUT_OF_BLOB)?;
    let data = at
        .checked_add(heap.data_offset)
        .and_then(|start| slice(blob, start, data_len))
        .ok_or(REJECT_LENGTH_OUT_OF_BLOB)?;
    let unaligned = heap.data_offset + data_len;
    let (pos, bits) = (heap.size_tag_pos, heap.size_tag_bits);
    if !size_tag_matches(tags, unaligned, pos, bits, heap.object_alignment) {
        return Err(REJECT_SIZE_TAG_MISMATCH);
    }
    let value = if unit == 1 {
        data.iter().map(|&b| char::from(b)).collect()
    } else {
        let units: Vec<u16> = data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16(&units).map_err(|_| REJECT_UNDECODABLE_UTF16)?
    };
    Ok((length, value))
}

/// Smi : valeur décalée d'un bit, bit 0 à 0. Sur 4 octets, signée 32 bits.
fn smi_value(raw: u64, width: usize) -> i64 {
    if width == 4 {
        i64::from(raw as u32 as i32) >> 1
    } else {
        (raw as i64) >> 1
    }
}

fn smi_equals(raw: u64, width: usize, value: u64) -> bool {
    raw & 1 == 0 && u64::try_from(smi_value(raw, width)).ok() == Some(value)
}

fn fits(pos: u32, bits: u32, word_size: usize) -> bool {
    u64::from(pos) + u64::from(bits) <= 8 * word_size as u64
}

/// Une taille d'objet trop grande pour le champ de taille y est codée 0.
fn size_tag_matches(tags: u64, unaligned: usize, pos: u32, bits: u32, alignment: usize) -> bool {
    let alignment = alignment.max(1) as u64;
    let size = (unaligned as u64).div_ceil(alignment) * alignment;
    let size_mask = mask(bits);
    let tag = (tags >> pos) & size_mask;
    if tag == 0 {
        size > size_mask.saturating_mul(alignment)
    } else {
        tag.checked_mul(alignment) == Some(size)
    }
}

struct WitnessSpec {
    value: String,
    encoding: &'static str,
    unit: usize,
    length: u64,
    needle: Vec<u8>,
}

impl WitnessSpec {
    fn new(value: &str) -> Self {
        let latin1: Option<Vec<u8>> = value
            .chars()
            .map(|c| u8::try_from(u32::from(c)).ok())
            .collect();
        match latin1 {
            Some(bytes) => WitnessSpec {
                value: value.to_string(),
                encoding: ONE_BYTE,
                unit: 1,
                length: bytes.len() as u64,
                needle: bytes,
            },
            None => {
                let units: Vec<u16> = value.encode_utf16().collect();
                WitnessSpec {
                    value: value.to_string(),
                    encoding: TWO_BYTE,
                    unit: 2,
                    length: units.len() as u64,
                    needle: units.iter().flat_map(|u| u.to_le_bytes()).collect(),
                }
            }
        }
    }
}

fn witness_specs(values: &[String]) -> Vec<WitnessSpec> {
    let mut seen = BTreeSet::new();
    values
        .iter()
        .filter(|v| seen.insert(v.as_str()))
        .map(|v| WitnessSpec::new(v))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    length_offset: usize,
    length_width: usize,
    data_offset: usize,
    tag: usize,
    alignment: usize,
}

/// Par témoin : class id candidat -> premier objet qui le porte.
type Support = BTreeMap<usize, BTreeMap<u64, usize>>;

/// (class id one_byte, class id two_byte, encodage dont le class id est déduit).
type CidPair = (u64, u64, Option<&'static str>);

impl Calibration {
    /// Avec `zoning`, la répartition des témoins par zone est rendue quand même.
    fn not_run(values: &[String], reason: &'static str, zoning: Option<&Zoning>) -> Self {
        let witnesses: Vec<Witness> = witness_specs(values)
            .iter()
            .map(|spec| witness(spec, zoning, None))
            .collect();
        let (found, in_image) = tally(&witnesses);
        let zoned = zoning.is_some();
        Calibration {
            outcome: NOT_RUN,
            not_run_reason: Some(reason),
            witnesses_total: witnesses.len(),
            witnesses_found: zoned.then_some(found),
            witnesses_in_data_image: zoned.then_some(in_image),
            witnesses_explained: None,
            data_image_verdict: data_image_verdict(&witnesses),
            witnesses,
            word_size: None,
            compressed_pointers: None,
            length_fields_tried: Vec::new(),
            object_alignments_tried: OBJECT_ALIGNMENTS.to_vec(),
            tag_layouts_tried: TAG_LAYOUTS.to_vec(),
            inferred: Vec::new(),
            known_version_literal: None,
        }
    }

    fn layout(&self) -> Option<HeapLayout> {
        if self.outcome == CALIBRATED {
            self.inferred.first().map(|i| i.layout)
        } else {
            None
        }
    }
}

/// `compressed_pointers` lu dans `features` fixe la largeur : 4 avec pointeurs
/// compressés, `word_size` sans.
fn length_fields(word_size: usize, compressed_pointers: Option<bool>) -> Vec<LengthField> {
    let fixed = compressed_pointers.map(|on| if on { 4 } else { word_size });
    LENGTH_FIELDS
        .iter()
        .filter(|&&(offset, width)| offset >= word_size && width <= word_size)
        .filter(|&&(_, width)| fixed.is_none_or(|w| w == width))
        .map(|&(offset, width)| LengthField { offset, width })
        .collect()
}

fn witness(spec: &WitnessSpec, zoning: Option<&Zoning>, examined: Option<usize>) -> Witness {
    let zones = zoning.map(|z| z.zones(&spec.needle));
    Witness {
        value: spec.value.clone(),
        encoding: spec.encoding,
        length: spec.length,
        occurrences: zones.as_ref().map(Zones::total),
        occurrences_examined: examined,
        zones,
        explained: false,
    }
}

/// (témoins localisés dans la section, témoins présents dans l'image de données).
fn tally(witnesses: &[Witness]) -> (usize, usize) {
    let found = witnesses
        .iter()
        .filter(|w| w.occurrences.unwrap_or(0) > 0)
        .count();
    let in_image = witnesses
        .iter()
        .filter(|w| w.zones.as_ref().is_some_and(|z| z.data_image.count > 0))
        .count();
    (found, in_image)
}

fn data_image_verdict(witnesses: &[Witness]) -> Option<&'static str> {
    let zones: Vec<&Zones> = witnesses
        .iter()
        .map(|w| w.zones.as_ref())
        .collect::<Option<_>>()?;
    if zones.is_empty() {
        return None;
    }
    let (found, in_image) = tally(witnesses);
    Some(if found == 0 {
        VERDICT_NO_WITNESS_FOUND
    } else if in_image == zones.len() {
        VERDICT_ALL_IN_DATA_IMAGE
    } else if in_image == 0 {
        VERDICT_NONE_IN_DATA_IMAGE
    } else {
        VERDICT_PARTLY_IN_DATA_IMAGE
    })
}

/// Déduit la disposition des chaînes de l'emplacement des témoins dans l'image
/// de données ; compte leurs occurrences dans toute la section, par zone.
fn calibrate(
    zoning: &Zoning,
    word_size: usize,
    compressed_pointers: Option<bool>,
    values: &[String],
    version_hash: Option<&str>,
) -> Calibration {
    let specs = witness_specs(values);
    let fields = length_fields(word_size, compressed_pointers);
    let blob = zoning.image_bytes();
    let image_start = zoning.image.as_ref().map_or(0, |r| r.start);
    let tag_layouts: Vec<(usize, TagLayout)> = TAG_LAYOUTS
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, t)| {
            fits(t.size_tag_pos, t.size_tag_bits, word_size)
                && fits(t.class_id_tag_pos, t.class_id_tag_bits, word_size)
        })
        .collect();
    let mut witnesses = Vec::new();
    let mut support: BTreeMap<Key, Support> = BTreeMap::new();
    for (index, spec) in specs.iter().enumerate() {
        let (_, examined) = find(blob, &spec.needle, MAX_EXAMINED_OCCURRENCES);
        for &d in &examined {
            for (object, field, tags) in headers_before(blob, d, word_size, &fields, spec.length) {
                let unaligned = (d - object) as u64 + spec.length * spec.unit as u64;
                let Ok(unaligned) = usize::try_from(unaligned) else {
                    continue;
                };
                for &(tag, layout) in &tag_layouts {
                    let cid = (tags >> layout.class_id_tag_pos) & mask(layout.class_id_tag_bits);
                    if cid == 0 {
                        continue;
                    }
                    for alignment in OBJECT_ALIGNMENTS {
                        let (pos, bits) = (layout.size_tag_pos, layout.size_tag_bits);
                        if !size_tag_matches(tags, unaligned, pos, bits, alignment) {
                            continue;
                        }
                        let key = Key {
                            length_offset: field.offset,
                            length_width: field.width,
                            data_offset: d - object,
                            tag,
                            alignment,
                        };
                        support
                            .entry(key)
                            .or_default()
                            .entry(index)
                            .or_default()
                            .entry(cid)
                            .or_insert(object);
                    }
                }
            }
        }
        witnesses.push(witness(spec, Some(zoning), Some(examined.len())));
    }
    for (index, witness) in witnesses.iter_mut().enumerate() {
        witness.explained = support.values().any(|s| s.contains_key(&index));
    }
    let inferred = survivors(&specs, &support, word_size, image_start);
    let (found, in_image) = tally(&witnesses);
    let explained = witnesses.iter().filter(|w| w.explained).count();
    let outcome = if specs.len() < MIN_WITNESSES {
        INSUFFICIENT_WITNESSES
    } else if found == 0 {
        WITNESS_NOT_FOUND
    } else if found < specs.len() {
        WITNESSES_NOT_ALL_FOUND
    } else if in_image == 0 {
        WITNESSES_OUTSIDE_DATA_IMAGE
    } else if inferred.is_empty() {
        NO_LAYOUT_EXPLAINS_WITNESSES
    } else if inferred.len() > 1 {
        AMBIGUOUS_LAYOUT
    } else {
        CALIBRATED
    };
    let known_version_literal = match (outcome, version_hash, inferred.first()) {
        (CALIBRATED, Some(hash), Some(only)) => Some(known_version_literal(hash, &only.layout)),
        _ => None,
    };
    Calibration {
        outcome,
        not_run_reason: None,
        witnesses_total: specs.len(),
        witnesses_found: Some(found),
        witnesses_in_data_image: Some(in_image),
        witnesses_explained: Some(explained),
        data_image_verdict: data_image_verdict(&witnesses),
        witnesses,
        word_size: Some(word_size),
        compressed_pointers,
        length_fields_tried: fields,
        object_alignments_tried: OBJECT_ALIGNMENTS.to_vec(),
        tag_layouts_tried: TAG_LAYOUTS.to_vec(),
        inferred,
        known_version_literal,
    }
}

/// Débuts des occurrences de `needle` dans `hay`, chevauchantes comprises, dans
/// l'ordre.
fn occurrences<'a>(hay: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    let mut at = 0;
    std::iter::from_fn(move || {
        let &first = needle.first()?;
        let starts = hay.len().checked_sub(needle.len())? + 1;
        while at < starts {
            let start = at + hay[at..starts].iter().position(|&b| b == first)?;
            at = start + 1;
            if hay[start..start + needle.len()] == *needle {
                return Some(start);
            }
        }
        None
    })
}

/// Nombre total d'occurrences de `needle`, chevauchantes comprises, et les
/// `keep` premières.
fn find(blob: &[u8], needle: &[u8], keep: usize) -> (usize, Vec<usize>) {
    let mut count = 0;
    let mut kept = Vec::new();
    for start in occurrences(blob, needle) {
        count += 1;
        if kept.len() < keep {
            kept.push(start);
        }
    }
    (count, kept)
}

/// Débuts d'objet `o` alignés sur `word_size`, à au plus [`HEADER_WINDOW`]
/// octets avant le contenu `d`, dont un champ de `fields` est un Smi égal à
/// `length`. Rend `(o, champ, tags)`.
fn headers_before(
    blob: &[u8],
    d: usize,
    word_size: usize,
    fields: &[LengthField],
    length: u64,
) -> Vec<(usize, LengthField, u64)> {
    let mut found = Vec::new();
    let Some(last) = d.checked_sub(word_size) else {
        return found;
    };
    let mut object = last - last % word_size;
    while d - object <= HEADER_WINDOW {
        if let Some(tags) = slice(blob, object, word_size).and_then(read_le) {
            for &field in fields {
                if field.offset + field.width > d - object {
                    continue;
                }
                let Some(raw) = slice(blob, object + field.offset, field.width).and_then(read_le)
                else {
                    continue;
                };
                if smi_equals(raw, field.width, length) {
                    found.push((object, field, tags));
                }
            }
        }
        if object < word_size {
            break;
        }
        object -= word_size;
    }
    found
}

/// Dispositions qui expliquent TOUS les témoins, avec un class id commun aux
/// témoins de même encodage. L'encodage sans témoin reçoit l'autre class id ± 1.
fn survivors(
    specs: &[WitnessSpec],
    support: &BTreeMap<Key, Support>,
    word_size: usize,
    image_start: u64,
) -> Vec<InferredLayout> {
    let mut out = Vec::new();
    if specs.is_empty() {
        return out;
    }
    for (key, per_witness) in support {
        if per_witness.len() != specs.len() {
            continue;
        }
        let common = |encoding: &str| -> Option<BTreeSet<u64>> {
            let mut sets = specs
                .iter()
                .enumerate()
                .filter(|(_, spec)| spec.encoding == encoding)
                .map(|(index, _)| {
                    per_witness
                        .get(&index)
                        .map(|cids| cids.keys().copied().collect::<BTreeSet<u64>>())
                        .unwrap_or_default()
                });
            let first = sets.next()?;
            Some(sets.fold(first, |acc, set| &acc & &set))
        };
        let (one, two) = (common(ONE_BYTE), common(TWO_BYTE));
        let pairs: Vec<CidPair> = match (one, two) {
            (Some(one), Some(two)) => one
                .iter()
                .flat_map(|&a| two.iter().map(move |&b| (a, b, None)))
                .collect(),
            (Some(one), None) => one.iter().map(|&a| (a, a + 1, Some(TWO_BYTE))).collect(),
            (None, Some(two)) => two
                .iter()
                .filter_map(|&b| Some((b.checked_sub(1)?, b, Some(ONE_BYTE))))
                .collect(),
            (None, None) => Vec::new(),
        };
        let tag = TAG_LAYOUTS[key.tag];
        for (one_byte, two_byte, derived_cid) in pairs {
            let evidence = specs
                .iter()
                .enumerate()
                .filter_map(|(index, spec)| {
                    let cid = if spec.encoding == ONE_BYTE {
                        one_byte
                    } else {
                        two_byte
                    };
                    let object = *per_witness.get(&index)?.get(&cid)?;
                    Some(Evidence {
                        witness: spec.value.clone(),
                        image_offset: object as u64,
                        file_offset: image_start + object as u64,
                    })
                })
                .collect();
            out.push(InferredLayout {
                layout: HeapLayout {
                    word_size,
                    object_alignment: key.alignment,
                    size_tag_pos: tag.size_tag_pos,
                    size_tag_bits: tag.size_tag_bits,
                    class_id_tag_pos: tag.class_id_tag_pos,
                    class_id_tag_bits: tag.class_id_tag_bits,
                    one_byte_string_cid: one_byte,
                    two_byte_string_cid: two_byte,
                    length_offset: key.length_offset,
                    length_width: key.length_width,
                    data_offset: key.data_offset,
                },
                derived_cid,
                evidence,
            });
        }
    }
    out
}

fn known_version_literal(version_hash: &str, heap: &HeapLayout) -> String {
    let HeapLayout {
        word_size,
        object_alignment,
        size_tag_pos,
        size_tag_bits,
        class_id_tag_pos,
        class_id_tag_bits,
        one_byte_string_cid,
        two_byte_string_cid,
        length_offset,
        length_width,
        data_offset,
    } = *heap;
    format!(
        "KnownVersion {{
    version_hash: \"{version_hash}\",
    label: \"calibrated\",
    kinds: None,
    heap: HeapLayout {{
        word_size: {word_size},
        object_alignment: {object_alignment},
        size_tag_pos: {size_tag_pos},
        size_tag_bits: {size_tag_bits},
        class_id_tag_pos: {class_id_tag_pos},
        class_id_tag_bits: {class_id_tag_bits},
        one_byte_string_cid: {one_byte_string_cid:#x},
        two_byte_string_cid: {two_byte_string_cid:#x},
        length_offset: {length_offset},
        length_width: {length_width},
        data_offset: {data_offset},
    }},
}},"
    )
}

fn mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn slice(bytes: &[u8], start: usize, len: usize) -> Option<&[u8]> {
    bytes.get(start..start.checked_add(len)?)
}

fn read_le(bytes: &[u8]) -> Option<u64> {
    match bytes.len() {
        4 => Some(u64::from(u32::from_le_bytes(bytes.try_into().ok()?))),
        8 => Some(u64::from_le_bytes(bytes.try_into().ok()?)),
        _ => None,
    }
}

fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(slice(bytes, at, 4)?.try_into().ok()?))
}

fn read_u64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(slice(bytes, at, 8)?.try_into().ok()?))
}

fn note(anomalies: &mut Vec<String>, code: &str, detail: impl std::fmt::Display) {
    anomalies.push(format!("{code}: {detail}"));
}

impl DartSnapshotReport {
    fn build(sha256: String, libraries: Vec<LibReport>, errors: Vec<String>) -> Self {
        let mut summary = Summary {
            libraries: libraries.len(),
            ..Summary::default()
        };
        let mut hashes = BTreeSet::new();
        let mut unknown = BTreeSet::new();
        for lib in &libraries {
            let mut calibrated = false;
            let mut with_strings = false;
            for s in &lib.sections {
                summary.sections_found += 1;
                if s.symbol == HEURISTIC {
                    summary.located_by_heuristic += 1;
                } else {
                    summary.located_by_symbol += 1;
                }
                if let Some(scan) = &s.scan {
                    summary.data_blobs += 1;
                    calibrated |= scan
                        .calibration
                        .as_ref()
                        .is_some_and(|c| c.outcome == CALIBRATED);
                    if let Some(strings) = &scan.strings {
                        with_strings = true;
                        summary.string_candidates += strings.candidates;
                        summary.strings_accepted += strings.accepted;
                        summary.strings_rejected += strings.rejected.values().sum::<u64>();
                        summary.strings_returned += strings.entries_returned;
                    }
                }
                let Some(header) = &s.header else {
                    continue;
                };
                summary.headers_parsed += 1;
                if header.magic_ok {
                    summary.headers_magic_ok += 1;
                }
                if let Some(hash) = &header.version_hash {
                    hashes.insert(hash.clone());
                    if header.known_version.is_none() {
                        unknown.insert(hash.clone());
                    }
                }
            }
            if calibrated {
                summary.libraries_calibrated += 1;
            }
            if with_strings {
                summary.libraries_with_strings += 1;
            } else {
                summary.libraries_without_strings += 1;
            }
        }
        summary.version_hashes = hashes.into_iter().collect();
        summary.unknown_version_hashes = unknown.into_iter().collect();
        DartSnapshotReport {
            sha256,
            summary,
            libraries,
            errors,
        }
    }
}

const LEGEND: &str = "\
--dart-snapshot : instantané Dart AOT d'une application Flutter. Lecture seule,
rien n'est extrait ni exécuté.
Mode APK : chaque entrée lib/<abi>/libapp.so du base et des splits ABI d'un XAPK ;
aucune autre entrée n'est lue. Archive lue par le crate zip, puis par le lecteur
ZIP tolérant s'il refuse (ouverture, by_name ou read_to_end). Mode ELF brut : un
fichier dont les 4 premiers octets valent 7F 45 4C 46 est lu seul, quel que soit
son nom.
Format lu dans dart-lang/sdk : runtime/vm/snapshot.h (tag 3.5.0 et branche main ;
tag 3.5.0 : Snapshot::length, Snapshot::DataImage), runtime/vm/pointer_tagging.h
(tag 3.5.0 : kObjectStartAlignment = 64), runtime/vm/app_snapshot.cc (tag 3.5.0 :
Serializer::WriteVersionAndFeatures, SnapshotHeaderReader::ReadFeatures),
runtime/vm/raw_object.h (tag 3.5.0 : UntaggedObject::TagBits, UntaggedString),
runtime/vm/class_id.h (tag 3.5.0 : kIllegalCid = 0, kTwoByteStringCid =
kOneByteStringCid + 1). Tous les entiers sont lus en little-endian.

Un blob de données est fait de deux parties consécutives (CALIBRATION, étape 0) : la partie
sérialisée (en-tête puis flux des clusters, sans objets à en-tête) et l'image de
données, où RODataSerializationCluster écrit les objets en lecture seule, chaînes
comprises. Le balayage et la calibration ne lisent que l'image de données.

OPTIONS
  --dart-max-rows N       Aperçu choisi : seules les N premières chaînes retenues,
                          dans l'ordre du blob, sont rendues dans strings.entries.
                          0 = toutes. Défaut 0 : le rapport JSON porte toutes les
                          chaînes retenues ; c'est le seul endroit où elles
                          apparaissent, la sortie texte n'en liste aucune.
  --dart-calibrate TEXTE  Témoin de calibration, répétable (section CALIBRATION).
  --dart-calibrate-file F Témoins depuis un fichier : une chaîne par ligne ; les
                          lignes vides ou blanches et celles qui commencent par #
                          sont ignorées. Un témoin qui commence par # se passe par
                          --dart-calibrate.
  Ces trois options exigent --dart-snapshot. Un témoin vide est refusé.

RAPPORT
  sha256          SHA-256 complet de l'APK (du base pour un XAPK), ou de l'ELF brut.
  summary         Agrégats sur libraries, définis plus bas.
  libraries[]     Un élément par libapp.so lu (ou par ELF brut).
  errors          Entrée d'archive ou split illisible : <entrée> ou <split>!<entrée>,
                  puis la raison. L'élément correspondant manque dans libraries.

RÉSUMÉ (summary)
  libraries               Nombre d'éléments de libraries.
  sections_found          Blobs localisés, toutes bibliothèques confondues.
  located_by_symbol       Dont localisés par un symbole de .dynsym.
  located_by_heuristic    Dont localisés par balayage du magic (symbol = heuristic).
  headers_parsed          Blobs dont l'en-tête a été lu (header non null).
  headers_magic_ok        Dont le magic est celui attendu.
  data_blobs              Blobs de données (BLOB DE DONNÉES), toutes bibliothèques
                          confondues.
  version_hashes          version_hash distincts lus, triés.
  unknown_version_hashes  Ceux qui ne figurent pas dans la table des versions connues.
  libraries_calibrated    Bibliothèques dont au moins un blob de données a
                          calibration.outcome = calibrated.
  libraries_with_strings  Bibliothèques dont au moins un blob de données a strings
                          non null.
  libraries_without_strings
                          Les autres (motifs dans strings_unavailable, de la
                          bibliothèque ou de chaque blob).
  string_candidates, strings_accepted, strings_rejected
                          Sommes, sur tous les blobs de données, de strings.candidates,
                          strings.accepted et des valeurs de strings.rejected. Taux de
                          rejet = strings_rejected / string_candidates.
  strings_returned        Somme de strings.entries_returned : chaînes présentes dans
                          le rapport. Égale à strings_accepted sauf avec
                          --dart-max-rows N, au plus N par blob.

BIBLIOTHÈQUE (libraries[])
  path            Entrée dans l'archive (lib/<abi>/libapp.so), ou nom du fichier brut.
  split           Split XAPK porteur (attribut split de son manifeste). Absent pour le
                  base APK, un APK simple ou un ELF brut.
  sha256, size    SHA-256 complet et taille du contenu décompressé.
  sections[]      Blobs localisés : d'abord ceux trouvés par symbole, dans l'ordre
                  _kDartVmSnapshotData, _kDartVmSnapshotInstructions,
                  _kDartIsolateSnapshotData, _kDartIsolateSnapshotInstructions ; puis,
                  si aucun des deux symboles de données n'est défini, ceux du balayage,
                  section par section, par offset croissant dans chacune. blob_index
                  donne l'ordre des offsets sur toute la bibliothèque.
  missing_symbols Parmi ces quatre symboles, ceux absents de .dynsym ou non définis.
  strings_unavailable
                  Motif pour lequel AUCUN blob de données n'est examiné, null sinon
                  (chaque blob de données porte alors son propre strings_unavailable,
                  section BLOB DE DONNÉES) :
    elf_unreadable                ELF illisible (raison dans anomalies).
    data_blob_not_found           Aucun blob de données : ni _kDartVmSnapshotData ni
                                  _kDartIsolateSnapshotData dans .dynsym, et aucun magic
                                  à en-tête cohérent dans les sections balayées.
                                  Sans blob, ni calibration ni zones : calibration est
                                  absent.
  anomalies       <code>: <détail>. Codes :
    not_elf                   L'entrée libapp.so ne commence pas par 7F 45 4C 46.
    elf_unreadable            En-tête ELF ou program headers illisibles, ou panique.
    partial_after_panic       Panique pendant l'analyse : sections, missing_symbols et
                              anomalies gardent l'état atteint avant elle et peuvent
                              être incomplets.
    section_headers_*, dynamic_unreadable
                              Anomalies du parseur ELF de --native (--native --legend).
                              Sans section headers, ni .dynsym ni balayage : rien n'est
                              localisé.
    symbol_size_zero          st_size du symbole vaut 0 : size est null. Détail :
                              symbole, puis la borne retenue (BORNES), ou aucune.
    symbol_unmapped           Adresse du symbole hors de tout PT_LOAD : file_offset null.
    blob_past_eof             Le blob déborde la fin du fichier ; il est lu jusqu'à elle.
    blob_unbounded            Blob de données non délimitable : header null.
    heuristic_magic_rejected  Occurrences du magic écartées par le balayage parce que
                              l'en-tête qui suit n'est pas cohérent (nombre).
    serialized_past_blob_end  magic + length + 4 dépasse la fin du blob (BORNES) :
                              serialized est rendu tel que l'en-tête le dit,
                              data_image est null. Détail : symbol @ file_offset.
    layout_disagreement       Calibration aboutie ET version_hash dans la table, avec
                              deux dispositions différentes : la calibrée est utilisée
                              (mesure contre saisie). Détail : les deux dispositions.
    invalid_heap_layout       Source (calibrated ou table), puis les règles violées.

BORNES (fin d'un blob ; c'est aussi la fin de son image de données)
  Blob localisé par symbole :
  symbol_size     st_size non nul : le blob fait st_size octets.
  next_symbol     st_size nul : le blob s'arrête à l'adresse du symbole défini suivant
                  (plus petit st_value strictement supérieur, parmi .dynsym et
                  .symtab) dans la même section ELF.
  section_end     st_size nul, aucun symbole suivant dans la section : fin de la
                  section. Suffit pour l'en-tête et les zones, jamais pour le
                  balayage (data_blob_size_unknown).
  Blob localisé par balayage (symbol = heuristic) :
  next_magic      Le blob s'arrête au magic du blob heuristique suivant de la même
                  section.
  section_end     Aucun blob heuristique après lui dans la section : fin de la
                  section. Le début du balayage vient alors de l'en-tête
                  (header_length), et sa fin est celle de la section.
  header_length   Valeur de strings.blob_bound pour un blob heuristique : l'image
                  balayée est bornée par son propre en-tête (début = magic +
                  RoundUp(length + 4, 64)), jamais par le seul magic.

BLOB (sections[])
  symbol          Nom du symbole de .dynsym, ou heuristic pour un blob trouvé par
                  balayage : magic F5 F5 DC DC à une adresse virtuelle multiple de 8,
                  dans une section allouée, non inscriptible, avec contenu dans le
                  fichier. Un candidat n'est retenu que si son en-tête est cohérent :
                  magic, length, kind_raw, version_hash et features tous lus,
                  kind_raw <= 4, et length + 4 couvre au moins l'en-tête, la version et
                  les features sans dépasser la fin de la section. Un blob heuristic
                  n'est jamais nommé _kDartVmSnapshotData ni _kDartIsolateSnapshotData :
                  seul un symbole dit quel blob est celui de la VM ou de l'isolate,
                  ni la position ni la taille ne le disent.
                  Les blobs d'instructions ne commencent pas par le magic : sans
                  symbole ils sont invisibles. C'est attendu, pas un défaut.
  blob_index      Rang du blob par file_offset croissant dans la bibliothèque, à
                  partir de 0 ; null si file_offset est null.
  file_offset     Offset dans le fichier, via les PT_LOAD ; null si non projeté.
  vaddr           Adresse virtuelle (st_value, ou adresse du magic pour heuristic).
  size            st_size du symbole ; null s'il vaut 0, et toujours null pour heuristic.
  elf_section     Section ELF allouée qui contient vaddr ; null si aucune.
  header          En-tête (section EN-TÊTE) pour les blobs de données ; null pour
                  les blobs d'instructions et pour un blob de données non délimitable.
  serialized      Partie sérialisée {start, end, size}, en offsets de fichier :
                  [magic, magic + length + 4), Snapshot::length() = length + 4.
                  null sans en-tête, avec magic_ok false ou length illisible.
  data_image      Image de données {start, end, size, end_bound, start_alignment,
                  start_alignment_source}, en offsets de fichier :
                  start = magic + RoundUp(length + 4, start_alignment), arrondi
                  relatif au magic comme Snapshot::DataImage ; end = fin du blob,
                  end_bound = sa borne (BORNES) ; start_alignment = 64,
                  kObjectStartAlignment ; start_alignment_source = read_sdk_3_5_0,
                  valeur lue dans runtime/vm/pointer_tagging.h au tag 3.5.0. null si
                  serialized est null, si l'arrondi dépasse la fin du blob, ou avec
                  serialized_past_blob_end.
  calibration, strings, strings_unavailable
                  Présents pour les blobs de données seulement (BLOB DE DONNÉES).

BLOB DE DONNÉES
  Tout blob nommé _kDartVmSnapshotData ou _kDartIsolateSnapshotData par son symbole,
  et tout blob heuristic, est examiné séparément : calibration et balayage portent
  sur SON image de données.
  calibration     Avec --dart-calibrate ou --dart-calibrate-file seulement, absent
                  sinon ; présent même quand le balayage est refusé (section
                  CALIBRATION).
  strings         Énumération des chaînes de l'image de données (section CHAÎNES),
                  ou null.
  strings_unavailable
                  Motif de strings null, null sinon. Les garde-fous sont évalués dans
                  cet ordre :
    data_blob_unbounded           Symbole présent mais blob non délimitable (hors fichier,
                                  hors segment chargé, taille nulle sans section).
    magic_mismatch                Le blob ne commence pas par le magic.
    data_blob_size_unknown        Blob localisé par symbole, borné par section_end :
                                  la fin de section déborde sur ce qui suit le blob.
                                  En-tête, serialized, data_image et zones sont rendus,
                                  le balayage et la calibration non.
    data_image_empty              data_image null ou de taille 0 : rien à balayer.
    version_hash_unreadable       Ni calibration aboutie, ni version_hash lisible.
    unsupported_snapshot_version  Ni calibration aboutie, ni version_hash dans la table
                                  des versions connues : la disposition des objets
                                  n'est pas devinée. calibration.outcome dit pourquoi
                                  la calibration, si elle a été demandée, n'a pas abouti.
    invalid_heap_layout           La disposition retenue (calibrée ou de la table)
                                  viole une règle de VALIDATION ; le détail est dans
                                  anomalies. Jamais de balayage sur une disposition
                                  non validée.

EN-TÊTE (header)
  Chaque champ est lu indépendamment ; un champ illisible vaut null et son code est
  dans errors.
  magic           u32 à l'offset 0, en hexadécimal. Attendu 0xdcdcf5f5
                  (Snapshot::kMagicValue), soit les octets F5 F5 DC DC.
  magic_ok        Les 4 premiers octets valent F5 F5 DC DC.
  length          int64 à l'offset 4, tel qu'écrit. Dart y stocke la taille de la
                  partie sérialisée MOINS 4 (Snapshot::set_length) : Snapshot::length()
                  = length + 4. Lu en non signé.
  kind_raw        int64 à l'offset 12 (Snapshot::kKindOffset), lu en non signé.
  kind            Libellé de kind_raw selon la numérotation de l'entrée de la table :
                    tag 3.5.0  0 full, 1 full_core, 2 full_jit, 3 full_aot, 4 none
                    main       0 full, 1 full_jit, 2 full_aot, 3 module
                  unknown(<kind_raw>) si la valeur n'y figure pas, si version_hash
                  n'est pas dans la table, ou si l'entrée ne fixe pas la numérotation
                  (kinds: None, cas de toute entrée issue de la calibration, qui ne
                  voit pas Snapshot::Kind).
  version_hash    Les 32 octets qui suivent l'en-tête de 20 octets, s'ils sont tous des
                  chiffres hexadécimaux ASCII, rendus tels quels. Dart écrit
                  Version::SnapshotString() sans terminateur ; la longueur 32 est
                  supposée, pas lue dans le source.
  known_version   Libellé de l'entrée de la table des versions connues ; null si absente.
  features        Chaîne terminée par NUL qui suit version_hash, rendue telle quelle,
                  sans interprétation.
  compressed_pointers
                  true si features contient le mot compressed-pointers, false s'il
                  contient no-compressed-pointers, null si aucun des deux (ou les
                  deux : compressed_pointers_contradictory). Mots séparés par des
                  blancs, comparés exactement ; le reste de features n'est pas
                  interprété.
  errors          Codes :
    truncated_at_magic, truncated_at_length, truncated_at_kind, truncated_at_version_hash
                              Le blob s'arrête avant la fin du champ nommé.
    magic_mismatch            4 premiers octets lus, différents de F5 F5 DC DC.
    version_hash_not_hex      Les 32 octets ne sont pas tous hexadécimaux.
    features_offset_unknown   version_hash null : la position des features en dépend,
                              elles ne sont pas lues.
    features_unterminated     Aucun NUL avant la fin du blob.
    features_not_utf8         Octets avant le NUL non décodables en UTF-8.
    compressed_pointers_contradictory
                              features porte compressed-pointers ET
                              no-compressed-pointers : compressed_pointers vaut null.

DISPOSITION (strings.layout, calibration.inferred[].layout, table des versions)
  word_size       Taille du mot d'en-tête (tags), en octets ; doit égaler la taille de
                  pointeur de l'ELF (ELFCLASS32 = 4, ELFCLASS64 = 8).
  object_alignment
                  Alignement des tailles d'objet, en octets.
  size_tag_pos, size_tag_bits
                  Position et largeur, en bits, du champ taille dans tags : taille de
                  l'objet / object_alignment, 0 si elle ne tient pas dans le champ.
  class_id_tag_pos, class_id_tag_bits
                  Position et largeur, en bits, du champ class id dans tags.
  one_byte_string_cid, two_byte_string_cid
                  Class id de OneByteString et de TwoByteString.
  length_offset, length_width
                  Offset et largeur, en octets, du champ length (Smi) depuis le début
                  de l'objet ; largeur 4 avec pointeurs compressés, word_size sans
                  (header.compressed_pointers, quand features le dit).
  data_offset     Offset du contenu depuis le début de l'objet.

VALIDATION (règles d'une disposition ; une seule violée suffit à refuser)
  word_size et length_width dans {4, 8} ; length_width <= word_size ; word_size =
  taille de pointeur de l'ELF ; object_alignment puissance de deux non nulle ;
  size_tag_bits et class_id_tag_bits non nuls ; pos + bits <= 8 x word_size pour
  chacun des deux champs ; length_offset >= word_size ; length_offset + length_width
  <= data_offset ; data_offset <= 64 ; one_byte_string_cid différent de
  two_byte_string_cid ; aucun des deux ne vaut 0 (kIllegalCid) ni ne dépasse
  2^class_id_tag_bits - 1.

CHAÎNES (strings) — HEURISTIQUE, faillible par construction
  Les clusters de l'instantané ne sont pas parcourus. L'image de données du blob
  (data_image) est balayée en entier, par pas de stride octets depuis son début ; la
  partie sérialisée ne l'est jamais. À chaque pas, le mot lu est pris pour l'en-tête
  d'un objet ; si son champ class
  id vaut celui de OneByteString ou de TwoByteString pour la disposition, c'est un
  candidat. Un candidat est retenu si : le champ length est lisible, est un Smi (bit 0
  à 0) non négatif, le contenu (length octets, ou 2 x length) tient dans l'image, la
  taille d'objet reconstituée (data_offset + contenu, arrondie à object_alignment)
  correspond au champ taille de l'en-tête (0 = taille trop grande pour le champ), et le
  contenu se décode. Un même offset ne produit jamais deux entrées ; deux chaînes de
  même valeur à deux offsets sont deux entrées.
  heuristic       Toujours true.
  method          aligned_object_scan.
  blob_bound      Ce qui borne la zone balayée (BORNES) : header_length pour un blob
                  heuristic ; symbol_size ou next_symbol pour un blob localisé par
                  symbole. section_end n'y apparaît jamais. La plage exacte est
                  data_image du même blob.
  layout_source   calibrated = disposition déduite par la calibration de cette
                  bibliothèque ; table = celle de l'entrée de la table des versions
                  connues pour version_hash. La calibration aboutie l'emporte toujours.
  layout          La disposition utilisée (DISPOSITION).
  stride          Pas du balayage = layout.word_size.
  candidates      Mots dont le class id désigne OneByteString ou TwoByteString.
  accepted        Candidats retenus : compte réel, indépendant de --dart-max-rows.
  rejected        Candidats écartés, par motif ; chaque motif est présent, même à 0 :
    truncated_fields    Le champ length dépasse la fin de l'image de données.
    length_not_smi      Bit 0 de length à 1.
    length_negative     length négatif.
    length_out_of_blob  Le contenu dépasse la fin de l'image de données.
    size_tag_mismatch   Taille reconstituée incompatible avec le champ taille.
    undecodable_utf16   TwoByteString non décodable en UTF-16 (surrogate isolé).
  OneByteString se décode toujours : tout octet est un caractère latin-1.
  entries_total   Nombre d'entrées avant coupe = accepted.
  entries_returned
                  Nombre d'entrées présentes dans entries : entries_total, ou au plus
                  N avec --dart-max-rows N.
  truncated       entries_total > entries_returned : entries est coupé par
                  --dart-max-rows. Toujours false sans lui.
  entries[]       Les entries_returned premières chaînes retenues, dans l'ordre de
                  l'image : image_offset (depuis data_image.start, début de l'image
                  de données, pas depuis le magic), file_offset (absolu, =
                  data_image.start + image_offset), encoding (one_byte = latin-1,
                  two_byte = UTF-16LE), length (nombre de caractères déclaré), value.

CALIBRATION (calibration) — --dart-calibrate / --dart-calibrate-file
  Déduit la disposition des chaînes de l'image de données d'un blob de données à
  partir de chaînes dont on connaît le texte (témoins), et la prouve sur eux.
  0. ZONES. Chaque témoin distinct est cherché en entier dans TOUTE la section ELF
     qui porte le blob (étendue au blob s'il en déborde ; le blob seul s'il n'est dans
     aucune section) : en latin-1 s'il est encodable ainsi (tous ses caractères
     <= U+00FF), en UTF-16LE sinon. Chaque occurrence est rangée, d'après son premier
     octet, dans une des trois zones du blob :
       serialized    [magic, magic + length + 4)
       data_image    [data_image.start, data_image.end)
       outside       dans la section, hors des deux : avant le magic, entre la fin de
                     la partie sérialisée et le début arrondi de l'image, après la fin
                     du blob (autre blob de la section compris).
     Faite même quand la calibration ne tourne pas (not_run), dès que serialized est
     connu : c'est elle qui dit si les chaînes sont des objets de l'image de données.
  1. Seules les occurrences en data_image sont examinées, les premières seulement
     (PARAMÈTRES), offsets relatifs à data_image.start.
  2. Pour chaque occurrence au décalage d, chaque début d'objet o multiple de
     word_size (taille de pointeur de l'ELF), o < d, d - o au plus la fenêtre, et
     chaque champ de length_fields_tried qui finit avant d : le champ lu en
     o + offset doit être un Smi non négatif égal à la longueur du témoin (octets en
     latin-1, unités UTF-16 sinon). Alors data_offset = d - o et le mot en o est tags.
  3. Pour chaque disposition de tag_layouts_tried et chaque alignement de
     object_alignments_tried : le class id extrait doit être non nul, et le champ
     taille cohérent avec data_offset + contenu arrondi à l'alignement (ou 0 avec une
     taille trop grande pour le champ).
  4. Une disposition n'est retenue que si elle explique TOUS les témoins, avec un même
     class id pour tous les témoins d'un même encodage. Pour l'encodage sans témoin,
     le class id est déduit de l'autre : two_byte = one_byte + 1 (class_id.h 3.5.0).
  outcome         Le premier qui s'applique, dans cet ordre ; les préconditions sur
                  l'entrée passent avant le résultat de l'inférence :
    not_run                       La calibration n'a pas tourné : not_run_reason donne
                                  le motif (un motif de strings_unavailable antérieur à
                                  la calibration). Les zones sont rendues si serialized
                                  est connu.
    insufficient_witnesses        Moins de 3 témoins distincts, quoi qu'il arrive par
                                  ailleurs : deux témoins peuvent coïncider par hasard.
                                  Les dispositions qui les expliquent restent listées
                                  dans inferred.
    witness_not_found             Aucun témoin localisé dans la section : mauvais blob,
                                  chaînes absentes, ou stockées autrement (compressées,
                                  construites à l'exécution).
    witnesses_not_all_found       Au moins un témoin localisé, pas tous : les témoins
                                  absents de la section (occurrences 0 dans
                                  witnesses[]) empêchent toute disposition de les
                                  expliquer tous.
    witnesses_outside_data_image  Tous les témoins localisés dans la section, AUCUN
                                  dans l'image de données (zones.data_image.count = 0
                                  pour chacun) : les chaînes ne sont pas des objets de
                                  l'image de données de ce blob, l'hypothèse du
                                  balayage est fausse pour lui.
    no_layout_explains_witnesses  Tous les témoins localisés, au moins un dans l'image
                                  de données, mais aucune disposition ne les explique
                                  tous (un témoin hors image n'est jamais expliqué).
    ambiguous_layout              Plusieurs dispositions expliquent tous les témoins :
                                  aucune n'est choisie, toutes sont dans inferred.
    calibrated                    Une seule disposition : elle sert au balayage.
  not_run_reason  Motif de not_run ; null sinon.
  witnesses_total Nombre de témoins distincts (taille de witnesses[]).
  witnesses_found Témoins dont occurrences > 0 (n'importe quelle zone) ; null sans
                  zones.
  witnesses_in_data_image
                  Témoins dont zones.data_image.count > 0 ; null sans zones.
  witnesses_explained
                  Témoins qu'AU MOINS UNE disposition candidate explique — pas
                  nécessairement celle retenue. Égale witnesses_total quand outcome
                  vaut calibrated ou ambiguous_layout ; peut être non nul sans
                  qu'aucune disposition survive (witnesses_not_all_found,
                  no_layout_explains_witnesses). null pour not_run.
  data_image_verdict
                  Lecture des zones, sans rien à déduire ; null sans zones :
    all_in_data_image             Chaque témoin a au moins une occurrence dans l'image
                                  de données : l'hypothèse « chaînes = objets à en-tête
                                  de l'image » tient, la calibration peut aboutir.
    partly_in_data_image          Certains témoins y sont, d'autres seulement hors
                                  image ou absents de la section.
    none_in_data_image            Au moins un témoin localisé, aucun dans l'image de
                                  données (tous en serialized ou outside) :
                                  l'hypothèse est fausse pour ce blob.
    no_witness_found              Aucun témoin dans la section.
  witnesses[]     value = le témoin ; encoding = one_byte (latin-1) ou two_byte
                  (UTF-16LE) ; length = longueur attendue (caractères latin-1 ou unités
                  UTF-16) ; occurrences = nombre d'occurrences des octets dans toute la
                  section, toutes zones confondues (= somme des trois zones.*.count),
                  null sans zones ; occurrences_examined = celles de l'image de
                  données soumises aux étapes 2 et 3, null pour not_run ;
                  zones = {serialized, data_image, outside}, chacune {count,
                  first_offset} : nombre d'occurrences dans la zone et offset de
                  fichier absolu de la première, null si la zone n'en a aucune ;
                  zones vaut null quand serialized est inconnu (data_blob_unbounded,
                  magic_mismatch) ; explained = au moins une disposition candidate
                  (étape 3) l'explique, avant l'exigence de couvrir tous les témoins.
                  Un témoin répété ne compte qu'une fois.
  word_size       Taille de pointeur de l'ELF ; null pour not_run.
  compressed_pointers
                  header.compressed_pointers du blob ; null pour not_run.
  length_fields_tried[]
                  {offset, width} essayés à l'étape 2 : ceux de la table PARAMÈTRES
                  dont offset >= word_size et width <= word_size ; de plus, la largeur
                  est imposée par le binaire quand compressed_pointers est connu :
                  width = 4 s'il vaut true, width = word_size s'il vaut false (8 sur
                  ELFCLASS64, 4 sur ELFCLASS32). Ce n'est alors plus un candidat.
                  Vide pour not_run.
  object_alignments_tried[]
                  Alignements essayés à l'étape 3.
  tag_layouts_tried[]
                  Dispositions de tags essayées à l'étape 3, en entier : size_tag_pos,
                  size_tag_bits, class_id_tag_pos, class_id_tag_bits, et source :
                  read_sdk_3_5_0 = lue dans UntaggedObject::TagBits de
                  runtime/vm/raw_object.h au tag 3.5.0 ; guessed = devinée, non lue
                  dans le source.
  inferred[]      Dispositions retenues à l'étape 4 : layout (DISPOSITION) ;
                  derived_cid = one_byte ou two_byte quand ce class id a été déduit
                  de l'autre faute de témoin de cet encodage, null si les deux ont été
                  observés ; evidence[] = pour chaque témoin, witness, puis le début
                  du premier objet qui l'établit : image_offset (depuis
                  data_image.start) et file_offset (absolu).
  known_version_literal
                  Avec outcome calibrated et un version_hash lu : le littéral Rust
                  KnownVersion { … } à coller dans KNOWN_VERSIONS (label
                  \"calibrated\", kinds: None) ; null sinon. Rien n'est jamais écrit
                  dans la table par l'outil.

TEXTE
  La sortie texte ne liste pas les valeurs des chaînes : --format json ou both.
";

/// Légende autonome : chaque champ, statut et code de `--dart-snapshot`.
pub fn legend() -> String {
    let mut out = String::from(LEGEND);
    out.push_str("\nPARAMÈTRES (image de données, calibration)\n");
    out.push_str(&format!(
        "  kObjectStartAlignment      {OBJECT_START_ALIGNMENT} ({TAG_SOURCE_READ}, \
         runtime/vm/pointer_tagging.h)\n"
    ));
    out.push_str(&format!(
        "  témoins minimum            {MIN_WITNESSES}\n  \
         fenêtre en amont (octets)  {HEADER_WINDOW}\n  \
         occurrences examinées      {MAX_EXAMINED_OCCURRENCES} premières par témoin\n"
    ));
    let fields: Vec<String> = LENGTH_FIELDS
        .iter()
        .map(|(offset, width)| format!("({offset}, {width})"))
        .collect();
    out.push_str(&format!(
        "  champs length (offset, largeur)  {}\n",
        fields.join(" ")
    ));
    let alignments: Vec<String> = OBJECT_ALIGNMENTS.iter().map(|a| a.to_string()).collect();
    out.push_str(&format!(
        "  alignements                {}\n",
        alignments.join(" ")
    ));
    for t in TAG_LAYOUTS {
        out.push_str(&format!(
            "  tags  size {}+{}  class_id {}+{}  {}\n",
            t.size_tag_pos, t.size_tag_bits, t.class_id_tag_pos, t.class_id_tag_bits, t.source
        ));
    }
    out.push_str("\nTABLE DES VERSIONS CONNUES (version_hash -> libellé)\n");
    if KNOWN_VERSIONS.is_empty() {
        out.push_str("  (vide : sans calibration aboutie, strings vaut null)\n");
    }
    for v in KNOWN_VERSIONS {
        out.push_str(&format!("  {}  {}\n", v.version_hash, v.label));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "0123456789abcdef0123456789abcdef";

    const HEAP: HeapLayout = HeapLayout {
        word_size: 8,
        object_alignment: 16,
        size_tag_pos: 8,
        size_tag_bits: 4,
        class_id_tag_pos: 12,
        class_id_tag_bits: 20,
        one_byte_string_cid: 0x55,
        two_byte_string_cid: 0x56,
        length_offset: 8,
        length_width: 4,
        data_offset: 12,
    };

    fn table(kinds: KindLayout) -> [KnownVersion; 1] {
        [KnownVersion {
            version_hash: HASH,
            label: "test",
            kinds: Some(kinds),
            heap: HEAP,
        }]
    }

    fn blob(kind: u64, version: &[u8], features: &[u8]) -> Vec<u8> {
        blob_with_length(0x1000, kind, version, features)
    }

    fn blob_with_length(length: u64, kind: u64, version: &[u8], features: &[u8]) -> Vec<u8> {
        let mut b = MAGIC.to_vec();
        b.extend_from_slice(&length.to_le_bytes());
        b.extend_from_slice(&kind.to_le_bytes());
        b.extend_from_slice(version);
        b.extend_from_slice(features);
        b
    }

    #[test]
    fn magic_is_read_little_endian() {
        let h = parse_header(&blob(3, HASH.as_bytes(), b"product\0"), &[]);
        assert!(h.magic_ok);
        assert_eq!(h.magic.as_deref(), Some("0xdcdcf5f5"));
        assert_eq!(h.length, Some(0x1000));
        assert!(h.errors.is_empty());
    }

    #[test]
    fn magic_mismatch_keeps_other_fields() {
        let mut b = blob(3, HASH.as_bytes(), b"product\0");
        b[0..4].copy_from_slice(&[0xdc, 0xdc, 0xf5, 0xf5]);
        let h = parse_header(&b, &[]);
        assert!(!h.magic_ok);
        assert_eq!(h.magic.as_deref(), Some("0xf5f5dcdc"));
        assert_eq!(h.errors, vec![MAGIC_MISMATCH]);
        assert_eq!(h.version_hash.as_deref(), Some(HASH));
    }

    #[test]
    fn known_kind_follows_version_layout() {
        let b = blob(3, HASH.as_bytes(), b"\0");
        let h = parse_header(&b, &table(KindLayout::WithFullCore));
        assert_eq!(h.kind.as_deref(), Some("full_aot"));
        assert_eq!(h.known_version, Some("test"));
        let h = parse_header(&b, &table(KindLayout::WithModule));
        assert_eq!(h.kind.as_deref(), Some("module"));
        let b = blob(2, HASH.as_bytes(), b"\0");
        let h = parse_header(&b, &table(KindLayout::WithModule));
        assert_eq!(h.kind.as_deref(), Some("full_aot"));
    }

    #[test]
    fn unknown_kind_value_is_not_labelled() {
        let b = blob(9, HASH.as_bytes(), b"\0");
        let h = parse_header(&b, &table(KindLayout::WithFullCore));
        assert_eq!(h.kind_raw, Some(9));
        assert_eq!(h.kind.as_deref(), Some("unknown(9)"));
        assert!(h.errors.is_empty());
    }

    #[test]
    fn kind_of_unknown_version_is_not_labelled() {
        let h = parse_header(&blob(3, HASH.as_bytes(), b"\0"), &[]);
        assert_eq!(h.kind.as_deref(), Some("unknown(3)"));
        assert_eq!(h.known_version, None);
    }

    #[test]
    fn kind_of_entry_without_numbering_is_not_labelled() {
        let mut known = table(KindLayout::WithFullCore);
        known[0].kinds = None;
        let h = parse_header(&blob(3, HASH.as_bytes(), b"\0"), &known);
        assert_eq!(h.kind.as_deref(), Some("unknown(3)"));
        assert_eq!(h.known_version, Some("test"));
    }

    #[test]
    fn version_hash_is_returned_without_table() {
        let h = parse_header(&blob(3, HASH.as_bytes(), b"\0"), &[]);
        assert_eq!(h.version_hash.as_deref(), Some(HASH));
    }

    #[test]
    fn version_hash_not_hex_is_null_and_hides_features() {
        let h = parse_header(&blob(3, &[b'z'; 32], b"product\0"), &[]);
        assert_eq!(h.version_hash, None);
        assert_eq!(h.features, None);
        assert_eq!(
            h.errors,
            vec![VERSION_HASH_NOT_HEX, FEATURES_OFFSET_UNKNOWN]
        );
    }

    #[test]
    fn features_are_returned_verbatim() {
        let raw = b"a no-b \"c-d\" e\0trailing";
        let h = parse_header(&blob(3, HASH.as_bytes(), raw), &[]);
        assert_eq!(h.features.as_deref(), Some("a no-b \"c-d\" e"));
        assert!(h.errors.is_empty());
    }

    #[test]
    fn features_without_nul_are_null() {
        let h = parse_header(&blob(3, HASH.as_bytes(), b"product"), &[]);
        assert_eq!(h.features, None);
        assert_eq!(h.errors, vec![FEATURES_UNTERMINATED]);
        assert_eq!(h.version_hash.as_deref(), Some(HASH));
    }

    #[test]
    fn features_not_utf8_are_null() {
        let h = parse_header(&blob(3, HASH.as_bytes(), b"\xff\xfe\0"), &[]);
        assert_eq!(h.features, None);
        assert_eq!(h.errors, vec![FEATURES_NOT_UTF8]);
    }

    #[test]
    fn truncated_blob_reports_each_missing_field() {
        let b = blob(3, HASH.as_bytes(), b"\0");
        let h = parse_header(&b[..10], &[]);
        assert!(h.magic_ok);
        assert_eq!(h.length, None);
        assert_eq!(h.kind_raw, None);
        assert_eq!(h.kind, None);
        assert_eq!(h.version_hash, None);
        assert_eq!(
            h.errors,
            vec![
                TRUNCATED_AT_LENGTH,
                TRUNCATED_AT_KIND,
                TRUNCATED_AT_VERSION_HASH,
                FEATURES_OFFSET_UNKNOWN
            ]
        );
        let h = parse_header(&b[..2], &[]);
        assert_eq!(h.magic, None);
        assert!(!h.magic_ok);
        assert_eq!(h.errors[0], TRUNCATED_AT_MAGIC);
        let h = parse_header(&b[..40], &[]);
        assert_eq!(h.kind_raw, Some(3));
        assert_eq!(h.version_hash, None);
        assert!(h.errors.contains(&TRUNCATED_AT_VERSION_HASH));
    }

    fn object(cid: u64, size_tag: u64, length_smi: u32, data: &[u8], padded: usize) -> Vec<u8> {
        let tags = (cid << HEAP.class_id_tag_pos) | (size_tag << HEAP.size_tag_pos);
        let mut o = tags.to_le_bytes().to_vec();
        o.extend_from_slice(&length_smi.to_le_bytes());
        o.extend_from_slice(data);
        o.resize(padded, 0);
        o
    }

    fn scan(blob: &[u8], max_rows: usize) -> StringScan {
        scan_strings(
            blob,
            0x4000,
            &HEAP,
            LAYOUT_TABLE,
            BOUND_SYMBOL_SIZE,
            max_rows,
        )
    }

    #[test]
    fn scan_keeps_coherent_strings_and_counts_rejects() {
        let mut b = object(0x55, 2, 5 << 1, b"hello", 32);
        b.extend(object(0x56, 1, 2 << 1, &[0xe9, 0x00, 0xac, 0x20], 16));
        b.extend(object(0x55, 2, (5 << 1) | 1, b"hello", 32));
        b.extend(object(0x55, 3, 5 << 1, b"hello", 32));
        b.extend(object(0x56, 1, 1 << 1, &[0x00, 0xd8], 16));
        let scan = scan(&b, 0);
        assert!(scan.heuristic);
        assert_eq!(scan.layout_source, LAYOUT_TABLE);
        assert_eq!(scan.blob_bound, BOUND_SYMBOL_SIZE);
        assert_eq!(scan.candidates, 5);
        assert_eq!(scan.accepted, 2);
        assert_eq!(scan.entries[0].value, "hello");
        assert_eq!(scan.entries[0].encoding, ONE_BYTE);
        assert_eq!(scan.entries[0].file_offset, 0x4000);
        assert_eq!(scan.entries[1].value, "é€");
        assert_eq!(scan.entries[1].image_offset, 32);
        assert_eq!(scan.rejected[REJECT_LENGTH_NOT_SMI], 1);
        assert_eq!(scan.rejected[REJECT_SIZE_TAG_MISMATCH], 1);
        assert_eq!(scan.rejected[REJECT_UNDECODABLE_UTF16], 1);
        assert_eq!(scan.rejected[REJECT_LENGTH_OUT_OF_BLOB], 0);
        assert!(!scan.truncated);
    }

    #[test]
    fn scan_rejects_length_past_blob_end() {
        let b = object(0x55, 0, 1000 << 1, b"abc", 16);
        let scan = scan(&b, 0);
        assert_eq!(scan.candidates, 1);
        assert_eq!(scan.accepted, 0);
        assert_eq!(scan.rejected[REJECT_LENGTH_OUT_OF_BLOB], 1);
    }

    fn sixty_strings() -> Vec<u8> {
        (0..60)
            .flat_map(|_| object(0x55, 2, 5 << 1, b"hello", 32))
            .collect()
    }

    #[test]
    fn default_returns_every_entry() {
        let scan = scan(&sixty_strings(), DartOptions::default().max_rows);
        assert_eq!(scan.accepted, 60);
        assert_eq!(scan.entries_total, 60);
        assert_eq!(scan.entries_returned, scan.entries_total);
        assert_eq!(scan.entries.len(), 60);
        assert!(!scan.truncated);
    }

    #[test]
    fn dart_max_rows_cuts_entries_not_counts() {
        let scan = scan(&sixty_strings(), 1);
        assert_eq!(scan.accepted, 60);
        assert_eq!(scan.entries_total, 60);
        assert_eq!(scan.entries_returned, 1);
        assert_eq!(scan.entries.len(), 1);
        assert!(scan.truncated);
        assert_eq!(scan.entries[0].value, "hello");
    }

    fn witnesses(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    /// `image` est à la fois la section et l'image de données, à l'offset 0.
    fn calibrate_image(image: &[u8], values: &[String]) -> Calibration {
        let zoning = Zoning {
            bytes: image,
            start: 0,
            serialized: 0..0,
            image: Some(0..image.len() as u64),
        };
        calibrate(&zoning, 8, None, values, Some(HASH))
    }

    fn assert_literal_matches_heap(literal: &str) {
        for line in [
            format!("version_hash: \"{HASH}\","),
            "kinds: None,".to_string(),
            "word_size: 8,".to_string(),
            "object_alignment: 16,".to_string(),
            "size_tag_pos: 8,".to_string(),
            "size_tag_bits: 4,".to_string(),
            "class_id_tag_pos: 12,".to_string(),
            "class_id_tag_bits: 20,".to_string(),
            "one_byte_string_cid: 0x55,".to_string(),
            "two_byte_string_cid: 0x56,".to_string(),
            "length_offset: 8,".to_string(),
            "length_width: 4,".to_string(),
            "data_offset: 12,".to_string(),
        ] {
            assert!(literal.contains(&line), "{line}");
        }
    }

    fn strings_blob(cid: u64) -> Vec<u8> {
        let mut b = object(cid, 2, 5 << 1, b"hello", 32);
        b.extend(object(cid, 2, 6 << 1, b"world!", 32));
        b.extend(object(cid, 2, 7 << 1, b"flutter", 32));
        b
    }

    #[test]
    fn calibration_recovers_the_construction_layout() {
        let b = strings_blob(0x55);
        let values = witnesses(&["hello", "world!", "flutter"]);
        let cal = calibrate_image(&b, &values);
        assert_eq!(cal.outcome, CALIBRATED);
        assert_eq!(cal.inferred.len(), 1);
        let inferred = &cal.inferred[0];
        assert_eq!(inferred.layout, HEAP);
        assert_eq!(inferred.derived_cid, Some(TWO_BYTE));
        let offsets: Vec<u64> = inferred.evidence.iter().map(|e| e.image_offset).collect();
        assert_eq!(offsets, vec![0, 32, 64]);
        assert!(cal.witnesses.iter().all(|w| w.explained));
        assert_eq!(cal.tag_layouts_tried, TAG_LAYOUTS.to_vec());
        assert_literal_matches_heap(&cal.known_version_literal.unwrap());
    }

    #[test]
    fn two_witnesses_are_insufficient() {
        let b = strings_blob(0x55);
        let cal = calibrate_image(&b, &witnesses(&["hello", "world!"]));
        assert_eq!(cal.outcome, INSUFFICIENT_WITNESSES);
        assert_eq!(cal.inferred.len(), 1);
        assert_eq!(cal.known_version_literal, None);
        assert_eq!(cal.layout(), None);
    }

    fn headerless_blob() -> Vec<u8> {
        let mut b = vec![0u8; 40];
        b.extend_from_slice(b"hello");
        b.resize(96, 0);
        b.extend_from_slice(b"world!");
        b.resize(160, 0);
        b.extend_from_slice(b"flutter");
        b.resize(224, 0);
        b
    }

    #[test]
    fn two_witnesses_without_layout_are_insufficient() {
        let b = headerless_blob();
        let cal = calibrate_image(&b, &witnesses(&["hello", "world!"]));
        assert_eq!(cal.outcome, INSUFFICIENT_WITNESSES);
        assert!(cal.inferred.is_empty());
        assert_eq!(cal.witnesses_total, 2);
    }

    #[test]
    fn one_witness_out_of_three_found_is_not_all_found() {
        let b = strings_blob(0x55);
        let values = witnesses(&["hello", "absent", "missing"]);
        let cal = calibrate_image(&b, &values);
        assert_eq!(cal.outcome, WITNESSES_NOT_ALL_FOUND);
        assert_eq!(cal.witnesses_total, 3);
        assert_eq!(cal.witnesses_found, Some(1));
        assert_eq!(cal.witnesses_explained, Some(1));
        assert!(cal.inferred.is_empty());
    }

    #[test]
    fn repeated_witness_counts_once() {
        let b = strings_blob(0x55);
        let values = witnesses(&["hello", "hello", "world!"]);
        let cal = calibrate_image(&b, &values);
        assert_eq!(cal.witnesses.len(), 2);
        assert_eq!(cal.outcome, INSUFFICIENT_WITNESSES);
    }

    #[test]
    fn two_tag_layouts_explaining_the_witnesses_are_ambiguous() {
        let b = strings_blob(0x50);
        let values = witnesses(&["hello", "world!", "flutter"]);
        let cal = calibrate_image(&b, &values);
        assert_eq!(cal.outcome, AMBIGUOUS_LAYOUT);
        assert_eq!(cal.inferred.len(), 2);
        assert_eq!(cal.layout(), None);
        assert_eq!(cal.known_version_literal, None);
    }

    #[test]
    fn absent_witnesses_are_not_found() {
        let b = strings_blob(0x55);
        let values = witnesses(&["absent", "missing", "nowhere"]);
        let cal = calibrate_image(&b, &values);
        assert_eq!(cal.outcome, WITNESS_NOT_FOUND);
        assert!(cal.witnesses.iter().all(|w| w.occurrences == Some(0)));
        assert_eq!(cal.witnesses_found, Some(0));
    }

    #[test]
    fn witnesses_without_object_header_explain_nothing() {
        let b = headerless_blob();
        let values = witnesses(&["hello", "world!", "flutter"]);
        let cal = calibrate_image(&b, &values);
        assert_eq!(cal.outcome, NO_LAYOUT_EXPLAINS_WITNESSES);
        assert!(cal.witnesses.iter().all(|w| w.occurrences == Some(1)));
        assert!(cal.witnesses.iter().all(|w| !w.explained));
        assert_eq!(cal.witnesses_total, 3);
        assert_eq!(cal.witnesses_found, Some(3));
        assert_eq!(cal.witnesses_explained, Some(0));
        assert!(cal.inferred.is_empty());
    }

    #[test]
    fn find_counts_overlapping_occurrences_in_order() {
        let (count, kept) = find(b"aaaa-aa", b"aa", 2);
        assert_eq!(count, 4);
        assert_eq!(kept, vec![0, 1]);
        assert_eq!(find(b"abc", b"", 5), (0, Vec::new()));
        assert_eq!(find(b"ab", b"abc", 5), (0, Vec::new()));
    }

    fn rodata() -> Section {
        Section {
            name: ".rodata".to_string(),
            sh_type: elf::SHT_PROGBITS,
            flags: u64::from(elf::SHF_ALLOC),
            addr: 0x1000,
            offset: 0x1000,
            size: 0x800,
        }
    }

    const DEFINED: [(&str, u64); 3] = [
        (VM_DATA, 0x1000),
        (ISOLATE_DATA, 0x1200),
        (ISOLATE_INSTRUCTIONS, 0x2000),
    ];

    #[test]
    fn zero_size_is_bounded_by_the_next_symbol_of_the_section() {
        let section = rodata();
        let end = blob_end(0x1000, 0x1000, 0, Some(&section), &DEFINED).unwrap();
        assert_eq!(end.bound, BOUND_NEXT_SYMBOL);
        assert_eq!(end.at, 0x1200);
        assert!(end.detail.contains(ISOLATE_DATA));
    }

    #[test]
    fn zero_size_without_next_symbol_falls_back_to_section_end() {
        let section = rodata();
        let end = blob_end(0x1200, 0x1200, 0, Some(&section), &DEFINED).unwrap();
        assert_eq!(end.bound, BOUND_SECTION_END);
        assert_eq!(end.at, 0x1800);
        let end = blob_end(0x1200, 0x1200, 0x40, Some(&section), &DEFINED).unwrap();
        assert_eq!(end.bound, BOUND_SYMBOL_SIZE);
        assert_eq!(end.at, 0x1240);
    }

    /// Blob localisé par le symbole de l'isolate, couvrant tout `data`.
    fn symbol_blob(data: &[u8], bound: &'static str) -> Blob {
        let mut blob = Blob {
            section: SnapshotSection {
                symbol: ISOLATE_DATA.to_string(),
                blob_index: None,
                file_offset: Some(0),
                vaddr: 0,
                size: None,
                elf_section: None,
                header: Some(parse_header(data, &[])),
                serialized: None,
                data_image: None,
                scan: None,
            },
            range: Some(0..data.len()),
            bound: Some(bound),
            container: None,
        };
        frame(&mut blob, &mut Vec::new());
        blob
    }

    /// En-tête de 53 octets (length 49), image de données à l'offset 64.
    fn snapshot_with_strings() -> Vec<u8> {
        let mut data = blob_with_length(49, 2, HASH.as_bytes(), b"\0");
        data.resize(64, 0);
        data.extend(strings_blob(0x55));
        data
    }

    fn run(
        blob: &Blob,
        data: &[u8],
        known: &[KnownVersion],
        options: &DartOptions,
    ) -> (BlobScan, Vec<String>) {
        let mut anomalies = Vec::new();
        let scan = scan_blob(data, blob, known, options, 8, &mut anomalies);
        (scan, anomalies)
    }

    fn calibrating(values: &[&str]) -> DartOptions {
        DartOptions {
            max_rows: 0,
            witnesses: Some(witnesses(values)),
        }
    }

    fn section_at(offset: u64, size: u64) -> Section {
        Section {
            name: ".rodata".to_string(),
            sh_type: elf::SHT_PROGBITS,
            flags: u64::from(elf::SHF_ALLOC),
            addr: 0x10000 + offset,
            offset,
            size,
        }
    }

    /// Blobs heuristiques de la section, indexés et découpés.
    fn heuristics(data: &[u8], section: &Section) -> Vec<Blob> {
        let mut anomalies = Vec::new();
        let (mut blobs, rejected) = magic_blobs(data, section, &[], &mut anomalies);
        assert_eq!(rejected, 0);
        index_blobs(&mut blobs);
        for blob in &mut blobs {
            frame(blob, &mut anomalies);
        }
        assert!(anomalies.is_empty(), "{anomalies:?}");
        blobs
    }

    fn place(data: &mut [u8], at: usize, bytes: &[u8]) {
        data[at..at + bytes.len()].copy_from_slice(bytes);
    }

    /// Section de 0x200 octets, magic à 0x40, length 0x6c : partie sérialisée
    /// [0x40, 0xb0), image de données [0xc0, 0x200).
    fn zoned_section(writes: &[(usize, &str)]) -> Vec<u8> {
        let mut data = vec![0u8; 0x200];
        place(&mut data, 0x40, &blob_with_length(0x6c, 2, HASH.as_bytes(), b"\0"));
        for &(at, text) in writes {
            place(&mut data, at, text.as_bytes());
        }
        data
    }

    #[test]
    fn header_bounds_serialized_part_and_data_image() {
        let mut data = vec![0u8; 0x200];
        place(&mut data, 0x48, &blob_with_length(0x6c, 2, HASH.as_bytes(), b"\0"));
        let blobs = heuristics(&data, &section_at(0, 0x200));
        assert_eq!(blobs.len(), 1);
        let s = &blobs[0].section;
        assert_eq!(s.symbol, HEURISTIC);
        assert_eq!(s.blob_index, Some(0));
        assert_eq!(
            s.serialized,
            Some(Span {
                start: 0x48,
                end: 0xb8,
                size: 0x70
            })
        );
        // RoundUp(0x70, 64) = 0x80 depuis le magic (Snapshot::DataImage), et non
        // RoundUp(0xb8, 64) = 0xc0 en absolu.
        assert_eq!(
            s.data_image,
            Some(DataImage {
                start: 0xc8,
                end: 0x200,
                size: 0x138,
                end_bound: BOUND_SECTION_END,
                start_alignment: 64,
                start_alignment_source: TAG_SOURCE_READ,
            })
        );
    }

    #[test]
    fn data_image_stops_at_the_next_magic() {
        let mut data = vec![0u8; 0x300];
        let header = blob_with_length(49, 2, HASH.as_bytes(), b"\0");
        place(&mut data, 0, &header);
        place(&mut data, 0x100, &header);
        let blobs = heuristics(&data, &section_at(0, 0x300));
        assert_eq!(blobs.len(), 2);
        let (first, second) = (&blobs[0].section, &blobs[1].section);
        assert_eq!((first.blob_index, second.blob_index), (Some(0), Some(1)));
        assert_eq!(first.serialized.unwrap().end, 53);
        let image = first.data_image.unwrap();
        assert_eq!((image.start, image.end, image.size), (0x40, 0x100, 0xc0));
        assert_eq!(image.end_bound, BOUND_NEXT_MAGIC);
        let image = second.data_image.unwrap();
        assert_eq!((image.start, image.end, image.size), (0x140, 0x300, 0x1c0));
        assert_eq!(image.end_bound, BOUND_SECTION_END);
    }

    #[test]
    fn empty_data_image_refuses_the_scan() {
        let known = table(KindLayout::WithFullCore);
        let options = calibrating(&["hello", "world!", "flutter"]);
        for (len, image) in [(64usize, Some(0)), (60, None)] {
            let mut data = blob_with_length(49, 2, HASH.as_bytes(), b"\0");
            data.resize(len, 0);
            let blobs = heuristics(&data, &section_at(0, len as u64));
            assert_eq!(blobs[0].section.data_image.map(|d| d.size), image, "{len}");
            let (scan, _) = run(&blobs[0], &data, &known, &options);
            assert_eq!(scan.strings, None, "{len}");
            assert_eq!(scan.strings_unavailable, Some(DATA_IMAGE_EMPTY), "{len}");
            let cal = scan.calibration.unwrap();
            assert_eq!(cal.outcome, NOT_RUN);
            assert_eq!(cal.not_run_reason, Some(DATA_IMAGE_EMPTY));
            assert!(cal.witnesses.iter().all(|w| w.zones.is_some()));
            assert_eq!(cal.data_image_verdict, Some(VERDICT_NO_WITNESS_FOUND));
        }
    }

    #[test]
    fn compressed_pointers_fix_the_length_width() {
        let header_of = |features: &[u8]| parse_header(&blob(2, HASH.as_bytes(), features), &[]);
        let on = header_of(b"product arm64 android compressed-pointers\0");
        assert_eq!(on.compressed_pointers, Some(true));
        assert_eq!(
            on.features.as_deref(),
            Some("product arm64 android compressed-pointers")
        );
        let off = header_of(b"product arm android no-compressed-pointers\0");
        assert_eq!(off.compressed_pointers, Some(false));
        assert_eq!(header_of(b"product arm64\0").compressed_pointers, None);
        let both = header_of(b"compressed-pointers no-compressed-pointers\0");
        assert_eq!(both.compressed_pointers, None);
        assert_eq!(both.errors, vec![COMPRESSED_POINTERS_CONTRADICTORY]);

        let field = |offset, width| LengthField { offset, width };
        assert_eq!(
            length_fields(8, Some(true)),
            vec![field(8, 4), field(12, 4)]
        );
        assert_eq!(
            length_fields(8, Some(false)),
            vec![field(8, 8), field(16, 8)]
        );
        assert_eq!(
            length_fields(8, None),
            vec![field(8, 4), field(8, 8), field(12, 4), field(16, 8)]
        );
        assert_eq!(
            length_fields(4, Some(false)),
            vec![field(4, 4), field(8, 4), field(12, 4)]
        );
    }

    fn zones_of(cal: &Calibration, value: &str) -> Zones {
        let witness = cal.witnesses.iter().find(|w| w.value == value).unwrap();
        witness.zones.clone().unwrap()
    }

    #[test]
    fn witnesses_are_counted_per_zone_over_the_whole_section() {
        let data = zoned_section(&[
            (0x10, "gamma"),
            (0x90, "alpha"),
            (0xb4, "gamma"),
            (0x100, "beta"),
        ]);
        let blobs = heuristics(&data, &section_at(0, 0x200));
        let options = calibrating(&["alpha", "beta", "gamma"]);
        let (scan, _) = run(&blobs[0], &data, &[], &options);
        let cal = scan.calibration.unwrap();

        let alpha = zones_of(&cal, "alpha");
        let counts = (alpha.serialized.count, alpha.data_image.count, alpha.outside.count);
        assert_eq!(counts, (1, 0, 0));
        assert_eq!(alpha.serialized.first_offset, Some(0x90));
        assert_eq!(alpha.data_image.first_offset, None);
        assert_eq!(alpha.outside.first_offset, None);

        let beta = zones_of(&cal, "beta");
        let counts = (beta.serialized.count, beta.data_image.count, beta.outside.count);
        assert_eq!(counts, (0, 1, 0));
        assert_eq!(beta.data_image.first_offset, Some(0x100));

        let gamma = zones_of(&cal, "gamma");
        let counts = (gamma.serialized.count, gamma.data_image.count, gamma.outside.count);
        assert_eq!(counts, (0, 0, 2));
        assert_eq!(gamma.outside.first_offset, Some(0x10));

        let seen: Vec<(Option<usize>, Option<usize>)> = cal
            .witnesses
            .iter()
            .map(|w| (w.occurrences, w.occurrences_examined))
            .collect();
        assert_eq!(seen, vec![(Some(1), Some(0)), (Some(1), Some(1)), (Some(2), Some(0))]);
        assert_eq!(cal.witnesses_found, Some(3));
        assert_eq!(cal.witnesses_in_data_image, Some(1));
        assert_eq!(cal.data_image_verdict, Some(VERDICT_PARTLY_IN_DATA_IMAGE));
        assert_eq!(cal.outcome, NO_LAYOUT_EXPLAINS_WITNESSES);
    }

    #[test]
    fn witnesses_all_outside_the_data_image_say_so() {
        let data = zoned_section(&[(0x10, "gamma"), (0x90, "alpha"), (0xb4, "delta")]);
        let blobs = heuristics(&data, &section_at(0, 0x200));
        let options = calibrating(&["alpha", "gamma", "delta"]);
        let (scan, _) = run(&blobs[0], &data, &[], &options);
        let cal = scan.calibration.unwrap();
        assert_eq!(cal.outcome, WITNESSES_OUTSIDE_DATA_IMAGE);
        assert_eq!(cal.witnesses_found, Some(3));
        assert_eq!(cal.witnesses_in_data_image, Some(0));
        assert_eq!(cal.data_image_verdict, Some(VERDICT_NONE_IN_DATA_IMAGE));
        assert_eq!(cal.layout(), None);
        assert_eq!(scan.strings_unavailable, Some(UNSUPPORTED_SNAPSHOT_VERSION));
    }

    #[test]
    fn heuristic_blob_calibrates_on_its_data_image() {
        let data = snapshot_with_strings();
        let blobs = heuristics(&data, &section_at(0, data.len() as u64));
        let options = calibrating(&["hello", "world!", "flutter"]);
        let (scan, anomalies) = run(&blobs[0], &data, &[], &options);
        assert!(anomalies.is_empty(), "{anomalies:?}");
        let cal = scan.calibration.unwrap();
        assert_eq!(cal.outcome, CALIBRATED);
        assert_eq!(cal.data_image_verdict, Some(VERDICT_ALL_IN_DATA_IMAGE));
        assert_eq!(cal.inferred.len(), 1);
        assert_eq!(cal.inferred[0].layout, HEAP);
        let evidence: Vec<(u64, u64)> = cal.inferred[0]
            .evidence
            .iter()
            .map(|e| (e.image_offset, e.file_offset))
            .collect();
        assert_eq!(evidence, vec![(0, 64), (32, 96), (64, 128)]);
        assert_literal_matches_heap(&cal.known_version_literal.unwrap());
        let strings = scan.strings.unwrap();
        assert_eq!(strings.blob_bound, BOUND_HEADER_LENGTH);
        assert_eq!(strings.layout_source, LAYOUT_CALIBRATED);
        assert_eq!(strings.layout, HEAP);
        assert_eq!(strings.accepted, 3);
        let entries: Vec<(u64, u64, &str)> = strings
            .entries
            .iter()
            .map(|e| (e.image_offset, e.file_offset, e.value.as_str()))
            .collect();
        assert_eq!(
            entries,
            vec![(0, 64, "hello"), (32, 96, "world!"), (64, 128, "flutter")]
        );
    }

    #[test]
    fn symbol_blob_still_scans_with_its_symbol_bound() {
        let data = snapshot_with_strings();
        let blob = symbol_blob(&data, BOUND_SYMBOL_SIZE);
        assert_eq!(blob.section.symbol, ISOLATE_DATA);
        let image = blob.section.data_image.unwrap();
        assert_eq!((image.start, image.end), (64, data.len() as u64));
        assert_eq!(image.end_bound, BOUND_SYMBOL_SIZE);
        let known = table(KindLayout::WithFullCore);
        let (scan, anomalies) = run(&blob, &data, &known, &DartOptions::default());
        assert!(anomalies.is_empty(), "{anomalies:?}");
        assert_eq!(scan.calibration, None);
        let strings = scan.strings.unwrap();
        assert_eq!(strings.blob_bound, BOUND_SYMBOL_SIZE);
        assert_eq!(strings.layout_source, LAYOUT_TABLE);
        assert_eq!(strings.accepted, 3);
        let offsets: Vec<u64> = strings.entries.iter().map(|e| e.file_offset).collect();
        assert_eq!(offsets, vec![64, 96, 128]);
    }

    #[test]
    fn section_end_bound_refuses_the_scan() {
        let data = snapshot_with_strings();
        let options = calibrating(&["hello", "world!", "flutter"]);
        let known = table(KindLayout::WithFullCore);
        let (scan, _) = run(&symbol_blob(&data, BOUND_SECTION_END), &data, &known, &options);
        assert_eq!(scan.strings, None);
        assert_eq!(scan.strings_unavailable, Some(DATA_BLOB_SIZE_UNKNOWN));
        let cal = scan.calibration.unwrap();
        assert_eq!(cal.outcome, NOT_RUN);
        assert_eq!(cal.not_run_reason, Some(DATA_BLOB_SIZE_UNKNOWN));
        assert_eq!(cal.data_image_verdict, Some(VERDICT_ALL_IN_DATA_IMAGE));
        let (scan, _) = run(&symbol_blob(&data, BOUND_NEXT_SYMBOL), &data, &known, &options);
        assert_eq!(scan.strings.unwrap().blob_bound, BOUND_NEXT_SYMBOL);
    }

    #[test]
    fn invalid_layout_refuses_the_scan() {
        let data = snapshot_with_strings();
        let mut known = table(KindLayout::WithFullCore);
        known[0].heap.length_width = 3;
        let options = DartOptions::default();
        let blob = symbol_blob(&data, BOUND_SYMBOL_SIZE);
        let (scan, anomalies) = run(&blob, &data, &known, &options);
        assert_eq!(scan.strings_unavailable, Some(INVALID_HEAP_LAYOUT));
        let detail = anomalies
            .iter()
            .find(|a| a.starts_with(INVALID_HEAP_LAYOUT))
            .unwrap();
        assert!(detail.contains("table"));
        assert!(detail.contains("length_width 3"));
    }

    #[test]
    fn layout_rules_are_each_enforced() {
        assert!(HEAP.violations().is_empty());
        let broken = [
            HeapLayout {
                word_size: 6,
                ..HEAP
            },
            HeapLayout {
                object_alignment: 12,
                ..HEAP
            },
            HeapLayout {
                object_alignment: 0,
                ..HEAP
            },
            HeapLayout {
                size_tag_bits: 0,
                ..HEAP
            },
            HeapLayout {
                class_id_tag_pos: 60,
                ..HEAP
            },
            HeapLayout {
                length_offset: 4,
                ..HEAP
            },
            HeapLayout {
                data_offset: 10,
                ..HEAP
            },
            HeapLayout {
                data_offset: 72,
                ..HEAP
            },
            HeapLayout {
                two_byte_string_cid: 0x55,
                ..HEAP
            },
            HeapLayout {
                one_byte_string_cid: 0,
                ..HEAP
            },
        ];
        for layout in broken {
            assert!(!layout.violations().is_empty(), "{layout:?}");
        }
    }

    #[test]
    fn calibration_overrides_a_disagreeing_table() {
        let data = snapshot_with_strings();
        let mut known = table(KindLayout::WithFullCore);
        known[0].heap.object_alignment = 8;
        let options = calibrating(&["hello", "world!", "flutter"]);
        let blob = symbol_blob(&data, BOUND_SYMBOL_SIZE);
        let (scan, anomalies) = run(&blob, &data, &known, &options);
        let strings = scan.strings.unwrap();
        assert_eq!(strings.layout_source, LAYOUT_CALIBRATED);
        assert_eq!(strings.layout, HEAP);
        assert_eq!(strings.accepted, 3);
        assert_eq!(scan.calibration.unwrap().outcome, CALIBRATED);
        assert!(anomalies
            .iter()
            .any(|a| a.starts_with("layout_disagreement")));
    }

    #[test]
    fn libapp_entries_only() {
        assert!(is_libapp("lib/arm64-v8a/libapp.so"));
        assert!(!is_libapp("lib/arm64-v8a/libflutter.so"));
        assert!(!is_libapp("lib/libapp.so"));
        assert!(!is_libapp("assets/lib/x/libapp.so"));
        assert!(!is_libapp("lib/arm64-v8a/sub/libapp.so"));
    }

    #[test]
    fn legend_defines_every_label() {
        let legend = legend();
        let labels = [
            HEURISTIC,
            TRUNCATED_AT_MAGIC,
            MAGIC_MISMATCH,
            TRUNCATED_AT_LENGTH,
            TRUNCATED_AT_KIND,
            TRUNCATED_AT_VERSION_HASH,
            VERSION_HASH_NOT_HEX,
            FEATURES_OFFSET_UNKNOWN,
            FEATURES_UNTERMINATED,
            FEATURES_NOT_UTF8,
            COMPRESSED_POINTERS_CONTRADICTORY,
            ELF_UNREADABLE,
            DATA_BLOB_NOT_FOUND,
            DATA_BLOB_UNBOUNDED,
            DATA_BLOB_SIZE_UNKNOWN,
            DATA_IMAGE_EMPTY,
            VERSION_HASH_UNREADABLE,
            UNSUPPORTED_SNAPSHOT_VERSION,
            INVALID_HEAP_LAYOUT,
            BOUND_SYMBOL_SIZE,
            BOUND_NEXT_SYMBOL,
            BOUND_SECTION_END,
            BOUND_NEXT_MAGIC,
            BOUND_HEADER_LENGTH,
            LAYOUT_CALIBRATED,
            LAYOUT_TABLE,
            CALIBRATED,
            INSUFFICIENT_WITNESSES,
            AMBIGUOUS_LAYOUT,
            NO_LAYOUT_EXPLAINS_WITNESSES,
            WITNESS_NOT_FOUND,
            WITNESSES_NOT_ALL_FOUND,
            WITNESSES_OUTSIDE_DATA_IMAGE,
            NOT_RUN,
            VERDICT_ALL_IN_DATA_IMAGE,
            VERDICT_PARTLY_IN_DATA_IMAGE,
            VERDICT_NONE_IN_DATA_IMAGE,
            VERDICT_NO_WITNESS_FOUND,
            COMPRESSED_POINTERS,
            NO_COMPRESSED_POINTERS,
            ONE_BYTE,
            TWO_BYTE,
            REJECT_TRUNCATED_FIELDS,
            REJECT_LENGTH_NOT_SMI,
            REJECT_LENGTH_NEGATIVE,
            REJECT_LENGTH_OUT_OF_BLOB,
            REJECT_SIZE_TAG_MISMATCH,
            REJECT_UNDECODABLE_UTF16,
            SCAN_METHOD,
            TAG_SOURCE_READ,
            TAG_SOURCE_GUESSED,
            "partial_after_panic",
            "layout_disagreement",
            "symbol_size_zero",
            "entries_total",
            "entries_returned",
            "truncated",
            "blob_bound",
            "layout_source",
            "known_version_literal",
            "derived_cid",
            "witnesses_total",
            "witnesses_found",
            "witnesses_explained",
            "witnesses_in_data_image",
            "data_image_verdict",
            "compressed_pointers",
            "serialized_past_blob_end",
            "blob_index",
            "serialized",
            "data_image",
            "end_bound",
            "start_alignment",
            "start_alignment_source",
            "image_offset",
            "zones",
            "first_offset",
            "outside",
            "data_blobs",
            "kObjectStartAlignment",
            "--dart-max-rows",
            "--dart-calibrate-file",
        ];
        for label in labels {
            assert!(legend.contains(label), "{label}");
        }
        for kind in KINDS_WITH_FULL_CORE.iter().chain(&KINDS_WITH_MODULE) {
            assert!(legend.contains(kind), "{kind}");
        }
        assert!(legend.contains(&format!("Défaut {DEFAULT_MAX_ROWS}")));
        assert!(legend.contains(&format!("Moins de {MIN_WITNESSES} témoins")));
        assert!(!legend.contains("isolate_data"));
    }
}
