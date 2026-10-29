//! Analyse statique de tous les ELF d'un APK et liaison JNI avec les méthodes
//! `native` du DEX (mode `--native`).
//!
//! Lecture seule, sans exécution. Sont lus les en-têtes, les sections, les
//! segments, la table dynamique, les symboles dynamiques, les relocations
//! relatives et les chaînes des sections de données. Le désassemblage n'a lieu
//! qu'avec `--native-disasm` (module `disasm`).
//!
//! Est retenue toute entrée dont les quatre premiers octets DÉCOMPRESSÉS valent
//! `\x7FELF`, quel que soit le chemin : un packer range son stub dans `assets/`,
//! un dropper son exécutable dans `res/raw/` sous un nom quelconque. Le `sha256`
//! suit la sémantique de [`super::native_extract`] : contenu décompressé, jamais
//! tronqué.
//!
//! Dans un `.so` PIE, les trois pointeurs d'une entrée `JNINativeMethod` valent
//! 0 dans le fichier : le chargeur les remplit par relocations relatives. Les
//! emplacements relogés sont donc résolus d'abord, base de chargement 0, et les
//! pointeurs lus à travers cette résolution. Comme le chargeur de bionic, on
//! prend les relocations dans `PT_DYNAMIC` ; les section headers ne servent
//! qu'en son absence.
//!
//! Toutes les étiquettes produites sont définies dans [`legend`].

use anyhow::{Context, Result};
use object::elf;
use object::read::elf::{Dyn, FileHeader, ProgramHeader, SectionHeader, SectionTable, Sym};
use object::Endianness;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::Ipv4Addr;
use std::panic::AssertUnwindSafe;
use std::path::Path;

use super::apkzip::TolerantZip;
use super::dex_facade::DexBin;
use super::native_arch::{expected_arch, parse_elf_header, Abi, Bits, ElfArch, Endian, Machine};

mod decode;
mod disasm;
mod jni_table;

pub use self::disasm::{
    DisasmCall, DisasmFunction, DisasmInsn, DisasmOptions, ElfDisasm, InvalidPath, JavaMember,
    JniCall, StringRef, Syscall, TruncatedAt,
};

/// Catégories d'imports : noms exacts, ou préfixes quand ils finissent par `*`.
pub const IMPORT_CATEGORIES: &[(&str, &str)] = &[
    ("process", "fork execve execl* system popen posix_spawn"),
    ("injection", "ptrace process_vm_writev process_vm_readv"),
    ("dynload", "dlopen dlsym android_dlopen_ext"),
    ("memory", "mmap mprotect munmap mremap"),
    (
        "network",
        "socket connect bind listen accept send* recv* getaddrinfo",
    ),
    ("crypto", "EVP_* AES_* RC4* MD5* SHA*"),
    (
        "anti_analysis",
        "__system_property_get inotify_* prctl kill getppid",
    ),
    ("file", "open openat fopen unlink rename chmod"),
];

/// Exports rangés dans `imports.jni`.
pub const JNI_EXPORTS: &str = "JNI_OnLoad JNI_OnUnload";

pub const SHELL_COMMANDS: &str = "sh su chmod chown mount umount pm am setprop getprop \
    iptables ip6tables busybox toybox insmod kill rm settings dumpsys logcat cat echo dd";

/// Caractères après lesquels une commande de [`SHELL_COMMANDS`] est reconnue.
pub const SHELL_BOUNDARIES: &str = "/;|&`(\"'";

pub const JAVA_PACKAGE_ROOTS: &str = "com/ org/ android/ androidx/ java/ javax/ dalvik/ kotlin/";

pub const STATUS_STATIC: &str = "static";
pub const STATUS_REGISTERED: &str = "registered";
pub const STATUS_AMBIGUOUS: &str = "registered_ambiguous";
pub const STATUS_UNBOUND: &str = "declared_unbound";
pub const STATUS_UNCLAIMED: &str = "native_unclaimed";

/// Upcalls de director SWIG : méthodes Java statiques non natives que le code
/// généré appelle depuis le natif.
pub const SWIG_DIRECTOR_PREFIX: &str = "SwigDirector_";

const ORIGIN_LIB: &str = "lib";
const ELF_MAGIC: &[u8] = b"\x7FELF";
const STRINGS_CAP: usize = 50;
const MIN_STRING_CHARS: usize = 4;
const PACKING_ENTROPY: f64 = 7.2;
const MAX_NAME_LEN: usize = 256;
const MAX_SIGNATURE_LEN: usize = 1024;
const MAX_DYNSTR_LEN: usize = 4096;

// Absentes du crate `object`. DT_RELR* : glibc elf/elf.h. *_ANDROID_* : bionic
// libc/include/elf.h.
const DT_RELRSZ: u32 = 35;
const DT_RELR: u32 = 36;
const DT_ANDROID_REL: u32 = 0x6000_000f;
const DT_ANDROID_RELA: u32 = 0x6000_0011;
const DT_ANDROID_RELR: u32 = 0x6fff_e000;
const DT_ANDROID_RELRSZ: u32 = 0x6fff_e001;
const SHT_ANDROID_REL: u32 = 0x6000_0001;
const SHT_ANDROID_RELA: u32 = 0x6000_0002;
const SHT_ANDROID_RELR: u32 = 0x6fff_ff00;

const RELOC_TAGS: [(u32, u32, RelocFormat); 4] = [
    (elf::DT_RELA, elf::DT_RELASZ, RelocFormat::Rela),
    (elf::DT_REL, elf::DT_RELSZ, RelocFormat::Rel),
    (DT_RELR, DT_RELRSZ, RelocFormat::Relr),
    (DT_ANDROID_RELR, DT_ANDROID_RELRSZ, RelocFormat::Relr),
];

const PACKED_TAGS: [(u32, &str); 2] = [
    (DT_ANDROID_REL, "DT_ANDROID_REL (format packé APS2)"),
    (DT_ANDROID_RELA, "DT_ANDROID_RELA (format packé APS2)"),
];

/// Rapport `--native` d'un APK.
#[derive(Debug, Clone, Serialize)]
pub struct NativeReport {
    pub sha256: String,
    pub elfs: Vec<ElfReport>,
    pub binding: Vec<Binding>,
    pub summary: Summary,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ElfReport {
    pub path: String,
    pub origin: &'static str,
    pub sha256: String,
    pub size: u64,
    pub machine: String,
    pub bits: u8,
    pub endian: &'static str,
    pub declared_abi: Option<String>,
    pub abi_mismatch: bool,
    pub elf_type: &'static str,
    pub pie: bool,
    pub stripped: bool,
    pub interp: Option<String>,
    pub sections: Vec<SectionInfo>,
    pub segments: Vec<SegmentInfo>,
    pub needed: Vec<String>,
    pub soname: Option<String>,
    pub init: Option<String>,
    pub init_array_count: u64,
    pub imports: Imports,
    pub exports_count: usize,
    pub jni: JniInfo,
    pub strings: Strings,
    pub anomalies: Vec<String>,
    /// Présent avec `--native-disasm` seulement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disasm: Option<ElfDisasm>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectionInfo {
    pub name: String,
    pub size: u64,
    pub flags: String,
    pub entropy: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SegmentInfo {
    #[serde(rename = "type")]
    pub kind: String,
    pub flags: String,
    pub vaddr: String,
    pub size: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Imports {
    pub process: Vec<String>,
    pub injection: Vec<String>,
    pub dynload: Vec<String>,
    pub memory: Vec<String>,
    pub network: Vec<String>,
    pub crypto: Vec<String>,
    pub anti_analysis: Vec<String>,
    pub file: Vec<String>,
    pub jni: Vec<String>,
    pub other_count: usize,
}

impl Imports {
    /// Les catégories, dans l'ordre de la sortie JSON.
    pub fn categories(&self) -> [(&'static str, &[String]); 9] {
        [
            ("process", self.process.as_slice()),
            ("injection", self.injection.as_slice()),
            ("dynload", self.dynload.as_slice()),
            ("memory", self.memory.as_slice()),
            ("network", self.network.as_slice()),
            ("crypto", self.crypto.as_slice()),
            ("anti_analysis", self.anti_analysis.as_slice()),
            ("file", self.file.as_slice()),
            ("jni", self.jni.as_slice()),
        ]
    }

    fn add(&mut self, symbol: &str) {
        let bucket = match import_category(symbol) {
            Some("process") => &mut self.process,
            Some("injection") => &mut self.injection,
            Some("dynload") => &mut self.dynload,
            Some("memory") => &mut self.memory,
            Some("network") => &mut self.network,
            Some("crypto") => &mut self.crypto,
            Some("anti_analysis") => &mut self.anti_analysis,
            Some("file") => &mut self.file,
            _ => {
                self.other_count += 1;
                return;
            }
        };
        bucket.push(symbol.to_string());
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct JniInfo {
    pub jni_onload: bool,
    pub registernatives_string: bool,
    pub jni_registration: &'static str,
    pub static_exports: Vec<StaticExport>,
    pub registered: Vec<RegisteredMethod>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub swig_director_upcalls: Vec<SwigUpcall>,
}

impl Default for JniInfo {
    fn default() -> Self {
        JniInfo {
            jni_onload: false,
            registernatives_string: false,
            jni_registration: "none",
            static_exports: Vec::new(),
            registered: Vec::new(),
            swig_director_upcalls: Vec::new(),
        }
    }
}

/// Entrée `{method, signature}` de la table que le `swig_module_init` généré
/// par SWIG passe à GetStaticMethodID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SwigUpcall {
    pub name: String,
    pub signature: String,
    pub table_offset: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StaticExport {
    pub symbol: String,
    pub class: String,
    pub method: String,
    pub signature: Option<String>,
    /// Bit Thumb déjà effacé. Exposé dans `binding[].fn_offset`.
    #[serde(skip)]
    pub address: u64,
}

impl StaticExport {
    fn binds(&self, m: &NativeMethod) -> bool {
        self.class == m.class
            && self.method == m.name
            && self.signature.as_deref().is_none_or(|s| s == m.params)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegisteredMethod {
    pub name: String,
    pub signature: String,
    pub fn_offset: String,
    pub table_offset: String,
    pub thumb: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct StringBucket {
    pub total: usize,
    pub items: Vec<String>,
}

impl StringBucket {
    fn push(&mut self, s: &str) {
        self.total += 1;
        if self.items.len() < STRINGS_CAP {
            self.items.push(s.to_string());
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Strings {
    pub paths: StringBucket,
    pub urls: StringBucket,
    pub ips: StringBucket,
    pub shell: StringBucket,
    pub java_classes: StringBucket,
    pub jni_signatures: StringBucket,
}

impl Strings {
    pub fn categories(&self) -> [(&'static str, &StringBucket); 6] {
        [
            ("paths", &self.paths),
            ("urls", &self.urls),
            ("ips", &self.ips),
            ("shell", &self.shell),
            ("java_classes", &self.java_classes),
            ("jni_signatures", &self.jni_signatures),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Binding {
    pub java: String,
    pub status: &'static str,
    pub elf: Option<String>,
    pub elf_sha256: Option<String>,
    pub fn_offset: Option<String>,
    pub candidates: Vec<String>,
    /// Avec `--native-disasm`, sur une ligne registered_ambiguous levée par un
    /// RegisterNatives dont la classe vient de FindClass.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disambiguated_by: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
}

impl Binding {
    fn found(
        java: &str,
        status: &'static str,
        elf: &ElfReport,
        fn_offset: String,
        candidates: Vec<String>,
    ) -> Self {
        Binding {
            java: java.to_string(),
            status,
            elf: Some(elf.path.clone()),
            elf_sha256: Some(elf.sha256.clone()),
            fn_offset: Some(fn_offset),
            candidates,
            disambiguated_by: None,
            class: None,
        }
    }

    fn unbound(java: String) -> Self {
        Binding {
            java,
            status: STATUS_UNBOUND,
            elf: None,
            elf_sha256: None,
            fn_offset: None,
            candidates: Vec::new(),
            disambiguated_by: None,
            class: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub elf_count: usize,
    pub native_methods_declared: usize,
    pub bound_static: usize,
    pub bound_registered: usize,
    pub ambiguous: usize,
    pub unbound: usize,
    pub unclaimed: usize,
}

/// Méthode `ACC_NATIVE` du DEX.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeMethod {
    /// Forme Dalvik : `Lcom/foo/Bar;`.
    pub class: String,
    pub name: String,
    /// Arguments seuls : `(ILjava/lang/String;)`.
    pub params: String,
    pub ret: String,
}

impl NativeMethod {
    pub fn java(&self) -> String {
        let NativeMethod {
            class,
            name,
            params,
            ret,
        } = self;
        format!("{class}->{name}{params}{ret}")
    }

    pub fn signature(&self) -> String {
        format!("{}{}", self.params, self.ret)
    }
}

/// Analyse un APK sur disque. Seule une archive illisible fait échouer le mode :
/// un ELF illisible devient une anomalie, une entrée illisible une erreur.
/// `disasm` active `--native-disasm`.
pub fn analyze_apk(path: &Path, disasm: Option<&DisasmOptions>) -> Result<NativeReport> {
    let sha256 = file_sha256(path)?;
    let zip = TolerantZip::open(path)?;
    let mut errors = Vec::new();
    let mut elfs = Vec::new();
    let mut kept = Vec::new();
    for (index, entry) in zip.entries().iter().enumerate() {
        let bytes = match zip.read(index) {
            Ok(bytes) => bytes,
            Err(e) => {
                errors.push(format!("{}: entrée illisible ({e:#})", entry.name));
                continue;
            }
        };
        if bytes.starts_with(ELF_MAGIC) {
            elfs.push(analyze_elf(&entry.name, &bytes));
            if disasm.is_some() {
                kept.push(bytes);
            }
        }
    }

    let natives = declared_natives(path, &mut errors);
    if let Some(options) = disasm {
        self::disasm::silence_panics(|| {
            for (elf, bytes) in elfs.iter_mut().zip(&kept) {
                self::disasm::run(bytes, elf, options);
            }
        });
        for elf in &mut elfs {
            self::disasm::adopt_tables(elf);
        }
    }
    let mut binding = match &natives {
        Some(natives) => bind(natives, &elfs),
        None => Vec::new(),
    };
    if disasm.is_some() {
        self::disasm::disambiguate(&elfs, &mut binding);
    }
    let declared = natives.as_ref().map_or(0, Vec::len);
    let summary = summarize(&binding, declared, elfs.len());
    Ok(NativeReport {
        sha256,
        elfs,
        binding,
        summary,
        errors,
    })
}

fn analyze_elf(path: &str, bytes: &[u8]) -> ElfReport {
    let mut report = ElfReport::new(path, bytes);
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| inspect(bytes, &mut report)));
    let failure = match outcome {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e.to_string()),
        Err(_) => Some("panique pendant l'analyse".to_string()),
    };
    if let Some(reason) = failure {
        report.anomalies.push(format!("elf_unreadable: {reason}"));
    }
    report
}

impl ElfReport {
    fn new(path: &str, bytes: &[u8]) -> Self {
        let abi = declared_abi(path);
        let arch = parse_elf_header(bytes);
        let abi_mismatch = match (&abi, arch) {
            (Some(abi), Some(arch)) => is_mismatch(abi, arch),
            _ => false,
        };
        let machine = match arch {
            Some(a) => a.machine.label(),
            None => "unknown".to_string(),
        };
        let bits = match arch.map(|a| a.bits) {
            Some(Bits::B32) => 32,
            Some(Bits::B64) => 64,
            None => 0,
        };
        let endian = match arch.map(|a| a.endian) {
            Some(Endian::Little) => "little",
            Some(Endian::Big) => "big",
            None => "unknown",
        };
        let origin = origin_of(path);
        let mut anomalies = Vec::new();
        if abi_mismatch {
            anomalies.push(format!(
                "abi_mismatch: ELF {machine} {bits} bits dans {path}"
            ));
        }
        if origin != ORIGIN_LIB {
            anomalies.push(format!("elf_outside_lib: {origin}"));
        }
        ElfReport {
            path: path.to_string(),
            origin,
            sha256: format!("{:x}", Sha256::digest(bytes)),
            size: bytes.len() as u64,
            machine,
            bits,
            endian,
            declared_abi: abi.map(|a| a.label()),
            abi_mismatch,
            elf_type: "other",
            pie: false,
            stripped: false,
            interp: None,
            sections: Vec::new(),
            segments: Vec::new(),
            needed: Vec::new(),
            soname: None,
            init: None,
            init_array_count: 0,
            imports: Imports::default(),
            exports_count: 0,
            jni: JniInfo::default(),
            strings: Strings::default(),
            anomalies,
            disasm: None,
        }
    }
}

fn origin_of(path: &str) -> &'static str {
    if path.starts_with("lib/") {
        ORIGIN_LIB
    } else if path.starts_with("assets/") {
        "assets"
    } else if path.starts_with("res/raw/") {
        "res_raw"
    } else {
        "other"
    }
}

fn declared_abi(path: &str) -> Option<Abi> {
    let mut parts = path.split('/');
    if parts.next() != Some("lib") {
        return None;
    }
    let dir = parts.next()?;
    parts.next()?;
    Some(Abi::from_dir(dir))
}

fn is_mismatch(abi: &Abi, arch: ElfArch) -> bool {
    match expected_arch(abi) {
        Some((machine, bits)) => {
            !matches!(arch.machine, Machine::Unknown(_))
                && (arch.machine != machine || arch.bits != bits)
        }
        None => false,
    }
}

struct Segment {
    p_type: u32,
    flags: u32,
    vaddr: u64,
    memsz: u64,
    offset: u64,
    filesz: u64,
}

impl Segment {
    fn has(&self, flag: u32) -> bool {
        self.flags & flag != 0
    }

    fn in_file(&self, at: u64) -> bool {
        at.checked_sub(self.vaddr).is_some_and(|d| d < self.filesz)
    }

    fn in_memory(&self, at: u64) -> bool {
        at.checked_sub(self.vaddr).is_some_and(|d| d < self.memsz)
    }
}

struct Section {
    name: String,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
}

impl Section {
    fn has(&self, flag: u32) -> bool {
        self.flags & u64::from(flag) != 0
    }

    fn has_file_data(&self) -> bool {
        self.sh_type != elf::SHT_NOBITS
    }
}

struct DynSymbol {
    name: String,
    defined: bool,
    bind: u8,
    value: u64,
    size: u64,
    func: bool,
}

struct Region<'a> {
    vaddr: u64,
    bytes: &'a [u8],
    read_only: bool,
}

/// L'ELF tel que le voit le chargeur : octets du fichier, segments, et sections
/// quand elles sont lisibles.
struct Image<'a> {
    data: &'a [u8],
    ptr_size: u64,
    big_endian: bool,
    machine: u16,
    segments: Vec<Segment>,
    sections: Vec<Section>,
}

impl Image<'_> {
    fn bytes_at(&self, offset: u64, size: u64) -> Option<&[u8]> {
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(size).ok()?)?;
        self.data.get(start..end)
    }

    fn offset_of(&self, vaddr: u64) -> Option<u64> {
        for s in &self.segments {
            if s.p_type == elf::PT_LOAD && s.in_file(vaddr) {
                return s.offset.checked_add(vaddr - s.vaddr);
            }
        }
        None
    }

    fn word_at(&self, vaddr: u64) -> Option<u64> {
        let bytes = self.bytes_at(self.offset_of(vaddr)?, self.ptr_size)?;
        read_uint(bytes, self.big_endian)
    }

    fn cstr_at(&self, vaddr: u64, max_len: usize) -> Option<&str> {
        let start = usize::try_from(self.offset_of(vaddr)?).ok()?;
        let tail = self.data.get(start..)?;
        let window = &tail[..tail.len().min(max_len + 1)];
        let len = window.iter().position(|&b| b == 0)?;
        if len == 0 {
            return None;
        }
        std::str::from_utf8(&window[..len]).ok()
    }

    fn is_exec(&self, vaddr: u64) -> bool {
        self.segments
            .iter()
            .any(|s| s.p_type == elf::PT_LOAD && s.has(elf::PF_X) && s.in_memory(vaddr))
    }

    /// Sections allouées non exécutables ; à défaut, segments LOAD.
    fn data_regions(&self, with_exec_segments: bool) -> Vec<Region<'_>> {
        let mut regions = Vec::new();
        for s in &self.sections {
            if !s.has(elf::SHF_ALLOC) || s.has(elf::SHF_EXECINSTR) || !s.has_file_data() {
                continue;
            }
            if let Some(bytes) = self.bytes_at(s.offset, s.size) {
                regions.push(Region {
                    vaddr: s.addr,
                    bytes,
                    read_only: !s.has(elf::SHF_WRITE),
                });
            }
        }
        if !regions.is_empty() {
            return regions;
        }
        for s in &self.segments {
            if s.p_type != elf::PT_LOAD || (s.has(elf::PF_X) && !with_exec_segments) {
                continue;
            }
            if let Some(bytes) = self.bytes_at(s.offset, s.filesz) {
                regions.push(Region {
                    vaddr: s.vaddr,
                    bytes,
                    read_only: !s.has(elf::PF_W),
                });
            }
        }
        regions
    }
}

struct Parsed<'a> {
    image: Image<'a>,
    e_type: u16,
    entry: u64,
    dynamic: Option<Vec<(u64, u64)>>,
    symbols: Vec<DynSymbol>,
    /// `.symtab`, quand l'ELF n'est pas strippé.
    local_symbols: Vec<DynSymbol>,
    anomalies: Vec<String>,
}

fn parse_elf(data: &[u8]) -> object::read::Result<Parsed<'_>> {
    if data.get(4) == Some(&elf::ELFCLASS64) {
        parse_with(elf::FileHeader64::<Endianness>::parse(data)?, data)
    } else {
        parse_with(elf::FileHeader32::<Endianness>::parse(data)?, data)
    }
}

fn parse_with<'a, Elf>(header: &'a Elf, data: &'a [u8]) -> object::read::Result<Parsed<'a>>
where
    Elf: FileHeader<Endian = Endianness>,
{
    let endian = header.endian()?;
    let mut anomalies = Vec::new();

    let mut segments = Vec::new();
    let mut dynamic = None;
    for phdr in header.program_headers(endian, data)? {
        let segment = Segment {
            p_type: phdr.p_type(endian),
            flags: phdr.p_flags(endian),
            vaddr: phdr.p_vaddr(endian).into(),
            memsz: phdr.p_memsz(endian).into(),
            offset: phdr.p_offset(endian).into(),
            filesz: phdr.p_filesz(endian).into(),
        };
        if segment.p_type == elf::PT_DYNAMIC && dynamic.is_none() {
            match phdr.dynamic(endian, data) {
                Ok(entries) => dynamic = entries.map(|e| dyn_pairs::<Elf>(e, endian)),
                Err(e) => note(&mut anomalies, "dynamic_unreadable", e),
            }
        }
        segments.push(segment);
    }

    let mut sections = Vec::new();
    let mut symbols = Vec::new();
    let mut local_symbols = Vec::new();
    match header.sections(endian, data) {
        Ok(table) if table.is_empty() => {
            note(&mut anomalies, "section_headers_absent", "table vide");
        }
        Ok(table) => {
            for sh in table.iter() {
                let name = table.section_name(endian, sh).unwrap_or_default();
                sections.push(Section {
                    name: String::from_utf8_lossy(name).into_owned(),
                    sh_type: sh.sh_type(endian),
                    flags: sh.sh_flags(endian).into(),
                    addr: sh.sh_addr(endian).into(),
                    offset: sh.sh_offset(endian).into(),
                    size: sh.sh_size(endian).into(),
                });
            }
            match read_symbols(&table, endian, data, elf::SHT_DYNSYM) {
                Ok(list) => symbols = list,
                Err(e) => note(&mut anomalies, "section_headers_incoherent", e),
            }
            if let Ok(list) = read_symbols(&table, endian, data, elf::SHT_SYMTAB) {
                local_symbols = list;
            }
        }
        Err(e) => note(&mut anomalies, "section_headers_invalid", e),
    }
    symbols.sort_by(|a, b| a.name.cmp(&b.name));

    let image = Image {
        data,
        ptr_size: if header.is_type_64() { 8 } else { 4 },
        big_endian: header.is_big_endian(),
        machine: header.e_machine(endian),
        segments,
        sections,
    };
    Ok(Parsed {
        image,
        e_type: header.e_type(endian),
        entry: header.e_entry(endian).into(),
        dynamic,
        symbols,
        local_symbols,
        anomalies,
    })
}

fn read_symbols<'data, Elf>(
    table: &SectionTable<'data, Elf>,
    endian: Endianness,
    data: &'data [u8],
    sh_type: u32,
) -> object::read::Result<Vec<DynSymbol>>
where
    Elf: FileHeader<Endian = Endianness>,
{
    let symtab = table.symbols(endian, data, sh_type)?;
    let mut symbols = Vec::new();
    for sym in symtab.iter() {
        let Ok(name) = symtab.symbol_name(endian, sym) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        symbols.push(DynSymbol {
            name: String::from_utf8_lossy(name).into_owned(),
            defined: !sym.is_undefined(endian),
            bind: sym.st_bind(),
            value: sym.st_value(endian).into(),
            size: sym.st_size(endian).into(),
            func: sym.st_type() == elf::STT_FUNC,
        });
    }
    Ok(symbols)
}

fn dyn_pairs<Elf>(entries: &[Elf::Dyn], endian: Elf::Endian) -> Vec<(u64, u64)>
where
    Elf: FileHeader<Endian = Endianness>,
{
    let mut pairs = Vec::new();
    for entry in entries {
        let tag: u64 = entry.d_tag(endian).into();
        if tag == u64::from(elf::DT_NULL) {
            break;
        }
        pairs.push((tag, entry.d_val(endian).into()));
    }
    pairs
}

fn inspect(bytes: &[u8], report: &mut ElfReport) -> object::read::Result<()> {
    let Parsed {
        image,
        e_type,
        entry,
        dynamic,
        symbols,
        anomalies,
        ..
    } = parse_elf(bytes)?;
    report.anomalies.extend(anomalies);
    report.elf_type = match e_type {
        elf::ET_EXEC => "exec",
        elf::ET_DYN => "dyn",
        elf::ET_REL => "rel",
        _ => "other",
    };
    report.pie = e_type == elf::ET_DYN;
    report.stripped = !image.sections.iter().any(|s| s.sh_type == elf::SHT_SYMTAB);
    for s in &image.segments {
        if s.p_type == elf::PT_INTERP {
            report.interp = image.bytes_at(s.offset, s.filesz).map(c_string);
        }
    }
    if entry != 0 && e_type != elf::ET_REL && !image.is_exec(entry) {
        note(&mut report.anomalies, "entry_outside_exec", hex(entry));
    }

    describe_segments(&image, report);
    describe_sections(&image, report);
    if let Some(entries) = &dynamic {
        describe_dynamic(&image, entries, report);
    }
    describe_symbols(&symbols, image.machine == elf::EM_ARM, report);

    let tables = match &dynamic {
        Some(entries) => dynamic_relocs(&image, entries, &mut report.anomalies),
        None => section_relocs(&image, &mut report.anomalies),
    };
    let slots = relocated_slots(&image, &tables, &mut report.anomalies);
    report.jni.registered = scan_jni_tables(&image, &slots);
    report.jni.swig_director_upcalls = scan_swig_tables(&image, &slots);
    report.jni.registernatives_string = has_registernatives(&image);
    report.jni.jni_registration = registration_status(&report.jni);
    describe_strings(&image, &mut report.strings);
    Ok(())
}

fn describe_segments(image: &Image, report: &mut ElfReport) {
    let anomalies = &mut report.anomalies;
    for s in &image.segments {
        if s.p_type == elf::PT_LOAD && s.has(elf::PF_W) && s.has(elf::PF_X) {
            note(anomalies, "segment_wx", hex(s.vaddr));
        }
        report.segments.push(SegmentInfo {
            kind: segment_type(s.p_type),
            flags: segment_flags(s.flags),
            vaddr: hex(s.vaddr),
            size: s.memsz,
        });
    }
}

fn describe_sections(image: &Image, report: &mut ElfReport) {
    let anomalies = &mut report.anomalies;
    for s in &image.sections {
        if s.sh_type == elf::SHT_NULL {
            continue;
        }
        let content = if s.has_file_data() {
            image.bytes_at(s.offset, s.size)
        } else {
            Some(&[][..])
        };
        if content.is_none() {
            note(anomalies, "section_headers_incoherent", s.name.as_str());
        }
        let entropy = content.map_or(0.0, shannon_entropy);
        let exec = s.has(elf::SHF_EXECINSTR);
        if exec && s.has(elf::SHF_WRITE) {
            note(anomalies, "section_wx", s.name.as_str());
        }
        if exec && entropy > PACKING_ENTROPY {
            let detail = format!("{} {entropy:.2}", s.name);
            note(anomalies, "high_entropy_exec", detail);
        }
        report.sections.push(SectionInfo {
            name: s.name.clone(),
            size: s.size,
            flags: section_flags(s),
            entropy: round3(entropy),
        });
    }
}

fn describe_dynamic(image: &Image, dynamic: &[(u64, u64)], report: &mut ElfReport) {
    let strtab = dyn_tag(dynamic, elf::DT_STRTAB);
    for &(tag, value) in dynamic {
        if tag != u64::from(elf::DT_NEEDED) {
            continue;
        }
        let name = match dyn_string(image, strtab, value) {
            Some(name) => name,
            None => format!("?{value:#x}"),
        };
        report.needed.push(name);
    }
    if let Some(offset) = dyn_tag(dynamic, elf::DT_SONAME) {
        report.soname = dyn_string(image, strtab, offset);
    }
    report.init = dyn_tag(dynamic, elf::DT_INIT).map(hex);
    if let Some(size) = dyn_tag(dynamic, elf::DT_INIT_ARRAYSZ) {
        report.init_array_count = size / image.ptr_size;
    }
}

fn dyn_tag(dynamic: &[(u64, u64)], tag: u32) -> Option<u64> {
    let tag = u64::from(tag);
    dynamic.iter().find(|e| e.0 == tag).map(|e| e.1)
}

fn dyn_string(image: &Image, strtab: Option<u64>, offset: u64) -> Option<String> {
    let at = strtab?.checked_add(offset)?;
    image.cstr_at(at, MAX_DYNSTR_LEN).map(str::to_string)
}

fn describe_symbols(symbols: &[DynSymbol], arm32: bool, report: &mut ElfReport) {
    let mut malformed = Vec::new();
    for sym in symbols {
        if !sym.defined {
            report.imports.add(&sym.name);
            continue;
        }
        if !matches!(sym.bind, elf::STB_GLOBAL | elf::STB_WEAK) {
            continue;
        }
        report.exports_count += 1;
        if JNI_EXPORTS.split_whitespace().any(|n| n == sym.name) {
            report.imports.jni.push(sym.name.clone());
        }
        if !sym.name.starts_with("Java_") {
            continue;
        }
        match demangle_jni(&sym.name) {
            Some(mut export) => {
                export.address = if arm32 { sym.value & !1 } else { sym.value };
                report.jni.static_exports.push(export);
            }
            None => malformed.push(sym.name.clone()),
        }
    }
    for name in malformed {
        note(&mut report.anomalies, "jni_export_malformed", name);
    }
    report.jni.jni_onload = report.imports.jni.iter().any(|n| n == "JNI_OnLoad");
}

fn registration_status(jni: &JniInfo) -> &'static str {
    if !jni.registered.is_empty() {
        "tables_found"
    } else if jni.jni_onload {
        "unresolved"
    } else {
        "none"
    }
}

#[derive(Clone, Copy)]
enum RelocFormat {
    Rel,
    Rela,
    Relr,
}

struct RelocTable {
    format: RelocFormat,
    offset: u64,
    size: u64,
    origin: String,
}

fn dynamic_relocs(
    image: &Image,
    dynamic: &[(u64, u64)],
    anomalies: &mut Vec<String>,
) -> Vec<RelocTable> {
    let mut tables = Vec::new();
    for (address_tag, size_tag, format) in RELOC_TAGS {
        let Some(address) = dyn_tag(dynamic, address_tag) else {
            continue;
        };
        let Some(offset) = image.offset_of(address) else {
            let detail = format!("d_tag {address_tag:#x}, adresse {address:#x}");
            note(anomalies, "relocation_unreadable", detail);
            continue;
        };
        tables.push(RelocTable {
            format,
            offset,
            size: dyn_tag(dynamic, size_tag).unwrap_or(0),
            origin: format!("d_tag {address_tag:#x}"),
        });
    }
    for (tag, label) in PACKED_TAGS {
        if dyn_tag(dynamic, tag).is_some() {
            note(anomalies, "relocation_unsupported", label);
        }
    }
    tables
}

fn section_relocs(image: &Image, anomalies: &mut Vec<String>) -> Vec<RelocTable> {
    let mut tables = Vec::new();
    for s in &image.sections {
        let format = match s.sh_type {
            elf::SHT_RELA => RelocFormat::Rela,
            elf::SHT_REL => RelocFormat::Rel,
            elf::SHT_RELR | SHT_ANDROID_RELR => RelocFormat::Relr,
            SHT_ANDROID_REL | SHT_ANDROID_RELA => {
                note(anomalies, "relocation_unsupported", s.name.as_str());
                continue;
            }
            _ => continue,
        };
        if !s.has(elf::SHF_ALLOC) {
            continue;
        }
        tables.push(RelocTable {
            format,
            offset: s.offset,
            size: s.size,
            origin: s.name.clone(),
        });
    }
    tables
}

/// Emplacement → valeur après relocation relative, base de chargement 0.
fn relocated_slots(
    image: &Image,
    tables: &[RelocTable],
    anomalies: &mut Vec<String>,
) -> HashMap<u64, u64> {
    let mut slots = HashMap::new();
    if tables.is_empty() {
        return slots;
    }
    let machine = image.machine;
    let Some(relative) = relative_type(machine) else {
        let detail = format!("type RELATIVE non modélisé pour e_machine {machine}");
        note(anomalies, "relocation_unsupported", detail);
        return slots;
    };
    let word = image.ptr_size as usize;
    for table in tables {
        let Some(bytes) = image.bytes_at(table.offset, table.size) else {
            note(anomalies, "relocation_unreadable", table.origin.as_str());
            continue;
        };
        let words: Vec<u64> = bytes
            .chunks_exact(word)
            .filter_map(|w| read_uint(w, image.big_endian))
            .collect();
        match table.format {
            RelocFormat::Rela => {
                for entry in words.as_chunks::<3>().0 {
                    if reloc_type(entry[1], image.ptr_size) == relative {
                        slots.insert(entry[0], entry[2]);
                    }
                }
            }
            RelocFormat::Rel => {
                for entry in words.as_chunks::<2>().0 {
                    if reloc_type(entry[1], image.ptr_size) != relative {
                        continue;
                    }
                    if let Some(value) = image.word_at(entry[0]) {
                        slots.insert(entry[0], value);
                    }
                }
            }
            RelocFormat::Relr => apply_relr(image, &words, &mut slots),
        }
    }
    slots
}

/// RELR : une adresse paire reloge cet emplacement ; un mot impair est une
/// bitmap des emplacements qui suivent. L'addend est lu en place.
fn apply_relr(image: &Image, words: &[u64], slots: &mut HashMap<u64, u64>) {
    let ps = image.ptr_size;
    let mut next = 0u64;
    for &entry in words {
        if entry & 1 == 0 {
            relocate_in_place(image, entry, slots);
            next = entry.wrapping_add(ps);
            continue;
        }
        let mut bitmap = entry >> 1;
        let mut at = next;
        while bitmap != 0 {
            if bitmap & 1 == 1 {
                relocate_in_place(image, at, slots);
            }
            bitmap >>= 1;
            at = at.wrapping_add(ps);
        }
        next = next.wrapping_add((ps * 8 - 1) * ps);
    }
}

fn relocate_in_place(image: &Image, at: u64, slots: &mut HashMap<u64, u64>) {
    if let Some(value) = image.word_at(at) {
        slots.insert(at, value);
    }
}

fn relative_type(machine: u16) -> Option<u32> {
    match machine {
        elf::EM_AARCH64 => Some(elf::R_AARCH64_RELATIVE),
        elf::EM_ARM => Some(elf::R_ARM_RELATIVE),
        elf::EM_X86_64 => Some(elf::R_X86_64_RELATIVE),
        elf::EM_386 => Some(elf::R_386_RELATIVE),
        elf::EM_RISCV => Some(elf::R_RISCV_RELATIVE),
        _ => None,
    }
}

fn reloc_type(info: u64, ptr_size: u64) -> u32 {
    if ptr_size == 8 {
        (info & 0xffff_ffff) as u32
    } else {
        (info & 0xff) as u32
    }
}

fn scan_jni_tables(image: &Image, slots: &HashMap<u64, u64>) -> Vec<RegisteredMethod> {
    let stride = 3 * image.ptr_size;
    let mut found = Vec::new();
    for region in image.data_regions(false) {
        let end = region.vaddr.saturating_add(region.bytes.len() as u64);
        let mut at = region
            .vaddr
            .checked_next_multiple_of(image.ptr_size)
            .unwrap_or(u64::MAX);
        while at.saturating_add(stride) <= end {
            let Some(mut entry) = jni_entry_at(image, slots, at) else {
                at += image.ptr_size;
                continue;
            };
            let table = hex(at);
            loop {
                entry.table_offset = table.clone();
                found.push(entry);
                at += stride;
                if at.saturating_add(stride) > end {
                    break;
                }
                match jni_entry_at(image, slots, at) {
                    Some(next) => entry = next,
                    None => break,
                }
            }
        }
    }
    found
}

/// Un nom `SwigDirector_*` est refusé : sur une table SWIG `{method,
/// signature}` lue par pas de trois pointeurs, fnPtr serait le nom de l'entrée
/// suivante, exécutable quand .rodata partage le segment du code.
fn jni_entry_at(image: &Image, slots: &HashMap<u64, u64>, at: u64) -> Option<RegisteredMethod> {
    let ps = image.ptr_size;
    let name = image.cstr_at(pointer(image, slots, at)?, MAX_NAME_LEN)?;
    if !is_java_identifier(name) || name.starts_with(SWIG_DIRECTOR_PREFIX) {
        return None;
    }
    let signature = image.cstr_at(pointer(image, slots, at + ps)?, MAX_SIGNATURE_LEN)?;
    if !is_jni_signature(signature) {
        return None;
    }
    let raw = pointer(image, slots, at + 2 * ps)?;
    let thumb = image.machine == elf::EM_ARM && raw & 1 == 1;
    let function = if thumb { raw & !1 } else { raw };
    if function == 0 || !image.is_exec(function) {
        return None;
    }
    Some(RegisteredMethod {
        name: name.to_string(),
        signature: signature.to_string(),
        fn_offset: hex(function),
        table_offset: String::new(),
        thumb,
    })
}

/// Tables `{method, signature}` de directors SWIG, par pas de deux pointeurs ;
/// des entrées consécutives forment une même table.
fn scan_swig_tables(image: &Image, slots: &HashMap<u64, u64>) -> Vec<SwigUpcall> {
    let ps = image.ptr_size;
    let stride = 2 * ps;
    let mut found = Vec::new();
    for region in image.data_regions(false) {
        let end = region.vaddr.saturating_add(region.bytes.len() as u64);
        let mut at = region
            .vaddr
            .checked_next_multiple_of(ps)
            .unwrap_or(u64::MAX);
        let mut table = None;
        while at.saturating_add(stride) <= end {
            let Some((name, signature)) = swig_upcall_at(image, slots, at) else {
                table = None;
                at += ps;
                continue;
            };
            let table_offset = table.get_or_insert_with(|| hex(at)).clone();
            found.push(SwigUpcall {
                name,
                signature,
                table_offset,
            });
            at += stride;
        }
    }
    found
}

fn swig_upcall_at(image: &Image, slots: &HashMap<u64, u64>, at: u64) -> Option<(String, String)> {
    let name = image.cstr_at(pointer(image, slots, at)?, MAX_NAME_LEN)?;
    if !name.starts_with(SWIG_DIRECTOR_PREFIX) || !is_java_identifier(name) {
        return None;
    }
    let at = at + image.ptr_size;
    let signature = image.cstr_at(pointer(image, slots, at)?, MAX_SIGNATURE_LEN)?;
    if !is_jni_signature(signature) {
        return None;
    }
    Some((name.to_string(), signature.to_string()))
}

fn pointer(image: &Image, slots: &HashMap<u64, u64>, at: u64) -> Option<u64> {
    slots.get(&at).copied().or_else(|| image.word_at(at))
}

fn has_registernatives(image: &Image) -> bool {
    let needle: &[u8] = b"RegisterNatives";
    for region in image.data_regions(true) {
        if region.read_only && region.bytes.windows(needle.len()).any(|w| w == needle) {
            return true;
        }
    }
    false
}

fn describe_strings(image: &Image, strings: &mut Strings) {
    let mut seen = HashSet::new();
    for region in image.data_regions(true) {
        for text in text_runs(region.bytes) {
            if seen.insert(text) {
                classify_string(text, strings);
            }
        }
    }
}

fn text_runs(bytes: &[u8]) -> Vec<&str> {
    let mut out = Vec::new();
    for run in bytes.split(|&b| !is_text_byte(b)) {
        match std::str::from_utf8(run) {
            Ok(text) => out.push(text),
            Err(_) => {
                for ascii in run.split(|b| !b.is_ascii()) {
                    out.extend(std::str::from_utf8(ascii).ok());
                }
            }
        }
    }
    out.retain(|t| t.chars().count() >= MIN_STRING_CHARS);
    out
}

fn is_text_byte(b: u8) -> bool {
    b == b'\t' || (0x20..0x7f).contains(&b) || b >= 0x80
}

fn classify_string(s: &str, out: &mut Strings) {
    if s.starts_with('/') {
        out.paths.push(s);
    }
    if has_url(s) {
        out.urls.push(s);
    }
    if has_ipv4(s) {
        out.ips.push(s);
    }
    if has_shell_command(s) {
        out.shell.push(s);
    }
    if is_java_class(s) {
        out.java_classes.push(s);
    }
    if is_jni_signature(s) {
        out.jni_signatures.push(s);
    }
}

fn has_url(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut from = 0;
    while let Some(found) = s[from..].find("://") {
        let at = from + found;
        let start = bytes[..at]
            .iter()
            .rposition(|&b| !is_scheme_byte(b))
            .map_or(0, |p| p + 1);
        let scheme = &bytes[start..at];
        if scheme.len() >= 2 && scheme[0].is_ascii_alphabetic() {
            return true;
        }
        from = at + 3;
    }
    false
}

fn is_scheme_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')
}

fn has_ipv4(s: &str) -> bool {
    s.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .any(|token| token.parse::<Ipv4Addr>().is_ok())
}

fn has_shell_command(s: &str) -> bool {
    for command in SHELL_COMMANDS.split_whitespace() {
        for (at, _) in s.match_indices(command) {
            let followed = s[at + command.len()..].starts_with(' ');
            let preceded = s[..at]
                .chars()
                .next_back()
                .is_none_or(|c| SHELL_BOUNDARIES.contains(c));
            if followed && preceded {
                return true;
            }
        }
    }
    false
}

fn is_java_class(s: &str) -> bool {
    let body = s
        .strip_prefix('L')
        .and_then(|b| b.strip_suffix(';'))
        .unwrap_or(s);
    let rooted = JAVA_PACKAGE_ROOTS
        .split_whitespace()
        .any(|root| body.len() > root.len() && body.starts_with(root));
    rooted
        && !body.ends_with('/')
        && !body.contains("//")
        && body.chars().all(is_internal_name_char)
}

fn is_internal_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '/')
}

/// Catégorie d'un symbole importé, `None` s'il est hors table.
pub fn import_category(symbol: &str) -> Option<&'static str> {
    IMPORT_CATEGORIES
        .iter()
        .find(|(_, patterns)| {
            patterns
                .split_whitespace()
                .any(|p| symbol_matches(p, symbol))
        })
        .map(|&(category, _)| category)
}

fn symbol_matches(pattern: &str, symbol: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => symbol.starts_with(prefix),
        None => symbol == pattern,
    }
}

/// Entropie de Shannon, en bits par octet (0 à 8).
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[usize::from(b)] += 1;
    }
    let n = bytes.len() as f64;
    let mut entropy = 0.0;
    for &count in counts.iter().filter(|&&c| c > 0) {
        let count = count as f64;
        entropy += count / n * (n / count).log2();
    }
    entropy
}

/// Descripteur complet de méthode, selon la grammaire de [`legend`].
pub fn is_jni_signature(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'(') {
        return false;
    }
    let mut at = 1;
    while bytes.get(at) != Some(&b')') {
        match jni_type_end(bytes, at) {
            Some(end) => at = end,
            None => return false,
        }
    }
    jni_type_end(bytes, at + 1) == Some(bytes.len())
}

fn jni_type_end(bytes: &[u8], mut at: usize) -> Option<usize> {
    while bytes.get(at) == Some(&b'[') {
        at += 1;
    }
    match bytes.get(at)? {
        b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' | b'V' => Some(at + 1),
        b'L' => {
            let len = bytes.get(at + 1..)?.iter().position(|&b| b == b';')?;
            (len > 0).then_some(at + len + 2)
        }
        _ => None,
    }
}

fn is_java_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_alphabetic() || c == '_' || c == '$' => {}
        _ => return false,
    }
    chars.all(|c| c.is_alphanumeric() || c == '_' || c == '$')
}

enum Token {
    Unit(u16),
    Separator,
    SignatureStart,
}

fn jni_tokens(mangled: &[u8]) -> Option<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut at = 0;
    while let Some(&b) = mangled.get(at) {
        if b != b'_' {
            if !b.is_ascii_alphanumeric() {
                return None;
            }
            tokens.push(Token::Unit(u16::from(b)));
            at += 1;
            continue;
        }
        let (token, width) = match mangled.get(at + 1) {
            Some(b'0') => (Token::Unit(hex_unit(mangled.get(at + 2..at + 6)?)?), 6),
            Some(b'1') => (Token::Unit(u16::from(b'_')), 2),
            Some(b'2') => (Token::Unit(u16::from(b';')), 2),
            Some(b'3') => (Token::Unit(u16::from(b'[')), 2),
            Some(b'_') => (Token::SignatureStart, 2),
            Some(_) => (Token::Separator, 1),
            None => return None,
        };
        tokens.push(token);
        at += width;
    }
    Some(tokens)
}

fn hex_unit(digits: &[u8]) -> Option<u16> {
    if !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u16::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()
}

/// Démangle un export `Java_*` selon les règles JNI. `None` si le symbole ne
/// les respecte pas.
pub fn demangle_jni(symbol: &str) -> Option<StaticExport> {
    let tokens = jni_tokens(symbol.strip_prefix("Java_")?.as_bytes())?;
    let mut parts: Vec<Vec<u16>> = vec![Vec::new()];
    let mut signature: Option<Vec<u16>> = None;
    for token in tokens {
        match token {
            Token::SignatureStart if signature.is_none() => signature = Some(Vec::new()),
            Token::SignatureStart => return None,
            Token::Separator => match signature.as_mut() {
                Some(units) => units.push(u16::from(b'/')),
                None => parts.push(Vec::new()),
            },
            Token::Unit(unit) => match signature.as_mut() {
                Some(units) => units.push(unit),
                None => parts.last_mut()?.push(unit),
            },
        }
    }
    let method = parts.pop()?;
    if parts.is_empty() || method.is_empty() || parts.iter().any(Vec::is_empty) {
        return None;
    }
    let mut class = String::from("L");
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            class.push('/');
        }
        class.push_str(&String::from_utf16(part).ok()?);
    }
    class.push(';');
    let signature = match signature {
        Some(units) => Some(format!("({})", String::from_utf16(&units).ok()?)),
        None => None,
    };
    Some(StaticExport {
        symbol: symbol.to_string(),
        class,
        method: String::from_utf16(&method).ok()?,
        signature,
        address: 0,
    })
}

fn declared_natives(apk: &Path, errors: &mut Vec<String>) -> Option<Vec<NativeMethod>> {
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| read_natives(apk)));
    match outcome {
        Ok(Ok((natives, mut problems))) => {
            errors.append(&mut problems);
            Some(natives)
        }
        Ok(Err(e)) => {
            errors.push(format!("dex: {e:#} ; liaison non calculée"));
            None
        }
        Err(_) => {
            errors.push("dex: panique pendant le parsing ; liaison non calculée".to_string());
            None
        }
    }
}

fn read_natives(apk: &Path) -> Result<(Vec<NativeMethod>, Vec<String>)> {
    let tmp = tempfile::tempdir().context("création du répertoire temporaire")?;
    let files = super::extract_dex_files(apk, tmp.path())?;
    let mut problems = Vec::new();
    let mut seen = HashSet::new();
    let mut natives = Vec::new();
    for file in &files {
        let label = match file.file_name() {
            Some(name) => name.to_string_lossy().into_owned(),
            None => String::new(),
        };
        let dex = match DexBin::open(file) {
            Ok(dex) => dex,
            Err(e) => {
                problems.push(format!("{label}: DEX illisible ({e:#})"));
                continue;
            }
        };
        let mut skipped = 0usize;
        for class in dex.classes() {
            let Ok(class) = class else {
                skipped += 1;
                continue;
            };
            for method in class.methods.iter().filter(|m| m.is_native) {
                let native = NativeMethod {
                    class: class.descriptor.to_string(),
                    name: method.name.to_string(),
                    params: format!("({})", method.params.concat()),
                    ret: method.return_type.to_string(),
                };
                if seen.insert(native.java()) {
                    natives.push(native);
                }
            }
        }
        if skipped > 0 {
            problems.push(format!("{label}: {skipped} classe(s) illisible(s)"));
        }
    }
    Ok((natives, problems))
}

/// Relie les méthodes natives du DEX aux exports `Java_*` et aux tables
/// `JNINativeMethod` des ELF d'origine `lib`. Une ligne par couple (méthode,
/// ELF) lié, une ligne `declared_unbound` par méthode sans liaison, une ligne
/// `native_unclaimed` par export ou entrée de table sans méthode.
pub fn bind(natives: &[NativeMethod], elfs: &[ElfReport]) -> Vec<Binding> {
    let libs: Vec<&ElfReport> = elfs.iter().filter(|e| e.origin == ORIGIN_LIB).collect();
    let mut homonyms: HashMap<(&str, String), Vec<String>> = HashMap::new();
    for m in natives {
        homonyms
            .entry((m.name.as_str(), m.signature()))
            .or_default()
            .push(m.java());
    }

    let mut claimed_exports = HashSet::new();
    let mut claimed_entries = HashSet::new();
    let mut rows = Vec::new();
    for m in natives {
        let java = m.java();
        let signature = m.signature();
        let before = rows.len();
        for (li, lib) in libs.iter().enumerate() {
            for (xi, export) in lib.jni.static_exports.iter().enumerate() {
                if !export.binds(m) {
                    continue;
                }
                claimed_exports.insert((li, xi));
                let at = hex(export.address);
                rows.push(Binding::found(&java, STATUS_STATIC, lib, at, Vec::new()));
            }
            for (ti, entry) in lib.jni.registered.iter().enumerate() {
                if entry.name != m.name || entry.signature != signature {
                    continue;
                }
                claimed_entries.insert((li, ti));
                let peers = homonyms.get(&(m.name.as_str(), signature.clone()));
                let (status, candidates) = match peers {
                    Some(peers) if peers.len() > 1 => (STATUS_AMBIGUOUS, peers.clone()),
                    _ => (STATUS_REGISTERED, Vec::new()),
                };
                let at = entry.fn_offset.clone();
                rows.push(Binding::found(&java, status, lib, at, candidates));
            }
        }
        if rows.len() == before {
            rows.push(Binding::unbound(java));
        }
    }

    for (li, lib) in libs.iter().enumerate() {
        for (xi, export) in lib.jni.static_exports.iter().enumerate() {
            if claimed_exports.contains(&(li, xi)) {
                continue;
            }
            let args = export.signature.as_deref().unwrap_or("");
            let java = format!("{}->{}{args}", export.class, export.method);
            let at = hex(export.address);
            rows.push(Binding::found(&java, STATUS_UNCLAIMED, lib, at, Vec::new()));
        }
        for (ti, entry) in lib.jni.registered.iter().enumerate() {
            if claimed_entries.contains(&(li, ti)) {
                continue;
            }
            let java = format!("?->{}{}", entry.name, entry.signature);
            let at = entry.fn_offset.clone();
            rows.push(Binding::found(&java, STATUS_UNCLAIMED, lib, at, Vec::new()));
        }
    }
    rows
}

/// Une méthode compte une fois, sous son meilleur statut.
pub fn summarize(binding: &[Binding], declared: usize, elf_count: usize) -> Summary {
    let mut summary = Summary {
        elf_count,
        native_methods_declared: declared,
        ..Summary::default()
    };
    let mut best: HashMap<&str, &'static str> = HashMap::new();
    for row in binding {
        if row.status == STATUS_UNCLAIMED {
            summary.unclaimed += 1;
            continue;
        }
        let status = best.entry(row.java.as_str()).or_insert(row.status);
        if rank(row.status) < rank(status) {
            *status = row.status;
        }
    }
    for status in best.values() {
        match *status {
            STATUS_STATIC => summary.bound_static += 1,
            STATUS_REGISTERED => summary.bound_registered += 1,
            STATUS_AMBIGUOUS => summary.ambiguous += 1,
            _ => summary.unbound += 1,
        }
    }
    summary
}

fn rank(status: &str) -> u8 {
    match status {
        STATUS_STATIC => 0,
        STATUS_REGISTERED => 1,
        STATUS_AMBIGUOUS => 2,
        _ => 3,
    }
}

fn note(anomalies: &mut Vec<String>, code: &str, detail: impl std::fmt::Display) {
    anomalies.push(format!("{code}: {detail}"));
}

fn hex(value: u64) -> String {
    format!("{value:#x}")
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn read_uint(bytes: &[u8], big_endian: bool) -> Option<u64> {
    match (bytes.len(), big_endian) {
        (4, false) => Some(u64::from(u32::from_le_bytes(bytes.try_into().ok()?))),
        (4, true) => Some(u64::from(u32::from_be_bytes(bytes.try_into().ok()?))),
        (8, false) => Some(u64::from_le_bytes(bytes.try_into().ok()?)),
        (8, true) => Some(u64::from_be_bytes(bytes.try_into().ok()?)),
        _ => None,
    }
}

fn c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn segment_type(p_type: u32) -> String {
    let name = match p_type {
        elf::PT_LOAD => "LOAD",
        elf::PT_DYNAMIC => "DYNAMIC",
        elf::PT_INTERP => "INTERP",
        elf::PT_NOTE => "NOTE",
        elf::PT_PHDR => "PHDR",
        elf::PT_TLS => "TLS",
        elf::PT_GNU_EH_FRAME => "GNU_EH_FRAME",
        elf::PT_GNU_STACK => "GNU_STACK",
        elf::PT_GNU_RELRO => "GNU_RELRO",
        elf::PT_GNU_PROPERTY => "GNU_PROPERTY",
        other => return hex(u64::from(other)),
    };
    name.to_string()
}

fn segment_flags(flags: u32) -> String {
    let mut out = String::with_capacity(3);
    for (mask, letter) in [(elf::PF_R, 'r'), (elf::PF_W, 'w'), (elf::PF_X, 'x')] {
        out.push(if flags & mask != 0 { letter } else { '-' });
    }
    out
}

fn section_flags(section: &Section) -> String {
    let letters = [
        (elf::SHF_ALLOC, 'r'),
        (elf::SHF_WRITE, 'w'),
        (elf::SHF_EXECINSTR, 'x'),
    ];
    let mut out = String::new();
    for (mask, letter) in letters {
        if section.has(mask) {
            out.push(letter);
        }
    }
    out
}

/// SHA-256 du fichier entier, lu par blocs pour ne pas charger l'APK en mémoire.
fn file_sha256(path: &Path) -> Result<String> {
    let mut f =
        std::fs::File::open(path).with_context(|| format!("ouverture {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

const LEGEND: &str = "\
--native : analyse statique de TOUS les ELF de l'APK et liaison avec les méthodes
`native` du DEX. Ni exécution, ni émulation ; désassemblage seulement avec
--native-disasm (section DÉSASSEMBLAGE).

RAPPORT
  sha256          SHA-256 complet du fichier APK.
  errors          Ce qui n'a pas pu être lu : entrée d'archive illisible (on ignore alors
                  si c'était un ELF), DEX illisible, classes sautées, panique du parseur
                  DEX. Une méthode native manquante peut faire apparaître à tort son
                  export en native_unclaimed. Si le DEX n'a pas pu être lu du tout,
                  binding est vide et native_methods_declared vaut 0.

ELF (elfs[])
  Est un ELF toute entrée dont les 4 premiers octets décompressés valent 7F 45 4C 46,
  quel que soit son chemin ou son extension. Archive lue par le lecteur ZIP tolérant.
  path            Chemin de l'entrée dans l'APK.
  origin          lib = sous lib/ ; assets = sous assets/ ; res_raw = sous res/raw/ ;
                  other = ailleurs (racine, res/ renommé, META-INF/…).
  sha256          SHA-256 COMPLET du contenu DÉCOMPRESSÉ, jamais des octets stockés
                  (même sémantique que --extract-libs) : la forme qui se croise avec
                  VirusTotal, MalwareBazaar, Koodous. Jamais tronqué.
  size            Taille décompressée, en octets.
  machine         e_machine : arm, aarch64, x86, x86_64, mips, riscv, unknown(0x..).
  bits / endian   EI_CLASS (32 ou 64 ; 0 si illisible) / EI_DATA (little, big, unknown).
  declared_abi    Répertoire NDK de lib/<abi>/… ; null hors de lib/<abi>/.
  abi_mismatch    machine ou bits incompatibles avec declared_abi.
  elf_type        exec = ET_EXEC, dyn = ET_DYN, rel = ET_REL, other = autre valeur.
  pie             e_type = ET_DYN : chargeable à n'importe quelle base. Vrai pour toute
                  .so et pour un exécutable PIE, faux pour ET_EXEC.
  stripped        Aucune section de type SHT_SYMTAB (.symtab). Sans section headers : vrai.
  interp          Contenu de PT_INTERP (chargeur demandé par un exécutable) ; null sinon.
  sections[]      name ; size = sh_size ; flags : r = SHF_ALLOC (en mémoire, donc lisible),
                  w = SHF_WRITE, x = SHF_EXECINSTR ; entropy = entropie de Shannon du
                  contenu fichier, en bits par octet (0 à 8), 0 pour SHT_NOBITS, arrondie
                  au millième. La section nulle d'index 0 est omise.
  segments[]      type = p_type (LOAD, DYNAMIC, INTERP, NOTE, PHDR, TLS, GNU_EH_FRAME,
                  GNU_STACK, GNU_RELRO, GNU_PROPERTY ; valeur hexadécimale sinon) ;
                  flags = r, w, x de p_flags, - si absent ; vaddr = p_vaddr ; size = p_memsz.
  needed          DT_NEEDED : bibliothèques requises. ?0x.. = nom illisible à cet offset
                  de DT_STRTAB.
  soname          DT_SONAME.
  init            DT_INIT, adresse virtuelle ; null si absent.
  init_array_count
                  DT_INIT_ARRAYSZ / taille de pointeur : constructeurs exécutés au
                  chargement, avant JNI_OnLoad.
  imports         Symboles INDÉFINIS de .dynsym, rangés dans les catégories de la table
                  ci-dessous. other_count = imports hors table : comptés, non listés.
  imports.jni     Exception : JNI_OnLoad et JNI_OnUnload EXPORTÉS (définis).
  exports_count   Symboles définis de .dynsym, de liaison GLOBAL ou WEAK.
  La table dynamique est lue dans PT_DYNAMIC, comme le fait le chargeur. Les symboles
  viennent de .dynsym, trouvée par les section headers : sans eux, imports et exports
  sont vides.

JNI (elfs[].jni)
  jni_onload      JNI_OnLoad est exporté.
  registernatives_string
                  Une région de données en lecture seule contient la chaîne
                  « RegisterNatives ». Indice, pas preuve : l'appel passe par la table de
                  fonctions de JNIEnv et ne laisse aucun symbole.
  jni_registration
                  tables_found = au moins une entrée de table JNINativeMethod reconstruite
                  (registered[] non vide) ; unresolved = JNI_OnLoad exporté mais aucune table
                  reconstruite (noms ou signatures chiffrés, construits à l'exécution, ou
                  relocations d'un format non géré) ; none = ni table ni JNI_OnLoad.
  static_exports[]
                  Exports Java_* démanglés selon les règles JNI : _1 → _, _2 → ;, _3 → [,
                  _0xxxx → unité UTF-16 xxxx, _ seul → /, __ sépare le nom des arguments.
                  symbol = nom exporté ; class = forme Dalvik Lpaquet/Classe; ;
                  method = nom Java ; signature = arguments seuls « (…) », sans type de
                  retour, présente seulement pour un export surchargé (nom long) ; null
                  pour le nom court.
  registered[]    Entrées de tables JNINativeMethod {name, signature, fnPtr} reconstruites
                  dans les régions de données allouées non exécutables, par pas d'un
                  pointeur. Triplet valide : name pointe vers une chaîne C qui est un
                  identifiant Java, signature vers une chaîne C conforme à la grammaire
                  ci-dessous, fnPtr dans un segment LOAD exécutable. Des triplets valides
                  consécutifs forment une même table. Les pointeurs sont lus APRÈS
                  résolution des relocations relatives, base de chargement 0.
                  fn_offset = adresse virtuelle de la fonction ; table_offset = adresse
                  virtuelle de la table ; thumb = bit 0 de fnPtr à 1 sur ARM 32 bits
                  (code Thumb ; bit effacé dans fn_offset). Un name qui commence par
                  SwigDirector_ n'est jamais une entrée (voir swig_director_upcalls).
                  Avec --native-disasm, s'y ajoutent, avant la liaison, les entrées lues à
                  la table passée à RegisterNatives ou à jniRegisterNativeMethods
                  (registered_by_code) qui n'y figurent pas déjà (même name, signature et
                  fn_offset) ; table_offset = adresse passée en argument.
  swig_director_upcalls[]
                  Tables {method, signature} du code généré par SWIG pour ses directors
                  (swig_module_init les passe à GetStaticMethodID) : name commence par
                  SwigDirector_, signature conforme à la grammaire ci-dessous, par pas de
                  deux pointeurs dans les mêmes régions que registered[]. Ce sont des
                  méthodes Java statiques NON natives que le natif appelle (upcalls) : ni
                  liées, ni native_unclaimed. table_offset = adresse virtuelle de la
                  table. Absent si vide.

  Grammaire d'une signature JNI (descripteur complet, chaîne entière) :
    \\((\\[*([ZBCSIJFDV]|L[^;]+;))*\\)\\[*([ZBCSIJFDV]|L[^;]+;)

  Relocations résolues : types R_AARCH64_RELATIVE, R_ARM_RELATIVE, R_X86_64_RELATIVE,
  R_386_RELATIVE, R_RISCV_RELATIVE ; formats RELA (addend explicite), REL (addend lu à
  l'emplacement), RELR (DT_RELR, DT_ANDROID_RELR ; addend lu à l'emplacement). Un
  emplacement non relogé est lu tel quel dans le fichier.

STRINGS (elfs[].strings)
  Chaînes d'au moins 4 caractères des régions de données allouées non exécutables ;
  sans section exploitable, de tous les segments LOAD. Une suite d'octets non UTF-8 est
  redécoupée en segments ASCII. Dédoublonnées. Une chaîne peut tomber dans plusieurs
  catégories. total = nombre de chaînes distinctes de la catégorie ;
  items = les 50 premières, dans l'ordre du fichier.
  paths           Commence par /.
  urls            Contient schéma:// ; schéma = au moins 2 caractères, une lettre en tête,
                  puis lettres, chiffres, + - .
  ips             Contient une IPv4 littérale valide : 4 octets décimaux de 0 à 255. Un
                  numéro de version à quatre composantes y tombe aussi.
  shell           Contient « commande » suivie d'une espace, pour une commande de la table
                  ci-dessous, en début de chaîne ou juste après l'un de : / ; | & ` ( \" '
  java_classes    Nom interne Java, forme L…; acceptée, sous une racine de la table
                  ci-dessous ; caractères A-Z a-z 0-9 _ $ / ; ni // ni / final.
  jni_signatures  Chaîne entièrement conforme à la grammaire des signatures JNI.

LIAISON (binding[]) — seuls les ELF d'origine lib sont liés
  java            Méthode : Lclasse;->nom(arguments)retour. Pour native_unclaimed : classe
                  et nom de l'export Java_*, arguments seulement s'il est surchargé ; « ? »
                  pour la classe d'une entrée de table, que la table ne porte pas.
  static          Export Java_* de même classe et même nom, et mêmes arguments si l'export
                  est surchargé.
  registered      Entrée de table de même nom ET même signature complète, et une seule
                  méthode native du DEX porte ce couple.
  registered_ambiguous
                  Même cas, mais plusieurs méthodes natives du DEX portent ce couple : la
                  table ne dit pas la classe. candidates = toutes ces méthodes.
  declared_unbound
                  Méthode native du DEX sans export ni entrée de table correspondante dans
                  les ELF de lib/ (bibliothèque chargée d'ailleurs, table non reconstruite,
                  code mort).
  native_unclaimed
                  Export Java_* ou entrée de table d'un ELF de lib/ sans méthode native du
                  DEX correspondante (DEX chiffré ou chargé dynamiquement, bibliothèque
                  tierce, méthode retirée).
  elf / elf_sha256 / fn_offset
                  ELF porteur (chemin, SHA-256 complet) et adresse virtuelle de la fonction ;
                  null pour declared_unbound. Une méthode liée dans plusieurs ELF (une .so
                  par ABI) produit une ligne par ELF.
  candidates      Rempli pour registered_ambiguous seulement.
  disambiguated_by / class
                  Avec --native-disasm, sur une ligne registered_ambiguous seulement :
                  find_class = un RegisterNatives dont la classe vient d'un FindClass de
                  la même fonction enregistre cette fonction ; class = la classe retenue.
                  Le statut ne change pas. Absents sinon.

SUMMARY
  elf_count       Nombre d'ELF inventoriés, toutes origines.
  native_methods_declared
                  Méthodes ACC_NATIVE distinctes du DEX.
  bound_static, bound_registered, ambiguous, unbound
                  Une méthode compte une fois, sous son meilleur statut :
                  static > registered > registered_ambiguous > declared_unbound.
  unclaimed       Nombre de lignes native_unclaimed.

DÉSASSEMBLAGE (elfs[].disasm) — avec --native-disasm seulement, absent sinon
  Désassemblage statique, sans exécution ni émulation, des fonctions qui portent la
  frontière Java↔natif. AArch64, ARM et Thumb-2 (yaxpeax-arm), x86 et x86_64
  (iced-x86) ; ELF petit-boutiste seulement. --disasm-depth N (défaut 1) ;
  --disasm-max-insns N (défaut 4000) ; --disasm-full ajoute les instructions à la
  sortie texte, le JSON les porte toujours.
  functions[]     Une par adresse ; la première origine trouvée est gardée.
    origin        jni_static = export Java_* ; jni_registered = entrée de table
                  JNINativeMethod ; jni_onload, jni_onunload = JNI_OnLoad, JNI_OnUnload
                  exportés ; init = DT_INIT ; init_array = entrée de DT_INIT_ARRAY, lue à
                  travers les relocations relatives ; entry = e_entry d'un ELF exec ;
                  main = fonction passée à __libc_init (3e argument) ou
                  __libc_start_main (1er argument) par le point d'entrée d'un
                  exécutable, quand cet argument est connu au site d'appel (import par
                  PLT ou GOT) et tombe dans un segment LOAD exécutable ; l'argument peut
                  être lu dans un emplacement de GOT, relogé ou nommant par
                  R_*_GLOB_DAT un symbole défini ; un thunk (saut direct inconditionnel,
                  ou ldr pc sur un littéral, vers une fonction interne : `b main` du
                  crtbegin de bionic ancien) est traversé, 4 sauts au plus ; désassemblée
                  comme un point d'entrée, même avec --disasm-depth 0 ; callee =
                  fonction interne appelée directement par une fonction déjà
                  désassemblée, jusqu'à --disasm-depth niveaux (0 = points d'entrée
                  seuls).
    address       Adresse virtuelle de la fonction, bit Thumb effacé.
    disasm_status ok = tous les chemins atteints ont été parcourus, invalid_paths
                  éventuels compris ; truncated = un plafond a interrompu le parcours,
                  voir truncated_reason ; arch_unsupported = autre machine ou ELF
                  gros-boutiste, aucune instruction ; invalid_entry = adresse hors
                  segment exécutable ou première instruction indécodable.
    truncated, truncated_reason
                  Plafonds seulement : max_insns = --disasm-max-insns atteint ; panic =
                  panique pendant l'analyse de la fonction, rendue vide.
    truncated_at  {address, bytes} : pour max_insns, première instruction non lue ;
                  absent sinon.
    invalid_paths[]
                  Chemins abandonnés, l'exploration continuant avec les autres
                  successeurs : {address, bytes, reason, reached_from}. reason :
                  invalid_instruction = octets indécodables atteints par un chemin ;
                  decoder_panic = le décodeur a paniqué sur l'instruction, traitée comme
                  invalide ; outside_exec = chemin sorti des segments exécutables (bytes
                  vide). reached_from = adresse du dernier branchement qui mène à ce
                  bloc, null si c'est le chemin de l'entrée. Un code aplati (type OLLVM)
                  y laisse ses blocs morts : prédicats opaques menant à des octets
                  poubelle. Les instructions lues avant l'abandon restent listées, avec
                  leurs appels et chaînes. Pendant --native-disasm, un hook de panique
                  muet remplace celui du programme : les paniques rattrapées n'écrivent
                  rien sur stderr ; le hook d'origine est rétabli ensuite.
    instructions[]
                  address, bytes (hexadécimal), mnemonic, operands, triées par adresse.
                  mnemonic coproc = instruction coprocesseur, VFP ou Advanced SIMD (ARM,
                  Thumb-2) que yaxpeax-arm ne décode pas : seule sa longueur est connue,
                  ses écritures éventuelles dans les registres généraux ne sont pas
                  suivies. Instructions media A32 (ARMv6/v7), que yaxpeax-arm 0.5.0
                  refuse en bloc, décodées à la main et nommées : ubfx, sbfx, bfi, bfc,
                  uxtb, uxth, uxtb16, sxtb, sxth, sxtb16, leurs formes à accumulation
                  uxtab, uxtah, uxtab16, sxtab, sxtah, sxtab16, puis rev, rev16, revsh,
                  rbit, usat, ssat, pkhbt, pkhtb, sel, usad8, usada8 ; sans effet de flot,
                  Rd devient inconnu, Rd = pc termine le bloc. Les autres instructions
                  media A32 (addition parallèle, multiplications, udf) restent
                  invalid_instruction. Délimitation par descente récursive depuis
                  l'entrée : seuls les successeurs explicites sont suivis (instruction
                  suivante, cible de branche), jamais la suite d'un retour, d'un saut,
                  d'un tail-call ou d'un appel sans retour. Appel sans retour : appel
                  direct vers un import de la table IMPORTS SANS RETOUR, ou vers une
                  fonction interne déjà désassemblée dont aucun chemin ne revient (rien
                  n'est supposé d'une fonction pas encore vue). st_size borne la fonction
                  quand un symbole le donne, sinon le début d'une autre fonction connue
                  arrête le parcours.
    calls[]       Appels et tail-calls distincts. kind : internal = cible dans l'ELF,
                  symbol = symbole de .dynsym ou .symtab à cette adresse, null sinon ;
                  plt = import appelé par un stub PLT ou par un emplacement de GOT,
                  import = nom résolu par R_*_JUMP_SLOT ou R_*_GLOB_DAT de PT_DYNAMIC,
                  target null si l'appel passe par la GOT ; indirect = cible non résolue,
                  target null ; unresolved = cible directe nulle ou hors des segments LOAD
                  exécutables, target conservée, aucune fonction callee créée. Les appels
                  par la table de JNIEnv y figurent en indirect.
                  Stub PLT reconnu en évaluant ses instructions jusqu'au saut indirect :
                  AArch64 adrp / ldr / br ; ARM add ip, pc / add ip, ip / ldr pc, [ip]!
                  (forme courte à 3 mots ou longue à 4) ou movw / movt / add ip, pc ;
                  x86_64 jmp [rip+…] ; x86 jmp [ebx+…]. Sur ARM, seule une cible en mode
                  ARM peut être une entrée PLT.
    string_refs[] address = instruction qui forme l'adresse ; target = adresse de la
                  chaîne ; value = octets jusqu'au premier nul, 256 au plus ; encoding =
                  utf8, ou hex pour des octets non UTF-8 d'une section en lecture seule.
                  Adresses formées par ADRP+ADD, ADR, LDR littéral, ADD pc, LEA rip ou
                  sur base connue (GOT x86), MOV immédiat x86.
    jni_calls[]   Appels de fonctions de JNIEnv, et de JavaVM pour les wrappers C++.
                  name = fonction de JNINativeInterface, ou de JNIInvokeInterface pour
                  DestroyJavaVM, AttachCurrentThread, DetachCurrentThread, GetEnv,
                  AttachCurrentThreadAsDaemon ; index = sa position dans cette table,
                  emplacements réservés compris (sources en fin de légende).
      form        vtable = appel indirect à un décalage de la table lue au premier
                  argument ; cxx_wrapper = appel direct (plt, internal, ou emplacement
                  de GOT) d'une méthode inline de jni.h émise hors ligne, reconnue à son
                  symbole _ZN7_JNIEnv<n><Nom>E… ou _ZN7_JavaVM<n><Nom>E…. En C++ this
                  est l'env ou la JavaVM : les arguments de jni.h occupent les mêmes
                  registres que sous la forme vtable (FindClass : nom en x1 / r1 ;
                  Get*ID : nom en x2 / r2, signature en x3 / r3 ; RegisterNatives :
                  table en x2 / r2, nombre en x3 / r3) ; jnihelp = appel direct (plt,
                  internal, ou emplacement de GOT) de jniRegisterNativeMethods(env,
                  className, gMethods, numMethods) de libnativehelper JNIHelp, symbole
                  exact ou surcharge C++ _Z24jniRegisterNativeMethods… : rangé sous
                  RegisterNatives (index 215), className est une chaîne C en x1 / r1,
                  table et nombre aux mêmes registres ; le symbole tient lieu de preuve
                  de l'env.
      resolved    true = l'appel est attribué à JNIEnv avec preuve (env suivi, premier
                  argument d'une fonction JNI ou écrit par GetEnv / AttachCurrentThread,
                  ou symbole de wrapper) ET tous les arguments décodés pour cette
                  fonction sont connus ; false sinon, avec unresolved_reason.
      unresolved_reason
                  Présent si resolved = false, première cause dans cet ordre :
                  env_unproven = forme vtable sans env prouvé, qui est aussi la forme
                  d'un appel virtuel C++ ; class_unresolved = nom de classe de FindClass
                  inconnu, ou jclass de Get*ID / RegisterNatives qui ne vient pas d'un
                  FindClass suivi, ou className de jniRegisterNativeMethods inconnu ;
                  name_unresolved, signature_unresolved = chaîne de
                  Get*ID inconnue ; table_unresolved = aucune entrée JNINativeMethod lue
                  pour RegisterNatives.
      class, method, signature
                  Chaînes passées en argument dans la même fonction pour FindClass,
                  Get[Static]MethodID, Get[Static]FieldID, RegisterNatives,
                  jniRegisterNativeMethods (class en forme L…;) ; absents sinon. Valeurs
                  suivies jusqu'au site d'appel à travers adrp+add, adr, ldr littéral,
                  mov / orr registre, add #imm, movw / movt, ldr [pc, #imm] + add pc,
                  ldr / str [rn, rm] et [pc, rm] sans décalage ni réécriture (ARM, GOT
                  indexée du code PIC), et la pile (str / stur puis ldr / ldur à la même
                  adresse sp ou fp + décalage).
    syscalls[]    svc, swi, syscall, sysenter, int 0x80 ; number = valeur de x8, r7, rax
                  ou eax si elle est connue à cet endroit, null sinon.
  upcalls[]       {class, name, signature} des Get[Static]MethodID / Get[Static]FieldID
                  dont la classe vient d'un FindClass suivi.
  registered_by_code[]
                  {class, name, signature} des entrées JNINativeMethod passées à
                  RegisterNatives quand la classe vient d'un FindClass de la même fonction,
                  ou à jniRegisterNativeMethods quand className est connu (voir
                  disambiguated_by). Reversées dans jni.registered avant la liaison.
  imports_called  Imports appelés par les fonctions désassemblées, par catégorie de la
                  table des imports ; other = hors table.
  invalid_paths_count
                  Somme des invalid_paths des fonctions de l'ELF.
  Suivi de valeurs : registres oubliés à chaque cible de branche, sauf sp et les
  registres callee-saved écrits une seule fois dans la fonction ; mémoire suivie pour
  la pile et les adresses connues ; rien ne passe d'une fonction à l'autre, sauf l'env
  ou la JavaVM en premier argument d'un callee.
  Invisible : chaînes construites ou déchiffrées à l'exécution, code natif absent de
  l'APK, cibles des tables de sauts ; les instructions des blocs IT (Thumb) sont lues
  comme inconditionnelles.

ANOMALIES (elfs[].anomalies, code avant « : », détail après)
  abi_mismatch    ELF incompatible avec son répertoire lib/<abi>/.
  elf_outside_lib ELF hors de lib/ : l'installateur ne l'extrait pas, c'est le code de
                  l'application qui le charge ou l'exécute (packer, dropper).
  section_headers_absent
                  Pas de section headers. Le chargeur s'en passe, les outils non.
  section_headers_invalid
                  Table des section headers illisible (taille d'entrée, offset, e_shstrndx).
  section_headers_incoherent
                  Section qui déborde du fichier, ou .dynsym illisible.
  dynamic_unreadable
                  PT_DYNAMIC hors du fichier.
  entry_outside_exec
                  e_entry non nul hors de tout segment LOAD exécutable.
  section_wx      Section à la fois SHF_WRITE et SHF_EXECINSTR.
  segment_wx      Segment LOAD à la fois PF_W et PF_X.
  high_entropy_exec
                  Section exécutable d'entropie supérieure à 7.2 bits par octet : code
                  chiffré ou compressé possible (packing).
  relocation_unsupported
                  Relocations présentes mais non décodées : DT_ANDROID_REL / DT_ANDROID_RELA
                  ou sections SHT_ANDROID_REL / SHT_ANDROID_RELA (format packé APS2), ou
                  type RELATIVE non modélisé pour la machine. Les tables JNI qui en
                  dépendent ne sont pas reconstruites.
  relocation_unreadable
                  Table de relocations hors segment chargé ou hors du fichier.
  jni_export_malformed
                  Export Java_* que les règles de démanglage JNI ne décodent pas.
  elf_unreadable  En-tête ou program headers illisibles (raison donnée). L'ELF reste
                  inventorié (chemin, origine, sha256, taille, architecture si l'en-tête
                  la donne) ; les autres champs gardent leur valeur par défaut (false, 0,
                  vide, null).
  disasm_failed   Panique pendant --native-disasm : disasm est vide pour cet ELF.
  opaque_dead_code
                  Informative, --native-disasm : au moins 3 fonctions abandonnent un
                  chemin sur les mêmes octets (détail : octets et nombre de fonctions).
                  Un motif répété désigne des octets poubelle derrière des prédicats
                  opaques plutôt que du code, signe d'obfuscation par aplatissement.
                  Les fonctions invalid_entry ne comptent pas : leur seul chemin abandonné
                  est leur point d'entrée (racine erronée), pas un bloc mort.
";

/// Légende autonome : chaque champ, statut, catégorie et anomalie de `--native`.
pub fn legend() -> String {
    let mut out = String::from(LEGEND);
    out.push_str("\nTABLE DES IMPORTS (nom exact ; * final = préfixe)\n");
    for (category, patterns) in IMPORT_CATEGORIES {
        out.push_str(&format!("  {category:<15} {patterns}\n"));
    }
    out.push_str(&format!("  jni             {JNI_EXPORTS} (exports)\n"));
    out.push_str(&format!("\nCOMMANDES SHELL\n  {SHELL_COMMANDS}\n"));
    out.push_str(&format!("\nRACINES JAVA\n  {JAVA_PACKAGE_ROOTS}\n"));
    let source = jni_table::JNI_SOURCE;
    let jni = format!("\nTABLE JNIEnv (jni_calls[].index)\n  {source}\n");
    out.push_str(&jni);
    let vm = jni_table::JNI_INVOKE_INTERFACE[jni_table::INVOKE_RESERVED_SLOTS..].join(" ");
    let vm = format!("\nTABLE JavaVM (jni_calls[].index, form cxx_wrapper)\n  {vm}\n");
    out.push_str(&vm);
    let noreturn = disasm::NORETURN_IMPORTS.join(" ");
    let section = format!("\nIMPORTS SANS RETOUR (--native-disasm)\n  {noreturn}\n");
    out.push_str(&section);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::elf::{SHT_DYNAMIC, SHT_PROGBITS, SHT_RELA, SHT_STRTAB};

    fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
        buf[at..at + bytes.len()].copy_from_slice(bytes);
    }

    // ELF64 AArch64 minimal. Segment r-x : en-têtes, .text, .rodata, .rela.dyn.
    // Segment rw- décalé de RW_BIAS : .dynamic, .data.rel.ro (un triplet à zéro).
    const TEXT: usize = 0x100;
    const RODATA: usize = 0x110;
    const RELA: usize = 0x120;
    const DYNAMIC: usize = 0x170;
    const RELRO: usize = 0x1b0;
    const SHSTRTAB: usize = 0x1c8;
    const RW_BIAS: u64 = 0x1_0000;
    const NAMES: &[u8] = b"\0.text\0.rodata\0.rela.dyn\0.dynamic\0.data.rel.ro\0.shstrtab\0";

    // (nom, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_entsize)
    type Shdr = (&'static str, u32, u64, u64, usize, usize, u64);

    fn name_offset(name: &str) -> u32 {
        let at = NAMES
            .windows(name.len())
            .position(|w| w == name.as_bytes())
            .unwrap();
        at as u32
    }

    fn phdr(
        buf: &mut [u8],
        index: usize,
        p_type: u32,
        flags: u32,
        offset: usize,
        vaddr: u64,
        size: usize,
    ) {
        let at = 64 + index * 56;
        put(buf, at, &p_type.to_le_bytes());
        put(buf, at + 4, &flags.to_le_bytes());
        put(buf, at + 8, &(offset as u64).to_le_bytes());
        put(buf, at + 16, &vaddr.to_le_bytes());
        put(buf, at + 24, &vaddr.to_le_bytes());
        put(buf, at + 32, &(size as u64).to_le_bytes());
        put(buf, at + 40, &(size as u64).to_le_bytes());
        put(buf, at + 48, &8u64.to_le_bytes());
    }

    fn shdr(buf: &mut [u8], at: usize, section: &Shdr) {
        let &(name, sh_type, flags, addr, offset, size, entsize) = section;
        put(buf, at, &name_offset(name).to_le_bytes());
        put(buf, at + 4, &sh_type.to_le_bytes());
        put(buf, at + 8, &flags.to_le_bytes());
        put(buf, at + 16, &addr.to_le_bytes());
        put(buf, at + 24, &(offset as u64).to_le_bytes());
        put(buf, at + 32, &(size as u64).to_le_bytes());
        put(buf, at + 48, &1u64.to_le_bytes());
        put(buf, at + 56, &entsize.to_le_bytes());
    }

    /// `with_dynamic` : relocations trouvées par PT_DYNAMIC ; sinon par la seule
    /// section .rela.dyn.
    fn aarch64_fixture(with_dynamic: bool) -> Vec<u8> {
        let rw = |offset: usize| RW_BIAS + offset as u64;
        let sections: [Shdr; 6] = [
            (".text", SHT_PROGBITS, 6, TEXT as u64, TEXT, 16, 0),
            (".rodata", SHT_PROGBITS, 2, RODATA as u64, RODATA, 9, 0),
            (".rela.dyn", SHT_RELA, 2, RELA as u64, RELA, 72, 24),
            (".dynamic", SHT_DYNAMIC, 3, rw(DYNAMIC), DYNAMIC, 64, 16),
            (".data.rel.ro", SHT_PROGBITS, 3, rw(RELRO), RELRO, 24, 0),
            (".shstrtab", SHT_STRTAB, 0, 0, SHSTRTAB, NAMES.len(), 0),
        ];
        let shoff = (SHSTRTAB + NAMES.len()).next_multiple_of(8);
        let mut buf = vec![0u8; shoff + 64 * (sections.len() + 1)];

        put(&mut buf, 0, b"\x7FELF\x02\x01\x01");
        put(&mut buf, 16, &elf::ET_DYN.to_le_bytes());
        put(&mut buf, 18, &elf::EM_AARCH64.to_le_bytes());
        put(&mut buf, 20, &1u32.to_le_bytes());
        put(&mut buf, 32, &64u64.to_le_bytes());
        put(&mut buf, 40, &(shoff as u64).to_le_bytes());
        put(&mut buf, 52, &64u16.to_le_bytes());
        put(&mut buf, 54, &56u16.to_le_bytes());
        let phnum: u16 = if with_dynamic { 3 } else { 2 };
        put(&mut buf, 56, &phnum.to_le_bytes());
        put(&mut buf, 58, &64u16.to_le_bytes());
        put(&mut buf, 60, &(sections.len() as u16 + 1).to_le_bytes());
        put(&mut buf, 62, &(sections.len() as u16).to_le_bytes());

        let rx = elf::PF_R | elf::PF_X;
        let rwf = elf::PF_R | elf::PF_W;
        let dyn_at = rw(DYNAMIC);
        let rw_size = SHSTRTAB - DYNAMIC;
        phdr(&mut buf, 0, elf::PT_LOAD, rx, 0, 0, RELA + 72);
        phdr(&mut buf, 1, elf::PT_LOAD, rwf, DYNAMIC, dyn_at, rw_size);
        phdr(&mut buf, 2, elf::PT_DYNAMIC, rwf, DYNAMIC, dyn_at, 64);

        for i in 0..4 {
            put(&mut buf, TEXT + 4 * i, &0xd65f_03c0u32.to_le_bytes());
        }
        put(&mut buf, RODATA, b"foo\0(I)V\0");

        let info = u64::from(elf::R_AARCH64_RELATIVE).to_le_bytes();
        let targets = [(0usize, RODATA), (8, RODATA + 4), (16, TEXT)];
        for (i, (slot, target)) in targets.into_iter().enumerate() {
            let at = RELA + 24 * i;
            put(&mut buf, at, &rw(RELRO + slot).to_le_bytes());
            put(&mut buf, at + 8, &info);
            put(&mut buf, at + 16, &(target as u64).to_le_bytes());
        }

        let dynamic = [
            (elf::DT_RELA, RELA as u64),
            (elf::DT_RELASZ, 72),
            (elf::DT_RELAENT, 24),
            (elf::DT_NULL, 0),
        ];
        for (i, (tag, value)) in dynamic.into_iter().enumerate() {
            put(&mut buf, DYNAMIC + 16 * i, &u64::from(tag).to_le_bytes());
            put(&mut buf, DYNAMIC + 16 * i + 8, &value.to_le_bytes());
        }

        put(&mut buf, SHSTRTAB, NAMES);
        for (i, section) in sections.iter().enumerate() {
            shdr(&mut buf, shoff + 64 * (i + 1), section);
        }
        buf
    }

    fn foo_entry() -> RegisteredMethod {
        RegisteredMethod {
            name: "foo".into(),
            signature: "(I)V".into(),
            fn_offset: "0x100".into(),
            table_offset: "0x101b0".into(),
            thumb: false,
        }
    }

    #[test]
    fn table_rebuilt_through_rela_relative_from_pt_dynamic() {
        let report = analyze_elf("lib/arm64-v8a/libt.so", &aarch64_fixture(true));
        assert!(report.anomalies.is_empty(), "{:?}", report.anomalies);
        assert_eq!(report.elf_type, "dyn");
        assert!(report.pie && report.stripped);
        assert_eq!(report.segments.len(), 3);
        assert_eq!(report.jni.registered, vec![foo_entry()]);
        assert_eq!(report.jni.jni_registration, "tables_found");
        assert_eq!(report.strings.jni_signatures.items, vec!["(I)V"]);
    }

    #[test]
    fn table_rebuilt_from_rela_section_without_pt_dynamic() {
        let report = analyze_elf("lib/arm64-v8a/libt.so", &aarch64_fixture(false));
        assert!(report.anomalies.is_empty(), "{:?}", report.anomalies);
        assert_eq!(report.segments.len(), 2);
        assert_eq!(report.jni.registered, vec![foo_entry()]);
    }

    #[test]
    fn no_table_without_relocations() {
        let mut bytes = aarch64_fixture(true);
        bytes[RELA..RELA + 72].fill(0);
        let report = analyze_elf("lib/arm64-v8a/libt.so", &bytes);
        assert!(report.jni.registered.is_empty());
        assert_eq!(report.jni.jni_registration, "none");
    }

    #[test]
    fn unreadable_elf_is_reported_not_fatal() {
        let mut bytes = aarch64_fixture(true);
        put(&mut bytes, 54, &12u16.to_le_bytes());
        let report = analyze_elf("assets/x", &bytes);
        assert_eq!(report.sha256.len(), 64);
        let has = |code: &str| report.anomalies.iter().any(|a| a.starts_with(code));
        assert!(has("elf_unreadable: "));
        assert!(has("elf_outside_lib: "));
    }

    fn load(offset: u64, vaddr: u64, size: u64, flags: u32) -> Segment {
        Segment {
            p_type: elf::PT_LOAD,
            flags,
            vaddr,
            memsz: size,
            offset,
            filesz: size,
        }
    }

    #[test]
    fn thumb_bit_cleared_on_arm32_with_in_place_addends() {
        let mut data = vec![0u8; 0x60];
        put(&mut data, 0x10, b"bar\0(J)Z\0");
        for (i, word) in [0x10u32, 0x14, 0x21].into_iter().enumerate() {
            put(&mut data, 0x40 + 4 * i, &word.to_le_bytes());
        }
        let image = Image {
            data: &data,
            ptr_size: 4,
            big_endian: false,
            machine: elf::EM_ARM,
            segments: vec![
                load(0, 0, 0x40, elf::PF_R | elf::PF_X),
                load(0x40, 0x1040, 0x20, elf::PF_R | elf::PF_W),
            ],
            sections: Vec::new(),
        };
        let found = scan_jni_tables(&image, &HashMap::new());
        let expected = RegisteredMethod {
            name: "bar".into(),
            signature: "(J)Z".into(),
            fn_offset: "0x20".into(),
            table_offset: "0x1040".into(),
            thumb: true,
        };
        assert_eq!(found, vec![expected]);
    }

    /// Table SWIG {method, signature} dont les chaînes partagent le segment
    /// exécutable : lue par pas de trois, elle passerait pour une table JNI.
    #[test]
    fn swig_director_tables_are_not_jni_entries() {
        let mut data = vec![0u8; 0x70];
        put(&mut data, 0x00, b"SwigDirector_A_run\0");
        put(&mut data, 0x14, b"(LA;)V\0");
        put(&mut data, 0x20, b"SwigDirector_A_get\0");
        put(&mut data, 0x34, b"(LA;)I\0");
        for (i, word) in [0x00u32, 0x14, 0x20, 0x34].into_iter().enumerate() {
            put(&mut data, 0x60 + 4 * i, &word.to_le_bytes());
        }
        let image = Image {
            data: &data,
            ptr_size: 4,
            big_endian: false,
            machine: elf::EM_ARM,
            segments: vec![
                load(0, 0, 0x60, elf::PF_R | elf::PF_X),
                load(0x60, 0x1060, 0x10, elf::PF_R | elf::PF_W),
            ],
            sections: Vec::new(),
        };
        assert!(scan_jni_tables(&image, &HashMap::new()).is_empty());
        let upcall = |name: &str, signature: &str| SwigUpcall {
            name: name.into(),
            signature: signature.into(),
            table_offset: "0x1060".into(),
        };
        let expected = vec![
            upcall("SwigDirector_A_run", "(LA;)V"),
            upcall("SwigDirector_A_get", "(LA;)I"),
        ];
        assert_eq!(scan_swig_tables(&image, &HashMap::new()), expected);
    }

    #[test]
    fn relr_bitmap_relocates_the_marked_slots() {
        let data = vec![0u8; 0x40];
        let image = Image {
            data: &data,
            ptr_size: 8,
            big_endian: false,
            machine: elf::EM_AARCH64,
            segments: vec![load(0, 0x1000, 0x40, elf::PF_R | elf::PF_W)],
            sections: Vec::new(),
        };
        let mut slots = HashMap::new();
        apply_relr(&image, &[0x1000, 0b1011], &mut slots);
        let mut keys: Vec<u64> = slots.keys().copied().collect();
        keys.sort_unstable();
        assert_eq!(keys, vec![0x1000, 0x1008, 0x1018]);
    }

    type Demangled = (String, String, Option<String>);

    fn demangled(symbol: &str) -> Option<Demangled> {
        demangle_jni(symbol).map(|e| (e.class, e.method, e.signature))
    }

    fn expect(class: &str, method: &str, signature: Option<&str>) -> Option<Demangled> {
        Some((class.into(), method.into(), signature.map(String::from)))
    }

    #[test]
    fn demangle_short_names() {
        assert_eq!(
            demangled("Java_com_foo_Bar_baz"),
            expect("Lcom/foo/Bar;", "baz", None)
        );
        assert_eq!(demangled("Java_Foo_bar"), expect("LFoo;", "bar", None));
    }

    #[test]
    fn demangle_escapes() {
        assert_eq!(
            demangled("Java_com_my_1app_Main_do_1it"),
            expect("Lcom/my_app/Main;", "do_it", None)
        );
        assert_eq!(
            demangled("Java_com_foo_Bar_caf_000e9"),
            expect("Lcom/foo/Bar;", "café", None)
        );
        assert_eq!(
            demangled("Java_com_foo_Bar_baz__Ljava_lang_String_2_3I"),
            expect("Lcom/foo/Bar;", "baz", Some("(Ljava/lang/String;[I)"))
        );
    }

    #[test]
    fn demangle_overloads() {
        assert_eq!(
            demangled("Java_com_foo_Bar_baz__I"),
            expect("Lcom/foo/Bar;", "baz", Some("(I)"))
        );
        assert_eq!(
            demangled("Java_com_foo_Bar_baz__"),
            expect("Lcom/foo/Bar;", "baz", Some("()"))
        );
    }

    #[test]
    fn demangle_rejects_malformed() {
        for symbol in [
            "Java_Foo",
            "Java_com_foo_Bar_baz_",
            "Java_a_B_x_0zzzz",
            "Java_a_B_x_0+abc",
            "Java_a_B_x__I__J",
            "Java_a__b",
            "NotJava_a_B",
        ] {
            assert_eq!(demangled(symbol), None, "{symbol}");
        }
    }

    #[test]
    fn jni_signature_grammar() {
        for valid in [
            "()V",
            "(I)V",
            "(V)V",
            "(Ljava/lang/String;[I)Z",
            "([[Ljava/lang/Object;J)[B",
        ] {
            assert!(is_jni_signature(valid), "{valid}");
        }
        for invalid in [
            "",
            "I",
            "(I)",
            "(I",
            "(I)VV",
            "()[",
            "(L;)V",
            "(Ljava/lang/String)V",
            "(Q)V",
            "foo(I)V",
        ] {
            assert!(!is_jni_signature(invalid), "{invalid}");
        }
    }

    #[test]
    fn entropy_bounds() {
        assert!(shannon_entropy(&[0x41; 4096]).abs() < 1e-12);
        let all: Vec<u8> = (0..=255).collect();
        assert!((shannon_entropy(&all) - 8.0).abs() < 1e-12);
        assert!(shannon_entropy(&[]).abs() < 1e-12);
    }

    #[test]
    fn imports_fall_in_fixed_categories() {
        assert_eq!(import_category("execlp"), Some("process"));
        assert_eq!(import_category("process_vm_writev"), Some("injection"));
        assert_eq!(import_category("android_dlopen_ext"), Some("dynload"));
        assert_eq!(import_category("mprotect"), Some("memory"));
        assert_eq!(import_category("sendto"), Some("network"));
        assert_eq!(import_category("EVP_EncryptInit_ex"), Some("crypto"));
        assert_eq!(import_category("inotify_add_watch"), Some("anti_analysis"));
        assert_eq!(import_category("openat"), Some("file"));
        assert_eq!(import_category("opendir"), None);
        assert_eq!(import_category("malloc"), None);

        let mut imports = Imports::default();
        for symbol in ["system", "socket", "malloc", "free"] {
            imports.add(symbol);
        }
        assert_eq!(imports.process, vec!["system"]);
        assert_eq!(imports.network, vec!["socket"]);
        assert_eq!(imports.other_count, 2);
    }

    #[test]
    fn strings_are_classified() {
        let mut s = Strings::default();
        for text in [
            "/system/bin/sh",
            "su -c id",
            "http://c2.example/gate",
            "connect 10.0.0.1:443",
            "999.1.1.1",
            "Lcom/foo/Bar;",
            "org/bar/Baz$Inner",
            "(Ljava/lang/String;)V",
            "I am here",
            "%s://%s",
        ] {
            classify_string(text, &mut s);
        }
        assert_eq!(s.paths.items, vec!["/system/bin/sh"]);
        assert_eq!(s.shell.items, vec!["su -c id"]);
        assert_eq!(s.urls.items, vec!["http://c2.example/gate"]);
        assert_eq!(s.ips.items, vec!["connect 10.0.0.1:443"]);
        assert_eq!(
            s.java_classes.items,
            vec!["Lcom/foo/Bar;", "org/bar/Baz$Inner"]
        );
        assert_eq!(s.jni_signatures.items, vec!["(Ljava/lang/String;)V"]);
    }

    #[test]
    fn string_buckets_are_capped_but_counted() {
        let mut bucket = StringBucket::default();
        for i in 0..STRINGS_CAP + 7 {
            bucket.push(&format!("/data/{i}"));
        }
        assert_eq!(bucket.total, STRINGS_CAP + 7);
        assert_eq!(bucket.items.len(), STRINGS_CAP);
    }

    fn native(class: &str, name: &str, params: &str, ret: &str) -> NativeMethod {
        NativeMethod {
            class: class.into(),
            name: name.into(),
            params: params.into(),
            ret: ret.into(),
        }
    }

    fn export(symbol: &str, address: u64) -> StaticExport {
        StaticExport {
            address,
            ..demangle_jni(symbol).unwrap()
        }
    }

    fn entry(name: &str, signature: &str, fn_offset: &str) -> RegisteredMethod {
        RegisteredMethod {
            name: name.into(),
            signature: signature.into(),
            fn_offset: fn_offset.into(),
            table_offset: "0x9000".into(),
            thumb: false,
        }
    }

    fn statuses(rows: &[Binding], java: &str) -> Vec<&'static str> {
        rows.iter()
            .filter(|r| r.java == java)
            .map(|r| r.status)
            .collect()
    }

    #[test]
    fn binding_statuses() {
        let natives = vec![
            native("Lcom/foo/Bar;", "stat", "(I)", "V"),
            native("Lcom/foo/Bar;", "reg", "(Ljava/lang/String;)", "Z"),
            native("Lcom/foo/A;", "dup", "()", "V"),
            native("Lcom/foo/B;", "dup", "()", "V"),
            native("Lcom/foo/Bar;", "none", "()", "V"),
            native("Lcom/foo/Bar;", "ov", "(I)", "V"),
        ];
        let mut lib = ElfReport::new("lib/arm64-v8a/libx.so", &[]);
        lib.jni.static_exports = vec![
            export("Java_com_foo_Bar_stat", 0x1000),
            export("Java_com_foo_Bar_ov__I", 0x1100),
            export("Java_com_foo_Bar_ov__J", 0x1200),
            export("Java_com_foo_Gone_x", 0x1300),
        ];
        lib.jni.registered = vec![
            entry("reg", "(Ljava/lang/String;)Z", "0x2000"),
            entry("dup", "()V", "0x2100"),
            entry("orphan", "(J)J", "0x2200"),
        ];
        let mut packed = ElfReport::new("assets/libpack.so", &[]);
        packed.jni.static_exports = vec![export("Java_com_foo_Bar_none", 0x3000)];

        let rows = bind(&natives, &[lib, packed]);

        assert_eq!(
            statuses(&rows, "Lcom/foo/Bar;->stat(I)V"),
            vec![STATUS_STATIC]
        );
        assert_eq!(
            statuses(&rows, "Lcom/foo/Bar;->ov(I)V"),
            vec![STATUS_STATIC]
        );
        assert_eq!(
            statuses(&rows, "Lcom/foo/Bar;->reg(Ljava/lang/String;)Z"),
            vec![STATUS_REGISTERED]
        );
        assert_eq!(
            statuses(&rows, "Lcom/foo/Bar;->none()V"),
            vec![STATUS_UNBOUND]
        );
        for java in ["Lcom/foo/A;->dup()V", "Lcom/foo/B;->dup()V"] {
            let row = rows.iter().find(|r| r.java == java).unwrap();
            assert_eq!(row.status, STATUS_AMBIGUOUS);
            assert_eq!(
                row.candidates,
                vec!["Lcom/foo/A;->dup()V", "Lcom/foo/B;->dup()V"]
            );
            assert_eq!(row.fn_offset.as_deref(), Some("0x2100"));
        }
        for java in ["Lcom/foo/Bar;->ov(J)", "Lcom/foo/Gone;->x", "?->orphan(J)J"] {
            assert_eq!(statuses(&rows, java), vec![STATUS_UNCLAIMED], "{java}");
        }

        let stat = rows
            .iter()
            .find(|r| r.java == "Lcom/foo/Bar;->stat(I)V")
            .unwrap();
        assert_eq!(stat.elf.as_deref(), Some("lib/arm64-v8a/libx.so"));
        assert_eq!(stat.elf_sha256.as_ref().map(String::len), Some(64));
        assert_eq!(stat.fn_offset.as_deref(), Some("0x1000"));
        assert!(rows
            .iter()
            .all(|r| r.elf.as_deref() != Some("assets/libpack.so")));

        assert_eq!(
            summarize(&rows, natives.len(), 2),
            Summary {
                elf_count: 2,
                native_methods_declared: 6,
                bound_static: 2,
                bound_registered: 1,
                ambiguous: 2,
                unbound: 1,
                unclaimed: 3,
            }
        );
    }

    #[test]
    fn legend_defines_every_label() {
        let legend = legend();
        let labels = [
            STATUS_STATIC,
            STATUS_REGISTERED,
            STATUS_AMBIGUOUS,
            STATUS_UNBOUND,
            STATUS_UNCLAIMED,
            "tables_found",
            "unresolved",
            "res_raw",
            "abi_mismatch",
            "elf_outside_lib",
            "section_headers_absent",
            "section_headers_invalid",
            "section_headers_incoherent",
            "dynamic_unreadable",
            "entry_outside_exec",
            "section_wx",
            "segment_wx",
            "high_entropy_exec",
            "relocation_unsupported",
            "relocation_unreadable",
            "jni_export_malformed",
            "elf_unreadable",
            "form",
            "unresolved_reason",
            "TABLE JavaVM",
            "swig_director_upcalls",
            SWIG_DIRECTOR_PREFIX,
        ];
        for label in labels {
            assert!(legend.contains(label), "{label}");
        }
        for (category, _) in IMPORT_CATEGORIES {
            assert!(legend.contains(category), "{category}");
        }
        for (category, _) in Strings::default().categories() {
            assert!(legend.contains(category), "{category}");
        }
        assert!(legend.contains(&format!("supérieure à {PACKING_ENTROPY} bits")));
        assert!(legend.contains(&format!("les {STRINGS_CAP} premières")));
    }
}
