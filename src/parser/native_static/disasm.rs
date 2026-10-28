//! `--native --native-disasm` : désassemblage statique, dans chaque ELF, des
//! fonctions qui portent la frontière Java↔natif. Rien n'est exécuté ni émulé.
//! Chaque fonction est délimitée par descente récursive, puis relue une fois
//! dans l'ordre des adresses par un évaluateur de valeurs qui suit JNIEnv,
//! JavaVM, les adresses calculées et la pile. Étiquettes définies dans
//! [`super::legend`].

use std::cell::RefCell;
use std::collections::BTreeMap;

use super::*;

use super::decode::{
    decode, hex_bytes, undecoded_len, Addr, Arch, Expr, Failure, Flow, Insn, Op, Via,
};
use super::jni_table as jni;

pub const DEFAULT_DISASM_DEPTH: u8 = 1;
pub const DEFAULT_DISASM_MAX_INSNS: usize = 4000;

const ORIGIN_JNI_STATIC: &str = "jni_static";
const ORIGIN_JNI_REGISTERED: &str = "jni_registered";
const ORIGIN_JNI_ONLOAD: &str = "jni_onload";
const ORIGIN_JNI_ONUNLOAD: &str = "jni_onunload";
const ORIGIN_INIT: &str = "init";
const ORIGIN_INIT_ARRAY: &str = "init_array";
const ORIGIN_ENTRY: &str = "entry";
const ORIGIN_CALLEE: &str = "callee";
const ORIGIN_MAIN: &str = "main";

const STATUS_OK: &str = "ok";
const STATUS_TRUNCATED: &str = "truncated";
const STATUS_ARCH_UNSUPPORTED: &str = "arch_unsupported";
const STATUS_INVALID_ENTRY: &str = "invalid_entry";

const REASON_MAX_INSNS: &str = "max_insns";
const REASON_INVALID_INSTRUCTION: &str = "invalid_instruction";
const REASON_OUTSIDE_EXEC: &str = "outside_exec";
const REASON_PANIC: &str = "panic";
const REASON_DECODER_PANIC: &str = "decoder_panic";

const CALL_INTERNAL: &str = "internal";
const CALL_PLT: &str = "plt";
const CALL_INDIRECT: &str = "indirect";
const CALL_UNRESOLVED: &str = "unresolved";

const FORM_VTABLE: &str = "vtable";
const FORM_CXX_WRAPPER: &str = "cxx_wrapper";

const UNRESOLVED_ENV: &str = "env_unproven";
const UNRESOLVED_CLASS: &str = "class_unresolved";
const UNRESOLVED_NAME: &str = "name_unresolved";
const UNRESOLVED_SIGNATURE: &str = "signature_unresolved";
const UNRESOLVED_TABLE: &str = "table_unresolved";

pub(super) const DISAMBIGUATED_BY_FIND_CLASS: &str = "find_class";

const MAX_STRING_BYTES: usize = 256;
const MAX_REGISTER_ENTRIES: u64 = 512;
const MAX_INIT_ARRAY: u64 = 4096;
const PLT_STUB_INSNS: usize = 6;
const OPAQUE_DEAD_CODE_MIN: usize = 3;

/// Imports qui ne rendent jamais la main : un appel direct vers l'un d'eux
/// termine le chemin. `_ZSt9terminatev` = `std::terminate()`.
pub(super) const NORETURN_IMPORTS: &[&str] = &[
    "__stack_chk_fail",
    "abort",
    "exit",
    "_exit",
    "_Exit",
    "__assert2",
    "__assert_fail",
    "__fortify_fail",
    "__cxa_throw",
    "__cxa_rethrow",
    "_Unwind_Resume",
    "pthread_exit",
    "longjmp",
    "siglongjmp",
    "__libc_fatal",
    "__android_log_assert",
    "_ZSt9terminatev",
    "__libc_init",
    "__libc_start_main",
];

/// Réglages de `--native-disasm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisasmOptions {
    /// 0 = points d'entrée seuls ; n = fonctions internes appelées directement,
    /// jusqu'à n niveaux.
    pub depth: u8,
    /// Plafond d'instructions par fonction.
    pub max_insns: usize,
}

impl Default for DisasmOptions {
    fn default() -> Self {
        DisasmOptions {
            depth: DEFAULT_DISASM_DEPTH,
            max_insns: DEFAULT_DISASM_MAX_INSNS,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ElfDisasm {
    pub functions: Vec<DisasmFunction>,
    pub upcalls: Vec<JavaMember>,
    pub registered_by_code: Vec<JavaMember>,
    pub imports_called: BTreeMap<&'static str, Vec<String>>,
    pub invalid_paths_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisasmFunction {
    pub origin: &'static str,
    pub address: String,
    pub disasm_status: &'static str,
    pub truncated: bool,
    pub truncated_reason: Option<&'static str>,
    /// Première instruction non lue quand un plafond a interrompu le parcours.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated_at: Option<TruncatedAt>,
    pub invalid_paths: Vec<InvalidPath>,
    pub instructions: Vec<DisasmInsn>,
    pub calls: Vec<DisasmCall>,
    pub string_refs: Vec<StringRef>,
    pub jni_calls: Vec<JniCall>,
    pub syscalls: Vec<Syscall>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TruncatedAt {
    pub address: String,
    pub bytes: String,
}

/// Chemin abandonné sur une instruction que le décodeur refuse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InvalidPath {
    pub address: String,
    pub bytes: String,
    pub reason: &'static str,
    pub reached_from: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisasmInsn {
    pub address: String,
    pub bytes: String,
    pub mnemonic: String,
    pub operands: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DisasmCall {
    pub target: Option<String>,
    pub import: Option<String>,
    pub symbol: Option<String>,
    pub kind: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StringRef {
    pub address: String,
    pub target: String,
    pub value: String,
    pub encoding: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JniCall {
    pub name: &'static str,
    pub index: usize,
    pub form: &'static str,
    pub resolved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unresolved_reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl JniCall {
    fn new(name: &'static str, index: usize, form: &'static str) -> Self {
        JniCall {
            name,
            index,
            form,
            resolved: false,
            unresolved_reason: None,
            class: None,
            method: None,
            signature: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Syscall {
    pub address: String,
    pub number: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct JavaMember {
    pub class: String,
    pub name: String,
    pub signature: String,
    /// Fonction d'une entrée passée à RegisterNatives, bit Thumb effacé.
    #[serde(skip)]
    pub fn_address: Option<u64>,
}

impl DisasmFunction {
    fn new(entry: &Entry) -> Self {
        DisasmFunction {
            origin: entry.origin,
            address: hex(entry.address),
            disasm_status: STATUS_OK,
            truncated: false,
            truncated_reason: None,
            truncated_at: None,
            invalid_paths: Vec::new(),
            instructions: Vec::new(),
            calls: Vec::new(),
            string_refs: Vec::new(),
            jni_calls: Vec::new(),
            syscalls: Vec::new(),
        }
    }
}

/// Le temps de `job`, les paniques (rattrapées plus bas, instruction par
/// instruction) n'écrivent rien sur stderr ; le hook précédent est rétabli.
pub(super) fn silence_panics(job: impl FnOnce()) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(job));
    std::panic::set_hook(previous);
    if let Err(payload) = outcome {
        std::panic::resume_unwind(payload);
    }
}

/// Désassemble `bytes`, l'ELF décrit par `report`, et range le résultat dans
/// `report.disasm`. Une panique devient une anomalie, jamais un échec du mode.
pub(super) fn run(bytes: &[u8], report: &mut ElfReport, options: &DisasmOptions) {
    let job = AssertUnwindSafe(|| disassemble(bytes, report, options));
    match std::panic::catch_unwind(job) {
        Ok(disasm) => {
            if let Some(anomaly) = opaque_dead_code(&disasm.functions) {
                report.anomalies.push(anomaly);
            }
            report.disasm = Some(disasm);
        }
        Err(_) => {
            let anomaly = "disasm_failed: panique pendant le désassemblage".to_string();
            report.anomalies.push(anomaly);
            report.disasm = Some(ElfDisasm::default());
        }
    }
}

/// Pose `disambiguated_by` et `class` sur les lignes registered_ambiguous dont
/// la fonction est passée à RegisterNatives avec une classe venue de FindClass.
pub(super) fn disambiguate(elfs: &[ElfReport], binding: &mut [Binding]) {
    for elf in elfs {
        let Some(disasm) = &elf.disasm else {
            continue;
        };
        for member in &disasm.registered_by_code {
            let Some(address) = member.fn_address else {
                continue;
            };
            let java = format!("{}->{}{}", member.class, member.name, member.signature);
            let at = hex(address);
            for row in binding.iter_mut() {
                let same_elf = row.elf.as_deref() == Some(elf.path.as_str());
                let same_fn = row.fn_offset.as_deref() == Some(at.as_str());
                let ambiguous = row.status == STATUS_AMBIGUOUS;
                if ambiguous && same_elf && same_fn && row.candidates.contains(&java) {
                    row.disambiguated_by = Some(DISAMBIGUATED_BY_FIND_CLASS);
                    row.class = Some(member.class.clone());
                }
            }
        }
    }
}

fn disassemble(bytes: &[u8], report: &ElfReport, options: &DisasmOptions) -> ElfDisasm {
    let Ok(parsed) = parse_elf(bytes) else {
        return ElfDisasm::default();
    };
    let mut scratch = Vec::new();
    let tables = match &parsed.dynamic {
        Some(entries) => dynamic_relocs(&parsed.image, entries, &mut scratch),
        None => section_relocs(&parsed.image, &mut scratch),
    };
    let slots = relocated_slots(&parsed.image, &tables, &mut scratch);
    let mut ctx = Ctx::new(parsed.image);
    ctx.slots = slots;
    if let Some(dynamic) = &parsed.dynamic {
        ctx.got = got_imports(&ctx.image, dynamic);
        ctx.plt_got = dyn_tag(dynamic, elf::DT_PLTGOT);
    }
    let arm = ctx.image.machine == elf::EM_ARM;
    let mut thumb_at = HashSet::new();
    for sym in parsed.symbols.iter().chain(&parsed.local_symbols) {
        if !sym.defined || !sym.func || sym.value == 0 {
            continue;
        }
        let (address, thumb) = split_thumb(arm, sym.value);
        if thumb {
            thumb_at.insert(address);
        }
        ctx.starts.insert(address);
        let slot = ctx.symbols.entry(address);
        slot.or_insert_with(|| (sym.name.clone(), sym.size));
    }

    let mut entries = Vec::new();
    for export in &report.jni.static_exports {
        let thumb = thumb_at.contains(&export.address);
        entries.push(entry(export.address, thumb, ORIGIN_JNI_STATIC, Val::Env));
    }
    for method in &report.jni.registered {
        if let Some(address) = parse_hex(&method.fn_offset) {
            let origin = ORIGIN_JNI_REGISTERED;
            entries.push(entry(address, method.thumb, origin, Val::Env));
        }
    }
    for sym in &parsed.symbols {
        let origin = match sym.name.as_str() {
            "JNI_OnLoad" => ORIGIN_JNI_ONLOAD,
            "JNI_OnUnload" => ORIGIN_JNI_ONUNLOAD,
            _ => continue,
        };
        if sym.defined {
            let (address, thumb) = split_thumb(arm, sym.value);
            entries.push(entry(address, thumb, origin, Val::Vm));
        }
    }
    if let Some(dynamic) = &parsed.dynamic {
        if let Some(init) = dyn_tag(dynamic, elf::DT_INIT) {
            let (address, thumb) = split_thumb(arm, init);
            entries.push(entry(address, thumb, ORIGIN_INIT, Val::Opaque(0)));
        }
        for value in init_array(&ctx, dynamic) {
            let (address, thumb) = split_thumb(arm, value);
            entries.push(entry(address, thumb, ORIGIN_INIT_ARRAY, Val::Opaque(0)));
        }
    }
    if parsed.e_type == elf::ET_EXEC && parsed.entry != 0 {
        let (address, thumb) = split_thumb(arm, parsed.entry);
        entries.push(entry(address, thumb, ORIGIN_ENTRY, Val::Opaque(0)));
    }
    walk_functions(&ctx, entries, options)
}

fn init_array(ctx: &Ctx, dynamic: &[(u64, u64)]) -> Vec<u64> {
    let mut values = Vec::new();
    let array = dyn_tag(dynamic, elf::DT_INIT_ARRAY);
    let size = dyn_tag(dynamic, elf::DT_INIT_ARRAYSZ);
    let (Some(array), Some(size)) = (array, size) else {
        return values;
    };
    let ptr = ctx.image.ptr_size;
    for index in 0..(size / ptr).min(MAX_INIT_ARRAY) {
        let at = array.wrapping_add(index * ptr);
        let Some(value) = pointer(&ctx.image, &ctx.slots, at) else {
            continue;
        };
        if value != 0 && value != ptr_mask(ptr) {
            values.push(value);
        }
    }
    values
}

fn ptr_mask(ptr: u64) -> u64 {
    if ptr == 4 {
        0xffff_ffff
    } else {
        u64::MAX
    }
}

fn split_thumb(arm: bool, value: u64) -> (u64, bool) {
    if arm {
        (value & !1, value & 1 == 1)
    } else {
        (value, false)
    }
}

fn parse_hex(text: &str) -> Option<u64> {
    u64::from_str_radix(text.strip_prefix("0x")?, 16).ok()
}

fn entry(address: u64, thumb: bool, origin: &'static str, arg0: Val) -> Entry {
    Entry {
        address,
        thumb,
        origin,
        arg0,
    }
}

/// Emplacement de GOT → nom de l'import, par les relocations R_*_JUMP_SLOT et
/// R_*_GLOB_DAT de PT_DYNAMIC (DT_JMPREL, DT_RELA, DT_REL).
fn got_imports(image: &Image, dynamic: &[(u64, u64)]) -> HashMap<u64, String> {
    let mut got = HashMap::new();
    let symtab = dyn_tag(dynamic, elf::DT_SYMTAB);
    let strtab = dyn_tag(dynamic, elf::DT_STRTAB);
    let (Some(symtab), Some(strtab)) = (symtab, strtab) else {
        return got;
    };
    let ptr = image.ptr_size;
    let default_syment = if ptr == 8 { 24 } else { 16 };
    let syment = match dyn_tag(dynamic, elf::DT_SYMENT) {
        Some(size) if size > 0 => size,
        _ => default_syment,
    };
    let syms = DynSyms {
        symtab,
        strtab,
        syment,
    };
    let plt_rela = match dyn_tag(dynamic, elf::DT_PLTREL) {
        Some(kind) => kind == u64::from(elf::DT_RELA),
        None => ptr == 8,
    };
    let tables = [
        (elf::DT_JMPREL, elf::DT_PLTRELSZ, plt_rela),
        (elf::DT_RELA, elf::DT_RELASZ, true),
        (elf::DT_REL, elf::DT_RELSZ, false),
    ];
    for (address_tag, size_tag, rela) in tables {
        let address = dyn_tag(dynamic, address_tag);
        let size = dyn_tag(dynamic, size_tag);
        let (Some(address), Some(size)) = (address, size) else {
            continue;
        };
        let Some(offset) = image.offset_of(address) else {
            continue;
        };
        let Some(bytes) = image.bytes_at(offset, size) else {
            continue;
        };
        let words = if rela { 3 } else { 2 };
        let Ok(entsize) = usize::try_from(words * ptr) else {
            continue;
        };
        for record in bytes.chunks_exact(entsize) {
            if let Some((slot, name)) = import_slot(image, &syms, record) {
                got.insert(slot, name);
            }
        }
    }
    got
}

fn import_slot(image: &Image, syms: &DynSyms, entry: &[u8]) -> Option<(u64, String)> {
    let ptr = usize::try_from(image.ptr_size).ok()?;
    let slot = read_uint(entry.get(..ptr)?, image.big_endian)?;
    let info = read_uint(entry.get(ptr..2 * ptr)?, image.big_endian)?;
    if !import_reloc(image.machine, reloc_type(info, image.ptr_size)) {
        return None;
    }
    let index = if ptr == 8 { info >> 32 } else { info >> 8 };
    if index == 0 {
        return None;
    }
    Some((slot, syms.name(image, index)?))
}

fn import_reloc(machine: u16, kind: u32) -> bool {
    match machine {
        elf::EM_AARCH64 => matches!(kind, elf::R_AARCH64_JUMP_SLOT | elf::R_AARCH64_GLOB_DAT),
        elf::EM_ARM => matches!(kind, elf::R_ARM_JUMP_SLOT | elf::R_ARM_GLOB_DAT),
        elf::EM_X86_64 => matches!(kind, elf::R_X86_64_JUMP_SLOT | elf::R_X86_64_GLOB_DAT),
        elf::EM_386 => matches!(kind, elf::R_386_JMP_SLOT | elf::R_386_GLOB_DAT),
        _ => false,
    }
}

/// Table des symboles dynamiques telle que la voit le chargeur.
struct DynSyms {
    symtab: u64,
    strtab: u64,
    syment: u64,
}

impl DynSyms {
    fn name(&self, image: &Image, index: u64) -> Option<String> {
        let at = self.symtab.checked_add(index.checked_mul(self.syment)?)?;
        let bytes = image.bytes_at(image.offset_of(at)?, 4)?;
        let name = read_uint(bytes, image.big_endian)?;
        let text = image.cstr_at(self.strtab.checked_add(name)?, MAX_DYNSTR_LEN)?;
        Some(text.to_string())
    }
}

impl Image<'_> {
    /// Octets à partir de `at`, au plus 16, pris dans un segment LOAD exécutable.
    fn code_window(&self, at: u64) -> Option<&[u8]> {
        for s in &self.segments {
            if s.p_type != elf::PT_LOAD || !s.has(elf::PF_X) || !s.in_file(at) {
                continue;
            }
            let start = s.offset.checked_add(at - s.vaddr)?;
            let end = s.offset.checked_add(s.filesz)?;
            let start = usize::try_from(start).ok()?;
            let end = usize::try_from(end).ok()?.min(start.saturating_add(16));
            let end = end.min(self.data.len());
            return self.data.get(start..end);
        }
        None
    }

    /// Octets d'une chaîne C, sans le nul final, 256 au plus.
    fn c_string_bytes(&self, at: u64) -> Option<&[u8]> {
        let start = usize::try_from(self.offset_of(at)?).ok()?;
        let tail = self.data.get(start..)?;
        let window = &tail[..tail.len().min(MAX_STRING_BYTES)];
        let end = window.iter().position(|&b| b == 0);
        let end = end.unwrap_or(window.len());
        if end == 0 {
            return None;
        }
        Some(&window[..end])
    }

    /// `Some(hex_allowed)` si `at` tombe dans des données : section allouée non
    /// exécutable (hexadécimal admis si elle est en lecture seule) ou, sans
    /// section, segment LOAD (texte UTF-8 seulement).
    fn data_kind(&self, at: u64) -> Option<bool> {
        if self.sections.is_empty() {
            for s in &self.segments {
                if s.p_type == elf::PT_LOAD && s.in_file(at) {
                    return Some(false);
                }
            }
            return None;
        }
        for s in &self.sections {
            let data = s.has(elf::SHF_ALLOC) && !s.has(elf::SHF_EXECINSTR) && s.has_file_data();
            if data && at >= s.addr && at - s.addr < s.size {
                return Some(!s.has(elf::SHF_WRITE));
            }
        }
        None
    }
}

fn printable(text: &str) -> bool {
    let allowed = |c: char| !c.is_control() || matches!(c, '\t' | '\n' | '\r');
    text.chars().all(allowed)
}

fn utf8_at(ctx: &Ctx, at: u64) -> Option<String> {
    let text = ctx.image.cstr_at(at, MAX_STRING_BYTES)?;
    if printable(text) {
        Some(text.to_string())
    } else {
        None
    }
}

/// `com/foo/Bar` → `Lcom/foo/Bar;` ; un descripteur déjà complet est gardé.
fn class_descriptor(name: &str) -> String {
    if name.starts_with('[') || (name.starts_with('L') && name.ends_with(';')) {
        name.to_string()
    } else {
        format!("L{name};")
    }
}

fn arch_of(image: &Image) -> Option<Arch> {
    if image.big_endian {
        return None;
    }
    match (image.machine, image.ptr_size) {
        (elf::EM_AARCH64, 8) => Some(Arch::Aarch64),
        (elf::EM_ARM, 4) => Some(Arch::Arm),
        (elf::EM_X86_64, 8) => Some(Arch::X86_64),
        (elf::EM_386, 4) => Some(Arch::X86),
        _ => None,
    }
}

fn sp_reg(arch: Arch) -> u8 {
    match arch {
        Arch::Aarch64 => 31,
        Arch::Arm => 13,
        Arch::X86 | Arch::X86_64 => 4,
    }
}

/// Registre du n-ième argument entier ; `None` pour x86, qui les passe sur la
/// pile.
fn arg_reg(arch: Arch, index: usize) -> Option<u8> {
    match arch {
        Arch::Aarch64 | Arch::Arm => u8::try_from(index).ok(),
        Arch::X86_64 => [7, 6, 2, 1].get(index).copied(),
        Arch::X86 => None,
    }
}

fn syscall_reg(arch: Arch) -> u8 {
    match arch {
        Arch::Aarch64 => 8,
        Arch::Arm => 7,
        Arch::X86 | Arch::X86_64 => 0,
    }
}

fn is_callee_saved(arch: Arch, reg: u8) -> bool {
    match arch {
        Arch::Aarch64 => (19..=29).contains(&reg),
        Arch::Arm => (4..=11).contains(&reg),
        Arch::X86_64 => matches!(reg, 3 | 5 | 12..=15),
        Arch::X86 => matches!(reg, 3 | 5 | 6 | 7),
    }
}

struct Ctx<'a> {
    image: Image<'a>,
    arch: Option<Arch>,
    slots: HashMap<u64, u64>,
    got: HashMap<u64, String>,
    /// Adresse de fonction → (nom, st_size).
    symbols: HashMap<u64, (String, u64)>,
    starts: HashSet<u64>,
    plt_got: Option<u64>,
    plt_cache: RefCell<HashMap<u64, Option<String>>>,
    /// Fonction déjà désassemblée → aucun de ses chemins ne revient.
    noreturn: RefCell<HashMap<u64, bool>>,
}

impl<'a> Ctx<'a> {
    fn new(image: Image<'a>) -> Self {
        let arch = arch_of(&image);
        Ctx {
            image,
            arch,
            slots: HashMap::new(),
            got: HashMap::new(),
            symbols: HashMap::new(),
            starts: HashSet::new(),
            plt_got: None,
            plt_cache: RefCell::new(HashMap::new()),
            noreturn: RefCell::new(HashMap::new()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Val {
    /// Valeur inconnue, avec une identité.
    Opaque(u32),
    Const(u64),
    /// Mot lu à cette adresse.
    Mem(u64),
    /// Adresse de pile : sp à l'entrée de la fonction plus ce décalage.
    Stack(i64),
    Env,
    EnvTable,
    EnvFn(u64),
    Vm,
    VmTable,
    VmFn(u64),
    /// jclass rendu par FindClass ; adresse du nom de la classe.
    Class(u64),
    /// `*opaque`.
    Deref(u32),
    /// `*(*opaque + décalage)`.
    Deref2(u32, u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Key {
    Stack(i64),
    Abs(u64),
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    address: u64,
    thumb: bool,
    origin: &'static str,
    /// Premier argument à l'entrée : Env, Vm, ou inconnu.
    arg0: Val,
}

struct Machine {
    arch: Arch,
    regs: [Val; 32],
    defs: [u16; 32],
    mem: HashMap<Key, Val>,
    next_id: u32,
}

impl Machine {
    fn new(arch: Arch) -> Self {
        let mut machine = Machine {
            arch,
            regs: std::array::from_fn(|i| Val::Opaque(i as u32 + 1)),
            defs: [0; 32],
            mem: HashMap::new(),
            next_id: 33,
        };
        machine.put(sp_reg(arch), Val::Stack(0));
        machine
    }

    fn enter(ctx: &Ctx, arch: Arch, entry: &Entry) -> Self {
        let mut machine = Machine::new(arch);
        match arg_reg(arch, 0) {
            Some(reg) => machine.put(reg, entry.arg0),
            None => {
                let at = ctx.image.ptr_size as i64;
                machine.mem.insert(Key::Stack(at), entry.arg0);
            }
        }
        machine
    }

    fn fresh(&mut self) -> Val {
        self.next_id = self.next_id.wrapping_add(1);
        Val::Opaque(self.next_id)
    }

    fn get(&self, reg: u8) -> Val {
        match self.regs.get(usize::from(reg)) {
            Some(&value) => value,
            None => Val::Opaque(0),
        }
    }

    fn put(&mut self, reg: u8, value: Val) {
        if let Some(slot) = self.regs.get_mut(usize::from(reg)) {
            *slot = value;
        }
    }

    fn set(&mut self, reg: u8, value: Val) {
        let index = usize::from(reg);
        if let Some(slot) = self.regs.get_mut(index) {
            *slot = value;
            self.defs[index] = self.defs[index].saturating_add(1);
        }
    }

    /// Cible de branche : seuls sp et les registres callee-saved écrits une
    /// seule fois dans la fonction gardent leur valeur.
    fn reset(&mut self) {
        let sp = sp_reg(self.arch);
        for reg in 0..32u8 {
            let single = self.defs[usize::from(reg)] == 1;
            if reg == sp || (single && is_callee_saved(self.arch, reg)) {
                continue;
            }
            let value = self.fresh();
            self.put(reg, value);
        }
    }

    fn materialize(&self, ctx: &Ctx, value: Val) -> Option<u64> {
        match value {
            Val::Const(c) => Some(c),
            Val::Mem(at) => pointer(&ctx.image, &ctx.slots, at),
            _ => None,
        }
    }

    fn add(&mut self, ctx: &Ctx, value: Val, delta: i64) -> Val {
        if delta == 0 {
            return value;
        }
        if let Val::Stack(d) = value {
            return Val::Stack(d.wrapping_add(delta));
        }
        let mask = ptr_mask(ctx.image.ptr_size);
        match self.materialize(ctx, value) {
            Some(c) => Val::Const(c.wrapping_add(delta as u64) & mask),
            None => self.fresh(),
        }
    }

    fn eval(&mut self, ctx: &Ctx, expr: Expr) -> Val {
        let mask = ptr_mask(ctx.image.ptr_size);
        match expr {
            Expr::Imm(c) => Val::Const(c & mask),
            Expr::Reg(reg) => self.get(reg),
            Expr::AddImm(reg, delta) => {
                let value = self.get(reg);
                self.add(ctx, value, delta)
            }
            Expr::AddReg(a, b) => {
                let (left, right) = (self.get(a), self.get(b));
                match self.materialize(ctx, right) {
                    Some(c) => self.add(ctx, left, c as i64),
                    None => self.fresh(),
                }
            }
            Expr::MovK(reg, imm, shift) => match self.get(reg) {
                Val::Const(c) => Val::Const((c & !(0xffff << shift)) | (imm << shift)),
                _ => self.fresh(),
            },
            Expr::MovT(reg, imm) => match self.get(reg) {
                Val::Const(c) => Val::Const((c & 0xffff) | (imm << 16)),
                _ => self.fresh(),
            },
            Expr::Unknown => self.fresh(),
        }
    }

    fn recall(&mut self, key: Key) -> Val {
        let known = self.mem.get(&key).copied();
        known.unwrap_or_else(|| self.fresh())
    }

    fn load(&mut self, ctx: &Ctx, addr: Addr, width: u64) -> Val {
        match addr {
            Addr::Abs(at) => self.load_abs(ctx, at, width),
            Addr::Base(reg, off) => {
                let base = self.get(reg);
                self.load_from(ctx, base, off, width)
            }
            Addr::Unknown => self.fresh(),
        }
    }

    fn load_from(&mut self, ctx: &Ctx, base: Val, off: i64, width: u64) -> Val {
        let word = width == ctx.image.ptr_size;
        match base {
            Val::Env if word && off == 0 => Val::EnvTable,
            Val::EnvTable if word && off >= 0 => Val::EnvFn(off as u64),
            Val::Vm if word && off == 0 => Val::VmTable,
            Val::VmTable if word && off >= 0 => Val::VmFn(off as u64),
            Val::Opaque(id) if word && off == 0 => Val::Deref(id),
            Val::Deref(id) if word && off >= 0 => Val::Deref2(id, off as u64),
            Val::Stack(d) => self.recall(Key::Stack(d.wrapping_add(off))),
            other => match self.materialize(ctx, other) {
                Some(at) => self.load_abs(ctx, at.wrapping_add(off as u64), width),
                None => self.fresh(),
            },
        }
    }

    fn load_abs(&mut self, ctx: &Ctx, at: u64, width: u64) -> Val {
        if let Some(&value) = self.mem.get(&Key::Abs(at)) {
            return value;
        }
        if width == ctx.image.ptr_size {
            return Val::Mem(at);
        }
        let offset = ctx.image.offset_of(at);
        let bytes = offset.and_then(|o| ctx.image.bytes_at(o, width));
        match bytes {
            Some(bytes) if !ctx.image.big_endian => Val::Const(read_le(bytes)),
            _ => self.fresh(),
        }
    }

    fn store(&mut self, ctx: &Ctx, value: Val, addr: Addr) {
        let place = match addr {
            Addr::Abs(at) => Val::Const(at),
            Addr::Base(reg, off) => {
                let base = self.get(reg);
                self.add(ctx, base, off)
            }
            Addr::Unknown => return,
        };
        self.store_at(ctx, place, value);
    }

    fn store_at(&mut self, ctx: &Ctx, place: Val, value: Val) {
        let key = match place {
            Val::Stack(d) => Key::Stack(d),
            other => match self.materialize(ctx, other) {
                Some(at) => Key::Abs(at),
                None => return,
            },
        };
        self.mem.insert(key, value);
    }

    fn apply(&mut self, ctx: &Ctx, insn: &Insn) {
        for op in &insn.ops {
            match *op {
                Op::Set(reg, expr) => {
                    let value = self.eval(ctx, expr);
                    self.set(reg, value);
                }
                Op::Load(reg, addr, width) => {
                    let value = self.load(ctx, addr, width);
                    self.set(reg, value);
                }
                Op::Store(expr, addr) => {
                    let value = self.eval(ctx, expr);
                    self.store(ctx, value, addr);
                }
            }
        }
    }

    fn via(&mut self, ctx: &Ctx, via: Via) -> Val {
        match via {
            Via::Reg(reg) => self.get(reg),
            Via::Mem(addr) => self.load(ctx, addr, ctx.image.ptr_size),
            Via::Unknown => self.fresh(),
        }
    }
}

fn read_le(bytes: &[u8]) -> u64 {
    let mut value = 0;
    for &b in bytes.iter().rev() {
        value = (value << 8) | u64::from(b);
    }
    value
}

fn in_function(ctx: &Ctx, start: u64, at: u64) -> bool {
    if let Some(&(_, size)) = ctx.symbols.get(&start) {
        if size > 0 {
            return at >= start && at - start < size;
        }
    }
    ctx.image.is_exec(at) && (at == start || !ctx.starts.contains(&at))
}

fn is_internal(ctx: &Ctx, start: u64, at: u64, thumb: bool) -> bool {
    at != 0 && in_function(ctx, start, at) && plt_import(ctx, at, thumb).is_none()
}

/// Cible d'appel direct qui peut être une fonction : non nulle, dans un segment
/// LOAD exécutable.
fn callable(ctx: &Ctx, at: u64) -> bool {
    at != 0 && ctx.image.is_exec(at)
}

/// Méthode inline de jni.h émise hors ligne par un compilateur C++.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wrapper {
    /// `_JNIEnv::<nom>` : nom et index dans JNINativeInterface.
    Env(&'static str, usize),
    /// `_JavaVM::<nom>` : nom et index dans JNIInvokeInterface.
    Vm(&'static str, usize),
}

/// `_ZN7_JNIEnv<n><Nom>E…` ou `_ZN7_JavaVM<n><Nom>E…`, `<Nom>` présent dans la
/// table correspondante, hors emplacements réservés.
fn cxx_wrapper(symbol: &str) -> Option<Wrapper> {
    let (vm, rest) = match symbol.strip_prefix("_ZN7_JNIEnv") {
        Some(rest) => (false, rest),
        None => (true, symbol.strip_prefix("_ZN7_JavaVM")?),
    };
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    let len: usize = rest[..digits].parse().ok()?;
    let end = digits.checked_add(len)?;
    let name = rest.get(digits..end)?;
    if !rest[end..].starts_with('E') {
        return None;
    }
    let (table, reserved): (&[&'static str], usize) = if vm {
        (&jni::JNI_INVOKE_INTERFACE, jni::INVOKE_RESERVED_SLOTS)
    } else {
        (&jni::JNI_NATIVE_INTERFACE, jni::RESERVED_SLOTS)
    };
    let index = table.iter().position(|&n| n == name)?;
    if index < reserved {
        return None;
    }
    let name = table[index];
    Some(if vm {
        Wrapper::Vm(name, index)
    } else {
        Wrapper::Env(name, index)
    })
}

/// Appel direct sans retour : import de [`NORETURN_IMPORTS`], ou fonction
/// interne déjà désassemblée dont aucun chemin ne revient. Rien n'est deviné
/// pour une fonction pas encore vue.
fn is_noreturn(ctx: &Ctx, target: u64, thumb: bool) -> bool {
    if ctx.noreturn.borrow().get(&target) == Some(&true) {
        return true;
    }
    match plt_import(ctx, target, thumb) {
        Some(name) => NORETURN_IMPORTS.contains(&name.as_str()),
        None => false,
    }
}

/// Les entrées PLT sont en ARM sur ARM 32 bits : une cible Thumb n'en est pas
/// une, et la décoder en ARM ferait lire du Thumb comme de l'ARM.
fn plt_import(ctx: &Ctx, at: u64, thumb: bool) -> Option<String> {
    if ctx.got.is_empty() || thumb {
        return None;
    }
    if let Some(found) = ctx.plt_cache.borrow().get(&at) {
        return found.clone();
    }
    let found = resolve_plt(ctx, at);
    ctx.plt_cache.borrow_mut().insert(at, found.clone());
    found
}

/// Un stub PLT charge un emplacement de GOT puis saute à sa valeur : quelques
/// instructions évaluées depuis un état vide suffisent à le reconnaître.
fn resolve_plt(ctx: &Ctx, at: u64) -> Option<String> {
    let arch = ctx.arch?;
    let mut machine = Machine::new(arch);
    if let (Arch::X86, Some(got)) = (arch, ctx.plt_got) {
        machine.put(3, Val::Const(got));
    }
    let mut pc = at;
    for _ in 0..PLT_STUB_INSNS {
        let insn = decode(arch, ctx.image.code_window(pc)?, pc, false).ok()?;
        machine.apply(ctx, &insn);
        match insn.flow {
            Flow::Next => pc = pc.wrapping_add(insn.len),
            Flow::JumpVia(via) => {
                return match machine.via(ctx, via) {
                    Val::Mem(slot) => ctx.got.get(&slot).cloned(),
                    _ => None,
                };
            }
            _ => return None,
        }
    }
    None
}

/// `__x86.get_pc_thunk.*` : `mov reg, [esp]; ret`. Rend le registre écrit.
fn pc_thunk(ctx: &Ctx, target: u64) -> Option<u8> {
    let code = ctx.image.code_window(target)?;
    match code.get(..4)? {
        [0x8b, modrm, 0x24, 0xc3] if *modrm & 0xc7 == 0x04 => Some((*modrm >> 3) & 7),
        _ => None,
    }
}

#[derive(Default)]
struct Explored {
    insns: Vec<Insn>,
    targets: HashSet<u64>,
    /// Plafond atteint : max_insns.
    reason: Option<&'static str>,
    truncated_at: Option<TruncatedAt>,
    invalid_paths: Vec<InvalidPath>,
    /// Un chemin au moins rend la main à l'appelant, ou peut le faire.
    returns: bool,
}

impl Explored {
    fn abandon(&mut self, at: u64, raw: &[u8], reason: &'static str, from: Option<u64>) {
        let path = InvalidPath {
            address: hex(at),
            bytes: hex_bytes(raw),
            reason,
            reached_from: from.map(hex),
        };
        self.invalid_paths.push(path);
    }
}

/// Descente récursive : seuls les successeurs explicites sont suivis. Après un
/// retour, un saut, un tail-call ou un appel sans retour, rien n'est lu en
/// séquence. Un chemin qui tombe sur des octets indécodables est abandonné
/// seul ; les autres successeurs en attente sont parcourus.
fn explore(ctx: &Ctx, arch: Arch, entry: &Entry, max_insns: usize) -> Explored {
    let mut out = Explored::default();
    let mut seen = HashSet::new();
    let mut work = vec![(entry.address, entry.thumb, None)];
    'paths: while let Some((start, thumb, origin)) = work.pop() {
        let mut at = start;
        // Dernier branchement qui mène à l'instruction courante.
        let mut from = origin;
        while seen.insert(at) {
            let code = ctx.image.code_window(at);
            if out.insns.len() >= max_insns {
                let raw = code.unwrap_or_default();
                let place = TruncatedAt {
                    address: hex(at),
                    bytes: hex_bytes(&raw[..undecoded_len(arch, raw, thumb)]),
                };
                out.reason = Some(REASON_MAX_INSNS);
                out.truncated_at = Some(place);
                break 'paths;
            }
            let Some(code) = code else {
                out.abandon(at, &[], REASON_OUTSIDE_EXEC, from);
                break;
            };
            let insn = match decode(arch, code, at, thumb) {
                Ok(insn) => insn,
                Err(failure) => {
                    let reason = match failure {
                        Failure::Invalid => REASON_INVALID_INSTRUCTION,
                        Failure::Panic => REASON_DECODER_PANIC,
                    };
                    let raw = &code[..undecoded_len(arch, code, thumb)];
                    out.abandon(at, raw, reason, from);
                    break;
                }
            };
            let next = at.wrapping_add(insn.len);
            let flow = insn.flow;
            out.insns.push(insn);
            match flow {
                Flow::Next | Flow::CallVia(_) => {}
                Flow::Call(target, mode) => {
                    if is_noreturn(ctx, target, mode) {
                        break;
                    }
                }
                Flow::Branch(target, mode) => {
                    if in_function(ctx, entry.address, target) {
                        out.targets.insert(target);
                        work.push((target, mode, Some(at)));
                    }
                    from = Some(at);
                }
                Flow::Jump(target, mode) => {
                    if is_internal(ctx, entry.address, target, mode) {
                        out.targets.insert(target);
                        work.push((target, mode, Some(at)));
                    } else if !is_noreturn(ctx, target, mode) {
                        out.returns = true;
                    }
                    break;
                }
                Flow::JumpVia(_) | Flow::Return => {
                    out.returns = true;
                    break;
                }
                Flow::Stop => break,
            }
            if !in_function(ctx, entry.address, next) {
                out.returns = true;
                break;
            }
            at = next;
        }
    }
    out.insns.sort_by_key(|insn| insn.address);
    out
}

struct Analyzed {
    function: DisasmFunction,
    callees: Vec<Entry>,
    /// main passé à __libc_init ou __libc_start_main : un point d'entrée de plus.
    mains: Vec<Entry>,
    upcalls: Vec<JavaMember>,
    registered: Vec<JavaMember>,
}

impl Analyzed {
    fn new(entry: &Entry) -> Self {
        Analyzed {
            function: DisasmFunction::new(entry),
            callees: Vec::new(),
            mains: Vec::new(),
            upcalls: Vec::new(),
            registered: Vec::new(),
        }
    }
}

fn analyze_function(ctx: &Ctx, entry: &Entry, max_insns: usize) -> Analyzed {
    let mut out = Analyzed::new(entry);
    let Some(arch) = ctx.arch else {
        out.function.disasm_status = STATUS_ARCH_UNSUPPORTED;
        return out;
    };
    let explored = explore(ctx, arch, entry, max_insns);
    out.function.invalid_paths = explored.invalid_paths;
    if explored.insns.is_empty() {
        out.function.disasm_status = STATUS_INVALID_ENTRY;
        return out;
    }
    let complete = explored.reason.is_none() && out.function.invalid_paths.is_empty();
    let noreturn = !explored.returns && complete;
    ctx.noreturn.borrow_mut().insert(entry.address, noreturn);
    if explored.reason.is_some() {
        out.function.disasm_status = STATUS_TRUNCATED;
        out.function.truncated = true;
        out.function.truncated_reason = explored.reason;
        out.function.truncated_at = explored.truncated_at;
    }

    let mut walk = Walk {
        ctx,
        arch,
        start: entry.address,
        machine: Machine::new(arch),
        out,
        calls: Vec::new(),
    };
    let mut expected = None;
    for insn in &explored.insns {
        if insn.address == entry.address {
            walk.machine = Machine::enter(ctx, arch, entry);
        } else if explored.targets.contains(&insn.address) || expected != Some(insn.address) {
            walk.machine.reset();
        }
        walk.step(insn);
        expected = match insn.flow {
            Flow::Jump(..) | Flow::JumpVia(_) | Flow::Return | Flow::Stop => None,
            _ => Some(insn.address.wrapping_add(insn.len)),
        };
    }

    let mut out = walk.out;
    for call in walk.calls {
        if !out.function.calls.contains(&call) {
            out.function.calls.push(call);
        }
    }
    for insn in explored.insns {
        let instruction = DisasmInsn {
            address: hex(insn.address),
            bytes: insn.bytes,
            mnemonic: insn.mnemonic,
            operands: insn.operands,
        };
        out.function.instructions.push(instruction);
    }
    out
}

struct Walk<'w, 'a> {
    ctx: &'w Ctx<'a>,
    arch: Arch,
    start: u64,
    machine: Machine,
    out: Analyzed,
    calls: Vec<DisasmCall>,
}

impl Walk<'_, '_> {
    fn step(&mut self, insn: &Insn) {
        let ctx = self.ctx;
        self.machine.apply(ctx, insn);
        if let Some(reg) = insn.forms_address {
            let value = self.machine.get(reg);
            if let Some(target) = self.machine.materialize(ctx, value) {
                self.string_ref(insn.address, target);
            }
        }
        if insn.syscall {
            let value = self.machine.get(syscall_reg(self.arch));
            let number = self.machine.materialize(ctx, value);
            let syscall = Syscall {
                address: hex(insn.address),
                number,
            };
            self.out.function.syscalls.push(syscall);
        }
        match insn.flow {
            Flow::Call(target, mode) => self.direct_call(insn, target, mode),
            Flow::Jump(target, mode) if !is_internal(ctx, self.start, target, mode) => {
                let arg0 = self.arg(0);
                self.record_direct(target, mode, arg0);
            }
            Flow::CallVia(via) => self.indirect(via, true),
            Flow::JumpVia(via) => self.indirect(via, false),
            _ => {}
        }
    }

    fn string_ref(&mut self, address: u64, target: u64) {
        let image = &self.ctx.image;
        let Some(hex_allowed) = image.data_kind(target) else {
            return;
        };
        let Some(bytes) = image.c_string_bytes(target) else {
            return;
        };
        let text = std::str::from_utf8(bytes).ok().filter(|t| printable(t));
        let (value, encoding) = match text {
            Some(text) => (text.to_string(), "utf8"),
            None if hex_allowed => (hex_bytes(bytes), "hex"),
            None => return,
        };
        let address = hex(address);
        let refs = &mut self.out.function.string_refs;
        if refs.iter().any(|r| r.address == address) {
            return;
        }
        refs.push(StringRef {
            address,
            target: hex(target),
            value,
            encoding,
        });
    }

    fn arg(&mut self, index: usize) -> Val {
        let ctx = self.ctx;
        match arg_reg(self.arch, index) {
            Some(reg) => self.machine.get(reg),
            None => {
                let ptr = ctx.image.ptr_size;
                let sp = self.machine.get(sp_reg(self.arch));
                let off = (index as u64 * ptr) as i64;
                self.machine.load_from(ctx, sp, off, ptr)
            }
        }
    }

    fn direct_call(&mut self, insn: &Insn, target: u64, mode: bool) {
        let ctx = self.ctx;
        let next = insn.address.wrapping_add(insn.len);
        if self.arch == Arch::X86 && target == next {
            // call/pop : lecture d'eip, pas un appel.
            let sp = sp_reg(self.arch);
            let top = self.machine.get(sp);
            let top = self.machine.add(ctx, top, -4);
            self.machine.set(sp, top);
            self.machine.store_at(ctx, top, Val::Const(next));
            return;
        }
        let arg0 = self.arg(0);
        let ret = self.record_direct(target, mode, arg0);
        self.after_call(ret);
        if self.arch == Arch::X86 {
            if let Some(reg) = pc_thunk(ctx, target) {
                self.machine.set(reg, Val::Const(next));
            }
        }
    }

    /// Appel ou tail-call direct. Rend la valeur produite quand la cible est un
    /// wrapper C++ de jni.h.
    fn record_direct(&mut self, target: u64, mode: bool, arg0: Val) -> Option<Val> {
        let ctx = self.ctx;
        if !callable(ctx, target) {
            self.calls.push(DisasmCall {
                target: Some(hex(target)),
                import: None,
                symbol: None,
                kind: CALL_UNRESOLVED,
            });
            return None;
        }
        if let Some(name) = plt_import(ctx, target, mode) {
            let wrapper = cxx_wrapper(&name);
            self.libc_main(&name);
            self.calls.push(DisasmCall {
                target: Some(hex(target)),
                import: Some(name),
                symbol: None,
                kind: CALL_PLT,
            });
            return wrapper.map(|w| self.wrapper_call(w));
        }
        let symbol = ctx.symbols.get(&target).map(|(name, _)| name.clone());
        let wrapper = symbol.as_deref().and_then(cxx_wrapper);
        self.calls.push(DisasmCall {
            target: Some(hex(target)),
            import: None,
            symbol,
            kind: CALL_INTERNAL,
        });
        let arg0 = match arg0 {
            Val::Env | Val::Vm => arg0,
            _ => Val::Opaque(0),
        };
        let callee = entry(target, mode, ORIGIN_CALLEE, arg0);
        self.out.callees.push(callee);
        wrapper.map(|w| self.wrapper_call(w))
    }

    fn indirect(&mut self, via: Via, is_call: bool) {
        let ctx = self.ctx;
        let value = self.machine.via(ctx, via);
        let arg0 = self.arg(0);
        let jni = match value {
            Val::EnvFn(off) => self.jni_call(off, true),
            Val::Deref2(id, off) if arg0 == Val::Opaque(id) => self.jni_call(off, false),
            _ => None,
        };
        if let Val::VmFn(off) = value {
            self.invoke_call(off);
        }
        let ret = match jni {
            Some(ret) => {
                self.calls.push(indirect_call());
                Some(ret)
            }
            None => self.record_value(value, arg0, is_call),
        };
        if is_call {
            self.after_call(ret);
        }
    }

    fn record_value(&mut self, value: Val, arg0: Val, is_call: bool) -> Option<Val> {
        let ctx = self.ctx;
        if let Val::Mem(slot) = value {
            if let Some(name) = ctx.got.get(&slot) {
                let wrapper = cxx_wrapper(name);
                self.libc_main(name);
                self.calls.push(DisasmCall {
                    target: None,
                    import: Some(name.clone()),
                    symbol: None,
                    kind: CALL_PLT,
                });
                return wrapper.map(|w| self.wrapper_call(w));
            }
        }
        let arm = self.arch == Arch::Arm;
        let target = self.machine.materialize(ctx, value);
        match target.map(|t| split_thumb(arm, t)) {
            Some((address, mode)) if ctx.image.is_exec(address) => {
                self.record_direct(address, mode, arg0)
            }
            _ if is_call => {
                self.calls.push(indirect_call());
                None
            }
            _ => None,
        }
    }

    /// `__libc_init(raw_args, onexit, main, structors)` (bionic) et
    /// `__libc_start_main(main, argc, argv, …)` (glibc) : main, lu avant que
    /// l'appel n'écrase les registres d'argument.
    fn libc_main(&mut self, import: &str) {
        let index = match import {
            "__libc_init" => 2,
            "__libc_start_main" => 0,
            _ => return,
        };
        let ctx = self.ctx;
        let value = self.arg(index);
        let Some(target) = self.machine.materialize(ctx, value) else {
            return;
        };
        let (address, thumb) = split_thumb(self.arch == Arch::Arm, target);
        if callable(ctx, address) {
            let main = entry(address, thumb, ORIGIN_MAIN, Val::Opaque(0));
            self.out.mains.push(main);
        }
    }

    fn after_call(&mut self, ret: Option<Val>) {
        let sp = sp_reg(self.arch);
        for reg in 0..32u8 {
            if reg != sp && !is_callee_saved(self.arch, reg) {
                let value = self.machine.fresh();
                self.machine.put(reg, value);
            }
        }
        let value = ret.unwrap_or_else(|| self.machine.fresh());
        self.machine.put(0, value);
    }

    fn string_arg(&mut self, index: usize) -> Option<String> {
        let value = self.arg(index);
        let at = self.machine.materialize(self.ctx, value)?;
        utf8_at(self.ctx, at)
    }

    fn class_arg(&mut self, index: usize) -> Option<String> {
        match self.arg(index) {
            Val::Class(at) => utf8_at(self.ctx, at).map(|name| class_descriptor(&name)),
            _ => None,
        }
    }

    /// Appel par la table de JNIEnv au décalage `off`. `None` si ce décalage ne
    /// désigne aucune fonction de la table ; sinon la valeur rendue.
    fn jni_call(&mut self, off: u64, env_proven: bool) -> Option<Val> {
        let ptr = self.ctx.image.ptr_size;
        if !off.is_multiple_of(ptr) {
            return None;
        }
        let index = usize::try_from(off / ptr).ok()?;
        if index < jni::RESERVED_SLOTS {
            return None;
        }
        let name = *jni::JNI_NATIVE_INTERFACE.get(index)?;
        Some(self.env_call(name, index, FORM_VTABLE, env_proven))
    }

    /// Wrapper C++ : `this` est l'env ou la JavaVM, si bien que les arguments
    /// de jni.h occupent les mêmes registres que dans l'appel par la table.
    fn wrapper_call(&mut self, wrapper: Wrapper) -> Val {
        match wrapper {
            Wrapper::Env(name, index) => self.env_call(name, index, FORM_CXX_WRAPPER, true),
            Wrapper::Vm(name, index) => {
                self.writes_env(index);
                let mut call = JniCall::new(name, index, FORM_CXX_WRAPPER);
                call.resolved = true;
                self.out.function.jni_calls.push(call);
                self.machine.fresh()
            }
        }
    }

    /// Fonction `index` de JNINativeInterface, sous l'une ou l'autre forme ;
    /// rend la valeur produite par l'appel.
    fn env_call(
        &mut self,
        name: &'static str,
        index: usize,
        form: &'static str,
        env_proven: bool,
    ) -> Val {
        let ctx = self.ctx;
        let mut call = JniCall::new(name, index, form);
        let mut ret = None;
        let mut missing = None;
        match index {
            jni::FIND_CLASS => {
                let value = self.arg(1);
                let at = self.machine.materialize(ctx, value);
                match at.and_then(|at| utf8_at(ctx, at).map(|name| (at, name))) {
                    Some((at, name)) => {
                        call.class = Some(class_descriptor(&name));
                        ret = Some(Val::Class(at));
                    }
                    None => missing = Some(UNRESOLVED_CLASS),
                }
            }
            jni::GET_METHOD_ID
            | jni::GET_STATIC_METHOD_ID
            | jni::GET_FIELD_ID
            | jni::GET_STATIC_FIELD_ID => {
                call.class = self.class_arg(1);
                call.method = self.string_arg(2);
                call.signature = self.string_arg(3);
                missing = if call.class.is_none() {
                    Some(UNRESOLVED_CLASS)
                } else if call.method.is_none() {
                    Some(UNRESOLVED_NAME)
                } else if call.signature.is_none() {
                    Some(UNRESOLVED_SIGNATURE)
                } else {
                    None
                };
                if let Some(member) = upcall(&call) {
                    self.out.upcalls.push(member);
                }
            }
            jni::REGISTER_NATIVES => {
                call.class = self.class_arg(1);
                missing = match call.class.clone() {
                    Some(class) => (!self.registered_by_code(&class)).then_some(UNRESOLVED_TABLE),
                    None => Some(UNRESOLVED_CLASS),
                };
            }
            jni::NEW_GLOBAL_REF | jni::NEW_LOCAL_REF | jni::NEW_WEAK_GLOBAL_REF => {
                if let Val::Class(at) = self.arg(1) {
                    ret = Some(Val::Class(at));
                }
            }
            _ => {}
        }
        let reason = if env_proven {
            missing
        } else {
            Some(UNRESOLVED_ENV)
        };
        call.resolved = reason.is_none();
        call.unresolved_reason = reason;
        self.out.function.jni_calls.push(call);
        ret.unwrap_or_else(|| self.machine.fresh())
    }

    /// Entrées JNINativeMethod passées à RegisterNatives : table en troisième
    /// argument, nombre en quatrième. Faux si aucune entrée n'a pu être lue.
    fn registered_by_code(&mut self, class: &str) -> bool {
        let ctx = self.ctx;
        let table = self.arg(2);
        let count = self.arg(3);
        let Some(mut at) = self.machine.materialize(ctx, table) else {
            return false;
        };
        let limit = match self.machine.materialize(ctx, count) {
            Some(count) => count.min(MAX_REGISTER_ENTRIES),
            None => MAX_REGISTER_ENTRIES,
        };
        let stride = 3 * ctx.image.ptr_size;
        let before = self.out.registered.len();
        for _ in 0..limit {
            let Some(method) = jni_entry_at(&ctx.image, &ctx.slots, at) else {
                break;
            };
            let member = JavaMember {
                class: class.to_string(),
                name: method.name,
                signature: method.signature,
                fn_address: parse_hex(&method.fn_offset),
            };
            self.out.registered.push(member);
            at = at.wrapping_add(stride);
        }
        self.out.registered.len() > before
    }

    fn invoke_call(&mut self, off: u64) {
        let ptr = self.ctx.image.ptr_size;
        if !off.is_multiple_of(ptr) {
            return;
        }
        if let Ok(index) = usize::try_from(off / ptr) {
            self.writes_env(index);
        }
    }

    /// GetEnv et AttachCurrentThread écrivent un JNIEnv* à l'adresse passée en
    /// deuxième argument.
    fn writes_env(&mut self, index: usize) {
        let writes_env = [
            jni::INVOKE_ATTACH_CURRENT_THREAD,
            jni::INVOKE_GET_ENV,
            jni::INVOKE_ATTACH_CURRENT_THREAD_AS_DAEMON,
        ];
        if writes_env.contains(&index) {
            let place = self.arg(1);
            self.machine.store_at(self.ctx, place, Val::Env);
        }
    }
}

/// Upcall : Get*MethodID ou Get*FieldID dont classe, nom et signature sont
/// connus.
fn upcall(call: &JniCall) -> Option<JavaMember> {
    Some(JavaMember {
        class: call.class.clone()?,
        name: call.method.clone()?,
        signature: call.signature.clone()?,
        fn_address: None,
    })
}

fn indirect_call() -> DisasmCall {
    DisasmCall {
        target: None,
        import: None,
        symbol: None,
        kind: CALL_INDIRECT,
    }
}

fn analyze_guarded(ctx: &Ctx, entry: &Entry, max_insns: usize) -> Analyzed {
    let job = AssertUnwindSafe(|| analyze_function(ctx, entry, max_insns));
    match std::panic::catch_unwind(job) {
        Ok(analyzed) => analyzed,
        Err(_) => {
            let mut analyzed = Analyzed::new(entry);
            analyzed.function.disasm_status = STATUS_TRUNCATED;
            analyzed.function.truncated = true;
            analyzed.function.truncated_reason = Some(REASON_PANIC);
            analyzed
        }
    }
}

fn walk_functions(ctx: &Ctx, entries: Vec<Entry>, options: &DisasmOptions) -> ElfDisasm {
    let mut out = ElfDisasm::default();
    let mut done = HashSet::new();
    let mut level = entries;
    for depth in 0..=options.depth {
        let mut next = Vec::new();
        let mut queue = level;
        let mut at = 0;
        while let Some(&entry) = queue.get(at) {
            at += 1;
            if !done.insert(entry.address) {
                continue;
            }
            let analyzed = analyze_guarded(ctx, &entry, options.max_insns);
            // main est désassemblé au niveau de l'entrée qui le passe.
            queue.extend(analyzed.mains);
            if depth < options.depth {
                next.extend(analyzed.callees);
            }
            push_unique(&mut out.upcalls, analyzed.upcalls);
            push_unique(&mut out.registered_by_code, analyzed.registered);
            out.functions.push(analyzed.function);
        }
        level = next;
    }
    out.imports_called = imports_called(&out.functions);
    out.invalid_paths_count = out.functions.iter().map(|f| f.invalid_paths.len()).sum();
    out
}

/// Anomalie `opaque_dead_code` : mêmes octets invalides dans au moins
/// [`OPAQUE_DEAD_CODE_MIN`] fonctions.
fn opaque_dead_code(functions: &[DisasmFunction]) -> Option<String> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for function in functions {
        let mut distinct: Vec<&str> = Vec::new();
        for path in &function.invalid_paths {
            let bytes = path.bytes.as_str();
            if !bytes.is_empty() && !distinct.contains(&bytes) {
                distinct.push(bytes);
            }
        }
        for bytes in distinct {
            *counts.entry(bytes).or_default() += 1;
        }
    }
    let mut repeated = Vec::new();
    for (bytes, count) in counts {
        if count >= OPAQUE_DEAD_CODE_MIN {
            repeated.push(format!("{bytes} dans {count} fonctions"));
        }
    }
    if repeated.is_empty() {
        return None;
    }
    Some(format!("opaque_dead_code: {}", repeated.join(" ; ")))
}

fn push_unique(into: &mut Vec<JavaMember>, members: Vec<JavaMember>) {
    for member in members {
        if !into.contains(&member) {
            into.push(member);
        }
    }
}

fn imports_called(functions: &[DisasmFunction]) -> BTreeMap<&'static str, Vec<String>> {
    let mut by_category: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for function in functions {
        for call in &function.calls {
            let Some(name) = &call.import else {
                continue;
            };
            let category = import_category(name).unwrap_or("other");
            let names = by_category.entry(category).or_default();
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
    }
    for names in by_category.values_mut() {
        names.sort();
    }
    by_category
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::decode::COPROCESSOR;

    const CODE: u64 = 0x1000;

    /// AArch64, x0 = JNIEnv*.
    const A64_JNI: &[(u32, &str)] = &[
        (0xaa0003f3, "1000  mov  x19, x0"),
        (0xf9400268, "1004  ldr  x8, [x19]"),
        (
            0xf9401908,
            "1008  ldr  x8, [x8, #0x30]   ; FindClass, index 6",
        ),
        (0xb0000001, "100c  adrp x1, 0x2000"),
        (0x91000021, "1010  add  x1, x1, #0x0      ; com/foo/Bar"),
        (0xaa1303e0, "1014  mov  x0, x19"),
        (0xd63f0100, "1018  blr  x8"),
        (0xaa0003f4, "101c  mov  x20, x0           ; jclass"),
        (0xf9400268, "1020  ldr  x8, [x19]"),
        (
            0xf9408508,
            "1024  ldr  x8, [x8, #0x108]  ; GetMethodID, index 33",
        ),
        (0xb0000002, "1028  adrp x2, 0x2000"),
        (0x91004042, "102c  add  x2, x2, #0x10     ; run"),
        (0xb0000003, "1030  adrp x3, 0x2000"),
        (0x91006063, "1034  add  x3, x3, #0x18     ; ()V"),
        (0xaa1403e1, "1038  mov  x1, x20"),
        (0xaa1303e0, "103c  mov  x0, x19"),
        (0xd63f0100, "1040  blr  x8"),
        (0xf9400268, "1044  ldr  x8, [x19]"),
        (
            0xf9429d08,
            "1048  ldr  x8, [x8, #0x538]  ; NewStringUTF, index 167",
        ),
        (0xb0000001, "104c  adrp x1, 0x2000"),
        (0x91008021, "1050  add  x1, x1, #0x20     ; hello"),
        (0xaa1303e0, "1054  mov  x0, x19"),
        (0xd63f0100, "1058  blr  x8"),
        (0xd65f03c0, "105c  ret"),
    ];

    /// AArch64, x0 = JNIEnv*. Table JNINativeMethod en 0x2040.
    const A64_REGISTER: &[(u32, &str)] = &[
        (0xaa0003f3, "1000  mov  x19, x0"),
        (0xf9400268, "1004  ldr  x8, [x19]"),
        (0xf9401908, "1008  ldr  x8, [x8, #0x30]   ; FindClass"),
        (0xb0000001, "100c  adrp x1, 0x2000"),
        (0x91000021, "1010  add  x1, x1, #0x0      ; com/foo/Bar"),
        (0xaa1303e0, "1014  mov  x0, x19"),
        (0xd63f0100, "1018  blr  x8"),
        (0xaa0003e1, "101c  mov  x1, x0            ; jclass"),
        (0xf9400268, "1020  ldr  x8, [x19]"),
        (
            0xf9435d08,
            "1024  ldr  x8, [x8, #0x6b8]  ; RegisterNatives, index 215",
        ),
        (0xb0000002, "1028  adrp x2, 0x2000"),
        (0x91010042, "102c  add  x2, x2, #0x40     ; table"),
        (0x52800023, "1030  mov  w3, #1"),
        (0xaa1303e0, "1034  mov  x0, x19"),
        (0xd63f0100, "1038  blr  x8"),
        (0xd65f03c0, "103c  ret"),
    ];

    const A64_BRANCHES: &[(u32, &str)] = &[
        (0xb4000060, "1000  cbz  x0, 0x100c"),
        (0x9400003f, "1004  bl   0x1100"),
        (0xd65f03c0, "1008  ret"),
        (0x17fffffe, "100c  b    0x1004"),
    ];

    const A64_CALLS_PLT: &[(u32, &str)] =
        &[(0x94000200, "1000  bl   0x1800"), (0xd65f03c0, "1004  ret")];

    /// Stub PLT AArch64 : GOT en 0x3000.
    const A64_PLT: &[(u32, &str)] = &[
        (0xd0000010, "1800  adrp x16, 0x3000"),
        (0xf9400211, "1804  ldr  x17, [x16]"),
        (0x91000210, "1808  add  x16, x16, #0x0"),
        (0xd61f0220, "180c  br   x17"),
    ];

    /// Thumb, r0 = JNIEnv*. Chaîne en PIC : littéral 0xff6 en 0x1014, puis add pc.
    const THUMB_JNI: &[(u16, &str)] = &[
        (0xb510, "1000  push {r4, lr}"),
        (0x4604, "1002  mov  r4, r0"),
        (0x4903, "1004  ldr  r1, [pc, #12]    ; 0x1014"),
        (
            0x4479,
            "1006  add  r1, pc           ; 0xff6 + 0x100a = 0x2000",
        ),
        (0x6822, "1008  ldr  r2, [r4]"),
        (0x6992, "100a  ldr  r2, [r2, #24]    ; FindClass, index 6"),
        (0x4620, "100c  mov  r0, r4"),
        (0x4790, "100e  blx  r2"),
        (0xbd10, "1010  pop  {r4, pc}"),
        (0xbf00, "1012  nop"),
    ];

    /// x86_64, rdi = JNIEnv*.
    const X64_JNI: &[(&[u8], &str)] = &[
        (&[0x53], "1000  push rbx"),
        (&[0x48, 0x89, 0xfb], "1001  mov  rbx, rdi"),
        (&[0x48, 0x8b, 0x07], "1004  mov  rax, [rdi]"),
        (
            &[0x48, 0x8d, 0x35, 0xf2, 0x0f, 0, 0],
            "1007  lea  rsi, [rip+0xff2]",
        ),
        (&[0xff, 0x50, 0x30], "100e  call [rax+0x30]   ; FindClass"),
        (&[0x48, 0x8b, 0x03], "1011  mov  rax, [rbx]"),
        (&[0x48, 0x89, 0xdf], "1014  mov  rdi, rbx"),
        (
            &[0x48, 0x8d, 0x35, 0x02, 0x10, 0, 0],
            "1017  lea  rsi, [rip+0x1002]",
        ),
        (
            &[0xff, 0x90, 0x38, 0x05, 0, 0],
            "101e  call [rax+0x538]  ; NewStringUTF",
        ),
        (&[0x5b], "1024  pop  rbx"),
        (&[0xc3], "1025  ret"),
    ];

    fn image(data: &[u8], machine: u16, ptr_size: u64) -> Image<'_> {
        let size = data.len() as u64;
        let segment = Segment {
            p_type: elf::PT_LOAD,
            flags: elf::PF_R | elf::PF_X,
            vaddr: 0,
            memsz: size,
            offset: 0,
            filesz: size,
        };
        Image {
            data,
            ptr_size,
            big_endian: false,
            machine,
            segments: vec![segment],
            sections: Vec::new(),
        }
    }

    fn put(data: &mut [u8], at: u64, bytes: &[u8]) {
        let at = at as usize;
        data[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn assemble(data: &mut [u8], at: u64, code: &[(u32, &str)]) {
        for (i, (word, _)) in code.iter().enumerate() {
            put(data, at + 4 * i as u64, &word.to_le_bytes());
        }
    }

    fn assemble_thumb(data: &mut [u8], at: u64, code: &[(u16, &str)]) {
        for (i, (half, _)) in code.iter().enumerate() {
            put(data, at + 2 * i as u64, &half.to_le_bytes());
        }
    }

    fn assemble_bytes(data: &mut [u8], mut at: u64, code: &[(&[u8], &str)]) {
        for (bytes, _) in code {
            put(data, at, bytes);
            at += bytes.len() as u64;
        }
    }

    fn strings(data: &mut [u8]) {
        put(data, 0x2000, b"com/foo/Bar\0");
        put(data, 0x2010, b"run\0");
        put(data, 0x2018, b"()V\0");
        put(data, 0x2020, b"hello\0");
    }

    fn jni_entry(address: u64, thumb: bool) -> Entry {
        entry(address, thumb, ORIGIN_JNI_STATIC, Val::Env)
    }

    fn analyze(ctx: &Ctx, address: u64, thumb: bool) -> Analyzed {
        let entry = jni_entry(address, thumb);
        analyze_function(ctx, &entry, DEFAULT_DISASM_MAX_INSNS)
    }

    fn options(depth: u8, max_insns: usize) -> DisasmOptions {
        DisasmOptions { depth, max_insns }
    }

    fn jni_names(function: &DisasmFunction) -> Vec<(&'static str, usize, bool)> {
        let mut names = Vec::new();
        for call in &function.jni_calls {
            names.push((call.name, call.index, call.resolved));
        }
        names
    }

    fn string_values(function: &DisasmFunction) -> Vec<(&str, &str)> {
        let mut values = Vec::new();
        for r in &function.string_refs {
            values.push((r.address.as_str(), r.value.as_str()));
        }
        values
    }

    fn member(class: &str, name: &str, signature: &str, fn_address: Option<u64>) -> JavaMember {
        JavaMember {
            class: class.to_string(),
            name: name.to_string(),
            signature: signature.to_string(),
            fn_address,
        }
    }

    fn keys(value: &serde_json::Value) -> Vec<String> {
        let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        keys
    }

    #[test]
    fn jni_table_follows_jni_h() {
        let table = jni::JNI_NATIVE_INTERFACE;
        assert_eq!(table.len(), 233);
        let reserved = ["reserved0", "reserved1", "reserved2", "reserved3"];
        assert_eq!(&table[..4], reserved);
        for (index, name) in [
            (4, "GetVersion"),
            (jni::FIND_CLASS, "FindClass"),
            (jni::NEW_GLOBAL_REF, "NewGlobalRef"),
            (jni::NEW_LOCAL_REF, "NewLocalRef"),
            (jni::GET_METHOD_ID, "GetMethodID"),
            (jni::GET_FIELD_ID, "GetFieldID"),
            (jni::GET_STATIC_METHOD_ID, "GetStaticMethodID"),
            (jni::GET_STATIC_FIELD_ID, "GetStaticFieldID"),
            (167, "NewStringUTF"),
            (jni::REGISTER_NATIVES, "RegisterNatives"),
            (219, "GetJavaVM"),
            (jni::NEW_WEAK_GLOBAL_REF, "NewWeakGlobalRef"),
            (232, "GetObjectRefType"),
        ] {
            assert_eq!(table[index], name, "{index}");
        }
        let invoke = jni::JNI_INVOKE_INTERFACE;
        assert_eq!(&invoke[..jni::INVOKE_RESERVED_SLOTS], &reserved[..3]);
        for (index, name) in [
            (3, "DestroyJavaVM"),
            (jni::INVOKE_ATTACH_CURRENT_THREAD, "AttachCurrentThread"),
            (5, "DetachCurrentThread"),
            (jni::INVOKE_GET_ENV, "GetEnv"),
            (
                jni::INVOKE_ATTACH_CURRENT_THREAD_AS_DAEMON,
                "AttachCurrentThreadAsDaemon",
            ),
        ] {
            assert_eq!(invoke[index], name, "{index}");
        }
    }

    #[test]
    fn cxx_wrapper_symbols_name_their_table_entry() {
        let find_class = cxx_wrapper("_ZN7_JNIEnv9FindClassEPKc");
        assert_eq!(find_class, Some(Wrapper::Env("FindClass", jni::FIND_CLASS)));
        let register = "_ZN7_JNIEnv15RegisterNativesEP7_jclassPK15JNINativeMethodi";
        let expected = Wrapper::Env("RegisterNatives", jni::REGISTER_NATIVES);
        assert_eq!(cxx_wrapper(register), Some(expected));
        let get_env = cxx_wrapper("_ZN7_JavaVM6GetEnvEPPvi");
        assert_eq!(get_env, Some(Wrapper::Vm("GetEnv", jni::INVOKE_GET_ENV)));
        for symbol in [
            "_ZN7_JNIEnv9reserved0EPv",
            "_ZN7_JNIEnv8FindClasEPKc",
            "_ZN7_JNIEnv99FindClassEPKc",
            "_ZN7_JNIEnvFindClassEPKc",
            "_ZN7_JavaVM9FindClassEPKc",
            "_ZN6Helper9FindClassEPKc",
        ] {
            assert_eq!(cxx_wrapper(symbol), None, "{symbol}");
        }
    }

    #[test]
    fn aarch64_jnienv_calls_are_named_with_their_strings() {
        let mut data = vec![0u8; 0x3000];
        strings(&mut data);
        assemble(&mut data, CODE, A64_JNI);
        let ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        let out = analyze(&ctx, CODE, false);
        let f = &out.function;
        assert_eq!(f.disasm_status, STATUS_OK);
        assert_eq!(f.instructions.len(), A64_JNI.len());
        let expected = [
            ("FindClass", 6, true),
            ("GetMethodID", 33, true),
            ("NewStringUTF", 167, true),
        ];
        assert_eq!(jni_names(f), expected);
        assert_eq!(f.jni_calls[0].class.as_deref(), Some("Lcom/foo/Bar;"));
        let get = &f.jni_calls[1];
        assert_eq!(get.class.as_deref(), Some("Lcom/foo/Bar;"));
        assert_eq!(get.method.as_deref(), Some("run"));
        assert_eq!(get.signature.as_deref(), Some("()V"));
        assert_eq!(out.upcalls, [member("Lcom/foo/Bar;", "run", "()V", None)]);
        let refs = [
            ("0x1010", "com/foo/Bar"),
            ("0x102c", "run"),
            ("0x1034", "()V"),
            ("0x1050", "hello"),
        ];
        assert_eq!(string_values(f), refs);
    }

    #[test]
    fn thumb_literal_and_add_pc_form_a_string_ref() {
        let mut data = vec![0u8; 0x3000];
        strings(&mut data);
        assemble_thumb(&mut data, CODE, THUMB_JNI);
        put(&mut data, 0x1014, &0xff6u32.to_le_bytes());
        let ctx = Ctx::new(image(&data, elf::EM_ARM, 4));
        let out = analyze(&ctx, CODE, true);
        let f = &out.function;
        assert_eq!(f.disasm_status, STATUS_OK);
        assert_eq!(f.instructions.len(), 9);
        assert_eq!(jni_names(f), [("FindClass", 6, true)]);
        assert_eq!(f.jni_calls[0].class.as_deref(), Some("Lcom/foo/Bar;"));
        assert_eq!(string_values(f), [("0x1006", "com/foo/Bar")]);
    }

    #[test]
    fn x86_64_jnienv_calls_through_memory_operands() {
        let mut data = vec![0u8; 0x3000];
        strings(&mut data);
        assemble_bytes(&mut data, CODE, X64_JNI);
        let ctx = Ctx::new(image(&data, elf::EM_X86_64, 8));
        let out = analyze(&ctx, CODE, false);
        let f = &out.function;
        assert_eq!(f.instructions.len(), X64_JNI.len());
        let expected = [("FindClass", 6, true), ("NewStringUTF", 167, true)];
        assert_eq!(jni_names(f), expected);
        assert_eq!(f.jni_calls[0].class.as_deref(), Some("Lcom/foo/Bar;"));
        let refs = [("0x1007", "com/foo/Bar"), ("0x1017", "hello")];
        assert_eq!(string_values(f), refs);
    }

    fn ambiguous(java: &str, elf: &ElfReport, candidates: &[String]) -> Binding {
        Binding::found(
            java,
            STATUS_AMBIGUOUS,
            elf,
            "0x1100".to_string(),
            candidates.to_vec(),
        )
    }

    #[test]
    fn registernatives_after_findclass_lifts_an_ambiguous_binding() {
        let mut data = vec![0u8; 0x3000];
        strings(&mut data);
        assemble(&mut data, CODE, A64_REGISTER);
        for (i, value) in [0x2010u64, 0x2018, 0x1100].into_iter().enumerate() {
            put(&mut data, 0x2040 + 8 * i as u64, &value.to_le_bytes());
        }
        put(&mut data, 0x1100, &0xd65f03c0u32.to_le_bytes());
        let ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        let out = analyze(&ctx, CODE, false);
        let expected = [("FindClass", 6, true), ("RegisterNatives", 215, true)];
        assert_eq!(jni_names(&out.function), expected);
        let class = out.function.jni_calls[1].class.as_deref();
        assert_eq!(class, Some("Lcom/foo/Bar;"));
        let run = member("Lcom/foo/Bar;", "run", "()V", Some(0x1100));
        assert_eq!(out.registered, std::slice::from_ref(&run));

        let mut elf = ElfReport::new("lib/arm64-v8a/libx.so", &[]);
        let disasm = ElfDisasm {
            registered_by_code: vec![run],
            ..ElfDisasm::default()
        };
        elf.disasm = Some(disasm);
        let candidates = [
            "Lcom/foo/Bar;->run()V".to_string(),
            "Lcom/other/Baz;->run()V".to_string(),
        ];
        let mut rows = [
            ambiguous("Lcom/foo/Bar;->run()V", &elf, &candidates),
            ambiguous("Lcom/other/Baz;->run()V", &elf, &candidates),
            Binding::unbound("Lcom/foo/Bar;->gone()V".to_string()),
        ];
        disambiguate(&[elf], &mut rows);
        for row in &rows[..2] {
            assert_eq!(row.status, STATUS_AMBIGUOUS);
            assert_eq!(row.disambiguated_by, Some(DISAMBIGUATED_BY_FIND_CLASS));
            assert_eq!(row.class.as_deref(), Some("Lcom/foo/Bar;"));
        }
        assert_eq!(rows[2].disambiguated_by, None);
        assert_eq!(rows[2].class, None);
    }

    #[test]
    fn plt_call_resolves_its_jump_slot_import() {
        let mut data = vec![0u8; 0x4000];
        assemble(&mut data, CODE, A64_CALLS_PLT);
        assemble(&mut data, 0x1800, A64_PLT);
        // Elf64_Rela { r_offset 0x3000, r_info (1 << 32) | R_AARCH64_JUMP_SLOT }
        put(&mut data, 0x2800, &0x3000u64.to_le_bytes());
        let info = (1u64 << 32) | u64::from(elf::R_AARCH64_JUMP_SLOT);
        put(&mut data, 0x2808, &info.to_le_bytes());
        // Symbole dynamique 1 : st_name = 1 dans "\0dlopen\0".
        put(&mut data, 0x2918, &1u32.to_le_bytes());
        put(&mut data, 0x2a00, b"\0dlopen\0");
        let dynamic = [
            (u64::from(elf::DT_JMPREL), 0x2800),
            (u64::from(elf::DT_PLTRELSZ), 24),
            (u64::from(elf::DT_PLTREL), u64::from(elf::DT_RELA)),
            (u64::from(elf::DT_SYMTAB), 0x2900),
            (u64::from(elf::DT_STRTAB), 0x2a00),
            (u64::from(elf::DT_SYMENT), 24),
        ];
        let mut ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        ctx.got = got_imports(&ctx.image, &dynamic);
        assert_eq!(ctx.got.get(&0x3000).map(String::as_str), Some("dlopen"));

        let out = analyze(&ctx, CODE, false);
        let plt = DisasmCall {
            target: Some("0x1800".to_string()),
            import: Some("dlopen".to_string()),
            symbol: None,
            kind: CALL_PLT,
        };
        assert_eq!(out.function.calls, [plt]);
        assert!(out.callees.is_empty());

        let entries = vec![jni_entry(CODE, false)];
        let disasm = walk_functions(&ctx, entries, &DisasmOptions::default());
        let dynload = disasm.imports_called.get("dynload").cloned();
        assert_eq!(dynload.unwrap_or_default(), ["dlopen"]);
    }

    #[test]
    fn recursive_descent_follows_branches_and_depth_adds_callees() {
        let mut data = vec![0u8; 0x2000];
        assemble(&mut data, CODE, A64_BRANCHES);
        put(&mut data, 0x1100, &0xd65f03c0u32.to_le_bytes());
        let ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        let out = analyze(&ctx, CODE, false);
        assert_eq!(out.function.instructions.len(), A64_BRANCHES.len());
        assert_eq!(out.function.disasm_status, STATUS_OK);
        assert!(!out.function.truncated);

        let entries = vec![jni_entry(CODE, false)];
        let shallow = walk_functions(&ctx, entries.clone(), &options(0, 100));
        assert_eq!(shallow.functions.len(), 1);
        let deep = walk_functions(&ctx, entries, &options(1, 100));
        let mut origins = Vec::new();
        for f in &deep.functions {
            origins.push((f.address.as_str(), f.origin));
        }
        let expected = [("0x1000", ORIGIN_JNI_STATIC), ("0x1100", ORIGIN_CALLEE)];
        assert_eq!(origins, expected);
    }

    #[test]
    fn max_insns_truncates_the_function() {
        let mut data = vec![0u8; 0x2000];
        assemble(&mut data, CODE, A64_BRANCHES);
        let ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        let out = analyze_function(&ctx, &jni_entry(CODE, false), 2);
        assert_eq!(out.function.instructions.len(), 2);
        assert!(out.function.truncated);
        assert_eq!(out.function.disasm_status, STATUS_TRUNCATED);
        assert_eq!(out.function.truncated_reason, Some(REASON_MAX_INSNS));
        assert!(out.function.invalid_paths.is_empty());
        let at = out.function.truncated_at.map(|at| at.address);
        assert_eq!(at.as_deref(), Some("0x1008"));
    }

    #[test]
    fn unsupported_machine_and_bad_entry_do_not_fail() {
        let data = vec![0u8; 0x2000];
        let ctx = Ctx::new(image(&data, elf::EM_MIPS, 4));
        let out = analyze(&ctx, CODE, false);
        assert_eq!(out.function.disasm_status, STATUS_ARCH_UNSUPPORTED);
        assert!(out.function.instructions.is_empty());

        let ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        let out = analyze(&ctx, 0x5000, false);
        assert_eq!(out.function.disasm_status, STATUS_INVALID_ENTRY);
        assert!(out.function.instructions.is_empty());
    }

    #[test]
    fn json_field_names_follow_the_contract() {
        let mut data = vec![0u8; 0x3000];
        strings(&mut data);
        assemble(&mut data, CODE, A64_JNI);
        let ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        let entries = vec![jni_entry(CODE, false)];
        let disasm = walk_functions(&ctx, entries, &DisasmOptions::default());
        let json = serde_json::to_value(&disasm).unwrap();
        let top = [
            "functions",
            "imports_called",
            "invalid_paths_count",
            "registered_by_code",
            "upcalls",
        ];
        assert_eq!(keys(&json), top);
        let function = &json["functions"][0];
        let fields = [
            "address",
            "calls",
            "disasm_status",
            "instructions",
            "invalid_paths",
            "jni_calls",
            "origin",
            "string_refs",
            "syscalls",
            "truncated",
            "truncated_reason",
        ];
        assert_eq!(keys(function), fields);
        let call = ["import", "kind", "symbol", "target"];
        assert_eq!(keys(&function["calls"][0]), call);
        let find_class = ["class", "form", "index", "name", "resolved"];
        assert_eq!(keys(&function["jni_calls"][0]), find_class);
        let get_method_id = [
            "class",
            "form",
            "index",
            "method",
            "name",
            "resolved",
            "signature",
        ];
        assert_eq!(keys(&function["jni_calls"][1]), get_method_id);
        assert_eq!(keys(&json["upcalls"][0]), ["class", "name", "signature"]);
        let refs = ["address", "encoding", "target", "value"];
        assert_eq!(keys(&function["string_refs"][0]), refs);
        let insn = ["address", "bytes", "mnemonic", "operands"];
        assert_eq!(keys(&function["instructions"][0]), insn);

        let mut elf = ElfReport::new("lib/arm64-v8a/libx.so", &[]);
        assert!(serde_json::to_value(&elf).unwrap().get("disasm").is_none());
        elf.disasm = Some(disasm);
        assert!(serde_json::to_value(elf).unwrap().get("disasm").is_some());

        let mut row = Binding::unbound("Lcom/a/B;->c()V".to_string());
        let plain = serde_json::to_value(&row).unwrap();
        assert!(plain.get("disambiguated_by").is_none());
        assert!(plain.get("class").is_none());
        row.disambiguated_by = Some(DISAMBIGUATED_BY_FIND_CLASS);
        row.class = Some("Lcom/a/B;".to_string());
        let lifted = serde_json::to_value(row).unwrap();
        assert_eq!(lifted["disambiguated_by"], "find_class");
        assert_eq!(lifted["class"], "Lcom/a/B;");
    }

    /// Une relocation JUMP_SLOT en 0x2800 vers le symbole dynamique 1, nommé
    /// `name` ; rend la table dynamique qui les décrit.
    fn jump_slot(data: &mut [u8], slot: u64, name: &str, arm: bool) -> [(u64, u64); 6] {
        put(data, 0x2a01, name.as_bytes());
        let (pltrel, size, syment) = if arm {
            put(data, 0x2800, &(slot as u32).to_le_bytes());
            let info = (1u32 << 8) | elf::R_ARM_JUMP_SLOT;
            put(data, 0x2804, &info.to_le_bytes());
            put(data, 0x2910, &1u32.to_le_bytes());
            (elf::DT_REL, 8, 16)
        } else {
            put(data, 0x2800, &slot.to_le_bytes());
            let info = (1u64 << 32) | u64::from(elf::R_AARCH64_JUMP_SLOT);
            put(data, 0x2808, &info.to_le_bytes());
            put(data, 0x2918, &1u32.to_le_bytes());
            (elf::DT_RELA, 24, 24)
        };
        [
            (u64::from(elf::DT_JMPREL), 0x2800),
            (u64::from(elf::DT_PLTRELSZ), size),
            (u64::from(elf::DT_PLTREL), u64::from(pltrel)),
            (u64::from(elf::DT_SYMTAB), 0x2900),
            (u64::from(elf::DT_STRTAB), 0x2a00),
            (u64::from(elf::DT_SYMENT), syment),
        ]
    }

    /// AArch64 : la branche mène à un appel sans retour, suivi d'une voisine.
    const A64_NORETURN: &[(u32, &str)] = &[
        (0xb4000040, "1000  cbz  x0, 0x1008"),
        (0xd65f03c0, "1004  ret"),
        (0x940001fe, "1008  bl   0x1800  ; __stack_chk_fail@plt"),
        (0xd2800020, "100c  mov  x0, #1  ; fonction voisine"),
        (0xd65f03c0, "1010  ret"),
    ];

    /// 0x1100 n'appelle qu'un import sans retour.
    const A64_NORETURN_CHAIN: &[(u32, &str)] = &[
        (0x940001c0, "1100  bl   0x1800"),
        (0xd2800020, "1104  mov  x0, #1"),
    ];

    const A64_CALLS_NORETURN: &[(u32, &str)] = &[
        (0x97ffffc0, "1200  bl   0x1100"),
        (0xd2800020, "1204  mov  x0, #1"),
        (0xd65f03c0, "1208  ret"),
    ];

    #[test]
    fn a_call_to_a_noreturn_import_ends_the_path() {
        let mut data = vec![0u8; 0x4000];
        assemble(&mut data, CODE, A64_NORETURN);
        assemble(&mut data, 0x1800, A64_PLT);
        let dynamic = jump_slot(&mut data, 0x3000, "__stack_chk_fail", false);
        let mut ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        ctx.got = got_imports(&ctx.image, &dynamic);
        let out = analyze(&ctx, CODE, false);
        let f = &out.function;
        assert_eq!(f.instructions.len(), 3);
        assert_eq!((f.disasm_status, f.truncated), (STATUS_OK, false));
        assert_eq!(f.calls[0].import.as_deref(), Some("__stack_chk_fail"));
    }

    #[test]
    fn a_known_noreturn_function_ends_the_path_of_its_callers() {
        let mut data = vec![0u8; 0x4000];
        assemble(&mut data, 0x1100, A64_NORETURN_CHAIN);
        assemble(&mut data, 0x1200, A64_CALLS_NORETURN);
        assemble(&mut data, 0x1800, A64_PLT);
        let dynamic = jump_slot(&mut data, 0x3000, "abort", false);
        let mut ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        ctx.got = got_imports(&ctx.image, &dynamic);
        // 0x1100 pas encore vue : rien n'est supposé.
        let unknown = analyze(&ctx, 0x1200, false);
        assert_eq!(unknown.function.instructions.len(), 3);
        let callee = analyze(&ctx, 0x1100, false);
        assert_eq!(callee.function.instructions.len(), 1);
        let caller = analyze(&ctx, 0x1200, false);
        assert_eq!(caller.function.instructions.len(), 1);
        assert_eq!(caller.function.disasm_status, STATUS_OK);
    }

    /// Entrée PLT ARM de libbash.so (armeabi-v7a, .plt + 0x20), déplacée en
    /// 0x1800 : GOT = 0x1808 + 0x1000 + 0xc84 = 0x348c.
    const ARM_PLT: &[(u32, &str)] = &[
        (0xe28fc600, "1800  add  ip, pc, #0, 12"),
        (0xe28cca01, "1804  add  ip, ip, #1, 20"),
        (0xe5bcfc84, "1808  ldr  pc, [ip, #0xc84]!"),
        (0xd4d4d4d4, "180c  remplissage"),
    ];

    const ARM_CALLS_PLT: &[(u32, &str)] = &[
        (0xeb0001fe, "1000  bl   0x1800"),
        (0xe12fff1e, "1004  bx   lr"),
    ];

    /// blx 0x1800 depuis 0x1100 : cible ARM = Align(0x1104, 4) + 0x6fc.
    const THUMB_CALLS_PLT: &[(u16, &str)] = &[
        (0xf000, "1100  blx  0x1800"),
        (0xeb7e, ""),
        (0x4770, "1104  bx   lr"),
    ];

    #[test]
    fn arm_plt_entry_resolves_its_jump_slot_from_arm_and_thumb() {
        let mut data = vec![0u8; 0x4000];
        assemble(&mut data, CODE, ARM_CALLS_PLT);
        assemble_thumb(&mut data, 0x1100, THUMB_CALLS_PLT);
        assemble(&mut data, 0x1800, ARM_PLT);
        let dynamic = jump_slot(&mut data, 0x348c, "dlopen", true);
        let mut ctx = Ctx::new(image(&data, elf::EM_ARM, 4));
        ctx.got = got_imports(&ctx.image, &dynamic);
        let plt = DisasmCall {
            target: Some("0x1800".to_string()),
            import: Some("dlopen".to_string()),
            symbol: None,
            kind: CALL_PLT,
        };
        let expected = std::slice::from_ref(&plt);
        for (address, thumb) in [(CODE, false), (0x1100, true)] {
            let out = analyze(&ctx, address, thumb);
            assert_eq!(out.function.calls, expected, "{address:#x}");
            assert!(out.callees.is_empty(), "{address:#x}");
        }
    }

    /// Point d'entrée ARM d'un exécutable : main (0x1100) par ldr littéral en r2,
    /// puis __libc_init par la PLT.
    const ARM_LIBC_INIT: &[(u32, &str)] = &[
        (0xe59f2004, "1000  ldr  r2, [pc, #4]   ; 0x100c"),
        (0xeb0001fd, "1004  bl   0x1800         ; __libc_init@plt"),
        (0xe12fff1e, "1008  bx   lr"),
        (0x00001100, "100c  littéral : main"),
    ];

    /// r2 jamais écrit avant l'appel.
    const ARM_LIBC_INIT_UNKNOWN: &[(u32, &str)] = &[
        (0xeb0001fe, "1000  bl   0x1800         ; __libc_init@plt"),
        (0xe12fff1e, "1004  bx   lr"),
    ];

    /// Point d'entrée AArch64 : main (0x2100) par adrp + add en x2.
    const A64_LIBC_INIT: &[(u32, &str)] = &[
        (0xb0000002, "1000  adrp x2, 0x2000"),
        (0x91040042, "1004  add  x2, x2, #0x100"),
        (0x940001fe, "1008  bl   0x1800         ; __libc_init@plt"),
        (0xd65f03c0, "100c  ret"),
    ];

    fn exec_entry(address: u64) -> Entry {
        entry(address, false, ORIGIN_ENTRY, Val::Opaque(0))
    }

    fn origins(disasm: &ElfDisasm) -> Vec<(&str, &'static str, &'static str)> {
        let mut origins = Vec::new();
        for f in &disasm.functions {
            origins.push((f.address.as_str(), f.origin, f.disasm_status));
        }
        origins
    }

    #[test]
    fn arm_libc_init_adds_main_from_its_third_argument() {
        let mut data = vec![0u8; 0x4000];
        assemble(&mut data, CODE, ARM_LIBC_INIT);
        put(&mut data, 0x1100, &0xe12fff1eu32.to_le_bytes());
        assemble(&mut data, 0x1800, ARM_PLT);
        let dynamic = jump_slot(&mut data, 0x348c, "__libc_init", true);
        let mut ctx = Ctx::new(image(&data, elf::EM_ARM, 4));
        ctx.got = got_imports(&ctx.image, &dynamic);
        let disasm = walk_functions(&ctx, vec![exec_entry(CODE)], &options(0, 100));
        let expected = [
            ("0x1000", ORIGIN_ENTRY, STATUS_OK),
            ("0x1100", ORIGIN_MAIN, STATUS_OK),
        ];
        assert_eq!(origins(&disasm), expected);
        let import = disasm.functions[0].calls[0].import.as_deref();
        assert_eq!(import, Some("__libc_init"));
    }

    #[test]
    fn aarch64_libc_init_adds_main_from_x2() {
        let mut data = vec![0u8; 0x4000];
        assemble(&mut data, CODE, A64_LIBC_INIT);
        put(&mut data, 0x2100, &0xd65f03c0u32.to_le_bytes());
        assemble(&mut data, 0x1800, A64_PLT);
        let dynamic = jump_slot(&mut data, 0x3000, "__libc_init", false);
        let mut ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        ctx.got = got_imports(&ctx.image, &dynamic);
        let disasm = walk_functions(&ctx, vec![exec_entry(CODE)], &options(0, 100));
        let expected = [
            ("0x1000", ORIGIN_ENTRY, STATUS_OK),
            ("0x2100", ORIGIN_MAIN, STATUS_OK),
        ];
        assert_eq!(origins(&disasm), expected);
    }

    #[test]
    fn an_unknown_main_adds_no_function() {
        let mut data = vec![0u8; 0x4000];
        assemble(&mut data, CODE, ARM_LIBC_INIT_UNKNOWN);
        assemble(&mut data, 0x1800, ARM_PLT);
        let dynamic = jump_slot(&mut data, 0x348c, "__libc_init", true);
        let mut ctx = Ctx::new(image(&data, elf::EM_ARM, 4));
        ctx.got = got_imports(&ctx.image, &dynamic);
        let disasm = walk_functions(&ctx, vec![exec_entry(CODE)], &options(0, 100));
        assert_eq!(origins(&disasm), [("0x1000", ORIGIN_ENTRY, STATUS_OK)]);
        let import = disasm.functions[0].calls[0].import.as_deref();
        assert_eq!(import, Some("__libc_init"));
    }

    /// AArch64 : FindClass par le wrapper C++ de jni.h, appelé par sa PLT.
    const A64_CXX_FIND_CLASS: &[(u32, &str)] = &[
        (0xb0000001, "1000  adrp x1, 0x2000"),
        (0x91000021, "1004  add  x1, x1, #0x0      ; com/foo/Bar"),
        (
            0x940001fe,
            "1008  bl   0x1800            ; _JNIEnv::FindClass@plt",
        ),
        (0xd65f03c0, "100c  ret"),
    ];

    #[test]
    fn a_cxx_findclass_wrapper_through_the_plt_is_a_jni_call() {
        let mut data = vec![0u8; 0x4000];
        strings(&mut data);
        assemble(&mut data, CODE, A64_CXX_FIND_CLASS);
        assemble(&mut data, 0x1800, A64_PLT);
        let dynamic = jump_slot(&mut data, 0x3000, "_ZN7_JNIEnv9FindClassEPKc", false);
        let mut ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        ctx.got = got_imports(&ctx.image, &dynamic);
        let out = analyze(&ctx, CODE, false);
        let f = &out.function;
        let import = f.calls[0].import.as_deref();
        assert_eq!(import, Some("_ZN7_JNIEnv9FindClassEPKc"));
        assert_eq!(jni_names(f), [("FindClass", jni::FIND_CLASS, true)]);
        let call = &f.jni_calls[0];
        assert_eq!(call.form, FORM_CXX_WRAPPER);
        assert_eq!(call.unresolved_reason, None);
        assert_eq!(call.class.as_deref(), Some("Lcom/foo/Bar;"));
    }

    /// FindClass par la table, puis RegisterNatives par son wrapper C++ (PLT).
    /// Table JNINativeMethod en 0x2040.
    const A64_CXX_REGISTER: &[(u32, &str)] = &[
        (0xaa0003f3, "1000  mov  x19, x0"),
        (0xf9400268, "1004  ldr  x8, [x19]"),
        (0xf9401908, "1008  ldr  x8, [x8, #0x30]   ; FindClass"),
        (0xb0000001, "100c  adrp x1, 0x2000"),
        (0x91000021, "1010  add  x1, x1, #0x0      ; com/foo/Bar"),
        (0xaa1303e0, "1014  mov  x0, x19"),
        (0xd63f0100, "1018  blr  x8"),
        (0xaa0003e1, "101c  mov  x1, x0            ; jclass"),
        (0xb0000002, "1020  adrp x2, 0x2000"),
        (0x91010042, "1024  add  x2, x2, #0x40     ; table"),
        (0x52800023, "1028  mov  w3, #1"),
        (0xaa1303e0, "102c  mov  x0, x19"),
        (
            0x940001f4,
            "1030  bl   0x1800            ; _JNIEnv::RegisterNatives@plt",
        ),
        (0xd65f03c0, "1034  ret"),
    ];

    #[test]
    fn a_cxx_registernatives_wrapper_registers_its_table() {
        let mut data = vec![0u8; 0x4000];
        strings(&mut data);
        assemble(&mut data, CODE, A64_CXX_REGISTER);
        assemble(&mut data, 0x1800, A64_PLT);
        for (i, value) in [0x2010u64, 0x2018, 0x1100].into_iter().enumerate() {
            put(&mut data, 0x2040 + 8 * i as u64, &value.to_le_bytes());
        }
        put(&mut data, 0x1100, &0xd65f03c0u32.to_le_bytes());
        let symbol = "_ZN7_JNIEnv15RegisterNativesEP7_jclassPK15JNINativeMethodi";
        let dynamic = jump_slot(&mut data, 0x3000, symbol, false);
        let mut ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        ctx.got = got_imports(&ctx.image, &dynamic);
        let out = analyze(&ctx, CODE, false);
        let expected = [("FindClass", 6, true), ("RegisterNatives", 215, true)];
        assert_eq!(jni_names(&out.function), expected);
        let mut forms = Vec::new();
        for call in &out.function.jni_calls {
            forms.push(call.form);
        }
        assert_eq!(forms, [FORM_VTABLE, FORM_CXX_WRAPPER]);
        let run = member("Lcom/foo/Bar;", "run", "()V", Some(0x1100));
        assert_eq!(out.registered, [run]);
    }

    /// AArch64 : le nom de classe passe par la pile avant FindClass.
    const A64_STACK_FIND_CLASS: &[(u32, &str)] = &[
        (0xd10083ff, "1000  sub  sp, sp, #0x20"),
        (0xaa0003f3, "1004  mov  x19, x0"),
        (0xb0000008, "1008  adrp x8, 0x2000"),
        (0x91000108, "100c  add  x8, x8, #0x0      ; com/foo/Bar"),
        (0xf90007e8, "1010  str  x8, [sp, #8]"),
        (0xf9400268, "1014  ldr  x8, [x19]"),
        (0xf9401908, "1018  ldr  x8, [x8, #0x30]   ; FindClass"),
        (0xf94007e1, "101c  ldr  x1, [sp, #8]"),
        (0xaa1303e0, "1020  mov  x0, x19"),
        (0xd63f0100, "1024  blr  x8"),
        (0x910083ff, "1028  add  sp, sp, #0x20"),
        (0xd65f03c0, "102c  ret"),
    ];

    #[test]
    fn a_class_name_spilled_to_the_stack_still_resolves_findclass() {
        let mut data = vec![0u8; 0x3000];
        strings(&mut data);
        assemble(&mut data, CODE, A64_STACK_FIND_CLASS);
        let ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        let out = analyze(&ctx, CODE, false);
        let f = &out.function;
        assert_eq!(f.instructions.len(), A64_STACK_FIND_CLASS.len());
        assert_eq!(jni_names(f), [("FindClass", jni::FIND_CLASS, true)]);
        assert_eq!(f.jni_calls[0].form, FORM_VTABLE);
        assert_eq!(f.jni_calls[0].class.as_deref(), Some("Lcom/foo/Bar;"));
    }

    /// AArch64 : FindClass dont le nom est un paramètre (x1 jamais écrit).
    const A64_PARAM_FIND_CLASS: &[(u32, &str)] = &[
        (0xf9400008, "1000  ldr  x8, [x0]"),
        (0xf9401908, "1004  ldr  x8, [x8, #0x30]   ; FindClass"),
        (0xd63f0100, "1008  blr  x8"),
        (0xd65f03c0, "100c  ret"),
    ];

    #[test]
    fn an_unknown_class_name_leaves_findclass_unresolved_with_its_reason() {
        let mut data = vec![0u8; 0x2000];
        assemble(&mut data, CODE, A64_PARAM_FIND_CLASS);
        let ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        let out = analyze(&ctx, CODE, false);
        let call = &out.function.jni_calls[0];
        assert_eq!((call.name, call.resolved), ("FindClass", false));
        assert_eq!(call.unresolved_reason, Some(UNRESOLVED_CLASS));
        assert_eq!(call.class, None);
    }

    /// ARM : ubfx et uxtb, que yaxpeax-arm 0.5.0 refuse.
    const ARM_MEDIA: &[(u32, &str)] = &[
        (0xe7e000d0, "1000  ubfx r0, r0, #1, #1"),
        (0xe6ef2078, "1004  uxtb r2, r8"),
        (0xe12fff1e, "1008  bx   lr"),
    ];

    #[test]
    fn arm_media_instructions_do_not_cut_a_function() {
        let mut data = vec![0u8; 0x2000];
        assemble(&mut data, CODE, ARM_MEDIA);
        let ctx = Ctx::new(image(&data, elf::EM_ARM, 4));
        let function = analyze(&ctx, CODE, false).function;
        assert_eq!(function.disasm_status, STATUS_OK);
        assert!(function.invalid_paths.is_empty());
        let mut mnemonics = Vec::new();
        for insn in &function.instructions {
            mnemonics.push(insn.mnemonic.as_str());
        }
        assert_eq!(mnemonics, ["ubfx", "uxtb", "bx"]);
        let three = [function.clone(), function.clone(), function];
        assert_eq!(opaque_dead_code(&three), None);
    }

    const A64_CALLS_ZERO: &[(u32, &str)] =
        &[(0x97fffc00, "1000  bl   0x0"), (0xd65f03c0, "1004  ret")];

    #[test]
    fn a_call_to_address_zero_is_unresolved_and_creates_no_callee() {
        let mut data = vec![0u8; 0x2000];
        assemble(&mut data, CODE, A64_CALLS_ZERO);
        let ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        let out = analyze(&ctx, CODE, false);
        let unresolved = DisasmCall {
            target: Some("0x0".to_string()),
            import: None,
            symbol: None,
            kind: CALL_UNRESOLVED,
        };
        assert_eq!(out.function.calls, [unresolved]);
        assert!(out.callees.is_empty());

        let entries = vec![jni_entry(CODE, false)];
        let disasm = walk_functions(&ctx, entries, &DisasmOptions::default());
        assert_eq!(disasm.functions.len(), 1);
        assert_eq!(disasm.functions[0].address, "0x1000");
    }

    /// Prologue et épilogue Thumb-2 de libbash.so (armeabi-v7a), le bl visant
    /// 0x1100. Les deux demi-mots qui suivent le pop sont un littéral.
    const THUMB_FRAME: &[(u16, &str)] = &[
        (0xb5f0, "1000  push   {r4-r7, lr}"),
        (0xaf03, "1002  add    r7, sp, #12"),
        (0xe92d, "1004  push.w {r8-r11}"),
        (0x0f00, ""),
        (0xb081, "1008  sub    sp, #4"),
        (0xf000, "100a  bl     0x1100"),
        (0xf879, ""),
        (0xb001, "100e  add    sp, #4"),
        (0xe8bd, "1010  pop.w  {r8-r11}"),
        (0x0f00, ""),
        (0xbdf0, "1014  pop    {r4-r7, pc}"),
        (0xffff, "1016  littéral"),
        (0xffff, ""),
    ];

    #[test]
    fn thumb2_frame_is_one_function_and_its_literal_is_not_code() {
        let mut data = vec![0u8; 0x2000];
        assemble_thumb(&mut data, CODE, THUMB_FRAME);
        put(&mut data, 0x1100, &0x4770u16.to_le_bytes());
        let ctx = Ctx::new(image(&data, elf::EM_ARM, 4));
        let out = analyze(&ctx, CODE, true);
        let f = &out.function;
        assert_eq!(f.disasm_status, STATUS_OK);
        assert_eq!(f.instructions.len(), 8);
        assert_eq!(f.instructions[7].address, "0x1014");
        assert_eq!(f.calls[0].target.as_deref(), Some("0x1100"));
        let callee = out.callees[0];
        assert_eq!((callee.address, callee.thumb), (0x1100, true));
    }

    /// vpush / vpop {d8-d9}, absents de yaxpeax-arm 0.5.0.
    const THUMB_VFP: &[(u16, &str)] = &[
        (0xb5f0, "1000  push   {r4-r7, lr}"),
        (0xed2d, "1002  vpush  {d8-d9}"),
        (0x8b04, ""),
        (0xecbd, "1006  vpop   {d8-d9}"),
        (0x8b04, ""),
        (0xbdf0, "100a  pop    {r4-r7, pc}"),
    ];

    #[test]
    fn vfp_instructions_do_not_cut_a_thumb_function() {
        let mut data = vec![0u8; 0x2000];
        assemble_thumb(&mut data, CODE, THUMB_VFP);
        let ctx = Ctx::new(image(&data, elf::EM_ARM, 4));
        let out = analyze(&ctx, CODE, true);
        let f = &out.function;
        assert_eq!(f.disasm_status, STATUS_OK);
        assert_eq!(f.instructions.len(), 4);
        assert_eq!(f.instructions[1].mnemonic, COPROCESSOR);
        assert_eq!(f.instructions[3].address, "0x100a");
    }

    #[test]
    fn an_invalid_instruction_abandons_only_its_path() {
        let mut data = vec![0u8; 0x2000];
        // 1000 je 0x1003 ; 1002 ret ; 1003 : 06, invalide en 64 bits
        put(&mut data, CODE, &[0x74, 0x01, 0xc3, 0x06]);
        let ctx = Ctx::new(image(&data, elf::EM_X86_64, 8));
        let out = analyze(&ctx, CODE, false);
        let f = &out.function;
        assert_eq!(f.instructions.len(), 2);
        assert_eq!((f.disasm_status, f.truncated), (STATUS_OK, false));
        let path = InvalidPath {
            address: "0x1003".to_string(),
            bytes: "06000000".to_string(),
            reason: REASON_INVALID_INSTRUCTION,
            reached_from: Some("0x1000".to_string()),
        };
        assert_eq!(f.invalid_paths, [path]);
    }

    /// Prédicat opaque d'un code aplati (libbash.so arm64-v8a, 0x17254) : la
    /// branche mène à un bloc mort qui finit sur des octets poubelle.
    const A64_OPAQUE: &[(u32, &str)] = &[
        (0xb4000060, "1000  cbz  x0, 0x100c"),
        (0xd2800020, "1004  mov  x0, #1"),
        (0xd65f03c0, "1008  ret"),
        (0x58ffffc1, "100c  ldr  x1, $-8"),
        (0xd63f0020, "1010  blr  x1"),
        (0xaa0103e0, "1014  mov  x0, x1"),
        (0xa2f2fff1, "1018  octets poubelle"),
    ];

    #[test]
    fn an_opaque_dead_block_leaves_the_function_complete() {
        let mut data = vec![0u8; 0x2000];
        assemble(&mut data, CODE, A64_OPAQUE);
        let ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        let out = analyze(&ctx, CODE, false);
        let f = &out.function;
        assert_eq!((f.disasm_status, f.truncated), (STATUS_OK, false));
        assert_eq!(f.truncated_at, None);
        assert_eq!(f.instructions.len(), 6);
        let path = InvalidPath {
            address: "0x1018".to_string(),
            bytes: "f1fff2a2".to_string(),
            reason: REASON_INVALID_INSTRUCTION,
            reached_from: Some("0x1000".to_string()),
        };
        assert_eq!(f.invalid_paths, [path]);
        // Le blr du bloc mort reste rattaché à la fonction.
        assert_eq!(f.calls.len(), 1);

        let entries = vec![jni_entry(CODE, false)];
        let disasm = walk_functions(&ctx, entries, &DisasmOptions::default());
        assert_eq!(disasm.invalid_paths_count, 1);
    }

    #[test]
    fn repeated_invalid_bytes_are_reported_as_opaque_dead_code() {
        let mut data = vec![0u8; 0x2000];
        assemble(&mut data, CODE, A64_OPAQUE);
        let ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        let function = analyze(&ctx, CODE, false).function;
        let two = [function.clone(), function.clone()];
        assert_eq!(opaque_dead_code(&two), None);
        let three = [function.clone(), function.clone(), function];
        let expected = "opaque_dead_code: f1fff2a2 dans 3 fonctions";
        assert_eq!(opaque_dead_code(&three).as_deref(), Some(expected));
    }

    #[test]
    fn legend_defines_every_disasm_label() {
        let legend = legend();
        let labels = [
            ORIGIN_JNI_STATIC,
            ORIGIN_JNI_REGISTERED,
            ORIGIN_JNI_ONLOAD,
            ORIGIN_JNI_ONUNLOAD,
            ORIGIN_INIT,
            ORIGIN_INIT_ARRAY,
            ORIGIN_ENTRY,
            ORIGIN_CALLEE,
            ORIGIN_MAIN,
            "__libc_init",
            "__libc_start_main",
            STATUS_TRUNCATED,
            STATUS_ARCH_UNSUPPORTED,
            STATUS_INVALID_ENTRY,
            REASON_MAX_INSNS,
            REASON_INVALID_INSTRUCTION,
            REASON_OUTSIDE_EXEC,
            REASON_PANIC,
            REASON_DECODER_PANIC,
            "truncated_at",
            "invalid_paths",
            "invalid_paths_count",
            "reached_from",
            "opaque_dead_code",
            COPROCESSOR,
            CALL_INTERNAL,
            CALL_PLT,
            CALL_INDIRECT,
            CALL_UNRESOLVED,
            FORM_VTABLE,
            FORM_CXX_WRAPPER,
            "form",
            "unresolved_reason",
            UNRESOLVED_ENV,
            UNRESOLVED_CLASS,
            UNRESOLVED_NAME,
            UNRESOLVED_SIGNATURE,
            UNRESOLVED_TABLE,
            "_ZN7_JNIEnv",
            "_ZN7_JavaVM",
            "ubfx",
            "uxtb",
            DISAMBIGUATED_BY_FIND_CLASS,
            "disambiguated_by",
            "disasm_failed",
            "truncated_reason",
            "string_refs",
            "jni_calls",
            "syscalls",
            "upcalls",
            "registered_by_code",
            "imports_called",
            jni::JNI_SOURCE,
        ];
        for label in labels.iter().chain(NORETURN_IMPORTS) {
            assert!(legend.contains(label), "{label}");
        }
        for name in &jni::JNI_INVOKE_INTERFACE[jni::INVOKE_RESERVED_SLOTS..] {
            assert!(legend.contains(name), "{name}");
        }
        assert!(legend.contains(&format!("(défaut {DEFAULT_DISASM_DEPTH})")));
        assert!(legend.contains(&format!("(défaut {DEFAULT_DISASM_MAX_INSNS})")));
    }

    #[test]
    fn class_names_become_descriptors() {
        assert_eq!(class_descriptor("com/foo/Bar"), "Lcom/foo/Bar;");
        assert_eq!(class_descriptor("Lcom/foo/Bar;"), "Lcom/foo/Bar;");
        assert_eq!(class_descriptor("[I"), "[I");
    }
}
