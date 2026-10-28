//! `--native --native-disasm` : désassemblage statique, dans chaque ELF, des
//! fonctions qui portent la frontière Java↔natif. Rien n'est exécuté ni émulé.
//! Chaque fonction est délimitée par descente récursive, puis relue une fois
//! dans l'ordre des adresses par un évaluateur de valeurs qui suit JNIEnv,
//! JavaVM, les adresses calculées et la pile. Étiquettes définies dans
//! [`super::legend`].

use std::cell::RefCell;
use std::collections::BTreeMap;

use super::*;

use super::decode::{decode, hex_bytes, Addr, Arch, Expr, Flow, Insn, Op, Via};
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

const STATUS_OK: &str = "ok";
const STATUS_TRUNCATED: &str = "truncated";
const STATUS_ARCH_UNSUPPORTED: &str = "arch_unsupported";
const STATUS_INVALID_ENTRY: &str = "invalid_entry";

const REASON_MAX_INSNS: &str = "max_insns";
const REASON_INVALID_INSTRUCTION: &str = "invalid_instruction";
const REASON_OUTSIDE_EXEC: &str = "outside_exec";
const REASON_PANIC: &str = "panic";

const CALL_INTERNAL: &str = "internal";
const CALL_PLT: &str = "plt";
const CALL_INDIRECT: &str = "indirect";

pub(super) const DISAMBIGUATED_BY_FIND_CLASS: &str = "find_class";

const MAX_STRING_BYTES: usize = 256;
const MAX_REGISTER_ENTRIES: u64 = 512;
const MAX_INIT_ARRAY: u64 = 4096;
const PLT_STUB_INSNS: usize = 6;

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
}

#[derive(Debug, Clone, Serialize)]
pub struct DisasmFunction {
    pub origin: &'static str,
    pub address: String,
    pub disasm_status: &'static str,
    pub truncated: bool,
    pub truncated_reason: Option<&'static str>,
    pub instructions: Vec<DisasmInsn>,
    pub calls: Vec<DisasmCall>,
    pub string_refs: Vec<StringRef>,
    pub jni_calls: Vec<JniCall>,
    pub syscalls: Vec<Syscall>,
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
    pub resolved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
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
            instructions: Vec::new(),
            calls: Vec::new(),
            string_refs: Vec::new(),
            jni_calls: Vec::new(),
            syscalls: Vec::new(),
        }
    }
}

/// Désassemble `bytes`, l'ELF décrit par `report`, et range le résultat dans
/// `report.disasm`. Une panique devient une anomalie, jamais un échec du mode.
pub(super) fn run(bytes: &[u8], report: &mut ElfReport, options: &DisasmOptions) {
    let job = AssertUnwindSafe(|| disassemble(bytes, report, options));
    match std::panic::catch_unwind(job) {
        Ok(disasm) => report.disasm = Some(disasm),
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

fn is_internal(ctx: &Ctx, start: u64, at: u64) -> bool {
    in_function(ctx, start, at) && plt_import(ctx, at).is_none()
}

fn plt_import(ctx: &Ctx, at: u64) -> Option<String> {
    if ctx.got.is_empty() {
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
        let insn = decode(arch, ctx.image.code_window(pc)?, pc, false)?;
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

struct Explored {
    insns: Vec<Insn>,
    targets: HashSet<u64>,
    reason: Option<&'static str>,
}

fn explore(ctx: &Ctx, arch: Arch, entry: &Entry, max_insns: usize) -> Explored {
    let mut insns: Vec<Insn> = Vec::new();
    let mut targets = HashSet::new();
    let mut seen = HashSet::new();
    let mut reason = None;
    let mut work = vec![(entry.address, entry.thumb)];
    'paths: while let Some((start, thumb)) = work.pop() {
        let mut at = start;
        while seen.insert(at) {
            if insns.len() >= max_insns {
                reason = Some(REASON_MAX_INSNS);
                break 'paths;
            }
            let Some(code) = ctx.image.code_window(at) else {
                reason = reason.or(Some(REASON_OUTSIDE_EXEC));
                break;
            };
            let Some(insn) = decode(arch, code, at, thumb) else {
                reason = reason.or(Some(REASON_INVALID_INSTRUCTION));
                break;
            };
            let next = at.wrapping_add(insn.len);
            let flow = insn.flow;
            insns.push(insn);
            match flow {
                Flow::Next | Flow::Call(..) | Flow::CallVia(_) => {}
                Flow::Branch(target, mode) => {
                    if in_function(ctx, entry.address, target) {
                        targets.insert(target);
                        work.push((target, mode));
                    }
                }
                Flow::Jump(target, mode) => {
                    if is_internal(ctx, entry.address, target) {
                        targets.insert(target);
                        work.push((target, mode));
                    }
                    break;
                }
                Flow::JumpVia(_) | Flow::Return | Flow::Stop => break,
            }
            if !in_function(ctx, entry.address, next) {
                break;
            }
            at = next;
        }
    }
    insns.sort_by_key(|insn| insn.address);
    Explored {
        insns,
        targets,
        reason,
    }
}

struct Analyzed {
    function: DisasmFunction,
    callees: Vec<Entry>,
    upcalls: Vec<JavaMember>,
    registered: Vec<JavaMember>,
}

impl Analyzed {
    fn new(entry: &Entry) -> Self {
        Analyzed {
            function: DisasmFunction::new(entry),
            callees: Vec::new(),
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
    if explored.insns.is_empty() {
        out.function.disasm_status = STATUS_INVALID_ENTRY;
        return out;
    }
    if explored.reason.is_some() {
        out.function.disasm_status = STATUS_TRUNCATED;
        out.function.truncated = true;
        out.function.truncated_reason = explored.reason;
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
            Flow::Jump(target, mode) if !is_internal(ctx, self.start, target) => {
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
        self.record_direct(target, mode, arg0);
        self.after_call(None);
        if self.arch == Arch::X86 {
            if let Some(reg) = pc_thunk(ctx, target) {
                self.machine.set(reg, Val::Const(next));
            }
        }
    }

    fn record_direct(&mut self, target: u64, mode: bool, arg0: Val) {
        let ctx = self.ctx;
        if let Some(name) = plt_import(ctx, target) {
            self.calls.push(DisasmCall {
                target: Some(hex(target)),
                import: Some(name),
                symbol: None,
                kind: CALL_PLT,
            });
            return;
        }
        let symbol = ctx.symbols.get(&target).map(|(name, _)| name.clone());
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
            None => {
                self.record_value(value, arg0, is_call);
                None
            }
        };
        if is_call {
            self.after_call(ret);
        }
    }

    fn record_value(&mut self, value: Val, arg0: Val, is_call: bool) {
        let ctx = self.ctx;
        if let Val::Mem(slot) = value {
            if let Some(name) = ctx.got.get(&slot) {
                self.calls.push(DisasmCall {
                    target: None,
                    import: Some(name.clone()),
                    symbol: None,
                    kind: CALL_PLT,
                });
                return;
            }
        }
        let arm = self.arch == Arch::Arm;
        let target = self.machine.materialize(ctx, value);
        match target.map(|t| split_thumb(arm, t)) {
            Some((address, mode)) if ctx.image.is_exec(address) => {
                self.record_direct(address, mode, arg0);
            }
            _ if is_call => self.calls.push(indirect_call()),
            _ => {}
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
    fn jni_call(&mut self, off: u64, resolved: bool) -> Option<Val> {
        let ptr = self.ctx.image.ptr_size;
        if !off.is_multiple_of(ptr) {
            return None;
        }
        let index = usize::try_from(off / ptr).ok()?;
        if index < jni::RESERVED_SLOTS {
            return None;
        }
        let name = *jni::JNI_NATIVE_INTERFACE.get(index)?;
        let mut call = JniCall {
            name,
            index,
            resolved,
            class: None,
            method: None,
            signature: None,
        };
        let mut ret = None;
        match index {
            jni::FIND_CLASS => {
                let value = self.arg(1);
                if let Some(at) = self.machine.materialize(self.ctx, value) {
                    if let Some(name) = utf8_at(self.ctx, at) {
                        call.class = Some(class_descriptor(&name));
                        ret = Some(Val::Class(at));
                    }
                }
            }
            jni::GET_METHOD_ID
            | jni::GET_STATIC_METHOD_ID
            | jni::GET_FIELD_ID
            | jni::GET_STATIC_FIELD_ID => {
                call.class = self.class_arg(1);
                call.method = self.string_arg(2);
                call.signature = self.string_arg(3);
                if let Some(member) = upcall(&call) {
                    self.out.upcalls.push(member);
                }
            }
            jni::REGISTER_NATIVES => {
                call.class = self.class_arg(1);
                if let Some(class) = call.class.clone() {
                    self.registered_by_code(&class);
                }
            }
            jni::NEW_GLOBAL_REF | jni::NEW_LOCAL_REF | jni::NEW_WEAK_GLOBAL_REF => {
                if let Val::Class(at) = self.arg(1) {
                    ret = Some(Val::Class(at));
                }
            }
            _ => {}
        }
        self.out.function.jni_calls.push(call);
        Some(ret.unwrap_or_else(|| self.machine.fresh()))
    }

    /// Entrées JNINativeMethod passées à RegisterNatives : table en troisième
    /// argument, nombre en quatrième.
    fn registered_by_code(&mut self, class: &str) {
        let ctx = self.ctx;
        let table = self.arg(2);
        let count = self.arg(3);
        let Some(mut at) = self.machine.materialize(ctx, table) else {
            return;
        };
        let limit = match self.machine.materialize(ctx, count) {
            Some(count) => count.min(MAX_REGISTER_ENTRIES),
            None => MAX_REGISTER_ENTRIES,
        };
        let stride = 3 * ctx.image.ptr_size;
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
    }

    /// GetEnv et AttachCurrentThread écrivent un JNIEnv* à l'adresse passée en
    /// deuxième argument.
    fn invoke_call(&mut self, off: u64) {
        let ptr = self.ctx.image.ptr_size;
        let index = off / ptr;
        let writes_env = [
            jni::INVOKE_ATTACH_CURRENT_THREAD,
            jni::INVOKE_GET_ENV,
            jni::INVOKE_ATTACH_CURRENT_THREAD_AS_DAEMON,
        ];
        if off.is_multiple_of(ptr) && writes_env.iter().any(|&i| i as u64 == index) {
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
        for entry in level {
            if !done.insert(entry.address) {
                continue;
            }
            let analyzed = analyze_guarded(ctx, &entry, options.max_insns);
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
    out
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
        let find_class = ["class", "index", "name", "resolved"];
        assert_eq!(keys(&function["jni_calls"][0]), find_class);
        let get_method_id = ["class", "index", "method", "name", "resolved", "signature"];
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
            STATUS_TRUNCATED,
            STATUS_ARCH_UNSUPPORTED,
            STATUS_INVALID_ENTRY,
            REASON_MAX_INSNS,
            REASON_INVALID_INSTRUCTION,
            REASON_OUTSIDE_EXEC,
            REASON_PANIC,
            CALL_INTERNAL,
            CALL_PLT,
            CALL_INDIRECT,
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
        for label in labels {
            assert!(legend.contains(label), "{label}");
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
