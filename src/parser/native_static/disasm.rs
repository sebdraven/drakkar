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
const ORIGIN_USER_ROOT: &str = "user_root";
const ORIGIN_EXPORT: &str = "export";

/// Exports du runtime C/C++ que `--native-roots exports` n'enracine pas.
pub(super) const RUNTIME_PREFIXES: &[&str] = &[
    "__cxa_",
    "__gxx_",
    "__gnu_",
    "__aeabi_",
    "_ZN10__cxxabiv1",
    "_ZNK10__cxxabiv1",
    "_ZNSt",
    "_ZNKSt",
    "_ZSt",
    "_ZN9__gnu_cxx",
    "_ZNK9__gnu_cxx",
    "_ZN17__eh_globals",
    "__clear_cache",
    "__stack_chk",
];

const SOURCE_SYMBOL: &str = "symbol";
const SOURCE_DISASM: &str = "disasm";
const SOURCE_PROLOGUE: &str = "prologue";

const SWEEP_MAPPING: &str = "mapping_symbols";
const SWEEP_FUNCTIONS: &str = "function_modes";
const SWEEP_DEFAULT_THUMB: &str = "default_thumb";

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
const FORM_JNIHELP: &str = "jnihelp";

/// libnativehelper `JNIHelp.h` : `jniRegisterNativeMethods(env, className,
/// gMethods, numMethods)`, extern "C" ; `_Z24` préfixe sa surcharge C++.
const JNIHELP_REGISTER: &str = "jniRegisterNativeMethods";
const JNIHELP_REGISTER_CXX: &str = "_Z24jniRegisterNativeMethods";

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
const MAX_THUNK_HOPS: usize = 4;
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisasmOptions {
    /// 0 = points d'entrée seuls ; n = fonctions internes appelées directement,
    /// jusqu'à n niveaux.
    pub depth: u8,
    /// Plafond d'instructions par fonction.
    pub max_insns: usize,
    /// `--native-root`.
    pub roots: Vec<RootSpec>,
    /// `--native-roots exports`.
    pub export_roots: bool,
    /// `--native-string-index`.
    pub string_index: bool,
}

impl Default for DisasmOptions {
    fn default() -> Self {
        DisasmOptions {
            depth: DEFAULT_DISASM_DEPTH,
            max_insns: DEFAULT_DISASM_MAX_INSNS,
            roots: Vec::new(),
            export_roots: false,
            string_index: false,
        }
    }
}

/// `--native-root` : symbole défini, ou adresse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootSpec {
    Symbol(String),
    /// `thumb` : forcé par `t:` / `a:`, sinon bit 0 de l'adresse.
    Address {
        address: u64,
        thumb: Option<bool>,
    },
}

impl std::fmt::Display for RootSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RootSpec::Symbol(name) => write!(f, "{name}"),
            RootSpec::Address { address, thumb } => {
                let prefix = match thumb {
                    Some(true) => "t:",
                    Some(false) => "a:",
                    None => "",
                };
                write!(f, "{prefix}{address:#x}")
            }
        }
    }
}

/// `nom`, `0x<hex>`, `t:<hex>` ou `a:<hex>` (`0x` facultatif après le préfixe).
pub fn parse_root_spec(spec: &str) -> Result<RootSpec, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("racine vide".into());
    }
    let (thumb, rest) = match spec.split_once(':') {
        Some(("t", rest)) => (Some(true), rest),
        Some(("a", rest)) => (Some(false), rest),
        _ => (None, spec),
    };
    let digits = match rest.strip_prefix("0x") {
        Some(digits) => digits,
        None if thumb.is_some() => rest,
        None => return Ok(RootSpec::Symbol(spec.to_string())),
    };
    let address = u64::from_str_radix(digits, 16)
        .map_err(|_| format!("adresse hexadécimale invalide : {rest:?}"))?;
    Ok(RootSpec::Address { address, thumb })
}

fn is_runtime_symbol(name: &str) -> bool {
    RUNTIME_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// WARN pour chaque `--native-root` qui n'a trouvé sa cible dans aucun ELF.
pub(super) fn warn_unmatched_roots(elfs: &[ElfReport], options: &DisasmOptions) {
    for (index, spec) in options.roots.iter().enumerate() {
        let found = elfs
            .iter()
            .filter_map(|e| e.disasm.as_ref())
            .any(|d| d.roots_matched.contains(&index));
        if !found {
            tracing::warn!(
                root = %spec,
                "--native-root introuvable : ni symbole défini de ce nom, ni adresse dans un \
                 segment exécutable, dans aucun ELF"
            );
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
    /// Entrées de `registered_by_code`, sous la forme de `jni.registered`.
    #[serde(skip)]
    pub(super) tables_by_code: Vec<RegisteredMethod>,
    /// Index dans `DisasmOptions::roots` des racines trouvées dans cet ELF.
    #[serde(skip)]
    pub(super) roots_matched: Vec<usize>,
    /// Remontés dans `ElfReport` par [`run`].
    #[serde(skip)]
    pub(super) string_index: Option<Vec<IndexedString>>,
    #[serde(skip)]
    pub(super) string_index_mode: Option<&'static str>,
}

/// Une chaîne de `--native-string-index` et les instructions qui forment son
/// adresse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IndexedString {
    pub value: String,
    pub target: String,
    pub encoding: &'static str,
    pub refs: Vec<StringIndexRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StringIndexRef {
    pub address: String,
    pub function: Option<String>,
    pub function_source: Option<&'static str>,
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
    /// Adresse d'instruction → commentaire de `--native-listing`.
    #[serde(skip)]
    pub(super) notes: BTreeMap<u64, String>,
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
    /// Veneer d'interworking Thumb-1 → ARM traversé pour atteindre `target`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub veneer: Option<String>,
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
            notes: BTreeMap::new(),
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
        Ok(mut disasm) => {
            if let Some(anomaly) = opaque_dead_code(&disasm.functions) {
                report.anomalies.push(anomaly);
            }
            report.string_index = disasm.string_index.take();
            report.string_index_mode = disasm.string_index_mode.take();
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

/// Ajoute à `jni.registered` les entrées lues à la table passée à
/// RegisterNatives ou jniRegisterNativeMethods que le scan des données n'a pas
/// trouvées, puis recalcule `jni_registration`. Avant la liaison.
pub(super) fn adopt_tables(report: &mut ElfReport) {
    let Some(disasm) = &report.disasm else {
        return;
    };
    for method in &disasm.tables_by_code {
        let known = report.jni.registered.iter().any(|r| {
            r.name == method.name
                && r.signature == method.signature
                && r.fn_offset == method.fn_offset
        });
        if !known {
            report.jni.registered.push(method.clone());
        }
    }
    report.jni.jni_registration = registration_status(&report.jni);
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
    for sym in parsed.symbols.iter().chain(&parsed.local_symbols) {
        if let Some((address, thumb)) = symbol_mode(arm, sym) {
            ctx.modes.entry(address).or_insert(thumb);
        }
        if !sym.defined || !sym.func || sym.value == 0 {
            continue;
        }
        let (address, _) = split_thumb(arm, sym.value);
        ctx.starts.insert(address);
        let slot = ctx.symbols.entry(address);
        slot.or_insert_with(|| (sym.name.clone(), sym.size));
        ctx.defined.entry(sym.name.clone()).or_insert(sym.value);
    }

    let mut entries = Vec::new();
    for export in &report.jni.static_exports {
        let thumb = ctx.modes.get(&export.address).copied().unwrap_or(false);
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
    let all_symbols: Vec<&DynSymbol> = parsed.symbols.iter().chain(&parsed.local_symbols).collect();
    let mut matched = Vec::new();
    for (index, spec) in options.roots.iter().enumerate() {
        if let Some((address, thumb)) = resolve_root(&ctx, &all_symbols, spec) {
            entries.push(entry(address, thumb, ORIGIN_USER_ROOT, Val::Opaque(0)));
            matched.push(index);
        }
    }
    if options.export_roots {
        for sym in &parsed.symbols {
            let exported = matches!(sym.bind, elf::STB_GLOBAL | elf::STB_WEAK);
            let runtime = is_runtime_symbol(&sym.name);
            if sym.defined && sym.func && sym.value != 0 && exported && !runtime {
                let (address, thumb) = split_thumb(arm, sym.value);
                entries.push(entry(address, thumb, ORIGIN_EXPORT, Val::Opaque(0)));
            }
        }
    }
    let mut out = walk_functions(&ctx, entries, options);
    out.roots_matched = matched;
    if options.string_index {
        if let Some(arch) = ctx.arch {
            let (index, mode) = string_index(&ctx, arch, &parsed.local_symbols, &out.functions);
            out.string_index = Some(index);
            out.string_index_mode = mode;
        }
    }
    out
}

/// Adresse et mode d'une racine `--native-root` dans cet ELF ; `None` si le
/// symbole n'y est pas défini ou si l'adresse tombe hors du code.
fn resolve_root(ctx: &Ctx, symbols: &[&DynSymbol], spec: &RootSpec) -> Option<(u64, bool)> {
    let arm = ctx.image.machine == elf::EM_ARM;
    let (address, thumb) = match spec {
        RootSpec::Symbol(name) => {
            let sym = symbols
                .iter()
                .find(|s| s.defined && s.value != 0 && s.name == *name)?;
            split_thumb(arm, sym.value)
        }
        RootSpec::Address { address, thumb } => {
            let (at, bit) = split_thumb(arm, *address);
            (at, arm && thumb.unwrap_or(bit))
        }
    };
    ctx.image.is_exec(address).then_some((address, thumb))
}

/// Mode ARM 32 bits du balayage linéaire, par plages.
struct SweepPlan {
    /// Début de plage → Thumb, ARM, ou données (`None`), trié.
    marks: Vec<(u64, Option<bool>)>,
    /// Avant la première plage.
    default: bool,
}

impl SweepPlan {
    fn mode_at(&self, at: u64) -> Option<bool> {
        match self.marks.partition_point(|(a, _)| *a <= at) {
            0 => Some(self.default),
            i => self.marks[i - 1].1,
        }
    }

    fn next_mark(&self, at: u64) -> Option<u64> {
        let i = self.marks.partition_point(|(a, _)| *a <= at);
        self.marks.get(i).map(|(a, _)| *a)
    }
}

/// `$a`, `$t`, `$d`, suffixés ou non (`$t.12`) : ARM, Thumb, données.
fn mapping_mode(name: &str) -> Option<Option<bool>> {
    match name.strip_prefix('$')?.split('.').next()? {
        "a" => Some(Some(false)),
        "t" => Some(Some(true)),
        "d" => Some(None),
        _ => None,
    }
}

/// Symboles de mapping s'il y en a, sinon mode des fonctions connues, sinon
/// Thumb ; le libellé rendu dit lequel.
fn sweep_plan(
    ctx: &Ctx,
    arch: Arch,
    local_symbols: &[DynSymbol],
) -> (SweepPlan, Option<&'static str>) {
    if arch != Arch::Arm {
        let plan = SweepPlan {
            marks: Vec::new(),
            default: false,
        };
        return (plan, None);
    }
    let mut marks: Vec<(u64, Option<bool>)> = local_symbols
        .iter()
        .filter(|s| s.defined)
        .filter_map(|s| mapping_mode(&s.name).map(|mode| (s.value & !1, mode)))
        .collect();
    let mut label = SWEEP_MAPPING;
    if marks.is_empty() {
        marks = ctx.modes.iter().map(|(&a, &t)| (a, Some(t))).collect();
        label = SWEEP_FUNCTIONS;
    }
    if marks.is_empty() {
        label = SWEEP_DEFAULT_THUMB;
    }
    marks.sort_by_key(|(a, _)| *a);
    let plan = SweepPlan {
        marks,
        default: true,
    };
    (plan, Some(label))
}

/// Sections exécutables ; sans section headers, segments LOAD exécutables.
fn code_regions(image: &Image) -> Vec<(u64, u64)> {
    let sections: Vec<(u64, u64)> = image
        .sections
        .iter()
        .filter(|s| s.has(elf::SHF_ALLOC) && s.has(elf::SHF_EXECINSTR) && s.has_file_data())
        .map(|s| (s.addr, s.addr.saturating_add(s.size)))
        .collect();
    if !sections.is_empty() {
        return sections;
    }
    image
        .segments
        .iter()
        .filter(|s| s.p_type == elf::PT_LOAD && s.has(elf::PF_X))
        .map(|s| (s.vaddr, s.vaddr.saturating_add(s.filesz)))
        .collect()
}

/// Section allouée en lecture seule ; sans section headers, segment LOAD non
/// inscriptible.
fn read_only_data(image: &Image, at: u64) -> bool {
    match image.data_kind(at) {
        Some(true) => true,
        Some(false) if image.sections.is_empty() => image
            .segments
            .iter()
            .any(|s| s.p_type == elf::PT_LOAD && s.in_file(at) && !s.has(elf::PF_W)),
        _ => false,
    }
}

fn string_value(image: &Image, at: u64) -> Option<(String, &'static str)> {
    let bytes = image.c_string_bytes(at)?;
    match std::str::from_utf8(bytes).ok().filter(|t| printable(t)) {
        Some(text) => Some((text.to_string(), "utf8")),
        None => Some((hex_bytes(bytes), "hex")),
    }
}

/// `push {…, lr}` (ARM, Thumb) ou `stp x29, x30, …` (AArch64).
fn is_prologue(insn: &Insn) -> bool {
    match insn.mnemonic.as_str() {
        "push" | "push.w" | "stmdb" | "stmfd" => insn.operands.contains("lr"),
        "stp" => insn.operands.starts_with("x29, x30"),
        _ => false,
    }
}

/// `[début, fin)` de chaque fonction désassemblée.
fn disasm_ranges(functions: &[DisasmFunction]) -> Vec<(u64, u64)> {
    functions
        .iter()
        .filter_map(|f| {
            let start = parse_hex(&f.address)?;
            let end = f
                .instructions
                .iter()
                .filter_map(|i| Some(parse_hex(&i.address)? + i.bytes.len() as u64 / 2))
                .max()?;
            Some((start, end))
        })
        .collect()
}

/// Fonction qui contient `at` : début de symbole ou de fonction désassemblée le
/// plus proche en amont qui la couvre, sinon le dernier prologue vu.
fn owner(
    ctx: &Ctx,
    ranges: &[(u64, u64)],
    at: u64,
    prologue: Option<u64>,
) -> (Option<u64>, Option<&'static str>) {
    let symbol = ctx
        .symbols
        .iter()
        .filter(|(start, (_, size))| {
            let (start, size) = (**start, *size);
            if start > at {
                return false;
            }
            if size > 0 {
                at - start < size
            } else {
                prologue.is_none_or(|p| p <= start)
            }
        })
        .map(|(start, _)| *start)
        .max();
    let disasm = ranges
        .iter()
        .filter(|(s, e)| *s <= at && at < *e)
        .map(|(s, _)| *s)
        .max();
    match (symbol, disasm) {
        (Some(s), Some(d)) if d > s => (Some(d), Some(SOURCE_DISASM)),
        (Some(s), _) => (Some(s), Some(SOURCE_SYMBOL)),
        (None, Some(d)) => (Some(d), Some(SOURCE_DISASM)),
        (None, None) => match prologue {
            Some(p) => (Some(p), Some(SOURCE_PROLOGUE)),
            None => (None, None),
        },
    }
}

/// `--native-string-index` : balayage linéaire du code, sans suivre aucun
/// branchement ; l'évaluateur repart d'un état vide après chaque saut ou retour.
fn string_index(
    ctx: &Ctx,
    arch: Arch,
    local_symbols: &[DynSymbol],
    functions: &[DisasmFunction],
) -> (Vec<IndexedString>, Option<&'static str>) {
    let (plan, label) = sweep_plan(ctx, arch, local_symbols);
    let ranges = disasm_ranges(functions);
    let mut found: BTreeMap<u64, IndexedString> = BTreeMap::new();
    for (start, end) in code_regions(&ctx.image) {
        let mut machine = Machine::new(arch);
        let mut prologue = None;
        let mut at = start;
        while at < end {
            let Some(thumb) = plan.mode_at(at) else {
                at = plan.next_mark(at).unwrap_or(end);
                machine = Machine::new(arch);
                continue;
            };
            if ctx.starts.contains(&at) {
                machine = Machine::new(arch);
            }
            let Some(code) = ctx.image.code_window(at) else {
                break;
            };
            let insn = match decode(arch, code, at, thumb) {
                Ok(insn) => insn,
                Err(_) => {
                    let step = match arch {
                        Arch::X86 | Arch::X86_64 => 1,
                        _ => undecoded_len(arch, code, thumb).max(2),
                    };
                    at = at.wrapping_add(step as u64);
                    machine = Machine::new(arch);
                    continue;
                }
            };
            if is_prologue(&insn) {
                prologue = Some(at);
            }
            machine.apply(ctx, &insn);
            let target = insn
                .forms_address
                .and_then(|reg| machine.materialize(ctx, machine.get(reg)));
            if let Some(target) = target.filter(|&t| read_only_data(&ctx.image, t)) {
                if let Some((text, encoding)) = string_value(&ctx.image, target) {
                    let (function, source) = owner(ctx, &ranges, at, prologue);
                    let item = found.entry(target).or_insert_with(|| IndexedString {
                        value: text,
                        target: hex(target),
                        encoding,
                        refs: Vec::new(),
                    });
                    let address = hex(at);
                    if !item.refs.iter().any(|r| r.address == address) {
                        item.refs.push(StringIndexRef {
                            address,
                            function: function.map(hex),
                            function_source: source,
                        });
                    }
                }
            }
            let stops = matches!(
                insn.flow,
                Flow::Return | Flow::Jump(..) | Flow::JumpVia(_) | Flow::Stop
            );
            if stops {
                machine = Machine::new(arch);
            }
            at = at.wrapping_add(insn.len.max(1));
        }
    }
    (found.into_values().collect(), label)
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

/// Mode porté par un symbole ARM défini : bit 0 de st_value. Un symbole autre
/// que STT_FUNC ne compte que s'il porte ce bit : pair, il peut désigner des
/// données ou un symbole de mapping ($a, $t, $d).
fn symbol_mode(arm: bool, sym: &DynSymbol) -> Option<(u64, bool)> {
    if !arm || !sym.defined || sym.value == 0 {
        return None;
    }
    let (address, thumb) = split_thumb(true, sym.value);
    (sym.func || thumb).then_some((address, thumb))
}

/// Veneer d'interworking Thumb-1 → ARM des builds armeabi, 16 octets :
/// Thumb `bx pc ; nop`, puis ARM `ldr ip, [pc, #0] ; add pc, ip, pc` et un
/// littéral. Cible = littéral + adresse de `add pc, ip, pc` + 8 ; mode = bit 0
/// de la cible. `None` si `at`, en Thumb, ne porte pas ce motif.
fn veneer_target(ctx: &Ctx, at: u64, thumb: bool) -> Option<(u64, bool)> {
    if ctx.arch != Some(Arch::Arm) || !thumb {
        return None;
    }
    let code = ctx.image.code_window(at)?;
    let word = |i: usize| -> Option<u32> {
        let b = code.get(i..i + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    if code.get(..4)? != [0x78, 0x47, 0xc0, 0x46].as_slice()
        || word(4)? != 0xe59f_c000
        || word(8)? != 0xe08c_f00f
    {
        return None;
    }
    let add_pc = at.wrapping_add(8);
    let target = u64::from(word(12)?).wrapping_add(add_pc.wrapping_add(8)) & 0xffff_ffff;
    Some(split_thumb(true, target))
}

/// Cible réelle d'un appel ou d'un saut direct : veneer traversé, puis mode
/// donné par un symbole connu à cette adresse plutôt que par le branchement.
/// Rend aussi l'adresse du veneer traversé.
fn direct_target(ctx: &Ctx, target: u64, mode: bool) -> (u64, bool, Option<u64>) {
    let (address, mode, veneer) = match veneer_target(ctx, target, mode) {
        Some((address, mode)) => (address, mode, Some(target)),
        None => (target, mode, None),
    };
    let mode = ctx.modes.get(&address).copied().unwrap_or(mode);
    (address, mode, veneer)
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
    /// Nom de fonction définie → st_value, bit Thumb compris.
    defined: HashMap<String, u64>,
    /// ARM 32 bits : adresse d'un symbole défini → Thumb, par [`symbol_mode`].
    modes: HashMap<u64, bool>,
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
            defined: HashMap::new(),
            modes: HashMap::new(),
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
            Addr::Index(..) | Addr::PcIndex(..) => match self.index_place(ctx, addr) {
                Some(place) => self.load_from(ctx, place, 0, width),
                None => self.fresh(),
            },
            Addr::Unknown => self.fresh(),
        }
    }

    /// `base + index`, à la largeur d'un pointeur ; `None` si l'index est inconnu.
    fn index_place(&mut self, ctx: &Ctx, addr: Addr) -> Option<Val> {
        let (base, index) = match addr {
            Addr::Index(base, index) => (self.get(base), index),
            Addr::PcIndex(pc, index) => (Val::Const(pc), index),
            _ => return None,
        };
        let index = self.get(index);
        let off = self.materialize(ctx, index)?;
        Some(self.add(ctx, base, off as i64))
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
            Addr::Index(..) | Addr::PcIndex(..) => match self.index_place(ctx, addr) {
                Some(place) => place,
                None => return,
            },
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
            Via::Expr(expr) => self.eval(ctx, expr),
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

/// Thunk vers main (crtbegin de bionic ancien : `add r2, pc, #4` désigne un
/// `b main`) : saut direct inconditionnel, ou `ldr pc` sur un littéral, suivi
/// tant que la cible est une fonction interne.
fn through_thunks(ctx: &Ctx, mut address: u64, mut thumb: bool) -> (u64, bool) {
    let Some(arch) = ctx.arch else {
        return (address, thumb);
    };
    for _ in 0..MAX_THUNK_HOPS {
        let Some(code) = ctx.image.code_window(address) else {
            break;
        };
        let Ok(insn) = decode(arch, code, address, thumb) else {
            break;
        };
        let (target, mode) = match insn.flow {
            Flow::Jump(target, mode) => (target, mode),
            Flow::JumpVia(Via::Mem(Addr::Abs(at))) => match pointer(&ctx.image, &ctx.slots, at) {
                Some(value) => split_thumb(arch == Arch::Arm, value),
                None => break,
            },
            _ => break,
        };
        if !callable(ctx, target) || plt_import(ctx, target, mode).is_some() {
            break;
        }
        (address, thumb) = (target, mode);
    }
    (address, thumb)
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
                    let (target, mode, _) = direct_target(ctx, target, mode);
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
                    let (target, mode, _) = direct_target(ctx, target, mode);
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
    tables: Vec<RegisteredMethod>,
}

impl Analyzed {
    fn new(entry: &Entry) -> Self {
        Analyzed {
            function: DisasmFunction::new(entry),
            callees: Vec::new(),
            mains: Vec::new(),
            upcalls: Vec::new(),
            registered: Vec::new(),
            tables: Vec::new(),
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
        let function = &walk.out.function;
        let seen = (
            walk.calls.len(),
            function.jni_calls.len(),
            function.string_refs.len(),
        );
        walk.step(insn);
        if let Some(note) = step_note(&walk.calls, &walk.out.function, seen) {
            walk.out.function.notes.insert(insn.address, note);
        }
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
            Flow::Jump(target, mode) => {
                let (real, real_mode, _) = direct_target(ctx, target, mode);
                if !is_internal(ctx, self.start, real, real_mode) {
                    let arg0 = self.arg(0);
                    self.record_direct(target, mode, arg0);
                }
            }
            Flow::CallVia(via) => self.indirect(via, true, false),
            Flow::JumpVia(via) => self.indirect(via, false, insn.branch_write_pc),
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
        let (target, mode, veneer) = direct_target(ctx, target, mode);
        let veneer = veneer.map(hex);
        if !callable(ctx, target) {
            self.calls.push(DisasmCall {
                target: Some(hex(target)),
                import: None,
                symbol: None,
                kind: CALL_UNRESOLVED,
                veneer,
            });
            return None;
        }
        if let Some(name) = plt_import(ctx, target, mode) {
            let wrapper = cxx_wrapper(&name);
            self.libc_main(&name);
            self.jnihelp_register(&name);
            self.calls.push(DisasmCall {
                target: Some(hex(target)),
                import: Some(name),
                symbol: None,
                kind: CALL_PLT,
                veneer,
            });
            return wrapper.map(|w| self.wrapper_call(w));
        }
        let symbol = ctx.symbols.get(&target).map(|(name, _)| name.clone());
        let wrapper = symbol.as_deref().and_then(cxx_wrapper);
        if let Some(name) = &symbol {
            self.jnihelp_register(name);
        }
        self.calls.push(DisasmCall {
            target: Some(hex(target)),
            import: None,
            symbol,
            kind: CALL_INTERNAL,
            veneer,
        });
        let arg0 = match arg0 {
            Val::Env | Val::Vm => arg0,
            _ => Val::Opaque(0),
        };
        let callee = entry(target, mode, ORIGIN_CALLEE, arg0);
        self.out.callees.push(callee);
        wrapper.map(|w| self.wrapper_call(w))
    }

    /// `stay_thumb` : BranchWritePC, la cible reste en Thumb sans regarder son
    /// bit 0.
    fn indirect(&mut self, via: Via, is_call: bool, stay_thumb: bool) {
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
            None => self.record_value(value, arg0, is_call, stay_thumb),
        };
        if is_call {
            self.after_call(ret);
        }
    }

    fn record_value(
        &mut self,
        value: Val,
        arg0: Val,
        is_call: bool,
        stay_thumb: bool,
    ) -> Option<Val> {
        let ctx = self.ctx;
        if let Val::Mem(slot) = value {
            if let Some(name) = ctx.got.get(&slot) {
                let wrapper = cxx_wrapper(name);
                self.libc_main(name);
                self.jnihelp_register(name);
                self.calls.push(DisasmCall {
                    target: None,
                    import: Some(name.clone()),
                    symbol: None,
                    kind: CALL_PLT,
                    veneer: None,
                });
                return wrapper.map(|w| self.wrapper_call(w));
            }
        }
        let arm = self.arch == Arch::Arm;
        let target = self.machine.materialize(ctx, value);
        let split = |t: u64| match stay_thumb {
            true => (t & !1, true),
            false => split_thumb(arm, t),
        };
        match target.map(split) {
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
        // Emplacement de GOT relogé par R_*_GLOB_DAT sur un symbole défini.
        let by_symbol = match value {
            Val::Mem(slot) => ctx.got.get(&slot).and_then(|name| ctx.defined.get(name)),
            _ => None,
        };
        let target = match by_symbol {
            Some(&raw) => raw,
            None => match self.machine.materialize(ctx, value) {
                Some(target) => target,
                None => return,
            },
        };
        let (address, thumb) = split_thumb(self.arch == Arch::Arm, target);
        let (address, thumb) = through_thunks(ctx, address, thumb);
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
        let table = hex(at);
        let before = self.out.registered.len();
        for _ in 0..limit {
            let Some(mut method) = jni_entry_at(&ctx.image, &ctx.slots, at) else {
                break;
            };
            let member = JavaMember {
                class: class.to_string(),
                name: method.name.clone(),
                signature: method.signature.clone(),
                fn_address: parse_hex(&method.fn_offset),
            };
            self.out.registered.push(member);
            method.table_offset = table.clone();
            self.out.tables.push(method);
            at = at.wrapping_add(stride);
        }
        self.out.registered.len() > before
    }

    /// `jniRegisterNativeMethods(env, className, gMethods, numMethods)` :
    /// RegisterNatives sur la classe nommée par une chaîne C, arguments aux
    /// mêmes positions. Le symbole tient lieu de preuve de l'env.
    fn jnihelp_register(&mut self, function: &str) {
        if function != JNIHELP_REGISTER && !function.starts_with(JNIHELP_REGISTER_CXX) {
            return;
        }
        let index = jni::REGISTER_NATIVES;
        let mut call = JniCall::new(jni::JNI_NATIVE_INTERFACE[index], index, FORM_JNIHELP);
        call.class = self.string_arg(1).map(|name| class_descriptor(&name));
        let missing = match call.class.clone() {
            Some(class) => (!self.registered_by_code(&class)).then_some(UNRESOLVED_TABLE),
            None => Some(UNRESOLVED_CLASS),
        };
        call.resolved = missing.is_none();
        call.unresolved_reason = missing;
        self.out.function.jni_calls.push(call);
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
        veneer: None,
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
            for method in analyzed.tables {
                if !out.tables_by_code.contains(&method) {
                    out.tables_by_code.push(method);
                }
            }
            out.functions.push(analyzed.function);
        }
        level = next;
    }
    out.imports_called = imports_called(&out.functions);
    out.invalid_paths_count = out.functions.iter().map(|f| f.invalid_paths.len()).sum();
    out
}

/// Anomalie `opaque_dead_code` : mêmes octets invalides dans au moins
/// [`OPAQUE_DEAD_CODE_MIN`] fonctions. Une fonction invalid_entry ne compte
/// pas : son seul chemin abandonné est sa racine, pas un bloc mort.
fn opaque_dead_code(functions: &[DisasmFunction]) -> Option<String> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for function in functions {
        if function.disasm_status == STATUS_INVALID_ENTRY {
            continue;
        }
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

/// Ce que `step` vient d'attribuer à une instruction : chaîne référencée, cible
/// ou import appelé, fonction JNI. `seen` : longueurs avant `step`.
fn step_note(
    calls: &[DisasmCall],
    function: &DisasmFunction,
    seen: (usize, usize, usize),
) -> Option<String> {
    let (calls_seen, jni_seen, refs_seen) = seen;
    let jni = &function.jni_calls[jni_seen..];
    let mut parts = Vec::new();
    for string in &function.string_refs[refs_seen..] {
        parts.push(format!("{:?}", string.value));
    }
    for call in &calls[calls_seen..] {
        let part = match (&call.import, &call.symbol, &call.target) {
            (Some(import), _, _) => import.clone(),
            (None, Some(symbol), _) => symbol.clone(),
            (None, None, Some(target)) => format!("{} {target}", call.kind),
            (None, None, None) if jni.is_empty() => call.kind.to_string(),
            (None, None, None) => continue,
        };
        parts.push(part);
    }
    for call in jni {
        parts.push(call.name.to_string());
    }
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// `--native-listing <elf>@<adresse>` ou `<elf>@<début>-<fin>`, fin exclue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingSpec {
    /// Chemin de l'ELF ; `None` pour `*`.
    pub elf: Option<String>,
    pub start: u64,
    pub end: Option<u64>,
}

impl std::fmt::Display for ListingSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}@{:#x}",
            self.elf.as_deref().unwrap_or("*"),
            self.start
        )?;
        if let Some(end) = self.end {
            write!(f, "-{end:#x}")?;
        }
        Ok(())
    }
}

/// Adresses hexadécimales, préfixe `0x` facultatif.
pub fn parse_listing_spec(spec: &str) -> Result<ListingSpec, String> {
    let Some((elf, at)) = spec.rsplit_once('@') else {
        return Err("forme attendue : <elf|*>@<adresse> ou <elf|*>@<début>-<fin>".into());
    };
    let elf = match elf {
        "" => return Err("chemin d'ELF vide (passer * pour tous les ELF)".into()),
        "*" => None,
        path => Some(path.to_string()),
    };
    let hex_addr = |text: &str| {
        let digits = text.strip_prefix("0x").unwrap_or(text);
        u64::from_str_radix(digits, 16)
            .map_err(|_| format!("adresse hexadécimale invalide : {text:?}"))
    };
    let (start, end) = match at.split_once('-') {
        Some((start, end)) => (hex_addr(start)?, Some(hex_addr(end)?)),
        None => (hex_addr(at)?, None),
    };
    if end.is_some_and(|end| end <= start) {
        return Err(format!("fin {at:?} : doit suivre le début"));
    }
    Ok(ListingSpec { elf, start, end })
}

#[derive(Debug, Clone, Serialize)]
pub struct Listing {
    pub elf: String,
    pub start: String,
    pub end: String,
    pub instructions: Vec<ListingInsn>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListingInsn {
    pub address: String,
    pub bytes: String,
    pub mnemonic: String,
    pub operands: String,
    pub comment: Option<String>,
}

/// Listing de `spec` dans l'ELF `report`, dont `bytes` est le contenu. Une
/// adresse seule liste la fonction désassemblée qui commence ou passe par elle ;
/// une plage liste les instructions de la fonction qui passe par son début, ou,
/// à défaut, la décode linéairement. `Err` : raison pour laquelle rien n'est listé.
pub(super) fn listing(
    bytes: &[u8],
    report: &ElfReport,
    spec: &ListingSpec,
    max_insns: usize,
) -> Result<Listing, String> {
    let disasm = report.disasm.as_ref().ok_or("ELF non désassemblé")?;
    let parsed = parse_elf(bytes).map_err(|e| format!("ELF illisible ({e})"))?;
    let image = parsed.image;
    let arm = image.machine == elf::EM_ARM;
    let mut notes = BTreeMap::new();
    for function in &disasm.functions {
        for (&at, note) in &function.notes {
            notes.insert(at, note.as_str());
        }
    }
    let (start, thumb) = split_thumb(arm, spec.start);
    let start_hex = hex(start);
    let passes_by = |f: &&DisasmFunction| f.instructions.iter().any(|i| i.address == start_hex);
    let Some(end) = spec.end else {
        let function = disasm
            .functions
            .iter()
            .find(|f| f.address == start_hex)
            .or_else(|| disasm.functions.iter().find(passes_by))
            .ok_or_else(|| format!("aucune fonction désassemblée en {start_hex}"))?;
        let instructions = function
            .instructions
            .iter()
            .map(|i| listed(i, &notes))
            .collect();
        let end = match function.instructions.last() {
            Some(last) => parse_hex(&last.address).unwrap_or(0) + last.bytes.len() as u64 / 2,
            None => start,
        };
        return Ok(Listing {
            elf: report.path.clone(),
            start: function.address.clone(),
            end: hex(end),
            instructions,
        });
    };
    let (end, _) = split_thumb(arm, end);
    if end <= start {
        return Err(format!(
            "plage vide une fois le bit Thumb effacé : {start_hex}"
        ));
    }
    let instructions = match disasm.functions.iter().find(passes_by) {
        Some(function) => function
            .instructions
            .iter()
            .filter(|i| parse_hex(&i.address).is_some_and(|at| (start..end).contains(&at)))
            .map(|i| listed(i, &notes))
            .collect(),
        None => linear(&image, start, end, thumb, max_insns, &notes)?,
    };
    Ok(Listing {
        elf: report.path.clone(),
        start: hex(start),
        end: hex(end),
        instructions,
    })
}

fn listed(insn: &DisasmInsn, notes: &BTreeMap<u64, &str>) -> ListingInsn {
    let comment = parse_hex(&insn.address).and_then(|at| notes.get(&at));
    ListingInsn {
        address: insn.address.clone(),
        bytes: insn.bytes.clone(),
        mnemonic: insn.mnemonic.clone(),
        operands: insn.operands.clone(),
        comment: comment.map(|note| note.to_string()),
    }
}

/// Décodage linéaire de `[start, end)`, sans suivre aucun branchement ; un
/// octet indécodable devient `(invalid)` et le décodage reprend après lui.
fn linear(
    image: &Image,
    start: u64,
    end: u64,
    thumb: bool,
    max_insns: usize,
    notes: &BTreeMap<u64, &str>,
) -> Result<Vec<ListingInsn>, String> {
    let Some(arch) = arch_of(image) else {
        return Err(format!(
            "e_machine {} ou gros-boutiste : pas de décodeur",
            image.machine
        ));
    };
    let mut out = Vec::new();
    let mut at = start;
    while at < end && out.len() < max_insns {
        let Some(code) = image.code_window(at) else {
            break;
        };
        let (len, bytes, mnemonic, operands) = match decode(arch, code, at, thumb) {
            Ok(insn) => (insn.len, insn.bytes, insn.mnemonic, insn.operands),
            Err(_) => {
                let len = undecoded_len(arch, code, thumb).max(1);
                let raw = hex_bytes(&code[..len.min(code.len())]);
                (len as u64, raw, "(invalid)".to_string(), String::new())
            }
        };
        out.push(ListingInsn {
            address: hex(at),
            bytes,
            mnemonic,
            operands,
            comment: notes.get(&at).map(|note| note.to_string()),
        });
        at = at.wrapping_add(len.max(1));
    }
    if out.is_empty() {
        return Err(format!("{} hors segment LOAD exécutable", hex(start)));
    }
    Ok(out)
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
        DisasmOptions {
            depth,
            max_insns,
            ..DisasmOptions::default()
        }
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
            veneer: None,
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
            veneer: None,
        };
        let expected = std::slice::from_ref(&plt);
        for (address, thumb) in [(CODE, false), (0x1100, true)] {
            let out = analyze(&ctx, address, thumb);
            assert_eq!(out.function.calls, expected, "{address:#x}");
            assert!(out.callees.is_empty(), "{address:#x}");
        }
    }

    /// armeabi (Thumb-1) : appel par un veneer d'interworking en 0x1100.
    const THUMB1_CALLS_VENEER: &[(u16, &str)] = &[
        (0xf000, "1000  bl   0x1100"),
        (0xf87e, ""),
        (0x2001, "1004  movs r0, #1"),
        (0x4770, "1006  bx   lr"),
    ];

    /// `bx pc ; nop ; ldr ip, [pc, #0] ; add pc, ip, pc ; .word` vers `target`.
    fn veneer_to(data: &mut [u8], at: u64, target: u64) {
        assemble_thumb(data, at, &[(0x4778, "bx pc"), (0x46c0, "nop")]);
        let arm = [
            (0xe59f_c000, "ldr ip, [pc, #0]"),
            (0xe08c_f00f, "add pc, ip, pc"),
        ];
        assemble(data, at + 4, &arm);
        let literal = target.wrapping_sub(at + 16) as u32;
        put(data, at + 12, &literal.to_le_bytes());
    }

    fn thumb1_through_veneer(import: &str) -> (Vec<u8>, [(u64, u64); 6]) {
        let mut data = vec![0u8; 0x4000];
        assemble_thumb(&mut data, CODE, THUMB1_CALLS_VENEER);
        veneer_to(&mut data, 0x1100, 0x1800);
        assemble(&mut data, 0x1800, ARM_PLT);
        let dynamic = jump_slot(&mut data, 0x348c, import, true);
        (data, dynamic)
    }

    #[test]
    fn a_thumb1_veneer_to_a_plt_stub_is_a_plt_call() {
        let (data, dynamic) = thumb1_through_veneer("malloc");
        let mut ctx = Ctx::new(image(&data, elf::EM_ARM, 4));
        ctx.got = got_imports(&ctx.image, &dynamic);
        let out = analyze(&ctx, CODE, true);
        let plt = DisasmCall {
            target: Some("0x1800".to_string()),
            import: Some("malloc".to_string()),
            symbol: None,
            kind: CALL_PLT,
            veneer: Some("0x1100".to_string()),
        };
        assert_eq!(out.function.calls, [plt]);
        assert!(out.callees.is_empty(), "aucune fonction pour le veneer");
        assert_eq!(out.function.instructions.len(), 3);

        let entries = vec![jni_entry(CODE, true)];
        let disasm = walk_functions(&ctx, entries, &DisasmOptions::default());
        let other = disasm.imports_called.get("other").cloned();
        assert_eq!(other.unwrap_or_default(), ["malloc"]);
        let json = serde_json::to_value(&disasm.functions[0].calls[0]).unwrap();
        assert_eq!(json["veneer"], "0x1100");
    }

    #[test]
    fn a_noreturn_import_behind_a_veneer_ends_the_path() {
        let (data, dynamic) = thumb1_through_veneer("__stack_chk_fail");
        let mut ctx = Ctx::new(image(&data, elf::EM_ARM, 4));
        ctx.got = got_imports(&ctx.image, &dynamic);
        let out = analyze(&ctx, CODE, true);
        assert_eq!(out.function.instructions.len(), 1);
        let import = out.function.calls[0].import.as_deref();
        assert_eq!(import, Some("__stack_chk_fail"));
    }

    #[test]
    fn a_thumb1_veneer_to_code_is_an_internal_arm_call() {
        let mut data = vec![0u8; 0x4000];
        assemble_thumb(&mut data, CODE, THUMB1_CALLS_VENEER);
        veneer_to(&mut data, 0x1100, 0x1200);
        put(&mut data, 0x1200, &0xe12f_ff1eu32.to_le_bytes());
        let ctx = Ctx::new(image(&data, elf::EM_ARM, 4));
        let out = analyze(&ctx, CODE, true);
        let call = &out.function.calls[0];
        let seen = (call.kind, call.target.as_deref(), call.veneer.as_deref());
        assert_eq!(seen, (CALL_INTERNAL, Some("0x1200"), Some("0x1100")));
        assert_eq!(out.callees.len(), 1);
        let callee = out.callees[0];
        assert_eq!((callee.address, callee.thumb), (0x1200, false));
    }

    /// Les mêmes octets sans le motif complet ne sont pas un veneer.
    #[test]
    fn a_bare_bx_pc_is_not_a_veneer() {
        let mut data = vec![0u8; 0x4000];
        assemble_thumb(&mut data, 0x1100, &[(0x4778, "bx pc"), (0x46c0, "nop")]);
        let ctx = Ctx::new(image(&data, elf::EM_ARM, 4));
        assert_eq!(veneer_target(&ctx, 0x1100, true), None);
        veneer_to(&mut data, 0x1100, 0x1800);
        let ctx = Ctx::new(image(&data, elf::EM_ARM, 4));
        assert_eq!(
            veneer_target(&ctx, 0x1100, false),
            None,
            "veneer atteint en ARM"
        );
        assert_eq!(veneer_target(&ctx, 0x1100, true), Some((0x1800, false)));
    }

    /// ARM `bl` vers 0x1100, où vit une fonction Thumb.
    const ARM_CALLS_THUMB_SYMBOL: &[(u32, &str)] = &[
        (0xeb00_003e, "1000  bl   0x1100"),
        (0xe12f_ff1e, "1004  bx   lr"),
    ];

    fn defined(value: u64, func: bool) -> DynSymbol {
        DynSymbol {
            name: "f".to_string(),
            defined: true,
            bind: elf::STB_GLOBAL,
            value,
            size: 0,
            func,
        }
    }

    #[test]
    fn symbol_modes_follow_bit_zero_of_st_value() {
        assert_eq!(
            symbol_mode(true, &defined(0x1101, true)),
            Some((0x1100, true))
        );
        assert_eq!(
            symbol_mode(true, &defined(0x1100, true)),
            Some((0x1100, false))
        );
        // Export Java_* rangé en STT_NOTYPE par un packer : le bit 0 suffit.
        assert_eq!(
            symbol_mode(true, &defined(0x2001, false)),
            Some((0x2000, true))
        );
        // Pair hors STT_FUNC : données ou symbole de mapping, rien n'est conclu.
        assert_eq!(symbol_mode(true, &defined(0x2000, false)), None);
        assert_eq!(symbol_mode(false, &defined(0x1101, true)), None);
    }

    /// Le cas de stage2_armv7.so : un callee Thumb atteint par un branchement qui
    /// dit ARM était lu en mots ARM. Le symbole à la cible l'emporte.
    #[test]
    fn a_callee_takes_the_mode_of_the_symbol_at_its_address() {
        let mut data = vec![0u8; 0x2000];
        assemble(&mut data, CODE, ARM_CALLS_THUMB_SYMBOL);
        assemble_thumb(
            &mut data,
            0x1100,
            &[(0x4478, "add r0, pc"), (0x4770, "bx lr")],
        );
        let mut ctx = Ctx::new(image(&data, elf::EM_ARM, 4));
        let out = analyze(&ctx, CODE, false);
        let callee = out.callees[0];
        assert_eq!(
            (callee.address, callee.thumb),
            (0x1100, false),
            "sans symbole"
        );

        let (address, thumb) = symbol_mode(true, &defined(0x1101, true)).unwrap();
        ctx.modes.insert(address, thumb);
        let out = analyze(&ctx, CODE, false);
        let callee = out.callees[0];
        assert_eq!((callee.address, callee.thumb), (0x1100, true));

        let walked = walk_functions(&ctx, vec![jni_entry(CODE, false)], &options(1, 100));
        let f = &walked.functions[1];
        assert_eq!(f.address, "0x1100");
        assert!(f.invalid_paths.is_empty(), "{:?}", f.invalid_paths);
        assert_eq!(f.instructions[0].mnemonic, "add");
    }

    /// stage2_armv7.so (BeatBanker), séquence de 0xe4a0 transposée en 0x1000 :
    /// l'entrée de table lue en 0x1104 vaut 0x1200, paire.
    const THUMB_MOV_PC_TABLE: &[(u16, &str)] = &[
        (0x4803, "1000  ldr  r0, [pc, #12]    ; 0x1010"),
        (
            0x4478,
            "1002  add  r0, pc           ; 0xfa + 0x1006 = 0x1100",
        ),
        (0x6840, "1004  ldr  r0, [r0, #4]     ; 0x1200"),
        (0x4687, "1006  mov  pc, r0"),
    ];

    #[test]
    fn a_thumb_mov_pc_keeps_thumb_for_an_even_table_entry() {
        let mut data = vec![0u8; 0x2000];
        assemble_thumb(&mut data, CODE, THUMB_MOV_PC_TABLE);
        put(&mut data, 0x1010, &0xfau32.to_le_bytes());
        put(&mut data, 0x1104, &0x1200u32.to_le_bytes());
        let target = [(0xb510, "push {r4, lr}"), (0xbd10, "pop {r4, pc}")];
        assemble_thumb(&mut data, 0x1200, &target);
        let ctx = Ctx::new(image(&data, elf::EM_ARM, 4));
        let out = analyze(&ctx, CODE, true);
        assert_eq!(out.callees.len(), 1);
        let callee = out.callees[0];
        assert_eq!((callee.address, callee.thumb), (0x1200, true));

        let walked = walk_functions(&ctx, vec![jni_entry(CODE, true)], &options(1, 100));
        let f = walked
            .functions
            .iter()
            .find(|f| f.address == "0x1200")
            .unwrap();
        assert!(f.invalid_paths.is_empty(), "{:?}", f.invalid_paths);
        assert_eq!(f.instructions[0].mnemonic, "push");
        assert_eq!(walked.invalid_paths_count, 0);
    }

    const ARM_MOV_PC_ODD: &[(u32, &str)] = &[
        (0xe59f_3000, "1000  ldr  r3, [pc, #0]    ; 0x1008"),
        (0xe1a0_f003, "1004  mov  pc, r3"),
        (0x0000_1101, "1008  littéral : 0x1100 | 1"),
    ];

    #[test]
    fn an_arm_mov_pc_to_an_odd_value_switches_to_thumb() {
        let mut data = vec![0u8; 0x2000];
        assemble(&mut data, CODE, ARM_MOV_PC_ODD);
        put(&mut data, 0x1100, &0x4770u16.to_le_bytes());
        let ctx = Ctx::new(image(&data, elf::EM_ARM, 4));
        let out = analyze(&ctx, CODE, false);
        let callee = out.callees[0];
        assert_eq!((callee.address, callee.thumb), (0x1100, true));
    }

    #[test]
    fn pc_writes_by_data_instructions_keep_thumb_only_in_thumb() {
        let add = decode(Arch::Arm, &[0x87, 0x44], 0x1000, true).unwrap();
        assert_eq!(add.flow, Flow::JumpVia(Via::Expr(Expr::AddImm(0, 0x1004))));
        assert!(add.branch_write_pc);
        let mov = decode(Arch::Arm, &[0x03, 0xf0, 0xa0, 0xe1], 0x1000, false).unwrap();
        assert_eq!(mov.flow, Flow::JumpVia(Via::Reg(3)));
        assert!(!mov.branch_write_pc);
        let bx = decode(Arch::Arm, &[0x18, 0x47], 0x1000, true).unwrap();
        assert!(!bx.branch_write_pc, "bx interworke");
    }

    #[test]
    fn root_specs_parse_names_addresses_and_forced_modes() {
        assert_eq!(parse_root_spec("init"), Ok(RootSpec::Symbol("init".into())));
        let address = |address: u64, thumb: Option<bool>| -> Result<RootSpec, String> {
            Ok(RootSpec::Address { address, thumb })
        };
        assert_eq!(parse_root_spec("0x4c79"), address(0x4c79, None));
        assert_eq!(parse_root_spec("t:4c78"), address(0x4c78, Some(true)));
        assert_eq!(parse_root_spec("a:0x1000"), address(0x1000, Some(false)));
        assert!(parse_root_spec("t:zz").is_err());
        assert!(parse_root_spec("").is_err());
        assert_eq!(parse_root_spec("t:4c78").unwrap().to_string(), "t:0x4c78");
    }

    #[test]
    fn a_root_resolves_by_symbol_or_by_address() {
        let mut data = vec![0u8; 0x2000];
        put(&mut data, 0x1100, &0x4770u16.to_le_bytes());
        let ctx = Ctx::new(image(&data, elf::EM_ARM, 4));
        let init = DynSymbol {
            name: "init".to_string(),
            defined: true,
            bind: elf::STB_GLOBAL,
            value: 0x1101,
            size: 2,
            func: true,
        };
        let symbols = [&init];
        let resolve = |spec: RootSpec| resolve_root(&ctx, &symbols, &spec);
        assert_eq!(
            resolve(RootSpec::Symbol("init".into())),
            Some((0x1100, true))
        );
        assert_eq!(resolve(RootSpec::Symbol("absent".into())), None);
        let at = |address, thumb| RootSpec::Address { address, thumb };
        assert_eq!(resolve(at(0x1100, Some(true))), Some((0x1100, true)));
        assert_eq!(resolve(at(0x1100, None)), Some((0x1100, false)));
        assert_eq!(resolve(at(0x1101, None)), Some((0x1100, true)));
        assert_eq!(resolve(at(0x1101, Some(false))), Some((0x1100, false)));
        assert_eq!(resolve(at(0x9000, None)), None, "hors du code");
    }

    #[test]
    fn export_roots_skip_the_c_and_cxx_runtime() {
        for name in [
            "__cxa_atexit",
            "__aeabi_memcpy",
            "_ZNSt6vectorIiE9push_backEv",
            "__stack_chk_fail",
            "__gnu_Unwind_Find_exidx",
            "_ZNK10__cxxabiv117__class_type_info10__do_catchEPKSt9type_infoPPvj",
            "_ZNK9__gnu_cxx24__concurrence_lock_error4whatEv",
            "_ZN17__eh_globals_initD1Ev",
        ] {
            assert!(is_runtime_symbol(name), "{name}");
        }
        for name in ["init", "Java_com_a_B_c", "JNI_OnLoad", "_ZN3foo3barEv"] {
            assert!(!is_runtime_symbol(name), "{name}");
        }
    }

    #[test]
    fn an_added_root_never_duplicates_an_existing_entry() {
        let mut data = vec![0u8; 0x2000];
        put(&mut data, CODE, &0xd65f03c0u32.to_le_bytes());
        let ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        let entries = vec![
            jni_entry(CODE, false),
            entry(CODE, false, ORIGIN_USER_ROOT, Val::Opaque(0)),
            entry(CODE, false, ORIGIN_EXPORT, Val::Opaque(0)),
        ];
        let walked = walk_functions(&ctx, entries, &options(0, 100));
        assert_eq!(walked.functions.len(), 1);
        assert_eq!(walked.functions[0].origin, ORIGIN_JNI_STATIC);
    }

    #[test]
    fn the_string_index_reaches_code_no_function_disassembled() {
        let mut data = vec![0u8; 0x3000];
        strings(&mut data);
        assemble_thumb(&mut data, CODE, THUMB_JNI);
        put(&mut data, 0x1014, &0xff6u32.to_le_bytes());
        let mut ctx = Ctx::new(image(&data, elf::EM_ARM, 4));
        let (index, mode) = string_index(&ctx, Arch::Arm, &[], &[]);
        assert_eq!(mode, Some(SWEEP_DEFAULT_THUMB));
        let bar = index
            .iter()
            .find(|s| s.value == "com/foo/Bar")
            .expect("indexée");
        assert_eq!((bar.target.as_str(), bar.encoding), ("0x2000", "utf8"));
        let r = bar
            .refs
            .iter()
            .find(|r| r.address == "0x1006")
            .expect("add r1, pc");
        assert_eq!(r.function.as_deref(), Some("0x1000"));
        assert_eq!(r.function_source, Some(SOURCE_PROLOGUE));

        ctx.symbols.insert(CODE, ("handler".to_string(), 0x14));
        let (index, _) = string_index(&ctx, Arch::Arm, &[], &[]);
        let bar = index.iter().find(|s| s.value == "com/foo/Bar").unwrap();
        let r = bar.refs.iter().find(|r| r.address == "0x1006").unwrap();
        assert_eq!(r.function_source, Some(SOURCE_SYMBOL));
    }

    #[test]
    fn mapping_symbols_choose_the_sweep_mode() {
        let data = [0u8; 16];
        let ctx = Ctx::new(image(&data, elf::EM_ARM, 4));
        let map = |name: &str, value: u64| DynSymbol {
            name: name.to_string(),
            defined: true,
            bind: elf::STB_LOCAL,
            value,
            size: 0,
            func: false,
        };
        let locals = [map("$t", 0x1000), map("$d.1", 0x1010), map("$a", 0x1020)];
        let (plan, label) = sweep_plan(&ctx, Arch::Arm, &locals);
        assert_eq!(label, Some(SWEEP_MAPPING));
        assert_eq!(plan.mode_at(0x1004), Some(true));
        assert_eq!(plan.mode_at(0x1014), None);
        assert_eq!(plan.next_mark(0x1014), Some(0x1020));
        assert_eq!(plan.mode_at(0x1024), Some(false));
        let (_, other) = sweep_plan(&ctx, Arch::Aarch64, &locals);
        assert_eq!(other, None);
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

    /// crtbegin de bionic ancien : r2 désigne un `b main`, tail-call de
    /// __libc_init par la PLT.
    const ARM_LIBC_INIT_THUNK: &[(u32, &str)] = &[
        (0xe1a0000d, "1000  mov  r0, sp"),
        (0xe3a01000, "1004  mov  r1, #0"),
        (0xe28f2004, "1008  add  r2, pc, #4     ; 0x1014"),
        (0xe28f3004, "100c  add  r3, pc, #4     ; 0x1018"),
        (0xea0001fa, "1010  b    0x1800         ; __libc_init@plt"),
        (0xea000039, "1014  b    0x1100         ; main"),
    ];

    #[test]
    fn arm_main_behind_a_branch_thunk_becomes_a_root() {
        let mut data = vec![0u8; 0x4000];
        assemble(&mut data, CODE, ARM_LIBC_INIT_THUNK);
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
    }

    /// main lu dans un emplacement de GOT (0x3010) que R_*_GLOB_DAT reloge sur
    /// le symbole défini main : le fichier y porte 0.
    const A64_LIBC_INIT_GOT: &[(u32, &str)] = &[
        (0xd0000002, "1000  adrp x2, 0x3000"),
        (0xf9400842, "1004  ldr  x2, [x2, #0x10]"),
        (0x940001fe, "1008  bl   0x1800         ; __libc_init@plt"),
        (0xd65f03c0, "100c  ret"),
    ];

    #[test]
    fn aarch64_main_from_a_got_slot_becomes_a_root() {
        let mut data = vec![0u8; 0x4000];
        assemble(&mut data, CODE, A64_LIBC_INIT_GOT);
        put(&mut data, 0x2100, &0xd65f03c0u32.to_le_bytes());
        assemble(&mut data, 0x1800, A64_PLT);
        let dynamic = jump_slot(&mut data, 0x3000, "__libc_init", false);
        let mut ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        ctx.got = got_imports(&ctx.image, &dynamic);
        ctx.got.insert(0x3010, "main".to_string());
        ctx.defined.insert("main".to_string(), 0x2100);
        let disasm = walk_functions(&ctx, vec![exec_entry(CODE)], &options(0, 100));
        let expected = [
            ("0x1000", ORIGIN_ENTRY, STATUS_OK),
            ("0x2100", ORIGIN_MAIN, STATUS_OK),
        ];
        assert_eq!(origins(&disasm), expected);
    }

    /// PIC ARM : décalage de GOT en littéral, puis `ldr r2, [pc, r2]`.
    const ARM_LIBC_INIT_PC_INDEXED: &[(u32, &str)] = &[
        (0xe59f2008, "1000  ldr  r2, [pc, #8]   ; 0x1010"),
        (0xe79f2002, "1004  ldr  r2, [pc, r2]   ; 0x100c + 0x2000"),
        (0xeb0001fc, "1008  bl   0x1800         ; __libc_init@plt"),
        (0xe12fff1e, "100c  bx   lr"),
        (
            0x00002000,
            "1010  littéral : décalage de l'emplacement de main",
        ),
    ];

    #[test]
    fn arm_main_through_a_pc_indexed_got_load_becomes_a_root() {
        let mut data = vec![0u8; 0x4000];
        assemble(&mut data, CODE, ARM_LIBC_INIT_PC_INDEXED);
        put(&mut data, 0x300c, &0x1100u32.to_le_bytes());
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

    /// JNIHelp : nom de classe en chaîne C, table JNINativeMethod en 0x2040.
    const A64_JNIHELP_REGISTER: &[(u32, &str)] = &[
        (0xb0000001, "1000  adrp x1, 0x2000"),
        (0x91000021, "1004  add  x1, x1, #0x0      ; com/foo/Bar"),
        (0xb0000002, "1008  adrp x2, 0x2000"),
        (0x91010042, "100c  add  x2, x2, #0x40     ; table"),
        (0x52800023, "1010  mov  w3, #1"),
        (
            0x940001fb,
            "1014  bl   0x1800            ; jniRegisterNativeMethods@plt",
        ),
        (0xd65f03c0, "1018  ret"),
    ];

    #[test]
    fn jnihelp_register_native_methods_registers_its_table() {
        let mut data = vec![0u8; 0x4000];
        strings(&mut data);
        assemble(&mut data, CODE, A64_JNIHELP_REGISTER);
        assemble(&mut data, 0x1800, A64_PLT);
        for (i, value) in [0x2010u64, 0x2018, 0x1100].into_iter().enumerate() {
            put(&mut data, 0x2040 + 8 * i as u64, &value.to_le_bytes());
        }
        put(&mut data, 0x1100, &0xd65f03c0u32.to_le_bytes());
        let dynamic = jump_slot(&mut data, 0x3000, JNIHELP_REGISTER, false);
        let mut ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        ctx.got = got_imports(&ctx.image, &dynamic);
        let out = analyze(&ctx, CODE, false);
        assert_eq!(jni_names(&out.function), [("RegisterNatives", 215, true)]);
        let call = &out.function.jni_calls[0];
        assert_eq!(call.form, FORM_JNIHELP);
        assert_eq!(call.class.as_deref(), Some("Lcom/foo/Bar;"));
        let run = member("Lcom/foo/Bar;", "run", "()V", Some(0x1100));
        assert_eq!(out.registered, [run]);
        let entry = RegisteredMethod {
            name: "run".into(),
            signature: "()V".into(),
            fn_offset: "0x1100".into(),
            table_offset: "0x2040".into(),
            thumb: false,
        };
        assert_eq!(out.tables, std::slice::from_ref(&entry));

        let mut elf = ElfReport::new("lib/arm64-v8a/libovpnutil.so", &[]);
        elf.jni.jni_onload = true;
        elf.jni.jni_registration = registration_status(&elf.jni);
        assert_eq!(elf.jni.jni_registration, "unresolved");
        elf.disasm = Some(ElfDisasm {
            tables_by_code: vec![entry.clone()],
            ..ElfDisasm::default()
        });
        adopt_tables(&mut elf);
        adopt_tables(&mut elf);
        assert_eq!(elf.jni.registered, [entry]);
        assert_eq!(elf.jni.jni_registration, "tables_found");
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
            veneer: None,
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
    fn invalid_entries_do_not_count_as_opaque_dead_code() {
        let mut data = vec![0u8; 0x2000];
        put(&mut data, CODE, &0xa2f2fff1u32.to_le_bytes());
        let ctx = Ctx::new(image(&data, elf::EM_AARCH64, 8));
        let function = analyze(&ctx, CODE, false).function;
        assert_eq!(function.disasm_status, STATUS_INVALID_ENTRY);
        assert_eq!(function.invalid_paths.len(), 1);
        let three = [function.clone(), function.clone(), function];
        assert_eq!(opaque_dead_code(&three), None);
    }

    #[test]
    fn listing_specs_parse_addresses_ranges_and_wildcards() {
        let spec = |elf: Option<&str>, start, end| ListingSpec {
            elf: elf.map(str::to_string),
            start,
            end,
        };
        let path = Some("lib/arm64-v8a/libx.so");
        let single = parse_listing_spec("lib/arm64-v8a/libx.so@0x1000");
        assert_eq!(single, Ok(spec(path, 0x1000, None)));
        let range = parse_listing_spec("lib/arm64-v8a/libx.so@1000-0x1020");
        assert_eq!(range, Ok(spec(path, 0x1000, Some(0x1020))));
        let any = parse_listing_spec("*@0x1001-0x1021");
        assert_eq!(any, Ok(spec(None, 0x1001, Some(0x1021))));
        assert_eq!(any.unwrap().to_string(), "*@0x1001-0x1021");
        let bad = [
            "libx.so",
            "@0x1000",
            "libx.so@",
            "libx.so@0xzz",
            "libx.so@0x1000-",
            "libx.so@0x1020-0x1000",
            "libx.so@0x1000-0x1000",
        ];
        for input in bad {
            assert!(parse_listing_spec(input).is_err(), "{input}");
        }
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
            FORM_JNIHELP,
            JNIHELP_REGISTER_CXX,
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
            "veneer",
            "e59fc000",
            ORIGIN_USER_ROOT,
            ORIGIN_EXPORT,
            SOURCE_SYMBOL,
            SOURCE_DISASM,
            SOURCE_PROLOGUE,
            SWEEP_MAPPING,
            SWEEP_FUNCTIONS,
            SWEEP_DEFAULT_THUMB,
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
        for label in labels
            .iter()
            .chain(NORETURN_IMPORTS)
            .chain(RUNTIME_PREFIXES)
        {
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
