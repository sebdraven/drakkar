//! `--native --native-symex` : propagation de valeurs symboliques dans une
//! fonction AArch64, chemin par chemin, sans solveur. Rien n'est exécuté.
//! Étiquettes définies dans [`super::legend`].

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet};
use std::fmt;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::panic::AssertUnwindSafe;
use std::rc::Rc;

use object::elf;
use serde::ser::{SerializeMap, Serializer};
use serde::Serialize;
use yaxpeax_arm::armv8::a64::{
    Instruction, Opcode as O, Operand, SIMDSizeCode, ShiftStyle, SizeCode,
};

use super::decode::{decode, decode_a64_full, Arch, Flow, Insn};
use super::disasm::{
    context, in_function, parse_listing_spec, plt_import, read_le, Ctx, ListingSpec,
    NORETURN_IMPORTS,
};
use super::native_strings::fde_ranges;
use super::{hex, parse_elf, ElfReport, Segment};

pub const DEFAULT_SYMEX_DEPTH: u8 = 0;
pub const MAX_SYMEX_DEPTH: u8 = 4;
pub const DEFAULT_SYMEX_MAX_INSNS: usize = 20_000;
pub const DEFAULT_SYMEX_MAX_PATHS: usize = 256;
pub const DEFAULT_SYMEX_FRAGMENT_MAX: u64 = 64;
pub const DEFAULT_SYMEX_CALLEE_FORKS: usize = 2;
pub const DEFAULT_SYMEX_REFINE: usize = 4;
pub const MAX_SYMEX_PEEK: u8 = 64;

const MAX_FRAGMENTS: u8 = 8;
const ARGS: usize = 9;

const INFINITE: u32 = u32::MAX;
const RANK_UNKNOWN: u32 = u32::MAX - 1;

const CONDITIONS: [&str; 16] = [
    "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
];

const MAX_VISITS: u8 = 2;
const MAX_TABLE_ENTRIES: u64 = 64;
const MAX_TABLE_SHIFT: u64 = 4;
const MAX_COPY: u64 = 4096;
const MAX_RUN: u64 = 16;
const MAX_EXPR_NODES: u32 = 256;
const MAX_TRACE: usize = 256;
const MAX_COPY_HOPS: usize = 4;

const COPY_IMPORTS: &[&str] = &["memcpy", "memmove", "__memcpy_chk", "__memmove_chk"];
const ATOMIC_PREFIXES: &[&str] = &[
    "swp", "cas", "ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin",
];

const SP: u8 = 31;
const V0: u8 = 32;

const STATUS_RETURNED: &str = "returned";
const STATUS_CUT_LOOP: &str = "cut_loop";
const STATUS_INDIRECT_BRANCH: &str = "indirect_branch";
const STATUS_BUDGET: &str = "budget";
const STATUS_NORETURN: &str = "noreturn";
const STATUS_TRAP: &str = "trap";
const STATUS_INVALID: &str = "invalid";
const STATUS_OFF_TARGET: &str = "off_target";

const KIND_LOAD: &str = "load";
const KIND_STORE: &str = "store";
const KIND_CALL: &str = "call";
const KIND_BRANCH: &str = "branch";
const KIND_DEF: &str = "def";
const KIND_OTHER: &str = "other";

const CALL_INDIRECT: &str = "indirect";
const CALL_DIRECT: &str = "direct";
const CALL_COPY: &str = "copy";
const CALL_INDIRECT_TAIL: &str = "indirect_tail";
const CALL_ABANDONED: &str = "abandoned";

/// Registres que l'appelé rend intacts (AAPCS64) : x19..x29 et sp.
const PRESERVED: [usize; 12] = [19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 31];

const BOUND_SYMBOL: &str = "symbol";
const BOUND_EH_FRAME: &str = "eh_frame";
const BOUND_NONE: &str = "none";

/// Réglages de `--native-symex`.
#[derive(Debug, Clone)]
pub struct SymexOptions {
    pub watch: Vec<u64>,
    pub entry: Option<u64>,
    pub depth: u8,
    pub max_insns: usize,
    pub max_paths: usize,
    /// Taille maximale d'un morceau externalisé, en octets ; 0 : aucun.
    pub fragment_max: u64,
    /// Chemins frères qu'un appel suivi depuis la fonction analysée peut ouvrir.
    pub callee_forks: usize,
    /// Relances au plus ; 0 : aucun raffinement.
    pub refine: usize,
    /// Adresses d'appel suivies quelle que soit la profondeur.
    pub follow: Vec<u64>,
    /// Élagage et ordre par distance aux watches.
    pub directed: bool,
    pub peek: Vec<SymexPeek>,
}

/// `len` octets à registre + `offset`, lus au watch `watch` avant son effet.
#[derive(Debug, Clone, PartialEq)]
pub struct SymexPeek {
    pub watch: u64,
    pub reg: u8,
    pub offset: i64,
    pub len: u8,
}

impl Default for SymexOptions {
    fn default() -> Self {
        SymexOptions {
            watch: Vec::new(),
            entry: None,
            depth: DEFAULT_SYMEX_DEPTH,
            max_insns: DEFAULT_SYMEX_MAX_INSNS,
            max_paths: DEFAULT_SYMEX_MAX_PATHS,
            fragment_max: DEFAULT_SYMEX_FRAGMENT_MAX,
            callee_forks: DEFAULT_SYMEX_CALLEE_FORKS,
            refine: DEFAULT_SYMEX_REFINE,
            follow: Vec::new(),
            directed: true,
            peek: Vec::new(),
        }
    }
}

/// `<elf|*>@<début>` : le sélecteur de `--native-listing`, sans plage.
pub fn parse_symex_spec(spec: &str) -> Result<ListingSpec, String> {
    let parsed = parse_listing_spec(spec)?;
    if parsed.end.is_some() {
        return Err("une fonction, pas une plage : <elf|*>@<début>".into());
    }
    Ok(parsed)
}

/// Adresse hexadécimale, préfixe `0x` facultatif.
pub fn parse_symex_address(text: &str) -> Result<u64, String> {
    let trimmed = text.trim();
    let digits = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let invalid = || format!("adresse hexadécimale invalide : {text:?}");
    u64::from_str_radix(digits, 16).map_err(|_| invalid())
}

/// `<watch>:<registre>+<décalage>:<longueur>`, `watch` pris dans `watches`.
pub fn parse_symex_peek(item: &str, watches: &[u64]) -> Result<SymexPeek, String> {
    let fail = |why: String| format!("élément {item:?} : {why}");
    let parts: Vec<&str> = item.trim().split(':').collect();
    let [watch, place, len] = parts.as_slice() else {
        return Err(fail(
            "attendu <watch>:<registre>+<décalage>:<longueur>".into(),
        ));
    };
    let watch = parse_symex_address(watch).map_err(fail)?;
    if !watches.contains(&watch) {
        return Err(fail(format!(
            "{} absente de --native-symex-watch",
            hex(watch)
        )));
    }
    let (reg, offset) = parse_peek_place(place).map_err(fail)?;
    let invalid = || fail(format!("longueur {len:?} : de 1 à {MAX_SYMEX_PEEK} octets"));
    let len = len.trim().parse::<u8>().map_err(|_| invalid())?;
    if !(1..=MAX_SYMEX_PEEK).contains(&len) {
        return Err(invalid());
    }
    Ok(SymexPeek {
        watch,
        reg,
        offset,
        len,
    })
}

/// `x0..x30` ou `sp`, puis `+` ou `-` et un décalage décimal ou `0x`.
fn parse_peek_place(text: &str) -> Result<(u8, i64), String> {
    let text = text.trim();
    let missing = || format!("{text:?} : attendu <registre>+<décalage>");
    let at = text.find(['+', '-']).ok_or_else(missing)?;
    let (name, offset) = text.split_at(at);
    let reg = match name {
        "sp" => SP,
        _ => match name.strip_prefix('x').and_then(|n| n.parse::<u8>().ok()) {
            Some(n) if n <= 30 => n,
            _ => return Err(format!("registre {name:?} : x0..x30 ou sp")),
        },
    };
    let mut negative = offset.starts_with('-');
    let mut digits = &offset[1..];
    if let Some(rest) = digits.strip_prefix('-') {
        negative = !negative;
        digits = rest;
    }
    let magnitude = match digits.strip_prefix("0x") {
        _ if digits.contains('+') => None,
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => digits.parse::<u64>().ok(),
    };
    let invalid = || format!("décalage {offset:?} : décimal ou 0x hexadécimal");
    let magnitude = magnitude.ok_or_else(invalid)?;
    let magnitude = i64::try_from(magnitude).map_err(|_| invalid())?;
    let offset = if negative { -magnitude } else { magnitude };
    Ok((reg, offset))
}

#[derive(Debug, Clone, Serialize)]
pub struct SymexReport {
    pub elf: String,
    pub fn_start: String,
    pub fn_end: Option<String>,
    pub bound: &'static str,
    pub entry: String,
    pub budgets: SymexBudgets,
    pub directed: bool,
    pub rounds: Vec<SymexRound>,
    pub paths_explored: usize,
    pub paths_cut: BTreeMap<&'static str, usize>,
    pub budget_hit: bool,
    pub callees_abandoned: usize,
    pub callees_incomplete: usize,
    pub forks_dropped: usize,
    pub watches: Vec<SymexWatch>,
    pub calls: Vec<SymexCall>,
    pub indirect_branches: Vec<SymexBranch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymexBudgets {
    pub depth: u8,
    pub max_insns: usize,
    pub max_paths: usize,
    pub fragment_max: u64,
    pub callee_forks: usize,
    pub refine: usize,
}

/// Une exploration complète de la fonction : 0 pour la première, puis une par
/// relance.
#[derive(Debug, Clone, Serialize)]
pub struct SymexRound {
    pub round: usize,
    pub follow: Vec<String>,
    pub paths: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymexWatch {
    pub insn_addr: String,
    pub instruction: Option<String>,
    pub reached: bool,
    pub results: Vec<SymexResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymexResult {
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Shown>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Shown>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value2: Option<Shown>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<Shown>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<Shown>,
    pub sp: Shown,
    pub paths: usize,
    pub trace: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub trace_truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub peeks: Vec<SymexPeeked>,
}

/// Une lecture de `--native-symex-peek` : `bytes` aux adresses croissantes.
#[derive(Debug, Clone, Serialize)]
pub struct SymexPeeked {
    pub reg: String,
    pub offset: String,
    pub len: u8,
    pub address: Shown,
    pub bytes: Vec<Shown>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymexCall {
    pub insn_addr: String,
    pub kind: &'static str,
    pub target: Shown,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import: Option<String>,
    pub args: Vec<String>,
    pub paths: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymexBranch {
    pub insn_addr: String,
    pub target: Shown,
    pub paths: usize,
}

/// Une expression : texte stable et arbre JSON.
#[derive(Debug, Clone, Serialize)]
pub struct Shown {
    pub text: String,
    pub expr: serde_json::Value,
}

impl Shown {
    fn of(expr: &Expr) -> Shown {
        Shown {
            text: expr.to_string(),
            expr: serde_json::to_value(expr).unwrap_or(serde_json::Value::Null),
        }
    }
}

impl SymexResult {
    /// Une ligne pour la sortie texte.
    pub fn summary(&self) -> String {
        let text = |shown: &Option<Shown>| match shown {
            Some(shown) => shown.text.clone(),
            None => "?".to_string(),
        };
        let head = match self.kind {
            KIND_LOAD | KIND_STORE => {
                let arrow = if self.kind == KIND_LOAD { "=" } else { "←" };
                let second = match &self.value2 {
                    Some(v) => format!(", {}", v.text),
                    None => String::new(),
                };
                let (address, value) = (text(&self.address), text(&self.value));
                format!("{} [{address}] {arrow} {value}{second}", self.kind)
            }
            KIND_CALL | KIND_BRANCH => {
                let args: Vec<&str> = self.args.iter().map(|a| a.text.as_str()).collect();
                let target = text(&self.target);
                format!("{} {target}  x0..x3 = {}", self.kind, args.join(", "))
            }
            KIND_DEF => format!("{} = {}", self.kind, text(&self.value)),
            _ => self.kind.to_string(),
        };
        format!("{head}  sp = {}", self.sp.text)
    }
}

/// `fn_start` dans l'ELF `bytes` que décrit `elf`. `Ok(None)` : `fn_start`
/// hors de tout segment LOAD exécutable de cet ELF.
pub(super) fn run(
    bytes: &[u8],
    elf: &ElfReport,
    fn_start: u64,
    options: &SymexOptions,
) -> Result<Option<SymexReport>, String> {
    let parsed = parse_elf(bytes).map_err(|e| format!("ELF illisible ({e})"))?;
    let dynamic = parsed.dynamic.as_deref();
    let ctx = context(
        parsed.image,
        dynamic,
        &parsed.symbols,
        &parsed.local_symbols,
    );
    if ctx.arch != Some(Arch::Aarch64) {
        return Err(format!("machine {} : AArch64 seulement", elf.machine));
    }
    if !ctx.image.is_exec(fn_start) {
        return Ok(None);
    }
    let fdes = fde_ranges(&ctx.image);
    let entry = options.entry.unwrap_or(fn_start);
    if !Bound::of(&ctx, &fdes, fn_start).contains(&ctx, entry) {
        let (entry, start) = (hex(entry), hex(fn_start));
        return Err(format!("entrée {entry} hors de la fonction {start}"));
    }
    let job = AssertUnwindSafe(|| analyze(&ctx, &fdes, &elf.path, fn_start, entry, options));
    let report =
        std::panic::catch_unwind(job).map_err(|_| "panique pendant la propagation".to_string())?;
    Ok(Some(report))
}

/// Explorations successives : chacune suit les appels de la précédente plus ceux
/// que le raffinement désigne, jusqu'à ce qu'il n'en désigne plus aucun ou que
/// `refine` relances aient eu lieu. Les relevés sont ceux de la dernière.
fn analyze(
    ctx: &Ctx,
    fdes: &[(u64, u64)],
    elf: &str,
    fn_start: u64,
    entry: u64,
    options: &SymexOptions,
) -> SymexReport {
    let bound = Bound::of(ctx, fdes, fn_start);
    let cfg = if options.directed {
        Cfg::build(ctx, &bound, &options.watch)
    } else {
        None
    };
    let mut follow: BTreeSet<u64> = options.follow.iter().copied().collect();
    let mut rounds = Vec::new();
    loop {
        let (mut report, wanted, paths) = {
            let mut explorer = Explorer::new(ctx, fdes, cfg.as_ref(), &follow, options);
            explorer.run(fn_start, entry);
            let report = explorer.report(elf, fn_start, entry);
            (report, explorer.wanted, explorer.started)
        };
        rounds.push(SymexRound {
            round: rounds.len(),
            follow: follow.iter().map(|&at| hex(at)).collect(),
            paths,
        });
        let added: Vec<u64> = wanted.difference(&follow).copied().collect();
        if added.is_empty() || rounds.len() > options.refine {
            report.rounds = rounds;
            return report;
        }
        follow.extend(added);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Op {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Lsl,
    Lsr,
    Asr,
    Mul,
}

impl Op {
    #[cfg(test)]
    const ALL: [Op; 9] = [
        Op::Add,
        Op::Sub,
        Op::And,
        Op::Or,
        Op::Xor,
        Op::Lsl,
        Op::Lsr,
        Op::Asr,
        Op::Mul,
    ];

    fn name(self) -> &'static str {
        match self {
            Op::Add => "add",
            Op::Sub => "sub",
            Op::And => "and",
            Op::Or => "or",
            Op::Xor => "xor",
            Op::Lsl => "lsl",
            Op::Lsr => "lsr",
            Op::Asr => "asr",
            Op::Mul => "mul",
        }
    }

    /// Majorant du nombre de bits significatifs du résultat.
    fn bits(self, a: &Expr, b: &Expr) -> u8 {
        let (x, y) = (a.bits(), b.bits());
        let shift = |k: Option<u64>| match k {
            Some(k) => u8::try_from(u64::from(x).saturating_sub(k)).unwrap_or(0),
            None => x,
        };
        match self {
            Op::Add => x.max(y).saturating_add(1).min(64),
            Op::Sub => 64,
            Op::And => x.min(y),
            Op::Or | Op::Xor => x.max(y),
            Op::Mul => x.saturating_add(y).min(64),
            Op::Lsl => match b.as_const() {
                Some(k) if k < 64 => (u64::from(x) + k).min(64) as u8,
                _ => 64,
            },
            Op::Lsr => shift(b.as_const()),
            Op::Asr if x < 64 => shift(b.as_const()),
            Op::Asr => 64,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Reason {
    CallNotFollowed,
    IndirectCall,
    UnsupportedInsn,
    Budget,
    Havoc,
}

impl Reason {
    #[cfg(test)]
    const ALL: [Reason; 5] = [
        Reason::CallNotFollowed,
        Reason::IndirectCall,
        Reason::UnsupportedInsn,
        Reason::Budget,
        Reason::Havoc,
    ];

    fn label(self) -> &'static str {
        match self {
            Reason::CallNotFollowed => "call_not_followed",
            Reason::IndirectCall => "indirect_call",
            Reason::UnsupportedInsn => "unsupported_insn",
            Reason::Budget => "budget",
            Reason::Havoc => "havoc",
        }
    }
}

/// Où l'inconnue est née : registre, ou décalage depuis le début de la zone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Slot {
    Reg(u8),
    Off(i64),
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Slot::Reg(reg) => f.write_str(&reg_name(reg)),
            Slot::Off(off) if off < 0 => write!(f, "-{:#x}", off.unsigned_abs()),
            Slot::Off(off) => write!(f, "+{off:#x}"),
        }
    }
}

/// Condition opaque : code de condition testé par l'instruction en `at`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Cond {
    at: u64,
    code: u8,
}

impl fmt::Display for Cond {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = CONDITIONS[usize::from(self.code & 0xf)];
        write!(f, "{name}@{:#x}", self.at)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Kind {
    Const(u64),
    Global(u64),
    Init(u8),
    Load(u8, Expr),
    Bin(Op, Expr, Expr),
    Zext(u8, Expr),
    Sext(u8, Expr),
    Trunc(u8, Expr),
    Ite(Cond, Expr, Expr),
    Unknown(Reason, u64, Slot),
}

/// Valeur symbolique, normalisée à la construction. Partagée : cloner ne copie
/// pas l'arbre.
#[derive(Clone)]
struct Expr(Rc<Node>);

struct Node {
    kind: Kind,
    hash: u64,
    size: u32,
    bits: u8,
}

impl PartialEq for Expr {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
            || (self.0.hash == other.0.hash && self.0.kind == other.0.kind)
    }
}

impl Eq for Expr {}

impl Hash for Expr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.0.hash);
    }
}

impl PartialOrd for Expr {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Expr {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if Rc::ptr_eq(&self.0, &other.0) {
            return std::cmp::Ordering::Equal;
        }
        self.0.kind.cmp(&other.0.kind)
    }
}

impl fmt::Debug for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind() {
            Kind::Const(value) => write!(f, "{value:#x}"),
            Kind::Global(at) => write!(f, "global({at:#x})"),
            Kind::Init(reg) => write!(f, "init({})", reg_name(*reg)),
            Kind::Load(size, addr) => write!(f, "load({size}, {addr})"),
            Kind::Bin(Op::Add, a, b) => match b.as_const() {
                Some(c) if (c as i64) < 0 => write!(f, "{a} - {:#x}", (c as i64).unsigned_abs()),
                _ => write!(f, "{a} + {b}"),
            },
            Kind::Bin(op, a, b) => write!(f, "{}({a}, {b})", op.name()),
            Kind::Zext(bits, e) => write!(f, "zext{bits}({e})"),
            Kind::Sext(bits, e) => write!(f, "sext{bits}({e})"),
            Kind::Trunc(bits, e) => write!(f, "trunc{bits}({e})"),
            Kind::Ite(cond, a, b) => write!(f, "ite({cond}, {a}, {b})"),
            Kind::Unknown(reason, at, slot) => {
                write!(f, "unknown({}, {at:#x}, {slot})", reason.label())
            }
        }
    }
}

#[derive(Serialize)]
struct LoadOut<'e> {
    size: u8,
    addr: &'e Expr,
}

#[derive(Serialize)]
struct ExtOut<'e> {
    bits: u8,
    of: &'e Expr,
}

#[derive(Serialize)]
struct IteOut<'e> {
    cond: String,
    then: &'e Expr,
    #[serde(rename = "else")]
    otherwise: &'e Expr,
}

#[derive(Serialize)]
struct UnknownOut {
    reason: &'static str,
    insn: String,
    slot: String,
}

impl Serialize for Expr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        match self.kind() {
            Kind::Const(value) => map.serialize_entry("const", &hex(*value))?,
            Kind::Global(at) => map.serialize_entry("global", &hex(*at))?,
            Kind::Init(reg) => map.serialize_entry("init", &reg_name(*reg))?,
            Kind::Load(size, addr) => {
                map.serialize_entry("load", &LoadOut { size: *size, addr })?
            }
            Kind::Bin(op, a, b) => map.serialize_entry(op.name(), &(a, b))?,
            Kind::Zext(bits, of) => map.serialize_entry("zext", &ExtOut { bits: *bits, of })?,
            Kind::Sext(bits, of) => map.serialize_entry("sext", &ExtOut { bits: *bits, of })?,
            Kind::Trunc(bits, of) => map.serialize_entry("trunc", &ExtOut { bits: *bits, of })?,
            Kind::Ite(cond, then, otherwise) => {
                let out = IteOut {
                    cond: cond.to_string(),
                    then,
                    otherwise,
                };
                map.serialize_entry("ite", &out)?
            }
            Kind::Unknown(reason, at, slot) => {
                let out = UnknownOut {
                    reason: reason.label(),
                    insn: hex(*at),
                    slot: slot.to_string(),
                };
                map.serialize_entry("unknown", &out)?
            }
        }
        map.end()
    }
}

impl Expr {
    fn make(kind: Kind) -> Expr {
        let mut hasher = DefaultHasher::new();
        kind.hash(&mut hasher);
        let (size, bits) = measure(&kind);
        Expr(Rc::new(Node {
            hash: hasher.finish(),
            size,
            bits,
            kind,
        }))
    }

    fn global(at: u64) -> Expr {
        Expr::make(Kind::Global(at))
    }

    fn init(reg: u8) -> Expr {
        Expr::make(Kind::Init(reg))
    }

    fn kind(&self) -> &Kind {
        &self.0.kind
    }

    fn size(&self) -> u32 {
        self.0.size
    }

    fn bits(&self) -> u8 {
        self.0.bits
    }

    fn as_const(&self) -> Option<u64> {
        match self.kind() {
            Kind::Const(value) => Some(*value),
            _ => None,
        }
    }
}

/// Nœuds de l'arbre, et majorant de ses bits significatifs (128 pour une valeur
/// vectorielle entière).
fn measure(kind: &Kind) -> (u32, u8) {
    match kind {
        Kind::Const(value) | Kind::Global(value) => (1, significant(*value)),
        Kind::Init(reg) => (1, if *reg >= V0 { 128 } else { 64 }),
        Kind::Load(size, addr) => (addr.size().saturating_add(1), size.saturating_mul(8)),
        Kind::Bin(op, a, b) => (
            a.size().saturating_add(b.size()).saturating_add(1),
            op.bits(a, b),
        ),
        Kind::Zext(bits, e) | Kind::Trunc(bits, e) => (e.size().saturating_add(1), *bits),
        Kind::Sext(_, e) => (e.size().saturating_add(1), 64),
        Kind::Ite(_, a, b) => (
            a.size().saturating_add(b.size()).saturating_add(1),
            a.bits().max(b.bits()),
        ),
        Kind::Unknown(_, _, Slot::Reg(reg)) if *reg < V0 => (1, 64),
        Kind::Unknown(..) => (1, 128),
    }
}

fn significant(value: u64) -> u8 {
    (64 - value.leading_zeros()) as u8
}

fn mask(bits: u8) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn sign_extend(value: u64, bits: u8) -> u64 {
    if bits == 0 || bits >= 64 {
        return value;
    }
    let shift = 64 - u32::from(bits);
    (((value << shift) as i64) >> shift) as u64
}

fn reg_name(reg: u8) -> String {
    match reg {
        SP => "sp".to_string(),
        r if r >= V0 => format!("q{}", r - V0),
        r => format!("x{r}"),
    }
}

fn konst(value: u64) -> Expr {
    Expr::make(Kind::Const(value))
}

fn load(size: u8, addr: &Expr) -> Expr {
    Expr::make(Kind::Load(size, addr.clone()))
}

fn unknown(reason: Reason, at: u64, slot: Slot) -> Expr {
    Expr::make(Kind::Unknown(reason, at, slot))
}

/// `a` si `cond` est vraie, `b` sinon ; non distribué par les opérations.
fn ite(cond: Cond, a: &Expr, b: &Expr) -> Expr {
    if a == b {
        return a.clone();
    }
    Expr::make(Kind::Ite(cond, a.clone(), b.clone()))
}

fn raw(op: Op, a: &Expr, b: &Expr) -> Expr {
    Expr::make(Kind::Bin(op, a.clone(), b.clone()))
}

/// Opérandes d'une opération commutative : constante à droite, sinon ordre
/// canonique.
fn ordered(a: &Expr, b: &Expr) -> (Expr, Expr) {
    let swap = match (a.as_const(), b.as_const()) {
        (Some(_), None) => true,
        (None, None) => a > b,
        _ => false,
    };
    if swap {
        (b.clone(), a.clone())
    } else {
        (a.clone(), b.clone())
    }
}

/// Somme aplatie : termes positifs et négatifs triés, constantes repliées dans
/// `off`. `global` : un terme global(g) unique, replié lui aussi dans `off`.
#[derive(Default)]
struct Sum {
    pos: Vec<Expr>,
    neg: Vec<Expr>,
    off: u64,
    global: bool,
}

impl Sum {
    fn of(e: &Expr) -> Sum {
        let mut sum = Sum::default();
        sum.collect(e, true);
        sum.settle();
        sum
    }

    fn collect(&mut self, e: &Expr, plus: bool) {
        match e.kind() {
            Kind::Const(c) if plus => self.off = self.off.wrapping_add(*c),
            Kind::Const(c) => self.off = self.off.wrapping_sub(*c),
            Kind::Bin(Op::Add, x, y) => {
                self.collect(x, plus);
                self.collect(y, plus);
            }
            Kind::Bin(Op::Sub, x, y) => {
                self.collect(x, plus);
                self.collect(y, !plus);
            }
            _ if plus => self.pos.push(e.clone()),
            _ => self.neg.push(e.clone()),
        }
    }

    fn settle(&mut self) {
        let mut i = 0;
        while i < self.neg.len() {
            match self.pos.iter().position(|p| *p == self.neg[i]) {
                Some(j) => {
                    self.pos.swap_remove(j);
                    self.neg.swap_remove(i);
                }
                None => i += 1,
            }
        }
        let globals = |terms: &mut Vec<Expr>| {
            let mut found = Vec::new();
            terms.retain(|t| match t.kind() {
                Kind::Global(g) => {
                    found.push(*g);
                    false
                }
                _ => true,
            });
            found
        };
        let mut plus = globals(&mut self.pos);
        let mut minus = globals(&mut self.neg);
        while let (Some(p), Some(m)) = (plus.last(), minus.last()) {
            self.off = self.off.wrapping_add(p.wrapping_sub(*m));
            plus.pop();
            minus.pop();
        }
        if minus.is_empty() && plus.len() == 1 && !self.global {
            self.off = self.off.wrapping_add(plus[0]);
            self.global = true;
        } else {
            self.pos.extend(plus.into_iter().map(Expr::global));
            self.neg.extend(minus.into_iter().map(Expr::global));
        }
        self.pos.sort();
        self.neg.sort();
    }

    fn build(mut self) -> Expr {
        self.settle();
        let mut e = chain(&self.pos);
        if let Some(negative) = chain(&self.neg) {
            let positive = e.unwrap_or_else(|| konst(0));
            e = Some(raw(Op::Sub, &positive, &negative));
        }
        let tail = if self.global {
            Some(Expr::global(self.off))
        } else if self.off != 0 {
            Some(konst(self.off))
        } else {
            None
        };
        match (e, tail) {
            (Some(e), Some(tail)) => raw(Op::Add, &e, &tail),
            (Some(e), None) => e,
            (None, Some(tail)) => tail,
            (None, None) => konst(0),
        }
    }
}

fn chain(terms: &[Expr]) -> Option<Expr> {
    terms.iter().cloned().reduce(|a, b| raw(Op::Add, &a, &b))
}

fn add(a: &Expr, b: &Expr) -> Expr {
    let mut sum = Sum::default();
    sum.collect(a, true);
    sum.collect(b, true);
    sum.build()
}

fn sub(a: &Expr, b: &Expr) -> Expr {
    let mut sum = Sum::default();
    sum.collect(a, true);
    sum.collect(b, false);
    sum.build()
}

/// Base et décalage d'une adresse. Une adresse absolue (constante ou global)
/// a pour base global(0).
fn split(addr: &Expr) -> (Expr, i64) {
    let mut sum = Sum::of(addr);
    let off = sum.off as i64;
    sum.off = 0;
    if sum.pos.is_empty() && sum.neg.is_empty() {
        sum.global = true;
    }
    (sum.build(), off)
}

fn and(a: &Expr, b: &Expr) -> Expr {
    let (a, b) = ordered(a, b);
    if let (Some(x), Some(y)) = (a.as_const(), b.as_const()) {
        return konst(x & y);
    }
    if let Some(m) = b.as_const() {
        if m == 0 {
            return konst(0);
        }
        if a.bits() <= 64 && mask(a.bits()) & !m == 0 {
            return a;
        }
        match a.kind() {
            Kind::Zext(n, x) | Kind::Trunc(n, x) if significant(m) <= *n => return and(x, &b),
            Kind::Bin(Op::And, x, y) => {
                if let Some(inner) = y.as_const() {
                    return and(x, &konst(m & inner));
                }
            }
            _ => {}
        }
        if m.wrapping_add(1) & m == 0 {
            return zext(significant(m), &a);
        }
        return raw(Op::And, &a, &b);
    }
    if a == b {
        return a;
    }
    raw(Op::And, &a, &b)
}

fn or(a: &Expr, b: &Expr) -> Expr {
    let (a, b) = ordered(a, b);
    match (a.as_const(), b.as_const()) {
        (Some(x), Some(y)) => konst(x | y),
        (_, Some(0)) => a,
        _ if a == b => a,
        _ => raw(Op::Or, &a, &b),
    }
}

fn xor(a: &Expr, b: &Expr) -> Expr {
    let (a, b) = ordered(a, b);
    match (a.as_const(), b.as_const()) {
        (Some(x), Some(y)) => konst(x ^ y),
        (_, Some(0)) => a,
        _ if a == b => konst(0),
        _ => raw(Op::Xor, &a, &b),
    }
}

fn mul(a: &Expr, b: &Expr) -> Expr {
    let (a, b) = ordered(a, b);
    match (a.as_const(), b.as_const()) {
        (Some(x), Some(y)) => konst(x.wrapping_mul(y)),
        (_, Some(0)) => konst(0),
        (_, Some(1)) => a,
        _ => raw(Op::Mul, &a, &b),
    }
}

fn lsl(a: &Expr, b: &Expr) -> Expr {
    match (a.as_const(), b.as_const()) {
        (_, Some(0)) => a.clone(),
        (_, Some(k)) if k >= 64 && a.bits() <= 64 => konst(0),
        (Some(x), Some(k)) if k < 64 => konst(x << k),
        (None, Some(k)) => match a.kind() {
            Kind::Bin(Op::Lsl, x, j) => match j.as_const() {
                Some(j) if j < 64 && k < 64 - j => lsl(x, &konst(j + k)),
                _ => raw(Op::Lsl, a, b),
            },
            _ => raw(Op::Lsl, a, b),
        },
        _ => raw(Op::Lsl, a, b),
    }
}

fn lsr(a: &Expr, b: &Expr) -> Expr {
    match (a.as_const(), b.as_const()) {
        (_, Some(0)) => a.clone(),
        (_, Some(k)) if k >= u64::from(a.bits()) => konst(0),
        (Some(x), Some(k)) if k < 64 => konst(x >> k),
        _ => raw(Op::Lsr, a, b),
    }
}

fn asr(a: &Expr, b: &Expr) -> Expr {
    match (a.as_const(), b.as_const()) {
        (_, Some(0)) => a.clone(),
        (Some(x), Some(k)) => konst(((x as i64) >> k.min(63)) as u64),
        _ if a.bits() < 64 => lsr(a, b),
        _ => raw(Op::Asr, a, b),
    }
}

/// `bits` bits de poids faible, étendus par des zéros. Hors de 8, 16 et 32,
/// s'écrit `and` avec le masque.
fn zext(bits: u8, e: &Expr) -> Expr {
    if bits >= 64 || e.bits() <= bits {
        return e.clone();
    }
    if let Some(value) = e.as_const() {
        return konst(value & mask(bits));
    }
    match e.kind() {
        Kind::Zext(n, x) | Kind::Trunc(n, x) => return zext(bits.min(*n), x),
        Kind::Sext(n, x) if bits <= *n => return zext(bits, x),
        Kind::Bin(Op::And, x, y) => {
            if let Some(m) = y.as_const() {
                return and(x, &konst(m & mask(bits)));
            }
        }
        _ => {}
    }
    if matches!(bits, 8 | 16 | 32) {
        Expr::make(Kind::Zext(bits, e.clone()))
    } else {
        raw(Op::And, e, &konst(mask(bits)))
    }
}

fn sext(bits: u8, e: &Expr) -> Expr {
    if bits >= 64 || e.bits() < bits {
        return e.clone();
    }
    if let Some(value) = e.as_const() {
        return konst(sign_extend(value, bits));
    }
    match e.kind() {
        Kind::Sext(n, _) if *n <= bits => return e.clone(),
        Kind::Zext(n, x) | Kind::Trunc(n, x) if *n >= bits => return sext(bits, x),
        _ => {}
    }
    Expr::make(Kind::Sext(bits, e.clone()))
}

fn trunc(bits: u8, e: &Expr) -> Expr {
    if e.bits() <= bits {
        return e.clone();
    }
    if let Some(value) = e.as_const() {
        return konst(value & mask(bits));
    }
    match e.kind() {
        Kind::Zext(n, x) | Kind::Trunc(n, x) => return trunc(bits.min(*n), x),
        Kind::Sext(n, x) if bits <= *n => return trunc(bits, x),
        _ => {}
    }
    Expr::make(Kind::Trunc(bits, e.clone()))
}

/// Instructions qui ont produit ou déplacé une valeur : graphe partagé entre
/// les valeurs qui en dérivent.
#[derive(Clone, Default)]
struct Trace(Option<Rc<Def>>);

struct Def {
    at: u64,
    step: u32,
    from: Vec<Trace>,
}

impl Drop for Def {
    fn drop(&mut self) {
        let mut stack: Vec<Rc<Def>> = self.from.drain(..).filter_map(|t| t.0).collect();
        while let Some(def) = stack.pop() {
            if let Ok(mut def) = Rc::try_unwrap(def) {
                stack.extend(def.from.drain(..).filter_map(|t| t.0));
            }
        }
    }
}

impl Trace {
    fn new(at: u64, step: u32, mut from: Vec<Trace>) -> Trace {
        from.retain(|t| t.0.is_some());
        Trace(Some(Rc::new(Def { at, step, from })))
    }

    fn same(&self, other: &Trace) -> bool {
        match (&self.0, &other.0) {
            (Some(a), Some(b)) => Rc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        }
    }

    /// Adresses, dans l'ordre d'exécution ; les [`MAX_TRACE`] dernières, et
    /// vrai si d'autres ont été écartées.
    fn addresses(&self) -> (Vec<u64>, bool) {
        let mut seen = HashSet::new();
        let mut steps = Vec::new();
        let mut stack: Vec<&Rc<Def>> = self.0.iter().collect();
        while let Some(def) = stack.pop() {
            if !seen.insert(Rc::as_ptr(def)) {
                continue;
            }
            steps.push((def.step, def.at));
            stack.extend(def.from.iter().filter_map(|t| t.0.as_ref()));
        }
        steps.sort_unstable();
        steps.dedup();
        let skip = steps.len().saturating_sub(MAX_TRACE);
        let addresses = steps[skip..].iter().map(|&(_, at)| at).collect();
        (addresses, skip > 0)
    }
}

#[derive(Clone, Copy)]
struct At {
    addr: u64,
    step: u32,
}

impl At {
    fn def(self, from: &[&Trace]) -> Trace {
        let from = from.iter().copied().cloned().collect();
        Trace::new(self.addr, self.step, from)
    }

    fn def_all(self, from: &[Trace]) -> Trace {
        Trace::new(self.addr, self.step, from.to_vec())
    }

    fn origin(self) -> Trace {
        Trace::new(self.addr, self.step, Vec::new())
    }
}

#[derive(Clone)]
struct Val {
    expr: Expr,
    trace: Trace,
}

impl Val {
    fn new(expr: Expr, trace: Trace) -> Val {
        Val { expr, trace }
    }

    fn plain(expr: Expr) -> Val {
        Val {
            expr,
            trace: Trace::default(),
        }
    }
}

/// Octet `byte` (petit-boutiste) d'une valeur de `width` octets.
#[derive(Clone)]
struct Cell {
    value: Expr,
    byte: u8,
    width: u8,
    trace: Trace,
}

impl Cell {
    fn moved(&self, at: At) -> Cell {
        Cell {
            trace: at.def(&[&self.trace]),
            ..self.clone()
        }
    }
}

fn zero() -> Cell {
    Cell {
        value: konst(0),
        byte: 0,
        width: 1,
        trace: Trace::default(),
    }
}

fn whole(value: &Expr, width: u8, trace: &Trace) -> Vec<Cell> {
    (0..width)
        .map(|byte| Cell {
            value: value.clone(),
            byte,
            width,
            trace: trace.clone(),
        })
        .collect()
}

/// Valeur de `width` octets de `value`, à partir de l'octet `byte`.
fn extract(value: &Expr, width: u8, byte: u8, len: u8) -> Expr {
    if byte == 0 && len == width {
        return value.clone();
    }
    if let Kind::Load(size, addr) = value.kind() {
        if *size == width {
            return load(len, &add(addr, &konst(u64::from(byte))));
        }
    }
    trunc(8 * len, &lsr(value, &konst(8 * u64::from(byte))))
}

/// `a` (une lecture entière de `a_len` octets) suivie de `b` en mémoire : une
/// seule lecture.
fn coalesce(a: &Expr, a_len: u64, b: &Expr) -> Option<Expr> {
    let (Kind::Load(n, x), Kind::Load(m, y)) = (a.kind(), b.kind()) else {
        return None;
    };
    if u64::from(*n) != a_len || n + m > 16 {
        return None;
    }
    let (base_x, off_x) = split(x);
    let (base_y, off_y) = split(y);
    (base_x == base_y && off_y == off_x.wrapping_add(i64::from(*n))).then(|| load(n + m, x))
}

/// Valeur des octets `cells`, dans l'ordre, et les traces qui y mènent.
fn assemble(cells: &[Cell]) -> (Expr, Vec<Trace>) {
    let mut parts: Vec<(Expr, u64, u64)> = Vec::new();
    let mut traces: Vec<Trace> = Vec::new();
    let mut i = 0;
    while i < cells.len() {
        let cell = &cells[i];
        let mut n = 1;
        while let Some(next) = cells.get(i + n) {
            let follows = next.width == cell.width
                && usize::from(next.byte) == usize::from(cell.byte) + n
                && next.value == cell.value;
            if !follows {
                break;
            }
            n += 1;
        }
        let len = n as u8;
        let part = extract(&cell.value, cell.width, cell.byte, len);
        let merged = parts
            .last()
            .and_then(|(last, _, length)| coalesce(last, *length, &part));
        match (merged, parts.last_mut()) {
            (Some(merged), Some(last)) => {
                last.0 = merged;
                last.2 += u64::from(len);
            }
            _ => parts.push((part, i as u64, u64::from(len))),
        }
        for c in &cells[i..i + n] {
            if c.trace.0.is_some() && !traces.iter().any(|t| t.same(&c.trace)) {
                traces.push(c.trace.clone());
            }
        }
        i += n;
    }
    let mut expr: Option<Expr> = None;
    for (part, start, _) in parts {
        let by = konst(8 * start);
        // Au-delà de 64 bits (lecture de 16 octets), lsl replierait une constante à 0.
        let shifted = match part.as_const() {
            Some(0) => continue,
            _ if start >= 8 => raw(Op::Lsl, &part, &by),
            _ => lsl(&part, &by),
        };
        expr = Some(match expr {
            None => shifted,
            Some(e) => or(&e, &shifted),
        });
    }
    (expr.unwrap_or_else(|| konst(0)), traces)
}

/// Repli d'une lecture jamais écrite de `len` octets à l'adresse absolue `at` :
/// pointeur relogé d'un emplacement de PT_GNU_RELRO (lecture entière de 8
/// octets alignée, hors import), sinon octets du fichier d'un segment LOAD sans
/// PF_W. `None` partout ailleurs.
fn folded(ctx: &Ctx, at: u64, len: u64, whole_read: bool) -> Option<Vec<Cell>> {
    let image = &ctx.image;
    let relro = |s: &Segment| s.p_type == elf::PT_GNU_RELRO && s.in_memory(at);
    let pointer = whole_read && len == 8 && at & 7 == 0;
    if pointer && image.segments.iter().any(relro) && !ctx.got.contains_key(&at) {
        let target = ctx.slots.get(&at)?;
        return Some(whole(&Expr::global(*target), 8, &Trace::default()));
    }
    let loaded = |s: &&Segment| s.p_type == elf::PT_LOAD && s.in_file(at);
    let segment = image.segments.iter().find(loaded)?;
    if segment.has(elf::PF_W) || !segment.in_file(at.checked_add(len - 1)?) {
        return None;
    }
    let offset = segment.offset.checked_add(at - segment.vaddr)?;
    let bytes = image.bytes_at(offset, len)?;
    let cells = bytes
        .iter()
        .map(|&b| Cell {
            value: konst(u64::from(b)),
            byte: 0,
            width: 1,
            trace: Trace::default(),
        })
        .collect();
    Some(cells)
}

/// Zone de mémoire dont le contenu est perdu : `[from, to)` sur `base`, sans
/// fin si `to` est absent.
#[derive(Clone)]
struct Zone {
    base: Expr,
    from: i64,
    to: Option<i64>,
    reason: Reason,
    at: u64,
    trace: Trace,
}

#[derive(Clone, Default)]
struct Memory {
    bases: HashMap<Expr, Rc<BTreeMap<i64, Cell>>>,
    zones: Rc<Vec<Zone>>,
}

impl Memory {
    fn zone_at(&self, base: &Expr, off: i64) -> Option<&Zone> {
        self.zones
            .iter()
            .rev()
            .find(|z| z.base == *base && z.from <= off && z.to.is_none_or(|to| off < to))
    }

    /// Octets lus en `addr`. Une suite d'octets jamais écrits devient
    /// load(n, …), sauf repli ([`folded`]), une suite d'octets d'une zone
    /// perdue unknown(…), par morceaux de [`MAX_RUN`] octets au plus.
    fn read(&self, ctx: &Ctx, addr: &Expr, width: u64) -> Vec<Cell> {
        let (base, off) = split(addr);
        let absolute = base == Expr::global(0);
        let written = self.bases.get(&base);
        let mut cells = Vec::new();
        let mut i = 0;
        while i < width {
            let at = off.wrapping_add(i as i64);
            if let Some(cell) = written.and_then(|m| m.get(&at)) {
                cells.push(cell.clone());
                i += 1;
                continue;
            }
            let zone = self.zone_at(&base, at);
            let mut n = 1;
            while i + n < width && n < MAX_RUN {
                let next = off.wrapping_add((i + n) as i64);
                let taken = written.is_some_and(|m| m.contains_key(&next));
                let same = match (zone, self.zone_at(&base, next)) {
                    (None, None) => true,
                    (Some(a), Some(b)) => std::ptr::eq(a, b),
                    _ => false,
                };
                if taken || !same {
                    break;
                }
                n += 1;
            }
            let whole_read = i == 0 && n == width;
            let rom = match zone {
                None if absolute => folded(ctx, at as u64, n, whole_read),
                _ => None,
            };
            if let Some(rom) = rom {
                cells.extend(rom);
                i += n;
                continue;
            }
            let (value, trace) = match zone {
                Some(z) => {
                    let slot = Slot::Off(at.wrapping_sub(z.from));
                    (unknown(z.reason, z.at, slot), z.trace.clone())
                }
                None => (load(n as u8, &add(addr, &konst(i))), Trace::default()),
            };
            cells.extend(whole(&value, n as u8, &trace));
            i += n;
        }
        cells
    }

    fn write(&mut self, addr: &Expr, cells: Vec<Cell>) {
        if cells.is_empty() {
            return;
        }
        let (base, off) = split(addr);
        let map = Rc::make_mut(self.bases.entry(base).or_default());
        for (i, cell) in cells.into_iter().enumerate() {
            map.insert(off.wrapping_add(i as i64), cell);
        }
    }

    fn zone(&mut self, addr: &Expr, len: Option<u64>, reason: Reason, at: u64, trace: Trace) {
        let (base, from) = split(addr);
        let to = len.map(|n| from.saturating_add(i64::try_from(n).unwrap_or(i64::MAX)));
        if let Some(map) = self.bases.get_mut(&base) {
            let map = Rc::make_mut(map);
            let mut lost = map.split_off(&from);
            if let Some(to) = to {
                let mut kept = lost.split_off(&to);
                map.append(&mut kept);
            }
        }
        Rc::make_mut(&mut self.zones).push(Zone {
            base,
            from,
            to,
            reason,
            at,
            trace,
        });
    }
}

enum Next {
    Fall,
    Jump(u64),
    Fork(u64),
    Call(u64),
    CallVia(Val),
    JumpVia(Val),
    Return,
    Trap,
}

struct Access {
    store: bool,
    addr: Expr,
    values: Vec<Val>,
}

struct Done {
    next: Next,
    accesses: Vec<Access>,
}

/// x0..x30 et sp (31), q0..q31 octet par octet, mémoire.
#[derive(Clone)]
struct State {
    x: [Val; 32],
    v: [Rc<Vec<Cell>>; 32],
    mem: Memory,
}

impl State {
    fn initial() -> State {
        State {
            x: std::array::from_fn(|r| Val::plain(Expr::init(r as u8))),
            v: std::array::from_fn(|r| {
                Rc::new(whole(&Expr::init(V0 + r as u8), 16, &Trace::default()))
            }),
            mem: Memory::default(),
        }
    }

    fn narrow(&self, reg: u16, size: SizeCode) -> Val {
        let v = &self.x[usize::from(reg)];
        if size == SizeCode::W {
            Val::new(zext(32, &v.expr), v.trace.clone())
        } else {
            v.clone()
        }
    }

    fn get(&self, op: &Operand) -> Option<Val> {
        Some(match *op {
            Operand::Register(_, 31) => Val::plain(konst(0)),
            Operand::Register(size, r) | Operand::RegisterOrSP(size, r) => self.narrow(r, size),
            Operand::RegShift(style, amount, size, r) => {
                let v = if r == 31 {
                    Val::plain(konst(0))
                } else {
                    self.narrow(r, size)
                };
                let width = if size == SizeCode::W { 32 } else { 64 };
                let by = konst(u64::from(amount));
                let x = &v.expr;
                let e = match style {
                    ShiftStyle::LSL | ShiftStyle::UXTX | ShiftStyle::SXTX => lsl(x, &by),
                    ShiftStyle::LSR => lsr(x, &by),
                    ShiftStyle::ASR => asr(&sext(width, x), &by),
                    ShiftStyle::ROR if amount == 0 => x.clone(),
                    ShiftStyle::ROR => return None,
                    ShiftStyle::UXTB => lsl(&zext(8, x), &by),
                    ShiftStyle::UXTH => lsl(&zext(16, x), &by),
                    ShiftStyle::UXTW => lsl(&zext(32, x), &by),
                    ShiftStyle::SXTB => lsl(&sext(8, x), &by),
                    ShiftStyle::SXTH => lsl(&sext(16, x), &by),
                    ShiftStyle::SXTW => lsl(&sext(32, x), &by),
                };
                Val::new(e, v.trace)
            }
            Operand::Immediate(value) => Val::plain(konst(u64::from(value))),
            Operand::Imm64(value) => Val::plain(konst(value)),
            Operand::Imm16(value) => Val::plain(konst(u64::from(value))),
            Operand::ImmShift(value, shift) => Val::plain(konst(u64::from(value) << shift)),
            _ => return None,
        })
    }

    fn put(&mut self, op: &Operand, val: Val, at: At) {
        let (reg, size) = match *op {
            Operand::Register(_, 31) => return,
            Operand::Register(size, r) | Operand::RegisterOrSP(size, r) => (r, size),
            _ => return,
        };
        let expr = if size == SizeCode::W {
            zext(32, &val.expr)
        } else {
            val.expr
        };
        let expr = if expr.size() > MAX_EXPR_NODES {
            unknown(Reason::Budget, at.addr, Slot::Reg(reg as u8))
        } else {
            expr
        };
        self.x[usize::from(reg)] = Val::new(expr, val.trace);
    }

    fn set(&mut self, op: &Operand, expr: Expr, at: At, from: &[&Trace]) {
        let trace = at.def(from);
        self.put(op, Val::new(expr, trace), at);
    }

    /// Les `width` premiers octets de q`reg`, déplacés par `at`.
    fn lanes(&self, reg: u16, width: usize, at: At) -> Vec<Cell> {
        let cells = &self.v[usize::from(reg % 32)][..width];
        cells.iter().map(|c| c.moved(at)).collect()
    }

    fn put_vector(&mut self, reg: u16, mut cells: Vec<Cell>) {
        cells.resize(16, zero());
        self.v[usize::from(reg % 32)] = Rc::new(cells);
    }

    fn clobber_vector(&mut self, reg: u16, reason: Reason, at: At, trace: &Trace) {
        let reg = reg % 32;
        let value = unknown(reason, at.addr, Slot::Reg(V0 + reg as u8));
        self.v[usize::from(reg)] = Rc::new(whole(&value, 16, trace));
    }

    /// Effet d'un appel non suivi sur les registres que l'appelé peut écrire.
    fn clobber_call(&mut self, reason: Reason, at: At) {
        let trace = at.origin();
        for r in 0..=18u8 {
            let value = unknown(reason, at.addr, Slot::Reg(r));
            self.x[usize::from(r)] = Val::new(value, trace.clone());
        }
        for r in (0..8u16).chain(16..32) {
            self.clobber_vector(r, reason, at, &trace);
        }
        for r in 8..16u16 {
            let value = unknown(reason, at.addr, Slot::Reg(V0 + r as u8));
            let cells = Rc::make_mut(&mut self.v[usize::from(r)]);
            for byte in 8..16u8 {
                cells[usize::from(byte)] = Cell {
                    value: value.clone(),
                    byte,
                    width: 16,
                    trace: trace.clone(),
                };
            }
        }
    }

    fn clobber_operand(&mut self, op: &Operand, at: At, trace: &Trace) {
        let reason = Reason::UnsupportedInsn;
        match *op {
            Operand::Register(_, 31) => {}
            Operand::Register(_, r) | Operand::RegisterOrSP(_, r) => {
                let value = unknown(reason, at.addr, Slot::Reg(r as u8));
                self.x[usize::from(r)] = Val::new(value, trace.clone());
            }
            Operand::SIMDRegister(_, r)
            | Operand::SIMDRegisterElements(_, r, _)
            | Operand::SIMDRegisterElementsLane(_, r, _, _)
            | Operand::SIMDRegisterElementsMultipleLane(_, r, _, _, _) => {
                self.clobber_vector(r, reason, at, trace)
            }
            Operand::SIMDRegisterGroup(_, r, _, count)
            | Operand::SIMDRegisterGroupLane(r, _, count, _) => {
                for i in 0..u16::from(count) {
                    self.clobber_vector(r + i, reason, at, trace);
                }
            }
            _ => {}
        }
    }

    fn address(&self, op: &Operand, at: At) -> Option<(Expr, Option<(usize, Val)>)> {
        let base = move |n: u16| &self.x[usize::from(n)];
        let index = move |m: u16| {
            if m == 31 {
                konst(0)
            } else {
                self.x[usize::from(m)].expr.clone()
            }
        };
        Some(match *op {
            Operand::RegPreIndex(n, imm, writeback) => {
                let b = base(n);
                let addr = add(&b.expr, &konst(i64::from(imm) as u64));
                let next = writeback.then(|| {
                    let val = Val::new(addr.clone(), at.def(&[&b.trace]));
                    (usize::from(n), val)
                });
                (addr, next)
            }
            Operand::RegPostIndex(n, imm) => {
                let b = base(n);
                let next = add(&b.expr, &konst(i64::from(imm) as u64));
                let val = Val::new(next, at.def(&[&b.trace]));
                (b.expr.clone(), Some((usize::from(n), val)))
            }
            Operand::RegPostIndexReg(n, m) => {
                let b = base(n);
                let next = add(&b.expr, &index(m));
                let val = Val::new(next, at.def(&[&b.trace]));
                (b.expr.clone(), Some((usize::from(n), val)))
            }
            Operand::RegRegOffset(n, m, size, style, amount) => {
                let i = index(m);
                let i = match (size, style) {
                    (SizeCode::W, ShiftStyle::SXTW) => sext(32, &i),
                    (SizeCode::W, _) => zext(32, &i),
                    _ => i,
                };
                let i = lsl(&i, &konst(u64::from(amount)));
                (add(&base(n).expr, &i), None)
            }
            Operand::PCOffset(off) => (Expr::global(at.addr.wrapping_add(off as u64)), None),
            _ => return None,
        })
    }

    fn exec(&mut self, ctx: &Ctx, inst: &Instruction, mnemonic: &str, at: At) -> Done {
        let mut accesses = Vec::new();
        let next = match self.control(inst, at) {
            Some(next) => next,
            None => {
                let handled = if is_load(inst.opcode) {
                    self.load(ctx, inst, at, &mut accesses)
                } else if is_store(inst.opcode) {
                    self.store(inst, at, &mut accesses)
                } else {
                    self.data(inst, at)
                };
                handled.unwrap_or_else(|| {
                    self.unsupported(inst, mnemonic, at);
                    Next::Fall
                })
            }
        };
        Done { next, accesses }
    }

    fn control(&self, inst: &Instruction, at: At) -> Option<Next> {
        let target = || {
            inst.operands.iter().find_map(|op| match *op {
                Operand::PCOffset(off) => Some(at.addr.wrapping_add(off as u64)),
                _ => None,
            })
        };
        Some(match inst.opcode {
            O::B => Next::Jump(target()?),
            O::Bcc(cond) | O::BCcc(cond) if cond >= 14 => Next::Jump(target()?),
            O::Bcc(_) | O::BCcc(_) | O::CBZ | O::CBNZ | O::TBZ | O::TBNZ => Next::Fork(target()?),
            O::BL => Next::Call(target()?),
            O::BLR | O::BLRAA | O::BLRAAZ | O::BLRAB | O::BLRABZ => {
                Next::CallVia(self.get(&inst.operands[0])?)
            }
            O::BR | O::BRAA | O::BRAAZ | O::BRAB | O::BRABZ => {
                Next::JumpVia(self.get(&inst.operands[0])?)
            }
            O::RET | O::RETAA | O::RETAB => Next::Return,
            O::BRK | O::HLT | O::UDF => Next::Trap,
            _ => return None,
        })
    }

    fn load(
        &mut self,
        ctx: &Ctx,
        inst: &Instruction,
        at: At,
        accesses: &mut Vec<Access>,
    ) -> Option<Next> {
        let ops = &inst.operands;
        let k = ops.iter().position(is_memory)?;
        let dests = &ops[..k];
        let width = access_width(inst.opcode, dests.first()?)?;
        let (addr, writeback) = self.address(&ops[k], at)?;
        let signed = is_signed_load(inst.opcode);
        let mut values = Vec::new();
        for (j, dest) in dests.iter().enumerate() {
            let place = add(&addr, &konst(j as u64 * u64::from(width)));
            let cells = self.mem.read(ctx, &place, u64::from(width));
            let (mut expr, traces) = assemble(&cells);
            if signed {
                expr = sext(8 * width, &expr);
            }
            let value = Val::new(expr, at.def_all(&traces));
            match *dest {
                Operand::SIMDRegister(_, r) => {
                    self.put_vector(r, cells.iter().map(|c| c.moved(at)).collect())
                }
                _ => self.put(dest, value.clone(), at),
            }
            values.push(value);
        }
        if let Some((reg, val)) = writeback {
            self.x[reg] = val;
        }
        accesses.push(Access {
            store: false,
            addr,
            values,
        });
        Some(Next::Fall)
    }

    fn store(&mut self, inst: &Instruction, at: At, accesses: &mut Vec<Access>) -> Option<Next> {
        let ops = &inst.operands;
        let k = ops.iter().position(is_memory)?;
        let first = usize::from(is_exclusive_store(inst.opcode));
        let sources = ops.get(first..k)?;
        let width = access_width(inst.opcode, sources.first()?)?;
        let (addr, writeback) = self.address(&ops[k], at)?;
        let mut writes = Vec::new();
        for (j, source) in sources.iter().enumerate() {
            let cells = match *source {
                Operand::SIMDRegister(_, r) => self.lanes(r, usize::from(width), at),
                _ => {
                    let v = self.get(source)?;
                    whole(&trunc(8 * width, &v.expr), width, &at.def(&[&v.trace]))
                }
            };
            writes.push((add(&addr, &konst(j as u64 * u64::from(width))), cells));
        }
        let mut values = Vec::new();
        for (place, cells) in writes {
            let (expr, mut traces) = assemble(&cells);
            let trace = match traces.len() {
                1 => traces.remove(0),
                _ => at.def_all(&traces),
            };
            values.push(Val::new(expr, trace));
            self.mem.write(&place, cells);
        }
        if first == 1 {
            self.set(&ops[0], unknown_status(&ops[0], at), at, &[]);
        }
        if let Some((reg, val)) = writeback {
            self.x[reg] = val;
        }
        accesses.push(Access {
            store: true,
            addr,
            values,
        });
        Some(Next::Fall)
    }

    fn data(&mut self, inst: &Instruction, at: At) -> Option<Next> {
        let ops = &inst.operands;
        let width = op_width(&ops[0]);
        match inst.opcode {
            O::MOVZ | O::MOVN => {
                let Operand::ImmShift(imm, shift) = ops[1] else {
                    return None;
                };
                let mut value = u64::from(imm) << shift;
                if inst.opcode == O::MOVN {
                    value = !value;
                }
                self.set(&ops[0], konst(value), at, &[]);
            }
            O::MOVK => {
                let Operand::ImmShift(imm, shift) = ops[1] else {
                    return None;
                };
                let old = self.get(&ops[0])?;
                let kept = and(&old.expr, &konst(!(0xffff_u64 << shift)));
                let e = or(&kept, &konst(u64::from(imm) << shift));
                self.set(&ops[0], e, at, &[&old.trace]);
            }
            O::ADR | O::ADRP => {
                let Operand::PCOffset(off) = ops[1] else {
                    return None;
                };
                let from = if inst.opcode == O::ADRP {
                    at.addr & !0xfff
                } else {
                    at.addr
                };
                let target = Expr::global(from.wrapping_add(off as u64));
                self.set(&ops[0], target, at, &[]);
            }
            O::ADD | O::ADDS | O::SUB | O::SUBS => {
                let (a, b) = (self.get(&ops[1])?, self.get(&ops[2])?);
                let e = if matches!(inst.opcode, O::ADD | O::ADDS) {
                    add(&a.expr, &b.expr)
                } else {
                    sub(&a.expr, &b.expr)
                };
                self.set(&ops[0], e, at, &[&a.trace, &b.trace]);
            }
            O::AND | O::ANDS | O::ORR | O::ORN | O::EOR | O::EON | O::BIC | O::BICS => {
                if matches!(ops[0], Operand::SIMDRegisterElements(..)) {
                    return self.vector_move(inst, at);
                }
                let (a, b) = (self.get(&ops[1])?, self.get(&ops[2])?);
                let rhs = match inst.opcode {
                    O::ORN | O::EON | O::BIC | O::BICS => xor(&b.expr, &konst(mask(width))),
                    _ => b.expr.clone(),
                };
                let e = match inst.opcode {
                    O::AND | O::ANDS | O::BIC | O::BICS => and(&a.expr, &rhs),
                    O::ORR | O::ORN => or(&a.expr, &rhs),
                    _ => xor(&a.expr, &rhs),
                };
                self.set(&ops[0], e, at, &[&a.trace, &b.trace]);
            }
            O::LSLV | O::LSRV | O::ASRV => {
                let (a, b) = (self.get(&ops[1])?, self.get(&ops[2])?);
                let amount = and(&b.expr, &konst(u64::from(width) - 1));
                let e = match inst.opcode {
                    O::LSLV => lsl(&a.expr, &amount),
                    O::LSRV => lsr(&a.expr, &amount),
                    _ => asr(&sext(width, &a.expr), &amount),
                };
                self.set(&ops[0], e, at, &[&a.trace, &b.trace]);
            }
            O::UBFM | O::SBFM | O::BFM => return self.bitfield(inst, at),
            O::EXTR => {
                let (high, low) = (self.get(&ops[1])?, self.get(&ops[2])?);
                let Operand::Immediate(lsb) = ops[3] else {
                    return None;
                };
                let lsb = u64::from(lsb);
                let e = if lsb == 0 {
                    low.expr.clone()
                } else {
                    let right = lsr(&low.expr, &konst(lsb));
                    or(&right, &lsl(&high.expr, &konst(u64::from(width) - lsb)))
                };
                self.set(&ops[0], e, at, &[&high.trace, &low.trace]);
            }
            O::CSEL | O::CSINC | O::CSINV | O::CSNEG => return self.select(inst, at),
            O::MADD | O::MSUB => {
                let (a, b) = (self.get(&ops[1])?, self.get(&ops[2])?);
                let c = self.get(&ops[3])?;
                let product = mul(&a.expr, &b.expr);
                let e = if inst.opcode == O::MADD {
                    add(&c.expr, &product)
                } else {
                    sub(&c.expr, &product)
                };
                self.set(&ops[0], e, at, &[&a.trace, &b.trace, &c.trace]);
            }
            O::SMADDL | O::SMSUBL | O::UMADDL | O::UMSUBL => {
                let (a, b) = (self.get(&ops[1])?, self.get(&ops[2])?);
                let c = self.get(&ops[3])?;
                let signed = matches!(inst.opcode, O::SMADDL | O::SMSUBL);
                let product = mul(&widen32(&a.expr, signed), &widen32(&b.expr, signed));
                let e = if matches!(inst.opcode, O::SMADDL | O::UMADDL) {
                    add(&c.expr, &product)
                } else {
                    sub(&c.expr, &product)
                };
                self.set(&ops[0], e, at, &[&a.trace, &b.trace, &c.trace]);
            }
            O::MOVI | O::MVNI => return self.movi(inst, at),
            O::FMOV => return self.fmov(inst, at),
            O::SVC => {
                let value = unknown(Reason::UnsupportedInsn, at.addr, Slot::Reg(0));
                self.x[0] = Val::new(value, at.origin());
            }
            O::CCMP
            | O::CCMN
            | O::FCMP
            | O::FCMPE
            | O::FCCMP
            | O::FCCMPE
            | O::HINT
            | O::CLREX
            | O::ISB
            | O::DMB(_)
            | O::DSB(_)
            | O::SB
            | O::SSBB
            | O::PSSBB
            | O::PRFM
            | O::PRFUM
            | O::MSR
            | O::SYS(_) => {}
            _ => return None,
        }
        Some(Next::Fall)
    }

    fn select(&mut self, inst: &Instruction, at: At) -> Option<Next> {
        let ops = &inst.operands;
        let Operand::ConditionCode(code) = ops[3] else {
            return None;
        };
        let width = op_width(&ops[0]);
        let (a, b) = (self.get(&ops[1])?, self.get(&ops[2])?);
        let otherwise = match inst.opcode {
            O::CSEL => b.expr.clone(),
            O::CSINC => add(&b.expr, &konst(1)),
            O::CSINV => xor(&b.expr, &konst(mask(width))),
            _ => sub(&konst(0), &b.expr),
        };
        if code >= 14 {
            self.set(&ops[0], a.expr, at, &[&a.trace]);
            return Some(Next::Fall);
        }
        let cond = Cond { at: at.addr, code };
        let e = ite(cond, &zext(width, &a.expr), &zext(width, &otherwise));
        self.set(&ops[0], e, at, &[&a.trace, &b.trace]);
        Some(Next::Fall)
    }

    fn bitfield(&mut self, inst: &Instruction, at: At) -> Option<Next> {
        let ops = &inst.operands;
        let (Operand::Immediate(immr), Operand::Immediate(imms)) = (ops[2], ops[3]) else {
            return None;
        };
        let width = op_width(&ops[0]);
        let (r, s) = (u8::try_from(immr).ok()?, u8::try_from(imms).ok()?);
        let src = self.get(&ops[1])?;
        let x = &src.expr;
        let by = |n: u8| konst(u64::from(n));
        let e = match inst.opcode {
            O::UBFM if s == width - 1 => lsr(x, &by(r)),
            O::UBFM if s >= r => zext(s - r + 1, &lsr(x, &by(r))),
            O::UBFM if s + 1 == r => lsl(x, &by(width - r)),
            O::UBFM => lsl(&zext(s + 1, x), &by(width - r)),
            O::SBFM if s == width - 1 => asr(&sext(width, x), &by(r)),
            O::SBFM if s >= r => sext(s - r + 1, &lsr(x, &by(r))),
            O::SBFM => lsl(&sext(s + 1, x), &by(width - r)),
            O::BFM => {
                let dst = self.get(&ops[0])?;
                let (len, shift, field) = if s >= r {
                    (s - r + 1, 0, zext(s - r + 1, &lsr(x, &by(r))))
                } else {
                    (s + 1, width - r, lsl(&zext(s + 1, x), &by(width - r)))
                };
                let hole = !(mask(len) << shift);
                let e = or(&and(&dst.expr, &konst(hole)), &field);
                self.set(&ops[0], e, at, &[&src.trace, &dst.trace]);
                return Some(Next::Fall);
            }
            _ => return None,
        };
        self.set(&ops[0], e, at, &[&src.trace]);
        Some(Next::Fall)
    }

    fn movi(&mut self, inst: &Instruction, at: At) -> Option<Next> {
        let ops = &inst.operands;
        let (reg, bytes, element) = match ops[0] {
            Operand::SIMDRegisterElements(size, reg, element) => {
                (reg, simd_bytes(size), simd_bytes(element))
            }
            Operand::SIMDRegister(SIMDSizeCode::D, reg) => (reg, 8, 8),
            _ => return None,
        };
        let pattern = match ops[1] {
            Operand::Imm64(value) => value,
            Operand::ImmShift(imm, shift) => replicate(u64::from(imm) << shift, element),
            _ => return None,
        };
        let pattern = if inst.opcode == O::MVNI {
            !pattern
        } else {
            pattern
        };
        let trace = at.origin();
        let cells = (0..bytes)
            .map(|i| Cell {
                value: konst((pattern >> (8 * u32::from(i % 8))) & 0xff),
                byte: 0,
                width: 1,
                trace: trace.clone(),
            })
            .collect();
        self.put_vector(reg, cells);
        Some(Next::Fall)
    }

    fn fmov(&mut self, inst: &Instruction, at: At) -> Option<Next> {
        let ops = &inst.operands;
        match (ops[0], ops[1]) {
            (Operand::SIMDRegister(size, d), Operand::Register(..)) => {
                let v = self.get(&ops[1])?;
                let w = simd_bytes(size);
                let cells = whole(&trunc(8 * w, &v.expr), w, &at.def(&[&v.trace]));
                self.put_vector(d, cells);
            }
            (Operand::Register(..), Operand::SIMDRegister(size, n)) => {
                let w = usize::from(simd_bytes(size));
                let (expr, traces) = assemble(&self.v[usize::from(n)][..w]);
                let trace = at.def_all(&traces);
                self.put(&ops[0], Val::new(expr, trace), at);
            }
            (Operand::SIMDRegister(size, d), Operand::SIMDRegister(_, n)) => {
                let cells = self.lanes(n, usize::from(simd_bytes(size)), at);
                self.put_vector(d, cells);
            }
            (Operand::SIMDRegister(size, d), Operand::ImmediateDouble(value)) => {
                let bits = match size {
                    SIMDSizeCode::D => value.to_bits(),
                    SIMDSizeCode::S => u64::from((value as f32).to_bits()),
                    _ => return None,
                };
                let w = simd_bytes(size);
                self.put_vector(d, whole(&konst(bits), w, &at.origin()));
            }
            _ => return None,
        }
        Some(Next::Fall)
    }

    /// `mov vd, vn` (orr vd, vn, vn).
    fn vector_move(&mut self, inst: &Instruction, at: At) -> Option<Next> {
        let ops = &inst.operands;
        if inst.opcode != O::ORR || ops[1] != ops[2] {
            return None;
        }
        let Operand::SIMDRegisterElements(size, d, _) = ops[0] else {
            return None;
        };
        let Operand::SIMDRegisterElements(_, n, _) = ops[1] else {
            return None;
        };
        let cells = self.lanes(n, usize::from(simd_bytes(size)), at);
        self.put_vector(d, cells);
        Some(Next::Fall)
    }

    /// Instruction non modélisée : ses registres de destination deviennent
    /// inconnus ; une écriture en mémoire perd la zone écrite.
    fn unsupported(&mut self, inst: &Instruction, mnemonic: &str, at: At) {
        let ops = &inst.operands;
        let memory = ops.iter().position(is_memory);
        let registers = match memory {
            Some(k) => &ops[..k],
            None => &ops[..1],
        };
        let pure_store = mnemonic.starts_with("st");
        let trace = at.origin();
        if !pure_store {
            for op in registers {
                self.clobber_operand(op, at, &trace);
            }
        }
        let Some(k) = memory else {
            return;
        };
        let Some((addr, writeback)) = self.address(&ops[k], at) else {
            return;
        };
        if pure_store || ATOMIC_PREFIXES.iter().any(|p| mnemonic.starts_with(p)) {
            let len = registers.iter().filter_map(operand_bytes).max();
            let reason = Reason::UnsupportedInsn;
            self.mem.zone(&addr, len, reason, at.addr, trace);
        }
        if let Some((reg, val)) = writeback {
            self.x[reg] = val;
        }
    }

    /// Registre écrit par une instruction de données, pour un watch.
    fn defined(&self, inst: &Instruction) -> Option<Val> {
        let source_only = matches!(
            inst.opcode,
            O::CCMP | O::CCMN | O::FCMP | O::FCMPE | O::FCCMP | O::FCCMPE | O::MSR | O::SYS(_)
        );
        if source_only {
            return None;
        }
        match inst.operands[0] {
            Operand::Register(_, 31) => None,
            Operand::Register(size, r) | Operand::RegisterOrSP(size, r) => {
                Some(self.narrow(r, size))
            }
            Operand::SIMDRegister(size, r) | Operand::SIMDRegisterElements(size, r, _) => {
                let w = usize::from(simd_bytes(size));
                let (expr, traces) = assemble(&self.v[usize::from(r % 32)][..w]);
                Some(Val::new(
                    expr,
                    traces.into_iter().next().unwrap_or_default(),
                ))
            }
            _ => None,
        }
    }
}

fn unknown_status(op: &Operand, at: At) -> Expr {
    let reg = match *op {
        Operand::Register(_, r) => r as u8,
        _ => 0,
    };
    unknown(Reason::UnsupportedInsn, at.addr, Slot::Reg(reg))
}

fn widen32(e: &Expr, signed: bool) -> Expr {
    if signed {
        sext(32, e)
    } else {
        zext(32, e)
    }
}

fn op_width(op: &Operand) -> u8 {
    match *op {
        Operand::Register(SizeCode::W, _) | Operand::RegisterOrSP(SizeCode::W, _) => 32,
        _ => 64,
    }
}

fn simd_bytes(size: SIMDSizeCode) -> u8 {
    match size {
        SIMDSizeCode::B => 1,
        SIMDSizeCode::H => 2,
        SIMDSizeCode::S => 4,
        SIMDSizeCode::D => 8,
        SIMDSizeCode::Q => 16,
    }
}

fn replicate(value: u64, element: u8) -> u64 {
    let bits = u32::from(element) * 8;
    if bits >= 64 {
        return value;
    }
    let unit = value & mask(bits as u8);
    (0..64 / bits).fold(0, |acc, i| acc | (unit << (i * bits)))
}

fn operand_bytes(op: &Operand) -> Option<u64> {
    Some(match *op {
        Operand::Register(SizeCode::W, _) => 4,
        Operand::Register(SizeCode::X, _) => 8,
        Operand::SIMDRegister(size, _) => u64::from(simd_bytes(size)),
        Operand::SIMDRegisterGroup(size, _, _, count) => {
            u64::from(simd_bytes(size)) * u64::from(count)
        }
        Operand::SIMDRegisterGroupLane(_, element, count, _) => {
            u64::from(simd_bytes(element)) * u64::from(count)
        }
        _ => return None,
    })
}

fn is_memory(op: &Operand) -> bool {
    matches!(
        op,
        Operand::RegPreIndex(..)
            | Operand::RegPostIndex(..)
            | Operand::RegPostIndexReg(..)
            | Operand::RegRegOffset(..)
            | Operand::PCOffset(..)
    )
}

fn is_load(opcode: O) -> bool {
    matches!(
        opcode,
        O::LDR
            | O::LDRB
            | O::LDRH
            | O::LDRSB
            | O::LDRSH
            | O::LDRSW
            | O::LDUR
            | O::LDURB
            | O::LDURH
            | O::LDURSB
            | O::LDURSH
            | O::LDURSW
            | O::LDTR
            | O::LDTRB
            | O::LDTRH
            | O::LDTRSB
            | O::LDTRSH
            | O::LDTRSW
            | O::LDP
            | O::LDPSW
            | O::LDNP
            | O::LDAR
            | O::LDARB
            | O::LDARH
            | O::LDLAR
            | O::LDLARB
            | O::LDLARH
            | O::LDAXR
            | O::LDAXRB
            | O::LDAXRH
            | O::LDXR
            | O::LDXRB
            | O::LDXRH
            | O::LDXP
            | O::LDAXP
            | O::LDAPR
            | O::LDAPRB
            | O::LDAPRH
            | O::LDAPUR
            | O::LDAPURB
            | O::LDAPURH
            | O::LDAPURSB
            | O::LDAPURSH
            | O::LDAPURSW
            | O::LDRAA
            | O::LDRAB
    )
}

fn is_store(opcode: O) -> bool {
    matches!(
        opcode,
        O::STR
            | O::STRB
            | O::STRH
            | O::STRW
            | O::STUR
            | O::STURB
            | O::STURH
            | O::STTR
            | O::STTRB
            | O::STTRH
            | O::STP
            | O::STNP
            | O::STLR
            | O::STLLR
            | O::STLRB
            | O::STLLRB
            | O::STLRH
            | O::STLLRH
            | O::STLUR
            | O::STLURB
            | O::STLURH
    ) || is_exclusive_store(opcode)
}

fn is_exclusive_store(opcode: O) -> bool {
    matches!(
        opcode,
        O::STXR | O::STXRB | O::STXRH | O::STLXR | O::STLXRB | O::STLXRH | O::STXP | O::STLXP
    )
}

fn is_signed_load(opcode: O) -> bool {
    matches!(
        opcode,
        O::LDRSB
            | O::LDRSH
            | O::LDRSW
            | O::LDURSB
            | O::LDURSH
            | O::LDURSW
            | O::LDTRSB
            | O::LDTRSH
            | O::LDTRSW
            | O::LDPSW
            | O::LDAPURSB
            | O::LDAPURSH
            | O::LDAPURSW
    )
}

/// Octets lus ou écrits par registre : suffixe du mnémonique, sinon taille du
/// registre.
fn access_width(opcode: O, reg: &Operand) -> Option<u8> {
    let fixed = match opcode {
        O::LDRB
        | O::LDURB
        | O::LDTRB
        | O::LDARB
        | O::LDLARB
        | O::LDAXRB
        | O::LDXRB
        | O::LDAPRB
        | O::LDAPURB
        | O::LDRSB
        | O::LDURSB
        | O::LDTRSB
        | O::LDAPURSB
        | O::STRB
        | O::STURB
        | O::STTRB
        | O::STLRB
        | O::STLLRB
        | O::STLURB
        | O::STXRB
        | O::STLXRB => Some(1),
        O::LDRH
        | O::LDURH
        | O::LDTRH
        | O::LDARH
        | O::LDLARH
        | O::LDAXRH
        | O::LDXRH
        | O::LDAPRH
        | O::LDAPURH
        | O::LDRSH
        | O::LDURSH
        | O::LDTRSH
        | O::LDAPURSH
        | O::STRH
        | O::STURH
        | O::STTRH
        | O::STLRH
        | O::STLLRH
        | O::STLURH
        | O::STXRH
        | O::STLXRH => Some(2),
        O::LDRSW | O::LDURSW | O::LDTRSW | O::LDPSW | O::LDAPURSW => Some(4),
        _ => None,
    };
    if fixed.is_some() {
        return fixed;
    }
    match *reg {
        Operand::Register(SizeCode::W, _) => Some(4),
        Operand::Register(SizeCode::X, _) => Some(8),
        Operand::SIMDRegister(size, _) => Some(simd_bytes(size)),
        _ => None,
    }
}

/// Plage `[start, end)` d'une fonction, d'après le st_size de son symbole ou le
/// FDE qui la contient ; sans l'un ni l'autre, [`in_function`] depuis `start`.
#[derive(Clone, Copy)]
pub(super) struct Bound {
    pub(super) start: u64,
    pub(super) end: Option<u64>,
    pub(super) source: &'static str,
}

impl Bound {
    /// `fdes` : plages triées de [`fde_ranges`].
    pub(super) fn of(ctx: &Ctx, fdes: &[(u64, u64)], at: u64) -> Bound {
        if let Some(&(_, size)) = ctx.symbols.get(&at) {
            if size > 0 {
                return Bound {
                    start: at,
                    end: Some(at.saturating_add(size)),
                    source: BOUND_SYMBOL,
                };
            }
        }
        let index = fdes.partition_point(|&(start, _)| start <= at);
        if let Some(&(start, end)) = index.checked_sub(1).and_then(|i| fdes.get(i)) {
            if at < end {
                return Bound {
                    start,
                    end: Some(end),
                    source: BOUND_EH_FRAME,
                };
            }
        }
        Bound {
            start: at,
            end: None,
            source: BOUND_NONE,
        }
    }

    fn contains(&self, ctx: &Ctx, at: u64) -> bool {
        match self.end {
            Some(end) => self.start <= at && at < end,
            None => in_function(ctx, self.start, at),
        }
    }
}

/// Cadre d'un bl suivi. `preserved` : sp et x19..x29 à l'entrée de l'appelé,
/// dans l'ordre de [`PRESERVED`]. `fragment` : l'appelé est un morceau.
/// `incomplete` : un appel direct interne n'a pas été suivi, profondeur atteinte.
/// `args` : x0..x8 au moment du bl.
#[derive(Clone)]
struct Frame {
    call: u64,
    target: u64,
    ret: u64,
    bound: Bound,
    context: u64,
    tails: u8,
    preserved: Vec<Val>,
    fragment: bool,
    incomplete: bool,
    args: Vec<Expr>,
}

/// Appel direct interne non suivi, et x0..x8 au moment de l'appel.
struct Skipped {
    at: u64,
    args: Vec<Expr>,
}

/// Un chemin : état, pile d'appels suivis, passages par adresse, et ce qu'il a
/// relevé, rattaché à lui seul quand il se termine. `tails` : appels terminaux
/// suivis depuis le dernier bl suivi ; `fragments` : cadres de morceaux empilés ;
/// `forks` : frères ouverts depuis l'entrée dans l'appelé de premier niveau ;
/// `rank` : distance aux watches du point de reprise, pour l'ordre d'attente.
#[derive(Clone)]
struct Path {
    pc: u64,
    bound: Bound,
    frames: Vec<Frame>,
    tails: u8,
    fragments: u8,
    forks: usize,
    rank: u32,
    context: u64,
    state: State,
    visits: HashMap<(u64, u64), u8>,
    insns: usize,
    hits: Vec<(u64, Rc<Seen>)>,
    calls: Vec<Rc<CallSeen>>,
    branches: Vec<Rc<BranchSeen>>,
    skipped: Vec<Rc<Skipped>>,
    abandoned: bool,
    incomplete: bool,
}

impl Path {
    fn new(bound: Bound, entry: u64) -> Path {
        Path {
            pc: entry,
            bound,
            frames: Vec::new(),
            tails: 0,
            fragments: 0,
            forks: 0,
            rank: RANK_UNKNOWN,
            context: 0,
            state: State::initial(),
            visits: HashMap::new(),
            insns: 0,
            hits: Vec::new(),
            calls: Vec::new(),
            branches: Vec::new(),
            skipped: Vec::new(),
            abandoned: false,
            incomplete: false,
        }
    }

    fn args(&self) -> Vec<Expr> {
        self.state.x[..ARGS]
            .iter()
            .map(|v| v.expr.clone())
            .collect()
    }

    fn skip(&mut self, at: u64) {
        let args = self.args();
        self.skipped.push(Rc::new(Skipped { at, args }));
    }

    /// Appels suivis empilés, terminaux compris, morceaux exclus.
    fn level(&self) -> usize {
        self.frames.len() - usize::from(self.fragments) + usize::from(self.tails)
    }

    /// Hors de la fonction analysée : un cadre empilé ou un appel terminal suivi.
    fn in_callee(&self) -> bool {
        !self.frames.is_empty() || self.tails > 0
    }

    /// bl suivi en `call` vers `target`.
    fn enter(&mut self, call: u64, target: u64, bound: Bound, fragment: bool) {
        let ret = call.wrapping_add(4);
        let x = &self.state.x;
        let preserved = PRESERVED.iter().map(|&r| x[r].clone()).collect();
        let args = self.args();
        self.frames.push(Frame {
            call,
            target,
            ret,
            bound: self.bound,
            context: self.context,
            tails: self.tails,
            preserved,
            fragment,
            incomplete: false,
            args,
        });
        if fragment {
            self.fragments += 1;
        }
        self.context = (self.context.rotate_left(5) ^ ret).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        self.bound = bound;
        self.tails = 0;
        self.pc = target;
    }

    /// Un appel direct interne n'est pas suivi faute de profondeur : la fonction
    /// courante, morceaux exclus, est incomplète.
    fn mark_incomplete(&mut self) {
        if let Some(frame) = self.frames.iter_mut().rev().find(|f| !f.fragment) {
            frame.incomplete = true;
        }
    }

    /// ret parcouru : rien n'est restauré, sauf cadre incomplet.
    fn ret(&mut self) -> Result<(), &'static str> {
        self.pop(false)?;
        Ok(())
    }

    /// Sortie d'un appelé dont la fin n'a pas été parcourue (appel terminal non
    /// suivi) : sp et x19..x29 reprennent leur valeur d'entrée (AAPCS64).
    fn unwind(&mut self) -> Result<(), &'static str> {
        self.pop(true)?;
        Ok(())
    }

    fn pop(&mut self, restore: bool) -> Result<Frame, &'static str> {
        let frame = self.frames.pop().ok_or(STATUS_RETURNED)?;
        self.pc = frame.ret;
        self.bound = frame.bound;
        self.context = frame.context;
        self.tails = frame.tails;
        if frame.fragment {
            self.fragments -= 1;
        }
        if frame.incomplete {
            self.incomplete = true;
        }
        if !self.in_callee() {
            self.forks = 0;
        }
        if restore || frame.incomplete {
            for (&r, val) in PRESERVED.iter().zip(&frame.preserved) {
                self.state.x[r] = val.clone();
            }
        }
        Ok(frame)
    }

    /// Boucle coupée dans un appelé : il est abandonné, le chemin reprend chez
    /// l'appelant du dernier bl suivi comme après un appel non suivi.
    fn abandon(&mut self) -> Result<(), &'static str> {
        let frame = self.pop(true)?;
        let at = At {
            addr: frame.call,
            step: u32::try_from(self.insns).unwrap_or(u32::MAX),
        };
        self.state.clobber_call(Reason::CallNotFollowed, at);
        self.abandoned = true;
        self.calls.push(Rc::new(CallSeen {
            at: frame.call,
            kind: CALL_ABANDONED,
            target: Expr::global(frame.target),
            import: None,
            args: frame.args,
        }));
        Ok(())
    }

    /// memcpy / memmove : x0 destination, x1 source, x2 longueur.
    fn copy(&mut self, ctx: &Ctx, at: At, target: Expr, name: String) {
        let args = self.args();
        let state = &mut self.state;
        let (dst, src, len) = (state.x[0].clone(), state.x[1].clone(), state.x[2].clone());
        match len.expr.as_const() {
            Some(n) if n <= MAX_COPY => {
                let cells = state.mem.read(ctx, &src.expr, n);
                let cells = cells.iter().map(|c| c.moved(at)).collect();
                state.mem.write(&dst.expr, cells);
            }
            Some(n) => state
                .mem
                .zone(&dst.expr, Some(n), Reason::Budget, at.addr, at.origin()),
            None => {
                let trace = at.def(&[&len.trace]);
                state
                    .mem
                    .zone(&dst.expr, None, Reason::Havoc, at.addr, trace)
            }
        }
        state.clobber_call(Reason::CallNotFollowed, at);
        state.x[0] = Val::new(dst.expr.clone(), at.def(&[&dst.trace]));
        self.calls.push(Rc::new(CallSeen {
            at: at.addr,
            kind: CALL_COPY,
            target,
            import: Some(name),
            args,
        }));
    }

    fn not_followed(
        &mut self,
        at: At,
        target: Expr,
        import: Option<String>,
        reason: Reason,
        kind: &'static str,
    ) -> Result<(), &'static str> {
        let noreturn = import
            .as_deref()
            .is_some_and(|name| NORETURN_IMPORTS.contains(&name));
        let args = self.args();
        self.calls.push(Rc::new(CallSeen {
            at: at.addr,
            kind,
            target,
            import,
            args,
        }));
        if noreturn {
            return Err(STATUS_NORETURN);
        }
        self.state.clobber_call(reason, at);
        Ok(())
    }
}

/// Ce qu'un watch a relevé sur un chemin. La trace n'entre pas dans l'égalité.
struct Seen {
    kind: &'static str,
    address: Option<Expr>,
    value: Option<Expr>,
    value2: Option<Expr>,
    target: Option<Expr>,
    args: Vec<Expr>,
    sp: Expr,
    trace: Trace,
    peeks: Vec<Peeked>,
}

impl PartialEq for Seen {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.address == other.address
            && self.value == other.value
            && self.value2 == other.value2
            && self.target == other.target
            && self.args == other.args
            && self.sp == other.sp
            && self.peeks == other.peeks
    }
}

#[derive(PartialEq)]
struct Peeked {
    reg: u8,
    offset: i64,
    address: Expr,
    bytes: Vec<Expr>,
}

/// Lecture de `spec` dans `state`, octet par octet comme par ldrb, sans le
/// modifier.
fn peek(ctx: &Ctx, state: &State, spec: &SymexPeek) -> Peeked {
    let base = &state.x[usize::from(spec.reg)].expr;
    let address = add(base, &konst(spec.offset as u64));
    let bytes = (0..u64::from(spec.len))
        .map(|i| assemble(&state.mem.read(ctx, &add(&address, &konst(i)), 1)).0)
        .collect();
    Peeked {
        reg: spec.reg,
        offset: spec.offset,
        address,
        bytes,
    }
}

/// `args` : x0..x8 au moment de l'appel.
#[derive(PartialEq)]
struct CallSeen {
    at: u64,
    kind: &'static str,
    target: Expr,
    import: Option<String>,
    args: Vec<Expr>,
}

#[derive(PartialEq)]
struct BranchSeen {
    at: u64,
    target: Expr,
}

/// Résultat distinct et nombre de chemins qui l'ont produit. `last` : dernier
/// chemin compté.
struct Tally<T> {
    seen: Rc<T>,
    paths: usize,
    last: usize,
}

fn tally<T: PartialEq>(list: &mut Vec<Tally<T>>, seen: &Rc<T>, id: usize) {
    match list.iter_mut().find(|t| *t.seen == **seen) {
        Some(t) if t.last != id => {
            t.paths += 1;
            t.last = id;
        }
        Some(_) => {}
        None => list.push(Tally {
            seen: seen.clone(),
            paths: 1,
            last: id,
        }),
    }
}

/// `args` et `sp` : x0..x3 et sp avant l'instruction.
fn observe(inst: &Instruction, done: &Done, args: &[Expr], sp: &Expr, state: &State) -> Seen {
    let mut seen = Seen {
        kind: KIND_OTHER,
        address: None,
        value: None,
        value2: None,
        target: None,
        args: Vec::new(),
        sp: sp.clone(),
        trace: Trace::default(),
        peeks: Vec::new(),
    };
    match &done.next {
        Next::Call(to) => {
            seen.kind = KIND_CALL;
            seen.target = Some(Expr::global(*to));
            seen.args = args.to_vec();
        }
        Next::CallVia(to) | Next::JumpVia(to) => {
            seen.kind = if matches!(done.next, Next::CallVia(_)) {
                KIND_CALL
            } else {
                KIND_BRANCH
            };
            seen.target = Some(to.expr.clone());
            seen.trace = to.trace.clone();
            seen.args = args.to_vec();
        }
        Next::Fall => {
            if let Some(access) = done.accesses.first() {
                seen.kind = if access.store { KIND_STORE } else { KIND_LOAD };
                seen.address = Some(access.addr.clone());
                if let Some(first) = access.values.first() {
                    seen.value = Some(first.expr.clone());
                    seen.trace = first.trace.clone();
                }
                seen.value2 = access.values.get(1).map(|v| v.expr.clone());
            } else if let Some(def) = state.defined(inst) {
                seen.kind = KIND_DEF;
                seen.value = Some(def.expr);
                seen.trace = def.trace;
            }
        }
        _ => {}
    }
    seen
}

/// memcpy ou memmove, par PLT ou par symbole, à `target` ou au bout d'une
/// suite de `b`.
fn copy_import(ctx: &Ctx, mut target: u64) -> Option<String> {
    for _ in 0..=MAX_COPY_HOPS {
        if let Some(name) = plt_import(ctx, target, false) {
            return COPY_IMPORTS.contains(&name.as_str()).then_some(name);
        }
        if let Some((name, _)) = ctx.symbols.get(&target) {
            return COPY_IMPORTS.contains(&name.as_str()).then(|| name.clone());
        }
        let code = ctx.image.code_window(target)?;
        let insn = decode(Arch::Aarch64, code, target, false).ok()?;
        let Flow::Jump(next, _) = insn.flow else {
            return None;
        };
        target = next;
    }
    None
}

/// Import dont l'emplacement de GOT est lu par `target` = load(8, global(slot)).
fn got_import(ctx: &Ctx, target: &Expr) -> Option<String> {
    let Kind::Load(8, slot) = target.kind() else {
        return None;
    };
    let Kind::Global(slot) = slot.kind() else {
        return None;
    };
    ctx.got.get(slot).cloned()
}

/// Cibles d'un `br` de forme global(B) + (entrée << k), l'entrée lue dans une
/// table global(T) + index : lues dans l'ELF, distinctes, jusqu'à la première
/// hors de la fonction. Index constant : la seule entrée global(T).
fn jump_table(ctx: &Ctx, bound: &Bound, target: &Expr) -> Option<Vec<u64>> {
    let sum = Sum::of(target);
    let ([term], [], true) = (sum.pos.as_slice(), sum.neg.as_slice(), sum.global) else {
        return None;
    };
    let (entry, shift) = match term.kind() {
        Kind::Bin(Op::Lsl, x, k) => (x, k.as_const()?),
        _ => (term, 0),
    };
    if shift > MAX_TABLE_SHIFT {
        return None;
    }
    let (read, extend) = match entry.kind() {
        Kind::Sext(bits, x) => (x, Some((*bits, true))),
        Kind::Zext(bits, x) | Kind::Trunc(bits, x) => (x, Some((*bits, false))),
        _ => (entry, None),
    };
    let Kind::Load(width @ (1 | 2 | 4), slot) = read.kind() else {
        return None;
    };
    let table = Sum::of(slot);
    if !table.global || !table.neg.is_empty() {
        return None;
    }
    let entries = if table.pos.is_empty() {
        1
    } else {
        MAX_TABLE_ENTRIES
    };
    let width = u64::from(*width);
    let mut targets = Vec::new();
    for index in 0..entries {
        let at = table.off.wrapping_add(index * width);
        let bytes = ctx
            .image
            .offset_of(at)
            .and_then(|offset| ctx.image.bytes_at(offset, width));
        let Some(bytes) = bytes else {
            break;
        };
        let raw = read_le(bytes);
        let value = match extend {
            Some((bits, true)) => sign_extend(raw, bits),
            Some((bits, false)) => raw & mask(bits),
            None => raw,
        };
        let to = sum.off.wrapping_add(value << shift);
        let inside = ctx.image.is_exec(to) && bound.contains(ctx, to);
        if !inside {
            break;
        }
        if !targets.contains(&to) {
            targets.push(to);
        }
    }
    (!targets.is_empty()).then_some(targets)
}

fn describe(ctx: &Ctx, at: u64) -> Option<String> {
    let code = ctx.image.code_window(at)?;
    let insn = decode(Arch::Aarch64, code, at, false).ok()?;
    let text = format!("{} {}", insn.mnemonic, insn.operands);
    Some(text.trim_end().to_string())
}

/// Bases et décalages des lectures jamais écrites contenues dans `e`.
fn fresh_loads(e: &Expr, out: &mut Vec<(Expr, i64)>) {
    match e.kind() {
        Kind::Load(_, addr) => {
            out.push(split(addr));
            fresh_loads(addr, out);
        }
        Kind::Bin(_, a, b) | Kind::Ite(_, a, b) => {
            fresh_loads(a, out);
            fresh_loads(b, out);
        }
        Kind::Zext(_, x) | Kind::Sext(_, x) | Kind::Trunc(_, x) => fresh_loads(x, out),
        _ => {}
    }
}

type Decoded = Option<(Instruction, Insn)>;

/// Graphe de flot de la fonction analysée : blocs de sa plage désassemblée
/// linéairement, et distance de chacun, en blocs, au watch le plus proche.
struct Cfg {
    starts: Vec<u64>,
    ends: Vec<u64>,
    distances: Vec<u32>,
}

impl Cfg {
    /// `None` : plage inconnue, aucun watch, ou un watch hors de la plage.
    fn build(ctx: &Ctx, bound: &Bound, watches: &[u64]) -> Option<Cfg> {
        let (start, end) = (bound.start, bound.end?);
        if watches.is_empty() || !watches.iter().all(|at| (start..end).contains(at)) {
            return None;
        }
        let mut insns: Vec<(u64, Decoded)> = Vec::new();
        let mut at = start;
        while at < end {
            let code = ctx.image.code_window(at);
            insns.push((at, code.and_then(|code| decode_a64_full(code, at).ok())));
            at = at.wrapping_add(4);
        }
        let index = |at: u64| ((at - start) / 4) as usize;
        let mut leaders = BTreeSet::from([start]);
        for (at, decoded) in &insns {
            let next = at.wrapping_add(4);
            match decoded.as_ref().map(|(_, insn)| insn.flow) {
                Some(Flow::Next | Flow::Call(..) | Flow::CallVia(_)) => {}
                Some(Flow::Jump(to, _) | Flow::Branch(to, _)) => {
                    leaders.insert(to);
                    leaders.insert(next);
                }
                _ => {
                    leaders.insert(next);
                }
            }
        }
        let mut tables: HashMap<u64, Vec<u64>> = HashMap::new();
        for (from, to) in spans(&leaders, start, end) {
            let block = &insns[index(from)..index(to).min(insns.len())];
            let Some((at, Some((_, insn)))) = block.last() else {
                continue;
            };
            if !matches!(insn.flow, Flow::JumpVia(_)) {
                continue;
            }
            if let Some(targets) = br_targets(ctx, bound, block) {
                leaders.extend(targets.iter().copied());
                tables.insert(*at, targets);
            }
        }
        let blocks = spans(&leaders, start, end);
        let mut cfg = Cfg {
            starts: blocks.iter().map(|&(from, _)| from).collect(),
            ends: blocks.iter().map(|&(_, to)| to).collect(),
            distances: vec![INFINITE; blocks.len()],
        };
        let mut preds = vec![Vec::new(); blocks.len()];
        let mut open = Vec::new();
        for (b, &(from, to)) in blocks.iter().enumerate() {
            let last = from + 4 * ((to - from - 1) / 4);
            let flow = insns
                .get(index(last))
                .and_then(|(_, d)| d.as_ref().map(|d| d.1.flow));
            let successors = match flow {
                Some(Flow::Next | Flow::Call(..) | Flow::CallVia(_)) => vec![to],
                Some(Flow::Jump(target, _)) => vec![target],
                Some(Flow::Branch(target, _)) => vec![target, to],
                Some(Flow::JumpVia(_)) => match tables.get(&last) {
                    Some(targets) => targets.clone(),
                    None => {
                        open.push(b);
                        Vec::new()
                    }
                },
                _ => Vec::new(),
            };
            for succ in successors.into_iter().filter_map(|at| cfg.block(at)) {
                preds[succ].push(b);
            }
        }
        let mut heap = BinaryHeap::new();
        let targets: Vec<usize> = watches.iter().filter_map(|&at| cfg.block(at)).collect();
        for b in targets {
            cfg.distances[b] = 0;
            heap.push(Reverse((0, b)));
        }
        // Un br non résolu peut mener à un watch : distance finie, la plus grande.
        let unknown = u32::try_from(blocks.len()).unwrap_or(RANK_UNKNOWN - 1);
        for b in open {
            if cfg.distances[b] > unknown {
                cfg.distances[b] = unknown;
                heap.push(Reverse((unknown, b)));
            }
        }
        while let Some(Reverse((d, b))) = heap.pop() {
            if d > cfg.distances[b] {
                continue;
            }
            for &p in &preds[b] {
                if d + 1 < cfg.distances[p] {
                    cfg.distances[p] = d + 1;
                    heap.push(Reverse((d + 1, p)));
                }
            }
        }
        Some(cfg)
    }

    fn block(&self, at: u64) -> Option<usize> {
        let index = self.starts.partition_point(|&s| s <= at).checked_sub(1)?;
        (at < self.ends[index]).then_some(index)
    }

    /// `None` : `at` hors de la plage ; [`INFINITE`] : aucun watch atteignable.
    fn distance(&self, at: u64) -> Option<u32> {
        self.block(at).map(|b| self.distances[b])
    }
}

/// Blocs `[début, fin)` délimités par `leaders` dans `[start, end)`.
fn spans(leaders: &BTreeSet<u64>, start: u64, end: u64) -> Vec<(u64, u64)> {
    let inside: Vec<u64> = leaders.range(start..end).copied().collect();
    let ends = inside.iter().skip(1).copied().chain([end]);
    inside.iter().copied().zip(ends).collect()
}

/// Cibles du `br` qui termine `block`, lues comme pendant l'exploration, depuis
/// un état initial pris au début du bloc.
fn br_targets(ctx: &Ctx, bound: &Bound, block: &[(u64, Decoded)]) -> Option<Vec<u64>> {
    let mut state = State::initial();
    for &(addr, ref decoded) in block {
        let (inst, insn) = decoded.as_ref()?;
        let at = At { addr, step: 0 };
        if let Next::JumpVia(target) = state.exec(ctx, inst, &insn.mnemonic, at).next {
            return match target.expr.kind() {
                Kind::Const(to) | Kind::Global(to) => Some(vec![*to]),
                _ => jump_table(ctx, bound, &target.expr),
            };
        }
    }
    None
}

struct Explorer<'c, 'a> {
    ctx: &'c Ctx<'a>,
    fdes: &'c [(u64, u64)],
    cfg: Option<&'c Cfg>,
    /// Adresses d'appel suivies quelle que soit la profondeur.
    follow: &'c BTreeSet<u64>,
    options: &'c SymexOptions,
    watched: HashSet<u64>,
    /// Frères ouverts dans la fonction analysée, explorés avant `pending_callees`.
    pending: Vec<Path>,
    pending_callees: Vec<Path>,
    /// Appels que le raffinement désigne pour la relance suivante.
    wanted: BTreeSet<u64>,
    started: usize,
    cut: BTreeMap<&'static str, usize>,
    budget_hit: bool,
    abandoned: usize,
    incomplete: usize,
    forks_dropped: usize,
    results: HashMap<u64, Vec<Tally<Seen>>>,
    calls: Vec<Tally<CallSeen>>,
    branches: Vec<Tally<BranchSeen>>,
}

impl<'c, 'a> Explorer<'c, 'a> {
    fn new(
        ctx: &'c Ctx<'a>,
        fdes: &'c [(u64, u64)],
        cfg: Option<&'c Cfg>,
        follow: &'c BTreeSet<u64>,
        options: &'c SymexOptions,
    ) -> Self {
        Explorer {
            ctx,
            fdes,
            cfg,
            follow,
            options,
            watched: options.watch.iter().copied().collect(),
            pending: Vec::new(),
            pending_callees: Vec::new(),
            wanted: BTreeSet::new(),
            started: 0,
            cut: BTreeMap::new(),
            budget_hit: false,
            abandoned: 0,
            incomplete: 0,
            forks_dropped: 0,
            results: HashMap::new(),
            calls: Vec::new(),
            branches: Vec::new(),
        }
    }

    /// En profondeur d'abord ; un frère attend son tour dans `pending`, ou dans
    /// `pending_callees` s'il a été ouvert dans un appelé.
    fn run(&mut self, fn_start: u64, entry: u64) {
        self.pending.push(Path::new(self.bound(fn_start), entry));
        while let Some(mut path) = self.next_path() {
            let id = self.started;
            self.started += 1;
            let status = loop {
                if let Err(status) = self.step(&mut path) {
                    break status;
                }
            };
            self.finish(&path, id, status);
        }
    }

    /// Le frère de la fonction analysée le plus proche d'un watch, le plus récent
    /// à égalité ; à défaut, le dernier frère ouvert dans un appelé.
    fn next_path(&mut self) -> Option<Path> {
        let ranked = self.pending.iter().enumerate();
        let best = ranked.min_by_key(|(i, p)| (p.rank, Reverse(*i)));
        match best.map(|(i, _)| i) {
            Some(index) => Some(self.pending.remove(index)),
            None => self.pending_callees.pop(),
        }
    }

    /// Distance aux watches du bloc de `at` dans la fonction analysée.
    fn rank(&self, at: u64) -> u32 {
        let distance = self.cfg.and_then(|cfg| cfg.distance(at));
        distance.unwrap_or(RANK_UNKNOWN)
    }

    fn fork(&mut self, mut path: Path) {
        let waiting = self.pending.len() + self.pending_callees.len();
        if self.started + waiting >= self.options.max_paths {
            self.budget_hit = true;
        } else if path.in_callee() {
            self.pending_callees.push(path);
        } else {
            path.rank = self.rank(path.pc);
            self.pending.push(path);
        }
    }

    /// Raffinement : appels directs sautés sur ce chemin dont un argument
    /// x0..x8, autre qu'une constante, a la base d'une lecture jamais écrite
    /// relevée par ce watch et un décalage inférieur ou égal au sien.
    fn want(&mut self, path: &Path, seen: &Seen) {
        if self.options.refine == 0 || path.skipped.is_empty() {
            return;
        }
        let mut reads = Vec::new();
        let observed = [&seen.address, &seen.value, &seen.value2, &seen.target];
        for e in observed.into_iter().flatten() {
            fresh_loads(e, &mut reads);
        }
        for call in &path.skipped {
            let points = |arg: &Expr| {
                let (base, off) = split(arg);
                arg.as_const().is_none() && reads.iter().any(|(b, o)| *b == base && off <= *o)
            };
            if call.args.iter().any(points) {
                self.wanted.insert(call.at);
            }
        }
    }

    fn peeks(&self, state: &State, pc: u64) -> Vec<Peeked> {
        let specs = self.options.peek.iter().filter(|spec| spec.watch == pc);
        specs.map(|spec| peek(self.ctx, state, spec)).collect()
    }

    /// Un branchement peut-il ouvrir un frère ? Toujours dans la fonction
    /// analysée ; dans un appelé, dans la limite de callee_forks.
    fn may_fork(&mut self, path: &mut Path) -> bool {
        if !path.in_callee() {
            return true;
        }
        if path.forks < self.options.callee_forks {
            path.forks += 1;
            return true;
        }
        self.forks_dropped += 1;
        false
    }

    fn finish(&mut self, path: &Path, id: usize, status: &'static str) {
        if status != STATUS_RETURNED {
            *self.cut.entry(status).or_insert(0) += 1;
        }
        if path.abandoned {
            self.abandoned += 1;
        }
        if path.incomplete {
            self.incomplete += 1;
        }
        for (watch, seen) in &path.hits {
            tally(self.results.entry(*watch).or_default(), seen, id);
        }
        for call in &path.calls {
            tally(&mut self.calls, call, id);
        }
        for branch in &path.branches {
            tally(&mut self.branches, branch, id);
        }
    }

    fn step(&mut self, path: &mut Path) -> Result<(), &'static str> {
        if path.insns >= self.options.max_insns {
            self.budget_hit = true;
            return Err(STATUS_BUDGET);
        }
        let pc = path.pc;
        let far = |cfg: &Cfg| cfg.distance(pc) == Some(INFINITE);
        if !path.in_callee() && self.cfg.is_some_and(far) {
            return Err(STATUS_OFF_TARGET);
        }
        let visits = path.visits.entry((pc, path.context)).or_insert(0);
        *visits += 1;
        if *visits > MAX_VISITS {
            if path.frames.is_empty() {
                return Err(STATUS_CUT_LOOP);
            }
            return path.abandon();
        }
        let code = self.ctx.image.code_window(pc).ok_or(STATUS_INVALID)?;
        let (inst, insn) = decode_a64_full(code, pc).map_err(|_| STATUS_INVALID)?;
        path.insns += 1;
        let at = At {
            addr: pc,
            step: u32::try_from(path.insns).unwrap_or(u32::MAX),
        };
        let watched = self.watched.contains(&pc);
        let args: Vec<Expr> = if watched {
            path.state.x[..4].iter().map(|v| v.expr.clone()).collect()
        } else {
            Vec::new()
        };
        let peeks: Vec<Peeked> = if watched {
            self.peeks(&path.state, pc)
        } else {
            Vec::new()
        };
        let sp = path.state.x[usize::from(SP)].expr.clone();
        let done = path.state.exec(self.ctx, &inst, &insn.mnemonic, at);
        let next_pc = pc.wrapping_add(4);
        if watched {
            let mut seen = observe(&inst, &done, &args, &sp, &path.state);
            self.want(path, &seen);
            seen.peeks = peeks;
            path.hits.push((pc, Rc::new(seen)));
        }
        match done.next {
            Next::Fall => {
                path.pc = next_pc;
                Ok(())
            }
            Next::Jump(target) => self.jump(path, at, target),
            Next::Fork(target) => {
                if self.may_fork(path) {
                    let mut other = path.clone();
                    other.pc = target;
                    self.fork(other);
                }
                path.pc = next_pc;
                Ok(())
            }
            Next::Call(target) => self.call(path, at, target),
            Next::CallVia(target) => self.call_via(path, at, target),
            Next::JumpVia(target) => self.jump_via(path, at, target),
            Next::Return => path.ret(),
            Next::Trap => Err(STATUS_TRAP),
        }
    }

    fn bound(&self, at: u64) -> Bound {
        Bound::of(self.ctx, self.fdes, at)
    }

    /// Appel direct en `at` suivi : profondeur restante, ou adresse d'appel dans
    /// l'ensemble à suivre.
    fn follows(&self, path: &Path, at: u64, target: u64) -> bool {
        let deep = path.level() < usize::from(self.options.depth);
        self.ctx.image.is_exec(target) && (deep || self.follow.contains(&at))
    }

    /// Morceau externalisé : `target` commence une plage connue d'au plus
    /// fragment_max octets, sous la limite d'imbrication.
    fn fragment(&self, path: &Path, bound: &Bound, target: u64) -> bool {
        let max = self.options.fragment_max;
        let small = bound
            .end
            .is_some_and(|end| end.saturating_sub(target) <= max);
        let nested = path.fragments < MAX_FRAGMENTS;
        max > 0 && bound.start == target && small && nested && self.ctx.image.is_exec(target)
    }

    fn call(&mut self, path: &mut Path, at: At, target: u64) -> Result<(), &'static str> {
        let ret = at.addr.wrapping_add(4);
        path.state.x[30] = Val::new(Expr::global(ret), at.origin());
        path.pc = ret;
        let to = Expr::global(target);
        let lost = Reason::CallNotFollowed;
        if let Some(name) = copy_import(self.ctx, target) {
            path.copy(self.ctx, at, to, name);
            return Ok(());
        }
        if let Some(name) = plt_import(self.ctx, target, false) {
            return path.not_followed(at, to, Some(name), lost, CALL_DIRECT);
        }
        let bound = self.bound(target);
        let fragment = self.fragment(path, &bound, target);
        if fragment || self.follows(path, at.addr, target) {
            path.enter(at.addr, target, bound, fragment);
            return Ok(());
        }
        if self.ctx.image.is_exec(target) {
            path.mark_incomplete();
            path.skip(at.addr);
        }
        path.not_followed(at, to, None, lost, CALL_DIRECT)
    }

    /// `b` : saut dans la fonction courante, sinon appel terminal.
    fn jump(&mut self, path: &mut Path, at: At, target: u64) -> Result<(), &'static str> {
        let to = Expr::global(target);
        let lost = Reason::CallNotFollowed;
        if let Some(name) = copy_import(self.ctx, target) {
            path.copy(self.ctx, at, to, name);
            return path.ret();
        }
        if let Some(name) = plt_import(self.ctx, target, false) {
            path.not_followed(at, to, Some(name), lost, CALL_DIRECT)?;
            return path.unwind();
        }
        if path.bound.contains(self.ctx, target) {
            path.pc = target;
            return Ok(());
        }
        let bound = self.bound(target);
        if self.fragment(path, &bound, target) {
            path.bound = bound;
            path.pc = target;
            return Ok(());
        }
        if self.follows(path, at.addr, target) {
            path.bound = bound;
            path.tails = path.tails.saturating_add(1);
            path.pc = target;
            return Ok(());
        }
        if self.ctx.image.is_exec(target) {
            path.mark_incomplete();
            path.skip(at.addr);
        }
        path.not_followed(at, to, None, lost, CALL_DIRECT)?;
        path.unwind()
    }

    fn call_via(&mut self, path: &mut Path, at: At, target: Val) -> Result<(), &'static str> {
        let ret = at.addr.wrapping_add(4);
        path.state.x[30] = Val::new(Expr::global(ret), at.origin());
        path.pc = ret;
        let lost = Reason::IndirectCall;
        match got_import(self.ctx, &target.expr) {
            Some(name) if COPY_IMPORTS.contains(&name.as_str()) => {
                path.copy(self.ctx, at, target.expr, name);
                Ok(())
            }
            import => path.not_followed(at, target.expr, import, lost, CALL_INDIRECT),
        }
    }

    fn jump_via(&mut self, path: &mut Path, at: At, target: Val) -> Result<(), &'static str> {
        if let Kind::Const(to) | Kind::Global(to) = target.expr.kind() {
            if self.ctx.image.is_exec(*to) {
                return self.jump(path, at, *to);
            }
        }
        if let Some(targets) = jump_table(self.ctx, &path.bound, &target.expr) {
            for &to in &targets[1..] {
                if self.may_fork(path) {
                    let mut other = path.clone();
                    other.pc = to;
                    self.fork(other);
                }
            }
            path.pc = targets[0];
            return Ok(());
        }
        if path.in_callee() {
            let import = got_import(self.ctx, &target.expr);
            let lost = Reason::IndirectCall;
            path.not_followed(at, target.expr, import, lost, CALL_INDIRECT_TAIL)?;
            return path.unwind();
        }
        path.branches.push(Rc::new(BranchSeen {
            at: at.addr,
            target: target.expr,
        }));
        Err(STATUS_INDIRECT_BRANCH)
    }

    fn report(&self, elf: &str, fn_start: u64, entry: u64) -> SymexReport {
        let watches = self
            .options
            .watch
            .iter()
            .map(|&at| {
                let results: Vec<SymexResult> = match self.results.get(&at) {
                    Some(list) => list.iter().map(result).collect(),
                    None => Vec::new(),
                };
                SymexWatch {
                    insn_addr: hex(at),
                    instruction: describe(self.ctx, at),
                    reached: !results.is_empty(),
                    results,
                }
            })
            .collect();
        let calls = self
            .calls
            .iter()
            .map(|t| SymexCall {
                insn_addr: hex(t.seen.at),
                kind: t.seen.kind,
                target: Shown::of(&t.seen.target),
                import: t.seen.import.clone(),
                args: t.seen.args.iter().map(|a| a.to_string()).collect(),
                paths: t.paths,
            })
            .collect();
        let indirect_branches = self
            .branches
            .iter()
            .map(|t| SymexBranch {
                insn_addr: hex(t.seen.at),
                target: Shown::of(&t.seen.target),
                paths: t.paths,
            })
            .collect();
        let bound = self.bound(fn_start);
        SymexReport {
            elf: elf.to_string(),
            fn_start: hex(bound.start),
            fn_end: bound.end.map(hex),
            bound: bound.source,
            entry: hex(entry),
            budgets: SymexBudgets {
                depth: self.options.depth,
                max_insns: self.options.max_insns,
                max_paths: self.options.max_paths,
                fragment_max: self.options.fragment_max,
                callee_forks: self.options.callee_forks,
                refine: self.options.refine,
            },
            directed: self.cfg.is_some(),
            rounds: Vec::new(),
            paths_explored: self.started,
            paths_cut: self.cut.clone(),
            budget_hit: self.budget_hit,
            callees_abandoned: self.abandoned,
            callees_incomplete: self.incomplete,
            forks_dropped: self.forks_dropped,
            watches,
            calls,
            indirect_branches,
        }
    }
}

fn result(t: &Tally<Seen>) -> SymexResult {
    let seen = &t.seen;
    let (trace, trace_truncated) = seen.trace.addresses();
    SymexResult {
        kind: seen.kind,
        address: seen.address.as_ref().map(Shown::of),
        value: seen.value.as_ref().map(Shown::of),
        value2: seen.value2.as_ref().map(Shown::of),
        target: seen.target.as_ref().map(Shown::of),
        args: seen.args.iter().map(Shown::of).collect(),
        sp: Shown::of(&seen.sp),
        paths: t.paths,
        trace: trace.into_iter().map(hex).collect(),
        trace_truncated,
        peeks: seen.peeks.iter().map(peeked).collect(),
    }
}

fn peeked(p: &Peeked) -> SymexPeeked {
    let offset = match p.offset {
        off if off < 0 => format!("-{:#x}", off.unsigned_abs()),
        off => format!("{off:#x}"),
    };
    SymexPeeked {
        reg: reg_name(p.reg),
        offset,
        len: p.bytes.len() as u8,
        address: Shown::of(&p.address),
        bytes: p.bytes.iter().map(Shown::of).collect(),
    }
}

/// Étiquettes à définir dans la légende : statuts, raisons, formes, kinds.
#[cfg(test)]
fn labels() -> Vec<&'static str> {
    let mut labels = vec![
        STATUS_RETURNED,
        STATUS_CUT_LOOP,
        STATUS_INDIRECT_BRANCH,
        STATUS_BUDGET,
        STATUS_NORETURN,
        STATUS_TRAP,
        STATUS_INVALID,
        STATUS_OFF_TARGET,
        KIND_LOAD,
        KIND_STORE,
        KIND_CALL,
        KIND_BRANCH,
        KIND_DEF,
        KIND_OTHER,
        CALL_INDIRECT,
        CALL_DIRECT,
        CALL_COPY,
        CALL_INDIRECT_TAIL,
        CALL_ABANDONED,
        "callees_abandoned",
        "callees_incomplete",
        "fragment_max",
        "callee_forks",
        "forks_dropped",
        "directed",
        "rounds[]",
        "raffinement",
        "follow",
        "peeks",
        "refine",
        "couverture",
        "ordre d'exploration",
        "morceau",
        "registres préservés",
        "repli",
        BOUND_SYMBOL,
        BOUND_EH_FRAME,
        BOUND_NONE,
        "fn_end",
        "const",
        "init(",
        "global(",
        "load(",
        "zext",
        "sext",
        "trunc",
        "ite(",
        "unknown(",
    ];
    labels.extend(Reason::ALL.iter().map(|r| r.label()));
    labels.extend(Op::ALL.iter().map(|op| op.name()));
    labels.extend(COPY_IMPORTS);
    labels
}

#[cfg(test)]
mod tests {
    use super::super::Image;
    use super::*;

    const CODE: u64 = 0x1000;

    /// Segment chargé à l'adresse de son offset.
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

    /// Un seul segment LOAD, R+X, sans écriture.
    fn image(data: &[u8]) -> Image<'_> {
        let size = data.len() as u64;
        Image {
            data,
            ptr_size: 8,
            big_endian: false,
            machine: elf::EM_AARCH64,
            segments: vec![segment(elf::PT_LOAD, elf::PF_R | elf::PF_X, 0, size)],
            sections: Vec::new(),
        }
    }

    fn put(data: &mut [u8], at: u64, bytes: &[u8]) {
        let at = at as usize;
        data[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn assemble_at(data: &mut [u8], at: u64, code: &[(u32, &str)]) {
        for (i, (word, _)) in code.iter().enumerate() {
            put(data, at + 4 * i as u64, &word.to_le_bytes());
        }
    }

    fn loaded<'d>(data: &'d [u8], dynamic: Option<&[(u64, u64)]>) -> Ctx<'d> {
        context(image(data), dynamic, &[], &[])
    }

    fn plain(data: &[u8]) -> Ctx<'_> {
        loaded(data, None)
    }

    fn function(ctx: &mut Ctx, at: u64, size: u64) {
        ctx.symbols.insert(at, (format!("f_{at:x}"), size));
        ctx.starts.insert(at);
    }

    fn options(watch: &[u64], depth: u8) -> SymexOptions {
        SymexOptions {
            watch: watch.to_vec(),
            depth,
            ..SymexOptions::default()
        }
    }

    /// Aucun morceau : toute fonction suivie compte dans la profondeur.
    fn no_fragments(watch: &[u64], depth: u8) -> SymexOptions {
        SymexOptions {
            fragment_max: 0,
            ..options(watch, depth)
        }
    }

    fn explore(ctx: &Ctx, options: &SymexOptions) -> SymexReport {
        bounded(ctx, &[], options)
    }

    /// `fdes` : plages FDE fournies à la place d'un `.eh_frame`.
    fn bounded(ctx: &Ctx, fdes: &[(u64, u64)], options: &SymexOptions) -> SymexReport {
        let follow = BTreeSet::new();
        let mut explorer = Explorer::new(ctx, fdes, None, &follow, options);
        explorer.run(CODE, CODE);
        explorer.report("libtest.so", CODE, CODE)
    }

    /// Exploration dirigée et relances, comme `run`.
    fn analyzed(ctx: &Ctx, options: &SymexOptions) -> SymexReport {
        analyze(ctx, &[], "libtest.so", CODE, CODE, options)
    }

    fn watch(report: &SymexReport, at: u64) -> &SymexWatch {
        let address = hex(at);
        let found = report.watches.iter().find(|w| w.insn_addr == address);
        found.expect("watch demandé")
    }

    fn only(report: &SymexReport, at: u64) -> &SymexResult {
        let w = watch(report, at);
        assert!(w.reached, "{} jamais atteinte", w.insn_addr);
        assert_eq!(w.results.len(), 1, "{:?}", w.results);
        &w.results[0]
    }

    fn text(shown: &Option<Shown>) -> &str {
        shown.as_ref().map_or("", |s| s.text.as_str())
    }

    fn value(report: &SymexReport, at: u64) -> &str {
        text(&only(report, at).value)
    }

    /// Un octet de [x0 + 5], puis 8 octets de [x0 + 8] via q0, transitent par la
    /// pile avant d'être rangés en [x1].
    const STACK_COPY: &[(u32, &str)] = &[
        (0xd10083ff, "1000  sub   sp, sp, #0x20"),
        (0x39401408, "1004  ldrb  w8, [x0, #0x5]"),
        (0x39003fe8, "1008  strb  w8, [sp, #0xf]"),
        (0x39403fe9, "100c  ldrb  w9, [sp, #0xf]"),
        (0x39000029, "1010  strb  w9, [x1]"),
        (0x3dc00000, "1014  ldr   q0, [x0]"),
        (0x3d8003e0, "1018  str   q0, [sp]"),
        (0xf94007ea, "101c  ldr   x10, [sp, #0x8]"),
        (0xf900002a, "1020  str   x10, [x1]"),
        (0x910083ff, "1024  add   sp, sp, #0x20"),
        (0xd65f03c0, "1028  ret"),
    ];

    #[test]
    fn a_value_copied_through_the_stack_keeps_its_origin() {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, STACK_COPY);
        let ctx = plain(&data);
        let report = explore(&ctx, &options(&[CODE, 0x1010, 0x1020], 2));
        assert_eq!(report.paths_explored, 1);
        assert!(report.paths_cut.is_empty());
        assert_eq!(only(&report, CODE).sp.text, "init(sp)");

        let byte = only(&report, 0x1010);
        assert_eq!(byte.sp.text, "init(sp) - 0x20");
        assert_eq!(byte.kind, KIND_STORE);
        assert_eq!(text(&byte.address), "init(x1)");
        assert_eq!(text(&byte.value), "load(1, init(x0) + 0x5)");
        assert_eq!(byte.trace, ["0x1004", "0x1008", "0x100c", "0x1010"]);

        let half = only(&report, 0x1020);
        assert_eq!(text(&half.value), "load(8, init(x0) + 0x8)");
        assert_eq!(half.trace, ["0x1014", "0x1018", "0x101c", "0x1020"]);
    }

    /// memcpy(sp, x1, 0x10) par la PLT, puis relectures dans et hors de la copie.
    const MEMCPY_CALL: &[(u32, &str)] = &[
        (0xd10103ff, "1000  sub   sp, sp, #0x40"),
        (0x910003e0, "1004  mov   x0, sp"),
        (0xd2800202, "1008  mov   x2, #0x10"),
        (0x940001fd, "100c  bl    0x1800   ; memcpy@plt"),
        (0x39400fe8, "1010  ldrb  w8, [sp, #0x3]"),
        (0xf94007e9, "1014  ldr   x9, [sp, #0x8]"),
        (0x39404fea, "1018  ldrb  w10, [sp, #0x13]"),
        (0x910103ff, "101c  add   sp, sp, #0x40"),
        (0xd65f03c0, "1020  ret"),
    ];

    /// Stub PLT AArch64 : GOT en 0x3000.
    const PLT: &[(u32, &str)] = &[
        (0xd0000010, "1800  adrp  x16, 0x3000"),
        (0xf9400211, "1804  ldr   x17, [x16]"),
        (0x91000210, "1808  add   x16, x16, #0x0"),
        (0xd61f0220, "180c  br    x17"),
    ];

    /// JUMP_SLOT en 0x2800 : emplacement 0x3000 → symbole dynamique 1, `name`.
    fn jump_slot(data: &mut [u8], name: &str) -> [(u64, u64); 6] {
        put(data, 0x2800, &0x3000u64.to_le_bytes());
        let info = (1u64 << 32) | u64::from(elf::R_AARCH64_JUMP_SLOT);
        put(data, 0x2808, &info.to_le_bytes());
        put(data, 0x2918, &1u32.to_le_bytes());
        put(data, 0x2a01, name.as_bytes());
        [
            (u64::from(elf::DT_JMPREL), 0x2800),
            (u64::from(elf::DT_PLTRELSZ), 24),
            (u64::from(elf::DT_PLTREL), u64::from(elf::DT_RELA)),
            (u64::from(elf::DT_SYMTAB), 0x2900),
            (u64::from(elf::DT_STRTAB), 0x2a00),
            (u64::from(elf::DT_SYMENT), 24),
        ]
    }

    #[test]
    fn a_constant_memcpy_copies_the_source_bytes() {
        let mut data = vec![0u8; 0x4000];
        assemble_at(&mut data, CODE, MEMCPY_CALL);
        assemble_at(&mut data, 0x1800, PLT);
        let dynamic = jump_slot(&mut data, "memcpy");
        let ctx = loaded(&data, Some(&dynamic[..]));
        let report = explore(&ctx, &options(&[0x1010, 0x1014, 0x1018], 2));

        assert_eq!(value(&report, 0x1010), "load(1, init(x1) + 0x3)");
        assert_eq!(value(&report, 0x1014), "load(8, init(x1) + 0x8)");
        assert_eq!(value(&report, 0x1018), "load(1, init(sp) - 0x2d)");

        assert_eq!(report.calls.len(), 1);
        let call = &report.calls[0];
        assert_eq!(call.kind, CALL_COPY);
        assert_eq!(call.import.as_deref(), Some("memcpy"));
        assert_eq!(call.target.text, "global(0x1800)");
    }

    /// Le helper externalisé finit par un b vers une autre fonction.
    const OUTLINED: &[(u32, &str)] = &[
        (0xa9bf7bfd, "1000  stp   x29, x30, [sp, #-0x10]!"),
        (0x9400003f, "1004  bl    0x1100"),
        (0x39000260, "1008  strb  w0, [x19]"),
        (0xa8c17bfd, "100c  ldp   x29, x30, [sp], #0x10"),
        (0xd65f03c0, "1010  ret"),
    ];

    const OUTLINED_HELPER: &[(u32, &str)] = &[
        (0x91004000, "1100  add   x0, x0, #0x10"),
        (0x1400003f, "1104  b     0x1200"),
    ];

    const OUTLINED_TAIL: &[(u32, &str)] = &[
        (0x39400800, "1200  ldrb  w0, [x0, #0x2]"),
        (0xd65f03c0, "1204  ret"),
    ];

    #[test]
    fn an_outlined_helper_ending_in_a_tail_call_is_traversed() {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, OUTLINED);
        assemble_at(&mut data, 0x1100, OUTLINED_HELPER);
        assemble_at(&mut data, 0x1200, OUTLINED_TAIL);
        let mut ctx = plain(&data);
        function(&mut ctx, CODE, 0x14);
        function(&mut ctx, 0x1100, 0x8);
        function(&mut ctx, 0x1200, 0x8);
        let report = explore(&ctx, &options(&[0x1008], 2));

        assert_eq!(report.paths_explored, 1);
        assert!(report.paths_cut.is_empty());
        assert!(report.calls.is_empty());
        let stored = only(&report, 0x1008);
        assert_eq!(text(&stored.address), "init(x19)");
        assert_eq!(text(&stored.value), "load(1, init(x0) + 0x12)");
        assert_eq!(stored.trace, ["0x1200", "0x1008"]);
    }

    /// Table de saut : adr de la table, ldrb de l'entrée, adr de la base, add
    /// lsl #2, br. Quatrième entrée hors de la fonction.
    const SWITCH: &[(u32, &str)] = &[
        (0x10000809, "1000  adr   x9, 0x1100"),
        (0x3860692a, "1004  ldrb  w10, [x9, x0]"),
        (0x100000cb, "1008  adr   x11, 0x1020"),
        (0x8b0a096b, "100c  add   x11, x11, x10, lsl #2"),
        (0xd61f0160, "1010  br    x11"),
    ];

    const SWITCH_CASES: &[(u32, &str)] = &[
        (0xd2800020, "1020  mov   x0, #1"),
        (0xd65f03c0, "1024  ret"),
        (0xd2800040, "1028  mov   x0, #2"),
        (0xd65f03c0, "102c  ret"),
        (0xd2800060, "1030  mov   x0, #3"),
        (0xd65f03c0, "1034  ret"),
    ];

    #[test]
    fn a_jump_table_gives_one_path_per_target_inside_the_function() {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, SWITCH);
        assemble_at(&mut data, 0x1020, SWITCH_CASES);
        put(&mut data, 0x1100, &[0, 2, 4, 0xff]);
        let mut ctx = plain(&data);
        function(&mut ctx, CODE, 0x38);
        let report = explore(&ctx, &options(&[0x1010, 0x1020, 0x1028, 0x1030], 2));

        assert_eq!(report.paths_explored, 3);
        assert!(report.paths_cut.is_empty());
        assert!(report.indirect_branches.is_empty());
        let branch = only(&report, 0x1010);
        assert_eq!(branch.kind, KIND_BRANCH);
        assert_eq!(branch.paths, 3);
        assert_eq!(
            text(&branch.target),
            "lsl(load(1, init(x0) + global(0x1100)), 0x2) + global(0x1020)"
        );
        for (at, expected) in [(0x1020, "0x1"), (0x1028, "0x2"), (0x1030, "0x3")] {
            let case = only(&report, at);
            assert_eq!(case.kind, KIND_DEF);
            assert_eq!(text(&case.value), expected);
            assert_eq!(case.paths, 1);
        }
    }

    #[test]
    fn without_symbols_an_fde_range_stops_a_jump_table_at_the_next_table() {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, SWITCH);
        assemble_at(&mut data, 0x1020, SWITCH_CASES);
        // Trois entrées, puis les deux premières d'une table voisine (0x1060, 0x1068).
        put(&mut data, 0x1100, &[0, 2, 4, 0x10, 0x12]);
        let ctx = plain(&data);
        let watched = options(&[0x1020, 0x1028, 0x1030], 2);

        let report = bounded(&ctx, &[(CODE, 0x1038)], &watched);
        assert_eq!(report.bound, BOUND_EH_FRAME);
        assert_eq!(report.fn_end.as_deref(), Some("0x1038"));
        assert_eq!(report.paths_explored, 3);
        assert!(report.paths_cut.is_empty());

        let loose = explore(&ctx, &watched);
        assert_eq!(loose.bound, BOUND_NONE);
        assert_eq!(loose.fn_end, None);
        assert_eq!(loose.paths_explored, 5);
    }

    #[test]
    fn an_inner_address_reports_the_function_start_and_starts_from_itself() {
        let mut data = vec![0u8; 0x2000];
        let code = [
            (0xd503201f, "1000  nop"),
            (0xd503201f, "1004  nop"),
            (0xd2800020, "1008  mov   x0, #0x1"),
            (0xd65f03c0, "100c  ret"),
        ];
        assemble_at(&mut data, CODE, &code);
        let ctx = plain(&data);
        let inner = CODE + 8;
        let watched = options(&[inner], 0);
        let fdes = [(CODE, CODE + 0x10)];

        let report = analyze(&ctx, &fdes, "libtest.so", inner, inner, &watched);
        assert_eq!(report.fn_start, "0x1000");
        assert_eq!(report.fn_end.as_deref(), Some("0x1010"));
        assert_eq!(report.bound, BOUND_EH_FRAME);
        assert_eq!(report.entry, "0x1008");
        assert_eq!(report.paths_explored, 1);
        assert_eq!(value(&report, inner), "0x1");

        let loose = analyze(&ctx, &[], "libtest.so", inner, inner, &watched);
        assert_eq!(loose.bound, BOUND_NONE);
        assert_eq!(loose.fn_start, "0x1008");
    }

    #[test]
    fn a_b_outside_the_fde_range_is_a_tail_call_counted_in_the_depth() {
        let mut data = vec![0u8; 0x2000];
        put(&mut data, CODE, &0x14000040u32.to_le_bytes());
        put(&mut data, 0x1100, &0xd2800020u32.to_le_bytes());
        put(&mut data, 0x1104, &0xd65f03c0u32.to_le_bytes());
        let ctx = plain(&data);
        let fdes = [(CODE, CODE + 4), (0x1100, 0x1108)];

        let shallow = bounded(&ctx, &fdes, &no_fragments(&[0x1100], 0));
        assert!(!watch(&shallow, 0x1100).reached);
        assert_eq!(shallow.calls.len(), 1);
        assert_eq!(shallow.calls[0].kind, CALL_DIRECT);
        assert_eq!(shallow.calls[0].target.text, "global(0x1100)");
        assert!(shallow.paths_cut.is_empty());

        let deep = bounded(&ctx, &fdes, &no_fragments(&[0x1100], 1));
        assert_eq!(value(&deep, 0x1100), "0x1");
        assert!(deep.calls.is_empty());
    }

    /// Index constant : ldrb lit l'entrée 2 dans une table en segment sans écriture.
    const CONSTANT_SWITCH: &[(u32, &str)] = &[
        (0x10000809, "1000  adr   x9, 0x1100"),
        (0x3940092a, "1004  ldrb  w10, [x9, #0x2]"),
        (0x100000cb, "1008  adr   x11, 0x1020"),
        (0x8b0a096b, "100c  add   x11, x11, x10, lsl #2"),
        (0xd61f0160, "1010  br    x11"),
    ];

    #[test]
    fn a_constant_index_read_from_a_read_only_table_gives_one_target() {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, CONSTANT_SWITCH);
        assemble_at(&mut data, 0x1020, SWITCH_CASES);
        put(&mut data, 0x1100, &[0, 2, 4, 0xff]);
        let mut ctx = plain(&data);
        function(&mut ctx, CODE, 0x38);
        let report = explore(&ctx, &options(&[0x1004, 0x1020, 0x1028, 0x1030], 2));

        let entry = only(&report, 0x1004);
        assert_eq!(text(&entry.value), "0x4");
        assert_eq!(entry.trace, ["0x1004"]);
        assert_eq!(report.paths_explored, 1);
        assert!(report.paths_cut.is_empty());
        assert_eq!(value(&report, 0x1030), "0x3");
        assert!(!watch(&report, 0x1020).reached);
        assert!(!watch(&report, 0x1028).reached);
    }

    /// Pointeur en 0x2008 (RELRO, emplacement relogé) puis en 0x3008 (données
    /// inscriptibles, hors RELRO).
    const POINTERS: &[(u32, &str)] = &[
        (0x10008048, "1000  adr   x8, 0x2008"),
        (0xf9400109, "1004  ldr   x9, [x8]"),
        (0x1001000a, "1008  adr   x10, 0x3008"),
        (0xf940014b, "100c  ldr   x11, [x10]"),
        (0xd65f03c0, "1010  ret"),
    ];

    #[test]
    fn a_relocated_relro_slot_folds_to_its_target_and_writable_data_does_not() {
        let mut data = vec![0u8; 0x4000];
        assemble_at(&mut data, CODE, POINTERS);
        let image = Image {
            segments: vec![
                segment(elf::PT_LOAD, elf::PF_R | elf::PF_X, 0, 0x2000),
                segment(elf::PT_LOAD, elf::PF_R | elf::PF_W, 0x2000, 0x2000),
                segment(elf::PT_GNU_RELRO, elf::PF_R, 0x2000, 0x100),
            ],
            ..image(&data)
        };
        let mut ctx = context(image, None, &[], &[]);
        ctx.slots.insert(0x2008, 0x1500);
        ctx.slots.insert(0x3008, 0x1600);
        let report = explore(&ctx, &options(&[0x1004, 0x100c], 2));

        assert_eq!(value(&report, 0x1004), "global(0x1500)");
        assert_eq!(value(&report, 0x100c), "load(8, global(0x3008))");
    }

    /// Fonction appelée qui finit par un br sur un pointeur lu en [x0].
    const CALLS_POINTER_TAIL: &[(u32, &str)] = &[
        (0xa9bf7bfd, "1000  stp   x29, x30, [sp, #-0x10]!"),
        (0x9400003f, "1004  bl    0x1100"),
        (0xa8c17bfd, "1008  ldp   x29, x30, [sp], #0x10"),
        (0xd65f03c0, "100c  ret"),
    ];

    const POINTER_TAIL: &[(u32, &str)] =
        &[(0xf9400010, "ldr   x16, [x0]"), (0xd61f0200, "br    x16")];

    #[test]
    fn an_unresolved_br_in_a_called_function_is_an_indirect_tail_call() {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, CALLS_POINTER_TAIL);
        assemble_at(&mut data, 0x1100, POINTER_TAIL);
        let mut ctx = plain(&data);
        function(&mut ctx, CODE, 0x10);
        function(&mut ctx, 0x1100, 0x8);
        let report = explore(&ctx, &options(&[0x1008], 2));

        assert!(watch(&report, 0x1008).reached);
        assert!(report.paths_cut.is_empty());
        assert!(report.indirect_branches.is_empty());
        assert_eq!(report.calls.len(), 1);
        assert_eq!(report.calls[0].kind, CALL_INDIRECT_TAIL);
        assert_eq!(report.calls[0].insn_addr, "0x1104");
        assert_eq!(report.calls[0].target.text, "load(8, init(x0))");
    }

    #[test]
    fn the_same_br_in_the_analyzed_function_stays_an_indirect_branch() {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, POINTER_TAIL);
        let ctx = plain(&data);
        let report = explore(&ctx, &options(&[], 2));

        assert_eq!(report.paths_cut.get(STATUS_INDIRECT_BRANCH), Some(&1));
        assert_eq!(report.indirect_branches.len(), 1);
        let branch = &report.indirect_branches[0];
        assert_eq!(branch.target.text, "load(8, init(x0))");
        assert!(report.calls.is_empty());
    }

    /// Appelant : bl, puis relit x19 et x0.
    const CALLER: &[(u32, &str)] = &[
        (0x94000040, "1000  bl    0x1100"),
        (0xaa1303e1, "1004  mov   x1, x19"),
        (0xaa0003e2, "1008  mov   x2, x0"),
        (0xd65f03c0, "100c  ret"),
    ];

    /// Appelé dont l'épilogue est externalisé en 0x1200.
    const CALLEE: &[(u32, &str)] = &[
        (0xd10083ff, "1100  sub   sp, sp, #0x20"),
        (0xd28000b3, "1104  mov   x19, #5"),
        (0x1400003e, "1108  b     0x1200"),
    ];

    const CALLEE_EPILOGUE: &[(u32, &str)] = &[
        (0x910043ff, "1200  add   sp, sp, #0x10"),
        (0xd65f03c0, "1204  ret"),
    ];

    fn caller_and_callee() -> Vec<u8> {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, CALLER);
        assemble_at(&mut data, 0x1100, CALLEE);
        assemble_at(&mut data, 0x1200, CALLEE_EPILOGUE);
        data
    }

    const CALLEE_RANGES: [(u64, u64); 3] = [(CODE, 0x1010), (0x1100, 0x110c), (0x1200, 0x1208)];

    #[test]
    fn a_callee_left_by_an_unfollowed_tail_call_keeps_sp_and_x19() {
        let data = caller_and_callee();
        let ctx = plain(&data);
        let report = bounded(&ctx, &CALLEE_RANGES, &no_fragments(&[0x1004, 0x1008], 1));

        let x19 = only(&report, 0x1004);
        assert_eq!(text(&x19.value), "init(x19)");
        assert_eq!(x19.sp.text, "init(sp)");
        let lost = "unknown(call_not_followed, 0x1108, x0)";
        assert_eq!(value(&report, 0x1008), lost);
        assert_eq!(report.calls[0].kind, CALL_DIRECT);
    }

    #[test]
    fn a_callee_whose_end_is_walked_is_not_restored() {
        let data = caller_and_callee();
        let ctx = plain(&data);
        let report = bounded(&ctx, &CALLEE_RANGES, &no_fragments(&[0x1004, 0x1008], 2));

        let x19 = only(&report, 0x1004);
        assert_eq!(text(&x19.value), "0x5");
        assert_eq!(x19.sp.text, "init(sp) - 0x10");
        assert_eq!(value(&report, 0x1008), "init(x0)");
        assert!(report.calls.is_empty());
    }

    #[test]
    fn an_outlined_chunk_may_change_x19_on_purpose() {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, CALLER);
        put(&mut data, 0x1100, &0xaa0003f3u32.to_le_bytes());
        put(&mut data, 0x1104, &0xd65f03c0u32.to_le_bytes());
        let ctx = plain(&data);
        let report = explore(&ctx, &options(&[0x1004], 2));

        assert_eq!(value(&report, 0x1004), "init(x0)");
    }

    #[test]
    fn a_loop_in_a_callee_abandons_the_callee_not_the_path() {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, CALLER);
        put(&mut data, 0x1100, &0xd10083ffu32.to_le_bytes());
        put(&mut data, 0x1104, &0x14000000u32.to_le_bytes());
        let ctx = plain(&data);
        let report = explore(&ctx, &options(&[0x1004, 0x1008], 2));

        assert!(report.paths_cut.is_empty());
        assert_eq!(report.callees_abandoned, 1);
        assert_eq!(report.calls.len(), 1);
        assert_eq!(report.calls[0].kind, CALL_ABANDONED);
        assert_eq!(report.calls[0].insn_addr, "0x1000");
        assert_eq!(report.calls[0].target.text, "global(0x1100)");
        let x19 = only(&report, 0x1004);
        assert_eq!(text(&x19.value), "init(x19)");
        assert_eq!(x19.sp.text, "init(sp)");
        let lost = "unknown(call_not_followed, 0x1000, x0)";
        assert_eq!(value(&report, 0x1008), lost);
    }

    /// Appelé de 0x100 octets dont l'appel interne vise 0x1200.
    const OUTER: &[(u32, &str)] = &[
        (0xd10083ff, "1100  sub   sp, sp, #0x20"),
        (0xd28000b3, "1104  mov   x19, #5"),
        (0x9400003e, "1108  bl    0x1200"),
        (0xd65f03c0, "110c  ret"),
    ];

    const FAR_INNER: &[(u32, &str)] = &[
        (0x910083ff, "1200  add   sp, sp, #0x20"),
        (0xd65f03c0, "1204  ret"),
    ];

    const NEAR_INNER: &[(u32, &str)] = &[
        (0x910043ff, "1200  add   sp, sp, #0x10"),
        (0xd65f03c0, "1204  ret"),
    ];

    const FAR_RANGES: [(u64, u64); 3] = [(CODE, 0x1100), (0x1100, 0x1200), (0x1200, 0x1300)];
    const NEAR_RANGES: [(u64, u64); 3] = [(CODE, 0x1100), (0x1100, 0x1200), (0x1200, 0x1208)];

    fn with_inner_call(inner: &[(u32, &str)]) -> Vec<u8> {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, CALLER);
        assemble_at(&mut data, 0x1100, OUTER);
        assemble_at(&mut data, 0x1200, inner);
        data
    }

    #[test]
    fn a_callee_with_an_inner_call_cut_by_depth_is_restored_after_its_ret() {
        let data = with_inner_call(FAR_INNER);
        let ctx = plain(&data);
        let report = bounded(&ctx, &FAR_RANGES, &options(&[0x1004], 1));

        let x19 = only(&report, 0x1004);
        assert_eq!(text(&x19.value), "init(x19)");
        assert_eq!(x19.sp.text, "init(sp)");
        assert_eq!(report.callees_incomplete, 1);
        assert_eq!(report.calls.len(), 1);
        assert_eq!(report.calls[0].kind, CALL_DIRECT);
        assert_eq!(report.calls[0].target.text, "global(0x1200)");
    }

    #[test]
    fn a_fragment_is_followed_beyond_the_depth() {
        let data = with_inner_call(NEAR_INNER);
        let ctx = plain(&data);
        let report = bounded(&ctx, &NEAR_RANGES, &options(&[0x1004], 1));

        let x19 = only(&report, 0x1004);
        assert_eq!(text(&x19.value), "0x5");
        assert_eq!(x19.sp.text, "init(sp) - 0x10");
        assert_eq!(report.callees_incomplete, 0);
        assert!(report.calls.is_empty());
    }

    #[test]
    fn without_fragments_the_same_call_counts_in_the_depth() {
        let data = with_inner_call(NEAR_INNER);
        let ctx = plain(&data);
        let report = bounded(&ctx, &NEAR_RANGES, &no_fragments(&[0x1004], 1));

        let x19 = only(&report, 0x1004);
        assert_eq!(text(&x19.value), "init(x19)");
        assert_eq!(x19.sp.text, "init(sp)");
        assert_eq!(report.callees_incomplete, 1);
        assert_eq!(report.calls[0].target.text, "global(0x1200)");
    }

    #[test]
    fn a_ninth_nested_fragment_is_an_ordinary_call() {
        let mut data = vec![0u8; 0x2000];
        put(&mut data, CODE, &0x94000040u32.to_le_bytes());
        put(&mut data, CODE + 4, &0xd65f03c0u32.to_le_bytes());
        let mut fdes = vec![(CODE, 0x1100)];
        for i in 0..9 {
            let at = 0x1100 + 0x10 * i;
            if i < 8 {
                put(&mut data, at, &0x94000004u32.to_le_bytes());
                put(&mut data, at + 4, &0xd65f03c0u32.to_le_bytes());
            } else {
                put(&mut data, at, &0xd65f03c0u32.to_le_bytes());
            }
            fdes.push((at, at + 8));
        }
        let ctx = plain(&data);
        let report = bounded(&ctx, &fdes, &options(&[0x1180], 0));

        assert!(!watch(&report, 0x1180).reached);
        assert_eq!(report.calls.len(), 1);
        assert_eq!(report.calls[0].kind, CALL_DIRECT);
        assert_eq!(report.calls[0].insn_addr, "0x1170");
        assert_eq!(report.calls[0].target.text, "global(0x1180)");
        assert!(report.paths_cut.is_empty());
    }

    #[test]
    fn a_fragment_entered_by_bl_may_change_x19() {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, CALLER);
        put(&mut data, 0x1100, &0xaa0003f3u32.to_le_bytes());
        put(&mut data, 0x1104, &0xd65f03c0u32.to_le_bytes());
        let ctx = plain(&data);
        let ranges = [(CODE, 0x1010), (0x1100, 0x1108)];
        let report = bounded(&ctx, &ranges, &options(&[0x1004], 0));

        assert_eq!(value(&report, 0x1004), "init(x0)");
        assert!(report.calls.is_empty());
        assert_eq!(report.callees_incomplete, 0);
    }

    fn callee_forks(watch: &[u64], forks: usize) -> SymexOptions {
        SymexOptions {
            callee_forks: forks,
            ..options(watch, 2)
        }
    }

    const CALLS_ONCE: &[(u32, &str)] = &[
        (0x94000040, "1000  bl    0x1100"),
        (0xd65f03c0, "1004  ret"),
    ];

    /// Trois branchements successifs, chacun vers la sortie.
    const THREE_EXITS: &[(u32, &str)] = &[
        (0xb4000060, "1100  cbz   x0, 0x110c"),
        (0xb4000041, "1104  cbz   x1, 0x110c"),
        (0xb4000022, "1108  cbz   x2, 0x110c"),
        (0xd65f03c0, "110c  ret"),
    ];

    fn three_exits() -> Vec<u8> {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, CALLS_ONCE);
        assemble_at(&mut data, 0x1100, THREE_EXITS);
        data
    }

    #[test]
    fn a_callee_opens_at_most_callee_forks_siblings() {
        let data = three_exits();
        let ctx = plain(&data);
        let report = explore(&ctx, &callee_forks(&[], 2));

        assert_eq!(report.paths_explored, 3);
        assert_eq!(report.forks_dropped, 1);
        assert_eq!(report.budgets.callee_forks, 2);
        assert!(report.paths_cut.is_empty());
    }

    #[test]
    fn with_no_callee_forks_a_callee_is_walked_once() {
        let data = three_exits();
        let ctx = plain(&data);
        let report = explore(&ctx, &callee_forks(&[], 0));

        assert_eq!(report.paths_explored, 1);
        assert_eq!(report.forks_dropped, 3);
    }

    #[test]
    fn the_quota_is_reset_between_two_calls() {
        let mut data = vec![0u8; 0x2000];
        put(&mut data, CODE, &0x94000040u32.to_le_bytes());
        put(&mut data, CODE + 4, &0x9400003fu32.to_le_bytes());
        put(&mut data, CODE + 8, &0xd65f03c0u32.to_le_bytes());
        put(&mut data, 0x1100, &0xb4000040u32.to_le_bytes());
        put(&mut data, 0x1104, &0xd2800021u32.to_le_bytes());
        put(&mut data, 0x1108, &0xd65f03c0u32.to_le_bytes());
        let ctx = plain(&data);
        let report = explore(&ctx, &callee_forks(&[], 1));

        assert_eq!(report.paths_explored, 4);
        assert_eq!(report.forks_dropped, 0);
    }

    const THREE_BRANCHES: &[(u32, &str)] = &[
        (0xb4000040, "1000  cbz   x0, 0x1008"),
        (0xd2800023, "1004  mov   x3, #1"),
        (0xb4000041, "1008  cbz   x1, 0x1010"),
        (0xd2800024, "100c  mov   x4, #1"),
        (0xb4000042, "1010  cbz   x2, 0x1018"),
        (0xd2800025, "1014  mov   x5, #1"),
        (0xd65f03c0, "1018  ret"),
    ];

    #[test]
    fn the_analyzed_function_is_never_capped() {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, THREE_BRANCHES);
        let ctx = plain(&data);
        let report = explore(&ctx, &callee_forks(&[], 0));

        assert_eq!(report.paths_explored, 8);
        assert_eq!(report.forks_dropped, 0);
    }

    /// Un frère dans la fonction analysée (cbz x0), puis un dans l'appelé (cbz x1).
    const ORDER: &[(u32, &str)] = &[
        (0xb4000040, "1000  cbz   x0, 0x1008"),
        (0xd2800029, "1004  mov   x9, #1"),
        (0x9400003e, "1008  bl    0x1100"),
        (0xaa0903e8, "100c  mov   x8, x9"),
        (0xd65f03c0, "1010  ret"),
    ];

    const ORDER_CALLEE: &[(u32, &str)] = &[
        (0xb4000041, "1100  cbz   x1, 0x1108"),
        (0xd2800049, "1104  mov   x9, #2"),
        (0xd65f03c0, "1108  ret"),
    ];

    #[test]
    fn a_sibling_of_the_analyzed_function_runs_before_a_callee_sibling() {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, ORDER);
        assemble_at(&mut data, 0x1100, ORDER_CALLEE);
        let ctx = plain(&data);
        let report = explore(&ctx, &options(&[0x100c], 2));

        let w = watch(&report, 0x100c);
        let seen: Vec<&str> = w.results.iter().map(|r| text(&r.value)).collect();
        // Sans file à deux niveaux : 0x2, 0x1 (frère de l'appelé), init(x9).
        assert_eq!(seen, ["0x2", "init(x9)", "0x1"]);
        assert_eq!(report.paths_explored, 4);
    }

    const MASK: &[(u32, &str)] = &[
        (0xb9400408, "1000  ldr   w8, [x0, #0x4]"),
        (0x12000108, "1004  and   w8, w8, #0x1"),
        (0x39000028, "1008  strb  w8, [x1]"),
        (0xd65f03c0, "100c  ret"),
    ];

    #[test]
    fn an_and_with_one_keeps_the_mask_on_the_loaded_word() {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, MASK);
        let ctx = plain(&data);
        let report = explore(&ctx, &options(&[0x1004, 0x1008], 2));

        let masked = "and(load(4, init(x0) + 0x4), 0x1)";
        assert_eq!(value(&report, 0x1004), masked);
        let stored = only(&report, 0x1008);
        assert_eq!(stored.kind, KIND_STORE);
        assert_eq!(text(&stored.value), masked);
        assert_eq!(stored.trace, ["0x1000", "0x1004", "0x1008"]);
    }

    /// bl non suivi (profondeur 0) entre un rangement sur la pile et sa
    /// relecture.
    const CALL_CLOBBERS: &[(u32, &str)] = &[
        (0xd10083ff, "1000  sub   sp, sp, #0x20"),
        (0xf90007e0, "1004  str   x0, [sp, #0x8]"),
        (0xaa0103f3, "1008  mov   x19, x1"),
        (0x9400003d, "100c  bl    0x1100"),
        (0xf94007e9, "1010  ldr   x9, [sp, #0x8]"),
        (0xf9000269, "1014  str   x9, [x19]"),
        (0xf9000662, "1018  str   x2, [x19, #0x8]"),
        (0x910083ff, "101c  add   sp, sp, #0x20"),
        (0xd65f03c0, "1020  ret"),
    ];

    #[test]
    fn a_call_not_followed_clobbers_x0_to_x18_but_not_the_stack() {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, CALL_CLOBBERS);
        put(&mut data, 0x1100, &0xd65f03c0u32.to_le_bytes());
        let ctx = plain(&data);
        let report = explore(&ctx, &options(&[0x100c, 0x1014, 0x1018], 0));

        let call = only(&report, 0x100c);
        assert_eq!(call.kind, KIND_CALL);
        assert_eq!(text(&call.target), "global(0x1100)");
        assert_eq!(call.args[1].text, "init(x1)");

        let kept = only(&report, 0x1014);
        assert_eq!(text(&kept.address), "init(x1)");
        assert_eq!(text(&kept.value), "init(x0)");
        assert_eq!(kept.trace, ["0x1004", "0x1010", "0x1014"]);

        let lost = only(&report, 0x1018);
        let clobbered = "unknown(call_not_followed, 0x100c, x2)";
        assert_eq!(text(&lost.address), "init(x1) + 0x8");
        assert_eq!(text(&lost.value), clobbered);

        assert_eq!(report.calls.len(), 1);
        assert_eq!(report.calls[0].kind, CALL_DIRECT);
        assert_eq!(report.calls[0].target.text, "global(0x1100)");
    }

    #[test]
    fn a_loop_is_cut_on_the_third_visit_and_a_bare_br_ends_its_path() {
        let mut looping = vec![0u8; 0x2000];
        put(&mut looping, CODE, &0x14000000u32.to_le_bytes());
        let ctx = plain(&looping);
        let report = explore(&ctx, &options(&[CODE], 2));
        assert_eq!(report.paths_cut.get(STATUS_CUT_LOOP), Some(&1));
        assert_eq!(report.callees_abandoned, 0);
        assert!(report.calls.is_empty());
        assert_eq!(only(&report, CODE).paths, 1);

        let mut bare = vec![0u8; 0x2000];
        put(&mut bare, CODE, &0xd61f0000u32.to_le_bytes());
        let ctx = plain(&bare);
        let report = explore(&ctx, &options(&[0x2000], 2));
        assert_eq!(report.paths_cut.get(STATUS_INDIRECT_BRANCH), Some(&1));
        assert_eq!(report.indirect_branches[0].target.text, "init(x0)");
        assert!(!watch(&report, 0x2000).reached);
    }

    /// Seul le repli sur 0x1004 mène au watch.
    const ONE_WAY: &[(u32, &str)] = &[
        (0xb4000060, "1000  cbz   x0, 0x100c"),
        (0xf9000041, "1004  str   x1, [x2]"),
        (0xd65f03c0, "1008  ret"),
        (0xd2800023, "100c  mov   x3, #1"),
        (0xd65f03c0, "1010  ret"),
    ];

    fn one_way() -> Vec<u8> {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, ONE_WAY);
        data
    }

    #[test]
    fn a_branch_with_no_path_to_a_watch_is_off_target() {
        let data = one_way();
        let mut ctx = plain(&data);
        function(&mut ctx, CODE, 0x14);
        let report = analyzed(&ctx, &options(&[0x1004], 0));

        assert!(report.directed);
        assert_eq!(report.paths_explored, 2);
        assert_eq!(report.paths_cut.get(STATUS_OFF_TARGET), Some(&1));
        assert_eq!(value(&report, 0x1004), "init(x1)");
    }

    #[test]
    fn undirected_the_same_branch_runs_to_its_ret() {
        let data = one_way();
        let mut ctx = plain(&data);
        function(&mut ctx, CODE, 0x14);
        let undirected = SymexOptions {
            directed: false,
            ..options(&[0x1004], 0)
        };
        let report = analyzed(&ctx, &undirected);

        assert!(!report.directed);
        assert_eq!(report.paths_explored, 2);
        assert!(report.paths_cut.is_empty());
    }

    #[test]
    fn a_watch_outside_the_function_turns_direction_off() {
        let data = one_way();
        let mut ctx = plain(&data);
        function(&mut ctx, CODE, 0x14);
        let report = analyzed(&ctx, &options(&[0x1004, 0x1100], 0));

        assert!(!report.directed);
        assert!(report.paths_cut.is_empty());
    }

    /// Frère A en 0x1014 à un bloc du watch, frère B en 0x1020 à deux ; B est
    /// ouvert après A.
    const NEAREST: &[(u32, &str)] = &[
        (0xb40000a0, "1000  cbz   x0, 0x1014"),
        (0xb40000e1, "1004  cbz   x1, 0x1020"),
        (0xd2800029, "1008  mov   x9, #1"),
        (0x14000003, "100c  b     0x1018"),
        (0xd65f03c0, "1010  ret"),
        (0xd2800049, "1014  mov   x9, #2"),
        (0xf9000049, "1018  str   x9, [x2]"),
        (0xd65f03c0, "101c  ret"),
        (0xd2800069, "1020  mov   x9, #3"),
        (0x14000002, "1024  b     0x102c"),
        (0xd65f03c0, "1028  ret"),
        (0x17fffffb, "102c  b     0x1018"),
    ];

    #[test]
    fn the_pending_path_nearest_to_a_watch_runs_first() {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, NEAREST);
        let mut ctx = plain(&data);
        function(&mut ctx, CODE, 0x30);
        let seen = |directed: bool| {
            let tuned = SymexOptions {
                directed,
                ..options(&[0x1018], 0)
            };
            let report = analyzed(&ctx, &tuned);
            let w = watch(&report, 0x1018);
            let values = w.results.iter().map(|r| text(&r.value).to_string());
            values.collect::<Vec<_>>()
        };

        assert_eq!(seen(true), ["0x1", "0x2", "0x3"]);
        assert_eq!(seen(false), ["0x1", "0x3", "0x2"]);
    }

    #[test]
    fn a_conditional_select_merges_into_one_path() {
        let mut data = vec![0u8; 0x2000];
        let code = [
            (0xf100001f, "1000  cmp   x0, #0"),
            (0x9a820020, "1004  csel  x0, x1, x2, eq"),
            (0xf9000060, "1008  str   x0, [x3]"),
            (0xd65f03c0, "100c  ret"),
        ];
        assemble_at(&mut data, CODE, &code);
        let ctx = plain(&data);
        let report = explore(&ctx, &options(&[0x1008], 0));

        assert_eq!(report.paths_explored, 1);
        let stored = only(&report, 0x1008);
        assert_eq!(text(&stored.value), "ite(eq@0x1004, init(x1), init(x2))");
        let json = &stored.value.as_ref().unwrap().expr;
        assert_eq!(json["ite"]["cond"], "eq@0x1004");
        assert_eq!(json["ite"]["else"]["init"], "x2");
    }

    #[test]
    fn a_select_of_one_value_is_that_value() {
        let mut data = vec![0u8; 0x2000];
        let code = [
            (0xf100001f, "1000  cmp   x0, #0"),
            (0x9a810020, "1004  csel  x0, x1, x1, eq"),
            (0xf9000060, "1008  str   x0, [x3]"),
            (0xd65f03c0, "100c  ret"),
        ];
        assemble_at(&mut data, CODE, &code);
        let ctx = plain(&data);
        let report = explore(&ctx, &options(&[0x1008], 0));

        assert_eq!(value(&report, 0x1008), "init(x1)");
    }

    #[test]
    fn a_select_keeps_the_traces_of_both_values() {
        let mut data = vec![0u8; 0x2000];
        let code = [
            (0xf94000a1, "1000  ldr   x1, [x5]"),
            (0xf94000c2, "1004  ldr   x2, [x6]"),
            (0xf100001f, "1008  cmp   x0, #0"),
            (0x9a820020, "100c  csel  x0, x1, x2, eq"),
            (0xf9000060, "1010  str   x0, [x3]"),
            (0xd65f03c0, "1014  ret"),
        ];
        assemble_at(&mut data, CODE, &code);
        let ctx = plain(&data);
        let report = explore(&ctx, &options(&[0x1010], 0));

        let stored = only(&report, 0x1010);
        assert_eq!(stored.trace, ["0x1000", "0x1004", "0x100c", "0x1010"]);
    }

    /// x8 = sp - 0x20 passé à l'appelé, qui range en [x8, #0x10] l'octet
    /// [x0, #0x5] ; l'appelant relit [sp, #0x30], soit init(sp) - 0x10.
    const OUT_PARAM: &[(u32, &str)] = &[
        (0xd10103ff, "1000  sub   sp, sp, #0x40"),
        (0x910083e8, "1004  add   x8, sp, #0x20"),
        (0x9400003e, "1008  bl    0x1100"),
        (0x3940c3e9, "100c  ldrb  w9, [sp, #0x30]"),
        (0x910103ff, "1010  add   sp, sp, #0x40"),
        (0xd65f03c0, "1014  ret"),
    ];

    const OUT_PARAM_CALLEE: &[(u32, &str)] = &[
        (0x39401409, "1100  ldrb  w9, [x0, #0x5]"),
        (0x39004109, "1104  strb  w9, [x8, #0x10]"),
        (0xd65f03c0, "1108  ret"),
    ];

    fn out_param<'d>(data: &'d mut [u8], caller: &[(u32, &str)]) -> Ctx<'d> {
        assemble_at(data, CODE, caller);
        assemble_at(data, 0x1100, OUT_PARAM_CALLEE);
        let mut ctx = plain(data);
        function(&mut ctx, CODE, 0x18);
        function(&mut ctx, 0x1100, 0x100);
        ctx
    }

    #[test]
    fn refinement_follows_the_call_that_writes_the_read_address() {
        let mut data = vec![0u8; 0x2000];
        let ctx = out_param(&mut data, OUT_PARAM);
        let report = analyzed(&ctx, &options(&[0x100c], 0));

        assert_eq!(report.rounds.len(), 2);
        assert!(report.rounds[0].follow.is_empty());
        assert_eq!(report.rounds[1].follow, ["0x1008"]);
        assert_eq!(report.rounds[1].paths, 1);
        assert_eq!(value(&report, 0x100c), "load(1, init(x0) + 0x5)");
        assert!(report.calls.is_empty());
    }

    #[test]
    fn without_refinement_the_read_stays_never_written() {
        let mut data = vec![0u8; 0x2000];
        let ctx = out_param(&mut data, OUT_PARAM);
        let once = SymexOptions {
            refine: 0,
            ..options(&[0x100c], 0)
        };
        let report = analyzed(&ctx, &once);

        assert_eq!(report.rounds.len(), 1);
        assert_eq!(value(&report, 0x100c), "load(1, init(sp) - 0x10)");
        let call = &report.calls[0];
        assert_eq!(call.kind, CALL_DIRECT);
        assert_eq!(call.args.len(), 9);
        assert_eq!(call.args[8], "init(sp) - 0x20");
    }

    #[test]
    fn a_call_unrelated_to_the_read_address_is_not_followed() {
        let mut caller = OUT_PARAM.to_vec();
        caller[1] = (0xd503201f, "1004  nop");
        let mut data = vec![0u8; 0x2000];
        let ctx = out_param(&mut data, &caller);
        let report = analyzed(&ctx, &options(&[0x100c], 0));

        assert_eq!(report.rounds.len(), 1);
        assert_eq!(value(&report, 0x100c), "load(1, init(sp) - 0x10)");
        assert_eq!(report.calls[0].args[8], "init(x8)");
    }

    #[test]
    fn a_call_given_by_hand_is_followed_from_the_first_round() {
        let mut data = vec![0u8; 0x2000];
        let ctx = out_param(&mut data, OUT_PARAM);
        let by_hand = SymexOptions {
            follow: vec![0x1008],
            ..options(&[0x100c], 0)
        };
        let report = analyzed(&ctx, &by_hand);

        assert_eq!(report.rounds.len(), 1);
        assert_eq!(report.rounds[0].follow, ["0x1008"]);
        assert_eq!(value(&report, 0x100c), "load(1, init(x0) + 0x5)");
    }

    #[test]
    fn a_followed_callee_keeps_its_fork_quota() {
        let data = three_exits();
        let ctx = plain(&data);
        let followed = SymexOptions {
            follow: vec![CODE],
            ..options(&[], 0)
        };
        let report = analyzed(&ctx, &followed);

        assert_eq!(report.paths_explored, 3);
        assert_eq!(report.forks_dropped, 1);
    }

    #[test]
    fn expressions_fold_to_base_plus_offset() {
        let sp = Expr::init(SP);
        let frame = add(&sp, &konst((-0x20i64) as u64));
        assert_eq!(frame.to_string(), "init(sp) - 0x20");
        let slot = add(&frame, &konst(8));
        assert_eq!(sub(&slot, &sp).as_const(), Some((-0x18i64) as u64));
        assert_eq!(split(&slot), (sp.clone(), -0x18));

        let (x0, x1) = (Expr::init(0), Expr::init(1));
        assert_eq!(add(&x1, &x0), add(&x0, &x1));
        let (low, high) = (Expr::global(0x1000), Expr::global(0x1010));
        assert_eq!(add(&low, &konst(0x10)), high);
        assert_eq!(high.to_string(), "global(0x1010)");
        assert_eq!(sub(&high, &low).as_const(), Some(0x10));
        assert_eq!(split(&konst(0x5000)), split(&Expr::global(0x5000)));

        let byte = load(1, &x0);
        assert_eq!(zext(32, &byte), byte);
        let masked = and(&zext(32, &x0), &konst(0xff));
        assert_eq!(masked.to_string(), "zext8(init(x0))");
        assert_eq!(trunc(8, &zext(32, &byte)), byte);
        let json = serde_json::to_value(add(&byte, &konst(1))).unwrap();
        assert_eq!(json["add"][1]["const"], "0x1");
        assert_eq!(json["add"][0]["load"]["size"], 1);
    }

    fn peeking(watch: u64, items: &[&str]) -> SymexOptions {
        let peek = items
            .iter()
            .map(|item| parse_symex_peek(item, &[watch]).unwrap());
        SymexOptions {
            peek: peek.collect(),
            ..options(&[watch], 0)
        }
    }

    const PEEKED: [(u32, &str); 3] = [
        (0xf9008801, "1000  str   x1, [x0, #0x110]"),
        (0x39444002, "1004  ldrb  w2, [x0, #0x111]"),
        (0xd65f03c0, "1008  ret"),
    ];

    #[test]
    fn a_peek_reads_each_byte_as_an_ldrb_would() {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, &PEEKED);
        let ctx = plain(&data);
        let report = explore(&ctx, &peeking(0x1004, &["1004:x0+0x10f:3"]));

        assert_eq!(report.paths_explored, 1);
        let read = only(&report, 0x1004);
        let peek = &read.peeks[0];
        assert_eq!(
            (peek.reg.as_str(), peek.offset.as_str(), peek.len),
            ("x0", "0x10f", 3)
        );
        assert_eq!(peek.address.text, "init(x0) + 0x10f");
        let bytes: Vec<&str> = peek.bytes.iter().map(|b| b.text.as_str()).collect();
        assert_eq!(bytes[0], "load(1, init(x0) + 0x10f)");
        assert!(bytes[1].contains("init(x1)"), "{bytes:?}");
        assert_eq!(bytes[2], text(&read.value));
        let json = serde_json::to_value(read).unwrap();
        assert_eq!(json["peeks"][0]["bytes"].as_array().map(Vec::len), Some(3));
    }

    #[test]
    fn a_peek_sees_memory_before_the_watched_store() {
        let mut data = vec![0u8; 0x2000];
        assemble_at(&mut data, CODE, &PEEKED);
        let ctx = plain(&data);
        let report = explore(&ctx, &peeking(0x1000, &["1000:x0+0x110:1"]));

        let stored = only(&report, 0x1000);
        assert_eq!(text(&stored.value), "init(x1)");
        assert_eq!(stored.peeks[0].bytes[0].text, "load(1, init(x0) + 0x110)");
    }

    #[test]
    fn paths_whose_peeks_differ_stay_distinct() {
        let mut data = vec![0u8; 0x2000];
        let code = [
            (0xb4000043, "1000  cbz   x3, 0x1008"),
            (0x39000001, "1004  strb  w1, [x0]"),
            (0xd503201f, "1008  nop"),
            (0xd65f03c0, "100c  ret"),
        ];
        assemble_at(&mut data, CODE, &code);
        let ctx = plain(&data);

        let merged = explore(&ctx, &options(&[0x1008], 0));
        assert_eq!(only(&merged, 0x1008).paths, 2);
        assert!(only(&merged, 0x1008).peeks.is_empty());
        let apart = explore(&ctx, &peeking(0x1008, &["1008:x0+0:1"]));
        assert_eq!(apart.paths_explored, 2);
        assert_eq!(watch(&apart, 0x1008).results.len(), 2);
    }

    #[test]
    fn peek_items_are_parsed_or_refused_with_the_item() {
        let watches = [0x36ffbd0];
        let peek = parse_symex_peek("36ffbd0:x0+0x110:3", &watches).unwrap();
        assert_eq!(
            (peek.watch, peek.reg, peek.offset, peek.len),
            (0x36ffbd0, 0, 0x110, 3)
        );
        let below = parse_symex_peek("36ffbd0:sp-16:64", &watches).unwrap();
        assert_eq!((below.reg, below.offset, below.len), (SP, -16, 64));
        let signed = parse_symex_peek("36ffbd0:x29+-0x8:1", &watches).unwrap();
        assert_eq!((signed.reg, signed.offset), (29, -8));
        let refused = [
            "1000:x0+0x110:3",
            "36ffbd0:x31+0:1",
            "36ffbd0:x0+0:0",
            "36ffbd0:x0+0:65",
            "36ffbd0:x0:3",
            "36ffbd0:x0+1",
            "36ffbd0:x0+0xzz:1",
        ];
        for item in refused {
            let why = parse_symex_peek(item, &watches).unwrap_err();
            assert!(why.contains(item), "{why}");
        }
    }

    #[test]
    fn legend_defines_every_symex_label() {
        let legend = super::super::legend();
        for label in labels() {
            assert!(legend.contains(label), "{label}");
        }
        assert!(legend.contains("SUPPOSÉES NE PAS SE RECOUVRIR"));
        assert!(legend.contains(&format!("{MAX_COPY} octets")));
        assert!(legend.contains(&format!("{MAX_EXPR_NODES} nœuds")));
    }
}
