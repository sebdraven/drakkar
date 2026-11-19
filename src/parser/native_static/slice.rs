//! `--native --native-slice` : d'où vient une valeur. Depuis un registre ou
//! une zone mémoire lus juste avant une instruction, remontée du graphe de flot
//! d'une fonction AArch64 sur tous les chemins à la fois, jusqu'à un point
//! fixe. Rien n'est exécuté. Étiquettes définies dans [`super::legend`].

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::panic::AssertUnwindSafe;
use std::rc::Rc;

use object::elf;
use serde::Serialize;

use super::decode::{decode, Arch, Flow, Via};
use super::disasm::{context, plt_import, Ctx};
use super::native_strings::fde_ranges;
use super::symex::{
    copy_import, effect, parse_peek_place, reg_name, Bound, ByteFrom, Effect, EffectBase,
    FlowGraph, DEFAULT_SYMEX_FRAGMENT_MAX, PRESERVED,
};
use super::{hex, parse_elf, parse_symex_address, ElfReport};

pub const DEFAULT_SLICE_DEPTH: u8 = 1;
pub const MAX_SLICE_DEPTH: u8 = 4;
pub const DEFAULT_SLICE_MAX_STEPS: usize = 200_000;
pub const DEFAULT_SLICE_MAX_SOURCES: usize = 200;
pub const MAX_SLICE_QUERIES: usize = 16;
pub const MAX_SLICE_LEN: u8 = 64;
const MAX_CHAIN: usize = 64;
const MAX_NESTED: usize = 12;
const MAX_EXPRESSION: usize = 3;
const MAX_ALIAS_CHAIN: usize = 4;
const MAX_ALIAS_PATH: usize = 2;
const ARGS: u8 = 9;
const LR: u8 = 30;
const SP: u8 = 31;
const V0: u8 = 32;
const EXIT: usize = usize::MAX;

const KIND_ARG: &str = "arg";
const KIND_INIT_MEM: &str = "init_mem";
const KIND_CONST: &str = "const";
const KIND_GLOBAL: &str = "global";
const KIND_CALL: &str = "call";
const KIND_INDIRECT_CALL: &str = "indirect_call";
const KIND_UNKNOWN: &str = "unknown";

const REASON_INDIRECT_BRANCH: &str = "indirect_branch";
const REASON_NO_PREDECESSOR: &str = "no_predecessor";
const REASON_COMPUTED_ADDRESS: &str = "computed_address";
const REASON_UNMODELED: &str = "unmodeled";
const REASON_ALIAS_DEPTH: &str = "alias_depth";

/// Emplacement d'une requête : registre, ou `len` octets à registre +
/// `offset`, le registre lu juste avant l'instruction de la requête.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceLocation {
    Reg(u8),
    Mem { reg: u8, offset: i64, len: u8 },
}

impl fmt::Display for SliceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            SliceLocation::Reg(reg) => f.write_str(&reg_name(reg)),
            SliceLocation::Mem { reg, offset, len } => {
                write!(f, "{}{}:{len}", reg_name(reg), offset_text(offset))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SliceQuery {
    pub at: u64,
    pub location: SliceLocation,
}

impl fmt::Display for SliceQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", hex(self.at), self.location)
    }
}

/// Réglages de `--native-slice`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceOptions {
    pub queries: Vec<SliceQuery>,
    pub depth: u8,
    /// Adresses d'appel suivies quelle que soit la profondeur.
    pub follow: Vec<u64>,
    pub max_steps: usize,
    pub max_sources: usize,
}

impl Default for SliceOptions {
    fn default() -> Self {
        SliceOptions {
            queries: Vec::new(),
            depth: DEFAULT_SLICE_DEPTH,
            follow: Vec::new(),
            max_steps: DEFAULT_SLICE_MAX_STEPS,
            max_sources: DEFAULT_SLICE_MAX_SOURCES,
        }
    }
}

/// `<adresse>:<emplacement>`, de 1 à 16 ; doublons retirés.
pub fn parse_slice_at(items: &[String]) -> Result<Vec<SliceQuery>, String> {
    let mut found = Vec::new();
    for item in items {
        let cite = |why: String| format!("élément {item:?} : {why}");
        let query = parse_query(item).map_err(cite)?;
        if !found.contains(&query) {
            found.push(query);
        }
    }
    if found.is_empty() || found.len() > MAX_SLICE_QUERIES {
        let count = found.len();
        return Err(format!("{count} requêtes : de 1 à {MAX_SLICE_QUERIES}"));
    }
    Ok(found)
}

fn parse_query(item: &str) -> Result<SliceQuery, String> {
    let shape = "attendu <adresse>:<registre> ou <adresse>:<registre>+<décalage>:<longueur>";
    let Some((at, place)) = item.trim().split_once(':') else {
        return Err(shape.into());
    };
    let at = parse_symex_address(at)?;
    let location = match place.split_once(':') {
        None => SliceLocation::Reg(parse_register(place)?),
        Some((base, len)) => {
            let (reg, offset) = parse_peek_place(base)?;
            let invalid = || format!("longueur {len:?} : de 1 à {MAX_SLICE_LEN} octets");
            let len = len.trim().parse::<u8>().map_err(|_| invalid())?;
            if !(1..=MAX_SLICE_LEN).contains(&len) {
                return Err(invalid());
            }
            SliceLocation::Mem { reg, offset, len }
        }
    };
    Ok(SliceQuery { at, location })
}

fn parse_register(text: &str) -> Result<u8, String> {
    match text.trim() {
        "sp" => Ok(SP),
        name => match name.strip_prefix('x').and_then(|n| n.parse::<u8>().ok()) {
            Some(n) if n <= 30 => Ok(n),
            _ => Err(format!("registre {name:?} : x0..x30 ou sp")),
        },
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SliceReport {
    pub elf: String,
    pub fn_start: String,
    pub fn_end: Option<String>,
    pub bound: &'static str,
    pub queries: Vec<SliceQueryReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SliceQueryReport {
    pub at: String,
    pub location: String,
    pub complete: bool,
    pub steps: usize,
    pub sources_total: usize,
    pub sources_truncated: bool,
    pub sources: Vec<SliceSource>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SliceSource {
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub insn_addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    pub bytes: [u8; 2],
    pub chain: Vec<SliceStep>,
    pub chain_truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SliceStep {
    pub insn_addr: String,
    pub mnemonic: String,
    pub operands: String,
}

/// Valeur d'un registre x ou sp avant une instruction : base + décalage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Origin {
    /// Registre à l'entrée de la fonction.
    Entry(u8),
    Absolute,
    /// Registre écrit par l'instruction.
    Def(u64, u8),
    /// Registre à la jonction qui commence à l'instruction.
    Merge(u64, u8),
}

type Value = (Origin, i64);
type Values = [Value; 32];

/// Emplacement recherché juste avant un point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Loc {
    /// Octets `lo..lo + len` d'un registre : x0..x30, sp, q0..q31 (32..63).
    Reg {
        reg: u8,
        lo: u8,
        len: u8,
    },
    Mem {
        origin: Origin,
        off: i64,
        len: u8,
    },
}

impl Loc {
    fn len(self) -> u8 {
        match self {
            Loc::Reg { len, .. } | Loc::Mem { len, .. } => len,
        }
    }
}

/// `loc` couvre les octets `q..q + len` de la requête.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Fact {
    loc: Loc,
    q: u8,
}

impl Fact {
    fn bytes(self) -> [u8; 2] {
        [self.q, self.q.saturating_add(self.loc.len())]
    }
}

/// Fonction bornée : graphe de flot par instruction, effet de chaque
/// instruction, valeur de x0..x30 et sp avant chacune, valeurs possibles de
/// chaque relecture de pile.
struct Func {
    bound: Bound,
    graph: FlowGraph,
    effects: Vec<Option<Effect>>,
    preds: Vec<Vec<usize>>,
    /// ret, et b ou b.cond hors de la fonction.
    exits: Vec<usize>,
    /// br dont les cibles sont inconnues.
    open: Vec<usize>,
    values: Vec<Values>,
    reloads: Reloads,
}

/// Registres écrits par un bl, par cible.
type Writes = HashMap<u64, Vec<u8>>;

/// (relecture, registre) : valeurs possibles, chacune avec les relectures
/// supposées pour l'obtenir, triées.
type Reloads = HashMap<(u64, u8), Vec<(Value, Vec<u64>)>>;

impl Func {
    fn build(ctx: &Ctx, fdes: &[(u64, u64)], writes: &mut Writes, bound: Bound) -> Option<Func> {
        let graph = FlowGraph::build(ctx, &bound)?;
        let end = bound.end?;
        let count = graph.insns.len();
        let inside =
            |to: u64| (bound.start..end).contains(&to) && (to - bound.start).is_multiple_of(4);
        let mut succs: Vec<Vec<usize>> = vec![Vec::new(); count];
        let mut exits = Vec::new();
        let mut open = Vec::new();
        let mut effects = Vec::with_capacity(count);
        for (i, (at, decoded)) in graph.insns.iter().enumerate() {
            let next = (i + 1 < count).then_some(i + 1);
            match decoded.as_ref().map(|(_, insn)| insn.flow) {
                Some(Flow::Next | Flow::Call(..) | Flow::CallVia(_)) => succs[i].extend(next),
                Some(Flow::Jump(to, _)) if inside(to) => succs[i].push(graph.index(to)),
                Some(Flow::Jump(..)) => exits.push(i),
                Some(Flow::Branch(to, _)) => {
                    if inside(to) {
                        succs[i].push(graph.index(to));
                    } else {
                        exits.push(i);
                    }
                    succs[i].extend(next);
                }
                Some(Flow::JumpVia(_)) => match graph.tables.get(at) {
                    Some(targets) => {
                        let known = targets.iter().filter(|&&to| inside(to));
                        succs[i].extend(known.map(|&to| graph.index(to)));
                    }
                    None => open.push(i),
                },
                Some(Flow::Return) => exits.push(i),
                _ => {}
            }
            let made = decoded.as_ref();
            effects.push(made.map(|(inst, insn)| effect(ctx, inst, &insn.mnemonic, *at)));
        }
        let mut preds = vec![Vec::new(); count];
        for (i, list) in succs.iter().enumerate() {
            for &j in list {
                if !preds[j].contains(&i) {
                    preds[j].push(i);
                }
            }
        }
        let values = forward(ctx, fdes, writes, &graph, &effects, &succs);
        let reloads = reloads(ctx, &graph, &effects, &values, &succs);
        Some(Func {
            bound,
            graph,
            effects,
            preds,
            exits,
            open,
            values,
            reloads,
        })
    }

    fn address(&self, index: usize) -> u64 {
        self.graph.insns[index].0
    }

    /// Valeurs que peut avoir `value` quand sa base est une relecture de
    /// pile : valeur, relecture, relectures supposées.
    fn may_be(&self, value: Value) -> Vec<(Value, u64, Vec<u64>)> {
        let (Origin::Def(at, reg), k) = value else {
            return Vec::new();
        };
        let Some(found) = self.reloads.get(&(at, reg)) else {
            return Vec::new();
        };
        found
            .iter()
            .map(|((origin, j), aliases)| ((*origin, j.wrapping_add(k)), at, aliases.clone()))
            .collect()
    }
}

/// Pour chaque relecture de 8 octets d'un emplacement de pile, la valeur
/// d'avant chaque rangement de 8 octets d'un registre au même emplacement qui
/// l'atteint ([`reaching`]), avec les relectures supposées. Un candidat
/// lui-même relu est remplacé par les siens, sur MAX_ALIAS_CHAIN niveaux ; un
/// candidat absolu hors des segments LOAD est écarté.
fn reloads(
    ctx: &Ctx,
    graph: &FlowGraph,
    effects: &[Option<Effect>],
    values: &[Values],
    succs: &[Vec<usize>],
) -> Reloads {
    let direct = reaching(graph, effects, values, succs);
    let in_image = |at: i64| {
        let mut loads = ctx.image.segments.iter().filter(|s| s.p_type == elf::PT_LOAD);
        loads.any(|s| s.in_memory(at as u64))
    };
    let mut table = Reloads::new();
    for (&(at, reg), found) in &direct {
        let mut frontier: BTreeSet<(Value, Vec<u64>)> =
            found.iter().map(|&value| (value, vec![at])).collect();
        let mut done = BTreeSet::new();
        for _ in 0..MAX_ALIAS_CHAIN {
            let mut next = BTreeSet::new();
            for ((origin, k), aliases) in frontier {
                let deeper = match origin {
                    Origin::Def(l, r) => direct.get(&(l, r)).map(|found| (l, found)),
                    _ => None,
                };
                let Some((l, found)) = deeper else {
                    done.insert(((origin, k), aliases));
                    continue;
                };
                for &(o, j) in found.iter() {
                    let mut more = aliases.clone();
                    more.push(l);
                    more.sort_unstable();
                    more.dedup();
                    next.insert(((o, j.wrapping_add(k)), more));
                }
            }
            frontier = next;
        }
        done.extend(frontier);
        let kept: Vec<_> = done
            .into_iter()
            .filter(|&((origin, k), _)| origin != Origin::Absolute || in_image(k))
            .collect();
        if !kept.is_empty() {
            table.insert((at, reg), kept);
        }
    }
    table
}

/// Rangements de 8 octets qui atteignent chaque relecture du même
/// emplacement : (relecture, registre) → valeurs rangées. Une écriture de la
/// fonction qui recouvre un octet de l'emplacement tue ses rangements ; un
/// appel ou une écriture par une autre base ne tue rien. Jonction = union ; le
/// code non atteint depuis l'entrée part d'un ensemble vide.
fn reaching(
    graph: &FlowGraph,
    effects: &[Option<Effect>],
    values: &[Values],
    succs: &[Vec<usize>],
) -> HashMap<(u64, u8), BTreeSet<Value>> {
    let count = effects.len();
    let mut spilled: Vec<Vec<(i64, u8)>> = vec![Vec::new(); count];
    let mut written: Vec<Vec<(i64, i64)>> = vec![Vec::new(); count];
    let mut read = Vec::new();
    for (i, effect) in effects.iter().enumerate() {
        let called = matches!(
            graph.insns[i].1.as_ref().map(|(_, insn)| insn.flow),
            Some(Flow::Call(..) | Flow::CallVia(_))
        );
        let Some(effect) = effect.as_ref().filter(|_| !called) else {
            continue;
        };
        spilled[i] = spills(effect, &values[i]);
        written[i] = stack_writes(effect, &values[i]);
        for (reg, slot) in stack_reads(effect, &values[i]) {
            read.push((i, reg, slot));
        }
    }
    let slots: BTreeSet<i64> = read.iter().map(|&(_, _, slot)| slot).collect();
    let mut defs: Vec<(i64, Value)> = Vec::new();
    let mut made: Vec<Vec<usize>> = vec![Vec::new(); count];
    for (i, found) in spilled.iter().enumerate() {
        for &(slot, reg) in found.iter().filter(|(slot, _)| slots.contains(slot)) {
            made[i].push(defs.len());
            defs.push((slot, values[i][usize::from(reg)]));
        }
    }
    if defs.is_empty() {
        return HashMap::new();
    }
    let words = defs.len().div_ceil(64);
    let bit = |set: &mut Vec<u64>, d: usize| set[d / 64] |= 1 << (d % 64);
    let mut transfer: Vec<Option<(Vec<u64>, Vec<u64>)>> = vec![None; count];
    for (i, ranges) in written.iter().enumerate() {
        if ranges.is_empty() {
            continue;
        }
        let overlaps = |slot: i64| {
            let end = slot.wrapping_add(8);
            ranges.iter().any(|&(from, to)| from < end && slot < to)
        };
        let (mut kill, mut make) = (vec![0u64; words], vec![0u64; words]);
        for (d, &(slot, _)) in defs.iter().enumerate() {
            if overlaps(slot) {
                bit(&mut kill, d);
            }
        }
        for &d in &made[i] {
            bit(&mut make, d);
        }
        if kill.iter().chain(&make).any(|&w| w != 0) {
            transfer[i] = Some((kill, make));
        }
    }
    let mut before: Vec<Option<Vec<u64>>> = vec![None; count];
    let mut work = VecDeque::new();
    if count > 0 {
        before[0] = Some(vec![0; words]);
        work.push_back(0);
    }
    while let Some(i) = work.pop_front() {
        let Some(mut out) = before[i].clone() else {
            continue;
        };
        if let Some((kill, make)) = &transfer[i] {
            for (w, word) in out.iter_mut().enumerate() {
                *word = (*word & !kill[w]) | make[w];
            }
        }
        for &j in &succs[i] {
            let changed = match &mut before[j] {
                None => {
                    before[j] = Some(out.clone());
                    true
                }
                Some(known) => {
                    let mut changed = false;
                    for (word, &w) in known.iter_mut().zip(&out) {
                        changed |= (*word | w) != *word;
                        *word |= w;
                    }
                    changed
                }
            };
            if changed {
                work.push_back(j);
            }
        }
    }
    let mut direct: HashMap<(u64, u8), BTreeSet<Value>> = HashMap::new();
    for (i, reg, slot) in read {
        let Some(reach) = &before[i] else {
            continue;
        };
        let found: BTreeSet<Value> = defs
            .iter()
            .enumerate()
            .filter(|&(d, &(s, _))| s == slot && (reach[d / 64] >> (d % 64)) & 1 == 1)
            .map(|(_, &(_, value))| value)
            .collect();
        if !found.is_empty() {
            direct.insert((graph.insns[i].0, reg), found);
        }
    }
    direct
}

/// Octets de pile (décalages depuis sp à l'entrée) qu'écrit l'effet : [début,
/// fin). Une zone perdue sans fin connue n'en donne pas.
fn stack_writes(effect: &Effect, values: &Values) -> Vec<(i64, i64)> {
    let mut found = Vec::new();
    for (base, off, _) in &effect.stores {
        if let Some((Origin::Entry(SP), at)) = canonical(*base, *off, values) {
            found.push((at, at.wrapping_add(1)));
        }
    }
    for &(base, from, to) in &effect.lost {
        let (Some(to), Some((Origin::Entry(SP), k))) = (to, canonical(base, 0, values)) else {
            continue;
        };
        found.push((k.wrapping_add(from), k.wrapping_add(to)));
    }
    found
}

/// Emplacements de pile (décalage depuis sp à l'entrée) où l'effet range les
/// octets 0..7 d'un même registre x0..x30, dans l'ordre.
fn spills(effect: &Effect, values: &Values) -> Vec<(i64, u8)> {
    let mut stored: HashMap<i64, &[ByteFrom]> = HashMap::new();
    for (base, off, from) in &effect.stores {
        if let Some((Origin::Entry(SP), slot)) = canonical(*base, *off, values) {
            stored.insert(slot, from.as_slice());
        }
    }
    let byte = |slot: i64, i: u8| stored.get(&slot.wrapping_add(i64::from(i))).copied();
    let mut found = Vec::new();
    for (&slot, &from) in &stored {
        let &[ByteFrom::Reg(reg, 0)] = from else {
            continue;
        };
        let whole = (1..8u8).all(|i| byte(slot, i) == Some(&[ByteFrom::Reg(reg, i)][..]));
        if reg <= LR && whole {
            found.push((slot, reg));
        }
    }
    found
}

/// Registres x0..x30 dont l'effet écrit les 8 octets depuis 8 octets
/// consécutifs d'un emplacement de pile.
fn stack_reads(effect: &Effect, values: &Values) -> Vec<(u8, i64)> {
    let mut found = Vec::new();
    for (reg, bytes) in &effect.regs {
        let Some(&[ByteFrom::Mem(base, off)]) = bytes.first().map(|b| b.as_slice()) else {
            continue;
        };
        let at = |i: usize| [ByteFrom::Mem(base, off.wrapping_add(i as i64))];
        let whole = bytes.len() == 8 && bytes.iter().enumerate().all(|(i, b)| *b == at(i));
        if *reg > LR || !whole {
            continue;
        }
        if let Some((Origin::Entry(SP), slot)) = canonical(base, off, values) {
            found.push((*reg, slot));
        }
    }
    found
}

/// Valeurs avant chaque instruction, jusqu'au point fixe : à l'entrée chaque
/// registre vaut lui-même ; deux valeurs différentes à une jonction en font
/// une nouvelle. Une instruction non atteinte depuis l'entrée garde ses
/// propres valeurs de jonction et n'en apporte à aucune.
fn forward(
    ctx: &Ctx,
    fdes: &[(u64, u64)],
    writes: &mut Writes,
    graph: &FlowGraph,
    effects: &[Option<Effect>],
    succs: &[Vec<usize>],
) -> Vec<Values> {
    let count = graph.insns.len();
    let mut values: Vec<Option<Values>> = vec![None; count];
    let mut work = VecDeque::new();
    if count > 0 {
        values[0] = Some(std::array::from_fn(|r| (Origin::Entry(r as u8), 0)));
        work.push_back(0);
    }
    while let Some(i) = work.pop_front() {
        let Some(before) = values[i] else {
            continue;
        };
        let out = after(ctx, fdes, writes, graph, effects, i, &before);
        for &j in &succs[i] {
            let at = graph.insns[j].0;
            let changed = match values[j] {
                None => {
                    values[j] = Some(out);
                    true
                }
                Some(mut known) => {
                    let mut changed = false;
                    for (r, value) in known.iter_mut().enumerate() {
                        let merged = (Origin::Merge(at, r as u8), 0);
                        if *value != out[r] && *value != merged {
                            *value = merged;
                            changed = true;
                        }
                    }
                    if changed {
                        values[j] = Some(known);
                    }
                    changed
                }
            };
            if changed {
                work.push_back(j);
            }
        }
    }
    let unknown = |i: usize| std::array::from_fn(|r| (Origin::Merge(graph.insns[i].0, r as u8), 0));
    let filled = values.into_iter().enumerate();
    filled
        .map(|(i, v)| v.unwrap_or_else(|| unknown(i)))
        .collect()
}

/// Valeurs après l'instruction `i`. Un bl écrit les registres de
/// [`call_writes`], un blr x0..x18 et x30.
fn after(
    ctx: &Ctx,
    fdes: &[(u64, u64)],
    writes: &mut Writes,
    graph: &FlowGraph,
    effects: &[Option<Effect>],
    i: usize,
    before: &Values,
) -> Values {
    let mut out = *before;
    let (at, decoded) = &graph.insns[i];
    let called = match decoded.as_ref().map(|(_, insn)| insn.flow) {
        Some(Flow::Call(to, _)) => Some(
            writes
                .entry(to)
                .or_insert_with(|| call_writes(ctx, fdes, to))
                .clone(),
        ),
        Some(Flow::CallVia(_)) => Some(scratch().collect()),
        _ => None,
    };
    if let Some(regs) = called {
        for r in regs {
            out[usize::from(r)] = (Origin::Def(*at, r), 0);
        }
        return out;
    }
    let Some(effect) = &effects[i] else {
        return out;
    };
    for &(r, linear) in &effect.linear {
        out[usize::from(r)] = match linear {
            Some((EffectBase::Reg(b), k)) => {
                let (origin, off) = before[usize::from(b)];
                (origin, off.wrapping_add(k))
            }
            Some((EffectBase::Absolute, k)) => (Origin::Absolute, k),
            _ => (Origin::Def(*at, r), 0),
        };
    }
    out
}

/// x0..x18 et x30.
fn scratch() -> impl Iterator<Item = u8> {
    (0..=18u8).chain([LR])
}

/// Fragment externalisé appelé en `to` : début borné égal à `to`, fin connue,
/// au plus DEFAULT_SYMEX_FRAGMENT_MAX octets, exécutable.
fn fragment_at(ctx: &Ctx, fdes: &[(u64, u64)], to: u64) -> Option<Bound> {
    let callee = Bound::of(ctx, fdes, to);
    let small = callee
        .end
        .is_some_and(|end| end.saturating_sub(to) <= DEFAULT_SYMEX_FRAGMENT_MAX);
    (callee.start == to && small && ctx.image.is_exec(to)).then_some(callee)
}

/// Registres x0..x30 qu'écrit un bl vers `to` : pour un fragment sans appel ni
/// br qui ne sort que par ret, ceux que ses instructions écrivent, et x30 ;
/// sinon x0..x18 et x30.
fn call_writes(ctx: &Ctx, fdes: &[(u64, u64)], to: u64) -> Vec<u8> {
    if copy_import(ctx, to).is_some() || plt_import(ctx, to, false).is_some() {
        return scratch().collect();
    }
    let Some(bound) = fragment_at(ctx, fdes, to) else {
        return scratch().collect();
    };
    let Some(graph) = FlowGraph::build(ctx, &bound) else {
        return scratch().collect();
    };
    let inside = |dest: u64| {
        bound
            .end
            .is_some_and(|end| (bound.start..end).contains(&dest))
    };
    let mut written = BTreeSet::from([LR]);
    for (at, decoded) in &graph.insns {
        let Some((inst, insn)) = decoded else {
            return scratch().collect();
        };
        match insn.flow {
            Flow::Next | Flow::Return => {}
            Flow::Jump(dest, _) | Flow::Branch(dest, _) if inside(dest) => {}
            _ => return scratch().collect(),
        }
        let made = effect(ctx, inst, &insn.mnemonic, *at);
        written.extend(made.regs.iter().map(|&(r, _)| r).filter(|&r| r <= LR));
    }
    written.into_iter().collect()
}

fn canonical(base: EffectBase, off: i64, values: &Values) -> Option<(Origin, i64)> {
    match base {
        EffectBase::Reg(r) => {
            let (origin, k) = values[usize::from(r)];
            Some((origin, k.wrapping_add(off)))
        }
        EffectBase::Absolute => Some((Origin::Absolute, off)),
        EffectBase::Other => None,
    }
}

/// Ce que devient un octet recherché en remontant une instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Target {
    Reg(u8, u8),
    Mem(Origin, i64),
    Const(u64),
    Global(u64),
    Unknown(&'static str),
    Call(u64),
}

impl Target {
    /// Classe et position : deux octets se suivent dans une même classe si
    /// leurs positions se suivent ; une source n'a pas de position.
    fn split(self) -> (Target, Option<i64>) {
        match self {
            Target::Reg(reg, byte) => (Target::Reg(reg, 0), Some(i64::from(byte))),
            Target::Mem(origin, off) => (Target::Mem(origin, 0), Some(off)),
            other => (other, None),
        }
    }
}

fn target(from: ByteFrom, values: &Values) -> Target {
    match from {
        ByteFrom::Reg(reg, byte) => Target::Reg(reg, byte),
        ByteFrom::Mem(base, off) => match canonical(base, off, values) {
            Some((origin, k)) => Target::Mem(origin, k),
            None => Target::Unknown(REASON_COMPUTED_ADDRESS),
        },
        ByteFrom::Const(value) => Target::Const(value),
        ByteFrom::Global(at) => Target::Global(at),
        ByteFrom::Unknown => Target::Unknown(REASON_UNMODELED),
    }
}

/// Emplacement vu depuis l'appelé, à sa sortie. Un fragment voit tous les
/// registres de l'appelant et ses globales ; un autre appelé, les zones dont la
/// base est dans x0..x8. Base exacte seulement : un registre relu de la pile
/// passe par [`alias_into_callee`].
fn into_callee(loc: Loc, values: &Values, fragment: bool) -> Option<Loc> {
    match loc {
        Loc::Reg { .. } => Some(loc),
        Loc::Mem {
            origin: Origin::Absolute,
            ..
        } => fragment.then_some(loc),
        Loc::Mem { origin, off, len } => {
            let regs = if fragment { 0..=SP } else { 0..=ARGS - 1 };
            let reg = regs
                .into_iter()
                .find(|&r| values[usize::from(r)].0 == origin)?;
            let k = values[usize::from(reg)].1;
            Some(Loc::Mem {
                origin: Origin::Entry(reg),
                off: off.wrapping_sub(k),
                len,
            })
        }
    }
}

/// Comme [`into_callee`], par un registre relu de la pile qui peut valoir la
/// base de la zone : emplacement, relecture, relectures supposées.
fn alias_into_callee(
    func: &Func,
    loc: Loc,
    values: &Values,
    fragment: bool,
) -> Vec<(Loc, u64, Vec<u64>)> {
    let Loc::Mem { origin, off, len } = loc else {
        return Vec::new();
    };
    if origin == Origin::Absolute {
        return Vec::new();
    }
    let regs = if fragment { 0..=SP } else { 0..=ARGS - 1 };
    let mut found = Vec::new();
    for reg in regs {
        for ((o, k), reload, aliases) in func.may_be(values[usize::from(reg)]) {
            if o == origin {
                let off = off.wrapping_sub(k);
                let loc = Loc::Mem {
                    origin: Origin::Entry(reg),
                    off,
                    len,
                };
                found.push((loc, reload, aliases));
            }
        }
    }
    found
}

fn offset_text(off: i64) -> String {
    if off < 0 {
        format!("-{}", hex(off.unsigned_abs()))
    } else {
        format!("+{}", hex(off as u64))
    }
}

fn base_name(origin: Origin) -> String {
    match origin {
        Origin::Entry(reg) => reg_name(reg),
        Origin::Absolute => String::new(),
        Origin::Def(at, reg) => format!("{}@{}", reg_name(reg), hex(at)),
        Origin::Merge(at, reg) => format!("{}@join:{}", reg_name(reg), hex(at)),
    }
}

fn render(loc: Loc) -> String {
    match loc {
        Loc::Reg { reg, lo, len } => {
            let width = if reg >= V0 { 16 } else { 8 };
            let name = reg_name(reg);
            if lo == 0 && len == width {
                name
            } else {
                format!("{name}[{lo}:{len}]")
            }
        }
        Loc::Mem {
            origin: Origin::Absolute,
            off,
            len,
        } => format!("{}:{len}", hex(off as u64)),
        Loc::Mem { origin, off, len } => format!("{}{}:{len}", base_name(origin), offset_text(off)),
    }
}

/// Valeur d'un registre, lectures de 8 octets développées entre crochets.
fn expression(func: &Func, value: Value, depth: usize) -> String {
    let (origin, off) = value;
    let tail = if off == 0 {
        String::new()
    } else {
        offset_text(off)
    };
    let loaded = match origin {
        Origin::Def(at, reg) if depth < MAX_EXPRESSION => loaded_from(func, at, reg),
        _ => None,
    };
    match (origin, loaded) {
        (Origin::Absolute, _) => hex(off as u64),
        (_, Some(address)) => format!("[{}]{tail}", expression(func, address, depth + 1)),
        _ => format!("{}{tail}", base_name(origin)),
    }
}

/// Adresse lue par l'instruction `at` pour écrire 8 octets de `reg`.
fn loaded_from(func: &Func, at: u64, reg: u8) -> Option<Value> {
    let index = func.graph.index(at);
    let effect = func.effects.get(index)?.as_ref()?;
    let (_, bytes) = effect.regs.iter().find(|(r, _)| *r == reg)?;
    let Some(&[ByteFrom::Mem(base, off)]) = bytes.first().map(|b| b.as_slice()) else {
        return None;
    };
    let Some(&[ByteFrom::Mem(_, last)]) = bytes.get(7).map(|b| b.as_slice()) else {
        return None;
    };
    (last == off.wrapping_add(7)).then_some(())?;
    canonical(base, off, &func.values[index])
}

/// Source rencontrée ; l'égalité porte sur tous les champs rendus.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Key {
    insn: u64,
    kind: &'static str,
    bytes: [u8; 2],
    location: Option<String>,
    value: Option<u64>,
    call_target: Option<String>,
    reason: Option<&'static str>,
    aliases: Vec<u64>,
}

impl Key {
    fn new(kind: &'static str, insn: u64, bytes: [u8; 2]) -> Key {
        Key {
            insn,
            kind,
            bytes,
            location: None,
            value: None,
            call_target: None,
            reason: None,
            aliases: Vec::new(),
        }
    }
}

/// Définition qui a transformé un emplacement ; `parent` : celle d'après, vers
/// la requête. `aliases` : relectures supposées égales à un rangement pour
/// franchir ce pas ; `aliased` : ici ou plus près de la requête.
struct Node {
    insn: Option<u64>,
    parent: Option<usize>,
    aliases: Vec<u64>,
    aliased: bool,
}

/// Fonction remontée : l'analysée, ou une appelée traversée depuis l'appel
/// `caller`. `seen` : emplacements déjà recherchés à chaque point, à part
/// selon qu'un alias a été supposé.
struct Instance {
    func: Rc<Func>,
    caller: Option<(usize, usize)>,
    level: u8,
    nest: usize,
    seen: HashMap<usize, HashSet<(Fact, bool)>>,
}

/// Recherche d'une requête. Un point est l'indice d'une instruction (juste
/// avant elle) ou EXIT (après le retour).
struct Search<'c, 'a> {
    ctx: &'c Ctx<'a>,
    fdes: &'c [(u64, u64)],
    options: &'c SliceOptions,
    funcs: &'c mut HashMap<u64, Option<Rc<Func>>>,
    writes: &'c mut Writes,
    instances: Vec<Instance>,
    children: HashMap<(usize, usize), usize>,
    nodes: Vec<Node>,
    work: VecDeque<(usize, usize, Fact, usize)>,
    sources: HashMap<Key, usize>,
    steps: usize,
    budget_hit: bool,
}

impl Search<'_, '_> {
    fn run(&mut self) {
        while let Some((inst, point, fact, node)) = self.work.pop_front() {
            if self.steps >= self.options.max_steps {
                self.budget_hit = true;
                return;
            }
            self.steps += 1;
            self.explain(inst, point, fact, node);
        }
    }

    fn push(&mut self, inst: usize, point: usize, fact: Fact, node: usize) {
        let aliased = self.nodes[node].aliased;
        let seen = self.instances[inst].seen.entry(point).or_default();
        if seen.insert((fact, aliased)) {
            self.work.push_back((inst, point, fact, node));
        }
    }

    fn node(&mut self, insn: u64, parent: usize) -> usize {
        let aliased = self.nodes[parent].aliased;
        self.nodes.push(Node {
            insn: Some(insn),
            parent: Some(parent),
            aliases: Vec::new(),
            aliased,
        });
        self.nodes.len() - 1
    }

    /// Pas franchi en supposant que la relecture `reload` rend une valeur
    /// rangée ; au-delà de MAX_ALIAS_PATH relectures sur le chemin, source
    /// unknown sur `fact` en `at` à la place.
    fn assume(
        &mut self,
        reload: u64,
        aliases: Vec<u64>,
        parent: usize,
        fact: Fact,
        at: u64,
    ) -> Option<usize> {
        let mut path = self.assumed(parent);
        path.extend(&aliases);
        path.sort_unstable();
        path.dedup();
        if path.len() > MAX_ALIAS_PATH {
            self.unknown(fact, at, REASON_ALIAS_DEPTH, parent);
            return None;
        }
        self.nodes.push(Node {
            insn: Some(reload),
            parent: Some(parent),
            aliases,
            aliased: true,
        });
        Some(self.nodes.len() - 1)
    }

    fn source(&mut self, mut key: Key, node: usize) {
        key.aliases = self.assumed(node);
        self.sources.entry(key).or_insert(node);
    }

    /// Relectures supposées de `node` vers la requête, triées.
    fn assumed(&self, node: usize) -> Vec<u64> {
        let mut found = Vec::new();
        let mut at = Some(node).filter(|&n| self.nodes[n].aliased);
        while let Some(index) = at {
            found.extend(&self.nodes[index].aliases);
            at = self.nodes[index].parent;
        }
        found.sort_unstable();
        found.dedup();
        found
    }

    fn unknown(&mut self, fact: Fact, at: u64, reason: &'static str, node: usize) {
        let key = Key {
            location: Some(render(fact.loc)),
            reason: Some(reason),
            ..Key::new(KIND_UNKNOWN, at, fact.bytes())
        };
        self.source(key, node);
    }

    fn explain(&mut self, inst: usize, point: usize, fact: Fact, node: usize) {
        let func = Rc::clone(&self.instances[inst].func);
        if point == 0 {
            self.entry(inst, fact, node);
        }
        if point == EXIT {
            for &p in &func.open {
                self.unknown(fact, func.address(p), REASON_INDIRECT_BRANCH, node);
            }
            if func.exits.is_empty() && func.open.is_empty() {
                self.unknown(fact, func.bound.start, REASON_NO_PREDECESSOR, node);
            }
            for &p in &func.exits {
                self.through(inst, &func, p, true, fact, node);
            }
            return;
        }
        let preds = &func.preds[point];
        if point != 0 && preds.is_empty() {
            let reason = if func.open.is_empty() {
                REASON_NO_PREDECESSOR
            } else {
                REASON_INDIRECT_BRANCH
            };
            self.unknown(fact, func.address(point), reason, node);
            return;
        }
        for &p in preds {
            self.through(inst, &func, p, false, fact, node);
        }
    }

    /// Entrée de la fonction : source dans l'analysée, emplacement de
    /// l'appelant juste avant l'appel dans une appelée.
    fn entry(&mut self, inst: usize, fact: Fact, node: usize) {
        let instance = &self.instances[inst];
        let start = instance.func.bound.start;
        let Some((caller, call)) = instance.caller else {
            let kind = match fact.loc {
                Loc::Reg { .. } => KIND_ARG,
                Loc::Mem { .. } => KIND_INIT_MEM,
            };
            let key = Key {
                location: Some(render(fact.loc)),
                ..Key::new(kind, start, fact.bytes())
            };
            return self.source(key, node);
        };
        let values = self.instances[caller].func.values[call];
        let mapped = match fact.loc {
            Loc::Mem {
                origin: Origin::Entry(reg),
                off,
                len,
            } => {
                let (origin, k) = values[usize::from(reg)];
                let off = k.wrapping_add(off);
                Some(Loc::Mem { origin, off, len })
            }
            Loc::Reg { .. }
            | Loc::Mem {
                origin: Origin::Absolute,
                ..
            } => Some(fact.loc),
            Loc::Mem { .. } => None,
        };
        match mapped {
            Some(loc) => self.push(caller, call, Fact { loc, ..fact }, node),
            None => self.unknown(fact, start, REASON_COMPUTED_ADDRESS, node),
        }
    }

    /// Remonte l'instruction `p` : `fact` est recherché juste après elle. Une
    /// zone dont la base est écrite par `p`, relecture de pile, est aussi
    /// cherchée sur chaque valeur rangée à cet emplacement.
    fn through(&mut self, inst: usize, func: &Func, p: usize, exit: bool, fact: Fact, node: usize) {
        let at = func.address(p);
        let Some((_, insn)) = &func.graph.insns[p].1 else {
            return self.unknown(fact, at, REASON_UNMODELED, node);
        };
        if let Loc::Mem {
            origin: origin @ Origin::Def(def, _),
            off,
            len,
        } = fact.loc
        {
            let candidates = if def == at {
                func.may_be((origin, off))
            } else {
                Vec::new()
            };
            for ((origin, off), reload, aliases) in candidates {
                let Some(next) = self.assume(reload, aliases, node, fact, at) else {
                    continue;
                };
                let loc = Loc::Mem { origin, off, len };
                self.push(inst, p, Fact { loc, ..fact }, next);
            }
        }
        match insn.flow {
            Flow::Call(to, _) => self.call(inst, func, p, to, fact, node),
            Flow::Jump(to, _) | Flow::Branch(to, _) if exit => {
                self.call(inst, func, p, to, fact, node)
            }
            Flow::CallVia(via) => self.indirect(inst, func, p, via, fact, node),
            _ => self.data(inst, func, p, fact, node),
        }
    }

    fn data(&mut self, inst: usize, func: &Func, p: usize, fact: Fact, node: usize) {
        let at = func.address(p);
        let Some(effect) = &func.effects[p] else {
            return self.unknown(fact, at, REASON_UNMODELED, node);
        };
        let values = &func.values[p];
        let mut out = Vec::new();
        let mut aliased: BTreeMap<(u64, Vec<u64>), Vec<(Target, u8, bool)>> = BTreeMap::new();
        match fact.loc {
            Loc::Reg { reg, lo, len } => {
                let written = effect.regs.iter().find(|(r, _)| *r == reg);
                for i in 0..len {
                    let (byte, q) = (lo + i, fact.q + i);
                    let Some((_, bytes)) = written else {
                        out.push((Target::Reg(reg, byte), q, true));
                        continue;
                    };
                    let origins = bytes.get(usize::from(byte));
                    for &from in origins.map_or(&[][..], |o| o.as_slice()) {
                        out.push((target(from, values), q, false));
                    }
                }
            }
            Loc::Mem { origin, off, len } => {
                let mut stored: HashMap<(Origin, i64), &Vec<ByteFrom>> = HashMap::new();
                for (base, off, origins) in &effect.stores {
                    if let Some(place) = canonical(*base, *off, values) {
                        stored.insert(place, origins);
                    }
                }
                for i in 0..len {
                    let (addr, q) = (off.wrapping_add(i64::from(i)), fact.q + i);
                    let lost = effect.lost.iter().any(|&(base, from, to)| {
                        let Some((o, k)) = canonical(base, 0, values) else {
                            return false;
                        };
                        let from = k.wrapping_add(from);
                        let below = to.is_none_or(|to| addr < k.wrapping_add(to));
                        o == origin && from <= addr && below
                    });
                    if let Some(origins) = stored.get(&(origin, addr)) {
                        for &from in origins.iter() {
                            out.push((target(from, values), q, false));
                        }
                    } else if lost {
                        out.push((Target::Unknown(REASON_UNMODELED), q, false));
                    } else {
                        out.push((Target::Mem(origin, addr), q, true));
                    }
                }
                for (base, at_off, origins) in &effect.stores {
                    let Some(place) = canonical(*base, *at_off, values) else {
                        continue;
                    };
                    for ((o, addr), reload, aliases) in func.may_be(place) {
                        let rel = addr.wrapping_sub(off);
                        if o != origin || !(0..i64::from(len)).contains(&rel) {
                            continue;
                        }
                        let q = fact.q + rel as u8;
                        let found = aliased.entry((reload, aliases)).or_default();
                        for &from in origins {
                            found.push((target(from, values), q, false));
                        }
                    }
                }
            }
        }
        self.emit(inst, p, at, fact, node, out);
        for ((reload, aliases), out) in aliased {
            if let Some(next) = self.assume(reload, aliases, node, fact, at) {
                self.emit(inst, p, at, fact, next, out);
            }
        }
    }

    /// Regroupe les octets en emplacements et en sources.
    fn emit(
        &mut self,
        inst: usize,
        p: usize,
        at: u64,
        fact: Fact,
        node: usize,
        mut out: Vec<(Target, u8, bool)>,
    ) {
        out.sort();
        out.dedup();
        let mut runs: Vec<(Target, bool, Option<i64>, u8, u8)> = Vec::new();
        for (target, q, kept) in out {
            let (class, pos) = target.split();
            if let Some(last) = runs.last_mut() {
                let (c, k, start, q0, n) = *last;
                let follows = match (start, pos) {
                    (Some(s), Some(p)) => s.wrapping_add(i64::from(n)) == p,
                    (None, None) => true,
                    _ => false,
                };
                if c == class && k == kept && q0 + n == q && follows {
                    last.4 += 1;
                    continue;
                }
            }
            runs.push((class, kept, pos, q, 1));
        }
        for (class, kept, pos, q, len) in runs {
            let next = if kept { node } else { self.node(at, node) };
            let range = [q, q + len];
            let found = |kind| Key::new(kind, at, range);
            match class {
                Target::Reg(reg, _) => {
                    let lo = pos.unwrap_or(0) as u8;
                    let loc = Loc::Reg { reg, lo, len };
                    self.push(inst, p, Fact { loc, q }, next);
                }
                Target::Mem(origin, _) => {
                    let off = pos.unwrap_or(0);
                    let loc = Loc::Mem { origin, off, len };
                    self.push(inst, p, Fact { loc, q }, next);
                }
                Target::Const(value) => {
                    let key = Key {
                        value: Some(value),
                        ..found(KIND_CONST)
                    };
                    self.source(key, node);
                }
                Target::Global(value) => {
                    let key = Key {
                        value: Some(value),
                        ..found(KIND_GLOBAL)
                    };
                    self.source(key, node);
                }
                Target::Unknown(reason) => {
                    let key = Key {
                        location: Some(render(fact.loc)),
                        reason: Some(reason),
                        ..found(KIND_UNKNOWN)
                    };
                    self.source(key, node);
                }
                Target::Call(to) => {
                    let key = Key {
                        location: Some(render(fact.loc)),
                        call_target: Some(hex(to)),
                        ..found(KIND_CALL)
                    };
                    self.source(key, node);
                }
            }
        }
    }

    /// bl, ou b hors de la fonction : memcpy, fragment toujours traversé,
    /// appel suivi, sinon source call si l'appel peut écrire l'emplacement.
    /// Atteint seulement par un registre relu de la pile : suivi ou source
    /// call, et l'emplacement continue aussi de remonter.
    fn call(&mut self, inst: usize, func: &Func, p: usize, to: u64, fact: Fact, node: usize) {
        let at = func.address(p);
        let values = &func.values[p];
        if copy_import(self.ctx, to).is_some() {
            return self.copy(inst, func, p, to, fact, node);
        }
        let fragment = fragment_at(self.ctx, self.fdes, to).is_some();
        let reached = match fact.loc {
            Loc::Reg { reg, .. } => fragment || !PRESERVED.contains(&usize::from(reg)),
            Loc::Mem { .. } => into_callee(fact.loc, values, fragment).is_some(),
        };
        let aliased = alias_into_callee(func, fact.loc, values, fragment);
        if !reached && aliased.is_empty() {
            return self.push(inst, p, fact, node);
        }
        let (level, nest) = (self.instances[inst].level, self.instances[inst].nest);
        let deep = level < self.options.depth || self.options.follow.contains(&at);
        let imported = plt_import(self.ctx, to, false).is_some();
        let child = if (fragment || deep) && nest < MAX_NESTED && !imported {
            let level = if fragment { level } else { level + 1 };
            self.child(inst, p, to, level)
        } else {
            None
        };
        let key = Key {
            location: Some(render(fact.loc)),
            call_target: Some(hex(to)),
            ..Key::new(KIND_CALL, at, fact.bytes())
        };
        for (loc, reload, aliases) in aliased {
            if reached && child.is_none() {
                break;
            }
            let Some(next) = self.assume(reload, aliases, node, fact, at) else {
                continue;
            };
            match child {
                Some(child) => self.push(child, EXIT, Fact { loc, ..fact }, next),
                None => self.source(key.clone(), next),
            }
        }
        if !reached {
            return self.push(inst, p, fact, node);
        }
        if let (Some(child), Some(loc)) = (child, into_callee(fact.loc, values, fragment)) {
            return self.push(child, EXIT, Fact { loc, ..fact }, node);
        }
        self.source(key, node);
    }

    /// `value` dans l'instance `inst`, lue chez les appelants successifs tant
    /// que sa base est un registre à l'entrée.
    fn outer(&self, mut inst: usize, mut value: Value) -> Value {
        while let (Origin::Entry(reg), Some((caller, call))) =
            (value.0, self.instances[inst].caller)
        {
            let (origin, k) = self.instances[caller].func.values[call][usize::from(reg)];
            value = (origin, k.wrapping_add(value.1));
            inst = caller;
        }
        value
    }

    /// memcpy, memmove : x0 destination, x1 source, x2 longueur ; renvoie x0.
    fn copy(&mut self, inst: usize, func: &Func, p: usize, to: u64, fact: Fact, node: usize) {
        let at = func.address(p);
        let values = &func.values[p];
        let (dst, src, len) = (values[0], values[1], self.outer(inst, values[2]));
        let len = (len.0 == Origin::Absolute).then_some(len.1);
        match fact.loc {
            Loc::Reg { reg: 0, .. } => {
                let next = self.node(at, node);
                self.push(inst, p, fact, next);
            }
            Loc::Reg { reg, .. } if PRESERVED.contains(&usize::from(reg)) => {
                self.push(inst, p, fact, node)
            }
            Loc::Reg { .. } => {
                let key = Key {
                    location: Some(render(fact.loc)),
                    call_target: Some(hex(to)),
                    ..Key::new(KIND_CALL, at, fact.bytes())
                };
                self.source(key, node);
            }
            Loc::Mem {
                origin,
                off,
                len: n,
            } => {
                let mut out = Vec::new();
                for i in 0..n {
                    let (addr, q) = (off.wrapping_add(i64::from(i)), fact.q + i);
                    let rel = addr.wrapping_sub(dst.1);
                    let copied = origin == dst.0 && rel >= 0 && len.is_none_or(|len| rel < len);
                    match (copied, len) {
                        (true, Some(_)) => {
                            let from = Target::Mem(src.0, src.1.wrapping_add(rel));
                            out.push((from, q, false));
                        }
                        (true, None) => {
                            out.push((Target::Call(to), q, false));
                            out.push((Target::Mem(origin, addr), q, true));
                        }
                        (false, _) => out.push((Target::Mem(origin, addr), q, true)),
                    }
                }
                self.emit(inst, p, at, fact, node, out);
                for ((o, k), reload, aliases) in func.may_be(dst) {
                    if o != origin {
                        continue;
                    }
                    let mut out = Vec::new();
                    for i in 0..n {
                        let (addr, q) = (off.wrapping_add(i64::from(i)), fact.q + i);
                        let rel = addr.wrapping_sub(k);
                        if rel < 0 || len.is_some_and(|len| rel >= len) {
                            continue;
                        }
                        let from = match len {
                            Some(_) => Target::Mem(src.0, src.1.wrapping_add(rel)),
                            None => Target::Call(to),
                        };
                        out.push((from, q, false));
                    }
                    if out.is_empty() {
                        continue;
                    }
                    if let Some(next) = self.assume(reload, aliases, node, fact, at) {
                        self.emit(inst, p, at, fact, next, out);
                    }
                }
            }
        }
    }

    /// blr : source indirect_call si l'appel peut écrire l'emplacement ;
    /// atteint seulement par un registre relu de la pile, l'emplacement
    /// continue aussi de remonter.
    fn indirect(&mut self, inst: usize, func: &Func, p: usize, via: Via, fact: Fact, node: usize) {
        let at = func.address(p);
        let values = &func.values[p];
        let reached = match fact.loc {
            Loc::Reg { reg, .. } => !PRESERVED.contains(&usize::from(reg)),
            Loc::Mem { .. } => into_callee(fact.loc, values, false).is_some(),
        };
        let aliased = alias_into_callee(func, fact.loc, values, false);
        if !reached && aliased.is_empty() {
            return self.push(inst, p, fact, node);
        }
        let shown = match via {
            Via::Reg(reg) if reg <= SP => Some(expression(func, values[usize::from(reg)], 0)),
            _ => None,
        };
        let key = Key {
            location: Some(render(fact.loc)),
            call_target: shown,
            ..Key::new(KIND_INDIRECT_CALL, at, fact.bytes())
        };
        if reached {
            return self.source(key, node);
        }
        for (_, reload, aliases) in aliased {
            if let Some(next) = self.assume(reload, aliases, node, fact, at) {
                self.source(key.clone(), next);
            }
        }
        self.push(inst, p, fact, node);
    }

    fn child(&mut self, inst: usize, call: usize, to: u64, level: u8) -> Option<usize> {
        if let Some(&child) = self.children.get(&(inst, call)) {
            return Some(child);
        }
        let func = self.func(to)?;
        let nest = self.instances[inst].nest + 1;
        self.instances.push(Instance {
            func,
            caller: Some((inst, call)),
            level,
            nest,
            seen: HashMap::new(),
        });
        let child = self.instances.len() - 1;
        self.children.insert((inst, call), child);
        Some(child)
    }

    fn func(&mut self, start: u64) -> Option<Rc<Func>> {
        if let Some(known) = self.funcs.get(&start) {
            return known.clone();
        }
        let bound = Bound::of(self.ctx, self.fdes, start);
        let built = if bound.start == start {
            Func::build(self.ctx, self.fdes, self.writes, bound).map(Rc::new)
        } else {
            None
        };
        self.funcs.insert(start, built.clone());
        built
    }

    /// Définitions de `node` vers la requête, au plus MAX_CHAIN.
    fn chain(&self, node: usize) -> (Vec<u64>, bool) {
        let mut found = Vec::new();
        let mut at = Some(node);
        while let Some(index) = at {
            let node = &self.nodes[index];
            if let Some(insn) = node.insn {
                if found.len() == MAX_CHAIN {
                    return (found, true);
                }
                found.push(insn);
            }
            at = node.parent;
        }
        (found, false)
    }
}

/// `fn_start` dans l'ELF `bytes` que décrit `elf`. `Ok(None)` : `fn_start`
/// hors de tout segment LOAD exécutable de cet ELF.
pub(super) fn run(
    bytes: &[u8],
    elf: &ElfReport,
    fn_start: u64,
    options: &SliceOptions,
) -> Result<Option<SliceReport>, String> {
    let parsed = parse_elf(bytes).map_err(|e| format!("ELF illisible ({e})"))?;
    let dynamic = parsed.dynamic.as_deref();
    let (symbols, local_symbols) = (&parsed.symbols, &parsed.local_symbols);
    let ctx = context(parsed.image, dynamic, symbols, local_symbols);
    if ctx.arch != Some(Arch::Aarch64) {
        return Err(format!("machine {} : AArch64 seulement", elf.machine));
    }
    if !ctx.image.is_exec(fn_start) {
        return Ok(None);
    }
    let fdes = fde_ranges(&ctx.image);
    let job = AssertUnwindSafe(|| slice(&ctx, &fdes, &elf.path, fn_start, options));
    let outcome = std::panic::catch_unwind(job);
    let report = outcome.map_err(|_| "panique pendant la remontée".to_string())??;
    Ok(Some(report))
}

fn slice(
    ctx: &Ctx,
    fdes: &[(u64, u64)],
    elf: &str,
    fn_start: u64,
    options: &SliceOptions,
) -> Result<SliceReport, String> {
    let bound = Bound::of(ctx, fdes, fn_start);
    let start = bound.start;
    let Some(end) = bound.end else {
        let start = hex(start);
        return Err(format!(
            "fonction {start} sans fin connue : ni symbole de taille non nulle, ni FDE"
        ));
    };
    for query in &options.queries {
        let at = query.at;
        if !(start..end).contains(&at) || !(at - start).is_multiple_of(4) {
            let (item, at, range) = (query.to_string(), hex(at), (hex(start), hex(end)));
            let why = format!("adresse {at} hors de la fonction {}-{}", range.0, range.1);
            return Err(format!("élément {item:?} : {why}"));
        }
    }
    let mut writes = Writes::new();
    let func = match Func::build(ctx, fdes, &mut writes, bound) {
        Some(func) => Rc::new(func),
        None => return Err(format!("fonction {} illisible", hex(start))),
    };
    let mut funcs = HashMap::from([(start, Some(Rc::clone(&func)))]);
    let mut queries = Vec::new();
    for query in &options.queries {
        queries.push(answer(
            ctx,
            fdes,
            &mut funcs,
            &mut writes,
            &func,
            query,
            options,
        ));
    }
    Ok(SliceReport {
        elf: elf.to_string(),
        fn_start: hex(start),
        fn_end: Some(hex(end)),
        bound: bound.source,
        queries,
    })
}

fn answer(
    ctx: &Ctx,
    fdes: &[(u64, u64)],
    funcs: &mut HashMap<u64, Option<Rc<Func>>>,
    writes: &mut Writes,
    func: &Rc<Func>,
    query: &SliceQuery,
    options: &SliceOptions,
) -> SliceQueryReport {
    let index = func.graph.index(query.at);
    let loc = match query.location {
        SliceLocation::Reg(reg) => Loc::Reg { reg, lo: 0, len: 8 },
        SliceLocation::Mem { reg, offset, len } => {
            let (origin, k) = func.values[index][usize::from(reg)];
            let off = k.wrapping_add(offset);
            Loc::Mem { origin, off, len }
        }
    };
    let top = Instance {
        func: Rc::clone(func),
        caller: None,
        level: 0,
        nest: 0,
        seen: HashMap::new(),
    };
    let mut search = Search {
        ctx,
        fdes,
        options,
        funcs,
        writes,
        instances: vec![top],
        children: HashMap::new(),
        nodes: vec![Node {
            insn: None,
            parent: None,
            aliases: Vec::new(),
            aliased: false,
        }],
        work: VecDeque::new(),
        sources: HashMap::new(),
        steps: 0,
        budget_hit: false,
    };
    search.push(0, index, Fact { loc, q: 0 }, 0);
    search.run();
    let mut found: Vec<(Key, usize)> = std::mem::take(&mut search.sources).into_iter().collect();
    found.sort();
    let sources_total = found.len();
    let mut sources = Vec::new();
    for (key, node) in found.into_iter().take(options.max_sources) {
        let (chain, chain_truncated) = search.chain(node);
        sources.push(SliceSource {
            kind: key.kind,
            location: key.location,
            value: key.value.map(hex),
            insn_addr: hex(key.insn),
            call_target: key.call_target,
            reason: key.reason,
            bytes: key.bytes,
            chain: chain.into_iter().map(|at| step(ctx, at)).collect(),
            chain_truncated,
            aliases: key.aliases.into_iter().map(hex).collect(),
        });
    }
    let sources_truncated = sources.len() < sources_total;
    SliceQueryReport {
        at: hex(query.at),
        location: query.location.to_string(),
        complete: !search.budget_hit && !sources_truncated,
        steps: search.steps,
        sources_total,
        sources_truncated,
        sources,
    }
}

fn step(ctx: &Ctx, at: u64) -> SliceStep {
    let code = ctx.image.code_window(at);
    let insn = code.and_then(|code| decode(Arch::Aarch64, code, at, false).ok());
    let (mnemonic, operands) = insn.map(|i| (i.mnemonic, i.operands)).unwrap_or_default();
    SliceStep {
        insn_addr: hex(at),
        mnemonic,
        operands: operands.trim_end().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use object::elf;

    use super::super::{Image, Segment};
    use super::*;

    const CODE: u64 = 0x1000;
    const CALLEE: u64 = 0x1100;
    const RET: u32 = 0xd65f03c0;

    fn program(code: &[u32], callee: &[u32]) -> Vec<u8> {
        let mut data = vec![0u8; 0x2000];
        for (base, words) in [(CODE, code), (CALLEE, callee)] {
            for (i, word) in words.iter().enumerate() {
                let at = (base + 4 * i as u64) as usize;
                data[at..at + 4].copy_from_slice(&word.to_le_bytes());
            }
        }
        data
    }

    /// Un seul segment LOAD R+X ; `functions` : (début, taille, nom).
    fn loaded<'d>(data: &'d [u8], functions: &[(u64, u64, &str)]) -> Ctx<'d> {
        let size = data.len() as u64;
        let image = Image {
            data,
            ptr_size: 8,
            big_endian: false,
            machine: elf::EM_AARCH64,
            segments: vec![Segment {
                p_type: elf::PT_LOAD,
                flags: elf::PF_R | elf::PF_X,
                vaddr: 0,
                memsz: size,
                offset: 0,
                filesz: size,
            }],
            sections: Vec::new(),
        };
        let mut ctx = context(image, None, &[], &[]);
        for &(at, size, name) in functions {
            ctx.symbols.insert(at, (name.to_string(), size));
            ctx.starts.insert(at);
        }
        ctx
    }

    fn sliced(ctx: &Ctx, at: &[&str], tune: impl FnOnce(&mut SliceOptions)) -> SliceReport {
        let items: Vec<String> = at.iter().map(|s| s.to_string()).collect();
        let mut options = SliceOptions {
            queries: parse_slice_at(&items).unwrap(),
            ..SliceOptions::default()
        };
        tune(&mut options);
        slice(ctx, &[], "libt.so", CODE, &options).unwrap()
    }

    /// (kind, location ou value, insn_addr, bytes).
    fn rows(report: &SliceReport) -> Vec<Row> {
        let row = |s: &SliceSource| {
            let what = s
                .location
                .clone()
                .or_else(|| s.value.clone())
                .unwrap_or_default();
            (s.kind, what, s.insn_addr.clone(), s.bytes)
        };
        report.queries[0].sources.iter().map(row).collect()
    }

    fn chain(source: &SliceSource) -> Vec<&str> {
        source.chain.iter().map(|s| s.insn_addr.as_str()).collect()
    }

    type Row = (&'static str, String, String, [u8; 2]);

    fn row(kind: &'static str, what: &str, insn: &str, bytes: [u8; 2]) -> Row {
        (kind, what.to_string(), insn.to_string(), bytes)
    }

    #[test]
    fn a_copied_argument_is_an_arg_source() {
        // mov x0, x1 ; ret
        let data = program(&[0xaa0103e0, RET], &[]);
        let ctx = loaded(&data, &[(CODE, 8, "f")]);
        let report = sliced(&ctx, &["0x1004:x0"], |_| {});
        assert_eq!(rows(&report), [row(KIND_ARG, "x1", "0x1000", [0, 8])]);
        assert_eq!(chain(&report.queries[0].sources[0]), ["0x1000"]);
        assert_eq!(report.queries[0].sources[0].chain[0].mnemonic, "mov");
        let query = &report.queries[0];
        assert!(query.complete);
        assert_eq!(
            (query.at.as_str(), query.location.as_str()),
            ("0x1004", "x0")
        );
        assert_eq!(
            (report.fn_start.as_str(), report.bound),
            ("0x1000", "symbol")
        );
    }

    #[test]
    fn a_moved_immediate_is_a_const_source() {
        // movz x0, #5 ; ret
        let data = program(&[0xd28000a0, RET], &[]);
        let ctx = loaded(&data, &[(CODE, 8, "f")]);
        let report = sliced(&ctx, &["0x1004:x0"], |_| {});
        assert_eq!(rows(&report), [row(KIND_CONST, "0x5", "0x1000", [0, 8])]);
        let json = serde_json::to_value(&report.queries[0].sources[0]).unwrap();
        assert!(json.get("location").is_none());
        assert!(json["chain"].as_array().unwrap().is_empty());
    }

    #[test]
    fn a_stack_store_then_load_leads_back_to_the_stored_register() {
        // sub sp, sp, #0x20 ; str x1, [sp, #8] ; ldr x0, [sp, #8] ;
        // add sp, sp, #0x20 ; ret
        let code = [0xd10083ff, 0xf90007e1, 0xf94007e0, 0x910083ff, RET];
        let data = program(&code, &[]);
        let ctx = loaded(&data, &[(CODE, 20, "f")]);
        let report = sliced(&ctx, &["0x100c:x0"], |_| {});
        assert_eq!(rows(&report), [row(KIND_ARG, "x1", "0x1000", [0, 8])]);
        assert_eq!(chain(&report.queries[0].sources[0]), ["0x1004", "0x1008"]);
    }

    #[test]
    fn a_store_wider_than_the_zone_covers_part_of_it_and_the_rest_goes_on() {
        // str x2, [sp, #0x10] ; ret
        let data = program(&[0xf9000be2, RET], &[]);
        let ctx = loaded(&data, &[(CODE, 8, "f")]);
        let report = sliced(&ctx, &["0x1004:sp+0x16:4"], |_| {});
        let expected = [
            row(KIND_ARG, "x2[6:2]", "0x1000", [0, 2]),
            row(KIND_INIT_MEM, "sp+0x18:2", "0x1000", [2, 4]),
        ];
        assert_eq!(rows(&report), expected);
        assert_eq!(chain(&report.queries[0].sources[0]), ["0x1000"]);
        assert!(report.queries[0].sources[1].chain.is_empty());
    }

    #[test]
    fn two_paths_give_two_sources() {
        // cbz x0, 0x100c ; movz x2, #5 ; b 0x1010 ; movz x2, #7 ; mov x0, x2 ; ret
        let code = [
            0xb4000060, 0xd28000a2, 0x14000002, 0xd28000e2, 0xaa0203e0, RET,
        ];
        let data = program(&code, &[]);
        let ctx = loaded(&data, &[(CODE, 24, "f")]);
        let report = sliced(&ctx, &["0x1014:x0"], |_| {});
        let expected = [
            row(KIND_CONST, "0x5", "0x1004", [0, 8]),
            row(KIND_CONST, "0x7", "0x100c", [0, 8]),
        ];
        assert_eq!(rows(&report), expected);
        assert_eq!(report.queries[0].sources_total, 2);
    }

    #[test]
    fn code_without_predecessor_does_not_make_sp_a_join() {
        // sub sp, sp, #0x20 ; str x1, [sp, #8] ; b 0x1014 ; nop ; b 0x1014 ;
        // ldr x0, [sp, #8] ; add sp, sp, #0x20 ; ret
        let code = [
            0xd10083ff, 0xf90007e1, 0x14000003, 0xd503201f, 0x14000001, 0xf94007e0, 0x910083ff, RET,
        ];
        let data = program(&code, &[]);
        let ctx = loaded(&data, &[(CODE, 32, "f")]);
        let report = sliced(&ctx, &["0x1018:x0"], |_| {});
        let expected = [
            row(KIND_ARG, "x1", "0x1000", [0, 8]),
            row(KIND_UNKNOWN, "sp-0x18:8", "0x100c", [0, 8]),
        ];
        assert_eq!(rows(&report), expected);
        let sources = &report.queries[0].sources;
        assert_eq!(chain(&sources[0]), ["0x1004", "0x1014"]);
        assert_eq!(sources[1].reason, Some(REASON_NO_PREDECESSOR));
    }

    /// movz x0, #0 ; add x0, x0, #1 ; subs x1, x1, #1 ; b.ne 0x1004 ; ret
    const LOOP: [u32; 5] = [0xd2800000, 0x91000400, 0xf1000421, 0x54ffffc1, RET];

    #[test]
    fn a_loop_converges() {
        let data = program(&LOOP, &[]);
        let ctx = loaded(&data, &[(CODE, 20, "f")]);
        let report = sliced(&ctx, &["0x1010:x0"], |_| {});
        assert_eq!(rows(&report), [row(KIND_CONST, "0x0", "0x1000", [0, 8])]);
        assert!(report.queries[0].complete);
    }

    #[test]
    fn the_budget_cuts_the_search_and_says_so() {
        let data = program(&LOOP, &[]);
        let ctx = loaded(&data, &[(CODE, 20, "f")]);
        let report = sliced(&ctx, &["0x1010:x0"], |o| o.max_steps = 2);
        let query = &report.queries[0];
        assert!(!query.complete);
        assert_eq!(query.steps, 2);
    }

    #[test]
    fn the_source_cap_keeps_the_exact_total() {
        let code = [
            0xb4000060, 0xd28000a2, 0x14000002, 0xd28000e2, 0xaa0203e0, RET,
        ];
        let data = program(&code, &[]);
        let ctx = loaded(&data, &[(CODE, 24, "f")]);
        let report = sliced(&ctx, &["0x1014:x0"], |o| o.max_sources = 1);
        let query = &report.queries[0];
        assert_eq!((query.sources_total, query.sources.len()), (2, 1));
        assert!(query.sources_truncated);
        assert!(!query.complete);
    }

    #[test]
    fn memcpy_maps_the_destination_to_the_source() {
        // sub sp, sp, #0x40 ; add x0, sp, #0x10 ; mov x1, x3 ; movz x2, #0x20 ;
        // bl memcpy ; ldrb w0, [sp, #0x18] ; add sp, sp, #0x40 ; ret
        let code = [
            0xd10103ff, 0x910043e0, 0xaa0303e1, 0xd2800402, 0x9400003c, 0x394063e0, 0x910103ff, RET,
        ];
        let data = program(&code, &[RET]);
        let functions = [(CODE, 32, "f"), (CALLEE, 16, "memcpy")];
        let ctx = loaded(&data, &functions);
        let report = sliced(&ctx, &["0x1018:x0"], |_| {});
        let sources = &report.queries[0].sources;
        let copied = sources.iter().find(|s| s.kind == KIND_INIT_MEM).unwrap();
        assert_eq!(copied.location.as_deref(), Some("x3+0x8:1"));
        assert_eq!(copied.bytes, [0, 1]);
        assert_eq!(chain(copied), ["0x1010", "0x1014"]);
        let zero = sources.iter().find(|s| s.kind == KIND_CONST).unwrap();
        assert_eq!((zero.value.as_deref(), zero.bytes), (Some("0x0"), [1, 8]));
    }

    #[test]
    fn a_value_loaded_in_a_fragment_and_stored_by_the_caller() {
        // sub sp, sp, #0x20 ; bl fragment ; str x8, [sp, #8] ; ldr x0, [sp, #8] ;
        // add sp, sp, #0x20 ; ret. Fragment : ldr x8, [x0, #0x10] ; ret.
        let code = [
            0xd10083ff, 0x9400003f, 0xf90007e8, 0xf94007e0, 0x910083ff, RET,
        ];
        let data = program(&code, &[0xf9400808, RET]);
        let ctx = loaded(&data, &[(CODE, 24, "f"), (CALLEE, 8, "fragment")]);
        let report = sliced(&ctx, &["0x1010:x0"], |o| o.depth = 0);
        assert_eq!(
            rows(&report),
            [row(KIND_INIT_MEM, "x0+0x10:8", "0x1000", [0, 8])]
        );
        let source = &report.queries[0].sources[0];
        assert_eq!(chain(source), ["0x1100", "0x1008", "0x100c"]);
    }

    /// sub sp, sp, #0x20 ; add x0, sp, #0x10 ; mov x8, x3 ; [movz x2, #0x20 ;]
    /// bl fragment ; ldrb w0, [sp, #0x18] ; add sp, sp, #0x20 ; ret.
    /// Fragment : add x1, x8, #0x28 ; b memcpy. Requête sur x0 après le ldrb.
    fn copied_in_a_fragment(length: bool) -> SliceReport {
        let mut code = vec![0xd10083ff, 0x910043e0, 0xaa0303e8];
        if length {
            code.push(0xd2800402);
        }
        let bl = 0x9400_0000 | ((CALLEE - CODE) / 4 - code.len() as u64) as u32;
        code.extend([bl, 0x394063e0, 0x910083ff, RET]);
        let data = program(&code, &[0x9100a101, 0x1400003f]);
        let size = 4 * code.len() as u64;
        let functions = [
            (CODE, size, "f"),
            (CALLEE, 8, "fragment"),
            (0x1200, 4, "memcpy"),
        ];
        let ctx = loaded(&data, &functions);
        let query = format!("{:#x}:x0", CODE + size - 8);
        sliced(&ctx, &[&query], |_| {})
    }

    #[test]
    fn a_memcpy_in_a_fragment_reads_the_length_set_by_the_caller() {
        let report = copied_in_a_fragment(true);
        let sources = &report.queries[0].sources;
        let copied: Vec<_> = sources.iter().filter(|s| s.kind == KIND_INIT_MEM).collect();
        assert_eq!(copied.len(), 1);
        assert_eq!(copied[0].location.as_deref(), Some("x3+0x30:1"));
        assert_eq!(copied[0].bytes, [0, 1]);
        assert_eq!(chain(copied[0]), ["0x1104", "0x1014"]);
        assert!(sources.iter().all(|s| s.kind != KIND_CALL));
    }

    #[test]
    fn a_memcpy_in_a_fragment_without_a_constant_length_is_a_call_source() {
        let report = copied_in_a_fragment(false);
        let sources = &report.queries[0].sources;
        let call = sources.iter().find(|s| s.kind == KIND_CALL).unwrap();
        assert_eq!(call.call_target.as_deref(), Some("0x1200"));
        assert_eq!(call.insn_addr, "0x1104");
    }

    /// bl callee ; mov x0, x19 ; ret. Appelé de 0x80 octets : movz x0, #1 ; ret.
    fn call_program() -> Vec<u8> {
        program(&[0x94000040, 0xaa1303e0, RET], &[0xd2800020, RET])
    }

    fn call_functions() -> [(u64, u64, &'static str); 2] {
        [(CODE, 12, "f"), (CALLEE, 0x80, "callee")]
    }

    #[test]
    fn a_call_not_followed_that_writes_a_scratch_register_is_a_call_source() {
        let data = call_program();
        let ctx = loaded(&data, &call_functions());
        let report = sliced(&ctx, &["0x1004:x0"], |o| o.depth = 0);
        assert_eq!(rows(&report), [row(KIND_CALL, "x0", "0x1000", [0, 8])]);
        let source = &report.queries[0].sources[0];
        assert_eq!(source.call_target.as_deref(), Some("0x1100"));
    }

    #[test]
    fn a_preserved_register_crosses_a_call() {
        let data = call_program();
        let ctx = loaded(&data, &call_functions());
        let report = sliced(&ctx, &["0x1008:x0"], |o| o.depth = 0);
        assert_eq!(rows(&report), [row(KIND_ARG, "x19", "0x1000", [0, 8])]);
        assert_eq!(chain(&report.queries[0].sources[0]), ["0x1004"]);
    }

    #[test]
    fn a_followed_call_is_searched_from_its_returns() {
        let data = call_program();
        let ctx = loaded(&data, &call_functions());
        let report = sliced(&ctx, &["0x1004:x0"], |_| {});
        assert_eq!(rows(&report), [row(KIND_CONST, "0x1", "0x1100", [0, 8])]);
        let follow = sliced(&ctx, &["0x1004:x0"], |o| {
            o.depth = 0;
            o.follow = vec![0x1000];
        });
        assert_eq!(rows(&follow), rows(&report));
    }

    const BR_X16: u32 = 0xd61f0200;

    #[test]
    fn a_followed_callee_that_leaves_only_by_br_gives_an_unknown_source() {
        // bl callee ; ret. Appelé de 0x80 octets : br x16.
        let data = program(&[0x94000040, RET], &[BR_X16]);
        let ctx = loaded(&data, &[(CODE, 8, "f"), (CALLEE, 0x80, "callee")]);
        let report = sliced(&ctx, &["0x1004:x0"], |_| {});
        assert_eq!(rows(&report), [row(KIND_UNKNOWN, "x0", "0x1100", [0, 8])]);
        let source = &report.queries[0].sources[0];
        assert_eq!(source.reason, Some(REASON_INDIRECT_BRANCH));
    }

    #[test]
    fn a_callee_with_a_ret_and_a_br_gives_both_sources() {
        // bl callee ; ret. Appelé de 0x80 octets : cbz x1, 0x110c ; movz x0, #1 ;
        // ret ; br x16.
        let callee = [0xb4000061, 0xd2800020, RET, BR_X16];
        let data = program(&[0x94000040, RET], &callee);
        let ctx = loaded(&data, &[(CODE, 8, "f"), (CALLEE, 0x80, "callee")]);
        let report = sliced(&ctx, &["0x1004:x0"], |_| {});
        let expected = [
            row(KIND_CONST, "0x1", "0x1104", [0, 8]),
            row(KIND_UNKNOWN, "x0", "0x110c", [0, 8]),
        ];
        assert_eq!(rows(&report), expected);
        let source = &report.queries[0].sources[1];
        assert_eq!(source.reason, Some(REASON_INDIRECT_BRANCH));
    }

    /// str x1, [x8, #0x10] ; bl fragment ; ldr x0, [x8, #0x10] ; ret.
    fn base_program(fragment: &[u32]) -> Vec<u8> {
        program(&[0xf9000901, 0x9400003f, 0xf9400900, RET], fragment)
    }

    #[test]
    fn a_base_crosses_a_fragment_that_does_not_write_it() {
        // Fragment : add x9, x9, #1 ; ret.
        let data = base_program(&[0x91000529, RET]);
        let ctx = loaded(&data, &[(CODE, 16, "f"), (CALLEE, 8, "fragment")]);
        let report = sliced(&ctx, &["0x100c:x0"], |_| {});
        assert_eq!(rows(&report), [row(KIND_ARG, "x1", "0x1000", [0, 8])]);
        assert_eq!(chain(&report.queries[0].sources[0]), ["0x1000", "0x1008"]);
    }

    #[test]
    fn a_base_written_by_a_fragment_is_not_the_stored_one() {
        // Fragment : mov x8, x2 ; ret.
        let data = base_program(&[0xaa0203e8, RET]);
        let ctx = loaded(&data, &[(CODE, 16, "f"), (CALLEE, 8, "fragment")]);
        let report = sliced(&ctx, &["0x100c:x0"], |_| {});
        let found = rows(&report);
        assert!(!found.is_empty());
        assert!(
            !found.contains(&row(KIND_ARG, "x1", "0x1000", [0, 8])),
            "{found:?}"
        );
    }

    fn aliases(source: &SliceSource) -> Vec<&str> {
        source.aliases.iter().map(String::as_str).collect()
    }

    /// sub sp, sp, #0x20 ; <spill> ; ldr x9, [sp, #8] ; str x1, [x9, #0x10] ;
    /// ldr x2, [x0, #0x10] ; add sp, sp, #0x20 ; ret. Requête sur x2.
    fn reloaded_store(spill: u32) -> SliceReport {
        let code = [
            0xd10083ff, spill, 0xf94007e9, 0xf9000921, 0xf9400802, 0x910083ff, RET,
        ];
        let data = program(&code, &[]);
        let ctx = loaded(&data, &[(CODE, 28, "f")]);
        sliced(&ctx, &["0x1014:x2"], |_| {})
    }

    #[test]
    fn a_store_through_a_reloaded_pointer_reaches_the_zone() {
        // str x0, [sp, #8]
        let report = reloaded_store(0xf90007e0);
        let expected = [
            row(KIND_ARG, "x1", "0x1000", [0, 8]),
            row(KIND_INIT_MEM, "x0+0x10:8", "0x1000", [0, 8]),
        ];
        assert_eq!(rows(&report), expected);
        let sources = &report.queries[0].sources;
        assert_eq!(aliases(&sources[0]), ["0x1008"]);
        assert_eq!(chain(&sources[0]), ["0x100c", "0x1008", "0x1010"]);
        assert!(sources[1].aliases.is_empty());
        assert_eq!(chain(&sources[1]), ["0x1010"]);
    }

    /// sub sp, sp, #0x20 ; mov x19, x0 ; str x0, [sp, #8] ; ldr x0, [sp, #8] ;
    /// bl callee ; ldr x2, [x19, #0x10] ; add sp, sp, #0x20 ; ret. Appelé de
    /// 0x80 octets : str x1, [x0, #0x10] ; ret. Requête sur x2.
    fn reloaded_argument(depth: u8) -> SliceReport {
        let code = [
            0xd10083ff, 0xaa0003f3, 0xf90007e0, 0xf94007e0, 0x9400003c, 0xf9400a62, 0x910083ff, RET,
        ];
        let data = program(&code, &[0xf9000801, RET]);
        let ctx = loaded(&data, &[(CODE, 32, "f"), (CALLEE, 0x80, "callee")]);
        sliced(&ctx, &["0x1018:x2"], |o| o.depth = depth)
    }

    #[test]
    fn a_callee_writing_through_a_reloaded_pointer_is_followed() {
        let report = reloaded_argument(DEFAULT_SLICE_DEPTH);
        let expected = [
            row(KIND_ARG, "x1", "0x1000", [0, 8]),
            row(KIND_INIT_MEM, "x0+0x10:8", "0x1000", [0, 8]),
        ];
        assert_eq!(rows(&report), expected);
        let sources = &report.queries[0].sources;
        assert_eq!(aliases(&sources[0]), ["0x100c"]);
        assert_eq!(chain(&sources[0]), ["0x1100", "0x100c", "0x1014"]);
        assert!(sources[1].aliases.is_empty());

        let report = reloaded_argument(0);
        let expected = [
            row(KIND_INIT_MEM, "x0+0x10:8", "0x1000", [0, 8]),
            row(KIND_CALL, "x0+0x10:8", "0x1010", [0, 8]),
        ];
        assert_eq!(rows(&report), expected);
        let sources = &report.queries[0].sources;
        assert!(sources[0].aliases.is_empty());
        assert_eq!(sources[1].call_target.as_deref(), Some("0x1100"));
        assert_eq!(aliases(&sources[1]), ["0x100c"]);
        assert_eq!(chain(&sources[1]), ["0x100c", "0x1014"]);
    }

    #[test]
    fn no_alias_without_a_matching_spill() {
        // str x3, [sp, #8]
        let report = reloaded_store(0xf90007e3);
        assert_eq!(
            rows(&report),
            [row(KIND_INIT_MEM, "x0+0x10:8", "0x1000", [0, 8])]
        );
        assert!(report.queries[0].sources[0].aliases.is_empty());
    }

    #[test]
    fn two_spills_to_one_slot_give_two_candidates() {
        // sub sp, sp, #0x20 ; cbz x2, 0x1010 ; str x0, [sp, #8] ; b 0x1014 ;
        // str x3, [sp, #8] ; ldr x9, [sp, #8] ; str x1, [x9, #0x10] ;
        // add sp, sp, #0x20 ; ret
        let code = [
            0xd10083ff, 0xb4000062, 0xf90007e0, 0x14000002, 0xf90007e3, 0xf94007e9, 0xf9000921,
            0x910083ff, RET,
        ];
        let data = program(&code, &[]);
        let ctx = loaded(&data, &[(CODE, 36, "f")]);
        for base in ["x0", "x3"] {
            let zone = format!("{base}+0x10:8");
            let report = sliced(&ctx, &[&format!("0x101c:{zone}")], |_| {});
            let expected = [
                row(KIND_ARG, "x1", "0x1000", [0, 8]),
                row(KIND_INIT_MEM, &zone, "0x1000", [0, 8]),
            ];
            assert_eq!(rows(&report), expected, "{base}");
            let sources = &report.queries[0].sources;
            assert_eq!(aliases(&sources[0]), ["0x1014"], "{base}");
            assert!(sources[1].aliases.is_empty(), "{base}");
        }
    }

    #[test]
    fn a_zone_based_on_a_reloaded_pointer_is_rebased() {
        // str x1, [x0, #0x10] ; sub sp, sp, #0x20 ; str x0, [sp, #8] ;
        // ldr x9, [sp, #8] ; ldr x2, [x9, #0x10] ; add sp, sp, #0x20 ; ret
        let code = [
            0xf9000801, 0xd10083ff, 0xf90007e0, 0xf94007e9, 0xf9400922, 0x910083ff, RET,
        ];
        let data = program(&code, &[]);
        let ctx = loaded(&data, &[(CODE, 28, "f")]);
        let report = sliced(&ctx, &["0x1014:x2"], |_| {});
        let expected = [
            row(KIND_ARG, "x1", "0x1000", [0, 8]),
            row(KIND_INIT_MEM, "x9@0x100c+0x10:8", "0x1000", [0, 8]),
        ];
        assert_eq!(rows(&report), expected);
        let sources = &report.queries[0].sources;
        assert_eq!(aliases(&sources[0]), ["0x100c"]);
        assert_eq!(chain(&sources[0]), ["0x1000", "0x100c", "0x1010"]);
        assert!(sources[1].aliases.is_empty());
    }

    #[test]
    fn a_partial_spill_is_not_a_candidate() {
        // str w0, [sp, #8]
        let report = reloaded_store(0xb9000be0);
        assert_eq!(
            rows(&report),
            [row(KIND_INIT_MEM, "x0+0x10:8", "0x1000", [0, 8])]
        );
        let sources = &report.queries[0].sources;
        assert!(sources.iter().all(|s| s.aliases.is_empty()));
    }

    #[test]
    fn a_slot_addressed_through_the_frame_pointer_is_the_same_slot() {
        // sub sp, sp, #0x20 ; add x29, sp, #0x20 ; stur x0, [x29, #-8] ;
        // ldr x9, [sp, #0x18] ; str x1, [x9, #0x10] ; ldr x2, [x0, #0x10] ;
        // add sp, sp, #0x20 ; ret
        let code = [
            0xd10083ff, 0x910083fd, 0xf81f83a0, 0xf9400fe9, 0xf9000921, 0xf9400802, 0x910083ff, RET,
        ];
        let data = program(&code, &[]);
        let ctx = loaded(&data, &[(CODE, 32, "f")]);
        let report = sliced(&ctx, &["0x1018:x2"], |_| {});
        let expected = [
            row(KIND_ARG, "x1", "0x1000", [0, 8]),
            row(KIND_INIT_MEM, "x0+0x10:8", "0x1000", [0, 8]),
        ];
        assert_eq!(rows(&report), expected);
        let sources = &report.queries[0].sources;
        assert_eq!(aliases(&sources[0]), ["0x100c"]);
        assert!(sources[1].aliases.is_empty());
    }

    #[test]
    fn a_memcpy_to_a_reloaded_pointer_maps_to_its_source() {
        // sub sp, sp, #0x20 ; mov x19, x0 ; str x0, [sp, #8] ; ldr x0, [sp, #8] ;
        // mov x1, x3 ; movz x2, #0x20 ; bl memcpy ; ldrb w0, [x19, #0x18] ;
        // add sp, sp, #0x20 ; ret
        let code = [
            0xd10083ff, 0xaa0003f3, 0xf90007e0, 0xf94007e0, 0xaa0303e1, 0xd2800402, 0x9400003a,
            0x39406260, 0x910083ff, RET,
        ];
        let data = program(&code, &[RET]);
        let ctx = loaded(&data, &[(CODE, 40, "f"), (CALLEE, 16, "memcpy")]);
        let report = sliced(&ctx, &["0x101c:x19+0x18:1"], |_| {});
        let expected = [
            row(KIND_INIT_MEM, "x0+0x18:1", "0x1000", [0, 1]),
            row(KIND_INIT_MEM, "x3+0x18:1", "0x1000", [0, 1]),
        ];
        assert_eq!(rows(&report), expected);
        let sources = &report.queries[0].sources;
        assert!(sources[0].aliases.is_empty());
        assert_eq!(aliases(&sources[1]), ["0x100c"]);
        assert_eq!(chain(&sources[1]), ["0x1018", "0x100c"]);
    }

    #[test]
    fn aliases_are_absent_from_json_when_empty_and_sorted_otherwise() {
        let report = reloaded_store(0xf90007e0);
        let sources = &report.queries[0].sources;
        let plain = serde_json::to_value(&sources[1]).unwrap();
        assert!(plain.get("aliases").is_none());
        let aliased = serde_json::to_value(&sources[0]).unwrap();
        assert_eq!(aliased["aliases"], serde_json::json!(["0x1008"]));

        // sub sp, sp, #0x20 ; str x0, [sp, #8] ; ldr x9, [sp, #8] ;
        // str x9, [sp, #0x10] ; ldr x10, [sp, #0x10] ; str x1, [x10, #0x10] ;
        // ldr x2, [x0, #0x10] ; add sp, sp, #0x20 ; ret
        let code = [
            0xd10083ff, 0xf90007e0, 0xf94007e9, 0xf9000be9, 0xf9400bea, 0xf9000941, 0xf9400802,
            0x910083ff, RET,
        ];
        let data = program(&code, &[]);
        let ctx = loaded(&data, &[(CODE, 36, "f")]);
        let report = sliced(&ctx, &["0x101c:x2"], |_| {});
        let expected = [
            row(KIND_ARG, "x1", "0x1000", [0, 8]),
            row(KIND_INIT_MEM, "x0+0x10:8", "0x1000", [0, 8]),
        ];
        assert_eq!(rows(&report), expected);
        let chained = serde_json::to_value(&report.queries[0].sources[0]).unwrap();
        assert_eq!(chained["aliases"], serde_json::json!(["0x1008", "0x1010"]));
    }

    /// aliases de chaque source, dans l'ordre de rows.
    fn all_aliases(report: &SliceReport) -> Vec<Vec<&str>> {
        report.queries[0].sources.iter().map(aliases).collect()
    }

    fn no_alias(report: &SliceReport) -> bool {
        report.queries[0].sources.iter().all(|s| s.aliases.is_empty())
    }

    #[test]
    fn a_spill_overwritten_before_the_reload_is_not_a_candidate() {
        // sub sp, sp, #0x20 ; str x0, [sp, #8] ; str x3, [sp, #8] ;
        // ldr x9, [sp, #8] ; str x1, [x9, #0x10] ; add sp, sp, #0x20 ; ret
        let code = [
            0xd10083ff, 0xf90007e0, 0xf90007e3, 0xf94007e9, 0xf9000921, 0x910083ff, RET,
        ];
        let data = program(&code, &[]);
        let ctx = loaded(&data, &[(CODE, 28, "f")]);
        let report = sliced(&ctx, &["0x1014:x0+0x10:8"], |_| {});
        assert_eq!(
            rows(&report),
            [row(KIND_INIT_MEM, "x0+0x10:8", "0x1000", [0, 8])]
        );
        assert!(no_alias(&report));
        let report = sliced(&ctx, &["0x1014:x3+0x10:8"], |_| {});
        let expected = [
            row(KIND_ARG, "x1", "0x1000", [0, 8]),
            row(KIND_INIT_MEM, "x3+0x10:8", "0x1000", [0, 8]),
        ];
        assert_eq!(rows(&report), expected);
        assert_eq!(all_aliases(&report), [vec!["0x100c"], vec![]]);
    }

    #[test]
    fn a_spill_after_the_reload_is_not_a_candidate() {
        // sub sp, sp, #0x20 ; ldr x9, [sp, #8] ; str x1, [x9, #0x10] ;
        // str x0, [sp, #8] ; add sp, sp, #0x20 ; ret
        let code = [
            0xd10083ff, 0xf94007e9, 0xf9000921, 0xf90007e0, 0x910083ff, RET,
        ];
        let data = program(&code, &[]);
        let ctx = loaded(&data, &[(CODE, 24, "f")]);
        let report = sliced(&ctx, &["0x1010:x0+0x10:8"], |_| {});
        assert_eq!(
            rows(&report),
            [row(KIND_INIT_MEM, "x0+0x10:8", "0x1000", [0, 8])]
        );
        assert!(no_alias(&report));
    }

    #[test]
    fn a_spill_reaching_through_a_loop_is_a_candidate() {
        // sub sp, sp, #0x20 ; ldr x9, [sp, #8] ; str x1, [x9, #0x10] ;
        // str x0, [sp, #8] ; subs x2, x2, #1 ; b.ne 0x1004 ;
        // add sp, sp, #0x20 ; ret
        let code = [
            0xd10083ff, 0xf94007e9, 0xf9000921, 0xf90007e0, 0xf1000442, 0x54ffff81, 0x910083ff, RET,
        ];
        let data = program(&code, &[]);
        let ctx = loaded(&data, &[(CODE, 32, "f")]);
        let report = sliced(&ctx, &["0x1018:x0+0x10:8"], |_| {});
        let expected = [
            row(KIND_ARG, "x1", "0x1000", [0, 8]),
            row(KIND_INIT_MEM, "x0+0x10:8", "0x1000", [0, 8]),
        ];
        assert_eq!(rows(&report), expected);
        assert_eq!(all_aliases(&report), [vec!["0x1004"], vec![]]);
    }

    #[test]
    fn a_partial_overwrite_kills_the_spill() {
        // sub sp, sp, #0x20 ; str x0, [sp, #8] ; str w3, [sp, #0xc] ;
        // ldr x9, [sp, #8] ; str x1, [x9, #0x10] ; add sp, sp, #0x20 ; ret
        let code = [
            0xd10083ff, 0xf90007e0, 0xb9000fe3, 0xf94007e9, 0xf9000921, 0x910083ff, RET,
        ];
        let data = program(&code, &[]);
        let ctx = loaded(&data, &[(CODE, 28, "f")]);
        let report = sliced(&ctx, &["0x1014:x0+0x10:8"], |_| {});
        assert_eq!(
            rows(&report),
            [row(KIND_INIT_MEM, "x0+0x10:8", "0x1000", [0, 8])]
        );
        assert!(no_alias(&report));
    }

    #[test]
    fn a_call_does_not_kill_a_spill() {
        // sub sp, sp, #0x20 ; mov x19, x0 ; str x0, [sp, #8] ; bl callee ;
        // ldr x9, [sp, #8] ; str x1, [x9, #0x10] ; add sp, sp, #0x20 ; ret.
        // Appelé de 0x80 octets : ret.
        let code = [
            0xd10083ff, 0xaa0003f3, 0xf90007e0, 0x9400003d, 0xf94007e9, 0xf9000921, 0x910083ff, RET,
        ];
        let data = program(&code, &[RET]);
        let ctx = loaded(&data, &[(CODE, 32, "f"), (CALLEE, 0x80, "callee")]);
        let report = sliced(&ctx, &["0x1018:x19+0x10:8"], |_| {});
        let expected = [
            row(KIND_ARG, "x1", "0x1000", [0, 8]),
            row(KIND_INIT_MEM, "x0+0x10:8", "0x1000", [0, 8]),
        ];
        assert_eq!(rows(&report), expected);
        assert_eq!(all_aliases(&report), [vec!["0x1010"], vec![]]);
    }

    /// sub sp, sp, #0x20 ; <x8> ; str x8, [sp, #8] ; ldr x9, [sp, #8] ;
    /// ldrb w0, [x9, #0xd] ; add sp, sp, #0x20 ; ret. Requête sur x0.
    fn spilled_constant(x8: u32) -> SliceReport {
        let code = [
            0xd10083ff, x8, 0xf90007e8, 0xf94007e9, 0x39403520, 0x910083ff, RET,
        ];
        let data = program(&code, &[]);
        let ctx = loaded(&data, &[(CODE, 28, "f")]);
        sliced(&ctx, &["0x1014:x0"], |_| {})
    }

    #[test]
    fn a_small_integer_spilled_is_not_a_pointer() {
        // movz x8, #0x2500 : hors du segment de 0x2000 octets.
        let report = spilled_constant(0xd284a008);
        let expected = [
            row(KIND_INIT_MEM, "x9@0x100c+0xd:1", "0x1000", [0, 1]),
            row(KIND_CONST, "0x0", "0x1010", [1, 8]),
        ];
        assert_eq!(rows(&report), expected);
        assert!(no_alias(&report));
    }

    #[test]
    fn an_address_of_the_image_spilled_is_a_candidate() {
        // adr x8, 0x1800
        let report = spilled_constant(0x10003fe8);
        let expected = [
            row(KIND_INIT_MEM, "0x180d:1", "0x1000", [0, 1]),
            row(KIND_INIT_MEM, "x9@0x100c+0xd:1", "0x1000", [0, 1]),
            row(KIND_CONST, "0x0", "0x1010", [1, 8]),
        ];
        assert_eq!(rows(&report), expected);
        assert_eq!(all_aliases(&report), [vec!["0x100c"], vec![], vec![]]);
    }

    #[test]
    fn the_third_assumed_reload_gives_an_alias_depth_source() {
        // sub sp, sp, #0x30 ; str x0, [sp, #8] ; str x3, [sp, #0x10] ;
        // str x3, [sp, #0x18] ; ldr x11, [sp, #0x18] ; str x1, [x11, #0x20] ;
        // ldr x10, [sp, #0x10] ; ldr x12, [x10, #0x20] ; ldr x9, [sp, #8] ;
        // str x12, [x9, #0x10] ; ldr x2, [x0, #0x10] ; add sp, sp, #0x30 ; ret
        let code = [
            0xd100c3ff, 0xf90007e0, 0xf9000be3, 0xf9000fe3, 0xf9400feb, 0xf9001161, 0xf9400bea,
            0xf940114c, 0xf94007e9, 0xf900092c, 0xf9400802, 0x9100c3ff, RET,
        ];
        let data = program(&code, &[]);
        let ctx = loaded(&data, &[(CODE, 52, "f")]);
        let report = sliced(&ctx, &["0x102c:x2"], |_| {});
        let expected = [
            row(KIND_INIT_MEM, "x0+0x10:8", "0x1000", [0, 8]),
            row(KIND_INIT_MEM, "x10@0x1018+0x20:8", "0x1000", [0, 8]),
            row(KIND_INIT_MEM, "x3+0x20:8", "0x1000", [0, 8]),
            row(KIND_UNKNOWN, "x3+0x20:8", "0x1014", [0, 8]),
        ];
        assert_eq!(rows(&report), expected);
        let expected = [
            vec![],
            vec!["0x1020"],
            vec!["0x1018", "0x1020"],
            vec!["0x1018", "0x1020"],
        ];
        assert_eq!(all_aliases(&report), expected);
        let sources = &report.queries[0].sources;
        assert_eq!(sources[3].reason, Some(REASON_ALIAS_DEPTH));
    }

    #[test]
    fn queries_are_parsed_or_refused_with_the_item() {
        let items = [
            "0x1004:x8",
            "1008:x0+0x5a9:1",
            "0x100c:sp-0x10:8",
            "0x1004:x8",
        ];
        let items: Vec<String> = items.iter().map(|s| s.to_string()).collect();
        let queries = parse_slice_at(&items).unwrap();
        assert_eq!(queries.len(), 3);
        assert_eq!(queries[0].location, SliceLocation::Reg(8));
        let zone = SliceLocation::Mem {
            reg: 0,
            offset: 0x5a9,
            len: 1,
        };
        assert_eq!(
            queries[1],
            SliceQuery {
                at: 0x1008,
                location: zone
            }
        );
        assert_eq!(queries[2].location.to_string(), "sp-0x10:8");
        let bad_items = [
            "0x1004",
            "zz:x0",
            "0x1004:x31",
            "0x1004:w0",
            "0x1004:x0+0x5:0",
            "0x1004:x0+zz:1",
            "0x1004:x0+0x5:65",
        ];
        for bad in bad_items {
            let why = parse_slice_at(&[bad.to_string()]).unwrap_err();
            assert!(why.contains(&format!("{bad:?}")), "{why}");
        }
        assert!(parse_slice_at(&[]).is_err());
        let many: Vec<String> = (0..17)
            .map(|i| format!("{:x}:x0", 0x1000 + 4 * i))
            .collect();
        assert!(parse_slice_at(&many).unwrap_err().contains("17 requêtes"));
        let data = program(&[RET], &[]);
        let ctx = loaded(&data, &[(CODE, 4, "f")]);
        let options = SliceOptions {
            queries: parse_slice_at(&["0x2000:x0".to_string()]).unwrap(),
            ..SliceOptions::default()
        };
        let why = slice(&ctx, &[], "libt.so", CODE, &options).unwrap_err();
        assert!(
            why.contains("\"0x2000:x0\"") && why.contains("hors de la fonction"),
            "{why}"
        );
    }

    #[test]
    fn legend_defines_every_slice_field_and_option() {
        let legend = super::super::legend();
        let labels = [
            "SLICE (slices[])",
            "fn_start, fn_end, bound",
            "queries[]",
            "at",
            "location",
            "complete",
            "steps",
            "sources_total",
            "sources_truncated",
            "sources[]",
            "kind",
            "value",
            "insn_addr",
            "call_target",
            "reason",
            "bytes",
            "chain[]",
            "chain_truncated",
            "aliases",
            "emplacement",
            "base",
            "@join:",
            "--native-slice-at",
            "--native-slice-depth",
            "--native-slice-follow",
            "--native-slice-max-steps",
            "--native-slice-max-sources",
            KIND_ARG,
            KIND_INIT_MEM,
            KIND_CONST,
            KIND_GLOBAL,
            KIND_CALL,
            KIND_INDIRECT_CALL,
            KIND_UNKNOWN,
            REASON_INDIRECT_BRANCH,
            REASON_NO_PREDECESSOR,
            REASON_COMPUTED_ADDRESS,
            REASON_UNMODELED,
            REASON_ALIAS_DEPTH,
        ];
        for label in labels {
            assert!(legend.contains(label), "{label}");
        }
    }
}
