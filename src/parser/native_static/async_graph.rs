//! `--native --native-async-graph` : graphe des fonctions d'un ELF AArch64,
//! arêtes d'appel direct et de fabrication de tables de méthodes Rust, pour
//! passer d'une fonction à une autre à travers les appels indirects. Rien
//! n'est exécuté. Étiquettes définies dans [`super::legend`].

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::panic::AssertUnwindSafe;

use object::elf;
use serde::Serialize;

use super::decode::Arch;
use super::disasm::context;
use super::native_strings::{code_addresses, code_bounds, fde_ranges, Access, FnBound};
use super::vtables::{detect, FIRST_METHOD};
use super::xrefs::{branch, data_words, relocation_tables, KIND_CALL as BRANCH_CALL, KIND_JUMP};
use super::{hex, parse_elf, parse_symex_address, ElfReport};

pub const DEFAULT_ASYNC_DEPTH: u8 = 4;
pub const DEFAULT_ASYNC_PATH_DEPTH: u8 = 12;
pub const MAX_ASYNC_DEPTH: u8 = 12;
pub const DEFAULT_ASYNC_MAX: usize = 500;
pub const MAX_ASYNC_PAIRS: usize = 64;
const MAX_PATHS: usize = 16;
const FRAGMENT_MAX: u64 = 64;

const KIND_CALL: &str = "call";
const KIND_MAKES: &str = "makes";
const KINDS: [&str; 2] = [KIND_CALL, KIND_MAKES];
const QUERY_FROM: &str = "from";
const QUERY_TO: &str = "to";
const QUERY_PATH: &str = "path";

/// `--native-async-graph <elf|*>` et ses requêtes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsyncGraphOptions {
    /// Chemin de l'ELF ; `None` pour `*`.
    pub elf: Option<String>,
    pub from: Vec<u64>,
    pub to: Vec<u64>,
    pub paths: Vec<(u64, u64)>,
    /// `None` : DEFAULT_ASYNC_DEPTH pour from et to, DEFAULT_ASYNC_PATH_DEPTH
    /// pour path.
    pub depth: Option<u8>,
    pub max: usize,
    pub kinds: Vec<&'static str>,
}

impl Default for AsyncGraphOptions {
    fn default() -> Self {
        AsyncGraphOptions {
            elf: None,
            from: Vec::new(),
            to: Vec::new(),
            paths: Vec::new(),
            depth: None,
            max: DEFAULT_ASYNC_MAX,
            kinds: KINDS.to_vec(),
        }
    }
}

/// `<a>:<b>` hexadécimaux, de 1 à 64 couples ; doublons retirés.
pub fn parse_async_paths(items: &[String]) -> Result<Vec<(u64, u64)>, String> {
    let mut found = Vec::new();
    for item in items {
        let cite = |why: String| format!("élément {item:?} : {why}");
        let Some((a, b)) = item.split_once(':') else {
            return Err(cite("attendu <adresse>:<adresse>".into()));
        };
        let pair = (
            parse_symex_address(a).map_err(cite)?,
            parse_symex_address(b).map_err(cite)?,
        );
        if !found.contains(&pair) {
            found.push(pair);
        }
    }
    if found.is_empty() || found.len() > MAX_ASYNC_PAIRS {
        let count = found.len();
        return Err(format!("{count} couples : de 1 à {MAX_ASYNC_PAIRS}"));
    }
    Ok(found)
}

/// Sous-ensemble de call, makes ; doublons retirés.
pub fn parse_async_kinds(items: &[String]) -> Result<Vec<&'static str>, String> {
    let mut found = Vec::new();
    for item in items {
        let Some(&kind) = KINDS.iter().find(|k| **k == item.as_str()) else {
            return Err(format!("élément {item:?} : call ou makes"));
        };
        if !found.contains(&kind) {
            found.push(kind);
        }
    }
    Ok(found)
}

/// Au moins une requête from, to ou path.
pub fn check_async_queries(options: &AsyncGraphOptions) -> Result<(), String> {
    if options.from.is_empty() && options.to.is_empty() && options.paths.is_empty() {
        return Err(
            "aucune requête : --native-async-from, --native-async-to ou --native-async-path".into(),
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct AsyncGraphReport {
    pub elf: String,
    pub tables_total: usize,
    pub queries: Vec<AsyncQuery>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AsyncQuery {
    pub kind: &'static str,
    pub requested: Vec<String>,
    pub resolved: Vec<String>,
    pub nodes_total: usize,
    pub edges_total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths_total: Option<usize>,
    pub truncated: bool,
    pub nodes: Vec<AsyncNode>,
    pub edges: Vec<AsyncEdge>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<Vec<AsyncEdge>>>,
    pub stores: Vec<AsyncStore>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AsyncNode {
    pub fn_start: String,
    pub fn_end: Option<String>,
    pub bound: &'static str,
    pub depth: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct AsyncEdge {
    pub from: String,
    pub to: String,
    pub kind: &'static str,
    pub insn_addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adrp_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via_fragment: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AsyncStore {
    pub table: String,
    pub vaddr: String,
}

/// Table détectée : début, destructeur, méthodes à partir de +0x18.
struct Table {
    vaddr: u64,
    dtor: Option<u64>,
    methods: Vec<u64>,
}

impl Table {
    /// (décalage, valeur) du destructeur puis des méthodes.
    fn slots(&self) -> Vec<(u64, u64)> {
        let dtor = self.dtor.map(|d| (0, d));
        let methods = self.methods.iter().enumerate();
        let methods = methods.map(|(i, &m)| (FIRST_METHOD + 8 * i as u64, m));
        dtor.into_iter().chain(methods).collect()
    }
}

/// Début de la table `table` formé par `insn` ; `adrp` : l'ADRP qui a posé la
/// page.
#[derive(Clone, Copy)]
struct Formed {
    insn: u64,
    adrp: Option<u64>,
    table: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Edge {
    from: u64,
    to: u64,
    kind: &'static str,
    insn: u64,
    adrp: Option<u64>,
    table: Option<u64>,
    offset: Option<u64>,
    via: Option<u64>,
}

/// Le graphe de l'ELF `bytes` que décrit `elf`, et les requêtes d'`options`.
pub(super) fn run(
    bytes: &[u8],
    elf: &ElfReport,
    options: &AsyncGraphOptions,
) -> Result<AsyncGraphReport, String> {
    let parsed = parse_elf(bytes).map_err(|e| format!("ELF illisible ({e})"))?;
    let pie = parsed.e_type == elf::ET_DYN;
    let dynamic = parsed.dynamic.as_deref();
    let (symbols, local_symbols) = (&parsed.symbols, &parsed.local_symbols);
    let ctx = context(parsed.image, dynamic, symbols, local_symbols);
    if ctx.arch != Some(Arch::Aarch64) {
        return Err(format!("machine {} : AArch64 seulement", elf.machine));
    }
    let fdes = fde_ranges(&ctx.image);
    let relocations = relocation_tables(&ctx.image, dynamic);
    let job = || {
        let bounds = code_bounds(&ctx.image, symbols, local_symbols);
        let found = detect(&ctx, &fdes, pie);
        let tables: Vec<Table> = found
            .into_iter()
            .map(|f| Table {
                vaddr: f.vaddr,
                dtor: f.dtor,
                methods: f.methods,
            })
            .collect();
        let index = tables.iter().enumerate().map(|(i, t)| (t.vaddr, i));
        let index: HashMap<u64, usize> = index.collect();
        let mut calls = Vec::new();
        let each = |pc, w| {
            if let Some((to, kind, _)) = branch(pc, w) {
                if kind == BRANCH_CALL || kind == KIND_JUMP {
                    calls.push((pc, to));
                }
            }
        };
        let addresses = code_addresses(&ctx.image, &ctx.slots, symbols, local_symbols, each);
        let mut formed = Vec::new();
        for a in addresses.iter().filter(|a| a.access == Access::Address) {
            if let Some(&table) = index.get(&a.target) {
                formed.push(Formed {
                    insn: a.insn,
                    adrp: a.adrp,
                    table,
                });
            }
        }
        let mut stored = Vec::new();
        for (table, words) in data_words(&ctx, &relocations, &index).iter().enumerate() {
            stored.extend(words.iter().map(|&(vaddr, _)| (table, vaddr)));
        }
        let span = |at| bounds.bound(at);
        analyze(&elf.path, span, &calls, &formed, &tables, &stored, options)
    };
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(job));
    outcome.map_err(|_| "panique pendant la recherche".to_string())?
}

/// `span` : fonction bornée qui contient une adresse. `calls` : (bl ou b,
/// destination). `stored` : (table, mot de données qui vaut son adresse).
fn analyze(
    elf: &str,
    span: impl Fn(u64) -> Option<FnBound>,
    calls: &[(u64, u64)],
    formed: &[Formed],
    tables: &[Table],
    stored: &[(usize, u64)],
    options: &AsyncGraphOptions,
) -> Result<AsyncGraphReport, String> {
    let resolve = |at: u64| {
        let why = || {
            format!(
                "élément {} : adresse hors de toute fonction bornée",
                hex(at)
            )
        };
        span(at).map(|b| b.start).ok_or_else(why)
    };
    let resolved = |list: &[u64]| -> Result<Vec<u64>, String> {
        let mut found = Vec::new();
        for &at in list {
            let start = resolve(at)?;
            if !found.contains(&start) {
                found.push(start);
            }
        }
        Ok(found)
    };
    let from = resolved(&options.from)?;
    let to = resolved(&options.to)?;
    let mut pairs = Vec::new();
    for &(a, b) in &options.paths {
        pairs.push(((a, b), (resolve(a)?, resolve(b)?)));
    }
    let edges = edges(&span, calls, formed, tables, &options.kinds);
    let mut out: HashMap<u64, Vec<usize>> = HashMap::new();
    let mut inn: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, e) in edges.iter().enumerate() {
        out.entry(e.from).or_default().push(i);
        inn.entry(e.to).or_default().push(i);
    }
    let graph = Graph {
        span,
        edges,
        out,
        inn,
        tables,
        stored,
        max: options.max,
    };
    let mut queries = Vec::new();
    if !from.is_empty() {
        let depth = options.depth.unwrap_or(DEFAULT_ASYNC_DEPTH);
        let found = graph.reach(&from, depth, true);
        queries.push(graph.answer(QUERY_FROM, &options.from, &from, found));
    }
    if !to.is_empty() {
        let depth = options.depth.unwrap_or(DEFAULT_ASYNC_DEPTH);
        let found = graph.reach(&to, depth, false);
        queries.push(graph.answer(QUERY_TO, &options.to, &to, found));
    }
    for ((a, b), (source, target)) in pairs {
        let depth = options.depth.unwrap_or(DEFAULT_ASYNC_PATH_DEPTH);
        let found = graph.shortest(source, target, depth);
        queries.push(graph.answer(QUERY_PATH, &[a, b], &[source, target], found));
    }
    Ok(AsyncGraphReport {
        elf: elf.to_string(),
        tables_total: tables.len(),
        queries,
    })
}

/// Arêtes call et makes ; celles qui partent d'un fragment remontées à
/// chacun de ses appelants ; filtrées par `kinds`, triées, sans doublon.
fn edges<S: Fn(u64) -> Option<FnBound>>(
    span: &S,
    calls: &[(u64, u64)],
    formed: &[Formed],
    tables: &[Table],
    kinds: &[&'static str],
) -> Vec<Edge> {
    let starts = |at: u64| span(at).is_some_and(|b| b.start == at);
    let blank = |from, to, kind, insn| Edge {
        from,
        to,
        kind,
        insn,
        adrp: None,
        table: None,
        offset: None,
        via: None,
    };
    let mut raw = Vec::new();
    for &(pc, to) in calls {
        if let (Some(owner), true) = (span(pc), starts(to)) {
            raw.push(blank(owner.start, to, KIND_CALL, pc));
        }
    }
    for f in formed {
        let Some(owner) = span(f.insn) else {
            continue;
        };
        let table = &tables[f.table];
        for (offset, value) in table.slots() {
            if starts(value) {
                raw.push(Edge {
                    adrp: f.adrp,
                    table: Some(table.vaddr),
                    offset: Some(offset),
                    ..blank(owner.start, value, KIND_MAKES, f.insn)
                });
            }
        }
    }
    let fragment = |start: u64| {
        let end = span(start).and_then(|b| b.end);
        end.is_some_and(|end| end.saturating_sub(start) <= FRAGMENT_MAX)
    };
    let mut callers: HashMap<u64, BTreeSet<u64>> = HashMap::new();
    for e in &raw {
        if e.kind == KIND_CALL && e.from != e.to && fragment(e.to) {
            callers.entry(e.to).or_default().insert(e.from);
        }
    }
    let mut kept = Vec::new();
    for e in raw {
        if !fragment(e.from) {
            kept.push(e);
            continue;
        }
        for &caller in callers.get(&e.from).into_iter().flatten() {
            kept.push(Edge {
                from: caller,
                via: Some(e.from),
                ..e
            });
        }
    }
    kept.retain(|e| kinds.contains(&e.kind));
    kept.sort();
    kept.dedup();
    kept
}

/// Nœuds atteints avec leur profondeur, arêtes retenues ; pour path, les
/// chemins rendus et le nombre de plus courts chemins.
struct Found {
    depths: HashMap<u64, u8>,
    edges: BTreeSet<usize>,
    paths: Option<(Vec<Vec<usize>>, usize)>,
}

struct Graph<'a, S> {
    span: S,
    edges: Vec<Edge>,
    out: HashMap<u64, Vec<usize>>,
    inn: HashMap<u64, Vec<usize>>,
    tables: &'a [Table],
    stored: &'a [(usize, u64)],
    max: usize,
}

impl<S: Fn(u64) -> Option<FnBound>> Graph<'_, S> {
    fn next(&self, at: u64, forward: bool) -> &[usize] {
        let lists = if forward { &self.out } else { &self.inn };
        lists.get(&at).map_or(&[], |l| l.as_slice())
    }

    /// Parcours en largeur jusqu'à `depth` : descendants si `forward`,
    /// ascendants sinon.
    fn depths(&self, roots: &[u64], depth: u8, forward: bool) -> HashMap<u64, u8> {
        let mut depths = HashMap::new();
        let mut queue = VecDeque::new();
        for &root in roots {
            if depths.insert(root, 0).is_none() {
                queue.push_back(root);
            }
        }
        while let Some(at) = queue.pop_front() {
            let d = depths[&at];
            if d >= depth {
                continue;
            }
            for &e in self.next(at, forward) {
                let edge = &self.edges[e];
                let other = if forward { edge.to } else { edge.from };
                if let std::collections::hash_map::Entry::Vacant(slot) = depths.entry(other) {
                    slot.insert(d + 1);
                    queue.push_back(other);
                }
            }
        }
        depths
    }

    fn reach(&self, roots: &[u64], depth: u8, forward: bool) -> Found {
        let depths = self.depths(roots, depth, forward);
        let mut edges = BTreeSet::new();
        for (&at, &d) in &depths {
            if d < depth {
                edges.extend(self.next(at, forward).iter().copied());
            }
        }
        Found {
            depths,
            edges,
            paths: None,
        }
    }

    /// Plus courts chemins de `source` à `target`, de `limit` arêtes au plus :
    /// leurs nœuds et arêtes, au plus MAX_PATHS chemins rendus.
    fn shortest(&self, source: u64, target: u64, limit: u8) -> Found {
        let reached = self.depths(&[source], limit, true);
        let Some(&goal) = reached.get(&target) else {
            return Found {
                depths: HashMap::new(),
                edges: BTreeSet::new(),
                paths: Some((Vec::new(), 0)),
            };
        };
        let on_path = |e: usize, to: u64| {
            let from = self.edges[e].from;
            let before = reached[&to].checked_sub(1);
            before.is_some() && reached.get(&from).copied() == before
        };
        let mut depths = HashMap::from([(target, goal)]);
        let mut edges = BTreeSet::new();
        let mut stack = vec![target];
        while let Some(at) = stack.pop() {
            for &e in self.next(at, false) {
                if !on_path(e, at) {
                    continue;
                }
                edges.insert(e);
                let from = self.edges[e].from;
                if depths.insert(from, reached[&from]).is_none() {
                    stack.push(from);
                }
            }
        }
        let mut order: Vec<(u8, u64)> = depths.iter().map(|(&n, &d)| (d, n)).collect();
        order.sort();
        let mut counts: HashMap<u64, u64> = HashMap::from([(source, 1)]);
        for &(_, at) in order.iter().filter(|&&(_, at)| at != source) {
            let total = self.next(at, false).iter().filter(|&&e| edges.contains(&e));
            let total = total.map(|&e| counts.get(&self.edges[e].from).copied().unwrap_or(0));
            counts.insert(at, total.fold(0u64, u64::saturating_add));
        }
        let total = usize::try_from(counts[&target]).unwrap_or(usize::MAX);
        let mut paths = Vec::new();
        let mut walk: Vec<(u64, Vec<usize>)> = vec![(target, Vec::new())];
        while let Some((at, suffix)) = walk.pop() {
            if paths.len() == MAX_PATHS {
                break;
            }
            if at == source {
                paths.push(suffix.into_iter().rev().collect());
                continue;
            }
            let incoming = self.next(at, false).iter().filter(|&&e| edges.contains(&e));
            let incoming: Vec<usize> = incoming.copied().collect();
            for &e in incoming.iter().rev() {
                let mut next = suffix.clone();
                next.push(e);
                walk.push((self.edges[e].from, next));
            }
        }
        Found {
            depths,
            edges,
            paths: Some((paths, total)),
        }
    }

    fn node(&self, at: u64, depth: u8) -> AsyncNode {
        let bound = (self.span)(at);
        AsyncNode {
            fn_start: hex(at),
            fn_end: bound.and_then(|b| b.end).map(hex),
            bound: bound.map_or("none", |b| b.source),
            depth,
        }
    }

    fn edge(&self, e: usize) -> AsyncEdge {
        let edge = &self.edges[e];
        AsyncEdge {
            from: hex(edge.from),
            to: hex(edge.to),
            kind: edge.kind,
            insn_addr: hex(edge.insn),
            adrp_addr: edge.adrp.map(hex),
            table: edge.table.map(hex),
            offset: edge.offset.map(hex),
            via_fragment: edge.via.map(hex),
        }
    }

    /// Nœuds triés par profondeur puis début, coupés à `max` ; arêtes entre
    /// nœuds rendus ; mots de données des tables qui touchent un nœud rendu.
    fn answer(
        &self,
        kind: &'static str,
        requested: &[u64],
        resolved: &[u64],
        found: Found,
    ) -> AsyncQuery {
        let mut order: Vec<(u8, u64)> = found.depths.iter().map(|(&n, &d)| (d, n)).collect();
        order.sort();
        order.truncate(self.max);
        let shown: HashSet<u64> = order.iter().map(|&(_, at)| at).collect();
        let kept = found.edges.iter().copied().filter(|&e| {
            let edge = &self.edges[e];
            shown.contains(&edge.from) && shown.contains(&edge.to)
        });
        let kept: Vec<usize> = kept.collect();
        let mut wanted: BTreeSet<u64> = kept.iter().filter_map(|&e| self.edges[e].table).collect();
        for table in self.tables {
            if table.slots().iter().any(|(_, value)| shown.contains(value)) {
                wanted.insert(table.vaddr);
            }
        }
        let mut stores: Vec<(u64, u64)> = Vec::new();
        for &(table, vaddr) in self.stored {
            let at = self.tables[table].vaddr;
            if wanted.contains(&at) {
                stores.push((at, vaddr));
            }
        }
        stores.sort_unstable();
        stores.dedup();
        let (paths, paths_total, paths_cut) = match &found.paths {
            Some((list, total)) => {
                let render = |path: &Vec<usize>| -> Vec<AsyncEdge> {
                    path.iter().map(|&e| self.edge(e)).collect()
                };
                let rendered: Vec<Vec<AsyncEdge>> = list.iter().map(render).collect();
                (Some(rendered), Some(*total), list.len() < *total)
            }
            None => (None, None, false),
        };
        let (nodes_total, edges_total) = (found.depths.len(), found.edges.len());
        let truncated = order.len() < nodes_total || kept.len() < edges_total || paths_cut;
        AsyncQuery {
            kind,
            requested: requested.iter().map(|&at| hex(at)).collect(),
            resolved: resolved.iter().map(|&at| hex(at)).collect(),
            nodes_total,
            edges_total,
            paths_total,
            truncated,
            nodes: order.iter().map(|&(d, at)| self.node(at, d)).collect(),
            edges: kept.iter().map(|&e| self.edge(e)).collect(),
            paths,
            stores: stores
                .into_iter()
                .map(|(table, vaddr)| AsyncStore {
                    table: hex(table),
                    vaddr: hex(vaddr),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: u64 = 0x1000;
    const B: u64 = 0x1100;
    const C: u64 = 0x1200;
    const D: u64 = 0x1300;
    const E: u64 = 0x1400;
    const F: u64 = 0x1500;
    const G: u64 = 0x1600;
    const H: u64 = 0x1700;
    const T: u64 = 0x9000;
    const U: u64 = 0x9100;

    const K: u64 = 0x2000;
    const M: u64 = 0x2100;
    const Y: u64 = 0x2140;
    const N: u64 = 0x2200;
    const R: u64 = 0x2300;
    const S: u64 = 0x2340;
    const Z: u64 = 0x2380;
    const Q: u64 = 0x2400;
    const P: u64 = 0x2500;
    const V: u64 = 0x9200;
    const W: u64 = 0x9300;

    /// F est un fragment de 0x20 octets ; les autres fonctions font 0x100.
    fn span(at: u64) -> Option<FnBound> {
        let starts = [A, B, C, D, E, F, G, H];
        let start = starts.into_iter().rev().find(|&s| s <= at)?;
        let end = if start == F { F + 0x20 } else { start + 0x100 };
        (at < end).then_some(FnBound {
            start,
            end: Some(end),
            source: "eh_frame",
        })
    }

    /// A appelle B ; B appelle le fragment F et fabrique T (destructeur E,
    /// méthode D) ; F saute à H et fabrique U (méthode G) ; D appelle C.
    fn graph(tune: impl FnOnce(&mut AsyncGraphOptions)) -> Result<AsyncGraphReport, String> {
        let calls = [
            (0x1010, B),
            (0x1110, F),
            (0x1504, H),
            (0x1310, C),
            (0x1320, 0x1234),
        ];
        let formed = [
            Formed {
                insn: 0x1120,
                adrp: Some(0x111c),
                table: 0,
            },
            Formed {
                insn: 0x1508,
                adrp: None,
                table: 1,
            },
        ];
        let tables = [
            Table {
                vaddr: T,
                dtor: Some(E),
                methods: vec![D],
            },
            Table {
                vaddr: U,
                dtor: None,
                methods: vec![G],
            },
        ];
        let stored = [(1, 0xa000), (0, 0xa008)];
        let mut options = AsyncGraphOptions::default();
        tune(&mut options);
        analyze("libt.so", span, &calls, &formed, &tables, &stored, &options)
    }

    fn query(tune: impl FnOnce(&mut AsyncGraphOptions)) -> AsyncQuery {
        graph(tune).unwrap().queries.remove(0)
    }

    type Row = (String, String, &'static str, String, Option<String>);

    fn rows(edges: &[AsyncEdge]) -> Vec<Row> {
        let row = |e: &AsyncEdge| {
            let (from, to, insn) = (e.from.clone(), e.to.clone(), e.insn_addr.clone());
            (from, to, e.kind, insn, e.via_fragment.clone())
        };
        edges.iter().map(row).collect()
    }

    fn row(from: u64, to: u64, kind: &'static str, insn: u64, via: Option<u64>) -> Row {
        (hex(from), hex(to), kind, hex(insn), via.map(hex))
    }

    fn starts(q: &AsyncQuery) -> Vec<(&str, u8)> {
        q.nodes
            .iter()
            .map(|n| (n.fn_start.as_str(), n.depth))
            .collect()
    }

    /// Second graphe : M fait 64 octets, Y, R et S 0x20, Z 68, les autres 0x100.
    fn small_span(at: u64) -> Option<FnBound> {
        let sizes = [
            (K, 0x100),
            (M, 0x40),
            (Y, 0x20),
            (N, 0x100),
            (R, 0x20),
            (S, 0x20),
            (Z, 0x44),
            (Q, 0x100),
            (P, 0x100),
        ];
        let &(start, size) = sizes.iter().rev().find(|&&(s, _)| s <= at)?;
        let end = start + size;
        (at < end).then_some(FnBound {
            start,
            end: Some(end),
            source: "eh_frame",
        })
    }

    /// K fabrique V (méthodes M, Y) et appelle Z ; M fabrique W (méthode P) ;
    /// N appelle R ; R, S, Y et Z appellent Q. `extra` : appels ajoutés.
    fn small_query(
        extra: &[(u64, u64)],
        tune: impl FnOnce(&mut AsyncGraphOptions),
    ) -> AsyncQuery {
        let mut calls = vec![
            (0x2010, Z),
            (0x2144, Q),
            (0x2210, R),
            (0x2304, Q),
            (0x2344, Q),
            (0x2384, Q),
        ];
        calls.extend_from_slice(extra);
        let formed = [
            Formed {
                insn: 0x2020,
                adrp: Some(0x201c),
                table: 0,
            },
            Formed {
                insn: 0x2120,
                adrp: Some(0x211c),
                table: 1,
            },
        ];
        let tables = [
            Table {
                vaddr: V,
                dtor: None,
                methods: vec![M, Y],
            },
            Table {
                vaddr: W,
                dtor: None,
                methods: vec![P],
            },
        ];
        let mut options = AsyncGraphOptions::default();
        tune(&mut options);
        let report = analyze("libs.so", small_span, &calls, &formed, &tables, &[], &options);
        report.unwrap().queries.remove(0)
    }

    #[test]
    fn a_direct_call_to_a_function_start_is_a_call_edge() {
        let q = query(|o| {
            o.from = vec![0x1010];
            o.depth = Some(1);
        });
        assert_eq!(rows(&q.edges), [row(A, B, KIND_CALL, 0x1010, None)]);
        let json = serde_json::to_value(&q.edges[0]).unwrap();
        for absent in ["adrp_addr", "table", "offset", "via_fragment"] {
            assert!(json.get(absent).is_none(), "{absent}");
        }
    }

    #[test]
    fn forming_a_table_makes_its_methods_and_destructor() {
        let q = query(|o| {
            o.from = vec![B];
            o.depth = Some(1);
        });
        let direct = |e: &&AsyncEdge| e.kind == KIND_MAKES && e.via_fragment.is_none();
        let makes: Vec<&AsyncEdge> = q.edges.iter().filter(direct).collect();
        let proofs: Vec<_> = makes
            .iter()
            .map(|&e| {
                let (table, offset) = (e.table.as_deref(), e.offset.as_deref());
                (e.to.as_str(), table, offset, e.adrp_addr.as_deref())
            })
            .collect();
        let expected = [
            ("0x1300", Some("0x9000"), Some("0x18"), Some("0x111c")),
            ("0x1400", Some("0x9000"), Some("0x0"), Some("0x111c")),
        ];
        assert_eq!(proofs, expected);
        assert!(makes.iter().all(|e| e.insn_addr == "0x1120"));
    }

    #[test]
    fn edges_leaving_a_fragment_are_raised_to_its_callers() {
        let q = query(|o| {
            o.from = vec![B];
            o.depth = Some(1);
        });
        let expected = [
            row(B, D, KIND_MAKES, 0x1120, None),
            row(B, E, KIND_MAKES, 0x1120, None),
            row(B, F, KIND_CALL, 0x1110, None),
            row(B, G, KIND_MAKES, 0x1508, Some(F)),
            row(B, H, KIND_CALL, 0x1504, Some(F)),
        ];
        assert_eq!(rows(&q.edges), expected);
        assert!(q.edges.iter().all(|e| e.from != hex(F)));
        let stores: Vec<_> = q
            .stores
            .iter()
            .map(|s| (s.table.as_str(), s.vaddr.as_str()))
            .collect();
        assert_eq!(stores, [("0x9000", "0xa008"), ("0x9100", "0xa000")]);
    }

    #[test]
    fn from_lists_descendants_by_depth() {
        let q = query(|o| o.from = vec![0x1010]);
        assert_eq!(q.kind, QUERY_FROM);
        assert_eq!(q.requested, ["0x1010"]);
        assert_eq!(q.resolved, ["0x1000"]);
        let expected = [
            ("0x1000", 0),
            ("0x1100", 1),
            ("0x1300", 2),
            ("0x1400", 2),
            ("0x1500", 2),
            ("0x1600", 2),
            ("0x1700", 2),
            ("0x1200", 3),
        ];
        assert_eq!(starts(&q), expected);
        assert_eq!((q.nodes_total, q.edges_total), (8, 7));
        assert!(!q.truncated);
        assert_eq!(
            (q.nodes[0].fn_end.as_deref(), q.nodes[0].bound),
            (Some("0x1100"), "eh_frame")
        );
    }

    #[test]
    fn to_lists_ascendants_by_depth() {
        let q = query(|o| o.to = vec![0x1210]);
        assert_eq!(q.kind, QUERY_TO);
        let expected = [("0x1200", 0), ("0x1300", 1), ("0x1100", 2), ("0x1000", 3)];
        assert_eq!(starts(&q), expected);
        assert!(q.paths.is_none());
    }

    #[test]
    fn a_path_alternates_call_and_makes() {
        let q = query(|o| o.paths = vec![(0x1010, 0x1210)]);
        assert_eq!(q.kind, QUERY_PATH);
        assert_eq!(q.resolved, ["0x1000", "0x1200"]);
        assert_eq!(q.paths_total, Some(1));
        let paths = q.paths.as_ref().unwrap();
        let expected = [
            row(A, B, KIND_CALL, 0x1010, None),
            row(B, D, KIND_MAKES, 0x1120, None),
            row(D, C, KIND_CALL, 0x1310, None),
        ];
        assert_eq!(rows(&paths[0]), expected);
        assert_eq!(
            starts(&q),
            [("0x1000", 0), ("0x1100", 1), ("0x1300", 2), ("0x1200", 3)]
        );
        assert_eq!((q.nodes_total, q.edges_total), (4, 3));
        let short = query(|o| {
            o.paths = vec![(A, C)];
            o.depth = Some(2);
        });
        assert!(short.paths.as_ref().is_some_and(|p| p.is_empty()));
        assert_eq!((short.nodes_total, short.paths_total), (0, Some(0)));
    }

    #[test]
    fn depth_and_cap_keep_exact_totals() {
        let q = query(|o| {
            o.from = vec![A];
            o.depth = Some(1);
            o.max = 1;
        });
        assert_eq!(starts(&q), [("0x1000", 0)]);
        assert!(q.edges.is_empty());
        assert_eq!((q.nodes_total, q.edges_total), (2, 1));
        assert!(q.truncated);
    }

    #[test]
    fn the_kinds_filter_keeps_one_kind() {
        let q = query(|o| {
            o.from = vec![B];
            o.depth = Some(1);
            o.kinds = vec![KIND_CALL];
        });
        let expected = [
            row(B, F, KIND_CALL, 0x1110, None),
            row(B, H, KIND_CALL, 0x1504, Some(F)),
        ];
        assert_eq!(rows(&q.edges), expected);
    }

    #[test]
    fn an_address_outside_every_function_is_refused() {
        let why = graph(|o| o.from = vec![0x9999]).unwrap_err();
        assert!(
            why.contains("0x9999") && why.contains("hors de toute fonction"),
            "{why}"
        );
        let why = graph(|o| o.paths = vec![(A, 0x9999)]).unwrap_err();
        assert!(why.contains("0x9999"), "{why}");
    }

    #[test]
    fn no_query_is_refused_and_lists_are_parsed() {
        let why = check_async_queries(&AsyncGraphOptions::default()).unwrap_err();
        assert!(why.contains("--native-async-from"), "{why}");
        let with_to = AsyncGraphOptions {
            to: vec![C],
            ..AsyncGraphOptions::default()
        };
        assert!(check_async_queries(&with_to).is_ok());
        let texts = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let pairs = parse_async_paths(&texts(&["1000:0x1200", "0x1000:1200"])).unwrap();
        assert_eq!(pairs, [(A, C)]);
        for bad in ["0x1000", "0x1000:zz"] {
            let why = parse_async_paths(&texts(&[bad])).unwrap_err();
            assert!(why.contains(&format!("{bad:?}")), "{why}");
        }
        assert_eq!(
            parse_async_kinds(&texts(&["makes", "call", "makes"])),
            Ok(vec![KIND_MAKES, KIND_CALL])
        );
        assert!(parse_async_kinds(&texts(&["jump"]))
            .unwrap_err()
            .contains("\"jump\""));
    }

    #[test]
    fn a_small_table_method_without_caller_keeps_its_edges() {
        let q = small_query(&[], |o| {
            o.from = vec![M];
            o.depth = Some(1);
        });
        assert_eq!(rows(&q.edges), [row(M, P, KIND_MAKES, 0x2120, None)]);
        let e = &q.edges[0];
        let proof = (e.table.as_deref(), e.offset.as_deref(), e.adrp_addr.as_deref());
        assert_eq!(proof, (Some("0x9300"), Some("0x18"), Some("0x211c")));
        let json = serde_json::to_value(e).unwrap();
        assert!(json.get("via_fragment").is_none());
        let q = small_query(&[], |o| o.paths = vec![(K, P)]);
        assert_eq!(q.paths_total, Some(1));
        let expected = [
            row(K, M, KIND_MAKES, 0x2020, None),
            row(M, P, KIND_MAKES, 0x2120, None),
        ];
        assert_eq!(rows(&q.paths.as_ref().unwrap()[0]), expected);
    }

    #[test]
    fn a_small_table_method_with_a_caller_is_not_a_fragment() {
        let q = small_query(&[(0x2214, M)], |o| {
            o.from = vec![N];
            o.depth = Some(2);
        });
        let expected = [
            row(M, P, KIND_MAKES, 0x2120, None),
            row(N, M, KIND_CALL, 0x2214, None),
            row(N, R, KIND_CALL, 0x2210, None),
            row(N, Q, KIND_CALL, 0x2304, Some(R)),
        ];
        assert_eq!(rows(&q.edges), expected);
        assert!(q.edges.iter().all(|e| e.via_fragment != Some(hex(M))));
    }

    #[test]
    fn a_small_function_without_caller_keeps_its_edges() {
        let q = small_query(&[], |o| {
            o.from = vec![S];
            o.depth = Some(1);
        });
        assert_eq!(rows(&q.edges), [row(S, Q, KIND_CALL, 0x2344, None)]);
    }

    #[test]
    fn a_small_called_function_outside_tables_is_still_a_fragment() {
        let q = small_query(&[], |o| {
            o.from = vec![N];
            o.depth = Some(1);
        });
        let expected = [
            row(N, R, KIND_CALL, 0x2210, None),
            row(N, Q, KIND_CALL, 0x2304, Some(R)),
        ];
        assert_eq!(rows(&q.edges), expected);
        let q = small_query(&[], |o| {
            o.from = vec![R];
            o.depth = Some(1);
        });
        assert_eq!(rows(&q.edges), Vec::<Row>::new());
    }

    #[test]
    fn the_fragment_size_limit_is_64_bytes() {
        let m = small_span(M).and_then(|b| b.end).unwrap();
        assert_eq!(m - M, FRAGMENT_MAX);
        let q = small_query(&[], |o| {
            o.from = vec![M];
            o.depth = Some(1);
        });
        assert_eq!(rows(&q.edges), [row(M, P, KIND_MAKES, 0x2120, None)]);
        let q = small_query(&[], |o| {
            o.from = vec![Y];
            o.depth = Some(1);
        });
        assert_eq!(rows(&q.edges), [row(Y, Q, KIND_CALL, 0x2144, None)]);
        let z = small_span(Z).and_then(|b| b.end).unwrap();
        assert_eq!(z - Z, 68);
        let q = small_query(&[], |o| {
            o.from = vec![K];
            o.depth = Some(1);
        });
        let expected = [
            row(K, M, KIND_MAKES, 0x2020, None),
            row(K, Y, KIND_MAKES, 0x2020, None),
            row(K, Z, KIND_CALL, 0x2010, None),
        ];
        assert_eq!(rows(&q.edges), expected);
        let q = small_query(&[], |o| {
            o.from = vec![Z];
            o.depth = Some(1);
        });
        assert_eq!(rows(&q.edges), [row(Z, Q, KIND_CALL, 0x2384, None)]);
    }

    #[test]
    fn legend_defines_every_async_graph_field_and_option() {
        let legend = super::super::legend();
        let labels = [
            "ASYNC_GRAPH (async_graph[])",
            "tables_total",
            "queries[]",
            "requested",
            "resolved",
            "nodes_total",
            "edges_total",
            "paths_total",
            "truncated",
            "nodes[]",
            "depth",
            "edges[]",
            "insn_addr",
            "adrp_addr",
            "table",
            "offset",
            "via_fragment",
            "paths[]",
            "stores[]",
            "fragment",
            "--native-async-from",
            "--native-async-to",
            "--native-async-path",
            "--native-async-depth",
            "--native-async-max",
            "--native-async-kinds",
            KIND_CALL,
            KIND_MAKES,
            QUERY_FROM,
            QUERY_TO,
            QUERY_PATH,
        ];
        for label in labels {
            assert!(legend.contains(label), "{label}");
        }
    }
}
