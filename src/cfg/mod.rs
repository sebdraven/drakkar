//! Call graph inter-procédural (petgraph).
use crate::model::MethodRef;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::Bfs;
use petgraph::Direction;
use std::collections::{HashMap, HashSet, VecDeque};

/// Callbacks de cycle de vie / framework qui servent de points d'entrée Android.
/// Le framework les invoque ; ils ne sont pas appelés explicitement dans le code.
const ENTRYPOINT_CALLBACKS: &[&str] = &[
    // Composants
    "onCreate",
    "onStart",
    "onStartCommand",
    "onResume",
    "onBind",
    "onReceive",
    "onHandleIntent",
    "onHandleWork",
    // Accessibility / notifications
    "onAccessibilityEvent",
    "onInterrupt",
    "onServiceConnected",
    "onNotificationPosted",
    "onNotificationRemoved",
    // Concurrence
    "run",
    "doInBackground",
    "onStartJob",
    "call",
    // Listeners courants
    "onLocationChanged",
    "onSensorChanged",
    "handleMessage",
];

/// Edge = un call site (offset dans le caller).
#[derive(Debug, Clone)]
pub struct CallSite {
    pub offset: u64,
}

pub struct CallGraph {
    pub graph: DiGraph<MethodRef, CallSite>,
    index: HashMap<String, NodeIndex>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self { graph: DiGraph::new(), index: HashMap::new() }
    }

    fn node(&mut self, m: MethodRef) -> NodeIndex {
        let key = m.signature();
        if let Some(&idx) = self.index.get(&key) {
            idx
        } else {
            let idx = self.graph.add_node(m);
            self.index.insert(key, idx);
            idx
        }
    }

    pub fn add_call(&mut self, caller: MethodRef, callee: MethodRef, site: u64) {
        let a = self.node(caller);
        let b = self.node(callee);
        self.graph.add_edge(a, b, CallSite { offset: site });
    }

    /// `to` est-il atteignable depuis `from` dans le graphe d'appel ?
    /// Matching par sous-chaîne sur la forme `api()` (class->method).
    pub fn reaches(&self, from_api: &str, to_api: &str) -> bool {
        let starts: Vec<NodeIndex> = self
            .graph
            .node_indices()
            .filter(|&n| self.graph[n].api().contains(from_api))
            .collect();
        for start in starts {
            let mut bfs = Bfs::new(&self.graph, start);
            while let Some(nx) = bfs.next(&self.graph) {
                if self.graph[nx].api().contains(to_api) {
                    return true;
                }
            }
        }
        false
    }

    /// Au moins une méthode du graphe matche `api` (sous-chaîne).
    pub fn has_api(&self, api: &str) -> bool {
        self.graph.node_indices().any(|n| self.graph[n].api().contains(api))
    }

    /// Renvoie les nœuds entrypoint : méthode dont le nom est un callback framework
    /// ET dont la classe est un composant déclaré au manifest (ou une sous-classe
    /// directe — ici on matche par égalité de classe avec les composants).
    pub fn entrypoints(&self, components: &[String]) -> Vec<NodeIndex> {
        let comp: HashSet<&str> = components.iter().map(String::as_str).collect();
        self.graph
            .node_indices()
            .filter(|&n| {
                let m = &self.graph[n];
                ENTRYPOINT_CALLBACKS.contains(&m.name.as_str()) && comp.contains(m.class.as_str())
            })
            .collect()
    }

    /// Cherche si une API (sous-chaîne de `class->name`) est atteignable depuis au
    /// moins un entrypoint validé par le manifest. Renvoie le statut + les chemins
    /// trouvés (un par entrypoint atteignant l'API), chaque chemin étant la liste
    /// ordonnée des signatures entrypoint -> ... -> API.
    pub fn reachability(&self, api: &str, entrypoints: &[NodeIndex]) -> Reachability {
        // Cibles : tous les nœuds matchant l'API.
        let targets: HashSet<NodeIndex> = self
            .graph
            .node_indices()
            .filter(|&n| self.graph[n].api().contains(api))
            .collect();
        if targets.is_empty() {
            return Reachability { reachable: false, paths: Vec::new() };
        }

        let mut paths = Vec::new();
        for &start in entrypoints {
            if let Some(path) = self.bfs_path(start, &targets) {
                paths.push(path);
            }
        }
        Reachability { reachable: !paths.is_empty(), paths }
    }

    /// BFS de `start` vers le premier nœud de `targets`, avec reconstruction du
    /// chemin (liste de signatures). None si aucune cible atteinte.
    fn bfs_path(&self, start: NodeIndex, targets: &HashSet<NodeIndex>) -> Option<Vec<String>> {
        let mut visited = HashSet::new();
        let mut pred: HashMap<NodeIndex, NodeIndex> = HashMap::new();
        let mut queue = VecDeque::new();
        visited.insert(start);
        queue.push_back(start);

        while let Some(cur) = queue.pop_front() {
            if targets.contains(&cur) {
                // Reconstruction du chemin start -> cur.
                let mut chain = vec![cur];
                let mut node = cur;
                while let Some(&p) = pred.get(&node) {
                    chain.push(p);
                    node = p;
                }
                chain.reverse();
                return Some(chain.into_iter().map(|n| self.graph[n].signature()).collect());
            }
            for next in self.graph.neighbors_directed(cur, Direction::Outgoing) {
                if visited.insert(next) {
                    pred.insert(next, cur);
                    queue.push_back(next);
                }
            }
        }
        None
    }
}

/// Résultat de reachability pour une API depuis les entrypoints.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Reachability {
    pub reachable: bool,
    /// Un chemin par entrypoint atteignant l'API (signatures ordonnées).
    pub paths: Vec<Vec<String>>,
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}
