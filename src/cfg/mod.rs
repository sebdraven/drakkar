//! Call graph inter-procédural (petgraph).
use crate::model::MethodRef;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::Bfs;
use std::collections::HashMap;

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
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}
