//! Sérialise CallGraph en node_link_data (networkx.readwrite.json_graph).
use crate::cfg::CallGraph;
use anyhow::Result;
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct Node {
    id: String,
    class: String,
    name: String,
    descriptor: String,
}

#[derive(Serialize)]
struct Link {
    source: String,
    target: String,
    offset: u64,
}

#[derive(Serialize)]
struct NodeLink {
    directed: bool,
    multigraph: bool,
    graph: serde_json::Value,
    nodes: Vec<Node>,
    links: Vec<Link>,
}

pub fn write(cg: &CallGraph, out: &Path) -> Result<()> {
    let mut nodes = Vec::new();
    for idx in cg.graph.node_indices() {
        let m = &cg.graph[idx];
        nodes.push(Node {
            id: m.signature(),
            class: m.class.clone(),
            name: m.name.clone(),
            descriptor: m.descriptor.clone(),
        });
    }
    let mut links = Vec::new();
    for e in cg.graph.edge_indices() {
        let (a, b) = cg.graph.edge_endpoints(e).unwrap();
        links.push(Link {
            source: cg.graph[a].signature(),
            target: cg.graph[b].signature(),
            offset: cg.graph[e].offset,
        });
    }
    let doc = NodeLink {
        directed: true,
        multigraph: true,
        graph: serde_json::json!({}),
        nodes,
        links,
    };
    std::fs::write(out, serde_json::to_string_pretty(&doc)?)?;
    tracing::info!(out = %out.display(), "NetworkX graph written");
    Ok(())
}
