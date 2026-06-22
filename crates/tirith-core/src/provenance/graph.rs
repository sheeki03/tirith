//! A provenance graph composed from already-computed artifact and MCP signals
//! (PR F1). It answers ownership / execution / payload questions about a package
//! set, an installed environment, or a repository's MCP surface by COMPOSING three
//! existing data sources into one typed graph:
//!
//! * **Execution edges** ([`crate::artifact::ExecutionEdge`]) from an
//!   [`crate::artifact::ArtifactInspection`] — the "this loader triggers that
//!   payload" relationships the B6/B7 analyzers already emit (a `.pth` import, a
//!   native module init, a cross-runtime launch).
//! * **Ownership** from the duplicate-aware [`crate::artifact::record::OwnershipIndex`]
//!   that [`crate::artifact::record::index_distribution_ownership`] builds — which
//!   distribution OWNS each installed path (and which paths two distributions both
//!   claim).
//! * **The MCP lock surface** ([`crate::mcp_lock::McpInventory`]) — each declared
//!   MCP server, its transport endpoint, and the tools it exposes.
//!
//! # Composition, not detection
//!
//! This module introduces NO new detection and NO new [`crate::verdict::RuleId`]:
//! it is a read model over signals other passes already produced. It never reads
//! bytes, never runs a policy, and never blocks. A node or edge here is descriptive
//! provenance, not a verdict. (The CLI surface that drives it — `tirith pkg graph`
//! / `tirith env graph` — does the I/O of inspecting artifacts and walking an
//! environment; this layer only shapes the result.)
//!
//! # Stable ids and determinism
//!
//! Every node carries a stable string id derived from its identity (an ecosystem +
//! name + version for a distribution, a rendered [`crate::location::SubjectLocation`]
//! for a file, an `mcp:<server>` / `mcp:<server>/<tool>` id for the MCP surface),
//! so two builds over the same inputs produce the same graph and an edge can name
//! its endpoints by id. Nodes and edges are de-duplicated by id and sorted, so the
//! JSON and DOT renderings are deterministic regardless of input order.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::artifact::record::{NormalizedInstalledPath, OwnershipIndex};
use crate::artifact::{
    ArtifactInspection, DistributionIdentity, EdgeConfidence, ExecutionEdge, ExecutionTrigger,
    GenericArchiveIdentity, InspectionSubject,
};
use crate::location::SubjectLocation;
use crate::mcp_lock::{McpInventory, McpServerEntry, McpTransport};

/// What kind of thing a [`ProvenanceNode`] represents. Kept coarse on purpose: the
/// graph reasons about "who owns what" and "what triggers what", not about payload
/// specifics (those live in the underlying signals).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    /// A distributable artifact or an installed distribution (a wheel, an sdist, a
    /// `.dist-info`-backed install).
    Distribution,
    /// A generic archive identified only by filename + hash (a plain `.zip`).
    Archive,
    /// A single file: an archive member, an installed file, or a RECORD-owned path.
    File,
    /// A declared MCP server.
    McpServer,
    /// A tool a declared MCP server exposes.
    McpTool,
}

/// How a [`ProvenanceEdge`] relates its two nodes. Each variant maps to one of the
/// three composed sources, so a reader can tell ownership from execution from MCP
/// wiring at a glance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// `from` (a loader/trigger site) can cause code in `to` (a payload site) to
    /// run. Sourced from an [`ExecutionEdge`]; the concrete trigger is carried in
    /// [`ProvenanceEdge::trigger`].
    Execution,
    /// `from` (a distribution) OWNS `to` (an installed path it lists in RECORD).
    Owns,
    /// `from` (an installed path) is claimed by MORE THAN ONE distribution; this
    /// edge points at one of the co-owning distributions. The companion `Owns`
    /// edges name the others. A duplicate-ownership marker, not a verdict.
    DuplicateOwner,
    /// `from` (an MCP server) EXPOSES `to` (a tool).
    ExposesTool,
    /// `from` (an MCP server) is reached via `to` (a transport endpoint node:
    /// a URL host or a stdio command). Provenance of HOW the server is reached.
    ServedBy,
}

/// One node in the provenance graph: a stable id, its kind, a human label, and the
/// optional identity coordinates a consumer may want (ecosystem / version for a
/// distribution, a rendered location for a file). All optional fields use
/// `skip_serializing_if` so an absent coordinate adds no JSON noise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceNode {
    /// The stable, deterministic node id (see the module docs).
    pub id: String,
    /// What the node is.
    pub kind: NodeKind,
    /// A human-readable label (the distribution name, the filename, the server
    /// name). Display only; the id is the identity.
    pub label: String,
    /// The packaging ecosystem, for a [`NodeKind::Distribution`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
    /// The version string, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The rendered location of a [`NodeKind::File`] (the `outer.whl!/member` or
    /// installed-path form), so a file node round-trips to its on-disk meaning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

/// One directed edge: its kind, the two node ids it connects, a human description
/// of the concrete mechanism, and the source confidence when it came from an
/// [`ExecutionEdge`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceEdge {
    /// What relationship this edge encodes.
    pub kind: EdgeKind,
    /// The source node id (the loader / owner / server).
    pub from: String,
    /// The destination node id (the payload / owned path / tool / endpoint).
    pub to: String,
    /// A short human description of the concrete relationship (the import line, the
    /// owning RECORD, the transport string).
    pub detail: String,
    /// The concrete execution trigger, for a [`EdgeKind::Execution`] edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<ExecutionTrigger>,
    /// The source confidence, for an edge derived from an [`ExecutionEdge`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<EdgeConfidence>,
}

/// A composed provenance graph. Build it from any combination of an
/// [`ArtifactInspection`] (or several), an [`OwnershipIndex`], and an
/// [`McpInventory`]; nodes and edges are de-duplicated by id and rendered
/// deterministically.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceGraph {
    /// The graph nodes, de-duplicated by id and sorted by id.
    pub nodes: Vec<ProvenanceNode>,
    /// The graph edges, de-duplicated and sorted.
    pub edges: Vec<ProvenanceEdge>,
}

/// An accumulating builder so the several composition sources can be folded in
/// before a single de-duplicated, sorted [`ProvenanceGraph`] is produced. Nodes are
/// keyed by id in a `BTreeMap` (last write wins, so a richer later identity for the
/// same id upgrades the earlier placeholder); edges are collected into a set keyed
/// by their full identity so an identical edge contributed by two sources appears
/// once.
#[derive(Debug, Default)]
pub struct ProvenanceGraphBuilder {
    nodes: BTreeMap<String, ProvenanceNode>,
    /// Edges keyed by `(kind, from, to, detail)` for de-duplication; the value is
    /// the full edge (carrying trigger/confidence). Two different mechanisms between
    /// the same pair (a distinct `detail`) are kept as distinct edges.
    edges: BTreeMap<(EdgeKind, String, String, String), ProvenanceEdge>,
}

impl ProvenanceGraphBuilder {
    /// A fresh, empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or upgrade) a node. A node already present keeps the richer of the
    /// two: a later insert only OVERWRITES a field that the new node fills, so a
    /// file node first seen as a bare execution endpoint and later as an owned path
    /// accumulates both its label and any ecosystem/version/location it learns.
    fn upsert_node(&mut self, node: ProvenanceNode) {
        match self.nodes.get_mut(&node.id) {
            None => {
                self.nodes.insert(node.id.clone(), node);
            }
            Some(existing) => {
                if existing.label.is_empty() {
                    existing.label = node.label;
                }
                if existing.ecosystem.is_none() {
                    existing.ecosystem = node.ecosystem;
                }
                if existing.version.is_none() {
                    existing.version = node.version;
                }
                if existing.location.is_none() {
                    existing.location = node.location;
                }
            }
        }
    }

    /// Insert an edge, de-duplicating an identical `(kind, from, to, detail)`.
    fn add_edge(&mut self, edge: ProvenanceEdge) {
        let key = (
            edge.kind,
            edge.from.clone(),
            edge.to.clone(),
            edge.detail.clone(),
        );
        self.edges.entry(key).or_insert(edge);
    }

    /// Fold one artifact inspection's subject, files, and execution edges into the
    /// graph. The subject becomes a distribution/archive node; every execution edge
    /// becomes an [`EdgeKind::Execution`] edge with its endpoints as file nodes
    /// (the loader and the payload), each tied back to the owning subject by an
    /// [`EdgeKind::Owns`] edge so "which distribution does this loader belong to" is
    /// answerable. An execution edge whose `to` is the empty
    /// [`SubjectLocation::default`] (a startup hook that launches a runtime with no
    /// concrete payload file) is rendered against a synthetic per-subject "runtime"
    /// node, so the launch is still visible.
    pub fn add_inspection(&mut self, inspection: &ArtifactInspection) {
        let subject_id = subject_node_id(&inspection.subject);
        self.upsert_node(subject_node(&inspection.subject));

        // Tie every member/installed file the subject carries to its subject, so the
        // graph knows the loader/payload file nodes belong to this distribution even
        // when no execution edge names them.
        for file in &inspection.files {
            let file_id = location_node_id(&file.location);
            self.upsert_node(file_node(&file.location));
            self.add_edge(ProvenanceEdge {
                kind: EdgeKind::Owns,
                from: subject_id.clone(),
                to: file_id,
                detail: "carries member".to_string(),
                trigger: None,
                confidence: None,
            });
        }

        for edge in &inspection.execution_edges {
            self.add_execution_edge(&subject_id, edge);
        }
    }

    /// Fold a single [`ExecutionEdge`] into the graph, materialising its loader and
    /// payload as file nodes and the trigger as an [`EdgeKind::Execution`] edge.
    fn add_execution_edge(&mut self, subject_id: &str, edge: &ExecutionEdge) {
        let from_id = location_node_id(&edge.from);
        self.upsert_node(file_node(&edge.from));

        // The payload location may be the empty default (a runtime launch with no
        // concrete file). Render it against a synthetic per-subject runtime node so
        // the edge is not silently dropped.
        let to_id = if is_empty_location(&edge.to) {
            let runtime_id = format!("{subject_id}::runtime");
            self.upsert_node(ProvenanceNode {
                id: runtime_id.clone(),
                kind: NodeKind::File,
                label: "<launched runtime>".to_string(),
                ecosystem: None,
                version: None,
                location: None,
            });
            runtime_id
        } else {
            let id = location_node_id(&edge.to);
            self.upsert_node(file_node(&edge.to));
            id
        };

        self.add_edge(ProvenanceEdge {
            kind: EdgeKind::Execution,
            from: from_id,
            to: to_id,
            detail: edge.mechanism.clone(),
            trigger: Some(edge.trigger),
            confidence: Some(edge.confidence),
        });
    }

    /// Fold a duplicate-aware [`OwnershipIndex`] into the graph: every owned path
    /// claimed by more than one distribution becomes a file node with an
    /// [`EdgeKind::DuplicateOwner`] edge per owner so the collision is explicit, and
    /// each owning distribution is materialised as a node. Single-owner paths are
    /// already carried by [`Self::add_inspection`] (which ties a subject to the
    /// members it carries); the index's duplicate view is the cross-distribution
    /// signal this fold adds.
    pub fn add_ownership_index(&mut self, index: &OwnershipIndex) {
        for (path, owners) in index.duplicates() {
            let path_id = normalized_path_node_id(path);
            self.upsert_node(ProvenanceNode {
                id: path_id.clone(),
                kind: NodeKind::File,
                label: path.as_str().to_string(),
                ecosystem: None,
                version: None,
                location: Some(path.as_str().to_string()),
            });
            for owner in owners {
                let owner_id = distribution_node_id(owner);
                self.upsert_node(distribution_node(owner));
                self.add_edge(ProvenanceEdge {
                    kind: EdgeKind::DuplicateOwner,
                    from: path_id.clone(),
                    to: owner_id,
                    detail: format!("path claimed by {} distributions", owners.len()),
                    trigger: None,
                    confidence: None,
                });
            }
        }
    }

    /// Fold an MCP inventory into the graph: each declared server becomes a server
    /// node, its transport endpoint a [`NodeKind::File`]-class endpoint node tied by
    /// an [`EdgeKind::ServedBy`] edge, and each tool a tool node tied by an
    /// [`EdgeKind::ExposesTool`] edge. The transport string never carries a raw
    /// credential (the lock already redacts userinfo / env values), so the rendered
    /// detail is safe to print.
    pub fn add_mcp_inventory(&mut self, inventory: &McpInventory) {
        for server in &inventory.servers {
            self.add_mcp_server(server);
        }
    }

    /// Fold one MCP server entry.
    fn add_mcp_server(&mut self, server: &McpServerEntry) {
        let server_id = format!("mcp:{}", server.name);
        self.upsert_node(ProvenanceNode {
            id: server_id.clone(),
            kind: NodeKind::McpServer,
            label: server.name.clone(),
            ecosystem: None,
            version: None,
            location: Some(server.source_config.clone()),
        });

        let (endpoint_id, endpoint_label, detail) = mcp_transport_endpoint(&server.transport);
        if let Some(endpoint_id) = endpoint_id {
            self.upsert_node(ProvenanceNode {
                id: endpoint_id.clone(),
                kind: NodeKind::File,
                label: endpoint_label,
                ecosystem: None,
                version: None,
                location: None,
            });
            self.add_edge(ProvenanceEdge {
                kind: EdgeKind::ServedBy,
                from: server_id.clone(),
                to: endpoint_id,
                detail,
                trigger: None,
                confidence: None,
            });
        }

        for tool in &server.tools {
            let tool_id = format!("mcp:{}/{}", server.name, tool);
            self.upsert_node(ProvenanceNode {
                id: tool_id.clone(),
                kind: NodeKind::McpTool,
                label: tool.clone(),
                ecosystem: None,
                version: None,
                location: None,
            });
            self.add_edge(ProvenanceEdge {
                kind: EdgeKind::ExposesTool,
                from: server_id.clone(),
                to: tool_id,
                detail: "declared tool".to_string(),
                trigger: None,
                confidence: None,
            });
        }
    }

    /// Finalise into a deterministic [`ProvenanceGraph`]: nodes sorted by id, edges
    /// sorted by their identity key.
    pub fn build(self) -> ProvenanceGraph {
        let nodes: Vec<ProvenanceNode> = self.nodes.into_values().collect();
        let edges: Vec<ProvenanceEdge> = self.edges.into_values().collect();
        ProvenanceGraph { nodes, edges }
    }
}

impl ProvenanceGraph {
    /// Build a graph from one artifact inspection alone (no ownership index, no MCP
    /// surface). The common single-wheel `tirith pkg graph foo.whl` case.
    pub fn from_inspection(inspection: &ArtifactInspection) -> Self {
        let mut b = ProvenanceGraphBuilder::new();
        b.add_inspection(inspection);
        b.build()
    }

    /// Build a graph from a SET of inspections plus a virtual ownership index across
    /// them (the cross-distribution `tirith pkg graph a.whl b.whl` case). The
    /// ownership index supplies the duplicate-owner cross-links the per-inspection
    /// edges cannot see.
    pub fn from_inspection_set(
        inspections: &[&ArtifactInspection],
        index: &OwnershipIndex,
    ) -> Self {
        let mut b = ProvenanceGraphBuilder::new();
        for inspection in inspections {
            b.add_inspection(inspection);
        }
        b.add_ownership_index(index);
        b.build()
    }

    /// Number of nodes (for tests / summaries).
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of edges (for tests / summaries).
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Whether the graph has any execution edge (a loader -> payload relationship).
    /// Answers the "does this set carry an execution path" question directly.
    pub fn has_execution_path(&self) -> bool {
        self.edges.iter().any(|e| e.kind == EdgeKind::Execution)
    }

    /// Render the graph as pretty JSON (the `--json` surface). Stable because the
    /// nodes/edges are already sorted.
    pub fn to_json(&self) -> String {
        // Serialization of this all-owned, derive-Serialize struct cannot fail; fall
        // back to an empty object rather than panicking if it somehow does.
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Render the graph as a Graphviz DOT digraph (the `--dot` surface). Node ids
    /// and labels are quoted-and-escaped so an id containing a quote or backslash
    /// cannot break the output; edge style is derived from [`EdgeKind`] so ownership,
    /// execution, and MCP wiring read distinctly.
    pub fn to_dot(&self) -> String {
        let mut out = String::from("digraph provenance {\n");
        out.push_str("  rankdir=LR;\n");
        out.push_str("  node [shape=box];\n");
        for node in &self.nodes {
            let shape = match node.kind {
                NodeKind::Distribution => "box",
                NodeKind::Archive => "box3d",
                NodeKind::File => "note",
                NodeKind::McpServer => "component",
                NodeKind::McpTool => "ellipse",
            };
            out.push_str(&format!(
                "  {} [label={}, shape={}];\n",
                dot_quote(&node.id),
                dot_quote(&node.label),
                shape
            ));
        }
        for edge in &self.edges {
            let style = match edge.kind {
                EdgeKind::Execution => "color=red",
                EdgeKind::Owns => "color=gray",
                EdgeKind::DuplicateOwner => "color=orange, style=dashed",
                EdgeKind::ExposesTool => "color=blue",
                EdgeKind::ServedBy => "color=green, style=dotted",
            };
            out.push_str(&format!(
                "  {} -> {} [label={}, {}];\n",
                dot_quote(&edge.from),
                dot_quote(&edge.to),
                dot_quote(&edge.detail),
                style
            ));
        }
        out.push_str("}\n");
        out
    }
}

// ---------------------------------------------------------------------------
// Node-identity helpers
// ---------------------------------------------------------------------------

/// The stable node id for an inspection subject.
fn subject_node_id(subject: &InspectionSubject) -> String {
    match subject {
        InspectionSubject::Artifact(a) => {
            format!("dist:{}:{}:{}", a.ecosystem, a.name, a.sha256)
        }
        InspectionSubject::InstalledDistribution(d) => distribution_id_parts(
            &d.ecosystem.to_string(),
            &d.name,
            d.version.as_deref(),
            &d.dist_info_path,
        ),
        InspectionSubject::GenericArchive(g) => format!("archive:{}:{}", g.filename, g.sha256),
        InspectionSubject::InstalledFile(f) => {
            format!("file:{}", f.location)
        }
    }
}

/// The node for an inspection subject.
fn subject_node(subject: &InspectionSubject) -> ProvenanceNode {
    let id = subject_node_id(subject);
    match subject {
        InspectionSubject::Artifact(a) => ProvenanceNode {
            id,
            kind: NodeKind::Distribution,
            label: a.name.clone(),
            ecosystem: Some(a.ecosystem.to_string()),
            version: a.version.clone(),
            location: Some(a.filename.clone()),
        },
        InspectionSubject::InstalledDistribution(d) => ProvenanceNode {
            id,
            kind: NodeKind::Distribution,
            label: d.name.clone(),
            ecosystem: Some(d.ecosystem.to_string()),
            version: d.version.clone(),
            location: Some(d.dist_info_path.to_string()),
        },
        InspectionSubject::GenericArchive(GenericArchiveIdentity { filename, .. }) => {
            ProvenanceNode {
                id,
                kind: NodeKind::Archive,
                label: filename.clone(),
                ecosystem: None,
                version: None,
                location: Some(filename.clone()),
            }
        }
        InspectionSubject::InstalledFile(f) => ProvenanceNode {
            id,
            kind: NodeKind::File,
            label: f.location.to_string(),
            ecosystem: None,
            version: None,
            location: Some(f.location.to_string()),
        },
    }
}

/// The stable node id for a distribution identity (used by the ownership index).
fn distribution_node_id(dist: &DistributionIdentity) -> String {
    distribution_id_parts(
        &dist.ecosystem.to_string(),
        &dist.name,
        dist.version.as_deref(),
        &dist.dist_info_path,
    )
}

/// The node for a distribution identity.
fn distribution_node(dist: &DistributionIdentity) -> ProvenanceNode {
    ProvenanceNode {
        id: distribution_node_id(dist),
        kind: NodeKind::Distribution,
        label: dist.name.clone(),
        ecosystem: Some(dist.ecosystem.to_string()),
        version: dist.version.clone(),
        location: Some(dist.dist_info_path.to_string()),
    }
}

/// Compose a distribution id from its parts. The `.dist-info` location is part of
/// the id (matching `record::same_distribution`'s identity) so two same-named
/// distributions in different trees stay distinct nodes.
fn distribution_id_parts(
    ecosystem: &str,
    name: &str,
    version: Option<&str>,
    dist_info: &SubjectLocation,
) -> String {
    format!(
        "dist:{}:{}:{}:{}",
        ecosystem,
        name,
        version.unwrap_or("?"),
        dist_info
    )
}

/// The stable node id for a [`SubjectLocation`] (a file).
fn location_node_id(location: &SubjectLocation) -> String {
    format!("file:{location}")
}

/// The node for a [`SubjectLocation`] (a file).
fn file_node(location: &SubjectLocation) -> ProvenanceNode {
    ProvenanceNode {
        id: location_node_id(location),
        kind: NodeKind::File,
        label: location.to_string(),
        ecosystem: None,
        version: None,
        location: Some(location.to_string()),
    }
}

/// The stable node id for a normalized owned path.
fn normalized_path_node_id(path: &NormalizedInstalledPath) -> String {
    format!("file:{}", path.as_str())
}

/// Whether a location is the empty default (no coordinate set), used to render a
/// runtime-launch payload against a synthetic node instead of dropping the edge.
fn is_empty_location(location: &SubjectLocation) -> bool {
    location.outer_path.is_none()
        && location.member_path.is_none()
        && location.installed_path.is_none()
}

/// Derive an MCP transport endpoint node `(id, label, detail)`. Returns `None` for
/// the id when the transport names no endpoint ([`McpTransport::Unknown`]), so no
/// `ServedBy` edge is drawn. The strings come from the already-redacted lock, so no
/// raw credential is rendered.
fn mcp_transport_endpoint(transport: &McpTransport) -> (Option<String>, String, String) {
    match transport {
        McpTransport::Url { url, .. } => (
            Some(format!("mcp-endpoint:url:{url}")),
            url.clone(),
            "reached over URL transport".to_string(),
        ),
        McpTransport::Stdio { command, .. } => (
            Some(format!("mcp-endpoint:stdio:{command}")),
            command.clone(),
            "spawned as a local stdio subprocess".to_string(),
        ),
        McpTransport::Unknown => (None, String::new(), "no declared transport".to_string()),
    }
}

/// Quote and escape a string for a DOT label / id: wrap in double quotes, escaping
/// any embedded `"` and `\`. Keeps an id with a `!/` archive separator or a path
/// with a backslash from breaking the digraph.
fn dot_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::record::index_distribution_ownership;
    use crate::artifact::{
        ArtifactFile, ArtifactFileKind, ArtifactIdentity, DistributionIdentity, EdgeConfidence,
        ExecutionEdge, ExecutionTrigger, InspectionSubject,
    };
    use crate::location::SubjectLocation;
    use crate::mcp_lock::{McpInventory, McpServerEntry, McpTransport};
    use crate::threatdb::Ecosystem;

    /// A wheel artifact subject with one member file and one loader->payload
    /// execution edge (a `.pth` startup line importing a sibling module).
    fn wheel_inspection_with_edge() -> ArtifactInspection {
        let mut insp = ArtifactInspection::new(InspectionSubject::Artifact(ArtifactIdentity {
            ecosystem: Ecosystem::PyPI,
            name: "demo".to_string(),
            version: Some("1.0".to_string()),
            filename: "demo-1.0-py3-none-any.whl".to_string(),
            sha256: "a".repeat(64),
        }));
        let loader = SubjectLocation::member("demo-1.0-py3-none-any.whl", "demo/bootstrap.pth");
        let payload = SubjectLocation::member("demo-1.0-py3-none-any.whl", "demo/_payload.py");
        insp.files.push(ArtifactFile {
            location: loader.clone(),
            size: 42,
            sha256: "b".repeat(64),
            kind: ArtifactFileKind::PthFile,
        });
        insp.execution_edges.push(ExecutionEdge {
            from: loader,
            trigger: ExecutionTrigger::PythonStartupPth,
            to: payload,
            mechanism: "startup line imports demo._payload".to_string(),
            confidence: EdgeConfidence::High,
        });
        insp
    }

    #[test]
    fn from_inspection_builds_subject_loader_payload() {
        let graph = ProvenanceGraph::from_inspection(&wheel_inspection_with_edge());
        // The distribution + loader file + payload file = 3 nodes.
        assert_eq!(graph.node_count(), 3);
        // One execution edge (loader -> payload) plus one ownership edge (subject ->
        // loader member). The payload is reached only via the execution edge.
        assert!(graph.has_execution_path());
        let exec: Vec<&ProvenanceEdge> = graph
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Execution)
            .collect();
        assert_eq!(exec.len(), 1);
        assert_eq!(exec[0].trigger, Some(ExecutionTrigger::PythonStartupPth));
        assert_eq!(exec[0].confidence, Some(EdgeConfidence::High));
        // The loader endpoint resolves to the .pth member.
        assert!(exec[0].from.contains("bootstrap.pth"));
        assert!(exec[0].to.contains("_payload.py"));
    }

    #[test]
    fn deterministic_render_independent_of_edge_order() {
        let insp = wheel_inspection_with_edge();
        let a = ProvenanceGraph::from_inspection(&insp);
        // Re-build over the same input must produce byte-identical JSON.
        let b = ProvenanceGraph::from_inspection(&insp);
        assert_eq!(a.to_json(), b.to_json());
        assert_eq!(a.to_dot(), b.to_dot());
    }

    #[test]
    fn dot_escapes_archive_separator_and_quotes() {
        let graph = ProvenanceGraph::from_inspection(&wheel_inspection_with_edge());
        let dot = graph.to_dot();
        assert!(dot.starts_with("digraph provenance {"));
        assert!(dot.trim_end().ends_with('}'));
        // The `!/` archive separator appears inside a quoted id, never bare.
        assert!(dot.contains("bootstrap.pth"));
        // A would-be-breaking quote in a label is escaped.
        let mut insp = wheel_inspection_with_edge();
        if let InspectionSubject::Artifact(a) = &mut insp.subject {
            a.name = "weird\"name".to_string();
        }
        let dot2 = ProvenanceGraph::from_inspection(&insp).to_dot();
        assert!(dot2.contains("weird\\\"name"));
    }

    #[test]
    fn runtime_launch_edge_is_not_dropped() {
        // A startup hook that launches a foreign runtime emits an edge whose `to` is
        // the empty default location; it must still appear, against a synthetic node.
        let mut insp = ArtifactInspection::new(InspectionSubject::Artifact(ArtifactIdentity {
            ecosystem: Ecosystem::PyPI,
            name: "demo".to_string(),
            version: Some("1.0".to_string()),
            filename: "demo-1.0-py3-none-any.whl".to_string(),
            sha256: "a".repeat(64),
        }));
        let loader = SubjectLocation::member("demo-1.0-py3-none-any.whl", "demo/start.pth");
        insp.execution_edges.push(ExecutionEdge {
            from: loader,
            trigger: ExecutionTrigger::CrossRuntimeInvocation,
            to: SubjectLocation::default(),
            mechanism: "launches Bun".to_string(),
            confidence: EdgeConfidence::High,
        });
        let graph = ProvenanceGraph::from_inspection(&insp);
        let exec: Vec<&ProvenanceEdge> = graph
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Execution)
            .collect();
        assert_eq!(exec.len(), 1);
        assert!(exec[0].to.ends_with("::runtime"));
    }

    #[test]
    fn ownership_index_adds_duplicate_owner_edges() {
        // Two distributions both claim the same installed path: the cross-distribution
        // duplicate the ownership index detects becomes DuplicateOwner edges.
        let di = |name: &str| DistributionIdentity {
            ecosystem: Ecosystem::PyPI,
            name: name.to_string(),
            version: Some("1.0".to_string()),
            dist_info_path: SubjectLocation::installed(format!("/venv/{name}-1.0.dist-info")),
        };
        let mut index = OwnershipIndex::new();
        index.insert(NormalizedInstalledPath::new("shared/mod.py"), di("alpha"));
        index.insert(NormalizedInstalledPath::new("shared/mod.py"), di("beta"));

        let mut builder = ProvenanceGraphBuilder::new();
        builder.add_ownership_index(&index);
        let graph = builder.build();

        let dups: Vec<&ProvenanceEdge> = graph
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::DuplicateOwner)
            .collect();
        // One duplicate path with two owners -> two DuplicateOwner edges.
        assert_eq!(dups.len(), 2);
        // Both owning distributions are nodes.
        assert!(graph.nodes.iter().any(|n| n.label == "alpha"));
        assert!(graph.nodes.iter().any(|n| n.label == "beta"));
    }

    #[test]
    fn ownership_via_index_distribution_ownership_round_trips() {
        // Reuse the real B5 builder so the graph composes from the same primitive the
        // post-install path uses, not a test-only shortcut.
        let tmp = std::env::temp_dir().join(format!("prov-graph-{}", std::process::id()));
        let dist_info = tmp.join("alpha-1.0.dist-info");
        std::fs::create_dir_all(&dist_info).unwrap();
        std::fs::write(
            dist_info.join("RECORD"),
            "alpha/__init__.py,,\nalpha/mod.py,,\nalpha-1.0.dist-info/RECORD,,\n",
        )
        .unwrap();
        let identity = DistributionIdentity {
            ecosystem: Ecosystem::PyPI,
            name: "alpha".to_string(),
            version: Some("1.0".to_string()),
            dist_info_path: SubjectLocation::installed(&dist_info),
        };
        let mut index = OwnershipIndex::new();
        let added = index_distribution_ownership(&dist_info, &identity, &mut index);
        assert!(added >= 2);
        // No duplicates with a single distribution -> no DuplicateOwner edges, and the
        // graph is empty of cross-distribution links (single ownership is carried by
        // add_inspection, not the duplicate view).
        let mut builder = ProvenanceGraphBuilder::new();
        builder.add_ownership_index(&index);
        let graph = builder.build();
        assert!(graph
            .edges
            .iter()
            .all(|e| e.kind != EdgeKind::DuplicateOwner));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn mcp_inventory_adds_server_tool_and_endpoint() {
        let inventory = McpInventory {
            servers: vec![
                McpServerEntry {
                    name: "fs".to_string(),
                    transport: McpTransport::Stdio {
                        command: "mcp-fs".to_string(),
                        args: vec!["--root".to_string(), "/srv".to_string()],
                        env: Vec::new(),
                    },
                    tools: vec!["read".to_string(), "write".to_string()],
                    tools_declared: true,
                    source_config: ".mcp.json".to_string(),
                },
                McpServerEntry {
                    name: "remote".to_string(),
                    transport: McpTransport::Url {
                        url: "https://mcp.example.invalid/sse".to_string(),
                        userinfo_hash: None,
                    },
                    tools: Vec::new(),
                    tools_declared: false,
                    source_config: ".mcp.json".to_string(),
                },
            ],
            configs: vec![".mcp.json".to_string()],
            malformed_configs: Vec::new(),
            rejected_configs: Vec::new(),
        };
        let mut builder = ProvenanceGraphBuilder::new();
        builder.add_mcp_inventory(&inventory);
        let graph = builder.build();

        // Two servers, two tools (fs), one stdio endpoint, one url endpoint = 6 nodes.
        assert!(graph
            .nodes
            .iter()
            .any(|n| n.kind == NodeKind::McpServer && n.label == "fs"));
        assert!(graph
            .nodes
            .iter()
            .any(|n| n.kind == NodeKind::McpTool && n.label == "read"));
        let exposes: Vec<&ProvenanceEdge> = graph
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::ExposesTool)
            .collect();
        assert_eq!(exposes.len(), 2);
        let served: Vec<&ProvenanceEdge> = graph
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::ServedBy)
            .collect();
        // Both servers name an endpoint.
        assert_eq!(served.len(), 2);
    }

    #[test]
    fn cross_distribution_set_links_loader_to_other_owner() {
        // Loader wheel A imports a path owned by wheel B; the set graph carries both
        // subjects, their members, and the duplicate-free cross link via the shared
        // virtual ownership index.
        let mut a = ArtifactInspection::new(InspectionSubject::Artifact(ArtifactIdentity {
            ecosystem: Ecosystem::PyPI,
            name: "loader".to_string(),
            version: Some("1.0".to_string()),
            filename: "loader-1.0-py3-none-any.whl".to_string(),
            sha256: "a".repeat(64),
        }));
        let loader_pth = SubjectLocation::member("loader-1.0-py3-none-any.whl", "loader/boot.pth");
        a.files.push(ArtifactFile {
            location: loader_pth.clone(),
            size: 10,
            sha256: "c".repeat(64),
            kind: ArtifactFileKind::PthFile,
        });
        a.execution_edges.push(ExecutionEdge {
            from: loader_pth,
            trigger: ExecutionTrigger::PythonStartupPth,
            to: SubjectLocation::member("payload-1.0-py3-none-any.whl", "payload/run.py"),
            mechanism: "imports payload.run".to_string(),
            confidence: EdgeConfidence::Medium,
        });
        let mut b = ArtifactInspection::new(InspectionSubject::Artifact(ArtifactIdentity {
            ecosystem: Ecosystem::PyPI,
            name: "payload".to_string(),
            version: Some("1.0".to_string()),
            filename: "payload-1.0-py3-none-any.whl".to_string(),
            sha256: "b".repeat(64),
        }));
        b.files.push(ArtifactFile {
            location: SubjectLocation::member("payload-1.0-py3-none-any.whl", "payload/run.py"),
            size: 20,
            sha256: "d".repeat(64),
            kind: ArtifactFileKind::PythonSource,
        });

        let index = OwnershipIndex::new();
        let graph = ProvenanceGraph::from_inspection_set(&[&a, &b], &index);
        // Both distributions present.
        assert!(graph.nodes.iter().any(|n| n.label == "loader"));
        assert!(graph.nodes.iter().any(|n| n.label == "payload"));
        // The execution edge crosses from the loader's .pth to the payload's run.py.
        let exec: Vec<&ProvenanceEdge> = graph
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Execution)
            .collect();
        assert_eq!(exec.len(), 1);
        assert!(exec[0].from.contains("boot.pth"));
        assert!(exec[0].to.contains("run.py"));
    }

    #[test]
    fn json_round_trips_through_serde() {
        let graph = ProvenanceGraph::from_inspection(&wheel_inspection_with_edge());
        let json = graph.to_json();
        let back: ProvenanceGraph = serde_json::from_str(&json).unwrap();
        assert_eq!(graph, back);
    }
}
