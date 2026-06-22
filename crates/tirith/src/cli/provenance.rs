//! `tirith pkg graph` / `tirith env graph`, the provenance-graph CLI surface
//! (PR F1).
//!
//! Both commands COMPOSE already-computed signals into one
//! [`tirith_core::provenance::graph::ProvenanceGraph`] and render it as JSON or
//! Graphviz DOT. They introduce no new detection and never block: the graph is a
//! read model that answers ownership / execution / payload questions.
//!
//! * **`pkg graph <wheels...>`** inspects a set of wheel artifacts (reusing the B8
//!   [`tirith_core::artifact::inspect::inspect_artifact_set`]) and graphs each
//!   wheel's subject, members, and the loader -> payload execution edges, with the
//!   cross-distribution links the set inspection resolves.
//! * **`pkg graph --installed <env>` / `env graph --installed <env>`** discovers
//!   every installed distribution under an environment (reusing the D5
//!   [`tirith_core::artifact::install::discover_installed_distributions`]), builds a
//!   duplicate-aware ownership index across them (the B5
//!   [`tirith_core::artifact::record::index_distribution_ownership`]), and graphs
//!   ownership plus any duplicate-owned path.
//!
//! Either form additionally folds in the repository's MCP surface (the
//! [`tirith_core::mcp_lock::build_inventory`] inventory) when run inside a repo, so
//! the graph also answers "which MCP servers and tools are present here".
//!
//! # What is tested vs. at runtime
//!
//! Inspecting real wheels and walking a real venv is integration territory; the
//! pure seams (the graph composition, the JSON/DOT rendering) are unit-tested in
//! [`tirith_core::provenance::graph`]. This module's logic is the thin glue
//! (discover -> compose -> render); its argument handling and the
//! ownership-index construction over installed distributions have direct tests
//! below.

use std::path::{Path, PathBuf};

use tirith_core::artifact::inspect::inspect_artifact_set;
use tirith_core::artifact::install::discover_installed_distributions;
use tirith_core::artifact::record::{index_distribution_ownership, OwnershipIndex};
use tirith_core::artifact::{ArtifactInspection, DistributionIdentity, InspectionSubject};
use tirith_core::mcp_lock::{build_inventory, McpInventory};
use tirith_core::policy;
use tirith_core::provenance::graph::{ProvenanceGraph, ProvenanceGraphBuilder};

/// How the graph should be rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphFormat {
    /// Human-readable summary (counts + a short node/edge listing).
    Human,
    /// Pretty JSON (the machine surface).
    Json,
    /// Graphviz DOT digraph.
    Dot,
}

impl GraphFormat {
    /// Resolve the format from the `--json` / `--dot` flags (mutually exclusive at
    /// the clap layer; if both somehow arrive, DOT wins as the more specific).
    pub fn resolve(json: bool, dot: bool) -> Self {
        if dot {
            GraphFormat::Dot
        } else if json {
            GraphFormat::Json
        } else {
            GraphFormat::Human
        }
    }
}

/// What the graph command should graph, parsed from the CLI.
#[derive(Debug, Clone)]
pub enum GraphTarget {
    /// Graph a set of wheel artifact files.
    Wheels(Vec<PathBuf>),
    /// Graph an installed environment tree (a venv root or `--target` dir).
    InstalledEnv(PathBuf),
}

/// Entry point for `tirith pkg graph` / `tirith env graph`. Returns a process exit
/// code: `0` on success (a graph was rendered), `2` on a usage error (no wheels and
/// no `--installed`).
pub fn run(target: GraphTarget, format: GraphFormat) -> i32 {
    let graph = match &target {
        GraphTarget::Wheels(paths) => {
            if paths.is_empty() {
                eprintln!(
                    "tirith pkg graph: no wheel paths given, and --installed not set. \
                     try: tirith pkg graph foo.whl   OR   tirith pkg graph --installed .venv"
                );
                return 2;
            }
            build_wheel_graph(paths)
        }
        GraphTarget::InstalledEnv(env) => build_installed_graph(env),
    };

    render(&graph, format);
    0
}

// ---------------------------------------------------------------------------
// Graph construction
// ---------------------------------------------------------------------------

/// Build the graph for a set of wheel files: inspect the set (B8), fold each
/// member's inspection in, build the cross-wheel ownership index from the inspected
/// member files, and add the repo MCP surface.
fn build_wheel_graph(paths: &[PathBuf]) -> ProvenanceGraph {
    let set = inspect_artifact_set(paths);
    let inspections: Vec<&ArtifactInspection> = set
        .members
        .iter()
        .map(|m| &m.inspected.inspection)
        .collect();

    // Build a virtual ownership index across the wheels keyed by member path, so a
    // path two wheels both carry surfaces as a duplicate-owner cross-link. Mirrors
    // the set inspection's own pass-2 keying (member path = the module path a
    // `.pth`/import would name).
    let mut index = OwnershipIndex::new();
    for m in &set.members {
        let Some(dist) =
            wheel_member_distribution_identity(m.path.clone(), &m.inspected.inspection)
        else {
            continue;
        };
        for file in &m.inspected.inspection.files {
            if let Some(member) = &file.location.member_path {
                index.insert(
                    tirith_core::artifact::record::NormalizedInstalledPath::new(member),
                    dist.clone(),
                );
            }
        }
    }

    let mut builder = ProvenanceGraphBuilder::new();
    for inspection in &inspections {
        builder.add_inspection(inspection);
    }
    builder.add_ownership_index(&index);
    add_repo_mcp_surface(&mut builder);
    builder.build()
}

/// The distribution identity for a wheel set member, keyed by its on-disk INPUT
/// path so two same-named wheels in different directories stay distinct. Mirrors the
/// set inspection's own (private) `member_distribution_identity`; reconstructed here
/// rather than widening that internal helper's visibility.
fn wheel_member_distribution_identity(
    path: PathBuf,
    inspection: &ArtifactInspection,
) -> Option<DistributionIdentity> {
    match &inspection.subject {
        InspectionSubject::Artifact(a) => Some(DistributionIdentity {
            ecosystem: a.ecosystem,
            name: a.name.clone(),
            version: a.version.clone(),
            dist_info_path: tirith_core::location::SubjectLocation::from_path(path),
        }),
        _ => None,
    }
}

/// Build the graph for an installed environment: discover every distribution (D5),
/// make an `InstalledDistribution` inspection per distribution, build the
/// duplicate-aware ownership index across them (B5), and add the repo MCP surface.
fn build_installed_graph(env: &Path) -> ProvenanceGraph {
    let dists = discover_installed_distributions(env);

    let mut index = OwnershipIndex::new();
    for (dist_info, identity) in &dists {
        index_distribution_ownership(dist_info, identity, &mut index);
    }

    let mut builder = ProvenanceGraphBuilder::new();
    for (_dist_info, identity) in &dists {
        // An installed distribution carries no source-artifact hash; the inspection
        // subject names it by its `.dist-info` identity. The ownership index supplies
        // the owned-path edges; the per-distribution inspection seeds the node.
        let inspection =
            ArtifactInspection::new(InspectionSubject::InstalledDistribution(identity.clone()));
        builder.add_inspection(&inspection);
    }
    builder.add_ownership_index(&index);
    add_repo_mcp_surface(&mut builder);
    builder.build()
}

/// Fold the repository's MCP surface into the builder, when run inside a repo. A
/// best-effort step: no repo root, or a repo with no MCP config, simply adds
/// nothing. The inventory is the same one `tirith mcp lock` builds.
fn add_repo_mcp_surface(builder: &mut ProvenanceGraphBuilder) {
    if let Some(repo_root) = policy::find_repo_root(None) {
        let inventory: McpInventory = build_inventory(&repo_root);
        builder.add_mcp_inventory(&inventory);
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Render the graph in the requested format to stdout.
fn render(graph: &ProvenanceGraph, format: GraphFormat) {
    match format {
        GraphFormat::Json => {
            println!("{}", graph.to_json());
        }
        GraphFormat::Dot => {
            print!("{}", graph.to_dot());
        }
        GraphFormat::Human => {
            render_human(graph);
        }
    }
}

/// A short human summary: the counts, then each node and edge on one line. Kept
/// terse so it reads in a terminal; `--json` / `--dot` carry the full structure.
fn render_human(graph: &ProvenanceGraph) {
    use tirith_core::provenance::graph::EdgeKind;

    eprintln!(
        "provenance graph: {} nodes, {} edges",
        graph.node_count(),
        graph.edge_count()
    );
    if graph.has_execution_path() {
        eprintln!("  carries an execution path (loader -> payload)");
    }
    for node in &graph.nodes {
        let version = node
            .version
            .as_deref()
            .map(|v| format!(" {v}"))
            .unwrap_or_default();
        eprintln!("  [{:?}] {}{}", node.kind, node.label, version);
    }
    for edge in &graph.edges {
        let arrow = match edge.kind {
            EdgeKind::Execution => "=exec=>",
            EdgeKind::Owns => "-owns->",
            EdgeKind::DuplicateOwner => "=dup=>",
            EdgeKind::ExposesTool => "-tool->",
            EdgeKind::ServedBy => "-via->",
        };
        eprintln!("  {} {} {} ({})", edge.from, arrow, edge.to, edge.detail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_format_resolution() {
        assert_eq!(GraphFormat::resolve(false, false), GraphFormat::Human);
        assert_eq!(GraphFormat::resolve(true, false), GraphFormat::Json);
        assert_eq!(GraphFormat::resolve(false, true), GraphFormat::Dot);
        // DOT wins if both arrive (clap normally makes them exclusive).
        assert_eq!(GraphFormat::resolve(true, true), GraphFormat::Dot);
    }

    #[test]
    fn empty_wheel_set_is_usage_error() {
        let code = run(GraphTarget::Wheels(Vec::new()), GraphFormat::Json);
        assert_eq!(code, 2);
    }

    #[test]
    fn installed_graph_over_real_dist_infos() {
        // Build a minimal env tree with two distributions, one of which duplicates a
        // path the other owns, and confirm the graph composes the ownership + the
        // duplicate-owner cross-link from the SAME B5 primitive the integrity check
        // uses.
        let tmp = std::env::temp_dir().join(format!("prov-cli-{}", std::process::id()));
        let site = tmp.join("lib").join("python3.11").join("site-packages");
        std::fs::create_dir_all(&site).unwrap();

        let write_dist = |name: &str, extra: &str| {
            let di = site.join(format!("{name}-1.0.dist-info"));
            std::fs::create_dir_all(&di).unwrap();
            std::fs::write(
                di.join("RECORD"),
                format!("{name}/__init__.py,,\n{extra}{name}-1.0.dist-info/RECORD,,\n"),
            )
            .unwrap();
        };
        // alpha and beta both list `shared/util.py` -> a duplicate-owned path.
        write_dist("alpha", "shared/util.py,,\n");
        write_dist("beta", "shared/util.py,,\n");

        let graph = build_installed_graph(&tmp);

        // Both distributions appear as nodes.
        assert!(graph.nodes.iter().any(|n| n.label == "alpha"));
        assert!(graph.nodes.iter().any(|n| n.label == "beta"));
        // The shared path is a duplicate-owned file with DuplicateOwner edges.
        use tirith_core::provenance::graph::EdgeKind;
        let dups = graph
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::DuplicateOwner)
            .count();
        assert_eq!(dups, 2, "shared/util.py owned by both alpha and beta");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn installed_graph_empty_env_is_empty_graph() {
        // A directory with no site-packages produces an empty (but valid) graph, not
        // a panic. The repo MCP surface may add nodes when the tests run inside the
        // tirith repo, so assert the absence of distribution nodes specifically.
        let tmp = std::env::temp_dir().join(format!("prov-cli-empty-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let graph = build_installed_graph(&tmp);
        use tirith_core::provenance::graph::NodeKind;
        assert!(
            !graph.nodes.iter().any(|n| n.kind == NodeKind::Distribution),
            "an empty env contributes no distribution nodes"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
