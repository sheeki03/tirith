//! `tirith pkg graph` / `tirith env graph` (PR F1) and `tirith pkg diff` (PR F2),
//! the provenance / release-differential CLI surface over package artifacts.
//!
//! The graph commands COMPOSE already-computed signals into one
//! [`tirith_core::provenance::graph::ProvenanceGraph`] and render it as JSON or
//! Graphviz DOT. They introduce no new detection and never block: the graph is a
//! read model that answers ownership / execution / payload questions.
//!
//! `pkg diff <old.whl> <new.whl>` (F2) is the one verdict-bearing surface here: it
//! differences two versions of the same distribution via
//! [`tirith_core::artifact::release_diff::diff_artifact_files`] (which reuses the
//! same hardened wheel inspection the graph does) and reports the structural deltas
//! that mark a benign release turning malicious. Unlike the graph, it routes the
//! result through the offline operator policy and exits with the verdict's code
//! (Allow `0`, Warn `2`, Block `1`), so a release anomaly is surfaced and a strict
//! policy can escalate it.
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
use tirith_core::artifact::release_diff::{diff_artifact_files, ReleaseDiff, ReleaseDiffError};
use tirith_core::artifact::{ArtifactInspection, DistributionIdentity, InspectionSubject};
use tirith_core::mcp_lock::{build_inventory, McpInventory};
use tirith_core::policy::{self, Policy};
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
// pkg diff (release differential, F2)
// ---------------------------------------------------------------------------

/// Entry point for `tirith pkg diff <old.whl> <new.whl>`. Inspects both wheels
/// (reusing the hardened wheel reader), runs the release differential, evaluates
/// the result under the offline operator policy, and reports the anomalies.
///
/// Returns a process exit code: the verdict's exit code (Allow `0`, Warn `2`,
/// Block `1`) when both wheels inspected, or `2` on a usage / input error (a wheel
/// that could not be inspected). A clean diff (no anomaly) is an Allow, exit `0`.
pub fn run_diff(old: &Path, new: &Path, json: bool) -> i32 {
    let diff = match diff_artifact_files(old, new) {
        Ok(d) => d,
        Err(e) => {
            report_diff_error(&e, json);
            return 2;
        }
    };

    // Evaluate under the offline operator policy (the same discovery the firewall
    // and verify-env use), so a per-rule severity / action override is honored and
    // a repo-scoped policy cannot weaken it.
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    let policy = Policy::discover_local_only(cwd.as_deref());
    let verdict = diff.evaluate(&policy);
    let exit = verdict.action.exit_code();

    if json {
        let out = serde_json::json!({
            "old": old.display().to_string(),
            "new": new.display().to_string(),
            "action": format!("{:?}", verdict.action),
            "anomaly_count": diff.anomalies.len(),
            "anomalies": diff.anomalies,
            "rule_ids": verdict
                .findings
                .iter()
                .map(|f| f.rule_id.to_string())
                .collect::<Vec<_>>(),
        });
        let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), &out);
        println!();
    } else {
        render_diff_human(old, new, &diff, &verdict);
    }

    exit
}

/// Report a release-diff input error (a wheel that could not be inspected) in the
/// requested format.
fn report_diff_error(err: &ReleaseDiffError, json: bool) {
    if json {
        let out = serde_json::json!({
            "error": err.to_string(),
        });
        let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), &out);
        println!();
    } else {
        eprintln!("tirith pkg diff: {err}");
        eprintln!(
            "  both artifacts must be inspectable wheels; try: tirith pkg diff old.whl new.whl"
        );
    }
}

/// Render the release diff as a short human summary to stderr: the verdict, the
/// anomaly count, and each anomaly's kind + detail.
fn render_diff_human(
    old: &Path,
    new: &Path,
    diff: &ReleaseDiff,
    verdict: &tirith_core::verdict::Verdict,
) {
    eprintln!("tirith pkg diff: {} -> {}", old.display(), new.display());
    eprintln!("  verdict:  {:?}", verdict.action);
    if diff.anomalies.is_empty() {
        eprintln!("  no release anomaly: the two releases have the same execution shape");
        return;
    }
    eprintln!("  {} release anomaly(ies):", diff.anomalies.len());
    for anomaly in &diff.anomalies {
        eprintln!("    [{}] {}", anomaly.kind.label(), anomaly.detail);
    }
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

    // -----------------------------------------------------------------------
    // pkg diff (F2)
    // -----------------------------------------------------------------------

    use std::io::Write as _;

    /// Write a minimal `demo` wheel (version `ver`) carrying the EXTRA members
    /// beyond dist-info, with a correct RECORD, to `<dir>/<filename>`, and return
    /// the path. Mirrors the core release_diff I/O test helper.
    fn write_demo_wheel(dir: &Path, ver: &str, extra: &[(&str, &[u8])]) -> PathBuf {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        use zip::write::SimpleFileOptions;
        use zip::ZipWriter;

        let cell = |body: &[u8]| {
            let mut h = Sha256::new();
            h.update(body);
            format!(
                "sha256={}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize())
            )
        };

        let metadata =
            format!("Metadata-Version: 2.1\nName: demo\nVersion: {ver}\n\n").into_bytes();
        let wheel =
            b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
                .to_vec();
        let mut record = format!(
            "demo-{ver}.dist-info/METADATA,{},{}\ndemo-{ver}.dist-info/WHEEL,{},{}\n",
            cell(&metadata),
            metadata.len(),
            cell(&wheel),
            wheel.len(),
        );
        for (name, body) in extra {
            record.push_str(&format!("{},{},{}\n", name, cell(body), body.len()));
        }
        record.push_str(&format!("demo-{ver}.dist-info/RECORD,,\n"));

        let mut members: Vec<(String, Vec<u8>)> = vec![
            (format!("demo-{ver}.dist-info/METADATA"), metadata),
            (format!("demo-{ver}.dist-info/WHEEL"), wheel),
        ];
        for (name, body) in extra {
            members.push((name.to_string(), body.to_vec()));
        }
        members.push((format!("demo-{ver}.dist-info/RECORD"), record.into_bytes()));

        let mut zw = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, body) in &members {
            zw.start_file(name.as_str(), SimpleFileOptions::default())
                .unwrap();
            zw.write_all(body).unwrap();
        }
        let bytes = zw.finish().unwrap().into_inner();
        let path = dir.join(format!("demo-{ver}-py3-none-any.whl"));
        std::fs::write(&path, &bytes).unwrap();
        path
    }

    /// `pkg diff` over a pure->native release returns the warn exit code (2): the
    /// release anomaly is surfaced, not blocked, under the default operator policy.
    #[test]
    fn run_diff_pure_to_native_warns() {
        let dir = tempfile::tempdir().unwrap();
        let old = write_demo_wheel(dir.path(), "1.0", &[("demo/__init__.py", b"x = 1\n")]);
        let so: &[u8] = b"\x7fELF\x02\x01\x01\x00 tiny native body";
        let new = write_demo_wheel(
            dir.path(),
            "1.1",
            &[("demo/__init__.py", b"x = 1\n"), ("demo/_speed.so", so)],
        );
        // JSON form so nothing is written to stderr in the test output.
        let code = run_diff(&old, &new, true);
        assert_eq!(code, 2, "a release anomaly warns (exit 2)");
    }

    /// `pkg diff` over an honest point release (same shape) returns 0.
    #[test]
    fn run_diff_clean_release_is_zero() {
        let dir = tempfile::tempdir().unwrap();
        let old = write_demo_wheel(dir.path(), "1.0", &[("demo/__init__.py", b"x = 1\n")]);
        let new = write_demo_wheel(dir.path(), "1.1", &[("demo/__init__.py", b"x = 2\n")]);
        let code = run_diff(&old, &new, true);
        assert_eq!(code, 0, "a clean diff is an Allow (exit 0)");
    }

    /// `pkg diff` with an uninspectable input is a usage error (exit 2), not a
    /// panic.
    #[test]
    fn run_diff_bad_input_is_usage_error() {
        let dir = tempfile::tempdir().unwrap();
        let new = write_demo_wheel(dir.path(), "1.1", &[("demo/__init__.py", b"x = 1\n")]);
        let missing = dir.path().join("nope.whl");
        let code = run_diff(&missing, &new, true);
        assert_eq!(code, 2);
    }
}
