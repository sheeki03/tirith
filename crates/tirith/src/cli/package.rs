//! `tirith package risk|explain|scan` — provenance / maintainer-risk scoring
//! for a package, scored like `tirith score` scores a URL: a deterministic,
//! fully explainable sum of named factors.
//!
//! `tirith package scan` is a thin wrapper over [`super::ecosystem::scan`] (the
//! engine is `tirith_core::ecosystem_scan::scan`); a byte-identical-JSON test
//! pins that one engine serves both CLIs.
//!
//! Offline by default (threat-DB name signals + on-disk content only).
//! `--online` additionally consults the registry API (npm/PyPI/crates.io) for
//! provenance — the ONLY networked path, never the `check` hot path.
//! `--offline` / `TIRITH_OFFLINE` forces offline; a registry failure degrades to
//! the offline score with an honest `api signals: unavailable (reason)`.

use std::path::{Path, PathBuf};

use tirith_core::package_risk::{
    self, ApiProvenance, ApiSignals, ContentSignals, NameVsPopular, PackageSignals, RiskBreakdown,
};
use tirith_core::registry_api::{self, HttpRegistryClient, RegistryClient};
use tirith_core::threatdb::{Ecosystem, ThreatDb};

/// Run `tirith package scan` — a thin wrapper over [`super::ecosystem::scan`]
/// (same engine; a byte-identical-JSON test in `cli_integration.rs` pins it).
///
/// `installed` and `lockfile` are mutually exclusive (clap-enforced); with
/// neither set and no `path`, defaults to `--installed` against cwd.
/// `max_installed_entries` caps the walk; `non_interactive` suppresses the
/// `--installed --online` network-call prompt.
#[allow(clippy::too_many_arguments)]
pub fn scan(
    installed: bool,
    lockfile: Option<&Path>,
    path: Option<&Path>,
    online: bool,
    offline: bool,
    max_installed_entries: usize,
    non_interactive: bool,
    json: bool,
) -> i32 {
    // Resolve the scan target. Precedence: --lockfile, then --installed (under
    // cwd unless `path` overrides), then a positional path, else --installed
    // against cwd.
    let (effective_path, effective_installed): (PathBuf, bool) = match (lockfile, installed, path) {
        (Some(lock), false, None) => (lock.to_path_buf(), false),
        (None, true, None) => (
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            true,
        ),
        (None, true, Some(p)) => (p.to_path_buf(), true),
        (None, false, Some(p)) => (p.to_path_buf(), false),
        (None, false, None) => (
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            true,
        ),
        (Some(_), true, _) => {
            // Defense in depth — clap's `conflicts_with` should block this.
            eprintln!("tirith package scan: --installed and --lockfile are mutually exclusive.");
            return 2;
        }
        (Some(_), false, Some(_)) => {
            // --lockfile + --path: reject explicitly so no input is dropped.
            eprintln!("tirith package scan: --lockfile and --path are mutually exclusive.");
            return 2;
        }
    };

    // Fail fast on a non-UTF-8 path rather than letting `ecosystem::scan`'s
    // `Option<&str>` silently drop it and fall back to cwd.
    let effective_path_str = match effective_path.to_str() {
        Some(s) => s,
        None => {
            eprintln!(
                "tirith package scan: path {:?} is not valid UTF-8; \
                 tirith can scan UTF-8 paths only.",
                effective_path.display()
            );
            return 2;
        }
    };

    super::ecosystem::scan(
        Some(effective_path_str),
        online,
        offline,
        effective_installed,
        max_installed_entries,
        non_interactive,
        json,
    )
}

/// Run `tirith package inspect` — the VERDICT-oriented artifact / installed
/// inspector (B8b). Unlike `risk`/`explain` (advisory scorers that always exit 0),
/// this exits scan-style: 0 clean, 1 a block-grade finding, 2 an advisory (warn)
/// finding, 2 on a usage error.
///
/// Modes (mutually exclusive at the CLI):
/// * one or more `--artifact <file>` — inspect each wheel; with two or more, also
///   correlate a cross-distribution loader/payload split across them (B8c);
/// * `--artifact-set <dir>` — inspect every `.whl` in a directory as a set;
/// * `--installed <dir>` — inspect an installed environment (routes through the
///   `ecosystem scan --installed` engine, which already runs B5/B6/B7 and the
///   multi-wheel cross-distribution correlation, B8e).
pub fn inspect(
    artifacts: &[PathBuf],
    artifact_set: Option<&Path>,
    installed: Option<&Path>,
    json: bool,
) -> i32 {
    // Exactly one mode must be selected. clap marks `--artifact-set`/`--installed`
    // mutually exclusive; guard the combinations clap cannot express.
    let mode_count =
        (!artifacts.is_empty()) as u8 + artifact_set.is_some() as u8 + installed.is_some() as u8;
    if mode_count == 0 {
        eprintln!(
            "tirith package inspect: nothing to inspect. Pass --artifact <file> \
             (repeatable), --artifact-set <dir>, or --installed <dir>."
        );
        return 2;
    }
    if mode_count > 1 {
        eprintln!(
            "tirith package inspect: choose ONE of --artifact, --artifact-set, or --installed."
        );
        return 2;
    }

    if let Some(venv) = installed {
        return inspect_installed(venv, json);
    }

    // Resolve the artifact paths to inspect (explicit list, or every `.whl` in the
    // set directory).
    let paths: Vec<PathBuf> = if let Some(dir) = artifact_set {
        match collect_set_wheels(dir) {
            Ok(p) => p,
            Err(code) => return code,
        }
    } else {
        artifacts.to_vec()
    };

    inspect_artifacts(&paths, json)
}

/// Inspect an installed environment by routing through the `ecosystem scan
/// --installed` engine (B8e: it already runs B5/B6/B7 and the cross-distribution
/// ownership correlation, surfaces the `InstalledIntegrityReport`, and folds the
/// findings into the verdict / exit code).
fn inspect_installed(venv: &Path, json: bool) -> i32 {
    let Some(path_str) = venv.to_str() else {
        eprintln!(
            "tirith package inspect: path {:?} is not valid UTF-8; tirith inspects UTF-8 paths only.",
            venv.display()
        );
        return 2;
    };
    super::ecosystem::scan(
        Some(path_str),
        /* online = */ false,
        /* offline = */ true,
        /* installed = */ true,
        /* max_installed_entries = */ 5000,
        /* non_interactive = */ true,
        json,
    )
}

/// Collect every `.whl` in `dir` (non-recursive) for `--artifact-set`. Returns an
/// exit code on a usage error (a missing/unreadable directory, or no wheels).
fn collect_set_wheels(dir: &Path) -> Result<Vec<PathBuf>, i32> {
    if !dir.is_dir() {
        eprintln!(
            "tirith package inspect: --artifact-set path is not a directory: {}",
            dir.display()
        );
        return Err(2);
    }
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!(
                "tirith package inspect: cannot read --artifact-set directory {}: {e}",
                dir.display()
            );
            return Err(2);
        }
    };
    let mut wheels: Vec<PathBuf> = rd
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            // `is_file()` FOLLOWS symlinks: a symlinked `.whl` would pass here, then the
            // no-follow reader rejects it downstream into `gaps`, leaving `members` empty and
            // the command exiting 0 (Allow). Require a REAL regular file so an all-symlink set
            // directory correctly exits 2 ("no .whl files found").
            p.is_file()
                && !p.is_symlink()
                && p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("whl"))
        })
        .collect();
    wheels.sort();
    if wheels.is_empty() {
        eprintln!(
            "tirith package inspect: no .whl files found in --artifact-set directory {}",
            dir.display()
        );
        return Err(2);
    }
    Ok(wheels)
}

/// Inspect a list of artifact paths (a single wheel, or a set for
/// cross-distribution correlation), print the verdict, and return a scan-style
/// exit code.
fn inspect_artifacts(paths: &[PathBuf], json: bool) -> i32 {
    use tirith_core::artifact::inspect::inspect_artifact_set;
    use tirith_core::verdict::Action;

    // Validate each path exists up front so a typo is a usage error (exit 2), not a
    // silent coverage gap.
    for p in paths {
        if !p.exists() {
            eprintln!(
                "tirith package inspect: artifact not found: {}",
                p.display()
            );
            return 2;
        }
        // A path that EXISTS but is not a REGULAR file (a symlink, directory, fifo, ...) would
        // be rejected by the no-follow reader downstream into `gaps`, leaving `members` empty
        // and the command exiting 0 (Allow) as if clean. Treat it as a usage error (exit 2).
        if !p.is_file() || p.is_symlink() {
            eprintln!(
                "tirith package inspect: artifact is not a regular file: {}",
                p.display()
            );
            return 2;
        }
    }

    // The set inspector handles BOTH a single artifact and a set: pass 1 inspects
    // each independently, pass 2 correlates cross-distribution splits (a no-op for a
    // single artifact). The threat DB is threaded for the (feature-gated)
    // known-malicious hash check.
    let db = ThreatDb::cached();
    let set = inspect_artifact_set(paths);

    // Discover the operator policy from the first artifact's directory so a strict
    // integrity policy's overrides are honored on this verdict site too.
    let policy_root = paths
        .first()
        .and_then(|p| p.parent())
        .map(|p| p.display().to_string());
    let policy = tirith_core::policy::Policy::discover(policy_root.as_deref());

    let findings = set.all_findings(db.as_deref());
    let mut verdict = tirith_core::escalation::finalize_static_verdict(
        findings,
        &policy,
        3,
        tirith_core::verdict::Timings::default(),
    );

    // A structurally REJECTED artifact (path traversal, duplicate-path collision, an
    // encrypted member, a CRC mismatch) is a hard archive violation that `all_findings`
    // (B5/B6/B7 signal correlation) does NOT see. Force Block AND synthesize a
    // WheelStructurallyRejected finding (carrying the violation details) for each rejected
    // member, so `findings` is non-empty whenever the action is Block due to a rejection:
    // a CI consumer gating on `findings.length` (not only the action, exit code, or the
    // nested `rejected`/`violations` fields) must not pass a path-traversal wheel.
    for m in set.members.iter().filter(|m| m.inspected.rejected) {
        verdict.action = Action::Block;
        let detail = if m.inspected.violation_details.is_empty() {
            "structural archive violation".to_string()
        } else {
            m.inspected.violation_details.join("; ")
        };
        verdict.findings.push(tirith_core::verdict::Finding {
            rule_id: tirith_core::verdict::RuleId::WheelStructurallyRejected,
            severity: tirith_core::verdict::Severity::High,
            title: "Wheel structurally rejected".to_string(),
            description: format!("{}: {}", m.path.display(), detail),
            evidence: Vec::new(),
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }

    // The verdict's own exit code, computed up front so a write failure can preserve it.
    let code = match verdict.action {
        Action::Block => 1,
        Action::Warn | Action::WarnAck => 2,
        Action::Allow => 0,
    };

    let output_ok = if json {
        print_inspect_json(&set, &verdict)
    } else {
        print_inspect_human(&set, &verdict);
        true
    };

    // A write failure must not DOWNGRADE a Warn (2) into a block-grade 1, nor pass a
    // clean scan off as success: surface the verdict's own non-zero code, or 1 when the
    // scan was clean (mirrors the ecosystem.rs write-failure path).
    if !output_ok {
        return if code == 0 { 1 } else { code };
    }
    code
}

/// JSON output for `package inspect`: the verdict (with member-qualified finding
/// locations carried in evidence) plus per-artifact coverage and the
/// cross-distribution findings. Returns `false` on a write failure.
fn print_inspect_json(
    set: &tirith_core::artifact::inspect::ArtifactSetInspection,
    verdict: &tirith_core::verdict::Verdict,
) -> bool {
    #[derive(serde::Serialize)]
    struct JsonOut<'a> {
        schema_version: u32,
        action: String,
        artifacts: Vec<JsonArtifact<'a>>,
        coverage_gaps: Vec<JsonGap>,
        // The single authoritative finding list (post `action_overrides` escalation), via
        // `set.all_findings` which already appends the cross-distribution findings. A
        // separate raw `cross_distribution_findings` field was removed: it duplicated each
        // cross finding here with its PRE-escalation severity, so a consumer saw the same
        // finding twice with conflicting severities and no authoritative one.
        findings: &'a [tirith_core::verdict::Finding],
    }
    #[derive(serde::Serialize)]
    struct JsonArtifact<'a> {
        path: String,
        rejected: bool,
        #[serde(skip_serializing_if = "<[_]>::is_empty")]
        violations: &'a [String],
        inspection: &'a tirith_core::artifact::ArtifactInspection,
    }
    #[derive(serde::Serialize)]
    struct JsonGap {
        location: String,
        kind: &'static str,
    }

    let artifacts: Vec<JsonArtifact> = set
        .members
        .iter()
        .map(|m| JsonArtifact {
            path: m.path.display().to_string(),
            rejected: m.inspected.rejected,
            violations: &m.inspected.violation_details,
            inspection: &m.inspected.inspection,
        })
        .collect();

    let out = JsonOut {
        schema_version: 1,
        action: format!("{:?}", verdict.action).to_lowercase(),
        artifacts,
        coverage_gaps: set
            .gaps
            .iter()
            .map(|g| JsonGap {
                location: g.location.to_string(),
                kind: g.kind.as_str(),
            })
            .collect(),
        findings: &verdict.findings,
    };
    super::write_json_stdout(&out, "tirith package inspect: failed to write JSON output")
}

/// Human output for `package inspect`: a per-artifact summary to stderr and the
/// findings (member-qualified) to stdout, mirroring the `tirith scan` convention.
fn print_inspect_human(
    set: &tirith_core::artifact::inspect::ArtifactSetInspection,
    verdict: &tirith_core::verdict::Verdict,
) {
    eprintln!(
        "tirith package inspect: {} artifact(s) inspected",
        set.members.len()
    );
    for m in &set.members {
        let status = if m.inspected.rejected {
            " [REJECTED: structural violation]"
        } else {
            ""
        };
        eprintln!("  {}{status}", m.path.display());
        for v in &m.inspected.violation_details {
            eprintln!("    - {v}");
        }
    }
    for gap in &set.gaps {
        eprintln!("  not inspected: {} ({})", gap.location, gap.kind.as_str());
    }

    if verdict.findings.is_empty() {
        eprintln!();
        eprintln!("  no artifact risks found.");
        return;
    }

    println!();
    println!("Artifact findings:");
    for finding in &verdict.findings {
        let sev = tirith_core::style::severity_label(
            &finding.severity,
            tirith_core::style::Stream::Stdout,
        );
        println!("  {} {} — {}", sev, finding.rule_id, finding.title);
        // Surface the member-qualified location lines from the evidence so a
        // reviewer sees `foo.whl!/member`, not just the outer wheel.
        for ev in &finding.evidence {
            if let tirith_core::verdict::Evidence::Text { detail } = ev {
                if detail.starts_with("location:") || detail.contains("!/") {
                    println!("    {detail}");
                }
            }
        }
    }
}

/// Run `tirith package risk <ecosystem> <name>`. Prints the deterministic risk
/// score; `path` optionally points at local package content to inspect (else
/// auto-discovered under `node_modules`/`site-packages`). `online` opts into
/// registry provenance; `offline`/`TIRITH_OFFLINE` forces offline.
pub fn risk(
    ecosystem: &str,
    name: &str,
    path: Option<&str>,
    online: bool,
    offline: bool,
    json: bool,
) -> i32 {
    run(
        ecosystem, name, path, online, offline, json, /* explain = */ false,
    )
}

/// Run `tirith package explain <ecosystem> <name>` — the factor-by-factor
/// derivation of the same score (mirrors `tirith score --explain`).
pub fn explain(
    ecosystem: &str,
    name: &str,
    path: Option<&str>,
    online: bool,
    offline: bool,
    json: bool,
) -> i32 {
    run(
        ecosystem, name, path, online, offline, json, /* explain = */ true,
    )
}

#[allow(clippy::too_many_arguments)]
fn run(
    ecosystem: &str,
    name: &str,
    path: Option<&str>,
    online: bool,
    offline: bool,
    json: bool,
    explain: bool,
) -> i32 {
    let Some(eco) = Ecosystem::from_name(ecosystem) else {
        eprintln!(
            "tirith package: unknown ecosystem '{ecosystem}'. \
             Known: npm, pypi, rubygems, crates.io, go, maven, nuget, packagist."
        );
        return 2;
    };

    let trimmed_name = name.trim();
    if trimmed_name.is_empty() {
        eprintln!("tirith package: package name must not be empty.");
        return 2;
    }

    // M6 ch6 — `<name>[@<version>]` parsing; version flows into the signals so
    // OSV can match a version-pinned advisory (bare `<name>` → version `None`).
    let (parsed_name, parsed_version) = package_risk::parse_name_and_version(trimmed_name);
    if parsed_name.is_empty() {
        eprintln!("tirith package: package name must not be empty.");
        return 2;
    }

    let db = ThreatDb::cached();
    let threat_db_missing = db.is_none();

    // Name signals — from the local threat DB only.
    let name_vs_popular = package_risk::classify_name(db.as_deref(), eco, &parsed_name);
    let malicious_typosquat_of = db
        .as_deref()
        .and_then(|db| db.check_typosquat(eco, &parsed_name))
        .map(|ts| ts.target_name);

    // Content signals — local content only; tirith never downloads to get these.
    let content_signals = gather_content_signals(eco, &parsed_name, path);

    // Registry-API signals — only with `--online` and offline not in force.
    // `gather_api` is offline-safe (NotComputed for an intentional skip,
    // Unavailable on a real failure).
    let api = if online {
        let client = HttpRegistryClient::new();
        gather_api(
            &client,
            eco,
            &parsed_name,
            parsed_version.as_deref(),
            offline,
        )
    } else {
        ApiSignals::offline()
    };

    let signals = PackageSignals {
        ecosystem: eco,
        name: parsed_name,
        version: parsed_version,
        threat_db_missing,
        name_vs_popular,
        malicious_typosquat_of,
        content_signals,
        api,
    };

    // `score_package` asserts the factor-sum invariant itself.
    let breakdown = package_risk::score_package(&signals);

    if json {
        // A JSON-write failure → exit non-zero so a piped consumer doesn't treat
        // truncated JSON as success.
        if !print_json(&breakdown, explain) {
            return 1;
        }
    } else {
        print_human(&breakdown, explain);
    }
    0
}

// registry-API signals (opt-in, networked)

/// Gather registry-API provenance signals using `client`. With `offline_flag`
/// (or `TIRITH_OFFLINE`) set this is a no-op returning [`ApiSignals::NotComputed`]
/// WITHOUT any network call — `NotComputed` (not `Unavailable`) because the
/// lookup was intentionally skipped, not attempted-and-failed. Otherwise
/// delegates to [`registry_api::gather_api_signals`], which degrades failures
/// gracefully; never panics, hangs, or blocks. `client` is a trait object so
/// tests inject a fake.
fn gather_api(
    client: &dyn RegistryClient,
    eco: Ecosystem,
    name: &str,
    version: Option<&str>,
    offline_flag: bool,
) -> ApiSignals {
    if offline_flag || super::offline_env_active() {
        return ApiSignals::NotComputed {
            reason: "offline mode is active (--offline / TIRITH_OFFLINE) — \
                     registry-API signals were intentionally skipped, scored \
                     with offline signals only"
                .to_string(),
        };
    }
    // M6 ch6 — fold the `(ApiSignals, PackageExistence)` pair back into a single
    // `ApiSignals`. On a failed call with a positive `NotFound`, upgrade to an
    // Available provenance carrying the existence so the policy gate reads it.
    let (mut signals, existence) = registry_api::gather_api_signals(client, eco, name);
    use tirith_core::package_risk::{ApiProvenance, PackageExistence};

    let nf = matches!(existence, PackageExistence::NotFound);
    if let ApiSignals::Available { provenance } = &mut signals {
        provenance.package_existence = existence;
        // Snapshot-store write — reuses the fetched response, no extra call.
        let _ = tirith_core::registry_history::record_snapshot(eco, name, provenance);
        // Diff vs the previous snapshot. `diff_and_transfer_recent` returns the
        // transfer ONLY when no original maintainer survives (a full takeover),
        // which is the honest signal `ownership_transfer` carries.
        if let Some((history, transfer)) =
            tirith_core::registry_history::diff_and_transfer_recent(eco, name)
        {
            provenance.maintainer_change_history = Some(history);
            if let Some(t) = transfer {
                provenance.ownership_transfer = Some(t);
            }
        }
        // OSV correlation (needs a version). Capture `OsvLookupState` so the
        // explainer distinguishes "no advisories" from "check unavailable".
        if let Some(v) = version {
            let result = tirith_core::osv_correlation::for_package_with_state(eco, name, v);
            provenance.osv_state = result.state;
            if !result.advisories.is_empty() {
                provenance.osv_advisories = Some(result.advisories);
            }
        }
        // Dep-confusion (offline-safe heuristic).
        let policy = tirith_core::policy::Policy::discover(None);
        let dc = tirith_core::dep_confusion::evaluate(eco, name, &policy);
        if dc.risk {
            provenance.dep_confusion = Some(dc);
        }
        // Repo-mismatch — online-only, only for known git hosts.
        if let Some(repo_url) = provenance.repository_url_for_check() {
            let rm = tirith_core::repo_mismatch::verify(&repo_url, eco, name);
            provenance.repo_mismatch = Some(rm);
        }
    } else if nf {
        let mut prov = ApiProvenance {
            source: eco.to_string(),
            package_existence: PackageExistence::NotFound,
            ..Default::default()
        };
        let policy = tirith_core::policy::Policy::discover(None);
        let dc = tirith_core::dep_confusion::evaluate(eco, name, &policy);
        if dc.risk {
            prov.dep_confusion = Some(dc);
        }
        // No OSV correlation / snapshot for a nonexistent package (incoherent).
        let _ = version;
        signals = ApiSignals::Available { provenance: prov };
    }
    signals
}

// content inspection (offline, filesystem-only)

/// The per-ecosystem directory a package's content lives under, for cwd-relative
/// auto-discovery. `None` for ecosystems with no safe conventional layout
/// (explicit `--path` still works).
fn ecosystem_content_root(eco: Ecosystem) -> Option<&'static str> {
    match eco {
        Ecosystem::Npm => Some("node_modules"),
        Ecosystem::PyPI => Some("site-packages"),
        _ => None,
    }
}

/// Gather install-script / binary-blob signals from local content: an explicit
/// `--path` (error if missing), else auto-discovered `<content-root>/<name>`
/// under cwd, else [`ContentSignals::NotInspected`]. Only ever reads a directory
/// the user already has; never fetches.
fn gather_content_signals(
    eco: Ecosystem,
    name: &str,
    explicit_path: Option<&str>,
) -> ContentSignals {
    let dir: Option<PathBuf> = match explicit_path {
        Some(p) => {
            let pb = PathBuf::from(p);
            if !pb.exists() {
                eprintln!(
                    "tirith package: --path '{p}' does not exist; \
                     scoring with name signals only."
                );
                None
            } else {
                Some(pb)
            }
        }
        None => discover_local_package(eco, name),
    };

    let Some(dir) = dir else {
        return ContentSignals::NotInspected;
    };

    let (has_install_script, install_script_detail) = detect_install_script(eco, &dir);
    let (has_binary_blob, binary_blob_detail) = detect_binary_blob(&dir);

    ContentSignals::Inspected {
        path: dir.display().to_string(),
        has_install_script,
        install_script_detail,
        has_binary_blob,
        binary_blob_detail,
    }
}

/// Auto-discover a package directory under the cwd's conventional content root.
fn discover_local_package(eco: Ecosystem, name: &str) -> Option<PathBuf> {
    let root = ecosystem_content_root(eco)?;
    let cwd = std::env::current_dir().ok()?;
    let candidate = cwd.join(root).join(name);
    if candidate.is_dir() {
        Some(candidate)
    } else {
        None
    }
}

/// Detect an install/lifecycle hook: npm `package.json` with a non-empty
/// `(pre|post)install`/`install` script, or a PyPI `setup.py`. Other ecosystems
/// are not inspected in this phase.
fn detect_install_script(eco: Ecosystem, dir: &Path) -> (bool, Option<String>) {
    match eco {
        Ecosystem::Npm => detect_npm_install_script(dir),
        Ecosystem::PyPI => {
            if dir.join("setup.py").is_file() {
                (
                    true,
                    Some("a setup.py (runs arbitrary Python at install time)".to_string()),
                )
            } else {
                (false, None)
            }
        }
        _ => (false, None),
    }
}

/// Read `package.json` and report whether any install lifecycle hook is set.
fn detect_npm_install_script(dir: &Path) -> (bool, Option<String>) {
    let manifest = dir.join("package.json");
    let Ok(text) = std::fs::read_to_string(&manifest) else {
        return (false, None);
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        return (false, None);
    };
    let Some(scripts) = json.get("scripts").and_then(|s| s.as_object()) else {
        return (false, None);
    };
    let mut hooks: Vec<&str> = Vec::new();
    for hook in ["preinstall", "install", "postinstall"] {
        if scripts
            .get(hook)
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
        {
            hooks.push(hook);
        }
    }
    if hooks.is_empty() {
        (false, None)
    } else {
        (
            true,
            Some(format!(
                "an npm {} lifecycle script in package.json",
                hooks.join(" / ")
            )),
        )
    }
}

/// Native/compiled artifact extensions (lowercased, leading dot) — opaque code
/// that can't be reviewed as source.
const BINARY_BLOB_EXTENSIONS: &[&str] = &[
    ".so", ".dll", ".dylib", ".node", ".wasm", ".a", ".lib", ".o", ".obj", ".exe", ".bin", ".dex",
    ".class", ".jar", ".pyd",
];

/// Detect bundled binary blobs by walking the package directory for known
/// native/compiled extensions. Bounded; reads file names only.
fn detect_binary_blob(dir: &Path) -> (bool, Option<String>) {
    // Cap the walk so a pathological tree can't stall the command.
    const MAX_ENTRIES: usize = 20_000;
    let mut examined = 0usize;
    let mut found: Vec<String> = Vec::new();

    for entry in walkdir::WalkDir::new(dir)
        .max_depth(8)
        .into_iter()
        .filter_map(Result::ok)
    {
        examined += 1;
        if examined > MAX_ENTRIES {
            break;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let fname = entry.file_name().to_string_lossy().to_lowercase();
        if let Some(ext) = BINARY_BLOB_EXTENSIONS
            .iter()
            .find(|ext| fname.ends_with(*ext))
        {
            if !found.iter().any(|f| f == ext) {
                found.push((*ext).to_string());
            }
            // Three distinct kinds is plenty for the human summary.
            if found.len() >= 3 {
                break;
            }
        }
    }

    if found.is_empty() {
        (false, None)
    } else {
        (
            true,
            Some(format!("bundled compiled artifacts ({})", found.join(", "))),
        )
    }
}

/// Emit the breakdown as JSON. `false` on a write failure so the caller exits
/// non-zero (a piped consumer must not see truncated JSON with success).
fn print_json(breakdown: &RiskBreakdown, explain: bool) -> bool {
    #[derive(serde::Serialize)]
    struct PackageRiskOutput<'a> {
        ecosystem: &'a str,
        name: &'a str,
        score: u32,
        risk_level: &'a str,
        threat_db_missing: bool,
        name_vs_popular: &'a NameVsPopular,
        #[serde(skip_serializing_if = "Option::is_none")]
        malicious_typosquat_of: Option<&'a str>,
        content_signals: &'a ContentSignals,
        api_signals: &'a ApiSignals,
        /// Full factor breakdown — present only with `explain`.
        #[serde(skip_serializing_if = "Option::is_none")]
        risk_breakdown: Option<&'a RiskBreakdown>,
    }

    let out = PackageRiskOutput {
        ecosystem: &breakdown.ecosystem,
        name: &breakdown.name,
        score: breakdown.score,
        risk_level: breakdown.risk_level,
        threat_db_missing: breakdown.threat_db_missing,
        name_vs_popular: &breakdown.name_vs_popular,
        malicious_typosquat_of: breakdown.malicious_typosquat_of.as_deref(),
        content_signals: &breakdown.content_signals,
        api_signals: &breakdown.api_signals,
        risk_breakdown: if explain { Some(breakdown) } else { None },
    };
    super::write_json_stdout(&out, "tirith package: failed to write JSON output")
}

fn print_human(breakdown: &RiskBreakdown, explain: bool) {
    println!(
        "tirith package risk: {} package '{}'",
        breakdown.ecosystem, breakdown.name
    );
    println!(
        "  risk score:  {}/100 ({})",
        breakdown.score, breakdown.risk_level
    );

    match &breakdown.name_vs_popular {
        NameVsPopular::KnownPopular => {
            println!("  name:        known-popular package (recognized)");
        }
        NameVsPopular::NearPopular {
            popular_name,
            distance,
        } => {
            println!(
                "  name:        edit-distance {distance} from popular package '{popular_name}' \
                 — possible typosquat/slopsquat"
            );
        }
        NameVsPopular::Unknown => {
            if breakdown.threat_db_missing {
                println!(
                    "  name:        unknown — threat DB not installed, \
                     popular-package comparison skipped"
                );
            } else {
                println!("  name:        not a known-popular package, and no near-miss");
            }
        }
    }

    if let Some(target) = &breakdown.malicious_typosquat_of {
        println!("  threat DB:   listed as a known malicious typosquat of '{target}'");
    }

    match &breakdown.content_signals {
        ContentSignals::NotInspected => {
            println!(
                "  content:     not inspected (no local package directory — \
                 pass --path to inspect install scripts and binary blobs)"
            );
        }
        ContentSignals::Inspected {
            path,
            has_install_script,
            install_script_detail,
            has_binary_blob,
            binary_blob_detail,
        } => {
            println!("  content:     inspected {path}");
            match (has_install_script, install_script_detail) {
                (true, Some(d)) => println!("               - install script: {d}"),
                (true, None) => println!("               - install script: present"),
                (false, _) => println!("               - install script: none"),
            }
            match (has_binary_blob, binary_blob_detail) {
                (true, Some(d)) => println!("               - binary blob: {d}"),
                (true, None) => println!("               - binary blob: present"),
                (false, _) => println!("               - binary blob: none"),
            }
        }
    }

    // API-signal seam — always reported so the offline/online scope is explicit.
    match &breakdown.api_signals {
        ApiSignals::NotComputed { reason } => {
            println!("  api signals: not computed — {reason}");
        }
        ApiSignals::Unavailable { reason } => {
            println!("  api signals: unavailable — {reason}");
        }
        ApiSignals::Available { provenance } => {
            print_api_provenance_human(provenance);
        }
    }

    if explain {
        print_breakdown_human(breakdown);
    } else {
        println!(
            "  Run 'tirith package explain {} {}' for the factor-by-factor derivation.",
            breakdown.ecosystem, breakdown.name
        );
    }
}

/// Render the registry-API provenance for the human summary; an unknown datum
/// shows as `unknown` so the reader sees what the registry didn't expose.
fn print_api_provenance_human(p: &ApiProvenance) {
    println!("  api signals: from the {} registry API", p.source);
    match p.package_age_days {
        Some(d) => println!("               - package age: {d} day(s) since first publish"),
        None => println!("               - package age: unknown (not reported)"),
    }
    match (&p.latest_version, p.latest_version_age_days) {
        (Some(v), Some(d)) => {
            println!("               - latest version: {v} ({d} day(s) old)")
        }
        (Some(v), None) => println!("               - latest version: {v}"),
        (None, _) => println!("               - latest version: unknown"),
    }
    #[allow(deprecated)]
    match p.ownership_transferred {
        Some(true) => {
            println!("               - ownership: no listed owners (established package)")
        }
        Some(false) => println!("               - ownership: has listed owners"),
        None => println!("               - ownership: unknown (registry exposes no owner field)"),
    }
    match p.version_spike {
        Some(true) => println!("               - version jump: abnormal (major-version spike)"),
        Some(false) => println!("               - version jump: normal"),
        None => println!("               - version jump: unknown (one version only)"),
    }
    match p.recent_downloads {
        Some(dl) => println!("               - downloads: {dl} (recent window)"),
        None => println!("               - downloads: unknown (not reported)"),
    }
    match p.has_source_repo {
        Some(true) => println!("               - source repo: listed"),
        Some(false) => println!("               - source repo: missing or unusable"),
        None => println!("               - source repo: unknown (field not in API)"),
    }
    if p.yanked_or_deprecated {
        println!("               - status: latest version yanked / deprecated");
    } else {
        println!("               - status: latest version current");
    }
}

/// Render the factor breakdown so the reader can reproduce the score by hand
/// (like `tirith score --explain`). Formatting lives in [`write_breakdown_human`]
/// for buffer-based unit tests.
fn print_breakdown_human(breakdown: &RiskBreakdown) {
    let _ = write_breakdown_human(breakdown, &mut std::io::stdout().lock());
}

/// Write the factor breakdown to `w` — split from [`print_breakdown_human`] only
/// so tests can capture the (identical) text.
fn write_breakdown_human(
    breakdown: &RiskBreakdown,
    w: &mut impl std::io::Write,
) -> std::io::Result<()> {
    writeln!(w)?;
    writeln!(
        w,
        "  risk breakdown (each factor is fixed and inspectable — no model):"
    )?;
    let mut running: i32 = 0;
    for factor in &breakdown.factors {
        running += factor.points;
        // `+NN` for positive contributions, `-NN` for the clamp factor.
        let sign = if factor.points >= 0 { "+" } else { "" };
        writeln!(
            w,
            "    {sign}{:<4} {}  (running total: {running})",
            factor.points, factor.label
        )?;
        writeln!(w, "           {}", factor.detail)?;
    }
    writeln!(
        w,
        "    = {} / {}  ({}) — sum of every factor above",
        breakdown.score,
        package_risk::MAX_SCORE,
        breakdown.risk_level
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn render(breakdown: &RiskBreakdown) -> String {
        let mut buf: Vec<u8> = Vec::new();
        write_breakdown_human(breakdown, &mut buf).expect("write to Vec never fails");
        String::from_utf8(buf).expect("breakdown output is valid UTF-8")
    }

    #[test]
    fn unknown_ecosystem_is_rejected_with_exit_2() {
        assert_eq!(
            risk("not-a-real-ecosystem", "react", None, false, false, false),
            2
        );
    }

    #[test]
    #[cfg(unix)]
    fn collect_set_wheels_excludes_symlinks() {
        // A symlinked `.whl` must NOT count as a set member: is_file() follows the link, but the
        // no-follow reader rejects it downstream into a gap, leaving members empty and the
        // command exiting 0 (Allow). An all-symlink set directory must exit 2, and a symlink
        // must not be mistaken for a member when a real wheel is also present.
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let target = dir.path().join("real-1.0-py3-none-any.whl");
        fs::write(&target, b"PK\x03\x04").unwrap();
        let set_dir = dir.path().join("set");
        fs::create_dir(&set_dir).unwrap();
        symlink(&target, set_dir.join("linked-1.0-py3-none-any.whl")).unwrap();
        // Only a symlinked .whl -> no real members -> Err(2).
        assert_eq!(collect_set_wheels(&set_dir), Err(2));
        // A REAL .whl alongside the symlink is collected; the symlink is excluded, not the dir.
        fs::write(set_dir.join("real2-1.0-py3-none-any.whl"), b"PK\x03\x04").unwrap();
        let got = collect_set_wheels(&set_dir).expect("a real wheel is present");
        assert_eq!(got.len(), 1, "symlink excluded, real wheel kept: {got:?}");
        assert!(got[0].ends_with("real2-1.0-py3-none-any.whl"));
    }

    #[test]
    fn empty_name_is_rejected_with_exit_2() {
        assert_eq!(risk("npm", "   ", None, false, false, false), 2);
    }

    #[test]
    fn detect_npm_install_script_finds_postinstall() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"p","scripts":{"postinstall":"node evil.js"}}"#,
        )
        .unwrap();
        let (found, detail) = detect_npm_install_script(dir.path());
        assert!(found);
        assert!(detail.unwrap().contains("postinstall"));
    }

    #[test]
    fn detect_npm_install_script_ignores_non_lifecycle_scripts() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"p","scripts":{"test":"jest","build":"tsc"}}"#,
        )
        .unwrap();
        let (found, _) = detect_npm_install_script(dir.path());
        assert!(!found, "test/build scripts are not install hooks");
    }

    #[test]
    fn detect_npm_install_script_ignores_empty_hook() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"p","scripts":{"postinstall":"   "}}"#,
        )
        .unwrap();
        let (found, _) = detect_npm_install_script(dir.path());
        assert!(!found, "an empty postinstall string is not a real hook");
    }

    #[test]
    fn detect_npm_install_script_handles_missing_or_bad_manifest() {
        let dir = tempdir().unwrap();
        // No package.json at all.
        assert!(!detect_npm_install_script(dir.path()).0);
        // Malformed package.json.
        fs::write(dir.path().join("package.json"), "{not json").unwrap();
        assert!(!detect_npm_install_script(dir.path()).0);
    }

    #[test]
    fn detect_install_script_pypi_setup_py() {
        let dir = tempdir().unwrap();
        let (no, _) = detect_install_script(Ecosystem::PyPI, dir.path());
        assert!(!no);
        fs::write(dir.path().join("setup.py"), "from setuptools import setup").unwrap();
        let (yes, detail) = detect_install_script(Ecosystem::PyPI, dir.path());
        assert!(yes);
        assert!(detail.unwrap().contains("setup.py"));
    }

    #[test]
    fn detect_binary_blob_finds_native_extensions() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("index.js"), "// pure source").unwrap();
        // No binary yet.
        assert!(!detect_binary_blob(dir.path()).0);
        // Add a native addon.
        fs::write(dir.path().join("addon.node"), [0u8, 1, 2, 3]).unwrap();
        let (found, detail) = detect_binary_blob(dir.path());
        assert!(found);
        assert!(detail.unwrap().contains(".node"));
    }

    #[test]
    fn detect_binary_blob_clean_directory() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("index.js"), "// pure source").unwrap();
        fs::write(dir.path().join("README.md"), "# docs").unwrap();
        let sub = dir.path().join("lib");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("util.js"), "// more source").unwrap();
        assert!(!detect_binary_blob(dir.path()).0);
    }

    #[test]
    fn gather_content_signals_missing_explicit_path_is_not_inspected() {
        let signals = gather_content_signals(
            Ecosystem::Npm,
            "whatever",
            Some("/definitely/not/a/real/path/xyzzy"),
        );
        assert!(matches!(signals, ContentSignals::NotInspected));
    }

    #[test]
    fn gather_content_signals_inspects_explicit_path() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"p","scripts":{"install":"node build.js"}}"#,
        )
        .unwrap();
        fs::write(dir.path().join("native.so"), [0u8; 4]).unwrap();
        let signals =
            gather_content_signals(Ecosystem::Npm, "p", Some(dir.path().to_str().unwrap()));
        match signals {
            ContentSignals::Inspected {
                has_install_script,
                has_binary_blob,
                ..
            } => {
                assert!(has_install_script);
                assert!(has_binary_blob);
            }
            ContentSignals::NotInspected => panic!("explicit path should be inspected"),
        }
    }

    #[test]
    fn breakdown_human_renders_known_popular_zero() {
        let signals = PackageSignals {
            ecosystem: Ecosystem::Npm,
            name: "react".to_string(),
            version: None,
            threat_db_missing: false,
            name_vs_popular: NameVsPopular::KnownPopular,
            malicious_typosquat_of: None,
            content_signals: ContentSignals::NotInspected,
            api: ApiSignals::offline(),
        };
        let breakdown = package_risk::score_package(&signals);
        let out = render(&breakdown);
        assert!(out.contains("risk breakdown"), "must print header: {out}");
        assert!(out.contains("+0"), "known-popular contributes +0: {out}");
        assert!(out.contains("= 0 / 100"), "total must read 0/100: {out}");
        assert!(out.contains("(low)"), "0 is the low bucket: {out}");
    }

    #[test]
    fn breakdown_human_renders_negative_clamp_factor() {
        let signals = PackageSignals {
            ecosystem: Ecosystem::Npm,
            name: "raect".to_string(),
            version: None,
            threat_db_missing: false,
            name_vs_popular: NameVsPopular::NearPopular {
                popular_name: "react".to_string(),
                distance: 1,
            },
            malicious_typosquat_of: Some("react".to_string()),
            content_signals: ContentSignals::Inspected {
                path: "/tmp/p".to_string(),
                has_install_script: true,
                install_script_detail: None,
                has_binary_blob: true,
                binary_blob_detail: None,
            },
            api: ApiSignals::offline(),
        };
        let breakdown = package_risk::score_package(&signals);
        assert_eq!(breakdown.score, 100);
        let out = render(&breakdown);
        // The clamp factor renders as a bare `-15` (no leading '+').
        assert!(out.contains("    -15 "), "clamp must render bare: {out}");
        assert!(!out.contains("+-15"), "clamp must not get a '+': {out}");
        assert!(
            out.contains("= 100 / 100"),
            "total must read 100/100: {out}"
        );
        assert!(
            out.contains("(critical)"),
            "100 is the critical bucket: {out}"
        );
    }

    // --- registry-API path (no real network: fixture-fed fake client) ------

    use tirith_core::registry_api::{FetchError, RegistryMetadata};

    /// A fixture-fed [`RegistryClient`].
    struct FakeClient {
        result: Result<RegistryMetadata, FetchError>,
    }
    impl RegistryClient for FakeClient {
        fn fetch(&self, _eco: Ecosystem, _name: &str) -> Result<RegistryMetadata, FetchError> {
            self.result.clone()
        }
    }

    /// A client whose `fetch` panics — proves the offline switch short-circuits
    /// before any registry call.
    struct ExplodingClient;
    impl RegistryClient for ExplodingClient {
        fn fetch(&self, _eco: Ecosystem, _name: &str) -> Result<RegistryMetadata, FetchError> {
            panic!("fetch must not be called when offline mode is active");
        }
    }

    #[test]
    fn gather_api_offline_flag_skips_network() {
        // CR12: `--offline` must short-circuit without calling `fetch` (the
        // exploding client would panic) and report NotComputed, not Unavailable.
        let sig = gather_api(&ExplodingClient, Ecosystem::Npm, "react", None, true);
        match sig {
            ApiSignals::NotComputed { reason } => {
                assert!(reason.contains("offline"), "reason: {reason}");
            }
            other => panic!("expected NotComputed for an intentional offline skip, got {other:?}"),
        }
    }

    #[test]
    fn gather_api_success_returns_available() {
        let meta = RegistryMetadata {
            source: "npm".to_string(),
            latest_version: Some("1.0.0".to_string()),
            ..Default::default()
        };
        let client = FakeClient { result: Ok(meta) };
        let sig = gather_api(&client, Ecosystem::Npm, "react", None, false);
        assert!(matches!(sig, ApiSignals::Available { .. }));
    }

    #[test]
    fn gather_api_failure_degrades_to_unavailable() {
        let client = FakeClient {
            result: Err(FetchError::Network("connection refused".to_string())),
        };
        let sig = gather_api(&client, Ecosystem::Npm, "react", None, false);
        assert!(matches!(sig, ApiSignals::Unavailable { .. }));
    }

    #[test]
    fn online_run_offline_flag_still_exits_zero_without_network() {
        // `--online --offline` scores offline and exits 0 with no network call,
        // exercising the public `run` end-to-end.
        let code = run(
            "npm", "react", None, /* online = */ true, /* offline = */ true,
            /* json = */ true, /* explain = */ false,
        );
        assert_eq!(code, 0, "an --online --offline run must exit 0 offline");
    }

    #[test]
    fn available_provenance_drives_api_factors_and_human_output() {
        #[allow(deprecated)]
        let provenance = ApiProvenance {
            source: "pypi".to_string(),
            package_age_days: Some(2),
            latest_version_age_days: Some(1),
            ownership_transferred: Some(true),
            version_spike: Some(true),
            recent_downloads: Some(5),
            has_source_repo: Some(false),
            yanked_or_deprecated: true,
            latest_version: Some("9.9.9".to_string()),
            ..Default::default()
        };
        let s = PackageSignals {
            ecosystem: Ecosystem::PyPI,
            name: "p".to_string(),
            version: None,
            threat_db_missing: true,
            name_vs_popular: NameVsPopular::Unknown,
            malicious_typosquat_of: None,
            content_signals: ContentSignals::NotInspected,
            api: ApiSignals::Available { provenance },
        };
        let breakdown = package_risk::score_package(&s);
        // The breakdown carries the API factors; score is non-zero.
        assert!(breakdown.score > 0);
        assert!(breakdown.factors.iter().any(|f| f.id.starts_with("api_")));
        assert!(matches!(
            breakdown.api_signals,
            ApiSignals::Available { .. }
        ));
        // Confirm the human renderer doesn't panic on a full provenance.
        if let ApiSignals::Available { provenance } = &breakdown.api_signals {
            print_api_provenance_human(provenance);
        }
    }
}
