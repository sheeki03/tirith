//! `tirith ecosystem scan` — supply-chain risk scan of a project's dependency
//! manifests.
//!
//! This is the directory-level companion to `tirith package risk`: it walks a
//! project, parses every dependency manifest it understands (npm / Python /
//! Rust / Go / Ruby), and scores **every declared dependency** with the same
//! deterministic [`tirith_core::package_risk`] factor engine — folding in a
//! *slopsquat* (AI-hallucinated package name) heuristic on top.
//!
//! **Offline by default.** Name and typosquat signals come from the local
//! threat DB; no network is touched. `--online` additionally consults each
//! package's registry API (npm / PyPI / crates.io) for provenance signals,
//! gated and degraded exactly as `tirith package risk --online` is — that is
//! the *only* path on which `ecosystem scan` reaches the network.
//!
//! Findings flow through tirith's normal [`Verdict`] / `Finding` model: the
//! result is explainable, audit-logged, and policy-aware (an allowlisted
//! package is suppressed). `--format json` emits the full machine-readable
//! report.

use std::path::PathBuf;

use tirith_core::ecosystem_scan::{
    self, DependencyAssessment, EcosystemScanReport, OnlineMode, ScanRequest,
};
use tirith_core::package_risk::ApiSignals;
use tirith_core::policy::Policy;
use tirith_core::registry_api::{self, HttpRegistryClient};
use tirith_core::threatdb::{Ecosystem, ThreatDb};
use tirith_core::verdict::Action;

/// Run `tirith ecosystem scan [path]`.
///
/// `path` is the project directory (or a single manifest file) to scan;
/// it defaults to the current directory. `online` opts into the registry-API
/// provenance signals; `offline` (or `TIRITH_OFFLINE`) forces offline scoring
/// even when `online` is set.
///
/// Exit codes mirror `tirith scan`:
/// * `0` — no findings (or every finding allowlisted);
/// * `1` — at least one finding at or above the BLOCK threshold (a
///   confirmed-malicious / typosquat dependency);
/// * `2` — only advisory (WARN-level) findings, **or** a usage error (the
///   given path does not exist). Exit `2` keeps a usage error distinct from a
///   `1` BLOCK finding, exactly as `tirith install` does.
pub fn scan(path: Option<&str>, online: bool, offline: bool, json: bool) -> i32 {
    let scan_root: PathBuf = path
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    if !scan_root.exists() {
        eprintln!(
            "tirith ecosystem scan: path not found: {}",
            scan_root.display()
        );
        eprintln!("  try: tirith ecosystem scan ./  (scan the current directory)");
        // A usage error, not a finding — exit 2 so it never collides with
        // exit 1 (= a BLOCK-level finding).
        return 2;
    }

    // Threat DB — offline name / typosquat signals. `None` is not an error:
    // the scan still runs (weaker), and a note records the missing DB.
    let db = ThreatDb::cached();

    // Policy — drives the allowlist (suppress findings for trusted packages).
    //
    // PR #121 fix-list item 14 — discover policy from the SCAN TARGET, not the
    // operator's cwd. Previously `Policy::discover(None)` fell back to
    // `std::env::current_dir()`, so `tirith ecosystem scan /path/to/repo` from
    // `~/elsewhere` ignored the repo's `.tirith/policy.yaml` (allowlist,
    // severity overrides) entirely. The scan target IS the project whose
    // policy must apply — passing `scan_root` is the same shape the per-file
    // analysis paths already use (`engine::analyze` discovers policy from the
    // analyzed file's directory, not the caller's cwd).
    let policy = Policy::discover(scan_root.to_str());

    // Build the allowlist predicate. A policy allowlist entry suppresses a
    // dependency when it matches the bare package name or the `ecosystem:name`
    // form — exact, predictable matching (a substring match would let `react`
    // silence `react-dom`). Both the global `allowlist` and the rule-scoped
    // `allowlist_rules` for the package supply-chain rules are honored.
    let is_allowlisted = |eco: Ecosystem, name: &str| package_allowlisted(&policy, eco, name);

    // Registry-API resolver — only when `--online` and offline mode is not in
    // force. The closure is offline-safe: it degrades any registry failure to
    // `ApiSignals::Unavailable` (the package-risk score then falls back to
    // offline signals). It is memoized inside `ecosystem_scan::scan`, so a
    // package declared in two manifests is fetched at most once.
    let use_online = online && !offline && !super::offline_env_active();
    let http_client = HttpRegistryClient::new();
    let resolver = |eco: Ecosystem, name: &str| -> ApiSignals {
        registry_api::gather_api_signals(&http_client, eco, name)
    };

    let online_mode = if use_online {
        OnlineMode::Resolver(&resolver)
    } else {
        OnlineMode::Off
    };

    let request = ScanRequest {
        root: &scan_root,
        db: db.as_deref(),
        online: online_mode,
        is_allowlisted: &is_allowlisted,
    };
    let mut report = ecosystem_scan::scan(&request);

    // M4 item 8 chunk 3 follow-up — stamp the resolved caller origin on the
    // scan's verdict BEFORE the audit-log write below. The scan engine does
    // not know the caller's identity by design; the CLI does. Without this
    // stamp, `tirith ecosystem scan` audit lines would land in the
    // `tirith agent sessions` "unknown" bucket.
    let interactive = is_terminal::is_terminal(std::io::stderr());
    report.verdict.agent_origin = Some(tirith_core::agent_origin::resolve_cli_origin(interactive));

    // M4 item 8 chunk 3 follow-up — enforce `agent_rules.deny` on the
    // ecosystem-scan path. `tirith ecosystem scan` does not route through
    // `post_process_verdict`, so without this call deny would stamp but
    // not enforce on the directory-level supply-chain surface. The
    // helper is a no-op on `Allowed`/`Unspecified`.
    //
    // M4 PR #120 fix-6 (Greptile P1): mirror the bypass-skip branch the
    // hot paths in `check`/`gateway` use — under `TIRITH=0`, the raw
    // verdict already wins and `apply_agent_rules` must NOT silently
    // re-Block. The CLI-side guard is defensive future-proofing for
    // ecosystem-scan (the engine bypass branch does NOT fire on this
    // path today; ecosystem-scan never routes through `engine::analyze`),
    // pinned by `ecosystem_tirith_bypass_not_wired_so_deny_enforces_today`
    // (renamed in fix-7 from `..._deny_skipped_under_tirith_bypass_today`
    // to match the assertions — bypass-skip never fires today, so deny
    // enforces).
    if !report.verdict.bypass_honored {
        tirith_core::escalation::apply_agent_rules(&mut report.verdict, &policy);
    }

    // Audit-log the verdict, exactly as the other analysis commands do. The
    // "command" string identifies this as an ecosystem scan of the root. A
    // failed audit write does not abort the scan, but it must not be silent —
    // surface it as a non-fatal notice.
    if let Err(e) = tirith_core::audit::log_verdict(
        &report.verdict,
        &format!("ecosystem scan {}", report.scan_root),
        None,
        None,
        &policy.dlp_custom_patterns,
    ) {
        if !json {
            eprintln!("tirith ecosystem scan: audit log not written (non-fatal): {e}");
        }
    }

    if json {
        // A JSON-write failure is the command's own I/O failure. If the report
        // would otherwise exit 0 (a clean scan), surface exit 1 so a piped
        // consumer does not treat truncated JSON as a clean pass. A non-zero
        // finding-driven code (1 BLOCK / 2 WARN) already propagates and is
        // kept.
        if !print_json(&report) {
            let code = exit_code(report.action());
            return if code == 0 { 1 } else { code };
        }
    } else {
        print_human(&report);
    }

    exit_code(report.action())
}

/// Exit code for a scan's resolved [`Action`]. Mirrors `tirith scan`:
/// BLOCK → 1, WARN → 2, ALLOW → 0.
fn exit_code(action: Action) -> i32 {
    match action {
        Action::Block => 1,
        Action::Warn | Action::WarnAck => 2,
        Action::Allow => 0,
    }
}

/// Decide whether a `(ecosystem, name)` dependency is allowlisted by `policy`.
///
/// A dependency is allowlisted when a policy allowlist entry — global or
/// scoped to one of the package supply-chain rules — matches it. Matching is
/// exact against either the bare package name (`react`) or the qualified
/// `ecosystem:name` form (`npm:react`), case-insensitively. Exact matching is
/// deliberate: a package allowlist must not let a short name silence every
/// longer name that contains it.
fn package_allowlisted(policy: &Policy, eco: Ecosystem, name: &str) -> bool {
    let bare = name.to_lowercase();
    let qualified = format!("{}:{}", eco, bare);

    let matches_entry = |entry: &str| {
        let e = entry.trim().to_lowercase();
        e == bare || e == qualified
    };

    // Global allowlist.
    if policy.allowlist.iter().any(|e| matches_entry(e)) {
        return true;
    }
    // Rule-scoped allowlist, for the rules `ecosystem scan` emits.
    for rule in &policy.allowlist_rules {
        let scoped = matches!(
            rule.rule_id.to_lowercase().as_str(),
            "threat_malicious_package"
                | "threat_package_typosquat"
                | "threat_package_similar_name"
                | "threat_suspicious_package"
        );
        if scoped && rule.patterns.iter().any(|p| matches_entry(p)) {
            return true;
        }
    }
    false
}

// --- output ----------------------------------------------------------------

/// Emit the full machine-readable report. The structure is a thin wrapper over
/// [`EcosystemScanReport`] (which already derives `Serialize`), with a
/// `schema_version` for forward compatibility.
///
/// Returns `false` on a JSON-write failure so the caller can exit non-zero — a
/// piped consumer must not see truncated JSON paired with a success code.
fn print_json(report: &EcosystemScanReport) -> bool {
    #[derive(serde::Serialize)]
    struct JsonOut<'a> {
        schema_version: u32,
        #[serde(flatten)]
        report: &'a EcosystemScanReport,
    }
    let out = JsonOut {
        schema_version: 1,
        report,
    };
    super::write_json_stdout(&out, "tirith ecosystem scan: failed to write JSON output")
}

/// Render the human-readable report to stderr (the summary) and stdout (the
/// findings), following the `tirith scan` convention of a stderr summary line.
fn print_human(report: &EcosystemScanReport) {
    let finding_count = report.verdict.findings.len();

    // Summary line.
    if report.manifests.is_empty() {
        eprintln!(
            "tirith ecosystem scan: {} — no dependency manifests found",
            report.scan_root
        );
    } else {
        eprintln!(
            "tirith ecosystem scan: {} — {} manifest(s), {} dependencies, {} finding(s)",
            report.scan_root,
            report.manifests.len(),
            report.dependency_count,
            finding_count,
        );
    }

    // Manifests scanned.
    if !report.manifests.is_empty() {
        eprintln!();
        eprintln!("  manifests:");
        for m in &report.manifests {
            eprintln!("    - {m}");
        }
    }

    // Notes about coverage (missing DB, unreadable manifest, truncation).
    if !report.notes.is_empty() {
        eprintln!();
        eprintln!("  notes:");
        for note in &report.notes {
            match &note.manifest {
                Some(m) => eprintln!("    - [{m}] {}", note.note),
                None => eprintln!("    - {}", note.note),
            }
        }
    }

    // Findings — printed to stdout so they can be captured / piped.
    if finding_count == 0 {
        eprintln!();
        if report.dependency_count == 0 {
            eprintln!("  no dependencies to assess.");
        } else {
            eprintln!(
                "  no supply-chain risks found across {} dependencies.",
                report.dependency_count
            );
        }
    } else {
        println!();
        println!("Supply-chain findings:");
        for finding in &report.verdict.findings {
            let sev = tirith_core::style::severity_label(
                &finding.severity,
                tirith_core::style::Stream::Stdout,
            );
            println!("  {} {} — {}", sev, finding.rule_id, finding.title);
            println!("    {}", finding.description);
        }
    }

    // The allowlist note: how many dependencies were suppressed.
    let allowlisted = report.allowlisted_count();
    if allowlisted > 0 {
        eprintln!();
        eprintln!("  {allowlisted} dependency/dependencies suppressed by policy allowlist.");
    }

    // A pointer to per-package inspection.
    if report.dependency_count > 0 {
        eprintln!();
        let highest = highest_risk_dependency(report);
        if let Some(dep) = highest {
            eprintln!(
                "  highest risk: {} {} ({}/100, {}). \
                 Run 'tirith package explain {} {}' for the factor breakdown.",
                dep.dependency.ecosystem,
                dep.dependency.name,
                dep.risk.score,
                dep.risk.risk_level,
                dep.dependency.ecosystem,
                dep.dependency.name,
            );
        }
        if !report.online {
            eprintln!(
                "  (offline scan — re-run with --online to add registry-API \
                 provenance signals)"
            );
        }
    }
}

/// The single highest-risk-scoring assessed dependency, for the human summary.
fn highest_risk_dependency(report: &EcosystemScanReport) -> Option<&DependencyAssessment> {
    report
        .assessments
        .iter()
        .max_by_key(|a| a.risk.score)
        .filter(|a| a.risk.score > 0)
}

/// Check whether a given path looks like a project that `ecosystem scan` can
/// meaningfully scan — used by the doctor / help, currently only by tests.
#[cfg(test)]
fn has_any_manifest(root: &std::path::Path) -> bool {
    !ecosystem_scan::discover_manifests(root).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use tirith_core::policy::{AllowlistRule, Policy};

    #[test]
    fn exit_code_maps_actions() {
        assert_eq!(exit_code(Action::Allow), 0);
        assert_eq!(exit_code(Action::Block), 1);
        assert_eq!(exit_code(Action::Warn), 2);
        assert_eq!(exit_code(Action::WarnAck), 2);
    }

    #[test]
    fn package_allowlisted_matches_bare_name() {
        let policy = Policy {
            allowlist: vec!["my-internal-pkg".to_string()],
            ..Default::default()
        };
        assert!(package_allowlisted(
            &policy,
            Ecosystem::Npm,
            "my-internal-pkg"
        ));
        assert!(!package_allowlisted(&policy, Ecosystem::Npm, "other-pkg"));
    }

    #[test]
    fn package_allowlisted_matches_qualified_name() {
        let policy = Policy {
            allowlist: vec!["npm:scoped-thing".to_string()],
            ..Default::default()
        };
        assert!(package_allowlisted(&policy, Ecosystem::Npm, "scoped-thing"));
        // The same bare name in a different ecosystem must NOT match a
        // qualified `npm:` entry.
        assert!(!package_allowlisted(
            &policy,
            Ecosystem::PyPI,
            "scoped-thing"
        ));
    }

    #[test]
    fn package_allowlisted_is_exact_not_substring() {
        // A short allowlist entry must NOT silence a longer name containing it.
        let policy = Policy {
            allowlist: vec!["react".to_string()],
            ..Default::default()
        };
        assert!(package_allowlisted(&policy, Ecosystem::Npm, "react"));
        assert!(
            !package_allowlisted(&policy, Ecosystem::Npm, "react-dom"),
            "an exact entry must not match by substring"
        );
    }

    #[test]
    fn package_allowlisted_honors_rule_scoped_entry() {
        let policy = Policy {
            allowlist_rules: vec![AllowlistRule {
                rule_id: "threat_suspicious_package".to_string(),
                patterns: vec!["python-data-helper".to_string()],
            }],
            ..Default::default()
        };
        assert!(package_allowlisted(
            &policy,
            Ecosystem::PyPI,
            "python-data-helper"
        ));
    }

    #[test]
    fn package_allowlisted_ignores_unrelated_rule_scope() {
        // A rule-scoped allowlist for an unrelated rule must NOT suppress a
        // package finding.
        let policy = Policy {
            allowlist_rules: vec![AllowlistRule {
                rule_id: "curl_pipe_shell".to_string(),
                patterns: vec!["some-pkg".to_string()],
            }],
            ..Default::default()
        };
        assert!(!package_allowlisted(&policy, Ecosystem::Npm, "some-pkg"));
    }

    #[test]
    fn has_any_manifest_detects_project() {
        let dir = tempdir().unwrap();
        assert!(!has_any_manifest(dir.path()));
        fs::write(dir.path().join("Cargo.toml"), "[dependencies]\n").unwrap();
        assert!(has_any_manifest(dir.path()));
    }

    #[test]
    fn scan_of_missing_path_exits_2() {
        // A path that does not exist is a usage error → exit 2, never 1
        // (1 is reserved for a BLOCK-level finding).
        let code = scan(
            Some("/definitely/not/a/real/path/xyzzy-ecosystem"),
            false,
            false,
            true,
        );
        assert_eq!(code, 2);
    }

    #[test]
    fn scan_of_clean_temp_project_exits_0() {
        // A temp project whose sole dependency is unknown to the (absent)
        // threat DB yields no findings → exit 0.
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[dependencies]\nmy-unique-internal-crate = \"1.0\"\n",
        )
        .unwrap();
        let code = scan(dir.path().to_str(), false, false, true);
        assert_eq!(code, 0, "a project with no flagged deps must exit 0");
    }

    #[test]
    fn scan_discovers_policy_from_scan_target_not_cwd() {
        // PR #121 fix-list item 14 regression pin — `Policy::discover` must be
        // anchored at the SCAN TARGET, not the operator's cwd. We write a
        // `.tirith/policy.yaml` to the scan target that allowlists the only
        // declared dependency; if discovery is anchored at the scan target the
        // allowlist suppresses findings (verdict ALLOW, exit 0). If discovery
        // falls back to cwd (the old bug), the allowlist never loads and the
        // dependency goes unsuppressed.
        //
        // This is a discovery-anchoring test, not an end-to-end finding test —
        // the temp project's only dep is unknown to the (absent) threat DB, so
        // a clean baseline scan would already exit 0. We exercise discovery
        // through `Policy::discover(scan_root.to_str())` directly to assert
        // the resolved policy carries the allowlist entry.
        let target = tempdir().unwrap();
        let cwd = tempdir().unwrap();

        // Mark both temp dirs as repo roots so policy-discovery's walk-up does
        // not climb out of the tempdir into a parent project. Without this
        // marker, `discover_policy_path` walks past the temp dir looking for
        // an ancestor with `.tirith/`; on a developer box the workspace root's
        // `.tirith/` could win.
        fs::create_dir_all(target.path().join(".git")).unwrap();
        fs::create_dir_all(cwd.path().join(".git")).unwrap();

        fs::create_dir_all(target.path().join(".tirith")).unwrap();
        fs::write(
            target.path().join(".tirith").join("policy.yaml"),
            "allowlist:\n  - my-internal-pkg\n",
        )
        .unwrap();
        fs::write(
            target.path().join("Cargo.toml"),
            "[dependencies]\nmy-internal-pkg = \"1.0\"\n",
        )
        .unwrap();

        // The discovered policy from the scan target must carry the allowlist
        // entry. Anchored at the cwd (no `.tirith/`) it would not.
        let from_target = Policy::discover(target.path().to_str());
        assert!(
            from_target.allowlist.iter().any(|e| e == "my-internal-pkg"),
            "policy discovered from the scan target must carry its allowlist: \
             {:?}",
            from_target.allowlist,
        );
        let from_cwd = Policy::discover(cwd.path().to_str());
        assert!(
            !from_cwd.allowlist.iter().any(|e| e == "my-internal-pkg"),
            "policy discovered from an unrelated cwd must NOT carry the scan \
             target's allowlist: {:?}",
            from_cwd.allowlist,
        );

        // The exported `scan` entry point is what wires discovery — invoke it
        // and assert no panic and a clean ALLOW (the scan finds the dep,
        // allowlist suppresses it). The threat DB is absent here so a clean
        // baseline already exits 0 regardless; this is a smoke that the new
        // wiring does not regress the happy path.
        let code = scan(target.path().to_str(), false, false, true);
        assert_eq!(
            code, 0,
            "ecosystem scan with allowlisted dep must exit 0 (policy discovery \
             from scan target)"
        );
    }
}
