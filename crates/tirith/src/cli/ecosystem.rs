//! `tirith ecosystem scan` — supply-chain risk scan of a project's dependency
//! manifests; the directory-level companion to `tirith package risk`.
//!
//! Walks a project, parses each dependency manifest (npm / Python / Rust / Go /
//! Ruby), and scores every declared dependency with the deterministic
//! [`tirith_core::package_risk`] engine plus a slopsquat (AI-hallucinated name)
//! heuristic. Offline by default (local threat DB, no network); `--online` is
//! the only path that touches the network, consulting each registry API for
//! provenance exactly as `tirith package risk --online` does. Findings flow
//! through the normal [`Verdict`] / `Finding` model (explainable, audit-logged,
//! allowlist-aware); `--format json` emits the full report.

use std::path::{Path, PathBuf};

#[cfg(test)]
use tirith_core::ecosystem_scan::DEFAULT_MAX_INSTALLED_ENTRIES;
use tirith_core::ecosystem_scan::{
    self, DependencyAssessment, EcosystemScanReport, OnlineMode, ScanMode, ScanRequest,
};
use tirith_core::package_risk::ApiSignals;
use tirith_core::policy::Policy;
use tirith_core::registry_api::{self, HttpRegistryClient};
use tirith_core::threatdb::{Ecosystem, ThreatDb};
use tirith_core::verdict::Action;

/// Lower bound for `--max-installed-entries`. Anything below this cap is
/// pointless for a real project and almost certainly a typo.
pub const MIN_INSTALLED_ENTRIES: usize = 100;

/// Upper bound for `--max-installed-entries`. Beyond this the walk is no
/// longer "bounded"; pass `0` (the explicit unbounded sentinel) instead.
pub const MAX_INSTALLED_ENTRIES: usize = 200_000;

/// Network-call threshold above which `--installed --online` prompts for
/// confirmation. Below this we proceed without asking — a few API calls
/// against a tiny installed tree is not enough to surprise an operator.
pub const ONLINE_PROMPT_THRESHOLD: usize = 100;

/// Run `tirith ecosystem scan [path]` (defaults to cwd; `path` may be a single
/// manifest). `offline` (or `TIRITH_OFFLINE`) forces offline even with
/// `online`. `installed` walks `node_modules`/`site-packages`/`vendor`/
/// `Cargo.lock` instead of manifests; `max_installed_entries` caps that walk
/// (`0` = unbounded). `non_interactive` suppresses the `--installed --online`
/// prompt (CI).
///
/// Exit codes mirror `tirith scan`: `0` clean/allowlisted; `1` a BLOCK-level
/// finding; `2` only WARN findings OR a usage error (keeps usage errors distinct
/// from a `1` BLOCK, like `tirith install`).
#[allow(clippy::too_many_arguments)]
pub fn scan(
    path: Option<&str>,
    online: bool,
    offline: bool,
    installed: bool,
    max_installed_entries: usize,
    non_interactive: bool,
    json: bool,
) -> i32 {
    let scan_root: PathBuf = path
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    if !scan_root.exists() {
        eprintln!(
            "tirith ecosystem scan: path not found: {}",
            scan_root.display()
        );
        eprintln!("  try: tirith ecosystem scan ./  (scan the current directory)");
        // Usage error → exit 2, never colliding with exit 1 (a BLOCK finding).
        return 2;
    }

    // `0` is the unbounded sentinel; any other value must be in range.
    if max_installed_entries != 0
        && !(MIN_INSTALLED_ENTRIES..=MAX_INSTALLED_ENTRIES).contains(&max_installed_entries)
    {
        eprintln!(
            "tirith ecosystem scan: --max-installed-entries must be 0 (unbounded) \
             or between {MIN_INSTALLED_ENTRIES} and {MAX_INSTALLED_ENTRIES}; got \
             {max_installed_entries}."
        );
        return 2;
    }

    let installed_effective = installed || force_installed_for_tests();

    // `installed` wins; otherwise a single-file lockfile path-arg is treated as
    // a specific lockfile (shipping behavior).
    let mode = pick_mode(&scan_root, installed_effective);

    // Threat DB — offline name/typosquat signals. `None` is not an error: the
    // scan still runs (weaker) and a note records the missing DB.
    let db = ThreatDb::cached();

    // PR #121 fix-list item 14 — discover policy from the SCAN TARGET, not cwd,
    // so `tirith ecosystem scan /repo` from elsewhere honors the repo's
    // `.tirith/policy.yaml` (matches the per-file analysis paths).
    let policy = Policy::discover(scan_root.to_str());

    // Allowlist predicate: exact match on the bare name or `ecosystem:name` (a
    // substring match would let `react` silence `react-dom`). Honors both the
    // global allowlist and the supply-chain rule-scoped `allowlist_rules`.
    let is_allowlisted = |eco: Ecosystem, name: &str| package_allowlisted(&policy, eco, name);

    // Registry-API resolver — only when `--online` and not forced offline.
    // Offline-safe (degrades any failure to `ApiSignals::Unavailable`) and
    // memoized inside `ecosystem_scan::scan`, so a package is fetched at most once.
    let use_online = online && !offline && !super::offline_env_active();
    let http_client = HttpRegistryClient::new();
    // Fold `gather_api_signals`'s existence result into provenance (as `tirith
    // install` does) so the `PackageNotFoundInRegistry` gate can read it.
    let resolver = |eco: Ecosystem, name: &str| -> ApiSignals {
        let (mut signals, existence) = registry_api::gather_api_signals(&http_client, eco, name);
        use tirith_core::package_risk::{ApiProvenance, PackageExistence};
        match &mut signals {
            ApiSignals::Available { provenance } => {
                provenance.package_existence = existence;
                let dc = tirith_core::dep_confusion::evaluate(eco, name, &policy);
                if dc.risk {
                    provenance.dep_confusion = Some(dc);
                }
            }
            ApiSignals::Unavailable { .. } if matches!(existence, PackageExistence::NotFound) => {
                let mut prov = ApiProvenance {
                    source: eco.to_string(),
                    package_existence: PackageExistence::NotFound,
                    ..Default::default()
                };
                let dc = tirith_core::dep_confusion::evaluate(eco, name, &policy);
                if dc.risk {
                    prov.dep_confusion = Some(dc);
                }
                signals = ApiSignals::Available { provenance: prov };
            }
            _ => {}
        }
        signals
    };

    // `--installed --online` on a large tree can fire thousands of API calls —
    // estimate and prompt above the threshold (skipped under `--non-interactive`
    // / non-TTY stderr).
    if use_online && matches!(mode, ScanMode::Installed) && !non_interactive {
        let estimate = estimate_installed_entries(&scan_root, max_installed_entries);
        if estimate > ONLINE_PROMPT_THRESHOLD
            && !super::confirm(
                &format!(
                    "tirith ecosystem scan: --installed --online would make ~{estimate} \
                 network calls against package registries; proceed?"
                ),
                false,
            )
        {
            eprintln!("tirith ecosystem scan: aborted by operator at confirmation prompt.");
            return 2;
        }
    }

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
        mode: mode.clone(),
        installed_max_entries: max_installed_entries,
        policy: Some(&policy),
    };
    let mut report = ecosystem_scan::scan(&request);

    // Stamp the resolved caller origin BEFORE the audit write — the scan engine
    // doesn't know the caller's identity, and unstamped lines land in the
    // `tirith agent sessions` "unknown" bucket.
    let interactive = is_terminal::is_terminal(std::io::stderr());
    report.verdict.agent_origin = Some(tirith_core::agent_origin::resolve_cli_origin(interactive));

    // Enforce `agent_rules.deny` here: ecosystem-scan never routes through
    // `post_process_verdict`, so deny would stamp but not enforce. The
    // bypass-skip guard mirrors `check`/`gateway` (under `TIRITH=0` the raw
    // verdict wins) — defensive, since the engine bypass branch can't fire on
    // this path; pinned by
    // `ecosystem_tirith_bypass_not_wired_so_deny_enforces_today`.
    if !report.verdict.bypass_honored {
        tirith_core::escalation::apply_agent_rules(&mut report.verdict, &policy);
    }

    // Audit-log the verdict (mode appended so a reader can tell the passes
    // apart). A failed write is non-fatal but surfaced, not silent.
    if let Err(e) = tirith_core::audit::log_verdict(
        &report.verdict,
        &format!("ecosystem scan ({}) {}", report.mode, report.scan_root),
        None,
        None,
        &policy.dlp_custom_patterns,
    ) {
        if !json {
            eprintln!("tirith ecosystem scan: audit log not written (non-fatal): {e}");
        }
    }

    if json {
        // On a JSON-write failure, surface exit 1 if the scan was otherwise
        // clean so a piped consumer never reads truncated JSON as a pass; a
        // finding-driven code (1/2) already propagates.
        if !print_json(&report) {
            let code = exit_code(report.action());
            return if code == 0 { 1 } else { code };
        }
    } else {
        print_human(&report);
    }

    exit_code(report.action())
}

/// Exit code for a resolved [`Action`]: BLOCK → 1, WARN → 2, ALLOW → 0.
fn exit_code(action: Action) -> i32 {
    match action {
        Action::Block => 1,
        Action::Warn | Action::WarnAck => 2,
        Action::Allow => 0,
    }
}

/// Whether `(eco, name)` is allowlisted: an exact, case-insensitive match (bare
/// `react` or qualified `npm:react`) against the global allowlist or a
/// supply-chain rule-scoped one. Exact (not substring) so a short name can't
/// silence every longer name containing it.
fn package_allowlisted(policy: &Policy, eco: Ecosystem, name: &str) -> bool {
    let bare = name.to_lowercase();
    let qualified = format!("{}:{}", eco, bare);

    let matches_entry = |entry: &str| {
        let e = entry.trim().to_lowercase();
        e == bare || e == qualified
    };

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

/// Emit the full report (a `schema_version`-tagged wrapper over
/// [`EcosystemScanReport`]). `false` on a JSON-write failure so the caller exits
/// non-zero — a piped consumer must not see truncated JSON with a success code.
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

/// Render the report: summary to stderr, findings to stdout (the `tirith scan`
/// convention).
fn print_human(report: &EcosystemScanReport) {
    let finding_count = report.verdict.findings.len();

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

    if !report.manifests.is_empty() {
        eprintln!();
        eprintln!("  manifests:");
        for m in &report.manifests {
            eprintln!("    - {m}");
        }
    }

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

    // Findings go to stdout so they can be captured / piped.
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

    let allowlisted = report.allowlisted_count();
    if allowlisted > 0 {
        eprintln!();
        eprintln!("  {allowlisted} dependency/dependencies suppressed by policy allowlist.");
    }

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

/// Resolve the effective [`ScanMode`]. Precedence: `--installed` (or debug-only
/// `TIRITH_FORCE_INSTALLED`) → `Installed`; a single recognized manifest file →
/// `SpecificLockfile`; otherwise `Manifests` (default).
pub(crate) fn pick_mode(scan_root: &Path, installed: bool) -> ScanMode {
    if installed {
        return ScanMode::Installed;
    }
    if scan_root.is_file() {
        if let Some(name) = scan_root.file_name().and_then(|n| n.to_str()) {
            if ecosystem_scan::ManifestKind::from_file_name(name).is_some() {
                return ScanMode::SpecificLockfile(scan_root.to_path_buf());
            }
        }
    }
    ScanMode::Manifests
}

/// `true` when `TIRITH_FORCE_INSTALLED` is set (tests only). GATED to debug
/// builds so a release binary never honors it from an inherited environment —
/// production depends only on `--installed`.
fn force_installed_for_tests() -> bool {
    if !cfg!(debug_assertions) {
        return false;
    }
    std::env::var("TIRITH_FORCE_INSTALLED")
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

/// Cheap upper-bound estimate of installed-package count, only to size the
/// `--online` prompt — need not be exact.
pub(crate) fn estimate_installed_entries(root: &Path, cap: usize) -> usize {
    let mut count = 0usize;
    // Count immediate children of node_modules + site-packages.
    let nm = root.join("node_modules");
    if let Ok(rd) = std::fs::read_dir(&nm) {
        for e in rd.flatten() {
            if !e.file_type().map(|f| f.is_dir()).unwrap_or(false) {
                continue;
            }
            let Some(name) = e.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if name.starts_with('@') {
                if let Ok(sub) = std::fs::read_dir(e.path()) {
                    count += sub.count();
                }
            } else {
                count += 1;
            }
            if cap > 0 && count > cap {
                return cap;
            }
        }
    }
    for sp in find_site_packages_for_estimate(root) {
        if let Ok(rd) = std::fs::read_dir(sp) {
            count += rd
                .flatten()
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .is_some_and(|n| n.ends_with(".dist-info"))
                })
                .count();
        }
        if cap > 0 && count > cap {
            return cap;
        }
    }
    count
}

/// Mirror of the core's `find_site_packages_dirs` for the CLI-side estimator.
/// Kept here so the CLI does not need to expose the core helper.
fn find_site_packages_for_estimate(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let cands = [
        root.join("site-packages"),
        root.join("Lib").join("site-packages"),
    ];
    for c in cands {
        if c.is_dir() {
            out.push(c);
        }
    }
    let lib = root.join("lib");
    if let Ok(rd) = std::fs::read_dir(&lib) {
        for e in rd.flatten() {
            let Some(name) = e.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if !name.starts_with("python") {
                continue;
            }
            let sp = e.path().join("site-packages");
            if sp.is_dir() {
                out.push(sp);
            }
        }
    }
    out
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
            false,
            DEFAULT_MAX_INSTALLED_ENTRIES,
            true,
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
        let code = scan(
            dir.path().to_str(),
            false,
            false,
            false,
            DEFAULT_MAX_INSTALLED_ENTRIES,
            true,
            true,
        );
        assert_eq!(code, 0, "a project with no flagged deps must exit 0");
    }

    #[test]
    fn scan_discovers_policy_from_scan_target_not_cwd() {
        // PR #121 fix-list item 14 regression pin — `Policy::discover` must
        // anchor at the SCAN TARGET, not cwd. Discovery-anchoring test (not
        // end-to-end): we assert the resolved policy carries the target's
        // blocklist entry, and cwd's does not.
        //
        // The marker is a `blocklist` entry (not `allowlist`): F9 neutralizes a
        // repo-scoped `allowlist`, so it would be cleared from the discovered
        // policy and could no longer prove anchoring. `blocklist` is a tightening
        // field F9 preserves at repo scope, so it survives and remains a valid
        // discovery marker.
        let target = tempdir().unwrap();
        let cwd = tempdir().unwrap();

        // Mark both as repo roots so discovery's walk-up does not climb out of
        // the tempdir into the workspace root's `.tirith/` on a dev box.
        fs::create_dir_all(target.path().join(".git")).unwrap();
        fs::create_dir_all(cwd.path().join(".git")).unwrap();

        fs::create_dir_all(target.path().join(".tirith")).unwrap();
        fs::write(
            target.path().join(".tirith").join("policy.yaml"),
            "blocklist:\n  - my-internal-pkg\n",
        )
        .unwrap();
        fs::write(
            target.path().join("Cargo.toml"),
            "[dependencies]\nmy-internal-pkg = \"1.0\"\n",
        )
        .unwrap();

        // The discovered policy from the scan target must carry the blocklist
        // entry. Anchored at the cwd (no `.tirith/`) it would not.
        let from_target = Policy::discover(target.path().to_str());
        assert!(
            from_target.blocklist.iter().any(|e| e == "my-internal-pkg"),
            "policy discovered from the scan target must carry its blocklist: \
             {:?}",
            from_target.blocklist,
        );
        let from_cwd = Policy::discover(cwd.path().to_str());
        assert!(
            !from_cwd.blocklist.iter().any(|e| e == "my-internal-pkg"),
            "policy discovered from an unrelated cwd must NOT carry the scan \
             target's blocklist: {:?}",
            from_cwd.blocklist,
        );

        // Smoke: the exported `scan` entry wires discovery — exit 0, no panic.
        // The ecosystem-scan path does not consume the URL `blocklist` (it gates
        // packages, and `my-internal-pkg` is unknown to the absent threat DB), so
        // there are no findings and the scan exits 0.
        let code = scan(
            target.path().to_str(),
            false,
            false,
            false,
            DEFAULT_MAX_INSTALLED_ENTRIES,
            true,
            true,
        );
        assert_eq!(
            code, 0,
            "ecosystem scan exits 0 (policy discovery from scan target; the \
             blocklist marker does not gate packages)"
        );
    }

    #[test]
    fn scan_max_installed_entries_out_of_range_is_usage_error() {
        let dir = tempdir().unwrap();
        // Below the minimum.
        let too_low = scan(dir.path().to_str(), false, false, true, 10, true, true);
        assert_eq!(too_low, 2, "below-min --max-installed-entries must exit 2");
        // Above the maximum.
        let too_high = scan(dir.path().to_str(), false, false, true, 300_000, true, true);
        assert_eq!(too_high, 2, "above-max --max-installed-entries must exit 2");
    }

    #[test]
    fn pick_mode_recognizes_lockfile_path_arg() {
        let dir = tempdir().unwrap();
        let lock = dir.path().join("package-lock.json");
        fs::write(&lock, "{}").unwrap();
        let mode = pick_mode(&lock, false);
        assert!(
            matches!(mode, ScanMode::SpecificLockfile(_)),
            "a single-file path-arg recognized as a lockfile must become SpecificLockfile, got {mode:?}"
        );
        let installed_wins = pick_mode(&lock, true);
        assert!(
            matches!(installed_wins, ScanMode::Installed),
            "--installed must win over a single-file path-arg, got {installed_wins:?}"
        );
    }

    #[test]
    fn pick_mode_defaults_to_manifests_for_directory() {
        let dir = tempdir().unwrap();
        let mode = pick_mode(dir.path(), false);
        assert!(
            matches!(mode, ScanMode::Manifests),
            "a directory must default to manifests mode, got {mode:?}"
        );
    }
}
