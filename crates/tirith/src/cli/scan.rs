use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};

use tirith_core::policy::Policy;
use tirith_core::scan::{self, ScanConfig};
use tirith_core::verdict::{RuleId, Severity};

// `tirith scan --profile <name>` tunes a scan for a use case. A policy
// `scan.profiles.<name>` entry overrides a same-named built-in. A built-in sets
// a default `fail_on`, an `exclude` list, and a per-rule overlay applied AFTER
// the scan — it may only suppress or re-grade findings, never invent one.

/// What a built-in profile does to one rule's findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileRuleAction {
    /// Drop every finding for this rule — the check is out of scope for the
    /// profile's use case.
    Suppress,
    /// Pin every finding for this rule to a fixed severity.
    SetSeverity(Severity),
}

/// A built-in scan profile: a default `fail_on`, scan-scope `exclude`
/// patterns, and a per-rule overlay.
struct BuiltInProfile {
    /// Default CI-failure threshold (overridden by an explicit `--fail-on`).
    fail_on: &'static str,
    /// Glob patterns excluded from the scan (merged with `--exclude`).
    exclude: &'static [&'static str],
    /// Per-rule overlay applied to the scan results.
    rule_overlay: &'static [(RuleId, ProfileRuleAction)],
}

/// Resolve a built-in profile by name, or `None`. All three default `fail_on`
/// to `high`:
/// * `ci-hardening` — pinning-gap findings kept but pinned to `medium`.
/// * `ai-agent-repo` — pinning-gap findings suppressed (low-value noise for an agent).
/// * `oss-maintainer` — pinning-gap findings downgraded to `low`.
fn built_in_profile(name: &str) -> Option<BuiltInProfile> {
    match name {
        "ci-hardening" => Some(BuiltInProfile {
            fail_on: "high",
            exclude: &[],
            rule_overlay: &[
                (
                    RuleId::WorkflowUnpinnedAction,
                    ProfileRuleAction::SetSeverity(Severity::Medium),
                ),
                (
                    RuleId::DockerfileUnpinnedImage,
                    ProfileRuleAction::SetSeverity(Severity::Medium),
                ),
            ],
        }),
        "ai-agent-repo" => Some(BuiltInProfile {
            fail_on: "high",
            exclude: &[],
            rule_overlay: &[
                (RuleId::WorkflowUnpinnedAction, ProfileRuleAction::Suppress),
                (RuleId::DockerfileUnpinnedImage, ProfileRuleAction::Suppress),
            ],
        }),
        "oss-maintainer" => Some(BuiltInProfile {
            fail_on: "high",
            exclude: &[],
            rule_overlay: &[
                (
                    RuleId::WorkflowUnpinnedAction,
                    ProfileRuleAction::SetSeverity(Severity::Low),
                ),
                (
                    RuleId::DockerfileUnpinnedImage,
                    ProfileRuleAction::SetSeverity(Severity::Low),
                ),
            ],
        }),
        _ => None,
    }
}

/// Names of every built-in profile, for help text and the unknown-profile error.
const BUILT_IN_PROFILE_NAMES: &[&str] = &["ci-hardening", "ai-agent-repo", "oss-maintainer"];

/// Apply a built-in profile's per-rule overlay: suppress or re-grade findings.
fn apply_rule_overlay(
    findings: Vec<tirith_core::verdict::Finding>,
    overlay: &[(RuleId, ProfileRuleAction)],
) -> Vec<tirith_core::verdict::Finding> {
    findings
        .into_iter()
        .filter_map(
            |mut f| match overlay.iter().find(|(rule, _)| *rule == f.rule_id) {
                Some((_, ProfileRuleAction::Suppress)) => None,
                Some((_, ProfileRuleAction::SetSeverity(sev))) => {
                    f.severity = *sev;
                    Some(f)
                }
                None => Some(f),
            },
        )
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    path: Option<&str>,
    file: Option<&str>,
    stdin: bool,
    ci: bool,
    fail_on: &str,
    json: bool,
    sarif: bool,
    ignore: &[String],
    include: &[String],
    exclude: &[String],
    profile: Option<&str>,
) -> i32 {
    let _policy_diagnostic_capture = tirith_core::policy::PolicyDiagnosticCapture::start();
    // Freeze startup diagnostics against the explicitly requested target's
    // effective policy, not the caller's cwd. A missing target is anchored at
    // its nearest canonical existing ancestor so its repository policy still
    // governs path-shaped secrets. The caller plan is unioned only as a
    // presentation-strengthening measure; an unsafe target resolution makes the
    // whole dynamic diagnostic value fail closed.
    let explicit_target = file.or(path).map(Path::new);
    let diagnostic_patterns = early_diagnostic_dlp_patterns(explicit_target);
    tirith_core::policy::freeze_captured_policy_dlp_patterns(&diagnostic_patterns);
    let diagnostic_compiled =
        tirith_core::redact::CompiledCustomPatterns::new_silent(&diagnostic_patterns);
    let mut effective_include: Vec<String> = include.to_vec();
    let mut effective_exclude: Vec<String> = exclude.to_vec();
    let mut effective_ignore: Vec<String> = ignore.to_vec();
    let mut effective_fail_on = fail_on.to_string();
    // Per-rule overlay from a resolved built-in profile (empty otherwise).
    let mut rule_overlay: Vec<(RuleId, ProfileRuleAction)> = Vec::new();

    if let Some(profile_name) = profile {
        let policy = Policy::discover(None);
        let policy_profile = policy.scan.profiles.get(profile_name);
        let built_in = built_in_profile(profile_name);

        if let Some(scan_profile) = policy_profile {
            // A policy profile entry — the user's policy wins over a built-in.
            if effective_include.is_empty() {
                effective_include = scan_profile.include.clone();
            }
            if effective_exclude.is_empty() {
                effective_exclude = scan_profile.exclude.clone();
            }
            if effective_ignore.is_empty() {
                effective_ignore = scan_profile.ignore.clone();
            }
            // Profile fail_on applies only at the CLI default.
            if fail_on == "critical" {
                if let Some(ref profile_fail_on) = scan_profile.fail_on {
                    effective_fail_on = profile_fail_on.clone();
                }
            }
        } else if let Some(bp) = &built_in {
            if effective_exclude.is_empty() {
                effective_exclude = bp.exclude.iter().map(|s| s.to_string()).collect();
            }
            if fail_on == "critical" {
                effective_fail_on = bp.fail_on.to_string();
            }
            rule_overlay = bp.rule_overlay.to_vec();
        } else {
            let profile_name = tirith_core::output::sanitize_human_field_with_compiled(
                profile_name,
                &diagnostic_compiled,
            );
            let mut human = tirith_core::output::HumanInvocationWriter::new(
                std::io::stderr().lock(),
                tirith_core::style::use_color_for(tirith_core::style::Stream::Stderr),
            );
            let _ = writeln!(
                human,
                "tirith scan: warning: profile '{profile_name}' not found — built-in profiles are: {}",
                BUILT_IN_PROFILE_NAMES.join(", ")
            );
            let _ = human.finish();
        }
    }

    let fail_on_severity = parse_severity(&effective_fail_on, &diagnostic_compiled);

    if stdin {
        return run_stdin(json, sarif, ci, fail_on_severity, &rule_overlay);
    }

    if let Some(file_path) = file {
        // An explicitly requested target is part of the CLI contract, not an
        // optional discovery location. Validate it before include/exclude/ignore
        // filters so a missing target can never turn into a successful no-op.
        if !explicit_target_exists(
            std::path::Path::new(file_path),
            "file",
            &diagnostic_compiled,
        ) {
            return 1;
        }
        if should_skip_file(
            file_path,
            &effective_include,
            &effective_exclude,
            &effective_ignore,
        ) {
            return 0;
        }
        return run_single_file(file_path, json, sarif, ci, fail_on_severity, &rule_overlay);
    }

    let scan_path = path
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    // The default current-directory scan remains best-effort discovery, but an
    // explicitly supplied positional target must exist. In particular, do not
    // route a missing path into the directory collector and report a clean
    // zero-file scan.
    if path.is_some() && !explicit_target_exists(&scan_path, "path", &diagnostic_compiled) {
        return 1;
    }

    if scan_path.is_file() {
        let path_str = scan_path.display().to_string();
        if should_skip_file(
            &path_str,
            &effective_include,
            &effective_exclude,
            &effective_ignore,
        ) {
            return 0;
        }
        return run_single_file(&path_str, json, sarif, ci, fail_on_severity, &rule_overlay);
    }

    let config = ScanConfig {
        path: scan_path,
        recursive: true,
        fail_on: fail_on_severity,
        ignore_patterns: effective_ignore,
        include_patterns: effective_include,
        exclude_patterns: effective_exclude,
        max_files: None,
    };

    let mut result = scan::scan(&config);
    // Preserve analyzer-originated incompleteness before a presentation profile
    // can suppress or transform its finding.
    let analyzer_incomplete = result.analysis_incomplete();
    // Apply the overlay before output and the exit-code decision, so CI sees the
    // profile's verdict. `scanned_count` is left untouched.
    if !rule_overlay.is_empty() {
        for file_result in &mut result.file_results {
            let findings = std::mem::take(&mut file_result.findings);
            file_result.findings = apply_rule_overlay(findings, &rule_overlay);
        }
    }

    // A2 — assemble the driver-level `AnalysisIncomplete` findings from the
    // recorded coverage gaps and attach each to a synthetic file entry (its
    // gap path) so it flows through the existing JSON/SARIF/human emitters and is
    // counted by `total_findings` / `has_findings_at_or_above`. Done BEFORE the
    // exit decision so a Fail-action gap can drive a non-zero code.
    // Discover policy from the SCAN TARGET (not the caller's cwd) so scanning another
    // tree applies THAT tree's repo policy to the AnalysisIncomplete synthesis and CI
    // coverage decision, consistent with the engine's own discovery.
    let scan_root = config.path.display().to_string();
    let policy = Policy::discover(Some(&scan_root));
    tirith_core::policy::freeze_captured_policy_dlp_patterns(&policy.dlp_custom_patterns);
    let compiled_dlp =
        tirith_core::redact::CompiledCustomPatterns::new_silent(&policy.dlp_custom_patterns);
    let dlp_incomplete = compiled_dlp.incomplete_reason().is_some();
    // Each finding is paired with the EXACT `SubjectLocation` of its gap, so the
    // file entry resolves to that gap's own path by exact equality. Matching back
    // by a substring of the finding's description is WRONG: one gap's location can
    // be a prefix of another's (`/a/b.so` vs `/a/b.so.bak`), so a substring match
    // mislabels the finding. The human/JSON output reads the per-file `path`.
    let coverage_findings =
        scan::build_analysis_incomplete_findings_located(&result.coverage_gaps, &policy);
    for (location, finding) in coverage_findings {
        // Preserve the gap's member-qualified location (`outer.whl!/member`) so the
        // synthetic finding attributes to the exact member, not just the outer
        // container; the rendered form matches the coverage gap's own location. A
        // non-member gap keeps its real on-disk path (outer, else installed, else root).
        let path = if location.member_path.is_some() {
            PathBuf::from(location.to_string())
        } else {
            location
                .outer_path
                .clone()
                .or_else(|| location.installed_path.clone())
                .unwrap_or_else(|| config.path.clone())
        };
        // A PDF analyzer gap already has its precise analyzer-originated
        // `AnalysisIncomplete` finding. Keep the typed root gap, but do not add
        // a second generic row for the same file unless an output overlay
        // removed the original finding.
        let analyzer_finding_already_present = result.coverage_gaps.iter().any(|gap| {
            gap.location == location && gap.kind == scan::CoverageGapKind::PdfAnalyzerIncomplete
        }) && result
            .file_results
            .iter()
            .any(|file| file.path == path && file.has_analysis_incomplete_finding());
        if analyzer_finding_already_present {
            continue;
        }
        result.file_results.push(scan::FileScanResult {
            path,
            findings: vec![finding],
            is_config_file: false,
            coverage_gaps: Vec::new(),
        });
    }

    let analysis_incomplete =
        result.truncated || !result.coverage_gaps.is_empty() || analyzer_incomplete;
    let decision_has_findings_at_or_above = result.has_findings_at_or_above(fail_on_severity);
    let decision_total_findings = result.total_findings();
    for file_result in &mut result.file_results {
        tirith_core::redact::redact_findings_with_compiled(
            &mut file_result.findings,
            &compiled_dlp,
        );
    }

    // A JSON/SARIF write failure must surface exit 1 instead of a `0` paired
    // with truncated output; a finding-driven non-zero code is kept.
    let mut panic_reported_human = false;
    let output_ok = if sarif {
        print_sarif_result(
            &result,
            analysis_incomplete,
            decision_total_findings,
            &compiled_dlp,
            dlp_incomplete,
        )
    } else if json {
        print_json_result(
            &result,
            analysis_incomplete,
            decision_total_findings,
            &compiled_dlp,
            dlp_incomplete,
        )
    } else {
        if !ci {
            let mut human = tirith_core::output::HumanInvocationWriter::new(
                std::io::stderr().lock(),
                tirith_core::style::use_color_for(tirith_core::style::Stream::Stderr),
            );
            let mut failed = false;
            failed |= write_policy_diagnostics_human(&compiled_dlp, &mut human).is_err();
            if let Some(reason) = compiled_dlp.incomplete_reason() {
                failed |= writeln!(
                    human,
                    "tirith scan: WARNING: DLP redaction plan is incomplete ({reason}); dynamic output fields were fully redacted."
                )
                .is_err();
            }
            failed |=
                print_human_result(&result, decision_total_findings, &compiled_dlp, &mut human)
                    .is_err();
            failed |= print_coverage_gaps_human(&result.coverage_gaps, &compiled_dlp, &mut human)
                .is_err();
            if !result.panic_files.is_empty() {
                panic_reported_human = true;
                failed |= writeln!(
                    human,
                    "tirith scan: WARNING: incomplete scan — {} file(s) were skipped because a rule panicked; results may be missing.",
                    result.panic_files.len()
                )
                .is_err();
            }
            failed |= human.finish().is_err();
            if failed {
                return 1;
            }
        }
        true
    };

    // Always surface a panic-incomplete scan (a subset of skipped files). Goes
    // to stderr so it never corrupts --json/--sarif stdout.
    if !result.panic_files.is_empty() && !panic_reported_human {
        eprintln!(
            "tirith scan: WARNING: incomplete scan — {} file(s) were skipped because a rule \
             panicked (see messages above); results may be missing.",
            result.panic_files.len()
        );
        if ci {
            eprintln!("tirith scan: --ci: treating an incomplete scan as a failure.");
        }
    }

    // CI fail-closed on incompleteness: the existing panic rule, PLUS a
    // security-relevant gap under `require_complete`, PLUS any gap whose effective
    // action is Fail.
    let ci_coverage_fail = ci
        && (!result.panic_files.is_empty()
            || coverage_requires_failure(&result.coverage_gaps, &policy));

    if decision_has_findings_at_or_above {
        1
    } else if ci_coverage_fail {
        // Fail closed in CI: an incomplete scan must not report success.
        1
    } else if ci {
        // repo-0230: under --ci, findings BELOW --fail-on must not fail the
        // build — every non-zero code is a failure in CI systems, so the
        // legacy "2 = findings below threshold" makes `--fail-on high` fail on
        // Low/Medium noise.
        if !output_ok {
            1
        } else {
            0
        }
    } else if decision_total_findings > 0 {
        2
    } else if !output_ok {
        1
    } else {
        0
    }
}

fn run_stdin(
    json: bool,
    sarif: bool,
    ci: bool,
    fail_on: Severity,
    rule_overlay: &[(RuleId, ProfileRuleAction)],
) -> i32 {
    const MAX_STDIN: u64 = 10 * 1024 * 1024;

    let mut raw_bytes = Vec::new();
    if let Err(e) = std::io::stdin()
        .take(MAX_STDIN + 1)
        .read_to_end(&mut raw_bytes)
    {
        eprintln!("tirith scan: failed to read stdin: {e}");
        return 1;
    }
    if raw_bytes.len() as u64 > MAX_STDIN {
        eprintln!("tirith scan: stdin exceeds 10 MiB limit");
        eprintln!("  try: tirith scan --file /path/to/file  (scan the file directly)");
        return 1;
    }
    if raw_bytes.is_empty() {
        return 0;
    }

    let content = String::from_utf8_lossy(&raw_bytes).into_owned();
    let mut result = scan::scan_stdin(&content, &raw_bytes);
    let analysis_incomplete = result.analysis_incomplete();
    let coverage_gaps = result.coverage_gaps.clone();
    if !rule_overlay.is_empty() {
        result.findings = apply_rule_overlay(std::mem::take(&mut result.findings), rule_overlay);
    }
    let decision_has_findings_at_or_above = result.findings.iter().any(|f| f.severity >= fail_on);
    let decision_has_findings = !result.findings.is_empty();
    let decision_total_findings = result.findings.len();
    let policy = Policy::discover(None);
    tirith_core::policy::freeze_captured_policy_dlp_patterns(&policy.dlp_custom_patterns);
    let compiled_dlp =
        tirith_core::redact::CompiledCustomPatterns::new_silent(&policy.dlp_custom_patterns);
    let dlp_incomplete = compiled_dlp.incomplete_reason().is_some();
    tirith_core::redact::redact_findings_with_compiled(&mut result.findings, &compiled_dlp);
    tirith_core::verdict::bound_findings_for_output(&mut result.findings);

    // Parser-originated coverage can still be incomplete for stdin even though
    // there is no filesystem path; retain its synthetic `<stdin>` location.
    // Write failure must not be a `0` success — see `run`.
    let output_ok = if sarif {
        print_sarif_file_result(
            &result,
            &coverage_gaps,
            analysis_incomplete,
            decision_total_findings,
            &compiled_dlp,
            dlp_incomplete,
        )
    } else if json {
        print_json_file_result(
            &result,
            &coverage_gaps,
            analysis_incomplete,
            &compiled_dlp,
            dlp_incomplete,
        )
    } else {
        if !ci {
            let mut human = tirith_core::output::HumanInvocationWriter::new(
                std::io::stderr().lock(),
                tirith_core::style::use_color_for(tirith_core::style::Stream::Stderr),
            );
            let mut failed = false;
            failed |= write_policy_diagnostics_human(&compiled_dlp, &mut human).is_err();
            if let Some(reason) = compiled_dlp.incomplete_reason() {
                failed |= writeln!(
                    human,
                    "tirith scan: WARNING: DLP redaction plan is incomplete ({reason}); dynamic output fields were fully redacted."
                )
                .is_err();
            }
            failed |= print_human_file_result(&result, &compiled_dlp, &mut human).is_err();
            failed |= print_coverage_gaps_human(&coverage_gaps, &compiled_dlp, &mut human).is_err();
            failed |= human.finish().is_err();
            if failed {
                return 1;
            }
        }
        true
    };

    let ci_coverage_fail = ci && coverage_requires_failure(&coverage_gaps, &policy);
    if decision_has_findings_at_or_above || ci_coverage_fail {
        1
    } else if decision_has_findings {
        2
    } else if !output_ok {
        1
    } else {
        0
    }
}

fn run_single_file(
    file_path: &str,
    json: bool,
    sarif: bool,
    ci: bool,
    fail_on: Severity,
    rule_overlay: &[(RuleId, ProfileRuleAction)],
) -> i32 {
    let path = PathBuf::from(file_path);
    // Discover policy from the scanned FILE's directory (not the caller's cwd)
    // before diagnostics so a raced-away target path is still bounded and
    // redacted with the same snapshot as the scan.
    let file_dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.display().to_string(),
        _ => ".".to_string(),
    };
    let policy = Policy::discover(Some(&file_dir));
    tirith_core::policy::freeze_captured_policy_dlp_patterns(&policy.dlp_custom_patterns);
    let compiled_dlp =
        tirith_core::redact::CompiledCustomPatterns::new_silent(&policy.dlp_custom_patterns);
    let dlp_incomplete = compiled_dlp.incomplete_reason().is_some();
    if !path.exists() {
        let mut human = tirith_core::output::HumanInvocationWriter::new(
            std::io::stderr().lock(),
            tirith_core::style::use_color_for(tirith_core::style::Stream::Stderr),
        );
        let shown =
            tirith_core::output::sanitize_human_field_with_compiled(file_path, &compiled_dlp);
        let _ = writeln!(human, "tirith scan: file not found: {shown}");
        let _ = writeln!(human, "  try: tirith scan ./  (scan the current directory)");
        let _ = human.finish();
        return 1;
    }

    // Route through the guarded scan so a coverage gap (oversized / unreadable /
    // unsupported artifact / hash-budget) or a rule panic carries a reason into
    // the JSON/SARIF/exit path instead of being read as "clean".
    use scan::{CoverageGap, FileScanResult, GuardedScanOutcome, ScanFileOutcome};
    let outcome = scan::scan_single_file_guarded(&path);
    // A RulePanic must fail `--ci` UNCONDITIONALLY (matching the directory path), so
    // capture it before the outcome is consumed by the match below.
    let was_panic = matches!(outcome, GuardedScanOutcome::RulePanic(_));
    let (mut result, coverage_gaps): (FileScanResult, Vec<CoverageGap>) = match outcome {
        GuardedScanOutcome::Completed(ScanFileOutcome::Scanned(r)) => {
            let coverage_gaps = r.coverage_gaps.clone();
            (r, coverage_gaps)
        }
        GuardedScanOutcome::Completed(ScanFileOutcome::Skipped(gap))
        | GuardedScanOutcome::RulePanic(gap) => {
            // No analyzed content: synthesize a result carrying only the
            // driver-assembled `AnalysisIncomplete` findings (if the gap is
            // security-relevant and not policy-ignored) so the gap surfaces in
            // every output and the exit code.
            let findings =
                scan::build_analysis_incomplete_findings(std::slice::from_ref(&gap), &policy);
            (
                FileScanResult {
                    path: path.clone(),
                    findings,
                    is_config_file: false,
                    coverage_gaps: Vec::new(),
                },
                vec![gap],
            )
        }
    };
    let analyzer_incomplete = result.analysis_incomplete();
    if !rule_overlay.is_empty() {
        result.findings = apply_rule_overlay(std::mem::take(&mut result.findings), rule_overlay);
    }
    let decision_has_findings_at_or_above = result.findings.iter().any(|f| f.severity >= fail_on);
    let decision_has_findings = !result.findings.is_empty();
    let decision_total_findings = result.findings.len();
    tirith_core::redact::redact_findings_with_compiled(&mut result.findings, &compiled_dlp);
    tirith_core::verdict::bound_findings_for_output(&mut result.findings);

    let analysis_incomplete = !coverage_gaps.is_empty() || analyzer_incomplete;

    // Write failure must not be a `0` success — see `run`.
    let output_ok = if sarif {
        print_sarif_file_result(
            &result,
            &coverage_gaps,
            analysis_incomplete,
            decision_total_findings,
            &compiled_dlp,
            dlp_incomplete,
        )
    } else if json {
        print_json_file_result(
            &result,
            &coverage_gaps,
            analysis_incomplete,
            &compiled_dlp,
            dlp_incomplete,
        )
    } else {
        if !ci {
            let mut human = tirith_core::output::HumanInvocationWriter::new(
                std::io::stderr().lock(),
                tirith_core::style::use_color_for(tirith_core::style::Stream::Stderr),
            );
            let mut failed = false;
            failed |= write_policy_diagnostics_human(&compiled_dlp, &mut human).is_err();
            if let Some(reason) = compiled_dlp.incomplete_reason() {
                failed |= writeln!(
                    human,
                    "tirith scan: WARNING: DLP redaction plan is incomplete ({reason}); dynamic output fields were fully redacted."
                )
                .is_err();
            }
            failed |= print_human_file_result(&result, &compiled_dlp, &mut human).is_err();
            failed |= print_coverage_gaps_human(&coverage_gaps, &compiled_dlp, &mut human).is_err();
            failed |= human.finish().is_err();
            if failed {
                return 1;
            }
        }
        true
    };

    // CI fail-closed on incompleteness: a security-relevant gap under
    // `require_complete`, or any gap whose effective action is Fail.
    let ci_coverage_fail = ci && (was_panic || coverage_requires_failure(&coverage_gaps, &policy));

    if decision_has_findings_at_or_above || ci_coverage_fail {
        1
    } else if decision_has_findings {
        2
    } else if !output_ok {
        1
    } else {
        0
    }
}

/// Whether a set of coverage gaps must FAIL a CI run under `policy`: an
/// intrinsically security-relevant directory-enumeration failure always fails;
/// otherwise `scan.require_complete` must be set with a security-relevant gap, or
/// a SECURITY-RELEVANT gap must have effective [`GapAction::Fail`].
/// The policy-driven conditions gate on security-relevance so the exit decision matches the
/// AnalysisIncomplete finding assembly (which only emits for security-relevant gaps) -
/// the scan never exits non-zero with an empty findings list. Shared by the directory
/// and single-file paths so both fail closed identically.
fn coverage_requires_failure(gaps: &[scan::CoverageGap], policy: &Policy) -> bool {
    use tirith_core::policy::GapAction;
    // A failed directory enumeration hides an unknown set of paths before their
    // kinds can be classified. `--ci` therefore fails on it unconditionally,
    // including when an operator policy ignores ordinary unreadable files.
    if gaps
        .iter()
        .any(|g| g.kind == scan::CoverageGapKind::EnumerationFailed)
    {
        return true;
    }
    // `require_complete` fails on a security-relevant gap, BUT a per-kind `Ignore` action is
    // an explicit operator override for that kind: an Ignore'd gap produces no
    // AnalysisIncomplete finding, so it must not fail the run either (else exit 1 pairs with
    // zero findings). Both this gate and the Fail-action one below exclude Ignore'd gaps, so
    // the exit decision always matches the findings list.
    if policy.scan.require_complete
        && gaps.iter().any(|g| {
            scan::gap_is_security_relevant(g)
                && policy.scan.action_for_gap_kind(g.kind) != GapAction::Ignore
        })
    {
        return true;
    }
    // A Fail-action gap fails the run ONLY when it is security-relevant. Without this gate,
    // a non-security-relevant gap with a Fail action (e.g. an oversized benign `notes.txt`
    // under `oversized_file_action: fail`) exits 1 with ZERO findings, since finding
    // assembly skips non-security-relevant gaps - a self-inconsistent exit-code/findings
    // pair for a CI consumer.
    gaps.iter().any(|g| {
        scan::gap_is_security_relevant(g)
            && policy.scan.action_for_gap_kind(g.kind) == GapAction::Fail
    })
}

const FAIL_CLOSED_DIAGNOSTIC_DLP_PATTERN: &str = "(?s).+";

/// Resolve the DLP plan for diagnostics emitted before the scan target itself
/// can be opened. An explicit target owns the primary plan; the caller's plan is
/// retained as a union so diagnostics produced while resolving either snapshot
/// cannot be weakened by switching repositories.
fn early_diagnostic_dlp_patterns(explicit_target: Option<&Path>) -> Vec<String> {
    let caller_policy = Policy::discover(None);
    let Some(target) = explicit_target else {
        return caller_policy.dlp_custom_patterns;
    };

    let Some(anchor) = nearest_existing_policy_anchor(target) else {
        return vec![FAIL_CLOSED_DIAGNOSTIC_DLP_PATTERN.to_string()];
    };
    let Some(anchor) = anchor.to_str() else {
        return vec![FAIL_CLOSED_DIAGNOSTIC_DLP_PATTERN.to_string()];
    };
    let target_policy = Policy::discover(Some(anchor));

    combine_early_diagnostic_dlp_patterns(&caller_policy, &target_policy)
}

fn combine_early_diagnostic_dlp_patterns(
    caller_policy: &Policy,
    target_policy: &Policy,
) -> Vec<String> {
    // A named policy that cannot be read/parsed, or a remote-policy failure in
    // closed mode, is represented by Policy's explicit fail-closed snapshot.
    // It carries no trustworthy custom patterns, so redact every dynamic field
    // rather than reconstructing a secret while formatting the error path.
    if caller_policy.path.as_deref() == Some("fail-closed")
        || target_policy.path.as_deref() == Some("fail-closed")
    {
        return vec![FAIL_CLOSED_DIAGNOSTIC_DLP_PATTERN.to_string()];
    }

    let mut patterns = target_policy.dlp_custom_patterns.clone();
    for pattern in &caller_policy.dlp_custom_patterns {
        if !patterns.contains(pattern) {
            patterns.push(pattern.clone());
        }
    }
    patterns
}

/// Return the canonical directory from which target policy discovery should
/// start. Missing suffixes are peeled one component at a time; any error other
/// than absence is ambiguous (permissions, symlink loop, raced metadata) and
/// therefore fails closed instead of falling back to the caller's cwd.
fn nearest_existing_policy_anchor(target: &Path) -> Option<PathBuf> {
    let absolute = if target.is_absolute() {
        target.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(target)
    };
    let mut candidate = absolute.as_path();

    loop {
        match std::fs::metadata(candidate) {
            Ok(metadata) => {
                let canonical = std::fs::canonicalize(candidate).ok()?;
                return if metadata.is_dir() {
                    Some(canonical)
                } else {
                    canonical.parent().map(Path::to_path_buf)
                };
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return None,
        }
        candidate = candidate.parent()?;
    }
}

/// Check an explicitly named CLI scan target without following a missing target
/// into the best-effort collection path. `try_exists` also distinguishes an I/O
/// failure from absence for useful diagnostics; both are operational errors.
fn explicit_target_exists(
    path: &std::path::Path,
    target_kind: &str,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> bool {
    match path.try_exists() {
        Ok(true) => true,
        Ok(false) => {
            // The target is an argument, so it can carry terminal control
            // sequences that would rewrite this diagnostic.
            let shown = tirith_core::output::sanitize_human_field_with_compiled(
                &path.display().to_string(),
                compiled,
            );
            let mut human = tirith_core::output::HumanInvocationWriter::new(
                std::io::stderr().lock(),
                tirith_core::style::use_color_for(tirith_core::style::Stream::Stderr),
            );
            let _ = writeln!(human, "tirith scan: {target_kind} not found: {shown}");
            let _ = writeln!(human, "  try: tirith scan ./  (scan the current directory)");
            let _ = human.finish();
            false
        }
        Err(error) => {
            let shown = tirith_core::output::sanitize_human_field_with_compiled(
                &path.display().to_string(),
                compiled,
            );
            let error = tirith_core::output::sanitize_human_field_with_compiled(
                &error.to_string(),
                compiled,
            );
            let mut human = tirith_core::output::HumanInvocationWriter::new(
                std::io::stderr().lock(),
                tirith_core::style::use_color_for(tirith_core::style::Stream::Stderr),
            );
            let _ = writeln!(
                human,
                "tirith scan: cannot access requested {target_kind} {shown}: {error}"
            );
            let _ = human.finish();
            false
        }
    }
}

/// Print coverage gaps to stderr for the human output path (so `--json`/SARIF
/// stdout stays uncorrupted). A no-op when there are none.
fn print_coverage_gaps_human(
    gaps: &[scan::CoverageGap],
    compiled: &tirith_core::redact::CompiledCustomPatterns,
    writer: &mut tirith_core::output::HumanInvocationWriter<impl std::io::Write>,
) -> std::io::Result<()> {
    if gaps.is_empty() {
        return Ok(());
    }
    writeln!(
        writer,
        "tirith scan: {} coverage gap(s) — file(s) not fully analyzed:",
        gaps.len()
    )?;
    for gap in gaps {
        // A coverage-gap location is an attacker-controlled file name from the scanned
        // tree; neutralize terminal controls and deceptive/invisible Unicode so a
        // malicious name cannot forge or visually reorder tirith's OWN stderr.
        writeln!(
            writer,
            "  {} ({})",
            sanitize_location_for_terminal(&gap.location.to_string(), compiled),
            gap.kind.as_str()
        )?;
        if writer.is_truncated() {
            break;
        }
    }
    Ok(())
}

/// Project an attacker-controlled location through the shared single-line human-output
/// sanitizer before it is printed to a terminal. This removes terminal control sequences,
/// line breaks, bidi overrides, and deceptive/invisible Unicode while preserving ordinary
/// printable non-ASCII paths.
fn sanitize_location_for_terminal(
    loc: &str,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> String {
    tirith_core::output::sanitize_human_field_with_compiled(loc, compiled)
}

fn parse_severity(s: &str, compiled: &tirith_core::redact::CompiledCustomPatterns) -> Severity {
    match s.to_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => {
            let shown = tirith_core::output::sanitize_human_field_with_compiled(s, compiled);
            let mut human = tirith_core::output::HumanInvocationWriter::new(
                std::io::stderr().lock(),
                tirith_core::style::use_color_for(tirith_core::style::Stream::Stderr),
            );
            let _ = writeln!(
                human,
                "tirith scan: warning: unknown severity '{shown}', defaulting to critical"
            );
            let _ = human.finish();
            Severity::Critical
        }
    }
}

/// Emit a directory-scan result as JSON. Returns `false` on a write failure so
/// the caller can exit non-zero (no truncated JSON with a success code).
fn print_json_result(
    result: &scan::ScanResult,
    analysis_incomplete: bool,
    original_total_findings: usize,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
    dlp_redaction_incomplete: bool,
) -> bool {
    let mut base = serde_json::json!({
        "schema_version": 5,
        "scanned_count": result.scanned_count,
        "skipped_count": result.skipped_count,
        "truncated": result.truncated,
        "truncation_reason": result.truncation_reason.as_deref(),
        "panic_count": result.panic_files.len(),
        "panic_files": [],
        "total_findings": original_total_findings,
        "analysis_incomplete": analysis_incomplete,
        "scan_analysis_incomplete": analysis_incomplete,
        "coverage_gaps": [],
        "files": [],
        "dlp_redaction_incomplete": dlp_redaction_incomplete,
    });
    append_policy_diagnostics_json(&mut base, compiled);
    tirith_core::redact::redact_json_strings(&mut base, compiled);
    let mut projection = tirith_core::verdict::BoundedJsonProjection::new(base);
    for rank in 0..3 {
        for (file_index, file) in result.file_results.iter().enumerate() {
            for finding in &file.findings {
                if json_finding_rank(finding) != rank {
                    continue;
                }
                let mut item = serde_json::json!({
                    "path": file.path.display().to_string(),
                    "is_config_file": file.is_config_file,
                    "_projection_file_id": file_index,
                    "findings": [finding],
                });
                tirith_core::redact::redact_json_strings(&mut item, compiled);
                let _ = projection.push_array_item("files", item, 1);
            }
        }
        if rank == 1 {
            for path in &result.panic_files {
                let path = tirith_core::redact::redact_sanitize_redact_with_compiled(
                    &path.display().to_string(),
                    compiled,
                );
                let _ =
                    projection.push_array_item("panic_files", serde_json::Value::String(path), 1);
            }
            for gap in &result.coverage_gaps {
                let mut gap = serde_json::to_value(JsonCoverageGap::from(gap))
                    .unwrap_or(serde_json::Value::Null);
                tirith_core::redact::redact_json_strings(&mut gap, compiled);
                let _ = projection.push_array_item("coverage_gaps", gap, 1);
            }
        }
    }
    let mut output = projection.finish();
    tirith_core::verdict::regroup_file_finding_projection(&mut output);
    super::write_json_stdout(&output, "tirith scan: failed to write JSON output")
}

fn json_finding_rank(finding: &tirith_core::verdict::Finding) -> u8 {
    if finding.severity == Severity::Critical {
        0
    } else if finding.severity == Severity::High || finding.rule_id == RuleId::AnalysisIncomplete {
        1
    } else {
        2
    }
}

/// Emit a single-file scan result as JSON. Returns `false` on a JSON-write
/// failure. Carries coverage gaps / `analysis_incomplete` so a skipped single
/// file is never read as clean by a `--json` consumer.
fn print_json_file_result(
    result: &scan::FileScanResult,
    coverage_gaps: &[scan::CoverageGap],
    analysis_incomplete: bool,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
    dlp_redaction_incomplete: bool,
) -> bool {
    #[derive(serde::Serialize)]
    struct JsonOutput<'a> {
        schema_version: u32,
        path: String,
        is_config_file: bool,
        findings: &'a [tirith_core::verdict::Finding],
        analysis_incomplete: bool,
        coverage_gaps: Vec<JsonCoverageGap>,
        dlp_redaction_incomplete: bool,
    }

    let output = JsonOutput {
        schema_version: 4,
        path: tirith_core::redact::redact_sanitize_redact_with_compiled(
            &result.path.display().to_string(),
            compiled,
        ),
        is_config_file: result.is_config_file,
        findings: &result.findings,
        analysis_incomplete,
        coverage_gaps: coverage_gaps
            .iter()
            .map(|gap| {
                let mut projected = JsonCoverageGap::from(gap);
                projected.location = tirith_core::redact::redact_sanitize_redact_with_compiled(
                    &projected.location,
                    compiled,
                );
                if let Some(sha256) = projected.sha256.as_mut() {
                    *sha256 =
                        tirith_core::redact::redact_sanitize_redact_with_compiled(sha256, compiled);
                }
                projected
            })
            .collect(),
        dlp_redaction_incomplete,
    };

    let output = match serde_json::to_value(output) {
        Ok(mut value) => {
            append_policy_diagnostics_json(&mut value, compiled);
            tirith_core::redact::redact_json_strings(&mut value, compiled);
            tirith_core::verdict::bound_json_value_for_output(value)
        }
        Err(error) => {
            eprintln!("tirith scan: failed to serialize JSON output: {error}");
            return false;
        }
    };
    super::write_json_stdout(&output, "tirith scan: failed to write JSON output")
}

/// JSON shape for one coverage gap, shared by the directory and single-file
/// outputs: the member-qualified location, the kind, and a best-effort sha256.
#[derive(serde::Serialize)]
struct JsonCoverageGap {
    location: String,
    kind: &'static str,
    security_relevant: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
}

impl From<&scan::CoverageGap> for JsonCoverageGap {
    fn from(gap: &scan::CoverageGap) -> Self {
        JsonCoverageGap {
            location: gap.location.to_string(),
            kind: gap.kind.as_str(),
            security_relevant: scan::gap_is_security_relevant(gap),
            sha256: gap.sha256.clone(),
        }
    }
}

fn print_human_result(
    result: &scan::ScanResult,
    original_total_findings: usize,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
    writer: &mut tirith_core::output::HumanInvocationWriter<impl std::io::Write>,
) -> std::io::Result<()> {
    let total = original_total_findings;
    let files_with_findings = result
        .file_results
        .iter()
        .filter(|r| !r.findings.is_empty())
        .count();

    if total == 0 {
        writeln!(
            writer,
            "tirith scan: {} files scanned, no issues found",
            result.scanned_count
        )?;
        return Ok(());
    }

    write!(
        writer,
        "tirith scan: {} files scanned, {} finding(s) in {} file(s)",
        result.scanned_count, total, files_with_findings
    )?;

    for file_result in &result.file_results {
        if file_result.findings.is_empty() {
            continue;
        }
        let label = if file_result.is_config_file {
            " [AI config]"
        } else {
            ""
        };
        write!(
            writer,
            "\n\n  {}{label}",
            tirith_core::output::sanitize_human_field_with_compiled(
                &file_result.path.display().to_string(),
                compiled
            )
        )?;
        for finding in &file_result.findings {
            let severity = tirith_core::style::severity_label(
                &finding.severity,
                tirith_core::style::Stream::Stderr,
            );
            write!(
                writer,
                "\n    {} {} — {}",
                severity,
                finding.rule_id,
                tirith_core::output::sanitize_human_field_with_compiled(&finding.title, compiled)
            )?;
            if writer.is_truncated() {
                break;
            }
        }
        if writer.is_truncated() {
            break;
        }
    }

    if result.truncated {
        if let Some(ref reason) = result.truncation_reason {
            let reason = tirith_core::output::sanitize_human_field_with_compiled(reason, compiled);
            let styled = tirith_core::style::dim(&reason, tirith_core::style::Stream::Stderr);
            write!(writer, "\n\n  {styled}")?;
        }
    }
    writeln!(writer)?;
    Ok(())
}

fn write_policy_diagnostics_human(
    compiled: &tirith_core::redact::CompiledCustomPatterns,
    writer: &mut tirith_core::output::HumanInvocationWriter<impl std::io::Write>,
) -> std::io::Result<()> {
    for diagnostic in tirith_core::policy::drain_captured_policy_diagnostics_for_output(compiled) {
        let diagnostic =
            tirith_core::output::sanitize_human_field_with_compiled(&diagnostic, compiled);
        writeln!(writer, "tirith scan: policy diagnostic: {diagnostic}")?;
    }
    Ok(())
}

fn append_policy_diagnostics_json(
    value: &mut serde_json::Value,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) {
    let diagnostics = tirith_core::policy::drain_captured_policy_diagnostics_for_output(compiled);
    if diagnostics.is_empty() {
        return;
    }
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "policy_diagnostics_count".to_string(),
            diagnostics.len().into(),
        );
        object.insert(
            "policy_diagnostics".to_string(),
            serde_json::json!(diagnostics),
        );
    }
}

const MAX_SARIF_POLICY_DIAGNOSTICS: usize = 8;
const MAX_SARIF_POLICY_DIAGNOSTIC_BYTES: usize = 2 * 1024;

#[derive(Default)]
struct SarifPolicyDiagnostics {
    total_count: usize,
    messages: Vec<String>,
    omitted_messages: usize,
    truncated_messages: usize,
    omitted_bytes: usize,
}

impl SarifPolicyDiagnostics {
    fn presentation_truncated(&self) -> bool {
        self.omitted_messages > 0 || self.truncated_messages > 0
    }
}

/// Drain policy diagnostics into the single SARIF document. The policy capture
/// already applies the frozen invocation DLP plan; the mandatory second
/// redact-sanitize-redact projection here keeps this boundary correct even if a
/// future capture implementation returns a less-processed representation.
fn take_sarif_policy_diagnostics(
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> SarifPolicyDiagnostics {
    let diagnostics = tirith_core::policy::drain_captured_policy_diagnostics_for_output(compiled);
    let total_count = diagnostics.len();
    let mut messages = Vec::with_capacity(total_count.min(MAX_SARIF_POLICY_DIAGNOSTICS));
    let mut omitted_messages = 0usize;
    let mut truncated_messages = 0usize;
    let mut omitted_bytes = 0usize;
    for (index, diagnostic) in diagnostics.into_iter().enumerate() {
        if index >= MAX_SARIF_POLICY_DIAGNOSTICS {
            omitted_messages += 1;
            omitted_bytes = omitted_bytes.saturating_add(diagnostic.len());
            continue;
        }
        let projected =
            tirith_core::redact::redact_sanitize_redact_with_compiled(&diagnostic, compiled);
        let (projected, message_omitted_bytes) =
            cap_sarif_text(&projected, MAX_SARIF_POLICY_DIAGNOSTIC_BYTES);
        if message_omitted_bytes > 0 {
            truncated_messages += 1;
            omitted_bytes = omitted_bytes.saturating_add(message_omitted_bytes);
        }
        messages.push(projected);
    }
    SarifPolicyDiagnostics {
        total_count,
        messages,
        omitted_messages,
        truncated_messages,
        omitted_bytes,
    }
}

/// Emit a directory-scan result as SARIF. Returns `false` on a write failure.
fn print_sarif_result(
    result: &scan::ScanResult,
    analysis_incomplete: bool,
    original_total_findings: usize,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
    dlp_redaction_incomplete: bool,
) -> bool {
    use tirith_core::sarif::SarifFinding;

    let version = env!("CARGO_PKG_VERSION");
    let mut findings = Vec::new();
    for rank in 0..3 {
        for file in &result.file_results {
            for finding in &file.findings {
                if sarif_priority_rank(finding) != rank
                    || findings.len() >= tirith_core::verdict::MAX_PRESENTED_FINDINGS - 1
                {
                    continue;
                }
                findings.push(SarifFinding {
                    finding,
                    file_path: Some(cap_sarif_path(
                        &tirith_core::redact::redact_sanitize_redact_with_compiled(
                            &file.path.display().to_string(),
                            compiled,
                        ),
                    )),
                    line_number: None,
                    suppressed: false,
                });
            }
        }
    }

    let policy_diagnostics = take_sarif_policy_diagnostics(compiled);
    let sarif_json = bounded_sarif(
        findings,
        analysis_incomplete,
        original_total_findings,
        version,
        dlp_redaction_incomplete,
        policy_diagnostics,
    );
    super::write_json_stdout(&sarif_json, "tirith scan: failed to write SARIF output")
}

/// Emit a single-file scan result as SARIF. Returns `false` on a write failure.
/// Coverage-gap `AnalysisIncomplete` findings already live in `result.findings`
/// (the single-file path synthesizes them), but each gap's member-qualified
/// LOCATION is attached here so a SARIF consumer sees `foo.whl!/member` rather
/// than just the outer path.
fn print_sarif_file_result(
    result: &scan::FileScanResult,
    coverage_gaps: &[scan::CoverageGap],
    analysis_incomplete: bool,
    original_total_findings: usize,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
    dlp_redaction_incomplete: bool,
) -> bool {
    use tirith_core::sarif::SarifFinding;

    let version = env!("CARGO_PKG_VERSION");
    // Map each finding to a SARIF entry; an `AnalysisIncomplete` finding is
    // located at the matching gap's member-qualified location when available.
    let findings = select_single_file_sarif_findings(&result.findings)
        .into_iter()
        .map(|finding| SarifFinding {
            finding,
            file_path: Some(cap_sarif_path(
                &tirith_core::redact::redact_sanitize_redact_with_compiled(
                    &sarif_location_for_finding(finding, &result.path, coverage_gaps),
                    compiled,
                ),
            )),
            line_number: None,
            suppressed: false,
        })
        .collect();

    let policy_diagnostics = take_sarif_policy_diagnostics(compiled);
    let sarif_json = bounded_sarif(
        findings,
        analysis_incomplete,
        original_total_findings,
        version,
        dlp_redaction_incomplete,
        policy_diagnostics,
    );
    super::write_json_stdout(&sarif_json, "tirith scan: failed to write SARIF output")
}

fn select_single_file_sarif_findings(
    findings: &[tirith_core::verdict::Finding],
) -> Vec<&tirith_core::verdict::Finding> {
    let mut selected = Vec::new();
    for rank in 0..3 {
        for finding in findings {
            if sarif_priority_rank(finding) == rank
                && selected.len() < tirith_core::verdict::MAX_PRESENTED_FINDINGS - 1
            {
                selected.push(finding);
            }
        }
    }
    selected
}

fn sarif_priority_rank(finding: &tirith_core::verdict::Finding) -> u8 {
    if finding.severity == Severity::Critical {
        0
    } else if finding.severity == Severity::High || finding.rule_id == RuleId::AnalysisIncomplete {
        1
    } else {
        2
    }
}

fn cap_sarif_path(path: &str) -> String {
    const PATH_CAP: usize = 512;
    cap_sarif_text(path, PATH_CAP).0
}

fn cap_sarif_text(value: &str, byte_cap: usize) -> (String, usize) {
    if value.len() <= byte_cap {
        return (value.to_string(), 0);
    }
    let mut end = byte_cap.saturating_sub('…'.len_utf8());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut output = value[..end].to_string();
    if byte_cap >= '…'.len_utf8() {
        output.push('…');
    }
    (output, value.len().saturating_sub(end))
}

fn bounded_sarif<'a>(
    mut selected: Vec<tirith_core::sarif::SarifFinding<'a>>,
    scan_analysis_incomplete: bool,
    original_total_findings: usize,
    version: &str,
    dlp_redaction_incomplete: bool,
    policy_diagnostics: SarifPolicyDiagnostics,
) -> serde_json::Value {
    loop {
        let retained_original = selected
            .iter()
            .filter(|item| item.finding.title != "Additional findings omitted from presentation")
            .count();
        let omitted = original_total_findings.saturating_sub(retained_original);
        let omission_finding = tirith_core::verdict::Finding {
            rule_id: RuleId::AnalysisIncomplete,
            severity: Severity::High,
            title: "SARIF presentation was truncated".to_string(),
            description: format!(
                "SARIF presentation was truncated: {omitted} finding(s) were omitted after the bounded presentation budget; policy and exit status used the complete finding set"
            ),
            evidence: Vec::new(),
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        };
        let mut view = selected
            .iter()
            .map(|item| tirith_core::sarif::SarifFinding {
                finding: item.finding,
                file_path: item.file_path.clone(),
                line_number: item.line_number,
                suppressed: item.suppressed,
            })
            .collect::<Vec<_>>();
        if omitted > 0 {
            view.push(tirith_core::sarif::SarifFinding {
                finding: &omission_finding,
                file_path: None,
                line_number: None,
                suppressed: false,
            });
        }
        let mut sarif = tirith_core::sarif::to_sarif(&view, version);
        let policy_presentation_truncated = policy_diagnostics.presentation_truncated();
        if scan_analysis_incomplete
            || omitted > 0
            || dlp_redaction_incomplete
            || policy_diagnostics.total_count > 0
        {
            sarif["runs"][0]["properties"] = serde_json::json!({
                "presentation_truncated": omitted > 0 || policy_presentation_truncated,
                "analysis_incomplete": scan_analysis_incomplete
                    || omitted > 0
                    || dlp_redaction_incomplete
                    || policy_diagnostics.total_count > 0,
                "scan_analysis_incomplete": scan_analysis_incomplete,
                "omitted_findings": omitted,
                "original_total_findings": original_total_findings,
                "dlp_redaction_incomplete": dlp_redaction_incomplete,
                "policy_diagnostics_count": policy_diagnostics.total_count,
                "policy_diagnostics": policy_diagnostics.messages.clone(),
                "policy_diagnostics_omitted": policy_diagnostics.omitted_messages,
                "policy_diagnostics_truncated": policy_presentation_truncated,
                "policy_diagnostics_truncated_count": policy_diagnostics.truncated_messages,
                "policy_diagnostics_omitted_bytes": policy_diagnostics.omitted_bytes,
            });
        }
        let bytes = tirith_core::verdict::serialized_json_pretty_size(&sarif).unwrap_or(usize::MAX);
        if bytes < tirith_core::verdict::MAX_PRESENTATION_BYTES {
            return sarif;
        }
        if selected.pop().is_none() {
            return sarif;
        }
    }
}

/// Choose the SARIF artifact location for a finding: an `AnalysisIncomplete`
/// finding uses the first coverage gap's member-qualified location (so a virtual
/// member shows as `foo.whl!/member`); any other finding uses `default_path`.
fn sarif_location_for_finding(
    finding: &tirith_core::verdict::Finding,
    default_path: &std::path::Path,
    coverage_gaps: &[scan::CoverageGap],
) -> String {
    if finding.rule_id == RuleId::AnalysisIncomplete {
        if let Some(gap) = coverage_gaps.first() {
            return gap.location.to_string();
        }
    }
    default_path.display().to_string()
}

fn print_human_file_result(
    result: &scan::FileScanResult,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
    writer: &mut tirith_core::output::HumanInvocationWriter<impl std::io::Write>,
) -> std::io::Result<()> {
    let path_display = tirith_core::output::sanitize_human_field_with_compiled(
        &result.path.display().to_string(),
        compiled,
    );
    if result.findings.is_empty() {
        writeln!(writer, "tirith scan: {path_display} — no issues found")?;
        return Ok(());
    }

    writeln!(
        writer,
        "tirith scan: {path_display} — {} finding(s)",
        result.findings.len()
    )?;

    for finding in &result.findings {
        let sev = tirith_core::style::severity_label(
            &finding.severity,
            tirith_core::style::Stream::Stderr,
        );
        writeln!(
            writer,
            "  {} {} — {}",
            sev,
            finding.rule_id,
            tirith_core::output::sanitize_human_field_with_compiled(&finding.title, compiled)
        )?;
        writeln!(
            writer,
            "    {}",
            tirith_core::output::sanitize_human_field_with_compiled(&finding.description, compiled)
        )?;
        if writer.is_truncated() {
            break;
        }
    }
    Ok(())
}

/// Whether a file should be skipped per include/exclude/ignore filters.
fn should_skip_file(
    file_path: &str,
    include: &[String],
    exclude: &[String],
    ignore: &[String],
) -> bool {
    let file_name = std::path::Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(file_path);

    let matches = |patterns: &[String]| -> bool {
        patterns.iter().any(|p| {
            tirith_core::scan::matches_ignore_pattern(file_name, p)
                || tirith_core::scan::matches_ignore_pattern(file_path, p)
        })
    };

    if matches(ignore) {
        return true;
    }

    if matches(exclude) {
        return true;
    }

    // '!'-prefixed include patterns act as excludes, not includes.
    let positive_includes: Vec<&String> = include.iter().filter(|p| !p.starts_with('!')).collect();
    let negated_includes: Vec<String> = include
        .iter()
        .filter(|p| p.starts_with('!'))
        .map(|p| p[1..].to_string())
        .collect();

    if !positive_includes.is_empty() {
        let matches_any = positive_includes.iter().any(|p| {
            tirith_core::scan::matches_ignore_pattern(file_name, p)
                || tirith_core::scan::matches_ignore_pattern(file_path, p)
        });
        if !matches_any {
            return true;
        }
    }

    if negated_includes.iter().any(|p| {
        tirith_core::scan::matches_ignore_pattern(file_name, p)
            || tirith_core::scan::matches_ignore_pattern(file_path, p)
    }) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_gate_always_fails_on_enumeration_gap() {
        let gap = scan::CoverageGap {
            location: tirith_core::location::SubjectLocation::from_path(PathBuf::from(
                "ordinary-directory",
            )),
            kind: scan::CoverageGapKind::EnumerationFailed,
            sha256: None,
        };
        let mut policy = Policy::default();
        policy.scan.unreadable_file_action = Some(tirith_core::policy::GapAction::Ignore);

        assert!(
            coverage_requires_failure(&[gap], &policy),
            "CI must fail before path-kind or unreadable Ignore filtering"
        );
    }

    #[test]
    fn sanitize_location_neutralizes_controls_and_deceptive_unicode() {
        // An attacker-controlled file name with ANSI/control or deceptive Unicode must
        // not reach the terminal raw; ordinary printable + non-ASCII content stays readable.
        let empty = tirith_core::redact::CompiledCustomPatterns::new_silent(&[]);
        let safe =
            sanitize_location_for_terminal("evil\x1b[31m\rname\u{202e}txt\u{200b}.so", &empty);
        assert!(!safe.contains('\x1b'), "ESC must be escaped: {safe:?}");
        assert!(!safe.contains('\r'), "CR must be escaped: {safe:?}");
        assert!(
            !safe.contains('\u{202e}'),
            "bidi override must be removed: {safe:?}"
        );
        assert!(
            !safe.contains('\u{200b}'),
            "zero-width space must be removed: {safe:?}"
        );
        assert!(
            safe.contains("evil") && safe.contains("name") && safe.ends_with(".so"),
            "printable text kept: {safe:?}"
        );
        // A clean non-ASCII path is unchanged.
        assert_eq!(
            sanitize_location_for_terminal("café/x.whl", &empty),
            "café/x.whl"
        );
        let secret = "SCAN_PATH_SECRET";
        let custom =
            tirith_core::redact::CompiledCustomPatterns::new_silent(&[regex::escape(secret)]);
        let redacted = sanitize_location_for_terminal(&format!("/repo/{secret}/file"), &custom);
        assert!(!redacted.contains(secret));
        assert!(redacted.contains("[REDACTED:custom]"));
    }

    #[test]
    fn oversized_sarif_remains_schema_valid_and_reports_omissions() {
        let findings = (0..tirith_core::verdict::MAX_PRESENTED_FINDINGS)
            .map(|index| tirith_core::verdict::Finding {
                rule_id: RuleId::ConfigInjection,
                severity: Severity::High,
                title: format!("finding {index} {}", "t".repeat(128)),
                description: "d".repeat(512),
                evidence: (0..tirith_core::verdict::MAX_EVIDENCE_PER_FINDING)
                    .map(|_| tirith_core::verdict::Evidence::Text {
                        detail: "e".repeat(1_024),
                    })
                    .collect(),
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            })
            .collect::<Vec<_>>();
        let selected = findings
            .iter()
            .map(|finding| tirith_core::sarif::SarifFinding {
                finding,
                file_path: Some(format!("/project/{}", "p".repeat(512))),
                line_number: None,
                suppressed: false,
            })
            .collect::<Vec<_>>();

        let sarif = bounded_sarif(
            selected,
            false,
            1_000,
            "test-version",
            false,
            SarifPolicyDiagnostics::default(),
        );
        let serialized_bytes = tirith_core::verdict::serialized_json_pretty_size(&sarif).unwrap();

        assert!(serialized_bytes < tirith_core::verdict::MAX_PRESENTATION_BYTES);
        assert_eq!(sarif["version"], "2.1.0");
        assert!(sarif["$schema"].as_str().is_some());
        assert!(sarif["runs"].as_array().is_some_and(|runs| runs.len() == 1));
        assert_eq!(
            sarif["runs"][0]["properties"]["presentation_truncated"],
            true
        );
        assert!(sarif["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|result| result["message"]["text"]
                .as_str()
                .is_some_and(|text| text.contains("presentation was truncated"))));
    }

    #[test]
    fn sarif_preserves_analyzer_incompleteness_without_driver_or_presentation_gap() {
        let sarif = bounded_sarif(
            Vec::new(),
            true,
            0,
            "test-version",
            false,
            SarifPolicyDiagnostics::default(),
        );
        let properties = &sarif["runs"][0]["properties"];
        assert_eq!(properties["analysis_incomplete"], true);
        assert_eq!(properties["scan_analysis_incomplete"], true);
        assert_eq!(properties["presentation_truncated"], false);
    }
    use tirith_core::verdict::Finding;

    fn finding(rule: RuleId, sev: Severity) -> Finding {
        Finding {
            rule_id: rule,
            severity: sev,
            title: "t".to_string(),
            description: "d".to_string(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }
    }

    #[test]
    fn single_file_sarif_keeps_late_critical_after_low_flood() {
        let mut findings = (0..tirith_core::verdict::MAX_PRESENTED_FINDINGS * 2)
            .map(|_| finding(RuleId::ConfigSuspiciousIndicator, Severity::Low))
            .collect::<Vec<_>>();
        findings.push(finding(RuleId::BidiControls, Severity::Critical));

        let selected = select_single_file_sarif_findings(&findings);
        assert!(selected
            .iter()
            .any(|finding| finding.severity == Severity::Critical));
        assert!(selected.len() < tirith_core::verdict::MAX_PRESENTED_FINDINGS);
    }

    #[test]
    fn scan_json_carries_captured_policy_diagnostics_through_recursive_dlp() {
        let secret = "C02_SCAN_POLICY_SECRET";
        let split = format!("{}\u{1b}[31m{}", &secret[..10], &secret[10..]);
        let patterns = vec![regex::escape(secret)];
        let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
        let _ = tirith_core::policy::Policy::load_from_yaml("[", Some(&split));
        tirith_core::policy::freeze_captured_policy_dlp_patterns(&patterns);
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&patterns);
        let mut value = serde_json::json!({"files": []});

        append_policy_diagnostics_json(&mut value, &compiled);
        tirith_core::redact::redact_json_strings(&mut value, &compiled);

        let rendered = serde_json::to_string(&value).unwrap();
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains('\u{1b}'));
        assert_eq!(value["policy_diagnostics_count"], 1);
        assert!(rendered.contains("[REDACTED:custom]"));
    }

    #[test]
    fn malformed_policy_diagnostic_has_human_json_sarif_redaction_parity() {
        let secret = "C02_SCAN_POLICY_PARITY_SECRET";
        let split = format!("bad\npolicy-{}\u{1b}[31m{}", &secret[..14], &secret[14..]);
        let patterns = vec![regex::escape(secret)];
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&patterns);

        let json_rendered = {
            let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
            let _ = tirith_core::policy::Policy::load_from_yaml("[", Some(&split));
            tirith_core::policy::freeze_captured_policy_dlp_patterns(&patterns);
            let mut value = serde_json::json!({"files": []});
            append_policy_diagnostics_json(&mut value, &compiled);
            tirith_core::redact::redact_json_strings(&mut value, &compiled);
            serde_json::to_string(&value).unwrap()
        };

        let human_rendered = {
            let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
            let _ = tirith_core::policy::Policy::load_from_yaml("[", Some(&split));
            tirith_core::policy::freeze_captured_policy_dlp_patterns(&patterns);
            let mut bytes = Vec::new();
            let mut writer = tirith_core::output::HumanInvocationWriter::new(&mut bytes, false);
            write_policy_diagnostics_human(&compiled, &mut writer).unwrap();
            writer.finish().unwrap();
            String::from_utf8(bytes).unwrap()
        };

        let sarif = {
            let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
            let _ = tirith_core::policy::Policy::load_from_yaml("[", Some(&split));
            tirith_core::policy::freeze_captured_policy_dlp_patterns(&patterns);
            let diagnostics = take_sarif_policy_diagnostics(&compiled);
            bounded_sarif(Vec::new(), false, 0, "test-version", false, diagnostics)
        };
        let sarif_rendered = serde_json::to_string(&sarif).unwrap();

        for rendered in [&json_rendered, &human_rendered, &sarif_rendered] {
            assert!(!rendered.contains(secret), "{rendered}");
            assert!(!rendered.contains('\u{1b}'), "{rendered}");
            assert!(rendered.contains("[REDACTED:custom]"), "{rendered}");
        }
        assert_eq!(
            sarif["runs"][0]["properties"]["policy_diagnostics_count"],
            1
        );
        assert_eq!(
            sarif["runs"][0]["properties"]["policy_diagnostics_omitted"],
            0
        );
        assert_eq!(sarif["runs"][0]["properties"]["analysis_incomplete"], true);
    }

    #[test]
    fn sarif_policy_diagnostics_are_counted_and_bounded() {
        let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&[]);
        for index in 0..(MAX_SARIF_POLICY_DIAGNOSTICS + 3) {
            let source = format!("malformed-policy-{index}-{}", "x".repeat(4_096));
            let _ = tirith_core::policy::Policy::load_from_yaml("[", Some(&source));
        }

        let diagnostics = take_sarif_policy_diagnostics(&compiled);
        let sarif = bounded_sarif(Vec::new(), false, 0, "test-version", false, diagnostics);
        let properties = &sarif["runs"][0]["properties"];

        assert_eq!(
            properties["policy_diagnostics_count"],
            (MAX_SARIF_POLICY_DIAGNOSTICS + 3) as u64
        );
        assert_eq!(properties["policy_diagnostics_omitted"], 3);
        assert_eq!(properties["presentation_truncated"], true);
        assert_eq!(properties["policy_diagnostics_truncated"], true);
        assert!(properties["policy_diagnostics_truncated_count"]
            .as_u64()
            .is_some_and(|count| count > 0));
        assert!(properties["policy_diagnostics_omitted_bytes"]
            .as_u64()
            .is_some_and(|bytes| bytes > 0));
        assert_eq!(
            properties["policy_diagnostics"].as_array().unwrap().len(),
            MAX_SARIF_POLICY_DIAGNOSTICS
        );
        assert!(properties["policy_diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(serde_json::Value::as_str)
            .all(|diagnostic| diagnostic.len() <= MAX_SARIF_POLICY_DIAGNOSTIC_BYTES));
        assert!(
            tirith_core::verdict::serialized_json_pretty_size(&sarif).unwrap()
                < tirith_core::verdict::MAX_PRESENTATION_BYTES
        );
    }

    #[test]
    fn sarif_single_long_policy_diagnostic_reports_byte_truncation() {
        let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&[]);
        let source = format!("one-long-malformed-policy-{}", "x".repeat(4_096));
        let _ = tirith_core::policy::Policy::load_from_yaml("[", Some(&source));

        let diagnostics = take_sarif_policy_diagnostics(&compiled);
        let sarif = bounded_sarif(Vec::new(), false, 0, "test-version", false, diagnostics);
        let properties = &sarif["runs"][0]["properties"];

        assert_eq!(properties["policy_diagnostics_count"], 1);
        assert_eq!(properties["policy_diagnostics_omitted"], 0);
        assert_eq!(properties["policy_diagnostics_truncated_count"], 1);
        assert_eq!(properties["policy_diagnostics_truncated"], true);
        assert_eq!(properties["presentation_truncated"], true);
        assert!(properties["policy_diagnostics_omitted_bytes"]
            .as_u64()
            .is_some_and(|bytes| bytes > 0));
    }

    #[test]
    fn scan_human_policy_diagnostic_is_one_terminal_safe_line() {
        let secret = "C02_SCAN_HUMAN_SECRET";
        let source = format!("bad\npath\u{1b}[31m{secret}");
        let patterns = vec![regex::escape(secret)];
        let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
        let _ = tirith_core::policy::Policy::load_from_yaml("[", Some(&source));
        tirith_core::policy::freeze_captured_policy_dlp_patterns(&patterns);
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&patterns);
        let mut bytes = Vec::new();
        let mut writer = tirith_core::output::HumanInvocationWriter::new(&mut bytes, false);

        write_policy_diagnostics_human(&compiled, &mut writer).unwrap();
        writer.finish().unwrap();

        let rendered = String::from_utf8(bytes).unwrap();
        assert_eq!(rendered.lines().count(), 1, "{rendered:?}");
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains('\u{1b}'));
        assert!(rendered.contains("[REDACTED:custom]"));
    }

    #[test]
    fn missing_scan_target_anchors_policy_at_nearest_existing_ancestor() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("target-repo");
        let existing = repo.join("nested");
        std::fs::create_dir_all(&existing).unwrap();
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        let missing = existing.join("not-created").join("file.txt");

        let anchor = nearest_existing_policy_anchor(&missing).unwrap();

        assert_eq!(anchor, std::fs::canonicalize(&existing).unwrap());
        assert_eq!(
            tirith_core::policy::find_repo_root(anchor.to_str()),
            Some(std::fs::canonicalize(repo).unwrap())
        );
    }

    #[test]
    fn target_diagnostic_plan_redacts_zero_width_split_custom_secret() {
        let secret = "C02_SCAN_TARGET_DLP_RECONSTITUTION_CANARY";
        let split = format!("{}\u{200b}{}", &secret[..18], &secret[18..]);
        let caller_policy = Policy::default();
        let target_policy = Policy {
            dlp_custom_patterns: vec![regex::escape(secret)],
            ..Default::default()
        };

        let patterns = combine_early_diagnostic_dlp_patterns(&caller_policy, &target_policy);
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&patterns);
        let shown = tirith_core::output::sanitize_human_field_with_compiled(&split, &compiled);

        assert!(!shown.contains(secret), "{shown}");
        assert!(!shown.contains('\u{200b}'), "{shown}");
        assert!(shown.contains("[REDACTED:custom]"), "{shown}");
    }

    #[test]
    fn built_in_profiles_resolve() {
        assert!(built_in_profile("ci-hardening").is_some());
        assert!(built_in_profile("ai-agent-repo").is_some());
        assert!(built_in_profile("oss-maintainer").is_some());
        assert!(built_in_profile("nonexistent").is_none());
        for name in BUILT_IN_PROFILE_NAMES {
            assert!(
                built_in_profile(name).is_some(),
                "advertised profile '{name}' must resolve"
            );
        }
    }

    #[test]
    fn ci_hardening_keeps_high_findings_and_regrades_pinning() {
        let bp = built_in_profile("ci-hardening").unwrap();
        assert_eq!(bp.fail_on, "high");
        let findings = vec![
            finding(RuleId::WorkflowDangerousTrigger, Severity::High),
            finding(RuleId::WorkflowUnpinnedAction, Severity::Medium),
        ];
        let out = apply_rule_overlay(findings, bp.rule_overlay);
        assert!(
            out.iter()
                .any(|f| f.rule_id == RuleId::WorkflowDangerousTrigger
                    && f.severity == Severity::High)
        );
        // Unpinned-action kept (still Medium under ci-hardening).
        assert!(
            out.iter()
                .any(|f| f.rule_id == RuleId::WorkflowUnpinnedAction
                    && f.severity == Severity::Medium)
        );
    }

    #[test]
    fn ai_agent_repo_suppresses_pinning_noise_keeps_injection() {
        let bp = built_in_profile("ai-agent-repo").unwrap();
        let findings = vec![
            finding(RuleId::WorkflowUntrustedInput, Severity::High),
            finding(RuleId::WorkflowUnpinnedAction, Severity::Medium),
            finding(RuleId::DockerfileUnpinnedImage, Severity::Medium),
        ];
        let out = apply_rule_overlay(findings, bp.rule_overlay);
        // Injection finding stays; pinning-hygiene findings suppressed.
        assert!(out
            .iter()
            .any(|f| f.rule_id == RuleId::WorkflowUntrustedInput));
        assert!(!out
            .iter()
            .any(|f| f.rule_id == RuleId::WorkflowUnpinnedAction));
        assert!(!out
            .iter()
            .any(|f| f.rule_id == RuleId::DockerfileUnpinnedImage));
    }

    #[test]
    fn oss_maintainer_downgrades_pinning_to_low() {
        let bp = built_in_profile("oss-maintainer").unwrap();
        let findings = vec![
            finding(RuleId::PackageScriptDangerous, Severity::High),
            finding(RuleId::WorkflowUnpinnedAction, Severity::Medium),
        ];
        let out = apply_rule_overlay(findings, bp.rule_overlay);
        // Dangerous-script stays High; unpinned-action downgraded to Low.
        assert!(out
            .iter()
            .any(|f| f.rule_id == RuleId::PackageScriptDangerous && f.severity == Severity::High));
        assert!(out
            .iter()
            .any(|f| f.rule_id == RuleId::WorkflowUnpinnedAction && f.severity == Severity::Low));
    }

    #[test]
    fn empty_overlay_is_identity() {
        let findings = vec![finding(RuleId::WorkflowDangerousTrigger, Severity::High)];
        let out = apply_rule_overlay(findings.clone(), &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, RuleId::WorkflowDangerousTrigger);
        assert_eq!(out[0].severity, Severity::High);
    }

    #[test]
    fn overlay_leaves_unlisted_rules_untouched() {
        let bp = built_in_profile("ci-hardening").unwrap();
        let findings = vec![finding(RuleId::ConfigInjection, Severity::High)];
        let out = apply_rule_overlay(findings, bp.rule_overlay);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, RuleId::ConfigInjection);
        assert_eq!(out[0].severity, Severity::High);
    }
}
