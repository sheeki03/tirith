//! `tirith pkg install | verify-env | approve | receipt | trust-tool`, the
//! CLI surface left from the removed pip package firewall (PR D7).
//!
//! Contained Python package execution is disabled by the shared private-input
//! qualification guard ([`capsule::private_input_execution_refusal`]).
//! Both commands that only existed to feed that execution path refuse with the
//! same named reason and exit code 1, before any policy discovery, target
//! binding, resolver, network, quarantine, or approval-store side effect:
//!
//! * **`pkg install`** validates its arguments (usage errors keep their exit
//!   codes and messages) and then refuses at phase `refused_before_exec`.
//! * **`pkg approve`** first checks the native approval authority (so a host
//!   without it keeps reporting phase `native_authority`), validates its
//!   arguments, and then refuses at phase `refused_before_exec`. It records no
//!   approval, because nothing can redeem one.
//!
//! The remaining commands keep working:
//!
//! * **`pkg verify-env`** runs the D5 post-install RECORD verification over an
//!   already-installed environment, without installing anything.
//! * **`pkg receipt`** lists and shows the D6 [`tirith_core::receipt::ArtifactScanReceipt`]s,
//!   including receipts written by earlier releases.
//! * **`pkg trust-tool`** pins a user-writable uv/python executable. Nothing in
//!   this release reads the pin: it is recorded only for when contained install
//!   returns, and the help, stderr note and JSON `enforced: false` say so.
//!
//! # Distinct from `tirith install`
//!
//! `tirith install` (in [`crate::cli::install`]) is the ANALYSIS path: it inspects a
//! package-manager command and optionally runs the real, UNcontained install.
//! `tirith pkg install` was the ENFORCING path; it refuses on every host because
//! contained package execution and its private-input backend were removed. The two stay separate
//! commands. This module reuses `tirith install`'s `MISPLACED_TIRITH_FLAGS`
//! footgun guard (a tirith-owned flag placed after the trailing args would
//! silently not affect tirith).

use std::path::{Path, PathBuf};

use tirith_core::artifact::install::verify_post_install_record;
use tirith_core::artifact::resolver::{
    enroll_resolver_tool, validate_resolver_request_with_artifact_origins, ResolverError,
    ResolverRequest,
};
use tirith_core::policy::Policy;

use crate::cli::capsule;

/// tirith-owned options that no package manager interprets. If one of these appears
/// AFTER the trailing requirement args it would silently not affect tirith (the same
/// footgun `tirith install` guards), so finding one trailing is a hard error. Shared
/// in spirit with [`crate::cli::install`]'s guard; kept local so the two surfaces
/// can carry their own flag sets.
const MISPLACED_TIRITH_FLAGS: &[&str] = &["--yes", "--allow-degraded", "--online"];

/// What the `pkg` command should do, parsed from the CLI. Mirrors the clap
/// subcommand in `main.rs`; kept here so the dispatch logic lives with the module.
#[derive(Debug, Clone)]
pub enum PkgAction {
    /// Checks the native approval authority and the arguments, then refuses:
    /// approvals exist only for the disabled contained `pkg install`.
    Approve {
        ecosystem: Ecosystem,
        requirements: Vec<String>,
        index_url: Vec<String>,
        artifact_origin: Vec<String>,
        json: bool,
    },
    /// Validates the arguments, then refuses: contained package execution is
    /// disabled by the private-input qualification guard.
    Install {
        ecosystem: Ecosystem,
        requirements: Vec<String>,
        index_url: Vec<String>,
        artifact_origin: Vec<String>,
        json: bool,
    },
    /// D5 post-install RECORD verification over an already-installed environment.
    VerifyEnv {
        target: PathBuf,
        packages: Vec<String>,
        json: bool,
    },
    /// Explicitly pin a user-writable uv/python executable by canonical path and
    /// SHA-256 in the owner-only operator trust store.
    TrustTool { path: PathBuf, json: bool },
    /// List / show the D6 tamper-evident receipts.
    Receipt {
        which: ReceiptQuery,
        json: bool,
        display_json: bool,
    },
}

/// Which receipt(s) `pkg receipt` reports.
#[derive(Debug, Clone)]
pub enum ReceiptQuery {
    /// All saved artifact-scan receipts, newest first.
    List,
    /// The newest saved artifact-scan receipt.
    Last,
    /// One receipt by its `receipt_id` (content hash).
    Show(String),
}

/// The ecosystem `pkg install` / `approve` enforce for. Only `pip` (Python wheels)
/// is enforced in v1; npm / cargo are deliberately refused here (their hardened
/// `.tgz` / `.crate` analysers do not exist yet, plan Stack D).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    /// Python wheels via the D2 `uv` + `pip` resolver. The only enforced ecosystem.
    Pip,
    /// npm, not enforced in v1 (resolve+inspect-metadata only lives behind hidden
    /// experimental flags; the firewall install path refuses it).
    Npm,
    /// cargo, not enforced in v1, as npm.
    Cargo,
}

impl Ecosystem {
    fn label(self) -> &'static str {
        match self {
            Ecosystem::Pip => "pip",
            Ecosystem::Npm => "npm",
            Ecosystem::Cargo => "cargo",
        }
    }
}

/// Entry point for `tirith pkg`. Returns a process exit code (0 success, 1 a
/// blocked / failed operation, 2 a usage error).
pub fn run(action: PkgAction) -> i32 {
    match action {
        PkgAction::Approve {
            ecosystem,
            requirements,
            index_url,
            artifact_origin,
            json,
        } => run_approve(ecosystem, &requirements, &index_url, &artifact_origin, json),
        PkgAction::Install {
            ecosystem,
            requirements,
            index_url,
            artifact_origin,
            json,
        } => run_install(ecosystem, &requirements, &index_url, &artifact_origin, json),
        PkgAction::VerifyEnv {
            target,
            packages,
            json,
        } => run_verify_env(&target, &packages, json),
        PkgAction::Receipt {
            which,
            json,
            display_json,
        } => run_receipt(which, json, display_json),
        PkgAction::TrustTool { path, json } => run_trust_tool(&path, json),
    }
}

// ---------------------------------------------------------------------------
// Shared guards
// ---------------------------------------------------------------------------

/// Refuse a non-pip ecosystem (only Python is enforced in v1) and refuse a
/// misplaced tirith-owned flag in the requirement list. The check is presentation-
/// free so `--json` callers can emit one structured document without a preceding
/// human diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PkgPrecheckFailure {
    exit_code: i32,
    reason: String,
}

fn precheck(ecosystem: Ecosystem, requirements: &[String]) -> Option<PkgPrecheckFailure> {
    if ecosystem != Ecosystem::Pip {
        return Some(PkgPrecheckFailure {
            exit_code: 2,
            reason: format!(
                "only `pip` is enforced in this version; `{}` is not yet supported \
             (npm / cargo resolve-and-inspect lives behind hidden experimental flags and cannot \
             install). Use `tirith install {}` for analysis-only.",
                ecosystem.label(),
                ecosystem.label()
            ),
        });
    }
    if let Some(flag) = requirements
        .iter()
        .find(|a| MISPLACED_TIRITH_FLAGS.contains(&a.as_str()))
    {
        return Some(PkgPrecheckFailure {
            exit_code: 2,
            reason: format!(
                "`{flag}` is a tirith option and must come before the requirement list \
             (e.g. `tirith pkg install pip {flag} requests==2.31.0`). After the ecosystem, \
             arguments are package requirements, so a misplaced `{flag}` would not affect tirith."
            ),
        });
    }
    if requirements.is_empty() {
        return Some(PkgPrecheckFailure {
            exit_code: 2,
            reason: "no requirements given. try: tirith pkg install pip requests==2.31.0 --target .tirith-pkg"
                .to_string(),
        });
    }
    None
}

fn report_pkg_precheck_failure(
    command: &'static str,
    failure: &PkgPrecheckFailure,
    json: bool,
) -> i32 {
    if json {
        let value = serde_json::json!({
            "success": false,
            "command": command,
            "error_phase": "precheck",
            "target_executed": false,
            "target_published": false,
            "reason": failure.reason.as_str(),
        });
        let _ = write_json_document(std::io::stdout().lock(), &value);
    } else {
        eprintln!(
            "tirith pkg: {}",
            crate::cli::sanitize_for_human_output(&failure.reason, false)
        );
    }
    failure.exit_code
}

/// Pure parsing and policy checks of the requirement set. They perform no PATH
/// lookup, quarantine mutation, DNS, or child execution.
fn validated_resolver_request(
    requirements: &[String],
    index_url: &[String],
    artifact_origin: &[String],
) -> Result<ResolverRequest, ResolverError> {
    let request = ResolverRequest {
        requirements: requirements.to_vec(),
        index_urls: index_url.to_vec(),
        allowances: Default::default(),
    };
    validate_resolver_request_with_artifact_origins(&request, artifact_origin)?;
    Ok(request)
}

/// The diagnostic both refusing commands print for an invalid requirement set.
fn resolver_request_error(error: &ResolverError) -> String {
    format!("resolve failed: {error}")
}

// ---------------------------------------------------------------------------
// resolver tool enrollment
// ---------------------------------------------------------------------------

/// Printed after a successful `pkg trust-tool`: the pin is stored, but no
/// command in this release reads it.
const TRUST_TOOL_NOT_ENFORCED_NOTE: &str = "tirith pkg trust-tool: the pin is recorded but not yet enforced; nothing in this release reads it while contained package installation is disabled";

/// The `--format json` document for a successful `pkg trust-tool`. `enforced`
/// is always false in this release (additive field).
fn trust_tool_success_json(canonical: &Path) -> serde_json::Value {
    serde_json::json!({
        "trusted": true,
        "canonical_path": canonical.display().to_string(),
        "binding": "sha256",
        "enforced": false,
    })
}

fn run_trust_tool(path: &Path, json: bool) -> i32 {
    match enroll_resolver_tool(path) {
        Ok(canonical) => {
            if json {
                let out = trust_tool_success_json(&canonical);
                let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), &out);
                println!();
            } else {
                eprintln!(
                    "tirith pkg trust-tool: enrolled canonical path + SHA-256 for {}",
                    canonical.display()
                );
                eprintln!("{TRUST_TOOL_NOT_ENFORCED_NOTE}");
            }
            0
        }
        Err(error) => {
            eprintln!("tirith pkg trust-tool: {error}");
            1
        }
    }
}

// ---------------------------------------------------------------------------
// pkg approve
// ---------------------------------------------------------------------------

fn report_approve_error(phase: &'static str, reason: &str, json: bool, exit_code: i32) -> i32 {
    if json {
        let value = approve_error_json(phase, reason);
        let _ = write_json_document(std::io::stdout().lock(), &value);
    } else {
        let reason = crate::cli::sanitize_for_human_output(reason, false);
        eprintln!("tirith pkg approve: {reason}");
    }
    exit_code
}

fn approve_error_json(phase: &'static str, reason: &str) -> serde_json::Value {
    serde_json::json!({
        "success": false,
        "command": "approve",
        "error_phase": phase,
        "target_executed": false,
        "target_published": false,
        "reason": reason,
    })
}

fn run_approve(
    ecosystem: Ecosystem,
    requirements: &[String],
    index_url: &[String],
    artifact_origin: &[String],
    json: bool,
) -> i32 {
    if let Err(error) =
        super::package_approval_authority::availability().require_explicit_issuance()
    {
        return report_approve_error("native_authority", &error.to_string(), json, 1);
    }
    let refusal = approve_refusal(ecosystem, requirements, index_url, artifact_origin);
    report_approve_error(refusal.phase, &refusal.reason, json, refusal.exit_code)
}

/// Why `pkg approve` refuses once the native authority is available. An
/// approval exists only to be redeemed by `pkg install`, whose execution path is
/// disabled, so approve refuses with the same named reason instead of resolving,
/// downloading, or publishing a grant nothing can consume. Usage and request
/// errors keep their earlier phases and exit codes.
#[derive(Debug, PartialEq, Eq)]
struct ApproveRefusal {
    phase: &'static str,
    reason: String,
    exit_code: i32,
}

fn approve_refusal(
    ecosystem: Ecosystem,
    requirements: &[String],
    index_url: &[String],
    artifact_origin: &[String],
) -> ApproveRefusal {
    if let Some(failure) = precheck(ecosystem, requirements) {
        return ApproveRefusal {
            phase: "precheck",
            reason: failure.reason,
            exit_code: failure.exit_code,
        };
    }
    if let Err(error) = validated_resolver_request(requirements, index_url, artifact_origin) {
        return ApproveRefusal {
            phase: "request_validation",
            reason: resolver_request_error(&error),
            exit_code: 1,
        };
    }
    ApproveRefusal {
        phase: "refused_before_exec",
        reason: capsule::private_input_execution_refusal().to_string(),
        exit_code: 1,
    }
}

// ---------------------------------------------------------------------------
// pkg install
// ---------------------------------------------------------------------------

fn run_install(
    ecosystem: Ecosystem,
    requirements: &[String],
    index_url: &[String],
    artifact_origin: &[String],
    json: bool,
) -> i32 {
    if let Some(failure) = precheck(ecosystem, requirements) {
        return report_pkg_precheck_failure("install", &failure, json);
    }
    if let Err(error) = validated_resolver_request(requirements, index_url, artifact_origin) {
        return report_install_failure("plan_preparation", &resolver_request_error(&error), json);
    }
    // Validate syntax first, then refuse the unqualified execution backend before
    // policy discovery, target retention, resolver/network work, quarantine,
    // approval consumption, checkpoint creation, or receipt publication.
    report_install_failure(
        "refused_before_exec",
        &capsule::private_input_execution_refusal().to_string(),
        json,
    )
}

/// `pkg install` never executes or publishes a target, so both flags are fixed.
fn install_failure_json(phase: &'static str, reason: &str) -> serde_json::Value {
    serde_json::json!({
        "success": false,
        "error_phase": phase,
        "target_executed": false,
        "target_published": false,
        "reason": reason,
    })
}

fn report_install_failure(phase: &'static str, reason: &str, json: bool) -> i32 {
    if json {
        let value = install_failure_json(phase, reason);
        let _ = write_json_document(std::io::stdout().lock(), &value);
    } else {
        eprintln!(
            "tirith pkg install: {}: {}",
            crate::cli::sanitize_for_human_output(phase, false),
            crate::cli::sanitize_for_human_output(reason, false)
        );
    }
    1
}

/// Serialize exactly one JSON value followed by one newline. Keeping JSON output
/// behind a writer seam lets tests prove each refusal is exactly one document.
fn write_json_document(
    mut writer: impl std::io::Write,
    value: &serde_json::Value,
) -> std::io::Result<()> {
    serde_json::to_writer_pretty(&mut writer, value).map_err(std::io::Error::other)?;
    writer.write_all(b"\n")
}

// ---------------------------------------------------------------------------
// pkg verify-env
// ---------------------------------------------------------------------------

fn run_verify_env(target: &Path, packages: &[String], json: bool) -> i32 {
    if packages.is_empty() {
        eprintln!(
            "tirith pkg verify-env: no package names given. \
             try: tirith pkg verify-env --target .venv requests flask"
        );
        return 2;
    }
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    let policy = Policy::discover_local_only(cwd.as_deref());

    // Normalise the given names with the SAME PEP 503 normaliser the install scope
    // uses, so a name spelled differently than the on-disk dist-info still matches.
    let names: Vec<String> = packages
        .iter()
        .map(|p| tirith_core::artifact::normalize_project_name_public(p))
        .collect();

    let result = verify_post_install_record(target, &names, &policy);
    let incomplete = !result.is_complete();
    let blocked = result.is_block() || incomplete;
    let effective_action = if incomplete {
        tirith_core::verdict::Action::Block
    } else {
        result.verdict.action
    };

    if json {
        let out = serde_json::json!({
            "target": target.display().to_string(),
            "blocked": blocked,
            "verification_incomplete": incomplete,
            "distributions_verified": result.distributions_verified,
            "distributions_not_found": result.distributions_not_found,
            "records_missing": result.records_missing,
            "hash_mismatches": result.hash_mismatches,
            "action": format!("{effective_action:?}"),
            "rule_ids": result
                .verdict
                .findings
                .iter()
                .map(|f| f.rule_id.to_string())
                .collect::<Vec<_>>(),
        });
        let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), &out);
        println!();
    } else {
        eprintln!("tirith pkg verify-env: {}", target.display());
        eprintln!("  verified:    {}", result.distributions_verified);
        eprintln!("  not found:   {}", result.distributions_not_found);
        eprintln!("  no RECORD:   {}", result.records_missing);
        eprintln!("  mismatches:  {}", result.hash_mismatches);
        eprintln!("  verdict:     {effective_action:?}");
        if blocked {
            eprintln!("  the installed environment FAILED complete RECORD integrity verification");
        }
    }

    if blocked {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// pkg receipt
// ---------------------------------------------------------------------------

fn run_receipt(which: ReceiptQuery, json: bool, display_json: bool) -> i32 {
    use super::receipt_display as display;
    let compiled = display::output_dlp();
    let is_list = matches!(which, ReceiptQuery::List);
    let selected = match which {
        ReceiptQuery::Show(id) => display::load_artifact(&id).map(|receipt| vec![receipt]),
        ReceiptQuery::List | ReceiptQuery::Last => display::list_artifact().map(|mut receipts| {
            receipts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            if !is_list {
                receipts.truncate(1);
            }
            receipts
        }),
    };
    let receipts = match selected {
        Ok(receipts) => receipts,
        Err(error) => {
            eprintln!("tirith pkg receipt: {error}");
            return 1;
        }
    };
    if !is_list && receipts.is_empty() {
        eprintln!("tirith pkg receipt: no artifact-scan receipts found");
        return 1;
    }
    let values = receipts
        .iter()
        .map(|receipt| {
            if display_json {
                Ok(display::artifact_display(receipt, &compiled))
            } else if json {
                display::artifact_canonical(receipt, &compiled)
            } else {
                Ok(display::artifact(receipt, &compiled))
            }
        })
        .collect::<Result<Vec<_>, _>>();
    let values = match values {
        Ok(values) => values,
        Err(error) => {
            eprintln!("tirith pkg receipt: {error}");
            return 1;
        }
    };
    let output = if is_list {
        serde_json::Value::Array(values)
    } else {
        values.into_iter().next().expect("selected receipt")
    };
    if let Err(error) = display::bounded(&output) {
        eprintln!("tirith pkg receipt: {error}");
        return 1;
    }
    if json || display_json {
        let written = if display_json {
            display::write(&output)
        } else if is_list {
            super::write_json_stdout(&receipts, "tirith pkg receipt: failed to write JSON output")
        } else {
            super::write_json_stdout(
                &receipts[0],
                "tirith pkg receipt: failed to write JSON output",
            )
        };
        if !written {
            return 1;
        }
    } else if is_list {
        if receipts.is_empty() {
            eprintln!("tirith pkg receipt: no artifact-scan receipts found");
        }
        for row in output.as_array().expect("receipt list") {
            eprintln!(
                "  {} {} {} {} artifact(s) {}",
                tirith_core::receipt::short_hash(&display::text(row, "receipt_id")),
                display::text(&row["verdict"], "action"),
                display::text(&row["capsule"], "backend_id"),
                row["artifact_sha256"].as_array().map_or(0, Vec::len),
                display::text(row, "timestamp")
            );
        }
    } else {
        eprintln!(
            "tirith pkg receipt: {}",
            display::text(&output, "receipt_id")
        );
        eprintln!("  schema: {}", output["schema"]);
        for (label, key) in [
            ("tirith", "tirith_version"),
            ("engine SHA", "engine_build_sha"),
            ("policy hash", "policy_hash"),
            ("resolver", "resolver_command"),
            ("when", "timestamp"),
        ] {
            eprintln!("  {label}: {}", display::text(&output, key));
        }
        eprintln!(
            "  capsule: {}",
            display::text(&output["capsule"], "backend_id")
        );
        eprintln!("  verdict: {}", display::text(&output["verdict"], "action"));
        eprintln!("  DB sequence: {}", output["threat_db_sequence"]);
        eprintln!("  artifacts: {}", receipts[0].artifact_sha256.len());
        eprintln!(
            "  content valid: {}",
            if receipts[0].content_hash_matches() {
                "yes"
            } else {
                "NO (edited?)"
            }
        );
    }
    if receipts
        .iter()
        .any(|receipt| !receipt.content_hash_matches())
    {
        eprintln!("tirith pkg receipt: stored receipt content does not match its ID.");
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_tool_success_output_says_the_pin_is_not_enforced() {
        let value = trust_tool_success_json(Path::new("/opt/uv/bin/uv"));
        assert_eq!(value["trusted"], true);
        assert_eq!(value["canonical_path"], "/opt/uv/bin/uv");
        assert_eq!(value["binding"], "sha256");
        assert_eq!(value["enforced"], false);
        assert!(TRUST_TOOL_NOT_ENFORCED_NOTE.contains("not yet enforced"));
    }

    #[test]
    fn approve_failures_share_one_stable_json_dto() {
        for phase in [
            "native_authority",
            "precheck",
            "request_validation",
            "refused_before_exec",
        ] {
            let value = approve_error_json(phase, "refused");
            assert_eq!(value["success"], false);
            assert_eq!(value["command"], "approve");
            assert_eq!(value["error_phase"], phase);
            assert_eq!(value["target_executed"], false);
            assert_eq!(value["target_published"], false);
            assert_eq!(value["reason"], "refused");
            assert_eq!(value.as_object().unwrap().len(), 6);
        }
    }

    #[test]
    fn approve_refuses_with_the_install_reason_after_argument_validation() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let refusal = approve_refusal(Ecosystem::Pip, &["requests==2.31.0".to_string()], &[], &[]);
        assert_eq!(refusal.phase, "refused_before_exec");
        assert_eq!(refusal.exit_code, 1);
        assert_eq!(
            refusal.reason,
            capsule::private_input_execution_refusal().to_string()
        );
        assert!(refusal
            .reason
            .starts_with("private_input_execution_unqualified:"));
    }

    #[test]
    fn approve_keeps_usage_and_request_errors_before_the_refusal() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let usage = approve_refusal(Ecosystem::Npm, &["lodash".to_string()], &[], &[]);
        assert_eq!((usage.phase, usage.exit_code), ("precheck", 2));
        let empty = approve_refusal(Ecosystem::Pip, &[], &[], &[]);
        assert_eq!((empty.phase, empty.exit_code), ("precheck", 2));
        let direct_url = approve_refusal(
            Ecosystem::Pip,
            &["examplepkg@https://unapproved.example/pkg-1.0-py3-none-any.whl".to_string()],
            &[],
            &[],
        );
        assert_eq!(direct_url.phase, "request_validation");
        assert_eq!(direct_url.exit_code, 1);
        assert!(direct_url.reason.starts_with("resolve failed: "));
        assert!(direct_url.reason.contains("direct-URL requirements"));
    }

    // ── precheck / misplaced-flag guard ─────────────────────────────────────

    #[test]
    fn precheck_refuses_non_pip_ecosystem() {
        assert_eq!(
            precheck(Ecosystem::Npm, &["lodash".to_string()]).map(|failure| failure.exit_code),
            Some(2)
        );
        assert_eq!(
            precheck(Ecosystem::Cargo, &["serde".to_string()]).map(|failure| failure.exit_code),
            Some(2)
        );
    }

    #[test]
    fn precheck_refuses_misplaced_tirith_flag_after_requirements() {
        // A tirith-owned flag trailing the requirement list is a hard error (it would
        // not affect tirith), mirroring `tirith install`'s guard.
        for flag in MISPLACED_TIRITH_FLAGS {
            let reqs = vec!["requests".to_string(), flag.to_string()];
            assert_eq!(
                precheck(Ecosystem::Pip, &reqs).map(|failure| failure.exit_code),
                Some(2),
                "trailing {flag} must be refused"
            );
        }
    }

    #[test]
    fn precheck_refuses_empty_requirements() {
        assert_eq!(
            precheck(Ecosystem::Pip, &[]).map(|failure| failure.exit_code),
            Some(2)
        );
    }

    #[test]
    fn precheck_allows_a_clean_pip_requirement() {
        assert_eq!(
            precheck(Ecosystem::Pip, &["requests==2.31.0".to_string()]),
            None
        );
    }

    #[test]
    fn early_pkg_json_failure_is_exactly_one_document() {
        let early = install_failure_json("refused_before_exec", "PIP_EARLY_FAILURE_SENTINEL");
        let mut rendered = Vec::new();
        write_json_document(&mut rendered, &early).unwrap();
        let mut documents =
            serde_json::Deserializer::from_slice(&rendered).into_iter::<serde_json::Value>();
        assert_eq!(documents.next().unwrap().unwrap(), early);
        assert!(
            documents.next().is_none(),
            "an early --json failure must also be exactly one document"
        );
    }

    #[test]
    fn verify_env_returns_nonzero_when_expected_distribution_is_absent() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let target = tempfile::tempdir().unwrap();
        let packages = vec!["definitely-not-installed".to_string()];
        assert_eq!(
            run_verify_env(target.path(), &packages, false),
            1,
            "an empty Allow verdict must not turn incomplete verification into success"
        );
    }
}
