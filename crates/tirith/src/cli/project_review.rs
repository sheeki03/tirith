//! Explicit project review and process-local retained report identities.
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tirith_core::policy::{captured_policy_dlp_patterns_or, PolicyDiagnosticCapture};
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
use tirith_core::project_review::ProjectReview;

struct Retained {
    root: PathBuf,
    report: ProjectReview,
    created: Instant,
    dlp_patterns: Vec<String>,
}
static REPORTS: OnceLock<Mutex<VecDeque<Retained>>> = OnceLock::new();
const REPORT_COUNT: usize = 4;
const REPORT_TTL: Duration = Duration::from_secs(600);

fn project_root(cwd: Option<&str>) -> Result<PathBuf, String> {
    cwd.map(PathBuf::from).map(Ok).unwrap_or_else(|| {
        std::env::current_dir().map_err(|_| "working directory unavailable".into())
    })
}

fn present(report: &ProjectReview, scope: &Path) -> Result<Value, String> {
    let snapshot = EffectivePolicySnapshot::resolve(scope.to_str(), ResolutionMode::LocalOnly);
    let patterns = captured_policy_dlp_patterns_or(&snapshot.policy.dlp_custom_patterns);
    let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&patterns);
    let mut value = report.projection(&patterns)?;
    let diagnostics = tirith_core::policy::drain_captured_policy_diagnostics_for_output(&compiled);
    value["redaction"] = json!({"source":"trusted_local_policy","remote_policy":"unavailable_offline","effective_runtime_policy":false});
    value["diagnostics"] = json!(diagnostics
        .into_iter()
        .take(16)
        .map(|text| if text.len() > 1024 {
            "[withheld: diagnostic exceeds output limit]".to_string()
        } else {
            text
        })
        .collect::<Vec<_>>());
    Ok(value)
}

/// Only an explicit request reaches discovery. The local browser supplies no
/// root pathname: its retained service working directory defines the scope.
pub(crate) fn inspect(cwd: Option<&str>, paths: &[String]) -> Result<Value, String> {
    inspect_retained(cwd, paths, None)
}

pub(crate) fn inspect_retained(
    cwd: Option<&str>,
    paths: &[String],
    anchor: Option<&tirith_core::util::ContainedAtomicFile>,
) -> Result<Value, String> {
    let root = project_root(cwd)?;
    let _capture = PolicyDiagnosticCapture::start();
    let policy = EffectivePolicySnapshot::resolve(root.to_str(), ResolutionMode::LocalOnly);
    let db = tirith_core::threatdb::ThreatDb::cached();
    let report = ProjectReview::capture(&root, paths, &policy.policy, db.as_deref())?;
    if anchor.is_some_and(|anchor| !report.shares_retained_root(anchor)) {
        return Err("The service project directory changed; reopen the dashboard.".into());
    }
    policy
        .revalidate_inputs()
        .map_err(|_| "local policy changed during project review; inspect again")?;
    let output = present(&report, &root)?;
    let mut reports = REPORTS
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| "project review store unavailable")?;
    reports.retain(|entry| entry.created.elapsed() < REPORT_TTL);
    while reports.len() >= REPORT_COUNT {
        reports.pop_front();
    }
    reports.push_back(Retained {
        root,
        report,
        created: Instant::now(),
        dlp_patterns: captured_policy_dlp_patterns_or(&policy.policy.dlp_custom_patterns),
    });
    Ok(output)
}

pub(crate) fn revalidate(id: &str, cwd: Option<&str>) -> Result<Value, String> {
    let _capture = PolicyDiagnosticCapture::start();
    if !uuid::Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() == id) {
        return Err("report ID must be a canonical UUID".into());
    }
    let root = project_root(cwd)?;
    let mut reports = REPORTS
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| "project review store unavailable")?;
    let retained = reports
        .iter_mut()
        .find(|entry| {
            entry.report.id() == id && entry.root == root && entry.created.elapsed() < REPORT_TTL
        })
        .ok_or("project report expired or belongs to another service scope; inspect again")?;
    tirith_core::policy::freeze_captured_policy_dlp_patterns(&retained.dlp_patterns);
    let output = present(&retained.report, &root)?;
    retained.dlp_patterns = captured_policy_dlp_patterns_or(&retained.dlp_patterns);
    Ok(output)
}

pub fn run(paths: Vec<String>, json_output: bool) -> i32 {
    let _capture = PolicyDiagnosticCapture::start();
    match inspect(None, &paths) {
        Ok(value) => {
            if json_output {
                if !super::write_json_stdout(&value, "tirith review: cannot write project report") {
                    return 1;
                }
            } else {
                eprintln!(
                    "Project review: {} selected files, {} inspected bytes.",
                    value["coverage"]["selected_files"], value["coverage"]["inspected_bytes"]
                );
                eprintln!(
                    "{}",
                    value["notice"]
                        .as_str()
                        .unwrap_or("Static project observations only.")
                );
                for file in value["files"].as_array().into_iter().flatten() {
                    eprintln!(
                        "  {}: {}",
                        file["path"].as_str().unwrap_or("withheld"),
                        file["status"].as_str().unwrap_or("unavailable")
                    );
                    for finding in file["findings"].as_array().into_iter().flatten() {
                        eprintln!(
                            "    {} — {}",
                            finding["rule_id"].as_str().unwrap_or("finding"),
                            finding["description"]
                                .as_str()
                                .unwrap_or("details unavailable")
                        );
                    }
                    if let Some(gaps) = file["gaps"].as_array() {
                        if !gaps.is_empty() {
                            eprintln!(
                                "    Unavailable evidence: {}",
                                gaps.iter()
                                    .filter_map(Value::as_str)
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            );
                        }
                    }
                }
                eprintln!(
                    "Use --json for dependency evidence, MCP destinations and per-file coverage."
                );
            }
            // Successful collection is not a clean/safe verdict. Return an
            // advisory exit whenever the selected static view is incomplete.
            let incomplete = value["presentation_incomplete"] == true
                || value["root_changed"] == true
                || value["changed_files"].as_u64().unwrap_or(1) > 0
                || value["files"].as_array().into_iter().flatten().any(|file| {
                    file["status"] != "absent"
                        && (file["status"] != "inspected"
                            || file["gaps"].as_array().is_some_and(|gaps| !gaps.is_empty())
                            || file["findings"]
                                .as_array()
                                .is_some_and(|findings| !findings.is_empty()))
                });
            if incomplete {
                2
            } else {
                0
            }
        }
        Err(error) => {
            eprintln!(
                "tirith review: {}",
                tirith_core::redact::redact_sanitize_redact(
                    &error,
                    &captured_policy_dlp_patterns_or(&[])
                )
            );
            1
        }
    }
}
