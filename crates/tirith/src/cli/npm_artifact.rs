//! Offline npm product projections over the exact-byte core inspector. All
//! content fields cross one captured DLP boundary before display limits apply.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use tirith_core::artifact::npm_archive::{
    read_npm_tarball, NpmArchiveState, NpmCoverage, NpmInspection, NpmLimits, NpmSignal,
    NpmSignalLevel, NPM_ANALYZER_VERSION,
};
use tirith_core::artifact::npm_diff::{
    compare_npm_releases, NpmComparison, NpmComparisonState, NpmDelta,
};
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
use tirith_core::redact::CompiledCustomPatterns;

const MAX_ARTIFACTS: usize = 8;
const MAX_REPORT_BYTES: usize = 384 * 1024;

#[path = "npm_artifact_browser.rs"]
pub(crate) mod browser;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Human,
    Json,
    Sarif,
}

pub(crate) fn usage_error(message: &str, format: Format) -> i32 {
    let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
    Context::capture().error(message, format)
}

pub fn is_npm_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            let name = name.to_ascii_lowercase();
            name.ends_with(".tgz") || name.ends_with(".tar.gz")
        })
}

/// Only this suffix selects npm implicitly. `.tar.gz` also names Python sdists
/// and must keep their existing report contract unless npm is selected explicitly.
pub fn is_unambiguous_npm_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("tgz"))
}

pub fn inspect(paths: &[PathBuf], format: Format) -> i32 {
    let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
    let mut context = Context::capture();
    if paths.is_empty() || paths.len() > MAX_ARTIFACTS {
        return context.error("Select between one and eight local npm tarballs.", format);
    }
    let mut inspected = Vec::new();
    for path in paths {
        match load(path) {
            Ok(inspection) => inspected.push(inspection),
            Err(error) => {
                context.refresh();
                return context.error(&error, format);
            }
        }
    }
    context.refresh();
    let report = context.with_redaction_coverage(inspection_projection(
        &inspected,
        &context.compiled,
        &context.diagnostics,
    ));
    let code = inspected.iter().map(inspection_code).max().unwrap_or(2);
    // A refused artifact is stronger than the advisory numeric exit code 2.
    let code = if inspected
        .iter()
        .any(|i| i.archive_state == NpmArchiveState::Refused)
    {
        1
    } else {
        code
    };
    output(&report, format, code)
}

pub fn diff(old: &Path, new: &Path, format: Format) -> i32 {
    let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
    let mut context = Context::capture();
    let pair = load(old).and_then(|old| load(new).map(|new| (old, new)));
    context.refresh();
    let (old, new) = match pair {
        Ok(pair) => pair,
        Err(error) => return context.error(&error, format),
    };
    let comparison = match compare_npm_releases(&old, &new) {
        Ok(comparison) => comparison,
        Err(error) => return context.error(error, format),
    };
    let code = if old.archive_state == NpmArchiveState::Refused
        || new.archive_state == NpmArchiveState::Refused
    {
        1
    } else if comparison.state != NpmComparisonState::Comparable
        || !comparison.deltas.is_empty()
        || !comparison.current_review_signals.is_empty()
    {
        2
    } else {
        0
    };
    let report = context.with_redaction_coverage(comparison_projection(
        &comparison,
        &context.compiled,
        &context.diagnostics,
    ));
    output(&report, format, code)
}

fn inspection_code(inspection: &NpmInspection) -> i32 {
    if inspection.archive_state == NpmArchiveState::Refused {
        1
    } else if !inspection.coverage.archive_complete
        || !inspection.coverage.metadata_complete
        || !inspection.coverage.static_analysis_complete
        || inspection
            .signals
            .iter()
            .any(|signal| signal.level == NpmSignalLevel::Review)
    {
        2
    } else {
        0
    }
}

fn inspection_status(inspection: &NpmInspection) -> &'static str {
    if inspection.archive_state == NpmArchiveState::Refused {
        "refused"
    } else if inspection
        .signals
        .iter()
        .any(|signal| signal.level == NpmSignalLevel::Review)
    {
        "review"
    } else if inspection_code(inspection) != 0 {
        "incomplete"
    } else {
        "accepted"
    }
}

/// Opens one regular no-follow handle; the core hashes and parses the same
/// bounded captured bytes. No preliminary path-content read supplies identity.
pub(crate) fn load(path: &Path) -> Result<NpmInspection, String> {
    let file =
        tirith_core::util::open_read_no_follow_capped(path, 512 * 1024 * 1024).map_err(|_| {
            format!(
                "Cannot open a bounded regular npm artifact: {}",
                path.display()
            )
        })?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "The artifact filename must be valid UTF-8.".to_owned())?;
    Ok(read_npm_tarball(file, filename, &NpmLimits::default()))
}

struct Context {
    compiled: CompiledCustomPatterns,
    diagnostics: Vec<String>,
}

impl Context {
    fn capture() -> Self {
        let cwd = std::env::current_dir()
            .ok()
            .map(|path| path.display().to_string());
        Self::capture_for(cwd.as_deref())
    }

    fn capture_for(cwd: Option<&str>) -> Self {
        // This advisory byte inspector does not issue runtime authorization.
        // LocalOnly captures trusted local DLP without remote network access.
        let snapshot = EffectivePolicySnapshot::resolve(cwd, ResolutionMode::LocalOnly);
        let compiled = CompiledCustomPatterns::new_silent(
            &tirith_core::policy::captured_policy_dlp_patterns_or(
                &snapshot.policy.dlp_custom_patterns,
            ),
        );
        let diagnostics =
            tirith_core::policy::drain_captured_policy_diagnostics_for_output(&compiled);
        Self {
            compiled,
            diagnostics,
        }
    }

    fn refresh(&mut self) {
        let cwd = std::env::current_dir()
            .ok()
            .map(|path| path.display().to_string());
        self.refresh_for(cwd.as_deref());
    }

    fn refresh_for(&mut self, cwd: Option<&str>) {
        let mut fresh = Self::capture_for(cwd);
        self.diagnostics.append(&mut fresh.diagnostics);
        self.diagnostics = self
            .diagnostics
            .iter()
            .map(|text| content(text, &fresh.compiled))
            .collect();
        self.compiled = fresh.compiled;
    }

    fn error(&self, error: &str, format: Format) -> i32 {
        let report = self.with_redaction_coverage(json!({"schema_version":1,"kind":"npm_artifact_error","status":"unavailable","message":content(error,&self.compiled),"diagnostics":self.diagnostics.iter().take(32).map(|s|content(s,&self.compiled)).collect::<Vec<_>>(),"omitted_diagnostics":self.diagnostics.len().saturating_sub(32)}));
        output(&report, format, 2)
    }

    fn with_redaction_coverage(&self, mut report: Value) -> Value {
        report["redaction"] = json!({"source":"trusted_local_policy","remote_policy":"unavailable_offline","effective_runtime_policy":false});
        report
    }
}

fn content(text: &str, compiled: &CompiledCustomPatterns) -> String {
    let redacted = tirith_core::redact::redact_sanitize_redact_with_compiled(text, compiled);
    if redacted.len() > 1024 {
        "[withheld: text exceeds display limit]".to_owned()
    } else {
        redacted
    }
}

fn optional_content(text: Option<&str>, compiled: &CompiledCustomPatterns) -> Value {
    text.map(|text| Value::String(content(text, compiled)))
        .unwrap_or(Value::Null)
}

fn hash_projection(text: Option<&str>, compiled: &CompiledCustomPatterns) -> Value {
    match text {
        Some(text)
            if text.len() == 64
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            Value::String(text.to_owned())
        }
        other => optional_content(other, compiled),
    }
}

fn artifact_projection(
    identity: &tirith_core::artifact::npm_archive::NpmArtifactIdentity,
    compiled: &CompiledCustomPatterns,
) -> Value {
    json!({"filename":content(&identity.filename,compiled),"name":optional_content(identity.name.as_deref(),compiled),"version":optional_content(identity.version.as_deref(),compiled),"sha256":hash_projection(identity.sha256.as_deref(),compiled),"compressed_bytes":identity.compressed_bytes})
}

fn coverage_projection(
    coverage: &NpmCoverage,
    compiled: &CompiledCustomPatterns,
    cap: usize,
) -> Value {
    json!({
        "analysis_scope": if coverage.analysis_scope == "bounded_static_patterns_and_native_triage; behavior_not_proven" { coverage.analysis_scope.clone() } else { content(&coverage.analysis_scope,compiled) },
        "archive_complete":coverage.archive_complete,"metadata_complete":coverage.metadata_complete,
        "static_analysis_complete":coverage.static_analysis_complete,
        "inspected_code_files":coverage.inspected_code_files,"inspected_code_bytes":coverage.inspected_code_bytes,
        "issues":coverage.issues.iter().take(cap).map(|issue|json!({"kind":issue.kind,"member":optional_content(issue.member.as_deref(),compiled),"detail":content(&issue.detail,compiled)})).collect::<Vec<_>>(),
        "total_issues":coverage.issues.len(),"omitted_issues":coverage.issues.len().saturating_sub(cap)
    })
}

fn signal_projection(signal: &NpmSignal, compiled: &CompiledCustomPatterns) -> Value {
    json!({"kind":signal.kind,"level":signal.level,"member":content(&signal.member,compiled),
        "capabilities":signal.capabilities,"lifecycle_events":signal.lifecycle_events.iter().map(|event| {
            if matches!(event.as_str(),"preinstall"|"install"|"postinstall"|"prepublish"|"preprepare"|"prepare"|"postprepare"|"prepublishOnly"|"prepack"|"postpack"|"publish"|"postpublish"|"dependencies") { event.clone() } else { content(event,compiled) }
        }).collect::<Vec<_>>(),"evidence":content(&signal.evidence,compiled)})
}

fn file_projection(
    file: &tirith_core::artifact::npm_archive::NpmFile,
    compiled: &CompiledCustomPatterns,
) -> Value {
    json!({"path":content(&file.path,compiled),"sha256":hash_projection(Some(&file.sha256),compiled),"size":file.size,"kind":file.kind,"executable":file.executable})
}

fn map_projection(
    map: &std::collections::BTreeMap<String, String>,
    compiled: &CompiledCustomPatterns,
    cap: usize,
) -> Value {
    // Dynamic metadata keys are content too; a row representation cannot lose
    // entries when two redacted names collapse to the same display marker.
    json!({"entries":map.iter().take(cap).map(|(name,value)|json!({"name":content(name,compiled),"value":content(value,compiled)})).collect::<Vec<_>>(),"total_entries":map.len(),"omitted_entries":map.len().saturating_sub(cap)})
}

fn one_inspection(
    inspection: &NpmInspection,
    compiled: &CompiledCustomPatterns,
    cap: usize,
) -> Value {
    let signals: Vec<_> = inspection
        .signals
        .iter()
        .filter(|s| s.level == NpmSignalLevel::Review)
        .chain(
            inspection
                .signals
                .iter()
                .filter(|s| s.level != NpmSignalLevel::Review),
        )
        .take(cap)
        .map(|signal| signal_projection(signal, compiled))
        .collect();
    json!({"schema_version":inspection.schema_version,"analyzer_version":if inspection.analyzer_version==NPM_ANALYZER_VERSION { inspection.analyzer_version.clone() } else { content(&inspection.analyzer_version,compiled) },
        "artifact":artifact_projection(&inspection.artifact,compiled),"archive_state":inspection.archive_state,"status":inspection_status(inspection),
        "limits":inspection.limits,"coverage":coverage_projection(&inspection.coverage,compiled,cap),
        "files":inspection.files.iter().take(cap).map(|file|file_projection(file,compiled)).collect::<Vec<_>>(),
        "total_files":inspection.files.len(),"omitted_files":inspection.files.len().saturating_sub(cap),
        "signals":signals,"total_signals":inspection.signals.len(),"omitted_signals":inspection.signals.len().saturating_sub(cap),
        "metadata":inspection.metadata.as_ref().map(|metadata|json!({"scripts":map_projection(&metadata.scripts,compiled,cap),"bin":map_projection(&metadata.bin,compiled,cap),"main":optional_content(metadata.main.as_deref(),compiled),"dependencies":map_projection(&metadata.dependencies,compiled,cap),"implicit_node_gyp_install":metadata.implicit_node_gyp_install,
            "bundled_dependencies":metadata.bundled_dependencies.iter().take(cap).map(|name|content(name,compiled)).collect::<Vec<_>>(),"omitted_bundled_dependencies":metadata.bundled_dependencies.len().saturating_sub(cap)})),
        "provenance_verification":if inspection.provenance_verification=="not_performed_offline" { inspection.provenance_verification.clone() } else { content(&inspection.provenance_verification,compiled) }
    })
}

/// Bounded, DLP-safe read model reusable by the browser report store. It consumes
/// captured inspections only; callers cannot inject a browser-selected path.
pub(crate) fn inspection_projection(
    inspections: &[NpmInspection],
    compiled: &CompiledCustomPatterns,
    diagnostics: &[String],
) -> Value {
    let mut cap = 32usize;
    loop {
        let selected = &inspections[..inspections.len().min(MAX_ARTIFACTS)];
        let status = if selected
            .iter()
            .any(|i| i.archive_state == NpmArchiveState::Refused)
        {
            "refused"
        } else if selected.iter().any(|i| inspection_status(i) == "review") {
            "review"
        } else if selected.iter().any(|i| inspection_code(i) != 0)
            || inspections.len() > MAX_ARTIFACTS
        {
            "incomplete"
        } else {
            "accepted"
        };
        let value = json!({"schema_version":1,"kind":"npm_inspection","status":status,"offline":true,
            "artifacts":selected.iter().map(|inspection|one_inspection(inspection,compiled,cap)).collect::<Vec<_>>(),
            "total_artifacts":inspections.len(),"omitted_artifacts":inspections.len().saturating_sub(MAX_ARTIFACTS),
            "diagnostics":diagnostics.iter().take(cap).map(|s|content(s,compiled)).collect::<Vec<_>>(),"omitted_diagnostics":diagnostics.len().saturating_sub(cap)});
        // Reserve space for the caller's fixed redaction-coverage metadata.
        if serde_json::to_vec(&value).is_ok_and(|bytes| bytes.len() <= MAX_REPORT_BYTES - 512)
            || cap == 0
        {
            return value;
        }
        cap /= 2;
    }
}

fn delta_projection(delta: &NpmDelta, compiled: &CompiledCustomPatterns) -> Value {
    // The tagged variants contain canonical enums and hashes at known positions;
    // every free-form field, including before/after scripts and map keys, is DLP.
    let mut value = serde_json::to_value(delta).unwrap_or(Value::Null);
    if let Some(file) = match delta {
        NpmDelta::MemberAdded { file } | NpmDelta::MemberRemoved { file } => Some(file),
        _ => None,
    } {
        value["file"] = file_projection(file, compiled);
        return value;
    }
    if let Some(fields) = value.as_object_mut() {
        for (key, value) in fields {
            if matches!(key.as_str(), "old_sha256" | "new_sha256") {
                *value = hash_projection(value.as_str(), compiled);
                continue;
            }
            if matches!(
                key.as_str(),
                "kind" | "old_kind" | "new_kind" | "capability"
            ) {
                continue;
            }
            if let Some(text) = value.as_str() {
                *value = Value::String(content(text, compiled));
            }
        }
    }
    value
}

pub(crate) fn comparison_projection(
    comparison: &NpmComparison,
    compiled: &CompiledCustomPatterns,
    diagnostics: &[String],
) -> Value {
    let mut cap = 64usize;
    loop {
        let value = json!({"schema_version":comparison.schema_version,"kind":"npm_comparison","status":comparison.state,
            "old_artifact":artifact_projection(&comparison.old_artifact,compiled),"new_artifact":artifact_projection(&comparison.new_artifact,compiled),
            "same_artifact":comparison.same_artifact,"capability_comparison_available":comparison.capability_comparison_available,
            "old_coverage":coverage_projection(&comparison.old_coverage,compiled,cap),"new_coverage":coverage_projection(&comparison.new_coverage,compiled,cap),"notes":comparison.notes,
            "deltas":comparison.deltas.iter().take(cap).map(|delta|delta_projection(delta,compiled)).collect::<Vec<_>>(),
            "total_deltas":comparison.deltas.len()+comparison.omitted_deltas,"omitted_deltas":comparison.omitted_deltas+comparison.deltas.len().saturating_sub(cap),
            "current_review_signals":comparison.current_review_signals.iter().take(cap).map(|signal|signal_projection(signal,compiled)).collect::<Vec<_>>(),
            "omitted_review_signals":comparison.current_review_signals.len().saturating_sub(cap),
            "diagnostics":diagnostics.iter().take(cap).map(|s|content(s,compiled)).collect::<Vec<_>>(),"omitted_diagnostics":diagnostics.len().saturating_sub(cap)});
        if serde_json::to_vec(&value).is_ok_and(|bytes| bytes.len() <= MAX_REPORT_BYTES - 512)
            || cap == 0
        {
            return value;
        }
        cap /= 2;
    }
}

fn output(report: &Value, format: Format, code: i32) -> i32 {
    let success = match format {
        Format::Json => {
            super::write_json_stdout(report, "tirith npm inspection: failed to write JSON report")
        }
        Format::Sarif => super::write_json_stdout(
            &sarif_projection(report),
            "tirith npm inspection: failed to write SARIF report",
        ),
        Format::Human => {
            print_human(report);
            true
        }
    };
    if success {
        code
    } else if code == 0 {
        1
    } else {
        code
    }
}

fn print_human(report: &Value) {
    let text = |value: &Value| {
        super::sanitize_for_human_output(value.as_str().unwrap_or("unknown"), false)
    };
    eprintln!("npm {}: {}", text(&report["kind"]), text(&report["status"]));
    if report["redaction"]["remote_policy"] == "unavailable_offline" {
        eprintln!(
            "  Redaction uses trusted local policy; remote policy rules are unavailable offline."
        );
    }
    if let Some(message) = report.get("message") {
        eprintln!("  {}", text(message));
    }
    if let Some(artifacts) = report["artifacts"].as_array() {
        for artifact in artifacts {
            eprintln!(
                "  {}: {}",
                text(&artifact["artifact"]["filename"]),
                text(&artifact["status"])
            );
            eprintln!("    SHA-256: {}", text(&artifact["artifact"]["sha256"]));
            eprintln!(
                "    {} files; archive={}, metadata={}, static={}",
                artifact["total_files"],
                artifact["coverage"]["archive_complete"],
                artifact["coverage"]["metadata_complete"],
                artifact["coverage"]["static_analysis_complete"]
            );
            if let Some(signals) = artifact["signals"].as_array() {
                for signal in signals.iter().take(8) {
                    eprintln!(
                        "    {}: {}",
                        text(&signal["kind"]),
                        text(&signal["evidence"])
                    );
                }
            }
            if let Some(issues) = artifact["coverage"]["issues"].as_array() {
                for issue in issues.iter().take(8) {
                    eprintln!(
                        "    Coverage {}: {}",
                        text(&issue["kind"]),
                        text(&issue["detail"])
                    );
                }
            }
        }
    }
    if report["kind"] == "npm_comparison" {
        eprintln!("  Old SHA-256: {}", text(&report["old_artifact"]["sha256"]));
        eprintln!("  New SHA-256: {}", text(&report["new_artifact"]["sha256"]));
        eprintln!(
            "  {} change(s); capability comparison available={}",
            report["total_deltas"], report["capability_comparison_available"]
        );
        if let Some(deltas) = report["deltas"].as_array() {
            for delta in deltas.iter().take(20) {
                eprintln!("    {}", text(&delta["kind"]));
            }
        }
        if let Some(notes) = report["notes"].as_array() {
            for note in notes {
                eprintln!("    Comparison: {}", text(note));
            }
        }
    }
    if let Some(diagnostics) = report["diagnostics"].as_array() {
        for diagnostic in diagnostics {
            eprintln!("  Policy: {}", text(diagnostic));
        }
    }
    eprintln!("  Local static inspection; package behavior is not proven. JSON reports include coverage and display omission counts.");
}

/// SARIF 2.1.0 adapter over the already-redacted bounded report. Review signals
/// are warnings; structural refusal is an error. Coverage stays visible in run
/// properties and notifications, including when no finding was produced.
pub(crate) fn sarif_projection(report: &Value) -> Value {
    let mut results = Vec::new();
    let mut notifications = Vec::new();
    let mut add_signal = |signal: &Value| {
        if signal["level"] != "review" {
            return;
        }
        results.push(json!({"ruleId":format!("npm_{}",signal["kind"].as_str().unwrap_or("review")),"level":"warning",
            "message":{"text":signal["evidence"]},"locations":[{"logicalLocations":[{"name":signal["member"],"kind":"module"}]}],"properties":{"capabilities":signal["capabilities"],"lifecycleEvents":signal["lifecycle_events"]}}));
    };
    if let Some(artifacts) = report["artifacts"].as_array() {
        for artifact in artifacts {
            if let Some(signals) = artifact["signals"].as_array() {
                for signal in signals {
                    add_signal(signal);
                }
            }
        }
    }
    if let Some(signals) = report["current_review_signals"].as_array() {
        for signal in signals {
            add_signal(signal);
        }
    }
    if report["status"] == "refused" || report["status"] == "unavailable" {
        results.push(json!({"ruleId":"npm_inspection_refused","level":"error","message":{"text":report.get("message").cloned().unwrap_or_else(||json!("The exact local artifact inspection or comparison was refused or unavailable."))}}));
    }
    if report["status"] == "incomplete"
        || report["status"] == "qualified"
        || report["status"] == "review"
    {
        notifications.push(json!({"level":"warning","message":{"text":"Review the retained coverage fields; absence of additional findings is not evidence of complete behavior analysis."}}));
    }
    json!({"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"tirith-npm-static","version":env!("CARGO_PKG_VERSION")}},"results":results,"invocations":[{"executionSuccessful":report["kind"]!="npm_artifact_error","toolExecutionNotifications":notifications}],"properties":{"tirithReport":report}}]})
}

#[cfg(test)]
#[path = "npm_artifact_tests.rs"]
mod tests;
