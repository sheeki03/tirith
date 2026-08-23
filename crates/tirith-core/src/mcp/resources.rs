use serde_json::json;

use crate::scan;

use super::types::{ContentItem, ResourceContent, ResourceDefinition, ToolCallResult};

const PROJECT_SAFETY_URI: &str = "tirith://project-safety";
pub const MCP_SCAN_MAX_FILES: usize = 5_000;

pub(super) fn scan_analysis_incomplete(result: &scan::ScanResult) -> bool {
    result.analysis_incomplete()
}

pub(super) fn bounded_scan_projection(
    result: &scan::ScanResult,
    total_findings: usize,
    completeness_policy_violated: Option<bool>,
    compiled: &crate::redact::CompiledCustomPatterns,
) -> serde_json::Value {
    let scan_incomplete = scan_analysis_incomplete(result);
    let mut base = json!({
        "scanned_count": result.scanned_count,
        "skipped_count": result.skipped_count,
        "truncated": result.truncated,
        "truncation_reason": result.truncation_reason.as_deref().map(|reason| {
            crate::redact::redact_sanitize_redact_with_compiled(reason, compiled)
        }),
        "panic_count": result.panic_files.len(),
        "panic_files": [],
        "analysis_incomplete": scan_incomplete,
        "scan_analysis_incomplete": scan_incomplete,
        "total_findings": total_findings,
        "coverage_gaps": [],
        "files": [],
        "dlp_redaction_incomplete": compiled.incomplete_reason().is_some(),
    });
    if let Some(violated) = completeness_policy_violated {
        base["completeness_policy_violated"] = json!(violated);
    }
    crate::redact::redact_json_strings(&mut base, compiled);
    let mut projection = crate::verdict::BoundedJsonProjection::new(base);
    for rank in 0..3 {
        for (file_index, file) in result.file_results.iter().enumerate() {
            for finding in &file.findings {
                if scan_finding_rank(finding) != rank {
                    continue;
                }
                let mut item = json!({
                    "path": file.path.display().to_string(),
                    "is_config_file": file.is_config_file,
                    "_projection_file_id": file_index,
                    "findings": [finding],
                });
                crate::redact::redact_json_strings(&mut item, compiled);
                let _ = projection.push_array_item("files", item, 1);
            }
        }
        if rank == 1 {
            for path in &result.panic_files {
                let path = crate::redact::redact_sanitize_redact_with_compiled(
                    &path.display().to_string(),
                    compiled,
                );
                let _ =
                    projection.push_array_item("panic_files", serde_json::Value::String(path), 1);
            }
            for gap in &result.coverage_gaps {
                let mut gap = serde_json::to_value(gap).unwrap_or(serde_json::Value::Null);
                crate::redact::redact_json_strings(&mut gap, compiled);
                let _ = projection.push_array_item("coverage_gaps", gap, 1);
            }
        }
    }
    let mut output = projection.finish();
    crate::verdict::regroup_file_finding_projection(&mut output);
    output
}

fn scan_finding_rank(finding: &crate::verdict::Finding) -> u8 {
    if finding.severity == crate::verdict::Severity::Critical {
        0
    } else if finding.severity == crate::verdict::Severity::High
        || finding.rule_id == crate::verdict::RuleId::AnalysisIncomplete
    {
        1
    } else {
        2
    }
}

/// Return available resources.
pub fn list() -> Vec<ResourceDefinition> {
    vec![ResourceDefinition {
        uri: PROJECT_SAFETY_URI.into(),
        name: "Project Safety Report".into(),
        description: "Scan the current working directory for AI config file security \
                      issues and return an aggregated safety report."
            .into(),
        mime_type: "application/json".into(),
    }]
}

/// Read a resource by URI.
pub fn read(uri: &str) -> ToolCallResult {
    let _capture = crate::policy::PolicyDiagnosticCapture::start();
    let policy = crate::policy::Policy::discover(None);
    crate::policy::freeze_captured_policy_dlp_patterns(&policy.dlp_custom_patterns);
    let compiled = crate::redact::CompiledCustomPatterns::new_silent(&policy.dlp_custom_patterns);
    let mut result = match uri {
        PROJECT_SAFETY_URI => read_project_safety(&policy, &compiled),
        _ => ToolCallResult {
            content: vec![ContentItem {
                content_type: "text".into(),
                text: crate::redact::redact_sanitize_redact_with_compiled(
                    &format!("Unknown resource: {uri}"),
                    &compiled,
                ),
            }],
            is_error: true,
            structured_content: None,
        },
    };
    attach_policy_diagnostics(&mut result, &compiled);
    redact_tool_result_strings(&mut result, &compiled);
    super::output_filter::bound_tool_result_for_output(&mut result);
    result
}

/// Read resource as ResourceContent for the resources/read response format.
pub fn read_content(uri: &str) -> Result<Vec<ResourceContent>, String> {
    let _capture = crate::policy::PolicyDiagnosticCapture::start();
    let policy = crate::policy::Policy::discover(None);
    crate::policy::freeze_captured_policy_dlp_patterns(&policy.dlp_custom_patterns);
    let compiled = crate::redact::CompiledCustomPatterns::new_silent(&policy.dlp_custom_patterns);
    match uri {
        PROJECT_SAFETY_URI => {
            let cwd = std::env::current_dir().map_err(|error| {
                crate::redact::redact_sanitize_redact_with_compiled(
                    &format!("Cannot determine working directory: {error}"),
                    &compiled,
                )
            })?;

            let config = scan::ScanConfig {
                path: cwd,
                recursive: true,
                fail_on: crate::verdict::Severity::Critical,
                ignore_patterns: policy.scan.ignore_patterns.clone(),
                include_patterns: vec![],
                exclude_patterns: vec![],
                max_files: Some(MCP_SCAN_MAX_FILES),
            };
            let mut result = scan::scan(&config);
            let total_findings = result.total_findings();
            for fr in &mut result.file_results {
                crate::redact::redact_findings_with_compiled(&mut fr.findings, &compiled);
            }

            // repo-0293: honor the operator's completeness policy — under
            // `scan.require_complete` (or per-gap Fail actions) coverage gaps
            // must surface as an explicit incomplete marker, not a clean
            // resource response.
            let completeness_violation = result.has_analysis_incomplete_finding()
                || result.truncated
                || (!result.coverage_gaps.is_empty()
                    && (policy.scan.require_complete
                        || result.coverage_gaps.iter().any(|gap| {
                            matches!(
                                policy.scan.action_for_gap_kind(gap.kind),
                                crate::policy::GapAction::Fail
                            )
                        })));

            let mut report = bounded_scan_projection(
                &result,
                total_findings,
                Some(completeness_violation),
                &compiled,
            );
            append_policy_diagnostics_to_json(&mut report, &compiled);
            crate::redact::redact_json_strings(&mut report, &compiled);
            let report = crate::verdict::bound_json_value_for_output(report);

            let text = serde_json::to_string(&report).map_err(|error| {
                crate::redact::redact_sanitize_redact_with_compiled(
                    &format!("resource serialization failed: {error}"),
                    &compiled,
                )
            })?;

            Ok(vec![ResourceContent {
                uri: PROJECT_SAFETY_URI.into(),
                mime_type: "application/json".into(),
                text,
            }])
        }
        _ => {
            let mut error = crate::redact::redact_sanitize_redact_with_compiled(
                &format!("Unknown resource: {uri}"),
                &compiled,
            );
            let diagnostics =
                crate::policy::drain_captured_policy_diagnostics_for_output(&compiled);
            if !diagnostics.is_empty() {
                error.push_str("; policy diagnostics: ");
                error.push_str(&diagnostics.join(" | "));
            }
            Err(crate::output::sanitize_human_field_with_compiled(
                &error, &compiled,
            ))
        }
    }
}

fn read_project_safety(
    policy: &crate::policy::Policy,
    compiled: &crate::redact::CompiledCustomPatterns,
) -> ToolCallResult {
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => {
            return ToolCallResult {
                content: vec![ContentItem {
                    content_type: "text".into(),
                    text: crate::output::sanitize_human_field_with_compiled(
                        &format!("Cannot determine working directory: {e}"),
                        compiled,
                    ),
                }],
                is_error: true,
                structured_content: None,
            }
        }
    };

    read_project_safety_at(cwd, policy, compiled)
}

fn read_project_safety_at(
    cwd: std::path::PathBuf,
    policy: &crate::policy::Policy,
    compiled: &crate::redact::CompiledCustomPatterns,
) -> ToolCallResult {
    let config = scan::ScanConfig {
        path: cwd,
        recursive: true,
        fail_on: crate::verdict::Severity::Critical,
        ignore_patterns: policy.scan.ignore_patterns.clone(),
        include_patterns: vec![],
        exclude_patterns: vec![],
        max_files: Some(MCP_SCAN_MAX_FILES),
    };
    let mut result = scan::scan(&config);
    let total = result.total_findings();
    for fr in &mut result.file_results {
        crate::redact::redact_findings_with_compiled(&mut fr.findings, compiled);
    }

    let structured = bounded_scan_projection(&result, total, None, compiled);
    let analysis_incomplete = scan_analysis_incomplete(&result);

    let panic_note = if result.panic_files.is_empty() {
        String::new()
    } else {
        format!(
            " WARNING: {} file(s) skipped due to a rule panic — results may be incomplete.",
            result.panic_files.len()
        )
    };
    let coverage_note = if !analysis_incomplete {
        String::new()
    } else {
        format!(
            " WARNING: analysis incomplete ({} coverage gap(s), analyzer_incomplete={}, truncated={}).",
            result.coverage_gaps.len(),
            result.has_analysis_incomplete_finding(),
            result.truncated
        )
    };
    let truncation_note = if result.truncated {
        format!(
            " {}",
            result
                .truncation_reason
                .as_deref()
                .unwrap_or("Scan file budget exhausted; additional files were omitted.")
        )
    } else {
        String::new()
    };
    let text = if total == 0 {
        if !analysis_incomplete {
            format!(
                "Project safety: {} files scanned, no issues found.{panic_note}",
                result.scanned_count
            )
        } else {
            format!(
                "Project safety: {} files scanned; analysis incomplete.{truncation_note}{coverage_note}{panic_note}",
                result.scanned_count
            )
        }
    } else {
        let files_with = result
            .file_results
            .iter()
            .filter(|r| !r.findings.is_empty())
            .count();
        format!(
            "Project safety: {} files scanned, {} finding(s) in {} file(s).{truncation_note}{coverage_note}{panic_note}",
            result.scanned_count, total, files_with,
        )
    };
    let text = crate::redact::redact_sanitize_redact_with_compiled(&text, compiled);
    let text = crate::output::sanitize_human_field_with_compiled(&text, compiled);
    let text = crate::verdict::bound_text_for_output(text);

    ToolCallResult {
        content: vec![ContentItem {
            content_type: "text".into(),
            text,
        }],
        is_error: analysis_incomplete,
        structured_content: Some(structured),
    }
}

fn attach_policy_diagnostics(
    result: &mut ToolCallResult,
    compiled: &crate::redact::CompiledCustomPatterns,
) {
    let diagnostics = crate::policy::drain_captured_policy_diagnostics_for_output(compiled);
    if diagnostics.is_empty() {
        return;
    }
    let diagnostics = diagnostics
        .into_iter()
        .map(|diagnostic| crate::output::sanitize_human_field_with_compiled(&diagnostic, compiled))
        .collect::<Vec<_>>();
    result.content.push(ContentItem {
        content_type: "text".into(),
        text: format!("Policy diagnostics: {}", diagnostics.join(" | ")),
    });
    let structured = result
        .structured_content
        .get_or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if let Some(object) = structured.as_object_mut() {
        object.insert(
            "policy_diagnostics_count".to_string(),
            diagnostics.len().into(),
        );
        object.insert("policy_diagnostics".to_string(), json!(diagnostics));
    }
}

pub(super) fn redact_tool_result_strings(
    result: &mut ToolCallResult,
    compiled: &crate::redact::CompiledCustomPatterns,
) {
    for content in &mut result.content {
        content.content_type =
            crate::redact::redact_sanitize_redact_with_compiled(&content.content_type, compiled);
        content.text = crate::redact::redact_sanitize_redact_with_compiled(&content.text, compiled);
    }
    if let Some(structured) = result.structured_content.as_mut() {
        crate::redact::redact_json_strings(structured, compiled);
    }
}

fn append_policy_diagnostics_to_json(
    value: &mut serde_json::Value,
    compiled: &crate::redact::CompiledCustomPatterns,
) {
    let diagnostics = crate::policy::drain_captured_policy_diagnostics_for_output(compiled);
    if diagnostics.is_empty() {
        return;
    }
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "policy_diagnostics_count".to_string(),
            diagnostics.len().into(),
        );
        object.insert("policy_diagnostics".to_string(), json!(diagnostics));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(
        rule_id: crate::verdict::RuleId,
        severity: crate::verdict::Severity,
        description: String,
    ) -> crate::verdict::Finding {
        crate::verdict::Finding {
            rule_id,
            severity,
            title: "finding".to_string(),
            description,
            evidence: Vec::new(),
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }
    }

    #[test]
    fn aggregate_projection_skips_oversized_low_and_keeps_later_critical() {
        let result = scan::ScanResult {
            scanned_count: 1,
            skipped_count: 0,
            file_results: vec![scan::FileScanResult {
                path: std::path::PathBuf::from("mixed.txt"),
                findings: vec![
                    finding(
                        crate::verdict::RuleId::ConfigSuspiciousIndicator,
                        crate::verdict::Severity::Low,
                        "l".repeat(crate::verdict::MAX_PRESENTATION_BYTES),
                    ),
                    finding(
                        crate::verdict::RuleId::BidiControls,
                        crate::verdict::Severity::Critical,
                        "critical survives".to_string(),
                    ),
                ],
                is_config_file: false,
                coverage_gaps: Vec::new(),
            }],
            truncated: false,
            truncation_reason: None,
            panic_files: Vec::new(),
            coverage_gaps: Vec::new(),
        };

        let compiled = crate::redact::CompiledCustomPatterns::new_silent(&[]);
        let projection = bounded_scan_projection(&result, 2, None, &compiled);
        let serialized = serde_json::to_string(&projection).unwrap();
        assert!(serialized.contains("bidi_controls"));
        assert!(!serialized.contains(&"l".repeat(1024)));
        assert_eq!(projection["presentation_truncated"], true);
    }

    #[test]
    fn aggregate_projection_regroups_findings_into_one_file_entry() {
        let result = scan::ScanResult {
            scanned_count: 1,
            skipped_count: 0,
            file_results: vec![scan::FileScanResult {
                path: std::path::PathBuf::from("CLAUDE.md"),
                findings: vec![
                    finding(
                        crate::verdict::RuleId::ConfigInjection,
                        crate::verdict::Severity::High,
                        "one".to_string(),
                    ),
                    finding(
                        crate::verdict::RuleId::BidiControls,
                        crate::verdict::Severity::Critical,
                        "two".to_string(),
                    ),
                ],
                is_config_file: true,
                coverage_gaps: Vec::new(),
            }],
            truncated: false,
            truncation_reason: None,
            panic_files: Vec::new(),
            coverage_gaps: Vec::new(),
        };
        let compiled = crate::redact::CompiledCustomPatterns::new_silent(&[]);
        let projection = bounded_scan_projection(&result, 2, None, &compiled);
        assert_eq!(projection["files"].as_array().unwrap().len(), 1);
        assert_eq!(
            projection["files"][0]["findings"].as_array().unwrap().len(),
            2
        );
    }

    #[test]
    fn analyzer_incomplete_finding_marks_aggregate_projection_incomplete_without_driver_gap() {
        let result = scan::ScanResult {
            scanned_count: 1,
            skipped_count: 0,
            file_results: vec![scan::FileScanResult {
                path: std::path::PathBuf::from("malformed.pdf"),
                findings: vec![finding(
                    crate::verdict::RuleId::AnalysisIncomplete,
                    crate::verdict::Severity::High,
                    "PDF parser coverage was incomplete".to_string(),
                )],
                is_config_file: false,
                coverage_gaps: Vec::new(),
            }],
            truncated: false,
            truncation_reason: None,
            panic_files: Vec::new(),
            coverage_gaps: Vec::new(),
        };

        let compiled = crate::redact::CompiledCustomPatterns::new_silent(&[]);
        let projection = bounded_scan_projection(&result, 1, None, &compiled);
        assert!(scan_analysis_incomplete(&result));
        assert_eq!(projection["analysis_incomplete"], true);
        assert_eq!(projection["scan_analysis_incomplete"], true);
    }

    #[test]
    fn actual_project_safety_resource_fails_closed_for_malformed_pdf() {
        let root = tempfile::tempdir().expect("create resource scan root");
        std::fs::write(
            root.path().join("malformed.pdf"),
            b"%PDF-1.7\nnot a complete PDF\n%%EOF\n",
        )
        .unwrap();
        let policy = crate::policy::Policy::default();
        let compiled = crate::redact::CompiledCustomPatterns::new_silent(&[]);

        let response = read_project_safety_at(root.path().to_path_buf(), &policy, &compiled);
        let structured = response
            .structured_content
            .as_ref()
            .expect("project-safety structured response");
        assert!(response.is_error);
        assert_eq!(structured["analysis_incomplete"], true);
        assert_eq!(
            structured["coverage_gaps"][0]["kind"],
            "pdf_analyzer_incomplete"
        );
        assert!(response.content[0].text.contains("analysis incomplete"));
        assert!(!response.content[0].text.contains("no issues found"));
    }

    #[test]
    fn tool_result_strings_are_recursively_scrubbed_before_transport_bounding() {
        let secret = "C02_MCP_SPLIT_SECRET";
        let split = format!("{}\u{1b}[31m{}", &secret[..8], &secret[8..]);
        let compiled = crate::redact::CompiledCustomPatterns::new_silent(&[regex::escape(secret)]);
        let mut result = ToolCallResult {
            content: vec![ContentItem {
                content_type: format!("text/{split}"),
                text: format!("message {split}"),
            }],
            is_error: true,
            structured_content: Some(json!({"nested": [{"error": split}]})),
        };

        redact_tool_result_strings(&mut result, &compiled);
        super::super::output_filter::bound_tool_result_for_output(&mut result);

        let rendered = serde_json::to_string(&result).unwrap();
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains('\u{1b}'));
        assert!(rendered.contains("[REDACTED:custom]"));
    }
}
