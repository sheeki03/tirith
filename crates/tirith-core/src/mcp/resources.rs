use serde_json::json;

use crate::scan;

use super::types::{ContentItem, ResourceContent, ResourceDefinition, ToolCallResult};

const PROJECT_SAFETY_URI: &str = "tirith://project-safety";

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
    match uri {
        PROJECT_SAFETY_URI => read_project_safety(),
        _ => ToolCallResult {
            content: vec![ContentItem {
                content_type: "text".into(),
                text: format!("Unknown resource: {uri}"),
            }],
            is_error: true,
            structured_content: None,
        },
    }
}

/// Read resource as ResourceContent for the resources/read response format.
pub fn read_content(uri: &str) -> Result<Vec<ResourceContent>, String> {
    match uri {
        PROJECT_SAFETY_URI => {
            let cwd = std::env::current_dir()
                .map_err(|e| format!("Cannot determine working directory: {e}"))?;

            let config = scan::ScanConfig {
                path: cwd,
                recursive: true,
                fail_on: crate::verdict::Severity::Critical,
                ignore_patterns: vec![],
                max_files: None,
            };

            let policy = crate::policy::Policy::discover(None);
            let mut result = scan::scan(&config);
            for fr in &mut result.file_results {
                crate::redact::redact_findings(&mut fr.findings, &policy.dlp_custom_patterns);
            }

            let report = json!({
                "scanned_count": result.scanned_count,
                "skipped_count": result.skipped_count,
                "truncated": result.truncated,
                "total_findings": result.total_findings(),
                "files": result.file_results.iter()
                    .filter(|r| !r.findings.is_empty())
                    .map(|r| json!({
                        "path": r.path.display().to_string(),
                        "is_config_file": r.is_config_file,
                        "findings": r.findings,
                    }))
                    .collect::<Vec<_>>(),
            });

            let text = serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string());

            Ok(vec![ResourceContent {
                uri: PROJECT_SAFETY_URI.into(),
                mime_type: "application/json".into(),
                text,
            }])
        }
        _ => Err(format!("Unknown resource: {uri}")),
    }
}

fn read_project_safety() -> ToolCallResult {
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => {
            return ToolCallResult {
                content: vec![ContentItem {
                    content_type: "text".into(),
                    text: format!("Cannot determine working directory: {e}"),
                }],
                is_error: true,
                structured_content: None,
            }
        }
    };

    let config = scan::ScanConfig {
        path: cwd,
        recursive: true,
        fail_on: crate::verdict::Severity::Critical,
        ignore_patterns: vec![],
        max_files: None,
    };

    let policy = crate::policy::Policy::discover(None);
    let mut result = scan::scan(&config);
    for fr in &mut result.file_results {
        crate::redact::redact_findings(&mut fr.findings, &policy.dlp_custom_patterns);
    }

    let total = result.total_findings();

    let structured = json!({
        "scanned_count": result.scanned_count,
        "skipped_count": result.skipped_count,
        "truncated": result.truncated,
        "total_findings": total,
        "files": result.file_results.iter()
            .filter(|r| !r.findings.is_empty())
            .map(|r| json!({
                "path": r.path.display().to_string(),
                "is_config_file": r.is_config_file,
                "findings": r.findings,
            }))
            .collect::<Vec<_>>(),
    });

    let text = if total == 0 {
        format!(
            "Project safety: {} files scanned, no issues found.",
            result.scanned_count
        )
    } else {
        let files_with = result
            .file_results
            .iter()
            .filter(|r| !r.findings.is_empty())
            .count();
        format!(
            "Project safety: {} files scanned, {} finding(s) in {} file(s).",
            result.scanned_count, total, files_with
        )
    };

    ToolCallResult {
        content: vec![ContentItem {
            content_type: "text".into(),
            text,
        }],
        is_error: false,
        structured_content: Some(structured),
    }
}
