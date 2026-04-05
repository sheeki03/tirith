use serde::Serialize;
use tirith_core::session_warnings::{self, HiddenEvent, SessionWarnings, WarningEvent};

/// JSON output structure for `tirith warnings --json`.
#[derive(Serialize)]
struct WarningsJson {
    session_id: String,
    session_start: String,
    total_warnings: u32,
    hidden_findings: u32,
    hidden_low: u32,
    hidden_info: u32,
    paranoia: u8,
    events: Vec<WarningEvent>,
    top_rules: Vec<(String, u32)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hidden_events: Option<Vec<HiddenEvent>>,
}

/// Run the `tirith warnings` command.
///
/// Returns 0 always (informational command, not enforcement).
pub fn run(
    clear: bool,
    session: Option<&str>,
    json: bool,
    summary: bool,
    show_hidden: bool,
) -> i32 {
    let sid = match session {
        Some(s) => s.to_string(),
        None => tirith_core::session::resolve_session_id(),
    };

    let warnings = session_warnings::load(&sid);

    // Load paranoia from local policy (no network fetch for shell-exit hot path).
    let cwd = std::env::current_dir().ok();
    let cwd_str = cwd.as_ref().and_then(|p| p.to_str());
    let policy = tirith_core::policy::Policy::discover_partial(cwd_str);
    let paranoia = policy.paranoia;

    let hidden_count = warnings.hidden_findings;

    // Short-circuit: nothing to show at all
    if warnings.total_warnings == 0 && hidden_count == 0 && !show_hidden {
        if json {
            let out = WarningsJson {
                session_id: warnings.session_id.clone(),
                session_start: warnings.session_start.clone(),
                total_warnings: 0,
                hidden_findings: 0,
                hidden_low: 0,
                hidden_info: 0,
                paranoia,
                events: Vec::new(),
                top_rules: Vec::new(),
                hidden_events: None,
            };
            if let Ok(s) = serde_json::to_string_pretty(&out) {
                println!("{s}");
            }
        } else if !summary {
            println!("No warnings in current session.");
        }
        maybe_clear(clear, &sid);
        return 0;
    }

    // If --hidden requested and there are hidden events but no visible warnings,
    // show the hidden events even when we would normally short-circuit.
    if show_hidden && warnings.total_warnings == 0 && hidden_count == 0 {
        if !warnings.hidden_events.is_empty() {
            if json {
                print_json(&warnings, &[], paranoia, true);
            } else {
                print_hidden_table(&warnings);
            }
            maybe_clear(clear, &sid);
            return 0;
        }
        if !json && !summary {
            println!("No warnings in current session.");
        }
        maybe_clear(clear, &sid);
        return 0;
    }

    // Summary mode: gate hidden-only output at >= 3 to avoid noise on shell exit
    if warnings.total_warnings == 0 && hidden_count < 3 && summary {
        maybe_clear(clear, &sid);
        return 0;
    }

    // Handle zero warnings but significant hidden findings (>= 3) in summary mode
    if warnings.total_warnings == 0 && hidden_count >= 3 && summary {
        eprintln!(
            "tirith: {hidden_count} hidden findings suppressed at paranoia={paranoia} \u{2014} run 'tirith doctor' for details"
        );
        maybe_clear(clear, &sid);
        return 0;
    }

    let top_rules = warnings.top_rules();

    if summary {
        print_summary(&warnings, &top_rules);
    } else if json {
        print_json(&warnings, &top_rules, paranoia, show_hidden);
    } else {
        print_table(&warnings, &top_rules, paranoia);
        if show_hidden {
            print_hidden_table(&warnings);
        }
    }

    maybe_clear(clear, &sid);
    0
}

/// Print one-line summary to stderr (for shell exit hooks).
fn print_summary(w: &SessionWarnings, top_rules: &[(String, u32)]) {
    let rule_summary: String = top_rules
        .iter()
        .map(|(rule, count)| format!("{count} {rule}"))
        .collect::<Vec<_>>()
        .join(", ");

    let hidden = w.hidden_findings;
    if hidden >= 3 {
        eprintln!(
            "tirith: {} warning(s) ({}) + {} hidden \u{2014} run 'tirith warnings' for details",
            w.total_warnings, rule_summary, hidden,
        );
        // Use stored per-severity counts (recorded at detection time) for accurate guidance
        let hidden_desc = hidden_severity_desc(w.hidden_low, w.hidden_info);
        let next_level = next_paranoia_for_hidden(w.hidden_low, w.hidden_info);
        if let Some(next) = next_level {
            eprintln!(
                "  \u{21b3} {} findings hidden ({hidden_desc}). Set 'paranoia: {next}' in .tirith/policy.yaml to see them.",
                hidden,
            );
        }
    } else {
        eprintln!(
            "tirith: {} warning(s) ({}) \u{2014} run 'tirith warnings' for details",
            w.total_warnings, rule_summary,
        );
    }
}

/// Print structured JSON to stdout.
fn print_json(w: &SessionWarnings, top_rules: &[(String, u32)], paranoia: u8, show_hidden: bool) {
    let hidden_events = if show_hidden {
        Some(w.hidden_events.iter().cloned().collect())
    } else {
        None
    };

    let out = WarningsJson {
        session_id: w.session_id.clone(),
        session_start: w.session_start.clone(),
        total_warnings: w.total_warnings,
        hidden_findings: w.hidden_findings,
        hidden_low: w.hidden_low,
        hidden_info: w.hidden_info,
        paranoia,
        events: w.events.iter().cloned().collect(),
        top_rules: top_rules.to_vec(),
        hidden_events,
    };

    match serde_json::to_string_pretty(&out) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("tirith: JSON serialization failed: {e}"),
    }
}

/// Print human-readable table to stdout.
fn print_table(w: &SessionWarnings, top_rules: &[(String, u32)], paranoia: u8) {
    let hidden = w.hidden_findings;
    // Handle zero-warnings-but-hidden-findings case
    if w.total_warnings == 0 && hidden >= 3 {
        println!("No warnings in current session.");
        print_paranoia_footer(w.hidden_low, w.hidden_info, paranoia);
        return;
    }

    println!(
        "Session warnings (session: {})",
        truncate_session_id(&w.session_id),
    );
    println!(
        "Started: {} | Total: {} warning(s)\n",
        w.session_start, w.total_warnings,
    );

    // Table header
    println!(
        "  {:<3} \u{2502} {:<8} \u{2502} {:<8} \u{2502} {:<20} \u{2502} {:<28} \u{2502} Command",
        "#", "Time", "Severity", "Rule", "Title",
    );
    println!(
        "  {}\u{2500}\u{253c}\u{2500}{}\u{2500}\u{253c}\u{2500}{}\u{2500}\u{253c}\u{2500}{}\u{2500}\u{253c}\u{2500}{}\u{2500}\u{253c}\u{2500}{}",
        "\u{2500}".repeat(3),
        "\u{2500}".repeat(8),
        "\u{2500}".repeat(8),
        "\u{2500}".repeat(20),
        "\u{2500}".repeat(28),
        "\u{2500}".repeat(30),
    );

    for (i, event) in w.events.iter().enumerate() {
        let time_short = extract_time(&event.timestamp);
        let cmd_truncated = truncate_str(&event.command_redacted, 40);
        let title_truncated = truncate_str(&event.title, 28);
        let rule_truncated = truncate_str(&event.rule_id, 20);

        println!(
            "  {:<3} \u{2502} {:<8} \u{2502} {:<8} \u{2502} {:<20} \u{2502} {:<28} \u{2502} {}",
            i + 1,
            time_short,
            event.severity,
            rule_truncated,
            title_truncated,
            cmd_truncated,
        );
    }

    // Top rules summary
    if !top_rules.is_empty() {
        let top_str: String = top_rules
            .iter()
            .map(|(rule, count)| format!("{rule} ({count})"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("\nTop rules: {top_str}");
    }

    // Suggestions for frequently-firing rules (threshold: 3+)
    let suggestion_threshold = 3;
    for (rule, count) in top_rules {
        if *count >= suggestion_threshold {
            // Try to extract a representative domain for the suggestion
            let domain = find_domain_for_rule(w, rule);
            if let Some(d) = domain {
                println!(
                    "\nSuggestion: {rule} fired {count} times. Consider: tirith trust add {d} --rule {rule}"
                );
            } else {
                println!(
                    "\nSuggestion: {rule} fired {count} times. Consider: tirith trust add <pattern> --rule {rule}"
                );
            }
        }
    }

    // Paranoia guidance footer when hidden findings exist
    if hidden > 0 {
        print_paranoia_footer(w.hidden_low, w.hidden_info, paranoia);
    }
}

/// Print table of hidden events (findings suppressed by paranoia filtering).
fn print_hidden_table(w: &SessionWarnings) {
    if w.hidden_events.is_empty() {
        println!("\nNo hidden findings recorded.");
        return;
    }

    let cap = MAX_HIDDEN_DISPLAY;
    let total = w.hidden_events.len();
    println!(
        "\nHidden findings (suppressed by paranoia, last {}):\n",
        total.min(cap)
    );

    // Table header
    println!(
        "  {:<3} \u{2502} {:<8} \u{2502} {:<8} \u{2502} {:<20} \u{2502} {:<28} \u{2502} Command",
        "#", "Time", "Severity", "Rule", "Title",
    );
    println!(
        "  {}\u{2500}\u{253c}\u{2500}{}\u{2500}\u{253c}\u{2500}{}\u{2500}\u{253c}\u{2500}{}\u{2500}\u{253c}\u{2500}{}\u{2500}\u{253c}\u{2500}{}",
        "\u{2500}".repeat(3),
        "\u{2500}".repeat(8),
        "\u{2500}".repeat(8),
        "\u{2500}".repeat(20),
        "\u{2500}".repeat(28),
        "\u{2500}".repeat(30),
    );

    for (i, event) in w.hidden_events.iter().rev().take(cap).enumerate() {
        let time_short = extract_time(&event.timestamp);
        let cmd_truncated = truncate_str(&event.command_redacted, 40);
        let title_truncated = truncate_str(&event.title, 28);
        let rule_truncated = truncate_str(&event.rule_id, 20);

        println!(
            "  {:<3} \u{2502} {:<8} \u{2502} {:<8} \u{2502} {:<20} \u{2502} {:<28} \u{2502} {}",
            i + 1,
            time_short,
            event.severity,
            rule_truncated,
            title_truncated,
            cmd_truncated,
        );
    }

    if total > cap {
        println!("  ... and {} more (showing most recent {cap})", total - cap);
    }
}

/// Maximum hidden events to display in the table.
const MAX_HIDDEN_DISPLAY: usize = 50;

/// Print paranoia guidance footer using stored per-severity hidden counts.
fn print_paranoia_footer(hidden_low: u32, hidden_info: u32, paranoia: u8) {
    let total = hidden_low + hidden_info;
    if total == 0 {
        return;
    }
    let desc = hidden_severity_desc(hidden_low, hidden_info);
    println!();
    println!("{total} lower-severity findings hidden ({desc}).");
    // Show paranoia levels with current marked
    println!(
        "  Level 1-2{}: Medium+ only",
        if paranoia <= 2 { " (current)" } else { "" }
    );
    println!(
        "  Level 3{}:   Low+",
        if paranoia == 3 { " (current)" } else { "" }
    );
    println!(
        "  Level 4{}:   All",
        if paranoia >= 4 { " (current)" } else { "" }
    );
    if let Some(next) = next_paranoia_for_hidden(hidden_low, hidden_info) {
        println!("Set 'paranoia: {next}' in .tirith/policy.yaml to surface them.");
    }
}

/// Describe hidden findings from stored per-severity counts.
fn hidden_severity_desc(hidden_low: u32, hidden_info: u32) -> String {
    match (hidden_low > 0, hidden_info > 0) {
        (true, true) => format!("{hidden_low} Low, {hidden_info} Info"),
        (true, false) => format!("{hidden_low} Low"),
        (false, true) => format!("{hidden_info} Info"),
        (false, false) => "none".to_string(),
    }
}

/// Compute the minimum paranoia level needed to surface stored hidden findings.
fn next_paranoia_for_hidden(hidden_low: u32, hidden_info: u32) -> Option<u8> {
    if hidden_low > 0 {
        Some(3) // Level 3 shows Low+
    } else if hidden_info > 0 {
        Some(4) // Level 4 shows Info
    } else {
        None
    }
}

/// Extract HH:MM:SS from an ISO 8601 timestamp.
fn extract_time(ts: &str) -> &str {
    // Look for 'T' separator, then take up to 8 chars (HH:MM:SS)
    if let Some(t_pos) = ts.find('T') {
        let after_t = &ts[t_pos + 1..];
        let end = after_t.len().min(8);
        &after_t[..end]
    } else {
        // Fallback: return first 8 chars or the whole string
        let end = ts.len().min(8);
        &ts[..end]
    }
}

/// Truncate a string to `max_len` bytes with "..." suffix if truncated.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        let truncated = tirith_core::util::truncate_bytes(s, max_len - 3);
        format!("{truncated}...")
    } else {
        tirith_core::util::truncate_bytes(s, max_len)
    }
}

/// Show first segment of a UUID-style session ID for compactness.
fn truncate_session_id(sid: &str) -> &str {
    // UUIDs have format xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    // Show first 8 chars + rest abbreviated
    if sid.len() > 12 {
        &sid[..12]
    } else {
        sid
    }
}

/// Find the first domain associated with a given rule in the warning events.
fn find_domain_for_rule<'a>(w: &'a SessionWarnings, rule: &str) -> Option<&'a str> {
    w.events
        .iter()
        .filter(|e| e.rule_id == rule)
        .flat_map(|e| e.domains.iter())
        .map(String::as_str)
        .next()
}

/// Clear session data if --clear was requested.
fn maybe_clear(clear: bool, session_id: &str) {
    if clear {
        session_warnings::clear_session(session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_time_iso8601() {
        assert_eq!(extract_time("2026-04-04T10:05:23Z"), "10:05:23");
        assert_eq!(extract_time("2026-04-04T10:05:23.456Z"), "10:05:23");
    }

    #[test]
    fn test_extract_time_no_t_separator() {
        assert_eq!(extract_time("10:05:23"), "10:05:23");
        assert_eq!(extract_time("short"), "short");
    }

    #[test]
    fn test_truncate_str_short() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_str_exact() {
        assert_eq!(truncate_str("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_str_long() {
        assert_eq!(truncate_str("hello world", 8), "hello...");
    }

    #[test]
    fn test_truncate_session_id_uuid() {
        let uuid = "a5b0c1d2-e3f4-5678-9abc-def012345678";
        assert_eq!(truncate_session_id(uuid), "a5b0c1d2-e3f");
    }

    #[test]
    fn test_truncate_session_id_short() {
        assert_eq!(truncate_session_id("short"), "short");
    }

    #[test]
    fn test_hidden_only_session_below_threshold_no_output() {
        // total_warnings=0, hidden_findings=2 (< 3) → no summary output
        let w = SessionWarnings {
            session_id: "test".to_string(),
            session_start: "2026-04-05T00:00:00Z".to_string(),
            total_warnings: 0,
            hidden_findings: 2,
            hidden_low: 1,
            hidden_info: 1,
            events: std::collections::VecDeque::new(),
            escalation_events: std::collections::VecDeque::new(),
            hidden_events: std::collections::VecDeque::new(),
        };
        let top_rules = w.top_rules();
        assert_eq!(w.total_warnings, 0);
        assert!(w.hidden_findings < 3);
        assert!(top_rules.is_empty());
    }

    #[test]
    fn test_hidden_only_session_at_threshold_shows_output() {
        let w = SessionWarnings {
            session_id: "test".to_string(),
            session_start: "2026-04-05T00:00:00Z".to_string(),
            total_warnings: 0,
            hidden_findings: 3,
            hidden_low: 2,
            hidden_info: 1,
            events: std::collections::VecDeque::new(),
            escalation_events: std::collections::VecDeque::new(),
            hidden_events: std::collections::VecDeque::new(),
        };
        // The gate in run() is: total_warnings == 0 && hidden >= 3 → print hidden line
        assert_eq!(w.total_warnings, 0);
        assert!(w.hidden_findings >= 3);
    }
}
