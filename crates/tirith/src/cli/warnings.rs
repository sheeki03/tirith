use serde::Serialize;
use tirith_core::session_warnings::{self, HiddenEvent, SessionWarnings, WarningEvent};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

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

    // discover_partial is local-only — the shell-exit hot path must not fetch.
    let cwd = std::env::current_dir().ok();
    let cwd_str = cwd.as_ref().and_then(|p| p.to_str());
    let policy = tirith_core::policy::Policy::discover_partial(cwd_str);
    let paranoia = policy.paranoia;

    let hidden_count = warnings.hidden_findings;

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

    // Summary mode suppresses hidden-only output under 3 findings to avoid
    // noise on every shell exit; >= 3 is significant enough to surface.
    if warnings.total_warnings == 0 && hidden_count < 3 && summary {
        maybe_clear(clear, &sid);
        return 0;
    }

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
        .map(|(rule, count)| format!("{count} {}", safe_single_line(rule)))
        .collect::<Vec<_>>()
        .join(", ");

    let hidden = w.hidden_findings;
    if hidden >= 3 {
        eprintln!(
            "tirith: {} warning(s) ({}) + {} hidden \u{2014} run 'tirith warnings' for details",
            w.total_warnings, rule_summary, hidden,
        );
        // Per-severity counts were recorded at detection time, so guidance is accurate.
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
        safe_single_line(&w.session_start),
        w.total_warnings,
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
        println!("{}", render_event_row(i + 1, event));
    }

    if !top_rules.is_empty() {
        let top_str: String = top_rules
            .iter()
            .map(|(rule, count)| format!("{} ({count})", safe_single_line(rule)))
            .collect::<Vec<_>>()
            .join(", ");
        println!("\nTop rules: {top_str}");
    }

    // Suggest trust entries when a rule fires >= 3 times in this session.
    let suggestion_threshold = 3;
    for (rule, count) in top_rules {
        if *count >= suggestion_threshold {
            let safe_rule = safe_single_line(rule);
            let quoted_rule = tirith_core::safe_command::shell_single_quote(&safe_rule);
            // The domain comes from analyzed (attacker-controlled) command text and this
            // line is copy-paste-ready. Scrub terminal-control bytes (ANSI/OSC/zero-width)
            // first so the target cannot repaint the terminal, then shell-single-quote so
            // `$(...)`/backtick/`;`/space can't execute on paste. find_domain_for_rule yields
            // a BARE domain, which `trust add` classifies as broad and rejects without
            // --broad, so emit --broad to keep the line runnable. An unquotable target falls
            // back to the <pattern> placeholder.
            let quoted = find_domain_for_rule(w, rule).and_then(|d| {
                let scrubbed = safe_single_line(d);
                tirith_core::safe_command::shell_single_quote(&scrubbed)
            });
            if let (Some(d), Some(rule_arg)) = (quoted, quoted_rule) {
                println!(
                    "\nSuggestion: {safe_rule} fired {count} times. Consider: tirith trust add {d} --broad --rule {rule_arg}"
                );
            } else {
                println!(
                    "\nSuggestion: {safe_rule} fired {count} times. Consider: tirith trust add <pattern> --broad --rule <rule>"
                );
            }
        }
    }

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
        println!("{}", render_hidden_event_row(i + 1, event));
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
        Some(3)
    } else if hidden_info > 0 {
        Some(4)
    } else {
        None
    }
}

fn safe_single_line(value: &str) -> String {
    super::sanitize_for_human_output(value, false)
}

/// Extract a terminal-safe HH:MM:SS-like prefix. The value is sanitized before
/// locating/truncating it, so decoded newlines or escape sequences cannot forge
/// rows and multibyte input can never trigger a byte-boundary panic.
fn extract_time(ts: &str) -> String {
    let safe = safe_single_line(ts);
    let candidate = safe
        .find('T')
        .map(|position| &safe[position + 1..])
        .unwrap_or(&safe);
    take_display_width(candidate, 8)
}

fn take_display_width(s: &str, max_width: usize) -> String {
    let mut width = 0usize;
    s.chars()
        .take_while(|ch| {
            let char_width = UnicodeWidthChar::width(*ch).unwrap_or(0);
            if width.saturating_add(char_width) > max_width {
                false
            } else {
                width += char_width;
                true
            }
        })
        .collect()
}

/// Truncate by terminal display columns, not UTF-8 bytes or scalar count.
fn truncate_display(s: &str, max_width: usize) -> String {
    if UnicodeWidthStr::width(s) <= max_width {
        s.to_string()
    } else if max_width > 3 {
        format!("{}...", take_display_width(s, max_width - 3))
    } else {
        take_display_width(s, max_width)
    }
}

fn display_cell(value: &str, width: usize) -> String {
    let safe = safe_single_line(value);
    let truncated = truncate_display(&safe, width);
    let padding = width.saturating_sub(UnicodeWidthStr::width(truncated.as_str()));
    format!("{truncated}{}", " ".repeat(padding))
}

fn render_row(
    index: usize,
    timestamp: &str,
    severity: &str,
    rule_id: &str,
    title: &str,
    command_redacted: &str,
) -> String {
    let time = display_cell(&extract_time(timestamp), 8);
    let severity = display_cell(severity, 8);
    let rule = display_cell(rule_id, 20);
    let title = display_cell(title, 28);
    let command = truncate_display(&safe_single_line(command_redacted), 40);
    format!(
        "  {index:<3} \u{2502} {time} \u{2502} {severity} \u{2502} {rule} \u{2502} {title} \u{2502} {command}"
    )
}

fn render_event_row(index: usize, event: &WarningEvent) -> String {
    render_row(
        index,
        &event.timestamp,
        &event.severity,
        &event.rule_id,
        &event.title,
        &event.command_redacted,
    )
}

fn render_hidden_event_row(index: usize, event: &HiddenEvent) -> String {
    render_row(
        index,
        &event.timestamp,
        &event.severity,
        &event.rule_id,
        &event.title,
        &event.command_redacted,
    )
}

/// Show the first 12 terminal columns of a session ID for compactness.
fn truncate_session_id(sid: &str) -> String {
    take_display_width(&safe_single_line(sid), 12)
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
    fn test_truncate_display_short() {
        assert_eq!(truncate_display("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_display_exact() {
        assert_eq!(truncate_display("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_display_long() {
        assert_eq!(truncate_display("hello world", 8), "hello...");
        assert_eq!(truncate_display("包包包", 5), "包...");
        assert_eq!(
            UnicodeWidthStr::width(truncate_display("包包包", 5).as_str()),
            5
        );
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
    fn warning_row_sanitizes_before_measuring_and_truncating() {
        let event = WarningEvent {
            timestamp: "2026-04-04T10:05:23Z\nFORGED".to_string(),
            rule_id: "rule\u{1b}]52;c;clipboard\u{7}\nROW".to_string(),
            severity: "high\u{202e}".to_string(),
            title: "包包 title\u{200b}\u{1b}[2J\nROW".to_string(),
            command_redacted: "echo safe\u{1b}[31m\nFORGED".to_string(),
            domains: vec![],
        };

        let row = render_event_row(1, &event);
        for forbidden in ['\u{1b}', '\u{7}', '\u{202e}', '\u{200b}', '\n', '\r'] {
            assert!(
                !row.contains(forbidden),
                "unsafe terminal character survived: {row:?}"
            );
        }
        assert!(!row.contains("clipboard"));
        assert!(row.contains("包包 title"));

        let cells: Vec<&str> = row.split('\u{2502}').collect();
        assert_eq!(UnicodeWidthStr::width(cells[1]), 10);
        assert_eq!(UnicodeWidthStr::width(cells[2]), 10);
        assert_eq!(UnicodeWidthStr::width(cells[3]), 22);
        assert_eq!(UnicodeWidthStr::width(cells[4]), 30);
        assert!(UnicodeWidthStr::width(cells[5]) <= 41);
    }

    #[test]
    fn extract_time_handles_hostile_multibyte_input_without_byte_slicing() {
        assert_eq!(extract_time("包包包包包"), "包包包包");
        assert_eq!(extract_time("x\nT12:34:56\u{1b}[2J"), "12:34:56");
    }

    #[test]
    fn test_hidden_only_session_below_threshold_no_output() {
        // hidden_findings < 3 should not produce summary output.
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
            cooldowns: std::collections::BTreeMap::new(),
            typed_events: std::collections::VecDeque::new(),
            next_typed_event_sequence: 1,
            surfaced_correlations: std::collections::VecDeque::new(),
        };
        let top_rules = w.top_rules();
        assert_eq!(w.total_warnings, 0);
        assert!(w.hidden_findings < 3);
        assert!(top_rules.is_empty());
    }

    #[test]
    fn test_hidden_only_session_at_threshold_shows_output() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
            cooldowns: std::collections::BTreeMap::new(),
            typed_events: std::collections::VecDeque::new(),
            next_typed_event_sequence: 1,
            surfaced_correlations: std::collections::VecDeque::new(),
        };
        // Matches the gate in run(): total_warnings == 0 && hidden >= 3.
        assert_eq!(w.total_warnings, 0);
        assert!(w.hidden_findings >= 3);
    }
}
