use std::io::Write;

use crate::verdict::{Action, Evidence, Finding, Severity, Verdict};

const SCHEMA_VERSION: u32 = 3;

/// JSON output wrapper with schema version.
#[derive(serde::Serialize)]
pub struct JsonOutput<'a> {
    pub schema_version: u32,
    pub action: Action,
    pub findings: &'a [Finding],
    pub tier_reached: u8,
    pub bypass_requested: bool,
    pub bypass_honored: bool,
    pub interactive_detected: bool,
    pub policy_path_used: &'a Option<String>,
    pub timings_ms: &'a crate::verdict::Timings,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub urls_extracted_count: Option<usize>,
}

/// Write verdict as JSON to the given writer.
pub fn write_json(verdict: &Verdict, mut w: impl Write) -> std::io::Result<()> {
    let output = JsonOutput {
        schema_version: SCHEMA_VERSION,
        action: verdict.action,
        findings: &verdict.findings,
        tier_reached: verdict.tier_reached,
        bypass_requested: verdict.bypass_requested,
        bypass_honored: verdict.bypass_honored,
        interactive_detected: verdict.interactive_detected,
        policy_path_used: &verdict.policy_path_used,
        timings_ms: &verdict.timings_ms,
        urls_extracted_count: verdict.urls_extracted_count,
    };
    serde_json::to_writer(&mut w, &output)?;
    writeln!(w)?;
    Ok(())
}

/// Write human-readable verdict to stderr.
pub fn write_human(verdict: &Verdict, mut w: impl Write) -> std::io::Result<()> {
    if verdict.findings.is_empty() {
        return Ok(());
    }

    let action_str = match verdict.action {
        Action::Allow => "INFO",
        Action::Warn => "WARNING",
        Action::Block => "BLOCKED",
    };

    writeln!(w, "tirith: {action_str}")?;

    for finding in &verdict.findings {
        let severity_color = match finding.severity {
            Severity::Critical => "\x1b[91m", // bright red
            Severity::High => "\x1b[31m",     // red
            Severity::Medium => "\x1b[33m",   // yellow
            Severity::Low => "\x1b[36m",      // cyan
            Severity::Info => "\x1b[90m",     // dim/gray
        };
        let reset = "\x1b[0m";

        writeln!(
            w,
            "  {}[{}]{} {} — {}",
            severity_color, finding.severity, reset, finding.rule_id, finding.title
        )?;
        writeln!(w, "    {}", finding.description)?;

        // Display detailed evidence for homoglyph findings
        for evidence in &finding.evidence {
            if let Evidence::HomoglyphAnalysis {
                raw,
                escaped,
                suspicious_chars,
            } = evidence
            {
                writeln!(w)?;
                // Visual line with markers
                let visual = format_visual_with_markers(raw, suspicious_chars);
                writeln!(w, "    Visual:  {visual}")?;
                writeln!(w, "    Escaped: \x1b[33m{escaped}\x1b[0m")?;

                // Suspicious bytes section
                if !suspicious_chars.is_empty() {
                    writeln!(w)?;
                    writeln!(w, "    \x1b[33mSuspicious bytes:\x1b[0m")?;
                    for sc in suspicious_chars {
                        writeln!(
                            w,
                            "      {:08x}: {} {:6} {}",
                            sc.offset, sc.hex_bytes, sc.codepoint, sc.description
                        )?;
                    }
                }
            }
        }
    }

    if verdict.action == Action::Block {
        writeln!(
            w,
            "  Bypass: prefix your command with TIRITH=0 (applies to that command only)"
        )?;
    }

    Ok(())
}

/// Format a string with red markers on suspicious characters
fn format_visual_with_markers(
    raw: &str,
    suspicious_chars: &[crate::verdict::SuspiciousChar],
) -> String {
    use std::collections::HashSet;

    // Build a set of suspicious byte offsets
    let suspicious_offsets: HashSet<usize> = suspicious_chars.iter().map(|sc| sc.offset).collect();

    let mut result = String::new();
    let mut byte_offset = 0;

    for ch in raw.chars() {
        if suspicious_offsets.contains(&byte_offset) {
            // Red background for suspicious character
            result.push_str("\x1b[41m\x1b[97m"); // red bg, white fg
            result.push(ch);
            result.push_str("\x1b[0m"); // reset
        } else {
            result.push(ch);
        }
        byte_offset += ch.len_utf8();
    }

    result
}

/// Write human-readable output to stderr, respecting TTY detection.
/// If stderr is not a TTY, strip ANSI colors.
pub fn write_human_auto(verdict: &Verdict) -> std::io::Result<()> {
    let stderr = std::io::stderr();
    let is_tty = is_terminal::is_terminal(&stderr);

    if is_tty {
        write_human(verdict, stderr.lock())
    } else {
        write_human_no_color(verdict, stderr.lock())
    }
}

/// Write human-readable output without ANSI colors.
fn write_human_no_color(verdict: &Verdict, mut w: impl Write) -> std::io::Result<()> {
    if verdict.findings.is_empty() {
        return Ok(());
    }

    let action_str = match verdict.action {
        Action::Allow => "INFO",
        Action::Warn => "WARNING",
        Action::Block => "BLOCKED",
    };

    writeln!(w, "tirith: {action_str}")?;

    for finding in &verdict.findings {
        writeln!(
            w,
            "  [{}] {} — {}",
            finding.severity, finding.rule_id, finding.title
        )?;
        writeln!(w, "    {}", finding.description)?;

        // Display detailed evidence for homoglyph findings (no color)
        for evidence in &finding.evidence {
            if let Evidence::HomoglyphAnalysis {
                raw,
                escaped,
                suspicious_chars,
            } = evidence
            {
                writeln!(w)?;
                // Visual line with markers (using brackets instead of color)
                let visual = format_visual_with_brackets(raw, suspicious_chars);
                writeln!(w, "    Visual:  {visual}")?;
                writeln!(w, "    Escaped: {escaped}")?;

                // Suspicious bytes section
                if !suspicious_chars.is_empty() {
                    writeln!(w)?;
                    writeln!(w, "    Suspicious bytes:")?;
                    for sc in suspicious_chars {
                        writeln!(
                            w,
                            "      {:08x}: {} {:6} {}",
                            sc.offset, sc.hex_bytes, sc.codepoint, sc.description
                        )?;
                    }
                }
            }
        }
    }

    if verdict.action == Action::Block {
        writeln!(
            w,
            "  Bypass: prefix your command with TIRITH=0 (applies to that command only)"
        )?;
    }

    Ok(())
}

/// Format a string with brackets around suspicious characters (for no-color mode)
fn format_visual_with_brackets(
    raw: &str,
    suspicious_chars: &[crate::verdict::SuspiciousChar],
) -> String {
    use std::collections::HashSet;

    let suspicious_offsets: HashSet<usize> = suspicious_chars.iter().map(|sc| sc.offset).collect();

    let mut result = String::new();
    let mut byte_offset = 0;

    for ch in raw.chars() {
        if suspicious_offsets.contains(&byte_offset) {
            result.push('[');
            result.push(ch);
            result.push(']');
        } else {
            result.push(ch);
        }
        byte_offset += ch.len_utf8();
    }

    result
}
