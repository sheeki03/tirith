use std::io::Write;

use crate::verdict::{Action, Evidence, Finding, Verdict};

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
pub fn write_json(
    verdict: &Verdict,
    custom_patterns: &[String],
    mut w: impl Write,
) -> std::io::Result<()> {
    let redacted_findings = crate::redact::redacted_findings(&verdict.findings, custom_patterns);
    let output = JsonOutput {
        schema_version: SCHEMA_VERSION,
        action: verdict.action,
        findings: &redacted_findings,
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
///
/// `warn_only` indicates the caller cannot actually enforce a block (e.g. bash
/// preexec `DEBUG` trap). In that mode, Block verdicts render as `DETECTED
/// (shell hook cannot block in preexec mode — command will still run)` instead
/// of `BLOCKED`, and the bypass hint line is rewritten accordingly. The flag
/// is human-only — it never reaches `write_json`, audit logs, or exit codes
/// (see issue #77).
pub fn write_human(verdict: &Verdict, warn_only: bool, mut w: impl Write) -> std::io::Result<()> {
    if verdict.findings.is_empty() {
        return Ok(());
    }

    let is_warn_only_block = warn_only && verdict.action == Action::Block;
    let action_str = match verdict.action {
        Action::Allow => "INFO",
        Action::Warn | Action::WarnAck => "WARNING",
        Action::Block if is_warn_only_block => {
            "DETECTED (shell hook cannot block in preexec mode — command will still run)"
        }
        Action::Block => "BLOCKED",
    };

    if let Some(ref reason) = verdict.escalation_reason {
        writeln!(w, "tirith: {action_str} (escalated: {reason})")?;
    } else {
        writeln!(w, "tirith: {action_str}")?;
    }

    for finding in &verdict.findings {
        let sev = crate::style::severity_label(&finding.severity, crate::style::Stream::Stderr);

        writeln!(w, "  {} {} — {}", sev, finding.rule_id, finding.title)?;
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
                let esc_styled = if crate::style::use_color_for(crate::style::Stream::Stderr) {
                    format!("\x1b[33m{escaped}\x1b[0m")
                } else {
                    escaped.to_string()
                };
                writeln!(w, "    Escaped: {esc_styled}")?;

                // Suspicious bytes section
                if !suspicious_chars.is_empty() {
                    writeln!(w)?;
                    let header =
                        crate::style::bold("Suspicious bytes:", crate::style::Stream::Stderr);
                    writeln!(w, "    {header}")?;
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

    if verdict.action == Action::Block && verdict.bypass_available {
        if is_warn_only_block {
            writeln!(
                w,
                "  Safer: use an enter-capable shell (bash 5+/zsh/fish) to actually block this, or prefix with TIRITH=0 to suppress."
            )?;
        } else {
            writeln!(
                w,
                "  Bypass: prefix your command with TIRITH=0 (applies to that command only)"
            )?;
        }
    }

    Ok(())
}

/// Format a string highlighting suspicious characters — red background when
/// color is enabled, bracket-wrapped (`[x]`) when color is off.
fn format_visual_with_markers(
    raw: &str,
    suspicious_chars: &[crate::verdict::SuspiciousChar],
) -> String {
    use std::collections::HashSet;

    let suspicious_offsets: HashSet<usize> = suspicious_chars.iter().map(|sc| sc.offset).collect();
    let use_color = crate::style::use_color_for(crate::style::Stream::Stderr);

    let mut result = String::new();
    let mut byte_offset = 0;

    for ch in raw.chars() {
        if suspicious_offsets.contains(&byte_offset) {
            if use_color {
                result.push_str("\x1b[41m\x1b[97m"); // red bg, white fg
                result.push(ch);
                result.push_str("\x1b[0m");
            } else {
                result.push('[');
                result.push(ch);
                result.push(']');
            }
        } else {
            result.push(ch);
        }
        byte_offset += ch.len_utf8();
    }

    result
}

/// Write human-readable output to stderr, respecting color preferences.
/// Uses the no-color path when stderr is not a TTY or `NO_COLOR` is set.
pub fn write_human_auto(verdict: &Verdict, warn_only: bool) -> std::io::Result<()> {
    if crate::style::use_color_for(crate::style::Stream::Stderr) {
        write_human(verdict, warn_only, std::io::stderr().lock())
    } else {
        write_human_no_color(verdict, warn_only, std::io::stderr().lock())
    }
}

/// Write human-readable output without ANSI colors.
fn write_human_no_color(
    verdict: &Verdict,
    warn_only: bool,
    mut w: impl Write,
) -> std::io::Result<()> {
    if verdict.findings.is_empty() {
        return Ok(());
    }

    let is_warn_only_block = warn_only && verdict.action == Action::Block;
    let action_str = match verdict.action {
        Action::Allow => "INFO",
        Action::Warn | Action::WarnAck => "WARNING",
        Action::Block if is_warn_only_block => {
            "DETECTED (shell hook cannot block in preexec mode — command will still run)"
        }
        Action::Block => "BLOCKED",
    };

    if let Some(ref reason) = verdict.escalation_reason {
        writeln!(w, "tirith: {action_str} (escalated: {reason})")?;
    } else {
        writeln!(w, "tirith: {action_str}")?;
    }

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

    if verdict.action == Action::Block && verdict.bypass_available {
        if is_warn_only_block {
            writeln!(
                w,
                "  Safer: use an enter-capable shell (bash 5+/zsh/fish) to actually block this, or prefix with TIRITH=0 to suppress."
            )?;
        } else {
            writeln!(
                w,
                "  Bypass: prefix your command with TIRITH=0 (applies to that command only)"
            )?;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Action, Evidence, Finding, RuleId, Severity, Timings, Verdict};

    fn block_verdict_with_bypass() -> Verdict {
        let mut v = Verdict::from_findings(
            vec![Finding {
                rule_id: RuleId::PlainHttpToSink,
                severity: Severity::High,
                title: "Plain HTTP URL in execution context".to_string(),
                description: "test".to_string(),
                evidence: vec![Evidence::Url {
                    raw: "http://evil.com/x.sh".to_string(),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }],
            3,
            Timings {
                tier0_ms: 0.0,
                tier1_ms: 0.0,
                tier2_ms: None,
                tier3_ms: None,
                total_ms: 0.0,
            },
        );
        // from_findings sets action based on severity; ensure it's Block for this test
        v.action = Action::Block;
        v.bypass_available = true;
        v
    }

    #[test]
    fn write_human_no_color_warn_only_renders_detected() {
        let verdict = block_verdict_with_bypass();
        let mut buf = Vec::new();
        write_human_no_color(&verdict, true, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            !out.contains("BLOCKED"),
            "warn-only must not render BLOCKED: {out}"
        );
        assert!(
            out.contains("DETECTED (shell hook cannot block in preexec mode"),
            "warn-only must render DETECTED with explanation: {out}"
        );
        assert!(
            !out.contains("Bypass:"),
            "warn-only must replace the Bypass hint: {out}"
        );
        assert!(
            out.contains("Safer:"),
            "warn-only must render the Safer hint: {out}"
        );
    }

    #[test]
    fn write_human_no_color_plain_renders_blocked() {
        let verdict = block_verdict_with_bypass();
        let mut buf = Vec::new();
        write_human_no_color(&verdict, false, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("BLOCKED"),
            "default must still render BLOCKED: {out}"
        );
        assert!(
            !out.contains("DETECTED"),
            "default must not render DETECTED: {out}"
        );
        assert!(
            out.contains("Bypass:"),
            "default must render the Bypass hint: {out}"
        );
    }

    #[test]
    fn warn_only_flag_does_not_reach_write_json() {
        // Invariant: `write_json` takes a `Verdict` (no warn_only parameter),
        // so the flag literally cannot be serialized into machine output.
        // This test pins down the shape — any refactor that passes warn_only
        // into write_json would require updating this assertion too, which
        // is the review bar the plan wants.
        let verdict = block_verdict_with_bypass();
        let mut buf = Vec::new();
        write_json(&verdict, &[], &mut buf).unwrap();
        let json = String::from_utf8(buf).unwrap();
        assert!(
            !json.contains("warn_only"),
            "JSON must not carry warn_only: {json}"
        );
        assert!(
            !json.contains("DETECTED"),
            "JSON must not carry the DETECTED banner string: {json}"
        );
    }
}
