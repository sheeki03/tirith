use std::io::Write;

use crate::verdict::{Action, Finding, Severity, Verdict};

const SCHEMA_VERSION: u32 = 1;

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
        Action::Allow => return Ok(()),
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
        };
        let reset = "\x1b[0m";

        writeln!(
            w,
            "  {}[{}]{} {} — {}",
            severity_color, finding.severity, reset, finding.rule_id, finding.title
        )?;
        writeln!(w, "    {}", finding.description)?;
    }

    if verdict.action == Action::Block {
        writeln!(w, "  Bypass: prefix your command with TIRITH=0 (applies to that command only)")?;
    }

    Ok(())
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
        Action::Allow => return Ok(()),
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
    }

    if verdict.action == Action::Block {
        writeln!(w, "  Bypass: prefix your command with TIRITH=0 (applies to that command only)")?;
    }

    Ok(())
}
