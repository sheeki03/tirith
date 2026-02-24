use crate::extract;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Check raw bytes for terminal deception (paste-time).
pub fn check_bytes(input: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let scan = extract::scan_bytes(input);

    if scan.has_ansi_escapes {
        findings.push(Finding {
            rule_id: RuleId::AnsiEscapes,
            severity: Severity::High,
            title: "ANSI escape sequences in pasted content".to_string(),
            description: "Pasted content contains ANSI escape sequences that could hide malicious commands or manipulate terminal display".to_string(),
            evidence: scan.details.iter()
                .filter(|d| d.description.contains("escape"))
                .map(|d| Evidence::ByteSequence {
                    offset: d.offset,
                    hex: format!("0x{:02x}", d.byte),
                    description: d.description.clone(),
                })
                .collect(),
        });
    }

    if scan.has_control_chars {
        findings.push(Finding {
            rule_id: RuleId::ControlChars,
            severity: Severity::High,
            title: "Control characters in pasted content".to_string(),
            description: "Pasted content contains control characters (display-overwriting carriage return, backspace, etc.) that could hide the true command being executed".to_string(),
            evidence: scan.details.iter()
                .filter(|d| d.description.contains("control"))
                .map(|d| Evidence::ByteSequence {
                    offset: d.offset,
                    hex: format!("0x{:02x}", d.byte),
                    description: d.description.clone(),
                })
                .collect(),
        });
    }

    if scan.has_bidi_controls {
        findings.push(Finding {
            rule_id: RuleId::BidiControls,
            severity: Severity::Critical,
            title: "Bidirectional control characters detected".to_string(),
            description: "Content contains Unicode bidi override characters that can make text appear to read in a different order than it actually executes".to_string(),
            evidence: scan.details.iter()
                .filter(|d| d.description.contains("bidi"))
                .map(|d| Evidence::ByteSequence {
                    offset: d.offset,
                    hex: format!("0x{:02x}", d.byte),
                    description: d.description.clone(),
                })
                .collect(),
        });
    }

    if scan.has_zero_width {
        findings.push(Finding {
            rule_id: RuleId::ZeroWidthChars,
            severity: Severity::High,
            title: "Zero-width characters detected".to_string(),
            description: "Content contains invisible zero-width characters that could be used to obfuscate URLs or commands".to_string(),
            evidence: scan.details.iter()
                .filter(|d| d.description.contains("zero-width"))
                .map(|d| Evidence::ByteSequence {
                    offset: d.offset,
                    hex: format!("0x{:02x}", d.byte),
                    description: d.description.clone(),
                })
                .collect(),
        });
    }

    findings
}

/// Check for hidden multiline content in string input.
pub fn check_hidden_multiline(input: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for lines that might be hidden after the visible first line
    let lines: Vec<&str> = input.lines().collect();
    if lines.len() > 1 {
        // Check if later lines contain suspicious patterns
        for (i, line) in lines.iter().enumerate().skip(1) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            // If a non-first line contains what looks like a command
            if looks_like_hidden_command(trimmed) {
                findings.push(Finding {
                    rule_id: RuleId::HiddenMultiline,
                    severity: Severity::High,
                    title: "Hidden multiline content detected".to_string(),
                    description: format!(
                        "Pasted content has a hidden command on line {}: '{}'",
                        i + 1,
                        truncate(trimmed, 60)
                    ),
                    evidence: vec![Evidence::Text {
                        detail: format!("line {}: {}", i + 1, truncate(trimmed, 100)),
                    }],
                });
                break;
            }
        }
    }

    findings
}

fn looks_like_hidden_command(line: &str) -> bool {
    let suspicious = [
        "curl ", "wget ", "bash", "/bin/", "sudo ", "rm ", "chmod ", "eval ", "exec ", "> /",
        ">> /", "| sh",
    ];
    suspicious.iter().any(|p| line.contains(p))
}

fn truncate(s: &str, max: usize) -> String {
    let prefix = crate::util::truncate_bytes(s, max);
    if prefix.len() == s.len() {
        prefix
    } else {
        format!("{prefix}...")
    }
}
