//! Output-direction rules (M7 ch1). Fire from [`crate::engine::analyze_output`]
//! (and the streaming sibling) over a downstream command's stdout/stderr; never
//! reached from the exec hot path (the output pipeline bypasses `PATTERN_TABLE`).
//!
//! v1 scope per rule:
//! * OSC 52 — fires unconditionally (no legit clipboard write via a pipe).
//! * Hidden text — (i) explicit fg == explicit bg within ONE SGR (no default-color
//!   inference), (ii) zero-width run > 8. Theme-dependent detection is a follow-up.
//! * Fake prompt — root-prompt shapes fire on any line; user-prompt shapes only as
//!   a trailing suffix on a stream not ending in `\n`. Inline `$ cmd` prose does not fire.
//! * OSC 8 hyperlink mismatch — only when the VISIBLE TEXT itself parses as a URL
//!   with a host differing from the href host.
//! * Title manipulation / screen clear — Info severity.

use crate::extract::{OutputScanResult, OutputSgrHit};
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Convert an [`OutputScanResult`] into findings — the entire tier-3 rule layer
/// for the output pipeline (every finding traces back to a byte-scanner hit).
pub fn check(scan: &OutputScanResult) -> Vec<Finding> {
    let mut findings = Vec::new();

    for hit in &scan.osc52 {
        findings.push(Finding {
            rule_id: RuleId::OutputOsc52ClipboardWrite,
            severity: Severity::High,
            title: "OSC 52 clipboard-write sequence in output".to_string(),
            description:
                "Output contains an OSC 52 (`\\e]52;c;<base64>\\a`) sequence that writes silently to the system clipboard. \
                 Attackers use this to stage a malicious command in the clipboard for the user's next paste."
                    .to_string(),
            evidence: vec![Evidence::ByteSequence {
                offset: hit.offset,
                hex: "1B 5D 35 32 3B".to_string(),
                description: format!("OSC 52 payload: {}", truncate(&hit.payload, 80)),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }

    for hit in &scan.title_set {
        findings.push(Finding {
            rule_id: RuleId::OutputTitleManipulation,
            severity: Severity::Info,
            title: "Terminal title rewrite in output".to_string(),
            description: format!(
                "Output contains an OSC 0 or OSC 2 sequence that rewrites the terminal title to {:?}. \
                 Legitimate programs set the title directly on /dev/tty, not through piped output.",
                truncate(&hit.payload, 80)
            ),
            evidence: vec![Evidence::ByteSequence {
                offset: hit.offset,
                hex: "1B 5D 30/32 3B".to_string(),
                description: "OSC 0/2 title set".to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }

    for hit in &scan.screen_clear {
        findings.push(Finding {
            rule_id: RuleId::OutputClearScreen,
            severity: Severity::Info,
            title: "Mid-stream screen-clear sequence in output".to_string(),
            description:
                "Output contains an explicit screen-clear / cursor-home sequence (\\e[2J or \\e[H). \
                 Attackers use these to scroll the prior context off-screen so a fake banner can take its place."
                    .to_string(),
            evidence: vec![Evidence::ByteSequence {
                offset: hit.offset,
                hex: "1B 5B 32 4A / 1B 5B 48".to_string(),
                description: hit.payload.clone(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }

    findings.extend(check_hyperlink_mismatch(scan));
    findings.extend(check_hidden_text_via_sgr(scan));
    findings.extend(check_hidden_text_via_zero_width(scan));

    findings
}

/// OSC 8 link where the visible text itself parses as a URL with a host
/// that differs from the href's host.
fn check_hyperlink_mismatch(scan: &OutputScanResult) -> Vec<Finding> {
    let mut findings = Vec::new();
    for link in &scan.hyperlinks {
        let Some(href_host) = parse_url_host(&link.uri) else {
            continue;
        };
        // Visible text must itself parse as a URL — otherwise we tolerate the
        // mismatch (legitimate URL-shortener / friendly-label pattern).
        let visible_trimmed = link.visible.trim();
        let Some(visible_host) = parse_url_host(visible_trimmed) else {
            continue;
        };
        if hosts_match(&href_host, &visible_host) {
            continue;
        }
        findings.push(Finding {
            rule_id: RuleId::OutputTerminalHyperlinkMismatch,
            severity: Severity::High,
            title: "Terminal hyperlink target differs from visible URL".to_string(),
            description: format!(
                "OSC 8 hyperlink renders visible text \"{}\" but clicks through to \"{}\". \
                 The visible URL is decoration — the click target is the real destination.",
                truncate(&link.visible, 100),
                truncate(&link.uri, 200)
            ),
            evidence: vec![Evidence::HostComparison {
                raw_host: visible_host,
                similar_to: href_host,
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }
    findings
}

/// SGR-based hidden text: one sequence sets fg == bg (across the 30-37/40-47,
/// 90-97/100-107 bright, and 38/48 extended-color forms).
fn check_hidden_text_via_sgr(scan: &OutputScanResult) -> Vec<Finding> {
    let mut findings = Vec::new();
    for sgr in &scan.sgr {
        if let Some(reason) = sgr_marks_invisible(sgr) {
            findings.push(Finding {
                rule_id: RuleId::OutputHiddenText,
                severity: Severity::Medium,
                title: "Hidden text via matching foreground/background SGR".to_string(),
                description: format!(
                    "Output contains an SGR sequence where the explicit foreground color equals the explicit background color, \
                     rendering any text after it invisible: {reason}."
                ),
                evidence: vec![Evidence::ByteSequence {
                    offset: sgr.offset,
                    hex: "1B 5B … 6D".to_string(),
                    description: format!("SGR params: {:?}", sgr.params),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }
    findings
}

/// Zero-width run > 8 chars — the v1 (ii) clause of OutputHiddenText.
fn check_hidden_text_via_zero_width(scan: &OutputScanResult) -> Vec<Finding> {
    let mut findings = Vec::new();
    for run in &scan.zero_width_runs {
        findings.push(Finding {
            rule_id: RuleId::OutputHiddenText,
            severity: Severity::Medium,
            title: "Long run of zero-width characters in output".to_string(),
            description: format!(
                "Output contains a run of {} consecutive zero-width characters — likely hides text from a human reader while remaining visible to downstream consumers (AI agents, grep, copy-paste).",
                run.count
            ),
            evidence: vec![Evidence::ByteSequence {
                offset: run.offset,
                hex: "200B / 200C / 200D / FEFF".to_string(),
                description: format!("zero-width run length {}", run.count),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }
    findings
}

/// `OutputFakePrompt` runs on the assembled text (not the byte scan); the
/// streaming driver calls this once at end-of-stream with the text buffer.
pub fn check_fake_prompt(text: &str) -> Vec<Finding> {
    // Fire if any line is a root/`#` prompt OR the LAST line is a `$ `/`% ` shape,
    // so inline `$ cmd` tutorial paragraphs don't false-fire.
    let mut findings = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return findings;
    }

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_end();
        // Root prompt anywhere — these are the dangerous shape.
        if looks_like_root_prompt(trimmed) {
            findings.push(Finding {
                rule_id: RuleId::OutputFakePrompt,
                severity: Severity::Medium,
                title: "Fake root-shell prompt injected in output".to_string(),
                description: format!(
                    "Output contains a line shaped like a root shell prompt: '{}'. \
                     This pattern tricks the user into thinking the command finished and a fresh shell is waiting.",
                    truncate(trimmed, 80)
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

    // Trailing-prompt heuristic: fire only when the stream ENDS in a
    // prompt-shaped line WITHOUT a trailing newline.
    let last_nonempty = lines.iter().rev().find(|l| !l.trim().is_empty()).copied();
    if let Some(last) = last_nonempty {
        let trimmed_end = last.trim_end();
        let stream_ends_without_newline = !text.ends_with('\n') && !text.ends_with("\r\n");
        if stream_ends_without_newline
            && looks_like_user_prompt(trimmed_end)
            && !findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutputFakePrompt)
        {
            findings.push(Finding {
                rule_id: RuleId::OutputFakePrompt,
                severity: Severity::Medium,
                title: "Output ends in a fake shell prompt".to_string(),
                description: format!(
                    "Output ends without a newline, on a prompt-shaped line: '{}'. \
                     This pattern tricks the user into thinking a fresh shell is waiting at the end of the stream.",
                    truncate(trimmed_end, 80)
                ),
                evidence: vec![Evidence::Text {
                    detail: truncate(trimmed_end, 100),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }

    findings
}

/// Resolve `(fg, bg)` comparable color tokens from an SGR param list (base
/// 30-37/40-47, indexed 38;5;N/48;5;N, truecolor 38;2;R;G;B). Either side is
/// `None` when the SGR did not specify it explicitly (we never infer defaults).
fn resolve_sgr_colors(params: &[u32]) -> (Option<ColorToken>, Option<ColorToken>) {
    let mut fg: Option<ColorToken> = None;
    let mut bg: Option<ColorToken> = None;
    let mut i = 0;
    while i < params.len() {
        let p = params[i];
        match p {
            0 => {
                // Reset → treat both sides as unset (we never infer defaults).
                fg = None;
                bg = None;
                i += 1;
            }
            30..=37 => {
                fg = Some(ColorToken::Basic(p - 30));
                i += 1;
            }
            40..=47 => {
                bg = Some(ColorToken::Basic(p - 40));
                i += 1;
            }
            90..=97 => {
                fg = Some(ColorToken::Bright(p - 90));
                i += 1;
            }
            100..=107 => {
                bg = Some(ColorToken::Bright(p - 100));
                i += 1;
            }
            38 => {
                // 38;5;N or 38;2;R;G;B
                if let Some(next_token) = parse_extended_color(&params[i..]) {
                    fg = Some(next_token.0);
                    i += next_token.1;
                } else {
                    i += 1;
                }
            }
            48 => {
                if let Some(next_token) = parse_extended_color(&params[i..]) {
                    bg = Some(next_token.0);
                    i += next_token.1;
                } else {
                    i += 1;
                }
            }
            _ => {
                i += 1;
            }
        }
    }
    (fg, bg)
}

fn parse_extended_color(params: &[u32]) -> Option<(ColorToken, usize)> {
    if params.len() < 3 {
        return None;
    }
    match params[1] {
        5 => Some((ColorToken::Indexed(params[2]), 3)),
        2 if params.len() >= 5 => Some((ColorToken::Rgb(params[2], params[3], params[4]), 5)),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ColorToken {
    Basic(u32),
    Bright(u32),
    Indexed(u32),
    Rgb(u32, u32, u32),
}

/// Some(reason) when the SGR sets fg == bg (both explicit) within one sequence.
fn sgr_marks_invisible(sgr: &OutputSgrHit) -> Option<String> {
    let (fg, bg) = resolve_sgr_colors(&sgr.params);
    match (fg, bg) {
        (Some(fg_tok), Some(bg_tok)) if fg_tok == bg_tok => {
            Some(format!("fg={fg_tok:?} bg={bg_tok:?}"))
        }
        _ => None,
    }
}

/// Extract a host from a URL string, or `None`. The bare-host branch requires
/// the last segment to be TLD-shaped (≥2 chars, all alpha) — without this guard,
/// version strings like `v1.2.3` parse as hosts and false-fire OSC8 mismatch.
fn parse_url_host(s: &str) -> Option<String> {
    if let Ok(u) = url::Url::parse(s) {
        return u.host_str().map(|h| h.to_ascii_lowercase());
    }
    // Try bare host[:port]/path — only when it looks plausibly like a hostname.
    let first_chunk = s.split(['/', '?', '#']).next().unwrap_or(s);
    if first_chunk.contains('.')
        && first_chunk.split('.').all(|seg| {
            !seg.is_empty()
                && seg.chars().all(|c| {
                    c.is_ascii_alphanumeric() || c == '-' || c == ':' /* port */
                })
        })
    {
        let host_only = first_chunk.split(':').next()?;
        if !host_only.contains('.') {
            return None;
        }
        // Last dot-segment must be ≥2 chars, all alpha — rejects `v1.2.3`, `foo.123`.
        let last = host_only.rsplit('.').next()?;
        if last.len() < 2 {
            return None;
        }
        if !last.chars().all(|c| c.is_ascii_alphabetic()) {
            return None;
        }
        return Some(host_only.to_ascii_lowercase());
    }
    None
}

fn hosts_match(a: &str, b: &str) -> bool {
    // Compare lowercased, treat `www.` as equivalent.
    let a_trim = a.trim_start_matches("www.");
    let b_trim = b.trim_start_matches("www.");
    a_trim == b_trim
}

fn looks_like_root_prompt(line: &str) -> bool {
    let trimmed = line.trim();
    // Match `[root@host …]# ` or `root@host…# ` shapes.
    if trimmed.contains("root@") && (trimmed.ends_with('#') || trimmed.ends_with("# ")) {
        return true;
    }
    if trimmed.starts_with("[root@") && (trimmed.ends_with("]#") || trimmed.ends_with("]# ")) {
        return true;
    }
    false
}

fn looks_like_user_prompt(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    // Shape: `<word>@<word>[…]$ ` or `…% ` or `…> `. The `@` is the load-bearing
    // distinguishing character — pure `$ cmd` lines don't fire here.
    if !trimmed.contains('@') {
        return false;
    }
    if !(trimmed.ends_with("$ ")
        || trimmed.ends_with('$')
        || trimmed.ends_with("% ")
        || trimmed.ends_with('%')
        || trimmed.ends_with("> ")
        || trimmed.ends_with('>'))
    {
        return false;
    }
    // The bit before `@` must look like a username (letters, digits, _, -, .).
    let head = trimmed.split('@').next().unwrap_or("");
    if head.is_empty() || head.len() > 32 {
        return false;
    }
    head.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
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
    use crate::extract::{
        OutputHyperlinkHit, OutputOscHit, OutputScanResult, OutputSgrHit, OutputZeroWidthRun,
    };

    fn scan() -> OutputScanResult {
        OutputScanResult::default()
    }

    #[test]
    fn osc52_emits_high_finding() {
        let mut s = scan();
        s.osc52.push(OutputOscHit {
            offset: 0,
            payload: "c;aGVsbG8=".to_string(),
        });
        let findings = check(&s);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::OutputOsc52ClipboardWrite);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn title_set_emits_info_finding() {
        let mut s = scan();
        s.title_set.push(OutputOscHit {
            offset: 0,
            payload: "Untitled".to_string(),
        });
        let findings = check(&s);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::OutputTitleManipulation);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn screen_clear_emits_info_finding() {
        let mut s = scan();
        s.screen_clear.push(OutputOscHit {
            offset: 0,
            payload: "\\e[2J".to_string(),
        });
        let findings = check(&s);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::OutputClearScreen);
    }

    #[test]
    fn hyperlink_mismatch_fires_when_visible_text_is_a_different_host_url() {
        let mut s = scan();
        s.hyperlinks.push(OutputHyperlinkHit {
            offset: 0,
            uri: "https://evil.example".to_string(),
            visible: "github.com".to_string(),
        });
        let findings = check(&s);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutputTerminalHyperlinkMismatch),
            "expected hyperlink mismatch finding: {findings:?}"
        );
    }

    #[test]
    fn hyperlink_no_fire_when_visible_text_is_human_prose() {
        let mut s = scan();
        s.hyperlinks.push(OutputHyperlinkHit {
            offset: 0,
            uri: "https://example.com/article/1".to_string(),
            visible: "Click here for the article".to_string(),
        });
        let findings = check(&s);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutputTerminalHyperlinkMismatch),
            "human prose label must NOT fire mismatch: {findings:?}"
        );
    }

    #[test]
    fn hyperlink_no_fire_when_hosts_match() {
        let mut s = scan();
        s.hyperlinks.push(OutputHyperlinkHit {
            offset: 0,
            uri: "https://github.com/torvalds/linux".to_string(),
            visible: "github.com/torvalds/linux".to_string(),
        });
        let findings = check(&s);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutputTerminalHyperlinkMismatch),
            "same host must NOT fire: {findings:?}"
        );
    }

    #[test]
    fn hyperlink_no_fire_when_visible_text_is_a_version_string() {
        // Regression: `parse_url_host` once accepted `v1.2.3` as a bare host.
        for label in ["v1.2.3", "1.0.0-alpha", "2.3.4", "release.1.0"] {
            let mut s = scan();
            s.hyperlinks.push(OutputHyperlinkHit {
                offset: 0,
                uri: "https://example.com/release".to_string(),
                visible: label.to_string(),
            });
            let findings = check(&s);
            assert!(
                !findings
                    .iter()
                    .any(|f| f.rule_id == RuleId::OutputTerminalHyperlinkMismatch),
                "version-shaped label {label:?} must NOT fire mismatch: {findings:?}"
            );
        }
    }

    #[test]
    fn hyperlink_fires_when_visible_text_is_a_raw_host_string() {
        // Positive control: guards against over-rejecting the bare-host path.
        let mut s = scan();
        s.hyperlinks.push(OutputHyperlinkHit {
            offset: 0,
            uri: "https://evil.example".to_string(),
            visible: "github.com".to_string(),
        });
        let findings = check(&s);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutputTerminalHyperlinkMismatch),
            "raw host label must fire mismatch on different uri host: {findings:?}"
        );
    }

    #[test]
    fn sgr_fg_eq_bg_fires_hidden_text() {
        let mut s = scan();
        // `\e[37;47m` — fg=white, bg=white (both basic 7).
        s.sgr.push(OutputSgrHit {
            offset: 0,
            params: vec![37, 47],
        });
        let findings = check(&s);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutputHiddenText),
            "fg==bg must fire: {findings:?}"
        );
    }

    #[test]
    fn sgr_fg_only_does_not_fire_hidden_text() {
        let mut s = scan();
        s.sgr.push(OutputSgrHit {
            offset: 0,
            params: vec![31],
        });
        let findings = check(&s);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutputHiddenText),
            "fg-only SGR (no explicit bg) must NOT fire — we don't infer defaults"
        );
    }

    #[test]
    fn long_zero_width_run_fires_hidden_text() {
        let mut s = scan();
        s.zero_width_runs.push(OutputZeroWidthRun {
            offset: 0,
            count: 12,
        });
        let findings = check(&s);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == RuleId::OutputHiddenText));
    }

    #[test]
    fn fake_root_prompt_fires() {
        let findings = check_fake_prompt("some output\n[root@server ~]# \nmore output\n");
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutputFakePrompt),
            "root@ prompt must fire: {findings:?}"
        );
    }

    #[test]
    fn fake_user_prompt_at_eof_fires() {
        let findings = check_fake_prompt("ls\nalice@laptop ~ $ ");
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutputFakePrompt),
            "user prompt at EOF must fire: {findings:?}"
        );
    }

    #[test]
    fn inline_dollar_prose_does_not_fire_fake_prompt() {
        // Tutorial / docs paragraph — `$ cmd` inline, no `@`, no terminal-shape.
        let findings = check_fake_prompt("Run the following:\n$ npm install\nThen build.\n");
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutputFakePrompt),
            "tutorial inline `$ cmd` must NOT fire: {findings:?}"
        );
    }
}
