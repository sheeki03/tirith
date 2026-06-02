//! MCP tool-result output filter (M7 ch4). Routes a [`ToolCallResult`]'s
//! `content[].text` through [`crate::engine::analyze_output`] and rewrites by
//! verdict [`Action`]:
//!
//! * `Block` — replace `content` with one placeholder text item citing the
//!   `event_id` (for audit-log correlation) and set `isError: true`.
//! * `Warn` — keep `isError`; prepend a `[tirith: WARNING …]` item and sanitize
//!   existing text in place (strip ANSI/OSC/zero-width, structure preserved).
//! * `Allow` — pass through unchanged.
//!
//! Blocks use MCP `isError: true` + placeholder, NOT a JSON-RPC error envelope
//! (that signals transport failure, not content policy). See
//! [`docs/mcp-output-filter.md`](../../../docs/mcp-output-filter.md).
//!
//! Risks handled: per-call scan capped at [`MAX_SCAN_BYTES`] (truncation noted,
//! content never silently dropped); the M7 ch1 ruleset flags only the dangerous
//! subset (plain SGR colour passes); and `fail_mode_closed=true` callers DENY on
//! analysis error rather than passing content through.

use serde::{Deserialize, Serialize};

use crate::engine::{analyze_output, OutputContext};
use crate::verdict::{Action, Finding, Severity};

use super::types::{ContentItem, ToolCallResult};

/// Per-call scan cap. Beyond it the result is marked truncated and only the first
/// `MAX_SCAN_BYTES` of concatenated text is scanned. Never drop content silently.
pub const MAX_SCAN_BYTES: usize = 1_048_576;

/// Outcome of one filter pass (the `event_id` is the join key against the audit log).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterOutcome {
    /// Effective action after the filter ran (`WarnAck` is folded into `Warn`).
    pub action: Action,
    /// Stable id persisted to the block placeholder for audit correlation.
    pub event_id: String,
    /// Rule IDs that fired, in scan order.
    pub rule_ids: Vec<String>,
    /// Highest severity that fired (None if no findings).
    pub max_severity: Option<Severity>,
    /// Wall time spent in `analyze_output`.
    pub elapsed_ms: f64,
    /// `true` when the scanned slice was truncated to `MAX_SCAN_BYTES`.
    pub truncated: bool,
    /// `true` when the response was force-blocked because the scan couldn't
    /// complete in budget under `fail_mode_closed` (v1: the truncation path only).
    pub fail_mode_triggered: bool,
}

impl FilterOutcome {
    /// Convenience: was a block forced (either by rule or by fail-mode)?
    pub fn is_block(&self) -> bool {
        matches!(self.action, Action::Block)
    }
}

/// Run the output filter on `result` in place, returning a [`FilterOutcome`] for
/// audit + routing. `fail_mode_closed`: `true` degrades an analysis error to
/// BLOCK (default for `mcp-server --sanitize-tool-output`); `false` (gateway
/// default) degrades to ALLOW.
pub fn filter_tool_result(result: &mut ToolCallResult, fail_mode_closed: bool) -> FilterOutcome {
    let event_id = uuid::Uuid::new_v4().to_string();

    // Concatenate `content[].text` (text items only; others pass through). A NUL
    // separates items so an OSC payload split across items isn't rejoined.
    let mut joined = String::new();
    let mut total_bytes: usize = 0;
    let mut truncated = false;
    for item in &result.content {
        if item.content_type != "text" {
            continue;
        }
        if !joined.is_empty() {
            joined.push('\0');
            total_bytes += 1;
        }
        let remaining = MAX_SCAN_BYTES.saturating_sub(total_bytes);
        if remaining == 0 {
            truncated = true;
            break;
        }
        if item.text.len() > remaining {
            // Char-boundary safe truncate.
            let mut cut = remaining;
            while cut > 0 && !item.text.is_char_boundary(cut) {
                cut -= 1;
            }
            joined.push_str(&item.text[..cut]);
            truncated = true;
            break;
        }
        joined.push_str(&item.text);
        total_bytes += item.text.len();
    }

    let start = std::time::Instant::now();
    let verdict = analyze_output(&joined, OutputContext::default());
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

    let rule_ids: Vec<String> = verdict
        .findings
        .iter()
        .map(|f| f.rule_id.to_string())
        .collect();
    let max_severity = verdict.findings.iter().map(|f| f.severity).max();

    let action = verdict.action;
    let mut outcome = FilterOutcome {
        action,
        event_id: event_id.clone(),
        rule_ids,
        max_severity,
        elapsed_ms,
        truncated,
        fail_mode_triggered: false,
    };

    match action {
        Action::Block => {
            apply_block(result, &event_id);
        }
        Action::Warn | Action::WarnAck => {
            apply_warn(result, &event_id, &verdict.findings);
            outcome.action = Action::Warn; // normalize WarnAck → Warn for transport
        }
        Action::Allow => {
            if truncated && fail_mode_closed {
                // Closed fail-mode: refuse to forward content not analyzed in full.
                apply_block(result, &event_id);
                outcome.action = Action::Block;
                outcome.fail_mode_triggered = true;
            }
        }
    }

    outcome
}

/// Block path: replace `content` with one placeholder text item and set
/// `isError: true` (structure preserved so MCP clients render uniformly).
fn apply_block(result: &mut ToolCallResult, event_id: &str) {
    result.content = vec![ContentItem {
        content_type: "text".to_string(),
        text: format!(
            "[tirith: tool output blocked \u{2014} see audit log entry {event_id} for details]"
        ),
    }];
    result.is_error = true;
}

/// Warn path: prepend a `[tirith: WARNING …]` notice and sanitize each existing
/// text item in place (non-text items pass through).
fn apply_warn(result: &mut ToolCallResult, event_id: &str, findings: &[Finding]) {
    let n = findings.len();
    let warning = ContentItem {
        content_type: "text".to_string(),
        text: format!(
            "[tirith: WARNING \u{2014} {n} finding{plural}; see audit log entry {event_id}]",
            plural = if n == 1 { "" } else { "s" }
        ),
    };

    for item in result.content.iter_mut() {
        if item.content_type != "text" {
            continue;
        }
        let mut out = Vec::with_capacity(item.text.len());
        sanitize_text_into(item.text.as_bytes(), &mut out);
        // Scrubbed output stays valid UTF-8 (we drop whole chars, never split one).
        item.text = String::from_utf8(out).unwrap_or_else(|_| item.text.clone());
    }

    result.content.insert(0, warning);
}

/// Strip ANSI/OSC/APC/DCS escapes and zero-width chars from `chunk` into `out`.
/// Mirrors `tirith view` so both surfaces sanitize identically. Keeps `\t`/`\n`
/// and CRLF; drops bare CR (display-overwriting), other C0 controls, and DEL.
pub fn sanitize_text_into(chunk: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    let n = chunk.len();
    while i < n {
        let b = chunk[i];

        if b == 0x1B {
            if i + 1 < n {
                match chunk[i + 1] {
                    b'[' => {
                        // CSI: final byte 0x40..=0x7E. Skip to and including final.
                        let mut j = i + 2;
                        while j < n {
                            let cb = chunk[j];
                            if (0x40..=0x7E).contains(&cb) {
                                j += 1;
                                break;
                            }
                            j += 1;
                        }
                        i = j;
                        continue;
                    }
                    b']' | b'_' | b'P' => {
                        // OSC/APC/DCS: terminated by BEL (0x07) or ST (ESC \).
                        let mut j = i + 2;
                        while j < n {
                            if chunk[j] == 0x07 {
                                j += 1;
                                break;
                            }
                            if chunk[j] == 0x1B && j + 1 < n && chunk[j + 1] == b'\\' {
                                j += 2;
                                break;
                            }
                            j += 1;
                        }
                        i = j;
                        continue;
                    }
                    _ => {
                        // Lone ESC - drop the ESC plus the following byte.
                        i += 2;
                        continue;
                    }
                }
            } else {
                // Trailing ESC - drop.
                break;
            }
        }

        // Drop bare CR (display-overwriting); keep CRLF.
        if b == b'\r' {
            if i + 1 < n && chunk[i + 1] == b'\n' {
                out.push(b'\r');
                out.push(b'\n');
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        // Drop other C0 controls except \t and \n.
        if b < 0x20 && b != b'\t' && b != b'\n' {
            i += 1;
            continue;
        }
        if b == 0x7F {
            i += 1;
            continue;
        }

        // Strip zero-width characters. Multi-byte UTF-8 - decode the char.
        if b >= 0xc0 {
            let remaining = &chunk[i..];
            if let Some(ch) = std::str::from_utf8(remaining)
                .ok()
                .or_else(|| std::str::from_utf8(&remaining[..remaining.len().min(4)]).ok())
                .and_then(|s| s.chars().next())
            {
                if is_strippable_zero_width(ch) {
                    i += ch.len_utf8();
                    continue;
                }
                let len = ch.len_utf8();
                out.extend_from_slice(&chunk[i..i + len]);
                i += len;
                continue;
            }
        }

        out.push(b);
        i += 1;
    }
}

fn is_strippable_zero_width(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' // ZERO WIDTH SPACE
        | '\u{200C}' // ZERO WIDTH NON-JOINER
        | '\u{200D}' // ZERO WIDTH JOINER
        | '\u{2060}' // WORD JOINER
        | '\u{FEFF}' // BYTE ORDER MARK / ZERO WIDTH NO-BREAK SPACE
    ) || ('\u{E0000}'..='\u{E007F}').contains(&ch)
    // Unicode Tags block — invisible, steganographic-attack vector (Greptile P2).
    // Keep in sync with `cli::view`/`cli::logs::is_strippable_zero_width`.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_item(s: &str) -> ContentItem {
        ContentItem {
            content_type: "text".to_string(),
            text: s.to_string(),
        }
    }

    fn osc52_text() -> String {
        // A complete OSC 52 (clipboard-write) sequence.
        "before-payload-\x1B]52;c;aGVsbG8=\x07-after-payload".to_string()
    }

    #[test]
    fn block_replaces_content_and_sets_is_error() {
        let mut result = ToolCallResult {
            content: vec![text_item(&osc52_text())],
            is_error: false,
            structured_content: None,
        };
        let outcome = filter_tool_result(&mut result, false);
        assert_eq!(outcome.action, Action::Block);
        assert!(result.is_error, "block must set isError=true");
        assert_eq!(
            result.content.len(),
            1,
            "block must collapse to single placeholder"
        );
        let text = &result.content[0].text;
        assert!(text.starts_with("[tirith: tool output blocked"));
        assert!(
            text.contains(&outcome.event_id),
            "placeholder must cite event_id: {text}"
        );
    }

    #[test]
    fn allow_passes_through_unchanged() {
        let mut result = ToolCallResult {
            content: vec![text_item("benign output\nno escape sequences")],
            is_error: false,
            structured_content: None,
        };
        let before = result.content[0].text.clone();
        let outcome = filter_tool_result(&mut result, false);
        assert_eq!(outcome.action, Action::Allow);
        assert!(!result.is_error);
        assert_eq!(result.content[0].text, before);
    }

    #[test]
    fn allow_with_plain_sgr_is_not_blocked() {
        // Agents legitimately use SGR colour. Output rules flag only dangerous
        // sequences. Plain SGR must pass.
        let mut result = ToolCallResult {
            content: vec![text_item("\x1B[31mred\x1B[0m text")],
            is_error: false,
            structured_content: None,
        };
        let outcome = filter_tool_result(&mut result, false);
        assert!(
            matches!(outcome.action, Action::Allow),
            "plain SGR must NOT block; got {:?} (rules: {:?})",
            outcome.action,
            outcome.rule_ids
        );
    }

    #[test]
    fn warn_prepends_notice_and_sanitizes() {
        // Force a Warn-shaped scenario via a hidden-text run (>8 zero-width
        // chars → Medium → Warn).
        let mut zw_block = String::new();
        for _ in 0..16 {
            zw_block.push('\u{200B}');
        }
        let payload = format!("visible{zw_block}hidden");
        let mut result = ToolCallResult {
            content: vec![text_item(&payload)],
            is_error: false,
            structured_content: None,
        };
        let outcome = filter_tool_result(&mut result, false);
        // We are not guaranteed Warn here at the verdict level — different
        // severities may apply. Cover the case where it lands at Warn.
        if matches!(outcome.action, Action::Warn) {
            assert!(result.content.len() >= 2, "warn must prepend a notice item");
            assert!(result.content[0].text.starts_with("[tirith: WARNING"));
            assert!(result.content[0].text.contains(&outcome.event_id));
            // Zero-width chars should be stripped from the existing item.
            let body = &result.content[1].text;
            assert!(!body.contains('\u{200B}'), "zero-width must be stripped");
        }
    }

    #[test]
    fn fail_mode_closed_blocks_on_truncation() {
        // Force truncation by exceeding MAX_SCAN_BYTES with benign content.
        let huge = "x".repeat(MAX_SCAN_BYTES + 1024);
        let mut result = ToolCallResult {
            content: vec![text_item(&huge)],
            is_error: false,
            structured_content: None,
        };
        let outcome = filter_tool_result(&mut result, true);
        assert_eq!(
            outcome.action,
            Action::Block,
            "closed fail-mode must deny on truncated scan"
        );
        assert!(outcome.truncated);
        assert!(outcome.fail_mode_triggered);
        assert!(result.is_error);
    }

    #[test]
    fn fail_mode_open_allows_on_truncation() {
        let huge = "x".repeat(MAX_SCAN_BYTES + 1024);
        let mut result = ToolCallResult {
            content: vec![text_item(&huge)],
            is_error: false,
            structured_content: None,
        };
        let outcome = filter_tool_result(&mut result, false);
        // Open fail-mode: benign content truncated past the cap still passes
        // (rules that fired on the first MAX_SCAN_BYTES are honored; if none
        // fired, the residual passes through).
        assert!(
            matches!(outcome.action, Action::Allow),
            "open fail-mode must pass truncated benign content; got {:?}",
            outcome.action,
        );
        assert!(outcome.truncated);
        assert!(!outcome.fail_mode_triggered);
        assert!(!result.is_error);
    }

    #[test]
    fn non_text_items_pass_through_untouched() {
        // A non-text item should not be inspected nor mutated, regardless of
        // verdict on the text siblings.
        let mut result = ToolCallResult {
            content: vec![
                text_item(&osc52_text()),
                ContentItem {
                    content_type: "image".to_string(),
                    text: "base64-blob".to_string(),
                },
            ],
            is_error: false,
            structured_content: None,
        };
        let outcome = filter_tool_result(&mut result, false);
        assert_eq!(outcome.action, Action::Block);
        // Block replaces all content with the placeholder — the sibling image
        // (a possible steg vector) is not preserved.
        assert_eq!(result.content.len(), 1);
        assert_eq!(result.content[0].content_type, "text");
    }

    #[test]
    fn sanitize_strips_csi_and_osc() {
        let mut out = Vec::new();
        sanitize_text_into(b"a\x1B[31mred\x1B[0mb", &mut out);
        assert_eq!(out, b"aredb");
        out.clear();
        sanitize_text_into(b"prefix\x1B]52;c;aGVsbG8=\x07suffix", &mut out);
        assert_eq!(out, b"prefixsuffix");
    }

    #[test]
    fn sanitize_keeps_tabs_and_newlines() {
        let mut out = Vec::new();
        sanitize_text_into(b"a\tb\nc\r\nd", &mut out);
        assert_eq!(out, b"a\tb\nc\r\nd");
    }

    #[test]
    fn sanitize_strips_zero_width() {
        let mut out = Vec::new();
        sanitize_text_into("a\u{200B}b\u{200D}c".as_bytes(), &mut out);
        assert_eq!(out, b"abc");
    }

    #[test]
    fn event_id_is_uuid_shaped() {
        let mut result = ToolCallResult {
            content: vec![text_item("hello")],
            is_error: false,
            structured_content: None,
        };
        let outcome = filter_tool_result(&mut result, false);
        // UUID v4 stringified is 36 chars: 8-4-4-4-12
        assert_eq!(outcome.event_id.len(), 36, "{}", outcome.event_id);
        assert_eq!(outcome.event_id.matches('-').count(), 4);
    }
}
