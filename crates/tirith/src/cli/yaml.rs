//! Shared YAML scalar / inline-comment helpers for every `tirith` subcommand
//! that writes YAML scaffolds (`mcp policy init`, `agent policy init`, …).
//! Centralized so the YAML safety rules (incl. the DEL-escape fix) live in one
//! place rather than being copied in `cli/mcp.rs` and `cli/agent.rs`.
//!
//! Safety contract:
//! * [`safe_scalar`] returns YAML that round-trips byte-for-byte through
//!   `serde_yaml` (every reserved indicator, C0 control byte, DEL, empty string,
//!   and multi-byte UTF-8 quoted/escaped). The full per-character contract is
//!   pinned by `cli/mcp.rs::yaml_safe_scalar_round_trips_through_yaml_parser`; a
//!   smoke set runs here too.
//! * [`safe_inline_comment`] is for `#`-comment suffixes: any control byte
//!   (line-breakers / ANSI escapes) renders the whole string in `Debug` form.
//!
//! Both are `pub(crate)`, not part of the public library surface.

/// Bytes that force a YAML scalar to be quoted: YAML's reserved indicator set
/// (`:#-?,[]{}&*!|>'"%@` plus backtick) and whitespace (space, tab). Control
/// bytes (`< 0x20`, `0x7f` DEL) are checked separately in [`safe_scalar`].
pub(crate) const YAML_NEEDS_QUOTING_BYTES: &[u8] = b":#-?,[]{}&*!|>'\"%@` \t";

/// Render a scalar (server / tool / matcher name) for a YAML document. Returns
/// the input unmodified when safe as a bare scalar; otherwise quotes and
/// JSON-escapes it.
///
/// LOAD-BEARING for safety: scaffolds carry names from arbitrary config files,
/// and a name with `:` / `#` / a newline / an ANSI escape would otherwise split
/// the key, comment out the value, break the document, or reach the terminal on
/// `cat`. The quoted/escaped form is unambiguous.
pub(crate) fn safe_scalar(s: &str) -> String {
    // Empty must be quoted — bare empty is invalid YAML.
    if s.is_empty() {
        return "\"\"".to_string();
    }
    // Bare-safe iff every byte is printable ASCII non-special. Control bytes are
    // checked separately so a future indicator change can't drop the guards.
    let needs_quoting = s
        .bytes()
        .any(|b| YAML_NEEDS_QUOTING_BYTES.contains(&b) || b < 0x20 || b == 0x7f);
    if !needs_quoting {
        return s.to_string();
    }
    // JSON escaping (a subset of YAML's double-quoted form) handles every C0
    // byte. Post-process DEL: JSON leaves it literal, but YAML 1.2 §5.7 rejects
    // a literal DEL in a quoted scalar; replace with``
    // (pinned by `yaml_safe_scalar_round_trips_del` in `cli/mcp.rs`).
    serde_json::to_string(s)
        .map(|json| json.replace('\u{7f}', "\\u007F"))
        .unwrap_or_else(|_| format!("\"{}\"", s.escape_debug()))
}

/// Render a string for an inline `#`-comment suffix. The risks are line-breakers
/// (`\n`, `\r`) and ANSI escapes, so any control byte triggers `Debug` rendering
/// (printable bytes only).
pub(crate) fn safe_inline_comment(s: &str) -> String {
    // No control bytes → as-is; otherwise debug-escape.
    if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        format!("{s:?}")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Full round-trip behavior is pinned by the call-site modules (`cli/mcp.rs`,
    // `cli/agent.rs`); these are a load-bearing smoke subset.

    #[test]
    fn safe_scalar_empty_becomes_quoted() {
        assert_eq!(safe_scalar(""), "\"\"");
    }

    #[test]
    fn safe_scalar_plain_identifier_is_bare() {
        assert_eq!(safe_scalar("abc"), "abc");
        assert_eq!(safe_scalar("v1_2_3"), "v1_2_3");
    }

    #[test]
    fn safe_scalar_quotes_yaml_indicator_byte() {
        for &b in YAML_NEEDS_QUOTING_BYTES {
            let s = format!("a{}b", b as char);
            let out = safe_scalar(&s);
            assert!(
                out.starts_with('"') && out.ends_with('"'),
                "byte 0x{b:02x} ({:?}) must force quoting: got {out:?}",
                b as char,
            );
        }
    }

    #[test]
    fn safe_scalar_quotes_control_bytes() {
        // C0 control + DEL.
        for b in 0u8..0x20 {
            let s = format!("a{}b", b as char);
            assert!(safe_scalar(&s).starts_with('"'));
        }
        assert!(safe_scalar("a\x7fb").starts_with('"'));
    }

    #[test]
    fn safe_scalar_escapes_del_for_yaml_roundtrip() {
        // DEL must be escaped, not a raw byte (YAML 1.2 §5.7 disallows a raw DEL
        // in a quoted scalar). Escaped to``.
        let scalar = safe_scalar("\x7f");
        assert!(
            !scalar.contains('\u{7f}'),
            "raw DEL must not appear: {scalar:?}"
        );
        assert!(
            scalar.contains("\\u007F"),
            "DEL must be escaped: {scalar:?}"
        );
        // And the round-trip through serde_yaml recovers the original.
        let doc = format!("k: {scalar}\n");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&doc).expect("DEL round-trip parses");
        assert_eq!(parsed.get("k").and_then(|v| v.as_str()), Some("\x7f"));
    }

    #[test]
    fn safe_inline_comment_passes_safe_strings_unchanged() {
        assert_eq!(safe_inline_comment("/etc/foo.json"), "/etc/foo.json");
        assert_eq!(safe_inline_comment(".mcp.json"), ".mcp.json");
    }

    #[test]
    fn safe_inline_comment_escapes_control_bytes() {
        let out = safe_inline_comment("evil\nname");
        // Debug form quotes the entire string and escapes the newline.
        assert!(out.starts_with('"') && out.ends_with('"'), "got {out:?}");
        assert!(out.contains("\\n"));
    }
}
