//! `tirith view <file>` — render a file with terminal-deception sequences
//! neutralized and a sidecar finding list.
//!
//! Streams the file in 64 KiB chunks through [`tirith_core::engine::analyze_output_chunk`]
//! so the byte-scanner state machine carries across chunk boundaries (an escape
//! sequence split on a 64 KiB boundary is still detected). Output is neutralized by
//! stripping ANSI escapes (CSI/OSC/APC/DCS) and zero-width chars — plain text only.
//!
//! Exit codes: 0 Allow, 1 Block (High finding), 2 Warn. `Action::WarnAck` folds
//! back to 2 here (no interactive ack channel in `tirith view`).

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

use tirith_core::engine::{self, OutputAnalyzerState};
use tirith_core::verdict::{Action, Verdict};

/// 64 KiB streaming chunks. Matches the M7 ch1 spec.
const CHUNK_BYTES: usize = 64 * 1024;

/// Hard ceiling on the default scan window. Anything larger requires
/// explicit `--max-bytes`. v1 cap is 16 MiB.
pub const DEFAULT_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Entry point. Reads `path` (or stdin when `None`), runs the output-direction
/// analyzer over the bytes in streaming chunks, prints the sanitized content
/// to stdout, and prints the finding list to stderr (or as JSON when `json`).
pub fn run(path: Option<&Path>, max_bytes: u64, json: bool) -> i32 {
    // C3a — honor operator/org `injection_seeds_custom` here too: a coding agent
    // reading a file back through `tirith view` should be scanned against the same
    // custom seeds as the paste/MCP paths. Discover OFFLINE (`discover_local_only`,
    // no network; a repo-scoped weakening flag is neutralized inside) from the
    // file's parent dir (or cwd for stdin). This is init, not the hot path, so each
    // bad seed is reported ONCE to stderr (safe: `view` writes its content to
    // stdout) rather than silently dropped — a seed that passes `policy validate`
    // but fails the real compile would otherwise vanish.
    let seed_cwd = path
        .and_then(|p| p.parent())
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.display().to_string());
    let policy = tirith_core::policy::Policy::discover_local_only(seed_cwd.as_deref());
    let (custom_seeds, bad_seeds) =
        tirith_core::rules::prompt_injection::compile_seeds(&policy.injection_seeds_custom);
    for (pattern, error) in &bad_seeds {
        eprintln!(
            "tirith view: warning: invalid injection_seeds_custom regex {pattern:?}: {error}"
        );
    }

    let mut state = OutputAnalyzerState::with_custom_seeds(custom_seeds);
    let mut display_sanitizer = StreamingDisplaySanitizer::default();
    let mut sanitized = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut truncated = false;

    let read_result: std::io::Result<()> = (|| {
        let mut reader: Box<dyn BufRead> = match path {
            Some(p) => Box::new(BufReader::with_capacity(CHUNK_BYTES, File::open(p)?)),
            None => Box::new(BufReader::with_capacity(
                CHUNK_BYTES,
                std::io::stdin().lock(),
            )),
        };

        let mut buf = vec![0u8; CHUNK_BYTES];
        loop {
            // Honor the byte cap: cap each read to whatever's left of
            // `max_bytes`. When the remaining budget is 0, stop.
            let remaining = max_bytes.saturating_sub(total_bytes);
            if remaining == 0 {
                // Probe one extra byte to distinguish truncation from a clean EOF.
                let mut probe = [0u8; 1];
                let n = reader.read(&mut probe)?;
                if n > 0 {
                    truncated = true;
                }
                break;
            }
            let want = std::cmp::min(buf.len(), remaining as usize);
            let n = reader.read(&mut buf[..want])?;
            if n == 0 {
                break;
            }
            total_bytes += n as u64;

            let decoded = display_sanitizer.push(&buf[..n], &mut sanitized);
            if !decoded.is_empty() {
                let _ = engine::analyze_output_chunk(&decoded, &mut state);
            }
        }
        Ok(())
    })();

    if let Err(e) = read_result {
        eprintln!(
            "tirith view: failed to read {}: {e}",
            path.map(|p| p.display().to_string())
                .unwrap_or_else(|| "<stdin>".to_string())
        );
        return 1;
    }

    // Flush an incomplete final UTF-8 sequence as U+FFFD. Unterminated escape
    // sequences and a trailing bare CR intentionally produce no display bytes.
    let decoded_tail = display_sanitizer.finish(&mut sanitized);
    if !decoded_tail.is_empty() {
        let _ = engine::analyze_output_chunk(&decoded_tail, &mut state);
    }

    let verdict = engine::analyze_output_finalize_mut(&mut state);

    if json {
        return emit_json(path, &verdict, total_bytes, truncated);
    }

    // Human path: write the sanitized content to stdout (so callers can
    // `tirith view foo | less`), and the findings/banner to stderr.
    // repo-0502: a broken pipe or full filesystem must not return the
    // verdict's clean exit code with truncated/absent output.
    let mut out_ok = std::io::stdout().lock().write_all(&sanitized).is_ok();
    if !sanitized.is_empty() && !sanitized.ends_with(b"\n") {
        out_ok = writeln!(std::io::stdout().lock()).is_ok() && out_ok;
    }
    if !out_ok {
        eprintln!("tirith view: failed to write output");
        return 1;
    }

    print_findings_human(&verdict, path, total_bytes, truncated);

    // Translate the Verdict to an exit code via the standard mapping.
    verdict.action.exit_code()
}

/// Incremental UTF-8 decoder. Definite malformed subsequences become U+FFFD;
/// only a potentially valid incomplete suffix is retained for the next chunk.
/// This prevents both split-codepoint corruption and verbatim invalid-byte
/// passthrough.
#[derive(Debug, Default)]
struct StreamingUtf8Decoder {
    pending: Vec<u8>,
}

impl StreamingUtf8Decoder {
    fn push(&mut self, chunk: &[u8]) -> String {
        self.pending.extend_from_slice(chunk);
        self.decode_available(false)
    }

    fn finish(&mut self) -> String {
        self.decode_available(true)
    }

    fn decode_available(&mut self, eof: bool) -> String {
        let mut decoded = String::new();
        while !self.pending.is_empty() {
            match std::str::from_utf8(&self.pending) {
                Ok(valid) => {
                    decoded.push_str(valid);
                    self.pending.clear();
                    break;
                }
                Err(error) => {
                    let valid_len = error.valid_up_to();
                    if valid_len > 0 {
                        // `valid_up_to` is guaranteed to end on a UTF-8 boundary.
                        let valid = std::str::from_utf8(&self.pending[..valid_len])
                            .expect("validated UTF-8 prefix");
                        decoded.push_str(valid);
                        self.pending.drain(..valid_len);
                        continue;
                    }

                    if let Some(error_len) = error.error_len() {
                        decoded.push('\u{FFFD}');
                        self.pending.drain(..error_len);
                        continue;
                    }

                    // The entire remaining buffer is a potentially valid but
                    // incomplete codepoint. Retain it across chunks; at EOF it
                    // becomes one visible replacement character.
                    if eof {
                        decoded.push('\u{FFFD}');
                        self.pending.clear();
                    }
                    break;
                }
            }
        }
        decoded
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum TerminalState {
    #[default]
    Ground,
    Escape,
    Csi,
    ControlString {
        escape_seen: bool,
    },
}

/// Stateful plain-text renderer for arbitrary byte streams. UTF-8, CRLF, CSI,
/// OSC, APC, and DCS state all survive chunk boundaries. After control-sequence
/// removal, the canonical core display scrub removes C0/C1 controls and every
/// deceptive or invisible Unicode class used elsewhere by the CLI.
#[derive(Debug, Default)]
struct StreamingDisplaySanitizer {
    decoder: StreamingUtf8Decoder,
    terminal: TerminalState,
    pending_cr: bool,
}

impl StreamingDisplaySanitizer {
    /// Decode and sanitize one byte chunk. The returned string is the original
    /// statefully decoded text for the output analyzer; `out` receives only safe
    /// display bytes.
    fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> String {
        let decoded = self.decoder.push(chunk);
        self.sanitize_decoded(&decoded, out);
        decoded
    }

    /// Flush a potentially incomplete UTF-8 suffix as U+FFFD. A pending bare CR
    /// or unterminated terminal escape is discarded rather than made active.
    fn finish(&mut self, out: &mut Vec<u8>) -> String {
        let decoded = self.decoder.finish();
        self.sanitize_decoded(&decoded, out);
        self.pending_cr = false;
        self.terminal = TerminalState::Ground;
        decoded
    }

    fn sanitize_decoded(&mut self, decoded: &str, out: &mut Vec<u8>) {
        let mut plain = String::with_capacity(decoded.len());
        for ch in decoded.chars() {
            if self.pending_cr {
                self.pending_cr = false;
                if ch == '\n' {
                    plain.push('\r');
                    plain.push('\n');
                    continue;
                }
            }

            match self.terminal {
                TerminalState::Ground => match ch {
                    '\u{1B}' => self.terminal = TerminalState::Escape,
                    '\u{009B}' => self.terminal = TerminalState::Csi,
                    '\u{0090}' | '\u{009D}' | '\u{009F}' => {
                        self.terminal = TerminalState::ControlString { escape_seen: false };
                    }
                    '\r' => self.pending_cr = true,
                    _ => plain.push(ch),
                },
                TerminalState::Escape => {
                    self.terminal = match ch {
                        '[' => TerminalState::Csi,
                        ']' | '_' | 'P' => TerminalState::ControlString { escape_seen: false },
                        '\u{1B}' => TerminalState::Escape,
                        _ => TerminalState::Ground,
                    };
                }
                TerminalState::Csi => {
                    if ch == '\u{1B}' {
                        self.terminal = TerminalState::Escape;
                    } else if ch.is_ascii() && ('@'..='~').contains(&ch) {
                        self.terminal = TerminalState::Ground;
                    }
                }
                TerminalState::ControlString { escape_seen } => {
                    if ch == '\u{7}' || ch == '\u{009C}' || (escape_seen && ch == '\\') {
                        self.terminal = TerminalState::Ground;
                    } else {
                        self.terminal = TerminalState::ControlString {
                            escape_seen: ch == '\u{1B}',
                        };
                    }
                }
            }
        }

        let safe = tirith_core::mcp::output_filter::sanitize_for_display(&plain);
        out.extend_from_slice(safe.as_bytes());
    }
}

fn print_findings_human(verdict: &Verdict, path: Option<&Path>, total_bytes: u64, truncated: bool) {
    let label = path
        .map(|p| super::sanitize_for_human_output(&p.display().to_string(), false))
        .unwrap_or_else(|| "<stdin>".to_string());

    let banner = match verdict.action {
        Action::Allow => "tirith view: clean",
        Action::Warn | Action::WarnAck => "tirith view: warnings",
        Action::Block => "tirith view: blocked",
    };
    eprintln!("{banner} — {label} ({total_bytes} bytes scanned)");
    if truncated {
        eprintln!(
            "  warning: file exceeded --max-bytes; only the first {total_bytes} bytes were scanned"
        );
    }

    for f in &verdict.findings {
        eprintln!(
            "  [{}] {} — {}",
            f.severity,
            f.rule_id,
            super::sanitize_for_human_output(&f.title, false)
        );
        eprintln!(
            "    {}",
            super::sanitize_for_human_output(&f.description, true)
        );
    }
}

fn emit_json(path: Option<&Path>, verdict: &Verdict, total_bytes: u64, truncated: bool) -> i32 {
    #[derive(serde::Serialize)]
    struct Out<'a> {
        schema_version: u32,
        path: Option<String>,
        action: Action,
        bytes_scanned: u64,
        truncated: bool,
        findings: &'a [tirith_core::verdict::Finding],
        timings_ms: &'a tirith_core::verdict::Timings,
    }
    let out = Out {
        schema_version: 1,
        path: path.map(|p| p.display().to_string()),
        action: verdict.action,
        bytes_scanned: total_bytes,
        truncated,
        findings: &verdict.findings,
        timings_ms: &verdict.timings_ms,
    };
    let mut stdout = std::io::stdout().lock();
    if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
        eprintln!("tirith view: failed to write JSON output");
        return 1;
    }
    verdict.action.exit_code()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn sanitize_chunks<'a>(chunks: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
        let mut sanitizer = StreamingDisplaySanitizer::default();
        let mut out = Vec::new();
        for chunk in chunks {
            let _ = sanitizer.push(chunk, &mut out);
        }
        let _ = sanitizer.finish(&mut out);
        out
    }

    fn assert_safe_at_every_split(input: &[u8], expected: &[u8]) {
        for split in 0..=input.len() {
            let actual = sanitize_chunks([&input[..split], &input[split..]]);
            assert_eq!(
                actual, expected,
                "unexpected output with byte split at {split} for {input:?}"
            );
        }

        let byte_chunks = input.iter().map(std::slice::from_ref);
        assert_eq!(
            sanitize_chunks(byte_chunks),
            expected,
            "unexpected output when every byte is a separate chunk"
        );
    }

    #[test]
    fn view_clean_file_exits_zero() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"hello world\n").unwrap();
        let code = run(Some(f.path()), DEFAULT_MAX_BYTES, false);
        assert_eq!(code, 0);
    }

    #[test]
    fn view_osc52_flags_findings_and_strips_sequence() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"before\x1b]52;c;aGVsbG8=\x07after\n").unwrap();
        // We can't easily capture stdout here; just assert the exit code.
        let code = run(Some(f.path()), DEFAULT_MAX_BYTES, false);
        assert_eq!(code, Action::Block.exit_code(), "OSC 52 must block (High)");
    }

    #[test]
    fn sanitize_strips_csi_and_osc() {
        assert_safe_at_every_split(b"a\x1b[31mred\x1b[0mb", b"aredb");
        assert_safe_at_every_split(b"prefix\x1b]52;c;aGVsbG8=\x07suffix", b"prefixsuffix");
        assert_safe_at_every_split(b"prefix\x1b]0;title\x1b\\suffix", b"prefixsuffix");
        assert_safe_at_every_split(b"prefix\x1b_Payload\x1b\\suffix", b"prefixsuffix");
        assert_safe_at_every_split(b"prefix\x1bPPayload\x1b\\suffix", b"prefixsuffix");
    }

    #[test]
    fn sanitize_keeps_tabs_and_newlines() {
        assert_safe_at_every_split(b"a\tb\nc\r\nd", b"a\tb\nc\r\nd");
        assert_safe_at_every_split(b"a\rb", b"ab");
    }

    #[test]
    fn sanitize_preserves_split_utf8_and_never_copies_invalid_bytes() {
        assert_safe_at_every_split("a包b".as_bytes(), "a包b".as_bytes());
        assert_safe_at_every_split(b"a\xf0\x9f\x92b", "a\u{FFFD}b".as_bytes());
        assert_safe_at_every_split(b"a\x80b", "a\u{FFFD}b".as_bytes());
        assert!(std::str::from_utf8(&sanitize_chunks([b"\xff".as_slice()])).is_ok());
    }

    #[test]
    fn sanitize_strips_every_display_deception_class_at_every_split() {
        let dangerous = [
            '\u{0001}',  // C0
            '\u{007F}',  // DEL
            '\u{0080}',  // C1 lower bound
            '\u{009B}',  // C1 CSI
            '\u{009F}',  // C1 upper bound
            '\u{202E}',  // bidi override
            '\u{200B}',  // zero width
            '\u{E0001}', // Unicode tag
            '\u{FE0F}',  // variation selector
            '\u{3164}',  // Hangul filler
            '\u{2061}',  // invisible math operator
            '\u{180E}',  // invisible whitespace
        ];

        for ch in dangerous {
            let input = format!("a{ch}b");
            let expected: &[u8] = if matches!(ch, '\u{009B}' | '\u{009F}') {
                b"a"
            } else {
                b"ab"
            };
            assert_safe_at_every_split(input.as_bytes(), expected);
        }
    }

    #[test]
    fn sanitize_strips_complete_c1_range_at_every_split() {
        for codepoint in 0x80..=0x9F {
            let ch = char::from_u32(codepoint).unwrap();
            let input = format!("a{ch}");
            assert_safe_at_every_split(input.as_bytes(), b"a");
        }
    }

    #[test]
    fn sanitize_drops_unterminated_escape_payload_at_eof() {
        assert_safe_at_every_split(b"safe\x1b]52;c;payload", b"safe");
        assert_safe_at_every_split(b"safe\x1b[31", b"safe");
    }
}
