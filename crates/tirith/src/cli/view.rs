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

            let chunk_str = String::from_utf8_lossy(&buf[..n]).into_owned();
            let _ = engine::analyze_output_chunk(&chunk_str, &mut state);

            sanitize_into(&buf[..n], &mut sanitized);
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

    let verdict = engine::analyze_output_finalize_mut(&mut state);

    if json {
        return emit_json(path, &verdict, total_bytes, truncated);
    }

    // Human path: write the sanitized content to stdout (so callers can
    // `tirith view foo | less`), and the findings/banner to stderr.
    let _ = std::io::stdout().lock().write_all(&sanitized);
    if !sanitized.is_empty() && !sanitized.ends_with(b"\n") {
        let _ = writeln!(std::io::stdout().lock());
    }

    print_findings_human(&verdict, path, total_bytes, truncated);

    // Translate the Verdict to an exit code via the standard mapping.
    verdict.action.exit_code()
}

/// Strip ANSI / OSC escape sequences and zero-width characters from `chunk`
/// into `out`. Intentionally simple — we render plain text only.
fn sanitize_into(chunk: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    let n = chunk.len();
    while i < n {
        let b = chunk[i];

        if b == 0x1B {
            if i + 1 < n {
                match chunk[i + 1] {
                    b'[' => {
                        // CSI — final byte 0x40..=0x7E. Skip to and including final.
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
                        // OSC / APC / DCS — terminated by BEL (0x07) or ST (\e\\).
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
                        // Lone ESC — drop it.
                        i += 2;
                        continue;
                    }
                }
            } else {
                // Trailing ESC, drop.
                break;
            }
        }

        // Drop CR not followed by LF (display-overwriting); keep CRLF.
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

        // Other low control chars except \t and \n: drop.
        if b < 0x20 && b != b'\t' && b != b'\n' {
            i += 1;
            continue;
        }
        if b == 0x7F {
            i += 1;
            continue;
        }

        // Strip zero-width characters. Multi-byte → decode the char.
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
        '\u{200B}' // ZWSP
        | '\u{200C}' // ZWNJ
        | '\u{200D}' // ZWJ
        | '\u{2060}' // WORD JOINER
        | '\u{FEFF}' // ZWNBSP / BOM
    ) || ('\u{E0000}'..='\u{E007F}').contains(&ch)
}

fn print_findings_human(verdict: &Verdict, path: Option<&Path>, total_bytes: u64, truncated: bool) {
    let label = path
        .map(|p| p.display().to_string())
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
        eprintln!("  [{}] {} — {}", f.severity, f.rule_id, f.title);
        eprintln!("    {}", f.description);
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
        let mut out = Vec::new();
        sanitize_into(b"a\x1b[31mred\x1b[0mb", &mut out);
        assert_eq!(out, b"aredb");

        out.clear();
        sanitize_into(b"prefix\x1b]52;c;aGVsbG8=\x07suffix", &mut out);
        assert_eq!(out, b"prefixsuffix");
    }

    #[test]
    fn sanitize_keeps_tabs_and_newlines() {
        let mut out = Vec::new();
        sanitize_into(b"a\tb\nc\r\nd", &mut out);
        assert_eq!(out, b"a\tb\nc\r\nd");
    }

    #[test]
    fn sanitize_strips_zero_width() {
        let mut out = Vec::new();
        sanitize_into("a\u{200B}b\u{200D}c".as_bytes(), &mut out);
        assert_eq!(out, b"abc");
    }
}
