use std::io::Read;

use crate::cli::last_trigger;
use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::output;
use tirith_core::tokenize::ShellType;

pub fn run(
    shell: &str,
    json: bool,
    non_interactive: bool,
    interactive_flag: bool,
    html_path: Option<&str>,
    with_source: bool,
) -> i32 {
    const MAX_PASTE: u64 = 1024 * 1024;

    let mut raw_bytes = Vec::new();
    if let Err(e) = std::io::stdin()
        .take(MAX_PASTE + 1)
        .read_to_end(&mut raw_bytes)
    {
        eprintln!("tirith: failed to read stdin: {e}");
        return 1;
    }
    if raw_bytes.len() as u64 > MAX_PASTE {
        eprintln!("tirith: paste input exceeds 1 MiB limit");
        return 1;
    }

    if raw_bytes.is_empty() {
        return 0;
    }

    let shell_type = match shell.parse::<ShellType>() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("tirith: warning: unknown shell '{shell}', falling back to posix");
            ShellType::Posix
        }
    };

    // Lossy is fine — raw bytes are preserved separately for byte-scan rules.
    let input = String::from_utf8_lossy(&raw_bytes).into_owned();

    let interactive = if interactive_flag {
        true
    } else if non_interactive {
        false
    } else if let Ok(val) = std::env::var("TIRITH_INTERACTIVE") {
        val == "1"
    } else {
        is_terminal::is_terminal(std::io::stderr())
    };

    let clipboard_html = html_path.and_then(|path| match std::fs::read_to_string(path) {
        Ok(html) => Some(html),
        Err(e) => {
            eprintln!("tirith: warning: failed to read clipboard HTML from '{path}': {e}");
            None
        }
    });

    // M12 ch1 G1 TOCTOU fix: only `--with-source` reads `clipboard_source.json`, and
    // exactly ONCE — the same record feeds both the engine (paste_source_mismatch) and
    // the display below. The tri-state lets the engine distinguish "CLI looked and found
    // nothing" (`AbsentOrInvalid`, must NOT re-read disk) from "CLI never looked"
    // (`Unread`, engine reads once itself — the plain `tirith paste` path).
    let display_record = if with_source {
        tirith_core::clipboard::read_source_record()
    } else {
        None
    };
    let clipboard_source_state = if with_source {
        match display_record.clone() {
            Some(rec) => tirith_core::clipboard::ClipboardSourceState::Loaded(rec),
            None => tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
        }
    } else {
        tirith_core::clipboard::ClipboardSourceState::Unread
    };

    let ctx = AnalysisContext {
        input,
        shell: shell_type,
        scan_context: ScanContext::Paste,
        raw_bytes: Some(raw_bytes),
        interactive,
        cwd: std::env::current_dir()
            .ok()
            .map(|p| p.display().to_string()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html,
        card_ref: None,
        clipboard_source: clipboard_source_state,
    };

    // PR #121 item 18: one policy snapshot for analysis + enforcement + audit, to
    // close the TOCTOU window where a `.tirith/policy.yaml` change between two
    // `Policy::discover` reads routed detection and enforcement against different policies.
    let (mut verdict, policy) = engine::analyze_returning_policy(&ctx);
    crate::cli::warn_repo_policy_neutralized(&policy);
    crate::cli::warn_bad_injection_seeds(&policy);

    // M4 item 8: origin attribution — the CLI is the only layer that knows whether the
    // caller was a human, an agent (TIRITH_INTEGRATION), or CI. The audit below picks it up.
    verdict.agent_origin = Some(tirith_core::agent_origin::resolve_cli_origin(interactive));

    // M4 item 8 ch3: enforce `agent_rules.deny` here — the paste path does NOT route
    // through `post_process_verdict`, so without this a deny matcher would fire on
    // `tirith check` but silently fail on `tirith paste`. M4 PR #120 fix-6 (Greptile P1):
    // skip under bypass (TIRITH=0), mirroring check/gateway — the raw verdict already
    // wins and apply_agent_rules must not re-Block. Pinned by
    // `paste_agent_rules_deny_skipped_under_tirith_bypass_today`.
    if !verdict.bypass_honored {
        tirith_core::escalation::apply_agent_rules(&mut verdict, &policy);
    }

    // Audit must capture full detection BEFORE paranoia filtering (ADR-13: paranoia is
    // an output-layer filter). M4 item 8 ch3: bypass-honored verdicts are logged here too
    // (the engine no longer audits its bypass path, so the CLI can stamp agent_origin first).
    let event_id = uuid::Uuid::new_v4().to_string();
    // Best-effort audit on the `paste` hot path — a write failure must not
    // change behavior, so the Result is intentionally dropped.
    let _ = tirith_core::audit::log_verdict(
        &verdict,
        &ctx.input,
        None,
        Some(event_id),
        &policy.dlp_custom_patterns,
    );

    engine::filter_findings_by_paranoia(&mut verdict, policy.paranoia);

    if verdict.action != tirith_core::verdict::Action::Allow {
        last_trigger::write_last_trigger(&verdict, &ctx.input, &policy.dlp_custom_patterns);
    }

    if json {
        // M12 ch1 `--with-source`: add the attributed clipboard source as extra top-level
        // JSON keys (not a Finding). `clipboard_source: null` when no extension / stale
        // record / hash mismatch, so a caller distinguishes "no source" from a missing flag.
        let source_attribution = if with_source {
            // Hash the ORIGINAL bytes, in lockstep with the engine's paste_source_mismatch.
            let raw = ctx.raw_bytes.as_deref().unwrap_or(ctx.input.as_bytes());
            Some(resolve_source_attribution(raw, display_record.as_ref()))
        } else {
            None
        };
        if write_paste_json(&verdict, &policy.dlp_custom_patterns, source_attribution).is_err() {
            eprintln!("tirith: failed to write JSON output");
        }
    } else {
        if output::write_human_auto(&verdict, false).is_err() {
            eprintln!("tirith: failed to write output");
        }
        // M12 ch1 `--with-source` human mode: a one-line stderr attribution note
        // (structured keys live in `--json`). Graceful when no source was recorded.
        if with_source {
            let raw = ctx.raw_bytes.as_deref().unwrap_or(ctx.input.as_bytes());
            match resolve_source_attribution(raw, display_record.as_ref()) {
                serde_json::Value::Null => {
                    eprintln!("tirith paste: no clipboard source recorded for this paste");
                }
                v => {
                    let url = v
                        .get("source_url")
                        .and_then(|u| u.as_str())
                        .unwrap_or("(unknown)");
                    eprintln!("tirith paste: clipboard source: {url}");
                }
            }
        }
    }

    verdict.action.exit_code()
}

/// Resolve the attributed clipboard source for this paste, if the companion extension
/// recorded one whose `content_sha256` matches the pasted bytes. Returns
/// `{source_url, source_title}` on a match, else `null` (no record / hash mismatch /
/// no extension) so `--with-source` always emits a `clipboard_source` key.
///
/// `raw` is the ORIGINAL bytes (not lossy `ctx.input`), hashed in LOCKSTEP with the
/// `paste_source_mismatch` rule so display and finding never disagree on a non-UTF-8
/// paste. `record` is the SAME one read once at the top of `run` (G1 TOCTOU fix) — we
/// do not re-read `clipboard_source.json` here.
fn resolve_source_attribution(
    raw: &[u8],
    record: Option<&tirith_core::clipboard::ClipboardSourceRecord>,
) -> serde_json::Value {
    let Some(record) = record else {
        return serde_json::Value::Null;
    };
    // Same `matches_bytes` the engine's rule uses (Greptile R1 #6), on the original bytes.
    if !record.matches_bytes(raw) {
        // Recorded source exists but does not describe this paste (stale / replaced).
        return serde_json::Value::Null;
    }
    // Provenance comes from an arbitrary web page via the untrusted extension, so it is
    // sanitized before surfacing: drop URL query/fragment/userinfo (token-bearing), strip
    // terminal control sequences, length-cap. Both output paths read these sanitized values.
    serde_json::json!({
        "source_url": sanitize_source_url(&record.source_url),
        "source_title": sanitize_provenance_text(&record.source_title),
    })
}

/// Max characters of provenance text surfaced into output. Bounds how much of a
/// (potentially sensitive) page title or path can leak into logs / JSON.
const PROVENANCE_MAX_CHARS: usize = 256;

/// Neutralize one untrusted provenance string before display/logging. Runs through the
/// shared `output_filter` (strips ANSI/OSC/APC/DCS, bare CR, C0 controls, DEL, zero-width),
/// then flattens tabs/newlines to spaces and length-caps.
fn sanitize_provenance_text(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    tirith_core::mcp::output_filter::sanitize_text_into(s.as_bytes(), &mut out);
    let cleaned = String::from_utf8(out).unwrap_or_default();
    let flattened: String = cleaned
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    cap_chars(flattened.trim(), PROVENANCE_MAX_CHARS)
}

/// Redact the high-risk parts of a source URL (query, fragment, `user:pass@` userinfo —
/// all token-bearing) while keeping `scheme://host/path`, then sanitize + cap. A value
/// that does not parse as a URL is still sanitized verbatim, just not structurally redacted.
fn sanitize_source_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            parsed.set_query(None);
            parsed.set_fragment(None);
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            sanitize_provenance_text(parsed.as_str())
        }
        Err(_) => sanitize_provenance_text(url),
    }
}

/// Truncate to at most `max` characters (not bytes), appending `…` when cut.
fn cap_chars(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    } else {
        s.to_string()
    }
}

/// Write the paste verdict as JSON, optionally splicing a top-level `clipboard_source`
/// key (`--with-source`). Renders the shared `output::write_json` envelope, then parses
/// it back to add the extra key. Without `--with-source` it is byte-identical to `write_json`.
fn write_paste_json(
    verdict: &tirith_core::verdict::Verdict,
    custom_patterns: &[String],
    source_attribution: Option<serde_json::Value>,
) -> std::io::Result<()> {
    use std::io::Write as _;
    let Some(source) = source_attribution else {
        return output::write_json(verdict, custom_patterns, std::io::stdout().lock());
    };
    // Render to a buffer, then add the extra key. A parse failure is unreachable for our
    // own serializer; fall back to the plain envelope rather than dropping output.
    let mut buf = Vec::new();
    output::write_json(verdict, custom_patterns, &mut buf)?;
    let mut value: serde_json::Value = match serde_json::from_slice(&buf) {
        Ok(v) => v,
        Err(_) => {
            // Still emit newline-terminated output for line-oriented consumers.
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&buf)?;
            return writeln!(stdout);
        }
    };
    if let Some(obj) = value.as_object_mut() {
        obj.insert("clipboard_source".to_string(), source);
    }
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &value)?;
    writeln!(stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_core::clipboard::{content_sha256_hex, ClipboardSourceRecord};

    fn record_for(payload: &[u8], source_url: &str, source_title: &str) -> ClipboardSourceRecord {
        ClipboardSourceRecord {
            updated_at: "2026-05-30T00:00:00Z".to_string(),
            // matching hash so attribution proceeds (matches_bytes == true)
            content_sha256: content_sha256_hex(payload),
            source_url: source_url.to_string(),
            source_title: source_title.to_string(),
            hidden_text_detected: false,
        }
    }

    // A hash mismatch yields no attribution (display stays in lockstep with the rule).
    #[test]
    fn no_attribution_when_hash_mismatches() {
        let rec = record_for(b"the-real-bytes", "https://docs.example.com/x", "X");
        let v = resolve_source_attribution(b"DIFFERENT-bytes", Some(&rec));
        assert_eq!(v, serde_json::Value::Null);
    }

    // CodeRabbit Major: untrusted provenance — URL token-bearing parts stripped and
    // terminal control sequences in the title neutralized before emission.
    #[test]
    fn provenance_is_sanitized_before_emission() {
        let payload = b"install-me";
        let rec = record_for(
            payload,
            "https://user:pw@docs.example.com/install?token=SECRET123&sig=ABC#section",
            // ANSI color escape + BEL + an embedded newline, injected via the page title
            "Install\u{1b}[31mGuide\u{07}\nline2",
        );
        let v = resolve_source_attribution(payload, Some(&rec));
        let url = v.get("source_url").and_then(|u| u.as_str()).unwrap();
        let title = v.get("source_title").and_then(|t| t.as_str()).unwrap();

        // URL: query, fragment, and userinfo dropped; meaningful path kept.
        assert_eq!(url, "https://docs.example.com/install");
        assert!(
            !url.contains("SECRET123"),
            "signed token must not leak: {url:?}"
        );
        assert!(!url.contains("token=") && !url.contains("sig="));
        assert!(!url.contains('#') && !url.contains("user:pw"));

        // Title: ANSI/BEL control sequences stripped, newline flattened, text kept.
        assert!(
            !title.contains('\u{1b}'),
            "ANSI escape must be stripped: {title:?}"
        );
        assert!(!title.contains('\u{07}'), "BEL must be stripped: {title:?}");
        assert!(
            !title.contains('\n'),
            "newline must be flattened: {title:?}"
        );
        assert!(title.contains("Install") && title.contains("Guide"));
    }

    // Long titles are length-capped so a sensitive page title can't dump
    // unbounded text into logs/JSON.
    #[test]
    fn provenance_title_is_length_capped() {
        let payload = b"x";
        let rec = record_for(
            payload,
            "https://example.com/",
            &"A".repeat(PROVENANCE_MAX_CHARS + 50),
        );
        let v = resolve_source_attribution(payload, Some(&rec));
        let title = v.get("source_title").and_then(|t| t.as_str()).unwrap();
        // capped to PROVENANCE_MAX_CHARS plus the single ellipsis marker
        assert!(title.chars().count() <= PROVENANCE_MAX_CHARS + 1);
        assert!(
            title.ends_with('…'),
            "truncation marker expected: {title:?}"
        );
    }

    // A non-URL provenance value is still sanitized (never emitted raw) even
    // though it can't be structurally redacted.
    #[test]
    fn non_url_source_is_still_sanitized() {
        let got = sanitize_source_url("not a url\u{1b}[2J\u{07}");
        assert!(!got.contains('\u{1b}') && !got.contains('\u{07}'));
    }
}
