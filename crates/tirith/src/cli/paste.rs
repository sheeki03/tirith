use std::io::{Read, Write as _};

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
    let _policy_diagnostic_capture = tirith_core::policy::PolicyDiagnosticCapture::start();
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

    let mut unknown_shell = None;
    let shell_type = match shell.parse::<ShellType>() {
        Ok(s) => s,
        Err(_) => {
            unknown_shell = Some(shell.to_string());
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

    let clipboard_html = match html_path {
        Some(path) => {
            // repo-0402: bounded read — the HTML sidecar was previously slurped
            // with no cap while the paste input itself is limited to 1 MiB.
            // repo-0401: an explicitly requested analyzer that cannot run must
            // FAIL CLOSED (exit non-zero), never silently degrade to plain
            // text — an unreadable/invalid sidecar means the hidden-content
            // analysis did not happen.
            match tirith_core::util::read_text_no_follow_capped(
                std::path::Path::new(path),
                MAX_PASTE,
            ) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(html) => Some(html),
                    Err(_) => {
                        return emit_early_paste_error(
                            &format!(
                                "clipboard HTML '{path}' is not valid UTF-8; refusing to skip rich-text analysis"
                            ),
                            2,
                        );
                    }
                },
                Err(e) => {
                    return emit_early_paste_error(
                        &format!(
                            "cannot read clipboard HTML '{path}' safely ({e:?}); refusing to skip rich-text analysis"
                        ),
                        2,
                    );
                }
            }
        }
        None => None,
    };

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
    tirith_core::policy::freeze_captured_policy_dlp_patterns(&policy.dlp_custom_patterns);
    crate::cli::warn_repo_policy_neutralized(&policy);
    crate::cli::warn_bad_injection_seeds(&policy);
    let provenance_dlp =
        tirith_core::redact::CompiledCustomPatterns::new_silent(&policy.dlp_custom_patterns);
    if let Some(shell) = unknown_shell {
        let shell =
            tirith_core::output::sanitize_human_field_with_compiled(&shell, &provenance_dlp);
        eprintln!("tirith: warning: unknown shell '{shell}', falling back to posix");
    }

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
            Some(resolve_source_attribution(
                raw,
                display_record.as_ref(),
                &provenance_dlp,
            ))
        } else {
            None
        };
        // repo-0489: a missing/truncated JSON document must not pair with a
        // success exit code — an Allow verdict still reports failure.
        if write_paste_json(&verdict, &policy.dlp_custom_patterns, source_attribution).is_err() {
            eprintln!("tirith: failed to write JSON output");
            return if verdict.action.exit_code() == 0 {
                1
            } else {
                verdict.action.exit_code()
            };
        }
    } else {
        let mut human = output::HumanInvocationWriter::new(
            std::io::stderr().lock(),
            tirith_core::style::use_color_for(tirith_core::style::Stream::Stderr),
        );
        let mut human_failed = output::write_human_to_invocation_with_patterns(
            &verdict,
            false,
            &policy.dlp_custom_patterns,
            &mut human,
        )
        .is_err();
        // M12 ch1 `--with-source` human mode: a one-line stderr attribution note
        // (structured keys live in `--json`). Graceful when no source was recorded.
        if with_source {
            let raw = ctx.raw_bytes.as_deref().unwrap_or(ctx.input.as_bytes());
            match resolve_source_attribution(raw, display_record.as_ref(), &provenance_dlp) {
                serde_json::Value::Null => {
                    human_failed |= writeln!(
                        human,
                        "tirith paste: no clipboard source recorded for this paste"
                    )
                    .is_err();
                }
                v => {
                    let url = v
                        .get("source_url")
                        .and_then(|u| u.as_str())
                        .unwrap_or("(unknown)");
                    human_failed |=
                        writeln!(human, "tirith paste: clipboard source: {url}").is_err();
                }
            }
        }
        human_failed |= human.finish().is_err();
        if human_failed {
            eprintln!("tirith: failed to write output");
        }
    }

    verdict.action.exit_code()
}

fn emit_early_paste_error(message: &str, exit_code: i32) -> i32 {
    let policy = tirith_core::policy::Policy::discover(None);
    tirith_core::policy::freeze_captured_policy_dlp_patterns(&policy.dlp_custom_patterns);
    let compiled =
        tirith_core::redact::CompiledCustomPatterns::new_silent(&policy.dlp_custom_patterns);
    let mut human = output::HumanInvocationWriter::new(
        std::io::stderr().lock(),
        tirith_core::style::use_color_for(tirith_core::style::Stream::Stderr),
    );
    for diagnostic in tirith_core::policy::drain_captured_policy_diagnostics_for_output(&compiled) {
        let diagnostic =
            tirith_core::output::sanitize_human_field_with_compiled(&diagnostic, &compiled);
        let _ = writeln!(human, "tirith paste: policy diagnostic: {diagnostic}");
    }
    let message = tirith_core::output::sanitize_human_field_with_compiled(message, &compiled);
    let _ = writeln!(human, "tirith: {message}");
    let _ = human.finish();
    exit_code
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
    compiled: &tirith_core::redact::CompiledCustomPatterns,
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
        "source_url": crate::cli::sanitize_provenance_url_with_compiled(&record.source_url, compiled),
        "source_title": crate::cli::sanitize_provenance_text_with_compiled(&record.source_title, compiled),
    })
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
    let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(custom_patterns);
    tirith_core::redact::redact_json_strings(&mut value, &compiled);
    let value = tirith_core::verdict::bound_json_value_for_output(value);
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &value)?;
    writeln!(stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_core::clipboard::{content_sha256_hex, ClipboardSourceRecord};

    fn dlp(patterns: &[String]) -> tirith_core::redact::CompiledCustomPatterns {
        tirith_core::redact::CompiledCustomPatterns::new_silent(patterns)
    }

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
        let v = resolve_source_attribution(b"DIFFERENT-bytes", Some(&rec), &dlp(&[]));
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
        let v = resolve_source_attribution(payload, Some(&rec), &dlp(&[]));
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
            &"A".repeat(crate::cli::PROVENANCE_MAX_CHARS + 50),
        );
        let v = resolve_source_attribution(payload, Some(&rec), &dlp(&[]));
        let title = v.get("source_title").and_then(|t| t.as_str()).unwrap();
        // capped to PROVENANCE_MAX_CHARS plus the single ellipsis marker
        assert!(title.chars().count() <= crate::cli::PROVENANCE_MAX_CHARS + 1);
        assert!(
            title.ends_with('…'),
            "truncation marker expected: {title:?}"
        );
    }

    // A non-URL provenance value is still sanitized (never emitted raw) even
    // though it can't be structurally redacted.
    #[test]
    fn non_url_source_is_still_sanitized() {
        let got = crate::cli::sanitize_provenance_url_with_compiled(
            "not a url\u{1b}[2J\u{07}",
            &dlp(&[]),
        );
        assert!(!got.contains('\u{1b}') && !got.contains('\u{07}'));
    }

    #[test]
    fn provenance_custom_patterns_are_redacted_before_length_bounding() {
        let payload = b"x";
        let canary = "C02_PASTE_SOURCE_SECRET";
        let rec = record_for(
            payload,
            &format!("https://example.com/{canary}/install"),
            &format!("Guide for {canary}"),
        );
        let patterns = vec![regex::escape(canary)];
        let value = resolve_source_attribution(payload, Some(&rec), &dlp(&patterns));
        let serialized = serde_json::to_string(&value).unwrap();

        assert!(!serialized.contains(canary));
        assert!(serialized.contains("[REDACTED:custom]"));
    }

    #[test]
    fn provenance_provider_path_tokens_are_removed_by_the_shared_sanitizer() {
        let token = "rpc-provider-token-0123456789";
        let value = crate::cli::sanitize_provenance_url_with_compiled(
            &format!("https://mainnet.infura.io/v3/{token}?key=also-secret#fragment"),
            &dlp(&[]),
        );
        assert_eq!(value, "https://mainnet.infura.io/v3");
        assert!(!value.contains(token));
    }
}
