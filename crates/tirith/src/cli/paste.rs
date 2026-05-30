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

    // Lossy is fine here — raw bytes are preserved separately for byte-scan rules.
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

    // M12 ch1 — G1 TOCTOU fix: read the companion clipboard-source record ONCE
    // here and feed the SAME in-memory record to BOTH the engine (which fires
    // `paste_source_mismatch`) and the `--with-source` display below. Previously
    // the engine read `clipboard_source.json` and `resolve_source_attribution`
    // read it AGAIN, so a fast copy-paste-copy could make the displayed
    // `clipboard_source` disagree with the finding. One read closes that window.
    let clipboard_source = tirith_core::clipboard::read_source_record();

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
        clipboard_source: clipboard_source.clone(),
    };

    // PR #121 fix-list item 18 (mirrors `install.rs:760` / `check.rs`):
    // single policy snapshot for analysis + enforcement + audit. Pre-fix
    // `engine::analyze` discovered policy internally, then the surrounding
    // code re-ran `Policy::discover` for the `apply_agent_rules` /
    // `filter_findings_by_paranoia` / audit calls below. A change to
    // `.tirith/policy.yaml` between the two reads then routed detection
    // and enforcement against inconsistent policies — a TOCTOU window.
    // `analyze_returning_policy` returns the same snapshot the engine
    // used so the rest of this function works against ONE policy.
    let (mut verdict, policy) = engine::analyze_returning_policy(&ctx);

    // M4 item 8: best-effort origin attribution for the paste path. The CLI
    // is the only place that knows whether the caller looked like a human,
    // an agent (via TIRITH_INTEGRATION), or a CI runner. The audit entry
    // below picks the origin up automatically.
    verdict.agent_origin = Some(tirith_core::agent_origin::resolve_cli_origin(interactive));

    // M4 item 8 chunk 3 follow-up — enforce `agent_rules.deny` here. The
    // paste path does NOT route through `post_process_verdict` (the engine
    // is the only consumer of escalation/session bookkeeping). Without
    // this call, an operator who writes a `deny` matcher to block an
    // untrusted agent would see deny enforce on `tirith check` but
    // silently fail on `tirith paste` (a clipboard-poisoning hostile
    // surface). The helper is a no-op on `Allowed`/`Unspecified`.
    //
    // M4 PR #120 fix-6 (Greptile P1): mirror the bypass-skip branch the
    // hot paths in `check`/`gateway` use — under `TIRITH=0`, the raw
    // verdict already wins and `apply_agent_rules` must NOT silently
    // re-Block. The pin
    // `paste_agent_rules_deny_skipped_under_tirith_bypass_today`
    // covers this; the `check` mirror is
    // `agent_rules_deny_skipped_under_tirith_bypass_today`.
    if !verdict.bypass_honored {
        tirith_core::escalation::apply_agent_rules(&mut verdict, &policy);
    }

    // Audit must capture full detection BEFORE paranoia filtering (ADR-13:
    // engine always detects everything; paranoia is an output-layer filter).
    // M4 item 8 chunk 3 — bypass-honored verdicts are now logged here too,
    // because the engine no longer audits its own bypass path (so the CLI
    // can stamp `agent_origin` on the verdict before the audit line
    // is written). Pre-chunk-3 this branch SKIPPED audit when bypass was
    // honored, trusting `analyze()` to have logged.
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
        // M12 ch1 — `--with-source`: enrich the JSON envelope with the attributed
        // clipboard source (the page the paste was copied from), as EXTRA
        // top-level keys, NOT as a Finding. Attribution only happens when the
        // companion extension's recorded `content_sha256` matches this paste's
        // hash; otherwise (no extension / stale record / hash mismatch) we report
        // a `clipboard_source: null` so a scripted caller can tell "no source
        // recorded" apart from a missing flag.
        let source_attribution = if with_source {
            Some(resolve_source_attribution(
                &ctx.input,
                clipboard_source.as_ref(),
            ))
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
        // M12 ch1 — `--with-source` in human mode: print a one-line attribution
        // note to stderr (the structured keys live in `--json`). Graceful when no
        // source was recorded for this paste.
        if with_source {
            match resolve_source_attribution(&ctx.input, clipboard_source.as_ref()) {
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

/// Resolve the attributed clipboard source for this paste, if the companion
/// extension recorded one whose `content_sha256` matches `input`. Returns a JSON
/// object (`{source_url, source_title}`) on a match, or `null` when there is no
/// recorded source / the hash does not match / the extension isn't installed —
/// so `--with-source` always emits a `clipboard_source` key and a scripted
/// caller can distinguish "matched source" from "no source recorded".
///
/// G1 TOCTOU fix: the `record` is the SAME one already read once at the top of
/// `run` and handed to the engine, so the displayed attribution and the
/// `paste_source_mismatch` finding can never disagree. We do NOT re-read
/// `clipboard_source.json` here.
fn resolve_source_attribution(
    input: &str,
    record: Option<&tirith_core::clipboard::ClipboardSourceRecord>,
) -> serde_json::Value {
    use sha2::{Digest, Sha256};
    let Some(record) = record else {
        return serde_json::Value::Null;
    };
    let digest = Sha256::digest(input.as_bytes());
    let mut actual = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(actual, "{b:02x}");
    }
    if !actual.eq_ignore_ascii_case(record.content_sha256.trim()) {
        // A recorded source exists, but it does NOT describe this paste (stale
        // record / clipboard replaced). No attribution.
        return serde_json::Value::Null;
    }
    serde_json::json!({
        "source_url": record.source_url,
        "source_title": record.source_title,
    })
}

/// Write the paste verdict as JSON, optionally splicing a top-level
/// `clipboard_source` key (`--with-source`). We render the verdict through the
/// shared `output::write_json` (so the envelope shape is identical to every
/// other JSON surface), then, only when source attribution was requested, parse
/// it back into a `serde_json::Value` to add the extra key. Without
/// `--with-source` this is byte-identical to `output::write_json`.
fn write_paste_json(
    verdict: &tirith_core::verdict::Verdict,
    custom_patterns: &[String],
    source_attribution: Option<serde_json::Value>,
) -> std::io::Result<()> {
    use std::io::Write as _;
    let Some(source) = source_attribution else {
        return output::write_json(verdict, custom_patterns, std::io::stdout().lock());
    };
    // Render the canonical envelope to a buffer, then add the extra key. A parse
    // failure here is impossible for our own serializer, but handle it by falling
    // back to the plain envelope rather than dropping output.
    let mut buf = Vec::new();
    output::write_json(verdict, custom_patterns, &mut buf)?;
    let mut value: serde_json::Value = match serde_json::from_slice(&buf) {
        Ok(v) => v,
        Err(_) => {
            // Unreachable in practice (our own serializer always emits valid
            // JSON), but if it ever happened we must still emit newline-
            // terminated output for line-oriented consumers. `write_json` already
            // appended a trailing newline to `buf`; flush it, then guarantee
            // termination explicitly rather than relying on that invariant.
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
