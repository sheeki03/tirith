//! M11 ch3 — `tirith canary create|status|list|prune|rotate` (design-decision D3).
//!
//! Thin presenter over [`tirith_core::canary`]. The store (a JSONL file at
//! `state_dir()/canaries.jsonl`), token generation, detection, and all
//! read/write logic live in the library; this module is output + the `prune`
//! confirmation prompt.
//!
//! A canary is a deliberately-synthetic, clearly-fake secret-shaped token you
//! plant as bait. tirith records it locally; when that exact token later shows
//! up in a command, paste, or inspected tool output, the engine fires
//! `CanaryTokenTouched` (High).
//!
//! # D3 — local-first
//!
//! By DEFAULT a canary is local-only: detection raises a finding + writes to the
//! local audit log, with no phone-home. `create --callback-url <url>` opts into
//! a best-effort POST (`{kind, detected_at, context}` — NEVER the token value)
//! to a URL YOU self-host. There is no tirith-operated endpoint.

use tirith_core::canary::{self, CanaryEntry, CanaryKind};

use super::{confirm, write_json_stdout};

/// Emit an operator error as a machine-readable `{"error": ...}` JSON object on
/// stdout when `--json`, or a human line on stderr otherwise. Keeps `--json`
/// surfaces parseable on the validation-failure paths (unknown kind, bad
/// callback URL, missing `--yes`) instead of emitting plain stderr that a JSON
/// consumer cannot parse. Mirrors `cli::command_card::emit_error`.
///
/// Returns `false` when the JSON write itself failed (broken pipe / truncated
/// output) so a `--json` caller can surface a write failure instead of pairing a
/// semantic exit code with no JSON delivered (CodeRabbit R8 #3). Human mode
/// always returns `true` — the stderr line is best-effort and not gated.
fn emit_error(json: bool, ctx: &str, msg: &str) -> bool {
    if json {
        let v = serde_json::json!({ "error": msg });
        write_json_stdout(&v, &format!("{ctx}: failed to write JSON output"))
    } else {
        eprintln!("{ctx}: {msg}");
        true
    }
}

/// `tirith canary create <kind> [--callback-url <url>]` — generate and store a
/// fresh synthetic canary token, printing the token + metadata.
pub fn create(kind: &str, callback_url: Option<String>, json: bool) -> i32 {
    let Some(kind) = CanaryKind::parse(kind) else {
        // A failed JSON write returns 2 anyway here (same as this validation
        // code), but routing through the bool keeps the broken-pipe path explicit.
        let _ = emit_error(
            json,
            "tirith canary create",
            &format!(
                "unknown kind '{kind}' — supported: {}",
                CanaryKind::all().join(", ")
            ),
        );
        return 2;
    };

    // Reject an obviously-malformed callback URL early (must be http(s)). We do
    // NOT verify reachability — the URL is the user's self-hosted endpoint and
    // is only contacted on detection. Normalize (trim) the value here and
    // persist the trimmed form, so whitespace padding from the CLI never lands
    // in the store (and never reaches the detached callback POST, which only
    // re-trims as a defensive backstop).
    let callback_url = match callback_url {
        Some(url) => {
            let trimmed = url.trim();
            if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
                let _ = emit_error(
                    json,
                    "tirith canary create",
                    &format!("--callback-url must be an http(s) URL (got '{url}')"),
                );
                return 2;
            }
            Some(trimmed.to_string())
        }
        None => None,
    };

    match canary::create(kind, callback_url) {
        Ok(entry) => {
            if json {
                if !write_json_stdout(&entry, "tirith canary create: failed to write JSON output") {
                    return 2;
                }
                return 0;
            }
            print_created_human(&entry);
            0
        }
        Err(e) => {
            // On a broken-pipe JSON write the error JSON never reached the
            // consumer; surface that as a write-failure exit (2) rather than the
            // semantic 1 paired with no output (mirrors command-card sign).
            if !emit_error(json, "tirith canary create", &e.to_string()) {
                return 2;
            }
            1
        }
    }
}

/// `tirith canary list` — print every recorded canary (id, kind, when,
/// callback). The token VALUE is shown so the user can plant it; it lives in a
/// local 0600 store either way.
pub fn list(json: bool) -> i32 {
    // Use the completeness-aware list: a present-but-unreadable/incomplete store
    // (FIFO/device, or a persistent mid-file read fault) degrades to a partial
    // view, which `canary::list()` would hide. Warn so a truncated listing is
    // never shown as if it were the whole store.
    let (entries, complete) = canary::list_complete();
    if !complete {
        // On the JSON surface a partial list must NOT look authoritative: a
        // stdout-only consumer never sees the stderr warning, so FAIL (CodeRabbit
        // R13f) instead of emitting a partial array with exit 0. The human path
        // warns and still shows the partial view — a person can judge it.
        if json {
            if !emit_error(
                json,
                "tirith canary list",
                "the canary store could not be read completely; refusing to emit a partial list",
            ) {
                return 2;
            }
            return 1;
        }
        eprintln!(
            "tirith canary list: warning: the canary store could not be read \
             completely; the list below may be partial."
        );
    }

    if json {
        if !write_json_stdout(&entries, "tirith canary list: failed to write JSON output") {
            return 2;
        }
        return 0;
    }

    if entries.is_empty() {
        print_empty_help();
        return 0;
    }

    println!("Registered canaries ({}):", entries.len());
    println!();
    for entry in &entries {
        print_entry_human(entry, true);
        println!();
    }
    println!("Plant a token where it should never be read. A later command, paste, or");
    println!("inspected tool output containing it fires CanaryTokenTouched (High).");
    0
}

/// `tirith canary status` — a compact summary: how many canaries, how many have
/// a callback URL, and where the store lives. Does NOT print token values.
pub fn status(json: bool) -> i32 {
    // Completeness-aware (see `list`): never report a partial store as the
    // authoritative status.
    let (entries, complete) = canary::list_complete();
    if !complete {
        // JSON surface must not report partial counts as authoritative (see
        // `list`, CodeRabbit R13f): fail rather than emit numbers a stdout-only
        // consumer would trust. The human path warns and shows the partial counts.
        if json {
            if !emit_error(
                json,
                "tirith canary status",
                "the canary store could not be read completely; refusing to report partial counts",
            ) {
                return 2;
            }
            return 1;
        }
        eprintln!(
            "tirith canary status: warning: the canary store could not be read \
             completely; the counts below may be partial."
        );
    }
    let with_callback = entries.iter().filter(|e| e.callback_url.is_some()).count();
    let store = canary::store_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<unresolved>".to_string());

    if json {
        #[derive(serde::Serialize)]
        struct StatusOut {
            registered: usize,
            with_callback: usize,
            local_only: usize,
            store_path: String,
        }
        let out = StatusOut {
            registered: entries.len(),
            with_callback,
            local_only: entries.len() - with_callback,
            store_path: store,
        };
        if !write_json_stdout(&out, "tirith canary status: failed to write JSON output") {
            return 2;
        }
        return 0;
    }

    println!("Canary status:");
    println!("  registered:    {}", entries.len());
    println!("  local-only:    {}", entries.len() - with_callback);
    println!("  with callback: {with_callback} (opt-in, user-self-hosted)");
    println!("  store:         {store}");
    if entries.is_empty() {
        println!();
        print_empty_help();
    }
    0
}

/// `tirith canary prune <id>` — remove one canary by id (prompts unless --yes).
pub fn prune(id: &str, yes: bool, json: bool) -> i32 {
    // Read the store COMPLETENESS-AWARE (CodeRabbit R17 #2): a lenient
    // `canary::list()` degrades a present-but-unreadable/incomplete store to an
    // empty/partial view, so the old "nothing to prune" pre-check could exit 0
    // "success" against a store that is actually UNREADABLE. We only treat
    // "id absent" as a genuine no-op when the store was read to COMPLETION; an
    // INCOMPLETE read falls through to the strict `prune_at` core below (which
    // aborts on an incomplete read and reports the real failure) rather than
    // short-circuiting. A truly-empty *resolvable* store is `complete == true`
    // with no entries, so its genuine "nothing to prune" UX is preserved.
    let (entries, complete) = canary::list_complete();
    let existing = entries.into_iter().find(|e| e.id == id);
    if complete && existing.is_none() {
        if json {
            if !write_json_stdout(
                &PruneOut {
                    id,
                    pruned: false,
                    removed: 0,
                },
                "tirith canary prune: failed to write JSON output",
            ) {
                return 2;
            }
        } else {
            println!("No canary with id '{id}' — nothing to prune.");
        }
        return 0;
    }

    // Confirm only when we have a concrete entry to remove (an informed prompt).
    // On an INCOMPLETE read `existing` is `None` but we still fall through here:
    // skip the (meaningless) prompt and let `prune_at` surface the read failure.
    if existing.is_some() && !json && !confirm(&format!("Prune canary {id}?"), yes) {
        println!("Aborted — canary left in place.");
        return 0;
    }
    // In JSON mode, require --yes to proceed non-interactively (no prompt on a
    // machine-readable surface). Without it, refuse rather than silently prune.
    if json && !yes {
        let _ = emit_error(
            json,
            "tirith canary prune",
            "--yes required in JSON mode to confirm removal",
        );
        return 2;
    }

    match canary::prune(id) {
        Ok(removed) => {
            if json {
                if !write_json_stdout(
                    &PruneOut {
                        id,
                        pruned: removed > 0,
                        removed,
                    },
                    "tirith canary prune: failed to write JSON output",
                ) {
                    return 2;
                }
            } else if removed == 0 {
                // Mirror the JSON `pruned: false`: a concurrent prune (or an
                // unknown id) between the pre-check and `prune` removed nothing.
                println!("No canary with id '{id}' — nothing to prune.");
            } else {
                println!("Pruned canary {id} ({removed} entr{}).", plural(removed));
            }
            0
        }
        Err(e) => {
            // Mirror `create` / command-card sign (CodeRabbit R13c): a normal
            // operation failure (store read-modify-write error) is the semantic
            // exit 1; only a broken-pipe JSON write — where the error never reached
            // the consumer — is the write-failure exit 2.
            if !emit_error(json, "tirith canary prune", &e.to_string()) {
                return 2;
            }
            1
        }
    }
}

#[derive(serde::Serialize)]
struct PruneOut<'a> {
    id: &'a str,
    pruned: bool,
    removed: usize,
}

/// `tirith canary rotate <id>` — generate a fresh token of the same kind for an
/// existing canary, preserving the id + callback URL. The OLD token stops
/// firing; the NEW one fires going forward.
pub fn rotate(id: &str, json: bool) -> i32 {
    match canary::rotate(id) {
        Ok(Some(entry)) => {
            if json {
                if !write_json_stdout(&entry, "tirith canary rotate: failed to write JSON output") {
                    return 2;
                }
                return 0;
            }
            println!("Rotated canary {id} — fresh token generated (old token no longer fires).");
            println!();
            print_entry_human(&entry, true);
            0
        }
        Ok(None) => {
            if json {
                #[derive(serde::Serialize)]
                struct RotateMiss<'a> {
                    id: &'a str,
                    rotated: bool,
                }
                if !write_json_stdout(
                    &RotateMiss { id, rotated: false },
                    "tirith canary rotate: failed to write JSON output",
                ) {
                    return 2;
                }
            } else {
                eprintln!("tirith canary rotate: no canary with id '{id}'");
            }
            1
        }
        Err(e) => {
            // Mirror `create` / command-card sign (CodeRabbit R13c): a normal
            // operation failure (store read-modify-write error) is the semantic
            // exit 1; only a broken-pipe JSON write — where the error never reached
            // the consumer — is the write-failure exit 2.
            if !emit_error(json, "tirith canary rotate", &e.to_string()) {
                return 2;
            }
            1
        }
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        "y"
    } else {
        "ies"
    }
}

/// Render the freshly-created canary: the token (so the user can plant it) plus
/// its id and a reminder of what it is.
fn print_created_human(entry: &CanaryEntry) {
    println!("Created {} canary (id {}).", entry.kind, entry.id);
    println!();
    println!("  token: {}", entry.token);
    println!();
    print_entry_human(entry, false);
    println!();
    println!("This token is CLEARLY SYNTHETIC (see `docs/canary-formats.md`) — it cannot be");
    println!("mistaken for a real third-party credential. Plant it where it should never be");
    println!("read (a decoy ~/.aws/credentials, a fake .env, a bait repo line). A later");
    println!("command, paste, or inspected tool output containing it fires CanaryTokenTouched.");
    if entry.callback_url.is_some() {
        println!();
        println!("On detection, a best-effort POST of {{kind, detected_at, context}} (NEVER the");
        println!("token value) is sent to your callback URL. Failures are logged, never block.");
    }
}

/// Render one canary entry as indented human output. `show_token` controls
/// whether the token value is printed (true for create/list/rotate where the
/// user needs it; false for the metadata recap inside `create`).
fn print_entry_human(entry: &CanaryEntry, show_token: bool) {
    println!("  id:         {}", entry.id);
    println!("    kind:       {}", entry.kind);
    if show_token {
        println!("    token:      {}", entry.token);
    }
    println!("    created_at: {}", entry.created_at);
    match &entry.callback_url {
        Some(url) => println!("    callback:   {url} (opt-in, user-self-hosted)"),
        None => println!("    callback:   none (local-only)"),
    }
}

fn print_empty_help() {
    println!("No canaries registered.");
    println!();
    println!("Create one and plant it as bait:");
    println!("  tirith canary create aws-like");
    println!("  tirith canary create github-like --callback-url https://my-host.example/hit");
    println!();
    println!("Supported kinds: {}", CanaryKind::all().join(", "));
}
