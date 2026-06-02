//! M11 ch3 — `tirith canary create|status|list|prune|rotate` (D3).
//!
//! Thin presenter over [`tirith_core::canary`] (the store, token generation,
//! and detection live in the library). A canary is a clearly-fake
//! secret-shaped token planted as bait; when it later appears in a command,
//! paste, or tool output the engine fires `CanaryTokenTouched` (High).
//!
//! D3 local-first: a canary is local-only by default (finding + audit log, no
//! phone-home). `--callback-url <url>` opts into a best-effort POST of
//! `{kind, detected_at, context}` (NEVER the token) to a URL YOU self-host;
//! there is no tirith-operated endpoint.

use tirith_core::canary::{self, CanaryEntry, CanaryKind};

use super::{confirm, write_json_stdout};

/// Emit an operator error as `{"error": ...}` JSON on stdout (`--json`) or a
/// human stderr line, keeping `--json` surfaces parseable on validation
/// failures. Mirrors `cli::command_card::emit_error`. Returns `false` when the
/// JSON write itself failed (broken pipe), so a caller can surface that instead
/// of a semantic exit with no JSON (CodeRabbit R8 #3); human mode always `true`.
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
        // Route through the bool to keep the broken-pipe path explicit.
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

    // Reject a non-http(s) callback URL early (reachability is not checked — it's
    // the user's self-hosted endpoint, contacted only on detection). Trim before
    // persisting so CLI whitespace never lands in the store.
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
            // Broken-pipe JSON write → write-failure exit 2 (not semantic 1 with
            // no output); mirrors command-card sign.
            if !emit_error(json, "tirith canary create", &e.to_string()) {
                return 2;
            }
            1
        }
    }
}

/// `tirith canary list` — print every recorded canary. The token VALUE is shown
/// so the user can plant it (it lives in a local 0600 store either way).
pub fn list(json: bool) -> i32 {
    // Completeness-aware: a partial read (FIFO/device, mid-file fault) would be
    // hidden by lenient `canary::list()`, so warn rather than show it as whole.
    let (entries, complete) = canary::list_complete();
    if !complete {
        // A partial JSON list must not look authoritative to a stdout-only
        // consumer, so FAIL (CodeRabbit R13f); the human path warns + shows it.
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

/// `tirith canary status` — a compact summary (counts + store path), never
/// token values.
pub fn status(json: bool) -> i32 {
    // Completeness-aware (see `list`): never report a partial store as authoritative.
    let (entries, complete) = canary::list_complete();
    if !complete {
        // JSON must not report partial counts as authoritative (R13f); fail.
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
    // Completeness-aware (CodeRabbit R17 #2): only treat "id absent" as a genuine
    // no-op when the store read to COMPLETION, else fall through to strict
    // `prune_at` (which reports the real read failure) instead of a false exit 0.
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

    // Confirm only with a concrete entry to remove; on an incomplete read skip
    // the prompt and let `prune_at` surface the failure.
    if existing.is_some() && !json && !confirm(&format!("Prune canary {id}?"), yes) {
        println!("Aborted — canary left in place.");
        return 0;
    }
    // JSON mode requires --yes (no prompt on a machine-readable surface).
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
                // Mirror JSON `pruned: false`: a concurrent prune (or unknown id)
                // removed nothing between the pre-check and `prune`.
                println!("No canary with id '{id}' — nothing to prune.");
            } else {
                println!("Pruned canary {id} ({removed} entr{}).", plural(removed));
            }
            0
        }
        Err(e) => {
            // R13c: a store read-modify-write error is semantic exit 1; only a
            // broken-pipe JSON write is the write-failure exit 2.
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

/// `tirith canary rotate <id>` — fresh token of the same kind, preserving id +
/// callback URL. The old token stops firing; the new one fires going forward.
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
            // R13c: a store read-modify-write error is semantic exit 1; only a
            // broken-pipe JSON write is the write-failure exit 2.
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

/// Render a freshly-created canary: the token (to plant) plus id and a reminder.
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

/// Render one canary entry as indented human output. `show_token` prints the
/// token value (true for create/list/rotate; false for the `create` recap).
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
