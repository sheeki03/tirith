//! M13 ch5 — `tirith ai scan|diff|quarantine|explain-config|snapshot`.
//!
//! AI-config drift + risk surface for a repository an AI coding agent operates
//! in. Five actions:
//!
//!  - `scan` — run the AI-config subset of the shipping scan engine (the
//!    `ai-agent-repo` profile) over the repo's AI-config files. Reuses
//!    [`crate::cli::scan::run`] — no scan engine is duplicated here.
//!  - `diff` — compare each current AI-config file to the last-known-safe
//!    snapshot at `state_dir()/ai_config_snapshot.json` and report added /
//!    removed instructions plus the M13 ch5 `AiConfig*` findings (produced by
//!    [`tirith_core::rules::aifile::diff_findings`]).
//!  - `quarantine <file>` — **v1 default is COPY, not move**: copy the file to
//!    `~/.cache/tirith/quarantine/<ts>-<sha256>-<basename>`, leaving the
//!    original UNTOUCHED, and print the restore command. `--move` opts into the
//!    destructive variant (with a confirmation prompt unless `--yes`).
//!  - `explain-config <file>` — identify which AI tool a config file configures
//!    and print what capabilities / risks its content grants.
//!  - `snapshot [--update]` — show the current snapshot state, or (`--update`)
//!    re-scan + record a fresh snapshot (refusing to bless a state with High+
//!    issues unless forced).
//!
//! The snapshot store and the diff / risk detection live in the library
//! (`tirith_core::rules::aifile`, `tirith_core::scan`); this module is the CLI
//! presenter + the quarantine filesystem op.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use tirith_core::policy::state_dir;
use tirith_core::rules::aifile;
use tirith_core::verdict::Severity;

use super::{confirm, write_file_atomic, write_json_stdout};

// ===========================================================================
// snapshot store
// ===========================================================================

/// One file's recorded content in the last-known-safe snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotEntry {
    /// SHA-256 (hex) of the recorded content — a quick changed/unchanged check.
    sha256: String,
    /// The full recorded content, so `ai diff` can compute a line-level diff.
    content: String,
}

/// The last-known-safe snapshot of a repo's AI-config files.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Snapshot {
    /// RFC3339 timestamp the snapshot was recorded.
    updated_at: String,
    /// The repository root the snapshot was taken against (canonical display
    /// path). `ai diff` / `ai snapshot` refuse to reuse a snapshot whose
    /// recorded root does not match the current repo root, so a stale snapshot
    /// from a DIFFERENT repo can never be silently compared against this one
    /// (M13 PR #132 finding I).
    root: String,
    /// Map of `root`-relative file path → recorded entry. A `BTreeMap` so the
    /// on-disk JSON is deterministic (stable key order).
    files: BTreeMap<String, SnapshotEntry>,
}

/// Per-repo snapshot path: `state_dir()/ai_config_snapshot-<hash>.json`, where
/// `<hash>` is derived from the canonical repo root. Making the path
/// repo-specific stops `tirith ai snapshot --update` in repo B from overwriting
/// repo A's baseline, and stops `ai diff` from comparing against an unrelated
/// snapshot (M13 PR #132 finding I).
fn snapshot_path(root: &Path) -> Option<PathBuf> {
    let hash = root_hash(root);
    state_dir().map(|d| d.join(format!("ai_config_snapshot-{hash}.json")))
}

/// A short, filesystem-safe hex digest of the canonical repo root, used only to
/// disambiguate per-repo snapshot files (not a security boundary — the recorded
/// `root` inside the snapshot is the authoritative match check).
fn root_hash(root: &Path) -> String {
    let sha = tirith_core::clipboard::content_sha256_hex(root.to_string_lossy().as_bytes());
    sha[..sha.len().min(16)].to_string()
}

/// Load the snapshot for `root`, returning `Ok(None)` when no snapshot file
/// exists yet. A snapshot whose recorded `root` differs from `root` is treated
/// as absent (`Ok(None)`): it belongs to a different repo (e.g. a hash collision
/// or a relocated tree) and must not be reused — the caller will report "no
/// snapshot" and prompt a fresh `--update` rather than diffing against a
/// foreign baseline (M13 PR #132 finding I).
fn load_snapshot(root: &Path) -> std::io::Result<Option<Snapshot>> {
    let Some(path) = snapshot_path(root) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot determine tirith state directory",
        ));
    };
    match std::fs::read(&path) {
        Ok(bytes) => {
            let snap: Snapshot = serde_json::from_slice(&bytes).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("snapshot at {} is corrupt: {e}", path.display()),
                )
            })?;
            // Defense in depth against a hash collision / a stale file whose
            // recorded root no longer matches: refuse to reuse it.
            if snap.root != root.display().to_string() {
                return Ok(None);
            }
            Ok(Some(snap))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Emit an operator error as `{"error": ...}` JSON on stdout in `--json` mode, or
/// a human stderr line otherwise. Mirrors `cli::canary::emit_error`. Returns
/// `false` only when the JSON write itself failed (broken pipe).
fn emit_error(json: bool, ctx: &str, msg: &str) -> bool {
    if json {
        let v = serde_json::json!({ "error": msg });
        write_json_stdout(&v, &format!("{ctx}: failed to write JSON output"))
    } else {
        eprintln!("{ctx}: {msg}");
        true
    }
}

/// Resolve the CANONICAL repo root to scan / snapshot. `tirith ai` is
/// repo-scoped: we walk up to the `.git` boundary (the same discovery
/// `tirith onboard` / `policy` use) and fall back to the current directory
/// outside a git repo. The result is canonicalized so the per-repo snapshot
/// path and the recorded `root` are stable regardless of how the user `cd`'d in
/// (symlinks, `..`, `/var` → `/private/var` on macOS). Canonicalization is
/// best-effort: if it fails (e.g. the dir was removed), the un-canonicalized
/// path is used.
fn repo_root() -> PathBuf {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let root = tirith_core::policy::find_repo_root(Some(&cwd.to_string_lossy())).unwrap_or(cwd);
    std::fs::canonicalize(&root).unwrap_or(root)
}

/// `root`-relative display key for a file, falling back to the file's own
/// display path when it is not under `root`.
fn rel_key(root: &Path, file: &Path) -> String {
    file.strip_prefix(root)
        .unwrap_or(file)
        .to_string_lossy()
        .replace('\\', "/")
}

// ===========================================================================
// `tirith ai scan`
// ===========================================================================

/// `tirith ai scan` — run the `ai-agent-repo` scan profile over the repo's
/// AI-config files. This is a thin wrapper over `tirith scan --profile
/// ai-agent-repo`: the AI-config subset of the shipping scan engine, no
/// duplicated detection. We scope the scan to the repo root and let the profile
/// (together with the engine's own AI-file rules — `agent_instruction_hidden`,
/// the config / notebook / svg checks) decide findings.
pub fn scan(json: bool) -> i32 {
    let root = repo_root();
    // Reuse the shipping scan command with the `ai-agent-repo` built-in profile.
    // `fail_on` is set by the profile; we pass the same default the bare `scan`
    // uses so the profile's `fail_on` (high) takes effect.
    super::scan::run(
        Some(&root.to_string_lossy()),
        None,   // file
        false,  // stdin
        false,  // ci
        "high", // fail_on (the profile overrides to its own default)
        json,   // json
        false,  // sarif
        &[],    // ignore
        &[],    // include
        &[],    // exclude
        Some("ai-agent-repo"),
    )
}

// ===========================================================================
// `tirith ai diff`
// ===========================================================================

/// One file's diff result for JSON output.
#[derive(Debug, Serialize)]
struct FileDiff {
    path: String,
    status: &'static str,
    added_instructions: Vec<String>,
    removed_instructions: Vec<String>,
    findings: Vec<tirith_core::verdict::Finding>,
}

/// `tirith ai diff` — compare each current AI-config file to the last-known-safe
/// snapshot and report added / removed instruction lines plus any `AiConfig*`
/// findings. With no snapshot, says so and suggests `tirith ai snapshot
/// --update`.
pub fn diff(json: bool) -> i32 {
    let root = repo_root();
    let snapshot = match load_snapshot(&root) {
        Ok(Some(s)) => s,
        Ok(None) => {
            if json {
                let v = serde_json::json!({
                    "snapshot": serde_json::Value::Null,
                    "message": "no AI-config snapshot recorded yet",
                    "hint": "run `tirith ai snapshot --update` to record the current state",
                });
                if !write_json_stdout(&v, "tirith ai diff: failed to write JSON output") {
                    return 2;
                }
            } else {
                println!("No AI-config snapshot recorded yet.");
                println!("Record the current (trusted) state with:");
                println!("  tirith ai snapshot --update");
            }
            return 0;
        }
        Err(e) => {
            if !emit_error(json, "tirith ai diff", &e.to_string()) {
                return 2;
            }
            return 1;
        }
    };

    let current_files = tirith_core::scan::collect_ai_config_files(&root);

    // Build the union of file keys: those in the snapshot and those on disk now.
    let mut keys: Vec<String> = snapshot.files.keys().cloned().collect();
    let mut current_by_key: BTreeMap<String, PathBuf> = BTreeMap::new();
    for f in &current_files {
        let key = rel_key(&root, f);
        current_by_key.insert(key.clone(), f.clone());
        if !snapshot.files.contains_key(&key) {
            keys.push(key);
        }
    }
    keys.sort();
    keys.dedup();

    let mut diffs: Vec<FileDiff> = Vec::new();
    let mut any_finding = false;

    for key in &keys {
        // Compute PRESENCE on each side first. "missing" and "empty" are
        // DIFFERENT states: a file may be absent from the snapshot yet present
        // (even empty) on disk, or vice-versa. Collapsing them — as a bare
        // `old == new` check does, since both render as "" — would hide the
        // creation/deletion of an empty AI-config (CodeRabbit M13 PR #132 R3-6).
        let existed_before = snapshot.files.contains_key(key);
        let exists_now = current_by_key.contains_key(key);

        let old = snapshot
            .files
            .get(key)
            .map(|e| e.content.clone())
            .unwrap_or_default();
        let new = match current_by_key.get(key) {
            // A file present on disk that we cannot read (I/O error or over the
            // size cap) must NOT be treated as empty — that would fabricate a
            // "removed"/"modified" diff for a file that is simply unreadable.
            // Surface the error and exit non-zero instead (M13 PR #132 finding J).
            Some(path) => match read_text(path) {
                Ok(content) => content,
                Err(e) => {
                    if !emit_error(
                        json,
                        "tirith ai diff",
                        &format!("cannot read {}: {e}", path.display()),
                    ) {
                        return 2;
                    }
                    return 1;
                }
            },
            None => String::new(), // present in snapshot, gone on disk
        };

        // Skip ONLY when the file exists on BOTH sides and its content is
        // unchanged. An added file (absent before, present now) or a removed
        // file (present before, absent now) is always reported — even when its
        // content is empty on both notional sides.
        if existed_before && exists_now && old == new {
            continue; // unchanged — skip
        }

        let status = if existed_before && exists_now {
            "modified"
        } else if exists_now {
            "added"
        } else {
            "removed"
        };

        let added = added_removed(&old, &new);
        let findings = aifile::diff_findings(&old, &new, key);
        if !findings.is_empty() {
            any_finding = true;
        }
        diffs.push(FileDiff {
            path: key.clone(),
            status,
            added_instructions: added.0,
            removed_instructions: added.1,
            findings,
        });
    }

    if json {
        let v = serde_json::json!({
            "snapshot_updated_at": snapshot.updated_at,
            "root": snapshot.root,
            "changed_files": diffs,
        });
        if !write_json_stdout(&v, "tirith ai diff: failed to write JSON output") {
            return 2;
        }
        return if any_finding { 1 } else { 0 };
    }

    if diffs.is_empty() {
        println!("No AI-config drift: every tracked file matches the snapshot.");
        println!("(snapshot recorded {}).", snapshot.updated_at);
        return 0;
    }

    println!(
        "AI-config drift vs snapshot ({} recorded):",
        snapshot.updated_at
    );
    println!();
    for d in &diffs {
        // Every displayed field below is AI-config-derived (path basenames, the
        // instruction line bodies, finding titles) and is sanitized so a hostile
        // config cannot inject terminal escapes into our output (R20).
        println!("  {} [{}]", sanitize_display(&d.path), d.status);
        for line in &d.added_instructions {
            println!("    + {}", sanitize_display(line));
        }
        for line in &d.removed_instructions {
            println!("    - {}", sanitize_display(line));
        }
        for f in &d.findings {
            println!(
                "    !! {} ({}): {}",
                f.rule_id,
                f.severity,
                sanitize_display(&f.title)
            );
        }
        println!();
    }
    if any_finding {
        println!("One or more changes tripped an AI-config drift rule (above). Review them,");
        println!("then re-snapshot once trusted: `tirith ai snapshot --update`.");
        return 1;
    }
    println!("Changes detected but no drift rule fired. Re-snapshot once trusted:");
    println!("  tirith ai snapshot --update");
    0
}

/// Compute the added / removed instruction-shaped lines between `old` and `new`
/// for human / JSON display. Uses the same normalization the diff producers use
/// (via a public re-derivation): a line present in one side's normalized set but
/// not the other. Whitespace-only churn is invisible. Returns `(added, removed)`.
fn added_removed(old: &str, new: &str) -> (Vec<String>, Vec<String>) {
    use std::collections::HashMap;
    let norm = |s: &str| -> Vec<String> {
        s.lines()
            .map(|l| l.trim_end().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    };
    let old_lines = norm(old);
    let new_lines = norm(new);
    // Count-based diff: a line appearing more often on one side than the other
    // contributes that many added/removed entries. A pure HashSet under-reports
    // a line duplicated on one side but single on the other.
    let mut old_counts: HashMap<&str, usize> = HashMap::new();
    for l in &old_lines {
        *old_counts.entry(l.as_str()).or_insert(0) += 1;
    }
    let mut new_counts: HashMap<&str, usize> = HashMap::new();
    for l in &new_lines {
        *new_counts.entry(l.as_str()).or_insert(0) += 1;
    }
    // Added: for each new line, emit (new_count - old_count) copies, in first-seen
    // order. Tracking how many of each line we have already emitted keeps the
    // output stable and avoids re-emitting on later occurrences of the same line.
    let mut emitted_added: HashMap<&str, usize> = HashMap::new();
    let mut added: Vec<String> = Vec::new();
    for l in &new_lines {
        let surplus = new_counts
            .get(l.as_str())
            .copied()
            .unwrap_or(0)
            .saturating_sub(old_counts.get(l.as_str()).copied().unwrap_or(0));
        let already = emitted_added.entry(l.as_str()).or_insert(0);
        if *already < surplus {
            *already += 1;
            added.push(truncate_line(l));
        }
    }
    // Removed: symmetric — for each old line, emit (old_count - new_count) copies.
    let mut emitted_removed: HashMap<&str, usize> = HashMap::new();
    let mut removed: Vec<String> = Vec::new();
    for l in &old_lines {
        let surplus = old_counts
            .get(l.as_str())
            .copied()
            .unwrap_or(0)
            .saturating_sub(new_counts.get(l.as_str()).copied().unwrap_or(0));
        let already = emitted_removed.entry(l.as_str()).or_insert(0);
        if *already < surplus {
            *already += 1;
            removed.push(truncate_line(l));
        }
    }
    (added, removed)
}

/// Truncate a displayed diff line so a hostile long line cannot flood output.
fn truncate_line(s: &str) -> String {
    const MAX: usize = 200;
    if s.chars().count() <= MAX {
        return s.to_string();
    }
    let cut: String = s.chars().take(MAX).collect();
    format!("{cut}…")
}

/// Neutralize one untrusted string before printing it to the terminal in HUMAN
/// mode (CodeRabbit M13 PR #132 R20 — raw terminal passthrough).
///
/// Everything `tirith ai` displays in human mode — diff line bodies, file paths
/// (whose basenames are attacker-controlled), finding titles, `explain-config`
/// risk detail — is derived from the very AI-config files tirith analyzes. A
/// malicious config containing ANSI/CSI/OSC escape or other control sequences
/// could otherwise spoof or rewrite terminal output the moment we `println!` it.
/// Run every such field through tirith's own output sanitizer — the same
/// `output_filter` the MCP gateway and `tirith paste` apply — which strips
/// ANSI/OSC/APC/DCS escape sequences, bare CR, other C0 controls (except `\t`),
/// DEL, and zero-width characters (tirith must never itself emit the terminal
/// injection it exists to detect). Tabs/newlines that the sanitizer legitimately
/// keeps are then flattened to spaces so a single display field stays on one
/// line (callers already control line structure).
fn sanitize_display(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    tirith_core::mcp::output_filter::sanitize_text_into(s.as_bytes(), &mut out);
    let cleaned = String::from_utf8(out).unwrap_or_default();
    cleaned
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect()
}

/// The per-file read cap (10 MiB), matching the scan engine's per-file cap so a
/// pathological file cannot exhaust memory. Shared by every read path in this
/// module ([`read_text`], [`read_capped`]) so the bound is enforced uniformly.
const READ_MAX_BYTES: usize = 10 * 1024 * 1024; // 10 MiB

/// Read a file's RAW bytes with the module's [`READ_MAX_BYTES`] cap.
///
/// The cap is enforced by reading through a `take`-bounded handle rather than
/// stat-then-read: a `metadata().len()` check is a TOCTOU race — the file can
/// grow between the stat and the read, so a stat-gated `std::fs::read` could
/// still slurp an arbitrarily large file. Reading at most `MAX_BYTES + 1` bytes
/// and rejecting when the buffer exceeds `MAX_BYTES` bounds memory regardless of
/// concurrent growth.
fn read_capped(path: &Path) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    // Read one byte past the cap so an exactly-`MAX_BYTES` file is accepted while
    // anything larger is detectable.
    file.take(READ_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > READ_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is larger than 10 MiB; skipping", path.display()),
        ));
    }
    Ok(bytes)
}

/// Read a file as UTF-8 (lossy), with the module's [`READ_MAX_BYTES`] cap.
/// Thin wrapper over [`read_capped`].
fn read_text(path: &Path) -> std::io::Result<String> {
    Ok(String::from_utf8_lossy(&read_capped(path)?).into_owned())
}

// ===========================================================================
// `tirith ai quarantine`
// ===========================================================================

/// `tirith ai quarantine <file>` — isolate a (suspected-poisoned) AI-config
/// file. **v1 DEFAULT IS COPY**: the file is COPIED to
/// `~/.cache/tirith/quarantine/<ts>-<sha256>-<basename>` and the ORIGINAL IS
/// LEFT UNTOUCHED; the restore command is printed. `--move` opts into the
/// destructive variant (copy, then remove the original) — which prompts for
/// confirmation unless `--yes`, and refuses non-interactively without `--yes`.
pub fn quarantine(file: &str, do_move: bool, yes: bool, json: bool) -> i32 {
    let src = PathBuf::from(file);
    // Capped read (R15-ai.rs:483): reuse the module's `READ_MAX_BYTES`-bounded
    // reader rather than `std::fs::read`, so a huge AI-config file cannot force a
    // full-file allocation before any validation. The sha below is computed from
    // these capped bytes.
    let content = match read_capped(&src) {
        Ok(c) => c,
        Err(e) => {
            if !emit_error(
                json,
                "tirith ai quarantine",
                &format!("cannot read {}: {e}", src.display()),
            ) {
                return 2;
            }
            return 1;
        }
    };

    // PROVISIONAL hash, computed from the bytes we just read. For the atomic
    // `rename` move below this may go stale if the file changes between this read
    // and the rename (the rename moves whatever is on disk at that instant), so
    // after a successful move we RECOMPUTE from `dest` and correct the name +
    // emitted sha (R15-ai.rs:516). `sha` is therefore `mut`.
    let mut sha = tirith_core::clipboard::content_sha256_hex(&content);
    let short_sha = sha[..sha.len().min(16)].to_string();
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let basename = src
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        // Defensive: a basename can never carry a path separator after
        // `file_name()`, but sanitize anyway so the quarantine name is flat.
        .replace(['/', '\\'], "_");

    let Some(qdir) = quarantine_dir() else {
        if !emit_error(
            json,
            "tirith ai quarantine",
            "cannot determine the cache directory for the quarantine store",
        ) {
            return 2;
        }
        return 1;
    };
    // Create the quarantine dir with restrictive perms (0700 on Unix) — it holds
    // copies of potentially-sensitive config.
    if let Err(e) = create_quarantine_dir(&qdir) {
        if !emit_error(
            json,
            "tirith ai quarantine",
            &format!("cannot create quarantine dir {}: {e}", qdir.display()),
        ) {
            return 2;
        }
        return 1;
    }

    let mut dest = qdir.join(format!("{ts}-{short_sha}-{basename}"));

    // --move requires confirmation (it deletes the original). Decide this BEFORE
    // copying so a refused move does not leave a stray quarantine copy.
    if do_move
        && !confirm(
            &format!(
                "Move (DELETE original) {} into quarantine? The original will be removed.",
                src.display()
            ),
            yes,
        )
    {
        // `confirm` returns false in TWO distinct situations and we must NOT
        // conflate them (CodeRabbit M13 PR #132 R3-7 / R20):
        //   1. We COULD prompt (an interactive answer was possible) and the
        //      operator answered "no" → an intentional abort; the original is kept
        //      and exit 0 is success.
        //   2. We COULD NOT prompt and `--yes` was not given → nothing was
        //      confirmed; returning 0 here would make a no-op look successful to a
        //      non-interactive caller. Fail non-zero (exit 2), matching the JSON
        //      branch.
        // `--yes` short-circuits `confirm` to true, so reaching this block always
        // means `--yes` was absent; the only question is whether an interactive
        // confirmation was actually possible.
        let could_prompt = confirmation_possible();
        if json || !could_prompt {
            let _ = emit_error(
                json,
                "tirith ai quarantine",
                "--move deletes the original; pass --yes to confirm (refused without a TTY)",
            );
            return 2;
        }
        // Interactive refusal: the operator deliberately declined.
        println!("Aborted — original left in place (nothing was moved).");
        return 0;
    }

    let mut moved = false;
    if do_move {
        // DESTRUCTIVE variant. Prefer an ATOMIC `rename` so there is NO
        // read→write→delete window (CodeRabbit M13 PR #132 R10-4): a concurrent
        // edit between our earlier `read` and a later `remove_file` would
        // otherwise discard the newer bytes (quarantine keeps the stale copy we
        // read; the original is gone). `rename` moves the inode atomically, so
        // whatever bytes the file holds at the instant of the move land in
        // quarantine and the source vanishes in the same operation.
        match std::fs::rename(&src, &dest) {
            Ok(()) => {
                moved = true;
            }
            Err(e) if is_cross_device(&e) => {
                // `rename` cannot cross filesystems (e.g. quarantine on a
                // different mount than the source). Fall back to copy-then-delete,
                // but CLOSE the TOCTOU: write the bytes we already read, then
                // re-read + re-hash the source IMMEDIATELY before deleting it, and
                // ABORT the delete if it changed since our initial read.
                if let Err(e) = write_file_atomic(&dest, &content, true) {
                    if !emit_error(
                        json,
                        "tirith ai quarantine",
                        &format!("failed to write quarantine copy {}: {e}", dest.display()),
                    ) {
                        return 2;
                    }
                    return 1;
                }
                // Re-read the source as late as possible (just before the delete)
                // and compare its hash to the bytes we quarantined. A mismatch
                // means the file was edited after our first read; deleting now
                // would lose the newer content, so we keep the original and fail.
                // Capped read for the same memory-bound reason as the initial read.
                match read_capped(&src) {
                    Ok(current) => {
                        let current_sha = tirith_core::clipboard::content_sha256_hex(&current);
                        if current_sha != sha {
                            if !emit_error(
                                json,
                                "tirith ai quarantine",
                                &format!(
                                    "{} changed on disk after it was read; refusing to delete the \
                                     original (the quarantine copy at {} is now stale). Re-run to \
                                     quarantine the current contents.",
                                    src.display(),
                                    dest.display()
                                ),
                            ) {
                                return 2;
                            }
                            return 1;
                        }
                    }
                    Err(e) => {
                        // Could not re-read to confirm the bytes are unchanged —
                        // do NOT delete blindly. The copy exists; the original
                        // stays. Exit non-zero, not a silent success.
                        if !emit_error(
                            json,
                            "tirith ai quarantine",
                            &format!(
                                "copied to {} but could not re-read {} to confirm it was unchanged \
                                 before deleting; left the original in place: {e}",
                                dest.display(),
                                src.display()
                            ),
                        ) {
                            return 2;
                        }
                        return 1;
                    }
                }
                if let Err(e) = std::fs::remove_file(&src) {
                    // The copy succeeded but the original could not be removed —
                    // report honestly: the file IS quarantined (a copy exists) but
                    // the original remains. Exit 1, not a silent success.
                    if !emit_error(
                        json,
                        "tirith ai quarantine",
                        &format!(
                            "copied to {} but could not remove the original {}: {e}",
                            dest.display(),
                            src.display()
                        ),
                    ) {
                        return 2;
                    }
                    return 1;
                }
                moved = true;
            }
            Err(e) => {
                // A non-cross-device rename failure (permissions, source vanished,
                // …). Report it; the original is untouched and no copy was made.
                if !emit_error(
                    json,
                    "tirith ai quarantine",
                    &format!(
                        "failed to move {} into quarantine at {}: {e}",
                        src.display(),
                        dest.display()
                    ),
                ) {
                    return 2;
                }
                return 1;
            }
        }
    } else {
        // COPY default (round-1, non-`--move`): write the bytes into quarantine
        // atomically and leave the original UNTOUCHED. No delete window exists
        // here, so this path is unaffected by the TOCTOU fix above.
        if let Err(e) = write_file_atomic(&dest, &content, true) {
            if !emit_error(
                json,
                "tirith ai quarantine",
                &format!("failed to write quarantine copy {}: {e}", dest.display()),
            ) {
                return 2;
            }
            return 1;
        }
    }

    // R15-ai.rs:516 — after a successful MOVE, the file living at `dest` is
    // whatever `std::fs::rename` moved at the instant of the move, which (on the
    // atomic-rename branch) may differ from the bytes we read up front. The
    // provisional `sha`/`short_sha`/`dest` then encode the OLD hash while the
    // quarantined file holds newer bytes. Re-read `dest` (capped), recompute the
    // hash, and — if it differs from the provisional short hash — atomically
    // rename WITHIN the quarantine dir to the corrected `<ts>-<new_short>-<base>`
    // name so the filename and the emitted `sha256` describe the bytes actually
    // at `dest`. The cross-device fallback already proved `dest == sha` (it
    // refused to delete otherwise), so for that branch this is a no-op confirm.
    if moved {
        match read_capped(&dest) {
            Ok(moved_bytes) => {
                let actual_sha = tirith_core::clipboard::content_sha256_hex(&moved_bytes);
                if actual_sha != sha {
                    let new_short = actual_sha[..actual_sha.len().min(16)].to_string();
                    let corrected = qdir.join(format!("{ts}-{new_short}-{basename}"));
                    // Atomic in-quarantine rename to the recomputed-hash name.
                    // Both paths share `qdir`, so this never crosses devices.
                    if corrected != dest {
                        if let Err(e) = std::fs::rename(&dest, &corrected) {
                            if !emit_error(
                                json,
                                "tirith ai quarantine",
                                &format!(
                                    "moved {} to {} but failed to rename it to its \
                                     recomputed-hash name {}: {e}",
                                    src.display(),
                                    dest.display(),
                                    corrected.display()
                                ),
                            ) {
                                return 2;
                            }
                            return 1;
                        }
                        dest = corrected;
                    }
                    sha = actual_sha;
                }
            }
            Err(e) => {
                // The move succeeded but we cannot re-read the quarantined file to
                // confirm/correct its hash. Emitting the provisional (possibly
                // stale) sha would be dishonest, so fail rather than advertise an
                // unverified hash. The original is already gone (moved into `dest`).
                if !emit_error(
                    json,
                    "tirith ai quarantine",
                    &format!(
                        "moved {} into quarantine at {} but could not re-read it to \
                         verify its sha256: {e}",
                        src.display(),
                        dest.display()
                    ),
                ) {
                    return 2;
                }
                return 1;
            }
        }
    }

    // Copy the quarantine copy (dest) back to the original location (src).
    let restore_cmd = restore_command(&dest, &src);

    if json {
        #[derive(Serialize)]
        struct Out<'a> {
            original: String,
            quarantined_to: String,
            sha256: &'a str,
            moved: bool,
            original_untouched: bool,
            restore_command: String,
        }
        let out = Out {
            original: src.display().to_string(),
            quarantined_to: dest.display().to_string(),
            sha256: &sha,
            moved,
            original_untouched: !moved,
            restore_command: restore_cmd,
        };
        if !write_json_stdout(&out, "tirith ai quarantine: failed to write JSON output") {
            return 2;
        }
        return 0;
    }

    // `src` is a user-supplied arg and `dest` embeds the (attacker-controllable)
    // source basename, so sanitize both before printing (R20). `restore_cmd` is
    // already shell-quoted by `restore_command`, which neutralizes the same
    // bytes for shell-paste safety.
    let src_disp = sanitize_display(&src.display().to_string());
    let dest_disp = sanitize_display(&dest.display().to_string());
    if moved {
        println!("Moved {src_disp} into quarantine.");
        println!("  quarantine copy: {dest_disp}");
        println!("  the original was REMOVED.");
    } else {
        println!("Copied {src_disp} into quarantine (original UNTOUCHED).");
        println!("  quarantine copy: {dest_disp}");
    }
    println!();
    println!("Restore with:");
    println!("  {restore_cmd}");
    0
}

/// Whether an interactive confirmation could ACTUALLY have been obtained
/// (CodeRabbit M13 PR #132 R20 — wrong stream for the interactivity check).
///
/// [`super::confirm`] writes its prompt to **stderr** but reads the answer from
/// **stdin** (`std::io::stdin().read_line`). The decision of whether `confirm`'s
/// `false` means "operator declined" vs "no prompt was possible" must therefore
/// key off the stream the ANSWER comes from — stdin. We require BOTH: stdin a
/// TTY (an answer can be read) AND stderr a TTY (the prompt is visible). Keying
/// off stderr alone (the old bug) treated a stdin-piped/EOF run with a TTY
/// stderr as a deliberate "no" (exit 0), when in fact no confirmation was ever
/// possible — that case must fail non-zero instead.
fn confirmation_possible() -> bool {
    is_terminal::is_terminal(std::io::stdin()) && is_terminal::is_terminal(std::io::stderr())
}

/// Whether a `std::fs::rename` error means the source and destination are on
/// DIFFERENT filesystems (so an atomic rename is impossible and the caller must
/// fall back to copy-then-delete). We match the raw OS error code rather than
/// `ErrorKind::CrossesDevices` because that `ErrorKind` was only stabilized in
/// Rust 1.85 and this crate's MSRV is 1.83. `EXDEV` (18 on Linux/macOS) is the
/// POSIX cross-device code; `ERROR_NOT_SAME_DEVICE` (17) is the Windows
/// equivalent.
fn is_cross_device(err: &std::io::Error) -> bool {
    match err.raw_os_error() {
        #[cfg(unix)]
        Some(code) => code == libc::EXDEV,
        #[cfg(windows)]
        // ERROR_NOT_SAME_DEVICE = 17.
        Some(code) => code == 17,
        #[cfg(not(any(unix, windows)))]
        Some(_) => false,
        None => false,
    }
}

/// Quarantine store directory: `~/.cache/tirith/quarantine`.
fn quarantine_dir() -> Option<PathBuf> {
    cache_dir().map(|c| c.join("tirith").join("quarantine"))
}

/// The user's cache base dir (`$XDG_CACHE_HOME` or `~/.cache`), honoring an
/// empty `XDG_CACHE_HOME` as unset (matching shell `${VAR:-fallback}`).
fn cache_dir() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg));
        }
    }
    home::home_dir().map(|h| h.join(".cache"))
}

/// Create the quarantine directory with restrictive permissions (0700 on Unix).
fn create_quarantine_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Single-quote a path for the printed restore command so a path with spaces /
/// shell metacharacters round-trips. Embedded single quotes become `'\''`.
/// (Used by the POSIX [`restore_command`]; gated to non-Windows so the Windows
/// build doesn't warn it unused.)
#[cfg(not(windows))]
fn shell_quote(p: &Path) -> String {
    let s = p.to_string_lossy();
    if s.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b':' | b'@' | b',')
    }) {
        return s.into_owned();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Single-quote a path for a PowerShell literal string. PowerShell escapes an
/// embedded single quote by DOUBLING it (`'` → `''`); backslashes are literal
/// inside single quotes, so a Windows path round-trips as-is. Always quoted (no
/// bare-word shortcut) — `-LiteralPath` takes the value verbatim.
#[cfg(windows)]
fn powershell_quote(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy().replace('\'', "''"))
}

/// The shell command that restores a quarantined file by copying it back from
/// `from` (the quarantine copy) to `to` (the original location). OS-aware: a
/// POSIX `cp` on Unix, a PowerShell `Copy-Item -LiteralPath` on Windows (where
/// `cp` is not a native command and POSIX `'\''`-escaping is wrong). (CodeRabbit
/// M13 round-2 R7.)
#[cfg(not(windows))]
fn restore_command(from: &Path, to: &Path) -> String {
    // Insert the literal `--` before the path operands (R15-ai.rs:780). Without
    // it, `shell_quote` leaves a safe-looking dash-prefixed path bare (e.g.
    // `-backup/.cursorrules`), so `cp` would parse it as an OPTION instead of a
    // source/destination. `--` ends option parsing so any path is treated as an
    // operand.
    format!("cp -- {} {}", shell_quote(from), shell_quote(to))
}

#[cfg(windows)]
fn restore_command(from: &Path, to: &Path) -> String {
    format!(
        "Copy-Item -LiteralPath {} -Destination {}",
        powershell_quote(from),
        powershell_quote(to)
    )
}

// ===========================================================================
// `tirith ai explain-config`
// ===========================================================================

/// `tirith ai explain-config <file>` — identify which AI tool a config file
/// configures and print the capabilities / risks its content grants.
pub fn explain_config(file: &str, json: bool) -> i32 {
    let path = PathBuf::from(file);
    let content = match read_text(&path) {
        Ok(c) => c,
        Err(e) => {
            if !emit_error(
                json,
                "tirith ai explain-config",
                &format!("cannot read {}: {e}", path.display()),
            ) {
                return 2;
            }
            return 1;
        }
    };

    let tool = aifile::classify_tool(&path);
    let risks = aifile::explain_config_risks(&content, &path);

    if json {
        #[derive(Serialize)]
        struct RiskOut {
            id: &'static str,
            detail: String,
        }
        #[derive(Serialize)]
        struct Out {
            file: String,
            tool: Option<&'static str>,
            is_ai_config: bool,
            risks: Vec<RiskOut>,
        }
        let out = Out {
            file: path.display().to_string(),
            tool: tool.map(|t| t.label()),
            is_ai_config: tool.is_some(),
            risks: risks
                .iter()
                .map(|r| RiskOut {
                    id: r.id,
                    detail: r.detail.clone(),
                })
                .collect(),
        };
        if !write_json_stdout(
            &out,
            "tirith ai explain-config: failed to write JSON output",
        ) {
            return 2;
        }
        return 0;
    }

    // `path` is a user-supplied arg and `r.detail` embeds raw snippets lifted
    // from the (untrusted) config content, so both are sanitized before display
    // (R20). `t.label()` and `r.id` are fixed internal strings, left as-is.
    let display_path = sanitize_display(&path.display().to_string());
    match tool {
        Some(t) => println!("{display_path} configures {}.", t.label()),
        None => {
            println!(
                "{display_path} is not a recognised AI-config file — showing any content risks found."
            );
        }
    }
    println!();
    if risks.is_empty() {
        println!("No capability / risk signals found in this file's content.");
    } else {
        println!("Capabilities / risks this config grants or signals:");
        for r in &risks {
            println!("  - [{}] {}", r.id, sanitize_display(&r.detail));
        }
    }
    0
}

// ===========================================================================
// `tirith ai snapshot [--update]`
// ===========================================================================

/// `tirith ai snapshot` — show the current snapshot state (path, age, file
/// count). `--update` re-scans the AI-config files and records a fresh snapshot,
/// refusing to bless a state with High+ scan issues unless `force`.
pub fn snapshot(update: bool, force: bool, json: bool) -> i32 {
    if !update {
        return snapshot_status(json);
    }
    snapshot_update(force, json)
}

/// Show the current snapshot's metadata without modifying it.
fn snapshot_status(json: bool) -> i32 {
    let root = repo_root();
    let path_str = snapshot_path(&root)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<unresolved>".to_string());

    let snap = match load_snapshot(&root) {
        Ok(s) => s,
        Err(e) => {
            if !emit_error(json, "tirith ai snapshot", &e.to_string()) {
                return 2;
            }
            return 1;
        }
    };

    if json {
        let v = match &snap {
            Some(s) => serde_json::json!({
                "exists": true,
                "path": path_str,
                "updated_at": s.updated_at,
                "root": s.root,
                "file_count": s.files.len(),
            }),
            None => serde_json::json!({
                "exists": false,
                "path": path_str,
                "hint": "run `tirith ai snapshot --update` to record the current state",
            }),
        };
        if !write_json_stdout(&v, "tirith ai snapshot: failed to write JSON output") {
            return 2;
        }
        return 0;
    }

    match snap {
        Some(s) => {
            // `root` is read back from the on-disk snapshot (a repo path); sanitize
            // it before display for the same reason as the other AI-derived fields.
            println!("AI-config snapshot:");
            println!("  path:       {path_str}");
            println!("  recorded:   {}", s.updated_at);
            println!("  root:       {}", sanitize_display(&s.root));
            println!("  files:      {}", s.files.len());
            println!();
            println!("Compare the current tree against it with `tirith ai diff`.");
        }
        None => {
            println!("No AI-config snapshot recorded yet.");
            println!("  path: {path_str}");
            println!();
            println!("Record the current (trusted) state with:");
            println!("  tirith ai snapshot --update");
        }
    }
    0
}

/// Exit-code policy for an un-scannable file during `snapshot --update`
/// (CodeRabbit M13 PR #132 R7-3). A `None` scan means the file could not be
/// analyzed, so it must never be recorded; the whole update aborts non-zero.
/// Mirrors the surrounding `emit_error` convention: emit the operator error,
/// then return 2 when the `--json` write itself failed (broken pipe), else 1.
fn snapshot_scan_failed_code(json: bool, file: &Path) -> i32 {
    if !emit_error(
        json,
        "tirith ai snapshot",
        &format!(
            "failed to scan {}: file could not be analyzed",
            file.display()
        ),
    ) {
        return 2;
    }
    1
}

/// Re-scan the AI-config files and record a fresh snapshot.
fn snapshot_update(force: bool, json: bool) -> i32 {
    let root = repo_root();
    let files = tirith_core::scan::collect_ai_config_files(&root);

    // Refuse to bless a compromised state: scan each AI-config file and abort if
    // any High+ finding is present (unless --force). This reuses the shipping
    // single-file scan engine (`scan_single_file`), the same detection
    // `tirith scan` uses — no new detection here.
    let mut blocking: Vec<(String, Severity, String)> = Vec::new();
    let mut entries: BTreeMap<String, SnapshotEntry> = BTreeMap::new();
    for f in &files {
        // R3-8 (CodeRabbit M13 PR #132): make the read-scan-record sequence
        // single-read-safe. `scan_single_file` does its OWN fresh disk read, so a
        // concurrent edit between our `read_text` and the scan could validate one
        // version of the file while we record a DIFFERENT version as the trusted
        // baseline. `scan_single_file` doesn't accept already-read bytes, so we
        // bracket the scan with a hash on each side and ABORT on any change:
        //   1. read once  → `content` (the bytes we intend to record) + `pre_hash`
        //   2. scan (its own read happens between the two hashes)
        //   3. re-read    → `post_hash`
        //   4. pre_hash != post_hash ⇒ the file changed during the validation
        //      window; the scanned bytes and the about-to-be-recorded bytes may
        //      diverge, so refuse to record an unvalidated baseline.
        // A file stable across the whole window guarantees the scan saw the same
        // bytes we record; any change aborts rather than risking a TOCTOU bless.
        let content = match read_text(f) {
            Ok(c) => c,
            Err(e) => {
                // A file we cannot read cannot be blessed; surface and abort.
                if !emit_error(
                    json,
                    "tirith ai snapshot",
                    &format!("cannot read {}: {e}", f.display()),
                ) {
                    return 2;
                }
                return 1;
            }
        };
        let pre_hash = tirith_core::clipboard::content_sha256_hex(content.as_bytes());

        // A `None` scan is a HARD failure, not a silent skip (CodeRabbit M13 PR
        // #132 R7-3). `scan_single_file` returns `None` when the file could not be
        // analyzed (metadata/read error, or it exceeds the scan size cap). We must
        // NOT record an un-scanned file into the trusted baseline — blessing a file
        // whose risk was never assessed would defeat the whole point of the
        // snapshot. Abort the entire update so the operator fixes the unreadable
        // file and re-runs, rather than recording a partial, half-validated set.
        let result = match tirith_core::scan::scan_single_file(f) {
            Some(r) => r,
            None => return snapshot_scan_failed_code(json, f),
        };
        for finding in &result.findings {
            if finding.severity >= Severity::High {
                blocking.push((
                    rel_key(&root, f),
                    finding.severity,
                    finding.rule_id.to_string(),
                ));
            }
        }

        // Re-read and re-hash AFTER scanning. If the bytes changed, the scan we
        // just trusted no longer describes what we would record — abort.
        let post = match read_text(f) {
            Ok(c) => c,
            Err(e) => {
                if !emit_error(
                    json,
                    "tirith ai snapshot",
                    &format!("cannot re-read {}: {e}", f.display()),
                ) {
                    return 2;
                }
                return 1;
            }
        };
        let post_hash = tirith_core::clipboard::content_sha256_hex(post.as_bytes());
        if pre_hash != post_hash {
            if !emit_error(
                json,
                "tirith ai snapshot",
                &format!(
                    "{} changed while it was being scanned; refusing to record a baseline that \
                     was not validated. Re-run `tirith ai snapshot --update`.",
                    f.display()
                ),
            ) {
                return 2;
            }
            return 1;
        }

        entries.insert(
            rel_key(&root, f),
            SnapshotEntry {
                sha256: pre_hash,
                content,
            },
        );
    }

    if !blocking.is_empty() && !force {
        let msg = format!(
            "refusing to snapshot: {} High+ issue(s) in the AI-config files — blessing this \
             state would record a possibly-compromised baseline. Resolve them, or re-run with \
             --force to snapshot anyway.",
            blocking.len()
        );
        if json {
            #[derive(Serialize)]
            struct Blocking {
                path: String,
                severity: String,
                rule: String,
            }
            let v = serde_json::json!({
                "error": msg,
                "blocking_findings": blocking
                    .iter()
                    .map(|(p, s, r)| Blocking { path: p.clone(), severity: s.to_string(), rule: r.clone() })
                    .collect::<Vec<_>>(),
            });
            if !write_json_stdout(&v, "tirith ai snapshot: failed to write JSON output") {
                return 2;
            }
        } else {
            eprintln!("tirith ai snapshot: {msg}");
            for (p, s, r) in &blocking {
                eprintln!("  - {p}: {r} ({s})");
            }
        }
        return 1;
    }

    let snap = Snapshot {
        updated_at: chrono::Utc::now().to_rfc3339(),
        root: root.display().to_string(),
        files: entries,
    };

    let Some(path) = snapshot_path(&root) else {
        if !emit_error(
            json,
            "tirith ai snapshot",
            "cannot determine tirith state directory",
        ) {
            return 2;
        }
        return 1;
    };
    // Ensure the state dir exists, then write atomically (reuse write_file_atomic).
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            if !emit_error(
                json,
                "tirith ai snapshot",
                &format!("cannot create state dir {}: {e}", parent.display()),
            ) {
                return 2;
            }
            return 1;
        }
    }
    let bytes = match serde_json::to_vec_pretty(&snap) {
        Ok(b) => b,
        Err(e) => {
            if !emit_error(
                json,
                "tirith ai snapshot",
                &format!("serialize failed: {e}"),
            ) {
                return 2;
            }
            return 1;
        }
    };
    if let Err(e) = write_file_atomic(&path, &bytes, true) {
        if !emit_error(
            json,
            "tirith ai snapshot",
            &format!("failed to write snapshot {}: {e}", path.display()),
        ) {
            return 2;
        }
        return 1;
    }

    if json {
        let v = serde_json::json!({
            "updated": true,
            "path": path.display().to_string(),
            "updated_at": snap.updated_at,
            "root": snap.root,
            "file_count": snap.files.len(),
            "forced_over_findings": !blocking.is_empty(),
        });
        if !write_json_stdout(&v, "tirith ai snapshot: failed to write JSON output") {
            return 2;
        }
        return 0;
    }

    println!("Recorded AI-config snapshot ({} files).", snap.files.len());
    println!("  path:     {}", path.display());
    println!("  recorded: {}", snap.updated_at);
    if !blocking.is_empty() {
        println!();
        println!("WARNING: --force recorded a snapshot despite {} High+ issue(s); the baseline may be compromised.", blocking.len());
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    // CodeRabbit M13 PR #132 R20: every untrusted, AI-config-derived string that
    // `tirith ai` prints in human mode is routed through `sanitize_display`,
    // which must strip raw terminal-control bytes so a hostile config cannot
    // spoof terminal output. Assert the load-bearing property directly: a field
    // carrying a CSI colour escape (`\x1b[31m…`) is rendered with NO raw ESC
    // (0x1B) byte, while the visible text survives.
    #[test]
    fn sanitize_display_strips_terminal_escapes() {
        let hostile = "\x1b[31mFAKE ALERT\x1b[0m drop tables";
        let safe = sanitize_display(hostile);
        assert!(
            !safe.contains('\u{1b}'),
            "sanitized output must contain no raw ESC byte, got: {safe:?}"
        );
        // The CSI sequences are gone but the human-readable payload remains.
        assert!(
            safe.contains("FAKE ALERT") && safe.contains("drop tables"),
            "visible text must survive sanitization, got: {safe:?}"
        );
        assert!(
            !safe.contains("[31m") && !safe.contains("[0m"),
            "the CSI bodies must be consumed with the ESC, got: {safe:?}"
        );

        // A bare OSC sequence (used for e.g. clipboard write / title spoofing) is
        // also fully removed — ESC, the `]…`, and the BEL terminator.
        let osc = "before\x1b]0;pwned\x07after";
        let safe_osc = sanitize_display(osc);
        assert!(
            !safe_osc.contains('\u{1b}') && !safe_osc.contains('\u{7}'),
            "OSC escape + BEL terminator must be stripped, got: {safe_osc:?}"
        );
        assert!(
            safe_osc.contains("before") && safe_osc.contains("after"),
            "text around the OSC sequence must survive, got: {safe_osc:?}"
        );

        // Embedded newlines/tabs (which the underlying filter keeps) are flattened
        // to spaces so one display field stays on a single line.
        let multiline = "line1\nline2\tcol";
        assert_eq!(sanitize_display(multiline), "line1 line2 col");
    }

    // CodeRabbit M13 PR #132 R20: the `--move` confirmation gate must key its
    // "could we prompt?" decision off the stream `confirm` reads the ANSWER from
    // (stdin), not just stderr. The predicate is the conjunction stdin-TTY AND
    // stderr-TTY, so the only deterministic assertion in a unit test (cargo runs
    // tests with BOTH stdin and stderr piped, i.e. not TTYs) is that it returns
    // `false` here — exactly the non-interactive case that must fail non-zero
    // (exit 2) rather than be mistaken for a deliberate "no" (exit 0). A full
    // TTY-vs-EOF end-to-end check is not unit-testable without a pty, so we pin
    // the decision seam itself: in a non-interactive context confirmation is
    // impossible, which is what routes `quarantine --move` (without `--yes`) to
    // the emit_error + return 2 branch.
    #[test]
    fn confirmation_impossible_without_a_tty() {
        assert!(
            !confirmation_possible(),
            "with stdin/stderr piped (the cargo-test default, no TTY), an interactive \
             confirmation must be reported impossible so the no-TTY branch fails non-zero"
        );
    }

    // CodeRabbit M13 round-2 R7: the quarantine restore hint must be OS-aware.
    // R15-ai.rs:780: the command must include a literal `--` before the path
    // operands so a dash-prefixed path can never be parsed as a `cp` option.
    #[cfg(not(windows))]
    #[test]
    fn restore_command_unix_uses_cp_with_posix_quoting() {
        // Plain paths: `cp -- <from> <to>`.
        let cmd = restore_command(Path::new("/q/copy.txt"), Path::new("/orig/secret.txt"));
        assert_eq!(cmd, "cp -- /q/copy.txt /orig/secret.txt");

        // A space forces single-quoting; the restore copies FROM the quarantine
        // copy TO the original (argument order matters).
        let cmd = restore_command(Path::new("/q/a b.txt"), Path::new("/orig/my notes.txt"));
        assert_eq!(cmd, "cp -- '/q/a b.txt' '/orig/my notes.txt'");

        // An embedded single quote round-trips as `'\''` (POSIX), not `''`.
        let cmd = restore_command(Path::new("/q/it's.txt"), Path::new("/orig/x.txt"));
        assert_eq!(cmd, r#"cp -- '/q/it'\''s.txt' /orig/x.txt"#);

        // Never emits PowerShell on Unix.
        assert!(!cmd.contains("Copy-Item"));
    }

    // R15-ai.rs:780: a dash-prefixed destination (the attack the `--` guards
    // against) must remain an operand, not become a `cp` option. The command
    // must contain the literal `cp -- ` separator.
    #[cfg(not(windows))]
    #[test]
    fn restore_command_unix_uses_double_dash_before_operands() {
        // A leading-dash path is exactly the case `--` protects: `shell_quote`
        // leaves it bare, so without `--` it would parse as an option.
        let cmd = restore_command(Path::new("/q/copy.txt"), Path::new("-backup/.cursorrules"));
        assert!(
            cmd.contains("cp -- "),
            "restore command must use `cp -- ` so a dash-prefixed path is not an option: {cmd:?}"
        );
        // The dash-prefixed operand survives verbatim after the separator (it is
        // shell-safe per `shell_quote`, so it stays bare — but now post-`--`).
        assert!(
            cmd.ends_with(" -backup/.cursorrules"),
            "the dash-prefixed destination must remain an operand: {cmd:?}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn restore_command_windows_uses_copy_item_literalpath() {
        let cmd = restore_command(
            Path::new(r"C:\q\copy.txt"),
            Path::new(r"C:\orig\secret.txt"),
        );
        assert_eq!(
            cmd,
            r"Copy-Item -LiteralPath 'C:\q\copy.txt' -Destination 'C:\orig\secret.txt'"
        );
        // Backslashes are literal inside PowerShell single quotes (no escaping);
        // never emits a POSIX `cp` on Windows.
        assert!(!cmd.starts_with("cp "));

        // An embedded single quote is DOUBLED for PowerShell (`'` → `''`).
        let cmd = restore_command(Path::new(r"C:\q\it's.txt"), Path::new(r"C:\orig\x.txt"));
        assert_eq!(
            cmd,
            r"Copy-Item -LiteralPath 'C:\q\it''s.txt' -Destination 'C:\orig\x.txt'"
        );
    }

    // CodeRabbit M13 round-4 N2: the display diff is count-based, so a line that
    // appears more often on one side than the other is reported by the surplus,
    // not collapsed to one (or dropped) the way a HashSet diff would.
    #[test]
    fn added_removed_reports_count_surplus() {
        // A single `a` becomes two `a`s → exactly one added `a`, nothing removed.
        let (added, removed) = added_removed("a", "a\na");
        assert_eq!(added, vec!["a".to_string()]);
        assert!(removed.is_empty());

        // Symmetric: two `a`s become one → exactly one removed `a`.
        let (added, removed) = added_removed("a\na", "a");
        assert!(added.is_empty());
        assert_eq!(removed, vec!["a".to_string()]);

        // No churn when the multiset is unchanged (whitespace-only differs are
        // normalized away by trim_end + empty-line filtering).
        let (added, removed) = added_removed("a\nb", "a  \nb\n");
        assert!(added.is_empty());
        assert!(removed.is_empty());
    }

    // CodeRabbit M13 round-5 D5-3: `read_text` must enforce its 10 MiB cap
    // through a `take`-bounded read, not a TOCTOU stat-then-read. The cap is the
    // load-bearing security property, so assert the boundary directly: a file
    // exactly at the cap reads, a file one byte over is rejected as InvalidData
    // with the documented message, and the buffer can never exceed the cap.
    const READ_TEXT_MAX_BYTES: usize = 10 * 1024 * 1024;

    #[test]
    fn read_text_accepts_file_at_cap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("at_cap.txt");
        std::fs::write(&path, vec![b'a'; READ_TEXT_MAX_BYTES]).expect("write");
        let s = read_text(&path).expect("a file exactly at the cap must be accepted");
        assert_eq!(s.len(), READ_TEXT_MAX_BYTES);
    }

    #[test]
    fn read_text_rejects_file_over_cap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("over_cap.txt");
        // One byte past the cap must be rejected — and crucially, only
        // MAX_BYTES + 1 bytes are ever read into memory regardless of how large
        // the file actually is.
        std::fs::write(&path, vec![b'a'; READ_TEXT_MAX_BYTES + 1]).expect("write");
        let err = read_text(&path).expect_err("a file over the cap must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("larger than 10 MiB"),
            "error must keep the documented message; got: {err}"
        );
    }

    #[test]
    fn read_text_reads_small_file_verbatim() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("small.txt");
        std::fs::write(&path, "hello\nworld\n").expect("write");
        assert_eq!(read_text(&path).expect("read"), "hello\nworld\n");
    }

    // CodeRabbit M13 PR #132 R7-3: a `None` scan during `snapshot --update` is a
    // HARD failure — the file is never recorded and the update aborts non-zero.
    //
    // Forcing `scan_single_file` to return `None` *after* the preceding
    // `read_text` already succeeded is a genuine TOCTOU race (both read the same
    // bytes), so it can't be triggered deterministically from a fixture. Instead
    // we pin the load-bearing decision directly: the abort path returns a
    // non-zero exit following the surrounding `emit_error` convention (1 in human
    // mode, where the stderr write always succeeds; 2 is reserved for a failed
    // `--json` stdout write / broken pipe). The `match … { None => return … }`
    // arm in `snapshot_update` routes through this helper, so a non-zero return
    // here is exactly "abort the update, record nothing".
    #[test]
    fn snapshot_scan_failed_aborts_nonzero_human_mode() {
        let code = snapshot_scan_failed_code(false, Path::new("/repo/.cursorrules"));
        assert_eq!(
            code, 1,
            "an un-scannable file must abort `snapshot --update` with a non-zero exit"
        );
        assert_ne!(code, 0, "a None scan must never be treated as success");
    }

    // `XDG_CACHE_HOME` is process-global and cargo runs unit tests in parallel.
    // The quarantine tests repoint it at a temp dir, so they must not interleave:
    // this mutex serialises them.
    static CACHE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// RAII guard that points `XDG_CACHE_HOME` at `dir` for the duration of a
    /// test and restores the previous value (even on panic), so the quarantine
    /// store resolves into an isolated temp dir.
    struct CacheHomeGuard {
        prev: Option<std::ffi::OsString>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl CacheHomeGuard {
        fn set(dir: &Path) -> Self {
            let lock = CACHE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prev = std::env::var_os("XDG_CACHE_HOME");
            // SAFETY: serialized by CACHE_ENV_LOCK; matches the `unsafe` env
            // mutation style used across the crate's tests (e.g. policy.rs).
            unsafe { std::env::set_var("XDG_CACHE_HOME", dir) };
            Self { prev, _lock: lock }
        }
    }

    impl Drop for CacheHomeGuard {
        fn drop(&mut self) {
            // SAFETY: serialized by CACHE_ENV_LOCK (held in `_lock`).
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var("XDG_CACHE_HOME", v),
                    None => std::env::remove_var("XDG_CACHE_HOME"),
                }
            }
        }
    }

    /// R15-ai.rs:516: a stable file quarantined via `--move --yes` must report a
    /// sha that matches the bytes actually at `dest`, and the quarantined
    /// filename (`<ts>-<short_sha>-<basename>`) must encode that same hash. For a
    /// file that does not change during the move the provisional and recomputed
    /// hashes coincide, so this confirms the emitted/encoded hash describes the
    /// moved bytes — the property the recompute path guarantees.
    #[cfg(unix)]
    #[test]
    fn quarantine_move_reports_sha_matching_dest_bytes() {
        let cache = tempfile::tempdir().expect("cache home");
        let work = tempfile::tempdir().expect("work dir");
        let src = work.path().join(".cursorrules");
        let body = b"# stable ai-config\nallow everything\n";
        std::fs::write(&src, body).expect("write src");
        let expected_sha = tirith_core::clipboard::content_sha256_hex(body);

        let _guard = CacheHomeGuard::set(cache.path());
        // `--move --yes` short-circuits the confirm prompt, so no TTY is needed.
        let code = quarantine(
            src.to_str().unwrap(),
            /*do_move*/ true,
            /*yes*/ true,
            false,
        );
        assert_eq!(code, 0, "a stable --move --yes quarantine must succeed");

        // The original is gone (it was MOVED).
        assert!(!src.exists(), "the original must be removed after --move");

        // Locate the single quarantined file in the store and verify its bytes +
        // the hash encoded in its filename both equal the sha of the moved bytes.
        let qdir = cache.path().join("tirith").join("quarantine");
        let entries: Vec<PathBuf> = std::fs::read_dir(&qdir)
            .expect("quarantine dir exists")
            .flatten()
            .map(|e| e.path())
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "exactly one quarantined file, got: {entries:?}"
        );
        let dest = &entries[0];

        // The emitted/encoded sha must match the bytes physically at `dest`.
        let dest_bytes = std::fs::read(dest).expect("read quarantined file");
        let dest_sha = tirith_core::clipboard::content_sha256_hex(&dest_bytes);
        assert_eq!(
            dest_sha, expected_sha,
            "the bytes at dest must hash to the expected sha"
        );

        // The filename encodes `<ts>-<short_sha>-<basename>`; the short hash must
        // be the 16-char prefix of the dest bytes' sha.
        let fname = dest.file_name().unwrap().to_string_lossy();
        let short = &expected_sha[..expected_sha.len().min(16)];
        assert!(
            fname.contains(short),
            "quarantine filename {fname:?} must encode the dest-bytes short hash {short:?}"
        );
        assert!(
            fname.ends_with(".cursorrules"),
            "quarantine filename {fname:?} must keep the basename"
        );
    }
}
