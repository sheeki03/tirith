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
    /// The repository root the snapshot was taken against (display path).
    root: String,
    /// Map of `root`-relative file path → recorded entry. A `BTreeMap` so the
    /// on-disk JSON is deterministic (stable key order).
    files: BTreeMap<String, SnapshotEntry>,
}

/// Default snapshot path: `state_dir()/ai_config_snapshot.json`.
fn snapshot_path() -> Option<PathBuf> {
    state_dir().map(|d| d.join("ai_config_snapshot.json"))
}

/// Load the snapshot, returning `Ok(None)` when no snapshot file exists yet.
fn load_snapshot() -> std::io::Result<Option<Snapshot>> {
    let Some(path) = snapshot_path() else {
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

/// Resolve the repo root to scan / snapshot. `tirith ai` is repo-scoped; absent
/// an override we use the current directory (the snapshot records the root it
/// was taken against, and `diff` re-derives relative paths the same way).
fn repo_root() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
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
    let snapshot = match load_snapshot() {
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

    let root = repo_root();
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
        let old = snapshot
            .files
            .get(key)
            .map(|e| e.content.clone())
            .unwrap_or_default();
        let new = match current_by_key.get(key) {
            Some(path) => read_text(path).unwrap_or_default(),
            None => String::new(), // present in snapshot, gone on disk
        };

        if old == new {
            continue; // unchanged — skip
        }

        let status = if snapshot.files.contains_key(key) && current_by_key.contains_key(key) {
            "modified"
        } else if current_by_key.contains_key(key) {
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
        println!("  {} [{}]", d.path, d.status);
        for line in &d.added_instructions {
            println!("    + {line}");
        }
        for line in &d.removed_instructions {
            println!("    - {line}");
        }
        for f in &d.findings {
            println!("    !! {} ({}): {}", f.rule_id, f.severity, f.title);
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
    use std::collections::HashSet;
    let norm = |s: &str| -> Vec<String> {
        s.lines()
            .map(|l| l.trim_end().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    };
    let old_lines = norm(old);
    let new_lines = norm(new);
    let old_set: HashSet<&str> = old_lines.iter().map(|s| s.as_str()).collect();
    let new_set: HashSet<&str> = new_lines.iter().map(|s| s.as_str()).collect();
    let added: Vec<String> = new_lines
        .iter()
        .filter(|l| !old_set.contains(l.as_str()))
        .map(|l| truncate_line(l))
        .collect();
    let removed: Vec<String> = old_lines
        .iter()
        .filter(|l| !new_set.contains(l.as_str()))
        .map(|l| truncate_line(l))
        .collect();
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

/// Read a file as UTF-8 (lossy), with a size cap matching the scan engine's
/// per-file cap so a pathological file cannot exhaust memory.
fn read_text(path: &Path) -> std::io::Result<String> {
    const MAX_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB
    let meta = std::fs::metadata(path)?;
    if meta.len() > MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is larger than 10 MiB; skipping", path.display()),
        ));
    }
    let bytes = std::fs::read(path)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
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
    let content = match std::fs::read(&src) {
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

    let sha = tirith_core::clipboard::content_sha256_hex(&content);
    let short_sha = &sha[..sha.len().min(16)];
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

    let dest = qdir.join(format!("{ts}-{short_sha}-{basename}"));

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
        if json {
            // Non-interactive without --yes (or an explicit "no") → refuse.
            let _ = emit_error(
                json,
                "tirith ai quarantine",
                "--move deletes the original; pass --yes to confirm (refused without a TTY)",
            );
            return 2;
        }
        println!("Aborted — original left in place (nothing was moved).");
        return 0;
    }

    // Always COPY the bytes into quarantine first (atomic write).
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

    let mut moved = false;
    if do_move {
        // Destructive variant: remove the original now that the copy is durable.
        if let Err(e) = std::fs::remove_file(&src) {
            // The copy succeeded but the original could not be removed — report
            // honestly: the file IS quarantined (a copy exists) but the original
            // remains. Exit 1, not a silent success.
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

    let restore_cmd = format!("cp {} {}", shell_quote(&dest), shell_quote(&src));

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

    if moved {
        println!("Moved {} into quarantine.", src.display());
        println!("  quarantine copy: {}", dest.display());
        println!("  the original was REMOVED.");
    } else {
        println!(
            "Copied {} into quarantine (original UNTOUCHED).",
            src.display()
        );
        println!("  quarantine copy: {}", dest.display());
    }
    println!();
    println!("Restore with:");
    println!("  {restore_cmd}");
    0
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
    #[allow(deprecated)]
    std::env::home_dir().map(|h| h.join(".cache"))
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
fn shell_quote(p: &Path) -> String {
    let s = p.to_string_lossy();
    if s.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b':' | b'@' | b',')
    }) {
        return s.into_owned();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
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

    match tool {
        Some(t) => println!("{} configures {}.", path.display(), t.label()),
        None => {
            println!(
                "{} is not a recognised AI-config file — showing any content risks found.",
                path.display()
            );
        }
    }
    println!();
    if risks.is_empty() {
        println!("No capability / risk signals found in this file's content.");
    } else {
        println!("Capabilities / risks this config grants or signals:");
        for r in &risks {
            println!("  - [{}] {}", r.id, r.detail);
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
    let path_str = snapshot_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<unresolved>".to_string());

    let snap = match load_snapshot() {
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
            println!("AI-config snapshot:");
            println!("  path:       {path_str}");
            println!("  recorded:   {}", s.updated_at);
            println!("  root:       {}", s.root);
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
        if let Some(result) = tirith_core::scan::scan_single_file(f) {
            for finding in &result.findings {
                if finding.severity >= Severity::High {
                    blocking.push((
                        rel_key(&root, f),
                        finding.severity,
                        finding.rule_id.to_string(),
                    ));
                }
            }
        }
        entries.insert(
            rel_key(&root, f),
            SnapshotEntry {
                sha256: tirith_core::clipboard::content_sha256_hex(content.as_bytes()),
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

    let Some(path) = snapshot_path() else {
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
