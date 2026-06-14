//! Checkpoint/rollback: file-level snapshots taken before destructive commands
//! (`rm -rf`, `git reset --hard`, …) so users can recover destroyed work.
//!
//! Storage: `$XDG_STATE_HOME/tirith/checkpoints/<uuid>/` — `meta.json`
//! (metadata), `files/` (contents, named by SHA-256), `manifest.json`
//! (path → SHA-256 for restore).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

fn require_pro() -> Result<(), String> {
    Ok(())
}

/// Commands that trigger automatic checkpointing.
const AUTO_TRIGGER_PATTERNS: &[&str] = &[
    "rm -rf",
    "rm -f",
    "rm -fr",
    "git reset --hard",
    "git checkout .",
    "git clean -fd",
    "git clean -f",
];

/// Check if a command should trigger auto-checkpointing.
pub fn should_auto_checkpoint(command: &str) -> bool {
    let lower = command.to_lowercase();
    AUTO_TRIGGER_PATTERNS
        .iter()
        .any(|p| lower.contains(p))
        // `mv` fires on ALL moves (we can't statically tell if the destination
        // exists); a spurious cheap snapshot beats missing a destructive move.
        || (lower.starts_with("mv ") || lower.contains(" mv "))
}

/// Checkpoint metadata stored alongside backed up files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointMeta {
    pub id: String,
    pub created_at: String,
    pub trigger_command: Option<String>,
    pub paths: Vec<String>,
    pub total_bytes: u64,
    pub file_count: usize,
    /// F6: the working directory at capture time, persisted so a RELATIVE
    /// `original_path` in the manifest is restored against the SAME root it was
    /// captured under, not against whatever cwd the restore happens to run in
    /// (which could overwrite unrelated files). Absent on pre-F6 checkpoints
    /// (serde-default None); a relative entry is then rejected at restore time
    /// because it cannot be anchored safely.
    #[serde(default)]
    pub capture_root: Option<String>,
}

/// File manifest entry: original path → SHA-256 of content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub original_path: String,
    pub sha256: String,
    pub size: u64,
    pub is_dir: bool,
}

/// Result of listing checkpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointListEntry {
    pub id: String,
    pub created_at: String,
    pub trigger_command: Option<String>,
    pub file_count: usize,
    pub total_bytes: u64,
}

/// Checkpoint configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointConfig {
    #[serde(default = "default_max_count")]
    pub max_count: usize,
    #[serde(default = "default_max_age_days")]
    pub max_age_days: u32,
    #[serde(default = "default_max_total_bytes")]
    pub max_total_bytes: u64,
}

fn default_max_count() -> usize {
    50
}
fn default_max_age_days() -> u32 {
    30
}
fn default_max_total_bytes() -> u64 {
    500 * 1024 * 1024 // 500 MiB
}

impl Default for CheckpointConfig {
    fn default() -> Self {
        Self {
            max_count: default_max_count(),
            max_age_days: default_max_age_days(),
            max_total_bytes: default_max_total_bytes(),
        }
    }
}

/// Get the checkpoints directory.
pub fn checkpoints_dir() -> PathBuf {
    match crate::policy::state_dir() {
        Some(d) => d.join("checkpoints"),
        None => {
            eprintln!("tirith: WARNING: state dir unavailable, using /tmp/tirith (world-readable)");
            PathBuf::from("/tmp/tirith").join("checkpoints")
        }
    }
}

/// Create a checkpoint of the given paths.
pub fn create(paths: &[&str], trigger_command: Option<&str>) -> Result<CheckpointMeta, String> {
    require_pro()?;
    let base_dir = checkpoints_dir();
    let id = uuid::Uuid::new_v4().to_string();
    let cp_dir = base_dir.join(&id);
    let files_dir = cp_dir.join("files");

    fs::create_dir_all(&files_dir).map_err(|e| format!("create checkpoint dir: {e}"))?;

    let mut manifest: Vec<ManifestEntry> = Vec::new();
    let mut total_bytes: u64 = 0;

    for path_str in paths {
        let path = Path::new(path_str);
        if !path.exists() {
            continue;
        }

        if path.is_file() {
            match backup_file(path, &files_dir) {
                Ok(entry) => {
                    total_bytes += entry.size;
                    manifest.push(entry);
                }
                Err(e) => {
                    eprintln!("tirith: checkpoint: skip {path_str}: {e}");
                }
            }
        } else if path.is_dir() {
            match backup_dir(path, &files_dir) {
                Ok(entries) => {
                    for entry in entries {
                        total_bytes += entry.size;
                        manifest.push(entry);
                    }
                }
                Err(e) => {
                    eprintln!("tirith: checkpoint: skip dir {path_str}: {e}");
                }
            }
        }
    }

    if manifest.is_empty() {
        let _ = fs::remove_dir_all(&cp_dir);
        return Err("no files to checkpoint".to_string());
    }

    let now = chrono::Utc::now().to_rfc3339();
    let meta = CheckpointMeta {
        id: id.clone(),
        created_at: now,
        trigger_command: trigger_command.map(|s| s.to_string()),
        paths: paths.iter().map(|s| s.to_string()).collect(),
        total_bytes,
        file_count: manifest.len(),
        // Persist the capture-time cwd so a relative `original_path` restores
        // against this root, independent of the cwd at restore time. Canonicalize
        // it first: on macOS the cwd often contains a symlinked ancestor
        // (`/tmp` -> `/private/tmp`, `/var` -> `/private/var`). Storing that
        // symlinked form would make every relative entry anchor through a symlink,
        // and `reject_symlinked_restore_dest` would then FALSELY reject a legitimate
        // restore. Canonicalizing resolves the symlinks once at capture time. If
        // canonicalize fails (e.g. the cwd was removed), fall back to the verbatim
        // path rather than dropping the anchor.
        capture_root: std::env::current_dir().ok().map(|p| {
            fs::canonicalize(&p)
                .unwrap_or(p)
                .to_string_lossy()
                .into_owned()
        }),
    };

    let meta_json = serde_json::to_string_pretty(&meta).map_err(|e| format!("serialize: {e}"))?;
    fs::write(cp_dir.join("meta.json"), meta_json).map_err(|e| format!("write meta: {e}"))?;

    let manifest_json =
        serde_json::to_string_pretty(&manifest).map_err(|e| format!("serialize: {e}"))?;
    fs::write(cp_dir.join("manifest.json"), manifest_json)
        .map_err(|e| format!("write manifest: {e}"))?;

    Ok(meta)
}

/// List all checkpoints, newest first.
pub fn list() -> Result<Vec<CheckpointListEntry>, String> {
    let base_dir = checkpoints_dir();
    if !base_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();

    for entry in fs::read_dir(&base_dir).map_err(|e| format!("read dir: {e}"))? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!("tirith: checkpoint list: cannot read entry: {e}");
                continue;
            }
        };
        let meta_path = entry.path().join("meta.json");
        if !meta_path.exists() {
            continue;
        }
        let meta_str = match fs::read_to_string(&meta_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "tirith: checkpoint list: cannot read {}: {e}",
                    meta_path.display()
                );
                continue;
            }
        };
        let meta: CheckpointMeta = match serde_json::from_str(&meta_str) {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "tirith: checkpoint list: corrupt {}: {e}",
                    meta_path.display()
                );
                continue;
            }
        };
        entries.push(CheckpointListEntry {
            id: meta.id,
            created_at: meta.created_at,
            trigger_command: meta.trigger_command,
            file_count: meta.file_count,
            total_bytes: meta.total_bytes,
        });
    }

    entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(entries)
}

/// Validate that a checkpoint id is an INTERNAL, single-component basename (the
/// UUID `create()` assigns), not an attacker-controlled path. The id comes
/// straight from the CLI, and `checkpoints_dir().join(id)` would otherwise let an
/// absolute or traversal-bearing id select state outside the checkpoints store
/// (e.g. `--id ../../evil` or `--id /tmp/evil`), whose attacker-planted manifest
/// could then restore a blob to an arbitrary absolute path. We require the id to
/// be a single `Normal` path component with no separators, no `..`/`.`, not
/// absolute, and non-empty. Restricting it to one component is what makes the
/// later containment check exact: a one-component join cannot escape the base.
fn validate_checkpoint_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("checkpoint id is empty".to_string());
    }
    // Reject any separator outright (covers `/`, `\\`, and platform mixes) before
    // component analysis, so a backslash on unix can't sneak through as a
    // "normal" char in a single component.
    if id.contains('/') || id.contains('\\') {
        return Err(format!(
            "checkpoint id must not contain a path separator: {id}"
        ));
    }
    let p = Path::new(id);
    if p.is_absolute() {
        return Err(format!("checkpoint id must not be absolute: {id}"));
    }
    let mut comps = p.components();
    match (comps.next(), comps.next()) {
        // Exactly one component, and it must be a plain name (not `.`, `..`,
        // a root, or a Windows prefix like `C:`).
        (Some(std::path::Component::Normal(_)), None) => Ok(()),
        _ => Err(format!(
            "checkpoint id must be a single path component (no '..', '.', or separators): {id}"
        )),
    }
}

/// Validate that a restore path does not contain `..` traversal components.
///
/// Absolute paths are ALLOWED: `create()` records `original_path` verbatim, and
/// the auto-checkpoint path feeds it an absolute cwd, so a checkpoint of an
/// absolute path is legitimate and must restore. The escape risk that remains
/// (a destination reached through a symlink) is handled separately by
/// [`reject_symlinked_restore_dest`], which is the real overwrite guard. We still
/// reject `..` here so a crafted manifest cannot climb out of an otherwise
/// in-tree path.
fn validate_restore_path(path: &str) -> Result<(), String> {
    let p = Path::new(path);
    for component in p.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(format!("restore path contains '..': {path}"));
        }
    }
    Ok(())
}

/// F6: resolve a manifest `original_path` into the absolute destination to write.
///
/// * An ABSOLUTE `original_path` is used verbatim (it already names a concrete
///   location; the auto-checkpoint path records an absolute cwd).
/// * A RELATIVE `original_path` is anchored to `capture_root` (the cwd at capture
///   time, persisted in meta.json) so the restore target does not depend on the
///   caller's cwd at restore time. After joining, the result must stay CONTAINED
///   within `capture_root` (defense in depth; `..` is already rejected upstream by
///   [`validate_restore_path`], so the lexical join cannot climb out).
/// * A RELATIVE path with NO recorded `capture_root` (a pre-F6 checkpoint, or a
///   missing/corrupt meta.json) cannot be anchored safely and is REJECTED rather
///   than silently resolved against the caller's cwd.
///
/// The caller still applies [`reject_symlinked_restore_dest`] +
/// [`copy_no_follow_from_reader`] to the returned path, so symlink redirection at
/// the final component is closed independently of this anchoring.
fn anchor_restore_dst(original_path: &str, capture_root: Option<&Path>) -> Result<PathBuf, String> {
    let p = Path::new(original_path);
    if p.is_absolute() {
        return Ok(p.to_path_buf());
    }
    let root = capture_root.ok_or_else(|| {
        format!(
            "relative restore path with no recorded capture root (cannot anchor safely): {original_path}"
        )
    })?;
    let joined = root.join(p);
    // Containment check: the joined path's components must begin with the root's.
    // `..` was already rejected, so this is belt-and-suspenders against any future
    // relaxation of `validate_restore_path`.
    if !joined.starts_with(root) {
        return Err(format!(
            "relative restore path escapes the capture root: {original_path}"
        ));
    }
    Ok(joined)
}

/// Refuse a restore destination that is reached through a symlink. `fs::copy`
/// follows symlinks at the destination, so an attacker who repoints `dst` (or
/// any existing parent component) at a path outside the working tree could
/// redirect the restored bytes there. We reject if `dst` itself is a symlink, or
/// if any existing ancestor component is a symlink. `symlink_metadata` does NOT
/// follow links, so a missing component (yet to be created by `create_dir_all`)
/// simply yields no metadata and is skipped. Only a present symlink trips this.
/// Reject a checkpoint directory that is itself a symlink before reading anything
/// under it. The lexical `cp_dir.parent() == store` check upstream does not catch
/// a symlink AT `cp_dir` that redirects outside the store, so a planted link could
/// otherwise make restore/diff read an attacker-controlled manifest and files.
/// `symlink_metadata` does not follow the final component, so a real directory
/// passes and only a symlink is refused.
fn reject_symlinked_checkpoint_dir(cp_dir: &Path) -> Result<(), String> {
    match fs::symlink_metadata(cp_dir) {
        Ok(meta) if meta.file_type().is_symlink() => Err(format!(
            "refusing to use a symlinked checkpoint directory: {}",
            cp_dir.display()
        )),
        Ok(_) => Ok(()),
        Err(e) => Err(format!("cannot stat checkpoint directory: {e}")),
    }
}

fn reject_symlinked_restore_dest(dst: &Path) -> Result<(), String> {
    // The destination file: a symlink here would have `fs::copy` write through it.
    if let Ok(meta) = fs::symlink_metadata(dst) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "refusing to restore through symlink at destination: {}",
                dst.display()
            ));
        }
    }
    // Every existing ancestor: a symlinked directory in the path could escape the
    // tree even though the leaf itself is not (yet) a link.
    let mut cur = dst.parent();
    while let Some(p) = cur {
        if p.as_os_str().is_empty() {
            break;
        }
        if let Ok(meta) = fs::symlink_metadata(p) {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "refusing to restore through symlinked parent directory: {}",
                    p.display()
                ));
            }
        }
        cur = p.parent();
    }
    Ok(())
}

/// Copy from an ALREADY-OPEN source handle into `dst` WITHOUT following a symlink
/// at the destination's final component, instead of reopening the blob by path.
/// The restore path hashes a blob through this same handle (after seeking it back
/// to 0), so the bytes written to `dst` are exactly the bytes that were verified,
/// closing the TOCTOU where the on-disk blob is replaced between the hash and a
/// path-based reopen (CodeRabbit C4). The destination keeps the same no-follow
/// discipline: on unix it is opened with `O_NOFOLLOW` (plus create/truncate) so a
/// symlink planted at `dst` is refused by the open itself; on non-unix it is
/// created with `File::create` and relies on the caller's pre-write symlink check.
fn copy_no_follow_from_reader<R: Read>(src: &mut R, dst: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(dst)?;
        std::io::copy(src, &mut out)?;
        out.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut out = fs::File::create(dst)?;
        std::io::copy(src, &mut out)?;
        out.sync_all()?;
        Ok(())
    }
}

/// Validate that a SHA-256 filename is exactly 64 lowercase hex characters.
fn validate_sha256_filename(sha: &str) -> Result<(), String> {
    if sha.len() != 64
        || !sha
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(format!("invalid sha256 in manifest: {sha}"));
    }
    Ok(())
}

/// Per-bucket outcome of a checkpoint restore.
///
/// Distinguishes files that were restored from those whose backup blob was
/// missing, whose backup blob failed integrity verification (corrupt/tampered,
/// and therefore deliberately NOT written back), and those that hit a
/// copy/parent-dir error.
#[derive(Debug, Clone, Serialize)]
pub struct RestoreReport {
    pub checkpoint_id: String,
    pub attempted: usize,
    pub restored: Vec<String>,
    pub missing: Vec<String>,
    pub corrupt: Vec<String>,
    pub errors: Vec<(String, String)>,
}

/// Restore files from a checkpoint, returning a per-bucket report.
///
/// For each non-directory manifest entry: a missing backup blob lands in
/// `missing`; a blob whose SHA-256 does not match the manifest lands in
/// `corrupt` and is NOT copied (we never write back a tampered/corrupt blob);
/// a copy or parent-dir failure lands in `errors`; success lands in `restored`.
/// `attempted` counts the file (non-dir) entries processed.
pub fn restore_reported(checkpoint_id: &str) -> Result<RestoreReport, String> {
    require_pro()?;
    // The id is an UNCONSTRAINED CLI argument; validate it is an internal
    // single-component basename before joining it onto the store path. Otherwise
    // an absolute or `..`-bearing id could select an attacker-controlled
    // checkpoint directory whose manifest restores a blob to an arbitrary path.
    validate_checkpoint_id(checkpoint_id)?;
    let base_dir = checkpoints_dir();
    let cp_dir = base_dir.join(checkpoint_id);
    // Defense in depth: even with a validated single-component id, assert the
    // resolved directory is contained under the checkpoints store before trusting
    // its manifest. (id-validated -> cp_dir contained -> no-follow destination
    // write are the three coherent restore protections.)
    if cp_dir.parent() != Some(base_dir.as_path()) {
        return Err(format!(
            "checkpoint id resolves outside the checkpoints store: {checkpoint_id}"
        ));
    }
    if !cp_dir.exists() {
        return Err(format!("checkpoint not found: {checkpoint_id}"));
    }
    // The parent containment check above is LEXICAL: it confirms `cp_dir`'s parent
    // path equals the store, but does not stop `cp_dir` ITSELF from being a symlink
    // that redirects outside the store. Reading its manifest / restoring its files
    // would then follow that link. Reject a symlinked checkpoint directory before
    // any read. (`symlink_metadata` does not follow the final component.)
    reject_symlinked_checkpoint_dir(&cp_dir)?;

    let manifest_str = fs::read_to_string(cp_dir.join("manifest.json"))
        .map_err(|e| format!("read manifest: {e}"))?;
    let manifest: Vec<ManifestEntry> =
        serde_json::from_str(&manifest_str).map_err(|e| format!("parse manifest: {e}"))?;

    // F6: the capture-time root used to anchor RELATIVE manifest paths. Read from
    // meta.json (best-effort; a missing/corrupt meta or a pre-F6 checkpoint yields
    // None, which makes relative entries non-anchorable and therefore rejected).
    let capture_root: Option<PathBuf> = fs::read_to_string(cp_dir.join("meta.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<CheckpointMeta>(&s).ok())
        .and_then(|m| m.capture_root)
        .map(PathBuf::from);

    let files_dir = cp_dir.join("files");
    let mut report = RestoreReport {
        checkpoint_id: checkpoint_id.to_string(),
        attempted: 0,
        restored: Vec::new(),
        missing: Vec::new(),
        corrupt: Vec::new(),
        errors: Vec::new(),
    };

    for entry in &manifest {
        if entry.is_dir {
            continue; // Directories are created implicitly when their children restore.
        }

        report.attempted += 1;
        // A bad path/sha in ONE manifest entry must not abort the whole restore:
        // bucket it into errors and move on so the remaining entries still run.
        if let Err(e) = validate_restore_path(&entry.original_path) {
            report.errors.push((entry.original_path.clone(), e));
            continue;
        }
        if let Err(e) = validate_sha256_filename(&entry.sha256) {
            report.errors.push((entry.original_path.clone(), e));
            continue;
        }

        let src = files_dir.join(&entry.sha256);
        if !src.exists() {
            eprintln!(
                "tirith: checkpoint restore: missing data for {}",
                entry.original_path
            );
            report.missing.push(entry.original_path.clone());
            continue;
        }

        // Open the backup blob ONCE and both hash AND copy through this single
        // handle (CodeRabbit C4 TOCTOU). Reopening `files/<sha>` by path for the
        // copy after a separate path-based hash would let a concurrent replacement
        // slip UNVERIFIED bytes into the destination, breaking the "corrupt blobs
        // are recorded, never written" guarantee. The handle is rewound to 0
        // between the hash and the copy below.
        let mut blob = match fs::File::open(&src) {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "tirith: checkpoint restore: cannot open backup for {}: {e}, skipping",
                    entry.original_path
                );
                report.corrupt.push(entry.original_path.clone());
                continue;
            }
        };

        // Verify the backup blob's content matches the manifest SHA before
        // restoring. A mismatch means the blob was corrupted or tampered with
        // on disk; restoring it would overwrite the live file with bad data, so
        // skip the copy and record it as corrupt.
        match sha256_reader(&mut blob) {
            Ok(actual) if actual == entry.sha256 => {}
            Ok(_) => {
                eprintln!(
                    "tirith: checkpoint restore: corrupt backup for {} (sha mismatch), skipping",
                    entry.original_path
                );
                report.corrupt.push(entry.original_path.clone());
                continue;
            }
            Err(e) => {
                eprintln!(
                    "tirith: checkpoint restore: cannot verify backup for {}: {e}, skipping",
                    entry.original_path
                );
                report.corrupt.push(entry.original_path.clone());
                continue;
            }
        }

        // F6: anchor a RELATIVE original_path to the capture-time root so the
        // restore target does not depend on the caller's cwd (which could clobber
        // unrelated files). An absolute path is used verbatim. A relative path with
        // no recorded capture_root cannot be anchored safely and is rejected.
        let dst_buf = match anchor_restore_dst(&entry.original_path, capture_root.as_deref()) {
            Ok(p) => p,
            Err(e) => {
                report.errors.push((entry.original_path.clone(), e));
                continue;
            }
        };
        let dst = dst_buf.as_path();

        // Refuse to write through a symlink. `fs::copy` follows symlinks at the
        // destination, so a repointed symlink at `dst` (or any existing parent
        // component) could redirect the write outside the intended tree. Reject
        // the entry and leave whatever the link points at untouched.
        if let Err(e) = reject_symlinked_restore_dest(dst) {
            report.errors.push((entry.original_path.clone(), e));
            continue;
        }

        if let Some(parent) = dst.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                report.errors.push((
                    entry.original_path.clone(),
                    format!("cannot create parent dir: {e}"),
                ));
                continue;
            }
        }

        // F5 (TOCTOU): the symlink pre-check above ran BEFORE `create_dir_all`, so
        // an attacker could have repointed `dst` (or swapped in a symlink) in the
        // window between. Re-validate the parent chain immediately before the
        // write, AND perform the write through a no-follow open on unix so a
        // symlink planted at the final component is refused atomically by the open
        // itself (`fs::copy` would instead follow it and write through). The
        // pre-check still runs for an early, cheap rejection and to cover non-unix.
        if let Err(e) = reject_symlinked_restore_dest(dst) {
            report.errors.push((entry.original_path.clone(), e));
            continue;
        }
        // Rewind the blob handle to the start and copy from THIS verified handle
        // (not a fresh open by path), so the bytes written are exactly the bytes
        // just hashed (CodeRabbit C4 TOCTOU). A seek failure means we cannot
        // guarantee that, so bucket it as an error rather than risk an unverified
        // or partial write.
        if let Err(e) = blob.seek(SeekFrom::Start(0)) {
            report.errors.push((
                entry.original_path.clone(),
                format!("cannot rewind verified backup: {e}"),
            ));
            continue;
        }
        match copy_no_follow_from_reader(&mut blob, dst) {
            Ok(_) => report.restored.push(entry.original_path.clone()),
            Err(e) => report
                .errors
                .push((entry.original_path.clone(), e.to_string())),
        }
    }

    let detail = format!(
        "checkpoint_id={checkpoint_id} attempted={} restored={} missing={} corrupt={} errors={}",
        report.attempted,
        report.restored.len(),
        report.missing.len(),
        report.corrupt.len(),
        report.errors.len(),
    );
    crate::audit::log_hook_event(
        "checkpoint",
        "restore",
        "snapshot_restore",
        None,
        Some(&detail),
    );

    Ok(report)
}

/// Restore files from a checkpoint, returning the restored paths.
///
/// Thin wrapper over `restore_reported` that preserves the historical return
/// shape for existing callers.
pub fn restore(checkpoint_id: &str) -> Result<Vec<String>, String> {
    restore_reported(checkpoint_id).map(|r| r.restored)
}

/// Get diff between checkpoint and current filesystem state.
pub fn diff(checkpoint_id: &str) -> Result<Vec<DiffEntry>, String> {
    require_pro()?;
    let cp_dir = checkpoints_dir().join(checkpoint_id);
    if !cp_dir.exists() {
        return Err(format!("checkpoint not found: {checkpoint_id}"));
    }
    // Same symlink guard as the restore path: a symlinked `cp_dir` could redirect
    // the manifest/file reads outside the store. Reject it before any read.
    reject_symlinked_checkpoint_dir(&cp_dir)?;

    let manifest_str = fs::read_to_string(cp_dir.join("manifest.json"))
        .map_err(|e| format!("read manifest: {e}"))?;
    let manifest: Vec<ManifestEntry> =
        serde_json::from_str(&manifest_str).map_err(|e| format!("parse manifest: {e}"))?;

    let files_dir = cp_dir.join("files");
    let mut diffs = Vec::new();
    // Track classified paths so the branches don't double-emit for one file.
    let mut classified_paths: std::collections::HashSet<String> = std::collections::HashSet::new();

    for entry in &manifest {
        if entry.is_dir {
            continue;
        }

        let backup = files_dir.join(&entry.sha256);
        if !backup.exists() {
            diffs.push(DiffEntry {
                path: entry.original_path.clone(),
                status: DiffStatus::BackupCorrupt,
                checkpoint_sha256: entry.sha256.clone(),
                current_sha256: None,
            });
            classified_paths.insert(entry.original_path.clone());
            continue;
        }

        let current_path = Path::new(&entry.original_path);
        if !current_path.exists() {
            diffs.push(DiffEntry {
                path: entry.original_path.clone(),
                status: DiffStatus::Deleted,
                checkpoint_sha256: entry.sha256.clone(),
                current_sha256: None,
            });
            classified_paths.insert(entry.original_path.clone());
            continue;
        }

        match sha256_file(current_path) {
            Ok(current_sha) => {
                if current_sha != entry.sha256 {
                    diffs.push(DiffEntry {
                        path: entry.original_path.clone(),
                        status: DiffStatus::Modified,
                        checkpoint_sha256: entry.sha256.clone(),
                        current_sha256: Some(current_sha),
                    });
                    classified_paths.insert(entry.original_path.clone());
                }
            }
            Err(e) => {
                eprintln!(
                    "tirith: checkpoint diff: cannot read {}: {e}",
                    entry.original_path
                );
                diffs.push(DiffEntry {
                    path: entry.original_path.clone(),
                    status: DiffStatus::Modified,
                    checkpoint_sha256: entry.sha256.clone(),
                    current_sha256: None,
                });
                classified_paths.insert(entry.original_path.clone());
            }
        }
    }

    let _ = &classified_paths;

    Ok(diffs)
}

/// Purge old checkpoints based on configuration limits.
pub fn purge(config: &CheckpointConfig) -> Result<PurgeResult, String> {
    require_pro()?;
    let base_dir = checkpoints_dir();
    if !base_dir.exists() {
        return Ok(PurgeResult {
            removed_count: 0,
            freed_bytes: 0,
        });
    }

    let mut all = list()?;
    let mut removed_count = 0;
    let mut freed_bytes: u64 = 0;

    let now = chrono::Utc::now();
    let max_age = chrono::Duration::days(config.max_age_days as i64);
    all.retain(|e| {
        if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&e.created_at) {
            let age = now.signed_duration_since(created);
            if age > max_age {
                let cp_dir = base_dir.join(&e.id);
                match fs::remove_dir_all(&cp_dir) {
                    Ok(()) => {
                        freed_bytes += e.total_bytes;
                        removed_count += 1;
                        return false;
                    }
                    Err(err) => {
                        eprintln!("tirith: checkpoint purge: failed to remove {}: {err}", e.id);
                        return true;
                    }
                }
            }
        }
        true
    });

    while all.len() > config.max_count {
        if let Some(oldest) = all.pop() {
            let cp_dir = base_dir.join(&oldest.id);
            match fs::remove_dir_all(&cp_dir) {
                Ok(()) => {
                    freed_bytes += oldest.total_bytes;
                    removed_count += 1;
                }
                Err(e) => {
                    eprintln!(
                        "tirith: checkpoint purge: failed to remove {}: {e}",
                        oldest.id
                    );
                    // A stuck entry would otherwise loop forever while `all.len()`
                    // stays over the cap.
                    break;
                }
            }
        }
    }

    let mut total: u64 = all.iter().map(|e| e.total_bytes).sum();
    while config.max_total_bytes > 0 && total > config.max_total_bytes && !all.is_empty() {
        if let Some(oldest) = all.pop() {
            let cp_dir = base_dir.join(&oldest.id);
            match fs::remove_dir_all(&cp_dir) {
                Ok(()) => {
                    total -= oldest.total_bytes;
                    freed_bytes += oldest.total_bytes;
                    removed_count += 1;
                }
                Err(e) => {
                    eprintln!(
                        "tirith: checkpoint purge: failed to remove {}: {e}",
                        oldest.id
                    );
                    // A stuck entry would otherwise loop forever while `total`
                    // stays over the cap.
                    break;
                }
            }
        }
    }

    Ok(PurgeResult {
        removed_count,
        freed_bytes,
    })
}

/// Diff status for a file between checkpoint and current state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub path: String,
    pub status: DiffStatus,
    pub checkpoint_sha256: String,
    pub current_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiffStatus {
    Deleted,
    Modified,
    BackupCorrupt,
}

/// Result of a purge operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurgeResult {
    pub removed_count: usize,
    pub freed_bytes: u64,
}

/// Runtime-state observation captured by `tirith watch` (M10 ch2): a
/// BEST-EFFORT, after-the-fact view of a watched command's effect on the
/// *environment* and *shell startup files*. NOT a network monitor and NOT a
/// security boundary.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostRunState {
    /// Heuristic DNS-resolver-side domain hints (experimental, opt-in via
    /// `--with-net-hints`). Empty means "not observed", NOT "no traffic"; may
    /// miss QUIC/UDP/direct-IP entirely. NOT authoritative.
    #[serde(default)]
    pub domains_contacted: Vec<String>,
    /// Env var names present after the run but absent before — only those the
    /// command exported back into tirith's own env (so mainly useful when
    /// `tirith watch` is invoked from a re-exporting wrapper).
    #[serde(default)]
    pub env_vars_added: Vec<String>,
    /// Directories newly on `$PATH` after the run (before-vs-after set diff).
    #[serde(default)]
    pub path_dirs_added: Vec<String>,
}

/// A before/after snapshot pair for the `tirith watch` runtime-state diff,
/// captured by [`capture_runtime_state`] and compared by [`diff_runtime_state`].
/// Separate from [`CheckpointMeta`] so working-tree vs env/PATH/shell-rc stay
/// independently testable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeStateSnapshot {
    /// Names of every environment variable visible at capture time.
    pub env_vars: Vec<String>,
    /// Colon-split `$PATH` entries at capture time (order preserved).
    pub path_dirs: Vec<String>,
    /// Per shell-rc/profile file: relative-name → sha256. An absent file gets
    /// the empty-string sha so a later *appearance* reads as a change.
    pub shell_rc_hashes: std::collections::BTreeMap<String, String>,
    /// Home dir used to resolve the shell-rc paths (so the after-snapshot
    /// resolves the identical set).
    pub home: String,
}

/// Shell rc / profile files watched during a `tirith watch` run. Mirrors
/// `persistence.rs::SHELL_RC_FILES` plus the common PowerShell profile paths.
const WATCH_SHELL_RC_FILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
    ".profile",
    ".config/fish/config.fish",
    ".config/powershell/Microsoft.PowerShell_profile.ps1",
    "Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
    "Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1",
];

/// Capture the current runtime state (env var names, `$PATH` entries, shell-rc
/// hashes) for a `tirith watch` before/after comparison.
///
/// `home` is a parameter (not read from `std::env`) so tests can point it at a
/// tempdir without mutating process-global `HOME` (a libc data race — PR #125).
pub fn capture_runtime_state(home: &Path) -> RuntimeStateSnapshot {
    let mut env_vars: Vec<String> = std::env::vars_os()
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect();
    env_vars.sort();

    let path_dirs: Vec<String> = std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p)
                .map(|d| d.to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();

    let mut shell_rc_hashes = std::collections::BTreeMap::new();
    for rel in WATCH_SHELL_RC_FILES {
        let path = home.join(rel);
        // Absent files get the empty-string hash so a later appearance reads as
        // a modification.
        let sha = if path.is_file() {
            match sha256_file(&path) {
                Ok(s) => s,
                Err(_) => continue,
            }
        } else {
            empty_sha256()
        };
        shell_rc_hashes.insert((*rel).to_string(), sha);
    }

    RuntimeStateSnapshot {
        env_vars,
        path_dirs,
        shell_rc_hashes,
        home: home.to_string_lossy().into_owned(),
    }
}

/// Diff two runtime-state snapshots into the additive [`PostRunState`] plus the
/// rc-file names whose sha256 changed between `before` and `after` (driving the
/// [`crate::verdict::RuleId::PostRunShellRcModified`] finding).
pub fn diff_runtime_state(
    before: &RuntimeStateSnapshot,
    after: &RuntimeStateSnapshot,
) -> (PostRunState, Vec<String>) {
    let before_env: std::collections::HashSet<&String> = before.env_vars.iter().collect();
    let env_vars_added: Vec<String> = after
        .env_vars
        .iter()
        .filter(|v| !before_env.contains(*v))
        .cloned()
        .collect();

    let before_path: std::collections::HashSet<&String> = before.path_dirs.iter().collect();
    let path_dirs_added: Vec<String> = after
        .path_dirs
        .iter()
        .filter(|d| !before_path.contains(*d))
        .cloned()
        .collect();

    let mut modified_rc_files: Vec<String> = Vec::new();
    for (rel, after_sha) in &after.shell_rc_hashes {
        match before.shell_rc_hashes.get(rel) {
            Some(before_sha) if before_sha == after_sha => {}
            // Changed hash or a newly-appeared file — both count as modified.
            _ => modified_rc_files.push(rel.clone()),
        }
    }
    modified_rc_files.sort();

    (
        PostRunState {
            // domains_contacted is filled by the CLI layer only under
            // --with-net-hints; the pure diff never invents network claims.
            domains_contacted: Vec::new(),
            env_vars_added,
            path_dirs_added,
        },
        modified_rc_files,
    )
}

/// SHA-256 of the empty byte string — sentinel hash for an absent shell-rc file.
fn empty_sha256() -> String {
    format!("{:x}", Sha256::new().finalize())
}

/// Findings for a `tirith watch` post-run diff: one High
/// [`crate::verdict::RuleId::PostRunShellRcModified`] listing every modified
/// shell-rc file, or none when nothing changed. In core (not the CLI) so it is
/// unit-testable without spawning a process.
pub fn findings_for_modified_rc(modified_rc_files: &[String]) -> Vec<crate::verdict::Finding> {
    use crate::verdict::{Finding, RuleId, Severity};
    if modified_rc_files.is_empty() {
        return Vec::new();
    }
    vec![Finding {
        rule_id: RuleId::PostRunShellRcModified,
        severity: Severity::High,
        title: "Watched command modified a shell rc / profile file".to_string(),
        description: format!(
            "The watched command modified the following shell startup file(s) \
             during its run: {}. A command rewriting your login shell is a \
             persistence foothold — review the added lines before trusting it.",
            modified_rc_files.join(", ")
        ),
        evidence: Vec::new(),
        human_view: None,
        agent_view: None,
        mitre_id: Some("T1546.004".to_string()),
        custom_rule_id: None,
    }]
}

/// Create a checkpoint then purge old ones with default limits. Test convenience
/// wrapper; the CLI calls `create()` then `purge()` for distinct error messages.
pub fn create_and_purge(paths: &[&str], trigger_command: Option<&str>) -> Result<(), String> {
    create(paths, trigger_command)?;
    let config = CheckpointConfig::default();
    purge(&config)?;
    Ok(())
}

/// Backup a single file to the checkpoint files directory.
/// Normalize a captured file's `original_path` for the manifest.
///
/// An ABSOLUTE path may run through a symlinked system alias (`/tmp` ->
/// `/private/tmp`, `/var` -> `/private/var` on macOS). Storing that verbatim
/// makes `reject_symlinked_restore_dest` falsely reject a legitimate restore at
/// restore time. We canonicalize the PARENT directory (resolving ancestor
/// symlinks once, at capture) and rejoin the final component verbatim, so a
/// symlink at the leaf itself is NOT followed (the file's identity is preserved)
/// while ancestor aliases are resolved. Relative paths are left untouched: they
/// anchor to the already-canonicalized `capture_root` at restore time.
fn normalize_capture_path(path: &Path) -> String {
    if !path.is_absolute() {
        return path.to_string_lossy().into_owned();
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => match fs::canonicalize(parent) {
            Ok(canon) => canon.join(name).to_string_lossy().into_owned(),
            Err(_) => path.to_string_lossy().into_owned(),
        },
        // Root or no file name: nothing to normalize.
        _ => path.to_string_lossy().into_owned(),
    }
}

fn backup_file(path: &Path, files_dir: &Path) -> Result<ManifestEntry, String> {
    let sha = sha256_file(path)?;
    let dst = files_dir.join(&sha);

    // Content-addressed dedup: two checkpointed files with identical contents
    // share a single on-disk copy.
    if !dst.exists() {
        fs::copy(path, &dst).map_err(|e| format!("copy: {e}"))?;
    }

    let size = match path.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            eprintln!(
                "tirith: checkpoint: cannot read metadata for {}: {e}",
                path.display()
            );
            0
        }
    };

    Ok(ManifestEntry {
        original_path: normalize_capture_path(path),
        sha256: sha,
        size,
        is_dir: false,
    })
}

/// Backup a directory recursively.
///
/// NOTE: only files are recorded, so `restore()` does not recreate empty
/// directories that existed at checkpoint time (parents of restored files are
/// created implicitly).
fn backup_dir(dir: &Path, files_dir: &Path) -> Result<Vec<ManifestEntry>, String> {
    let mut entries = Vec::new();
    const MAX_FILES: usize = 10_000;
    const MAX_SINGLE_FILE: u64 = 100 * 1024 * 1024; // 100 MiB per file

    backup_dir_recursive(dir, files_dir, &mut entries, MAX_FILES, MAX_SINGLE_FILE)?;
    Ok(entries)
}

fn backup_dir_recursive(
    dir: &Path,
    files_dir: &Path,
    entries: &mut Vec<ManifestEntry>,
    max_files: usize,
    max_single_file: u64,
) -> Result<(), String> {
    if entries.len() >= max_files {
        return Ok(());
    }

    let read_dir = fs::read_dir(dir).map_err(|e| format!("read dir {}: {e}", dir.display()))?;

    for entry in read_dir {
        if entries.len() >= max_files {
            break;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!(
                    "tirith: checkpoint: skip unreadable entry in {}: {e}",
                    dir.display()
                );
                continue;
            }
        };
        let path = entry.path();

        // symlink_metadata avoids a TOCTOU race vs is_symlink() + later reads.
        let meta = match path.symlink_metadata() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("tirith: checkpoint: skip {}: {e}", path.display());
                continue;
            }
        };

        if meta.file_type().is_symlink() {
            continue; // following symlinks could back up files outside the tree
        }

        if meta.file_type().is_file() {
            let size = meta.len();
            if size > max_single_file {
                eprintln!(
                    "tirith: checkpoint: skip large file {} ({} bytes)",
                    path.display(),
                    size
                );
                continue;
            }
            match backup_file(&path, files_dir) {
                Ok(e) => entries.push(e),
                Err(e) => {
                    eprintln!("tirith: checkpoint: skip {}: {e}", path.display());
                }
            }
        } else if path.is_dir() {
            // Skip dot-dirs (e.g. .git) — rarely worth it and can dominate the budget.
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with('.'))
                .unwrap_or(false)
            {
                continue;
            }
            backup_dir_recursive(&path, files_dir, entries, max_files, max_single_file)?;
        }
    }

    Ok(())
}

/// Compute SHA-256 of a file.
fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    sha256_reader(&mut file)
}

/// SHA-256 of everything readable from `reader`, streaming in fixed chunks. Used
/// both by [`sha256_file`] and by the restore path, which hashes a blob through
/// the SAME open handle it then copies from (seeking back to 0 between), so the
/// bytes verified are exactly the bytes written even if the blob is replaced on
/// disk concurrently (CodeRabbit C4 TOCTOU).
fn sha256_reader<R: Read>(reader: &mut R) -> Result<String, String> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_auto_checkpoint() {
        assert!(should_auto_checkpoint("rm -rf /tmp/myproject"));
        assert!(should_auto_checkpoint("rm -f important.txt"));
        assert!(should_auto_checkpoint("git reset --hard HEAD~3"));
        assert!(should_auto_checkpoint("git checkout ."));
        assert!(should_auto_checkpoint("git clean -fd"));
        assert!(should_auto_checkpoint("sudo rm -rf /"));
        assert!(!should_auto_checkpoint("ls -la"));
        assert!(!should_auto_checkpoint("echo hello"));
        assert!(!should_auto_checkpoint("git status"));
    }

    #[test]
    fn test_checkpoint_config_defaults() {
        let config = CheckpointConfig::default();
        assert_eq!(config.max_count, 50);
        assert_eq!(config.max_age_days, 30);
        assert_eq!(config.max_total_bytes, 500 * 1024 * 1024);
    }

    #[test]
    fn test_backup_and_sha256() {
        let tmp = tempfile::tempdir().unwrap();
        let test_file = tmp.path().join("test.txt");
        fs::write(&test_file, "hello world").unwrap();

        let files_dir = tmp.path().join("files");
        fs::create_dir_all(&files_dir).unwrap();

        let entry = backup_file(&test_file, &files_dir).unwrap();
        assert!(!entry.sha256.is_empty());
        assert_eq!(entry.size, 11);
        assert!(!entry.is_dir);

        let backup_path = files_dir.join(&entry.sha256);
        assert!(backup_path.exists());
        let content = fs::read_to_string(&backup_path).unwrap();
        assert_eq!(content, "hello world");
    }

    #[test]
    fn test_backup_dir_recursive() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("project");
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("README.md"), "# Hello").unwrap();
        fs::write(dir.join("src/main.rs"), "fn main() {}").unwrap();

        let files_dir = tmp.path().join("files");
        fs::create_dir_all(&files_dir).unwrap();

        let entries = backup_dir(&dir, &files_dir).unwrap();
        assert_eq!(entries.len(), 2, "should backup 2 files: {entries:?}");
    }

    #[test]
    fn test_backup_nonexistent_file() {
        let tmp = tempfile::tempdir().unwrap();
        let files_dir = tmp.path().join("files");
        fs::create_dir_all(&files_dir).unwrap();

        let result = backup_file(Path::new("/nonexistent/file.txt"), &files_dir);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_restore_path_rejects_traversal() {
        // `..` traversal is always rejected, including inside an absolute path.
        assert!(validate_restore_path("../../etc/passwd").is_err());
        assert!(validate_restore_path("/tmp/../etc/evil").is_err());
        assert!(validate_restore_path("normal/path/file.txt").is_ok());
        // Absolute paths are ALLOWED: create() records original_path verbatim
        // (the auto-checkpoint feeds an absolute cwd), so a legitimate absolute
        // checkpoint must restore. Symlink-overwrite escape is guarded separately
        // by reject_symlinked_restore_dest, not by this path validator.
        assert!(
            validate_restore_path("/absolute/path/file.txt").is_ok(),
            "absolute paths must be allowed (create() writes them verbatim)"
        );
        assert!(
            validate_restore_path("/etc/passwd").is_ok(),
            "a plain absolute path is allowed; symlink escape is guarded elsewhere"
        );
    }

    #[test]
    fn test_validate_sha256_filename() {
        let valid = "a".repeat(64);
        assert!(validate_sha256_filename(&valid).is_ok());
        assert!(validate_sha256_filename("short").is_err());
        assert!(validate_sha256_filename("../../etc/passwd").is_err());
        assert!(validate_sha256_filename(&"g".repeat(64)).is_err()); // non-hex
    }

    #[test]
    fn test_diff_status_serde() {
        let entry = DiffEntry {
            path: "/tmp/test.txt".to_string(),
            status: DiffStatus::Deleted,
            checkpoint_sha256: "abc123".to_string(),
            current_sha256: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: DiffEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status, DiffStatus::Deleted);
    }

    #[test]
    fn test_restore_reported_missing_and_corrupt_buckets() {
        // A restore must honestly bucket a missing backup blob into `missing`
        // and a tampered backup blob into `corrupt`, and must NOT write the
        // corrupt blob back over the live file.
        //
        // `validate_restore_path` rejects absolute original paths, so the
        // checkpointed paths must be relative. We chdir into a temp workdir
        // (serialized by TEST_ENV_LOCK, the same boundary the env mutation
        // below relies on) and checkpoint by bare filename.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let tmpdir = tempfile::tempdir().unwrap();
        let workdir = tmpdir.path().join("project");
        fs::create_dir_all(&workdir).unwrap();

        let state_dir = tmpdir.path().join("state");
        let prev_state = std::env::var("XDG_STATE_HOME").ok();
        let prev_cwd = std::env::current_dir().ok();
        // SAFETY: serialized by crate::TEST_ENV_LOCK across all modules.
        unsafe { std::env::set_var("XDG_STATE_HOME", &state_dir) };

        // Relative names that pass validate_restore_path; resolved against `workdir`.
        let name_a = "a.txt";
        let name_b = "b.txt";

        let run = || -> Result<RestoreReport, String> {
            std::env::set_current_dir(&workdir).map_err(|e| format!("chdir: {e}"))?;

            fs::write(name_a, "alpha contents").map_err(|e| format!("write a: {e}"))?;
            fs::write(name_b, "bravo contents").map_err(|e| format!("write b: {e}"))?;

            let meta = create(&[name_a, name_b], Some("rm -rf project"))?;

            let files_dir = checkpoints_dir().join(&meta.id).join("files");

            // Look up each file's backup blob by its manifest SHA.
            let manifest_str =
                fs::read_to_string(checkpoints_dir().join(&meta.id).join("manifest.json"))
                    .map_err(|e| format!("read manifest: {e}"))?;
            let manifest: Vec<ManifestEntry> =
                serde_json::from_str(&manifest_str).map_err(|e| format!("parse: {e}"))?;
            let sha_for = |orig: &str| -> String {
                manifest
                    .iter()
                    .find(|m| m.original_path == orig)
                    .map(|m| m.sha256.clone())
                    .expect("manifest entry for file")
            };
            let blob_a = files_dir.join(sha_for(name_a));
            let blob_b = files_dir.join(sha_for(name_b));

            // (a) delete one backup blob -> should bucket into `missing`.
            fs::remove_file(&blob_a).map_err(|e| format!("rm blob_a: {e}"))?;
            // (b) byte-corrupt the other blob -> should bucket into `corrupt`.
            fs::write(&blob_b, "tampered bytes that do not match the sha")
                .map_err(|e| format!("corrupt blob_b: {e}"))?;

            // Overwrite the live files so a restore copy would be observable.
            fs::write(name_a, "live a unchanged").map_err(|e| format!("write a: {e}"))?;
            fs::write(name_b, "live b unchanged").map_err(|e| format!("write b: {e}"))?;

            restore_reported(&meta.id)
        };

        let result = run();

        // Read the live files back while cwd is still the workdir.
        let live_a = fs::read_to_string(workdir.join(name_a)).ok();
        let live_b = fs::read_to_string(workdir.join(name_b)).ok();

        // Restore cwd and env before assertions so cleanup runs even on failure.
        if let Some(dir) = prev_cwd {
            let _ = std::env::set_current_dir(dir);
        }
        match prev_state {
            Some(val) => unsafe { std::env::set_var("XDG_STATE_HOME", val) },
            None => unsafe { std::env::remove_var("XDG_STATE_HOME") },
        }

        let report = result.expect("restore_reported should succeed");

        assert_eq!(
            report.attempted, 2,
            "two file entries processed: {report:?}"
        );
        assert!(
            report.restored.is_empty(),
            "nothing should restore cleanly: {report:?}"
        );
        assert_eq!(report.missing, vec![name_a.to_string()], "{report:?}");
        assert_eq!(report.corrupt, vec![name_b.to_string()], "{report:?}");
        assert!(report.errors.is_empty(), "no copy errors: {report:?}");

        // Neither the missing nor the corrupt file may be written back.
        assert_eq!(
            live_b.as_deref(),
            Some("live b unchanged"),
            "corrupt backup must not overwrite the live file"
        );
        assert_eq!(
            live_a.as_deref(),
            Some("live a unchanged"),
            "missing backup must not change the live file"
        );
    }

    /// The SUCCESS path of `restore_reported`: a verified blob is copied back
    /// into `restored` (live file content restored to the checkpointed bytes),
    /// AND a `snapshot_restore` audit record is emitted. The existing buckets
    /// test only sabotages both blobs, so this is the only coverage of a
    /// non-empty `restored` and of the restore audit side-effect.
    #[cfg(unix)]
    #[test]
    fn test_restore_reported_happy_path() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let tmpdir = tempfile::tempdir().unwrap();
        let workdir = tmpdir.path().join("project");
        fs::create_dir_all(&workdir).unwrap();

        let state_dir = tmpdir.path().join("state");
        let data_dir = tmpdir.path().join("data");
        let prev_state = std::env::var("XDG_STATE_HOME").ok();
        let prev_data = std::env::var("XDG_DATA_HOME").ok();
        let prev_log = std::env::var("TIRITH_LOG").ok();
        let prev_cwd = std::env::current_dir().ok();
        // SAFETY: serialized by crate::TEST_ENV_LOCK across all modules. Point the
        // audit log at the temp data dir and ENABLE logging so the restore
        // emission is observable.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", &state_dir);
            std::env::set_var("XDG_DATA_HOME", &data_dir);
            std::env::set_var("TIRITH_LOG", "1");
        }

        let name_a = "a.txt";
        let name_b = "b.txt";

        let run = || -> Result<RestoreReport, String> {
            std::env::set_current_dir(&workdir).map_err(|e| format!("chdir: {e}"))?;
            fs::write(name_a, "original alpha").map_err(|e| format!("write a: {e}"))?;
            fs::write(name_b, "original bravo").map_err(|e| format!("write b: {e}"))?;
            let meta = create(&[name_a, name_b], Some("rm -rf project"))?;
            // Overwrite the live files; a successful restore must put the
            // original bytes back.
            fs::write(name_a, "MUTATED alpha").map_err(|e| format!("rewrite a: {e}"))?;
            fs::write(name_b, "MUTATED bravo").map_err(|e| format!("rewrite b: {e}"))?;
            restore_reported(&meta.id)
        };

        let result = run();
        let live_a = fs::read_to_string(workdir.join(name_a)).ok();
        let live_b = fs::read_to_string(workdir.join(name_b)).ok();
        let audit_log = crate::audit::audit_log_path();
        let audit_body = audit_log.as_ref().and_then(|p| fs::read_to_string(p).ok());

        // Restore cwd + env before assertions so cleanup runs even on failure.
        if let Some(dir) = prev_cwd {
            let _ = std::env::set_current_dir(dir);
        }
        unsafe {
            match prev_state {
                Some(v) => std::env::set_var("XDG_STATE_HOME", v),
                None => std::env::remove_var("XDG_STATE_HOME"),
            }
            match prev_data {
                Some(v) => std::env::set_var("XDG_DATA_HOME", v),
                None => std::env::remove_var("XDG_DATA_HOME"),
            }
            match prev_log {
                Some(v) => std::env::set_var("TIRITH_LOG", v),
                None => std::env::remove_var("TIRITH_LOG"),
            }
        }

        let report = result.expect("restore_reported should succeed");
        assert_eq!(
            report.attempted, 2,
            "two file entries processed: {report:?}"
        );
        assert!(
            report.restored.contains(&name_a.to_string())
                && report.restored.contains(&name_b.to_string()),
            "both files must restore cleanly: {report:?}"
        );
        assert!(report.missing.is_empty(), "no missing: {report:?}");
        assert!(report.corrupt.is_empty(), "no corrupt: {report:?}");
        assert!(report.errors.is_empty(), "no errors: {report:?}");

        // Live files restored to their original (checkpointed) bytes.
        assert_eq!(live_a.as_deref(), Some("original alpha"));
        assert_eq!(live_b.as_deref(), Some("original bravo"));

        // The restore audit record must have been emitted with restored=2.
        let body = audit_body.expect("audit log written");
        let line = body
            .lines()
            .find(|l| l.contains("snapshot_restore"))
            .expect("a snapshot_restore audit line must exist");
        let v: serde_json::Value = serde_json::from_str(line).expect("audit line is valid JSON");
        assert_eq!(v["integration"], "checkpoint");
        assert_eq!(v["hook_type"], "restore");
        assert_eq!(v["event"], "snapshot_restore");
        assert!(
            v["detail"]
                .as_str()
                .map(|d| d.contains("restored=2"))
                .unwrap_or(false),
            "restore audit detail must report restored=2: {v}"
        );
    }

    /// Security (A6): a checkpoint DIRECTORY that is itself a symlink must be
    /// refused before its manifest is read. The lexical parent-containment check
    /// does not catch a symlink AT `cp_dir`, so without this guard a planted link
    /// could redirect the restore at an attacker-controlled manifest outside the
    /// store. The restore must error out without reading through the link.
    #[cfg(unix)]
    #[test]
    fn test_restore_refuses_symlinked_checkpoint_dir() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let tmpdir = tempfile::tempdir().unwrap();
        let state_dir = tmpdir.path().join("state");
        let prev_state = std::env::var("XDG_STATE_HOME").ok();
        // SAFETY: serialized by crate::TEST_ENV_LOCK across all modules.
        unsafe { std::env::set_var("XDG_STATE_HOME", &state_dir) };

        let outcome = std::panic::catch_unwind(|| {
            let store = checkpoints_dir();
            fs::create_dir_all(&store).expect("create store");

            // An attacker-controlled checkpoint OUTSIDE the store, with a manifest
            // that would restore to an arbitrary absolute path if followed.
            let evil = tmpdir.path().join("evil-checkpoint");
            fs::create_dir_all(evil.join("files")).expect("create evil dir");
            let evil_manifest = serde_json::to_string(&vec![ManifestEntry {
                original_path: "/tmp/should-not-be-written".to_string(),
                sha256: empty_sha256(),
                size: 0,
                is_dir: false,
            }])
            .unwrap();
            fs::write(evil.join("manifest.json"), evil_manifest).expect("write evil manifest");

            // Plant `cp_dir` as a SYMLINK to the evil directory. Its lexical parent
            // is still the store, so the parent-containment check alone passes.
            let id = "symlinked-cp";
            let cp_dir = store.join(id);
            std::os::unix::fs::symlink(&evil, &cp_dir).expect("plant symlink cp_dir");
            assert_eq!(
                cp_dir.parent(),
                Some(store.as_path()),
                "the symlink's lexical parent is the store"
            );

            let res = restore_reported(id);
            assert!(
                res.is_err(),
                "a symlinked checkpoint directory must be refused: {res:?}"
            );
            let msg = res.unwrap_err();
            assert!(
                msg.contains("symlinked checkpoint directory"),
                "the error must name the symlink guard: {msg}"
            );
            // The guarded restore must NOT have written the evil target.
            assert!(
                !Path::new("/tmp/should-not-be-written").exists(),
                "restore must not write through the symlinked checkpoint dir"
            );
        });

        // SAFETY: serialized by crate::TEST_ENV_LOCK; restore regardless.
        unsafe {
            match prev_state {
                Some(v) => std::env::set_var("XDG_STATE_HOME", v),
                None => std::env::remove_var("XDG_STATE_HOME"),
            }
        }
        if let Err(e) = outcome {
            std::panic::resume_unwind(e);
        }
    }

    /// Security: a restore destination that has become a symlink (e.g. an
    /// attacker repointed it at a file outside the working tree) must be REFUSED.
    /// `fs::copy` follows destination symlinks, so without the guard the restored
    /// bytes would be written through the link. The entry must land in `errors`
    /// and the symlink's target file must be left untouched.
    #[cfg(unix)]
    #[test]
    fn test_restore_refuses_symlinked_destination() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let tmpdir = tempfile::tempdir().unwrap();
        let workdir = tmpdir.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        // The sentinel lives OUTSIDE the workdir; a followed symlink would clobber it.
        let outside = tmpdir.path().join("outside_secret.txt");
        fs::write(&outside, "SENTINEL DO NOT OVERWRITE").unwrap();

        let state_dir = tmpdir.path().join("state");
        let prev_state = std::env::var("XDG_STATE_HOME").ok();
        let prev_log = std::env::var("TIRITH_LOG").ok();
        let prev_cwd = std::env::current_dir().ok();
        // SAFETY: serialized by crate::TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", &state_dir);
            std::env::set_var("TIRITH_LOG", "0");
        }

        let name = "victim.txt";
        let outside_for_run = outside.clone();
        let run = || -> Result<RestoreReport, String> {
            std::env::set_current_dir(&workdir).map_err(|e| format!("chdir: {e}"))?;
            fs::write(name, "checkpointed bytes").map_err(|e| format!("write: {e}"))?;
            let meta = create(&[name], Some("rm -rf project"))?;
            // Remove the live file and replace it with a symlink that escapes the
            // tree, pointing at the sentinel. A naive `fs::copy` would follow it.
            fs::remove_file(name).map_err(|e| format!("rm: {e}"))?;
            std::os::unix::fs::symlink(&outside_for_run, name)
                .map_err(|e| format!("symlink: {e}"))?;
            restore_reported(&meta.id)
        };

        let result = run();
        let sentinel_after = fs::read_to_string(&outside).ok();

        // Restore cwd + env before assertions so cleanup runs even on failure.
        if let Some(dir) = prev_cwd {
            let _ = std::env::set_current_dir(dir);
        }
        unsafe {
            match prev_state {
                Some(v) => std::env::set_var("XDG_STATE_HOME", v),
                None => std::env::remove_var("XDG_STATE_HOME"),
            }
            match prev_log {
                Some(v) => std::env::set_var("TIRITH_LOG", v),
                None => std::env::remove_var("TIRITH_LOG"),
            }
        }

        let report = result.expect("restore_reported should run");
        assert!(
            !report.restored.contains(&name.to_string()),
            "a symlinked destination must not be reported as restored: {report:?}"
        );
        assert!(
            report.errors.iter().any(|(p, msg)| p == name
                && (msg.contains("symlink") || msg.contains("symlinked"))),
            "the symlinked destination must be recorded as an error: {report:?}"
        );
        // The link target outside the tree must be byte-for-byte untouched.
        assert_eq!(
            sentinel_after.as_deref(),
            Some("SENTINEL DO NOT OVERWRITE"),
            "restore must NOT write through the symlink to the outside target"
        );
    }

    /// Regression: `create()` records `original_path` verbatim, so an absolute
    /// checkpoint path (what the auto-checkpoint feeds from an absolute cwd) must
    /// RESTORE, not be rejected as "restore path is absolute". The first such
    /// entry must also not abort the whole report.
    #[cfg(unix)]
    #[test]
    fn test_restore_reported_absolute_path_restores() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let tmpdir = tempfile::tempdir().unwrap();
        let state_dir = tmpdir.path().join("state");
        let prev_state = std::env::var("XDG_STATE_HOME").ok();
        let prev_log = std::env::var("TIRITH_LOG").ok();
        // SAFETY: serialized by crate::TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", &state_dir);
            std::env::set_var("TIRITH_LOG", "0");
        }

        // An ABSOLUTE path under the tempdir (not a symlink) — exactly the shape
        // create() records for an auto-checkpoint of an absolute target. Canonicalize
        // the base first: on macOS the temp root is under `/var`, a symlink to
        // `/private/var`, which the (correct) symlinked-ancestor guard would
        // otherwise reject. Canonicalizing removes that incidental symlink so the
        // test exercises the absolute-path-allowed behavior, not the symlink guard.
        let work_dir = tmpdir.path().join("work");
        fs::create_dir_all(&work_dir).unwrap();
        let abs_file = fs::canonicalize(&work_dir).unwrap().join("data.txt");
        fs::write(&abs_file, "original bytes").unwrap();
        let abs_str = abs_file.to_string_lossy().to_string();

        let run = || -> Result<RestoreReport, String> {
            let meta = create(&[abs_str.as_str()], Some("rm -rf work"))?;
            // Mutate the live file so a successful restore is observable.
            fs::write(&abs_file, "MUTATED").map_err(|e| format!("rewrite: {e}"))?;
            restore_reported(&meta.id)
        };

        let result = run();
        let live = fs::read_to_string(&abs_file).ok();

        unsafe {
            match prev_state {
                Some(v) => std::env::set_var("XDG_STATE_HOME", v),
                None => std::env::remove_var("XDG_STATE_HOME"),
            }
            match prev_log {
                Some(v) => std::env::set_var("TIRITH_LOG", v),
                None => std::env::remove_var("TIRITH_LOG"),
            }
        }

        let report = result.expect("restore_reported should succeed");
        assert_eq!(
            report.attempted, 1,
            "the absolute entry is attempted: {report:?}"
        );
        assert!(
            report.restored.contains(&abs_str),
            "an absolute checkpoint path must restore, not be rejected: {report:?}"
        );
        assert!(
            report.errors.is_empty(),
            "a legitimate absolute path must not land in errors: {report:?}"
        );
        assert_eq!(
            live.as_deref(),
            Some("original bytes"),
            "the live file must be restored to its checkpointed bytes"
        );
    }

    // Gated to unix: the assertions use unix-style absolute path literals
    // ("/etc/hosts", "/capture/root"), and `Path::is_absolute` is false for a
    // leading-slash path on Windows (it needs a drive prefix), so the absolute
    // pass-through case does not hold there. `anchor_restore_dst` itself is
    // portable; this test only exercises its unix-path semantics.
    #[cfg(unix)]
    #[test]
    fn test_anchor_restore_dst_resolution() {
        // F6 unit: absolute paths pass through; relative paths anchor to the
        // capture root; a relative path with no root is rejected.
        let root = Path::new("/capture/root");
        // Absolute -> verbatim.
        assert_eq!(
            anchor_restore_dst("/etc/hosts", Some(root)).unwrap(),
            PathBuf::from("/etc/hosts")
        );
        // Relative -> anchored to the capture root.
        assert_eq!(
            anchor_restore_dst("sub/file.txt", Some(root)).unwrap(),
            PathBuf::from("/capture/root/sub/file.txt")
        );
        // Relative with NO root -> rejected (cannot anchor safely).
        assert!(
            anchor_restore_dst("sub/file.txt", None).is_err(),
            "a relative path with no capture root must be rejected"
        );
    }

    // F-followup: an absolute capture path running through a symlinked ancestor
    // (the macOS /tmp -> /private/tmp case) is normalized at capture so a later
    // restore is not falsely rejected by reject_symlinked_restore_dest.
    #[cfg(unix)]
    #[test]
    fn normalize_capture_path_resolves_absolute_ancestor_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let real = fs::canonicalize(tmp.path()).unwrap();
        let target = real.join("target");
        fs::create_dir(&target).unwrap();
        let link = real.join("alias");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let file = target.join("data.txt");
        fs::write(&file, b"x").unwrap();

        // Absolute path THROUGH the symlinked alias: parent symlink resolved,
        // final component kept, so it equals the real canonical file path.
        let through_link = link.join("data.txt");
        let normalized = normalize_capture_path(&through_link);
        assert_eq!(normalized, file.to_string_lossy());
        assert!(
            !normalized.contains("alias"),
            "ancestor symlink must be resolved at capture"
        );

        // Relative paths are left exactly as-is (they anchor to capture_root).
        assert_eq!(
            normalize_capture_path(Path::new("sub/file.txt")),
            "sub/file.txt"
        );
    }

    /// F6: a checkpoint created with RELATIVE paths must restore against the
    /// capture-time root, NOT the caller's cwd at restore time. Capturing in dir A
    /// and restoring while cwd is dir B must write into A/<name>, leaving B
    /// untouched. The old `dst = Path::new(&original_path)` resolved against the
    /// restore cwd, so it would have written into B and could clobber unrelated
    /// files there.
    #[cfg(unix)]
    #[test]
    fn test_restore_reported_relative_path_anchors_to_capture_root() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let tmpdir = tempfile::tempdir().unwrap();
        // Canonicalize so the macOS /var -> /private/var symlink does not trip the
        // symlinked-ancestor guard (same rationale as the absolute-path test).
        let base = fs::canonicalize(tmpdir.path()).unwrap();
        let dir_a = base.join("capture_here");
        let dir_b = base.join("restore_from_here");
        fs::create_dir_all(&dir_a).unwrap();
        fs::create_dir_all(&dir_b).unwrap();

        let state_dir = base.join("state");
        let prev_state = std::env::var("XDG_STATE_HOME").ok();
        let prev_log = std::env::var("TIRITH_LOG").ok();
        let prev_cwd = std::env::current_dir().ok();
        // SAFETY: serialized by crate::TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", &state_dir);
            std::env::set_var("TIRITH_LOG", "0");
        }

        let name = "note.txt";
        let run = || -> Result<RestoreReport, String> {
            // Capture in dir A with a RELATIVE name (capture_root := dir A).
            std::env::set_current_dir(&dir_a).map_err(|e| format!("chdir A: {e}"))?;
            fs::write(name, "captured bytes").map_err(|e| format!("write: {e}"))?;
            let meta = create(&[name], Some("rm -rf ."))?;
            // Mutate the live file in A so a successful restore is observable.
            fs::write(name, "MUTATED").map_err(|e| format!("rewrite: {e}"))?;
            // Restore from a DIFFERENT cwd (dir B).
            std::env::set_current_dir(&dir_b).map_err(|e| format!("chdir B: {e}"))?;
            restore_reported(&meta.id)
        };

        let result = run();
        let live_a = fs::read_to_string(dir_a.join(name)).ok();
        let leaked_b = dir_b.join(name).exists();

        if let Some(dir) = prev_cwd {
            let _ = std::env::set_current_dir(dir);
        }
        unsafe {
            match prev_state {
                Some(v) => std::env::set_var("XDG_STATE_HOME", v),
                None => std::env::remove_var("XDG_STATE_HOME"),
            }
            match prev_log {
                Some(v) => std::env::set_var("TIRITH_LOG", v),
                None => std::env::remove_var("TIRITH_LOG"),
            }
        }

        let report = result.expect("restore_reported should succeed");
        assert!(
            report.restored.contains(&name.to_string()),
            "the relative entry must restore (anchored to capture root): {report:?}"
        );
        assert_eq!(
            live_a.as_deref(),
            Some("captured bytes"),
            "the file in the CAPTURE dir must be restored to its checkpointed bytes"
        );
        assert!(
            !leaked_b,
            "restore must NOT write into the caller's cwd (dir B); it leaked there"
        );
    }

    /// F6: a relative manifest entry on a checkpoint whose meta.json has NO
    /// recorded capture_root (a pre-F6 checkpoint) cannot be anchored safely, so it
    /// must be bucketed into `errors` and NOT written into the caller's cwd.
    #[cfg(unix)]
    #[test]
    fn test_restore_reported_legacy_relative_without_root_is_rejected() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let tmpdir = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmpdir.path()).unwrap();
        let state_dir = base.join("state");
        let cwd_dir = base.join("caller_cwd");
        fs::create_dir_all(&cwd_dir).unwrap();

        let prev_state = std::env::var("XDG_STATE_HOME").ok();
        let prev_log = std::env::var("TIRITH_LOG").ok();
        let prev_cwd = std::env::current_dir().ok();
        // SAFETY: serialized by crate::TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", &state_dir);
            std::env::set_var("TIRITH_LOG", "0");
        }

        let name = "legacy.txt";
        let run = || -> Result<RestoreReport, String> {
            // Hand-build a pre-F6 checkpoint: meta.json WITHOUT capture_root, a
            // manifest with a RELATIVE original_path, and a matching blob.
            let cp_base = checkpoints_dir();
            let id = "legacy-no-root";
            let cp_dir = cp_base.join(id);
            let files_dir = cp_dir.join("files");
            fs::create_dir_all(&files_dir).map_err(|e| format!("mkdir: {e}"))?;

            let content = b"legacy content";
            let sha = {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(content);
                format!("{:x}", h.finalize())
            };
            fs::write(files_dir.join(&sha), content).map_err(|e| format!("blob: {e}"))?;

            // meta.json WITHOUT a capture_root key (legacy shape).
            let meta = serde_json::json!({
                "id": id,
                "created_at": chrono::Utc::now().to_rfc3339(),
                "trigger_command": "rm -rf .",
                "paths": [name],
                "total_bytes": content.len(),
                "file_count": 1
            });
            fs::write(cp_dir.join("meta.json"), meta.to_string())
                .map_err(|e| format!("meta: {e}"))?;

            let manifest = serde_json::json!([{
                "original_path": name,
                "sha256": sha,
                "size": content.len(),
                "is_dir": false
            }]);
            fs::write(cp_dir.join("manifest.json"), manifest.to_string())
                .map_err(|e| format!("manifest: {e}"))?;

            // Restore from a cwd where a leaked write would be observable.
            std::env::set_current_dir(&cwd_dir).map_err(|e| format!("chdir: {e}"))?;
            restore_reported(id)
        };

        let result = run();
        let leaked = cwd_dir.join(name).exists();

        if let Some(dir) = prev_cwd {
            let _ = std::env::set_current_dir(dir);
        }
        unsafe {
            match prev_state {
                Some(v) => std::env::set_var("XDG_STATE_HOME", v),
                None => std::env::remove_var("XDG_STATE_HOME"),
            }
            match prev_log {
                Some(v) => std::env::set_var("TIRITH_LOG", v),
                None => std::env::remove_var("TIRITH_LOG"),
            }
        }

        let report = result.expect("restore_reported should succeed");
        assert!(
            report.restored.is_empty(),
            "a non-anchorable relative entry must NOT restore: {report:?}"
        );
        assert!(
            report
                .errors
                .iter()
                .any(|(p, msg)| p == name && msg.contains("capture root")),
            "the legacy relative entry must be bucketed into errors: {report:?}"
        );
        assert!(
            !leaked,
            "restore must NOT write the legacy relative entry into the caller's cwd"
        );
    }

    #[test]
    fn test_create_and_purge_removes_expired() {
        // create_and_purge() must create a new checkpoint AND purge age-expired
        // ones in a single call.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let tmpdir = tempfile::tempdir().unwrap();
        let workdir = tmpdir.path().join("project");
        fs::create_dir_all(&workdir).unwrap();
        fs::write(workdir.join("file.txt"), "content").unwrap();

        let state_dir = tmpdir.path().join("state");

        let prev = std::env::var("XDG_STATE_HOME").ok();
        // SAFETY: serialized by crate::TEST_ENV_LOCK across all modules.
        unsafe { std::env::set_var("XDG_STATE_HOME", &state_dir) };

        // Seed an ancient checkpoint (60 days old, past the 30-day default).
        let cp_base = state_dir.join("tirith/checkpoints");
        let old_cp = cp_base.join("old-expired");
        let old_files = old_cp.join("files");
        fs::create_dir_all(&old_files).unwrap();

        let old_time = chrono::Utc::now() - chrono::Duration::days(60);
        let meta_json = serde_json::json!({
            "id": "old-expired",
            "created_at": old_time.to_rfc3339(),
            "trigger_command": "rm -rf old",
            "paths": ["/tmp/old"],
            "total_bytes": 8,
            "file_count": 1
        });
        fs::write(old_cp.join("meta.json"), meta_json.to_string()).unwrap();
        fs::write(old_files.join("dummy"), "old data").unwrap();
        let manifest = serde_json::json!([{
            "original_path": "old.txt",
            "sha256": "dummy",
            "size": 8,
            "is_dir": false
        }]);
        fs::write(old_cp.join("manifest.json"), manifest.to_string()).unwrap();
        assert!(old_cp.exists());

        let work_str = workdir.to_str().unwrap();
        let result = create_and_purge(&[work_str], Some("rm -rf tempstuff"));

        // Restore env before assertions so cleanup runs even on assertion failure.
        match prev {
            Some(val) => unsafe { std::env::set_var("XDG_STATE_HOME", val) },
            None => unsafe { std::env::remove_var("XDG_STATE_HOME") },
        }

        assert!(result.is_ok(), "create_and_purge failed: {result:?}");
        assert!(
            !old_cp.exists(),
            "expired checkpoint should have been purged"
        );
        let remaining: Vec<_> = fs::read_dir(&cp_base)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(
            remaining.len(),
            1,
            "exactly one new checkpoint should remain"
        );
    }

    // --- M10 ch2: `tirith watch` runtime-state diff -------------------------

    #[test]
    fn watch_flags_shell_rc_modification() {
        // Snapshot before, simulate an rc-file modification during the "run",
        // snapshot after → the PostRunShellRcModified rule must fire High.
        // Uses a tempdir as HOME; never mutates process-global env (libc race).
        let home = tempfile::tempdir().unwrap();
        let zshrc = home.path().join(".zshrc");
        fs::write(&zshrc, "alias ll='ls -la'\n").unwrap();

        let before = capture_runtime_state(home.path());

        // Simulate the watched command appending a persistence line.
        fs::write(&zshrc, "alias ll='ls -la'\nsource ~/.cache/evil.sh\n").unwrap();

        let after = capture_runtime_state(home.path());

        let (_state, modified) = diff_runtime_state(&before, &after);
        assert_eq!(
            modified,
            vec![".zshrc".to_string()],
            "the modified .zshrc must be detected"
        );

        let findings = findings_for_modified_rc(&modified);
        assert_eq!(findings.len(), 1, "exactly one rc-modified finding");
        assert_eq!(
            findings[0].rule_id,
            crate::verdict::RuleId::PostRunShellRcModified
        );
        assert_eq!(findings[0].severity, crate::verdict::Severity::High);
        assert_eq!(
            crate::verdict::action_from_findings(&findings),
            crate::verdict::Action::Block,
            "a High rc-modified finding must resolve to Block"
        );
    }

    #[test]
    fn watch_no_finding_when_rc_unchanged() {
        // A run that touches no rc file must produce zero findings (clean diff).
        let home = tempfile::tempdir().unwrap();
        fs::write(home.path().join(".bashrc"), "export EDITOR=vim\n").unwrap();

        // Diff a single captured snapshot against ITSELF. Capturing the live env
        // twice would race other test threads that mutate process-global env
        // (e.g. XDG_STATE_HOME) between the two reads; diffing one snapshot
        // against itself isolates the pure-diff contract we mean to test here.
        let snap = capture_runtime_state(home.path());

        let (state, modified) = diff_runtime_state(&snap, &snap);
        assert!(modified.is_empty(), "no rc file changed: {modified:?}");
        assert!(
            findings_for_modified_rc(&modified).is_empty(),
            "clean run must emit no findings"
        );
        // An unchanged snapshot adds nothing to env / PATH.
        assert!(state.env_vars_added.is_empty());
        assert!(state.path_dirs_added.is_empty());
        assert!(state.domains_contacted.is_empty());
    }

    #[test]
    fn watch_detects_new_rc_file_and_path_addition() {
        // A shell-rc file that did not exist before but appears after must be
        // flagged (appearance == modification-from-absent). Also exercises the
        // PATH set-difference on synthetic snapshots.
        let home = tempfile::tempdir().unwrap();
        // .zshrc absent at first snapshot.
        let before = capture_runtime_state(home.path());
        assert_eq!(
            before.shell_rc_hashes.get(".zshrc").map(String::as_str),
            Some(super::empty_sha256().as_str()),
            "absent rc file recorded with empty-string sha"
        );

        // The watched command creates ~/.zshrc.
        fs::write(home.path().join(".zshrc"), "export FOO=1\n").unwrap();
        let after = capture_runtime_state(home.path());

        let (_state, modified) = diff_runtime_state(&before, &after);
        assert!(
            modified.contains(&".zshrc".to_string()),
            "a newly-created rc file must be flagged: {modified:?}"
        );

        // PATH set-difference: construct two snapshots that differ only in PATH.
        let mut b = before.clone();
        let mut a = before.clone();
        b.path_dirs = vec!["/usr/bin".to_string(), "/bin".to_string()];
        a.path_dirs = vec![
            "/usr/bin".to_string(),
            "/bin".to_string(),
            "/opt/evil/bin".to_string(),
        ];
        let (state, _m) = diff_runtime_state(&b, &a);
        assert_eq!(
            state.path_dirs_added,
            vec!["/opt/evil/bin".to_string()],
            "only the newly-added PATH dir is reported"
        );
    }

    #[test]
    fn test_validate_checkpoint_id_rejects_traversal_and_absolute() {
        // F10: the id is an unconstrained CLI argument joined onto the store path,
        // so a traversal/absolute id could select attacker-controlled state. Only
        // a single-component basename (the UUID create() assigns) is accepted.
        assert!(validate_checkpoint_id("").is_err(), "empty id");
        assert!(
            validate_checkpoint_id("../../etc").is_err(),
            "parent-dir traversal must be rejected"
        );
        assert!(
            validate_checkpoint_id("..").is_err(),
            "bare .. must be rejected"
        );
        assert!(
            validate_checkpoint_id("a/b").is_err(),
            "a path separator must be rejected"
        );
        assert!(
            validate_checkpoint_id("a\\b").is_err(),
            "a backslash separator must be rejected"
        );
        assert!(
            validate_checkpoint_id("/tmp/evil").is_err(),
            "an absolute id must be rejected"
        );
        assert!(
            validate_checkpoint_id(".").is_err(),
            "current-dir must be rejected"
        );
        // A legitimate UUID-style basename is accepted.
        let uuid = uuid::Uuid::new_v4().to_string();
        assert!(
            validate_checkpoint_id(&uuid).is_ok(),
            "a UUID basename must be accepted"
        );
        assert!(
            validate_checkpoint_id("1234-5678").is_ok(),
            "a plain single-component name must be accepted"
        );
    }

    #[test]
    fn test_restore_reported_rejects_traversal_id() {
        // F10 end-to-end: `restore_reported` must reject a traversal/absolute id
        // up front (before reading any manifest), so an attacker cannot point the
        // restore at a checkpoint directory outside the store.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmpdir = tempfile::tempdir().unwrap();
        let state_dir = tmpdir.path().join("state");
        let prev_state = std::env::var("XDG_STATE_HOME").ok();
        // SAFETY: serialized by crate::TEST_ENV_LOCK across all modules.
        unsafe { std::env::set_var("XDG_STATE_HOME", &state_dir) };

        let traversal = restore_reported("../../../../etc");
        let absolute = restore_reported("/tmp/evil");

        match prev_state {
            Some(v) => unsafe { std::env::set_var("XDG_STATE_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_STATE_HOME") },
        }

        assert!(
            traversal.is_err(),
            "a traversal id must be rejected by restore_reported"
        );
        assert!(
            absolute.is_err(),
            "an absolute id must be rejected by restore_reported"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_copy_no_follow_refuses_symlinked_destination() {
        // F5/C4: the destination write must NOT follow a symlink at the final
        // component (closing the TOCTOU window that plain `fs::copy` would leave
        // open). `copy_no_follow_from_reader` opens with O_NOFOLLOW, so a symlinked
        // dst is refused and the link target outside the tree is left untouched.
        let tmpdir = tempfile::tempdir().unwrap();
        let src = tmpdir.path().join("src.txt");
        fs::write(&src, "restored bytes").unwrap();

        let outside = tmpdir.path().join("outside_secret.txt");
        fs::write(&outside, "SENTINEL DO NOT OVERWRITE").unwrap();

        // dst is a symlink pointing at the outside sentinel.
        let dst = tmpdir.path().join("dst.txt");
        std::os::unix::fs::symlink(&outside, &dst).unwrap();

        let mut blob = fs::File::open(&src).unwrap();
        let result = copy_no_follow_from_reader(&mut blob, &dst);
        assert!(
            result.is_err(),
            "copy_no_follow_from_reader must refuse to write through a symlinked destination"
        );
        assert_eq!(
            fs::read_to_string(&outside).ok().as_deref(),
            Some("SENTINEL DO NOT OVERWRITE"),
            "the symlink target outside the tree must be untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_copy_no_follow_writes_regular_destination() {
        // The happy path of the no-follow write: a regular (or absent) destination
        // is created/overwritten with the source bytes read from the open handle.
        let tmpdir = tempfile::tempdir().unwrap();
        let src = tmpdir.path().join("src.txt");
        fs::write(&src, "hello no-follow").unwrap();
        let dst = tmpdir.path().join("dst.txt");

        let mut blob = fs::File::open(&src).unwrap();
        copy_no_follow_from_reader(&mut blob, &dst)
            .expect("copy to a regular destination must succeed");
        assert_eq!(
            fs::read_to_string(&dst).unwrap(),
            "hello no-follow",
            "the destination must contain the source bytes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_copy_no_follow_from_reader_copies_from_seek_position() {
        // C4: the restore path hashes the blob through the handle, then rewinds to
        // 0 and copies from the SAME handle. Verify the copy honours the current
        // seek position: reading the handle to EOF (as the hash does) then rewinding
        // must still copy the FULL contents, and copying without rewinding (from
        // EOF) copies nothing. This is exactly the same-handle guarantee the restore
        // loop relies on.
        let tmpdir = tempfile::tempdir().unwrap();
        let src = tmpdir.path().join("blob");
        fs::write(&src, "verified bytes").unwrap();

        let mut blob = fs::File::open(&src).unwrap();
        // Drain to EOF like the hash step does.
        let _ = sha256_reader(&mut blob).unwrap();

        // Without rewinding, the handle is at EOF: a copy yields an empty file.
        let dst_eof = tmpdir.path().join("dst_eof");
        copy_no_follow_from_reader(&mut blob, &dst_eof).unwrap();
        assert_eq!(
            fs::read_to_string(&dst_eof).unwrap(),
            "",
            "copying from an unrewound (EOF) handle writes nothing"
        );

        // After rewinding to 0, the copy writes the full verified bytes.
        blob.seek(SeekFrom::Start(0)).unwrap();
        let dst_full = tmpdir.path().join("dst_full");
        copy_no_follow_from_reader(&mut blob, &dst_full).unwrap();
        assert_eq!(
            fs::read_to_string(&dst_full).unwrap(),
            "verified bytes",
            "after rewind, the copy writes the same bytes that were hashed"
        );
    }
}
