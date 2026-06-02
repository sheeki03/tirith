//! Checkpoint/rollback: file-level snapshots taken before destructive commands
//! (`rm -rf`, `git reset --hard`, …) so users can recover destroyed work.
//!
//! Storage: `$XDG_STATE_HOME/tirith/checkpoints/<uuid>/` — `meta.json`
//! (metadata), `files/` (contents, named by SHA-256), `manifest.json`
//! (path → SHA-256 for restore).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
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

/// Validate that a restore path does not contain path traversal components
/// or absolute paths.
fn validate_restore_path(path: &str) -> Result<(), String> {
    let p = Path::new(path);
    // `Path::is_absolute()` on Windows only matches paths with a drive letter,
    // so also reject Unix-style absolute paths explicitly on all platforms.
    if p.is_absolute() || path.starts_with('/') {
        return Err(format!("restore path is absolute: {path}"));
    }
    for component in p.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(format!("restore path contains '..': {path}"));
        }
    }
    Ok(())
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

/// Restore files from a checkpoint.
pub fn restore(checkpoint_id: &str) -> Result<Vec<String>, String> {
    require_pro()?;
    let cp_dir = checkpoints_dir().join(checkpoint_id);
    if !cp_dir.exists() {
        return Err(format!("checkpoint not found: {checkpoint_id}"));
    }

    let manifest_str = fs::read_to_string(cp_dir.join("manifest.json"))
        .map_err(|e| format!("read manifest: {e}"))?;
    let manifest: Vec<ManifestEntry> =
        serde_json::from_str(&manifest_str).map_err(|e| format!("parse manifest: {e}"))?;

    let files_dir = cp_dir.join("files");
    let mut restored = Vec::new();

    for entry in &manifest {
        if entry.is_dir {
            continue; // Directories are created implicitly when their children restore.
        }

        validate_restore_path(&entry.original_path)?;
        validate_sha256_filename(&entry.sha256)?;

        let src = files_dir.join(&entry.sha256);
        if !src.exists() {
            eprintln!(
                "tirith: checkpoint restore: missing data for {}",
                entry.original_path
            );
            continue;
        }

        let dst = Path::new(&entry.original_path);
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "restore {}: cannot create parent dir: {e}",
                    entry.original_path
                )
            })?;
        }

        fs::copy(&src, dst).map_err(|e| format!("restore {}: {e}", entry.original_path))?;
        restored.push(entry.original_path.clone());
    }

    Ok(restored)
}

/// Get diff between checkpoint and current filesystem state.
pub fn diff(checkpoint_id: &str) -> Result<Vec<DiffEntry>, String> {
    require_pro()?;
    let cp_dir = checkpoints_dir().join(checkpoint_id);
    if !cp_dir.exists() {
        return Err(format!("checkpoint not found: {checkpoint_id}"));
    }

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
        original_path: path.to_string_lossy().to_string(),
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
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).map_err(|e| format!("read: {e}"))?;
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
        assert!(validate_restore_path("../../etc/passwd").is_err());
        assert!(validate_restore_path("/tmp/../etc/evil").is_err());
        assert!(validate_restore_path("normal/path/file.txt").is_ok());
        // Unix-style absolute paths must be rejected on all platforms
        assert!(
            validate_restore_path("/absolute/path/file.txt").is_err(),
            "absolute paths should be rejected"
        );
        assert!(
            validate_restore_path("/etc/passwd").is_err(),
            "absolute paths should be rejected"
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
}
