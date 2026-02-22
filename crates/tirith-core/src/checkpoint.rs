//! Checkpoint/rollback system for protecting against destructive operations.
//!
//! Creates file-level snapshots before destructive commands (`rm -rf`, `git reset --hard`, etc.)
//! so users can recover accidentally destroyed work.
//!
//! Storage: `$XDG_STATE_HOME/tirith/checkpoints/<uuid>/`
//!   - `meta.json`: checkpoint metadata (timestamp, paths, trigger command)
//!   - `files/`: preserved file contents (original directory structure flattened to SHA-256 names)
//!   - `manifest.json`: path → SHA-256 mapping for restore

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Check if the current license tier permits checkpoint operations.
/// Returns `Ok(())` if Pro or above, `Err(message)` otherwise.
fn require_pro() -> Result<(), String> {
    let tier = crate::license::current_tier();
    if tier >= crate::license::Tier::Pro {
        Ok(())
    } else {
        Err(format!(
            "Checkpoint features require a Pro license (current tier: {tier})."
        ))
    }
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
        // Also catch `mv` that overwrites (mv src dst where dst exists)
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

/// Validate that a checkpoint ID is safe to use in filesystem paths.
/// Rejects path traversal attempts (`..`, `/`, `\`) and empty strings.
fn validate_checkpoint_id(id: &str) -> Result<(), String> {
    if id.is_empty()
        || id.contains("..")
        || id.contains('/')
        || id.contains('\\')
        || id.contains('\0')
    {
        return Err(format!("Invalid checkpoint ID: {id}"));
    }
    Ok(())
}

/// Get the checkpoints directory.
pub fn checkpoints_dir() -> PathBuf {
    crate::policy::state_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp/tirith"))
        .join("checkpoints")
}

/// Maximum number of files allowed in a single checkpoint.
const CHECKPOINT_MAX_FILES: usize = 1_000;
/// Maximum total size (bytes) allowed in a single checkpoint (50 MiB).
const CHECKPOINT_MAX_TOTAL_BYTES: u64 = 50 * 1024 * 1024;

/// Create a checkpoint of the given paths. Requires Pro tier (ADR-6: gate in core).
pub fn create(paths: &[&str], trigger_command: Option<&str>) -> Result<CheckpointMeta, String> {
    require_pro()?;
    let base_dir = checkpoints_dir();
    let id = uuid::Uuid::new_v4().to_string();
    let cp_dir = base_dir.join(&id);
    let files_dir = cp_dir.join("files");

    fs::create_dir_all(&files_dir).map_err(|e| format!("create checkpoint dir: {e}"))?;

    let mut manifest: Vec<ManifestEntry> = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut limit_exceeded = false;

    for path_str in paths {
        if limit_exceeded {
            break;
        }
        let path = Path::new(path_str);
        if !path.exists() {
            continue;
        }

        if path.is_file() {
            if manifest.len() >= CHECKPOINT_MAX_FILES {
                eprintln!(
                    "tirith: checkpoint: file limit ({CHECKPOINT_MAX_FILES}) exceeded, skipping checkpoint"
                );
                limit_exceeded = true;
                break;
            }
            match backup_file(path, &files_dir) {
                Ok(entry) => {
                    total_bytes += entry.size;
                    if total_bytes > CHECKPOINT_MAX_TOTAL_BYTES {
                        eprintln!(
                            "tirith: checkpoint: size limit ({} MiB) exceeded, skipping checkpoint",
                            CHECKPOINT_MAX_TOTAL_BYTES / (1024 * 1024)
                        );
                        limit_exceeded = true;
                        break;
                    }
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
                        if manifest.len() >= CHECKPOINT_MAX_FILES {
                            eprintln!(
                                "tirith: checkpoint: file limit ({CHECKPOINT_MAX_FILES}) exceeded, skipping checkpoint"
                            );
                            limit_exceeded = true;
                            break;
                        }
                        total_bytes += entry.size;
                        if total_bytes > CHECKPOINT_MAX_TOTAL_BYTES {
                            eprintln!(
                                "tirith: checkpoint: size limit ({} MiB) exceeded, skipping checkpoint",
                                CHECKPOINT_MAX_TOTAL_BYTES / (1024 * 1024)
                            );
                            limit_exceeded = true;
                            break;
                        }
                        manifest.push(entry);
                    }
                }
                Err(e) => {
                    eprintln!("tirith: checkpoint: skip dir {path_str}: {e}");
                }
            }
        }
    }

    // If limits were exceeded, clean up and abort the checkpoint
    if limit_exceeded {
        let _ = fs::remove_dir_all(&cp_dir);
        return Err("checkpoint skipped: file count or total size limit exceeded".to_string());
    }

    if manifest.is_empty() {
        // Clean up empty checkpoint dir
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

    // Write metadata
    let meta_json = serde_json::to_string_pretty(&meta).map_err(|e| format!("serialize: {e}"))?;
    fs::write(cp_dir.join("meta.json"), meta_json).map_err(|e| format!("write meta: {e}"))?;

    // Write manifest
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
            Err(_) => continue,
        };
        let meta_path = entry.path().join("meta.json");
        if !meta_path.exists() {
            continue;
        }
        let meta_str = match fs::read_to_string(&meta_path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let meta: CheckpointMeta = match serde_json::from_str(&meta_str) {
            Ok(m) => m,
            Err(_) => continue,
        };
        entries.push(CheckpointListEntry {
            id: meta.id,
            created_at: meta.created_at,
            trigger_command: meta.trigger_command,
            file_count: meta.file_count,
            total_bytes: meta.total_bytes,
        });
    }

    // Sort newest first
    entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(entries)
}

/// Restore files from a checkpoint. Requires Pro tier (ADR-6: gate in core).
pub fn restore(checkpoint_id: &str) -> Result<Vec<String>, String> {
    require_pro()?;
    validate_checkpoint_id(checkpoint_id)?;
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
            continue; // Directories are created implicitly
        }
        let src = files_dir.join(&entry.sha256);
        if !src.exists() {
            eprintln!(
                "tirith: checkpoint restore: missing data for {}",
                entry.original_path
            );
            continue;
        }

        let dst = Path::new(&entry.original_path);
        // Create parent directories
        if let Some(parent) = dst.parent() {
            let _ = fs::create_dir_all(parent);
        }

        fs::copy(&src, dst).map_err(|e| format!("restore {}: {e}", entry.original_path))?;
        restored.push(entry.original_path.clone());
    }

    Ok(restored)
}

/// Get diff between checkpoint and current filesystem state. Requires Pro tier (ADR-6: gate in core).
pub fn diff(checkpoint_id: &str) -> Result<Vec<DiffEntry>, String> {
    require_pro()?;
    validate_checkpoint_id(checkpoint_id)?;
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
    let mut seen_paths = std::collections::HashSet::new();

    for entry in &manifest {
        if entry.is_dir {
            continue;
        }
        let current_path = Path::new(&entry.original_path);
        if !current_path.exists() {
            seen_paths.insert(entry.original_path.clone());
            diffs.push(DiffEntry {
                path: entry.original_path.clone(),
                status: DiffStatus::Deleted,
                checkpoint_sha256: entry.sha256.clone(),
                current_sha256: None,
            });
            continue;
        }

        let current_sha = sha256_file(current_path).unwrap_or_default();
        if current_sha != entry.sha256 {
            seen_paths.insert(entry.original_path.clone());
            diffs.push(DiffEntry {
                path: entry.original_path.clone(),
                status: DiffStatus::Modified,
                checkpoint_sha256: entry.sha256.clone(),
                current_sha256: Some(current_sha),
            });
        }
        // If SHA matches, file unchanged — skip
    }

    // Check if checkpoint backup files still exist, but skip paths
    // already categorized in the first pass (e.g. Deleted or Modified).
    for entry in &manifest {
        if entry.is_dir {
            continue;
        }
        if seen_paths.contains(&entry.original_path) {
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
        }
    }

    Ok(diffs)
}

/// Purge old checkpoints based on configuration limits. Requires Pro tier (ADR-6: gate in core).
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

    // Remove by age
    let now = chrono::Utc::now();
    let max_age = chrono::Duration::days(config.max_age_days as i64);
    all.retain(|e| {
        if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&e.created_at) {
            let age = now.signed_duration_since(created);
            if age > max_age {
                let cp_dir = base_dir.join(&e.id);
                freed_bytes += e.total_bytes;
                let _ = fs::remove_dir_all(cp_dir);
                removed_count += 1;
                return false;
            }
        }
        true
    });

    // Remove by count (keep newest)
    while all.len() > config.max_count {
        if let Some(oldest) = all.pop() {
            let cp_dir = base_dir.join(&oldest.id);
            freed_bytes += oldest.total_bytes;
            let _ = fs::remove_dir_all(cp_dir);
            removed_count += 1;
        }
    }

    // Remove by total size (keep newest)
    let mut total: u64 = all.iter().map(|e| e.total_bytes).sum();
    while total > config.max_total_bytes && !all.is_empty() {
        if let Some(oldest) = all.pop() {
            total -= oldest.total_bytes;
            let cp_dir = base_dir.join(&oldest.id);
            freed_bytes += oldest.total_bytes;
            let _ = fs::remove_dir_all(cp_dir);
            removed_count += 1;
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

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Backup a single file to the checkpoint files directory.
fn backup_file(path: &Path, files_dir: &Path) -> Result<ManifestEntry, String> {
    let sha = sha256_file(path)?;
    let dst = files_dir.join(&sha);

    // Only copy if not already stored (dedup by content hash)
    if !dst.exists() {
        fs::copy(path, &dst).map_err(|e| format!("copy: {e}"))?;
    }

    let size = path.metadata().map(|m| m.len()).unwrap_or(0);

    Ok(ManifestEntry {
        original_path: path.to_string_lossy().to_string(),
        sha256: sha,
        size,
        is_dir: false,
    })
}

/// Backup a directory recursively.
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
            Err(_) => continue,
        };
        let path = entry.path();

        if path.is_symlink() {
            continue; // Skip symlinks for safety
        }

        if path.is_file() {
            let size = path.metadata().map(|m| m.len()).unwrap_or(0);
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
            // Skip hidden directories (like .git)
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
        assert_eq!(entry.size, 11); // "hello world" = 11 bytes
        assert!(!entry.is_dir);

        // Verify the backed up file exists
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
        assert_eq!(entries.len(), 2, "should backup 2 files: {:?}", entries);
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
    fn test_validate_checkpoint_id_rejects_traversal() {
        assert!(validate_checkpoint_id("../../etc/passwd").is_err());
        assert!(validate_checkpoint_id("..").is_err());
        assert!(validate_checkpoint_id("foo/bar").is_err());
        assert!(validate_checkpoint_id("foo\\bar").is_err());
        assert!(validate_checkpoint_id("").is_err());
        assert!(validate_checkpoint_id("foo\0bar").is_err());
    }

    #[test]
    fn test_validate_checkpoint_id_accepts_valid() {
        assert!(validate_checkpoint_id("a1b2c3d4-e5f6-7890-abcd-ef1234567890").is_ok());
        assert!(validate_checkpoint_id("simple-id").is_ok());
        assert!(validate_checkpoint_id("checkpoint_123").is_ok());
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
}
