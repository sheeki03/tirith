//! Filesystem helpers for `tirith setup` — atomic writes, hook scripts,
//! directory validation, CLI subprocess runner, and backup management.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

// ── Atomic write ───────────────────────────────────────────────────────

/// Write `content` to `path` atomically via temp+rename.
///
/// Uses `O_EXCL` (`create_new`) to prevent clobbering stale temp files.
/// Retries up to 3 times on collision. If `path` already exists as a
/// regular file, its permissions are preserved; otherwise `mode` is used.
/// Refuses to overwrite a symlink target.
pub fn atomic_write(path: &Path, content: &str, mode: u32) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("no parent directory for {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|e| format!("create dirs {}: {e}", parent.display()))?;

    // Determine mode: preserve existing file permissions or use default
    let effective_mode = match fs::metadata(path) {
        Ok(meta) => meta.permissions().mode() & 0o7777,
        Err(_) => mode,
    };

    // Generate unique temp file name: PID + monotonic counter
    static COUNTER: AtomicU32 = AtomicU32::new(0);

    let tmp = {
        let mut tmp_path;
        let mut f_result;

        // First attempt
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        tmp_path = parent.join(format!(".tirith-setup-{}-{}.tmp", std::process::id(), n));
        f_result = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path);

        // Retry up to 3 times on collision (stale temp from previous crash)
        for _ in 0..3 {
            if f_result.is_ok() {
                break;
            }
            let n2 = COUNTER.fetch_add(1, Ordering::Relaxed);
            tmp_path = parent.join(format!(".tirith-setup-{}-{}.tmp", std::process::id(), n2));
            f_result = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path);
        }

        use std::io::Write;
        let mut f = f_result.map_err(|e| format!("create tmp {}: {e}", tmp_path.display()))?;
        f.write_all(content.as_bytes()).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            format!("write tmp: {e}")
        })?;
        tmp_path
    };

    fs::set_permissions(&tmp, fs::Permissions::from_mode(effective_mode)).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("chmod {}: {e}", tmp.display())
    })?;

    // Symlink safety: refuse to overwrite a symlink target (or broken symlink).
    // Always use symlink_metadata — path.exists() misses broken symlinks.
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let _ = fs::remove_file(&tmp);
            return Err(format!(
                "{} is a symlink — refusing to overwrite for safety",
                path.display()
            ));
        }
        Ok(_) => {} // Regular file or directory — proceed
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // New file — safe
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            return Err(format!("stat {}: {e}", path.display()));
        }
    }

    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("rename {} -> {}: {e}", tmp.display(), path.display())
    })?;

    Ok(())
}

// ── Write hook script ──────────────────────────────────────────────────

/// Write a hook script with executable permissions.
///
/// - Hard-errors if `path` is a symlink (even with `--force`).
/// - If file exists with matching content: skip (but verify 0o755 mode).
/// - If file exists with different content: error without `--force`, overwrite with `--force`.
/// - After write, always enforce mode 0o755.
/// - Dry-run: print what would happen, write nothing.
pub fn write_hook_script(
    path: &Path,
    content: &str,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    // Symlink check first (always, even in dry-run — safety violation)
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "{} is a symlink — refusing to modify for safety",
                path.display()
            ));
        }
    }

    // Check existing content
    if path.exists() {
        let existing =
            fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        if existing == content {
            // Content matches — verify mode
            if !dry_run {
                let meta =
                    fs::metadata(path).map_err(|e| format!("stat {}: {e}", path.display()))?;
                if meta.permissions().mode() & 0o777 != 0o755 {
                    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
                        .map_err(|e| format!("chmod {}: {e}", path.display()))?;
                    eprintln!(
                        "tirith: {} already configured, fixed permissions",
                        path.display()
                    );
                } else {
                    eprintln!("tirith: {} already configured, up to date", path.display());
                }
            } else {
                eprintln!(
                    "[dry-run] would skip {} (already up to date)",
                    path.display()
                );
            }
            return Ok(());
        }

        // Content differs
        if !force {
            if dry_run {
                eprintln!(
                    "[dry-run] would error: {} exists but content differs — use --force to update",
                    path.display()
                );
                return Ok(());
            }
            return Err(format!(
                "{} exists but content differs — use --force to update",
                path.display()
            ));
        }
    }

    // Write the file
    if dry_run {
        eprintln!(
            "[dry-run] would write {} ({} bytes, mode 0755)",
            path.display(),
            content.len()
        );
        return Ok(());
    }

    atomic_write(path, content, 0o755)?;

    // Always enforce 0o755 (overrides permission preservation from atomic_write)
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("chmod {}: {e}", path.display()))?;

    eprintln!("tirith: wrote {}", path.display());
    Ok(())
}

// ── Directory validation ───────────────────────────────────────────────

/// Validate that `dir` stays within `scope_root` after canonicalization.
///
/// Walks up from `dir` to find the nearest existing ancestor, canonicalizes
/// it, and verifies it starts with the canonical `scope_root`. Also checks
/// each existing path component for symlinks within the scope.
pub fn validate_target_dir(dir: &Path, scope_root: Option<&Path>) -> Result<(), String> {
    let root = match scope_root {
        Some(r) => r,
        None => return Ok(()),
    };

    let root_canonical = root
        .canonicalize()
        .map_err(|e| format!("canonicalize {}: {e}", root.display()))?;

    // Walk up from dir to find nearest existing ancestor
    let mut check = dir.to_path_buf();
    loop {
        if check.exists() {
            let canonical = check
                .canonicalize()
                .map_err(|e| format!("canonicalize {}: {e}", check.display()))?;
            if !canonical.starts_with(&root_canonical) {
                return Err(format!(
                    "{} resolves outside project root {} — refusing for safety",
                    dir.display(),
                    root.display()
                ));
            }
            break;
        }
        if !check.pop() {
            return Err(format!(
                "cannot resolve {} — no existing ancestor found",
                dir.display()
            ));
        }
    }

    // Check each component for symlinks inside scope
    let mut path_so_far = PathBuf::new();
    for component in dir.components() {
        path_so_far.push(component);
        if path_so_far.exists() {
            if let Ok(meta) = fs::symlink_metadata(&path_so_far) {
                if meta.file_type().is_symlink() && path_so_far.starts_with(&root_canonical) {
                    return Err(format!(
                        "{} is a symlink inside project scope — refusing for safety",
                        path_so_far.display()
                    ));
                }
            }
        }
    }

    Ok(())
}

// ── CLI subprocess runner ──────────────────────────────────────────────

/// Run a CLI subprocess with 30s timeout and sanitized env.
///
/// Spawns the command, drains stdout/stderr in background threads to prevent
/// pipe-buffer deadlock, and polls with `try_wait()` against a 30s deadline.
/// On timeout or error: `kill()` + `wait()` to fully reap (no zombie).
pub fn run_cli(cmd: &str, args: &[&str]) -> Result<std::process::Output, String> {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let mut child = Command::new(cmd)
        .args(args)
        .env_remove("TERM")
        .env_remove("COLORTERM")
        .env_remove("GPG_TTY")
        .env_remove("EDITOR")
        .env_remove("VISUAL")
        .env_remove("PAGER")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{cmd} not found or failed to start: {e}"))?;

    // Take pipe handles — child retains the process handle for wait/kill
    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    // Drain pipes in background threads (prevents pipe-buffer deadlock)
    let mut stdout_thread = Some(std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut h) = stdout_handle {
            let _ = h.read_to_end(&mut buf);
        }
        buf
    }));
    let mut stderr_thread = Some(std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut h) = stderr_handle {
            let _ = h.read_to_end(&mut buf);
        }
        buf
    }));

    // Poll child with timeout
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait(); // Reap zombie
                    if let Some(t) = stdout_thread.take() {
                        let _ = t.join();
                    }
                    if let Some(t) = stderr_thread.take() {
                        let _ = t.join();
                    }
                    break Err(format!("{cmd} timed out after 30s — check installation"));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                if let Some(t) = stdout_thread.take() {
                    let _ = t.join();
                }
                if let Some(t) = stderr_thread.take() {
                    let _ = t.join();
                }
                break Err(format!("{cmd} wait failed: {e}"));
            }
        }
    };

    match status {
        Ok(exit_status) => {
            let stdout_buf = stdout_thread
                .take()
                .and_then(|t| t.join().ok())
                .unwrap_or_default();
            let stderr_buf = stderr_thread
                .take()
                .and_then(|t| t.join().ok())
                .unwrap_or_default();
            Ok(std::process::Output {
                status: exit_status,
                stdout: stdout_buf,
                stderr: stderr_buf,
            })
        }
        Err(e) => Err(e),
    }
}

// ── Backup helpers ─────────────────────────────────────────────────────

/// Create a timestamped backup of `path` when `force` is true and the file exists.
///
/// Format: `{path}.tirith-backup-{YYYYMMDD-HHMMSS}`
/// Retention: keeps the 5 most recent backups, deletes older ones (best-effort).
pub fn create_backup(path: &Path, force: bool) -> Result<(), String> {
    if !force || !path.exists() {
        return Ok(());
    }

    let now = chrono::Local::now();
    let timestamp = now.format("%Y%m%d-%H%M%S");
    let backup_name = format!(
        "{}.tirith-backup-{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        timestamp
    );
    let backup_path = path
        .parent()
        .ok_or_else(|| format!("no parent for {}", path.display()))?
        .join(&backup_name);

    fs::copy(path, &backup_path).map_err(|e| {
        format!(
            "backup {} -> {}: {e}",
            path.display(),
            backup_path.display()
        )
    })?;
    eprintln!("tirith: backup at {}", backup_path.display());

    // Retention: keep 5 most recent, delete older (best-effort)
    cleanup_old_backups(path);

    Ok(())
}

/// Create a timestamped backup unconditionally (not gated on `--force`).
///
/// Used for high-value user files like VS Code settings.json where any
/// modification (even first-time insertion) warrants a backup.
pub fn create_backup_always(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }

    let now = chrono::Local::now();
    let timestamp = now.format("%Y%m%d-%H%M%S");
    let backup_name = format!(
        "{}.tirith-backup-{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        timestamp
    );
    let backup_path = path
        .parent()
        .ok_or_else(|| format!("no parent for {}", path.display()))?
        .join(&backup_name);

    fs::copy(path, &backup_path).map_err(|e| {
        format!(
            "backup {} -> {}: {e}",
            path.display(),
            backup_path.display()
        )
    })?;
    eprintln!("tirith: backup at {}", backup_path.display());

    cleanup_old_backups(path);

    Ok(())
}

/// Remove old backup files, keeping only the 5 most recent.
fn cleanup_old_backups(path: &Path) {
    let parent = match path.parent() {
        Some(p) => p,
        None => return,
    };
    let stem = match path.file_name() {
        Some(n) => n.to_string_lossy().to_string(),
        None => return,
    };
    let prefix = format!("{stem}.tirith-backup-");

    let mut backups: Vec<PathBuf> = match fs::read_dir(parent) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
            .map(|e| e.path())
            .collect(),
        Err(_) => return,
    };

    if backups.len() <= 5 {
        return;
    }

    // Sort by name (timestamp is embedded, lexicographic order = chronological)
    backups.sort();
    let to_remove = backups.len() - 5;
    for old in &backups[..to_remove] {
        if let Err(e) = fs::remove_file(old) {
            eprintln!("tirith: could not clean old backup {}: {e}", old.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        atomic_write(&path, "hello", 0o644).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn atomic_write_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        fs::write(&target, "original").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = atomic_write(&link, "evil", 0o644);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("symlink"));
        // Original untouched
        assert_eq!(fs::read_to_string(&target).unwrap(), "original");
    }

    #[test]
    fn atomic_write_preserves_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("strict.txt");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        atomic_write(&path, "new", 0o644).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600); // Preserved, not overwritten to 0o644
    }

    #[test]
    fn write_hook_script_skip_on_same_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hook.sh");
        fs::write(&path, "#!/bin/bash\necho hi").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();

        // Should skip (same content)
        write_hook_script(&path, "#!/bin/bash\necho hi", false, false).unwrap();
    }

    #[test]
    fn write_hook_script_errors_on_different_content_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hook.sh");
        fs::write(&path, "old content").unwrap();

        let result = write_hook_script(&path, "new content", false, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("content differs"));
    }

    #[test]
    fn write_hook_script_overwrites_with_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hook.sh");
        fs::write(&path, "old content").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        write_hook_script(&path, "new content", true, false).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new content");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn write_hook_script_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.sh");
        fs::write(&target, "original").unwrap();
        let link = dir.path().join("link.sh");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = write_hook_script(&link, "evil", true, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("symlink"));
    }

    #[test]
    fn validate_target_dir_accepts_normal_path() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("subdir");
        validate_target_dir(&target, Some(dir.path())).unwrap();
    }

    #[test]
    fn validate_target_dir_rejects_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        let evil = tempfile::tempdir().unwrap();

        // Create a symlink inside dir that points outside
        let link = dir.path().join("escape");
        std::os::unix::fs::symlink(evil.path(), &link).unwrap();

        let target = link.join("subdir");
        let result = validate_target_dir(&target, Some(dir.path()));
        assert!(result.is_err());
    }

    #[test]
    fn backup_creates_and_retains_five() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, "data").unwrap();

        // Create 7 backups
        for i in 0..7 {
            let name = format!("config.json.tirith-backup-20260101-00000{i}");
            fs::write(dir.path().join(&name), "backup").unwrap();
        }

        // Run cleanup
        cleanup_old_backups(&path);

        let count = fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains("tirith-backup")
            })
            .count();
        assert_eq!(count, 5);
    }
}
