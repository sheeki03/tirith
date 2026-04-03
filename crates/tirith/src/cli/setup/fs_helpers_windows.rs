//! Windows filesystem helpers for `tirith setup`.
//!
//! Provides the same public API as `fs_helpers.rs` but without Unix-specific
//! permission handling. NTFS ACLs default to owner-only for user-created files,
//! so explicit chmod is unnecessary on Windows.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

// ── Atomic write ───────────────────────────────────────────────────────

/// Write `content` to `path` atomically via temp+rename.
///
/// The `mode` parameter is accepted for API compatibility but ignored on Windows
/// (NTFS ACLs handle permissions).
pub fn atomic_write(path: &Path, content: &str, _mode: u32) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("no parent directory for {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|e| format!("create dirs {}: {e}", parent.display()))?;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    let tmp = {
        let mut tmp_path;
        let mut f_result;

        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        tmp_path = parent.join(format!(".tirith-setup-{}-{}.tmp", std::process::id(), n));
        f_result = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path);

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

    // Symlink safety: refuse to overwrite a symlink target.
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let _ = fs::remove_file(&tmp);
            return Err(format!(
                "{} is a symlink — refusing to overwrite for safety",
                path.display()
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
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

/// Write a hook script. On Windows, executable permission is not needed
/// (executability is determined by file extension, not mode bits).
pub fn write_hook_script(
    path: &Path,
    content: &str,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    // Symlink check
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "{} is a symlink — refusing to modify for safety",
                path.display()
            ));
        }
    }

    if path.exists() {
        let existing =
            fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        if existing == content {
            if !dry_run {
                eprintln!("tirith: {} already configured, up to date", path.display());
            } else {
                eprintln!(
                    "[dry-run] would skip {} (already up to date)",
                    path.display()
                );
            }
            return Ok(());
        }

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

    if dry_run {
        eprintln!(
            "[dry-run] would write {} ({} bytes)",
            path.display(),
            content.len()
        );
        return Ok(());
    }

    atomic_write(path, content, 0)?;
    eprintln!("tirith: wrote {}", path.display());
    Ok(())
}

// ── Directory validation ───────────────────────────────────────────────

/// Validate that `dir` stays within `scope_root` after canonicalization.
pub fn validate_target_dir(dir: &Path, scope_root: Option<&Path>) -> Result<(), String> {
    let root = match scope_root {
        Some(r) => r,
        None => return Ok(()),
    };

    let root_canonical = root
        .canonicalize()
        .map_err(|e| format!("canonicalize {}: {e}", root.display()))?;

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
pub fn run_cli(cmd: &str, args: &[&str]) -> Result<std::process::Output, String> {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let mut child = Command::new(cmd)
        .args(args)
        .env_remove("TERM")
        .env_remove("COLORTERM")
        .env_remove("EDITOR")
        .env_remove("VISUAL")
        .env_remove("PAGER")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{cmd} not found or failed to start: {e}"))?;

    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

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

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
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
pub fn create_backup(path: &Path, force: bool) -> Result<(), String> {
    if !force || !path.exists() {
        return Ok(());
    }
    create_backup_impl(path)
}

/// Create a timestamped backup unconditionally.
pub fn create_backup_always(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    create_backup_impl(path)
}

fn create_backup_impl(path: &Path) -> Result<(), String> {
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

    backups.sort();
    let to_remove = backups.len() - 5;
    for old in &backups[..to_remove] {
        if let Err(e) = fs::remove_file(old) {
            eprintln!("tirith: could not clean old backup {}: {e}", old.display());
        }
    }
}
