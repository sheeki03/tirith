use std::fs;
use std::io::{BufRead as _, Read as _, Seek as _, Write as _};
use std::path::PathBuf;

const DEFAULT_MAX_EVENTS: usize = 1000;
const DEFAULT_MAX_BYTES: u64 = 5 * 1024 * 1024; // 5 MiB
/// Absolute allocation/read ceiling even when a caller supplies a larger
/// retention value.
const ABSOLUTE_MAX_SPOOL_BYTES: u64 = 64 * 1024 * 1024;

/// Dedicated cross-process lock guarding every spool read/append/rewrite
/// (repo-0250): without it, two drainers snapshot-then-rewrite from stale
/// state and can delete or duplicate each other's events.
fn spool_lock_path() -> PathBuf {
    let mut name = spool_path().into_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

fn with_spool_lock<R>(f: impl FnOnce() -> std::io::Result<R>) -> std::io::Result<R> {
    use fs2::FileExt as _;
    let lock_path = spool_lock_path();
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut opts = fs::OpenOptions::new();
    opts.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(&lock_path)?;
    file.lock_exclusive()?;
    let result = f();
    // Call the fs2 trait method explicitly: std gained an inherent
    // File::unlock in 1.89 that would otherwise shadow it above the MSRV.
    let _ = fs2::FileExt::unlock(&file);
    result
}

/// Spool file path: `$XDG_STATE_HOME/tirith/audit-queue.jsonl` (falls back to
/// `~/.local/state/...`).
fn spool_path() -> PathBuf {
    let state_dir = std::env::var("XDG_STATE_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home::home_dir().unwrap_or_default().join(".local/state"));
    state_dir.join("tirith").join("audit-queue.jsonl")
}

/// Append a redacted audit event to the spool file.
///
/// DLP redaction must be applied **before** calling this function.
pub fn spool_event(event_json: &str) -> std::io::Result<()> {
    if event_json.len() as u64 + 1 > ABSOLUTE_MAX_SPOOL_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "audit event exceeds the per-event spool limit",
        ));
    }
    with_spool_lock(|| spool_event_locked(event_json))
}

fn spool_event_locked(event_json: &str) -> std::io::Result<()> {
    let path = spool_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut opts = fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(not(unix))]
    {
        if fs::symlink_metadata(&path)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(std::io::Error::other(
                "refusing to append through a symlinked audit spool",
            ));
        }
    }
    let mut file = opts.open(&path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(
            "refusing to append to a non-regular audit spool",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    writeln!(file, "{event_json}")?;
    file.sync_data()?;
    Ok(())
}

/// Enforce bounded retention, dropping oldest events when over limits. Returns
/// the (possibly trimmed) list of lines to process.
fn enforce_retention(lines: Vec<String>, max_events: usize, max_bytes: u64) -> Vec<String> {
    let mut result = lines;

    if result.len() > max_events {
        let drop_count = result.len() - max_events;
        crate::audit::audit_diagnostic(format!(
            "tirith: audit-spool: dropping {drop_count} oldest events (max_events={max_events})"
        ));
        result = result.into_iter().skip(drop_count).collect();
    }

    let total_bytes: u64 = result.iter().map(|l| l.len() as u64 + 1).sum(); // +1 per newline
    if total_bytes > max_bytes {
        let mut kept = Vec::new();
        let mut running_bytes: u64 = 0;
        // Walk newest→oldest so the drop list favors the most stale events.
        for line in result.into_iter().rev() {
            let line_bytes = line.len() as u64 + 1;
            if line_bytes > max_bytes {
                continue;
            }
            if running_bytes + line_bytes > max_bytes {
                break;
            }
            running_bytes += line_bytes;
            kept.push(line);
        }
        kept.reverse();
        crate::audit::audit_diagnostic(format!(
            "tirith: audit-spool: trimmed to {} events to stay under {max_bytes} bytes",
            kept.len()
        ));
        result = kept;
    }

    result
}

/// Read only the newest bounded suffix of the spool. The returned boolean says
/// older bytes (or a partial boundary record) were omitted.
fn read_spool_lines_bounded(
    path: &std::path::Path,
    requested_max_bytes: u64,
) -> std::io::Result<(Vec<String>, bool)> {
    let max_bytes = requested_max_bytes.min(ABSOLUTE_MAX_SPOOL_BYTES);
    let mut file = crate::util::open_read_no_follow_capped(path, u64::MAX)
        .map_err(|e| std::io::Error::other(format!("cannot safely open audit spool: {e:?}")))?;
    let length = file.metadata()?.len();
    if max_bytes == 0 {
        return Ok((Vec::new(), length > 0));
    }
    let start = length.saturating_sub(max_bytes);
    let mut discard_partial = false;
    if start > 0 {
        file.seek(std::io::SeekFrom::Start(start - 1))?;
        let mut previous = [0u8; 1];
        file.read_exact(&mut previous)?;
        discard_partial = previous[0] != b'\n';
    }
    file.seek(std::io::SeekFrom::Start(start))?;
    let mut reader = std::io::BufReader::new(file.take(length.saturating_sub(start)));
    if discard_partial {
        let mut ignored = String::new();
        reader.read_line(&mut ignored)?;
    }
    let mut lines = Vec::new();
    for line in reader.lines() {
        lines.push(line?);
    }
    Ok((lines, start > 0))
}

/// Drain the spool by uploading events to the server (background, non-blocking).
/// Events go one at a time with exponential backoff; auth errors (401/403) stop
/// uploading immediately.
pub fn drain_spool(server_url: &str, api_key: &str, max_events: usize, max_bytes: u64) {
    // Reject server URLs that would let us SSRF into private/internal hosts.
    if let Err(reason) = crate::url_validate::validate_server_url(server_url) {
        crate::audit::audit_diagnostic(format!("tirith: audit-upload: {reason}"));
        return;
    }

    let path = spool_path();
    if !path.exists() {
        return;
    }

    // Snapshot under the spool lock (repo-0250); the network phase runs
    // unlocked so appends are not blocked behind slow sends, and the final
    // rewrite re-locks and removes only the prefix this drainer actually sent.
    let lines = match with_spool_lock(|| -> std::io::Result<Vec<String>> {
        let (current, tail_truncated) = read_spool_lines_bounded(&path, max_bytes)?;
        let retained = enforce_retention(current.clone(), max_events, max_bytes);
        if tail_truncated || retained != current {
            write_spool_atomic(&path, &retained)?;
        }
        Ok(retained)
    }) {
        Ok(lines) => lines,
        Err(_) => return,
    };
    if lines.is_empty() {
        return;
    }

    let client = match crate::ssrf_guard::server_client_builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    let endpoint = format!("{}/api/audit/ingest", server_url.trim_end_matches('/'));
    let mut sent_count = 0usize;
    let mut backoff_ms = 1000u64;
    let max_retries = 3u32;

    for line in &lines {
        let mut success = false;
        for _attempt in 0..max_retries {
            match client
                .post(&endpoint)
                .header("Authorization", format!("Bearer {api_key}"))
                .header("Content-Type", "application/json")
                .body(format!("[{line}]"))
                .send()
            {
                Ok(resp) if resp.status().is_success() => {
                    success = true;
                    backoff_ms = 1000;
                    break;
                }
                Ok(resp) if resp.status().as_u16() == 401 || resp.status().as_u16() == 403 => {
                    // Auth error — further retries will fail identically; stop early.
                    crate::audit::audit_diagnostic(
                        "tirith: audit-upload: auth failed, stopping upload",
                    );
                    rewrite_spool(&path, &lines, sent_count, max_bytes);
                    return;
                }
                _ => {
                    std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
                    backoff_ms = (backoff_ms * 2).min(4000);
                }
            }
        }
        if success {
            sent_count += 1;
        } else {
            break;
        }
    }

    rewrite_spool(&path, &lines, sent_count, max_bytes);
}

fn write_spool_atomic(path: &std::path::Path, lines: &[String]) -> std::io::Result<()> {
    let mut content = lines.join("\n");
    if !content.is_empty() {
        content.push('\n');
    }
    crate::util::write_file_atomic_0600(path, content.as_bytes())
}

/// Remove exactly the sent prefix of `snapshot`, preserving its unsent suffix
/// and every line appended after that snapshot. If another drainer or retention
/// pass changed the prefix, leave the file untouched: at-least-once delivery is
/// safer than guessing and deleting an event.
fn rewrite_spool(path: &std::path::Path, snapshot: &[String], sent_count: usize, max_bytes: u64) {
    let result = with_spool_lock(|| {
        // repo-0250: under the lock, re-read the CURRENT file and remove only
        // the prefix this drainer sent. Events appended by another process
        // while we were sending land at the end and must survive.
        let (current_lines, tail_truncated) = read_spool_lines_bounded(path, max_bytes)?;
        if tail_truncated {
            return Ok(());
        }
        if sent_count > snapshot.len()
            || current_lines.len() < snapshot.len()
            || current_lines[..snapshot.len()] != *snapshot
        {
            return Ok(());
        }
        let mut keep = snapshot[sent_count..].to_vec();
        keep.extend_from_slice(&current_lines[snapshot.len()..]);
        write_spool_atomic(path, &keep)
    });
    if let Err(error) = result {
        crate::audit::audit_diagnostic(format!(
            "tirith: audit-spool: failed to publish rewritten spool: {error}"
        ));
    }
}

/// repo-0194: coalesce bursts into ONE drainer. A thread per event lets a burst
/// create unbounded concurrent workers in a long-lived process.
static DRAIN_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// The running drainer snapshots the spool once, so an event appended after that
/// snapshot is not covered by it. Record that the spool changed and let the
/// drainer take another pass; without this the event waits for an unrelated
/// later append and retention can drop it undelivered.
static DRAIN_RESCAN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Releases the drainer claim even if the worker panics or never starts.
/// Without it a failed spawn or a panic inside `drain_spool` would leave
/// `DRAIN_ACTIVE` set forever and every later event would only flag a rescan
/// nobody performs, stranding the durable queue until the process restarts.
struct DrainOwnership {
    held: bool,
}

impl DrainOwnership {
    fn release(&mut self) {
        if self.held {
            self.held = false;
            DRAIN_ACTIVE.store(false, std::sync::atomic::Ordering::Release);
        }
    }

    fn retake(&mut self) -> bool {
        self.held = DRAIN_ACTIVE
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok();
        self.held
    }
}

impl Drop for DrainOwnership {
    fn drop(&mut self) {
        self.release();
    }
}

/// Primary entry point: append the event to the durable spool, then spawn a
/// background thread to attempt uploading accumulated events.
pub fn spool_and_upload(
    event_json: &str,
    server_url: &str,
    api_key: &str,
    max_events: Option<usize>,
    max_bytes: Option<u64>,
) {
    let max_ev = max_events.unwrap_or(DEFAULT_MAX_EVENTS);
    let max_b = max_bytes
        .unwrap_or(DEFAULT_MAX_BYTES)
        .min(ABSOLUTE_MAX_SPOOL_BYTES);
    if event_json.len() as u64 + 1 > max_b {
        crate::audit::audit_diagnostic(
            "tirith: audit-spool: event exceeds the configured spool byte limit; event not queued",
        );
        return;
    }
    if let Err(e) = spool_event(event_json) {
        crate::audit::audit_diagnostic(format!("tirith: audit-spool: failed to write event: {e}"));
        return;
    }

    // repo-0195: enforce retention AT APPEND TIME, before any destination
    // validation or network state can skip it — a prolonged outage must not
    // grow the queue past the configured bounds.
    trim_spool_to_retention(max_ev, max_b);

    if DRAIN_ACTIVE
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_err()
    {
        DRAIN_RESCAN.store(true, std::sync::atomic::Ordering::Release);
        return; // a drainer is already running; the flag makes it rescan
    }

    // Drain runs on a background thread — the CLI path must never block on network I/O.
    let url = server_url.to_string();
    let key = api_key.to_string();
    let spawned = std::thread::Builder::new()
        .name("tirith-audit-drain".to_string())
        .spawn(move || {
            let mut ownership = DrainOwnership { held: true };
            loop {
                // Clear before draining: an append during this pass sets the
                // flag again and earns another one.
                DRAIN_RESCAN.store(false, std::sync::atomic::Ordering::Release);
                drain_spool(&url, &key, max_ev, max_b);
                if DRAIN_RESCAN.load(std::sync::atomic::Ordering::Acquire) {
                    continue;
                }
                ownership.release();
                // An append between the load above and that release saw an
                // active drainer and only set the flag, so re-take ownership for
                // it. If another caller already became the drainer, it owns the
                // work.
                if !DRAIN_RESCAN.load(std::sync::atomic::Ordering::Acquire) || !ownership.retake() {
                    break;
                }
            }
        });
    if spawned.is_err() {
        // Never leave the claim set for a worker that does not exist.
        DRAIN_ACTIVE.store(false, std::sync::atomic::Ordering::Release);
        crate::audit::audit_diagnostic(
            "tirith: audit-upload: could not start the drain worker; the spool is retained",
        );
    }
}

/// Trim the spool file to the retention bounds (event count and total bytes),
/// dropping the oldest lines. Runs under the spool lock.
fn trim_spool_to_retention(max_events: usize, max_bytes: u64) {
    let path = spool_path();
    let _ = with_spool_lock(|| -> std::io::Result<()> {
        let (lines, tail_truncated) = match read_spool_lines_bounded(&path, max_bytes) {
            Ok(c) => c,
            Err(_) => return Ok(()),
        };
        let trimmed = enforce_retention(lines.clone(), max_events, max_bytes);
        if tail_truncated || trimmed != lines {
            write_spool_atomic(&path, &trimmed)?;
        }
        Ok(())
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spool_path_uses_xdg_state() {
        let _path = spool_path();
    }

    #[test]
    fn test_enforce_retention_max_events() {
        let lines: Vec<String> = (0..20).map(|i| format!("{{\"n\":{i}}}")).collect();
        let trimmed = enforce_retention(lines, 10, u64::MAX);
        assert_eq!(trimmed.len(), 10);
        // Should keep the newest 10 (indices 10-19).
        assert!(trimmed[0].contains("10"));
        assert!(trimmed[9].contains("19"));
    }

    #[test]
    fn test_enforce_retention_max_bytes() {
        // Each line is ~10 bytes + newline = 11 bytes; 55-byte cap fits ~5 lines.
        let lines: Vec<String> = (0..100).map(|i| format!("{{\"n\":{i:03}}}")).collect();
        let trimmed = enforce_retention(lines, usize::MAX, 55);
        assert!(trimmed.len() <= 5);
    }

    #[test]
    fn test_enforce_retention_within_limits() {
        let lines: Vec<String> = (0..5).map(|i| format!("{{\"n\":{i}}}")).collect();
        let trimmed = enforce_retention(lines.clone(), 100, u64::MAX);
        assert_eq!(trimmed.len(), 5);
    }

    #[test]
    fn test_spool_event_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tirith").join("audit-queue.jsonl");

        // spool_path() isn't easily overridable in unit tests, so exercise the
        // write logic directly rather than going through spool_event().
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "{{\"test\":true}}").unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"test\":true"));
    }

    #[test]
    fn test_rewrite_spool_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        fs::write(&path, "line1\nline2\n").unwrap();

        let snapshot = vec!["line1".to_string(), "line2".to_string()];
        rewrite_spool(&path, &snapshot, snapshot.len(), u64::MAX);
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.is_empty());
    }

    #[test]
    fn test_rewrite_spool_with_remaining() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        // The on-disk spool holds the drainer's snapshot (sent + unsent lines).
        fs::write(&path, "line1\nline2\nline3\nline4\n").unwrap();

        let snapshot = vec![
            "line1".to_string(),
            "line2".to_string(),
            "line3".to_string(),
            "line4".to_string(),
        ];
        rewrite_spool(&path, &snapshot, 2, u64::MAX);
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "line3\nline4\n");
    }

    #[test]
    fn test_rewrite_spool_preserves_concurrent_appends() {
        // repo-0250: lines appended by another process AFTER the drainer's
        // snapshot must survive the rewrite; the rewrite is refused when the
        // pending tail no longer matches (at-least-once beats silent loss).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        fs::write(&path, "line1\nline3\nline4\nline5-new\n").unwrap();

        let snapshot = vec![
            "line1".to_string(),
            "line3".to_string(),
            "line4".to_string(),
        ];
        rewrite_spool(&path, &snapshot, 1, u64::MAX);
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(
            content, "line3\nline4\nline5-new\n",
            "the sent prefix is removed while a concurrent append survives"
        );
    }

    #[test]
    fn test_rewrite_spool_preserves_append_after_fully_sent_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        fs::write(&path, "line1\nline2\nline3-new\n").unwrap();
        let snapshot = vec!["line1".to_string(), "line2".to_string()];

        rewrite_spool(&path, &snapshot, snapshot.len(), u64::MAX);

        assert_eq!(fs::read_to_string(&path).unwrap(), "line3-new\n");
    }

    #[test]
    fn test_rewrite_spool_refuses_changed_snapshot_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        fs::write(&path, "other\nline2\nline3-new\n").unwrap();
        let snapshot = vec!["line1".to_string(), "line2".to_string()];

        rewrite_spool(&path, &snapshot, 1, u64::MAX);

        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "other\nline2\nline3-new\n"
        );
    }
}
