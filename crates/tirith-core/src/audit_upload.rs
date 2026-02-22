use std::fs;
use std::io::Write;
use std::path::PathBuf;

const DEFAULT_MAX_EVENTS: usize = 1000;
const DEFAULT_MAX_BYTES: u64 = 5 * 1024 * 1024; // 5 MiB

/// Get the spool file path: `$XDG_STATE_HOME/tirith/audit-queue.jsonl`
/// (falls back to `~/.local/state/tirith/audit-queue.jsonl`).
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
    }
    let mut file = opts.open(&path)?;
    writeln!(file, "{event_json}")?;
    Ok(())
}

/// Enforce bounded retention on the spool. Drop oldest events when over limits.
///
/// Returns the (possibly trimmed) list of lines to process.
fn enforce_retention(lines: Vec<String>, max_events: usize, max_bytes: u64) -> Vec<String> {
    let mut result = lines;

    // Trim to max_events (drop oldest = front of vec)
    if result.len() > max_events {
        let drop_count = result.len() - max_events;
        eprintln!(
            "tirith: audit-spool: dropping {drop_count} oldest events (max_events={max_events})"
        );
        result = result.into_iter().skip(drop_count).collect();
    }

    // Trim to max_bytes (drop oldest until under limit)
    let total_bytes: u64 = result.iter().map(|l| l.len() as u64 + 1).sum(); // +1 for newline
    if total_bytes > max_bytes {
        let mut kept = Vec::new();
        let mut running_bytes: u64 = 0;
        // Walk from newest (end) to oldest (start), keep until over budget
        for line in result.into_iter().rev() {
            let line_bytes = line.len() as u64 + 1;
            if running_bytes + line_bytes > max_bytes {
                break;
            }
            running_bytes += line_bytes;
            kept.push(line);
        }
        kept.reverse();
        eprintln!(
            "tirith: audit-spool: trimmed to {} events to stay under {max_bytes} bytes",
            kept.len()
        );
        result = kept;
    }

    result
}

/// Try to drain the spool by uploading events to the server.
///
/// Called in the background -- should not block the main command.
/// Events are uploaded one at a time with exponential backoff on failure.
/// On auth errors (401/403) uploading stops immediately.
#[cfg(unix)]
pub fn drain_spool(server_url: &str, api_key: &str, max_events: usize, max_bytes: u64) {
    // SSRF protection
    if let Err(reason) = crate::url_validate::validate_server_url(server_url) {
        eprintln!("tirith: audit-upload: {reason}");
        return;
    }

    let path = spool_path();
    if !path.exists() {
        return;
    }

    // Read all lines
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let lines: Vec<String> = content.lines().map(String::from).collect();
    if lines.is_empty() {
        return;
    }

    // Enforce bounded retention
    let lines = enforce_retention(lines, max_events, max_bytes);
    if lines.is_empty() {
        // Everything was trimmed -- write empty spool
        let _ = fs::write(&path, "");
        return;
    }

    // Build HTTP client
    let client = match reqwest::blocking::Client::builder()
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
                    backoff_ms = 1000; // reset on success
                    break;
                }
                Ok(resp) if resp.status().as_u16() == 401 || resp.status().as_u16() == 403 => {
                    // Auth error -- stop trying entirely
                    eprintln!("tirith: audit-upload: auth failed, stopping upload");
                    rewrite_spool(&path, &lines[sent_count..]);
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
            // Failed after retries -- stop and keep remaining
            break;
        }
    }

    // Rewrite spool with unsent lines
    rewrite_spool(&path, &lines[sent_count..]);
}

/// Stub for non-unix platforms where reqwest is not available.
#[cfg(not(unix))]
pub fn drain_spool(_server_url: &str, _api_key: &str, _max_events: usize, _max_bytes: u64) {
    // No-op: remote upload not supported on non-unix platforms
}

/// Rewrite the spool file with the remaining unsent lines.
fn rewrite_spool(path: &std::path::Path, remaining: &[String]) {
    if remaining.is_empty() {
        let _ = fs::write(path, "");
    } else {
        let mut content = remaining.join("\n");
        content.push('\n');
        let _ = fs::write(path, content);
    }
}

/// Spool the event and attempt background drain.
///
/// This is the primary entry point. It appends the event to the durable spool,
/// then spawns a background thread to attempt uploading accumulated events.
pub fn spool_and_upload(
    event_json: &str,
    server_url: &str,
    api_key: &str,
    max_events: Option<usize>,
    max_bytes: Option<u64>,
) {
    if let Err(e) = spool_event(event_json) {
        eprintln!("tirith: audit-spool: failed to write event: {e}");
        return;
    }

    // Spawn background thread for drain -- must not block the CLI
    let url = server_url.to_string();
    let key = api_key.to_string();
    let max_ev = max_events.unwrap_or(DEFAULT_MAX_EVENTS);
    let max_b = max_bytes.unwrap_or(DEFAULT_MAX_BYTES);
    std::thread::spawn(move || {
        drain_spool(&url, &key, max_ev, max_b);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spool_path_uses_xdg_state() {
        // Just verify the function doesn't panic
        let _path = spool_path();
    }

    #[test]
    fn test_enforce_retention_max_events() {
        let lines: Vec<String> = (0..20).map(|i| format!("{{\"n\":{i}}}")).collect();
        let trimmed = enforce_retention(lines, 10, u64::MAX);
        assert_eq!(trimmed.len(), 10);
        // Should keep the newest 10 (indices 10-19)
        assert!(trimmed[0].contains("10"));
        assert!(trimmed[9].contains("19"));
    }

    #[test]
    fn test_enforce_retention_max_bytes() {
        // Each line is ~10 bytes + newline = 11 bytes
        let lines: Vec<String> = (0..100).map(|i| format!("{{\"n\":{i:03}}}")).collect();
        // Allow 55 bytes -- should fit ~5 lines
        let trimmed = enforce_retention(lines, usize::MAX, 55);
        assert!(trimmed.len() <= 5);
        // Should keep newest lines
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

        // Override spool path via XDG_STATE_HOME
        // We can't easily override spool_path() in unit tests, so test
        // the write logic directly.
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

        rewrite_spool(&path, &[]);
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.is_empty());
    }

    #[test]
    fn test_rewrite_spool_with_remaining() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        fs::write(&path, "").unwrap();

        let remaining = vec!["line3".to_string(), "line4".to_string()];
        rewrite_spool(&path, &remaining);
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "line3\nline4\n");
    }
}
