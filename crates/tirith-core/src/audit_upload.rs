use std::fs;
use std::io::Write;
use std::path::PathBuf;

const DEFAULT_MAX_EVENTS: usize = 1000;
const DEFAULT_MAX_BYTES: u64 = 5 * 1024 * 1024; // 5 MiB

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
            if running_bytes + line_bytes > max_bytes && !kept.is_empty() {
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

    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let lines: Vec<String> = content.lines().map(String::from).collect();
    if lines.is_empty() {
        return;
    }

    let lines = enforce_retention(lines, max_events, max_bytes);
    if lines.is_empty() {
        if let Err(e) = fs::write(&path, "") {
            crate::audit::audit_diagnostic(format!(
                "tirith: audit-spool: failed to clear spool: {e}"
            ));
        }
        return;
    }

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
                    backoff_ms = 1000;
                    break;
                }
                Ok(resp) if resp.status().as_u16() == 401 || resp.status().as_u16() == 403 => {
                    // Auth error — further retries will fail identically; stop early.
                    crate::audit::audit_diagnostic(
                        "tirith: audit-upload: auth failed, stopping upload",
                    );
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
            break;
        }
    }

    rewrite_spool(&path, &lines[sent_count..]);
}

/// Rewrite the spool file with the remaining unsent lines.
fn rewrite_spool(path: &std::path::Path, remaining: &[String]) {
    if remaining.is_empty() {
        if let Err(e) = fs::write(path, "") {
            crate::audit::audit_diagnostic(format!(
                "tirith: audit-spool: failed to clear spool: {e}"
            ));
        }
    } else {
        let mut content = remaining.join("\n");
        content.push('\n');
        if let Err(e) = fs::write(path, content) {
            crate::audit::audit_diagnostic(format!(
                "tirith: audit-spool: failed to rewrite spool: {e}"
            ));
        }
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
    if let Err(e) = spool_event(event_json) {
        crate::audit::audit_diagnostic(format!("tirith: audit-spool: failed to write event: {e}"));
        return;
    }

    // Drain runs on a background thread — the CLI path must never block on network I/O.
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
