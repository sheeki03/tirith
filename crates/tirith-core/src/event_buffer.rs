//! Cross-event correlation over a bounded, per-session ring of typed events.
//!
//! This module is PURE: it performs no I/O, reads no clock of its own, and
//! touches no global state. Callers (see [`crate::session_warnings`]) own the
//! buffer's persistence and pass the current time in explicitly. That keeps the
//! correlation logic trivially testable and keeps it OFF the hot path: confirmed
//! executions are persisted after caller completion, while pre-execution checks
//! correlate a provisional current event without recording it.
//!
//! The correlations here are "A THEN B within a window" patterns: behaviours
//! that are individually unremarkable but, in sequence and close in time, look
//! like an exfiltration or destruction chain. Each rule maps to a dedicated
//! [`RuleId`] variant flagged `EXTERNALLY_TRIGGERED_RULES` (session/post-process,
//! no PATTERN_TABLE entry).

use std::collections::BTreeMap;
use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::verdict::{RuleId, Severity};

/// The class of a recorded event. Deliberately coarse: correlation reasons about
/// "what kind of thing happened", and finer detail lives in
/// [`TypedEvent::metadata`].
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A process/command was executed.
    ProcessExec,
    /// A file was written (created or modified).
    FileWrite,
    /// A file was deleted / unlinked.
    FileDelete,
    /// A `git push --force` (or `-f`) was run.
    GitForcePush,
    /// A network egress (curl/wget/http client, or a network-class rule fired).
    Network,
    /// A secret-bearing file was written (`.env`, `id_rsa`, `.npmrc`, ...).
    SecretWrite,
    /// A pipe-to-shell shape (`curl ... | sh`).
    ShellPipe,
    /// A package install (npm/pip/cargo/brew ...).
    PackageInstall,
}

/// Assurance attached to a typed event's execution boundary.
///
/// Legacy events default to `Unresolved` because the old JSON recorder carried
/// no execution proof. Strict execution records explicitly mark kernel/gateway
/// completions as `Confirmed`, while the current command
/// is `Provisional` until a trusted boundary durably promotes it. Correlation
/// enforcement may use all three conservatively, but its text must not turn an
/// unresolved observation into an assertion that code ran.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum EventProvenance {
    Confirmed,
    #[default]
    Unresolved,
    Provisional,
}

/// One recorded, time-stamped event. `path` / `host` / `domain` and any other
/// detail live in [`Self::metadata`] so the struct stays stable as new
/// correlations want new context.
#[derive(Clone, PartialEq, Eq)]
pub struct TypedEvent {
    /// Stable opaque identity. Empty only while deserializing a legacy event;
    /// session migration fills it deterministically before the event is used.
    pub event_id: String,
    /// Monotonic sequence within the owning session. Zero is the legacy sentinel
    /// and is replaced under the session lock during migration.
    pub sequence: u64,
    /// Execution assurance. Missing on legacy records means unresolved because
    /// those records predate the proof-carrying split.
    pub provenance: EventProvenance,
    /// RFC 3339 UTC timestamp (`chrono::Utc::now().to_rfc3339()`), lexically
    /// comparable against other events recorded the same way.
    pub timestamp: String,
    /// The class of event.
    pub kind: EventKind,
    /// The rule id (or command-derived label) that produced this event.
    pub rule_id: String,
    /// Free-form context: `path`, `host`, `domain`, a `manifest` flag, etc.
    pub metadata: BTreeMap<String, String>,
}

const MAX_TYPED_EVENT_ID_BYTES: usize = 128;
const MAX_TYPED_EVENT_TIMESTAMP_BYTES: usize = 64;
const MAX_TYPED_EVENT_RULE_ID_BYTES: usize = 128;
const MAX_TYPED_EVENT_METADATA_ENTRIES: usize = 32;
const MAX_TYPED_EVENT_METADATA_KEY_BYTES: usize = 64;
const MAX_TYPED_EVENT_METADATA_VALUE_BYTES: usize = 512;
const PRIVACY_REDACTED_EVENT_ID: &str = "privacy-redacted";

/// Serde-only compatibility shape. The public wire field names and legacy
/// defaults stay unchanged, while [`TypedEvent`]'s trait boundary gets a chance
/// to project attacker-controlled strings before they can be rendered or made
/// durable.
#[derive(Serialize, Deserialize)]
#[serde(rename = "TypedEvent")]
struct TypedEventWire {
    #[serde(default)]
    event_id: String,
    #[serde(default)]
    sequence: u64,
    #[serde(default)]
    provenance: EventProvenance,
    timestamp: String,
    kind: EventKind,
    rule_id: String,
    metadata: BTreeMap<String, String>,
}

impl From<TypedEventWire> for TypedEvent {
    fn from(wire: TypedEventWire) -> Self {
        Self {
            event_id: wire.event_id,
            sequence: wire.sequence,
            provenance: wire.provenance,
            timestamp: wire.timestamp,
            kind: wire.kind,
            rule_id: wire.rule_id,
            metadata: wire.metadata,
        }
    }
}

impl From<TypedEvent> for TypedEventWire {
    fn from(event: TypedEvent) -> Self {
        Self {
            event_id: event.event_id,
            sequence: event.sequence,
            provenance: event.provenance,
            timestamp: event.timestamp,
            kind: event.kind,
            rule_id: event.rule_id,
            metadata: event.metadata,
        }
    }
}

fn privacy_project_unbounded_text(value: &str) -> String {
    let projected = crate::redact::privacy_project_durable_text(value);
    crate::mcp::output_filter::sanitize_for_display(&projected)
}

fn privacy_project_bounded_text(value: &str, max_bytes: usize) -> String {
    crate::util::truncate_bytes(&privacy_project_unbounded_text(value), max_bytes)
}

fn fits_bound_or_privacy_projects(value: &str, projected: &str, max_bytes: usize) -> bool {
    value.len() <= max_bytes || (projected != value && projected.len() <= max_bytes)
}

pub(crate) fn privacy_project_endpoint(value: &str) -> String {
    let projected = privacy_project_bounded_text(value, MAX_TYPED_EVENT_METADATA_VALUE_BYTES);
    if projected.starts_with("[REDACTED:") {
        return projected;
    }
    let canonical =
        crate::sensitive_assets::canonicalize_rpc_for_display(&projected).or_else(|| {
            let endpoint = format!("https://{projected}");
            crate::sensitive_assets::canonicalize_rpc_for_display(&endpoint)
                .and_then(|origin| origin.strip_prefix("https://").map(str::to_string))
        });
    crate::util::truncate_bytes(
        canonical.as_deref().unwrap_or(&projected),
        MAX_TYPED_EVENT_METADATA_VALUE_BYTES,
    )
}

fn metadata_priority(key: &str) -> usize {
    match key {
        "path" => 0,
        "host" => 1,
        "domain" => 2,
        "rpc" => 3,
        "rpc_url" => 4,
        MANIFEST_FLAG_KEY => 5,
        DELETE_COUNT_KEY => 6,
        NON_BUILD_DELETE_COUNT_KEY => 7,
        _ => 8,
    }
}

/// Mandatory privacy and semantic-size projection for a typed event.
///
/// The return value says whether any identity-bearing source field or the id
/// itself changed. A session owner can use that signal to regenerate the stable
/// id from the fully projected source and to rewrite correlation de-dup markers.
/// This function deliberately never hashes a rejected value by itself.
pub(crate) fn privacy_project_typed_event(event: &mut TypedEvent) -> bool {
    let original_timestamp = event.timestamp.clone();
    let original_rule_id = event.rule_id.clone();
    let original_metadata = event.metadata.clone();

    event.timestamp =
        privacy_project_bounded_text(&event.timestamp, MAX_TYPED_EVENT_TIMESTAMP_BYTES);
    event.rule_id = privacy_project_bounded_text(&event.rule_id, MAX_TYPED_EVENT_RULE_ID_BYTES);

    let mut projected =
        Vec::with_capacity(event.metadata.len().min(MAX_TYPED_EVENT_METADATA_ENTRIES));
    for (key, value) in std::mem::take(&mut event.metadata) {
        let (key, value) = crate::redact::privacy_project_durable_pair(&key, &value);
        let key = privacy_project_bounded_text(&key, MAX_TYPED_EVENT_METADATA_KEY_BYTES);
        if key.is_empty() {
            continue;
        }
        let value = if matches!(key.as_str(), "host" | "domain" | "rpc" | "rpc_url") {
            privacy_project_endpoint(&value)
        } else {
            privacy_project_bounded_text(&value, MAX_TYPED_EVENT_METADATA_VALUE_BYTES)
        };
        projected.push((metadata_priority(&key), key, value));
    }
    // Preserve correlation-critical categorical metadata before arbitrary
    // extension fields if a hostile direct construction exceeds the cap.
    projected.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    for (_, key, value) in projected.into_iter().take(MAX_TYPED_EVENT_METADATA_ENTRIES) {
        event.metadata.insert(key, value);
    }

    let source_changed = event.timestamp != original_timestamp
        || event.rule_id != original_rule_id
        || event.metadata != original_metadata;
    let projected_id = privacy_project_bounded_text(&event.event_id, MAX_TYPED_EVENT_ID_BYTES);
    let identity_changed = projected_id != event.event_id;
    // An otherwise opaque id may be a digest of any source field that just
    // changed. A session owner replaces this sentinel with a reproducible
    // sequence identity after inspecting the whole ring; keeping one bounded,
    // stable-id-safe sentinel until then also preserves duplicate-id detection
    // instead of laundering two hostile ids into two empty strings.
    event.event_id = if source_changed || identity_changed {
        PRIVACY_REDACTED_EVENT_ID.to_string()
    } else {
        projected_id
    };
    source_changed || identity_changed
}

impl Serialize for TypedEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut projected = self.clone();
        privacy_project_typed_event(&mut projected);
        TypedEventWire::from(projected).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TypedEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = TypedEventWire::deserialize(deserializer)?;
        let projected_id = privacy_project_unbounded_text(&wire.event_id);
        let projected_rule_id = privacy_project_unbounded_text(&wire.rule_id);
        let metadata_within_bounds = wire.metadata.iter().all(|(key, value)| {
            let (projected_key, projected_value) =
                crate::redact::privacy_project_durable_pair(key, value);
            let projected_key = privacy_project_unbounded_text(&projected_key);
            let projected_value = privacy_project_unbounded_text(&projected_value);
            !key.is_empty()
                && !projected_key.is_empty()
                && fits_bound_or_privacy_projects(
                    key,
                    &projected_key,
                    MAX_TYPED_EVENT_METADATA_KEY_BYTES,
                )
                && fits_bound_or_privacy_projects(
                    value,
                    &projected_value,
                    MAX_TYPED_EVENT_METADATA_VALUE_BYTES,
                )
        });
        if !fits_bound_or_privacy_projects(&wire.event_id, &projected_id, MAX_TYPED_EVENT_ID_BYTES)
            || wire.timestamp.len() > MAX_TYPED_EVENT_TIMESTAMP_BYTES
            || wire.rule_id.is_empty()
            || projected_rule_id.is_empty()
            || !fits_bound_or_privacy_projects(
                &wire.rule_id,
                &projected_rule_id,
                MAX_TYPED_EVENT_RULE_ID_BYTES,
            )
            || wire.metadata.len() > MAX_TYPED_EVENT_METADATA_ENTRIES
            || !metadata_within_bounds
        {
            return Err(D::Error::custom(
                "typed event exceeds its public semantic bounds",
            ));
        }
        let mut event = Self::from(wire);
        privacy_project_typed_event(&mut event);
        Ok(event)
    }
}

impl fmt::Debug for TypedEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut projected = self.clone();
        privacy_project_typed_event(&mut projected);
        formatter
            .debug_struct("TypedEvent")
            .field("event_id", &projected.event_id)
            .field("sequence", &projected.sequence)
            .field("provenance", &projected.provenance)
            .field("timestamp", &projected.timestamp)
            .field("kind", &projected.kind)
            .field("rule_id", &projected.rule_id)
            .field("metadata", &projected.metadata)
            .finish()
    }
}

impl TypedEvent {
    /// Convenience constructor used by recorders and tests.
    pub fn new(timestamp: &str, kind: EventKind, rule_id: &str) -> Self {
        Self {
            event_id: String::new(),
            sequence: 0,
            provenance: EventProvenance::Confirmed,
            timestamp: timestamp.to_string(),
            kind,
            rule_id: rule_id.to_string(),
            metadata: BTreeMap::new(),
        }
    }

    /// Builder-style metadata insert.
    pub fn with_meta(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    /// Upgrade a deserialized legacy event to a stable identity. The caller
    /// supplies a unique sequence allocated under the session lock, making
    /// migration deterministic even when two legacy events otherwise have equal
    /// content. Identity is intentionally sequence-derived rather than a digest
    /// of free text: even a later projection bug therefore cannot turn the id
    /// into an offline oracle for a secret-bearing legacy field. The allocator
    /// must start above every non-zero legacy/new sequence.
    pub(crate) fn migrate_legacy_identity(&mut self, _session_id: &str, assigned_sequence: u64) {
        if self.sequence == 0 {
            self.sequence = assigned_sequence.max(1);
        }
        if self.event_id.is_empty() {
            self.event_id = format!("legacy-event-{}", self.sequence);
        }
    }

    /// Borrow the `path` metadatum, if present.
    fn path(&self) -> Option<&str> {
        self.metadata.get("path").map(|s| s.as_str())
    }

    /// How many deleted PATHS this [`EventKind::FileDelete`] event represents.
    /// Reads the [`DELETE_COUNT_KEY`] metadatum, defaulting to 1 when absent or
    /// unparsable (back-compat with single-path deletes and pre-existing events).
    fn delete_count(&self) -> usize {
        self.metadata
            .get(DELETE_COUNT_KEY)
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|n| *n >= 1)
            .unwrap_or(1)
    }

    /// How many of this delete event's paths are NON-build-artifacts, for the
    /// mass-deletion correlation (which must not count `dist/`, `node_modules/`,
    /// etc.).
    ///
    /// PREFERS the precomputed [`NON_BUILD_DELETE_COUNT_KEY`] metadatum, which the
    /// deriver fills in by classifying EVERY path in the command individually. That
    /// is the correct value for a MIXED command (`rm app.rs dist/x dist/y` -> 1),
    /// which a single representative path cannot capture.
    ///
    /// FALLS BACK (events recorded before this key existed, or test-constructed
    /// events) to the old single-representative-path heuristic: if the one recorded
    /// `path` is a build artifact, the whole event contributes 0; otherwise it
    /// contributes its [`delete_count`](Self::delete_count). An event with no path
    /// is counted conservatively (cannot be proven a build artifact).
    fn non_build_delete_count(&self) -> usize {
        if let Some(n) = self
            .metadata
            .get(NON_BUILD_DELETE_COUNT_KEY)
            .and_then(|v| v.parse::<usize>().ok())
        {
            return n;
        }
        match self.path() {
            Some(p) if crate::util_build_dirs::is_build_artifact_path(p) => 0,
            _ => self.delete_count(),
        }
    }
}

/// Timestamp-free event derived during preparation. It cannot be mistaken for
/// executed history; the execution gate supplies time, stable id, and sequence
/// only while atomically promoting confirmed evidence.
#[derive(Clone, PartialEq, Eq)]
pub struct EventPrototype {
    pub kind: EventKind,
    pub rule_id: String,
    pub metadata: BTreeMap<String, String>,
}

/// Serde-only compatibility shape for [`EventPrototype`]. Public field names
/// remain stable while every trait boundary projects free text first.
#[derive(Serialize, Deserialize)]
#[serde(rename = "EventPrototype")]
struct EventPrototypeWire {
    kind: EventKind,
    rule_id: String,
    metadata: BTreeMap<String, String>,
}

impl From<EventPrototypeWire> for EventPrototype {
    fn from(wire: EventPrototypeWire) -> Self {
        Self {
            kind: wire.kind,
            rule_id: wire.rule_id,
            metadata: wire.metadata,
        }
    }
}

impl From<EventPrototype> for EventPrototypeWire {
    fn from(prototype: EventPrototype) -> Self {
        Self {
            kind: prototype.kind,
            rule_id: prototype.rule_id,
            metadata: prototype.metadata,
        }
    }
}

fn privacy_project_event_prototype(prototype: &mut EventPrototype) {
    prototype.rule_id =
        privacy_project_bounded_text(&prototype.rule_id, MAX_TYPED_EVENT_RULE_ID_BYTES);

    let mut projected = Vec::with_capacity(
        prototype
            .metadata
            .len()
            .min(MAX_TYPED_EVENT_METADATA_ENTRIES),
    );
    for (key, value) in std::mem::take(&mut prototype.metadata) {
        let (key, value) = crate::redact::privacy_project_durable_pair(&key, &value);
        let key = privacy_project_bounded_text(&key, MAX_TYPED_EVENT_METADATA_KEY_BYTES);
        if key.is_empty() {
            continue;
        }
        let value = if matches!(key.as_str(), "host" | "domain" | "rpc" | "rpc_url") {
            privacy_project_endpoint(&value)
        } else {
            privacy_project_bounded_text(&value, MAX_TYPED_EVENT_METADATA_VALUE_BYTES)
        };
        projected.push((metadata_priority(&key), key, value));
    }
    projected.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    for (_, key, value) in projected.into_iter().take(MAX_TYPED_EVENT_METADATA_ENTRIES) {
        prototype.metadata.insert(key, value);
    }
}

impl Serialize for EventPrototype {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut projected = self.clone();
        privacy_project_event_prototype(&mut projected);
        EventPrototypeWire::from(projected).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EventPrototype {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = EventPrototypeWire::deserialize(deserializer)?;
        let projected_rule_id = privacy_project_unbounded_text(&wire.rule_id);
        let metadata_within_bounds = wire.metadata.iter().all(|(key, value)| {
            let (projected_key, projected_value) =
                crate::redact::privacy_project_durable_pair(key, value);
            let projected_key = privacy_project_unbounded_text(&projected_key);
            let projected_value = privacy_project_unbounded_text(&projected_value);
            !key.is_empty()
                && !projected_key.is_empty()
                && fits_bound_or_privacy_projects(
                    key,
                    &projected_key,
                    MAX_TYPED_EVENT_METADATA_KEY_BYTES,
                )
                && fits_bound_or_privacy_projects(
                    value,
                    &projected_value,
                    MAX_TYPED_EVENT_METADATA_VALUE_BYTES,
                )
        });
        if wire.rule_id.is_empty()
            || projected_rule_id.is_empty()
            || !fits_bound_or_privacy_projects(
                &wire.rule_id,
                &projected_rule_id,
                MAX_TYPED_EVENT_RULE_ID_BYTES,
            )
            || wire.metadata.len() > MAX_TYPED_EVENT_METADATA_ENTRIES
            || !metadata_within_bounds
        {
            return Err(D::Error::custom(
                "event prototype exceeds its public semantic bounds",
            ));
        }
        let mut prototype = Self::from(wire);
        privacy_project_event_prototype(&mut prototype);
        Ok(prototype)
    }
}

impl fmt::Debug for EventPrototype {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut projected = self.clone();
        privacy_project_event_prototype(&mut projected);
        formatter
            .debug_struct("EventPrototype")
            .field("kind", &projected.kind)
            .field("rule_id", &projected.rule_id)
            .field("metadata", &projected.metadata)
            .finish()
    }
}

impl EventPrototype {
    pub fn new(kind: EventKind, rule_id: impl Into<String>) -> Self {
        Self {
            kind,
            rule_id: rule_id.into(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub(crate) fn materialize(
        mut self,
        event_id: String,
        sequence: u64,
        timestamp: String,
        provenance: EventProvenance,
    ) -> TypedEvent {
        privacy_project_event_prototype(&mut self);
        TypedEvent {
            event_id,
            sequence,
            provenance,
            timestamp,
            kind: self.kind,
            rule_id: self.rule_id,
            metadata: self.metadata,
        }
    }
}

/// A correlation that fired. Mirrors the shape of a [`crate::verdict::Finding`]
/// closely enough that a consumer can surface it as one, but stays decoupled so
/// this module never depends on the full finding/evidence machinery.
#[derive(Clone)]
pub struct CorrelationHit {
    /// The dedicated correlation rule that matched.
    pub rule_id: RuleId,
    /// Severity for the surfaced finding.
    pub severity: Severity,
    /// Short title.
    pub title: String,
    /// Human-readable description of the matched sequence.
    pub description: String,
    /// Strongest uncertainty among the source events. Consumers can enforce a
    /// hit while preserving an honest audit/presentation claim.
    pub provenance: EventProvenance,
    /// Stable signature identifying THIS specific match. New events contribute
    /// only a rebuilt, sequence-derived identity; legacy events fall back to a
    /// valid projected timestamp. A session-level consumer uses it to
    /// de-duplicate the same A-then-B pair while its source events remain live.
    pub signature: String,
}

const MAX_CORRELATION_TITLE_BYTES: usize = 160;
const MAX_CORRELATION_DESCRIPTION_BYTES: usize = 1024;
const MAX_CORRELATION_SIGNATURE_PARTS: usize = 8;

/// Serde-only compatibility shape for [`CorrelationHit`]. The shape was not
/// historically serializable, but keeping its public field names here makes the
/// new safe trait boundary unsurprising and stable.
#[derive(Serialize, Deserialize)]
#[serde(rename = "CorrelationHit")]
struct CorrelationHitWire {
    rule_id: RuleId,
    severity: Severity,
    title: String,
    description: String,
    provenance: EventProvenance,
    signature: String,
}

impl From<CorrelationHitWire> for CorrelationHit {
    fn from(wire: CorrelationHitWire) -> Self {
        Self {
            rule_id: wire.rule_id,
            severity: wire.severity,
            title: wire.title,
            description: wire.description,
            provenance: wire.provenance,
            signature: wire.signature,
        }
    }
}

impl From<CorrelationHit> for CorrelationHitWire {
    fn from(hit: CorrelationHit) -> Self {
        Self {
            rule_id: hit.rule_id,
            severity: hit.severity,
            title: hit.title,
            description: hit.description,
            provenance: hit.provenance,
            signature: hit.signature,
        }
    }
}

fn canonical_correlation_timestamp(value: &str) -> Option<String> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc).to_rfc3339())
}

/// Rebuild a correlation signature exclusively from categorical rule identity,
/// monotonic sequence numbers, and valid timestamps. In particular, an opaque
/// event id is never copied: a public caller can directly construct a
/// [`TypedEvent`], so treating that string as trusted would make the signature a
/// secret or a stable digest oracle.
fn privacy_project_correlation_signature(rule_id: RuleId, untrusted: &str) -> String {
    let mut projected = format!("{rule_id:?}");
    for part in untrusted
        .split('|')
        .skip(1)
        .take(MAX_CORRELATION_SIGNATURE_PARTS)
    {
        let safe_part = if let Some(rest) = part.strip_prefix("e:") {
            rest.rsplit_once(':')
                .and_then(|(_, sequence)| sequence.parse::<u64>().ok())
                .filter(|sequence| *sequence > 0)
                .map(|sequence| format!("e:legacy-event-{sequence}:{sequence}"))
        } else {
            let timestamp = part.strip_prefix("t:").unwrap_or(part);
            canonical_correlation_timestamp(timestamp).map(|timestamp| format!("t:{timestamp}"))
        };
        if let Some(safe_part) = safe_part {
            projected.push('|');
            projected.push_str(&safe_part);
        }
    }
    projected
}

fn privacy_project_correlation_hit(hit: &mut CorrelationHit) {
    hit.title = privacy_project_bounded_text(&hit.title, MAX_CORRELATION_TITLE_BYTES);
    hit.description =
        privacy_project_bounded_text(&hit.description, MAX_CORRELATION_DESCRIPTION_BYTES);
    hit.signature = privacy_project_correlation_signature(hit.rule_id, &hit.signature);
}

impl Serialize for CorrelationHit {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut projected = self.clone();
        privacy_project_correlation_hit(&mut projected);
        CorrelationHitWire::from(projected).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CorrelationHit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut hit = Self::from(CorrelationHitWire::deserialize(deserializer)?);
        privacy_project_correlation_hit(&mut hit);
        Ok(hit)
    }
}

impl fmt::Debug for CorrelationHit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut projected = self.clone();
        privacy_project_correlation_hit(&mut projected);
        formatter
            .debug_struct("CorrelationHit")
            .field("rule_id", &projected.rule_id)
            .field("severity", &projected.severity)
            .field("title", &projected.title)
            .field("description", &projected.description)
            .field("provenance", &projected.provenance)
            .field("signature", &projected.signature)
            .finish()
    }
}

/// Window, in seconds, for each correlation rule.
const SECRET_THEN_NETWORK_WINDOW_SECS: i64 = 30;
const DEP_CHANGE_THEN_NETWORK_WINDOW_SECS: i64 = 60;
const DELETE_THEN_FORCE_PUSH_WINDOW_SECS: i64 = 60;
const MASS_DELETE_WINDOW_SECS: i64 = 20;
/// How many file deletions inside [`MASS_DELETE_WINDOW_SECS`] constitute a mass
/// deletion.
const MASS_DELETE_THRESHOLD: usize = 3;

/// Metadata key set on a [`EventKind::FileWrite`] event whose target basename is
/// a dependency manifest. Lets the dependency-change correlation distinguish a
/// manifest write from an arbitrary file write without a second event kind.
pub const MANIFEST_FLAG_KEY: &str = "manifest";

/// Metadata key on a [`EventKind::FileDelete`] event carrying how many PATHS that
/// one delete command targeted (`rm a b c` -> "3"). [`mass_file_deletion`] sums
/// this across events so a single multi-path delete is weighed by paths, not by
/// command count. Absent or unparsable -> treated as 1 (back-compat with events
/// recorded before this key existed, and with single-path deletes).
pub const DELETE_COUNT_KEY: &str = "count";

/// Metadata key on a [`EventKind::FileDelete`] event carrying how many of that one
/// delete command's paths are NON-build-artifacts (the deriver classifies each
/// path with `crate::util_build_dirs::is_build_artifact_path`). [`mass_file_deletion`]
/// SUMS this across events rather than re-deriving artifact status from a single
/// representative path, which would misclassify a MIXED command (e.g.
/// `rm app.rs dist/x dist/y` has one non-build path, not three or zero). Absent
/// (older events / test fixtures) -> the consumer falls back to the per-path
/// heuristic; see [`TypedEvent::non_build_delete_count`].
pub const NON_BUILD_DELETE_COUNT_KEY: &str = "non_build_count";

/// Returns true if `basename` (a file's final path component) is a recognised
/// dependency manifest / lockfile. Conservative and exact-match where possible;
/// lockfiles use a small suffix/contains set so `pnpm-lock.yaml`,
/// `package-lock.json`, etc. all match.
pub fn is_dependency_manifest(basename: &str) -> bool {
    const EXACT: &[&str] = &[
        "package.json",
        "cargo.toml",
        "requirements.txt",
        "go.mod",
        "go.sum",
        "gemfile",
        "pipfile",
        "pyproject.toml",
        "build.gradle",
        "pom.xml",
        "composer.json",
        "package-lock.json",
        "yarn.lock",
        "cargo.lock",
        "poetry.lock",
        "pipfile.lock",
        "gemfile.lock",
        "composer.lock",
        // pnpm lockfile (both YAML extensions); matched EXACTLY like the others so
        // a `contains("pnpm-lock")` does not also catch `notes-pnpm-lock-backup.txt`.
        "pnpm-lock.yaml",
        "pnpm-lock.yml",
        "npm-shrinkwrap.json",
    ];
    let lower = basename.to_ascii_lowercase();
    EXACT.contains(&lower.as_str())
}

/// Compute the RFC 3339 cutoff string for `now_rfc3339 - window_secs`. Returns
/// `None` if `now_rfc3339` does not parse; callers then skip that rule (fail
/// safe: a malformed clock string never fabricates a correlation).
fn cutoff(now_rfc3339: &str, window_secs: i64) -> Option<String> {
    let now = chrono::DateTime::parse_from_rfc3339(now_rfc3339).ok()?;
    let cut = now - chrono::Duration::seconds(window_secs);
    // Render in the SAME shape recorders use (`Utc::now().to_rfc3339()`), so the
    // returned string is lexically comparable against event timestamps.
    Some(cut.with_timezone(&chrono::Utc).to_rfc3339())
}

/// True if `ts` (an event timestamp) is within `[cutoff, now]` for `now`'s
/// window. Both `ts` and `cutoff` are RFC 3339 UTC strings produced the same
/// way, so a lexical compare is an instant compare.
fn within_window(ts: &str, cutoff: &str, now_rfc3339: &str) -> bool {
    let (Ok(ts), Ok(cutoff), Ok(_now)) = (
        chrono::DateTime::parse_from_rfc3339(ts),
        chrono::DateTime::parse_from_rfc3339(cutoff),
        chrono::DateTime::parse_from_rfc3339(now_rfc3339),
    ) else {
        return false;
    };
    // Do not let a local-clock rollback erase a durable event whose monotonic
    // sequence still precedes the current command. A valid future wall-clock
    // timestamp therefore remains conservatively live until the clock catches
    // up; only events older than the lower window bound expire.
    ts >= cutoff
}

fn correlation_provenance(events: &[&TypedEvent]) -> EventProvenance {
    if events
        .iter()
        .any(|event| event.provenance == EventProvenance::Provisional)
    {
        EventProvenance::Provisional
    } else if events
        .iter()
        .any(|event| event.provenance == EventProvenance::Unresolved)
    {
        EventProvenance::Unresolved
    } else {
        EventProvenance::Confirmed
    }
}

fn provenance_safe_description(
    provenance: EventProvenance,
    confirmed: String,
    conservative: String,
) -> String {
    match provenance {
        EventProvenance::Confirmed => confirmed,
        EventProvenance::Unresolved | EventProvenance::Provisional => format!(
            "{conservative} At least one source is pending or has unresolved execution evidence; Tirith enforces this conservatively but does not assert that source executed."
        ),
    }
}

/// Run every correlation rule over `events` as of `now_rfc3339` (an RFC 3339 UTC
/// instant). `events` need not be sorted. Returns one [`CorrelationHit`] per rule
/// that matched (a rule fires at most once per call).
pub fn correlate(events: &[TypedEvent], now_rfc3339: &str) -> Vec<CorrelationHit> {
    // `TypedEvent` keeps public fields for compatibility, so callers can bypass
    // its safe constructor/serde paths with a struct literal. Never match or
    // render those borrowed values directly. The private clone is fully
    // projected and receives a sequence-only identity before any description,
    // ordering key, or signature is built.
    let events: Vec<TypedEvent> = events
        .iter()
        .map(privacy_project_correlation_event)
        .collect();
    let mut hits = Vec::new();

    if let Some(hit) = secret_then_network(&events, now_rfc3339) {
        hits.push(hit);
    }
    if let Some(hit) = dependency_change_then_network(&events, now_rfc3339) {
        hits.push(hit);
    }
    if let Some(hit) = delete_then_force_push(&events, now_rfc3339) {
        hits.push(hit);
    }
    if let Some(hit) = mass_file_deletion(&events, now_rfc3339) {
        hits.push(hit);
    }

    // Keep this final projection even though each current constructor consumes
    // only projected events. It makes the public return boundary mandatory if a
    // future correlation adds free-form text without remembering to sanitize it.
    for hit in &mut hits {
        privacy_project_correlation_hit(hit);
    }

    hits
}

fn privacy_project_correlation_event(event: &TypedEvent) -> TypedEvent {
    let mut projected = event.clone();
    privacy_project_typed_event(&mut projected);
    projected.event_id = if projected.sequence > 0 {
        // This is the same sequence-only presentation identity used by session
        // state projection. Matching that established grammar preserves exact
        // de-dup markers across the subsequent serialization round-trip.
        format!("legacy-event-{}", projected.sequence)
    } else {
        String::new()
    };
    projected
}

/// Find the earliest event of `kind` within the window, returning the event.
fn earliest_in_window<'a>(
    events: &'a [TypedEvent],
    kind: EventKind,
    cutoff: &str,
    now_rfc3339: &str,
) -> Option<&'a TypedEvent> {
    events
        .iter()
        .filter(|e| e.kind == kind && within_window(&e.timestamp, cutoff, now_rfc3339))
        .min_by(|a, b| event_order(a, b))
}

fn event_order(left: &TypedEvent, right: &TypedEvent) -> std::cmp::Ordering {
    if left.sequence > 0 && right.sequence > 0 {
        left.sequence
            .cmp(&right.sequence)
            .then_with(|| event_semantic_order(left, right))
    } else {
        // Mixed/legacy state has no durable order identity, so retain the old
        // wall-clock ordering as a compatibility fallback. The projected
        // semantic tail makes selection deterministic without trusting an
        // attacker-controlled event id as a tie-breaker.
        left.timestamp
            .cmp(&right.timestamp)
            .then_with(|| left.sequence.cmp(&right.sequence))
            .then_with(|| event_semantic_order(left, right))
    }
}

fn event_semantic_order(left: &TypedEvent, right: &TypedEvent) -> std::cmp::Ordering {
    event_kind_rank(left.kind)
        .cmp(&event_kind_rank(right.kind))
        .then_with(|| {
            event_provenance_rank(left.provenance).cmp(&event_provenance_rank(right.provenance))
        })
        .then_with(|| left.rule_id.cmp(&right.rule_id))
        .then_with(|| left.metadata.cmp(&right.metadata))
}

fn event_kind_rank(kind: EventKind) -> u8 {
    match kind {
        EventKind::ProcessExec => 0,
        EventKind::FileWrite => 1,
        EventKind::FileDelete => 2,
        EventKind::GitForcePush => 3,
        EventKind::Network => 4,
        EventKind::SecretWrite => 5,
        EventKind::ShellPipe => 6,
        EventKind::PackageInstall => 7,
    }
}

fn event_provenance_rank(provenance: EventProvenance) -> u8 {
    match provenance {
        EventProvenance::Confirmed => 0,
        EventProvenance::Unresolved => 1,
        EventProvenance::Provisional => 2,
    }
}

fn causally_after(candidate: &TypedEvent, prior: &TypedEvent) -> bool {
    if candidate.sequence > 0 && prior.sequence > 0 {
        candidate.sequence > prior.sequence
    } else {
        candidate.timestamp > prior.timestamp
    }
}

/// `B` of kind `b_kind` happened strictly after `after`, within the wall-clock
/// window. Stable non-zero session sequences are authoritative, including when
/// two separate transitions share a timestamp; legacy/mixed events retain the
/// timestamp fallback.
fn any_after<'a>(
    events: &'a [TypedEvent],
    b_kind: EventKind,
    after: &TypedEvent,
    cutoff: &str,
    now_rfc3339: &str,
) -> Option<&'a TypedEvent> {
    // Return the EARLIEST matching B by timestamp, not the first by slice order, so
    // the result is deterministic regardless of how the ring was filled.
    events
        .iter()
        .filter(|e| {
            e.kind == b_kind
                && within_window(&e.timestamp, cutoff, now_rfc3339)
                && causally_after(e, after)
        })
        .min_by(|a, b| event_order(a, b))
}

/// Stable signature part for one source event. A non-zero session sequence is
/// sufficient inside the owning session and cannot carry a raw or
/// secret-derived opaque id; timestamp-only events exist solely for
/// mixed-version compatibility.
fn event_signature_part(event: &TypedEvent) -> String {
    if event.sequence > 0 {
        format!("e:legacy-event-{}:{}", event.sequence, event.sequence)
    } else {
        format!("t:{}", event.timestamp)
    }
}

/// Build a stable de-dup signature for a correlation from its rule and source
/// events.
fn signature(rule_id: RuleId, events: &[&TypedEvent]) -> String {
    let mut sig = format!("{rule_id:?}");
    for event in events {
        sig.push('|');
        sig.push_str(&event_signature_part(event));
    }
    sig
}

/// The valid legacy timestamp parts in a signature. Current signatures prefer a
/// sequence-derived `e:` part and therefore yield no timestamp here; pre-sequence
/// signatures retain their RFC 3339 timestamp for mixed-version expiry. Invalid
/// or attacker-provided free text is never returned.
pub fn signature_event_timestamps(sig: &str) -> impl Iterator<Item = &str> {
    sig.split('|').skip(1).filter_map(|part| {
        let timestamp = if let Some(timestamp) = part.strip_prefix("t:") {
            timestamp
        } else if part.starts_with("e:") {
            return None;
        } else {
            // Pre-stable-id signature: the part itself was a timestamp.
            part
        };
        chrono::DateTime::parse_from_rfc3339(timestamp)
            .ok()
            .map(|_| timestamp)
    })
}

/// Whether at least one source named by a correlation signature is still in the
/// live event window. Understands current sequence-derived signatures, old
/// opaque-id-plus-sequence signatures, and legacy timestamp signatures so
/// mixed-version state expires markers correctly. Old opaque ids are ignored:
/// sequence allocation is unique within the owning session, while accepting the
/// old id as an output/matching authority would preserve a secret-bearing value.
pub fn signature_references_live_event(sig: &str, events: &[TypedEvent]) -> bool {
    let events: Vec<TypedEvent> = events
        .iter()
        .map(privacy_project_correlation_event)
        .collect();
    sig.split('|').skip(1).any(|part| {
        if let Some(rest) = part.strip_prefix("e:") {
            let Some((_, sequence)) = rest.rsplit_once(':') else {
                return false;
            };
            let Ok(sequence) = sequence.parse::<u64>() else {
                return false;
            };
            events
                .iter()
                .any(|event| event.sequence > 0 && event.sequence == sequence)
        } else {
            let timestamp = part.strip_prefix("t:").unwrap_or(part);
            let Some(timestamp) = canonical_correlation_timestamp(timestamp) else {
                return false;
            };
            events.iter().any(|event| {
                canonical_correlation_timestamp(&event.timestamp).as_deref()
                    == Some(timestamp.as_str())
            })
        }
    })
}

/// SecretWrite THEN Network within 30s -> CRITICAL.
fn secret_then_network(events: &[TypedEvent], now_rfc3339: &str) -> Option<CorrelationHit> {
    let cut = cutoff(now_rfc3339, SECRET_THEN_NETWORK_WINDOW_SECS)?;
    let secret = earliest_in_window(events, EventKind::SecretWrite, &cut, now_rfc3339)?;
    let net = any_after(events, EventKind::Network, secret, &cut, now_rfc3339)?;
    let host = net
        .metadata
        .get("host")
        .or_else(|| net.metadata.get("domain"))
        .map(|h| h.as_str())
        .unwrap_or("a network destination");
    let provenance = correlation_provenance(&[secret, net]);
    Some(CorrelationHit {
        rule_id: RuleId::SecretWriteThenNetwork,
        severity: Severity::Critical,
        title: "Secret write followed by network egress".to_string(),
        description: provenance_safe_description(
            provenance,
            format!(
                "A secret-bearing file was written, then a network call to {host} ran within {SECRET_THEN_NETWORK_WINDOW_SECS}s. This is the shape of a credential-exfiltration chain."
            ),
            format!(
                "A secret-write-shaped event was followed by a network-egress observation for {host} within {SECRET_THEN_NETWORK_WINDOW_SECS}s. This is the shape of a credential-exfiltration chain."
            ),
        ),
        provenance,
        signature: signature(RuleId::SecretWriteThenNetwork, &[secret, net]),
    })
}

/// Dependency-manifest FileWrite THEN Network within 60s -> WARN.
fn dependency_change_then_network(
    events: &[TypedEvent],
    now_rfc3339: &str,
) -> Option<CorrelationHit> {
    let cut = cutoff(now_rfc3339, DEP_CHANGE_THEN_NETWORK_WINDOW_SECS)?;
    // A manifest write is a FileWrite carrying the manifest flag, OR (defence in
    // depth) a FileWrite whose path basename is itself a known manifest.
    let manifest_write = events
        .iter()
        .filter(|e| {
            e.kind == EventKind::FileWrite && within_window(&e.timestamp, &cut, now_rfc3339)
        })
        .filter(|e| {
            e.metadata.get(MANIFEST_FLAG_KEY).map(|v| v == "true") == Some(true)
                || e.path()
                    .map(basename)
                    .map(is_dependency_manifest)
                    .unwrap_or(false)
        })
        .min_by(|a, b| event_order(a, b))?;
    let net = any_after(
        events,
        EventKind::Network,
        manifest_write,
        &cut,
        now_rfc3339,
    )?;
    let what = manifest_write
        .path()
        .map(basename)
        .filter(|b| !b.is_empty())
        .unwrap_or("a dependency manifest");
    let host = net
        .metadata
        .get("host")
        .or_else(|| net.metadata.get("domain"))
        .map(|h| h.as_str())
        .unwrap_or("a network destination");
    let provenance = correlation_provenance(&[manifest_write, net]);
    Some(CorrelationHit {
        rule_id: RuleId::DependencyChangeThenNetwork,
        severity: Severity::Medium,
        title: "Dependency manifest change followed by network egress".to_string(),
        description: provenance_safe_description(
            provenance,
            format!(
                "{what} was modified, then a network call to {host} ran within {DEP_CHANGE_THEN_NETWORK_WINDOW_SECS}s. A dependency edit that immediately phones out can indicate a poisoned install step."
            ),
            format!(
                "A {what} modification-shaped event was followed by a network-egress observation for {host} within {DEP_CHANGE_THEN_NETWORK_WINDOW_SECS}s. This can indicate a poisoned install step."
            ),
        ),
        provenance,
        signature: signature(RuleId::DependencyChangeThenNetwork, &[manifest_write, net]),
    })
}

/// FileDelete THEN GitForcePush within 60s -> CRITICAL.
fn delete_then_force_push(events: &[TypedEvent], now_rfc3339: &str) -> Option<CorrelationHit> {
    let cut = cutoff(now_rfc3339, DELETE_THEN_FORCE_PUSH_WINDOW_SECS)?;
    let del = earliest_in_window(events, EventKind::FileDelete, &cut, now_rfc3339)?;
    let push = any_after(events, EventKind::GitForcePush, del, &cut, now_rfc3339)?;
    let provenance = correlation_provenance(&[del, push]);
    Some(CorrelationHit {
        rule_id: RuleId::DeleteThenForcePush,
        severity: Severity::Critical,
        title: "File deletion followed by git force-push".to_string(),
        description: provenance_safe_description(
            provenance,
            format!(
                "A file was deleted, then a `git push --force` ran within {DELETE_THEN_FORCE_PUSH_WINDOW_SECS}s. Deleting then force-pushing can erase history and overwrite a remote branch."
            ),
            format!(
                "A file-deletion-shaped event was followed by a force-push observation within {DELETE_THEN_FORCE_PUSH_WINDOW_SECS}s. This sequence can erase history and overwrite a remote branch."
            ),
        ),
        provenance,
        signature: signature(RuleId::DeleteThenForcePush, &[del, push]),
    })
}

/// >= 3 deleted NON-BUILD PATHS within 20s -> CRITICAL.
///
/// Counts PATHS, not delete COMMANDS, and counts only NON-build-artifact paths.
/// Each [`EventKind::FileDelete`] event reports its non-build path count via
/// [`TypedEvent::non_build_delete_count`] (the precomputed
/// [`NON_BUILD_DELETE_COUNT_KEY`] metadatum when present, else a per-path fallback),
/// and the threshold is checked against the SUM of those counts across every
/// matching event. So a single `rm a b c d` (one event, four non-build paths) trips
/// the rule, three separate single-path source deletes still do, and a mixed
/// `rm app.rs dist/x dist/y` contributes only its one non-build path, no longer
/// letting the single sampled path decide for the whole batch.
fn mass_file_deletion(events: &[TypedEvent], now_rfc3339: &str) -> Option<CorrelationHit> {
    let cut = cutoff(now_rfc3339, MASS_DELETE_WINDOW_SECS)?;
    let matched: Vec<&TypedEvent> = events
        .iter()
        .filter(|e| {
            e.kind == EventKind::FileDelete && within_window(&e.timestamp, &cut, now_rfc3339)
        })
        .collect();
    // Sum NON-BUILD deleted PATHS across the matching events: each event reports its
    // own non-build path count, so a mixed command contributes exactly its real
    // non-build paths rather than all-or-nothing on one representative path.
    let count: usize = matched.iter().map(|e| e.non_build_delete_count()).sum();
    if count >= MASS_DELETE_THRESHOLD {
        // Signature spans the latest CONTRIBUTING delete so a later burst (a
        // genuinely new mass deletion) re-surfaces while the same set does not.
        // Only deletes that actually contribute a non-build path are eligible: a
        // zero-contribution artifact-only delete (`rm dist/x`) landing later in the
        // window must NOT change the signature, or it would let the SAME already
        // surfaced non-build burst be re-emitted on a pure artifact-cleanup command.
        let mut contributing: Vec<&TypedEvent> = matched
            .iter()
            .filter(|e| e.non_build_delete_count() > 0)
            .copied()
            .collect();
        contributing.sort_unstable_by(|left, right| event_order(left, right));
        let provenance = correlation_provenance(&contributing);
        Some(CorrelationHit {
            rule_id: RuleId::MassFileDeletion,
            severity: Severity::Critical,
            title: "Mass file deletion in a short window".to_string(),
            description: provenance_safe_description(
                provenance,
                format!(
                    "{count} non-build files were deleted within {MASS_DELETE_WINDOW_SECS}s. A burst of deletions can be destructive (ransomware-like or an accidental recursive wipe)."
                ),
                format!(
                    "{count} non-build file-deletion observations fell within {MASS_DELETE_WINDOW_SECS}s. This burst has a destructive shape (ransomware-like or an accidental recursive wipe)."
                ),
            ),
            provenance,
            signature: signature(
                RuleId::MassFileDeletion,
                &[contributing.last().copied()?],
            ),
        })
    } else {
        None
    }
}

/// Final path component, split on both `/` and `\`.
fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `base + offset_secs`, rendered the way recorders render timestamps.
    fn ts(base: chrono::DateTime<chrono::Utc>, offset_secs: i64) -> String {
        (base + chrono::Duration::seconds(offset_secs)).to_rfc3339()
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }

    fn ev(timestamp: String, kind: EventKind) -> TypedEvent {
        TypedEvent {
            event_id: String::new(),
            sequence: 0,
            provenance: EventProvenance::Confirmed,
            timestamp,
            kind,
            rule_id: "test".to_string(),
            metadata: BTreeMap::new(),
        }
    }

    fn ev_path(timestamp: String, kind: EventKind, path: &str) -> TypedEvent {
        let mut e = ev(timestamp, kind);
        e.metadata.insert("path".to_string(), path.to_string());
        e
    }

    fn ev_path_count(timestamp: String, kind: EventKind, path: &str, count: usize) -> TypedEvent {
        let mut e = ev_path(timestamp, kind, path);
        e.metadata
            .insert(DELETE_COUNT_KEY.to_string(), count.to_string());
        e
    }

    /// A FileDelete event carrying BOTH `count` (total paths) and `non_build_count`
    /// (the precomputed non-build paths), as the real deriver records for a mixed
    /// command. `path` is the representative first path (here a build artifact, to
    /// prove the correlation uses non_build_count and NOT the representative path).
    fn ev_mixed_delete(
        timestamp: String,
        path: &str,
        total: usize,
        non_build: usize,
    ) -> TypedEvent {
        let mut e = ev_path_count(timestamp, EventKind::FileDelete, path, total);
        e.metadata.insert(
            NON_BUILD_DELETE_COUNT_KEY.to_string(),
            non_build.to_string(),
        );
        e
    }

    fn fired(hits: &[CorrelationHit], rule: RuleId) -> bool {
        hits.iter().any(|h| h.rule_id == rule)
    }

    // --- SecretWrite THEN Network -------------------------------------------

    #[test]
    fn secret_then_network_fires_in_window() {
        let base = now();
        // Place both events comfortably inside the 30s window, secret first.
        let events = vec![
            ev(ts(base, -20), EventKind::SecretWrite),
            ev(ts(base, -10), EventKind::Network),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::SecretWriteThenNetwork));
    }

    #[test]
    fn secret_then_network_outside_window_does_not_fire() {
        let base = now();
        // Secret is 40s before now: outside the 30s window.
        let events = vec![
            ev(ts(base, -40), EventKind::SecretWrite),
            ev(ts(base, -38), EventKind::Network),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::SecretWriteThenNetwork));
    }

    #[test]
    fn secret_then_network_wrong_order_does_not_fire() {
        let base = now();
        // Network BEFORE the secret write: not the "A then B" sequence.
        let events = vec![
            ev(ts(base, -20), EventKind::Network),
            ev(ts(base, -10), EventKind::SecretWrite),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::SecretWriteThenNetwork));
    }

    #[test]
    fn secret_then_network_same_instant_does_not_fire() {
        // A single command (`curl https://x -o id_rsa`) emits BOTH a SecretWrite
        // and a Network at one shared timestamp. The network call IS the write,
        // not a subsequent exfiltration, so the strict `>` boundary must keep
        // this from firing a Critical credential-exfiltration correlation.
        let base = now();
        let same = ts(base, -10);
        let events = vec![
            ev(same.clone(), EventKind::SecretWrite),
            ev(same, EventKind::Network),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::SecretWriteThenNetwork));
    }

    // --- DependencyChange THEN Network --------------------------------------

    #[test]
    fn dependency_change_then_network_fires_via_flag() {
        let base = now();
        let mut write = ev(ts(base, -50), EventKind::FileWrite);
        write
            .metadata
            .insert(MANIFEST_FLAG_KEY.to_string(), "true".to_string());
        let events = vec![write, ev(ts(base, -10), EventKind::Network)];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::DependencyChangeThenNetwork));
        // It is a WARN-class (Medium) correlation, not CRITICAL.
        let hit = hits
            .iter()
            .find(|h| h.rule_id == RuleId::DependencyChangeThenNetwork)
            .unwrap();
        assert_eq!(hit.severity, Severity::Medium);
    }

    #[test]
    fn dependency_change_then_network_fires_via_basename() {
        let base = now();
        let events = vec![
            ev_path(ts(base, -50), EventKind::FileWrite, "repo/package.json"),
            ev(ts(base, -5), EventKind::Network),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::DependencyChangeThenNetwork));
    }

    #[test]
    fn dependency_change_non_manifest_write_does_not_fire() {
        let base = now();
        let events = vec![
            ev_path(ts(base, -50), EventKind::FileWrite, "src/main.rs"),
            ev(ts(base, -5), EventKind::Network),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::DependencyChangeThenNetwork));
    }

    #[test]
    fn dependency_change_then_network_outside_window_does_not_fire() {
        let base = now();
        // Manifest write 70s ago: outside the 60s window.
        let events = vec![
            ev_path(ts(base, -70), EventKind::FileWrite, "go.mod"),
            ev(ts(base, -65), EventKind::Network),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::DependencyChangeThenNetwork));
    }

    // --- FileDelete THEN GitForcePush ---------------------------------------

    #[test]
    fn delete_then_force_push_fires_in_window() {
        let base = now();
        let events = vec![
            ev(ts(base, -40), EventKind::FileDelete),
            ev(ts(base, -5), EventKind::GitForcePush),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::DeleteThenForcePush));
    }

    #[test]
    fn delete_then_force_push_wrong_order_does_not_fire() {
        let base = now();
        let events = vec![
            ev(ts(base, -40), EventKind::GitForcePush),
            ev(ts(base, -5), EventKind::FileDelete),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::DeleteThenForcePush));
    }

    #[test]
    fn delete_then_force_push_outside_window_does_not_fire() {
        let base = now();
        // Delete 90s ago: outside the 60s window.
        let events = vec![
            ev(ts(base, -90), EventKind::FileDelete),
            ev(ts(base, -80), EventKind::GitForcePush),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::DeleteThenForcePush));
    }

    // --- Mass file deletion --------------------------------------------------

    #[test]
    fn mass_deletion_fires_at_threshold() {
        let base = now();
        let events = vec![
            ev_path(ts(base, -15), EventKind::FileDelete, "src/a.rs"),
            ev_path(ts(base, -10), EventKind::FileDelete, "src/b.rs"),
            ev_path(ts(base, -5), EventKind::FileDelete, "src/c.rs"),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_below_threshold_does_not_fire() {
        let base = now();
        let events = vec![
            ev_path(ts(base, -15), EventKind::FileDelete, "src/a.rs"),
            ev_path(ts(base, -5), EventKind::FileDelete, "src/b.rs"),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_excludes_build_artifacts() {
        let base = now();
        // Three deletes, but all under build-artifact dirs: must NOT trip.
        let events = vec![
            ev_path(ts(base, -15), EventKind::FileDelete, "node_modules/a.js"),
            ev_path(ts(base, -10), EventKind::FileDelete, "target/debug/b"),
            ev_path(ts(base, -5), EventKind::FileDelete, "dist/c.js"),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_mixes_build_and_source_counts_only_source() {
        let base = now();
        // Two build-artifact deletes + two real source deletes = 2 counted: below
        // the threshold of 3, so it must NOT fire.
        let events = vec![
            ev_path(ts(base, -15), EventKind::FileDelete, "node_modules/a.js"),
            ev_path(ts(base, -14), EventKind::FileDelete, "target/b"),
            ev_path(ts(base, -10), EventKind::FileDelete, "src/x.rs"),
            ev_path(ts(base, -5), EventKind::FileDelete, "src/y.rs"),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::MassFileDeletion));

        // Add a third real source delete: now it fires.
        let mut events = events;
        events.push(ev_path(ts(base, -3), EventKind::FileDelete, "src/z.rs"));
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_outside_window_does_not_fire() {
        let base = now();
        // All deletes are >20s old.
        let events = vec![
            ev_path(ts(base, -40), EventKind::FileDelete, "src/a.rs"),
            ev_path(ts(base, -35), EventKind::FileDelete, "src/b.rs"),
            ev_path(ts(base, -30), EventKind::FileDelete, "src/c.rs"),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_single_multipath_command_fires() {
        // A SINGLE `rm a b c d` records ONE FileDelete event whose count is 4.
        // Counting PATHS (not events) means it trips the >= 3 threshold on its
        // own, which is the whole point of this fix.
        let base = now();
        let events = vec![ev_path_count(
            ts(base, -5),
            EventKind::FileDelete,
            "src/a.rs",
            4,
        )];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_single_multipath_below_threshold_does_not_fire() {
        // `rm a b` is one event, count 2: below the threshold of 3.
        let base = now();
        let events = vec![ev_path_count(
            ts(base, -5),
            EventKind::FileDelete,
            "src/a.rs",
            2,
        )];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_single_multipath_artifacts_does_not_fire() {
        // `rm dist/x dist/y dist/z` records one event whose first path is a build
        // artifact, so the event is excluded entirely even though its count is 3.
        let base = now();
        let events = vec![ev_path_count(
            ts(base, -5),
            EventKind::FileDelete,
            "dist/x",
            3,
        )];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_missing_count_key_treated_as_one() {
        // Back-compat: events without the count key weigh 1 each, so three of
        // them still trip the rule (the old behaviour) and two do not.
        let base = now();
        let two = vec![
            ev_path(ts(base, -10), EventKind::FileDelete, "src/a.rs"),
            ev_path(ts(base, -5), EventKind::FileDelete, "src/b.rs"),
        ];
        assert!(!fired(
            &correlate(&two, &base.to_rfc3339()),
            RuleId::MassFileDeletion
        ));
        let mut three = two;
        three.push(ev_path(ts(base, -3), EventKind::FileDelete, "src/c.rs"));
        assert!(fired(
            &correlate(&three, &base.to_rfc3339()),
            RuleId::MassFileDeletion
        ));
    }

    #[test]
    fn mass_deletion_sums_counts_across_events() {
        // Two commands: `rm a b` (count 2) then `rm c` (count 1) = 3 paths total.
        let base = now();
        let events = vec![
            ev_path_count(ts(base, -10), EventKind::FileDelete, "src/a.rs", 2),
            ev_path_count(ts(base, -5), EventKind::FileDelete, "src/c.rs", 1),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_prefers_non_build_count_over_representative_path() {
        // A7: when an event carries `non_build_count`, the correlation SUMS that and
        // ignores the representative `path`. A mixed `rm app.rs dist/x dist/y` is
        // count=3 but non_build_count=1, and its representative path here is a build
        // artifact: it must contribute 1, not 3 and not 0.
        let base = now();
        // One mixed event (1 non-build) is below the threshold on its own.
        let one = vec![ev_mixed_delete(ts(base, -5), "dist/x", 3, 1)];
        assert!(
            !fired(
                &correlate(&one, &base.to_rfc3339()),
                RuleId::MassFileDeletion
            ),
            "a single mixed delete with one non-build path must NOT fire"
        );
        // Three such mixed events sum to 3 non-build paths and DO fire, even though
        // every representative path is a build artifact (the old heuristic would
        // have excluded them all and never fired).
        let three = vec![
            ev_mixed_delete(ts(base, -15), "dist/x", 3, 1),
            ev_mixed_delete(ts(base, -10), "node_modules/y", 2, 1),
            ev_mixed_delete(ts(base, -5), "target/z", 4, 1),
        ];
        assert!(
            fired(
                &correlate(&three, &base.to_rfc3339()),
                RuleId::MassFileDeletion
            ),
            "three mixed deletes summing to 3 non-build paths must fire"
        );
        // An explicit non_build_count of 0 contributes nothing even with a non-build
        // representative path and a large total count.
        let all_build = vec![ev_mixed_delete(ts(base, -5), "src/keep.rs", 9, 0)];
        assert!(
            !fired(
                &correlate(&all_build, &base.to_rfc3339()),
                RuleId::MassFileDeletion
            ),
            "an explicit non_build_count of 0 must contribute nothing"
        );
    }

    #[test]
    fn mass_deletion_signature_ignores_zero_contribution_deletes() {
        // A zero-contribution artifact-only delete landing LATER in the window must
        // not change the de-dup signature: otherwise the SAME already-surfaced
        // non-build burst would be re-emitted as a fresh hit on a pure artifact
        // cleanup (`rm dist/x`), double-counting it. The signature must span only the
        // latest CONTRIBUTING (non-build) delete.
        let base = now();
        // A real >= 3 non-build burst, with `t-5` the latest contributing delete.
        let burst = vec![
            ev_path(ts(base, -15), EventKind::FileDelete, "src/a.rs"),
            ev_path(ts(base, -10), EventKind::FileDelete, "src/b.rs"),
            ev_path(ts(base, -5), EventKind::FileDelete, "src/c.rs"),
        ];
        let first = correlate(&burst, &base.to_rfc3339());
        let sig_before = first
            .iter()
            .find(|h| h.rule_id == RuleId::MassFileDeletion)
            .expect("the burst must surface MassFileDeletion")
            .signature
            .clone();

        // Now a later pure-artifact `rm dist/x` (0 non-build) enters the window. The
        // burst is unchanged, so the signature must be identical and the
        // session-level dedup would treat it as already surfaced (not re-emitted).
        let mut with_artifact = burst.clone();
        with_artifact.push(ev_path(ts(base, -2), EventKind::FileDelete, "dist/x"));
        let second = correlate(&with_artifact, &base.to_rfc3339());
        let sig_after = second
            .iter()
            .find(|h| h.rule_id == RuleId::MassFileDeletion)
            .expect("the burst still tallies >= 3 non-build paths")
            .signature
            .clone();

        assert_eq!(
            sig_before, sig_after,
            "a zero-contribution artifact delete must not change the signature \
             (would let the same burst re-emit): {sig_before} vs {sig_after}"
        );
        // The signature must anchor on the latest CONTRIBUTING delete (`t-5`), not the
        // later artifact-only delete (`t-2`).
        assert!(
            sig_after.contains(&ts(base, -5)),
            "signature must span the latest non-build delete: {sig_after}"
        );
        assert!(
            !sig_after.contains(&ts(base, -2)),
            "signature must NOT span the zero-contribution artifact delete: {sig_after}"
        );
    }

    #[test]
    fn any_after_returns_earliest_match_regardless_of_slice_order() {
        // A8: with two valid B candidates after A, `any_after` (via the time-ordered
        // correlations) must key on the EARLIEST B by timestamp, deterministically,
        // not the first by slice order. Place the later B first in the slice.
        let base = now();
        let secret_ts = ts(base, -20);
        let early_net = ts(base, -15);
        let late_net = ts(base, -5);
        let events = vec![
            ev(secret_ts.clone(), EventKind::SecretWrite),
            // Later B appears BEFORE the earlier B in slice order.
            ev(late_net.clone(), EventKind::Network),
            ev(early_net.clone(), EventKind::Network),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        let hit = hits
            .iter()
            .find(|h| h.rule_id == RuleId::SecretWriteThenNetwork)
            .expect("secret-then-network must fire");
        // The de-dup signature embeds the chosen B timestamp; it must be the EARLIER
        // network event, independent of slice order.
        assert!(
            hit.signature.contains(&early_net),
            "the earliest matching B must be chosen: {}",
            hit.signature
        );
        assert!(
            !hit.signature.contains(&late_net),
            "the later B must not be the chosen match: {}",
            hit.signature
        );
    }

    #[test]
    fn legacy_missing_provenance_is_unresolved() {
        let event: TypedEvent = serde_json::from_value(serde_json::json!({
            "event_id": "legacy-event",
            "sequence": 1,
            "timestamp": "2026-01-01T00:00:00Z",
            "kind": "network",
            "rule_id": "network_egress",
            "metadata": {}
        }))
        .expect("legacy typed event");
        assert_eq!(event.provenance, EventProvenance::Unresolved);
    }

    #[test]
    fn typed_event_public_traits_project_the_complete_free_text_graph() {
        let canary = format!("ghp_canary_{}", "A".repeat(30));
        let mut event = TypedEvent::new(
            "2026-01-01T00:00:00Z",
            EventKind::FileWrite,
            &format!("rule-{canary}"),
        )
        .with_meta("path", &format!("/wallets/{canary}/keypair.json"))
        .with_meta(
            "host",
            &format!("https://operator:{canary}@rpc.example/private/{canary}"),
        )
        .with_meta(MANIFEST_FLAG_KEY, "true")
        .with_meta(&format!("private-{canary}"), &format!("value-{canary}"));
        event.event_id = format!("event-{canary}");
        event.sequence = 7;

        let serialized = serde_json::to_string(&event).expect("serialize projected event");
        let debug = format!("{event:?}");
        assert!(!serialized.contains(&canary), "{serialized}");
        assert!(!debug.contains(&canary), "{debug}");

        let value: serde_json::Value = serde_json::from_str(&serialized).expect("projected JSON");
        assert_eq!(value["event_id"], PRIVACY_REDACTED_EVENT_ID);
        assert_eq!(value["metadata"][MANIFEST_FLAG_KEY], "true");
        assert!(value["metadata"]["path"]
            .as_str()
            .is_some_and(|path| path.contains("[REDACTED:tirith_canary]")));
        assert_eq!(value["metadata"]["host"], "https://rpc.example");
    }

    #[test]
    fn typed_event_deserialization_projects_and_bounds_hostile_metadata() {
        let canary = format!("ghp_canary_{}", "B".repeat(30));
        let mut metadata = serde_json::Map::new();
        metadata.insert(
            "path".to_string(),
            serde_json::Value::String(format!("/secrets/{canary}/wallet.dat")),
        );
        metadata.insert(
            "host".to_string(),
            serde_json::Value::String(format!(
                "https://operator:{canary}@rpc.example/api/{canary}"
            )),
        );
        metadata.insert(
            MANIFEST_FLAG_KEY.to_string(),
            serde_json::Value::String("true".to_string()),
        );
        for index in 0..64 {
            metadata.insert(
                format!("extension-{index:02}-{canary}"),
                serde_json::Value::String(format!("value-{index}-{canary}")),
            );
        }
        let oversized = serde_json::json!({
            "event_id": format!("legacy-{canary}"),
            "sequence": 9,
            "timestamp": "2026-01-01T00:00:00Z",
            "kind": "network",
            "rule_id": format!("network-{canary}"),
            "metadata": metadata,
        });
        assert!(
            serde_json::from_value::<TypedEvent>(oversized).is_err(),
            "oversized untrusted metadata must be rejected before it can launder strict state"
        );

        let event: TypedEvent = serde_json::from_value(serde_json::json!({
            "event_id": format!("legacy-{canary}"),
            "sequence": 9,
            "timestamp": "2026-01-01T00:00:00Z",
            "kind": "network",
            "rule_id": format!("network-{canary}"),
            "metadata": {
                "path": format!("/secrets/{canary}/wallet.dat"),
                "host": format!("https://operator:{canary}@rpc.example/api/{canary}"),
                (MANIFEST_FLAG_KEY): "true",
            },
        }))
        .expect("deserialize projected event");

        assert_eq!(event.event_id, PRIVACY_REDACTED_EVENT_ID);
        assert!(event.metadata.len() <= MAX_TYPED_EVENT_METADATA_ENTRIES);
        assert_eq!(
            event.metadata.get(MANIFEST_FLAG_KEY).map(String::as_str),
            Some("true")
        );
        assert_eq!(
            event.metadata.get("host").map(String::as_str),
            Some("https://rpc.example")
        );
        let serialized = serde_json::to_string(&event).expect("reserialize projected event");
        let debug = format!("{event:?}");
        assert!(!serialized.contains(&canary), "{serialized}");
        assert!(!debug.contains(&canary), "{debug}");
        assert!(event.metadata.keys().all(|key| key.len() <= 64));
        assert!(event.metadata.values().all(|value| value.len() <= 512));
    }

    #[test]
    fn typed_event_deserialization_rejects_projected_empty_rule_or_key() {
        let base = serde_json::json!({
            "event_id": "event-safe",
            "sequence": 1,
            "timestamp": "2026-01-01T00:00:00Z",
            "kind": "network",
            "rule_id": "\u{1b}[31m",
            "metadata": {"host": "rpc.example"},
        });
        assert!(serde_json::from_value::<TypedEvent>(base).is_err());

        let control_key = serde_json::json!({
            "event_id": "event-safe",
            "sequence": 1,
            "timestamp": "2026-01-01T00:00:00Z",
            "kind": "network",
            "rule_id": "network_egress",
            "metadata": {"\u{1b}[0m": "true"},
        });
        assert!(serde_json::from_value::<TypedEvent>(control_key).is_err());
    }

    #[test]
    fn event_prototype_public_traits_project_direct_and_hostile_free_text() {
        let contextual_canary = format!("ghp_canary_{}", "P".repeat(30));
        let provider_token = "providerToken123456789";
        let host = format!(
            "https://operator:{contextual_canary}@mainnet.infura.io/v3/{provider_token}?token={contextual_canary}"
        );
        let prototype = EventPrototype {
            kind: EventKind::Network,
            rule_id: format!("network-{contextual_canary}"),
            metadata: BTreeMap::from([
                ("host".to_string(), host.clone()),
                (
                    "path".to_string(),
                    format!("/wallet/{contextual_canary}/keypair.json"),
                ),
            ]),
        };

        let debug = format!("{prototype:?}");
        let serialized = serde_json::to_string(&prototype).expect("safe prototype JSON");
        for rejected in [&contextual_canary, provider_token] {
            assert!(!debug.contains(rejected), "{debug}");
            assert!(!serialized.contains(rejected), "{serialized}");
        }
        let wire: serde_json::Value =
            serde_json::from_str(&serialized).expect("prototype wire field names");
        assert_eq!(wire["kind"], "network");
        assert!(wire.get("rule_id").is_some());
        assert!(wire.get("metadata").is_some());
        assert_eq!(wire["metadata"]["host"], "https://infura.io");

        let deserialized: EventPrototype = serde_json::from_value(serde_json::json!({
            "kind": "network",
            "rule_id": format!("network-{contextual_canary}"),
            "metadata": {
                "host": host,
                "path": format!("/wallet/{contextual_canary}/keypair.json"),
            },
        }))
        .expect("hostile prototype is projected on deserialize");
        let returned = format!("{deserialized:?}");
        assert_eq!(deserialized.kind, EventKind::Network);
        assert_eq!(
            deserialized.metadata.get("host").map(String::as_str),
            Some("https://infura.io")
        );
        assert!(!returned.contains(&contextual_canary), "{returned}");
        assert!(!returned.contains(provider_token), "{returned}");
    }

    #[test]
    fn correlation_projects_direct_inputs_before_returning_fields() {
        let contextual_canary = format!("ghp_canary_{}", "C".repeat(30));
        let provider_token = "providerToken123456789";
        let opaque_secret_digest =
            "a8624f5f421d627c6b65e30bc39d5f78f8e339603d4cfcb4f3c2d795397347bb";
        let mut secret = ev(
            "2026-01-01T00:00:00+00:00".to_string(),
            EventKind::SecretWrite,
        );
        secret.event_id = format!("{opaque_secret_digest}-{contextual_canary}");
        secret.sequence = 41;
        secret.metadata.insert(
            "path".to_string(),
            format!("/wallet/{contextual_canary}/private-key.json"),
        );
        let mut network = ev("2026-01-01T00:00:05+00:00".to_string(), EventKind::Network);
        network.event_id = format!("{provider_token}-{contextual_canary}");
        network.sequence = 42;
        network.metadata.insert(
            "host".to_string(),
            format!(
                "https://operator:{contextual_canary}@mainnet.infura.io/v3/{provider_token}?api_key={contextual_canary}"
            ),
        );

        let hit = correlate(
            &[secret.clone(), network.clone()],
            "2026-01-01T00:00:10+00:00",
        )
        .into_iter()
        .find(|hit| hit.rule_id == RuleId::SecretWriteThenNetwork)
        .expect("directly constructed events still correlate");

        let returned_fields = format!("{}\n{}\n{}", hit.title, hit.description, hit.signature);
        let debug = format!("{hit:?}");
        let serialized = serde_json::to_string(&hit).expect("safe correlation JSON");
        for rejected in [
            contextual_canary.as_str(),
            provider_token,
            opaque_secret_digest,
        ] {
            assert!(!returned_fields.contains(rejected), "{returned_fields}");
            assert!(!debug.contains(rejected), "{debug}");
            assert!(!serialized.contains(rejected), "{serialized}");
        }
        assert!(hit.description.contains("https://infura.io"), "{hit:?}");
        assert_eq!(
            hit.signature,
            "SecretWriteThenNetwork|e:legacy-event-41:41|e:legacy-event-42:42"
        );
        assert!(signature_references_live_event(
            &hit.signature,
            &[secret, network]
        ));
    }

    #[test]
    fn correlation_hit_traits_project_direct_construction_and_hostile_deserialize() {
        let contextual_canary = format!("ghp_canary_{}", "H".repeat(30));
        let provider_token = "providerToken123456789";
        let direct = CorrelationHit {
            rule_id: RuleId::SecretWriteThenNetwork,
            severity: Severity::Critical,
            title: format!("Correlation {contextual_canary}"),
            description: format!(
                "Network to https://mainnet.infura.io/v3/{provider_token}?token={contextual_canary}"
            ),
            provenance: EventProvenance::Confirmed,
            signature: format!("attacker-prefix|e:{contextual_canary}:91|e:{provider_token}:92"),
        };
        let direct_debug = format!("{direct:?}");
        let direct_json = serde_json::to_string(&direct).expect("direct correlation JSON");
        for rejected in [&contextual_canary, provider_token] {
            assert!(!direct_debug.contains(rejected), "{direct_debug}");
            assert!(!direct_json.contains(rejected), "{direct_json}");
        }

        let deserialized: CorrelationHit = serde_json::from_value(serde_json::json!({
            "rule_id": "secret_write_then_network",
            "severity": "CRITICAL",
            "title": format!("Correlation {contextual_canary}"),
            "description": format!(
                "Network to https://mainnet.infura.io/v3/{provider_token}?token={contextual_canary}"
            ),
            "provenance": "confirmed",
            "signature": format!(
                "wrong-rule|e:{contextual_canary}:91|t:2026-01-01T00:00:00Z|e:{provider_token}:92"
            ),
        }))
        .expect("hostile correlation is projected on deserialize");
        let returned_fields = format!(
            "{}\n{}\n{}",
            deserialized.title, deserialized.description, deserialized.signature
        );
        for rejected in [&contextual_canary, provider_token] {
            assert!(!returned_fields.contains(rejected), "{returned_fields}");
        }
        assert_eq!(deserialized.rule_id, RuleId::SecretWriteThenNetwork);
        assert!(deserialized
            .signature
            .starts_with("SecretWriteThenNetwork|e:legacy-event-91:91|t:"));
        assert!(deserialized.signature.ends_with("|e:legacy-event-92:92"));

        let wire = serde_json::to_value(&deserialized).expect("correlation wire fields");
        for field in [
            "rule_id",
            "severity",
            "title",
            "description",
            "provenance",
            "signature",
        ] {
            assert!(wire.get(field).is_some(), "missing {field}: {wire}");
        }
    }

    #[test]
    fn direct_correlation_is_deterministic_without_event_id_tiebreakers() {
        let contextual_canary = format!("ghp_canary_{}", "D".repeat(30));
        let mut secret = ev(
            "2026-01-01T00:00:00+00:00".to_string(),
            EventKind::SecretWrite,
        );
        secret.event_id = format!("secret-{contextual_canary}");
        secret.sequence = 71;

        let mut early_network = ev("2026-01-01T00:00:05+00:00".to_string(), EventKind::Network);
        early_network.event_id = format!("early-{contextual_canary}");
        early_network.sequence = 72;
        early_network.metadata.insert(
            "host".to_string(),
            "https://mainnet.infura.io/v3/firstProviderToken123".to_string(),
        );

        let mut late_network = ev("2026-01-01T00:00:06+00:00".to_string(), EventKind::Network);
        late_network.event_id = format!("late-{contextual_canary}");
        late_network.sequence = 73;
        late_network.metadata.insert(
            "host".to_string(),
            "https://mainnet.infura.io/v3/secondProviderToken456".to_string(),
        );

        let first_order = vec![late_network.clone(), secret.clone(), early_network.clone()];
        let reverse_order = vec![early_network, secret, late_network];
        let select = |events: &[TypedEvent]| {
            correlate(events, "2026-01-01T00:00:10+00:00")
                .into_iter()
                .find(|hit| hit.rule_id == RuleId::SecretWriteThenNetwork)
                .expect("deterministic match")
        };
        let first = select(&first_order);
        let second = select(&reverse_order);
        assert_eq!(first.signature, second.signature);
        assert_eq!(first.description, second.description);
        assert_eq!(
            first.signature,
            "SecretWriteThenNetwork|e:legacy-event-71:71|e:legacy-event-72:72"
        );
        assert!(!format!("{first:?}").contains(&contextual_canary));
    }

    #[test]
    fn same_timestamp_events_follow_strict_sequence_order() {
        let base = now();
        let timestamp = base.to_rfc3339();
        let mut secret = ev(timestamp.clone(), EventKind::SecretWrite);
        secret.event_id = "event-secret".to_string();
        secret.sequence = 41;
        let mut network = ev(timestamp, EventKind::Network);
        network.event_id = "event-network".to_string();
        network.sequence = 42;
        let hits = correlate(&[secret, network], &base.to_rfc3339());
        assert!(fired(&hits, RuleId::SecretWriteThenNetwork));
    }

    #[test]
    fn clock_rollback_keeps_durable_prior_event_conservatively_live() {
        let base = now();
        let mut secret = ev(ts(base, 10), EventKind::SecretWrite);
        secret.event_id = "future-secret".to_string();
        secret.sequence = 71;
        let mut network = ev(ts(base, 0), EventKind::Network);
        network.event_id = "current-network".to_string();
        network.sequence = 72;
        let hits = correlate(&[secret, network], &base.to_rfc3339());
        assert!(fired(&hits, RuleId::SecretWriteThenNetwork));
    }

    #[test]
    fn unresolved_correlation_enforces_without_claiming_execution() {
        let base = now();
        let mut secret = ev(ts(base, -10), EventKind::SecretWrite);
        secret.event_id = "unresolved-secret".to_string();
        secret.sequence = 81;
        secret.provenance = EventProvenance::Unresolved;
        let mut network = ev(ts(base, -1), EventKind::Network);
        network.event_id = "confirmed-network".to_string();
        network.sequence = 82;
        let hit = correlate(&[secret, network], &base.to_rfc3339())
            .into_iter()
            .find(|hit| hit.rule_id == RuleId::SecretWriteThenNetwork)
            .expect("conservative correlation");
        assert_eq!(hit.provenance, EventProvenance::Unresolved);
        assert!(hit.description.contains("does not assert"));
        assert!(!hit.description.contains(" ran "));
    }

    // --- helpers + isolation -------------------------------------------------

    #[test]
    fn empty_events_yield_no_hits() {
        let base = now();
        assert!(correlate(&[], &base.to_rfc3339()).is_empty());
    }

    #[test]
    fn malformed_now_is_safe_no_hits() {
        // A clock string that does not parse must never fabricate a correlation.
        let events = vec![
            ev(
                "2026-01-01T00:00:00+00:00".to_string(),
                EventKind::SecretWrite,
            ),
            ev("2026-01-01T00:00:05+00:00".to_string(), EventKind::Network),
        ];
        let hits = correlate(&events, "not-a-timestamp");
        assert!(hits.is_empty());
    }

    #[test]
    fn is_dependency_manifest_matches_known_and_rejects_others() {
        assert!(is_dependency_manifest("package.json"));
        assert!(is_dependency_manifest("Cargo.toml"));
        assert!(is_dependency_manifest("requirements.txt"));
        assert!(is_dependency_manifest("go.mod"));
        assert!(is_dependency_manifest("pnpm-lock.yaml"));
        assert!(is_dependency_manifest("pnpm-lock.yml"));
        assert!(is_dependency_manifest("package-lock.json"));
        assert!(!is_dependency_manifest("main.rs"));
        assert!(!is_dependency_manifest("README.md"));
        // A `contains("pnpm-lock")` would wrongly match a backup-named file; the
        // exact-match family must reject anything but the real lockfile basename.
        assert!(!is_dependency_manifest("notes-pnpm-lock-backup.txt"));
        assert!(!is_dependency_manifest("pnpm-lock.yaml.bak"));
    }

    #[test]
    fn basename_splits_both_separators() {
        assert_eq!(basename("a/b/c.txt"), "c.txt");
        assert_eq!(basename("a\\b\\c.txt"), "c.txt");
        assert_eq!(basename("nodir"), "nodir");
    }
}
