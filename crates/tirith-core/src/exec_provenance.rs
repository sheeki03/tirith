//! Executable provenance (M9 ch5) — the COLD, off-hot-path side.
//!
//! Reachable ONLY from explicit `tirith exec check|provenance` (and shared by
//! `tirith path audit`); NONE of it runs on the `engine::analyze` hot path,
//! which is limited to [`crate::path_audit::classify_leader_path`].
//!
//! Given an executable path, [`provenance_of`] collects stat bits (mtime ->
//! recently-modified, mode -> world-writable, uid/gid), file type via `file
//! --brief`, code signature via `codesign --verify --strict` (macOS only;
//! Windows/Linux report not-applicable), and package-manager ownership by
//! matching well-known install roots.
//!
//! Both child processes are bounded by [`crate::util::run_shell_with_timeout`]
//! (2s, args as an array — no shell/injection); a timeout or missing binary
//! degrades to "unknown", never a hang. Provenance is gathered at ANALYSIS
//! time — TOCTOU: the file could be replaced before the shell executes it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::util::{run_shell_with_timeout, ShellTimeoutOutcome};
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// "Recently modified" window — a binary written within this many seconds of
/// now is flagged by [`RuleId::ExecRecentlyModified`].
pub const RECENT_MODIFY_SECS: u64 = 5 * 60;

/// Child-process deadline for `file` / `codesign` (risk #1: codesign latency).
const SHELL_TIMEOUT: Duration = Duration::from_millis(2000);
const SHELL_POLL: Duration = Duration::from_millis(20);

/// Code-signature verification outcome (platform-dependent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    /// `codesign --verify` (macOS) / Authenticode (Windows) succeeded.
    Valid,
    /// Verification FAILED (no signature or an invalid one). -> [`RuleId::ExecUnsigned`].
    Invalid,
    /// No platform signing baseline (Linux), or verifier missing/timed out.
    /// Never produces a finding.
    NotApplicable,
}

impl SignatureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SignatureStatus::Valid => "valid",
            SignatureStatus::Invalid => "invalid",
            SignatureStatus::NotApplicable => "not_applicable",
        }
    }
}

/// Which package manager owns the install root a path lives under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageOwner {
    /// Short label (`homebrew`, `nix`, `cargo`, `rustup`, `linuxbrew`, `user-local`).
    pub manager: String,
    /// The install root that matched (display form).
    pub root: String,
}

/// Full provenance record for one executable. Serializes directly to the
/// `tirith exec check|provenance --json` body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    /// The resolved path that was inspected (display form).
    pub path: String,
    /// `true` if the path exists and is a regular file.
    pub exists: bool,
    /// Unix permission bits as a 4-digit octal string (`"0755"`), or `None` on
    /// non-Unix / when the file is missing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// `true` when the world-write bit is set (`mode & 0o002`).
    pub world_writable: bool,
    /// Owner uid (Unix only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Owner gid (Unix only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    /// Seconds since the file was last modified (`None` if mtime unavailable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_secs_ago: Option<u64>,
    /// `true` when modified within [`RECENT_MODIFY_SECS`].
    pub recently_modified: bool,
    /// `file --brief` output (file type), trimmed. `None` if the child process
    /// failed / timed out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_type: Option<String>,
    /// Code-signature status.
    pub signature: SignatureStatus,
    /// Package-manager owner, if the path lives under a known install root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_owner: Option<PackageOwner>,
}

impl Provenance {
    /// Derive the COLD exec-provenance findings ([`RuleId::ExecRecentlyModified`],
    /// [`RuleId::ExecWorldWritable`], [`RuleId::ExecUnsigned`]).
    /// [`RuleId::ExecShadowsSystemCommand`] needs the full PATH —
    /// see [`shadow_finding`].
    pub fn findings(&self) -> Vec<Finding> {
        let mut out = Vec::new();
        if !self.exists {
            return out;
        }
        if self.recently_modified {
            out.push(Finding {
                rule_id: RuleId::ExecRecentlyModified,
                severity: Severity::High,
                title: "Executable was modified within the last 5 minutes".to_string(),
                description: format!(
                    "`{}` was last modified {} second(s) ago. A binary written immediately \
                     before execution is the signature of a freshly-dropped payload.",
                    self.path,
                    self.modified_secs_ago.unwrap_or(0)
                ),
                evidence: vec![Evidence::Text {
                    detail: format!("modified_secs_ago={}", self.modified_secs_ago.unwrap_or(0)),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
        if self.world_writable {
            out.push(Finding {
                rule_id: RuleId::ExecWorldWritable,
                severity: Severity::High,
                title: "Executable is world-writable".to_string(),
                description: format!(
                    "`{}` has mode {} — any local process can overwrite it before the next \
                     invocation, silently substituting a different binary.",
                    self.path,
                    self.mode.as_deref().unwrap_or("?")
                ),
                evidence: vec![Evidence::Text {
                    detail: format!("mode={}", self.mode.as_deref().unwrap_or("?")),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
        if self.signature == SignatureStatus::Invalid {
            out.push(Finding {
                rule_id: RuleId::ExecUnsigned,
                severity: Severity::Medium,
                title: "Executable has no valid code signature".to_string(),
                description: format!(
                    "`{}` failed code-signature verification (codesign on macOS / Authenticode \
                     on Windows). An unsigned binary in a position to run cannot be attributed \
                     to a trusted publisher.",
                    self.path
                ),
                evidence: vec![Evidence::Text {
                    detail: "signature=invalid".to_string(),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
        out
    }
}

/// Gather provenance for `path` (the single testable entry point). Best-effort:
/// every sub-probe degrades to a neutral value rather than erroring.
pub fn provenance_of(path: &Path) -> Provenance {
    let md = std::fs::metadata(path).ok();
    let exists = md.as_ref().map(|m| m.is_file()).unwrap_or(false);

    let (mode, world_writable, uid, gid) = stat_bits(md.as_ref());
    let modified_secs_ago = md.as_ref().and_then(modified_secs_ago);
    let recently_modified = modified_secs_ago
        .map(|s| s <= RECENT_MODIFY_SECS)
        .unwrap_or(false);

    let file_type = if exists { file_brief(path) } else { None };
    let signature = if exists {
        verify_signature(path)
    } else {
        SignatureStatus::NotApplicable
    };
    let package_owner = match_package_owner(path);

    Provenance {
        path: path.display().to_string(),
        exists,
        mode,
        world_writable,
        uid,
        gid,
        modified_secs_ago,
        recently_modified,
        file_type,
        signature,
        package_owner,
    }
}

/// Build a [`RuleId::ExecShadowsSystemCommand`] (Medium) finding when `resolved`
/// shares its file name with a system-dir command but is NOT that system copy.
/// Returns `None` when no system copy exists or `resolved` IS the system one.
pub fn shadow_finding(command: &str, resolved: &Path) -> Option<Finding> {
    if crate::path_audit::is_system_path(resolved) {
        return None;
    }
    let system_copy = crate::path_audit::SYSTEM_PATH_DIRS
        .iter()
        .map(|d| Path::new(d).join(command))
        .find(|p| crate::path_audit::is_executable_file(p))?;
    Some(Finding {
        rule_id: RuleId::ExecShadowsSystemCommand,
        severity: Severity::Medium,
        title: format!("`{command}` resolves outside the system path"),
        description: format!(
            "`{command}` resolves to `{}`, shadowing the system command at `{}`. Confirm this \
             is the binary you intend to run.",
            resolved.display(),
            system_copy.display()
        ),
        evidence: vec![Evidence::Text {
            detail: format!(
                "resolved={} system={}",
                resolved.display(),
                system_copy.display()
            ),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    })
}

/// Returns `(mode_octal, world_writable, uid, gid)`. All `None`/`false` on
/// non-Unix or when metadata is unavailable.
#[cfg(unix)]
fn stat_bits(md: Option<&std::fs::Metadata>) -> (Option<String>, bool, Option<u32>, Option<u32>) {
    use std::os::unix::fs::MetadataExt;
    match md {
        Some(m) => {
            let mode = m.mode();
            (
                Some(format!("{:04o}", mode & 0o7777)),
                mode & 0o002 != 0,
                Some(m.uid()),
                Some(m.gid()),
            )
        }
        None => (None, false, None, None),
    }
}

#[cfg(not(unix))]
fn stat_bits(_md: Option<&std::fs::Metadata>) -> (Option<String>, bool, Option<u32>, Option<u32>) {
    (None, false, None, None)
}

/// Seconds since `md`'s mtime, or `None` if the clock is unavailable. An mtime
/// in the future (clock skew) is treated as "just modified" (0 ago).
fn modified_secs_ago(md: &std::fs::Metadata) -> Option<u64> {
    let mtime = md.modified().ok()?;
    let now = std::time::SystemTime::now();
    match now.duration_since(mtime) {
        Ok(d) => Some(d.as_secs()),
        Err(_) => Some(0),
    }
}

/// `file --brief <path>` — the human file type. 2s timeout, stderr discarded.
/// `None` on missing `file`, non-zero exit, or timeout.
fn file_brief(path: &Path) -> Option<String> {
    let path_str = path.to_str()?;
    match run_shell_with_timeout(
        "file",
        &["--brief", path_str],
        SHELL_TIMEOUT,
        SHELL_POLL,
        std::process::Stdio::null(),
    ) {
        ShellTimeoutOutcome::Completed { status, stdout } if status.success() => {
            // Collapse whitespace so a multi-arch Mach-O stays a single line.
            let s = String::from_utf8_lossy(&stdout);
            let collapsed = s.split_whitespace().collect::<Vec<_>>().join(" ");
            if collapsed.is_empty() {
                None
            } else {
                Some(crate::util::truncate_bytes(&collapsed, 200))
            }
        }
        _ => None,
    }
}

/// Verify a code signature. macOS: `codesign --verify --strict <path>` (exit 0
/// = valid), 2s timeout. Windows/Linux: [`SignatureStatus::NotApplicable`].
#[cfg(target_os = "macos")]
fn verify_signature(path: &Path) -> SignatureStatus {
    let Some(path_str) = path.to_str() else {
        return SignatureStatus::NotApplicable;
    };
    match run_shell_with_timeout(
        "codesign",
        &["--verify", "--strict", path_str],
        SHELL_TIMEOUT,
        SHELL_POLL,
        std::process::Stdio::null(),
    ) {
        ShellTimeoutOutcome::Completed { status, .. } => {
            if status.success() {
                SignatureStatus::Valid
            } else {
                // Non-zero exit = no signature or an invalid one.
                SignatureStatus::Invalid
            }
        }
        // missing / timed out / spawn error -> don't claim "unsigned".
        _ => SignatureStatus::NotApplicable,
    }
}

#[cfg(not(target_os = "macos"))]
fn verify_signature(_path: &Path) -> SignatureStatus {
    // No platform baseline here, so no false `ExecUnsigned`.
    SignatureStatus::NotApplicable
}

/// Match `path` against well-known package-manager install roots. Home-anchored
/// roots (`~/.cargo/bin`, ...) are resolved against the real home dir.
pub fn match_package_owner(path: &Path) -> Option<PackageOwner> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

    let mut roots: Vec<(&str, PathBuf)> = vec![
        ("homebrew", PathBuf::from("/opt/homebrew/Cellar")),
        ("homebrew", PathBuf::from("/opt/homebrew/bin")),
        ("homebrew", PathBuf::from("/usr/local/Cellar")),
        ("nix", PathBuf::from("/nix/store")),
        ("linuxbrew", PathBuf::from("/home/linuxbrew/.linuxbrew")),
    ];
    if let Some(home) = home::home_dir() {
        roots.push(("cargo", home.join(".cargo/bin")));
        roots.push(("rustup", home.join(".rustup")));
        roots.push(("user-local", home.join(".local/bin")));
    }

    for (label, root) in roots {
        let root_canon = root.canonicalize().unwrap_or(root);
        if canonical == root_canon || canonical.starts_with(&root_canon) {
            return Some(PackageOwner {
                manager: label.to_string(),
                root: root_canon.display().to_string(),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mkexec(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, b"#!/bin/sh\necho hi\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn provenance_of_missing_file_is_neutral() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("does-not-exist");
        let prov = provenance_of(&p);
        assert!(!prov.exists);
        assert!(prov.findings().is_empty());
        assert_eq!(prov.signature, SignatureStatus::NotApplicable);
    }

    #[cfg(unix)]
    #[test]
    fn recently_modified_binary_fires_high() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("payload");
        mkexec(&p, 0o755);
        let prov = provenance_of(&p);
        assert!(prov.exists);
        assert!(prov.recently_modified, "just-written file is recent");
        let ids: Vec<RuleId> = prov.findings().iter().map(|f| f.rule_id).collect();
        assert!(ids.contains(&RuleId::ExecRecentlyModified), "{ids:?}");
        let recent = prov
            .findings()
            .into_iter()
            .find(|f| f.rule_id == RuleId::ExecRecentlyModified)
            .unwrap();
        assert_eq!(recent.severity, Severity::High);
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_binary_fires_high() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("loose");
        mkexec(&p, 0o757); // world-writable + world-exec
        let prov = provenance_of(&p);
        assert!(prov.world_writable, "mode {:?}", prov.mode);
        let ids: Vec<RuleId> = prov.findings().iter().map(|f| f.rule_id).collect();
        assert!(ids.contains(&RuleId::ExecWorldWritable), "{ids:?}");
    }

    #[cfg(unix)]
    #[test]
    fn non_world_writable_recent_binary_does_not_fire_world_writable() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ok");
        mkexec(&p, 0o755);
        let prov = provenance_of(&p);
        assert!(!prov.world_writable);
        let ids: Vec<RuleId> = prov.findings().iter().map(|f| f.rule_id).collect();
        assert!(!ids.contains(&RuleId::ExecWorldWritable), "{ids:?}");
    }

    #[test]
    fn shadow_finding_fires_for_non_system_copy() {
        // A "sh" resolving outside /bin shadows the system /bin/sh.
        if !Path::new("/bin/sh").exists() {
            eprintln!("skipping: no /bin/sh on this host");
            return;
        }
        let f = shadow_finding("sh", Path::new("/opt/custom/bin/sh"));
        let f = f.expect("should flag a non-system sh that shadows /bin/sh");
        assert_eq!(f.rule_id, RuleId::ExecShadowsSystemCommand);
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn shadow_finding_silent_for_system_path() {
        let f = shadow_finding("sh", Path::new("/bin/sh"));
        assert!(f.is_none());
    }

    #[test]
    fn shadow_finding_silent_when_no_system_copy() {
        let f = shadow_finding("definitely-not-a-real-cmd-xyz", Path::new("/opt/x/bin/foo"));
        assert!(f.is_none());
    }

    #[test]
    fn match_package_owner_recognizes_nix_store() {
        let owner = match_package_owner(Path::new("/nix/store/abc-foo/bin/foo"));
        // Canonicalize falls back to the literal path, so the prefix match holds
        // even when /nix/store is absent.
        assert!(owner.is_some(), "{owner:?}");
        assert_eq!(owner.unwrap().manager, "nix");
    }

    #[test]
    fn match_package_owner_none_for_random_path() {
        let owner = match_package_owner(Path::new("/some/random/place/bin/foo"));
        assert!(owner.is_none());
    }

    #[test]
    fn signature_status_str() {
        assert_eq!(SignatureStatus::Valid.as_str(), "valid");
        assert_eq!(SignatureStatus::Invalid.as_str(), "invalid");
        assert_eq!(SignatureStatus::NotApplicable.as_str(), "not_applicable");
    }
}
