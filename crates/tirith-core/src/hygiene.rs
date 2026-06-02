//! Workstation file-permission / credential-file hygiene scanner.
//!
//! Walks a fixed set of well-known sensitive paths under `~` (plus the repo
//! root) and reports hygiene problems: loose-perm private keys / cloud creds,
//! plaintext registry tokens, unsafe SSH `Include`s, `git credential.helper =
//! store`, secret-shaped shell histories, and stray DB dumps in a repo.
//!
//! The testable entry point [`scan_with_root`] takes the home root + optional
//! repo root; [`scan`] resolves the real dirs and calls it. Tests point it at a
//! tempdir and NEVER mutate `HOME`/`std::env` (process-global env mutation is a
//! libc data race — PR #125).
//!
//! `fix` is chmod-only: the sole auto-fix is `chmod 0600` on a loose file.
//! Hygiene NEVER moves or deletes; content/location problems carry
//! [`FixKind::Manual`] and are only reported. Permission comparison is
//! mask-based (`mode & 0o077`), not exact octal, to tolerate file-type /
//! sticky / setgid bit variation across macOS and Linux.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::extract::ScanContext;
use crate::tokenize::ShellType;
use crate::verdict::{RuleId, Severity};

/// Category of hygiene problem, used for grouping in output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HygieneCategory {
    /// Loose mode bits.
    Perm,
    /// Plaintext secret inside a config / history.
    Contents,
    /// Sensitive artifact in the wrong place (e.g. a DB dump in a repo).
    Location,
}

impl HygieneCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            HygieneCategory::Perm => "perm",
            HygieneCategory::Contents => "contents",
            HygieneCategory::Location => "location",
        }
    }
}

/// What mechanical fix (if any) is available. `fix` is chmod-only; anything
/// requiring a move/delete is [`FixKind::Manual`] (reported, never auto-applied).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FixKind {
    /// `chmod <mode>` — the only automated remediation.
    Chmod { mode: u32 },
    /// No safe mechanical rewrite; reported with `fix_suggestion`, never auto-applied.
    Manual,
}

/// A single hygiene finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HygieneFinding {
    pub rule_id: RuleId,
    /// Absolute path to the offending file.
    pub path: PathBuf,
    /// Drives the scan exit code.
    pub severity: Severity,
    pub category: HygieneCategory,
    /// Expected state, e.g. `"0600"`, `"no plaintext token"`.
    pub expected: String,
    /// Actual state, e.g. `"0644"`, `"plaintext _authToken"`.
    pub actual: String,
    /// One-line remediation guidance shown to the operator.
    pub fix_suggestion: String,
    pub fix_kind: FixKind,
}

impl HygieneFinding {
    /// `true` when High or Critical (drives scan exit 1).
    pub fn is_high(&self) -> bool {
        matches!(self.severity, Severity::High | Severity::Critical)
    }
}

/// Scan the real home dir + cwd repo root. Empty if home cannot be resolved.
pub fn scan() -> Vec<HygieneFinding> {
    let home = home::home_dir();
    let cwd = std::env::current_dir().ok();
    match home {
        Some(h) => scan_with_root(&h, cwd.as_deref()),
        None => {
            // No home → still scan the repo root if we have one.
            match cwd {
                Some(c) => scan_repo_root(&c),
                None => Vec::new(),
            }
        }
    }
}

/// Testable entry point: scan `home` (stand-in for `~`) plus an optional
/// `repo_root` for stray-dump detection. Tests pass a `tempfile::tempdir()`.
pub fn scan_with_root(home: &Path, repo_root: Option<&Path>) -> Vec<HygieneFinding> {
    let mut findings = Vec::new();

    findings.extend(scan_ssh_dir(&home.join(".ssh")));
    findings.extend(scan_aws_dir(&home.join(".aws")));
    findings.extend(scan_kubeconfig(&home.join(".kube").join("config")));
    findings.extend(scan_npmrc(&home.join(".npmrc")));
    findings.extend(scan_pypirc(&home.join(".pypirc")));
    findings.extend(scan_gitconfig(&home.join(".gitconfig")));
    findings.extend(scan_shell_histories(home));

    if let Some(root) = repo_root {
        findings.extend(scan_repo_root(root));
    }

    findings
}

/// `~/.ssh`: private keys must be 0600; `config` must not carry an unsafe
/// `Include` directive pointing outside `~/.ssh`.
fn scan_ssh_dir(ssh_dir: &Path) -> Vec<HygieneFinding> {
    let mut findings = Vec::new();
    let entries = match std::fs::read_dir(ssh_dir) {
        Ok(e) => e,
        Err(_) => return findings,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        if name == "config" {
            if let Some(f) = check_ssh_config_includes(&path, ssh_dir) {
                findings.push(f);
            }
            continue;
        }

        if !path.is_file() {
            continue;
        }

        // Private-key candidates: `id_*` without a `.pub` suffix.
        let is_private_key_name = name.starts_with("id_") && !name.ends_with(".pub");
        if !is_private_key_name {
            continue;
        }

        if let Some(mode) = file_mode(&path) {
            if mode_is_group_or_other_accessible(mode) {
                findings.push(HygieneFinding {
                    rule_id: RuleId::HygienePrivateKeyLoosePerms,
                    path: path.clone(),
                    severity: Severity::High,
                    category: HygieneCategory::Perm,
                    expected: "0600".to_string(),
                    actual: format_mode(mode),
                    fix_suggestion: format!("chmod 0600 {}", path.display()),
                    fix_kind: FixKind::Chmod { mode: 0o600 },
                });
            }
        }
    }

    findings
}

/// `~/.ssh/config`: flag `Include` directives that resolve outside `~/.ssh`
/// (a world-writable include path is a classic config-injection foothold).
fn check_ssh_config_includes(config_path: &Path, ssh_dir: &Path) -> Option<HygieneFinding> {
    let contents = std::fs::read_to_string(config_path).ok()?;
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // `Include <path>` — case-insensitive keyword per ssh_config(5).
        let mut parts = line.splitn(2, char::is_whitespace);
        let keyword = parts.next().unwrap_or("");
        if !keyword.eq_ignore_ascii_case("include") {
            continue;
        }
        let target = parts.next().unwrap_or("").trim();
        if target.is_empty() {
            continue;
        }
        if include_target_is_unsafe(target, ssh_dir) {
            return Some(HygieneFinding {
                rule_id: RuleId::HygieneSshConfigUnsafeInclude,
                path: config_path.to_path_buf(),
                severity: Severity::Medium,
                category: HygieneCategory::Contents,
                expected: "Include paths confined to ~/.ssh".to_string(),
                actual: format!("Include {target}"),
                fix_suggestion: format!(
                    "Review the `Include {target}` directive in {} — confine SSH includes \
                     to ~/.ssh and verify the target is not world-writable.",
                    config_path.display()
                ),
                fix_kind: FixKind::Manual,
            });
        }
    }
    None
}

/// An `Include` target is "unsafe" when it is absolute and lives outside the
/// `~/.ssh` directory, or it escapes upward with `../`. Relative paths without
/// `..` resolve under `~/.ssh` (ssh's default) and are fine.
fn include_target_is_unsafe(target: &str, ssh_dir: &Path) -> bool {
    let target = target.trim_matches('"').trim_matches('\'');

    // `~/`-expanded: `~/.ssh/...` is fine, anything else under `~` is outside.
    if let Some(stripped) = target.strip_prefix("~/") {
        return !stripped.starts_with(".ssh/") && stripped != ".ssh";
    }
    // Absolute: unsafe unless confined to ~/.ssh (best-effort prefix check).
    if target.starts_with('/') {
        let p = Path::new(target);
        return !p.starts_with(ssh_dir);
    }
    // Relative: unsafe only if it climbs out with `..`.
    target.split('/').any(|seg| seg == "..")
}

/// `~/.aws`: `credentials` (and `config`) must be 0600.
fn scan_aws_dir(aws_dir: &Path) -> Vec<HygieneFinding> {
    let mut findings = Vec::new();
    for fname in ["credentials", "config"] {
        let path = aws_dir.join(fname);
        if !path.is_file() {
            continue;
        }
        if let Some(mode) = file_mode(&path) {
            if mode_is_group_or_other_accessible(mode) {
                findings.push(HygieneFinding {
                    rule_id: RuleId::HygieneCloudCredsBadPerms,
                    path: path.clone(),
                    severity: Severity::High,
                    category: HygieneCategory::Perm,
                    expected: "0600".to_string(),
                    actual: format_mode(mode),
                    fix_suggestion: format!("chmod 0600 {}", path.display()),
                    fix_kind: FixKind::Chmod { mode: 0o600 },
                });
            }
        }
    }
    findings
}

/// `~/.kube/config`: group-readable leaks cluster creds. Medium (not High):
/// distro default is 0644 and the threat is local-multiuser only.
fn scan_kubeconfig(kube_config: &Path) -> Vec<HygieneFinding> {
    let mut findings = Vec::new();
    if !kube_config.is_file() {
        return findings;
    }
    if let Some(mode) = file_mode(kube_config) {
        if mode_is_group_or_other_accessible(mode) {
            findings.push(HygieneFinding {
                rule_id: RuleId::HygieneKubeconfigGroupReadable,
                path: kube_config.to_path_buf(),
                severity: Severity::Medium,
                category: HygieneCategory::Perm,
                expected: "0600".to_string(),
                actual: format_mode(mode),
                fix_suggestion: format!("chmod 0600 {}", kube_config.display()),
                fix_kind: FixKind::Chmod { mode: 0o600 },
            });
        }
    }
    findings
}

/// `~/.npmrc`: a plaintext `_authToken` is a publish/install secret on disk. High.
fn scan_npmrc(npmrc: &Path) -> Vec<HygieneFinding> {
    let mut findings = Vec::new();
    let contents = match read_text_if_file(npmrc) {
        Some(c) => c,
        None => return findings,
    };
    if npmrc_has_plaintext_token(&contents) {
        findings.push(HygieneFinding {
            rule_id: RuleId::HygieneNpmrcPlaintextToken,
            path: npmrc.to_path_buf(),
            severity: Severity::High,
            category: HygieneCategory::Contents,
            expected: "no plaintext _authToken (use ${NPM_TOKEN} env reference)".to_string(),
            actual: "plaintext _authToken".to_string(),
            fix_suggestion: format!(
                "Replace the literal token in {} with an env reference \
                 (`//registry.npmjs.org/:_authToken=${{NPM_TOKEN}}`) and rotate the exposed token.",
                npmrc.display()
            ),
            fix_kind: FixKind::Manual,
        });
    }
    findings
}

/// True when an `_authToken` / `_password` / `_auth` assignment has a literal
/// value (not an `${ENV}` reference).
fn npmrc_has_plaintext_token(contents: &str) -> bool {
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        let is_secret_key = lower.contains("_authtoken")
            || lower.contains(":_auth")
            || lower.contains(":_password")
            || lower.starts_with("_auth")
            || lower.starts_with("_password");
        if !is_secret_key {
            continue;
        }
        if let Some((_, value)) = line.split_once('=') {
            if value_is_literal_secret(value) {
                return true;
            }
        }
    }
    false
}

/// `~/.pypirc`: a plaintext `password` or literal `pypi-` token is a publish
/// credential. High.
fn scan_pypirc(pypirc: &Path) -> Vec<HygieneFinding> {
    let mut findings = Vec::new();
    let contents = match read_text_if_file(pypirc) {
        Some(c) => c,
        None => return findings,
    };
    if pypirc_has_plaintext_token(&contents) {
        findings.push(HygieneFinding {
            rule_id: RuleId::HygienePypircPlaintextToken,
            path: pypirc.to_path_buf(),
            severity: Severity::High,
            category: HygieneCategory::Contents,
            expected: "no plaintext password / API token".to_string(),
            actual: "plaintext password or pypi- token".to_string(),
            fix_suggestion: format!(
                "Remove the literal password/token from {} and use a keyring-backed \
                 credential or a `${{TWINE_PASSWORD}}` env reference; rotate the exposed token.",
                pypirc.display()
            ),
            fix_kind: FixKind::Manual,
        });
    }
    findings
}

/// True when a `password` has a literal value, or a literal `pypi-…` API token
/// appears in a value position.
fn pypirc_has_plaintext_token(contents: &str) -> bool {
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.contains("pypi-") {
            // Only a value position counts (after `=` / `:`).
            if let Some(value) = line
                .split_once('=')
                .map(|(_, v)| v)
                .or_else(|| line.split_once(':').map(|(_, v)| v))
            {
                if value.trim().contains("pypi-") {
                    return true;
                }
            }
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("password") {
            if let Some((_, value)) = line.split_once(['=', ':']) {
                if value_is_literal_secret(value) {
                    return true;
                }
            }
        }
    }
    false
}

/// `~/.gitconfig`: `credential.helper = store` persists git creds as cleartext
/// in `~/.git-credentials`. Medium — surfaced, not blocked.
fn scan_gitconfig(gitconfig: &Path) -> Vec<HygieneFinding> {
    let mut findings = Vec::new();
    let contents = match read_text_if_file(gitconfig) {
        Some(c) => c,
        None => return findings,
    };
    if gitconfig_uses_store_helper(&contents) {
        findings.push(HygieneFinding {
            rule_id: RuleId::HygieneGitCredentialHelperStore,
            path: gitconfig.to_path_buf(),
            severity: Severity::Medium,
            category: HygieneCategory::Contents,
            expected: "credential.helper using an OS keychain (osxkeychain / libsecret)"
                .to_string(),
            actual: "credential.helper = store (plaintext ~/.git-credentials)".to_string(),
            fix_suggestion: format!(
                "Switch the `helper = store` line in {} to an encrypted helper \
                 (`git config --global credential.helper osxkeychain` on macOS, \
                 `libsecret` on Linux) and delete ~/.git-credentials.",
                gitconfig.display()
            ),
            fix_kind: FixKind::Manual,
        });
    }
    findings
}

/// Detect `helper = store` in a `[credential]` (or `[credential "url"]`) section,
/// or the one-line `credential.helper = store` form.
fn gitconfig_uses_store_helper(contents: &str) -> bool {
    let mut in_credential_section = false;
    for raw_line in contents.lines() {
        let line = raw_line.trim();
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
            in_credential_section = section == "credential";
            continue;
        }
        // Dotted `credential.helper = store` anywhere, or bare `helper = store`
        // only inside a `[credential]` section (the section check is the guard).
        if let Some((key, value)) = line.split_once('=') {
            let key_lc = key.trim().to_ascii_lowercase();
            let value_lc = value.trim().to_ascii_lowercase();
            if key_lc == "credential.helper" && value_lc == "store" {
                return true;
            }
            if in_credential_section && key_lc == "helper" && value_lc == "store" {
                return true;
            }
        }
    }
    false
}

/// Shell histories: reuse the shipping credential detector
/// (`rules::credential::check` in Paste context) rather than inventing new
/// regex — false positives on history files are costly.
fn scan_shell_histories(home: &Path) -> Vec<HygieneFinding> {
    let mut findings = Vec::new();
    let histories = [
        ".bash_history",
        ".zsh_history",
        ".history",
        ".local/share/fish/fish_history",
    ];
    for rel in histories {
        let path = home.join(rel);
        let contents = match read_text_if_file(&path) {
            Some(c) => c,
            None => continue,
        };
        let creds =
            crate::rules::credential::check(&contents, ShellType::Posix, ScanContext::Paste);
        if !creds.is_empty() {
            // One finding per history file (not per match); count is in `actual`.
            let titles: Vec<String> = creds.iter().map(|f| f.title.clone()).collect();
            findings.push(HygieneFinding {
                rule_id: RuleId::HygieneShellHistorySecretLike,
                path: path.clone(),
                severity: Severity::Medium,
                category: HygieneCategory::Contents,
                expected: "no credential-shaped secrets in shell history".to_string(),
                actual: format!(
                    "{} credential-shaped match(es): {}",
                    creds.len(),
                    titles.join(", ")
                ),
                fix_suggestion: format!(
                    "Review {} for leaked secrets, scrub the offending lines, and rotate any \
                     exposed credential. Consider `HISTIGNORE`/`HISTCONTROL` to avoid recording \
                     secret-bearing commands.",
                    path.display()
                ),
                fix_kind: FixKind::Manual,
            });
        }
    }
    findings
}

/// Repo root: flag stray DB dumps (`*.dump`/`*.sql` → Medium) and world-readable
/// env files (`*.env*` → High). The walk is bounded (skips `.git`,
/// `node_modules`, `target`, `vendor`, dot-dirs) to avoid a full-tree crawl.
fn scan_repo_root(root: &Path) -> Vec<HygieneFinding> {
    let mut findings = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut budget: usize = 5_000;

    while let Some(dir) = stack.pop() {
        if budget == 0 {
            break;
        }
        budget -= 1;

        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // `entry.file_type()` does NOT follow symlinks: use it for the
            // descent decision (a symlinked dir is NOT descended — loop/escape
            // prevention) but follow the link via `path.is_file()` for leaf
            // candidates, else a world-readable `.env` behind a symlink hides.
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };

            if file_type.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if is_skippable_dir(name) {
                        continue;
                    }
                }
                stack.push(path);
                continue;
            }
            if !path.is_file() {
                continue;
            }

            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };

            if is_db_dump_name(name) {
                findings.push(HygieneFinding {
                    rule_id: RuleId::HygieneDbDumpInRepo,
                    path: path.clone(),
                    severity: Severity::Medium,
                    category: HygieneCategory::Location,
                    expected: "no database dumps committed to the repo".to_string(),
                    actual: format!("database dump present: {name}"),
                    fix_suggestion: format!(
                        "Move {} out of the repo and add the pattern to .gitignore. \
                         Database dumps frequently contain PII / credentials. \
                         (tirith never deletes files — remove it manually.)",
                        path.display()
                    ),
                    fix_kind: FixKind::Manual,
                });
                continue;
            }

            if is_env_file_name(name) {
                if let Some(mode) = file_mode(&path) {
                    if mode_is_world_readable(mode) {
                        findings.push(HygieneFinding {
                            rule_id: RuleId::HygieneEnvWorldReadable,
                            path: path.clone(),
                            severity: Severity::High,
                            category: HygieneCategory::Perm,
                            expected: "0600 (not world-readable)".to_string(),
                            actual: format_mode(mode),
                            fix_suggestion: format!("chmod 0600 {}", path.display()),
                            fix_kind: FixKind::Chmod { mode: 0o600 },
                        });
                    }
                }
            }
        }
    }

    findings
}

/// Directories we never descend into during the repo walk.
fn is_skippable_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | "node_modules" | "target" | "vendor" | ".venv" | "venv" | "__pycache__" | "dist"
    ) || name.starts_with('.')
}

/// `*.dump` / `*.sql` (case-insensitive).
fn is_db_dump_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".dump") || lower.ends_with(".sql")
}

/// `.env`, `.env.local`, `.env.production`, `prod.env`, etc.
fn is_env_file_name(name: &str) -> bool {
    if name == ".env" {
        return true;
    }
    if name.starts_with(".env.") {
        return true;
    }
    name.ends_with(".env")
}

/// Read a path as UTF-8 text only when it is a regular file; `None` otherwise.
fn read_text_if_file(path: &Path) -> Option<String> {
    if !path.is_file() {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// A config value is a "literal secret" when non-empty and NOT an env reference
/// (`${VAR}` / `$VAR`) — distinguishing a committed token from the recommended
/// env-indirection form. A bare `__token__` placeholder is not a secret.
fn value_is_literal_secret(value: &str) -> bool {
    let v = value.trim().trim_matches('"').trim_matches('\'').trim();
    if v.is_empty() {
        return false;
    }
    if v.starts_with("${") || (v.starts_with('$') && v.len() > 1) {
        return false;
    }
    if v.eq_ignore_ascii_case("__token__") {
        return false;
    }
    true
}

/// Unix file mode (permission + type bits) for `path`, or `None`.
#[cfg(unix)]
fn file_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| m.mode())
}

/// Non-Unix has no POSIX modes; perm rules no-op.
#[cfg(not(unix))]
fn file_mode(_path: &Path) -> Option<u32> {
    None
}

/// `true` when group or other has ANY access bit (`mode & 0o077`). Mask-based to
/// tolerate sticky/setgid/file-type bit variation across OSes.
fn mode_is_group_or_other_accessible(mode: u32) -> bool {
    mode & 0o077 != 0
}

/// `true` when "other" has the read bit (`mode & 0o004`).
fn mode_is_world_readable(mode: u32) -> bool {
    mode & 0o004 != 0
}

/// Permission bits of `mode` as a 4-digit octal string (e.g. `"0644"`).
fn format_mode(mode: u32) -> String {
    format!("{:04o}", mode & 0o7777)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(unix)]
    fn chmod(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, perms).unwrap();
    }

    fn rule_ids(findings: &[HygieneFinding]) -> Vec<RuleId> {
        findings.iter().map(|f| f.rule_id).collect()
    }

    #[test]
    fn mask_comparison_tolerates_file_type_and_sticky_bits() {
        // Regular file (0o100000) + sticky (0o1000) + 0600 → not accessible.
        assert!(!mode_is_group_or_other_accessible(0o101600));
        // 0640 → group-readable → accessible.
        assert!(mode_is_group_or_other_accessible(0o100640));
        // 0644 → world-readable.
        assert!(mode_is_world_readable(0o100644));
        // 0640 → NOT world-readable (group only).
        assert!(!mode_is_world_readable(0o100640));
    }

    #[test]
    fn format_mode_masks_type_bits() {
        assert_eq!(format_mode(0o100644), "0644");
        assert_eq!(format_mode(0o40755), "0755");
    }

    #[cfg(unix)]
    #[test]
    fn ssh_private_key_loose_perms_flags_high() {
        let dir = tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let key = ssh.join("id_ed25519");
        std::fs::write(&key, b"-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
        chmod(&key, 0o644);
        // A correctly-locked key must NOT fire.
        let pub_key = ssh.join("id_ed25519.pub");
        std::fs::write(&pub_key, b"ssh-ed25519 AAAA").unwrap();
        chmod(&pub_key, 0o644);

        let findings = scan_with_root(dir.path(), None);
        let ids = rule_ids(&findings);
        assert!(
            ids.contains(&RuleId::HygienePrivateKeyLoosePerms),
            "expected loose-perm key finding, got {ids:?}"
        );
        // .pub file must not be flagged.
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.rule_id == RuleId::HygienePrivateKeyLoosePerms)
                .count(),
            1
        );
        let f = findings
            .iter()
            .find(|f| f.rule_id == RuleId::HygienePrivateKeyLoosePerms)
            .unwrap();
        assert!(f.is_high());
        assert!(matches!(f.fix_kind, FixKind::Chmod { mode: 0o600 }));
    }

    #[cfg(unix)]
    #[test]
    fn ssh_private_key_0600_is_clean() {
        let dir = tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let key = ssh.join("id_rsa");
        std::fs::write(&key, b"key").unwrap();
        chmod(&key, 0o600);

        let findings = scan_with_root(dir.path(), None);
        assert!(!rule_ids(&findings).contains(&RuleId::HygienePrivateKeyLoosePerms));
    }

    #[cfg(unix)]
    #[test]
    fn aws_credentials_loose_perms_flags_high() {
        let dir = tempdir().unwrap();
        let aws = dir.path().join(".aws");
        std::fs::create_dir_all(&aws).unwrap();
        let creds = aws.join("credentials");
        std::fs::write(&creds, b"[default]\naws_access_key_id=AKIA...\n").unwrap();
        chmod(&creds, 0o644);

        let findings = scan_with_root(dir.path(), None);
        assert!(rule_ids(&findings).contains(&RuleId::HygieneCloudCredsBadPerms));
    }

    #[cfg(unix)]
    #[test]
    fn kubeconfig_group_readable_flags_medium() {
        let dir = tempdir().unwrap();
        let kube = dir.path().join(".kube");
        std::fs::create_dir_all(&kube).unwrap();
        let config = kube.join("config");
        std::fs::write(&config, b"apiVersion: v1\n").unwrap();
        chmod(&config, 0o640);

        let findings = scan_with_root(dir.path(), None);
        let f = findings
            .iter()
            .find(|f| f.rule_id == RuleId::HygieneKubeconfigGroupReadable)
            .expect("expected kubeconfig finding");
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn npmrc_plaintext_token_flags_high() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join(".npmrc"),
            "//registry.npmjs.org/:_authToken=npm_abcdef0123456789abcdef0123456789abcd\n",
        )
        .unwrap();

        let findings = scan_with_root(dir.path(), None);
        let f = findings
            .iter()
            .find(|f| f.rule_id == RuleId::HygieneNpmrcPlaintextToken)
            .expect("expected npmrc plaintext token finding");
        assert!(f.is_high());
        assert_eq!(f.fix_kind, FixKind::Manual);
    }

    #[test]
    fn npmrc_env_reference_is_clean() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join(".npmrc"),
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n",
        )
        .unwrap();

        let findings = scan_with_root(dir.path(), None);
        assert!(!rule_ids(&findings).contains(&RuleId::HygieneNpmrcPlaintextToken));
    }

    #[test]
    fn pypirc_plaintext_password_flags_high() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join(".pypirc"),
            "[pypi]\nusername = __token__\npassword = pypi-AgEIcHlwaS5vcmcabcdef0123456789\n",
        )
        .unwrap();

        let findings = scan_with_root(dir.path(), None);
        assert!(rule_ids(&findings).contains(&RuleId::HygienePypircPlaintextToken));
    }

    #[test]
    fn pypirc_token_placeholder_username_is_clean() {
        let dir = tempdir().unwrap();
        // `__token__` username with NO literal password → not a leak.
        std::fs::write(dir.path().join(".pypirc"), "[pypi]\nusername = __token__\n").unwrap();

        let findings = scan_with_root(dir.path(), None);
        assert!(!rule_ids(&findings).contains(&RuleId::HygienePypircPlaintextToken));
    }

    #[test]
    fn gitconfig_store_helper_flags_medium() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join(".gitconfig"),
            "[credential]\n\thelper = store\n",
        )
        .unwrap();

        let findings = scan_with_root(dir.path(), None);
        let f = findings
            .iter()
            .find(|f| f.rule_id == RuleId::HygieneGitCredentialHelperStore)
            .expect("expected git credential.helper store finding");
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn gitconfig_keychain_helper_is_clean() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join(".gitconfig"),
            "[credential]\n\thelper = osxkeychain\n",
        )
        .unwrap();

        let findings = scan_with_root(dir.path(), None);
        assert!(!rule_ids(&findings).contains(&RuleId::HygieneGitCredentialHelperStore));
    }

    #[test]
    fn ssh_config_unsafe_include_flags_medium() {
        let dir = tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("config"), "Include /tmp/evil_ssh_config\n").unwrap();

        let findings = scan_with_root(dir.path(), None);
        let f = findings
            .iter()
            .find(|f| f.rule_id == RuleId::HygieneSshConfigUnsafeInclude)
            .expect("expected unsafe SSH include finding");
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn ssh_config_local_include_is_clean() {
        let dir = tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        // Relative include under ~/.ssh is the ssh default and is fine.
        std::fs::write(ssh.join("config"), "Include config.d/*\nHost *\n").unwrap();

        let findings = scan_with_root(dir.path(), None);
        assert!(!rule_ids(&findings).contains(&RuleId::HygieneSshConfigUnsafeInclude));
    }

    #[test]
    fn shell_history_with_secret_flags_medium() {
        let dir = tempdir().unwrap();
        // AKIA-prefixed access key is a high-confidence provider pattern.
        std::fs::write(
            dir.path().join(".bash_history"),
            "ls -la\naws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE\ncd /tmp\n",
        )
        .unwrap();

        let findings = scan_with_root(dir.path(), None);
        let f = findings
            .iter()
            .find(|f| f.rule_id == RuleId::HygieneShellHistorySecretLike)
            .expect("expected shell-history secret finding");
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn clean_shell_history_does_not_fire() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join(".zsh_history"),
            "ls -la\ncd /tmp\ngit status\ncargo build\n",
        )
        .unwrap();

        let findings = scan_with_root(dir.path(), None);
        assert!(!rule_ids(&findings).contains(&RuleId::HygieneShellHistorySecretLike));
    }

    #[cfg(unix)]
    #[test]
    fn env_world_readable_in_repo_flags_high() {
        let home = tempdir().unwrap();
        let repo = tempdir().unwrap();
        let env_file = repo.path().join(".env");
        std::fs::write(&env_file, b"SECRET=hunter2\n").unwrap();
        chmod(&env_file, 0o644);

        let findings = scan_with_root(home.path(), Some(repo.path()));
        let f = findings
            .iter()
            .find(|f| f.rule_id == RuleId::HygieneEnvWorldReadable)
            .expect("expected world-readable .env finding");
        assert!(f.is_high());
        assert!(matches!(f.fix_kind, FixKind::Chmod { mode: 0o600 }));
    }

    #[cfg(unix)]
    #[test]
    fn env_locked_down_in_repo_is_clean() {
        let home = tempdir().unwrap();
        let repo = tempdir().unwrap();
        let env_file = repo.path().join(".env.local");
        std::fs::write(&env_file, b"SECRET=hunter2\n").unwrap();
        chmod(&env_file, 0o600);

        let findings = scan_with_root(home.path(), Some(repo.path()));
        assert!(!rule_ids(&findings).contains(&RuleId::HygieneEnvWorldReadable));
    }

    #[test]
    fn db_dump_in_repo_flags_medium() {
        let home = tempdir().unwrap();
        let repo = tempdir().unwrap();
        std::fs::write(repo.path().join("backup.sql"), b"-- dump\n").unwrap();
        std::fs::write(repo.path().join("snapshot.dump"), b"binary").unwrap();

        let findings = scan_with_root(home.path(), Some(repo.path()));
        let dumps: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == RuleId::HygieneDbDumpInRepo)
            .collect();
        assert_eq!(dumps.len(), 2, "expected both .sql and .dump flagged");
        assert!(dumps.iter().all(|f| f.severity == Severity::Medium));
        assert!(dumps.iter().all(|f| f.fix_kind == FixKind::Manual));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_world_readable_env_is_flagged() {
        // A world-readable `.env` reached via symlink must be flagged (follows
        // the link through `path.is_file()` for leaf candidates).
        let home = tempdir().unwrap();
        let repo = tempdir().unwrap();
        let target_dir = tempdir().unwrap();
        let real_env = target_dir.path().join("real_secret.env");
        std::fs::write(&real_env, b"SECRET=hunter2\n").unwrap();
        chmod(&real_env, 0o644);
        std::os::unix::fs::symlink(&real_env, repo.path().join(".env")).unwrap();

        let findings = scan_with_root(home.path(), Some(repo.path()));
        assert!(
            rule_ids(&findings).contains(&RuleId::HygieneEnvWorldReadable),
            "a world-readable .env exposed via symlink must be flagged, got {:?}",
            rule_ids(&findings)
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_dir_is_not_descended() {
        // A symlink-to-dir must NOT be descended (loop/escape prevention).
        let home = tempdir().unwrap();
        let repo = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::fs::write(outside.path().join("backup.sql"), b"-- dump\n").unwrap();
        std::os::unix::fs::symlink(outside.path(), repo.path().join("linked_dir")).unwrap();

        let findings = scan_with_root(home.path(), Some(repo.path()));
        assert!(
            !rule_ids(&findings).contains(&RuleId::HygieneDbDumpInRepo),
            "a dump inside a symlinked directory must not be discovered (no descent)"
        );
    }

    #[test]
    fn repo_walk_skips_node_modules_and_git() {
        let home = tempdir().unwrap();
        let repo = tempdir().unwrap();
        let nm = repo.path().join("node_modules").join("pkg");
        std::fs::create_dir_all(&nm).unwrap();
        std::fs::write(nm.join("fixture.sql"), b"-- dump\n").unwrap();
        let git = repo.path().join(".git");
        std::fs::create_dir_all(&git).unwrap();
        std::fs::write(git.join("backup.dump"), b"x").unwrap();

        let findings = scan_with_root(home.path(), Some(repo.path()));
        assert!(
            !rule_ids(&findings).contains(&RuleId::HygieneDbDumpInRepo),
            "dumps inside node_modules/.git must be skipped"
        );
    }

    #[test]
    fn empty_home_yields_no_findings() {
        let dir = tempdir().unwrap();
        let findings = scan_with_root(dir.path(), None);
        assert!(findings.is_empty());
    }
}
