//! `$PATH` shadowing + leader-path provenance (M9 ch5). Two surfaces:
//!
//! 1. Hot-path leader checks ([`classify_leader_path`]) — three cheap,
//!    stat-free compares (Exec, behind `policy.exec_guard_enabled`): is the
//!    resolved leader in `/tmp`, in the repo, or in a user-writable repo-local/
//!    `/tmp` `$PATH` dir preceding a system dir? Only syscall is one
//!    `libc::access(W_OK)`. No codesign/file/mtime.
//! 2. `tirith path audit` ([`audit_path_str`]) — cold full-PATH enumeration
//!    (duplicate names, repo-local/`/tmp` dirs, writable-before-system). Takes
//!    `$PATH` as a STRING so tests never mutate process `PATH` (PR #125).
//!
//! `PathWritableDirBeforeSystem` is scoped to repo-local/`/tmp` dirs because
//! "any writable dir before a system dir" fires on nearly every shell (Intel
//! macOS's world-writable `/usr/local/bin`, `~/.local/bin`, Homebrew, …). The
//! broader inventory is informational in `tirith path audit`, not a hot block.
//!
//! Known TOCTOU: everything resolves at ANALYSIS time; the shell may run a
//! different binary at EXEC time (PATH hash cache, a swapped symlink). Inherent
//! to a pre-exec advisory.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// System dirs the writable-before-system rule cares about: a user-writable,
/// repo-local/`/tmp` dir BEFORE one of these in `$PATH` can shadow a system
/// command. Windows variant powers only `is_system_path`/`--secure` (the
/// writability probe is Unix-only).
#[cfg(not(windows))]
pub const SYSTEM_PATH_DIRS: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

/// Windows system dirs (see [`SYSTEM_PATH_DIRS`]). Backslash form matches `%PATH%`.
#[cfg(windows)]
pub const SYSTEM_PATH_DIRS: &[&str] = &[
    r"C:\Windows\System32",
    r"C:\Windows",
    r"C:\Windows\System32\Wbem",
    r"C:\Windows\System32\WindowsPowerShell\v1.0",
];

/// One cheap classification of the resolved leader's path. A leader can match
/// more than one, so [`classify_leader_path`] returns a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaderLocation {
    /// Under `/tmp` (or `$TMPDIR`). → [`RuleId::ExecInTmp`].
    InTmp,
    /// Inside the current repo working tree. → [`RuleId::ExecInRepoBin`].
    InRepo,
    /// User-writable repo-local/`/tmp` `$PATH` dir preceding a system dir.
    /// → [`RuleId::PathWritableDirBeforeSystem`].
    WritableDirBeforeSystem,
}

/// Inputs to the hot-path leader classification (borrowed slices the engine holds).
pub struct LeaderContext<'a> {
    /// Resolved leader path (an explicit typed path or the `$PATH` hit). `None`
    /// short-circuits to no findings.
    pub resolved_path: Option<PathBuf>,
    /// Current repo root (`policy::find_repo_root(cwd)`), if any.
    pub repo_root: Option<&'a Path>,
    /// Directory the leader resolved FROM, for the writable-before-system check.
    pub resolved_dir: Option<&'a Path>,
    /// Ordered (already-split) `$PATH` dirs, to test whether `resolved_dir`
    /// precedes a system dir.
    pub path_dirs: &'a [PathBuf],
    /// Temp-dir roots to treat as `/tmp` (production: `["/tmp", $TMPDIR]`).
    pub tmp_roots: &'a [PathBuf],
}

/// Classify the resolved leader path against the three cheap signals. Pure
/// except for one `libc::access(W_OK)` probe on `resolved_dir` (only after the
/// precedence check matches). Returns matched locations in a stable order.
pub fn classify_leader_path(ctx: &LeaderContext<'_>) -> Vec<LeaderLocation> {
    let mut out = Vec::new();
    let Some(resolved) = ctx.resolved_path.as_deref() else {
        return out;
    };

    // (i) /tmp
    if path_under_any(resolved, ctx.tmp_roots) {
        out.push(LeaderLocation::InTmp);
    }

    // (ii) repo
    if let Some(repo) = ctx.repo_root {
        if path_under(resolved, repo) {
            out.push(LeaderLocation::InRepo);
        }
    }

    // (iii) writable dir before system: dir must (a) precede a system dir in
    // $PATH, (b) be repo-local or /tmp (keeps ~/.local/bin and world-writable
    // /usr/local/bin out of the HOT finding), and (c) be user-writable.
    if let Some(dir) = ctx.resolved_dir {
        let repo_local = ctx.repo_root.map(|r| path_under(dir, r)).unwrap_or(false);
        let tmp_local = path_under_any(dir, ctx.tmp_roots);
        if (repo_local || tmp_local)
            && dir_precedes_system(dir, ctx.path_dirs)
            && dir_is_user_writable(dir)
        {
            out.push(LeaderLocation::WritableDirBeforeSystem);
        }
    }

    out
}

/// Build the hot-path [`Finding`]s for the matched leader locations (the resolved
/// path is non-secret, so it's included as evidence).
pub fn leader_findings(locations: &[LeaderLocation], resolved_display: &str) -> Vec<Finding> {
    locations
        .iter()
        .map(|loc| match loc {
            LeaderLocation::InTmp => Finding {
                rule_id: RuleId::ExecInTmp,
                severity: Severity::Medium,
                title: "Command resolves to a binary under /tmp".to_string(),
                description: format!(
                    "The command leader resolves to `{resolved_display}`, which lives in a \
                     world-writable scratch directory. Binaries dropped in /tmp are a classic \
                     staging location for run-once payloads."
                ),
                evidence: vec![Evidence::Text {
                    detail: format!("resolved_path={resolved_display}"),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            },
            LeaderLocation::InRepo => Finding {
                rule_id: RuleId::ExecInRepoBin,
                severity: Severity::Medium,
                title: "Command resolves to a binary inside the repository".to_string(),
                description: format!(
                    "The command leader resolves to `{resolved_display}`, which lives inside the \
                     current repository's working tree. Running a checked-in binary executes \
                     code that an attacker can land through a pull request. Run \
                     `tirith exec check` for full provenance."
                ),
                evidence: vec![Evidence::Text {
                    detail: format!("resolved_path={resolved_display}"),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            },
            LeaderLocation::WritableDirBeforeSystem => Finding {
                rule_id: RuleId::PathWritableDirBeforeSystem,
                severity: Severity::High,
                title: "Command resolved from a user-writable PATH dir ahead of the system path"
                    .to_string(),
                description: format!(
                    "The command leader resolves to `{resolved_display}`, from a directory the \
                     current user can write that precedes /usr/bin (and is repo-local or under \
                     /tmp). A writable directory ahead of the system path lets any local process \
                     shadow system commands. Reorder $PATH so system dirs come first."
                ),
                evidence: vec![Evidence::Text {
                    detail: format!("resolved_path={resolved_display}"),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            },
        })
        .collect()
}

// ─── cold: `tirith path audit` ───────────────────────────────────────────────

/// How a `$PATH` directory is classified by the audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathDirRisk {
    /// Inside the current repo working tree.
    InRepo,
    /// Under `/tmp` (or `$TMPDIR`).
    InTmp,
    /// User-writable AND precedes a system dir (informational; the HOT rule is narrower).
    WritableBeforeSystem,
    /// Resolves a command name that also resolves in another dir (duplicate).
    DuplicateCommand,
}

/// One reported entry from [`audit_path_str`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathAuditEntry {
    /// The `$PATH` directory.
    pub dir: String,
    /// Why it was flagged.
    pub risk: PathDirRisk,
    /// For `DuplicateCommand`: the command name that collides. Empty otherwise.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub command: String,
}

/// Full result of [`audit_path_str`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathAuditReport {
    /// The ordered `$PATH` dirs as parsed (display form).
    pub path_dirs: Vec<String>,
    /// Flagged entries (one per (dir, risk) — duplicates carry the command).
    pub findings: Vec<PathAuditEntry>,
}

impl PathAuditReport {
    /// `true` when a High-class finding (`InTmp`/`WritableBeforeSystem`) is present.
    pub fn has_high(&self) -> bool {
        self.findings.iter().any(|e| {
            matches!(
                e.risk,
                PathDirRisk::InTmp | PathDirRisk::WritableBeforeSystem
            )
        })
    }
}

/// Audit a `$PATH` string. `repo_root` and `tmp_roots` are injected for
/// hermeticity; directory existence + writability are probed on the real FS, so
/// tests that want those signals create real temp dirs.
pub fn audit_path_str(
    path_value: &str,
    repo_root: Option<&Path>,
    tmp_roots: &[PathBuf],
) -> PathAuditReport {
    let dirs = split_path(path_value);
    let mut report = PathAuditReport {
        path_dirs: dirs.iter().map(|d| d.display().to_string()).collect(),
        findings: Vec::new(),
    };

    // Per-dir location/writability classification.
    for dir in &dirs {
        let repo_local = repo_root.map(|r| path_under(dir, r)).unwrap_or(false);
        let tmp_local = path_under_any(dir, tmp_roots);
        if repo_local {
            report.findings.push(PathAuditEntry {
                dir: dir.display().to_string(),
                risk: PathDirRisk::InRepo,
                command: String::new(),
            });
        }
        if tmp_local {
            report.findings.push(PathAuditEntry {
                dir: dir.display().to_string(),
                risk: PathDirRisk::InTmp,
                command: String::new(),
            });
        }
        // Writable-before-system is SCOPED to repo-local / /tmp dirs, matching
        // the hot-path rule (flagging every writable dir would fire everywhere).
        if (repo_local || tmp_local) && dir_precedes_system(dir, &dirs) && dir_is_user_writable(dir)
        {
            report.findings.push(PathAuditEntry {
                dir: dir.display().to_string(),
                risk: PathDirRisk::WritableBeforeSystem,
                command: String::new(),
            });
        }
    }

    // Duplicate command names across dirs: report the SHADOWED (later) dir so the
    // entry points at the copy the shell would NOT run. SCOPED to duplicates where
    // one colliding dir is repo-local/`/tmp` — flagging every Homebrew-vs-system
    // dup (`node`, `git`, …) would bury the real signal.
    let suspicious_dir = |dir: &Path| -> bool {
        repo_root.map(|r| path_under(dir, r)).unwrap_or(false) || path_under_any(dir, tmp_roots)
    };
    let mut first_seen: BTreeMap<String, usize> = BTreeMap::new();
    for (idx, dir) in dirs.iter().enumerate() {
        for name in executables_in_dir(dir) {
            match first_seen.get(&name).copied() {
                None => {
                    first_seen.insert(name, idx);
                }
                Some(first_idx) => {
                    // Report only when the first or shadowed dir is repo-local/`/tmp`.
                    if suspicious_dir(dir) || suspicious_dir(&dirs[first_idx]) {
                        report.findings.push(PathAuditEntry {
                            dir: dir.display().to_string(),
                            risk: PathDirRisk::DuplicateCommand,
                            command: name,
                        });
                    }
                }
            }
        }
    }

    report
}

/// Resolve a bare command NAME against `$PATH`, returning every dir (in order)
/// holding an executable of that name. Does NOT mutate the process environment.
pub fn which_all(command: &str, path_value: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in split_path(path_value) {
        let candidate = dir.join(command);
        if is_executable_file(&candidate) {
            out.push(candidate);
        }
    }
    out
}

/// `true` when `path` is under one of [`SYSTEM_PATH_DIRS`]. Used by
/// `tirith path which --secure`.
pub fn is_system_path(path: &Path) -> bool {
    SYSTEM_PATH_DIRS
        .iter()
        .any(|sys| path_under(path, Path::new(sys)))
}

// ─── hot-path leader resolution ──────────────────────────────────────────────

/// A resolved command leader, ready for [`classify_leader_path`].
pub struct ResolvedLeader {
    /// Absolute (best-effort) path to the leader binary.
    pub path: PathBuf,
    /// The directory it resolved from (parent of `path`).
    pub dir: PathBuf,
}

/// Resolve a command leader token to a path for the provenance check.
///
/// With a path component: `~/…` expands against `home`, a relative path against
/// `cwd`, an absolute path as-is — the path need not exist (a typed `./build/x`
/// is still classifiable). Otherwise it's a bare name resolved via [`which_all`]
/// (first hit; `None` if no PATH hit). Pure w.r.t. process env — `cwd`/`home`/
/// `path_value` are passed in for hermeticity.
pub fn resolve_leader(
    leader: &str,
    cwd: Option<&Path>,
    home: Option<&Path>,
    path_value: &str,
) -> Option<ResolvedLeader> {
    let leader = leader.trim();
    if leader.is_empty() {
        return None;
    }

    let has_path_component = leader.contains('/') || (cfg!(windows) && leader.contains('\\'));

    let path = if has_path_component {
        if let Some(rest) = leader.strip_prefix("~/") {
            home?.join(rest)
        } else if leader == "~" {
            home?.to_path_buf()
        } else {
            let p = PathBuf::from(leader);
            if p.is_absolute() {
                p
            } else {
                cwd?.join(p)
            }
        }
    } else {
        // Bare command name → first PATH hit.
        which_all(leader, path_value).into_iter().next()?
    };

    let dir = path.parent().map(|p| p.to_path_buf())?;
    Some(ResolvedLeader { path, dir })
}

// ─── shared helpers ──────────────────────────────────────────────────────────

/// Split a `$PATH` value into dirs. Empty entries (`::` or leading/trailing `:`)
/// mean "current directory" in POSIX (itself a shadowing risk), so map to `.`
/// rather than drop them.
pub fn split_path(path_value: &str) -> Vec<PathBuf> {
    #[cfg(windows)]
    let sep = ';';
    #[cfg(not(windows))]
    let sep = ':';
    path_value
        .split(sep)
        .map(|e| {
            if e.is_empty() {
                PathBuf::from(".")
            } else {
                PathBuf::from(e)
            }
        })
        .collect()
}

/// `true` when `child` is `ancestor` or lives beneath it. Both are canonicalized
/// so a symlinked ancestor (macOS `/tmp` -> `/private/tmp`) still matches; a
/// non-existent child resolves its nearest existing ancestor (keeps a typed
/// `./build/x` classifiable). See [`canonicalize_lenient`].
fn path_under(child: &Path, ancestor: &Path) -> bool {
    let c = canonicalize_lenient(child);
    let a = canonicalize_lenient(ancestor);
    c == a || c.starts_with(&a)
}

/// Canonicalize `path`, or its longest existing ancestor with the remaining
/// components re-appended; falls back to the literal path.
fn canonicalize_lenient(path: &Path) -> PathBuf {
    if let Ok(c) = path.canonicalize() {
        return c;
    }
    let mut remainder: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = path;
    while let Some(parent) = cur.parent() {
        if let Some(name) = cur.file_name() {
            remainder.push(name.to_os_string());
        }
        if let Ok(base) = parent.canonicalize() {
            let mut out = base;
            for name in remainder.iter().rev() {
                out.push(name);
            }
            return out;
        }
        cur = parent;
    }
    path.to_path_buf()
}

fn path_under_any(child: &Path, ancestors: &[PathBuf]) -> bool {
    ancestors.iter().any(|a| path_under(child, a))
}

/// `true` when `dir` appears in `path_dirs` strictly before the first system dir
/// (false if no system dir is present).
fn dir_precedes_system(dir: &Path, path_dirs: &[PathBuf]) -> bool {
    let dir_idx = path_dirs.iter().position(|d| d == dir);
    let Some(dir_idx) = dir_idx else {
        return false;
    };
    let sys_idx = path_dirs
        .iter()
        .position(|d| SYSTEM_PATH_DIRS.iter().any(|s| d == Path::new(s)));
    match sys_idx {
        Some(s) => dir_idx < s,
        None => false,
    }
}

/// `true` when the current user can write to `dir` (via `access(2)` `W_OK`).
/// Non-Unix returns `false` (the rule is a Unix-PATH concern).
#[cfg(unix)]
fn dir_is_user_writable(dir: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let Ok(cpath) = CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: cpath is a valid NUL-terminated C string; access() only reads it.
    unsafe { libc::access(cpath.as_ptr(), libc::W_OK) == 0 }
}

#[cfg(not(unix))]
fn dir_is_user_writable(_dir: &Path) -> bool {
    false
}

/// `true` when `path` is a regular file with an execute bit (Unix) or a
/// likely-executable extension (non-Unix). Symlinks are followed.
pub fn is_executable_file(path: &Path) -> bool {
    let Ok(md) = std::fs::metadata(path) else {
        return false;
    };
    if !md.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        md.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("exe") | Some("bat") | Some("cmd") | Some("com")
        )
    }
}

/// Executable file names directly inside `dir` (non-recursive, names only).
/// Unreadable/missing dirs yield an empty list.
fn executables_in_dir(dir: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in rd.flatten() {
        let p = entry.path();
        if is_executable_file(&p) {
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                out.push(name.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mkexec(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn pb(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    // ── hot-path classify_leader_path ─────────────────────────────────────

    #[test]
    fn leader_in_tmp_classifies_in_tmp() {
        let tmp = tempfile::tempdir().unwrap();
        let leader = tmp.path().join("payload");
        let tmp_roots = vec![tmp.path().to_path_buf()];
        let ctx = LeaderContext {
            resolved_path: Some(leader),
            repo_root: None,
            resolved_dir: Some(tmp.path()),
            path_dirs: &[],
            tmp_roots: &tmp_roots,
        };
        let locs = classify_leader_path(&ctx);
        assert!(locs.contains(&LeaderLocation::InTmp), "{locs:?}");
    }

    #[test]
    fn leader_in_repo_classifies_in_repo() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".git")).unwrap();
        let bindir = repo.path().join("node_modules/.bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let leader = bindir.join("eslint");
        std::fs::write(&leader, b"x").unwrap();
        let ctx = LeaderContext {
            resolved_path: Some(leader),
            repo_root: Some(repo.path()),
            resolved_dir: Some(&bindir),
            path_dirs: &[],
            tmp_roots: &[],
        };
        let locs = classify_leader_path(&ctx);
        assert!(locs.contains(&LeaderLocation::InRepo), "{locs:?}");
    }

    #[test]
    fn leader_outside_repo_and_tmp_classifies_nothing() {
        let other = tempfile::tempdir().unwrap();
        let leader = other.path().join("git");
        std::fs::write(&leader, b"x").unwrap();
        let ctx = LeaderContext {
            resolved_path: Some(leader),
            repo_root: None,
            resolved_dir: Some(other.path()),
            path_dirs: &[],
            tmp_roots: &[],
        };
        assert!(classify_leader_path(&ctx).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn writable_repo_dir_before_system_fires() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".git")).unwrap();
        let bindir = repo.path().join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let leader = bindir.join("ls");
        mkexec(&leader);
        // $PATH: repo bin FIRST, then /usr/bin.
        let path_dirs = vec![bindir.clone(), pb("/usr/bin")];
        let ctx = LeaderContext {
            resolved_path: Some(leader),
            repo_root: Some(repo.path()),
            resolved_dir: Some(&bindir),
            path_dirs: &path_dirs,
            tmp_roots: &[],
        };
        let locs = classify_leader_path(&ctx);
        assert!(
            locs.contains(&LeaderLocation::WritableDirBeforeSystem),
            "{locs:?}"
        );
        assert!(locs.contains(&LeaderLocation::InRepo), "{locs:?}");
    }

    #[cfg(unix)]
    #[test]
    fn writable_dir_after_system_does_not_fire() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".git")).unwrap();
        let bindir = repo.path().join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let leader = bindir.join("ls");
        mkexec(&leader);
        // /usr/bin FIRST, repo bin AFTER → not "before system".
        let path_dirs = vec![pb("/usr/bin"), bindir.clone()];
        let ctx = LeaderContext {
            resolved_path: Some(leader),
            repo_root: Some(repo.path()),
            resolved_dir: Some(&bindir),
            path_dirs: &path_dirs,
            tmp_roots: &[],
        };
        let locs = classify_leader_path(&ctx);
        assert!(
            !locs.contains(&LeaderLocation::WritableDirBeforeSystem),
            "must not fire when writable dir is AFTER the system dir: {locs:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_repo_writable_dir_before_system_does_not_fire_on_hot_path() {
        // The ~/.local/bin shape (writable, before /usr/bin, but not repo/tmp)
        // must NOT fire the HOT rule.
        let home_local = tempfile::tempdir().unwrap();
        let leader = home_local.path().join("ls");
        mkexec(&leader);
        let path_dirs = vec![home_local.path().to_path_buf(), pb("/usr/bin")];
        let ctx = LeaderContext {
            resolved_path: Some(leader),
            repo_root: None,
            resolved_dir: Some(home_local.path()),
            path_dirs: &path_dirs,
            tmp_roots: &[],
        };
        let locs = classify_leader_path(&ctx);
        assert!(
            locs.is_empty(),
            "a generic writable ~/.local/bin shape must not fire the HOT rule: {locs:?}"
        );
    }

    #[test]
    fn leader_findings_carry_path_evidence() {
        let f = leader_findings(&[LeaderLocation::InTmp], "/tmp/payload");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, RuleId::ExecInTmp);
        assert_eq!(f[0].severity, Severity::Medium);
        let blob = format!("{:?}", f[0].evidence);
        assert!(blob.contains("/tmp/payload"), "{blob}");
    }

    // ── cold: audit_path_str ──────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn audit_flags_repo_local_dir_before_system() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".git")).unwrap();
        let nm = repo.path().join("node_modules/.bin");
        std::fs::create_dir_all(&nm).unwrap();
        mkexec(&nm.join("eslint"));
        let path_value = format!("{}:/usr/bin", nm.display());
        let report = audit_path_str(&path_value, Some(repo.path()), &[]);
        let risks: Vec<PathDirRisk> = report.findings.iter().map(|e| e.risk).collect();
        assert!(risks.contains(&PathDirRisk::InRepo), "{risks:?}");
        assert!(
            risks.contains(&PathDirRisk::WritableBeforeSystem),
            "{risks:?}"
        );
        assert!(report.has_high());
    }

    #[cfg(unix)]
    #[test]
    fn audit_flags_tmp_dir_and_duplicate_command() {
        let tmp = tempfile::tempdir().unwrap();
        let d1 = tmp.path().join("d1");
        let d2 = tmp.path().join("d2");
        std::fs::create_dir_all(&d1).unwrap();
        std::fs::create_dir_all(&d2).unwrap();
        // Same command name in both dirs → duplicate; both under tmp root.
        mkexec(&d1.join("kubectl"));
        mkexec(&d2.join("kubectl"));
        let path_value = format!("{}:{}", d1.display(), d2.display());
        let tmp_roots = vec![tmp.path().to_path_buf()];
        let report = audit_path_str(&path_value, None, &tmp_roots);
        let risks: Vec<PathDirRisk> = report.findings.iter().map(|e| e.risk).collect();
        assert!(risks.contains(&PathDirRisk::InTmp), "{risks:?}");
        assert!(risks.contains(&PathDirRisk::DuplicateCommand), "{risks:?}");
        // The duplicate entry names the colliding command and points at d2
        // (the shadowed, later copy).
        let dup = report
            .findings
            .iter()
            .find(|e| e.risk == PathDirRisk::DuplicateCommand)
            .unwrap();
        assert_eq!(dup.command, "kubectl");
        assert!(dup.dir.contains("d2"), "{}", dup.dir);
    }

    #[test]
    fn audit_clean_path_has_no_findings() {
        // Two non-existent, non-system, non-repo dirs → nothing to flag.
        let report = audit_path_str("/opt/clean/bin:/usr/bin", None, &[]);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert!(!report.has_high());
    }

    // ── which_all + is_system_path ────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn which_all_resolves_in_path_order() {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        mkexec(&d1.path().join("git"));
        mkexec(&d2.path().join("git"));
        let path_value = format!("{}:{}", d1.path().display(), d2.path().display());
        let hits = which_all("git", &path_value);
        assert_eq!(hits.len(), 2);
        assert!(hits[0].starts_with(d1.path()));
        assert!(hits[1].starts_with(d2.path()));
    }

    #[cfg(unix)]
    #[test]
    fn which_all_skips_non_executable() {
        let d1 = tempfile::tempdir().unwrap();
        // A non-executable file named git → not resolved.
        std::fs::write(d1.path().join("git"), b"text").unwrap();
        let hits = which_all("git", &d1.path().display().to_string());
        assert!(hits.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn is_system_path_recognizes_usr_bin() {
        assert!(is_system_path(Path::new("/usr/bin/git")));
        assert!(is_system_path(Path::new("/bin/sh")));
        assert!(!is_system_path(Path::new("/opt/homebrew/bin/git")));
        assert!(!is_system_path(Path::new("/tmp/git")));
    }

    #[cfg(windows)]
    #[test]
    fn is_system_path_recognizes_system32() {
        // SYSTEM_PATH_DIRS on Windows holds the System32 / Windows dirs.
        assert!(is_system_path(Path::new(r"C:\Windows\System32\cmd.exe")));
        assert!(!is_system_path(Path::new(r"C:\Users\me\bin\git.exe")));
    }

    // `split_path` uses the platform separator (`:` on Unix, `;` on Windows),
    // so each separator case is gated to the platform whose separator it uses.
    #[cfg(not(windows))]
    #[test]
    fn split_path_maps_empty_to_dot() {
        let dirs = split_path("/usr/bin::/bin");
        assert_eq!(dirs, vec![pb("/usr/bin"), pb("."), pb("/bin")]);
    }

    #[cfg(windows)]
    #[test]
    fn split_path_maps_empty_to_dot_windows() {
        // On Windows the separator is `;`; an empty entry (a literal `;;` or a
        // trailing `;`) still maps to `.` so it is audited, not dropped.
        let dirs = split_path(r"C:\bin;;C:\sys");
        assert_eq!(dirs, vec![pb(r"C:\bin"), pb("."), pb(r"C:\sys")]);
        // A colon inside a drive-letter path must NOT be treated as a separator.
        let drive = split_path(r"C:\Windows\System32");
        assert_eq!(drive, vec![pb(r"C:\Windows\System32")]);
    }

    // ── resolve_leader ────────────────────────────────────────────────────

    #[test]
    fn resolve_leader_relative_path_against_cwd() {
        let cwd = tempfile::tempdir().unwrap();
        let r = resolve_leader("./build/tool", Some(cwd.path()), None, "").unwrap();
        assert_eq!(r.path, cwd.path().join("build/tool"));
        assert_eq!(r.dir, cwd.path().join("build"));
    }

    #[test]
    fn resolve_leader_tilde_expands_against_home() {
        let home = tempfile::tempdir().unwrap();
        let r = resolve_leader("~/bin/x", None, Some(home.path()), "").unwrap();
        assert_eq!(r.path, home.path().join("bin/x"));
    }

    // `/usr/local/bin/foo` is only `is_absolute()` on Unix (no drive letter on
    // Windows), so the Unix and Windows absolute-path cases are gated apart.
    #[cfg(not(windows))]
    #[test]
    fn resolve_leader_absolute_path_used_directly() {
        let r = resolve_leader("/usr/local/bin/foo", None, None, "").unwrap();
        assert_eq!(r.path, pb("/usr/local/bin/foo"));
    }

    #[cfg(windows)]
    #[test]
    fn resolve_leader_absolute_path_used_directly_windows() {
        // A drive-rooted Windows path with backslashes is absolute and used
        // as-is (no cwd needed) — and a `\`-bearing leader counts as having a
        // path component on Windows.
        let r = resolve_leader(r"C:\tools\foo.exe", None, None, "").unwrap();
        assert_eq!(r.path, pb(r"C:\tools\foo.exe"));
    }

    #[cfg(windows)]
    #[test]
    fn resolve_leader_relative_no_cwd_is_none_not_panic() {
        // A relative leader with no cwd returns None, never panics (Windows CI bug:
        // a non-drive path is relative, so `cwd?` short-circuits to None).
        assert!(resolve_leader(r"build\tool", None, None, "").is_none());
        assert!(resolve_leader("/usr/local/bin/foo", None, None, "").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn resolve_leader_bare_name_uses_first_path_hit() {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        mkexec(&d1.path().join("mytool"));
        mkexec(&d2.path().join("mytool"));
        let path_value = format!("{}:{}", d1.path().display(), d2.path().display());
        let r = resolve_leader("mytool", None, None, &path_value).unwrap();
        assert!(
            r.path.starts_with(d1.path()),
            "first hit wins: {:?}",
            r.path
        );
    }

    #[test]
    fn resolve_leader_bare_name_no_hit_is_none() {
        assert!(resolve_leader("definitely-not-on-path-xyz", None, None, "/usr/bin").is_none());
    }
}
