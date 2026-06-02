//! Blast-radius simulator (M10 ch1).
//!
//! Two surfaces, load-bearing split:
//!   * [`cheap_check`] — pure string-shape analysis (no fs access/glob/`stat`).
//!     Fires when a target is dangerous by shape alone (`/`, `/home`, `~`, or a
//!     `"$VAR/"` glob resolving to empty). The ONLY surface the `engine::analyze`
//!     exec/paste hot path may call; gated at tier-1 by `destructive_fs_op`.
//!   * [`simulate`] — full simulator: walks the fs (capped depth 5 / 100k files),
//!     expands globs, counts files/dirs/symlinks, decides repo / system-path
//!     escape. EXPENSIVE; runs ONLY under `tirith preview`, NEVER from the hot path.
//!
//! `$VAR` resolution: the empty-var-glob bug (`rm -rf "$EMPTY/"` → `rm -rf "/"`)
//! is detected against an injected variable map, not `std::env` inside the
//! detector, so tests avoid the libc `setenv` race (PR #125). Production callers
//! pass a `std::env::vars()` snapshot via [`env_snapshot`].

use crate::tokenize::{self, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Maximum directory-walk depth for [`simulate`].
pub const MAX_WALK_DEPTH: usize = 5;

/// Max files [`simulate`] counts before stopping (guards pathological trees /
/// `rm -rf /`).
pub const MAX_FILE_COUNT: usize = 100_000;

/// File-count threshold above which [`RuleId::BlastLargeFileCount`] (Info) fires.
pub const LARGE_FILE_COUNT_THRESHOLD: u64 = 1000;

/// Result of a full filesystem simulation. Produced ONLY by [`simulate`] (i.e.
/// only under `tirith preview`).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BlastReport {
    /// Regular files within the resolved targets (capped at [`MAX_FILE_COUNT`]).
    pub file_count: u64,
    pub dir_count: u64,
    /// Symlinks encountered (counted, never followed).
    pub symlink_count: u64,
    /// The largest regular file, as `(path, size_bytes)`.
    pub largest_file: Option<(String, u64)>,
    /// Any resolved target escapes the repo root (or, with no root, is absolute /
    /// climbs above cwd).
    pub paths_outside_repo: bool,
    /// Any resolved target is (or is under) a well-known system path.
    pub writes_system_path: bool,
    /// Paths a glob argument expanded to against the cwd.
    pub glob_expansion_count: u64,
    /// A `"$VAR/"`-shaped argument resolved to an empty variable, collapsing to
    /// root (`rm -rf "$EMPTY/"` → `rm -rf "/"`).
    pub unsafe_empty_var_glob: bool,
    /// Walk hit [`MAX_FILE_COUNT`] / [`MAX_WALK_DEPTH`]; counts are lower bounds.
    pub walk_truncated: bool,
    /// Directories/entries the walk could NOT read (perms, I/O, symlink loop).
    /// When `> 0` a subtree was silently skipped, so counts are lower bounds and
    /// a `preview` must not present them as complete.
    pub walk_errors: u64,
}

/// How an empty-`$VAR`-glob target resolved against tirith's own env. Drives the
/// severity split in [`cheap_check`] (F2): tirith sees only its OWN env, so an
/// ABSENT var might be a benign non-exported shell-local — must not BLOCK on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmptyVarKind {
    /// Present in tirith's env and empty → unambiguous root collapse → High.
    PresentEmpty,
    /// Absent from tirith's env: collapses to root IFF the shell also has it
    /// unset, but could be a set shell-local. Advisory Info, not Block (F2).
    Absent,
}

/// A destructive filesystem operation recognized by the blast-radius surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FsOp {
    Rm,
    /// `mv` (the source is removed).
    Mv,
    /// `chmod` (recursive is the dangerous shape).
    Chmod,
    FindDelete,
    /// `rsync --delete` (mirror delete on the destination side).
    RsyncDelete,
}

/// A parsed destructive invocation: op plus quote-stripped non-flag targets in order.
struct ParsedFsOp {
    op: FsOp,
    /// Carries a recursive flag (`-r`/`-R`/`--recursive`) — only for `rm`/`chmod`.
    recursive: bool,
    targets: Vec<String>,
}

/// Snapshot the process environment for the `env_map` parameter of
/// [`cheap_check`] / [`simulate`]. Call ONCE in the caller (never inside the
/// detector) so the detector stays pure and testable.
pub fn env_snapshot() -> HashMap<String, String> {
    std::env::vars().collect()
}

/// Cheap, filesystem-free blast-radius check for the hot path. Fires the
/// string-shape-only rules ([`RuleId::BlastWritesSystemPath`],
/// [`RuleId::BlastEmptyVarGlob`], [`RuleId::BlastFindDelete`],
/// [`RuleId::BlastRsyncDelete`]). Does NOT touch the fs, glob, or count — the
/// simulator-only signals are produced exclusively by [`simulate`].
pub fn cheap_check(
    input: &str,
    shell: ShellType,
    env_map: &HashMap<String, String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let segments = tokenize::tokenize(input, shell);

    for seg in &segments {
        let Some(parsed) = parse_fs_op(seg) else {
            continue;
        };

        // `find … -delete` / `rsync --delete` are advisory in their own right:
        // surface them even for non-system targets — the recursive sweep is the hazard.
        match parsed.op {
            FsOp::FindDelete => {
                findings.push(finding(
                    RuleId::BlastFindDelete,
                    Severity::Medium,
                    "find with -delete recursively removes matching files",
                    "A `find … -delete` traverses the directory tree and unlinks every \
                     matching entry. Run `tirith preview` to see how many files this would \
                     remove before executing it.",
                    Evidence::CommandPattern {
                        pattern: "find … -delete".to_string(),
                        matched: seg.raw.clone(),
                    },
                ));
            }
            FsOp::RsyncDelete => {
                findings.push(finding(
                    RuleId::BlastRsyncDelete,
                    Severity::Medium,
                    "rsync --delete removes files on the destination not present in the source",
                    "A mirror with `rsync --delete` deletes anything in the destination that \
                     is not in the source. A wrong source/destination pair can wipe the \
                     destination. Run `tirith preview` to see the impact.",
                    Evidence::CommandPattern {
                        pattern: "rsync --delete".to_string(),
                        matched: seg.raw.clone(),
                    },
                ));
            }
            FsOp::Rm | FsOp::Mv | FsOp::Chmod => {}
        }

        for target in &parsed.targets {
            // Empty-`$VAR/` glob (`rm -rf "$EMPTY/"` → `rm -rf "/"`). F2: tirith
            // sees only its OWN env. PRESENT-and-empty is an unambiguous collapse
            // (High/Block); merely ABSENT might be a set shell-local, so emit Info
            // with a note rather than a false High.
            if let Some((var, kind)) = empty_var_glob_var(target, env_map) {
                let (severity, description) = match kind {
                    EmptyVarKind::PresentEmpty => (
                        Severity::High,
                        "An argument of the shape `\"$VAR/\"` where `VAR` is set to the empty \
                         string expands to `\"/\"`, so this command would operate on the \
                         filesystem root. Quote-and-set the variable, or guard with \
                         `${VAR:?must be set}`."
                            .to_string(),
                    ),
                    EmptyVarKind::Absent => (
                        Severity::Info,
                        format!(
                            "The argument references `${var}`, which is NOT set in tirith's \
                             environment. If `${var}` is also unset in your shell, `\"${var}/\"` \
                             collapses to `\"/\"` (a filesystem-root delete); if it is a \
                             non-exported shell-local that IS set, this is harmless — tirith \
                             cannot see shell-locals, so this is advisory only. Run \
                             `tirith preview` in the same shell to resolve it, or guard with \
                             `${{{var}:?must be set}}`."
                        ),
                    ),
                };
                findings.push(finding(
                    RuleId::BlastEmptyVarGlob,
                    severity,
                    "destructive command targets an empty-variable path that may collapse to root",
                    &description,
                    Evidence::Text {
                        detail: format!(
                            "argument '{target}' references empty variable '${var}' → may collapse to a root path"
                        ),
                    },
                ));
                continue;
            }

            // Spec scopes the destructive set to `chmod -R`: a non-recursive
            // `chmod 0644 /etc/foo.conf` touches one file, not a tree, so it does
            // not trip the system-path rule. rm/mv/find-delete/rsync always check.
            if parsed.op == FsOp::Chmod && !parsed.recursive {
                continue;
            }

            if is_system_path(target) {
                findings.push(finding(
                    RuleId::BlastWritesSystemPath,
                    Severity::High,
                    "destructive command targets a system path",
                    "This destructive command targets a broad system path (root, a home \
                     tree, or a system directory). Even when intentional this routinely \
                     breaks the OS or removes other users' data. Run `tirith preview` to \
                     see the exact impact first.",
                    Evidence::Text {
                        detail: format!("target '{target}' is a system path"),
                    },
                ));
            }
        }
    }

    dedup_findings(findings)
}

/// Full filesystem simulation for `tirith preview`: walks cwd-relative targets
/// (capped at [`MAX_WALK_DEPTH`] / [`MAX_FILE_COUNT`]), expands globs, counts
/// files/dirs/symlinks, finds the largest file, decides repo/system-path escape.
///
/// `cwd` is what globs/relative paths resolve against; `repo_root` (when known)
/// is the [`BlastReport::paths_outside_repo`] boundary, else any absolute target
/// / `..`-escape counts as outside.
pub fn simulate(
    input: &str,
    shell: ShellType,
    cwd: &Path,
    repo_root: Option<&Path>,
    env_map: &HashMap<String, String>,
) -> BlastReport {
    let mut report = BlastReport::default();
    let segments = tokenize::tokenize(input, shell);

    for seg in &segments {
        let Some(parsed) = parse_fs_op(seg) else {
            continue;
        };

        for target in &parsed.targets {
            // Empty-var glob collapses to root — record and skip the walk (no `/`).
            if empty_var_glob_var(target, env_map).is_some() {
                report.unsafe_empty_var_glob = true;
                report.paths_outside_repo = true;
                report.writes_system_path = true;
                continue;
            }

            if is_system_path(target) {
                report.writes_system_path = true;
            }

            // Expand the target (glob against cwd, else literal) to concrete paths.
            let expanded = expand_target(target, cwd, &mut report);
            if expanded.len() > 1 || target_is_glob(target) {
                report.glob_expansion_count += expanded.len() as u64;
            }

            for path in expanded {
                if path_escapes_repo(&path, cwd, repo_root) {
                    report.paths_outside_repo = true;
                }
                walk_into(&path, cwd, &mut report);
            }
        }
    }

    report
}

/// Emit the simulator-only findings ([`RuleId::BlastDeletesOutsideRepo`],
/// [`RuleId::BlastSymlinkTraversal`], [`RuleId::BlastLargeFileCount`]) from a
/// [`BlastReport`]; the caller merges in the cheap [`cheap_check`] rules.
pub fn report_findings(report: &BlastReport) -> Vec<Finding> {
    let mut findings = Vec::new();

    if report.paths_outside_repo && !report.unsafe_empty_var_glob {
        findings.push(finding(
            RuleId::BlastDeletesOutsideRepo,
            Severity::High,
            "destructive command reaches outside the repository",
            "At least one resolved target is outside the current repository (or above the \
             current directory). A destructive operation here can affect files you did not \
             intend to touch.",
            Evidence::Text {
                detail: "one or more targets resolve outside the repo root".to_string(),
            },
        ));
    }

    if report.symlink_count > 0 {
        findings.push(finding(
            RuleId::BlastSymlinkTraversal,
            Severity::Medium,
            "destructive command's target tree contains symlinks",
            "The target tree contains symbolic links. Depending on the tool and flags, a \
             destructive operation may traverse a link and affect files outside the visible \
             tree. Review the links before proceeding.",
            Evidence::Text {
                detail: format!(
                    "{} symlink(s) found in the target tree",
                    report.symlink_count
                ),
            },
        ));
    }

    if report.file_count > LARGE_FILE_COUNT_THRESHOLD {
        findings.push(finding(
            RuleId::BlastLargeFileCount,
            Severity::Info,
            "destructive command affects a large number of files",
            "This operation would touch more than 1000 files. That is not necessarily wrong, \
             but it is large enough to be worth a second look.",
            Evidence::Text {
                detail: format!(
                    "{}{} file(s) in the target tree",
                    report.file_count,
                    if report.walk_truncated { "+" } else { "" }
                ),
            },
        ));
    }

    findings
}

// --- Parsing ---

/// Parse a tokenized segment into a destructive-op descriptor, or `None` when
/// the leader is not a recognized destructive command.
fn parse_fs_op(seg: &tokenize::Segment) -> Option<ParsedFsOp> {
    let leader = seg.command.as_deref()?;
    let leader = leader_name(leader);

    // Unwrap a leading `sudo`/`doas` so `sudo rm -rf /home` is recognized as the
    // `rm` it is — privilege escalation must NOT drop out of the check. Mirrors
    // `engine::baseline_shared_components`, which also de-sudo's the leader.
    if matches!(leader, "sudo" | "doas") {
        let (wrapped_leader, wrapped_args) = unwrap_sudo(&seg.args)?;
        return parse_op_for_leader(leader_name(&wrapped_leader), &wrapped_args);
    }

    parse_op_for_leader(leader, &seg.args)
}

/// Match a (de-sudo'd) leader + args onto a destructive-op descriptor.
fn parse_op_for_leader(leader: &str, args: &[String]) -> Option<ParsedFsOp> {
    match leader {
        "rm" => Some(parse_simple(FsOp::Rm, args)),
        "mv" => Some(parse_simple(FsOp::Mv, args)),
        "chmod" => Some(parse_simple(FsOp::Chmod, args)),
        "find" => parse_find(args),
        "rsync" => parse_rsync(args),
        _ => None,
    }
}

/// Skip a `sudo`/`doas` invocation's own flags (and their values), leading
/// `VAR=value` assignments, and an optional `--`, then return the WRAPPED command.
/// `None` when no wrapped command follows (e.g. `sudo -v`).
fn unwrap_sudo(args: &[String]) -> Option<(String, Vec<String>)> {
    // sudo short flags that consume the NEXT token as their value.
    const VALUE_SHORT: [&str; 6] = ["-u", "-g", "-C", "-D", "-R", "-T"];
    // sudo long flags that consume the next token (`--flag=value` is handled by
    // the `contains('=')` branch below).
    const VALUE_LONG: [&str; 9] = [
        "--user",
        "--group",
        "--close-from",
        "--chdir",
        "--role",
        "--type",
        "--other-user",
        "--host",
        "--prompt",
    ];

    let mut idx = 0;
    while idx < args.len() {
        let a = strip_outer_quotes(&args[idx]);
        if a == "--" {
            idx += 1;
            break;
        }
        if a.starts_with("--") {
            let name = a.split('=').next().unwrap_or(a);
            // `--flag=value` is self-contained; a bare VALUE_LONG `--flag` eats
            // the next token.
            if !a.contains('=') && VALUE_LONG.contains(&name) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            if VALUE_SHORT.contains(&a) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        // A leading `VAR=value` is an env assignment, not the command.
        if a.contains('=') && !a.starts_with('/') {
            idx += 1;
            continue;
        }
        // First non-flag, non-assignment token is the wrapped leader.
        break;
    }

    let leader = args.get(idx).map(|s| strip_outer_quotes(s).to_string())?;
    let wrapped_args: Vec<String> = args[idx + 1..].to_vec();
    Some((leader, wrapped_args))
}

/// Strip a leading path component from a leader so `/bin/rm` matches `rm`.
fn leader_name(leader: &str) -> &str {
    leader.rsplit(['/', '\\']).next().unwrap_or(leader)
}

/// Parse `rm` / `mv` / `chmod`: collect non-flag operands, note recursion. For
/// `chmod` the first non-flag operand is the mode and is dropped from targets.
fn parse_simple(op: FsOp, args: &[String]) -> ParsedFsOp {
    let mut recursive = false;
    let mut targets = Vec::new();
    let mut after_double_dash = false;
    let mut seen_mode = false;

    for arg in args {
        let a = strip_outer_quotes(arg);
        if after_double_dash {
            targets.push(a.to_string());
            continue;
        }
        if a == "--" {
            after_double_dash = true;
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            if is_recursive_flag(a) {
                recursive = true;
            }
            continue;
        }
        if op == FsOp::Chmod && !seen_mode {
            // First positional chmod arg is the mode, not a target.
            seen_mode = true;
            continue;
        }
        targets.push(a.to_string());
    }

    ParsedFsOp {
        op,
        recursive,
        targets,
    }
}

/// Parse `find`: destructive only with `-delete`. Targets are the leading path
/// operands (before the first `-` predicate); default to `.` when none given.
fn parse_find(args: &[String]) -> Option<ParsedFsOp> {
    let stripped: Vec<&str> = args.iter().map(|a| strip_outer_quotes(a)).collect();
    if !stripped.contains(&"-delete") {
        return None;
    }

    let mut targets = Vec::new();
    for a in &stripped {
        if a.starts_with('-') {
            break;
        }
        targets.push((*a).to_string());
    }
    if targets.is_empty() {
        targets.push(".".to_string());
    }

    Some(ParsedFsOp {
        op: FsOp::FindDelete,
        recursive: true,
        targets,
    })
}

/// Parse `rsync`: destructive only with a `--delete*` flag. The destination
/// (the side that loses files) is the last non-flag operand.
fn parse_rsync(args: &[String]) -> Option<ParsedFsOp> {
    let stripped: Vec<&str> = args.iter().map(|a| strip_outer_quotes(a)).collect();
    let has_delete = stripped
        .iter()
        .any(|a| *a == "--delete" || a.starts_with("--delete-") || *a == "--del");
    if !has_delete {
        return None;
    }

    let operands: Vec<String> = stripped
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(|a| (*a).to_string())
        .collect();
    // Destination = last operand; the side `--delete` prunes.
    let targets = operands.last().cloned().into_iter().collect();

    Some(ParsedFsOp {
        op: FsOp::RsyncDelete,
        recursive: true,
        targets,
    })
}

fn is_recursive_flag(a: &str) -> bool {
    if a == "--recursive" {
        return true;
    }
    // Bundled short flags, e.g. `-rf`, `-Rf`.
    if let Some(rest) = a.strip_prefix('-') {
        if !rest.starts_with('-') {
            return rest.chars().any(|c| c == 'r' || c == 'R');
        }
    }
    false
}

// --- String-shape predicates ---

/// Returns the variable name when `arg` is a `"$VAR/"`-shaped path whose variable
/// resolves to empty in `env_map` (the empty-var-glob bug: `rm -rf "$EMPTY/"` →
/// `rm -rf "/"`). Shapes: `$VAR/`, `${VAR}/`, and the bare `$VAR` / `${VAR}`.
///
/// A braced parameter-expansion operator (`${VAR:-default}`, `${VAR:?msg}`,
/// `${VAR:+alt}`, `${VAR#pat}`, …) is NOT eligible: those supply/substitute,
/// transform, or abort on empty — none collapse to `"/"`, and treating them as
/// such would false-positive on the rule's own `${VAR:?must be set}` guard. Only
/// the bare `${NAME}` form (name = all `[A-Za-z0-9_]`) is eligible.
fn empty_var_glob_var(
    arg: &str,
    env_map: &HashMap<String, String>,
) -> Option<(String, EmptyVarKind)> {
    let rest = arg.strip_prefix('$')?;

    // `${VAR}` / `${VAR}/...` form.
    let (name, tail) = if let Some(braced) = rest.strip_prefix('{') {
        let end = braced.find('}')?;
        let body = &braced[..end];
        // Reject any parameter-expansion operator: a non-`[A-Za-z0-9_]` char
        // after the name means an operator (`:-`, `?`, `#`, …) that defeats the
        // empty-collapse, so it must not fire.
        let name_end = body
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(body.len());
        if name_end != body.len() {
            return None;
        }
        (&body[..name_end], &braced[end + 1..])
    } else {
        // `$VAR` / `$VAR/...` — name runs while alnum/underscore.
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        (&rest[..end], &rest[end..])
    };

    if name.is_empty() {
        return None;
    }
    // Footgun = a variable used as a path prefix: the operand is just the
    // variable or `$VAR/...`. Other trailing text (`$VARsuffix`) is not this shape.
    if !(tail.is_empty() || tail.starts_with('/')) {
        return None;
    }

    match env_map.get(name) {
        // Present and "" → unambiguous collapse → High.
        Some(v) if v.is_empty() => Some((name.to_string(), EmptyVarKind::PresentEmpty)),
        // Present and non-empty → normal expansion.
        Some(_) => None,
        // Absent → MIGHT be an unset shell var OR a set shell-local. Advisory (F2).
        None => Some((name.to_string(), EmptyVarKind::Absent)),
    }
}

/// Well-known broad system paths by string shape. Mirrors `rules::sudo`'s
/// `is_broad_path` plus the bare `~` home shape.
fn is_system_path(p: &str) -> bool {
    let p = p.trim();
    if p == "~" || p == "~/" {
        return true;
    }
    // Exact roots and trailing-slash variants.
    matches!(
        p,
        "/" | "/home"
            | "/usr"
            | "/etc"
            | "/var"
            | "/opt"
            | "/srv"
            | "/lib"
            | "/bin"
            | "/sbin"
            | "/boot"
            | "/root"
            | "/sys"
            | "/proc"
            | "/dev"
    ) || matches!(
        p,
        "/home/"
            | "/usr/"
            | "/etc/"
            | "/var/"
            | "/opt/"
            | "/srv/"
            | "/lib/"
            | "/bin/"
            | "/sbin/"
            | "/boot/"
            | "/root/"
            | "/sys/"
            | "/proc/"
            | "/dev/"
    )
}

fn target_is_glob(target: &str) -> bool {
    target.contains('*') || target.contains('?') || target.contains('[')
}

/// Strip one layer of matching single/double quotes.
fn strip_outer_quotes(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 2
        && ((b[0] == b'"' && b[b.len() - 1] == b'"') || (b[0] == b'\'' && b[b.len() - 1] == b'\''))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

// --- Filesystem walk (simulate-only) ---

/// Expand a target into concrete paths. Globs (`*`/`?`/`[`) match a single
/// directory against `cwd` (no recursive `**`); non-globs resolve to one path.
fn expand_target(target: &str, cwd: &Path, report: &mut BlastReport) -> Vec<PathBuf> {
    if target_is_glob(target) {
        glob_in_cwd(target, cwd, report)
    } else {
        vec![resolve_relative(target, cwd)]
    }
}

/// Resolve a possibly-relative / `~`-prefixed path against `cwd` (`~` from `HOME`).
fn resolve_relative(target: &str, cwd: &Path) -> PathBuf {
    if let Some(rest) = target.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    let p = PathBuf::from(target);
    if p.is_absolute() {
        p
    } else {
        cwd.join(p)
    }
}

/// Single-level glob: split into `<dir>/<basename-pattern>`, read `<dir>`, keep
/// name-matching entries. Only the basename may have a wildcard — enough for the
/// common `./dist/*` / `*.log` preview shapes.
fn glob_in_cwd(pattern: &str, cwd: &Path, report: &mut BlastReport) -> Vec<PathBuf> {
    let (dir_part, name_part) = match pattern.rsplit_once('/') {
        Some((d, n)) => (d.to_string(), n.to_string()),
        None => (String::new(), pattern.to_string()),
    };
    let dir = if dir_part.is_empty() {
        cwd.to_path_buf()
    } else {
        resolve_relative(&dir_part, cwd)
    };

    let mut out = Vec::new();
    match std::fs::read_dir(&dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if glob_match(&name_part, &name) {
                    out.push(entry.path());
                }
            }
        }
        // A glob over an unreadable dir expands to nothing; record it so the
        // report flags the walk as incomplete (F3).
        Err(_) => report.walk_errors += 1,
    }
    out
}

/// Minimal glob matcher: `*` (any run), `?` (one char), `[` literal. Enough for
/// preview-grade counting.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    // Iterative match with backtracking on `*`.
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Decide whether `path` escapes the repo: with a `repo_root`, not under the
/// canonicalized root; without one, any absolute path or climb above `cwd`.
fn path_escapes_repo(path: &Path, cwd: &Path, repo_root: Option<&Path>) -> bool {
    let resolved = canonicalize_lexical(path, cwd);
    match repo_root {
        Some(root) => {
            let root = canonicalize_lexical(root, cwd);
            !resolved.starts_with(&root)
        }
        None => {
            let base = canonicalize_lexical(cwd, cwd);
            !resolved.starts_with(&base)
        }
    }
}

/// Lexically normalize a path (resolve `.`/`..` without the fs, so it works for
/// nonexistent paths). Relative paths are first joined onto `cwd`.
fn canonicalize_lexical(path: &Path, cwd: &Path) -> PathBuf {
    use std::path::Component;
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let mut out = PathBuf::new();
    for comp in joined.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Walk `path` into the report, honoring the depth/file-count caps. Symlinks are
/// counted, never followed.
fn walk_into(path: &Path, _cwd: &Path, report: &mut BlastReport) {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            // NotFound is normal (nothing to count); any other error means we
            // under-counted, so flag it.
            if e.kind() != std::io::ErrorKind::NotFound {
                report.walk_errors += 1;
            }
            return;
        }
    };

    if meta.file_type().is_symlink() {
        report.symlink_count += 1;
        return;
    }
    if meta.is_file() {
        count_file(path, meta.len(), report);
        return;
    }
    if meta.is_dir() {
        report.dir_count += 1;
        walk_dir(path, 1, report);
    }
}

fn walk_dir(dir: &Path, depth: usize, report: &mut BlastReport) {
    if report.file_count >= MAX_FILE_COUNT as u64 {
        report.walk_truncated = true;
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => {
            // Unreadable dir (perms/I/O): its subtree is silently uncounted.
            // Record it so the report does not present a partial walk as complete (F3).
            report.walk_errors += 1;
            return;
        }
    };
    for entry in entries.flatten() {
        if report.file_count >= MAX_FILE_COUNT as u64 {
            report.walk_truncated = true;
            return;
        }
        let path = entry.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => {
                report.walk_errors += 1;
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            report.symlink_count += 1;
            continue; // never follow
        }
        if meta.is_dir() {
            report.dir_count += 1;
            if depth < MAX_WALK_DEPTH {
                walk_dir(&path, depth + 1, report);
            } else {
                report.walk_truncated = true;
            }
        } else if meta.is_file() {
            count_file(&path, meta.len(), report);
        }
    }
}

fn count_file(path: &Path, size: u64, report: &mut BlastReport) {
    report.file_count += 1;
    let bigger = report
        .largest_file
        .as_ref()
        .map(|(_, s)| size > *s)
        .unwrap_or(true);
    if bigger {
        report.largest_file = Some((path.display().to_string(), size));
    }
}

// --- Helpers ---

fn finding(
    rule_id: RuleId,
    severity: Severity,
    title: &str,
    description: &str,
    evidence: Evidence,
) -> Finding {
    Finding {
        rule_id,
        severity,
        title: title.to_string(),
        description: description.to_string(),
        evidence: vec![evidence],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

/// Drop duplicate `rule_id` findings (keep first): multiple system-path targets
/// surface one finding, not N.
fn dedup_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen = std::collections::HashSet::new();
    findings
        .into_iter()
        .filter(|f| seen.insert(f.rule_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn empty_env() -> HashMap<String, String> {
        HashMap::new()
    }

    #[test]
    fn cheap_check_flags_system_path_rm() {
        let f = cheap_check("rm -rf /home", ShellType::Posix, &empty_env());
        assert!(
            f.iter().any(|f| f.rule_id == RuleId::BlastWritesSystemPath),
            "expected BlastWritesSystemPath, got {:?}",
            f.iter().map(|f| f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn cheap_check_flags_root_slash() {
        let f = cheap_check("rm -rf /", ShellType::Posix, &empty_env());
        assert!(f.iter().any(|f| f.rule_id == RuleId::BlastWritesSystemPath));
    }

    #[test]
    fn cheap_check_flags_empty_var_glob() {
        // EMPTY absent → empty → collapses to "/".
        let f = cheap_check("rm -rf \"$EMPTY/\"", ShellType::Posix, &empty_env());
        assert!(
            f.iter().any(|f| f.rule_id == RuleId::BlastEmptyVarGlob),
            "expected BlastEmptyVarGlob, got {:?}",
            f.iter().map(|f| f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn cheap_check_set_var_does_not_fire_empty_var_glob() {
        let mut env = HashMap::new();
        env.insert("BUILD".to_string(), "dist".to_string());
        let f = cheap_check("rm -rf \"$BUILD/\"", ShellType::Posix, &env);
        assert!(
            !f.iter().any(|f| f.rule_id == RuleId::BlastEmptyVarGlob),
            "a set variable must not fire the empty-var rule"
        );
    }

    #[test]
    fn cheap_check_braced_empty_var() {
        let f = cheap_check("rm -rf \"${MISSING}/\"", ShellType::Posix, &empty_env());
        assert!(f.iter().any(|f| f.rule_id == RuleId::BlastEmptyVarGlob));
    }

    #[test]
    fn cheap_check_brace_default_does_not_fire() {
        // C2: `${BUILD:-dist}` has a default, so it never collapses — must NOT
        // fire even when BUILD is absent.
        let f = cheap_check("rm -rf \"${BUILD:-dist}/\"", ShellType::Posix, &empty_env());
        assert!(
            !f.iter().any(|f| f.rule_id == RuleId::BlastEmptyVarGlob),
            "${{BUILD:-dist}} has a default and must not fire empty-var-glob, got {:?}",
            f.iter().map(|f| f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn cheap_check_brace_required_guard_does_not_fire() {
        // C2: `${VAR:?msg}` is the rule's own guard — aborts on empty, must not fire.
        let f = cheap_check(
            "rm -rf \"${BUILD:?must be set}/\"",
            ShellType::Posix,
            &empty_env(),
        );
        assert!(
            !f.iter().any(|f| f.rule_id == RuleId::BlastEmptyVarGlob),
            "${{BUILD:?msg}} aborts on empty and must not fire"
        );
    }

    #[test]
    fn cheap_check_brace_alt_and_transform_do_not_fire() {
        // `:+alt`, `#pat`, `%pat` supply or transform — none collapse to root.
        for form in [
            "rm -rf \"${BUILD:+x}/\"",
            "rm -rf \"${BUILD#pre}/\"",
            "rm -rf \"${BUILD%suf}/\"",
        ] {
            let f = cheap_check(form, ShellType::Posix, &empty_env());
            assert!(
                !f.iter().any(|f| f.rule_id == RuleId::BlastEmptyVarGlob),
                "{form} must not fire empty-var-glob"
            );
        }
    }

    #[test]
    fn cheap_check_flags_find_delete() {
        let f = cheap_check("find . -type f -delete", ShellType::Posix, &empty_env());
        assert!(f.iter().any(|f| f.rule_id == RuleId::BlastFindDelete));
    }

    #[test]
    fn cheap_check_find_without_delete_is_silent() {
        let f = cheap_check(
            "find . -type f -name '*.rs'",
            ShellType::Posix,
            &empty_env(),
        );
        assert!(f.is_empty(), "find without -delete must not fire");
    }

    #[test]
    fn cheap_check_flags_rsync_delete() {
        let f = cheap_check(
            "rsync -a --delete src/ dst/",
            ShellType::Posix,
            &empty_env(),
        );
        assert!(f.iter().any(|f| f.rule_id == RuleId::BlastRsyncDelete));
    }

    #[test]
    fn cheap_check_rsync_without_delete_is_silent() {
        let f = cheap_check("rsync -a src/ dst/", ShellType::Posix, &empty_env());
        assert!(f.is_empty());
    }

    #[test]
    fn cheap_check_relative_target_is_silent() {
        // Hot/cold split: `rm -rf ./dist` is not a system path, so the cheap path
        // stays silent and leaves counting to `tirith preview`.
        let f = cheap_check("rm -rf ./dist", ShellType::Posix, &empty_env());
        assert!(
            f.is_empty(),
            "relative target must not fire on the cheap path, got {:?}",
            f.iter().map(|f| f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn cheap_check_mv_to_root() {
        let f = cheap_check("mv important /", ShellType::Posix, &empty_env());
        assert!(f.iter().any(|f| f.rule_id == RuleId::BlastWritesSystemPath));
    }

    #[test]
    fn cheap_check_sudo_rm_rf_home_blocks() {
        // C1: `sudo rm -rf /home` must NOT bypass the check — sudo is stripped,
        // wrapped `rm` matched.
        let f = cheap_check("sudo rm -rf /home", ShellType::Posix, &empty_env());
        assert!(
            f.iter().any(|f| f.rule_id == RuleId::BlastWritesSystemPath),
            "sudo rm -rf /home must fire BlastWritesSystemPath, got {:?}",
            f.iter().map(|f| f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn cheap_check_doas_rm_rf_root_blocks() {
        let f = cheap_check("doas rm -rf /", ShellType::Posix, &empty_env());
        assert!(f.iter().any(|f| f.rule_id == RuleId::BlastWritesSystemPath));
    }

    #[test]
    fn cheap_check_sudo_with_flags_and_assignment_unwraps() {
        // sudo flags (`-u root`), an env assignment, and `--` are all skipped.
        let f = cheap_check(
            "sudo -u root FOO=bar -- rm -rf /etc",
            ShellType::Posix,
            &empty_env(),
        );
        assert!(
            f.iter().any(|f| f.rule_id == RuleId::BlastWritesSystemPath),
            "wrapped rm under sudo flags must still fire"
        );
    }

    #[test]
    fn cheap_check_sudo_find_delete_unwraps() {
        let f = cheap_check("sudo find / -delete", ShellType::Posix, &empty_env());
        assert!(f.iter().any(|f| f.rule_id == RuleId::BlastFindDelete));
        assert!(f.iter().any(|f| f.rule_id == RuleId::BlastWritesSystemPath));
    }

    #[test]
    fn cheap_check_sudo_alone_is_silent() {
        // `sudo -v` has no wrapped command — must not panic or fire.
        let f = cheap_check("sudo -v", ShellType::Posix, &empty_env());
        assert!(f.is_empty());
    }

    #[test]
    fn cheap_check_chmod_skips_mode_operand() {
        // `0777` is the mode, `/etc` the target — mode not mistaken for target.
        let f = cheap_check("chmod -R 0777 /etc", ShellType::Posix, &empty_env());
        assert!(f.iter().any(|f| f.rule_id == RuleId::BlastWritesSystemPath));
    }

    #[test]
    fn cheap_check_non_recursive_chmod_does_not_fire() {
        // Spec scopes the chmod shape to `chmod -R`: non-recursive touches one
        // entry, not a tree, so it must not fire.
        let f = cheap_check("chmod 0644 /etc", ShellType::Posix, &empty_env());
        assert!(
            !f.iter().any(|f| f.rule_id == RuleId::BlastWritesSystemPath),
            "non-recursive chmod must not fire the system-path rule"
        );
    }

    #[test]
    fn simulate_counts_files_in_temp_tree() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("dist");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("a.txt"), b"hello").unwrap();
        fs::write(target.join("b.txt"), b"world!!").unwrap();
        fs::create_dir_all(target.join("nested")).unwrap();
        fs::write(target.join("nested/c.txt"), b"x").unwrap();

        let report = simulate(
            "rm -rf ./dist",
            ShellType::Posix,
            dir.path(),
            Some(dir.path()),
            &empty_env(),
        );
        assert_eq!(report.file_count, 3);
        assert!(report.dir_count >= 2); // dist + nested
        assert!(!report.paths_outside_repo, "./dist is inside the repo");
        assert!(!report.writes_system_path);
        // Largest file is b.txt (7 bytes).
        let (lp, ls) = report.largest_file.unwrap();
        assert_eq!(ls, 7);
        assert!(lp.ends_with("b.txt"));
    }

    #[test]
    fn simulate_counts_symlinks_without_following() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("d");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("real.txt"), b"data").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/hosts", target.join("link")).unwrap();
            let report = simulate(
                "rm -rf ./d",
                ShellType::Posix,
                dir.path(),
                Some(dir.path()),
                &empty_env(),
            );
            assert_eq!(report.symlink_count, 1);
            assert_eq!(
                report.file_count, 1,
                "symlink must not be followed/counted as a file"
            );
            let f = report_findings(&report);
            assert!(f.iter().any(|f| f.rule_id == RuleId::BlastSymlinkTraversal));
        }
    }

    #[test]
    fn simulate_detects_outside_repo() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let outside = dir.path().join("outside");
        fs::create_dir_all(&repo).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("f.txt"), b"x").unwrap();

        // cwd is the repo; target climbs out via `../outside`.
        let report = simulate(
            "rm -rf ../outside",
            ShellType::Posix,
            &repo,
            Some(&repo),
            &empty_env(),
        );
        assert!(
            report.paths_outside_repo,
            "../outside escapes the repo root"
        );
        let f = report_findings(&report);
        assert!(f
            .iter()
            .any(|f| f.rule_id == RuleId::BlastDeletesOutsideRepo));
    }

    #[test]
    fn simulate_large_file_count_info() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("many");
        fs::create_dir_all(&target).unwrap();
        for i in 0..1001 {
            fs::write(target.join(format!("f{i}.txt")), b"x").unwrap();
        }
        let report = simulate(
            "rm -rf ./many",
            ShellType::Posix,
            dir.path(),
            Some(dir.path()),
            &empty_env(),
        );
        assert!(report.file_count > LARGE_FILE_COUNT_THRESHOLD);
        let f = report_findings(&report);
        assert!(f.iter().any(|f| f.rule_id == RuleId::BlastLargeFileCount));
    }

    #[test]
    fn simulate_truncates_past_depth_cap() {
        // pr-test-analyzer #2: a tree deeper than MAX_WALK_DEPTH must set
        // walk_truncated (depth-cap DoS guard).
        let dir = tempfile::tempdir().unwrap();
        // dir/d0/.../d7 (8 levels > MAX_WALK_DEPTH=5), each with a file.
        let mut nested = dir.path().join("deep");
        fs::create_dir_all(&nested).unwrap();
        for i in 0..(MAX_WALK_DEPTH + 3) {
            nested = nested.join(format!("d{i}"));
            fs::create_dir_all(&nested).unwrap();
            fs::write(nested.join("f.txt"), b"x").unwrap();
        }
        let report = simulate(
            "rm -rf ./deep",
            ShellType::Posix,
            dir.path(),
            Some(dir.path()),
            &empty_env(),
        );
        assert!(
            report.walk_truncated,
            "a tree deeper than MAX_WALK_DEPTH must set walk_truncated"
        );
    }

    #[test]
    fn simulate_glob_expansion_counted() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.log"), b"x").unwrap();
        fs::write(dir.path().join("b.log"), b"x").unwrap();
        fs::write(dir.path().join("keep.txt"), b"x").unwrap();
        let report = simulate(
            "rm -f *.log",
            ShellType::Posix,
            dir.path(),
            Some(dir.path()),
            &empty_env(),
        );
        assert_eq!(report.glob_expansion_count, 2, "*.log matches two files");
        assert_eq!(report.file_count, 2);
    }

    #[test]
    fn simulate_empty_var_glob_is_system_and_outside() {
        let dir = tempfile::tempdir().unwrap();
        let report = simulate(
            "rm -rf \"$EMPTY/\"",
            ShellType::Posix,
            dir.path(),
            Some(dir.path()),
            &empty_env(),
        );
        assert!(report.unsafe_empty_var_glob);
        assert!(report.writes_system_path);
        assert!(report.paths_outside_repo);
        // We do NOT walk `/`.
        assert_eq!(report.file_count, 0);
    }

    #[cfg(unix)]
    #[test]
    fn simulate_flags_unreadable_subdir_as_walk_error() {
        // F3: a read_dir permission error on a subtree must increment walk_errors.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("tree");
        let locked = target.join("locked");
        fs::create_dir_all(&locked).unwrap();
        fs::write(target.join("visible.txt"), b"x").unwrap();
        fs::write(locked.join("hidden.txt"), b"secret").unwrap();
        // Remove read/exec on the subdir so its contents can't be enumerated.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

        let report = simulate(
            "rm -rf ./tree",
            ShellType::Posix,
            dir.path(),
            Some(dir.path()),
            &empty_env(),
        );

        // Restore perms so tempdir cleanup can remove the tree.
        let _ = fs::set_permissions(&locked, fs::Permissions::from_mode(0o755));

        assert!(
            report.walk_errors >= 1,
            "an unreadable subdir must increment walk_errors, got {}",
            report.walk_errors
        );
    }

    #[test]
    fn glob_match_basic() {
        assert!(glob_match("*.log", "a.log"));
        assert!(glob_match("*.log", "b.log"));
        assert!(!glob_match("*.log", "keep.txt"));
        assert!(glob_match("f?.txt", "f1.txt"));
        assert!(!glob_match("f?.txt", "f12.txt"));
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn empty_var_glob_var_recognizes_shapes() {
        let env = empty_env();
        // Absent from the (empty) env → Absent.
        assert_eq!(
            empty_var_glob_var("$EMPTY/", &env),
            Some(("EMPTY".to_string(), EmptyVarKind::Absent))
        );
        assert_eq!(
            empty_var_glob_var("${EMPTY}/", &env),
            Some(("EMPTY".to_string(), EmptyVarKind::Absent))
        );
        assert_eq!(
            empty_var_glob_var("$EMPTY", &env),
            Some(("EMPTY".to_string(), EmptyVarKind::Absent))
        );
        // A non-slash tail (`$EMPTY.bak`) is not a path-prefix shape.
        assert_eq!(empty_var_glob_var("$EMPTY.bak", &env), None);
        // `$EMPTYsuffix` is a distinct unset variable that also collapses → fires.
        assert_eq!(
            empty_var_glob_var("$EMPTYsuffix", &env),
            Some(("EMPTYsuffix".to_string(), EmptyVarKind::Absent))
        );
        // No `$` prefix.
        assert_eq!(empty_var_glob_var("dist/", &env), None);
    }

    #[test]
    fn empty_var_present_empty_is_high_absent_is_info() {
        // F2: PRESENT-and-empty → High; merely ABSENT (possible shell-local) → Info.
        let mut env = HashMap::new();
        env.insert("PRESENT_EMPTY".to_string(), String::new());
        assert_eq!(
            empty_var_glob_var("$PRESENT_EMPTY/", &env),
            Some(("PRESENT_EMPTY".to_string(), EmptyVarKind::PresentEmpty))
        );

        let f_present = cheap_check("rm -rf \"$PRESENT_EMPTY/\"", ShellType::Posix, &env);
        let present = f_present
            .iter()
            .find(|f| f.rule_id == RuleId::BlastEmptyVarGlob)
            .expect("present-empty var must fire");
        assert_eq!(
            present.severity,
            Severity::High,
            "a present-and-empty var collapses unambiguously → High"
        );

        let f_absent = cheap_check("rm -rf \"$ABSENT_SHELL_LOCAL/\"", ShellType::Posix, &env);
        let absent = f_absent
            .iter()
            .find(|f| f.rule_id == RuleId::BlastEmptyVarGlob)
            .expect("absent var still fires, but advisory");
        assert_eq!(
            absent.severity,
            Severity::Info,
            "an absent var might be a shell-local → Info, never Block"
        );
    }
}
