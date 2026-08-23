//! Blast-radius simulator (M10 ch1).
//!
//! Two surfaces, load-bearing split:
//!   * [`cheap_check`] — pure string-shape analysis (no fs access/glob/`stat`).
//!     Fires when a target is dangerous by shape alone (`/`, `/home`, `~`, or a
//!     `"$VAR/"` glob resolving to empty). The ONLY surface the `engine::analyze`
//!     exec/paste hot path may call; gated at tier-1 by `destructive_fs_op`.
//!   * [`simulate`] — full simulator: walks the fs (capped depth 5 / 100k charged
//!     traversal operations),
//!     expands globs, counts files/dirs/symlinks, decides repo / system-path
//!     escape. EXPENSIVE; runs ONLY under `tirith preview`, NEVER from the hot path.
//!
//! `$VAR` resolution: the empty-var-glob bug (`rm -rf "$EMPTY/"` → `rm -rf "/"`)
//! is detected against an injected variable map, not `std::env` inside the
//! detector, so tests avoid the libc `setenv` race (PR #125). Production callers
//! pass a `std::env::vars_os()` snapshot via [`env_snapshot`].

use crate::tokenize::{self, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Maximum directory-walk depth for [`simulate`].
pub const MAX_WALK_DEPTH: usize = 5;

/// Legacy public name for the preview work cap. Retained for callers and output
/// compatibility; the cap now bounds all traversal work, not only regular files.
pub const MAX_FILE_COUNT: usize = 100_000;

/// Maximum charged traversal operations for [`simulate`]. Every directory-entry
/// result, glob candidate, metadata attempt, classified file/directory/symlink,
/// and filesystem error consumes one unit from the same budget.
pub const MAX_WORK_COUNT: usize = MAX_FILE_COUNT;

/// File-count threshold above which [`RuleId::BlastLargeFileCount`] (Info) fires.
pub const LARGE_FILE_COUNT_THRESHOLD: u64 = 1000;

/// Result of a full filesystem simulation. Produced ONLY by [`simulate`] (i.e.
/// only under `tirith preview`).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BlastReport {
    /// Regular files within the resolved targets (bounded by [`MAX_WORK_COUNT`]).
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
    /// Walk hit [`MAX_WORK_COUNT`] / [`MAX_WALK_DEPTH`]; counts are lower bounds.
    pub walk_truncated: bool,
    /// The traversal stopped because its global operation budget was exhausted.
    /// `walk_truncated` remains set too for compatibility with existing clients.
    pub work_cap_reached: bool,
    /// The budget ran out with destructive targets still unclassified, so
    /// `paths_outside_repo` and the symlink signals are NOT a complete answer
    /// for this command — a later target could escape the repository without
    /// ever being examined.
    pub classification_incomplete: bool,
    /// Successfully charged traversal operations before completion or cutoff.
    pub work_units_used: u64,
    /// Operation limit applied to this report.
    pub work_limit: u64,
    /// Directories/entries the walk could NOT read (perms, I/O, symlink loop).
    /// When `> 0` a subtree was silently skipped, so counts are lower bounds and
    /// a `preview` must not present them as complete.
    pub walk_errors: u64,
}

#[derive(Debug)]
struct WorkBudget {
    limit: usize,
    used: usize,
}

impl WorkBudget {
    fn new(limit: usize) -> Self {
        Self { limit, used: 0 }
    }

    /// Charge one traversal operation. Failure marks the report incomplete and
    /// every caller must propagate it immediately instead of doing more work.
    fn consume(&mut self, report: &mut BlastReport) -> bool {
        if self.used >= self.limit {
            report.work_cap_reached = true;
            report.walk_truncated = true;
            return false;
        }
        self.used += 1;
        report.work_units_used = self.used as u64;
        true
    }
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
///
/// Non-UTF-8 keys/values are omitted. `std::env::vars()` panics on them
/// (MSRV 1.83), which would turn a host env byte into an analysis crash.
pub fn env_snapshot() -> HashMap<String, String> {
    std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .collect()
}

const MAX_NESTED_COMMAND_DEPTH: usize = 8;

fn collect_executable_segments(
    input: &str,
    shell: ShellType,
    depth: usize,
    out: &mut Vec<(tokenize::Segment, ShellType)>,
) -> bool {
    let execution_view = crate::extract::shell_execution_view(input, shell);
    out.extend(
        tokenize::tokenize(execution_view.as_ref(), shell)
            .into_iter()
            .map(|segment| (segment, shell)),
    );
    let nested_scan = crate::extract::executable_substitution_scan(input, shell);
    let mut incomplete = nested_scan.gap.is_some();
    let nested = nested_scan.bodies;
    if nested.is_empty() {
        return incomplete;
    }
    if depth >= MAX_NESTED_COMMAND_DEPTH {
        return true;
    }
    for body in nested {
        // Do not use `Iterator::any`: traversing every sibling is required to
        // collect all executable segments even after an earlier depth gap.
        incomplete |= collect_executable_segments(&body.input, body.shell, depth + 1, out);
    }
    incomplete
}

fn executable_segments(
    input: &str,
    shell: ShellType,
) -> (Vec<(tokenize::Segment, ShellType)>, bool) {
    let mut segments = Vec::new();
    let incomplete = collect_executable_segments(input, shell, 0, &mut segments);
    (segments, incomplete)
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
    let (segments, nested_incomplete) = executable_segments(input, shell);

    if nested_incomplete {
        findings.push(finding(
            RuleId::AnalysisIncomplete,
            Severity::High,
            "nested command analysis was incomplete",
            "A destructive command may be hidden beyond Tirith's bounded nested-shell depth, \
             lexical-candidate, input, or retained-body budget.",
            Evidence::CommandPattern {
                pattern: "nested shell execution coverage gap".to_string(),
                matched: "nested body suffix omitted by bounded analysis".to_string(),
            },
        ));
    }

    for (seg, segment_shell) in &segments {
        let parsed = match parse_fs_op(seg, *segment_shell) {
            Ok(Some(parsed)) => parsed,
            Ok(None) => continue,
            Err(crate::rules::command::EffectiveCommandError::WorkBudgetExceeded) => {
                findings.push(finding(
                    RuleId::AnalysisIncomplete,
                    Severity::High,
                    "destructive command analysis exceeded its work budget",
                    "The command exceeded Tirith's bounded token-normalization budget. A \
                     destructive operation may remain in the omitted suffix, so it is blocked \
                     instead of being treated as absent.",
                    Evidence::CommandPattern {
                        pattern: "destructive command work budget exhausted".to_string(),
                        matched: "input or token suffix omitted before command normalization"
                            .to_string(),
                    },
                ));
                continue;
            }
            Err(_) => {
                if segment_has_destructive_marker(seg, *segment_shell) {
                    findings.push(finding(
                        RuleId::AnalysisIncomplete,
                        Severity::High,
                        "could not resolve destructive command wrapper",
                        "The command contains a destructive filesystem operation behind an \
                         ambiguous or over-deep wrapper chain. Tirith refuses to treat the \
                         outer wrapper as benign.",
                        Evidence::CommandPattern {
                            pattern: "unresolved destructive wrapper".to_string(),
                            matched: seg.raw.clone(),
                        },
                    ));
                }
                continue;
            }
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

            let resolved_target = match expand_known_path(target, env_map) {
                Ok(target) => target,
                // An absent variable is the same ambiguity `EmptyVarKind::Absent`
                // already treats as advisory: tirith cannot see a non-exported
                // shell-local, so `rm -rf build/$TARGET` must not block harder
                // than `rm -rf "$TARGET/"`, which is the more dangerous shape.
                // Anything tirith genuinely cannot model — an operator, a
                // command substitution, `~user`, a malformed reference — still
                // blocks.
                Err(ExpansionFailure::MissingVariable(name)) => {
                    findings.push(finding(
                        RuleId::AnalysisIncomplete,
                        Severity::Info,
                        "destructive target references a variable tirith cannot see",
                        &format!(
                            "The destructive target '{target}' references `${name}`, which is \
                             NOT set in tirith's environment. If it is also unset in your \
                             shell the target is not what it looks like; if it is a \
                             non-exported shell-local that IS set, this is harmless — tirith \
                             cannot see shell-locals, so this is advisory only. Run \
                             `tirith preview` in the same shell to resolve it."
                        ),
                        Evidence::Text {
                            detail: format!("unresolved destructive target '{target}'"),
                        },
                    ));
                    continue;
                }
                Err(ExpansionFailure::Unsupported) => {
                    findings.push(finding(
                        RuleId::AnalysisIncomplete,
                        Severity::High,
                        "destructive target expansion could not be resolved",
                        "A destructive filesystem target contains a shell expansion Tirith \
                         cannot resolve from the injected environment. It is blocked instead \
                         of being classified from the benign-looking raw operand.",
                        Evidence::Text {
                            detail: format!("unresolved destructive target '{target}'"),
                        },
                    ));
                    continue;
                }
            };
            if is_system_path(&resolved_target, env_map.get("HOME").map(String::as_str)) {
                findings.push(finding(
                    RuleId::BlastWritesSystemPath,
                    Severity::High,
                    "destructive command targets a system path",
                    "This destructive command targets a broad system path (root, a home \
                     tree, or a system directory). Even when intentional this routinely \
                     breaks the OS or removes other users' data. Run `tirith preview` to \
                     see the exact impact first.",
                    Evidence::Text {
                        detail: format!(
                            "target '{target}' resolves to system path '{resolved_target}'"
                        ),
                    },
                ));
            }
        }
    }

    dedup_findings(findings)
}

/// Full filesystem simulation for `tirith preview`: walks cwd-relative targets
/// (capped at [`MAX_WALK_DEPTH`] / [`MAX_WORK_COUNT`]), expands globs, counts
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
    simulate_with_work_limit(input, shell, cwd, repo_root, env_map, MAX_WORK_COUNT)
}

fn simulate_with_work_limit(
    input: &str,
    shell: ShellType,
    cwd: &Path,
    repo_root: Option<&Path>,
    env_map: &HashMap<String, String>,
    work_limit: usize,
) -> BlastReport {
    let mut report = BlastReport {
        work_limit: work_limit as u64,
        ..BlastReport::default()
    };
    let mut budget = WorkBudget::new(work_limit);
    let (segments, nested_incomplete) = executable_segments(input, shell);
    if nested_incomplete {
        report.walk_errors += 1;
        report.walk_truncated = true;
        report.classification_incomplete = true;
    }

    for (seg, segment_shell) in &segments {
        let parsed = match parse_fs_op(seg, *segment_shell) {
            Ok(Some(parsed)) => parsed,
            Ok(None) => continue,
            Err(crate::rules::command::EffectiveCommandError::WorkBudgetExceeded) => {
                report.walk_errors += 1;
                report.walk_truncated = true;
                report.classification_incomplete = true;
                continue;
            }
            Err(_) => {
                if segment_has_destructive_marker(seg, *segment_shell) {
                    report.walk_errors += 1;
                    report.walk_truncated = true;
                }
                continue;
            }
        };
        for target in &parsed.targets {
            // Empty-var glob collapses to root — record and skip the walk (no `/`).
            if empty_var_glob_var(target, env_map).is_some() {
                report.unsafe_empty_var_glob = true;
                report.paths_outside_repo = true;
                report.writes_system_path = true;
                continue;
            }

            let resolved_target = match expand_known_path(target, env_map) {
                Ok(target) => target,
                Err(_) => {
                    report.walk_errors += 1;
                    report.walk_truncated = true;
                    continue;
                }
            };

            if is_system_path_for_preview(
                &resolved_target,
                cwd,
                env_map.get("HOME").map(String::as_str),
            ) {
                report.writes_system_path = true;
            }

            // Expand the target (glob against cwd, else literal) to concrete
            // paths. A spent budget yields no expansion, but the target still
            // needs the free lexical containment check below, and so do the
            // targets after it.
            let expanded = expand_target(&resolved_target, cwd, &mut report, &mut budget)
                .unwrap_or_else(|| {
                    report.classification_incomplete = true;
                    vec![resolve_relative(&resolved_target, cwd)]
                });

            for path in expanded {
                // Classify BEFORE walking. `walk_into` stops on an exhausted
                // budget, and a dropped repo-escape signal turns a Block into an
                // Allow. Both budget helpers charge before touching the disk, so
                // continuing past a refusal does no further filesystem work.
                if path_escapes_repo(&path, cwd, repo_root) {
                    report.paths_outside_repo = true;
                }
                if !walk_into(&path, &mut report, &mut budget) {
                    report.classification_incomplete = true;
                }
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

    if report.classification_incomplete {
        findings.push(finding(
            RuleId::AnalysisIncomplete,
            Severity::High,
            "destructive target classification stopped at the work budget",
            "The traversal budget ran out while destructive targets were still \
             unclassified, so \"outside repo\" and the symlink signals describe only \
             the part that was examined. A remaining target could reach outside the \
             repository without appearing here, so this is reported instead of being \
             presented as a complete result.",
            Evidence::Text {
                detail: format!(
                    "traversal stopped after {} of {} work units with targets unclassified",
                    report.work_units_used, report.work_limit
                ),
            },
        ));
    }

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
fn parse_fs_op(
    seg: &tokenize::Segment,
    shell: ShellType,
) -> Result<Option<ParsedFsOp>, crate::rules::command::EffectiveCommandError> {
    let effective = crate::rules::command::resolve_effective_segment(seg, shell)?;
    let Some(leader) = effective.command.as_deref() else {
        return Ok(None);
    };
    let leader = crate::rules::command::normalize_cmd_base(leader, shell);
    Ok(parse_op_for_leader(&leader, &effective.args))
}

fn segment_has_destructive_marker(seg: &tokenize::Segment, shell: ShellType) -> bool {
    tokenize::split_words(&crate::rules::command::normalize_shell_token(
        &seg.raw, shell,
    ))
    .iter()
    .any(|word| {
        matches!(
            crate::rules::command::normalize_cmd_base(word, shell).as_str(),
            "rm" | "mv" | "chmod" | "find" | "rsync"
        )
    })
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

/// Parse `rm` / `mv` / `chmod`: collect non-flag operands, note recursion. For
/// `chmod` the first non-flag operand is the mode and is dropped from targets.
fn parse_simple(op: FsOp, args: &[String]) -> ParsedFsOp {
    let mut recursive = false;
    let mut targets = Vec::new();
    let mut after_double_dash = false;
    let mut seen_mode = false;

    let mut idx = 0;
    while idx < args.len() {
        let a = strip_outer_quotes(&args[idx]);
        if after_double_dash {
            targets.push(a.to_string());
            idx += 1;
            continue;
        }
        if a == "--" {
            after_double_dash = true;
            idx += 1;
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            if is_recursive_flag(a) {
                recursive = true;
            }
            if op == FsOp::Chmod && a == "--reference" {
                // The consumed reference replaces MODE; the following positional
                // is therefore already a target.
                seen_mode = true;
                idx += 2;
                continue;
            }
            if op == FsOp::Chmod && a.starts_with("--reference=") {
                seen_mode = true;
                idx += 1;
                continue;
            }
            if op == FsOp::Mv && matches!(a, "-t" | "--target-directory") {
                if let Some(directory) = args.get(idx + 1) {
                    targets.push(strip_outer_quotes(directory).to_string());
                }
                idx += 2;
                continue;
            }
            if op == FsOp::Mv {
                if let Some(directory) = a.strip_prefix("--target-directory=") {
                    targets.push(directory.to_string());
                    idx += 1;
                    continue;
                }
                if let Some(directory) = a.strip_prefix("-t").filter(|value| !value.is_empty()) {
                    // GNU short options may carry their required value in the
                    // same argv token (`mv -t/etc payload`). The destination is
                    // still a destructive target and must not disappear merely
                    // because the spelling is attached.
                    targets.push(directory.to_string());
                    idx += 1;
                    continue;
                }
                if matches!(a, "-S" | "--suffix") {
                    idx += 2;
                    continue;
                }
            }
            idx += 1;
            continue;
        }
        if op == FsOp::Chmod && !seen_mode {
            // First positional chmod arg is the mode, not a target.
            seen_mode = true;
            idx += 1;
            continue;
        }
        targets.push(a.to_string());
        idx += 1;
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
    let mut idx = 0;
    // GNU/POSIX find traversal options precede the path operands.
    while idx < stripped.len() {
        match stripped[idx] {
            "-H" | "-L" | "-P" => idx += 1,
            "-D" => idx += 2,
            option if option.starts_with("-O") => idx += 1,
            _ => break,
        }
    }
    while idx < stripped.len() {
        let arg = stripped[idx];
        if arg.starts_with('-') || matches!(arg, "!" | "(" | ")") {
            break;
        }
        targets.push(arg.to_string());
        idx += 1;
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

/// Expand only deterministic shell path forms: `~`/`~/...` and bare `$NAME` /
/// `${NAME}` references supplied by the injected environment. Shell operators,
/// command substitutions, and unknown variables are unresolved rather than
/// compared as harmless literal text.
/// Why a deterministic expansion could not be performed. The distinction
/// matters for severity: an absent variable may simply be a non-exported
/// shell-local tirith cannot see (the same reasoning `EmptyVarKind::Absent`
/// already applies), while a shell operator, command substitution, or malformed
/// brace is something tirith genuinely cannot model.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ExpansionFailure {
    /// `$NAME` / `${NAME}` naming a variable absent from the injected
    /// environment.
    MissingVariable(String),
    /// `~user`, a parameter-expansion operator, a command substitution, or a
    /// malformed reference.
    Unsupported,
}

fn expand_known_path(
    target: &str,
    env_map: &HashMap<String, String>,
) -> Result<String, ExpansionFailure> {
    let target = target.trim();
    let mut source = target.to_string();
    if source == "~" || source.starts_with("~/") {
        let home = env_map
            .get("HOME")
            .ok_or_else(|| ExpansionFailure::MissingVariable("HOME".to_string()))?;
        source = if source == "~" {
            home.clone()
        } else {
            format!("{}/{}", home.trim_end_matches('/'), &source[2..])
        };
    } else if source.starts_with('~') {
        // `~user` requires passwd-database lookup and is intentionally unresolved.
        return Err(ExpansionFailure::Unsupported);
    }

    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut idx = 0;
    while idx < chars.len() {
        if chars[idx] != '$' {
            out.push(chars[idx]);
            idx += 1;
            continue;
        }
        idx += 1;
        let name = if idx < chars.len() && chars[idx] == '{' {
            idx += 1;
            let start = idx;
            while idx < chars.len() && (chars[idx].is_ascii_alphanumeric() || chars[idx] == '_') {
                idx += 1;
            }
            if idx == start || idx >= chars.len() || chars[idx] != '}' {
                return Err(ExpansionFailure::Unsupported);
            }
            let name: String = chars[start..idx].iter().collect();
            idx += 1;
            name
        } else {
            let start = idx;
            while idx < chars.len() && (chars[idx].is_ascii_alphanumeric() || chars[idx] == '_') {
                idx += 1;
            }
            if idx == start {
                return Err(ExpansionFailure::Unsupported);
            }
            chars[start..idx].iter().collect()
        };
        out.push_str(
            env_map
                .get(&name)
                .ok_or_else(|| ExpansionFailure::MissingVariable(name.clone()))?,
        );
    }
    Ok(out)
}

/// Lexically normalize a POSIX (`/`-separated) path as a string, resolving `.`
/// and `..` without touching the filesystem and WITHOUT `std::path::Path` (whose
/// separator, root, and absoluteness rules are host-defined — on Windows they
/// rewrite `/etc` to `\etc` and treat it as relative, which silently defeated
/// every system-path finding). A leading `/` is preserved; `..` cannot rise
/// above root; the result has no trailing slash except bare root, which stays
/// `/`.
fn posix_lexical(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    format!("/{}", out.join("/"))
}

/// The POSIX parent of a `/`-rooted path: everything up to the last `/`, or `/`
/// when the path has a single component. String-only, host-independent.
fn posix_parent(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(index) => &path[..index],
    }
}

fn is_protected_root(path: &str) -> bool {
    matches!(
        path.trim_end_matches('/'),
        "" | "/home"
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
    )
}

/// Classify exact broad roots, the injected HOME, lexical aliases of either,
/// and wildcard patterns rooted in those protected trees.
fn is_system_path(path: &str, home: Option<&str>) -> bool {
    // The cheap path has no cwd, so it cannot safely classify a relative
    // operand as a system path. Joining relative paths onto `/` made ordinary
    // cleanup targets such as `.`, `*.log`, and `foo*` look like the filesystem
    // root. Deterministic `~`/environment expansion happens before this helper,
    // so protected paths reached through those forms are absolute here and
    // remain covered; cwd-relative operands are left to `tirith preview`.
    //
    // Absoluteness is POSIX-defined ("starts with `/`"), NOT host-defined: this
    // analyzes shell commands whose targets are POSIX paths regardless of the
    // OS tirith runs on, and the protected-root set below is entirely
    // `/`-rooted. `Path::is_absolute()` is host-dependent (it rejects `/etc` on
    // Windows because there is no drive letter), which silently disabled every
    // system-path finding on Windows.
    if !path.starts_with('/') {
        return false;
    }

    // POSIX-string classification only — never `std::path::Path`, whose
    // host-defined semantics rewrite these `/`-rooted operands on Windows.
    let first_glob = path.find(['*', '?', '[']);
    let candidate = if let Some(index) = first_glob {
        let prefix = &path[..index];
        let directory = if prefix.ends_with('/') {
            let trimmed = prefix.trim_end_matches('/');
            if trimmed.is_empty() {
                "/"
            } else {
                trimmed
            }
        } else {
            posix_parent(prefix)
        };
        posix_lexical(directory)
    } else {
        posix_lexical(path)
    };
    if is_protected_root(&candidate) {
        return true;
    }
    home.is_some_and(|home| {
        let home = posix_lexical(home);
        candidate == home
            || (first_glob.is_some()
                && (candidate == home
                    || candidate.starts_with(&format!("{}/", home.trim_end_matches('/')))))
    })
}

/// Preview has an explicit cwd, so it can safely classify relative operands and
/// wildcard patterns after resolving them against that cwd. The hot-path helper
/// above deliberately cannot do this because it has no trustworthy cwd input.
fn is_system_path_for_preview(path: &str, cwd: &Path, home: Option<&str>) -> bool {
    // Resolve in POSIX-string space, never through `std::path::Path`: on Windows
    // `PathBuf::join`/`is_absolute` rewrite these `/`-rooted operands with `\`
    // and drop the leading `/`, so the resolved string failed `is_system_path`'s
    // `starts_with('/')` gate and every preview classification went dark. The
    // classification is POSIX-only by contract (its protected-root set is
    // `/`-rooted), so resolve the same way.
    let cwd = cwd.to_string_lossy();
    let resolved = if let Some(rest) = path.strip_prefix("~/") {
        match std::env::var("HOME") {
            Ok(home) => format!("{}/{rest}", home.trim_end_matches('/')),
            Err(_) => path.to_string(),
        }
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("{}/{path}", cwd.trim_end_matches('/'))
    };
    is_system_path(&resolved, home)
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
fn expand_target(
    target: &str,
    cwd: &Path,
    report: &mut BlastReport,
    budget: &mut WorkBudget,
) -> Option<Vec<PathBuf>> {
    if target_is_glob(target) {
        glob_in_cwd(target, cwd, report, budget)
    } else {
        Some(vec![resolve_relative(target, cwd)])
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

/// Bounded component-by-component shell glob expansion. Every directory open,
/// entry result, and candidate classification is charged to the shared work
/// budget, so wildcard directory components cannot grow work outside the preview
/// cap. `**` is intentionally treated as a single-level `*` (no recursive glob).
fn glob_in_cwd(
    pattern: &str,
    cwd: &Path,
    report: &mut BlastReport,
    budget: &mut WorkBudget,
) -> Option<Vec<PathBuf>> {
    let mut candidates = vec![if pattern.starts_with('/') {
        PathBuf::from("/")
    } else {
        cwd.to_path_buf()
    }];
    let components: Vec<&str> = pattern.split('/').filter(|part| !part.is_empty()).collect();

    for (component_index, component) in components.iter().enumerate() {
        let component = *component;
        if !target_is_glob(component) {
            for candidate in &mut candidates {
                candidate.push(component);
            }
            continue;
        }

        let mut next = Vec::new();
        for directory in &candidates {
            if !budget.consume(report) {
                return None;
            }
            match std::fs::read_dir(directory) {
                Ok(entries) => {
                    for entry in entries {
                        if !budget.consume(report) {
                            return None;
                        }
                        match entry {
                            Ok(entry) => {
                                if !budget.consume(report) {
                                    return None;
                                }
                                let name = entry.file_name();
                                let name = name.to_string_lossy();
                                if name.starts_with('.') && !component.starts_with('.') {
                                    continue;
                                }
                                if glob_match(component, &name) {
                                    // A match used as an intermediate path
                                    // component must be traversable as a
                                    // directory. Shell globbing silently drops
                                    // ordinary files here; treating their later
                                    // `read_dir(NotADirectory)` as an analysis
                                    // error made normal mixed directories look
                                    // incomplete. The existing candidate-
                                    // classification budget charge above also
                                    // bounds this metadata lookup.
                                    if component_index + 1 < components.len() {
                                        match std::fs::metadata(entry.path()) {
                                            Ok(metadata) if metadata.is_dir() => {}
                                            Ok(_) => continue,
                                            Err(error)
                                                if error.kind() == std::io::ErrorKind::NotFound =>
                                            {
                                                continue;
                                            }
                                            Err(_) => {
                                                if !budget.consume(report) {
                                                    return None;
                                                }
                                                report.walk_errors += 1;
                                                continue;
                                            }
                                        }
                                    }
                                    next.push(entry.path());
                                }
                            }
                            Err(_) => {
                                if !budget.consume(report) {
                                    return None;
                                }
                                report.walk_errors += 1;
                            }
                        }
                    }
                }
                Err(_) => {
                    if !budget.consume(report) {
                        return None;
                    }
                    report.walk_errors += 1;
                }
            }
        }
        candidates = next;
        if candidates.is_empty() {
            break;
        }
    }

    report.glob_expansion_count = report
        .glob_expansion_count
        .saturating_add(candidates.len() as u64);
    Some(candidates)
}

/// Component glob matcher supporting `*`, `?`, bracket sets/ranges, and bracket
/// negation (`[!x]`/`[^x]`). Memoization bounds adversarial backtracking.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let mut memo = vec![vec![None; t.len() + 1]; p.len() + 1];

    fn matches_from(
        p: &[char],
        t: &[char],
        pi: usize,
        ti: usize,
        memo: &mut [Vec<Option<bool>>],
    ) -> bool {
        if let Some(result) = memo[pi][ti] {
            return result;
        }
        let result = if pi == p.len() {
            ti == t.len()
        } else {
            match p[pi] {
                '*' => {
                    matches_from(p, t, pi + 1, ti, memo)
                        || (ti < t.len() && matches_from(p, t, pi, ti + 1, memo))
                }
                '?' => ti < t.len() && matches_from(p, t, pi + 1, ti + 1, memo),
                '[' => {
                    let mut end = pi + 1;
                    while end < p.len() && p[end] != ']' {
                        end += 1;
                    }
                    if end == p.len() {
                        ti < t.len() && p[pi] == t[ti] && matches_from(p, t, pi + 1, ti + 1, memo)
                    } else if ti >= t.len() {
                        false
                    } else {
                        let mut cursor = pi + 1;
                        let negated = cursor < end && matches!(p[cursor], '!' | '^');
                        if negated {
                            cursor += 1;
                        }
                        let mut class_match = false;
                        while cursor < end {
                            if cursor + 2 < end && p[cursor + 1] == '-' {
                                class_match |= p[cursor] <= t[ti] && t[ti] <= p[cursor + 2];
                                cursor += 3;
                            } else {
                                class_match |= p[cursor] == t[ti];
                                cursor += 1;
                            }
                        }
                        (class_match != negated) && matches_from(p, t, end + 1, ti + 1, memo)
                    }
                }
                literal => {
                    ti < t.len() && literal == t[ti] && matches_from(p, t, pi + 1, ti + 1, memo)
                }
            }
        };
        memo[pi][ti] = Some(result);
        result
    }

    matches_from(&p, &t, 0, 0, &mut memo)
}

/// Decide whether `path` escapes the repo: with a `repo_root`, not under the
/// canonicalized root; without one, any absolute path or climb above `cwd`.
///
/// The lexical answer is only trusted when NO existing component of the path
/// is a symlink (repo-0409): for `repo/link/file` where `link` is a repository
/// symlink to an outside directory, the filesystem follows the intermediate
/// symlink while the lexical check still sees containment. In that case the
/// canonical target (or, for a not-yet-existing tail, its canonical deepest
/// existing ancestor with the tail re-appended) is compared against the
/// canonical containment root; anything unresolvable is conservatively an
/// escape.
fn path_escapes_repo(path: &Path, cwd: &Path, repo_root: Option<&Path>) -> bool {
    let resolved = canonicalize_lexical(path, cwd);
    let lexical_root = repo_root.map(|r| canonicalize_lexical(r, cwd));
    let lexical_escape = match &lexical_root {
        Some(root) => !resolved.starts_with(root),
        None => !resolved.starts_with(canonicalize_lexical(cwd, cwd)),
    };
    if lexical_escape {
        return true;
    }
    if !has_symlink_component(&resolved) {
        return false;
    }
    let root_basis = lexical_root.unwrap_or_else(|| canonicalize_lexical(cwd, cwd));
    let canon_root = canonicalize_or_deepest(&root_basis);
    let canon_target = canonicalize_or_deepest(&resolved);
    match (canon_target, canon_root) {
        (Some(target), Some(root)) => !target.starts_with(root),
        // Cannot prove containment through a symlinked path: fail safe.
        _ => true,
    }
}

/// True when ANY existing component of `path` (an absolute, lexically
/// normalized path) is a symlink — including the final component. Stops at the
/// first missing prefix (nothing deeper can exist).
fn has_symlink_component(path: &Path) -> bool {
    let mut prefix = std::path::PathBuf::new();
    for comp in path.components() {
        prefix.push(comp.as_os_str());
        match std::fs::symlink_metadata(&prefix) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return true;
                }
            }
            Err(_) => return false,
        }
    }
    false
}

/// Canonicalize `path` when it exists; otherwise canonicalize its deepest
/// existing ancestor and re-append the (nonexistent) tail components, so a
/// not-yet-created target beneath a symlinked directory still resolves to its
/// real destination. `None` when no ancestor can be canonicalized.
fn canonicalize_or_deepest(path: &Path) -> Option<std::path::PathBuf> {
    let mut missing: Vec<&std::ffi::OsStr> = Vec::new();
    let mut cursor = path;
    loop {
        if cursor.as_os_str().is_empty() {
            return None;
        }
        match std::fs::canonicalize(cursor) {
            Ok(mut canon) => {
                for tail in missing.iter().rev() {
                    canon.push(tail);
                }
                return Some(canon);
            }
            Err(_) => {
                missing.push(cursor.file_name()?);
                cursor = cursor.parent()?;
            }
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

/// Walk `path` into the report, honoring the depth/work caps. Symlinks are
/// counted, never followed.
fn walk_into(path: &Path, report: &mut BlastReport, budget: &mut WorkBudget) -> bool {
    if !budget.consume(report) {
        return false;
    }
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            if !budget.consume(report) {
                return false;
            }
            // NotFound is normal (nothing to count); any other error means we
            // under-counted, so flag it.
            if e.kind() != std::io::ErrorKind::NotFound {
                report.walk_errors += 1;
            }
            return true;
        }
    };

    if meta.file_type().is_symlink() {
        if !budget.consume(report) {
            return false;
        }
        report.symlink_count += 1;
        return true;
    }
    if meta.is_file() {
        if !budget.consume(report) {
            return false;
        }
        count_file(path, meta.len(), report);
        return true;
    }
    if meta.is_dir() {
        if !budget.consume(report) {
            return false;
        }
        report.dir_count += 1;
        return walk_dir(path, 1, report, budget);
    }
    true
}

fn walk_dir(dir: &Path, depth: usize, report: &mut BlastReport, budget: &mut WorkBudget) -> bool {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => {
            if !budget.consume(report) {
                return false;
            }
            // Unreadable dir (perms/I/O): its subtree is silently uncounted.
            // Record it so the report does not present a partial walk as complete (F3).
            report.walk_errors += 1;
            return true;
        }
    };
    for entry in entries {
        if !budget.consume(report) {
            return false;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                if !budget.consume(report) {
                    return false;
                }
                report.walk_errors += 1;
                continue;
            }
        };
        let path = entry.path();
        if !budget.consume(report) {
            return false;
        }
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => {
                if !budget.consume(report) {
                    return false;
                }
                report.walk_errors += 1;
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            if !budget.consume(report) {
                return false;
            }
            report.symlink_count += 1;
            continue; // never follow
        }
        if meta.is_dir() {
            if !budget.consume(report) {
                return false;
            }
            report.dir_count += 1;
            if depth < MAX_WALK_DEPTH {
                if !walk_dir(&path, depth + 1, report, budget) {
                    return false;
                }
            } else {
                report.walk_truncated = true;
            }
        } else if meta.is_file() {
            if !budget.consume(report) {
                return false;
            }
            count_file(&path, meta.len(), report);
        }
    }
    true
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

/// Keep one ordinary blast finding per rule, while dropping only exact
/// `AnalysisIncomplete` duplicates. Distinct unresolved destructive targets
/// can share that rule ID but carry different evidence; collapsing them would
/// hide an independent failure boundary.
fn dedup_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen_rules = std::collections::HashSet::new();
    let mut seen_incomplete = std::collections::HashSet::new();
    findings
        .into_iter()
        .filter(|finding| {
            if finding.rule_id != RuleId::AnalysisIncomplete {
                return seen_rules.insert(finding.rule_id);
            }
            let evidence = serde_json::to_string(&finding.evidence)
                .unwrap_or_else(|_| format!("{:?}", finding.evidence));
            seen_incomplete.insert((
                finding.severity,
                finding.title.clone(),
                finding.description.clone(),
                evidence,
            ))
        })
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
    fn dedup_preserves_distinct_incomplete_boundaries() {
        let first = finding(
            RuleId::AnalysisIncomplete,
            Severity::High,
            "first unresolved boundary",
            "first description",
            Evidence::Text {
                detail: "first evidence".to_string(),
            },
        );
        let second = finding(
            RuleId::AnalysisIncomplete,
            Severity::High,
            "second unresolved boundary",
            "second description",
            Evidence::Text {
                detail: "second evidence".to_string(),
            },
        );
        let deduped = dedup_findings(vec![first.clone(), first, second]);
        assert_eq!(deduped.len(), 2);
    }

    fn simulate_with_tiny_budget(input: &str, cwd: &Path, work_limit: usize) -> BlastReport {
        simulate_with_work_limit(
            input,
            ShellType::Posix,
            cwd,
            Some(cwd),
            &empty_env(),
            work_limit,
        )
    }

    #[test]
    fn work_budget_caps_directory_only_trees_and_keeps_dir_counts_honest() {
        let root = tempfile::tempdir().unwrap();
        let tree = root.path().join("tree");
        fs::create_dir_all(tree.join("a")).unwrap();
        fs::create_dir_all(tree.join("b")).unwrap();

        let report = simulate_with_tiny_budget("rm -rf ./tree", root.path(), 4);

        assert!(report.work_cap_reached);
        assert!(
            report.walk_truncated,
            "legacy incomplete marker must remain set"
        );
        assert_eq!(report.work_units_used, 4);
        assert_eq!(report.work_limit, 4);
        assert_eq!(
            report.dir_count, 1,
            "an uncharged directory must not be counted"
        );
        assert_eq!(report.file_count, 0);
        assert_eq!(report.symlink_count, 0);
    }

    #[cfg(unix)]
    #[test]
    fn work_budget_caps_symlink_only_trees_and_exact_budget_is_complete() {
        let root = tempfile::tempdir().unwrap();
        let tree = root.path().join("tree");
        fs::create_dir_all(&tree).unwrap();
        std::os::unix::fs::symlink("missing-target", tree.join("link")).unwrap();

        let capped = simulate_with_tiny_budget("rm -rf ./tree", root.path(), 4);
        assert!(capped.work_cap_reached);
        assert_eq!(capped.work_units_used, 4);
        assert_eq!(
            capped.symlink_count, 0,
            "uncharged symlink must not be counted"
        );

        let complete = simulate_with_tiny_budget("rm -rf ./tree", root.path(), 5);
        assert!(!complete.work_cap_reached);
        assert!(!complete.walk_truncated);
        assert_eq!(complete.work_units_used, 5);
        assert_eq!(complete.dir_count, 1);
        assert_eq!(complete.symlink_count, 1);
    }

    #[test]
    fn nonmatching_glob_candidates_consume_the_global_work_budget() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("a.txt"), b"x").unwrap();
        fs::write(root.path().join("b.txt"), b"x").unwrap();

        let report = simulate_with_tiny_budget("rm -f *.log", root.path(), 4);

        assert!(report.work_cap_reached);
        assert_eq!(report.work_units_used, 4);
        assert_eq!(report.glob_expansion_count, 0);
        assert_eq!(report.file_count, 0);
    }

    #[cfg(unix)]
    #[test]
    fn intermediate_symlink_component_counts_as_repo_escape() {
        // repo-0409: `repo/link/file` where `link` is a repository symlink to
        // an outside directory must be an escape — the filesystem follows the
        // intermediate symlink even though the lexical path looks contained.
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        let outside = root.path().join("outside");
        fs::create_dir_all(&repo).unwrap();
        fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, repo.join("link")).unwrap();

        // Existing target through the symlink.
        assert!(path_escapes_repo(
            &repo.join("link").join("file"),
            &repo,
            Some(&repo),
        ));
        // Not-yet-existing target beneath the symlinked directory.
        assert!(path_escapes_repo(
            &repo.join("link").join("newfile"),
            &repo,
            Some(&repo),
        ));
        // A genuinely contained path stays contained.
        fs::create_dir_all(repo.join("sub")).unwrap();
        assert!(!path_escapes_repo(
            &repo.join("sub").join("file"),
            &repo,
            Some(&repo),
        ));
    }

    #[cfg(unix)]
    #[test]
    fn in_repo_symlink_pointing_inside_repo_is_not_an_escape() {
        // A symlink whose target remains inside the repo is not an escape —
        // canonical resolution proves containment instead of flagging every
        // symlink indiscriminately.
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        fs::create_dir_all(repo.join("real")).unwrap();
        std::os::unix::fs::symlink(repo.join("real"), repo.join("alias")).unwrap();
        assert!(!path_escapes_repo(
            &repo.join("alias").join("file"),
            &repo,
            Some(&repo),
        ));
    }

    #[test]
    fn matching_glob_growth_and_followup_walk_share_one_budget() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("a.log"), b"x").unwrap();
        fs::write(root.path().join("b.log"), b"x").unwrap();

        let report = simulate_with_tiny_budget("rm -f *.log", root.path(), 7);

        assert!(report.work_cap_reached);
        assert_eq!(report.work_units_used, 7);
        assert_eq!(report.glob_expansion_count, 2);
        assert_eq!(
            report.file_count, 1,
            "only the fully charged match is counted"
        );
    }

    #[test]
    fn glob_errors_are_not_flattened_and_consume_budget_before_later_targets() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("later.txt"), b"x").unwrap();

        let report = simulate_with_tiny_budget("rm -f ./missing/*.log ./later.txt", root.path(), 2);

        assert!(report.work_cap_reached);
        assert_eq!(report.work_units_used, 2);
        assert_eq!(report.walk_errors, 1);
        assert_eq!(
            report.file_count, 0,
            "work must stop before the later target"
        );
    }

    #[test]
    fn max_file_count_remains_the_compatible_default_work_limit() {
        assert_eq!(MAX_WORK_COUNT, MAX_FILE_COUNT);
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
    fn cheap_check_relative_roots_and_globs_are_left_to_preview() {
        for input in ["rm -rf .", "rm -f *.log", "rm -rf foo*"] {
            let findings = cheap_check(input, ShellType::Posix, &empty_env());
            assert!(
                findings
                    .iter()
                    .all(|finding| finding.rule_id != RuleId::BlastWritesSystemPath),
                "relative target must not be resolved against filesystem root: {input} -> {findings:?}"
            );
        }
    }

    #[test]
    fn cheap_check_absolute_glob_and_expanded_home_remain_protected() {
        let mut env = HashMap::new();
        env.insert("HOME".to_string(), "/Users/alice".to_string());

        for input in [r#"rm -rf /etc/*"#, r#"rm -rf "$HOME""#] {
            let findings = cheap_check(input, ShellType::Posix, &env);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_id == RuleId::BlastWritesSystemPath),
                "protected absolute target escaped classification: {input} -> {findings:?}"
            );
        }
    }

    #[test]
    fn preview_classifies_relative_targets_against_its_supplied_cwd() {
        // Exercise only lexical classification: do not invoke `simulate` and do
        // not read or walk the synthetic system paths.
        assert!(is_system_path_for_preview(".", Path::new("/etc"), None));
        assert!(is_system_path_for_preview(
            "*.conf",
            Path::new("/etc"),
            None
        ));
        assert!(!is_system_path_for_preview(
            ".",
            Path::new("/tmp/project"),
            None
        ));
    }

    #[test]
    fn cheap_check_mv_to_root() {
        let f = cheap_check("mv important /", ShellType::Posix, &empty_env());
        assert!(f.iter().any(|f| f.rule_id == RuleId::BlastWritesSystemPath));
    }

    #[test]
    fn cheap_check_mv_attached_target_directory_preserves_destination() {
        let protected = cheap_check("mv -t/etc payload", ShellType::Posix, &empty_env());
        assert!(protected
            .iter()
            .any(|finding| finding.rule_id == RuleId::BlastWritesSystemPath));

        let relative = cheap_check("mv -t./dist payload", ShellType::Posix, &empty_env());
        assert!(relative
            .iter()
            .all(|finding| finding.rule_id != RuleId::BlastWritesSystemPath));
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
    fn cheap_check_resolves_execution_wrappers_and_value_taking_options() {
        for input in [
            "env rm -rf /home",
            "command rm -rf /etc",
            "exec rm -rf /var",
            "nohup rm -rf /opt",
            "time -f %e rm -rf /srv",
            "sudo -p prompt rm -rf /root",
            "doas -u root rm -rf /boot",
        ] {
            let findings = cheap_check(input, ShellType::Posix, &empty_env());
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_id == RuleId::BlastWritesSystemPath),
                "wrapper bypassed blast-radius check: {input} -> {findings:?}"
            );
        }
    }

    #[test]
    fn cheap_check_find_traversal_options_preserve_the_real_root_target() {
        let findings = cheap_check("find -H / -delete", ShellType::Posix, &empty_env());
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::BlastFindDelete));
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::BlastWritesSystemPath));
    }

    #[test]
    fn cheap_check_resolves_environment_tilde_glob_and_lexical_path_equivalence() {
        let mut env = HashMap::new();
        env.insert("HOME".to_string(), "/Users/alice".to_string());
        env.insert("ROOT".to_string(), "/etc".to_string());
        for input in [
            r#"rm -rf "$HOME""#,
            r#"rm -rf "$ROOT/*""#,
            "rm -rf /tmp/../etc",
            "rm -rf ~/",
            "rm -rf /var/log/../*",
        ] {
            let findings = cheap_check(input, ShellType::Posix, &env);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_id == RuleId::BlastWritesSystemPath),
                "equivalent protected path escaped: {input} -> {findings:?}"
            );
        }

        // A prefix assignment does not affect parameter expansion in the same
        // shell command: `HOME=/tmp rm -rf "$HOME"` still expands the shell's
        // inherited HOME and must remain blocked.
        let prefixed_home =
            cheap_check(r#"HOME=/tmp/build rm -rf "$HOME""#, ShellType::Posix, &env);
        assert!(prefixed_home
            .iter()
            .any(|finding| finding.rule_id == RuleId::BlastWritesSystemPath));

        let mut safe_env = env.clone();
        safe_env.insert("ROOT".to_string(), "/tmp/build".to_string());
        let control = cheap_check(r#"rm -rf "$ROOT""#, ShellType::Posix, &safe_env);
        assert!(control
            .iter()
            .all(|finding| finding.rule_id != RuleId::BlastWritesSystemPath));
    }

    #[test]
    fn cheap_check_analyzes_background_groups_and_command_substitutions() {
        for input in [
            "echo ready & rm -rf /",
            "echo $(rm -rf /)",
            "(rm -rf /)",
            "{ rm -rf /; }",
        ] {
            let findings = cheap_check(input, ShellType::Posix, &empty_env());
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_id == RuleId::BlastWritesSystemPath),
                "nested/secondary command escaped: {input} -> {findings:?}"
            );
        }

        for (input, shell) in [
            ("echo ready; echo (rm -rf /)", ShellType::Fish),
            ("echo ok; and rm -rf /", ShellType::Fish),
            ("false; or rm -rf /", ShellType::Fish),
            ("not rm -rf /", ShellType::Fish),
            ("if true; then rm -rf /; fi", ShellType::Posix),
            ("while true; do rm -rf /; done", ShellType::Posix),
            ("case x in x) rm -rf /;; esac", ShellType::Posix),
            ("(echo ready & rm -rf /)", ShellType::Cmd),
            (r#"cmd /C "(echo ready & rm -rf /)""#, ShellType::Cmd),
            (r#"cmd /C "if exist marker rm -rf /""#, ShellType::Cmd),
            (r#"cmd /C "for %i in (x) do rm -rf /""#, ShellType::Cmd),
        ] {
            let findings = cheap_check(input, shell, &empty_env());
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_id == RuleId::BlastWritesSystemPath),
                "shell-specific group/substitution escaped: {input} -> {findings:?}"
            );
        }
    }

    #[test]
    fn cheap_check_retains_executable_scan_budget_exhaustion() {
        let exact = format!("{}echo $(rm -rf /)", "true;".repeat(254));
        let exact_findings = cheap_check(&exact, ShellType::Posix, &empty_env());
        assert!(
            exact_findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::BlastWritesSystemPath),
            "the exact-cap body must remain visible: {exact_findings:?}"
        );
        assert!(
            exact_findings
                .iter()
                .all(|finding| finding.rule_id != RuleId::AnalysisIncomplete),
            "the exact-cap control must remain complete: {exact_findings:?}"
        );

        let plus_one = format!("{}echo $(rm -rf /)", "true;".repeat(255));
        let findings = cheap_check(&plus_one, ShellType::Posix, &empty_env());
        assert!(
            findings.iter().any(|finding| {
                finding.rule_id == RuleId::AnalysisIncomplete && finding.severity == Severity::High
            }),
            "the executable-substitution work gap must fail closed: {findings:?}"
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
    fn budget_cutoff_before_a_later_target_fails_closed() {
        // The first target exhausts the work budget, so the second target — which
        // escapes the repository — is never classified. The report must say so
        // rather than presenting "outside repo: no" as a complete answer.
        let repo = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let wide = repo.path().join("wide");
        fs::create_dir_all(&wide).unwrap();
        for i in 0..8 {
            fs::write(wide.join(format!("f{i}.txt")), b"x").unwrap();
        }
        let command = format!("rm -rf ./wide {}", outside.path().display());
        let report = simulate_with_work_limit(
            &command,
            ShellType::Posix,
            repo.path(),
            Some(repo.path()),
            &empty_env(),
            2,
        );
        assert!(
            report.classification_incomplete,
            "a budget cutoff with targets left must be reported: {report:?}"
        );
        let findings = report_findings(&report);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == crate::verdict::RuleId::AnalysisIncomplete),
            "incomplete classification must fail closed: {findings:?}"
        );
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
    fn simulate_supports_bracket_and_wildcard_directory_components() {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("service-a/logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(logs.join("a.txt"), b"a").unwrap();
        fs::write(logs.join("b.txt"), b"b").unwrap();
        fs::write(logs.join("c.txt"), b"c").unwrap();

        let report = simulate(
            "rm -f service-*/logs/[ab].txt",
            ShellType::Posix,
            dir.path(),
            Some(dir.path()),
            &empty_env(),
        );
        assert_eq!(report.glob_expansion_count, 2);
        assert_eq!(report.file_count, 2);
        assert_eq!(report.walk_errors, 0);
    }

    #[test]
    fn glob_intermediate_component_ignores_ordinary_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("plain.txt"), b"not a directory").unwrap();
        fs::create_dir_all(dir.path().join("service-a")).unwrap();
        fs::write(dir.path().join("service-a/a.txt"), b"match").unwrap();

        let report = simulate(
            "rm -f */*.txt",
            ShellType::Posix,
            dir.path(),
            Some(dir.path()),
            &empty_env(),
        );
        assert_eq!(report.glob_expansion_count, 1);
        assert_eq!(report.file_count, 1);
        assert_eq!(report.walk_errors, 0);
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
        assert!(glob_match("[ab].txt", "a.txt"));
        assert!(glob_match("[a-c].txt", "b.txt"));
        assert!(glob_match("[!a].txt", "b.txt"));
        assert!(!glob_match("[!a].txt", "a.txt"));
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

    #[test]
    fn absent_variable_is_advisory_but_an_unsupported_expansion_still_blocks() {
        // The same absent variable must not block harder in the LESS dangerous
        // shape: `"$TARGET/"` (which collapses toward root) is already advisory,
        // so `build/$TARGET` is too.
        let findings = cheap_check("rm -rf build/$TARGET", ShellType::Posix, &empty_env());
        let incomplete: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == RuleId::AnalysisIncomplete)
            .collect();
        assert_eq!(incomplete.len(), 1, "{findings:?}");
        assert_eq!(incomplete[0].severity, Severity::Info);

        // An expansion tirith genuinely cannot model still fails closed.
        for command in [
            "rm -rf ${TARGET:-/}",
            "rm -rf ~someone/build",
            "rm -rf build/${TARGET",
        ] {
            let findings = cheap_check(command, ShellType::Posix, &empty_env());
            assert!(
                findings.iter().any(|f| {
                    f.rule_id == RuleId::AnalysisIncomplete && f.severity == Severity::High
                }),
                "{command} must still block: {findings:?}"
            );
        }
    }
}
