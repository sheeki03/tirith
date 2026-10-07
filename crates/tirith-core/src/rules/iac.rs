//! IaC operational-context rules (M8 ch3).
//!
//! Fire when the parsed command leader is an IaC CLI (`terraform`, `pulumi`,
//! `tofu`). Tier-1 gate: PATTERN_TABLE entry `iac_cmd`. The rules are:
//!
//! 1. `IacApplyWithoutPlan` (High, gated by `iac_require_plan_before_apply`) —
//!    apply with no plan-file positional.
//! 2. `IacApplyAutoApprove` (Medium) — apply with auto-approve outside a
//!    production-labeled context.
//! 3. `IacApplyAutoApproveProd` (High) — #2 against a critical/prod context.
//! 4. `IacDestroyProd` (High) — destroy against a labeled-prod context.
//! 5. `IacPlanHashMismatch` (High, gated by `iac_require_plan_before_apply`) —
//!    apply against a plan file whose SHA-256 is not recorded in
//!    `state_dir()/iac_plans/`.
//!
//! `IacPlanHighRiskChanges` is emitted by the `iac check-plan` CLI path, not
//! here (see `iac_plan.rs`).
//!
//! Detection short-circuits when the leader is not an IaC CLI. The prod-context
//! rules additionally require `context_guard_enabled` + an operator-labeled
//! context (`policy.context_labels`).

use std::path::{Path, PathBuf};

use crate::context_detect::{self, Provider};
use crate::iac_plan;
use crate::policy::Policy;
use crate::rules::command::normalize_shell_token;
use crate::rules::shared::is_critical_label;
use crate::tokenize::{self, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// IaC tool detected from the parsed command leader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IacTool {
    Terraform,
    Pulumi,
    Tofu,
}

impl IacTool {
    fn as_str(self) -> &'static str {
        match self {
            Self::Terraform => "terraform",
            Self::Pulumi => "pulumi",
            Self::Tofu => "tofu",
        }
    }
}

/// Run the IaC rules over every executable segment of the parsed command, as
/// `rules::context` does, so `cd infra; terraform apply -auto-approve` and the
/// #264 literal view `T=terraform; terraform apply ...` are checked (the
/// prod-context rule and the apply-gate rule can both fire on one segment).
///
/// The plan-hash gate reads the plan file the apply segment will use, so it
/// tracks the working directory across segments (`DirTracker`) and recognizes
/// a plan file that `tirith iac check-plan` records right before the apply,
/// in the same `&&` chain (`check_plan_chained_before`).
pub fn check(input: &str, shell: ShellType, policy: &Policy) -> Vec<Finding> {
    let segments = tokenize::tokenize(input, shell);
    let tirith_may_be_rebound = tirith_lookup_may_be_rebound(&segments);
    let mut dirs = DirTracker::start();
    let mut findings = Vec::new();
    for (i, seg) in segments.iter().enumerate() {
        dirs.enter(seg);
        let recorded_by_previous = if tirith_may_be_rebound {
            None
        } else {
            check_plan_chained_before(&segments, i)
        };
        let work_dir = dirs.current();
        let plan_env = PlanEnv {
            work_dir: &work_dir,
            recorded_by_previous: recorded_by_previous.as_deref(),
        };
        findings.extend(check_segment(input, shell, policy, seg, &plan_env));
        dirs.leave(&segments, i, shell);
    }
    findings
}

/// `true` when a segment with this preceding separator starts a new and-or
/// list, i.e. runs regardless of how the previous command exited.
fn starts_and_or_list(sep: Option<&str>) -> bool {
    matches!(sep, None | Some(";" | "\n" | "&"))
}

/// The shell's working directory at a segment, relative to the directory
/// tirith resolves plain relative paths against (its own cwd).
#[derive(Debug, Clone, PartialEq, Eq)]
enum WorkDir {
    /// Statically known: the tirith cwd joined with this path (empty = no
    /// change; absolute after `cd /abs`).
    Known(PathBuf),
    /// An earlier segment changed directory in a way tirith cannot resolve.
    Unknown,
}

impl WorkDir {
    /// Where the shell will find `path` (already relative to the segment's
    /// working directory); `None` when that cannot be resolved statically.
    fn resolve(&self, path: &Path) -> Option<PathBuf> {
        if path.is_absolute() {
            return Some(path.to_path_buf());
        }
        match self {
            Self::Known(base) => Some(base.join(path)),
            Self::Unknown => None,
        }
    }
}

/// Tracks the working directory across the segments of one input.
///
/// A `cd <literal>` is resolved only when it runs unconditionally: it starts
/// its and-or list (preceded by nothing, `;` or a newline), is not part of a
/// pipeline, and its and-or list is not backgrounded with `&` (a subshell).
/// The cd then runs, and it succeeds whenever the plan file tirith reads
/// below it exists. Inside the rest of that and-or list, a segment reached
/// through `||` may run because the cd failed, so its directory is unknown.
/// A conditional cd (after `&&` / `||`) makes the directory unknown.
#[derive(Debug, Clone)]
struct DirTracker {
    dir: WorkDir,
    /// The current and-or list resolved an unconditional `cd`.
    cd_in_list: bool,
    /// ... and a `||` has followed that cd in the list.
    or_after_cd: bool,
    /// An earlier segment of the input names `CDPATH` (or zsh's `cdpath`):
    /// the shell's cd may then search it even when tirith's own environment
    /// has none (an unexported shell variable is enough).
    input_set_cdpath: bool,
}

impl DirTracker {
    fn start() -> Self {
        Self {
            dir: WorkDir::Known(PathBuf::new()),
            cd_in_list: false,
            or_after_cd: false,
            input_set_cdpath: false,
        }
    }

    /// Update the and-or list state for the segment about to be checked.
    fn enter(&mut self, seg: &tokenize::Segment) {
        let sep = seg.preceding_separator.as_deref();
        if starts_and_or_list(sep) {
            self.cd_in_list = false;
            self.or_after_cd = false;
        } else if sep == Some("||") && self.cd_in_list {
            self.or_after_cd = true;
        }
    }

    /// The working directory of the segment last passed to `enter`.
    fn current(&self) -> WorkDir {
        if self.or_after_cd {
            WorkDir::Unknown
        } else {
            self.dir.clone()
        }
    }

    /// Apply the directory change (if any) of `segments[i]`.
    fn leave(&mut self, segments: &[tokenize::Segment], i: usize, shell: ShellType) {
        let seg = &segments[i];
        if seg
            .raw
            .as_bytes()
            .windows(b"cdpath".len())
            .any(|window| window.eq_ignore_ascii_case(b"cdpath"))
        {
            self.input_set_cdpath = true;
        }
        if !segment_may_change_dir(seg, shell) {
            return;
        }
        let target = cd_runs_unconditionally(segments, i)
            .then(|| literal_cd_target(seg, shell, self.input_set_cdpath))
            .flatten();
        let dir = std::mem::replace(&mut self.dir, WorkDir::Unknown);
        self.dir = match (dir, target) {
            (WorkDir::Known(base), Some(target)) => WorkDir::Known(base.join(target)),
            (WorkDir::Unknown, Some(target)) if target.is_absolute() => WorkDir::Known(target),
            _ => WorkDir::Unknown,
        };
        if matches!(self.dir, WorkDir::Known(_)) {
            self.cd_in_list = true;
        }
    }
}

/// `true` when `segments[i]` runs whenever the line runs, in the shell
/// process itself: it starts its and-or list (after nothing, `;` or a
/// newline; not after `&`, `&&`, `||` or a pipe), is not piped into the next
/// segment, and its and-or list is not backgrounded with `&`.
fn cd_runs_unconditionally(segments: &[tokenize::Segment], i: usize) -> bool {
    if !matches!(
        segments[i].preceding_separator.as_deref(),
        None | Some(";" | "\n")
    ) {
        return false;
    }
    for (k, next) in segments.iter().enumerate().skip(i + 1) {
        match next.preceding_separator.as_deref() {
            Some("&&" | "||") => {}
            Some("|" | "|&") if k == i + 1 => return false,
            Some("|" | "|&") => {}
            Some("&") => return false,
            _ => return true,
        }
    }
    true
}

/// The plan path that `tirith iac check-plan` records in `segments[i - 1]`
/// when that check-plan surely runs, and succeeds, before `segments[i]`:
/// `segments[i]` follows it with `&&`, and every separator back to the start
/// of the and-or list is `&&` too (no `||` or pipe can skip it).
fn check_plan_chained_before(segments: &[tokenize::Segment], i: usize) -> Option<PathBuf> {
    let prev = i.checked_sub(1)?;
    if segments[i].preceding_separator.as_deref() != Some("&&") {
        return None;
    }
    let mut j = prev;
    loop {
        let sep = segments[j].preceding_separator.as_deref();
        if starts_and_or_list(sep) {
            break;
        }
        if sep != Some("&&") || j == 0 {
            return None;
        }
        j -= 1;
    }
    check_plan_recorded_path(&segments[prev])
}

/// `true` when some segment other than a plain `tirith iac check-plan` could
/// make the bare word `tirith` run something else: it names `tirith` (an
/// alias, function or `hash` entry), changes `PATH`, defines a function, or
/// evaluates code that could. Over-approximates: a false positive only means
/// the plan file is read at preexec time as usual.
fn tirith_lookup_may_be_rebound(segments: &[tokenize::Segment]) -> bool {
    segments
        .iter()
        .filter(|seg| check_plan_recorded_path(seg).is_none())
        .any(|seg| {
            let squeezed: String = seg.raw.chars().filter(|c| !c.is_whitespace()).collect();
            squeezed.contains("()") || seg_words(&seg.raw).any(|w| word_may_rebind_tirith(&w))
        })
}

/// Plan-gate inputs that depend on the segments before the current one.
struct PlanEnv<'a> {
    work_dir: &'a WorkDir,
    /// The plan path (relative to the shared working directory) that the
    /// immediately preceding `&&` segment records via `tirith iac check-plan`.
    recorded_by_previous: Option<&'a Path>,
}

/// Commands that change (or may change) the shell's working directory. Words
/// are compared case-insensitively so PowerShell aliases are covered too.
const DIR_CHANGE_WORDS: &[&str] = &[
    "cd",
    "chdir",
    "pushd",
    "popd",
    "prevd",
    "nextd",
    "source",
    "eval",
    "set-location",
    "sl",
    "push-location",
    "pop-location",
];

/// `true` when the segment contains a word that can change the working
/// directory (as its command, behind `builtin` / `command` / `time`, or inside
/// a `{ ...; }` group), sources a file (`. file`), or has a command word built
/// by an expansion (`$X ..`). A word counts with its quoting and escapes
/// removed, the way the shell reads it (`\cd`, `c''d`, `'c'd`, `$'\x63d'`,
/// PowerShell `` c`d ``, cmd `c^d` are all `cd`). Over-approximates: a false
/// positive only makes a later relative plan path unresolvable.
fn segment_may_change_dir(seg: &tokenize::Segment, shell: ShellType) -> bool {
    if let Some(cmd) = seg.command.as_deref() {
        if normalize_shell_token(cmd, shell) == "." || cmd.contains(['$', '`']) {
            return true;
        }
    }
    let is_dir_change = |w: &str| DIR_CHANGE_WORDS.contains(&w.to_ascii_lowercase().as_str());
    // Each word as the shell decodes it (quotes, backslashes, ANSI-C escapes).
    let decoded =
        split_shell_words(&seg.raw).any(|w| is_dir_change(&normalize_shell_token(w, shell)));
    // And with every quote and escape character simply dropped, so an escape
    // character that is also a separator above (PowerShell's backtick) or a
    // quoting form the decoder leaves alone cannot hide the word either.
    let stripped: String = seg
        .raw
        .chars()
        .filter(|c| !matches!(c, '\'' | '"' | '\\' | '`' | '^' | '$'))
        .collect();
    decoded || split_shell_words(&stripped).any(is_dir_change)
}

/// `raw` split at whitespace, operators and brackets (quotes are kept).
fn split_shell_words(raw: &str) -> impl Iterator<Item = &str> {
    raw.split(|c: char| {
        c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')' | '{' | '}' | '`')
    })
}

/// The target of a plain `cd <literal>` / `pushd <literal>` segment in a POSIX
/// or fish shell; `None` for anything else (no or several operands, `-`,
/// `+N`, expansions, quoting inside the word, a `CDPATH` that could redirect
/// a bare name, PowerShell / cmd syntax). `input_set_cdpath`: an earlier
/// segment of the input names `CDPATH`, so a bare name may be redirected even
/// when tirith's environment has no `CDPATH`.
fn literal_cd_target(
    seg: &tokenize::Segment,
    shell: ShellType,
    input_set_cdpath: bool,
) -> Option<PathBuf> {
    if matches!(shell, ShellType::PowerShell | ShellType::Cmd) {
        return None;
    }
    let cmd = seg.command.as_deref()?;
    if !matches!(cmd, "cd" | "pushd") || !seg.raw.trim_start().starts_with(cmd) {
        return None;
    }
    let mut operands = seg
        .args
        .iter()
        .map(|a| strip_outer_quotes(a))
        .skip_while(|a| matches!(*a, "-L" | "-P"));
    let mut target = operands.next()?;
    if target == "--" {
        target = operands.next()?;
    }
    if operands.next().is_some() {
        return None;
    }
    let target = literal_path_word(target)?;
    let bare_name = !(target.starts_with('/')
        || target.starts_with("./")
        || target.starts_with("../")
        || target == "."
        || target == "..");
    if bare_name && (input_set_cdpath || std::env::var_os("CDPATH").is_some_and(|v| !v.is_empty()))
    {
        return None;
    }
    Some(PathBuf::from(target))
}

/// `word` when it is a plain path with no shell expansion, quoting or option
/// syntax left in it.
fn literal_path_word(word: &str) -> Option<&str> {
    let plain = !word.is_empty()
        && !word.starts_with(['-', '+'])
        && !word.contains([
            '$', '`', '~', '*', '?', '[', ']', '{', '}', '\\', '\'', '"', '<', '>', '(', ')',
        ]);
    plain.then_some(word)
}

/// The shell words of `raw`, split at whitespace, operators and brackets,
/// with surrounding quotes dropped and lower-cased.
fn seg_words(raw: &str) -> impl Iterator<Item = String> + '_ {
    raw.split(|c: char| {
        c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')' | '{' | '}' | '`' | '[' | ']')
    })
    .map(|w| {
        w.trim_matches(|c| matches!(c, '\'' | '"'))
            .to_ascii_lowercase()
    })
}

/// `true` when the word can rebind what the bare command `tirith` runs: an
/// assignment to `PATH` (`PATH=`, `$env:PATH`, zsh `path`), a word that
/// defines aliases / functions or evaluates code, or a mention of `tirith`
/// (`alias tirith=...`, `alias t=tirith`, `hash -p ... tirith`).
fn word_may_rebind_tirith(word: &str) -> bool {
    const REBINDING_WORDS: &[&str] = &[
        "path",
        "eval",
        "source",
        ".",
        "alias",
        "hash",
        "enable",
        "function",
        "functions",
        "aliases",
        "autoload",
        "fpath",
        "invoke-expression",
        "iex",
        "set-alias",
        "new-alias",
        "sal",
        "nal",
        "new-item",
        "ni",
        "set-item",
        "si",
    ];
    let head = word.split(['=', '+']).next().unwrap_or(word);
    REBINDING_WORDS.contains(&head)
        || word.contains("env:path")
        || word.contains("function:")
        || word.contains("alias:")
        || word.split('=').any(|part| {
            part == "tirith"
                || part == "tirith.exe"
                || part.ends_with("/tirith")
                || part.ends_with("\\tirith")
        })
}

/// The plan path `tirith iac check-plan <plan>` records in this segment
/// (exactly that command: no prefix assignments, only known options).
fn check_plan_recorded_path(seg: &tokenize::Segment) -> Option<PathBuf> {
    // Only the bare command word: a path-qualified or quoted `tirith` may be
    // any program (`tirith_lookup_may_be_rebound` covers the bare word).
    if seg.command.as_deref() != Some("tirith") || !seg.raw.trim_start().starts_with("tirith") {
        return None;
    }
    let args: Vec<&str> = seg.args.iter().map(|a| strip_outer_quotes(a)).collect();
    let rest = match args.as_slice() {
        ["iac", "check-plan", rest @ ..] => rest,
        _ => return None,
    };
    let mut plan = None;
    let mut iter = rest.iter();
    while let Some(arg) = iter.next() {
        match *arg {
            "--json" => {}
            "--tool" | "--format" => {
                iter.next()?;
            }
            a if a.starts_with("--tool=") || a.starts_with("--format=") => {}
            "--" => {
                plan = Some(*iter.next()?);
                if iter.next().is_some() {
                    return None;
                }
            }
            a if a.starts_with('-') => return None,
            a => {
                if plan.replace(a).is_some() {
                    return None;
                }
            }
        }
    }
    literal_path_word(plan?).map(normalize_lexically)
}

/// Drop `.` components so `./tfplan` and `tfplan` compare equal.
fn normalize_lexically(path: &str) -> PathBuf {
    Path::new(path)
        .components()
        .filter(|c| !matches!(c, std::path::Component::CurDir))
        .collect()
}

/// The terraform / tofu `-chdir=<dir>` global option before the verb:
/// `Ok(None)` when absent, `Err(())` when its value is not a literal path.
fn chdir_option(tool: IacTool, pre_verb: &[String]) -> Result<Option<PathBuf>, ()> {
    if !matches!(tool, IacTool::Terraform | IacTool::Tofu) {
        return Ok(None);
    }
    let mut dir = None;
    for arg in pre_verb {
        let value = arg
            .strip_prefix("-chdir=")
            .or_else(|| arg.strip_prefix("--chdir="));
        if let Some(value) = value {
            dir = Some(PathBuf::from(
                literal_path_word(strip_outer_quotes(value)).ok_or(())?,
            ));
        }
    }
    Ok(dir)
}

fn check_segment(
    input: &str,
    shell: ShellType,
    policy: &Policy,
    seg: &tokenize::Segment,
    plan_env: &PlanEnv<'_>,
) -> Vec<Finding> {
    let Some(cmd) = seg.command.as_deref() else {
        return Vec::new();
    };
    let leader = command_basename(cmd, shell);

    let tool = match leader.as_str() {
        "terraform" => IacTool::Terraform,
        "pulumi" => IacTool::Pulumi,
        "tofu" => IacTool::Tofu,
        _ => return Vec::new(),
    };

    let args: Vec<String> = seg
        .args
        .iter()
        .map(|a| strip_outer_quotes(a).to_string())
        .collect();

    // Shape: <tool> <apply|up|destroy> [flags] [plan_file?]
    let (verb, post_verb) = match locate_verb(tool, &args) {
        Some(p) => p,
        None => return Vec::new(),
    };
    let pre_verb = &args[..args.len() - post_verb.len() - 1];
    let is_apply = matches!(verb, IacVerb::Apply | IacVerb::Up);
    let is_destroy = matches!(verb, IacVerb::Destroy);
    if !is_apply && !is_destroy {
        return Vec::new();
    }

    let mut findings = Vec::new();

    let auto_approve = has_auto_approve(tool, post_verb);
    let plan_file = positional_plan_file(post_verb);

    // Prod-context detection gates the prod-aware rules only; the others fire
    // regardless.
    let prod_context = if policy.context_guard_enabled && !policy.context_labels.is_empty() {
        find_prod_context(policy)
    } else {
        None
    };

    if is_destroy && prod_context.is_some() {
        let label_text = prod_context.as_deref().unwrap_or("(prod)");
        findings.push(make_finding(
            RuleId::IacDestroyProd,
            Severity::High,
            format!("{} destroy against production context", tool.as_str()),
            format!(
                "`{} destroy` against an active provider context labeled \
                 production / critical removes every resource in the workspace. \
                 Confirm `tirith context status` shows the intended context.",
                tool.as_str(),
            ),
            tool,
            input,
            Some(label_text),
        ));
    }

    if is_apply && auto_approve {
        let (rule_id, severity, title) = if prod_context.is_some() {
            (
                RuleId::IacApplyAutoApproveProd,
                Severity::High,
                format!(
                    "{} apply -auto-approve against production context",
                    tool.as_str()
                ),
            )
        } else {
            (
                RuleId::IacApplyAutoApprove,
                Severity::Medium,
                format!("{} apply with auto-approve", tool.as_str()),
            )
        };
        findings.push(make_finding(
            rule_id,
            severity,
            title,
            format!(
                "`{}` was invoked with the auto-approve flag (skips the interactive \
                 confirmation step). {}",
                tool.as_str(),
                if prod_context.is_some() {
                    "The active context is labeled production / critical — the combination is \
                     a documented anti-pattern."
                } else {
                    "Outside of production this is a footgun rather than a critical risk; \
                     surfaced for awareness."
                },
            ),
            tool,
            input,
            prod_context.as_deref(),
        ));
    }

    // Plan-before-apply gate (opt-in).
    if is_apply && policy.iac_require_plan_before_apply {
        match plan_file {
            None => {
                findings.push(make_finding(
                    RuleId::IacApplyWithoutPlan,
                    Severity::High,
                    format!("{} apply without a saved plan file", tool.as_str()),
                    format!(
                        "`{}` was invoked with no positional plan file and \
                         `iac_require_plan_before_apply` is on. Run \
                         `{} plan -out tfplan && tirith iac check-plan tfplan && \
                         {} apply tfplan`.",
                        tool.as_str(),
                        tool.as_str(),
                        tool.as_str(),
                    ),
                    tool,
                    input,
                    prod_context.as_deref(),
                ));
            }
            Some(path) => {
                // The plan file relative to the shell's working directory at
                // this segment (`-chdir=` applies first), then where tirith
                // finds it after any earlier `cd`.
                let in_segment_dir = chdir_option(tool, pre_verb).map(|chdir| match chdir {
                    Some(dir) => dir.join(normalize_lexically(&path)),
                    None => normalize_lexically(&path),
                });
                let recorded_by_previous = matches!(
                    (&in_segment_dir, plan_env.recorded_by_previous),
                    (Ok(p), Some(recorded)) if p == recorded
                );
                let resolved = in_segment_dir
                    .ok()
                    .and_then(|p| plan_env.work_dir.resolve(&p));
                if recorded_by_previous {
                    // `tirith iac check-plan <plan> && <tool> apply <plan>`:
                    // the chain records this exact file right before the
                    // apply, and the apply does not run when recording fails.
                    // The file may not exist yet at preexec time.
                } else if let Some(pb) = resolved {
                    findings.extend(check_plan_hash(
                        tool,
                        &path,
                        &pb,
                        input,
                        prod_context.as_deref(),
                    ));
                } else {
                    findings.push(make_finding(
                        RuleId::IacPlanHashMismatch,
                        Severity::High,
                        format!(
                            "{} apply: plan file '{}' cannot be located",
                            tool.as_str(),
                            path
                        ),
                        format!(
                            "`{}` was invoked with plan file `{}` after a directory change \
                             (`cd`, `pushd`, `-chdir=`, ...) that tirith cannot resolve, so \
                             it cannot verify which plan file will be applied. Use an \
                             absolute plan path, or run `tirith iac check-plan <plan> && \
                             {} apply <plan>` from the plan's directory.",
                            tool.as_str(),
                            path,
                            tool.as_str(),
                        ),
                        tool,
                        input,
                        prod_context.as_deref(),
                    ));
                }
            }
        }
    }

    findings
}

/// Hash `pb` (the plan file `path` names) and report it unless it is recorded.
fn check_plan_hash(
    tool: IacTool,
    path: &str,
    pb: &Path,
    input: &str,
    prod_context: Option<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    match std::fs::read(pb) {
        Ok(bytes) => {
            let sha = iac_plan::sha256_hex(&bytes);
            let status = iac_plan::plan_hash_status(&sha);
            // Both NotRecorded and StateDirUnresolved fail closed
            // (PR-127 review #14); the evidence text differentiates.
            if !matches!(status, iac_plan::PlanHashStatus::Recorded) {
                let detail = match status {
                    iac_plan::PlanHashStatus::StateDirUnresolved => format!(
                        "tirith could not resolve its state directory; plan-hash \
                         verification cannot proceed. Set `XDG_STATE_HOME` or \
                         ensure `$HOME` is writable, then run \
                         `tirith iac check-plan {path}` to record this plan."
                    ),
                    _ => format!(
                        "`{}` was invoked with plan file `{}` but the file's \
                         SHA-256 (`{}`) does not match any plan recorded in \
                         `{}`. Run `tirith iac check-plan {}` first.",
                        tool.as_str(),
                        path,
                        sha,
                        iac_plan::iac_plans_dir_display(),
                        path,
                    ),
                };
                findings.push(make_finding(
                    RuleId::IacPlanHashMismatch,
                    Severity::High,
                    format!("{} apply against an unrecorded plan file", tool.as_str()),
                    detail,
                    tool,
                    input,
                    prod_context,
                ));
            }
        }
        Err(e) => {
            // Couldn't open the plan file — emit the mismatch anyway.
            findings.push(make_finding(
                RuleId::IacPlanHashMismatch,
                Severity::High,
                format!(
                    "{} apply: plan file '{}' could not be read",
                    tool.as_str(),
                    path
                ),
                format!(
                    "`{}` was invoked with plan file `{}` but tirith could not \
                     read it (`{e}`). Verify the path before re-running.",
                    tool.as_str(),
                    path
                ),
                tool,
                input,
                prod_context,
            ));
        }
    }

    findings
}

/// `Some(label)` when an active provider context is labeled critical/prod.
fn find_prod_context(policy: &Policy) -> Option<String> {
    let detection = context_detect::detect_all();
    for provider in [
        Provider::Kube,
        Provider::Aws,
        Provider::Gcp,
        Provider::Azure,
    ] {
        if let Some(ctx) = detection.contexts.get(&provider) {
            if let Some(label) = policy.context_labels.get(&ctx.label_key()) {
                if is_critical_label(label) {
                    return Some(format!("{}={} ({label})", provider.as_str(), ctx.context));
                }
            }
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IacVerb {
    Apply,
    /// Pulumi calls it `up` — we treat it as apply.
    Up,
    Destroy,
}

/// Locate the verb, skipping global flags before it; returns the slice after.
fn locate_verb(tool: IacTool, args: &[String]) -> Option<(IacVerb, &[String])> {
    for (i, arg) in args.iter().enumerate() {
        if arg.starts_with('-') {
            continue;
        }
        let verb = match (tool, arg.as_str()) {
            (IacTool::Terraform | IacTool::Tofu, "apply") => IacVerb::Apply,
            (IacTool::Terraform | IacTool::Tofu, "destroy") => IacVerb::Destroy,
            (IacTool::Pulumi, "up") => IacVerb::Up,
            (IacTool::Pulumi, "destroy") => IacVerb::Destroy,
            _ => return None,
        };
        return Some((verb, &args[i + 1..]));
    }
    None
}

/// Detect the auto-approve flag (`-auto-approve` for terraform/tofu, `--yes` /
/// `-y` for pulumi).
fn has_auto_approve(tool: IacTool, post_verb: &[String]) -> bool {
    match tool {
        IacTool::Terraform | IacTool::Tofu => post_verb.iter().any(|a| {
            let a = strip_outer_quotes(a);
            a == "-auto-approve" || a == "--auto-approve" || a.starts_with("-auto-approve=")
        }),
        IacTool::Pulumi => post_verb.iter().any(|a| {
            let a = strip_outer_quotes(a);
            a == "--yes" || a == "-y" || a.starts_with("--yes=")
        }),
    }
}

/// Locate the first post-verb positional that looks like a plan-file path (not
/// a flag, not `KEY=VAL`); `None` when there is none.
fn positional_plan_file(post_verb: &[String]) -> Option<String> {
    let mut iter = post_verb.iter();
    while let Some(arg) = iter.next() {
        let arg = strip_outer_quotes(arg);
        if arg.is_empty() {
            continue;
        }
        if arg == "--" {
            // Following arg is positional, regardless of how it starts.
            if let Some(p) = iter.next() {
                let p = strip_outer_quotes(p);
                if !p.is_empty() {
                    return Some(p.to_string());
                }
            }
            return None;
        }
        if arg.starts_with('-') {
            // Terraform flag values are glued (`-target=res`), so skip bare flags.
            continue;
        }
        if arg.contains('=') {
            // KEY=VAL shape — not a plan file.
            continue;
        }
        return Some(arg.to_string());
    }
    None
}

fn make_finding(
    rule_id: RuleId,
    severity: Severity,
    title: String,
    description: String,
    tool: IacTool,
    input: &str,
    prod_context: Option<&str>,
) -> Finding {
    let mut evidence = vec![Evidence::CommandPattern {
        pattern: format!("{} <iac-gate>", tool.as_str()),
        matched: input.chars().take(200).collect(),
    }];
    if let Some(ctx) = prod_context {
        evidence.push(Evidence::Text {
            detail: format!("active prod context: {ctx}"),
        });
    }

    Finding {
        rule_id,
        severity,
        title,
        description,
        evidence,
        human_view: Some(format!(
            "{} — confirm with `tirith iac --help` before re-running.",
            tool.as_str()
        )),
        agent_view: Some(format!(
            "tirith refused: IaC gate. tool={} rule={:?} {}",
            tool.as_str(),
            rule_id,
            prod_context.map(|c| format!("ctx={c}")).unwrap_or_default(),
        )),
        mitre_id: None,
        custom_rule_id: None,
    }
}

fn strip_outer_quotes(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn command_basename(cmd: &str, shell: ShellType) -> String {
    let unq = strip_outer_quotes(cmd);
    let basename = match shell {
        ShellType::PowerShell | ShellType::Cmd => unq.rsplit(['/', '\\']).next().unwrap_or(unq),
        _ => unq.rsplit('/').next().unwrap_or(unq),
    };
    let lower = basename.to_lowercase();
    lower
        .strip_suffix(".exe")
        .map(str::to_string)
        .unwrap_or(lower)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn policy_with_prod_label(provider: &str, ctx: &str) -> Policy {
        let mut p = Policy {
            context_guard_enabled: true,
            ..Policy::default()
        };
        let key = format!("{provider}:{ctx}");
        p.context_labels.insert(key, "critical".to_string());
        p
    }

    #[test]
    fn locate_verb_skips_chdir_flag() {
        let args = vec!["-chdir=infra".to_string(), "apply".to_string()];
        let v = locate_verb(IacTool::Terraform, &args);
        assert!(matches!(v, Some((IacVerb::Apply, _))));
    }

    #[test]
    fn locate_verb_returns_none_for_non_apply() {
        let args = vec!["fmt".to_string()];
        let v = locate_verb(IacTool::Terraform, &args);
        assert!(v.is_none());
    }

    #[test]
    fn auto_approve_detected_terraform() {
        assert!(has_auto_approve(
            IacTool::Terraform,
            &["-auto-approve".to_string()],
        ));
        assert!(!has_auto_approve(
            IacTool::Terraform,
            &["-target=foo".to_string()],
        ));
    }

    #[test]
    fn auto_approve_detected_pulumi() {
        assert!(has_auto_approve(IacTool::Pulumi, &["--yes".to_string()]));
        assert!(has_auto_approve(IacTool::Pulumi, &["-y".to_string()]));
        assert!(!has_auto_approve(
            IacTool::Pulumi,
            &["--stack".to_string(), "dev".to_string()],
        ));
    }

    #[test]
    fn positional_plan_file_finds_plain_arg() {
        let p = positional_plan_file(&["tfplan".to_string()]);
        assert_eq!(p.as_deref(), Some("tfplan"));
    }

    #[test]
    fn positional_plan_file_skips_flag() {
        let p = positional_plan_file(&["-no-color".to_string(), "tfplan".to_string()]);
        assert_eq!(p.as_deref(), Some("tfplan"));
    }

    #[test]
    fn positional_plan_file_returns_none_when_no_positional() {
        let p = positional_plan_file(&["-auto-approve".to_string()]);
        assert!(p.is_none());
    }

    #[test]
    fn positional_plan_file_handles_double_dash() {
        let p = positional_plan_file(&["--".to_string(), "tfplan".to_string()]);
        assert_eq!(p.as_deref(), Some("tfplan"));
    }

    #[test]
    fn check_terraform_apply_auto_approve_dev_warns_medium() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let policy = Policy::default();
        let findings = check("terraform apply -auto-approve", ShellType::Posix, &policy);
        let auto = findings
            .iter()
            .find(|f| matches!(f.rule_id, RuleId::IacApplyAutoApprove));
        assert!(auto.is_some(), "expected IacApplyAutoApprove: {findings:?}");
        assert!(matches!(auto.unwrap().severity, Severity::Medium));
    }

    #[test]
    fn check_pulumi_up_yes_dev_warns_medium() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let policy = Policy::default();
        let findings = check("pulumi up --yes", ShellType::Posix, &policy);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::IacApplyAutoApprove)),
            "expected IacApplyAutoApprove: {findings:?}",
        );
    }

    #[test]
    fn check_tofu_apply_with_no_args_does_not_fire() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let policy = Policy::default();
        let findings = check("tofu apply", ShellType::Posix, &policy);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn check_terraform_apply_requires_plan_when_policy_on() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let policy = Policy {
            iac_require_plan_before_apply: true,
            ..Policy::default()
        };
        let findings = check("terraform apply", ShellType::Posix, &policy);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::IacApplyWithoutPlan)),
            "expected IacApplyWithoutPlan: {findings:?}",
        );
    }

    #[test]
    fn check_terraform_destroy_without_prod_does_not_fire_destroy_rule() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let policy = Policy::default();
        let findings = check("terraform destroy", ShellType::Posix, &policy);
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::IacDestroyProd)),
            "{findings:?}",
        );
    }

    #[test]
    fn check_inspects_every_shell_segment() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let policy = Policy::default();
        for input in [
            "cd infra; terraform apply -auto-approve",
            "cd infra && terraform apply -auto-approve",
            "terraform init || terraform apply -auto-approve",
            "echo start | tofu apply -auto-approve",
            // The #264 literal view of `T=terraform; "$T" apply -auto-approve`.
            "T=terraform; terraform apply -auto-approve",
            "terraform plan; pulumi up --yes",
        ] {
            let findings = check(input, ShellType::Posix, &policy);
            assert!(
                findings
                    .iter()
                    .any(|f| matches!(f.rule_id, RuleId::IacApplyAutoApprove)),
                "expected IacApplyAutoApprove for {input:?}: {findings:?}",
            );
        }
        let gated = Policy {
            iac_require_plan_before_apply: true,
            ..Policy::default()
        };
        let findings = check("cd infra; terraform apply", ShellType::Posix, &gated);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::IacApplyWithoutPlan)),
            "{findings:?}",
        );
        // Segments that are not an IaC apply/destroy still add nothing.
        for input in [
            "cd infra; terraform plan",
            "cd infra; terraform apply tfplan",
        ] {
            assert!(
                check(input, ShellType::Posix, &policy).is_empty(),
                "{input:?}"
            );
        }
    }

    /// The working directory `DirTracker` gives the last segment of `input`.
    fn work_dir_at_last_segment(input: &str) -> WorkDir {
        let segments = tokenize::tokenize(input, ShellType::Posix);
        let mut dirs = DirTracker::start();
        for (i, seg) in segments.iter().enumerate() {
            dirs.enter(seg);
            if i + 1 == segments.len() {
                break;
            }
            dirs.leave(&segments, i, ShellType::Posix);
        }
        dirs.current()
    }

    #[test]
    fn work_dir_follows_literal_cd_and_gives_up_on_anything_else() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let known = |p: &str| WorkDir::Known(PathBuf::from(p));
        for (input, expected) in [
            ("terraform apply tfplan", known("")),
            ("echo cd; terraform apply tfplan", WorkDir::Unknown),
            ("cd infra; terraform apply tfplan", known("infra")),
            ("cd 'infra' && terraform apply tfplan", known("infra")),
            (
                "cd -P -- ./infra || exit; terraform apply tfplan",
                known("./infra"),
            ),
            (
                "cd infra; cd ../ops; terraform apply tfplan",
                known("infra/../ops"),
            ),
            ("cd /srv/infra; terraform apply tfplan", known("/srv/infra")),
            ("cd \"$D\"; terraform apply tfplan", WorkDir::Unknown),
            ("cd ~/infra; terraform apply tfplan", WorkDir::Unknown),
            ("cd; terraform apply tfplan", WorkDir::Unknown),
            ("cd -; terraform apply tfplan", WorkDir::Unknown),
            ("cd a b; terraform apply tfplan", WorkDir::Unknown),
            ("pushd +1; terraform apply tfplan", WorkDir::Unknown),
            ("popd; terraform apply tfplan", WorkDir::Unknown),
            ("builtin cd infra; terraform apply tfplan", WorkDir::Unknown),
            ("{ cd infra; }; terraform apply tfplan", WorkDir::Unknown),
            ("(cd infra); terraform apply tfplan", WorkDir::Unknown),
            (". ./env.sh; terraform apply tfplan", WorkDir::Unknown),
            ("source env.sh; terraform apply tfplan", WorkDir::Unknown),
            (
                "echo x | cd infra; terraform apply tfplan",
                WorkDir::Unknown,
            ),
            ("cd infra & terraform apply tfplan", WorkDir::Unknown),
            ("cd \"$D\"; cd /srv; terraform apply tfplan", known("/srv")),
            // R4 fix round 2: a cd that may not run, or that runs in a
            // background subshell, and the `||` branch taken when it fails.
            (
                "false && cd infra; terraform apply tfplan",
                WorkDir::Unknown,
            ),
            ("true || cd infra; terraform apply tfplan", WorkDir::Unknown),
            ("false && cd /srv; terraform apply tfplan", WorkDir::Unknown),
            ("cd infra || terraform apply tfplan", WorkDir::Unknown),
            ("cd infra && x || terraform apply tfplan", WorkDir::Unknown),
            ("cd infra || x && terraform apply tfplan", WorkDir::Unknown),
            ("cd infra && x & terraform apply tfplan", WorkDir::Unknown),
            ("cd infra | x; terraform apply tfplan", WorkDir::Unknown),
            ("cd infra && x | y; terraform apply tfplan", known("infra")),
            ("cd infra || x; terraform apply tfplan", known("infra")),
            ("cd infra && x; terraform apply tfplan", known("infra")),
            ("cd infra\nterraform apply tfplan", known("infra")),
            (
                "cd infra && cd ops; terraform apply tfplan",
                WorkDir::Unknown,
            ),
            // R4 fix round 3: quoting or escaping inside the word does not
            // stop the shell from running it as `cd`.
            (
                "cd infra; \\cd ..; terraform apply tfplan",
                WorkDir::Unknown,
            ),
            (
                "cd infra; c''d ..; terraform apply tfplan",
                WorkDir::Unknown,
            ),
            (
                "cd infra; c\"d\" ..; terraform apply tfplan",
                WorkDir::Unknown,
            ),
            (
                "cd infra; 'c'd ..; terraform apply tfplan",
                WorkDir::Unknown,
            ),
            (
                "cd infra; c\\d ..; terraform apply tfplan",
                WorkDir::Unknown,
            ),
            (
                "cd infra; $'\\x63d' ..; terraform apply tfplan",
                WorkDir::Unknown,
            ),
            (
                "cd infra; $\"cd\" ..; terraform apply tfplan",
                WorkDir::Unknown,
            ),
            (
                "cd infra; pu''shd ..; terraform apply tfplan",
                WorkDir::Unknown,
            ),
            (
                "cd infra; so\\urce x; terraform apply tfplan",
                WorkDir::Unknown,
            ),
            (
                "cd infra; { 'cd' ..; }; terraform apply tfplan",
                WorkDir::Unknown,
            ),
            ("cd infra; $X ..; terraform apply tfplan", WorkDir::Unknown),
            ("cd infra; echo ok; terraform apply tfplan", known("infra")),
        ] {
            assert_eq!(work_dir_at_last_segment(input), expected, "{input:?}");
        }
    }

    #[test]
    fn literal_cd_target_refuses_bare_names_under_cdpath() {
        let mut global = tirith_test_support::GlobalStateGuard::new().unwrap();
        global.set_env("CDPATH", "/srv/projects");
        assert_eq!(
            work_dir_at_last_segment("cd infra; terraform apply tfplan"),
            WorkDir::Unknown
        );
        assert_eq!(
            work_dir_at_last_segment("cd ./infra; terraform apply tfplan"),
            WorkDir::Known(PathBuf::from("./infra"))
        );
        global.remove_env("CDPATH");
        assert_eq!(
            work_dir_at_last_segment("cd infra; terraform apply tfplan"),
            WorkDir::Known(PathBuf::from("infra"))
        );
        // A CDPATH the input sets (in any segment, in any spelling) counts too.
        for input in [
            "CDPATH=/srv; cd infra; terraform apply tfplan",
            "export CDPATH=/srv; cd infra; terraform apply tfplan",
            "cdpath=(/srv); cd infra; terraform apply tfplan",
            "set CDPATH /srv\ncd infra\nterraform apply tfplan",
        ] {
            assert_eq!(
                work_dir_at_last_segment(input),
                WorkDir::Unknown,
                "{input:?}"
            );
        }
        for (input, expected) in [
            ("CDPATH=/srv; cd ./infra; terraform apply tfplan", "./infra"),
            // Set only after the cd ran.
            ("cd infra; CDPATH=/srv; terraform apply tfplan", "infra"),
        ] {
            assert_eq!(
                work_dir_at_last_segment(input),
                WorkDir::Known(PathBuf::from(expected)),
                "{input:?}"
            );
        }
    }

    #[test]
    fn check_plan_recorded_path_accepts_only_the_plain_command() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let recorded = |input: &str| {
            let segments = tokenize::tokenize(input, ShellType::Posix);
            check_plan_recorded_path(&segments[0])
        };
        for (input, expected) in [
            ("tirith iac check-plan tfplan", Some("tfplan")),
            ("tirith iac check-plan ./tfplan", Some("tfplan")),
            ("tirith iac check-plan 'out/tf plan'", Some("out/tf plan")),
            // Only the bare command word (R4 fix round 2).
            ("/usr/local/bin/tirith iac check-plan tfplan", None),
            ("./tirith iac check-plan tfplan", None),
            ("'tirith' iac check-plan tfplan", None),
            (
                "tirith iac check-plan --tool tofu --json tfplan",
                Some("tfplan"),
            ),
            (
                "tirith iac check-plan --format=json -- tfplan",
                Some("tfplan"),
            ),
            ("tirith iac check-plan", None),
            ("tirith iac check-plan a b", None),
            ("tirith iac check-plan --unknown tfplan", None),
            ("tirith iac check-plan \"$PLAN\"", None),
            ("tirith iac guard tfplan", None),
            ("XDG_STATE_HOME=/tmp/x tirith iac check-plan tfplan", None),
            ("echo tirith iac check-plan tfplan", None),
        ] {
            assert_eq!(recorded(input), expected.map(PathBuf::from), "{input:?}");
        }
    }

    #[test]
    fn check_plan_shortcut_needs_an_unconditional_check_plan_and_the_bare_tirith() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let shortcut = |input: &str| {
            let segments = tokenize::tokenize(input, ShellType::Posix);
            let last = segments.len() - 1;
            if tirith_lookup_may_be_rebound(&segments) {
                return None;
            }
            check_plan_chained_before(&segments, last)
        };
        for (input, plan) in [
            ("tirith iac check-plan p && terraform apply p", "p"),
            ("true; tirith iac check-plan p && terraform apply p", "p"),
            ("x & tirith iac check-plan p && terraform apply p", "p"),
            (
                "terraform plan -out p && tirith iac check-plan p && terraform apply p",
                "p",
            ),
            (
                "a && b && tirith iac check-plan p && terraform apply p",
                "p",
            ),
            (
                "tirith iac check-plan path/p && terraform -chdir=path apply p",
                "path/p",
            ),
        ] {
            assert_eq!(shortcut(input), Some(PathBuf::from(plan)), "{input:?}");
        }
        for input in [
            "true || tirith iac check-plan p && terraform apply p",
            "a || b && tirith iac check-plan p && terraform apply p",
            "echo | tirith iac check-plan p && terraform apply p",
            "tirith iac check-plan p || terraform apply p",
            "tirith iac check-plan p; terraform apply p",
            "tirith() { :; }; tirith iac check-plan p && terraform apply p",
            "f () { :; }; tirith iac check-plan p && terraform apply p",
            "alias tirith=true; tirith iac check-plan p && terraform apply p",
            "alias t=tirith; tirith iac check-plan p && terraform apply p",
            "hash -p /tmp/x/tirith tirith; tirith iac check-plan p && terraform apply p",
            "PATH=/tmp/x:$PATH; tirith iac check-plan p && terraform apply p",
            "export PATH=/tmp/x; tirith iac check-plan p && terraform apply p",
            "set -x PATH /tmp/x $PATH; tirith iac check-plan p && terraform apply p",
            "path=(/tmp/x $path); tirith iac check-plan p && terraform apply p",
            "functions[tir$x]=:; tirith iac check-plan p && terraform apply p",
            "eval \"$DEF\"; tirith iac check-plan p && terraform apply p",
            ". ./defs.sh; tirith iac check-plan p && terraform apply p",
            "source defs.sh; tirith iac check-plan p && terraform apply p",
            "/tmp/x/tirith iac check-plan p && terraform apply p",
        ] {
            assert_eq!(shortcut(input), None, "{input:?}");
        }
    }

    #[test]
    fn plan_gate_chain_and_unresolvable_directories() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let gated = Policy {
            iac_require_plan_before_apply: true,
            ..Policy::default()
        };
        let rules = |input: &str| {
            check(input, ShellType::Posix, &gated)
                .into_iter()
                .map(|f| (f.rule_id, f.title))
                .collect::<Vec<_>>()
        };
        // The chain the IacApplyWithoutPlan message recommends.
        for input in [
            "terraform plan -out tfplan && tirith iac check-plan tfplan && terraform apply tfplan",
            "tirith iac check-plan ./tfplan && tofu apply tfplan",
            "tirith iac check-plan infra/tfplan && terraform -chdir=infra apply tfplan",
        ] {
            assert_eq!(rules(input), Vec::new(), "{input:?}");
        }
        // Unresolvable working directory: fail closed with a distinct title.
        for input in [
            "cd \"$D\" && terraform apply tfplan",
            "terraform -chdir=$D apply tfplan",
            "popd; terraform apply tfplan",
            // The input itself sets a CDPATH, which can send a bare-name cd
            // elsewhere (an unexported shell variable is enough for cd).
            "CDPATH=/x; cd infra; terraform apply tfplan",
            "export CDPATH=/x; cd infra && terraform apply tfplan",
            "cdpath=(/x); cd infra; terraform apply tfplan",
            "set CDPATH /x; cd infra; terraform apply tfplan",
        ] {
            let found = rules(input);
            assert!(
                matches!(
                    found.as_slice(),
                    [(RuleId::IacPlanHashMismatch, title)] if title.contains("cannot be located")
                ),
                "{input:?}: {found:?}"
            );
        }
    }

    #[test]
    fn check_non_iac_leader_does_not_fire() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let policy = Policy::default();
        let findings = check("git apply -auto-approve", ShellType::Posix, &policy);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn check_terraform_apply_tfplan_no_policy_no_finding() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // No policy gate and no auto-approve → a clean apply yields nothing.
        let policy = Policy::default();
        let findings = check("terraform apply tfplan", ShellType::Posix, &policy);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn find_prod_context_with_empty_labels_returns_none() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let policy = Policy::default();
        assert!(find_prod_context(&policy).is_none());
    }

    #[test]
    fn is_critical_label_synonyms() {
        for s in ["critical", "Production", "PROD", "live", "p0", "p1"] {
            assert!(is_critical_label(s), "{s} should be critical");
        }
        for s in ["dev", "staging", "qa", "test", "p2", ""] {
            assert!(!is_critical_label(s), "{s} should NOT be critical");
        }
    }

    #[test]
    fn check_terraform_fmt_does_not_fire() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // `terraform fmt` is read-only — no apply/destroy verb.
        let policy = Policy::default();
        let findings = check("terraform fmt", ShellType::Posix, &policy);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn check_terraform_plan_does_not_fire() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let policy = Policy::default();
        let findings = check("terraform plan -out tfplan", ShellType::Posix, &policy);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn check_handles_chdir_global_flag() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let policy = Policy {
            iac_require_plan_before_apply: true,
            ..Policy::default()
        };
        let findings = check("terraform -chdir=infra apply", ShellType::Posix, &policy);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::IacApplyWithoutPlan)),
            "expected IacApplyWithoutPlan: {findings:?}",
        );
    }

    #[allow(dead_code)]
    fn _force_btreemap_use() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    #[test]
    fn policy_helper_builds_labeled_aws() {
        let p = policy_with_prod_label("aws", "prod");
        assert_eq!(
            p.context_labels.get("aws:prod").map(String::as_str),
            Some("critical")
        );
    }
}
