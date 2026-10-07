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
    check_executable_inputs(|| std::iter::once((input, shell)), None, policy)
}

/// [`check`] over every executable input of one command: the analysed
/// command first, then the nested shell bodies it runs (`bash -c '...'`,
/// `$(...)`, ...). A nested body does not start where tirith runs: it starts
/// in whatever directory, and with whatever `CDPATH`, `cd` functions and
/// aliases, the commands around it leave (`cd x; bash -c '...'`,
/// `CDPATH=/x bash -c '...'`), so it inherits what the other inputs may do
/// (`nested_start`). `masked_root` is the analysed command before heredoc
/// bodies were blanked out of its execution view (the first input), when
/// they were: an unquoted heredoc body still expands before its command
/// runs (`: <<EOF` + `${CDPATH:=/x}`; a bash 5.3 `${ cd x; }` in it moves
/// the command, also an external one).
pub(crate) fn check_executable_inputs<'a, I>(
    inputs: impl Fn() -> I,
    masked_root: Option<&str>,
    policy: &Policy,
) -> Vec<Finding>
where
    I: Iterator<Item = (&'a str, ShellType)>,
{
    let mut findings = Vec::new();
    // What each input may do to a nested body, computed once when a nested
    // body first needs it (`input_effects`).
    let mut effects: Option<Vec<InputEffects>> = None;
    // What the heredoc bodies blanked out of the root's view may do.
    let masked = || {
        let (view, shell) = inputs().next()?;
        masked_root.map(|raw| heredoc_effects(raw, view, shell))
    };
    for (k, (input, shell)) in inputs().enumerate() {
        let segments = tokenize::tokenize(input, shell);
        // Every rule here needs an IaC command in this input.
        if !segments.iter().any(|seg| iac_tool(seg, shell).is_some()) {
            continue;
        }
        let dirs = if k == 0 {
            // An unquoted heredoc body expands before its command runs.
            let (dir, hazard) = nested_start(masked().into_iter());
            DirTracker::start(dir, hazard)
        } else {
            let effects = effects.get_or_insert_with(|| {
                inputs()
                    .map(|(input, shell)| input_effects(input, shell))
                    .chain(masked())
                    .collect()
            });
            let others = effects
                .iter()
                .enumerate()
                .filter(|&(j, _)| j != k)
                .map(|(_, other)| *other);
            let (dir, hazard) = nested_start(others);
            DirTracker::start(dir, hazard)
        };
        findings.extend(check_segments(input, shell, policy, &segments, dirs));
    }
    findings
}

/// The IaC rules over the segments of one executable input, with the working
/// directory state it starts with.
fn check_segments(
    input: &str,
    shell: ShellType,
    policy: &Policy,
    segments: &[tokenize::Segment],
    mut dirs: DirTracker,
) -> Vec<Finding> {
    let tirith_may_be_rebound = tirith_lookup_may_be_rebound(segments);
    let mut findings = Vec::new();
    for (i, seg) in segments.iter().enumerate() {
        dirs.enter(seg);
        let recorded_by_previous = if tirith_may_be_rebound {
            None
        } else {
            check_plan_chained_before(segments, i)
        };
        // The segment's own words expand before its command runs, and an
        // expansion can change the directory (bash 5.3 `${ cd x; }` runs in
        // the shell) or run code that does.
        let work_dir = match dirs.current() {
            WorkDir::Elsewhere => WorkDir::Elsewhere,
            _ if iac_tool(seg, shell).is_some()
                && (segment_may_change_dir(seg, shell)
                    || segment_cd_hazard(seg, shell) == CdHazard::Rebind) =>
            {
                WorkDir::Unknown
            }
            dir => dir,
        };
        let plan_env = PlanEnv {
            work_dir: &work_dir,
            recorded_by_previous: recorded_by_previous.as_deref(),
        };
        findings.extend(check_segment(input, shell, policy, seg, &plan_env));
        dirs.leave(segments, i, shell);
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
    /// A nested shell started on another host, in a container or under
    /// another root directory (`ssh`, `docker exec`, `chroot`, ...): no path,
    /// not even an absolute one, names the file tirith can read.
    Elsewhere,
}

impl WorkDir {
    /// Where the shell will find `path` (already relative to the segment's
    /// working directory); `None` when that cannot be resolved statically.
    fn resolve(&self, path: &Path) -> Option<PathBuf> {
        match self {
            Self::Elsewhere => None,
            _ if path.is_absolute() => Some(path.to_path_buf()),
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
///
/// After a segment that may run code later or redefine `cd`
/// (`CdHazard::Rebind`, in this input or around a nested body) the directory
/// is unknown and no literal cd is followed. A cd to a bare name is followed
/// only while nothing may have set `CDPATH` (`CdHazard::Cdpath`).
#[derive(Debug, Clone)]
struct DirTracker {
    dir: WorkDir,
    /// The current and-or list resolved an unconditional `cd`.
    cd_in_list: bool,
    /// ... and a `||` has followed that cd in the list.
    or_after_cd: bool,
    /// The worst hazard of the segments scanned so far (and of the inputs
    /// around a nested body).
    hazard: CdHazard,
    /// Segments `[0, hazard_scanned)` of the input are folded into `hazard`.
    hazard_scanned: usize,
}

impl DirTracker {
    fn start(dir: WorkDir, hazard: CdHazard) -> Self {
        Self {
            dir,
            cd_in_list: false,
            or_after_cd: false,
            hazard,
            hazard_scanned: 0,
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
        if self.or_after_cd && self.dir != WorkDir::Elsewhere {
            WorkDir::Unknown
        } else {
            self.dir.clone()
        }
    }

    /// The worst hazard of `segments[..=i]` and of the start state.
    fn hazard_through(
        &mut self,
        segments: &[tokenize::Segment],
        i: usize,
        shell: ShellType,
    ) -> CdHazard {
        while self.hazard < CdHazard::Rebind && self.hazard_scanned <= i {
            let seg = &segments[self.hazard_scanned];
            self.hazard = self.hazard.max(segment_cd_hazard(seg, shell));
            self.hazard_scanned += 1;
        }
        self.hazard
    }

    /// Apply the directory change (if any) of `segments[i]`.
    fn leave(&mut self, segments: &[tokenize::Segment], i: usize, shell: ShellType) {
        let seg = &segments[i];
        if self.dir == WorkDir::Elsewhere {
            return;
        }
        // The hazard counts this segment too (`CDPATH=/x cd infra`).
        let hazard = self.hazard_through(segments, i, shell);
        // Code that may run before a later segment (a `DEBUG` trap, a `PS4`
        // traced by `set -x`, an alias or function for a later command, `fc`)
        // can change the directory there.
        if hazard == CdHazard::Rebind {
            self.dir = WorkDir::Unknown;
            return;
        }
        if !segment_may_change_dir(seg, shell) {
            return;
        }
        let target = if cd_runs_unconditionally(segments, i) {
            literal_cd_target(seg, shell)
        } else {
            None
        };
        let target = target
            .filter(|target| {
                !is_bare_cd_name(target)
                    || (hazard == CdHazard::None
                        && std::env::var_os("CDPATH").is_none_or(|v| v.is_empty()))
            })
            .map(PathBuf::from);
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

/// What a segment may do to a later literal `cd`, worst last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CdHazard {
    None,
    /// It may set `CDPATH` (zsh: `cdpath`), which a cd to a bare directory
    /// name searches before the working directory: an unexported shell
    /// variable is enough, so tirith's own environment cannot show it.
    Cdpath,
    /// It may redefine what `cd` / `pushd` run (a function, an alias, a
    /// disabled builtin, a startup file of a nested shell), or run code later
    /// (a trap, a traced `PS4`): the directory becomes unknown and no later
    /// literal cd is trusted.
    Rebind,
}

/// The hazard of every segment of `text` (a whole command, where segment
/// positions are not known).
fn text_cd_hazard(text: &str, shell: ShellType) -> CdHazard {
    tokenize::tokenize(text, shell)
        .iter()
        .map(|seg| segment_cd_hazard(seg, shell))
        .max()
        .unwrap_or(CdHazard::None)
}

/// What the heredoc bodies that `shell_execution_view` blanked out of the
/// root's view (`raw` -> `view`) may do. An unquoted heredoc body expands in
/// the shell before its command runs, so a directory-changing word in a body
/// (bash 5.3 `${ cd x; }`) makes the whole line start in an unknown
/// directory, and the worst hazard of the raw line counts from its start.
fn heredoc_effects(raw: &str, view: &str, shell: ShellType) -> InputEffects {
    let dir_change_words = |text: &str| {
        let is_dir_change = |w: &str| DIR_CHANGE_WORDS.contains(&w.to_ascii_lowercase().as_str());
        split_shell_words(text)
            .filter(|w| is_dir_change(&normalize_shell_token(w, shell)))
            .count()
            + split_shell_words(&without_quoting(text))
                .filter(|w| is_dir_change(w))
                .count()
    };
    InputEffects {
        changes_dir: dir_change_words(raw) > dir_change_words(view),
        elsewhere: false,
        hazard: text_cd_hazard(raw, shell),
    }
}

/// What one executable input may do to a nested body run by the command.
#[derive(Debug, Clone, Copy)]
struct InputEffects {
    /// A segment other than the last may change the directory (a later
    /// segment may run the body there), or starts its child in another one.
    changes_dir: bool,
    /// A segment starts its child on another host, in a container or under
    /// another root (`starts_child_on_other_filesystem`).
    elsewhere: bool,
    /// The worst `CdHazard` of its segments.
    hazard: CdHazard,
}

fn input_effects(input: &str, shell: ShellType) -> InputEffects {
    let segments = tokenize::tokenize(input, shell);
    let mut effects = InputEffects {
        changes_dir: false,
        elsewhere: false,
        hazard: CdHazard::None,
    };
    for (i, seg) in segments.iter().enumerate() {
        effects.elsewhere |= starts_child_on_other_filesystem(seg, shell);
        effects.changes_dir |= starts_child_elsewhere(seg, shell)
            || (i + 1 < segments.len()
                && !runs_in_child_process(seg, shell)
                && segment_may_change_dir(seg, shell));
        if effects.hazard < CdHazard::Rebind {
            effects.hazard = effects.hazard.max(segment_cd_hazard(seg, shell));
        }
    }
    effects
}

/// `true` when the segment's command is a program that runs its arguments
/// in another process (a shell, `env`, `sudo`, ...), so a `cd` among them
/// (`sh -c 'cd infra && ...'`) cannot change this shell's directory. A
/// function or alias of that name defined on the line is a
/// `CdHazard::Rebind`, which makes a nested body start in an unknown
/// directory anyway.
fn runs_in_child_process(seg: &tokenize::Segment, shell: ShellType) -> bool {
    seg.command
        .as_deref()
        .is_some_and(|cmd| CHILD_RUNNERS.contains(&command_basename(cmd, shell).as_str()))
}

/// `true` when the segment's command starts the program it runs (a nested
/// shell body among them) in another directory: `env -C dir`, `sudo -D dir`
/// or a login `sudo -i` / `su -`, PowerShell `-WorkingDirectory`, `find
/// -execdir`, or anywhere `starts_child_on_other_filesystem` covers.
fn starts_child_elsewhere(seg: &tokenize::Segment, shell: ShellType) -> bool {
    if starts_child_on_other_filesystem(seg, shell) {
        return true;
    }
    let Some(cmd) = seg.command.as_deref() else {
        return false;
    };
    let args: Vec<String> = seg
        .args
        .iter()
        .map(|arg| normalize_shell_token(arg, shell))
        .collect();
    let short_option_with = |word: &str, letters: &[char]| {
        word.starts_with('-')
            && !word.starts_with("--")
            && word.chars().skip(1).any(|c| letters.contains(&c))
    };
    let any_arg = |pred: &dyn Fn(&str) -> bool| args.iter().any(|arg| pred(arg));
    match command_basename(cmd, shell).as_str() {
        "env" => any_arg(&|a| short_option_with(a, &['C']) || a.starts_with("--chdir")),
        "sudo" => any_arg(&|a| {
            short_option_with(a, &['D', 'i']) || a.starts_with("--chdir") || a == "--login"
        }),
        "su" | "runuser" => {
            any_arg(&|a| a == "-" || short_option_with(a, &['l']) || a == "--login")
        }
        "pwsh" | "powershell" => any_arg(&|a| a.to_ascii_lowercase().starts_with("-w")),
        "find" => any_arg(&|a| a == "-execdir" || a == "-okdir"),
        _ => false,
    }
}

/// `true` when the segment's command starts the program it runs on another
/// host, in a container, or under another root or mount namespace (`ssh`,
/// `docker`, `kubectl`, `chroot`, `bwrap`, ...), where even an absolute path
/// may name a file tirith cannot read.
fn starts_child_on_other_filesystem(seg: &tokenize::Segment, shell: ShellType) -> bool {
    const RUNNERS: &[&str] = &[
        "bwrap",
        "chroot",
        "docker",
        "firejail",
        "incus",
        "kubectl",
        "lxc",
        "machinectl",
        "nerdctl",
        "nsenter",
        "podman",
        "ssh",
        "systemd-run",
        "unshare",
        "vagrant",
    ];
    seg.command
        .as_deref()
        .is_some_and(|cmd| RUNNERS.contains(&command_basename(cmd, shell).as_str()))
}

/// Where a nested shell body starts, from the effects of the other
/// executable inputs of the same command (the enclosing command and its
/// other nested bodies: which of them encloses the body, and where, is not
/// known). The body starts in an unknown directory when one of them may
/// change the directory before a later segment (`cd x; bash -c '...'`),
/// starts its child elsewhere (`env -C x sh -c '...'`) or may run code
/// later or in the child (`trap`, functions, startup files), on another
/// host or filesystem (`ssh host '...'`: `WorkDir::Elsewhere`), and it
/// inherits their worst `CdHazard` (`CDPATH=/x bash -c '...'`).
/// Over-approximates: a false positive only makes a plan path in the body
/// unresolvable.
fn nested_start(others: impl Iterator<Item = InputEffects>) -> (WorkDir, CdHazard) {
    let (changes_dir, elsewhere, hazard) = others.fold(
        (false, false, CdHazard::None),
        |(dir, elsewhere, hazard), other| {
            (
                dir || other.changes_dir,
                elsewhere || other.elsewhere,
                hazard.max(other.hazard),
            )
        },
    );
    if elsewhere {
        (WorkDir::Elsewhere, hazard)
    } else if changes_dir || hazard == CdHazard::Rebind {
        (WorkDir::Unknown, hazard)
    } else {
        (WorkDir::Known(PathBuf::new()), hazard)
    }
}

/// Words that redefine commands, disable builtins, or run code from
/// elsewhere: `fc` re-runs a history entry, zsh `emulate -c` evaluates its
/// argument and `zmodload` can load a builtin (`.` and zsh's `r` count only
/// as a command, see `runs_as_command`).
const CD_REBINDING_WORDS: &[&str] = &[
    "alias",
    "aliases",
    "autoload",
    "disable",
    "emulate",
    "enable",
    "eval",
    "fc",
    "function",
    "functions",
    "source",
    "trap",
    "zmodload",
];

/// Variables and options whose value runs as code, in this shell or in a
/// nested one, or chooses the startup files a nested shell runs (which may
/// set `CDPATH` or define `cd`): bash `PS4` (a `${ ...; }` substitution in it
/// runs in this shell at every command traced by `set -x`, bash 5.3+),
/// `BASH_ENV`, `--rcfile`, `--init-file` and exported `BASH_FUNC_*`
/// functions, zsh `ZDOTDIR`, and fish `--init-command` and its configuration
/// under the XDG directories. Looked for anywhere in a segment.
const CODE_VARIABLE_NAMES: &[&str] = &[
    "bash_env",
    "bash_func_",
    "init-command",
    "init-file",
    "ps4",
    "rcfile",
    "xdg_config_dirs",
    "xdg_config_home",
    "xdg_data_dirs",
    "zdotdir",
];

/// Variables that also choose a nested shell's startup files, but whose
/// names are too short to look for as a substring: `HOME` (zsh's
/// `~/.zshenv`, fish's configuration, login shells) and `ENV` (an
/// interactive `sh`). They count where a segment assigns them.
const STARTUP_VARIABLES: &[&str] = &["env", "home"];

/// Builtins that set a variable from data or from their arguments' values
/// (`read y < f; (( y ))` sets whatever `f` names; `printf -v y %s%s CD
/// PATH`), so the variable a later expansion or arithmetic evaluation
/// assigns cannot be read from the line.
const VARIABLE_READING_WORDS: &[&str] = &[
    "for",
    "getln",
    "getopts",
    "mapfile",
    "readarray",
    "read",
    "select",
    "sysread",
    "vared",
    "zparseopts",
];

/// Builtins that assign the variables their arguments name.
const DECLARING_WORDS: &[&str] = &[
    "declare", "export", "float", "integer", "let", "local", "nameref", "private", "readonly",
    "set", "typeset",
];

/// Programs that run their arguments in a child process (a shell, `env`,
/// `sudo`, ...); see `runs_in_child_process`.
const CHILD_RUNNERS: &[&str] = &[
    "ash", "bash", "dash", "doas", "env", "fish", "ksh", "mksh", "nice", "nohup", "pwsh", "setsid",
    "sh", "stdbuf", "su", "sudo", "timeout", "xargs", "zsh",
];

/// What `seg` may do to a later literal `cd` (see `CdHazard`). This is a
/// list of known shell features, checked with over-approximation, not a
/// proof: words count as the shell decodes them and with every quote and
/// escape character dropped, as in `segment_may_change_dir`, and expansion
/// syntax counts even inside single quotes.
///
/// `Rebind`: a function definition; `alias`, `enable` / `disable`, `eval`,
/// `source`, `.`, `trap`, `autoload`, `fc`, zsh `r`, `emulate` or
/// `zmodload`; a command word built by an expansion; a variable or option
/// that runs code or picks a nested shell's startup files
/// (`CODE_VARIABLE_NAMES`, an assigned `HOME` or `ENV`, fish `-C`); a
/// variable named through an expansion, brace or glob by a builtin that
/// assigns it or by a program that passes it to a child (`export "$n=$v"`,
/// `export C{D,}PATH=/x`, `env "$n=$v" bash -c '...'`), or a nameref
/// (`declare -n`), since such a variable may be any of those; or any
/// PowerShell / cmd segment (tirith models neither language's variables,
/// functions or aliases).
///
/// `Cdpath`: the segment names `CDPATH` in any such spelling (`CD''PATH`,
/// `CD\PATH`, `$'\x43DPATH'`, a backslash-newline inside the name); has any
/// expansion syntax (`v=CD; y=${v}PATH=5; : $((y))` assigns the variable the
/// value of `y` names, and text the shell keeps literal can still be
/// evaluated later in this shell, as in `declare -a 'a=($((...)))'`); reads
/// a variable from data or arguments (`read`, `printf -v`, `for`, ...); or
/// passes a brace or glob pattern to a declaring builtin or into an array
/// assignment (`y=(*); (( y ))` assigns whatever a file name says).
fn segment_cd_hazard(seg: &tokenize::Segment, shell: ShellType) -> CdHazard {
    if matches!(shell, ShellType::PowerShell | ShellType::Cmd) {
        return CdHazard::Rebind;
    }
    let raw = seg.raw.as_str();
    let stripped = without_quoting(raw);
    // The whole segment as the shell decodes its quoting (a `$'...'` string
    // may hold spaces and brackets), and each word decoded, then lower-cased.
    let decoded_raw = normalize_shell_token(raw, shell);
    let words: Vec<String> = split_shell_words(raw)
        .filter(|w| !w.is_empty())
        .map(|w| normalize_shell_token(w, shell))
        .collect();
    let decoded: Vec<String> = words.iter().map(|w| w.to_ascii_lowercase()).collect();
    let names = |needle: &str| {
        contains_ignore_ascii_case(raw, needle)
            || contains_ignore_ascii_case(&stripped, needle)
            || contains_ignore_ascii_case(&decoded_raw, needle)
            || decoded.iter().any(|w| w.contains(needle))
    };
    let has_word = |list: &[&str]| {
        decoded.iter().any(|w| list.contains(&w.as_str()))
            || split_shell_words(&stripped)
                .any(|w| list.iter().any(|entry| w.eq_ignore_ascii_case(entry)))
    };
    let declaring = has_word(DECLARING_WORDS);
    let assigns = |name: &str| {
        decoded.iter().any(|w| {
            w.strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('=') || rest.starts_with("+="))
        }) || (declaring && decoded.iter().any(|w| w == name))
    };
    let expands = has_expansion_syntax(raw, shell) || has_expansion_syntax(&decoded_raw, shell);
    let sets_from_data = has_word(VARIABLE_READING_WORDS)
        || (has_word(&["printf"]) && decoded.iter().any(|w| w.starts_with("-v")));
    let passes_to_child = decoded.iter().any(|w| {
        let base = w.rsplit('/').next().unwrap_or(w);
        CHILD_RUNNERS.contains(&base)
    });
    let nameref = has_word(&["nameref"])
        || (declaring
            && decoded
                .iter()
                .any(|w| w.starts_with('-') && !w.starts_with("--") && w.contains('n')));
    let command_is_expanded = seg.command.as_deref().is_some_and(|cmd| {
        cmd.contains(['$', '`']) || (shell == ShellType::Fish && cmd.contains('('))
    });

    if command_is_expanded
        || has_word(CD_REBINDING_WORDS)
        || runs_as_command(seg, shell, &[".", "r"])
        || defines_a_function(raw)
        || CODE_VARIABLE_NAMES.iter().any(|name| names(name))
        || STARTUP_VARIABLES.iter().any(|name| assigns(name))
        || runs_fish_init_command(&words)
        || nameref
        || ((declaring || sets_from_data || passes_to_child)
            && names_a_variable_dynamically(raw, shell))
    {
        return CdHazard::Rebind;
    }

    if names("cdpath")
        || expands
        || sets_from_data
        || (declaring && raw.contains(['{', '}', '*', '?', '[', ']']))
        || (raw.contains("=(") && raw.contains(['{', '*', '?', '[']))
    {
        return CdHazard::Cdpath;
    }
    CdHazard::None
}

/// `true` when some word of `raw` (split at whitespace only) names a
/// variable through an expansion, a brace or a glob: the part before its
/// first `=` (all of it when there is none) has expansion syntax or one of
/// `{ } * ? [ ]` (`"$n=$v"`, `${v}PATH=/x`, `C{D,}PATH=/x`, `$x`).
fn names_a_variable_dynamically(raw: &str, shell: ShellType) -> bool {
    raw.split_whitespace().any(|word| {
        let name = word.split('=').next().unwrap_or(word);
        has_expansion_syntax(name, shell) || name.contains(['{', '}', '*', '?', '[', ']'])
    })
}

/// `true` when the segment runs fish with an init command (`-C`, also
/// bundled with other short options, or a prefix of `--init-command`),
/// which runs before the body and may define `cd`.
fn runs_fish_init_command(words: &[String]) -> bool {
    words
        .iter()
        .any(|w| w.rsplit('/').next().is_some_and(|base| base == "fish"))
        && words.iter().any(|w| {
            (w.starts_with('-') && !w.starts_with("--") && w.contains('C'))
                || w.starts_with("--ini")
        })
}

/// `raw` with backslash-newline continuations removed and then every quote
/// and escape character dropped (`CD''PATH`, `C"D"PATH`, `CD\` + newline +
/// `PATH` all become `CDPATH`).
fn without_quoting(raw: &str) -> String {
    raw.replace("\\\r\n", "")
        .replace("\\\n", "")
        .chars()
        .filter(|c| !matches!(c, '\'' | '"' | '\\' | '`' | '^' | '$'))
        .collect()
}

fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

/// `true` when the segment defines a shell function (`f() { ...; }`,
/// `function f { ...; }`): `(` then `)` with only whitespace between.
fn defines_a_function(raw: &str) -> bool {
    let mut open = false;
    for c in raw.chars() {
        match c {
            '(' => open = true,
            ')' if open => return true,
            c if c.is_whitespace() => {}
            _ => open = false,
        }
    }
    false
}

/// `true` when the segment runs one of `words` as a command: its command
/// word, or such a word in command position anywhere in it (`{ . env.sh; }`,
/// `if . env.sh`, `builtin . env.sh`, `X=1 . env.sh`). For `.` (source a
/// file), `cd .` and `find . -name x` do not count; for zsh's `r` (re-run
/// the previous command), `grep r` does not.
fn runs_as_command(seg: &tokenize::Segment, shell: ShellType, words: &[&str]) -> bool {
    const COMMAND_STARTERS: &[&str] = &[
        "!", "builtin", "command", "do", "elif", "else", "exec", "if", "then", "time", "until",
        "while",
    ];
    if seg
        .command
        .as_deref()
        .is_some_and(|cmd| words.contains(&normalize_shell_token(cmd, shell).as_str()))
    {
        return true;
    }
    let is_assignment = |word: &str| {
        word.split_once('=').is_some_and(|(name, _)| {
            !name.is_empty()
                && !name.starts_with(|c: char| c.is_ascii_digit())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
    };
    // `true` while the next word is in command position.
    let mut command_position = true;
    for word in split_shell_words(&seg.raw).filter(|w| !w.is_empty()) {
        let word = normalize_shell_token(word, shell);
        if command_position && words.contains(&word.as_str()) {
            return true;
        }
        command_position = COMMAND_STARTERS.contains(&word.to_ascii_lowercase().as_str())
            || (command_position && is_assignment(&word));
    }
    false
}

/// `true` when `text` has expansion syntax anywhere, quoted or not: a `$`
/// parameter, arithmetic or command expansion (`$?`, `$#`, `$$`, `$!` and
/// `$-` are numbers or flags and cannot spell a name; `$'...'` and `$"..."`
/// are quotes), a backquote, or, in fish, a `(command)` substitution.
/// Quoting is ignored on purpose: text the shell keeps literal here can still
/// be evaluated later in this shell (`PS4='$((...))'` under `set -x`,
/// `declare -a 'a=($((...)))'`, `[ -v 'a[$((...))]' ]`).
fn has_expansion_syntax(text: &str, shell: ShellType) -> bool {
    let fish = shell == ShellType::Fish;
    let bytes = text.as_bytes();
    bytes.iter().enumerate().any(|(i, &b)| match b {
        b'$' => match bytes.get(i + 1) {
            Some(b'?' | b'#' | b'$' | b'!' | b'-') | None => false,
            Some(c) => {
                c.is_ascii_alphanumeric()
                    || matches!(
                        c,
                        b'_' | b'{' | b'(' | b'[' | b'@' | b'*' | b'=' | b'~' | b'^' | b'+'
                    )
            }
        },
        b'`' => !fish,
        b'(' => fish,
        _ => false,
    })
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
/// a `{ ...; }` group), sources a file (`. file`, also `{ . file; }`), or has
/// a command word built by an expansion (`$X ..`). A word counts with its
/// quoting and escapes removed, the way the shell reads it (`\cd`, `c''d`,
/// `'c'd`, `$'\x63d'`, `c\` + newline + `d`, PowerShell `` c`d ``, cmd `c^d`
/// are all `cd`). Over-approximates: a false positive only makes a later
/// relative plan path unresolvable.
fn segment_may_change_dir(seg: &tokenize::Segment, shell: ShellType) -> bool {
    if seg
        .command
        .as_deref()
        .is_some_and(|cmd| cmd.contains(['$', '`']))
        || runs_as_command(seg, shell, &["."])
    {
        return true;
    }
    let is_dir_change = |w: &str| DIR_CHANGE_WORDS.contains(&w.to_ascii_lowercase().as_str());
    // Each word as the shell decodes it (quotes, backslashes, ANSI-C escapes).
    let decoded =
        split_shell_words(&seg.raw).any(|w| is_dir_change(&normalize_shell_token(w, shell)));
    // And with every quote and escape character simply dropped, so an escape
    // character that is also a separator above (PowerShell's backtick) or a
    // quoting form the decoder leaves alone cannot hide the word either.
    decoded || split_shell_words(&without_quoting(&seg.raw)).any(is_dir_change)
}

/// `raw` split at whitespace, operators and brackets (quotes are kept).
fn split_shell_words(raw: &str) -> impl Iterator<Item = &str> {
    raw.split(|c: char| {
        c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')' | '{' | '}' | '`')
    })
}

/// The target of a plain `cd <literal>` / `pushd <literal>` segment in a POSIX
/// or fish shell; `None` for anything else (no or several operands, `-`,
/// `+N`, expansions, quoting inside the word, PowerShell / cmd syntax).
/// Whether a `CDPATH` or a redefined `cd` may send it elsewhere is
/// `DirTracker::leave`'s call.
fn literal_cd_target(seg: &tokenize::Segment, shell: ShellType) -> Option<&str> {
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
    literal_path_word(target)
}

/// `true` for a cd operand the shells look up in `CDPATH`: not absolute and
/// not starting with a `.` or `..` component.
fn is_bare_cd_name(target: &str) -> bool {
    !(target.starts_with('/')
        || target.starts_with("./")
        || target.starts_with("../")
        || target == "."
        || target == "..")
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

/// The IaC tool a segment runs as its command, if any.
fn iac_tool(seg: &tokenize::Segment, shell: ShellType) -> Option<IacTool> {
    match command_basename(seg.command.as_deref()?, shell).as_str() {
        "terraform" => Some(IacTool::Terraform),
        "pulumi" => Some(IacTool::Pulumi),
        "tofu" => Some(IacTool::Tofu),
        _ => None,
    }
}

fn check_segment(
    input: &str,
    shell: ShellType,
    policy: &Policy,
    seg: &tokenize::Segment,
    plan_env: &PlanEnv<'_>,
) -> Vec<Finding> {
    let Some(tool) = iac_tool(seg, shell) else {
        return Vec::new();
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
                             (`cd`, `pushd`, `-chdir=`, ...) or other shell code that tirith \
                             cannot resolve, or in a shell started on another host, in a \
                             container or under another root, so it cannot verify which plan \
                             file will be applied. Use an absolute plan path, or run `tirith \
                             iac check-plan <plan> && {} apply <plan>` from the plan's \
                             directory.",
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
        work_dir_at_last_segment_in(input, ShellType::Posix)
    }

    fn work_dir_at_last_segment_in(input: &str, shell: ShellType) -> WorkDir {
        let segments = tokenize::tokenize(input, shell);
        let mut dirs = DirTracker::start(WorkDir::Known(PathBuf::new()), CdHazard::None);
        for (i, seg) in segments.iter().enumerate() {
            dirs.enter(seg);
            if i + 1 == segments.len() {
                break;
            }
            dirs.leave(&segments, i, shell);
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
        // A CDPATH the input sets (in any segment) counts too.
        for input in [
            "CDPATH=/srv; cd infra; terraform apply tfplan",
            "export CDPATH=/srv; cd infra; terraform apply tfplan",
            "cdpath=(/srv); cd infra; terraform apply tfplan",
            "set CDPATH /srv\ncd infra\nterraform apply tfplan",
            // Fix round 1: in any spelling the shell decodes to CDPATH ...
            "export CD''PATH=/srv; cd infra; terraform apply tfplan",
            "export C''DPATH=/srv; cd infra; terraform apply tfplan",
            "export CD\\PATH=/srv; cd infra; terraform apply tfplan",
            "declare -x CD\\PATH=/srv; cd infra; terraform apply tfplan",
            "export C\"D\"PATH=/srv; cd infra; terraform apply tfplan",
            "declare -x \"CD\"\"PATH=/srv\"; cd infra; terraform apply tfplan",
            "export $'\\x43DPATH'=/srv; cd infra; terraform apply tfplan",
            "printf -v C''DPATH /srv; cd infra; terraform apply tfplan",
            "export CD\\\nPATH=/srv\ncd infra\nterraform apply tfplan",
            // ... or through a name or value built by an expansion ...
            "v=CD; export \"${v}PATH=/srv\"; cd infra; terraform apply tfplan",
            "n=CD; export ${n}PATH=/srv; cd infra; terraform apply tfplan",
            "x=CD; y=\"${x}PATH=5\"; : $((y)); cd infra; terraform apply tfplan",
            "a=CD b=PATH=5; [[ $a$b -eq 1 ]]; cd infra; terraform apply tfplan",
            "export `echo CD`PATH=/srv; cd infra; terraform apply tfplan",
            // ... a brace or glob pattern, a variable read from data or
            // arguments, or a nameref.
            "export C{D,}PATH=/srv; cd infra; terraform apply tfplan",
            "export {CD,X}PATH=/srv; cd infra; terraform apply tfplan",
            "export C?PATH=x; cd infra; terraform apply tfplan",
            "read y < f; (( y )); cd infra; terraform apply tfplan",
            "printf -v y %s%s=5 CD PATH; (( y )); cd infra; terraform apply tfplan",
            "for y in C{D,}PATH=5; do (( y )); done; cd infra; terraform apply tfplan",
            "declare -n r; r=x; cd infra; terraform apply tfplan",
            // Expansion syntax counts inside single quotes too: bash later
            // evaluates it in a traced `PS4`, a quoted compound array
            // assignment or a `-v` subscript (`CDPATH=5` from `$y$z`).
            "y=CD; z=PATH; PS4='$(($y$z=5))'; set -x; cd infra; terraform apply tfplan",
            "y=CD; z=PATH; declare -a 'a=($(($y$z=5)))'; cd infra; terraform apply tfplan",
            "y=CD; z=PATH; [ -v 'a[$(($y$z=5))]' ]; cd infra; terraform apply tfplan",
            "declare -a $'a=(\\x24((y=5)))'; cd infra; terraform apply tfplan",
            "echo '$HOME'; cd infra; terraform apply tfplan",
            // An array assignment of a glob or brace pattern (a file named
            // `CDPATH=5`, then `(( y ))`).
            "y=(*); (( y )); cd infra; terraform apply tfplan",
            "y=(C{D,}PATH=5); (( y )); cd infra; terraform apply tfplan",
        ] {
            assert_eq!(
                work_dir_at_last_segment(input),
                WorkDir::Unknown,
                "{input:?}"
            );
        }
        assert_eq!(
            work_dir_at_last_segment_in(
                "set -gx (echo CD)PATH /srv\ncd infra\nterraform apply tfplan",
                ShellType::Fish
            ),
            WorkDir::Unknown
        );
        for (input, expected) in [
            ("CDPATH=/srv; cd ./infra; terraform apply tfplan", "./infra"),
            (
                "export CD''PATH=/srv; cd ../infra; terraform apply tfplan",
                "../infra",
            ),
            (
                "export TF_VAR_region=$REGION; cd /srv/infra; terraform apply tfplan",
                "/srv/infra",
            ),
            // Set only after the cd ran.
            ("cd infra; CDPATH=/srv; terraform apply tfplan", "infra"),
            (
                "cd infra; export C''DPATH=/srv; terraform apply tfplan",
                "infra",
            ),
            // Nothing that can reach CDPATH.
            (
                "export TF_LOG=1 AWS_PROFILE=dev; cd infra; terraform apply tfplan",
                "infra",
            ),
            (
                "set -euo pipefail; cd infra; terraform apply tfplan",
                "infra",
            ),
            (
                "echo \"exit=$?\"; cd infra; terraform apply tfplan",
                "infra",
            ),
            (
                "echo 'plain text'; cd infra; terraform apply tfplan",
                "infra",
            ),
            ("find . -name x; cd infra; terraform apply tfplan", "infra"),
            (
                "grep r notes.txt; cd infra; terraform apply tfplan",
                "infra",
            ),
        ] {
            assert_eq!(
                work_dir_at_last_segment(input),
                WorkDir::Known(PathBuf::from(expected)),
                "{input:?}"
            );
        }
    }

    #[test]
    fn literal_cd_is_not_trusted_after_cd_may_be_redefined() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // A function, alias, disabled builtin, sourced file, eval or trap can
        // make a later `cd`, even to an absolute path, go elsewhere.
        for input in [
            "cd() { builtin cd /x/\"$1\"; }; cd /srv/infra; terraform apply tfplan",
            "function cd { builtin cd /x; }; cd /srv/infra; terraform apply tfplan",
            "alias cd='cd /x/'\ncd ./infra\nterraform apply tfplan",
            "enable -n cd; cd /srv/infra; terraform apply tfplan",
            "source env.sh; cd /srv/infra; terraform apply tfplan",
            "{ . ./env.sh; }; cd /srv/infra; terraform apply tfplan",
            "eval \"$DEF\"; cd /srv/infra; terraform apply tfplan",
            "trap 'cd /x' DEBUG; cd /srv/infra; terraform apply tfplan",
            "$X; cd /srv/infra; terraform apply tfplan",
            // `.` in command position sources a file, which may cd.
            "{ . ./env.sh; }; terraform apply tfplan",
            "if . ./env.sh; then terraform apply tfplan; fi",
            // A backslash-newline inside the `cd` word.
            "cd infra\nc\\\nd ..\nterraform apply tfplan",
            // Fix round 1: a traced `PS4` runs a bash 5.3 `${ ...; }` in the
            // shell; a variable named through an expansion, brace or
            // nameref may be `PS4`; `fc`, zsh `r` and `emulate` run code.
            "PS4=\"$v\"; set -x; cd /srv/infra; terraform apply tfplan",
            "n=PS4; export \"$n=$v\"; set -x; cd /srv/infra; terraform apply tfplan",
            "export {P,Q}S4=\"$v\"; set -x; cd /srv/infra; terraform apply tfplan",
            "printf -v \"$n\" %s \"$v\"; cd /srv/infra; terraform apply tfplan",
            "declare -n r=\"$n\"; cd /srv/infra; terraform apply tfplan",
            "fc -s; cd /srv/infra; terraform apply tfplan",
            "r; cd /srv/infra; terraform apply tfplan",
            "emulate sh -c \"$x\"; cd /srv/infra; terraform apply tfplan",
            // Code that runs later can move the directory with no later cd.
            "trap \"$x\" DEBUG; terraform apply tfplan",
            "PS4=\"$v\"; set -x; terraform apply tfplan",
            "alias terraform=\"$x\"\nterraform apply tfplan",
            "cd /srv/infra; trap \"$x\" DEBUG; terraform apply tfplan",
        ] {
            assert_eq!(
                work_dir_at_last_segment(input),
                WorkDir::Unknown,
                "{input:?}"
            );
        }
        for (input, expected) in [
            ("cd /srv/infra; terraform apply tfplan", "/srv/infra"),
            ("echo hi; cd /srv; terraform apply tfplan", "/srv"),
            ("cd \"$D\"; cd /srv; terraform apply tfplan", "/srv"),
            ("cd .; terraform apply tfplan", "."),
            (
                "export TF_VAR_region=\"$REGION\"; cd /srv; terraform apply tfplan",
                "/srv",
            ),
            ("grep r notes.txt; cd /srv; terraform apply tfplan", "/srv"),
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
            // Fix round 1: the spellings reviewers ran through bash.
            "export CD''PATH=/x; cd infra; terraform apply tfplan",
            "export CD\\PATH=/x; cd infra; terraform apply tfplan",
            "declare -x \"CD\"\"PATH=/x\"; cd infra; terraform apply tfplan",
            "v=CD; export \"${v}PATH=/x\"; cd infra; terraform apply tfplan",
            "export $'\\x43DPATH'=/x; cd infra; terraform apply tfplan",
            "export C''DPATH=/x; cd infra; terraform apply tfplan",
            "export C\"D\"PATH=/x; cd infra; terraform apply tfplan",
            "declare -x CD\\PATH=/x; cd infra; terraform apply tfplan",
            "printf -v C''DPATH /x; cd infra; terraform apply tfplan",
            "n=CD; export ${n}PATH=/x; cd infra; terraform apply tfplan",
            "y=CD; z=PATH; PS4='$(($y$z=5))'; set -x; cd infra; terraform apply tfplan",
            "y=CD; z=PATH; declare -a 'a=($(($y$z=5)))'; cd infra; terraform apply tfplan",
            // Code that may run before the apply, and the apply's own
            // expansions (bash 5.3 `${ cd x; }` runs in the shell).
            "trap \"$x\" DEBUG; terraform apply tfplan",
            "terraform apply tfplan \"${ cd /x; }\"",
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
    fn nested_bodies_start_where_the_enclosing_command_leaves_them() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let gated = Policy {
            iac_require_plan_before_apply: true,
            ..Policy::default()
        };
        // The executable inputs the engine passes: the command, then the
        // nested body it runs.
        let titles = |inputs: &[(&str, ShellType)], masked_root: Option<&str>| {
            check_executable_inputs(|| inputs.iter().copied(), masked_root, &gated)
                .into_iter()
                .map(|f| f.title)
                .collect::<Vec<_>>()
        };
        let unlocatable =
            |titles: &[String]| titles.len() == 1 && titles[0].contains("cannot be located");
        let posix = ShellType::Posix;
        for (outer, body) in [
            // A CDPATH the outer command gives the nested shell.
            (
                "CDPATH=/x bash -c 'cd infra; terraform apply tfplan'",
                "cd infra; terraform apply tfplan",
            ),
            (
                "export CDPATH=/x; bash -c 'cd infra; terraform apply tfplan'",
                "cd infra; terraform apply tfplan",
            ),
            (
                "env CDPATH=/x sh -c 'cd infra && terraform apply tfplan'",
                "cd infra && terraform apply tfplan",
            ),
            (
                "export C''DPATH=/x; bash -c 'cd infra; terraform apply tfplan'",
                "cd infra; terraform apply tfplan",
            ),
            // A directory change before the nested shell runs.
            (
                "cd other; bash -c 'terraform apply tfplan'",
                "terraform apply tfplan",
            ),
            (
                "cd other && sh -c 'terraform apply tfplan'",
                "terraform apply tfplan",
            ),
            // A startup file or a trap of the outer command.
            (
                "BASH_ENV=./x.sh bash -c 'cd /srv/infra && terraform apply tfplan'",
                "cd /srv/infra && terraform apply tfplan",
            ),
            (
                "trap \"bash -c 'terraform apply tfplan'\" EXIT; cd other",
                "terraform apply tfplan",
            ),
            // A wrapper that starts the nested shell in another directory.
            (
                "env -C other sh -c 'terraform apply tfplan'",
                "terraform apply tfplan",
            ),
            (
                "sudo -D other sh -c 'terraform apply tfplan'",
                "terraform apply tfplan",
            ),
            (
                "sudo -i sh -c 'terraform apply tfplan'",
                "terraform apply tfplan",
            ),
            (
                "find . -name other -execdir sh -c 'terraform apply tfplan' \\;",
                "terraform apply tfplan",
            ),
            // Fix round 1: the outer command picks the nested shell's
            // startup files or init code, or passes it a variable whose name
            // tirith cannot read (which may be one of those, or a
            // `BASH_FUNC_cd%%` function).
            (
                "ENV=./e.sh sh -ic 'cd /srv/infra && terraform apply tfplan'",
                "cd /srv/infra && terraform apply tfplan",
            ),
            (
                "HOME=./h zsh -c 'cd /srv/infra && terraform apply tfplan'",
                "cd /srv/infra && terraform apply tfplan",
            ),
            (
                "env \"$n=$v\" bash -c 'cd /srv/infra && terraform apply tfplan'",
                "cd /srv/infra && terraform apply tfplan",
            ),
            (
                "export \"$n=$v\"; bash -c 'cd /srv/infra && terraform apply tfplan'",
                "cd /srv/infra && terraform apply tfplan",
            ),
            (
                "env 'BASH_FUNC_cd%%=() { builtin cd /x; }' bash -c 'cd /srv/infra && terraform apply tfplan'",
                "cd /srv/infra && terraform apply tfplan",
            ),
            // A remote host or container: tirith cannot read its files.
            (
                "ssh host 'cd /srv/infra && terraform apply tfplan'",
                "cd /srv/infra && terraform apply tfplan",
            ),
            (
                "docker exec box sh -c 'terraform apply tfplan'",
                "terraform apply tfplan",
            ),
            (
                "ssh host 'terraform apply /srv/infra/tfplan'",
                "terraform apply /srv/infra/tfplan",
            ),
            (
                "chroot /mnt sh -c 'cd /srv/infra || exit; terraform apply tfplan'",
                "cd /srv/infra || exit; terraform apply tfplan",
            ),
        ] {
            let found = titles(&[(outer, posix), (body, posix)], None);
            assert!(unlocatable(&found), "{outer:?}: {found:?}");
        }
        // fish reads its configuration from HOME or XDG_CONFIG_HOME and runs
        // `-C` / `--init-command` code before the body.
        for outer in [
            "XDG_CONFIG_HOME=./h fish -c 'cd /srv/infra; terraform apply tfplan'",
            "HOME=./h fish -c 'cd /srv/infra; terraform apply tfplan'",
            "fish -C \"$x\" -c 'cd /srv/infra; terraform apply tfplan'",
            "fish --init-command=\"$x\" -c 'cd /srv/infra; terraform apply tfplan'",
        ] {
            let found = titles(
                &[
                    (outer, posix),
                    ("cd /srv/infra; terraform apply tfplan", ShellType::Fish),
                ],
                None,
            );
            assert!(unlocatable(&found), "{outer:?}: {found:?}");
        }
        // tirith models no PowerShell or cmd assignments around a POSIX body.
        let found = titles(
            &[
                (
                    "bash -c 'cd infra; terraform apply tfplan'",
                    ShellType::PowerShell,
                ),
                ("cd infra; terraform apply tfplan", posix),
            ],
            None,
        );
        assert!(unlocatable(&found), "{found:?}");
        // The plain cases still resolve (the plan file is then read).
        for (outer, body) in [
            (
                "bash -c 'cd infra && terraform apply tfplan'",
                "cd infra && terraform apply tfplan",
            ),
            (
                "CDPATH=/x bash -c 'cd ./infra && terraform apply tfplan'",
                "cd ./infra && terraform apply tfplan",
            ),
            (
                "bash -c 'terraform apply tfplan'; cd other",
                "terraform apply tfplan",
            ),
            (
                "env TF_LOG=1 sh -c 'terraform apply tfplan'",
                "terraform apply tfplan",
            ),
            (
                "sh -c 'cd infra && terraform apply tfplan'; echo \"exit=$?\"",
                "cd infra && terraform apply tfplan",
            ),
            // A value (not a name) tirith cannot read only rules out a bare
            // name, and a startup variable only counts where it is assigned.
            (
                "export TF_VAR_region=\"$REGION\"; bash -c 'cd /srv/infra && terraform apply tfplan'",
                "cd /srv/infra && terraform apply tfplan",
            ),
            (
                "echo \"$HOME\"; env -u CDPATH bash -c 'cd /srv/infra && terraform apply tfplan'",
                "cd /srv/infra && terraform apply tfplan",
            ),
        ] {
            let found = titles(&[(outer, posix), (body, posix)], None);
            assert!(
                found.len() == 1 && found[0].contains("could not be read"),
                "{outer:?}: {found:?}"
            );
        }
        // A heredoc body blanked out of the execution view still counts.
        let raw = ": <<EOF\n${CDPATH:=/x}\nEOF\ncd infra\nterraform apply tfplan";
        let view = crate::extract::shell_execution_view(raw, posix);
        assert_ne!(view, raw);
        assert!(
            !titles(&[(&view, posix)], None)[0].contains("cannot be located"),
            "the view alone hides the heredoc"
        );
        let found = titles(&[(&view, posix)], Some(raw));
        assert!(unlocatable(&found), "{found:?}");
        // A heredoc body that changes the directory as it expands (bash 5.3
        // `${ cd x; }`) before the apply runs.
        let raw = "terraform apply tfplan <<EOF\n${ cd /x; }\nEOF";
        let view = crate::extract::shell_execution_view(raw, posix);
        assert_ne!(view, raw);
        let found = titles(&[(&view, posix)], Some(raw));
        assert!(unlocatable(&found), "{found:?}");
        let raw = "cat <<EOF\n${ cd /x; }\nEOF\nterraform apply tfplan";
        let view = crate::extract::shell_execution_view(raw, posix);
        let found = titles(&[(&view, posix)], Some(raw));
        assert!(unlocatable(&found), "{found:?}");
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
