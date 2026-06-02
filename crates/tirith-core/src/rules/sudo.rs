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
//!    env var (`sensitive_env.toml`) set; the value becomes readable via
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

/// Run the sudo-escalation rules. Returns at most a small handful of
/// findings — most invocations fire at most one of the five.
pub fn check(input: &str, shell: ShellType, policy: &Policy) -> Vec<Finding> {
    let segments = tokenize::tokenize(input, shell);
    let mut findings: Vec<Finding> = Vec::new();

    for seg in &segments {
        if let Some(parsed) = parse_sudo_invocation(seg, shell) {
            findings.extend(rules_for_segment(&parsed, input, seg, shell));
        } else if let Some(parsed) = parse_pipe_into_sudo_tee(seg, shell) {
            // `… | sudo tee /etc/foo` arrives as a segment whose leader
            // is `sudo` and arg-list starts with `tee`. We still need to
            // run the tee check on it.
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
            for f in &mut findings {
                if f.severity == Severity::High {
                    f.severity = Severity::Medium;
                }
            }
        }
    }

    findings
}

/// A parsed `sudo` invocation: the inner command (post-flag-strip) plus observed flags.
struct SudoParsed {
    /// `-E` / `--preserve-env` (no value): preserve ALL. Distinct from `--preserve-env=LIST`.
    preserve_env_all: bool,
    /// Specific vars from `--preserve-env=A,B,C` (matched case-insensitively).
    preserve_env_vars: Vec<String>,
    /// Inner command base name; empty when sudo had no positional command.
    inner_cmd: String,
    /// Inner command's args (raw, quotes preserved).
    inner_args: Vec<String>,
}

/// Parse a segment as a `sudo` invocation when its leader (after `env`-wrapper
/// resolution) is `sudo`. `None` for non-sudo segments.
fn parse_sudo_invocation(seg: &tokenize::Segment, shell: ShellType) -> Option<SudoParsed> {
    let cmd = seg.command.as_deref()?;
    let base = command_basename(cmd, shell);

    if base == "sudo" {
        return Some(parse_sudo_args(&seg.args, shell));
    }

    // `env [VAR=val …] sudo …` — strip the env wrapper, then sudo.
    if base == "env" {
        let inner_start = skip_env_assignments(&seg.args);
        if inner_start < seg.args.len() {
            let inner_leader = command_basename(&seg.args[inner_start], shell);
            if inner_leader == "sudo" {
                return Some(parse_sudo_args(&seg.args[inner_start + 1..], shell));
            }
        }
    }

    None
}

/// Parser for the trailing pipe segment (`… | sudo tee /etc/foo`). The leader is already
/// `sudo`, so `parse_sudo_invocation` handles it; kept for symmetry. Currently delegates.
fn parse_pipe_into_sudo_tee(seg: &tokenize::Segment, shell: ShellType) -> Option<SudoParsed> {
    let leader = seg.command.as_deref().map(|c| command_basename(c, shell))?;
    if leader != "sudo" {
        return None;
    }
    Some(parse_sudo_args(&seg.args, shell))
}

/// Skip `KEY=VAL` assignments and bare flags between the `env` leader and the inner
/// command. Returns the index of the first non-assignment, non-flag positional.
fn skip_env_assignments(args: &[String]) -> usize {
    let mut idx = 0;
    while idx < args.len() {
        let a = strip_outer_quotes(&args[idx]);
        if a == "-S" || a == "--split-string" {
            idx += 1;
            continue;
        }
        if a.starts_with('-') && a.len() >= 2 {
            // Skip any leading env flag. We do NOT consume a value for `-u` — that would
            // mis-resolve `env -u SUDO_ASKPASS sudo`; skip one slot and fall through.
            idx += 1;
            continue;
        }
        if a.contains('=') {
            idx += 1;
            continue;
        }
        return idx;
    }
    idx
}

/// Parse the args beyond the `sudo` leader into the inner command + post-flag args.
fn parse_sudo_args(args: &[String], shell: ShellType) -> SudoParsed {
    let value_short = ["-u", "-g", "-C", "-D", "-R", "-T"];
    let value_long = [
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
    let mut preserve_env_all = false;
    let mut preserve_env_vars: Vec<String> = Vec::new();
    let mut inner_start: Option<usize> = None;

    while idx < args.len() {
        let raw = &args[idx];
        let a = strip_outer_quotes(raw);
        if a == "--" {
            inner_start = Some(idx + 1);
            break;
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
        // `-Eu user` form: a bundled short flag containing `E` still preserves all env.
        if a.starts_with('-') && a.len() > 1 && !a.starts_with("--") && a.contains('E') {
            preserve_env_all = true;
        }
        if a.starts_with("--") {
            if value_long.contains(&a) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            if value_short.contains(&a) {
                idx += 2;
            } else {
                idx += 1;
            }
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
            inner_cmd: String::new(),
            inner_args: Vec::new(),
        };
    }

    let inner_cmd = command_basename(&args[inner_start], shell);
    let inner_args: Vec<String> = args[inner_start + 1..].to_vec();

    SudoParsed {
        preserve_env_all,
        preserve_env_vars,
        inner_cmd,
        inner_args,
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

    // 1) sudo <interactive-shell>
    if is_interactive_shell(inner) {
        findings.push(make_finding(
            RuleId::SudoShellSpawn,
            Severity::High,
            format!("sudo {inner}: interactive root shell"),
            format!(
                "`sudo {inner}` opens an interactive root shell. Subsequent commands typed \
                 into that shell run with full privileges and are NOT seen by tirith \
                 (we intercept the local shell, not nested shells). Run the specific \
                 command that needs elevation with sudo, not a shell."
            ),
            input,
            seg,
        ));
    }

    // 2) sudo -E with sensitive env set
    if parsed.preserve_env_all {
        let active = sensitive_env_active();
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
        // --preserve-env=VAR_LIST: fire only if a listed var is sensitive (presence-only).
        let intersecting: Vec<&str> = parsed
            .preserve_env_vars
            .iter()
            .filter(|v| is_sensitive_env_name(v))
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
        if let Some(target) = first_tee_target(inner_args) {
            if is_protected_system_path(&target) {
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
    }

    // 4) sudo curl|wget|fetch -o <system-path>
    if is_download_tool(inner) {
        if let Some(target) = first_download_output_path(inner_args) {
            if is_protected_system_path(&target) {
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
    matches!(
        p,
        "/" | "/home" | "/usr" | "/etc" | "/var" | "/opt" | "/srv" | "/lib" | "/bin"
    )
        // Trailing slash variants.
        || matches!(
            p,
            "/home/" | "/usr/" | "/etc/" | "/var/" | "/opt/" | "/srv/" | "/lib/" | "/bin/"
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

/// Find the `tee` target — first positional arg that is not a flag.
fn first_tee_target(args: &[String]) -> Option<String> {
    for arg in args.iter() {
        let a = strip_outer_quotes(arg);
        if a == "--" {
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            continue;
        }
        return Some(a.to_string());
    }
    None
}

/// Find the `curl/wget -o <path>` output path. Handles glued forms
/// (`-o=file`, `--output=file`) and split forms (`-o file`).
fn first_download_output_path(args: &[String]) -> Option<String> {
    let mut iter = args.iter().enumerate();
    while let Some((_i, arg)) = iter.next() {
        let a = strip_outer_quotes(arg);
        if let Some(rest) = a.strip_prefix("--output=") {
            return Some(rest.to_string());
        }
        if let Some(rest) = a.strip_prefix("-o=") {
            return Some(rest.to_string());
        }
        if a == "-o" || a == "--output" || a == "-O" {
            // Next arg is the path (wget also uses `-O`).
            if let Some((_, next)) = iter.next() {
                let v = strip_outer_quotes(next);
                return Some(v.to_string());
            }
        }
    }
    None
}

/// `true` when the target is under a protected system dir or a home shell-init dotfile.
/// Deliberately narrow (`tee /tmp/foo` / `~/notes.md` / `./relative` never fire). The
/// home-dotfile arm closes a gap: `check_dotfile_overwrite` catches the redirect shape
/// but not the pipe-into-`sudo tee` shape.
fn is_protected_system_path(p: &str) -> bool {
    // Repo-relative / current-dir — never protected.
    if !p.starts_with('/')
        && !p.starts_with('~')
        && !p.starts_with("$HOME")
        && !p.starts_with("${HOME")
    {
        return false;
    }

    // Home shell-init dotfiles are protected (bare name only; `~/.config/zsh/…` is not).
    if is_home_shell_init_dotfile(p) {
        return true;
    }

    // Other paths under ~/ and $HOME/ are user-writable.
    if p.starts_with('~') || p.starts_with("$HOME") || p.starts_with("${HOME") {
        return false;
    }

    // /tmp is shared but not OS-system.
    if p == "/tmp" || p.starts_with("/tmp/") {
        return false;
    }
    // /var/tmp same.
    if p == "/var/tmp" || p.starts_with("/var/tmp/") {
        return false;
    }
    // Documented system trees.
    p.starts_with("/etc/")
        || p == "/etc"
        || p.starts_with("/usr/local/bin/")
        || p == "/usr/local/bin"
        || p.starts_with("/usr/bin/")
        || p == "/usr/bin"
        || p.starts_with("/usr/sbin/")
        || p == "/usr/sbin"
        || p.starts_with("/lib/systemd/")
        || p.starts_with("/lib/")
        || p.starts_with("/usr/lib/systemd/")
        || p.starts_with("/etc/cron")
        || p.starts_with("/etc/systemd/")
        // Webroot / persistent system dirs added per PR-127 review.
        || p == "/var/www"
        || p.starts_with("/var/www/")
        || p == "/srv"
        || p.starts_with("/srv/")
        || p == "/root"
        || p.starts_with("/root/")
        || p == "/boot"
        || p.starts_with("/boot/")
        || p == "/var/lib"
        || p.starts_with("/var/lib/")
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

/// Sensitive env-var names currently set in `std::env`, ordered by `sensitive_env.toml`.
fn sensitive_env_active() -> Vec<String> {
    crate::safe_command::sensitive_env_vars()
        .iter()
        .filter(|name| std::env::var_os(name).is_some())
        .map(|s| s.to_string())
        .collect()
}

fn is_sensitive_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    crate::safe_command::sensitive_env_vars()
        .iter()
        .any(|s| s.eq_ignore_ascii_case(&upper))
}

fn make_finding(
    rule_id: RuleId,
    severity: Severity,
    title: String,
    description: String,
    input: &str,
    seg: &tokenize::Segment,
) -> Finding {
    Finding {
        rule_id,
        severity,
        title,
        description,
        evidence: vec![
            Evidence::CommandPattern {
                pattern: "sudo <escalation-gate>".to_string(),
                matched: seg.raw.chars().take(200).collect(),
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
            "sudo wget --output=/etc/foo https://example.com/foo",
            ShellType::Posix,
            &policy,
        );
        assert!(findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::SudoDownloadInstall)));
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
        // Neither PATH nor LANG is in sensitive_env.toml.
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::SudoEnvPreserveSensitive)),
            "PATH/LANG must NOT fire SudoEnvPreserveSensitive: {findings:?}"
        );
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
        assert!(!is_broad_path("/etc/cron.d"));
        assert!(!is_broad_path("/home/me"));
    }

    #[test]
    fn first_download_output_path_split_and_glued() {
        assert_eq!(
            first_download_output_path(&[
                "-o".to_string(),
                "/usr/local/bin/foo".to_string(),
                "https://example.com/foo".to_string(),
            ])
            .as_deref(),
            Some("/usr/local/bin/foo"),
        );
        assert_eq!(
            first_download_output_path(&[
                "--output=/etc/x".to_string(),
                "https://example.com/x".to_string(),
            ])
            .as_deref(),
            Some("/etc/x"),
        );
        assert_eq!(
            first_download_output_path(&["-O".to_string(), "/usr/local/bin/foo".to_string(),])
                .as_deref(),
            Some("/usr/local/bin/foo"),
        );
    }
}
