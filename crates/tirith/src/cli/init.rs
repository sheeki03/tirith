#[cfg(unix)]
use libc;
use std::path::{Path, PathBuf};

use crate::assets;

fn posix_single_quote(path: &str) -> String {
    format!("'{}'", path.replace('\'', "'\\''"))
}

fn powershell_single_quote(path: &str) -> String {
    format!("'{}'", path.replace('\'', "''"))
}

fn fish_single_quote(path: &str) -> String {
    // Fish interprets backslash escapes inside single quotes, unlike POSIX
    // shells. Escape backslashes before apostrophes to preserve exact bytes.
    format!("'{}'", path.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// Offer a version handoff before sourcing. Only newly initialized hook code
/// consumes it; a successful double-source return cannot relabel older functions.
/// An external bundle must match the embedded bytes to receive a known version.
pub(crate) fn integration_stamp(shell: &str, hook_dir: &Path) -> String {
    let (file, expected) = match shell {
        "bash" => ("bash-hook.bash", assets::BASH_HOOK),
        "zsh" => ("zsh-hook.zsh", assets::ZSH_HOOK),
        "fish" => ("fish-hook.fish", assets::FISH_HOOK),
        "powershell" | "pwsh" => ("powershell-hook.ps1", assets::POWERSHELL_HOOK),
        "nushell" | "nu" => ("nushell-hook.nu", assets::NUSHELL_HOOK),
        _ => return String::new(),
    };
    use std::io::Read as _;
    let matches = std::fs::File::open(hook_dir.join("lib").join(file))
        .ok()
        .and_then(|file| {
            let mut bytes = Vec::new();
            file.take(expected.len() as u64 + 1)
                .read_to_end(&mut bytes)
                .ok()?;
            Some(bytes == expected.as_bytes())
        })
        .unwrap_or(false);
    let version = if matches {
        env!("CARGO_PKG_VERSION")
    } else {
        "unknown"
    };
    integration_handoff(shell, version)
}

pub(crate) fn integration_handoff(shell: &str, version: &str) -> String {
    match shell {
        "fish" => format!("set -g _TIRITH_INIT_VERSION '{version}'"),
        "powershell" | "pwsh" => format!("$global:_TIRITH_INIT_VERSION = '{version}'"),
        "nushell" | "nu" => format!("$env._TIRITH_INIT_VERSION = \"{version}\""),
        "bash" | "zsh" => format!("_TIRITH_INIT_VERSION='{version}'"),
        _ => String::new(),
    }
}

pub(crate) fn integration_handoff_cleanup(shell: &str) -> &'static str {
    match shell {
        "fish" => "set -e _TIRITH_INIT_VERSION",
        "powershell" | "pwsh" => "$global:_TIRITH_INIT_VERSION = $null",
        "nushell" | "nu" => "hide-env --ignore-errors _TIRITH_INIT_VERSION",
        "bash" | "zsh" => "unset _TIRITH_INIT_VERSION",
        _ => "",
    }
}

fn native_hook_source_line(shell: &str, hook: &Path, executable: &Path) -> Result<String, String> {
    let hook = hook
        .to_str()
        .ok_or_else(|| "shell hook path is not valid UTF-8".to_string())?;
    let quote = if shell == "fish" {
        fish_single_quote
    } else {
        posix_single_quote
    };
    // Native Windows paths do not satisfy the POSIX hooks' absolute-path
    // contract. Strict receipts are unavailable there, so preserve each
    // shell's existing PATH resolution instead of passing a native path.
    if !cfg!(unix) {
        return Ok(format!("source {}", quote(hook)));
    }
    let executable = executable
        .to_str()
        .ok_or_else(|| "native executable path is not valid UTF-8".to_string())?;
    Ok(format!(
        "source {} --tirith-executable {}",
        quote(hook),
        quote(executable)
    ))
}

/// Render an exact Nushell string literal. Nushell's single-quoted strings do
/// not support embedded apostrophes or escapes, so paths are always emitted as
/// double-quoted literals with every special/control character encoded.
pub(crate) fn nushell_string_literal(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        match character {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            control if control.is_control() => {
                use std::fmt::Write as _;
                write!(quoted, "\\u{{{:x}}}", control as u32)
                    .expect("writing to a String cannot fail");
            }
            ordinary => quoted.push(ordinary),
        }
    }
    quoted.push('"');
    quoted
}

/// Warn if another `tirith` binary shadows us on PATH.
fn check_path_shadow() -> Option<String> {
    let shadows = super::find_shadow_binaries();
    if shadows.is_empty() {
        return None;
    }
    let our_exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "unknown".into());
    Some(format!(
        "tirith: WARNING: '{}' may shadow this binary ({})\n\
         tirith: This may be a different package (e.g. pip-installed).\n\
         tirith: Run '{}' to inspect these installations before removing anything.",
        shadows[0],
        our_exe,
        super::tirith_path_lookup_command(),
    ))
}

/// How long to suppress a repeat PATH-shadow warning. `eval "$(tirith init)"`
/// runs on every new shell, so without this the warning would print every time.
const SHADOW_WARN_INTERVAL_SECS: u64 = 24 * 60 * 60;

/// True when the shadow warning hasn't fired in the last 24h (or ever). Cheap
/// marker stat — checked BEFORE the `check_path_shadow` PATH walk.
fn shadow_warn_due() -> bool {
    let Some(marker) = tirith_core::policy::state_dir().map(|d| d.join("shadow-warned")) else {
        return true;
    };
    match std::fs::metadata(&marker).and_then(|m| m.modified()) {
        Ok(modified) => modified
            .elapsed()
            .map(|age| age.as_secs() >= SHADOW_WARN_INTERVAL_SECS)
            .unwrap_or(true),
        Err(_) => true,
    }
}

fn mark_shadow_warned() {
    if let Some(dir) = tirith_core::policy::state_dir() {
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join("shadow-warned"), b"");
    }
}

pub fn run(shell: Option<&str>, prompt_status: bool) -> i32 {
    // Throttled (once/24h) + `--quiet`-gated: a sourced `tirith init` runs on every
    // new shell. The PATH walk is skipped entirely when a warning isn't due.
    if !crate::cli::is_quiet() && shadow_warn_due() {
        if let Some(warning) = check_path_shadow() {
            eprintln!("{warning}");
            mark_shadow_warned();
        }
    }

    let shell = shell.unwrap_or_else(|| detect_shell());

    let prompt_executable = if prompt_status {
        match tirith_core::trusted_child::TrustedExecutable::current() {
            Ok(executable) => Some(executable),
            Err(error) => {
                eprintln!("tirith: cannot bind prompt status to the running executable: {error}");
                return 1;
            }
        }
    } else {
        None
    };

    let hook_dir = find_hook_dir();
    // npm and version-manager launchers add a process between the shell and
    // Tirith. Receipt registration requires the native binary to be the shell's
    // direct child. Bind each new initialization to this running installation,
    // rather than resolving the launcher again from PATH inside the hook.
    let native_executable = if matches!(shell, "bash" | "zsh" | "fish") {
        match std::env::current_exe().and_then(std::fs::canonicalize) {
            Ok(path) => Some(path),
            Err(error) => {
                eprintln!("tirith: cannot locate the native executable for shell hooks: {error}");
                return 1;
            }
        }
    } else {
        None
    };

    match shell {
        "zsh" => {
            if let Some(dir) = &hook_dir {
                match native_hook_source_line(
                    shell,
                    &dir.join("lib/zsh-hook.zsh"),
                    native_executable.as_ref().unwrap(),
                ) {
                    Ok(line) => {
                        println!("{}", integration_stamp(shell, dir));
                        println!("{line}");
                        println!("{}", integration_handoff_cleanup(shell));
                    }
                    Err(error) => {
                        eprintln!("tirith: {error}");
                        return 1;
                    }
                }
            } else {
                eprintln!("tirith: could not locate or materialize shell hooks.");
                return 1;
            }
            if prompt_status {
                println!(
                    "{}",
                    prompt_status_snippet_for("zsh", prompt_executable.as_ref().unwrap().path())
                );
            }
            0
        }
        "bash" => {
            if let Some(dir) = &hook_dir {
                match native_hook_source_line(
                    shell,
                    &dir.join("lib/bash-hook.bash"),
                    native_executable.as_ref().unwrap(),
                ) {
                    Ok(line) => {
                        println!("{}", integration_stamp(shell, dir));
                        println!("{line}");
                        println!("{}", integration_handoff_cleanup(shell));
                    }
                    Err(error) => {
                        eprintln!("tirith: {error}");
                        return 1;
                    }
                }
            } else {
                eprintln!("tirith: could not locate or materialize shell hooks.");
                return 1;
            }
            if prompt_status {
                println!(
                    "{}",
                    prompt_status_snippet_for("bash", prompt_executable.as_ref().unwrap().path())
                );
            }
            0
        }
        "fish" => {
            if let Some(dir) = &hook_dir {
                match native_hook_source_line(
                    shell,
                    &dir.join("lib/fish-hook.fish"),
                    native_executable.as_ref().unwrap(),
                ) {
                    Ok(line) => {
                        println!("{}", integration_stamp(shell, dir));
                        println!("{line}");
                        println!("{}", integration_handoff_cleanup(shell));
                    }
                    Err(error) => {
                        eprintln!("tirith: {error}");
                        return 1;
                    }
                }
            } else {
                eprintln!("tirith: could not locate or materialize shell hooks.");
                return 1;
            }
            if prompt_status {
                println!(
                    "{}",
                    prompt_status_snippet_for("fish", prompt_executable.as_ref().unwrap().path())
                );
            }
            0
        }
        "powershell" | "pwsh" => {
            if let Some(dir) = &hook_dir {
                println!("{}", integration_stamp(shell, dir));
                println!(
                    ". {}",
                    powershell_single_quote(
                        &dir.join("lib/powershell-hook.ps1").display().to_string()
                    )
                );
                println!("{}", integration_handoff_cleanup(shell));
            } else {
                eprintln!("tirith: could not locate or materialize shell hooks.");
                return 1;
            }
            if prompt_status {
                println!(
                    "{}",
                    prompt_status_snippet_for(
                        "powershell",
                        prompt_executable.as_ref().unwrap().path(),
                    )
                );
            }
            0
        }
        "nushell" | "nu" => {
            if let Some(dir) = &hook_dir {
                let hook_path = dir.join("lib/nushell-hook.nu");
                if !hook_path.is_file() {
                    eprintln!(
                        "tirith: resolved nushell hook is missing or not a file: {}",
                        hook_path.display()
                    );
                    return 1;
                }
                let Some(hook_path) = hook_path.to_str() else {
                    eprintln!(
                        "tirith: resolved nushell hook path is not valid UTF-8 and cannot be emitted without changing its identity"
                    );
                    return 1;
                };
                println!("{}", integration_stamp(shell, dir));
                println!("source {}", nushell_string_literal(hook_path));
                println!("{}", integration_handoff_cleanup(shell));
            } else {
                eprintln!("tirith: could not locate or materialize shell hooks.");
                return 1;
            }
            if prompt_status {
                // Nushell can't be wired via eval; emit a manual-install pointer
                // (the shipped hook does the real wiring).
                println!(
                    "{}",
                    prompt_status_snippet_for(
                        "nushell",
                        prompt_executable.as_ref().unwrap().path(),
                    )
                );
            }
            0
        }
        _ => {
            eprintln!("tirith: unsupported shell '{shell}'");
            eprintln!("Supported: zsh, bash, fish, powershell, nushell");
            eprintln!("  try: tirith init --shell zsh");
            1
        }
    }
}

/// Render the opt-in `--prompt-status` snippet for `shell`. Each snippet is
/// guarded against double-eval (so PS1/PROMPT isn't double-wrapped) and uses
/// single quotes around the command substitution so it defers to prompt-render
/// time (the only quoting that produces a live status).
pub(crate) fn prompt_status_snippet_for(shell: &str, executable: &std::path::Path) -> String {
    let executable = executable.display().to_string();
    let posix_executable = posix_single_quote(&executable);
    let powershell_executable = powershell_single_quote(&executable);
    match shell {
        "zsh" => {
            let substitution = posix_single_quote(&format!(
                "$(TIRITH_STATUS=\"${{TIRITH_STATUS:-}}\" {posix_executable} prompt-status --short) "
            ));
            [
                "# >>> tirith prompt-status (M8 ch6) >>>".to_string(),
                "if [[ -z \"${_TIRITH_PROMPT_STATUS_LOADED:-}\" ]]; then".to_string(),
                "  _TIRITH_PROMPT_STATUS_LOADED=1".to_string(),
                "  setopt PROMPT_SUBST".to_string(),
                format!("  PROMPT={substitution}\"$PROMPT\""),
                "fi".to_string(),
                "# <<< tirith prompt-status (M8 ch6) <<<".to_string(),
            ]
            .join("\n")
        }
        "bash" => {
            let substitution = posix_single_quote(&format!(
                "$(TIRITH_STATUS=\"${{TIRITH_STATUS:-}}\" {posix_executable} prompt-status --short) "
            ));
            [
                "# >>> tirith prompt-status (M8 ch6) >>>".to_string(),
                "if [ -z \"${_TIRITH_PROMPT_STATUS_LOADED:-}\" ]; then".to_string(),
                "  _TIRITH_PROMPT_STATUS_LOADED=1".to_string(),
                format!("  PS1={substitution}\"$PS1\""),
                "fi".to_string(),
                "# <<< tirith prompt-status (M8 ch6) <<<".to_string(),
            ]
            .join("\n")
        }
        "fish" => [
            "# >>> tirith prompt-status (M8 ch6) >>>".to_string(),
            "if not set -q _TIRITH_PROMPT_STATUS_LOADED".to_string(),
            "    set -g _TIRITH_PROMPT_STATUS_LOADED 1".to_string(),
            "    functions -q fish_right_prompt; and functions -e _tirith_orig_fish_right_prompt".to_string(),
            "    if functions -q fish_right_prompt".to_string(),
            "        functions -c fish_right_prompt _tirith_orig_fish_right_prompt".to_string(),
            "    end".to_string(),
            "    function fish_right_prompt".to_string(),
            format!("        env TIRITH_STATUS=\"$TIRITH_STATUS\" {posix_executable} prompt-status --short"),
            "        if functions -q _tirith_orig_fish_right_prompt".to_string(),
            "            _tirith_orig_fish_right_prompt".to_string(),
            "        end".to_string(),
            "    end".to_string(),
            "end".to_string(),
            "# <<< tirith prompt-status (M8 ch6) <<<".to_string(),
        ]
        .join("\n"),
        "powershell" | "pwsh" => [
            "# >>> tirith prompt-status (M8 ch6) >>>".to_string(),
            "if (-not $global:_TIRITH_PROMPT_STATUS_LOADED) {".to_string(),
            "    $global:_TIRITH_PROMPT_STATUS_LOADED = $true".to_string(),
            "    if (Test-Path Function:prompt) {".to_string(),
            "        Copy-Item Function:prompt Function:_tirith_orig_prompt -Force".to_string(),
            "    }".to_string(),
            "    function global:prompt {".to_string(),
            "        $_tps = $env:TIRITH_STATUS; $env:TIRITH_STATUS = $global:TIRITH_STATUS".to_string(),
            format!("        try {{ $line = (& {powershell_executable} prompt-status --short) 2>$null }} finally {{ if ($null -eq $_tps) {{ Remove-Item Env:\\TIRITH_STATUS -ErrorAction SilentlyContinue }} else {{ $env:TIRITH_STATUS = $_tps }} }}"),
            "        if (Get-Command _tirith_orig_prompt -ErrorAction SilentlyContinue) {".to_string(),
            "            \"$line $(_tirith_orig_prompt)\"".to_string(),
            "        } else {".to_string(),
            "            \"$line PS $($executionContext.SessionState.Path.CurrentLocation)> \"".to_string(),
            "        }".to_string(),
            "    }".to_string(),
            "}".to_string(),
            "# <<< tirith prompt-status (M8 ch6) <<<".to_string(),
        ]
        .join("\n"),
        // Nushell wiring lives in config.nu and can't be spliced via `eval`;
        // print a manual-install pointer instead.
        "nushell" | "nu" => [
            "# >>> tirith prompt-status (M8 ch6) >>>",
            "# Nushell exposes no non-exported TIRITH_STATUS variable, so a live",
            "# status segment would always read `off`. nushell protection is",
            "# warn-only regardless — there is no live prompt status to wire up",
            "# here. See docs/prompt-status.md.",
            "# <<< tirith prompt-status (M8 ch6) <<<",
        ]
        .join("\n"),
        _ => String::new(),
    }
}

pub(crate) fn detect_shell() -> &'static str {
    detect_shell_identity().shell
}

pub(crate) struct ShellIdentity {
    pub shell: &'static str,
    pub executable: Option<PathBuf>,
    pub source: &'static str,
    pub startup_mode: &'static str,
    pub process_id: Option<u32>,
}

pub(crate) fn detect_shell_identity() -> ShellIdentity {
    if let Some(identity) = detect_shell_from_parent() {
        return identity;
    }

    if let Ok(shell) = std::env::var("SHELL") {
        if let Some(shell) = normalize_shell_name(&shell) {
            return ShellIdentity {
                shell,
                executable: std::env::var_os("SHELL").map(PathBuf::from),
                source: "environment-default-shell",
                startup_mode: "unknown",
                process_id: None,
            };
        }
    }
    ShellIdentity {
        shell: "unknown",
        executable: None,
        source: "unobservable",
        startup_mode: "unknown",
        process_id: None,
    }
}

fn normalize_shell_name(name: &str) -> Option<&'static str> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .trim_start_matches('-')
        .to_ascii_lowercase();

    if matches!(base.as_str(), "zsh" | "zsh.exe") {
        Some("zsh")
    } else if matches!(base.as_str(), "bash" | "bash.exe") {
        Some("bash")
    } else if matches!(base.as_str(), "fish" | "fish.exe") {
        Some("fish")
    } else if matches!(base.as_str(), "pwsh" | "pwsh.exe") {
        Some("pwsh")
    } else if matches!(base.as_str(), "powershell" | "powershell.exe") {
        Some("powershell")
    } else if matches!(base.as_str(), "nu" | "nu.exe" | "nushell" | "nushell.exe") {
        Some("nushell")
    } else {
        None
    }
}

#[cfg(unix)]
fn detect_shell_from_parent() -> Option<ShellIdentity> {
    let mut pid = unsafe { libc::getppid() };

    // Walk ancestors: the immediate parent may be a wrapper (timeout/env) or a
    // shell that exec'd into another program.
    for _ in 0..8 {
        if pid <= 1 {
            return None;
        }
        let (name, parent_pid) = read_process(pid)?;
        if let Some(shell) = normalize_shell_name(&name) {
            return Some(ShellIdentity {
                shell,
                executable: process_executable(pid).or_else(|| {
                    PathBuf::from(&name)
                        .is_absolute()
                        .then(|| PathBuf::from(&name))
                }),
                source: "observed-ancestor-process",
                startup_mode: process_arguments(pid)
                    .as_deref()
                    .map(|args| startup_mode_from_args(shell, args))
                    .unwrap_or(if name.starts_with('-') {
                        "login"
                    } else {
                        "unknown"
                    }),
                process_id: Some(pid as u32),
            });
        }
        if parent_pid == pid {
            break;
        }
        pid = parent_pid;
    }

    None
}

/// Classify only shell options before a command/script payload. Arguments are
/// transient process evidence and must never be returned in diagnostics.
pub(crate) fn startup_mode_from_args(shell: &str, args: &[String]) -> &'static str {
    let mut login = args.first().is_some_and(|arg| arg.starts_with('-'));
    let mut interactive = false;
    let mut bash_option_value = false;
    for arg in args.iter().skip(1) {
        let lower = arg.to_ascii_lowercase();
        if bash_option_value {
            if lower == "posix" {
                return "custom-profile";
            }
            bash_option_value = false;
            continue;
        }
        if shell == "bash" && lower == "--posix" {
            return "custom-profile";
        }
        if shell == "bash" && arg == "-o" {
            bash_option_value = true;
            continue;
        }
        if lower == "--" {
            break;
        }
        if matches!(shell, "powershell" | "pwsh") {
            if matches!(lower.as_str(), "-noprofile" | "-nop") {
                return "no-profile";
            }
            if matches!(
                lower.as_str(),
                "-command" | "-c" | "-file" | "-f" | "-encodedcommand" | "-enc"
            ) {
                return "noninteractive-command";
            }
            continue;
        }
        if matches!(
            lower.as_str(),
            "--norc" | "--noprofile" | "--no-config" | "--no-config-file"
        ) || (shell == "fish" && arg == "-N")
            || (shell == "zsh"
                && arg.starts_with('-')
                && !arg.starts_with("--")
                && arg.contains('f'))
        {
            return "no-profile";
        }
        if ["--rcfile", "--init-file", "--config", "--env-config"]
            .iter()
            .any(|option| lower == *option || lower.starts_with(&format!("{option}=")))
        {
            return "custom-profile";
        }
        if lower == "--login" {
            login = true;
            continue;
        }
        if lower == "--interactive" {
            interactive = true;
            continue;
        }
        if arg.starts_with('-') && !arg.starts_with("--") {
            login |= arg.contains('l');
            interactive |= arg.contains('i');
            if arg.contains('c') {
                return if interactive {
                    "interactive-command"
                } else {
                    "noninteractive-command"
                };
            }
        } else if !arg.starts_with('-') {
            break;
        }
    }
    if login {
        "login"
    } else if interactive {
        "interactive-non-login"
    } else {
        "unknown"
    }
}

#[cfg(unix)]
fn process_arguments(pid: libc::pid_t) -> Option<Vec<String>> {
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(format!("/proc/{pid}/cmdline"))
            .ok()?
            .take(16 * 1024 + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() > 16 * 1024 {
            return None;
        }
        bytes
            .split(|b| *b == 0)
            .filter(|arg| !arg.is_empty())
            .map(|arg| String::from_utf8(arg.to_vec()).ok())
            .collect()
    }
    #[cfg(not(target_os = "linux"))]
    {
        use tirith_core::trusted_child::{ChildLimits, ChildOutcome, ChildSpec, TrustedExecutable};
        let program = TrustedExecutable::from_system_candidates(&[
            Path::new("/bin/ps"),
            Path::new("/usr/bin/ps"),
        ])
        .ok()?;
        let pid = pid.to_string();
        let spec = ChildSpec::new(
            ["-p", pid.as_str(), "-o", "args="],
            ChildLimits::new(std::time::Duration::from_secs(1), 16 * 1024, 1024),
        );
        let ChildOutcome::Completed { status, stdout, .. } =
            tirith_core::trusted_child::run(&program, &spec)
        else {
            return None;
        };
        if !status.success() {
            return None;
        }
        // ps has already flattened argv. Only option-like tokens before a
        // command payload are used; ambiguous values remain unobservable.
        Some(
            String::from_utf8(stdout)
                .ok()?
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
        )
    }
}

#[cfg(unix)]
fn process_executable(pid: libc::pid_t) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        let mut bytes = vec![0u8; 4096];
        // SAFETY: proc_pidpath writes at most the supplied buffer length.
        let length =
            unsafe { libc::proc_pidpath(pid, bytes.as_mut_ptr().cast(), bytes.len() as u32) };
        if length <= 0 {
            return None;
        }
        let end = bytes
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(length as usize);
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(&bytes[..end])))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

#[cfg(unix)]
fn read_process(pid: libc::pid_t) -> Option<(String, libc::pid_t)> {
    use tirith_core::trusted_child::{ChildLimits, ChildOutcome, ChildSpec, TrustedExecutable};

    let program = TrustedExecutable::from_system_candidates(&[
        std::path::Path::new("/bin/ps"),
        std::path::Path::new("/usr/bin/ps"),
    ])
    .ok()?;
    let pid = pid.to_string();
    let spec = ChildSpec::new(
        ["-p", pid.as_str(), "-o", "comm=", "-o", "ppid="],
        ChildLimits::new(std::time::Duration::from_secs(1), 16 * 1024, 16 * 1024),
    );
    let ChildOutcome::Completed { status, stdout, .. } =
        tirith_core::trusted_child::run(&program, &spec)
    else {
        return None;
    };
    if !status.success() {
        return None;
    }

    let line = String::from_utf8_lossy(&stdout);
    let (name, ppid) = line.trim().rsplit_once(char::is_whitespace)?;
    let name = name.trim().to_owned();
    let ppid = ppid.parse::<libc::pid_t>().ok()?;
    Some((name, ppid))
}

#[cfg(windows)]
fn detect_shell_from_parent() -> Option<ShellIdentity> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    // SAFETY: Toolhelp fills a correctly sized structure; the snapshot handle
    // is closed before any return and UTF-16 names are bounded by szExeFile.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut processes = std::collections::HashMap::new();
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let end = entry
                    .szExeFile
                    .iter()
                    .position(|c| *c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
                processes.insert(entry.th32ProcessID, (entry.th32ParentProcessID, name));
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
        let mut pid = std::process::id();
        for _ in 0..8 {
            let (parent, _) = processes.get(&pid)?;
            if *parent == pid || *parent == 0 {
                break;
            }
            let (_, name) = processes.get(parent)?;
            if let Some(shell) = normalize_shell_name(name) {
                use windows::Win32::System::Threading::{
                    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                };
                let executable = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, *parent)
                    .ok()
                    .and_then(|handle| {
                        let mut buffer = vec![0u16; 32768];
                        let mut length = buffer.len() as u32;
                        let result = QueryFullProcessImageNameW(
                            handle,
                            PROCESS_NAME_WIN32,
                            windows::core::PWSTR(buffer.as_mut_ptr()),
                            &mut length,
                        );
                        let _ = CloseHandle(handle);
                        result.ok().map(|_| {
                            PathBuf::from(String::from_utf16_lossy(&buffer[..length as usize]))
                        })
                    });
                return Some(ShellIdentity {
                    shell,
                    executable,
                    source: "observed-ancestor-process",
                    startup_mode: "unknown",
                    process_id: Some(*parent),
                });
            }
            pid = *parent;
        }
        None
    }
}

#[cfg(not(any(unix, windows)))]
fn detect_shell_from_parent() -> Option<ShellIdentity> {
    None
}

/// Find the shell hooks directory using the following search order:
/// 1. TIRITH_SHELL_DIR env var (explicit override)
/// 2. ../share/tirith/shell relative to binary (Homebrew layout)
/// 3. /usr/share/tirith/shell (.deb layout)
/// 4. ../shell relative to binary (cargo install / dev layout)
/// 5. ../../shell relative to binary (workspace dev layout)
/// 6. Fallback: materialize embedded hooks to data dir
pub fn find_hook_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("TIRITH_SHELL_DIR") {
        let p = PathBuf::from(&dir);
        if p.join("lib").exists() {
            return Some(p);
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(bin_dir) = exe.parent() {
            let brew_dir = bin_dir.join("../share/tirith/shell");
            if brew_dir.join("lib").exists() {
                return Some(brew_dir.canonicalize().unwrap_or(brew_dir));
            }

            #[cfg(unix)]
            {
                let sys_dir = PathBuf::from("/usr/share/tirith/shell");
                if sys_dir.join("lib").exists() {
                    return Some(sys_dir);
                }
            }

            let cargo_dir = bin_dir.join("../shell");
            if cargo_dir.join("lib").exists() {
                return Some(cargo_dir.canonicalize().unwrap_or(cargo_dir));
            }

            let dev_dir = bin_dir.join("../../shell");
            if dev_dir.join("lib").exists() {
                return Some(dev_dir.canonicalize().unwrap_or(dev_dir));
            }
        }
    }

    materialize_hooks()
}

/// Find the shell hooks directory without materializing (read-only variant for diagnostics).
pub fn find_hook_dir_readonly() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("TIRITH_SHELL_DIR") {
        let p = PathBuf::from(&dir);
        if p.join("lib").exists() {
            return Some(p);
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(bin_dir) = exe.parent() {
            let brew_dir = bin_dir.join("../share/tirith/shell");
            if brew_dir.join("lib").exists() {
                return Some(brew_dir.canonicalize().unwrap_or(brew_dir));
            }

            #[cfg(unix)]
            {
                let sys_dir = PathBuf::from("/usr/share/tirith/shell");
                if sys_dir.join("lib").exists() {
                    return Some(sys_dir);
                }
            }

            let cargo_dir = bin_dir.join("../shell");
            if cargo_dir.join("lib").exists() {
                return Some(cargo_dir.canonicalize().unwrap_or(cargo_dir));
            }

            let dev_dir = bin_dir.join("../../shell");
            if dev_dir.join("lib").exists() {
                return Some(dev_dir.canonicalize().unwrap_or(dev_dir));
            }
        }
    }

    // Check if hooks were previously materialized, but do not create or trust a
    // presence-only bundle. Every byte and the exact version frame must match
    // the currently embedded assets.
    if let Some(data_dir) = tirith_core::policy::data_dir() {
        let shell_dir = data_dir.join("shell");
        if materialized_hooks_match_at(&data_dir).unwrap_or(false) {
            return Some(shell_dir);
        }
    }

    None
}

/// Write embedded hook files to the user data dir, returning the shell dir.
fn materialize_hooks() -> Option<PathBuf> {
    let data_dir = tirith_core::policy::data_dir()?;
    match materialize_hooks_at(&data_dir) {
        Ok((shell_dir, wrote)) => {
            if wrote {
                eprintln!(
                    "tirith: materialized shell hooks to {}",
                    shell_dir.display()
                );
            }
            Some(shell_dir)
        }
        Err(error) => {
            eprintln!("tirith: failed to materialize shell hooks: {error}");
            None
        }
    }
}

fn expected_materialized_files<'a>(
    shell_dir: &Path,
    version: &'a [u8],
) -> Vec<(PathBuf, &'a [u8])> {
    let lib_dir = shell_dir.join("lib");
    vec![
        (shell_dir.join("tirith.sh"), assets::TIRITH_SH.as_bytes()),
        (lib_dir.join("zsh-hook.zsh"), assets::ZSH_HOOK.as_bytes()),
        (lib_dir.join("bash-hook.bash"), assets::BASH_HOOK.as_bytes()),
        (lib_dir.join("fish-hook.fish"), assets::FISH_HOOK.as_bytes()),
        (
            lib_dir.join("powershell-hook.ps1"),
            assets::POWERSHELL_HOOK.as_bytes(),
        ),
        (
            lib_dir.join("nushell-hook.nu"),
            assets::NUSHELL_HOOK.as_bytes(),
        ),
        (shell_dir.join(".hooks-version"), version),
    ]
}

fn prepared_file_matches(
    destination: &tirith_core::util::ContainedAtomicFile,
    path: &Path,
    expected: &[u8],
) -> Result<bool, String> {
    let cap = u64::try_from(expected.len())
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    match destination.read_capped(cap) {
        Ok(observed) => Ok(observed == expected),
        Err(tirith_core::util::OpenRegularError::NotFound)
        | Err(tirith_core::util::OpenRegularError::TooLarge) => Ok(false),
        Err(tirith_core::util::OpenRegularError::NotRegularFile) => Err(format!(
            "refusing non-regular materialized hook destination {}",
            path.display()
        )),
        Err(tirith_core::util::OpenRegularError::Io(error)) => Err(format!(
            "could not read materialized hook {}: {error}",
            path.display()
        )),
    }
}

fn materialized_hooks_match_at(data_dir: &Path) -> Result<bool, String> {
    let shell_dir = data_dir.join("shell");
    let version = format!("{}\n", env!("CARGO_PKG_VERSION"));
    for (path, expected) in expected_materialized_files(&shell_dir, version.as_bytes()) {
        let destination =
            match tirith_core::util::ContainedAtomicFile::prepare(data_dir, &path, false) {
                Ok(destination) => destination,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(error) => {
                    return Err(format!(
                        "could not bind materialized hook {}: {error}",
                        path.display()
                    ))
                }
            };
        if !prepared_file_matches(&destination, &path, expected)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Materialize through retained directory capabilities. All destinations are
/// prepared before the first write and each file is published atomically, but
/// the group is not transactional: a later failure can leave earlier files
/// published. Any error denotes failed materialization, successful completion
/// verifies every file, and the version is attempted last.
fn materialize_hooks_at(data_dir: &Path) -> Result<(PathBuf, bool), String> {
    let shell_dir = data_dir.join("shell");
    let version = format!("{}\n", env!("CARGO_PKG_VERSION"));
    let expected_files = expected_materialized_files(&shell_dir, version.as_bytes());
    let mut prepared = Vec::with_capacity(expected_files.len());

    for (path, expected) in expected_files {
        let destination = tirith_core::util::ContainedAtomicFile::prepare(data_dir, &path, true)
            .map_err(|error| {
                format!(
                    "could not bind materialized hook destination {}: {error}",
                    path.display()
                )
            })?;
        prepared.push((path, expected, destination));
    }

    let mut needs_write = false;
    for (path, expected, destination) in &prepared {
        if !prepared_file_matches(destination, path, expected)? {
            needs_write = true;
        }
    }
    if !needs_write {
        return Ok((shell_dir, false));
    }

    for (path, expected, destination) in &prepared {
        destination.write_atomic(expected, true).map_err(|error| {
            format!(
                "failed to write materialized hook {}: {error}",
                path.display()
            )
        })?;
    }
    for (path, expected, destination) in &prepared {
        if !prepared_file_matches(destination, path, expected)? {
            return Err(format!(
                "materialized hook did not verify after publication: {}",
                path.display()
            ));
        }
    }

    Ok((shell_dir, true))
}

#[cfg(test)]
mod tests {
    use super::{
        integration_stamp, materialize_hooks_at, materialized_hooks_match_at,
        native_hook_source_line, normalize_shell_name, nushell_string_literal, posix_single_quote,
        powershell_single_quote, prompt_status_snippet_for,
    };
    use crate::assets;
    use std::path::Path;

    fn prompt_status_snippet(shell: &str) -> String {
        prompt_status_snippet_for(shell, Path::new("/opt/Tirith Bin/tirith"))
    }

    #[test]
    #[cfg(unix)]
    fn native_hook_binding_quotes_both_paths_as_literal_source_arguments() {
        let line = native_hook_source_line(
            "bash",
            Path::new("/hook's dir/$hook\nfile"),
            Path::new("/native's dir/$(not-a-command)/tirith"),
        )
        .unwrap();
        assert_eq!(
            line,
            "source '/hook'\\''s dir/$hook\nfile' --tirith-executable '/native'\\''s dir/$(not-a-command)/tirith'"
        );
    }

    #[test]
    #[cfg(not(unix))]
    fn native_hook_binding_preserves_non_unix_shell_path_resolution() {
        for (shell, expected) in [
            ("bash", "source 'C:/hook'\\''s dir/hook'"),
            ("zsh", "source 'C:/hook'\\''s dir/hook'"),
            ("fish", "source 'C:/hook\\'s dir/hook'"),
        ] {
            let line = native_hook_source_line(
                shell,
                Path::new("C:/hook's dir/hook"),
                Path::new(r"\\?\C:\native\tirith.exe"),
            )
            .unwrap();
            assert_eq!(line, expected, "shell={shell}");
            assert!(!line.contains("--tirith-executable"));
        }
    }

    #[test]
    #[cfg(unix)]
    fn native_hook_binding_rejects_lossy_path_identity() {
        use std::os::unix::ffi::OsStrExt as _;
        let invalid = Path::new(std::ffi::OsStr::from_bytes(b"/bin/non-utf8-\xff"));
        for shell in ["bash", "zsh", "fish"] {
            assert!(native_hook_source_line(shell, invalid, Path::new("/bin/tirith")).is_err());
            assert!(native_hook_source_line(shell, Path::new("/shell/hook"), invalid).is_err());
        }
    }

    #[test]
    #[cfg(unix)]
    fn native_hook_binding_preserves_fish_source_argument_identity() {
        use std::process::Command;

        let root = tempfile::tempdir().unwrap();
        for component in [
            r"double\\backslash",
            "mixed\\'apostrophe",
            "trailing\\",
            "white space\tand\nnewline",
        ] {
            let directory = root.path().join(component);
            std::fs::create_dir(&directory).unwrap();
            let hook = directory.join("hook.fish");
            std::fs::write(&hook, "builtin printf '%s\\0' \"$argv[1]\" \"$argv[2]\"\n").unwrap();
            // Include a trailing backslash in the executable argument as well
            // as its directory: the closing quote must remain unambiguous.
            let executable = directory.join("native's binary\\");
            let line = native_hook_source_line("fish", &hook, &executable).unwrap();
            let output = match Command::new("fish")
                .args(["--no-config", "-c", &line])
                .env("HOME", root.path())
                .output()
            {
                Ok(output) => output,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    eprintln!("skipping fish source argument test: fish is not installed");
                    return;
                }
                Err(error) => panic!("could not execute fish: {error}"),
            };
            assert!(
                output.status.success(),
                "component={component:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let expected = format!("--tirith-executable\0{}\0", executable.to_str().unwrap());
            assert_eq!(
                output.stdout,
                expected.as_bytes(),
                "component={component:?}"
            );
        }
    }

    #[test]
    fn nushell_literal_quotes_apostrophe_hash_backslash_quote_and_controls() {
        assert_eq!(
            nushell_string_literal("/tmp/it's \\quoted\" #hook\n\t\u{001f}"),
            "\"/tmp/it's \\\\quoted\\\" #hook\\n\\t\\u{1f}\""
        );
    }

    #[test]
    fn integration_version_is_reported_only_for_matching_embedded_hook_bytes() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("lib")).unwrap();
        let hook = root.path().join("lib/bash-hook.bash");
        std::fs::write(&hook, assets::BASH_HOOK).unwrap();
        let matching = integration_stamp("bash", root.path());
        assert!(matching.contains(&format!(
            "_TIRITH_INIT_VERSION='{}'",
            env!("CARGO_PKG_VERSION")
        )));
        assert!(!matching.contains("TIRITH_INTEGRATION_VERSION"));
        std::fs::write(&hook, "# older external hook\n").unwrap();
        assert!(integration_stamp("bash", root.path()).contains("_TIRITH_INIT_VERSION='unknown'"));
        assert!(integration_stamp("unsupported", root.path()).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn double_source_does_not_relabel_already_loaded_hook_generation() {
        // Exercise the actual shipped guard. No new hook or Tirith command is
        // installed: each child starts with a session-local loaded sentinel.
        for (shell, candidates, hook, loaded) in [
            (
                "bash",
                &["/bin/bash"][..],
                assets::BASH_HOOK,
                "_TIRITH_BASH_LOADED=1",
            ),
            (
                "zsh",
                &["/bin/zsh", "/usr/bin/zsh"][..],
                assets::ZSH_HOOK,
                "_TIRITH_ZSH_LOADED=1",
            ),
            (
                "fish",
                &["/opt/homebrew/bin/fish", "/usr/bin/fish"][..],
                assets::FISH_HOOK,
                "set -g _TIRITH_FISH_LOADED 1",
            ),
        ] {
            let Some(executable) = candidates.iter().find(|path| Path::new(path).is_file()) else {
                continue; // Optional native guard regression, not qualification evidence.
            };
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("hook");
            std::fs::write(&path, hook).unwrap();
            let set_old = if shell == "fish" {
                "set -gx TIRITH_INTEGRATION_VERSION old-generation"
            } else {
                "export TIRITH_INTEGRATION_VERSION=old-generation"
            };
            let script = format!("{loaded}\n{set_old}\n{}\nsource '{}'\n{}\nprintf '%s' \"$TIRITH_INTEGRATION_VERSION\"",
                super::integration_handoff(shell, "new-generation"), path.display(),
                super::integration_handoff_cleanup(shell));
            let output = std::process::Command::new(executable)
                .args(["-c", &script])
                .env_clear()
                .env("HOME", root.path())
                .env("PATH", "/usr/bin:/bin")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{shell}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, b"old-generation", "{shell}");
        }
    }

    #[test]
    fn startup_options_stop_at_command_payload_and_identify_custom_profiles() {
        for (shell, args, expected) in [
            (
                "bash",
                vec!["bash", "--rcfile", "/custom/rc"],
                "custom-profile",
            ),
            ("bash", vec!["bash", "--norc", "-i"], "no-profile"),
            ("bash", vec!["-bash"], "login"),
            ("bash", vec!["bash", "-i"], "interactive-non-login"),
            ("bash", vec!["bash", "--posix", "-i"], "custom-profile"),
            ("bash", vec!["bash", "-o", "posix", "-i"], "custom-profile"),
            (
                "bash",
                vec!["bash", "-c", "echo --norc"],
                "noninteractive-command",
            ),
            ("zsh", vec!["zsh", "-f"], "no-profile"),
            ("fish", vec!["fish", "--no-config"], "no-profile"),
            (
                "nushell",
                vec!["nu", "--config=/private/custom.nu"],
                "custom-profile",
            ),
            ("pwsh", vec!["pwsh", "-NoProfile"], "no-profile"),
            (
                "powershell",
                vec!["powershell.exe", "-Command", "Write-Host -NoProfile"],
                "noninteractive-command",
            ),
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert_eq!(
                super::startup_mode_from_args(shell, &args),
                expected,
                "{args:?}"
            );
        }
    }

    #[test]
    fn normalize_shell_name_from_paths_and_login_shells() {
        assert_eq!(normalize_shell_name("/bin/bash"), Some("bash"));
        assert_eq!(normalize_shell_name("/opt/homebrew/bin/fish"), Some("fish"));
        assert_eq!(normalize_shell_name("-zsh"), Some("zsh"));
    }

    #[test]
    fn normalize_shell_name_supports_case_insensitive_names() {
        assert_eq!(normalize_shell_name("BASH"), Some("bash"));
        assert_eq!(normalize_shell_name("PwSh"), Some("pwsh"));
        assert_eq!(normalize_shell_name("PowerShell"), Some("powershell"));
    }

    #[test]
    fn normalize_shell_name_distinguishes_pwsh_and_windows_powershell() {
        // pwsh (PowerShell 7+) is a distinct label from legacy powershell 5.1;
        // the hook script is the same, only the label differs.
        assert_eq!(normalize_shell_name("/usr/local/bin/pwsh"), Some("pwsh"));
        assert_eq!(
            normalize_shell_name("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            Some("powershell")
        );
        // Non-PowerShell shells are unaffected by the split.
        assert_eq!(normalize_shell_name("/bin/bash"), Some("bash"));
    }

    #[test]
    fn normalize_shell_name_supports_nushell() {
        assert_eq!(normalize_shell_name("nu"), Some("nushell"));
        assert_eq!(normalize_shell_name("nu.exe"), Some("nushell"));
        assert_eq!(normalize_shell_name("nushell"), Some("nushell"));
        assert_eq!(normalize_shell_name("nushell.exe"), Some("nushell"));
        assert_eq!(normalize_shell_name("/usr/bin/nu"), Some("nushell"));
        assert_eq!(
            normalize_shell_name("C:\\Program Files\\nu.exe"),
            Some("nushell")
        );
    }

    #[test]
    fn normalize_shell_name_no_false_positive_on_gnu() {
        // "gnu" contains "nu" but is not nushell — require exact match.
        assert_eq!(normalize_shell_name("gnu"), None);
    }

    #[test]
    fn normalize_shell_name_rejects_unknown_values() {
        assert_eq!(normalize_shell_name(""), None);
        assert_eq!(normalize_shell_name("python"), None);
    }

    #[test]
    fn quote_helpers_escape_shell_metacharacters() {
        assert_eq!(
            posix_single_quote("/tmp/hook' > file"),
            "'/tmp/hook'\\'' > file'"
        );
        assert_eq!(
            powershell_single_quote("C:\\temp\\it's.ps1"),
            "'C:\\temp\\it''s.ps1'"
        );
    }

    /// Each per-shell snippet must carry the BEGIN/END markers (for external
    /// dedupe), reference `tirith prompt-status --short`, guard against double-eval,
    /// and single-quote the substitution so it defers to prompt render.
    #[test]
    fn prompt_status_snippet_zsh_is_marker_wrapped_and_deferred() {
        let s = prompt_status_snippet("zsh");
        assert!(s.contains("# >>> tirith prompt-status (M8 ch6) >>>"));
        assert!(s.contains("# <<< tirith prompt-status (M8 ch6) <<<"));
        assert!(s.contains("setopt PROMPT_SUBST"));
        assert!(s.contains("_TIRITH_PROMPT_STATUS_LOADED"));
        // Single-quoted so PROMPT re-renders each redraw, AND the non-exported
        // TIRITH_STATUS is forwarded inline so the child can actually read it
        // (a bare `tirith prompt-status` child sees a non-exported var as unset).
        assert!(s.contains("/opt/Tirith Bin/tirith"));
        assert!(!s.contains(" tirith prompt-status --short"));
    }

    #[test]
    fn prompt_status_snippet_bash_uses_ps1_with_single_quoted_subst() {
        let s = prompt_status_snippet("bash");
        assert!(s.contains("/opt/Tirith Bin/tirith"));
        assert!(!s.contains(" tirith prompt-status --short"));
        assert!(s.contains("_TIRITH_PROMPT_STATUS_LOADED"));
        assert!(s.contains("# >>> tirith prompt-status (M8 ch6) >>>"));
        assert!(s.contains("# <<< tirith prompt-status (M8 ch6) <<<"));
    }

    #[test]
    fn prompt_status_snippet_fish_wraps_right_prompt() {
        let s = prompt_status_snippet("fish");
        assert!(s.contains("function fish_right_prompt"));
        // Forwards the non-exported TIRITH_STATUS via `env` so the child sees it.
        assert!(s.contains("'/opt/Tirith Bin/tirith' prompt-status --short"));
        assert!(s.contains("_TIRITH_PROMPT_STATUS_LOADED"));
    }

    #[test]
    fn prompt_status_snippet_powershell_forwards_status_env() {
        let s = prompt_status_snippet("powershell");
        // PowerShell stores $global:TIRITH_STATUS (a PS variable, NOT $env:), which
        // a child process cannot see — forward it via $env: for the call, restored
        // in `finally` so it does not leak into the session.
        assert!(s.contains("$env:TIRITH_STATUS = $global:TIRITH_STATUS"));
        assert!(s.contains("finally"));
        assert!(s.contains("_TIRITH_PROMPT_STATUS_LOADED"));
    }

    #[test]
    fn prompt_status_snippet_powershell_wraps_prompt_function() {
        for shell in ["powershell", "pwsh"] {
            let s = prompt_status_snippet(shell);
            assert!(s.contains("function global:prompt"), "shell={shell}");
            assert!(
                s.contains("'/opt/Tirith Bin/tirith' prompt-status --short"),
                "shell={shell}"
            );
            assert!(s.contains("$global:_TIRITH_PROMPT_STATUS_LOADED"));
        }
    }

    #[test]
    fn prompt_status_snippet_quotes_an_executable_with_a_single_quote() {
        let executable = Path::new("/opt/Tirith's Bin/tirith");
        for shell in ["zsh", "bash", "fish", "powershell"] {
            let snippet = prompt_status_snippet_for(shell, executable);
            assert!(snippet.contains("Tirith"), "shell={shell}: {snippet}");
            assert!(!snippet.contains(" tirith prompt-status --short"));
        }
    }

    #[test]
    fn prompt_status_snippet_nushell_explains_no_live_status() {
        let s = prompt_status_snippet("nushell");
        // Nushell exposes no non-exported TIRITH_STATUS, so the snippet must be an
        // HONEST explanation (warn-only, no live status), NOT a prompt-status
        // command that would always render `off`.
        assert!(s.contains("warn-only"));
        assert!(s.contains("docs/prompt-status.md"));
        // Must NOT hand the user runnable prompt wiring that would render `off`.
        // (The `# >>> tirith prompt-status` MARKER legitimately names the command;
        // we guard against the old `$env.PROMPT_COMMAND` closure instead.)
        assert!(
            !s.contains("PROMPT_COMMAND"),
            "nushell snippet must not suggest a runnable prompt closure (always reads off); got: {s}"
        );
    }

    #[test]
    fn materialized_hooks_require_and_repair_exact_asset_and_version_bytes() {
        let data_dir = tempfile::tempdir().unwrap();
        let (shell_dir, wrote) = materialize_hooks_at(data_dir.path()).unwrap();
        assert!(wrote);
        assert_eq!(
            std::fs::read(shell_dir.join("tirith.sh")).unwrap(),
            crate::assets::TIRITH_SH.as_bytes()
        );
        assert_eq!(
            std::fs::read(shell_dir.join("lib/zsh-hook.zsh")).unwrap(),
            crate::assets::ZSH_HOOK.as_bytes()
        );
        assert_eq!(
            std::fs::read(shell_dir.join("lib/bash-hook.bash")).unwrap(),
            crate::assets::BASH_HOOK.as_bytes()
        );
        assert_eq!(
            std::fs::read(shell_dir.join("lib/fish-hook.fish")).unwrap(),
            crate::assets::FISH_HOOK.as_bytes()
        );
        assert_eq!(
            std::fs::read(shell_dir.join("lib/powershell-hook.ps1")).unwrap(),
            crate::assets::POWERSHELL_HOOK.as_bytes()
        );
        assert_eq!(
            std::fs::read(shell_dir.join("lib/nushell-hook.nu")).unwrap(),
            crate::assets::NUSHELL_HOOK.as_bytes()
        );
        assert_eq!(
            std::fs::read(shell_dir.join(".hooks-version")).unwrap(),
            format!("{}\n", env!("CARGO_PKG_VERSION")).as_bytes()
        );
        assert!(materialized_hooks_match_at(data_dir.path()).unwrap());

        std::fs::write(shell_dir.join("lib/zsh-hook.zsh"), b"tampered\n").unwrap();
        std::fs::write(
            shell_dir.join(".hooks-version"),
            format!("{}\n", env!("CARGO_PKG_VERSION")),
        )
        .unwrap();
        assert!(!materialized_hooks_match_at(data_dir.path()).unwrap());
        let (_, repaired) = materialize_hooks_at(data_dir.path()).unwrap();
        assert!(repaired);
        assert_eq!(
            std::fs::read(shell_dir.join("lib/zsh-hook.zsh")).unwrap(),
            crate::assets::ZSH_HOOK.as_bytes()
        );

        std::fs::write(shell_dir.join(".hooks-version"), env!("CARGO_PKG_VERSION")).unwrap();
        assert!(!materialized_hooks_match_at(data_dir.path()).unwrap());
        let (_, repaired_version) = materialize_hooks_at(data_dir.path()).unwrap();
        assert!(repaired_version);
        assert_eq!(
            std::fs::read(shell_dir.join(".hooks-version")).unwrap(),
            format!("{}\n", env!("CARGO_PKG_VERSION")).as_bytes()
        );
        let (_, rewrote_current_bundle) = materialize_hooks_at(data_dir.path()).unwrap();
        assert!(!rewrote_current_bundle);
    }

    #[cfg(unix)]
    #[test]
    fn materialized_hooks_reject_symlinked_lib_directory_without_external_write() {
        use std::os::unix::fs::symlink;

        let data_dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let shell_dir = data_dir.path().join("shell");
        std::fs::create_dir(&shell_dir).unwrap();
        symlink(outside.path(), shell_dir.join("lib")).unwrap();

        let error = materialize_hooks_at(data_dir.path()).unwrap_err();
        assert!(error.contains("could not bind materialized hook destination"));
        assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
        assert!(!shell_dir.join("tirith.sh").exists());
    }

    #[cfg(unix)]
    #[test]
    fn materialized_hooks_reject_symlinked_leaf_without_touching_target() {
        use std::os::unix::fs::symlink;

        let data_dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let sentinel = outside.path().join("sentinel");
        std::fs::write(&sentinel, b"unchanged").unwrap();
        let lib_dir = data_dir.path().join("shell/lib");
        std::fs::create_dir_all(&lib_dir).unwrap();
        symlink(&sentinel, lib_dir.join("zsh-hook.zsh")).unwrap();

        let error = materialize_hooks_at(data_dir.path()).unwrap_err();
        assert!(error.contains("could not bind materialized hook destination"));
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"unchanged");
        assert!(!data_dir.path().join("shell/tirith.sh").exists());
    }

    #[test]
    fn materialized_hooks_reject_non_directory_parents_and_non_regular_leaves() {
        let file_shell_root = tempfile::tempdir().unwrap();
        std::fs::write(file_shell_root.path().join("shell"), b"not a directory").unwrap();
        let shell_error = materialize_hooks_at(file_shell_root.path()).unwrap_err();
        assert!(shell_error.contains("could not bind materialized hook destination"));

        let file_lib_root = tempfile::tempdir().unwrap();
        let shell_dir = file_lib_root.path().join("shell");
        std::fs::create_dir(&shell_dir).unwrap();
        std::fs::write(shell_dir.join("lib"), b"not a directory").unwrap();
        let lib_error = materialize_hooks_at(file_lib_root.path()).unwrap_err();
        assert!(lib_error.contains("could not bind materialized hook destination"));
        assert!(!shell_dir.join("tirith.sh").exists());

        let directory_leaf_root = tempfile::tempdir().unwrap();
        let directory_leaf = directory_leaf_root.path().join("shell/lib/zsh-hook.zsh");
        std::fs::create_dir_all(&directory_leaf).unwrap();
        let leaf_error = materialize_hooks_at(directory_leaf_root.path()).unwrap_err();
        assert!(leaf_error.contains("refusing non-regular materialized hook destination"));
        assert!(!directory_leaf_root.path().join("shell/tirith.sh").exists());
    }
}
