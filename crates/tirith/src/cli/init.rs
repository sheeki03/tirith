#[cfg(unix)]
use libc;
use std::fs;
use std::path::PathBuf;
#[cfg(unix)]
use std::process::Command;

use crate::assets;

pub fn run(shell: Option<&str>) -> i32 {
    let shell = shell.unwrap_or_else(|| detect_shell());

    let hook_dir = find_hook_dir();

    match shell {
        "zsh" => {
            if let Some(dir) = &hook_dir {
                println!(r#"source "{}/lib/zsh-hook.zsh""#, dir.display());
            } else {
                eprintln!("tirith: could not locate or materialize shell hooks.");
                return 1;
            }
            0
        }
        "bash" => {
            if let Some(dir) = &hook_dir {
                println!(r#"source "{}/lib/bash-hook.bash""#, dir.display());
            } else {
                eprintln!("tirith: could not locate or materialize shell hooks.");
                return 1;
            }
            0
        }
        "fish" => {
            if let Some(dir) = &hook_dir {
                println!(r#"source "{}/lib/fish-hook.fish""#, dir.display());
            } else {
                eprintln!("tirith: could not locate or materialize shell hooks.");
                return 1;
            }
            0
        }
        "powershell" | "pwsh" => {
            if let Some(dir) = &hook_dir {
                println!(r#". "{}\lib\powershell-hook.ps1""#, dir.display());
            } else {
                eprintln!("tirith: could not locate or materialize shell hooks.");
                return 1;
            }
            0
        }
        _ => {
            eprintln!("tirith: unsupported shell '{shell}'");
            eprintln!("Supported: zsh, bash, fish, powershell");
            1
        }
    }
}

pub(crate) fn detect_shell() -> &'static str {
    if let Some(shell) = detect_shell_from_parent() {
        return shell;
    }

    if let Ok(shell) = std::env::var("SHELL") {
        if let Some(shell) = normalize_shell_name(&shell) {
            return shell;
        }
    }

    #[cfg(windows)]
    return "powershell";

    #[cfg(not(windows))]
    "bash"
}

fn normalize_shell_name(name: &str) -> Option<&'static str> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let base = name
        .rsplit('/')
        .next()
        .unwrap_or(name)
        .trim_start_matches('-')
        .to_ascii_lowercase();

    if base.contains("zsh") {
        Some("zsh")
    } else if base.contains("bash") {
        Some("bash")
    } else if base.contains("fish") {
        Some("fish")
    } else if base.contains("pwsh") || base.contains("powershell") {
        Some("powershell")
    } else {
        None
    }
}

#[cfg(unix)]
fn detect_shell_from_parent() -> Option<&'static str> {
    let mut pid = unsafe { libc::getppid() };

    // Walk ancestors because the immediate parent may be a wrapper process
    // (e.g., timeout/env) or a shell that exec'd into another program.
    for _ in 0..8 {
        if pid <= 1 {
            return None;
        }
        let (name, parent_pid) = read_process(pid)?;
        if let Some(shell) = normalize_shell_name(&name) {
            return Some(shell);
        }
        if parent_pid == pid {
            break;
        }
        pid = parent_pid;
    }

    None
}

#[cfg(unix)]
fn read_process(pid: libc::pid_t) -> Option<(String, libc::pid_t)> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm=", "-o", "ppid="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let line = String::from_utf8_lossy(&output.stdout);
    let mut parts = line.split_whitespace();
    let name = parts.next()?.to_string();
    let ppid = parts.next()?.parse::<libc::pid_t>().ok()?;
    Some((name, ppid))
}

#[cfg(not(unix))]
fn detect_shell_from_parent() -> Option<&'static str> {
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
    // 1. Explicit env var override
    if let Ok(dir) = std::env::var("TIRITH_SHELL_DIR") {
        let p = PathBuf::from(&dir);
        if p.join("lib").exists() {
            return Some(p);
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(bin_dir) = exe.parent() {
            // 2. Homebrew layout: ../share/tirith/shell
            let brew_dir = bin_dir.join("../share/tirith/shell");
            if brew_dir.join("lib").exists() {
                return Some(brew_dir.canonicalize().unwrap_or(brew_dir));
            }

            // 3. System package layout: /usr/share/tirith/shell
            #[cfg(unix)]
            {
                let sys_dir = PathBuf::from("/usr/share/tirith/shell");
                if sys_dir.join("lib").exists() {
                    return Some(sys_dir);
                }
            }

            // 4. cargo install layout: ../shell
            let cargo_dir = bin_dir.join("../shell");
            if cargo_dir.join("lib").exists() {
                return Some(cargo_dir.canonicalize().unwrap_or(cargo_dir));
            }

            // 5. Workspace dev layout: ../../shell
            let dev_dir = bin_dir.join("../../shell");
            if dev_dir.join("lib").exists() {
                return Some(dev_dir.canonicalize().unwrap_or(dev_dir));
            }
        }
    }

    // 6. Fallback: materialize embedded hooks to data dir
    materialize_hooks()
}

/// Find the shell hooks directory without materializing (read-only variant for diagnostics).
pub fn find_hook_dir_readonly() -> Option<PathBuf> {
    // 1. Explicit env var override
    if let Ok(dir) = std::env::var("TIRITH_SHELL_DIR") {
        let p = PathBuf::from(&dir);
        if p.join("lib").exists() {
            return Some(p);
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(bin_dir) = exe.parent() {
            // 2. Homebrew layout: ../share/tirith/shell
            let brew_dir = bin_dir.join("../share/tirith/shell");
            if brew_dir.join("lib").exists() {
                return Some(brew_dir.canonicalize().unwrap_or(brew_dir));
            }

            // 3. System package layout: /usr/share/tirith/shell
            #[cfg(unix)]
            {
                let sys_dir = PathBuf::from("/usr/share/tirith/shell");
                if sys_dir.join("lib").exists() {
                    return Some(sys_dir);
                }
            }

            // 4. cargo install layout: ../shell
            let cargo_dir = bin_dir.join("../shell");
            if cargo_dir.join("lib").exists() {
                return Some(cargo_dir.canonicalize().unwrap_or(cargo_dir));
            }

            // 5. Workspace dev layout: ../../shell
            let dev_dir = bin_dir.join("../../shell");
            if dev_dir.join("lib").exists() {
                return Some(dev_dir.canonicalize().unwrap_or(dev_dir));
            }
        }
    }

    // 6. Check if hooks were previously materialized (but don't create them)
    if let Some(data_dir) = tirith_core::policy::data_dir() {
        let shell_dir = data_dir.join("shell");
        if shell_dir.join("lib").exists() {
            return Some(shell_dir);
        }
    }

    None
}

/// Write embedded hook files to the user data directory.
/// Returns the shell directory path if successful.
fn materialize_hooks() -> Option<PathBuf> {
    let data_dir = tirith_core::policy::data_dir()?;
    let shell_dir = data_dir.join("shell");
    let lib_dir = shell_dir.join("lib");
    let version_path = shell_dir.join(".hooks-version");
    let current_version = env!("CARGO_PKG_VERSION");

    // Re-materialize if required files are missing or embedded hook version changed.
    let required_files = [
        shell_dir.join("tirith.sh"),
        lib_dir.join("zsh-hook.zsh"),
        lib_dir.join("bash-hook.bash"),
        lib_dir.join("fish-hook.fish"),
        lib_dir.join("powershell-hook.ps1"),
    ];
    let version_matches = fs::read_to_string(&version_path)
        .ok()
        .map(|v| v.trim() == current_version)
        .unwrap_or(false);
    let needs_write = !required_files.iter().all(|p| p.exists()) || !version_matches;

    if needs_write {
        fs::create_dir_all(&lib_dir).ok()?;

        fs::write(shell_dir.join("tirith.sh"), assets::TIRITH_SH).ok()?;
        fs::write(lib_dir.join("zsh-hook.zsh"), assets::ZSH_HOOK).ok()?;
        fs::write(lib_dir.join("bash-hook.bash"), assets::BASH_HOOK).ok()?;
        fs::write(lib_dir.join("fish-hook.fish"), assets::FISH_HOOK).ok()?;
        fs::write(lib_dir.join("powershell-hook.ps1"), assets::POWERSHELL_HOOK).ok()?;
        fs::write(&version_path, format!("{current_version}\n")).ok()?;

        eprintln!(
            "tirith: materialized shell hooks to {}",
            shell_dir.display()
        );
    }

    Some(shell_dir)
}

#[cfg(test)]
mod tests {
    use super::normalize_shell_name;

    #[test]
    fn normalize_shell_name_from_paths_and_login_shells() {
        assert_eq!(normalize_shell_name("/bin/bash"), Some("bash"));
        assert_eq!(normalize_shell_name("/opt/homebrew/bin/fish"), Some("fish"));
        assert_eq!(normalize_shell_name("-zsh"), Some("zsh"));
    }

    #[test]
    fn normalize_shell_name_supports_case_insensitive_names() {
        assert_eq!(normalize_shell_name("BASH"), Some("bash"));
        assert_eq!(normalize_shell_name("PwSh"), Some("powershell"));
        assert_eq!(normalize_shell_name("PowerShell"), Some("powershell"));
    }

    #[test]
    fn normalize_shell_name_rejects_unknown_values() {
        assert_eq!(normalize_shell_name(""), None);
        assert_eq!(normalize_shell_name("python"), None);
    }
}
