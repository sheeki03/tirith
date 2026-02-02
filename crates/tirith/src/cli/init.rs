use std::fs;
use std::path::PathBuf;

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
                println!(r#"export TIRITH_BASH_MODE=enter"#);
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

fn detect_shell() -> &'static str {
    if let Ok(shell) = std::env::var("SHELL") {
        if shell.contains("zsh") {
            return "zsh";
        }
        if shell.contains("bash") {
            return "bash";
        }
        if shell.contains("fish") {
            return "fish";
        }
    }

    #[cfg(windows)]
    return "powershell";

    #[cfg(not(windows))]
    "bash"
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

/// Write embedded hook files to the user data directory.
/// Returns the shell directory path if successful.
fn materialize_hooks() -> Option<PathBuf> {
    let data_dir = tirith_core::policy::data_dir()?;
    let shell_dir = data_dir.join("shell");
    let lib_dir = shell_dir.join("lib");

    // Check if we need to materialize (files missing or binary newer)
    let needs_write = !lib_dir.join("zsh-hook.zsh").exists() || binary_newer_than(&lib_dir);

    if needs_write {
        fs::create_dir_all(&lib_dir).ok()?;

        fs::write(shell_dir.join("tirith.sh"), assets::TIRITH_SH).ok()?;
        fs::write(lib_dir.join("zsh-hook.zsh"), assets::ZSH_HOOK).ok()?;
        fs::write(lib_dir.join("bash-hook.bash"), assets::BASH_HOOK).ok()?;
        fs::write(lib_dir.join("fish-hook.fish"), assets::FISH_HOOK).ok()?;
        fs::write(lib_dir.join("powershell-hook.ps1"), assets::POWERSHELL_HOOK).ok()?;

        eprintln!(
            "tirith: materialized shell hooks to {}",
            shell_dir.display()
        );
    }

    Some(shell_dir)
}

/// Check if the binary is newer than existing hook files.
fn binary_newer_than(lib_dir: &std::path::Path) -> bool {
    let exe_mtime = std::env::current_exe()
        .ok()
        .and_then(|p| fs::metadata(p).ok())
        .and_then(|m| m.modified().ok());

    let hook_mtime = fs::metadata(lib_dir.join("zsh-hook.zsh"))
        .ok()
        .and_then(|m| m.modified().ok());

    match (exe_mtime, hook_mtime) {
        (Some(exe), Some(hook)) => exe > hook,
        _ => true, // If we can't compare, re-materialize
    }
}
