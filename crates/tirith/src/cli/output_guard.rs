//! `tirith output wrap on|off|status` — manage the opt-in `tirith-out` shell
//! function that pipes a command's stdout/stderr through the view-style filter.
//!
//! This WRAPS individually-invoked commands (`tirith-out ./myscript`); it does
//! NOT intercept output from anything run outside the wrapper.
//!
//! `on` appends an idempotent BEGIN/END marker block (function + `tirith-out`
//! alias) to the user's shell profile; `off` removes it preserving surrounding
//! content; `status` reports presence, profile path, and function name. The
//! on-disk function name is `tirith-output-guard-wrap` (low collision risk).

use std::fs;
use std::path::PathBuf;

/// BEGIN / END markers for the `tirith output wrap` block. Distinct from the
/// `tirith init` hook markers so the two regions are independently removable.
const BEGIN_MARKER: &str = "# BEGIN tirith-output-wrap v1";
const END_MARKER: &str = "# END tirith-output-wrap";

pub fn run(action: &str) -> i32 {
    match action {
        "on" => enable(),
        "off" => disable(),
        "status" => status(),
        other => {
            eprintln!("tirith output wrap: unknown action '{other}' — expected on|off|status");
            2
        }
    }
}

fn enable() -> i32 {
    let Some((shell, profile)) = detect_profile() else {
        eprintln!("tirith output wrap: could not detect shell profile (set SHELL or run again with --shell)");
        return 1;
    };

    if let Some(parent) = profile.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!(
                "tirith output wrap: failed to create profile dir {}: {e}",
                parent.display()
            );
            return 1;
        }
    }

    // repo-0224: only a MISSING file means "empty profile". Any other read
    // failure (invalid UTF-8, permissions, transient I/O) must abort rather
    // than replacing the real profile with just our snippet.
    let current = match fs::read_to_string(&profile) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            eprintln!(
                "tirith output wrap: cannot read {} ({e}); refusing to modify it",
                profile.display()
            );
            return 1;
        }
    };
    let expected = build_snippet(shell);
    match managed_block(&current) {
        Ok(Some(existing_block)) if existing_block == expected => {
            eprintln!(
                "tirith output wrap: already enabled in {} (no changes made)",
                profile.display()
            );
            eprintln!("  function:  tirith-output-guard-wrap");
            eprintln!("  alias:     tirith-out");
            return 0;
        }
        Ok(Some(_)) => {
            // repo-0225: a present BEGIN marker is not proof of a healthy block.
            // A balanced but obsolete managed block can be replaced safely.
            let Some(stripped) = strip_block(&current) else {
                eprintln!(
                    "tirith output wrap: the tirith block in {} is corrupted; fix it manually — no changes made",
                    profile.display()
                );
                return 1;
            };
            let new_content = format!("{stripped}{expected}");
            if let Err(e) = super::write_file_atomic(&profile, new_content.as_bytes(), true) {
                eprintln!(
                    "tirith output wrap: failed to repair {}: {e}",
                    profile.display()
                );
                return 1;
            }
            eprintln!(
                "tirith output wrap: repaired the tirith block in {} (function: tirith-output-guard-wrap, alias: tirith-out)",
                profile.display()
            );
            return 0;
        }
        Err(()) => {
            eprintln!(
                "tirith output wrap: the tirith block in {} is corrupted; fix it manually — no changes made",
                profile.display()
            );
            return 1;
        }
        Ok(None) => {}
    }

    let separator = if current.is_empty() || current.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    let new_content = format!("{current}{separator}{expected}");
    // Atomic write: a crash mid read-modify-write of the user's rc file must
    // never truncate or corrupt their shell config.
    if let Err(e) = super::write_file_atomic(&profile, new_content.as_bytes(), true) {
        eprintln!(
            "tirith output wrap: failed to write {}: {e}",
            profile.display()
        );
        return 1;
    }

    println!(
        "tirith output wrap: enabled in {} ({} shell)",
        profile.display(),
        shell
    );
    println!("  function:  tirith-output-guard-wrap");
    println!("  alias:     tirith-out");
    println!("  scope:     wraps INDIVIDUAL commands invoked via `tirith-out <cmd>`;");
    println!("             does NOT intercept output from commands run outside the wrapper.");
    println!(
        "  next:      reload your shell, or `source {}`",
        profile.display()
    );
    0
}

fn disable() -> i32 {
    let Some((_shell, profile)) = detect_profile() else {
        eprintln!("tirith output wrap: could not detect shell profile");
        return 1;
    };

    let current = match fs::read_to_string(&profile) {
        Ok(current) => current,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "tirith output wrap: {} not found — nothing to disable",
                profile.display()
            );
            return 0;
        }
        Err(error) => {
            eprintln!(
                "tirith output wrap: cannot read {} ({error}); refusing to modify it",
                profile.display()
            );
            return 1;
        }
    };

    match managed_block(&current) {
        Ok(None) => {
            eprintln!(
                "tirith output wrap: not currently enabled in {} (no changes made)",
                profile.display()
            );
            return 0;
        }
        Ok(Some(_)) => {}
        Err(()) => {
            eprintln!(
                "tirith output wrap: the tirith block in {} is corrupted; fix it manually — no changes made",
                profile.display()
            );
            return 1;
        }
    }

    let Some(new_content) = strip_block(&current) else {
        // repo-0225: an unterminated/tampered block must fail loudly — silently
        // publishing would discard every profile line after the BEGIN marker.
        eprintln!(
            "tirith output wrap: the tirith block in {} is corrupted (missing END marker); fix it manually — no changes made",
            profile.display()
        );
        return 1;
    };
    // Atomic write (see `enable`): removing the block also rewrites the rc file.
    if let Err(e) = super::write_file_atomic(&profile, new_content.as_bytes(), true) {
        eprintln!(
            "tirith output wrap: failed to write {}: {e}",
            profile.display()
        );
        return 1;
    }

    println!("tirith output wrap: disabled in {}", profile.display());
    0
}

fn status() -> i32 {
    let Some((shell, profile)) = detect_profile() else {
        eprintln!("tirith output wrap: status — could not detect shell profile");
        return 1;
    };
    let current = match fs::read_to_string(&profile) {
        Ok(current) => current,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => {
            eprintln!(
                "tirith output wrap: cannot read {} ({error}); status is unknown",
                profile.display()
            );
            return 1;
        }
    };
    let block = managed_block(&current);
    let enabled = matches!(block, Ok(Some(_)));
    let healthy = match &block {
        Ok(None) => true,
        Ok(Some(found)) => found == &build_snippet(shell),
        Err(()) => false,
    };
    println!("tirith output wrap status");
    println!("  shell:     {shell}");
    println!("  profile:   {}", profile.display());
    println!(
        "  enabled:   {}",
        if enabled && healthy {
            "yes"
        } else if enabled {
            "invalid/outdated"
        } else {
            "no"
        }
    );
    if enabled && healthy {
        println!("  function:  tirith-output-guard-wrap");
        println!("  alias:     tirith-out");
    }
    println!("  scope:     wraps INDIVIDUAL commands invoked via `tirith-out <cmd>`;");
    println!("             does NOT intercept output from commands run outside the wrapper.");
    if healthy {
        0
    } else {
        1
    }
}

/// Return the one balanced managed block, including marker lines and its final
/// newline. Duplicate, nested, stray, or unterminated markers are corruption.
fn managed_block(content: &str) -> Result<Option<String>, ()> {
    let mut block = String::new();
    let mut in_block = false;
    let mut found = false;

    for line in content.lines() {
        if line == BEGIN_MARKER {
            if in_block || found {
                return Err(());
            }
            found = true;
            in_block = true;
        } else if line == END_MARKER && !in_block {
            return Err(());
        }

        if in_block {
            block.push_str(line);
            block.push('\n');
            if line == END_MARKER {
                in_block = false;
            }
        }
    }

    if in_block {
        Err(())
    } else if found {
        Ok(Some(block))
    } else {
        Ok(None)
    }
}

/// Strip the BEGIN…END block (inclusive), preserving surrounding user content.
/// Returns `None` when the BEGIN marker has no matching END (repo-0225): a
/// corrupted block must NOT truncate every following line of the profile.
fn strip_block(content: &str) -> Option<String> {
    let mut out = String::with_capacity(content.len());
    let mut in_block = false;
    let mut first = true;
    for line in content.lines() {
        if line == BEGIN_MARKER {
            if in_block {
                return None; // nested BEGIN: corrupted
            }
            in_block = true;
            continue;
        }
        if in_block {
            if line == END_MARKER {
                in_block = false;
            }
            continue;
        }
        if !first {
            out.push('\n');
        }
        first = false;
        out.push_str(line);
    }
    if in_block {
        return None; // unterminated block
    }
    if content.ends_with('\n') && !out.ends_with('\n') {
        out.push('\n');
    }
    Some(out)
}

fn build_snippet(shell: &str) -> String {
    match shell {
        "fish" => format!(
            "{BEGIN_MARKER}\nfunction tirith-output-guard-wrap\n    if test (count $argv) -eq 0\n        echo 'tirith-output-guard-wrap: usage: tirith-out <cmd> [args...]' >&2\n        return 2\n    end\n    $argv 2>&1 | tirith view --max-bytes 16777216 -\nend\nalias tirith-out 'tirith-output-guard-wrap'\n{END_MARKER}\n",
        ),
        "nushell" => format!(
            "{BEGIN_MARKER}\ndef tirith-output-guard-wrap [...cmd] {{\n    if ($cmd | length) == 0 {{\n        print --stderr 'tirith-output-guard-wrap: usage: tirith-out <cmd> [args...]'\n        return 2\n    }}\n    run-external $cmd.0 ...($cmd | skip 1) | tirith view --max-bytes 16777216 -\n}}\nalias tirith-out = tirith-output-guard-wrap\n{END_MARKER}\n",
        ),
        // repo-0226: `pwsh` is PowerShell 7's shell label — it needs the
        // PowerShell snippet, not the POSIX one.
        "powershell" | "pwsh" => format!(
            "{BEGIN_MARKER}\nfunction tirith-output-guard-wrap {{\n    param([Parameter(ValueFromRemainingArguments=$true)]$Args)\n    if ($Args.Count -eq 0) {{\n        Write-Error 'tirith-output-guard-wrap: usage: tirith-out <cmd> [args...]'\n        return\n    }}\n    if ($Args.Count -eq 1) {{ & $Args[0] 2>&1 | & tirith view --max-bytes 16777216 - }} else {{ & $Args[0] $Args[1..($Args.Count-1)] 2>&1 | & tirith view --max-bytes 16777216 - }}\n}}\nSet-Alias tirith-out tirith-output-guard-wrap\n{END_MARKER}\n",
        ),
        // zsh / bash / posix sh share one snippet.
        _ => format!(
            "{BEGIN_MARKER}\ntirith-output-guard-wrap() {{\n    if [ \"$#\" -eq 0 ]; then\n        echo 'tirith-output-guard-wrap: usage: tirith-out <cmd> [args...]' >&2\n        return 2\n    fi\n    \"$@\" 2>&1 | command tirith view --max-bytes 16777216 -\n}}\nalias tirith-out='tirith-output-guard-wrap'\n{END_MARKER}\n",
        ),
    }
}

fn detect_profile() -> Option<(&'static str, PathBuf)> {
    let home = home::home_dir()?;
    let shell = crate::cli::init::detect_shell();
    let profile = match shell {
        "zsh" => home.join(".zshrc"),
        "bash" => {
            let bashrc = home.join(".bashrc");
            let bash_profile = home.join(".bash_profile");
            if bashrc.exists() {
                bashrc
            } else if bash_profile.exists() {
                bash_profile
            } else {
                bashrc
            }
        }
        "fish" => home.join(".config").join("fish").join("config.fish"),
        "nushell" => home.join(".config").join("nushell").join("config.nu"),
        "powershell" | "pwsh" => home
            .join(".config")
            .join("powershell")
            .join("Microsoft.PowerShell_profile.ps1"),
        _ => return None,
    };
    Some((shell, profile))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_block_removes_inserted_section() {
        let content = format!("before line\n{BEGIN_MARKER}\nfunc def\n{END_MARKER}\nafter line\n",);
        let out = strip_block(&content).expect("balanced block strips");
        assert!(out.contains("before line"));
        assert!(out.contains("after line"));
        assert!(!out.contains(BEGIN_MARKER));
        assert!(!out.contains(END_MARKER));
        assert!(!out.contains("func def"));
    }

    #[test]
    fn strip_block_no_marker_is_noop() {
        let content = "alpha\nbeta\n";
        assert_eq!(strip_block(content).as_deref(), Some(content));
    }

    #[test]
    fn managed_block_requires_one_balanced_exact_region() {
        let expected = build_snippet("zsh");
        assert_eq!(managed_block(&expected), Ok(Some(expected.clone())));
        assert_eq!(managed_block("ordinary profile\n"), Ok(None));
        assert_eq!(managed_block(BEGIN_MARKER), Err(()));
        assert_eq!(managed_block(END_MARKER), Err(()));
        assert_eq!(managed_block(&format!("{expected}{expected}")), Err(()));
    }

    #[test]
    fn snippet_zsh_contains_function_and_alias() {
        let s = build_snippet("zsh");
        assert!(s.contains("tirith-output-guard-wrap()"));
        assert!(s.contains("alias tirith-out='tirith-output-guard-wrap'"));
        assert!(s.contains(BEGIN_MARKER));
        assert!(s.contains(END_MARKER));
    }

    #[test]
    fn snippet_fish_uses_function_keyword() {
        let s = build_snippet("fish");
        assert!(s.contains("function tirith-output-guard-wrap"));
        assert!(s.contains("alias tirith-out 'tirith-output-guard-wrap'"));
    }
}
