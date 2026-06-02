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

    let current = fs::read_to_string(&profile).unwrap_or_default();
    if current.contains(BEGIN_MARKER) {
        eprintln!(
            "tirith output wrap: already enabled in {} (no changes made)",
            profile.display()
        );
        eprintln!("  function:  tirith-output-guard-wrap");
        eprintln!("  alias:     tirith-out");
        return 0;
    }

    let snippet = build_snippet(shell);
    let separator = if current.is_empty() || current.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    let new_content = format!("{current}{separator}{snippet}");
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

    let Ok(current) = fs::read_to_string(&profile) else {
        eprintln!(
            "tirith output wrap: {} not found — nothing to disable",
            profile.display()
        );
        return 0;
    };

    if !current.contains(BEGIN_MARKER) {
        eprintln!(
            "tirith output wrap: not currently enabled in {} (no changes made)",
            profile.display()
        );
        return 0;
    }

    let new_content = strip_block(&current);
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
    let current = fs::read_to_string(&profile).unwrap_or_default();
    let enabled = current.contains(BEGIN_MARKER);
    println!("tirith output wrap status");
    println!("  shell:     {shell}");
    println!("  profile:   {}", profile.display());
    println!("  enabled:   {}", if enabled { "yes" } else { "no" });
    if enabled {
        println!("  function:  tirith-output-guard-wrap");
        println!("  alias:     tirith-out");
    }
    println!("  scope:     wraps INDIVIDUAL commands invoked via `tirith-out <cmd>`;");
    println!("             does NOT intercept output from commands run outside the wrapper.");
    0
}

/// Strip the BEGIN…END block (inclusive), preserving surrounding user content.
fn strip_block(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut in_block = false;
    let mut first = true;
    for line in content.lines() {
        if line == BEGIN_MARKER {
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
    if content.ends_with('\n') && !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn build_snippet(shell: &str) -> String {
    match shell {
        "fish" => format!(
            "{begin}\nfunction tirith-output-guard-wrap\n    if test (count $argv) -eq 0\n        echo 'tirith-output-guard-wrap: usage: tirith-out <cmd> [args...]' >&2\n        return 2\n    end\n    $argv 2>&1 | tirith view --max-bytes 16777216 -\nend\nalias tirith-out 'tirith-output-guard-wrap'\n{end}\n",
            begin = BEGIN_MARKER,
            end = END_MARKER,
        ),
        "nushell" => format!(
            "{begin}\ndef tirith-output-guard-wrap [...cmd] {{\n    if ($cmd | length) == 0 {{\n        print --stderr 'tirith-output-guard-wrap: usage: tirith-out <cmd> [args...]'\n        return 2\n    }}\n    run-external $cmd.0 ...($cmd | skip 1) | tirith view --max-bytes 16777216 -\n}}\nalias tirith-out = tirith-output-guard-wrap\n{end}\n",
            begin = BEGIN_MARKER,
            end = END_MARKER,
        ),
        "powershell" => format!(
            "{begin}\nfunction tirith-output-guard-wrap {{\n    param([Parameter(ValueFromRemainingArguments=$true)]$Args)\n    if ($Args.Count -eq 0) {{\n        Write-Error 'tirith-output-guard-wrap: usage: tirith-out <cmd> [args...]'\n        return\n    }}\n    & $Args[0] $Args[1..($Args.Count-1)] 2>&1 | & tirith view --max-bytes 16777216 -\n}}\nSet-Alias tirith-out tirith-output-guard-wrap\n{end}\n",
            begin = BEGIN_MARKER,
            end = END_MARKER,
        ),
        // zsh / bash / posix sh share one snippet.
        _ => format!(
            "{begin}\ntirith-output-guard-wrap() {{\n    if [ \"$#\" -eq 0 ]; then\n        echo 'tirith-output-guard-wrap: usage: tirith-out <cmd> [args...]' >&2\n        return 2\n    fi\n    \"$@\" 2>&1 | command tirith view --max-bytes 16777216 -\n}}\nalias tirith-out='tirith-output-guard-wrap'\n{end}\n",
            begin = BEGIN_MARKER,
            end = END_MARKER,
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
        let content = format!(
            "before line\n{begin}\nfunc def\n{end}\nafter line\n",
            begin = BEGIN_MARKER,
            end = END_MARKER,
        );
        let out = strip_block(&content);
        assert!(out.contains("before line"));
        assert!(out.contains("after line"));
        assert!(!out.contains(BEGIN_MARKER));
        assert!(!out.contains(END_MARKER));
        assert!(!out.contains("func def"));
    }

    #[test]
    fn strip_block_no_marker_is_noop() {
        let content = "alpha\nbeta\n";
        assert_eq!(strip_block(content), content);
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
