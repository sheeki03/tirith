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

const PROFILE_READ_CAP: u64 = 1024 * 1024;

fn read_profile_retained(
    profile: &std::path::Path,
) -> std::io::Result<(
    PathBuf,
    Option<tirith_core::util::ContainedAtomicFile>,
    String,
    bool,
)> {
    let root = profile
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let policy = tirith_core::policy::Policy::discover_local_only(None);
    super::preflight_config_write_authorization(&root, profile, true, &policy, false)?;
    let destination = match tirith_core::util::ContainedAtomicFile::prepare(&root, profile, false) {
        Ok(destination) => destination,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((root, None, String::new(), false));
        }
        Err(error) => return Err(error),
    };
    destination.lock_parent_for_mutation()?;
    match destination.read_capped(PROFILE_READ_CAP) {
        Ok(bytes) => {
            let content = String::from_utf8(bytes).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "shell profile is not valid UTF-8",
                )
            })?;
            Ok((root, Some(destination), content, true))
        }
        Err(tirith_core::util::OpenRegularError::NotFound) => {
            Ok((root, Some(destination), String::new(), false))
        }
        Err(error) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("refusing unsafe shell profile: {error:?}"),
        )),
    }
}

fn publish_profile(
    root: &std::path::Path,
    profile: &std::path::Path,
    destination: Option<tirith_core::util::ContainedAtomicFile>,
    contents: &[u8],
) -> std::io::Result<()> {
    let policy = tirith_core::policy::Policy::discover_local_only(None);
    publish_profile_with_policy(root, profile, destination, contents, &policy)
}

fn publish_profile_with_policy(
    root: &std::path::Path,
    profile: &std::path::Path,
    destination: Option<tirith_core::util::ContainedAtomicFile>,
    contents: &[u8],
    policy: &tirith_core::policy::Policy,
) -> std::io::Result<()> {
    super::preflight_config_write_authorization(root, profile, true, policy, false)?;
    let destination = match destination {
        Some(destination) => destination,
        None => {
            let destination = tirith_core::util::ContainedAtomicFile::prepare(root, profile, true)?;
            destination.lock_parent_for_mutation()?;
            destination.expect_absent_preimage()?;
            destination
        }
    };
    super::write_prepared_config_file_permitted(
        root,
        profile,
        destination,
        contents,
        true,
        policy,
        false,
    )
}

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

    // repo-0224: only a MISSING file means "empty profile". Any other read
    // failure (invalid UTF-8, permissions, transient I/O) must abort rather
    // than replacing the real profile with just our snippet.
    let (root, mut destination, current, _) = match read_profile_retained(&profile) {
        Ok(profile) => profile,
        Err(e) => {
            eprintln!(
                "tirith output wrap: cannot read {} ({e}); refusing to modify it",
                profile.display()
            );
            return 1;
        }
    };
    if current.contains(BEGIN_MARKER) {
        // repo-0225: a present BEGIN marker is not proof of a healthy block.
        // Compare the exact managed block; a tampered/obsolete one is repaired
        // in place so enable actually guarantees the wrapper exists.
        let expected = build_snippet(shell);
        let existing_block = {
            let mut found = String::new();
            let mut in_block = false;
            for line in current.lines() {
                if line == BEGIN_MARKER {
                    in_block = true;
                }
                if in_block {
                    found.push_str(line);
                    found.push('\n');
                }
                if in_block && line == END_MARKER {
                    break;
                }
            }
            found
        };
        if existing_block == expected {
            eprintln!(
                "tirith output wrap: already enabled in {} (no changes made)",
                profile.display()
            );
            eprintln!("  function:  tirith-output-guard-wrap");
            eprintln!("  alias:     tirith-out");
            return 0;
        }
        let Some(stripped) = strip_block(&current) else {
            eprintln!(
                "tirith output wrap: the tirith block in {} is corrupted (missing END marker); fix it manually — no changes made",
                profile.display()
            );
            return 1;
        };
        let new_content = format!("{stripped}{expected}");
        if let Err(e) = publish_profile(&root, &profile, destination.take(), new_content.as_bytes())
        {
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

    let snippet = build_snippet(shell);
    let separator = if current.is_empty() || current.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    let new_content = format!("{current}{separator}{snippet}");
    // Atomic write: a crash mid read-modify-write of the user's rc file must
    // never truncate or corrupt their shell config.
    if let Err(e) = publish_profile(&root, &profile, destination.take(), new_content.as_bytes()) {
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

    let (root, destination, current, existed) = match read_profile_retained(&profile) {
        Ok(profile) => profile,
        Err(error) => {
            eprintln!(
                "tirith output wrap: cannot read {} ({error}); refusing to modify it",
                profile.display()
            );
            return 1;
        }
    };
    if !existed {
        eprintln!(
            "tirith output wrap: {} not found — nothing to disable",
            profile.display()
        );
        return 0;
    }

    if !current.contains(BEGIN_MARKER) {
        eprintln!(
            "tirith output wrap: not currently enabled in {} (no changes made)",
            profile.display()
        );
        return 0;
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
    if let Err(e) = publish_profile(&root, &profile, destination, new_content.as_bytes()) {
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
            "{begin}\nfunction tirith-output-guard-wrap\n    if test (count $argv) -eq 0\n        echo 'tirith-output-guard-wrap: usage: tirith-out <cmd> [args...]' >&2\n        return 2\n    end\n    $argv 2>&1 | tirith view --max-bytes 16777216 -\nend\nalias tirith-out 'tirith-output-guard-wrap'\n{end}\n",
            begin = BEGIN_MARKER,
            end = END_MARKER,
        ),
        "nushell" => format!(
            "{begin}\ndef tirith-output-guard-wrap [...cmd] {{\n    if ($cmd | length) == 0 {{\n        print --stderr 'tirith-output-guard-wrap: usage: tirith-out <cmd> [args...]'\n        return 2\n    }}\n    run-external $cmd.0 ...($cmd | skip 1) | tirith view --max-bytes 16777216 -\n}}\nalias tirith-out = tirith-output-guard-wrap\n{end}\n",
            begin = BEGIN_MARKER,
            end = END_MARKER,
        ),
        // repo-0226: `pwsh` is PowerShell 7's shell label — it needs the
        // PowerShell snippet, not the POSIX one.
        "powershell" | "pwsh" => format!(
            "{begin}\nfunction tirith-output-guard-wrap {{\n    param([Parameter(ValueFromRemainingArguments=$true)]$Args)\n    if ($Args.Count -eq 0) {{\n        Write-Error 'tirith-output-guard-wrap: usage: tirith-out <cmd> [args...]'\n        return\n    }}\n    if ($Args.Count -eq 1) {{ & $Args[0] 2>&1 | & tirith view --max-bytes 16777216 - }} else {{ & $Args[0] $Args[1..($Args.Count-1)] 2>&1 | & tirith view --max-bytes 16777216 - }}\n}}\nSet-Alias tirith-out tirith-output-guard-wrap\n{end}\n",
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

    #[test]
    fn denied_profile_write_creates_neither_parent_nor_file() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("missing-profile-dir");
        let profile = parent.join("config.nu");
        let mut policy = tirith_core::policy::Policy::default();
        policy.task_gate.mode = tirith_core::web3_policy::TaskGateMode::Enforce;
        policy
            .task_gate
            .effects_denied_for_untrusted_sources
            .insert(tirith_core::effects::CommandEffectKind::PersistenceChange);

        let error = publish_profile_with_policy(&parent, &profile, None, b"managed\n", &policy)
            .expect_err("task gate must refuse profile persistence");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!parent.exists());
        assert!(!profile.exists());
    }
}
