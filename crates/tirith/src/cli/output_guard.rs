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
    let target = match detect_profile() {
        Ok(found) => found,
        Err(reason) => {
            eprintln!("tirith output wrap: could not detect shell profile (set SHELL or run again with --shell)");
            print_profile_reason(&reason);
            return 1;
        }
    };
    let code = enable_at(target.shell, &target.profile);
    if code == 0 {
        if let Some(stale) = &target.stale {
            // The wrapper now lives where the shell reads it; the old copy is
            // only clutter, so a failure to remove it is reported, not fatal.
            let _ = remove_stale_copy(target.shell, stale);
        }
    }
    code
}

fn enable_at(shell: &str, profile: &std::path::Path) -> i32 {
    // repo-0224: only a MISSING file means "empty profile". Any other read
    // failure (invalid UTF-8, permissions, transient I/O) must abort rather
    // than replacing the real profile with just our snippet.
    let (root, mut destination, current, _) = match read_profile_retained(profile) {
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
        if let Err(e) = publish_profile(&root, profile, destination.take(), new_content.as_bytes())
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
    if let Err(e) = publish_profile(&root, profile, destination.take(), new_content.as_bytes()) {
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
    let target = match detect_profile() {
        Ok(found) => found,
        Err(reason) => {
            eprintln!("tirith output wrap: could not detect shell profile");
            print_profile_reason(&reason);
            return 1;
        }
    };
    let code = disable_at(&target.profile);
    match &target.stale {
        Some(stale) if !remove_stale_copy(target.shell, stale) => 1,
        _ => code,
    }
}

/// Remove an older release's wrapper block from a profile the shell does not
/// read at startup. Prints the outcome; returns false when the block remains.
fn remove_stale_copy(shell: &str, stale: &std::path::Path) -> bool {
    let (root, destination, current, existed) = match read_profile_retained(stale) {
        Ok(found) => found,
        Err(error) => {
            print_stale_left(shell, stale, &format!("cannot read it: {error}"));
            return false;
        }
    };
    if !existed || !current.contains(BEGIN_MARKER) {
        return true;
    }
    let Some(new_content) = strip_block(&current) else {
        print_stale_left(shell, stale, "its block is missing the END marker");
        return false;
    };
    if let Err(error) = publish_profile(&root, stale, destination, new_content.as_bytes()) {
        print_stale_left(shell, stale, &format!("write failed: {error}"));
        return false;
    }
    eprintln!(
        "tirith output wrap: removed the older copy from {} ({shell} does not read that file at startup)",
        stale.display()
    );
    true
}

fn print_stale_left(shell: &str, stale: &std::path::Path, reason: &str) {
    eprintln!(
        "tirith output wrap: an older copy remains in {}, which {shell} does not read at startup; could not remove it ({reason}). Delete the lines from `{BEGIN_MARKER}` to `{END_MARKER}` there.",
        stale.display()
    );
}

fn disable_at(profile: &std::path::Path) -> i32 {
    let (root, destination, current, existed) = match read_profile_retained(profile) {
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
    if let Err(e) = publish_profile(&root, profile, destination, new_content.as_bytes()) {
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
    let ProfileTarget {
        shell,
        profile,
        stale,
    } = match detect_profile() {
        Ok(found) => found,
        Err(reason) => {
            eprintln!("tirith output wrap: status — could not detect shell profile");
            print_profile_reason(&reason);
            return 1;
        }
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
    if let Some(stale) = stale {
        println!(
            "  older copy: {} (not loaded: {shell} does not read that file at startup;",
            stale.display()
        );
        println!(
            "             `tirith output wrap on` moves it to the profile above, `off` removes it)"
        );
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

/// The profile the wrapper is written to, from the shared shell-target
/// resolution (honours ZDOTDIR and XDG_CONFIG_HOME, and the platform's native
/// locations). Bash uses `.bashrc`, or an existing `.bash_profile` when there
/// is no `.bashrc`. It never uses `.profile`: sh and dash login shells read
/// that file too and reject the snippet's hyphenated function name.
fn profile_for(
    shell: &str,
    inputs: &super::shell_target::TargetInputs,
    mut exists: impl FnMut(&std::path::Path) -> bool,
) -> Result<Option<PathBuf>, String> {
    if shell == "bash" {
        let bashrc = inputs.home.join(".bashrc");
        let bash_profile = inputs.home.join(".bash_profile");
        return Ok(Some(if !exists(&bashrc) && exists(&bash_profile) {
            bash_profile
        } else {
            bashrc
        }));
    }
    let profiles = super::shell_target::profiles_for(shell, inputs, |path| Ok(exists(path)))?;
    Ok(profiles.first().map(|profile| profile.path.clone()))
}

/// Where releases before the shared resolution put the wrapper: fixed paths
/// under HOME that ignored ZDOTDIR and XDG_CONFIG_HOME.
fn legacy_profile_for(
    shell: &str,
    home: &std::path::Path,
    mut exists: impl FnMut(&std::path::Path) -> bool,
) -> Option<PathBuf> {
    Some(match shell {
        "zsh" => home.join(".zshrc"),
        "bash" => {
            let bashrc = home.join(".bashrc");
            let bash_profile = home.join(".bash_profile");
            if !exists(&bashrc) && exists(&bash_profile) {
                bash_profile
            } else {
                bashrc
            }
        }
        "fish" => home.join(".config/fish/config.fish"),
        "nushell" => home.join(".config/nushell/config.nu"),
        "powershell" | "pwsh" => home.join(".config/powershell/Microsoft.PowerShell_profile.ps1"),
        _ => return None,
    })
}

/// The profile the wrapper belongs in, and a copy an older release left at a
/// path this shell does not read at startup.
struct ProfileTarget {
    shell: &'static str,
    profile: PathBuf,
    stale: Option<PathBuf>,
}

/// The old fixed path is only stale when it differs from the resolved profile
/// (the one the shell reads); then a block there is never loaded, so it is
/// reported and cleaned up rather than treated as the active wrapper.
fn stale_legacy_copy(
    resolved: &std::path::Path,
    legacy: Option<PathBuf>,
    has_block: impl Fn(&std::path::Path) -> bool,
) -> Option<PathBuf> {
    legacy.filter(|legacy| legacy != resolved && has_block(legacy))
}

/// `Err` carries an optional reason shown under the caller's message.
fn detect_profile() -> Result<ProfileTarget, String> {
    let home = home::home_dir().ok_or_else(String::new)?;
    let shell = crate::cli::init::detect_shell();
    let inputs = super::shell_target::TargetInputs::current(home.clone())?;
    let resolved = profile_for(shell, &inputs, |path| path.exists())?.ok_or_else(String::new)?;
    let legacy = legacy_profile_for(shell, &home, |path| path.exists());
    let has_block = |path: &std::path::Path| {
        fs::read_to_string(path).is_ok_and(|content| content.contains(BEGIN_MARKER))
    };
    let stale = stale_legacy_copy(&resolved, legacy, has_block);
    Ok(ProfileTarget {
        shell,
        profile: resolved,
        stale,
    })
}

fn print_profile_reason(reason: &str) {
    if !reason.is_empty() {
        eprintln!("  {reason}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(
        platform: super::super::shell_target::Platform,
        xdg: Option<&str>,
        zdotdir: Option<&str>,
    ) -> super::super::shell_target::TargetInputs {
        super::super::shell_target::TargetInputs {
            platform,
            home: PathBuf::from("/home/op"),
            xdg_config: xdg.map(PathBuf::from),
            zdotdir: zdotdir.map(PathBuf::from),
            appdata: None,
            documents: None,
        }
    }

    #[test]
    fn profile_follows_zdotdir_and_xdg_config_home() {
        use super::super::shell_target::Platform::Unix;
        let none = |_: &std::path::Path| false;
        let custom = inputs(Unix, Some("/cfg"), Some("/zdot"));
        assert_eq!(
            profile_for("zsh", &custom, none).unwrap(),
            Some(PathBuf::from("/zdot/.zshrc"))
        );
        assert_eq!(
            profile_for("fish", &custom, none).unwrap(),
            Some(PathBuf::from("/cfg/fish/config.fish"))
        );
        assert_eq!(
            profile_for("nushell", &custom, none).unwrap(),
            Some(PathBuf::from("/cfg/nushell/config.nu"))
        );
        assert_eq!(
            profile_for("pwsh", &custom, none).unwrap(),
            Some(PathBuf::from(
                "/cfg/powershell/Microsoft.PowerShell_profile.ps1"
            ))
        );
        let plain = inputs(Unix, None, None);
        assert_eq!(
            profile_for("zsh", &plain, none).unwrap(),
            Some(PathBuf::from("/home/op/.zshrc"))
        );
        assert_eq!(
            profile_for("fish", &plain, none).unwrap(),
            Some(PathBuf::from("/home/op/.config/fish/config.fish"))
        );
        assert_eq!(profile_for("unknown", &plain, none).unwrap(), None);
    }

    #[test]
    fn a_legacy_copy_the_shell_does_not_read_is_stale_not_the_target() {
        let resolved = PathBuf::from("/zdot/.zshrc");
        let legacy = legacy_profile_for("zsh", std::path::Path::new("/home/op"), |_| false);
        assert_eq!(legacy, Some(PathBuf::from("/home/op/.zshrc")));
        let only =
            |with: &'static str| move |path: &std::path::Path| path == std::path::Path::new(with);
        // Left only at the old fixed path that zsh skips while ZDOTDIR is set:
        // it is stale, and the wrapper still goes to the resolved profile.
        assert_eq!(
            stale_legacy_copy(&resolved, legacy.clone(), only("/home/op/.zshrc")),
            Some(PathBuf::from("/home/op/.zshrc"))
        );
        assert_eq!(
            stale_legacy_copy(&resolved, legacy.clone(), |_| true),
            Some(PathBuf::from("/home/op/.zshrc"))
        );
        // Nothing at the old path: nothing stale.
        assert_eq!(
            stale_legacy_copy(&resolved, legacy.clone(), only("/zdot/.zshrc")),
            None
        );
        assert_eq!(stale_legacy_copy(&resolved, legacy, |_| false), None);
        // When the old path is the file the shell reads, it is the profile.
        let home_zshrc = PathBuf::from("/home/op/.zshrc");
        assert_eq!(
            stale_legacy_copy(&home_zshrc, Some(home_zshrc.clone()), |_| true),
            None
        );
    }

    #[test]
    fn bash_profile_is_bashrc_or_an_existing_bash_profile_never_a_posix_sh_file() {
        use super::super::shell_target::Platform::Unix;
        let plain = inputs(Unix, None, None);
        let only = |name: &'static str| move |path: &std::path::Path| path.ends_with(name);
        assert_eq!(
            profile_for("bash", &plain, |_| false).unwrap(),
            Some(PathBuf::from("/home/op/.bashrc"))
        );
        assert_eq!(
            profile_for("bash", &plain, |_| true).unwrap(),
            Some(PathBuf::from("/home/op/.bashrc"))
        );
        assert_eq!(
            profile_for("bash", &plain, only(".bash_profile")).unwrap(),
            Some(PathBuf::from("/home/op/.bash_profile"))
        );
        // `.profile` is also read by sh/dash login shells, which reject the
        // snippet's hyphenated function name, and `.bash_login` was never a
        // target: both fall back to creating `.bashrc`.
        assert_eq!(
            profile_for("bash", &plain, only(".profile")).unwrap(),
            Some(PathBuf::from("/home/op/.bashrc"))
        );
        assert_eq!(
            profile_for("bash", &plain, only(".bash_login")).unwrap(),
            Some(PathBuf::from("/home/op/.bashrc"))
        );
        assert_eq!(
            profile_for("bash", &plain, |path: &std::path::Path| {
                path.ends_with(".bash_profile") || path.ends_with(".profile")
            })
            .unwrap(),
            Some(PathBuf::from("/home/op/.bash_profile"))
        );
    }

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
