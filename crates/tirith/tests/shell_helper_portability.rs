//! Helper discovery must work on non-FHS hosts without allowing later PATH or
//! command-cache changes to redirect a hook's capture/receipt operations.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "pty_support/mod.rs"]
mod pty_support;

fn shells() -> Vec<(&'static str, PathBuf)> {
    let mut shells = vec![(
        "bash",
        pty_support::modern_bash().unwrap_or_else(|| PathBuf::from("/bin/bash")),
    )];
    if let Some(shell) = pty_support::zsh_bin() {
        shells.push(("zsh", shell));
    }
    if let Some(shell) = pty_support::fish_bin() {
        shells.push(("fish", shell));
    }
    shells
}

fn quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

fn run(shell: &Path, family: &str, root: &Path, interactive: bool, script: &str) -> Output {
    let mut command = Command::new(shell);
    match family {
        "bash" => command.args(["--noprofile", "--norc"]),
        "zsh" => command.arg("-f"),
        "fish" => command.arg("--no-config"),
        _ => unreachable!(),
    };
    if interactive {
        command.arg("-i");
    }
    let output = command
        .args(["-c", script])
        .env_clear()
        .env("HOME", root)
        .env("XDG_STATE_HOME", root.join("state"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("TERM", "xterm")
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{family}: script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn executable(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    for directory in ["good bin", "fixed", "shadow", "relative"] {
        fs::create_dir(root.path().join(directory)).unwrap();
    }
    for directory in ["good bin", "fixed"] {
        executable(
            &root.path().join(directory).join("tool"),
            "printf 'PINNED_OK\\n'",
        );
    }
    for directory in ["shadow", "relative"] {
        executable(
            &root.path().join(directory).join("tool"),
            "printf 'SHADOWED\\n'",
        );
    }
    executable(&root.path().join("good bin/tirith"), "exit 1");
    root
}

#[test]
fn explicit_native_source_argument_bypasses_launchers_without_changing_path() {
    for (family, shell) in shells() {
        let root = fixture();
        let native = root.path().join("native's binary");
        executable(&native, "printf 'NATIVE_EXECUTED\\n'");
        let bin = quote(&root.path().join("good bin"));
        let hook = quote(&pty_support::embedded_hook(&format!(
            "{family}-hook.{family}"
        )));
        let native = quote(&native);
        let script = if family == "fish" {
            format!(
                r#"set -gx PATH {bin}; set argv caller arguments
source {hook} --tirith-executable {native}
test "$argv[1]" = caller; and test "$argv[2]" = arguments; or exit 1
test "$PATH" = {bin}; or exit 2
command "$_TIRITH_BIN"
"#
            )
        } else {
            format!(
                r#"PATH={bin}; set -- caller arguments
source {hook} --tirith-executable {native}
[[ "$1" == caller && "$2" == arguments ]] || exit 1
[[ "$PATH" == {bin} ]] || exit 2
command "$_TIRITH_BIN"
"#
            )
        };
        let output = run(&shell, family, root.path(), false, &script);
        assert_eq!(output.stdout, b"NATIVE_EXECUTED\n", "{family}");
    }
}

#[test]
fn source_loader_resolves_itself_independently_of_caller_and_cdpath() {
    let mut candidates = shells();
    if !candidates
        .iter()
        .any(|(_, path)| path == Path::new("/bin/bash"))
    {
        candidates.push(("bash", PathBuf::from("/bin/bash")));
    }
    for (family, shell) in candidates {
        if family == "fish" {
            continue;
        }
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("hook's directory");
        fs::create_dir_all(directory.join("lib")).unwrap();
        let loader = directory.join("tirith.sh");
        fs::copy(pty_support::embedded_hook("../tirith.sh"), &loader).unwrap();
        fs::write(
            directory.join(format!("lib/{family}-hook.{family}")),
            "builtin printf 'LOADED_FROM_SOURCE\\n'\n",
        )
        .unwrap();
        for source in [&loader, &PathBuf::from("hook's directory/tirith.sh")] {
            let script = format!(
                "PATH=/missing; CDPATH=/does/not/exist; {}; source {}",
                if family == "zsh" {
                    "unsetopt functionargzero"
                } else {
                    ":"
                },
                quote(source)
            );
            let output = run(&shell, family, root.path(), false, &script);
            assert_eq!(output.stdout, b"LOADED_FROM_SOURCE\n", "{family}");
            assert!(output.stderr.is_empty(), "{family}: {output:?}");
        }
    }
}

#[test]
fn bash_prompt_fast_path_preserves_typed_sentinels_and_history_drift() {
    for shell in [
        PathBuf::from("/bin/bash"),
        pty_support::modern_bash().unwrap_or_else(|| PathBuf::from("/bin/bash")),
    ] {
        let root = fixture();
        let history_log = root.path().join("history.log");
        let check_log = root.path().join("check.log");
        executable(
            &root.path().join("good bin/tirith"),
            &format!("printf '%s\\n' \"$*\" >> {}", quote(&check_log)),
        );
        let script = format!(
            r#"PATH={bin}:/usr/bin:/bin
source {hook}
_TIRITH_PREEXEC_PROMPT_GUARDS=1
_TIRITH_RECEIPT_PROTOCOL=0
_tirith_read_history_entry() {{ printf 'read\n' >> {history_log}; printf '%s\n' "$_TEST_HISTORY"; }}
_tirith_preexec_prompt_guards_attached() {{ return 0; }}
_tirith_preexec_block_current_line() {{ printf 'DRIFT_BLOCKED\n'; return 1; }}
for phase in startup prompt off; do
    _TIRITH_PREEXEC_PHASE="$phase"
    _tirith_preexec 1 1 'automatic_prompt_work'
    _tirith_preexec 1 1 '_tirith_preexec_prompt_begin'
done
[[ ! -e {history_log} ]] || exit 11
_TIRITH_PREEXEC_PHASE=user
_TIRITH_PREEXEC_ACTIVE_DECISION=''
_TEST_HISTORY='1|_tirith_preexec_prompt_begin'
_tirith_preexec 2 1 '_tirith_preexec_prompt_begin'
[[ "$_TIRITH_PREEXEC_PHASE" == user ]] || exit 12
_TIRITH_PREEXEC_PHASE=user
_TIRITH_PREEXEC_ENFORCE=1
_TIRITH_PREEXEC_ACTIVE_DECISION=''
_TEST_HISTORY='2|echo prior_command'
_tirith_preexec 3 1 'echo changed_command'
[[ $? == 1 ]] || exit 13
"#,
            bin = quote(&root.path().join("good bin")),
            hook = quote(&pty_support::embedded_hook("bash-hook.bash")),
            history_log = quote(&history_log),
        );
        let output = run(&shell, "bash", root.path(), false, &script);
        assert_eq!(fs::read_to_string(history_log).unwrap(), "read\nread\n");
        assert_eq!(
            fs::read_to_string(check_log).unwrap(),
            "check --shell posix --warn-only -- _tirith_preexec_prompt_begin\n"
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("DRIFT_BLOCKED"));
    }
}

#[test]
fn helper_resolution_ignores_hashes_functions_and_relative_path_entries() {
    for (family, shell) in shells() {
        let root = fixture();
        let hook = pty_support::embedded_hook(&format!("{family}-hook.{family}"));
        let good = quote(&root.path().join("good bin"));
        let fixed = quote(&root.path().join("fixed/tool"));
        let shadow = quote(&root.path().join("shadow"));
        let script = if family == "fish" {
            format!(
                r#"set -gx PATH {good}; source {hook};
function tool; builtin printf 'FUNCTION_BAD\n'; end
builtin printf 'FIXED=%s\n' (_tirith_resolve_helper tool /missing/helper {fixed})
set -gx PATH relative '' {good}
set -l pinned (_tirith_resolve_helper tool /missing/helper)
builtin printf 'FALLBACK=%s\n' "$pinned"
_tirith_resolve_helper printf /missing/helper; builtin printf 'BUILTIN_RC=%s\n' $status
set -gx PATH relative ''
_tirith_resolve_helper tool /missing/helper; builtin printf 'RELATIVE_RC=%s\n' $status
set -gx PATH {shadow}
command "$pinned"
"#,
                hook = quote(&hook),
            )
        } else {
            // Both shells can retain a stale hash even while the named file
            // exists on PATH; this was missed by the original PR #241 probe.
            let stale_hash = if family == "zsh" {
                "hash tool=/missing/cached/tool"
            } else {
                "hash -p /missing/cached/tool tool"
            };
            format!(
                r#"PATH={good}; source {hook};
tool() {{ builtin printf 'FUNCTION_BAD\n'; }}
{stale_hash}
builtin printf 'FIXED=%s\n' "$(_tirith_resolve_helper tool /missing/helper {fixed})"
PATH=relative::{good}
pinned="$(_tirith_resolve_helper tool /missing/helper)"
builtin printf 'FALLBACK=%s\n' "$pinned"
_tirith_resolve_helper printf /missing/helper; builtin printf 'BUILTIN_RC=%s\n' "$?"
PATH=relative:
_tirith_resolve_helper tool /missing/helper; builtin printf 'RELATIVE_RC=%s\n' "$?"
PATH={shadow}
command "$pinned"
"#,
                hook = quote(&hook),
            )
        };
        let output = run(&shell, family, root.path(), false, &script);
        let stdout = String::from_utf8_lossy(&output.stdout);
        for expected in [
            format!("FIXED={}/fixed/tool", root.path().display()),
            format!("FALLBACK={}/good bin/tool", root.path().display()),
            "BUILTIN_RC=1".into(),
            "RELATIVE_RC=1".into(),
            "PINNED_OK".into(),
        ] {
            assert!(stdout.contains(&expected), "{family}: {stdout}");
        }
        assert!(!stdout.contains("SHADOWED"), "{family}: {stdout}");
        assert!(!stdout.contains("FUNCTION_BAD"), "{family}: {stdout}");
    }
}

// Remove only the fixed helper candidates in a private hook copy to reproduce
// NixOS on an FHS test host. The fallback and all capture logic remain intact.
fn non_fhs_hook(family: &str, root: &Path) -> PathBuf {
    let name = format!("{family}-hook.{family}");
    let mut hook = fs::read_to_string(pty_support::embedded_hook(&name)).unwrap();
    for helper in ["mktemp", "rm", "wc", "mkdir", "stty", "env", "sh", "bash"] {
        for prefix in ["/usr/bin/", "/bin/"] {
            hook = hook.replace(
                &format!("{prefix}{helper}"),
                &format!("/missing-tirith-test-helper/{helper}"),
            );
        }
    }
    let destination = root.join(name);
    fs::write(&destination, hook).unwrap();
    destination
}

#[test]
fn non_fhs_hooks_pin_all_helpers_and_create_private_captures() {
    for (family, shell) in shells() {
        let root = fixture();
        let bin = root.path().join("good bin");
        for helper in ["mktemp", "rm", "wc", "mkdir", "stty", "env", "sh", "bash"] {
            let output = Command::new("sh")
                .args(["-c", &format!("command -v {helper}")])
                .output()
                .unwrap();
            assert!(output.status.success(), "test needs {helper}");
            let target = String::from_utf8(output.stdout).unwrap();
            symlink(target.trim(), bin.join(helper)).unwrap();
        }
        let hook = non_fhs_hook(family, root.path());
        let expected = ["MKTEMP", "RM", "WC"];
        let script = if family == "fish" {
            format!(
                r#"set -gx PATH {bin}; source {hook}
builtin printf 'PINS=%s|%s|%s\n' "$_TIRITH_MKTEMP_BIN" "$_TIRITH_RM_BIN" "$_TIRITH_WC_BIN"
builtin printf 'READY=%s\n' "$_TIRITH_V3_HELPERS_READY"
set -gx PATH /missing-after-source
set -l capture (_tirith_v3_new_capture_file)
test -f "$capture"; and test -O "$capture"; and not test -L "$capture"; or exit 1
_tirith_v3_remove_capture_files "$capture"; or exit 1
test ! -e "$capture"; or exit 1
builtin printf 'CAPTURE_OK\n'
"#,
                bin = quote(&bin),
                hook = quote(&hook),
            )
        } else {
            let capture_function = if family == "bash" {
                "_tirith_new_capture_file"
            } else {
                "_tirith_v3_new_capture_file"
            };
            let remove_function = if family == "bash" {
                "_tirith_remove_capture_file"
            } else {
                "_tirith_v3_remove_capture_files"
            };
            format!(
                r#"PATH={bin}; source {hook}
builtin printf 'PINS=%s|%s|%s\n' "$_TIRITH_MKTEMP_BIN" "$_TIRITH_RM_BIN" "$_TIRITH_WC_BIN"
PATH=/missing-after-source
capture="$({capture_function})" || exit 1
[[ -f "$capture" && -O "$capture" && ! -L "$capture" ]] || exit 1
{remove_function} "$capture" || exit 1
[[ ! -e "$capture" ]] || exit 1
builtin printf 'CAPTURE_OK\n'
"#,
                bin = quote(&bin),
                hook = quote(&hook),
            )
        };
        let output = run(&shell, family, root.path(), false, &script);
        let stdout = String::from_utf8_lossy(&output.stdout);
        for helper in expected {
            assert!(
                stdout.contains(&format!("{}/{}", bin.display(), helper.to_lowercase())),
                "{family}: {stdout}"
            );
        }
        assert!(stdout.contains("CAPTURE_OK"), "{family}: {stdout}");
        if family == "fish" {
            assert!(stdout.contains("READY=1"), "{family}: {stdout}");
        }
    }
}

#[test]
fn missing_startup_capture_helpers_preserve_interactive_enter_bindings() {
    for (family, shell) in shells().into_iter().filter(|(name, _)| *name != "bash") {
        let root = fixture();
        let bin = root.path().join("good bin");
        let hook = non_fhs_hook(family, root.path());
        let script = if family == "fish" {
            format!(
                r#"set -gx PATH {bin}
bind \r 'commandline -f execute'
set -l before (bind \r | string collect)
source {hook}
set -l after (bind \r | string collect)
test "$before" = "$after"; or exit 1
functions -q _tirith_check_command; and exit 1
set -q _TIRITH_FISH_LOADED; and exit 1
builtin printf 'STATUS=%s\nENTER_UNCHANGED\n' "$TIRITH_STATUS"
"#,
                bin = quote(&bin),
                hook = quote(&hook),
            )
        } else {
            format!(
                r#"PATH={bin}
before="$widgets[accept-line]"
source {hook}
[[ "$before" == "$widgets[accept-line]" ]] || exit 1
(( $+functions[_tirith_accept_line] )) && exit 1
[[ -z "${{_TIRITH_ZSH_LOADED:-}}" ]] || exit 1
builtin printf 'STATUS=%s\nENTER_UNCHANGED\n' "$TIRITH_STATUS"
"#,
                bin = quote(&bin),
                hook = quote(&hook),
            )
        };
        let output = run(&shell, family, root.path(), true, &script);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("STATUS=off"), "{family}: {stdout}");
        assert!(stdout.contains("ENTER_UNCHANGED"), "{family}: {stdout}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("hooks disabled"),
            "{family}: expected an explicit startup warning"
        );
    }
}
