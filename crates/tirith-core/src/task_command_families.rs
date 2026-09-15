//! Bounded effect hints for Python packaging and Cargo workflows.
//!
//! Grammar and qualification contract: docs/next-cycle/task-command-families.md.
//! Nothing here can produce a complete analysis. Interpreter startup, build
//! backends, build.rs/proc macros, package entrypoints and configuration remain
//! unanalyzed, including when flags claim offline or dry-run behavior.

use std::collections::BTreeSet;

use crate::effects::CommandEffectKind;
use crate::tokenize::{Segment, ShellType};

const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_SEGMENTS: usize = 256;
const MAX_WORDS: usize = 512;
const MAX_WORD_BYTES: usize = 16 * 1024;

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct FamilyAnalysis {
    pub effects: BTreeSet<CommandEffectKind>,
    pub unknown_runtime: bool,
    pub limits_reached: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Pip,
    Cargo,
}

/// Use only the selected dialect. The caller owns authority and whole-command
/// occurrence accounting; this result may only add effects or incompleteness.
pub(crate) fn analyze_input(input: &str, shell: ShellType) -> FamilyAnalysis {
    if input.len() > MAX_INPUT_BYTES {
        return FamilyAnalysis {
            limits_reached: true,
            ..FamilyAnalysis::default()
        };
    }
    let execution = crate::extract::shell_execution_view(input, shell);
    if execution.len() > MAX_INPUT_BYTES {
        return FamilyAnalysis {
            limits_reached: true,
            ..FamilyAnalysis::default()
        };
    }
    let (segments, budget) = crate::tokenize::tokenize_bounded(
        &execution,
        shell,
        MAX_SEGMENTS,
        MAX_WORDS,
        MAX_WORD_BYTES,
    );
    let mut analysis = FamilyAnalysis {
        limits_reached: budget.segments_truncated
            || budget.words_truncated
            || budget.word_bytes_truncated,
        ..FamilyAnalysis::default()
    };
    for segment in segments {
        if let Some(effects) = parse_segment(&segment, shell) {
            analysis.effects.extend(effects);
            analysis.unknown_runtime = true;
        }
    }
    analysis
}

fn numbered_name(name: &str, prefix: &str) -> bool {
    name == prefix
        || name.strip_prefix(prefix).is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .split('.')
                    .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        })
}

fn parse_segment(segment: &Segment, shell: ShellType) -> Option<BTreeSet<CommandEffectKind>> {
    let (command, raw_args) = crate::extract::resolve_wrapped_command_for_shell(segment, shell)?;
    let command = crate::npm_command::launcher_basename(&command, shell);
    let args: Vec<_> = raw_args
        .iter()
        .map(|argument| crate::rules::command::normalize_shell_token(argument, shell))
        .collect();
    let (family, start) = if numbered_name(&command, "pip") {
        (Family::Pip, 0)
    } else if numbered_name(&command, "python") || command == "py" {
        (Family::Pip, python_pip_start(&args, command == "py")?)
    } else if command == "cargo" {
        let start = usize::from(args.first().is_some_and(|arg| arg.starts_with('+')));
        (Family::Cargo, start)
    } else {
        return None;
    };
    let mut effects = BTreeSet::new();
    let operation = operation_word(family, &args, start, &mut effects);
    use CommandEffectKind::*;
    let inferred: &[CommandEffectKind] = match (family, operation) {
        (Family::Pip | Family::Cargo, Some("install")) => &[
            PackageInstall,
            NetworkEgress,
            FilesystemWrite,
            PersistenceChange,
        ],
        (Family::Pip, Some("download" | "wheel"))
        | (
            Family::Cargo,
            Some(
                "build" | "b" | "check" | "c" | "test" | "t" | "run" | "r" | "bench" | "rustc"
                | "rustdoc" | "doc" | "fetch",
            ),
        ) => &[NetworkEgress, FilesystemWrite],
        (Family::Pip, Some("uninstall")) => &[FilesystemWrite, PersistenceChange],
        _ => &[],
    };
    effects.extend(inferred.iter().copied());
    Some(effects)
}

/// A Python script or -c payload never becomes a pip invocation merely by
/// containing the words `-m pip install`. Only the interpreter's prefix grammar
/// can select module execution.
fn python_pip_start(args: &[String], launcher: bool) -> Option<usize> {
    let mut index = 0;
    while let Some(argument) = args.get(index) {
        match argument.as_str() {
            "-m" => return (args.get(index + 1)?.as_str() == "pip").then_some(index + 2),
            "-mpip" => return Some(index + 1),
            "-W" | "-X" => {
                args.get(index + 1)?;
                index += 2;
            }
            value if value.starts_with("-W") || value.starts_with("-X") => index += 1,
            value
                if value.starts_with('-')
                    && value.len() > 1
                    && value[1..]
                        .bytes()
                        .all(|byte| b"bBdEiIOPqRsSuvx".contains(&byte)) =>
            {
                index += 1;
            }
            value
                if launcher
                    && value.strip_prefix('-').is_some_and(|version| {
                        !version.is_empty()
                            && version.split('.').all(|part| {
                                !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
                            })
                    }) =>
            {
                index += 1;
            }
            _ => return None,
        }
    }
    None
}

fn operation_word<'a>(
    family: Family,
    args: &'a [String],
    mut index: usize,
    effects: &mut BTreeSet<CommandEffectKind>,
) -> Option<&'a str> {
    while let Some(argument) = args.get(index) {
        if !argument.starts_with('-') {
            return Some(argument);
        }
        let (flag, inline) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(name, value)| {
                (name, Some(value))
            });
        let value_flag = match family {
            Family::Pip => matches!(
                flag,
                "--python"
                    | "--log"
                    | "--proxy"
                    | "--retries"
                    | "--resume-retries"
                    | "--timeout"
                    | "--exists-action"
                    | "--trusted-host"
                    | "--cert"
                    | "--client-cert"
                    | "--cache-dir"
                    | "--keyring-provider"
                    | "--use-feature"
                    | "--use-deprecated"
            ),
            Family::Cargo => matches!(flag, "--color" | "--config" | "-Z" | "-C"),
        };
        if value_flag {
            if inline.is_some_and(str::is_empty) {
                return None;
            }
            if inline.is_none() {
                args.get(index + 1)?;
                index += 1;
            }
            if family == Family::Pip && flag == "--log" {
                effects.insert(CommandEffectKind::FilesystemWrite);
            }
        } else {
            let boolean_flag = match family {
                Family::Pip => matches!(
                    flag,
                    "--isolated"
                        | "--require-virtualenv"
                        | "--no-input"
                        | "--no-color"
                        | "--no-cache-dir"
                        | "--disable-pip-version-check"
                        | "--debug"
                        | "--no-proxy-env"
                        | "--verbose"
                        | "--quiet"
                ),
                Family::Cargo => matches!(
                    flag,
                    "--frozen" | "--locked" | "--offline" | "--verbose" | "--quiet"
                ),
            };
            let short_verbosity = argument.starts_with('-')
                && argument.len() > 1
                && argument[1..].bytes().all(|byte| b"vq".contains(&byte));
            if inline.is_some() || (!boolean_flag && !short_verbosity) {
                return None;
            }
        }
        index += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use CommandEffectKind::*;

    #[test]
    fn package_install_effects_cover_literal_launchers_and_known_prefix_values() {
        for command in [
            "pip install requests",
            "pip3.12 --isolated --proxy https://proxy.invalid install -r requirements.txt",
            "python3.12 -I -W ignore -m pip --log install install -e .",
            "python -mpip install wheel.whl --no-index --dry-run",
            "sudo -u builder env PIP_NO_INDEX=1 pip install local.whl",
            "cargo +stable --config net.offline=true install --path .",
            "cargo --locked install ripgrep",
        ] {
            let analysis = analyze_input(command, ShellType::Posix);
            for effect in [
                PackageInstall,
                NetworkEgress,
                FilesystemWrite,
                PersistenceChange,
            ] {
                assert!(
                    analysis.effects.contains(&effect),
                    "{command}: {analysis:?}"
                );
            }
            assert!(analysis.unknown_runtime);
            assert!(!analysis.limits_reached);
        }
    }

    #[test]
    fn operation_names_inside_values_scripts_or_unknown_options_are_not_commands() {
        for command in [
            "python -c 'print(1)' -m pip install requests",
            "python script.py -m pip install requests",
            "python -m other pip install requests",
            "pip --proxy install list",
            "pip --unknown install requests",
            "cargo --unknown install ripgrep",
            "cargo custom install ripgrep",
            "echo pip install requests",
        ] {
            let analysis = analyze_input(command, ShellType::Posix);
            assert!(
                !analysis.effects.contains(&PackageInstall),
                "{command}: {analysis:?}"
            );
        }
        let log = analyze_input("pip --log install list", ShellType::Posix);
        assert!(log.effects.contains(&FilesystemWrite));
        assert!(!log.effects.contains(&PackageInstall));
        assert!(log.unknown_runtime);
    }

    #[test]
    fn build_artifact_and_removal_shapes_keep_runtime_unknown() {
        for command in [
            "cargo check",
            "cargo test --offline",
            "cargo run -- --help",
            "cargo fetch",
            "pip download package",
            "pip wheel .",
        ] {
            let analysis = analyze_input(command, ShellType::Posix);
            assert_eq!(
                analysis.effects,
                [FilesystemWrite, NetworkEgress].into_iter().collect(),
                "{command}"
            );
            assert!(analysis.unknown_runtime);
        }
        let removal = analyze_input("pip uninstall -y requests", ShellType::Posix);
        assert_eq!(
            removal.effects,
            [FilesystemWrite, PersistenceChange].into_iter().collect()
        );
        assert!(removal.unknown_runtime);
    }

    #[test]
    fn bounded_parser_reports_limits_and_preserves_retained_effects() {
        let input = format!(
            "pip install package;{}",
            "echo padding;".repeat(MAX_SEGMENTS + 1)
        );
        let analysis = analyze_input(&input, ShellType::Posix);
        assert!(analysis.limits_reached);
        assert!(analysis.effects.contains(&PackageInstall));
        for input in [
            format!("pip install {}", "x ".repeat(MAX_WORDS + 1)),
            format!("pip install {}", "x".repeat(MAX_WORD_BYTES + 1)),
            "x".repeat(MAX_INPUT_BYTES + 1),
        ] {
            assert!(analyze_input(&input, ShellType::Posix).limits_reached);
        }
    }

    #[test]
    fn shell_specific_literal_shapes_are_lexical_fixtures_not_native_certification() {
        for (shell, command) in [
            (ShellType::Fish, "command pip3 install package"),
            (
                ShellType::PowerShell,
                r#"& 'C:\Python\python.exe' -I -m pip install package"#,
            ),
            (
                ShellType::Cmd,
                r#"C:\Python\py.exe -3.12 -m pip install package"#,
            ),
            (
                ShellType::PowerShell,
                r#"& 'C:\Rust\cargo.exe' +stable install package"#,
            ),
        ] {
            let analysis = analyze_input(command, shell);
            assert!(
                analysis.effects.contains(&PackageInstall),
                "{shell:?}: {command}: {analysis:?}"
            );
            assert!(analysis.unknown_runtime);
        }
    }
}
