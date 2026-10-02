//! Optional, one-command terminal navigation over the existing typed CLI.
//! No shell command parsing, process spawning, configuration writes, or raw mode.

use std::io::{self, BufRead, IsTerminal, Read, Write};

use crate::{AuditAction, Commands, PolicyAction, TrustAction, TrustQueryScope};

const MAX_INPUT_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Page {
    Home,
    Protection,
    Profiles,
    Activity,
    Exceptions,
    Integrations,
    Maintenance,
}

impl Page {
    fn text(self) -> &'static str {
        match self {
            Self::Home => {
                "Tirith menu\n\
                Choose a category, then one inspection or preview.\n\
                Selected commands run once and keep their normal exit status.\n\
                Changes use the explicit direct CLI workflows shown under g.\n\n\
                Policy-aware inspections may read configured remote policy.\n\n\
                1  Protection\n2  Profiles\n3  Activity and recent blocks\n\
                4  Exceptions\n5  Integrations\n6  Maintenance\n"
            }
            Self::Protection => {
                "Protection\n\
                1  Show protection status\n\
                2  Show instructions to verify blocking in this shell\n"
            }
            Self::Profiles => {
                "Profiles\n\
                1  Show local policy diagnostics (offline; excludes overlays)\n\
                2  Resolve runtime policy (may refresh configured remote policy)\n\
                Profile previews may resolve configured remote policy:\n\
                3  Preview Comfortable\n4  Preview Balanced\n5  Preview Strict\n"
            }
            Self::Activity => {
                "Activity and recent blocks\n\
                Recorded checks do not prove execution or attacks prevented.\n\
                1  Show up to 25 recent blocked checks\n\
                2  Show up to 25 recent checks of all outcomes\n\
                3  Explain the last triggered rule\n\
                4  Review bounded tuning suggestions (no policy changes)\n"
            }
            Self::Exceptions => {
                "Exceptions\n\
                1  List current grants and their effective state\n\
                2  List grants including expired entries\n\
                An exception may leave other blockers or broader grants in place.\n"
            }
            Self::Integrations => {
                "Integrations\n\
                1  Show current protection and integration evidence\n\
                2  Preview recommended shell setup with Balanced protection\n\
                3  Show instructions to verify the calling shell\n\
                Setup preview may resolve configured remote policy.\n\
                Configured integrations still require fresh activation evidence.\n"
            }
            Self::Maintenance => {
                "Maintenance\n\
                1  Show installed version and offline provenance\n\
                2  Preview a redacted diagnostic bundle (no file or upload)\n"
            }
        }
    }

    fn guidance(self) -> &'static str {
        match self {
            Self::Home => "Choose a numbered category. Direct commands support scripts and JSON; see tirith --help.\n",
            Self::Protection => "Review status with tirith status; require fresh blocking evidence with tirith status --require-verified-blocking.\n\
                tirith doctor --verify-shell prints the commands to run in the actual shell.\n",
            Self::Profiles => "Compare a profile against your own commands with tirith policy rollout prepare --help.\n\
                Inspect the saved review with tirith policy rollout show OPERATION_ID.\n\
                Activate deliberately with tirith policy rollout activate OPERATION_ID; undo uses tirith policy rollout undo OPERATION_ID.\n",
            Self::Activity => "Filter recorded checks with tirith audit recent --help.\n\
                Explain a finding with tirith explain --help; record an expectation with tirith audit feedback --help.\n\
                Feedback is a review signal and does not grant trust.\n",
            Self::Exceptions => "Inspect a target with tirith trust explain TARGET.\n\
                Review narrow target, rule, expiry, and reason options in tirith trust add --help.\n\
                Revoke a reviewed grant with tirith trust revoke GRANT_ID; inspect the reported remaining permissions.\n",
            Self::Integrations => "Customize shell/profile/agent selection with tirith setup recommended --help.\n\
                Save a review with tirith setup recommended --plan-only.\n\
                Inspect it with tirith policy operation OPERATION_ID; deliberately apply it with tirith policy operation OPERATION_ID --action apply.\n\
                Open a fresh terminal when requested, then verify the actual shell.\n",
            Self::Maintenance => "Review update behavior with tirith update --dry-run (network access); tirith update starts the existing confirmed workflow.\n\
                Save a reviewed support bundle with tirith doctor --bundle. Nothing is uploaded.\n\
                tirith audit rotate saves a retention plan; tirith audit rotate --operation-id OPERATION_ID --apply explicitly applies it.\n\
                Preview shell-hook removal with tirith setup shell --remove --dry-run; tirith setup shell --remove applies removal.\n",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Status,
    VerifyShellInstructions,
    EffectivePolicy { runtime: bool },
    PreviewProfile(&'static str),
    Recent { blocked: bool },
    Why,
    Tune,
    ListGrants { expired: bool },
    PreviewSetup,
    Version,
    PreviewBundle,
}

impl Action {
    fn command(self) -> Commands {
        match self {
            Self::Status => Commands::Status {
                json: false,
                require_verified_blocking: false,
            },
            Self::EffectivePolicy { runtime } => Commands::Policy {
                action: PolicyAction::Effective {
                    runtime,
                    local_only: !runtime,
                    format: None,
                    json: false,
                },
            },
            Self::PreviewProfile(name) => Commands::Policy {
                action: PolicyAction::Profile {
                    name: name.into(),
                    dry_run: true,
                    json: false,
                },
            },
            Self::Recent { blocked } => Commands::Audit {
                action: AuditAction::Recent {
                    limit: 25,
                    since: None,
                    until: None,
                    action: blocked.then(|| "block".into()),
                    rule: None,
                    json: false,
                },
            },
            Self::Why => Commands::Why {
                format: None,
                json: false,
            },
            Self::Tune => Commands::Policy {
                action: PolicyAction::Tune {
                    from_audit: true,
                    format: None,
                    json: false,
                },
            },
            Self::ListGrants { expired } => Commands::Trust {
                action: TrustAction::List {
                    rule: None,
                    format: None,
                    json: false,
                    expired,
                    scope: TrustQueryScope::All,
                },
            },
            Self::PreviewSetup => Commands::Setup {
                tool: "recommended".into(),
                profile: Some("balanced".into()),
                agents: Vec::new(),
                plan_only: false,
                operation_id: None,
                json: false,
                shell: None,
                scope: None,
                with_mcp: false,
                install_zshenv: false,
                dry_run: true,
                remove: false,
                force: false,
                update_configs: false,
            },
            Self::Version => Commands::Version {
                provenance: true,
                format: None,
                json: false,
            },
            Self::VerifyShellInstructions | Self::PreviewBundle => Commands::Doctor {
                format: None,
                json: false,
                verify_shell: self == Self::VerifyShellInstructions,
                reset_bash_safe_mode: false,
                fix: false,
                yes: false,
                simulate_enter: false,
                compat: false,
                bundle: self == Self::PreviewBundle,
                bundle_preview: self == Self::PreviewBundle,
                bundle_operation: Vec::new(),
                bundle_incident: Vec::new(),
                quick: false,
            },
        }
    }
}

fn action(page: Page, choice: &str) -> Option<Action> {
    Some(match (page, choice) {
        (Page::Protection | Page::Integrations, "1") => Action::Status,
        (Page::Protection, "2") | (Page::Integrations, "3") => Action::VerifyShellInstructions,
        (Page::Profiles, "1") => Action::EffectivePolicy { runtime: false },
        (Page::Profiles, "2") => Action::EffectivePolicy { runtime: true },
        (Page::Profiles, "3") => Action::PreviewProfile("comfortable"),
        (Page::Profiles, "4") => Action::PreviewProfile("balanced"),
        (Page::Profiles, "5") => Action::PreviewProfile("strict"),
        (Page::Activity, "1") => Action::Recent { blocked: true },
        (Page::Activity, "2") => Action::Recent { blocked: false },
        (Page::Activity, "3") => Action::Why,
        (Page::Activity, "4") => Action::Tune,
        (Page::Exceptions, "1") => Action::ListGrants { expired: false },
        (Page::Exceptions, "2") => Action::ListGrants { expired: true },
        (Page::Integrations, "2") => Action::PreviewSetup,
        (Page::Maintenance, "1") => Action::Version,
        (Page::Maintenance, "2") => Action::PreviewBundle,
        _ => return None,
    })
}

/// EOF cancels even a partial line. Limit reads before allocating or waiting for
/// the rest of an oversized line; never reinterpret its suffix as another choice.
fn read_choice(input: &mut impl BufRead) -> io::Result<Option<String>> {
    let mut bytes = Vec::with_capacity(MAX_INPUT_BYTES + 1);
    input
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "selection exceeds 64 bytes; menu cancelled",
        ));
    }
    if bytes.last() != Some(&b'\n') {
        return Ok(None);
    }
    let text = std::str::from_utf8(&bytes).unwrap_or("");
    Ok(Some(text.trim_matches([' ', '\t', '\r', '\n']).into()))
}

pub(crate) fn select_command() -> io::Result<Option<Commands>> {
    let input = io::stdin();
    let output = io::stdout();
    select_with(
        &mut input.lock(),
        &mut output.lock(),
        input.is_terminal(),
        output.is_terminal(),
    )
    .map(|selected| selected.map(Action::command))
}

fn select_with(
    input: &mut impl BufRead,
    output: &mut impl Write,
    input_terminal: bool,
    output_terminal: bool,
) -> io::Result<Option<Action>> {
    if !input_terminal || !output_terminal {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "requires terminal input and output; use direct commands such as tirith status --json or tirith audit recent --json",
        ));
    }
    let mut page = Page::Home;
    loop {
        writeln!(output, "\n{}", page.text())?;
        writeln!(output, "g  Workflow guidance   b  Back   q  Quit")?;
        write!(output, "Select: ")?;
        output.flush()?;
        let Some(choice) = read_choice(input)? else {
            writeln!(output, "\nMenu cancelled.")?;
            return Ok(None);
        };
        match choice.as_str() {
            "q" | "Q" => return Ok(None),
            "b" | "B" => page = Page::Home,
            "g" | "G" => writeln!(output, "\n{}", page.guidance())?,
            _ if page == Page::Home => {
                page = match choice.as_str() {
                    "1" => Page::Protection,
                    "2" => Page::Profiles,
                    "3" => Page::Activity,
                    "4" => Page::Exceptions,
                    "5" => Page::Integrations,
                    "6" => Page::Maintenance,
                    _ => {
                        writeln!(output, "Choose a listed number, g, b, or q.")?;
                        continue;
                    }
                };
            }
            _ => match action(page, &choice) {
                Some(selected) => {
                    writeln!(output)?;
                    output.flush()?;
                    return Ok(Some(selected));
                }
                None => writeln!(output, "Choose a listed number, g, b, or q.")?,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn menu_is_explicit_and_has_no_machine_output_mode() {
        // Building the complete clap tree needs the same larger stack as the
        // other CLI registration tests; no user configuration is inspected.
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                use clap::Parser;
                assert!(matches!(
                    crate::Cli::try_parse_from(["tirith", "menu"])
                        .unwrap()
                        .command,
                    Commands::Menu
                ));
                assert!(crate::Cli::try_parse_from(["tirith"]).is_err());
                assert!(crate::Cli::try_parse_from(["tirith", "menu", "--json"]).is_err());
                assert!(matches!(
                    crate::Cli::try_parse_from(["tirith", "status", "--json"])
                        .unwrap()
                        .command,
                    Commands::Status { json: true, .. }
                ));
                let help = crate::Cli::try_parse_from(["tirith", "menu", "--help"])
                    .err()
                    .expect("help should exit before menu selection");
                assert_eq!(help.kind(), clap::error::ErrorKind::DisplayHelp);
                assert!(help.to_string().contains("machine-readable"));
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn noninteractive_refusal_does_not_read_or_print_a_prompt() {
        for (stdin_tty, stdout_tty) in [(false, false), (false, true), (true, false)] {
            let mut input = Cursor::new(b"1\n1\n");
            let mut output = Vec::new();
            let error = select_with(&mut input, &mut output, stdin_tty, stdout_tty).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::NotConnected);
            assert_eq!(input.position(), 0);
            assert!(output.is_empty());
        }
    }

    #[test]
    fn input_limit_stops_before_consuming_or_dispatching_a_suffix() {
        let mut input = Cursor::new(format!("{}\n1\n1\n", "x".repeat(4096)));
        let error = select_with(&mut input, &mut Vec::new(), true, true).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(input.position(), (MAX_INPUT_BYTES + 1) as u64);
        let mut boundary = Cursor::new(format!("{}q\n", " ".repeat(MAX_INPUT_BYTES - 2)));
        assert_eq!(read_choice(&mut boundary).unwrap().as_deref(), Some("q"));
    }

    #[test]
    fn eof_quit_back_and_guidance_never_select_an_action() {
        for bytes in ["", "1", "1\n", "q\n", "1\nq\n", "2\ng\nb\nq\n"] {
            assert_eq!(
                select_with(&mut Cursor::new(bytes), &mut Vec::new(), true, true).unwrap(),
                None
            );
        }
    }

    #[test]
    fn unlisted_commands_and_terminal_controls_are_not_echoed_or_dispatched() {
        let mut output = Vec::new();
        assert_eq!(
            select_with(
                &mut Cursor::new(b"2\n\napply\n!sh\n\x1b[2J\n\xff\nq\n"),
                &mut output,
                true,
                true
            )
            .unwrap(),
            None
        );
        assert!(!output.contains(&0x1b));
        let display = String::from_utf8(output).unwrap();
        assert!(!display.contains("!sh"));
        assert!(!display.contains("Select: apply"));
    }

    #[test]
    fn navigation_selects_only_one_command_and_leaves_following_input_unread() {
        let mut input = Cursor::new(b"3\n1\nq\n");
        let selected = select_with(&mut input, &mut Vec::new(), true, true).unwrap();
        assert_eq!(selected, Some(Action::Recent { blocked: true }));
        assert_eq!(input.position(), 4);
        assert!(matches!(
            selected.unwrap().command(),
            Commands::Audit { action: AuditAction::Recent { limit: 25, action: Some(filter), since: None, until: None, rule: None, json: false } }
                if filter == "block"
        ));
    }

    #[test]
    fn every_selectable_command_is_an_inspection_or_preview() {
        let pages = [
            Page::Home,
            Page::Protection,
            Page::Profiles,
            Page::Activity,
            Page::Exceptions,
            Page::Integrations,
            Page::Maintenance,
        ];
        let mut count = 0;
        for page in pages {
            for number in 0..=9 {
                let Some(selected) = action(page, &number.to_string()) else {
                    continue;
                };
                count += 1;
                match selected.command() {
                    Commands::Status {
                        require_verified_blocking: false,
                        json: false,
                    }
                    | Commands::Why {
                        format: None,
                        json: false,
                    }
                    | Commands::Version {
                        provenance: true,
                        format: None,
                        json: false,
                    } => {}
                    Commands::Policy {
                        action:
                            PolicyAction::Effective {
                                runtime,
                                local_only,
                                format: None,
                                json: false,
                            },
                    } => assert_ne!(runtime, local_only),
                    Commands::Policy {
                        action:
                            PolicyAction::Profile {
                                name,
                                dry_run: true,
                                json: false,
                            },
                    } => assert!(["comfortable", "balanced", "strict"].contains(&name.as_str())),
                    Commands::Policy {
                        action:
                            PolicyAction::Tune {
                                from_audit: true,
                                format: None,
                                json: false,
                            },
                    } => {}
                    Commands::Audit {
                        action:
                            AuditAction::Recent {
                                limit: 25,
                                since: None,
                                until: None,
                                rule: None,
                                json: false,
                                action,
                            },
                    } => assert!(action.is_none() || action.as_deref() == Some("block")),
                    Commands::Trust {
                        action:
                            TrustAction::List {
                                rule: None,
                                format: None,
                                json: false,
                                scope: TrustQueryScope::All,
                                ..
                            },
                    } => {}
                    Commands::Setup {
                        tool,
                        profile,
                        agents,
                        dry_run: true,
                        plan_only: false,
                        operation_id: None,
                        json: false,
                        shell: None,
                        scope: None,
                        with_mcp: false,
                        install_zshenv: false,
                        remove: false,
                        force: false,
                        update_configs: false,
                    } => {
                        assert_eq!(tool, "recommended");
                        assert_eq!(profile.as_deref(), Some("balanced"));
                        assert!(agents.is_empty());
                    }
                    Commands::Doctor {
                        verify_shell,
                        bundle,
                        bundle_preview,
                        format: None,
                        json: false,
                        fix: false,
                        yes: false,
                        reset_bash_safe_mode: false,
                        simulate_enter: false,
                        compat: false,
                        quick: false,
                        bundle_operation,
                        bundle_incident,
                    } => {
                        assert!(verify_shell ^ (bundle && bundle_preview));
                        assert!(bundle_operation.is_empty() && bundle_incident.is_empty());
                    }
                    _ => panic!(
                        "menu selected a command outside its read-only contract: {selected:?}"
                    ),
                }
            }
        }
        assert_eq!(count, 18);
    }
}
