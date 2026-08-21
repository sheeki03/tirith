//! SSH operational-context rules (M8 ch2).
//!
//! Fire when the parsed command leader is `ssh` and either:
//!
//! 1. `SshRemoteDestructiveOnLabeledHost` (High) — a destructive inner command
//!    on a remote host labeled critical/production. The inner command runs
//!    through the same verb classifier as `rules::context`.
//! 2. `SshRemoteShellOnLabeledHost` (Info) — a bare interactive shell on a
//!    labeled host; a reminder that tirith's interception is local to the SSH
//!    client (remote commands aren't protected without `ssh bootstrap`).
//!
//! Detection short-circuits when `policy.ssh_host_labels` is empty (opt-in).
//! Tier-1 gate: PATTERN_TABLE entry `ssh_cmd`.
//!
//! Inner-command parsing: pop the host (skipping `-t`, `-i path`, `-o KEY=VAL`,
//! …) then classify the remaining string. PowerShell is handled identically —
//! `ssh` on Windows takes the same POSIX-shaped inner string.

use crate::policy::Policy;
use crate::rules::context::classify_inner_command_for_ssh;
use crate::rules::shared::{canonicalize_ssh_label_key, is_critical_label};
use crate::tokenize::{self, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// SSH flags that consume the next arg (per `ssh(1)`), so the host detector
/// doesn't mistake a flag value for the hostname.
const SSH_FLAGS_WITH_ARG: &[&str] = &[
    "-i", "-p", "-l", "-L", "-R", "-D", "-F", "-S", "-c", "-e", "-o", "-J", "-Q", "-b", "-B", "-E",
    "-I", "-O", "-w", "-m",
];

/// Run SSH-context rules across every executable shell segment.
pub fn check(input: &str, shell: ShellType, policy: &Policy) -> Vec<Finding> {
    // Empty labels file → no enforcement (opt-in).
    if !policy.context_guard_enabled || policy.ssh_host_labels.is_empty() {
        return Vec::new();
    }

    tokenize::tokenize(input, shell)
        .iter()
        .flat_map(|seg| check_segment(input, shell, policy, seg))
        .collect()
}

fn check_segment(
    input: &str,
    shell: ShellType,
    policy: &Policy,
    seg: &tokenize::Segment,
) -> Vec<Finding> {
    let effective = match crate::rules::command::resolve_effective_segment(seg, shell) {
        Ok(effective) => effective,
        Err(crate::rules::command::EffectiveCommandError::WorkBudgetExceeded) => {
            return vec![Finding {
                rule_id: RuleId::AnalysisIncomplete,
                severity: Severity::High,
                title: "SSH command analysis exceeded its work budget".to_string(),
                description: "The SSH command exceeded Tirith's bounded token-normalization budget while SSH host labels are active. The omitted token suffix is blocked instead of being treated as a non-SSH command."
                    .to_string(),
                evidence: vec![Evidence::CommandPattern {
                    pattern: "ssh command work budget exhausted".to_string(),
                    matched: "input or token suffix omitted before command normalization"
                        .to_string(),
                }],
                human_view: Some(
                    "SSH context guard stopped at its command-analysis budget.".to_string(),
                ),
                agent_view: Some(
                    "tirith refused: SSH command analysis incomplete.".to_string(),
                ),
                mitre_id: None,
                custom_rule_id: None,
            }];
        }
        Err(_) => {
            if seg
                .raw
                .split_whitespace()
                .any(|word| command_basename(word, shell) == "ssh")
            {
                return vec![Finding {
                    rule_id: RuleId::AnalysisIncomplete,
                    severity: Severity::High,
                    title: "SSH wrapper chain could not be classified safely".to_string(),
                    description: "SSH appears behind ambiguous or over-deep execution-wrapper options while SSH host labels are active. Tirith blocks it instead of assuming the unresolved remote target is safe.".to_string(),
                    evidence: vec![Evidence::CommandPattern {
                        pattern: "ssh <analysis-incomplete>".to_string(),
                        matched: seg.raw.chars().take(200).collect(),
                    }],
                    human_view: Some("SSH context guard could not prove this command safe.".to_string()),
                    agent_view: Some("tirith refused: SSH wrapper analysis incomplete.".to_string()),
                    mitre_id: None,
                    custom_rule_id: None,
                }];
            }
            return Vec::new();
        }
    };
    let Some(cmd) = effective.command.as_deref() else {
        return Vec::new();
    };
    let base = command_basename(cmd, shell);
    if base != "ssh" {
        return Vec::new();
    }

    let parsed = match parse_ssh_invocation(effective.args.as_slice()) {
        Some(p) => p,
        None => return Vec::new(),
    };

    // Consider both identities and retain the more restrictive semantic
    // result. Exact `user@host` inventory remains useful, but a noncritical
    // exact label must never shadow a critical bare-host label.
    let exact_key = canonicalize_ssh_label_key(&parsed.user_at_host)
        .unwrap_or_else(|| parsed.user_at_host.clone());
    let bare_key = canonicalize_ssh_label_key(&parsed.host).unwrap_or_else(|| parsed.host.clone());
    let exact_label = policy.ssh_host_labels.get(&exact_key);
    let bare_label = policy.ssh_host_labels.get(&bare_key);
    let label = match exact_label
        .filter(|label| is_critical_label(label))
        .or_else(|| bare_label.filter(|label| is_critical_label(label)))
        .or(exact_label)
        .or(bare_label)
    {
        Some(l) => l,
        None => return Vec::new(),
    };
    if !is_critical_label(label) {
        // A non-critical label (staging/dev/test) is inventory-only; don't fire.
        return Vec::new();
    }

    if let Some(inner) = parsed.inner_command {
        // Classify the inner command with the same verb classifier as
        // `rules::context`, using POSIX even from a PowerShell launcher.
        let category = classify_inner_command_for_ssh(&inner, ShellType::Posix);
        // The conservative treatment is scoped to the `-o RemoteCommand=`
        // channel on purpose. That channel is an evasion vector, and unknown
        // syntax there should not buy a pass. A POSITIONAL remote command is
        // the ordinary way to run anything on a host, so an `Unknown` verb
        // there is usually a project's own script name; blocking on it would
        // turn this High finding into "refuse every unrecognized command on a
        // critical host" and take out the deploy workflows the label exists to
        // protect. `positional_unknown_command_is_not_blocked_on_a_critical_host`
        // pins that boundary.
        let conservative_remote_command = parsed.remote_command_from_option
            && (parsed.remote_command_unparseable
                || category == crate::rules::context::VerbCategory::Unknown);
        if !category.is_actionable() && !conservative_remote_command {
            return Vec::new();
        }

        let category_text = if conservative_remote_command {
            "unclassifiable_remote_command"
        } else {
            category.as_str()
        };

        let title = format!(
            "Destructive remote command against labeled-{} host '{}'",
            label.to_lowercase(),
            parsed.host,
        );
        let description = format!(
            "About to run a {category_text} command on remote host '{}' (label: '{label}'). \
             SSH inner commands bypass tirith's local enter / paste interception.",
            parsed.host,
        );
        return vec![Finding {
            rule_id: RuleId::SshRemoteDestructiveOnLabeledHost,
            severity: Severity::High,
            title,
            description,
            evidence: vec![
                Evidence::Text {
                    detail: format!(
                        "host={} user_at_host={} label={} category={category_text} inner={}",
                        parsed.host,
                        parsed.user_at_host,
                        label,
                        // Cap the inner-command preview so a giant paste doesn't bloat evidence.
                        inner.chars().take(200).collect::<String>(),
                    ),
                },
                Evidence::CommandPattern {
                    pattern: format!("ssh {} <{category_text}>", parsed.host),
                    matched: input.chars().take(200).collect(),
                },
            ],
            human_view: Some(format!(
                "tirith refused: '{}' is labeled '{label}'. The inner command falls in the {category_text} category.",
                parsed.host,
            )),
            agent_view: Some(format!(
                "tirith refused: remote SSH command. host='{}' label='{label}' category={category_text}.",
                parsed.host,
            )),
            mitre_id: None,
            custom_rule_id: None,
        }];
    }

    // Bare `ssh host` → Info reminder.
    vec![Finding {
        rule_id: RuleId::SshRemoteShellOnLabeledHost,
        severity: Severity::Info,
        title: format!(
            "Opening a remote shell on labeled-{} host '{}'",
            label.to_lowercase(),
            parsed.host,
        ),
        description: format!(
            "Connecting to '{}' (label: '{label}'). tirith protects the local shell only — \
             commands you type AFTER the SSH handshake are not intercepted by this hook. \
             Run `tirith ssh bootstrap user@host` (planned for M8.1) to install the hook \
             on the remote side.",
            parsed.host,
        ),
        evidence: vec![Evidence::Text {
            detail: format!("host={} label={label}", parsed.host),
        }],
        human_view: Some(format!(
            "Heads up: '{}' is labeled '{label}'. tirith does not protect the remote session.",
            parsed.host,
        )),
        agent_view: Some(format!(
            "Opening remote shell. host='{}' label='{label}'. Remote-side tirith hook NOT installed.",
            parsed.host,
        )),
        mitre_id: None,
        custom_rule_id: None,
    }]
}

/// The SSH command line decoded into host and optional inner command. The host
/// is the first non-`-` positional; the inner command is everything after it.
#[derive(Debug)]
struct ParsedSsh {
    /// Bare host, with any leading `user@` stripped.
    host: String,
    /// The full `user@host` form (or bare host when no userinfo).
    user_at_host: String,
    /// The inner command portion (after the host) if present.
    inner_command: Option<String>,
    /// Whether at least part of the effective command came from `-o
    /// RemoteCommand=...`; unknown syntax on this channel fails conservatively.
    remote_command_from_option: bool,
    remote_command_unparseable: bool,
}

fn parse_ssh_invocation(args: &[String]) -> Option<ParsedSsh> {
    let mut idx = 0;
    let mut option_user: Option<String> = None;
    let mut remote_commands: Vec<String> = Vec::new();
    let mut remote_command_from_option = false;
    let mut remote_command_unparseable = false;
    while idx < args.len() {
        let raw = strip_outer_quotes(&args[idx]);

        if raw == "--" {
            idx += 1;
            break;
        }
        if raw.starts_with('-') && raw != "-" {
            if raw == "-l" || raw == "-o" {
                let value = strip_outer_quotes(args.get(idx + 1)?);
                if raw == "-l" {
                    if value.is_empty() {
                        return None;
                    }
                    if option_user.is_none() {
                        option_user = Some(value.to_string());
                    }
                } else {
                    parse_ssh_config_option(
                        value,
                        &mut option_user,
                        &mut remote_commands,
                        &mut remote_command_from_option,
                        &mut remote_command_unparseable,
                    );
                }
                idx += 2;
                continue;
            }
            if let Some(value) = raw.strip_prefix("-l").filter(|value| !value.is_empty()) {
                if option_user.is_none() {
                    option_user = Some(strip_outer_quotes(value).to_string());
                }
                idx += 1;
                continue;
            }
            if let Some(value) = raw.strip_prefix("-o").filter(|value| !value.is_empty()) {
                parse_ssh_config_option(
                    value,
                    &mut option_user,
                    &mut remote_commands,
                    &mut remote_command_from_option,
                    &mut remote_command_unparseable,
                );
                idx += 1;
                continue;
            }
            if SSH_FLAGS_WITH_ARG.contains(&raw) {
                args.get(idx + 1)?;
                idx += 2;
                continue;
            }
            if SSH_FLAGS_WITH_ARG
                .iter()
                .filter(|flag| !matches!(**flag, "-l" | "-o"))
                .any(|flag| raw.starts_with(flag) && raw.len() > flag.len())
            {
                idx += 1;
                continue;
            }
            // Boolean flags, including clusters such as `-tt`.
            idx += 1;
            continue;
        }
        // First positional — the host (possibly `user@host`).
        let destination = raw.to_string();
        let (destination_user, host) = match destination.rsplit_once('@') {
            Some((user, host)) => (Some(user.to_string()), host.to_string()),
            None => (None, destination.clone()),
        };

        if host.is_empty() {
            return None;
        }

        // OpenSSH uses the first command-line user value it obtains. Since
        // options precede the destination, `-l`/`-o User` wins over a later
        // `user@host` spelling, and repeated user options do not overwrite it.
        let effective_user = option_user.or(destination_user);
        let user_at_host = effective_user
            .as_deref()
            .map(|user| format!("{user}@{host}"))
            .unwrap_or_else(|| host.clone());

        let inner: Vec<String> = args[idx + 1..]
            .iter()
            .map(|a| strip_outer_quotes(a).to_string())
            .collect();

        if !inner.is_empty() {
            remote_commands.push(inner.join(" "));
        }
        let inner_command = if remote_command_unparseable && remote_commands.is_empty() {
            Some("<unparseable RemoteCommand>".to_string())
        } else {
            (!remote_commands.is_empty()).then(|| remote_commands.join(" ; "))
        };

        return Some(ParsedSsh {
            host,
            user_at_host,
            inner_command,
            remote_command_from_option,
            remote_command_unparseable,
        });
    }

    // `--` may have ended options immediately before the destination.
    if idx < args.len() {
        let mut tail = args[idx..].to_vec();
        if let Some(first) = tail.first_mut() {
            *first = strip_outer_quotes(first).to_string();
        }
        return parse_ssh_invocation_with_options(
            &tail,
            option_user,
            remote_commands,
            remote_command_from_option,
            remote_command_unparseable,
        );
    }
    None
}

fn parse_ssh_invocation_with_options(
    args: &[String],
    option_user: Option<String>,
    mut remote_commands: Vec<String>,
    remote_command_from_option: bool,
    remote_command_unparseable: bool,
) -> Option<ParsedSsh> {
    let destination = strip_outer_quotes(args.first()?);
    let (destination_user, host) = match destination.rsplit_once('@') {
        Some((user, host)) => (Some(user.to_string()), host.to_string()),
        None => (None, destination.to_string()),
    };
    if host.is_empty() {
        return None;
    }
    let effective_user = option_user.or(destination_user);
    let user_at_host = effective_user
        .as_deref()
        .map(|user| format!("{user}@{host}"))
        .unwrap_or_else(|| host.clone());
    let positional = args[1..]
        .iter()
        .map(|arg| strip_outer_quotes(arg).to_string())
        .collect::<Vec<_>>();
    if !positional.is_empty() {
        remote_commands.push(positional.join(" "));
    }
    Some(ParsedSsh {
        host,
        user_at_host,
        inner_command: if remote_command_unparseable && remote_commands.is_empty() {
            Some("<unparseable RemoteCommand>".to_string())
        } else {
            (!remote_commands.is_empty()).then(|| remote_commands.join(" ; "))
        },
        remote_command_from_option,
        remote_command_unparseable,
    })
}

fn parse_ssh_config_option(
    raw: &str,
    option_user: &mut Option<String>,
    remote_commands: &mut Vec<String>,
    remote_command_from_option: &mut bool,
    remote_command_unparseable: &mut bool,
) {
    let raw = strip_outer_quotes(raw).trim();
    let parsed = raw
        .split_once('=')
        .or_else(|| raw.split_once(char::is_whitespace));
    let Some((name, value)) = parsed else {
        if raw.eq_ignore_ascii_case("RemoteCommand") {
            *remote_command_from_option = true;
            *remote_command_unparseable = true;
        }
        return;
    };
    let name = name.trim();
    let value = strip_outer_quotes(value.trim()).trim();
    if name.eq_ignore_ascii_case("User") {
        if !value.is_empty() && option_user.is_none() {
            *option_user = Some(value.to_string());
        }
    } else if name.eq_ignore_ascii_case("RemoteCommand") {
        if *remote_command_from_option {
            return;
        }
        *remote_command_from_option = true;
        if value.is_empty() {
            *remote_command_unparseable = true;
        } else if !value.eq_ignore_ascii_case("none") {
            remote_commands.push(value.to_string());
        }
    }
}

fn strip_outer_quotes(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        // SAFETY: outer quotes are single-byte ASCII, so the byte boundary is a
        // char boundary in any valid UTF-8 string.
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn command_basename(cmd: &str, shell: ShellType) -> String {
    let unq = strip_outer_quotes(cmd);
    let basename = match shell {
        ShellType::PowerShell | ShellType::Cmd => unq.rsplit(['/', '\\']).next().unwrap_or(unq),
        _ => unq.rsplit('/').next().unwrap_or(unq),
    };
    let lower = basename.to_lowercase();
    lower
        .strip_suffix(".exe")
        .map(str::to_string)
        .unwrap_or(lower)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn policy_with_label(host: &str, criticality: &str) -> Policy {
        let mut p = Policy::default();
        let mut labels = BTreeMap::new();
        labels.insert(host.to_string(), criticality.to_string());
        p.ssh_host_labels = labels;
        p
    }

    #[test]
    fn empty_labels_silences_rule() {
        let policy = Policy::default();
        let findings = check(
            "ssh prod-host 'sudo systemctl restart payments'",
            ShellType::Posix,
            &policy,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn disabled_context_guard_silences_ssh_labels() {
        let mut policy = policy_with_label("prod-host", "critical");
        policy.context_guard_enabled = false;
        let findings = check(
            "ssh prod-host 'systemctl restart payments'",
            ShellType::Posix,
            &policy,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn execution_wrappers_do_not_hide_ssh() {
        let policy = policy_with_label("prod-host", "critical");
        for command in [
            "env ssh prod-host 'systemctl restart payments'",
            "sudo ssh prod-host 'systemctl restart payments'",
            "command ssh prod-host 'systemctl restart payments'",
        ] {
            let findings = check(command, ShellType::Posix, &policy);
            assert!(
                findings.iter().any(|finding| matches!(
                    finding.rule_id,
                    RuleId::SshRemoteDestructiveOnLabeledHost
                )),
                "wrapper hid SSH invocation for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn ambiguous_wrapper_around_ssh_fails_closed() {
        let policy = policy_with_label("prod-host", "critical");
        let findings = check(
            "sudo --future-option value ssh prod-host 'systemctl restart payments'",
            ShellType::Posix,
            &policy,
        );
        assert!(findings.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete && finding.severity == Severity::High
        }));
    }

    #[test]
    fn host_lookup_is_case_insensitive_and_ignores_dns_root_dot() {
        let policy = policy_with_label("prod.example", "critical");
        let findings = check(
            "ssh Alice@PROD.EXAMPLE. 'systemctl restart payments'",
            ShellType::Posix,
            &policy,
        );
        assert_eq!(
            findings.len(),
            1,
            "canonical host did not match: {findings:?}"
        );
    }

    #[test]
    fn destructive_inner_command_blocks_labeled_host() {
        let policy = policy_with_label("prod-host", "critical");
        let findings = check(
            "ssh prod-host 'sudo systemctl restart payments'",
            ShellType::Posix,
            &policy,
        );
        assert_eq!(findings.len(), 1, "expected one finding: {findings:?}");
        assert!(matches!(
            findings[0].rule_id,
            RuleId::SshRemoteDestructiveOnLabeledHost
        ));
        assert!(matches!(findings[0].severity, Severity::High));
    }

    #[test]
    fn every_local_and_remote_segment_is_classified() {
        let policy = policy_with_label("prod-host", "critical");
        for command in [
            "true; ssh prod-host 'systemctl restart payments'",
            "ssh prod-host 'true; systemctl restart payments'",
            "ssh prod-host 'ls && kubectl delete namespace payments'",
        ] {
            let findings = check(command, ShellType::Posix, &policy);
            assert!(
                findings.iter().any(|finding| {
                    matches!(finding.rule_id, RuleId::SshRemoteDestructiveOnLabeledHost)
                }),
                "later SSH segment escaped detection for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn remote_command_option_is_preserved_and_classified() {
        let policy = policy_with_label("prod-host", "critical");
        for command in [
            r#"ssh -oRemoteCommand='systemctl restart payments' prod-host"#,
            r#"ssh -o "RemoteCommand=systemctl restart payments" prod-host"#,
            r#"ssh -o 'remotecommand systemctl restart payments' prod-host"#,
        ] {
            let findings = check(command, ShellType::Posix, &policy);
            assert!(
                findings.iter().any(|finding| {
                    matches!(finding.rule_id, RuleId::SshRemoteDestructiveOnLabeledHost)
                }),
                "RemoteCommand bypassed classification for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn unknown_remote_command_fails_conservatively_on_critical_host() {
        let policy = policy_with_label("prod-host", "critical");
        for command in [
            "ssh -oRemoteCommand=custom-deployer prod-host",
            "ssh -oRemoteCommand prod-host",
        ] {
            let findings = check(command, ShellType::Posix, &policy);
            assert!(findings.iter().any(|finding| {
                matches!(finding.rule_id, RuleId::SshRemoteDestructiveOnLabeledHost)
                    && finding.severity == Severity::High
            }));
        }
    }

    #[test]
    fn positional_unknown_command_is_not_blocked_on_a_critical_host() {
        // Counterpart to the `-o RemoteCommand=` case above. A positional
        // command that classifies as Unknown is an ordinary project script, and
        // this rule blocks at High, so firing here would refuse every
        // unrecognized command against a critical host. The destructive verbs
        // still fire, and the obscure option channel still fails closed.
        let policy = policy_with_label("prod-host", "critical");
        let findings = check("ssh prod-host 'custom-deployer'", ShellType::Posix, &policy);
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::SshRemoteDestructiveOnLabeledHost),
            "an unclassifiable positional command must not block: {findings:?}"
        );

        let destructive = check("ssh prod-host 'rm -rf /srv'", ShellType::Posix, &policy);
        assert!(
            destructive
                .iter()
                .any(|finding| finding.rule_id == RuleId::SshRemoteDestructiveOnLabeledHost),
            "a destructive positional command must still fire: {destructive:?}"
        );
    }

    #[test]
    fn bare_ssh_to_labeled_host_emits_info() {
        let policy = policy_with_label("prod-host", "critical");
        let findings = check("ssh prod-host", ShellType::Posix, &policy);
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].rule_id,
            RuleId::SshRemoteShellOnLabeledHost
        ));
        assert!(matches!(findings[0].severity, Severity::Info));
    }

    #[test]
    fn ssh_to_unlabeled_host_does_not_fire() {
        let policy = policy_with_label("prod-host", "critical");
        let findings = check(
            "ssh dev-host 'sudo systemctl restart x'",
            ShellType::Posix,
            &policy,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ls_inner_command_does_not_fire() {
        let policy = policy_with_label("prod-host", "critical");
        let findings = check("ssh prod-host 'ls'", ShellType::Posix, &policy);
        assert!(
            findings.is_empty(),
            "read-only ls must not fire: {findings:?}"
        );
    }

    #[test]
    fn dash_t_flag_is_skipped() {
        let policy = policy_with_label("prod-host", "critical");
        let findings = check(
            "ssh -t prod-host 'sudo rm -rf /var/log/foo'",
            ShellType::Posix,
            &policy,
        );
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].rule_id,
            RuleId::SshRemoteDestructiveOnLabeledHost
        ));
    }

    #[test]
    fn dash_tt_flag_is_skipped() {
        let policy = policy_with_label("prod-host", "critical");
        let findings = check(
            "ssh -tt prod-host 'sudo systemctl stop payments'",
            ShellType::Posix,
            &policy,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flag_with_value_is_skipped() {
        let policy = policy_with_label("prod-host", "critical");
        let findings = check(
            "ssh -i /tmp/key -p 2222 prod-host 'sudo systemctl restart payments'",
            ShellType::Posix,
            &policy,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn glued_flag_value_is_skipped() {
        let policy = policy_with_label("prod-host", "critical");
        let findings = check(
            "ssh -i/tmp/key prod-host 'sudo rm -rf /tmp/foo'",
            ShellType::Posix,
            &policy,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn user_at_host_resolves_to_host() {
        let policy = policy_with_label("prod-host", "critical");
        let findings = check(
            "ssh root@prod-host 'sudo rm -rf /tmp/x'",
            ShellType::Posix,
            &policy,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn user_at_host_prefers_user_at_host_label() {
        // A critical exact user@host label wins over noncritical bare inventory.
        let mut policy = Policy::default();
        let mut labels = BTreeMap::new();
        labels.insert("root@prod-host".to_string(), "critical".to_string());
        labels.insert("prod-host".to_string(), "staging".to_string());
        policy.ssh_host_labels = labels;

        let findings = check(
            "ssh root@prod-host 'sudo rm -rf /tmp/x'",
            ShellType::Posix,
            &policy,
        );
        assert_eq!(findings.len(), 1);
        // user@host took precedence (the bare host's `staging` would not fire).
        assert!(matches!(
            findings[0].rule_id,
            RuleId::SshRemoteDestructiveOnLabeledHost
        ));
    }

    #[test]
    fn noncritical_exact_label_cannot_shadow_critical_bare_host() {
        let mut policy = Policy::default();
        policy
            .ssh_host_labels
            .insert("root@prod-host".to_string(), "dev".to_string());
        policy
            .ssh_host_labels
            .insert("prod-host".to_string(), "production".to_string());

        let findings = check(
            "ssh root@prod-host 'sudo rm -rf /tmp/x'",
            ShellType::Posix,
            &policy,
        );
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].rule_id,
            RuleId::SshRemoteDestructiveOnLabeledHost
        ));
    }

    #[test]
    fn split_and_attached_user_options_preserve_exact_label_identity() {
        let mut policy = Policy::default();
        policy
            .ssh_host_labels
            .insert("root@prod-host".to_string(), "critical".to_string());
        policy
            .ssh_host_labels
            .insert("prod-host".to_string(), "staging".to_string());

        for command in [
            "ssh -l root prod-host 'systemctl restart payments'",
            "ssh -lroot prod-host 'systemctl restart payments'",
            "ssh -oUser=root prod-host 'systemctl restart payments'",
            "ssh -o 'User root' prod-host 'systemctl restart payments'",
            "ssh -l root dev@prod-host 'systemctl restart payments'",
            "ssh -oUser=root -oUser=dev prod-host 'systemctl restart payments'",
        ] {
            let findings = check(command, ShellType::Posix, &policy);
            assert!(
                findings.iter().any(|finding| {
                    matches!(finding.rule_id, RuleId::SshRemoteDestructiveOnLabeledHost)
                }),
                "effective SSH user was lost for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn non_critical_label_does_not_fire() {
        let policy = policy_with_label("prod-host", "staging");
        let findings = check(
            "ssh prod-host 'sudo systemctl restart payments'",
            ShellType::Posix,
            &policy,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn non_ssh_leader_does_not_fire() {
        let policy = policy_with_label("prod-host", "critical");
        let findings = check("rsync prod-host:/srv/data /tmp/", ShellType::Posix, &policy);
        assert!(findings.is_empty());
    }

    #[test]
    fn parse_ssh_skips_dash_o_kv() {
        let p = parse_ssh_invocation(&[
            "-o".into(),
            "StrictHostKeyChecking=no".into(),
            "prod-host".into(),
            "ls".into(),
        ])
        .unwrap();
        assert_eq!(p.host, "prod-host");
        assert_eq!(p.inner_command.as_deref(), Some("ls"));
    }

    #[test]
    fn parse_ssh_with_jump_host() {
        let p = parse_ssh_invocation(&["-J".into(), "bastion".into(), "prod-host".into()]).unwrap();
        assert_eq!(p.host, "prod-host");
        assert!(p.inner_command.is_none());
    }

    #[test]
    fn is_critical_label_recognizes_aliases() {
        for s in [
            "critical",
            "CRITICAL",
            "production",
            "Prod",
            "live",
            "p0",
            "p1",
        ] {
            assert!(is_critical_label(s), "{s} should be critical");
        }
        for s in ["dev", "staging", "qa", "test", "p2", ""] {
            assert!(!is_critical_label(s), "{s} should NOT be critical");
        }
    }
}
