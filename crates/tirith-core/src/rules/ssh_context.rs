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
use crate::rules::shared::is_critical_label;
use crate::tokenize::{self, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// SSH flags that consume the next arg (per `ssh(1)`), so the host detector
/// doesn't mistake a flag value for the hostname.
const SSH_FLAGS_WITH_ARG: &[&str] = &[
    "-i", "-p", "-l", "-L", "-R", "-D", "-F", "-S", "-c", "-e", "-o", "-J", "-Q", "-b", "-B", "-E",
    "-I", "-O", "-w", "-m",
];

/// Run SSH-context rules; returns at most one finding. A destructive inner
/// command on a labeled host → `SshRemoteDestructiveOnLabeledHost` (High); a
/// bare `ssh host` on a labeled host → `SshRemoteShellOnLabeledHost` (Info).
pub fn check(input: &str, shell: ShellType, policy: &Policy) -> Vec<Finding> {
    // Empty labels file → no enforcement (opt-in).
    if policy.ssh_host_labels.is_empty() {
        return Vec::new();
    }

    let segments = tokenize::tokenize(input, shell);
    let Some(seg) = segments.first() else {
        return Vec::new();
    };
    let Some(cmd) = seg.command.as_deref() else {
        return Vec::new();
    };
    let base = command_basename(cmd, shell);
    if base != "ssh" {
        return Vec::new();
    }

    let parsed = match parse_ssh_invocation(seg.args.as_slice()) {
        Some(p) => p,
        None => return Vec::new(),
    };

    // Try the user@host label first, then the bare host.
    let label = match policy
        .ssh_host_labels
        .get(&parsed.user_at_host)
        .or_else(|| policy.ssh_host_labels.get(&parsed.host))
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
        if !category.is_actionable() {
            return Vec::new();
        }

        let title = format!(
            "Destructive remote command against labeled-{} host '{}'",
            label.to_lowercase(),
            parsed.host,
        );
        let description = format!(
            "About to run a {category} command on remote host '{}' (label: '{label}'). \
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
                        "host={} user_at_host={} label={} category={category} inner={}",
                        parsed.host,
                        parsed.user_at_host,
                        label,
                        // Cap the inner-command preview so a giant paste doesn't bloat evidence.
                        inner.chars().take(200).collect::<String>(),
                    ),
                },
                Evidence::CommandPattern {
                    pattern: format!("ssh {} <{category}>", parsed.host),
                    matched: input.chars().take(200).collect(),
                },
            ],
            human_view: Some(format!(
                "tirith refused: '{}' is labeled '{label}'. The inner command falls in the {category} category.",
                parsed.host,
            )),
            agent_view: Some(format!(
                "tirith refused: remote SSH command. host='{}' label='{label}' category={category}.",
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
}

fn parse_ssh_invocation(args: &[String]) -> Option<ParsedSsh> {
    let mut idx = 0;
    while idx < args.len() {
        let raw = strip_outer_quotes(&args[idx]);

        if raw.starts_with('-') {
            if SSH_FLAGS_WITH_ARG.contains(&raw) {
                // Flag takes a separate value — consume both.
                idx += 2;
            } else if SSH_FLAGS_WITH_ARG
                .iter()
                .any(|f| raw.starts_with(f) && raw.len() > f.len())
            {
                // `-iidentity` form — value glued on, single token.
                idx += 1;
            } else {
                idx += 1;
            }
            continue;
        }
        // First positional — the host (possibly `user@host`).
        let user_at_host = raw.to_string();
        let host = match user_at_host.rsplit_once('@') {
            Some((_, h)) => h.to_string(),
            None => user_at_host.clone(),
        };

        if host.is_empty() {
            return None;
        }

        let inner: Vec<String> = args[idx + 1..]
            .iter()
            .map(|a| strip_outer_quotes(a).to_string())
            .collect();

        let inner_command = if inner.is_empty() {
            None
        } else {
            Some(inner.join(" "))
        };

        return Some(ParsedSsh {
            host,
            user_at_host,
            inner_command,
        });
    }
    None
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
        // The exact user@host key should win over the bare host.
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
