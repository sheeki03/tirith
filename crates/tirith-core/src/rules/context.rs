//! Operational-context rules (M8 ch1).
//!
//! Fire when the command's leader is a cloud/k8s CLI (`kubectl`, `helm`,
//! `aws`, `gcloud`, `az`, …) AND the active provider context is labeled
//! `critical`/`production`. Three signals: `ContextProdDestructiveCommand`
//! (High, destructive verbs), `ContextProdWriteOperation` (Medium, state
//! mutations), `ContextProdCredentialChange` (High, IAM/RBAC mutations).
//!
//! Two short-circuit gates before consulting [`crate::context_detect`]:
//! empty `context_labels` table → rule cannot fire; `context_guard_enabled:
//! false` → operator opt-out. After the gates, [`crate::context_detect::detect_all`]
//! (5s cached) supplies the active context; only a `critical`/`production`
//! label emits a finding.

use crate::context_detect::{self, Provider};
use crate::policy::Policy;
use crate::rules::shared::is_critical_label;
use crate::tokenize::{self, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Run context rules. Returns at most one finding (the highest-severity
/// signal we found for the command's leader).
pub fn check(input: &str, shell: ShellType, policy: &Policy) -> Vec<Finding> {
    if !policy.context_guard_enabled {
        return Vec::new();
    }
    if policy.context_labels.is_empty() {
        return Vec::new();
    }

    let segments = tokenize::tokenize(input, shell);
    let Some(seg) = segments.first() else {
        return Vec::new();
    };
    let Some(cmd) = seg.command.as_deref() else {
        return Vec::new();
    };

    // Step past one level of sudo / aws-vault wrappers so
    // `aws-vault exec prod -- aws s3 rm s3://x` resolves to the inner
    // `aws s3 rm` call.
    let (leader, args) = resolve_leader_and_args(cmd, seg.args.as_slice(), shell);

    let provider = match Provider::from_leader(&leader) {
        Some(p) => p,
        None => return Vec::new(),
    };

    let detection = context_detect::detect_all();

    // Surface a provider detection failure (timeout/exec/parse) on stderr so the
    // operator knows the verdict can't safely fall back to "allow" (PR-127 finding #5).
    if let Some(failure) = detection.failures.get(&provider) {
        eprintln!(
            "tirith: warning: {} context detection failed ({}); rule may not fire correctly for this command",
            provider.as_str(),
            failure,
        );
    }

    let active = match detection.contexts.get(&provider) {
        Some(ctx) => ctx,
        None => return Vec::new(),
    };

    let label_key = active.label_key();
    let criticality = match policy.context_labels.get(&label_key) {
        Some(c) => c,
        None => return Vec::new(),
    };
    if !is_critical_label(criticality) {
        return Vec::new();
    }

    // Custom destructive verbs from policy override the built-in list.
    let custom_destructive = policy
        .context_destructive_verbs
        .get(provider.as_str())
        .cloned()
        .unwrap_or_default();

    let category = classify(provider, &args, &custom_destructive);
    let (rule_id, severity) = match category {
        VerbCategory::Destructive => (RuleId::ContextProdDestructiveCommand, Severity::High),
        VerbCategory::CredentialChange => (RuleId::ContextProdCredentialChange, Severity::High),
        VerbCategory::Write => (RuleId::ContextProdWriteOperation, Severity::Medium),
        VerbCategory::ReadOnly | VerbCategory::Unknown => return Vec::new(),
    };

    let title = format!(
        "{} command against labeled-{} context '{}'",
        rule_id_human(&rule_id),
        criticality.to_lowercase(),
        active.context,
    );
    let description = format!(
        "Active {} context '{}' is labeled '{}' in tirith's context-labels file; \
         the command's verb is {}. Confirm with `tirith context status` and re-run \
         with explicit acknowledgement if intentional.",
        provider.as_str(),
        active.context,
        criticality,
        category.as_str(),
    );

    vec![Finding {
        rule_id,
        severity,
        title,
        description,
        evidence: vec![
            Evidence::Text {
                detail: format!(
                    "provider={} context={} label={} leader={} verb_category={}",
                    provider.as_str(),
                    active.context,
                    criticality,
                    leader,
                    category.as_str(),
                ),
            },
            Evidence::CommandPattern {
                pattern: format!("{} <{}>", leader, category.as_str()),
                matched: input.chars().take(200).collect(),
            },
        ],
        human_view: Some(format!(
            "About to run a {} command against '{}' (labeled {}).",
            category.as_str(),
            active.context,
            criticality.to_lowercase(),
        )),
        agent_view: Some(format!(
            "tirith refused: active {} context '{}' is operator-labeled \
             {}. The command's verb falls in the {} category for this provider.",
            provider.as_str(),
            active.context,
            criticality,
            category.as_str(),
        )),
        mitre_id: None,
        custom_rule_id: None,
    }]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerbCategory {
    Destructive,
    CredentialChange,
    Write,
    ReadOnly,
    Unknown,
}

impl VerbCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Destructive => "destructive",
            Self::CredentialChange => "credential_change",
            Self::Write => "write",
            Self::ReadOnly => "read_only",
            Self::Unknown => "unknown",
        }
    }

    /// `true` when the category should drive a finding (Destructive,
    /// Write, or CredentialChange). Read-only / Unknown do not fire.
    pub fn is_actionable(self) -> bool {
        matches!(
            self,
            Self::Destructive | Self::CredentialChange | Self::Write
        )
    }
}

impl std::fmt::Display for VerbCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classify an SSH inner-command string (the body of `ssh host '<body>'`).
///
/// Used by `rules::ssh_context` to decide whether a destructive verb runs on a
/// labeled-prod remote host. Steps past one level of `sudo`/`doas`, then maps
/// the leader to a [`VerbCategory`] via the cloud-CLI heuristics plus a small
/// extra surface for general shell verbs (`systemctl stop`, `rm -rf`, `dd`).
pub fn classify_inner_command_for_ssh(inner: &str, shell: ShellType) -> VerbCategory {
    let segments = tokenize::tokenize(inner, shell);
    let Some(seg) = segments.first() else {
        return VerbCategory::Unknown;
    };
    let Some(cmd) = seg.command.as_deref() else {
        return VerbCategory::Unknown;
    };
    let (leader, args) = resolve_leader_and_args(cmd, seg.args.as_slice(), shell);

    let positional: Vec<&str> = args
        .iter()
        .map(|a| a.trim_matches(|c: char| c == '"' || c == '\''))
        .filter(|a| !a.starts_with('-') && !a.contains('='))
        .collect();
    let first = positional.first().copied().unwrap_or("");

    // Cloud-CLI path first so a remote `kubectl delete ns` is still Destructive.
    if let Some(provider) = crate::context_detect::Provider::from_leader(&leader) {
        return classify(provider, &args, &[]);
    }

    // General-purpose remote-shell verbs — only the highest-signal ones. Read-only
    // commands map to ReadOnly so `ssh prod-host 'ls'` does NOT fire.
    let leader_lc = leader.to_lowercase();
    match leader_lc.as_str() {
        "rm" => VerbCategory::Destructive,
        "dd" | "mkfs" | "shred" | "wipefs" | "fdisk" | "parted" | "blkdiscard" => {
            VerbCategory::Destructive
        }
        "systemctl" => match first {
            "stop" | "restart" | "disable" | "mask" | "kill" | "reload-or-restart" => {
                VerbCategory::Destructive
            }
            "start" | "enable" | "unmask" | "reload" => VerbCategory::Write,
            "status" | "is-active" | "is-enabled" | "list-units" | "show" | "cat" => {
                VerbCategory::ReadOnly
            }
            _ => VerbCategory::Unknown,
        },
        "service" => match first {
            "stop" | "restart" | "force-reload" => VerbCategory::Destructive,
            "start" | "reload" => VerbCategory::Write,
            "status" => VerbCategory::ReadOnly,
            _ => VerbCategory::Unknown,
        },
        "shutdown" | "poweroff" | "reboot" | "halt" | "init" => VerbCategory::Destructive,
        "iptables" | "nft" | "nftables" => VerbCategory::Write,
        "passwd" | "chpasswd" | "useradd" | "userdel" | "usermod" | "groupadd" | "groupdel"
        | "groupmod" | "visudo" => VerbCategory::CredentialChange,
        "ls" | "cat" | "less" | "more" | "head" | "tail" | "stat" | "find" | "grep" | "ps"
        | "top" | "df" | "du" | "uname" | "hostname" | "whoami" | "id" | "uptime" => {
            VerbCategory::ReadOnly
        }
        _ => VerbCategory::Unknown,
    }
}

fn classify(provider: Provider, args: &[String], custom_destructive: &[String]) -> VerbCategory {
    // Skip flags / `KEY=VAL` so `aws --profile foo s3 rm` resolves to (`s3`, `rm`).
    let positional: Vec<&str> = args
        .iter()
        .map(|a| a.trim_matches(|c: char| c == '"' || c == '\''))
        .filter(|a| !a.starts_with('-') && !a.contains('='))
        .collect();

    let first = positional.first().copied().unwrap_or("");
    let second = positional.get(1).copied().unwrap_or("");
    let third = positional.get(2).copied().unwrap_or("");

    if !custom_destructive.is_empty() {
        let custom: Vec<String> = custom_destructive
            .iter()
            .map(|v| v.to_lowercase())
            .collect();
        for cand in [first, second, third] {
            if !cand.is_empty() && custom.iter().any(|c| c == &cand.to_lowercase()) {
                return VerbCategory::Destructive;
            }
        }
    }

    match provider {
        Provider::Kube => classify_kube(first, args),
        Provider::Aws => classify_aws(first, second, args),
        Provider::Gcp => classify_gcp(first, second, third, args),
        Provider::Azure => classify_azure(first, second, third, args),
    }
}

fn classify_kube(subcommand: &str, args: &[String]) -> VerbCategory {
    let sc = subcommand.to_lowercase();
    match sc.as_str() {
        "delete" | "destroy" | "rm" | "remove" | "uninstall" | "drain" | "evict" | "cordon" => {
            VerbCategory::Destructive
        }
        "apply" | "create" | "patch" | "replace" | "edit" | "rollout" | "scale" | "label"
        | "annotate" | "upgrade" | "install" | "set" | "expose" | "sync" | "rollback" => {
            if sc == "create" && args_mention_rbac(args) {
                VerbCategory::CredentialChange
            } else {
                VerbCategory::Write
            }
        }
        "get" | "list" | "describe" | "logs" | "version" | "config" | "explain" | "top"
        | "auth" | "context" | "contexts" | "current-context" => VerbCategory::ReadOnly,
        _ => VerbCategory::Unknown,
    }
}

fn classify_aws(service: &str, action: &str, args: &[String]) -> VerbCategory {
    let svc = service.to_lowercase();
    let act = action.to_lowercase();

    if svc == "iam" {
        if act.starts_with("get-")
            || act.starts_with("list-")
            || act.starts_with("describe-")
            || act == "simulate-custom-policy"
        {
            return VerbCategory::ReadOnly;
        }
        return VerbCategory::CredentialChange;
    }

    if svc == "s3" || svc == "s3api" {
        match act.as_str() {
            "rm" | "rb" | "delete-object" | "delete-objects" | "delete-bucket" => {
                VerbCategory::Destructive
            }
            "cp" | "mv" | "sync" | "mb" | "put-object" | "create-bucket" | "put-bucket-policy" => {
                VerbCategory::Write
            }
            "ls" | "cat" | "head" | "list-buckets" | "list-objects" | "list-objects-v2"
            | "get-object" => VerbCategory::ReadOnly,
            _ => VerbCategory::Unknown,
        }
    } else if svc == "ec2" || svc == "rds" || svc == "ecs" || svc == "eks" || svc == "lambda" {
        if act.starts_with("describe-") || act.starts_with("list-") || act.starts_with("get-") {
            VerbCategory::ReadOnly
        } else if act.contains("delete") || act.contains("terminate") {
            VerbCategory::Destructive
        } else {
            VerbCategory::Write
        }
    } else if !act.is_empty() {
        if act.starts_with("describe-") || act.starts_with("list-") || act.starts_with("get-") {
            VerbCategory::ReadOnly
        } else if act.contains("delete") || act.contains("terminate") || act.contains("destroy") {
            VerbCategory::Destructive
        } else {
            VerbCategory::Unknown
        }
    } else {
        let _ = args;
        VerbCategory::Unknown
    }
}

fn classify_gcp(first: &str, second: &str, third: &str, args: &[String]) -> VerbCategory {
    let joined: Vec<String> = [first, second, third]
        .iter()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .collect();
    let verb = joined.last().cloned().unwrap_or_default();
    let first_lc = joined.first().cloned().unwrap_or_default();

    if first_lc == "iam"
        || joined
            .iter()
            .any(|s| s == "service-accounts" || s == "roles")
    {
        if verb == "list" || verb.starts_with("describe") || verb == "get-iam-policy" {
            return VerbCategory::ReadOnly;
        }
        return VerbCategory::CredentialChange;
    }

    match verb.as_str() {
        "delete" | "destroy" | "remove" | "purge" => VerbCategory::Destructive,
        "create" | "update" | "apply" | "patch" | "set" | "start" | "stop" | "restart"
        | "deploy" | "import" | "add" | "enable" | "disable" => VerbCategory::Write,
        "list" | "describe" | "get" | "version" | "config" => VerbCategory::ReadOnly,
        _ => {
            let _ = args;
            VerbCategory::Unknown
        }
    }
}

fn classify_azure(first: &str, second: &str, third: &str, args: &[String]) -> VerbCategory {
    let joined: Vec<String> = [first, second, third]
        .iter()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .collect();
    let verb = joined.last().cloned().unwrap_or_default();
    let first_lc = joined.first().cloned().unwrap_or_default();

    if first_lc == "ad"
        || first_lc == "role"
        || joined
            .iter()
            .any(|s| s == "sp" || s == "user" || s == "group")
    {
        if verb == "list" || verb == "show" {
            return VerbCategory::ReadOnly;
        }
        return VerbCategory::CredentialChange;
    }

    match verb.as_str() {
        "delete" | "purge" | "remove" => VerbCategory::Destructive,
        "create" | "update" | "set" | "start" | "stop" | "restart" | "deploy" | "configure"
        | "add" | "enable" | "disable" => VerbCategory::Write,
        "list" | "show" | "get" | "version" => VerbCategory::ReadOnly,
        _ => {
            let _ = args;
            VerbCategory::Unknown
        }
    }
}

fn args_mention_rbac(args: &[String]) -> bool {
    args.iter().any(|a| {
        let lower = a.to_lowercase();
        matches!(
            lower.as_str(),
            "clusterrolebinding"
                | "rolebinding"
                | "clusterrole"
                | "role"
                | "serviceaccount"
                | "secret"
        )
    })
}

fn resolve_leader_and_args(cmd: &str, args: &[String], shell: ShellType) -> (String, Vec<String>) {
    let base = command_basename(cmd, shell);

    if base == "aws-vault" {
        let mut idx = 0;
        if args.first().is_some_and(|a| a == "exec") {
            idx += 1;
        }
        let mut took_profile = false;
        while idx < args.len() {
            let a = &args[idx];
            if a == "--" {
                idx += 1;
                break;
            }
            if !a.starts_with('-') && !took_profile {
                took_profile = true;
                idx += 1;
                continue;
            }
            if a.starts_with('-') {
                idx += 1;
                continue;
            }
            break;
        }
        if idx < args.len() {
            let inner_cmd = args[idx].clone();
            let inner_args = args[idx + 1..].to_vec();
            return (command_basename(&inner_cmd, shell), inner_args);
        }
    }

    if base == "sudo" || base == "doas" {
        let mut idx = 0;
        while idx < args.len() {
            let a = &args[idx];
            if a == "--" {
                idx += 1;
                break;
            }
            if a.starts_with('-') {
                if matches!(a.as_str(), "-u" | "-g" | "-C" | "-h" | "-p" | "-r" | "-t") {
                    idx += 2;
                } else {
                    idx += 1;
                }
                continue;
            }
            break;
        }
        if idx < args.len() {
            let inner_cmd = args[idx].clone();
            let inner_args = args[idx + 1..].to_vec();
            return (command_basename(&inner_cmd, shell), inner_args);
        }
    }

    (base, args.to_vec())
}

fn command_basename(cmd: &str, shell: ShellType) -> String {
    let unq = cmd.trim_matches(|c: char| c == '"' || c == '\'');
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

fn rule_id_human(id: &RuleId) -> &'static str {
    match id {
        RuleId::ContextProdDestructiveCommand => "Destructive",
        RuleId::ContextProdWriteOperation => "Write",
        RuleId::ContextProdCredentialChange => "Credential",
        _ => "Context",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with_label(label_key: &str, criticality: &str) -> Policy {
        let mut p = Policy {
            context_guard_enabled: true,
            ..Policy::default()
        };
        p.context_labels
            .insert(label_key.to_string(), criticality.to_string());
        p
    }

    #[test]
    fn empty_labels_silences_rule() {
        let policy = Policy::default();
        let findings = check(
            "kubectl delete namespace payments",
            ShellType::Posix,
            &policy,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn disabled_guard_silences_rule() {
        let mut policy = policy_with_label("kube:prod", "critical");
        policy.context_guard_enabled = false;
        let findings = check(
            "kubectl delete namespace payments",
            ShellType::Posix,
            &policy,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn classify_kube_destructive() {
        assert_eq!(
            classify_kube("delete", &["namespace".into(), "payments".into()]),
            VerbCategory::Destructive
        );
        assert_eq!(
            classify_kube("uninstall", &["payments".into()]),
            VerbCategory::Destructive
        );
    }

    #[test]
    fn classify_kube_read_only() {
        assert_eq!(
            classify_kube("get", &["pods".into()]),
            VerbCategory::ReadOnly
        );
    }

    #[test]
    fn classify_kube_write() {
        assert_eq!(
            classify_kube("apply", &["-f".into(), "deploy.yaml".into()]),
            VerbCategory::Write
        );
        assert_eq!(
            classify_kube("upgrade", &["payments".into(), "./chart".into()]),
            VerbCategory::Write
        );
    }

    #[test]
    fn classify_kube_create_clusterrolebinding_is_credential() {
        assert_eq!(
            classify_kube("create", &["clusterrolebinding".into(), "admin".into()]),
            VerbCategory::CredentialChange,
        );
    }

    #[test]
    fn classify_aws_s3_rm_destructive() {
        assert_eq!(
            classify_aws("s3", "rm", &["s3://bucket".into(), "--recursive".into()]),
            VerbCategory::Destructive,
        );
    }

    #[test]
    fn classify_aws_s3_ls_read_only() {
        assert_eq!(
            classify_aws("s3", "ls", &["s3://bucket".into()]),
            VerbCategory::ReadOnly,
        );
    }

    #[test]
    fn classify_aws_s3_cp_write() {
        assert_eq!(
            classify_aws("s3", "cp", &["./local".into(), "s3://prod-bucket/".into()]),
            VerbCategory::Write,
        );
    }

    #[test]
    fn classify_aws_iam_create_access_key_credential() {
        assert_eq!(
            classify_aws("iam", "create-access-key", &[]),
            VerbCategory::CredentialChange,
        );
    }

    #[test]
    fn classify_aws_iam_list_read_only() {
        assert_eq!(
            classify_aws("iam", "list-users", &[]),
            VerbCategory::ReadOnly,
        );
    }

    #[test]
    fn classify_gcp_compute_delete() {
        assert_eq!(
            classify_gcp("compute", "instances", "delete", &["prod-frontend".into()]),
            VerbCategory::Destructive,
        );
    }

    #[test]
    fn classify_gcp_iam_service_account_credential() {
        assert_eq!(
            classify_gcp("iam", "service-accounts", "create", &["svc".into()]),
            VerbCategory::CredentialChange,
        );
    }

    #[test]
    fn classify_azure_delete() {
        assert_eq!(
            classify_azure("vm", "delete", "", &["--name".into(), "prod-vm".into()]),
            VerbCategory::Destructive,
        );
    }

    #[test]
    fn classify_azure_ad_sp_delete_credential() {
        assert_eq!(
            classify_azure("ad", "sp", "delete", &["--id".into(), "x".into()]),
            VerbCategory::CredentialChange,
        );
    }

    #[test]
    fn resolve_unwraps_aws_vault_exec() {
        let (leader, args) = resolve_leader_and_args(
            "aws-vault",
            &[
                "exec".into(),
                "prod".into(),
                "--".into(),
                "aws".into(),
                "s3".into(),
                "rm".into(),
                "s3://x".into(),
            ],
            ShellType::Posix,
        );
        assert_eq!(leader, "aws");
        assert_eq!(args, vec!["s3", "rm", "s3://x"]);
    }

    #[test]
    fn resolve_unwraps_sudo() {
        let (leader, args) = resolve_leader_and_args(
            "/usr/bin/sudo",
            &[
                "-u".into(),
                "root".into(),
                "kubectl".into(),
                "delete".into(),
                "ns".into(),
            ],
            ShellType::Posix,
        );
        assert_eq!(leader, "kubectl");
        assert_eq!(args, vec!["delete", "ns"]);
    }

    #[test]
    fn is_critical_label_synonyms() {
        for s in ["critical", "CRITICAL", " prod ", "Production", "p0", "live"] {
            assert!(is_critical_label(s), "{s} should be critical");
        }
        for s in ["dev", "staging", "qa", ""] {
            assert!(!is_critical_label(s), "{s} should NOT be critical");
        }
    }

    #[test]
    fn check_short_circuits_when_no_active_context() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized via TEST_ENV_LOCK.
        unsafe {
            std::env::set_var("TIRITH_CONTEXT_DETECT_DISABLE", "1");
        }
        crate::context_detect::clear_cache_for_tests();
        let policy = policy_with_label("kube:prod-us-east", "critical");
        let findings = check(
            "kubectl delete namespace payments",
            ShellType::Posix,
            &policy,
        );
        assert!(findings.is_empty());
        unsafe {
            std::env::remove_var("TIRITH_CONTEXT_DETECT_DISABLE");
        }
        crate::context_detect::clear_cache_for_tests();
    }
}
