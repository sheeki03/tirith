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
//! false` → operator opt-out. After the gates, the selected provider's fresh
//! detector supplies the active context; only a `critical`/`production`
//! label emits a finding.

use crate::context_detect::{self, Provider, ProviderContext};
use crate::policy::Policy;
use crate::rules::command::{
    resolve_effective_command, EffectiveEnvironment, EffectiveEnvironmentValue,
};
use crate::rules::shared::is_critical_label;
use crate::tokenize::{self, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Run context rules across every executable segment and return the
/// highest-severity context signal.
pub fn check(input: &str, shell: ShellType, policy: &Policy) -> Vec<Finding> {
    if !policy.context_guard_enabled {
        return Vec::new();
    }
    if policy.context_labels.is_empty() {
        return Vec::new();
    }

    let mut findings = tokenize::tokenize(input, shell)
        .iter()
        .filter_map(|seg| check_segment(input, shell, policy, seg))
        .collect::<Vec<_>>();
    findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));
    findings.into_iter().take(1).collect()
}

fn check_segment(
    input: &str,
    shell: ShellType,
    policy: &Policy,
    seg: &tokenize::Segment,
) -> Option<Finding> {
    seg.command.as_deref()?;
    let (leader, args, environment) = match resolve_context_segment_checked(seg, shell) {
        Ok(resolved) => resolved,
        Err(reason) => {
            return segment_mentions_labeled_provider(seg, shell, policy)
                .then(|| analysis_incomplete_finding(input, seg, "wrapper", reason));
        }
    };
    let provider = Provider::from_leader(&leader)?;
    if !policy_has_provider_labels(policy, provider) {
        return None;
    }

    let parsed = match parse_provider_args(provider, &leader, &args) {
        Ok(parsed) => parsed,
        Err(reason) => {
            return Some(analysis_incomplete_finding(
                input,
                seg,
                provider.as_str(),
                reason,
            ));
        }
    };

    if context_mutating_command(provider, &parsed.positional) {
        // The command is analyzed before it changes provider configuration.
        // Evict the process cache now so the next command cannot reuse the old
        // context during its five-second TTL.
        context_detect::invalidate_cache();
        return None;
    }

    let custom_destructive = policy
        .context_destructive_verbs
        .get(provider.as_str())
        .cloned()
        .unwrap_or_default();
    let category = classify_positionals(provider, &parsed.positional, &custom_destructive);
    if category == VerbCategory::ReadOnly {
        return None;
    }

    let (active, criticality) =
        match resolve_labeled_context(provider, &parsed, &environment, policy) {
            Ok(Some(labeled)) => labeled,
            Ok(None) => return None,
            Err(reason) => {
                return Some(analysis_incomplete_finding(
                    input,
                    seg,
                    provider.as_str(),
                    &reason,
                ));
            }
        };

    let (rule_id, severity) = match category {
        VerbCategory::Destructive => (RuleId::ContextProdDestructiveCommand, Severity::High),
        VerbCategory::CredentialChange => (RuleId::ContextProdCredentialChange, Severity::High),
        VerbCategory::Write => (RuleId::ContextProdWriteOperation, Severity::Medium),
        VerbCategory::Unknown => {
            return Some(analysis_incomplete_finding(
                input,
                seg,
                provider.as_str(),
                "command verb could not be classified safely for a critical context",
            ));
        }
        VerbCategory::ReadOnly => return None,
    };

    Some(Finding {
        rule_id,
        severity,
        title: format!(
            "{} command against labeled-{} context '{}'",
            rule_id_human(&rule_id),
            criticality.to_lowercase(),
            active.context,
        ),
        description: format!(
            "Effective {} context '{}' is labeled '{}' in tirith's context-labels file; \
             the command's verb is {}. Confirm with `tirith context status` and re-run \
             with explicit acknowledgement if intentional.",
            provider.as_str(),
            active.context,
            criticality,
            category.as_str(),
        ),
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
                matched: seg.raw.chars().take(200).collect(),
            },
        ],
        human_view: Some(format!(
            "About to run a {} command against '{}' (labeled {}).",
            category.as_str(),
            active.context,
            criticality.to_lowercase(),
        )),
        agent_view: Some(format!(
            "tirith refused: effective {} context '{}' is operator-labeled \
             {}. The command's verb falls in the {} category for this provider.",
            provider.as_str(),
            active.context,
            criticality,
            category.as_str(),
        )),
        mitre_id: None,
        custom_rule_id: None,
    })
}

fn analysis_incomplete_finding(
    _input: &str,
    seg: &tokenize::Segment,
    provider: &str,
    reason: &str,
) -> Finding {
    Finding {
        rule_id: RuleId::AnalysisIncomplete,
        severity: Severity::High,
        title: format!("{provider} context guard could not classify command safely"),
        description: format!(
            "The operational-context guard is enabled, but analysis was incomplete: {reason}. \
             The command is blocked because allowing it could bypass a critical-context label."
        ),
        evidence: vec![Evidence::CommandPattern {
            pattern: format!("{provider} <analysis-incomplete>"),
            matched: seg.raw.chars().take(200).collect(),
        }],
        human_view: Some("Context guard could not prove this command safe.".to_string()),
        agent_view: Some(format!(
            "tirith refused: context analysis incomplete ({reason})."
        )),
        mitre_id: None,
        custom_rule_id: None,
    }
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
    let mut best: Option<VerbCategory> = None;
    for seg in &segments {
        let Some(cmd) = seg.command.as_deref() else {
            continue;
        };
        let category = match resolve_leader_and_args_checked(cmd, &seg.args, shell) {
            Ok((leader, args)) => classify_remote_segment(&leader, &args),
            Err(_) => VerbCategory::Unknown,
        };
        if best.is_none_or(|current| category_rank(category) > category_rank(current)) {
            best = Some(category);
        }
    }
    best.unwrap_or(VerbCategory::Unknown)
}

fn classify_remote_segment(leader: &str, args: &[String]) -> VerbCategory {
    if let Some(provider) = Provider::from_leader(leader) {
        return parse_provider_args(provider, leader, args)
            .map(|parsed| classify_positionals(provider, &parsed.positional, &[]))
            .unwrap_or(VerbCategory::Unknown);
    }

    let positional = args
        .iter()
        .map(|arg| strip_outer_quotes(arg))
        .filter(|arg| !arg.starts_with('-') && !tokenize::is_env_assignment(arg))
        .collect::<Vec<_>>();
    let first = positional.first().copied().unwrap_or("");
    match leader.to_lowercase().as_str() {
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
        | "top" | "df" | "du" | "uname" | "hostname" | "whoami" | "id" | "uptime" | "true" => {
            VerbCategory::ReadOnly
        }
        _ => VerbCategory::Unknown,
    }
}

fn category_rank(category: VerbCategory) -> u8 {
    match category {
        VerbCategory::Destructive => 5,
        VerbCategory::CredentialChange => 4,
        VerbCategory::Write => 3,
        VerbCategory::Unknown => 2,
        VerbCategory::ReadOnly => 1,
    }
}

#[derive(Debug, Default)]
struct ParsedProviderArgs {
    positional: Vec<String>,
    explicit_contexts: Vec<String>,
    kubeconfig: Option<String>,
    gcp_account: Option<String>,
    gcp_project: Option<String>,
    gcp_configuration: Option<String>,
    has_explicit_selector: bool,
}

fn parse_provider_args(
    provider: Provider,
    leader: &str,
    args: &[String],
) -> Result<ParsedProviderArgs, &'static str> {
    let mut parsed = ParsedProviderArgs::default();
    let required = required_positionals(provider);
    let mut idx = 0;
    while idx < args.len() {
        let arg = strip_outer_quotes(&args[idx]);
        if arg == "--" {
            parsed.positional.extend(
                args[idx + 1..]
                    .iter()
                    .map(|value| strip_outer_quotes(value).to_string()),
            );
            break;
        }
        if arg.starts_with("--") {
            let (name, inline_value) = arg
                .split_once('=')
                .map(|(name, value)| (name, Some(value)))
                .unwrap_or((arg, None));
            match provider_long_option_takes_value(provider, leader, name) {
                Some(true) => {
                    let value = if let Some(value) = inline_value {
                        value
                    } else {
                        idx += 1;
                        strip_outer_quotes(
                            args.get(idx)
                                .ok_or("provider option is missing its value")?,
                        )
                    };
                    if value.is_empty() {
                        return Err("provider selector has an empty value");
                    }
                    record_provider_selector(provider, leader, name, value, &mut parsed);
                    idx += 1;
                    continue;
                }
                Some(false) => {
                    idx += 1;
                    continue;
                }
                None if parsed.positional.len() < required => {
                    return Err(
                        "unknown provider option before command verb has ambiguous value grammar",
                    );
                }
                None => {
                    idx += 1;
                    continue;
                }
            }
        }
        if arg.starts_with('-') && arg != "-" {
            let exact = provider_short_option_takes_value(provider, arg);
            if let Some(takes_value) = exact {
                if takes_value {
                    idx += 1;
                    let value = strip_outer_quotes(
                        args.get(idx)
                            .ok_or("provider short option is missing its value")?,
                    );
                    record_provider_selector(provider, leader, arg, value, &mut parsed);
                }
                idx += 1;
                continue;
            }
            if let Some((name, value)) = attached_provider_short_option(provider, arg) {
                record_provider_selector(provider, leader, name, value, &mut parsed);
                idx += 1;
                continue;
            }
            if parsed.positional.len() < required {
                return Err(
                    "unknown provider short option before command verb has ambiguous value grammar",
                );
            }
            idx += 1;
            continue;
        }
        parsed.positional.push(arg.to_string());
        idx += 1;
    }
    Ok(parsed)
}

fn required_positionals(provider: Provider) -> usize {
    match provider {
        Provider::Kube => 1,
        Provider::Aws => 2,
        Provider::Gcp => 3,
        Provider::Azure => 2,
    }
}

fn provider_long_option_takes_value(provider: Provider, leader: &str, name: &str) -> Option<bool> {
    let value = match provider {
        Provider::Kube => matches!(
            name,
            "--as"
                | "--as-group"
                | "--as-uid"
                | "--cache-dir"
                | "--certificate-authority"
                | "--client-certificate"
                | "--client-key"
                | "--cluster"
                | "--context"
                | "--kube-apiserver"
                | "--kube-as-group"
                | "--kube-as-user"
                | "--kube-ca-file"
                | "--kube-context"
                | "--kube-token"
                | "--kubeconfig"
                | "--namespace"
                | "--password"
                | "--profile"
                | "--profile-output"
                | "--request-timeout"
                | "--server"
                | "--tls-server-name"
                | "--token"
                | "--user"
                | "--username"
                | "--v"
                | "--vmodule"
                | "--registry-config"
                | "--repository-cache"
                | "--repository-config"
        ),
        Provider::Aws => matches!(
            name,
            "--ca-bundle"
                | "--cli-binary-format"
                | "--cli-connect-timeout"
                | "--cli-read-timeout"
                | "--color"
                | "--endpoint-url"
                | "--output"
                | "--profile"
                | "--query"
                | "--region"
        ),
        Provider::Gcp => matches!(
            name,
            "--account"
                | "--billing-project"
                | "--configuration"
                | "--flags-file"
                | "--flatten"
                | "--format"
                | "--impersonate-service-account"
                | "--project"
                | "--trace-token"
                | "--verbosity"
        ),
        Provider::Azure => matches!(name, "--output" | "--query" | "--subscription"),
    };
    if value {
        return Some(true);
    }
    let boolean = match provider {
        Provider::Kube => {
            matches!(
                name,
                "--disable-compression"
                    | "--help"
                    | "--insecure-skip-tls-verify"
                    | "--kube-insecure-skip-tls-verify"
                    | "--match-server-version"
                    | "--warnings-as-errors"
            ) || (leader == "argocd" && matches!(name, "--grpc-web" | "--plaintext"))
        }
        Provider::Aws => matches!(
            name,
            "--cli-auto-prompt"
                | "--debug"
                | "--no-cli-auto-prompt"
                | "--no-debug"
                | "--no-paginate"
                | "--no-sign-request"
                | "--no-verify-ssl"
        ),
        Provider::Gcp => matches!(
            name,
            "--help"
                | "--log-http"
                | "--quiet"
                | "--user-output-enabled"
                | "--no-user-output-enabled"
        ),
        Provider::Azure => matches!(
            name,
            "--debug" | "--help" | "--only-show-errors" | "--verbose"
        ),
    };
    boolean.then_some(false)
}

fn provider_short_option_takes_value(provider: Provider, option: &str) -> Option<bool> {
    match provider {
        Provider::Kube => match option {
            "-n" | "-s" | "-v" => Some(true),
            "-h" => Some(false),
            _ => None,
        },
        Provider::Aws => None,
        Provider::Gcp => match option {
            "-q" => Some(false),
            _ => None,
        },
        Provider::Azure => match option {
            "-o" => Some(true),
            "-h" => Some(false),
            _ => None,
        },
    }
}

fn attached_provider_short_option(
    provider: Provider,
    option: &str,
) -> Option<(&'static str, &str)> {
    let candidates: &'static [&'static str] = match provider {
        Provider::Kube => &["-n", "-s", "-v"],
        Provider::Azure => &["-o"],
        Provider::Aws | Provider::Gcp => &[],
    };
    candidates.iter().find_map(|name| {
        option.strip_prefix(name).and_then(|value| {
            let value = value.strip_prefix('=').unwrap_or(value);
            (!value.is_empty()).then_some((*name, value))
        })
    })
}

fn record_provider_selector(
    provider: Provider,
    leader: &str,
    name: &str,
    value: &str,
    parsed: &mut ParsedProviderArgs,
) {
    match provider {
        Provider::Kube => match name {
            "--context" | "--kube-context" => {
                parsed.has_explicit_selector = true;
                parsed.explicit_contexts.push(value.to_string());
            }
            "--kubeconfig" => {
                parsed.has_explicit_selector = true;
                parsed.kubeconfig = Some(value.to_string());
            }
            "--server" if leader == "argocd" => {
                parsed.has_explicit_selector = true;
                parsed.explicit_contexts.push(value.to_string());
            }
            _ => {}
        },
        Provider::Aws if name == "--profile" => {
            parsed.has_explicit_selector = true;
            parsed.explicit_contexts.push(value.to_string());
        }
        Provider::Gcp => match name {
            "--account" => {
                parsed.has_explicit_selector = true;
                parsed.gcp_account = Some(value.to_string());
            }
            "--project" => {
                parsed.has_explicit_selector = true;
                parsed.gcp_project = Some(value.to_string());
            }
            "--configuration" => {
                parsed.has_explicit_selector = true;
                parsed.gcp_configuration = Some(value.to_string());
            }
            _ => {}
        },
        Provider::Azure if name == "--subscription" => {
            parsed.has_explicit_selector = true;
            parsed.explicit_contexts.push(value.to_string());
        }
        _ => {}
    }
}

fn policy_has_provider_labels(policy: &Policy, provider: Provider) -> bool {
    let prefix = format!("{}:", provider.as_str());
    policy
        .context_labels
        .keys()
        .any(|key| key.starts_with(&prefix))
}

fn resolve_labeled_context(
    provider: Provider,
    parsed: &ParsedProviderArgs,
    environment: &EffectiveEnvironment,
    policy: &Policy,
) -> Result<Option<(ProviderContext, String)>, String> {
    if let Some(contexts) = explicit_context_candidates(provider, parsed)? {
        if let Some(labeled) = first_labeled_context(provider, contexts, policy) {
            return Ok(Some(labeled));
        }
        // An explicit selector is authoritative. Never fall back to the current
        // default and accidentally approve/deny against a different target.
        return Ok(None);
    }

    if let Some(contexts) = environment_context_candidates(provider, environment)? {
        if let Some(labeled) = first_labeled_context(provider, contexts, policy) {
            return Ok(Some(labeled));
        }
        // Command-scoped environment is authoritative even when it selects an
        // unlabeled/dev context. Never consult this process's ambient context.
        return Ok(None);
    }

    if crate::context_detect::context_detect_disabled() {
        return Err(format!(
            "fresh {} context detection is disabled",
            provider.as_str()
        ));
    }
    let active = context_detect::detect_single(provider).map_err(|failure| {
        format!(
            "fresh {} context detection failed: {failure}",
            provider.as_str()
        )
    })?;
    let Some(label) = policy.context_labels.get(&active.label_key()) else {
        return Ok(None);
    };
    if !is_critical_label(label) {
        return Ok(None);
    }
    Ok(Some((active, label.clone())))
}

fn first_labeled_context(
    provider: Provider,
    contexts: Vec<String>,
    policy: &Policy,
) -> Option<(ProviderContext, String)> {
    for context in contexts {
        let active = ProviderContext { provider, context };
        if let Some(label) = policy.context_labels.get(&active.label_key()) {
            if is_critical_label(label) {
                return Some((active, label.clone()));
            }
        }
    }
    None
}

fn environment_context_candidates(
    provider: Provider,
    environment: &EffectiveEnvironment,
) -> Result<Option<Vec<String>>, String> {
    let relevant: &[&str] = match provider {
        Provider::Aws => &["AWS_PROFILE", "AWS_DEFAULT_PROFILE"],
        Provider::Kube => &["KUBECONFIG"],
        Provider::Gcp => &[
            "CLOUDSDK_ACTIVE_CONFIG_NAME",
            "CLOUDSDK_CORE_ACCOUNT",
            "CLOUDSDK_CORE_PROJECT",
        ],
        Provider::Azure => &["AZURE_CONFIG_DIR"],
    };
    let mutated = environment.clear_ambient
        || relevant
            .iter()
            .any(|name| environment.values.contains_key(*name));
    if !mutated {
        return Ok(None);
    }
    for name in relevant {
        if matches!(
            environment.values.get(*name),
            Some(EffectiveEnvironmentValue::Unresolved)
        ) {
            return Err(format!(
                "command-scoped {name} contains an unresolved shell expansion"
            ));
        }
    }

    let set = |name: &str| match environment.values.get(name) {
        Some(EffectiveEnvironmentValue::Set(value)) if !value.trim().is_empty() => {
            Some(value.trim().to_string())
        }
        _ => None,
    };
    let mut contexts = Vec::new();
    match provider {
        Provider::Aws => {
            if let Some(profile) = set("AWS_PROFILE").or_else(|| set("AWS_DEFAULT_PROFILE")) {
                contexts.push(profile);
            }
        }
        Provider::Kube => {
            if let Some(paths) = set("KUBECONFIG") {
                contexts.push(read_kubeconfig_path_list_context(&paths)?);
            }
        }
        Provider::Gcp => {
            if let Some(configuration) = set("CLOUDSDK_ACTIVE_CONFIG_NAME") {
                contexts.push(configuration);
            }
            let account = set("CLOUDSDK_CORE_ACCOUNT");
            let project = set("CLOUDSDK_CORE_PROJECT");
            match (account, project) {
                (Some(account), Some(project)) => {
                    contexts.push(format!("{account}@{project}"));
                    contexts.push(project);
                }
                (Some(account), None) => contexts.push(account),
                (None, Some(project)) => contexts.push(project),
                (None, None) => {}
            }
        }
        Provider::Azure => {
            return Err(
                "command-scoped AZURE_CONFIG_DIR changes Azure context but cannot be resolved safely"
                    .to_string(),
            );
        }
    }
    contexts.sort();
    contexts.dedup();
    if contexts.is_empty() {
        Err(format!(
            "command-scoped environment clears or unsets the active {} context",
            provider.as_str()
        ))
    } else {
        Ok(Some(contexts))
    }
}

fn explicit_context_candidates(
    provider: Provider,
    parsed: &ParsedProviderArgs,
) -> Result<Option<Vec<String>>, String> {
    let mut contexts = parsed.explicit_contexts.clone();
    if provider == Provider::Kube && contexts.is_empty() {
        if let Some(path) = parsed.kubeconfig.as_deref() {
            contexts.push(read_kubeconfig_context(path)?);
        }
    }
    if provider == Provider::Gcp {
        let account = parsed.gcp_account.clone();
        let project = parsed.gcp_project.clone();
        let configuration = parsed.gcp_configuration.clone();
        if let Some(configuration) = configuration {
            contexts.push(configuration);
        }
        match (account, project) {
            (Some(account), Some(project)) => {
                contexts.push(format!("{account}@{project}"));
                contexts.push(project);
            }
            (Some(account), None) => contexts.push(account),
            (None, Some(project)) => contexts.push(project),
            (None, None) => {}
        }
    }
    contexts.sort();
    contexts.dedup();
    if parsed.has_explicit_selector || !contexts.is_empty() {
        Ok(Some(contexts))
    } else {
        Ok(None)
    }
}

fn read_kubeconfig_path_list_context(raw_paths: &str) -> Result<String, String> {
    let paths = std::env::split_paths(raw_paths).collect::<Vec<_>>();
    if paths.is_empty() {
        return Err("KUBECONFIG does not contain a usable path".to_string());
    }
    let mut failures = Vec::new();
    for path in paths {
        let path = path.to_string_lossy();
        match read_kubeconfig_context(&path) {
            Ok(context) => return Ok(context),
            Err(error) => failures.push(error),
        }
    }
    Err(format!(
        "no KUBECONFIG entry exposed a current-context: {}",
        failures.join("; ")
    ))
}

fn read_kubeconfig_context(raw_path: &str) -> Result<String, String> {
    let path = if let Some(tail) = raw_path.strip_prefix("~/") {
        home::home_dir()
            .ok_or_else(|| "cannot resolve home directory for --kubeconfig".to_string())?
            .join(tail)
    } else if raw_path == "~" {
        home::home_dir()
            .ok_or_else(|| "cannot resolve home directory for --kubeconfig".to_string())?
    } else {
        std::path::PathBuf::from(raw_path)
    };
    if raw_path.contains('$') {
        return Err("--kubeconfig contains an unresolved environment expansion".to_string());
    }
    let metadata = std::fs::metadata(&path).map_err(|error| {
        format!(
            "cannot stat explicit kubeconfig {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_file() || metadata.len() > 4 * 1024 * 1024 {
        return Err("explicit kubeconfig is not a regular file within the size limit".to_string());
    }
    let content = std::fs::read_to_string(&path).map_err(|error| {
        format!(
            "cannot read explicit kubeconfig {}: {error}",
            path.display()
        )
    })?;
    let value: serde_yaml::Value = serde_yaml::from_str(&content)
        .map_err(|error| format!("cannot parse explicit kubeconfig: {error}"))?;
    value
        .get("current-context")
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .filter(|context| !context.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "explicit kubeconfig has no current-context".to_string())
}

fn context_mutating_command(provider: Provider, positional: &[String]) -> bool {
    let first = positional.first().map(String::as_str).unwrap_or("");
    let second = positional.get(1).map(String::as_str).unwrap_or("");
    let third = positional.get(2).map(String::as_str).unwrap_or("");
    match provider {
        Provider::Kube => {
            first == "config"
                && matches!(
                    second,
                    "use-context" | "set-context" | "delete-context" | "rename-context"
                )
        }
        Provider::Aws => first == "configure" && matches!(second, "set" | "unset"),
        Provider::Gcp => {
            (first == "config" && matches!(second, "set" | "unset"))
                || (first == "config" && second == "configurations" && third == "activate")
        }
        Provider::Azure => first == "account" && second == "set",
    }
}

fn segment_mentions_labeled_provider(
    seg: &tokenize::Segment,
    shell: ShellType,
    policy: &Policy,
) -> bool {
    seg.command
        .as_deref()
        .and_then(|command| Provider::from_leader(&command_basename(command, shell)))
        .is_some_and(|provider| policy_has_provider_labels(policy, provider))
        || seg.args.iter().any(|arg| {
            Provider::from_leader(&command_basename(arg, shell))
                .is_some_and(|provider| policy_has_provider_labels(policy, provider))
        })
}

fn classify_positionals(
    provider: Provider,
    positional: &[String],
    custom_destructive: &[String],
) -> VerbCategory {
    let first = positional.first().map(String::as_str).unwrap_or("");
    let second = positional.get(1).map(String::as_str).unwrap_or("");
    let third = positional.get(2).map(String::as_str).unwrap_or("");

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
        Provider::Kube => classify_kube(first, positional),
        Provider::Aws => classify_aws(first, second, positional),
        Provider::Gcp => classify_gcp(first, second, third, positional),
        Provider::Azure => classify_azure(first, second, third, positional),
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
    // A command-specific option that appears after the provider's verb can be
    // unknown to the global-option parser. Its value must not displace an
    // already parsed verb (for example `compute instances delete --name vm`).
    let verb = joined
        .iter()
        .rev()
        .find(|candidate| {
            matches!(
                candidate.as_str(),
                "delete"
                    | "destroy"
                    | "remove"
                    | "purge"
                    | "create"
                    | "update"
                    | "apply"
                    | "patch"
                    | "set"
                    | "start"
                    | "stop"
                    | "restart"
                    | "deploy"
                    | "import"
                    | "add"
                    | "enable"
                    | "disable"
                    | "list"
                    | "describe"
                    | "get"
                    | "version"
                    | "config"
                    | "get-iam-policy"
            ) || candidate.starts_with("describe")
        })
        .cloned()
        .or_else(|| joined.last().cloned())
        .unwrap_or_default();
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
    let verb = joined
        .iter()
        .rev()
        .find(|candidate| {
            matches!(
                candidate.as_str(),
                "delete"
                    | "purge"
                    | "remove"
                    | "create"
                    | "update"
                    | "set"
                    | "start"
                    | "stop"
                    | "restart"
                    | "deploy"
                    | "configure"
                    | "add"
                    | "enable"
                    | "disable"
                    | "list"
                    | "show"
                    | "get"
                    | "version"
            )
        })
        .cloned()
        .or_else(|| joined.last().cloned())
        .unwrap_or_default();
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

fn resolve_leader_and_args_checked(
    cmd: &str,
    args: &[String],
    shell: ShellType,
) -> Result<(String, Vec<String>), &'static str> {
    let synthetic = tokenize::Segment {
        raw: std::iter::once(cmd)
            .chain(args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" "),
        command: Some(cmd.to_string()),
        args: args.to_vec(),
        preceding_separator: None,
        byte_range: 0..0,
    };
    resolve_context_segment_checked(&synthetic, shell).map(|(leader, args, _)| (leader, args))
}

fn merge_effective_environment(accumulated: &mut EffectiveEnvironment, next: EffectiveEnvironment) {
    if next.clear_ambient {
        accumulated.clear_ambient = true;
        accumulated.values.clear();
    }
    accumulated.values.extend(next.values);
}

fn resolve_context_segment_checked(
    seg: &tokenize::Segment,
    shell: ShellType,
) -> Result<(String, Vec<String>, EffectiveEnvironment), &'static str> {
    let mut current = seg.clone();
    let mut aws_vault_profile: Option<String> = None;
    let mut environment = EffectiveEnvironment::default();

    for _ in 0..32 {
        let effective = resolve_effective_command(&current, shell)
            .map_err(|_| "supported command wrapper could not be resolved")?;
        merge_effective_environment(&mut environment, effective.environment);
        let leader = effective
            .segment
            .command
            .as_deref()
            .map(|command| command_basename(command, shell))
            .ok_or("supported command wrapper could not be resolved")?;
        let resolved_args = effective.segment.args;
        if leader != "aws-vault" {
            let mut resolved_args = resolved_args;
            if leader == "aws"
                && !args_have_aws_profile(&resolved_args)
                && aws_vault_profile.is_some()
            {
                let profile = aws_vault_profile.take().expect("checked is_some");
                resolved_args.splice(0..0, ["--profile".to_string(), profile]);
            }
            return Ok((leader, resolved_args, environment));
        }
        let (profile, next_command, next_args) = unwrap_aws_vault(&resolved_args)?;
        aws_vault_profile = Some(profile);
        current = tokenize::Segment {
            raw: std::iter::once(next_command.as_str())
                .chain(next_args.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" "),
            command: Some(next_command),
            args: next_args,
            preceding_separator: None,
            byte_range: 0..0,
        };
    }
    Err("command wrapper chain exceeded the analysis depth limit")
}

fn args_have_aws_profile(args: &[String]) -> bool {
    args.iter().any(|arg| {
        let arg = strip_outer_quotes(arg);
        arg == "--profile" || arg.starts_with("--profile=")
    })
}

fn unwrap_aws_vault(args: &[String]) -> Result<(String, String, Vec<String>), &'static str> {
    let mut idx = 0;
    while idx < args.len() && strip_outer_quotes(&args[idx]).starts_with('-') {
        let option = strip_outer_quotes(&args[idx]);
        if matches!(option, "--backend" | "--prompt") {
            args.get(idx + 1)
                .ok_or("aws-vault global option is missing its value")?;
            idx += 2;
        } else if option.contains('=') || matches!(option, "--debug" | "--version") {
            idx += 1;
        } else {
            return Err("unknown aws-vault global option has ambiguous value grammar");
        }
    }
    if strip_outer_quotes(args.get(idx).ok_or("aws-vault subcommand is missing")?) != "exec" {
        return Err("aws-vault invocation is not an analyzable exec command");
    }
    idx += 1;

    while idx < args.len() && strip_outer_quotes(&args[idx]).starts_with('-') {
        let option = strip_outer_quotes(&args[idx]);
        if matches!(
            option,
            "--assume-role-ttl"
                | "--duration"
                | "--mfa-token"
                | "--prompt"
                | "--server"
                | "--session-ttl"
        ) {
            args.get(idx + 1)
                .ok_or("aws-vault exec option is missing its value")?;
            idx += 2;
        } else if option.contains('=')
            || matches!(option, "--ec2-server" | "--env" | "--json" | "--no-session")
        {
            idx += 1;
        } else {
            return Err("unknown aws-vault exec option has ambiguous value grammar");
        }
    }
    let profile = strip_outer_quotes(args.get(idx).ok_or("aws-vault profile is missing")?);
    if profile.is_empty() {
        return Err("aws-vault profile is empty");
    }
    idx += 1;
    if args
        .get(idx)
        .is_some_and(|arg| strip_outer_quotes(arg) == "--")
    {
        idx += 1;
    }
    let command = args
        .get(idx)
        .ok_or("aws-vault exec without an inner command cannot be classified")?
        .clone();
    Ok((profile.to_string(), command, args[idx + 1..].to_vec()))
}

fn strip_outer_quotes(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"'))
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
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

    struct DisabledContextDetection {
        _global: tirith_test_support::GlobalStateGuard,
    }

    impl DisabledContextDetection {
        fn new() -> Self {
            let mut global = tirith_test_support::GlobalStateGuard::new()
                .expect("isolate process-global context-rule state");
            global.set_env("TIRITH_CONTEXT_DETECT_DISABLE", "1");
            global.after_restore(crate::context_detect::invalidate_cache);
            crate::context_detect::invalidate_cache();
            Self { _global: global }
        }
    }

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
        let (leader, args) = resolve_leader_and_args_checked(
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
        )
        .expect("resolve aws-vault");
        assert_eq!(leader, "aws");
        assert_eq!(args, vec!["--profile", "prod", "s3", "rm", "s3://x"]);
    }

    #[test]
    fn resolve_unwraps_sudo() {
        let (leader, args) = resolve_leader_and_args_checked(
            "/usr/bin/sudo",
            &[
                "-u".into(),
                "root".into(),
                "kubectl".into(),
                "delete".into(),
                "ns".into(),
            ],
            ShellType::Posix,
        )
        .expect("resolve sudo");
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
    fn context_detection_failure_blocks_when_guard_has_provider_labels() {
        let _disabled = DisabledContextDetection::new();
        let policy = policy_with_label("kube:prod-us-east", "critical");
        let findings = check(
            "kubectl delete namespace payments",
            ShellType::Posix,
            &policy,
        );
        assert!(findings.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete && finding.severity == Severity::High
        }));
    }

    #[test]
    fn provider_option_values_do_not_become_verbs() {
        let kube = parse_provider_args(
            Provider::Kube,
            "kubectl",
            &[
                "--namespace".into(),
                "prod".into(),
                "delete".into(),
                "pod".into(),
            ],
        )
        .expect("parse kubectl");
        assert_eq!(kube.positional, vec!["delete", "pod"]);

        let aws = parse_provider_args(
            Provider::Aws,
            "aws",
            &["--profile".into(), "prod".into(), "s3".into(), "rm".into()],
        )
        .expect("parse aws");
        assert_eq!(aws.positional, vec!["s3", "rm"]);
        assert_eq!(aws.explicit_contexts, vec!["prod"]);
    }

    #[test]
    fn explicit_provider_targets_override_default_detection() {
        for (command, key, rule) in [
            (
                "kubectl --context prod delete namespace payments",
                "kube:prod",
                RuleId::ContextProdDestructiveCommand,
            ),
            (
                "aws --profile prod s3 rm s3://bucket --recursive",
                "aws:prod",
                RuleId::ContextProdDestructiveCommand,
            ),
            (
                "gcloud --project prod-project compute instances delete api",
                "gcp:prod-project",
                RuleId::ContextProdDestructiveCommand,
            ),
            (
                "az --subscription prod-sub vm delete --name api",
                "azure:prod-sub",
                RuleId::ContextProdDestructiveCommand,
            ),
        ] {
            let policy = policy_with_label(key, "critical");
            let findings = check(command, ShellType::Posix, &policy);
            assert!(
                findings.iter().any(|finding| finding.rule_id == rule),
                "explicit target escaped critical label for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn command_scoped_aws_profile_overrides_are_authoritative() {
        let policy = policy_with_label("aws:prod", "critical");
        for command in [
            "AWS_PROFILE=prod aws s3 rm s3://bucket --recursive",
            "env AWS_PROFILE=prod aws s3 rm s3://bucket --recursive",
            "env -- AWS_PROFILE=prod aws s3 rm s3://bucket --recursive",
            "env -S 'AWS_PROFILE=prod aws s3 rm s3://bucket --recursive'",
            "env -i AWS_PROFILE=prod aws s3 rm s3://bucket --recursive",
        ] {
            let findings = check(command, ShellType::Posix, &policy);
            assert!(
                findings
                    .iter()
                    .any(|finding| { finding.rule_id == RuleId::ContextProdDestructiveCommand }),
                "command-scoped AWS profile escaped for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn command_scoped_kubeconfig_and_gcloud_configuration_are_authoritative() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config");
        std::fs::write(&path, "apiVersion: v1\ncurrent-context: prod-from-env\n")
            .expect("write kubeconfig");
        let kube = policy_with_label("kube:prod-from-env", "critical");
        // The command is parsed as a POSIX shell string, where a backslash
        // escapes the next character — embedding a Windows `C:\...` path would
        // dissolve its separators and leave an unreadable KUBECONFIG. Windows
        // accepts forward slashes in filesystem paths, so this spelling names
        // the same file on every host while staying POSIX-quotable.
        let kube_command = format!(
            "env KUBECONFIG={} kubectl delete namespace payments",
            path.display().to_string().replace('\\', "/")
        );
        let findings = check(&kube_command, ShellType::Posix, &kube);
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::ContextProdDestructiveCommand));

        let gcp = policy_with_label("gcp:prod-config", "critical");
        let findings = check(
            "CLOUDSDK_ACTIVE_CONFIG_NAME=prod-config gcloud compute instances delete api",
            ShellType::Posix,
            &gcp,
        );
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::ContextProdDestructiveCommand));
    }

    #[test]
    fn unresolved_or_removed_command_context_fails_closed() {
        let policy = policy_with_label("aws:prod", "critical");
        for command in [
            "AWS_PROFILE=$TARGET aws s3 rm s3://bucket --recursive",
            "env -u AWS_PROFILE aws s3 rm s3://bucket --recursive",
            "env -i aws s3 rm s3://bucket --recursive",
        ] {
            let findings = check(command, ShellType::Posix, &policy);
            assert!(
                findings.iter().any(|finding| {
                    finding.rule_id == RuleId::AnalysisIncomplete
                        && finding.severity == Severity::High
                }),
                "unresolved command context did not fail closed for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn later_shell_segment_is_checked() {
        let policy = policy_with_label("kube:prod", "critical");
        let findings = check(
            "echo ok; kubectl --context prod delete namespace payments",
            ShellType::Posix,
            &policy,
        );
        assert!(findings
            .iter()
            .any(|finding| { finding.rule_id == RuleId::ContextProdDestructiveCommand }));
    }

    #[test]
    fn ambiguous_provider_option_fails_closed() {
        let policy = policy_with_label("kube:prod", "critical");
        let findings = check(
            "kubectl --future-option prod delete namespace payments",
            ShellType::Posix,
            &policy,
        );
        assert!(findings.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete && finding.severity == Severity::High
        }));
    }

    #[test]
    fn explicit_kubeconfig_current_context_is_honored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config");
        std::fs::write(&path, "apiVersion: v1\ncurrent-context: prod-from-file\n")
            .expect("write kubeconfig");
        let policy = policy_with_label("kube:prod-from-file", "critical");
        let command = format!(
            "kubectl --kubeconfig {} delete namespace payments",
            path.display()
        );
        let findings = check(&command, ShellType::Posix, &policy);
        assert!(findings
            .iter()
            .any(|finding| { finding.rule_id == RuleId::ContextProdDestructiveCommand }));
    }

    #[test]
    fn ssh_inner_classifier_aggregates_every_remote_segment() {
        assert_eq!(
            classify_inner_command_for_ssh("true; systemctl restart payments", ShellType::Posix),
            VerbCategory::Destructive
        );
    }

    #[test]
    fn context_mutators_are_recognized_for_cache_invalidation() {
        assert!(context_mutating_command(
            Provider::Kube,
            &["config".into(), "use-context".into(), "prod".into()]
        ));
        assert!(context_mutating_command(
            Provider::Azure,
            &["account".into(), "set".into(), "--subscription".into()]
        ));
    }
}
