//! IaC operational-context rules (M8 ch3).
//!
//! Fire when the parsed command leader is an IaC CLI (`terraform`, `pulumi`,
//! `tofu`). Tier-1 gate: PATTERN_TABLE entry `iac_cmd`. The rules are:
//!
//! 1. `IacApplyWithoutPlan` (High, gated by `iac_require_plan_before_apply`) —
//!    apply with no plan-file positional.
//! 2. `IacApplyAutoApprove` (Medium) — apply with auto-approve outside a
//!    production-labeled context.
//! 3. `IacApplyAutoApproveProd` (High) — #2 against a critical/prod context.
//! 4. `IacDestroyProd` (High) — destroy against a labeled-prod context.
//! 5. `IacPlanHashMismatch` (High, gated by `iac_require_plan_before_apply`) —
//!    apply against a plan file whose SHA-256 is not recorded in
//!    `state_dir()/iac_plans/`.
//!
//! `IacPlanHighRiskChanges` is emitted by the `iac check-plan` CLI path, not
//! here (see `iac_plan.rs`).
//!
//! Detection short-circuits when the leader is not an IaC CLI. The prod-context
//! rules additionally require `context_guard_enabled` + an operator-labeled
//! context (`policy.context_labels`).

use std::path::PathBuf;

use crate::context_detect::{self, Provider};
use crate::iac_plan;
use crate::policy::Policy;
use crate::rules::shared::is_critical_label;
use crate::tokenize::{self, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// IaC tool detected from the parsed command leader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IacTool {
    Terraform,
    Pulumi,
    Tofu,
}

impl IacTool {
    fn as_str(self) -> &'static str {
        match self {
            Self::Terraform => "terraform",
            Self::Pulumi => "pulumi",
            Self::Tofu => "tofu",
        }
    }
}

/// Run the IaC rules over the parsed command (the prod-context rule and the
/// apply-gate rule can both fire on the same input).
pub fn check(input: &str, shell: ShellType, policy: &Policy) -> Vec<Finding> {
    let segments = tokenize::tokenize(input, shell);
    let Some(seg) = segments.first() else {
        return Vec::new();
    };
    let Some(cmd) = seg.command.as_deref() else {
        return Vec::new();
    };
    let leader = command_basename(cmd, shell);

    let tool = match leader.as_str() {
        "terraform" => IacTool::Terraform,
        "pulumi" => IacTool::Pulumi,
        "tofu" => IacTool::Tofu,
        _ => return Vec::new(),
    };

    let args: Vec<String> = seg
        .args
        .iter()
        .map(|a| strip_outer_quotes(a).to_string())
        .collect();

    // Shape: <tool> <apply|up|destroy> [flags] [plan_file?]
    let (verb, post_verb) = match locate_verb(tool, &args) {
        Some(p) => p,
        None => return Vec::new(),
    };
    let is_apply = matches!(verb, IacVerb::Apply | IacVerb::Up);
    let is_destroy = matches!(verb, IacVerb::Destroy);
    if !is_apply && !is_destroy {
        return Vec::new();
    }

    let mut findings = Vec::new();

    let auto_approve = has_auto_approve(tool, post_verb);
    let plan_file = positional_plan_file(post_verb);

    // Prod-context detection gates the prod-aware rules only; the others fire
    // regardless.
    let prod_context = if policy.context_guard_enabled && !policy.context_labels.is_empty() {
        find_prod_context(policy)
    } else {
        None
    };

    if is_destroy && prod_context.is_some() {
        let label_text = prod_context.as_deref().unwrap_or("(prod)");
        findings.push(make_finding(
            RuleId::IacDestroyProd,
            Severity::High,
            format!("{} destroy against production context", tool.as_str()),
            format!(
                "`{} destroy` against an active provider context labeled \
                 production / critical removes every resource in the workspace. \
                 Confirm `tirith context status` shows the intended context.",
                tool.as_str(),
            ),
            tool,
            input,
            Some(label_text),
        ));
    }

    if is_apply && auto_approve {
        let (rule_id, severity, title) = if prod_context.is_some() {
            (
                RuleId::IacApplyAutoApproveProd,
                Severity::High,
                format!(
                    "{} apply -auto-approve against production context",
                    tool.as_str()
                ),
            )
        } else {
            (
                RuleId::IacApplyAutoApprove,
                Severity::Medium,
                format!("{} apply with auto-approve", tool.as_str()),
            )
        };
        findings.push(make_finding(
            rule_id,
            severity,
            title,
            format!(
                "`{}` was invoked with the auto-approve flag (skips the interactive \
                 confirmation step). {}",
                tool.as_str(),
                if prod_context.is_some() {
                    "The active context is labeled production / critical — the combination is \
                     a documented anti-pattern."
                } else {
                    "Outside of production this is a footgun rather than a critical risk; \
                     surfaced for awareness."
                },
            ),
            tool,
            input,
            prod_context.as_deref(),
        ));
    }

    // Plan-before-apply gate (opt-in).
    if is_apply && policy.iac_require_plan_before_apply {
        match plan_file {
            None => {
                findings.push(make_finding(
                    RuleId::IacApplyWithoutPlan,
                    Severity::High,
                    format!("{} apply without a saved plan file", tool.as_str()),
                    format!(
                        "`{}` was invoked with no positional plan file and \
                         `iac_require_plan_before_apply` is on. Run \
                         `{} plan -out tfplan && tirith iac check-plan tfplan && \
                         {} apply tfplan`.",
                        tool.as_str(),
                        tool.as_str(),
                        tool.as_str(),
                    ),
                    tool,
                    input,
                    prod_context.as_deref(),
                ));
            }
            Some(path) => {
                // Validate the plan hash against the recorded store.
                let pb = PathBuf::from(&path);
                match std::fs::read(&pb) {
                    Ok(bytes) => {
                        let sha = iac_plan::sha256_hex(&bytes);
                        let status = iac_plan::plan_hash_status(&sha);
                        // Both NotRecorded and StateDirUnresolved fail closed
                        // (PR-127 review #14); the evidence text differentiates.
                        if !matches!(status, iac_plan::PlanHashStatus::Recorded) {
                            let detail = match status {
                                iac_plan::PlanHashStatus::StateDirUnresolved => format!(
                                    "tirith could not resolve its state directory; plan-hash \
                                     verification cannot proceed. Set `XDG_STATE_HOME` or \
                                     ensure `$HOME` is writable, then run \
                                     `tirith iac check-plan {path}` to record this plan."
                                ),
                                _ => format!(
                                    "`{}` was invoked with plan file `{}` but the file's \
                                     SHA-256 (`{}`) does not match any plan recorded in \
                                     `{}`. Run `tirith iac check-plan {}` first.",
                                    tool.as_str(),
                                    path,
                                    sha,
                                    iac_plan::iac_plans_dir_display(),
                                    path,
                                ),
                            };
                            findings.push(make_finding(
                                RuleId::IacPlanHashMismatch,
                                Severity::High,
                                format!("{} apply against an unrecorded plan file", tool.as_str()),
                                detail,
                                tool,
                                input,
                                prod_context.as_deref(),
                            ));
                        }
                    }
                    Err(e) => {
                        // Couldn't open the plan file — emit the mismatch anyway.
                        findings.push(make_finding(
                            RuleId::IacPlanHashMismatch,
                            Severity::High,
                            format!(
                                "{} apply: plan file '{}' could not be read",
                                tool.as_str(),
                                path
                            ),
                            format!(
                                "`{}` was invoked with plan file `{}` but tirith could not \
                                 read it (`{e}`). Verify the path before re-running.",
                                tool.as_str(),
                                path
                            ),
                            tool,
                            input,
                            prod_context.as_deref(),
                        ));
                    }
                }
            }
        }
    }

    findings
}

/// `Some(label)` when an active provider context is labeled critical/prod.
fn find_prod_context(policy: &Policy) -> Option<String> {
    let detection = context_detect::detect_all();
    for provider in [
        Provider::Kube,
        Provider::Aws,
        Provider::Gcp,
        Provider::Azure,
    ] {
        if let Some(ctx) = detection.contexts.get(&provider) {
            if let Some(label) = policy.context_labels.get(&ctx.label_key()) {
                if is_critical_label(label) {
                    return Some(format!("{}={} ({label})", provider.as_str(), ctx.context));
                }
            }
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IacVerb {
    Apply,
    /// Pulumi calls it `up` — we treat it as apply.
    Up,
    Destroy,
}

/// Locate the verb, skipping global flags before it; returns the slice after.
fn locate_verb(tool: IacTool, args: &[String]) -> Option<(IacVerb, &[String])> {
    for (i, arg) in args.iter().enumerate() {
        if arg.starts_with('-') {
            continue;
        }
        let verb = match (tool, arg.as_str()) {
            (IacTool::Terraform | IacTool::Tofu, "apply") => IacVerb::Apply,
            (IacTool::Terraform | IacTool::Tofu, "destroy") => IacVerb::Destroy,
            (IacTool::Pulumi, "up") => IacVerb::Up,
            (IacTool::Pulumi, "destroy") => IacVerb::Destroy,
            _ => return None,
        };
        return Some((verb, &args[i + 1..]));
    }
    None
}

/// Detect the auto-approve flag (`-auto-approve` for terraform/tofu, `--yes` /
/// `-y` for pulumi).
fn has_auto_approve(tool: IacTool, post_verb: &[String]) -> bool {
    match tool {
        IacTool::Terraform | IacTool::Tofu => post_verb.iter().any(|a| {
            let a = strip_outer_quotes(a);
            a == "-auto-approve" || a == "--auto-approve" || a.starts_with("-auto-approve=")
        }),
        IacTool::Pulumi => post_verb.iter().any(|a| {
            let a = strip_outer_quotes(a);
            a == "--yes" || a == "-y" || a.starts_with("--yes=")
        }),
    }
}

/// Locate the first post-verb positional that looks like a plan-file path (not
/// a flag, not `KEY=VAL`); `None` when there is none.
fn positional_plan_file(post_verb: &[String]) -> Option<String> {
    let mut iter = post_verb.iter();
    while let Some(arg) = iter.next() {
        let arg = strip_outer_quotes(arg);
        if arg.is_empty() {
            continue;
        }
        if arg == "--" {
            // Following arg is positional, regardless of how it starts.
            if let Some(p) = iter.next() {
                let p = strip_outer_quotes(p);
                if !p.is_empty() {
                    return Some(p.to_string());
                }
            }
            return None;
        }
        if arg.starts_with('-') {
            // Terraform flag values are glued (`-target=res`), so skip bare flags.
            continue;
        }
        if arg.contains('=') {
            // KEY=VAL shape — not a plan file.
            continue;
        }
        return Some(arg.to_string());
    }
    None
}

fn make_finding(
    rule_id: RuleId,
    severity: Severity,
    title: String,
    description: String,
    tool: IacTool,
    input: &str,
    prod_context: Option<&str>,
) -> Finding {
    let mut evidence = vec![Evidence::CommandPattern {
        pattern: format!("{} <iac-gate>", tool.as_str()),
        matched: input.chars().take(200).collect(),
    }];
    if let Some(ctx) = prod_context {
        evidence.push(Evidence::Text {
            detail: format!("active prod context: {ctx}"),
        });
    }

    Finding {
        rule_id,
        severity,
        title,
        description,
        evidence,
        human_view: Some(format!(
            "{} — confirm with `tirith iac --help` before re-running.",
            tool.as_str()
        )),
        agent_view: Some(format!(
            "tirith refused: IaC gate. tool={} rule={:?} {}",
            tool.as_str(),
            rule_id,
            prod_context.map(|c| format!("ctx={c}")).unwrap_or_default(),
        )),
        mitre_id: None,
        custom_rule_id: None,
    }
}

fn strip_outer_quotes(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
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

    fn policy_with_prod_label(provider: &str, ctx: &str) -> Policy {
        let mut p = Policy {
            context_guard_enabled: true,
            ..Policy::default()
        };
        let key = format!("{provider}:{ctx}");
        p.context_labels.insert(key, "critical".to_string());
        p
    }

    #[test]
    fn locate_verb_skips_chdir_flag() {
        let args = vec!["-chdir=infra".to_string(), "apply".to_string()];
        let v = locate_verb(IacTool::Terraform, &args);
        assert!(matches!(v, Some((IacVerb::Apply, _))));
    }

    #[test]
    fn locate_verb_returns_none_for_non_apply() {
        let args = vec!["fmt".to_string()];
        let v = locate_verb(IacTool::Terraform, &args);
        assert!(v.is_none());
    }

    #[test]
    fn auto_approve_detected_terraform() {
        assert!(has_auto_approve(
            IacTool::Terraform,
            &["-auto-approve".to_string()],
        ));
        assert!(!has_auto_approve(
            IacTool::Terraform,
            &["-target=foo".to_string()],
        ));
    }

    #[test]
    fn auto_approve_detected_pulumi() {
        assert!(has_auto_approve(IacTool::Pulumi, &["--yes".to_string()]));
        assert!(has_auto_approve(IacTool::Pulumi, &["-y".to_string()]));
        assert!(!has_auto_approve(
            IacTool::Pulumi,
            &["--stack".to_string(), "dev".to_string()],
        ));
    }

    #[test]
    fn positional_plan_file_finds_plain_arg() {
        let p = positional_plan_file(&["tfplan".to_string()]);
        assert_eq!(p.as_deref(), Some("tfplan"));
    }

    #[test]
    fn positional_plan_file_skips_flag() {
        let p = positional_plan_file(&["-no-color".to_string(), "tfplan".to_string()]);
        assert_eq!(p.as_deref(), Some("tfplan"));
    }

    #[test]
    fn positional_plan_file_returns_none_when_no_positional() {
        let p = positional_plan_file(&["-auto-approve".to_string()]);
        assert!(p.is_none());
    }

    #[test]
    fn positional_plan_file_handles_double_dash() {
        let p = positional_plan_file(&["--".to_string(), "tfplan".to_string()]);
        assert_eq!(p.as_deref(), Some("tfplan"));
    }

    #[test]
    fn check_terraform_apply_auto_approve_dev_warns_medium() {
        let policy = Policy::default();
        let findings = check("terraform apply -auto-approve", ShellType::Posix, &policy);
        let auto = findings
            .iter()
            .find(|f| matches!(f.rule_id, RuleId::IacApplyAutoApprove));
        assert!(auto.is_some(), "expected IacApplyAutoApprove: {findings:?}");
        assert!(matches!(auto.unwrap().severity, Severity::Medium));
    }

    #[test]
    fn check_pulumi_up_yes_dev_warns_medium() {
        let policy = Policy::default();
        let findings = check("pulumi up --yes", ShellType::Posix, &policy);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::IacApplyAutoApprove)),
            "expected IacApplyAutoApprove: {findings:?}",
        );
    }

    #[test]
    fn check_tofu_apply_with_no_args_does_not_fire() {
        let policy = Policy::default();
        let findings = check("tofu apply", ShellType::Posix, &policy);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn check_terraform_apply_requires_plan_when_policy_on() {
        let policy = Policy {
            iac_require_plan_before_apply: true,
            ..Policy::default()
        };
        let findings = check("terraform apply", ShellType::Posix, &policy);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::IacApplyWithoutPlan)),
            "expected IacApplyWithoutPlan: {findings:?}",
        );
    }

    #[test]
    fn check_terraform_destroy_without_prod_does_not_fire_destroy_rule() {
        let policy = Policy::default();
        let findings = check("terraform destroy", ShellType::Posix, &policy);
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::IacDestroyProd)),
            "{findings:?}",
        );
    }

    #[test]
    fn check_non_iac_leader_does_not_fire() {
        let policy = Policy::default();
        let findings = check("git apply -auto-approve", ShellType::Posix, &policy);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn check_terraform_apply_tfplan_no_policy_no_finding() {
        // No policy gate and no auto-approve → a clean apply yields nothing.
        let policy = Policy::default();
        let findings = check("terraform apply tfplan", ShellType::Posix, &policy);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn find_prod_context_with_empty_labels_returns_none() {
        let policy = Policy::default();
        assert!(find_prod_context(&policy).is_none());
    }

    #[test]
    fn is_critical_label_synonyms() {
        for s in ["critical", "Production", "PROD", "live", "p0", "p1"] {
            assert!(is_critical_label(s), "{s} should be critical");
        }
        for s in ["dev", "staging", "qa", "test", "p2", ""] {
            assert!(!is_critical_label(s), "{s} should NOT be critical");
        }
    }

    #[test]
    fn check_terraform_fmt_does_not_fire() {
        // `terraform fmt` is read-only — no apply/destroy verb.
        let policy = Policy::default();
        let findings = check("terraform fmt", ShellType::Posix, &policy);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn check_terraform_plan_does_not_fire() {
        let policy = Policy::default();
        let findings = check("terraform plan -out tfplan", ShellType::Posix, &policy);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn check_handles_chdir_global_flag() {
        let policy = Policy {
            iac_require_plan_before_apply: true,
            ..Policy::default()
        };
        let findings = check("terraform -chdir=infra apply", ShellType::Posix, &policy);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::IacApplyWithoutPlan)),
            "expected IacApplyWithoutPlan: {findings:?}",
        );
    }

    #[allow(dead_code)]
    fn _force_btreemap_use() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    #[test]
    fn policy_helper_builds_labeled_aws() {
        let p = policy_with_prod_label("aws", "prod");
        assert_eq!(
            p.context_labels.get("aws:prod").map(String::as_str),
            Some("critical")
        );
    }
}
