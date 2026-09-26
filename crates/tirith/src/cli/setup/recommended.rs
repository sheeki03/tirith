//! One immutable personal setup plan. Defaults are explicit and customization
//! changes the reviewed payload; package-manager context never selects a home.
use super::change_plan::{MutationService, OperationKind};
use super::shell_service::{PreparedShell, ShellChange, ShellKind};
use serde::{Deserialize, Serialize};
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
use tirith_core::protection_profiles::ProtectionProfile;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SetupScope {
    User,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SelectedAgent {
    ClaudeCode,
    Codex,
    Cursor,
    Windsurf,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecommendedSetup {
    pub scope: SetupScope,
    #[serde(default)]
    pub shell: Option<ShellKind>,
    #[serde(default = "balanced")]
    pub profile: ProtectionProfile,
    #[serde(default)]
    pub agents: Vec<SelectedAgent>,
}
fn balanced() -> ProtectionProfile {
    ProtectionProfile::Balanced
}

pub(crate) fn prepare(
    id: &str,
    request: RecommendedSetup,
    cwd: Option<&str>,
    dry_run: bool,
) -> Result<serde_json::Value, String> {
    if !uuid::Uuid::parse_str(id).is_ok_and(|value| value.to_string() == id) {
        return Err("recommended setup ID must be a canonical UUID".into());
    }
    if request.agents.len() > 4 {
        return Err("select at most four agent integrations".into());
    }
    let cwd = cwd.map(str::to_owned).or_else(|| {
        std::env::current_dir()
            .ok()
            .map(|p| p.display().to_string())
    });
    let intent = (&request, &cwd);
    let service = MutationService::current()?;
    if !dry_run {
        if let Some(status) =
            service.status_for_intent(id, OperationKind::RecommendedSetup, &intent)?
        {
            return result(status, None, cwd.as_deref());
        }
    }
    if request
        .agents
        .iter()
        .any(|agent| *agent != SelectedAgent::ClaudeCode)
    {
        return Err("selected agent hosts lack current combined-setup certification; preserve their explicit setup workflow".into());
    }
    if request.agents.len() > 1 {
        return Err(
            "duplicate agent selections are ambiguous; select each supported host once".into(),
        );
    }
    let shell = if let Some(shell) = request.shell {
        shell
    } else {
        let observed = crate::cli::shell_target::resolve_current()?;
        crate::cli::shell_target::require_personal_writer(&observed)?;
        if observed.identity_source != "observed-ancestor-process"
            || observed.unsupported_reason.is_some()
        {
            return Err("automatic setup cannot identify a supported current shell; provide an explicit --shell for the intended user".into());
        }
        ShellKind::parse(&observed.shell)?
    };
    if !matches!(shell, ShellKind::Bash | ShellKind::Zsh | ShellKind::Fish) {
        return Err("recommended automatic setup currently supports Bash, Zsh and Fish; qualification against the installed candidate is still required. Use explicit shell setup for other variants and verify the actual surface".into());
    }
    let profile = crate::cli::profile_service::PreparedProfile::capture(
        request.profile.as_str(),
        cwd.as_deref(),
    )?;
    let shell = PreparedShell::capture(
        ShellChange::Install {
            shell,
            force: false,
        },
        cwd.as_deref(),
    )?;
    if profile.snapshot.private_replay_guard() != shell.snapshot.private_replay_guard() {
        return Err("policy or operator context changed while capturing recommended setup; refresh the plan".into());
    }
    let agent = if request.agents.is_empty() {
        None
    } else {
        Some(super::claude_service::PreparedClaude::capture(
            cwd.as_deref(),
        )?)
    };
    if agent.as_ref().is_some_and(|agent| {
        agent.snapshot.private_replay_guard() != profile.snapshot.private_replay_guard()
    }) {
        return Err(
            "policy or operator context changed while capturing agent setup; refresh the plan"
                .into(),
        );
    }
    profile
        .snapshot
        .revalidate_for_mutation()
        .map_err(|e| e.to_string())?;
    let (mut changes, mut expected) = profile.setup_parts()?;
    // Materialize the selected personal profile before any startup reference.
    for change in &mut changes {
        change.activation = false;
    }
    let (shell_changes, shell_expected, precondition) = shell.setup_parts()?;
    changes.extend(shell_changes);
    for (path, bytes) in shell_expected {
        if expected.insert(path, bytes).is_some() {
            return Err("recommended setup targets overlap".into());
        }
    }
    let agent_precondition = if let Some(agent) = &agent {
        let (agent_changes, agent_expected, precondition) = agent.setup_parts()?;
        changes.extend(agent_changes);
        for (path, bytes) in agent_expected {
            if expected.insert(path, bytes).is_some() {
                return Err("recommended setup targets overlap".into());
            }
        }
        Some(precondition)
    } else {
        None
    };
    let mut verification = shell.verification_intent()?;
    if let Some(agent) = &agent {
        verification.add_unchanged_inputs(agent.unchanged_verification_inputs()?)?;
    }
    let preview = serde_json::json!({"schema_version":1,"kind":"recommended_setup_preview",
        "scope":"user","profile":profile.projection(),"shell":shell.projection(),
        "selected_agents":request.agents,"agent":agent.as_ref().map(|agent| agent.projection()),"step_count":changes.len(),"applied":false,
        "activation_required":true,"current_shell_verified":false,
        "verification_intent":verification.request(),
        "next_action":"Open a fresh terminal and run the current-shell verification handshake after loading the configured integration."});
    if dry_run {
        return Ok(preview);
    }
    let status = service.plan_recommended_with_verification_intent(
        id,
        super::change_plan::PlanChanges {
            requests: changes,
            preimages: &expected,
        },
        &profile.snapshot,
        &intent,
        super::change_plan::IntegrationPreconditions {
            shell: Some(precondition),
            agent: agent_precondition,
        },
        verification,
    )?;
    result(status, Some(preview), cwd.as_deref())
}
fn result(
    status: super::change_plan::OperationStatus,
    preview: Option<serde_json::Value>,
    cwd: Option<&str>,
) -> Result<serde_json::Value, String> {
    let snapshot = EffectivePolicySnapshot::resolve(cwd, ResolutionMode::LocalOnly);
    let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(
        &tirith_core::policy::captured_policy_dlp_patterns_or(&snapshot.policy.dlp_custom_patterns),
    );
    let verification =
        MutationService::current()?.setup_verification_request(&status.operation_id)?;
    Ok(
        serde_json::json!({"schema_version":1,"kind":"recommended_setup_plan","preview":preview,
        "operation":crate::cli::profile::status_projection(&status,&compiled)?,"executed":false,
        "current_shell_verified":false,"activation_required":true,"verification_intent":verification}),
    )
}

#[cfg(test)]
mod tests {
    use super::super::change_plan::JobState;
    use super::*;
    use crate::cli::test_harness::with_fake_env;

    fn request() -> RecommendedSetup {
        RecommendedSetup {
            scope: SetupScope::User,
            shell: Some(ShellKind::Zsh),
            profile: ProtectionProfile::Balanced,
            agents: Vec::new(),
        }
    }
    #[test]
    fn arbitrary_scope_paths_commands_and_unknown_agents_are_not_configuration_inputs() {
        for value in [
            serde_json::json!({"scope":"project","shell":"zsh"}),
            serde_json::json!({"scope":"user","path":"/tmp/unowned"}),
            serde_json::json!({"scope":"user","command":"echo changed"}),
            serde_json::json!({"scope":"user","agents":["unknown-agent"]}),
        ] {
            assert!(serde_json::from_value::<RecommendedSetup>(value).is_err());
        }
    }
    #[cfg(unix)]
    #[test]
    fn recommended_dry_run_is_inert_then_one_plan_applies_and_compensates_both_surfaces() {
        with_fake_env(true, |home, _| {
            let id = uuid::Uuid::new_v4().to_string();
            let preview = prepare(&id, request(), None, true).unwrap();
            assert_eq!(preview["applied"], false);
            assert!(!home.join(".zshrc").exists());
            let planned = prepare(&id, request(), None, false).unwrap();
            assert_eq!(planned["operation"]["kind"], "recommended-setup");
            assert!(planned["operation"]["steps"].as_array().unwrap().len() >= 2);
            let cwd = std::env::current_dir().unwrap().display().to_string();
            let snapshot = EffectivePolicySnapshot::resolve(Some(&cwd), ResolutionMode::Runtime);
            let service = MutationService::current().unwrap();
            assert_eq!(
                service.apply(&id, &snapshot).unwrap().state,
                JobState::Completed
            );
            assert!(std::fs::read_to_string(home.join(".zshrc"))
                .unwrap()
                .contains("tirith-hook v1"));
            let replay = prepare(&id, request(), None, false).unwrap();
            assert_eq!(replay["operation"]["state"], "completed");
            let mut changed = request();
            changed.profile = ProtectionProfile::Strict;
            assert!(prepare(&id, changed, None, false).is_err());
            service
                .undo(
                    &id,
                    &EffectivePolicySnapshot::resolve(Some(&cwd), ResolutionMode::Runtime),
                )
                .unwrap();
            assert!(!std::fs::read_to_string(home.join(".zshrc"))
                .unwrap()
                .contains("tirith-hook v1"));
        });
    }
    #[test]
    fn unsupported_selected_agent_refuses_before_any_component_is_planned() {
        with_fake_env(true, |home, _| {
            let mut request = request();
            request.agents.push(SelectedAgent::Codex);
            let id = uuid::Uuid::new_v4().to_string();
            assert!(prepare(&id, request, None, false)
                .unwrap_err()
                .contains("certification"));
            assert!(!home.join(".zshrc").exists());
            assert!(MutationService::current()
                .unwrap()
                .read_status(&id)
                .is_err());
        });
    }

    #[cfg(unix)]
    #[test]
    fn unchanged_recommended_setup_keeps_explicit_verification_intent_without_claiming_activation()
    {
        with_fake_env(true, |home, _| {
            let _zdotdir = crate::cli::test_harness::EnvGuard::remove("ZDOTDIR");
            let first = uuid::Uuid::new_v4().to_string();
            prepare(&first, request(), None, false).unwrap();
            let cwd = std::env::current_dir().unwrap().display().to_string();
            let service = MutationService::current().unwrap();
            let policy = EffectivePolicySnapshot::resolve(Some(&cwd), ResolutionMode::Runtime);
            assert_eq!(
                service.apply(&first, &policy).unwrap().state,
                JobState::Completed
            );
            let before = std::fs::read(home.join(".zshrc")).unwrap();
            let second = uuid::Uuid::new_v4().to_string();
            let result = prepare(&second, request(), None, false).unwrap();
            assert_eq!(result["operation"]["no_op"], true);
            assert_eq!(result["operation"]["state"], "completed");
            assert_eq!(
                result["verification_intent"],
                serde_json::json!({"schema_version":1,"scope":"fresh_terminal_activation","shell":"zsh"})
            );
            assert_eq!(result["current_shell_verified"], false);
            assert_eq!(result["activation_required"], true);
            assert_eq!(result["executed"], false);
            assert_eq!(std::fs::read(home.join(".zshrc")).unwrap(), before);
            let policy = EffectivePolicySnapshot::resolve(Some(&cwd), ResolutionMode::Runtime);
            let lease = service
                .completed_setup_lease(&second, policy)
                .unwrap()
                .unwrap();
            lease.revalidate().unwrap();
        });
    }
}
