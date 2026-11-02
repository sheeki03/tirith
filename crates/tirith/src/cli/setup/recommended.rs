//! One immutable personal setup plan. Defaults are explicit and customization
//! changes the reviewed payload; package-manager context never selects a home.
use super::change_plan::{MutationService, OperationKind, PlanRequest};
use super::shell_service::{PreparedShell, ShellChange, ShellKind};
use serde::{Deserialize, Serialize};
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
use tirith_core::protection_profiles::ProtectionProfile;

/// A personal (user-scope) setup plan. Claude Code is the one agent
/// integration recommended setup can include in the same undoable plan; other
/// hosts keep their explicit `tirith setup <tool>` workflow.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecommendedSetup {
    #[serde(default)]
    pub shell: Option<ShellKind>,
    #[serde(default = "balanced")]
    pub profile: ProtectionProfile,
    #[serde(default)]
    pub claude_code: bool,
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
    if !tirith_core::util::is_uuid(id) {
        return Err("recommended setup ID must be a canonical UUID".into());
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
    let agent = if !request.claude_code {
        None
    } else {
        Some(super::claude_config::PreparedClaude::capture(
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
    if let Some(agent) = &agent {
        let (agent_changes, agent_expected) = agent.setup_parts()?;
        changes.extend(agent_changes);
        for (path, bytes) in agent_expected {
            if expected.insert(path, bytes).is_some() {
                return Err("recommended setup targets overlap".into());
            }
        }
    }
    let preview = serde_json::json!({"schema_version":1,"kind":"recommended_setup_preview",
        "scope":"user","profile":profile.projection(),"shell":shell.projection(),
        "selected_agents":if request.claude_code { &["claude-code"][..] } else { &[] },"agent":agent.as_ref().map(|agent| agent.projection()),"step_count":changes.len(),"applied":false,
        "activation_required":true,"current_shell_verified":false,
        "next_action":"Open a fresh terminal and run the current-shell verification handshake after loading the configured integration."});
    if dry_run {
        return Ok(preview);
    }
    let request = if changes.is_empty() {
        PlanRequest::no_op(OperationKind::RecommendedSetup)
    } else {
        PlanRequest::change(OperationKind::RecommendedSetup, changes)
            .preimages(expected)
            .shell(precondition)
    };
    let status = service.submit(id, &profile.snapshot, request.intent(&intent)?)?;
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
    Ok(
        serde_json::json!({"schema_version":1,"kind":"recommended_setup_plan","preview":preview,
        "operation":crate::cli::profile::status_projection(&status,&compiled)?,"executed":false,
        "current_shell_verified":false,"activation_required":true}),
    )
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::super::change_plan::JobState;
    use super::*;
    #[cfg(unix)]
    use crate::cli::test_harness::with_fake_env;

    #[cfg(unix)]
    fn request() -> RecommendedSetup {
        RecommendedSetup {
            shell: Some(ShellKind::Zsh),
            profile: ProtectionProfile::Balanced,
            claude_code: false,
        }
    }
    #[test]
    fn arbitrary_scope_paths_commands_and_unknown_agents_are_not_configuration_inputs() {
        for value in [
            // The plan is personal only; there is no scope to choose.
            serde_json::json!({"scope":"project","shell":"zsh"}),
            serde_json::json!({"scope":"user","shell":"zsh"}),
            serde_json::json!({"path":"/tmp/unowned"}),
            serde_json::json!({"command":"echo changed"}),
            serde_json::json!({"agents":["unknown-agent"]}),
            // Hosts without a combined step keep their explicit workflow.
            serde_json::json!({"codex":true}),
            serde_json::json!({"cursor":true}),
            serde_json::json!({"windsurf":true}),
            serde_json::json!({"claude_code":"yes"}),
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
    #[cfg(unix)]
    #[test]
    fn recommended_claude_step_plans_applies_and_undoes_with_the_explicit_command() {
        with_fake_env(true, |home, _| {
            // Pin the interpreter through the test seam so this test always
            // runs, including on hosts without a trusted python3 on PATH.
            let python = "/usr/bin/python3".to_string();
            super::super::claude_config::TEST_HOOK_PYTHON
                .with(|slot| *slot.borrow_mut() = Some(python.clone()));
            let mut request = request();
            request.claude_code = true;
            let id = uuid::Uuid::new_v4().to_string();
            let preview = prepare(&id, request.clone(), None, true).unwrap();
            assert_eq!(preview["agent"]["kind"], "claude_setup_preview");
            assert!(preview["agent"].get("host_version").is_none());
            assert!(!home.join(".claude").exists());
            prepare(&id, request, None, false).unwrap();
            let cwd = std::env::current_dir().unwrap().display().to_string();
            let snapshot = EffectivePolicySnapshot::resolve(Some(&cwd), ResolutionMode::Runtime);
            let service = MutationService::current().unwrap();
            assert_eq!(
                service.apply(&id, &snapshot).unwrap().state,
                JobState::Completed
            );
            let settings: serde_json::Value =
                serde_json::from_slice(&std::fs::read(home.join(".claude/settings.json")).unwrap())
                    .unwrap();
            assert_eq!(
                settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
                super::super::tools::claude_user_hook_command(&super::super::shell_quote(
                    &python, "bash"
                ))
            );
            assert_eq!(
                std::fs::read_to_string(home.join(".claude/hooks/tirith-check.py")).unwrap(),
                crate::assets::TIRITH_CHECK_PY
            );
            service
                .undo(
                    &id,
                    &EffectivePolicySnapshot::resolve(Some(&cwd), ResolutionMode::Runtime),
                )
                .unwrap();
            let undone: serde_json::Value =
                serde_json::from_slice(&std::fs::read(home.join(".claude/settings.json")).unwrap())
                    .unwrap();
            assert_eq!(undone, serde_json::json!({}));
            // Undo of a created hook leaves an empty placeholder. The explicit
            // command must still take over without --force afterwards.
            let hook = home.join(".claude/hooks/tirith-check.py");
            assert_eq!(std::fs::read(&hook).unwrap(), b"");
            super::super::tools::setup_claude_code(&super::super::run_impl::SetupOpts {
                scope: super::super::run_impl::Scope::User,
                with_mcp: false,
                install_zshenv: false,
                dry_run: false,
                force: false,
                tirith_bin: "/opt/tirith/bin/tirith".into(),
                python_bin: Some(python.clone()),
                update_configs: false,
            })
            .unwrap();
            assert_eq!(
                std::fs::read_to_string(&hook).unwrap(),
                crate::assets::TIRITH_CHECK_PY
            );
            super::super::claude_config::TEST_HOOK_PYTHON.with(|slot| *slot.borrow_mut() = None);
        });
    }

    #[cfg(unix)]
    #[test]
    fn unchanged_recommended_setup_is_a_completed_noop_without_claiming_activation() {
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
            assert!(result.get("verification_intent").is_none());
            assert_eq!(result["current_shell_verified"], false);
            assert_eq!(result["activation_required"], true);
            assert_eq!(result["executed"], false);
            assert_eq!(std::fs::read(home.join(".zshrc")).unwrap(), before);
        });
    }
}
