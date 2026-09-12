//! Typed personal Claude preparation. Native qualification is deliberately
//! narrow; preparing settings never claims an already running host is protected.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
use tirith_core::trusted_child::{self, ChildLimits, ChildOutcome, ChildSpec, TrustedExecutable};

use super::change_plan::{Edit, RequestedChange};
use super::claude_config::OwnedClaudeHandler;
use crate::cli::control::identity::BinaryIdentity;
use crate::cli::shell_target;

const QUALIFIED_CLAUDE_VERSION: &str = "2.1.268 (Claude Code)";
const QUALIFIED_PYTHON_VERSION: &str = "Python 3.9.6";
const MAX_INPUT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ToolRole {
    Claude,
    Python,
    Tirith,
    PythonRuntime,
}

impl ToolRole {
    fn resolve(self) -> Result<TrustedExecutable, String> {
        let result = match self {
            Self::Claude => trusted_child::resolve_ambient("claude"),
            Self::Python => trusted_child::resolve_ambient("python3"),
            Self::Tirith => TrustedExecutable::current(),
            Self::PythonRuntime => {
                return Err("Python runtime must be derived from its validated launcher".into())
            }
        };
        result.map_err(|_| "a selected agent executable is unavailable or untrusted".into())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolInput {
    role: ToolRole,
    invocation: PathBuf,
    canonical: PathBuf,
    sha256: String,
    #[cfg(test)]
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    fixture: bool,
}

impl ToolInput {
    fn resolve(&self) -> Result<TrustedExecutable, String> {
        #[cfg(test)]
        if self.fixture {
            return TrustedExecutable::from_absolute(&self.invocation, &[])
                .map_err(|_| "fixture executable is untrusted".into());
        }
        if self.role == ToolRole::PythonRuntime {
            return TrustedExecutable::from_absolute(&self.invocation, &[])
                .map_err(|_| "captured Python runtime is unavailable or untrusted".into());
        }
        self.role.resolve()
    }
}

struct HeldTool {
    expected: ToolInput,
    executable: TrustedExecutable,
    identity: BinaryIdentity,
}

impl HeldTool {
    fn capture(role: ToolRole) -> Result<Self, String> {
        Self::from_executable(role, role.resolve()?)
    }

    fn from_executable(role: ToolRole, executable: TrustedExecutable) -> Result<Self, String> {
        let identity = BinaryIdentity::capture(executable.path())?;
        executable
            .revalidate()
            .map_err(|_| "agent executable changed during capture")?;
        let expected = ToolInput {
            role,
            invocation: executable.invocation_path().into(),
            canonical: executable.path().into(),
            sha256: identity.sha256().into(),
            #[cfg(test)]
            fixture: false,
        };
        Ok(Self {
            expected,
            executable,
            identity,
        })
    }

    fn validate(&self) -> Result<(), String> {
        self.identity.revalidate()?;
        self.executable
            .revalidate()
            .map_err(|_| "agent executable selection changed")?;
        let selected = self.expected.resolve()?;
        if selected.path() != self.expected.canonical
            || selected.invocation_path() != self.expected.invocation
        {
            return Err("agent executable discovery changed; refresh the setup plan".into());
        }
        Ok(())
    }
}

/// Private durable input identities, not a serialized authorization permit.
/// A resumed operation must reacquire live leases and compare exact bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentPrecondition {
    home: PathBuf,
    uid: Option<u32>,
    claude_version: String,
    tools: Vec<ToolInput>,
}

/// Keep live executable handles until the final protected publication returns.
/// Every writer callback revalidates these same retained objects. Never replace
/// this with a metadata/digest cache after the handles have been dropped.
pub(crate) struct RetainedAgentInputs {
    expected: AgentPrecondition,
    tools: Vec<HeldTool>,
}

impl AgentPrecondition {
    pub(crate) fn retain(&self) -> Result<RetainedAgentInputs, String> {
        self.validate_selection()?;
        let native_scope = cfg!(all(target_os = "macos", target_arch = "aarch64"));
        #[cfg(test)]
        let native_scope = native_scope || self.tools.iter().all(|tool| tool.fixture);
        if !native_scope
            || self.claude_version != QUALIFIED_CLAUDE_VERSION
            || self.tools.len() != 4
            || !self.tools.iter().map(|t| t.role).eq([
                ToolRole::Claude,
                ToolRole::Python,
                ToolRole::Tirith,
                ToolRole::PythonRuntime,
            ])
        {
            return Err(
                "agent setup qualification changed; prepare a supported native plan".into(),
            );
        }
        let mut tools = Vec::with_capacity(4);
        for expected in &self.tools {
            let held = HeldTool::from_executable(expected.role, expected.resolve()?)?;
            #[cfg(test)]
            let held = {
                let mut held = held;
                held.expected.fixture = expected.fixture;
                held
            };

            if held.expected.invocation != expected.invocation
                || held.expected.canonical != expected.canonical
                || held.expected.sha256 != expected.sha256
            {
                return Err("agent executable bytes changed; refresh the setup plan".into());
            }
            tools.push(held);
        }
        let retained = RetainedAgentInputs {
            expected: self.clone(),
            tools,
        };
        retained.revalidate()?;
        Ok(retained)
    }

    pub(crate) fn validate_handler_target(
        &self,
        target: &Path,
        scope: &Path,
    ) -> Result<(), String> {
        if target != self.home.join(".claude/settings.json") || scope != self.home {
            return Err(
                "Claude handler target is not the fixed personal settings destination".into(),
            );
        }
        Ok(())
    }

    fn validate_selection(&self) -> Result<(), String> {
        self.validate_undo()?;
        refuse_managed_configuration()?;
        let settings = read(&self.home.join(".claude/settings.json"), &self.home)?;
        super::claude_config::activation_allowed(settings.as_deref())?;
        if std::env::var_os("CLAUDE_CONFIG_DIR")
            .is_some_and(|path| Path::new(&path) != self.home.join(".claude"))
        {
            return Err("Claude uses a different configuration directory; preserve that explicit setup workflow".into());
        }
        Ok(())
    }

    pub(crate) fn validate_undo(&self) -> Result<(), String> {
        let target = shell_target::resolve_for_shell("unknown")?;
        shell_target::require_personal_writer(&target)?;
        if target.operator_home != self.home || target.operator_uid != self.uid {
            return Err("agent setup operator changed; refresh the operation".into());
        }
        // Compensation still requires exact owned postimages. It may remove the
        // old integration after a host or interpreter update without accepting
        // new activation or acquiring authority over a newly selected path.
        Ok(())
    }
}

impl RetainedAgentInputs {
    pub(crate) fn revalidate_for(&self, expected: &AgentPrecondition) -> Result<(), String> {
        if expected != &self.expected {
            return Err("retained agent inputs do not belong to this immutable operation".into());
        }
        self.revalidate()
    }

    pub(crate) fn revalidate(&self) -> Result<(), String> {
        self.expected.validate_selection()?;
        for tool in &self.tools {
            tool.validate()?;
        }
        Ok(())
    }
}

fn refuse_managed_configuration() -> Result<(), String> {
    for path in [
        "/Library/Application Support/ClaudeCode/managed-settings.json",
        "/Library/Application Support/ClaudeCode/managed-mcp.json",
        "/etc/claude-code/managed-settings.json",
        "/etc/claude-code/managed-mcp.json",
    ] {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err("cannot establish the managed Claude configuration boundary".into())
            }
            Ok(_) => {
                return Err(
                    "managed Claude configuration requires its explicit administrator workflow"
                        .into(),
                )
            }
        }
    }
    Ok(())
}

fn version(executable: &TrustedExecutable, arguments: &[&str]) -> Result<String, String> {
    // The real host sees no user config, provider/session credentials or inherited
    // Tirith overrides. These ephemeral version-probe files are removed before
    // preparation returns; no selected destination or journal is written.
    let probe = tempfile::Builder::new()
        .prefix("tirith-agent-version-")
        .tempdir()
        .map_err(|_| "cannot isolate agent version probe")?;
    let spec = ChildSpec::new(
        arguments,
        ChildLimits::new(Duration::from_secs(5), 4096, 4096),
    )
    .cwd(probe.path())
    .env("HOME", probe.path())
    .env("CLAUDE_CONFIG_DIR", probe.path())
    .env("XDG_CONFIG_HOME", probe.path())
    .env("TMPDIR", probe.path())
    .env("PATH", "/usr/bin:/bin")
    .env("LANG", "C")
    .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
    .env("DISABLE_AUTOUPDATER", "1")
    .env("DISABLE_TELEMETRY", "1")
    .env("DISABLE_ERROR_REPORTING", "1");
    match trusted_child::run(executable, &spec) {
        ChildOutcome::Completed { status, stdout, .. } if status.success() => {
            String::from_utf8(stdout)
                .map(|s| s.trim().into())
                .map_err(|_| "agent version is not UTF-8".into())
        }
        _ => Err("agent version probe failed or exceeded its bounded deadline".into()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PythonRuntimeProbe {
    executable: String,
    implementation: String,
    version: [u32; 3],
}

fn capture_python_runtime(launcher: &HeldTool) -> Result<HeldTool, String> {
    let output = version(&launcher.executable, &["-I", "-S", "-c", "import json,sys; print(json.dumps({'executable':sys.executable,'implementation':sys.implementation.name,'version':list(sys.version_info[:3])}))"])?;
    let value = tirith_core::mcp_lock::parse_json_no_duplicates(&output)
        .map_err(|_| "Python runtime probe returned malformed or duplicate JSON")?;
    let report: PythonRuntimeProbe = serde_json::from_value(value)
        .map_err(|_| "Python runtime probe returned unsupported fields")?;
    if report.implementation != "cpython" || report.version != [3, 9, 6] {
        return Err(
            "this Python runtime version lacks current combined-setup qualification".into(),
        );
    }
    let path = Path::new(&report.executable);
    // Probe stdout is only a candidate. Apply the same native owner, path,
    // executable and no-follow identity checks before retaining or using it.
    let mut denied = vec![
        std::env::temp_dir(),
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
    ];
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.parent().is_some() {
            denied.push(cwd);
        }
    }
    let executable = TrustedExecutable::from_absolute(path, &denied)
        .map_err(|_| "reported Python runtime path is unavailable or untrusted")?;
    let runtime = HeldTool::from_executable(ToolRole::PythonRuntime, executable)?;
    if version(&runtime.executable, &["-I", "-S", "--version"])? != QUALIFIED_PYTHON_VERSION {
        return Err("reported Python runtime changed during capture".into());
    }
    runtime.identity.revalidate()?;
    launcher.validate()?;
    Ok(runtime)
}

fn read(path: &Path, home: &Path) -> Result<Option<String>, String> {
    super::fs_helpers::read_snapshot_scoped_capped(path, home, MAX_INPUT_BYTES)?
        .bytes
        .map(|bytes| {
            String::from_utf8(bytes).map_err(|_| "agent configuration is not UTF-8".into())
        })
        .transpose()
}

fn quote(path: &Path) -> Result<String, String> {
    let value = path
        .to_str()
        .ok_or("agent executable/configuration path must be UTF-8")?;
    if value.contains('\0') || value.contains('\n') || value.contains('\r') {
        return Err(
            "agent executable/configuration path contains unsupported control characters".into(),
        );
    }
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

fn command(binary: &Path, python: &Path, hook: &Path) -> Result<String, String> {
    // Exactly one synchronous POSIX command. The host's blocking exit code also
    // covers a missing interpreter and a crashed Python hook. Host removal or a
    // deadline shorter than the internal checker remains an explicit boundary.
    Ok(format!(
        "TIRITH_BIN={} {} -I -S {} || exit 2",
        quote(binary)?,
        quote(python)?,
        quote(hook)?
    ))
}

pub(crate) struct PreparedClaude {
    pub snapshot: EffectivePolicySnapshot,
    home: PathBuf,
    settings: PathBuf,
    hook: PathBuf,
    before_settings: Option<String>,
    before_hook: Option<String>,
    handler: OwnedClaudeHandler,
    retained: RetainedAgentInputs,
}

pub(crate) type PreparedClaudeParts = (
    Vec<RequestedChange>,
    BTreeMap<PathBuf, Option<String>>,
    AgentPrecondition,
);

impl PreparedClaude {
    pub(crate) fn capture(cwd: Option<&str>) -> Result<Self, String> {
        if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            return Err("combined Claude setup currently requires qualified native macOS host evidence; use explicit manual setup on this platform".into());
        }
        refuse_managed_configuration()?;
        let target = shell_target::resolve_for_shell("unknown")?;
        shell_target::require_personal_writer(&target)?;
        let snapshot = EffectivePolicySnapshot::resolve(cwd, ResolutionMode::Runtime);
        snapshot
            .revalidate_for_mutation()
            .map_err(|e| e.to_string())?;
        let mut tools = vec![
            HeldTool::capture(ToolRole::Claude)?,
            HeldTool::capture(ToolRole::Python)?,
            HeldTool::capture(ToolRole::Tirith)?,
        ];
        // A native host is part of the exercised scope; an npm/script wrapper is
        // not silently promoted to the installed native executable contract.
        let mut magic = [0u8; 4];
        use std::io::Read as _;
        tirith_core::util::open_read_no_follow_capped(
            tools[0].executable.path(),
            512 * 1024 * 1024,
        )
        .map_err(|_| "cannot open native Claude executable")?
        .read_exact(&mut magic)
        .map_err(|_| "cannot inspect native Claude executable")?;
        if !matches!(
            magic,
            [0xcf, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
                | [0xca, 0xfe, 0xba, 0xbf]
                | [0xbf, 0xba, 0xfe, 0xca]
        ) {
            return Err("combined Claude setup requires the qualified native executable, not a launcher wrapper".into());
        }
        let claude_version = version(&tools[0].executable, &["--version"])?;
        if claude_version != QUALIFIED_CLAUDE_VERSION {
            return Err("this Claude host version lacks current combined-setup qualification; preserve the explicit setup workflow".into());
        }
        tools.push(capture_python_runtime(&tools[1])?);

        let precondition = AgentPrecondition {
            home: target.operator_home.clone(),
            uid: target.operator_uid,
            claude_version,
            tools: tools.iter().map(|held| held.expected.clone()).collect(),
        };
        let retained = RetainedAgentInputs {
            expected: precondition,
            tools,
        };
        retained.revalidate()?;
        Self::prepare(snapshot, target.operator_home, retained)
    }

    fn prepare(
        snapshot: EffectivePolicySnapshot,
        home: PathBuf,
        retained: RetainedAgentInputs,
    ) -> Result<Self, String> {
        let settings = home.join(".claude/settings.json");
        let hook = home.join(".claude/hooks/tirith-check.py");
        let before_settings = read(&settings, &home)?;
        let before_hook = read(&hook, &home)?;
        if before_hook
            .as_deref()
            .is_some_and(|text| !text.is_empty() && text != crate::assets::TIRITH_CHECK_PY)
        {
            return Err("existing Claude hook script differs from this embedded candidate; preserve manual content and review explicit repair".into());
        }
        let launcher = &retained.tools[1].expected.invocation;
        let python = &retained.tools[3].expected.invocation;
        let binary = &retained.tools[2].expected.invocation;
        let intended = command(binary, python, &hook)?;
        let legacy_python = super::shell_profile::shell_quote(
            launcher
                .to_str()
                .ok_or("Python launcher path is not UTF-8")?,
            "bash",
        );
        let legacy = [format!(
            "{legacy_python} \"$HOME/.claude/hooks/tirith-check.py\" || exit 2"
        )];
        let handler = OwnedClaudeHandler::capture(before_settings.as_deref(), &intended, &legacy)?;
        snapshot.revalidate_inputs().map_err(|e| e.to_string())?;
        retained.revalidate()?;
        Ok(Self {
            snapshot,
            home,
            settings,
            hook,
            before_settings,
            before_hook,
            handler,
            retained,
        })
    }

    pub(crate) fn setup_parts(&self) -> Result<PreparedClaudeParts, String> {
        self.snapshot
            .revalidate_inputs()
            .map_err(|e| e.to_string())?;
        self.retained.revalidate()?;
        if self.handler.is_noop()
            && self.before_hook.as_deref() == Some(crate::assets::TIRITH_CHECK_PY)
        {
            return Ok((Vec::new(), BTreeMap::new(), self.retained.expected.clone()));
        }
        // Retain the already-current script as an inactive step too: activation
        // must not accept an intervening change merely because staging was a no-op.
        let requests = vec![
            RequestedChange {
                target: self.hook.clone(),
                scope_root: self.home.clone(),
                edit: Edit::WholeFile(crate::assets::TIRITH_CHECK_PY.into()),
                activation: false,
                description: "Stage the embedded Claude command hook".into(),
            },
            RequestedChange {
                target: self.settings.clone(),
                scope_root: self.home.clone(),
                edit: Edit::ClaudeHandler(self.handler.clone()),
                activation: true,
                description: "Configure the owned synchronous Claude Bash command handler".into(),
            },
        ];
        Ok((
            requests,
            BTreeMap::from([
                (self.hook.clone(), self.before_hook.clone()),
                (self.settings.clone(), self.before_settings.clone()),
            ]),
            self.retained.expected.clone(),
        ))
    }

    pub(crate) fn projection(&self) -> serde_json::Value {
        // Canonical protocol facts only. Private identities, host output, config
        // bytes and paths stay in the prepared object/journal, never the browser.
        serde_json::json!({"kind":"claude_setup_preview","scope":"user","tool_scope":"Bash","host":"claude-code","host_version":QUALIFIED_CLAUDE_VERSION,"applied":false,"reload_required":true,"verified_blocking":false,"verification_source":"configuration_only","preserves_unrelated_settings":true})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn derived_command_quotes_paths_without_expanding_shell_material() {
        assert_eq!(command(Path::new("/safe/bin/tirith"), Path::new("/Python's/bin/python3"), Path::new("/home/user $(touch nope)/.claude/hooks/tirith-check.py")).unwrap(), "TIRITH_BIN='/safe/bin/tirith' '/Python'\\''s/bin/python3' -I -S '/home/user $(touch nope)/.claude/hooks/tirith-check.py' || exit 2");
        assert!(command(
            Path::new("/bad\nname"),
            Path::new("/python"),
            Path::new("/hook")
        )
        .is_err());
    }
    #[cfg(unix)]
    fn fixture(home: &Path) -> PreparedClaude {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = home.join("agent-fixture-bin");
        std::fs::create_dir(&directory).unwrap();
        let mut tools = Vec::new();
        for (role, name) in [
            (ToolRole::Claude, "claude"),
            (ToolRole::Python, "python3"),
            (ToolRole::Tirith, "tirith"),
            (ToolRole::PythonRuntime, "python-runtime"),
        ] {
            let path = directory.join(name);
            std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            let mut tool = HeldTool::from_executable(
                role,
                TrustedExecutable::from_absolute(&path, &[]).unwrap(),
            )
            .unwrap();
            tool.expected.fixture = true;
            tools.push(tool);
        }
        let operator = shell_target::resolve_for_shell("unknown").unwrap();
        let retained = RetainedAgentInputs {
            expected: AgentPrecondition {
                home: home.into(),
                uid: operator.operator_uid,
                claude_version: QUALIFIED_CLAUDE_VERSION.into(),
                tools: tools.iter().map(|tool| tool.expected.clone()).collect(),
            },
            tools,
        };
        PreparedClaude::prepare(
            EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime),
            home.into(),
            retained,
        )
        .unwrap()
    }

    #[cfg(unix)]
    fn plan(prepared: &PreparedClaude, id: &str) -> super::super::change_plan::OperationStatus {
        use super::super::change_plan::{IntegrationPreconditions, MutationService, PlanChanges};
        let (requests, preimages, agent) = prepared.setup_parts().unwrap();
        MutationService::current()
            .unwrap()
            .plan_integrations_with_intent(
                id,
                PlanChanges {
                    requests,
                    preimages: &preimages,
                },
                &prepared.snapshot,
                &serde_json::json!({"agent":"claude-code"}),
                IntegrationPreconditions {
                    shell: None,
                    agent: Some(agent),
                },
            )
            .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn shared_plan_stages_before_activation_and_compensates_only_owned_handler() {
        use super::super::change_plan::{JobState, MutationService};
        crate::cli::test_harness::with_fake_env(true, |home, _| {
            let prepared = fixture(home);
            let id = uuid::Uuid::new_v4().to_string();
            let planned = plan(&prepared, &id);
            assert!(!planned.steps[0].activation);
            assert!(planned.steps[1].activation);
            assert!(!prepared.settings.exists());
            assert!(!prepared.hook.exists());
            let service = MutationService::current().unwrap();
            assert_eq!(
                service.apply(&id, &prepared.snapshot).unwrap().state,
                JobState::Completed
            );
            let mut settings: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&prepared.settings).unwrap())
                    .unwrap();
            settings["extra"] = serde_json::json!({"kept":true});
            settings["hooks"]["PreToolUse"].as_array_mut().unwrap().push(serde_json::json!({"matcher":"Read", "hooks":[{"type":"command","command":"manual"}]}));
            std::fs::write(
                &prepared.settings,
                serde_json::to_string(&settings).unwrap(),
            )
            .unwrap();
            assert_eq!(
                service
                    .undo(
                        &id,
                        &EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime)
                    )
                    .unwrap()
                    .state,
                JobState::Undone
            );
            let restored: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&prepared.settings).unwrap())
                    .unwrap();
            assert_eq!(
                restored,
                serde_json::json!({"extra":{"kept":true},"hooks":{"PreToolUse":[{"matcher":"Read","hooks":[{"type":"command","command":"manual"}]}]}})
            );
            assert_eq!(std::fs::read(&prepared.hook).unwrap(), b"");
        });
    }

    #[cfg(unix)]
    #[test]
    fn cancellation_never_activates_a_prepared_agent() {
        use super::super::change_plan::{JobState, MutationService};
        crate::cli::test_harness::with_fake_env(true, |home, _| {
            let prepared = fixture(home);
            let id = uuid::Uuid::new_v4().to_string();
            plan(&prepared, &id);
            let service = MutationService::current().unwrap();
            service.cancel(&id).unwrap();
            assert_eq!(
                service.apply(&id, &prepared.snapshot).unwrap().state,
                JobState::Cancelled
            );
            assert!(!prepared.settings.exists());
            assert!(!prepared.hook.exists());
        });
    }

    #[cfg(unix)]
    #[test]
    fn changed_tool_and_manual_disable_each_refuse_before_staging() {
        use super::super::change_plan::{JobState, MutationService};
        for changed_tool in [None, Some("python3"), Some("python-runtime")] {
            crate::cli::test_harness::with_fake_env(true, |home, _| {
                let prepared = fixture(home);
                let id = uuid::Uuid::new_v4().to_string();
                plan(&prepared, &id);
                if let Some(tool) = changed_tool {
                    std::fs::write(
                        home.join("agent-fixture-bin").join(tool),
                        "#!/bin/sh\nexit 1\n",
                    )
                    .unwrap();
                } else {
                    std::fs::create_dir_all(prepared.settings.parent().unwrap()).unwrap();
                    std::fs::write(&prepared.settings, r#"{"disableAllHooks":true}"#).unwrap();
                }
                let state = MutationService::current()
                    .unwrap()
                    .apply(&id, &prepared.snapshot)
                    .unwrap();
                assert_eq!(state.state, JobState::RefreshRequired);
                assert!(!prepared.hook.exists());
            });
        }
    }

    #[cfg(unix)]
    #[test]
    fn owned_handler_conflict_preserves_the_manual_change() {
        use super::super::change_plan::{JobState, MutationService};
        crate::cli::test_harness::with_fake_env(true, |home, _| {
            let prepared = fixture(home);
            let id = uuid::Uuid::new_v4().to_string();
            plan(&prepared, &id);
            std::fs::create_dir_all(prepared.settings.parent().unwrap()).unwrap();
            let manual = r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"manual-tirith-check.py"}]}]}}"#;
            std::fs::write(&prepared.settings, manual).unwrap();
            let state = MutationService::current()
                .unwrap()
                .apply(&id, &prepared.snapshot)
                .unwrap();
            assert_eq!(state.state, JobState::RefreshRequired);
            assert_eq!(std::fs::read_to_string(&prepared.settings).unwrap(), manual);
            assert!(!prepared.hook.exists());
        });
    }
}
