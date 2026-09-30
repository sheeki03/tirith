//! Owned Claude command-handler edits. Other settings, matchers and hooks are
//! preserved semantically; the one owned handler has an exact pre/postimage.
//!
//! [`PreparedClaude`] is the recommended-setup Claude step. It writes the same
//! bytes as `tirith setup claude-code --scope user` (shared command helper,
//! same trusted `python3` resolver, same settings serialization), but through
//! the journaled, undoable change plan. It does not pin a Claude Code version,
//! executable format, Python version or platform architecture.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};

use super::change_plan::{Edit, RequestedChange};
use crate::cli::shell_target;

const MAX_SETTINGS_BYTES: usize = 1024 * 1024;
const MAX_MATCHERS: usize = 128;
const MAX_HANDLERS: usize = 128;
const MARKER: &str = "tirith-check.py";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnedClaudeHandler {
    before: Option<Value>,
    after: Value,
    created_hooks: bool,
    created_event: bool,
    created_matcher: bool,
}

#[derive(Default)]
struct Selection {
    matcher: Option<usize>,
    handler: Option<usize>,
}

fn document(text: Option<&str>) -> Result<Value, String> {
    let Some(text) = text else {
        return Ok(json!({}));
    };
    if text.len() > MAX_SETTINGS_BYTES {
        return Err("Claude settings exceed the one MiB preparation limit".into());
    }
    let value = tirith_core::mcp_lock::parse_json_no_duplicates(text)
        .map_err(|_| "Claude settings contain malformed JSON or duplicate keys")?;
    if !value.is_object() {
        return Err("Claude settings must be a JSON object".into());
    }
    Ok(value)
}

fn activation_allowed(text: Option<&str>) -> Result<(), String> {
    validate_activation(&document(text)?)
}

/// Administrator-managed Claude configuration has its own workflow; personal
/// setup never competes with it.
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

/// Whether the personal Claude handler at `home/.claude/settings.json` may be
/// activated now. Preparation, planning and every apply authorization run
/// this, so a later managed policy, configuration-directory override or
/// manual hook disable refuses before anything is staged.
pub(super) fn personal_activation_allowed(
    home: &Path,
    settings: Option<&str>,
) -> Result<(), String> {
    refuse_managed_configuration()?;
    if std::env::var_os("CLAUDE_CONFIG_DIR")
        .is_some_and(|path| Path::new(&path) != home.join(".claude"))
    {
        return Err(
            "Claude uses a different configuration directory; preserve that explicit setup workflow"
                .into(),
        );
    }
    activation_allowed(settings)
}

/// The only settings file a Claude handler edit may target.
pub(super) fn personal_settings_path(home: &Path) -> PathBuf {
    home.join(".claude").join("settings.json")
}

fn validate_activation(document: &Value) -> Result<(), String> {
    if document
        .get("disableAllHooks")
        .is_some_and(|value| value != &Value::Bool(false))
        || document
            .get("allowManagedHooksOnly")
            .is_some_and(|value| value != &Value::Bool(false))
    {
        return Err(
            "Claude settings disable personal command hooks; preserve that explicit policy".into(),
        );
    }
    Ok(())
}

fn select(document: &Value) -> Result<Selection, String> {
    let Some(hooks) = document.get("hooks") else {
        return Ok(Selection::default());
    };
    let hooks = hooks.as_object().ok_or("Claude hooks must be an object")?;
    let Some(event) = hooks.get("PreToolUse") else {
        return Ok(Selection::default());
    };
    let entries = event
        .as_array()
        .ok_or("Claude PreToolUse hooks must be an array")?;
    if entries.len() > MAX_MATCHERS {
        return Err("Claude settings exceed the matcher limit".into());
    }
    let mut selected = Selection::default();
    for (matcher_index, matcher) in entries.iter().enumerate() {
        let matcher = matcher
            .as_object()
            .ok_or("Claude matcher must be an object")?;
        let is_bash = matcher.get("matcher").and_then(Value::as_str) == Some("Bash");
        if is_bash && selected.matcher.replace(matcher_index).is_some() {
            return Err("multiple Claude Bash matchers require manual review".into());
        }
        let handlers = matcher
            .get("hooks")
            .and_then(Value::as_array)
            .ok_or("Claude matcher hooks must be an array")?;
        if handlers.len() > MAX_HANDLERS {
            return Err("Claude settings exceed the handler limit".into());
        }
        for (handler_index, handler) in handlers.iter().enumerate() {
            let handler = handler
                .as_object()
                .ok_or("Claude handler must be an object")?;
            if !handler
                .get("command")
                .and_then(Value::as_str)
                .is_some_and(|command| command.contains(MARKER))
            {
                continue;
            }
            if !is_bash
                || selected.handler.replace(handler_index).is_some()
                || handler.get("type").and_then(Value::as_str) != Some("command")
            {
                return Err("ambiguous or unsupported existing Tirith Claude handler; preserve manual setup".into());
            }
        }
    }
    Ok(selected)
}

fn handler<'a>(document: &'a Value, selected: &Selection) -> Option<&'a Value> {
    Some(&document["hooks"]["PreToolUse"][selected.matcher?]["hooks"][selected.handler?])
}

impl OwnedClaudeHandler {
    /// Candidate commands come only from the typed preparer. Existing commands
    /// must be the current intended command or an exact recognized legacy form;
    /// a marker substring never authorizes replacing an arbitrary manual hook.
    pub(crate) fn capture(
        before: Option<&str>,
        intended_command: &str,
        accepted_legacy: &[String],
    ) -> Result<Self, String> {
        if intended_command.len() > 16 * 1024 || !intended_command.contains(MARKER) {
            return Err("invalid prepared Claude command".into());
        }
        let value = document(before)?;
        validate_activation(&value)?;
        let selection = select(&value)?;
        let before = handler(&value, &selection).cloned();
        if let Some(previous) = &before {
            let command = previous["command"]
                .as_str()
                .ok_or("Claude handler command is not text")?;
            if command != intended_command && !accepted_legacy.iter().any(|known| command == known)
            {
                return Err("existing Tirith Claude handler was customized; preserve it and use explicit repair".into());
            }
            // These affect the blocking contract. Preserve unknown settings,
            // but never silently advertise a known asynchronous/short deadline
            // variant as the synchronously qualified command-hook scope.
            if previous
                .get("async")
                .is_some_and(|v| v != &Value::Bool(false))
                || previous
                    .get("timeout")
                    .is_some_and(|v| v.as_f64().is_none_or(|n| n < 30.0 || !n.is_finite()))
            {
                return Err(
                    "Claude handler has unsupported asynchronous or short timeout settings".into(),
                );
            }
        }
        let mut after = before.clone().unwrap_or_else(|| json!({"type":"command"}));
        after
            .as_object_mut()
            .expect("selected handler is an object")
            .insert("command".into(), Value::String(intended_command.into()));
        Ok(Self {
            before,
            after,
            created_hooks: value.get("hooks").is_none(),
            created_event: value.pointer("/hooks/PreToolUse").is_none(),
            created_matcher: selection.matcher.is_none(),
        })
    }

    pub(crate) fn is_noop(&self) -> bool {
        self.before.as_ref() == Some(&self.after)
    }

    pub(crate) fn matches(&self, current: Option<&str>, after: bool) -> Result<bool, String> {
        let value = document(current)?;
        let selection = select(&value)?;
        Ok(handler(&value, &selection)
            == if after {
                Some(&self.after)
            } else {
                self.before.as_ref()
            })
    }

    pub(crate) fn transform(
        &self,
        current: Option<&str>,
        undo: bool,
    ) -> Result<Option<String>, String> {
        if !undo {
            validate_activation(&document(current)?)?;
        }
        if self.matches(current, !undo)? {
            return Ok(None);
        }
        if !self.matches(current, undo)? {
            return Err(
                "refresh-required: owned Claude handler changed; manual settings were preserved"
                    .into(),
            );
        }
        let mut value = document(current)?;
        let selection = select(&value)?;
        let replacement = if undo {
            self.before.as_ref()
        } else {
            Some(&self.after)
        };
        let root = value.as_object_mut().expect("validated root");
        let hooks = root
            .entry("hooks")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .expect("validated hooks");
        let event = hooks
            .entry("PreToolUse")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .expect("validated event");
        let matcher = match selection.matcher {
            Some(index) => index,
            None => {
                event.push(json!({"matcher":"Bash","hooks":[]}));
                event.len() - 1
            }
        };
        let handlers = event[matcher]["hooks"]
            .as_array_mut()
            .expect("validated handlers");
        match (selection.handler, replacement) {
            (Some(index), Some(replacement)) => handlers[index] = replacement.clone(),
            (Some(index), None) => {
                handlers.remove(index);
            }
            (None, Some(replacement)) => handlers.push(replacement.clone()),
            (None, None) => unreachable!("matching absence returned unchanged"),
        }
        if undo
            && self.created_matcher
            && handlers.is_empty()
            && event[matcher]
                .as_object()
                .is_some_and(|value| value.len() == 2)
        {
            event.remove(matcher);
        }
        if undo && self.created_event && event.is_empty() {
            hooks.remove("PreToolUse");
        }
        if undo && self.created_hooks && hooks.is_empty() {
            root.remove("hooks");
        }
        // Same serialization as the explicit `merge_claude_settings` writer
        // (pretty JSON, no trailing newline), so both paths write equal bytes.
        let output =
            serde_json::to_string_pretty(&value).map_err(|_| "cannot serialize Claude settings")?;
        if output.len() > MAX_SETTINGS_BYTES {
            return Err("resulting Claude settings exceed one MiB".into());
        }
        Ok(Some(output))
    }
}

fn read(path: &Path, home: &Path) -> Result<Option<String>, String> {
    super::fs_helpers::read_snapshot_scoped_capped(path, home, MAX_SETTINGS_BYTES)?
        .bytes
        .map(|bytes| {
            String::from_utf8(bytes).map_err(|_| "Claude configuration is not UTF-8".into())
        })
        .transpose()
}

/// SHA-256 of the hook script that `tirith setup claude-code` wrote in
/// v0.4.0, v0.4.1 and v0.4.2 (identical bytes in all three). Recommended setup
/// replaces exactly this script in place, and undo restores it byte for byte.
/// Any other existing content is manual and is refused.
const SHIPPED_HOOK_SHA256: &str =
    "78363cadc752fcf26fa20aa6cf34c215403d9905f555b33743cdb4fd032772af";

fn is_shipped_hook(text: &str) -> bool {
    use sha2::{Digest as _, Sha256};
    format!("{:x}", Sha256::digest(text.as_bytes())) == SHIPPED_HOOK_SHA256
}

/// The personal Claude step of recommended setup: stage the embedded hook
/// script, then activate the owned Bash handler in `~/.claude/settings.json`.
pub(crate) struct PreparedClaude {
    pub snapshot: EffectivePolicySnapshot,
    home: PathBuf,
    settings: PathBuf,
    hook: PathBuf,
    before_settings: Option<String>,
    before_hook: Option<String>,
    handler: OwnedClaudeHandler,
}

pub(crate) type PreparedClaudeParts = (Vec<RequestedChange>, BTreeMap<PathBuf, Option<String>>);

impl PreparedClaude {
    pub(crate) fn capture(cwd: Option<&str>) -> Result<Self, String> {
        if cfg!(not(unix)) {
            // The fail-closed `|| exit 2` wrapper is POSIX-only.
            return Err("combined Claude setup is not available on this platform; run `tirith setup claude-code` instead".into());
        }
        let target = shell_target::resolve_for_shell("unknown")?;
        shell_target::require_personal_writer(&target)?;
        let snapshot = EffectivePolicySnapshot::resolve(cwd, ResolutionMode::Runtime);
        snapshot
            .revalidate_for_mutation()
            .map_err(|e| e.to_string())?;
        // Same trusted, upgrade-stable launcher the explicit setup persists.
        let python = super::run_impl::resolve_hook_dependency(&["python3"], "Python", false)?
            .ok_or("Python is required — install Python and retry")?;
        Self::prepare(snapshot, target.operator_home, &python)
    }

    fn prepare(
        snapshot: EffectivePolicySnapshot,
        home: PathBuf,
        python: &str,
    ) -> Result<Self, String> {
        let settings = personal_settings_path(&home);
        let hook = home.join(".claude").join("hooks").join("tirith-check.py");
        let before_settings = read(&settings, &home)?;
        let before_hook = read(&hook, &home)?;
        personal_activation_allowed(&home, before_settings.as_deref())?;
        if before_hook.as_deref().is_some_and(|text| {
            !text.is_empty() && text != crate::assets::TIRITH_CHECK_PY && !is_shipped_hook(text)
        }) {
            return Err("existing Claude hook script differs from this embedded candidate; preserve manual content and review explicit repair".into());
        }
        let python = super::shell_profile::shell_quote(python, "bash");
        let intended = super::tools::claude_user_hook_command(&python);
        let legacy = [super::tools::claude_user_hook_command_without_wrapper(
            &python,
        )];
        let handler = OwnedClaudeHandler::capture(before_settings.as_deref(), &intended, &legacy)?;
        snapshot.revalidate_inputs().map_err(|e| e.to_string())?;
        Ok(Self {
            snapshot,
            home,
            settings,
            hook,
            before_settings,
            before_hook,
            handler,
        })
    }

    pub(crate) fn setup_parts(&self) -> Result<PreparedClaudeParts, String> {
        self.snapshot
            .revalidate_inputs()
            .map_err(|e| e.to_string())?;
        if self.handler.is_noop()
            && self.before_hook.as_deref() == Some(crate::assets::TIRITH_CHECK_PY)
        {
            return Ok((Vec::new(), BTreeMap::new()));
        }
        // Retain the already-current script as an inactive step too: activation
        // must not accept an intervening change merely because staging was a no-op.
        let requests = vec![
            RequestedChange {
                target: self.hook.clone(),
                scope_root: self.home.clone(),
                edit: Edit::ExecutableFile(crate::assets::TIRITH_CHECK_PY.into()),
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
        ))
    }

    pub(crate) fn projection(&self) -> serde_json::Value {
        // Canonical protocol facts only. Private config bytes and paths stay in
        // the prepared object/journal, never the browser.
        serde_json::json!({"kind":"claude_setup_preview","scope":"user","tool_scope":"Bash","host":"claude-code","applied":false,"reload_required":true,"verified_blocking":false,"verification_source":"configuration_only","preserves_unrelated_settings":true})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const COMMAND: &str = "TIRITH_BIN='/fixture/tirith' '/fixture/python3' '/fixture/.claude/hooks/tirith-check.py' || exit 2";
    #[test]
    fn preserves_unknown_settings_and_other_hooks_across_apply_and_undo() {
        let original = json!({"theme":"dark","future_setting":{"nested":[1,2]},"hooks":{"SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":"echo other"}]}],"PreToolUse":[{"matcher":"Bash","future_matcher":true,"hooks":[{"type":"command","command":"echo manual"}]}]}});
        let text = original.to_string();
        let edit = OwnedClaudeHandler::capture(Some(&text), COMMAND, &[]).unwrap();
        let applied = edit.transform(Some(&text), false).unwrap().unwrap();
        let mut changed: Value = serde_json::from_str(&applied).unwrap();
        changed["unrelated_later"] = json!({"preserved":true});
        let undone = edit
            .transform(Some(&changed.to_string()), true)
            .unwrap()
            .unwrap();
        let mut expected = original;
        expected["unrelated_later"] = json!({"preserved":true});
        assert_eq!(serde_json::from_str::<Value>(&undone).unwrap(), expected);
    }
    #[test]
    fn known_legacy_upgrade_preserves_extra_handler_fields_and_rejects_manual_edits() {
        let legacy = "'/fixture/python3' '/fixture/.claude/hooks/tirith-check.py' || exit 2";
        let before=json!({"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":legacy,"timeout":600,"future_field":"keep"}]}]}}).to_string();
        let edit = OwnedClaudeHandler::capture(Some(&before), COMMAND, &[legacy.into()]).unwrap();
        let after = edit.transform(Some(&before), false).unwrap().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&after).unwrap()["hooks"]["PreToolUse"][0]["hooks"][0]
                ["future_field"],
            "keep"
        );
        let mut altered: Value = serde_json::from_str(&after).unwrap();
        altered["hooks"]["PreToolUse"][0]["hooks"][0]["future_field"] = json!("manual change");
        assert!(edit.transform(Some(&altered.to_string()), true).is_err());
        assert_eq!(
            serde_json::from_str::<Value>(&edit.transform(Some(&after), true).unwrap().unwrap())
                .unwrap(),
            serde_json::from_str::<Value>(&before).unwrap()
        );
    }
    #[test]
    fn duplicate_or_ambiguous_configuration_is_refused() {
        for raw in [
            r#"{"hooks":{},"hooks":{}}"#,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[]},{"matcher":"Bash","hooks":[]}]}}"#,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Write","hooks":[{"type":"command","command":"tirith-check.py"}]}]}}"#,
        ] {
            assert!(OwnedClaudeHandler::capture(Some(raw), COMMAND, &[]).is_err());
        }
        let duplicate = json!({"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":COMMAND},{"type":"command","command":COMMAND}]}]}});
        assert!(OwnedClaudeHandler::capture(Some(&duplicate.to_string()), COMMAND, &[]).is_err());
    }
    #[test]
    fn new_handler_compensation_removes_only_empty_created_containers() {
        let edit = OwnedClaudeHandler::capture(None, COMMAND, &[]).unwrap();
        let after = edit.transform(None, false).unwrap().unwrap();
        assert_eq!(edit.transform(Some(&after), false).unwrap(), None);
        assert_eq!(
            serde_json::from_str::<Value>(&edit.transform(Some(&after), true).unwrap().unwrap())
                .unwrap(),
            json!({})
        );
        let mut changed: Value = serde_json::from_str(&after).unwrap();
        changed["hooks"]["PreToolUse"][0]["hooks"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"command","command":"echo later"}));
        let undone = edit
            .transform(Some(&changed.to_string()), true)
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&undone).unwrap(),
            json!({"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo later"}]}]}})
        );
    }
    #[test]
    fn manual_commands_and_blocking_contract_overrides_are_not_overwritten() {
        for extra in [
            json!({"command":"custom tirith-check.py"}),
            json!({"command":COMMAND,"async":true}),
            json!({"command":COMMAND,"timeout":1}),
        ] {
            let mut handler = extra;
            handler["type"] = json!("command");
            let before = json!({"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[handler]}]}});
            assert!(OwnedClaudeHandler::capture(Some(&before.to_string()), COMMAND, &[]).is_err());
        }
    }
    // ---- recommended-setup preparer (journaled, unpinned) ----

    #[cfg(unix)]
    const PYTHON: &str = "/usr/bin/python3";

    #[cfg(unix)]
    fn prepared(home: &std::path::Path) -> Result<PreparedClaude, String> {
        PreparedClaude::prepare(
            EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime),
            home.into(),
            PYTHON,
        )
    }

    #[cfg(unix)]
    fn plan(prepared: &PreparedClaude, id: &str) -> super::super::change_plan::OperationStatus {
        use super::super::change_plan::{MutationService, OperationKind};
        let (requests, preimages) = prepared.setup_parts().unwrap();
        MutationService::current()
            .unwrap()
            .plan_with_preimages_and_intent(
                id,
                OperationKind::RecommendedSetup,
                requests,
                &prepared.snapshot,
                &preimages,
                &serde_json::json!({"agent":"claude-code"}),
            )
            .unwrap()
    }

    #[cfg(unix)]
    fn apply(prepared: &PreparedClaude) {
        use super::super::change_plan::{JobState, MutationService};
        let id = uuid::Uuid::new_v4().to_string();
        plan(prepared, &id);
        assert_eq!(
            MutationService::current()
                .unwrap()
                .apply(&id, &prepared.snapshot)
                .unwrap()
                .state,
            JobState::Completed
        );
    }

    #[cfg(unix)]
    fn explicit_setup(python: &str) {
        use super::super::run_impl::{Scope, SetupOpts};
        super::super::tools::setup_claude_code(&SetupOpts {
            scope: Scope::User,
            with_mcp: false,
            install_zshenv: false,
            dry_run: false,
            force: false,
            tirith_bin: "/opt/tirith/bin/tirith".into(),
            python_bin: Some(python.into()),
            update_configs: false,
        })
        .unwrap();
    }

    /// (settings bytes, settings mode, hook bytes, hook mode)
    #[cfg(unix)]
    fn written(home: &std::path::Path) -> (Vec<u8>, u32, Vec<u8>, u32) {
        use std::os::unix::fs::PermissionsExt as _;
        let settings = home.join(".claude/settings.json");
        let hook = home.join(".claude/hooks/tirith-check.py");
        let mode =
            |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;
        (
            std::fs::read(&settings).unwrap(),
            mode(&settings),
            std::fs::read(&hook).unwrap(),
            mode(&hook),
        )
    }

    #[cfg(unix)]
    #[test]
    fn recommended_command_is_the_explicit_user_scope_command() {
        use super::super::run_impl::{Scope, SetupOpts};
        crate::cli::test_harness::with_fake_env(true, |home, _| {
            let prepared = prepared(home).unwrap();
            let explicit = super::super::tools::claude_hook_command_for_test(&SetupOpts {
                scope: Scope::User,
                with_mcp: false,
                install_zshenv: false,
                dry_run: false,
                force: false,
                tirith_bin: "/opt/tirith/bin/tirith".into(),
                python_bin: Some(PYTHON.into()),
                update_configs: false,
            })
            .unwrap();
            assert_eq!(
                prepared.handler.after["command"].as_str().unwrap(),
                explicit
            );
            assert_eq!(
                explicit,
                format!(r#"{PYTHON} "$HOME/.claude/hooks/tirith-check.py" || exit 2"#)
            );
            // No pinned binary, runtime or isolated-mode flags in the command.
            assert!(!explicit.contains("TIRITH_BIN") && !explicit.contains(" -I "));
            // The preview reports no host version: nothing is version-pinned.
            assert!(prepared.projection().get("host_version").is_none());
        });
    }

    #[cfg(unix)]
    #[test]
    fn recommended_and_explicit_setup_write_identical_bytes_and_modes() {
        let explicit = crate::cli::test_harness::with_fake_env(true, |home, _| {
            explicit_setup(PYTHON);
            written(home)
        });
        let recommended = crate::cli::test_harness::with_fake_env(true, |home, _| {
            apply(&prepared(home).unwrap());
            written(home)
        });
        assert_eq!(
            String::from_utf8(recommended.0.clone()).unwrap(),
            String::from_utf8(explicit.0.clone()).unwrap()
        );
        assert_eq!(recommended, explicit);
        assert_eq!(explicit.1, 0o644);
        assert_eq!(explicit.3, 0o755);
        assert_eq!(explicit.2, crate::assets::TIRITH_CHECK_PY.as_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn explicit_then_recommended_is_a_noop_and_recommended_then_explicit_is_up_to_date() {
        crate::cli::test_harness::with_fake_env(true, |home, _| {
            explicit_setup(PYTHON);
            let before = written(home);
            let (requests, preimages) = prepared(home).unwrap().setup_parts().unwrap();
            assert!(requests.is_empty() && preimages.is_empty());
            assert_eq!(written(home), before);
        });
        crate::cli::test_harness::with_fake_env(true, |home, _| {
            apply(&prepared(home).unwrap());
            let before = written(home);
            explicit_setup(PYTHON);
            assert_eq!(written(home), before);
            let (requests, _) = prepared(home).unwrap().setup_parts().unwrap();
            assert!(requests.is_empty());
        });
    }

    #[cfg(unix)]
    #[test]
    fn shipped_command_without_fail_closed_wrapper_is_upgraded_in_place() {
        use super::super::change_plan::{JobState, MutationService};
        // The hook script exactly as `tirith setup claude-code` wrote it in
        // v0.4.0-v0.4.2, next to the command those releases wrote.
        const SHIPPED_HOOK: &str =
            include_str!("../../../../../tests/fixtures/cycle-0.4.2/claude-tirith-check.py");
        assert_ne!(SHIPPED_HOOK, crate::assets::TIRITH_CHECK_PY);
        crate::cli::test_harness::with_fake_env(true, |home, _| {
            std::fs::create_dir_all(home.join(".claude/hooks")).unwrap();
            let legacy = format!(r#"{PYTHON} "$HOME/.claude/hooks/tirith-check.py""#);
            let settings_path = home.join(".claude/settings.json");
            let hook_path = home.join(".claude/hooks/tirith-check.py");
            let before_settings = json!({"theme":"dark","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":legacy}]}]}}).to_string();
            std::fs::write(&settings_path, &before_settings).unwrap();
            std::fs::write(&hook_path, SHIPPED_HOOK).unwrap();
            let prepared = prepared(home).unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            plan(&prepared, &id);
            let service = MutationService::current().unwrap();
            assert_eq!(
                service.apply(&id, &prepared.snapshot).unwrap().state,
                JobState::Completed
            );
            let settings: Value =
                serde_json::from_slice(&std::fs::read(&settings_path).unwrap()).unwrap();
            assert_eq!(settings["theme"], "dark");
            assert_eq!(
                settings["hooks"]["PreToolUse"][0]["hooks"],
                json!([{"type":"command","command":format!("{legacy} || exit 2")}])
            );
            assert_eq!(
                std::fs::read_to_string(&hook_path).unwrap(),
                crate::assets::TIRITH_CHECK_PY
            );
            // Undo restores the shipped bytes exactly.
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
            assert_eq!(std::fs::read_to_string(&hook_path).unwrap(), SHIPPED_HOOK);
            assert_eq!(
                serde_json::from_slice::<Value>(&std::fs::read(&settings_path).unwrap()).unwrap(),
                serde_json::from_str::<Value>(&before_settings).unwrap()
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn shared_plan_stages_before_activation_and_compensates_only_owned_handler() {
        use super::super::change_plan::{JobState, MutationService};
        crate::cli::test_harness::with_fake_env(true, |home, _| {
            let prepared = prepared(home).unwrap();
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
            let mut settings: Value =
                serde_json::from_str(&std::fs::read_to_string(&prepared.settings).unwrap())
                    .unwrap();
            settings["extra"] = json!({"kept":true});
            settings["hooks"]["PreToolUse"]
                .as_array_mut()
                .unwrap()
                .push(json!({"matcher":"Read", "hooks":[{"type":"command","command":"manual"}]}));
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
            let restored: Value =
                serde_json::from_str(&std::fs::read_to_string(&prepared.settings).unwrap())
                    .unwrap();
            assert_eq!(
                restored,
                json!({"extra":{"kept":true},"hooks":{"PreToolUse":[{"matcher":"Read","hooks":[{"type":"command","command":"manual"}]}]}})
            );
            assert_eq!(std::fs::read(&prepared.hook).unwrap(), b"");
        });
    }

    #[cfg(unix)]
    #[test]
    fn cancellation_never_activates_a_prepared_agent() {
        use super::super::change_plan::{JobState, MutationService};
        crate::cli::test_harness::with_fake_env(true, |home, _| {
            let prepared = prepared(home).unwrap();
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
    fn manual_disable_or_config_dir_override_refuses_before_staging() {
        use super::super::change_plan::{JobState, MutationService};
        for config_dir_override in [false, true] {
            crate::cli::test_harness::with_fake_env(true, |home, _| {
                let prepared = prepared(home).unwrap();
                let id = uuid::Uuid::new_v4().to_string();
                plan(&prepared, &id);
                let _guard = config_dir_override.then(|| {
                    crate::cli::test_harness::EnvGuard::set(
                        "CLAUDE_CONFIG_DIR",
                        &home.join("elsewhere"),
                    )
                });
                if !config_dir_override {
                    std::fs::create_dir_all(prepared.settings.parent().unwrap()).unwrap();
                    std::fs::write(&prepared.settings, r#"{"disableAllHooks":true}"#).unwrap();
                }
                let state = MutationService::current()
                    .unwrap()
                    .apply(&id, &prepared.snapshot)
                    .unwrap();
                assert_eq!(state.state, JobState::RefreshRequired);
                assert!(!prepared.hook.exists());
                // Preparation refuses the same boundary up front.
                assert!(prepared_refuses(home));
            });
        }
    }

    #[cfg(unix)]
    fn prepared_refuses(home: &std::path::Path) -> bool {
        prepared(home).is_err()
    }

    #[cfg(unix)]
    #[test]
    fn owned_handler_conflict_preserves_the_manual_change() {
        use super::super::change_plan::{JobState, MutationService};
        crate::cli::test_harness::with_fake_env(true, |home, _| {
            let prepared = prepared(home).unwrap();
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

    #[cfg(unix)]
    #[test]
    fn divergent_hook_script_and_customized_handler_refuse_preparation() {
        crate::cli::test_harness::with_fake_env(true, |home, _| {
            std::fs::create_dir_all(home.join(".claude/hooks")).unwrap();
            std::fs::write(home.join(".claude/hooks/tirith-check.py"), "# manual\n").unwrap();
            assert!(prepared(home).is_err());
            std::fs::remove_file(home.join(".claude/hooks/tirith-check.py")).unwrap();
            std::fs::write(
                home.join(".claude/settings.json"),
                r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"python3 custom/tirith-check.py"}]}]}}"#,
            )
            .unwrap();
            assert!(prepared(home).err().unwrap().contains("customized"));
        });
    }

    #[test]
    fn later_hook_disable_refuses_apply_but_is_preserved_by_compensation() {
        for flag in ["disableAllHooks", "allowManagedHooksOnly"] {
            let edit =
                OwnedClaudeHandler::capture(None, "python /owned/tirith-check.py", &[]).unwrap();
            let disabled = serde_json::json!({flag:true});
            assert!(edit.transform(Some(&disabled.to_string()), false).is_err());
            let applied = edit.transform(None, false).unwrap().unwrap();
            let mut disabled_after: Value = serde_json::from_str(&applied).unwrap();
            disabled_after[flag] = Value::Bool(true);
            let undone = edit
                .transform(Some(&disabled_after.to_string()), true)
                .unwrap()
                .unwrap();
            assert_eq!(serde_json::from_str::<Value>(&undone).unwrap(), disabled);
        }
    }
}
