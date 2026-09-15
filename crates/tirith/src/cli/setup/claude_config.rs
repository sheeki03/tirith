//! Owned Claude command-handler edits. Other settings, matchers and hooks are
//! preserved semantically; the one owned handler has an exact pre/postimage.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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

pub(super) fn activation_allowed(text: Option<&str>) -> Result<(), String> {
    validate_activation(&document(text)?)
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
        let output =
            serde_json::to_string_pretty(&value).map_err(|_| "cannot serialize Claude settings")?;
        if output.len() > MAX_SETTINGS_BYTES {
            return Err("resulting Claude settings exceed one MiB".into());
        }
        Ok(Some(format!("{output}\n")))
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
