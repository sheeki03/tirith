//! Shared profile preparation for CLI and local browser controls. Only the
//! versioned preset name is accepted; paths and owned-field edits are derived here.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
use tirith_core::protection_profiles::{self, ProfileChange, ProfilePreview, ProtectionProfile};

use super::managed_policy::ProfileScope;
use super::setup::change_plan::{
    Edit, MutationService, OperationKind, OperationStatus, RequestedChange,
};

pub(crate) type PreparedProfileParts = (Vec<RequestedChange>, BTreeMap<PathBuf, Option<String>>);

#[derive(Serialize)]
struct ProfileIntent {
    profile: String,
    scope: &'static str,
    cwd: Option<String>,
}

pub(crate) struct PreparedProfile {
    pub snapshot: EffectivePolicySnapshot,
    pub preview: ProfilePreview,
    pub compiled: tirith_core::redact::CompiledCustomPatterns,
    path: PathBuf,
    config: PathBuf,
    original: serde_yaml::Value,
    original_text: Option<String>,
    intent: ProfileIntent,
    scope: ProfileScope,
}

fn intent(name: &str, cwd: Option<&str>) -> ProfileIntent {
    ProfileIntent {
        profile: name.into(),
        scope: "user",
        cwd: cwd.map(str::to_owned).or_else(|| {
            std::env::current_dir()
                .ok()
                .map(|path| path.display().to_string())
        }),
    }
}

impl PreparedProfile {
    pub fn capture(name: &str, cwd: Option<&str>) -> Result<Self, String> {
        Self::capture_scoped(name, cwd, ProfileScope::User)
    }

    pub(crate) fn capture_scoped(
        name: &str,
        cwd: Option<&str>,
        scope: ProfileScope,
    ) -> Result<Self, String> {
        if cwd.is_some_and(|value| !Path::new(value).is_absolute()) {
            return Err("profile project scope must be absolute".into());
        }
        let change = if name == "reset" {
            ProfileChange::Reset
        } else {
            ProfileChange::Apply(
                ProtectionProfile::parse(name)
                    .ok_or("profile must be comfortable, balanced, strict, or reset")?,
            )
        };
        let operator = super::shell_target::resolve_for_shell("unknown")?;
        super::shell_target::require_personal_writer(&operator)?;
        let mut intent = intent(name, cwd);
        intent.scope = scope.as_str();
        let snapshot =
            EffectivePolicySnapshot::resolve(intent.cwd.as_deref(), ResolutionMode::Runtime);
        let (config, path) = match scope {
            ProfileScope::User => {
                let config = tirith_core::policy::config_dir()
                    .ok_or("cannot locate the operator policy directory")?;
                let path = personal_policy_path(&config)?;
                (config, path)
            }
            ProfileScope::Org => super::managed_policy::selected_target(&snapshot)?,
        };
        let original_text = match tirith_core::util::read_text_no_follow_capped(&path, 1024 * 1024)
        {
            Ok(bytes) => Some(
                String::from_utf8(bytes).map_err(|_| "existing selected policy is not UTF-8")?,
            ),
            Err(tirith_core::util::OpenRegularError::NotFound) => None,
            Err(_) => {
                return Err("selected policy is unreadable, non-regular, or exceeds 1 MiB".into())
            }
        };
        let original = original_text
            .as_deref()
            .map(serde_yaml::from_str::<serde_yaml::Value>)
            .transpose()
            .map_err(|_| {
                "existing selected policy is invalid YAML; repair it before applying a profile"
            })?
            .unwrap_or_else(|| serde_yaml::Value::Mapping(Default::default()));
        let mut patterns = tirith_core::policy::captured_policy_dlp_patterns_or(
            &snapshot.policy.dlp_custom_patterns,
        );
        if let Some(values) = original
            .get("dlp_custom_patterns")
            .and_then(serde_yaml::Value::as_sequence)
        {
            patterns.extend(
                values
                    .iter()
                    .filter_map(serde_yaml::Value::as_str)
                    .map(str::to_owned),
            );
        }
        tirith_core::policy::freeze_captured_policy_dlp_patterns(&patterns);
        let preview = protection_profiles::prepare_change(&original, change)
            .map_err(|error| tirith_core::redact::redact_sanitize_redact(&error, &patterns))?;
        patterns.extend(
            preview
                .policy()
                .map_err(|error| tirith_core::redact::redact_sanitize_redact(&error, &patterns))?
                .dlp_custom_patterns,
        );
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&patterns);
        Ok(Self {
            snapshot,
            preview,
            compiled,
            path,
            config,
            original,
            original_text,
            intent,
            scope,
        })
    }

    pub fn projection(&self) -> serde_json::Value {
        let changes: Vec<_> = self
            .preview
            .changes
            .iter()
            .map(|change| {
                let display = |document: &serde_yaml::Value| {
                    let value = change
                        .field
                        .split('.')
                        .try_fold(document, |value, field| value.get(field));
                    let mut value = value
                        .and_then(|value| serde_json::to_value(value).ok())
                        .unwrap_or(serde_json::Value::Null);
                    tirith_core::redact::redact_json_strings(&mut value, &self.compiled);
                    value
                };
                serde_json::json!({"field": change.field, "operation": change.operation,
                "before": display(&self.original), "after": display(self.preview.document())})
            })
            .collect();
        let definition = self.preview.selection.as_ref().and_then(|selection| {
            protection_profiles::definition(selection.name, selection.version).ok()
        });
        serde_json::json!({"schema_version": 1, "kind": "profile_preview", "applied": false,
            "target": tirith_core::redact::redact_with_compiled(&self.path.display().to_string(), &self.compiled),
            "previous": self.preview.previous, "selection": self.preview.selection,
            "changes": self.preview.changes, "custom_overrides": self.preview.custom_overrides,
            "field_changes": changes, "definition": definition,
            "policy_identity": self.snapshot.identity, "effective_settings_may_be_constrained": true})
    }

    pub fn plan(&self, id: &str) -> Result<Option<OperationStatus>, String> {
        self.plan_bound(id, &self.intent, None)
    }

    pub(crate) fn plan_with_rollout_review(
        &self,
        id: &str,
        intent: &impl Serialize,
        review: tirith_core::policy_rollout::ImpactReport,
    ) -> Result<OperationStatus, String> {
        self.plan_bound(id, intent, Some(review))?
            .ok_or_else(|| "rollout preparation did not produce a durable outcome".into())
    }

    fn plan_bound(
        &self,
        id: &str,
        intent: &impl Serialize,
        review: Option<tirith_core::policy_rollout::ImpactReport>,
    ) -> Result<Option<OperationStatus>, String> {
        let service = MutationService::current()?;
        if let Some(status) = service.status_for_intent(id, self.scope.operation_kind(), intent)? {
            return Ok(Some(status));
        }
        let (changes, expected) = self.setup_parts()?;
        if changes.is_empty() {
            if let Some(review) = review {
                return service
                    .complete_noop_with_intent_and_review(
                        id,
                        self.scope.operation_kind(),
                        &self.snapshot,
                        intent,
                        review,
                    )
                    .map(Some);
            }
            return service
                .complete_noop_with_intent(id, self.scope.operation_kind(), &self.snapshot, intent)
                .map(Some);
        }
        let result = if let Some(review) = review {
            service.plan_with_preimages_intent_and_review(
                id,
                self.scope.operation_kind(),
                super::setup::change_plan::PlanChanges {
                    requests: changes,
                    preimages: &expected,
                },
                &self.snapshot,
                intent,
                review,
            )
        } else {
            service.plan_with_preimages_and_intent(
                id,
                self.scope.operation_kind(),
                changes,
                &self.snapshot,
                &expected,
                intent,
            )
        };
        result.map(Some).map_err(|error| {
            tirith_core::redact::redact_sanitize_redact_with_compiled(&error, &self.compiled)
        })
    }

    /// Reuse the exact prepared field materialization in a combined setup
    /// operation. The caller must bind this snapshot and these full preimages in
    /// the shared mutation journal; this method does not publish any state.
    pub(crate) fn setup_parts(&self) -> Result<PreparedProfileParts, String> {
        self.snapshot
            .revalidate_inputs()
            .map_err(|_| "policy changed while preparing profile; refresh the preview")?;
        let before =
            serde_json::to_value(&self.original).map_err(|_| "cannot project existing policy")?;
        let after = serde_json::to_value(self.preview.document())
            .map_err(|_| "cannot project requested policy")?;
        let mut fields = BTreeMap::new();
        for field in self
            .preview
            .changes
            .iter()
            .map(|change| change.field.as_str())
            .chain(std::iter::once("protection_profile"))
        {
            let pointer = format!(
                "/{}",
                field
                    .split('.')
                    .map(|part| part.replace('~', "~0").replace('/', "~1"))
                    .collect::<Vec<_>>()
                    .join("/")
            );
            if before.pointer(&pointer) != after.pointer(&pointer) {
                fields.insert(pointer.clone(), after.pointer(&pointer).cloned());
            }
        }
        if fields.is_empty() {
            return Ok((Vec::new(), BTreeMap::new()));
        }
        let expected = BTreeMap::from([(self.path.clone(), self.original_text.clone())]);
        let changes = vec![RequestedChange {
            target: self.path.clone(),
            scope_root: self.config.clone(),
            edit: Edit::YamlFields(fields),
            activation: true,
            description: format!(
                "Apply {} profile: {}",
                match self.scope {
                    ProfileScope::User => "personal",
                    ProfileScope::Org => "organization",
                },
                self.intent.profile
            ),
        }];
        Ok((changes, expected))
    }

    /// Apply only the preset-owned changes to the captured effective policy.
    /// Ambiguous managed/repository/incident composition is explicitly marked
    /// unavailable instead of replacing runtime restrictions with a local file.
    pub(crate) fn rollout_candidate(
        &self,
    ) -> Result<
        (
            tirith_core::policy::Policy,
            tirith_core::policy_rollout::CandidateCoverage,
        ),
        String,
    > {
        use tirith_core::policy_rollout::CandidateCoverage;
        let personal = self.preview.policy()?;
        let mut candidate = self.snapshot.policy.clone();
        let mut coverage = CandidateCoverage::EffectivePolicy;
        let target_effective = self
            .snapshot
            .operator_targets
            .iter()
            .find(|target| target.scope == self.scope.as_str())
            .is_some_and(|target| target.effective)
            && self.snapshot.remote.availability == "not_configured";
        for change in &self.preview.changes {
            let constrained = !target_effective
                || self
                    .snapshot
                    .field_provenance
                    .get(&change.field)
                    .is_some_and(|provenance| {
                        provenance.contributions.iter().any(|contribution| {
                            contribution.source.kind != "default"
                                && contribution.source.kind != self.scope.as_str()
                        })
                    });
            if constrained {
                coverage = CandidateCoverage::ManagedConstraintsUnresolved;
                continue;
            }
            match change.field.as_str() {
                "fail_mode" => candidate.fail_mode = personal.fail_mode,
                "allow_bypass_env" => candidate.allow_bypass_env = personal.allow_bypass_env,
                "allow_bypass_env_noninteractive" => {
                    candidate.allow_bypass_env_noninteractive =
                        personal.allow_bypass_env_noninteractive
                }
                "paranoia" => candidate.paranoia = personal.paranoia,
                "strict_warn" => candidate.strict_warn = personal.strict_warn,
                "scan.require_complete" => {
                    candidate.scan.require_complete = personal.scan.require_complete
                }
                "approval_rules" => candidate.approval_rules = personal.approval_rules.clone(),
                field if field.starts_with("severity_overrides.") => {
                    let key = field.trim_start_matches("severity_overrides.");
                    if let Some(value) = personal.severity_overrides.get(key) {
                        candidate.severity_overrides.insert(key.into(), *value);
                    } else {
                        candidate.severity_overrides.remove(key);
                    }
                }
                field if field.starts_with("action_overrides.") => {
                    let key = field.trim_start_matches("action_overrides.");
                    if let Some(value) = personal.action_overrides.get(key) {
                        candidate.action_overrides.insert(key.into(), value.clone());
                    } else {
                        candidate.action_overrides.remove(key);
                    }
                }
                _ => return Err("profile impact requires a newly supported setting model".into()),
            }
        }
        // Selection is descriptive; all runtime settings above retain their
        // captured overlay constraints. FrozenEvaluation ignores this metadata.
        candidate.protection_profile = self.preview.selection.clone();
        Ok((candidate, coverage))
    }
}

/// Follow the resolver's named-file precedence, retaining unreadable and
/// dangling entries for explicit refusal rather than creating a shadow policy.
fn personal_policy_path(config: &Path) -> Result<PathBuf, String> {
    for name in ["policy.yaml", "policy.yml"] {
        let path = config.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("cannot inspect existing personal policy".into()),
        }
    }
    Ok(config.join("policy.yaml"))
}

/// Store a plan without applying it. A lost-response retry finds the original
/// immutable intent before reading a new policy or regenerating derived values.
pub(crate) fn prepare(
    id: &str,
    name: &str,
    cwd: Option<&str>,
) -> Result<serde_json::Value, String> {
    uuid::Uuid::parse_str(id).map_err(|_| "operation ID must be a UUID")?;
    if name != "reset" && ProtectionProfile::parse(name).is_none() {
        return Err("unknown protection profile".into());
    }
    let service = MutationService::current()?;
    if let Some(status) =
        service.status_for_intent(id, OperationKind::SetProfile, &intent(name, cwd))?
    {
        let policy = EffectivePolicySnapshot::resolve(cwd, ResolutionMode::Runtime);
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(
            &tirith_core::policy::captured_policy_dlp_patterns_or(
                &policy.policy.dlp_custom_patterns,
            ),
        );
        return Ok(
            serde_json::json!({"schema_version": 1, "kind": "profile_plan", "applied": false, "reused": true,
            "operation": super::profile::status_projection(&status, &compiled)?}),
        );
    }
    let prepared = PreparedProfile::capture(name, cwd)?;
    let status = prepared.plan(id)?;
    Ok(
        serde_json::json!({"schema_version": 1, "kind": "profile_plan", "applied": false, "reused": false,
        "unchanged": status.as_ref().is_none_or(|status| status.no_op), "preview": prepared.projection(),
        "operation": status.as_ref().map(|status| super::profile::status_projection(status, &prepared.compiled)).transpose()?}),
    )
}

/// Each setting is a typed, personal-policy operation. Browser input cannot
/// choose a file, field pointer, shell command, or organization destination.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "setting", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum PersonalSettingChange {
    StrictWarn {
        #[serde(deserialize_with = "required_nullable")]
        value: Option<bool>,
    },
    AllowBypassEnv {
        #[serde(deserialize_with = "required_nullable")]
        value: Option<bool>,
    },
    AllowBypassEnvNoninteractive {
        #[serde(deserialize_with = "required_nullable")]
        value: Option<bool>,
    },
    ScanRequireComplete {
        #[serde(deserialize_with = "required_nullable")]
        value: Option<bool>,
    },
    EnvGuardEnabled {
        #[serde(deserialize_with = "required_nullable")]
        value: Option<bool>,
    },
    ContextGuardEnabled {
        #[serde(deserialize_with = "required_nullable")]
        value: Option<bool>,
    },
    ExecGuardEnabled {
        #[serde(deserialize_with = "required_nullable")]
        value: Option<bool>,
    },
    HooksGuardEnabled {
        #[serde(deserialize_with = "required_nullable")]
        value: Option<bool>,
    },
    BaselineEnabled {
        #[serde(deserialize_with = "required_nullable")]
        value: Option<bool>,
    },
    McpRedactInjection {
        #[serde(deserialize_with = "required_nullable")]
        value: Option<bool>,
    },
    FailMode {
        #[serde(deserialize_with = "required_nullable")]
        value: Option<tirith_core::policy::FailMode>,
    },
    Paranoia {
        #[serde(deserialize_with = "required_nullable")]
        value: Option<u8>,
    },
    RuleSeverity {
        rule: tirith_core::verdict::RuleId,
        #[serde(deserialize_with = "required_nullable")]
        value: Option<tirith_core::verdict::Severity>,
    },
}

fn required_nullable<'de, T: serde::de::DeserializeOwned, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    serde_json::from_value(value).map_err(serde::de::Error::custom)
}

impl PersonalSettingChange {
    fn field_value(&self) -> Result<(String, Option<serde_json::Value>), String> {
        use PersonalSettingChange::*;
        let (field, value) = match self {
            StrictWarn { value } => ("strict_warn", serde_json::to_value(value)),
            AllowBypassEnv { value } => ("allow_bypass_env", serde_json::to_value(value)),
            AllowBypassEnvNoninteractive { value } => (
                "allow_bypass_env_noninteractive",
                serde_json::to_value(value),
            ),
            ScanRequireComplete { value } => ("scan.require_complete", serde_json::to_value(value)),
            EnvGuardEnabled { value } => ("env_guard_enabled", serde_json::to_value(value)),
            ContextGuardEnabled { value } => ("context_guard_enabled", serde_json::to_value(value)),
            ExecGuardEnabled { value } => ("exec_guard_enabled", serde_json::to_value(value)),
            HooksGuardEnabled { value } => ("hooks_guard_enabled", serde_json::to_value(value)),
            BaselineEnabled { value } => ("baseline_enabled", serde_json::to_value(value)),
            McpRedactInjection { value } => ("mcp_redact_injection", serde_json::to_value(value)),
            FailMode { value } => ("fail_mode", serde_json::to_value(value)),
            Paranoia { value } => {
                if value.is_some_and(|value| !(1..=4).contains(&value)) {
                    return Err("paranoia must be between 1 and 4".into());
                }
                ("paranoia", serde_json::to_value(value))
            }
            RuleSeverity { rule, value } => {
                let rule = serde_json::to_value(rule).map_err(|_| "cannot encode rule ID")?;
                let value = serde_json::to_value(value).map_err(|_| "cannot encode severity")?;
                return Ok((
                    format!(
                        "severity_overrides.{}",
                        rule.as_str().ok_or("invalid canonical rule ID")?
                    ),
                    (!value.is_null()).then_some(value),
                ));
            }
        };
        let value = value.map_err(|_| "cannot encode setting")?;
        Ok((field.into(), (!value.is_null()).then_some(value)))
    }
}

#[derive(Serialize)]
struct SettingIntent {
    scope: &'static str,
    cwd: Option<String>,
    change: PersonalSettingChange,
}

struct PreparedSetting {
    base: PreparedProfile,
    intent: SettingIntent,
    fields: BTreeMap<String, Option<serde_json::Value>>,
    field: String,
    before: serde_json::Value,
    after: serde_json::Value,
}

fn pointer(field: &str) -> String {
    format!(
        "/{}",
        field
            .split('.')
            .map(|part| part.replace('~', "~0").replace('/', "~1"))
            .collect::<Vec<_>>()
            .join("/")
    )
}

fn edit_field(
    document: &mut serde_json::Value,
    field: &str,
    value: Option<serde_json::Value>,
) -> Result<(), String> {
    let parts: Vec<_> = field.split('.').collect();
    let mut current = document;
    for part in &parts[..parts.len() - 1] {
        if value.is_none() && current.get(*part).is_none() {
            return Ok(());
        }
        let map = current
            .as_object_mut()
            .ok_or("setting parent must be a mapping")?;
        current = map.entry(*part).or_insert_with(|| serde_json::json!({}));
    }
    let map = current
        .as_object_mut()
        .ok_or("setting parent must be a mapping")?;
    let key = parts.last().expect("setting has a field");
    if let Some(value) = value {
        map.insert((*key).into(), value);
    } else {
        map.remove(*key);
    }
    Ok(())
}

impl PreparedSetting {
    fn capture(change: PersonalSettingChange, cwd: Option<&str>) -> Result<Self, String> {
        let (field, value) = change.field_value()?;
        // Capture the same operator, named-file precedence, private preimage,
        // effective policy, and DLP union used by profile preparation.
        let base = PreparedProfile::capture("reset", cwd)?;
        let mut before_document =
            serde_json::to_value(&base.original).map_err(|_| "cannot inspect personal policy")?;
        if before_document.is_null() {
            before_document = serde_json::json!({});
        }
        let mut document = before_document.clone();
        edit_field(&mut document, &field, value.clone())?;
        // An explicit override belongs to the user even if it equals the
        // preset today. Later profile reset must not remove that preference.
        if let Some(owned) = document
            .pointer_mut("/protection_profile/owned_fields")
            .and_then(serde_json::Value::as_array_mut)
        {
            owned.retain(|owned| owned.as_str() != Some(field.as_str()));
        }
        let yaml =
            serde_yaml::to_string(&document).map_err(|_| "cannot validate personal settings")?;
        let issues = tirith_core::policy_validate::validate(&yaml);
        if let Some(issue) = issues
            .iter()
            .find(|issue| issue.level == tirith_core::policy_validate::IssueLevel::Error)
        {
            return Err(tirith_core::redact::redact_sanitize_redact_with_compiled(
                &issue.message,
                &base.compiled,
            ));
        }
        let ptr = pointer(&field);
        let before = before_document.pointer(&ptr).cloned().unwrap_or_default();
        let after = document.pointer(&ptr).cloned().unwrap_or_default();
        let mut fields = BTreeMap::new();
        if before != after {
            fields.insert(ptr, value);
        }
        if before_document.get("protection_profile") != document.get("protection_profile") {
            fields.insert(
                "/protection_profile".into(),
                document.get("protection_profile").cloned(),
            );
        }
        let intent = SettingIntent {
            scope: "user",
            cwd: base.intent.cwd.clone(),
            change,
        };
        Ok(Self {
            base,
            intent,
            fields,
            field,
            before,
            after,
        })
    }

    fn projection(&self) -> serde_json::Value {
        let mut before = self.before.clone();
        // Existing policy values can be malformed/custom; proposed values are
        // typed booleans, bounded numbers, or canonical enum values.
        tirith_core::redact::redact_json_strings(&mut before, &self.base.compiled);
        let effective = serde_json::to_value(&self.base.snapshot.policy).unwrap_or_default();
        let mut effective = effective
            .pointer(&pointer(&self.field))
            .cloned()
            .unwrap_or_default();
        tirith_core::redact::redact_json_strings(&mut effective, &self.base.compiled);
        serde_json::json!({"schema_version":1,"kind":"personal_setting_preview", "applied":false,
            "scope":"user", "field":self.field, "before":before, "after":self.after,
            "effective_before":effective,"effective_after":"requires_apply_and_fresh_readback",
            "target":tirith_core::redact::redact_sanitize_redact_with_compiled(&self.base.path.display().to_string(),&self.base.compiled),
            "policy_identity":self.base.snapshot.identity, "profile_owns_this_setting_after":false,
            "constraints":"Organization, remote, project, and incident restrictions still apply; saved personal settings may be overridden."})
    }

    fn plan(&self, id: &str) -> Result<Option<OperationStatus>, String> {
        if self.fields.is_empty() {
            return MutationService::current()?
                .complete_noop_with_intent(
                    id,
                    OperationKind::SetPersonalSetting,
                    &self.base.snapshot,
                    &self.intent,
                )
                .map(Some);
        }
        self.base
            .snapshot
            .revalidate_inputs()
            .map_err(|_| "policy changed; refresh the personal settings plan")?;
        MutationService::current()?
            .plan_with_preimages_and_intent(
                id,
                OperationKind::SetPersonalSetting,
                vec![RequestedChange {
                    target: self.base.path.clone(),
                    scope_root: self.base.config.clone(),
                    edit: Edit::YamlFields(self.fields.clone()),
                    activation: true,
                    description: format!("Change personal setting: {}", self.field),
                }],
                &self.base.snapshot,
                &BTreeMap::from([(self.base.path.clone(), self.base.original_text.clone())]),
                &self.intent,
            )
            .map(Some)
    }
}

pub(crate) fn prepare_setting(
    id: &str,
    change: PersonalSettingChange,
    cwd: Option<&str>,
) -> Result<serde_json::Value, String> {
    uuid::Uuid::parse_str(id).map_err(|_| "operation ID must be a UUID")?;
    change.field_value()?;
    let expected = SettingIntent {
        scope: "user",
        cwd: intent("reset", cwd).cwd,
        change: change.clone(),
    };
    if let Some(status) = MutationService::current()?.status_for_intent(
        id,
        OperationKind::SetPersonalSetting,
        &expected,
    )? {
        let snapshot =
            EffectivePolicySnapshot::resolve(expected.cwd.as_deref(), ResolutionMode::Runtime);
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(
            &tirith_core::policy::captured_policy_dlp_patterns_or(
                &snapshot.policy.dlp_custom_patterns,
            ),
        );
        return Ok(
            serde_json::json!({"schema_version":1,"kind":"personal_setting_plan","applied":false,"reused":true,"operation":super::profile::status_projection(&status,&compiled)?}),
        );
    }
    let prepared = PreparedSetting::capture(change, cwd)?;
    let status = prepared.plan(id)?;
    Ok(
        serde_json::json!({"schema_version":1,"kind":"personal_setting_plan","applied":false,"unchanged":status.as_ref().is_none_or(|status| status.no_op),"preview":prepared.projection(),
        "operation":status.as_ref().map(|status|super::profile::status_projection(status,&prepared.base.compiled)).transpose()?}),
    )
}

pub(crate) fn preview_setting(
    change: PersonalSettingChange,
    cwd: Option<&str>,
) -> Result<serde_json::Value, String> {
    Ok(PreparedSetting::capture(change, cwd)?.projection())
}

pub(crate) fn setting_cli(
    name: &str,
    value: &str,
    rule: Option<&str>,
    dry_run: bool,
    json: bool,
) -> i32 {
    let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
    let result = (|| -> Result<i32, String> {
        let value = match value {
            "reset" => serde_json::Value::Null,
            "true" => true.into(),
            "false" => false.into(),
            value => value
                .parse::<u8>()
                .map(serde_json::Value::from)
                .unwrap_or_else(|_| value.into()),
        };
        let mut request = serde_json::json!({"setting":name,"value":value});
        if let Some(rule) = rule {
            request["rule"] = rule.into();
        }
        let change: PersonalSettingChange = serde_json::from_value(request)
            .map_err(|_| "unknown setting or invalid typed value")?;
        let prepared = PreparedSetting::capture(change, None)?;
        let output = if dry_run {
            prepared.projection()
        } else {
            let id = uuid::Uuid::new_v4().to_string();
            match prepared.plan(&id)? {
                None => serde_json::json!({"kind":"personal_setting_change","state":"unchanged"}),
                Some(_) => {
                    let status = MutationService::current()?.apply(&id, &prepared.base.snapshot)?;
                    super::profile::status_projection(&status, &prepared.base.compiled)?
                }
            }
        };
        for message in tirith_core::policy::drain_captured_policy_diagnostics_for_output(
            &prepared.base.compiled,
        ) {
            eprintln!("{message}");
        }
        if json {
            if !super::write_json_stdout(&output, "tirith policy setting: failed to write result") {
                return Ok(1);
            }
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&output)
                    .map_err(|_| "cannot display setting result")?
            );
        }
        Ok(
            if output["state"].as_str().is_some_and(|state| {
                !matches!(state, "unchanged" | "completed" | "completed-with-recovery")
            }) {
                1
            } else {
                0
            },
        )
    })();
    result.unwrap_or_else(|error| {
        let patterns = tirith_core::policy::captured_policy_dlp_patterns_or(&[]);
        eprintln!(
            "tirith policy setting: {}",
            tirith_core::redact::redact_sanitize_redact(&error, &patterns)
        );
        1
    })
}

#[cfg(test)]
mod settings_input_tests {
    use super::*;
    #[test]
    fn personal_settings_require_an_explicit_value_or_null_and_deny_paths() {
        assert!(serde_json::from_value::<PersonalSettingChange>(
            serde_json::json!({"setting":"strict_warn"})
        )
        .is_err());
        assert!(serde_json::from_value::<PersonalSettingChange>(
            serde_json::json!({"setting":"strict_warn","value":null})
        )
        .is_ok());
        assert!(serde_json::from_value::<PersonalSettingChange>(
            serde_json::json!({"setting":"strict_warn","value":true,"path":"/tmp/fixture"})
        )
        .is_err());
        assert!(serde_json::from_value::<PersonalSettingChange>(
            serde_json::json!({"setting":"strict_warn","value":"false"})
        )
        .is_err());
        assert!(serde_json::from_value::<PersonalSettingChange>(
            serde_json::json!({"setting":"rule_severity","value":"HIGH","rule":"not_a_rule"})
        )
        .is_err());
    }
}
