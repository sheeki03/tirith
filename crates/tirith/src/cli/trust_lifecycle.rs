//! Stable trust grants and CLI projections over the shared policy/mutation
//! services. Filesystem paths and edits are derived here, never from UI payloads.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::Serialize;
use serde_json::{json, Value};
use tirith_core::policy::{Policy, PolicyDiagnosticCapture};
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
use tirith_core::redact::CompiledCustomPatterns;
use tirith_core::trust_grants::{
    self, Expiry, GrantScope, GrantState, ProjectIdentity, TrustGrant, TrustGrantStore,
};

use super::setup::change_plan::{
    Edit, JobState, MutationService, OperationKind, OperationStatus, RequestedChange,
};

struct Context {
    snapshot: EffectivePolicySnapshot,
    project: Option<ProjectIdentity>,
    config: PathBuf,
    patterns: CompiledCustomPatterns,
    cwd: Option<String>,
    plan_only: Option<String>,
    intent: Option<Value>,
}

impl Context {
    fn capture() -> Result<Self, String> {
        Self::capture_at(None)
    }

    fn capture_at(cwd: Option<&str>) -> Result<Self, String> {
        if cwd.is_some_and(|value| !Path::new(value).is_absolute()) {
            return Err("trust service project scope must be absolute".into());
        }
        let resolved_cwd = cwd
            .map(str::to_string)
            .or_else(|| {
                std::env::current_dir()
                    .ok()
                    .map(|path| path.display().to_string())
            })
            .ok_or("cannot resolve the trust operation working directory")?;
        let cwd = Some(resolved_cwd.as_str());
        let config =
            tirith_core::policy::config_dir().ok_or("cannot locate operator configuration")?;
        let snapshot = EffectivePolicySnapshot::resolve(cwd, ResolutionMode::Runtime);
        let project = ProjectIdentity::capture(cwd).ok();
        let patterns =
            CompiledCustomPatterns::new(&tirith_core::policy::captured_policy_dlp_patterns_or(
                &snapshot.policy.dlp_custom_patterns,
            ));
        Ok(Self {
            snapshot,
            project,
            config,
            patterns,
            cwd: cwd.map(str::to_string),
            plan_only: None,
            intent: None,
        })
    }

    fn refresh(&mut self) {
        if self.plan_only.is_some() {
            return;
        }
        self.snapshot =
            EffectivePolicySnapshot::resolve(self.cwd.as_deref(), ResolutionMode::Runtime);
        self.project = ProjectIdentity::capture(self.cwd.as_deref()).ok();
        self.patterns =
            CompiledCustomPatterns::new(&tirith_core::policy::captured_policy_dlp_patterns_or(
                &self.snapshot.policy.dlp_custom_patterns,
            ));
    }

    fn redact(&self, text: &str) -> String {
        tirith_core::redact::redact_sanitize_redact_with_compiled(text, &self.patterns)
    }
}

/// High-level inputs for CLI/browser planning. No member can select a file,
/// JSON pointer, policy source, or arbitrary write payload.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GrantTarget {
    User,
    Project,
}

#[derive(Serialize)]
pub(crate) struct AddGrantRequest {
    pub pattern: String,
    pub rule: Option<String>,
    pub ttl: Option<String>,
    pub permanent: bool,
    pub broad: bool,
    pub all_rules: bool,
    pub reason: Option<String>,
    pub scope: GrantTarget,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TrustChange {
    Add(AddGrantRequest),
    Expiry {
        id: String,
        ttl: Option<String>,
        permanent: bool,
    },
    Revoke {
        id: String,
    },
    MigrateUser,
}

/// Construct per request using the service's fixed project scope. A read never
/// writes history or applies a plan. Diagnostics are retained as projected data.
pub(crate) struct TrustService {
    context: Context,
    pub diagnostics: Vec<String>,
}

impl TrustService {
    pub(crate) fn capture(cwd: Option<&str>) -> Result<Self, String> {
        let _capture = PolicyDiagnosticCapture::start();
        let context = Context::capture_at(cwd)?;
        let diagnostics =
            tirith_core::policy::drain_captured_policy_diagnostics_for_output(&context.patterns);
        Ok(Self {
            context,
            diagnostics,
        })
    }

    pub(crate) fn list(
        &mut self,
        rule: Option<&str>,
        include_inactive: bool,
        scope: &str,
    ) -> Result<Value, String> {
        list_value(&mut self.context, rule, include_inactive, scope)
            .map_err(|error| self.context.redact(&error))
    }

    pub(crate) fn explain(&mut self, target: &str, scope: &str) -> Result<Value, String> {
        explain_value(&mut self.context, target, scope).map_err(|error| self.context.redact(&error))
    }

    /// Persist a reviewable plan; the apply endpoint accepts only its stored ID.
    /// Identical caller intent returns the original immutable TTL/UUID payload,
    /// including after a lost response or concurrent preparation.
    pub(crate) fn prepare(
        &mut self,
        operation_id: &str,
        change: TrustChange,
    ) -> Result<Value, String> {
        uuid::Uuid::parse_str(operation_id).map_err(|_| "operation ID must be a UUID")?;
        let service = MutationService::current()?;
        let kind = match &change {
            TrustChange::Revoke { .. } => OperationKind::RevokeTrust,
            _ => OperationKind::AddTrust,
        };
        let intent = serde_json::to_value((&self.context.cwd, &change))
            .map_err(|_| "cannot bind trust request intent")?;
        if let Some(status) = service
            .status_for_intent(operation_id, kind, &intent)
            .map_err(|error| self.context.redact(&error))?
        {
            return self.project_plan(&status);
        }
        self.context.plan_only = Some(operation_id.into());
        self.context.intent = Some(intent.clone());
        let result = match change {
            TrustChange::Add(request) => add_value(
                &mut self.context,
                &request.pattern,
                request.rule.as_deref(),
                request.ttl.as_deref(),
                request.permanent,
                request.broad,
                request.all_rules,
                request.reason.as_deref(),
                match request.scope {
                    GrantTarget::User => "user",
                    GrantTarget::Project => "project",
                },
            ),
            TrustChange::Expiry { id, ttl, permanent } => {
                change_expiry_value(&mut self.context, &id, ttl.as_deref(), permanent)
            }
            TrustChange::Revoke { id } => revoke_value(&mut self.context, &id),
            TrustChange::MigrateUser => migrate_value(&mut self.context, "user"),
        };
        self.context.plan_only = None;
        self.context.intent = None;
        let value = result.map_err(|error| self.context.redact(&error))?;
        if value.get("operation_id").and_then(Value::as_str) != Some(operation_id) {
            if value.get("no_op").and_then(Value::as_bool) != Some(true) {
                return Err("trust preparation did not produce an operation outcome".into());
            }
            let status = service
                .complete_noop_with_intent(operation_id, kind, &self.context.snapshot, &intent)
                .map_err(|error| self.context.redact(&error))?;
            return self.project_plan(&status);
        }
        let status = service
            .status(operation_id)
            .map_err(|error| self.context.redact(&error))?;
        self.project_plan(&status)
    }

    fn project_plan(&self, status: &OperationStatus) -> Result<Value, String> {
        let mut value =
            serde_json::to_value(status).map_err(|_| "cannot serialize operation status")?;
        if let Some(detail) = value
            .get("detail")
            .and_then(Value::as_str)
            .map(str::to_string)
        {
            value["detail"] = Value::String(self.context.redact(&detail));
        }
        for step in value
            .get_mut("steps")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            for key in ["target", "description"] {
                if let Some(text) = step.get(key).and_then(Value::as_str) {
                    let projected = self.context.redact(text);
                    step[key] = Value::String(projected);
                }
            }
        }
        Ok(
            json!({"schema_version":1,"kind":"trust_plan","applied":false,"operation":value,"diagnostics":self.diagnostics}),
        )
    }
}

fn run(json_output: bool, operation: impl FnOnce(&mut Context) -> Result<Value, String>) -> i32 {
    let _diagnostics = PolicyDiagnosticCapture::start();
    let mut context = match Context::capture() {
        Ok(context) => context,
        Err(_) => {
            eprintln!("tirith trust: cannot resolve operator configuration");
            return 1;
        }
    };
    let result = operation(&mut context);
    for line in tirith_core::policy::drain_captured_policy_diagnostics_for_output(&context.patterns)
    {
        eprintln!("{line}");
    }
    match result {
        Ok(value) if json_output => {
            if super::write_json_stdout(&value, "tirith trust: output write failed") {
                0
            } else {
                1
            }
        }
        Ok(value) => {
            show_human(&value);
            0
        }
        Err(error) => {
            if json_output {
                let _ = super::write_json_stdout(
                    &json!({"schema_version":1,"kind":"trust_error","error":context.redact(&error)}),
                    "tirith trust: output write failed",
                );
            } else {
                eprintln!("tirith trust: {}", context.redact(&error));
            }
            1
        }
    }
}

fn show_human(value: &Value) {
    if let Some(rows) = value.get("grants").and_then(Value::as_array) {
        if rows.is_empty() {
            eprintln!("No trust grants found.");
        }
        for row in rows {
            eprintln!(
                "{}  {}  {}  rule={}  {}",
                row["id"].as_str().unwrap_or("legacy/no-id"),
                row["state"].as_str().unwrap_or("invalid"),
                row["pattern"].as_str().unwrap_or("[invalid record]"),
                row["rule_id"].as_str().unwrap_or("all rules"),
                row["source"].as_str().unwrap_or("unknown")
            );
            eprintln!(
                "  {}; expiry={}",
                row["state_reason"].as_str().unwrap_or("unknown"),
                row["expires_at"].as_str().unwrap_or("permanent")
            );
            if row["requires_migration"] == true {
                eprintln!("  Legacy grant has no stable ID; use tirith trust migrate --scope user before editing expiry.");
            }
        }
    } else {
        eprintln!(
            "Trust operation: {}",
            value["state"].as_str().unwrap_or("completed")
        );
        if let Some(id) = value["grant_id"].as_str() {
            eprintln!("Grant ID: {id}");
        }
        if let Some(id) = value["operation_id"].as_str() {
            eprintln!("Operation ID: {id}");
        }
        if let Some(count) = value["remaining_grants"].as_array().map(Vec::len) {
            eprintln!("{count} remaining applicable grant(s) cover this target; other policy blockers may still apply.");
            for row in value["remaining_grants"].as_array().into_iter().flatten() {
                eprintln!(
                    "  {}  {}  rule={}",
                    row["id"].as_str().unwrap_or("legacy/no-id"),
                    row["pattern"].as_str().unwrap_or("[redacted]"),
                    row["rule_id"].as_str().unwrap_or("all rules")
                );
            }
        }
        if let Some(note) = value["note"].as_str() {
            eprintln!("{note}");
        }
    }
}

fn read_text(path: &Path) -> Result<Option<String>, String> {
    match tirith_core::util::read_text_no_follow_capped(path, trust_grants::STORE_READ_CAP) {
        Ok(bytes) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| "trust store is not UTF-8".into()),
        Err(tirith_core::util::OpenRegularError::NotFound) => Ok(None),
        Err(_) => Err("trust store is unreadable, non-regular, linked, or oversized".into()),
    }
}

fn read_store(config: &Path) -> Result<(PathBuf, Option<String>, TrustGrantStore), String> {
    let path = config.join(trust_grants::STORE_FILE);
    let text = read_text(&path)?;
    let store = text
        .as_deref()
        .map(|text| TrustGrantStore::parse(text.as_bytes()))
        .transpose()?
        .unwrap_or_default();
    Ok((path, text, store))
}

fn legacy_path(context: &Context, scope: &str) -> Result<(PathBuf, PathBuf), String> {
    match scope {
        "user" => Ok((context.config.join("trust.json"), context.config.clone())),
        "repo" => {
            let root = tirith_core::policy::find_repo_root(context.cwd.as_deref())
                .ok_or("not inside a Git repository")?;
            Ok((root.join(".tirith/trust.json"), root))
        }
        _ => Err("legacy scope must be user or repo".into()),
    }
}

fn legacy_document(text: Option<&str>) -> Result<Value, String> {
    let value: Value = text
        .map(serde_json::from_str)
        .transpose()
        .map_err(|_| "legacy trust store is invalid JSON")?
        .unwrap_or_else(|| json!({"version":1,"entries":[]}));
    if value.get("entries").and_then(Value::as_array).is_none() {
        return Err("legacy trust store has no entries array".into());
    }
    Ok(value)
}

fn same_rule(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        (None, None) => true,
        _ => false,
    }
}

fn perform(
    context: &Context,
    kind: OperationKind,
    changes: Vec<(PathBuf, PathBuf, Option<String>, Value)>,
) -> Result<String, String> {
    let operator = super::shell_target::resolve_for_shell("unknown")?;
    super::shell_target::require_personal_writer(&operator)?;
    let mut expected = BTreeMap::new();
    let mut requests = Vec::new();
    for (target, root, before, after) in changes {
        super::preflight_config_write_authorization(
            &root,
            &target,
            true,
            &context.snapshot.policy,
            true,
        )
        .map_err(|error| error.to_string())?;
        expected.insert(target.clone(), before);
        requests.push(RequestedChange {
            target,
            scope_root: root,
            edit: Edit::WholeFile(
                serde_json::to_string_pretty(&after).map_err(|_| "cannot serialize grant edit")?,
            ),
            activation: true,
            description: "Update selected operator trust grants".into(),
        });
    }
    let service = MutationService::current()?;
    let id = context
        .plan_only
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    if let Some(intent) = &context.intent {
        service.plan_with_preimages_and_intent(
            &id,
            kind,
            requests,
            &context.snapshot,
            &expected,
            intent,
        )?;
    } else {
        service.plan_with_preimages(&id, kind, requests, &context.snapshot, &expected)?;
    }
    if context.plan_only.is_some() {
        return Ok(id);
    }
    let status = service.apply(&id, &context.snapshot)?;
    if !matches!(
        status.state,
        JobState::Completed | JobState::CompletedWithRecovery
    ) {
        return Err(format!(
            "trust operation {} requires attention: {:?}; inspect tirith policy operation status",
            id, status.state
        ));
    }
    Ok(id)
}

#[derive(Serialize)]
struct Row {
    id: Option<String>,
    pattern: Option<String>,
    rule_id: Option<String>,
    source: &'static str,
    scope: &'static str,
    project_root: Option<String>,
    expires_at: Option<String>,
    state: GrantState,
    state_reason: &'static str,
    requires_migration: bool,
    broad: bool,
    reason: Option<String>,
}

impl Row {
    fn project(&self, context: &Context) -> Value {
        json!({"id":self.id,"pattern":self.pattern.as_deref().map(|v| context.redact(v)),"rule_id":self.rule_id.as_deref().map(|v| context.redact(v)),"source":self.source,"scope":self.scope,"project_root":self.project_root.as_deref().map(|v| context.redact(v)),"expires_at":self.expires_at.as_deref().filter(|v| chrono::DateTime::parse_from_rfc3339(v).is_ok()),"state":self.state,"state_reason":self.state_reason,"requires_migration":self.requires_migration,"broad":self.broad,"reason":self.reason.as_deref().map(|v| context.redact(v))})
    }
    fn matches(&self, target: &str, rule: Option<&str>) -> bool {
        self.pattern
            .as_deref()
            .is_some_and(|pattern| tirith_core::policy::allowlist_pattern_matches(pattern, target))
            && self
                .rule_id
                .as_deref()
                .is_none_or(|own| rule.is_none_or(|rule| own.eq_ignore_ascii_case(rule)))
    }
}

fn grant_row(grant: &TrustGrant, context: &Context) -> Row {
    let status = grant.status(
        context.project.as_ref(),
        Some(&context.snapshot.policy),
        Utc::now(),
    );
    let (scope, project_root) = match &grant.scope {
        GrantScope::User => ("user", None),
        GrantScope::Project { project } => (
            "project",
            Some(project.canonical_root.display().to_string()),
        ),
    };
    Row {
        id: Some(grant.id.clone()),
        pattern: Some(grant.pattern.clone()),
        rule_id: grant.rule_id.clone(),
        source: "operator_grant",
        scope,
        project_root,
        expires_at: grant.expires_at.clone(),
        state: status.state,
        state_reason: status.reason,
        requires_migration: false,
        broad: tirith_core::policy::classify_trust_pattern(&grant.pattern).is_broad()
            || grant.rule_id.is_none(),
        reason: grant.reason.clone(),
    }
}

fn legacy_row(value: &Value, source: &'static str, scope: &'static str, policy: &Policy) -> Row {
    let pattern = value
        .get("pattern")
        .and_then(Value::as_str)
        .map(str::to_string);
    let rule_id = value
        .get("rule_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    let expires_at = value
        .get("ttl_expires")
        .and_then(Value::as_str)
        .map(str::to_string);
    let valid = pattern
        .as_deref()
        .is_some_and(|pattern| tirith_core::policy::validate_trust_pattern(pattern).is_ok())
        && match value.get("rule_id") {
            None | Some(Value::Null) => true,
            Some(Value::String(rule)) => tirith_core::policy::validate_trust_pattern(rule).is_ok(),
            _ => false,
        };
    let (state, state_reason) = if !valid {
        (GrantState::Invalid, "invalid_pattern_or_rule")
    } else {
        match trust_grants::expiry_value(value.get("ttl_expires"), Utc::now()) {
            Expiry::Invalid => (GrantState::Invalid, "invalid_expiry"),
            Expiry::Expired => (GrantState::Expired, "deadline_reached"),
            _ if scope == "repo" => (
                GrantState::Recorded,
                "repository_content_cannot_authorize_trust",
            ),
            _ if pattern
                .as_ref()
                .is_some_and(|pattern| policy.is_blocklisted(pattern)) =>
            {
                (GrantState::Overridden, "target_matches_blocklist")
            }
            _ => (
                GrantState::Effective,
                "eligible_exception_other_blockers_may_remain",
            ),
        }
    };
    Row {
        id: None,
        broad: pattern
            .as_deref()
            .is_some_and(|pattern| tirith_core::policy::classify_trust_pattern(pattern).is_broad())
            || rule_id.is_none(),
        pattern,
        rule_id,
        source,
        scope,
        project_root: None,
        expires_at,
        state,
        state_reason,
        requires_migration: source == "legacy_user",
        reason: value
            .get("reason")
            .and_then(Value::as_str)
            .map(str::to_string),
    }
}

fn rows(context: &Context, scope: &str) -> Result<Vec<Row>, String> {
    if !matches!(scope, "user" | "project" | "repo" | "all") {
        return Err("scope must be user, project, repo, or all".into());
    }
    let mut rows = Vec::new();
    if scope != "repo" {
        let (_, _, store) = read_store(&context.config)?;
        for record in store.records() {
            match record {
                Ok(grant) => {
                    let row = grant_row(&grant, context);
                    if scope == "all" || row.scope == scope {
                        rows.push(row);
                    }
                }
                Err(reason) => rows.push(Row {
                    id: None,
                    pattern: None,
                    rule_id: None,
                    source: "operator_grant",
                    scope: "unknown",
                    project_root: None,
                    expires_at: None,
                    state: GrantState::Invalid,
                    state_reason: reason,
                    requires_migration: false,
                    broad: false,
                    reason: None,
                }),
            }
        }
    }
    for (which, source) in [("user", "legacy_user"), ("repo", "legacy_repo")] {
        if scope != "all" && scope != which {
            continue;
        }
        let Ok((path, _)) = legacy_path(context, which) else {
            if scope == "all" {
                continue;
            }
            return Err("not inside a Git repository".into());
        };
        if let Some(text) = read_text(&path)? {
            let document = legacy_document(Some(&text))?;
            for value in document["entries"]
                .as_array()
                .expect("validated legacy entries")
            {
                rows.push(legacy_row(value, source, which, &context.snapshot.policy));
            }
        }
    }
    if scope == "all" {
        for pattern in &context.snapshot.policy.allowlist {
            if !rows.iter().any(|row| {
                row.state == GrantState::Effective
                    && row.rule_id.is_none()
                    && row.pattern.as_ref() == Some(pattern)
            }) {
                rows.push(legacy_row(
                    &json!({"pattern":pattern}),
                    "resolved_policy",
                    "policy",
                    &context.snapshot.policy,
                ));
            }
        }
        for rule in &context.snapshot.policy.allowlist_rules {
            for pattern in &rule.patterns {
                if !rows.iter().any(|row| {
                    row.state == GrantState::Effective
                        && row.rule_id.as_ref() == Some(&rule.rule_id)
                        && row.pattern.as_ref() == Some(pattern)
                }) {
                    rows.push(legacy_row(
                        &json!({"pattern":pattern,"rule_id":rule.rule_id}),
                        "resolved_policy",
                        "policy",
                        &context.snapshot.policy,
                    ));
                }
            }
        }
        // The repository flat allowlist is recorded but deliberately inactive.
        if let Some(root) = tirith_core::policy::find_repo_root(context.cwd.as_deref()) {
            if let Ok(Some(text)) = read_text(&root.join(".tirith/allowlist")) {
                for line in text
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                {
                    rows.push(legacy_row(
                        &json!({"pattern":line}),
                        "repository_allowlist",
                        "repo",
                        &context.snapshot.policy,
                    ));
                }
            }
        }
    }
    context
        .snapshot
        .revalidate_inputs()
        .map_err(|_| "trust or policy changed while reading; refresh the list")?;
    Ok(rows)
}

fn remaining(context: &Context, target: &str, rule: Option<&str>) -> Result<Vec<Value>, String> {
    Ok(rows(context, "all")?
        .into_iter()
        .filter(|row| row.state == GrantState::Effective && row.matches(target, rule))
        .map(|row| row.project(context))
        .collect())
}

pub fn list(rule: Option<&str>, include_inactive: bool, scope: &str, json_output: bool) -> i32 {
    run(json_output, |context| {
        list_value(context, rule, include_inactive, scope)
    })
}

#[allow(clippy::too_many_arguments)]
fn list_value(
    context: &mut Context,
    rule: Option<&str>,
    include_inactive: bool,
    scope: &str,
) -> Result<Value, String> {
    let grants: Vec<Value> = rows(context, scope)?
        .into_iter()
        .filter(|row| {
            include_inactive || !matches!(row.state, GrantState::Expired | GrantState::Revoked)
        })
        .filter(|row| {
            rule.is_none_or(|rule| {
                row.rule_id
                    .as_deref()
                    .is_none_or(|own| own.eq_ignore_ascii_case(rule))
            })
        })
        .map(|row| row.project(context))
        .collect();
    Ok(
        json!({"schema_version":1,"kind":"trust_list","grants":grants,"policy_identity":context.snapshot.identity,"next_expiry":context.snapshot.next_trust_expiry}),
    )
}

pub fn explain(target: &str, scope: &str, json_output: bool) -> i32 {
    run(json_output, |context| explain_value(context, target, scope))
}

#[allow(clippy::too_many_arguments)]
fn explain_value(context: &mut Context, target: &str, scope: &str) -> Result<Value, String> {
    if !matches!(scope, "user" | "project" | "repo" | "all") {
        return Err("scope must be user, project, repo, or all".into());
    }
    let all_rows = rows(context, "all")?;
    // Resolve a stable ID to its private input in the service. Displayed DLP
    // text must never be sent back as the identity of the underlying grant.
    let selected = if uuid::Uuid::parse_str(target).is_ok() {
        Some(
            all_rows
                .iter()
                .find(|row| {
                    row.id.as_deref() == Some(target) && (scope == "all" || row.scope == scope)
                })
                .ok_or("grant ID is not present in the selected scope")?,
        )
    } else {
        None
    };
    let pattern = selected
        .and_then(|row| row.pattern.as_deref())
        .unwrap_or(target);
    let rule = selected.and_then(|row| row.rule_id.as_deref());
    let grants: Vec<Value> = all_rows
        .iter()
        .filter(|row| scope == "all" || row.scope == scope)
        .filter(|row| {
            row.id.as_deref() == Some(target)
                || row.pattern.as_deref() == Some(pattern)
                || row.matches(pattern, rule)
        })
        .map(|row| row.project(context))
        .collect();
    let effective_grants: Vec<Value> = all_rows
        .iter()
        .filter(|row| row.state == GrantState::Effective && row.matches(pattern, rule))
        .map(|row| row.project(context))
        .collect();
    Ok(json!({"schema_version":1,"kind":"trust_explanation",
            "selected_grant_id":selected.and_then(|row| row.id.as_deref()),
            "target":context.redact(pattern),"rule_id":rule.map(|rule| context.redact(rule)),
            "grants":grants,"matching_effective_grants":effective_grants,
            "target_matches_blocklist":context.snapshot.policy.is_blocklisted(pattern),
            "semantics":"trust_eligibility_only","command_evaluated":false,
            "independent_command_blockers_may_remain":true,
            "policy_identity":context.snapshot.identity}))
}

#[allow(clippy::too_many_arguments)]
pub fn add(
    pattern: &str,
    rule: Option<&str>,
    ttl: Option<&str>,
    permanent: bool,
    broad: bool,
    all_rules: bool,
    reason: Option<&str>,
    scope: &str,
    json_output: bool,
) -> i32 {
    run(json_output, |context| {
        add_value(
            context, pattern, rule, ttl, permanent, broad, all_rules, reason, scope,
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn add_value(
    context: &mut Context,
    pattern: &str,
    rule: Option<&str>,
    ttl: Option<&str>,
    permanent: bool,
    broad: bool,
    all_rules: bool,
    reason: Option<&str>,
    scope: &str,
) -> Result<Value, String> {
    if permanent && ttl.is_some() {
        return Err("--permanent cannot be combined with --ttl".into());
    }
    if rule.is_none() && !all_rules {
        return Err("select --rule for a narrow grant, or explicitly pass --all-rules; existing scripts must add this opt-in".into());
    }
    if rule.is_some() && all_rules {
        return Err("--rule cannot be combined with --all-rules".into());
    }
    tirith_core::policy::validate_trust_pattern(pattern)?;
    if let Some(rule) = rule {
        tirith_core::policy::validate_trust_pattern(rule)?;
    }
    if reason.is_some_and(|reason| {
        tirith_core::mcp::output_filter::sanitize_for_display(reason) != reason
    }) {
        return Err("reason contains unsafe display characters".into());
    }
    if context.snapshot.policy.is_blocklisted(pattern) {
        return Err("target is blocklisted; trust cannot override this blocker".into());
    }
    if tirith_core::policy::classify_trust_pattern(pattern).is_broad() && !broad {
        return Err(
            "domain or wildcard trust requires explicit --broad; prefer the exact URL and --rule"
                .into(),
        );
    }
    let expiry = if permanent {
        None
    } else {
        Some(trust_grants::expiry_from_ttl(
            ttl.unwrap_or("30d"),
            Utc::now(),
        )?)
    };
    if scope == "repo" {
        let (path, root) = legacy_path(context, scope)?;
        let before = read_text(&path)?;
        let mut document = legacy_document(before.as_deref())?;
        let entries = document["entries"]
            .as_array_mut()
            .expect("validated legacy entries");
        entries.retain(|entry| {
            !(entry["pattern"].as_str() == Some(pattern)
                && entry.get("rule_id").and_then(Value::as_str) == rule)
        });
        entries.push(json!({"pattern":pattern,"rule_id":rule,"ttl_expires":expiry,"added":Utc::now().to_rfc3339(),"source":"cli","reason":reason}));
        let operation_id = perform(
            context,
            OperationKind::AddTrust,
            vec![(path, root, before, document)],
        )?;
        return Ok(
            json!({"schema_version":1,"kind":"trust_change","state":"recorded","operation_id":operation_id,"note":"Repository trust is inactive. Use --scope project to create an operator-owned checkout grant."}),
        );
    }
    let grant_scope = match scope {
        "user" => GrantScope::User,
        "project" => GrantScope::Project {
            project: context.project.clone().ok_or(
                "project trust requires a Git checkout with supported filesystem identity",
            )?,
        },
        _ => return Err("scope must be user, project, or repo".into()),
    };
    // Legacy duplicates could keep a supposedly shortened grant permanent.
    // Require an explicit migration first, preserving old-client behavior
    // until the operator chooses the documented transition.
    if scope == "user" {
        let (path, _) = legacy_path(context, "user")?;
        if let Some(text) = read_text(&path)? {
            let document = legacy_document(Some(&text))?;
            if document["entries"].as_array().unwrap().iter().any(|entry| {
                entry["pattern"].as_str() == Some(pattern)
                    && same_rule(entry.get("rule_id").and_then(Value::as_str), rule)
            }) {
                return Err("a matching legacy grant exists; run tirith trust migrate --scope user, then update its stable grant ID".into());
            }
        }
    }
    let (path, before, mut store) = read_store(&context.config)?;
    let matches: Vec<(usize, TrustGrant)> = store
        .records()
        .into_iter()
        .enumerate()
        .filter_map(|(index, grant)| grant.ok().map(|grant| (index, grant)))
        .filter(|(_, grant)| {
            grant.pattern == pattern
                && same_rule(grant.rule_id.as_deref(), rule)
                && grant.scope == grant_scope
                && grant.revoked_at.is_none()
        })
        .collect();
    if matches.len() > 1 {
        return Err(
            "multiple matching grants exist; update or revoke each identified grant explicitly"
                .into(),
        );
    }
    let id = if let Some((index, mut grant)) = matches.into_iter().next() {
        grant.expires_at = expiry;
        grant.reason = reason.map(str::to_string).or(grant.reason);
        store.replace(index, &grant)?;
        grant.id
    } else {
        let grant = TrustGrant {
            id: uuid::Uuid::new_v4().to_string(),
            pattern: pattern.into(),
            rule_id: rule.map(str::to_string),
            scope: grant_scope,
            created_at: Utc::now().to_rfc3339(),
            expires_at: expiry,
            revoked_at: None,
            reason: reason.map(str::to_string),
        };
        store.insert(&grant)?;
        grant.id
    };
    let operation_id = perform(
        context,
        OperationKind::AddTrust,
        vec![(
            path,
            context.config.clone(),
            before,
            serde_json::to_value(&store).unwrap(),
        )],
    )?;
    context.refresh();
    let current = store.find(&id)?.1;
    Ok(
        json!({"schema_version":1,"kind":"trust_change","state":current.status(context.project.as_ref(),Some(&context.snapshot.policy),Utc::now()).state,"grant_id":id,"operation_id":operation_id,"remaining_grants":remaining(context,pattern,rule)?,"note":"Trust is an eligible exception; other policy blockers may still apply. Older clients ignore the new grant store."}),
    )
}

pub fn change_expiry(id: &str, ttl: Option<&str>, permanent: bool, json_output: bool) -> i32 {
    run(json_output, |context| {
        change_expiry_value(context, id, ttl, permanent)
    })
}

#[allow(clippy::too_many_arguments)]
fn change_expiry_value(
    context: &mut Context,
    id: &str,
    ttl: Option<&str>,
    permanent: bool,
) -> Result<Value, String> {
    if ttl.is_none() == !permanent {
        return Err("select exactly one of --ttl or --permanent".into());
    }
    let (path, before, mut store) = read_store(&context.config)?;
    let (index, mut grant) = store.find(id)?;
    if grant.revoked_at.is_some() {
        return Err("revoked grants cannot be renewed; add a new grant explicitly".into());
    }
    grant.expires_at = if permanent {
        None
    } else {
        Some(trust_grants::expiry_from_ttl(ttl.unwrap(), Utc::now())?)
    };
    store.replace(index, &grant)?;
    let operation_id = perform(
        context,
        OperationKind::AddTrust,
        vec![(
            path,
            context.config.clone(),
            before,
            serde_json::to_value(store).unwrap(),
        )],
    )?;
    context.refresh();
    Ok(
        json!({"schema_version":1,"kind":"trust_expiry_change","state":grant.status(context.project.as_ref(),Some(&context.snapshot.policy),Utc::now()).state,"grant_id":grant.id,"expires_at":grant.expires_at,"operation_id":operation_id,"remaining_grants":remaining(context,&grant.pattern,grant.rule_id.as_deref())?}),
    )
}

pub fn revoke(id: &str, json_output: bool) -> i32 {
    run(json_output, |context| revoke_value(context, id))
}

#[allow(clippy::too_many_arguments)]
fn revoke_value(context: &mut Context, id: &str) -> Result<Value, String> {
    let (path, before, mut store) = read_store(&context.config)?;
    let (index, mut grant) = store.find(id)?;
    if grant.revoked_at.is_some() {
        return Ok(
            json!({"schema_version":1,"kind":"trust_revocation","state":"revoked","no_op":true,"grant_id":grant.id,"remaining_grants":remaining(context,&grant.pattern,grant.rule_id.as_deref())?}),
        );
    }
    grant.revoked_at = Some(Utc::now().to_rfc3339());
    store.replace(index, &grant)?;
    let operation_id = perform(
        context,
        OperationKind::RevokeTrust,
        vec![(
            path,
            context.config.clone(),
            before,
            serde_json::to_value(store).unwrap(),
        )],
    )?;
    context.refresh();
    Ok(
        json!({"schema_version":1,"kind":"trust_revocation","state":"revoked","grant_id":grant.id,"operation_id":operation_id,"remaining_grants":remaining(context,&grant.pattern,grant.rule_id.as_deref())?}),
    )
}

pub fn migrate(scope: &str, json_output: bool) -> i32 {
    run(json_output, |context| migrate_value(context, scope))
}

#[allow(clippy::too_many_arguments)]
fn migrate_value(context: &mut Context, scope: &str) -> Result<Value, String> {
    if scope != "user" {
        return Err("only operator-owned user grants may be migrated; repository trust is inactive and requires individual --scope project enrolment".into());
    }
    let (legacy_path, legacy_root) = legacy_path(context, scope)?;
    let legacy_before = read_text(&legacy_path)?;
    let mut legacy = legacy_document(legacy_before.as_deref())?;
    let (path, before, mut store) = read_store(&context.config)?;
    let mut migrated = Vec::new();
    let mut retained = Vec::new();
    for value in legacy["entries"].as_array().unwrap() {
        let row = legacy_row(value, "legacy_user", "user", &context.snapshot.policy);
        if row.state == GrantState::Invalid {
            retained.push(value.clone());
            continue;
        }
        let grant = TrustGrant {
            id: uuid::Uuid::new_v4().to_string(),
            pattern: row.pattern.unwrap(),
            rule_id: row.rule_id,
            scope: GrantScope::User,
            created_at: Utc::now().to_rfc3339(),
            expires_at: row.expires_at,
            revoked_at: None,
            reason: row.reason,
        };
        store.insert(&grant)?;
        migrated.push(grant.id);
    }
    if migrated.is_empty() {
        return Ok(
            json!({"schema_version":1,"kind":"trust_migration","state":"unchanged","no_op":true,"migrated_ids":migrated,"invalid_retained":retained.len()}),
        );
    }
    let retained_count = retained.len();
    legacy["entries"] = Value::Array(retained);
    // Remove legacy applicability before activating the new envelope. An
    // interrupted migration can temporarily narrow trust, never globalize
    // or extend a project/expiring grant. The journal supports recovery.
    let operation_id = perform(
        context,
        OperationKind::AddTrust,
        vec![
            (legacy_path, legacy_root, legacy_before, legacy),
            (
                path,
                context.config.clone(),
                before,
                serde_json::to_value(store).unwrap(),
            ),
        ],
    )?;
    Ok(
        json!({"schema_version":1,"kind":"trust_migration","state":"completed","operation_id":operation_id,"migrated_ids":migrated,"invalid_retained":retained_count,"note":"Migrated grants keep user-global scope and expiry. 0.4.2 ignores them; downgrade removes these exceptions rather than broadening them."}),
    )
}

pub fn remove(pattern: &str, rule: Option<&str>, scope: &str) -> i32 {
    run(false, |context| {
        if !matches!(scope, "user" | "repo" | "project") {
            return Err("scope must be user, project, or repo".into());
        }
        let mut changes = Vec::new();
        let mut removed = 0usize;
        if scope != "repo" {
            let (path, before, mut store) = read_store(&context.config)?;
            for (index, decoded) in store.records().into_iter().enumerate() {
                let Ok(mut grant) = decoded else {
                    continue;
                };
                let scope_matches = match (&grant.scope, scope) {
                    (GrantScope::User, "user") => true,
                    (GrantScope::Project { project }, "project") => {
                        Some(project) == context.project.as_ref()
                    }
                    _ => false,
                };
                if scope_matches
                    && grant.pattern == pattern
                    && rule.is_none_or(|rule| grant.rule_id.as_deref() == Some(rule))
                    && grant.revoked_at.is_none()
                {
                    grant.revoked_at = Some(Utc::now().to_rfc3339());
                    store.replace(index, &grant)?;
                    removed += 1;
                }
            }
            if removed > 0 {
                changes.push((
                    path,
                    context.config.clone(),
                    before,
                    serde_json::to_value(store).unwrap(),
                ));
            }
        }
        if scope != "project" {
            let (path, root) = legacy_path(context, scope)?;
            let before = read_text(&path)?;
            if before.is_some() {
                let mut document = legacy_document(before.as_deref())?;
                let entries = document["entries"].as_array_mut().unwrap();
                let len = entries.len();
                entries.retain(|entry| {
                    !(entry["pattern"].as_str() == Some(pattern)
                        && rule.is_none_or(|rule| entry["rule_id"].as_str() == Some(rule)))
                });
                let count = len - entries.len();
                removed += count;
                if count > 0 {
                    changes.push((path, root, before, document));
                }
            }
        }
        if removed == 0 {
            return Err("no matching trust grant found".into());
        }
        let operation_id = perform(context, OperationKind::RevokeTrust, changes)?;
        context.refresh();
        Ok(
            json!({"schema_version":1,"kind":"trust_removal","state":"completed","removed":removed,"operation_id":operation_id,"remaining_grants":remaining(context,pattern,rule)?}),
        )
    })
}

pub fn gc(scope: &str, json_output: bool) -> i32 {
    run(json_output, |context| {
        if !matches!(scope, "user" | "repo" | "project" | "all") {
            return Err("scope must be user, project, repo, or all".into());
        }
        let mut changes = Vec::new();
        let mut pruned = 0usize;
        if scope != "repo" {
            let (path, before, mut store) = read_store(&context.config)?;
            let records = store.records();
            let mut keep = Vec::new();
            for (raw, decoded) in store.grants.into_iter().zip(records) {
                let remove = decoded.ok().is_some_and(|grant| {
                    let selected = scope == "all"
                        || match (&grant.scope, scope) {
                            (GrantScope::User, "user") => true,
                            (GrantScope::Project { project }, "project") => {
                                Some(project) == context.project.as_ref()
                            }
                            _ => false,
                        };
                    selected
                        && matches!(
                            trust_grants::expiry(grant.expires_at.as_deref(), Utc::now()),
                            Expiry::Expired
                        )
                });
                if remove {
                    pruned += 1;
                } else {
                    keep.push(raw);
                }
            }
            store.grants = keep;
            if pruned > 0 {
                changes.push((
                    path,
                    context.config.clone(),
                    before,
                    serde_json::to_value(store).unwrap(),
                ));
            }
        }
        for selected in ["user", "repo"] {
            if scope != "all" && scope != selected {
                continue;
            }
            let Ok((path, root)) = legacy_path(context, selected) else {
                if scope == "all" {
                    continue;
                }
                return Err("not inside a Git repository".into());
            };
            let before = read_text(&path)?;
            if before.is_none() {
                continue;
            }
            let mut document = legacy_document(before.as_deref())?;
            let entries = document["entries"].as_array_mut().unwrap();
            let len = entries.len();
            entries.retain(|entry| {
                !matches!(
                    trust_grants::expiry_value(entry.get("ttl_expires"), Utc::now()),
                    Expiry::Expired
                )
            });
            let count = len - entries.len();
            pruned += count;
            if count > 0 {
                changes.push((path, root, before, document));
            }
        }
        if changes.is_empty() {
            return Ok(
                json!({"schema_version":1,"kind":"trust_gc","state":"unchanged","pruned":0}),
            );
        }
        let operation_id = perform(context, OperationKind::RevokeTrust, changes)?;
        Ok(
            json!({"schema_version":1,"kind":"trust_gc","state":"completed","operation_id":operation_id,"pruned":pruned}),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_test_support::GlobalStateGuard;

    fn saved() -> TrustGrantStore {
        read_store(&tirith_core::policy::config_dir().unwrap())
            .unwrap()
            .2
    }

    #[test]
    fn service_prepares_without_applying_and_retries_preserve_the_original_plan() {
        let state = GlobalStateGuard::new().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let request = |pattern: &str| {
            TrustChange::Add(AddGrantRequest {
                pattern: pattern.into(),
                rule: Some("shortened_url".into()),
                ttl: Some("1h".into()),
                permanent: false,
                broad: false,
                all_rules: false,
                reason: None,
                scope: GrantTarget::User,
            })
        };
        let mut service = TrustService::capture(state.roots().cwd.to_str()).unwrap();
        let first = service
            .prepare(&id, request("https://mirror.example/x"))
            .unwrap();
        assert_eq!(first["operation"]["state"], "planned");
        assert_eq!(first["operation"]["operation_id"], id);
        assert_eq!(first["applied"], false);
        assert!(!service
            .context
            .config
            .join(trust_grants::STORE_FILE)
            .exists());
        let retry = service
            .prepare(&id, request("https://mirror.example/x"))
            .unwrap();
        assert_eq!(first["operation"], retry["operation"]);
        assert!(service
            .prepare(&id, request("https://other.example/x"))
            .is_err());
        assert!(service.list(None, true, "all").unwrap()["grants"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn empty_migration_retry_keeps_its_durable_noop_after_legacy_drift() {
        let state = GlobalStateGuard::new().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let mut service = TrustService::capture(state.roots().cwd.to_str()).unwrap();
        let first = service.prepare(&id, TrustChange::MigrateUser).unwrap();
        assert_eq!(first["operation"]["state"], "completed");
        assert_eq!(first["operation"]["no_op"], true);
        assert!(first["operation"]["steps"].as_array().unwrap().is_empty());
        let config = tirith_core::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let legacy = json!({"version":1,"entries":[{"pattern":"https://mirror.example/later","rule_id":"shortened_url"}]}).to_string();
        std::fs::write(config.join("trust.json"), &legacy).unwrap();
        let mut retry_service = TrustService::capture(state.roots().cwd.to_str()).unwrap();
        let retry = retry_service
            .prepare(&id, TrustChange::MigrateUser)
            .unwrap();
        assert_eq!(first["operation"], retry["operation"]);
        assert_eq!(
            std::fs::read_to_string(config.join("trust.json")).unwrap(),
            legacy
        );
        assert!(!config.join(trust_grants::STORE_FILE).exists());
        assert!(retry_service
            .prepare(
                &id,
                TrustChange::Revoke {
                    id: uuid::Uuid::new_v4().to_string()
                }
            )
            .is_err());
    }

    #[test]
    fn revoked_grant_retry_cannot_become_a_new_revocation_after_state_drift() {
        let state = GlobalStateGuard::new().unwrap();
        let config = tirith_core::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let mut grant = TrustGrant {
            id: uuid::Uuid::new_v4().to_string(),
            pattern: "https://mirror.example/revoked".into(),
            rule_id: Some("shortened_url".into()),
            scope: GrantScope::User,
            created_at: Utc::now().to_rfc3339(),
            expires_at: None,
            revoked_at: Some(Utc::now().to_rfc3339()),
            reason: None,
        };
        let write = |grant: &TrustGrant| {
            let mut store = TrustGrantStore::default();
            store.insert(grant).unwrap();
            std::fs::write(
                config.join(trust_grants::STORE_FILE),
                serde_json::to_vec(&store).unwrap(),
            )
            .unwrap();
        };
        write(&grant);
        let id = uuid::Uuid::new_v4().to_string();
        let mut service = TrustService::capture(state.roots().cwd.to_str()).unwrap();
        let first = service
            .prepare(
                &id,
                TrustChange::Revoke {
                    id: grant.id.clone(),
                },
            )
            .unwrap();
        assert_eq!(first["operation"]["state"], "completed");
        assert_eq!(first["operation"]["no_op"], true);
        grant.revoked_at = None;
        write(&grant);
        let mut retry_service = TrustService::capture(state.roots().cwd.to_str()).unwrap();
        let retry = retry_service
            .prepare(
                &id,
                TrustChange::Revoke {
                    id: grant.id.clone(),
                },
            )
            .unwrap();
        assert_eq!(first["operation"], retry["operation"]);
        assert!(saved().decode(0).unwrap().revoked_at.is_none());
        assert!(retry_service
            .prepare(
                &id,
                TrustChange::Revoke {
                    id: uuid::Uuid::new_v4().to_string()
                }
            )
            .is_err());
    }

    #[test]
    fn undo_of_first_grant_restores_an_empty_readable_store() {
        let state = GlobalStateGuard::new().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let mut service = TrustService::capture(state.roots().cwd.to_str()).unwrap();
        service
            .prepare(
                &id,
                TrustChange::Add(AddGrantRequest {
                    pattern: "https://mirror.example/x".into(),
                    rule: Some("shortened_url".into()),
                    ttl: Some("1h".into()),
                    permanent: false,
                    broad: false,
                    all_rules: false,
                    reason: None,
                    scope: GrantTarget::User,
                }),
            )
            .unwrap();
        let writer = MutationService::current().unwrap();
        writer.apply(&id, &service.context.snapshot).unwrap();
        let refreshed = service.context.snapshot.refresh_runtime();
        writer.undo(&id, &refreshed).unwrap();
        let mut after = TrustService::capture(state.roots().cwd.to_str()).unwrap();
        assert!(after.list(None, true, "all").unwrap()["grants"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(saved().grants.is_empty());
        assert!(!after
            .context
            .snapshot
            .policy
            .is_allowlisted_for_rule("shortened_url", "https://mirror.example/x"));
    }

    #[test]
    fn typed_add_expiry_and_revocation_keep_one_id_and_reveal_broader_trust() {
        let _state = GlobalStateGuard::new().unwrap();
        let target = "https://mirror.example/install.sh";
        assert_eq!(
            add(
                target,
                Some("pipe_to_interpreter"),
                None,
                true,
                false,
                false,
                None,
                "user",
                true
            ),
            0
        );
        let original = saved().decode(0).unwrap();
        assert!(original.expires_at.is_none());
        assert_eq!(change_expiry(&original.id, Some("1h"), false, true), 0);
        assert_eq!(saved().grants.len(), 1);
        assert_eq!(saved().decode(0).unwrap().id, original.id);
        assert!(saved().decode(0).unwrap().expires_at.is_some());
        assert_eq!(
            add(
                target,
                Some("PIPE_TO_INTERPRETER"),
                Some("1h"),
                false,
                false,
                false,
                None,
                "user",
                true
            ),
            0
        );
        assert_eq!(
            saved().grants.len(),
            1,
            "rule matching must use enforcement's case-insensitive identity"
        );
        assert_eq!(saved().decode(0).unwrap().id, original.id);
        assert_eq!(
            add(
                "mirror.example",
                None,
                Some("7d"),
                false,
                true,
                true,
                None,
                "user",
                true
            ),
            0
        );
        assert_eq!(revoke(&original.id, true), 0);
        let context = Context::capture().unwrap();
        let remaining = remaining(&context, target, Some("pipe_to_interpreter")).unwrap();
        assert!(remaining
            .iter()
            .any(|row| row["pattern"] == "mirror.example" && row["rule_id"].is_null()));
        assert!(!saved()
            .applicable(None, Utc::now())
            .iter()
            .any(|grant| grant.id == original.id));
        assert_eq!(change_expiry(&original.id, Some("1d"), false, true), 1);
    }

    #[test]
    fn rule_and_broadness_opt_ins_precede_all_store_side_effects() {
        let _state = GlobalStateGuard::new().unwrap();
        assert_eq!(
            add(
                "https://mirror.example/x",
                None,
                None,
                false,
                false,
                false,
                None,
                "user",
                true
            ),
            1
        );
        assert_eq!(
            add(
                "mirror.example",
                Some("shortened_url"),
                None,
                false,
                false,
                false,
                None,
                "user",
                true
            ),
            1
        );
        assert!(!tirith_core::policy::config_dir()
            .unwrap()
            .join(trust_grants::STORE_FILE)
            .exists());
        assert!(!tirith_core::policy::state_dir()
            .unwrap()
            .join("operations")
            .exists());
    }

    #[test]
    fn project_grant_applies_only_to_enrolled_checkout_and_next_read_sees_removal() {
        let state = GlobalStateGuard::new().unwrap();
        std::fs::create_dir(state.roots().cwd.join(".git")).unwrap();
        let target = "https://mirror.example/x";
        assert_eq!(
            add(
                target,
                Some("shortened_url"),
                None,
                false,
                false,
                false,
                None,
                "project",
                true
            ),
            0
        );
        let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert!(snapshot
            .policy
            .is_allowlisted_for_rule("shortened_url", target));
        let other = state.roots().cwd.join("nested");
        std::fs::create_dir_all(other.join(".git")).unwrap();
        let outside = EffectivePolicySnapshot::resolve(other.to_str(), ResolutionMode::Runtime);
        assert!(!outside
            .policy
            .is_allowlisted_for_rule("shortened_url", target));
        std::fs::remove_file(
            tirith_core::policy::config_dir()
                .unwrap()
                .join(trust_grants::STORE_FILE),
        )
        .unwrap();
        assert!(snapshot.revalidate_inputs().is_err());
        let refreshed = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert!(!refreshed
            .policy
            .is_allowlisted_for_rule("shortened_url", target));
    }

    #[test]
    fn malformed_expiry_agrees_across_legacy_display_and_runtime() {
        let _state = GlobalStateGuard::new().unwrap();
        let config = tirith_core::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let values = [json!("bad"), json!(42), json!(false), json!({})];
        let entries: Vec<_> = values.into_iter().enumerate().map(|(i, expiry)| json!({"pattern":format!("https://mirror.example/{i}"),"ttl_expires":expiry})).collect();
        std::fs::write(
            config.join("trust.json"),
            serde_json::to_vec(&json!({"version":1,"entries":entries})).unwrap(),
        )
        .unwrap();
        let context = Context::capture().unwrap();
        assert!(context.snapshot.policy.allowlist.is_empty());
        let records = rows(&context, "user").unwrap();
        assert_eq!(records.len(), 4);
        assert!(records.iter().all(|row| row.state == GrantState::Invalid));
    }

    #[test]
    fn legacy_migration_preserves_expiry_scope_and_invalid_records_and_downgrade_is_narrower() {
        let _state = GlobalStateGuard::new().unwrap();
        let config = tirith_core::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let expiry = trust_grants::expiry_from_ttl("7d", Utc::now()).unwrap();
        std::fs::write(config.join("trust.json"), serde_json::to_vec(&json!({"version":1,"entries":[{"pattern":"https://mirror.example/x","rule_id":"shortened_url","ttl_expires":expiry},{"pattern":"https://invalid.example/x","ttl_expires":false}]})).unwrap()).unwrap();
        assert_eq!(migrate("user", true), 0);
        let legacy: Value =
            serde_json::from_str(&std::fs::read_to_string(config.join("trust.json")).unwrap())
                .unwrap();
        assert_eq!(legacy["entries"].as_array().unwrap().len(), 1);
        assert_eq!(legacy["entries"][0]["ttl_expires"], false);
        let grant = saved().decode(0).unwrap();
        assert_eq!(grant.expires_at.as_deref(), Some(expiry.as_str()));
        assert_eq!(grant.scope, GrantScope::User);
        let new: Value = serde_json::to_value(saved()).unwrap();
        assert!(new.get("entries").is_none());
        assert_eq!(migrate("user", true), 0);
        assert_eq!(saved().grants.len(), 1);
    }

    #[test]
    fn projection_redacts_content_without_destroying_ids_states_and_sources() {
        let _state = GlobalStateGuard::new().unwrap();
        let mut context = Context::capture().unwrap();
        context.patterns = CompiledCustomPatterns::new(&[".+".into()]);
        let grant = TrustGrant {
            id: uuid::Uuid::new_v4().to_string(),
            pattern: "https://mirror.example/private".into(),
            rule_id: Some("secret_rule".into()),
            scope: GrantScope::User,
            created_at: Utc::now().to_rfc3339(),
            expires_at: None,
            revoked_at: None,
            reason: Some("private reason".into()),
        };
        let row = grant_row(&grant, &context).project(&context);
        assert_eq!(row["id"], grant.id);
        assert_eq!(row["state"], "effective");
        assert_eq!(row["source"], "operator_grant");
        let text = serde_json::to_string(&row).unwrap();
        for private in ["mirror.example", "secret_rule", "private reason"] {
            assert!(!text.contains(private));
        }
    }

    #[test]
    fn explain_resolves_private_grant_id_and_reports_broader_user_eligibility() {
        let state = GlobalStateGuard::new().unwrap();
        std::fs::create_dir_all(state.roots().cwd.join(".git")).unwrap();
        let config = tirith_core::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let project = ProjectIdentity::capture(state.roots().cwd.to_str()).unwrap();
        let selected = TrustGrant {
            id: uuid::Uuid::new_v4().to_string(),
            pattern: "https://mirror.example/private".into(),
            rule_id: Some("shortened_url".into()),
            scope: GrantScope::Project { project },
            created_at: Utc::now().to_rfc3339(),
            expires_at: None,
            revoked_at: Some(Utc::now().to_rfc3339()),
            reason: None,
        };
        let broader = TrustGrant {
            id: uuid::Uuid::new_v4().to_string(),
            pattern: "mirror.example".into(),
            rule_id: None,
            scope: GrantScope::User,
            revoked_at: None,
            ..selected.clone()
        };
        let store = TrustGrantStore {
            schema_version: trust_grants::STORE_VERSION,
            grants: vec![
                serde_json::to_value(&selected).unwrap(),
                serde_json::to_value(&broader).unwrap(),
            ],
        };
        std::fs::write(
            config.join(trust_grants::STORE_FILE),
            serde_json::to_vec(&store).unwrap(),
        )
        .unwrap();
        let mut context = Context::capture_at(state.roots().cwd.to_str()).unwrap();
        context.patterns = CompiledCustomPatterns::new(&[".+".into()]);
        let value = explain_value(&mut context, &selected.id, "project").unwrap();
        assert_eq!(value["selected_grant_id"], selected.id);
        assert_eq!(value["grants"][0]["state"], "revoked");
        assert_eq!(value["matching_effective_grants"][0]["id"], broader.id);
        assert_eq!(value["matching_effective_grants"][0]["scope"], "user");
        assert_eq!(value["semantics"], "trust_eligibility_only");
        assert_eq!(value["command_evaluated"], false);
        assert!(!value.to_string().contains("mirror.example"));
        assert!(explain_value(&mut context, &selected.id, "user").is_err());
    }
}
