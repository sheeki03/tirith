//! IaC plan parsing and hashing — M8 ch3.
//!
//! Terraform, OpenTofu, and Pulumi only; CDK / CloudFormation / Ansible /
//! Crossplane are out of scope (their plan shapes need their own dispatch arms).
//!
//! Two responsibilities, kept off the hot path:
//!
//! 1. **Plan parsing.** `parse_plan_json` accepts `terraform show -json` /
//!    `tofu show -json` output, or the `steps`-keyed `pulumi preview --json`
//!    shape. Counts create/update/destroy and flags IAM/SG/public-bucket/DB/LB
//!    changes against a deliberately narrow heuristic table.
//! 2. **Plan hashing + cache.** `record_plan_hash` writes
//!    `state_dir()/iac_plans/<sha256>.json`; `plan_hash_recorded` checks
//!    membership; `purge_old_plans` drops files older than the TTL.
//!
//! Shell-out happens ONLY from the `tirith iac check-plan` CLI path via
//! [`run_terraform_show_json`] — the engine hot path consults
//! `plan_hash_recorded` directly with the plan file's bytes.

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// Hard wall-clock cap for the `terraform/tofu show -json` shell-out (plans can
/// be large). The hot path never calls this.
pub const TERRAFORM_SHOW_TIMEOUT: Duration = Duration::from_secs(5);

/// Stored plans older than this are dropped by [`purge_old_plans`].
pub const PLAN_CACHE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Max bytes read into memory for a plan file or its JSON rendering.
pub const MAX_PLAN_SIZE_BYTES: u64 = 32 * 1024 * 1024;

/// Per-resource change counts plus the curated high-risk flags.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanSummary {
    /// Detected tool (`terraform` default; `pulumi` for the `steps` shape).
    #[serde(default)]
    pub tool: PlanTool,
    pub create: usize,
    pub update: usize,
    pub destroy: usize,
    /// `create + update + destroy`.
    pub total_changes: usize,
    /// Addresses in the IAM category (`aws_iam_*`, `azurerm_role_*`, etc.).
    pub iam_changes: Vec<String>,
    /// Addresses touching security groups / firewalls.
    pub security_group_changes: Vec<String>,
    /// Addresses granting public bucket access.
    pub public_bucket_changes: Vec<String>,
    /// Addresses touching DB / cluster instances.
    pub db_changes: Vec<String>,
    /// Addresses touching load balancers.
    pub lb_changes: Vec<String>,
}

impl PlanSummary {
    /// `true` if any high-risk category is non-empty.
    pub fn has_high_risk_changes(&self) -> bool {
        !self.iam_changes.is_empty()
            || !self.security_group_changes.is_empty()
            || !self.public_bucket_changes.is_empty()
            || !self.db_changes.is_empty()
            || !self.lb_changes.is_empty()
    }
}

/// Which tool emitted the plan JSON.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanTool {
    #[default]
    Terraform,
    Pulumi,
    Tofu,
}

impl PlanTool {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Terraform => "terraform",
            Self::Pulumi => "pulumi",
            Self::Tofu => "tofu",
        }
    }
}

/// Parse a plan-JSON byte buffer into a [`PlanSummary`].
///
/// Supports two shapes: Terraform/OpenTofu (`resource_changes`, each with
/// `change.actions` + `address`/`type`) and Pulumi (`steps`, each with `op` +
/// `urn`). Any other shape returns `Err`.
pub fn parse_plan_json(bytes: &[u8]) -> Result<PlanSummary, String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("json parse error: {e}"))?;

    if value.get("resource_changes").is_some() {
        parse_terraform_plan(&value)
    } else if value.get("steps").is_some() {
        parse_pulumi_plan(&value)
    } else {
        Err(
            "unrecognized plan JSON shape: expected a `resource_changes` array (terraform / tofu) or a `steps` array (pulumi)"
                .into(),
        )
    }
}

fn parse_terraform_plan(value: &serde_json::Value) -> Result<PlanSummary, String> {
    let changes = value
        .get("resource_changes")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing `resource_changes` array".to_string())?;

    let mut summary = PlanSummary {
        tool: PlanTool::Terraform,
        ..PlanSummary::default()
    };

    for change in changes {
        let address = change
            .get("address")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let resource_type = change.get("type").and_then(|v| v.as_str()).unwrap_or("");

        let actions: Vec<String> = change
            .get("change")
            .and_then(|c| c.get("actions"))
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        record_actions(&mut summary, &actions);
        record_high_risk(&mut summary, &address, resource_type);
    }

    summary.total_changes = summary.create + summary.update + summary.destroy;
    Ok(summary)
}

fn parse_pulumi_plan(value: &serde_json::Value) -> Result<PlanSummary, String> {
    let steps = value
        .get("steps")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing `steps` array".to_string())?;

    let mut summary = PlanSummary {
        tool: PlanTool::Pulumi,
        ..PlanSummary::default()
    };

    for step in steps {
        let op = step.get("op").and_then(|v| v.as_str()).unwrap_or("");
        let urn = step.get("urn").and_then(|v| v.as_str()).unwrap_or("");

        record_actions(&mut summary, &[op.to_string()]);

        // Type is the second-to-last `::` segment of the URN.
        let resource_type = pulumi_type_from_urn(urn);
        record_high_risk(&mut summary, urn, resource_type);
    }

    summary.total_changes = summary.create + summary.update + summary.destroy;
    Ok(summary)
}

fn pulumi_type_from_urn(urn: &str) -> &str {
    // urn:pulumi:<stack>::<project>::<type>::<name>
    let parts: Vec<&str> = urn.split("::").collect();
    if parts.len() >= 3 {
        parts[parts.len() - 2]
    } else {
        ""
    }
}

fn record_actions(summary: &mut PlanSummary, actions: &[String]) {
    // Terraform actions is an array (incl. `["delete", "create"]` replace);
    // Pulumi passes a single `op`.
    for action in actions {
        match action.as_str() {
            "create" => summary.create += 1,
            "update" => summary.update += 1,
            "delete" => summary.destroy += 1,
            _ => {}
        }
    }
}

/// Resource-type / address heuristics for high-risk changes (narrow table —
/// highest-signal categories only).
fn record_high_risk(summary: &mut PlanSummary, address: &str, resource_type: &str) {
    let lower = resource_type.to_lowercase();
    let address = if address.is_empty() {
        resource_type.to_string()
    } else {
        address.to_string()
    };

    // IAM mutations — Terraform (`aws_iam_role`) and Pulumi URN type names
    // (`aws:iam/role:Role`, `...roleAssignment:RoleAssignment`).
    let is_iam = lower.contains("iam_")
        || lower.contains("iam:")
        || lower.contains("iam/")
        || lower.contains(":iam")
        || lower.contains("_iam_")
        || lower.contains("role_")
        || lower.contains("clusterrole")
        || lower.contains("roleassignment")
        || lower.contains("roledefinition");
    if is_iam {
        summary.iam_changes.push(address.clone());
    }

    // Security-group / firewall.
    let is_sg = lower.contains("security_group") || lower.contains("compute_firewall");
    if is_sg {
        summary.security_group_changes.push(address.clone());
    }

    // Public bucket grants.
    let is_public_bucket = lower.contains("s3_bucket_public_access")
        || lower.contains("s3_bucket_acl")
        || lower.contains("storage_bucket_iam");
    if is_public_bucket {
        summary.public_bucket_changes.push(address.clone());
    }

    // DB / cluster.
    let is_db = lower.contains("db_instance")
        || lower.contains("rds_cluster")
        || lower.contains("sql_database_instance");
    if is_db {
        summary.db_changes.push(address.clone());
    }

    // Load balancers.
    let is_lb = lower == "aws_lb"
        || lower == "aws_alb"
        || lower.contains("_load_balancer")
        || lower.contains("forwarding_rule");
    if is_lb {
        summary.lb_changes.push(address);
    }
}

/// Compute the SHA-256 of a byte buffer as a lowercase hex string.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    let mut s = String::with_capacity(result.len() * 2);
    for b in result {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Metadata stored alongside the recorded plan-hash (the plan body is NOT
/// recorded — kept small so the store stays fast to walk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedPlan {
    pub sha256: String,
    pub recorded_at_unix: u64,
    pub plan_path: String,
    pub summary: PlanSummary,
}

/// Record a plan hash + summary into `state_dir()/iac_plans/<sha256>.json` and
/// return the hash. Idempotent — re-recording overwrites the metadata.
pub fn record_plan_hash(
    plan_bytes: &[u8],
    plan_path: &Path,
    summary: &PlanSummary,
) -> Result<String, String> {
    let sha = sha256_hex(plan_bytes);
    let dir = match crate::policy::iac_plans_dir() {
        Some(d) => d,
        None => return Err("could not resolve tirith state directory".into()),
    };
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let entry = RecordedPlan {
        sha256: sha.clone(),
        recorded_at_unix: unix_now(),
        plan_path: plan_path.display().to_string(),
        summary: summary.clone(),
    };
    let body =
        serde_json::to_vec_pretty(&entry).map_err(|e| format!("serialize recorded plan: {e}"))?;
    let dest = dir.join(format!("{sha}.json"));
    write_file_0600(&dest, &body).map_err(|e| format!("write {}: {e}", dest.display()))?;
    Ok(sha)
}

/// Status of a plan-hash lookup. PR-127 review #14: a bare `bool` conflated
/// "state dir unresolvable" with "hash not recorded" — distinguish them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanHashStatus {
    /// A plan file with the supplied hash exists in the store.
    Recorded,
    /// The store exists but the hash isn't in it — a real mismatch.
    NotRecorded,
    /// The state directory couldn't be resolved — a config problem, not a
    /// mismatch.
    StateDirUnresolved,
}

/// Check whether a plan with the supplied hash has been recorded.
pub fn plan_hash_status(sha256: &str) -> PlanHashStatus {
    let dir = match crate::policy::iac_plans_dir() {
        Some(d) => d,
        None => return PlanHashStatus::StateDirUnresolved,
    };
    let path = dir.join(format!("{sha256}.json"));
    if path.is_file() {
        PlanHashStatus::Recorded
    } else {
        PlanHashStatus::NotRecorded
    }
}

/// `true` when a plan with the supplied hash has been recorded. Folds both
/// non-recorded states into `false`; use [`plan_hash_status`] to distinguish.
pub fn plan_hash_recorded(sha256: &str) -> bool {
    matches!(plan_hash_status(sha256), PlanHashStatus::Recorded)
}

/// Human-readable iac plan store path for evidence strings; `<unresolved>` when
/// `state_dir()` can't be resolved (never panics).
pub fn iac_plans_dir_display() -> String {
    match crate::policy::iac_plans_dir() {
        Some(p) => p.display().to_string(),
        None => "<unresolved>".to_string(),
    }
}

/// Load a recorded plan's metadata, if any.
pub fn load_recorded_plan(sha256: &str) -> Option<RecordedPlan> {
    let dir = crate::policy::iac_plans_dir()?;
    let path = dir.join(format!("{sha256}.json"));
    let content = std::fs::read(&path).ok()?;
    serde_json::from_slice(&content).ok()
}

/// Purge plans older than [`PLAN_CACHE_TTL`]; returns the removed count.
/// Best-effort (errors swallowed). Prefers the JSON `recorded_at_unix` over
/// mtime (rewritten by `cp -p` / backup tools); forward clock skew never purges
/// (PR-127 review #15 + greptile P2 fix).
pub fn purge_old_plans() -> usize {
    let dir = match crate::policy::iac_plans_dir() {
        Some(d) => d,
        None => return 0,
    };
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    let now = SystemTime::now();
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        // Prefer JSON `recorded_at_unix` over mtime (backup tools rewrite mtime).
        let recorded_at = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<RecordedPlan>(&b).ok())
            .map(|p| SystemTime::UNIX_EPOCH + Duration::from_secs(p.recorded_at_unix))
            .or_else(|| entry.metadata().ok().and_then(|m| m.modified().ok()));
        let Some(recorded_at) = recorded_at else {
            continue;
        };
        // `duration_since` errs on future recorded_at (clock skew) — leave it.
        if let Ok(age) = now.duration_since(recorded_at) {
            if age > PLAN_CACHE_TTL && std::fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

fn write_file_0600(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    use std::io::Write as _;
    f.write_all(body)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Shell out to `terraform/tofu show -json <plan_path>` with a hard timeout.
///
/// Hot-path warning: MUST NOT be called from `engine::analyze` — the only
/// caller is the interactive `tirith iac check-plan`.
pub fn run_terraform_show_json(plan_path: &Path, tool: PlanTool) -> Result<Vec<u8>, String> {
    use crate::util::{run_shell_with_timeout, ShellTimeoutOutcome};

    let program = match tool {
        PlanTool::Terraform => "terraform",
        PlanTool::Tofu => "tofu",
        PlanTool::Pulumi => {
            return Err(
                "pulumi plans are JSON already — read the file directly rather than shelling out"
                    .into(),
            );
        }
    };

    let plan_path_string = plan_path.to_string_lossy().into_owned();
    // Stderr is discarded, not piped — piping without draining could deadlock
    // the child on ≥64KiB of stderr (PR-127 CodeRabbit).
    let outcome = run_shell_with_timeout(
        program,
        &["show", "-json", plan_path_string.as_str()],
        TERRAFORM_SHOW_TIMEOUT,
        Duration::from_millis(50),
        Stdio::null(),
    );
    match outcome {
        ShellTimeoutOutcome::Completed { status, stdout } => {
            if status.success() {
                if stdout.len() as u64 > MAX_PLAN_SIZE_BYTES {
                    return Err(format!(
                        "{program} show -json produced {} bytes; cap is {} bytes ({} MiB)",
                        stdout.len(),
                        MAX_PLAN_SIZE_BYTES,
                        MAX_PLAN_SIZE_BYTES / (1024 * 1024),
                    ));
                }
                Ok(stdout)
            } else {
                Err(format!(
                    "{program} show -json exited with status {}",
                    status.code().unwrap_or(-1)
                ))
            }
        }
        ShellTimeoutOutcome::NotFound => Err(format!("{program}: binary not found on PATH")),
        ShellTimeoutOutcome::SpawnError(reason) => Err(reason),
        ShellTimeoutOutcome::WaitError(reason) => Err(reason),
        ShellTimeoutOutcome::Timeout => Err(format!(
            "{program} show -json exceeded {}s timeout",
            TERRAFORM_SHOW_TIMEOUT.as_secs()
        )),
    }
}

/// Detect the IaC tool from the plan file's parent directory (e.g.
/// `Pulumi.yaml`). Falls back to Terraform, which also reads OpenTofu plans (1.x
/// wire format is identical).
pub fn detect_plan_tool(plan_path: &Path) -> PlanTool {
    let parent = match plan_path.parent() {
        Some(p) => p,
        None => return PlanTool::Terraform,
    };

    let pulumi_marker = parent.join("Pulumi.yaml").is_file() || parent.join("Pulumi.yml").is_file();
    if pulumi_marker {
        return PlanTool::Pulumi;
    }

    // tofu writes a `.tofu` dir / `tofu.lock.hcl` that terraform does not.
    let tofu_marker = parent.join(".tofu").is_dir() || parent.join("tofu.lock.hcl").is_file();
    if tofu_marker {
        return PlanTool::Tofu;
    }

    PlanTool::Terraform
}

/// Whether a byte buffer is a JSON plan (Pulumi) vs a binary terraform plan, so
/// `iac check-plan` can accept either form.
pub fn looks_like_json(bytes: &[u8]) -> bool {
    let prefix: Vec<u8> = bytes
        .iter()
        .take(256)
        .filter(|b| !b.is_ascii_whitespace())
        .copied()
        .collect();
    prefix.first() == Some(&b'{') || prefix.first() == Some(&b'[')
}

#[cfg(test)]
mod tests {
    use super::*;

    const TF_PLAN_JSON: &str = r#"{
        "format_version": "1.2",
        "terraform_version": "1.5.7",
        "resource_changes": [
            {
                "address": "aws_s3_bucket.assets",
                "type": "aws_s3_bucket",
                "change": { "actions": ["create"] }
            },
            {
                "address": "aws_iam_role.app",
                "type": "aws_iam_role",
                "change": { "actions": ["create"] }
            },
            {
                "address": "aws_security_group.web",
                "type": "aws_security_group",
                "change": { "actions": ["update"] }
            },
            {
                "address": "aws_db_instance.primary",
                "type": "aws_db_instance",
                "change": { "actions": ["delete"] }
            },
            {
                "address": "aws_cloudwatch_metric_alarm.cpu",
                "type": "aws_cloudwatch_metric_alarm",
                "change": { "actions": ["no-op"] }
            }
        ]
    }"#;

    const PULUMI_PLAN_JSON: &str = r#"{
        "steps": [
            {
                "op": "create",
                "urn": "urn:pulumi:prod::myproj::aws:iam/role:Role::svc"
            },
            {
                "op": "delete",
                "urn": "urn:pulumi:prod::myproj::aws:s3/bucket:Bucket::assets"
            }
        ]
    }"#;

    #[test]
    fn parse_terraform_plan_counts_actions() {
        let summary = parse_plan_json(TF_PLAN_JSON.as_bytes()).unwrap();
        assert_eq!(summary.create, 2);
        assert_eq!(summary.update, 1);
        assert_eq!(summary.destroy, 1);
        assert_eq!(summary.total_changes, 4);
        assert_eq!(summary.tool, PlanTool::Terraform);
    }

    #[test]
    fn parse_terraform_plan_flags_iam() {
        let summary = parse_plan_json(TF_PLAN_JSON.as_bytes()).unwrap();
        assert_eq!(summary.iam_changes, vec!["aws_iam_role.app"]);
    }

    #[test]
    fn parse_terraform_plan_flags_security_group() {
        let summary = parse_plan_json(TF_PLAN_JSON.as_bytes()).unwrap();
        assert_eq!(
            summary.security_group_changes,
            vec!["aws_security_group.web"]
        );
    }

    #[test]
    fn parse_terraform_plan_flags_db_delete() {
        let summary = parse_plan_json(TF_PLAN_JSON.as_bytes()).unwrap();
        assert_eq!(summary.db_changes, vec!["aws_db_instance.primary"]);
    }

    #[test]
    fn parse_terraform_plan_high_risk_true() {
        let summary = parse_plan_json(TF_PLAN_JSON.as_bytes()).unwrap();
        assert!(summary.has_high_risk_changes());
    }

    #[test]
    fn parse_pulumi_plan_counts_actions() {
        let summary = parse_plan_json(PULUMI_PLAN_JSON.as_bytes()).unwrap();
        assert_eq!(summary.create, 1);
        assert_eq!(summary.destroy, 1);
        assert_eq!(summary.tool, PlanTool::Pulumi);
    }

    #[test]
    fn parse_pulumi_plan_flags_iam_from_urn() {
        let summary = parse_plan_json(PULUMI_PLAN_JSON.as_bytes()).unwrap();
        assert_eq!(summary.iam_changes.len(), 1);
        assert!(summary.iam_changes[0].contains("iam/role:Role"));
    }

    #[test]
    fn parse_plan_rejects_unknown_shape() {
        let bad = r#"{ "foo": [] }"#;
        let err = parse_plan_json(bad.as_bytes()).unwrap_err();
        assert!(err.contains("unrecognized plan JSON shape"));
    }

    #[test]
    fn parse_plan_rejects_invalid_json() {
        let bad = "not json at all";
        let err = parse_plan_json(bad.as_bytes()).unwrap_err();
        assert!(err.contains("json parse error"));
    }

    #[test]
    fn sha256_hex_stable() {
        let h1 = sha256_hex(b"hello");
        let h2 = sha256_hex(b"hello");
        let h3 = sha256_hex(b"world");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn looks_like_json_detects_object() {
        assert!(looks_like_json(b"{\"foo\": 1}"));
        assert!(looks_like_json(b"   \n  [1,2,3]"));
    }

    #[test]
    fn looks_like_json_rejects_binary() {
        // Any non-`{`/`[` first non-whitespace byte rejects.
        assert!(!looks_like_json(&[0x50, 0x4b, 0x03, 0x04]));
    }

    #[test]
    fn detect_plan_tool_handles_missing_parent_dir() {
        // Must not panic on a path without a parent.
        let path = std::path::PathBuf::from("");
        let _ = detect_plan_tool(&path);
    }

    #[test]
    fn pulumi_type_from_urn_handles_short_urn() {
        assert_eq!(pulumi_type_from_urn(""), "");
        assert_eq!(pulumi_type_from_urn("urn:pulumi"), "");
        assert_eq!(
            pulumi_type_from_urn("urn:pulumi::proj::aws:iam/role:Role::svc"),
            "aws:iam/role:Role",
        );
    }
}
