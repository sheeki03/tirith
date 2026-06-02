//! `tirith iac guard|check-plan|require-plan-before-apply` (M8 ch3).
//!
//! * `guard on|off|status` — flips `policy.context_guard_enabled` (the shared
//!   M8 ch1 operator switch). The non-prod IaC rules stay tool-only.
//! * `check-plan <tfplan>` — parse a saved Terraform/Pulumi/OpenTofu plan,
//!   record its SHA-256 in `state_dir()/iac_plans/`, and report change counts
//!   plus IAM/SG/public-bucket flags.
//! * `require-plan-before-apply on|off|status` — flips
//!   `policy.iac_require_plan_before_apply` (drives `IacApplyWithoutPlan` /
//!   `IacPlanHashMismatch`).

use std::io::Write;
use std::path::{Path, PathBuf};

use tirith_core::iac_plan::{self, PlanSummary, PlanTool};
use tirith_core::policy::{self as policy_mod, Policy};

/// `tirith iac guard on|off|status` — flip the shared operational-context
/// switch.
pub fn guard(action: &str, json: bool) -> i32 {
    let enable = match action {
        "on" | "enable" | "true" => true,
        "off" | "disable" | "false" => false,
        "status" => return guard_status(json),
        other => {
            eprintln!("tirith iac guard: unknown action '{other}' (expected on|off|status)");
            return 2;
        }
    };

    let target_path = match resolve_policy_path() {
        Ok(p) => p,
        Err(code) => return code,
    };

    if let Err(e) = update_policy_key(&target_path, "context_guard_enabled", &enable.to_string()) {
        eprintln!(
            "tirith iac guard: failed to update {}: {e}",
            target_path.display()
        );
        return 1;
    }

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "guard_enabled": enable,
            "policy_path": target_path.display().to_string(),
        });
        let mut stdout = std::io::stdout().lock();
        if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
            return 1;
        }
    } else {
        eprintln!(
            "tirith iac guard: {} (written to {})",
            if enable { "ON" } else { "OFF" },
            target_path.display(),
        );
    }
    0
}

fn guard_status(json: bool) -> i32 {
    let policy = Policy::discover_partial(None);
    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "guard_enabled": policy.context_guard_enabled,
            "policy_path": policy.path,
        });
        let mut stdout = std::io::stdout().lock();
        if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
            return 1;
        }
    } else {
        eprintln!(
            "tirith iac guard: {}",
            if policy.context_guard_enabled {
                "ON"
            } else {
                "OFF"
            }
        );
    }
    0
}

/// `tirith iac require-plan-before-apply on|off|status`.
pub fn require_plan_before_apply(action: &str, json: bool) -> i32 {
    let enable = match action {
        "on" | "enable" | "true" => true,
        "off" | "disable" | "false" => false,
        "status" => return require_plan_status(json),
        other => {
            eprintln!(
                "tirith iac require-plan-before-apply: unknown action '{other}' (expected on|off|status)"
            );
            return 2;
        }
    };

    let target_path = match resolve_policy_path() {
        Ok(p) => p,
        Err(code) => return code,
    };

    if let Err(e) = update_policy_key(
        &target_path,
        "iac_require_plan_before_apply",
        &enable.to_string(),
    ) {
        eprintln!(
            "tirith iac require-plan-before-apply: failed to update {}: {e}",
            target_path.display()
        );
        return 1;
    }

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "require_plan_before_apply": enable,
            "policy_path": target_path.display().to_string(),
        });
        let mut stdout = std::io::stdout().lock();
        if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
            return 1;
        }
    } else {
        eprintln!(
            "tirith iac require-plan-before-apply: {} (written to {})",
            if enable { "ON" } else { "OFF" },
            target_path.display(),
        );
    }
    0
}

fn require_plan_status(json: bool) -> i32 {
    let policy = Policy::discover_partial(None);
    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "require_plan_before_apply": policy.iac_require_plan_before_apply,
            "policy_path": policy.path,
        });
        let mut stdout = std::io::stdout().lock();
        if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
            return 1;
        }
    } else {
        eprintln!(
            "tirith iac require-plan-before-apply: {}",
            if policy.iac_require_plan_before_apply {
                "ON"
            } else {
                "OFF"
            }
        );
    }
    0
}

/// `tirith iac check-plan <tfplan> [--tool terraform|pulumi|tofu]` —
/// parse a saved plan, record its SHA-256 in `state_dir()/iac_plans/`,
/// and print the change summary.
pub fn check_plan(plan_path: &Path, forced_tool: Option<&str>, json: bool) -> i32 {
    let purged = iac_plan::purge_old_plans();

    // Cap the read at MAX_PLAN_SIZE_BYTES (32 MiB) so a symlink-to-/dev/zero or
    // oversized JSON can't OOM the CLI before parsing (PR-127 review #10).
    match std::fs::metadata(plan_path) {
        Ok(md) if md.len() > iac_plan::MAX_PLAN_SIZE_BYTES => {
            eprintln!(
                "tirith iac check-plan: {} is {} bytes; cap is {} bytes ({} MiB). Refusing to read.",
                plan_path.display(),
                md.len(),
                iac_plan::MAX_PLAN_SIZE_BYTES,
                iac_plan::MAX_PLAN_SIZE_BYTES / (1024 * 1024),
            );
            return 1;
        }
        _ => {}
    }
    let bytes = match std::fs::read(plan_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "tirith iac check-plan: cannot read {}: {e}",
                plan_path.display()
            );
            return 1;
        }
    };
    if bytes.len() as u64 > iac_plan::MAX_PLAN_SIZE_BYTES {
        // metadata() may have lied (symlink, /dev/zero, fifo) — re-check post-read.
        eprintln!(
            "tirith iac check-plan: read {} bytes from {}; cap is {} bytes ({} MiB). Refusing to parse.",
            bytes.len(),
            plan_path.display(),
            iac_plan::MAX_PLAN_SIZE_BYTES,
            iac_plan::MAX_PLAN_SIZE_BYTES / (1024 * 1024),
        );
        return 1;
    }

    let tool = if let Some(name) = forced_tool {
        match name {
            "terraform" => PlanTool::Terraform,
            "pulumi" => PlanTool::Pulumi,
            "tofu" => PlanTool::Tofu,
            other => {
                eprintln!(
                    "tirith iac check-plan: unknown --tool '{other}' (expected terraform | pulumi | tofu)"
                );
                return 2;
            }
        }
    } else {
        iac_plan::detect_plan_tool(plan_path)
    };

    // Pulumi plans are already JSON; terraform's binary plan needs a shell-out
    // to `terraform show -json <plan>`.
    let plan_json: Vec<u8> = if iac_plan::looks_like_json(&bytes) {
        bytes.clone()
    } else {
        match iac_plan::run_terraform_show_json(plan_path, tool) {
            Ok(out) => out,
            Err(e) => {
                eprintln!(
                    "tirith iac check-plan: could not render {} via `{} show -json`: {e}",
                    plan_path.display(),
                    tool.as_str(),
                );
                eprintln!(
                    "  Hint: install the {} CLI, OR pass the JSON output of `{} show -json <plan>` directly.",
                    tool.as_str(),
                    tool.as_str(),
                );
                return 1;
            }
        }
    };

    let summary = match iac_plan::parse_plan_json(&plan_json) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tirith iac check-plan: plan parse failed: {e}");
            return 1;
        }
    };

    // Hash the ORIGINAL plan-file bytes (what the engine hashes at apply-time),
    // not the JSON rendering — they differ for terraform binary plans.
    let sha = match iac_plan::record_plan_hash(&bytes, plan_path, &summary) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("tirith iac check-plan: failed to record plan hash: {e}");
            return 1;
        }
    };

    if json {
        emit_check_plan_json(plan_path, &sha, &summary, purged)
    } else {
        emit_check_plan_human(plan_path, &sha, &summary, purged);
        0
    }
}

fn emit_check_plan_human(plan_path: &Path, sha: &str, summary: &PlanSummary, purged: usize) {
    eprintln!("tirith iac check-plan:");
    eprintln!("  plan:        {}", plan_path.display());
    eprintln!("  tool:        {}", summary.tool.as_str());
    eprintln!("  sha256:      {}", sha);
    eprintln!(
        "  changes:     create={} update={} destroy={} (total={})",
        summary.create, summary.update, summary.destroy, summary.total_changes,
    );
    if summary.has_high_risk_changes() {
        eprintln!("  high-risk categories:");
        if !summary.iam_changes.is_empty() {
            eprintln!("    iam:                {}", summary.iam_changes.join(", "));
        }
        if !summary.security_group_changes.is_empty() {
            eprintln!(
                "    security_groups:    {}",
                summary.security_group_changes.join(", ")
            );
        }
        if !summary.public_bucket_changes.is_empty() {
            eprintln!(
                "    public_buckets:     {}",
                summary.public_bucket_changes.join(", ")
            );
        }
        if !summary.db_changes.is_empty() {
            eprintln!("    db_instances:       {}", summary.db_changes.join(", "));
        }
        if !summary.lb_changes.is_empty() {
            eprintln!("    load_balancers:     {}", summary.lb_changes.join(", "));
        }
    }
    if purged > 0 {
        eprintln!("  purged {} old plan(s) from the cache", purged);
    }
    eprintln!("  recorded in: {}", iac_plan::iac_plans_dir_display(),);
}

fn emit_check_plan_json(plan_path: &Path, sha: &str, summary: &PlanSummary, purged: usize) -> i32 {
    let out = serde_json::json!({
        "schema_version": 1,
        "plan_path": plan_path.display().to_string(),
        "sha256": sha,
        "summary": summary,
        "high_risk": summary.has_high_risk_changes(),
        "purged": purged,
        "store_dir": iac_plan::iac_plans_dir_display(),
    });
    let mut stdout = std::io::stdout().lock();
    if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
        return 1;
    }
    0
}

fn resolve_policy_path() -> Result<PathBuf, i32> {
    if let Some(existing) = policy_mod::discover_local_policy_path(None) {
        return Ok(existing);
    }
    let user = policy_mod::config_dir().ok_or_else(|| {
        eprintln!("tirith iac: could not resolve user config dir");
        1
    })?;
    Ok(user.join("policy.yaml"))
}

/// Idempotent append-or-rewrite of a single policy key. Mirrors the
/// helper used by `cli::ssh` / `cli::context` for `context_guard_enabled`.
fn update_policy_key(path: &Path, key: &str, value: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let new_line = format!("{key}: {value}");

    let prefix = format!("{key}:");

    let mut out = String::new();
    let mut replaced = false;
    for line in existing.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with(&prefix) {
            out.push_str(&new_line);
            out.push('\n');
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&new_line);
        out.push('\n');
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    use std::io::Write as _;
    f.write_all(out.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn update_policy_key_creates_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        update_policy_key(&path, "iac_require_plan_before_apply", "true").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("iac_require_plan_before_apply: true"));
    }

    #[test]
    fn update_policy_key_replaces_existing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(
            &path,
            "paranoia: 2\niac_require_plan_before_apply: true\nfail_mode: open\n",
        )
        .unwrap();
        update_policy_key(&path, "iac_require_plan_before_apply", "false").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("iac_require_plan_before_apply: false"));
        assert!(content.contains("paranoia: 2"));
        assert!(!content.contains("iac_require_plan_before_apply: true"));
    }

    #[test]
    fn update_policy_key_distinct_keys_dont_collide() {
        // Prefix-matching must use `key:`, not just `key`.
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(
            &path,
            "context_guard_enabled: false\niac_require_plan_before_apply: false\n",
        )
        .unwrap();
        update_policy_key(&path, "iac_require_plan_before_apply", "true").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("context_guard_enabled: false"));
        assert!(content.contains("iac_require_plan_before_apply: true"));
    }
}
