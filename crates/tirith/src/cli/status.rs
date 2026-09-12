//! `tirith status` — the canonical "am I protected?" command.
//!
//! Builds on the cheap `doctor --quick` gather (protection mode + hook + policy)
//! and adds policy SCOPE and threat-DB freshness. Unlike the poller-safe
//! `doctor --quick` (which always exits 0 for the VS Code extension), `status`
//! carries an exit-code contract: it exits NON-ZERO when protection is PROVABLY
//! reduced (warn-only / degraded / no hook), and 0 when actively blocking OR when a
//! configured hook's live mode is not visible to this external process (only bash
//! re-exports it). A CI step or wary user gets a hard signal on a real downgrade,
//! without a false alarm on a protected shell whose live mode it cannot see.

use crate::cli::doctor;
use crate::cli::prompt_status::ProtectionHealth;
use crate::cli::threatdb_cmd;

pub fn run(json: bool) -> i32 {
    run_with_requirement(json, false)
}

pub fn run_with_requirement(json: bool, require_verified_blocking: bool) -> i32 {
    let status = StatusSnapshot::capture(json).finish(require_verified_blocking);
    if json {
        if !super::write_json_stdout(&status.projection(), "tirith status: cannot write JSON") {
            return 1;
        }
    } else {
        status.print_human();
    }
    status.exit_code
}

/// The helper's final status uses the same snapshot, projection and strict exit
/// contract. Its existing diagnostic keys remain alongside the canonical result.
pub(crate) fn run_authenticated(
    proof: tirith_core::execution_state::ShellVerificationProof,
) -> i32 {
    let mut snapshot = StatusSnapshot::capture(true);
    let (observation, evidence) =
        super::protection_evidence::ProtectionEvidence::from_authenticated_shell(proof);
    if evidence.verified_blocking {
        snapshot.quick.protection_mode = "guarded".into();
    }
    snapshot.quick.protection_evidence = evidence;
    let status = snapshot.finish(true);
    let value = serde_json::json!({
        "observation": observation,
        "protection": status.snapshot.quick.protection_evidence,
        "status": status.projection(),
        "status_exit_code": status.exit_code,
    });
    if !super::write_json_stdout(&value, "tirith: cannot write shell verification result") {
        return 1;
    }
    status.exit_code
}

struct StatusSnapshot {
    quick: doctor::QuickDoctorInfo,
    scope: Option<&'static str>,
    tdb: threatdb_cmd::ThreatDbStatus,
    audit_recording: super::audit_health::AuditHealth,
    shell_target: serde_json::Value,
    approval: super::package_approval_authority::PackageApprovalAvailability,
}

impl StatusSnapshot {
    fn capture(include_shell_target: bool) -> Self {
        let quick = doctor::gather_quick_info();
        let cwd = std::env::current_dir()
            .ok()
            .map(|p| p.display().to_string());
        let scope = tirith_core::policy::discover_local_policy_path_scoped(cwd.as_deref())
            .map(|(_, s)| scope_label(s));
        Self {
            quick,
            scope,
            tdb: threatdb_cmd::gather_status(),
            audit_recording: super::audit_health::read(),
            shell_target: if include_shell_target {
                serde_json::json!(super::shell_target::inspect_current().ok())
            } else {
                serde_json::Value::Null
            },
            approval: super::package_approval_authority::availability(),
        }
    }

    fn finish(self, require_verified_blocking: bool) -> StatusResult {
        // A sourced hook can prove current interception without a startup-file
        // claim. Keep hook_configured as the separate disk fact in the output.
        let health = if self.quick.protection_evidence.verified_blocking {
            ProtectionHealth::Guarded
        } else {
            ProtectionHealth::classify(&self.quick.protection_mode, self.quick.hook_configured)
        };
        let exit_code = status_exit_code(
            health,
            require_verified_blocking,
            self.quick.protection_evidence.verified_blocking,
        );
        StatusResult {
            snapshot: self,
            health,
            require_verified_blocking,
            exit_code,
        }
    }
}

struct StatusResult {
    snapshot: StatusSnapshot,
    health: ProtectionHealth,
    require_verified_blocking: bool,
    exit_code: i32,
}

fn status_exit_code(health: ProtectionHealth, required: bool, verified: bool) -> i32 {
    if required && !verified {
        1
    } else {
        health.exit_code()
    }
}

impl StatusResult {
    fn projection(&self) -> serde_json::Value {
        let quick = &self.snapshot.quick;
        let evidence = &quick.protection_evidence;
        let mut out = status_json(
            &quick.protection_mode,
            self.health,
            self.snapshot.scope,
            quick.policy_path_used.as_deref(),
            quick.hook_configured,
            &self.snapshot.tdb,
        );
        out["schema_version"] = serde_json::json!(1);
        out["audit_recording"] = self.snapshot.audit_recording.projection();
        out["protection_evidence"] = serde_json::json!(evidence);
        out["shell_target"] = self.snapshot.shell_target.clone();
        out["protected"] = serde_json::json!(evidence.verified_blocking);
        out["requirement"] = serde_json::json!({
            "verified_blocking_required": self.require_verified_blocking,
            "satisfied": !self.require_verified_blocking || evidence.verified_blocking,
        });
        out["package_approval"] = serde_json::json!(self.snapshot.approval);
        out
    }

    fn print_human(&self) {
        let quick = &self.snapshot.quick;
        let evidence = &quick.protection_evidence;
        println!("tirith status");
        println!("  protection:  {}", quick.protection_mode);
        println!(
            "  hook:        {}",
            if quick.hook_configured {
                "configured"
            } else {
                "NOT configured"
            }
        );
        match (&quick.policy_path_used, &self.snapshot.scope) {
            (Some(p), Some(s)) => println!("  policy:      {p} (scope: {s})"),
            (Some(p), None) => println!("  policy:      {p}"),
            (None, _) => println!("  policy:      (none found)"),
        }
        println!("  threat db:   {}", threatdb_summary(&self.snapshot.tdb));
        println!(
            "  audit recording: {}",
            self.snapshot.audit_recording.summary()
        );
        let approval = &self.snapshot.approval;
        println!("  pkg approval: {} (optional)", approval.state);
        println!("    {}", approval.detail);
        println!("    {}", approval.next_action);
        println!();
        if evidence.verified_blocking {
            println!("tirith: blocking observed in this caller shell; evidence is limited to the authenticated diagnostic sequence");
        } else {
            match self.health {
                ProtectionHealth::Guarded => println!("tirith: hook reports blocking; current-shell blocking has not been verified"),
                ProtectionHealth::ConfiguredUnknown => println!(
                    "tirith: hook configured; this external check can't see the live per-shell mode\n  (run `tirith doctor --verify-shell` for caller-shell verification instructions)"
                ),
                other => eprintln!("tirith: NOT FULLY PROTECTED — {}", health_reason(other)),
            }
        }
        if self.require_verified_blocking && !evidence.verified_blocking {
            eprintln!("tirith: verified blocking requirement not satisfied for current-shell; configuration and inherited environment are insufficient evidence");
        }
    }
}

/// Build the `status --json` envelope. A pure seam (no env, no I/O) so the
/// JSON shape — the contract a CI step or the VS Code extension parses — is unit
/// testable. Field values mirror the human path exactly; `threat_db.error`
/// surfaces a corrupt/unreadable DB instead of silently rendering it "unsigned".
fn status_json(
    mode: &str,
    health: ProtectionHealth,
    scope: Option<&str>,
    policy_path: Option<&str>,
    hook_configured: bool,
    tdb: &threatdb_cmd::ThreatDbStatus,
) -> serde_json::Value {
    serde_json::json!({
        "protection_mode": mode,
        "health": health.label(),
        "protected": false,
        "hook_configured": hook_configured,
        "policy_path": policy_path,
        "policy_scope": scope,
        "threat_db": {
            "installed": tdb.installed,
            "age_hours": tdb.age_hours,
            "stale": tdb.stale,
            "signature_valid": tdb.signature_valid,
            "error": tdb.error.as_deref(),
        },
    })
}

fn scope_label(s: tirith_core::policy::PolicyScope) -> &'static str {
    s.as_str()
}

fn threatdb_summary(t: &threatdb_cmd::ThreatDbStatus) -> String {
    if !t.installed {
        return "not installed (run `tirith threat-db update`)".to_string();
    }
    if let Some(err) = t.error.as_deref() {
        return format!("ERROR: {err} (run `tirith threat-db update --force`)");
    }
    let age = t
        .age_hours
        .map(|h| format!("{h:.0}h old"))
        .unwrap_or_else(|| "age unknown".into());
    let sig = match t.signature_valid {
        Some(true) => "signature ok",
        Some(false) => "SIGNATURE INVALID",
        None => "unsigned",
    };
    let stale = if t.stale { ", STALE" } else { "" };
    format!("{age}, {sig}{stale}")
}

fn health_reason(h: ProtectionHealth) -> &'static str {
    match h {
        ProtectionHealth::Guarded => "protected",
        ProtectionHealth::WarnOnly => "the hook is warn-only and cannot block (TIRITH_BASH_MODE=enter or `tirith doctor --reset-bash-safe-mode`)",
        ProtectionHealth::Degraded => "protection degraded to warn-only this session (`tirith doctor --fix`)",
        ProtectionHealth::ConfiguredUnknown => {
            "the hook is configured but its live mode is not visible to an external check"
        }
        ProtectionHealth::HookMissing => "the shell hook is not configured (run `tirith init`)",
        ProtectionHealth::Unknown => "protection state could not be determined",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_harness::{EnvGuard, ENV_LOCK};

    #[test]
    fn canonical_strict_exit_never_accepts_configuration_as_observation() {
        for health in [
            ProtectionHealth::Guarded,
            ProtectionHealth::ConfiguredUnknown,
            ProtectionHealth::WarnOnly,
            ProtectionHealth::Degraded,
            ProtectionHealth::HookMissing,
            ProtectionHealth::Unknown,
        ] {
            assert_eq!(status_exit_code(health, true, false), 1);
            assert_eq!(status_exit_code(health, false, false), health.exit_code());
        }
        assert_eq!(status_exit_code(ProtectionHealth::Guarded, true, true), 0);
    }

    #[test]
    fn ordinary_canonical_capture_does_not_promote_inherited_blocking() {
        let mut guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        guard.set_env("TIRITH_STATUS", "blocks");
        guard.set_env("TIRITH_BASH_EFFECTIVE_PROTECTION", "blocks");
        guard.set_env("TIRITH_VERIFIED_BLOCKING", "1");
        let status = StatusSnapshot::capture(true).finish(true);
        let value = status.projection();
        assert_eq!(value["protected"], false);
        assert_eq!(value["protection_evidence"]["verified_blocking"], false);
        assert_eq!(value["requirement"]["satisfied"], false);
        assert_eq!(status.exit_code, 1);
    }

    /// A deterministic, "not installed" [`ThreatDbStatus`] used as a functional
    /// update base. `ThreatDbStatus` has private fields (and no `Default`), so a
    /// literal can't be written from this sibling module; instead we drive
    /// `gather_status()` down its not-installed early return by pointing
    /// `TIRITH_THREATDB_PATH` at a path that doesn't exist. That sets every field
    /// to a known empty value, and tests override the public ones via `..base`.
    fn tdb_base() -> threatdb_cmd::ThreatDbStatus {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().expect("tempdir for threat-db base");
        let missing = dir.path().join("no-such-threat-db.bin");
        let _guard = EnvGuard::set("TIRITH_THREATDB_PATH", &missing);
        let base = threatdb_cmd::gather_status();
        assert!(
            !base.installed,
            "base fixture must be not-installed; got installed=true \
             (a real DB leaked past TIRITH_THREATDB_PATH)"
        );
        base
    }

    /// `status --json` carries EXACTLY the documented top-level key set and the
    /// `threat_db` sub-object carries EXACTLY its documented keys (including the
    /// `error` key added so a corrupt DB isn't silently shown as "unsigned").
    /// This is the parse contract for CI steps and the VS Code extension.
    #[test]
    fn status_json_has_exactly_the_documented_fields() {
        let tdb = threatdb_cmd::ThreatDbStatus {
            installed: true,
            age_hours: Some(12.0),
            signature_valid: Some(true),
            stale: false,
            error: None,
            ..tdb_base()
        };
        let v = status_json(
            "guarded",
            ProtectionHealth::Guarded,
            Some("repo"),
            Some("/repo/.tirith/policy.yaml"),
            true,
            &tdb,
        );
        let obj = v.as_object().expect("status JSON is an object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "health",
                "hook_configured",
                "policy_path",
                "policy_scope",
                "protected",
                "protection_mode",
                "threat_db",
            ],
            "status JSON must carry exactly the documented top-level field set"
        );

        let tdb_obj = obj["threat_db"]
            .as_object()
            .expect("threat_db is an object");
        let mut tdb_keys: Vec<&str> = tdb_obj.keys().map(String::as_str).collect();
        tdb_keys.sort_unstable();
        assert_eq!(
            tdb_keys,
            [
                "age_hours",
                "error",
                "installed",
                "signature_valid",
                "stale",
            ],
            "threat_db must carry exactly its documented field set (incl. error)"
        );

        // Field types are the contract downstream parsers rely on.
        assert!(obj["protected"].is_boolean(), "protected must be bool");
        assert!(
            obj["hook_configured"].is_boolean(),
            "hook_configured must be bool"
        );
        assert!(
            obj["protection_mode"].is_string(),
            "protection_mode must be a string"
        );
        assert!(obj["health"].is_string(), "health must be a string");
        assert!(
            obj["policy_path"].is_string() || obj["policy_path"].is_null(),
            "policy_path must be a string or null"
        );
        assert!(
            obj["policy_scope"].is_string() || obj["policy_scope"].is_null(),
            "policy_scope must be a string or null"
        );
        assert!(
            tdb_obj["installed"].is_boolean(),
            "threat_db.installed must be bool"
        );
        assert!(
            tdb_obj["stale"].is_boolean(),
            "threat_db.stale must be bool"
        );
        assert!(
            tdb_obj["signature_valid"].is_boolean() || tdb_obj["signature_valid"].is_null(),
            "threat_db.signature_valid must be bool or null"
        );
        assert!(
            tdb_obj["age_hours"].is_number() || tdb_obj["age_hours"].is_null(),
            "threat_db.age_hours must be a number or null"
        );
        assert!(
            tdb_obj["error"].is_string() || tdb_obj["error"].is_null(),
            "threat_db.error must be a string or null"
        );
    }

    /// Optional top-level fields serialize to JSON `null` (not absent) when their
    /// source is `None`, and `error` is `null` on a healthy DB.
    #[test]
    fn status_json_nulls_for_absent_optionals() {
        let tdb = threatdb_cmd::ThreatDbStatus {
            installed: true,
            age_hours: Some(1.0),
            signature_valid: Some(true),
            stale: false,
            error: None,
            ..tdb_base()
        };
        let v = status_json(
            "off",
            ProtectionHealth::HookMissing,
            None,
            None,
            false,
            &tdb,
        );
        assert!(v["policy_path"].is_null(), "absent policy_path → JSON null");
        assert!(
            v["policy_scope"].is_null(),
            "absent policy_scope → JSON null"
        );
        assert!(
            v["threat_db"]["error"].is_null(),
            "healthy DB → threat_db.error is null"
        );
    }

    /// A not-installed DB renders the install hint.
    #[test]
    fn threatdb_summary_not_installed() {
        let summary = threatdb_summary(&tdb_base());
        assert!(
            summary.contains("not installed"),
            "not-installed summary must say so: {summary:?}"
        );
    }

    /// An installed DB with an invalid signature AND staleness renders both
    /// markers, and never the benign "unsigned" wording.
    #[test]
    fn threatdb_summary_invalid_signature_and_stale() {
        let tdb = threatdb_cmd::ThreatDbStatus {
            installed: true,
            age_hours: Some(720.0),
            signature_valid: Some(false),
            stale: true,
            error: None,
            ..tdb_base()
        };
        let summary = threatdb_summary(&tdb);
        assert!(
            summary.contains("SIGNATURE INVALID"),
            "invalid signature must show SIGNATURE INVALID: {summary:?}"
        );
        assert!(
            summary.contains(", STALE"),
            "stale DB must show , STALE: {summary:?}"
        );
        assert!(
            !summary.contains("unsigned"),
            "Some(false) is invalid, not unsigned: {summary:?}"
        );
    }

    /// A corrupt/unreadable DB (load error set) renders an ERROR line, NOT the
    /// misleading "unsigned" — the bug this fix closes.
    #[test]
    fn threatdb_summary_load_error_is_error_not_unsigned() {
        let tdb = threatdb_cmd::ThreatDbStatus {
            installed: true,
            age_hours: None,
            signature_valid: None,
            stale: true,
            error: Some("magic mismatch: not a tirith threat-db".to_string()),
            ..tdb_base()
        };
        let summary = threatdb_summary(&tdb);
        assert!(
            summary.contains("ERROR:"),
            "load error must surface as ERROR: {summary:?}"
        );
        assert!(
            !summary.contains("unsigned"),
            "a corrupt DB must not be reported as unsigned: {summary:?}"
        );
    }
}
