//! `tirith status` — the canonical "am I protected?" command.
//!
//! Builds on the cheap `doctor --quick` gather (protection mode + hook + policy)
//! and adds policy SCOPE and threat-DB freshness. Unlike the poller-safe
//! `doctor --quick` (which always exits 0 for the VS Code extension), `status`
//! carries the exit-code contract: it exits NON-ZERO whenever protection is not
//! actively blocking (warn-only / degraded / off / hook-missing), so a CI step or
//! a wary user gets a hard signal that they are not fully protected.

use crate::cli::doctor;
use crate::cli::prompt_status::ProtectionHealth;
use crate::cli::threatdb_cmd;

pub fn run(json: bool) -> i32 {
    let quick = doctor::gather_quick_info();
    let health = ProtectionHealth::classify(&quick.protection_mode, quick.hook_configured);

    // Active policy scope — local discovery only, never a network fetch.
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    let scope = tirith_core::policy::discover_local_policy_path_scoped(cwd.as_deref())
        .map(|(_, s)| scope_label(s));

    let tdb = threatdb_cmd::gather_status();

    if json {
        let out = serde_json::json!({
            "protection_mode": quick.protection_mode,
            "health": health.label(),
            "protected": health == ProtectionHealth::Guarded,
            "hook_configured": quick.hook_configured,
            "policy_path": quick.policy_path_used,
            "policy_scope": scope,
            "threat_db": {
                "installed": tdb.installed,
                "age_hours": tdb.age_hours,
                "stale": tdb.stale,
                "signature_valid": tdb.signature_valid,
            },
        });
        match serde_json::to_string_pretty(&out) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("tirith status: failed to serialize JSON: {e}");
                return 1;
            }
        }
        return health.exit_code();
    }

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
    match (&quick.policy_path_used, &scope) {
        (Some(p), Some(s)) => println!("  policy:      {p} (scope: {s})"),
        (Some(p), None) => println!("  policy:      {p}"),
        (None, _) => println!("  policy:      (none found)"),
    }
    println!("  threat db:   {}", threatdb_summary(&tdb));
    println!();
    // The verdict line: PROTECTED on stdout when guarded; otherwise the reason on
    // stderr (a security notice — always shown, never `--quiet`-gated).
    if health == ProtectionHealth::Guarded {
        println!("tirith: PROTECTED");
    } else {
        eprintln!("tirith: NOT FULLY PROTECTED — {}", health_reason(health));
    }
    health.exit_code()
}

fn scope_label(s: tirith_core::policy::PolicyScope) -> &'static str {
    use tirith_core::policy::PolicyScope::*;
    match s {
        Repo => "repo",
        User => "user",
        Org => "org",
        Remote => "remote",
        Default => "default",
    }
}

fn threatdb_summary(t: &threatdb_cmd::ThreatDbStatus) -> String {
    if !t.installed {
        return "not installed (run `tirith threat-db update`)".to_string();
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
        ProtectionHealth::Off => "the hook is inactive in this shell",
        ProtectionHealth::HookMissing => "the shell hook is not configured (run `tirith init`)",
        ProtectionHealth::Unknown => "protection state could not be determined",
    }
}
