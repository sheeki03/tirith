//! `tirith baseline learn|status|reset` (M10 ch5, design-decision D2).
//!
//! Thin presenter over [`tirith_core::baseline`] (the window, salted hashing,
//! and store I/O live in the library); this module is output, the
//! `policy.baseline_enabled` toggle, and the `reset` prompt.
//!
//! The anomaly baseline is OPT-IN (D2). Subcommands: `learn` flips
//! `policy.baseline_enabled` to `true`; `status` shows the top 20 patterns plus
//! the enabled flag and an early-baseline note; `reset` zeroes the store
//! (prompts unless `--yes`; `--json` requires `--yes`).
//!
//! Privacy: the store records only salted-sha256 hashes and low-cardinality
//! categoricals — never raw hostnames or paths.

use std::path::PathBuf;

use tirith_core::baseline;
use tirith_core::policy::{self as policy_mod, Policy};

use super::{confirm, write_json_stdout};

// ─── learn (enable) ──────────────────────────────────────────────────────────

/// `tirith baseline learn` — turn the opt-in baseline ON by setting
/// `policy.baseline_enabled = true` in the local policy file.
pub fn learn(json: bool) -> i32 {
    let target_path = match resolve_policy_path() {
        Ok(p) => p,
        Err(code) => return code,
    };

    if let Err(e) = update_baseline_flag(&target_path, true) {
        eprintln!(
            "tirith baseline learn: failed to update {}: {e}",
            target_path.display()
        );
        return 1;
    }

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "baseline_enabled": true,
            "policy_path": target_path.display().to_string(),
        });
        if !write_json_stdout(&out, "tirith baseline learn: failed to write JSON output") {
            return 1;
        }
    } else {
        eprintln!(
            "tirith baseline: learning ON (written to {}).",
            target_path.display()
        );
        eprintln!(
            "  From now on tirith records a privacy-hashed observation for every finding and"
        );
        eprintln!("  surfaces an Info 'first time / rare for you' note for novel patterns. No raw");
        eprintln!("  hostnames or paths are stored — only salted hashes. It never blocks.");
        eprintln!(
            "  Expect 'early-baseline mode' (everything looks new) until ~{} observations.",
            baseline::EARLY_BASELINE_ENTRIES
        );
    }
    0
}

// ─── status ──────────────────────────────────────────────────────────────────

/// `tirith baseline status` — top 20 patterns, the enabled flag, and the
/// early-baseline note. Always exits 0.
pub fn status(json: bool) -> i32 {
    let policy = Policy::discover_partial(None);
    let top = baseline::status(20);
    let total = baseline::entry_count();
    let early = total < baseline::EARLY_BASELINE_ENTRIES;

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "baseline_enabled": policy.baseline_enabled,
            "total_observations": total,
            "early_baseline_mode": early,
            "early_baseline_threshold": baseline::EARLY_BASELINE_ENTRIES,
            "window_days": baseline::WINDOW_DAYS,
            "top_patterns": top,
        });
        if !write_json_stdout(&out, "tirith baseline status: failed to write JSON output") {
            return 1;
        }
        return 0;
    }

    eprintln!(
        "tirith baseline: {}",
        if policy.baseline_enabled {
            "ON (learning)"
        } else {
            "OFF (opt-in — run `tirith baseline learn` to enable)"
        }
    );
    eprintln!(
        "  {total} observation(s) in the last {} days.",
        baseline::WINDOW_DAYS
    );
    if early {
        eprintln!(
            "  early-baseline mode: fewer than {} observations — anomaly signals are not yet",
            baseline::EARLY_BASELINE_ENTRIES
        );
        eprintln!(
            "  meaningful (everything looks new). Keep using tirith to fill in the baseline."
        );
    }

    if top.is_empty() {
        eprintln!("  No patterns recorded yet.");
        return 0;
    }

    eprintln!();
    eprintln!("Top patterns (privacy-hashed; counts over the window):");
    for p in &top {
        let host = p.host_hash.as_deref().unwrap_or("-");
        let eco = p.ecosystem.as_deref().unwrap_or("-");
        let repo = p.cwd_repo_hash.as_deref().unwrap_or("-");
        eprintln!(
            "  {:>4}x  {:<32} host={host} eco={eco} sudo={} repo={repo}",
            p.count, p.rule_id, p.sudo_flag,
        );
    }
    0
}

// ─── reset ─────────────────────────────────────────────────────────────────--

/// `tirith baseline reset` — zero the store. Prompts unless `--yes`; `--json`
/// requires `--yes` (no prompt on a machine surface).
pub fn reset(yes: bool, json: bool) -> i32 {
    let total = baseline::entry_count();

    if total == 0 {
        if json {
            let out = serde_json::json!({
                "schema_version": 1,
                "reset": false,
                "removed": 0,
            });
            if !write_json_stdout(&out, "tirith baseline reset: failed to write JSON output") {
                return 1;
            }
        } else {
            eprintln!("tirith baseline reset: nothing to reset (baseline is empty).");
        }
        return 0;
    }

    if json && !yes {
        eprintln!("tirith baseline reset: --yes required in JSON mode to confirm reset");
        return 2;
    }
    if !json
        && !confirm(
            &format!("Zero the anomaly baseline ({total} observation(s))?"),
            yes,
        )
    {
        eprintln!("Aborted — baseline left in place.");
        return 0;
    }

    match baseline::reset() {
        Ok(removed) => {
            if json {
                let out = serde_json::json!({
                    "schema_version": 1,
                    "reset": removed > 0,
                    "removed": removed,
                });
                if !write_json_stdout(&out, "tirith baseline reset: failed to write JSON output") {
                    return 1;
                }
            } else {
                eprintln!("tirith baseline: reset — {removed} observation(s) removed.");
            }
            0
        }
        Err(e) => {
            eprintln!("tirith baseline reset: {e}");
            2
        }
    }
}

// ─── helpers ───────────────────────────────────────────────────────────────--

/// Resolve the policy file `learn` writes to: the active local policy if
/// discoverable, else the user config-dir default.
fn resolve_policy_path() -> Result<PathBuf, i32> {
    if let Some(existing) = policy_mod::discover_local_policy_path(None) {
        return Ok(existing);
    }
    let user = policy_mod::config_dir().ok_or_else(|| {
        eprintln!("tirith baseline: could not resolve user config dir");
        1
    })?;
    Ok(user.join("policy.yaml"))
}

/// Idempotently set the `baseline_enabled` line in a policy YAML file:
/// append-or-rewrite, never touching other lines.
pub(super) fn update_baseline_flag(path: &std::path::Path, enable: bool) -> std::io::Result<()> {
    // Baseline enablement must never follow an untrusted repository policy
    // symlink (repo-0361): confine the read-modify-write beneath the policy
    // file's own directory (the repository `.tirith` directory or the user
    // config dir) through a retained no-follow parent capability, refuse a
    // symlinked destination, and publish atomically. A repository checkout
    // that points `.tirith/policy.yaml` at `~/.bashrc` is refused instead of
    // appended to, and an unreadable file is no longer treated as empty
    // (which would have clobbered its real contents).
    let root = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "policy path has no parent directory",
            )
        })?;
    let policy = Policy::discover_local_only(root.to_str());
    let prepared =
        super::prepare_config_destination_permitted(root, path, true, &policy, true, true)?;
    let existing = match prepared.read_capped(1024 * 1024) {
        Ok(bytes) => String::from_utf8(bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "policy file is not UTF-8; refusing to rewrite it",
            )
        })?,
        Err(tirith_core::util::OpenRegularError::NotFound) => String::new(),
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("refusing to read unsafe policy file: {e:?}"),
            ))
        }
    };
    let new_line = format!("baseline_enabled: {enable}");

    let mut out = String::new();
    let mut replaced = false;
    for line in existing.lines() {
        if line.trim_start().starts_with("baseline_enabled:") {
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

    super::write_prepared_config_file_permitted(
        root,
        path,
        prepared,
        out.as_bytes(),
        true,
        &policy,
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_baseline_flag_appends_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, "paranoia: 2\nfail_mode: open\n").unwrap();

        update_baseline_flag(&path, true).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("baseline_enabled: true"), "{content}");
        assert!(content.contains("paranoia: 2"), "other lines preserved");

        // Flip off — must REPLACE the line, not duplicate it.
        update_baseline_flag(&path, false).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("baseline_enabled: false"), "{content}");
        assert!(!content.contains("baseline_enabled: true"), "{content}");
        assert_eq!(
            content.matches("baseline_enabled:").count(),
            1,
            "must not duplicate the key"
        );
    }

    #[cfg(unix)]
    #[test]
    fn update_baseline_flag_refuses_symlinked_policy() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let external = outside.path().join("bashrc-like");
        std::fs::write(&external, "export PATH=/usr/bin\n").unwrap();
        let link = dir.path().join("policy.yaml");
        std::os::unix::fs::symlink(&external, &link).unwrap();

        assert!(
            update_baseline_flag(&link, true).is_err(),
            "a symlinked policy must be refused, not appended to"
        );
        assert_eq!(
            std::fs::read_to_string(&external).unwrap(),
            "export PATH=/usr/bin\n",
            "the symlink target must remain untouched"
        );
    }
}
