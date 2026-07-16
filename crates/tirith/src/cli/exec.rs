//! `tirith exec check|provenance` (M9 ch5) — the COLD, off-hot-path provenance
//! surface. `check <bin>` resolves a bare name on `$PATH` (first hit) and reports
//! provenance + shadowing; `provenance <path>` inspects a path directly. Both run
//! the expensive probes (stat, `file --brief`, `codesign`) that NEVER run on the
//! engine hot path — see [`tirith_core::exec_provenance`].

use std::io::Write;
use std::path::{Path, PathBuf};

use tirith_core::exec_provenance::{self, Provenance};
use tirith_core::path_audit;
use tirith_core::policy::{self as policy_mod, Policy};
use tirith_core::verdict::{Finding, Severity};

use super::write_json_stdout;

/// `tirith exec guard on|off|status` — flip / report `policy.exec_guard_enabled`.
///
/// When ON, the exec hot path runs the three cheap leader-provenance rules
/// (`ExecInTmp`, `ExecInRepoBin`, `PathWritableDirBeforeSystem`); off by default.
/// Mirrors `tirith hooks guard` (append-or-rewrite one line in local `policy.yaml`, 0600).
pub fn guard(action: &str, json: bool) -> i32 {
    let enable = match action {
        "on" | "enable" | "true" => true,
        "off" | "disable" | "false" => false,
        "status" => return guard_status(json),
        other => {
            eprintln!("tirith exec guard: unknown action '{other}' (expected on|off|status)");
            return 2;
        }
    };

    let target_path = match resolve_policy_path_for_guard() {
        Ok(p) => p,
        Err(code) => return code,
    };

    if let Err(e) = update_policy_guard_key(&target_path, enable) {
        eprintln!(
            "tirith exec guard: failed to update {}: {e}",
            target_path.display()
        );
        return 1;
    }

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "exec_guard_enabled": enable,
            "policy_path": target_path.display().to_string(),
        });
        if !write_json_stdout(&out, "tirith exec guard: failed to write JSON output") {
            return 1;
        }
    } else {
        eprintln!(
            "tirith exec guard: {} (written to {})",
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
            "exec_guard_enabled": policy.exec_guard_enabled,
            "policy_path": policy.path,
        });
        if !write_json_stdout(&out, "tirith exec guard: failed to write JSON output") {
            return 1;
        }
    } else {
        eprintln!(
            "tirith exec guard: {}",
            if policy.exec_guard_enabled {
                "ON"
            } else {
                "OFF"
            }
        );
        if !policy.exec_guard_enabled {
            eprintln!(
                "  (when ON, a command whose leader resolves under /tmp, inside the repo, or \
                 from a user-writable PATH dir ahead of the system path will WARN on the exec \
                 hot path. Run `tirith exec check <bin>` for the full cold provenance.)"
            );
        }
    }
    0
}

fn resolve_policy_path_for_guard() -> Result<PathBuf, i32> {
    if let Some(existing) = policy_mod::discover_local_policy_path(None) {
        return Ok(existing);
    }
    let user = policy_mod::config_dir().ok_or_else(|| {
        eprintln!("tirith exec guard: could not resolve user config dir");
        1
    })?;
    Ok(user.join("policy.yaml"))
}

/// Largest policy file we will read-modify-write for a guard toggle. A policy
/// YAML is hand-authored and tiny; 1 MiB bounds a hostile or symlinked-to-huge
/// target so the read cannot be turned into an unbounded slurp.
const MAX_POLICY_SIZE: u64 = 1024 * 1024;

/// Idempotently set the `exec_guard_enabled` line in a policy YAML, leaving
/// other lines untouched.
///
/// NOTE: byte-for-byte identical (apart from the `exec_guard_enabled` key) to
/// `cli::hooks::update_policy_guard_key`. The two are kept as deliberate
/// duplicates because unifying them would require a shared third module; if you
/// edit one, mirror the change in the other.
///
/// Symlink-hardened (F16): the policy path is a repo-discovered
/// `<repo>/.tirith/policy.yaml` (or `<config>/tirith/policy.yaml`), so an attacker
/// who can plant a symlink there could otherwise redirect this truncating write
/// onto an arbitrary file. Three layers defend the write:
///   * `canonical_within` against the GRANDPARENT (`<repo>` / `<config>`)
///     canonicalizes through the containing `.tirith` directory, so a SYMLINKED
///     `.tirith` that escapes the repo is rejected before any read or write.
///   * the read uses `O_NOFOLLOW` + a size cap (refuses a symlinked final
///     component, bounds a hostile target); and
///   * the write uses `O_NOFOLLOW` + `0600` (refuses a symlinked final component).
///
/// The grandparent is the right containment root because the policy path is always
/// at least three components deep (`<root>/.tirith/policy.yaml`); passing the
/// parent (`.tirith`) instead is a tautology for a fixed `policy.yaml` filename and
/// would NOT catch a symlinked `.tirith`. A malformed path with no grandparent is
/// rejected rather than written.
fn update_policy_guard_key(path: &std::path::Path, enable: bool) -> std::io::Result<()> {
    // The containment root is the grandparent: <repo>/.tirith/policy.yaml → <repo>,
    // <config>/tirith/policy.yaml → <config>. A policy path is always at least
    // three components deep; refuse a malformed shallower path rather than guess.
    let containment_root = path.parent().and_then(|p| p.parent()).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "policy path must be <root>/<dir>/policy.yaml",
        )
    })?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Containment FIRST: reject a symlinked containing directory (e.g. a planted
    // `.tirith` symlink) that escapes the trusted root before we read or write
    // through it. `O_NOFOLLOW` on the final component alone misses this, because
    // the OS still follows an intermediate-dir symlink during path resolution.
    // Done after create_dir_all so a legit first-run `.tirith` exists to canonicalize.
    if !tirith_core::util::canonical_within(path, containment_root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "refusing to write policy through a symlinked path",
        ));
    }

    // Read the current contents WITHOUT following a symlinked final component. An
    // absent file is an empty baseline (the key is then appended); any other read
    // failure (symlinked, oversized, I/O) aborts rather than clobbering blind.
    let existing = match tirith_core::util::read_text_no_follow_capped(path, MAX_POLICY_SIZE) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(tirith_core::util::OpenRegularError::NotFound) => String::new(),
        Err(e) => return Err(open_regular_io_error(e)),
    };
    let new_line = format!("exec_guard_enabled: {enable}");

    let mut out = String::new();
    let mut replaced = false;
    for line in existing.lines() {
        if line.trim_start().starts_with("exec_guard_enabled:") {
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

    // Truncating write that REFUSES to follow a symlinked final component (0600).
    let mut f = tirith_core::util::open_write_no_follow(path, true)?;
    f.write_all(out.as_bytes())
}

/// Map an `OpenRegularError` from the no-follow policy read onto an `io::Error`
/// so the guard read-modify-write surfaces a single failure type to the caller.
fn open_regular_io_error(e: tirith_core::util::OpenRegularError) -> std::io::Error {
    match e {
        tirith_core::util::OpenRegularError::Io(io) => io,
        tirith_core::util::OpenRegularError::NotRegularFile => std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "policy path is not a regular file (symlink or special file)",
        ),
        tirith_core::util::OpenRegularError::TooLarge => std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "policy file exceeds the size cap",
        ),
        tirith_core::util::OpenRegularError::NotFound => {
            std::io::Error::new(std::io::ErrorKind::NotFound, "policy file not found")
        }
    }
}

/// `tirith exec check <bin>` — resolve `bin` on `$PATH`, report provenance +
/// shadowing. Exit 1 on any High finding, 0 otherwise, 2 if `bin` does not resolve.
pub fn check(bin: &str, json: bool) -> i32 {
    let path_value = std::env::var("PATH").unwrap_or_default();
    let hits = path_audit::which_all(bin, &path_value);

    let Some(first) = hits.first().cloned() else {
        if json {
            let body = serde_json::json!({
                "schema_version": 1,
                "command": bin,
                "resolved": false,
                "message": "not found on PATH",
            });
            let _ = write_json_stdout(&body, "tirith exec check: failed to write JSON output");
        } else {
            eprintln!("tirith exec check: `{bin}` was not found on $PATH.");
        }
        return 2;
    };

    let prov = exec_provenance::provenance_of(&first);
    let mut findings = prov.findings();
    if let Some(shadow) = exec_provenance::shadow_finding(bin, &first) {
        findings.push(shadow);
    }

    if json {
        let body = serde_json::json!({
            "schema_version": 1,
            "command": bin,
            "resolved": true,
            "resolved_path": first.display().to_string(),
            "all_path_hits": hits.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "provenance": prov,
            "findings": findings,
        });
        if !write_json_stdout(&body, "tirith exec check: failed to write JSON output") {
            return 1;
        }
    } else {
        print_human_check(bin, &first, &hits, &prov, &findings);
    }

    exit_for(&findings)
}

/// `tirith exec provenance <path>` — inspect a path's provenance. Exit 1 on a
/// High finding, 0 otherwise, 2 if the path is not a file.
pub fn provenance(path: &str, json: bool) -> i32 {
    let p = expand_path(path);
    let prov = exec_provenance::provenance_of(&p);

    if !prov.exists {
        if json {
            let body = serde_json::json!({
                "schema_version": 1,
                "path": p.display().to_string(),
                "exists": false,
            });
            let _ = write_json_stdout(&body, "tirith exec provenance: failed to write JSON output");
        } else {
            eprintln!(
                "tirith exec provenance: `{}` is not a regular file.",
                p.display()
            );
        }
        return 2;
    }

    let findings = prov.findings();

    if json {
        let body = serde_json::json!({
            "schema_version": 1,
            "path": p.display().to_string(),
            "provenance": prov,
            "findings": findings,
        });
        if !write_json_stdout(&body, "tirith exec provenance: failed to write JSON output") {
            return 1;
        }
    } else {
        print_human_provenance(&prov, &findings);
    }

    exit_for(&findings)
}

/// Expand a leading `~/` against the home dir; otherwise return the path as-is.
fn expand_path(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

/// Exit 1 when any High/Critical finding is present, else 0.
fn exit_for(findings: &[Finding]) -> i32 {
    let high = findings
        .iter()
        .any(|f| matches!(f.severity, Severity::High | Severity::Critical));
    if high {
        1
    } else {
        0
    }
}

fn print_human_check(
    bin: &str,
    resolved: &Path,
    hits: &[PathBuf],
    prov: &Provenance,
    findings: &[Finding],
) {
    eprintln!("tirith exec check `{bin}`:");
    eprintln!(
        "  resolves to: {}",
        super::sanitize_for_human_output(&resolved.display().to_string(), false)
    );
    if hits.len() > 1 {
        eprintln!("  also on PATH ({} total):", hits.len());
        for h in hits.iter().skip(1) {
            eprintln!(
                "    {}",
                super::sanitize_for_human_output(&h.display().to_string(), false)
            );
        }
    }
    print_provenance_body(prov);
    print_findings(findings);
}

fn print_human_provenance(prov: &Provenance, findings: &[Finding]) {
    eprintln!(
        "tirith exec provenance `{}`:",
        super::sanitize_for_human_output(&prov.path, false)
    );
    print_provenance_body(prov);
    print_findings(findings);
}

fn print_provenance_body(prov: &Provenance) {
    eprintln!(
        "  package manager: {}",
        prov.package_owner
            .as_ref()
            .map(|o| format!("{} ({})", o.manager, o.root))
            .unwrap_or_else(|| "none (not under a known install root)".to_string())
    );
    eprintln!("  signature: {}", prov.signature.as_str());
    eprintln!(
        "  file type: {}",
        prov.file_type.as_deref().unwrap_or("unknown")
    );
    if let Some(mode) = &prov.mode {
        eprintln!(
            "  mode: {mode}{}",
            if prov.world_writable {
                " (WORLD-WRITABLE)"
            } else {
                ""
            }
        );
    }
    if let Some(secs) = prov.modified_secs_ago {
        eprintln!(
            "  modified: {secs}s ago{}",
            if prov.recently_modified {
                " (RECENT — within 5 min)"
            } else {
                ""
            }
        );
    }
}

fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        eprintln!("  no provenance concerns.");
        return;
    }
    eprintln!("\n  {} finding(s):", findings.len());
    for f in findings {
        eprintln!(
            "    [{}] {} — {}",
            f.severity,
            f.rule_id,
            super::sanitize_for_human_output(&f.title, false)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_path_handles_tilde_and_plain() {
        assert_eq!(expand_path("/usr/bin/git"), PathBuf::from("/usr/bin/git"));
        if let Some(home) = home::home_dir() {
            assert_eq!(expand_path("~/bin/x"), home.join("bin/x"));
        }
    }

    #[test]
    fn exit_for_high_is_1_else_0() {
        let high = vec![Finding {
            rule_id: tirith_core::verdict::RuleId::ExecWorldWritable,
            severity: Severity::High,
            title: "t".into(),
            description: "d".into(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }];
        assert_eq!(exit_for(&high), 1);
        assert_eq!(exit_for(&[]), 0);
    }

    #[test]
    fn check_nonexistent_command_exits_2() {
        // A command guaranteed not on PATH → exit 2 (not resolved).
        assert_eq!(check("tirith-no-such-bin-xyz-9999", true), 2);
    }

    #[test]
    fn guard_unknown_action_returns_2() {
        assert_eq!(guard("bogus", false), 2);
    }

    #[test]
    fn update_policy_guard_key_appends_and_replaces() {
        // Real layout: <root>/.tirith/policy.yaml so the grandparent containment
        // root (<root>) exists and is not a symlink — the legit write must pass.
        let dir = tempfile::tempdir().unwrap();
        let tirith_dir = dir.path().join(".tirith");
        std::fs::create_dir(&tirith_dir).unwrap();
        let path = tirith_dir.join("policy.yaml");
        std::fs::write(&path, "paranoia: 2\nfail_mode: open\n").unwrap();

        update_policy_guard_key(&path, true).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("exec_guard_enabled: true"), "{content}");
        assert!(content.contains("paranoia: 2"), "other lines preserved");

        // Flip off — must REPLACE the existing line, not duplicate it.
        update_policy_guard_key(&path, false).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("exec_guard_enabled: false"), "{content}");
        assert_eq!(
            content.matches("exec_guard_enabled:").count(),
            1,
            "must not duplicate the key"
        );

        // The written YAML must deserialize back into the field the engine
        // reads at its tier-1 force-past gate (`policy.exec_guard_enabled`).
        update_policy_guard_key(&path, true).unwrap();
        let yaml = std::fs::read_to_string(&path).unwrap();
        let parsed = Policy::try_parse_yaml(&yaml).expect("policy YAML must parse");
        assert!(
            parsed.exec_guard_enabled,
            "exec_guard_enabled must round-trip to the engine-readable Policy"
        );
    }

    /// F16: a guard toggle whose policy path's FINAL component is a SYMLINK must
    /// NOT write through to the link target — the truncating `O_NOFOLLOW` write
    /// refuses the symlink, so a sentinel the link points at is byte-unchanged.
    #[cfg(unix)]
    #[test]
    fn update_policy_guard_key_does_not_follow_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let sentinel = dir.path().join("sentinel.yaml");
        let original = "paranoia: 2\n# do not clobber\n";
        std::fs::write(&sentinel, original).unwrap();

        // Real layout: <root>/.tirith/ (a genuine dir, so the grandparent
        // containment passes) with policy.yaml -> ../sentinel.yaml as the
        // symlinked FINAL component — the case O_NOFOLLOW must catch.
        let tirith_dir = dir.path().join(".tirith");
        std::fs::create_dir(&tirith_dir).unwrap();
        let policy = tirith_dir.join("policy.yaml");
        std::os::unix::fs::symlink(&sentinel, &policy).unwrap();

        // The toggle must FAIL closed rather than rewrite the sentinel.
        let res = update_policy_guard_key(&policy, true);
        assert!(
            res.is_err(),
            "writing through a symlinked policy path must error, got {res:?}"
        );
        // The sentinel target is untouched: no key written, content identical.
        let after = std::fs::read_to_string(&sentinel).unwrap();
        assert_eq!(after, original, "symlink target must be unchanged");
        assert!(
            !after.contains("exec_guard_enabled"),
            "the guard key must not have leaked into the symlink target: {after}"
        );
    }

    /// F16 (intermediate-dir escape): when the CONTAINING `.tirith` is itself a
    /// symlink to an outside directory, the write must be rejected. `O_NOFOLLOW`
    /// on the final component alone does NOT catch this (the OS follows the dir
    /// symlink during path resolution, and `policy.yaml` inside it is a real
    /// file) — only the grandparent `canonical_within` containment does. The
    /// outside sentinel must be left byte-for-byte unchanged.
    #[cfg(unix)]
    #[test]
    fn update_policy_guard_key_rejects_symlinked_intermediate_dir() {
        let base = tempfile::tempdir().unwrap();

        // An outside directory holding a real (non-symlink) policy.yaml sentinel.
        let outside = base.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let sentinel = outside.join("policy.yaml");
        let original = "paranoia: 2\n# do not clobber via dir symlink\n";
        std::fs::write(&sentinel, original).unwrap();

        // The repo root, with `.tirith` a SYMLINK pointing at `outside`.
        let root = base.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let tirith_link = root.join(".tirith");
        std::os::unix::fs::symlink(&outside, &tirith_link).unwrap();

        // Toggling on <root>/.tirith/policy.yaml resolves to outside/policy.yaml.
        let policy = tirith_link.join("policy.yaml");
        let res = update_policy_guard_key(&policy, true);
        assert!(
            res.is_err(),
            "a symlinked intermediate `.tirith` dir must be rejected, got {res:?}"
        );

        // The outside sentinel must be untouched: not written through.
        let after = std::fs::read_to_string(&sentinel).unwrap();
        assert_eq!(
            after, original,
            "the dir-symlink target must be byte-unchanged"
        );
        assert!(
            !after.contains("exec_guard_enabled"),
            "the guard key must not have leaked through the dir symlink: {after}"
        );
    }
}
