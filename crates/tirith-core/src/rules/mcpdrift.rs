//! MCP lockfile drift detection — fires when the committed `.tirith/mcp.lock` no
//! longer matches the repo's current MCP-server inventory. The FileScan-path
//! counterpart to `tirith mcp verify`: on `tirith scan`, parse the lockfile, rebuild
//! the inventory from the repo's MCP configs, and emit [`RuleId::McpServerDrift`] on a diff.
//!
//! FileScan-only (never the exec hot path), so no tier-1 PATTERN_TABLE entry is needed
//! for reachability (`tier1_scan` always returns `true` for FileScan). The module
//! self-selects by path: only the `.tirith/mcp.lock` target triggers the rebuild, so a
//! loose `mcp.lock` elsewhere is not misclassified.
//!
//! **Privacy.** Findings carry only aggregate counts and server *names* — never an env
//! value, URL userinfo, or secret-dependent commitment. The v8 lockfile records only
//! env-name and URL-userinfo presence, so secret rotation is intentionally unobservable.
//!
//! **A malformed lockfile is itself a finding** (same `McpServerDrift` rule/severity,
//! naming the parse failure without echoing bytes): an unparseable baseline can't be
//! diffed, exactly how an attacker would hide a surface change. An unreadable repo root
//! or a malformed config still yields zero findings — those are operational, not tampering.

use std::collections::HashMap;
use std::path::Path;

use crate::mcp_lock;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// `true` when `path` is the `.tirith/mcp.lock` this rule scans: basename `mcp.lock`
/// AND immediate parent `.tirith`. A loose `mcp.lock` elsewhere is not this lockfile.
pub fn is_mcp_lockfile(path: Option<&Path>) -> bool {
    let Some(path) = path else { return false };

    let Some(basename) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if basename != mcp_lock::MCP_LOCK_FILENAME {
        return false;
    }

    let Some(parent) = path.parent() else {
        return false;
    };
    parent
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n == ".tirith")
        .unwrap_or(false)
}

/// `true` when `repo_root` looks like a real repo, so "no MCP configs found" means
/// "every locked server removed" drift rather than "not a repo". Without this gate, a
/// stray `.tirith/mcp.lock` (e.g. under `/tmp/random/`) produces a finding-storm of
/// every-server-removed (finding F9). Cheap (a few `metadata` probes), run only when the
/// rule is about to fire.
///
/// Admits iff one of:
/// 1. `repo_root` is empty / `.` — a relative scan path (`.tirith/mcp.lock`) means "scan
///    against cwd"; honor that. Also the contract the FileScan fixture path relies on.
/// 2. `.git` is a dir OR file under the root (the file form is how worktrees/submodules mark it).
/// 3. a known MCP discovery probe ([`mcp_lock::MCP_CONFIG_RELATIVE_PATHS`]) is a regular file.
///
/// No `.tirith/` arm: this rule self-selects on a `<X>/.tirith/mcp.lock` path, so `.tirith/`
/// always exists on a real scan and that arm was tautological — defeating F9. The remaining
/// arms aren't derivable from the lockfile's own presence. Rejected: an absolute path with
/// none of (2)–(3) — the F9 failure mode.
fn looks_like_repo_root(repo_root: &Path) -> bool {
    // Arm 1: a relative root with no parent components — caller pointed by relative path.
    if repo_root.as_os_str().is_empty() || repo_root == Path::new(".") {
        return true;
    }

    let git_path = repo_root.join(".git");
    if let Ok(meta) = std::fs::metadata(&git_path) {
        if meta.is_dir() || meta.is_file() {
            return true;
        }
    }

    for rel in mcp_lock::MCP_CONFIG_RELATIVE_PATHS {
        if let Ok(meta) = std::fs::metadata(repo_root.join(rel)) {
            if meta.is_file() {
                return true;
            }
        }
    }

    false
}

/// Run the MCP-drift rule against a file's contents.
///
/// `file_path` is the scanned path; the repo root is derived from it
/// (`<repo>/.tirith/mcp.lock` → `<repo>`). A non-lockfile path, or one whose root can't
/// be derived, yields no findings. `content` is the read body (non-UTF8/non-JSON → no
/// findings).
///
/// `trusted_mcp_servers` (`policy.scan.trusted_mcp_servers`): drift entries whose exact
/// source/name/transport identity is trusted are filtered before a finding is built.
///
/// `mcp_allowed_tools` (`policy.scan.mcp_allowed_tools`): per-server tool allow-list with
/// effects — (a) lockfile-side: an explicit entry requires approved live descriptor
/// coverage and checks the union of declared + descriptor names; (b) drift-side: an
/// Added/Changed identity introducing an unknown/disallowed live surface upgrades the
/// drift finding Medium→High.
pub fn check(
    content: &str,
    file_path: Option<&Path>,
    trusted_mcp_servers: &[String],
    mcp_allowed_tools: &HashMap<String, Vec<String>>,
) -> Vec<Finding> {
    if !is_mcp_lockfile(file_path) {
        return Vec::new();
    }

    // A malformed lockfile is itself a security signal (an unparseable baseline can't be
    // diffed, so an attacker could hide a surface change). Emit the same `McpServerDrift`
    // rule (distinct description) so safeguard tests / rule_explanations need no change.
    let lockfile = match mcp_lock::parse_lockfile(content) {
        Ok(l) => l,
        Err(e) => return vec![finding_for_unparseable_lockfile(&e)],
    };

    // Derive the repo root: `<repo>/.tirith/mcp.lock` → `<repo>`.
    let Some(repo_root) = file_path.and_then(|p| p.parent()).and_then(|p| p.parent()) else {
        return Vec::new();
    };

    // The root must look like a real repo before absence-of-configs counts as drift, else
    // a stray lockfile produces an every-server-removed storm (F9; see `looks_like_repo_root`).
    if !looks_like_repo_root(repo_root) {
        return Vec::new();
    }

    // `build_inventory` is total (a malformed config contributes no entries).
    let current = mcp_lock::build_inventory(repo_root);

    // Coverage is part of the security baseline, not informational metadata.
    // A current refusal/malformed config always fails, even when an operator
    // explicitly recorded it, and any change from the recorded coverage also
    // fails. Otherwise an attacker can replace an accepted config with a
    // symlink/oversized/ambiguous decoy while leaving the accepted-server hash
    // unchanged.
    let coverage_finding = finding_for_incomplete_coverage(&current, &lockfile);

    let drifts = mcp_lock::compute_drift(&current, &lockfile);

    // Evaluate the orthogonal tool allow-list on the UNFILTERED drift. Trust may
    // suppress ordinary identity drift, but it must never suppress a forbidden
    // capability introduced by that same trusted identity.
    let drifts_after_trust = drift_filter_trusted(
        drifts,
        trusted_mcp_servers,
        mcp_allowed_tools,
        &current,
        &lockfile,
    );

    let mut findings: Vec<Finding> = coverage_finding.into_iter().collect();

    // Lockfile-side: an explicit tool policy requires an operator-approved live
    // descriptor set, and every name in the union of static declarations and
    // approved descriptors must be allowed. Trust is orthogonal to both checks.
    if let Some(finding) = finding_for_missing_descriptor_coverage(&lockfile, mcp_allowed_tools) {
        findings.push(finding);
    }
    if let Some(finding) =
        finding_for_disallowed_lockfile_tools(&lockfile, mcp_allowed_tools, trusted_mcp_servers)
    {
        findings.push(finding);
    }

    if !drifts_after_trust.is_empty() {
        // A SchemaUpgradeRequired entry is a schema-wide signal (lockfile `format_version`
        // predates this build): emit a distinct Medium finding prompting `mcp lock`.
        // It does NOT short-circuit per-server drift — `compute_drift` still reports real
        // v4 drift, so a config change made during the v4→v5 window can't slip in silently.
        let migration_entry = drifts_after_trust.iter().find_map(|d| match d {
            mcp_lock::McpDrift::SchemaUpgradeRequired {
                from_version,
                to_version,
            } => Some((*from_version, *to_version)),
            _ => None,
        });
        if let Some((from_version, to_version)) = migration_entry {
            findings.push(finding_for_schema_upgrade_required(
                from_version,
                to_version,
            ));
        }

        // Per-server drift gets its own finding; filter out the schema-wide entry so it
        // doesn't pollute the change counts or server-name summary.
        let per_server_drifts: Vec<mcp_lock::McpDrift> = drifts_after_trust
            .into_iter()
            .filter(|d| !matches!(d, mcp_lock::McpDrift::SchemaUpgradeRequired { .. }))
            .collect();
        if !per_server_drifts.is_empty() {
            // Severity ladder: Medium default, High if any newly-added tool is disallowed.
            let severity =
                if any_added_tool_out_of_allowed(&per_server_drifts, mcp_allowed_tools, &current) {
                    Severity::High
                } else {
                    Severity::Medium
                };
            findings.push(finding_for_drift(&per_server_drifts, severity));
        }
    }

    findings
}

fn finding_for_incomplete_coverage(
    current: &mcp_lock::McpInventory,
    lockfile: &mcp_lock::McpLockfile,
) -> Option<Finding> {
    let current_incomplete =
        !current.malformed_configs.is_empty() || !current.rejected_configs.is_empty();
    let coverage_changed = current.malformed_configs != lockfile.malformed_configs
        || current.rejected_configs != lockfile.rejected_configs;
    if !current_incomplete && !coverage_changed {
        return None;
    }

    let mut lines = vec![format!(
        "baseline coverage: {} malformed, {} rejected; current coverage: {} malformed, {} rejected",
        lockfile.malformed_configs.len(),
        lockfile.rejected_configs.len(),
        current.malformed_configs.len(),
        current.rejected_configs.len(),
    )];
    for path in current.malformed_configs.iter().take(3) {
        lines.push(format!("  - malformed: {path:?}"));
    }
    for rejected in current.rejected_configs.iter().take(3) {
        lines.push(format!(
            "  - rejected: {:?} ({})",
            rejected.path,
            rejected_reason_label(&rejected.reason),
        ));
    }

    Some(Finding {
        rule_id: RuleId::McpServerDrift,
        severity: Severity::High,
        title: "MCP inventory coverage is incomplete or changed".to_string(),
        description: "One or more supported MCP configuration paths could not be safely \
            inventoried, or the structured coverage metadata differs from the committed \
            baseline. Tirith refuses to treat the accepted-server subset as complete because \
            an ordinary MCP client may still consume a symlinked, oversized, malformed, \
            ambiguous, or secret-bearing declaration. Fix every coverage gap before \
            refreshing the lockfile."
            .to_string(),
        evidence: vec![Evidence::Text {
            detail: lines.join("\n"),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    })
}

fn rejected_reason_label(reason: &mcp_lock::RejectedReason) -> &'static str {
    match reason {
        mcp_lock::RejectedReason::Symlink => "symlink",
        mcp_lock::RejectedReason::NotRegularFile => "not_regular_file",
        mcp_lock::RejectedReason::OutsideRepo => "outside_repo",
        mcp_lock::RejectedReason::Oversize { .. } => "oversize",
        mcp_lock::RejectedReason::Unreadable { .. } => "unreadable",
        mcp_lock::RejectedReason::AmbiguousServerObjects => "ambiguous_server_objects",
        mcp_lock::RejectedReason::AmbiguousTransport => "ambiguous_transport",
        mcp_lock::RejectedReason::SecretBearingArgument => "secret_bearing_argument",
        mcp_lock::RejectedReason::SecretBearingUrl => "secret_bearing_url",
        mcp_lock::RejectedReason::InvalidServerEntry => "invalid_server_entry",
        mcp_lock::RejectedReason::DuplicateJsonKey => "duplicate_json_key",
        mcp_lock::RejectedReason::InvalidServerField => "invalid_server_field",
        mcp_lock::RejectedReason::UnsupportedServerField => "unsupported_server_field",
    }
}

/// Drop drift entries whose exact policy identity is in `trusted`.
fn drift_filter_trusted(
    drifts: Vec<mcp_lock::McpDrift>,
    trusted: &[String],
    mcp_allowed_tools: &HashMap<String, Vec<String>>,
    current: &mcp_lock::McpInventory,
    lockfile: &mcp_lock::McpLockfile,
) -> Vec<mcp_lock::McpDrift> {
    if trusted.is_empty() {
        return drifts;
    }
    drifts
        .into_iter()
        .filter(|drift| {
            if drift_violates_allowed_tools(drift, mcp_allowed_tools, current) {
                return true;
            }
            let identity = identity_for_drift(drift, current, lockfile);
            !identity.is_some_and(|identity| trusted.iter().any(|trusted| trusted == &identity))
        })
        .collect()
}

fn identity_for_drift(
    drift: &mcp_lock::McpDrift,
    current: &mcp_lock::McpInventory,
    lockfile: &mcp_lock::McpLockfile,
) -> Option<String> {
    let (name, source_config, use_current) = match drift {
        mcp_lock::McpDrift::Removed {
            name,
            source_config,
        } => (name, source_config, false),
        mcp_lock::McpDrift::Added {
            name,
            source_config,
            ..
        } => (name, source_config, true),
        mcp_lock::McpDrift::Changed(entry) => (&entry.name, &entry.source_config, true),
        mcp_lock::McpDrift::SchemaUpgradeRequired { .. } => return None,
    };
    if use_current {
        current
            .servers
            .iter()
            .find(|server| server.name == *name && server.source_config == *source_config)
            .map(mcp_lock::McpServerEntry::policy_identity)
    } else {
        lockfile
            .servers
            .iter()
            .find(|server| server.name == *name && server.source_config == *source_config)
            .map(mcp_lock::McpLockServer::policy_identity)
    }
}

/// `true` when a drift introduces a tool NOT in `mcp_allowed_tools` for that server. Two
/// drift kinds feed the ladder: `Changed` (its `tools_added`) and `Added` (the new server's
/// declared `tools`, treated as fresh additions — else an attacker smuggles a tool via a new
/// server; CodeRabbit). Semantics: a server unlisted is unconstrained; listed with `[]`
/// forbids any tool; listed non-empty permits exactly those.
fn any_added_tool_out_of_allowed(
    drifts: &[mcp_lock::McpDrift],
    mcp_allowed_tools: &HashMap<String, Vec<String>>,
    current: &mcp_lock::McpInventory,
) -> bool {
    if mcp_allowed_tools.is_empty() {
        return false;
    }
    drifts
        .iter()
        .any(|drift| drift_violates_allowed_tools(drift, mcp_allowed_tools, current))
}

/// Evaluate one drift against the explicit capability policy before any trust
/// suppression. A trusted principal is still constrained by its allow-list.
fn drift_violates_allowed_tools(
    drift: &mcp_lock::McpDrift,
    mcp_allowed_tools: &HashMap<String, Vec<String>>,
    current: &mcp_lock::McpInventory,
) -> bool {
    let current_server = |name: &str, source_config: &str| {
        current
            .servers
            .iter()
            .find(|server| server.name == name && server.source_config == source_config)
    };
    match drift {
        mcp_lock::McpDrift::Changed(entry) => {
            let Some(server) = current_server(&entry.name, &entry.source_config) else {
                return false;
            };
            let identity = server.policy_identity();
            let Some(allowed) = mcp_allowed_tools.get(&identity) else {
                return false;
            };
            entry
                .tools_added
                .iter()
                .any(|tool| !allowed.iter().any(|candidate| candidate == tool))
        }
        mcp_lock::McpDrift::Added {
            name,
            source_config,
            ..
        } => {
            let Some(server) = current_server(name, source_config) else {
                return false;
            };
            // A newly-added server has no approved live descriptor baseline in
            // the committed lock. Any explicit allow-list therefore requires a
            // fail-closed High signal until the live set is approved.
            mcp_allowed_tools.contains_key(&server.policy_identity())
        }
        mcp_lock::McpDrift::Removed { .. } | mcp_lock::McpDrift::SchemaUpgradeRequired { .. } => {
            false
        }
    }
}

/// Build a High finding for lockfile-recorded tools outside `mcp_allowed_tools` (`None`
/// if all allowed or no policy entry). Lists a few server names + offending tools; full
/// detail belongs in `tirith mcp verify`. A recorded tool outside policy is a stronger
/// signal than ordinary drift (the lockfile should have caught it).
///
/// `trusted` is intentionally NOT consulted (PR #121 item 8): trust suppresses *drift*,
/// while `mcp_allowed_tools` is an orthogonal per-tool allow-list the operator wants
/// enforced even on a trusted server. Trust still applies to servers with NO allow-list
/// entry (nothing to enforce). Param kept for signature stability.
fn finding_for_disallowed_lockfile_tools(
    lockfile: &mcp_lock::McpLockfile,
    mcp_allowed_tools: &HashMap<String, Vec<String>>,
    _trusted: &[String],
) -> Option<Finding> {
    if mcp_allowed_tools.is_empty() {
        return None;
    }

    // (server, disallowed_tools) in stable lockfile order. An explicit allow-list entry
    // is enforced regardless of trust (PR #121 item 8); a server with no entry is skipped.
    let mut offenders: Vec<(String, Vec<String>)> = Vec::new();
    for server in &lockfile.servers {
        let identity = server.policy_identity();
        let Some(allowed) = mcp_allowed_tools.get(&identity) else {
            continue;
        };
        let mut exposed: Vec<&String> = server
            .tools
            .iter()
            .chain(server.descriptors.iter().map(|descriptor| &descriptor.name))
            .collect();
        exposed.sort();
        exposed.dedup();
        let disallowed: Vec<String> = exposed
            .into_iter()
            .filter(|t| !allowed.iter().any(|a| a == *t))
            .cloned()
            .collect();
        if !disallowed.is_empty() {
            offenders.push((server.name.clone(), disallowed));
        }
    }

    if offenders.is_empty() {
        return None;
    }

    // Summary + structured detail. Names are debug-escaped (`{:?}`) so a control byte in a
    // name can't inject into the terminal (same as `mcp.rs::escape_name`).
    let server_count = offenders.len();
    let total_tool_count: usize = offenders.iter().map(|(_, t)| t.len()).sum();
    let summary = format!(
        "{server_count} server(s) record {total_tool_count} tool(s) outside `scan.mcp_allowed_tools`"
    );

    let mut lines: Vec<String> = Vec::with_capacity(offenders.len());
    for (name, tools) in offenders.iter().take(5) {
        let escaped_tools: Vec<String> = tools.iter().map(|t| format!("{t:?}")).collect();
        lines.push(format!(
            "  - {} → {}",
            format_args!("{name:?}"),
            escaped_tools.join(", ")
        ));
    }
    if offenders.len() > 5 {
        lines.push(format!("  - … and {} more server(s)", offenders.len() - 5));
    }
    let detail = format!(
        "MCP lockfile carries tools outside policy: {summary}.\n{}",
        lines.join("\n")
    );

    Some(Finding {
        rule_id: RuleId::McpServerDrift,
        severity: Severity::High,
        title: "MCP lockfile records tools outside `mcp_allowed_tools` policy".to_string(),
        description: format!(
            "The committed `.tirith/mcp.lock` lists MCP server tools that are not in the \
             `scan.mcp_allowed_tools` allow-list for those servers ({summary}). A tool \
             recorded in the lockfile that policy does not permit is a stronger signal \
             than ordinary drift: the lockfile was supposed to be the gating baseline, \
             and a forbidden tool reached the recorded state anyway. Either widen the \
             policy's `mcp_allowed_tools` set for the affected server(s) to admit the \
             tool intentionally, or remove the tool from the server's configuration and \
             re-run `tirith mcp lock`."
        ),
        evidence: vec![Evidence::Text { detail }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    })
}

/// An explicit tool allow-list governs what the live server may expose, not
/// merely what a config file happens to declare. Without a completed descriptor
/// approval there is no evidence for that live surface, so fail closed with a
/// separate High finding. `descriptors_approved` distinguishes an intentionally
/// approved empty set from the config-only default.
fn finding_for_missing_descriptor_coverage(
    lockfile: &mcp_lock::McpLockfile,
    mcp_allowed_tools: &HashMap<String, Vec<String>>,
) -> Option<Finding> {
    let mut missing = Vec::new();
    for server in &lockfile.servers {
        if mcp_allowed_tools.contains_key(&server.policy_identity()) && !server.descriptors_approved
        {
            missing.push(server.name.clone());
        }
    }
    if missing.is_empty() {
        return None;
    }

    let listed = missing
        .iter()
        .take(5)
        .map(|name| format!("{name:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    Some(Finding {
        rule_id: RuleId::McpServerDrift,
        severity: Severity::High,
        title: "MCP tool allow-list lacks an approved live descriptor baseline".to_string(),
        description: format!(
            "`scan.mcp_allowed_tools` constrains {} exact MCP server identity(ies), but their \
             lock entries do not carry an operator-approved live `tools/list` descriptor set. \
             Static config declarations cannot prove the tools a server actually exposes. Run \
             the explicit gateway descriptor-approval flow for each identity before treating \
             the allow-list as enforced.",
            missing.len()
        ),
        evidence: vec![Evidence::Text {
            detail: format!("MCP identities missing approved live descriptors: {listed}"),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    })
}

/// Build the single drift finding, aggregated by kind ("N added, M removed, K changed")
/// with a few server names for orientation (full detail is `tirith mcp verify`'s domain).
/// `severity` is Medium by default; the caller passes High via the `mcp_allowed_tools` ladder.
fn finding_for_drift(drifts: &[mcp_lock::McpDrift], severity: Severity) -> Finding {
    let mut added = 0usize;
    let mut removed = 0usize;
    let mut changed = 0usize;
    let mut names: Vec<String> = Vec::new();
    let mut added_tools: Vec<(String, String)> = Vec::new();
    for d in drifts {
        match d {
            mcp_lock::McpDrift::Added { name, tools, .. } => {
                added += 1;
                for tool in tools {
                    if added_tools.len() < 5 {
                        added_tools.push((name.clone(), tool.clone()));
                    }
                }
            }
            mcp_lock::McpDrift::Removed { .. } => removed += 1,
            mcp_lock::McpDrift::Changed(entry) => {
                changed += 1;
                for tool in &entry.tools_added {
                    if added_tools.len() < 5 {
                        added_tools.push((entry.name.clone(), tool.clone()));
                    }
                }
            }
            mcp_lock::McpDrift::SchemaUpgradeRequired { .. } => {
                // Routed to `finding_for_schema_upgrade_required`; skip defensively here.
                continue;
            }
        }
        if names.len() < 5 {
            // Only per-server drifts contribute a name (SchemaUpgradeRequired was skipped above).
            if let Some(n) = d.name() {
                names.push(n.to_string());
            }
        }
    }

    let summary =
        format!("{added} added, {removed} removed, {changed} changed since the lockfile was taken");
    let mut detail = format!("MCP inventory drift: {summary}.");
    if !names.is_empty() {
        let listed: Vec<String> = names.iter().map(|n| format!("{n:?}")).collect();
        let suffix = if drifts.len() > names.len() {
            format!(" first servers: {} …", listed.join(", "))
        } else {
            format!(" servers: {}", listed.join(", "))
        };
        detail.push_str(&suffix);
    }
    if !added_tools.is_empty() {
        let listed: Vec<String> = added_tools
            .iter()
            .map(|(server, tool)| format!("{server:?} -> {tool:?}"))
            .collect();
        detail.push_str(&format!(" newly exposed tools: {}", listed.join(", ")));
    }

    Finding {
        rule_id: RuleId::McpServerDrift,
        severity,
        title: "MCP server inventory has drifted from the committed lockfile".to_string(),
        description: format!(
            "The MCP servers declared in this repository's configuration files no longer \
             match `.tirith/mcp.lock` ({summary}). The change may be intentional — but it \
             is a security-relevant surface change (a server added, removed, or its \
             transport / env-name presence / declared tools / URL-userinfo presence altered) \
             and should be \
             reviewed before commit. Run `tirith mcp diff` (informational) or \
             `tirith mcp verify` (gating) to see the exact drift, then re-run \
             `tirith mcp lock` to refresh the lockfile."
        ),
        evidence: vec![Evidence::Text { detail }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

/// Finding fired when the lockfile `format_version` predates this build. Same
/// `McpServerDrift`/Medium as generic drift (paperwork unchanged); the title
/// names the migration so the operator runs `tirith mcp lock` once.
fn finding_for_schema_upgrade_required(from_version: u32, to_version: u32) -> Finding {
    let detail = format!(
        "MCP lockfile is at schema v{from_version}; re-lock with `tirith mcp lock` \
         to migrate to v{to_version} and enable the latest drift detection. Real \
         drift (if any) is reported separately."
    );
    Finding {
        rule_id: RuleId::McpServerDrift,
        severity: Severity::Medium,
        title: "MCP lockfile schema upgrade required — re-run `tirith mcp lock`".to_string(),
        description: format!(
            "The committed `.tirith/mcp.lock` was written with schema version {from_version}, \
             but this build of tirith writes version {to_version}. Tirith accepts the legacy \
             shape only as a migration input, normalizes retired fields before comparison, \
             and still reports observable drift (URL changed, command changed, env or URL \
             credential presence changed, tools changed, or a server added/removed) as its \
             own finding. Re-run `tirith mcp lock` once to regenerate the lockfile \
             under v{to_version}'s current privacy, hashing, and descriptor semantics."
        ),
        evidence: vec![Evidence::Text { detail }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

/// Finding fired when `.tirith/mcp.lock` cannot be parsed — an unparseable baseline can't
/// be diffed, the silent-failure mode an attacker would use. Same `RuleId`/severity as a
/// drift finding, distinct description.
///
/// **Privacy.** Does NOT interpolate the `serde_json::Error` message: its `Display` can
/// echo the offending JSON value, and this is the file we redact secrets out of — so a
/// malformed lockfile holding a credential would leak it via the diagnostic. We name the
/// category (`unparseable JSON`, …) and surface only structurally-safe line/column numbers.
fn finding_for_unparseable_lockfile(err: &mcp_lock::McpLockLoadError) -> Finding {
    // Map the error to (category, optional location). The location, when present, is
    // line/column only — never a message that could echo bytes. The schema-version case is
    // its own arm (intact file, just an older/newer schema); its `u32`s are safe to print.
    let (category, location): (String, Option<String>) = match err {
        mcp_lock::McpLockLoadError::NotFound => {
            // Not reachable here in practice; named so no caller leaks a path string.
            ("missing baseline file".to_string(), None)
        }
        mcp_lock::McpLockLoadError::Io { .. } => {
            // Suppress io detail entirely (category-only) to forestall diagnostic-leak regressions.
            ("unreadable file".to_string(), None)
        }
        mcp_lock::McpLockLoadError::Parse { line: 0, column: 0 } => {
            ("privacy-invalid secret-presence marker".to_string(), None)
        }
        mcp_lock::McpLockLoadError::Parse { line, column } => (
            "unparseable JSON or schema mismatch".to_string(),
            Some(format!("line {line}, column {column}")),
        ),
        mcp_lock::McpLockLoadError::UnsupportedVersion { found, supported } => (
            format!(
                "incompatible lockfile schema version {found} (this tirith supports {supported})"
            ),
            None,
        ),
    };
    let location_suffix = match &location {
        Some(loc) => format!(" at {loc}"),
        None => String::new(),
    };

    // Version-mismatch gets its own title/description ("refresh the schema" vs "JSON is
    // corrupt"); both still emit Medium `McpServerDrift` so the paperwork is unchanged.
    let (title, description) = match err {
        mcp_lock::McpLockLoadError::UnsupportedVersion { found, supported } => (
            "MCP lockfile schema version is incompatible — drift cannot be verified".to_string(),
            format!(
                "The committed `.tirith/mcp.lock` declares schema version {found}, but this \
                 build of tirith supports version {supported}. Because the baseline cannot \
                 be loaded, this scan cannot diff it against the current MCP-server \
                 inventory — drift that would otherwise have been caught is silently \
                 undetectable. The lockfile was likely written by a different tirith \
                 release (a newer one that bumped the schema, or an older one that hasn't \
                 caught up to the current shape). Re-run `tirith mcp lock` to refresh the \
                 lockfile, or upgrade tirith to a build that understands schema version \
                 {found}."
            ),
        ),
        _ => (
            "MCP lockfile is unparseable — drift cannot be verified".to_string(),
            format!(
                "The committed `.tirith/mcp.lock` is not valid JSON or does not match the \
                 expected lockfile schema ({category}{location_suffix}). Because the baseline \
                 cannot be loaded, this scan cannot diff it against the current MCP-server \
                 inventory — drift that would otherwise have been caught is silently \
                 undetectable. The lockfile may have been tampered with, accidentally \
                 corrupted, or written by a future tirith version with an incompatible schema. \
                 Inspect `.tirith/mcp.lock` (it is a small JSON document), restore it from \
                 version control if it has been damaged, or re-run `tirith mcp lock` to \
                 refresh the baseline against the current inventory."
            ),
        ),
    };

    let detail = format!(
        "MCP lockfile `.tirith/mcp.lock` could not be loaded ({category}{location_suffix}); \
         drift cannot be verified."
    );

    Finding {
        rule_id: RuleId::McpServerDrift,
        severity: Severity::Medium,
        title,
        description,
        evidence: vec![Evidence::Text { detail }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::tempdir;

    use crate::mcp_lock::{McpInventory, McpLockfile, McpServerEntry, McpTransport};

    fn write_lockfile_for(repo: &Path, inv: &McpInventory) {
        let lockdir = repo.join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        let mut lock = McpLockfile::from_inventory(inv);
        // Most rule tests exercise drift/tool-policy semantics rather than the
        // separate missing-approval branch. Give each fixture an explicit live
        // descriptor approval mirroring its declared tools; dedicated tests
        // below cover config-only and approved-empty baselines.
        for server in &mut lock.servers {
            server.descriptors = server
                .tools
                .iter()
                .map(|name| {
                    mcp_lock::ToolDescriptor::from_tool_entry(&serde_json::json!({"name": name}))
                })
                .collect();
            server.descriptor_hash = mcp_lock::compute_descriptor_hash(&server.descriptors);
            server.descriptors_approved = true;
        }
        fs::write(
            lockdir.join("mcp.lock"),
            lock.render().expect("render MCP lockfile"),
        )
        .unwrap();
    }

    fn server_identity(inv: &McpInventory, name: &str) -> String {
        inv.servers
            .iter()
            .find(|server| server.name == name)
            .unwrap_or_else(|| panic!("fixture server {name:?} is missing"))
            .policy_identity()
    }

    fn write_config(repo: &Path, name: &str, body: &str) {
        if let Some(parent) = Path::new(name).parent() {
            fs::create_dir_all(repo.join(parent)).unwrap();
        }
        fs::write(repo.join(name), body).unwrap();
    }

    #[test]
    fn is_mcp_lockfile_matches_exact_layout() {
        assert!(is_mcp_lockfile(Some(&PathBuf::from(".tirith/mcp.lock"))));
        assert!(is_mcp_lockfile(Some(&PathBuf::from(
            "/abs/repo/.tirith/mcp.lock"
        ))));
        // Wrong parent dir.
        assert!(!is_mcp_lockfile(Some(&PathBuf::from("subdir/mcp.lock"))));
        // Wrong basename.
        assert!(!is_mcp_lockfile(Some(&PathBuf::from(
            ".tirith/policy.yaml"
        ))));
        // No parent.
        assert!(!is_mcp_lockfile(Some(&PathBuf::from("mcp.lock"))));
        // No path.
        assert!(!is_mcp_lockfile(None));
    }

    #[test]
    fn check_returns_empty_on_non_lockfile_path() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // A file with the right name elsewhere must not trigger.
        let v = check(
            r#"{"format_version":4,"inventory_hash":"x","configs":[],"servers":[]}"#,
            Some(&PathBuf::from("subdir/mcp.lock")),
            &[],
            &HashMap::new(),
        );
        assert!(v.is_empty());
    }

    #[test]
    fn check_returns_empty_when_inventory_matches_lockfile() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // Clean repo: lockfile matches the computed inventory → no finding.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node" } } }"#,
        );
        let inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &inv);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &HashMap::new());
        assert!(findings.is_empty(), "no drift → no finding: {findings:?}");
    }

    #[test]
    fn check_fires_when_server_added_to_config_after_lockfile() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // One server, lockfile committed; then add a second server (config drifts).
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "a": { "command": "node" } } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": {
                "a": { "command": "node" },
                "b": { "command": "deno" }
            } }"#,
        );

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &HashMap::new());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::McpServerDrift);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].description.contains("1 added"));
    }

    #[test]
    fn check_ignores_env_value_rotation() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // V8 records only env-name presence, so rotating the credential does
        // not create drift or expose a reusable verifier in the lockfile.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "env": { "API_TOKEN": "old-credential" } } } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        // Rotate the token.
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "env": { "API_TOKEN": "new-credential" } } } }"#,
        );

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &HashMap::new());
        assert!(
            findings.is_empty(),
            "same env-name presence must not drift after value rotation: {findings:?}",
        );

        // No raw credential bytes appear in the finding.
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(!serialized.contains("old-credential"));
        assert!(!serialized.contains("new-credential"));
    }

    #[test]
    fn check_fires_when_lockfile_is_malformed_json() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // A malformed lockfile is itself a finding (same RuleId/severity, distinct
        // description) — else an attacker could hide a surface change behind a broken lockfile.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node" } } }"#,
        );
        let lockdir = repo.path().join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        fs::write(lockdir.join("mcp.lock"), "{not json").unwrap();

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &HashMap::new());
        assert_eq!(
            findings.len(),
            1,
            "malformed lockfile must fire one finding"
        );
        assert_eq!(findings[0].rule_id, RuleId::McpServerDrift);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(
            findings[0].title.contains("unparseable"),
            "unparseable-lockfile title should name the failure mode: {:?}",
            findings[0].title,
        );
        assert!(
            findings[0]
                .description
                .contains("`.tirith/mcp.lock` is not valid JSON")
                || findings[0]
                    .description
                    .contains("does not match the expected lockfile schema"),
            "description should name the parse failure: {:?}",
            findings[0].description,
        );

        // The finding must not echo raw lockfile bytes (only line/column metadata is safe).
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(
            !serialized.contains("{not json"),
            "raw lockfile bytes leaked into finding: {serialized}"
        );
    }

    #[test]
    fn unparseable_finding_does_not_echo_serde_json_message() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // Privacy: `serde_json::Error`'s `Display` can echo the offending JSON value, so a
        // secret-shaped value in the lockfile must NOT reach the finding (category + line/col only).
        let repo = tempdir().unwrap();
        let lockdir = repo.path().join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();

        // A credential-shaped value serde_json would echo via `format!("{e}")`; valid JSON
        // but the wrong shape (triggers the `invalid type: string "...", expected struct …`).
        let secret = "ghp_LEAK_PROBE_DO_NOT_LET_THIS_INTO_THE_FINDING";
        let body = format!(r#""{secret}""#);
        fs::write(lockdir.join("mcp.lock"), &body).unwrap();

        let lock_path = lockdir.join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &HashMap::new());
        assert_eq!(findings.len(), 1);

        let f = &findings[0];
        // The secret, serde_json's framing substrings, and the raw body must all be absent.
        assert!(
            !f.description.contains(secret),
            "secret leaked into finding description: {}",
            f.description,
        );
        assert!(
            !f.description.contains("invalid type:"),
            "serde_json's `invalid type:` framing leaked into description: {}",
            f.description,
        );
        // Can't assert `!contains("expected")` (legit prose uses it); assert the specific
        // serde_json idioms `expected struct`/`one of`/`value` didn't leak.
        assert!(
            !f.description.contains("expected struct"),
            "serde_json's `expected struct ...` framing leaked into description: {}",
            f.description,
        );
        assert!(
            !f.description.contains("expected value"),
            "serde_json's `expected value` framing leaked into description: {}",
            f.description,
        );
        assert!(
            !f.description.contains("expected one of"),
            "serde_json's `expected one of ...` framing leaked into description: {}",
            f.description,
        );
        assert!(
            !f.description.contains(&body),
            "raw lockfile bytes leaked into description: {}",
            f.description,
        );

        // Likewise on the full serialized finding (every field).
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(
            !serialized.contains(secret),
            "secret leaked into serialized finding: {serialized}"
        );
        assert!(
            !serialized.contains("invalid type:"),
            "serde_json's `invalid type:` framing leaked into serialized finding: {serialized}"
        );
        assert!(
            !serialized.contains("expected struct"),
            "serde_json's `expected struct` framing leaked into serialized finding: {serialized}"
        );

        // Sanity: the description still names the failure category so the operator can act.
        assert!(
            f.description.contains("unparseable JSON") || f.description.contains("schema mismatch"),
            "description must still name the failure category: {}",
            f.description,
        );
    }

    #[test]
    fn check_fires_on_lockfile_with_unknown_schema_fields() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // Valid JSON but wrong schema must also surface — same verification-impossible mode.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node" } } }"#,
        );
        let lockdir = repo.path().join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        // Valid JSON, but missing every required field.
        fs::write(lockdir.join("mcp.lock"), r#"{"unrelated":true}"#).unwrap();

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &HashMap::new());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::McpServerDrift);
        assert!(
            findings[0].title.contains("unparseable"),
            "schema mismatch is treated as unparseable: {:?}",
            findings[0].title,
        );
    }

    #[test]
    fn check_ignores_url_userinfo_rotation() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // V8 records only that URL userinfo exists. Rotating those credentials
        // therefore stays clean, and no secret bytes reach a finding.
        let repo = tempdir().unwrap();
        let inv = McpInventory {
            servers: vec![McpServerEntry {
                name: "s".into(),
                transport: McpTransport::Url {
                    url: "https://host.example/sse".into(),
                    userinfo_hash: Some("present".into()),
                },
                tools: vec![],
                tools_declared: true,
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        write_lockfile_for(repo.path(), &inv);
        // Current config userinfo "rotated:newcredential" — distinctive, substring-scanned below.
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "url": "https://rotated:newcredential@host.example/sse" } } }"#,
        );

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &HashMap::new());
        assert!(
            findings.is_empty(),
            "same URL-userinfo presence must not drift after rotation: {findings:?}",
        );
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(
            !serialized.contains("rotated:newcredential"),
            "raw URL userinfo leaked into the finding: {serialized}"
        );
    }

    #[test]
    fn check_returns_empty_when_no_lockfile_layout() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // Path has parent and grandparent but is not `<x>/.tirith/mcp.lock`.
        let path = PathBuf::from("some/other/mcp.lock");
        let findings = check(
            r#"{"format_version":4,"inventory_hash":"x","configs":[],"servers":[]}"#,
            Some(&path),
            &[],
            &HashMap::new(),
        );
        assert!(findings.is_empty());
    }

    // Chunk 3 — policy-aware suppression: trusted_mcp_servers filters drift; mcp_allowed_tools
    // drives the lockfile-side finding and the drift severity ladder.

    #[test]
    fn trusted_server_suppresses_drift_finding() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // A trusted server's drift (here, dropped from config) is filtered out → no finding.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "trusted": { "command": "node" } } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        let trusted_identity = server_identity(&old_inv, "trusted");
        write_lockfile_for(repo.path(), &old_inv);

        // Drop the trusted server — drift would fire, but trust suppresses it.
        write_config(repo.path(), ".mcp.json", r#"{ "mcpServers": {} }"#);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let trusted = vec![trusted_identity];
        let findings = check(&content, Some(&lock_path), &trusted, &HashMap::new());
        assert!(
            findings.is_empty(),
            "drift on a trusted server name must be suppressed: {findings:?}",
        );
    }

    #[test]
    fn untrusted_server_still_drifts_when_others_are_trusted() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // Two drifts (trusted + untrusted); only the untrusted one surfaces.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": {
                "trusted": { "command": "node" },
                "untrusted": { "command": "node" }
            } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        let trusted_identity = server_identity(&old_inv, "trusted");
        write_lockfile_for(repo.path(), &old_inv);

        // Trusted server changes only its declared tools (identity excludes the
        // governed tool surface); untrusted rotates transport. Only the exact
        // trusted identity's drift is suppressed.
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": {
                "trusted": { "command": "node", "tools": ["added"] },
                "untrusted": { "command": "deno" }
            } }"#,
        );

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let trusted = vec![trusted_identity];
        let findings = check(&content, Some(&lock_path), &trusted, &HashMap::new());
        assert_eq!(
            findings.len(),
            1,
            "exactly one drift finding (only for the untrusted server): {findings:?}",
        );
        let f = &findings[0];
        assert_eq!(f.rule_id, RuleId::McpServerDrift);
        // The trusted server's name must NOT appear in the finding.
        let serialized = serde_json::to_string(f).unwrap();
        assert!(
            !serialized.contains("\"trusted\""),
            "trusted server's name leaked into a finding meant for the untrusted one: {serialized}",
        );
        // The untrusted name DOES appear (it's the surviving drift).
        assert!(
            serialized.contains("untrusted"),
            "untrusted server's drift should have surfaced: {serialized}",
        );
    }

    #[test]
    fn unparseable_lockfile_still_fires_even_with_trusted_servers() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // Trust can't silence a malformed lockfile — it couldn't be parsed to know which
        // servers it concerns.
        let repo = tempdir().unwrap();
        let lockdir = repo.path().join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        fs::write(lockdir.join("mcp.lock"), "{not json").unwrap();
        let lock_path = lockdir.join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();

        let trusted = vec!["trusted".to_string()];
        let findings = check(&content, Some(&lock_path), &trusted, &HashMap::new());
        assert_eq!(
            findings.len(),
            1,
            "unparseable-lockfile finding must still fire"
        );
        assert!(findings[0].title.contains("unparseable"));
    }

    #[test]
    fn lockfile_recording_disallowed_tool_fires_finding() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // A lockfile-recorded tool outside `mcp_allowed_tools` → High finding naming it.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "tools": ["read", "evil_tool"] } } }"#,
        );
        let inv = mcp_lock::build_inventory(repo.path());
        let identity = server_identity(&inv, "s");
        write_lockfile_for(repo.path(), &inv);

        // Policy: server "s" is allowed only "read".
        let mut allowed = HashMap::new();
        allowed.insert(identity, vec!["read".to_string()]);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        assert_eq!(
            findings.len(),
            1,
            "expected one finding for the disallowed tool: {findings:?}",
        );
        let f = &findings[0];
        assert_eq!(f.rule_id, RuleId::McpServerDrift);
        assert_eq!(f.severity, Severity::High);
        // The offending tool name appears; the allowed one does not need to.
        let serialized = serde_json::to_string(f).unwrap();
        assert!(
            serialized.contains("evil_tool"),
            "expected the disallowed tool to be named: {serialized}",
        );
    }

    #[test]
    fn lockfile_within_allowed_tools_fires_no_disallowed_finding() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // Every recorded tool is allowed → no disallowed-tool finding (and no drift).
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "tools": ["read", "write"] } } }"#,
        );
        let inv = mcp_lock::build_inventory(repo.path());
        let identity = server_identity(&inv, "s");
        write_lockfile_for(repo.path(), &inv);

        let mut allowed = HashMap::new();
        allowed.insert(identity, vec!["read".to_string(), "write".to_string()]);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        assert!(
            findings.is_empty(),
            "every tool in policy's allowed set → no finding: {findings:?}",
        );
    }

    #[test]
    fn explicit_allowlist_fails_when_live_descriptors_were_never_approved() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node", "tools": ["read"] } } }"#,
        );
        let inv = mcp_lock::build_inventory(repo.path());
        let identity = server_identity(&inv, "s");
        let lockdir = repo.path().join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        fs::write(
            lockdir.join("mcp.lock"),
            McpLockfile::from_inventory(&inv)
                .render()
                .expect("render MCP lockfile"),
        )
        .unwrap();

        let mut allowed = HashMap::new();
        allowed.insert(identity, vec!["read".to_string()]);
        let lock_path = lockdir.join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        assert!(findings.iter().any(|finding| {
            finding.severity == Severity::High && finding.title.contains("approved live descriptor")
        }));
    }

    #[test]
    fn allowlist_checks_approved_live_descriptor_names_not_only_static_tools() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node" } } }"#,
        );
        let inv = mcp_lock::build_inventory(repo.path());
        let identity = server_identity(&inv, "s");
        let mut lock = McpLockfile::from_inventory(&inv);
        lock.servers[0].descriptors = vec![mcp_lock::ToolDescriptor::from_tool_entry(
            &serde_json::json!({"name": "live_exec"}),
        )];
        lock.servers[0].descriptor_hash =
            mcp_lock::compute_descriptor_hash(&lock.servers[0].descriptors);
        lock.servers[0].descriptors_approved = true;
        let lockdir = repo.path().join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        let lock_path = lockdir.join("mcp.lock");
        fs::write(&lock_path, lock.render().expect("render MCP lockfile")).unwrap();

        let mut allowed = HashMap::new();
        allowed.insert(identity, Vec::new());
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(serialized.contains("live_exec"), "{serialized}");
        assert!(findings
            .iter()
            .any(|finding| finding.severity == Severity::High));
    }

    #[test]
    fn approved_live_empty_set_satisfies_an_explicit_empty_allowlist() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node" } } }"#,
        );
        let inv = mcp_lock::build_inventory(repo.path());
        let identity = server_identity(&inv, "s");
        write_lockfile_for(repo.path(), &inv);
        let mut allowed = HashMap::new();
        allowed.insert(identity, Vec::new());
        let lock_path = repo.path().join(".tirith/mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        assert!(
            findings.is_empty(),
            "approved empty set is complete: {findings:?}"
        );
    }

    #[test]
    fn server_not_in_mcp_allowed_tools_is_unconstrained() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // A server not keyed in `mcp_allowed_tools` is unconstrained — no finding.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "other": { "command": "node",
                "tools": ["anything"] } } }"#,
        );
        let inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &inv);

        let mut allowed = HashMap::new();
        allowed.insert(
            "different-server".to_string(),
            vec!["only-this".to_string()],
        );

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        assert!(
            findings.is_empty(),
            "a server not in mcp_allowed_tools is unconstrained: {findings:?}",
        );
    }

    #[test]
    fn drift_with_disallowed_added_tool_upgrades_to_high_severity() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // A `Changed` drift adding a disallowed tool upgrades the drift Medium→High.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "tools": ["read"] } } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        let identity = server_identity(&old_inv, "s");
        write_lockfile_for(repo.path(), &old_inv);

        // Add a disallowed tool to the config.
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "tools": ["read", "evil_tool"] } } }"#,
        );

        let mut allowed = HashMap::new();
        allowed.insert(identity, vec!["read".to_string()]);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        // The drift finding (1 changed) is High.
        let drift_finding = findings
            .iter()
            .find(|f| f.description.contains("1 changed"))
            .expect("expected a drift finding for the change");
        assert_eq!(
            drift_finding.severity,
            Severity::High,
            "drift adding a tool outside the allowed set must be High: {:?}",
            drift_finding,
        );
    }

    #[test]
    fn drift_with_only_allowed_added_tool_stays_medium() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // A `Changed` drift adding an allowed tool stays Medium.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "tools": ["read"] } } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        let identity = server_identity(&old_inv, "s");
        write_lockfile_for(repo.path(), &old_inv);

        // Add a tool that IS in the allowed set.
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "tools": ["read", "write"] } } }"#,
        );

        let mut allowed = HashMap::new();
        allowed.insert(identity, vec!["read".to_string(), "write".to_string()]);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        let drift_finding = findings
            .iter()
            .find(|f| f.description.contains("1 changed"))
            .expect("expected a drift finding for the change");
        assert_eq!(
            drift_finding.severity,
            Severity::Medium,
            "drift adding only allowed tools must stay Medium: {:?}",
            drift_finding,
        );
    }

    #[test]
    fn empty_allowed_tools_for_server_forbids_any_new_tool() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // An empty allow-list (`[]`) forbids ANY tool — every new tool is out-of-set.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node" } } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        let identity = server_identity(&old_inv, "s");
        write_lockfile_for(repo.path(), &old_inv);

        // The config now declares one tool.
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "tools": ["any_tool"] } } }"#,
        );

        let mut allowed = HashMap::new();
        allowed.insert(identity, vec![]);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        // The drift finding must be High (the tool is outside the [] set).
        let drift = findings
            .iter()
            .find(|f| f.description.contains("1 changed"))
            .expect("expected a drift finding");
        assert_eq!(drift.severity, Severity::High);
    }

    // CodeRabbit follow-up — extend the ladder to the `Added` path: a new server smuggling
    // a disallowed tool must escalate to High, mirroring `Changed`'s `tools_added` check.

    #[test]
    fn added_server_with_disallowed_tool_upgrades_to_high_severity() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // Lockfile has no servers; the config then adds "newcomer" with a disallowed tool.
        let repo = tempdir().unwrap();
        write_config(repo.path(), ".mcp.json", r#"{ "mcpServers": {} }"#);
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        // A brand-new server exposing "evil_tool" (not permitted for "newcomer").
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "newcomer": { "command": "node",
                "tools": ["read", "evil_tool"] } } }"#,
        );

        let current_inv = mcp_lock::build_inventory(repo.path());
        let identity = server_identity(&current_inv, "newcomer");
        let mut allowed = HashMap::new();
        allowed.insert(identity, vec!["read".to_string()]);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        let drift_finding = findings
            .iter()
            .find(|f| f.description.contains("1 added"))
            .expect("expected a drift finding for the added server");
        assert_eq!(
            drift_finding.severity,
            Severity::High,
            "an Added server exposing a tool outside the allowed set must be \
             High (symmetric with the Changed-path ladder): {:?}",
            drift_finding,
        );
    }

    #[test]
    fn added_server_with_only_allowed_static_tools_is_high_without_live_baseline() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // Static declarations cannot prove a newly-added server's live surface;
        // an explicit allow-list therefore fails closed until approval.
        let repo = tempdir().unwrap();
        write_config(repo.path(), ".mcp.json", r#"{ "mcpServers": {} }"#);
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "newcomer": { "command": "node",
                "tools": ["read", "write"] } } }"#,
        );

        let current_inv = mcp_lock::build_inventory(repo.path());
        let identity = server_identity(&current_inv, "newcomer");
        let mut allowed = HashMap::new();
        allowed.insert(identity, vec!["read".to_string(), "write".to_string()]);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        let drift_finding = findings
            .iter()
            .find(|f| f.description.contains("1 added"))
            .expect("expected a drift finding for the added server");
        assert_eq!(
            drift_finding.severity,
            Severity::High,
            "an Added server has no approved live descriptor baseline yet: {:?}",
            drift_finding,
        );
    }

    #[test]
    fn added_server_unlisted_in_mcp_allowed_tools_stays_medium() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // A new server unlisted in `mcp_allowed_tools` is unconstrained → drifts but Medium.
        let repo = tempdir().unwrap();
        write_config(repo.path(), ".mcp.json", r#"{ "mcpServers": {} }"#);
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "unconstrained-newcomer": { "command": "node",
                "tools": ["anything", "goes"] } } }"#,
        );

        // Policy mentions a DIFFERENT server, so the newcomer is unconstrained.
        let mut allowed = HashMap::new();
        allowed.insert(
            "different-server".to_string(),
            vec!["only-this".to_string()],
        );

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        let drift_finding = findings
            .iter()
            .find(|f| f.description.contains("1 added"))
            .expect("expected a drift finding for the added server");
        assert_eq!(
            drift_finding.severity,
            Severity::Medium,
            "an Added server unlisted in mcp_allowed_tools is unconstrained \
             and must stay Medium: {:?}",
            drift_finding,
        );
    }

    #[test]
    fn added_server_with_empty_allowed_tools_and_any_tool_is_high() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // A new server under an empty `[]` allow-list exposing ANY tool escalates to High.
        let repo = tempdir().unwrap();
        write_config(repo.path(), ".mcp.json", r#"{ "mcpServers": {} }"#);
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "newcomer": { "command": "node",
                "tools": ["any_tool"] } } }"#,
        );

        let current_inv = mcp_lock::build_inventory(repo.path());
        let identity = server_identity(&current_inv, "newcomer");
        let mut allowed = HashMap::new();
        allowed.insert(identity, vec![]);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        let drift_finding = findings
            .iter()
            .find(|f| f.description.contains("1 added"))
            .expect("expected a drift finding for the added server");
        assert_eq!(
            drift_finding.severity,
            Severity::High,
            "an Added server under an empty `[]` allow-list exposing any tool \
             must be High: {:?}",
            drift_finding,
        );
    }

    #[test]
    fn added_server_with_no_static_tools_is_high_until_live_empty_set_is_approved() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // Omitted static tools do not prove that the server exposes none live.
        let repo = tempdir().unwrap();
        write_config(repo.path(), ".mcp.json", r#"{ "mcpServers": {} }"#);
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "newcomer": { "command": "node" } } }"#,
        );

        let current_inv = mcp_lock::build_inventory(repo.path());
        let identity = server_identity(&current_inv, "newcomer");
        let mut allowed = HashMap::new();
        allowed.insert(identity, vec![]);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        let drift_finding = findings
            .iter()
            .find(|f| f.description.contains("1 added"))
            .expect("expected a drift finding for the added server");
        assert_eq!(
            drift_finding.severity,
            Severity::High,
            "an Added server still needs an approved live empty set: {:?}",
            drift_finding,
        );
    }

    // F1 — `UnsupportedVersion` surfaces as its own category (schema-version, not "corrupt").

    #[test]
    fn unparseable_finding_version_mismatch_arm_names_versions() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // A v999 lockfile surfaces as a `McpServerDrift` naming the schema-version case.
        let repo = tempdir().unwrap();
        let lockdir = repo.path().join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        // Plant an MCP config so `looks_like_repo_root` admits (see the F9 test).
        fs::write(repo.path().join(".mcp.json"), r#"{ "mcpServers": {} }"#).unwrap();
        fs::write(
            lockdir.join("mcp.lock"),
            r#"{ "format_version": 999, "inventory_hash": "x", "configs": [], "servers": [] }"#,
        )
        .unwrap();

        let lock_path = lockdir.join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &HashMap::new());
        assert_eq!(
            findings.len(),
            1,
            "must fire one finding for the version mismatch"
        );
        let f = &findings[0];
        assert_eq!(f.rule_id, RuleId::McpServerDrift);
        assert_eq!(f.severity, Severity::Medium);
        // Title names the version-mismatch case (not generic "unparseable").
        assert!(
            f.title.contains("schema version") || f.title.contains("incompatible"),
            "title must name the schema-version case: {}",
            f.title,
        );
        // Description carries both the found and supported numbers.
        assert!(
            f.description.contains("999"),
            "description must name the found version: {}",
            f.description,
        );
    }

    // F9 — `check` requires the derived repo root to look like a real repo before treating
    // absence-of-configs as drift; a stray `.tirith/mcp.lock` must produce zero findings.

    #[test]
    fn check_returns_empty_when_only_tirith_directory_present() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // Regression (CodeRabbit cid 3292118206): the old `.tirith/` admit arm was
        // tautological (the lockfile lives inside `.tirith/`), defeating F9. After the fix,
        // a root whose ONLY signal is `.tirith/` (no `.git`, no MCP probe) must NOT admit.
        let repo = tempdir().unwrap();
        // `<repo>/.tirith/` is the deliberate, ONLY signal under the root.
        let lockdir = repo.path().join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        // The lockfile records a server the empty inventory doesn't — would drift if tautological.
        let inv = McpInventory {
            servers: vec![McpServerEntry {
                name: "a".into(),
                transport: McpTransport::Stdio {
                    command: "node".into(),
                    args: vec![],
                    env: vec![],
                },
                tools: vec![],
                tools_declared: true,
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let body = McpLockfile::from_inventory(&inv)
            .render()
            .expect("render MCP lockfile");
        let lock_path = lockdir.join("mcp.lock");
        fs::write(&lock_path, &body).unwrap();

        let findings = check(&body, Some(&lock_path), &[], &HashMap::new());
        assert!(
            findings.is_empty(),
            "`.tirith/` alone is no longer a repo-root admit signal — its presence \
             on every real scan path made the gate tautological. With `.tirith/` as \
             the only marker (no `.git`, no MCP probe), the rule must produce zero \
             findings: {findings:?}",
        );
    }

    #[test]
    fn check_returns_empty_when_repo_root_has_no_markers() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // F9: a derived repo root with NO `.git`/`.tirith` admit signal and NO MCP probe
        // (a non-existent layout) has nothing for `looks_like_repo_root` to admit on.
        let non_existent =
            std::path::PathBuf::from("/tmp/tirith_F9_does_not_exist_xyz_xyz_xyz/.tirith/mcp.lock");
        // A well-formed v4 body — it's the path, not the content, that should make us bail.
        let inv = McpInventory {
            servers: vec![McpServerEntry {
                name: "a".into(),
                transport: McpTransport::Stdio {
                    command: "node".into(),
                    args: vec![],
                    env: vec![],
                },
                tools: vec![],
                tools_declared: true,
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let body = McpLockfile::from_inventory(&inv)
            .render()
            .expect("render MCP lockfile");
        let findings = check(&body, Some(&non_existent), &[], &HashMap::new());
        assert!(
            findings.is_empty(),
            "scanning a lockfile whose derived repo root has no repo markers must \
             produce zero findings (not a finding-storm of every-server-removed): \
             {findings:?}",
        );
    }

    #[test]
    fn check_admits_when_git_marker_present() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // A `.git/` directory is an admit signal — drift fires normally (the common case).
        let repo = tempdir().unwrap();
        fs::create_dir_all(repo.path().join(".git")).unwrap();
        // Lockfile records a server the current inventory lacks.
        let lockdir = repo.path().join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        let inv = McpInventory {
            servers: vec![McpServerEntry {
                name: "a".into(),
                transport: McpTransport::Stdio {
                    command: "node".into(),
                    args: vec![],
                    env: vec![],
                },
                tools: vec![],
                tools_declared: true,
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let body = McpLockfile::from_inventory(&inv)
            .render()
            .expect("render MCP lockfile");
        let lock_path = lockdir.join("mcp.lock");
        fs::write(&lock_path, &body).unwrap();

        let findings = check(&body, Some(&lock_path), &[], &HashMap::new());
        assert!(
            !findings.is_empty(),
            "a `.git/` directory at the repo root must admit; drift must fire \
             normally: {findings:?}",
        );
    }

    // PR #121 item 8 — `mcp_allowed_tools` no longer bows to `trusted_mcp_servers`: trust
    // suppresses drift only, not the explicit per-tool allow-list (orthogonal mechanisms).

    #[test]
    fn trusted_server_does_not_bypass_mcp_allowed_tools() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // A trusted server recording a tool outside its allow-list still fires the
        // lockfile-side finding (trust suppresses drift only).
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "trusted": { "command": "node",
                "tools": ["read", "evil_tool"] } } }"#,
        );
        let inv = mcp_lock::build_inventory(repo.path());
        let identity = server_identity(&inv, "trusted");
        write_lockfile_for(repo.path(), &inv);

        // "trusted" allows only "read", so "evil_tool" must fire regardless of trust.
        let mut allowed = HashMap::new();
        allowed.insert(identity.clone(), vec!["read".to_string()]);

        let trusted = vec![identity];

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &trusted, &allowed);
        let lockfile_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.title.contains("records tools outside"))
            .collect();
        assert_eq!(
            lockfile_findings.len(),
            1,
            "trusted server with an explicit mcp_allowed_tools entry must still fire the \
             disallowed-tool finding (trust suppresses drift only): {findings:?}",
        );
        let serialized = serde_json::to_string(lockfile_findings[0]).unwrap();
        assert!(
            serialized.contains("evil_tool"),
            "finding must name the offending tool: {serialized}",
        );
    }

    #[test]
    fn trusted_server_cannot_hide_new_disallowed_tool_drift() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{"mcpServers":{"trusted":{"command":"node","tools":["read"]}}}"#,
        );
        let baseline_inventory = mcp_lock::build_inventory(repo.path());
        let identity = server_identity(&baseline_inventory, "trusted");
        write_lockfile_for(repo.path(), &baseline_inventory);

        // Tool declarations are deliberately outside the principal identity, so
        // the trusted identity remains stable while the governed capability set
        // changes. The explicit allow-list must be evaluated before trust drops
        // ordinary drift.
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{"mcpServers":{"trusted":{"command":"node","tools":["read","exec"]}}}"#,
        );
        let mut allowed = HashMap::new();
        allowed.insert(identity.clone(), vec!["read".to_string()]);
        let trusted = vec![identity];
        let lock_path = repo.path().join(".tirith/mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &trusted, &allowed);

        let drift = findings
            .iter()
            .find(|finding| finding.title.contains("MCP server inventory has drifted"))
            .expect("disallowed drift survives trust filtering");
        assert_eq!(drift.severity, Severity::High);
        assert!(serde_json::to_string(drift).unwrap().contains("exec"));
    }

    #[test]
    fn trusted_server_without_mcp_allowed_tools_still_silent() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // Trust still suppresses when the server has NO `mcp_allowed_tools` entry — nothing
        // to enforce, so no finding fires.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "trusted": { "command": "node",
                "tools": ["read", "anything"] } } }"#,
        );
        let inv = mcp_lock::build_inventory(repo.path());
        let identity = server_identity(&inv, "trusted");
        write_lockfile_for(repo.path(), &inv);

        // No `mcp_allowed_tools` entry for "trusted".
        let allowed = HashMap::new();
        let trusted = vec![identity];

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &trusted, &allowed);
        assert!(
            findings.is_empty(),
            "no mcp_allowed_tools entry + trusted server → no findings: {findings:?}",
        );
    }

    #[test]
    fn both_trusted_and_untrusted_fire_lockfile_side_when_both_have_allow_lists() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // PR #121 item 8 — Both servers have an explicit (empty) allow-list. Trust no longer
        // bypasses the lockfile-side finding, so BOTH servers' offending tools must appear.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": {
                "trusted":   { "command": "node", "tools": ["evil_tool_a"] },
                "untrusted": { "command": "node", "tools": ["evil_tool_b"] }
            } }"#,
        );
        let inv = mcp_lock::build_inventory(repo.path());
        let trusted_identity = server_identity(&inv, "trusted");
        let untrusted_identity = server_identity(&inv, "untrusted");
        write_lockfile_for(repo.path(), &inv);

        let mut allowed = HashMap::new();
        allowed.insert(trusted_identity.clone(), vec![]);
        allowed.insert(untrusted_identity, vec![]);

        let trusted = vec![trusted_identity];

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &trusted, &allowed);
        let lockfile_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.title.contains("records tools outside"))
            .collect();
        assert_eq!(
            lockfile_findings.len(),
            1,
            "exactly one lockfile-side disallowed-tool finding (covering both servers): \
             got {findings:?}",
        );
        let serialized = serde_json::to_string(&lockfile_findings[0]).unwrap();
        assert!(
            serialized.contains("evil_tool_a"),
            "trusted server's offending tool MUST appear (explicit allow-list overrides trust): \
             {serialized}",
        );
        assert!(
            serialized.contains("evil_tool_b"),
            "untrusted server's offending tool must appear: {serialized}",
        );
    }

    // F22 (PRT II-5) — the ladder applies to NEW exposure only. A `Removed` drift is lost
    // exposure, so it must NOT upgrade to High even if the gone server recorded a bad tool.

    #[test]
    fn removed_server_with_disallowed_tools_in_lockfile_stays_medium() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // Lockfile records "s" with disallowed tool "evil"...
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "tools": ["evil"] } } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        let identity = server_identity(&old_inv, "s");
        write_lockfile_for(repo.path(), &old_inv);

        // ...then remove "s" entirely → one `Removed` drift.
        write_config(repo.path(), ".mcp.json", r#"{ "mcpServers": {} }"#);

        // "s" allows only "read", so the Changed/Added arm would go High; Removed must NOT.
        let mut allowed = HashMap::new();
        allowed.insert(identity, vec!["read".to_string()]);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);

        // The "1 removed" drift finding must stay Medium.
        let drift_finding = findings
            .iter()
            .find(|f| f.description.contains("1 removed"))
            .expect("expected a drift finding for the removed server");
        assert_eq!(
            drift_finding.severity,
            Severity::Medium,
            "a Removed drift must NOT upgrade severity from the \
             `mcp_allowed_tools` ladder — the ladder is about NEW exposure, \
             never lost exposure: {drift_finding:?}",
        );

        // The lockfile-side finding still fires (independent code path); pin it so a refactor
        // that drops one of the two findings is caught.
        let lockfile_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.title.contains("records tools outside"))
            .collect();
        assert_eq!(
            lockfile_findings.len(),
            1,
            "the lockfile-side disallowed-tool finding must still fire for \
             a Removed server whose lockfile record carries a disallowed \
             tool — its code path is independent of the drift ladder: \
             {findings:?}",
        );
    }

    // F23 (PRT II-6) — `check` can emit BOTH the lockfile-side finding AND the drift finding
    // in one call. Existing tests cover each path alone but never the cohabitation.

    #[test]
    fn check_emits_two_findings_when_lockfile_records_disallowed_tools_and_drift_present() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // "s" with tool "read" (allowed), recorded in the lockfile.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "tools": ["read"] } } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        let identity = server_identity(&old_inv, "s");
        write_lockfile_for(repo.path(), &old_inv);

        // Doctor the lockfile to ALSO record disallowed tool "evil" (snuck past `mcp lock`).
        // Use the CURRENT format version (v8) so no schema-migration finding fires — this
        // test pins the dual-firing of the lockfile-side + per-server drift findings, not the
        // migration prompt (which has its own tests). `hash` is recomputed from data at parse,
        // so the placeholder is discarded but the doctored `tools` still surface.
        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let lockfile_doctored = r#"{
            "format_version": 8,
            "inventory_hash": "x",
            "configs": [".mcp.json"],
            "servers": [
                {
                    "name": "s",
                    "transport": { "kind": "stdio", "command": "node", "args": [], "env": [] },
                    "tools": ["evil", "read"],
                    "tools_declared": true,
                    "source_config": ".mcp.json",
                    "hash": "deadbeef",
                    "descriptors": [
                        {"name": "evil", "descriptor_hash": "x"},
                        {"name": "read", "descriptor_hash": "y"}
                    ],
                    "descriptors_approved": true,
                    "descriptor_hash": "z"
                }
            ]
        }"#;
        fs::write(&lock_path, lockfile_doctored).unwrap();

        // Add a brand-new server "new" so a drift fires alongside the lockfile-side check.
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": {
                "s":   { "command": "node", "tools": ["read"] },
                "new": { "command": "node", "tools": ["read"] }
            } }"#,
        );

        // "s" allows only "read", so the doctored "evil" fires the lockfile-side finding.
        let mut allowed = HashMap::new();
        allowed.insert(identity, vec!["read".to_string()]);

        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);

        assert_eq!(
            findings.len(),
            2,
            "exactly two findings: the lockfile-side disallowed-tool finding \
             AND the drift finding for the brand-new server. got: {findings:?}",
        );
        // Both use `McpServerDrift` — no new RuleId from the dual-firing case.
        for f in &findings {
            assert_eq!(
                f.rule_id,
                RuleId::McpServerDrift,
                "both findings must use the McpServerDrift rule id: {f:?}",
            );
        }
        // Distinct titles so a reader can tell them apart.
        let titles: std::collections::HashSet<&str> =
            findings.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(
            titles.len(),
            2,
            "the two findings must have distinct titles so they are \
             distinguishable in human / JSON output: titles={titles:?}",
        );
        // Pin the title content: lockfile-side names the allow-list, drift-side names drift.
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("records tools outside")),
            "one of the two findings must be the lockfile-side disallowed-tool finding: {findings:?}",
        );
        assert!(
            findings.iter().any(|f| f.title.contains("drift")),
            "one of the two findings must be the drift finding: {findings:?}",
        );
    }
}
