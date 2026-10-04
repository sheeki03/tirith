use std::fs;
use std::io::{self, Write};

use serde::{Deserialize, Serialize};

pub use tirith_core::policy::TrustScopeKind as ScopeKind;

/// Default TTL for a `trust add` with neither `--ttl` nor `--permanent`. Trust
/// expires by default; permanent trust must be chosen explicitly.
const DEFAULT_TTL: &str = "30d";
const TRUST_STORE_MAX_BYTES: u64 = 1024 * 1024;

/// A single entry in trust.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEntry {
    pub pattern: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_expires: Option<String>,
    pub added: String,
    pub source: String,
    /// Optional free-text reason recorded when the entry was added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The trust.json file format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustStore {
    pub version: u32,
    pub entries: Vec<TrustEntry>,
}

impl Default for TrustStore {
    fn default() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }
}

/// Classify how broad a trust pattern is.
pub fn classify_scope(pattern: &str) -> ScopeKind {
    tirith_core::policy::classify_trust_pattern(pattern)
}

/// Legacy-compatible row used to compare active trust snapshots.
#[derive(Debug, Clone, Serialize)]
struct TrustListRow {
    pattern: String,
    rule_id: Option<String>,
    source: String,
    expires: Option<String>,
    expired: bool,
    /// Machine-readable scope class.
    scope_kind: ScopeKind,
    /// One-line description of what the entry covers.
    scope_coverage: String,
    /// True when the entry is dangerously broad (wildcard / bare TLD).
    broad_warning: bool,
}

fn human(value: &str) -> String {
    super::sanitize_for_human_output(value, false)
}

fn human_multiline(value: &str) -> String {
    super::sanitize_for_human_output(value, true)
}

/// Render one trust-command error at the final human-output boundary. Both the
/// action and detail may originate outside the typed CLI path (library callers,
/// loaded parser diagnostics, environment-derived paths), so sanitize the
/// complete dynamic fields here instead of relying on validation upstream.
fn trust_error_line(action: &str, detail: &str) -> String {
    format!("tirith: trust {}: {}", human(action), human(detail))
}

#[cfg(test)]
fn unknown_scope_line(action: &str, scope: &str, allowed: &str) -> String {
    trust_error_line(action, &format!("unknown scope '{scope}' (use {allowed})"))
}

#[cfg(test)]
fn trust_prompt_line(domain: &str) -> String {
    format!(
        "Trust {}? [y/N/r(rule-scoped)/t(temporary 7d)] ",
        human(domain)
    )
}

/// Serialize `value` as pretty JSON to stdout. Returns `0` on success, `1` on a
/// serialization failure — surfaced as a non-zero exit so a consumer can tell
/// the output is incomplete rather than a misleading exit-0.
#[must_use]
fn print_json(value: &impl Serialize) -> i32 {
    match serde_json::to_string_pretty(value) {
        Ok(s) => {
            println!("{s}");
            0
        }
        Err(e) => {
            eprintln!(
                "tirith: JSON serialization failed: {}",
                human(&e.to_string())
            );
            1
        }
    }
}

/// Resolve the trust.json path for a given scope.
fn trust_store_path(scope: &str) -> Result<std::path::PathBuf, String> {
    match scope {
        "user" => {
            let config = tirith_core::policy::config_dir()
                .ok_or_else(|| "cannot determine config directory".to_string())?;
            Ok(config.join("trust.json"))
        }
        "repo" => {
            let repo_root = tirith_core::policy::find_repo_root(None)
                .ok_or_else(|| "not inside a git repository".to_string())?;
            Ok(repo_root.join(".tirith").join("trust.json"))
        }
        other => Err(format!("unknown scope: {other} (use 'user' or 'repo')")),
    }
}

/// Load the trust store from a path.
///
/// Returns `Ok(default)` if the file does not exist, or `Err` if the file
/// exists but cannot be parsed (prevents silent data loss on corruption).
fn load_store(path: &std::path::Path) -> Result<TrustStore, String> {
    let bytes = match tirith_core::util::read_text_no_follow_capped(path, TRUST_STORE_MAX_BYTES) {
        Ok(bytes) => bytes,
        Err(tirith_core::util::OpenRegularError::NotFound) => return Ok(TrustStore::default()),
        Err(tirith_core::util::OpenRegularError::NotRegularFile) => {
            return Err(format!(
                "refusing non-regular or symlinked trust store at {}",
                path.display()
            ))
        }
        Err(tirith_core::util::OpenRegularError::TooLarge) => {
            return Err(format!(
                "trust store at {} exceeds the {} byte limit",
                path.display(),
                TRUST_STORE_MAX_BYTES
            ))
        }
        Err(tirith_core::util::OpenRegularError::Io(error)) => {
            return Err(format!("cannot read {}: {error}", path.display()))
        }
    };
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("corrupt trust store at {}: {e}", path.display()))
}

fn load_store_scoped(scope: &str, path: &std::path::Path) -> Result<TrustStore, String> {
    if scope == "repo" {
        load_repo_store(path)
    } else {
        load_store(path)
    }
}

/// Read the legacy repo-scoped `<root>/.tirith/trust.json` through retained,
/// no-follow directory capabilities (`ContainedAtomicFile`), the same reader on
/// Unix and Windows. A symlinked or reparse `.tirith` or `trust.json` is
/// refused; an absent repository root, `.tirith` or store reads as empty; and
/// the bytes come from one regular file whose generation did not change while
/// it was read.
#[cfg(any(unix, windows))]
fn load_repo_store(path: &std::path::Path) -> Result<TrustStore, String> {
    use tirith_core::util::{ContainedAtomicFile, OpenRegularError};

    let root = path
        .parent()
        .filter(|directory| directory.file_name() == Some(std::ffi::OsStr::new(".tirith")))
        .and_then(std::path::Path::parent)
        .filter(|_| path.file_name() == Some(std::ffi::OsStr::new("trust.json")))
        .ok_or_else(|| "repo trust path is not <root>/.tirith/trust.json".to_string())?;
    let file = match ContainedAtomicFile::prepare(root, path, false) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(TrustStore::default()),
        Err(error) => {
            return Err(format!(
                "refusing repo trust store {}: {error}",
                path.display()
            ))
        }
    };
    let bytes = match file.read_capped(TRUST_STORE_MAX_BYTES) {
        Ok(bytes) => bytes,
        Err(OpenRegularError::NotFound) => return Ok(TrustStore::default()),
        Err(OpenRegularError::TooLarge) => {
            return Err(format!(
                "repo trust store exceeds the {TRUST_STORE_MAX_BYTES} byte limit"
            ))
        }
        Err(OpenRegularError::NotRegularFile) => {
            return Err("repo trust store is not a regular file".to_string())
        }
        Err(OpenRegularError::Io(error)) => {
            return Err(format!("cannot read repo trust store: {error}"))
        }
    };
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("corrupt trust store at {}: {error}", path.display()))
}

#[cfg(all(not(unix), not(windows)))]
fn load_repo_store(path: &std::path::Path) -> Result<TrustStore, String> {
    let parent = path
        .parent()
        .ok_or_else(|| "repo trust path has no parent".to_string())?;
    match fs::symlink_metadata(parent) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(TrustStore::default()),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err("refusing symlinked or non-directory repo trust path".to_string())
        }
        Ok(_) => {}
        Err(error) => return Err(format!("cannot inspect repo trust directory: {error}")),
    }
    if matches!(fs::symlink_metadata(path), Err(error) if error.kind() == io::ErrorKind::NotFound) {
        return Ok(TrustStore::default());
    }
    Err(
        "repo-scoped trust requires descriptor-relative no-symlink filesystem operations, which are not available on this platform; use --scope user"
            .to_string(),
    )
}

/// Parse a duration string like "1h", "7d", "30d" into an expiry timestamp.
#[cfg(test)]
fn parse_ttl(ttl: &str) -> Result<String, String> {
    tirith_core::trust_grants::expiry_from_ttl(ttl, chrono::Utc::now())
}

/// Expired and malformed timestamps are inactive, matching enforcement.
fn is_expired(entry: &TrustEntry) -> bool {
    matches!(
        tirith_core::trust_grants::expiry(entry.ttl_expires.as_deref(), chrono::Utc::now()),
        tirith_core::trust_grants::Expiry::Expired | tirith_core::trust_grants::Expiry::Invalid
    )
}

/// Format the time remaining until an RFC3339 expiry, e.g. "in 6d" / "in 2h".
/// Returns `None` for a permanent (no-TTL) entry, "expired" when already past.
#[cfg(test)]
fn humanize_expiry(ttl_expires: Option<&str>) -> Option<String> {
    let exp = ttl_expires?;
    let expiry = chrono::DateTime::parse_from_rfc3339(exp).ok()?;
    let now = chrono::Utc::now();
    let delta = expiry.signed_duration_since(now);
    if delta.num_seconds() <= 0 {
        return Some("expired".to_string());
    }
    let secs = delta.num_seconds();
    let human = if secs >= 86400 {
        format!("in {}d", secs / 86400)
    } else if secs >= 3600 {
        format!("in {}h", secs / 3600)
    } else if secs >= 60 {
        format!("in {}m", secs / 60)
    } else {
        format!("in {secs}s")
    };
    Some(human)
}

/// Validate a pattern for trust add.
#[cfg(test)]
fn validate_pattern(pattern: &str, policy: &tirith_core::policy::Policy) -> Result<(), String> {
    tirith_core::policy::validate_trust_pattern(pattern)?;
    if policy.is_blocklisted(pattern) {
        return Err(format!(
            "pattern '{pattern}' is in the blocklist and cannot be trusted"
        ));
    }
    Ok(())
}

/// `tirith trust add <pattern> [--rule <rule_id>] [--ttl <duration>]
/// [--permanent] [--broad] [--reason <text>] [--scope user|repo]`
#[allow(clippy::too_many_arguments)]
pub fn add(
    pattern: &str,
    rule_id: Option<&str>,
    ttl: Option<&str>,
    permanent: bool,
    broad: bool,
    reason: Option<&str>,
    scope: &str,
    json: bool,
) -> i32 {
    super::trust_lifecycle::add(
        pattern, rule_id, ttl, permanent, broad, false, reason, scope, json,
    )
}

/// Collect trust-style rows (legacy stores, operator grants, allowlists) for
/// `trust diff`. `show_expired` controls whether expired
/// TTL-bearing entries are included. An unreadable operator grant store grants
/// nothing at runtime, so its rows are left out and the reason is returned
/// next to the other rows instead of failing the whole collection.
fn collect_rows(
    scope: &str,
    show_expired: bool,
) -> Result<(Vec<TrustListRow>, Option<String>), String> {
    let mut rows: Vec<TrustListRow> = Vec::new();
    let mut grant_store_error = None;

    let scopes_to_load: Vec<&str> = match scope {
        "all" => vec!["user", "repo"],
        s => vec![s],
    };

    for s in &scopes_to_load {
        let path = match trust_store_path(s) {
            Ok(p) => p,
            Err(e) => {
                // "all" skips missing scopes (e.g., repo outside a git tree);
                // an explicit single scope is a hard error.
                if scope != "all" {
                    return Err(e);
                }
                continue;
            }
        };
        let store = load_store_scoped(s, &path)?;
        let source = format!("trust-{s}");
        for entry in &store.entries {
            let expired = is_expired(entry);
            if expired && !show_expired {
                continue;
            }
            rows.push(make_row(
                entry.pattern.clone(),
                entry.rule_id.clone(),
                source.clone(),
                entry.ttl_expires.clone(),
                expired,
            ));
        }
    }

    if scope == "all" {
        match operator_grant_rows(show_expired) {
            Ok(grants) => rows.extend(grants),
            Err(error) => grant_store_error = Some(error),
        }
        if let Some(config) = tirith_core::policy::config_dir() {
            let allowlist_path = config.join("allowlist");
            if let Ok(content) = fs::read_to_string(&allowlist_path) {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        rows.push(make_row(
                            line.to_string(),
                            None,
                            "allowlist-user".to_string(),
                            None,
                            false,
                        ));
                    }
                }
            }
        }

        if let Some(repo_root) = tirith_core::policy::find_repo_root(None) {
            let allowlist_path = repo_root.join(".tirith").join("allowlist");
            if let Ok(content) = fs::read_to_string(&allowlist_path) {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        rows.push(make_row(
                            line.to_string(),
                            None,
                            "allowlist-org".to_string(),
                            None,
                            false,
                        ));
                    }
                }
            }
        }

        let policy = tirith_core::policy::Policy::discover(None);
        for pattern in &policy.allowlist {
            // Skip patterns already surfaced from the flat allowlist files.
            if !rows
                .iter()
                .any(|r| r.pattern == *pattern && r.source.starts_with("allowlist"))
            {
                rows.push(make_row(
                    pattern.clone(),
                    None,
                    "policy".to_string(),
                    None,
                    false,
                ));
            }
        }
        for rule in &policy.allowlist_rules {
            for pattern in &rule.patterns {
                rows.push(make_row(
                    pattern.clone(),
                    Some(rule.rule_id.clone()),
                    "policy".to_string(),
                    None,
                    false,
                ));
            }
        }
    }

    Ok((rows, grant_store_error))
}

/// Rows for the operator grant store (`trust-grants.json`). Revoked and
/// undecodable records grant nothing and are left out; a project grant's
/// source names its checkout so grants for different checkouts stay distinct.
fn operator_grant_rows(show_expired: bool) -> Result<Vec<TrustListRow>, String> {
    use tirith_core::trust_grants::{self, Expiry, GrantScope, TrustGrantStore};
    let Some(config) = tirith_core::policy::config_dir() else {
        return Ok(Vec::new());
    };
    let path = config.join(trust_grants::STORE_FILE);
    let bytes =
        match tirith_core::util::read_text_no_follow_capped(&path, trust_grants::STORE_READ_CAP) {
            Ok(bytes) => bytes,
            Err(tirith_core::util::OpenRegularError::NotFound) => return Ok(Vec::new()),
            Err(_) => {
                return Err(format!(
                    "trust grant store at {} is unreadable, non-regular, linked, or oversized",
                    path.display()
                ))
            }
        };
    let store = TrustGrantStore::parse(&bytes).map_err(str::to_string)?;
    let now = chrono::Utc::now();
    let mut rows = Vec::new();
    for grant in store.records().into_iter().flatten() {
        if grant.revoked_at.is_some() {
            continue;
        }
        let expired = match trust_grants::expiry(grant.expires_at.as_deref(), now) {
            Expiry::Invalid => continue,
            Expiry::Expired => true,
            Expiry::Permanent | Expiry::Active(_) => false,
        };
        if expired && !show_expired {
            continue;
        }
        let source = match &grant.scope {
            GrantScope::User => "grant-user".to_string(),
            GrantScope::Project { project } => {
                format!("grant-project {}", project.canonical_root.display())
            }
        };
        rows.push(make_row(
            grant.pattern,
            grant.rule_id,
            source,
            grant.expires_at,
            expired,
        ));
    }
    Ok(rows)
}

/// Build a `TrustListRow`, computing the scope classification once.
fn make_row(
    pattern: String,
    rule_id: Option<String>,
    source: String,
    expires: Option<String>,
    expired: bool,
) -> TrustListRow {
    let scope_kind = classify_scope(&pattern);
    TrustListRow {
        pattern,
        rule_id,
        source,
        expires,
        expired,
        scope_kind,
        scope_coverage: scope_kind.coverage().to_string(),
        broad_warning: scope_kind.is_dangerous(),
    }
}

/// Read and JSON-parse `last_trigger.json` from the data dir.
///
/// Shared by `last()` (interactive prompt) and `from_last_trigger()` (suggest
/// ready-to-run commands). Returns the parsed value so each caller can pull the
/// fields it needs without re-reading the file. `Ok(None)` means there is no
/// recent trigger on disk (missing file); `Err` is a real read/parse failure.
fn load_last_trigger_value() -> Result<Option<serde_json::Value>, String> {
    super::last_trigger::load_last_trigger_record()?
        .map(|record| {
            serde_json::to_value(record)
                .map_err(|e| format!("failed to project structured last trigger: {e}"))
        })
        .transpose()
}

/// Extract `(target, rule_id)` PAIRS from a parsed `last_trigger.json`.
///
/// Pairing is PER FINDING: each finding carries its OWN `rule_id` and its own
/// `evidence`, so a target pulled from a finding's evidence is paired with THAT
/// finding's `rule_id` — never the flat top-level `rule_ids` array. Pairing
/// against the top-level array would form a cartesian product, so for a
/// multi-finding trigger `--apply` could trust URL A under rule B even though
/// rule B fired for a DIFFERENT target.
///
/// Each target prefers a FULL URL when the evidence carries one (a `raw` string
/// with a scheme that parses) so the suggested trust can be narrow; it falls
/// back to a bare host/domain otherwise. Per-finding `raw` is read before
/// `raw_host`, mirroring how `last()` walks findings. A finding with no
/// extractable rule_id yields `(target, None)`. Results are de-duped on the full
/// `(target, rule_id)` pair, so the same URL flagged by two different rules
/// keeps both pairings.
fn extract_target_rule_pairs(val: &serde_json::Value) -> Vec<(String, Option<String>)> {
    let mut pairs: Vec<(String, Option<String>)> = Vec::new();
    let push = |t: String, rid: &Option<String>, pairs: &mut Vec<(String, Option<String>)>| {
        if t.is_empty() {
            return;
        }
        let pair = (t, rid.clone());
        if !pairs.contains(&pair) {
            pairs.push(pair);
        }
    };
    if let Some(findings) = val.get("findings").and_then(|v| v.as_array()) {
        for finding in findings {
            // THIS finding's own rule id — paired with every target it produces.
            let rule_id = finding
                .get("rule_id")
                .and_then(|v| v.as_str())
                .map(String::from);
            if let Some(evidence) = finding.get("evidence").and_then(|v| v.as_array()) {
                for ev in evidence {
                    if let Some(raw) = ev.get("raw").and_then(|v| v.as_str()) {
                        // Prefer the full URL when `raw` is one; else fall back
                        // to the bare host so we still have something to trust.
                        if raw.contains("://") && url::Url::parse(raw).is_ok() {
                            push(raw.to_string(), &rule_id, &mut pairs);
                        } else if let Some(host) = extract_host(raw) {
                            push(host, &rule_id, &mut pairs);
                        }
                    }
                    if let Some(host) = ev.get("raw_host").and_then(|v| v.as_str()) {
                        push(host.to_string(), &rule_id, &mut pairs);
                    }
                }
            }
        }
    }

    pairs
}

/// Normalize a per-finding target to the bare host `last()` displays and
/// prompts on. `extract_target_rule_pairs` may yield a FULL URL or a bare host;
/// `last()`'s `domains` list is always a bare host (via `extract_host` /
/// `raw_host`). Reduce a URL target to its host so a pair can be matched back to
/// the host the user was actually asked about; a target that is already a bare
/// host (or any non-URL) maps to itself.
#[cfg(test)]
fn target_host(target: &str) -> String {
    extract_host(target).unwrap_or_else(|| target.to_string())
}

/// The rule_id(s) that actually fired for a single host in the last trigger.
///
/// Reuses `extract_target_rule_pairs` (the same per-finding source
/// `from_last_trigger` uses) as the single source of truth, then keeps only the
/// rules whose finding targeted `host`, never the flat top-level `rule_ids`
/// array. This is what stops `last()`'s rule-scoped choice from granting one
/// host every rule in the whole verdict. Results are de-duped, preserving order.
#[cfg(test)]
fn rules_for_host(val: &serde_json::Value, host: &str) -> Vec<String> {
    let mut rules: Vec<String> = Vec::new();
    for (target, rule_id) in extract_target_rule_pairs(val) {
        if target_host(&target) != host {
            continue;
        }
        if let Some(rid) = rule_id {
            if !rules.contains(&rid) {
                rules.push(rid);
            }
        }
    }
    rules
}

/// Read + parse + extract in one step: per-finding `(target, rule_id)` pairs.
///
/// Each target prefers a full URL, else a bare domain (see
/// `extract_target_rule_pairs`). `Err` covers both "no recent trigger" (so
/// callers can print a friendly note) and real read/parse failures.
fn read_last_trigger() -> Result<Vec<(String, Option<String>)>, String> {
    match load_last_trigger_value()? {
        Some(val) => Ok(extract_target_rule_pairs(&val)),
        None => Err("no recent trigger found".into()),
    }
}

/// Build the ready-to-run `tirith trust add` suggestion lines for each
/// per-finding `(target, rule_id)` pair. A full-URL target is narrow, so it is
/// suggested without `--broad`; a bare domain needs `--broad` because
/// `trust add` rejects broad scopes without the opt-in (see `add()` /
/// `classify_scope`). Each pair carries ITS OWN rule id, so a rule is never
/// suggested for a target it didn't fire on.
fn suggestion_lines(pairs: &[(String, Option<String>)]) -> Vec<String> {
    pairs
        .iter()
        .map(|(target, rule_id)| {
            // A target that classifies as broad (bare domain/wildcard/TLD) needs
            // `--broad`; a full URL (or any narrow pattern) does not.
            let needs_broad = classify_scope(target).is_broad();
            format_add_line(target, rule_id.as_deref(), needs_broad)
        })
        .collect()
}

fn format_add_line(target: &str, rule_id: Option<&str>, needs_broad: bool) -> String {
    // The target is attacker-controlled (a URL/host pulled from the trigger's
    // finding evidence) and this line is printed for the operator to copy/paste
    // into a shell. If display sanitization would alter any character, emit only
    // a static manual-review note: silently stripping an escape, bidi control, or
    // forged newline could turn untrusted data into a different runnable trust
    // command. Benign shell metacharacters remain unchanged here and are protected
    // by the single-quote below.
    if human(target) != target {
        return "# trust this target manually with `tirith trust add` \
                (it contains characters unsafe to embed in a suggested command)."
            .to_string();
    }
    let Some(quoted) = tirith_core::safe_command::shell_single_quote(target) else {
        return "# trust this target manually with `tirith trust add` \
                (it contains characters unsafe to embed in a suggested command)."
            .to_string();
    };
    let broad = if needs_broad { " --broad" } else { "" };
    match rule_id {
        Some(rid) => {
            if human(rid) != rid {
                return "# trust this target manually with `tirith trust add` \
                        (its rule id contains characters unsafe to embed in a suggested command)."
                    .to_string();
            }
            let rid = if rid
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
                && !rid.is_empty()
            {
                rid.to_string()
            } else {
                let Some(quoted) = tirith_core::safe_command::shell_single_quote(rid) else {
                    return "# trust this target manually with `tirith trust add` \
                            (its rule id contains characters unsafe to embed in a suggested command)."
                        .to_string();
                };
                quoted
            };
            format!("tirith trust add {quoted}{broad} --rule {rid} --ttl {DEFAULT_TTL}")
        }
        None => "# No rule was recorded; select --rule explicitly before trusting this target."
            .to_string(),
    }
}

/// `tirith trust from-last-trigger [--apply]` -- turn the most recent trigger
/// into trust commands. Default (suggest) prints ready-to-run `trust add`
/// lines so the operator can copy/paste the narrowest one; `--apply` runs them.
///
/// Print-only by default mirrors the codebase's `policy tune` stance: suggest,
/// don't mutate.
pub fn from_last_trigger(apply: bool) -> i32 {
    let pairs = match read_last_trigger() {
        Ok(v) => v,
        // A missing/empty trigger is not an error for this command -- it is the
        // common "nothing happened yet" case, so exit 0 with a friendly note.
        Err(e) if e == "no recent trigger found" => {
            eprintln!("tirith: no recent trigger to trust");
            return 0;
        }
        Err(e) => {
            eprintln!("{}", trust_error_line("from-last-trigger", &e));
            return 1;
        }
    };

    if pairs.is_empty() {
        eprintln!("tirith: no recent trigger to trust");
        return 0;
    }

    if !apply {
        eprintln!("Suggested trust commands (run the narrowest one that fits):");
        eprintln!();
        for line in suggestion_lines(&pairs) {
            println!("{}", human(&line));
        }
        eprintln!();
        eprintln!("Re-run with --apply to add these automatically.");
        return 0;
    }

    // --apply: actually add each per-finding entry, pairing each target with ITS
    // OWN rule id (never a rule that fired on a different target). A bare-domain
    // target is broad, so pass `broad = true`; a full-URL (narrow) one does not.
    let mut added = 0;
    let mut failed = 0;
    for (target, rule_id) in &pairs {
        let broad = classify_scope(target).is_broad();
        if broad || rule_id.is_none() {
            eprintln!("tirith: this finding lacks an exact target and rule; review it and opt into --broad or --all-rules explicitly");
            failed += 1;
            continue;
        }
        // Pass DEFAULT_TTL explicitly (not None) so the applied entry uses the
        // same source the printed suggestion's `--ttl {DEFAULT_TTL}` does. `add()`
        // would resolve None to DEFAULT_TTL anyway, but sharing the one constant
        // keeps suggest and apply from drifting on separate literals.
        if add(
            target,
            rule_id.as_deref(),
            Some(DEFAULT_TTL),
            false,
            broad,
            None,
            "user",
            false,
        ) == 0
        {
            added += 1;
        } else {
            failed += 1;
        }
    }

    eprintln!("tirith: added {added} trust entry/entries from last trigger");
    // A partial apply (some entries rejected by `add()`, e.g. a blocklisted or
    // control-char target) must NOT exit 0 and masquerade as a clean success --
    // surface the count and fail loud so the operator knows not every entry stuck.
    if failed > 0 {
        eprintln!("tirith: {failed} trust entry/entries could not be added");
        return 1;
    }
    0
}

/// `tirith trust last` -- show last trigger and offer to trust.
pub fn last() -> i32 {
    match load_last_trigger_value() {
        Ok(Some(_)) => from_last_trigger(false),
        Ok(None) => {
            eprintln!("tirith: no recent trigger found");
            1
        }
        Err(error) => {
            eprintln!("{}", trust_error_line("last", &error));
            1
        }
    }
}

// --- trust diff ------------------------------------------------------------

/// File name for the append-only trust snapshot history used by `trust diff`.
const TRUST_HISTORY_FILE: &str = "trust-history.jsonl";
/// Hard cap on retained snapshot lines — keeps the file tiny and bounded.
const TRUST_HISTORY_MAX_LINES: usize = 64;

/// One observation of the full trust set, appended to the history file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrustSnapshot {
    /// RFC3339 timestamp when this snapshot was recorded.
    recorded_at: String,
    /// Every trusted pattern at observation time, as `source\u{1f}pattern\u{1f}rule`.
    /// A stable, sorted, flattened key list — enough to diff set membership.
    entries: Vec<String>,
}

/// Resolve the trust snapshot history file path under the state dir.
fn trust_history_path() -> Option<std::path::PathBuf> {
    tirith_core::policy::state_dir().map(|d| d.join(TRUST_HISTORY_FILE))
}

/// Stable flattened key for one trust row: `source\u{1f}pattern\u{1f}rule`.
fn row_key(r: &TrustListRow) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}",
        r.source,
        r.pattern,
        r.rule_id.as_deref().unwrap_or("")
    )
}

/// Decompose a `row_key` back into `(source, pattern, rule)` for display.
fn split_key(key: &str) -> (String, String, Option<String>) {
    let mut it = key.split('\u{1f}');
    let source = it.next().unwrap_or("").to_string();
    let pattern = it.next().unwrap_or("").to_string();
    let rule = it.next().filter(|s| !s.is_empty()).map(String::from);
    (source, pattern, rule)
}

/// Build a snapshot of the current full trust set (all scopes, including
/// expired entries — diff cares about set membership, not expiry). The second
/// value explains why the snapshot is incomplete (an unreadable operator grant
/// store), in which case it must not become a recorded baseline.
fn current_trust_snapshot() -> (TrustSnapshot, Option<String>) {
    let (rows, incomplete) = collect_rows("all", true).unwrap_or_default();
    let mut entries: Vec<String> = rows.iter().map(row_key).collect();
    entries.sort();
    entries.dedup();
    let incomplete = incomplete.map(|error| {
        format!(
            "{error}; its grants are not applied and are left out of this diff, \
             and this snapshot was not recorded as a baseline"
        )
    });
    (
        TrustSnapshot {
            recorded_at: chrono::Utc::now().to_rfc3339(),
            entries,
        },
        incomplete,
    )
}

/// Load all retained trust snapshots, oldest first (unparseable lines skipped).
/// Returns `(snapshots, read_error)`: a missing file → empty + `None`; a file
/// that exists but can't be read → empty + `Some(msg)` so `diff` can say "could
/// not read history" instead of falsely reporting "first observation".
fn load_trust_history() -> (Vec<TrustSnapshot>, Option<String>) {
    let Some(path) = trust_history_path() else {
        return (Vec::new(), None);
    };
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return (Vec::new(), None),
        Err(e) => {
            return (
                Vec::new(),
                Some(format!(
                    "could not read trust snapshot history at {} ({e}) — check file \
                     permissions; the diff below cannot use any earlier snapshot",
                    path.display()
                )),
            );
        }
    };
    let snapshots = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<TrustSnapshot>(l).ok())
        .collect();
    (snapshots, None)
}

/// Atomic write (temp file + rename) so a torn write can never leave a partial
/// snapshot history. Mirrors `threatdb_cmd::record_snapshot`.
fn atomic_write(dest: &std::path::Path, data: &[u8]) -> Result<(), String> {
    let parent = dest
        .parent()
        .ok_or_else(|| "cannot determine parent directory".to_string())?;
    fs::create_dir_all(parent).map_err(|e| format!("failed to create directory: {e}"))?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("failed to create temp file: {e}"))?;
    tmp.write_all(data)
        .map_err(|e| format!("failed to write temp file: {e}"))?;
    tmp.flush()
        .map_err(|e| format!("failed to flush temp file: {e}"))?;
    tmp.persist(dest)
        .map_err(|e| format!("failed to rename temp file: {e}"))?;
    Ok(())
}

/// Append `snapshot` to the trust history file if its entry set differs from
/// the most recent snapshot. Best-effort: any I/O error is silently ignored —
/// the history is a convenience for `diff`, never load-bearing for analysis.
fn record_trust_snapshot(snapshot: &TrustSnapshot) {
    let Some(path) = trust_history_path() else {
        return;
    };
    // Read-error note is irrelevant: recording rewrites the whole file regardless.
    let (mut history, _) = load_trust_history();
    // Dedup on entry set so an unchanged trust set doesn't append a line every call.
    if history
        .last()
        .map(|s| s.entries == snapshot.entries)
        .unwrap_or(false)
    {
        return;
    }
    history.push(snapshot.clone());
    if history.len() > TRUST_HISTORY_MAX_LINES {
        let drop = history.len() - TRUST_HISTORY_MAX_LINES;
        history.drain(0..drop);
    }
    let mut body = String::new();
    for s in &history {
        if let Ok(line) = serde_json::to_string(s) {
            body.push_str(&line);
            body.push('\n');
        }
    }
    let _ = atomic_write(&path, body.as_bytes());
}

#[derive(Debug, Serialize)]
struct DiffEntry {
    pattern: String,
    source: String,
    rule_id: Option<String>,
    scope_kind: ScopeKind,
}

#[derive(Debug, Serialize)]
struct TrustDiffReport {
    /// RFC3339 time of the baseline snapshot, if one was found.
    baseline_recorded_at: Option<String>,
    /// Entries present now but not in the baseline.
    added: Vec<DiffEntry>,
    /// Entries present in the baseline but not now.
    removed: Vec<DiffEntry>,
    /// True when nothing changed.
    unchanged: bool,
    /// Set when the diff could not be produced against a real baseline, or
    /// when the current trust set could only be read in part.
    note: Option<String>,
}

fn diff_entry_of(key: &str) -> DiffEntry {
    let (source, pattern, rule_id) = split_key(key);
    let scope_kind = classify_scope(&pattern);
    DiffEntry {
        pattern,
        source,
        rule_id,
        scope_kind,
    }
}

/// `tirith trust audit` — show recorded trust-store mutations (M6 ch3).
///
/// Walks the audit-log JSONL and filters entries with
/// `entry_type == "trust_change"`. Optionally trims the window with
/// `--since <duration>` (e.g. `7d`, `24h`, `15m`).
pub fn audit(since: Option<&str>, json: bool) -> i32 {
    let cutoff = match since {
        Some(s) => match parse_relative_duration(s) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!(
                    "{}",
                    trust_error_line("audit", &format!("invalid --since value: {e}"))
                );
                return 1;
            }
        },
        None => None,
    };

    let Some(log_path) = tirith_core::audit::audit_log_path() else {
        eprintln!("tirith: trust audit: cannot resolve audit log path (no data dir)");
        return 1;
    };

    if !log_path.exists() {
        if json {
            // Same envelope shape as the normal path so consumers never special-case
            // "no log yet": `entries` always an array, `skipped_lines` always present.
            let _ = print_json(&serde_json::json!({"entries": [], "skipped_lines": 0_usize}));
        } else {
            eprintln!(
                "{}",
                trust_error_line(
                    "audit",
                    &format!("no audit log yet at {}", log_path.display())
                )
            );
        }
        return 0;
    }

    // Reuse the superset reader so missing fields on older entries parse cleanly.
    let result = match tirith_core::audit_aggregator::read_log(&log_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "{}",
                trust_error_line(
                    "audit",
                    &format!("cannot read audit log at {}: {e}", log_path.display())
                )
            );
            return 1;
        }
    };

    // Surface malformed-line skips so a corrupted log isn't invisible to an
    // operator chasing a missing entry. JSON shape includes it in the envelope below.
    if result.skipped_lines > 0 && !json {
        eprintln!(
            "{}",
            trust_error_line(
                "audit",
                &format!(
                    "skipped {} malformed audit log line(s) at {}",
                    result.skipped_lines,
                    log_path.display()
                )
            )
        );
    }

    #[derive(Serialize)]
    struct TrustAuditRow {
        timestamp: String,
        action: String,
        scope: String,
        pattern: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        rule_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        ttl_expires: Option<String>,
    }

    let mut rows: Vec<TrustAuditRow> = Vec::new();
    for entry in result.records {
        if entry.entry_type != "trust_change" {
            continue;
        }
        if let Some(cutoff_ts) = cutoff {
            if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&entry.timestamp) {
                if ts.to_utc() < cutoff_ts {
                    continue;
                }
            }
        }
        rows.push(TrustAuditRow {
            timestamp: entry.timestamp,
            action: entry.trust_action.unwrap_or_else(|| "?".to_string()),
            scope: entry.trust_scope.unwrap_or_else(|| "?".to_string()),
            pattern: entry.trust_pattern.unwrap_or_default(),
            rule_id: entry.trust_rule_id,
            ttl_expires: entry.trust_ttl_expires,
        });
    }

    if json {
        // Skipped-line count lets a JSON consumer detect a corrupted log without parsing stderr.
        return print_json(&serde_json::json!({
            "entries": rows,
            "skipped_lines": result.skipped_lines,
        }));
    }

    if rows.is_empty() {
        eprintln!("tirith: trust audit: no trust-store mutations recorded");
        return 0;
    }
    println!("{:<26} {:<8} {:<6} pattern", "timestamp", "action", "scope");
    for r in &rows {
        let rule_suffix = match &r.rule_id {
            Some(rid) => format!("  [rule: {rid}]"),
            None => String::new(),
        };
        println!(
            "{:<26} {:<8} {:<6} {}{}",
            human(&r.timestamp),
            human(&r.action),
            human(&r.scope),
            human(&r.pattern),
            human(&rule_suffix)
        );
    }
    0
}

/// Parse a relative-duration string (`7d`, `24h`, `15m`) into the UTC
/// timestamp that the duration is "ago from now".
fn parse_relative_duration(s: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let (num_str, unit) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| format!("missing unit suffix (use e.g. '7d', '24h', '15m'): {s}"))?,
    );
    let n: i64 = num_str
        .parse()
        .map_err(|_| format!("not a number: {num_str:?}"))?;
    let seconds = match unit {
        "d" => n.checked_mul(86_400),
        "h" => n.checked_mul(3_600),
        "m" => n.checked_mul(60),
        "s" => Some(n),
        other => {
            return Err(format!(
                "unknown duration unit {other:?} (use 'd', 'h', 'm', or 's')",
            ))
        }
    }
    .ok_or_else(|| format!("duration overflow: {s}"))?;
    Ok(chrono::Utc::now() - chrono::Duration::seconds(seconds))
}

/// `tirith trust diff` — show what changed in the trust set since the previous
/// recorded snapshot.
pub fn diff(json: bool) -> i32 {
    let (history, history_read_error) = load_trust_history();
    let (current, incomplete) = current_trust_snapshot();

    // Baseline = the literal last recorded snapshot (not "last that differs"),
    // which keeps repeated `trust diff` calls idempotent.
    let baseline = history.last();

    let report = match baseline {
        None => TrustDiffReport {
            baseline_recorded_at: None,
            added: Vec::new(),
            removed: Vec::new(),
            unchanged: true,
            // A history file that exists but could not be read must not be
            // reported as "first observation" — surface the read failure.
            note: Some(
                history_read_error
                    .clone()
                    .or_else(|| incomplete.clone())
                    .unwrap_or_else(|| {
                        "No earlier trust snapshot to compare against — this is the first \
                 observation. Run a 'tirith trust' command again later to build a \
                 diff trail."
                            .to_string()
                    }),
            ),
        },
        Some(base) => {
            let base_set: std::collections::BTreeSet<&String> = base.entries.iter().collect();
            let cur_set: std::collections::BTreeSet<&String> = current.entries.iter().collect();

            let added: Vec<DiffEntry> = cur_set
                .difference(&base_set)
                .map(|k| diff_entry_of(k))
                .collect();
            let removed: Vec<DiffEntry> = base_set
                .difference(&cur_set)
                .map(|k| diff_entry_of(k))
                .collect();
            let unchanged = added.is_empty() && removed.is_empty();
            TrustDiffReport {
                baseline_recorded_at: Some(base.recorded_at.clone()),
                added,
                removed,
                unchanged,
                note: incomplete.clone(),
            }
        }
    };

    // Record the current snapshot AFTER computing the diff so the next `diff`
    // has a fresh baseline. A partial snapshot never becomes the baseline:
    // the next diff after the store is readable again compares to the last
    // complete one.
    if incomplete.is_none() {
        record_trust_snapshot(&current);
    }

    if json {
        return print_json(&report);
    }

    match &report.baseline_recorded_at {
        Some(ts) => println!("trust diff (since {})", human(ts)),
        None => println!("trust diff"),
    }
    if let Some(note) = &report.note {
        println!("  note: {}", human_multiline(note));
        if report.baseline_recorded_at.is_none() {
            return 0;
        }
    }
    if report.unchanged {
        println!("  no changes since the last snapshot");
        return 0;
    }
    if !report.added.is_empty() {
        println!("  added ({}):", report.added.len());
        for e in &report.added {
            let rule = e
                .rule_id
                .as_deref()
                .map(|r| format!(" [rule: {r}]"))
                .unwrap_or_default();
            println!(
                "    + {} ({}, {}){}",
                human(&e.pattern),
                human(&e.source),
                e.scope_kind.label(),
                human(&rule)
            );
        }
    }
    if !report.removed.is_empty() {
        println!("  removed ({}):", report.removed.len());
        for e in &report.removed {
            let rule = e
                .rule_id
                .as_deref()
                .map(|r| format!(" [rule: {r}]"))
                .unwrap_or_default();
            println!(
                "    - {} ({}, {}){}",
                human(&e.pattern),
                human(&e.source),
                e.scope_kind.label(),
                human(&rule)
            );
        }
    }
    0
}

/// Extract a hostname from a URL string for trust prompts.
fn extract_host(raw: &str) -> Option<String> {
    // Only trust url::Url when the input has a scheme — schemeless inputs
    // parse into unusable shapes.
    if raw.contains("://") {
        if let Ok(parsed) = url::Url::parse(raw) {
            return parsed.host_str().map(String::from);
        }
    }
    // Schemeless fallback: take the prefix up to the first '/'.
    let candidate = raw.split('/').next()?;
    let candidate = candidate.trim();
    if candidate.contains('.') && !candidate.contains(' ') {
        let host = if let Some((h, port)) = candidate.rsplit_once(':') {
            if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() {
                h
            } else {
                candidate
            }
        } else {
            candidate
        };
        Some(host.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plant a legacy trust.json fixture. Product code only reads this format;
    /// new trust is written to the grant store by `trust_lifecycle`.
    fn plant_store(path: &std::path::Path, store: &TrustStore) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, serde_json::to_vec_pretty(store).unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn repo_trust_dir_refuses_a_symlinked_tirith_component() {
        use std::os::unix::fs::symlink;

        let holder = tempfile::tempdir().unwrap();
        let root = holder.path().join("checkout");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join(".tirith")).unwrap();
        assert!(load_repo_store(&root.join(".tirith").join("trust.json"))
            .expect("an ordinary repository root opens")
            .entries
            .is_empty());

        // The component that carries repository content refuses a symlink.
        let hostile = holder.path().join("hostile");
        std::fs::create_dir(&hostile).unwrap();
        let swapped = holder.path().join("swapped");
        std::fs::create_dir(&swapped).unwrap();
        symlink(&hostile, swapped.join(".tirith")).unwrap();
        let error = load_repo_store(&swapped.join(".tirith").join("trust.json"))
            .expect_err("a symlinked .tirith component must be refused");
        assert!(error.contains("symlinked"), "unexpected error: {error}");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn repo_store_is_empty_without_a_repository_root_and_refuses_other_shapes() {
        let holder = tempfile::tempdir().unwrap();
        let missing = holder.path().join("missing-root/.tirith/trust.json");
        assert!(load_repo_store(&missing).unwrap().entries.is_empty());
        let error = load_repo_store(&holder.path().join("trust.json")).unwrap_err();
        assert!(error.contains("<root>/.tirith/trust.json"), "{error}");
        fs::write(holder.path().join(".tirith"), b"not a directory").unwrap();
        assert!(load_repo_store(&holder.path().join(".tirith/trust.json")).is_err());
    }

    #[test]
    fn test_parse_ttl_days() {
        let result = parse_ttl("7d");
        assert!(result.is_ok());
        let expiry = chrono::DateTime::parse_from_rfc3339(&result.unwrap()).unwrap();
        let expected_min = chrono::Utc::now() + chrono::Duration::days(6);
        assert!(expiry > expected_min);
    }

    #[test]
    fn test_parse_ttl_hours() {
        let result = parse_ttl("1h");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_ttl_minutes() {
        let result = parse_ttl("30m");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_ttl_invalid() {
        assert!(parse_ttl("").is_err());
        assert!(parse_ttl("0d").is_err());
        assert!(parse_ttl("abc").is_err());
        assert!(parse_ttl("7x").is_err());
    }

    #[test]
    fn test_default_ttl_parses() {
        // The compiled-in default must always be a valid TTL.
        assert!(parse_ttl(DEFAULT_TTL).is_ok());
    }

    #[test]
    fn test_is_expired_no_ttl() {
        let entry = TrustEntry {
            pattern: "example.com".to_string(),
            rule_id: None,
            ttl_expires: None,
            added: chrono::Utc::now().to_rfc3339(),
            source: "cli".to_string(),
            reason: None,
        };
        assert!(!is_expired(&entry));
    }

    #[test]
    fn test_is_expired_future() {
        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        let entry = TrustEntry {
            pattern: "example.com".to_string(),
            rule_id: None,
            ttl_expires: Some(future.to_rfc3339()),
            added: chrono::Utc::now().to_rfc3339(),
            source: "cli".to_string(),
            reason: None,
        };
        assert!(!is_expired(&entry));
    }

    #[test]
    fn test_is_expired_past() {
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        let entry = TrustEntry {
            pattern: "example.com".to_string(),
            rule_id: None,
            ttl_expires: Some(past.to_rfc3339()),
            added: chrono::Utc::now().to_rfc3339(),
            source: "cli".to_string(),
            reason: None,
        };
        assert!(is_expired(&entry));
    }

    #[test]
    fn test_is_expired_unparseable_ttl_matches_inactive_enforcement() {
        // Malformed timestamps cannot authorize trust in either reader.
        let entry = TrustEntry {
            pattern: "example.com".to_string(),
            rule_id: None,
            ttl_expires: Some("not-a-timestamp".to_string()),
            added: chrono::Utc::now().to_rfc3339(),
            source: "cli".to_string(),
            reason: None,
        };
        assert!(is_expired(&entry));
    }

    #[test]
    fn test_validate_pattern_empty() {
        let policy = tirith_core::policy::Policy::default();
        assert!(validate_pattern("", &policy).is_err());
    }

    #[test]
    fn test_validate_pattern_control_chars() {
        let policy = tirith_core::policy::Policy::default();
        assert!(validate_pattern("hello\x00world", &policy).is_err());
        assert!(validate_pattern("hello\x01world", &policy).is_err());
    }

    #[test]
    fn test_validate_pattern_rejects_tab_and_deceptive_unicode() {
        let policy = tirith_core::policy::Policy::default();
        assert!(validate_pattern("hello\tworld", &policy).is_err());
        assert!(validate_pattern("hello\u{202e}world", &policy).is_err());
        assert!(validate_pattern("hello\u{200b}world", &policy).is_err());
    }

    #[test]
    fn test_validate_pattern_blocklisted() {
        let policy = tirith_core::policy::Policy {
            blocklist: vec!["evil.com".to_string()],
            ..Default::default()
        };
        assert!(validate_pattern("evil.com", &policy).is_err());
    }

    #[test]
    fn test_validate_pattern_ok() {
        let policy = tirith_core::policy::Policy::default();
        assert!(validate_pattern("example.com", &policy).is_ok());
    }

    #[test]
    fn test_extract_host_full_url() {
        assert_eq!(
            extract_host("https://example.com/path"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_host_schemeless() {
        assert_eq!(
            extract_host("example.com/path"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_host_with_port() {
        assert_eq!(
            extract_host("example.com:8080/path"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_host_no_dot() {
        assert_eq!(extract_host("localhost"), None);
    }

    #[test]
    fn test_store_roundtrip() {
        let _global = crate::cli::test_harness::ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");

        let store = TrustStore {
            version: 1,
            entries: vec![TrustEntry {
                pattern: "example.com".to_string(),
                rule_id: Some("shortened_url".to_string()),
                ttl_expires: None,
                added: "2026-04-03T12:00:00Z".to_string(),
                source: "cli".to_string(),
                reason: Some("internal mirror".to_string()),
            }],
        };

        plant_store(&path, &store);
        let loaded = load_store(&path).unwrap();

        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].pattern, "example.com");
        assert_eq!(loaded.entries[0].rule_id.as_deref(), Some("shortened_url"));
        assert_eq!(loaded.entries[0].reason.as_deref(), Some("internal mirror"));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn repo_store_loads_a_planted_store() {
        let _global = crate::cli::test_harness::ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(".tirith/trust.json");
        assert!(load_repo_store(&path).unwrap().entries.is_empty());
        let store = TrustStore {
            version: 1,
            entries: vec![TrustEntry {
                pattern: "https://example.com/install.sh".into(),
                rule_id: None,
                ttl_expires: None,
                added: "2026-07-31T00:00:00Z".into(),
                source: "cli".into(),
                reason: None,
            }],
        };
        plant_store(&path, &store);
        assert_eq!(load_repo_store(&path).unwrap().entries.len(), 1);
        plant_store(&path, &TrustStore::default());
        assert!(load_repo_store(&path).unwrap().entries.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn repo_store_rejects_symlinked_directory_component() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_store = outside.path().join("trust.json");
        fs::write(&outside_store, r#"{"version":1,"entries":[]}"#).unwrap();
        symlink(outside.path(), root.path().join(".tirith")).unwrap();
        let path = root.path().join(".tirith/trust.json");
        let before = fs::read(&outside_store).unwrap();

        assert!(load_repo_store(&path).is_err());
        assert_eq!(fs::read(&outside_store).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn repo_store_rejects_symlinked_destination() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), r#"{"version":1,"entries":[]}"#).unwrap();
        fs::create_dir(root.path().join(".tirith")).unwrap();
        let path = root.path().join(".tirith/trust.json");
        symlink(outside.path(), &path).unwrap();
        let before = fs::read(outside.path()).unwrap();

        assert!(load_repo_store(&path).is_err());
        assert_eq!(fs::read(outside.path()).unwrap(), before);
    }

    #[cfg(windows)]
    #[test]
    fn repo_store_rejects_windows_reparse_directory_component() {
        use std::os::windows::fs::symlink_dir;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_store = outside.path().join("trust.json");
        fs::write(&outside_store, r#"{"version":1,"entries":[]}"#).unwrap();
        if let Err(error) = symlink_dir(outside.path(), root.path().join(".tirith")) {
            if error.kind() == io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(1314)
            {
                return;
            }
            panic!("cannot create Windows directory symlink fixture: {error}");
        }
        let path = root.path().join(".tirith/trust.json");
        let before = fs::read(&outside_store).unwrap();

        assert!(load_repo_store(&path).is_err());
        assert_eq!(fs::read(&outside_store).unwrap(), before);
    }

    #[cfg(windows)]
    #[test]
    fn repo_store_rejects_windows_reparse_destination() {
        use std::os::windows::fs::symlink_file;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), r#"{"version":1,"entries":[]}"#).unwrap();
        fs::create_dir(root.path().join(".tirith")).unwrap();
        let path = root.path().join(".tirith/trust.json");
        if let Err(error) = symlink_file(outside.path(), &path) {
            if error.kind() == io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(1314)
            {
                return;
            }
            panic!("cannot create Windows file symlink fixture: {error}");
        }
        let before = fs::read(outside.path()).unwrap();

        assert!(load_repo_store(&path).is_err());
        assert_eq!(fs::read(outside.path()).unwrap(), before);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn repo_store_rejects_oversized_and_non_regular_files() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(".tirith")).unwrap();
        let path = root.path().join(".tirith/trust.json");
        fs::write(&path, vec![b'x'; TRUST_STORE_MAX_BYTES as usize + 1]).unwrap();
        assert!(load_repo_store(&path).is_err());

        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(load_repo_store(&path).is_err());
    }

    #[cfg(all(not(unix), not(windows)))]
    #[test]
    fn repo_store_is_empty_when_absent_and_refuses_a_present_store() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(".tirith/trust.json");
        assert!(load_repo_store(&path).unwrap().entries.is_empty());
        fs::create_dir(path.parent().unwrap()).unwrap();
        assert!(load_repo_store(&path).unwrap().entries.is_empty());
        assert!(!path.exists());

        fs::write(&path, br#"{"version":1,"entries":[]}"#).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(load_repo_store(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn human_trust_fields_strip_terminal_forgery_but_json_stays_raw() {
        let raw = "safe\u{1b}]52;c;Y2xpcA\u{7}\u{1b}[2J\nFORGED\u{202e}\u{200b}";
        let one_line = human(raw);
        let multiline = human_multiline(raw);
        for rendered in [&one_line, &multiline] {
            assert!(!rendered.contains('\u{1b}'));
            assert!(!rendered.contains('\u{202e}'));
            assert!(!rendered.contains('\u{200b}'));
        }
        assert!(!one_line.contains('\n'));
        assert!(multiline.contains("\n  FORGED"));

        let structured = serde_json::to_string(&serde_json::json!({"pattern": raw})).unwrap();
        let decoded: serde_json::Value = serde_json::from_str(&structured).unwrap();
        assert_eq!(decoded["pattern"], raw);
        assert!(
            !structured.contains('\u{1b}'),
            "JSON must escape raw ESC bytes"
        );
    }

    fn assert_safe_single_line(rendered: &str) {
        for forbidden in ['\u{1b}', '\u{7}', '\u{202e}', '\u{200b}'] {
            assert!(
                !rendered.contains(forbidden),
                "forbidden terminal/deception character {forbidden:?} survived in {rendered:?}"
            );
        }
        assert!(
            !rendered.contains('\n'),
            "forged line survived: {rendered:?}"
        );
        assert!(!rendered.contains('\r'), "bare CR survived: {rendered:?}");
    }

    #[test]
    fn hostile_scope_action_and_prompt_are_safe_at_the_final_sink() {
        let hostile = "repo\u{1b}]52;c;Y2xpcA\u{7}\u{1b}[2J\nFORGED\u{202e}\u{200b}";
        let scope_line = unknown_scope_line(hostile, hostile, "'user', 'repo', or 'all'");
        let prompt = trust_prompt_line(hostile);
        assert_safe_single_line(&scope_line);
        assert_safe_single_line(&prompt);
        assert_eq!(
            unknown_scope_line("list", "staging", "'user', 'repo', or 'all'"),
            "tirith: trust list: unknown scope 'staging' (use 'user', 'repo', or 'all')"
        );
        assert_eq!(
            trust_prompt_line("example.com"),
            "Trust example.com? [y/N/r(rule-scoped)/t(temporary 7d)] "
        );
    }

    #[cfg(unix)]
    #[test]
    fn corrupt_store_error_sanitizes_hostile_path_and_parser_diagnostic_at_sink() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("trust\u{1b}]52;c;Y2xpcA\u{7}\nFORGED\u{202e}\u{200b}.json");
        fs::write(&path, b"{ definitely-not-json").unwrap();

        let error = load_store(&path).unwrap_err();
        let rendered = trust_error_line("list", &error);
        assert_safe_single_line(&rendered);
        assert!(rendered.contains("tirith: trust list: corrupt trust store at"));
        assert!(rendered.contains("definitely-not-json") || rendered.contains("key"));
    }

    #[test]
    fn test_load_legacy_store_without_reason() {
        // An older trust.json has no `reason` field — it must still load and
        // deserialize `reason` as None (backward compatibility).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");
        let legacy = r#"{
  "version": 1,
  "entries": [
    {
      "pattern": "old.example.com",
      "added": "2026-01-01T00:00:00Z",
      "source": "cli"
    }
  ]
}"#;
        fs::write(&path, legacy).unwrap();
        let loaded = load_store(&path).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].pattern, "old.example.com");
        assert!(loaded.entries[0].reason.is_none());
        assert!(loaded.entries[0].ttl_expires.is_none());
        // A legacy entry with no TTL is treated as permanent — never expired.
        assert!(!is_expired(&loaded.entries[0]));
    }

    #[test]
    fn test_gc_removes_expired() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");

        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        let future = chrono::Utc::now() + chrono::Duration::hours(1);

        let store = TrustStore {
            version: 1,
            entries: vec![
                TrustEntry {
                    pattern: "expired.com".to_string(),
                    rule_id: None,
                    ttl_expires: Some(past.to_rfc3339()),
                    added: chrono::Utc::now().to_rfc3339(),
                    source: "cli".to_string(),
                    reason: None,
                },
                TrustEntry {
                    pattern: "valid.com".to_string(),
                    rule_id: None,
                    ttl_expires: Some(future.to_rfc3339()),
                    added: chrono::Utc::now().to_rfc3339(),
                    source: "cli".to_string(),
                    reason: None,
                },
                TrustEntry {
                    pattern: "forever.com".to_string(),
                    rule_id: None,
                    ttl_expires: None,
                    added: chrono::Utc::now().to_rfc3339(),
                    source: "cli".to_string(),
                    reason: None,
                },
            ],
        };

        plant_store(&path, &store);

        let mut loaded = load_store(&path).unwrap();
        loaded.entries.retain(|e| !is_expired(e));
        plant_store(&path, &loaded);

        let after = load_store(&path).unwrap();
        assert_eq!(after.entries.len(), 2);
        assert!(after.entries.iter().any(|e| e.pattern == "valid.com"));
        assert!(after.entries.iter().any(|e| e.pattern == "forever.com"));
        assert!(!after.entries.iter().any(|e| e.pattern == "expired.com"));
    }

    // --- scope classification ---------------------------------------------

    #[test]
    fn test_classify_scope_exact_url() {
        assert_eq!(
            classify_scope("https://example.com/install.sh"),
            ScopeKind::Exact
        );
        assert_eq!(
            classify_scope("raw.githubusercontent.com/org/repo/main/get.sh"),
            ScopeKind::Exact
        );
    }

    #[test]
    fn test_classify_scope_domain() {
        assert_eq!(classify_scope("github.com"), ScopeKind::Domain);
        assert_eq!(classify_scope("api.github.com"), ScopeKind::Domain);
        assert_eq!(classify_scope("get.docker.com"), ScopeKind::Domain);
    }

    #[test]
    fn test_classify_scope_wildcard() {
        assert_eq!(classify_scope("*.example.com"), ScopeKind::Wildcard);
        assert_eq!(classify_scope("*.internal.corp.net"), ScopeKind::Wildcard);
    }

    #[test]
    fn test_classify_scope_bare_tld() {
        assert_eq!(classify_scope("com"), ScopeKind::BareTld);
        assert_eq!(classify_scope("dev"), ScopeKind::BareTld);
        assert_eq!(classify_scope("io"), ScopeKind::BareTld);
        assert_eq!(classify_scope("zip"), ScopeKind::BareTld);
        assert_eq!(classify_scope("co.uk"), ScopeKind::BareTld);
        // A wildcard over a bare TLD is the worst case — still bare-TLD.
        assert_eq!(classify_scope("*.com"), ScopeKind::BareTld);
    }

    #[test]
    fn test_classify_scope_substring() {
        // A non-domain, non-TLD bare token is a substring fragment.
        assert_eq!(classify_scope("get-pip"), ScopeKind::Substring);
    }

    #[test]
    fn test_scope_kind_broad_and_dangerous() {
        assert!(!ScopeKind::Exact.is_broad());
        assert!(ScopeKind::Substring.is_broad());
        assert!(ScopeKind::Domain.is_broad());
        assert!(ScopeKind::Wildcard.is_broad());
        assert!(ScopeKind::BareTld.is_broad());

        assert!(!ScopeKind::Domain.is_dangerous());
        assert!(ScopeKind::Wildcard.is_dangerous());
        assert!(ScopeKind::BareTld.is_dangerous());
    }

    #[test]
    fn test_humanize_expiry() {
        assert_eq!(humanize_expiry(None), None);
        let future = chrono::Utc::now() + chrono::Duration::days(6) + chrono::Duration::hours(2);
        let h = humanize_expiry(Some(&future.to_rfc3339())).unwrap();
        assert!(h.starts_with("in 6d"), "got {h}");
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        assert_eq!(
            humanize_expiry(Some(&past.to_rfc3339())),
            Some("expired".to_string())
        );
    }

    // --- trust diff snapshot keys -----------------------------------------

    #[test]
    fn test_row_key_roundtrip() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let row = make_row(
            "github.com".to_string(),
            Some("shortened_url".to_string()),
            "trust-user".to_string(),
            None,
            false,
        );
        let key = row_key(&row);
        let (source, pattern, rule) = split_key(&key);
        assert_eq!(source, "trust-user");
        assert_eq!(pattern, "github.com");
        assert_eq!(rule.as_deref(), Some("shortened_url"));
    }

    #[test]
    fn test_row_key_roundtrip_no_rule() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let row = make_row(
            "example.com".to_string(),
            None,
            "policy".to_string(),
            None,
            false,
        );
        let (source, pattern, rule) = split_key(&row_key(&row));
        assert_eq!(source, "policy");
        assert_eq!(pattern, "example.com");
        assert_eq!(rule, None);
    }

    #[test]
    fn test_diff_set_logic() {
        // Baseline has A and B; current has B and C.
        let base: std::collections::BTreeSet<&str> = ["A", "B"].into_iter().collect();
        let cur: std::collections::BTreeSet<&str> = ["B", "C"].into_iter().collect();
        let added: Vec<_> = cur.difference(&base).collect();
        let removed: Vec<_> = base.difference(&cur).collect();
        assert_eq!(added, vec![&"C"]);
        assert_eq!(removed, vec![&"A"]);
    }

    /// Redirect every base directory this module resolves at runtime into one
    /// temp root, and hand the root back so a caller can seed or inspect it.
    ///
    /// `data_dir()` (where `last_trigger.json` lives) is only half of it. The
    /// trust store itself is `config_dir()/trust.json`, and
    /// `from_last_trigger(--apply)` calls `add()`, so leaving `XDG_CONFIG_HOME`
    /// alone appended a real allowlist entry to the operator's own
    /// `~/.config/tirith/trust.json` on every `cargo test --workspace`. That
    /// file is read on the analysis hot path by `Policy::load_trust_entries`,
    /// so the residue suppresses a rule for the operator and for every later
    /// test that analyzes a matching URL. Both values are returned so the
    /// caller keeps them alive.
    ///
    /// Deliberately NOT `HOME`/`USERPROFILE`: every base directory this module
    /// resolves goes through an XDG variable on unix and `%APPDATA%` on
    /// Windows, so redirecting the home directory buys nothing here, and
    /// `cli::daemon`'s tests remove `HOME` without holding `ENV_LOCK`. A second
    /// unsynchronized writer of that variable would trade one race for another.
    fn isolated_base_dirs() -> (tempfile::TempDir, Vec<crate::cli::test_harness::EnvGuard>) {
        use crate::cli::test_harness::EnvGuard;
        let dir = tempfile::tempdir().expect("tempdir");
        let guards = [
            "XDG_DATA_HOME",
            "XDG_CONFIG_HOME",
            "XDG_STATE_HOME",
            "XDG_CACHE_HOME",
            "APPDATA",
            "LOCALAPPDATA",
        ]
        .into_iter()
        .map(|key| EnvGuard::set(key, dir.path()))
        .collect();
        (dir, guards)
    }

    /// Plant a `last_trigger.json` under a temp data dir and run `f` with every
    /// base directory pointed at it. Holds `ENV_LOCK` (process-global env
    /// mutation) and restores each variable on Drop. `data_dir()` honors
    /// `XDG_DATA_HOME` on Unix but `%APPDATA%` on Windows (etcetera), so both
    /// spellings are set.
    fn with_seeded_last_trigger<F: FnOnce()>(json: &str, f: F) {
        use crate::cli::test_harness::ENV_LOCK;
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let (dir, _guards) = isolated_base_dirs();

        let tirith_data = dir.path().join("tirith");
        fs::create_dir_all(&tirith_data).expect("create data dir");
        fs::write(tirith_data.join("last_trigger.json"), json).expect("write last_trigger.json");

        f();
    }

    /// Same env isolation, but plant NO `last_trigger.json` (empty data dir).
    fn with_empty_data_dir<F: FnOnce()>(f: F) {
        use crate::cli::test_harness::ENV_LOCK;
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let (_dir, _guards) = isolated_base_dirs();
        f();
    }

    /// The harness has to move the STORE, not just the trigger file.
    ///
    /// `from_last_trigger_apply_partial_failure_returns_one` calls
    /// `from_last_trigger(true)`, which calls `add()`, which writes
    /// `config_dir()/trust.json`. While the harness redirected only
    /// `XDG_DATA_HOME`/`APPDATA` that write landed in the operator's real
    /// `~/.config/tirith/trust.json`, one live 30-day allowlist entry per
    /// `cargo test --workspace`. `Policy::load_trust_entries` reads that file on
    /// the analysis hot path, so the residue silently suppresses a rule for the
    /// operator and for any later test that analyzes a matching URL.
    #[test]
    fn the_trust_harness_never_resolves_the_operators_own_store() {
        use crate::cli::test_harness::ENV_LOCK;
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Resolved under the lock and BEFORE the guards, so this is the real
        // path the binary would use on this machine.
        let operator_store = trust_store_path("user").expect("operator trust store path");

        let (dir, _guards) = isolated_base_dirs();
        let harness_store = trust_store_path("user").expect("harness trust store path");

        assert!(
            harness_store.starts_with(dir.path()),
            "the trust harness resolves {}, which is outside its temp root {}",
            harness_store.display(),
            dir.path().display()
        );
        assert_ne!(
            harness_store, operator_store,
            "the trust harness would write the operator's own store"
        );
    }

    /// A full-URL evidence target is suggested NARROW: a copy/paste-ready
    /// `tirith trust add '<url>' --rule <rule_id> --ttl 30d` line (URL
    /// single-quoted) with NO `--broad`.
    #[test]
    fn from_last_trigger_suggests_narrow_url_without_broad() {
        let json = r#"{
            "rule_ids": ["shortened_url"],
            "severity": "high",
            "command_redacted": "curl https://example.com/install.sh | sh",
            "timestamp": "2026-06-10T00:00:00Z",
            "findings": [
                {
                    "rule_id": "shortened_url",
                    "title": "Shortened URL",
                    "evidence": [
                        { "raw": "https://example.com/install.sh" }
                    ]
                }
            ]
        }"#;

        with_seeded_last_trigger(json, || {
            // read_last_trigger prefers the FULL URL as the target and pairs it
            // with THAT finding's rule_id.
            let pairs = read_last_trigger().expect("read_last_trigger");
            assert_eq!(
                pairs,
                vec![(
                    "https://example.com/install.sh".to_string(),
                    Some("shortened_url".to_string())
                )]
            );

            // The suggested line is the narrow, single-quoted, no-`--broad` form.
            let lines = suggestion_lines(&pairs);
            let expected =
                "tirith trust add 'https://example.com/install.sh' --rule shortened_url --ttl 30d";
            assert!(
                lines.iter().any(|l| l == expected),
                "expected narrow single-quoted URL suggestion {expected:?}, got: {lines:?}"
            );
            assert!(
                lines.iter().all(|l| !l.contains("--broad")),
                "a full-URL target must NOT be suggested with --broad: {lines:?}"
            );

            // The real entry point runs clean in suggest (print-only) mode.
            assert_eq!(from_last_trigger(false), 0);
        });
    }

    /// A bare-domain target (only `raw_host`, no URL) needs `--broad` because
    /// `trust add` rejects broad scopes without the opt-in.
    #[test]
    fn from_last_trigger_bare_domain_gets_broad() {
        let json = r#"{
            "rule_ids": ["homograph"],
            "findings": [
                { "rule_id": "homograph", "title": "Homograph", "evidence": [ { "raw_host": "example.com" } ] }
            ]
        }"#;

        with_seeded_last_trigger(json, || {
            let pairs = read_last_trigger().expect("read_last_trigger");
            assert_eq!(
                pairs,
                vec![("example.com".to_string(), Some("homograph".to_string()))]
            );

            let lines = suggestion_lines(&pairs);
            let expected = "tirith trust add 'example.com' --broad --rule homograph --ttl 30d";
            assert!(
                lines.iter().any(|l| l == expected),
                "expected single-quoted bare-domain suggestion with --broad {expected:?}, got: {lines:?}"
            );
        });
    }

    /// F2 (P1): a MULTI-finding trigger must pair each target with ITS OWN
    /// finding's rule_id — never the cartesian product of all targets × all
    /// top-level `rule_ids`. Here finding A (rule `shortened_url`) fired for
    /// `https://a.example/x`, finding B (rule `plain_http_to_sink`) for
    /// `http://b.example/y`. The wrong (old) behavior would suggest trusting A
    /// under `plain_http_to_sink` and B under `shortened_url`.
    #[test]
    fn from_last_trigger_pairs_each_target_with_its_own_rule() {
        let json = r#"{
            "rule_ids": ["shortened_url", "plain_http_to_sink"],
            "findings": [
                {
                    "rule_id": "shortened_url",
                    "title": "Shortened URL",
                    "evidence": [ { "raw": "https://a.example/x" } ]
                },
                {
                    "rule_id": "plain_http_to_sink",
                    "title": "Plain HTTP",
                    "evidence": [ { "raw": "http://b.example/y" } ]
                }
            ]
        }"#;

        with_seeded_last_trigger(json, || {
            let pairs = read_last_trigger().expect("read_last_trigger");
            assert_eq!(
                pairs,
                vec![
                    (
                        "https://a.example/x".to_string(),
                        Some("shortened_url".to_string())
                    ),
                    (
                        "http://b.example/y".to_string(),
                        Some("plain_http_to_sink".to_string())
                    ),
                ],
                "each target must keep its own finding's rule_id (no cartesian product)"
            );

            let lines = suggestion_lines(&pairs);
            // Exactly the two correct pairings — and NO cross-paired line.
            assert!(
                lines.iter().any(|l| l
                    == "tirith trust add 'https://a.example/x' --rule shortened_url --ttl 30d"),
                "A must pair with shortened_url: {lines:?}"
            );
            assert!(
                lines.iter().any(|l| l
                    == "tirith trust add 'http://b.example/y' --rule plain_http_to_sink --ttl 30d"),
                "B must pair with plain_http_to_sink: {lines:?}"
            );
            assert_eq!(
                lines.len(),
                2,
                "exactly two lines, no cartesian product: {lines:?}"
            );
            assert!(
                !lines.iter().any(
                    |l| l.contains("'https://a.example/x'") && l.contains("plain_http_to_sink")
                ),
                "A must NOT be cross-paired with plain_http_to_sink: {lines:?}"
            );
            assert!(
                !lines
                    .iter()
                    .any(|l| l.contains("'http://b.example/y'") && l.contains("shortened_url")),
                "B must NOT be cross-paired with shortened_url: {lines:?}"
            );
        });
    }

    /// `--apply` must fail loud on a PARTIAL apply: if `add()` rejects even one
    /// entry, the command exits non-zero instead of 0, so a partial result never
    /// masquerades as a clean success. Here the first finding's target is a valid
    /// narrow URL (`add()` accepts it -> stored), while the second's `raw_host`
    /// carries a control byte (0x07 BEL) that `validate_pattern` rejects ->
    /// `add()` returns 1 for that entry. Both reach the apply loop, so one
    /// succeeds and one fails: the overall exit must be 1.
    #[test]
    fn from_last_trigger_apply_partial_failure_returns_one() {
        let json = "{\
            \"rule_ids\": [\"shortened_url\", \"homograph\"],\
            \"findings\": [\
                {\
                    \"rule_id\": \"shortened_url\",\
                    \"title\": \"Shortened URL\",\
                    \"evidence\": [ { \"raw\": \"https://good.example/install.sh\" } ]\
                },\
                {\
                    \"rule_id\": \"homograph\",\
                    \"title\": \"Homograph\",\
                    \"evidence\": [ { \"raw_host\": \"evil.example\\u0007\" } ]\
                }\
            ]\
        }";

        with_seeded_last_trigger(json, || {
            // Both targets survive extraction: the good URL and the control-char
            // host (raw_host is pushed verbatim, no validation at read time).
            let pairs = read_last_trigger().expect("read_last_trigger");
            assert_eq!(
                pairs,
                vec![
                    (
                        "https://good.example/install.sh".to_string(),
                        Some("shortened_url".to_string())
                    ),
                    (
                        "evil.example\u{0007}".to_string(),
                        Some("homograph".to_string())
                    ),
                ],
                "both entries must reach the apply loop so one can succeed and one fail"
            );

            // Suggest (print-only) still exits 0 -- it never calls `add()`.
            assert_eq!(from_last_trigger(false), 0);

            // --apply: the good URL is stored, the control-char host is rejected
            // by `validate_pattern` inside `add()`. A partial apply must exit 1.
            assert_eq!(
                from_last_trigger(true),
                1,
                "a partial apply (one entry rejected by add) must fail loud, not exit 0"
            );
        });
    }

    /// F1 (HIGH): the suggestion line is copy/paste-ready, so a hostile target
    /// carrying shell metacharacters must be single-quoted; a target that can't
    /// be safely quoted (newline) must NOT yield a runnable command.
    #[test]
    fn from_last_trigger_shell_quotes_hostile_target() {
        // `extract_host` is applied to a schemeless `raw`; use `raw_host` so the
        // hostile bytes survive verbatim into the suggested line.
        let json = r#"{
            "rule_ids": ["confusable_domain"],
            "findings": [
                {
                    "rule_id": "confusable_domain",
                    "title": "Confusable",
                    "evidence": [ { "raw_host": "evil.example/$(touch X)" } ]
                }
            ]
        }"#;
        with_seeded_last_trigger(json, || {
            let pairs = read_last_trigger().expect("read_last_trigger");
            let lines = suggestion_lines(&pairs);
            let line = lines
                .iter()
                .find(|l| l.contains("tirith trust add"))
                .expect("a suggestion line");
            assert!(
                line.contains("'evil.example/$(touch X)'"),
                "hostile target must be single-quoted so $(touch X) cannot execute: {line}"
            );
            assert!(
                !line.replace("'evil.example/$(touch X)'", "").contains("$("),
                "no bare $( may survive outside the quoted token: {line}"
            );
        });

        // A target with a newline cannot be single-quoted as one token → no
        // runnable command, just the safe manual-trust note.
        assert_eq!(
            format_add_line("evil.example/a\nrm -rf ~", Some("confusable_domain"), true),
            "# trust this target manually with `tirith trust add` \
             (it contains characters unsafe to embed in a suggested command)."
        );

        // ANSI/OSC and deceptive Unicode must never be silently stripped into a
        // different runnable trust command. The sink emits only the static,
        // non-runnable manual-review note.
        let osc = format_add_line(
            "evil.example/\u{1b}]0;pwned\u{7}\u{1b}[31m",
            Some("confusable_domain"),
            true,
        );
        assert_eq!(
            osc,
            "# trust this target manually with `tirith trust add` \
             (it contains characters unsafe to embed in a suggested command)."
        );
        assert_eq!(
            format_add_line(
                "evil.example/\u{202e}txt.exe\u{200b}",
                Some("confusable_domain"),
                true,
            ),
            "# trust this target manually with `tirith trust add` \
             (it contains characters unsafe to embed in a suggested command)."
        );
    }

    /// `last()`'s rule-scoped ("r") choice must trust a host under ONLY the
    /// rule(s) that fired for THAT host, never every top-level rule in the
    /// verdict. `rules_for_host` is the per-host lookup that branch uses; here
    /// finding A (rule `shortened_url`) fired for `a.example`, finding B (rule
    /// `plain_http_to_sink`) for `b.example`. The old `last()` would have added
    /// BOTH rules to BOTH hosts (over-broad). `rules_for_host` must return each
    /// host's own single rule.
    #[test]
    fn rules_for_host_returns_only_that_hosts_rules() {
        let val: serde_json::Value = serde_json::from_str(
            r#"{
            "rule_ids": ["shortened_url", "plain_http_to_sink"],
            "findings": [
                {
                    "rule_id": "shortened_url",
                    "title": "Shortened URL",
                    "evidence": [ { "raw": "https://a.example/x" } ]
                },
                {
                    "rule_id": "plain_http_to_sink",
                    "title": "Plain HTTP",
                    "evidence": [ { "raw": "http://b.example/y" } ]
                }
            ]
        }"#,
        )
        .unwrap();

        // The display loop / prompt key on the bare host (via `extract_host`).
        assert_eq!(rules_for_host(&val, "a.example"), vec!["shortened_url"]);
        assert_eq!(
            rules_for_host(&val, "b.example"),
            vec!["plain_http_to_sink"]
        );
        // A host that did not trigger gets no rules (falls back to global trust).
        assert!(rules_for_host(&val, "c.example").is_empty());
    }

    /// When ONE host triggers MULTIPLE rules, the rule-scoped choice must add
    /// each of that host's own rules (and de-dupe), not collapse to one.
    #[test]
    fn rules_for_host_returns_all_own_rules_deduped() {
        let val: serde_json::Value = serde_json::from_str(
            r#"{
            "rule_ids": ["shortened_url", "plain_http_to_sink", "homograph"],
            "findings": [
                {
                    "rule_id": "shortened_url",
                    "evidence": [ { "raw": "https://a.example/x" }, { "raw_host": "a.example" } ]
                },
                {
                    "rule_id": "plain_http_to_sink",
                    "evidence": [ { "raw": "http://a.example/y" } ]
                },
                {
                    "rule_id": "homograph",
                    "evidence": [ { "raw_host": "b.example" } ]
                }
            ]
        }"#,
        )
        .unwrap();

        // a.example fired on two distinct rules across its findings; both are
        // returned, de-duped despite the repeated `raw`/`raw_host` evidence.
        assert_eq!(
            rules_for_host(&val, "a.example"),
            vec!["shortened_url", "plain_http_to_sink"],
            "a host with multiple rules keeps all of its own rules, deduped"
        );
        // b.example's unrelated rule must NOT leak onto a.example.
        assert_eq!(rules_for_host(&val, "b.example"), vec!["homograph"]);
    }

    /// A finding with evidence but no `rule_id` yields a host with no rules, so
    /// the rule-scoped branch falls back to global trust for that host. (Mirrors
    /// the old "no rule IDs in last trigger" path, now scoped per-host.)
    #[test]
    fn rules_for_host_empty_when_finding_has_no_rule_id() {
        let val: serde_json::Value = serde_json::from_str(
            r#"{
            "findings": [
                { "title": "Mystery", "evidence": [ { "raw_host": "a.example" } ] }
            ]
        }"#,
        )
        .unwrap();
        assert!(rules_for_host(&val, "a.example").is_empty());
    }

    /// A missing/empty trigger is the common "nothing happened yet" case:
    /// `from_last_trigger` returns 0 (friendly note), not an error.
    #[test]
    fn from_last_trigger_missing_returns_zero() {
        with_empty_data_dir(|| {
            assert_eq!(from_last_trigger(false), 0);
            // read_last_trigger surfaces the no-trigger sentinel for callers.
            assert_eq!(
                read_last_trigger().unwrap_err(),
                "no recent trigger found".to_string()
            );
        });
    }

    /// The refactor must keep `last()` behavior identical: with no trigger on
    /// disk it still returns 1 (its non-interactive, stdin-free path).
    #[test]
    fn last_unchanged_without_trigger_returns_one() {
        with_empty_data_dir(|| {
            assert_eq!(last(), 1);
        });
    }

    #[test]
    fn unreadable_grant_store_keeps_other_rows_and_is_never_recorded_as_baseline() {
        use tirith_core::trust_grants::STORE_FILE;
        let _state = tirith_test_support::GlobalStateGuard::new().unwrap();
        let config = tirith_core::policy::config_dir().unwrap();
        fs::create_dir_all(&config).unwrap();
        fs::write(config.join("allowlist"), "allowed.example\n").unwrap();
        let key = "allowlist-user\u{1f}allowed.example\u{1f}";
        let (complete, incomplete) = current_trust_snapshot();
        assert!(incomplete.is_none());
        assert!(complete.entries.iter().any(|entry| entry == key));
        record_trust_snapshot(&complete);

        // A store written by a newer client (or corrupted) cannot be read.
        fs::write(
            config.join(STORE_FILE),
            r#"{"schema_version":2,"grants":[]}"#,
        )
        .unwrap();
        let (partial, incomplete) = current_trust_snapshot();
        assert!(incomplete.is_some(), "the unreadable store is reported");
        assert!(
            partial.entries.iter().any(|entry| entry == key),
            "other trust sources stay in the snapshot: {:?}",
            partial.entries
        );
        assert_eq!(diff(true), 0);
        let (history, _) = load_trust_history();
        assert_eq!(history.len(), 1, "a partial snapshot is not recorded");
        assert_eq!(history[0].entries, complete.entries);

        // Once the store is readable again nothing looks added or removed.
        fs::remove_file(config.join(STORE_FILE)).unwrap();
        assert_eq!(diff(true), 0);
        let (history, _) = load_trust_history();
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn diff_snapshot_includes_operator_grants_and_drops_revoked_ones() {
        use tirith_core::trust_grants::{GrantScope, TrustGrant, TrustGrantStore, STORE_FILE};
        let _state = tirith_test_support::GlobalStateGuard::new().unwrap();
        let config = tirith_core::policy::config_dir().unwrap();
        fs::create_dir_all(&config).unwrap();
        let mut grant = TrustGrant {
            id: uuid::Uuid::new_v4().to_string(),
            pattern: "https://mirror.example/install.sh".into(),
            rule_id: Some("pipe_to_interpreter".into()),
            scope: GrantScope::User,
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
            revoked_at: None,
            reason: None,
        };
        let write = |grant: &TrustGrant| {
            let mut store = TrustGrantStore::default();
            store.insert(grant).unwrap();
            fs::write(config.join(STORE_FILE), serde_json::to_vec(&store).unwrap()).unwrap();
        };
        let key = "grant-user\u{1f}https://mirror.example/install.sh\u{1f}pipe_to_interpreter";
        write(&grant);
        let (before, _) = current_trust_snapshot();
        assert!(
            before.entries.iter().any(|entry| entry == key),
            "trust diff must see trust-grants.json: {:?}",
            before.entries
        );
        record_trust_snapshot(&before);
        grant.revoked_at = Some(chrono::Utc::now().to_rfc3339());
        write(&grant);
        let (after, _) = current_trust_snapshot();
        assert!(!after.entries.iter().any(|entry| entry == key));
        let (history, _) = load_trust_history();
        let baseline = history.last().unwrap();
        assert!(baseline.entries.iter().any(|entry| entry == key));
        assert!(diff(true) == 0);
    }
}
