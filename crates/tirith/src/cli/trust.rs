use std::fs;
use std::io::{self, BufRead, Write};

use serde::{Deserialize, Serialize};

/// Default TTL for a `trust add` with neither `--ttl` nor `--permanent`. Trust
/// expires by default; permanent trust must be chosen explicitly.
const DEFAULT_TTL: &str = "30d";

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

/// How broad a trust pattern is, declared narrowest-first so the derived `Ord`
/// agrees: `ScopeKind::Exact < ScopeKind::BareTld` (broader = riskier).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    /// A specific URL, path, or checksum-like literal — trusts exactly one thing.
    Exact,
    /// A non-domain substring fragment (e.g. `repo/get-pip.py`) — trusts any
    /// URL/command containing that substring.
    Substring,
    /// A whole domain and all its subdomains (e.g. `github.com`).
    Domain,
    /// A wildcard domain (e.g. `*.example.com`).
    Wildcard,
    /// A bare top-level domain (e.g. `com`, `dev`) — trusts every host under
    /// that TLD. Almost always a mistake.
    BareTld,
}

impl ScopeKind {
    /// Short human label for listings.
    fn label(self) -> &'static str {
        match self {
            ScopeKind::Exact => "exact",
            ScopeKind::Substring => "substring",
            ScopeKind::Domain => "domain",
            ScopeKind::Wildcard => "wildcard",
            ScopeKind::BareTld => "bare-TLD",
        }
    }

    /// One-line description of what an entry of this kind covers.
    fn coverage(self) -> &'static str {
        match self {
            ScopeKind::Exact => "matches this exact string only",
            ScopeKind::Substring => "matches any URL or command containing this substring",
            ScopeKind::Domain => "matches this domain and every subdomain under it",
            ScopeKind::Wildcard => "matches every subdomain of this domain",
            ScopeKind::BareTld => "matches every host under this entire top-level domain",
        }
    }

    /// True when an entry of this kind is broad enough that `trust add` should
    /// require an explicit `--broad` opt-in.
    fn is_broad(self) -> bool {
        matches!(
            self,
            ScopeKind::Domain | ScopeKind::Wildcard | ScopeKind::BareTld
        )
    }

    /// True when an entry of this kind is dangerously broad and deserves a
    /// standing warning wherever it is shown.
    fn is_dangerous(self) -> bool {
        matches!(self, ScopeKind::Wildcard | ScopeKind::BareTld)
    }
}

/// Small set of public suffixes to distinguish a *bare* TLD (`com`) from a
/// registrable domain (`example.com`). Not a full PSL — just enough to reject
/// `trust add com` by default.
const KNOWN_TLDS: &[&str] = &[
    "com", "net", "org", "io", "dev", "sh", "co", "ai", "app", "xyz", "info", "biz", "me", "us",
    "uk", "de", "fr", "ru", "cn", "jp", "in", "br", "ca", "au", "eu", "gov", "edu", "mil", "tv",
    "cc", "ws", "to", "gg", "fm", "site", "online", "tech", "cloud", "store", "live", "run", "id",
];

/// Classify how broad a trust pattern is.
pub fn classify_scope(pattern: &str) -> ScopeKind {
    let p = pattern.trim().to_lowercase();

    if let Some(rest) = p.strip_prefix("*.") {
        // `*.com` is a bare-TLD wildcard — still the worst case.
        if !rest.contains('.') && KNOWN_TLDS.contains(&rest) {
            return ScopeKind::BareTld;
        }
        return ScopeKind::Wildcard;
    }

    // A scheme, path, query, or fragment pins a specific URL/resource → Exact.
    if p.contains("://") || p.contains('/') || p.contains('?') || p.contains('#') {
        return ScopeKind::Exact;
    }

    // Bare token, no dot: a bare TLD or a non-domain substring fragment.
    if !p.contains('.') {
        if KNOWN_TLDS.contains(&p.as_str()) {
            return ScopeKind::BareTld;
        }
        return ScopeKind::Substring;
    }

    // At least one dot, no path: a `host.tld`-shaped registrable domain.
    let labels: Vec<&str> = p.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() >= 2 {
        ScopeKind::Domain
    } else {
        // Trailing-dot oddity → substring.
        ScopeKind::Substring
    }
}

/// A unified trust listing row shown by `trust list`.
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

/// Print an error from a trust subcommand, with a "try --scope user" hint
/// when the error mentions "git repository" (i.e., `--scope repo` failed
/// because we are outside a git repo).
fn print_trust_error(subcmd: &str, err: &str, hint_pattern: Option<&str>) {
    eprintln!("tirith: trust {subcmd}: {err}");
    if err.contains("git repository") {
        if let Some(pattern) = hint_pattern {
            eprintln!("  try: tirith trust {subcmd} {pattern} --scope user");
        } else {
            eprintln!("  try: tirith trust {subcmd} --scope user");
        }
    }
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
            eprintln!("tirith: JSON serialization failed: {e}");
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
    match fs::read_to_string(path) {
        Ok(content) => serde_json::from_str(&content)
            .map_err(|e| format!("corrupt trust store at {}: {e}", path.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(TrustStore::default()),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

/// Write the trust store to a path, creating parent directories as needed.
fn write_store(path: &std::path::Path, store: &TrustStore) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create directory {}: {e}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(store)
        .map_err(|e| format!("failed to serialize trust store: {e}"))?;
    fs::write(path, json).map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    Ok(())
}

/// Parse a duration string like "1h", "7d", "30d" into an expiry timestamp.
fn parse_ttl(ttl: &str) -> Result<String, String> {
    let ttl = ttl.trim();
    if ttl.is_empty() {
        return Err("empty TTL".to_string());
    }

    let (num_str, unit) = if let Some(n) = ttl.strip_suffix('d') {
        (n, "d")
    } else if let Some(n) = ttl.strip_suffix('h') {
        (n, "h")
    } else if let Some(n) = ttl.strip_suffix('m') {
        (n, "m")
    } else {
        return Err(format!(
            "unsupported TTL format: {ttl} (use e.g. 1h, 7d, 30d)"
        ));
    };

    let num: u64 = num_str
        .parse()
        .map_err(|_| format!("invalid TTL number: {num_str}"))?;
    if num == 0 {
        return Err("TTL must be > 0".to_string());
    }

    let multiplier: u64 = match unit {
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => unreachable!(),
    };

    let seconds = num
        .checked_mul(multiplier)
        .ok_or_else(|| format!("TTL value too large: {num}{unit}"))?;

    let seconds_i64 =
        i64::try_from(seconds).map_err(|_| format!("TTL value too large: {num}{unit}"))?;

    let expires = chrono::Utc::now() + chrono::Duration::seconds(seconds_i64);
    Ok(expires.to_rfc3339())
}

/// Check if an entry is expired. No `ttl_expires` (older/`--permanent` entries)
/// never expires; an unparseable `ttl_expires` is treated as NOT expired so a
/// malformed timestamp never silently revokes trust.
fn is_expired(entry: &TrustEntry) -> bool {
    if let Some(ref exp) = entry.ttl_expires {
        if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(exp) {
            return expiry < chrono::Utc::now();
        }
    }
    false
}

/// Format the time remaining until an RFC3339 expiry, e.g. "in 6d" / "in 2h".
/// Returns `None` for a permanent (no-TTL) entry, "expired" when already past.
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
fn validate_pattern(pattern: &str, policy: &tirith_core::policy::Policy) -> Result<(), String> {
    if pattern.is_empty() {
        return Err("pattern must not be empty".to_string());
    }
    // Reject control chars (< 0x20, except tab) to stop ANSI escapes / NULs in entries.
    for (i, b) in pattern.bytes().enumerate() {
        if b < 0x20 && b != b'\t' {
            return Err(format!(
                "pattern contains control character at byte offset {i} (0x{b:02x})"
            ));
        }
    }
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
    // Validate against policy plus flat user/org blocklists loaded below.
    let mut policy = tirith_core::policy::Policy::discover(None);
    policy.load_user_lists();
    policy.load_org_lists(None);
    if let Err(e) = validate_pattern(pattern, &policy) {
        eprintln!("tirith: trust add: {e}");
        return 1;
    }

    // --ttl and --permanent are mutually exclusive (clap enforces it too; guard
    // here for the library-call path).
    if permanent && ttl.is_some() {
        eprintln!("tirith: trust add: --permanent cannot be combined with --ttl");
        return 1;
    }

    // Narrow-trust-by-default: a broad pattern (domain/wildcard/bare-TLD) requires
    // an explicit `--broad` opt-in.
    let scope_kind = classify_scope(pattern);
    if scope_kind.is_broad() && !broad {
        eprintln!(
            "tirith: trust add: '{pattern}' is a {} pattern — {}.",
            scope_kind.label(),
            scope_kind.coverage()
        );
        eprintln!(
            "  Trust the narrowest thing that works (a specific URL or path), \
             or pass --broad to accept this scope."
        );
        if scope_kind == ScopeKind::BareTld {
            eprintln!(
                "  Note: trusting a bare TLD allows EVERY host under '.{pattern}' — \
                 this is almost never what you want."
            );
        }
        return 1;
    }

    let path = match trust_store_path(scope) {
        Ok(p) => p,
        Err(e) => {
            print_trust_error("add", &e, Some(pattern));
            return 1;
        }
    };

    let mut store = match load_store(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tirith: trust add: {e}");
            return 1;
        }
    };

    // Resolve the effective TTL:
    //   --permanent          -> no expiry
    //   --ttl <d>            -> that duration
    //   neither              -> DEFAULT_TTL (trust expires by default)
    let (ttl_expires, ttl_label): (Option<String>, Option<String>) = if permanent {
        (None, None)
    } else {
        let effective = ttl.unwrap_or(DEFAULT_TTL);
        match parse_ttl(effective) {
            Ok(exp) => (Some(exp), Some(effective.to_string())),
            Err(e) => {
                eprintln!("tirith: trust add: {e}");
                return 1;
            }
        }
    };

    let entry = TrustEntry {
        pattern: pattern.to_string(),
        rule_id: rule_id.map(String::from),
        ttl_expires: ttl_expires.clone(),
        added: chrono::Utc::now().to_rfc3339(),
        source: "cli".to_string(),
        reason: reason.map(str::to_string),
    };

    store.entries.push(entry);

    if let Err(e) = write_store(&path, &store) {
        eprintln!("tirith: trust add: {e}");
        return 1;
    }

    tirith_core::audit::log_trust_change(pattern, rule_id, "add", ttl_expires.as_deref(), scope);

    if json {
        let out = serde_json::json!({
            "added": pattern,
            "scope": scope,
            "rule_id": rule_id,
            "scope_kind": scope_kind,
            "scope_coverage": scope_kind.coverage(),
            "ttl": ttl_label,
            "ttl_expires": ttl_expires,
            "permanent": permanent,
            "reason": reason,
        });
        return print_json(&out);
    }
    let ttl_note = match &ttl_label {
        Some(t) => format!(", ttl: {t}"),
        None => ", permanent (no expiry)".to_string(),
    };
    eprintln!(
        "tirith: trusted '{pattern}' (scope: {scope}, {} pattern{ttl_note})",
        scope_kind.label()
    );
    if scope_kind.is_dangerous() {
        eprintln!(
            "  warning: this is a {} entry — {}.",
            scope_kind.label(),
            scope_kind.coverage()
        );
    }
    0
}

/// `tirith trust list [--rule <id>] [--json] [--expired] [--scope user|repo|all]`
pub fn list(rule_filter: Option<&str>, json: bool, show_expired: bool, scope: &str) -> i32 {
    if !matches!(scope, "user" | "repo" | "all") {
        eprintln!("tirith: trust list: unknown scope '{scope}' (use 'user', 'repo', or 'all')");
        return 1;
    }

    let mut rows: Vec<TrustListRow> = match collect_rows(scope, show_expired) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tirith: trust list: {e}");
            return 1;
        }
    };

    if let Some(filter) = rule_filter {
        rows.retain(|r| {
            r.rule_id
                .as_ref()
                .map(|id| id.eq_ignore_ascii_case(filter))
                .unwrap_or(false)
        });
    }

    if json {
        return print_json(&rows);
    }
    if rows.is_empty() {
        eprintln!("tirith: no trust entries found");
    } else {
        let max_pat = rows
            .iter()
            .map(|r| r.pattern.len())
            .max()
            .unwrap_or(7)
            .max(7);
        let max_src = rows
            .iter()
            .map(|r| r.source.len())
            .max()
            .unwrap_or(6)
            .max(6);
        let max_rule = rows
            .iter()
            .map(|r| r.rule_id.as_ref().map(|s| s.len()).unwrap_or(1))
            .max()
            .unwrap_or(4)
            .max(4);
        // A '!' suffix marks a dangerously broad entry; size the SCOPE column
        // on the *rendered* string so the trailing '!' never breaks alignment.
        let scope_render = |row: &TrustListRow| -> String {
            if row.broad_warning {
                format!("{}!", row.scope_kind.label())
            } else {
                row.scope_kind.label().to_string()
            }
        };
        let max_scope = rows
            .iter()
            .map(|r| scope_render(r).len())
            .max()
            .unwrap_or(5)
            .max(5);

        eprintln!(
            "{:<max_pat$}  {:<max_rule$}  {:<max_scope$}  {:<max_src$}  EXPIRES",
            "PATTERN", "RULE", "SCOPE", "SOURCE"
        );
        let mut any_dangerous = false;
        for row in &rows {
            let rule_display = row.rule_id.as_deref().unwrap_or("-");
            let expires_display = match (&row.expires, row.expired) {
                (Some(exp), true) => format!("{exp} (EXPIRED)"),
                (Some(exp), false) => match humanize_expiry(Some(exp)) {
                    Some(h) => format!("{exp} ({h})"),
                    None => exp.clone(),
                },
                (None, _) => "permanent".to_string(),
            };
            let scope_display = scope_render(row);
            if row.broad_warning {
                any_dangerous = true;
            }
            eprintln!(
                "{:<max_pat$}  {:<max_rule$}  {:<max_scope$}  {:<max_src$}  {}",
                row.pattern, rule_display, scope_display, row.source, expires_display
            );
        }
        if any_dangerous {
            eprintln!(
                "\ntirith: '!' marks dangerously broad entries (wildcard / bare TLD). \
                 Run 'tirith trust explain <pattern>' for detail."
            );
        }
    }

    0
}

/// Collect every trust-style row for the given scope. Shared by `list` and the
/// scope-visualisation paths. `show_expired` controls whether expired
/// TTL-bearing entries are included.
fn collect_rows(scope: &str, show_expired: bool) -> Result<Vec<TrustListRow>, String> {
    let mut rows: Vec<TrustListRow> = Vec::new();

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
        let store = load_store(&path)?;
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

/// `tirith trust remove <pattern> [--rule <rule_id>] [--scope user|repo]`
pub fn remove(pattern: &str, rule_id: Option<&str>, scope: &str) -> i32 {
    let path = match trust_store_path(scope) {
        Ok(p) => p,
        Err(e) => {
            print_trust_error("remove", &e, Some(pattern));
            return 1;
        }
    };

    let mut store = match load_store(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tirith: trust remove: {e}");
            return 1;
        }
    };
    let before_len = store.entries.len();

    store.entries.retain(|entry| {
        let pattern_matches = entry.pattern == pattern;
        let rule_matches = match (rule_id, &entry.rule_id) {
            (Some(filter), Some(entry_rule)) => filter.eq_ignore_ascii_case(entry_rule),
            (Some(_), None) => false,
            (None, _) => true,
        };
        !(pattern_matches && rule_matches)
    });

    let removed = before_len - store.entries.len();
    if removed == 0 {
        eprintln!("tirith: trust remove: no matching entry found for '{pattern}'");
        return 1;
    }

    if let Err(e) = write_store(&path, &store) {
        eprintln!("tirith: trust remove: {e}");
        return 1;
    }

    tirith_core::audit::log_trust_change(pattern, rule_id, "remove", None, scope);

    eprintln!("tirith: removed {removed} trust entry/entries for '{pattern}' (scope: {scope})");
    0
}

/// Read and JSON-parse `last_trigger.json` from the data dir.
///
/// Shared by `last()` (interactive prompt) and `from_last_trigger()` (suggest
/// ready-to-run commands). Returns the parsed value so each caller can pull the
/// fields it needs without re-reading the file. `Ok(None)` means there is no
/// recent trigger on disk (missing file); `Err` is a real read/parse failure.
fn load_last_trigger_value() -> Result<Option<serde_json::Value>, String> {
    let data_dir = tirith_core::policy::data_dir()
        .ok_or_else(|| "cannot determine data directory".to_string())?;
    let path = data_dir.join("last_trigger.json");
    if !path.exists() {
        return Ok(None);
    }
    let content =
        fs::read_to_string(&path).map_err(|e| format!("failed to read last trigger: {e}"))?;
    let val: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("failed to parse last trigger: {e}"))?;
    Ok(Some(val))
}

/// Extract trust targets and rule IDs from a parsed `last_trigger.json`.
///
/// `targets` prefer a FULL URL when the finding evidence carries one (a `raw`
/// string with a scheme that parses) so the suggested trust can be narrow; it
/// falls back to a bare host/domain otherwise. Order and de-dup mirror the way
/// `last()` walks findings (per-finding `raw` first, then `raw_host`).
fn extract_targets_and_rules(val: &serde_json::Value) -> (Vec<String>, Vec<String>) {
    let mut targets: Vec<String> = Vec::new();
    let push = |t: String, targets: &mut Vec<String>| {
        if !t.is_empty() && !targets.contains(&t) {
            targets.push(t);
        }
    };
    if let Some(findings) = val.get("findings").and_then(|v| v.as_array()) {
        for finding in findings {
            if let Some(evidence) = finding.get("evidence").and_then(|v| v.as_array()) {
                for ev in evidence {
                    if let Some(raw) = ev.get("raw").and_then(|v| v.as_str()) {
                        // Prefer the full URL when `raw` is one; else fall back
                        // to the bare host so we still have something to trust.
                        if raw.contains("://") && url::Url::parse(raw).is_ok() {
                            push(raw.to_string(), &mut targets);
                        } else if let Some(host) = extract_host(raw) {
                            push(host, &mut targets);
                        }
                    }
                    if let Some(host) = ev.get("raw_host").and_then(|v| v.as_str()) {
                        push(host.to_string(), &mut targets);
                    }
                }
            }
        }
    }

    let rule_ids: Vec<String> = val
        .get("rule_ids")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    (targets, rule_ids)
}

/// Read + parse + extract in one step: `(targets, rule_ids)`.
///
/// `targets` prefer full URLs, else bare domains (see `extract_targets_and_rules`).
/// `Err` covers both "no recent trigger" (so callers can print a friendly note)
/// and real read/parse failures.
fn read_last_trigger() -> Result<(Vec<String>, Vec<String>), String> {
    match load_last_trigger_value()? {
        Some(val) => Ok(extract_targets_and_rules(&val)),
        None => Err("no recent trigger found".into()),
    }
}

/// Build the ready-to-run `tirith trust add` suggestion lines for each
/// (target, rule_id) pair. A full-URL target is narrow, so it is suggested
/// without `--broad`; a bare domain needs `--broad` because `trust add` rejects
/// broad scopes without the opt-in (see `add()` / `classify_scope`).
fn suggestion_lines(targets: &[String], rule_ids: &[String]) -> Vec<String> {
    let mut lines = Vec::new();
    for target in targets {
        // A target that classifies as broad (bare domain/wildcard/TLD) needs
        // `--broad`; a full URL (or any narrow pattern) does not.
        let needs_broad = classify_scope(target).is_broad();
        if rule_ids.is_empty() {
            lines.push(format_add_line(target, None, needs_broad));
        } else {
            for rid in rule_ids {
                lines.push(format_add_line(target, Some(rid), needs_broad));
            }
        }
    }
    lines
}

fn format_add_line(target: &str, rule_id: Option<&str>, needs_broad: bool) -> String {
    let broad = if needs_broad { " --broad" } else { "" };
    match rule_id {
        Some(rid) => format!("tirith trust add {target}{broad} --rule {rid} --ttl 30d"),
        None => format!("tirith trust add {target}{broad} --ttl 30d"),
    }
}

/// `tirith trust from-last-trigger [--apply]` -- turn the most recent trigger
/// into trust commands. Default (suggest) prints ready-to-run `trust add`
/// lines so the operator can copy/paste the narrowest one; `--apply` runs them.
///
/// Print-only by default mirrors the codebase's `policy tune` stance: suggest,
/// don't mutate.
pub fn from_last_trigger(apply: bool) -> i32 {
    let (targets, rule_ids) = match read_last_trigger() {
        Ok(v) => v,
        // A missing/empty trigger is not an error for this command -- it is the
        // common "nothing happened yet" case, so exit 0 with a friendly note.
        Err(e) if e == "no recent trigger found" => {
            eprintln!("tirith: no recent trigger to trust");
            return 0;
        }
        Err(e) => {
            eprintln!("tirith: trust from-last-trigger: {e}");
            return 1;
        }
    };

    if targets.is_empty() {
        eprintln!("tirith: no recent trigger to trust");
        return 0;
    }

    if !apply {
        eprintln!("Suggested trust commands (run the narrowest one that fits):");
        eprintln!();
        for line in suggestion_lines(&targets, &rule_ids) {
            println!("{line}");
        }
        eprintln!();
        eprintln!("Re-run with --apply to add these automatically.");
        return 0;
    }

    // --apply: actually add each entry. A bare-domain target is broad, so pass
    // `broad = true`; a full-URL (narrow) target does not need it.
    let mut added = 0;
    for target in &targets {
        let broad = classify_scope(target).is_broad();
        if rule_ids.is_empty() {
            if add(target, None, None, false, broad, None, "user", false) == 0 {
                added += 1;
            }
        } else {
            for rid in &rule_ids {
                if add(target, Some(rid), None, false, broad, None, "user", false) == 0 {
                    added += 1;
                }
            }
        }
    }

    eprintln!("tirith: added {added} trust entry/entries from last trigger");
    0
}

/// `tirith trust last` -- show last trigger and offer to trust.
pub fn last() -> i32 {
    let val = match load_last_trigger_value() {
        Ok(Some(v)) => v,
        Ok(None) => {
            eprintln!("tirith: no recent trigger found");
            return 1;
        }
        Err(e) => {
            eprintln!("tirith: {e}");
            return 1;
        }
    };

    if let Some(ts) = val.get("timestamp").and_then(|v| v.as_str()) {
        eprintln!("Last trigger at: {ts}");
    }
    if let Some(cmd) = val.get("command_redacted").and_then(|v| v.as_str()) {
        eprintln!("Command: {cmd}");
    }

    let mut domains: Vec<String> = Vec::new();
    if let Some(findings) = val.get("findings").and_then(|v| v.as_array()) {
        for finding in findings {
            if let Some(title) = finding.get("title").and_then(|v| v.as_str()) {
                eprintln!("  - {title}");
            }
            if let Some(evidence) = finding.get("evidence").and_then(|v| v.as_array()) {
                for ev in evidence {
                    if let Some(raw) = ev.get("raw").and_then(|v| v.as_str()) {
                        if let Some(host) = extract_host(raw) {
                            if !domains.contains(&host) {
                                domains.push(host);
                            }
                        }
                    }
                    if let Some(host) = ev.get("raw_host").and_then(|v| v.as_str()) {
                        let h = host.to_string();
                        if !domains.contains(&h) {
                            domains.push(h);
                        }
                    }
                }
            }
        }
    }

    if domains.is_empty() {
        eprintln!("\ntirith: no domain/URL found in last trigger to trust");
        return 0;
    }

    let rule_ids: Vec<String> = val
        .get("rule_ids")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    for domain in &domains {
        eprintln!();
        eprint!("Trust {domain}? [y/N/r(rule-scoped)/t(temporary 7d)] ");
        let _ = io::stderr().flush();

        let stdin = io::stdin();
        let mut line = String::new();
        if stdin.lock().read_line(&mut line).is_err() {
            continue;
        }
        let choice = line.trim().to_lowercase();

        match choice.as_str() {
            "y" | "yes" => {
                // A bare `y` trusts the whole domain — keep that affordance,
                // but it is a broad scope, so pass `broad = true` explicitly.
                add(domain, None, None, false, true, None, "user", false);
            }
            "r" | "rule" => {
                if rule_ids.is_empty() {
                    eprintln!("tirith: no rule IDs in last trigger, adding global trust");
                    add(domain, None, None, false, true, None, "user", false);
                } else {
                    for rid in &rule_ids {
                        // Rule-scoped trust is narrow by construction.
                        add(domain, Some(rid), None, false, true, None, "user", false);
                    }
                }
            }
            "t" | "temp" | "temporary" => {
                add(domain, None, Some("7d"), false, true, None, "user", false);
            }
            _ => {
                eprintln!("tirith: skipped {domain}");
            }
        }
    }

    0
}

/// `tirith trust gc [--expired] [--scope user|repo|all]`
///
/// `--expired` is the default and only collection mode today; it is accepted
/// explicitly so the command reads clearly and leaves room for future modes.
pub fn gc(expired: bool, scope: &str, json: bool) -> i32 {
    gc_with_action("gc", expired, scope, json)
}

/// `tirith trust prune` — spec-named alias for `gc` (M6 ch3). Both
/// invoke the same backing implementation; only the audit `trust_action`
/// field differs so an operator can tell which command the user actually
/// typed.
pub fn prune(expired: bool, scope: &str, json: bool) -> i32 {
    gc_with_action("prune", expired, scope, json)
}

fn gc_with_action(action_label: &str, expired: bool, scope: &str, json: bool) -> i32 {
    if !matches!(scope, "user" | "repo" | "all") {
        eprintln!(
            "tirith: trust {action_label}: unknown scope '{scope}' (use 'user', 'repo', or 'all')",
        );
        return 1;
    }
    // `--expired` is currently the only mode; if a caller explicitly passes
    // nothing we still collect expired entries (documented default).
    let _ = expired;

    let scopes: Vec<&str> = match scope {
        "all" => vec!["user", "repo"],
        s => vec![s],
    };

    let mut total_removed = 0;
    let mut per_scope: Vec<(String, usize)> = Vec::new();

    for s in scopes {
        let path = match trust_store_path(s) {
            Ok(p) => p,
            Err(e) => {
                if scope != "all" {
                    print_trust_error(action_label, &e, None);
                    return 1;
                }
                continue;
            }
        };

        if !path.exists() {
            continue;
        }

        let mut store = match load_store(&path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("tirith: trust {action_label}: {e}");
                return 1;
            }
        };
        let before = store.entries.len();
        // Capture removed entries so each lands in the audit log under the right
        // `trust_action` (M6 ch3) — otherwise gc/prune sweeps are invisible there.
        let expired_entries: Vec<TrustEntry> = store
            .entries
            .iter()
            .filter(|entry| is_expired(entry))
            .cloned()
            .collect();
        store.entries.retain(|entry| !is_expired(entry));
        let removed = before - store.entries.len();

        if removed > 0 {
            if let Err(e) = write_store(&path, &store) {
                eprintln!("tirith: trust {action_label}: {e}");
                return 1;
            }
            for entry in &expired_entries {
                tirith_core::audit::log_trust_change(
                    &entry.pattern,
                    entry.rule_id.as_deref(),
                    action_label,
                    entry.ttl_expires.as_deref(),
                    s,
                );
            }
            if !json {
                eprintln!(
                    "tirith: {action_label}: removed {removed} expired entries from {s} scope",
                );
            }
        }

        per_scope.push((s.to_string(), removed));
        total_removed += removed;
    }

    if json {
        let out = serde_json::json!({
            "removed_total": total_removed,
            "by_scope": per_scope
                .iter()
                .map(|(s, n)| serde_json::json!({ "scope": s, "removed": n }))
                .collect::<Vec<_>>(),
        });
        return print_json(&out);
    }
    if total_removed == 0 {
        eprintln!("tirith: {action_label}: no expired entries found");
    }

    0
}

// --- trust explain ---------------------------------------------------------

/// `tirith trust explain <pattern> [--scope ...]` — explain one trust entry:
/// what it covers, how broad it is, when it expires, and why it was added.
#[derive(Debug, Serialize)]
struct ExplainReport {
    pattern: String,
    /// True when no matching trust/allowlist entry exists.
    found: bool,
    /// One report per matching entry (a pattern may appear in several scopes).
    matches: Vec<ExplainMatch>,
}

#[derive(Debug, Serialize)]
struct ExplainMatch {
    source: String,
    rule_id: Option<String>,
    scope_kind: ScopeKind,
    scope_coverage: String,
    /// True when this entry is dangerously broad.
    broad_warning: bool,
    added: Option<String>,
    reason: Option<String>,
    ttl_expires: Option<String>,
    /// Human "in 6d" / "expired" / `None` for permanent.
    expires_in: Option<String>,
    expired: bool,
    permanent: bool,
}

/// `tirith trust explain <pattern>`.
pub fn explain(pattern: &str, scope: &str, json: bool) -> i32 {
    if !matches!(scope, "user" | "repo" | "all") {
        eprintln!("tirith: trust explain: unknown scope '{scope}' (use 'user', 'repo', or 'all')");
        return 1;
    }
    if pattern.is_empty() {
        eprintln!("tirith: trust explain: pattern must not be empty");
        return 1;
    }

    // Gather full entry detail (reason/added) from the trust stores, plus
    // bare allowlist/policy rows. Show expired entries too — `explain` is for
    // understanding an entry, including a stale one.
    let mut matches: Vec<ExplainMatch> = Vec::new();

    let scopes: Vec<&str> = match scope {
        "all" => vec!["user", "repo"],
        s => vec![s],
    };
    for s in &scopes {
        let path = match trust_store_path(s) {
            Ok(p) => p,
            Err(e) => {
                if scope != "all" {
                    print_trust_error("explain", &e, None);
                    return 1;
                }
                continue;
            }
        };
        let store = match load_store(&path) {
            Ok(st) => st,
            Err(e) => {
                eprintln!("tirith: trust explain: {e}");
                return 1;
            }
        };
        for entry in &store.entries {
            if entry.pattern == pattern {
                let kind = classify_scope(&entry.pattern);
                matches.push(ExplainMatch {
                    source: format!("trust-{s}"),
                    rule_id: entry.rule_id.clone(),
                    scope_kind: kind,
                    scope_coverage: kind.coverage().to_string(),
                    broad_warning: kind.is_dangerous(),
                    added: Some(entry.added.clone()),
                    reason: entry.reason.clone(),
                    ttl_expires: entry.ttl_expires.clone(),
                    expires_in: humanize_expiry(entry.ttl_expires.as_deref()),
                    expired: is_expired(entry),
                    permanent: entry.ttl_expires.is_none(),
                });
            }
        }
    }

    // Also surface a match coming purely from policy / flat allowlist files.
    if scope == "all" {
        if let Ok(rows) = collect_rows("all", true) {
            for r in rows {
                let from_allowlist_or_policy =
                    r.source.starts_with("allowlist") || r.source == "policy";
                if r.pattern == pattern && from_allowlist_or_policy {
                    matches.push(ExplainMatch {
                        source: r.source,
                        rule_id: r.rule_id,
                        scope_kind: r.scope_kind,
                        scope_coverage: r.scope_coverage,
                        broad_warning: r.broad_warning,
                        added: None,
                        reason: None,
                        ttl_expires: None,
                        expires_in: None,
                        expired: false,
                        permanent: true,
                    });
                }
            }
        }
    }

    let report = ExplainReport {
        pattern: pattern.to_string(),
        found: !matches.is_empty(),
        matches,
    };

    if json {
        return print_json(&report);
    }

    if !report.found {
        // Still explain what *would* happen if this pattern were trusted.
        let kind = classify_scope(pattern);
        eprintln!("tirith: '{pattern}' is not currently trusted in scope '{scope}'.");
        eprintln!(
            "  If added, it would be a {} entry — {}.",
            kind.label(),
            kind.coverage()
        );
        if kind.is_broad() {
            eprintln!("  That is a broad scope; `trust add` would require --broad to accept it.");
        }
        return 0;
    }

    println!("trust explain: {pattern}");
    for (i, m) in report.matches.iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!("  source:   {}", m.source);
        println!(
            "  scope:    {} — {}",
            m.scope_kind.label(),
            m.scope_coverage
        );
        if let Some(rid) = &m.rule_id {
            println!("  rule:     {rid} (suppresses this rule only)");
        } else {
            println!("  rule:     (global — suppresses every rule)");
        }
        if let Some(added) = &m.added {
            println!("  added:    {added}");
        }
        match &m.reason {
            Some(r) => println!("  reason:   {r}"),
            None => println!("  reason:   (none recorded)"),
        }
        match (&m.ttl_expires, m.permanent) {
            (_, true) => println!("  expires:  never (permanent)"),
            (Some(exp), false) => {
                let suffix = m
                    .expires_in
                    .as_deref()
                    .map(|h| format!(" ({h})"))
                    .unwrap_or_default();
                println!("  expires:  {exp}{suffix}");
            }
            (None, false) => println!("  expires:  never (permanent)"),
        }
        if m.expired {
            println!("  status:   EXPIRED — run 'tirith trust gc --expired' to remove it");
        }
        if m.broad_warning {
            println!(
                "  warning:  dangerously broad — {}",
                m.scope_kind.coverage()
            );
        }
    }
    0
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
/// expired entries — diff cares about set membership, not expiry).
fn current_trust_snapshot() -> TrustSnapshot {
    let mut entries: Vec<String> = collect_rows("all", true)
        .unwrap_or_default()
        .iter()
        .map(row_key)
        .collect();
    entries.sort();
    entries.dedup();
    TrustSnapshot {
        recorded_at: chrono::Utc::now().to_rfc3339(),
        entries,
    }
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

/// Take a snapshot of the current trust set and fold it into the history file.
/// Called by the read-only `trust list` / `trust diff` paths so a diff trail
/// accrues over time without any extra user action.
pub fn snapshot_current_trust() {
    record_trust_snapshot(&current_trust_snapshot());
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
    /// Set when the diff could not be produced against a real baseline.
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
                eprintln!("tirith: trust audit: invalid --since value: {e}");
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
                "tirith: trust audit: no audit log yet at {}",
                log_path.display()
            );
        }
        return 0;
    }

    // Reuse the superset reader so missing fields on older entries parse cleanly.
    let result = match tirith_core::audit_aggregator::read_log(&log_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "tirith: trust audit: cannot read audit log at {}: {e}",
                log_path.display(),
            );
            return 1;
        }
    };

    // Surface malformed-line skips so a corrupted log isn't invisible to an
    // operator chasing a missing entry. JSON shape includes it in the envelope below.
    if result.skipped_lines > 0 && !json {
        eprintln!(
            "tirith: trust audit: skipped {} malformed audit log line(s) at {}",
            result.skipped_lines,
            log_path.display(),
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
            r.timestamp, r.action, r.scope, r.pattern, rule_suffix
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
    let current = current_trust_snapshot();

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
            note: Some(history_read_error.clone().unwrap_or_else(|| {
                "No earlier trust snapshot to compare against — this is the first \
                 observation. Run a 'tirith trust' command again later to build a \
                 diff trail."
                    .to_string()
            })),
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
                note: None,
            }
        }
    };

    // Record the current snapshot AFTER computing the diff so the next `diff`
    // has a fresh baseline.
    record_trust_snapshot(&current);

    if json {
        return print_json(&report);
    }

    match &report.baseline_recorded_at {
        Some(ts) => println!("trust diff (since {ts})"),
        None => println!("trust diff"),
    }
    if let Some(note) = &report.note {
        println!("  note: {note}");
        return 0;
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
                "    + {} ({}, {}){rule}",
                e.pattern,
                e.source,
                e.scope_kind.label()
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
                "    - {} ({}, {}){rule}",
                e.pattern,
                e.source,
                e.scope_kind.label()
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
    fn test_is_expired_unparseable_ttl_is_not_expired() {
        // A malformed timestamp must never silently revoke trust.
        let entry = TrustEntry {
            pattern: "example.com".to_string(),
            rule_id: None,
            ttl_expires: Some("not-a-timestamp".to_string()),
            added: chrono::Utc::now().to_rfc3339(),
            source: "cli".to_string(),
            reason: None,
        };
        assert!(!is_expired(&entry));
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
    fn test_validate_pattern_tab_ok() {
        let policy = tirith_core::policy::Policy::default();
        assert!(validate_pattern("hello\tworld", &policy).is_ok());
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

        write_store(&path, &store).unwrap();
        let loaded = load_store(&path).unwrap();

        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].pattern, "example.com");
        assert_eq!(loaded.entries[0].rule_id.as_deref(), Some("shortened_url"));
        assert_eq!(loaded.entries[0].reason.as_deref(), Some("internal mirror"));
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

        write_store(&path, &store).unwrap();

        let mut loaded = load_store(&path).unwrap();
        loaded.entries.retain(|e| !is_expired(e));
        write_store(&path, &loaded).unwrap();

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
        assert!(!ScopeKind::Substring.is_broad());
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

    /// Plant a `last_trigger.json` under a temp data dir and run `f` with
    /// `data_dir()` pointed at it. Holds `ENV_LOCK` (process-global env mutation)
    /// and restores `XDG_DATA_HOME` / `APPDATA` on Drop. `data_dir()` honors
    /// `XDG_DATA_HOME` on Unix but `%APPDATA%` on Windows (etcetera), so set both.
    fn with_seeded_last_trigger<F: FnOnce()>(json: &str, f: F) {
        use crate::cli::test_harness::{EnvGuard, ENV_LOCK};
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().expect("tempdir");
        let _xdg = EnvGuard::set("XDG_DATA_HOME", dir.path());
        let _appdata = EnvGuard::set("APPDATA", dir.path());

        let tirith_data = dir.path().join("tirith");
        fs::create_dir_all(&tirith_data).expect("create data dir");
        fs::write(tirith_data.join("last_trigger.json"), json).expect("write last_trigger.json");

        f();
    }

    /// Same env isolation, but plant NO `last_trigger.json` (empty data dir).
    fn with_empty_data_dir<F: FnOnce()>(f: F) {
        use crate::cli::test_harness::{EnvGuard, ENV_LOCK};
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().expect("tempdir");
        let _xdg = EnvGuard::set("XDG_DATA_HOME", dir.path());
        let _appdata = EnvGuard::set("APPDATA", dir.path());
        f();
    }

    /// A full-URL evidence target is suggested NARROW: a copy/paste-ready
    /// `tirith trust add <url> --rule <rule_id> --ttl 30d` line with NO `--broad`.
    #[test]
    fn from_last_trigger_suggests_narrow_url_without_broad() {
        let json = r#"{
            "rule_ids": ["shortened_url"],
            "severity": "high",
            "command_redacted": "curl https://example.com/install.sh | sh",
            "timestamp": "2026-06-10T00:00:00Z",
            "findings": [
                {
                    "title": "Shortened URL",
                    "evidence": [
                        { "raw": "https://example.com/install.sh" }
                    ]
                }
            ]
        }"#;

        with_seeded_last_trigger(json, || {
            // read_last_trigger prefers the FULL URL as the target.
            let (targets, rule_ids) = read_last_trigger().expect("read_last_trigger");
            assert_eq!(targets, vec!["https://example.com/install.sh".to_string()]);
            assert_eq!(rule_ids, vec!["shortened_url".to_string()]);

            // The suggested line is the narrow, no-`--broad` form.
            let lines = suggestion_lines(&targets, &rule_ids);
            let expected =
                "tirith trust add https://example.com/install.sh --rule shortened_url --ttl 30d";
            assert!(
                lines.iter().any(|l| l == expected),
                "expected narrow URL suggestion {expected:?}, got: {lines:?}"
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
                { "title": "Homograph", "evidence": [ { "raw_host": "example.com" } ] }
            ]
        }"#;

        with_seeded_last_trigger(json, || {
            let (targets, rule_ids) = read_last_trigger().expect("read_last_trigger");
            assert_eq!(targets, vec!["example.com".to_string()]);

            let lines = suggestion_lines(&targets, &rule_ids);
            let expected = "tirith trust add example.com --broad --rule homograph --ttl 30d";
            assert!(
                lines.iter().any(|l| l == expected),
                "expected bare-domain suggestion with --broad {expected:?}, got: {lines:?}"
            );
        });
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
}
