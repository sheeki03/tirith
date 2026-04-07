use std::fs;
use std::io::{self, BufRead, Write};

use serde::{Deserialize, Serialize};

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

/// A unified trust listing row shown by `trust list`.
#[derive(Debug, Clone, Serialize)]
struct TrustListRow {
    pattern: String,
    rule_id: Option<String>,
    source: String,
    expires: Option<String>,
    expired: bool,
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

/// Check if an entry is expired.
fn is_expired(entry: &TrustEntry) -> bool {
    if let Some(ref exp) = entry.ttl_expires {
        if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(exp) {
            return expiry < chrono::Utc::now();
        }
    }
    false
}

/// Validate a pattern for trust add.
fn validate_pattern(pattern: &str, policy: &tirith_core::policy::Policy) -> Result<(), String> {
    if pattern.is_empty() {
        return Err("pattern must not be empty".to_string());
    }
    // No control characters (bytes < 0x20 except tab)
    for (i, b) in pattern.bytes().enumerate() {
        if b < 0x20 && b != b'\t' {
            return Err(format!(
                "pattern contains control character at byte offset {i} (0x{b:02x})"
            ));
        }
    }
    // Not in blocklist
    if policy.is_blocklisted(pattern) {
        return Err(format!(
            "pattern '{pattern}' is in the blocklist and cannot be trusted"
        ));
    }
    Ok(())
}

/// `tirith trust add <pattern> [--rule <rule_id>] [--ttl <duration>] [--scope user|repo]`
pub fn add(pattern: &str, rule_id: Option<&str>, ttl: Option<&str>, scope: &str) -> i32 {
    // Validate pattern against policy (including flat user/org blocklists)
    let mut policy = tirith_core::policy::Policy::discover(None);
    policy.load_user_lists();
    policy.load_org_lists(None);
    if let Err(e) = validate_pattern(pattern, &policy) {
        eprintln!("tirith: trust add: {e}");
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

    // Compute TTL expiry if provided
    let ttl_expires = match ttl {
        Some(t) => match parse_ttl(t) {
            Ok(exp) => Some(exp),
            Err(e) => {
                eprintln!("tirith: trust add: {e}");
                return 1;
            }
        },
        None => None,
    };

    let entry = TrustEntry {
        pattern: pattern.to_string(),
        rule_id: rule_id.map(String::from),
        ttl_expires: ttl_expires.clone(),
        added: chrono::Utc::now().to_rfc3339(),
        source: "cli".to_string(),
    };

    store.entries.push(entry);

    if let Err(e) = write_store(&path, &store) {
        eprintln!("tirith: trust add: {e}");
        return 1;
    }

    // Audit log the trust change
    tirith_core::audit::log_trust_change(pattern, rule_id, "add", ttl_expires.as_deref(), scope);

    eprintln!(
        "tirith: trusted '{pattern}' (scope: {scope}{})",
        ttl.map(|t| format!(", ttl: {t}")).unwrap_or_default()
    );
    0
}

/// `tirith trust list [--rule <id>] [--json] [--expired] [--scope user|repo|all]`
pub fn list(rule_filter: Option<&str>, json: bool, show_expired: bool, scope: &str) -> i32 {
    // Validate scope early
    if !matches!(scope, "user" | "repo" | "all") {
        eprintln!("tirith: trust list: unknown scope '{scope}' (use 'user', 'repo', or 'all')");
        return 1;
    }

    let mut rows: Vec<TrustListRow> = Vec::new();

    let scopes_to_load: Vec<&str> = match scope {
        "all" => vec!["user", "repo"],
        s => vec![s],
    };

    // Load trust.json entries from each scope
    for s in &scopes_to_load {
        let path = match trust_store_path(s) {
            Ok(p) => p,
            Err(e) => {
                // Explicit single-scope request: hard error.
                // "all" scope: skip gracefully (repo may not exist).
                if scope != "all" {
                    print_trust_error("list", &e, None);
                    return 1;
                }
                continue;
            }
        };
        let store = match load_store(&path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("tirith: trust list: {e}");
                return 1;
            }
        };
        let source = format!("trust-{s}");
        for entry in &store.entries {
            let expired = is_expired(entry);
            if expired && !show_expired {
                continue;
            }
            rows.push(TrustListRow {
                pattern: entry.pattern.clone(),
                rule_id: entry.rule_id.clone(),
                source: source.clone(),
                expires: entry.ttl_expires.clone(),
                expired,
            });
        }
    }

    // Load flat allowlists when showing "all" scope
    if scope == "all" {
        // User flat allowlist
        if let Some(config) = tirith_core::policy::config_dir() {
            let allowlist_path = config.join("allowlist");
            if let Ok(content) = fs::read_to_string(&allowlist_path) {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        rows.push(TrustListRow {
                            pattern: line.to_string(),
                            rule_id: None,
                            source: "allowlist-user".to_string(),
                            expires: None,
                            expired: false,
                        });
                    }
                }
            }
        }

        // Org flat allowlist
        if let Some(repo_root) = tirith_core::policy::find_repo_root(None) {
            let allowlist_path = repo_root.join(".tirith").join("allowlist");
            if let Ok(content) = fs::read_to_string(&allowlist_path) {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        rows.push(TrustListRow {
                            pattern: line.to_string(),
                            rule_id: None,
                            source: "allowlist-org".to_string(),
                            expires: None,
                            expired: false,
                        });
                    }
                }
            }
        }

        // Policy YAML allowlist
        let policy = tirith_core::policy::Policy::discover(None);
        for pattern in &policy.allowlist {
            // Avoid duplicates from flat files already loaded
            if !rows
                .iter()
                .any(|r| r.pattern == *pattern && r.source.starts_with("allowlist"))
            {
                rows.push(TrustListRow {
                    pattern: pattern.clone(),
                    rule_id: None,
                    source: "policy".to_string(),
                    expires: None,
                    expired: false,
                });
            }
        }
        for rule in &policy.allowlist_rules {
            for pattern in &rule.patterns {
                rows.push(TrustListRow {
                    pattern: pattern.clone(),
                    rule_id: Some(rule.rule_id.clone()),
                    source: "policy".to_string(),
                    expires: None,
                    expired: false,
                });
            }
        }
    }

    // Apply rule filter
    if let Some(filter) = rule_filter {
        rows.retain(|r| {
            r.rule_id
                .as_ref()
                .map(|id| id.eq_ignore_ascii_case(filter))
                .unwrap_or(false)
        });
    }

    if json {
        let output = serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".to_string());
        println!("{output}");
    } else if rows.is_empty() {
        eprintln!("tirith: no trust entries found");
    } else {
        // Column-aligned table output
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

        let header_expires: &str = "EXPIRES";
        eprintln!(
            "{:<max_pat$}  {:<max_rule$}  {:<max_src$}  {}",
            "PATTERN", "RULE", "SOURCE", header_expires
        );
        for row in &rows {
            let rule_display = row.rule_id.as_deref().unwrap_or("-");
            let expires_display = match (&row.expires, row.expired) {
                (Some(exp), true) => format!("{exp} (EXPIRED)"),
                (Some(exp), false) => exp.clone(),
                (None, _) => "-".to_string(),
            };
            eprintln!(
                "{:<max_pat$}  {:<max_rule$}  {:<max_src$}  {}",
                row.pattern, rule_display, row.source, expires_display
            );
        }
    }

    0
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

    // Audit log the trust change
    tirith_core::audit::log_trust_change(pattern, rule_id, "remove", None, scope);

    eprintln!("tirith: removed {removed} trust entry/entries for '{pattern}' (scope: {scope})");
    0
}

/// `tirith trust last` -- show last trigger and offer to trust.
pub fn last() -> i32 {
    let data_dir = match tirith_core::policy::data_dir() {
        Some(d) => d,
        None => {
            eprintln!("tirith: cannot determine data directory");
            return 1;
        }
    };

    let path = data_dir.join("last_trigger.json");
    if !path.exists() {
        eprintln!("tirith: no recent trigger found");
        return 1;
    }

    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tirith: failed to read last trigger: {e}");
            return 1;
        }
    };

    let val: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("tirith: failed to parse last trigger: {e}");
            return 1;
        }
    };

    // Display trigger summary
    if let Some(ts) = val.get("timestamp").and_then(|v| v.as_str()) {
        eprintln!("Last trigger at: {ts}");
    }
    if let Some(cmd) = val.get("command_redacted").and_then(|v| v.as_str()) {
        eprintln!("Command: {cmd}");
    }

    // Extract domains/URLs from findings evidence
    let mut domains: Vec<String> = Vec::new();
    if let Some(findings) = val.get("findings").and_then(|v| v.as_array()) {
        for finding in findings {
            if let Some(title) = finding.get("title").and_then(|v| v.as_str()) {
                eprintln!("  - {title}");
            }
            if let Some(evidence) = finding.get("evidence").and_then(|v| v.as_array()) {
                for ev in evidence {
                    // Extract URL evidence
                    if let Some(raw) = ev.get("raw").and_then(|v| v.as_str()) {
                        if let Some(host) = extract_host(raw) {
                            if !domains.contains(&host) {
                                domains.push(host);
                            }
                        }
                    }
                    // Extract host comparison
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

    // Collect rule IDs from the trigger
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
                add(domain, None, None, "user");
            }
            "r" | "rule" => {
                // Trust for the specific rule(s) that triggered
                if rule_ids.is_empty() {
                    eprintln!("tirith: no rule IDs in last trigger, adding global trust");
                    add(domain, None, None, "user");
                } else {
                    for rid in &rule_ids {
                        add(domain, Some(rid), None, "user");
                    }
                }
            }
            "t" | "temp" | "temporary" => {
                add(domain, None, Some("7d"), "user");
            }
            _ => {
                eprintln!("tirith: skipped {domain}");
            }
        }
    }

    0
}

/// `tirith trust gc [--scope user|repo|all]`
pub fn gc(scope: &str) -> i32 {
    // Validate scope early
    if !matches!(scope, "user" | "repo" | "all") {
        eprintln!("tirith: trust gc: unknown scope '{scope}' (use 'user', 'repo', or 'all')");
        return 1;
    }

    let scopes: Vec<&str> = match scope {
        "all" => vec!["user", "repo"],
        s => vec![s],
    };

    let mut total_removed = 0;

    for s in scopes {
        let path = match trust_store_path(s) {
            Ok(p) => p,
            Err(e) => {
                if scope != "all" {
                    print_trust_error("gc", &e, None);
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
                eprintln!("tirith: trust gc: {e}");
                return 1;
            }
        };
        let before = store.entries.len();
        store.entries.retain(|entry| !is_expired(entry));
        let removed = before - store.entries.len();

        if removed > 0 {
            if let Err(e) = write_store(&path, &store) {
                eprintln!("tirith: trust gc: {e}");
                return 1;
            }
            eprintln!("tirith: gc: removed {removed} expired entries from {s} scope");
        }

        total_removed += removed;
    }

    if total_removed == 0 {
        eprintln!("tirith: gc: no expired entries found");
    }

    0
}

/// Extract a hostname from a URL string for trust prompts.
fn extract_host(raw: &str) -> Option<String> {
    // Try full URL parse first -- only trust result if the input has a scheme
    if raw.contains("://") {
        if let Ok(parsed) = url::Url::parse(raw) {
            return parsed.host_str().map(String::from);
        }
    }
    // Fallback for schemeless: take everything before the first /
    let candidate = raw.split('/').next()?;
    let candidate = candidate.trim();
    if candidate.contains('.') && !candidate.contains(' ') {
        // Strip port if present
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
    fn test_is_expired_no_ttl() {
        let entry = TrustEntry {
            pattern: "example.com".to_string(),
            rule_id: None,
            ttl_expires: None,
            added: chrono::Utc::now().to_rfc3339(),
            source: "cli".to_string(),
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
            }],
        };

        write_store(&path, &store).unwrap();
        let loaded = load_store(&path).unwrap();

        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].pattern, "example.com");
        assert_eq!(loaded.entries[0].rule_id.as_deref(), Some("shortened_url"));
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
                },
                TrustEntry {
                    pattern: "valid.com".to_string(),
                    rule_id: None,
                    ttl_expires: Some(future.to_rfc3339()),
                    added: chrono::Utc::now().to_rfc3339(),
                    source: "cli".to_string(),
                },
                TrustEntry {
                    pattern: "forever.com".to_string(),
                    rule_id: None,
                    ttl_expires: None,
                    added: chrono::Utc::now().to_rfc3339(),
                    source: "cli".to_string(),
                },
            ],
        };

        write_store(&path, &store).unwrap();

        // Simulate GC
        let mut loaded = load_store(&path).unwrap();
        loaded.entries.retain(|e| !is_expired(e));
        write_store(&path, &loaded).unwrap();

        let after = load_store(&path).unwrap();
        assert_eq!(after.entries.len(), 2);
        assert!(after.entries.iter().any(|e| e.pattern == "valid.com"));
        assert!(after.entries.iter().any(|e| e.pattern == "forever.com"));
        assert!(!after.entries.iter().any(|e| e.pattern == "expired.com"));
    }
}
