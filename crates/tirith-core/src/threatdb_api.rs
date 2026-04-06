use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::extract;
use crate::parse::UrlLike;
use crate::policy::{self, ThreatIntelConfig};
use crate::rules::threatintel;
use crate::threatdb::{Confidence, Ecosystem};
use crate::tokenize::ShellType;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

const CACHE_TTL_SECS: u64 = 3600;
const KEV_CACHE_TTL_SECS: u64 = 24 * 3600;
const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Debug, Clone, Copy)]
pub enum RuntimeThreatMode {
    Inline,
    Daemon,
}

impl RuntimeThreatMode {
    pub fn timeout(self) -> Duration {
        match self {
            RuntimeThreatMode::Inline => Duration::from_millis(500),
            RuntimeThreatMode::Daemon => Duration::from_secs(5),
        }
    }
}

pub fn enrich_command(
    input: &str,
    shell: ShellType,
    config: &ThreatIntelConfig,
    mode: RuntimeThreatMode,
) -> Vec<Finding> {
    if !config.osv_enabled && !config.deps_dev_enabled && config.google_safe_browsing_key.is_none()
    {
        return Vec::new();
    }

    let deadline = Instant::now() + mode.timeout();
    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    let segments = crate::tokenize::tokenize(input, shell);
    let packages = threatintel::extract_packages(&segments);
    let urls = extract::extract_urls(input, shell);

    for package in packages {
        let effective_version = if let Some(version) = package.version.clone() {
            Some(version)
        } else if config.deps_dev_enabled {
            resolve_default_version(package.ecosystem, &package.name, deadline)
        } else {
            None
        };

        if config.osv_enabled {
            if let Some(version) = effective_version.as_deref() {
                if let Some(advisories) =
                    query_osv(package.ecosystem, &package.name, version, deadline)
                {
                    if !advisories.is_empty()
                        && seen.insert(format!(
                            "osv:{}:{}:{version}",
                            package.ecosystem as u8, package.name
                        ))
                    {
                        findings.push(build_osv_finding(
                            package.ecosystem,
                            &package.name,
                            version,
                            &advisories,
                        ));
                    }

                    if let Some(kev_hit) = find_kev_alias(&advisories, deadline) {
                        if seen.insert(format!(
                            "kev:{}:{}:{kev_hit}",
                            package.ecosystem as u8, package.name
                        )) {
                            findings.push(build_kev_finding(
                                package.ecosystem,
                                &package.name,
                                version,
                                &kev_hit,
                            ));
                        }
                    }
                }
            }
        }

        if config.deps_dev_enabled {
            let metadata = collect_package_metadata(
                package.ecosystem,
                &package.name,
                effective_version.as_deref(),
                deadline,
            );
            if let Some(signal) = metadata {
                if signal.is_suspicious()
                    && seen.insert(format!(
                        "suspicious:{}:{}",
                        package.ecosystem as u8, package.name
                    ))
                {
                    findings.push(build_suspicious_package_finding(
                        package.ecosystem,
                        &package.name,
                        &signal,
                    ));
                }
            }
        }
    }

    if let Some(api_key) = config.google_safe_browsing_key.as_deref() {
        for url_info in urls {
            if let Some(url) = safe_browsing_candidate_url(&url_info.parsed, &url_info.raw) {
                if let Some(match_type) = query_safe_browsing(&url, api_key, deadline) {
                    let key = format!("safe-browsing:{url}");
                    if seen.insert(key) {
                        findings.push(Finding {
                            rule_id: RuleId::ThreatSafeBrowsing,
                            severity: Severity::High,
                            title: "Google Safe Browsing match".to_string(),
                            description: format!(
                                "URL '{}' matched Google Safe Browsing threat type '{}'.",
                                url, match_type
                            ),
                            evidence: vec![Evidence::ThreatIntel {
                                source: "Google Safe Browsing".to_string(),
                                threat_type: "safe_browsing".to_string(),
                                confidence: Confidence::Confirmed,
                                reference: Some(url.to_string()),
                            }],
                            human_view: None,
                            agent_view: None,
                            mitre_id: None,
                            custom_rule_id: None,
                        });
                    }
                }
            }
        }
    }

    findings
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheEnvelope<T> {
    fetched_at: u64,
    value: T,
}

fn cache_path(kind: &str, key: &str) -> Option<PathBuf> {
    let state = policy::state_dir()?;
    let digest = sha2::Sha256::digest(format!("{kind}:{key}").as_bytes());
    let hex: String = digest.iter().take(16).map(|b| format!("{b:02x}")).collect();
    Some(
        state
            .join("threatdb-api-cache")
            .join(format!("{kind}-{hex}.json")),
    )
}

fn load_cache<T: DeserializeOwned>(kind: &str, key: &str, ttl_secs: u64) -> Option<T> {
    let path = cache_path(kind, key)?;
    let content = std::fs::read_to_string(path).ok()?;
    let envelope: CacheEnvelope<T> = serde_json::from_str(&content).ok()?;
    if unix_now().saturating_sub(envelope.fetched_at) > ttl_secs {
        return None;
    }
    Some(envelope.value)
}

fn store_cache<T: Serialize>(kind: &str, key: &str, value: &T) {
    let Some(path) = cache_path(kind, key) else {
        return;
    };
    let Some(parent) = path.parent() else {
        return;
    };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    let envelope = CacheEnvelope {
        fetched_at: unix_now(),
        value,
    };
    let parent_owned = parent.to_path_buf();
    if let Ok(serialized) = serde_json::to_vec(&envelope) {
        let _ = std::fs::write(path, serialized);
    }
    // Opportunistic eviction: periodically purge stale cache files to prevent
    // unbounded growth. Runs at most once per process (cheap stat-only scan).
    evict_stale_cache_once(&parent_owned);
}

/// Max age for cache files before eviction (7 days).
const CACHE_EVICT_MAX_AGE_SECS: u64 = 7 * 24 * 3600;

static EVICTION_RAN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn evict_stale_cache_once(cache_dir: &std::path::Path) {
    if EVICTION_RAN.swap(true, std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let now = unix_now();
    let entries = match std::fs::read_dir(cache_dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let age = path
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| now.saturating_sub(d.as_secs()))
            .unwrap_or(0);
        if age > CACHE_EVICT_MAX_AGE_SECS {
            let _ = std::fs::remove_file(&path);
        }
    }
}

fn remaining_timeout(deadline: Instant) -> Option<Duration> {
    deadline.checked_duration_since(Instant::now())
}

fn build_client(deadline: Instant) -> Option<reqwest::blocking::Client> {
    let timeout = remaining_timeout(deadline)?;
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .ok()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    references: Vec<OsvReference>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct OsvReference {
    url: String,
}

fn query_osv(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    deadline: Instant,
) -> Option<Vec<OsvVuln>> {
    let cache_key = format!("{}:{name}:{version}", ecosystem_label(ecosystem)?);
    if let Some(response) = load_cache::<OsvQueryResponse>("osv", &cache_key, CACHE_TTL_SECS) {
        return Some(response.vulns);
    }

    let client = build_client(deadline)?;
    let ecosystem_name = osv_ecosystem_name(ecosystem)?;
    let body = serde_json::json!({
        "package": {
            "name": name,
            "ecosystem": ecosystem_name,
        },
        "version": version,
    });

    let response = client
        .post("https://api.osv.dev/v1/query")
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .ok()?
        .error_for_status()
        .ok()?
        .json::<OsvQueryResponse>()
        .ok()?;

    store_cache("osv", &cache_key, &response);
    Some(response.vulns)
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct DepsPackageResponse {
    #[serde(default)]
    versions: Vec<DepsPackageVersion>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct DepsPackageVersion {
    #[serde(rename = "versionKey")]
    version_key: DepsVersionKey,
    #[serde(default, rename = "publishedAt")]
    published_at: Option<String>,
    #[serde(default, rename = "isDefault")]
    is_default: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct DepsVersionKey {
    version: String,
}

fn deps_package(
    ecosystem: Ecosystem,
    name: &str,
    deadline: Instant,
) -> Option<DepsPackageResponse> {
    let system = deps_system_name(ecosystem)?;
    let encoded = utf8_percent_encode(name, NON_ALPHANUMERIC).to_string();
    let cache_key = format!("{system}:{encoded}");
    if let Some(response) =
        load_cache::<DepsPackageResponse>("deps-package", &cache_key, CACHE_TTL_SECS)
    {
        return Some(response);
    }

    let client = build_client(deadline)?;
    let response = client
        .get(format!(
            "https://api.deps.dev/v3/systems/{system}/packages/{encoded}"
        ))
        .send()
        .ok()?
        .error_for_status()
        .ok()?
        .json::<DepsPackageResponse>()
        .ok()?;
    store_cache("deps-package", &cache_key, &response);
    Some(response)
}

fn resolve_default_version(ecosystem: Ecosystem, name: &str, deadline: Instant) -> Option<String> {
    deps_package(ecosystem, name, deadline)?
        .versions
        .into_iter()
        .find(|version| version.is_default)
        .map(|version| version.version_key.version)
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct EcosystemsPackageResponse {
    #[serde(default)]
    maintainers: Vec<EcosystemsMaintainer>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct EcosystemsMaintainer {
    login: String,
}

fn ecosystems_package(
    ecosystem: Ecosystem,
    name: &str,
    deadline: Instant,
) -> Option<EcosystemsPackageResponse> {
    let registry = ecosystems_registry_name(ecosystem)?;
    let encoded = utf8_percent_encode(name, NON_ALPHANUMERIC).to_string();
    let cache_key = format!("{registry}:{encoded}");
    if let Some(response) =
        load_cache::<EcosystemsPackageResponse>("ecosystems-package", &cache_key, CACHE_TTL_SECS)
    {
        return Some(response);
    }

    let client = build_client(deadline)?;
    let response = client
        .get(format!(
            "https://packages.ecosyste.ms/api/v1/registries/{registry}/packages/{encoded}"
        ))
        .send()
        .ok()?
        .error_for_status()
        .ok()?
        .json::<EcosystemsPackageResponse>()
        .ok()?;
    store_cache("ecosystems-package", &cache_key, &response);
    Some(response)
}

#[derive(Debug, Clone)]
struct SuspiciousPackageSignal {
    first_release_days: Option<i64>,
    maintainers: Option<usize>,
}

impl SuspiciousPackageSignal {
    fn is_suspicious(&self) -> bool {
        self.first_release_days.is_some_and(|days| days <= 30)
            || self.maintainers.is_some_and(|count| count <= 1)
    }
}

fn collect_package_metadata(
    ecosystem: Ecosystem,
    name: &str,
    _version: Option<&str>,
    deadline: Instant,
) -> Option<SuspiciousPackageSignal> {
    let deps = deps_package(ecosystem, name, deadline);
    let first_release_days = deps.as_ref().and_then(|response| {
        response
            .versions
            .iter()
            .filter_map(|version| version.published_at.as_deref())
            .filter_map(parse_rfc3339_secs)
            .min()
            .map(|first_seen| {
                let now = unix_now() as i64;
                ((now - first_seen).max(0)) / 86_400
            })
    });

    let maintainers =
        ecosystems_package(ecosystem, name, deadline).map(|package| package.maintainers.len());
    if first_release_days.is_none() && maintainers.is_none() {
        return None;
    }

    Some(SuspiciousPackageSignal {
        first_release_days,
        maintainers,
    })
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct KevCatalog {
    #[serde(default)]
    vulnerabilities: Vec<KevVulnerability>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct KevVulnerability {
    #[serde(default, alias = "cveID")]
    cve_id: String,
}

fn kev_aliases(deadline: Instant) -> Option<HashSet<String>> {
    if let Some(cached) = load_cache::<Vec<String>>("kev", "active", KEV_CACHE_TTL_SECS) {
        return Some(cached.into_iter().collect());
    }
    let client = build_client(deadline)?;
    let response = client
        .get(KEV_URL)
        .send()
        .ok()?
        .error_for_status()
        .ok()?
        .json::<KevCatalog>()
        .ok()?;
    let aliases: Vec<String> = response
        .vulnerabilities
        .into_iter()
        .map(|vuln| vuln.cve_id)
        .filter(|id| !id.is_empty())
        .collect();
    store_cache("kev", "active", &aliases);
    Some(aliases.into_iter().collect())
}

fn find_kev_alias(advisories: &[OsvVuln], deadline: Instant) -> Option<String> {
    let kev = kev_aliases(deadline)?;
    advisories
        .iter()
        .flat_map(|advisory| advisory.aliases.iter().chain(std::iter::once(&advisory.id)))
        .find(|alias| kev.contains(*alias))
        .cloned()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SafeBrowsingResponse {
    #[serde(default)]
    matches: Vec<SafeBrowsingMatch>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SafeBrowsingMatch {
    #[serde(default, rename = "threatType")]
    threat_type: String,
}

fn query_safe_browsing(url: &str, api_key: &str, deadline: Instant) -> Option<String> {
    let cache_key = url.to_string();
    if let Some(response) =
        load_cache::<SafeBrowsingResponse>("safe-browsing", &cache_key, CACHE_TTL_SECS)
    {
        return response.matches.first().map(|m| m.threat_type.clone());
    }

    let client = build_client(deadline)?;
    let body = serde_json::json!({
        "client": {
            "clientId": "tirith",
            "clientVersion": env!("CARGO_PKG_VERSION"),
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{ "url": url }],
        },
    });

    let response = client
        .post("https://safebrowsing.googleapis.com/v4/threatMatches:find")
        .header("x-goog-api-key", api_key)
        .json(&body)
        .send()
        .ok()?
        .error_for_status()
        .ok()?
        .json::<SafeBrowsingResponse>()
        .ok()?;
    store_cache("safe-browsing", &cache_key, &response);
    response.matches.first().map(|m| m.threat_type.clone())
}

fn build_osv_finding(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    advisories: &[OsvVuln],
) -> Finding {
    let ids: Vec<String> = advisories
        .iter()
        .take(3)
        .map(|advisory| advisory.id.clone())
        .collect();
    let reference = advisories
        .iter()
        .flat_map(|advisory| advisory.references.iter())
        .map(|reference| reference.url.clone())
        .next()
        .or_else(|| {
            advisories
                .first()
                .map(|advisory| format!("https://osv.dev/vulnerability/{}", advisory.id))
        });
    Finding {
        rule_id: RuleId::ThreatOsvVulnerable,
        severity: Severity::High,
        title: format!("Package has live OSV advisory data: {name}@{version}"),
        description: format!(
            "Package '{}' in {} version '{}' matched {} OSV advisory record(s): {}.",
            name,
            ecosystem,
            version,
            advisories.len(),
            ids.join(", ")
        ),
        evidence: vec![Evidence::ThreatIntel {
            source: "OSV.dev".to_string(),
            threat_type: "vulnerable_package".to_string(),
            confidence: Confidence::Confirmed,
            reference,
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

fn build_kev_finding(ecosystem: Ecosystem, name: &str, version: &str, cve_id: &str) -> Finding {
    Finding {
        rule_id: RuleId::ThreatCisaKev,
        severity: Severity::High,
        title: format!("Package advisory is in CISA KEV: {name}@{version}"),
        description: format!(
            "Package '{}' in {} version '{}' is associated with actively exploited CVE '{}'.",
            name, ecosystem, version, cve_id
        ),
        evidence: vec![Evidence::ThreatIntel {
            source: "CISA KEV via OSV.dev".to_string(),
            threat_type: "actively_exploited_vulnerability".to_string(),
            confidence: Confidence::Confirmed,
            reference: Some(format!("https://www.cve.org/CVERecord?id={cve_id}")),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

fn build_suspicious_package_finding(
    ecosystem: Ecosystem,
    name: &str,
    signal: &SuspiciousPackageSignal,
) -> Finding {
    let mut parts = Vec::new();
    if let Some(days) = signal.first_release_days {
        parts.push(format!("first release {} day(s) ago", days));
    }
    if let Some(maintainers) = signal.maintainers {
        parts.push(format!("{} maintainer(s)", maintainers));
    }

    Finding {
        rule_id: RuleId::ThreatSuspiciousPackage,
        severity: Severity::Low,
        title: format!("Package has weak ecosystem health signals: {name}"),
        description: format!(
            "Package '{}' in {} has suspicious ecosystem health signals ({}).",
            name,
            ecosystem,
            parts.join(", ")
        ),
        evidence: vec![Evidence::ThreatIntel {
            source: "deps.dev + ecosyste.ms".to_string(),
            threat_type: "suspicious_package".to_string(),
            confidence: Confidence::Low,
            reference: None,
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

fn parse_rfc3339_secs(raw: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|dt| dt.timestamp())
}

fn safe_browsing_candidate_url(parsed: &UrlLike, raw: &str) -> Option<String> {
    match parsed {
        UrlLike::Standard { parsed, .. } if matches!(parsed.scheme(), "http" | "https") => {
            Some(parsed.as_str().to_string())
        }
        UrlLike::Unparsed { .. } if raw.starts_with("http://") || raw.starts_with("https://") => {
            Some(raw.to_string())
        }
        _ => None,
    }
}

fn ecosystem_label(ecosystem: Ecosystem) -> Option<&'static str> {
    match ecosystem {
        Ecosystem::Npm => Some("npm"),
        Ecosystem::PyPI => Some("pypi"),
        Ecosystem::RubyGems => Some("rubygems"),
        Ecosystem::Crates => Some("cargo"),
        Ecosystem::Go => Some("go"),
        Ecosystem::Maven => Some("maven"),
        Ecosystem::NuGet => Some("nuget"),
        Ecosystem::Packagist => Some("packagist"),
    }
}

fn osv_ecosystem_name(ecosystem: Ecosystem) -> Option<&'static str> {
    match ecosystem {
        Ecosystem::Npm => Some("npm"),
        Ecosystem::PyPI => Some("PyPI"),
        Ecosystem::RubyGems => Some("RubyGems"),
        Ecosystem::Crates => Some("crates.io"),
        Ecosystem::Go => Some("Go"),
        Ecosystem::Maven => Some("Maven"),
        Ecosystem::NuGet => Some("NuGet"),
        Ecosystem::Packagist => Some("Packagist"),
    }
}

fn deps_system_name(ecosystem: Ecosystem) -> Option<&'static str> {
    match ecosystem {
        Ecosystem::Npm => Some("npm"),
        Ecosystem::PyPI => Some("pypi"),
        Ecosystem::RubyGems => Some("rubygems"),
        Ecosystem::Crates => Some("cargo"),
        Ecosystem::Go => Some("go"),
        Ecosystem::Maven => Some("maven"),
        Ecosystem::NuGet => Some("nuget"),
        Ecosystem::Packagist => None,
    }
}

fn ecosystems_registry_name(ecosystem: Ecosystem) -> Option<&'static str> {
    match ecosystem {
        Ecosystem::Npm => Some("npmjs.org"),
        Ecosystem::PyPI => Some("pypi.org"),
        Ecosystem::RubyGems => Some("rubygems.org"),
        Ecosystem::Crates => Some("crates.io"),
        Ecosystem::Go => None,
        Ecosystem::Maven => None,
        Ecosystem::NuGet => Some("nuget.org"),
        Ecosystem::Packagist => Some("packagist.org"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    #[test]
    fn safe_browsing_filter_only_accepts_http_urls() {
        let parsed = UrlLike::Standard {
            parsed: Url::parse("https://example.com/login").expect("url"),
            raw_host: "example.com".to_string(),
        };
        assert_eq!(
            safe_browsing_candidate_url(&parsed, "https://example.com/login"),
            Some("https://example.com/login".to_string())
        );

        let unparsed = UrlLike::Unparsed {
            raw: "http://phish.example".to_string(),
            raw_host: Some("phish.example".to_string()),
            raw_path: None,
        };
        assert_eq!(
            safe_browsing_candidate_url(&unparsed, "http://phish.example"),
            Some("http://phish.example".to_string())
        );

        let docker = UrlLike::DockerRef {
            registry: Some("ghcr.io".to_string()),
            image: "owner/image".to_string(),
            tag: Some("latest".to_string()),
            digest: None,
        };
        assert_eq!(
            safe_browsing_candidate_url(&docker, "ghcr.io/owner/image"),
            None
        );

        let scp = UrlLike::Scp {
            user: Some("git".to_string()),
            host: "github.com".to_string(),
            path: "owner/repo.git".to_string(),
        };
        assert_eq!(
            safe_browsing_candidate_url(&scp, "git@github.com:owner/repo.git"),
            None
        );
    }

    #[test]
    fn enrich_command_returns_empty_when_all_apis_disabled() {
        let config = ThreatIntelConfig {
            osv_enabled: false,
            deps_dev_enabled: false,
            google_safe_browsing_key: None,
            ..ThreatIntelConfig::default()
        };
        let findings = enrich_command(
            "pip install requests==2.31.0",
            crate::tokenize::ShellType::Posix,
            &config,
            RuntimeThreatMode::Inline,
        );
        assert!(
            findings.is_empty(),
            "should return empty when all APIs are disabled"
        );
    }
}
