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

/// Per-analysis caps on remote enrichment work (repo-0348): an attacker can
/// stuff arbitrary package/URL values into a command, but each analysis may
/// only spend this many unique lookups of paid/quota APIs and cache files.
const MAX_ENRICH_PACKAGES: usize = 32;
const MAX_ENRICH_URLS: usize = 64;
/// Response body caps (repo-0347): bodies are streamed through a bounded
/// reader BEFORE deserialization so a hostile or compromised upstream cannot
/// force unbounded allocation.
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
const KEV_MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
/// Decoded-collection caps applied after parsing (repo-0347).
const MAX_DECODED_ITEMS: usize = 4096;
/// Persistent cache bounds (repo-0348): eviction is age-based AND size-based —
/// oldest entries are removed once either bound is exceeded.
const MAX_CACHE_ENTRIES: usize = 512;
const MAX_CACHE_BYTES: u64 = 32 * 1024 * 1024;
/// Safe Browsing batches this many URL entries per request (API limit 500).
const GSB_BATCH_SIZE: usize = 450;

/// Read a JSON response body through a `limit + 1` bounded reader and only
/// then deserialize. A missing or dishonest Content-Length cannot bypass the
/// streaming cap.
fn read_json_bounded<T: DeserializeOwned>(
    resp: reqwest::blocking::Response,
    max_bytes: u64,
) -> Option<T> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes {
            return None;
        }
    }
    use std::io::Read as _;
    let mut buf = Vec::new();
    resp.take(max_bytes + 1).read_to_end(&mut buf).ok()?;
    if buf.len() as u64 > max_bytes {
        return None;
    }
    serde_json::from_slice(&buf).ok()
}

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
    // `extract_packages_detail_for_shell`, not the bare variant: the detail form
    // exists precisely so a consumer whose output is a security decision can see
    // that the package list was cut. Discarding it made a runtime verdict read
    // as a complete assessment of a command it had only partly looked at.
    let extracted = threatintel::extract_packages_detail_for_shell(&segments, shell);
    let extraction_truncated = extracted.truncated;
    let packages = extracted.packages;
    let urls = extract::extract_urls(input, shell);

    // Deduplicate BEFORE the cap. Capping the raw list first let repeats
    // consume the budget, so a command padded with duplicates pushed a real
    // candidate out of the window without ever being looked up.
    let mut queried_packages: HashSet<(u8, String)> = HashSet::new();
    let deduplicated_packages: Vec<_> = packages
        .into_iter()
        .filter(|package| queried_packages.insert((package.ecosystem as u8, package.name.clone())))
        .collect();
    // A second, independent cut. The extraction cap above is the grammar's; this
    // one is the lookup budget, and it was equally silent.
    let package_budget_truncated = deduplicated_packages.len() > MAX_ENRICH_PACKAGES;
    let packages_by_first_use: Vec<_> = deduplicated_packages
        .into_iter()
        .take(MAX_ENRICH_PACKAGES)
        .collect();
    for package in packages_by_first_use {
        // Only a CONCRETE version (Exact/Resolved) is a valid OSV `version`; a range
        // or constraint must NOT be sent as one (OSV would treat the range text as a
        // literal version, degrading matching and skipping deps.dev fallback). A
        // non-concrete intent falls through to resolution instead.
        let effective_version = if let Some(version) = package.version.exact_version() {
            Some(version.to_string())
        } else if config.deps_dev_enabled {
            match &package.version {
                // A range/constraint: substituting the registry's default
                // version is only sound when that version verifiably satisfies
                // the requested constraint — otherwise `foo<2` would be
                // checked as `foo@3` and a relevant advisory suppressed.
                crate::version_intent::VersionIntent::Constraint { parsed, raw } => {
                    let resolved =
                        resolve_default_version(package.ecosystem, &package.name, deadline);
                    let satisfies = match (parsed, resolved.as_deref()) {
                        (Some(constraint), Some(candidate)) => {
                            crate::version_intent::ReleaseVersion::parse(candidate)
                                .map(|rv| constraint.matches(&rv))
                                .unwrap_or(false)
                        }
                        _ => false,
                    };
                    if satisfies {
                        resolved
                    } else if resolved.is_some() {
                        // A concrete default WAS resolved and it does not satisfy
                        // the requested range (the registry's current default is
                        // older than the requested floor, say). Deterministic and
                        // independent of order, so it stays a finding.
                        if seen.insert(format!(
                            "unresolved:{}:{}",
                            package.ecosystem as u8, package.name
                        )) {
                            findings.push(Finding {
                                rule_id: RuleId::ThreatUnresolvedMaliciousPackage,
                                severity: Severity::Medium,
                                title: "Version constraint could not be verified".to_string(),
                                description: format!(
                                    "Package '{}' is requested with version constraint '{}', and \
                                     the registry's concrete default version does not satisfy it, \
                                     so OSV/KEV correlation could not be performed against a \
                                     constraint-satisfying version.",
                                    package.name, raw
                                ),
                                evidence: vec![Evidence::ThreatIntel {
                                    source: "version-resolution".to_string(),
                                    threat_type: "unresolved_constraint".to_string(),
                                    confidence: Confidence::Medium,
                                    reference: None,
                                }],
                                human_view: None,
                                agent_view: None,
                                mitre_id: None,
                                custom_rule_id: None,
                            });
                        }
                        None
                    } else {
                        // Resolution did not complete (the shared deadline was
                        // spent on earlier packages, the network was down, or the
                        // registry stayed silent). This is not evidence of a
                        // threat and must not be labelled as a malicious package
                        // nor block the command; it is an honest "could not
                        // verify this constraint within the budget". Kept at the
                        // same Medium severity the old finding used, so the
                        // action is unchanged, but the framing no longer implies
                        // the package is malicious.
                        if seen.insert(format!(
                            "unverified:{}:{}",
                            package.ecosystem as u8, package.name
                        )) {
                            findings.push(Finding {
                                rule_id: RuleId::AnalysisIncomplete,
                                severity: Severity::Medium,
                                title: "Version constraint could not be verified within the budget"
                                    .to_string(),
                                description: format!(
                                    "Package '{}' is requested with version constraint '{}', but \
                                     tirith could not resolve it to a concrete version within the \
                                     enrichment time budget, so OSV/KEV correlation was not \
                                     performed for it. This is an incomplete check, not a threat \
                                     signal; run the install for this package on its own to have \
                                     it fully assessed.",
                                    package.name, raw
                                ),
                                evidence: vec![Evidence::ThreatIntel {
                                    source: "version-resolution".to_string(),
                                    threat_type: "resolution_incomplete".to_string(),
                                    confidence: Confidence::Low,
                                    reference: None,
                                }],
                                human_view: None,
                                agent_view: None,
                                mitre_id: None,
                                custom_rule_id: None,
                            });
                        }
                        None
                    }
                }
                // No version requested at all: the resolver will install the
                // registry's current default, so checking that version is sound.
                _ => resolve_default_version(package.ecosystem, &package.name, deadline),
            }
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

    let mut url_budget_truncated = false;
    if let Some(api_key) = config.google_safe_browsing_key.as_deref() {
        // Privacy scrub BEFORE anything is transmitted or cached: userinfo,
        // query (presigned tokens, reset links, bearer params), and fragments
        // never leave the process, and private/credential-bearing URLs are not
        // sent to a third party at all (repo-0346). Scrubbed URLs are also
        // deduplicated, capped, and batched into as few requests as possible
        // (repo-0348).
        let mut candidates: Vec<String> = Vec::new();
        let mut candidate_set: HashSet<String> = HashSet::new();
        let dns_resolver = crate::network::SystemDnsResolver::new().ok();
        // DNS classification shares the enrichment deadline and one lookup per
        // candidate at most. If system DNS is unavailable or time is exhausted,
        // dotted hostnames fail closed and are not disclosed to Google.
        let mut dns_budget =
            crate::network::DnsRequestBudget::new(deadline, MAX_ENRICH_URLS, MAX_ENRICH_URLS);
        // Same ordering as the package budget: the cap counts candidates that
        // will actually be looked up, so repeats cannot displace a distinct URL.
        for url_info in urls {
            if candidates.len() >= MAX_ENRICH_URLS {
                // Third silent cut, same class as the two package caps.
                url_budget_truncated = true;
                break;
            }
            if let Some(url) = safe_browsing_candidate_url(
                &url_info.parsed,
                &url_info.raw,
                dns_resolver
                    .as_ref()
                    .map(|resolver| resolver as &dyn crate::network::DnsResolver),
                &mut dns_budget,
            ) {
                if candidate_set.insert(url.clone()) {
                    candidates.push(url);
                }
            }
        }
        for batch in candidates.chunks(GSB_BATCH_SIZE) {
            for (url, match_type) in query_safe_browsing_batch(batch, api_key, deadline) {
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

    // Any cut above means this enrichment did not see the whole command. Say so
    // rather than returning a list that reads as a complete assessment: the
    // static rule path already discloses its own cap through
    // `RuleId::AnalysisIncomplete`, and the runtime path silently did not.
    //
    // Inserted at the FRONT for the same reason the MCP projections sort
    // completeness findings first: the presentation bound drops the tail, and
    // the caveat is the last thing that should be dropped.
    if let Some(finding) = incomplete_enrichment_finding(
        extraction_truncated,
        package_budget_truncated,
        url_budget_truncated,
    ) {
        findings.insert(0, finding);
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
    let hex: String = hex::encode(&digest[..16]);
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
    // Opportunistic eviction (once per process) to bound cache growth.
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
    let mut live: Vec<(std::path::PathBuf, std::time::SystemTime, u64)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let (modified, len) = match path
            .metadata()
            .and_then(|m| m.modified().map(|t| (t, m.len())))
        {
            Ok(v) => v,
            Err(_) => continue,
        };
        let age = modified
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| now.saturating_sub(d.as_secs()))
            .unwrap_or(0);
        if age > CACHE_EVICT_MAX_AGE_SECS {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        live.push((path, modified, len));
    }

    // Bounded-size LRU: age-only eviction lets an attacker stuffing fresh
    // cache keys grow the directory without limit, so also enforce entry-count
    // and total-byte bounds, evicting oldest-first.
    live.sort_by_key(|(_, modified, _)| *modified);
    let mut total_bytes: u64 = live.iter().map(|(_, _, len)| *len).sum();
    let mut count = live.len();
    for (path, _, len) in &live {
        if count <= MAX_CACHE_ENTRIES && total_bytes <= MAX_CACHE_BYTES {
            break;
        }
        if std::fs::remove_file(path).is_ok() {
            count -= 1;
            total_bytes = total_bytes.saturating_sub(*len);
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

    let mut response: OsvQueryResponse = read_json_bounded(
        client
            .post("https://api.osv.dev/v1/query")
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .ok()?
            .error_for_status()
            .ok()?,
        MAX_RESPONSE_BYTES,
    )?;
    response.vulns.truncate(MAX_DECODED_ITEMS);
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
    let mut response: DepsPackageResponse = read_json_bounded(
        client
            .get(format!(
                "https://api.deps.dev/v3/systems/{system}/packages/{encoded}"
            ))
            .send()
            .ok()?
            .error_for_status()
            .ok()?,
        MAX_RESPONSE_BYTES,
    )?;
    response.versions.truncate(MAX_DECODED_ITEMS);
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
    let mut response: EcosystemsPackageResponse = read_json_bounded(
        client
            .get(format!(
                "https://packages.ecosyste.ms/api/v1/registries/{registry}/packages/{encoded}"
            ))
            .send()
            .ok()?
            .error_for_status()
            .ok()?,
        MAX_RESPONSE_BYTES,
    )?;
    response.maintainers.truncate(MAX_DECODED_ITEMS);
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
    let response: KevCatalog = read_json_bounded(
        client.get(KEV_URL).send().ok()?.error_for_status().ok()?,
        KEV_MAX_RESPONSE_BYTES,
    )?;
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
    #[serde(default, rename = "threatEntry")]
    threat_entry: SafeBrowsingThreatEntry,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
struct SafeBrowsingThreatEntry {
    #[serde(default)]
    url: String,
}

/// Batch form of the Safe Browsing lookup (repo-0348): one request carries
/// the whole chunk of scrubbed candidate URLs instead of one request per URL.
/// Returns `(url, threat_type)` for every matched entry. Per-URL results are
/// cached individually; a full cache hit avoids the network entirely.
fn query_safe_browsing_batch(
    urls: &[String],
    api_key: &str,
    deadline: Instant,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut missing: Vec<&str> = Vec::new();
    for url in urls {
        if let Some(response) =
            load_cache::<SafeBrowsingResponse>("safe-browsing", url, CACHE_TTL_SECS)
        {
            if let Some(m) = response.matches.first() {
                out.push((url.clone(), m.threat_type.clone()));
            }
        } else {
            missing.push(url);
        }
    }
    if missing.is_empty() {
        return out;
    }

    let Some(client) = build_client(deadline) else {
        return out;
    };
    let entries: Vec<serde_json::Value> = missing
        .iter()
        .map(|url| serde_json::json!({ "url": url }))
        .collect();
    let body = serde_json::json!({
        "client": {
            "clientId": "tirith",
            "clientVersion": env!("CARGO_PKG_VERSION"),
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": entries,
        },
    });

    let Some(response) = client
        .post("https://safebrowsing.googleapis.com/v4/threatMatches:find")
        .header("x-goog-api-key", api_key)
        .json(&body)
        .send()
        .ok()
        .and_then(|r| r.error_for_status().ok())
    else {
        return out;
    };
    let Some(parsed) = read_json_bounded::<SafeBrowsingResponse>(response, MAX_RESPONSE_BYTES)
    else {
        return out;
    };
    out.extend(cache_successful_safe_browsing_batch(&missing, parsed));
    out
}

/// Persist every outcome from one successfully parsed Safe Browsing response.
/// The API omits clean entries, so each requested URL not present in a complete,
/// fully mappable `matches` response receives an authenticated empty cache
/// envelope. Transport, status, parse, truncation, or response-mapping failures
/// are never cached as clean.
fn cache_successful_safe_browsing_batch(
    requested: &[&str],
    mut parsed: SafeBrowsingResponse,
) -> Vec<(String, String)> {
    // If the decoded match list exceeds our cap, omitted entries are unknown,
    // not confirmed clean. Positive entries within the cap remain actionable,
    // but no negative cache entry may be synthesized from an incomplete view.
    let response_complete = parsed.matches.len() <= MAX_DECODED_ITEMS;
    parsed.matches.truncate(MAX_DECODED_ITEMS);
    let requested_set: HashSet<&str> = requested.iter().copied().collect();
    let mut by_url: std::collections::HashMap<String, Vec<SafeBrowsingMatch>> =
        std::collections::HashMap::new();
    let mut response_mappable = true;
    for matched in parsed.matches {
        let url = matched.threat_entry.url.clone();
        // A compromised/malformed response cannot plant cache entries for URLs
        // that were absent from this authenticated request batch.
        if requested_set.contains(url.as_str()) {
            by_url.entry(url).or_default().push(matched);
        } else {
            response_mappable = false;
        }
    }

    let mut out = Vec::new();
    for &url in requested {
        let single = SafeBrowsingResponse {
            matches: by_url.remove(url).unwrap_or_default(),
        };
        if let Some(matched) = single.matches.first() {
            out.push((url.to_string(), matched.threat_type.clone()));
            store_cache("safe-browsing", url, &single);
        } else if response_complete && response_mappable {
            store_cache("safe-browsing", url, &single);
        }
    }
    out
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

/// Disclose that runtime enrichment did not look at the whole command.
///
/// Three independent caps can cut what gets assessed, and each one used to be
/// silent: the extraction grammar's `MAX_PACKAGES_PER_INVOCATION`, the package
/// lookup budget `MAX_ENRICH_PACKAGES`, and the URL lookup budget
/// `MAX_ENRICH_URLS`. Returns `None` when nothing was cut, so a complete
/// analysis carries no extra finding.
fn incomplete_enrichment_finding(
    extraction_truncated: bool,
    package_budget_truncated: bool,
    url_budget_truncated: bool,
) -> Option<Finding> {
    let mut reasons: Vec<String> = Vec::new();
    if extraction_truncated {
        reasons.push(format!(
            "the command names more than {} distinct packages in one invocation, so package \
             extraction stopped at that cap",
            crate::npm_command::MAX_PACKAGES_PER_INVOCATION
        ));
    }
    if package_budget_truncated {
        reasons.push(format!(
            "more than {MAX_ENRICH_PACKAGES} distinct packages were named, so only the first \
             {MAX_ENRICH_PACKAGES} were looked up against live threat intelligence"
        ));
    }
    if url_budget_truncated {
        reasons.push(format!(
            "more than {MAX_ENRICH_URLS} distinct URLs were named, so only the first \
             {MAX_ENRICH_URLS} were checked against Safe Browsing"
        ));
    }
    if reasons.is_empty() {
        return None;
    }
    Some(Finding {
        rule_id: RuleId::AnalysisIncomplete,
        severity: Severity::High,
        title: "Threat-intelligence enrichment did not cover the whole command".to_string(),
        description: format!(
            "Tirith could not assess every candidate this command names: {}. The remainder was \
             never looked up, so this result is reported as incompletely analyzed rather than \
             clean. Split the command into smaller invocations to have everything assessed.",
            reasons.join("; ")
        ),
        evidence: vec![Evidence::CommandPattern {
            pattern: "bounded threat-intelligence enrichment budget exhausted".to_string(),
            matched: "candidates omitted after the enrichment cap".to_string(),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    })
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

fn safe_browsing_candidate_url(
    parsed: &UrlLike,
    raw: &str,
    resolver: Option<&dyn crate::network::DnsResolver>,
    dns_budget: &mut crate::network::DnsRequestBudget,
) -> Option<String> {
    let candidate = match parsed {
        UrlLike::Standard { parsed, .. } if matches!(parsed.scheme(), "http" | "https") => {
            parsed.as_str()
        }
        UrlLike::Unparsed { .. } if raw.starts_with("http://") || raw.starts_with("https://") => {
            raw
        }
        _ => return None,
    };
    privacy_scrub_url(candidate, resolver, dns_budget)
}

/// Reduce a URL to the minimum form Safe Browsing can evaluate, and refuse
/// URLs that must never leave the machine (repo-0346):
///
///  * userinfo, path, query string, and fragment are stripped — presigned URLs,
///    password-reset links, route identifiers, and bearer tokens must not be
///    transmitted to a third party (or persisted in the on-disk cache);
///  * private, loopback, link-local, and otherwise non-public destinations
///    are excluded, including dotted split-DNS names that resolve to any
///    non-public address;
///  * anything that does not parse as an http(s) URL is excluded.
fn privacy_scrub_url(
    raw: &str,
    resolver: Option<&dyn crate::network::DnsResolver>,
    dns_budget: &mut crate::network::DnsRequestBudget,
) -> Option<String> {
    let mut parsed = url::Url::parse(raw).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_query(None);
    parsed.set_fragment(None);
    // Local-only classification (no DNS — we never connect to the candidate,
    // we only transmit its scrubbed string): reject non-public IP literals and
    // intranet-style hostnames so internal URLs never leave the machine.
    match parsed.host()? {
        url::Host::Ipv4(v4) => {
            if !crate::url_validate::is_public_addr(&std::net::SocketAddr::new(
                std::net::IpAddr::V4(v4),
                0,
            )) {
                return None;
            }
        }
        url::Host::Ipv6(v6) => {
            if !crate::url_validate::is_public_addr(&std::net::SocketAddr::new(
                std::net::IpAddr::V6(v6),
                0,
            )) {
                return None;
            }
        }
        url::Host::Domain(domain) => {
            let lower = domain.trim_end_matches('.').to_ascii_lowercase();
            let intranet = !lower.contains('.')
                || lower == "localhost"
                || lower.ends_with(".local")
                || lower.ends_with(".internal")
                || lower.ends_with(".lan")
                || lower.ends_with(".corp");
            if intranet {
                return None;
            }
            let addresses = dns_budget.resolve_subject(resolver?, &lower)?;
            if addresses.is_empty()
                || addresses.iter().any(|address| {
                    !crate::url_validate::is_public_addr(&std::net::SocketAddr::new(*address, 0))
                })
            {
                return None;
            }
        }
    }
    // Keep only the origin. Secrets embedded in path segments are as sensitive
    // as query tokens, and Safe Browsing does not justify disclosing them.
    parsed.set_path("/");
    Some(parsed.into())
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
        // M6 ch1 — distro/docker backends have no upstream threat-feed label, so
        // they map to `None` and the adapters that consult these tables skip them.
        Ecosystem::Apt
        | Ecosystem::Brew
        | Ecosystem::Dnf
        | Ecosystem::Yum
        | Ecosystem::Pacman
        | Ecosystem::Scoop
        | Ecosystem::Docker => None,
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
        Ecosystem::Apt
        | Ecosystem::Brew
        | Ecosystem::Dnf
        | Ecosystem::Yum
        | Ecosystem::Pacman
        | Ecosystem::Scoop
        | Ecosystem::Docker => None,
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
        Ecosystem::Apt
        | Ecosystem::Brew
        | Ecosystem::Dnf
        | Ecosystem::Yum
        | Ecosystem::Pacman
        | Ecosystem::Scoop
        | Ecosystem::Docker => None,
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
        Ecosystem::Apt
        | Ecosystem::Brew
        | Ecosystem::Dnf
        | Ecosystem::Yum
        | Ecosystem::Pacman
        | Ecosystem::Scoop
        | Ecosystem::Docker => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Mutex;
    use url::Url;

    #[derive(Default)]
    struct FakeDns {
        answers: HashMap<String, Option<Vec<IpAddr>>>,
        calls: Mutex<Vec<String>>,
    }

    impl FakeDns {
        fn public_for(names: &[&str]) -> Self {
            let answers = names
                .iter()
                .map(|name| {
                    (
                        (*name).to_string(),
                        Some(vec!["93.184.216.34".parse().expect("public IP")]),
                    )
                })
                .collect();
            Self {
                answers,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn with_answer(mut self, name: &str, addresses: Option<Vec<IpAddr>>) -> Self {
            self.answers.insert(name.to_string(), addresses);
            self
        }
    }

    impl crate::network::DnsResolver for FakeDns {
        fn lookup_ips(&self, name: &str, _deadline: Instant) -> Option<Vec<IpAddr>> {
            self.calls
                .lock()
                .expect("DNS calls lock")
                .push(name.to_string());
            self.answers.get(name).cloned().flatten()
        }
    }

    fn dns_budget() -> crate::network::DnsRequestBudget {
        crate::network::DnsRequestBudget::new(Instant::now() + Duration::from_secs(1), 64, 64)
    }

    #[test]
    fn safe_browsing_filter_only_accepts_http_urls() {
        let resolver = FakeDns::public_for(&["example.com", "phish.example"]);
        let mut budget = dns_budget();
        let parsed = UrlLike::Standard {
            parsed: Url::parse("https://example.com/login").expect("url"),
            raw_host: "example.com".to_string(),
        };
        assert_eq!(
            safe_browsing_candidate_url(
                &parsed,
                "https://example.com/login",
                Some(&resolver),
                &mut budget,
            ),
            Some("https://example.com/".to_string())
        );

        let unparsed = UrlLike::Unparsed {
            raw: "http://phish.example".to_string(),
            raw_host: Some("phish.example".to_string()),
            raw_path: None,
        };
        assert_eq!(
            safe_browsing_candidate_url(
                &unparsed,
                "http://phish.example",
                Some(&resolver),
                &mut budget,
            ),
            // The scrubber parses and re-serializes; an empty path normalizes
            // to `/`.
            Some("http://phish.example/".to_string())
        );

        let docker = UrlLike::DockerRef {
            registry: Some("ghcr.io".to_string()),
            image: "owner/image".to_string(),
            tag: Some("latest".to_string()),
            digest: None,
        };
        assert_eq!(
            safe_browsing_candidate_url(
                &docker,
                "ghcr.io/owner/image",
                Some(&resolver),
                &mut budget,
            ),
            None
        );

        let scp = UrlLike::Scp {
            user: Some("git".to_string()),
            host: "github.com".to_string(),
            path: "owner/repo.git".to_string(),
        };
        assert_eq!(
            safe_browsing_candidate_url(
                &scp,
                "git@github.com:owner/repo.git",
                Some(&resolver),
                &mut budget,
            ),
            None
        );
    }

    #[test]
    fn privacy_scrub_strips_secrets_and_rejects_internal_urls() {
        let resolver =
            FakeDns::public_for(&["example.com", "storage.example", "downloads.example.com"]);
        let mut budget = dns_budget();
        // Userinfo, path, query, and fragment are removed before transmission.
        assert_eq!(
            privacy_scrub_url(
                "https://user:pass@example.com/reset/secret123?token=secret123#frag",
                Some(&resolver),
                &mut budget,
            ),
            Some("https://example.com/".to_string())
        );
        assert_eq!(
            privacy_scrub_url(
                "https://storage.example/x.tar.gz?X-Amz-Signature=abc&X-Amz-Expires=60",
                Some(&resolver),
                &mut budget,
            ),
            Some("https://storage.example/".to_string())
        );
        // Private / loopback / link-local literals and intranet names never leave.
        for raw in [
            "http://192.168.1.1/admin",
            "http://127.0.0.1:8080/debug",
            "http://169.254.169.254/latest/meta-data",
            "http://10.0.0.4/internal",
            "http://localhost:9000/x",
            "http://printer.local/status",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://intranet/hr",
        ] {
            assert_eq!(
                privacy_scrub_url(raw, Some(&resolver), &mut budget),
                None,
                "must not transmit: {raw}"
            );
        }
        // Public destinations survive as origins only.
        assert_eq!(
            privacy_scrub_url(
                "https://downloads.example.com/pkg.tar.gz",
                Some(&resolver),
                &mut budget,
            ),
            Some("https://downloads.example.com/".to_string())
        );
    }

    #[test]
    fn privacy_scrub_rejects_private_mixed_and_unresolved_dotted_names() {
        let resolver = FakeDns::default()
            .with_answer(
                "private.example.com",
                Some(vec!["10.0.0.7".parse().unwrap()]),
            )
            .with_answer(
                "mixed.example.com",
                Some(vec![
                    "93.184.216.34".parse().unwrap(),
                    "192.168.1.9".parse().unwrap(),
                ]),
            )
            .with_answer("missing.example.com", None)
            .with_answer(
                "public.example.com",
                Some(vec!["93.184.216.34".parse().unwrap()]),
            );
        let mut budget = dns_budget();

        assert_eq!(
            privacy_scrub_url(
                "https://unclassified.example.com/private/path",
                None,
                &mut budget,
            ),
            None,
            "a dotted hostname must not be disclosed when DNS classification is unavailable"
        );

        for host in [
            "private.example.com",
            "mixed.example.com",
            "missing.example.com",
        ] {
            let raw = format!("https://{host}/internal/reset-token");
            assert_eq!(
                privacy_scrub_url(&raw, Some(&resolver), &mut budget),
                None,
                "must not disclose {host}"
            );
        }
        assert_eq!(
            privacy_scrub_url(
                "https://public.example.com/private/path",
                Some(&resolver),
                &mut budget,
            ),
            Some("https://public.example.com/".to_string())
        );
        assert_eq!(
            privacy_scrub_url("https://93.184.216.34/private/path", None, &mut budget),
            Some("https://93.184.216.34/".to_string())
        );
    }

    #[test]
    fn successful_safe_browsing_batch_caches_clean_and_matched_results() {
        let _guard = tirith_test_support::GlobalStateGuard::new().expect("isolated state");
        let clean = "https://clean.example/";
        let matched = "https://matched.example/";
        let extraneous = "https://not-requested.example/";
        let parsed = SafeBrowsingResponse {
            matches: vec![SafeBrowsingMatch {
                threat_type: "MALWARE".to_string(),
                threat_entry: SafeBrowsingThreatEntry {
                    url: matched.to_string(),
                },
            }],
        };

        let out = cache_successful_safe_browsing_batch(&[clean, matched], parsed);
        assert_eq!(out, vec![(matched.to_string(), "MALWARE".to_string())]);

        let clean_cache: SafeBrowsingResponse =
            load_cache("safe-browsing", clean, CACHE_TTL_SECS).expect("clean cache entry");
        assert!(clean_cache.matches.is_empty());
        let matched_cache: SafeBrowsingResponse =
            load_cache("safe-browsing", matched, CACHE_TTL_SECS).expect("matched cache entry");
        assert_eq!(matched_cache.matches.len(), 1);

        let ambiguous_clean = "https://ambiguous-clean.example/";
        let malformed = SafeBrowsingResponse {
            matches: vec![SafeBrowsingMatch {
                threat_type: "SOCIAL_ENGINEERING".to_string(),
                threat_entry: SafeBrowsingThreatEntry {
                    url: extraneous.to_string(),
                },
            }],
        };
        assert!(cache_successful_safe_browsing_batch(&[ambiguous_clean], malformed).is_empty());
        assert!(load_cache::<SafeBrowsingResponse>(
            "safe-browsing",
            ambiguous_clean,
            CACHE_TTL_SECS
        )
        .is_none());
        assert!(
            load_cache::<SafeBrowsingResponse>("safe-browsing", extraneous, CACHE_TTL_SECS)
                .is_none()
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

    /// Runtime enrichment has three independent caps and every one of them used
    /// to be silent, so a verdict could report a clean assessment of a command
    /// it had only partly looked at. The static rule path already discloses its
    /// cap through `RuleId::AnalysisIncomplete`; this is the runtime twin.
    ///
    /// The network paths are not reachable from a unit test, so this pins the
    /// decision function itself across all eight flag combinations.
    #[test]
    fn every_enrichment_cap_is_disclosed_and_a_complete_run_is_not() {
        assert!(
            incomplete_enrichment_finding(false, false, false).is_none(),
            "nothing was cut, so nothing may be disclosed"
        );

        for (extraction, package, url, expected) in [
            (true, false, false, "package extraction stopped at that cap"),
            (
                false,
                true,
                false,
                "were looked up against live threat intelligence",
            ),
            (false, false, true, "were checked against Safe Browsing"),
        ] {
            let finding = incomplete_enrichment_finding(extraction, package, url)
                .expect("a cut must be disclosed");
            assert_eq!(finding.rule_id, RuleId::AnalysisIncomplete);
            assert_eq!(finding.severity, Severity::High);
            assert!(
                finding.description.contains(expected),
                "{extraction}/{package}/{url} must name its cause: {}",
                finding.description
            );
        }

        // Several at once are reported together, not collapsed to the first.
        let all = incomplete_enrichment_finding(true, true, true).expect("disclosed");
        for expected in [
            "package extraction stopped at that cap",
            "were looked up against live threat intelligence",
            "were checked against Safe Browsing",
        ] {
            assert!(all.description.contains(expected), "{}", all.description);
        }
        assert!(
            all.description.contains("incompletely analyzed"),
            "the verdict wording must say it is not clean: {}",
            all.description
        );
    }
}
