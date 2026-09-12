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
    read_json_bounded_result(resp, max_bytes).ok()
}

fn read_json_bounded_result<T: DeserializeOwned>(
    resp: reqwest::blocking::Response,
    max_bytes: u64,
) -> Result<T, LookupFailure> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes {
            return Err(LookupFailure::Response);
        }
    }
    use std::io::Read as _;
    let mut buf = Vec::new();
    resp.take(max_bytes + 1)
        .read_to_end(&mut buf)
        .map_err(|_| LookupFailure::Response)?;
    if buf.len() as u64 > max_bytes {
        return Err(LookupFailure::Response);
    }
    serde_json::from_slice(&buf).map_err(|_| LookupFailure::Response)
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

/// Whether runtime threat intelligence may perform network I/O.
///
/// `CacheOnly` is an enforcement boundary, not a timeout hint: every live
/// backend reads its persistent cache first and reports an incomplete lookup
/// on a miss without constructing an HTTP client, resolving DNS, or sending a
/// request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeThreatNetwork {
    Online,
    CacheOnly,
}

impl RuntimeThreatNetwork {
    fn allows_network(self) -> bool {
        self == Self::Online
    }
}

/// A remote lookup must distinguish a complete negative answer from work that
/// never completed. Collapsing both to `None` made a timed-out OSV request look
/// exactly like "no advisory" and let later packages inherit a false clean
/// result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LookupFailure {
    Offline,
    Deadline,
    Client,
    Transport,
    HttpStatus,
    Response,
}

impl LookupFailure {
    fn label(self) -> &'static str {
        match self {
            Self::Offline => "was skipped by offline mode",
            Self::Deadline => "deadline exhausted",
            Self::Client => "HTTP client setup failed",
            Self::Transport => "transport failed",
            Self::HttpStatus => "upstream returned an error status",
            Self::Response => "upstream response was invalid or exceeded its bound",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LookupOutcome<T> {
    Complete(T),
    Unsupported,
    Incomplete(LookupFailure),
}

#[derive(Debug, Clone)]
struct MetadataLookup {
    signal: Option<SuspiciousPackageSignal>,
    incomplete: Vec<(&'static str, LookupFailure)>,
}

trait PackageThreatBackend {
    fn resolve_default_version(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        deadline: Instant,
    ) -> LookupOutcome<Option<String>>;

    fn query_osv(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
        deadline: Instant,
    ) -> LookupOutcome<Vec<OsvVuln>>;

    fn find_kev_alias(
        &self,
        advisories: &[OsvVuln],
        deadline: Instant,
    ) -> LookupOutcome<Option<String>>;

    fn collect_package_metadata(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: Option<&str>,
        deadline: Instant,
    ) -> MetadataLookup;
}

struct LivePackageThreatBackend {
    network: RuntimeThreatNetwork,
    cache: CacheReadContext,
}

impl PackageThreatBackend for LivePackageThreatBackend {
    fn resolve_default_version(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        deadline: Instant,
    ) -> LookupOutcome<Option<String>> {
        resolve_default_version(ecosystem, name, deadline, self.network, &self.cache)
    }

    fn query_osv(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
        deadline: Instant,
    ) -> LookupOutcome<Vec<OsvVuln>> {
        query_osv(
            ecosystem,
            name,
            version,
            deadline,
            self.network,
            &self.cache,
        )
    }

    fn find_kev_alias(
        &self,
        advisories: &[OsvVuln],
        deadline: Instant,
    ) -> LookupOutcome<Option<String>> {
        find_kev_alias(advisories, deadline, self.network, &self.cache)
    }

    fn collect_package_metadata(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: Option<&str>,
        deadline: Instant,
    ) -> MetadataLookup {
        collect_package_metadata(
            ecosystem,
            name,
            version,
            deadline,
            self.network,
            &self.cache,
        )
    }
}

fn version_intent_identity(intent: &crate::version_intent::VersionIntent) -> String {
    match intent {
        crate::version_intent::VersionIntent::Unspecified => "unspecified".to_string(),
        crate::version_intent::VersionIntent::Exact(version) => format!("exact:{version}"),
        crate::version_intent::VersionIntent::Resolved(version) => {
            format!("resolved:{version}")
        }
        crate::version_intent::VersionIntent::Constraint { raw, parsed } => {
            format!("constraint:{}:{raw}", parsed.is_some())
        }
    }
}

fn deduplicate_packages(packages: Vec<threatintel::PackageRef>) -> Vec<threatintel::PackageRef> {
    let mut seen: HashSet<(u8, String, String)> = HashSet::new();
    packages
        .into_iter()
        .filter(|package| {
            seen.insert((
                package.ecosystem as u8,
                crate::threatdb::canonical_package_name(package.ecosystem, &package.name),
                version_intent_identity(&package.version),
            ))
        })
        .collect()
}

fn package_incomplete_finding(
    package: &threatintel::PackageRef,
    mut reasons: Vec<String>,
) -> Option<Finding> {
    reasons.sort();
    reasons.dedup();
    if reasons.is_empty() {
        return None;
    }
    Some(Finding {
        rule_id: RuleId::AnalysisIncomplete,
        severity: Severity::Medium,
        title: "Package threat intelligence could not be completed".to_string(),
        description: format!(
            "Tirith could not complete every configured runtime threat-intelligence check for package '{}' ({}). This is incomplete verification, not evidence that the package is malicious.",
            package.name,
            reasons.join("; ")
        ),
        evidence: vec![Evidence::ThreatIntel {
            source: "runtime-package-enrichment".to_string(),
            threat_type: "lookup_incomplete".to_string(),
            confidence: Confidence::Low,
            reference: None,
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    })
}

fn enrich_packages_with_backend(
    packages: Vec<threatintel::PackageRef>,
    config: &ThreatIntelConfig,
    timeout: Duration,
    backend: &dyn PackageThreatBackend,
) -> (Vec<Finding>, bool) {
    let deduplicated = deduplicate_packages(packages);
    let budget_truncated = deduplicated.len() > MAX_ENRICH_PACKAGES;
    let packages: Vec<_> = deduplicated.into_iter().take(MAX_ENRICH_PACKAGES).collect();
    if packages.is_empty() {
        return (Vec::new(), budget_truncated);
    }

    // Give every distinct package an equal wall-clock slice. A slow first
    // registry request can consume only its own slice; it cannot starve every
    // later package of the one shared deadline as it did in #211.
    let divisor = u32::try_from(packages.len()).unwrap_or(u32::MAX);
    let per_package = (timeout / divisor).max(Duration::from_millis(1));
    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    for package in packages {
        let deadline = Instant::now()
            .checked_add(per_package)
            .unwrap_or_else(Instant::now);
        let mut incomplete = Vec::new();

        // Only a concrete version is a valid OSV `version`. Constraints and
        // unspecified requests first resolve through deps.dev, but every
        // resolver outcome remains typed so failure cannot masquerade as a
        // clean negative result.
        let effective_version = if let Some(version) = package.version.exact_version() {
            Some(version.to_string())
        } else if config.deps_dev_enabled {
            match backend.resolve_default_version(package.ecosystem, &package.name, deadline) {
                LookupOutcome::Complete(Some(resolved)) => match &package.version {
                    crate::version_intent::VersionIntent::Constraint { parsed, raw } => {
                        match parsed {
                            Some(constraint) => {
                                match crate::version_intent::ReleaseVersion::parse(&resolved) {
                                    Some(version) if constraint.matches(&version) => Some(resolved),
                                    Some(_) => {
                                        incomplete.push(format!(
                                            "the registry default does not satisfy constraint '{raw}'"
                                        ));
                                        None
                                    }
                                    None => {
                                        incomplete.push(
                                            "the registry default was not a supported concrete version"
                                                .to_string(),
                                        );
                                        None
                                    }
                                }
                            }
                            None => {
                                incomplete.push(format!(
                                    "constraint '{raw}' is outside the supported proof grammar"
                                ));
                                None
                            }
                        }
                    }
                    crate::version_intent::VersionIntent::Unspecified => Some(resolved),
                    crate::version_intent::VersionIntent::Exact(_)
                    | crate::version_intent::VersionIntent::Resolved(_) => {
                        unreachable!("concrete versions are handled before registry resolution")
                    }
                },
                LookupOutcome::Complete(None) => {
                    incomplete.push("the registry returned no default version".to_string());
                    None
                }
                LookupOutcome::Unsupported => {
                    incomplete.push(
                        "default-version resolution is unsupported for this ecosystem".to_string(),
                    );
                    None
                }
                LookupOutcome::Incomplete(failure) => {
                    incomplete.push(format!("default-version resolution {}", failure.label()));
                    None
                }
            }
        } else {
            incomplete.push(
                "no concrete version was available and deps.dev resolution is disabled".to_string(),
            );
            None
        };

        if config.osv_enabled {
            if let Some(version) = effective_version.as_deref() {
                match backend.query_osv(package.ecosystem, &package.name, version, deadline) {
                    LookupOutcome::Complete(advisories) => {
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

                        if !advisories.is_empty() {
                            match backend.find_kev_alias(&advisories, deadline) {
                                LookupOutcome::Complete(Some(kev_hit)) => {
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
                                LookupOutcome::Complete(None) => {}
                                LookupOutcome::Unsupported => incomplete
                                    .push("CISA KEV correlation is unsupported".to_string()),
                                LookupOutcome::Incomplete(failure) => incomplete
                                    .push(format!("CISA KEV correlation {}", failure.label())),
                            }
                        }
                    }
                    LookupOutcome::Unsupported => {
                        incomplete.push("OSV lookup is unsupported for this ecosystem".to_string())
                    }
                    LookupOutcome::Incomplete(failure) => {
                        incomplete.push(format!("OSV lookup {}", failure.label()));
                    }
                }
            }
        }

        if config.deps_dev_enabled {
            let metadata = backend.collect_package_metadata(
                package.ecosystem,
                &package.name,
                effective_version.as_deref(),
                deadline,
            );
            for (source, failure) in metadata.incomplete {
                incomplete.push(format!("{source} metadata lookup {}", failure.label()));
            }
            if let Some(signal) = metadata.signal {
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

        if let Some(finding) = package_incomplete_finding(&package, incomplete) {
            findings.push(finding);
        }
    }

    (findings, budget_truncated)
}

pub fn enrich_command(
    input: &str,
    shell: ShellType,
    config: &ThreatIntelConfig,
    mode: RuntimeThreatMode,
) -> Vec<Finding> {
    enrich_command_with_network(input, shell, config, mode, RuntimeThreatNetwork::Online)
}

/// Runtime enrichment with an explicit network policy. CLI entry points must
/// use this form after resolving `--offline` and `TIRITH_OFFLINE`.
pub fn enrich_command_with_network(
    input: &str,
    shell: ShellType,
    config: &ThreatIntelConfig,
    mode: RuntimeThreatMode,
    network: RuntimeThreatNetwork,
) -> Vec<Finding> {
    enrich_command_with_cache(
        input,
        shell,
        config,
        mode,
        network,
        CacheReadContext::new(unix_now(), mode.timeout()),
    )
}

/// One explicit read phase, with no network, cache publication or eviction.
/// Complete refers to configured enrichment, not arbitrary command safety.
pub(crate) fn capture_cached_enrichment(
    input: &str,
    shell: ShellType,
    config: &ThreatIntelConfig,
    captured_at: chrono::DateTime<chrono::Utc>,
) -> (Vec<Finding>, bool) {
    let findings = enrich_command_with_cache(
        input,
        shell,
        config,
        RuntimeThreatMode::Inline,
        RuntimeThreatNetwork::CacheOnly,
        CacheReadContext::new(
            captured_at.timestamp().max(0) as u64,
            Duration::from_millis(500),
        ),
    );
    let complete = !findings
        .iter()
        .any(|finding| finding.rule_id == RuleId::AnalysisIncomplete);
    (findings, complete)
}

fn enrich_command_with_cache(
    input: &str,
    shell: ShellType,
    config: &ThreatIntelConfig,
    mode: RuntimeThreatMode,
    network: RuntimeThreatNetwork,
    cache: CacheReadContext,
) -> Vec<Finding> {
    if !config.osv_enabled && !config.deps_dev_enabled && config.google_safe_browsing_key.is_none()
    {
        return Vec::new();
    }

    let segments = crate::tokenize::tokenize(input, shell);
    // `extract_packages_detail_for_shell`, not the bare variant: the detail form
    // exists precisely so a consumer whose output is a security decision can see
    // that the package list was cut. Discarding it made a runtime verdict read
    // as a complete assessment of a command it had only partly looked at.
    let extracted = threatintel::extract_packages_detail_for_shell(&segments, shell);
    let extraction_truncated = extracted.truncated;
    let packages = extracted.packages;
    let urls = extract::extract_urls(input, shell);
    let backend = LivePackageThreatBackend { network, cache };
    let (mut findings, package_budget_truncated) =
        enrich_packages_with_backend(packages, config, mode.timeout(), &backend);
    let mut seen = HashSet::new();
    // URL enrichment receives its own phase budget. Package lookups cannot
    // silently consume the entire Safe Browsing deadline.
    let deadline = Instant::now() + mode.timeout();

    let mut url_budget_truncated = false;
    let safe_browsing_offline = network == RuntimeThreatNetwork::CacheOnly
        && config.google_safe_browsing_key.is_some()
        && !urls.is_empty();
    if network.allows_network() {
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
                for (url, match_type) in
                    query_safe_browsing_batch(batch, api_key, deadline, &backend.cache)
                {
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
        safe_browsing_offline,
    ) {
        findings.insert(0, finding);
    }

    findings
}

// A capture owns the complete cache-read budget. Repeated references to a
// package or KEV catalog reuse the first observed bytes, including misses.
// No mutable global cache or thread-local input can change a frozen preview.
struct CacheReadContext {
    now: u64,
    deadline: Instant,
    state: std::cell::RefCell<CacheReadState>,
}

#[derive(Default)]
struct CacheReadState {
    bytes: u64,
    entries: std::collections::BTreeMap<PathBuf, Option<std::rc::Rc<CachedValue>>>,
}

struct CachedValue {
    fetched_at: u64,
    value: serde_json::Value,
}

const MAX_CAPTURE_CACHE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_CAPTURE_CACHE_FILES: usize = 128;
const MAX_CACHE_JSON_NODES: usize = 65_536;

impl CacheReadContext {
    fn new(now: u64, timeout: Duration) -> Self {
        Self {
            now,
            deadline: Instant::now() + timeout,
            state: Default::default(),
        }
    }

    fn load<T: DeserializeOwned>(&self, kind: &str, key: &str, ttl_secs: u64) -> Option<T> {
        if Instant::now() >= self.deadline {
            return None;
        }
        let path = cache_path(kind, key)?;
        let cached = {
            let mut state = self.state.borrow_mut();
            if let Some(prior) = state.entries.get(&path) {
                prior.clone()
            } else {
                if state.entries.len() >= MAX_CAPTURE_CACHE_FILES {
                    return None;
                }
                let remaining = MAX_CAPTURE_CACHE_BYTES.saturating_sub(state.bytes);
                let cap = remaining.min(MAX_RESPONSE_BYTES);
                let observed = self
                    .read(&path, cap, &mut state.bytes)
                    .map(std::rc::Rc::new);
                state.entries.insert(path, observed.clone());
                observed
            }
        }?;
        // Future clocks are unknown, never fresh forever via saturating_sub.
        if cached.fetched_at > self.now
            || self.now - cached.fetched_at > ttl_secs
            || Instant::now() >= self.deadline
        {
            return None;
        }
        serde_json::from_value(cached.value.clone()).ok()
    }

    fn read(&self, path: &std::path::Path, cap: u64, bytes_read: &mut u64) -> Option<CachedValue> {
        use crate::util::dirfd::{file_generation, DirCapability};
        use std::io::Read as _;
        if cap == 0 {
            return None;
        }
        let parent = DirCapability::open_root(path.parent()?).ok()?;
        let parent_identity = parent.identity().ok()?;
        let name = path.file_name()?.to_str()?;
        let mut file = parent.open_child_file(name, cap).ok()?;
        let generation = file_generation(&file).ok()?;
        let mut bytes = Vec::new();
        let result = (&mut file)
            .take(cap.saturating_add(1))
            .read_to_end(&mut bytes);
        *bytes_read = bytes_read.saturating_add(bytes.len() as u64);
        if result.is_err()
            || bytes.len() as u64 > cap
            || file_generation(&file).ok()? != generation
            || file_generation(&parent.open_child_file(name, cap).ok()?).ok()? != generation
            || DirCapability::open_root(path.parent()?)
                .ok()?
                .identity()
                .ok()?
                != parent_identity
            || Instant::now() >= self.deadline
        {
            return None;
        }
        let text = std::str::from_utf8(&bytes).ok()?;
        let value = crate::mcp_lock::parse_json_no_duplicates(text).ok()?;
        let mut pending = vec![&value];
        let mut nodes = 0;
        while let Some(value) = pending.pop() {
            nodes += 1;
            if nodes > MAX_CACHE_JSON_NODES {
                return None;
            }
            match value {
                serde_json::Value::Array(values) => {
                    if values.len() > MAX_DECODED_ITEMS {
                        return None;
                    }
                    pending.extend(values.iter());
                }
                serde_json::Value::Object(values) => {
                    if values.len() > MAX_DECODED_ITEMS {
                        return None;
                    }
                    pending.extend(values.values());
                }
                _ => (),
            }
        }
        let envelope: CacheEnvelope<serde_json::Value> = serde_json::from_value(value).ok()?;
        Some(CachedValue {
            fetched_at: envelope.fetched_at,
            value: envelope.value,
        })
    }
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

#[cfg(test)]
fn load_cache<T: DeserializeOwned>(kind: &str, key: &str, ttl_secs: u64) -> Option<T> {
    CacheReadContext::new(unix_now(), Duration::from_secs(5)).load(kind, key, ttl_secs)
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
    build_client_result(deadline).ok()
}

fn build_client_result(deadline: Instant) -> Result<reqwest::blocking::Client, LookupFailure> {
    let timeout = remaining_timeout(deadline).ok_or(LookupFailure::Deadline)?;
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|_| LookupFailure::Client)
}

fn classify_request_error(error: &reqwest::Error) -> LookupFailure {
    if error.is_timeout() {
        LookupFailure::Deadline
    } else {
        LookupFailure::Transport
    }
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
    network: RuntimeThreatNetwork,
    cache: &CacheReadContext,
) -> LookupOutcome<Vec<OsvVuln>> {
    let Some(label) = ecosystem_label(ecosystem) else {
        return LookupOutcome::Unsupported;
    };
    let Some(ecosystem_name) = osv_ecosystem_name(ecosystem) else {
        return LookupOutcome::Unsupported;
    };
    let cache_key = format!("{label}:{name}:{version}");
    if let Some(response) = cache.load::<OsvQueryResponse>("osv", &cache_key, CACHE_TTL_SECS) {
        return LookupOutcome::Complete(response.vulns);
    }
    if !network.allows_network() {
        return LookupOutcome::Incomplete(LookupFailure::Offline);
    }

    let client = match build_client_result(deadline) {
        Ok(client) => client,
        Err(error) => return LookupOutcome::Incomplete(error),
    };
    let body = serde_json::json!({
        "package": {
            "name": name,
            "ecosystem": ecosystem_name,
        },
        "version": version,
    });

    let response = match client
        .post("https://api.osv.dev/v1/query")
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
    {
        Ok(response) => response,
        Err(error) => return LookupOutcome::Incomplete(classify_request_error(&error)),
    };
    let response = match response.error_for_status() {
        Ok(response) => response,
        Err(_) => return LookupOutcome::Incomplete(LookupFailure::HttpStatus),
    };
    let mut response: OsvQueryResponse =
        match read_json_bounded_result(response, MAX_RESPONSE_BYTES) {
            Ok(response) => response,
            Err(error) => return LookupOutcome::Incomplete(error),
        };
    response.vulns.truncate(MAX_DECODED_ITEMS);
    store_cache("osv", &cache_key, &response);
    LookupOutcome::Complete(response.vulns)
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
    network: RuntimeThreatNetwork,
    cache: &CacheReadContext,
) -> LookupOutcome<DepsPackageResponse> {
    let Some(system) = deps_system_name(ecosystem) else {
        return LookupOutcome::Unsupported;
    };
    let encoded = utf8_percent_encode(name, NON_ALPHANUMERIC).to_string();
    let cache_key = format!("{system}:{encoded}");
    if let Some(response) =
        cache.load::<DepsPackageResponse>("deps-package", &cache_key, CACHE_TTL_SECS)
    {
        return LookupOutcome::Complete(response);
    }
    if !network.allows_network() {
        return LookupOutcome::Incomplete(LookupFailure::Offline);
    }

    let client = match build_client_result(deadline) {
        Ok(client) => client,
        Err(error) => return LookupOutcome::Incomplete(error),
    };
    let response = match client
        .get(format!(
            "https://api.deps.dev/v3/systems/{system}/packages/{encoded}"
        ))
        .send()
    {
        Ok(response) => response,
        Err(error) => return LookupOutcome::Incomplete(classify_request_error(&error)),
    };
    let response = match response.error_for_status() {
        Ok(response) => response,
        Err(_) => return LookupOutcome::Incomplete(LookupFailure::HttpStatus),
    };
    let mut response: DepsPackageResponse =
        match read_json_bounded_result(response, MAX_RESPONSE_BYTES) {
            Ok(response) => response,
            Err(error) => return LookupOutcome::Incomplete(error),
        };
    response.versions.truncate(MAX_DECODED_ITEMS);
    store_cache("deps-package", &cache_key, &response);
    LookupOutcome::Complete(response)
}

fn resolve_default_version(
    ecosystem: Ecosystem,
    name: &str,
    deadline: Instant,
    network: RuntimeThreatNetwork,
    cache: &CacheReadContext,
) -> LookupOutcome<Option<String>> {
    match deps_package(ecosystem, name, deadline, network, cache) {
        LookupOutcome::Complete(package) => LookupOutcome::Complete(
            package
                .versions
                .into_iter()
                .find(|version| version.is_default)
                .map(|version| version.version_key.version),
        ),
        LookupOutcome::Unsupported => LookupOutcome::Unsupported,
        LookupOutcome::Incomplete(error) => LookupOutcome::Incomplete(error),
    }
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
    network: RuntimeThreatNetwork,
    cache: &CacheReadContext,
) -> LookupOutcome<EcosystemsPackageResponse> {
    let Some(registry) = ecosystems_registry_name(ecosystem) else {
        return LookupOutcome::Unsupported;
    };
    let encoded = utf8_percent_encode(name, NON_ALPHANUMERIC).to_string();
    let cache_key = format!("{registry}:{encoded}");
    if let Some(response) =
        cache.load::<EcosystemsPackageResponse>("ecosystems-package", &cache_key, CACHE_TTL_SECS)
    {
        return LookupOutcome::Complete(response);
    }
    if !network.allows_network() {
        return LookupOutcome::Incomplete(LookupFailure::Offline);
    }

    let client = match build_client_result(deadline) {
        Ok(client) => client,
        Err(error) => return LookupOutcome::Incomplete(error),
    };
    let response = match client
        .get(format!(
            "https://packages.ecosyste.ms/api/v1/registries/{registry}/packages/{encoded}"
        ))
        .send()
    {
        Ok(response) => response,
        Err(error) => return LookupOutcome::Incomplete(classify_request_error(&error)),
    };
    let response = match response.error_for_status() {
        Ok(response) => response,
        Err(_) => return LookupOutcome::Incomplete(LookupFailure::HttpStatus),
    };
    let mut response: EcosystemsPackageResponse =
        match read_json_bounded_result(response, MAX_RESPONSE_BYTES) {
            Ok(response) => response,
            Err(error) => return LookupOutcome::Incomplete(error),
        };
    response.maintainers.truncate(MAX_DECODED_ITEMS);
    store_cache("ecosystems-package", &cache_key, &response);
    LookupOutcome::Complete(response)
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
    network: RuntimeThreatNetwork,
    cache: &CacheReadContext,
) -> MetadataLookup {
    let mut incomplete = Vec::new();
    let first_release_days = match deps_package(ecosystem, name, deadline, network, cache) {
        LookupOutcome::Complete(response) => response
            .versions
            .iter()
            .filter_map(|version| version.published_at.as_deref())
            .filter_map(parse_rfc3339_secs)
            .min()
            .map(|first_seen| {
                let now = cache.now as i64;
                ((now - first_seen).max(0)) / 86_400
            }),
        LookupOutcome::Unsupported => None,
        LookupOutcome::Incomplete(error) => {
            incomplete.push(("deps.dev", error));
            None
        }
    };

    let maintainers = match ecosystems_package(ecosystem, name, deadline, network, cache) {
        LookupOutcome::Complete(package) => Some(package.maintainers.len()),
        LookupOutcome::Unsupported => None,
        LookupOutcome::Incomplete(error) => {
            incomplete.push(("ecosyste.ms", error));
            None
        }
    };
    let signal = (first_release_days.is_some() || maintainers.is_some()).then_some(
        SuspiciousPackageSignal {
            first_release_days,
            maintainers,
        },
    );

    MetadataLookup { signal, incomplete }
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

fn kev_aliases(
    deadline: Instant,
    network: RuntimeThreatNetwork,
    cache: &CacheReadContext,
) -> LookupOutcome<HashSet<String>> {
    if let Some(cached) = cache.load::<Vec<String>>("kev", "active", KEV_CACHE_TTL_SECS) {
        return LookupOutcome::Complete(cached.into_iter().collect());
    }
    if !network.allows_network() {
        return LookupOutcome::Incomplete(LookupFailure::Offline);
    }
    let client = match build_client_result(deadline) {
        Ok(client) => client,
        Err(error) => return LookupOutcome::Incomplete(error),
    };
    let response = match client.get(KEV_URL).send() {
        Ok(response) => response,
        Err(error) => return LookupOutcome::Incomplete(classify_request_error(&error)),
    };
    let response = match response.error_for_status() {
        Ok(response) => response,
        Err(_) => return LookupOutcome::Incomplete(LookupFailure::HttpStatus),
    };
    let response: KevCatalog = match read_json_bounded_result(response, KEV_MAX_RESPONSE_BYTES) {
        Ok(response) => response,
        Err(error) => return LookupOutcome::Incomplete(error),
    };
    let aliases: Vec<String> = response
        .vulnerabilities
        .into_iter()
        .map(|vuln| vuln.cve_id)
        .filter(|id| !id.is_empty())
        .collect();
    store_cache("kev", "active", &aliases);
    LookupOutcome::Complete(aliases.into_iter().collect())
}

fn find_kev_alias(
    advisories: &[OsvVuln],
    deadline: Instant,
    network: RuntimeThreatNetwork,
    cache: &CacheReadContext,
) -> LookupOutcome<Option<String>> {
    if advisories.is_empty() {
        return LookupOutcome::Complete(None);
    }
    match kev_aliases(deadline, network, cache) {
        LookupOutcome::Complete(kev) => LookupOutcome::Complete(
            advisories
                .iter()
                .flat_map(|advisory| advisory.aliases.iter().chain(std::iter::once(&advisory.id)))
                .find(|alias| kev.contains(*alias))
                .cloned(),
        ),
        LookupOutcome::Unsupported => LookupOutcome::Unsupported,
        LookupOutcome::Incomplete(error) => LookupOutcome::Incomplete(error),
    }
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
    cache: &CacheReadContext,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut missing: Vec<&str> = Vec::new();
    for url in urls {
        if let Some(response) =
            cache.load::<SafeBrowsingResponse>("safe-browsing", url, CACHE_TTL_SECS)
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
/// `MAX_ENRICH_URLS`. Offline Safe Browsing is also reported because its DNS
/// classification and API request are intentionally forbidden. Returns `None`
/// when nothing was cut, so a complete analysis carries no extra finding.
fn incomplete_enrichment_finding(
    extraction_truncated: bool,
    package_budget_truncated: bool,
    url_budget_truncated: bool,
    safe_browsing_offline: bool,
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
            "more than {MAX_ENRICH_PACKAGES} distinct package/version requests were named, so \
             only the first {MAX_ENRICH_PACKAGES} were looked up against live threat intelligence"
        ));
    }
    if url_budget_truncated {
        reasons.push(format!(
            "more than {MAX_ENRICH_URLS} distinct URLs were named, so only the first \
             {MAX_ENRICH_URLS} were checked against Safe Browsing"
        ));
    }
    if safe_browsing_offline {
        reasons.push(
            "Safe Browsing URL checks were skipped because offline mode forbids DNS and HTTP"
                .to_string(),
        );
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
    use std::collections::{HashMap, HashSet};
    use std::net::IpAddr;
    use std::sync::Mutex;
    use url::Url;

    fn write_cache_fixture(kind: &str, key: &str, value: &str) -> PathBuf {
        let path = cache_path(kind, key).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, value).unwrap();
        path
    }

    #[test]
    fn bounded_cache_capture_reuses_first_hit_and_miss_without_writes() {
        let _guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        let path = write_cache_fixture(
            "fixture",
            "known",
            r#"{"fetched_at":100,"value":["first"]}"#,
        );
        let cache = CacheReadContext::new(100, Duration::from_secs(5));
        assert_eq!(
            cache.load::<Vec<String>>("fixture", "known", 60).unwrap(),
            ["first"]
        );
        let bytes = cache.state.borrow().bytes;
        std::fs::write(&path, r#"{"fetched_at":100,"value":["changed"]}"#).unwrap();
        assert_eq!(
            cache.load::<Vec<String>>("fixture", "known", 60).unwrap(),
            ["first"]
        );
        assert_eq!(cache.state.borrow().bytes, bytes);
        assert!(cache
            .load::<Vec<String>>("fixture", "missing", 60)
            .is_none());
        write_cache_fixture("fixture", "missing", r#"{"fetched_at":100,"value":[]}"#);
        assert!(cache
            .load::<Vec<String>>("fixture", "missing", 60)
            .is_none());
        assert_eq!(
            CacheReadContext::new(100, Duration::from_secs(5))
                .load::<Vec<String>>("fixture", "known", 60)
                .unwrap(),
            ["changed"]
        );
    }

    #[test]
    fn bounded_cache_rejects_future_expired_duplicate_and_excessive_values() {
        let _guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        for (key, text) in [
            ("future", r#"{"fetched_at":101,"value":[]}"#.to_string()),
            ("expired", r#"{"fetched_at":1,"value":[]}"#.to_string()),
            (
                "duplicate",
                r#"{"fetched_at":100,"fetched_at":100,"value":[]}"#.to_string(),
            ),
            (
                "collection",
                serde_json::json!({"fetched_at":100,"value":vec!["x";MAX_DECODED_ITEMS+1]})
                    .to_string(),
            ),
        ] {
            write_cache_fixture("fixture", key, &text);
            assert!(
                CacheReadContext::new(100, Duration::from_secs(5))
                    .load::<Vec<String>>("fixture", key, 60)
                    .is_none(),
                "{key}"
            );
        }
        let large = write_cache_fixture("fixture", "large", "");
        std::fs::OpenOptions::new()
            .write(true)
            .open(large)
            .unwrap()
            .set_len(MAX_RESPONSE_BYTES + 1)
            .unwrap();
        let cache = CacheReadContext::new(100, Duration::from_secs(5));
        assert!(cache.load::<Vec<String>>("fixture", "large", 60).is_none());
        assert_eq!(
            cache.state.borrow().bytes,
            0,
            "oversize refused before read"
        );

        write_cache_fixture("fixture", "small", r#"{"fetched_at":100,"value":[]}"#);
        let cache = CacheReadContext::new(100, Duration::from_secs(5));
        cache.state.borrow_mut().bytes = MAX_CAPTURE_CACHE_BYTES - 1;
        assert!(cache.load::<Vec<String>>("fixture", "small", 60).is_none());
        let cache = CacheReadContext::new(100, Duration::ZERO);
        assert!(cache.load::<Vec<String>>("fixture", "small", 60).is_none());
        assert!(cache.state.borrow().entries.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn bounded_cache_refuses_symlink_fifo_and_replaced_directory() {
        use std::os::unix::fs::symlink;
        let _guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        let source = write_cache_fixture("fixture", "source", r#"{"fetched_at":100,"value":[]}"#);
        let linked = cache_path("fixture", "link").unwrap();
        symlink(&source, &linked).unwrap();
        let fifo = cache_path("fixture", "fifo").unwrap();
        let cpath = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        let cache = CacheReadContext::new(100, Duration::from_secs(5));
        assert!(cache.load::<Vec<String>>("fixture", "link", 60).is_none());
        assert!(cache.load::<Vec<String>>("fixture", "fifo", 60).is_none());
        let directory = source.parent().unwrap();
        let moved = directory.with_extension("moved");
        std::fs::rename(directory, &moved).unwrap();
        symlink(&moved, directory).unwrap();
        assert!(cache.load::<Vec<String>>("fixture", "source", 60).is_none());
    }

    #[test]
    fn disabled_cached_enrichment_has_no_gap_and_creates_no_cache_directory() {
        let _guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        let config = ThreatIntelConfig {
            osv_enabled: false,
            deps_dev_enabled: false,
            google_safe_browsing_key: None,
            ..ThreatIntelConfig::default()
        };
        let directory = policy::state_dir().unwrap().join("threatdb-api-cache");
        assert!(!directory.exists());
        let (findings, complete) = capture_cached_enrichment(
            "pip install missing-package==1.0.0",
            ShellType::Posix,
            &config,
            chrono::Utc::now(),
        );
        assert!(findings.is_empty() && complete);
        assert!(!directory.exists());
    }

    #[test]
    fn frozen_cached_threat_uses_candidate_policy_and_never_rereads_changed_cache() {
        let guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        let name = "tirith-frozen-cache-regression";
        // The existing PEP440 contract canonicalizes ==1.0.0 to exact version
        // "1" before choosing a registry/cache identity.
        let key = format!("pypi:{name}:1");
        store_cache(
            "osv",
            &key,
            &OsvQueryResponse {
                vulns: vec![OsvVuln {
                    id: "OSV-FROZEN-FIXTURE".into(),
                    aliases: Vec::new(),
                    summary: None,
                    references: Vec::new(),
                }],
            },
        );
        store_cache("kev", "active", &Vec::<String>::new());
        let policy = crate::policy::Policy {
            threat_intel: ThreatIntelConfig {
                osv_enabled: true,
                deps_dev_enabled: false,
                google_safe_browsing_key: None,
                ..ThreatIntelConfig::default()
            },
            ..crate::policy::Policy::default()
        };
        let context = crate::engine::AnalysisContext {
            input: format!("pip install {name}==1.0.0"),
            shell: ShellType::Posix,
            scan_context: crate::extract::ScanContext::Exec,
            raw_bytes: None,
            interactive: true,
            cwd: Some(guard.roots().cwd.display().to_string()),
            file_path: None,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
            card_ref: None,
            clipboard_source: crate::clipboard::ClipboardSourceState::AbsentOrInvalid,
        };
        let frozen = crate::evaluation::FrozenEvaluation::capture_with_policy(
            context,
            &policy,
            crate::escalation::CallerContext::Cli,
            None,
            crate::evaluation::SessionEvidence::Captured(Box::new(
                crate::session_warnings::SessionWarnings::new("frozen-cache"),
            )),
        );
        let before = frozen.evaluate_current();
        assert!(
            !before
                .explanation
                .gaps
                .contains(&crate::evaluation::EvidenceGap::RuntimeThreatEnrichmentNotCaptured),
            "{:?}",
            before.verdict.findings
        );
        assert!(before
            .verdict
            .findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::ThreatOsvVulnerable));
        std::fs::remove_dir_all(policy::state_dir().unwrap().join("threatdb-api-cache")).unwrap();
        let repeated = frozen.evaluate_current();
        assert_eq!(
            serde_json::to_value(&before.verdict).unwrap(),
            serde_json::to_value(&repeated.verdict).unwrap()
        );
        assert!(!policy::state_dir()
            .unwrap()
            .join("threatdb-api-cache")
            .exists());
        let mut candidate = policy;
        candidate.paranoia = 4;
        candidate
            .severity_overrides
            .insert(RuleId::ThreatOsvVulnerable.to_string(), Severity::Info);
        let changed = frozen.evaluate(&candidate);
        assert!(changed
            .verdict
            .findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::ThreatOsvVulnerable
                && finding.severity == Severity::Info));
        assert!(!changed
            .explanation
            .gaps
            .contains(&crate::evaluation::EvidenceGap::DetectorPolicyChanged));
    }

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

    #[derive(Default)]
    struct FakePackageBackend {
        calls: Mutex<Vec<String>>,
        slow_osv: HashSet<String>,
        failed_osv: HashSet<String>,
        vulnerable: HashSet<(String, String)>,
        resolutions: HashMap<String, LookupOutcome<Option<String>>>,
    }

    impl FakePackageBackend {
        fn slow(mut self, name: &str) -> Self {
            self.slow_osv.insert(name.to_string());
            self
        }

        fn fail_osv(mut self, name: &str) -> Self {
            self.failed_osv.insert(name.to_string());
            self
        }

        fn vulnerable(mut self, name: &str, version: &str) -> Self {
            self.vulnerable
                .insert((name.to_string(), version.to_string()));
            self
        }

        fn resolution(mut self, name: &str, outcome: LookupOutcome<Option<String>>) -> Self {
            self.resolutions.insert(name.to_string(), outcome);
            self
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("calls lock").clone()
        }
    }

    impl PackageThreatBackend for FakePackageBackend {
        fn resolve_default_version(
            &self,
            _ecosystem: Ecosystem,
            name: &str,
            _deadline: Instant,
        ) -> LookupOutcome<Option<String>> {
            self.calls
                .lock()
                .expect("calls lock")
                .push(format!("resolve:{name}"));
            self.resolutions
                .get(name)
                .cloned()
                .unwrap_or_else(|| LookupOutcome::Complete(Some("1.0.0".to_string())))
        }

        fn query_osv(
            &self,
            _ecosystem: Ecosystem,
            name: &str,
            version: &str,
            deadline: Instant,
        ) -> LookupOutcome<Vec<OsvVuln>> {
            self.calls
                .lock()
                .expect("calls lock")
                .push(format!("osv:{name}:{version}"));
            if self.slow_osv.contains(name) {
                let wait = deadline.saturating_duration_since(Instant::now());
                if !wait.is_zero() {
                    std::thread::sleep(wait + Duration::from_millis(1));
                }
                return LookupOutcome::Incomplete(LookupFailure::Deadline);
            }
            if self.failed_osv.contains(name) {
                return LookupOutcome::Incomplete(LookupFailure::Transport);
            }
            if self
                .vulnerable
                .contains(&(name.to_string(), version.to_string()))
            {
                LookupOutcome::Complete(vec![OsvVuln {
                    id: "OSV-TEST-1".to_string(),
                    aliases: Vec::new(),
                    summary: Some("fixture advisory".to_string()),
                    references: Vec::new(),
                }])
            } else {
                LookupOutcome::Complete(Vec::new())
            }
        }

        fn find_kev_alias(
            &self,
            _advisories: &[OsvVuln],
            _deadline: Instant,
        ) -> LookupOutcome<Option<String>> {
            LookupOutcome::Complete(None)
        }

        fn collect_package_metadata(
            &self,
            _ecosystem: Ecosystem,
            _name: &str,
            _version: Option<&str>,
            _deadline: Instant,
        ) -> MetadataLookup {
            MetadataLookup {
                signal: None,
                incomplete: Vec::new(),
            }
        }
    }

    fn package_config(osv_enabled: bool, deps_dev_enabled: bool) -> ThreatIntelConfig {
        ThreatIntelConfig {
            osv_enabled,
            deps_dev_enabled,
            google_safe_browsing_key: None,
            ..ThreatIntelConfig::default()
        }
    }

    fn extracted_packages(command: &str) -> Vec<threatintel::PackageRef> {
        let shell = crate::tokenize::ShellType::Posix;
        let segments = crate::tokenize::tokenize(command, shell);
        threatintel::extract_packages_detail_for_shell(&segments, shell).packages
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

    #[test]
    fn distinct_versions_of_one_package_are_both_queried_in_both_orders() {
        for command in [
            "pip install demo-pkg==1.0.0 && pip install demo_pkg==2.0.0",
            "pip install demo_pkg==2.0.0 && pip install demo-pkg==1.0.0",
        ] {
            let backend = FakePackageBackend::default().vulnerable("demo-pkg", "2");
            let (findings, truncated) = enrich_packages_with_backend(
                extracted_packages(command),
                &package_config(true, false),
                Duration::from_millis(50),
                &backend,
            );
            assert!(!truncated);
            let calls = backend.calls();
            assert!(calls.contains(&"osv:demo-pkg:1".to_string()), "{calls:?}");
            assert!(calls.contains(&"osv:demo-pkg:2".to_string()), "{calls:?}");
            assert!(findings.iter().any(|finding| {
                finding.rule_id == RuleId::ThreatOsvVulnerable
                    && finding.title.contains("demo-pkg@2")
            }));
        }
    }

    #[test]
    fn identical_package_version_duplicates_share_one_lookup() {
        let backend = FakePackageBackend::default();
        let (findings, truncated) = enrich_packages_with_backend(
            extracted_packages("pip install demo_pkg==1.0.0 && pip install demo-pkg==1.0.0"),
            &package_config(true, false),
            Duration::from_millis(50),
            &backend,
        );
        assert!(!truncated);
        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(
            backend
                .calls()
                .iter()
                .filter(|call| call.as_str() == "osv:demo-pkg:1")
                .count(),
            1
        );
    }

    #[test]
    fn a_slow_package_cannot_starve_a_later_package_in_either_order() {
        for command in [
            "pip install slow-pkg==1.0.0 && pip install danger-pkg==2.0.0",
            "pip install danger-pkg==2.0.0 && pip install slow-pkg==1.0.0",
        ] {
            let backend = FakePackageBackend::default()
                .slow("slow-pkg")
                .vulnerable("danger-pkg", "2");
            let (findings, _) = enrich_packages_with_backend(
                extracted_packages(command),
                &package_config(true, false),
                Duration::from_millis(30),
                &backend,
            );
            assert!(
                findings.iter().any(|finding| {
                    finding.rule_id == RuleId::ThreatOsvVulnerable
                        && finding.title.contains("danger-pkg@2")
                }),
                "later package was starved for {command}: {findings:?}"
            );
            assert!(findings.iter().any(|finding| {
                finding.rule_id == RuleId::AnalysisIncomplete
                    && finding.description.contains("slow-pkg")
                    && finding
                        .description
                        .contains("OSV lookup deadline exhausted")
            }));
        }
    }

    #[test]
    fn lookup_failures_and_unsatisfied_constraints_are_incomplete_not_threats() {
        let failed = FakePackageBackend::default().fail_osv("demo-pkg");
        let (findings, _) = enrich_packages_with_backend(
            extracted_packages("pip install demo-pkg==1.0.0"),
            &package_config(true, false),
            Duration::from_millis(50),
            &failed,
        );
        assert!(findings.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete
                && finding.description.contains("OSV lookup transport failed")
                && finding.description.contains("not evidence")
        }));
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::ThreatUnresolvedMaliciousPackage));

        let unsatisfied = FakePackageBackend::default().resolution(
            "demo-pkg",
            LookupOutcome::Complete(Some("1.0.0".to_string())),
        );
        let (findings, _) = enrich_packages_with_backend(
            extracted_packages("pip install 'demo-pkg>=2.0.0'"),
            &package_config(true, true),
            Duration::from_millis(50),
            &unsatisfied,
        );
        assert!(findings.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete
                && finding
                    .description
                    .contains("registry default does not satisfy constraint")
        }));
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::ThreatUnresolvedMaliciousPackage));
    }

    #[test]
    fn resolver_timeout_is_disclosed_without_an_osv_false_negative() {
        let backend = FakePackageBackend::default().resolution(
            "demo-pkg",
            LookupOutcome::Incomplete(LookupFailure::Deadline),
        );
        let (findings, _) = enrich_packages_with_backend(
            extracted_packages("pip install 'demo-pkg>=2.0.0'"),
            &package_config(true, true),
            Duration::from_millis(50),
            &backend,
        );
        assert!(findings.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete
                && finding
                    .description
                    .contains("default-version resolution deadline exhausted")
        }));
        assert!(!backend.calls().iter().any(|call| call.starts_with("osv:")));
    }

    #[test]
    fn cache_only_backend_reads_hits_and_never_falls_through_to_http() {
        let _guard = tirith_test_support::GlobalStateGuard::new().expect("isolated state");
        let cached_name = "tirith-offline-cached-fixture";
        let cached_key = format!("pypi:{cached_name}:1.0.0");
        store_cache(
            "osv",
            &cached_key,
            &OsvQueryResponse {
                vulns: vec![OsvVuln {
                    id: "OSV-OFFLINE-CACHED".to_string(),
                    aliases: Vec::new(),
                    summary: None,
                    references: Vec::new(),
                }],
            },
        );

        let deadline = Instant::now() + Duration::from_secs(1);
        let cached = query_osv(
            Ecosystem::PyPI,
            cached_name,
            "1.0.0",
            deadline,
            RuntimeThreatNetwork::CacheOnly,
            &CacheReadContext::new(unix_now(), Duration::from_secs(5)),
        );
        assert!(matches!(cached, LookupOutcome::Complete(vulns) if vulns.len() == 1));

        let missing = query_osv(
            Ecosystem::PyPI,
            "tirith-offline-never-cached-fixture",
            "9.9.9",
            deadline,
            RuntimeThreatNetwork::CacheOnly,
            &CacheReadContext::new(unix_now(), Duration::from_secs(5)),
        );
        assert!(
            matches!(missing, LookupOutcome::Incomplete(LookupFailure::Offline)),
            "a cache miss must stop before HTTP client construction"
        );
    }

    #[test]
    fn cache_only_enrichment_discloses_skipped_package_and_url_checks() {
        let _guard = tirith_test_support::GlobalStateGuard::new().expect("isolated state");
        let config = ThreatIntelConfig {
            osv_enabled: true,
            deps_dev_enabled: false,
            google_safe_browsing_key: Some("unused-offline-key".to_string()),
            ..ThreatIntelConfig::default()
        };
        let findings = enrich_command_with_network(
            "pip install tirith-offline-command-fixture==9.9.9; curl https://public.example/test",
            crate::tokenize::ShellType::Posix,
            &config,
            RuntimeThreatMode::Inline,
            RuntimeThreatNetwork::CacheOnly,
        );

        assert!(findings.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete
                && finding
                    .description
                    .contains("OSV lookup was skipped by offline mode")
        }));
        assert!(findings.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete
                && finding
                    .description
                    .contains("offline mode forbids DNS and HTTP")
        }));
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
            incomplete_enrichment_finding(false, false, false, false).is_none(),
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
            let finding = incomplete_enrichment_finding(extraction, package, url, false)
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
        let all = incomplete_enrichment_finding(true, true, true, true).expect("disclosed");
        for expected in [
            "package extraction stopped at that cap",
            "were looked up against live threat intelligence",
            "were checked against Safe Browsing",
            "offline mode forbids DNS and HTTP",
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
