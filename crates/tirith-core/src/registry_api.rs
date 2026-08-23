//! Registry-API-backed provenance signals for `tirith package risk --online`.
//!
//! The ONLY networked half of package-risk scoring, reached only behind the
//! explicit `--online` opt-in (never `tirith check` / any hot path). Consults a
//! package's registry API (npm / PyPI JSON / crates.io) and normalizes the
//! response into a registry-agnostic [`RegistryMetadata`], which
//! [`provenance_from_metadata`] turns into the
//! [`ApiProvenance`](crate::package_risk::ApiProvenance) the factor model
//! consumes.
//!
//! Design: all network access goes through the [`RegistryClient`] trait (tests
//! inject a fixture fake). A failed fetch degrades gracefully to a [`FetchError`]
//! → [`ApiSignals::Unavailable`] with an honest reason — never a crash or hang.
//! Successful fetches are cached under the state dir for [`CACHE_TTL_SECS`]
//! (mirrors `threatdb_api.rs`).

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::package_risk::{
    ApiProvenance, ApiSignals, InstallScriptSignals, PackageExistence, VERY_NEW_PACKAGE_DAYS,
};
use crate::policy;
use crate::threatdb::Ecosystem;

#[cfg(test)]
type RegistryUrlValidator =
    std::sync::Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync + 'static>;

/// HTTP timeout for one registry request (short — a degraded score beats a hang).
const REQUEST_TIMEOUT_SECS: u64 = 12;
/// Hard cap on a registry JSON response (npm "full" docs can be large).
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
/// How long a cached registry response is reused before a fresh fetch.
pub const CACHE_TTL_SECS: u64 = 6 * 3600;
/// Cache files older than this are evicted opportunistically.
const CACHE_EVICT_MAX_AGE_SECS: u64 = 7 * 24 * 3600;
const SECONDS_PER_DAY: u64 = 86_400;

/// A package's registry metadata, normalized across npm / PyPI / crates.io.
/// Every field is `Option`/defaulted; an unset datum is "no signal", not invented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RegistryMetadata {
    /// Which registry the data came from (`"npm"`, `"pypi"`, `"crates.io"`).
    pub source: String,
    /// Canonical package identity claimed by the native registry document.
    /// Older cache entries deserialize as `None` and are deliberately ignored:
    /// they predate package-name binding and therefore cannot prove identity.
    #[serde(default)]
    pub package_name: Option<String>,
    /// Unix epoch seconds of the package's *first* publication, when known.
    pub created_unix: Option<u64>,
    /// Unix epoch seconds of the *latest version*'s publication, when known.
    pub latest_version_unix: Option<u64>,
    /// The latest (most recent) version string, when known.
    pub latest_version: Option<String>,
    /// The exact version this metadata was requested for. `None` on legacy,
    /// unbound lookups. Install enforcement only accepts a response when this
    /// equals the version that the package manager will receive.
    #[serde(default)]
    pub selected_version: Option<String>,
    /// Publication time of [`Self::selected_version`], when known.
    #[serde(default)]
    pub selected_version_unix: Option<u64>,
    /// Version before `latest_version` (for the version-jump signal). `None`
    /// when fewer than two versions exist.
    pub previous_version: Option<String>,
    /// Maintainer/owner ids the registry lists. `Some(list)` = the API exposes
    /// the field (empty = a real "zero owners" signal); `None` = the API has no
    /// maintainer field (PyPI/crates.io), so ownership is honestly unknown.
    #[serde(default)]
    pub maintainers: Option<Vec<String>>,
    /// Total downloads over the registry's reported window, when available.
    pub recent_downloads: Option<u64>,
    /// A source-repository URL the registry lists for the package, when any.
    pub repository_url: Option<String>,
    /// `true` when the registry marks the selected version (or latest on an
    /// unbound lookup) yanked / deprecated.
    pub yanked_or_deprecated: bool,
    /// Read-only lifecycle-script analysis for the selected npm version.
    /// `Some(default)` means the exact version was inspected and has no
    /// suspicious lifecycle hook; `None` means the registry cannot provide it.
    #[serde(default)]
    pub install_script_signals: Option<InstallScriptSignals>,
    /// C13: npm `dist` provenance FACTS for the selected version. Parsed, never
    /// verified: no code path can raise a state to `Verified`, and the tarball
    /// bytes are never downloaded, so nothing is bound to them. `None` for a
    /// non-npm registry or a record with no `dist` object.
    #[serde(default)]
    pub npm_dist_facts: Option<crate::provenance::npm_facts::NpmDistFacts>,
}

/// Why a registry fetch could not produce usable metadata. Every variant is a
/// graceful degradation → [`ApiSignals::Unavailable`]. No `Offline` variant: the
/// `--offline` / `TIRITH_OFFLINE` decision short-circuits before any fetch.
#[derive(Debug, Clone)]
pub enum FetchError {
    /// The ecosystem has no registry API wired up here.
    UnsupportedEcosystem(Ecosystem),
    /// The name carries a `..` segment / stray `/` a URL library would
    /// normalize into a different path. Rejected before any URL is built.
    InvalidName,
    /// A connect / timeout / transport error.
    Network(String),
    /// A non-success HTTP status.
    HttpStatus(u16),
    /// The package was not found (HTTP 404).
    NotFound,
    /// The package exists, but the exact requested version was absent.
    VersionNotFound(String),
    /// The body could not be parsed as the expected JSON shape.
    BadResponse(String),
    /// The response exceeded [`MAX_RESPONSE_BYTES`].
    TooLarge,
}

impl FetchError {
    /// An honest, human-readable explanation for [`ApiSignals::Unavailable`].
    pub fn reason(&self) -> String {
        match self {
            FetchError::UnsupportedEcosystem(eco) => {
                // M6 ch1 — surfaced verbatim by the CLI as
                // `api signals: unavailable — no registry adapter for <eco>`.
                format!("no registry adapter for {eco}")
            }
            FetchError::InvalidName => {
                "the package name is not a valid registry name (it contains a path-traversal \
                 segment or a stray '/') — no registry request was made, scored with offline \
                 signals only"
                    .to_string()
            }
            FetchError::Network(e) => {
                format!("could not reach the registry ({e}) — scored with offline signals only")
            }
            FetchError::HttpStatus(code) => {
                format!("the registry returned HTTP {code} — scored with offline signals only")
            }
            FetchError::NotFound => {
                "the registry has no such package — scored with offline signals only".to_string()
            }
            FetchError::VersionNotFound(version) => format!(
                "the registry has no exact version '{version}' — provenance was not reused from a different release"
            ),
            FetchError::BadResponse(e) => {
                format!(
                    "the registry response could not be parsed ({e}) — scored with offline \
                         signals only"
                )
            }
            FetchError::TooLarge => {
                "the registry response exceeded tirith's size cap — scored with offline signals \
                 only"
                    .to_string()
            }
        }
    }
}

/// Fetches normalized registry metadata — the single seam through which
/// package-risk reaches (or does not reach) the network. Production uses
/// [`HttpRegistryClient`]; tests inject a fixture fake.
pub trait RegistryClient {
    /// Fetch metadata for `name` in `ecosystem`, or a [`FetchError`]. A
    /// successful result must carry [`RegistryMetadata::package_name`] bound
    /// to the native registry response; gatherers reject missing/mismatched
    /// identities, including from test or third-party implementations.
    fn fetch(&self, ecosystem: Ecosystem, name: &str) -> Result<RegistryMetadata, FetchError>;

    /// Fetch metadata bound to one exact version. Implementations that do not
    /// provide a version-aware endpoint may use the default, which accepts the
    /// legacy response only when it explicitly names the requested release.
    fn fetch_exact(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
    ) -> Result<RegistryMetadata, FetchError> {
        let mut metadata = self.fetch(ecosystem, name)?;
        if metadata.selected_version.as_deref() == Some(version)
            || metadata.latest_version.as_deref() == Some(version)
        {
            metadata.selected_version = Some(version.to_string());
            if metadata.selected_version_unix.is_none() {
                metadata.selected_version_unix = metadata.latest_version_unix;
            }
            Ok(metadata)
        } else {
            Err(FetchError::VersionNotFound(version.to_string()))
        }
    }
}

/// Gather registry-API provenance, returning [`ApiSignals`] AND
/// [`PackageExistence`] (M6 ch6). 404 → `NotFound`, other failures → `Unknown`,
/// success → `Exists`. Best-effort side effect: a successful fetch also records
/// one [`crate::registry_history`] snapshot (no extra request). Never panics or
/// blocks beyond the client timeout.
pub fn gather_api_signals(
    client: &dyn RegistryClient,
    ecosystem: Ecosystem,
    name: &str,
) -> (ApiSignals, PackageExistence) {
    gather_api_signals_result(client.fetch(ecosystem, name), ecosystem, name, true)
}

/// Resolve only whether `name` exists in its native registry.
///
/// This preserves the same response-identity validation and failure mapping as
/// [`gather_api_signals`], but deliberately does not write a registry-history
/// snapshot. Install authorization uses this narrow seam for unpinned package
/// names: the approved effect is one registry request, not a filesystem write.
pub fn gather_name_existence(
    client: &dyn RegistryClient,
    ecosystem: Ecosystem,
    name: &str,
) -> PackageExistence {
    let (_signals, existence) =
        gather_api_signals_result(client.fetch(ecosystem, name), ecosystem, name, false);
    existence
}

/// Version-bound registry provenance for an install. A successful result is
/// accepted only for `version`; metadata for latest or another release is never
/// substituted. The package existence remains `Exists` when only the requested
/// version is absent.
pub fn gather_api_signals_exact(
    client: &dyn RegistryClient,
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
) -> (ApiSignals, PackageExistence) {
    gather_api_signals_result(
        client.fetch_exact(ecosystem, name, version),
        ecosystem,
        name,
        false,
    )
}

fn gather_api_signals_result(
    result: Result<RegistryMetadata, FetchError>,
    ecosystem: Ecosystem,
    name: &str,
    record_history: bool,
) -> (ApiSignals, PackageExistence) {
    match result {
        Ok(meta) if !metadata_identity_matches(&meta, ecosystem, name) => (
            ApiSignals::unavailable(
                FetchError::BadResponse(
                    "registry response package identity did not match the request".to_string(),
                )
                .reason(),
            ),
            PackageExistence::Unknown,
        ),
        Ok(meta) => {
            // M6 ch6 — record a snapshot from this response (no extra request).
            let maintainers: Vec<crate::package_risk::MaintainerRef> = meta
                .maintainers
                .as_ref()
                .map(|m| {
                    m.iter()
                        .map(|s| crate::package_risk::MaintainerRef {
                            id: s.to_lowercase(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            if record_history {
                let _ = crate::registry_history::record_snapshot_with_maintainers(
                    ecosystem,
                    name,
                    maintainers,
                    meta.latest_version.clone(),
                    meta.repository_url.clone(),
                );
            }

            let mut provenance = provenance_from_metadata(&meta);
            provenance.package_existence = PackageExistence::Exists;
            (
                ApiSignals::Available { provenance },
                PackageExistence::Exists,
            )
        }
        Err(FetchError::NotFound) => (
            ApiSignals::unavailable(FetchError::NotFound.reason()),
            PackageExistence::NotFound,
        ),
        Err(error @ FetchError::VersionNotFound(_)) => (
            ApiSignals::unavailable(error.reason()),
            PackageExistence::Exists,
        ),
        Err(e) => (
            ApiSignals::unavailable(e.reason()),
            PackageExistence::Unknown,
        ),
    }
}

/// Turn normalized [`RegistryMetadata`] into the [`ApiProvenance`] signal
/// booleans the factor model consumes. Pure (no I/O beyond `now`-derived ages).
pub fn provenance_from_metadata(meta: &RegistryMetadata) -> ApiProvenance {
    let now = unix_now();

    let package_age_days = meta
        .created_unix
        .map(|t| now.saturating_sub(t) / SECONDS_PER_DAY);
    let latest_version_age_days = meta
        .selected_version_unix
        .or(meta.latest_version_unix)
        .map(|t| now.saturating_sub(t) / SECONDS_PER_DAY);

    // Ownership signal — assessed only when the registry exposes maintainers
    // (`Some`). One document carries the current set, not history, so a transfer
    // can't be proven; the real red flag is an ESTABLISHED package the registry
    // lists with ZERO owners (a very new ownerless package is just new). When
    // the API carries no maintainer field (PyPI/crates.io → `None`), this stays
    // `None` (honestly unknown), never a false `Some(true)`.
    let ownership_transferred = match &meta.maintainers {
        None => None,
        Some(list) => match (list.is_empty(), package_age_days) {
            (true, Some(age)) if age > VERY_NEW_PACKAGE_DAYS => Some(true),
            (true, None) => None, // ownerless but age unknown — cannot judge
            _ => Some(false),
        },
    };

    let selected_or_latest = meta
        .selected_version
        .as_ref()
        .or(meta.latest_version.as_ref());
    let version_spike = match (selected_or_latest, &meta.previous_version) {
        (Some(latest), Some(prev)) => Some(is_version_spike(prev, latest)),
        _ => None,
    };

    // `None` (no repository field) is distinct from `Some(false)` (field
    // present, no usable URL).
    let has_source_repo = meta.repository_url.as_deref().map(is_usable_repo_url);

    // Carry the repo URL only when it parses as usable (callers want a fetchable
    // URL, not the raw field).
    let repository_url = meta
        .repository_url
        .as_deref()
        .filter(|u| is_usable_repo_url(u))
        .map(|s| s.to_string());

    #[allow(deprecated)] // M6 ch6 grace period
    ApiProvenance {
        source: meta.source.clone(),
        package_name: meta.package_name.clone(),
        package_age_days,
        latest_version_age_days,
        ownership_transferred,
        version_spike,
        recent_downloads: meta.recent_downloads,
        has_source_repo,
        yanked_or_deprecated: meta.yanked_or_deprecated,
        latest_version: meta
            .selected_version
            .clone()
            .or_else(|| meta.latest_version.clone()),
        install_script_signals: meta.install_script_signals.clone(),
        repository_url,
        npm_dist: meta.npm_dist_facts.clone(),
        ..Default::default()
    }
}

/// `true` when `prev`→`latest` is an abnormal major-version jump of ≥2 (a
/// hijacked release commonly inflates the version to capture a broad range).
fn is_version_spike(prev: &str, latest: &str) -> bool {
    let prev_major = leading_number(prev);
    let latest_major = leading_number(latest);
    match (prev_major, latest_major) {
        (Some(p), Some(l)) => l >= p.saturating_add(2),
        _ => false, // unparseable → no spike
    }
}

/// Parse the leading integer (major component) of a version string.
fn leading_number(v: &str) -> Option<u64> {
    let v = v.trim().strip_prefix('v').unwrap_or(v.trim());
    let digits: String = v.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

/// `true` when a repository URL string looks like a real, usable source link.
/// Rejects empty / whitespace strings and obvious placeholders.
fn is_usable_repo_url(url: &str) -> bool {
    let u = url.trim();
    if u.is_empty() {
        return false;
    }
    let lower = u.to_lowercase();
    // Reject obvious placeholders.
    let placeholders = ["example.com", "your-repo", "todo", "n/a", "none"];
    if placeholders.iter().any(|p| lower.contains(p)) {
        return false;
    }
    // repo-0318: decide from the PARSED URL, never substring matching —
    // `javascript:github.com` or `https://github.com.attacker.invalid` must not
    // count as a usable source repository.
    // A recognized source-host only counts when it is the real host or one of
    // its subdomains.
    fn is_source_host(host: &str) -> bool {
        ["github.com", "gitlab.com", "bitbucket.org"]
            .iter()
            .any(|base| host == *base || host.ends_with(&format!(".{base}")))
    }
    // A host that merely CONTAINS a known forge string (without being that
    // forge or its subdomain) is a suffix-spoof and never a usable source link
    // (repo-0318: `github.com.attacker.invalid`).
    fn spoofs_source_host(host: &str) -> bool {
        ["github.com", "gitlab.com", "bitbucket.org"]
            .iter()
            .any(|base| host.contains(base) && !is_source_host(host))
    }
    // git+<scheme>://…
    let normalized = lower.strip_prefix("git+").unwrap_or(&lower);
    if normalized
        .strip_prefix("https://")
        .or_else(|| normalized.strip_prefix("http://"))
        .or_else(|| normalized.strip_prefix("git://"))
        .or_else(|| normalized.strip_prefix("ssh://"))
        .is_some()
    {
        let Ok(parsed) = url::Url::parse(normalized) else {
            return false;
        };
        return parsed
            .host_str()
            .is_some_and(|host| !host.is_empty() && !spoofs_source_host(host));
    }
    // scp-style git remote: `[user@]host:path` with a real source host.
    if let Some((user_host, _path)) = lower.split_once(':') {
        let host = user_host.rsplit('@').next().unwrap_or(user_host);
        if !host.is_empty() && is_source_host(host) {
            return true;
        }
    }
    // Bare `host/path` shorthand with a real source host as the first segment.
    if let Some(host) = lower.split('/').next() {
        if is_source_host(host) {
            return true;
        }
    }
    false
}

/// Default registry base URLs (the per-registry path is appended in fetchers).
const NPM_BASE: &str = "https://registry.npmjs.org";
const PYPI_BASE: &str = "https://pypi.org";
const CRATES_BASE: &str = "https://crates.io";

/// The production [`RegistryClient`]: a `reqwest` blocking client with a
/// timeout + response-size cap, plus an on-disk TTL cache.
pub struct HttpRegistryClient {
    timeout: Duration,
    /// When `false`, the on-disk cache is bypassed (tests).
    use_cache: bool,
    /// Base URLs, overridable so a test can point the real HTTP path at a mock.
    npm_base: String,
    pypi_base: String,
    crates_base: String,
    /// Production requests enforce Tirith's full destination boundary. The
    /// only false value is the explicit local-mock integration-test factory.
    enforce_destination_guard: bool,
}

impl Default for HttpRegistryClient {
    fn default() -> Self {
        HttpRegistryClient {
            timeout: Duration::from_secs(REQUEST_TIMEOUT_SECS),
            use_cache: true,
            npm_base: NPM_BASE.to_string(),
            pypi_base: PYPI_BASE.to_string(),
            crates_base: CRATES_BASE.to_string(),
            enforce_destination_guard: true,
        }
    }
}

impl HttpRegistryClient {
    /// A client with the default timeout and caching enabled.
    pub fn new() -> Self {
        Self::default()
    }

    /// A client with caching disabled (for tests that must not touch the cache).
    pub fn without_cache() -> Self {
        HttpRegistryClient {
            use_cache: false,
            ..Self::default()
        }
    }

    /// Point all base URLs at `base` and disable the cache — for integration
    /// tests against a local mock server.
    pub fn with_base_url_for_test(base: &str) -> Self {
        HttpRegistryClient {
            use_cache: false,
            npm_base: base.to_string(),
            pypi_base: base.to_string(),
            crates_base: base.to_string(),
            // The private-destination bypass exists only in debug/test builds;
            // release artifacts keep the production SSRF boundary even if a
            // downstream caller reaches this test-oriented constructor.
            enforce_destination_guard: !cfg!(debug_assertions),
            ..Self::default()
        }
    }

    /// GET `url` and return the body, capped at [`MAX_RESPONSE_BYTES`].
    fn get_json_bytes(&self, url: &str) -> Result<Vec<u8>, FetchError> {
        let parsed = url::Url::parse(url).map_err(|e| FetchError::Network(e.to_string()))?;
        if self.enforce_destination_guard {
            crate::url_validate::validate_server_url(url).map_err(FetchError::Network)?;
        }

        let builder = if self.enforce_destination_guard {
            crate::ssrf_guard::server_client_builder()
        } else {
            // Debug/test-only local registry fixtures deliberately bypass the
            // destination guard, but still never inherit ambient proxies.
            reqwest::blocking::Client::builder().no_proxy()
        };
        let client = builder
            .timeout(self.timeout)
            .redirect(registry_redirect_policy(
                &parsed,
                !self.enforce_destination_guard,
            ))
            .build()
            .map_err(|e| FetchError::Network(e.to_string()))?;

        Self::get_json_bytes_with_client(url, &client)
    }

    fn get_json_bytes_with_client(
        url: &str,
        client: &reqwest::blocking::Client,
    ) -> Result<Vec<u8>, FetchError> {
        let resp = client
            .get(url)
            .header(
                "User-Agent",
                format!("tirith/{} (package-risk)", env!("CARGO_PKG_VERSION")),
            )
            .header("Accept", "application/json")
            .send()
            // Connect/timeout/transport all degrade to the offline score.
            .map_err(|e| FetchError::Network(e.to_string()))?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(FetchError::NotFound);
        }
        if !status.is_success() {
            return Err(FetchError::HttpStatus(status.as_u16()));
        }

        // Fast-reject via Content-Length first.
        if let Some(len) = resp.content_length() {
            if len > MAX_RESPONSE_BYTES {
                return Err(FetchError::TooLarge);
            }
        }

        use std::io::Read as _;
        let mut buf = Vec::new();
        resp.take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(|e| FetchError::Network(e.to_string()))?;
        if buf.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(FetchError::TooLarge);
        }
        Ok(buf)
    }

    #[cfg(test)]
    fn get_json_bytes_with_test_client(
        &self,
        url: &str,
        client: &reqwest::blocking::Client,
        validate_initial: &(dyn Fn(&str) -> Result<(), String> + Send + Sync),
    ) -> Result<Vec<u8>, FetchError> {
        validate_initial(url).map_err(FetchError::Network)?;
        Self::get_json_bytes_with_client(url, client)
    }
}

/// Registry metadata redirects are stricter than general server redirects:
/// every target must remain on the exact validated origin. This prevents a
/// public registry (or an open redirect on it) from changing the provenance
/// authority even when the destination itself is public.
fn registry_redirect_policy(
    initial: &url::Url,
    allow_private_test_base: bool,
) -> reqwest::redirect::Policy {
    registry_redirect_policy_with_validator(
        initial,
        allow_private_test_base,
        crate::url_validate::validate_server_url,
    )
}

fn registry_redirect_policy_with_validator<Validate>(
    initial: &url::Url,
    allow_private_test_base: bool,
    validate_target: Validate,
) -> reqwest::redirect::Policy
where
    Validate: Fn(&str) -> Result<(), String> + Send + Sync + 'static,
{
    let initial = initial.clone();
    reqwest::redirect::Policy::custom(
        move |attempt| match registry_redirect_decision_with_validator(
            &initial,
            attempt.url(),
            attempt.previous().len(),
            allow_private_test_base,
            &validate_target,
        ) {
            Ok(()) => attempt.follow(),
            Err(reason) => attempt.error(reason),
        },
    )
}

#[cfg(test)]
fn registry_redirect_decision(
    initial: &url::Url,
    target: &url::Url,
    prior_hops: usize,
    allow_private_test_base: bool,
) -> Result<(), String> {
    registry_redirect_decision_with_validator(
        initial,
        target,
        prior_hops,
        allow_private_test_base,
        &crate::url_validate::validate_server_url,
    )
}

fn registry_redirect_decision_with_validator<Validate>(
    initial: &url::Url,
    target: &url::Url,
    prior_hops: usize,
    allow_private_test_base: bool,
    validate_target: &Validate,
) -> Result<(), String>
where
    Validate: Fn(&str) -> Result<(), String> + ?Sized,
{
    const MAX_REDIRECTS: usize = 5;
    if prior_hops >= MAX_REDIRECTS {
        return Err("too many registry redirects".to_string());
    }
    // The origin comparison runs FIRST, and the ordering is load-bearing.
    // `validate_target` resolves the host over DNS, while `target` is
    // attacker-influenced text (a redirect `Location`, or a packument's
    // `dist.tarball`). Validating first turned every off-origin host into a
    // live lookup against the attacker's own nameserver: an out-of-band beacon,
    // with an attacker-chosen label as payload, for a URL this function rejects
    // on the very next line. Comparing first is pure and costs nothing.
    // Targets that pass the origin rule are still fully validated below, so
    // this is strictly a narrowing of what gets contacted.
    let same_origin = initial.scheme() == target.scheme()
        && initial.host_str().map(str::to_ascii_lowercase)
            == target.host_str().map(str::to_ascii_lowercase)
        && initial.port_or_known_default() == target.port_or_known_default();
    if !same_origin {
        return Err("registry redirect changed the validated origin".to_string());
    }
    if !allow_private_test_base {
        validate_target(target.as_str())?;
    }
    Ok(())
}

#[cfg(test)]
fn registry_client_with_resolver_for_test(
    initial: &url::Url,
    resolver: std::sync::Arc<crate::ssrf_guard::SsrfGuardResolver>,
    validate_target: RegistryUrlValidator,
) -> Result<reqwest::blocking::Client, FetchError> {
    let redirect_validator = std::sync::Arc::clone(&validate_target);
    crate::ssrf_guard::server_client_builder_with_resolver_for_test(resolver)
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .redirect(registry_redirect_policy_with_validator(
            initial,
            false,
            move |target| redirect_validator(target),
        ))
        .build()
        .map_err(|error| FetchError::Network(error.to_string()))
}

impl RegistryClient for HttpRegistryClient {
    fn fetch(&self, ecosystem: Ecosystem, name: &str) -> Result<RegistryMetadata, FetchError> {
        self.fetch_version(ecosystem, name, None)
    }

    fn fetch_exact(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
    ) -> Result<RegistryMetadata, FetchError> {
        self.fetch_version(ecosystem, name, Some(version))
    }
}

impl HttpRegistryClient {
    fn fetch_version(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        exact_version: Option<&str>,
    ) -> Result<RegistryMetadata, FetchError> {
        // Reject an unsafe name BEFORE any URL is built. `name` can come from
        // untrusted manifest content (`ecosystem scan --online`), and a `..`
        // segment would be normalized into a GET against an arbitrary same-host
        // path — a path-traversal sink.
        if !is_safe_registry_name(name) {
            return Err(FetchError::InvalidName);
        }

        if self.use_cache {
            if let Some(cached) = load_cache(ecosystem, name, exact_version) {
                // Cache entries written before package-identity binding have no
                // native name. Ignore them and refresh instead of treating a
                // path-key match as proof about the cached response body.
                if metadata_identity_matches(&cached, ecosystem, name) {
                    return Ok(cached);
                }
            }
        }

        let meta = match ecosystem {
            Ecosystem::Npm => fetch_npm(self, name, exact_version)?,
            Ecosystem::PyPI => fetch_pypi(self, name, exact_version)?,
            Ecosystem::Crates => fetch_crates(self, name, exact_version)?,
            other => return Err(FetchError::UnsupportedEcosystem(other)),
        };

        if self.use_cache {
            store_cache(ecosystem, name, exact_version, &meta);
        }
        Ok(meta)
    }
}

// --- npm registry ----------------------------------------------------------

/// Fetch and normalize an npm "full" package document (`time`, `versions`,
/// `maintainers`, `dist-tags.latest`, per-version `deprecated`).
fn fetch_npm(
    client: &HttpRegistryClient,
    name: &str,
    exact_version: Option<&str>,
) -> Result<RegistryMetadata, FetchError> {
    let url = format!("{}/{}", client.npm_base, url_path_segment(name));
    let bytes = client.get_json_bytes(&url)?;
    let doc: NpmDoc =
        serde_json::from_slice(&bytes).map_err(|e| FetchError::BadResponse(e.to_string()))?;
    if !registry_names_match(Ecosystem::Npm, name, &doc.name) {
        return Err(FetchError::BadResponse(format!(
            "npm response identified package '{}' instead of '{}'",
            doc.name, name
        )));
    }

    let latest_version = doc
        .dist_tags
        .as_ref()
        .and_then(|d| d.latest.clone())
        .or_else(|| newest_version_key(doc.versions.keys()));

    let created_unix = doc
        .time
        .as_ref()
        .and_then(|t| t.get("created"))
        .and_then(|s| parse_rfc3339_to_unix(s));
    let latest_version_unix = latest_version
        .as_ref()
        .and_then(|v| doc.time.as_ref().and_then(|t| t.get(v)))
        .and_then(|s| parse_rfc3339_to_unix(s));

    let selected_version = exact_version
        .map(str::to_string)
        .or_else(|| latest_version.clone());
    let selected_record = selected_version.as_ref().and_then(|v| doc.versions.get(v));
    if exact_version.is_some() && selected_record.is_none() {
        return Err(FetchError::VersionNotFound(
            exact_version.unwrap_or_default().to_string(),
        ));
    }
    let selected_version_unix = selected_version
        .as_ref()
        .and_then(|v| doc.time.as_ref().and_then(|t| t.get(v)))
        .and_then(|s| parse_rfc3339_to_unix(s));
    let previous_version = selected_version
        .as_ref()
        .and_then(|selected| previous_version_key(doc.versions.keys(), selected));

    // Deprecated when the selected version object has a non-empty marker.
    let yanked_or_deprecated = selected_record
        .map(NpmVersion::deprecated_present)
        .unwrap_or(false);
    let install_script_signals = selected_record.map(NpmVersion::install_script_signals);
    let npm_dist_facts = selected_record.and_then(|record| {
        npm_dist_facts_from_record(record, &client.npm_base, !client.enforce_destination_guard)
    });

    let repository_url = doc.repository.as_ref().and_then(|r| r.url_field());

    Ok(RegistryMetadata {
        source: "npm".to_string(),
        package_name: Some(canonical_registry_name(Ecosystem::Npm, &doc.name)),
        created_unix,
        latest_version_unix,
        latest_version,
        selected_version,
        selected_version_unix,
        previous_version,
        // npm exposes `maintainers` → `Some` (an empty list is a real signal).
        maintainers: Some(doc.maintainers.into_iter().filter_map(|m| m.name).collect()),
        // Download counts are a separate endpoint; no second request.
        recent_downloads: None,
        repository_url,
        yanked_or_deprecated,
        install_script_signals,
        npm_dist_facts,
    })
}

/// Build the C13 provenance facts for one release record.
///
/// The only active check here is the tarball URL's ORIGIN. Tirith never fetches
/// a tarball, but it does display the URL and a receipt may record it, so a
/// packument that points its `dist.tarball` at a different host, a private or
/// loopback address, or a plain-http scheme must not have that value pass
/// through as if the registry vouched for it. The origin rule is the same one
/// `registry_redirect_decision_with_validator` applies to a redirect: exact
/// scheme + host + port match against the validated packument origin, plus
/// `validate_server_url` on the target.
///
/// Returns `None` for a record with no `dist` object at all. That is a response
/// shape Tirith never inspected, not a release with nothing published, and
/// rendering it as a row of "not published" lines would state a fact about the
/// registry that the response never carried.
fn npm_dist_facts_from_record(
    record: &NpmVersion,
    registry_base: &str,
    allow_private_test_base: bool,
) -> Option<crate::provenance::npm_facts::NpmDistFacts> {
    use crate::provenance::npm_facts::{
        attestation_state_from_presence, signature_state_from_entries, NpmDistFacts, SriDigest,
    };

    let dist = record.dist.as_ref()?;

    let mut facts = NpmDistFacts::default();
    let base = url::Url::parse(registry_base).ok();
    facts.registry_origin = base.as_ref().map(registry_origin_display);

    let published_integrity = dist
        .integrity
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    facts.integrity_sri = published_integrity.and_then(SriDigest::parse);
    facts.integrity_unparsed = published_integrity.is_some() && facts.integrity_sri.is_none();
    facts.legacy_shasum_present = dist
        .shasum
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());

    let key_ids: Vec<String> = dist
        .signatures
        .iter()
        .filter_map(|entry| entry.keyid.clone())
        .collect();
    // The ENTRY count, not the key-id count: a signature published without a
    // `keyid` is still a published signature.
    let (signature_state, signature_key_ids) =
        signature_state_from_entries(dist.signatures.len(), &key_ids);
    facts.signature_state = signature_state;
    facts.signature_key_ids = signature_key_ids;
    facts.attestation_state = attestation_state_from_presence(
        dist.attestations
            .as_ref()
            .is_some_and(|value| !value.is_null()),
    );

    if let Some(raw) = dist.tarball.as_deref() {
        match validate_registry_bound_tarball(raw, base.as_ref(), allow_private_test_base) {
            Ok(url) => facts.tarball_url = Some(url),
            Err(reason) => {
                facts.tarball_url_rejected = true;
                facts.tarball_rejection_reason = Some(reason);
            }
        }
    }

    Some(facts)
}

/// `scheme://host[:port]` for display, with no path or credentials.
fn registry_origin_display(base: &url::Url) -> String {
    match base.port() {
        Some(port) => format!(
            "{}://{}:{port}",
            base.scheme(),
            base.host_str().unwrap_or_default()
        ),
        None => format!(
            "{}://{}",
            base.scheme(),
            base.host_str().unwrap_or_default()
        ),
    }
}

fn validate_registry_bound_tarball(
    raw: &str,
    base: Option<&url::Url>,
    allow_private_test_base: bool,
) -> Result<String, String> {
    let accepted = crate::provenance::npm_facts::accept_tarball_url(raw)
        .ok_or_else(|| "tarball URL is empty or over the retention cap".to_string())?;
    let target =
        url::Url::parse(&accepted).map_err(|_| "tarball URL is not a valid URL".to_string())?;
    let base = base.ok_or_else(|| "the registry base URL could not be parsed".to_string())?;
    // The redirect decision is reused verbatim rather than re-implemented so a
    // future tightening of the origin rule applies to both at once. A tarball
    // URL is a first hop, hence `prior_hops = 0`.
    registry_redirect_decision_with_validator(
        base,
        &target,
        0,
        allow_private_test_base,
        &crate::url_validate::validate_server_url,
    )
    .map_err(|reason| format!("tarball URL rejected: {reason}"))?;
    Ok(accepted)
}

#[derive(Debug, Deserialize)]
struct NpmDoc {
    name: String,
    #[serde(rename = "dist-tags")]
    dist_tags: Option<NpmDistTags>,
    #[serde(default)]
    time: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default)]
    versions: std::collections::BTreeMap<String, NpmVersion>,
    #[serde(default)]
    maintainers: Vec<NpmMaintainer>,
    repository: Option<NpmRepository>,
}

#[derive(Debug, Deserialize)]
struct NpmDistTags {
    latest: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NpmVersion {
    /// `deprecated` is `false`/absent normally, or a string message when set.
    deprecated: Option<serde_json::Value>,
    #[serde(default)]
    scripts: std::collections::BTreeMap<String, String>,
    /// npm's normalized manifest marks packages that carry a root
    /// `binding.gyp`. Unless the package defines its own `install` or
    /// `preinstall`, npm synthesizes `node-gyp rebuild` at install time.
    #[serde(default)]
    gypfile: Option<bool>,
    /// C13: the release's `dist` object. Absent on a minimal/abbreviated
    /// packument, which is a real "no signal", not a zero value.
    #[serde(default)]
    dist: Option<NpmDist>,
}

/// The `dist` object of one npm release record. Every field is optional
/// because a registry mirror may omit any of them, and an omitted field must
/// read as "not published", never as a failed check.
#[derive(Debug, Deserialize)]
struct NpmDist {
    #[serde(default)]
    tarball: Option<String>,
    #[serde(default)]
    integrity: Option<String>,
    /// npm's legacy SHA-1 of the tarball. Display status only.
    #[serde(default)]
    shasum: Option<String>,
    #[serde(default)]
    signatures: Vec<NpmDistSignature>,
    /// Present when the release carries a Sigstore provenance bundle. The
    /// pointer is NOT followed: fetching it would mean requesting a host the
    /// packument named, and the bundle could not be verified on this MSRV.
    #[serde(default)]
    attestations: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct NpmDistSignature {
    #[serde(default)]
    keyid: Option<String>,
}

impl NpmVersion {
    fn deprecated_present(&self) -> bool {
        match &self.deprecated {
            None => false,
            Some(serde_json::Value::Bool(b)) => *b,
            Some(serde_json::Value::String(s)) => !s.trim().is_empty(),
            Some(serde_json::Value::Null) => false,
            Some(_) => true,
        }
    }

    fn install_script_signals(&self) -> InstallScriptSignals {
        let mut script_text = String::new();
        for hook in ["preinstall", "install", "postinstall", "prepare"] {
            if let Some(body) = self.scripts.get(hook) {
                if !body.trim().is_empty() {
                    script_text.push_str(body);
                    script_text.push('\n');
                }
            }
        }
        let overrides_implicit_gyp = ["preinstall", "install"].iter().any(|hook| {
            self.scripts
                .get(*hook)
                // npm's defaulting logic uses JavaScript truthiness, so a
                // whitespace-only string suppresses the implicit hook while
                // an empty string does not.
                .is_some_and(|body| !body.is_empty())
        });
        if self.gypfile == Some(true) && !overrides_implicit_gyp {
            // This is executable lifecycle behavior even though the packument's
            // `scripts` map is empty. Record it explicitly instead of returning
            // `Some(clean)` for native-addon releases such as heapdump@0.3.8.
            script_text.push_str("node-gyp rebuild\n");
        }
        crate::install_script_analysis::analyze_script_text(&script_text)
    }
}

#[derive(Debug, Deserialize)]
struct NpmMaintainer {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum NpmRepository {
    /// `"repository": "github:owner/repo"` or a bare URL string.
    Str(String),
    /// `"repository": { "type": "git", "url": "..." }`.
    Obj { url: Option<String> },
}

impl NpmRepository {
    fn url_field(&self) -> Option<String> {
        match self {
            NpmRepository::Str(s) => Some(s.clone()),
            NpmRepository::Obj { url } => url.clone(),
        }
    }
}

// --- PyPI JSON API ---------------------------------------------------------

/// Fetch and normalize from the PyPI JSON API (`info` with `version`/`yanked`/
/// `project_urls`, and a `releases` map of file records with upload times).
fn fetch_pypi(
    client: &HttpRegistryClient,
    name: &str,
    exact_version: Option<&str>,
) -> Result<RegistryMetadata, FetchError> {
    let url = format!("{}/pypi/{}/json", client.pypi_base, url_path_segment(name));
    let bytes = client.get_json_bytes(&url)?;
    let doc: PypiDoc =
        serde_json::from_slice(&bytes).map_err(|e| FetchError::BadResponse(e.to_string()))?;
    if !registry_names_match(Ecosystem::PyPI, name, &doc.info.name) {
        return Err(FetchError::BadResponse(format!(
            "PyPI response identified package '{}' instead of '{}'",
            doc.info.name, name
        )));
    }

    let latest_version = doc.info.version.clone();
    let selected_version = exact_version
        .map(str::to_string)
        .or_else(|| latest_version.clone());
    // Tirith stores PEP 440 exact intent under its comparison identity (for
    // example `2.31.0` and `2.31` compare equal), while the PyPI document keeps
    // the registry's concrete release-key spelling. Bind the request to one
    // unique equivalent key instead of requiring lossy string equality.
    let selected_release_key = match exact_version {
        Some(version) => matching_pypi_release_key(doc.releases.keys(), version)?
            .ok_or_else(|| FetchError::VersionNotFound(version.to_string()))?,
        None => latest_version.clone().unwrap_or_default(),
    };

    // First publication = earliest upload time across all releases.
    let mut earliest: Option<u64> = None;
    let mut latest_ver_unix: Option<u64> = None;
    let mut selected_ver_unix: Option<u64> = None;
    for (ver, files) in &doc.releases {
        for f in files {
            if let Some(t) = f
                .upload_time_iso_8601
                .as_deref()
                .and_then(parse_rfc3339_to_unix)
            {
                earliest = Some(earliest.map_or(t, |e| e.min(t)));
                if Some(ver) == latest_version.as_ref() {
                    latest_ver_unix = Some(latest_ver_unix.map_or(t, |e| e.max(t)));
                }
                if ver == &selected_release_key {
                    selected_ver_unix = Some(selected_ver_unix.map_or(t, |e| e.max(t)));
                }
            }
        }
    }

    let previous_version = previous_version_key(doc.releases.keys(), &selected_release_key);

    // Yanked when `info.yanked`, or every file of the latest release is yanked.
    let selected_files_yanked = doc
        .releases
        .get(&selected_release_key)
        .map(|files| !files.is_empty() && files.iter().all(|f| f.yanked.unwrap_or(false)))
        .unwrap_or(false);
    let yanked_or_deprecated = if exact_version.is_some() {
        selected_files_yanked
    } else {
        doc.info.yanked.unwrap_or(false) || selected_files_yanked
    };

    // Prefer a `project_urls` entry naming a source repo; fall back to home_page.
    let repository_url = doc
        .info
        .project_urls
        .as_ref()
        .and_then(pick_repo_url)
        .or_else(|| doc.info.home_page.clone());

    Ok(RegistryMetadata {
        source: "pypi".to_string(),
        package_name: Some(canonical_registry_name(Ecosystem::PyPI, &doc.info.name)),
        created_unix: earliest,
        latest_version_unix: latest_ver_unix,
        latest_version,
        selected_version,
        selected_version_unix: selected_ver_unix,
        previous_version,
        // PyPI's JSON API exposes no maintainers / downloads → `None` (unknown).
        maintainers: None,
        recent_downloads: None,
        repository_url,
        yanked_or_deprecated,
        install_script_signals: None,
        // npm-only provenance facts.
        npm_dist_facts: None,
    })
}

#[derive(Debug, Deserialize)]
struct PypiDoc {
    info: PypiInfo,
    #[serde(default)]
    releases: std::collections::BTreeMap<String, Vec<PypiFile>>,
}

#[derive(Debug, Deserialize)]
struct PypiInfo {
    name: String,
    version: Option<String>,
    yanked: Option<bool>,
    home_page: Option<String>,
    project_urls: Option<std::collections::BTreeMap<String, String>>,
}

/// Resolve one exact PEP 440 comparison identity to the registry document's
/// concrete release key. Multiple equivalent keys are an ambiguous response
/// and therefore fail closed rather than choosing attacker-controlled order.
fn matching_pypi_release_key<'a, I>(keys: I, requested: &str) -> Result<Option<String>, FetchError>
where
    I: Iterator<Item = &'a String>,
{
    let Some(requested) = crate::version_intent::canonical_pep440_version(requested) else {
        return Ok(None);
    };
    let mut matched = None;
    for key in keys {
        if crate::version_intent::canonical_pep440_version(key).as_ref() == Some(&requested) {
            if matched.is_some() {
                return Err(FetchError::BadResponse(
                    "PyPI response contained ambiguous equivalent release keys".to_string(),
                ));
            }
            matched = Some(key.clone());
        }
    }
    Ok(matched)
}

#[derive(Debug, Deserialize)]
struct PypiFile {
    upload_time_iso_8601: Option<String>,
    yanked: Option<bool>,
}

/// Pick a source-repo URL from `project_urls`: prefer a repo-named key, else any
/// GitHub/GitLab-looking value.
fn pick_repo_url(urls: &std::collections::BTreeMap<String, String>) -> Option<String> {
    const REPO_KEYS: &[&str] = &["source", "repository", "code", "github", "source code"];
    for (k, v) in urls {
        if REPO_KEYS.iter().any(|rk| k.to_lowercase().contains(rk)) {
            return Some(v.clone());
        }
    }
    for v in urls.values() {
        let lv = v.to_lowercase();
        if lv.contains("github.com") || lv.contains("gitlab.com") || lv.contains("bitbucket.org") {
            return Some(v.clone());
        }
    }
    None
}

// --- crates.io API ---------------------------------------------------------

/// Fetch and normalize a crate from the crates.io API (a `crate` object +
/// `versions` array of `{num, created_at, yanked}`).
fn fetch_crates(
    client: &HttpRegistryClient,
    name: &str,
    exact_version: Option<&str>,
) -> Result<RegistryMetadata, FetchError> {
    let url = format!(
        "{}/api/v1/crates/{}",
        client.crates_base,
        url_path_segment(name)
    );
    let bytes = client.get_json_bytes(&url)?;
    let doc: CratesDoc =
        serde_json::from_slice(&bytes).map_err(|e| FetchError::BadResponse(e.to_string()))?;
    if !registry_names_match(Ecosystem::Crates, name, &doc.krate.id) {
        return Err(FetchError::BadResponse(format!(
            "crates.io response identified package '{}' instead of '{}'",
            doc.krate.id, name
        )));
    }

    let created_unix = doc
        .krate
        .created_at
        .as_deref()
        .and_then(parse_rfc3339_to_unix);

    let latest_version = doc.krate.newest_version.clone();
    let selected_version = exact_version
        .map(str::to_string)
        .or_else(|| latest_version.clone());

    // Latest version's publish time + yanked flag from `versions`.
    let latest_ver = latest_version
        .as_ref()
        .and_then(|v| doc.versions.iter().find(|cv| cv.num.as_ref() == Some(v)));
    let latest_version_unix = latest_ver
        .and_then(|cv| cv.created_at.as_deref())
        .and_then(parse_rfc3339_to_unix);
    let yanked_or_deprecated = latest_ver
        .map(|cv| cv.yanked.unwrap_or(false))
        .unwrap_or(false);
    let selected_ver = selected_version
        .as_ref()
        .and_then(|v| doc.versions.iter().find(|cv| cv.num.as_ref() == Some(v)));
    if exact_version.is_some() && selected_ver.is_none() {
        return Err(FetchError::VersionNotFound(
            exact_version.unwrap_or_default().to_string(),
        ));
    }
    let selected_version_unix = selected_ver
        .and_then(|cv| cv.created_at.as_deref())
        .and_then(parse_rfc3339_to_unix);
    let yanked_or_deprecated = selected_ver
        .map(|cv| cv.yanked.unwrap_or(false))
        .unwrap_or(yanked_or_deprecated);

    let previous_version = selected_version.as_ref().and_then(|selected| {
        previous_version_key(
            doc.versions.iter().filter_map(|cv| cv.num.as_ref()),
            selected,
        )
    });

    Ok(RegistryMetadata {
        source: "crates.io".to_string(),
        package_name: Some(canonical_registry_name(Ecosystem::Crates, &doc.krate.id)),
        created_unix,
        latest_version_unix,
        latest_version,
        selected_version,
        selected_version_unix,
        previous_version,
        // Owners are a separate endpoint → `maintainers: None` (unknown).
        maintainers: None,
        recent_downloads: doc.krate.downloads,
        repository_url: doc.krate.repository,
        yanked_or_deprecated,
        install_script_signals: None,
        // npm-only provenance facts.
        npm_dist_facts: None,
    })
}

#[derive(Debug, Deserialize)]
struct CratesDoc {
    #[serde(rename = "crate")]
    krate: CratesCrate,
    #[serde(default)]
    versions: Vec<CratesVersion>,
}

#[derive(Debug, Deserialize)]
struct CratesCrate {
    id: String,
    created_at: Option<String>,
    newest_version: Option<String>,
    downloads: Option<u64>,
    repository: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CratesVersion {
    num: Option<String>,
    created_at: Option<String>,
    yanked: Option<bool>,
}

// ===========================================================================
// shared helpers
// ===========================================================================

/// Registry-native canonical package identity. PyPI follows PEP 503 by
/// lowercasing and collapsing runs of `-`, `_`, and `.`. npm and crates.io
/// identities are compared case-insensitively but otherwise remain distinct.
pub(crate) fn canonical_registry_name(ecosystem: Ecosystem, name: &str) -> String {
    match ecosystem {
        Ecosystem::PyPI => {
            let mut normalized = String::with_capacity(name.len());
            let mut in_separator = false;
            for ch in name.chars().flat_map(char::to_lowercase) {
                if matches!(ch, '-' | '_' | '.') {
                    if !in_separator {
                        normalized.push('-');
                    }
                    in_separator = true;
                } else {
                    normalized.push(ch);
                    in_separator = false;
                }
            }
            normalized
        }
        Ecosystem::Npm | Ecosystem::Crates => name.to_ascii_lowercase(),
        _ => name.to_string(),
    }
}

fn registry_names_match(ecosystem: Ecosystem, requested: &str, returned: &str) -> bool {
    canonical_registry_name(ecosystem, requested) == canonical_registry_name(ecosystem, returned)
}

fn metadata_identity_matches(
    metadata: &RegistryMetadata,
    ecosystem: Ecosystem,
    requested: &str,
) -> bool {
    metadata
        .package_name
        .as_deref()
        .is_some_and(|returned| registry_names_match(ecosystem, requested, returned))
}

/// Whether `name` can be safely interpolated into a registry URL path. A
/// SECURITY gate (not a full validator): rejects a `.`/`..` segment (which a
/// URL library would collapse into a same-host traversal), an empty segment,
/// and any `/` except a single one on an npm scope (`@scope/pkg`). A passing
/// name still goes through [`url_path_segment`].
fn is_safe_registry_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let slash_count = name.matches('/').count();
    if slash_count > 1 {
        return false;
    }
    // A single `/` is allowed only for an npm scope.
    if slash_count == 1 && !name.starts_with('@') {
        return false;
    }
    // No empty segment, no `.`/`..` relative component.
    name.split('/')
        .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// Percent-encode a name as a URL path segment (scoped npm names keep their
/// `/`). PRECONDITION: `name` has passed [`is_safe_registry_name`] — this does
/// NOT collapse `..`, so an unvalidated name would leave a traversal intact.
fn url_path_segment(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        match ch {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' | '/' | '@' => out.push(ch),
            _ => {
                let mut buf = [0u8; 4];
                for b in ch.encode_utf8(&mut buf).bytes() {
                    out.push_str(&format!("%{b:02X}"));
                }
            }
        }
    }
    out
}

/// Parse an RFC-3339 timestamp to Unix epoch seconds.
fn parse_rfc3339_to_unix(s: &str) -> Option<u64> {
    let dt = chrono::DateTime::parse_from_rfc3339(s.trim()).ok()?;
    let secs = dt.timestamp();
    if secs < 0 {
        None
    } else {
        Some(secs as u64)
    }
}

/// Greatest version key by `(major, minor, patch)` — a best-effort "newest"
/// when the registry gives no explicit latest tag.
fn newest_version_key<'a, I: Iterator<Item = &'a String>>(keys: I) -> Option<String> {
    keys.max_by(|a, b| version_tuple(a).cmp(&version_tuple(b)))
        .cloned()
}

/// The version key immediately below `latest` (the previous release).
fn previous_version_key<'a, I: Iterator<Item = &'a String>>(
    keys: I,
    latest: &str,
) -> Option<String> {
    let latest_t = version_tuple(latest);
    keys.filter(|k| version_tuple(k) < latest_t)
        .max_by(|a, b| version_tuple(a).cmp(&version_tuple(b)))
        .cloned()
}

/// Decompose a version into a comparable `(major, minor, patch)` (unparseable
/// components → 0, so comparison is total).
fn version_tuple(v: &str) -> (u64, u64, u64) {
    let v = v.trim().strip_prefix('v').unwrap_or(v.trim());
    let mut it = v.split(['.', '-', '+']);
    let major = it.next().and_then(parse_leading_u64).unwrap_or(0);
    let minor = it.next().and_then(parse_leading_u64).unwrap_or(0);
    let patch = it.next().and_then(parse_leading_u64).unwrap_or(0);
    (major, minor, patch)
}

fn parse_leading_u64(s: &str) -> Option<u64> {
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

// on-disk cache (mirrors threatdb_api.rs)

#[derive(Debug, Serialize, Deserialize)]
struct CacheEnvelope {
    fetched_at: u64,
    value: RegistryMetadata,
}

/// Cache file path for a package, under the tirith state dir.
fn cache_path(ecosystem: Ecosystem, name: &str, exact_version: Option<&str>) -> Option<PathBuf> {
    let state = policy::state_dir()?;
    let key = format!("{ecosystem}:{name}:{}", exact_version.unwrap_or("<latest>"));
    let digest = sha2::Sha256::digest(key.as_bytes());
    let hex: String = hex::encode(&digest[..16]);
    Some(
        state
            .join("registry-api-cache")
            .join(format!("pkg-{hex}.json")),
    )
}

/// Load a cached `RegistryMetadata` if one exists and is within the TTL.
fn load_cache(
    ecosystem: Ecosystem,
    name: &str,
    exact_version: Option<&str>,
) -> Option<RegistryMetadata> {
    let path = cache_path(ecosystem, name, exact_version)?;
    let content = std::fs::read_to_string(path).ok()?;
    let envelope: CacheEnvelope = serde_json::from_str(&content).ok()?;
    if unix_now().saturating_sub(envelope.fetched_at) > CACHE_TTL_SECS {
        return None;
    }
    Some(envelope.value)
}

/// Store a fetched `RegistryMetadata` in the cache. Best-effort (I/O errors
/// ignored — the cache is a performance convenience).
fn store_cache(
    ecosystem: Ecosystem,
    name: &str,
    exact_version: Option<&str>,
    value: &RegistryMetadata,
) {
    let Some(path) = cache_path(ecosystem, name, exact_version) else {
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
        value: value.clone(),
    };
    let parent_owned = parent.to_path_buf();
    if let Ok(serialized) = serde_json::to_vec(&envelope) {
        let _ = std::fs::write(path, serialized);
    }
    evict_stale_cache_once(&parent_owned);
}

static EVICTION_RAN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Purge cache files older than [`CACHE_EVICT_MAX_AGE_SECS`], at most once per
/// process (stat-only scan).
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
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| now.saturating_sub(d.as_secs()))
            .unwrap_or(0);
        if age > CACHE_EVICT_MAX_AGE_SECS {
            let _ = std::fs::remove_file(&path);
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package_risk::LOW_DOWNLOAD_THRESHOLD;

    fn public_server_validator(expected_host: &'static str) -> RegistryUrlValidator {
        std::sync::Arc::new(move |candidate| {
            crate::url_validate::validate_server_url_with_resolver_for_test(
                candidate,
                &|host, _| {
                    if host != expected_host {
                        return Err(format!("unexpected validation host: {host}"));
                    }
                    Ok(vec!["93.184.216.34".parse().unwrap()])
                },
            )
        })
    }

    fn request_error_messages(error: &reqwest::Error) -> Vec<String> {
        use std::error::Error as _;

        let mut messages = vec![error.to_string()];
        let mut source = error.source();
        while let Some(cause) = source {
            messages.push(cause.to_string());
            source = cause.source();
        }
        messages
    }

    /// A fixture-fed [`RegistryClient`] — no network.
    struct FakeClient {
        result: Result<RegistryMetadata, FetchError>,
    }

    impl RegistryClient for FakeClient {
        fn fetch(
            &self,
            _ecosystem: Ecosystem,
            _name: &str,
        ) -> Result<RegistryMetadata, FetchError> {
            self.result.clone()
        }
    }

    fn meta_clean() -> RegistryMetadata {
        RegistryMetadata {
            source: "npm".to_string(),
            package_name: Some("react".to_string()),
            created_unix: Some(unix_now() - 3650 * SECONDS_PER_DAY),
            latest_version_unix: Some(unix_now() - 365 * SECONDS_PER_DAY),
            latest_version: Some("4.18.2".to_string()),
            previous_version: Some("4.18.1".to_string()),
            maintainers: Some(vec!["alice".to_string()]),
            recent_downloads: Some(5_000_000),
            repository_url: Some("https://github.com/owner/repo".to_string()),
            yanked_or_deprecated: false,
            ..Default::default()
        }
    }

    #[test]
    fn gather_available_on_success() {
        let client = FakeClient {
            result: Ok(meta_clean()),
        };
        let (sig, existence) = gather_api_signals(&client, Ecosystem::Npm, "react");
        assert!(matches!(sig, ApiSignals::Available { .. }));
        assert_eq!(existence, PackageExistence::Exists);
    }

    #[test]
    fn gather_unavailable_on_network_error() {
        let client = FakeClient {
            result: Err(FetchError::Network("connection refused".to_string())),
        };
        let (sig, existence) = gather_api_signals(&client, Ecosystem::Npm, "react");
        match sig {
            ApiSignals::Unavailable { reason } => {
                assert!(reason.contains("connection refused"));
            }
            other => panic!("expected Unavailable, got {other:?}"),
        }
        assert_eq!(existence, PackageExistence::Unknown);
    }

    #[test]
    fn gather_unavailable_on_not_found_sets_existence_not_found() {
        let client = FakeClient {
            result: Err(FetchError::NotFound),
        };
        let (sig, existence) = gather_api_signals(&client, Ecosystem::Npm, "nope");
        assert!(matches!(sig, ApiSignals::Unavailable { .. }));
        assert_eq!(
            existence,
            PackageExistence::NotFound,
            "404 must surface as NotFound, distinct from Unknown"
        );
    }

    #[test]
    fn name_existence_validates_identity_without_recording_registry_history() {
        use crate::ssrf_guard::test_support::EnvironmentRestore;

        let _environment = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = tempfile::tempdir().unwrap();
        let mut restore = EnvironmentRestore::new();
        restore.set(
            "XDG_STATE_HOME",
            Some(state.path().to_str().expect("UTF-8 temp state path")),
        );

        let client = FakeClient {
            result: Ok(meta_clean()),
        };
        assert_eq!(
            gather_name_existence(&client, Ecosystem::Npm, "react"),
            PackageExistence::Exists
        );
        assert!(
            !state.path().join("tirith/registry_snapshots").exists(),
            "an existence-only lookup must not create registry-history state"
        );

        let mut mismatched = meta_clean();
        mismatched.package_name = Some("replacement".to_string());
        let client = FakeClient {
            result: Ok(mismatched),
        };
        assert_eq!(
            gather_name_existence(&client, Ecosystem::Npm, "react"),
            PackageExistence::Unknown,
            "a successful response for another package cannot prove existence"
        );
    }

    #[test]
    fn exact_lookup_never_reuses_different_latest_version() {
        let mut metadata = meta_clean();
        metadata.latest_version = Some("2.0.0".to_string());
        let client = FakeClient {
            result: Ok(metadata),
        };
        let (signals, existence) =
            gather_api_signals_exact(&client, Ecosystem::Npm, "demo", "1.0.0");
        assert!(matches!(signals, ApiSignals::Unavailable { .. }));
        assert_eq!(existence, PackageExistence::Exists);
    }

    #[test]
    fn registry_redirects_stay_on_validated_origin_and_under_cap() {
        let initial = url::Url::parse("https://registry.npmjs.org/demo").unwrap();
        let same_origin = url::Url::parse("https://registry.npmjs.org/demo-2").unwrap();
        assert!(registry_redirect_decision(&initial, &same_origin, 4, true).is_ok());

        let cross_origin = url::Url::parse("https://example.com/demo").unwrap();
        assert!(registry_redirect_decision(&initial, &cross_origin, 0, true).is_err());

        let insecure = url::Url::parse("http://registry.npmjs.org/demo").unwrap();
        assert!(registry_redirect_decision(&initial, &insecure, 0, true).is_err());
        assert!(registry_redirect_decision(&initial, &same_origin, 5, true).is_err());
    }

    /// A packument's `dist.tarball` and a redirect `Location` are untrusted
    /// text. `validate_server_url` resolves the host over DNS, so running it
    /// before the origin comparison turned a rejected off-origin URL into a
    /// live query against the attacker's own nameserver: an out-of-band beacon
    /// carrying an attacker-chosen label, emitted for a URL that is refused
    /// anyway. The cheap comparison must come first.
    #[test]
    fn an_off_origin_target_is_refused_before_the_host_is_resolved() {
        let resolved = std::cell::RefCell::new(Vec::<String>::new());
        let spy = |url: &str| -> Result<(), String> {
            resolved.borrow_mut().push(url.to_string());
            Ok(())
        };
        let initial = url::Url::parse("https://registry.npmjs.org/demo").unwrap();

        let off_origin = url::Url::parse("https://exfil-label.attacker.invalid/x.tgz").unwrap();
        assert!(
            registry_redirect_decision_with_validator(&initial, &off_origin, 0, false, &spy)
                .is_err(),
            "an off-origin target is refused"
        );
        assert!(
            resolved.borrow().is_empty(),
            "the host of a refused target must never be handed to the resolving validator: {:?}",
            resolved.borrow()
        );

        // The validator is not bypassed; it still runs for every target the
        // origin rule admits.
        let same_origin =
            url::Url::parse("https://registry.npmjs.org/demo/-/demo-1.0.0.tgz").unwrap();
        assert!(
            registry_redirect_decision_with_validator(&initial, &same_origin, 0, false, &spy)
                .is_ok()
        );
        assert_eq!(
            resolved.borrow().as_slice(),
            &["https://registry.npmjs.org/demo/-/demo-1.0.0.tgz".to_string()],
            "a same-origin target is still fully validated"
        );
    }

    #[test]
    fn registry_redirect_rejects_loopback_in_production_mode() {
        let initial = url::Url::parse("https://registry.npmjs.org/demo").unwrap();
        let loopback = url::Url::parse("http://127.0.0.1/metadata").unwrap();
        assert!(registry_redirect_decision(&initial, &loopback, 0, false).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn registry_client_rejects_connect_time_private_dns_rebind() {
        use crate::ssrf_guard::test_support::EnvironmentRestore;

        let _environment = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut restore = EnvironmentRestore::new();
        restore.set("TIRITH_ALLOW_HTTP", Some("1"));
        let url = "http://registry-public.example.test:8080/package";
        let initial = url::Url::parse(url).unwrap();
        let validator = public_server_validator("registry-public.example.test");
        validator(url).expect("public preflight answer passes");
        let resolver = crate::ssrf_guard::ssrf_guard_resolver_with_lookup_for_test(|host| {
            assert_eq!(host, "registry-public.example.test");
            Ok(vec!["127.0.0.1:9".parse().unwrap()])
        });
        let client = registry_client_with_resolver_for_test(&initial, resolver, validator)
            .expect("build guarded registry client");
        let error = client
            .get(url)
            .send()
            .expect_err("connect-time private answer must be refused");
        let messages = request_error_messages(&error);
        assert!(
            messages.iter().any(|message| {
                message.contains("ssrf_guard") && message.contains("non-public address")
            }),
            "registry failure must come from guarded DNS: {messages:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn registry_client_rejects_private_redirect_before_second_request() {
        use crate::ssrf_guard::test_support::{
            http_response, EnvironmentRestore, ScriptedHttpServer,
        };

        let _environment = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut restore = EnvironmentRestore::new();
        restore.set("TIRITH_ALLOW_HTTP", Some("1"));
        let fixture = ScriptedHttpServer::start(vec![http_response(
            "302 Found",
            &[("Location", "http://127.0.0.1:9/internal")],
            b"",
        )]);
        let address = fixture.address();
        let url = format!(
            "http://registry-public.example.test:{}/package",
            address.port()
        );
        let initial = url::Url::parse(&url).unwrap();
        let validator = public_server_validator("registry-public.example.test");
        validator(&url).expect("public preflight answer passes");
        let resolver = crate::ssrf_guard::fixture_resolver_with_lookup_for_test(move |host| {
            assert_eq!(host, "registry-public.example.test");
            Ok(vec![address])
        });
        let client = registry_client_with_resolver_for_test(&initial, resolver, validator)
            .expect("build registry fixture client");
        let error = client
            .get(&url)
            .send()
            .expect_err("private redirect must be refused");
        let messages = request_error_messages(&error);
        // The refusal now comes from the origin rule rather than destination
        // validation. An off-origin private target trips the pure comparison
        // first, so it is refused without resolving or contacting anything;
        // destination validation still runs for targets that pass the origin
        // rule (see `an_off_origin_target_is_refused_before_the_host_is_resolved`).
        assert!(
            messages
                .iter()
                .any(|message| message.contains("changed the validated origin")),
            "private redirect must be refused: {messages:?}"
        );
        assert_eq!(
            fixture.finish().len(),
            1,
            "redirect target must be refused before a second request"
        );
    }

    #[cfg(unix)]
    #[test]
    fn registry_client_ignores_ambient_proxy_and_allows_same_origin_redirect() {
        use crate::ssrf_guard::test_support::{
            http_response, EnvironmentRestore, ProxyTrap, ScriptedHttpServer,
        };

        let _environment = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = ScriptedHttpServer::start(vec![
            http_response("302 Found", &[("Location", "/final")], b""),
            http_response("200 OK", &[("Content-Type", "application/json")], b"{}"),
        ]);
        let proxy = ProxyTrap::start();
        let mut restore = EnvironmentRestore::new();
        restore.set("TIRITH_ALLOW_HTTP", Some("1"));
        restore.install_ambient_proxy(&proxy.url());
        let address = fixture.address();
        let url = format!(
            "http://registry-public.example.test:{}/package",
            address.port()
        );
        let initial = url::Url::parse(&url).unwrap();
        let validator = public_server_validator("registry-public.example.test");
        let resolver = crate::ssrf_guard::fixture_resolver_with_lookup_for_test(move |host| {
            assert_eq!(host, "registry-public.example.test");
            Ok(vec![address])
        });
        let client = registry_client_with_resolver_for_test(
            &initial,
            resolver,
            std::sync::Arc::clone(&validator),
        )
        .expect("build registry fixture client");
        let body = HttpRegistryClient::without_cache()
            .get_json_bytes_with_test_client(&url, &client, validator.as_ref())
            .expect("same-origin registry redirect remains available");

        assert_eq!(body, b"{}");
        let requests = fixture.finish();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with(b"GET /package HTTP/1.1\r\n"));
        assert!(requests[1].starts_with(b"GET /final HTTP/1.1\r\n"));
        assert!(
            !proxy.finish(),
            "registry client must take its independently resolved direct route"
        );
    }

    #[test]
    fn unsupported_ecosystem_degrades_gracefully() {
        // Go has no registry API — a graceful Unavailable.
        let err = FetchError::UnsupportedEcosystem(Ecosystem::Go);
        assert!(err.reason().contains("go"));
        let client = FakeClient {
            result: Err(FetchError::UnsupportedEcosystem(Ecosystem::Go)),
        };
        let (sig, existence) = gather_api_signals(&client, Ecosystem::Go, "x");
        assert!(matches!(sig, ApiSignals::Unavailable { .. }));
        assert_eq!(
            existence,
            PackageExistence::Unknown,
            "unsupported ecosystem reports Unknown, never NotFound"
        );
    }

    #[test]
    fn provenance_flags_very_new_package() {
        let mut m = meta_clean();
        m.created_unix = Some(unix_now() - 2 * SECONDS_PER_DAY);
        let p = provenance_from_metadata(&m);
        assert!(p.package_age_days.unwrap() <= VERY_NEW_PACKAGE_DAYS);
    }

    #[test]
    fn provenance_flags_low_downloads() {
        let mut m = meta_clean();
        m.recent_downloads = Some(LOW_DOWNLOAD_THRESHOLD);
        let p = provenance_from_metadata(&m);
        assert_eq!(p.recent_downloads, Some(LOW_DOWNLOAD_THRESHOLD));
    }

    #[test]
    fn version_spike_detection() {
        assert!(is_version_spike("1.2.3", "9.0.0"));
        assert!(is_version_spike("1.0.0", "3.0.0"));
        assert!(!is_version_spike("1.0.0", "2.0.0"), "a +1 major is normal");
        assert!(!is_version_spike("1.0.0", "1.5.0"));
        assert!(!is_version_spike("abc", "9.0.0"), "unparseable → no spike");
    }

    #[test]
    fn provenance_version_spike_needs_two_versions() {
        let mut m = meta_clean();
        m.previous_version = None;
        assert_eq!(provenance_from_metadata(&m).version_spike, None);
        m.previous_version = Some("4.18.1".to_string());
        assert_eq!(provenance_from_metadata(&m).version_spike, Some(false));
    }

    #[test]
    fn usable_repo_url_classification() {
        assert!(is_usable_repo_url("https://github.com/owner/repo"));
        assert!(is_usable_repo_url("git+https://github.com/o/r.git"));
        assert!(is_usable_repo_url("git://gitlab.com/o/r"));
        assert!(is_usable_repo_url("git@github.com:owner/repo.git"));
        assert!(is_usable_repo_url("github.com/owner/repo"));
        assert!(!is_usable_repo_url(""));
        assert!(!is_usable_repo_url("   "));
        assert!(!is_usable_repo_url("not a url"));
        assert!(!is_usable_repo_url("https://example.com/your-repo"));
        // repo-0318: substring lookalikes are not usable source links.
        assert!(!is_usable_repo_url("javascript:github.com"));
        assert!(!is_usable_repo_url(
            "https://github.com.attacker.invalid/o/r"
        ));
        assert!(!is_usable_repo_url("https://"));
        assert!(!is_usable_repo_url("ssh://:22/path"));
    }

    #[test]
    fn provenance_repo_url_missing_vs_unknown() {
        let mut m = meta_clean();
        m.repository_url = Some(String::new());
        assert_eq!(provenance_from_metadata(&m).has_source_repo, Some(false));
        m.repository_url = None;
        assert_eq!(
            provenance_from_metadata(&m).has_source_repo,
            None,
            "a registry that omits the field reports unknown, not false"
        );
        m.repository_url = Some("https://github.com/o/r".to_string());
        assert_eq!(provenance_from_metadata(&m).has_source_repo, Some(true));
    }

    #[test]
    #[allow(deprecated)]
    fn ownership_transfer_inferred_for_ownerless_old_package() {
        // npm-shaped: `maintainers` is `Some` but empty.
        let mut m = meta_clean();
        m.maintainers = Some(Vec::new());
        m.created_unix = Some(unix_now() - 3650 * SECONDS_PER_DAY);
        assert_eq!(
            provenance_from_metadata(&m).ownership_transferred,
            Some(true),
            "an established npm package with no listed owners is flagged"
        );
        // A very new ownerless package is just new, not a transfer.
        m.created_unix = Some(unix_now() - 2 * SECONDS_PER_DAY);
        assert_eq!(
            provenance_from_metadata(&m).ownership_transferred,
            Some(false),
            "a very new package is too new to have 'transferred'"
        );
    }

    #[test]
    #[allow(deprecated)]
    fn ownership_unknown_when_registry_omits_maintainers() {
        // PyPI/crates.io-shaped: `maintainers` is `None`, so an ownerless package
        // is honestly unknown, not a transfer.
        let mut m = meta_clean();
        m.maintainers = None;
        m.created_unix = Some(unix_now() - 3650 * SECONDS_PER_DAY);
        assert_eq!(
            provenance_from_metadata(&m).ownership_transferred,
            None,
            "an absent maintainer field is unknown, never a false transfer"
        );
    }

    #[test]
    fn version_tuple_is_total_and_ordered() {
        assert_eq!(version_tuple("1.2.3"), (1, 2, 3));
        assert_eq!(version_tuple("v2.0"), (2, 0, 0));
        assert_eq!(version_tuple("garbage"), (0, 0, 0));
        assert!(version_tuple("1.2.3") < version_tuple("1.3.0"));
        assert!(version_tuple("2.0.0") > version_tuple("1.99.99"));
    }

    #[test]
    fn previous_version_key_finds_prior_release() {
        let keys: Vec<String> = ["1.0.0", "1.1.0", "2.0.0", "1.5.0"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            previous_version_key(keys.iter(), "2.0.0").as_deref(),
            Some("1.5.0")
        );
        // Nothing below the earliest version.
        assert_eq!(previous_version_key(keys.iter(), "1.0.0"), None);
    }

    #[test]
    fn npm_doc_parses_real_shape() {
        let json = r#"{
            "name": "demo",
            "dist-tags": { "latest": "2.0.0" },
            "time": {
                "created": "2020-01-01T00:00:00.000Z",
                "1.0.0": "2020-01-01T00:00:00.000Z",
                "2.0.0": "2024-06-01T00:00:00.000Z"
            },
            "versions": {
                "1.0.0": {},
                "2.0.0": { "deprecated": "do not use" }
            },
            "maintainers": [ { "name": "alice" }, { "name": "bob" } ],
            "repository": { "type": "git", "url": "git+https://github.com/o/r.git" }
        }"#;
        let doc: NpmDoc = serde_json::from_str(json).unwrap();
        assert_eq!(doc.dist_tags.unwrap().latest.unwrap(), "2.0.0");
        let v = doc.versions.get("2.0.0").unwrap();
        assert!(v.deprecated_present());
        assert!(!doc.versions.get("1.0.0").unwrap().deprecated_present());
    }

    #[test]
    fn npm_gypfile_without_install_override_records_implicit_node_gyp() {
        let version: NpmVersion = serde_json::from_value(serde_json::json!({
            "gypfile": true,
            "scripts": {}
        }))
        .unwrap();
        let signals = version.install_script_signals();
        assert!(signals.has_shell_spawn);
        assert!(signals
            .suspicious_patterns
            .iter()
            .any(|pattern| pattern.contains("node-gyp rebuild")));
    }

    #[test]
    fn npm_explicit_install_suppresses_implicit_node_gyp_default() {
        let version: NpmVersion = serde_json::from_value(serde_json::json!({
            "gypfile": true,
            "scripts": { "install": "echo prebuilt" }
        }))
        .unwrap();
        let signals = version.install_script_signals();
        assert!(!signals.fires());
        assert!(signals.suspicious_patterns.is_empty());
    }

    #[test]
    fn npm_whitespace_install_suppresses_implicit_node_gyp_default() {
        let version: NpmVersion = serde_json::from_value(serde_json::json!({
            "gypfile": true,
            "scripts": { "install": " " }
        }))
        .unwrap();
        assert!(!version.install_script_signals().fires());
    }

    #[test]
    fn npm_empty_install_keeps_implicit_node_gyp_default() {
        let version: NpmVersion = serde_json::from_value(serde_json::json!({
            "gypfile": true,
            "scripts": { "install": "" }
        }))
        .unwrap();
        assert!(version.install_script_signals().has_shell_spawn);
    }

    #[test]
    fn npm_gypfile_false_without_scripts_is_a_clean_control() {
        let version: NpmVersion = serde_json::from_value(serde_json::json!({
            "gypfile": false,
            "scripts": {}
        }))
        .unwrap();
        assert!(!version.install_script_signals().fires());
    }

    #[test]
    fn pypi_doc_parses_real_shape() {
        let json = r#"{
            "info": {
                "name": "demo",
                "version": "3.1.0",
                "yanked": false,
                "home_page": "",
                "project_urls": { "Source": "https://github.com/o/r" }
            },
            "releases": {
                "3.0.0": [ { "upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": false } ],
                "3.1.0": [ { "upload_time_iso_8601": "2024-01-01T00:00:00Z", "yanked": false } ]
            }
        }"#;
        let doc: PypiDoc = serde_json::from_str(json).unwrap();
        assert_eq!(doc.info.version.as_deref(), Some("3.1.0"));
        let urls = doc.info.project_urls.unwrap();
        assert_eq!(
            pick_repo_url(&urls).as_deref(),
            Some("https://github.com/o/r")
        );
    }

    #[test]
    fn pypi_exact_lookup_binds_canonical_intent_to_concrete_release_key() {
        let keys = ["2.30.0".to_string(), "2.31.0".to_string()];
        assert_eq!(
            matching_pypi_release_key(keys.iter(), "2.31").unwrap(),
            Some("2.31.0".to_string())
        );
    }

    #[test]
    fn pypi_exact_lookup_rejects_ambiguous_equivalent_release_keys() {
        let keys = ["2.31".to_string(), "2.31.0".to_string()];
        assert!(matches!(
            matching_pypi_release_key(keys.iter(), "2.31.0"),
            Err(FetchError::BadResponse(_))
        ));
    }

    #[test]
    fn crates_doc_parses_real_shape() {
        let json = r#"{
            "crate": {
                "id": "demo",
                "created_at": "2019-05-01T00:00:00.000000+00:00",
                "newest_version": "1.4.0",
                "downloads": 1234567,
                "repository": "https://github.com/o/r"
            },
            "versions": [
                { "num": "1.3.0", "created_at": "2022-01-01T00:00:00.000000+00:00", "yanked": false },
                { "num": "1.4.0", "created_at": "2024-01-01T00:00:00.000000+00:00", "yanked": true }
            ]
        }"#;
        let doc: CratesDoc = serde_json::from_str(json).unwrap();
        assert_eq!(doc.krate.newest_version.as_deref(), Some("1.4.0"));
        assert_eq!(doc.krate.downloads, Some(1234567));
        let latest = doc
            .versions
            .iter()
            .find(|v| v.num.as_deref() == Some("1.4.0"));
        assert!(latest.unwrap().yanked.unwrap());
    }

    #[test]
    fn url_path_segment_encodes_unsafe_chars() {
        assert_eq!(url_path_segment("react"), "react");
        assert_eq!(url_path_segment("@scope/pkg"), "@scope/pkg");
        // A space must be encoded.
        assert_eq!(url_path_segment("bad name"), "bad%20name");
    }

    #[test]
    fn safe_registry_name_accepts_real_names() {
        assert!(is_safe_registry_name("react"));
        assert!(is_safe_registry_name("@scope/pkg"));
        assert!(is_safe_registry_name("lodash.merge"));
        assert!(is_safe_registry_name("some-crate_name"));
        // A `..` substring without a surrounding `/` is a name component, kept.
        assert!(is_safe_registry_name("a..b"));
    }

    #[test]
    fn registry_native_names_use_ecosystem_canonical_identity() {
        assert!(registry_names_match(
            Ecosystem::Npm,
            "@Scope/Package",
            "@scope/package"
        ));
        assert!(registry_names_match(
            Ecosystem::PyPI,
            "Demo_Package.Name",
            "demo-package-name"
        ));
        assert!(registry_names_match(Ecosystem::Crates, "Serde", "serde"));
        assert!(!registry_names_match(
            Ecosystem::Crates,
            "serde-json",
            "serde_json"
        ));
    }

    #[test]
    fn safe_registry_name_rejects_path_traversal() {
        // F2: a `..` path segment is rejected before any URL is built.
        assert!(!is_safe_registry_name("../../../x"));
        assert!(!is_safe_registry_name(".."));
        assert!(!is_safe_registry_name("react/.."));
        assert!(!is_safe_registry_name("@scope/.."));
        assert!(!is_safe_registry_name("."));
        // A stray / extra / empty `/` segment is also rejected.
        assert!(!is_safe_registry_name("a/b/c"));
        assert!(!is_safe_registry_name("not-a-scope/pkg"));
        assert!(!is_safe_registry_name("/leading"));
        assert!(!is_safe_registry_name("trailing/"));
        assert!(!is_safe_registry_name("@scope//pkg"));
        assert!(!is_safe_registry_name(""));
    }

    #[test]
    fn fetch_rejects_traversal_name_without_a_request() {
        // F2 end-to-end: a traversal name short-circuits to `InvalidName` before
        // any URL is built, so this test issues no request.
        let client = HttpRegistryClient::without_cache();
        let err = client
            .fetch(Ecosystem::Npm, "../../../etc/passwd")
            .expect_err("a path-traversal name must not produce a request");
        assert!(
            matches!(err, FetchError::InvalidName),
            "expected InvalidName, got {err:?}"
        );
        // The degradation reason is honest about why no request was made.
        assert!(err.reason().contains("path-traversal"));
        // And it surfaces as a graceful Unavailable, not a panic.
        let (sig, _existence) = gather_api_signals(&client, Ecosystem::Npm, "../../../etc/passwd");
        assert!(matches!(sig, ApiSignals::Unavailable { .. }));
    }

    #[test]
    fn production_registry_transport_rejects_private_destination() {
        let client = HttpRegistryClient::without_cache();
        let error = client
            .get_json_bytes("https://127.0.0.1/package")
            .expect_err("production registry transport must reject private destinations");
        assert!(matches!(error, FetchError::Network(_)));
        assert!(error.reason().contains("non-public"));
    }

    #[test]
    fn local_mock_factory_is_the_only_destination_guard_bypass() {
        assert!(HttpRegistryClient::new().enforce_destination_guard);
        assert!(HttpRegistryClient::without_cache().enforce_destination_guard);
        assert!(
            !HttpRegistryClient::with_base_url_for_test("http://127.0.0.1:9")
                .enforce_destination_guard
        );
    }

    #[test]
    fn rfc3339_parsing() {
        assert!(parse_rfc3339_to_unix("2020-01-01T00:00:00Z").is_some());
        assert!(parse_rfc3339_to_unix("2020-01-01T00:00:00.000Z").is_some());
        assert!(parse_rfc3339_to_unix("not-a-date").is_none());
    }

    #[test]
    fn cache_envelope_tolerates_old_maintainers_shape() {
        // A stale entry from the old `maintainers` + `maintainers_known` shape
        // must still deserialize (array → `Some(list)`, unknown field ignored).
        let old = r#"{
            "fetched_at": 1700000000,
            "value": {
                "source": "npm",
                "maintainers": ["alice", "bob"],
                "maintainers_known": true,
                "yanked_or_deprecated": false
            }
        }"#;
        let env: CacheEnvelope =
            serde_json::from_str(old).expect("an old-format cache entry must still deserialize");
        assert_eq!(
            env.value.maintainers,
            Some(vec!["alice".to_string(), "bob".to_string()])
        );
        assert_eq!(env.value.package_name, None);
        assert!(
            !metadata_identity_matches(&env.value, Ecosystem::Npm, "react"),
            "pre-binding cache entries must be refreshed, never accepted by path alone"
        );

        // An envelope with no `maintainers` field defaults to `None`.
        let no_field = r#"{
            "fetched_at": 1700000000,
            "value": { "source": "pypi", "yanked_or_deprecated": false }
        }"#;
        let env: CacheEnvelope = serde_json::from_str(no_field)
            .expect("a cache entry without `maintainers` must deserialize");
        assert_eq!(env.value.maintainers, None);
    }
}
