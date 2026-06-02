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

use crate::package_risk::{ApiProvenance, ApiSignals, PackageExistence, VERY_NEW_PACKAGE_DAYS};
use crate::policy;
use crate::threatdb::Ecosystem;

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
    /// Unix epoch seconds of the package's *first* publication, when known.
    pub created_unix: Option<u64>,
    /// Unix epoch seconds of the *latest version*'s publication, when known.
    pub latest_version_unix: Option<u64>,
    /// The latest (most recent) version string, when known.
    pub latest_version: Option<String>,
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
    /// `true` when the registry marks the latest version yanked / deprecated.
    pub yanked_or_deprecated: bool,
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
    /// Fetch metadata for `name` in `ecosystem`, or a [`FetchError`].
    fn fetch(&self, ecosystem: Ecosystem, name: &str) -> Result<RegistryMetadata, FetchError>;
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
    match client.fetch(ecosystem, name) {
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
            let _ = crate::registry_history::record_snapshot_with_maintainers(
                ecosystem,
                name,
                maintainers,
                meta.latest_version.clone(),
                meta.repository_url.clone(),
            );

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
        .latest_version_unix
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

    let version_spike = match (&meta.latest_version, &meta.previous_version) {
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
        package_age_days,
        latest_version_age_days,
        ownership_transferred,
        version_spike,
        recent_downloads: meta.recent_downloads,
        has_source_repo,
        yanked_or_deprecated: meta.yanked_or_deprecated,
        latest_version: meta.latest_version.clone(),
        repository_url,
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
    // A URL or a git+/scp-style remote.
    let looks_like_url = lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("git://")
        || lower.starts_with("git+")
        || lower.starts_with("ssh://")
        || lower.contains("github.com")
        || lower.contains("gitlab.com")
        || lower.contains("bitbucket.org");
    if !looks_like_url {
        return false;
    }
    // Reject obvious placeholders.
    let placeholders = ["example.com", "your-repo", "todo", "n/a", "none"];
    !placeholders.iter().any(|p| lower.contains(p))
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
}

impl Default for HttpRegistryClient {
    fn default() -> Self {
        HttpRegistryClient {
            timeout: Duration::from_secs(REQUEST_TIMEOUT_SECS),
            use_cache: true,
            npm_base: NPM_BASE.to_string(),
            pypi_base: PYPI_BASE.to_string(),
            crates_base: CRATES_BASE.to_string(),
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
            ..Self::default()
        }
    }

    /// GET `url` and return the body, capped at [`MAX_RESPONSE_BYTES`].
    fn get_json_bytes(&self, url: &str) -> Result<Vec<u8>, FetchError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(|e| FetchError::Network(e.to_string()))?;

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
}

impl RegistryClient for HttpRegistryClient {
    fn fetch(&self, ecosystem: Ecosystem, name: &str) -> Result<RegistryMetadata, FetchError> {
        // Reject an unsafe name BEFORE any URL is built. `name` can come from
        // untrusted manifest content (`ecosystem scan --online`), and a `..`
        // segment would be normalized into a GET against an arbitrary same-host
        // path — a path-traversal sink.
        if !is_safe_registry_name(name) {
            return Err(FetchError::InvalidName);
        }

        if self.use_cache {
            if let Some(cached) = load_cache(ecosystem, name) {
                return Ok(cached);
            }
        }

        let meta = match ecosystem {
            Ecosystem::Npm => fetch_npm(self, name)?,
            Ecosystem::PyPI => fetch_pypi(self, name)?,
            Ecosystem::Crates => fetch_crates(self, name)?,
            other => return Err(FetchError::UnsupportedEcosystem(other)),
        };

        if self.use_cache {
            store_cache(ecosystem, name, &meta);
        }
        Ok(meta)
    }
}

// --- npm registry ----------------------------------------------------------

/// Fetch and normalize an npm "full" package document (`time`, `versions`,
/// `maintainers`, `dist-tags.latest`, per-version `deprecated`).
fn fetch_npm(client: &HttpRegistryClient, name: &str) -> Result<RegistryMetadata, FetchError> {
    let url = format!("{}/{}", client.npm_base, url_path_segment(name));
    let bytes = client.get_json_bytes(&url)?;
    let doc: NpmDoc =
        serde_json::from_slice(&bytes).map_err(|e| FetchError::BadResponse(e.to_string()))?;

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

    let previous_version = latest_version
        .as_ref()
        .and_then(|latest| previous_version_key(doc.versions.keys(), latest));

    // Deprecated when the latest version object has a non-empty `deprecated`.
    let yanked_or_deprecated = latest_version
        .as_ref()
        .and_then(|v| doc.versions.get(v))
        .map(|vd| vd.deprecated_present())
        .unwrap_or(false);

    let repository_url = doc.repository.as_ref().and_then(|r| r.url_field());

    Ok(RegistryMetadata {
        source: "npm".to_string(),
        created_unix,
        latest_version_unix,
        latest_version,
        previous_version,
        // npm exposes `maintainers` → `Some` (an empty list is a real signal).
        maintainers: Some(doc.maintainers.into_iter().filter_map(|m| m.name).collect()),
        // Download counts are a separate endpoint; no second request.
        recent_downloads: None,
        repository_url,
        yanked_or_deprecated,
    })
}

#[derive(Debug, Deserialize)]
struct NpmDoc {
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
fn fetch_pypi(client: &HttpRegistryClient, name: &str) -> Result<RegistryMetadata, FetchError> {
    let url = format!("{}/pypi/{}/json", client.pypi_base, url_path_segment(name));
    let bytes = client.get_json_bytes(&url)?;
    let doc: PypiDoc =
        serde_json::from_slice(&bytes).map_err(|e| FetchError::BadResponse(e.to_string()))?;

    let latest_version = doc.info.version.clone();

    // First publication = earliest upload time across all releases.
    let mut earliest: Option<u64> = None;
    let mut latest_ver_unix: Option<u64> = None;
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
            }
        }
    }

    let previous_version = latest_version
        .as_ref()
        .and_then(|latest| previous_version_key(doc.releases.keys(), latest));

    // Yanked when `info.yanked`, or every file of the latest release is yanked.
    let latest_files_yanked = latest_version
        .as_ref()
        .and_then(|v| doc.releases.get(v))
        .map(|files| !files.is_empty() && files.iter().all(|f| f.yanked.unwrap_or(false)))
        .unwrap_or(false);
    let yanked_or_deprecated = doc.info.yanked.unwrap_or(false) || latest_files_yanked;

    // Prefer a `project_urls` entry naming a source repo; fall back to home_page.
    let repository_url = doc
        .info
        .project_urls
        .as_ref()
        .and_then(pick_repo_url)
        .or_else(|| doc.info.home_page.clone());

    Ok(RegistryMetadata {
        source: "pypi".to_string(),
        created_unix: earliest,
        latest_version_unix: latest_ver_unix,
        latest_version,
        previous_version,
        // PyPI's JSON API exposes no maintainers / downloads → `None` (unknown).
        maintainers: None,
        recent_downloads: None,
        repository_url,
        yanked_or_deprecated,
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
    version: Option<String>,
    yanked: Option<bool>,
    home_page: Option<String>,
    project_urls: Option<std::collections::BTreeMap<String, String>>,
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
fn fetch_crates(client: &HttpRegistryClient, name: &str) -> Result<RegistryMetadata, FetchError> {
    let url = format!(
        "{}/api/v1/crates/{}",
        client.crates_base,
        url_path_segment(name)
    );
    let bytes = client.get_json_bytes(&url)?;
    let doc: CratesDoc =
        serde_json::from_slice(&bytes).map_err(|e| FetchError::BadResponse(e.to_string()))?;

    let created_unix = doc
        .krate
        .created_at
        .as_deref()
        .and_then(parse_rfc3339_to_unix);

    let latest_version = doc.krate.newest_version.clone();

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

    let previous_version = latest_version.as_ref().and_then(|latest| {
        previous_version_key(doc.versions.iter().filter_map(|cv| cv.num.as_ref()), latest)
    });

    Ok(RegistryMetadata {
        source: "crates.io".to_string(),
        created_unix,
        latest_version_unix,
        latest_version,
        previous_version,
        // Owners are a separate endpoint → `maintainers: None` (unknown).
        maintainers: None,
        recent_downloads: doc.krate.downloads,
        repository_url: doc.krate.repository,
        yanked_or_deprecated,
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
fn cache_path(ecosystem: Ecosystem, name: &str) -> Option<PathBuf> {
    let state = policy::state_dir()?;
    let key = format!("{ecosystem}:{name}");
    let digest = sha2::Sha256::digest(key.as_bytes());
    let hex: String = digest.iter().take(16).map(|b| format!("{b:02x}")).collect();
    Some(
        state
            .join("registry-api-cache")
            .join(format!("pkg-{hex}.json")),
    )
}

/// Load a cached `RegistryMetadata` if one exists and is within the TTL.
fn load_cache(ecosystem: Ecosystem, name: &str) -> Option<RegistryMetadata> {
    let path = cache_path(ecosystem, name)?;
    let content = std::fs::read_to_string(path).ok()?;
    let envelope: CacheEnvelope = serde_json::from_str(&content).ok()?;
    if unix_now().saturating_sub(envelope.fetched_at) > CACHE_TTL_SECS {
        return None;
    }
    Some(envelope.value)
}

/// Store a fetched `RegistryMetadata` in the cache. Best-effort (I/O errors
/// ignored — the cache is a performance convenience).
fn store_cache(ecosystem: Ecosystem, name: &str, value: &RegistryMetadata) {
    let Some(path) = cache_path(ecosystem, name) else {
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
            created_unix: Some(unix_now() - 3650 * SECONDS_PER_DAY),
            latest_version_unix: Some(unix_now() - 365 * SECONDS_PER_DAY),
            latest_version: Some("4.18.2".to_string()),
            previous_version: Some("4.18.1".to_string()),
            maintainers: Some(vec!["alice".to_string()]),
            recent_downloads: Some(5_000_000),
            repository_url: Some("https://github.com/owner/repo".to_string()),
            yanked_or_deprecated: false,
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
        assert!(!is_usable_repo_url(""));
        assert!(!is_usable_repo_url("   "));
        assert!(!is_usable_repo_url("not a url"));
        assert!(!is_usable_repo_url("https://example.com/your-repo"));
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
    fn pypi_doc_parses_real_shape() {
        let json = r#"{
            "info": {
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
    fn crates_doc_parses_real_shape() {
        let json = r#"{
            "crate": {
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
