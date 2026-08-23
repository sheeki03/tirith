//! Point-in-time deployment receipt: which routes of one HTTPS origin served
//! the exact bytes a build receipt bound, at one moment (C18).
//!
//! # The honesty constraint, which is why this module exists at all
//!
//! A deployment receipt proves ONE thing: at the timestamp it records, the
//! routes it lists returned the byte sequences the build receipt bound. It is
//! not continuous monitoring, it is not a claim about routes it did not fetch,
//! and it is not proof that "the deployed site is the build". A CDN can serve
//! different bytes to the next client, to a different region, or a second later.
//! Every status, every rendered line, and the receipt's own `caveats` field say
//! so, and [`DeploymentReceipt::validate`] refuses a receipt that dropped the
//! caveats.
//!
//! # Why the fetch lives in tirith-core and not in the CLI
//!
//! Two reasons, and the second is the binding one:
//!
//! 1. the SSRF-guarded client builders ([`crate::ssrf_guard`]) are `pub(crate)`,
//!    so a fetch defined in the CLI crate could not use the connect-time DNS
//!    guard and would have to rebuild a weaker client;
//! 2. the scripted local HTTP fixture the request-shape, redirect, compression,
//!    and cap tests need is `#[cfg(test)]` and crate-private, so those tests can
//!    only be an inline module inside this crate.
//!
//! The CLI file is therefore a thin renderer with no network code of its own.
//!
//! # What the fetcher enforces
//!
//! - ONE origin. The base URL is validated through
//!   [`crate::url_validate::validate_server_url`] (HTTPS unless
//!   `TIRITH_ALLOW_HTTP=1`, no embedded credentials, no private, loopback,
//!   link-local, or cloud-metadata destination after DNS), and every redirect
//!   hop must stay on that exact scheme, host, and port. A cross-origin redirect
//!   is a MISMATCH, not a follow: an open redirect that moves the answer to
//!   another host has changed which server the receipt is about.
//! - Redirects are followed MANUALLY, one hop at a time, capped at
//!   [`MAX_REDIRECTS`]. reqwest's own policy would work, but its `Attempt` API
//!   cannot hand back a per-request chain without shared mutable state that the
//!   concurrent fetcher would interleave across routes.
//! - `Accept-Encoding: identity`, and any non-identity `Content-Encoding` in the
//!   response makes the route PARTIAL. The workspace builds reqwest without
//!   gzip, brotli, or deflate, so a `Content-Encoding` that arrives anyway means
//!   the origin or a CDN transformed the body: the bytes on the wire are then
//!   genuinely not the bytes that were built, and calling that a mismatch would
//!   be a false accusation.
//! - [`MAX_RESPONSE_BYTES`] per response, checked against `Content-Length` first
//!   and then again on the read, so a lying `Content-Length` cannot get past it.
//! - [`MAX_AGGREGATE_BYTES`] across the whole run, held in one atomic so the
//!   concurrent workers cannot each spend the full budget.
//! - [`FETCH_CONCURRENCY`] workers on `std::thread::scope`. tirith-core has no
//!   async runtime and no thread pool, and the blocking client is what the rest
//!   of the crate uses.
//!
//! # CSP, SRI, and Trusted Types
//!
//! Recorded as OBSERVATIONS on the route, bounded and sanitized. They are
//! deployment hygiene, not byte-deployment proof, and they never move a route's
//! state. A site with a perfect CSP that serves the wrong bytes is a mismatch.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::build_receipt::{AttestStatus, BuildReceipt, TreeFile};
use crate::command_card::sha256_hex;

/// Schema version of [`DeploymentReceipt`].
pub const DEPLOYMENT_RECEIPT_SCHEMA: u32 = 1;

/// Stable discriminator so a reader can tell this envelope from the build,
/// capsule, browser-baseline, and npm-provenance receipts.
pub const DEPLOYMENT_RECEIPT_TYPE: &str = "attest_deployment";

/// Maximum bytes read from one response body.
pub const MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;

/// Maximum bytes read across the whole run.
pub const MAX_AGGREGATE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Maximum redirect hops followed per route.
pub const MAX_REDIRECTS: usize = 5;

/// Concurrent fetch workers.
pub const FETCH_CONCURRENCY: usize = 8;

/// Per-request wall-clock budget.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-request connect budget, separate from the total so a black-holed address
/// fails fast instead of consuming the whole request budget.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum routes one receipt will cover.
pub const MAX_ROUTES: usize = 4096;

/// Maximum bytes of one recorded observation value.
pub const MAX_OBSERVATION_BYTES: usize = 512;

/// Maximum bytes of a saved deployment receipt that will be re-read.
pub const MAX_DEPLOYMENT_RECEIPT_BYTES: u64 = 32 * 1024 * 1024;

/// The honesty statement a deployment receipt may never be read without.
pub const POINT_IN_TIME_CAVEAT: &str =
    "this receipt proves only that the routes it lists returned these exact bytes at the timestamp \
     it records; it is not continuous monitoring, it says nothing about routes that were not \
     fetched, and it is not proof that the deployed site is the build";

/// The second honesty statement: what the header observations are and are not.
pub const OBSERVATIONS_CAVEAT: &str =
    "content-security-policy, trusted-types, and related response headers are recorded as \
     observations about deployment hygiene; they are never evidence that the served bytes match \
     the build";

/// Response headers recorded as observations. Deployment hygiene, never proof.
const OBSERVED_HEADERS: &[&str] = &[
    "content-security-policy",
    "content-security-policy-report-only",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "referrer-policy",
    "strict-transport-security",
    "x-content-type-options",
];

// ---------------------------------------------------------------------------
// Route map
// ---------------------------------------------------------------------------

/// Which build-relative output path is served at which URL path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteMap {
    pub routes: BTreeMap<String, String>,
}

/// Why a route map was refused. Every variant is a usage error: the operator
/// asked for something the receipt could not honestly describe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteMapError {
    Malformed(String),
    Empty,
    TooManyRoutes(usize),
    /// A key that names no file in the build receipt's output manifest. Fetching
    /// it would produce a row the receipt cannot compare against anything.
    UnknownBuildPath(String),
    /// A value that is not an absolute, same-origin URL path.
    InvalidRoute(String),
}

impl std::fmt::Display for RouteMapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(detail) => write!(f, "the route map is not valid JSON: {detail}"),
            Self::Empty => write!(f, "the route map names no routes"),
            Self::TooManyRoutes(count) => {
                write!(
                    f,
                    "the route map names {count} routes, over the {MAX_ROUTES} cap"
                )
            }
            Self::UnknownBuildPath(path) => write!(
                f,
                "the route map names {path}, which is not in the build receipt's output manifest"
            ),
            Self::InvalidRoute(route) => write!(
                f,
                "{route} is not an absolute same-origin URL path (it must start with / and must \
                 not contain a scheme, an authority, or a .. segment)"
            ),
        }
    }
}

impl std::error::Error for RouteMapError {}

/// The default mapping: `index.html` at any depth serves its containing
/// directory, and every other file serves its exact relative path.
///
/// This is a convention, not a discovery: Tirith does not ask the host how it
/// routes. A host that rewrites differently needs an explicit `--route-map`, and
/// the receipt records which of the two was used.
pub fn default_route_map(files: &[TreeFile]) -> RouteMap {
    let mut routes = BTreeMap::new();
    for file in files {
        // The suffix must be a whole path COMPONENT: `myindex.html` is an
        // ordinary file, and mapping it to `/my` would fetch a route that has
        // nothing to do with it.
        let index_prefix = file
            .path
            .strip_suffix("index.html")
            .filter(|prefix| prefix.is_empty() || prefix.ends_with('/'));
        let route = match index_prefix {
            Some(prefix) => format!("/{prefix}"),
            None => format!("/{}", file.path),
        };
        routes.insert(file.path.clone(), route);
    }
    RouteMap { routes }
}

/// Parse an explicit route map. Accepts either `{"routes": {...}}` or a bare
/// object of the same shape, because both spellings appear in the wild and
/// rejecting one is a usability trap with no security value.
pub fn parse_route_map(text: &str) -> Result<RouteMap, RouteMapError> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|error| RouteMapError::Malformed(error.to_string()))?;
    let object = value
        .get("routes")
        .unwrap_or(&value)
        .as_object()
        .ok_or_else(|| RouteMapError::Malformed("expected a JSON object of routes".to_string()))?;
    let mut routes = BTreeMap::new();
    for (key, mapped) in object {
        let route = mapped
            .as_str()
            .ok_or_else(|| RouteMapError::Malformed(format!("{key} does not map to a string")))?;
        routes.insert(key.clone(), route.to_string());
    }
    Ok(RouteMap { routes })
}

/// Check a route map against the build receipt's output manifest and the
/// same-origin path rules.
pub fn validate_route_map(map: &RouteMap, files: &[TreeFile]) -> Result<(), RouteMapError> {
    if map.routes.is_empty() {
        return Err(RouteMapError::Empty);
    }
    if map.routes.len() > MAX_ROUTES {
        return Err(RouteMapError::TooManyRoutes(map.routes.len()));
    }
    for (build_path, route) in &map.routes {
        if !files.iter().any(|file| &file.path == build_path) {
            return Err(RouteMapError::UnknownBuildPath(build_path.clone()));
        }
        if !route_is_same_origin_path(route) {
            return Err(RouteMapError::InvalidRoute(route.clone()));
        }
    }
    Ok(())
}

/// Whether one mapped value is an absolute path on the base origin.
///
/// A route map is operator input that may have come from a repository, and the
/// URL parser this value is later joined against is far more forgiving than it
/// looks. Under the WHATWG rules a special scheme treats `\` exactly like `/`,
/// and ASCII tab, LF, and CR are STRIPPED from the input before parsing, so
/// `/\evil.example/x` and `/<tab>/evil.example/x` both resolve to another
/// authority while reading like ordinary absolute paths. Rejecting the second
/// byte only when it is literally `/` would let both through.
///
/// So the rule is a whitelist of the syntax an absolute path can legitimately
/// use: a leading `/`, no second separator of either slash flavour, no
/// backslash, no C0 control or space anywhere, no scheme, and no `..` segment.
/// [`fetch_one_route`] then re-checks the RESOLVED origin, because a predicate
/// over text can only ever be a first line of defence against a parser.
fn route_is_same_origin_path(route: &str) -> bool {
    let separators = |byte: u8| byte == b'/' || byte == b'\\';
    let bytes = route.as_bytes();
    if bytes.first() != Some(&b'/') {
        return false;
    }
    if bytes.get(1).copied().is_some_and(separators) {
        return false;
    }
    if bytes
        .iter()
        .any(|byte| *byte == b'\\' || *byte <= b' ' || *byte == 0x7f)
    {
        return false;
    }
    !route.contains("://") && !route.split(['/', '?', '#']).any(|segment| segment == "..")
}

// ---------------------------------------------------------------------------
// Route outcomes
// ---------------------------------------------------------------------------

/// What one route produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteState {
    /// The response body hashed to exactly the digest the build receipt bound.
    Match,
    /// The route returned bytes that are not the built bytes, or the origin
    /// itself moved. A positive disagreement.
    Mismatch,
    /// The route could not be measured: unreachable, authenticated, challenged,
    /// transformed by a CDN, encoded in a form the fetcher does not decode, or
    /// over a cap. An absence of evidence, never a claim of agreement.
    Partial,
}

impl RouteState {
    /// Stable wire token, matching the serde spelling.
    pub fn token(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::Mismatch => "mismatch",
            Self::Partial => "partial",
        }
    }

    fn as_status(self) -> AttestStatus {
        match self {
            Self::Match => AttestStatus::Clean,
            Self::Mismatch => AttestStatus::Mismatch,
            Self::Partial => AttestStatus::Partial,
        }
    }
}

/// One fetched route, fully bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteOutcome {
    /// The output-manifest path this route is supposed to serve.
    pub build_path: String,
    /// The requested URL path.
    pub route: String,
    /// The URL the body actually came from, userinfo-redacted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    /// Every redirect hop, in order, userinfo-redacted.
    pub redirect_chain: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_bytes: Option<u64>,
    /// What the build receipt says these bytes should be.
    pub expected_sha256: String,
    pub expected_bytes: u64,
    pub fetched_at: String,
    pub state: RouteState,
    /// Why the state is not [`RouteState::Match`]. `None` when it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Deployment-hygiene headers. Never evidence about the bytes.
    pub observations: Vec<String>,
}

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

/// The knobs the fetcher runs under. Defaults are the shipped caps; tests lower
/// them so a cap can be exercised without materializing gigabytes.
#[derive(Debug, Clone, Copy)]
pub struct FetchSettings {
    pub concurrency: usize,
    pub max_response_bytes: u64,
    pub aggregate_budget: u64,
    pub timeout: Duration,
}

impl Default for FetchSettings {
    fn default() -> Self {
        Self {
            concurrency: FETCH_CONCURRENCY,
            max_response_bytes: MAX_RESPONSE_BYTES,
            aggregate_budget: MAX_AGGREGATE_BYTES,
            timeout: REQUEST_TIMEOUT,
        }
    }
}

/// Why a whole deployment run could not start. Distinct from a per-route
/// Partial: nothing was fetched at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentError {
    /// The base URL failed the destination boundary: not HTTPS, credential
    /// bearing, or resolving to a private, loopback, link-local, or
    /// cloud-metadata address.
    BaseUrlRefused(String),
    /// The HTTP client could not be constructed.
    ClientUnavailable(String),
}

impl std::fmt::Display for DeploymentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BaseUrlRefused(detail) => write!(f, "the base URL was refused: {detail}"),
            Self::ClientUnavailable(detail) => {
                write!(f, "the guarded HTTP client could not be built: {detail}")
            }
        }
    }
}

impl std::error::Error for DeploymentError {}

/// The URL preflight the fetcher applies to the base URL and to every redirect
/// target. Production always uses [`crate::url_validate::validate_server_url`];
/// the inline tests substitute a hermetic resolver so a fixture host can be
/// exercised without touching real DNS.
type UrlValidator = std::sync::Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

fn production_validator() -> UrlValidator {
    std::sync::Arc::new(crate::url_validate::validate_server_url)
}

/// Fetch every mapped route from one origin and bind what came back.
pub fn fetch_routes(
    base_url: &str,
    map: &RouteMap,
    files: &[TreeFile],
    settings: FetchSettings,
) -> Result<Vec<RouteOutcome>, DeploymentError> {
    let validator = production_validator();
    validator(base_url).map_err(DeploymentError::BaseUrlRefused)?;
    let base = url::Url::parse(base_url)
        .map_err(|error| DeploymentError::BaseUrlRefused(error.to_string()))?;
    let client = crate::ssrf_guard::server_client_builder()
        // Redirects are followed by hand so each route owns its own chain; see
        // the module note.
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(settings.timeout)
        .build()
        .map_err(|error| DeploymentError::ClientUnavailable(error.to_string()))?;
    Ok(fetch_routes_with_client(
        &base, &client, map, files, settings, &validator,
    ))
}

/// The testable core: everything except client construction and the base-URL
/// preflight.
fn fetch_routes_with_client(
    base: &url::Url,
    client: &reqwest::blocking::Client,
    map: &RouteMap,
    files: &[TreeFile],
    settings: FetchSettings,
    validator: &UrlValidator,
) -> Vec<RouteOutcome> {
    let work: Vec<(String, String, &TreeFile)> = map
        .routes
        .iter()
        .filter_map(|(build_path, route)| {
            files
                .iter()
                .find(|file| &file.path == build_path)
                .map(|file| (build_path.clone(), route.clone(), file))
        })
        .collect();

    let next = AtomicUsize::new(0);
    // One shared budget, so eight workers cannot each spend the whole thing.
    let remaining = AtomicU64::new(settings.aggregate_budget);
    let results: Vec<std::sync::Mutex<Option<RouteOutcome>>> =
        work.iter().map(|_| std::sync::Mutex::new(None)).collect();
    let workers = settings
        .concurrency
        .clamp(1, FETCH_CONCURRENCY)
        .min(work.len().max(1));

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                let Some((build_path, route, file)) = work.get(index) else {
                    return;
                };
                let outcome = fetch_one_route(
                    base, client, build_path, route, file, settings, &remaining, validator,
                );
                *results[index]
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(outcome);
            });
        }
    });

    results
        .into_iter()
        .filter_map(|slot| {
            slot.into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        })
        .collect()
}

/// One route, start to finish.
#[allow(clippy::too_many_arguments)]
fn fetch_one_route(
    base: &url::Url,
    client: &reqwest::blocking::Client,
    build_path: &str,
    route: &str,
    file: &TreeFile,
    settings: FetchSettings,
    remaining: &AtomicU64,
    validator: &UrlValidator,
) -> RouteOutcome {
    let fetched_at = chrono::Utc::now().to_rfc3339();
    let mut outcome = RouteOutcome {
        build_path: build_path.to_string(),
        route: route.to_string(),
        final_url: None,
        redirect_chain: Vec::new(),
        status_code: None,
        body_sha256: None,
        body_bytes: None,
        expected_sha256: file.sha256.clone(),
        expected_bytes: file.size,
        fetched_at,
        state: RouteState::Partial,
        detail: None,
        observations: Vec::new(),
    };

    let Ok(mut current) = base.join(route) else {
        outcome.detail = Some("the route could not be resolved against the base URL".to_string());
        return outcome;
    };
    // The authority the PARSER produced, not the one the text implied. This is
    // the gate that actually holds the "ONE origin" contract: the route map may
    // have come from a repository, and the default map is derived from filenames
    // in a build tree, so both are attacker-influenced text handed to a URL
    // parser with its own opinions about backslashes and control characters.
    if !same_origin(base, &current) {
        outcome.state = RouteState::Mismatch;
        outcome.detail =
            Some("the route resolves to a different origin than the base URL".to_string());
        return outcome;
    }

    for hop in 0..=MAX_REDIRECTS {
        if hop > 0 {
            outcome
                .redirect_chain
                .push(crate::receipt::redact_url_userinfo(current.as_str()));
        }
        if let Err(reason) = validator(current.as_str()) {
            // A destination that fails the boundary is a positive statement
            // about where this origin sent us, not an absence of evidence.
            outcome.state = RouteState::Mismatch;
            outcome.detail = Some(format!("the destination was refused: {reason}"));
            return outcome;
        }
        let response = match client
            .get(current.clone())
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .header(
                reqwest::header::USER_AGENT,
                format!("tirith/{} (attest-deployment)", env!("CARGO_PKG_VERSION")),
            )
            .send()
        {
            Ok(response) => response,
            Err(error) => {
                outcome.detail = Some(format!("the route was unreachable: {error}"));
                return outcome;
            }
        };

        outcome.final_url = Some(crate::receipt::redact_url_userinfo(current.as_str()));
        outcome.status_code = Some(response.status().as_u16());

        if response.status().is_redirection() {
            match redirect_target(base, &current, &response) {
                Ok(next) => {
                    current = next;
                    continue;
                }
                Err(RedirectRefusal::Mismatch(detail)) => {
                    outcome.state = RouteState::Mismatch;
                    outcome.detail = Some(detail);
                    return outcome;
                }
                Err(RedirectRefusal::Partial(detail)) => {
                    outcome.detail = Some(detail);
                    return outcome;
                }
            }
        }

        // Recorded from the response that SERVED the bytes, and only that one. A
        // 302 hop can carry a perfect CSP while the response behind it carries
        // none, and observations scraped off both would assert a hygiene posture
        // for a response that never had it.
        record_observations(&mut outcome, response.headers());
        return finish_route(outcome, response, settings, remaining);
    }

    outcome.detail = Some(format!(
        "the route redirected more than {MAX_REDIRECTS} times"
    ));
    outcome
}

/// Why a redirect was not followed.
enum RedirectRefusal {
    /// The origin moved. A positive disagreement about which server answers.
    Mismatch(String),
    /// The redirect was unusable, which measures nothing.
    Partial(String),
}

/// Resolve one redirect hop, refusing anything that leaves the validated origin.
fn redirect_target(
    base: &url::Url,
    current: &url::Url,
    response: &reqwest::blocking::Response,
) -> Result<url::Url, RedirectRefusal> {
    let Some(location) = response.headers().get(reqwest::header::LOCATION) else {
        return Err(RedirectRefusal::Partial(
            "the origin returned a redirect with no Location header".to_string(),
        ));
    };
    let Ok(location) = location.to_str() else {
        return Err(RedirectRefusal::Partial(
            "the origin returned a Location header that is not valid text".to_string(),
        ));
    };
    let Ok(target) = current.join(location) else {
        return Err(RedirectRefusal::Partial(
            "the origin returned a Location header that is not a URL".to_string(),
        ));
    };
    // The origin comparison runs BEFORE any validation that would resolve the
    // host: the target is attacker-influenced text, and validating first turns
    // every off-origin hostname into a live lookup against the attacker's own
    // nameserver. The same ordering argument the registry redirect lock makes.
    if !same_origin(base, &target) {
        return Err(RedirectRefusal::Mismatch(
            "the route redirected off the validated origin".to_string(),
        ));
    }
    Ok(target)
}

/// Whether two URLs name the same scheme, host, and port.
fn same_origin(base: &url::Url, target: &url::Url) -> bool {
    base.scheme() == target.scheme()
        && base.host_str().map(str::to_ascii_lowercase)
            == target.host_str().map(str::to_ascii_lowercase)
        && base.port_or_known_default() == target.port_or_known_default()
}

/// Classify a non-redirect response and, when it is a body worth hashing, hash
/// exactly the bytes that came back.
fn finish_route(
    mut outcome: RouteOutcome,
    response: reqwest::blocking::Response,
    settings: FetchSettings,
    remaining: &AtomicU64,
) -> RouteOutcome {
    use std::io::Read as _;

    let status = response.status();
    // A challenge is a challenge whatever the status line says, so the header is
    // checked alongside the codes.
    let challenged = response
        .headers()
        .contains_key(reqwest::header::WWW_AUTHENTICATE)
        || matches!(status.as_u16(), 401 | 403 | 407 | 511);
    if challenged {
        outcome.detail = Some(format!(
            "the route is authenticated or challenged (HTTP {})",
            status.as_u16()
        ));
        return outcome;
    }
    if matches!(status.as_u16(), 404 | 410) {
        // A manifest-listed path that the origin does not serve is a positive
        // disagreement with the build, not a measurement failure.
        outcome.state = RouteState::Mismatch;
        outcome.detail = Some(format!(
            "the origin does not serve this route (HTTP {})",
            status.as_u16()
        ));
        return outcome;
    }
    if !status.is_success() {
        outcome.detail = Some(format!("the origin returned HTTP {}", status.as_u16()));
        return outcome;
    }
    // EVERY field line, and every comma-separated token inside each: RFC 9110
    // 5.3 makes repeated field lines equivalent to one comma-joined list, so an
    // origin that says `identity` and a CDN in front of it that appends `gzip`
    // together mean `identity, gzip`. Reading only the first line would hash the
    // compressed bytes and report the build as wrong for something transit did.
    let transformed = response
        .headers()
        .get_all(reqwest::header::CONTENT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .find(|token| !token.is_empty() && !token.eq_ignore_ascii_case("identity"));
    if let Some(token) = transformed {
        // The request asked for identity and this build of reqwest decodes
        // nothing, so the body on the wire is not the body that was built.
        // Calling that a byte mismatch would blame the build for a CDN.
        outcome.detail = Some(format!(
            "the response was transformed in transit (Content-Encoding: {})",
            crate::util::truncate_bytes(token, MAX_OBSERVATION_BYTES)
        ));
        return outcome;
    }

    if let Some(declared) = response.content_length() {
        if declared > settings.max_response_bytes {
            outcome.detail = Some(format!(
                "the response declares {declared} bytes, over the {} byte per-response cap",
                settings.max_response_bytes
            ));
            return outcome;
        }
    }

    // Claim the budget BEFORE reading, so two workers cannot both read against
    // the same remaining bytes.
    let claim = settings.max_response_bytes;
    let granted = remaining
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
            (left >= claim).then(|| left - claim)
        })
        .is_ok();
    if !granted {
        outcome.detail = Some(format!(
            "the {} byte aggregate response budget was exhausted before this route",
            settings.aggregate_budget
        ));
        return outcome;
    }

    let mut body = Vec::new();
    let read = response
        .take(settings.max_response_bytes.saturating_add(1))
        .read_to_end(&mut body);
    // Give back what was not used, so a run of small responses is not charged
    // the per-response cap each time.
    let spent = body.len() as u64;
    remaining.fetch_add(claim.saturating_sub(spent.min(claim)), Ordering::SeqCst);
    if let Err(error) = read {
        outcome.detail = Some(format!("the response body could not be read: {error}"));
        return outcome;
    }
    if spent > settings.max_response_bytes {
        outcome.detail = Some(format!(
            "the response body exceeded the {} byte per-response cap",
            settings.max_response_bytes
        ));
        return outcome;
    }

    let digest = sha256_hex(&body);
    outcome.body_bytes = Some(spent);
    if digest == outcome.expected_sha256 {
        outcome.state = RouteState::Match;
    } else {
        outcome.state = RouteState::Mismatch;
        outcome.detail =
            Some("the served bytes are not the bytes the build receipt bound".to_string());
    }
    outcome.body_sha256 = Some(digest);
    outcome
}

/// Record the deployment-hygiene headers, bounded and terminal-neutralized.
fn record_observations(outcome: &mut RouteOutcome, headers: &reqwest::header::HeaderMap) {
    for name in OBSERVED_HEADERS {
        let Some(value) = headers.get(*name) else {
            continue;
        };
        let Ok(text) = value.to_str() else {
            continue;
        };
        let safe = crate::util::truncate_bytes(
            &crate::mcp::output_filter::sanitize_for_display(text),
            MAX_OBSERVATION_BYTES,
        );
        outcome.observations.push(format!("{name}: {safe}"));
        if name.starts_with("content-security-policy")
            && text
                .to_ascii_lowercase()
                .contains("require-trusted-types-for")
        {
            outcome
                .observations
                .push("trusted-types: required by the content security policy".to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

/// What the deployment receipt is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentSubject {
    /// The build receipt this run compared against.
    pub build_receipt_id: String,
    pub build_receipt_status: AttestStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tree_digest: Option<String>,
    /// The base URL, userinfo-redacted.
    pub base_url: String,
    /// The scheme, host, and port the whole run was locked to.
    pub origin: String,
    /// `default` or `explicit`, so a reader knows whether the route mapping was
    /// a Tirith convention or the operator's own statement.
    pub route_map_source: String,
    pub route_count: usize,
}

/// What was and was not accounted for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentCoverage {
    /// Whether the build receipt passed its own integrity rules. A run that
    /// starts from an unverifiable build receipt fetches nothing.
    pub build_receipt_verified: bool,
    /// What the build receipt's signature established.
    #[serde(default = "unsigned_trust")]
    pub build_signature: crate::build_receipt::SignatureTrust,
    /// Why no route was fetched, when the route map itself was refused. Named
    /// rather than left as an empty ledger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_map_refusal: Option<String>,
    /// How many files the build produced, taken from the output TREE rather than
    /// from the manifest: the manifest is capped, and reading the cap as the
    /// total would make a truncated build look like whole-site coverage. The
    /// difference between this and `routes_requested` is the part of the build
    /// this receipt says NOTHING about.
    pub output_files_total: usize,
    pub routes_requested: usize,
    pub routes_matched: usize,
    pub routes_mismatched: usize,
    pub routes_partial: usize,
    /// Always `false` in this schema; see [`crate::build_receipt`] on why the
    /// audit chain's receipt anchors cannot accept an operator-chosen path.
    pub audit_chain_anchored: bool,
}

/// The serde default for a document written before `build_signature` existed.
fn unsigned_trust() -> crate::build_receipt::SignatureTrust {
    crate::build_receipt::SignatureTrust::Unsigned
}

/// A content-addressed, optionally ed25519-signed deployment receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentReceipt {
    pub schema: u32,
    pub receipt_type: String,
    /// sha256 over the canonical JSON with `receipt_id` and `signature` blanked.
    pub receipt_id: String,
    pub created_at: String,
    pub tirith_version: String,
    pub engine_build_sha: String,
    pub policy_projection_hash: String,
    pub status: AttestStatus,
    pub subject: DeploymentSubject,
    pub routes: Vec<RouteOutcome>,
    pub coverage: DeploymentCoverage,
    pub caveats: Vec<String>,
    /// Inside the content address on purpose, so stripping the signature is a
    /// mismatch rather than a silent downgrade to unsigned.
    pub signature_present: bool,
    pub signature: Option<String>,
}

/// Everything [`DeploymentReceipt::new`] needs.
#[derive(Debug, Clone)]
pub struct DeploymentReceiptFacts {
    pub policy_projection_hash: String,
    pub status: AttestStatus,
    pub subject: DeploymentSubject,
    pub routes: Vec<RouteOutcome>,
    pub coverage: DeploymentCoverage,
}

/// Why a deployment receipt could not be assembled, trusted, or saved.
#[derive(Debug)]
pub enum DeploymentReceiptError {
    Invalid(String),
    Malformed(String),
    Io(std::io::Error),
}

impl std::fmt::Display for DeploymentReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "refusing an invalid deployment receipt: {reason}"),
            Self::Malformed(reason) => write!(f, "not a deployment receipt: {reason}"),
            Self::Io(error) => write!(f, "deployment receipt I/O failed: {error}"),
        }
    }
}

impl std::error::Error for DeploymentReceiptError {}

impl DeploymentReceipt {
    /// Assemble, stamp the content address, and sign when a key is available.
    pub fn new(facts: DeploymentReceiptFacts) -> Self {
        let mut receipt = Self {
            schema: DEPLOYMENT_RECEIPT_SCHEMA,
            receipt_type: DEPLOYMENT_RECEIPT_TYPE.to_string(),
            receipt_id: String::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
            tirith_version: env!("CARGO_PKG_VERSION").to_string(),
            engine_build_sha: crate::receipt::engine_build_sha().to_string(),
            policy_projection_hash: facts.policy_projection_hash,
            status: facts.status,
            subject: facts.subject,
            routes: facts.routes,
            coverage: facts.coverage,
            caveats: vec![
                POINT_IN_TIME_CAVEAT.to_string(),
                OBSERVATIONS_CAVEAT.to_string(),
            ],
            signature_present: false,
            signature: None,
        };
        let signature = {
            let mut probe = receipt.clone();
            probe.signature_present = true;
            probe.receipt_id = probe.compute_content_hash();
            crate::audit::sign_canonical_bytes(probe.signing_payload().as_bytes())
        };
        receipt.signature_present = signature.is_some();
        receipt.receipt_id = receipt.compute_content_hash();
        receipt.signature = signature;
        receipt
    }

    /// The canonical JSON the signature covers.
    pub fn signing_payload(&self) -> String {
        self.canonical_json(false)
    }

    /// Lowercase-hex sha256 of the canonical JSON with `receipt_id` and
    /// `signature` blanked.
    pub fn compute_content_hash(&self) -> String {
        sha256_hex(self.canonical_json(true).as_bytes())
    }

    fn canonical_json(&self, blank_receipt_id: bool) -> String {
        let serialized = serde_json::to_value(self);
        debug_assert!(
            serialized.is_ok(),
            "deployment receipt failed to serialize; a field is not serializable"
        );
        let mut value = serialized.unwrap_or(serde_json::Value::Null);
        if let Some(object) = value.as_object_mut() {
            if blank_receipt_id {
                object.insert(
                    "receipt_id".to_string(),
                    serde_json::Value::String(String::new()),
                );
            }
            object.insert("signature".to_string(), serde_json::Value::Null);
        }
        crate::audit::canonical_json_for_hash(&value)
    }

    /// Whether the stored id still matches a recomputation over the content.
    pub fn content_hash_matches(&self) -> bool {
        self.receipt_id == self.compute_content_hash()
    }

    /// Verify the detached signature against an ed25519 public key.
    pub fn signature_verifies(&self, public_key: &[u8; 32]) -> bool {
        use base64::Engine as _;
        use ed25519_dalek::Verifier as _;

        let Some(encoded) = self.signature.as_deref() else {
            return false;
        };
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
            return false;
        };
        let Ok(signature) = ed25519_dalek::Signature::from_slice(&bytes) else {
            return false;
        };
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        key.verify(self.signing_payload().as_bytes(), &signature)
            .is_ok()
    }

    /// Every honesty invariant, checked before the receipt reaches a file.
    ///
    /// The load-bearing rule is the [`AttestStatus::Clean`] gate: a clean
    /// deployment receipt requires a verified build receipt, at least one route,
    /// every requested route to have MATCHED, and every built file to have been
    /// fetched. Partial coverage is fine and normal, and the ledger says how much
    /// was covered, but it is PARTIAL: the durable status field and the exit code
    /// must not be more permissive than [`verify_deployment`], which reads the
    /// same numbers off the same document.
    pub fn validate(&self) -> Result<(), DeploymentReceiptError> {
        if self.schema != DEPLOYMENT_RECEIPT_SCHEMA {
            return Err(DeploymentReceiptError::Invalid(format!(
                "unsupported deployment receipt schema {}",
                self.schema
            )));
        }
        if self.receipt_type != DEPLOYMENT_RECEIPT_TYPE {
            return Err(DeploymentReceiptError::Malformed(
                "receipt_type is not a deployment receipt".to_string(),
            ));
        }
        if !self.content_hash_matches() {
            return Err(DeploymentReceiptError::Invalid(
                "receipt_id does not match the canonical receipt content".to_string(),
            ));
        }
        if self.signature_present != self.signature.is_some() {
            return Err(DeploymentReceiptError::Invalid(
                "the signature does not match what the signed content says about it".to_string(),
            ));
        }
        if self.coverage.audit_chain_anchored {
            return Err(DeploymentReceiptError::Invalid(
                "this schema is never audit-chain anchored, so it cannot claim to be".to_string(),
            ));
        }
        for required in [POINT_IN_TIME_CAVEAT, OBSERVATIONS_CAVEAT] {
            if !self.caveats.iter().any(|caveat| caveat == required) {
                return Err(DeploymentReceiptError::Invalid(
                    "the receipt must carry its honesty caveats".to_string(),
                ));
            }
        }
        let counted = tally(&self.routes);
        if counted
            != (
                self.coverage.routes_matched,
                self.coverage.routes_mismatched,
                self.coverage.routes_partial,
            )
        {
            return Err(DeploymentReceiptError::Invalid(
                "the coverage counters do not match the recorded routes".to_string(),
            ));
        }
        if self.coverage.routes_requested != self.routes.len() {
            return Err(DeploymentReceiptError::Invalid(
                "the requested route count does not match the recorded routes".to_string(),
            ));
        }
        if self.status == AttestStatus::Clean {
            if !self.coverage.build_receipt_verified {
                return Err(DeploymentReceiptError::Invalid(
                    "a clean receipt requires a verified build receipt".to_string(),
                ));
            }
            if self.routes.is_empty() {
                return Err(DeploymentReceiptError::Invalid(
                    "a clean receipt requires at least one fetched route".to_string(),
                ));
            }
            if self.coverage.routes_mismatched > 0 || self.coverage.routes_partial > 0 {
                return Err(DeploymentReceiptError::Invalid(
                    "a clean receipt cannot carry a mismatched or unmeasured route".to_string(),
                ));
            }
            if self.coverage.output_files_total > self.coverage.routes_requested {
                return Err(DeploymentReceiptError::Invalid(
                    "a clean receipt cannot leave built files unfetched".to_string(),
                ));
            }
            if self.subject.build_receipt_status != AttestStatus::Clean {
                return Err(DeploymentReceiptError::Invalid(
                    "a clean receipt cannot stand on a build receipt that was not itself clean"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Serialize for publication.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Parse and validate a deployment receipt document.
    pub fn parse(text: &str) -> Result<Self, DeploymentReceiptError> {
        let receipt: Self = serde_json::from_str(text)
            .map_err(|error| DeploymentReceiptError::Malformed(error.to_string()))?;
        receipt.validate()?;
        Ok(receipt)
    }

    /// Read, parse, and validate a deployment receipt from a bounded file.
    pub fn load(path: &std::path::Path) -> Result<Self, DeploymentReceiptError> {
        let receipt = Self::load_unvalidated(path)?;
        receipt.validate()?;
        Ok(receipt)
    }

    /// Read and parse without validating, so a caller can tell "not a deployment
    /// receipt" from "a deployment receipt that no longer stands up".
    pub fn load_unvalidated(path: &std::path::Path) -> Result<Self, DeploymentReceiptError> {
        let bytes = crate::util::read_text_no_follow_capped(path, MAX_DEPLOYMENT_RECEIPT_BYTES)
            .map_err(|error| DeploymentReceiptError::Malformed(format!("{error:?}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| DeploymentReceiptError::Malformed(error.to_string()))
    }

    /// Validate, then write the receipt atomically at mode 0600.
    pub fn write_to(&self, path: &std::path::Path) -> Result<(), DeploymentReceiptError> {
        self.validate()?;
        crate::util::write_file_atomic_0600(path, self.to_json().as_bytes())
            .map_err(DeploymentReceiptError::Io)
    }
}

/// Count the route states. Returned as a tuple in
/// `(matched, mismatched, partial)` order.
pub fn tally(routes: &[RouteOutcome]) -> (usize, usize, usize) {
    let mut matched = 0;
    let mut mismatched = 0;
    let mut partial = 0;
    for route in routes {
        match route.state {
            RouteState::Match => matched += 1,
            RouteState::Mismatch => mismatched += 1,
            RouteState::Partial => partial += 1,
        }
    }
    (matched, mismatched, partial)
}

/// Roll the route states into the receipt status.
pub fn roll_up_status(routes: &[RouteOutcome]) -> AttestStatus {
    routes.iter().fold(AttestStatus::Clean, |status, route| {
        status.worst(route.state.as_status())
    })
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

/// Everything `tirith attest deployment` was asked to do.
#[derive(Debug, Clone)]
pub struct DeploymentRequest {
    pub base_url: String,
    /// `None` selects [`default_route_map`], which the receipt records as
    /// `default` so a reader can tell a convention from an operator statement.
    pub route_map: Option<RouteMap>,
    pub settings: FetchSettings,
}

/// Verify the build receipt, fetch the mapped routes, and assemble.
///
/// The ordering is the security property: the build receipt is verified FIRST,
/// and a build receipt that fails its own integrity rules or carries a signature
/// this installation rejects produces a Mismatch with zero requests. Fetching
/// against a document that cannot be trusted would mean comparing served bytes
/// with digests nobody stands behind.
///
/// The route map is validated here whichever way it arrived. The CLI validates
/// the explicit one too, for a better message, but the DEFAULT map is derived
/// from filenames in a build tree that nothing has character-checked, so it is
/// exactly as untrusted as the operator's file and cannot be the one path that
/// skips the gate.
pub fn deployment_receipt(
    build: &BuildReceipt,
    request: &DeploymentRequest,
    policy_projection_hash: String,
    anchor: crate::build_receipt::SignatureAnchor,
) -> DeploymentReceipt {
    use crate::build_receipt::SignatureTrust;

    let (build_signature, _) = crate::build_receipt::classify_signature(
        build.signature.is_some(),
        |key| build.signature_verifies(key),
        anchor,
        "build receipt",
    );
    let build_verified = build.validate().is_ok() && build_signature != SignatureTrust::Rejected;
    let (map, source) = match request.route_map.clone() {
        Some(map) => (map, "explicit"),
        None => (default_route_map(&build.subject.output_files), "default"),
    };
    let route_map_refusal = validate_route_map(&map, &build.subject.output_files)
        .err()
        .map(|error| error.to_string());
    let origin = url::Url::parse(&request.base_url)
        .map(|parsed| parsed.origin().ascii_serialization())
        .unwrap_or_else(|_| "unknown".to_string());
    let subject = DeploymentSubject {
        build_receipt_id: build.receipt_id.clone(),
        build_receipt_status: build.status,
        output_tree_digest: build
            .subject
            .output_tree
            .as_ref()
            .map(|tree| tree.digest.clone()),
        base_url: crate::receipt::redact_url_userinfo(&request.base_url),
        origin,
        route_map_source: source.to_string(),
        route_count: map.routes.len(),
    };

    let routes = if build_verified && route_map_refusal.is_none() {
        match fetch_routes(
            &request.base_url,
            &map,
            &build.subject.output_files,
            request.settings,
        ) {
            Ok(routes) => routes,
            Err(error) => {
                // A refused base URL is a statement about the target, so it is a
                // mismatch. Every mapped route is recorded as refused so the
                // ledger still accounts for all of them.
                refused_routes(&map, &build.subject.output_files, &error)
            }
        }
    } else {
        Vec::new()
    };

    // The build's own output TREE, not its manifest: the manifest stops at
    // MAX_RECORDED_OUTPUT_FILES, so a truncated build read off the manifest would
    // report routes_requested == output_files_total and look like whole-site
    // coverage with every file past the cap silently gone.
    let output_files_total = build
        .subject
        .output_tree
        .as_ref()
        .map(|tree| tree.file_count)
        .unwrap_or(build.subject.output_files.len())
        .max(build.subject.output_files.len());

    let (matched, mismatched, partial) = tally(&routes);
    let mut status = if !build_verified || route_map_refusal.is_some() {
        AttestStatus::Mismatch
    } else if routes.is_empty() {
        AttestStatus::Partial
    } else {
        roll_up_status(&routes)
    };
    // Coverage of part of the build is a PARTIAL measurement. Stamping it clean
    // here while `verify_deployment` calls the same numbers partial would put two
    // different answers in one document.
    if output_files_total > routes.len() {
        status = status.worst(AttestStatus::Partial);
    }
    // A build receipt that did not bind everything cannot support a clean
    // deployment answer either, exactly as `verify_build` propagates it.
    if build.status != AttestStatus::Clean {
        status = status.worst(AttestStatus::Partial);
    }
    if build_signature == SignatureTrust::Uncheckable {
        status = status.worst(AttestStatus::Partial);
    }

    DeploymentReceipt::new(DeploymentReceiptFacts {
        policy_projection_hash,
        status,
        subject: DeploymentSubject {
            route_count: routes.len(),
            ..subject
        },
        coverage: DeploymentCoverage {
            build_receipt_verified: build_verified,
            build_signature,
            route_map_refusal,
            output_files_total,
            routes_requested: routes.len(),
            routes_matched: matched,
            routes_mismatched: mismatched,
            routes_partial: partial,
            audit_chain_anchored: false,
        },
        routes,
    })
}

/// Record every mapped route as refused when the run could not start.
fn refused_routes(
    map: &RouteMap,
    files: &[TreeFile],
    error: &DeploymentError,
) -> Vec<RouteOutcome> {
    let fetched_at = chrono::Utc::now().to_rfc3339();
    let state = match error {
        // A private, loopback, or credential-bearing target is a positive
        // statement about the destination the operator named.
        DeploymentError::BaseUrlRefused(_) => RouteState::Mismatch,
        DeploymentError::ClientUnavailable(_) => RouteState::Partial,
    };
    map.routes
        .iter()
        .filter_map(|(build_path, route)| {
            let file = files.iter().find(|file| &file.path == build_path)?;
            Some(RouteOutcome {
                build_path: build_path.clone(),
                route: route.clone(),
                final_url: None,
                redirect_chain: Vec::new(),
                status_code: None,
                body_sha256: None,
                body_bytes: None,
                expected_sha256: file.sha256.clone(),
                expected_bytes: file.size,
                fetched_at: fetched_at.clone(),
                state,
                detail: Some(error.to_string()),
                observations: Vec::new(),
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// verify-deployment
// ---------------------------------------------------------------------------

/// The answer `tirith attest verify-deployment` produces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentVerification {
    pub status: AttestStatus,
    pub receipt_id: String,
    /// What the signature established, never merely whether one is present.
    pub signature: crate::build_receipt::SignatureTrust,
    pub findings: Vec<String>,
    pub routes_matched: usize,
    pub routes_mismatched: usize,
    pub routes_partial: usize,
    /// What the receipt is ABOUT and WHEN it was taken. Without these an old
    /// receipt for a staging origin verifies byte-identically to a fresh one for
    /// production, in both the human and the JSON answer, while the rendering
    /// prints a point-in-time caveat about a timestamp it never shows.
    pub origin: String,
    pub base_url: String,
    pub created_at: String,
    pub build_receipt_id: String,
    pub build_receipt_status: AttestStatus,
    pub output_files_total: usize,
    pub routes_requested: usize,
}

/// Re-verify a deployment receipt DOCUMENT.
///
/// This deliberately does NOT re-fetch. A second fetch would be a second
/// point-in-time measurement, and presenting it as verification of the first
/// would be exactly the continuous-monitoring claim this slice refuses to make.
/// To measure the site again, run `attest deployment` again and compare the two
/// receipts.
pub fn verify_deployment(
    receipt: &DeploymentReceipt,
    anchor: crate::build_receipt::SignatureAnchor,
) -> DeploymentVerification {
    let mut findings = Vec::new();
    let (signature, signature_reason) = crate::build_receipt::classify_signature(
        receipt.signature.is_some(),
        |key| receipt.signature_verifies(key),
        anchor,
        "deployment receipt",
    );
    if let Some(reason) = signature_reason {
        findings.push(reason);
    }
    let mut status = signature.status();
    if let Err(error) = receipt.validate() {
        findings.push(error.to_string());
        status = status.worst(AttestStatus::Mismatch);
    }
    if let Some(refusal) = receipt.coverage.route_map_refusal.as_deref() {
        findings.push(format!("no route was fetched: {refusal}"));
        status = status.worst(AttestStatus::Mismatch);
    }
    if receipt.subject.build_receipt_status != AttestStatus::Clean {
        findings.push(format!(
            "the build receipt behind this one is {}, so the manifest it fetched from is \
             incomplete",
            receipt.subject.build_receipt_status.token()
        ));
        status = status.worst(AttestStatus::Partial);
    }
    if receipt.coverage.routes_mismatched > 0 {
        findings.push(format!(
            "{} route(s) served bytes the build receipt did not bind",
            receipt.coverage.routes_mismatched
        ));
        status = status.worst(AttestStatus::Mismatch);
    }
    if receipt.coverage.routes_partial > 0 {
        findings.push(format!(
            "{} route(s) could not be measured",
            receipt.coverage.routes_partial
        ));
        status = status.worst(AttestStatus::Partial);
    }
    let uncovered = receipt
        .coverage
        .output_files_total
        .saturating_sub(receipt.coverage.routes_requested);
    if uncovered > 0 {
        findings.push(format!(
            "{uncovered} built file(s) were never fetched, so this receipt says nothing about them"
        ));
        status = status.worst(AttestStatus::Partial);
    }
    DeploymentVerification {
        status,
        receipt_id: receipt.receipt_id.clone(),
        signature,
        findings,
        routes_matched: receipt.coverage.routes_matched,
        routes_mismatched: receipt.coverage.routes_mismatched,
        routes_partial: receipt.coverage.routes_partial,
        origin: receipt.subject.origin.clone(),
        base_url: receipt.subject.base_url.clone(),
        created_at: receipt.created_at.clone(),
        build_receipt_id: receipt.subject.build_receipt_id.clone(),
        build_receipt_status: receipt.subject.build_receipt_status,
        output_files_total: receipt.coverage.output_files_total,
        routes_requested: receipt.coverage.routes_requested,
    }
}

#[cfg(test)]
mod tests;
