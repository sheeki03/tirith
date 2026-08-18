use super::*;

use std::sync::Arc;

use crate::build_receipt::{
    BuildCoverage, BuildEvidence, BuildReceipt, BuildReceiptFacts, BuildSubject, ExecutionLink,
    GitBinding, SignatureAnchor, SignatureTrust, TreeDigest, TreeLimits,
};
use crate::ssrf_guard::test_support::{http_response, ScriptedHttpServer};
use tirith_test_support::GlobalStateGuard;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// The hostname the fixture resolver maps onto the local scripted server. It is
/// public-LOOKING on purpose: the production validator's shape is exercised, and
/// only the resolver is substituted.
const FIXTURE_HOST: &str = "deploy-public.example.test";

fn tree_file(path: &str, body: &[u8]) -> TreeFile {
    TreeFile {
        path: path.to_string(),
        sha256: sha256_hex(body),
        size: body.len() as u64,
        mode: 0o644,
    }
}

/// A validator that accepts only the fixture host, through the REAL server-URL
/// rules with a hermetic DNS answer. A test therefore still exercises the
/// scheme, credential, and destination checks.
fn fixture_validator() -> UrlValidator {
    Arc::new(|candidate: &str| {
        crate::url_validate::validate_server_url_with_resolver_for_test(candidate, &|host, _| {
            if host != FIXTURE_HOST {
                return Err(format!("unexpected validation host: {host}"));
            }
            Ok(vec!["93.184.216.34".parse().expect("public address")])
        })
    })
}

fn fixture_client(address: std::net::SocketAddr) -> reqwest::blocking::Client {
    let resolver = crate::ssrf_guard::fixture_resolver_with_lookup_for_test(move |host| {
        if host != FIXTURE_HOST {
            return Err(format!("unexpected fixture host: {host}"));
        }
        Ok(vec![address])
    });
    crate::ssrf_guard::server_client_builder_with_resolver_for_test(resolver)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .expect("build the fixture client")
}

/// Single-worker settings. The scripted fixture serves one connection at a time
/// from a FIXED list, so concurrent workers would consume the responses in a
/// nondeterministic order.
fn sequential(max_response_bytes: u64, aggregate_budget: u64) -> FetchSettings {
    FetchSettings {
        concurrency: 1,
        max_response_bytes,
        aggregate_budget,
        timeout: std::time::Duration::from_secs(2),
    }
}

fn one_route(path: &str) -> RouteMap {
    let mut routes = BTreeMap::new();
    routes.insert(path.to_string(), format!("/{path}"));
    RouteMap { routes }
}

/// Drive the fetcher against a scripted fixture and return both the outcomes and
/// the raw requests the fixture actually received.
fn run_fixture(
    responses: Vec<Vec<u8>>,
    map: &RouteMap,
    files: &[TreeFile],
    settings: FetchSettings,
) -> (Vec<RouteOutcome>, Vec<Vec<u8>>) {
    let mut environment = GlobalStateGuard::new().expect("isolate deployment receipt fixture");
    let fixture = ScriptedHttpServer::start(responses);
    // The fixture speaks plain HTTP; the destination rules are unchanged.
    environment.set_env("TIRITH_ALLOW_HTTP", "1");
    let address = fixture.address();
    let base = url::Url::parse(&format!("http://{FIXTURE_HOST}:{}/", address.port()))
        .expect("parse the fixture base URL");
    let client = fixture_client(address);
    let outcomes =
        fetch_routes_with_client(&base, &client, map, files, settings, &fixture_validator());
    (outcomes, fixture.finish())
}

fn header_line(requests: &[Vec<u8>], index: usize) -> String {
    String::from_utf8_lossy(&requests[index]).to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Request shape and the happy path
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_matching_route_binds_the_exact_body_bytes_and_asks_for_no_encoding() {
    let body = b"<html>built</html>";
    let files = vec![tree_file("app.js", body)];
    let (outcomes, requests) = run_fixture(
        vec![http_response("200 OK", &[], body)],
        &one_route("app.js"),
        &files,
        sequential(MAX_RESPONSE_BYTES, MAX_AGGREGATE_BYTES),
    );

    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].state, RouteState::Match);
    assert_eq!(
        outcomes[0].body_sha256.as_deref(),
        Some(files[0].sha256.as_str())
    );
    assert_eq!(outcomes[0].body_bytes, Some(body.len() as u64));
    assert_eq!(outcomes[0].status_code, Some(200));
    assert!(outcomes[0].redirect_chain.is_empty());
    assert_eq!(roll_up_status(&outcomes), AttestStatus::Clean);

    assert_eq!(requests.len(), 1);
    let request = header_line(&requests, 0);
    assert!(request.starts_with("get /app.js http/1.1\r\n"));
    assert!(
        request.contains("accept-encoding: identity"),
        "the fetcher must ask for untransformed bytes: {request}"
    );
}

#[cfg(unix)]
#[test]
fn a_different_body_is_a_mismatch_not_a_partial() {
    let files = vec![tree_file("app.js", b"built")];
    let (outcomes, _) = run_fixture(
        vec![http_response("200 OK", &[], b"deployed")],
        &one_route("app.js"),
        &files,
        sequential(MAX_RESPONSE_BYTES, MAX_AGGREGATE_BYTES),
    );
    assert_eq!(outcomes[0].state, RouteState::Mismatch);
    assert_eq!(roll_up_status(&outcomes).exit_code(), 1);
    assert!(outcomes[0]
        .detail
        .as_deref()
        .expect("a mismatch names itself")
        .contains("not the bytes the build receipt bound"));
}

// ---------------------------------------------------------------------------
// Redirects
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_same_origin_redirect_is_followed_and_every_hop_is_recorded() {
    let body = b"built";
    let files = vec![tree_file("app.js", body)];
    let (outcomes, requests) = run_fixture(
        vec![
            http_response("302 Found", &[("Location", "/static/app.js")], b""),
            http_response("200 OK", &[], body),
        ],
        &one_route("app.js"),
        &files,
        sequential(MAX_RESPONSE_BYTES, MAX_AGGREGATE_BYTES),
    );

    assert_eq!(outcomes[0].state, RouteState::Match);
    assert_eq!(outcomes[0].redirect_chain.len(), 1);
    assert!(outcomes[0].redirect_chain[0].ends_with("/static/app.js"));
    assert_eq!(requests.len(), 2);
    assert!(header_line(&requests, 1).starts_with("get /static/app.js http/1.1\r\n"));
}

#[cfg(unix)]
#[test]
fn a_cross_origin_redirect_is_refused_before_a_second_request() {
    let files = vec![tree_file("app.js", b"built")];
    let (outcomes, requests) = run_fixture(
        vec![http_response(
            "302 Found",
            &[("Location", "https://elsewhere.example/app.js")],
            b"",
        )],
        &one_route("app.js"),
        &files,
        sequential(MAX_RESPONSE_BYTES, MAX_AGGREGATE_BYTES),
    );

    assert_eq!(
        outcomes[0].state,
        RouteState::Mismatch,
        "an origin change is a positive disagreement about which server answers"
    );
    assert!(outcomes[0]
        .detail
        .as_deref()
        .expect("detail")
        .contains("off the validated origin"));
    assert_eq!(
        requests.len(),
        1,
        "the off-origin target must never be contacted"
    );
}

#[cfg(unix)]
#[test]
fn a_protocol_relative_redirect_is_treated_as_a_different_origin() {
    let files = vec![tree_file("app.js", b"built")];
    let (outcomes, requests) = run_fixture(
        vec![http_response(
            "302 Found",
            &[("Location", "//elsewhere.example/app.js")],
            b"",
        )],
        &one_route("app.js"),
        &files,
        sequential(MAX_RESPONSE_BYTES, MAX_AGGREGATE_BYTES),
    );
    assert_eq!(outcomes[0].state, RouteState::Mismatch);
    assert_eq!(requests.len(), 1);
}

#[cfg(unix)]
#[test]
fn a_redirect_loop_stops_at_the_hop_cap() {
    let files = vec![tree_file("app.js", b"built")];
    let hop = || http_response("302 Found", &[("Location", "/app.js")], b"");
    let (outcomes, requests) = run_fixture(
        (0..=MAX_REDIRECTS).map(|_| hop()).collect(),
        &one_route("app.js"),
        &files,
        sequential(MAX_RESPONSE_BYTES, MAX_AGGREGATE_BYTES),
    );
    assert_eq!(outcomes[0].state, RouteState::Partial);
    assert!(outcomes[0]
        .detail
        .as_deref()
        .expect("detail")
        .contains("redirected more than"));
    assert_eq!(
        requests.len(),
        MAX_REDIRECTS + 1,
        "the cap bounds the requests, and the fixture proves it"
    );
}

// ---------------------------------------------------------------------------
// Transport states
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_transformed_body_is_partial_and_never_a_byte_mismatch() {
    let files = vec![tree_file("app.js", b"built")];
    let (outcomes, _) = run_fixture(
        vec![http_response(
            "200 OK",
            &[("Content-Encoding", "gzip")],
            b"\x1f\x8b-not-really-gzip",
        )],
        &one_route("app.js"),
        &files,
        sequential(MAX_RESPONSE_BYTES, MAX_AGGREGATE_BYTES),
    );
    assert_eq!(
        outcomes[0].state,
        RouteState::Partial,
        "a CDN that recompressed the body must not be reported as the build being wrong"
    );
    assert!(outcomes[0]
        .detail
        .as_deref()
        .expect("detail")
        .contains("transformed in transit"));
    assert!(outcomes[0].body_sha256.is_none());
}

#[cfg(unix)]
#[test]
fn a_second_content_encoding_field_line_is_not_missed() {
    // RFC 9110 5.3: repeated field lines are equivalent to one comma-joined
    // list, so `identity` then `gzip` means `identity, gzip`. Reading only the
    // first line hashes the compressed bytes and blames the build for a CDN.
    let files = vec![tree_file("app.js", b"built")];
    let mut response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n".to_vec();
    response.extend_from_slice(b"Content-Encoding: identity\r\n");
    response.extend_from_slice(b"Content-Encoding: gzip\r\n");
    response.extend_from_slice(b"Content-Length: 18\r\n\r\n");
    response.extend_from_slice(b"\x1f\x8b-not-really-gzip");
    let (outcomes, _) = run_fixture(
        vec![response],
        &one_route("app.js"),
        &files,
        sequential(MAX_RESPONSE_BYTES, MAX_AGGREGATE_BYTES),
    );
    assert_eq!(
        outcomes[0].state,
        RouteState::Partial,
        "a transit transformation announced on a second field line is still a transformation"
    );
    assert!(outcomes[0]
        .detail
        .as_deref()
        .expect("detail")
        .contains("transformed in transit"));
    assert!(outcomes[0].body_sha256.is_none());
}

#[cfg(unix)]
#[test]
fn a_comma_joined_content_encoding_list_is_not_missed() {
    let files = vec![tree_file("app.js", b"built")];
    let (outcomes, _) = run_fixture(
        vec![http_response(
            "200 OK",
            &[("Content-Encoding", "identity, gzip")],
            b"\x1f\x8b-not-really-gzip",
        )],
        &one_route("app.js"),
        &files,
        sequential(MAX_RESPONSE_BYTES, MAX_AGGREGATE_BYTES),
    );
    assert_eq!(outcomes[0].state, RouteState::Partial);
    assert!(outcomes[0]
        .detail
        .as_deref()
        .expect("detail")
        .contains("transformed in transit"));
}

#[cfg(unix)]
#[test]
fn an_identity_content_encoding_header_is_not_treated_as_a_transformation() {
    let body = b"built";
    let files = vec![tree_file("app.js", body)];
    let (outcomes, _) = run_fixture(
        vec![http_response(
            "200 OK",
            &[("Content-Encoding", "identity")],
            body,
        )],
        &one_route("app.js"),
        &files,
        sequential(MAX_RESPONSE_BYTES, MAX_AGGREGATE_BYTES),
    );
    assert_eq!(outcomes[0].state, RouteState::Match);
}

#[cfg(unix)]
#[test]
fn an_authenticated_or_challenged_route_is_partial() {
    let files = vec![tree_file("app.js", b"built")];
    for response in [
        http_response("401 Unauthorized", &[], b""),
        http_response("403 Forbidden", &[], b""),
        // A 200 that carries a challenge is still a challenge.
        http_response(
            "200 OK",
            &[("WWW-Authenticate", "Bearer realm=\"edge\"")],
            b"built",
        ),
    ] {
        let (outcomes, _) = run_fixture(
            vec![response],
            &one_route("app.js"),
            &files,
            sequential(MAX_RESPONSE_BYTES, MAX_AGGREGATE_BYTES),
        );
        assert_eq!(outcomes[0].state, RouteState::Partial);
        assert!(outcomes[0]
            .detail
            .as_deref()
            .expect("detail")
            .contains("authenticated or challenged"));
    }
}

#[cfg(unix)]
#[test]
fn a_route_the_origin_does_not_serve_is_a_mismatch() {
    let files = vec![tree_file("app.js", b"built")];
    let (outcomes, _) = run_fixture(
        vec![http_response("404 Not Found", &[], b"nope")],
        &one_route("app.js"),
        &files,
        sequential(MAX_RESPONSE_BYTES, MAX_AGGREGATE_BYTES),
    );
    assert_eq!(outcomes[0].state, RouteState::Mismatch);
    assert!(outcomes[0]
        .detail
        .as_deref()
        .expect("detail")
        .contains("does not serve this route"));
}

#[cfg(unix)]
#[test]
fn a_server_error_is_partial_because_it_measures_nothing() {
    let files = vec![tree_file("app.js", b"built")];
    let (outcomes, _) = run_fixture(
        vec![http_response("503 Service Unavailable", &[], b"")],
        &one_route("app.js"),
        &files,
        sequential(MAX_RESPONSE_BYTES, MAX_AGGREGATE_BYTES),
    );
    assert_eq!(outcomes[0].state, RouteState::Partial);
}

// ---------------------------------------------------------------------------
// Caps
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_declared_length_over_the_per_response_cap_is_rejected_before_the_read() {
    let body = b"0123456789abcdef";
    let files = vec![tree_file("app.js", body)];
    let (outcomes, _) = run_fixture(
        vec![http_response("200 OK", &[], body)],
        &one_route("app.js"),
        &files,
        sequential(4, MAX_AGGREGATE_BYTES),
    );
    assert_eq!(outcomes[0].state, RouteState::Partial);
    assert!(outcomes[0]
        .detail
        .as_deref()
        .expect("detail")
        .contains("per-response cap"));
    assert!(outcomes[0].body_sha256.is_none());
}

#[cfg(unix)]
#[test]
fn a_body_with_no_declared_length_is_still_capped_on_the_read() {
    // No Content-Length at all, so the fast reject cannot fire and the
    // take(cap + 1) read is the only thing standing between the fetcher and an
    // unbounded body.
    let mut response =
        b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n".to_vec();
    response.extend_from_slice(b"0123456789abcdef");
    let files = vec![tree_file("app.js", b"0123456789abcdef")];
    let (outcomes, _) = run_fixture(
        vec![response],
        &one_route("app.js"),
        &files,
        sequential(4, MAX_AGGREGATE_BYTES),
    );
    assert_eq!(outcomes[0].state, RouteState::Partial);
    assert!(outcomes[0]
        .detail
        .as_deref()
        .expect("detail")
        .contains("per-response cap"));
}

#[cfg(unix)]
#[test]
fn an_exhausted_aggregate_budget_stops_the_run_as_partial() {
    let body = b"built";
    let files = vec![tree_file("app.js", body)];
    let (outcomes, _) = run_fixture(
        vec![http_response("200 OK", &[], body)],
        &one_route("app.js"),
        &files,
        // The whole aggregate budget is smaller than one per-response claim, so
        // the very first route cannot reserve its share.
        sequential(64, 8),
    );
    assert_eq!(outcomes[0].state, RouteState::Partial);
    assert!(outcomes[0]
        .detail
        .as_deref()
        .expect("detail")
        .contains("aggregate response budget"));
}

// ---------------------------------------------------------------------------
// Observations
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn security_headers_are_recorded_as_observations_and_never_change_the_state() {
    let body = b"deployed";
    let files = vec![tree_file("app.js", b"built")];
    let (outcomes, _) = run_fixture(
        vec![http_response(
            "200 OK",
            &[(
                "Content-Security-Policy",
                "default-src 'self'; require-trusted-types-for 'script'",
            )],
            body,
        )],
        &one_route("app.js"),
        &files,
        sequential(MAX_RESPONSE_BYTES, MAX_AGGREGATE_BYTES),
    );

    assert_eq!(
        outcomes[0].state,
        RouteState::Mismatch,
        "a perfect CSP over the wrong bytes is still the wrong bytes"
    );
    assert!(outcomes[0]
        .observations
        .iter()
        .any(|line| line.starts_with("content-security-policy:")));
    assert!(outcomes[0]
        .observations
        .iter()
        .any(|line| line.starts_with("trusted-types:")));
}

#[cfg(unix)]
#[test]
fn observations_come_from_the_response_that_served_the_bytes_and_no_other() {
    let body = b"built";
    let files = vec![tree_file("app.js", body)];
    // A 302 carrying a perfect hygiene posture, then the response that actually
    // serves the bytes carrying none of it. Scraping both would let the receipt
    // assert a CSP for an asset that has no CSP.
    let (outcomes, _) = run_fixture(
        vec![
            http_response(
                "302 Found",
                &[
                    ("Location", "/final"),
                    (
                        "Content-Security-Policy",
                        "default-src 'none'; require-trusted-types-for 'script'",
                    ),
                    ("Strict-Transport-Security", "max-age=63072000"),
                ],
                b"",
            ),
            http_response("200 OK", &[], body),
        ],
        &one_route("app.js"),
        &files,
        sequential(MAX_RESPONSE_BYTES, MAX_AGGREGATE_BYTES),
    );

    assert_eq!(outcomes[0].state, RouteState::Match);
    assert_eq!(
        outcomes[0].observations,
        Vec::<String>::new(),
        "a hop's headers are not the served response's headers"
    );
}

// ---------------------------------------------------------------------------
// Destination boundary
// ---------------------------------------------------------------------------

#[test]
fn a_loopback_base_url_is_refused_before_any_request() {
    let files = vec![tree_file("app.js", b"built")];
    let error = fetch_routes(
        "https://127.0.0.1/",
        &one_route("app.js"),
        &files,
        FetchSettings::default(),
    )
    .expect_err("a loopback destination must be refused");
    assert!(matches!(error, DeploymentError::BaseUrlRefused(_)));
}

#[test]
fn a_credential_bearing_base_url_is_refused() {
    let files = vec![tree_file("app.js", b"built")];
    let error = fetch_routes(
        "https://user:secret@app.example/",
        &one_route("app.js"),
        &files,
        FetchSettings::default(),
    )
    .expect_err("an embedded credential must be refused");
    assert!(matches!(error, DeploymentError::BaseUrlRefused(_)));
}

// ---------------------------------------------------------------------------
// Route maps
// ---------------------------------------------------------------------------

#[test]
fn the_default_route_map_serves_index_html_from_its_directory() {
    let files = vec![
        tree_file("index.html", b"root"),
        tree_file("docs/index.html", b"docs"),
        tree_file("assets/app.js", b"js"),
        // Not an index file: the suffix must be a whole path component.
        tree_file("myindex.html", b"decoy"),
    ];
    let map = default_route_map(&files);
    assert_eq!(map.routes["index.html"], "/");
    assert_eq!(map.routes["docs/index.html"], "/docs/");
    assert_eq!(map.routes["assets/app.js"], "/assets/app.js");
    assert_eq!(map.routes["myindex.html"], "/myindex.html");
}

#[test]
fn an_explicit_route_map_overrides_the_default_and_accepts_both_spellings() {
    let files = vec![tree_file("app.js", b"js")];
    let wrapped = parse_route_map(r#"{"routes": {"app.js": "/static/app.js"}}"#).expect("parse");
    let bare = parse_route_map(r#"{"app.js": "/static/app.js"}"#).expect("parse");
    assert_eq!(wrapped, bare);
    validate_route_map(&wrapped, &files).expect("a mapped built file validates");
    assert_ne!(wrapped, default_route_map(&files));
}

#[test]
fn an_spa_route_map_may_point_several_routes_at_one_built_file() {
    let files = vec![tree_file("index.html", b"spa")];
    // A single-page app serves the same document from every deep link. The
    // build path is the key, so the catch-all is expressed as one mapping and
    // the receipt records exactly which URL was measured.
    let map = parse_route_map(r#"{"index.html": "/dashboard/settings"}"#).expect("parse");
    validate_route_map(&map, &files).expect("an SPA deep link validates");
}

#[test]
fn a_route_map_naming_a_file_the_build_did_not_produce_is_refused() {
    let files = vec![tree_file("app.js", b"js")];
    let map = parse_route_map(r#"{"vendor.js": "/vendor.js"}"#).expect("parse");
    assert_eq!(
        validate_route_map(&map, &files),
        Err(RouteMapError::UnknownBuildPath("vendor.js".to_string()))
    );
}

#[test]
fn a_route_that_leaves_the_origin_is_refused() {
    let files = vec![tree_file("app.js", b"js")];
    for route in [
        "https://elsewhere.example/app.js",
        "//elsewhere.example/app.js",
        "app.js",
        "/../../etc/passwd",
        // Under the WHATWG rules a special scheme treats `\` as `/`, so this is
        // a protocol-relative URL wearing a path's clothes.
        "/\\elsewhere.example:443/app.js",
        "/\\\\elsewhere.example/app.js",
        // ASCII tab, LF, and CR are STRIPPED before parsing, so each of these
        // also collapses to `//elsewhere.example/...`.
        "/\t/elsewhere.example/app.js",
        "/\n/elsewhere.example/app.js",
        "/\r/elsewhere.example/app.js",
        // A filename a build tree can legally contain, which is how the DEFAULT
        // route map reaches this rule.
        "/\\c2.example/p?id=1",
    ] {
        let map = RouteMap {
            routes: BTreeMap::from([("app.js".to_string(), route.to_string())]),
        };
        assert!(
            matches!(
                validate_route_map(&map, &files),
                Err(RouteMapError::InvalidRoute(_))
            ),
            "{route:?} must be refused"
        );
        // And the resolved authority is what the fetcher checks, independently of
        // the predicate above.
        let base = url::Url::parse("https://good.example/").expect("base");
        if let Ok(joined) = base.join(route) {
            assert!(
                !same_origin(&base, &joined) || joined.host_str() == Some("good.example"),
                "{route:?} resolved to {joined} and the origin check must catch it"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn a_route_resolving_off_the_origin_reaches_no_network() {
    let files = vec![tree_file("app.js", b"built")];
    // Every one of these passes a naive "starts with / and not //" predicate and
    // still resolves to another authority. The fixture is scripted with one
    // response; if the fetcher sent the request anywhere it would consume it.
    for route in [
        "/\\evil.example:443/app.js",
        "/\t/evil.example/app.js",
        "/\\c2.example/p",
    ] {
        let map = RouteMap {
            routes: BTreeMap::from([("app.js".to_string(), route.to_string())]),
        };
        // A fixture scripted with NO responses at all: it fails loudly if the
        // fetcher connects, which is the property under test.
        let (outcomes, requests) = run_fixture(
            Vec::new(),
            &map,
            &files,
            sequential(MAX_RESPONSE_BYTES, MAX_AGGREGATE_BYTES),
        );
        assert_eq!(
            outcomes[0].state,
            RouteState::Mismatch,
            "{route:?} must be a mismatch"
        );
        assert!(outcomes[0]
            .detail
            .as_deref()
            .expect("detail")
            .contains("different origin"));
        assert!(
            requests.is_empty(),
            "{route:?} must reach no server at all, and it reached {}",
            requests.len()
        );
    }
}

#[test]
fn the_default_route_map_goes_through_the_same_gate_as_an_explicit_one() {
    // A directory named `\c2.example` holding a file `p?id=1` is a legal tree on
    // Linux and macOS, and the tree scanner applies no character validation, so
    // an honest `attest build` over a hostile dependency produces this manifest.
    let hostile = tree_file("\\c2.example/p?id=1", b"js");
    let map = default_route_map(std::slice::from_ref(&hostile));
    assert_eq!(map.routes["\\c2.example/p?id=1"], "/\\c2.example/p?id=1");
    assert!(matches!(
        validate_route_map(&map, std::slice::from_ref(&hostile)),
        Err(RouteMapError::InvalidRoute(_))
    ));

    let build = build_with(vec![hostile], AttestStatus::Partial);
    let receipt = deployment_receipt(
        &build,
        &DeploymentRequest {
            base_url: "https://app.example/".to_string(),
            route_map: None,
            settings: FetchSettings::default(),
        },
        "a".repeat(64),
        unsigned_anchor(),
    );
    assert_eq!(receipt.status, AttestStatus::Mismatch);
    assert!(
        receipt.routes.is_empty(),
        "a refused route map must fetch nothing"
    );
    assert!(receipt
        .coverage
        .route_map_refusal
        .as_deref()
        .expect("the refusal names itself")
        .contains("same-origin"));
    receipt.validate().expect("the receipt is still valid");
}

#[test]
fn the_default_route_map_is_capped_like_an_explicit_one() {
    // `default_route_map` emits one route per manifest entry with no cap of its
    // own, so the cap has to come from the gate. Only a hand-edited build
    // receipt can carry a manifest this long, which is why `BuildReceipt`
    // refuses one too; this is the other half of that pair.
    let files: Vec<TreeFile> = (0..MAX_ROUTES + 7)
        .map(|index| tree_file(&format!("f{index}.js"), b"js"))
        .collect();
    let map = default_route_map(&files);
    assert_eq!(map.routes.len(), files.len());
    assert_eq!(
        validate_route_map(&map, &files),
        Err(RouteMapError::TooManyRoutes(files.len()))
    );

    let build = build_with(files, AttestStatus::Partial);
    assert!(
        build.validate().is_err(),
        "a manifest over the cap must not be a valid build receipt either"
    );
    let receipt = deployment_receipt(
        &build,
        &DeploymentRequest {
            base_url: "https://app.example/".to_string(),
            route_map: None,
            settings: FetchSettings::default(),
        },
        "a".repeat(64),
        unsigned_anchor(),
    );
    assert!(
        receipt.routes.is_empty(),
        "an oversized manifest must not turn one command into thousands of requests"
    );
}

#[test]
fn an_empty_or_malformed_route_map_is_refused() {
    let files = vec![tree_file("app.js", b"js")];
    assert_eq!(
        validate_route_map(&RouteMap::default(), &files),
        Err(RouteMapError::Empty)
    );
    assert!(matches!(
        parse_route_map("not json"),
        Err(RouteMapError::Malformed(_))
    ));
    assert!(matches!(
        parse_route_map(r#"{"app.js": 7}"#),
        Err(RouteMapError::Malformed(_))
    ));
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

fn build_with(files: Vec<TreeFile>, status: AttestStatus) -> BuildReceipt {
    build_with_tree(files.len(), files, status, false)
}

/// A build receipt whose output TREE claims `tree_files` files while its
/// manifest carries `files`. The two differ exactly when the manifest was
/// truncated, which is the case the coverage arithmetic has to survive.
fn build_with_tree(
    tree_files: usize,
    files: Vec<TreeFile>,
    status: AttestStatus,
    truncated: bool,
) -> BuildReceipt {
    // A clean build receipt has to be internally coherent or it fails its own
    // honesty rules and the deployment run refuses it for the wrong reason.
    let bound = status == AttestStatus::Clean;
    let tree = |files: usize| TreeDigest {
        digest: "c".repeat(64),
        file_count: files,
        directory_count: 0,
        total_bytes: 0,
        mode_model: crate::build_receipt::ModeModel::host(),
    };
    BuildReceipt::new(BuildReceiptFacts {
        policy_projection_hash: "a".repeat(64),
        status,
        subject: BuildSubject {
            source_tree: bound.then(|| tree(1)),
            source_exclusions: Vec::new(),
            source_pruned: Vec::new(),
            output_relative: Some("dist".to_string()),
            output_tree: Some(tree(tree_files)),
            output_exclusions: Vec::new(),
            output_files: files,
            output_files_truncated: truncated,
            git: GitBinding::default(),
            lockfiles: Vec::new(),
            argv_digest: "b".repeat(64),
            argv_len: 1,
        },
        evidence: BuildEvidence {
            tools: Vec::new(),
            execution: ExecutionLink::default(),
            limits: TreeLimits::default(),
        },
        coverage: BuildCoverage {
            source_scanned: bound,
            output_scanned: bound,
            scan_refusal: (!bound).then(|| "synthetic".to_string()),
            audit_chain_anchored: false,
        },
    })
}

fn assembled_receipt(routes: Vec<RouteOutcome>, build_verified: bool) -> DeploymentReceipt {
    let (matched, mismatched, partial) = tally(&routes);
    DeploymentReceipt::new(DeploymentReceiptFacts {
        policy_projection_hash: "a".repeat(64),
        status: if build_verified {
            roll_up_status(&routes)
        } else {
            AttestStatus::Mismatch
        },
        subject: DeploymentSubject {
            build_receipt_id: "b".repeat(64),
            build_receipt_status: AttestStatus::Clean,
            output_tree_digest: Some("c".repeat(64)),
            base_url: "https://app.example/".to_string(),
            origin: "https://app.example".to_string(),
            route_map_source: "default".to_string(),
            route_count: routes.len(),
        },
        coverage: DeploymentCoverage {
            build_receipt_verified: build_verified,
            build_signature: SignatureTrust::Unsigned,
            route_map_refusal: None,
            output_files_total: routes.len(),
            routes_requested: routes.len(),
            routes_matched: matched,
            routes_mismatched: mismatched,
            routes_partial: partial,
            audit_chain_anchored: false,
        },
        routes,
    })
}

/// An installation that neither signs nor can check a signature, so the
/// signature rules are held still and the test measures what it says it does.
fn unsigned_anchor() -> SignatureAnchor {
    SignatureAnchor::default()
}

fn outcome(state: RouteState) -> RouteOutcome {
    RouteOutcome {
        build_path: "app.js".to_string(),
        route: "/app.js".to_string(),
        final_url: Some("https://app.example/app.js".to_string()),
        redirect_chain: Vec::new(),
        status_code: Some(200),
        body_sha256: Some("d".repeat(64)),
        body_bytes: Some(5),
        expected_sha256: "d".repeat(64),
        expected_bytes: 5,
        fetched_at: "2026-01-01T00:00:00Z".to_string(),
        state,
        detail: None,
        observations: Vec::new(),
    }
}

#[test]
fn a_fresh_deployment_receipt_is_content_addressed_and_valid() {
    let receipt = assembled_receipt(vec![outcome(RouteState::Match)], true);
    assert_eq!(receipt.status, AttestStatus::Clean);
    assert_eq!(receipt.receipt_id.len(), 64);
    assert!(receipt.content_hash_matches());
    receipt.validate().expect("a coherent receipt validates");
    assert!(!receipt.coverage.audit_chain_anchored);
}

#[test]
fn every_field_is_bound_by_the_content_address() {
    let receipt = assembled_receipt(vec![outcome(RouteState::Match)], true);
    for mutate in [
        (|r: &mut DeploymentReceipt| r.status = AttestStatus::Partial) as fn(&mut _),
        |r: &mut DeploymentReceipt| r.subject.origin = "https://evil.example".to_string(),
        |r: &mut DeploymentReceipt| r.routes[0].body_sha256 = Some("e".repeat(64)),
        |r: &mut DeploymentReceipt| r.coverage.routes_matched = 9,
        |r: &mut DeploymentReceipt| r.routes[0].observations.push("x".to_string()),
    ] {
        let mut tampered = receipt.clone();
        mutate(&mut tampered);
        assert!(!tampered.content_hash_matches());
        assert!(tampered.validate().is_err());
    }
}

#[test]
fn stripping_the_signature_fails_verification() {
    let mut receipt = assembled_receipt(vec![outcome(RouteState::Match)], true);
    receipt.signature_present = true;
    receipt.receipt_id = receipt.compute_content_hash();
    receipt.signature = Some("signed-elsewhere".to_string());
    receipt.validate().expect("a signed receipt validates");

    let mut stripped = receipt;
    stripped.signature = None;
    assert!(stripped.content_hash_matches());
    assert!(stripped.validate().is_err());
}

#[test]
fn a_build_receipt_does_not_deserialize_as_a_deployment_receipt() {
    let build = build_with(vec![tree_file("app.js", b"js")], AttestStatus::Partial);
    assert!(matches!(
        DeploymentReceipt::parse(&build.to_json()),
        Err(DeploymentReceiptError::Malformed(_))
    ));
}

#[test]
fn a_clean_status_requires_a_verified_build_and_no_unmeasured_route() {
    let mut mismatched = assembled_receipt(vec![outcome(RouteState::Match)], true);
    mismatched.coverage.routes_mismatched = 1;
    mismatched.receipt_id = mismatched.compute_content_hash();
    assert!(mismatched.validate().is_err());

    let mut unverified = assembled_receipt(vec![outcome(RouteState::Match)], true);
    unverified.coverage.build_receipt_verified = false;
    unverified.receipt_id = unverified.compute_content_hash();
    assert!(unverified.validate().is_err());

    let mut empty = assembled_receipt(Vec::new(), true);
    empty.status = AttestStatus::Clean;
    empty.receipt_id = empty.compute_content_hash();
    assert!(
        empty.validate().is_err(),
        "a receipt that fetched nothing cannot be clean"
    );
}

#[test]
fn the_coverage_counters_must_match_the_recorded_routes() {
    let mut receipt = assembled_receipt(
        vec![outcome(RouteState::Match), outcome(RouteState::Partial)],
        true,
    );
    receipt.coverage.routes_partial = 0;
    receipt.receipt_id = receipt.compute_content_hash();
    assert!(receipt.validate().is_err());
}

#[test]
fn a_receipt_that_drops_its_caveats_is_refused() {
    let mut receipt = assembled_receipt(vec![outcome(RouteState::Match)], true);
    receipt.caveats.clear();
    receipt.receipt_id = receipt.compute_content_hash();
    assert!(receipt.validate().is_err());
}

// ---------------------------------------------------------------------------
// Assembly and verify-deployment
// ---------------------------------------------------------------------------

#[test]
fn an_unverifiable_build_receipt_produces_a_mismatch_with_no_fetch() {
    let mut build = build_with(vec![tree_file("app.js", b"js")], AttestStatus::Partial);
    // Tamper: the content address no longer covers the document.
    build.subject.argv_digest = "f".repeat(64);
    assert!(build.validate().is_err());

    let receipt = deployment_receipt(
        &build,
        &DeploymentRequest {
            // A destination that would be refused anyway, so a fetch attempt
            // could not be mistaken for success.
            base_url: "https://app.example/".to_string(),
            route_map: None,
            settings: FetchSettings::default(),
        },
        "a".repeat(64),
        unsigned_anchor(),
    );
    assert_eq!(receipt.status, AttestStatus::Mismatch);
    assert!(!receipt.coverage.build_receipt_verified);
    assert!(
        receipt.routes.is_empty(),
        "nothing may be fetched against a build receipt that does not stand up"
    );
    receipt
        .validate()
        .expect("a mismatch receipt is still valid");
}

#[test]
fn a_refused_base_url_records_every_route_as_a_mismatch() {
    let build = build_with(vec![tree_file("app.js", b"js")], AttestStatus::Partial);
    let receipt = deployment_receipt(
        &build,
        &DeploymentRequest {
            base_url: "https://127.0.0.1/".to_string(),
            route_map: None,
            settings: FetchSettings::default(),
        },
        "a".repeat(64),
        unsigned_anchor(),
    );
    assert_eq!(receipt.status, AttestStatus::Mismatch);
    assert_eq!(receipt.coverage.routes_mismatched, 1);
    assert!(receipt.routes[0]
        .detail
        .as_deref()
        .expect("detail")
        .contains("base URL was refused"));
    receipt.validate().expect("valid");
}

#[test]
fn verify_deployment_re_checks_the_document_and_never_re_fetches() {
    let clean = assembled_receipt(vec![outcome(RouteState::Match)], true);
    let verification = verify_deployment(&clean, unsigned_anchor());
    assert_eq!(verification.status, AttestStatus::Clean);
    assert!(verification.findings.is_empty());
    assert_eq!(verification.status.exit_code(), 0);

    let mut tampered = clean.clone();
    tampered.routes[0].body_sha256 = Some("0".repeat(64));
    let verification = verify_deployment(&tampered, unsigned_anchor());
    assert_eq!(verification.status, AttestStatus::Mismatch);
    assert_eq!(verification.status.exit_code(), 1);
}

#[test]
fn verify_deployment_reports_the_built_files_that_were_never_fetched() {
    let mut receipt = assembled_receipt(vec![outcome(RouteState::Match)], true);
    receipt.coverage.output_files_total = 12;
    // The document's own status must already be partial: a receipt that covered
    // one file of twelve and called itself clean would say one thing in the
    // field that gets mailed around and another when it is re-checked.
    receipt.status = AttestStatus::Partial;
    receipt.receipt_id = receipt.compute_content_hash();

    let verification = verify_deployment(&receipt, unsigned_anchor());
    assert_eq!(verification.status, AttestStatus::Partial);
    assert_eq!(verification.status.exit_code(), 3);
    assert!(verification
        .findings
        .iter()
        .any(|finding| finding.contains("never fetched")));

    // And the same numbers under a clean label are refused as a document, so the
    // permissive answer cannot be re-created by hand.
    let mut relabelled = receipt;
    relabelled.status = AttestStatus::Clean;
    relabelled.receipt_id = relabelled.compute_content_hash();
    assert!(relabelled.validate().is_err());
}

#[test]
fn a_truncated_build_manifest_is_never_reported_as_whole_site_coverage() {
    // The build produced 4097 files and the manifest stops at the cap. Reading
    // the manifest length as the total makes routes_requested == the total and
    // the uncovered arithmetic structurally zero, so every file past the cap
    // disappears from the ledger.
    let files: Vec<TreeFile> = (0..crate::build_receipt::MAX_RECORDED_OUTPUT_FILES)
        .map(|index| tree_file(&format!("f{index:05}.js"), b"js"))
        .collect();
    let build = build_with_tree(
        crate::build_receipt::MAX_RECORDED_OUTPUT_FILES + 1,
        files,
        AttestStatus::Partial,
        true,
    );

    let receipt = deployment_receipt(
        &build,
        &DeploymentRequest {
            // Refused before any request, so this test measures the ledger and
            // not a network.
            base_url: "https://127.0.0.1/".to_string(),
            route_map: None,
            settings: FetchSettings::default(),
        },
        "a".repeat(64),
        unsigned_anchor(),
    );
    assert_eq!(
        receipt.coverage.output_files_total,
        crate::build_receipt::MAX_RECORDED_OUTPUT_FILES + 1,
        "the total must come from the output tree, not the capped manifest"
    );
    assert!(receipt.coverage.output_files_total > receipt.coverage.routes_requested);

    let verification = verify_deployment(&receipt, unsigned_anchor());
    assert!(verification
        .findings
        .iter()
        .any(|finding| finding.contains("never fetched")));
    assert!(verification
        .findings
        .iter()
        .any(|finding| finding.contains("build receipt behind this one is partial")));
}

#[test]
fn partial_coverage_is_partial_in_the_document_and_in_the_verifier_alike() {
    // One route mapped against a hundred built files. The permissive halves were
    // the durable status field and the exit code, so both are pinned here.
    let files: Vec<TreeFile> = (0..100)
        .map(|index| tree_file(&format!("f{index:03}.js"), b"js"))
        .collect();
    let build = build_with(files, AttestStatus::Clean);
    let receipt = deployment_receipt(
        &build,
        &DeploymentRequest {
            // Refused before any request: this test is about the ledger, and a
            // fetch would need a network.
            base_url: "https://127.0.0.1/".to_string(),
            route_map: Some(RouteMap {
                routes: BTreeMap::from([("f000.js".to_string(), "/f000.js".to_string())]),
            }),
            settings: FetchSettings::default(),
        },
        "a".repeat(64),
        unsigned_anchor(),
    );
    assert_eq!(receipt.coverage.output_files_total, 100);
    assert_eq!(receipt.coverage.routes_requested, 1);
    assert_ne!(receipt.status, AttestStatus::Clean);

    let verification = verify_deployment(&receipt, unsigned_anchor());
    assert!(verification
        .findings
        .iter()
        .any(|finding| finding.contains("99 built file(s) were never fetched")));

    // And the permissive answer cannot be written by hand either: a document
    // that measured one file of a hundred may not carry a clean status.
    let mut relabelled = assembled_receipt(vec![outcome(RouteState::Match)], true);
    relabelled.coverage.output_files_total = 100;
    relabelled.status = AttestStatus::Clean;
    relabelled.receipt_id = relabelled.compute_content_hash();
    let error = relabelled
        .validate()
        .expect_err("clean over partial coverage must be refused");
    assert!(error.to_string().contains("unfetched"));
}

#[test]
fn verify_deployment_reports_what_the_receipt_is_about_and_when_it_was_taken() {
    let receipt = assembled_receipt(vec![outcome(RouteState::Match)], true);
    let verification = verify_deployment(&receipt, unsigned_anchor());
    assert_eq!(verification.origin, "https://app.example");
    assert_eq!(verification.base_url, "https://app.example/");
    assert_eq!(verification.created_at, receipt.created_at);
    assert_eq!(
        verification.build_receipt_id,
        receipt.subject.build_receipt_id
    );
    assert_eq!(verification.build_receipt_status, AttestStatus::Clean);
    assert_eq!(verification.routes_requested, 1);
    assert_eq!(verification.output_files_total, 1);
}

#[test]
fn verify_deployment_refuses_a_receipt_whose_signature_does_not_verify() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let anchor = SignatureAnchor {
        verifying_key: Some(key.verifying_key().to_bytes()),
        signing_expected: true,
    };
    let mut receipt = assembled_receipt(vec![outcome(RouteState::Match)], true);
    receipt.signature_present = true;
    receipt.receipt_id = receipt.compute_content_hash();
    {
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;
        receipt.signature = Some(
            base64::engine::general_purpose::STANDARD
                .encode(key.sign(receipt.signing_payload().as_bytes()).to_bytes()),
        );
    }
    let honest = verify_deployment(&receipt, anchor);
    assert_eq!(honest.status, AttestStatus::Clean);
    assert_eq!(honest.signature, SignatureTrust::Verified);

    // A fabricated signature plus a recomputed content address: the forgery must
    // not read as the more trustworthy document.
    let mut forged = receipt;
    forged.signature = Some("AAAA-not-a-real-ed25519-signature".to_string());
    forged.receipt_id = forged.compute_content_hash();
    let verification = verify_deployment(&forged, anchor);
    assert_eq!(verification.status, AttestStatus::Mismatch);
    assert_eq!(verification.signature, SignatureTrust::Rejected);
}

#[test]
fn a_build_receipt_whose_signature_is_rejected_is_never_fetched_against() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let anchor = SignatureAnchor {
        verifying_key: Some(key.verifying_key().to_bytes()),
        signing_expected: true,
    };
    let mut build = build_with(vec![tree_file("app.js", b"js")], AttestStatus::Clean);
    build.signature_present = true;
    build.signature = Some("AAAA-not-a-real-ed25519-signature".to_string());
    build.receipt_id = build.compute_content_hash();
    assert!(
        build.validate().is_ok(),
        "the forgery is self-consistent, which is the whole point"
    );

    let receipt = deployment_receipt(
        &build,
        &DeploymentRequest {
            base_url: "https://app.example/".to_string(),
            route_map: None,
            settings: FetchSettings::default(),
        },
        "a".repeat(64),
        anchor,
    );
    assert_eq!(receipt.status, AttestStatus::Mismatch);
    assert!(!receipt.coverage.build_receipt_verified);
    assert_eq!(receipt.coverage.build_signature, SignatureTrust::Rejected);
    assert!(
        receipt.routes.is_empty(),
        "nothing may be fetched against a build receipt whose signature is rejected"
    );
}

#[test]
fn the_shipped_bounds_are_the_documented_ones() {
    let settings = FetchSettings::default();
    assert_eq!(settings.concurrency, 8);
    assert_eq!(settings.max_response_bytes, 32 * 1024 * 1024);
    assert_eq!(settings.aggregate_budget, 2 * 1024 * 1024 * 1024);
    assert_eq!(MAX_REDIRECTS, 5);
}
