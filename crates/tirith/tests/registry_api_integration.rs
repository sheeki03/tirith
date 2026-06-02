//! Integration tests for the registry-API-backed package-risk signals.
//!
//! These drive the real HTTP client and JSON parsers in
//! `tirith_core::registry_api` against a local `mockito` mock server (bound to
//! `127.0.0.1`), never the public registries.
//! `HttpRegistryClient::with_base_url_for_test` points all three base URLs at
//! the mock and disables the on-disk cache, so each test is hermetic.

use tirith_core::package_risk::{self, ApiSignals, NameVsPopular, PackageSignals};
use tirith_core::registry_api::{HttpRegistryClient, RegistryClient};
use tirith_core::threatdb::Ecosystem;

/// A trimmed-but-realistic npm full package document, parameterized so a test
/// can make the package new/old, deprecated/current, etc.
fn npm_doc(latest: &str, created: &str, latest_time: &str, deprecated: bool) -> String {
    let dep = if deprecated {
        r#""deprecated": "no longer maintained""#
    } else {
        r#""x": 0"#
    };
    format!(
        r#"{{
            "dist-tags": {{ "latest": "{latest}" }},
            "time": {{
                "created": "{created}",
                "1.0.0": "{created}",
                "{latest}": "{latest_time}"
            }},
            "versions": {{
                "1.0.0": {{ "x": 0 }},
                "{latest}": {{ {dep} }}
            }},
            "maintainers": [ {{ "name": "alice" }} ],
            "repository": {{ "type": "git", "url": "git+https://github.com/o/r.git" }}
        }}"#
    )
}

#[test]
fn npm_fetch_parses_established_package() {
    let mut server = mockito::Server::new();
    let body = npm_doc(
        "2.0.0",
        "2015-01-01T00:00:00.000Z",
        "2023-01-01T00:00:00.000Z",
        false,
    );
    let _m = server
        .mock("GET", "/react")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&body)
        .create();

    let client = HttpRegistryClient::with_base_url_for_test(&server.url());
    let meta = client
        .fetch(Ecosystem::Npm, "react")
        .expect("mock npm fetch should succeed");

    assert_eq!(meta.source, "npm");
    assert_eq!(meta.latest_version.as_deref(), Some("2.0.0"));
    assert!(meta.created_unix.is_some());
    assert!(meta.latest_version_unix.is_some());
    assert!(!meta.yanked_or_deprecated);
    assert_eq!(
        meta.repository_url.as_deref(),
        Some("git+https://github.com/o/r.git")
    );
}

#[test]
fn npm_deprecated_latest_version_is_flagged() {
    let mut server = mockito::Server::new();
    let body = npm_doc(
        "3.0.0",
        "2015-01-01T00:00:00.000Z",
        "2024-01-01T00:00:00.000Z",
        true,
    );
    let _m = server
        .mock("GET", "/somepkg")
        .with_status(200)
        .with_body(&body)
        .create();

    let client = HttpRegistryClient::with_base_url_for_test(&server.url());
    let meta = client.fetch(Ecosystem::Npm, "somepkg").unwrap();
    assert!(
        meta.yanked_or_deprecated,
        "a deprecated latest version must be flagged"
    );
}

#[test]
fn npm_404_degrades_to_unavailable() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/ghost-package")
        .with_status(404)
        .with_body("Not found")
        .create();

    let client = HttpRegistryClient::with_base_url_for_test(&server.url());
    // A 404 must degrade to Unavailable AND surface NotFound (M6 ch6).
    let (sig, existence) =
        tirith_core::registry_api::gather_api_signals(&client, Ecosystem::Npm, "ghost-package");
    assert!(
        matches!(sig, ApiSignals::Unavailable { .. }),
        "a 404 must degrade to ApiSignals::Unavailable, not crash"
    );
    assert_eq!(
        existence,
        tirith_core::package_risk::PackageExistence::NotFound,
        "M6 ch6: a 404 must surface as NotFound, distinct from Unknown"
    );
}

#[test]
fn npm_500_degrades_to_unavailable() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/broken")
        .with_status(500)
        .with_body("internal error")
        .create();

    let client = HttpRegistryClient::with_base_url_for_test(&server.url());
    let (sig, existence) =
        tirith_core::registry_api::gather_api_signals(&client, Ecosystem::Npm, "broken");
    assert!(matches!(sig, ApiSignals::Unavailable { .. }));
    assert_eq!(
        existence,
        tirith_core::package_risk::PackageExistence::Unknown,
        "M6 ch6: a 500 is honest no-data (Unknown), not a positive NotFound"
    );
}

#[test]
fn npm_garbage_body_degrades_to_unavailable() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/weird")
        .with_status(200)
        .with_body("this is definitely not json {{{")
        .create();

    let client = HttpRegistryClient::with_base_url_for_test(&server.url());
    let (sig, _existence) =
        tirith_core::registry_api::gather_api_signals(&client, Ecosystem::Npm, "weird");
    assert!(
        matches!(sig, ApiSignals::Unavailable { .. }),
        "an unparseable body must degrade gracefully"
    );
}

#[test]
fn pypi_fetch_parses_and_picks_repo_url() {
    let mut server = mockito::Server::new();
    let body = r#"{
        "info": {
            "version": "3.1.0",
            "yanked": false,
            "home_page": "",
            "project_urls": { "Source Code": "https://github.com/o/r" }
        },
        "releases": {
            "3.0.0": [ { "upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": false } ],
            "3.1.0": [ { "upload_time_iso_8601": "2024-06-01T00:00:00Z", "yanked": false } ]
        }
    }"#;
    let _m = server
        .mock("GET", "/pypi/flask/json")
        .with_status(200)
        .with_body(body)
        .create();

    let client = HttpRegistryClient::with_base_url_for_test(&server.url());
    let meta = client.fetch(Ecosystem::PyPI, "flask").unwrap();
    assert_eq!(meta.source, "pypi");
    assert_eq!(meta.latest_version.as_deref(), Some("3.1.0"));
    assert_eq!(meta.previous_version.as_deref(), Some("3.0.0"));
    assert_eq!(
        meta.repository_url.as_deref(),
        Some("https://github.com/o/r")
    );
    assert!(!meta.yanked_or_deprecated);
}

#[test]
fn pypi_yanked_latest_version_is_flagged() {
    let mut server = mockito::Server::new();
    let body = r#"{
        "info": { "version": "1.0.0", "yanked": true },
        "releases": {
            "1.0.0": [ { "upload_time_iso_8601": "2024-01-01T00:00:00Z", "yanked": true } ]
        }
    }"#;
    let _m = server
        .mock("GET", "/pypi/badpkg/json")
        .with_status(200)
        .with_body(body)
        .create();

    let client = HttpRegistryClient::with_base_url_for_test(&server.url());
    let meta = client.fetch(Ecosystem::PyPI, "badpkg").unwrap();
    assert!(meta.yanked_or_deprecated);
}

#[test]
fn crates_fetch_parses_downloads_and_yanked() {
    let mut server = mockito::Server::new();
    let body = r#"{
        "crate": {
            "created_at": "2019-05-01T00:00:00.000000+00:00",
            "newest_version": "1.4.0",
            "downloads": 9876543,
            "repository": "https://github.com/o/r"
        },
        "versions": [
            { "num": "1.3.0", "created_at": "2022-01-01T00:00:00.000000+00:00", "yanked": false },
            { "num": "1.4.0", "created_at": "2024-01-01T00:00:00.000000+00:00", "yanked": true }
        ]
    }"#;
    let _m = server
        .mock("GET", "/api/v1/crates/serde")
        .with_status(200)
        .with_body(body)
        .create();

    let client = HttpRegistryClient::with_base_url_for_test(&server.url());
    let meta = client.fetch(Ecosystem::Crates, "serde").unwrap();
    assert_eq!(meta.source, "crates.io");
    assert_eq!(meta.latest_version.as_deref(), Some("1.4.0"));
    assert_eq!(meta.previous_version.as_deref(), Some("1.3.0"));
    assert_eq!(meta.recent_downloads, Some(9_876_543));
    assert!(meta.yanked_or_deprecated, "yanked latest version flagged");
}

#[test]
fn online_score_folds_in_api_factors_end_to_end() {
    // A brand-new crate with low downloads, no repo, and a version spike.
    let mut server = mockito::Server::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // created 3 days ago — "very new".
    let created = chrono::DateTime::from_timestamp((now - 3 * 86_400) as i64, 0)
        .unwrap()
        .to_rfc3339();
    let body = format!(
        r#"{{
            "crate": {{
                "created_at": "{created}",
                "newest_version": "9.0.0",
                "downloads": 4,
                "repository": ""
            }},
            "versions": [
                {{ "num": "1.0.0", "created_at": "{created}", "yanked": false }},
                {{ "num": "9.0.0", "created_at": "{created}", "yanked": false }}
            ]
        }}"#
    );
    let _m = server
        .mock("GET", "/api/v1/crates/evil-crate")
        .with_status(200)
        .with_body(&body)
        .create();

    let client = HttpRegistryClient::with_base_url_for_test(&server.url());
    let (api, _existence) =
        tirith_core::registry_api::gather_api_signals(&client, Ecosystem::Crates, "evil-crate");
    assert!(matches!(api, ApiSignals::Available { .. }));

    // Fold into a full score.
    let signals = PackageSignals {
        ecosystem: Ecosystem::Crates,
        name: "evil-crate".to_string(),
        version: None,
        threat_db_missing: true,
        name_vs_popular: NameVsPopular::Unknown,
        malicious_typosquat_of: None,
        content_signals: package_risk::ContentSignals::NotInspected,
        api,
    };
    let breakdown = package_risk::score_package(&signals);

    // Must verify and carry the very-new / version-spike / low-downloads /
    // missing-repo API factors.
    assert!(breakdown.verify(), "breakdown must sum to score");
    let api_ids: Vec<&str> = breakdown
        .factors
        .iter()
        .map(|f| f.id)
        .filter(|id| id.starts_with("api_"))
        .collect();
    assert!(
        api_ids.contains(&"api_package_very_new"),
        "factors: {api_ids:?}"
    );
    assert!(
        api_ids.contains(&"api_version_spike"),
        "factors: {api_ids:?}"
    );
    assert!(
        api_ids.contains(&"api_low_downloads"),
        "factors: {api_ids:?}"
    );
    assert!(
        api_ids.contains(&"api_repo_url_missing"),
        "factors: {api_ids:?}"
    );
    // The score is meaningfully raised above the bare unknown-name baseline.
    assert!(
        breakdown.score > package_risk::MAX_SCORE / 4,
        "a fully-bad provenance should raise the score, got {}",
        breakdown.score
    );
}

#[test]
fn unsupported_ecosystem_degrades_without_network() {
    // Go has no registry API wired up — must degrade gracefully, and must not
    // even attempt a request (the mock server has no matching route).
    let server = mockito::Server::new();
    let client = HttpRegistryClient::with_base_url_for_test(&server.url());
    let (sig, _existence) =
        tirith_core::registry_api::gather_api_signals(&client, Ecosystem::Go, "anything");
    match sig {
        ApiSignals::Unavailable { reason } => {
            assert!(
                reason.contains("go") || reason.contains("ecosystem"),
                "reason should explain the unsupported ecosystem: {reason}"
            );
        }
        other => panic!("expected Unavailable for an unsupported ecosystem, got {other:?}"),
    }
}

#[test]
fn npm_ownerless_established_package_flags_ownership() {
    // An established npm package with ZERO maintainers must fire the ownership
    // signal (npm DOES expose maintainers).
    let mut server = mockito::Server::new();
    let body = r#"{
        "dist-tags": { "latest": "2.0.0" },
        "time": {
            "created": "2014-01-01T00:00:00.000Z",
            "2.0.0": "2020-01-01T00:00:00.000Z"
        },
        "versions": { "2.0.0": { "x": 0 } },
        "maintainers": [],
        "repository": { "url": "https://github.com/o/r" }
    }"#;
    let _m = server
        .mock("GET", "/abandoned-pkg")
        .with_status(200)
        .with_body(body)
        .create();

    let client = HttpRegistryClient::with_base_url_for_test(&server.url());
    let meta = client.fetch(Ecosystem::Npm, "abandoned-pkg").unwrap();
    // npm exposes a maintainers field — `Some` — and this package lists none.
    assert_eq!(
        meta.maintainers,
        Some(Vec::new()),
        "npm exposes maintainers; this package lists zero"
    );
    let prov = tirith_core::registry_api::provenance_from_metadata(&meta);
    #[allow(deprecated)]
    {
        assert_eq!(
            prov.ownership_transferred,
            Some(true),
            "an ownerless established npm package must flag the ownership signal"
        );
    }
}

#[test]
fn pypi_ownership_signal_is_unknown_not_false_positive() {
    // PyPI carries no maintainer field, so the ownership signal must be `None`,
    // never a false `Some(true)` (the flask false-positive regression guard).
    let mut server = mockito::Server::new();
    let body = r#"{
        "info": { "version": "3.1.0", "yanked": false,
                  "project_urls": { "Source": "https://github.com/o/r" } },
        "releases": {
            "3.0.0": [ { "upload_time_iso_8601": "2015-01-01T00:00:00Z" } ],
            "3.1.0": [ { "upload_time_iso_8601": "2024-01-01T00:00:00Z" } ]
        }
    }"#;
    let _m = server
        .mock("GET", "/pypi/flask/json")
        .with_status(200)
        .with_body(body)
        .create();

    let client = HttpRegistryClient::with_base_url_for_test(&server.url());
    let meta = client.fetch(Ecosystem::PyPI, "flask").unwrap();
    assert_eq!(
        meta.maintainers, None,
        "the PyPI API carries no maintainers field"
    );
    let prov = tirith_core::registry_api::provenance_from_metadata(&meta);
    #[allow(deprecated)]
    {
        assert_eq!(
            prov.ownership_transferred, None,
            "PyPI ownership must be unknown, not a false-positive transfer"
        );
    }
    // And therefore no ownership factor in the score.
    let signals = PackageSignals {
        ecosystem: Ecosystem::PyPI,
        name: "flask".to_string(),
        version: None,
        threat_db_missing: true,
        name_vs_popular: NameVsPopular::KnownPopular,
        malicious_typosquat_of: None,
        content_signals: package_risk::ContentSignals::NotInspected,
        api: ApiSignals::Available { provenance: prov },
    };
    let breakdown = package_risk::score_package(&signals);
    assert!(
        !breakdown
            .factors
            .iter()
            .any(|f| f.id == "api_ownership_transfer"),
        "no ownership factor may appear for a PyPI package"
    );
}

#[test]
fn npm_response_over_size_cap_degrades() {
    // A response whose Content-Length exceeds the 8 MiB cap must degrade, not
    // load into memory.
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/huge-package")
        .with_status(200)
        // Advertise a body far larger than the cap via Content-Length.
        .with_header("content-length", "999999999")
        .with_body("{}")
        .create();

    let client = HttpRegistryClient::with_base_url_for_test(&server.url());
    let (sig, _existence) =
        tirith_core::registry_api::gather_api_signals(&client, Ecosystem::Npm, "huge-package");
    assert!(
        matches!(sig, ApiSignals::Unavailable { .. }),
        "an over-cap response must degrade to Unavailable"
    );
}
