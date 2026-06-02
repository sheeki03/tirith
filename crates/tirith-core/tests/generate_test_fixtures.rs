//! One-shot generator for the Ed25519 keypair and test threat DB fixture.
//!
//! Run with: `cargo test -p tirith-core --test generate_test_fixtures -- --ignored`
//!
//! Generates `assets/keys/threatdb-verify.pub` (raw public key),
//! `<repo>/threatdb-signing.key` (base64 private key, gitignored), and
//! `<repo>/tests/fixtures/test-threatdb.dat` (signed test DB).

use std::net::Ipv4Addr;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use tirith_core::threatdb::{Confidence, Ecosystem, ThreatDbWriter, ThreatSource};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Generate a fresh Ed25519 keypair: write the public key to assets (embedded
/// via `include_bytes!`) and the base64 private key to the repo root (gitignored).
fn generate_keypair() -> SigningKey {
    let signing_key = SigningKey::generate(&mut OsRng);

    let pub_path = crate_root().join("assets/keys/threatdb-verify.pub");
    std::fs::write(&pub_path, signing_key.verifying_key().as_bytes())
        .unwrap_or_else(|e| panic!("Failed to write {}: {}", pub_path.display(), e));
    eprintln!("Wrote public key to {}", pub_path.display());

    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(signing_key.to_bytes());
    let key_path = repo_root().join("threatdb-signing.key");
    std::fs::write(&key_path, &b64)
        .unwrap_or_else(|e| panic!("Failed to write {}: {}", key_path.display(), e));
    eprintln!("Wrote private key to {}", key_path.display());

    signing_key
}

/// Build the test threat DB fixture with known entries for golden fixture tests.
fn build_test_db(signing_key: &SigningKey) {
    let mut writer = ThreatDbWriter::new(1700000000, 42);

    writer.add_package(
        Ecosystem::Npm,
        "evil-package",
        &["1.0.0", "1.0.1"],
        ThreatSource::OssfMalicious,
        Confidence::Confirmed,
        false,
        Some("https://example.com/advisory/evil-package"),
    );
    writer.add_package(
        Ecosystem::PyPI,
        "malware-pkg",
        &[],
        ThreatSource::DatadogMalicious,
        Confidence::Confirmed,
        true,
        None,
    );
    writer.add_package(
        Ecosystem::Npm,
        "borderline-pkg",
        &["2.0.0"],
        ThreatSource::OssfMalicious,
        Confidence::Medium,
        false,
        Some("https://example.com/advisory/borderline-pkg"),
    );

    writer.add_ip(Ipv4Addr::new(203, 0, 113, 50), ThreatSource::FeodoTracker);

    writer.add_typosquat(Ecosystem::Npm, "reacct", "react");
    writer.add_typosquat(Ecosystem::PyPI, "reqeusts", "requests");

    // Popular packages for Levenshtein distance checks.
    writer.add_popular(Ecosystem::Npm, "react");
    writer.add_popular(Ecosystem::Npm, "express");
    writer.add_popular(Ecosystem::PyPI, "requests");
    writer.add_popular(Ecosystem::PyPI, "flask");

    let dat_path = repo_root().join("tests/fixtures/test-threatdb.dat");
    writer
        .write_to(&dat_path, signing_key)
        .unwrap_or_else(|e| panic!("Failed to write test DB: {}", e));
    eprintln!("Wrote test DB to {}", dat_path.display());

    // Structural reload only: verify_signature() fails until a rebuild embeds
    // the freshly-written public key via `include_bytes!`.
    let db = tirith_core::threatdb::ThreatDb::load_from_path(&dat_path, 0)
        .expect("Failed to reload test DB");
    let stats = db.stats();
    assert_eq!(stats.package_count, 3, "expected 3 packages");
    assert_eq!(stats.ip_count, 1, "expected 1 IP");
    assert_eq!(stats.typosquat_count, 2, "expected 2 typosquats");
    assert_eq!(stats.popular_count, 4, "expected 4 popular");
    eprintln!(
        "Test DB: {} packages, {} IPs, {} typosquats, {} popular",
        stats.package_count, stats.ip_count, stats.typosquat_count, stats.popular_count
    );
    eprintln!("Signature will verify after recompilation with new public key.");
}

#[test]
#[ignore = "one-shot generator, run manually with --ignored"]
fn generate_keypair_and_test_db() {
    let key = generate_keypair();
    build_test_db(&key);
    eprintln!("Done. Now rebuild tirith-core to embed the new public key.");
}
