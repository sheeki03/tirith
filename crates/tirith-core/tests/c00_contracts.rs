//! C00: frozen compatibility contracts at the exact post-r3 branch point.
//!
//! These are deliberately golden tests. A mismatch requires an explicit
//! compatibility review; regenerating expected values is not a routine fix.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::OnceLock;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use tirith_core::command_card::Card;
use tirith_core::policy::Policy;
use tirith_core::threatdb::{
    BehaviorTag, Confidence, Ecosystem, ThreatDb, ThreatDbFormat, ThreatDbWriter, ThreatSource,
};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/c00")
}

fn contracts() -> &'static toml::Value {
    static CONTRACTS: OnceLock<toml::Value> = OnceLock::new();
    CONTRACTS.get_or_init(|| {
        let text = std::fs::read_to_string(fixture_root().join("contracts.toml"))
            .expect("read C00 contracts fixture");
        toml::from_str(&text).expect("parse C00 contracts fixture")
    })
}

fn contract_str(section: &str, key: &str) -> &'static str {
    contracts()[section][key]
        .as_str()
        .unwrap_or_else(|| panic!("C00 contract {section}.{key} must be a string"))
}

fn contract_u64(section: &str, key: &str) -> u64 {
    contracts()[section][key]
        .as_integer()
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or_else(|| panic!("C00 contract {section}.{key} must be a non-negative integer"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn frozen_writer() -> ThreatDbWriter {
    let mut writer = ThreatDbWriter::new(1_700_000_000, 181);
    writer.add_package(
        Ecosystem::PyPI,
        "Frozen_Package",
        &["1.0.0", "1.0.1+LOCAL"],
        ThreatSource::OssfMalicious,
        Confidence::Confirmed,
        false,
        Some("https://example.invalid/advisories/C00"),
    );
    writer.add_package(
        Ecosystem::Npm,
        "@scope/frozen-package",
        &[],
        ThreatSource::DatadogMalicious,
        Confidence::Medium,
        true,
        None,
    );
    writer.add_hostname("MALWARE.EXAMPLE.", ThreatSource::OssfMalicious);
    writer.add_ip(Ipv4Addr::new(203, 0, 113, 181), ThreatSource::FeodoTracker);
    writer.add_typosquat(Ecosystem::Npm, "etherss", "ethers");
    writer.add_popular(Ecosystem::Npm, "ethers");
    writer.add_artifact_sha256(
        [0x11; 32],
        ThreatSource::OssfMalicious,
        Confidence::Confirmed,
        true,
        Some("c00-artifact"),
    );
    writer.add_file_sha256(
        [0x22; 32],
        ThreatSource::OssfMalicious,
        Confidence::Medium,
        &[BehaviorTag::ProcessSpawn, BehaviorTag::NetworkExfil],
        Some("c00-file"),
    );
    writer.add_malicious_url("https://malware.example/c00", ThreatSource::OssfMalicious);
    writer
}

#[test]
fn threatdb_v1_v2_writer_bytes_are_frozen() {
    let key = SigningKey::from_bytes(&[0x0b; 32]);
    let mut writer = frozen_writer();
    let v1 = writer
        .build_format(ThreatDbFormat::V1, &key)
        .expect("build frozen v1 DB");
    let v2 = writer
        .build_format(ThreatDbFormat::V2, &key)
        .expect("build frozen v2 DB from the same writer");

    let actual = (
        v1.len() as u64,
        sha256_hex(&v1),
        v2.len() as u64,
        sha256_hex(&v2),
    );
    let expected = (
        contract_u64("threatdb_v1", "size"),
        contract_str("threatdb_v1", "sha256").to_string(),
        contract_u64("threatdb_v2", "size"),
        contract_str("threatdb_v2", "sha256").to_string(),
    );
    assert_eq!(
        actual, expected,
        "ThreatDB writer bytes changed; review ordering, layout, and signing bytes"
    );

    for (expected_format, bytes) in [(1, v1), (2, v2)] {
        let db = ThreatDb::from_bytes(bytes, 0).expect("frozen writer output remains readable");
        assert_eq!(db.stats().format_version, expected_format);
        assert_eq!(db.stats().build_sequence, 181);
    }
}

#[test]
fn legacy_policy_security_projection_is_frozen() {
    let yaml = std::fs::read_to_string(fixture_root().join("legacy-policy-v1.yaml"))
        .expect("read legacy policy fixture");
    let policy: Policy = serde_yaml::from_str(&yaml).expect("legacy policy must keep parsing");
    let projection_bytes =
        serde_json::to_vec(&policy.security_projection()).expect("serialize security projection");

    assert_eq!(
        (
            sha256_hex(&projection_bytes),
            policy.security_projection_hash(),
        ),
        (
            contract_str("legacy_policy", "projection_bytes_sha256").to_string(),
            contract_str("legacy_policy", "security_projection_hash").to_string(),
        ),
        "security projection JSON/hash contract changed"
    );
}

#[test]
fn command_card_v1_signing_bytes_are_frozen() {
    let fixture = std::fs::read_to_string(fixture_root().join("command-card-v1-signing.json"))
        .expect("read command-card fixture");
    let expected_payload = fixture.trim_end().as_bytes();
    let mut card = Card::from_json(expected_payload).expect("parse unsigned v1 card fixture");
    let payload = card.signing_payload().expect("serialize signing payload");
    assert_eq!(
        payload, expected_payload,
        "v1 signing payload bytes changed"
    );
    card.sign(&[0x13; 32]).expect("sign frozen v1 card");
    let signature = card.signature.as_ref().expect("signature block");
    assert_eq!(
        (
            sha256_hex(&payload),
            signature.key_id.as_str(),
            signature.value.as_str(),
        ),
        (
            contract_str("command_card_v1", "signing_payload_sha256").to_string(),
            contract_str("command_card_v1", "key_id"),
            contract_str("command_card_v1", "signature_hex"),
        ),
        "command-card v1 signing contract changed"
    );
}

#[test]
fn default_mcp_tools_list_is_frozen() {
    let mut expected: Vec<String> = contracts()["mcp"]["default_tools"]
        .as_array()
        .expect("mcp.default_tools array")
        .iter()
        .map(|value| value.as_str().expect("MCP tool name string").to_string())
        .collect();
    #[cfg(unix)]
    expected.extend(
        contracts()["mcp"]["unix_additional_tools"]
            .as_array()
            .expect("mcp.unix_additional_tools array")
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .expect("Unix MCP tool name string")
                    .to_string()
            }),
    );

    let actual: Vec<String> = tirith_core::mcp::tools::list()
        .into_iter()
        .map(|tool| tool.name)
        .collect();
    assert_eq!(actual, expected, "default MCP tools/list changed");
}

#[test]
fn capability_manifest_bytes_are_frozen() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/capability-manifest.toml");
    let bytes = std::fs::read(path).expect("read capability manifest");
    assert_eq!(
        sha256_hex(&bytes),
        contract_str("capability_manifest", "sha256"),
        "capability manifest changed before its C00 compatibility contract was reviewed"
    );
}
