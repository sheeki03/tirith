//! C16 unit tests. Every extension tree here is SYNTHETIC: no real extension's
//! code is copied. Wallet extension ids appear only as classification fixtures,
//! exactly as the shared sensitive-asset catalogue already holds them.

use std::path::{Path, PathBuf};

use super::*;

/// A real MetaMask id, used here only as a fixture for the wallet LABEL. It is
/// never a trust anchor and never changes a digest, a risk level, or a drift
/// verdict.
const WALLET_ID: &str = "nkbihfbeogaeaoehlefnkodbefgpgknn";
/// A real Rabby id, same status.
const WALLET_ID_TWO: &str = "acmacodkjbdgmoleebolmdjonilkdbch";
/// A synthetic non-wallet id.
const PLAIN_ID: &str = "abcdefghijklmnopabcdefghijklmnop";

fn temp() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("tirith-browser-audit-")
        .tempdir()
        .expect("create fixture root")
}

/// Create `<root>/<name>` as a profile directory and return it.
fn make_profile(root: &Path, name: &str) -> PathBuf {
    let profile = root.join(name);
    std::fs::create_dir_all(profile.join("Extensions")).expect("create profile");
    profile
}

/// Write one synthetic extension version tree.
fn write_extension(
    profile: &Path,
    id: &str,
    version_dir: &str,
    manifest: &str,
    files: &[(&str, &str)],
) -> PathBuf {
    let dir = profile.join("Extensions").join(id).join(version_dir);
    std::fs::create_dir_all(&dir).expect("create extension version directory");
    std::fs::write(dir.join("manifest.json"), manifest).expect("write manifest");
    for (relative, contents) in files {
        let path = dir.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create extension subdirectory");
        }
        std::fs::write(path, contents).expect("write extension file");
    }
    dir
}

/// Write a `Preferences` document declaring an install location per id, plus a
/// pile of realistic-shaped private data that the audit must never carry out.
fn write_preferences(profile: &Path, entries: &[(&str, u64, bool)]) {
    let mut settings = serde_json::Map::new();
    for (id, location, from_webstore) in entries {
        settings.insert(
            (*id).to_string(),
            serde_json::json!({
                "location": location,
                "from_webstore": from_webstore,
                "was_installed_by_default": false,
                // Fields OUTSIDE the allowed set, seeded on purpose.
                "manifest": {"name": "POISON-PREF-MANIFEST-NAME"},
                "path": "POISON-PREF-PATH",
                "ack_external": true,
                "install_time": "13300000000000000",
            }),
        );
    }
    let document = serde_json::json!({
        "extensions": {"settings": settings},
        "account_info": [{"email": "POISON-ACCOUNT-EMAIL@example.invalid"}],
        "profile": {
            "name": "POISON-PROFILE-DISPLAY-NAME",
            "content_settings": {"exceptions": {"cookies": {"POISON-COOKIE-HOST": 1}}},
        },
        "sync": {"last_synced_time": "POISON-SYNC-TIME"},
        "session": {"startup_urls": ["https://poison-startup-url.invalid/"]},
    });
    std::fs::write(
        profile.join("Preferences"),
        serde_json::to_string(&document).expect("serialize preferences"),
    )
    .expect("write preferences");
}

/// Seed the storage roots the audit must never open.
fn seed_private_stores(profile: &Path) {
    let seeds: &[(&str, &str)] = &[
        ("Cookies", "POISON-COOKIES"),
        ("History", "POISON-HISTORY"),
        ("Login Data", "POISON-LOGIN-DATA"),
        ("Web Data", "POISON-WEB-DATA"),
        ("Local Storage/leveldb/000003.log", "POISON-LOCAL-STORAGE"),
        (
            "Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log",
            "POISON-WALLET-VAULT",
        ),
        (
            "Sync Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000004.log",
            "POISON-WALLET-SYNC",
        ),
        (
            "IndexedDB/chrome-extension_nkbihfbeogaeaoehlefnkodbefgpgknn_0.indexeddb.leveldb/000003.log",
            "POISON-WALLET-INDEXEDDB",
        ),
    ];
    for (relative, contents) in seeds {
        let path = profile.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create private store directory");
        }
        std::fs::write(path, contents).expect("write private store seed");
    }
}

const MV3_WALLET_MANIFEST: &str = r#"{
  "manifest_version": 3,
  "name": "Synthetic Wallet",
  "version": "10.0.0",
  "permissions": ["storage", "notifications", "scripting"],
  "host_permissions": ["https://rpc.example.invalid/*"],
  "background": {"service_worker": "background.js"},
  "content_scripts": [{"matches": ["https://dapp.example.invalid/*"], "js": ["inpage.js"]}],
  "externally_connectable": {"ids": ["abcdefghijklmnopabcdefghijklmnop"]}
}"#;

const MV2_MANIFEST: &str = r#"{
  "manifest_version": 2,
  "name": "Synthetic Legacy",
  "version": "1.2.3",
  "permissions": ["storage", "https://legacy.example.invalid/*"],
  "background": {"scripts": ["bg.js"]}
}"#;

const MV3_BROAD_MANIFEST: &str = r#"{
  "manifest_version": 3,
  "name": "Synthetic Broad",
  "version": "2.0.0",
  "permissions": ["debugger", "nativeMessaging", "webRequestBlocking", "cookies"],
  "host_permissions": ["<all_urls>", "*://*/*"],
  "background": {"service_worker": "sw.js"}
}"#;

fn audit_profile(profile: &Path) -> BrowserRecord {
    audit_report(profile)
        .browsers
        .into_iter()
        .next()
        .expect("one browser")
}

fn audit_report(profile: &Path) -> BrowserAuditReport {
    audit(&AuditRequest {
        families: vec![BrowserFamily::Chrome],
        explicit_profile: Some(profile.to_path_buf()),
        budget: AuditBudget::default(),
    })
}

fn only_extension(record: &BrowserRecord) -> &ExtensionRecord {
    &record.profiles[0].extensions[0]
}

/// Every rejection in a profile, wherever it was recorded. An extension's own
/// rejections are what reach the baseline and therefore drift; the profile-level
/// list holds the ones that belong to no extension. A test asserting a refusal
/// happened should not care which list it landed in, only that it happened.
fn all_rejections(record: &BrowserRecord) -> Vec<RejectedEntry> {
    let profile = &record.profiles[0];
    profile
        .rejected
        .iter()
        .cloned()
        .chain(
            profile
                .extensions
                .iter()
                .flat_map(|extension| extension.rejected.iter().cloned()),
        )
        .collect()
}

// ---------------------------------------------------------------------------
// Discovery, identity, and layout
// ---------------------------------------------------------------------------

#[test]
fn every_family_has_a_user_data_root_on_every_supported_platform() {
    for family in BrowserFamily::ALL {
        for platform in [
            HostPlatform::MacOs,
            HostPlatform::Linux,
            HostPlatform::Windows,
        ] {
            let roots = user_data_relative_roots(family, platform);
            assert!(
                !roots.is_empty(),
                "{}/{} has no user-data root",
                family.token(),
                platform.token()
            );
            for root in roots {
                assert!(!root.starts_with('/'), "{root} must be home-relative");
            }
        }
    }
    // Edge is in scope for C16 and must resolve on all three hosts.
    assert_eq!(
        user_data_relative_roots(BrowserFamily::Edge, HostPlatform::Windows),
        &["AppData/Local/Microsoft/Edge/User Data"]
    );
}

#[test]
fn profile_identity_comes_from_the_directory_name_shape_only() {
    assert_eq!(
        classify_profile_directory("Default"),
        Some(ProfileKind::Default)
    );
    assert_eq!(
        classify_profile_directory("Profile 7"),
        Some(ProfileKind::Numbered)
    );
    assert_eq!(
        classify_profile_directory("Guest Profile"),
        Some(ProfileKind::Guest)
    );
    assert_eq!(
        classify_profile_directory("System Profile"),
        Some(ProfileKind::System)
    );
    for not_a_profile in [
        "Crashpad",
        "ShaderCache",
        "Profile",
        "Profile x",
        "Local State",
    ] {
        assert_eq!(classify_profile_directory(not_a_profile), None);
    }
}

#[test]
fn multiple_profiles_enumerate_independently_and_local_state_is_never_read() {
    let root = temp();
    let user_data = root.path().join("User Data");
    std::fs::create_dir_all(&user_data).expect("create user data");
    // The file that holds the human profile names and the signed-in account
    // email. Seeded, and it must not reach the report.
    std::fs::write(
        user_data.join("Local State"),
        serde_json::to_string(&serde_json::json!({
            "profile": {"info_cache": {
                "Default": {"name": "POISON-LOCAL-STATE-NAME",
                            "user_name": "POISON-LOCAL-STATE-EMAIL@example.invalid",
                            "gaia_id": "POISON-GAIA-ID"}
            }}
        }))
        .expect("serialize local state"),
    )
    .expect("write local state");
    std::fs::create_dir_all(user_data.join("Crashpad")).expect("create non-profile sibling");

    for name in [
        "Default",
        "Profile 1",
        "Profile 7",
        "Guest Profile",
        "System Profile",
    ] {
        let profile = make_profile(&user_data, name);
        write_extension(
            &profile,
            PLAIN_ID,
            "1.0.0_0",
            MV3_BROAD_MANIFEST,
            &[("sw.js", name)],
        );
        write_preferences(&profile, &[(PLAIN_ID, 1, true)]);
    }

    let mut progress = AuditProgress::new();
    let record = audit_user_data_dir(
        BrowserFamily::Chrome,
        &user_data,
        &AuditBudget::default(),
        &mut progress,
    );

    assert_eq!(record.status, BrowserStatus::Audited);
    let names: Vec<&str> = record
        .profiles
        .iter()
        .map(|profile| profile.profile_directory.as_str())
        .collect();
    assert_eq!(
        names,
        vec![
            "Default",
            "Guest Profile",
            "Profile 1",
            "Profile 7",
            "System Profile"
        ]
    );
    // Each profile carries its own extension bytes, so identical ids in
    // different profiles are independent subjects.
    let digests: std::collections::BTreeSet<&str> = record
        .profiles
        .iter()
        .map(|profile| profile.extensions[0].tree.digest.as_str())
        .collect();
    assert_eq!(
        digests.len(),
        5,
        "per-profile trees must hash independently"
    );

    let json = serde_json::to_string(&record).expect("serialize");
    for poison in [
        "POISON-LOCAL-STATE-NAME",
        "POISON-LOCAL-STATE-EMAIL",
        "POISON-GAIA-ID",
        "info_cache",
    ] {
        assert!(!json.contains(poison), "{poison} leaked into the report");
    }
}

#[test]
fn a_missing_user_data_directory_is_reported_explicitly() {
    let root = temp();
    let mut progress = AuditProgress::new();
    let record = audit_user_data_dir(
        BrowserFamily::Edge,
        &root.path().join("absent"),
        &AuditBudget::default(),
        &mut progress,
    );
    assert_eq!(record.status, BrowserStatus::UserDataUnreadable);
    assert_eq!(record.coverage, AuditCoverage::Partial);
    assert!(record.profiles.is_empty());
}

// ---------------------------------------------------------------------------
// The privacy boundary
// ---------------------------------------------------------------------------

#[test]
fn the_audit_never_opens_a_path_the_shared_catalogue_calls_sensitive() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    seed_private_stores(&profile);
    write_extension(
        &profile,
        WALLET_ID,
        "10.0.0_0",
        MV3_WALLET_MANIFEST,
        &[
            ("background.js", "// synthetic"),
            ("inpage.js", "// synthetic"),
        ],
    );
    write_preferences(&profile, &[(WALLET_ID, 1, true)]);

    let record = audit_profile(&profile);
    let json = serde_json::to_string(&record).expect("serialize");
    for poison in [
        "POISON-COOKIES",
        "POISON-HISTORY",
        "POISON-LOGIN-DATA",
        "POISON-WEB-DATA",
        "POISON-LOCAL-STORAGE",
        "POISON-WALLET-VAULT",
        "POISON-WALLET-SYNC",
        "POISON-WALLET-INDEXEDDB",
        "Local Extension Settings",
        "Sync Extension Settings",
        "leveldb",
        "IndexedDB",
        "Login Data",
    ] {
        assert!(!json.contains(poison), "{poison} reached the audit output");
    }

    // Positive control: the gate itself refuses each seeded store, so the
    // absence above is enforcement rather than luck.
    //
    // Asserted UNCONDITIONALLY. Guarding it on `classify_path(...).is_some()`
    // made it assert nothing for the four entries where the catalogue gate does
    // not fire, which is every non-wallet store: `classify_path` calls a browser
    // storage root sensitive only when a hardcoded wallet extension id is also
    // in the path, so a plain cookie jar walked straight through the gate this
    // test was written to prove closed.
    for relative in [
        "Cookies",
        "History",
        "Login Data",
        "Web Data",
        "Local Storage/leveldb/000003.log",
        "Local Extension Settings/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/000003.log",
        "Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log",
        "Sync Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000004.log",
        "IndexedDB/chrome-extension_nkbihfbeogaeaoehlefnkodbefgpgknn_0.indexeddb.leveldb/000003.log",
    ] {
        let path = profile.join(relative);
        assert!(
            matches!(
                open_audit_file(&path, 1024),
                Err(RejectionReason::SensitivePath)
            ),
            "the read gate must refuse {relative}, got {:?}",
            open_audit_file(&path, 1024).map(|_| "an open handle")
        );
    }
    // And the user-data-level document that names the signed-in human.
    assert!(matches!(
        open_audit_file(&profile.join("..").join("Local State"), 1024),
        Err(RejectionReason::SensitivePath)
    ));

    // And the source tree the audit DOES read is, by the same catalogue, not
    // sensitive: that carve-out is what makes this audit possible at all.
    let manifest = profile
        .join("Extensions")
        .join(WALLET_ID)
        .join("10.0.0_0")
        .join("manifest.json");
    assert!(
        crate::sensitive_assets::classify_path(&manifest.to_string_lossy()).is_none(),
        "the extension source tree must remain readable"
    );
    assert!(open_audit_file(&manifest, MAX_MANIFEST_BYTES).is_ok());
}

#[test]
fn nothing_outside_the_allowed_preferences_fields_reaches_the_output() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV3_BROAD_MANIFEST,
        &[("sw.js", "// synthetic")],
    );
    write_preferences(&profile, &[(PLAIN_ID, 4, false)]);

    let record = audit_profile(&profile);
    assert_eq!(
        only_extension(&record).install_class,
        InstallClass::DeveloperUnpacked,
        "the allowed `location` field must still be read"
    );

    // Every string in the emitted report, compared against every string the
    // Preferences document holds outside the allowed field set.
    let json = serde_json::to_string(&record).expect("serialize");
    for poison in [
        "POISON-PREF-MANIFEST-NAME",
        "POISON-PREF-PATH",
        "POISON-ACCOUNT-EMAIL",
        "POISON-PROFILE-DISPLAY-NAME",
        "POISON-COOKIE-HOST",
        "POISON-SYNC-TIME",
        "poison-startup-url",
        "ack_external",
        "install_time",
        "account_info",
        "startup_urls",
        "content_settings",
    ] {
        assert!(
            !json.contains(poison),
            "{poison} escaped the bounded preferences read"
        );
    }
    // The allowed set is exactly three fields and the constant says so.
    assert_eq!(
        PREFERENCES_ALLOWED_FIELDS,
        &["location", "from_webstore", "was_installed_by_default"]
    );
}

#[test]
fn no_value_from_outside_the_allowed_preferences_fields_appears_anywhere_in_the_report() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV3_BROAD_MANIFEST,
        &[("sw.js", "// synthetic")],
    );
    write_preferences(&profile, &[(PLAIN_ID, 7, false)]);

    // Every string the Preferences document holds, minus the extension ids and
    // the three allowed field names. Generated from the file rather than listed
    // by hand, so a future field added to the fixture is covered automatically.
    let document: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(profile.join("Preferences")).expect("read preferences"),
    )
    .expect("parse preferences");
    let mut forbidden = std::collections::BTreeSet::new();
    collect_strings(&document, &mut forbidden);
    forbidden.remove(PLAIN_ID);
    for allowed in PREFERENCES_ALLOWED_FIELDS {
        forbidden.remove(*allowed);
    }
    forbidden.remove("extensions");
    forbidden.remove("settings");
    // A word the MANIFEST also uses (`cookies` as a permission, `name` as a
    // manifest key) is legitimately reportable from the manifest side, so
    // subtract everything the manifest carries before accusing the preferences
    // read of leaking it.
    let manifest: serde_json::Value =
        serde_json::from_str(MV3_BROAD_MANIFEST).expect("parse manifest fixture");
    let mut from_manifest = std::collections::BTreeSet::new();
    collect_strings(&manifest, &mut from_manifest);
    for shared in &from_manifest {
        forbidden.remove(shared);
    }
    assert!(!forbidden.is_empty(), "the fixture must carry decoy values");

    let report = serde_json::to_value(audit_report(&profile)).expect("serialize");
    let mut emitted = std::collections::BTreeSet::new();
    collect_strings(&report, &mut emitted);

    let leaked: Vec<&String> = emitted.intersection(&forbidden).collect();
    assert!(
        leaked.is_empty(),
        "these preferences values escaped the bounded read: {leaked:?}"
    );
    // The audit still learned what it was allowed to learn.
    assert_eq!(
        report["browsers"][0]["profiles"][0]["extensions"][0]["install_class"],
        "enterprise_policy"
    );
}

/// Every string key and string value in a JSON document.
fn collect_strings(value: &serde_json::Value, out: &mut std::collections::BTreeSet<String>) {
    match value {
        serde_json::Value::String(text) => {
            out.insert(text.clone());
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_strings(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, item) in map {
                out.insert(key.clone());
                collect_strings(item, out);
            }
        }
        _ => {}
    }
}

#[test]
fn every_wire_token_matches_its_own_serde_spelling() {
    // The human renderer prints `token()` while the JSON envelope prints the
    // serde name. If the two ever disagree, an operator reading one and grepping
    // the other silently misses findings.
    fn assert_token<T: Serialize>(value: &T, token: &str) {
        let serialized = serde_json::to_value(value).expect("serialize");
        assert_eq!(serialized, serde_json::Value::String(token.to_string()));
    }
    for value in BrowserFamily::ALL {
        assert_token(&value, value.token());
    }
    for value in [
        HostPlatform::MacOs,
        HostPlatform::Linux,
        HostPlatform::Windows,
    ] {
        assert_token(&value, value.token());
    }
    for value in [
        InstallClass::WebStore,
        InstallClass::Sideloaded,
        InstallClass::EnterprisePolicy,
        InstallClass::DeveloperUnpacked,
        InstallClass::BrowserComponent,
        InstallClass::Unknown,
    ] {
        assert_token(&value, value.token());
    }
    for value in [
        ProvenanceClass::StoreSigned,
        ProvenanceClass::ComputedHashesOnly,
        ProvenanceClass::Unrecorded,
    ] {
        assert_token(&value, value.token());
    }
    for value in [RiskLevel::Ordinary, RiskLevel::Elevated, RiskLevel::Broad] {
        assert_token(&value, value.token());
    }
    for value in [
        PermissionRiskReason::AllHosts,
        PermissionRiskReason::Debugger,
        PermissionRiskReason::NativeMessaging,
        PermissionRiskReason::WebRequestBlocking,
        PermissionRiskReason::Proxy,
        PermissionRiskReason::Cookies,
        PermissionRiskReason::BrowsingHistory,
        PermissionRiskReason::Management,
        PermissionRiskReason::Downloads,
        PermissionRiskReason::Scripting,
        PermissionRiskReason::BrowserSettings,
        PermissionRiskReason::ClipboardRead,
    ] {
        assert_token(&value, value.token());
    }
    for value in [
        SurfaceChange::Background,
        SurfaceChange::ContentScripts,
        SurfaceChange::ContentScriptMatches,
        SurfaceChange::NativeMessaging,
        SurfaceChange::ExternallyConnectable,
        SurfaceChange::WebAccessibleResources,
        SurfaceChange::DeclarativeNetRequest,
        SurfaceChange::DevtoolsPage,
        SurfaceChange::ChromeUrlOverrides,
        SurfaceChange::SandboxPages,
        SurfaceChange::ContentSecurityPolicy,
    ] {
        assert_token(&value, value.token());
    }
    for value in [AuditCoverage::Complete, AuditCoverage::Partial] {
        assert_token(&value, value.token());
    }
    for value in [
        ProfileKind::Default,
        ProfileKind::Numbered,
        ProfileKind::Guest,
        ProfileKind::System,
        ProfileKind::Explicit,
    ] {
        assert_token(&value, value.token());
    }
    for value in [
        InstallClassSource::Preferences,
        InstallClassSource::Unavailable,
    ] {
        assert_token(&value, value.token());
    }
    for value in [
        BrowserStatus::Audited,
        BrowserStatus::UserDataNotFound,
        BrowserStatus::UserDataUnreadable,
        BrowserStatus::PlatformUnsupported,
        BrowserStatus::HomeUnresolved,
    ] {
        assert_token(&value, value.token());
    }
}

#[test]
fn the_report_carries_no_absolute_host_path() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV3_BROAD_MANIFEST,
        &[("sw.js", "// synthetic")],
    );
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);
    let json = serde_json::to_string(&audit_report(&profile)).expect("serialize");
    let absolute = root.path().to_string_lossy().to_string();
    assert!(!json.contains(&absolute), "{json}");
    for prefix in ["/Users/", "/home/", "/var/folders/", "C:\\\\Users"] {
        assert!(
            !json.contains(prefix),
            "{prefix} reached the report: {json}"
        );
    }
}

// ---------------------------------------------------------------------------
// Inventory facts
// ---------------------------------------------------------------------------

#[test]
fn wallet_shaped_ids_are_labelled_and_never_trusted() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    for id in [WALLET_ID, WALLET_ID_TWO] {
        write_extension(
            &profile,
            id,
            "10.0.0_0",
            MV3_WALLET_MANIFEST,
            &[
                ("background.js", "// synthetic"),
                ("inpage.js", "// synthetic"),
            ],
        );
    }
    write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV3_WALLET_MANIFEST,
        &[
            ("background.js", "// synthetic"),
            ("inpage.js", "// synthetic"),
        ],
    );
    write_preferences(
        &profile,
        &[
            (WALLET_ID, 1, true),
            (WALLET_ID_TWO, 1, true),
            (PLAIN_ID, 1, true),
        ],
    );

    let record = audit_profile(&profile);
    let extensions = &record.profiles[0].extensions;
    assert_eq!(extensions.len(), 3);
    for extension in extensions {
        assert_eq!(
            extension.wallet_fixture_match,
            extension.id == WALLET_ID || extension.id == WALLET_ID_TWO
        );
    }
    // The label changes nothing: identical trees hash identically and carry the
    // same risk level whether or not the id is a wallet fixture.
    let wallet = extensions.iter().find(|e| e.id == WALLET_ID).unwrap();
    let plain = extensions.iter().find(|e| e.id == PLAIN_ID).unwrap();
    assert_eq!(wallet.tree.digest, plain.tree.digest);
    assert_eq!(wallet.risk, plain.risk);
    assert_eq!(wallet.surface_hash, plain.surface_hash);
    assert!(is_wallet_fixture_id(WALLET_ID));
    assert!(!is_wallet_fixture_id(PLAIN_ID));
}

#[test]
fn mv2_and_mv3_both_parse_and_report_their_manifest_version_verbatim() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.2.3_0",
        MV2_MANIFEST,
        &[("bg.js", "//")],
    );
    write_extension(
        &profile,
        WALLET_ID,
        "10.0.0_0",
        MV3_WALLET_MANIFEST,
        &[("background.js", "//"), ("inpage.js", "//")],
    );
    write_preferences(&profile, &[(PLAIN_ID, 1, true), (WALLET_ID, 1, true)]);

    let record = audit_profile(&profile);
    let legacy = &record.profiles[0].extensions[0];
    assert_eq!(legacy.id, PLAIN_ID);
    assert_eq!(legacy.manifest_version, 2);
    assert_eq!(legacy.surfaces.background, BackgroundKind::Scripts);
    // MV2 mixes host patterns into `permissions`; they are split out so an
    // MV2-to-MV3 migration is not read as a permission reduction.
    assert_eq!(legacy.permissions, vec!["storage".to_string()]);
    assert_eq!(
        legacy.host_permissions,
        vec!["https://legacy.example.invalid/*".to_string()]
    );

    let modern = &record.profiles[0].extensions[1];
    assert_eq!(modern.manifest_version, 3);
    assert_eq!(modern.surfaces.background, BackgroundKind::ServiceWorker);
    assert_eq!(modern.surfaces.content_script_count, 1);
    assert!(modern.surfaces.externally_connectable);
}

#[test]
fn install_classes_are_classified_and_none_of_them_raises_risk() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    let ids = [
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            1u64,
            true,
            InstallClass::WebStore,
        ),
        (
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            2,
            false,
            InstallClass::Sideloaded,
        ),
        (
            "cccccccccccccccccccccccccccccccc",
            9,
            false,
            InstallClass::EnterprisePolicy,
        ),
        (
            "dddddddddddddddddddddddddddddddd",
            4,
            false,
            InstallClass::DeveloperUnpacked,
        ),
        (
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            5,
            false,
            InstallClass::BrowserComponent,
        ),
    ];
    let mut preferences = Vec::new();
    for (id, location, from_webstore, _) in ids {
        write_extension(&profile, id, "1.0.0_0", MV2_MANIFEST, &[("bg.js", "//")]);
        preferences.push((id, location, from_webstore));
    }
    write_preferences(&profile, &preferences);

    let record = audit_profile(&profile);
    assert_eq!(
        record.profiles[0].install_class_source,
        InstallClassSource::Preferences
    );
    for (id, _, _, expected) in ids {
        let extension = record.profiles[0]
            .extensions
            .iter()
            .find(|extension| extension.id == id)
            .expect("classified extension");
        assert_eq!(extension.install_class, expected, "{id}");
        // Classified, not condemned: no install class alone raises risk.
        assert_eq!(extension.risk.level, RiskLevel::Ordinary, "{id}");
    }
    assert_eq!(record.coverage, AuditCoverage::Complete);
}

#[test]
fn an_unreadable_preferences_file_degrades_install_class_to_unknown_and_partial() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV2_MANIFEST,
        &[("bg.js", "//")],
    );
    // No Preferences file at all.

    let record = audit_profile(&profile);
    assert_eq!(
        record.profiles[0].install_class_source,
        InstallClassSource::Unavailable
    );
    assert_eq!(only_extension(&record).install_class, InstallClass::Unknown);
    assert_eq!(record.coverage, AuditCoverage::Partial);
}

#[test]
fn provenance_is_read_from_the_presence_of_the_browsers_own_records() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "1.0.0_0",
        MV2_MANIFEST,
        &[
            ("bg.js", "//"),
            ("_metadata/computed_hashes.json", "{}"),
            ("_metadata/verified_contents.json", "{}"),
        ],
    );
    write_extension(
        &profile,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "1.0.0_0",
        MV2_MANIFEST,
        &[("bg.js", "//"), ("_metadata/computed_hashes.json", "{}")],
    );
    write_extension(
        &profile,
        "cccccccccccccccccccccccccccccccc",
        "1.0.0_0",
        MV2_MANIFEST,
        &[("bg.js", "//")],
    );
    write_preferences(
        &profile,
        &[
            ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, true),
            ("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1, true),
            ("cccccccccccccccccccccccccccccccc", 4, false),
        ],
    );

    let record = audit_profile(&profile);
    let classes: Vec<ProvenanceClass> = record.profiles[0]
        .extensions
        .iter()
        .map(|extension| extension.provenance)
        .collect();
    assert_eq!(
        classes,
        vec![
            ProvenanceClass::StoreSigned,
            ProvenanceClass::ComputedHashesOnly,
            ProvenanceClass::Unrecorded,
        ]
    );
}

#[test]
fn several_version_directories_are_recorded_and_the_highest_is_audited() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.9.0_0",
        MV2_MANIFEST,
        &[("bg.js", "old")],
    );
    write_extension(
        &profile,
        PLAIN_ID,
        "1.10.0_0",
        MV2_MANIFEST,
        &[("bg.js", "new")],
    );
    write_extension(
        &profile,
        PLAIN_ID,
        "1.10.0_1",
        MV2_MANIFEST,
        &[("bg.js", "newest")],
    );
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let record = audit_profile(&profile);
    let extension = only_extension(&record);
    assert_eq!(extension.version_directory, "1.10.0_1");
    assert_eq!(
        extension.version_directories,
        vec![
            "1.10.0_0".to_string(),
            "1.10.0_1".to_string(),
            "1.9.0_0".to_string()
        ]
    );
}

// ---------------------------------------------------------------------------
// Risk stays separate from drift
// ---------------------------------------------------------------------------

#[test]
fn broad_authority_is_permission_risk_and_never_integrity_drift() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        WALLET_ID,
        "2.0.0_0",
        MV3_BROAD_MANIFEST,
        &[("sw.js", "// synthetic")],
    );
    write_preferences(&profile, &[(WALLET_ID, 1, true)]);

    let report = audit_report(&profile);
    let extension = &report.browsers[0].profiles[0].extensions[0];
    assert_eq!(extension.risk.level, RiskLevel::Broad);
    for expected in [
        PermissionRiskReason::AllHosts,
        PermissionRiskReason::Debugger,
        PermissionRiskReason::NativeMessaging,
        PermissionRiskReason::WebRequestBlocking,
        PermissionRiskReason::Cookies,
    ] {
        assert!(extension.risk.reasons.contains(&expected), "{expected:?}");
    }

    // The same broad extension, recorded in a baseline and re-audited, is not
    // drift. Risk and drift are different questions.
    let baseline = BrowserBaseline::from_report(&report);
    let again = audit_report(&profile);
    assert!(
        compute_drift(&again, &baseline).is_empty(),
        "an unchanged broad extension must produce no drift"
    );
    assert_eq!(
        again.browsers[0].profiles[0].extensions[0].risk.level,
        RiskLevel::Broad,
        "and its risk must still be reported"
    );
}

// ---------------------------------------------------------------------------
// Digest and drift
// ---------------------------------------------------------------------------

#[test]
fn the_tree_digest_is_deterministic_and_sensitive_to_bytes_and_paths() {
    let root = temp();
    let first = make_profile(root.path(), "Default");
    write_extension(
        &first,
        PLAIN_ID,
        "1.0.0_0",
        MV2_MANIFEST,
        &[
            ("a.js", "one"),
            ("nested/b.js", "two"),
            ("nested/deep/c.js", "three"),
        ],
    );
    write_preferences(&first, &[(PLAIN_ID, 1, true)]);

    let one = audit_profile(&first);
    let two = audit_profile(&first);
    assert_eq!(
        only_extension(&one).tree.digest,
        only_extension(&two).tree.digest,
        "two walks of the same tree must agree"
    );
    assert!(only_extension(&one).tree.complete);
    assert_eq!(only_extension(&one).tree.file_count, 4);

    // A one-byte content change moves the digest.
    std::fs::write(
        first
            .join("Extensions")
            .join(PLAIN_ID)
            .join("1.0.0_0")
            .join("a.js"),
        "onE",
    )
    .expect("tamper");
    let tampered = audit_profile(&first);
    assert_ne!(
        only_extension(&one).tree.digest,
        only_extension(&tampered).tree.digest
    );

    // So does a rename that keeps every byte.
    let version = first.join("Extensions").join(PLAIN_ID).join("1.0.0_0");
    std::fs::write(version.join("a.js"), "one").expect("restore");
    std::fs::rename(version.join("a.js"), version.join("z.js")).expect("rename");
    let renamed = audit_profile(&first);
    assert_ne!(
        only_extension(&one).tree.digest,
        only_extension(&renamed).tree.digest
    );
}

#[test]
fn a_same_version_byte_change_is_its_own_drift_variant() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        WALLET_ID,
        "10.0.0_0",
        MV3_WALLET_MANIFEST,
        &[
            ("background.js", "// original"),
            ("inpage.js", "// original"),
        ],
    );
    write_preferences(&profile, &[(WALLET_ID, 1, true)]);
    let baseline = BrowserBaseline::from_report(&audit_report(&profile));

    // The version string does not move; one byte of a content script does.
    std::fs::write(
        profile
            .join("Extensions")
            .join(WALLET_ID)
            .join("10.0.0_0")
            .join("inpage.js"),
        "// original ",
    )
    .expect("tamper");

    let drifts = compute_drift(&audit_report(&profile), &baseline);
    assert_eq!(drifts.len(), 1, "{drifts:?}");
    match &drifts[0] {
        ExtensionDrift::SameVersionByteChange {
            subject,
            version,
            from_digest,
            to_digest,
        } => {
            assert_eq!(subject.extension_id, WALLET_ID);
            assert_eq!(version, "10.0.0");
            assert_ne!(from_digest, to_digest);
        }
        other => panic!("expected a same-version byte change, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn a_tree_that_could_not_be_fully_hashed_is_not_comparable_rather_than_clean_or_tampered() {
    use std::os::unix::fs::symlink;

    let root = temp();
    let profile = make_profile(root.path(), "Default");
    let version = write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV2_MANIFEST,
        &[("bg.js", "//"), ("extra.js", "//")],
    );
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);
    let baseline = BrowserBaseline::from_report(&audit_report(&profile));
    assert!(baseline.entries[0].tree_complete);
    assert!(compute_drift(&audit_report(&profile), &baseline).is_empty());

    // One planted symlink makes the walk incomplete without changing any byte
    // the previous walk covered. A naive comparison would call this clean.
    symlink(root.path().join("nowhere"), version.join("planted.js")).expect("plant symlink");

    let drifts = compute_drift(&audit_report(&profile), &baseline);
    assert_eq!(drifts.len(), 1, "{drifts:?}");
    match &drifts[0] {
        ExtensionDrift::IntegrityNotComparable {
            baseline_complete,
            current_complete,
            ..
        } => {
            assert!(*baseline_complete);
            assert!(!*current_complete);
        }
        other => panic!("expected an incomparable result, got {other:?}"),
    }
}

#[test]
fn a_version_move_does_not_also_report_a_byte_change() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.2.3_0",
        MV2_MANIFEST,
        &[("bg.js", "//")],
    );
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);
    let baseline = BrowserBaseline::from_report(&audit_report(&profile));

    let upgraded = MV2_MANIFEST.replace("\"1.2.3\"", "\"1.2.4\"");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.2.4_0",
        &upgraded,
        &[("bg.js", "// new")],
    );

    let drifts = compute_drift(&audit_report(&profile), &baseline);
    let tokens: Vec<&str> = drifts.iter().map(|drift| drift.token()).collect();
    assert!(
        !tokens.contains(&"same_version_byte_change"),
        "a genuine update must not also report a byte change: {drifts:?}"
    );
    assert!(
        !tokens.contains(&"version_directory_reused"),
        "a genuine update writes a NEW version directory, so nothing was reused: {drifts:?}"
    );
    assert!(tokens.contains(&"version_changed"), "{drifts:?}");
    // The new directory is reported as a set change: Chrome keeps the old one
    // alongside during an update, and the SET is what says which trees exist.
    assert!(
        tokens.contains(&"version_directory_set_change"),
        "{drifts:?}"
    );
    assert_eq!(tokens.len(), 2, "{drifts:?}");
}

#[test]
fn every_expansion_drift_fires_on_its_own_and_is_never_conflated() {
    let base = r#"{
  "manifest_version": 2,
  "name": "Synthetic",
  "version": "1.0.0",
  "permissions": ["storage"],
  "host_permissions": ["https://a.example.invalid/*"],
  "background": {"page": "bg.html"}
}"#;
    // Each case declares the EXACT token set it must produce. A manifest rewrite
    // always moves the tree bytes too, so `same_version_byte_change` is expected
    // alongside every one of them; anything beyond the declared set is a
    // conflation.
    let cases: &[(&[&str], &str, &str)] = &[
        (
            // Replacing one host with `<all_urls>` genuinely adds one scope and
            // drops another, and the two are reported separately rather than
            // collapsed into a single "hosts changed".
            &[
                "same_version_byte_change",
                "host_expansion",
                "host_reduction",
            ],
            r#""host_permissions": ["https://a.example.invalid/*"]"#,
            r#""host_permissions": ["<all_urls>"]"#,
        ),
        (
            &["same_version_byte_change", "permission_expansion"],
            r#""permissions": ["storage"]"#,
            r#""permissions": ["storage", "cookies"]"#,
        ),
        (
            &["same_version_byte_change", "execution_surface_change"],
            r#""background": {"page": "bg.html"}"#,
            r#""background": {"service_worker": "sw.js"}"#,
        ),
    ];

    for (expected, from, to) in cases {
        let root = temp();
        let profile = make_profile(root.path(), "Default");
        write_extension(&profile, PLAIN_ID, "1.0.0_0", base, &[("bg.js", "//")]);
        write_preferences(&profile, &[(PLAIN_ID, 1, true)]);
        let baseline = BrowserBaseline::from_report(&audit_report(&profile));

        let mutated = base.replace(from, to);
        assert_ne!(
            mutated, base,
            "the {expected:?} fixture must actually change"
        );
        std::fs::write(
            profile
                .join("Extensions")
                .join(PLAIN_ID)
                .join("1.0.0_0")
                .join("manifest.json"),
            &mutated,
        )
        .expect("rewrite manifest");

        let drifts = compute_drift(&audit_report(&profile), &baseline);
        let mut tokens: Vec<&str> = drifts.iter().map(|drift| drift.token()).collect();
        tokens.sort_unstable();
        let mut wanted: Vec<&str> = expected.to_vec();
        wanted.sort_unstable();
        assert_eq!(tokens, wanted, "{expected:?} was conflated or lost");
    }
}

#[test]
fn added_content_scripts_and_native_messaging_are_surface_changes() {
    let base = r#"{
  "manifest_version": 3,
  "name": "Synthetic",
  "version": "1.0.0",
  "permissions": ["storage"],
  "background": {"service_worker": "sw.js"}
}"#;
    let expanded = r#"{
  "manifest_version": 3,
  "name": "Synthetic",
  "version": "1.0.0",
  "permissions": ["storage", "nativeMessaging"],
  "background": {"service_worker": "sw.js"},
  "content_scripts": [{"matches": ["https://x.example.invalid/*"], "js": ["c.js"]}],
  "externally_connectable": {"matches": ["https://y.example.invalid/*"]}
}"#;
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(&profile, PLAIN_ID, "1.0.0_0", base, &[("sw.js", "//")]);
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);
    let baseline = BrowserBaseline::from_report(&audit_report(&profile));

    std::fs::write(
        profile
            .join("Extensions")
            .join(PLAIN_ID)
            .join("1.0.0_0")
            .join("manifest.json"),
        expanded,
    )
    .expect("rewrite manifest");

    let drifts = compute_drift(&audit_report(&profile), &baseline);
    let surface = drifts
        .iter()
        .find_map(|drift| match drift {
            ExtensionDrift::ExecutionSurfaceChange { changes, .. } => Some(changes.clone()),
            _ => None,
        })
        .expect("a surface change");
    assert!(surface.contains(&SurfaceChange::ContentScripts));
    assert!(surface.contains(&SurfaceChange::ContentScriptMatches));
    assert!(surface.contains(&SurfaceChange::NativeMessaging));
    assert!(surface.contains(&SurfaceChange::ExternallyConnectable));
    assert!(!surface.contains(&SurfaceChange::Background));
}

#[test]
fn provenance_and_install_class_changes_are_their_own_drift_variants() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV2_MANIFEST,
        &[("bg.js", "//"), ("_metadata/verified_contents.json", "{}")],
    );
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);
    let baseline = BrowserBaseline::from_report(&audit_report(&profile));

    std::fs::remove_file(
        profile
            .join("Extensions")
            .join(PLAIN_ID)
            .join("1.0.0_0")
            .join("_metadata/verified_contents.json"),
    )
    .expect("drop the store signature");
    write_preferences(&profile, &[(PLAIN_ID, 4, false)]);

    let drifts = compute_drift(&audit_report(&profile), &baseline);
    let tokens: Vec<&str> = drifts.iter().map(|drift| drift.token()).collect();
    assert!(tokens.contains(&"provenance_change"), "{tokens:?}");
    assert!(tokens.contains(&"install_class_change"), "{tokens:?}");
    assert!(tokens.contains(&"same_version_byte_change"), "{tokens:?}");
}

#[test]
fn new_and_removed_extensions_are_reported_from_the_baseline() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV2_MANIFEST,
        &[("bg.js", "//")],
    );
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);
    let baseline = BrowserBaseline::from_report(&audit_report(&profile));

    std::fs::remove_dir_all(profile.join("Extensions").join(PLAIN_ID)).expect("uninstall");
    write_extension(
        &profile,
        WALLET_ID,
        "10.0.0_0",
        MV3_WALLET_MANIFEST,
        &[("background.js", "//"), ("inpage.js", "//")],
    );
    write_preferences(&profile, &[(WALLET_ID, 1, true)]);

    let drifts = compute_drift(&audit_report(&profile), &baseline);
    let tokens: Vec<&str> = drifts.iter().map(|drift| drift.token()).collect();
    assert_eq!(tokens, vec!["removed", "new"], "removed sorts first");
}

// ---------------------------------------------------------------------------
// Baseline document
// ---------------------------------------------------------------------------

#[test]
fn a_baseline_round_trips_with_zero_drift_and_a_stable_inventory_hash() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV2_MANIFEST,
        &[("bg.js", "//")],
    );
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let first = BrowserBaseline::from_report(&audit_report(&profile));
    first.validate().expect("a fresh baseline validates");
    assert_eq!(first.receipt_id.len(), 64);
    assert!(first.content_hash_matches());

    let parsed = BrowserBaseline::parse(&first.to_json()).expect("round trip");
    assert_eq!(parsed, first);
    assert!(compute_drift(&audit_report(&profile), &parsed).is_empty());

    // `receipt_id` binds `created_at`, so a second run mints a different id but
    // the SAME inventory hash. That is what "idempotent" means for a baseline.
    let second = BrowserBaseline::from_report(&audit_report(&profile));
    assert_eq!(second.inventory_hash, first.inventory_hash);
}

#[test]
fn an_edited_baseline_fails_its_own_content_address() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV2_MANIFEST,
        &[("bg.js", "//")],
    );
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);
    let baseline = BrowserBaseline::from_report(&audit_report(&profile));

    let mut tampered = baseline.clone();
    tampered.entries[0].tree_digest = "0".repeat(64);
    assert!(!tampered.content_hash_matches());
    assert_eq!(tampered.validate(), Err(BaselineError::ContentHashMismatch));

    // The content address ignores the signature field, exactly as the capsule
    // receipt's does.
    let mut resigned = baseline.clone();
    let before = resigned.compute_content_hash();
    resigned.signature = Some("not-a-real-signature".to_string());
    assert_eq!(resigned.compute_content_hash(), before);
    assert!(resigned.content_hash_matches());
    assert!(!resigned.signature_verifies(&[7u8; 32]));
}

#[test]
fn the_signature_binds_the_content_address() {
    use ed25519_dalek::{Signer as _, SigningKey};

    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV2_MANIFEST,
        &[("bg.js", "//")],
    );
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);
    let mut baseline = BrowserBaseline::from_report(&audit_report(&profile));

    let key = SigningKey::from_bytes(&[11u8; 32]);
    use base64::Engine as _;
    baseline.signature = Some(
        base64::engine::general_purpose::STANDARD
            .encode(key.sign(baseline.signing_payload().as_bytes()).to_bytes()),
    );
    let public = key.verifying_key().to_bytes();
    assert!(baseline.signature_verifies(&public));

    let mut edited = baseline.clone();
    edited.receipt_id = "f".repeat(64);
    assert!(!edited.signature_verifies(&public));
}

#[test]
fn an_older_hashing_format_reports_one_upgrade_rather_than_phantom_drift() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    for id in [PLAIN_ID, WALLET_ID, WALLET_ID_TWO] {
        write_extension(&profile, id, "1.0.0_0", MV2_MANIFEST, &[("bg.js", "//")]);
    }
    write_preferences(
        &profile,
        &[
            (PLAIN_ID, 1, true),
            (WALLET_ID, 1, true),
            (WALLET_ID_TWO, 1, true),
        ],
    );

    let mut baseline = BrowserBaseline::from_report(&audit_report(&profile));
    baseline.format_version = BROWSER_BASELINE_FORMAT_VERSION - 1;
    // Re-stamp so the document is otherwise coherent; only the hashing rules
    // are stale.
    baseline.receipt_id = baseline.compute_content_hash();

    let drifts = compute_drift(&audit_report(&profile), &baseline);
    assert_eq!(drifts.len(), 1, "{drifts:?}");
    assert!(matches!(
        drifts[0],
        ExtensionDrift::SchemaUpgradeRequired {
            from_version: 0,
            to_version: 1
        }
    ));
}

// ---------------------------------------------------------------------------
// Safety: symlinks, collisions, caps, unreadable state, malformed input
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_symlinked_version_directory_is_refused_without_opening_its_target() {
    use std::os::unix::fs::symlink;

    let root = temp();
    let outside = root.path().join("outside");
    std::fs::create_dir_all(&outside).expect("create escape target");
    std::fs::write(outside.join("secret.js"), "POISON-ESCAPED-BYTES").expect("write escape target");

    let profile = make_profile(root.path(), "Default");
    let extension_dir = profile.join("Extensions").join(PLAIN_ID);
    std::fs::create_dir_all(&extension_dir).expect("create extension dir");
    symlink(&outside, extension_dir.join("1.0.0_0")).expect("plant version symlink");
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let record = audit_profile(&profile);
    assert_eq!(record.coverage, AuditCoverage::Partial);
    let rejected = all_rejections(&record);
    assert!(
        rejected
            .iter()
            .any(|entry| entry.reason == RejectionReason::Symlink),
        "{rejected:?}"
    );
    let json = serde_json::to_string(&record).expect("serialize");
    assert!(!json.contains("POISON-ESCAPED-BYTES"));
    // The refusal is recorded ON the extension, so it travels into the baseline
    // and a later verify run can see it. Recorded one level up it degraded only
    // the profile, and the extension still claimed `coverage: complete`.
    let extension = only_extension(&record);
    assert!(!extension.enumeration_complete);
    assert_eq!(extension.coverage, AuditCoverage::Partial);
}

#[cfg(unix)]
#[test]
fn a_symlinked_file_inside_the_tree_is_refused_and_never_folded_into_the_digest() {
    use std::os::unix::fs::symlink;

    let root = temp();
    let outside = root.path().join("outside.js");
    std::fs::write(&outside, "POISON-ESCAPED-BYTES").expect("write escape target");

    let profile = make_profile(root.path(), "Default");
    let version = write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV2_MANIFEST,
        &[("bg.js", "//")],
    );
    symlink(&outside, version.join("linked.js")).expect("plant file symlink");
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let record = audit_profile(&profile);
    let extension = only_extension(&record);
    assert!(
        !extension.tree.complete,
        "a skipped file makes the digest partial"
    );
    assert_eq!(extension.tree.file_count, 2);
    assert!(extension
        .rejected
        .iter()
        .any(|entry| entry.reason == RejectionReason::Symlink));
    assert_eq!(extension.coverage, AuditCoverage::Partial);
    let json = serde_json::to_string(&record).expect("serialize");
    assert!(!json.contains("POISON-ESCAPED-BYTES"));
}

#[test]
fn the_collision_fold_is_nfkc_plus_lowercase() {
    // Case and NFKC compatibility folding, both of which a filesystem may apply
    // silently while a byte comparison would not.
    assert_eq!(fold_key("Manifest.JSON"), fold_key("manifest.json"));
    assert_eq!(fold_key("\u{ff41}bc"), fold_key("abc"));
    assert_eq!(fold_key("\u{fb01}le.js"), fold_key("file.js"));
    assert_ne!(fold_key("a.js"), fold_key("b.js"));

    let collisions = colliding_names(&[
        "one.js".to_string(),
        "One.js".to_string(),
        "two.js".to_string(),
    ]);
    assert_eq!(collisions.len(), 1);
    assert!(collisions.contains("one.js"));
}

#[test]
fn sibling_version_directories_that_fold_together_are_refused_on_both_sides() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    // Two version directories whose NFKC + lowercase fold keys collide: the
    // second uses a fullwidth digit zero, which NFKC-normalizes to ASCII `0`.
    // Extension IDS cannot collide (they are validated as 32 letters a-p, so two
    // distinct valid ids never fold together); version directory names are
    // unconstrained, which is where the rule has to hold.
    for version in ["1.0.0_0", "1.0.0_\u{ff10}"] {
        let dir = profile.join("Extensions").join(PLAIN_ID).join(version);
        std::fs::create_dir_all(&dir).expect("create colliding version directory");
        std::fs::write(dir.join("manifest.json"), MV2_MANIFEST).expect("write manifest");
    }
    // A normalizing filesystem may have merged the two names already; the
    // collision rule only has something to say when both survived.
    let siblings = std::fs::read_dir(profile.join("Extensions").join(PLAIN_ID))
        .expect("list")
        .count();
    if siblings < 2 {
        return;
    }
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let record = audit_profile(&profile);
    let collisions = all_rejections(&record)
        .iter()
        .filter(|entry| entry.reason == RejectionReason::NameCollision)
        .count();
    assert_eq!(
        collisions, 2,
        "both siblings must be refused, never last-wins"
    );
    // The id is still REPORTED, as unauditable: an extension that vanishes from
    // the inventory produces no drift entry, so dropping it is how a refused
    // sibling became invisible to a `--baseline` run.
    let extension = only_extension(&record);
    assert_eq!(extension.id, PLAIN_ID);
    assert_eq!(extension.coverage, AuditCoverage::Partial);
    assert!(!extension.enumeration_complete);
    assert_eq!(record.coverage, AuditCoverage::Partial);
}

#[test]
fn colliding_file_names_inside_a_tree_refuse_both_and_never_hash_one() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    let version = write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV2_MANIFEST,
        &[("bg.js", "//")],
    );
    std::fs::write(version.join("payload.js"), "// benign").expect("write");
    std::fs::write(version.join("payload\u{ff0e}js"), "// hostile").expect("write");
    if std::fs::read_dir(&version).expect("list").count() < 4 {
        return;
    }
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let record = audit_profile(&profile);
    let extension = only_extension(&record);
    assert!(!extension.tree.complete);
    assert_eq!(
        extension
            .rejected
            .iter()
            .filter(|entry| entry.reason == RejectionReason::NameCollision)
            .count(),
        2
    );
    assert_eq!(
        extension.tree.file_count, 2,
        "neither colliding file is hashed"
    );
}

#[test]
fn a_sibling_that_is_not_an_extension_id_is_a_typed_rejection() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    std::fs::create_dir_all(profile.join("Extensions").join("Temp")).expect("create Temp");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV2_MANIFEST,
        &[("bg.js", "//")],
    );
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let record = audit_profile(&profile);
    assert!(record.profiles[0]
        .rejected
        .iter()
        .any(|entry| entry.reason == RejectionReason::NotAnExtensionId
            && entry.path == "Extensions/Temp"));
    assert_eq!(record.profiles[0].extensions.len(), 1);
    assert_eq!(record.coverage, AuditCoverage::Partial);
}

#[test]
fn a_file_count_cap_produces_a_gap_and_never_a_complete_digest() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    let files: Vec<(String, String)> = (0..10)
        .map(|index| (format!("chunk{index}.js"), format!("// {index}")))
        .collect();
    let borrowed: Vec<(&str, &str)> = files
        .iter()
        .map(|(name, body)| (name.as_str(), body.as_str()))
        .collect();
    write_extension(&profile, PLAIN_ID, "1.0.0_0", MV2_MANIFEST, &borrowed);
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let report = audit(&AuditRequest {
        families: vec![BrowserFamily::Chrome],
        explicit_profile: Some(profile.to_path_buf()),
        budget: AuditBudget {
            max_files_per_extension: 3,
            ..AuditBudget::default()
        },
    });
    let extension = &report.browsers[0].profiles[0].extensions[0];
    assert!(!extension.tree.complete);
    assert_eq!(extension.tree.file_count, 3);
    assert!(extension
        .gaps
        .iter()
        .any(|gap| gap.kind == CoverageGapKind::EntryCountCapped));
    assert!(extension
        .rejected
        .iter()
        .any(|entry| entry.reason == RejectionReason::BudgetExhausted));
    assert_eq!(report.coverage, AuditCoverage::Partial);
}

#[test]
fn the_run_wide_budget_bounds_a_multi_browser_walk() {
    let root = temp();
    let user_data = root.path().join("User Data");
    std::fs::create_dir_all(&user_data).expect("create user data");
    for name in ["Default", "Profile 1"] {
        let profile = make_profile(&user_data, name);
        write_extension(
            &profile,
            PLAIN_ID,
            "1.0.0_0",
            MV2_MANIFEST,
            &[("a.js", "//"), ("b.js", "//"), ("c.js", "//")],
        );
        write_preferences(&profile, &[(PLAIN_ID, 1, true)]);
    }

    let budget = AuditBudget {
        max_total_files: 4,
        ..AuditBudget::default()
    };
    let mut progress = AuditProgress::new();
    let first = audit_user_data_dir(BrowserFamily::Chrome, &user_data, &budget, &mut progress);
    // The run-wide ceiling is shared, so the SECOND browser inherits an already
    // spent budget rather than getting a fresh one.
    let second = audit_user_data_dir(BrowserFamily::Brave, &user_data, &budget, &mut progress);
    assert!(progress.files_used() >= 4);
    assert_eq!(first.coverage, AuditCoverage::Partial);
    assert_eq!(second.coverage, AuditCoverage::Partial);
    assert!(second.profiles.iter().all(|profile| profile
        .extensions
        .iter()
        .all(|extension| !extension.tree.complete)));
}

#[test]
fn an_oversize_file_becomes_a_coverage_gap_rather_than_an_unbounded_read() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV2_MANIFEST,
        &[("big.js", &"x".repeat(4096))],
    );
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let report = audit(&AuditRequest {
        families: vec![BrowserFamily::Chrome],
        explicit_profile: Some(profile.to_path_buf()),
        budget: AuditBudget {
            max_file_bytes: 64,
            ..AuditBudget::default()
        },
    });
    let extension = &report.browsers[0].profiles[0].extensions[0];
    assert!(!extension.tree.complete);
    assert!(extension
        .gaps
        .iter()
        .any(|gap| gap.kind == CoverageGapKind::Oversized));
    assert!(extension
        .rejected
        .iter()
        .any(|entry| matches!(entry.reason, RejectionReason::Oversize { .. })));
}

#[cfg(unix)]
#[test]
fn an_unreadable_subdirectory_is_partial_and_not_a_hard_error() {
    use std::os::unix::fs::PermissionsExt as _;

    // SAFETY: geteuid always succeeds and does not mutate memory.
    if unsafe { libc::geteuid() } == 0 {
        // Root ignores the mode bits, so the refusal this test needs cannot be
        // staged.
        return;
    }

    let root = temp();
    let profile = make_profile(root.path(), "Default");
    let version = write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV2_MANIFEST,
        &[("bg.js", "//")],
    );
    let locked = version.join("locked");
    std::fs::create_dir_all(&locked).expect("create locked dir");
    std::fs::write(locked.join("hidden.js"), "//").expect("write hidden file");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let record = audit_profile(&profile);
    let extension = only_extension(&record);
    assert!(!extension.tree.complete);
    assert!(extension
        .gaps
        .iter()
        .any(|gap| gap.kind == CoverageGapKind::EnumerationFailed));
    assert_eq!(record.coverage, AuditCoverage::Partial);

    // Restore so the tempdir can be removed.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).expect("restore");
}

#[test]
fn malformed_manifests_are_typed_rejections_and_never_panic() {
    let cases: &[(&str, RejectionReason)] = &[
        ("not json at all", RejectionReason::MalformedManifest),
        ("[1, 2, 3]", RejectionReason::MalformedManifest),
        (
            r#"{"manifest_version": 3, "permissions": ["a"], "permissions": ["b"]}"#,
            RejectionReason::DuplicateJsonKey,
        ),
    ];
    for (body, expected) in cases {
        let root = temp();
        let profile = make_profile(root.path(), "Default");
        write_extension(&profile, PLAIN_ID, "1.0.0_0", body, &[("bg.js", "//")]);
        write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

        let record = audit_profile(&profile);
        // Reported as unauditable, never dropped: a manifest Chromium accepts
        // and this parser refuses must not make the extension disappear from the
        // inventory a baseline compares against.
        let extension = only_extension(&record);
        assert_eq!(extension.id, PLAIN_ID, "{body}");
        assert_eq!(extension.coverage, AuditCoverage::Partial, "{body}");
        assert!(!extension.enumeration_complete, "{body}");
        assert!(
            all_rejections(&record)
                .iter()
                .any(|entry| entry.reason == *expected),
            "{body}: {:?}",
            all_rejections(&record)
        );
        assert_eq!(record.coverage, AuditCoverage::Partial);
    }
}

#[test]
fn a_manifest_that_is_a_directory_is_refused() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    let version = profile.join("Extensions").join(PLAIN_ID).join("1.0.0_0");
    std::fs::create_dir_all(version.join("manifest.json")).expect("create manifest directory");
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let record = audit_profile(&profile);
    assert_eq!(only_extension(&record).coverage, AuditCoverage::Partial);
    // Unix opens the directory and the post-open fstat refuses it; Windows
    // refuses the open itself without FILE_FLAG_BACKUP_SEMANTICS. Either way it
    // is a typed rejection and never a parsed manifest.
    assert!(
        all_rejections(&record).iter().any(|entry| matches!(
            entry.reason,
            RejectionReason::NotRegularFile | RejectionReason::Unreadable { .. }
        )),
        "{:?}",
        all_rejections(&record)
    );
}

#[test]
fn an_oversize_manifest_is_refused_before_it_is_parsed() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    let filler = "x".repeat(MAX_MANIFEST_BYTES as usize + 16);
    let manifest = format!(r#"{{"manifest_version": 3, "name": "{filler}", "version": "1.0"}}"#);
    write_extension(&profile, PLAIN_ID, "1.0.0_0", &manifest, &[]);
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let record = audit_profile(&profile);
    assert_eq!(only_extension(&record).coverage, AuditCoverage::Partial);
    assert!(all_rejections(&record)
        .iter()
        .any(|entry| matches!(entry.reason, RejectionReason::Oversize { .. })));
}

#[test]
fn an_extension_directory_with_no_version_is_a_typed_rejection() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    std::fs::create_dir_all(profile.join("Extensions").join(PLAIN_ID)).expect("create empty");
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let record = audit_profile(&profile);
    assert!(all_rejections(&record)
        .iter()
        .any(|entry| entry.reason == RejectionReason::NoVersionDirectory));
    assert_eq!(only_extension(&record).coverage, AuditCoverage::Partial);
    assert_eq!(record.coverage, AuditCoverage::Partial);
}

#[test]
fn manifest_text_is_display_sanitized_before_it_reaches_a_durable_artifact() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    let hostile = "{\"manifest_version\": 3, \"name\": \"Sy\\u001b[31mnthetic\\u200b\", \
                   \"version\": \"1.0\"}";
    write_extension(&profile, PLAIN_ID, "1.0.0_0", hostile, &[]);
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let record = audit_profile(&profile);
    let name = &only_extension(&record).name;
    assert!(!name.contains('\u{1b}'), "{name:?}");
    assert!(!name.contains('\u{200b}'), "{name:?}");
    assert!(
        name.contains("Synthetic") || name.contains("Sy"),
        "{name:?}"
    );
}

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------

#[test]
fn version_directories_sort_numerically_not_lexically() {
    assert_eq!(
        select_version_directory(&[
            "1.9.0_0".to_string(),
            "1.10.0_0".to_string(),
            "1.10.0_1".to_string()
        ]),
        "1.10.0_1"
    );
    assert_eq!(
        select_version_directory(&["2.0.0_0".to_string(), "unparsed".to_string()]),
        "2.0.0_0"
    );
}

#[test]
fn extension_ids_are_exactly_thirty_two_letters_a_to_p() {
    assert!(is_extension_id(PLAIN_ID));
    assert!(!is_extension_id("abc"));
    assert!(!is_extension_id(&"z".repeat(32)));
    assert!(!is_extension_id(&"a".repeat(33)));
}

#[test]
fn install_ordinals_map_to_classes_and_an_unknown_ordinal_stays_unknown() {
    assert_eq!(
        classify_install(Some(1), true, false),
        InstallClass::WebStore
    );
    assert_eq!(
        classify_install(Some(1), false, true),
        InstallClass::BrowserComponent
    );
    assert_eq!(
        classify_install(Some(1), false, false),
        InstallClass::Sideloaded
    );
    assert_eq!(
        classify_install(Some(3), false, false),
        InstallClass::Sideloaded
    );
    assert_eq!(
        classify_install(Some(7), false, false),
        InstallClass::EnterprisePolicy
    );
    assert_eq!(
        classify_install(Some(8), false, false),
        InstallClass::DeveloperUnpacked
    );
    assert_eq!(
        classify_install(Some(99), false, false),
        InstallClass::Unknown
    );
    assert_eq!(classify_install(None, true, false), InstallClass::Unknown);
}

#[test]
fn host_patterns_are_split_out_of_a_mixed_permission_list() {
    let (api, hosts) = split_host_patterns(vec![
        "storage".to_string(),
        "<all_urls>".to_string(),
        "https://x.example.invalid/*".to_string(),
        "file:///*".to_string(),
        "tabs".to_string(),
    ]);
    assert_eq!(api, vec!["storage".to_string(), "tabs".to_string()]);
    assert_eq!(hosts.len(), 3);
    assert!(is_all_hosts("<all_urls>"));
    assert!(is_all_hosts("*://*/*"));
    assert!(!is_all_hosts("https://x.example.invalid/*"));
}

// ---------------------------------------------------------------------------
// Regressions: the read set, the walk, and what drift can see
//
// Each test below reproduces one way an earlier build reported `clean`,
// `complete`, or `no drift` over a profile it had not actually covered.
// ---------------------------------------------------------------------------

/// The `Extensions` directory was the one level of the walk that was never
/// lstat'd, so a symlink there was followed onto a tree outside the profile and
/// the result was reported as a fully covered clean audit.
#[cfg(unix)]
#[test]
fn a_symlinked_extensions_directory_is_refused_and_its_tree_is_never_hashed() {
    use std::os::unix::fs::symlink;

    let root = temp();
    let stash = root.path().join("stash");
    let planted = stash.join(PLAIN_ID).join("3.0_0");
    std::fs::create_dir_all(&planted).expect("create planted tree");
    std::fs::write(
        planted.join("manifest.json"),
        r#"{"manifest_version": 3, "name": "POISON-OUTSIDE-NAME", "version": "3.0"}"#,
    )
    .expect("write planted manifest");
    std::fs::write(planted.join("blob.bin"), "POISON-OUTSIDE-BYTES").expect("write planted blob");

    let profile = root.path().join("Default");
    std::fs::create_dir_all(&profile).expect("create profile");
    symlink(&stash, profile.join("Extensions")).expect("plant Extensions symlink");
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let record = audit_profile(&profile);
    assert!(
        record.profiles[0].extensions.is_empty(),
        "nothing outside the profile may be audited: {:?}",
        record.profiles[0].extensions
    );
    assert_eq!(record.coverage, AuditCoverage::Partial);
    assert!(
        record.profiles[0]
            .rejected
            .iter()
            .any(|entry| entry.path == "Extensions" && entry.reason == RejectionReason::Symlink),
        "{:?}",
        record.profiles[0].rejected
    );
    let json = serde_json::to_string(&record).expect("serialize");
    assert!(!json.contains("POISON-OUTSIDE-NAME"), "{json}");
    assert!(!json.contains("POISON-OUTSIDE-BYTES"), "{json}");
}

/// The containment backstop used to be anchored on `Extensions/<id>`, which is
/// itself derived from the same walk, so an escape was compared against itself
/// and could never be detected. It is anchored on the PROFILE now, which is the
/// root the operator named and what `RejectionReason::OutsideProfile` has always
/// documented.
///
/// Driven through `audit_extension` directly, because the enumerators above it
/// refuse a symlinked component first: this asserts the BACKSTOP still holds
/// when a component is swapped after those checks, which is the only job it has.
#[cfg(unix)]
#[test]
fn a_version_directory_outside_the_profile_is_refused_by_the_profile_anchor() {
    use std::os::unix::fs::symlink;

    let root = temp();
    let stash = root.path().join("stash");
    std::fs::create_dir_all(stash.join(PLAIN_ID).join("3.0_0")).expect("create outside tree");
    std::fs::write(
        stash.join(PLAIN_ID).join("3.0_0").join("manifest.json"),
        r#"{"manifest_version": 3, "name": "POISON-ANCHOR-NAME", "version": "3.0"}"#,
    )
    .expect("write outside manifest");

    let profile = root.path().join("Default");
    std::fs::create_dir_all(&profile).expect("create profile");
    let extensions_root = profile.join("Extensions");
    symlink(&stash, &extensions_root).expect("plant Extensions symlink");

    let mut state = AuditProgress::new();
    let record = audit_extension(
        &profile,
        &extensions_root,
        PLAIN_ID,
        InstallClass::WebStore,
        InstallClassSource::Preferences,
        &AuditBudget::default(),
        &mut state,
    );
    assert_eq!(record.coverage, AuditCoverage::Partial);
    assert!(
        record
            .rejected
            .iter()
            .any(|entry| entry.reason == RejectionReason::OutsideProfile),
        "{:?}",
        record.rejected
    );
    let json = serde_json::to_string(&record).expect("serialize");
    assert!(!json.contains("POISON-ANCHOR-NAME"), "{json}");
}

/// The read gate documented two independent guarantees and had one: the shared
/// catalogue calls a browser storage root sensitive only when a hardcoded wallet
/// extension id is ALSO in the path, so a plain cookie jar was not covered.
#[test]
fn the_read_gate_refuses_every_never_read_profile_store_by_name() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    for store in NEVER_READ_PROFILE_STORES {
        let path = profile.join(store).join("payload.bin");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create store");
        std::fs::write(&path, "POISON-STORE").expect("write store");
        assert!(
            matches!(
                open_audit_file(&path, 1024),
                Err(RejectionReason::SensitivePath)
            ),
            "the read gate must refuse a path under {store}"
        );
        // And the store named directly, whether it is a file or a directory.
        assert!(
            matches!(
                open_audit_file(&profile.join(store), 1024),
                Err(RejectionReason::SensitivePath)
            ),
            "the read gate must refuse {store} itself"
        );
    }
}

/// A hard link is invisible to every symlink guard in this module: `lstat` calls
/// it a regular file and the catalogue gate sees only the name it was handed. A
/// link planted inside an extension tree pointed the digest at the profile's
/// cookie jar and read it in full.
#[cfg(unix)]
#[test]
fn a_hard_linked_file_inside_a_tree_is_refused_and_never_hashed() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    std::fs::write(profile.join("Cookies"), "POISON-COOKIE-JAR").expect("write cookie jar");
    let version = write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV2_MANIFEST,
        &[("bg.js", "//")],
    );
    std::fs::hard_link(profile.join("Cookies"), version.join("data.bin")).expect("plant hard link");
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let record = audit_profile(&profile);
    let extension = only_extension(&record);
    assert!(!extension.tree.complete);
    assert!(
        extension
            .rejected
            .iter()
            .any(|entry| entry.reason == RejectionReason::HardLink),
        "{:?}",
        extension.rejected
    );
    let json = serde_json::to_string(&record).expect("serialize");
    assert!(!json.contains("POISON-COOKIE-JAR"), "{json}");
}

/// Chrome unpacks an update into a NEW `<version>_<ordinal>` directory, so a
/// version string that moves inside a fixed directory is an in-place rewrite.
/// The digest comparison is skipped once the version moves, so without this the
/// one extra line `"version": "1.0.1"` defeated the byte-change detector.
#[test]
fn a_version_bump_inside_an_unchanged_version_directory_is_reported_with_its_digests() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.2.3_0",
        MV2_MANIFEST,
        &[("bg.js", "// clean")],
    );
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);
    let baseline = BrowserBaseline::from_report(&audit_report(&profile));

    let version = profile.join("Extensions").join(PLAIN_ID).join("1.2.3_0");
    std::fs::write(version.join("bg.js"), "// EVIL").expect("rewrite in place");
    std::fs::write(
        version.join("manifest.json"),
        MV2_MANIFEST.replace("\"1.2.3\"", "\"1.2.4\""),
    )
    .expect("relabel the manifest");

    let drifts = compute_drift(&audit_report(&profile), &baseline);
    let reused = drifts
        .iter()
        .find_map(|drift| match drift {
            ExtensionDrift::VersionDirectoryReused {
                version_directory,
                from_digest,
                to_digest,
                ..
            } => Some((
                version_directory.clone(),
                from_digest.clone(),
                to_digest.clone(),
            )),
            _ => None,
        })
        .unwrap_or_else(|| panic!("an in-place rewrite must be reported: {drifts:?}"));
    assert_eq!(reused.0, "1.2.3_0");
    assert_ne!(reused.1, reused.2, "the byte change must be carried");
}

/// Only the SELECTED version directory is hashed, so a complete second tree
/// dropped beside it (which `extensions.settings.<id>.path` can point the
/// browser at) changes no digest. The set of directories is what says it is
/// there.
#[test]
fn a_second_version_tree_beside_the_audited_one_is_drift() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.2.3_0",
        MV2_MANIFEST,
        &[("bg.js", "//")],
    );
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);
    let baseline = BrowserBaseline::from_report(&audit_report(&profile));

    // Lower version, so `select_version_directory` still audits the original.
    write_extension(
        &profile,
        PLAIN_ID,
        "0.0.1_0",
        &MV2_MANIFEST.replace("\"1.2.3\"", "\"0.0.1\""),
        &[("bg.js", "// payload")],
    );

    let drifts = compute_drift(&audit_report(&profile), &baseline);
    let added = drifts
        .iter()
        .find_map(|drift| match drift {
            ExtensionDrift::VersionDirectorySetChange { added, .. } => Some(added.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("a second tree must be drift: {drifts:?}"));
    assert_eq!(added, vec!["0.0.1_0".to_string()]);
}

/// Anything directly beneath `Extensions/<id>/` that is not a version directory
/// fell through a catch-all arm with no rejection and no coverage change, so an
/// extension holding an unaudited payload still reported `coverage: complete`.
#[test]
fn a_stray_entry_under_an_extension_directory_is_recorded_not_dropped() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV2_MANIFEST,
        &[("bg.js", "//")],
    );
    std::fs::write(
        profile.join("Extensions").join(PLAIN_ID).join("payload.js"),
        "// unaudited",
    )
    .expect("plant stray file");
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let record = audit_profile(&profile);
    let extension = only_extension(&record);
    assert!(!extension.enumeration_complete);
    assert_eq!(extension.coverage, AuditCoverage::Partial);
    assert!(
        extension.rejected.iter().any(|entry| {
            entry.path.ends_with("payload.js") && entry.reason == RejectionReason::UnexpectedEntry
        }),
        "{:?}",
        extension.rejected
    );
    assert_eq!(record.coverage, AuditCoverage::Partial);
}

/// Optional grants were captured into the baseline and then never compared, so
/// an update that added `optional_permissions: ["debugger"]` plus an optional
/// `<all_urls>` reported exactly one `version_changed` line and nothing else.
#[test]
fn optional_permission_and_host_expansions_are_their_own_drift_entries() {
    let base = r#"{
  "manifest_version": 3,
  "name": "Synthetic",
  "version": "1.0.0",
  "permissions": ["storage"],
  "host_permissions": ["https://one.example.invalid/*"]
}"#;
    let expanded = r#"{
  "manifest_version": 3,
  "name": "Synthetic",
  "version": "1.0.1",
  "permissions": ["storage"],
  "host_permissions": ["https://one.example.invalid/*"],
  "optional_permissions": ["cookies", "debugger", "nativeMessaging"],
  "optional_host_permissions": ["<all_urls>"]
}"#;
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(&profile, PLAIN_ID, "1.0.0_0", base, &[("bg.js", "//")]);
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);
    let baseline = BrowserBaseline::from_report(&audit_report(&profile));

    std::fs::remove_dir_all(profile.join("Extensions").join(PLAIN_ID).join("1.0.0_0"))
        .expect("remove old tree");
    write_extension(&profile, PLAIN_ID, "1.0.1_0", expanded, &[("bg.js", "//")]);

    let drifts = compute_drift(&audit_report(&profile), &baseline);
    let permissions = drifts
        .iter()
        .find_map(|drift| match drift {
            ExtensionDrift::OptionalPermissionExpansion { added, .. } => Some(added.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("optional permissions must be drift: {drifts:?}"));
    assert_eq!(
        permissions,
        vec![
            "cookies".to_string(),
            "debugger".to_string(),
            "nativeMessaging".to_string()
        ]
    );
    let hosts = drifts
        .iter()
        .find_map(|drift| match drift {
            ExtensionDrift::OptionalHostExpansion { added, .. } => Some(added.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("optional hosts must be drift: {drifts:?}"));
    assert_eq!(hosts, vec!["<all_urls>".to_string()]);
}

/// An MV2-to-MV3 move was captured into the baseline and never compared.
#[test]
fn a_manifest_version_move_is_its_own_drift_entry() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV2_MANIFEST,
        &[("bg.js", "//")],
    );
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);
    let baseline = BrowserBaseline::from_report(&audit_report(&profile));

    std::fs::write(
        profile
            .join("Extensions")
            .join(PLAIN_ID)
            .join("1.0.0_0")
            .join("manifest.json"),
        MV2_MANIFEST.replace("\"manifest_version\": 2", "\"manifest_version\": 3"),
    )
    .expect("rewrite manifest version");

    let drifts = compute_drift(&audit_report(&profile), &baseline);
    assert!(
        drifts.iter().any(|drift| matches!(
            drift,
            ExtensionDrift::ManifestVersionChanged { from: 2, to: 3, .. }
        )),
        "{drifts:?}"
    );
}

/// The same unbounded-record pressure exists ABOVE the walk: entries directly
/// beneath `Extensions/<id>/` are attacker-chosen and free to create, so one
/// rejection each is one report entry each.
#[test]
fn a_hostile_extension_directory_cannot_grow_the_report_without_bound() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV2_MANIFEST,
        &[("bg.js", "//")],
    );
    let extension_dir = profile.join("Extensions").join(PLAIN_ID);
    for index in 0..3_000 {
        std::fs::write(extension_dir.join(format!("stray{index}.js")), "").expect("write stray");
    }
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let record = audit_profile(&profile);
    let extension = only_extension(&record);
    assert!(!extension.enumeration_complete);
    assert!(
        extension.rejected.len() <= 2 * MAX_RECORDED_TREE_ENTRIES + 2,
        "recorded rejections must be bounded, got {}",
        extension.rejected.len()
    );
    assert!(
        extension
            .rejected
            .iter()
            .any(|entry| entry.reason == RejectionReason::RecordLimitReached),
        "the truncation must be stated, not silent: {:?}",
        extension.rejected
    );
}

/// Past a per-extension budget the walk used to keep enumerating and push one
/// rejection AND one gap per remaining file into unbounded vectors, so an
/// extension of cheap empty files drove the report's size linearly.
#[test]
fn an_exhausted_budget_stops_the_walk_and_bounds_what_is_recorded() {
    let root = temp();
    let profile = make_profile(root.path(), "Default");
    let version = write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV2_MANIFEST,
        &[("bg.js", "//")],
    );
    for index in 0..2_000 {
        std::fs::write(version.join(format!("f{index}.js")), "").expect("write filler");
    }
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let mut state = AuditProgress::new();
    let budget = AuditBudget {
        max_files_per_extension: 4,
        ..AuditBudget::default()
    };
    let record = audit_user_data_dir(BrowserFamily::Chrome, root.path(), &budget, &mut state);
    let extension = &record.profiles[0].extensions[0];
    assert!(!extension.tree.complete);
    assert_eq!(
        extension.tree.file_count, 4,
        "the walk must stop at the ceiling, not keep enumerating"
    );
    assert!(
        extension.rejected.len() <= MAX_RECORDED_TREE_ENTRIES + 1,
        "recorded rejections must be bounded, got {}",
        extension.rejected.len()
    );
    assert!(
        extension.gaps.len() <= MAX_RECORDED_TREE_ENTRIES + 1,
        "recorded gaps must be bounded, got {}",
        extension.gaps.len()
    );
    assert_eq!(
        extension
            .rejected
            .iter()
            .filter(|entry| entry.reason == RejectionReason::BudgetExhausted)
            .count(),
        1,
        "one statement that the budget stopped the walk, not one per skipped file: {:?}",
        extension.rejected
    );
}

/// The walk pushed directories onto a LIFO stack and re-opened them BY PATH on
/// pop, so a directory could sit there for a whole sibling subtree while an
/// attacker swapped it for a symlink and the walker enumerated, and hashed,
/// whatever the link pointed at. It holds the descriptor now, so the second
/// resolution the swap depends on never happens.
///
/// The mechanism is proved deterministically by
/// `util::dirfd::tests::a_swapped_component_cannot_be_reached_through_a_retained_descriptor`,
/// which fails outright against a path-based enumeration. This is the tree-level
/// half: a symlinked subdirectory is classified by an `fstatat` against the
/// RETAINED parent descriptor, so it is refused rather than descended into.
#[cfg(unix)]
#[test]
fn a_symlinked_subdirectory_inside_the_tree_is_refused_and_never_descended_into() {
    use std::os::unix::fs::symlink;

    let root = temp();
    let outside = root.path().join("OUTSIDE");
    std::fs::create_dir_all(&outside).expect("create escape target");
    std::fs::write(
        outside.join("PROOF_OUTSIDE_PROFILE.js"),
        "POISON-ESCAPED-DIR-BYTES",
    )
    .expect("write escape marker");

    let profile = make_profile(root.path(), "Default");
    let version = write_extension(
        &profile,
        PLAIN_ID,
        "1.0.0_0",
        MV2_MANIFEST,
        &[("bg.js", "//")],
    );
    symlink(&outside, version.join("vendor")).expect("plant directory symlink");
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let record = audit_profile(&profile);
    let extension = only_extension(&record);
    assert!(!extension.tree.complete);
    assert!(
        extension.rejected.iter().any(
            |entry| entry.path.ends_with("/vendor") && entry.reason == RejectionReason::Symlink
        ),
        "{:?}",
        extension.rejected
    );
    let json = serde_json::to_string(&record).expect("serialize");
    assert!(!json.contains("PROOF_OUTSIDE_PROFILE"), "{json}");
    assert!(!json.contains("POISON-ESCAPED-DIR-BYTES"), "{json}");
}
