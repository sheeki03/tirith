//! C16 integration tests for `tirith browser audit`.
//!
//! Kept in its own file rather than appended to `cli_integration.rs`: the audit
//! needs a profile tree assembled per test, and the receipt-privacy assertions
//! are the point of the slice, so they should be findable.
//!
//! Every extension tree is assembled from the synthetic fixtures under
//! `tests/fixtures/browser_extensions/`. No real extension's code is copied.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// A real MetaMask id, used only as a classification fixture for the wallet
/// LABEL. It is never a trust anchor.
const WALLET_ID: &str = "nkbihfbeogaeaoehlefnkodbefgpgknn";
/// A synthetic non-wallet id.
const PLAIN_ID: &str = "abcdefghijklmnopabcdefghijklmnop";
/// A second synthetic id.
const OTHER_ID: &str = "ponmlkjihgfedcbaponmlkjihgfedcba";

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/browser_extensions")
}

/// A hermetic HOME plus XDG/Windows config roots per command, so no test can
/// read or write the developer's real browser profiles or tirith state.
fn fresh_home() -> PathBuf {
    static SUITE_ROOT: OnceLock<tempfile::TempDir> = OnceLock::new();
    static NEXT: AtomicU64 = AtomicU64::new(0);

    let suite = SUITE_ROOT.get_or_init(|| {
        tempfile::Builder::new()
            .prefix("tirith-browser-audit-cli-")
            .tempdir()
            .expect("create hermetic root")
    });
    let root = suite
        .path()
        .join(format!("home-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
    for relative in [
        "config",
        "data",
        "state",
        "cache",
        "appdata",
        "localappdata",
    ] {
        fs::create_dir_all(root.join(relative)).expect("create hermetic directory");
    }
    root
}

fn tirith(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tirith"));
    cmd.env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("APPDATA", home.join("appdata"))
        .env("LOCALAPPDATA", home.join("localappdata"))
        .env("TIRITH_LOG", "0")
        .env_remove("TIRITH_POLICY_ROOT")
        .env_remove("SSH_AUTH_SOCK");
    cmd
}

/// Copy one synthetic fixture tree into `<profile>/Extensions/<id>/<version>/`.
fn install_fixture(profile: &Path, fixture: &str, id: &str, version: &str) -> PathBuf {
    let source = fixture_root().join(fixture);
    let destination = profile.join("Extensions").join(id).join(version);
    copy_tree(&source, &destination);
    destination
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create destination");
    for entry in fs::read_dir(source).expect("read fixture") {
        let entry = entry.expect("fixture entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("fixture file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy fixture file");
        }
    }
}

/// Write a `Preferences` document with the three install-class fields per id,
/// plus private data the audit must never carry out.
fn write_preferences(profile: &Path, entries: &[(&str, u64, bool)]) {
    let mut settings = serde_json::Map::new();
    for (id, location, from_webstore) in entries {
        settings.insert(
            (*id).to_string(),
            serde_json::json!({
                "location": location,
                "from_webstore": from_webstore,
                "was_installed_by_default": false,
                "path": "POISON-PREF-PATH",
                "manifest": {"name": "POISON-PREF-MANIFEST"},
            }),
        );
    }
    let document = serde_json::json!({
        "extensions": {"settings": settings},
        "account_info": [{"email": "POISON-ACCOUNT@example.invalid"}],
        "profile": {"name": "POISON-PROFILE-NAME"},
    });
    fs::write(
        profile.join("Preferences"),
        serde_json::to_string(&document).expect("serialize preferences"),
    )
    .expect("write preferences");
}

/// Seed the stores the audit must never open.
fn seed_private_stores(profile: &Path) {
    let seeds: &[(&str, &str)] = &[
        ("Cookies", "POISON-COOKIES"),
        ("History", "POISON-HISTORY"),
        ("Login Data", "POISON-LOGIN-DATA"),
        ("Local Storage/leveldb/000003.log", "POISON-LOCAL-STORAGE"),
        (
            "Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log",
            "POISON-WALLET-VAULT",
        ),
        (
            "IndexedDB/chrome-extension_nkbihfbeogaeaoehlefnkodbefgpgknn_0.indexeddb.leveldb/000003.log",
            "POISON-WALLET-INDEXEDDB",
        ),
    ];
    for (relative, contents) in seeds {
        let path = profile.join(relative);
        fs::create_dir_all(path.parent().expect("seed parent")).expect("create seed directory");
        fs::write(path, contents).expect("write seed");
    }
}

/// A profile holding a wallet-shaped extension, a legacy MV2 one, and a
/// broad-permission one, with private stores seeded alongside.
fn build_profile(home: &Path) -> PathBuf {
    let user_data = home.join("User Data");
    let profile = user_data.join("Default");
    fs::create_dir_all(profile.join("Extensions")).expect("create profile");
    install_fixture(&profile, "wallet-mv3", WALLET_ID, "10.0.0_0");
    install_fixture(&profile, "legacy-mv2", PLAIN_ID, "1.2.3_0");
    install_fixture(&profile, "broad-mv3", OTHER_ID, "2.0.0_0");
    write_preferences(
        &profile,
        &[
            (WALLET_ID, 1, true),
            (PLAIN_ID, 4, false),
            (OTHER_ID, 9, false),
        ],
    );
    seed_private_stores(&profile);
    profile
}

fn run_json(home: &Path, args: &[&str]) -> (i32, serde_json::Value, String) {
    let output = tirith(home).args(args).output().expect("run tirith");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("stdout is not JSON ({error}): {stdout}"));
    (output.status.code().unwrap_or(-1), value, stdout)
}

// ---------------------------------------------------------------------------

#[test]
fn a_clean_audit_emits_a_parseable_envelope_and_exits_zero() {
    let home = fresh_home();
    let profile = build_profile(&home);
    let (code, envelope, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--browser",
            "chrome",
            "--profile",
            &profile.to_string_lossy(),
            "--format",
            "json",
        ],
    );

    assert_eq!(code, 0, "{envelope}");
    assert_eq!(envelope["command"], "browser audit");
    assert_eq!(envelope["status"], "clean");
    assert_eq!(envelope["extension_count"], 3);
    assert_eq!(envelope["drift_count"], 0);
    assert!(envelope["baseline"].is_null());

    let extensions = envelope["report"]["browsers"][0]["profiles"][0]["extensions"]
        .as_array()
        .expect("extensions array");
    assert_eq!(extensions.len(), 3);

    // Profile identity is the directory name, never a display name or account.
    assert_eq!(
        envelope["report"]["browsers"][0]["profiles"][0]["profile_directory"],
        "Default"
    );
    assert_eq!(
        envelope["report"]["browsers"][0]["profiles"][0]["identity"]["root"]["family"],
        "chrome"
    );
    assert_eq!(
        envelope["report"]["browsers"][0]["profiles"][0]["identity"]["root"]["channel"],
        "explicit"
    );
    assert_eq!(
        envelope["report"]["browsers"][0]["profiles"][0]["identity"]["root"]["edition"],
        "explicit"
    );
    assert_eq!(
        extensions[0]["identity"]["profile"]["profile_directory"],
        "Default"
    );
    assert!(extensions
        .iter()
        .all(|extension| { extension["identity"]["extension_id"] == extension["id"] }));

    // Install classes come from the three allowed Preferences fields.
    let by_id = |id: &str| {
        extensions
            .iter()
            .find(|extension| extension["id"] == id)
            .unwrap_or_else(|| panic!("{id} missing"))
            .clone()
    };
    assert_eq!(by_id(WALLET_ID)["install_class"], "webstore");
    assert_eq!(by_id(PLAIN_ID)["install_class"], "developer_unpacked");
    assert_eq!(by_id(OTHER_ID)["install_class"], "enterprise_policy");

    // Risk is reported, and it is a different field from anything drift-shaped.
    assert_eq!(by_id(OTHER_ID)["risk"]["level"], "broad");
    assert_eq!(by_id(WALLET_ID)["wallet_fixture_match"], true);
    assert_eq!(by_id(PLAIN_ID)["wallet_fixture_match"], false);
    assert_eq!(by_id(PLAIN_ID)["manifest_version"], 2);
    assert_eq!(by_id(WALLET_ID)["manifest_version"], 3);
    assert_eq!(by_id(WALLET_ID)["tree"]["complete"], true);
}

#[test]
fn the_json_envelope_carries_no_browsing_data_and_no_host_path() {
    let home = fresh_home();
    let profile = build_profile(&home);
    let (_, _, stdout) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--profile",
            &profile.to_string_lossy(),
            "--format",
            "json",
        ],
    );

    for poison in [
        "POISON-COOKIES",
        "POISON-HISTORY",
        "POISON-LOGIN-DATA",
        "POISON-LOCAL-STORAGE",
        "POISON-WALLET-VAULT",
        "POISON-WALLET-INDEXEDDB",
        "POISON-PREF-PATH",
        "POISON-PREF-MANIFEST",
        "POISON-ACCOUNT",
        "POISON-PROFILE-NAME",
        "Cookies",
        "History",
        "Login Data",
        "Local Extension Settings",
        "Sync Extension Settings",
        "leveldb",
        "IndexedDB",
    ] {
        assert!(
            !stdout.contains(poison),
            "{poison} reached the JSON envelope"
        );
    }
    // The envelope names no absolute host path either: the operator supplied the
    // profile path, and it is not echoed back into the report.
    assert!(
        !stdout.contains(&home.to_string_lossy().to_string()),
        "{stdout}"
    );
}

#[test]
fn the_human_output_separates_risk_from_drift_and_states_coverage() {
    let home = fresh_home();
    let profile = build_profile(&home);
    let output = tirith(&home)
        .args(["browser", "audit", "--profile", &profile.to_string_lossy()])
        .output()
        .expect("run tirith");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("read-only"), "{stdout}");
    assert!(stdout.contains("coverage: complete"), "{stdout}");
    assert!(stdout.contains("risk broad"), "{stdout}");
    assert!(stdout.contains("[wallet-shaped id]"), "{stdout}");
    assert!(
        stdout.contains("no baseline supplied"),
        "an audit with nothing to compare against must say so: {stdout}"
    );
    for poison in ["POISON-COOKIES", "POISON-ACCOUNT", "POISON-PROFILE-NAME"] {
        assert!(!stdout.contains(poison), "{stdout}");
    }
}

#[test]
fn a_baseline_round_trip_reports_no_drift_then_reports_a_same_version_byte_change() {
    let home = fresh_home();
    let profile = build_profile(&home);
    let baseline = home.join("baseline.json");

    let (code, envelope, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--profile",
            &profile.to_string_lossy(),
            "--write-baseline",
            &baseline.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 0);
    let first_inventory = envelope["baseline_written"]["inventory_hash"]
        .as_str()
        .expect("inventory hash")
        .to_string();
    assert!(baseline.is_file());

    // Re-running against the freshly written baseline is clean.
    let (code, envelope, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--profile",
            &profile.to_string_lossy(),
            "--baseline",
            &baseline.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 0, "{envelope}");
    assert_eq!(envelope["status"], "clean");
    assert_eq!(envelope["drift_count"], 0);

    // One byte of a content script changes; the declared version does not.
    let script = profile
        .join("Extensions")
        .join(WALLET_ID)
        .join("10.0.0_0")
        .join("inpage.js");
    fs::write(&script, "// synthetic fixture: page script (tampered)\n").expect("tamper");

    let (code, envelope, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--profile",
            &profile.to_string_lossy(),
            "--baseline",
            &baseline.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 1, "drift must exit 1: {envelope}");
    assert_eq!(envelope["status"], "drift");
    assert_eq!(envelope["drift_count"], 1);
    assert_eq!(envelope["drift"][0]["kind"], "same_version_byte_change");
    assert_eq!(envelope["drift"][0]["subject"]["extension_id"], WALLET_ID);
    assert_eq!(
        envelope["drift"][0]["subject"]["profile_directory"],
        "Default"
    );

    // The baseline is unchanged by a verify run.
    let inventory_again = serde_json::from_str::<serde_json::Value>(
        &fs::read_to_string(&baseline).expect("read baseline"),
    )
    .expect("parse baseline")["inventory_hash"]
        .as_str()
        .expect("inventory hash")
        .to_string();
    assert_eq!(inventory_again, first_inventory);
}

#[test]
fn a_written_baseline_is_idempotent_and_carries_no_private_data() {
    let home = fresh_home();
    let profile = build_profile(&home);
    let first = home.join("first.json");
    let second = home.join("second.json");

    for path in [&first, &second] {
        let (code, _, _) = run_json(
            &home,
            &[
                "browser",
                "audit",
                "--profile",
                &profile.to_string_lossy(),
                "--write-baseline",
                &path.to_string_lossy(),
                "--format",
                "json",
            ],
        );
        assert_eq!(code, 0);
    }

    let read = |path: &Path| -> serde_json::Value {
        serde_json::from_str(&fs::read_to_string(path).expect("read baseline"))
            .expect("parse baseline")
    };
    let a = read(&first);
    let b = read(&second);
    assert_eq!(
        a["inventory_hash"], b["inventory_hash"],
        "two runs over an unchanged profile must agree on the inventory"
    );
    assert_eq!(a["entries"], b["entries"]);
    assert_eq!(a["receipt_type"], "browser_extension_baseline");
    assert_eq!(a["schema"], 2);
    assert_eq!(a["format_version"], 1);
    assert!(a["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .all(|entry| {
            entry["identity"]["extension_id"] == entry["extension_id"]
                && entry["identity"]["profile"]["root"]["family"] == entry["browser"]
        }));

    let text = fs::read_to_string(&first).expect("read baseline");
    for poison in [
        "POISON-COOKIES",
        "POISON-ACCOUNT",
        "POISON-PROFILE-NAME",
        "POISON-PREF-PATH",
        "Local Extension Settings",
        "leveldb",
    ] {
        assert!(
            !text.contains(poison),
            "{poison} reached the baseline receipt"
        );
    }
    assert!(
        !text.contains(&home.to_string_lossy().to_string()),
        "the baseline must not record the operator's home layout"
    );
    for prefix in ["/Users/", "/home/", "C:\\\\Users"] {
        assert!(
            !text.contains(prefix),
            "{prefix} reached the baseline receipt"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_symlinked_baseline_destination_is_replaced_and_never_written_through() {
    let home = fresh_home();
    let profile = build_profile(&home);
    let victim = home.join("victim.json");
    fs::write(&victim, "ORIGINAL-VICTIM-CONTENT").expect("write victim");
    let link = home.join("planted.json");
    std::os::unix::fs::symlink(&victim, &link).expect("plant symlink");

    let (code, _, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--profile",
            &profile.to_string_lossy(),
            "--write-baseline",
            &link.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 0);
    assert_eq!(
        fs::read_to_string(&victim).expect("read victim"),
        "ORIGINAL-VICTIM-CONTENT",
        "an atomic rename must replace the planted link, never follow it"
    );
    assert!(
        !fs::symlink_metadata(&link)
            .expect("stat published path")
            .file_type()
            .is_symlink(),
        "the published path must be the real baseline file"
    );
}

#[test]
fn a_corrupt_baseline_is_a_usage_error_and_never_a_clean_result() {
    let home = fresh_home();
    let profile = build_profile(&home);
    let baseline = home.join("baseline.json");
    let (code, _, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--profile",
            &profile.to_string_lossy(),
            "--write-baseline",
            &baseline.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 0);

    // Edit one recorded digest. The content address no longer matches, so the
    // baseline is refused rather than silently trusted.
    let mut document: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&baseline).expect("read")).expect("parse");
    document["entries"][0]["tree_digest"] = serde_json::Value::String("0".repeat(64));
    fs::write(&baseline, document.to_string()).expect("rewrite");

    let output = tirith(&home)
        .args([
            "browser",
            "audit",
            "--profile",
            &profile.to_string_lossy(),
            "--baseline",
            &baseline.to_string_lossy(),
        ])
        .output()
        .expect("run tirith");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(stderr.contains("receipt_id"), "{stderr}");

    // An absent baseline is likewise a usage error, not an implicit "clean".
    let missing = home.join("absent.json");
    let output = tirith(&home)
        .args([
            "browser",
            "audit",
            "--profile",
            &profile.to_string_lossy(),
            "--baseline",
            &missing.to_string_lossy(),
        ])
        .output()
        .expect("run tirith");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not exist"));
}

#[test]
fn an_unsupported_browser_is_refused_by_name_rather_than_reported_clean() {
    let home = fresh_home();
    for (value, expected) in [
        ("firefox", "Chromium-family"),
        ("safari", "chrome, chromium, brave, edge, or all"),
        ("", "chrome, chromium, brave, edge, or all"),
    ] {
        let output = tirith(&home)
            .args(["browser", "audit", "--browser", value])
            .output()
            .expect("run tirith");
        assert_eq!(output.status.code(), Some(2), "--browser {value}");
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        assert!(stderr.contains(expected), "--browser {value}: {stderr}");
    }
}

#[test]
fn profile_and_browser_all_cannot_be_combined() {
    let home = fresh_home();
    let profile = build_profile(&home);
    let output = tirith(&home)
        .args([
            "browser",
            "audit",
            "--browser",
            "all",
            "--profile",
            &profile.to_string_lossy(),
        ])
        .output()
        .expect("run tirith");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(stderr.contains("--browser all"), "{stderr}");
}

#[test]
fn browser_all_on_a_host_with_no_profiles_stays_explicit() {
    let home = fresh_home();
    let (code, envelope, _) = run_json(
        &home,
        &["browser", "audit", "--browser", "all", "--format", "json"],
    );
    assert_eq!(code, 0, "{envelope}");
    let browsers = envelope["report"]["browsers"]
        .as_array()
        .expect("browsers array");
    assert_eq!(
        browsers.len(),
        4,
        "all four Chromium-family browsers are reported"
    );
    let names: Vec<&str> = browsers
        .iter()
        .map(|browser| browser["browser"].as_str().expect("browser token"))
        .collect();
    assert_eq!(names, vec!["chrome", "chromium", "brave", "edge"]);
    for browser in browsers {
        assert!(
            browser["status"] == "user_data_not_found"
                || browser["status"] == "platform_unsupported"
                || browser["status"] == "home_unresolved",
            "an absent browser must be named, not silently clean: {browser}"
        );
        assert!(browser["profiles"].as_array().expect("profiles").is_empty());
    }
    assert_eq!(envelope["extension_count"], 0);
}

#[test]
fn discovery_continues_from_an_inaccessible_stable_root_into_beta() {
    let home = fresh_home();
    let (stable, beta) = if cfg!(target_os = "macos") {
        (
            home.join("Library/Application Support/Google/Chrome"),
            home.join("Library/Application Support/Google/Chrome Beta"),
        )
    } else if cfg!(target_os = "windows") {
        (
            home.join("AppData/Local/Google/Chrome/User Data"),
            home.join("AppData/Local/Google/Chrome Beta/User Data"),
        )
    } else {
        (
            home.join(".config/google-chrome"),
            home.join(".config/google-chrome-beta"),
        )
    };
    fs::create_dir_all(stable.parent().expect("stable parent")).expect("create stable parent");
    fs::write(&stable, "present but not a directory").expect("write inaccessible root");
    let profile = beta.join("Default");
    fs::create_dir_all(profile.join("Extensions")).expect("create beta profile");
    install_fixture(&profile, "legacy-mv2", PLAIN_ID, "1.2.3_0");
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let (code, envelope, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--browser",
            "chrome",
            "--format",
            "json",
        ],
    );
    assert_eq!(
        code, 0,
        "a partial audit without a baseline is informational"
    );
    assert_eq!(envelope["status"], "partial");
    let browser = &envelope["report"]["browsers"][0];
    assert_eq!(browser["status"], "audited");
    assert_eq!(browser["root_gaps"].as_array().expect("root gaps").len(), 1);
    assert_eq!(browser["root_gaps"][0]["root"]["channel"], "stable");
    assert_eq!(browser["profiles"].as_array().expect("profiles").len(), 1);
    assert_eq!(
        browser["profiles"][0]["identity"]["root"]["channel"],
        "beta"
    );
    assert!(browser["roots"]
        .as_array()
        .expect("roots")
        .iter()
        .any(|root| { root["identity"]["channel"] == "beta" && root["status"] == "audited" }));
}

#[test]
fn a_profile_argument_that_is_not_a_directory_is_a_usage_error() {
    let home = fresh_home();
    let file = home.join("not-a-directory");
    fs::write(&file, b"x").expect("write");
    let output = tirith(&home)
        .args(["browser", "audit", "--profile", &file.to_string_lossy()])
        .output()
        .expect("run tirith");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a directory"));
}

#[test]
fn a_profile_with_no_preferences_reports_partial_rather_than_clean() {
    let home = fresh_home();
    let profile = home.join("User Data").join("Profile 1");
    fs::create_dir_all(profile.join("Extensions")).expect("create profile");
    install_fixture(&profile, "legacy-mv2", PLAIN_ID, "1.2.3_0");

    let (code, envelope, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--profile",
            &profile.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 0, "a partial result is not a failure: {envelope}");
    assert_eq!(envelope["status"], "partial");
    assert_eq!(envelope["report"]["coverage"], "partial");
    let extension = &envelope["report"]["browsers"][0]["profiles"][0]["extensions"][0];
    assert_eq!(extension["install_class"], "unknown");
    assert_eq!(extension["coverage"], "partial");
    assert_eq!(
        envelope["report"]["browsers"][0]["profiles"][0]["install_class_source"],
        "unavailable"
    );
}

#[test]
fn provenance_is_reported_from_the_browsers_own_integrity_records() {
    let home = fresh_home();
    let profile = home.join("User Data").join("Default");
    fs::create_dir_all(profile.join("Extensions")).expect("create profile");
    install_fixture(&profile, "enterprise-mv3", PLAIN_ID, "3.1.0_0");
    install_fixture(&profile, "broad-mv3", OTHER_ID, "2.0.0_0");
    write_preferences(&profile, &[(PLAIN_ID, 9, false), (OTHER_ID, 1, true)]);

    let (code, envelope, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--browser",
            "edge",
            "--profile",
            &profile.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 0, "{envelope}");
    assert_eq!(envelope["report"]["browsers"][0]["browser"], "edge");
    let extensions = envelope["report"]["browsers"][0]["profiles"][0]["extensions"]
        .as_array()
        .expect("extensions");
    let managed = extensions
        .iter()
        .find(|extension| extension["id"] == PLAIN_ID)
        .expect("managed extension");
    assert_eq!(managed["provenance"], "store_signed");
    assert_eq!(managed["install_class"], "enterprise_policy");
    // An enterprise install is classified, not condemned.
    assert_eq!(managed["risk"]["level"], "ordinary");
    let broad = extensions
        .iter()
        .find(|extension| extension["id"] == OTHER_ID)
        .expect("broad extension");
    assert_eq!(broad["provenance"], "unrecorded");
    assert_eq!(broad["risk"]["level"], "broad");
}

#[test]
fn a_new_or_removed_extension_is_drift_and_exits_one() {
    let home = fresh_home();
    let profile = build_profile(&home);
    let baseline = home.join("baseline.json");
    let (code, _, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--profile",
            &profile.to_string_lossy(),
            "--write-baseline",
            &baseline.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 0);

    fs::remove_dir_all(profile.join("Extensions").join(OTHER_ID)).expect("uninstall");

    let (code, envelope, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--profile",
            &profile.to_string_lossy(),
            "--baseline",
            &baseline.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 1, "{envelope}");
    assert_eq!(envelope["drift_count"], 1);
    assert_eq!(envelope["drift"][0]["kind"], "removed");
    assert_eq!(envelope["drift"][0]["subject"]["extension_id"], OTHER_ID);
}

#[cfg(unix)]
#[test]
fn a_symlinked_extension_tree_is_refused_and_its_target_is_never_hashed() {
    let home = fresh_home();
    let outside = home.join("outside");
    fs::create_dir_all(&outside).expect("create escape target");
    fs::write(outside.join("secret.js"), "POISON-ESCAPED-BYTES").expect("write escape target");

    let profile = home.join("User Data").join("Default");
    fs::create_dir_all(profile.join("Extensions").join(PLAIN_ID)).expect("create profile");
    std::os::unix::fs::symlink(
        &outside,
        profile.join("Extensions").join(PLAIN_ID).join("1.0.0_0"),
    )
    .expect("plant symlink");
    write_preferences(&profile, &[(PLAIN_ID, 1, true)]);

    let (code, envelope, stdout) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--profile",
            &profile.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 0);
    assert_eq!(envelope["status"], "partial");
    assert!(!stdout.contains("POISON-ESCAPED-BYTES"), "{stdout}");
    // Recorded on the EXTENSION, which is what travels into a baseline. A
    // rejection kept only at profile level degraded the profile while the
    // extension record still said `coverage: complete`, so a later verify run
    // compared it and reported no drift.
    let extension = &envelope["report"]["browsers"][0]["profiles"][0]["extensions"][0];
    assert_eq!(extension["id"], PLAIN_ID);
    assert_eq!(extension["coverage"], "partial");
    assert_eq!(extension["enumeration_complete"], false);
    let rejected = extension["rejected"].as_array().expect("rejected array");
    assert!(
        rejected
            .iter()
            .any(|entry| entry["reason"]["kind"] == "symlink"),
        "{rejected:?}"
    );
}

#[cfg(unix)]
#[test]
fn a_partially_readable_tree_is_reported_not_comparable_and_exits_one() {
    let home = fresh_home();
    let profile = build_profile(&home);
    let baseline = home.join("baseline.json");
    let (code, _, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--profile",
            &profile.to_string_lossy(),
            "--write-baseline",
            &baseline.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 0);

    // One planted symlink makes the walk incomplete without changing any byte
    // the baseline walk covered. A naive comparison would call this clean.
    std::os::unix::fs::symlink(
        home.join("nowhere"),
        profile
            .join("Extensions")
            .join(WALLET_ID)
            .join("10.0.0_0")
            .join("planted.js"),
    )
    .expect("plant symlink");

    let (code, envelope, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--profile",
            &profile.to_string_lossy(),
            "--baseline",
            &baseline.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 1, "a verify that could not verify must not exit 0");
    assert_eq!(envelope["drift_count"], 1);
    assert_eq!(envelope["drift"][0]["kind"], "integrity_not_comparable");
    assert_eq!(envelope["drift"][0]["baseline_complete"], true);
    assert_eq!(envelope["drift"][0]["current_complete"], false);
    assert_eq!(envelope["drift"][0]["subject"]["extension_id"], WALLET_ID);
}

// ---------------------------------------------------------------------------
// Regressions: what a baseline proves, and what "no drift" is allowed to mean
// ---------------------------------------------------------------------------

/// Install an ed25519 audit signing key (and its public half) into the hermetic
/// config directory, so `--write-baseline` signs and `--baseline` can verify.
fn install_audit_key(home: &Path) -> ed25519_dalek::SigningKey {
    let config = home.join("config").join("tirith");
    fs::create_dir_all(&config).expect("create config dir");
    let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let key_path = config.join("audit-signing.key");
    fs::write(&key_path, signing.to_bytes()).expect("write signing key");
    let pub_path = config.join("audit-signing.pub");
    fs::write(&pub_path, signing.verifying_key().to_bytes()).expect("write verifying key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("chmod key");
        fs::set_permissions(&pub_path, fs::Permissions::from_mode(0o644)).expect("chmod pub");
    }
    signing
}

/// Recompute the two self-consistency hashes the way the document does, so a
/// forged baseline is internally valid. Both are sha256 over canonical JSON that
/// any local writer can reproduce, which is exactly why they cannot be the only
/// thing a baseline is trusted on.
fn reseal(document: &mut serde_json::Value) {
    fn canonical(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                let body: Vec<String> = keys
                    .iter()
                    .map(|key| {
                        format!(
                            "{}:{}",
                            serde_json::to_string(key).unwrap(),
                            canonical(&map[*key])
                        )
                    })
                    .collect();
                format!("{{{}}}", body.join(","))
            }
            serde_json::Value::Array(items) => {
                let body: Vec<String> = items.iter().map(canonical).collect();
                format!("[{}]", body.join(","))
            }
            other => serde_json::to_string(other).unwrap(),
        }
    }
    fn sha256_hex(text: &str) -> String {
        use sha2::{Digest as _, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(text.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    let entries = document["entries"].clone();
    document["inventory_hash"] = serde_json::Value::String(sha256_hex(&canonical(&entries)));
    let mut blanked = document.clone();
    blanked["receipt_id"] = serde_json::Value::String(String::new());
    blanked["signature"] = serde_json::Value::Null;
    document["receipt_id"] = serde_json::Value::String(sha256_hex(&canonical(&blanked)));
}

fn downgrade_baseline_to_v1(path: &Path) -> String {
    let mut document: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(path).expect("read current baseline"))
            .expect("parse current baseline");
    document["schema"] = serde_json::json!(1);
    document["format_version"] = serde_json::json!(1);
    for entry in document["entries"].as_array_mut().expect("entries") {
        entry
            .as_object_mut()
            .expect("baseline entry")
            .remove("identity");
    }
    document["signature"] = serde_json::Value::Null;
    reseal(&mut document);
    let legacy = serde_json::to_string_pretty(&document).expect("serialize v1 baseline");
    fs::write(path, &legacy).expect("write v1 baseline");
    legacy
}

#[test]
fn a_v1_baseline_reports_upgrade_and_is_replaced_atomically_on_request() {
    let home = fresh_home();
    let profile = build_profile(&home);
    let baseline = home.join("legacy-baseline.json");
    let (code, envelope, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--profile",
            &profile.to_string_lossy(),
            "--write-baseline",
            &baseline.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 0, "{envelope}");
    let legacy = downgrade_baseline_to_v1(&baseline);

    let (code, envelope, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--profile",
            &profile.to_string_lossy(),
            "--baseline",
            &baseline.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 1, "{envelope}");
    assert_eq!(envelope["baseline"]["schema"], 1);
    assert_eq!(envelope["baseline"]["trust"], "schema_upgrade_required");
    assert_eq!(envelope["drift_count"], 1);
    assert_eq!(envelope["drift"][0]["kind"], "schema_upgrade_required");
    assert_eq!(envelope["verify_complete"], false);
    assert_eq!(fs::read_to_string(&baseline).expect("read legacy"), legacy);

    let (code, envelope, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--profile",
            &profile.to_string_lossy(),
            "--baseline",
            &baseline.to_string_lossy(),
            "--write-baseline",
            &baseline.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(
        code, 1,
        "the old comparison still requires upgrade: {envelope}"
    );
    let replacement: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&baseline).expect("read replacement"))
            .expect("parse replacement");
    assert_eq!(replacement["schema"], 2);
    assert_eq!(replacement["format_version"], 1);
    assert!(replacement["entries"][0]["identity"].is_object());
}

#[cfg(unix)]
#[test]
fn a_failed_v1_replacement_leaves_the_old_file_byte_for_byte() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = fresh_home();
    let profile = build_profile(&home);
    let locked = home.join("locked-baseline-dir");
    fs::create_dir_all(&locked).expect("create locked directory");
    let baseline = locked.join("legacy.json");
    let (code, envelope, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--profile",
            &profile.to_string_lossy(),
            "--write-baseline",
            &baseline.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 0, "{envelope}");
    let legacy = downgrade_baseline_to_v1(&baseline);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).expect("lock directory");

    let output = tirith(&home)
        .args([
            "browser",
            "audit",
            "--profile",
            &profile.to_string_lossy(),
            "--baseline",
            &baseline.to_string_lossy(),
            "--write-baseline",
            &baseline.to_string_lossy(),
            "--format",
            "json",
        ])
        .output()
        .expect("run tirith");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).expect("unlock directory");

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read_to_string(&baseline).expect("read legacy"), legacy);
}

/// A baseline used to be accepted on nothing but its own unkeyed
/// self-consistency: both stored hashes are recomputable by whoever edits the
/// file, and the one field that is not (`signature`) had no caller outside
/// tests. A local attacker who can tamper with an extension tree can, by
/// definition, rewrite the baseline too.
#[cfg(unix)]
#[test]
fn a_forged_baseline_is_refused_rather_than_compared_against() {
    let home = fresh_home();
    install_audit_key(&home);
    let profile = build_profile(&home);
    let baseline = home.join("signed-baseline.json");
    let (code, envelope, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--browser",
            "chrome",
            "--profile",
            &profile.to_string_lossy(),
            "--write-baseline",
            &baseline.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 0, "{envelope}");
    assert_eq!(envelope["baseline_written"]["signed"], true, "{envelope}");

    // An honestly signed baseline verifies and compares.
    let (code, envelope, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--browser",
            "chrome",
            "--profile",
            &profile.to_string_lossy(),
            "--baseline",
            &baseline.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 0, "{envelope}");
    assert_eq!(envelope["baseline"]["trust"], "verified");
    assert_eq!(envelope["baseline"]["signed"], true);

    // Tamper with the tree, then rewrite the baseline to match, resealing both
    // hashes. Two forgeries: keep the now-stale signature, and strip it.
    let target = profile
        .join("Extensions")
        .join(PLAIN_ID)
        .join("1.2.3_0")
        .join("bg.js");
    let original = fs::read(&target).expect("read fixture file");
    fs::write(&target, b"// EVIL PAYLOAD\n").expect("tamper");
    let tampered_baseline = home.join("tampered.json");
    let (code, _, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--browser",
            "chrome",
            "--profile",
            &profile.to_string_lossy(),
            "--write-baseline",
            &tampered_baseline.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 0);
    let tampered: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&tampered_baseline).expect("read"))
            .expect("parse tampered");
    let mut forged: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&baseline).expect("read")).expect("parse signed");
    for entry in forged["entries"].as_array_mut().expect("entries") {
        let id = entry["extension_id"].clone();
        let replacement = tampered["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .find(|candidate| candidate["extension_id"] == id)
            .expect("matching entry");
        entry["tree_digest"] = replacement["tree_digest"].clone();
    }
    reseal(&mut forged);

    let with_stale_signature = home.join("forged-signed.json");
    fs::write(
        &with_stale_signature,
        serde_json::to_string_pretty(&forged).expect("serialize"),
    )
    .expect("write forgery");
    let (code, envelope, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--browser",
            "chrome",
            "--profile",
            &profile.to_string_lossy(),
            "--baseline",
            &with_stale_signature.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 2, "a forged baseline must not compare: {envelope}");
    assert_eq!(envelope["status"], "error");
    assert!(
        envelope["error"]
            .as_str()
            .expect("error text")
            .contains("does not verify"),
        "{envelope}"
    );

    let mut stripped = forged.clone();
    stripped["signature"] = serde_json::Value::Null;
    reseal(&mut stripped);
    let unsigned = home.join("forged-unsigned.json");
    fs::write(
        &unsigned,
        serde_json::to_string_pretty(&stripped).expect("serialize"),
    )
    .expect("write forgery");
    let (code, envelope, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--browser",
            "chrome",
            "--profile",
            &profile.to_string_lossy(),
            "--baseline",
            &unsigned.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(
        code, 2,
        "stripping the signature must not be a way past it: {envelope}"
    );
    assert!(
        envelope["error"]
            .as_str()
            .expect("error text")
            .contains("unsigned"),
        "{envelope}"
    );

    fs::write(&target, original).expect("restore fixture");
}

/// A gap ABOVE the tree walk never reached drift, so a run that could not finish
/// reading the profile printed `no drift` and exited 0. The exit-code contract
/// says a verify run that could not verify exits 1.
#[cfg(unix)]
#[test]
fn a_verify_run_that_could_not_cover_the_profile_exits_one() {
    let home = fresh_home();
    let profile = build_profile(&home);
    let baseline = home.join("baseline.json");
    let (code, _, _) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--browser",
            "chrome",
            "--profile",
            &profile.to_string_lossy(),
            "--write-baseline",
            &baseline.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 0);

    // A NEW extension whose manifest repeats a key: Chromium's reader accepts it
    // last-wins, tirith's strict parser refuses it. It used to vanish from the
    // inventory entirely, so no `new` drift was ever emitted.
    let smuggled = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let version = profile.join("Extensions").join(smuggled).join("9.9.9_0");
    fs::create_dir_all(&version).expect("create smuggled tree");
    fs::write(
        version.join("manifest.json"),
        r#"{"manifest_version": 3, "name": "A", "name": "B", "version": "9.9.9",
            "permissions": ["debugger"], "host_permissions": ["<all_urls>"]}"#,
    )
    .expect("write duplicate-key manifest");

    let (code, envelope, stdout) = run_json(
        &home,
        &[
            "browser",
            "audit",
            "--browser",
            "chrome",
            "--profile",
            &profile.to_string_lossy(),
            "--baseline",
            &baseline.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(code, 1, "{stdout}");
    assert_eq!(envelope["verify_complete"], false);
    let ids: Vec<&str> = envelope["report"]["browsers"][0]["profiles"][0]["extensions"]
        .as_array()
        .expect("extensions")
        .iter()
        .map(|extension| extension["id"].as_str().expect("id"))
        .collect();
    assert!(
        ids.contains(&smuggled),
        "an unauditable extension must still be reported: {ids:?}"
    );
    let kinds: Vec<&str> = envelope["drift"]
        .as_array()
        .expect("drift")
        .iter()
        .map(|drift| drift["kind"].as_str().expect("kind"))
        .collect();
    assert!(kinds.contains(&"new"), "{kinds:?}");
}
