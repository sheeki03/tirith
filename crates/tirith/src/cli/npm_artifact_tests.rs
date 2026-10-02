use super::*;
use tirith_core::artifact::npm_archive::{NpmCapability, NpmFile, NpmFileKind, NpmSignalKind};

#[test]
fn artifact_refresh_retains_earlier_dlp_and_adds_new_policy_patterns() {
    let state = tirith_test_support::GlobalStateGuard::new().unwrap();
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    let policy = config.join("policy.yaml");
    std::fs::write(&policy, "dlp_custom_patterns:\n  - 'EARLIER_SECRET'\n").unwrap();
    let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
    let mut context = Context::capture_for(state.roots().cwd.to_str());
    std::fs::write(&policy, "dlp_custom_patterns:\n  - 'LATER_SECRET'\n").unwrap();
    context.refresh_for(state.roots().cwd.to_str());
    let displayed = content("EARLIER_SECRET LATER_SECRET", &context.compiled);
    assert!(!displayed.contains("EARLIER_SECRET"));
    assert!(!displayed.contains("LATER_SECRET"));
}

fn fixture() -> NpmInspection {
    read_npm_tarball(
        include_bytes!("../../../tirith-core/tests/fixtures/npm/npm-11.19.0-portable-pax.tgz")
            .as_slice(),
        "PRIVATE_ARCHIVE.tgz",
        &NpmLimits::default(),
    )
}

#[test]
fn broad_dlp_preserves_only_canonical_hashes_statuses_and_protocol_enums() {
    let inspection = fixture();
    let hash = inspection.artifact.sha256.clone().unwrap();
    let compiled = CompiledCustomPatterns::new_silent(&[".+".to_owned()]);
    let value = inspection_projection(&[inspection], &compiled, &["PRIVATE_DIAGNOSTIC".to_owned()]);
    assert_eq!(value["kind"], "npm_inspection");
    assert_eq!(value["status"], "accepted");
    assert_eq!(value["artifacts"][0]["artifact"]["sha256"], hash);
    assert_eq!(value["artifacts"][0]["archive_state"], "accepted");
    assert_eq!(
        value["artifacts"][0]["analyzer_version"],
        NPM_ANALYZER_VERSION
    );
    assert_eq!(value["artifacts"][0]["files"][0]["kind"], "java_script");
    assert_eq!(
        value["artifacts"][0]["signals"][0]["kind"],
        "lifecycle_script"
    );
    assert_eq!(
        value["artifacts"][0]["signals"][0]["lifecycle_events"][0],
        "postinstall"
    );
    let text = value.to_string();
    assert!(!text.contains("PRIVATE_ARCHIVE"));
    assert!(!text.contains("PRIVATE_DIAGNOSTIC"));
    assert!(!text.contains("tirith-local-inspection-fixture"));
    assert!(!text.contains("node install.js"));
    assert!(text.contains("REDACTED"));
}

#[test]
fn dynamic_metadata_keys_are_redacted_without_collapsing_rows() {
    let mut inspection = fixture();
    let scripts = &mut inspection.metadata.as_mut().unwrap().scripts;
    scripts.insert("PRIVATE_ONE".to_owned(), "PRIVATE_VALUE_ONE".to_owned());
    scripts.insert("PRIVATE_TWO".to_owned(), "PRIVATE_VALUE_TWO".to_owned());
    let compiled = CompiledCustomPatterns::new_silent(&["PRIVATE_[A-Z_]+".to_owned()]);
    let value = inspection_projection(&[inspection], &compiled, &[]);
    assert_eq!(
        value["artifacts"][0]["metadata"]["scripts"]["entries"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert!(!value.to_string().contains("PRIVATE_"));
}

#[test]
fn full_string_redaction_precedes_all_display_caps_and_invalid_hashes_have_no_exemption() {
    let mut inspection = fixture();
    let secret = format!("PRIVATE_BEGIN{}PRIVATE_END", "x".repeat(1800));
    inspection
        .metadata
        .as_mut()
        .unwrap()
        .scripts
        .insert("test".to_owned(), secret.clone());
    inspection.artifact.sha256 = Some("PRIVATE_INVALID_HASH".to_owned());
    let compiled = CompiledCustomPatterns::new_silent(&[secret, "PRIVATE_INVALID_HASH".to_owned()]);
    let value = inspection_projection(&[inspection], &compiled, &[]);
    let text = value.to_string();
    assert!(!text.contains("PRIVATE_BEGIN"));
    assert!(!text.contains("PRIVATE_END"));
    assert!(!text.contains("PRIVATE_INVALID_HASH"));
    assert!(text.contains("REDACTED"));
}

#[test]
fn bounded_projection_keeps_late_review_signal_and_reports_omitted_rows() {
    let mut inspection = fixture();
    for index in 0..200 {
        inspection.signals.push(NpmSignal {
            kind: NpmSignalKind::NativeArtifact,
            level: NpmSignalLevel::Observation,
            member: format!("package/{index}.node"),
            capabilities: vec![NpmCapability::NativeModule],
            lifecycle_events: Vec::new(),
            evidence: "Ordinary module".to_owned(),
        });
        inspection.files.push(NpmFile {
            path: format!("package/{index}/{}.js", "p".repeat(3500)),
            sha256: "b".repeat(64),
            size: 1,
            kind: NpmFileKind::JavaScript,
            executable: false,
        });
    }
    inspection.signals.push(NpmSignal {
        kind: NpmSignalKind::DownloadToShell,
        level: NpmSignalLevel::Review,
        member: "package/package.json".to_owned(),
        capabilities: vec![NpmCapability::NetworkAccess],
        lifecycle_events: vec!["install".to_owned()],
        evidence: "Review download pipeline".to_owned(),
    });
    let compiled = CompiledCustomPatterns::new_silent(&[]);
    let value = inspection_projection(&vec![inspection; 8], &compiled, &[]);
    assert!(serde_json::to_vec(&value).unwrap().len() <= MAX_REPORT_BYTES);
    assert_eq!(value["status"], "review");
    assert_eq!(
        value["artifacts"][0]["signals"][0]["kind"],
        "download_to_shell"
    );
    assert!(value["artifacts"][0]["omitted_files"].as_u64().unwrap() > 0);
    assert!(value["artifacts"][0]["omitted_signals"].as_u64().unwrap() > 0);
}

#[test]
fn comparison_projection_and_sarif_share_redacted_content_and_exact_identities() {
    let old = fixture();
    let mut new = old.clone();
    new.artifact.sha256 = Some("a".repeat(64));
    new.metadata
        .as_mut()
        .unwrap()
        .scripts
        .insert("install".to_owned(), "PRIVATE_SCRIPT".to_owned());
    new.signals.push(NpmSignal {
        kind: NpmSignalKind::DownloadToShell,
        level: NpmSignalLevel::Review,
        member: "PRIVATE_PATH".to_owned(),
        capabilities: vec![NpmCapability::NetworkAccess, NpmCapability::ProcessSpawn],
        lifecycle_events: vec!["install".to_owned()],
        evidence: "PRIVATE_EVIDENCE".to_owned(),
    });
    let comparison = compare_npm_releases(&old, &new).unwrap();
    let compiled = CompiledCustomPatterns::new_silent(&[".+".to_owned()]);
    let report = comparison_projection(&comparison, &compiled, &[]);
    assert_eq!(report["kind"], "npm_comparison");
    assert_eq!(report["new_artifact"]["sha256"], "a".repeat(64));
    assert_eq!(report["deltas"][0]["kind"], "declared_script_added");
    let sarif = sarif_projection(&report);
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(
        sarif["runs"][0]["results"][0]["ruleId"],
        "npm_download_to_shell"
    );
    assert_eq!(sarif["runs"][0]["results"][0]["level"], "warning");
    let text = sarif.to_string();
    assert!(!text.contains("PRIVATE_"));
    assert!(text.contains("REDACTED"));
}

#[test]
fn no_follow_file_reader_refuses_symlinks_and_inspection_exit_is_honest() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("fixture.tgz");
    std::fs::write(
        &file,
        include_bytes!("../../../tirith-core/tests/fixtures/npm/npm-11.19.0-portable-pax.tgz"),
    )
    .unwrap();
    let inspection = load(&file).unwrap();
    assert_eq!(inspection_code(&inspection), 0);
    #[cfg(unix)]
    {
        let link = root.path().join("link.tgz");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(load(&link).is_err());
    }
    let rejected = read_npm_tarball(b"not gzip".as_slice(), "bad.tgz", &NpmLimits::default());
    assert_eq!(inspection_code(&rejected), 1);
    let mut incomplete = inspection;
    incomplete.coverage.static_analysis_complete = false;
    assert_eq!(inspection_code(&incomplete), 2);
}
