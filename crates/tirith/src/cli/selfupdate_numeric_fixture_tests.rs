//! Ignored test-only controller for owned ordinary 0.4.2/0.4.3 products.
//! It drives the CLI update/rollback primitives (`tirith update` building
//! blocks) and stops at named crash boundaries between them.
//! No production key, URL, policy or recovery override is introduced.
//! The controller has an independent executable path; it never impersonates a
//! running installed product. Its input provenance is an outer owned-process
//! observation bound to the held installed bytes and retained build closure.
use super::*;
use serde_json::{json, Value};

const NUMERIC_ENV: &str = "TIRITH_TEST_NUMERIC_REPLACEMENT_MANIFEST";
const NUMERIC_CONTRACT: &str = "tirith_signed_numeric_replacement_fixture_v1";

#[derive(Debug, Clone, Copy, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Boundary {
    Complete,
    Verifying,
    PublicationIntent,
    Published,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NumericManifest {
    fixture: Manifest,
    installed: Image,
    installed_source_manifest: Identity,
    installed_provenance: Identity,
    operation_id: String,
    action: String,
    boundary: Boundary,
}

fn numeric_layout(m: &NumericManifest, pointer: &Path) -> Result<Vec<DirectoryIdentity>, String> {
    let f = &m.fixture;
    require(
        unsafe { libc::geteuid() } != 0 && unsafe { libc::geteuid() } == unsafe { libc::getuid() },
        "numeric fixture requires an ordinary unchanged operator",
    )?;
    let id = uuid::Uuid::parse_str(&f.fixture_id).map_err(|_| "invalid fixture UUID")?;
    let operation = uuid::Uuid::parse_str(&m.operation_id).map_err(|_| "invalid operation UUID")?;
    require(
        !id.is_nil()
            && id.to_string() == f.fixture_id
            && !operation.is_nil()
            && operation.to_string() == m.operation_id,
        "fixture/operation UUID must be canonical and nonnil",
    )?;
    require(
        f.schema_version == 1
            && f.contract == NUMERIC_CONTRACT
            && f.authority == AUTHORITY
            && f.version == "0.4.3"
            && env!("CARGO_PKG_VERSION") == "0.4.2"
            && Some(f.target.as_str()) == selfupdate::release_target_triple(),
        "numeric fixture contract differs",
    )?;
    require(
        f.root.is_absolute()
            && f.root.canonicalize().map_err(io)? == f.root
            && f.root.file_name().and_then(|p| p.to_str())
                == Some(format!("tirith-signed-replacement-{id}").as_str())
            && pointer == f.root.join("numeric-manifest.json"),
        "numeric fixture root/pointer differs",
    )?;
    require(
        m.action == "update" || m.action == "rollback",
        "unknown numeric fixture action",
    )?;
    require(
        m.action == "update" || m.boundary == Boundary::Complete,
        "rollback death injection is outside this lane",
    )?;
    require(
        f.test_executable.kind == "test_harness_not_product"
            && f.test_executable.profile_test
            && f.candidate.kind == "retained_product"
            && !f.candidate.profile_test
            && m.installed.kind == "retained_product"
            && !m.installed.profile_test
            && f.test_executable.identity.sha256 != m.installed.identity.sha256
            && f.test_executable.identity.sha256 != f.candidate.identity.sha256
            && m.installed.identity.sha256 != f.candidate.identity.sha256,
        "numeric executable roles are not distinct",
    )?;
    for (key, suffix) in [
        ("HOME", "home"),
        ("XDG_CONFIG_HOME", "home/.config"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_STATE_HOME", "state"),
        ("XDG_CACHE_HOME", "cache"),
        ("TMPDIR", "tmp"),
    ] {
        require(
            std::env::var_os(key).as_deref() == Some(f.root.join(suffix).as_os_str()),
            "numeric environment escapes its roots",
        )?;
    }
    let path = format!("{}:/usr/bin:/bin", f.root.join("home/.local/bin").display());
    require(
        std::env::var_os("PATH").as_deref() == Some(std::ffi::OsStr::new(&path))
            && std::env::current_dir().map_err(io)? == f.root.join("workspace")
            && std::env::current_exe().map_err(io)? == f.root.join("inputs/controller"),
        "numeric controller path/cwd/PATH differs",
    )?;
    for (key, value) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("TIRITH_") && key != NUMERIC_ENV {
            require(
                key == "TIRITH_LOG" && value == "1",
                "unexpected Tirith fixture environment",
            )?;
        }
    }
    let mut guards = Vec::new();
    for relative in [
        "",
        "home",
        "home/.local",
        "home/.local/bin",
        "home/.config",
        "home/.config/tirith",
        "data",
        "state",
        "cache",
        "tmp",
        "workspace",
        "workspace/.git",
        "workspace/.tirith",
        "inputs",
        "inputs/candidate",
        "inputs/installed",
        "inputs/release",
    ] {
        let directory = f.root.join(relative);
        require(
            std::fs::symlink_metadata(&directory)
                .map_err(io)?
                .permissions()
                .mode()
                & 0o7777
                == 0o700,
            "numeric fixture directory is not private",
        )?;
        guards.push(DirectoryIdentity::capture(&directory)?);
    }
    Ok(guards)
}

fn source_role(
    input: &Input,
    version: &str,
    test: bool,
    identity: &Identity,
) -> Result<Value, String> {
    let value: Value =
        serde_json::from_slice(&input.bytes()?).map_err(|_| "invalid numeric build record")?;
    require(
        value["schema_version"] == 1
            && value["contract"] == "tirith_signed_numeric_build_input_v1"
            && value["version"] == version
            && value["profile_test"] == test
            && value["role"] == if test { "test_harness" } else { "product" }
            && value["binary"]["sha256"] == identity.sha256
            && value["binary"]["size"] == identity.size,
        "numeric source record role/version/image differs",
    )?;
    Ok(value)
}

fn observed_provenance(
    m: &NumericManifest,
    input: &Input,
    destination: &Path,
) -> Result<CliProvenance, String> {
    let value: Value = serde_json::from_slice(&input.bytes()?)
        .map_err(|_| "invalid product provenance observation")?;
    let (version, sha) = if m.action == "update" {
        ("0.4.2", &m.installed.identity.sha256)
    } else {
        ("0.4.3", &m.fixture.candidate.identity.sha256)
    };
    require(
        value["version"] == version
            && value["binary_path"] == destination.to_string_lossy().as_ref()
            && value["binary_sha256"] == *sha
            && value["target"] == m.fixture.target
            && value["build_profile"] == "release"
            && value["dev_build"] == false
            && value["install_method"] == "self-managed"
            && value["install_method_resolved"] == true,
        "actual ordinary installed product provenance differs",
    )?;
    require(
        selfupdate::classify_install_method(destination, true, &read_os_release_ids())
            == InstallMethod::SelfManaged,
        "numeric slot is not classified as self-managed",
    )?;
    verify_exact_regular_preimage(destination, Some(sha))?;
    Ok(CliProvenance {
        core: Provenance {
            version: version.into(),
            binary_path: Some(destination.into()),
            binary_sha256: Some(sha.clone()),
            install_method: InstallMethod::SelfManaged,
            target: Some(m.fixture.target.clone()),
            dev_build: false,
            path_resolution_failed: false,
        },
        origin: CliInstallOrigin::Standard,
    })
}

fn stop_at(m: &NumericManifest, boundary: Boundary) -> Result<(), String> {
    if m.boundary != boundary {
        return Ok(());
    }
    // Every CLI primitive before this boundary has completed. The owner must
    // observe WSTOPPED, then kill/reap its own process and check that the
    // installed binary is the complete old or the complete new image.
    // A marker alone never qualifies process death or recovery.
    let bytes = serde_json::to_vec(&json!({"contract": NUMERIC_CONTRACT, "operation_id": m.operation_id,
        "pid": std::process::id(), "phase": boundary, "published": boundary == Boundary::Published}))
        .map_err(|e| e.to_string())?;
    fixture_create(
        &m.fixture.root.join("observed-boundary.json"),
        &bytes,
        0o600,
    )?;
    File::open(&m.fixture.root)
        .map_err(io)?
        .sync_all()
        .map_err(io)?;
    require(
        unsafe { libc::raise(libc::SIGSTOP) } == 0,
        "could not enter observed fixture stop",
    )?;
    Err("stopped numeric controller was resumed; publication must not continue".into())
}

#[test]
#[ignore = "requires three held build admissions and an owned private numeric fixture; never a real install"]
fn signed_numeric_product_publication() -> Result<(), String> {
    let pointer = std::env::var_os(NUMERIC_ENV).ok_or("numeric fixture manifest required")?;
    let manifest_input = Input::capture(Path::new(&pointer), 48 * 1024, false, None)?;
    let m: NumericManifest = serde_json::from_slice(&manifest_input.bytes()?)
        .map_err(|_| "malformed closed numeric manifest")?;
    let guards = numeric_layout(&m, Path::new(&pointer))?;
    let f = &m.fixture;
    let root = &f.root;
    let destination = root.join("home/.local/bin/tirith");
    let backup = previous_backup_path(&destination);
    let archive_path = root
        .join("inputs/release")
        .join(selfupdate::release_archive_name(&f.target));
    let mut inputs = vec![manifest_input];
    for (path, identity, cap, executable) in [
        (
            "inputs/controller",
            &f.test_executable.identity,
            512 * MIB,
            true,
        ),
        (
            "inputs/installed/tirith",
            &m.installed.identity,
            256 * MIB,
            true,
        ),
        (
            "inputs/candidate/tirith",
            &f.candidate.identity,
            256 * MIB,
            true,
        ),
        (
            "home/.config/tirith/policy.yaml",
            &f.preserved.policy,
            64 * 1024,
            false,
        ),
        ("home/.zshrc", &f.preserved.startup, 64 * 1024, false),
        (
            "home/.config/tirith/trust.json",
            &f.preserved.legacy_trust,
            64 * 1024,
            false,
        ),
        (
            "home/.config/tirith/trust-grants.json",
            &f.preserved.scoped_grants,
            64 * 1024,
            false,
        ),
        (
            "workspace/.tirith/mcp.lock",
            &f.preserved.mcp_lock,
            64 * 1024,
            false,
        ),
    ] {
        inputs.push(Input::capture(
            &root.join(path),
            cap,
            executable,
            Some(identity),
        )?);
    }
    let test_source = Input::capture(
        &root.join("inputs/test-source.json"),
        MIB,
        false,
        Some(&f.test_source_manifest),
    )?;
    let old_source = Input::capture(
        &root.join("inputs/installed-source.json"),
        MIB,
        false,
        Some(&m.installed_source_manifest),
    )?;
    let new_source = Input::capture(
        &root.join("inputs/candidate-source.json"),
        MIB,
        false,
        Some(&f.candidate_source_manifest),
    )?;
    let test_record = source_role(&test_source, "0.4.2", true, &f.test_executable.identity)?;
    let old_record = source_role(&old_source, "0.4.2", false, &m.installed.identity)?;
    let new_record = source_role(&new_source, "0.4.3", false, &f.candidate.identity)?;
    require(
        test_record["source"]["files"] == old_record["source"]["files"],
        "controller contract does not equal the installed ordinary product source",
    )?;
    let files = |value: &Value| -> Result<std::collections::BTreeMap<String, Value>, String> {
        let rows = value["source"]["files"]
            .as_array()
            .ok_or("source file array missing")?;
        let mut result = std::collections::BTreeMap::new();
        for row in rows {
            let path = row["path"].as_str().ok_or("source path missing")?;
            require(
                result.insert(path.to_string(), row.clone()).is_none(),
                "duplicate source path",
            )?;
        }
        Ok(result)
    };
    let before = files(&old_record)?;
    let after = files(&new_record)?;
    require(
        before.keys().eq(after.keys())
            && before
                .iter()
                .filter(|(path, value)| after.get(*path) != Some(*value))
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>()
                == ["Cargo.lock", "Cargo.toml"],
        "numeric source delta exceeds the separately byte-admitted version manifests",
    )?;
    inputs.extend([test_source, old_source, new_source]);
    let observed = Input::capture(
        &root.join("inputs/installed-provenance.json"),
        64 * 1024,
        false,
        Some(&m.installed_provenance),
    )?;
    let provenance = observed_provenance(&m, &observed, &destination)?;
    inputs.push(observed);
    let current = Input::capture(
        &destination,
        256 * MIB,
        true,
        Some(if m.action == "update" {
            &m.installed.identity
        } else {
            &f.candidate.identity
        }),
    )?;
    let archive = Input::capture(&archive_path, MAX_ARCHIVE_SIZE, false, Some(&f.archive))?;
    let checksums = Input::capture(
        &root.join("inputs/release/checksums.txt"),
        MAX_METADATA_SIZE,
        false,
        Some(&f.checksums),
    )?;
    let signature = Input::capture(
        &root.join("inputs/release/checksums.fixture.ed25519"),
        64,
        false,
        Some(&f.signature),
    )?;
    let compatibility = Input::capture(
        &root.join("inputs/release/release-compatibility.json"),
        MAX_METADATA_SIZE,
        false,
        Some(&f.compatibility),
    )?;
    let release = ReleaseSet {
        tag: "v0.4.3".into(),
        archive_path: archive_path.clone(),
        checksums_txt: String::from_utf8(checksums.bytes()?).map_err(|_| "checksums not UTF-8")?,
        checksums_path: checksums.path.clone(),
        sig_path: None,
        cert_path: None,
    };
    let verified = release_compatibility::VerifiedCandidate::verify_fixture_key(
        &release,
        &compatibility.bytes()?,
        &f.target,
        &signature.bytes()?,
    )?;
    require(
        verified.binary_sha256() == f.candidate.identity.sha256
            && verified.archive_sha256() == archive.digest,
        "numeric signature does not bind candidate/archive",
    )?;
    preflight_archive(
        &archive.bytes()?,
        verified.archive_sha256(),
        &f.candidate.identity,
    )?;
    verified.preview(&provenance).require_compatible()?;
    inputs.extend([archive, checksums, signature, compatibility]);
    require(
        tirith_core::policy::Policy::discover_local_only(None)
            .task_gate
            .mode
            == tirith_core::web3_policy::TaskGateMode::Enforce,
        "numeric fixture requires the real enabled task gate",
    )?;
    revalidate(&guards, &inputs)?;
    current.revalidate()?;
    stop_at(&m, Boundary::Verifying)?;
    if m.action == "update" {
        verify_exact_regular_preimage(&backup, None)?;
        let auth = authorization(
            f,
            "extract-and-update",
            &destination,
            &current.digest,
            verified.binary_sha256(),
            None,
            None,
        )?;
        let work = root.join("tmp/numeric-extraction");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&work)
            .map_err(io)?;
        let extracted = extract_tirith_binary(&archive_path, &f.target, &work, &auth)?;
        println!("\nTIRITH_NUMERIC_EXTRACTOR_COMPLETED");
        let extracted_input =
            Input::capture(&extracted, 256 * MIB, true, Some(&f.candidate.identity))?;
        let control = crate::cli::control::quiesce_for_update()?;
        control.revalidate()?;
        current.revalidate()?;
        revalidate(&guards, &inputs)?;
        release_compatibility::preserve_current_for_rollback(&provenance, &auth)?;
        stop_at(&m, Boundary::PublicationIntent)?;
        control.revalidate()?;
        revalidate(&guards, &inputs)?;
        current.revalidate()?;
        extracted_input.revalidate()?;
        verified.preview(&provenance).require_compatible()?;
        atomic_self_replace(
            &destination,
            &extracted,
            verified.binary_sha256(),
            &current.digest,
            None,
            &auth,
        )?;
        verify_exact_regular_preimage(&destination, Some(verified.binary_sha256()))?;
        verify_exact_regular_preimage(&backup, Some(&m.installed.identity.sha256))?;
        stop_at(&m, Boundary::Published)?;
    } else {
        verify_exact_regular_preimage(&backup, Some(&m.installed.identity.sha256))?;
        let rollback = release_compatibility::VerifiedRollback::load(
            &destination,
            &m.installed.identity.sha256,
        )?;
        rollback.preview(&provenance).require_compatible()?;
        let auth = authorization(
            f,
            "numeric-rollback",
            &destination,
            &current.digest,
            &m.installed.identity.sha256,
            Some(&m.installed.identity.sha256),
            Some(rollback.receipt_sha256()),
        )?;
        let control = crate::cli::control::quiesce_for_update()?;
        control.revalidate()?;
        revalidate(&guards, &inputs)?;
        current.revalidate()?;
        rollback.revalidate(&destination, &m.installed.identity.sha256)?;
        control.revalidate()?;
        atomic_restore_from(
            &destination,
            &backup,
            &current.digest,
            &m.installed.identity.sha256,
            &auth,
        )?;
        verify_exact_regular_preimage(&destination, Some(&m.installed.identity.sha256))?;
    }
    revalidate(&guards, &inputs)?;
    println!("\nTIRITH_NUMERIC_PUBLICATION_COMPLETE");
    Ok(())
}
