//! Explicit, ignored same-version native fixture; this entire module is test-only.
//! A public test key qualifies mechanisms, never official release authority.
use super::*;
use crate::cli::control::identity::DirectoryIdentity;
use serde::Deserialize;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

const CONTRACT: &str = "tirith_signed_replacement_fixture_v1";
const AUTHORITY: &str = "fixture_key_signed_checksums_not_official_release";
const MANIFEST_ENV: &str = "TIRITH_TEST_SIGNED_REPLACEMENT_MANIFEST";
const MIB: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    sha256: String,
    size: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Image {
    kind: String,
    profile_test: bool,
    identity: Identity,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preserved {
    policy: Identity,
    startup: Identity,
    legacy_trust: Identity,
    scoped_grants: Identity,
    mcp_lock: Identity,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    contract: String,
    fixture_id: String,
    root: PathBuf,
    version: String,
    target: String,
    authority: String,
    test_executable: Image,
    candidate: Image,
    archive: Identity,
    checksums: Identity,
    signature: Identity,
    compatibility: Identity,
    test_source_manifest: Identity,
    candidate_source_manifest: Identity,
    preserved: Preserved,
}

fn require(condition: bool, reason: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(reason.into())
    }
}
fn io(error: std::io::Error) -> String {
    error.to_string()
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
fn validate_identity(identity: &Identity, cap: u64) -> Result<(), String> {
    require(
        valid_digest(&identity.sha256) && identity.size > 0 && identity.size <= cap,
        "fixture identity is invalid or exceeds its bound",
    )
}
type Generation = (u64, u64, u64, i64, i64, i64, i64, u32, u32, u64);
fn generation(metadata: &Metadata) -> Generation {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
        metadata.mode(),
        metadata.uid(),
        metadata.nlink(),
    )
}

/// Retain native input ownership and bytes, not merely a digest of a reopened path.
/// These witnesses are fixture guards, not a production signature or mutation permit.
struct Input {
    path: PathBuf,
    file: File,
    before: Metadata,
    digest: String,
    cap: u64,
}
impl Input {
    fn capture(
        path: &Path,
        cap: u64,
        executable: bool,
        expected: Option<&Identity>,
    ) -> Result<Self, String> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(io)?;
        let before = file.metadata().map_err(io)?;
        require(
            before.is_file()
                && before.uid() == unsafe { libc::geteuid() }
                && before.nlink() == 1
                && before.len() > 0
                && before.len() <= cap,
            "fixture input is not a bounded, singly linked owner file",
        )?;
        let mode = before.mode() & 0o7777;
        require(
            if executable {
                matches!(mode, 0o700 | 0o755)
            } else {
                mode == 0o600
            },
            "fixture input permissions differ from the admitted profile",
        )?;
        let digest = hash_held(&file, cap)?;
        if let Some(expected) = expected {
            validate_identity(expected, cap)?;
            require(
                before.len() == expected.size && digest == expected.sha256,
                "fixture bytes differ from their retained manifest",
            )?;
        }
        let input = Self {
            path: path.into(),
            file,
            before,
            digest,
            cap,
        };
        input.revalidate()?;
        Ok(input)
    }
    fn revalidate(&self) -> Result<(), String> {
        let current = std::fs::symlink_metadata(&self.path).map_err(io)?;
        require(
            generation(&current) == generation(&self.before)
                && generation(&self.file.metadata().map_err(io)?) == generation(&self.before)
                && hash_held(&self.file, self.cap)? == self.digest
                && generation(&self.file.metadata().map_err(io)?) == generation(&self.before)
                && generation(&std::fs::symlink_metadata(&self.path).map_err(io)?)
                    == generation(&self.before),
            "retained fixture input changed",
        )
    }
    fn bytes(&self) -> Result<Vec<u8>, String> {
        self.revalidate()?;
        let mut file = self.file.try_clone().map_err(io)?;
        file.seek(SeekFrom::Start(0)).map_err(io)?;
        let mut bytes = Vec::new();
        file.take(self.cap + 1)
            .read_to_end(&mut bytes)
            .map_err(io)?;
        require(
            bytes.len() as u64 <= self.cap && hex_sha256(&bytes) == self.digest,
            "fixture input changed while reading",
        )?;
        self.revalidate()?;
        Ok(bytes)
    }
}
fn hash_held(file: &File, cap: u64) -> Result<String, String> {
    let mut file = file.try_clone().map_err(io)?;
    file.seek(SeekFrom::Start(0)).map_err(io)?;
    let mut limited = file.take(cap + 1);
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut block = [0u8; 64 * 1024];
    loop {
        let read = limited.read(&mut block).map_err(io)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        require(total <= cap, "fixture file grew beyond its bound")?;
        hash.update(&block[..read]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

/// Strict USTAR subset, fully accepted before invoking the production extractor.
/// Stream the payload; reject links, prefixes, extensions, multiple members,
/// concatenated gzip streams and unbounded padding. No package bytes execute.
fn preflight_archive(
    compressed: &[u8],
    expected_archive: &str,
    candidate: &Identity,
) -> Result<(), String> {
    require(
        compressed.len() as u64 <= MAX_ARCHIVE_SIZE && hex_sha256(compressed) == expected_archive,
        "archive bytes differ from the signed checksum",
    )?;
    validate_identity(candidate, 256 * MIB)?;
    let mut gzip = flate2::bufread::GzDecoder::new(compressed);
    single_ustar_member(&mut gzip, candidate)?;
    require(
        gzip.into_inner().is_empty(),
        "fixture gzip has trailing compressed data",
    )
}
fn octal(field: &[u8]) -> Result<u64, String> {
    let digits = field
        .iter()
        .copied()
        .take_while(|v| *v != 0 && *v != b' ')
        .collect::<Vec<_>>();
    require(
        !digits.is_empty()
            && digits.iter().all(|v| (b'0'..=b'7').contains(v))
            && field[digits.len()..].iter().all(|v| *v == 0 || *v == b' '),
        "noncanonical USTAR number",
    )?;
    digits.into_iter().try_fold(0u64, |n, digit| {
        n.checked_mul(8)
            .and_then(|n| n.checked_add(u64::from(digit - b'0')))
            .ok_or_else(|| "USTAR number overflow".into())
    })
}
fn single_ustar_member(reader: &mut impl Read, candidate: &Identity) -> Result<(), String> {
    let mut header = [0u8; 512];
    reader.read_exact(&mut header).map_err(io)?;
    require(
        &header[..7] == b"tirith\0"
            && header[7..100].iter().all(|v| *v == 0)
            && &header[257..263] == b"ustar\0"
            && &header[263..265] == b"00"
            && header[156] == b'0'
            && header[157..257].iter().all(|v| *v == 0)
            && header[265..].iter().all(|v| *v == 0),
        "archive is outside the single root regular USTAR profile",
    )?;
    let sum: u64 = header
        .iter()
        .enumerate()
        .map(|(i, v)| {
            if (148..156).contains(&i) {
                32
            } else {
                u64::from(*v)
            }
        })
        .sum();
    require(
        octal(&header[148..156])? == sum
            && octal(&header[100..108])? == 0o755
            && octal(&header[108..116])? == 0
            && octal(&header[116..124])? == 0
            && octal(&header[136..148])? == 0
            && octal(&header[124..136])? == candidate.size,
        "USTAR header checksum, mode or payload size differs",
    )?;
    let mut remaining = candidate.size;
    let mut hash = Sha256::new();
    let mut block = [0u8; 64 * 1024];
    while remaining > 0 {
        let count = remaining.min(block.len() as u64) as usize;
        reader.read_exact(&mut block[..count]).map_err(io)?;
        hash.update(&block[..count]);
        remaining -= count as u64;
    }
    require(
        format!("{:x}", hash.finalize()) == candidate.sha256,
        "archive executable differs from retained candidate",
    )?;
    let pad = ((512 - candidate.size % 512) % 512) as usize;
    reader.read_exact(&mut block[..pad]).map_err(io)?;
    require(
        block[..pad].iter().all(|v| *v == 0),
        "nonzero member padding",
    )?;
    reader.read_exact(&mut block[..1024]).map_err(io)?;
    require(
        block[..1024].iter().all(|v| *v == 0),
        "archive contains an extra member or missing terminator",
    )?;
    let mut padding = Vec::new();
    reader
        .take(10 * 1024 + 1)
        .read_to_end(&mut padding)
        .map_err(io)?;
    require(
        padding.len() <= 10 * 1024 && padding.len() % 512 == 0 && padding.iter().all(|v| *v == 0),
        "archive trailing expansion exceeds the bounded zero padding profile",
    )
}

fn validate_layout(manifest: &Manifest, pointer: &Path) -> Result<Vec<DirectoryIdentity>, String> {
    require(
        manifest.schema_version == 1
            && manifest.contract == CONTRACT
            && manifest.authority == AUTHORITY,
        "unknown fixture manifest contract or authority",
    )?;
    let id = uuid::Uuid::parse_str(&manifest.fixture_id).map_err(|_| "invalid fixture UUID")?;
    require(
        !id.is_nil() && id.to_string() == manifest.fixture_id,
        "fixture UUID must be canonical and non-nil",
    )?;
    require(
        manifest.root.is_absolute()
            && manifest.root.canonicalize().map_err(io)? == manifest.root
            && manifest.root.file_name().and_then(|p| p.to_str())
                == Some(format!("tirith-signed-replacement-{id}").as_str())
            && pointer == manifest.root.join("manifest.json"),
        "fixture root/pointer is not the exact private layout",
    )?;
    require(
        manifest.version == env!("CARGO_PKG_VERSION")
            && manifest.version == "0.4.2"
            && Some(manifest.target.as_str()) == selfupdate::release_target_triple(),
        "fixture version or native target differs",
    )?;
    require(
        manifest.test_executable.kind == "test_harness_not_product"
            && manifest.test_executable.profile_test
            && manifest.candidate.kind == "retained_product"
            && !manifest.candidate.profile_test
            && manifest.candidate.identity.sha256 != manifest.test_executable.identity.sha256,
        "fixture executable roles or distinct generations are invalid",
    )?;
    // Conservative bound on all simultaneously retained images/staging/backup copies.
    let storage = manifest
        .test_executable
        .identity
        .size
        .checked_mul(3)
        .and_then(|n| {
            manifest
                .candidate
                .identity
                .size
                .checked_mul(4)
                .and_then(|m| n.checked_add(m))
        })
        .and_then(|n| n.checked_add(manifest.archive.size));
    require(
        storage.is_some_and(|n| n <= 3 * 1024 * MIB),
        "fixture storage budget cannot be bounded",
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
            std::env::var_os(key).as_deref() == Some(manifest.root.join(suffix).as_os_str()),
            "fixture environment escapes its fixed roots",
        )?;
    }
    let path = format!(
        "{}:/usr/bin:/bin",
        manifest.root.join("home/.local/bin").display()
    );
    require(
        std::env::var_os("PATH").as_deref() == Some(std::ffi::OsStr::new(&path))
            && std::env::current_dir().map_err(io)? == manifest.root.join("workspace"),
        "fixture PATH or working directory differs",
    )?;
    for (key, value) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("TIRITH_") && key != MANIFEST_ENV {
            require(
                key == "TIRITH_LOG" && value == "1",
                "unexpected Tirith environment in isolated fixture",
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
        "inputs/release",
    ] {
        let directory = manifest.root.join(relative);
        require(
            std::fs::symlink_metadata(&directory)
                .map_err(io)?
                .permissions()
                .mode()
                & 0o7777
                == 0o700,
            "fixture directory is not mode0700",
        )?;
        guards.push(DirectoryIdentity::capture(&directory)?);
    }
    require(
        std::env::current_exe().map_err(io)? == manifest.root.join("home/.local/bin/tirith"),
        "native test is not executing from its fixed disposable install slot",
    )?;
    Ok(guards)
}
fn revalidate(guards: &[DirectoryIdentity], inputs: &[Input]) -> Result<(), String> {
    for guard in guards {
        guard.revalidate()?;
    }
    for input in inputs {
        input.revalidate()?;
    }
    Ok(())
}
fn fixture_create(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(io)?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)
}
fn remove_exact_fixture(path: &Path, sha: &str) -> Result<(), String> {
    verify_exact_regular_preimage(path, Some(sha))?;
    std::fs::remove_file(path).map_err(io)
}
fn authorization(
    manifest: &Manifest,
    mode: &str,
    destination: &Path,
    old: &str,
    new: &str,
    backup: Option<&str>,
    receipt: Option<&str>,
) -> Result<RetainedSelfAuthorization<tirith_core::task_boundary::SelfUpdateBoundary>, String> {
    let envelope = self_boundary_envelope(
        "signed-native-fixture",
        serde_json::json!({
            "fixture_id": manifest.fixture_id, "mode": mode, "authority": AUTHORITY,
            "old_sha256": old, "new_sha256": new, "expected_backup_sha256": backup,
            "receipt_sha256": receipt, "archive_sha256": manifest.archive.sha256,
            "compatibility_sha256": manifest.compatibility.sha256, "checksums_sha256": manifest.checksums.sha256,
            "test_source_sha256": manifest.test_source_manifest.sha256,
            "candidate_source_sha256": manifest.candidate_source_manifest.sha256,
            "updates_privileged_helper": false,
        }),
        Some(destination),
    )?;
    // Extraction/update keeps the production update's conservative network effect;
    // rollback and explicit test mutations use its ordinary write-only effect set.
    prepare_self_authorization::<tirith_core::task_boundary::SelfUpdateBoundary>(
        envelope,
        if mode == "extract-and-update" {
            update_effects(false, false)
        } else {
            rollback_effects(false)
        },
    )
}

#[test]
#[ignore = "requires an owned, hash-pinned disposable native fixture; never a real install"]
fn signed_native_self_replacement_and_rollback() -> Result<(), String> {
    require(
        unsafe { libc::geteuid() } != 0 && unsafe { libc::geteuid() } == unsafe { libc::getuid() },
        "fixture requires an ordinary user without a changed effective identity",
    )?;
    let pointer = std::env::var_os(MANIFEST_ENV).ok_or("native fixture manifest is required")?;
    let manifest_input = Input::capture(Path::new(&pointer), 32 * 1024, false, None)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_input.bytes()?)
        .map_err(|_| "malformed closed fixture manifest")?;
    let guards = validate_layout(&manifest, Path::new(&pointer))?;
    let root = &manifest.root;
    let destination = root.join("home/.local/bin/tirith");
    let backup = previous_backup_path(&destination);
    verify_exact_regular_preimage(&backup, None)?;
    let old = Input::capture(
        &destination,
        512 * MIB,
        true,
        Some(&manifest.test_executable.identity),
    )?;
    let candidate = Input::capture(
        &root.join("inputs/candidate/tirith"),
        256 * MIB,
        true,
        Some(&manifest.candidate.identity),
    )?;
    require(
        old.before.mode() & 0o7777 == 0o755 && candidate.before.mode() & 0o7777 == 0o755,
        "retained input executable permissions must be mode0755",
    )?;
    let archive_path = root
        .join("inputs/release")
        .join(selfupdate::release_archive_name(&manifest.target));
    let archive = Input::capture(
        &archive_path,
        MAX_ARCHIVE_SIZE,
        false,
        Some(&manifest.archive),
    )?;
    let checksums = Input::capture(
        &root.join("inputs/release/checksums.txt"),
        MAX_METADATA_SIZE,
        false,
        Some(&manifest.checksums),
    )?;
    let signature = Input::capture(
        &root.join("inputs/release/checksums.fixture.ed25519"),
        64,
        false,
        Some(&manifest.signature),
    )?;
    let compatibility = Input::capture(
        &root.join("inputs/release/release-compatibility.json"),
        MAX_METADATA_SIZE,
        false,
        Some(&manifest.compatibility),
    )?;
    let mut inputs = vec![manifest_input];
    for (path, identity, cap) in [
        (
            "inputs/test-source.json",
            &manifest.test_source_manifest,
            MIB,
        ),
        (
            "inputs/candidate-source.json",
            &manifest.candidate_source_manifest,
            MIB,
        ),
        (
            "home/.config/tirith/policy.yaml",
            &manifest.preserved.policy,
            64 * 1024,
        ),
        ("home/.zshrc", &manifest.preserved.startup, 64 * 1024),
        (
            "home/.config/tirith/trust.json",
            &manifest.preserved.legacy_trust,
            64 * 1024,
        ),
        (
            "home/.config/tirith/trust-grants.json",
            &manifest.preserved.scoped_grants,
            64 * 1024,
        ),
        (
            "workspace/.tirith/mcp.lock",
            &manifest.preserved.mcp_lock,
            64 * 1024,
        ),
    ] {
        inputs.push(Input::capture(
            &root.join(path),
            cap,
            false,
            Some(identity),
        )?);
    }
    let compatibility_bytes = compatibility.bytes()?;
    let signature_bytes = signature.bytes()?;
    let release = ReleaseSet {
        tag: format!("v{}", manifest.version),
        archive_path: archive_path.clone(),
        checksums_txt: String::from_utf8(checksums.bytes()?)
            .map_err(|_| "checksums are not UTF-8")?,
        checksums_path: checksums.path.clone(),
        sig_path: None,
        cert_path: None,
    };
    let verified = release_compatibility::VerifiedCandidate::verify_fixture_key(
        &release,
        &compatibility_bytes,
        &manifest.target,
        &signature_bytes,
    )?;
    require(
        verified.binary_sha256() == candidate.digest && verified.archive_sha256() == archive.digest,
        "signed fixture does not bind both actual candidate and archive",
    )?;
    let archive_bytes = archive.bytes()?;
    preflight_archive(
        &archive_bytes,
        verified.archive_sha256(),
        &manifest.candidate.identity,
    )?;
    let mut altered = archive_bytes.clone();
    altered[0] ^= 1;
    require(
        preflight_archive(
            &altered,
            verified.archive_sha256(),
            &manifest.candidate.identity,
        )
        .is_err(),
        "modified archive was accepted",
    )?;
    drop(altered);
    drop(archive_bytes);
    // Real signature/checksum refusals against the retained native fixture bytes.
    let mut wrong_signature = signature_bytes.clone();
    wrong_signature[0] ^= 1;
    require(
        release_compatibility::VerifiedCandidate::verify_fixture_key(
            &release,
            &compatibility_bytes,
            &manifest.target,
            &wrong_signature,
        )
        .is_err(),
        "modified signature accepted",
    )?;
    let mut wrong_document = compatibility_bytes.clone();
    wrong_document[0] ^= 1;
    require(
        release_compatibility::VerifiedCandidate::verify_fixture_key(
            &release,
            &wrong_document,
            &manifest.target,
            &signature_bytes,
        )
        .is_err(),
        "modified document accepted",
    )?;
    let wrong_release = ReleaseSet {
        checksums_txt: format!("{} ", release.checksums_txt),
        ..release
    };
    require(
        release_compatibility::VerifiedCandidate::verify_fixture_key(
            &wrong_release,
            &compatibility_bytes,
            &manifest.target,
            &signature_bytes,
        )
        .is_err(),
        "modified checksums accepted",
    )?;
    semantic_signature_negatives(&wrong_release, &compatibility_bytes, &manifest.target)?;
    inputs.extend([candidate, archive, checksums, signature, compatibility]);
    let provenance = gather_cli_provenance();
    require(
        provenance.binary_path.as_deref() == Some(destination.as_path())
            && provenance.binary_sha256.as_deref() == Some(old.digest.as_str())
            && !provenance.path_resolution_failed,
        "running-image provenance did not bind the actual disposable executable",
    )?;
    let preview = verified.preview(&provenance);
    preview.require_compatible()?;
    require(
        preview.evidence == AUTHORITY,
        "fixture authority was mislabelled",
    )?;
    for (surface, version) in [
        ("policy", 2),
        ("legacy_trust", 1),
        ("scoped_grants", 1),
        ("mcp_lock", 8),
    ] {
        require(
            preview.observed_formats.iter().any(|fact| {
                fact.surface == surface
                    && fact.declared_version == Some(version)
                    && fact.state == "declared_local_unverified"
            }),
            "required actual local format was not observed",
        )?;
    }
    require(
        tirith_core::policy::config_dir().as_deref()
            == Some(root.join("home/.config/tirith").as_path())
            && tirith_core::policy::data_dir().as_deref()
                == Some(root.join("data/tirith").as_path()),
        "native policy or audit roots differ from the isolated profile",
    )?;
    let policy = tirith_core::policy::Policy::discover_local_only(None);
    require(
        policy.task_gate.mode == tirith_core::web3_policy::TaskGateMode::Enforce,
        "fixture must exercise the enabled real task gate",
    )?;
    let future_format = root.join("workspace/.tirith/trust.json");
    let future_bytes = b"{\"version\":999,\"entries\":[]}";
    fixture_create(&future_format, future_bytes, 0o600)?;
    let incompatible = verified.preview(&provenance).require_compatible();
    remove_exact_fixture(&future_format, &hex_sha256(future_bytes))?;
    require(
        incompatible.is_err(),
        "unsupported actual local format was accepted",
    )?;
    verified.preview(&provenance).require_compatible()?;
    let mut deny_gate = policy.task_gate.clone();
    deny_gate
        .effects_denied_for_untrusted_sources
        .insert(tirith_core::effects::CommandEffectKind::FilesystemWrite);
    let denied =
        prepare_self_authorization_with_policy::<tirith_core::task_boundary::SelfUpdateBoundary>(
            self_boundary_envelope(
                "signed-native-fixture-policy-refusal",
                serde_json::json!({"fixture_id": manifest.fixture_id}),
                Some(&destination),
            )?,
            update_effects(false, false),
            &deny_gate,
        );
    require(
        denied.is_err(),
        "real task policy failed to refuse filesystem effects",
    )?;
    revalidate(&guards, &inputs)?;
    old.revalidate()?;
    verify_exact_regular_preimage(&backup, None)?;
    let auth = authorization(
        &manifest,
        "extract-and-update",
        &destination,
        &old.digest,
        &manifest.candidate.identity.sha256,
        None,
        None,
    )?;
    // work/extracted is fresh and fixture-contained; tar is the fixed trusted production helper.
    let work = root.join("tmp/native-extraction");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&work)
        .map_err(io)?;
    let work_guard = DirectoryIdentity::capture(&work)?;
    let extracted = extract_tirith_binary(&archive_path, &manifest.target, &work, &auth)?;
    // The production extractor returned only after trusted_child reported a
    // successful Completed outcome. The outer runner cannot observe its PGID.
    println!("\nTIRITH_SIGNED_REPLACEMENT_EXTRACTOR_COMPLETED");
    let extracted_before = Input::capture(
        &extracted,
        256 * MIB,
        true,
        Some(&manifest.candidate.identity),
    )?;
    let saved_extracted = work.join("verified-extracted");
    verify_exact_regular_preimage(&saved_extracted, None)?;
    extracted_before.revalidate()?;
    std::fs::rename(&extracted, &saved_extracted).map_err(io)?;
    let changed_bytes = b"fixture changed extracted candidate";
    fixture_create(&extracted, changed_bytes, 0o755)?;
    let refused_changed = atomic_self_replace(
        &destination,
        &extracted,
        verified.binary_sha256(),
        &old.digest,
        None,
        &auth,
    );
    require(
        refused_changed.is_err(),
        "changed extracted candidate was accepted",
    )?;
    old.revalidate()?;
    verify_exact_regular_preimage(&backup, None)?;
    revalidate(&guards, &inputs)?;
    remove_exact_fixture(&extracted, &hex_sha256(changed_bytes))?;
    verify_exact_regular_preimage(&saved_extracted, Some(verified.binary_sha256()))?;
    std::fs::rename(&saved_extracted, &extracted).map_err(io)?;
    let extracted_input = Input::capture(
        &extracted,
        256 * MIB,
        true,
        Some(&manifest.candidate.identity),
    )?;
    require(
        atomic_self_replace(
            &destination,
            &extracted,
            verified.binary_sha256(),
            &"0".repeat(64),
            None,
            &auth,
        )
        .is_err(),
        "stale destination preimage was accepted",
    )?;
    old.revalidate()?;
    verify_exact_regular_preimage(&backup, None)?;
    revalidate(&guards, &inputs)?;
    let prior_backup = b"fixture preexisting rollback generation";
    fixture_create(&backup, prior_backup, 0o755)?;
    require(
        atomic_self_replace(
            &destination,
            &extracted,
            verified.binary_sha256(),
            &old.digest,
            None,
            &auth,
        )
        .is_err(),
        "unexpected backup was overwritten",
    )?;
    verify_exact_regular_preimage(&backup, Some(&hex_sha256(prior_backup)))?;
    old.revalidate()?;
    revalidate(&guards, &inputs)?;
    remove_exact_fixture(&backup, &hex_sha256(prior_backup))?;
    revalidate(&guards, &inputs)?;
    old.revalidate()?;
    extracted_input.revalidate()?;
    work_guard.revalidate()?;
    verify_exact_regular_preimage(&backup, None)?;
    release_compatibility::preserve_current_for_rollback(&provenance, &auth)?;
    let rollback = release_compatibility::VerifiedRollback::load(&destination, &old.digest)?;
    rollback.preview(&provenance).require_compatible()?;
    let swap = atomic_self_replace(
        &destination,
        &extracted,
        verified.binary_sha256(),
        &old.digest,
        None,
        &auth,
    )?;
    require(
        swap.previous_backup == backup,
        "replacement returned an unexpected backup path",
    )?;
    verify_exact_regular_preimage(&destination, Some(verified.binary_sha256()))?;
    verify_exact_regular_preimage(&backup, Some(&old.digest))?;
    revalidate(&guards, &inputs)?;
    // The still-running original inode is independent from the now-replaced pathname.
    require(
        hash_held(&old.file, old.cap)? == old.digest,
        "running original inode bytes changed",
    )?;
    let receipt_path =
        destination.with_file_name(format!("tirith.tirith-rollback-{}.json", old.digest));
    let receipt = Input::capture(&receipt_path, MAX_METADATA_SIZE, false, None)?;
    let receipt_bytes = receipt.bytes()?;
    let mut edited_receipt: serde_json::Value =
        serde_json::from_slice(&receipt_bytes).map_err(|_| "receipt JSON invalid")?;
    edited_receipt["document"]["version"] = serde_json::json!("0.4.1");
    let edited_receipt_bytes = serde_json::to_vec(&edited_receipt).map_err(|e| e.to_string())?;
    // Narrow explicit fixture mutation, only after native and exact-byte readback.
    replace_fixture_metadata(&receipt_path, &receipt.digest, &edited_receipt_bytes)?;
    let changed_receipt = rollback.revalidate(&destination, &old.digest);
    replace_fixture_metadata(
        &receipt_path,
        &hex_sha256(&edited_receipt_bytes),
        &receipt_bytes,
    )?;
    require(
        changed_receipt.is_err(),
        "edited rollback receipt was accepted after preview",
    )?;
    rollback.revalidate(&destination, &old.digest)?;
    verify_exact_regular_preimage(&destination, Some(verified.binary_sha256()))?;
    verify_exact_regular_preimage(&backup, Some(&old.digest))?;
    revalidate(&guards, &inputs)?;
    let rollback_auth = authorization(
        &manifest,
        "rollback",
        &destination,
        verified.binary_sha256(),
        &old.digest,
        Some(&old.digest),
        Some(rollback.receipt_sha256()),
    )?;
    let newer_source = work.join("newer-destination-source");
    let newer_bytes = b"fixture later destination; never executed";
    let newer_sha = hex_sha256(newer_bytes);
    fixture_create(&newer_source, newer_bytes, 0o755)?;
    let newer_auth = authorization(
        &manifest,
        "fixture-later-generation",
        &destination,
        verified.binary_sha256(),
        &newer_sha,
        Some(&old.digest),
        Some(rollback.receipt_sha256()),
    )?;
    atomic_restore_from(
        &destination,
        &newer_source,
        verified.binary_sha256(),
        &newer_sha,
        &newer_auth,
    )?;
    require(
        atomic_restore_from(
            &destination,
            &backup,
            verified.binary_sha256(),
            &old.digest,
            &rollback_auth,
        )
        .is_err(),
        "rollback accepted the later actual destination generation",
    )?;
    verify_exact_regular_preimage(&destination, Some(&newer_sha))?;
    verify_exact_regular_preimage(&backup, Some(&old.digest))?;
    revalidate(&guards, &inputs)?;
    let repair_auth = authorization(
        &manifest,
        "restore-only-fixture-mutation",
        &destination,
        &newer_sha,
        verified.binary_sha256(),
        Some(&old.digest),
        Some(rollback.receipt_sha256()),
    )?;
    atomic_restore_from(
        &destination,
        &root.join("inputs/candidate/tirith"),
        &newer_sha,
        verified.binary_sha256(),
        &repair_auth,
    )?;
    verify_exact_regular_preimage(&destination, Some(verified.binary_sha256()))?;
    verify_exact_regular_preimage(&backup, Some(&old.digest))?;
    revalidate(&guards, &inputs)?;
    rollback.preview(&provenance).require_compatible()?;
    rollback.revalidate(&destination, &old.digest)?;
    atomic_restore_from(
        &destination,
        &backup,
        verified.binary_sha256(),
        &old.digest,
        &rollback_auth,
    )?;
    verify_exact_regular_preimage(&destination, Some(&old.digest))?;
    verify_exact_regular_preimage(&backup, Some(&old.digest))?;
    revalidate(&guards, &inputs)?;
    require(
        hash_held(&old.file, old.cap)? == old.digest,
        "original retained image changed after rollback",
    )?;
    println!("\nTIRITH_SIGNED_REPLACEMENT_FIXTURE_V1_COMPLETE");
    Ok(())
}

fn semantic_signature_negatives(
    release: &ReleaseSet,
    document: &[u8],
    target: &str,
) -> Result<(), String> {
    use ed25519_dalek::Signer;
    // RFC8032 7.1 test1 seed is deliberately public and exists only in this cfg(test) module.
    let signer = ed25519_dalek::SigningKey::from_bytes(&[
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ]);
    let original: serde_json::Value =
        serde_json::from_slice(document).map_err(|_| "invalid fixture document")?;
    let archive = selfupdate::release_archive_name(target);
    let archive_sha = original["targets"][target]["archive_sha256"]
        .as_str()
        .ok_or("missing archive identity")?;
    for variation in [
        "wrong_key",
        "missing_target",
        "extra_target",
        "wrong_version",
        "archive_binding",
    ] {
        let mut changed = original.clone();
        match variation {
            "missing_target" => changed["targets"] = serde_json::json!({}),
            "extra_target" => {
                let extra = if target == "x86_64-unknown-linux-gnu" {
                    "aarch64-unknown-linux-gnu"
                } else {
                    "x86_64-unknown-linux-gnu"
                };
                let mut entry = original["targets"][target].clone();
                entry["archive"] = serde_json::json!(selfupdate::release_archive_name(extra));
                changed["targets"][extra] = entry;
            }
            "wrong_version" => changed["version"] = serde_json::json!("999.0.0"),
            "archive_binding" => {
                changed["targets"][target]["archive_sha256"] = serde_json::json!("0".repeat(64))
            }
            _ => {}
        }
        let bytes = serde_json::to_vec(&changed).map_err(|e| e.to_string())?;
        let altered = ReleaseSet {
            tag: release.tag.clone(),
            archive_path: release.archive_path.clone(),
            checksums_txt: format!(
                "{archive_sha}  {archive}\n{}  release-compatibility.json\n",
                hex_sha256(&bytes)
            ),
            checksums_path: release.checksums_path.clone(),
            sig_path: None,
            cert_path: None,
        };
        let wrong = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let signing = if variation == "wrong_key" {
            &wrong
        } else {
            &signer
        };
        let signature = signing.sign(altered.checksums_txt.as_bytes()).to_bytes();
        require(
            release_compatibility::VerifiedCandidate::verify_fixture_key(
                &altered, &bytes, target, &signature,
            )
            .is_err(),
            &format!("fixture semantic crypto negative was accepted: {variation}"),
        )?;
    }
    Ok(())
}

fn replace_fixture_metadata(path: &Path, old_sha: &str, bytes: &[u8]) -> Result<(), String> {
    require(
        bytes.len() as u64 <= MAX_METADATA_SIZE,
        "fixture metadata exceeds cap",
    )?;
    verify_exact_regular_preimage(path, Some(old_sha))?;
    let parent = path.parent().ok_or("fixture metadata parent missing")?;
    let mut staged = tempfile::NamedTempFile::new_in(parent).map_err(io)?;
    staged.write_all(bytes).map_err(io)?;
    staged.as_file().sync_all().map_err(io)?;
    verify_exact_regular_preimage(path, Some(old_sha))?;
    staged.persist(path).map_err(|e| e.error.to_string())?;
    Ok(())
}

#[test]
fn strict_ustar_refuses_extra_members_and_unbounded_expansion() {
    let payload = b"inert fixture bytes";
    let identity = Identity {
        sha256: hex_sha256(payload),
        size: payload.len() as u64,
    };
    let mut header = [0u8; 512];
    header[..7].copy_from_slice(b"tirith\0");
    header[100..108].copy_from_slice(b"0000755\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[136..148].copy_from_slice(b"00000000000\0");
    header[124..136].copy_from_slice(format!("{:011o}\0", payload.len()).as_bytes());
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[148..156].fill(b' ');
    let sum: u64 = header.iter().map(|v| u64::from(*v)).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let mut tar = header.to_vec();
    tar.extend_from_slice(payload);
    tar.resize(1024 + 1024, 0);
    assert!(single_ustar_member(&mut tar.as_slice(), &identity).is_ok());
    for index in [0, 100, 124, 148, 156, 157, 257, 345, 512, 1024] {
        let mut changed = tar.clone();
        changed[index] ^= 1;
        assert!(
            single_ustar_member(&mut changed.as_slice(), &identity).is_err(),
            "index {index}"
        );
    }
    let mut excessive = tar.clone();
    excessive.resize(excessive.len() + 11 * 1024, 0);
    assert!(single_ustar_member(&mut excessive.as_slice(), &identity).is_err());
    assert!(single_ustar_member(&mut &tar[..tar.len() - 1], &identity).is_err());
    use flate2::{write::GzEncoder, Compression};
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar).unwrap();
    let compressed = encoder.finish().unwrap();
    assert!(preflight_archive(&compressed, &hex_sha256(&compressed), &identity).is_ok());
    let mut concatenated = compressed.clone();
    concatenated.extend_from_slice(&compressed);
    assert!(preflight_archive(&concatenated, &hex_sha256(&concatenated), &identity).is_err());
}

#[test]
fn retained_fixture_inputs_refuse_links_overflow_and_same_bytes_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("input");
    fixture_create(&path, b"abc", 0o600).unwrap();
    let identity = Identity {
        sha256: hex_sha256(b"abc"),
        size: 3,
    };
    let input = Input::capture(&path, 3, false, Some(&identity)).unwrap();
    assert_eq!(input.bytes().unwrap(), b"abc");
    assert!(Input::capture(&path, 2, false, None).is_err());
    let alias = directory.path().join("alias");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(Input::capture(&alias, 3, false, Some(&identity)).is_err());
    let hard = directory.path().join("hard");
    std::fs::hard_link(&path, &hard).unwrap();
    assert!(Input::capture(&path, 3, false, Some(&identity)).is_err());
    std::fs::remove_file(&hard).unwrap();
    let before_replace = Input::capture(&path, 3, false, Some(&identity)).unwrap();
    replace_fixture_metadata(&path, &identity.sha256, b"abc").unwrap();
    assert!(before_replace.revalidate().is_err());
    assert_eq!(
        Input::capture(&path, 3, false, Some(&identity))
            .unwrap()
            .bytes()
            .unwrap(),
        b"abc"
    );
}
