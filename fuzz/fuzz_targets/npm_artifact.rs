#![no_main]
//! Fuzz exact local npm transport parsing with small, explicit work ceilings.
//! Seed with the real npm PAX fixture and deterministic generated tarballs.
use libfuzzer_sys::fuzz_target;
use tirith_core::artifact::npm_archive::{read_npm_tarball, NpmArchiveState, NpmLimits};

fuzz_target!(|data: &[u8]| {
    let limits = NpmLimits {
        compressed_bytes: 256 * 1024,
        decompressed_bytes: 1024 * 1024,
        member_bytes: 128 * 1024,
        headers: 128,
        total_path_bytes: 16 * 1024,
        pax_bytes: 8192,
        code_member_bytes: 64 * 1024,
        total_code_bytes: 128 * 1024,
        code_files: 16,
        native_files: 2,
        signals: 16,
        ..NpmLimits::default()
    };
    let result = read_npm_tarball(data, "fuzz.tgz", &limits);
    assert!(result.files.len() <= limits.headers);
    assert!(result.signals.len() <= limits.signals);
    assert!(result.coverage.issues.len() <= 256);
    assert!(result.coverage.inspected_code_files <= limits.code_files);
    assert!(result.coverage.inspected_code_bytes <= limits.total_code_bytes as u64);
    if result.archive_state == NpmArchiveState::Refused {
        assert!(!result.coverage.archive_complete);
        assert!(!result.coverage.static_analysis_complete);
        assert!(result.signals.is_empty());
    }
    if data.len() > limits.compressed_bytes {
        assert!(result.artifact.sha256.is_none());
    }
});
