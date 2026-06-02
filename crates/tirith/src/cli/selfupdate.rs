//! `tirith verify-self`, `tirith update`, and `tirith version --provenance`.
//!
//! Verify tirith's OWN integrity and update tirith itself. Network access only
//! on explicit invocation. Honesty is load-bearing: a `verify-self` that cannot
//! fully verify says so and never falsely reports "verified", and `update` never
//! self-modifies a package-manager-managed install.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tirith_core::selfupdate::{self, InstallMethod, Provenance, SemVer, VerificationStatus};

/// GitHub repository slug for tirith releases.
const REPO: &str = "sheeki03/tirith";
/// HTTP timeout for the small GitHub API metadata request.
const API_TIMEOUT_SECS: u64 = 20;
/// HTTP timeout for downloading a release archive / checksum file.
const DOWNLOAD_TIMEOUT_SECS: u64 = 120;
/// Hard cap on a downloaded release archive (binary + completions + man).
const MAX_ARCHIVE_SIZE: u64 = 64 * 1024 * 1024;
/// Hard cap on `checksums.txt` / signature / certificate files.
const MAX_METADATA_SIZE: u64 = 256 * 1024;
/// cosign keyless verification identity regexp — must match the workflow.
const COSIGN_IDENTITY_REGEXP: &str = "github.com/sheeki03/tirith";
/// cosign OIDC issuer — the GitHub Actions OIDC provider.
const COSIGN_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Gather the running binary's provenance without any network access.
pub fn gather_provenance() -> Provenance {
    let raw_exe = std::env::current_exe().ok();
    // Resolve through symlinks / npm wrapper / Scoop shim so the install-method
    // classifier sees the real on-disk binary.
    let resolved = raw_exe
        .as_deref()
        .and_then(crate::cli::resolve_effective_tirith_target);
    // Fall back to the unresolved `current_exe()` path when resolution failed;
    // record it so consumers lower confidence (an unresolved symlink/wrapper
    // could misdetect the install method, including toward `SelfManaged`).
    let path_resolution_failed = resolved.is_none() && raw_exe.is_some();
    let binary_path = resolved.or(raw_exe);

    let binary_sha256 = binary_path.as_deref().and_then(hash_file_opt);

    let install_method = match &binary_path {
        Some(p) => {
            let m = selfupdate::detect_install_method(p);
            selfupdate::refine_system_pm(m, &read_os_release_ids())
        }
        None => InstallMethod::Unknown,
    };

    let dev_build =
        selfupdate::looks_like_dev_build(binary_path.as_deref(), cfg!(debug_assertions));

    Provenance {
        version: env!("CARGO_PKG_VERSION").to_string(),
        binary_path,
        binary_sha256,
        target: selfupdate::release_target_triple().map(|s| s.to_string()),
        install_method,
        dev_build,
        path_resolution_failed,
    }
}

/// `tirith version --provenance`. Prints version, build info, install method,
/// and a verification status. With `provenance == false` it prints just the
/// version line (the plain `tirith version` behavior).
pub fn version(provenance: bool, json: bool) -> i32 {
    if !provenance {
        if json {
            let v = serde_json::json!({ "version": env!("CARGO_PKG_VERSION") });
            println!("{v}");
        } else {
            println!("tirith {}", env!("CARGO_PKG_VERSION"));
        }
        return 0;
    }

    let prov = gather_provenance();
    // Offline: reports local facts and a local-only verdict. Full networked
    // verification is `verify-self`.
    let local_status = local_verification_status(&prov);

    if json {
        let v = serde_json::json!({
            "version": prov.version,
            "binary_path": prov.binary_path.as_ref().map(|p| p.display().to_string()),
            "binary_sha256": prov.binary_sha256,
            "target": prov.target,
            "install_method": prov.install_method.as_str(),
            "install_method_resolved": !prov.path_resolution_failed,
            "dev_build": prov.dev_build,
            "build_profile": if cfg!(debug_assertions) { "debug" } else { "release" },
            "verification_status": local_status.token(),
            "verification_detail": status_detail(&local_status),
        });
        match serde_json::to_string_pretty(&v) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("tirith: JSON serialization failed: {e}");
                return 1;
            }
        }
    } else {
        println!("tirith {}", prov.version);
        println!(
            "  build profile:   {}",
            if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            }
        );
        println!(
            "  target:          {}",
            prov.target.as_deref().unwrap_or("(unpublished platform)")
        );
        println!(
            "  binary:          {}",
            prov.binary_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        );
        if let Some(sha) = &prov.binary_sha256 {
            println!("  sha256:          {sha}");
        }
        println!("  install method:  {}", prov.install_method.as_str());
        if prov.path_resolution_failed {
            println!(
                "  note:            the binary path could not be fully resolved; the install \
                 method above is a lower-confidence guess"
            );
        }
        println!("  verification:    {}", describe_status(&local_status));
        if prov.dev_build {
            println!(
                "  note:            this is a local/dev build — run `tirith verify-self` \
                 against a release to verify provenance"
            );
        } else {
            println!("  note:            run `tirith verify-self` for full networked provenance verification");
        }
    }
    0
}

/// Read lowercased `ID`/`ID_LIKE` tokens from `/etc/os-release` for apt-vs-dnf
/// disambiguation. Empty vec on non-Linux or absent/unreadable file (caller then
/// leaves the method `Unknown`).
fn read_os_release_ids() -> Vec<String> {
    if !cfg!(target_os = "linux") {
        return Vec::new();
    }
    let contents = match std::fs::read_to_string("/etc/os-release") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut ids = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        let (key, value) = match line.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        if key != "ID" && key != "ID_LIKE" {
            continue;
        }
        // Values may be quoted; ID_LIKE is a space-separated list.
        let value = value.trim().trim_matches(['"', '\'']);
        for tok in value.split_whitespace() {
            let tok = tok.to_lowercase();
            if !tok.is_empty() && !ids.contains(&tok) {
                ids.push(tok);
            }
        }
    }
    ids
}

/// The verification verdict obtainable WITHOUT network access: structural facts
/// only. Full verification of an installed release requires `verify-self`.
fn local_verification_status(prov: &Provenance) -> VerificationStatus {
    if prov.dev_build {
        return VerificationStatus::Unverified {
            reason: "local/dev build — not an installed release, cannot verify against a \
                     release checksum"
                .to_string(),
        };
    }
    if prov.target.is_none() {
        return VerificationStatus::Unverified {
            reason: "this platform has no published tirith release artifact".to_string(),
        };
    }
    if SemVer::parse(&prov.version).is_none() {
        return VerificationStatus::Unverified {
            reason: format!(
                "version `{}` is not a parseable release version",
                prov.version
            ),
        };
    }
    VerificationStatus::Unverified {
        reason: "offline check — run `tirith verify-self` to verify against the signed release"
            .to_string(),
    }
}

// ===========================================================================
// verify-self
// ===========================================================================

/// Outcome of `run_verify_self`: verification status plus whether the run hit an
/// *operational* error (a local failure that prevented verification, e.g. tirith
/// could not read its own bytes). An operational error is distinct from an honest
/// [`VerificationStatus::Unverified`] (offline / dev build / unpublished
/// platform): the latter is a benign "cannot verify"; the former must exit
/// non-zero so a scripted `verify-self && deploy` does not proceed.
struct VerifySelfOutcome {
    status: VerificationStatus,
    operational_error: bool,
    /// Precise `verification_detail` to report instead of the generic
    /// [`status_detail`] — surfaces *why* the cosign signature was not checked
    /// (absent vs present-but-broken) on a checksum-only verification.
    detail_override: Option<String>,
}

impl VerifySelfOutcome {
    /// An honest verification verdict (no operational error).
    fn verdict(status: VerificationStatus) -> Self {
        VerifySelfOutcome {
            status,
            operational_error: false,
            detail_override: None,
        }
    }

    /// An operational error: surfaced as `Unverified` but flagged so
    /// `verify-self` exits non-zero.
    fn operational(reason: String) -> Self {
        VerifySelfOutcome {
            status: VerificationStatus::Unverified { reason },
            operational_error: true,
            detail_override: None,
        }
    }

    /// Attach a precise `verification_detail` override to this outcome.
    fn with_detail(mut self, detail: Option<String>) -> Self {
        self.detail_override = detail;
        self
    }
}

/// `tirith verify-self`. Verify the running binary against its release checksum
/// and signature where possible. Exit `0` on success OR an honest "unverified"
/// (dev build, offline, unpublished platform); `1` on a FAILED verification
/// (mismatch / bad signature), an operational error, or a JSON serialize failure.
pub fn verify_self(json: bool) -> i32 {
    let prov = gather_provenance();
    let outcome = run_verify_self(&prov);
    let emit_rc = emit_verify_self(
        &prov,
        &outcome.status,
        outcome.detail_override.as_deref(),
        json,
    );
    let verdict_rc = match outcome.status {
        VerificationStatus::Failed { .. } => 1,
        // An operational error must fail the command (it is not a benign
        // "cannot verify") so `verify-self && deploy` does not proceed.
        _ if outcome.operational_error => 1,
        _ => 0,
    };
    verdict_rc.max(emit_rc)
}

/// Core of `verify-self`: the networked verification, kept separate so the
/// emit/exit logic is trivially correct.
fn run_verify_self(prov: &Provenance) -> VerifySelfOutcome {
    // 1. A dev build can never be matched against a release.
    if prov.dev_build {
        return VerifySelfOutcome::verdict(VerificationStatus::Unverified {
            reason: "this is a local/dev build (compiled from source, not installed from a \
                     release) — there is no release checksum to verify it against"
                .to_string(),
        });
    }

    // 2. Need a published target and parseable version — both honest "cannot
    //    verify" conditions, not operational errors.
    let target = match &prov.target {
        Some(t) => t.clone(),
        None => {
            return VerifySelfOutcome::verdict(VerificationStatus::Unverified {
                reason: "this platform has no published tirith release artifact to verify \
                         against"
                    .to_string(),
            })
        }
    };
    let version = match SemVer::parse(&prov.version) {
        Some(v) => v,
        None => {
            return VerifySelfOutcome::verdict(VerificationStatus::Unverified {
                reason: format!(
                    "running version `{}` is not a parseable release version",
                    prov.version
                ),
            })
        }
    };

    // 3. Need the running binary's own bytes. Failure here is an OPERATIONAL
    //    error (path known but unreadable/replaced), not a benign "cannot
    //    verify" — `verify-self` must exit non-zero.
    let (binary_path, binary_sha) = match (&prov.binary_path, &prov.binary_sha256) {
        (Some(p), Some(s)) => (p.clone(), s.clone()),
        (Some(p), None) => {
            return VerifySelfOutcome::operational(format!(
                "could not read the running binary's own bytes at {} (I/O or permission error, \
                 or the binary was replaced) — cannot verify",
                p.display()
            ))
        }
        (None, _) => {
            return VerifySelfOutcome::operational(
                "could not determine the running binary's own path — cannot verify".to_string(),
            )
        }
    };

    // 4. Download the release archive + checksums for this exact version.
    let tag = format!("v{version}");
    let archive_name = selfupdate::release_archive_name(&target);
    let workdir = match tempfile::Builder::new().prefix("tirith-verify-").tempdir() {
        Ok(d) => d,
        Err(e) => {
            // Could not create a temp dir: operational error — verification
            // could not even start.
            return VerifySelfOutcome::operational(format!(
                "could not create a working directory: {e}"
            ));
        }
    };

    let release = match download_release_set(&tag, &archive_name, workdir.path()) {
        Ok(r) => r,
        Err(DownloadError::Offline(msg)) => {
            return VerifySelfOutcome::verdict(VerificationStatus::Unverified {
                reason: format!("could not reach the release server ({msg}) — re-run online"),
            })
        }
        Err(DownloadError::NotFound(msg)) => {
            return VerifySelfOutcome::verdict(VerificationStatus::Unverified {
                reason: format!(
                    "no release artifact found for {tag} ({msg}) — this binary may predate \
                     the release-checksum scheme, or be a custom build"
                ),
            })
        }
        Err(DownloadError::Other(msg)) => {
            return VerifySelfOutcome::verdict(VerificationStatus::Failed {
                reason: format!("release download failed: {msg}"),
            })
        }
    };

    // 5. Verify the archive bytes against the (possibly signed) checksums.
    let verdict = verify_archive_against_checksums(&release, &archive_name);
    let (checksum_status, cosign_note) = match verdict {
        ArchiveVerdict::Ok {
            signed,
            cosign_note,
        } => (signed, cosign_note),
        ArchiveVerdict::Failed(reason) => {
            return VerifySelfOutcome::verdict(VerificationStatus::Failed { reason })
        }
        ArchiveVerdict::ChecksumMissing(reason) => {
            return VerifySelfOutcome::verdict(VerificationStatus::Unverified { reason })
        }
    };

    // 6. Extract the binary from the verified archive and compare it
    //    byte-for-byte to the running binary — ties the archive checksum to the
    //    actual file on disk.
    let extracted = match extract_tirith_binary(&release.archive_path, &target, workdir.path()) {
        Ok(p) => p,
        Err(e) => {
            return VerifySelfOutcome::verdict(VerificationStatus::Failed {
                reason: format!(
                    "could not extract the tirith binary from the verified release archive: {e}"
                ),
            })
        }
    };
    let extracted_sha = match hash_file_opt(&extracted) {
        Some(s) => s,
        None => {
            return VerifySelfOutcome::verdict(VerificationStatus::Failed {
                reason: "could not hash the binary extracted from the release archive".to_string(),
            })
        }
    };

    if !selfupdate::digest_eq(&extracted_sha, &binary_sha) {
        return VerifySelfOutcome::verdict(VerificationStatus::Failed {
            reason: format!(
                "the running binary at {} (sha256 {}) does NOT match the official {} release \
                 binary (sha256 {}) — it has been modified or replaced",
                binary_path.display(),
                short(&binary_sha),
                tag,
                short(&extracted_sha),
            ),
        });
    }

    // Running binary == official release binary. Verdict strength is whatever
    // the archive-vs-checksums step achieved; for a checksum-only result, carry
    // the cosign note (absent vs broken) into the detail.
    match checksum_status {
        ChecksumStrength::Signed => VerifySelfOutcome::verdict(VerificationStatus::VerifiedSigned),
        ChecksumStrength::ChecksumOnly => {
            VerifySelfOutcome::verdict(VerificationStatus::VerifiedChecksumOnly)
                .with_detail(cosign_note)
        }
    }
}

/// Print the `verify-self` result. Returns `1` only when JSON was requested but
/// could not be serialized (so a JSON consumer never gets empty stdout + exit 0);
/// `0` otherwise (the verdict-based exit code is the caller's). `detail_override`,
/// when `Some`, is a more precise `verification_detail` than [`status_detail`].
fn emit_verify_self(
    prov: &Provenance,
    status: &VerificationStatus,
    detail_override: Option<&str>,
    json: bool,
) -> i32 {
    let detail = detail_override.map_or_else(|| status_detail(status), |d| d.to_string());
    if json {
        let v = serde_json::json!({
            "version": prov.version,
            "binary_path": prov.binary_path.as_ref().map(|p| p.display().to_string()),
            "binary_sha256": prov.binary_sha256,
            "install_method": prov.install_method.as_str(),
            "install_method_resolved": !prov.path_resolution_failed,
            "target": prov.target,
            "dev_build": prov.dev_build,
            "verification_status": status.token(),
            "verification_detail": detail,
            "integrity_ok": status.is_integrity_ok(),
        });
        match serde_json::to_string_pretty(&v) {
            Ok(s) => {
                println!("{s}");
                return 0;
            }
            Err(e) => {
                eprintln!("tirith: JSON serialization failed: {e}");
                return 1;
            }
        }
    }

    println!("tirith verify-self");
    println!("  version:        {}", prov.version);
    println!(
        "  binary:         {}",
        prov.binary_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!("  install method: {}", prov.install_method.as_str());
    if prov.path_resolution_failed {
        println!(
            "  note:           the binary path could not be fully resolved; the install method \
             above is a lower-confidence guess"
        );
    }
    println!();
    match status {
        VerificationStatus::VerifiedSigned => {
            println!("  VERIFIED (signed)");
            println!(
                "  The running binary matches the official signed release: its SHA-256 is in \
                 the release checksums.txt and the cosign signature over checksums.txt verified."
            );
        }
        VerificationStatus::VerifiedChecksumOnly => {
            println!("  VERIFIED (checksum only)");
            println!(
                "  The running binary matches the SHA-256 published in the release \
                 checksums.txt."
            );
            // Report *why* the signature went unchecked, preferring the precise
            // detail when present.
            if detail_override.is_some() {
                println!("  The cosign signature was NOT checked: {detail}");
            } else {
                println!(
                    "  The cosign signature was NOT checked (cosign is not installed). Install \
                     cosign and re-run for full signature verification."
                );
            }
        }
        VerificationStatus::Unverified { reason } => {
            println!("  UNVERIFIED (could not verify — this is not a failure)");
            println!("  {reason}");
        }
        VerificationStatus::Failed { reason } => {
            println!("  FAILED — the running binary did NOT verify");
            println!("  {reason}");
            println!();
            println!(
                "  Do not trust this binary. Re-install tirith from a trusted source \
                 (https://github.com/{REPO})."
            );
        }
    }
    // Human output never fails to "serialize".
    0
}

/// `tirith update`. Update tirith to the latest release, package-manager-aware.
///
/// * `verify` — verify the new release's provenance before installing.
/// * `rollback` — revert to the previously-installed version (self-managed
///   installs only).
/// * `dry_run` — show what would happen, change nothing.
///
/// Exit `0` on success or a clean no-op, `1` on any failure.
pub fn update(verify: bool, rollback: bool, dry_run: bool, yes: bool, json: bool) -> i32 {
    let prov = gather_provenance();

    if rollback {
        return run_rollback(&prov, dry_run, yes, json);
    }

    run_update(&prov, verify, dry_run, yes, json)
}

fn run_update(prov: &Provenance, verify: bool, dry_run: bool, yes: bool, json: bool) -> i32 {
    // Package-manager (and unknown) installs: never self-modify. Advise.
    if !prov.install_method.is_self_replaceable() {
        return advise_package_manager(prov, json);
    }

    // Self-managed install: tirith owns the binary and may replace it.
    let current = match SemVer::parse(&prov.version) {
        Some(v) => v,
        None => {
            emit_update_error(
                json,
                &format!(
                    "running version `{}` is not a parseable release version; cannot \
                     determine whether an update is needed",
                    prov.version
                ),
            );
            return 1;
        }
    };
    let target = match &prov.target {
        Some(t) => t.clone(),
        None => {
            emit_update_error(
                json,
                "this platform has no published tirith release artifact to update from",
            );
            return 1;
        }
    };
    let binary_path = match &prov.binary_path {
        Some(p) => p.clone(),
        None => {
            emit_update_error(json, "could not resolve the running binary's path");
            return 1;
        }
    };

    // 1. Find the latest release version via the GitHub API.
    let latest = match fetch_latest_version() {
        Ok(v) => v,
        Err(DownloadError::Offline(msg)) => {
            emit_update_error(
                json,
                &format!("could not reach the release server ({msg}) — re-run online"),
            );
            return 1;
        }
        Err(e) => {
            emit_update_error(
                json,
                &format!("could not determine the latest release: {e}"),
            );
            return 1;
        }
    };

    if latest <= current {
        if json {
            let v = serde_json::json!({
                "action": "none",
                "current_version": current.to_string(),
                "latest_version": latest.to_string(),
                "message": "already up to date",
            });
            println!("{v}");
        } else {
            println!("tirith is already up to date (v{current}; latest release is v{latest}).");
        }
        return 0;
    }

    if dry_run {
        if json {
            let v = serde_json::json!({
                "action": "would-update",
                "current_version": current.to_string(),
                "latest_version": latest.to_string(),
                "install_method": prov.install_method.as_str(),
                "binary_path": binary_path.display().to_string(),
                "verify": verify,
            });
            println!("{v}");
        } else {
            println!("tirith update (dry run)");
            println!("  current:  v{current}");
            println!("  latest:   v{latest}");
            println!("  binary:   {}", binary_path.display());
            println!(
                "  would download, {}verify, and atomically replace the binary in place.",
                if verify { "" } else { "optionally " }
            );
        }
        return 0;
    }

    if !crate::cli::confirm(&format!("Update tirith from v{current} to v{latest}?"), yes) {
        eprintln!("tirith: update cancelled");
        return 0;
    }

    // 2. Download the latest release archive + checksums.
    let tag = format!("v{latest}");
    let archive_name = selfupdate::release_archive_name(&target);
    let workdir = match tempfile::Builder::new().prefix("tirith-update-").tempdir() {
        Ok(d) => d,
        Err(e) => {
            emit_update_error(json, &format!("could not create a working directory: {e}"));
            return 1;
        }
    };

    println!("tirith: downloading {tag} for {target}...");
    let release = match download_release_set(&tag, &archive_name, workdir.path()) {
        Ok(r) => r,
        Err(e) => {
            emit_update_error(json, &format!("download failed: {}", e.message()));
            return 1;
        }
    };

    // 3. Verify the downloaded release. `--verify` makes verification
    //    MANDATORY; without it we still refuse on a hard FAILED (checksum
    //    mismatch) but tolerate an honest "unverified" (e.g. cosign missing).
    let archive_verdict = verify_archive_against_checksums(&release, &archive_name);
    match &archive_verdict {
        ArchiveVerdict::Failed(reason) => {
            emit_update_error(
                json,
                &format!("release verification FAILED — aborting update: {reason}"),
            );
            return 1;
        }
        ArchiveVerdict::ChecksumMissing(reason) => {
            // No checksum entry: refuse either way — installing an unverifiable
            // binary over a working one is unacceptable for a security tool.
            emit_update_error(
                json,
                &format!(
                    "release checksum could not be verified ({reason}) — aborting update; \
                     install manually from https://github.com/{REPO}/releases if intended"
                ),
            );
            return 1;
        }
        ArchiveVerdict::Ok { signed, .. } => {
            if verify && *signed == ChecksumStrength::ChecksumOnly {
                emit_update_error(
                    json,
                    "--verify was requested but the cosign signature could not be verified \
                     (either cosign is not installed, or this release did not publish a \
                     signature). The release checksum DID verify. Install cosign and re-run, \
                     or drop --verify to proceed with checksum-only verification.",
                );
                return 1;
            }
        }
    }

    // 4. Extract the new binary from the verified archive.
    let new_binary = match extract_tirith_binary(&release.archive_path, &target, workdir.path()) {
        Ok(p) => p,
        Err(e) => {
            emit_update_error(
                json,
                &format!("could not extract the tirith binary from the release archive: {e}"),
            );
            return 1;
        }
    };

    // 5. Atomic swap, keeping the previous binary for rollback.
    let swap = match atomic_self_replace(&binary_path, &new_binary) {
        Ok(s) => s,
        Err(e) => {
            emit_update_error(json, &format!("could not install the new binary: {e}"));
            return 1;
        }
    };

    if json {
        let v = serde_json::json!({
            "action": "updated",
            "previous_version": current.to_string(),
            "new_version": latest.to_string(),
            "binary_path": binary_path.display().to_string(),
            "previous_binary_kept_at": swap.previous_backup.display().to_string(),
            "verification": match &archive_verdict {
                ArchiveVerdict::Ok { signed: ChecksumStrength::Signed, .. } => "verified-signed",
                ArchiveVerdict::Ok { signed: ChecksumStrength::ChecksumOnly, .. } => {
                    "verified-checksum-only"
                }
                _ => "unverified",
            },
        });
        println!("{v}");
    } else {
        println!();
        println!("tirith updated: v{current} -> v{latest}");
        println!("  binary:        {}", binary_path.display());
        println!(
            "  verification:  {}",
            match &archive_verdict {
                ArchiveVerdict::Ok {
                    signed: ChecksumStrength::Signed,
                    ..
                } => "signed release (checksum + cosign signature)",
                ArchiveVerdict::Ok {
                    signed: ChecksumStrength::ChecksumOnly,
                    ..
                } => "checksum-verified (cosign not installed — signature unchecked)",
                _ => "unverified",
            }
        );
        println!(
            "  previous:      kept at {} — run `tirith update --rollback` to revert",
            swap.previous_backup.display()
        );
    }
    0
}

/// Print the package-manager upgrade command for a PM-managed install and
/// explain tirith will not self-modify it. Exit `0` — the intended outcome.
fn advise_package_manager(prov: &Provenance, json: bool) -> i32 {
    let method = &prov.install_method;
    let cmd = method.upgrade_command();

    if json {
        let v = serde_json::json!({
            "action": "use-package-manager",
            "install_method": method.as_str(),
            "current_version": prov.version,
            "upgrade_command": cmd,
            "message": match method {
                InstallMethod::Unknown => "tirith could not determine how it was installed; \
                    it will not self-modify the binary. Update it the same way you installed it.",
                _ => "tirith was installed by a package manager; update it with the package \
                    manager so its database stays consistent.",
            },
        });
        match serde_json::to_string_pretty(&v) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("tirith: JSON serialization failed: {e}");
                return 1;
            }
        }
        return 0;
    }

    match method {
        InstallMethod::Unknown => {
            println!(
                "tirith could not determine how it was installed (binary: {}).",
                prov.binary_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            );
            println!(
                "It will NOT self-modify the binary. Update tirith the same way you installed \
                 it, or re-install from https://github.com/{REPO}."
            );
        }
        _ => {
            println!(
                "tirith was installed via {} — it will not self-modify a package-managed \
                 install.",
                method.as_str()
            );
            if let Some(c) = cmd {
                println!();
                println!("To update, run:");
                println!("  {c}");
            }
        }
    }
    0
}

/// `tirith update --rollback`. Restore the previous binary saved by the last
/// self-managed update. Only valid for a self-managed install.
fn run_rollback(prov: &Provenance, dry_run: bool, yes: bool, json: bool) -> i32 {
    if !prov.install_method.is_self_replaceable() {
        let msg = format!(
            "--rollback only applies to a self-managed (install.sh / standalone) install; \
             this is a `{}` install. Use the package manager to install a previous version.",
            prov.install_method.as_str()
        );
        if json {
            let v = serde_json::json!({
                "action": "rollback-unavailable",
                "install_method": prov.install_method.as_str(),
                "message": msg,
            });
            println!("{v}");
        } else {
            println!("tirith: {msg}");
        }
        return 1;
    }

    let binary_path = match &prov.binary_path {
        Some(p) => p.clone(),
        None => {
            emit_update_error(json, "could not resolve the running binary's path");
            return 1;
        }
    };
    let backup = previous_backup_path(&binary_path);
    if !backup.is_file() {
        let msg = format!(
            "no previous binary to roll back to (expected {}). A rollback point is only \
             created by `tirith update`.",
            backup.display()
        );
        if json {
            let v = serde_json::json!({
                "action": "rollback-unavailable",
                "message": msg,
            });
            println!("{v}");
        } else {
            println!("tirith: {msg}");
        }
        return 1;
    }

    if dry_run {
        if json {
            let v = serde_json::json!({
                "action": "would-rollback",
                "binary_path": binary_path.display().to_string(),
                "rollback_from": backup.display().to_string(),
            });
            println!("{v}");
        } else {
            println!("tirith update --rollback (dry run)");
            println!(
                "  would restore {} from {}",
                binary_path.display(),
                backup.display()
            );
        }
        return 0;
    }

    if !crate::cli::confirm("Roll tirith back to the previously-installed binary?", yes) {
        eprintln!("tirith: rollback cancelled");
        return 0;
    }

    // Restore via `atomic_restore_from`, NOT `atomic_self_replace`: the latter
    // would first copy the live binary onto `previous_backup_path(dest)` (the
    // same path as `backup`), clobbering the rollback source before the swap.
    // `atomic_restore_from` reads the source up front and never writes to it.
    match atomic_restore_from(&binary_path, &backup) {
        Ok(()) => {
            // Remove the now-stale backup (no longer "the previous version").
            // A leftover `.tirith-previous` identical to the live binary would
            // make a later `--rollback` a confusing no-op — so warn if removal
            // fails.
            if let Err(e) = std::fs::remove_file(&backup) {
                eprintln!(
                    "tirith: warning: rolled back successfully but could not remove the now-stale \
                     backup {} ({e}); delete it manually — a future `--rollback` would otherwise \
                     restore these same (no-longer-previous) bytes",
                    backup.display()
                );
            }
            if json {
                let v = serde_json::json!({
                    "action": "rolled-back",
                    "binary_path": binary_path.display().to_string(),
                });
                println!("{v}");
            } else {
                println!("tirith: rolled back to the previously-installed binary.");
                println!("  binary: {}", binary_path.display());
                println!("  run `tirith version` to confirm the version.");
            }
            0
        }
        Err(e) => {
            emit_update_error(json, &format!("rollback failed: {e}"));
            1
        }
    }
}

fn emit_update_error(json: bool, msg: &str) {
    if json {
        let v = serde_json::json!({ "action": "error", "error": msg });
        println!("{v}");
    } else {
        eprintln!("tirith: {msg}");
    }
}

/// A downloaded release artifact set, all in a working directory.
struct ReleaseSet {
    archive_path: PathBuf,
    /// Raw `checksums.txt` content (the signed-over payload).
    checksums_txt: String,
    /// cosign signature over `checksums.txt`, if the release published one.
    sig_path: Option<PathBuf>,
    /// cosign certificate, if the release published one.
    cert_path: Option<PathBuf>,
    /// On-disk path of the saved `checksums.txt` (cosign needs the file).
    checksums_path: PathBuf,
}

/// Why a download could not be completed. `Offline`/`NotFound` are honest
/// non-failures for `verify-self`; `Other` is an operational error.
enum DownloadError {
    Offline(String),
    NotFound(String),
    Other(String),
}

impl DownloadError {
    fn message(&self) -> String {
        match self {
            DownloadError::Offline(m) => format!("offline: {m}"),
            DownloadError::NotFound(m) => format!("not found: {m}"),
            DownloadError::Other(m) => m.clone(),
        }
    }
}

impl std::fmt::Display for DownloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

/// Download the archive, `checksums.txt`, and (best-effort) the cosign
/// signature + certificate for a given release tag.
fn download_release_set(
    tag: &str,
    archive_name: &str,
    workdir: &Path,
) -> Result<ReleaseSet, DownloadError> {
    let base = format!("https://github.com/{REPO}/releases/download/{tag}");

    let client = http_client(DOWNLOAD_TIMEOUT_SECS)
        .map_err(|e| DownloadError::Other(format!("HTTP client: {e}")))?;

    // The archive and checksums.txt are required; the cosign sig/cert are
    // optional (an older release may lack them — an honest "checksum-only").
    let archive_url = format!("{base}/{archive_name}");
    let archive_bytes = fetch_bytes(&client, &archive_url, MAX_ARCHIVE_SIZE)?;
    let archive_path = workdir.join(archive_name);
    write_file(&archive_path, &archive_bytes)
        .map_err(|e| DownloadError::Other(format!("write archive: {e}")))?;

    let checksums_url = format!("{base}/checksums.txt");
    let checksums_bytes = fetch_bytes(&client, &checksums_url, MAX_METADATA_SIZE)?;
    let checksums_txt = String::from_utf8(checksums_bytes.clone())
        .map_err(|_| DownloadError::Other("checksums.txt is not valid UTF-8".to_string()))?;
    let checksums_path = workdir.join("checksums.txt");
    write_file(&checksums_path, &checksums_bytes)
        .map_err(|e| DownloadError::Other(format!("write checksums.txt: {e}")))?;

    let sig_path = fetch_optional(
        &client,
        &format!("{base}/checksums.txt.sig"),
        workdir,
        "checksums.txt.sig",
    );
    let cert_path = fetch_optional(
        &client,
        &format!("{base}/checksums.txt.pem"),
        workdir,
        "checksums.txt.pem",
    );

    Ok(ReleaseSet {
        archive_path,
        checksums_txt,
        sig_path,
        cert_path,
        checksums_path,
    })
}

/// Resolve the latest published release version through the GitHub API.
fn fetch_latest_version() -> Result<SemVer, DownloadError> {
    let client = http_client(API_TIMEOUT_SECS)
        .map_err(|e| DownloadError::Other(format!("HTTP client: {e}")))?;
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let body = fetch_bytes(&client, &url, MAX_METADATA_SIZE)?;
    let json: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| DownloadError::Other(format!("GitHub API response was not JSON: {e}")))?;
    let tag = json
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DownloadError::Other("GitHub API response had no tag_name".to_string()))?;
    SemVer::parse(tag).ok_or_else(|| {
        DownloadError::Other(format!(
            "latest release tag `{tag}` is not a parseable version"
        ))
    })
}

/// Build a blocking reqwest client with a timeout and a tirith User-Agent
/// (GitHub requires a User-Agent on API requests).
fn http_client(timeout_secs: u64) -> Result<reqwest::blocking::Client, reqwest::Error> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
}

/// GET `url` and return the body, capped at `max`. Maps connection errors to
/// `Offline`, 404 to `NotFound`, and everything else to `Other`.
fn fetch_bytes(
    client: &reqwest::blocking::Client,
    url: &str,
    max: u64,
) -> Result<Vec<u8>, DownloadError> {
    let resp = client
        .get(url)
        .header(
            "User-Agent",
            format!("tirith/{} (self-update)", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .map_err(|e| {
            // Connect/timeout → offline; anything else → operational.
            if e.is_connect() || e.is_timeout() {
                DownloadError::Offline(e.to_string())
            } else {
                DownloadError::Other(e.to_string())
            }
        })?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(DownloadError::NotFound(format!("{url} returned 404")));
    }
    if !status.is_success() {
        return Err(DownloadError::Other(format!(
            "{url} returned HTTP {status}"
        )));
    }

    // Fast-reject via Content-Length before reading.
    if let Some(len) = resp.content_length() {
        if len > max {
            return Err(DownloadError::Other(format!(
                "{url} body is {len} bytes (max {max})"
            )));
        }
    }

    use std::io::Read as _;
    let mut buf = Vec::new();
    resp.take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|e| DownloadError::Other(format!("reading {url}: {e}")))?;
    if buf.len() as u64 > max {
        return Err(DownloadError::Other(format!(
            "{url} body exceeds the {max}-byte limit"
        )));
    }
    Ok(buf)
}

/// Best-effort fetch of an optional release asset (the cosign sig / cert).
/// Returns `None` on any error — the caller treats absence as "no signature".
fn fetch_optional(
    client: &reqwest::blocking::Client,
    url: &str,
    workdir: &Path,
    name: &str,
) -> Option<PathBuf> {
    let bytes = fetch_bytes(client, url, MAX_METADATA_SIZE).ok()?;
    let path = workdir.join(name);
    write_file(&path, &bytes).ok()?;
    Some(path)
}

/// Strength of a successful archive verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChecksumStrength {
    /// Checksum matched AND the cosign signature verified.
    Signed,
    /// Checksum matched; signature not checked (cosign absent).
    ChecksumOnly,
}

/// Outcome of verifying a downloaded archive against its checksums file.
enum ArchiveVerdict {
    /// The archive's SHA-256 matched the entry in `checksums.txt`.
    Ok {
        signed: ChecksumStrength,
        /// Why the signature was NOT checked (`None` when fully signed). For
        /// `ChecksumOnly` this distinguishes "cosign not installed" from
        /// "cosign present but unrunnable" — lost by an `eprintln!` under JSON.
        cosign_note: Option<String>,
    },
    /// Verification was attempted and FAILED (mismatch / bad signature).
    Failed(String),
    /// `checksums.txt` had no entry for this archive — cannot verify.
    ChecksumMissing(String),
}

/// Verify a downloaded `ReleaseSet`'s archive against `checksums.txt`, then —
/// if `cosign` is available and the release shipped a signature — verify the
/// cosign signature over `checksums.txt`.
fn verify_archive_against_checksums(release: &ReleaseSet, archive_name: &str) -> ArchiveVerdict {
    // 1. Archive bytes vs the digest in checksums.txt.
    let archive_bytes = match std::fs::read(&release.archive_path) {
        Ok(b) => b,
        Err(e) => {
            return ArchiveVerdict::Failed(format!("could not re-read the downloaded archive: {e}"))
        }
    };
    let archive_sha = hex_sha256(&archive_bytes);

    let expected = match selfupdate::checksum_for(&release.checksums_txt, archive_name) {
        Ok(Some(d)) => d,
        Ok(None) => {
            return ArchiveVerdict::ChecksumMissing(format!(
                "checksums.txt has no entry for {archive_name}"
            ))
        }
        Err(e) => return ArchiveVerdict::Failed(format!("checksums.txt is malformed: {e}")),
    };

    if !selfupdate::digest_eq(&archive_sha, &expected) {
        return ArchiveVerdict::Failed(format!(
            "archive SHA-256 mismatch: downloaded {} but checksums.txt expects {}",
            short(&archive_sha),
            short(&expected),
        ));
    }

    // 2. cosign signature over checksums.txt, if possible.
    match verify_cosign_signature(release) {
        CosignOutcomeInternal::Verified => ArchiveVerdict::Ok {
            signed: ChecksumStrength::Signed,
            cosign_note: None,
        },
        CosignOutcomeInternal::Unavailable(reason) => ArchiveVerdict::Ok {
            signed: ChecksumStrength::ChecksumOnly,
            cosign_note: Some(reason.detail()),
        },
        CosignOutcomeInternal::Failed(reason) => {
            ArchiveVerdict::Failed(format!("cosign signature verification FAILED: {reason}"))
        }
    }
}

/// Why a cosign signature check could not be performed. NOT a verification
/// failure (an honest "signature not checked"), but the cases differ
/// operationally and the distinction must reach JSON output.
enum CosignUnavailable {
    /// The release did not publish a `.sig`/`.pem` pair at all.
    NoSignaturePublished,
    /// No `cosign` binary is resolvable on `PATH`.
    NotInstalled,
    /// `cosign` is on `PATH` but could not be executed (string is the spawn
    /// error). Distinct from `NotInstalled` so we don't misadvise "install it".
    ExecFailed(String),
}

impl CosignUnavailable {
    /// One-line, JSON-safe explanation of why the signature was not checked.
    fn detail(&self) -> String {
        match self {
            CosignUnavailable::NoSignaturePublished => {
                "this release did not publish a cosign signature, so only the checksum was \
                 verified"
                    .to_string()
            }
            CosignUnavailable::NotInstalled => {
                "cosign is not installed, so the signature was not checked — install cosign and \
                 re-run for full signature verification"
                    .to_string()
            }
            CosignUnavailable::ExecFailed(err) => format!(
                "cosign is installed but could not be executed ({err}), so the signature was \
                 not checked — verify the cosign installation"
            ),
        }
    }
}

/// Outcome of attempting cosign verification.
enum CosignOutcomeInternal {
    /// The signature verified against the expected Sigstore identity.
    Verified,
    /// Verification could not be attempted (not a failure — see
    /// [`CosignUnavailable`]).
    Unavailable(CosignUnavailable),
    /// `cosign` ran and the signature did NOT verify.
    Failed(String),
}

/// Verify the cosign keyless signature over `checksums.txt`.
///
/// No in-process Sigstore (keyless needs Rekor/Fulcio), so this shells out to
/// `cosign` exactly as `scripts/install.sh` does, with the SAME pinned identity
/// and OIDC issuer. Missing cosign / no signature → `Unavailable` (honest, never
/// a false pass); the cases are reported distinctly so JSON consumers can tell
/// "cosign absent" from "cosign broken".
fn verify_cosign_signature(release: &ReleaseSet) -> CosignOutcomeInternal {
    let (sig, cert) = match (&release.sig_path, &release.cert_path) {
        (Some(s), Some(c)) => (s, c),
        _ => return CosignOutcomeInternal::Unavailable(CosignUnavailable::NoSignaturePublished),
    };

    if !cosign_available() {
        return CosignOutcomeInternal::Unavailable(CosignUnavailable::NotInstalled);
    }

    let output = std::process::Command::new("cosign")
        .arg("verify-blob")
        .arg("--signature")
        .arg(sig)
        .arg("--certificate")
        .arg(cert)
        .arg("--certificate-identity-regexp")
        .arg(COSIGN_IDENTITY_REGEXP)
        .arg("--certificate-oidc-issuer")
        .arg(COSIGN_OIDC_ISSUER)
        .arg(&release.checksums_path)
        .output();

    match output {
        Ok(out) if out.status.success() => CosignOutcomeInternal::Verified,
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            CosignOutcomeInternal::Failed(
                stderr
                    .lines()
                    .next()
                    .unwrap_or("cosign verify-blob exited non-zero")
                    .to_string(),
            )
        }
        Err(e) => {
            // cosign was on PATH but could not be executed: unavailable, not a
            // verification failure — and distinct from "not installed" so the
            // JSON detail does not falsely advise "install cosign".
            eprintln!("tirith: warning: could not run cosign ({e}); skipping signature check");
            CosignOutcomeInternal::Unavailable(CosignUnavailable::ExecFailed(e.to_string()))
        }
    }
}

/// True when a `cosign` binary is resolvable on `PATH`.
fn cosign_available() -> bool {
    let probe = {
        #[cfg(unix)]
        {
            std::process::Command::new("sh")
                .args(["-c", "command -v cosign >/dev/null 2>&1"])
                .status()
        }
        #[cfg(not(unix))]
        {
            std::process::Command::new("where.exe")
                .arg("cosign")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
        }
    };
    probe.map(|s| s.success()).unwrap_or(false)
}

/// Extract the `tirith` binary (`tirith.exe` on Windows) from a release archive
/// into `workdir` and return its path. Shells out to `tar` / PowerShell
/// `Expand-Archive` rather than pulling in an archive crate.
///
/// Path-traversal containment (defense-in-depth, done unconditionally even
/// though the archive is already checksum/cosign-verified): `tar` runs with
/// `--no-same-owner`, and the produced path is canonicalized and asserted to lie
/// INSIDE `extract_dir`, so an escaping symlink member is rejected here rather
/// than hashed/installed.
fn extract_tirith_binary(archive: &Path, target: &str, workdir: &Path) -> Result<PathBuf, String> {
    let extract_dir = workdir.join("extracted");
    std::fs::create_dir_all(&extract_dir).map_err(|e| format!("create extract dir: {e}"))?;

    let binary_name = if target.contains("windows") {
        "tirith.exe"
    } else {
        "tirith"
    };

    if target.contains("windows") {
        // `.zip` via PowerShell Expand-Archive.
        let status = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command"])
            .arg(format!(
                "Expand-Archive -LiteralPath '{}' -DestinationPath '{}' -Force",
                archive.display(),
                extract_dir.display(),
            ))
            .status()
            .map_err(|e| format!("could not run PowerShell Expand-Archive: {e}"))?;
        if !status.success() {
            return Err("Expand-Archive failed to extract the release zip".to_string());
        }
    } else {
        // `.tar.gz` via `tar`. `--no-same-owner` keeps extracted files owned by
        // the current user regardless of the archived uid/gid (matters as root).
        let status = std::process::Command::new("tar")
            .arg("--no-same-owner")
            .arg("-xzf")
            .arg(archive)
            .arg("-C")
            .arg(&extract_dir)
            .status()
            .map_err(|e| format!("could not run tar: {e}"))?;
        if !status.success() {
            return Err("tar failed to extract the release archive".to_string());
        }
    }

    let binary = extract_dir.join(binary_name);
    if !binary.is_file() {
        return Err(format!(
            "release archive did not contain a `{binary_name}` binary"
        ));
    }

    // Containment check: the extracted binary must canonicalize to a path
    // INSIDE `extract_dir`, catching a symlink or `..` member that escapes.
    let canonical_extract_dir = extract_dir
        .canonicalize()
        .map_err(|e| format!("could not canonicalize the extraction directory: {e}"))?;
    let canonical_binary = binary
        .canonicalize()
        .map_err(|e| format!("could not canonicalize the extracted `{binary_name}` path: {e}"))?;
    if !canonical_binary.starts_with(&canonical_extract_dir) {
        return Err(format!(
            "the extracted `{binary_name}` resolves to {} which is OUTSIDE the extraction \
             directory {} — refusing to use it (the release archive may contain a \
             path-traversal payload)",
            canonical_binary.display(),
            canonical_extract_dir.display(),
        ));
    }

    Ok(canonical_binary)
}

/// Result of an atomic self-replace.
struct SwapResult {
    /// Where the previous binary was saved (for `--rollback`).
    previous_backup: PathBuf,
}

/// The path the previous binary is saved to next to `binary_path`.
fn previous_backup_path(binary_path: &Path) -> PathBuf {
    let mut p = binary_path.to_path_buf();
    let name = binary_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tirith".to_string());
    p.set_file_name(format!("{name}.tirith-previous"));
    p
}

/// Atomically replace the binary at `dest` with `new_binary`, keeping the
/// current `dest` as a `.tirith-previous` backup for rollback.
///
/// Safety: the new binary is staged in `dest`'s own directory (so the swap is a
/// same-filesystem, atomic rename) with the exec bit set before the rename; the
/// current `dest` is backed up first; the swap is a single `rename(temp, dest)`
/// so a reader always sees either the old or the new binary, never a partial.
fn atomic_self_replace(dest: &Path, new_binary: &Path) -> Result<SwapResult, String> {
    let dir = dest
        .parent()
        .ok_or_else(|| "cannot determine the binary's directory".to_string())?;

    // Refuse early on a non-writable directory: a clean error beats a raw
    // rename failure, and no temp file is created.
    if !dir_is_writable(dir) {
        return Err(format!(
            "the directory {} is not writable — tirith cannot replace its own binary there \
             (is this a system path that needs sudo, or a package-managed install?)",
            dir.display()
        ));
    }

    // 1. Save the current binary as the rollback backup.
    let backup = previous_backup_path(dest);
    std::fs::copy(dest, &backup).map_err(|e| {
        format!(
            "could not save the current binary to {}: {e}",
            backup.display()
        )
    })?;
    // Durability: fsync the backup's CONTENTS so a crash after the swap can't
    // leave the live binary replaced while the `--rollback` target is
    // truncated. The handle MUST be opened for WRITE — Windows `sync_all` calls
    // `FlushFileBuffers`, which rejects a read-only handle; `write(true)` opens
    // the existing copy without truncating. Its dir entry is covered by the
    // parent fsync at step 4.
    std::fs::OpenOptions::new()
        .write(true)
        .open(&backup)
        .and_then(|f| f.sync_all())
        .map_err(|e| {
            format!(
                "could not sync the rollback backup {}: {e}",
                backup.display()
            )
        })?;

    // 2. Copy the new binary into a temp file in the destination directory.
    let mut tmp = tempfile::Builder::new()
        .prefix(".tirith-new-")
        .tempfile_in(dir)
        .map_err(|e| format!("could not create a temp file in {}: {e}", dir.display()))?;
    let new_bytes =
        std::fs::read(new_binary).map_err(|e| format!("could not read the new binary: {e}"))?;
    tmp.write_all(&new_bytes)
        .map_err(|e| format!("could not write the new binary: {e}"))?;
    tmp.flush()
        .map_err(|e| format!("could not flush the new binary: {e}"))?;

    // 3. Set the exec bit BEFORE the swap so `tirith` is never live-but-unrunnable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("could not set executable permissions: {e}"))?;
    }

    // Durability: fsync the new binary's bytes AND mode before the rename. The
    // sync MUST follow `set_permissions` — syncing first could leave the file
    // durable without the exec bit (durable-but-unrunnable).
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("could not sync the new binary: {e}"))?;

    // 4. Atomic rename over the live binary.
    tmp.persist(dest).map_err(|e| {
        // Rename failed; the old binary is intact (rename doesn't touch dest
        // until it succeeds) and the backup exists.
        format!(
            "could not atomically replace {}: {} (the old binary is intact)",
            dest.display(),
            e.error
        )
    })?;
    // Rename durability: fsync the parent dir so the new name→inode entry
    // survives a crash. Best-effort; no-op on non-Unix.
    fsync_parent_dir(dest);

    Ok(SwapResult {
        previous_backup: backup,
    })
}

/// Atomically install `source`'s bytes onto `dest`, used by `--rollback`.
///
/// Unlike [`atomic_self_replace`] this takes NO backup: rollback's `source` IS
/// the backup, which `atomic_self_replace` would clobber as its first step. This
/// reads `source` fully into memory up front, so the restored bytes are correct
/// even when `source == previous_backup_path(dest)`.
fn atomic_restore_from(dest: &Path, source: &Path) -> Result<(), String> {
    let dir = dest
        .parent()
        .ok_or_else(|| "cannot determine the binary's directory".to_string())?;
    if !dir_is_writable(dir) {
        return Err(format!(
            "the directory {} is not writable — tirith cannot restore its binary there",
            dir.display()
        ));
    }

    // Read source bytes up front: `source` may then be freely overwritten.
    let bytes = std::fs::read(source).map_err(|e| {
        format!(
            "could not read the rollback binary {}: {e}",
            source.display()
        )
    })?;

    let mut tmp = tempfile::Builder::new()
        .prefix(".tirith-rollback-")
        .tempfile_in(dir)
        .map_err(|e| format!("could not create a temp file in {}: {e}", dir.display()))?;
    tmp.write_all(&bytes)
        .map_err(|e| format!("could not write the rollback binary: {e}"))?;
    tmp.flush()
        .map_err(|e| format!("could not flush the rollback binary: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("could not set executable permissions: {e}"))?;
    }
    // Durability: fsync AFTER `set_permissions`, before the rename (syncing
    // first could leave the restored binary durable without the exec bit).
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("could not sync the rollback binary: {e}"))?;
    tmp.persist(dest).map_err(|e| {
        format!(
            "could not atomically restore {}: {} (the current binary is intact)",
            dest.display(),
            e.error
        )
    })?;
    // Rename durability (see `atomic_self_replace`): fsync the parent dir.
    fsync_parent_dir(dest);
    Ok(())
}

/// fsync `path`'s parent directory after a rename so the new name→inode entry is
/// durable. Routes through the shared `fsync_parent_dir_logged`: the swap already
/// succeeded, so a dir-fsync failure is LOGGED, never fatal. No-op on non-Unix.
fn fsync_parent_dir(path: &Path) {
    tirith_core::util::fsync_parent_dir_logged(path, "binary swap");
}

/// Best-effort writability probe: try to create a temp file in `dir`.
fn dir_is_writable(dir: &Path) -> bool {
    tempfile::Builder::new()
        .prefix(".tirith-wtest-")
        .tempfile_in(dir)
        .is_ok()
}

/// SHA-256 of a byte slice, lowercase hex.
fn hex_sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

/// SHA-256 of a file's contents, lowercase hex; `None` if it cannot be read.
fn hash_file_opt(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(hex_sha256(&bytes))
}

/// Write `bytes` to `path` (plain, non-atomic — only for files in a private temp dir).
fn write_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = std::fs::File::create(path)?;
    f.write_all(bytes)?;
    f.flush()
}

/// First 12 hex chars of a digest, for human messages.
fn short(digest: &str) -> String {
    digest.chars().take(12).collect()
}

/// One-line detail string for a verification status, for JSON `*_detail`.
fn status_detail(status: &VerificationStatus) -> String {
    match status {
        VerificationStatus::VerifiedSigned => {
            "binary matches the signed release (checksum + cosign signature verified)".to_string()
        }
        VerificationStatus::VerifiedChecksumOnly => {
            "binary matches the release checksum; cosign signature not checked".to_string()
        }
        VerificationStatus::Unverified { reason } | VerificationStatus::Failed { reason } => {
            reason.clone()
        }
    }
}

/// Short human label for a verification status (used in `version --provenance`).
fn describe_status(status: &VerificationStatus) -> String {
    match status {
        VerificationStatus::VerifiedSigned => "verified (signed release)".to_string(),
        VerificationStatus::VerifiedChecksumOnly => "verified (checksum only)".to_string(),
        VerificationStatus::Unverified { reason } => format!("unverified — {reason}"),
        VerificationStatus::Failed { reason } => format!("FAILED — {reason}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_self_replace_swaps_and_keeps_backup() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("tirith");
        let new = dir.path().join("new-tirith");
        std::fs::write(&live, b"OLD-BINARY").unwrap();
        std::fs::write(&new, b"NEW-BINARY").unwrap();

        let swap = atomic_self_replace(&live, &new).expect("swap should succeed");

        // Live binary is now the new bytes.
        assert_eq!(std::fs::read(&live).unwrap(), b"NEW-BINARY");
        // Backup holds the old bytes and is where the result says it is.
        assert!(swap.previous_backup.is_file());
        assert_eq!(std::fs::read(&swap.previous_backup).unwrap(), b"OLD-BINARY");
        assert_eq!(swap.previous_backup, previous_backup_path(&live));
    }

    /// `--rollback` property: restoring from the backup recovers the original.
    #[test]
    fn rollback_from_backup_restores_original() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("tirith");
        let new = dir.path().join("new-tirith");
        std::fs::write(&live, b"V1").unwrap();
        std::fs::write(&new, b"V2").unwrap();

        let swap = atomic_self_replace(&live, &new).unwrap();
        assert_eq!(std::fs::read(&live).unwrap(), b"V2");

        // Roll back: restore the backup over the live binary.
        atomic_restore_from(&live, &swap.previous_backup).unwrap();
        assert_eq!(std::fs::read(&live).unwrap(), b"V1");
    }

    /// REGRESSION: `atomic_restore_from` must restore the SOURCE bytes even when
    /// `source == previous_backup_path(dest)` (the rollback case).
    #[test]
    fn atomic_restore_from_does_not_clobber_source_at_backup_path() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("tirith");
        std::fs::write(&live, b"CURRENT-BYTES").unwrap();
        let backup = previous_backup_path(&live);
        std::fs::write(&backup, b"PREVIOUS-BYTES").unwrap();

        atomic_restore_from(&live, &backup).unwrap();

        assert_eq!(std::fs::read(&live).unwrap(), b"PREVIOUS-BYTES");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_restore_from_sets_executable_bit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("tirith");
        let src = dir.path().join("backup");
        std::fs::write(&live, b"live").unwrap();
        std::fs::write(&src, b"restored").unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o600)).unwrap();

        atomic_restore_from(&live, &src).unwrap();

        let mode = std::fs::metadata(&live).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "restored binary must be executable");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_self_replace_sets_executable_bit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("tirith");
        let new = dir.path().join("new-tirith");
        std::fs::write(&live, b"old").unwrap();
        std::fs::write(&new, b"new").unwrap();
        // Deliberately NOT executable before the swap.
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o644)).unwrap();

        atomic_self_replace(&live, &new).unwrap();

        let mode = std::fs::metadata(&live).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "swapped-in binary must be executable");
    }

    #[test]
    fn previous_backup_path_is_next_to_binary() {
        let p = Path::new("/Users/alice/.local/bin/tirith");
        let b = previous_backup_path(p);
        assert_eq!(
            b,
            PathBuf::from("/Users/alice/.local/bin/tirith.tirith-previous")
        );
    }

    #[test]
    fn dir_is_writable_true_for_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(dir_is_writable(dir.path()));
    }

    #[test]
    fn dir_is_writable_false_for_nonexistent_dir() {
        assert!(!dir_is_writable(Path::new("/nonexistent/tirith/xyz")));
    }

    #[test]
    fn hex_sha256_known_value() {
        assert_eq!(
            hex_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hash_file_opt_reads_and_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("data");
        std::fs::write(&f, b"").unwrap();
        assert_eq!(
            hash_file_opt(&f).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(hash_file_opt(Path::new("/nonexistent/x")), None);
    }

    #[test]
    fn short_truncates_to_twelve() {
        assert_eq!(short(&"a".repeat(64)), "aaaaaaaaaaaa");
        assert_eq!(short("abc"), "abc");
    }

    /// `Failed` when the archive bytes don't match checksums.txt (tampered download).
    #[test]
    fn archive_verify_fails_on_checksum_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("tirith-x86_64-unknown-linux-gnu.tar.gz");
        std::fs::write(&archive, b"TAMPERED ARCHIVE BYTES").unwrap();
        let checksums = dir.path().join("checksums.txt");
        // checksums.txt claims a digest that is NOT the archive's real digest.
        let txt = format!(
            "{}  tirith-x86_64-unknown-linux-gnu.tar.gz\n",
            "0".repeat(64)
        );
        std::fs::write(&checksums, &txt).unwrap();

        let release = ReleaseSet {
            archive_path: archive,
            checksums_txt: txt,
            sig_path: None,
            cert_path: None,
            checksums_path: checksums,
        };
        let verdict =
            verify_archive_against_checksums(&release, "tirith-x86_64-unknown-linux-gnu.tar.gz");
        assert!(matches!(verdict, ArchiveVerdict::Failed(_)));
    }

    /// Archive matches checksums.txt with no signature → `Ok(ChecksumOnly)`.
    #[test]
    fn archive_verify_ok_checksum_only_without_signature() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("tirith-x86_64-unknown-linux-gnu.tar.gz");
        let body = b"REAL ARCHIVE BYTES";
        std::fs::write(&archive, body).unwrap();
        let real_digest = hex_sha256(body);
        let txt = format!("{real_digest}  tirith-x86_64-unknown-linux-gnu.tar.gz\n");
        let checksums = dir.path().join("checksums.txt");
        std::fs::write(&checksums, &txt).unwrap();

        let release = ReleaseSet {
            archive_path: archive,
            checksums_txt: txt,
            sig_path: None, // release shipped no cosign signature
            cert_path: None,
            checksums_path: checksums,
        };
        let verdict =
            verify_archive_against_checksums(&release, "tirith-x86_64-unknown-linux-gnu.tar.gz");
        match verdict {
            ArchiveVerdict::Ok {
                signed,
                cosign_note,
            } => {
                assert_eq!(signed, ChecksumStrength::ChecksumOnly);
                // No `.sig`/`.pem` published — the note must say so, not advise
                // "install cosign".
                let note = cosign_note.expect("checksum-only must carry a cosign note");
                assert!(
                    note.contains("did not publish"),
                    "note should explain no signature was published, got: {note}"
                );
            }
            _ => panic!("expected Ok(ChecksumOnly), got a different verdict"),
        }
    }

    /// No entry for the archive → `ChecksumMissing`, never a false pass.
    #[test]
    fn archive_verify_checksum_missing_when_no_entry() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("tirith-x86_64-unknown-linux-gnu.tar.gz");
        std::fs::write(&archive, b"bytes").unwrap();
        let txt = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  some-other-file.tar.gz\n";
        let checksums = dir.path().join("checksums.txt");
        std::fs::write(&checksums, txt).unwrap();

        let release = ReleaseSet {
            archive_path: archive,
            checksums_txt: txt.to_string(),
            sig_path: None,
            cert_path: None,
            checksums_path: checksums,
        };
        let verdict =
            verify_archive_against_checksums(&release, "tirith-x86_64-unknown-linux-gnu.tar.gz");
        assert!(matches!(verdict, ArchiveVerdict::ChecksumMissing(_)));
    }

    /// A dev build is always Unverified, never a confident pass.
    #[test]
    fn local_status_dev_build_is_unverified() {
        let prov = Provenance {
            version: "0.3.1".to_string(),
            binary_path: Some(PathBuf::from("/src/tirith/target/release/tirith")),
            binary_sha256: Some("a".repeat(64)),
            install_method: InstallMethod::Unknown,
            target: Some("x86_64-unknown-linux-gnu".to_string()),
            dev_build: true,
            path_resolution_failed: false,
        };
        let status = local_verification_status(&prov);
        assert_eq!(status.token(), "unverified");
        assert!(matches!(status, VerificationStatus::Unverified { .. }));
    }

    /// A dev build short-circuits to Unverified WITHOUT network — an honest
    /// unverified (not operational): exit 0 must be kept.
    #[test]
    fn verify_self_dev_build_short_circuits_offline() {
        let prov = Provenance {
            version: "0.3.1".to_string(),
            binary_path: Some(PathBuf::from("/home/dev/tirith/target/release/tirith")),
            binary_sha256: Some("b".repeat(64)),
            install_method: InstallMethod::SelfManaged,
            target: Some("x86_64-unknown-linux-gnu".to_string()),
            dev_build: true,
            path_resolution_failed: false,
        };
        let outcome = run_verify_self(&prov);
        assert!(matches!(
            outcome.status,
            VerificationStatus::Unverified { .. }
        ));
        assert_eq!(outcome.status.token(), "unverified");
        assert!(
            !outcome.operational_error,
            "a dev build is an honest unverified, not an operational error"
        );
    }

    /// An unpublished platform short-circuits to Unverified, not operational.
    #[test]
    fn verify_self_unpublished_platform_short_circuits() {
        let prov = Provenance {
            version: "0.3.1".to_string(),
            binary_path: Some(PathBuf::from("/usr/bin/tirith")),
            binary_sha256: Some("c".repeat(64)),
            install_method: InstallMethod::Unknown,
            target: None, // unpublished platform
            dev_build: false,
            path_resolution_failed: false,
        };
        let outcome = run_verify_self(&prov);
        assert!(matches!(
            outcome.status,
            VerificationStatus::Unverified { .. }
        ));
        assert!(
            !outcome.operational_error,
            "an unpublished platform is an honest unverified, not an operational error"
        );
    }

    /// F2: a known PATH but unreadable own bytes (`binary_sha256 == None`) is an
    /// OPERATIONAL error — surfaced as `Unverified` but exits non-zero.
    #[test]
    fn verify_self_unreadable_own_binary_is_operational_error() {
        let prov = Provenance {
            version: "0.3.1".to_string(),
            binary_path: Some(PathBuf::from("/usr/local/bin/tirith")),
            binary_sha256: None, // could not read / hash the running binary
            install_method: InstallMethod::SelfManaged,
            target: Some("x86_64-unknown-linux-gnu".to_string()),
            dev_build: false,
            path_resolution_failed: false,
        };
        let outcome = run_verify_self(&prov);
        assert!(
            outcome.operational_error,
            "an unreadable own-binary is an operational error, not a benign unverified"
        );
        // Surfaced as `Unverified`, never a false `Failed`.
        assert!(matches!(
            outcome.status,
            VerificationStatus::Unverified { .. }
        ));
    }

    /// F2: an unknown own-binary path (`binary_path == None`) is operational too.
    #[test]
    fn verify_self_unknown_own_path_is_operational_error() {
        let prov = Provenance {
            version: "0.3.1".to_string(),
            binary_path: None,
            binary_sha256: None,
            install_method: InstallMethod::SelfManaged,
            target: Some("x86_64-unknown-linux-gnu".to_string()),
            dev_build: false,
            path_resolution_failed: false,
        };
        let outcome = run_verify_self(&prov);
        assert!(
            outcome.operational_error,
            "an unknown own-binary path is an operational error"
        );
        assert!(matches!(
            outcome.status,
            VerificationStatus::Unverified { .. }
        ));
    }

    /// `extract_tirith_binary` round-trips a real tar.gz, finding the `tirith`
    /// member and returning a path whose bytes match.
    #[cfg(unix)]
    #[test]
    fn extract_tirith_binary_finds_member_in_targz() {
        let dir = tempfile::tempdir().unwrap();
        // tar.gz with a `tirith` file plus a decoy.
        let stage = dir.path().join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("tirith"), b"BINARY-CONTENT").unwrap();
        std::fs::write(stage.join("README"), b"decoy").unwrap();
        let archive = dir.path().join("tirith-x86_64-unknown-linux-gnu.tar.gz");
        let ok = std::process::Command::new("tar")
            .arg("czf")
            .arg(&archive)
            .arg("-C")
            .arg(&stage)
            .arg("tirith")
            .arg("README")
            .status()
            .expect("tar should run")
            .success();
        assert!(ok, "tar czf should succeed");

        let extracted =
            extract_tirith_binary(&archive, "x86_64-unknown-linux-gnu", dir.path()).unwrap();
        assert_eq!(std::fs::read(&extracted).unwrap(), b"BINARY-CONTENT");
    }

    /// Errors when the archive has no `tirith` member.
    #[cfg(unix)]
    #[test]
    fn extract_tirith_binary_errors_when_no_binary() {
        let dir = tempfile::tempdir().unwrap();
        let stage = dir.path().join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("NOT-tirith"), b"x").unwrap();
        let archive = dir.path().join("tirith-x86_64-unknown-linux-gnu.tar.gz");
        std::process::Command::new("tar")
            .arg("czf")
            .arg(&archive)
            .arg("-C")
            .arg(&stage)
            .arg("NOT-tirith")
            .status()
            .unwrap();

        let r = extract_tirith_binary(&archive, "x86_64-unknown-linux-gnu", dir.path());
        assert!(r.is_err());
    }

    /// F21 / F1: extraction containment. A `tirith` member that is a SYMLINK
    /// escaping the extraction dir must be REJECTED (canonicalized path refused),
    /// never hashed or installed.
    #[cfg(unix)]
    #[test]
    fn extract_tirith_binary_rejects_symlink_escaping_extract_dir() {
        let dir = tempfile::tempdir().unwrap();

        // A sensitive file OUTSIDE the extraction dir the payload targets.
        let outside_secret = dir.path().join("outside-secret");
        std::fs::write(&outside_secret, b"SENSITIVE-BYTES-OUTSIDE").unwrap();

        // `tirith` member is a `../../`-escaping symlink. Extraction lands in
        // `dir/work/extracted`, so `../../outside-secret` reaches `dir`.
        let stage = dir.path().join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::os::unix::fs::symlink("../../outside-secret", stage.join("tirith")).unwrap();
        let archive = dir.path().join("tirith-x86_64-unknown-linux-gnu.tar.gz");
        let ok = std::process::Command::new("tar")
            // Without -h, tar archives the symlink AS a symlink (the attack).
            .arg("czf")
            .arg(&archive)
            .arg("-C")
            .arg(&stage)
            .arg("tirith")
            .status()
            .expect("tar should run")
            .success();
        assert!(ok, "tar czf should succeed");

        let workdir = dir.path().join("work");
        std::fs::create_dir_all(&workdir).unwrap();
        let r = extract_tirith_binary(&archive, "x86_64-unknown-linux-gnu", &workdir);
        assert!(
            r.is_err(),
            "an escaping-symlink `tirith` member must be rejected, got: {r:?}"
        );
        let err = r.unwrap_err();
        assert!(
            err.contains("OUTSIDE") || err.contains("path-traversal"),
            "rejection should name the containment violation, got: {err}"
        );
        // The outside file is untouched — never written through the link.
        assert_eq!(
            std::fs::read(&outside_secret).unwrap(),
            b"SENSITIVE-BYTES-OUTSIDE"
        );
    }

    /// F21 / F1: a `../`-prefixed archive MEMBER must not write outside the
    /// extraction dir. `tar` strips the leading `../`, so the member never lands
    /// and extraction fails cleanly with nothing written to the parent.
    #[cfg(unix)]
    #[test]
    fn extract_tirith_binary_dotdot_member_writes_nothing_outside() {
        let dir = tempfile::tempdir().unwrap();
        let stage = dir.path().join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("tirith"), b"PAYLOAD").unwrap();
        // Archive the member under a `../escaped-tirith` name.
        let archive = dir.path().join("tirith-x86_64-unknown-linux-gnu.tar.gz");
        let ok = std::process::Command::new("tar")
            .arg("czf")
            .arg(&archive)
            .arg("-C")
            .arg(&stage)
            .arg("--transform")
            .arg("s,^tirith,../escaped-tirith,")
            .arg("tirith")
            .status();
        // GNU tar has --transform; bsdtar may not, so tolerate failure.
        let renamed = ok.map(|s| s.success()).unwrap_or(false);

        let workdir = dir.path().join("work");
        std::fs::create_dir_all(&workdir).unwrap();
        let leak = workdir.join("escaped-tirith");
        let _ = extract_tirith_binary(&archive, "x86_64-unknown-linux-gnu", &workdir);

        if renamed {
            // The `../`-prefixed member must not have escaped into `work/`.
            assert!(
                !leak.exists(),
                "a `../`-prefixed archive member must not be written outside the extract dir"
            );
        }
    }

    /// F21 / F1: the containment check rejects ESCAPES, not in-bounds files — a
    /// pre-existing `extracted/tirith` inside `extract_dir` must be allowed.
    #[cfg(unix)]
    #[test]
    fn extract_tirith_binary_preexisting_in_bounds_file_is_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let stage = dir.path().join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("tirith"), b"ARCHIVE-BINARY").unwrap();
        let archive = dir.path().join("tirith-x86_64-unknown-linux-gnu.tar.gz");
        std::process::Command::new("tar")
            .arg("czf")
            .arg(&archive)
            .arg("-C")
            .arg(&stage)
            .arg("tirith")
            .status()
            .unwrap();

        let workdir = dir.path().join("work");
        // Pre-create `work/extracted/tirith` before extraction.
        let pre = workdir.join("extracted");
        std::fs::create_dir_all(&pre).unwrap();
        std::fs::write(pre.join("tirith"), b"PRE-EXISTING").unwrap();

        let extracted =
            extract_tirith_binary(&archive, "x86_64-unknown-linux-gnu", &workdir).unwrap();
        assert!(extracted.starts_with(pre.canonicalize().unwrap()));
    }

    /// F19: a `cosign` on `PATH` that EXITS NON-ZERO must yield
    /// `ArchiveVerdict::Failed` — never folded into a checksum-only pass.
    /// Mutates `PATH`, so it holds the crate-wide `ENV_LOCK` and restores via
    /// `EnvGuard`.
    #[cfg(unix)]
    #[test]
    fn cosign_failure_makes_archive_verdict_failed() {
        use crate::cli::test_harness::{EnvGuard, ENV_LOCK};
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();

        // A fake `cosign` that always exits 1. MUST be executable or PATH
        // resolution would skip it.
        let fake_bin_dir = dir.path().join("fakebin");
        std::fs::create_dir_all(&fake_bin_dir).unwrap();
        let fake_cosign = fake_bin_dir.join("cosign");
        std::fs::write(
            &fake_cosign,
            "#!/bin/sh\necho 'fake cosign: signature did not verify' 1>&2\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake_cosign, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Archive bytes match checksums.txt so verification reaches the cosign
        // step; the release ships a dummy .sig and .pem.
        let archive = dir.path().join("tirith-x86_64-unknown-linux-gnu.tar.gz");
        let body = b"REAL ARCHIVE BYTES FOR COSIGN TEST";
        std::fs::write(&archive, body).unwrap();
        let real_digest = hex_sha256(body);
        let txt = format!("{real_digest}  tirith-x86_64-unknown-linux-gnu.tar.gz\n");
        let checksums = dir.path().join("checksums.txt");
        std::fs::write(&checksums, &txt).unwrap();
        let sig = dir.path().join("checksums.txt.sig");
        std::fs::write(&sig, b"dummy-signature").unwrap();
        let cert = dir.path().join("checksums.txt.pem");
        std::fs::write(&cert, b"dummy-certificate").unwrap();

        let release = ReleaseSet {
            archive_path: archive,
            checksums_txt: txt,
            sig_path: Some(sig),
            cert_path: Some(cert),
            checksums_path: checksums,
        };

        let verdict = {
            // Serialize against every other env-mutating test in the crate.
            let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            // Prepend (not replace) the fake-cosign dir so `sh` stays
            // resolvable; `EnvGuard` restores PATH on Drop.
            let mut entries = vec![fake_bin_dir.clone()];
            if let Some(p) = std::env::var_os("PATH") {
                entries.extend(std::env::split_paths(&p));
            }
            let joined = std::env::join_paths(entries).expect("join PATH");
            let _path_guard = EnvGuard::set("PATH", std::path::Path::new(&joined));

            verify_archive_against_checksums(&release, "tirith-x86_64-unknown-linux-gnu.tar.gz")
        };

        match verdict {
            ArchiveVerdict::Failed(reason) => {
                assert!(
                    reason.contains("cosign"),
                    "the failure reason should mention cosign, got: {reason}"
                );
            }
            other => panic!(
                "a non-zero cosign exit must yield ArchiveVerdict::Failed, got a different verdict ({})",
                match other {
                    ArchiveVerdict::Ok { .. } => "Ok",
                    ArchiveVerdict::ChecksumMissing(_) => "ChecksumMissing",
                    ArchiveVerdict::Failed(_) => unreachable!(),
                }
            ),
        }
    }

    #[test]
    fn status_detail_carries_reason() {
        let s = VerificationStatus::Unverified {
            reason: "offline".to_string(),
        };
        assert_eq!(status_detail(&s), "offline");
        let f = VerificationStatus::Failed {
            reason: "mismatch".to_string(),
        };
        assert_eq!(status_detail(&f), "mismatch");
    }
}
