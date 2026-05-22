//! `tirith verify-self`, `tirith update`, and `tirith version --provenance`.
//!
//! These commands verify tirith's OWN integrity and update tirith itself. They
//! reach the network ONLY when the user explicitly invokes them — there is no
//! hot-path network here. Honesty is the load-bearing property: a `verify-self`
//! that cannot fully verify says so plainly and never reports a falsely
//! confident "verified", and `update` never self-modifies a package-manager-
//! managed install.
//!
//! See `tirith_core::selfupdate` for the design notes on what the release
//! pipeline actually produces and how verification maps onto it.

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

// ===========================================================================
// version --provenance
// ===========================================================================

/// Gather the running binary's provenance without any network access.
pub fn gather_provenance() -> Provenance {
    let raw_exe = std::env::current_exe().ok();
    // Resolve through symlinks / npm wrapper / Scoop shim, the same way the
    // shadow-binary detector does, so the install-method classifier sees the
    // real on-disk binary.
    let binary_path = raw_exe
        .as_deref()
        .and_then(crate::cli::resolve_effective_tirith_target)
        .or(raw_exe);

    let binary_sha256 = binary_path.as_deref().and_then(hash_file_opt);

    let install_method = match &binary_path {
        Some(p) => {
            let m = selfupdate::detect_install_method(p);
            // Refine a system-path Unknown into apt/dnf when on Linux.
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
    }
}

/// `tirith version --provenance`. Prints version, build info, install method,
/// and a verification status. With `provenance == false` it prints just the
/// version line (the plain `tirith version` behavior).
pub fn version(provenance: bool, json: bool) -> i32 {
    if !provenance {
        // Plain `tirith version`: same string clap's `--version` produces.
        if json {
            let v = serde_json::json!({ "version": env!("CARGO_PKG_VERSION") });
            println!("{v}");
        } else {
            println!("tirith {}", env!("CARGO_PKG_VERSION"));
        }
        return 0;
    }

    let prov = gather_provenance();
    // `version --provenance` is offline: it reports the *local* facts and a
    // local-only verification verdict. Full networked verification is
    // `verify-self`.
    let local_status = local_verification_status(&prov);

    if json {
        let v = serde_json::json!({
            "version": prov.version,
            "binary_path": prov.binary_path.as_ref().map(|p| p.display().to_string()),
            "binary_sha256": prov.binary_sha256,
            "target": prov.target,
            "install_method": prov.install_method.as_str(),
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

/// Read the `ID` and `ID_LIKE` tokens from `/etc/os-release`, lowercased, for
/// apt-vs-dnf disambiguation of a system-path install. Returns an empty vec on
/// any non-Linux platform or when the file is absent/unreadable — the caller
/// (`refine_system_pm`) then simply leaves the method as `Unknown`.
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

/// The verification verdict obtainable WITHOUT network access. `version
/// --provenance` is intentionally offline, so it can only state structural
/// facts: a dev build cannot be a verified release; an installed release
/// binary's full verification requires `verify-self`.
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

/// `tirith verify-self`. Verify the running binary against its known-good
/// release checksum and signature, where possible. Exit code:
///   * `0` — verification succeeded (signed or checksum-only) OR could only be
///     honestly reported as *unverified* for a benign reason (dev build,
///     offline, unpublished platform). An honest "cannot verify" is not an
///     error.
///   * `1` — verification was attempted and FAILED (mismatch / bad signature),
///     or an unexpected operational error occurred.
pub fn verify_self(json: bool) -> i32 {
    let prov = gather_provenance();
    let status = run_verify_self(&prov);
    emit_verify_self(&prov, &status, json);
    match status {
        VerificationStatus::Failed { .. } => 1,
        _ => 0,
    }
}

/// Core of `verify-self`: do the networked verification of the running binary.
/// Kept separate so the emit/exit logic is trivially correct.
fn run_verify_self(prov: &Provenance) -> VerificationStatus {
    // 1. A dev build can never be matched against a release.
    if prov.dev_build {
        return VerificationStatus::Unverified {
            reason: "this is a local/dev build (compiled from source, not installed from a \
                     release) — there is no release checksum to verify it against"
                .to_string(),
        };
    }

    // 2. Need a published target and a parseable version.
    let target = match &prov.target {
        Some(t) => t.clone(),
        None => {
            return VerificationStatus::Unverified {
                reason: "this platform has no published tirith release artifact to verify \
                         against"
                    .to_string(),
            }
        }
    };
    let version = match SemVer::parse(&prov.version) {
        Some(v) => v,
        None => {
            return VerificationStatus::Unverified {
                reason: format!(
                    "running version `{}` is not a parseable release version",
                    prov.version
                ),
            }
        }
    };

    // 3. Need the running binary's own bytes.
    let (binary_path, binary_sha) = match (&prov.binary_path, &prov.binary_sha256) {
        (Some(p), Some(s)) => (p.clone(), s.clone()),
        _ => {
            return VerificationStatus::Unverified {
                reason: "could not read the running binary's own bytes".to_string(),
            }
        }
    };

    // 4. Download the release archive + checksums for this exact version.
    let tag = format!("v{version}");
    let archive_name = selfupdate::release_archive_name(&target);
    let workdir = match tempfile::Builder::new().prefix("tirith-verify-").tempdir() {
        Ok(d) => d,
        Err(e) => {
            return VerificationStatus::Unverified {
                reason: format!("could not create a working directory: {e}"),
            }
        }
    };

    let release = match download_release_set(&tag, &archive_name, workdir.path()) {
        Ok(r) => r,
        Err(DownloadError::Offline(msg)) => {
            return VerificationStatus::Unverified {
                reason: format!("could not reach the release server ({msg}) — re-run online"),
            }
        }
        Err(DownloadError::NotFound(msg)) => {
            return VerificationStatus::Unverified {
                reason: format!(
                    "no release artifact found for {tag} ({msg}) — this binary may predate \
                     the release-checksum scheme, or be a custom build"
                ),
            }
        }
        Err(DownloadError::Other(msg)) => {
            return VerificationStatus::Failed {
                reason: format!("release download failed: {msg}"),
            }
        }
    };

    // 5. Verify the archive bytes against the (possibly signed) checksums.
    let verdict = verify_archive_against_checksums(&release, &archive_name);
    let checksum_status = match verdict {
        ArchiveVerdict::Ok { signed } => signed,
        ArchiveVerdict::Failed(reason) => return VerificationStatus::Failed { reason },
        ArchiveVerdict::ChecksumMissing(reason) => {
            return VerificationStatus::Unverified { reason }
        }
    };

    // 6. Extract the binary from the verified archive and compare it,
    //    byte-for-byte, to the running binary. This is the step that ties the
    //    archive-level checksum to the actual file on disk.
    let extracted = match extract_tirith_binary(&release.archive_path, &target, workdir.path()) {
        Ok(p) => p,
        Err(e) => {
            return VerificationStatus::Failed {
                reason: format!(
                    "could not extract the tirith binary from the verified release archive: {e}"
                ),
            }
        }
    };
    let extracted_sha = match hash_file_opt(&extracted) {
        Some(s) => s,
        None => {
            return VerificationStatus::Failed {
                reason: "could not hash the binary extracted from the release archive".to_string(),
            }
        }
    };

    if !selfupdate::digest_eq(&extracted_sha, &binary_sha) {
        return VerificationStatus::Failed {
            reason: format!(
                "the running binary at {} (sha256 {}) does NOT match the official {} release \
                 binary (sha256 {}) — it has been modified or replaced",
                binary_path.display(),
                short(&binary_sha),
                tag,
                short(&extracted_sha),
            ),
        };
    }

    // Running binary == official release binary. The strength of the verdict
    // is whatever the archive-vs-checksums step achieved.
    match checksum_status {
        ChecksumStrength::Signed => VerificationStatus::VerifiedSigned,
        ChecksumStrength::ChecksumOnly => VerificationStatus::VerifiedChecksumOnly,
    }
}

fn emit_verify_self(prov: &Provenance, status: &VerificationStatus, json: bool) {
    if json {
        let v = serde_json::json!({
            "version": prov.version,
            "binary_path": prov.binary_path.as_ref().map(|p| p.display().to_string()),
            "binary_sha256": prov.binary_sha256,
            "install_method": prov.install_method.as_str(),
            "target": prov.target,
            "dev_build": prov.dev_build,
            "verification_status": status.token(),
            "verification_detail": status_detail(status),
            "integrity_ok": status.is_integrity_ok(),
        });
        match serde_json::to_string_pretty(&v) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("tirith: JSON serialization failed: {e}"),
        }
        return;
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
            println!(
                "  The cosign signature was NOT checked (cosign is not installed). Install \
                 cosign and re-run for full signature verification."
            );
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
}

// ===========================================================================
// update
// ===========================================================================

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

    // 3. Verify the downloaded release.
    //    `--verify` makes verification MANDATORY: anything short of a positive
    //    integrity result aborts. Without `--verify` we still verify and
    //    refuse on a hard FAILED (a checksum mismatch is never acceptable),
    //    but tolerate an honest "unverified" (e.g. cosign missing → still
    //    checksum-verified; that is `is_integrity_ok`).
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
            // No checksum entry at all. With --verify this is fatal; without
            // it, we still refuse — installing an unverifiable binary over a
            // working one is not acceptable for a security tool.
            emit_update_error(
                json,
                &format!(
                    "release checksum could not be verified ({reason}) — aborting update; \
                     install manually from https://github.com/{REPO}/releases if intended"
                ),
            );
            return 1;
        }
        ArchiveVerdict::Ok { signed } => {
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
                ArchiveVerdict::Ok { signed: ChecksumStrength::Signed } => "verified-signed",
                ArchiveVerdict::Ok { signed: ChecksumStrength::ChecksumOnly } => {
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
                } => "signed release (checksum + cosign signature)",
                ArchiveVerdict::Ok {
                    signed: ChecksumStrength::ChecksumOnly,
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

/// Print the exact package-manager upgrade command for a PM-managed install,
/// and explain that tirith will not self-modify it. Exit `0` — this is the
/// correct, intended outcome for a package-managed install, not an error.
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

    // Restore: atomically install the backup's bytes onto the live path.
    //
    // This deliberately does NOT route through `atomic_self_replace` —
    // `atomic_self_replace` would first copy the live binary onto
    // `previous_backup_path(dest)`, which is the *same path* as `backup`,
    // overwriting the rollback source with the current bytes before the swap.
    // `atomic_restore_from` reads the source up front and never writes to it.
    match atomic_restore_from(&binary_path, &backup) {
        Ok(()) => {
            // The backup's bytes are now the live binary. Remove the now-stale
            // backup file: it is no longer "the previous version".
            let _ = std::fs::remove_file(&backup);
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

// ===========================================================================
// networking — release download
// ===========================================================================

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

/// Why a download could not be completed. The distinction matters: `Offline`
/// and `NotFound` are *honest* non-failures for `verify-self`, while `Other`
/// is an operational error.
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

    // The archive is required.
    let archive_url = format!("{base}/{archive_name}");
    let archive_bytes = fetch_bytes(&client, &archive_url, MAX_ARCHIVE_SIZE)?;
    let archive_path = workdir.join(archive_name);
    write_file(&archive_path, &archive_bytes)
        .map_err(|e| DownloadError::Other(format!("write archive: {e}")))?;

    // checksums.txt is required for any verification.
    let checksums_url = format!("{base}/checksums.txt");
    let checksums_bytes = fetch_bytes(&client, &checksums_url, MAX_METADATA_SIZE)?;
    let checksums_txt = String::from_utf8(checksums_bytes.clone())
        .map_err(|_| DownloadError::Other("checksums.txt is not valid UTF-8".to_string()))?;
    let checksums_path = workdir.join("checksums.txt");
    write_file(&checksums_path, &checksums_bytes)
        .map_err(|e| DownloadError::Other(format!("write checksums.txt: {e}")))?;

    // The cosign signature + certificate are optional: an older release may
    // not have them, and that is an honest "checksum-only", not a failure.
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
            // A connect/timeout error is "offline"; anything else is operational.
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

    // Fast-reject via Content-Length before reading the body.
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

// ===========================================================================
// verification — archive vs checksums vs cosign
// ===========================================================================

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
    Ok { signed: ChecksumStrength },
    /// Verification was attempted and FAILED (mismatch / bad signature).
    Failed(String),
    /// `checksums.txt` had no entry for this archive — cannot verify.
    ChecksumMissing(String),
}

/// Verify a downloaded `ReleaseSet`'s archive against `checksums.txt`, then —
/// if `cosign` is available and the release shipped a signature — verify the
/// cosign signature over `checksums.txt`.
fn verify_archive_against_checksums(release: &ReleaseSet, archive_name: &str) -> ArchiveVerdict {
    // 1. Archive bytes vs the digest recorded in checksums.txt.
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
        },
        CosignOutcomeInternal::Unavailable => ArchiveVerdict::Ok {
            signed: ChecksumStrength::ChecksumOnly,
        },
        CosignOutcomeInternal::Failed(reason) => {
            ArchiveVerdict::Failed(format!("cosign signature verification FAILED: {reason}"))
        }
    }
}

/// Outcome of attempting cosign verification.
enum CosignOutcomeInternal {
    /// The signature verified against the expected Sigstore identity.
    Verified,
    /// Verification could not be attempted (no `cosign`, or the release did
    /// not publish a `.sig`/`.pem`). NOT a failure.
    Unavailable,
    /// `cosign` ran and the signature did NOT verify.
    Failed(String),
}

/// Verify the cosign keyless signature over `checksums.txt`.
///
/// tirith has no in-process Sigstore implementation — keyless verification
/// needs to talk to Rekor/Fulcio — so this shells out to the `cosign` binary,
/// exactly as `scripts/install.sh` does, with the SAME pinned identity and
/// OIDC issuer. If `cosign` is not on `PATH`, or the release shipped no
/// signature, verification is `Unavailable` (honest), never a false pass.
fn verify_cosign_signature(release: &ReleaseSet) -> CosignOutcomeInternal {
    let (sig, cert) = match (&release.sig_path, &release.cert_path) {
        (Some(s), Some(c)) => (s, c),
        _ => return CosignOutcomeInternal::Unavailable, // release shipped no signature
    };

    if !cosign_available() {
        return CosignOutcomeInternal::Unavailable;
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
            // cosign was on PATH a moment ago but could not be executed; treat
            // as unavailable rather than a verification failure.
            eprintln!("tirith: warning: could not run cosign ({e}); skipping signature check");
            CosignOutcomeInternal::Unavailable
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

// ===========================================================================
// archive extraction
// ===========================================================================

/// Extract the `tirith` binary from a release archive into `workdir` and
/// return its path. The archive is `.tar.gz` (Unix) or `.zip` (Windows); we
/// shell out to `tar` / `unzip` (or PowerShell `Expand-Archive`) rather than
/// pulling in an archive crate. The extracted binary file name is `tirith`
/// (`tirith.exe` on Windows).
fn extract_tirith_binary(archive: &Path, target: &str, workdir: &Path) -> Result<PathBuf, String> {
    let extract_dir = workdir.join("extracted");
    std::fs::create_dir_all(&extract_dir).map_err(|e| format!("create extract dir: {e}"))?;

    let binary_name = if target.contains("windows") {
        "tirith.exe"
    } else {
        "tirith"
    };

    if target.contains("windows") {
        // `.zip` — use PowerShell's Expand-Archive (always present on Windows).
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
        // `.tar.gz` — use `tar`.
        let status = std::process::Command::new("tar")
            .arg("xzf")
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
    Ok(binary)
}

// ===========================================================================
// atomic self-replace + rollback
// ===========================================================================

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
/// Safety properties:
///   * The new binary is first copied into a temp file in `dest`'s OWN
///     directory (so the final step is a same-filesystem rename, which is
///     atomic), with executable permissions set BEFORE the rename.
///   * The current `dest` is copied to the backup path before the swap, so a
///     rollback point exists even though the swap itself never deletes the old
///     bytes.
///   * The swap is a single `rename(temp, dest)` — `dest` is never absent or
///     half-written at any instant. A reader either sees the old binary or the
///     new one.
fn atomic_self_replace(dest: &Path, new_binary: &Path) -> Result<SwapResult, String> {
    let dir = dest
        .parent()
        .ok_or_else(|| "cannot determine the binary's directory".to_string())?;

    // Refuse early if the directory is not writable: better a clean error than
    // a partial install. (The rename below would fail anyway, but this gives a
    // clearer message and never even creates a temp file.)
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

    // 3. Make the temp file executable BEFORE it becomes the live binary, so
    //    there is never an instant where `tirith` exists but is not runnable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("could not set executable permissions: {e}"))?;
    }

    // 4. Atomic rename over the live binary.
    tmp.persist(dest).map_err(|e| {
        // The rename failed. The old binary is still in place (rename does not
        // touch dest until it succeeds) and the backup exists; report cleanly.
        format!(
            "could not atomically replace {}: {} (the old binary is intact)",
            dest.display(),
            e.error
        )
    })?;

    Ok(SwapResult {
        previous_backup: backup,
    })
}

/// Atomically install the bytes of `source` onto `dest`, used by `--rollback`.
///
/// Unlike [`atomic_self_replace`] this takes NO backup: rollback's `source` is
/// the backup, and [`atomic_self_replace`] would clobber that very file as its
/// first step (it backs `dest` up to `previous_backup_path(dest)`, which the
/// rollback caller passes as `source`). `atomic_restore_from` reads `source`
/// fully into memory up front, so even if `source` and `previous_backup_path`
/// coincide the restored bytes are correct, and the atomic rename is the only
/// thing that touches `dest`.
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

    // Read the source bytes up front: after this point `source` may be freely
    // overwritten or deleted without affecting the restore.
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
    tmp.persist(dest).map_err(|e| {
        format!(
            "could not atomically restore {}: {} (the current binary is intact)",
            dest.display(),
            e.error
        )
    })?;
    Ok(())
}

/// Best-effort writability probe for a directory: try to create and delete a
/// temp file in it. A `false` here lets `atomic_self_replace` fail with a
/// helpful message instead of a raw rename error.
fn dir_is_writable(dir: &Path) -> bool {
    tempfile::Builder::new()
        .prefix(".tirith-wtest-")
        .tempfile_in(dir)
        .is_ok()
}

// ===========================================================================
// small shared helpers
// ===========================================================================

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

/// Write `bytes` to `path` (plain, non-atomic — used only for files inside a
/// freshly-created private temp dir).
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

    /// `atomic_self_replace` swaps the binary AND keeps a recoverable backup.
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

    /// After a swap, restoring from the backup via `atomic_restore_from`
    /// recovers the original binary — the property `--rollback` depends on.
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

    /// REGRESSION: `atomic_restore_from` must restore the SOURCE bytes even
    /// when `source` is exactly `previous_backup_path(dest)` — which is the
    /// rollback case. Using `atomic_self_replace` here would clobber the
    /// source with the live bytes first and "restore" the wrong thing.
    #[test]
    fn atomic_restore_from_does_not_clobber_source_at_backup_path() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("tirith");
        std::fs::write(&live, b"CURRENT-BYTES").unwrap();
        // The rollback source IS the conventional backup path next to `live`.
        let backup = previous_backup_path(&live);
        std::fs::write(&backup, b"PREVIOUS-BYTES").unwrap();

        atomic_restore_from(&live, &backup).unwrap();

        // The live binary must hold the PREVIOUS bytes, not the current ones.
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
        // The new file is deliberately NOT executable before the swap.
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
        // SHA-256 of the empty string.
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

    /// `verify_archive_against_checksums` returns `Failed` when the archive
    /// bytes do not match the digest in checksums.txt — a tampered download.
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

    /// When the archive bytes DO match checksums.txt and no signature was
    /// published, the verdict is `Ok` with `ChecksumOnly` strength — an honest
    /// "checksum verified, signature not checked".
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
            ArchiveVerdict::Ok { signed } => {
                assert_eq!(signed, ChecksumStrength::ChecksumOnly);
            }
            _ => panic!("expected Ok(ChecksumOnly), got a different verdict"),
        }
    }

    /// A checksums.txt with no entry for the archive yields `ChecksumMissing`
    /// (an honest "cannot verify"), never a false pass.
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

    /// `local_verification_status` for a dev build is always Unverified with a
    /// dev-build reason — never a confident pass.
    #[test]
    fn local_status_dev_build_is_unverified() {
        let prov = Provenance {
            version: "0.3.1".to_string(),
            binary_path: Some(PathBuf::from("/src/tirith/target/release/tirith")),
            binary_sha256: Some("a".repeat(64)),
            install_method: InstallMethod::Unknown,
            target: Some("x86_64-unknown-linux-gnu".to_string()),
            dev_build: true,
        };
        let status = local_verification_status(&prov);
        assert_eq!(status.token(), "unverified");
        assert!(matches!(status, VerificationStatus::Unverified { .. }));
    }

    /// `run_verify_self` for a dev build short-circuits to Unverified WITHOUT
    /// any network access — the honest-failure path the spec calls out.
    #[test]
    fn verify_self_dev_build_short_circuits_offline() {
        let prov = Provenance {
            version: "0.3.1".to_string(),
            binary_path: Some(PathBuf::from("/home/dev/tirith/target/release/tirith")),
            binary_sha256: Some("b".repeat(64)),
            install_method: InstallMethod::SelfManaged,
            target: Some("x86_64-unknown-linux-gnu".to_string()),
            dev_build: true,
        };
        // No network is touched because dev_build is checked first.
        let status = run_verify_self(&prov);
        assert!(matches!(status, VerificationStatus::Unverified { .. }));
        assert_eq!(status.token(), "unverified");
    }

    /// `run_verify_self` for an unpublished platform short-circuits to
    /// Unverified, again without network.
    #[test]
    fn verify_self_unpublished_platform_short_circuits() {
        let prov = Provenance {
            version: "0.3.1".to_string(),
            binary_path: Some(PathBuf::from("/usr/bin/tirith")),
            binary_sha256: Some("c".repeat(64)),
            install_method: InstallMethod::Unknown,
            target: None, // unpublished platform
            dev_build: false,
        };
        let status = run_verify_self(&prov);
        assert!(matches!(status, VerificationStatus::Unverified { .. }));
    }

    /// `extract_tirith_binary` round-trips a real tar.gz on Unix: it must find
    /// the `tirith` member and return a path whose bytes match.
    #[cfg(unix)]
    #[test]
    fn extract_tirith_binary_finds_member_in_targz() {
        let dir = tempfile::tempdir().unwrap();
        // Build a tiny tar.gz containing a `tirith` file plus a decoy.
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

    /// `extract_tirith_binary` errors when the archive has no `tirith` member.
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
