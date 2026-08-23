//! Privileged half of the package-approval authority protocol.

#[cfg(unix)]
use tirith_core::artifact::install::InstallPlanDigest;
use tirith_core::package_approval::PackageApprovalRecordV2;

use crate::package_approval_authority_native::NativeAuthorityError;
#[cfg(unix)]
use crate::package_approval_authority_native::{
    load_trusted_keys, open_no_follow, validate_admin_hierarchy, validate_root_owned_executable,
    TRUSTED_KEYS_PATH,
};

#[cfg(unix)]
use std::io::{Read as _, Write as _};
#[cfg(unix)]
use std::path::Path;

#[cfg(target_os = "macos")]
const AUTHORITY_ROOT: &str = "/Library/Application Support/Tirith/package-approval";
#[cfg(target_os = "macos")]
const PRIVATE_KEY_PATH: &str = "/Library/Application Support/Tirith/package-approval/authority.key";
#[cfg(all(unix, not(target_os = "macos")))]
const AUTHORITY_ROOT: &str = "/etc/tirith/package-approval";
#[cfg(all(unix, not(target_os = "macos")))]
const PRIVATE_KEY_PATH: &str = "/etc/tirith/package-approval/authority.key";

const HELPER_NAME: &str = "tirith-package-approval-authority";
#[cfg(unix)]
const NOPASSWD_PROBE_EXIT: i32 = 42;
#[cfg(unix)]
const HELPER_REQUEST_CAP: u64 = 128 * 1024;
#[cfg(unix)]
const PUBLIC_KEY_CAP: u64 = 128;

#[cfg(unix)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperRequest {
    digest: InstallPlanDigest,
}

pub(crate) fn helper_main() -> i32 {
    #[cfg(unix)]
    if std::env::args().nth(1).as_deref() == Some("auth-probe") {
        return helper_auth_probe();
    }
    match helper_issue() {
        Ok(record) => match record.to_json_pretty() {
            Ok(json) => {
                println!("{json}");
                0
            }
            Err(error) => {
                eprintln!("{HELPER_NAME}: {error}");
                1
            }
        },
        Err(error) => {
            eprintln!("{HELPER_NAME}: {error}");
            1
        }
    }
}

#[cfg(unix)]
fn helper_auth_probe() -> i32 {
    if unsafe { libc::geteuid() } != 0 {
        return 1;
    }
    let Ok(executable) = std::env::current_exe() else {
        return 1;
    };
    if validate_root_owned_executable(&executable).is_err() {
        return 1;
    }
    NOPASSWD_PROBE_EXIT
}

#[cfg(unix)]
fn helper_issue() -> Result<PackageApprovalRecordV2, NativeAuthorityError> {
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        Err(NativeAuthorityError::blocked(
            "package approval issuance is supported only for redeemable x86_64 Linux installs",
        ))
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        if std::env::args().nth(1).as_deref() != Some("issue") {
            return Err(NativeAuthorityError::blocked(
                "unsupported helper operation",
            ));
        }
        if unsafe { libc::geteuid() } != 0 {
            return Err(NativeAuthorityError::blocked(
                "native authority must execute as root",
            ));
        }
        let executable = std::env::current_exe().map_err(|_| {
            NativeAuthorityError::blocked("cannot identify native authority executable")
        })?;
        validate_root_owned_executable(&executable)?;

        let mut bytes = Vec::new();
        std::io::stdin()
            .take(HELPER_REQUEST_CAP + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| NativeAuthorityError::blocked("could not read approval request"))?;
        if bytes.len() as u64 > HELPER_REQUEST_CAP {
            return Err(NativeAuthorityError::blocked(
                "package approval request exceeds the helper limit",
            ));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| NativeAuthorityError::blocked("package approval request is malformed"))?;
        let value = tirith_core::mcp_lock::parse_json_no_duplicates(text)
            .map_err(|_| NativeAuthorityError::blocked("package approval request is malformed"))?;
        let request: HelperRequest = serde_json::from_value(value.clone())
            .map_err(|_| NativeAuthorityError::blocked("package approval request is malformed"))?;
        if serde_json::to_value(&request)
            .map_err(|_| NativeAuthorityError::blocked("package approval request is malformed"))?
            != value
        {
            return Err(NativeAuthorityError::blocked(
                "package approval request contains non-canonical fields",
            ));
        }
        if !request.digest.expiry.is_empty() || !request.digest.digest_matches() {
            return Err(NativeAuthorityError::blocked(
                "package approval request must be content-bound and expiry-independent",
            ));
        }
        confirm_exact_plan(&request.digest)?;
        let signing_key = load_or_create_authority_key()?;
        let issued = chrono::Utc::now();
        let issued_at = issued.to_rfc3339();
        let expires_at = (issued
            + chrono::Duration::seconds(
                tirith_core::package_approval::MAX_PACKAGE_APPROVAL_LIFETIME_SECS,
            ))
        .to_rfc3339();
        let mut signed_digest = request.digest;
        signed_digest.expiry = expires_at.clone();
        signed_digest.plan_digest = signed_digest.compute_plan_digest();
        PackageApprovalRecordV2::issue(signed_digest, &issued_at, &expires_at, &signing_key)
            .map_err(|error| NativeAuthorityError::blocked(error.to_string()))
    }
}

#[cfg(all(unix, target_os = "linux", target_arch = "x86_64"))]
fn confirm_exact_plan(digest: &InstallPlanDigest) -> Result<(), NativeAuthorityError> {
    use std::io::BufRead as _;

    let projection = tirith_core::package_approval::package_approval_plan_projection(digest)
        .map_err(|_| NativeAuthorityError::blocked("could not render the exact approval plan"))?;
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| {
            NativeAuthorityError::blocked(
                "independent administrator confirmation terminal is unavailable",
            )
        })?;
    writeln!(
        tty,
        "Tirith privileged package approval request:\n{projection}\n\nApprove this exact plan? Type `approve` to continue:"
    )
    .and_then(|()| tty.flush())
    .map_err(|_| NativeAuthorityError::blocked("could not display the approval plan"))?;
    let mut answer = String::new();
    let mut reader = std::io::BufReader::new(
        tty.try_clone()
            .map_err(|_| NativeAuthorityError::blocked("could not bind the approval terminal"))?,
    );
    reader
        .read_line(&mut answer)
        .map_err(|_| NativeAuthorityError::blocked("administrator confirmation failed"))?;
    if answer.trim() != "approve" {
        return Err(NativeAuthorityError::blocked(
            "administrator did not approve the exact package plan",
        ));
    }
    Ok(())
}

#[cfg(all(unix, not(all(target_os = "linux", target_arch = "x86_64"))))]
fn confirm_exact_plan(_digest: &InstallPlanDigest) -> Result<(), NativeAuthorityError> {
    Err(NativeAuthorityError::blocked(
        "package approval issuance is supported only for redeemable x86_64 Linux installs",
    ))
}

#[cfg(not(unix))]
fn helper_issue() -> Result<PackageApprovalRecordV2, NativeAuthorityError> {
    Err(NativeAuthorityError::blocked(
        "the package approval authority is unsupported on this platform",
    ))
}

#[cfg(unix)]
fn load_or_create_authority_key() -> Result<ed25519_dalek::SigningKey, NativeAuthorityError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    #[cfg(target_os = "macos")]
    ensure_admin_directory(Path::new("/Library/Application Support/Tirith"), 0o755)?;
    #[cfg(not(target_os = "macos"))]
    ensure_admin_directory(Path::new("/etc/tirith"), 0o755)?;
    ensure_admin_directory(Path::new(AUTHORITY_ROOT), 0o755)?;
    ensure_admin_directory(Path::new(TRUSTED_KEYS_PATH), 0o755)?;

    let key_path = Path::new(PRIVATE_KEY_PATH);
    let secret = match open_no_follow(key_path, 32) {
        Ok(mut file) => {
            let metadata = file.metadata().map_err(|_| {
                NativeAuthorityError::blocked("authority private-key metadata failed")
            })?;
            if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
                return Err(NativeAuthorityError::blocked(
                    "authority private-key permissions are unsafe",
                ));
            }
            let mut secret = [0_u8; 32];
            file.read_exact(&mut secret).map_err(|_| {
                NativeAuthorityError::blocked("authority private key could not be read")
            })?;
            secret
        }
        Err(_) if !key_path.exists() => {
            let (secret, _) = tirith_core::command_card::generate_keypair()
                .map_err(|_| NativeAuthorityError::blocked("authority key generation failed"))?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(key_path)
                .map_err(|_| NativeAuthorityError::blocked("authority key creation failed"))?;
            file.write_all(&secret)
                .and_then(|()| file.sync_all())
                .map_err(|_| NativeAuthorityError::blocked("authority key persistence failed"))?;
            secret
        }
        Err(error) => return Err(error),
    };
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let public = signing_key.verifying_key().to_bytes();
    let key_id = tirith_core::command_card::key_id_for_pubkey(&public);
    let public_path = Path::new(TRUSTED_KEYS_PATH).join(format!("{key_id}.pub"));
    if public_path.exists() {
        let mut file = open_no_follow(&public_path, PUBLIC_KEY_CAP)?;
        let mut installed = Vec::new();
        file.read_to_end(&mut installed)
            .map_err(|_| NativeAuthorityError::blocked("authority public key could not be read"))?;
        if installed.as_slice() != public.as_slice() {
            return Err(NativeAuthorityError::blocked(
                "installed authority public key does not match the private key",
            ));
        }
    } else {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&public_path)
            .map_err(|_| NativeAuthorityError::blocked("authority public-key creation failed"))?;
        file.write_all(&public)
            .and_then(|()| file.sync_all())
            .map_err(|_| {
                NativeAuthorityError::blocked("authority public-key persistence failed")
            })?;
        std::fs::set_permissions(&public_path, std::fs::Permissions::from_mode(0o644))
            .map_err(|_| NativeAuthorityError::blocked("authority public-key mode failed"))?;
    }
    load_trusted_keys(Path::new(TRUSTED_KEYS_PATH), 0)?;
    Ok(signing_key)
}

#[cfg(unix)]
fn ensure_admin_directory(path: &Path, mode: u32) -> Result<(), NativeAuthorityError> {
    use std::os::unix::fs::PermissionsExt as _;

    if !path.exists() {
        std::fs::create_dir(path)
            .map_err(|_| NativeAuthorityError::blocked("authority directory creation failed"))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|_| NativeAuthorityError::blocked("authority directory mode failed"))?;
    }
    validate_admin_hierarchy(path, 0)
}

#[cfg(all(test, unix))]
mod tests {
    use super::HelperRequest;

    #[test]
    fn helper_wire_rejects_unsigned_and_unknown_fields() {
        let unsigned = br#"{"digest":{}}"#;
        assert!(serde_json::from_slice::<HelperRequest>(unsigned).is_err());
        let extra = br#"{"digest":{},"extra":true}"#;
        assert!(serde_json::from_slice::<HelperRequest>(extra).is_err());
    }
}
