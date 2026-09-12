//! User-side client for the OS-native package-approval authority.
//!
//! The interactive CLI never owns the signing key. It invokes one fixed,
//! root-owned helper through a fixed `sudo`, after invalidating cached sudo
//! credentials. Missing native guarantees return `blocked_native`; there is no
//! user-owned-key or unsigned fallback.

use std::collections::BTreeMap;

#[cfg(unix)]
use std::io::IsTerminal as _;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::io::Write as _;
#[cfg(unix)]
use std::path::Path;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::path::PathBuf;

use tirith_core::artifact::install::InstallPlanDigest;
use tirith_core::package_approval::PackageApprovalRecordV2;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::package_approval_authority_native::validate_root_owned_executable;
pub(crate) use super::package_approval_authority_native::NativeAuthorityError;
#[cfg(unix)]
use super::package_approval_authority_native::{load_trusted_keys, TRUSTED_KEYS_PATH};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const HELPER_REQUEST_CAP: u64 = 128 * 1024;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const NOPASSWD_PROBE_EXIT: i32 = 42;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const HELPER_CANDIDATES: &[&str] = &[
    "/usr/libexec/tirith-package-approval-authority",
    "/usr/local/libexec/tirith-package-approval-authority",
    "/usr/local/bin/tirith-package-approval-authority",
];

pub(crate) trait PackageApprovalIssuer {
    fn issue(
        &self,
        digest: &InstallPlanDigest,
    ) -> Result<PackageApprovalRecordV2, NativeAuthorityError>;
}

pub(crate) trait PackageApprovalKeyProvider {
    fn trusted_keys(&self) -> Result<BTreeMap<String, [u8; 32]>, NativeAuthorityError>;
}

pub(crate) trait PackageApprovalAuthority:
    PackageApprovalIssuer + PackageApprovalKeyProvider
{
}

impl<T> PackageApprovalAuthority for T where T: PackageApprovalIssuer + PackageApprovalKeyProvider {}

pub(crate) struct NativePackageApprovalAuthority;

#[cfg(unix)]
impl PackageApprovalIssuer for NativePackageApprovalAuthority {
    fn issue(
        &self,
        digest: &InstallPlanDigest,
    ) -> Result<PackageApprovalRecordV2, NativeAuthorityError> {
        if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            return Err(NativeAuthorityError::blocked(
                "package approval requires a fresh interactive administrator confirmation",
            ));
        }
        if unsafe { libc::geteuid() } == 0 {
            return Err(NativeAuthorityError::blocked(
                "package approval must originate from a non-root operator session",
            ));
        }
        if !digest.expiry.is_empty() || !digest.digest_matches() {
            return Err(NativeAuthorityError::blocked(
                "the package approval request must be content-bound and expiry-independent",
            ));
        }

        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            Err(NativeAuthorityError::blocked(
                "package approval issuance is supported only for redeemable x86_64 Linux installs",
            ))
        }

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let helper = find_installed_helper()?;
            let sudo = Path::new("/usr/bin/sudo");
            validate_approval_sudo(sudo)?;

            let invalidated = std::process::Command::new(sudo)
                .arg("-k")
                .status()
                .map_err(|_| {
                    NativeAuthorityError::blocked("could not invoke the native authority")
                })?;
            if !invalidated.success() {
                return Err(NativeAuthorityError::blocked(
                    "could not invalidate cached administrator presence",
                ));
            }

            // A cached credential was invalidated above. If the exact installed
            // helper can still execute non-interactively, sudoers grants it through
            // NOPASSWD and therefore cannot establish fresh administrator presence.
            // The probe has no persistence or signing path in the helper.
            let nopasswd_probe = std::process::Command::new(sudo)
                .arg("-n")
                .arg("--")
                .arg(&helper)
                .arg("auth-probe")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map_err(|_| {
                    NativeAuthorityError::blocked("could not probe administrator policy")
                })?;
            if nopasswd_probe.code() == Some(NOPASSWD_PROBE_EXIT) {
                return Err(NativeAuthorityError::blocked(
                    "NOPASSWD is not an acceptable package-approval authority channel",
                ));
            }

            #[derive(serde::Serialize)]
            struct HelperRequest<'a> {
                digest: &'a InstallPlanDigest,
            }
            let request = serde_json::to_vec(&HelperRequest { digest }).map_err(|_| {
                NativeAuthorityError::blocked("could not encode the approval request")
            })?;
            if request.len() as u64 > HELPER_REQUEST_CAP {
                return Err(NativeAuthorityError::blocked(
                    "package approval request exceeds the native authority limit",
                ));
            }

            let mut child = std::process::Command::new(sudo)
                .arg("--")
                .arg(&helper)
                .arg("issue")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit())
                .spawn()
                .map_err(|_| {
                    NativeAuthorityError::blocked("could not start the native authority")
                })?;
            child
                .stdin
                .take()
                .ok_or_else(|| {
                    NativeAuthorityError::blocked("native authority input was unavailable")
                })?
                .write_all(&request)
                .map_err(|_| NativeAuthorityError::blocked("native authority request failed"))?;
            let output = child
                .wait_with_output()
                .map_err(|_| NativeAuthorityError::blocked("native authority did not complete"))?;
            if !output.status.success() || output.stdout.len() as u64 > HELPER_REQUEST_CAP {
                return Err(NativeAuthorityError::blocked(
                    "administrator approval was refused or the native authority failed",
                ));
            }
            PackageApprovalRecordV2::from_json(&output.stdout).map_err(|_| {
                NativeAuthorityError::blocked("native authority returned invalid proof")
            })
        }
    }
}

#[cfg(not(unix))]
impl PackageApprovalIssuer for NativePackageApprovalAuthority {
    fn issue(
        &self,
        _digest: &InstallPlanDigest,
    ) -> Result<PackageApprovalRecordV2, NativeAuthorityError> {
        Err(NativeAuthorityError::blocked(
            "the package approval authority is unsupported on this platform",
        ))
    }
}

#[cfg(unix)]
impl PackageApprovalKeyProvider for NativePackageApprovalAuthority {
    fn trusted_keys(&self) -> Result<BTreeMap<String, [u8; 32]>, NativeAuthorityError> {
        load_trusted_keys(Path::new(TRUSTED_KEYS_PATH), 0)
    }
}

#[cfg(not(unix))]
impl PackageApprovalKeyProvider for NativePackageApprovalAuthority {
    fn trusted_keys(&self) -> Result<BTreeMap<String, [u8; 32]>, NativeAuthorityError> {
        Err(NativeAuthorityError::blocked(
            "the package approval authority is unsupported on this platform",
        ))
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn find_installed_helper() -> Result<PathBuf, NativeAuthorityError> {
    for candidate in HELPER_CANDIDATES {
        let path = Path::new(candidate);
        if path.exists() && validate_root_owned_executable(path).is_ok() {
            return Ok(path.to_path_buf());
        }
    }
    Err(NativeAuthorityError::blocked(
        "the fixed root-owned package approval helper is not installed",
    ))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn validate_approval_sudo(path: &Path) -> Result<(), NativeAuthorityError> {
    validate_root_owned_executable(path).map_err(|_| {
        NativeAuthorityError::blocked(
            "package approval requires a trusted /usr/bin/sudo for fresh administrator confirmation; ordinary command checks do not require sudo",
        )
    })
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod sudo_tests {
    use super::validate_approval_sudo;

    #[test]
    fn unavailable_sudo_blocks_only_the_approval_authority() {
        let directory = tempfile::tempdir().unwrap();
        let error = validate_approval_sudo(&directory.path().join("sudo")).unwrap_err();
        let message = error.to_string();
        assert!(message.starts_with("blocked_native:"));
        assert!(message.contains("trusted /usr/bin/sudo"));
        assert!(message.contains("ordinary command checks do not require sudo"));
    }

    #[test]
    fn untrusted_sudo_placeholder_cannot_satisfy_the_approval_authority() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sudo");
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(validate_approval_sudo(&path)
            .unwrap_err()
            .to_string()
            .starts_with("blocked_native:"));
    }
}

#[cfg(all(test, not(unix)))]
mod tests {
    use super::{NativePackageApprovalAuthority, PackageApprovalKeyProvider as _};

    #[test]
    fn unsupported_platform_is_explicitly_blocked_native() {
        let authority = NativePackageApprovalAuthority;
        assert!(authority
            .trusted_keys()
            .unwrap_err()
            .to_string()
            .starts_with("blocked_native:"));
    }
}
