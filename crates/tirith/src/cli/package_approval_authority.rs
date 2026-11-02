//! User-side availability probe for the OS-native package-approval authority.
//!
//! `tirith pkg approve` checks this first so a host without the native
//! prerequisites keeps reporting phase `native_authority`, and `tirith status`
//! reports the same metadata. The probe never invokes sudo or the helper and
//! never creates authority state. Issuing approvals was removed together with
//! contained package execution, which was their only consumer.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::path::{Path, PathBuf};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::package_approval_authority_native::validate_root_owned_executable;
pub(crate) use super::package_approval_authority_native::NativeAuthorityError;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const HELPER_CANDIDATES: &[&str] = &[
    "/usr/libexec/tirith-package-approval-authority",
    "/usr/local/libexec/tirith-package-approval-authority",
    "/usr/local/bin/tirith-package-approval-authority",
];

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct PackageApprovalAvailability {
    pub state: &'static str,
    pub platform_supported: bool,
    pub trusted_sudo_present: bool,
    pub trusted_helper_present: bool,
    pub automatic_elevation: bool,
    pub ordinary_protection_requires_sudo: bool,
    pub detail: &'static str,
    pub next_action: &'static str,
}

impl PackageApprovalAvailability {
    fn from_prerequisites(platform: bool, sudo: bool, helper: bool) -> Self {
        // `pkg approve` refuses after this check in every state (contained
        // package execution, the only consumer of approvals, is disabled), so
        // no state may suggest that sudo, the helper, or approve itself would
        // issue an approval. The state names are part of the status schema.
        let (state, detail, next_action) = if !platform {
            (
                "unsupported",
                "package approvals are redeemable only on x86_64 Linux, and tirith pkg approve issues no approvals in this release on any platform.",
                "No action needed: command checks and shell protection remain available. Contained package execution is disabled, so moving to another host does not enable it.",
            )
        } else if !sudo {
            (
                "unavailable",
                "Native package-approval issuance is off: trusted /usr/bin/sudo is unavailable, and tirith pkg approve issues no approvals in this release. Command checks and shell protection do not require sudo.",
                "No action needed: contained package execution is disabled, so installing sudo or the protected approval helper does not enable it.",
            )
        } else if !helper {
            (
                "unavailable",
                "Native package-approval issuance is off: the protected approval helper is unavailable, and tirith pkg approve issues no approvals in this release. Command checks and shell protection do not require it.",
                "No action needed: contained package execution is disabled, so installing the protected approval helper does not enable it.",
            )
        } else {
            (
                "available_on_explicit_request",
                "Native approval prerequisites are present, but tirith pkg approve issues no approvals in this release; nothing runs or elevates automatically.",
                "No action needed: pkg approve validates its request and then refuses with private_input_execution_unqualified without prompting for sudo or calling the helper. Contained package execution is disabled; having the helper and sudo does not enable it.",
            )
        };
        Self {
            state,
            platform_supported: platform,
            trusted_sudo_present: platform && sudo,
            trusted_helper_present: platform && helper,
            automatic_elevation: false,
            ordinary_protection_requires_sudo: false,
            detail,
            next_action,
        }
    }

    pub(crate) fn require_explicit_issuance(&self) -> Result<(), NativeAuthorityError> {
        if self.state == "available_on_explicit_request" {
            Ok(())
        } else {
            Err(NativeAuthorityError::blocked(format!(
                "{} {}",
                self.detail, self.next_action
            )))
        }
    }
}

/// Metadata validation only: never invokes sudo/helper or creates authority state.
pub(crate) fn availability() -> PackageApprovalAvailability {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        PackageApprovalAvailability::from_prerequisites(
            true,
            validate_approval_sudo(Path::new("/usr/bin/sudo")).is_ok(),
            find_installed_helper().is_ok(),
        )
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    PackageApprovalAvailability::from_prerequisites(false, false, false)
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

#[cfg(test)]
mod availability_tests {
    use super::PackageApprovalAvailability;

    #[test]
    fn capability_is_explicit_and_missing_prerequisites_do_not_disable_protection() {
        for platform in [false, true] {
            for sudo in [false, true] {
                for helper in [false, true] {
                    let report =
                        PackageApprovalAvailability::from_prerequisites(platform, sudo, helper);
                    assert!(!report.automatic_elevation);
                    assert!(!report.ordinary_protection_requires_sudo);
                    assert_eq!(
                        report.require_explicit_issuance().is_ok(),
                        platform && sudo && helper
                    );
                    if platform && !sudo {
                        assert!(report.detail.contains("off"));
                        assert!(report.detail.contains("/usr/bin/sudo"));
                    }
                }
            }
        }
    }

    /// `pkg approve` refuses in every state, so the availability metadata
    /// (printed by `status --json`, `doctor`, the control API and approve's own
    /// native_authority error) must never tell the operator that installing
    /// sudo or the helper, or running approve, will issue an approval.
    #[test]
    fn every_state_says_approve_issues_no_approvals_and_nothing_enables_it() {
        for platform in [false, true] {
            for sudo in [false, true] {
                for helper in [false, true] {
                    let report =
                        PackageApprovalAvailability::from_prerequisites(platform, sudo, helper);
                    let text = format!("{} {}", report.detail, report.next_action);
                    assert!(
                        text.contains("tirith pkg approve issues no approvals"),
                        "{text}"
                    );
                    assert!(text.contains("does not enable it"), "{text}");
                    for stale in [
                        "Only if you need",
                        "Run tirith pkg approve",
                        "use a supported x86_64 Linux host for native package approvals",
                        "sudo password confirmation are required",
                        "Fresh administrator confirmation is still required",
                    ] {
                        assert!(!text.contains(stale), "stale guidance {stale:?}: {text}");
                    }
                }
            }
        }
    }
}
