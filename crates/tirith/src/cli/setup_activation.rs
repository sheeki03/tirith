//! Automatic inert bodies have a separate core route. They cannot create an
//! attempt, complete manual verification, or render authenticated current status.

mod receipt;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod coordinator;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod native_modules;

/// The exact argv matcher and main-thread self deadline must precede this call.
pub(crate) fn run_receipt(action: super::automatic_deadline::ReceiptAction) -> i32 {
    receipt::run(action)
}

pub(crate) fn run_coordinator(argv: &[std::ffi::OsString]) -> i32 {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        coordinator::run(argv).map_or(1, |()| 0)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = argv;
        1
    }
}

use tirith_core::execution_state::{
    self, ShellReceiptChannel, ShellVerificationProbe, ShellVerificationStatus,
};

/// Only the exact bounded internal argv is dispatched here. The core remains
/// the authority for the live automatic record, actual shell and issued stage.
pub(crate) fn run_probe(action: &str, id: &str) -> i32 {
    let result = (|| -> Result<(), String> {
        let loaded = super::shell_verification::read_fingerprint()?;
        let channel = ShellReceiptChannel::Zsh;
        if action == "status" {
            return execution_state::finish_automatic_shell_verification_status(
                id, channel, &loaded,
            );
        }
        let probe = match action {
            "allowed" => ShellVerificationProbe::Allowed,
            "blocked" => ShellVerificationProbe::Blocked,
            _ => return Err("unsupported automatic probe".into()),
        };
        let observation = execution_state::execute_automatic_shell_verification_probe(
            id, probe, channel, &loaded,
        )?;
        if action == "allowed" && observation.status == ShellVerificationStatus::Pending {
            Ok(())
        } else {
            Err("automatic diagnostic body was not permitted".into())
        }
    })();
    if result.is_ok() {
        0
    } else {
        // Internal storage/configuration errors can contain private paths. The
        // broker records the closed refusal, not this diagnostic's raw error.
        eprintln!("tirith: automatic terminal verification could not complete");
        1
    }
}
