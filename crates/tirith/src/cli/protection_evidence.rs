//! Evidence vocabulary shared by CLI projections. Configuration and inherited
//! process environment are never a successful live blocking observation.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProtectionState {
    Configured,
    ActivationRequired,
    ObservedBlocking,
    WarnOnly,
    Degraded,
    Off,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProtectionEvidence {
    pub schema_version: u32,
    pub surface: String,
    pub state: ProtectionState,
    pub source: String,
    pub observed_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub fresh: bool,
    pub verified_blocking: bool,
    pub invalidation_reason: Option<String>,
    /// Reported by init-generated activation code; inherited values are not a
    /// live observation of this process and never confer verified blocking.
    pub reported_integration_version: Option<String>,
    pub reported_integration_shell: Option<String>,
    pub integration_version_source: &'static str,
}

impl ProtectionEvidence {
    /// The only promotion route consumes core's opaque in-process capability.
    /// Revalidation happens after the canonical status capture, not while its
    /// potentially slower configuration and threat database reads are pending.
    pub(crate) fn from_authenticated_shell(
        proof: tirith_core::execution_state::ShellVerificationProof,
    ) -> (
        tirith_core::execution_state::ShellVerificationObservation,
        Self,
    ) {
        let mut observation = proof.into_current_observation();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_millis() as u64)
            .unwrap_or(0);
        if observation.status
            == tirith_core::execution_state::ShellVerificationStatus::ObservedBlocking
            && (observation.observed_unix_ms.is_none_or(|at| at > now)
                || observation.expires_unix_ms <= now)
        {
            observation.status = if observation.expires_unix_ms <= now {
                tirith_core::execution_state::ShellVerificationStatus::Expired
            } else {
                tirith_core::execution_state::ShellVerificationStatus::Stale
            };
        }
        let mut evidence = Self::from_report(&observation);
        if observation.status
            == tirith_core::execution_state::ShellVerificationStatus::ObservedBlocking
            && observation.observed_unix_ms.is_some_and(|at| at <= now)
            && observation.expires_unix_ms > now
        {
            evidence.state = ProtectionState::ObservedBlocking;
            evidence.fresh = true;
            evidence.verified_blocking = true;
            evidence.invalidation_reason = None;
        }
        (observation, evidence)
    }

    /// Report DTOs retain their diagnostic detail, but cannot confer authority.
    pub(crate) fn from_report(
        observation: &tirith_core::execution_state::ShellVerificationObservation,
    ) -> Self {
        use tirith_core::execution_state::ShellVerificationStatus;
        let mut evidence = Self::configuration("guarded", true, true);
        evidence.source = observation.source.into();
        evidence.observed_at = observation.observed_unix_ms.map(|at| at / 1000);
        evidence.expires_at = Some(observation.expires_unix_ms / 1000);
        evidence.state = ProtectionState::Unknown;
        evidence.invalidation_reason = Some(
            match observation.status {
                ShellVerificationStatus::Pending => {
                    "caller-shell diagnostic sequence is incomplete"
                }
                ShellVerificationStatus::Failed => "caller-shell diagnostic sequence failed",
                ShellVerificationStatus::Stale => {
                    "shell, loaded hook, configuration, policy or projection context changed"
                }
                ShellVerificationStatus::Expired => "caller-shell observation expired",
                ShellVerificationStatus::ObservedBlocking => {
                    "a report alone cannot establish fresh authenticated caller-shell blocking"
                }
            }
            .into(),
        );
        evidence
    }

    pub(crate) fn configuration(mode: &str, configured: bool, observable: bool) -> Self {
        let state = match mode {
            "warn-only" => ProtectionState::WarnOnly,
            "degraded" => ProtectionState::Degraded,
            // The legacy "off" label also represents an absent/nonexported
            // signal; an external process cannot infer missing activation.
            "off" if configured => ProtectionState::Configured,
            "off" if observable => ProtectionState::Off,
            "guarded" if configured => ProtectionState::Configured,
            _ => ProtectionState::Unknown,
        };
        Self {
            schema_version: 1,
            surface: "current-shell".into(),
            state,
            source: if matches!(mode, "guarded" | "warn-only" | "degraded") {
                "inherited-environment-unverified"
            } else {
                "startup-configuration"
            }
            .into(),
            observed_at: None,
            expires_at: None,
            fresh: false,
            verified_blocking: false,
            invalidation_reason: Some(
                "no allow-and-block observation for this shell process and current configuration"
                    .into(),
            ),
            reported_integration_version: reported_version(),
            reported_integration_shell: std::env::var("TIRITH_INTEGRATION_SHELL").ok().filter(
                |shell| {
                    matches!(
                        shell.as_str(),
                        "bash" | "zsh" | "fish" | "powershell" | "pwsh" | "nushell"
                    )
                },
            ),
            integration_version_source: "inherited-environment-unverified",
        }
    }
}

fn reported_version() -> Option<String> {
    std::env::var("TIRITH_INTEGRATION_VERSION")
        .ok()
        .filter(|version| {
            version == "unknown"
                || (!version.is_empty()
                    && version.len() <= 64
                    && version
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'+')))
        })
}

pub(crate) fn gather(mode: &str, configured: bool) -> ProtectionEvidence {
    let observable = super::shell_target::resolve_current().is_ok_and(|target| {
        target.unsupported_reason.is_none() && target.identity_source == "observed-ancestor-process"
    });
    ProtectionEvidence::configuration(mode, configured, observable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_core::execution_state::{
        ShellHookFamily, ShellVerificationObservation, ShellVerificationStatus,
    };
    fn observation() -> ShellVerificationObservation {
        ShellVerificationObservation {
            schema_version: 1,
            challenge_id: "85d25009-90d2-4f47-8258-df5976567a7b".into(),
            family: ShellHookFamily::Bash,
            status: ShellVerificationStatus::ObservedBlocking,
            observed_unix_ms: Some(100_000),
            expires_unix_ms: 160_000,
            source: "authenticated_caller_shell",
            scope: "current_shell_only",
        }
    }
    #[test]
    fn absent_exported_signal_does_not_prove_missing_activation() {
        let evidence = ProtectionEvidence::configuration("off", true, true);
        assert_eq!(evidence.state, ProtectionState::Configured);
        assert!(!evidence.verified_blocking);
    }
    #[test]
    fn inherited_blocking_even_with_configuration_cannot_verify() {
        let evidence = ProtectionEvidence::configuration("guarded", true, true);
        assert_eq!(evidence.state, ProtectionState::Configured);
        assert!(!evidence.verified_blocking);
        assert!(!evidence.fresh);
    }
    #[test]
    fn public_report_dto_cannot_promote_current_or_saved_success() {
        let mut observation = observation();
        for status in [
            ShellVerificationStatus::Pending,
            ShellVerificationStatus::Failed,
            ShellVerificationStatus::Stale,
            ShellVerificationStatus::Expired,
            ShellVerificationStatus::ObservedBlocking,
        ] {
            observation.status = status;
            let report = ProtectionEvidence::from_report(&observation);
            assert!(!report.verified_blocking && !report.fresh);
            assert_ne!(report.state, ProtectionState::ObservedBlocking);
            assert!(report.invalidation_reason.is_some());
        }
        observation.observed_unix_ms = Some(0);
        observation.expires_unix_ms = u64::MAX;
        assert!(!ProtectionEvidence::from_report(&observation).verified_blocking);
    }
    #[test]
    fn disposable_or_unauthenticated_result_cannot_certify_the_caller() {
        let mut value = observation();
        value.scope = "disposable_child_only";
        assert!(!ProtectionEvidence::from_report(&value).verified_blocking);
        value.scope = "current_shell_only";
        value.source = "inherited_environment";
        assert!(!ProtectionEvidence::from_report(&value).verified_blocking);
    }
}
