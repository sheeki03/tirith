//! Hook-freshness readout shared by `tirith status` and `tirith doctor`: is the
//! hook loaded in this terminal the one registered by this Tirith executable?
//!
//! Bash, Zsh and Fish hooks register a private protocol-v3 capability record at
//! startup that names the executable which generated them. A record from a
//! different or replaced executable means the terminal still runs an older
//! hook. This is loaded-hook evidence only, never blocking proof: that stays
//! with `tirith doctor --verify-shell` and `tirith status
//! --require-verified-blocking`. Shells without registration (PowerShell,
//! Nushell) fall back to the inherited, unverified integration-version hint.

use tirith_core::execution_state::{HookFreshness, HookFreshnessState};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct HookFreshnessReport {
    pub this_shell: HookFreshnessState,
    /// Detected caller shell, when known.
    pub shell: Option<&'static str>,
    /// `registered_hook_capability` or `inherited_environment_unverified`.
    pub evidence: &'static str,
    /// Inherited `TIRITH_INTEGRATION_VERSION` for shells without registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inherited_integration_version: Option<String>,
    pub other_live_current: u32,
    pub other_live_stale: u32,
    pub scan_limited: bool,
    /// Always false: a loaded hook does not prove blocking.
    pub blocking_proof: bool,
}

fn registers_capability(shell: &str) -> bool {
    matches!(shell, "bash" | "zsh" | "fish")
}

pub(crate) fn gather() -> HookFreshnessReport {
    let identity = super::init::detect_shell_identity();
    let shell = (identity.shell != "unknown").then_some(identity.shell);
    let pid = identity
        .process_id
        .filter(|_| registers_capability(identity.shell));
    let inherited = super::selfupdate::inherited_integration_version();
    report(
        shell,
        pid.is_some(),
        tirith_core::execution_state::hook_freshness(pid),
        inherited,
    )
}

fn report(
    shell: Option<&'static str>,
    registered_shell: bool,
    freshness: HookFreshness,
    inherited_version: Option<String>,
) -> HookFreshnessReport {
    let (this_shell, evidence, inherited_integration_version) = if registered_shell {
        (freshness.this_shell, "registered_hook_capability", None)
    } else {
        (
            HookFreshnessState::Unknown,
            "inherited_environment_unverified",
            inherited_version,
        )
    };
    HookFreshnessReport {
        this_shell,
        shell,
        evidence,
        inherited_integration_version,
        other_live_current: freshness.other_live_current,
        other_live_stale: freshness.other_live_stale,
        scan_limited: freshness.scan_limited,
        blocking_proof: false,
    }
}

impl HookFreshnessReport {
    /// Human lines, without indentation.
    pub(crate) fn human_lines(&self) -> Vec<String> {
        let mut lines = vec![match self.this_shell {
            HookFreshnessState::Current => {
                "this terminal's hook: current (loaded, not a blocking proof)".to_string()
            }
            HookFreshnessState::Stale => {
                "this terminal's hook: stale: open a new terminal to load the upgraded hook"
                    .to_string()
            }
            HookFreshnessState::Unregistered => "this terminal's hook: not registered: open a new terminal after setup, or run `tirith init`".to_string(),
            HookFreshnessState::Unknown => match &self.inherited_integration_version {
                Some(version) => format!(
                    "this terminal's hook: unknown (inherited integration version {version}, unverified)"
                ),
                None => "this terminal's hook: unknown".to_string(),
            },
        }];
        if self.other_live_stale > 0 {
            lines.push(format!(
                "{} other open terminal{} running an older hook",
                self.other_live_stale,
                if self.other_live_stale == 1 {
                    " is"
                } else {
                    "s are"
                }
            ));
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn freshness(this_shell: HookFreshnessState, stale: u32) -> HookFreshness {
        HookFreshness {
            this_shell,
            other_live_current: 1,
            other_live_stale: stale,
            scan_limited: false,
        }
    }

    #[test]
    fn registered_shells_report_current_stale_and_unregistered() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        for (state, token, text) in [
            (
                HookFreshnessState::Current,
                "current",
                "current (loaded, not a blocking proof)",
            ),
            (
                HookFreshnessState::Stale,
                "stale",
                "open a new terminal to load the upgraded hook",
            ),
            (
                HookFreshnessState::Unregistered,
                "unregistered",
                "run `tirith init`",
            ),
        ] {
            let report = report(Some("zsh"), true, freshness(state, 0), Some("0.4.2".into()));
            let value = serde_json::to_value(&report).unwrap();
            assert_eq!(value["this_shell"], token);
            assert_eq!(value["evidence"], "registered_hook_capability");
            assert_eq!(value["blocking_proof"], false);
            assert!(value.get("inherited_integration_version").is_none());
            let lines = report.human_lines();
            assert_eq!(lines.len(), 1);
            assert!(lines[0].contains(text), "{lines:?}");
            assert!(!lines[0].contains("verified"), "{lines:?}");
        }
    }

    #[test]
    fn other_stale_terminals_are_counted_in_human_output() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let one = report(
            Some("bash"),
            true,
            freshness(HookFreshnessState::Current, 1),
            None,
        );
        assert_eq!(
            one.human_lines()[1],
            "1 other open terminal is running an older hook"
        );
        let two = report(
            Some("fish"),
            true,
            freshness(HookFreshnessState::Current, 2),
            None,
        );
        assert_eq!(
            two.human_lines()[1],
            "2 other open terminals are running an older hook"
        );
        let value = serde_json::to_value(&two).unwrap();
        assert_eq!(value["other_live_stale"], 2);
        assert_eq!(value["other_live_current"], 1);
    }

    #[test]
    fn unregistered_shell_families_fall_back_to_the_unverified_inherited_hint() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // A record-free shell never becomes current, even if a record existed.
        let report = report(
            Some("pwsh"),
            false,
            freshness(HookFreshnessState::Current, 0),
            Some("0.4.2".into()),
        );
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["this_shell"], "unknown");
        assert_eq!(value["evidence"], "inherited_environment_unverified");
        assert_eq!(value["inherited_integration_version"], "0.4.2");
        assert!(report.human_lines()[0].contains("inherited integration version 0.4.2, unverified"));
    }
}
