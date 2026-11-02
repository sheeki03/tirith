//! Hook-freshness readout shared by `tirith status` and `tirith doctor`: is the
//! hook loaded in this terminal the one registered by this Tirith executable?
//!
//! Bash, Zsh and Fish hooks register a private protocol-v3 capability record at
//! startup that names the executable which generated them. PowerShell and
//! Nushell have no receipt capability; on Unix their hooks instead write a
//! private hook load record (`tirith __hook-presence`) naming the same things,
//! with no secret. A record from a different or replaced executable means the
//! terminal still runs an older hook. This is loaded-hook evidence only, never
//! blocking proof: that stays with `tirith doctor --verify-shell` and `tirith
//! status --require-verified-blocking`. Where no record can exist (Windows,
//! where process identity is Unix-only, and unrecognized shells) the readout
//! falls back to the inherited, unverified integration-version hint.

use tirith_core::execution_state::{
    HookFreshness, HookFreshnessState, HookPresenceFamily, HookRegistration,
};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct HookFreshnessReport {
    pub this_shell: HookFreshnessState,
    /// Detected caller shell, when known.
    pub shell: Option<&'static str>,
    /// `registered_hook_capability`, `registered_hook_presence` or
    /// `inherited_environment_unverified`.
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

/// The hook load-record family of a detected shell name.
fn presence_family(shell: &str) -> Option<HookPresenceFamily> {
    match shell {
        "pwsh" | "powershell" => Some(HookPresenceFamily::PowerShell),
        "nushell" => Some(HookPresenceFamily::Nushell),
        _ => None,
    }
}

/// The record a detected shell's hook writes on this platform, if any.
fn registration(shell: &str) -> Option<HookRegistration> {
    if matches!(shell, "bash" | "zsh" | "fish") {
        return Some(HookRegistration::Capability);
    }
    if cfg!(unix) {
        presence_family(shell).map(HookRegistration::Presence)
    } else {
        None
    }
}

pub(crate) fn gather() -> HookFreshnessReport {
    let identity = super::init::detect_shell_identity();
    let shell = (identity.shell != "unknown").then_some(identity.shell);
    let target = identity.process_id.zip(registration(identity.shell));
    let inherited = super::selfupdate::inherited_integration_version();
    report(
        shell,
        target.map(|(_, registration)| registration),
        tirith_core::execution_state::hook_freshness(target),
        inherited,
    )
}

/// `tirith __hook-presence`: record that a PowerShell or Nushell hook loaded
/// in the calling shell. The target must be the shell this process detects as
/// its caller (the same detection `status` uses), of the named family. Prints
/// nothing on success.
pub(crate) fn register_presence(family: HookPresenceFamily, shell_pid: u32) -> i32 {
    if !cfg!(unix) {
        eprintln!("tirith: hook load records are unsupported on this platform");
        return 1;
    }
    let identity = super::init::detect_shell_identity();
    if identity.process_id != Some(shell_pid) || presence_family(identity.shell) != Some(family) {
        eprintln!(
            "tirith: hook load record refused: the target is not the calling {} shell",
            match family {
                HookPresenceFamily::PowerShell => "PowerShell",
                HookPresenceFamily::Nushell => "Nushell",
            }
        );
        return 1;
    }
    match tirith_core::execution_state::register_hook_presence(shell_pid, family) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("tirith: failed to record the hook load: {error}");
            1
        }
    }
}

fn report(
    shell: Option<&'static str>,
    registration: Option<HookRegistration>,
    freshness: HookFreshness,
    inherited_version: Option<String>,
) -> HookFreshnessReport {
    let (this_shell, evidence, inherited_integration_version) = match registration {
        Some(HookRegistration::Capability) => {
            (freshness.this_shell, "registered_hook_capability", None)
        }
        Some(HookRegistration::Presence(_)) => {
            (freshness.this_shell, "registered_hook_presence", None)
        }
        None => (
            HookFreshnessState::Unknown,
            "inherited_environment_unverified",
            inherited_version,
        ),
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
            let report = report(
                Some("zsh"),
                Some(HookRegistration::Capability),
                freshness(state, 0),
                Some("0.4.2".into()),
            );
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
            Some(HookRegistration::Capability),
            freshness(HookFreshnessState::Current, 1),
            None,
        );
        assert_eq!(
            one.human_lines()[1],
            "1 other open terminal is running an older hook"
        );
        let two = report(
            Some("fish"),
            Some(HookRegistration::Capability),
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
        // A record-free shell (PowerShell on Windows, an unrecognized shell)
        // never becomes current, even if a record existed.
        let report = report(
            Some("pwsh"),
            None,
            freshness(HookFreshnessState::Current, 0),
            Some("0.4.2".into()),
        );
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["this_shell"], "unknown");
        assert_eq!(value["evidence"], "inherited_environment_unverified");
        assert_eq!(value["inherited_integration_version"], "0.4.2");
        assert!(report.human_lines()[0].contains("inherited integration version 0.4.2, unverified"));
    }

    #[test]
    fn powershell_and_nushell_report_their_hook_load_record_on_unix() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        for shell in ["bash", "zsh", "fish"] {
            assert_eq!(registration(shell), Some(HookRegistration::Capability));
        }
        for (shell, family) in [
            ("pwsh", HookPresenceFamily::PowerShell),
            ("powershell", HookPresenceFamily::PowerShell),
            ("nushell", HookPresenceFamily::Nushell),
        ] {
            assert_eq!(presence_family(shell), Some(family));
            assert_eq!(
                registration(shell),
                cfg!(unix).then_some(HookRegistration::Presence(family)),
                "{shell}"
            );
        }
        for shell in ["unknown", "sh", "nu", "cmd"] {
            assert_eq!(registration(shell), None, "{shell}");
        }
        for (state, token) in [
            (HookFreshnessState::Current, "current"),
            (HookFreshnessState::Stale, "stale"),
            (HookFreshnessState::Unregistered, "unregistered"),
        ] {
            let report = report(
                Some("nushell"),
                Some(HookRegistration::Presence(HookPresenceFamily::Nushell)),
                freshness(state, 0),
                Some("0.4.2".into()),
            );
            let value = serde_json::to_value(&report).unwrap();
            assert_eq!(value["this_shell"], token);
            assert_eq!(value["evidence"], "registered_hook_presence");
            assert_eq!(value["blocking_proof"], false);
            assert!(value.get("inherited_integration_version").is_none());
        }
    }

    /// The shipped hooks are the only callers of `__hook-presence`. PowerShell
    /// and Nushell may not be installed where this runs, so pin the calls to
    /// what the parser and `register_presence` accept, after the hook is live.
    #[test]
    fn shipped_powershell_and_nushell_hooks_record_their_load() {
        use clap::Parser as _;
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        for (hook, call, installed) in [
            (
                crate::assets::POWERSHELL_HOOK,
                "& $global:_TIRITH_BIN __hook-presence --family powershell --shell-pid $PID",
                "Set-PSReadLineKeyHandler -Key Ctrl+v",
            ),
            (
                crate::assets::NUSHELL_HOOK,
                "^tirith __hook-presence --family nushell --shell-pid $nu.pid",
                "$env.config.hooks.pre_execution = ($existing | append",
            ),
        ] {
            assert_eq!(hook.matches("__hook-presence").count(), 1, "{call}");
            let at = hook.find(call).unwrap_or_else(|| panic!("missing: {call}"));
            assert!(hook.find(installed).is_some_and(|handler| handler < at));
            let family = call
                .split_whitespace()
                .skip_while(|word| *word != "--family")
                .nth(1)
                .unwrap()
                .to_string();
            // The full parser graph needs the CLI's main-thread stack size.
            let parsed = std::thread::Builder::new()
                .stack_size(16 * 1024 * 1024)
                .spawn(move || {
                    crate::Cli::try_parse_from([
                        "tirith",
                        "__hook-presence",
                        "--family",
                        &family,
                        "--shell-pid",
                        "4242",
                    ])
                    .is_ok()
                })
                .expect("parser thread")
                .join()
                .expect("parse the hook's call");
            assert!(parsed, "{call}");
        }
    }
}
