//! Recovery advice is a projection, never an execution authorization. It uses
//! the runtime bypass parser on exact input but emits only protocol-owned text.
use serde::Serialize;

use crate::tokenize::ShellType;
use crate::verdict::{Action, RuleId, Verdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BypassEligibility {
    NotNeeded,
    Eligible,
    DisabledByPolicy,
    UnsupportedCommandShape,
    UnsupportedOneUseSurface,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryAdvice {
    pub schema_version: u32,
    pub shell: ShellType,
    pub bypass: BypassEligibility,
    inline_prefix: Option<&'static str>,
    pub acknowledgement_at_execution_boundary: bool,
    pub hard_block_is_approvable: bool,
    pub execution_permitted: bool,
    pub current_restrictions: Vec<RuleId>,
    instruction: &'static str,
}

/// Do not pass a redacted command here. No command bytes, hashes, paths, custom
/// policy text, or reusable permit are included in the resulting advice.
pub fn for_command(verdict: &Verdict, command: &str, shell: ShellType) -> RecoveryAdvice {
    let bypass = if verdict.action != Action::Block {
        BypassEligibility::NotNeeded
    } else if !verdict.bypass_available {
        BypassEligibility::DisabledByPolicy
    } else if !matches!(shell, ShellType::Posix | ShellType::Fish) {
        // PowerShell/cmd environment assignments persist beyond one operation.
        // A try/finally wrapper could change scope/exit semantics; never invent
        // one as an equivalent one-use permission.
        BypassEligibility::UnsupportedOneUseSurface
    } else if crate::engine::find_inline_bypass(&format!("TIRITH=0 {command}"), shell) {
        BypassEligibility::Eligible
    } else {
        BypassEligibility::UnsupportedCommandShape
    };
    let acknowledgement = verdict.action != Action::Block
        && (verdict.action == Action::WarnAck || verdict.requires_approval == Some(true));
    let instruction = match bypass {
        BypassEligibility::Eligible => "Policy permits an explicit bypass for this submitted line: prefix the original line with TIRITH=0. Retry through the same shell hook for a fresh check; this advice grants no authorization.",
        BypassEligibility::DisabledByPolicy => "Policy disables bypass for this context. Review the reported restrictions; browser confirmation cannot approve this hard block.",
        BypassEligibility::UnsupportedCommandShape => "This compound or background command is ineligible for a line-scoped bypass. Review each operation separately and re-check the exact intended shell input.",
        BypassEligibility::UnsupportedOneUseSurface => "This shell has no supported one-use inline bypass. Persistent environment changes are not an operation-scoped recovery action; review the reported restrictions.",
        BypassEligibility::NotNeeded if acknowledgement => "Acknowledge only at the owned execution prompt. Its one-use receipt is bound to the exact command, shell process, working directory, session, policy and expiry; the hook rechecks it before execution.",
        BypassEligibility::NotNeeded => "No blocked-command recovery is needed for this decision.",
    };
    let mut restrictions = Vec::new();
    for finding in &verdict.findings {
        if !restrictions.contains(&finding.rule_id) {
            restrictions.push(finding.rule_id);
        }
    }
    RecoveryAdvice {
        schema_version: 1,
        shell,
        bypass,
        inline_prefix: (bypass == BypassEligibility::Eligible).then_some("TIRITH=0 "),
        acknowledgement_at_execution_boundary: acknowledgement,
        hard_block_is_approvable: false,
        execution_permitted: false,
        current_restrictions: restrictions,
        instruction,
    }
}

impl RecoveryAdvice {
    pub fn write_human(&self, mut writer: impl std::io::Write) -> std::io::Result<()> {
        if self.bypass != BypassEligibility::NotNeeded || self.acknowledgement_at_execution_boundary
        {
            writeln!(writer, "  Recovery: {}", self.instruction)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn blocked() -> Verdict {
        let mut verdict = Verdict::allow_fast(1, Default::default());
        verdict.action = Action::Block;
        verdict.bypass_available = true;
        verdict
    }
    #[test]
    fn eligibility_uses_runtime_shape_and_preserves_shell_differences() {
        for shell in [ShellType::Posix, ShellType::Fish] {
            assert_eq!(
                for_command(&blocked(), "printf true | sh", shell).bypass,
                BypassEligibility::Eligible
            );
            for input in [
                "printf true | sh; touch marker",
                "echo one && echo two",
                "echo one &",
            ] {
                assert_eq!(
                    for_command(&blocked(), input, shell).bypass,
                    BypassEligibility::UnsupportedCommandShape,
                    "{shell:?}: {input}"
                );
            }
        }
        for shell in [ShellType::PowerShell, ShellType::Cmd] {
            assert_eq!(
                for_command(&blocked(), "echo test", shell).bypass,
                BypassEligibility::UnsupportedOneUseSurface
            );
        }
    }
    #[test]
    fn policy_denial_and_hard_block_cannot_become_acknowledgement() {
        let mut verdict = blocked();
        verdict.bypass_available = false;
        verdict.requires_approval = Some(true);
        let advice = for_command(&verdict, "echo test", ShellType::Posix);
        assert_eq!(advice.bypass, BypassEligibility::DisabledByPolicy);
        assert!(!advice.acknowledgement_at_execution_boundary);
        assert!(!advice.hard_block_is_approvable);
        assert!(!advice.execution_permitted);
        verdict.action = Action::WarnAck;
        assert!(
            for_command(&verdict, "echo test", ShellType::Posix)
                .acknowledgement_at_execution_boundary
        );
    }
    #[test]
    fn advice_never_contains_original_or_redacted_command_material() {
        let raw = "printf SECRET_RECOVERY_CANARY | sh";
        let advice = for_command(&blocked(), raw, ShellType::Posix);
        let output = serde_json::to_string(&advice).unwrap();
        assert!(!output.contains("SECRET_RECOVERY_CANARY"));
        assert!(!output.contains("printf"));
    }
}
