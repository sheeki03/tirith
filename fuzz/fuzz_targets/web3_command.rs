#![no_main]
//! Fuzz target for the bounded Web3 tool grammar
//! (`tirith_core::rules::web3::parse_web3_commands_v2`) and the three rules
//! that read its facts.
//!
//! The input is a shell line. The parser is a pure classifier: it never
//! executes anything and, in the `without_filesystem` context used here, never
//! touches disk either.
//!
//! Contract under fuzz:
//!
//!   * never panic;
//!   * every fact collection stays inside its declared bound, so an
//!     attacker-chosen line cannot drive unbounded allocation;
//!   * the complete parse result, including effects, completeness, and
//!     truncation state, is deterministic in one fixed no-I/O context;
//!   * findings carry categorical evidence only, so no argv word from the input
//!     may appear verbatim in a finding, which is what keeps a private key or a
//!     destination address out of every downstream surface;
//!   * a hostile repository policy never enlarges authority: the findings for a
//!     merged trusted+hostile policy are the same as for the trusted one alone.
use libfuzzer_sys::fuzz_target;

use tirith_core::rules::web3::{
    parse_web3_commands_v2, Web3ParseContextV2, MAX_ARGV_ITEMS, MAX_SHELL_SEGMENTS,
};
use tirith_core::rules::web3_gate;
use tirith_core::tokenize::ShellType;
use tirith_core::web3_policy::{TrustedSignerKind, Web3GuardAction, Web3GuardPolicy};

fn trusted() -> Web3GuardPolicy {
    Web3GuardPolicy {
        allowed_signers: [TrustedSignerKind::KeystoreFile].into_iter().collect(),
        action_unclassified_rpc: Web3GuardAction::Warn,
        ..Web3GuardPolicy::default()
    }
}

/// Everything a repository-scope policy could ask for. `merge_repo_scoped` must
/// drop every grant, so folding this in changes no decision.
fn hostile_repo() -> Web3GuardPolicy {
    Web3GuardPolicy {
        allowed_signers: [
            TrustedSignerKind::UnlockedNode,
            TrustedSignerKind::AccountAlias,
        ]
        .into_iter()
        .collect(),
        command_card_key_ids: ["attacker".to_string()].into_iter().collect(),
        action_unclassified_rpc: Web3GuardAction::Allow,
        action_incomplete_analysis: Web3GuardAction::Allow,
        action_ambiguous_hardhat_production_run: Web3GuardAction::Allow,
        ..Web3GuardPolicy::default()
    }
}

fn project(findings: &[tirith_core::verdict::Finding]) -> Vec<String> {
    let mut ids = findings
        .iter()
        .map(|finding| format!("{}:{}", finding.rule_id, finding.severity))
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

fuzz_target!(|data: &str| {
    let context = Web3ParseContextV2::without_filesystem();

    for shell in [ShellType::Posix, ShellType::PowerShell] {
        let first = parse_web3_commands_v2(data, shell, &context);
        let second = parse_web3_commands_v2(data, shell, &context);

        assert_eq!(
            first, second,
            "the complete Web3 parse result is not deterministic in a fixed no-I/O context"
        );
        assert!(
            first.commands.len() <= MAX_SHELL_SEGMENTS,
            "the Web3 grammar exceeded its segment bound"
        );

        for facts in &first.commands {
            assert!(
                facts.signers.len() <= MAX_ARGV_ITEMS,
                "signer collection exceeded its bound"
            );
            assert!(
                facts.destinations.len() <= MAX_ARGV_ITEMS,
                "destination collection exceeded its bound"
            );
            assert!(
                facts.safety_flags.len() <= MAX_ARGV_ITEMS,
                "safety-flag collection exceeded its bound"
            );
        }

        let trusted_findings = web3_gate::check(&first, &trusted());

        // A hostile repo policy folded into the trusted one changes nothing.
        let mut composed = trusted();
        composed.merge_repo_scoped(hostile_repo());
        let composed_findings = web3_gate::check(&first, &composed);
        assert_eq!(
            project(&trusted_findings),
            project(&composed_findings),
            "a repository-scope policy changed a Web3 decision"
        );

        // Categorical evidence only. The words that matter are the SECRET- and
        // ADDRESS-shaped ones: a long hex run is a key, a keypair, or a
        // destination, and none of the three may appear verbatim in a finding.
        // Ordinary flag words are deliberately not asserted on, because the
        // evidence legitimately names a signer KIND ("keystore_file") that
        // shares a substring with the flag that selected it.
        if !trusted_findings.is_empty() {
            let rendered = serde_json::to_string(&trusted_findings).unwrap_or_default();
            for segment in tirith_core::tokenize::tokenize(data, shell) {
                for word in segment.args {
                    for run in word.split(|c: char| !c.is_ascii_alphanumeric()) {
                        let hex_shaped =
                            run.len() >= 16 && run.chars().all(|c| c.is_ascii_hexdigit());
                        if !hex_shaped {
                            continue;
                        }
                        assert!(
                            !rendered.contains(run),
                            "a secret- or address-shaped word reached a Web3 finding verbatim"
                        );
                    }
                }
            }
        }
    }
});
