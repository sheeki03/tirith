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
//!   * parser-produced JSON is accepted by the bounded reader and reaches a
//!     stable privacy-projected wire form after one decode;
//!   * a valid raw-private-key command never exposes the key through parser
//!     `Debug` or JSON, independently of whether any finding is emitted;
//!   * findings carry categorical evidence only, so no argv word from the input
//!     may appear verbatim in a finding, which is what keeps a private key or a
//!     destination address out of every downstream surface;
//!   * a hostile repository policy never enlarges authority: the findings for a
//!     merged trusted+hostile policy are the same as for the trusted one alone.
use libfuzzer_sys::fuzz_target;

use tirith_core::rules::web3::{
    parse_web3_commands_v2, SignerKindV2, Web3ParseContextV2, Web3ParseResultV2, MAX_ARGV_ITEMS,
    MAX_SHELL_SEGMENTS,
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

fn assert_bounded_wire_contract(result: &Web3ParseResultV2) {
    let encoded = serde_json::to_vec(result).expect("Web3 parse result must serialize");
    let decoded = Web3ParseResultV2::from_json_slice_bounded(&encoded)
        .expect("parser-produced JSON must fit the bounded public reader");
    let reencoded = serde_json::to_vec(&decoded).expect("decoded Web3 result must serialize");

    // Nonsecret signer references are intentionally projected to digests at
    // the wire boundary, so the in-memory result need not equal its first
    // decode. The public form itself must be stable and preserve every bounded
    // collection plus the authoritative effect/completeness contract.
    assert_eq!(
        encoded, reencoded,
        "Web3 wire privacy projection is not idempotent"
    );
    assert_eq!(
        decoded.effects, result.effects,
        "Web3 effects changed across bounded JSON"
    );
    assert_eq!(
        decoded.completeness, result.completeness,
        "Web3 completeness changed across bounded JSON"
    );
    assert_eq!(
        decoded.commands.len(),
        result.commands.len(),
        "Web3 command count changed across bounded JSON"
    );
}

fn private_key_canary(data: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let input = data.as_bytes();
    let mut canary = String::with_capacity(66);
    canary.push_str("0x");
    for index in 0..32usize {
        let source = if input.is_empty() {
            0xa5
        } else {
            input[index % input.len()]
        };
        let byte = source ^ (index as u8).wrapping_mul(0x5b) ^ 0xc3;
        canary.push(HEX[usize::from(byte >> 4)] as char);
        canary.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    canary
}

fn assert_raw_private_key_privacy(data: &str, shell: ShellType, context: &Web3ParseContextV2) {
    let canary = private_key_canary(data);
    let command = format!("cast send 0xdead --rpc-url https://rpc.example --private-key {canary}");
    let parsed = parse_web3_commands_v2(&command, shell, context);
    assert!(
        parsed.commands.iter().any(|facts| {
            facts
                .signers
                .iter()
                .any(|tagged| tagged.signer.kind() == SignerKindV2::RawPrivateKey)
        }),
        "the privacy probe must exercise a recognized raw private key"
    );

    let debug = format!("{parsed:?}");
    let json = serde_json::to_string(&parsed).expect("private-key parse result must serialize");
    let bare_canary = canary.trim_start_matches("0x");
    for rendered in [&debug, &json] {
        assert!(
            !rendered.contains(&canary),
            "raw private key leaked from parser surface"
        );
        assert!(
            !rendered.contains(bare_canary),
            "raw private-key payload leaked from parser surface"
        );
    }
    assert_bounded_wire_contract(&parsed);
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
        assert_bounded_wire_contract(&first);
        assert_raw_private_key_privacy(data, shell, &context);
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
