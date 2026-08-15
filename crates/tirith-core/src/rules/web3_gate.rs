//! Turn bounded Web3 command facts into findings (C10).
//!
//! The parser slice deliberately emitted facts and nothing else. This module
//! is the first place those facts become a verdict, and it adds exactly three
//! rule ids:
//!
//! - [`RuleId::Web3StateChangingCommand`] — the command writes on-chain;
//! - [`RuleId::Web3SignerRisk`] — how the signer is supplied;
//! - [`RuleId::Web3NetworkPolicyViolation`] — the operation contradicts the
//!   trusted `web3_guard`.
//!
//! Parser and configuration gaps reuse the existing `AnalysisIncomplete`
//! rather than minting a fourth id, and bare private-key fragments stay out of
//! the global hot path because the credential and exfiltration rules already
//! cover them in their own contexts.
//!
//! Two boundaries are load-bearing here.
//!
//! **Unclassified is not hostile.** An endpoint no trusted network claims is
//! reported through the policy's `action_unclassified_rpc`, which defaults to a
//! warning, and never as a policy violation. Calling an unrecognized host
//! malicious would train operators to ignore the rule.
//!
//! **Evidence is categorical.** Findings name the operation, the signer KIND,
//! and the tool. They never carry a key, a keystore path, a destination
//! address, or the raw command; the C04 redaction contract applies to whatever
//! does get emitted, but the right fix is not to put it there in the first
//! place.

use crate::rules::web3::{
    SignerKindV2, Web3CommandFactsV2, Web3ParseResultV2, Web3SafetyFlag, Web3WriteMode,
};
use crate::verdict::{Evidence, Finding, RuleId, Severity};
use crate::web3_policy::{Web3GuardAction, Web3GuardPolicy};

/// Build findings for one parsed command line.
pub fn check(result: &Web3ParseResultV2, guard: &Web3GuardPolicy) -> Vec<Finding> {
    let mut findings = Vec::new();
    for facts in &result.commands {
        push_state_change(&mut findings, facts);
        push_signer_risk(&mut findings, facts);
        push_policy_violation(&mut findings, facts, guard);
    }
    findings
}

// Evidence tokens are mapped EXPLICITLY rather than derived from `{:?}`.
// Debug formatting would make the wire vocabulary depend on Rust variant
// names, so renaming a variant would silently change evidence that other
// tooling parses, and `RawPrivateKey` would render as the unreadable
// `rawprivatekey`.

fn tool_token(facts: &Web3CommandFactsV2) -> &'static str {
    use crate::rules::web3::Web3ToolFamily;
    match facts.tool {
        Web3ToolFamily::Cast => "cast",
        Web3ToolFamily::Forge => "forge",
        Web3ToolFamily::Hardhat => "hardhat",
        Web3ToolFamily::Solana => "solana",
        Web3ToolFamily::Anchor => "anchor",
    }
}

fn signer_kind_token(kind: SignerKindV2) -> &'static str {
    match kind {
        SignerKindV2::RawPrivateKey => "raw_private_key",
        SignerKindV2::RawKeypair => "raw_keypair",
        SignerKindV2::Mnemonic => "mnemonic",
        SignerKindV2::KeypairFile => "keypair_file",
        SignerKindV2::Keystore => "keystore",
        SignerKindV2::Ledger => "ledger",
        SignerKindV2::Trezor => "trezor",
        SignerKindV2::AwsKms => "aws_kms",
        SignerKindV2::UnlockedNode => "unlocked_node",
        SignerKindV2::AccountAlias => "account_alias",
        SignerKindV2::Stdin => "stdin",
        SignerKindV2::Prompt => "prompt",
        SignerKindV2::Unknown => "unknown",
    }
}

fn signer_role_token(role: crate::rules::web3::SignerRole) -> &'static str {
    use crate::rules::web3::SignerRole;
    // Exhaustive on purpose: a new role must be given a stable token here
    // rather than silently rendering as something else.
    match role {
        SignerRole::Default => "default",
        SignerRole::Keypair => "keypair",
        SignerRole::Authority => "authority",
        SignerRole::FeePayer => "fee_payer",
        SignerRole::ProgramId => "program_id",
        SignerRole::Wallet => "wallet",
    }
}

/// A bounded lowercase token for the parsed operation. The operation enum is
/// large and still growing, so this normalizes rather than enumerating, and
/// anything unexpected degrades to `unknown` instead of emitting a value the
/// categorical validator would reject.
fn operation_token(facts: &Web3CommandFactsV2) -> String {
    let debug = format!("{:?}", facts.operation);
    let mut token = String::with_capacity(debug.len() + 4);
    for (index, ch) in debug.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if index > 0 {
                token.push('_');
            }
            token.push(ch.to_ascii_lowercase());
        } else if ch.is_ascii_alphanumeric() {
            token.push(ch);
        } else {
            return "unknown".to_string();
        }
    }
    if token.is_empty() || token.len() > 48 {
        "unknown".to_string()
    } else {
        token
    }
}

fn is_state_changing(facts: &Web3CommandFactsV2) -> bool {
    matches!(
        facts.write_mode,
        Web3WriteMode::StateChanging | Web3WriteMode::PotentialWrite
    )
}

/// Cluster monikers that name a development or test network.
///
/// Deliberately a SHORT exact list, not a substring test: `devnet` must match
/// while `my-devnet-proxy.example` must not, because an attacker-supplied host
/// containing "devnet" is not a development network.
const DEVELOPMENT_NETWORK_ALIASES: &[&str] = &[
    "devnet",
    "testnet",
    "localhost",
    "localnet",
    "local",
    "l",
    "d",
    "t",
];

/// Is this operation explicitly aimed at a development or test network?
///
/// Deploying to devnet is routine developer activity that happens many times a
/// day, and the C00 benign corpus lists local and devnet operations as
/// negatives precisely so a new rule cannot start warning on them. Warning here
/// would be the alert-fatigue failure that makes operators stop reading the
/// output.
///
/// Only an EXPLICIT selector counts. A command with no endpoint at all falls
/// through to the tool's configured default, which may well be mainnet, so
/// silence there would be under-detection.
fn targets_development_network(facts: &Web3CommandFactsV2) -> bool {
    let Some(rpc) = facts.rpc.as_ref() else {
        return false;
    };
    if let Some(alias) = rpc.alias.as_deref() {
        if DEVELOPMENT_NETWORK_ALIASES
            .iter()
            .any(|known| alias.eq_ignore_ascii_case(known))
        {
            return true;
        }
    }
    // A loopback endpoint is a local node by definition.
    matches!(
        rpc.host.as_deref(),
        Some("localhost") | Some("127.0.0.1") | Some("::1")
    )
}

/// A safety control the operator would have to switch off deliberately.
fn disables_declared_safety(facts: &Web3CommandFactsV2) -> bool {
    facts.safety_flags.iter().any(|flag| {
        matches!(
            flag,
            Web3SafetyFlag::SkipSimulation | Web3SafetyFlag::SkipPreflight | Web3SafetyFlag::Force
        )
    })
}

fn push_state_change(findings: &mut Vec<Finding>, facts: &Web3CommandFactsV2) {
    if !is_state_changing(facts) {
        return;
    }
    // A deploy explicitly aimed at devnet, testnet, or a local validator is
    // normal development, not an event worth interrupting. The signer rules
    // still apply: a raw key is just as exposed on devnet as on mainnet.
    if targets_development_network(facts) {
        return;
    }
    // High only when a write ALSO disables a declared check. A plain deploy is
    // the tool doing its job; a deploy with simulation switched off is the
    // shape that turns a mistake into an unrecoverable one.
    let bypassed = disables_declared_safety(facts);
    let severity = if bypassed {
        Severity::High
    } else {
        Severity::Medium
    };
    let operation = operation_token(facts);
    findings.push(Finding {
        rule_id: RuleId::Web3StateChangingCommand,
        severity,
        title: "Command changes on-chain state".to_string(),
        description: if bypassed {
            "This command performs an on-chain write and also disables a declared safety control. \
             On-chain writes cannot be rolled back."
                .to_string()
        } else {
            "This command performs an on-chain write. On-chain writes cannot be rolled back."
                .to_string()
        },
        evidence: vec![Evidence::Text {
            detail: format!(
                "tirith:v1:web3_operation;tool={};operation={};write=state_changing;safety_bypass={}",
                tool_token(facts),
                operation,
                if bypassed { "yes" } else { "no" }
            ),
        }],
        human_view: Some(
            "Web3 guard — confirm the network and signer before re-running.".to_string(),
        ),
        agent_view: Some("tirith refused: web3 state-changing command".to_string()),
        mitre_id: Some("T1565".to_string()),
        custom_rule_id: None,
    });
}

fn push_signer_risk(findings: &mut Vec<Finding>, facts: &Web3CommandFactsV2) {
    for tagged in &facts.signers {
        let kind = tagged.signer.kind();
        // Critical only for literal secret material in argv: it is readable
        // from the process table, the shell history, and any log that captured
        // the command, so the key is compromised the moment it is typed.
        let severity = if kind.is_raw_secret() {
            Severity::Critical
        } else if matches!(kind, SignerKindV2::UnlockedNode | SignerKindV2::Prompt) {
            Severity::High
        } else {
            continue;
        };
        findings.push(Finding {
            rule_id: RuleId::Web3SignerRisk,
            severity,
            title: if kind.is_raw_secret() {
                "Raw signer material on the command line".to_string()
            } else {
                "Signer exposure risk".to_string()
            },
            description: if kind.is_raw_secret() {
                "A private key, keypair, or mnemonic appears literally in this command. It is \
                 readable from the process table, the shell history, and any log that captured \
                 the command. Treat the key as compromised."
                    .to_string()
            } else {
                "This command signs using an unlocked node or an interactive prompt rather than a \
                 keystore or hardware wallet."
                    .to_string()
            },
            // Categorical only: the KIND, never the key, path, or address.
            evidence: vec![Evidence::Text {
                detail: format!(
                    "tirith:v1:web3_signer;tool={};kind={};role={}",
                    tool_token(facts),
                    signer_kind_token(kind),
                    signer_role_token(tagged.role)
                ),
            }],
            human_view: Some(
                "Web3 guard — use a keystore, account alias, or hardware wallet.".to_string(),
            ),
            agent_view: Some("tirith refused: web3 signer risk".to_string()),
            mitre_id: Some("T1552".to_string()),
            custom_rule_id: None,
        });
    }
}

fn push_policy_violation(
    findings: &mut Vec<Finding>,
    facts: &Web3CommandFactsV2,
    guard: &Web3GuardPolicy,
) {
    let Some(rpc) = facts.rpc.as_ref() else {
        return;
    };
    let Some(host) = rpc.host.as_deref() else {
        return;
    };
    let scheme = rpc.scheme.as_deref().unwrap_or("https");
    let denied = guard.denies_rpc(scheme, host, rpc.port, None);
    let classified = guard.classify_rpc(scheme, host, rpc.port, None).is_some();

    if denied {
        findings.push(policy_finding(
            facts,
            "denied_endpoint",
            "The endpoint this command contacts is denied by the trusted policy.",
        ));
        return;
    }

    // An endpoint no trusted network claims is NOT a violation. Reporting an
    // unrecognized host as hostile would be a claim the analysis cannot
    // support, so this follows the policy's declared action instead and stays
    // silent when that action is Allow.
    if !classified && !guard.networks.is_empty() {
        match guard.action_unclassified_rpc {
            Web3GuardAction::Allow => {}
            action => findings.push(Finding {
                rule_id: RuleId::Web3NetworkPolicyViolation,
                severity: match action {
                    Web3GuardAction::Block => Severity::High,
                    Web3GuardAction::RequireApproval => Severity::Medium,
                    _ => Severity::Low,
                },
                title: "Web3 endpoint is not covered by trusted policy".to_string(),
                description: "No trusted network claims this endpoint. This is not a claim that \
                              the host is malicious; it means the policy cannot vouch for it."
                    .to_string(),
                evidence: vec![Evidence::Text {
                    detail: format!(
                        "tirith:v1:web3_policy;tool={};status=unclassified_endpoint",
                        tool_token(facts)
                    ),
                }],
                human_view: Some(
                    "Web3 guard — declare this endpoint in web3_guard if it is expected."
                        .to_string(),
                ),
                agent_view: Some("tirith: web3 endpoint unclassified".to_string()),
                mitre_id: None,
                custom_rule_id: None,
            }),
        }
        return;
    }

    // A signer the policy does not permit, on a state-changing command, IS a
    // violation: the operator wrote down which signers are acceptable.
    if is_state_changing(facts) && !guard.allowed_signers.is_empty() {
        for tagged in &facts.signers {
            if let Some(trusted) = trusted_signer_kind(tagged.signer.kind()) {
                if !guard.permits_signer(trusted) {
                    findings.push(policy_finding(
                        facts,
                        "signer_not_permitted",
                        "The signer this command uses is not permitted by the trusted policy.",
                    ));
                    return;
                }
            }
        }
    }
}

fn policy_finding(facts: &Web3CommandFactsV2, status: &str, description: &str) -> Finding {
    Finding {
        rule_id: RuleId::Web3NetworkPolicyViolation,
        severity: Severity::High,
        title: "Web3 operation contradicts trusted policy".to_string(),
        description: description.to_string(),
        evidence: vec![Evidence::Text {
            detail: format!(
                "tirith:v1:web3_policy;tool={};status={status}",
                tool_token(facts)
            ),
        }],
        human_view: Some("Web3 guard — compare against `tirith policy effective`.".to_string()),
        agent_view: Some("tirith refused: web3 policy violation".to_string()),
        mitre_id: Some("T1565".to_string()),
        custom_rule_id: None,
    }
}

/// Map a parsed signer kind onto the policy's trusted vocabulary. Raw-secret
/// kinds have no trusted spelling by design, so they return `None` and are
/// handled by the signer-risk rule instead of the policy rule.
fn trusted_signer_kind(kind: SignerKindV2) -> Option<crate::web3_policy::TrustedSignerKind> {
    use crate::web3_policy::TrustedSignerKind as Trusted;
    match kind {
        SignerKindV2::Ledger | SignerKindV2::Trezor => Some(Trusted::HardwareWallet),
        SignerKindV2::Keystore => Some(Trusted::KeystoreFile),
        SignerKindV2::KeypairFile => Some(Trusted::KeypairFile),
        SignerKindV2::AccountAlias => Some(Trusted::AccountAlias),
        SignerKindV2::UnlockedNode => Some(Trusted::UnlockedNode),
        SignerKindV2::RawPrivateKey
        | SignerKindV2::RawKeypair
        | SignerKindV2::Mnemonic
        | SignerKindV2::AwsKms
        | SignerKindV2::Stdin
        | SignerKindV2::Prompt
        | SignerKindV2::Unknown => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::web3::{parse_web3_commands_v2, Web3ParseContextV2};
    use crate::tokenize::ShellType;

    fn findings_for(command: &str, guard: &Web3GuardPolicy) -> Vec<Finding> {
        let parsed = parse_web3_commands_v2(
            command,
            ShellType::Posix,
            &Web3ParseContextV2::without_filesystem(),
        );
        check(&parsed, guard)
    }

    fn has(findings: &[Finding], rule: RuleId) -> bool {
        findings.iter().any(|finding| finding.rule_id == rule)
    }

    #[test]
    fn read_only_and_dry_run_commands_stay_silent() {
        let guard = Web3GuardPolicy::default();
        for command in [
            "cast call 0xabc 'balanceOf(address)'",
            "cast send 0xabc --dry-run",
            "forge build",
            "solana program show someid",
        ] {
            let findings = findings_for(command, &guard);
            assert!(
                !has(&findings, RuleId::Web3StateChangingCommand),
                "benign command fired: {command} -> {findings:?}"
            );
        }
    }

    #[test]
    fn a_state_changing_command_fires_medium_and_rises_on_a_safety_bypass() {
        let guard = Web3GuardPolicy::default();
        let plain = findings_for("forge script Deploy.s.sol --broadcast", &guard);
        let state_change = plain
            .iter()
            .find(|finding| finding.rule_id == RuleId::Web3StateChangingCommand)
            .expect("broadcast must fire");
        assert_eq!(state_change.severity, Severity::Medium);

        let bypassed = findings_for(
            "forge script Deploy.s.sol --broadcast --skip-simulation",
            &guard,
        );
        let raised = bypassed
            .iter()
            .find(|finding| finding.rule_id == RuleId::Web3StateChangingCommand)
            .expect("broadcast must fire");
        assert_eq!(
            raised.severity,
            Severity::High,
            "disabling a declared safety control must raise severity"
        );
    }

    #[test]
    fn raw_signer_material_is_critical_and_never_echoed() {
        let guard = Web3GuardPolicy::default();
        let secret = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let findings = findings_for(&format!("cast send 0xabc --private-key {secret}"), &guard);
        let signer = findings
            .iter()
            .find(|finding| finding.rule_id == RuleId::Web3SignerRisk)
            .expect("raw key must fire");
        assert_eq!(signer.severity, Severity::Critical);

        // The whole finding set must be free of the key and the destination.
        let rendered = format!("{findings:?}");
        assert!(!rendered.contains(secret), "signer material leaked");
        assert!(
            !rendered.contains("0xabc"),
            "destination address leaked: {rendered}"
        );
    }

    #[test]
    fn evidence_records_survive_the_redaction_boundary_intact() {
        // Found by dogfooding, not by a unit test: these records go through the
        // shared command-text scrubber, which treats `tool=cast` as a shell
        // assignment and blanks the value. That redacted the evidence into
        // `tool=[REDACTED];operation=[REDACTED]` while protecting nothing,
        // since every token is a closed enum name. The records are now
        // registered with the categorical validator so they are preserved
        // byte-for-byte.
        let guard = Web3GuardPolicy::default();
        let secret = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let findings = findings_for(&format!("cast send 0xabc --private-key {secret}"), &guard);

        for finding in &findings {
            for evidence in &finding.evidence {
                let Evidence::Text { detail } = evidence else {
                    continue;
                };
                if !detail.starts_with("tirith:v1:web3_") {
                    continue;
                }
                assert!(
                    crate::verdict::is_internal_categorical_evidence_record(detail),
                    "record is not preserved by the redaction boundary: {detail}"
                );
                assert!(
                    !detail.contains("REDACTED"),
                    "categorical record was blanked: {detail}"
                );
            }
        }

        // The tokens are stable names, not Debug output: a variant rename must
        // not silently change the wire vocabulary.
        assert_eq!(
            signer_kind_token(SignerKindV2::RawPrivateKey),
            "raw_private_key"
        );
        assert_eq!(
            signer_kind_token(SignerKindV2::UnlockedNode),
            "unlocked_node"
        );
    }

    #[test]
    fn a_development_network_deploy_is_not_worth_interrupting() {
        // The C00 benign corpus lists local and devnet operations as negatives
        // precisely so a new rule cannot start warning on routine development.
        let guard = Web3GuardPolicy::default();
        for command in [
            "solana program deploy --url devnet target/deploy/example.so",
            "solana program deploy --url testnet x.so",
            "solana program deploy --url localhost x.so",
            "solana program deploy --url localnet x.so",
        ] {
            let findings = findings_for(command, &guard);
            assert!(
                !has(&findings, RuleId::Web3StateChangingCommand),
                "a development-network deploy warned: {command}"
            );
        }

        // Production is unaffected, including the no-selector case, which falls
        // through to the tool's configured default and may well be mainnet.
        for command in [
            "solana program deploy --url mainnet-beta x.so",
            "solana program deploy x.so",
        ] {
            assert!(
                has(
                    &findings_for(command, &guard),
                    RuleId::Web3StateChangingCommand
                ),
                "a production deploy went unreported: {command}"
            );
        }

        // The carve-out is an EXACT moniker match, so a hostile host that merely
        // contains the word does not inherit the exemption.
        assert!(
            has(
                &findings_for(
                    "cast send 0xabc --rpc-url https://my-devnet-proxy.example",
                    &guard
                ),
                RuleId::Web3StateChangingCommand
            ),
            "a host containing 'devnet' must not be treated as a development network"
        );

        // A raw key is just as exposed on devnet, so the signer rule still fires.
        let devnet_key = findings_for(
            "solana program deploy --url devnet --keypair 5MaiiCavjCmn9Hs1o3eznqDEhRwxo7pXiAYez7keQUviUkauRiTMD8DrESdrNjN8zd9mTmVhRvBJeg9LhaTLDBK9 x.so",
            &guard,
        );
        assert!(
            has(&devnet_key, RuleId::Web3SignerRisk),
            "the signer rule must not inherit the development-network exemption"
        );
    }

    #[test]
    fn a_hardware_wallet_is_not_a_signer_risk() {
        let guard = Web3GuardPolicy::default();
        // An explicit remote endpoint, because `cast send` with no `--rpc-url`
        // resolves to the localhost tool default, which is a local node and is
        // covered by the development-network carve-out.
        let findings = findings_for(
            "cast send 0xabc --rpc-url https://mainnet.example --ledger",
            &guard,
        );
        assert!(!has(&findings, RuleId::Web3SignerRisk));
        // ...but it is still an on-chain write.
        assert!(has(&findings, RuleId::Web3StateChangingCommand));
    }

    #[test]
    fn an_unclassified_endpoint_is_not_reported_as_a_violation() {
        // The distinction that keeps this rule trustworthy: a host no trusted
        // network claims is unclassified, not hostile.
        let guard = Web3GuardPolicy {
            networks: vec![crate::web3_policy::TrustedNetwork {
                name: "prod".into(),
                family: crate::web3_policy::Web3Family::Evm,
                identity: crate::web3_policy::NetworkIdentity::Evm { evm_chain_id: 1 },
                endpoints: vec![crate::web3_policy::RpcMatcher {
                    scheme: "https".into(),
                    host: "rpc.trusted.test".into(),
                    port: None,
                    path_prefix: None,
                    subdomains: crate::web3_policy::SubdomainPolicy::ExactHost,
                }],
            }],
            action_unclassified_rpc: Web3GuardAction::Warn,
            ..Web3GuardPolicy::default()
        };
        let findings = findings_for("cast send 0xabc --rpc-url https://unknown.test", &guard);
        let violation = findings
            .iter()
            .find(|finding| finding.rule_id == RuleId::Web3NetworkPolicyViolation)
            .expect("an unclassified endpoint is still reported");
        // Reported, but NOT as a High violation and not as a malicious-host claim.
        assert_eq!(violation.severity, Severity::Low);
        assert!(violation.description.contains("not a claim"));

        // With the action set to allow, it is silent entirely.
        let permissive = Web3GuardPolicy {
            action_unclassified_rpc: Web3GuardAction::Allow,
            ..guard.clone()
        };
        let quiet = findings_for(
            "cast send 0xabc --rpc-url https://unknown.test",
            &permissive,
        );
        assert!(!has(&quiet, RuleId::Web3NetworkPolicyViolation));
    }

    #[test]
    fn a_denied_endpoint_is_a_high_violation() {
        let guard = Web3GuardPolicy {
            deny_rpc: vec![crate::web3_policy::RpcMatcher {
                scheme: "https".into(),
                host: "banned.test".into(),
                port: None,
                path_prefix: None,
                subdomains: crate::web3_policy::SubdomainPolicy::ExactHost,
            }],
            ..Web3GuardPolicy::default()
        };
        let findings = findings_for("cast send 0xabc --rpc-url https://banned.test", &guard);
        let violation = findings
            .iter()
            .find(|finding| finding.rule_id == RuleId::Web3NetworkPolicyViolation)
            .expect("a denied endpoint must fire");
        assert_eq!(violation.severity, Severity::High);
    }

    #[test]
    fn an_empty_policy_never_produces_a_violation() {
        // C10 must not start blocking for operators who declared nothing.
        let guard = Web3GuardPolicy::default();
        for command in [
            "cast send 0xabc --rpc-url https://anything.test",
            "forge script Deploy.s.sol --broadcast",
            "solana program deploy p.so",
        ] {
            let findings = findings_for(command, &guard);
            assert!(
                !has(&findings, RuleId::Web3NetworkPolicyViolation),
                "an undeclared policy produced a violation: {command}"
            );
        }
    }
}
