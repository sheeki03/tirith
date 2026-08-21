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
    RpcPathMatcherId, SignerKindV2, TrustedRpcPathPrefix, Web3CommandFactsV2, Web3OperationV2,
    Web3ParseResultV2, Web3SafetyFlag, Web3WriteMode, MAX_TRUSTED_RPC_PATH_MATCHERS,
};
use crate::verdict::{Evidence, Finding, RuleId, Severity};
use crate::web3_policy::{
    NetworkIdentity, RpcMatcher, SubdomainPolicy, TrustedNetwork, Web3Family, Web3GuardAction,
    Web3GuardPolicy,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathProbeEffect {
    Deny,
    Network(usize),
}

#[derive(Clone)]
struct PathProbe {
    id: RpcPathMatcherId,
    matcher: RpcMatcher,
    effect: PathProbeEffect,
}

/// Private, bounded policy compilation shared by parsing and enforcement. The
/// parser sees only opaque IDs and transient prefixes; enforcement owns the
/// ID-to-policy meaning.
pub(crate) struct CompiledWeb3Guard {
    path_prefixes: Vec<TrustedRpcPathPrefix>,
    probes: Vec<PathProbe>,
    complete: bool,
}

impl CompiledWeb3Guard {
    pub(crate) fn new(guard: &Web3GuardPolicy) -> Self {
        let mut compiled = Self {
            path_prefixes: Vec::new(),
            probes: Vec::new(),
            complete: true,
        };
        for matcher in &guard.deny_rpc {
            compiled.push_matcher(matcher, PathProbeEffect::Deny);
        }
        for (index, network) in guard.networks.iter().enumerate() {
            for matcher in &network.endpoints {
                compiled.push_matcher(matcher, PathProbeEffect::Network(index));
            }
        }
        compiled
    }

    fn push_matcher(&mut self, matcher: &RpcMatcher, effect: PathProbeEffect) {
        let Some(prefix) = matcher.path_prefix.as_deref() else {
            return;
        };
        if self.path_prefixes.len() >= MAX_TRUSTED_RPC_PATH_MATCHERS {
            self.complete = false;
            return;
        }
        let id = RpcPathMatcherId::new(self.path_prefixes.len() as u64);
        let Some(private) = TrustedRpcPathPrefix::for_origin(
            id,
            prefix,
            &matcher.scheme,
            &matcher.host,
            matcher.port,
            matcher.subdomains == SubdomainPolicy::HostAndSubdomains,
        ) else {
            self.complete = false;
            return;
        };
        self.path_prefixes.push(private);
        self.probes.push(PathProbe {
            id,
            matcher: matcher.clone(),
            effect,
        });
    }

    /// Parse and bind facts to this exact private matcher vector in one step.
    /// The returned marker owns its facts and cannot be deserialized or
    /// constructed outside this module, so enforcement never reinterprets
    /// matcher IDs from a legacy file, IPC peer, or different policy compile.
    pub(crate) fn analyze(
        &self,
        command: &str,
        shell: crate::tokenize::ShellType,
        mut context: crate::rules::web3::Web3ParseContextV2,
    ) -> BoundWeb3Parse {
        context.trusted_rpc_path_prefixes = Some(self.path_prefixes.clone());
        BoundWeb3Parse {
            result: crate::rules::web3::parse_web3_commands_v2(command, shell, &context),
        }
    }
}

pub(crate) struct BoundWeb3Parse {
    result: Web3ParseResultV2,
}

#[derive(Debug, Clone)]
pub(crate) struct Web3Decision {
    pub(crate) findings: Vec<Finding>,
    pub(crate) action: Web3GuardAction,
    pub(crate) approval_cause: Option<String>,
}

impl Web3Decision {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            action: Web3GuardAction::Allow,
            approval_cause: None,
        }
    }

    fn apply(
        &mut self,
        facts: &Web3CommandFactsV2,
        action: Web3GuardAction,
        status: &'static str,
        description: &'static str,
    ) {
        if action == Web3GuardAction::Allow {
            return;
        }
        if action > self.action {
            self.action = action;
            self.approval_cause =
                (action == Web3GuardAction::RequireApproval).then(|| description.to_string());
        }
        self.findings.push(policy_finding_for_action(
            facts,
            action,
            status,
            description,
        ));
    }

    fn apply_without_facts(
        &mut self,
        action: Web3GuardAction,
        status: &'static str,
        description: &'static str,
    ) {
        if action == Web3GuardAction::Allow {
            return;
        }
        if action > self.action {
            self.action = action;
            self.approval_cause =
                (action == Web3GuardAction::RequireApproval).then(|| description.to_string());
        }
        self.findings.push(Finding {
            rule_id: RuleId::AnalysisIncomplete,
            severity: action_severity(action),
            title: "Web3 analysis incomplete".to_string(),
            description: description.to_string(),
            evidence: policy_evidence("unknown", action, status),
            human_view: Some("Web3 guard — resolve the analysis gap before execution.".into()),
            agent_view: Some("tirith: web3 analysis incomplete".into()),
            mitre_id: None,
            custom_rule_id: None,
        });
    }
}

/// Build findings for one parsed command line. Because a standalone result has
/// no unforgeable matcher-context capability, guards with private path probes
/// fail closed here. Call [`check_command_with_context`] when path matchers are
/// configured.
pub fn check(result: &Web3ParseResultV2, guard: &Web3GuardPolicy) -> Vec<Finding> {
    let compiled = CompiledWeb3Guard::new(guard);
    if compiled.probes.is_empty() || result.commands.is_empty() {
        decide(
            &BoundWeb3Parse {
                result: result.clone(),
            },
            guard,
            &compiled,
            false,
        )
        .findings
    } else {
        policy_context_mismatch_decision().findings
    }
}

/// Parse and enforce a command while binding opaque RPC path outcomes to the
/// exact compiled guard. This is the enforcement-capable public entry point for
/// policies containing path matchers.
pub fn check_command_with_context(
    command: &str,
    shell: crate::tokenize::ShellType,
    context: &crate::rules::web3::Web3ParseContextV2,
    guard: &Web3GuardPolicy,
) -> Vec<Finding> {
    let compiled = CompiledWeb3Guard::new(guard);
    let bound = compiled.analyze(command, shell, context.clone());
    decide(&bound, guard, &compiled, false).findings
}

pub(crate) fn decide(
    bound: &BoundWeb3Parse,
    guard: &Web3GuardPolicy,
    compiled: &CompiledWeb3Guard,
    command_card_approved: bool,
) -> Web3Decision {
    let result = &bound.result;
    let mut decision = Web3Decision::new();
    for facts in &result.commands {
        push_state_change(&mut decision.findings, facts);
        push_signer_risk(&mut decision.findings, facts);
        if !guard.is_default() {
            apply_policy(&mut decision, facts, guard, compiled, command_card_approved);
        }
    }
    if !guard.is_default() && !result.completeness.is_complete() {
        if let Some(facts) = result.commands.first() {
            decision.apply(
                facts,
                guard.action_incomplete_analysis,
                "incomplete_analysis",
                "Web3 analysis did not cover the complete command.",
            );
        } else {
            decision.apply_without_facts(
                guard.action_incomplete_analysis,
                "incomplete_analysis",
                "Web3 analysis did not produce complete command facts.",
            );
        }
    }
    decision
}

fn policy_context_mismatch_decision() -> Web3Decision {
    let mut decision = Web3Decision::new();
    decision.apply_without_facts(
        Web3GuardAction::Block,
        "policy_context_mismatch",
        "Web3 parse facts are not bound to this exact RPC matcher context.",
    );
    decision
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

/// Decide the Hardhat production-run carve-out from the trusted network that
/// policy selected, rather than from the attacker-controlled selector spelling.
fn trusted_network_is_development(network: &TrustedNetwork) -> bool {
    DEVELOPMENT_NETWORK_ALIASES
        .iter()
        .any(|known| network.name.eq_ignore_ascii_case(known))
        || (!network.endpoints.is_empty()
            && network.endpoints.iter().all(|endpoint| {
                matches!(endpoint.host.as_str(), "localhost" | "127.0.0.1" | "::1")
            }))
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
                // Prose discipline: an alias word followed by a plain-space word
                // ("mnemonic appears") trips the mandatory value redactor and
                // mangles the sentence, so the parenthesized form is deliberate.
                "Raw signer material appears literally in this command (a private key, \
                 keypair, or mnemonic). It is readable from the process table, the shell \
                 history, and any log that captured the command. Treat the key as compromised."
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

fn apply_policy(
    decision: &mut Web3Decision,
    facts: &Web3CommandFactsV2,
    guard: &Web3GuardPolicy,
    compiled: &CompiledWeb3Guard,
    command_card_approved: bool,
) {
    let rpc = evaluate_rpc(facts, guard, compiled);
    if rpc.denied {
        decision.apply(
            facts,
            Web3GuardAction::Block,
            "denied_endpoint",
            "The endpoint this command contacts is denied by the trusted policy.",
        );
    }
    if rpc.unclassified && !guard.networks.is_empty() {
        decision.apply(
            facts,
            guard.action_unclassified_rpc,
            "unclassified_endpoint",
            "No trusted network claims this endpoint; policy cannot vouch for it.",
        );
    }
    if rpc.incomplete || !compiled.complete || !facts.completeness.is_complete() {
        decision.apply(
            facts,
            guard.action_incomplete_analysis,
            "incomplete_analysis",
            "Web3 policy matching could not be completed without ambiguity.",
        );
    }

    if is_state_changing(facts) {
        if facts.signers.is_empty() {
            decision.apply(
                facts,
                guard.action_incomplete_analysis,
                "signer_missing",
                "A state-changing Web3 command has no resolved signer.",
            );
        }
        for tagged in &facts.signers {
            let permitted = trusted_signer_kind(tagged.signer.kind())
                .is_some_and(|trusted| guard.permits_signer(trusted));
            if !permitted {
                decision.apply(
                    facts,
                    Web3GuardAction::Block,
                    "signer_not_permitted",
                    "A signer used by this command is not permitted by the trusted policy.",
                );
            }
        }

        for destination in destinations(facts) {
            let Some(value) = destination.value.as_deref() else {
                decision.apply(
                    facts,
                    guard.action_incomplete_analysis,
                    "destination_unresolved",
                    "A state-changing destination could not be resolved.",
                );
                continue;
            };
            let denied = guard.deny_destinations.iter().any(|candidate| {
                if rpc
                    .network
                    .is_some_and(|network| network.family == Web3Family::Evm)
                    || value.starts_with("0x")
                {
                    candidate.eq_ignore_ascii_case(value)
                } else {
                    candidate == value
                }
            });
            if denied {
                decision.apply(
                    facts,
                    Web3GuardAction::Block,
                    "denied_destination",
                    "A destination this command touches is denied by trusted policy.",
                );
            }
        }

        if facts.tool == crate::rules::web3::Web3ToolFamily::Hardhat
            && facts.operation == Web3OperationV2::RunScript
            && rpc
                .network
                .is_some_and(|network| !trusted_network_is_development(network))
        {
            decision.apply(
                facts,
                guard.action_ambiguous_hardhat_production_run,
                "ambiguous_hardhat_production_run",
                "Hardhat run executes arbitrary script code against a trusted non-development network.",
            );
        }

        if guard.require_command_card && !command_card_approved {
            decision.apply(
                facts,
                Web3GuardAction::Block,
                "command_card_required",
                "Trusted policy requires an exactly bound signed command card for this operation.",
            );
        }
    }
}

#[derive(Default)]
struct RpcEvaluation<'a> {
    denied: bool,
    unclassified: bool,
    incomplete: bool,
    network: Option<&'a TrustedNetwork>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Web3ApprovalObservation {
    pub(crate) network_policy_id: String,
    pub(crate) family: String,
    pub(crate) chain_or_genesis: String,
    pub(crate) signer_kind: String,
    pub(crate) signers: Vec<crate::command_card::Web3CardSignerBinding>,
    pub(crate) operations: Vec<String>,
    pub(crate) destinations: Vec<String>,
    pub(crate) artifacts: Vec<String>,
}

/// Why an exact schema-v2 command-card template could not be derived from the
/// same bounded Web3 analysis used by enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Web3CardTemplateError {
    RefusedSignerMaterial,
    ApprovalKeyMissing,
    AnalysisIncomplete,
    ExecutableIdentityUnbound,
    ArtifactExecutionRecheckUnavailable,
    InvalidBindings,
}

impl std::fmt::Display for Web3CardTemplateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::RefusedSignerMaterial => {
                "command-card authoring refuses raw or interactive signer material"
            }
            Self::ApprovalKeyMissing => {
                "an exact Web3 card requires the approval key that will sign it"
            }
            Self::AnalysisIncomplete => {
                "the command did not produce one complete, unambiguous Web3 approval projection"
            }
            Self::ExecutableIdentityUnbound => {
                "an exact Web3 card cannot be authored until execution binds the analyzed executable identity"
            }
            Self::ArtifactExecutionRecheckUnavailable => {
                "an exact Web3 artifact card cannot be authored until execution rechecks the analyzed artifact object"
            }
            Self::InvalidBindings => "the derived Web3 card bindings are incomplete",
        })
    }
}

impl std::error::Error for Web3CardTemplateError {}

/// Privacy firewall run for every card-authoring attempt, independently of
/// whether Web3 approval keys are configured. The result is categorical and
/// never contains the command, signer value, or credential path.
pub fn refuse_command_card_secret_material(
    command: &str,
    shell: crate::tokenize::ShellType,
    cwd: Option<&str>,
) -> Result<(), Web3CardTemplateError> {
    let context = match cwd {
        Some(cwd) => crate::rules::web3::Web3ParseContextV2::for_cwd(cwd),
        None => crate::rules::web3::Web3ParseContextV2::without_filesystem(),
    };
    let parsed = crate::rules::web3::parse_web3_commands_v2(command, shell, &context);
    let refused = parsed.commands.iter().any(|facts| {
        facts.signers.iter().any(|tagged| {
            matches!(
                tagged.signer.kind(),
                SignerKindV2::RawPrivateKey
                    | SignerKindV2::RawKeypair
                    | SignerKindV2::Mnemonic
                    | SignerKindV2::Stdin
                    | SignerKindV2::Prompt
            )
        })
    });
    if refused {
        Err(Web3CardTemplateError::RefusedSignerMaterial)
    } else {
        Ok(())
    }
}

/// Derive an unsigned exact schema-v2 Web3 binding from the enforcement parser.
/// A command with no state-changing Web3 operation returns `Ok(None)` so the
/// existing v1 command-card workflow remains source- and behavior-compatible.
pub fn command_card_bindings_for_command(
    command: &str,
    shell: crate::tokenize::ShellType,
    cwd: Option<&str>,
    guard: &Web3GuardPolicy,
    policy_identity: &str,
    approval_key_id: Option<&str>,
) -> Result<Option<crate::command_card::Web3CardBindings>, Web3CardTemplateError> {
    let context = match cwd {
        Some(cwd) => crate::rules::web3::Web3ParseContextV2::for_cwd(cwd),
        None => crate::rules::web3::Web3ParseContextV2::without_filesystem(),
    };
    let compiled = CompiledWeb3Guard::new(guard);
    let bound = compiled.analyze(command, shell, context);
    if !bound.result.commands.iter().any(is_state_changing) {
        return Ok(None);
    }
    if bound
        .result
        .commands
        .iter()
        .filter(|facts| is_state_changing(facts))
        .any(|facts| facts.artifact.is_some())
    {
        return Err(Web3CardTemplateError::ArtifactExecutionRecheckUnavailable);
    }
    if bound
        .result
        .completeness
        .gaps()
        .any(|gap| gap == crate::effects::IncompleteReasonV2::DynamicExecutionUnsupported)
    {
        return Err(Web3CardTemplateError::ExecutableIdentityUnbound);
    }
    let approval_key_id = approval_key_id
        .filter(|key_id| !key_id.is_empty())
        .ok_or(Web3CardTemplateError::ApprovalKeyMissing)?;
    let observation = approval_observation(&bound, guard, &compiled)
        .ok_or(Web3CardTemplateError::AnalysisIncomplete)?;

    let bindings = crate::command_card::Web3CardBindings {
        shell: Some(shell_token(shell).to_string()),
        network_policy_id: observation.network_policy_id,
        family: observation.family,
        chain_or_genesis: observation.chain_or_genesis,
        signer_kind: observation.signer_kind,
        signers: observation.signers,
        destinations: observation.destinations,
        artifact_sha256: Vec::new(),
        policy_identity: policy_identity.to_string(),
        operations: observation.operations,
        approval_key_id: approval_key_id.to_string(),
    };
    bindings
        .validate()
        .map_err(|_| Web3CardTemplateError::InvalidBindings)?;
    if bindings.signers.is_empty() {
        return Err(Web3CardTemplateError::InvalidBindings);
    }
    Ok(Some(bindings))
}

/// Build the exact semantic projection a v2 command card must bind. Any
/// unresolved or heterogeneous field refuses approval instead of selecting a
/// convenient legacy projection.
pub(crate) fn approval_observation(
    bound: &BoundWeb3Parse,
    guard: &Web3GuardPolicy,
    compiled: &CompiledWeb3Guard,
) -> Option<Web3ApprovalObservation> {
    approval_observation_inner(&bound.result, guard, compiled)
}

fn approval_observation_inner(
    result: &Web3ParseResultV2,
    guard: &Web3GuardPolicy,
    compiled: &CompiledWeb3Guard,
) -> Option<Web3ApprovalObservation> {
    if !result.completeness.is_complete() || !compiled.complete {
        return None;
    }
    let mut network: Option<&TrustedNetwork> = None;
    let mut primary_signer_kind = None;
    let mut signer_projection = Vec::new();
    let mut operations = Vec::new();
    let mut observed_destinations = Vec::new();
    let mut artifacts = Vec::new();
    for facts in result
        .commands
        .iter()
        .filter(|facts| is_state_changing(facts))
    {
        if !facts.completeness.is_complete() {
            return None;
        }
        let evaluated = evaluate_rpc(facts, guard, compiled);
        if evaluated.denied || evaluated.incomplete || evaluated.unclassified {
            return None;
        }
        let current_network = evaluated.network?;
        if network.is_some_and(|prior| prior != current_network) {
            return None;
        }
        network = Some(current_network);
        if facts.signers.is_empty() {
            return None;
        }
        for signer in &facts.signers {
            let current = card_signer_kind(signer.signer.kind())?;
            primary_signer_kind.get_or_insert(current);
            let reference = signer
                .signer
                .nonsecret_reference()
                .map(signer_reference_digest);
            signer_projection.push(crate::command_card::Web3CardSignerBinding {
                role: signer_role_token(signer.role).to_string(),
                kind: current.to_string(),
                reference_sha256: reference,
            });
        }
        operations.push(operation_token(facts));
        for destination in destinations(facts) {
            let value = destination.value.as_deref()?;
            observed_destinations.push(
                if destination.kind == crate::rules::web3::DestinationKind::ProgramIdFile {
                    format!("sha256:{}", signer_reference_digest(value))
                } else {
                    value.to_string()
                },
            );
        }
        if let Some(artifact) = facts.artifact.as_ref() {
            artifacts.push(artifact.value.clone()?);
        }
    }
    let network = network?;
    let (family, chain_or_genesis) = match &network.identity {
        NetworkIdentity::Evm { evm_chain_id } => ("evm", evm_chain_id.to_string()),
        NetworkIdentity::Solana {
            solana_cluster,
            solana_genesis,
        } => ("solana", format!("{solana_cluster}:{solana_genesis}")),
    };
    Some(Web3ApprovalObservation {
        network_policy_id: network.name.clone(),
        family: family.to_string(),
        chain_or_genesis,
        signer_kind: primary_signer_kind?.to_string(),
        signers: signer_projection,
        operations,
        destinations: observed_destinations,
        artifacts,
    })
}

fn shell_token(shell: crate::tokenize::ShellType) -> &'static str {
    match shell {
        crate::tokenize::ShellType::Posix => "posix",
        crate::tokenize::ShellType::Fish => "fish",
        crate::tokenize::ShellType::PowerShell => "powershell",
        crate::tokenize::ShellType::Cmd => "cmd",
    }
}

fn signer_reference_digest(reference: &str) -> String {
    if let Some(digest) = reference
        .strip_prefix("sha256:")
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return digest.to_ascii_lowercase();
    }
    signer_reference_digest_bytes(reference.as_bytes())
}

fn signer_reference_digest_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

fn card_signer_kind(kind: SignerKindV2) -> Option<&'static str> {
    match trusted_signer_kind(kind)? {
        crate::web3_policy::TrustedSignerKind::HardwareWallet => Some("hardware_wallet"),
        crate::web3_policy::TrustedSignerKind::KeystoreFile => Some("keystore_file"),
        crate::web3_policy::TrustedSignerKind::KeypairFile => Some("keypair_file"),
        crate::web3_policy::TrustedSignerKind::AccountAlias => Some("account_alias"),
        crate::web3_policy::TrustedSignerKind::UnlockedNode => Some("unlocked_node"),
    }
}

fn evaluate_rpc<'a>(
    facts: &Web3CommandFactsV2,
    guard: &'a Web3GuardPolicy,
    compiled: &CompiledWeb3Guard,
) -> RpcEvaluation<'a> {
    let Some(rpc) = facts.rpc.as_ref() else {
        if facts.tool == crate::rules::web3::Web3ToolFamily::Hardhat {
            if let Some(selector) = facts.network.network.as_ref().filter(|selector| {
                selector.source != crate::rules::web3::SelectorSource::Unresolved
            }) {
                let network = guard
                    .selector_aliases
                    .get("hardhat")
                    .and_then(|aliases| aliases.get(&selector.value))
                    .and_then(|name| guard.networks.iter().find(|network| network.name == *name));
                let mut evaluation = RpcEvaluation {
                    unclassified: network.is_none(),
                    incomplete: network.is_none(),
                    network,
                    ..RpcEvaluation::default()
                };
                apply_network_identity(facts, &mut evaluation);
                return evaluation;
            }
        }
        return RpcEvaluation {
            incomplete: is_state_changing(facts),
            ..RpcEvaluation::default()
        };
    };
    if let Some(alias) = rpc.alias.as_deref() {
        let network = guard
            .selector_aliases
            .get(tool_token(facts))
            .and_then(|aliases| aliases.get(alias))
            .and_then(|name| guard.networks.iter().find(|network| network.name == *name));
        let mut evaluation = RpcEvaluation {
            unclassified: network.is_none(),
            incomplete: network.is_none()
                && rpc.source == crate::rules::web3::SelectorSource::Unresolved,
            network,
            ..RpcEvaluation::default()
        };
        apply_network_identity(facts, &mut evaluation);
        return evaluation;
    }
    let (Some(scheme), Some(host)) = (rpc.scheme.as_deref(), rpc.host.as_deref()) else {
        return RpcEvaluation {
            unclassified: true,
            incomplete: true,
            ..RpcEvaluation::default()
        };
    };

    let mut evaluation = RpcEvaluation::default();
    let mut candidate_networks = Vec::new();
    for matcher in guard
        .deny_rpc
        .iter()
        .filter(|matcher| matcher.path_prefix.is_none())
    {
        evaluation.denied |= matcher.matches_origin(scheme, host, rpc.port);
    }
    for (index, network) in guard.networks.iter().enumerate() {
        if network
            .endpoints
            .iter()
            .filter(|matcher| matcher.path_prefix.is_none())
            .any(|matcher| matcher.matches_origin(scheme, host, rpc.port))
        {
            push_unique_network(&mut candidate_networks, index);
        }
    }
    for probe in compiled
        .probes
        .iter()
        .filter(|probe| probe.matcher.matches_origin(scheme, host, rpc.port))
    {
        match rpc.trusted_path_outcome(probe.id) {
            Some(true) => match probe.effect {
                PathProbeEffect::Deny => evaluation.denied = true,
                PathProbeEffect::Network(index) => {
                    push_unique_network(&mut candidate_networks, index)
                }
            },
            Some(false) => {}
            None => {
                // A relevant outcome can be absent because the bounded parser
                // retained fewer matcher results than the compiled policy. A
                // missing deny outcome must never turn the 65th deny into the
                // policy's weaker incomplete-analysis action.
                if probe.effect == PathProbeEffect::Deny {
                    evaluation.denied = true;
                }
                evaluation.incomplete = true;
            }
        }
    }
    let mut identity_matches = Vec::new();
    let mut identity_was_unparseable = false;
    for index in candidate_networks.iter().copied() {
        let Some(network) = guard.networks.get(index) else {
            evaluation.incomplete = true;
            continue;
        };
        match network_identity_matches(facts, network) {
            Some(true) => identity_matches.push(index),
            Some(false) => {}
            None => identity_was_unparseable = true,
        }
    }
    evaluation.incomplete |= identity_was_unparseable;
    match identity_matches.as_slice() {
        [index] => evaluation.network = guard.networks.get(*index),
        [] => {
            // An endpoint matched policy but contradicted every declared chain
            // identity. Preserve the historical fail-closed incomplete signal;
            // a plain unknown endpoint remains only unclassified.
            evaluation.incomplete |= !candidate_networks.is_empty();
        }
        _ => {
            // Never let declaration order choose between two networks that both
            // claim the same observed endpoint and chain evidence.
            evaluation.incomplete = true;
        }
    }
    evaluation.unclassified = evaluation.network.is_none();
    evaluation
}

fn push_unique_network(candidates: &mut Vec<usize>, index: usize) {
    if !candidates.contains(&index) {
        candidates.push(index);
    }
}

fn apply_network_identity(facts: &Web3CommandFactsV2, evaluation: &mut RpcEvaluation<'_>) {
    if let Some(network) = evaluation.network {
        match network_identity_matches(facts, network) {
            Some(true) => {}
            Some(false) | None => {
                evaluation.incomplete = true;
                evaluation.network = None;
                evaluation.unclassified = true;
            }
        }
    }
}

fn network_identity_matches(facts: &Web3CommandFactsV2, network: &TrustedNetwork) -> Option<bool> {
    let Some(chain) = facts
        .network
        .chain
        .as_ref()
        .map(|selector| selector.value.as_str())
    else {
        return Some(true);
    };
    match &network.identity {
        NetworkIdentity::Evm { evm_chain_id } => {
            parse_evm_chain_id(chain).map(|observed| observed == *evm_chain_id)
        }
        NetworkIdentity::Solana {
            solana_cluster,
            solana_genesis,
        } => Some(chain == solana_cluster || chain == solana_genesis),
    }
}

fn parse_evm_chain_id(value: &str) -> Option<u64> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map(|hex| u64::from_str_radix(hex, 16).ok())
        .unwrap_or_else(|| value.parse::<u64>().ok())
}

fn destinations(facts: &Web3CommandFactsV2) -> Vec<&crate::rules::web3::DestinationReference> {
    if facts.destinations.is_empty() {
        facts.destination.iter().collect()
    } else {
        facts.destinations.iter().collect()
    }
}

fn policy_finding_for_action(
    facts: &Web3CommandFactsV2,
    action: Web3GuardAction,
    status: &str,
    description: &str,
) -> Finding {
    Finding {
        rule_id: RuleId::Web3NetworkPolicyViolation,
        severity: action_severity(action),
        title: match action {
            Web3GuardAction::Block => "Web3 operation contradicts trusted policy",
            Web3GuardAction::RequireApproval => "Web3 operation requires approval",
            Web3GuardAction::Warn | Web3GuardAction::Allow => "Web3 policy warning",
        }
        .to_string(),
        description: description.to_string(),
        evidence: policy_evidence(tool_token(facts), action, status),
        human_view: Some("Web3 guard — compare against `tirith policy effective`.".to_string()),
        agent_view: Some(
            match action {
                Web3GuardAction::Block => "tirith refused: web3 policy violation",
                Web3GuardAction::RequireApproval => "tirith: web3 approval required",
                Web3GuardAction::Warn | Web3GuardAction::Allow => "tirith: web3 policy warning",
            }
            .to_string(),
        ),
        mitre_id: (action == Web3GuardAction::Block).then(|| "T1565".to_string()),
        custom_rule_id: None,
    }
}

fn policy_evidence(tool: &str, action: Web3GuardAction, status: &str) -> Vec<Evidence> {
    let mut evidence = vec![Evidence::Text {
        detail: format!("tirith:v1:web3_policy;tool={tool};status={status}"),
    }];
    if action == Web3GuardAction::Block {
        evidence.push(Evidence::Text {
            detail: "tirith:v1:web3_enforcement;action=block".to_string(),
        });
    }
    evidence
}

pub(crate) fn is_authoritative_block_finding(finding: &Finding) -> bool {
    if !matches!(
        finding.rule_id,
        RuleId::Web3NetworkPolicyViolation | RuleId::AnalysisIncomplete
    ) {
        return false;
    }
    finding.evidence.iter().any(|evidence| {
        let Evidence::Text { detail } = evidence else {
            return false;
        };
        detail == "tirith:v1:web3_enforcement;action=block"
    })
}

fn action_severity(action: Web3GuardAction) -> Severity {
    match action {
        Web3GuardAction::Block => Severity::High,
        Web3GuardAction::RequireApproval | Web3GuardAction::Warn => Severity::Medium,
        Web3GuardAction::Allow => Severity::Info,
    }
}

/// Map every representable parsed signer kind onto the policy vocabulary.
/// `None` is a deliberate refusal: raw, ambient, interactive, KMS, and unknown
/// kinds have no policy spelling and therefore cannot be silently trusted.
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

    fn policy_status(decision: &Web3Decision, status: &str) -> bool {
        let expected = format!("status={status}");
        decision.findings.iter().any(|finding| {
            finding.evidence.iter().any(|evidence| {
                matches!(evidence, Evidence::Text { detail } if detail.split(';').any(|field| field == expected.as_str()))
            })
        })
    }

    fn evm_network(name: &str, host: &str) -> TrustedNetwork {
        TrustedNetwork {
            name: name.to_string(),
            family: Web3Family::Evm,
            identity: NetworkIdentity::Evm { evm_chain_id: 1 },
            endpoints: vec![RpcMatcher {
                scheme: "https".into(),
                host: host.into(),
                port: None,
                path_prefix: None,
                subdomains: SubdomainPolicy::ExactHost,
            }],
        }
    }

    fn findings_for(command: &str, guard: &Web3GuardPolicy) -> Vec<Finding> {
        let compiled = CompiledWeb3Guard::new(guard);
        let bound = compiled.analyze(
            command,
            ShellType::Posix,
            Web3ParseContextV2::without_filesystem(),
        );
        decide(&bound, guard, &compiled, false).findings
    }

    #[test]
    fn matcher_outcomes_are_bound_to_the_exact_compiled_policy_context() {
        let guard_for = |prefix: &str| Web3GuardPolicy {
            networks: vec![TrustedNetwork {
                name: "prod".into(),
                family: Web3Family::Evm,
                identity: NetworkIdentity::Evm { evm_chain_id: 1 },
                endpoints: vec![RpcMatcher {
                    scheme: "https".into(),
                    host: "rpc.test".into(),
                    port: None,
                    path_prefix: Some(prefix.into()),
                    subdomains: SubdomainPolicy::ExactHost,
                }],
            }],
            ..Web3GuardPolicy::default()
        };
        let parsed_guard = guard_for("/public");
        let enforcing_guard = guard_for("/private");
        let parsed_compiled = CompiledWeb3Guard::new(&parsed_guard);
        let parsed = parsed_compiled.analyze(
            "cast call 0xabc --rpc-url https://rpc.test/public",
            ShellType::Posix,
            Web3ParseContextV2::without_filesystem(),
        );

        assert!(!decide(&parsed, &parsed_guard, &parsed_compiled, false)
            .findings
            .iter()
            .any(|finding| finding.evidence.iter().any(
                |evidence| matches!(evidence, Evidence::Text { detail } if detail.contains("status=policy_context_mismatch"))
            )));
        let refused = check(&parsed.result, &enforcing_guard);
        assert!(refused.iter().any(|finding| finding.evidence.iter().any(
            |evidence| matches!(evidence, Evidence::Text { detail } if detail.contains("status=policy_context_mismatch"))
        )));
    }

    #[test]
    fn command_card_privacy_firewall_runs_without_policy_keys_and_never_echoes() {
        let private_key = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let keypair = format!(
            "[{}]",
            std::iter::repeat_n("7", 64).collect::<Vec<_>>().join(",")
        );
        for command in [
            format!("cast send 0xabc --private-key {private_key}"),
            format!("forge script X --broadcast --mnemonic '{mnemonic}'"),
            format!(
                "solana --url https://api.devnet.solana.com --keypair '{keypair}' program deploy p.so"
            ),
        ] {
            let error = refuse_command_card_secret_material(
                &command,
                ShellType::Posix,
                None,
            )
            .unwrap_err();
            assert_eq!(error, Web3CardTemplateError::RefusedSignerMaterial);
            let rendered = error.to_string();
            assert!(!rendered.contains(private_key));
            assert!(!rendered.contains(mnemonic));
            assert!(!rendered.contains(&keypair));
        }
        refuse_command_card_secret_material("cast send 0xabc --ledger", ShellType::Posix, None)
            .unwrap();
    }

    fn has(findings: &[Finding], rule: RuleId) -> bool {
        findings.iter().any(|finding| finding.rule_id == rule)
    }

    #[test]
    fn authored_finding_prose_survives_mandatory_redaction() {
        // "…or mnemonic appears literally…" taught the value redactor to eat
        // the word after the alias; the parenthesized wording must not
        // regress, or the CLI shows `[REDACTED:web3_secret]` mid-sentence.
        let guard = Web3GuardPolicy::default();
        let findings = findings_for(
            "cast send 0xabc --private-key 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &guard,
        );
        for finding in &findings {
            let mut clone = finding.clone();
            crate::redact::redact_finding(&mut clone, &[]);
            assert_eq!(
                clone.description, finding.description,
                "description mangled by mandatory redaction"
            );
            assert_eq!(
                clone.title, finding.title,
                "title mangled by mandatory redaction"
            );
        }
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
        let unclassified = findings
            .iter()
            .find(|finding| {
                finding.rule_id == RuleId::Web3NetworkPolicyViolation
                    && finding.evidence.iter().any(|evidence| {
                        matches!(evidence, Evidence::Text { detail } if detail.contains("status=unclassified_endpoint"))
                    })
            })
            .expect("an unclassified endpoint is still reported");
        // Reported, but NOT as a High violation or malicious-host claim.
        assert_eq!(unclassified.severity, Severity::Medium);
        assert!(unclassified.description.contains("cannot vouch"));

        // With the action set to allow, it is silent entirely.
        let permissive = Web3GuardPolicy {
            action_unclassified_rpc: Web3GuardAction::Allow,
            ..guard.clone()
        };
        let quiet = findings_for(
            "cast send 0xabc --rpc-url https://unknown.test",
            &permissive,
        );
        assert!(!quiet.iter().any(|finding| finding.evidence.iter().any(
            |evidence| matches!(evidence, Evidence::Text { detail } if detail.contains("status=unclassified_endpoint"))
        )));
        assert!(quiet.iter().any(|finding| finding.evidence.iter().any(
            |evidence| matches!(evidence, Evidence::Text { detail } if detail.contains("status=incomplete_analysis"))
        )), "allowing an unclassified endpoint must not erase the independent executable-identity gap");
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

    #[test]
    fn every_declared_unclassified_action_survives_as_a_decision() {
        for (action, expected_finding) in [
            (Web3GuardAction::Allow, false),
            (Web3GuardAction::Warn, true),
            (Web3GuardAction::RequireApproval, true),
            (Web3GuardAction::Block, true),
        ] {
            let guard = Web3GuardPolicy {
                networks: vec![TrustedNetwork {
                    name: "prod".into(),
                    family: Web3Family::Evm,
                    identity: NetworkIdentity::Evm { evm_chain_id: 1 },
                    endpoints: vec![RpcMatcher {
                        scheme: "https".into(),
                        host: "trusted.test".into(),
                        port: None,
                        path_prefix: None,
                        subdomains: SubdomainPolicy::ExactHost,
                    }],
                }],
                action_unclassified_rpc: action,
                ..Web3GuardPolicy::default()
            };
            let compiled = CompiledWeb3Guard::new(&guard);
            let bound = compiled.analyze(
                "cast call 0xabc --rpc-url https://unknown.test",
                ShellType::Posix,
                Web3ParseContextV2::without_filesystem(),
            );
            let decision = decide(&bound, &guard, &compiled, false);
            assert_eq!(
                decision.action,
                action.stricter(guard.action_incomplete_analysis),
                "the independent executable-identity gap must remain in the final action"
            );
            assert_eq!(
                decision.findings.iter().any(|finding| finding.evidence.iter().any(
                    |evidence| matches!(evidence, Evidence::Text { detail } if detail.contains("status=unclassified_endpoint"))
                )),
                expected_finding
            );
            assert!(decision.findings.iter().any(|finding| finding.evidence.iter().any(
                |evidence| matches!(evidence, Evidence::Text { detail } if detail.contains("status=incomplete_analysis"))
            )));
        }
    }

    #[test]
    fn hardhat_selector_alias_and_command_card_actions_are_complete_lattices() {
        let aliases: std::collections::BTreeMap<String, String> =
            [("mainnet".to_string(), "prod".to_string())]
                .into_iter()
                .collect();
        for action in [
            Web3GuardAction::Allow,
            Web3GuardAction::Warn,
            Web3GuardAction::RequireApproval,
            Web3GuardAction::Block,
        ] {
            let guard = Web3GuardPolicy {
                networks: vec![evm_network("prod", "rpc.prod.test")],
                selector_aliases: [("hardhat".to_string(), aliases.clone())]
                    .into_iter()
                    .collect(),
                action_incomplete_analysis: Web3GuardAction::Allow,
                action_ambiguous_hardhat_production_run: action,
                ..Web3GuardPolicy::default()
            };
            let compiled = CompiledWeb3Guard::new(&guard);
            let bound = compiled.analyze(
                "hardhat run scripts/deploy.ts --network mainnet",
                ShellType::Posix,
                Web3ParseContextV2::without_filesystem(),
            );
            let decision = decide(&bound, &guard, &compiled, false);
            assert_eq!(decision.action, action);
            assert_eq!(
                policy_status(&decision, "ambiguous_hardhat_production_run"),
                action != Web3GuardAction::Allow
            );
            assert_eq!(
                decision.findings.iter().any(is_authoritative_block_finding),
                action == Web3GuardAction::Block
            );
        }

        let guard = Web3GuardPolicy {
            networks: vec![evm_network("prod", "rpc.prod.test")],
            selector_aliases: [(
                "hardhat".to_string(),
                [("devnet".to_string(), "prod".to_string())]
                    .into_iter()
                    .collect(),
            )]
            .into_iter()
            .collect(),
            action_incomplete_analysis: Web3GuardAction::Allow,
            action_ambiguous_hardhat_production_run: Web3GuardAction::Block,
            ..Web3GuardPolicy::default()
        };
        let compiled = CompiledWeb3Guard::new(&guard);
        let bound = compiled.analyze(
            "hardhat run scripts/deploy.ts --network devnet",
            ShellType::Posix,
            Web3ParseContextV2::without_filesystem(),
        );
        assert_eq!(
            decide(&bound, &guard, &compiled, false).action,
            Web3GuardAction::Block,
            "an attacker-controlled alias spelling must not override the trusted network identity"
        );

        let unmapped = compiled.analyze(
            "hardhat run scripts/deploy.ts --network unknown-selector",
            ShellType::Posix,
            Web3ParseContextV2::without_filesystem(),
        );
        let unmapped = decide(&unmapped, &guard, &compiled, false);
        assert_eq!(unmapped.action, guard.action_unclassified_rpc);
        assert!(policy_status(&unmapped, "unclassified_endpoint"));
        assert!(
            !policy_status(&unmapped, "incomplete_analysis"),
            "an explicitly allowed incomplete-analysis status must not emit a finding"
        );
        assert!(!policy_status(
            &unmapped,
            "ambiguous_hardhat_production_run"
        ));

        let required = Web3GuardPolicy {
            require_command_card: true,
            command_card_key_ids: ["trusted-key-id".to_string()].into_iter().collect(),
            action_ambiguous_hardhat_production_run: Web3GuardAction::Allow,
            ..guard
        };
        let compiled = CompiledWeb3Guard::new(&required);
        let bound = compiled.analyze(
            "hardhat run scripts/deploy.ts --network devnet",
            ShellType::Posix,
            Web3ParseContextV2::without_filesystem(),
        );
        let missing = decide(&bound, &required, &compiled, false);
        assert_eq!(missing.action, Web3GuardAction::Block);
        assert!(policy_status(&missing, "command_card_required"));
        let approved = decide(&bound, &required, &compiled, true);
        assert_eq!(approved.action, Web3GuardAction::Allow);
        assert!(!policy_status(&approved, "command_card_required"));
    }

    #[test]
    fn configured_incomplete_analysis_action_is_a_complete_lattice() {
        let oversized = "x".repeat(crate::rules::web3::MAX_INPUT_BYTES + 1);
        for action in [
            Web3GuardAction::Allow,
            Web3GuardAction::Warn,
            Web3GuardAction::RequireApproval,
            Web3GuardAction::Block,
        ] {
            let guard = Web3GuardPolicy {
                networks: vec![evm_network("prod", "rpc.prod.test")],
                action_incomplete_analysis: action,
                ..Web3GuardPolicy::default()
            };
            let compiled = CompiledWeb3Guard::new(&guard);
            let bound = compiled.analyze(
                "cast call 0xabc --rpc-url https://rpc.prod.test --chain 1",
                ShellType::Posix,
                Web3ParseContextV2::without_filesystem(),
            );
            assert!(!bound.result.completeness.is_complete());
            let decision = decide(&bound, &guard, &compiled, false);
            assert_eq!(decision.action, action);
            assert_eq!(
                policy_status(&decision, "incomplete_analysis"),
                action != Web3GuardAction::Allow
            );
            assert_eq!(
                decision.approval_cause.is_some(),
                action == Web3GuardAction::RequireApproval
            );
            assert_eq!(
                decision.findings.iter().any(is_authoritative_block_finding),
                action == Web3GuardAction::Block
            );

            let empty = compiled.analyze(
                &oversized,
                ShellType::Posix,
                Web3ParseContextV2::without_filesystem(),
            );
            assert!(empty.result.commands.is_empty());
            assert!(!empty.result.completeness.is_complete());
            let empty_decision = decide(&empty, &guard, &compiled, false);
            assert_eq!(empty_decision.action, action);
            assert_eq!(
                policy_status(&empty_decision, "incomplete_analysis"),
                action != Web3GuardAction::Allow
            );
        }
    }

    #[test]
    fn signer_policy_is_exhaustive_even_when_rpc_is_absent() {
        let guard = Web3GuardPolicy {
            allowed_signers: [crate::web3_policy::TrustedSignerKind::KeypairFile]
                .into_iter()
                .collect(),
            action_incomplete_analysis: Web3GuardAction::Allow,
            ..Web3GuardPolicy::default()
        };
        let compiled = CompiledWeb3Guard::new(&guard);

        let implicit_dir = tempfile::tempdir().unwrap();
        let config = implicit_dir.path().join("solana.yml");
        std::fs::write(&config, "keypair_path: implicit-wallet.json\n").unwrap();
        let mut implicit_context = Web3ParseContextV2::for_cwd(implicit_dir.path());
        implicit_context.solana_config_path = Some(config);

        let cases = [
            (
                "explicit",
                "solana --keypair explicit-wallet.json program deploy p.so",
                Web3ParseContextV2::without_filesystem(),
                Web3GuardAction::Allow,
            ),
            (
                "implicit",
                "solana program deploy p.so",
                implicit_context,
                Web3GuardAction::Allow,
            ),
            (
                "stdin",
                "solana --keypair - program deploy p.so",
                Web3ParseContextV2::without_filesystem(),
                Web3GuardAction::Block,
            ),
            (
                "prompt",
                "solana --keypair ASK program deploy p.so",
                Web3ParseContextV2::without_filesystem(),
                Web3GuardAction::Block,
            ),
            (
                "aws-kms",
                "cast send 0xabc --aws",
                Web3ParseContextV2::without_filesystem(),
                Web3GuardAction::Block,
            ),
            (
                "unknown",
                "solana --keypair 'vault://private-reference' program deploy p.so",
                Web3ParseContextV2::without_filesystem(),
                Web3GuardAction::Block,
            ),
        ];
        for (label, command, context, expected) in cases {
            let mut bound = compiled.analyze(command, ShellType::Posix, context);
            bound.result.commands[0].rpc = None;
            let decision = decide(&bound, &guard, &compiled, false);
            assert_eq!(decision.action, expected, "no-RPC signer case: {label}");
            assert_eq!(
                policy_status(&decision, "signer_not_permitted"),
                expected == Web3GuardAction::Block,
                "no-RPC signer case: {label}"
            );
        }
    }

    #[test]
    fn private_rpc_path_denies_are_boundary_aware_bounded_and_secret_free() {
        let canary = "C04-private-path-canary";
        let matcher = |host: &str, prefix: String| RpcMatcher {
            scheme: "https".into(),
            host: host.into(),
            port: None,
            path_prefix: Some(prefix),
            subdomains: SubdomainPolicy::ExactHost,
        };
        let guard = Web3GuardPolicy {
            deny_rpc: vec![matcher("rpc.test", "/private".into())],
            action_incomplete_analysis: Web3GuardAction::Allow,
            ..Web3GuardPolicy::default()
        };
        for path in [
            format!("/private/{canary}"),
            format!("/public/../private/{canary}"),
        ] {
            let findings = check_command_with_context(
                &format!("cast call 0xabc --rpc-url https://rpc.test{path}"),
                ShellType::Posix,
                &Web3ParseContextV2::without_filesystem(),
                &guard,
            );
            assert!(findings.iter().any(is_authoritative_block_finding));
            let rendered = format!("{findings:?} {}", serde_json::to_string(&findings).unwrap());
            assert!(!rendered.contains(canary));
            assert!(!rendered.contains(&path));
        }
        let boundary_negative = check_command_with_context(
            &format!("cast call 0xabc --rpc-url https://rpc.test/private2/{canary}"),
            ShellType::Posix,
            &Web3ParseContextV2::without_filesystem(),
            &guard,
        );
        assert!(!boundary_negative.iter().any(is_authoritative_block_finding));

        let mut deny_rpc = (0..crate::rules::web3::MAX_RETAINED_RPC_PATH_MATCH_OUTCOMES)
            .map(|index| matcher("rpc.test", format!("/nonmatching-{index}")))
            .collect::<Vec<_>>();
        deny_rpc.push(matcher("rpc.test", "/private".into()));
        let overflow_guard = Web3GuardPolicy {
            deny_rpc,
            action_incomplete_analysis: Web3GuardAction::Allow,
            ..Web3GuardPolicy::default()
        };
        let overflow = findings_for(
            "cast call 0xabc --rpc-url https://rpc.test/private/resource",
            &overflow_guard,
        );
        assert!(overflow.iter().any(is_authoritative_block_finding));

        let mut unrelated = (0..crate::rules::web3::MAX_RETAINED_RPC_PATH_MATCH_OUTCOMES)
            .map(|index| matcher("other.test", format!("/unrelated-{index}")))
            .collect::<Vec<_>>();
        unrelated.push(matcher("rpc.test", "/private".into()));
        let unrelated_guard = Web3GuardPolicy {
            deny_rpc: unrelated,
            action_incomplete_analysis: Web3GuardAction::Allow,
            ..Web3GuardPolicy::default()
        };
        assert!(findings_for(
            "cast call 0xabc --rpc-url https://rpc.test/private/resource",
            &unrelated_guard,
        )
        .iter()
        .any(is_authoritative_block_finding));
    }

    #[test]
    fn signer_and_destination_policy_are_independent_of_rpc_classification() {
        let guard = Web3GuardPolicy {
            allowed_signers: [crate::web3_policy::TrustedSignerKind::HardwareWallet]
                .into_iter()
                .collect(),
            deny_destinations: ["0xdead".to_string()].into_iter().collect(),
            ..Web3GuardPolicy::default()
        };
        let forbidden_signer = findings_for(
            "cast send 0xbeef --rpc-url https://rpc.test --keystore wallet.json",
            &guard,
        );
        assert!(forbidden_signer.iter().any(|finding| finding
            .evidence
            .iter()
            .any(|evidence| matches!(evidence, Evidence::Text { detail } if detail.contains("signer_not_permitted")))));

        let forbidden_destination = findings_for(
            "cast send 0xDeAd --rpc-url https://rpc.test --ledger",
            &guard,
        );
        assert!(forbidden_destination.iter().any(|finding| finding
            .evidence
            .iter()
            .any(|evidence| matches!(evidence, Evidence::Text { detail } if detail.contains("denied_destination")))));
    }

    #[test]
    fn evm_chain_identity_accepts_decimal_and_hex_but_not_unknown() {
        assert_eq!(parse_evm_chain_id("1"), Some(1));
        assert_eq!(parse_evm_chain_id("0x1"), Some(1));
        assert_eq!(parse_evm_chain_id("0X01"), Some(1));
        assert_eq!(parse_evm_chain_id("mainnet"), None);
    }

    #[test]
    fn rpc_candidates_are_identity_filtered_and_never_first_match_wins() {
        let endpoint = RpcMatcher {
            scheme: "https".into(),
            host: "shared.test".into(),
            port: None,
            path_prefix: None,
            subdomains: SubdomainPolicy::ExactHost,
        };
        let guard = Web3GuardPolicy {
            networks: vec![
                TrustedNetwork {
                    name: "first".into(),
                    family: Web3Family::Evm,
                    identity: NetworkIdentity::Evm { evm_chain_id: 1 },
                    endpoints: vec![endpoint.clone()],
                },
                TrustedNetwork {
                    name: "second".into(),
                    family: Web3Family::Evm,
                    identity: NetworkIdentity::Evm { evm_chain_id: 10 },
                    endpoints: vec![endpoint],
                },
            ],
            ..Web3GuardPolicy::default()
        };
        let compiled = CompiledWeb3Guard::new(&guard);
        let parsed = parse_web3_commands_v2(
            "cast send 0xdead --rpc-url https://shared.test --chain 10 --ledger",
            ShellType::Posix,
            &Web3ParseContextV2::without_filesystem(),
        );
        let selected = evaluate_rpc(&parsed.commands[0], &guard, &compiled);
        assert_eq!(
            selected.network.map(|network| network.name.as_str()),
            Some("second")
        );
        assert!(!selected.incomplete);
        assert!(!selected.unclassified);

        let ambiguous = parse_web3_commands_v2(
            "cast send 0xdead --rpc-url https://shared.test --ledger",
            ShellType::Posix,
            &Web3ParseContextV2::without_filesystem(),
        );
        let ambiguous = evaluate_rpc(&ambiguous.commands[0], &guard, &compiled);
        assert!(ambiguous.network.is_none());
        assert!(ambiguous.incomplete);
        assert!(ambiguous.unclassified);
    }

    #[test]
    fn exact_card_signer_projection_hashes_nonsecret_references() {
        let guard = Web3GuardPolicy {
            networks: vec![TrustedNetwork {
                name: "prod".into(),
                family: Web3Family::Evm,
                identity: NetworkIdentity::Evm { evm_chain_id: 1 },
                endpoints: vec![RpcMatcher {
                    scheme: "https".into(),
                    host: "rpc.test".into(),
                    port: None,
                    path_prefix: None,
                    subdomains: SubdomainPolicy::ExactHost,
                }],
            }],
            allowed_signers: [crate::web3_policy::TrustedSignerKind::KeystoreFile]
                .into_iter()
                .collect(),
            ..Web3GuardPolicy::default()
        };
        let compiled = CompiledWeb3Guard::new(&guard);
        let secret_path = "/Users/alice/.keys/production-wallet.json";
        let bound = compiled.analyze(
            &format!("cast send 0xdead --rpc-url https://rpc.test --keystore {secret_path}"),
            ShellType::Posix,
            Web3ParseContextV2::without_filesystem(),
        );
        assert!(!bound.result.completeness.is_complete());
        assert!(
            approval_observation(&bound, &guard, &compiled).is_none(),
            "runtime approval must refuse an executable whose identity is not snapshotted"
        );
        let reference = bound.result.commands[0].signers[0]
            .signer
            .nonsecret_reference()
            .unwrap();
        let projection = crate::command_card::Web3CardSignerBinding {
            role: "default".to_string(),
            kind: "keystore_file".to_string(),
            reference_sha256: Some(signer_reference_digest(reference)),
        };
        let wire = serde_json::to_string(&projection).unwrap();
        assert!(!wire.contains(secret_path));
        assert!(!wire.contains("production-wallet"));
        assert!(projection
            .reference_sha256
            .as_deref()
            .is_some_and(|digest| digest.len() == 64));
        let serialized = serde_json::to_string(&bound.result).unwrap();
        let decoded = Web3ParseResultV2::from_json_slice_bounded(serialized.as_bytes()).unwrap();
        let projected_reference = decoded.commands[0].signers[0]
            .signer
            .nonsecret_reference()
            .unwrap();
        assert_eq!(
            signer_reference_digest(projected_reference),
            projection.reference_sha256.unwrap(),
            "privacy projection must preserve exact card identity"
        );
    }

    #[test]
    fn exact_card_authoring_refuses_unbound_execution_and_artifact_rechecks() {
        let guard = Web3GuardPolicy {
            networks: vec![TrustedNetwork {
                name: "prod".into(),
                family: Web3Family::Evm,
                identity: NetworkIdentity::Evm { evm_chain_id: 1 },
                endpoints: vec![RpcMatcher {
                    scheme: "https".into(),
                    host: "rpc.test".into(),
                    port: Some(443),
                    path_prefix: None,
                    subdomains: SubdomainPolicy::ExactHost,
                }],
            }],
            allowed_signers: [crate::web3_policy::TrustedSignerKind::HardwareWallet]
                .into_iter()
                .collect(),
            ..Web3GuardPolicy::default()
        };
        let command = "cast send 0xdead --rpc-url https://rpc.test --chain 1 --ledger";
        let error = command_card_bindings_for_command(
            command,
            ShellType::Posix,
            None,
            &guard,
            "policy-identity",
            Some("0123456789abcdef"),
        )
        .unwrap_err();
        assert_eq!(error, Web3CardTemplateError::ExecutableIdentityUnbound);

        let artifact_error = command_card_bindings_for_command(
            "forge script Deploy --broadcast --rpc-url https://rpc.test --chain 1 --ledger",
            ShellType::Posix,
            None,
            &guard,
            "policy-identity",
            Some("0123456789abcdef"),
        )
        .unwrap_err();
        assert_eq!(
            artifact_error,
            Web3CardTemplateError::ArtifactExecutionRecheckUnavailable
        );

        let compiled = CompiledWeb3Guard::new(&guard);
        let bound = compiled.analyze(
            command,
            ShellType::Posix,
            Web3ParseContextV2::without_filesystem(),
        );
        assert!(bound
            .result
            .completeness
            .gaps()
            .any(|gap| { gap == crate::effects::IncompleteReasonV2::DynamicExecutionUnsupported }));
        assert!(approval_observation(&bound, &guard, &compiled).is_none());
        let approved = decide(&bound, &guard, &compiled, true);
        assert!(approved.findings.iter().any(|finding| finding.evidence.iter().any(
            |evidence| matches!(evidence, Evidence::Text { detail } if detail.contains("status=incomplete_analysis"))
        )), "a derived card must not bless an untrusted executable basename as complete");

        assert!(command_card_bindings_for_command(
            "cast call 0xdead --rpc-url https://rpc.test",
            ShellType::Posix,
            None,
            &guard,
            "policy-identity",
            None,
        )
        .unwrap()
        .is_none());
    }
}
