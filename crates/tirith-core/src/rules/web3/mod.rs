//! Bounded Web3 command semantics.
//!
//! This module exports facts only. Rule emission and policy enforcement are
//! intentionally deferred to later stack commits.

mod config;
mod coverage;
mod model;
mod parse;

pub(crate) use coverage::analyze_task_coverage;
#[cfg(test)]
pub(crate) use model::MAX_RETAINED_RPC_PATH_MATCH_OUTCOMES;
pub(crate) use parse::parse_web3_commands_with_occurrences_v2;

pub use config::{Web3ParseContext, Web3ParseContextV2, MAX_CONTEXT_SELECTORS, MAX_SELECTOR_BYTES};
pub use model::{
    ArtifactKind, ArtifactReference, DestinationKind, DestinationReference, NetworkEvidence,
    RoleTaggedSigner, RpcPathClass, RpcPathMatchOutcome, RpcPathMatchOutcomes, RpcPathMatcherId,
    RpcReference, RpcReferenceV2, SelectorReference, SelectorSource, SignerKind, SignerKindV2,
    SignerReference, SignerReferenceV2, SignerRole, TrustedRpcPathPrefix, Web3CommandFacts,
    Web3CommandFactsV2, Web3JsonDecodeError, Web3Operation, Web3OperationV2, Web3ParseResult,
    Web3ParseResultV2, Web3SafetyFlag, Web3ToolFamily, Web3WriteMode,
    MAX_TRUSTED_RPC_MATCHER_BYTES, MAX_TRUSTED_RPC_PATH_MATCHERS, MAX_WEB3_PARSE_RESULT_JSON_BYTES,
    WEB3_PARSE_RESULT_SCHEMA_V1, WEB3_PARSE_RESULT_SCHEMA_V2,
};
pub use parse::{
    parse_web3_commands, parse_web3_commands_v2, MAX_ARGUMENT_BYTES, MAX_ARGV_ITEMS,
    MAX_INPUT_BYTES, MAX_SHELL_SEGMENTS, MAX_WRAPPER_DEPTH,
};
