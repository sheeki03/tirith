pub mod approval;
pub mod audit;
pub mod audit_aggregator;
pub mod audit_upload;
pub mod checkpoint;
pub mod confusables;
pub mod data;
pub mod engine;
pub mod extract;
pub mod homoglyph;
pub mod license;
pub mod mcp;
pub mod network;
pub mod normalize;
pub mod output;
pub mod parse;
pub mod policy;
pub mod policy_client;
pub mod policy_validate;
pub mod receipt;
pub mod redact;
pub mod rule_explanations;
pub mod rule_metadata;
pub mod rules;
pub mod sarif;
pub mod scan;
pub mod session;
pub mod text_confusables;
pub mod tokenize;
pub mod url_validate;
pub mod util;
pub mod verdict;
pub mod webhook;

#[cfg(unix)]
pub mod runner;
pub mod script_analysis;

/// Crate-wide mutex for tests that mutate process-global environment variables.
/// `std::env::set_var` is not thread-safe — all env-mutating tests across every
/// module in this crate MUST hold this lock.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
