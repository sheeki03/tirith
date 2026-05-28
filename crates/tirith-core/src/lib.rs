pub mod agent_origin;
pub mod aliases;
pub mod approval;
pub mod audit;
pub mod audit_aggregator;
pub mod audit_tune;
pub mod audit_upload;
pub mod checkpoint;
pub mod clipboard;
pub mod confusables;
pub mod context_detect;
pub mod data;
pub mod dep_confusion;
pub mod devcontainer_writer;
pub mod ecosystem_scan;
pub mod engine;
pub mod escalation;
pub mod extract;
pub mod homoglyph;
pub mod hygiene;
pub mod iac_plan;
pub mod install_script_analysis;
pub mod install_txn;
pub mod license;
pub mod mcp;
pub mod mcp_lock;
pub mod network;
pub mod normalize;
pub mod osv_correlation;
pub mod output;
pub mod package_risk;
pub mod parse;
pub mod persistence;
pub mod policy;
pub mod policy_client;
pub mod policy_migrations;
pub mod policy_validate;
pub mod receipt;
pub mod redact;
pub mod registry_api;
pub mod registry_history;
pub mod repo_mismatch;
pub mod rule_explanations;
pub mod rule_metadata;
pub mod rules;
pub mod safe_command;
pub mod sarif;
pub mod scan;
pub mod scoring;
pub mod selfupdate;
pub mod session;
pub mod session_warnings;
pub mod style;
pub mod sudo_session;
pub mod text_confusables;
pub mod threatdb;
pub mod threatdb_api;
pub mod threatdb_feeds;
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
