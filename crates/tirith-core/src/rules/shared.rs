//! Shared constants and helpers used by multiple rule modules.

/// Environment variable names that carry sensitive credentials.
/// Used by both `command.rs` (SensitiveEnvExport detection) and
/// `credential.rs` (dedup suppression).
pub const SENSITIVE_KEY_VARS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
];
