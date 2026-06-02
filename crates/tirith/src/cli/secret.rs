//! M11 ch4 — `tirith secret triage|rotate <provider>|revoke --provider <p>`.
//!
//! A secret-rotation **ASSISTANT**: it shows *where* and *how* to rotate a
//! leaked credential. It does NOT rotate or revoke anything and makes **zero
//! network calls** (no HTTP client here or in [`tirith_core::secret_rotation`]);
//! the revocation/doc URLs are inert strings for you to open.
//!
//! * `triage` — reads recent credential findings from the local audit log and
//!   prints a one-line next-step per finding, attributing a provider where the
//!   leaked shape is recognizable.
//! * `rotate <provider>` — prints the revocation URL, doc URL, and checklist.
//! * `revoke --provider <p>` — the same data, leading with the revocation URL.
//!
//! Honesty contract (loud in `--help` and output): tirith does NOT perform
//! rotation or revocation; you do.

use tirith_core::secret_rotation::{self, Provider, TriageItem, HONESTY_BANNER};

use super::write_json_stdout;

/// How many of the most-recent credential findings `triage` reports by default.
const TRIAGE_RECENT: usize = 25;

/// `tirith secret triage [--json] [--verbose]` — scan recent audit findings for
/// credential leaks and print a one-line rotation next-step for each.
///
/// Exit `0` on a successful read, `1` if the audit log can't be resolved/read,
/// and `2` only in `--json` mode when the JSON write itself fails, so a piped
/// consumer never pairs truncated JSON with success (CodeRabbit R12 #H). The
/// `1` fatal path stays `1` even if its `{"error":…}` write fails.
pub fn triage(json: bool, verbose: bool) -> i32 {
    let Some(log_path) = tirith_core::audit::audit_log_path() else {
        return triage_fatal(json, "cannot determine the audit log path");
    };

    // A missing log is "nothing audited yet" — report as no findings, not error.
    if !log_path.exists() {
        return triage_empty(json, &log_path.display().to_string());
    }

    let records = match tirith_core::audit_aggregator::read_log(&log_path) {
        Ok(result) => result.records,
        Err(e) => {
            return triage_fatal(json, &e);
        }
    };

    let items = secret_rotation::triage_records(&records, TRIAGE_RECENT);

    if json {
        let payload = TriageJson::from_items(&items);
        if !write_json_stdout(
            &payload,
            "tirith secret triage: failed to write JSON output",
        ) {
            return 2;
        }
        return 0;
    }

    println!("{HONESTY_BANNER}");
    println!();
    if items.is_empty() {
        println!("No recent credential findings in the audit log.");
        println!("  (scanned {})", log_path.display());
        println!();
        println!("When the engine records a credential finding, this command will point you");
        println!("at the right provider's revocation page. To rotate a known provider now:");
        println!(
            "  tirith secret rotate <provider>   (one of: {})",
            secret_rotation::provider_names().join(", ")
        );
        return 0;
    }

    println!(
        "{} recent credential finding{} — rotate the affected secrets:",
        items.len(),
        if items.len() == 1 { "" } else { "s" }
    );
    println!();
    for item in &items {
        println!("  - {}", item.next_step());
        if verbose {
            println!("      redacted: {}", item.redacted);
            if let Some(p) = item.provider {
                println!("      docs:     {}", p.doc_url);
                println!("      verified: {}", p.last_verified);
            }
        }
    }
    println!();
    println!("Run `tirith secret rotate <provider>` for the full checklist for any provider.");
    0
}

/// Print the "no findings" surface for both empty and missing logs.
fn triage_empty(json: bool, scanned_path: &str) -> i32 {
    if json {
        let payload = TriageJson {
            assistant_only: true,
            disclaimer: HONESTY_BANNER,
            count: 0,
            findings: Vec::new(),
        };
        if !write_json_stdout(
            &payload,
            "tirith secret triage: failed to write JSON output",
        ) {
            return 2;
        }
        return 0;
    }
    println!("{HONESTY_BANNER}");
    println!();
    println!("No audit log yet — nothing to triage.");
    println!("  (looked for {scanned_path})");
    println!();
    println!("To rotate a known provider now:");
    println!(
        "  tirith secret rotate <provider>   (one of: {})",
        secret_rotation::provider_names().join(", ")
    );
    0
}

/// Emit a fatal `triage` error and return exit 1. In `--json` mode writes a
/// structured `{"error": ...}` on stdout (so a `--json` consumer always parses
/// JSON); exit stays 1 even if that write fails.
fn triage_fatal(json: bool, msg: &str) -> i32 {
    if json {
        let payload = serde_json::json!({ "error": msg });
        let _ = write_json_stdout(
            &payload,
            "tirith secret triage: failed to write JSON output",
        );
    } else {
        eprintln!("tirith secret triage: {msg}");
    }
    1
}

/// `tirith secret rotate <provider> [--json] [--verbose]` — print the provider's
/// rotation guidance (revocation URL, docs, checklist). Exit `0` on a known
/// provider, `2` on an unknown one (with the valid list).
pub fn rotate(provider: &str, json: bool, verbose: bool) -> i32 {
    let Some(p) = secret_rotation::lookup(provider) else {
        return unknown_provider("rotate", provider, json);
    };

    if json {
        let payload = ProviderJson::from(p);
        if !write_json_stdout(
            &payload,
            "tirith secret rotate: failed to write JSON output",
        ) {
            return 2;
        }
        return 0;
    }

    println!("{HONESTY_BANNER}");
    println!();
    println!("Rotate your {} credential", p.provider);
    println!();
    println!("  Revoke / regenerate at:");
    println!("    {}", p.revocation_url);
    println!("  Provider docs:");
    println!("    {}", p.doc_url);
    println!();
    println!("  Manual checklist (you perform these — tirith performs none):");
    for (i, step) in p.manual_checklist.iter().enumerate() {
        println!("    {}. {step}", i + 1);
    }
    if verbose {
        println!();
        println!("  guidance last verified: {}", p.last_verified);
        println!(
            "  triage shapes:          {}",
            p.key_prefix_shapes.join(", ")
        );
    }
    println!();
    println!("Reminder: {HONESTY_BANNER}");
    0
}

/// `tirith secret revoke --provider <p> [--json] [--verbose]` — the same
/// provider data as `rotate`, leading with the revocation URL prominently.
pub fn revoke(provider: &str, json: bool, verbose: bool) -> i32 {
    let Some(p) = secret_rotation::lookup(provider) else {
        return unknown_provider("revoke", provider, json);
    };

    if json {
        let payload = ProviderJson::from(p);
        if !write_json_stdout(
            &payload,
            "tirith secret revoke: failed to write JSON output",
        ) {
            return 2;
        }
        return 0;
    }

    println!("{HONESTY_BANNER}");
    println!();
    println!("REVOKE your {} credential here:", p.provider);
    println!();
    println!("    >>> {} <<<", p.revocation_url);
    println!();
    println!("Then complete the rotation checklist:");
    for (i, step) in p.manual_checklist.iter().enumerate() {
        println!("    {}. {step}", i + 1);
    }
    println!();
    println!("  Provider docs: {}", p.doc_url);
    if verbose {
        println!("  guidance last verified: {}", p.last_verified);
    }
    println!();
    println!("Reminder: {HONESTY_BANNER}");
    0
}

/// Shared "unknown provider" error: list the valid providers and exit 2. In
/// `--json` mode emits `{"error": ..., "valid_providers": [...]}` on stdout so a
/// JSON consumer always parses JSON. Exit stays 2 even on a JSON-write failure.
fn unknown_provider(action: &str, provider: &str, json: bool) -> i32 {
    let valid = secret_rotation::provider_names();
    if json {
        let payload = serde_json::json!({
            "error": format!("unknown provider '{provider}'"),
            "action": action,
            "valid_providers": valid,
        });
        // Best-effort write; exit 2 is already non-zero. Route through
        // write_json_stdout for a consistent newline + stderr diagnostic.
        let _ = write_json_stdout(
            &payload,
            &format!("tirith secret {action}: failed to write JSON output"),
        );
    } else {
        eprintln!(
            "tirith secret {action}: unknown provider '{provider}' — valid providers: {}",
            valid.join(", ")
        );
    }
    2
}

// ---- JSON shapes ----------------------------------------------------------

/// JSON envelope for `rotate` / `revoke`. Carries the `assistant_only` flag and
/// disclaimer so machine consumers also see the honesty contract.
#[derive(serde::Serialize)]
struct ProviderJson {
    assistant_only: bool,
    disclaimer: &'static str,
    provider: &'static str,
    revocation_url: &'static str,
    doc_url: &'static str,
    manual_checklist: &'static [&'static str],
    key_prefix_shapes: &'static [&'static str],
    last_verified: &'static str,
}

impl From<&'static Provider> for ProviderJson {
    fn from(p: &'static Provider) -> Self {
        ProviderJson {
            assistant_only: true,
            disclaimer: HONESTY_BANNER,
            provider: p.provider,
            revocation_url: p.revocation_url,
            doc_url: p.doc_url,
            manual_checklist: p.manual_checklist,
            key_prefix_shapes: p.key_prefix_shapes,
            last_verified: p.last_verified,
        }
    }
}

/// JSON envelope for `triage`.
#[derive(serde::Serialize)]
struct TriageJson {
    assistant_only: bool,
    disclaimer: &'static str,
    count: usize,
    findings: Vec<TriageFindingJson>,
}

impl TriageJson {
    fn from_items(items: &[TriageItem]) -> Self {
        TriageJson {
            assistant_only: true,
            disclaimer: HONESTY_BANNER,
            count: items.len(),
            findings: items.iter().map(TriageFindingJson::from).collect(),
        }
    }
}

/// One triage finding rendered for JSON. `provider`/`revocation_url` are `None`
/// when the leaked shape could not be attributed.
#[derive(serde::Serialize)]
struct TriageFindingJson {
    rule_id: String,
    timestamp: String,
    redacted: String,
    provider: Option<&'static str>,
    revocation_url: Option<&'static str>,
    next_step: String,
}

impl From<&TriageItem> for TriageFindingJson {
    fn from(item: &TriageItem) -> Self {
        TriageFindingJson {
            rule_id: item.rule_id.clone(),
            timestamp: item.timestamp.clone(),
            redacted: item.redacted.clone(),
            provider: item.provider.map(|p| p.provider),
            revocation_url: item.provider.map(|p| p.revocation_url),
            next_step: item.next_step(),
        }
    }
}
