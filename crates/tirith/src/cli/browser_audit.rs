//! C16 `tirith browser audit`: a read-only integrity audit of the extensions
//! installed in a Chromium-family browser profile.
//!
//! Thin renderer over [`tirith_core::browser_extensions`]. Everything about what
//! is read, what is never read, and how coverage is decided lives in that
//! module's documentation; this file parses flags, prints, and picks an exit
//! code.

use std::path::{Path, PathBuf};

use tirith_core::browser_extensions::{
    self as audit, AuditBudget, AuditCoverage, AuditRequest, BrowserAuditReport, BrowserBaseline,
    BrowserFamily, BrowserRecord, BrowserStatus, ExtensionDrift, ExtensionRecord, ProfileRecord,
};

use super::{sanitize_for_human_output, write_json_stdout};

/// Maximum bytes of a `--baseline` document that will be read. A baseline is a
/// bounded record of an extension inventory; a larger file is a mistake or an
/// attack, not a baseline.
pub const MAX_BASELINE_BYTES: u64 = 16 * 1024 * 1024;

/// Which browsers `--browser` selected.
///
/// Deliberately its own type rather than a new variant on
/// [`super::browser::Browser`]: that enum carries a per-browser
/// `NativeMessagingHosts` path contract through several exhaustive matches, and
/// `all` is not a browser. The concrete values still go through its parser, so
/// there is one spelling table for `chrome|chromium|brave|edge` in the CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserSelection {
    All,
    One(BrowserFamily),
}

impl BrowserSelection {
    /// The families to walk, in report order.
    pub fn families(&self) -> Vec<BrowserFamily> {
        match self {
            Self::All => BrowserFamily::ALL.to_vec(),
            Self::One(family) => vec![*family],
        }
    }
}

/// Map the CLI's browser enum onto the core family enum. The CLI type is the
/// parser; the core type is what the audit understands.
fn family_of(browser: super::browser::Browser) -> BrowserFamily {
    match browser {
        super::browser::Browser::Chrome => BrowserFamily::Chrome,
        super::browser::Browser::Chromium => BrowserFamily::Chromium,
        super::browser::Browser::Brave => BrowserFamily::Brave,
        super::browser::Browser::Edge => BrowserFamily::Edge,
    }
}

/// Parse `--browser`. `all` is handled here; everything else is delegated to the
/// existing browser parser so the two commands accept the same spellings.
///
/// An unsupported browser stays EXPLICIT: `firefox` is a usage error naming the
/// scope limit, never an empty clean inventory.
pub fn parse_selection(value: &str) -> Result<BrowserSelection, String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized == "all" {
        return Ok(BrowserSelection::All);
    }
    if matches!(normalized.as_str(), "firefox" | "gecko" | "librewolf") {
        return Err(format!(
            "'{normalized}' is not a Chromium-family browser; the extension audit covers chrome, \
             chromium, brave, and edge only (Firefox and XPI are out of scope)"
        ));
    }
    match normalized.parse::<super::browser::Browser>() {
        Ok(browser) => Ok(BrowserSelection::One(family_of(browser))),
        Err(_) => Err(format!(
            "unknown browser '{normalized}' (expected chrome, chromium, brave, edge, or all)"
        )),
    }
}

/// Decide the exit code from `(in_sync, json_write_ok)`.
///
/// Same contract as `tirith mcp verify`: a JSON-write failure must not collapse
/// "drift, exit 1" into "usage error, exit 2". So no-drift plus a good write is
/// 0; no-drift plus a broken write is 2 (the only signal is broken); drift is 1
/// regardless, because drift dominates.
///
/// Partial coverage with NO baseline is 0 and says `partial` in the output. It
/// is not a failure that the browser was running; it is a statement about what
/// the result can prove. Partial coverage WITH a baseline is different: an
/// extension whose tree could not be fully hashed produces an
/// `integrity_not_comparable` drift entry, so a verify run that could not verify
/// exits 1 rather than reporting a clean comparison it did not make.
pub fn audit_exit_code(in_sync: bool, json_write_ok: bool) -> i32 {
    match (in_sync, json_write_ok) {
        (true, true) => 0,
        (true, false) => 2,
        (false, _) => 1,
    }
}

/// Everything `tirith browser audit` was asked to do.
#[derive(Debug, Clone, Default)]
pub struct AuditArgs {
    pub browser: String,
    pub profile: Option<PathBuf>,
    pub baseline: Option<PathBuf>,
    pub write_baseline: Option<PathBuf>,
    pub json: bool,
}

/// `tirith browser audit` entry point.
pub fn run(args: AuditArgs) -> i32 {
    let selection = match parse_selection(&args.browser) {
        Ok(selection) => selection,
        Err(message) => return usage_error(args.json, &message),
    };

    if args.profile.is_some() && selection == BrowserSelection::All {
        return usage_error(
            args.json,
            "--profile names one profile directory, so it cannot be combined with \
             --browser all; pass the browser that profile belongs to",
        );
    }

    if let Some(profile) = args.profile.as_deref() {
        if let Err(message) = validate_profile_path(profile) {
            return usage_error(args.json, &message);
        }
    }

    let report = audit::audit(&AuditRequest {
        families: selection.families(),
        explicit_profile: args.profile.clone(),
        budget: AuditBudget::default(),
    });

    let baseline = match args.baseline.as_deref() {
        Some(path) => match load_baseline(path) {
            Ok(loaded) => Some(loaded),
            Err(message) => return usage_error(args.json, &message),
        },
        None => None,
    };
    let drifts = baseline
        .as_ref()
        .map(|(baseline, _)| audit::compute_drift(&report, baseline))
        .unwrap_or_default();

    let written = match args.write_baseline.as_deref() {
        Some(path) => {
            let document = BrowserBaseline::from_report(&report);
            if let Err(error) =
                tirith_core::util::write_file_atomic_0600(path, document.to_json().as_bytes())
            {
                eprintln!(
                    "tirith browser audit: cannot write the baseline to {}: {error}",
                    path.display()
                );
                return 2;
            }
            Some((path.to_path_buf(), document))
        }
        None => None,
    };

    let in_sync = drifts.is_empty() && !verify_was_incomplete(&report, baseline.is_some());
    if args.json {
        let envelope = json_envelope(&report, baseline.as_ref(), &drifts, written.as_ref());
        let write_ok = write_json_stdout(&envelope, "tirith browser audit: failed to write JSON");
        return audit_exit_code(in_sync, write_ok);
    }
    print_human(&report, baseline.as_ref(), &drifts, written.as_ref());
    audit_exit_code(in_sync, true)
}

/// `true` when a `--baseline` run could not cover everything it was asked to
/// compare.
///
/// The per-extension `integrity_not_comparable` drift entry covers the gaps the
/// COMPARISON can see, but a gap can also sit above any extension: a refused
/// `Extensions` directory, a profile that could not be listed, a truncated id
/// enumeration. Those leave `drift` empty, and without this the command reports
/// `no drift` and exits 0 over a profile it never finished reading. The exit
/// code contract is that a verify run which could not verify exits 1 rather than
/// reporting a clean comparison it did not make, so it is enforced here
/// structurally instead of relying on each gap to find its own way into drift.
fn verify_was_incomplete(report: &BrowserAuditReport, has_baseline: bool) -> bool {
    has_baseline && report.coverage == AuditCoverage::Partial
}

fn usage_error(json: bool, message: &str) -> i32 {
    if json {
        let envelope = serde_json::json!({
            "command": "browser audit",
            "status": "error",
            "error": message,
        });
        let _ = write_json_stdout(&envelope, "tirith browser audit: failed to write JSON");
    } else {
        eprintln!("tirith browser audit: {message}");
    }
    2
}

/// Reject a `--profile` that is absent, is not a directory, or whose final
/// component is a symlink. The core walk refuses symlinks at every step; this
/// refuses the operator's own entry point with a message they can act on.
fn validate_profile_path(profile: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(profile) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "--profile {} is a symlink; pass the real profile directory",
            profile.display()
        )),
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(format!(
            "--profile {} is not a directory",
            profile.display()
        )),
        Err(error) => Err(format!(
            "--profile {} cannot be read: {error}",
            profile.display()
        )),
    }
}

fn load_baseline(path: &Path) -> Result<(BrowserBaseline, BaselineTrust), String> {
    let bytes = tirith_core::util::read_text_no_follow_capped(path, MAX_BASELINE_BYTES).map_err(
        |error| match error {
            tirith_core::util::OpenRegularError::NotFound => {
                format!("--baseline {} does not exist", path.display())
            }
            tirith_core::util::OpenRegularError::TooLarge => format!(
                "--baseline {} is larger than {MAX_BASELINE_BYTES} bytes",
                path.display()
            ),
            tirith_core::util::OpenRegularError::NotRegularFile => format!(
                "--baseline {} is not a regular file (a symlink or a directory)",
                path.display()
            ),
            tirith_core::util::OpenRegularError::Io(error) => {
                format!("--baseline {} cannot be read: {error}", path.display())
            }
        },
    )?;
    let text = String::from_utf8(bytes)
        .map_err(|_| format!("--baseline {} is not UTF-8", path.display()))?;
    let baseline = BrowserBaseline::parse(&text)
        .map_err(|error| format!("--baseline {}: {error}", path.display()))?;
    let signature = check_baseline_signature(&baseline, path)?;
    Ok((baseline, signature))
}

/// Whether a loaded baseline's signature was CHECKED, and against what.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineTrust {
    /// A signature was present and verified against this installation's audit
    /// verifying key.
    Verified,
    /// No signature, and this installation has no audit signing key configured,
    /// so there is nothing a signature could have been checked against. The
    /// baseline is trusted on its content hash alone, which any local writer can
    /// recompute.
    Unsigned,
    /// A legacy document was recognized only far enough to demand an upgrade.
    /// It was not trusted or used as a comparison anchor.
    SchemaUpgradeRequired,
}

impl BaselineTrust {
    fn token(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Unsigned => "unsigned",
            Self::SchemaUpgradeRequired => "schema_upgrade_required",
        }
    }
}

/// Decide whether a baseline may be used as a comparison anchor.
///
/// `validate()` only checks the document against ITSELF: `receipt_id` is a
/// sha256 the document computes over its own content and `inventory_hash` is a
/// sha256 over its own entries, so a local attacker who tampers with an
/// extension tree has, by definition, the write access needed to recompute both
/// and hand back a self-consistent forgery. The signature is the only field they
/// cannot reproduce without the private key, so on a signing installation it is
/// REQUIRED and it is CHECKED.
///
/// Two downgrades are refused, not warned about:
///
/// - a signature that does not verify (a stale one retained from an earlier,
///   genuine baseline verifies against nothing);
/// - no signature at all on an installation that has an audit key, because
///   deleting the field would otherwise be the cheapest forgery available.
fn check_baseline_signature(
    baseline: &BrowserBaseline,
    path: &Path,
) -> Result<BaselineTrust, String> {
    if baseline.requires_schema_upgrade() {
        return Ok(BaselineTrust::SchemaUpgradeRequired);
    }
    let expected = tirith_core::audit::audit_signing_expected();
    match (baseline.signature.is_some(), expected) {
        (true, _) => {
            let Some(key) = tirith_core::audit::audit_verifying_key_bytes() else {
                return Err(format!(
                    "--baseline {} is signed but no usable audit verifying key is installed, so \
                     the signature cannot be checked; install the matching audit-signing.pub in \
                     the tirith config directory (owner-only writable) or re-take the baseline",
                    path.display()
                ));
            };
            if !baseline.signature_verifies(&key) {
                return Err(format!(
                    "--baseline {} carries a signature that does not verify against the installed \
                     audit key; treat this baseline as forged and re-take it",
                    path.display()
                ));
            }
            Ok(BaselineTrust::Verified)
        }
        (false, true) => Err(format!(
            "--baseline {} is unsigned but this installation signs its audit artifacts; an \
             unsigned baseline here is a stripped signature, so it is refused rather than \
             compared against",
            path.display()
        )),
        (false, false) => Ok(BaselineTrust::Unsigned),
    }
}

fn json_envelope(
    report: &BrowserAuditReport,
    baseline: Option<&(BrowserBaseline, BaselineTrust)>,
    drifts: &[ExtensionDrift],
    written: Option<&(PathBuf, BrowserBaseline)>,
) -> serde_json::Value {
    serde_json::json!({
        "command": "browser audit",
        "schema": audit::BROWSER_AUDIT_SCHEMA,
        "status": status_token(report, drifts),
        "report": report,
        "extension_count": report.extension_count(),
        "baseline": baseline.map(|(baseline, trust)| serde_json::json!({
            "schema": baseline.schema,
            "receipt_id": (*trust != BaselineTrust::SchemaUpgradeRequired)
                .then_some(&baseline.receipt_id),
            "inventory_hash": (*trust != BaselineTrust::SchemaUpgradeRequired)
                .then_some(&baseline.inventory_hash),
            "format_version": baseline.format_version,
            "coverage": (*trust != BaselineTrust::SchemaUpgradeRequired)
                .then_some(baseline.coverage.token()),
            "created_at": (*trust != BaselineTrust::SchemaUpgradeRequired)
                .then_some(&baseline.created_at),
            // A CHECKED statement. `signature.is_some()` said "signed" for a
            // stale signature that verified against nothing.
            "signed": *trust == BaselineTrust::Verified,
            "trust": trust.token(),
        })),
        "drift": drifts,
        "drift_count": drifts.len(),
        // Null with no baseline: nothing was verified, so neither `true` nor
        // `false` is an honest answer.
        "verify_complete": baseline.map(|(_, trust)| {
            *trust != BaselineTrust::SchemaUpgradeRequired
                && !verify_was_incomplete(report, true)
        }),
        "baseline_written": written.map(|(path, document)| serde_json::json!({
            "path": path.display().to_string(),
            "schema": document.schema,
            "format_version": document.format_version,
            "receipt_id": document.receipt_id,
            "inventory_hash": document.inventory_hash,
            "signed": document.signature.is_some(),
            "coverage": document.coverage.token(),
        })),
    })
}

/// The one-word verdict. `partial` covers both "no baseline, and the walk did
/// not reach everything" and "a baseline was supplied and the verify could not
/// finish"; the two differ in exit code, never in honesty.
fn status_token(report: &BrowserAuditReport, drifts: &[ExtensionDrift]) -> &'static str {
    if !drifts.is_empty() {
        "drift"
    } else if report.coverage == AuditCoverage::Partial {
        "partial"
    } else {
        "clean"
    }
}

fn print_human(
    report: &BrowserAuditReport,
    baseline: Option<&(BrowserBaseline, BaselineTrust)>,
    drifts: &[ExtensionDrift],
    written: Option<&(PathBuf, BrowserBaseline)>,
) {
    println!("tirith browser audit (read-only)");
    println!(
        "  platform: {}",
        report
            .platform
            .map(|platform| platform.token())
            .unwrap_or("unsupported")
    );
    println!(
        "  coverage: {}   extensions: {}",
        report.coverage.token(),
        report.extension_count()
    );
    if report.budget_exhausted {
        println!("  note:     a run-wide budget stopped the walk; this result is not complete");
    }

    for browser in &report.browsers {
        print_browser(browser);
    }

    match baseline {
        Some((baseline, trust)) => {
            println!();
            if *trust == BaselineTrust::SchemaUpgradeRequired {
                println!(
                    "baseline schema v{} / format v{} requires replacement (not trusted)",
                    baseline.schema, baseline.format_version
                );
            } else {
                println!(
                    "baseline {} (schema v{}, format v{}, coverage {}, signature {})",
                    &baseline.receipt_id[..baseline.receipt_id.len().min(16)],
                    baseline.schema,
                    baseline.format_version,
                    baseline.coverage.token(),
                    trust.token()
                );
            }
            if *trust != BaselineTrust::SchemaUpgradeRequired
                && baseline.coverage == AuditCoverage::Partial
            {
                println!(
                    "  the baseline itself was taken from a partial run, so absence of drift \
                     here does not prove absence of change"
                );
            }
            if report.coverage == AuditCoverage::Partial {
                println!(
                    "  this run did not cover everything it compared, so it did not verify; see \
                     the refused paths and gaps above"
                );
            }
            if drifts.is_empty() {
                println!("  no drift");
            } else {
                println!("  {} drift finding(s):", drifts.len());
                for drift in drifts {
                    println!("    {}", describe_drift(drift));
                }
            }
        }
        None => {
            println!();
            println!("no baseline supplied; nothing to compare against");
        }
    }

    if let Some((path, document)) = written {
        println!();
        println!(
            "baseline written to {} ({}, inventory {})",
            path.display(),
            if document.signature.is_some() {
                "signed"
            } else {
                "unsigned"
            },
            &document.inventory_hash[..document.inventory_hash.len().min(16)]
        );
    }
}

fn print_browser(browser: &BrowserRecord) {
    println!();
    match browser.status {
        BrowserStatus::Audited => {
            println!(
                "{} ({} profile(s), coverage {})",
                browser.browser.token(),
                browser.profiles.len(),
                browser.coverage.token()
            );
            for profile in &browser.profiles {
                print_profile(profile);
            }
        }
        status => println!("{}: {}", browser.browser.token(), status.token()),
    }
    for root in &browser.roots {
        println!(
            "  root {}/{}/{}: {}",
            root.identity.family.token(),
            root.identity.channel.token(),
            root.identity.edition.token(),
            root.status.token()
        );
    }
    for gap in &browser.root_gaps {
        println!(
            "  root gap {}/{}/{}: {}",
            gap.root.family.token(),
            gap.root.channel.token(),
            gap.root.edition.token(),
            gap.kind.as_str()
        );
    }
}

fn print_profile(profile: &ProfileRecord) {
    println!(
        "  profile {}/{}/{}:{} ({}, install class from {})",
        profile.identity.root.family.token(),
        profile.identity.root.channel.token(),
        profile.identity.root.edition.token(),
        sanitize_for_human_output(&profile.profile_directory, false),
        profile.profile_kind.token(),
        profile.install_class_source.token()
    );
    if profile.extensions.is_empty() {
        println!("    no extensions");
    }
    for extension in &profile.extensions {
        print_extension(extension);
    }
    for rejected in &profile.rejected {
        println!(
            "    refused {}: {}",
            sanitize_for_human_output(&rejected.path, false),
            rejection_token(&rejected.reason)
        );
    }
    for gap in &profile.gaps {
        println!(
            "    gap {}: {}",
            sanitize_for_human_output(&gap.scope, false),
            gap.kind.as_str()
        );
    }
}

fn print_extension(extension: &ExtensionRecord) {
    println!(
        "    {} {} v{}{}",
        extension.id,
        sanitize_for_human_output(&extension.name, false),
        sanitize_for_human_output(&extension.version, false),
        if extension.wallet_fixture_match {
            "  [wallet-shaped id]"
        } else {
            ""
        }
    );
    println!(
        "      mv{}  install {}  provenance {}  coverage {}",
        extension.manifest_version,
        extension.install_class.token(),
        extension.provenance.token(),
        extension.coverage.token()
    );
    println!(
        "      tree sha256:{} ({} files, {} bytes, {})",
        &extension.tree.digest[..extension.tree.digest.len().min(16)],
        extension.tree.file_count,
        extension.tree.total_bytes,
        if extension.tree.complete {
            "complete"
        } else {
            "PARTIAL"
        }
    );
    if !extension.permissions.is_empty() {
        println!(
            "      permissions: {}",
            join_display(&extension.permissions)
        );
    }
    if !extension.host_permissions.is_empty() {
        println!("      hosts: {}", join_display(&extension.host_permissions));
    }
    println!(
        "      risk {}{}",
        extension.risk.level.token(),
        if extension.risk.reasons.is_empty() {
            String::new()
        } else {
            format!(
                " ({})",
                extension
                    .risk
                    .reasons
                    .iter()
                    .map(|reason| reason.token())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    );
    for rejected in &extension.rejected {
        println!(
            "      refused {}: {}",
            sanitize_for_human_output(&rejected.path, false),
            rejection_token(&rejected.reason)
        );
    }
    for gap in &extension.gaps {
        println!(
            "      gap {}: {}",
            sanitize_for_human_output(&gap.scope, false),
            gap.kind.as_str()
        );
    }
}

fn join_display(values: &[String]) -> String {
    values
        .iter()
        .map(|value| sanitize_for_human_output(value, false))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A stable token for a rejection reason, derived from its own serde spelling so
/// the human line and the JSON envelope never disagree.
fn rejection_token(reason: &tirith_core::browser_extensions::RejectionReason) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|value| {
            value
                .get("kind")
                .and_then(|kind| kind.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn describe_drift(drift: &ExtensionDrift) -> String {
    let subject = drift
        .subject()
        .map(|subject| {
            format!(
                "{}/{}/{}/{}/{}",
                subject.identity.profile.root.family.token(),
                subject.identity.profile.root.channel.token(),
                subject.identity.profile.root.edition.token(),
                sanitize_for_human_output(&subject.profile_directory, false),
                subject.extension_id
            )
        })
        .unwrap_or_else(|| "<document>".to_string());
    let detail = match drift {
        ExtensionDrift::SchemaUpgradeRequired {
            from_schema,
            to_schema,
            from_version,
            to_version,
        } => format!(
            "baseline schema v{from_schema} -> v{to_schema}, hashing format v{from_version} -> \
             v{to_version}; re-take it"
        ),
        ExtensionDrift::New { version, .. } => {
            format!("v{}", sanitize_for_human_output(version, false))
        }
        ExtensionDrift::Removed { version, .. } => {
            format!("was v{}", sanitize_for_human_output(version, false))
        }
        ExtensionDrift::VersionChanged { from, to, .. } => format!(
            "{} -> {}",
            sanitize_for_human_output(from, false),
            sanitize_for_human_output(to, false)
        ),
        ExtensionDrift::VersionDirectoryReused {
            version_directory,
            from,
            to,
            from_digest,
            to_digest,
            ..
        } => format!(
            "{} -> {} rewritten in place inside {} (bytes {} -> {}); a real update writes a new \
             version directory",
            sanitize_for_human_output(from, false),
            sanitize_for_human_output(to, false),
            sanitize_for_human_output(version_directory, false),
            &from_digest[..from_digest.len().min(16)],
            &to_digest[..to_digest.len().min(16)]
        ),
        ExtensionDrift::VersionDirectorySetChange { added, removed, .. } => {
            let mut parts = Vec::new();
            if !added.is_empty() {
                parts.push(format!("added {}", join_display(added)));
            }
            if !removed.is_empty() {
                parts.push(format!("removed {}", join_display(removed)));
            }
            format!("version directories {}", parts.join(", "))
        }
        ExtensionDrift::ManifestVersionChanged { from, to, .. } => {
            format!("mv{from} -> mv{to}")
        }
        ExtensionDrift::SameVersionByteChange {
            version,
            from_digest,
            to_digest,
            ..
        } => format!(
            "v{} bytes changed {} -> {}",
            sanitize_for_human_output(version, false),
            &from_digest[..from_digest.len().min(16)],
            &to_digest[..to_digest.len().min(16)]
        ),
        ExtensionDrift::PermissionExpansion { added, .. } => {
            format!("added {}", join_display(added))
        }
        ExtensionDrift::IntegrityNotComparable {
            version,
            baseline_complete,
            current_complete,
            ..
        } => format!(
            "v{} could not be compared (baseline digest {}, current digest {})",
            sanitize_for_human_output(version, false),
            if *baseline_complete {
                "complete"
            } else {
                "partial"
            },
            if *current_complete {
                "complete"
            } else {
                "partial"
            }
        ),
        ExtensionDrift::PermissionReduction { removed, .. } => {
            format!("removed {}", join_display(removed))
        }
        ExtensionDrift::HostExpansion { added, .. } => format!("added {}", join_display(added)),
        ExtensionDrift::HostReduction { removed, .. } => {
            format!("removed {}", join_display(removed))
        }
        ExtensionDrift::OptionalPermissionExpansion { added, .. }
        | ExtensionDrift::OptionalHostExpansion { added, .. } => {
            format!("added (runtime-grantable) {}", join_display(added))
        }
        ExtensionDrift::OptionalPermissionReduction { removed, .. }
        | ExtensionDrift::OptionalHostReduction { removed, .. } => {
            format!("removed (runtime-grantable) {}", join_display(removed))
        }
        ExtensionDrift::SurfaceHashChanged { from, to, .. } => format!(
            "declared surface digest {} -> {} with no field difference reported; the audit's own \
             surface comparison is incomplete",
            &from[..from.len().min(16)],
            &to[..to.len().min(16)]
        ),
        ExtensionDrift::ExecutionSurfaceChange { changes, .. } => changes
            .iter()
            .map(|change| change.token())
            .collect::<Vec<_>>()
            .join(", "),
        ExtensionDrift::ProvenanceChange { from, to, .. } => {
            format!("{} -> {}", from.token(), to.token())
        }
        ExtensionDrift::InstallClassChange { from, to, .. } => {
            format!("{} -> {}", from.token(), to.token())
        }
    };
    format!("{} {}: {}", drift.token(), subject, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_is_parsed_at_the_cli_and_never_as_a_browser_variant() {
        assert_eq!(parse_selection("all").unwrap(), BrowserSelection::All);
        assert_eq!(
            parse_selection("ALL ").unwrap().families(),
            BrowserFamily::ALL.to_vec()
        );
        assert_eq!(
            parse_selection("brave").unwrap(),
            BrowserSelection::One(BrowserFamily::Brave)
        );
        assert_eq!(
            parse_selection("msedge").unwrap(),
            BrowserSelection::One(BrowserFamily::Edge)
        );
        assert_eq!(
            parse_selection("chrome").unwrap().families(),
            vec![BrowserFamily::Chrome]
        );
    }

    #[test]
    fn an_out_of_scope_browser_is_named_rather_than_silently_empty() {
        let error = parse_selection("firefox").expect_err("firefox is out of scope");
        assert!(error.contains("Chromium-family"), "{error}");
        assert!(error.contains("out of scope"), "{error}");
        let unknown = parse_selection("safari").expect_err("safari is unknown");
        assert!(
            unknown.contains("chrome, chromium, brave, edge, or all"),
            "{unknown}"
        );
    }

    #[test]
    fn the_exit_code_contract_matches_mcp_verify() {
        assert_eq!(audit_exit_code(true, true), 0);
        assert_eq!(audit_exit_code(true, false), 2);
        assert_eq!(audit_exit_code(false, true), 1);
        assert_eq!(audit_exit_code(false, false), 1);
    }

    #[test]
    fn a_missing_profile_directory_is_a_usage_error() {
        let root = tempfile::tempdir().expect("tempdir");
        let error = validate_profile_path(&root.path().join("absent"))
            .expect_err("an absent profile is refused");
        assert!(error.contains("cannot be read"), "{error}");

        let file = root.path().join("file");
        std::fs::write(&file, b"x").expect("write");
        let error = validate_profile_path(&file).expect_err("a file is refused");
        assert!(error.contains("not a directory"), "{error}");

        std::fs::create_dir(root.path().join("Default")).expect("create");
        validate_profile_path(&root.path().join("Default")).expect("a directory is accepted");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_profile_argument_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let real = root.path().join("real");
        std::fs::create_dir(&real).expect("create");
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let error = validate_profile_path(&link).expect_err("a symlink is refused");
        assert!(error.contains("symlink"), "{error}");
    }
}
