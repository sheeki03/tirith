//! `tirith attest build | verify-build | deployment | verify-deployment` (C18).
//!
//! A thin renderer over [`tirith_core::build_receipt`] and
//! [`tirith_core::deployment_receipt`]. Every byte of filesystem walking,
//! digesting, and HTTP fetching lives in core, for two reasons: the SSRF-guarded
//! client builders are crate-private there, and the scripted HTTP fixture the
//! deployment tests need is `#[cfg(test)]` and crate-private too. This file
//! resolves and validates paths, calls one core entry point, writes the receipt,
//! and prints.
//!
//! # This namespace is not `tirith pkg attest`
//!
//! `tirith pkg attest <wheel>` binds PyPI publish attestations and is untouched
//! by this slice. The two share a verb and nothing else.
//!
//! # Exit codes
//!
//! `0` clean, `1` mismatch, `2` usage or input error, `3` partial. The `3` is
//! deliberately NOT the meaning `tirith check` gives it (a warn
//! acknowledgement); per-command codes in this repository are distinct, and each
//! subcommand's `after_help` says so.
//!
//! # What these commands never claim
//!
//! Tirith does not run the build. A build receipt records the bytes of two trees
//! at one moment; it is not a reproducibility claim. A deployment receipt
//! records what a set of routes returned at one moment; it is not continuous
//! monitoring and says nothing about routes it did not fetch. `verify-deployment`
//! re-checks the DOCUMENT and deliberately does not re-fetch, because a second
//! measurement presented as verification of the first would be exactly the
//! continuous-monitoring claim this slice refuses to make.

use std::path::{Path, PathBuf};

use tirith_core::build_receipt::{
    self, BuildReceipt, BuildReceiptError, BuildRequest, SignatureAnchor, SignatureTrust,
    TreeLimits,
};
use tirith_core::deployment_receipt::{
    self, DeploymentReceipt, DeploymentReceiptError, DeploymentRequest, FetchSettings, RouteMap,
    RouteState,
};
use tirith_core::policy::Policy;

use super::{sanitize_for_human_output, write_json_stdout};

/// Exit code for a usage or input error, distinct from every evidence outcome.
const EXIT_USAGE: i32 = 2;

/// Longest route map accepted from disk. A route map is a small document.
const MAX_ROUTE_MAP_BYTES: u64 = 4 * 1024 * 1024;

/// Everything `tirith attest build` was asked to do.
#[derive(Debug, Clone)]
pub struct BuildArgs {
    pub source: PathBuf,
    pub output: PathBuf,
    pub execution_receipt: Option<PathBuf>,
    pub out: Option<PathBuf>,
    pub json: bool,
}

/// Everything `tirith attest verify-build` was asked to do.
#[derive(Debug, Clone)]
pub struct VerifyBuildArgs {
    pub receipt: PathBuf,
    pub source: PathBuf,
    pub output: PathBuf,
    pub json: bool,
}

/// Everything `tirith attest deployment` was asked to do.
#[derive(Debug, Clone)]
pub struct DeploymentArgs {
    pub build_receipt: PathBuf,
    pub base_url: String,
    pub route_map: Option<PathBuf>,
    pub out: Option<PathBuf>,
    pub json: bool,
}

/// Everything `tirith attest verify-deployment` was asked to do.
#[derive(Debug, Clone)]
pub struct VerifyDeploymentArgs {
    pub receipt: PathBuf,
    pub json: bool,
}

// ---------------------------------------------------------------------------
// build
// ---------------------------------------------------------------------------

/// `tirith attest build` entry point. Returns the process exit code.
pub fn build(args: BuildArgs) -> i32 {
    let source = match resolve_directory(&args.source, "--source") {
        Ok(path) => path,
        Err(message) => return usage(args.json, "attest build", &message),
    };
    let output = match resolve_directory(&args.output, "--output") {
        Ok(path) => path,
        Err(message) => return usage(args.json, "attest build", &message),
    };
    if let Some(path) = args.execution_receipt.as_deref() {
        if !path.is_file() {
            return usage(
                args.json,
                "attest build",
                &format!(
                    "--execution-receipt {} is not a readable file",
                    path.display()
                ),
            );
        }
    }

    // The receipt destination is excluded from BOTH scans EXPLICITLY, so a
    // receipt written under either tree cannot hash itself into existence and
    // cannot make a second run of the same command produce a different digest.
    // Excluding it from the source alone left `--out dist/build.receipt.json`
    // reporting clean at build time and mismatch forever after, because the file
    // is absent when the output tree is measured and present at every later
    // verification.
    let mut extra_exclusions = Vec::new();
    let mut extra_output_exclusions = Vec::new();
    if let Some(out) = args.out.as_deref() {
        if let Some(relative) = build_receipt::relative_under(&source, out) {
            extra_exclusions.push(relative);
        }
        if let Some(relative) = build_receipt::relative_under(&output, out) {
            extra_output_exclusions.push(relative);
        }
    }

    let request = BuildRequest {
        source,
        output,
        extra_exclusions,
        extra_output_exclusions,
        execution_receipt: args.execution_receipt.clone(),
        // The exact argv, so the receipt binds what was asked for. It is digested
        // after redaction; the strings themselves never reach the document.
        argv: std::env::args().collect(),
        limits: TreeLimits::default(),
    };
    let receipt = build_receipt::build_receipt(&request, policy_projection_hash());

    if let Err(error) = receipt.validate() {
        // A receipt that fails its own honesty rules is a bug, and writing it
        // would publish a claim the type refuses to stand behind.
        eprintln!("tirith attest build: {error}");
        return EXIT_USAGE;
    }
    if let Some(path) = args.out.as_deref() {
        if let Err(error) = write_build_receipt(&receipt, path) {
            eprintln!(
                "tirith attest build: cannot write the receipt to {}: {error}",
                path.display()
            );
            return EXIT_USAGE;
        }
    }

    let exit = receipt.status.exit_code();
    if args.json {
        if !write_json_stdout(&receipt, "tirith attest build: failed to write JSON") {
            return EXIT_USAGE;
        }
        return exit;
    }
    print_build_receipt(&receipt, args.out.as_deref());
    exit
}

fn write_build_receipt(receipt: &BuildReceipt, path: &Path) -> Result<(), BuildReceiptError> {
    receipt.write_to(path)
}

fn print_build_receipt(receipt: &BuildReceipt, out: Option<&Path>) {
    let short = short_id(&receipt.receipt_id);
    eprintln!(
        "tirith attest build: {} (receipt {short})",
        receipt.status.token()
    );
    match receipt.subject.source_tree.as_ref() {
        Some(tree) => eprintln!(
            "  source:       {} ({} files, {} bytes)",
            tree.digest, tree.file_count, tree.total_bytes
        ),
        None => eprintln!("  source:       NOT BOUND"),
    }
    match receipt.subject.output_tree.as_ref() {
        Some(tree) => eprintln!(
            "  output:       {} ({} files, {} bytes)",
            tree.digest, tree.file_count, tree.total_bytes
        ),
        None => eprintln!("  output:       NOT BOUND"),
    }
    eprintln!(
        "  src excluded: {}",
        exclusion_line(&receipt.subject.source_exclusions)
    );
    if !receipt.subject.source_pruned.is_empty() {
        // A pruned subtree that appeared in neither the digest nor the rendering
        // would be content the receipt silently says nothing about.
        eprintln!(
            "  src pruned:   {}",
            exclusion_line(&receipt.subject.source_pruned)
        );
    }
    eprintln!(
        "  out excluded: {}",
        exclusion_line(&receipt.subject.output_exclusions)
    );
    match (
        receipt.subject.git.commit.as_deref(),
        receipt.subject.git.dirty,
    ) {
        (Some(commit), Some(true)) => eprintln!("  commit:       {commit} (working tree DIRTY)"),
        (Some(commit), Some(false)) => eprintln!("  commit:       {commit} (working tree clean)"),
        (Some(commit), None) => {
            eprintln!("  commit:       {commit} (dirty state could not be determined)")
        }
        (None, _) => eprintln!("  commit:       none; the source is not a readable repository"),
    }
    if receipt.subject.git.source_is_repository_root == Some(false) {
        // Without this line the commit reads as describing the digested bytes.
        eprintln!("    the commit describes the repository CONTAINING --source, not --source");
    }
    if !receipt.subject.lockfiles.is_empty() {
        eprintln!("  lockfiles:");
        for lockfile in &receipt.subject.lockfiles {
            eprintln!(
                "    {} {}",
                sanitize_for_human_output(&lockfile.name, false),
                lockfile.sha256
            );
        }
    }
    eprintln!(
        "  signature:    {}",
        signature_line(receipt.signature_present)
    );
    eprintln!(
        "  execution:    {}",
        receipt.evidence.execution.verdict.token()
    );
    for reason in &receipt.evidence.execution.reasons {
        eprintln!("    {}", sanitize_for_human_output(reason, false));
    }
    if let Some(refusal) = receipt.coverage.scan_refusal.as_deref() {
        eprintln!(
            "  NOT BOUND:    {}",
            sanitize_for_human_output(refusal, true)
        );
    }
    if let Some(path) = out {
        eprintln!("  receipt:      {}", path.display());
    }
    print_caveats(&receipt.caveats);
}

// ---------------------------------------------------------------------------
// verify-build
// ---------------------------------------------------------------------------

/// `tirith attest verify-build` entry point. Returns the process exit code.
pub fn verify_build(args: VerifyBuildArgs) -> i32 {
    // Loaded WITHOUT validating: a receipt that no longer stands up is a
    // finding this command must report as a mismatch, not an input error.
    let receipt = match BuildReceipt::load_unvalidated(&args.receipt) {
        Ok(receipt) => receipt,
        Err(error) => {
            return usage(
                args.json,
                "attest verify-build",
                &format!("{} is not a build receipt: {error}", args.receipt.display()),
            )
        }
    };
    let source = match resolve_directory(&args.source, "--source") {
        Ok(path) => path,
        Err(message) => return usage(args.json, "attest verify-build", &message),
    };
    let output = match resolve_directory(&args.output, "--output") {
        Ok(path) => path,
        Err(message) => return usage(args.json, "attest verify-build", &message),
    };

    let verification =
        build_receipt::verify_build(&receipt, &source, &output, SignatureAnchor::installed());
    let exit = verification.status.exit_code();
    if args.json {
        if !write_json_stdout(
            &verification,
            "tirith attest verify-build: failed to write JSON",
        ) {
            return EXIT_USAGE;
        }
        return exit;
    }
    eprintln!(
        "tirith attest verify-build: {} (receipt {})",
        verification.status.token(),
        short_id(&verification.receipt_id)
    );
    print_signature_trust(verification.signature);
    // The exclusion sets and the covered counts are printed on every answer,
    // because "clean" over a receipt whose exclusion set swallowed the whole tree
    // is only visibly wrong when the reader can see the set and the count.
    eprintln!(
        "  source:       {} file(s), excluded {}",
        count_line(verification.source_files),
        exclusion_line(&verification.source_exclusions)
    );
    eprintln!(
        "  output:       {} file(s), excluded {}",
        count_line(verification.output_files),
        exclusion_line(&verification.output_exclusions)
    );
    for finding in &verification.findings {
        eprintln!("  {}", sanitize_for_human_output(finding, false));
    }
    if verification.findings.is_empty() {
        eprintln!("  both trees still hash to exactly what the receipt bound.");
    }
    eprintln!("  {}", build_receipt::NOT_A_REPRODUCIBILITY_CLAIM);
    exit
}

// ---------------------------------------------------------------------------
// deployment
// ---------------------------------------------------------------------------

/// `tirith attest deployment` entry point. Returns the process exit code.
pub fn deployment(args: DeploymentArgs) -> i32 {
    let build = match BuildReceipt::load_unvalidated(&args.build_receipt) {
        Ok(receipt) => receipt,
        Err(error) => {
            return usage(
                args.json,
                "attest deployment",
                &format!(
                    "{} is not a build receipt: {error}",
                    args.build_receipt.display()
                ),
            )
        }
    };
    if build.subject.output_files.is_empty() {
        return usage(
            args.json,
            "attest deployment",
            "the build receipt carries no output manifest, so there is nothing to fetch",
        );
    }

    let route_map = match args.route_map.as_deref() {
        None => None,
        Some(path) => match load_route_map(path, &build) {
            Ok(map) => Some(map),
            Err(message) => return usage(args.json, "attest deployment", &message),
        },
    };

    let request = DeploymentRequest {
        base_url: args.base_url.clone(),
        route_map,
        settings: FetchSettings::default(),
    };
    let receipt = deployment_receipt::deployment_receipt(
        &build,
        &request,
        policy_projection_hash(),
        SignatureAnchor::installed(),
    );

    if let Err(error) = receipt.validate() {
        eprintln!("tirith attest deployment: {error}");
        return EXIT_USAGE;
    }
    if let Some(path) = args.out.as_deref() {
        if let Err(error) = write_deployment_receipt(&receipt, path) {
            eprintln!(
                "tirith attest deployment: cannot write the receipt to {}: {error}",
                path.display()
            );
            return EXIT_USAGE;
        }
    }

    let exit = receipt.status.exit_code();
    if args.json {
        if !write_json_stdout(&receipt, "tirith attest deployment: failed to write JSON") {
            return EXIT_USAGE;
        }
        return exit;
    }
    print_deployment_receipt(&receipt, args.out.as_deref());
    exit
}

fn write_deployment_receipt(
    receipt: &DeploymentReceipt,
    path: &Path,
) -> Result<(), DeploymentReceiptError> {
    receipt.write_to(path)
}

fn load_route_map(path: &Path, build: &BuildReceipt) -> Result<RouteMap, String> {
    let bytes = tirith_core::util::read_text_no_follow_capped(path, MAX_ROUTE_MAP_BYTES).map_err(
        |error| {
            format!(
                "--route-map {} could not be read: {error:?}",
                path.display()
            )
        },
    )?;
    let text = String::from_utf8(bytes)
        .map_err(|_| format!("--route-map {} is not UTF-8", path.display()))?;
    let map = deployment_receipt::parse_route_map(&text).map_err(|error| error.to_string())?;
    deployment_receipt::validate_route_map(&map, &build.subject.output_files)
        .map_err(|error| error.to_string())?;
    Ok(map)
}

fn print_deployment_receipt(receipt: &DeploymentReceipt, out: Option<&Path>) {
    eprintln!(
        "tirith attest deployment: {} (receipt {})",
        receipt.status.token(),
        short_id(&receipt.receipt_id)
    );
    eprintln!(
        "  origin:       {}",
        sanitize_for_human_output(&receipt.subject.origin, false)
    );
    eprintln!(
        "  build:        {} ({}, signature {})",
        short_id(&receipt.subject.build_receipt_id),
        receipt.subject.build_receipt_status.token(),
        receipt.coverage.build_signature.token()
    );
    if !receipt.coverage.build_receipt_verified {
        eprintln!("  the build receipt did not stand up; nothing was fetched.");
    }
    eprintln!(
        "  signature:    {}",
        signature_line(receipt.signature_present)
    );
    if let Some(refusal) = receipt.coverage.route_map_refusal.as_deref() {
        eprintln!(
            "  the route map was refused; nothing was fetched: {}",
            sanitize_for_human_output(refusal, false)
        );
    }
    eprintln!(
        "  routes:       {} of {} built files ({} map)",
        receipt.coverage.routes_requested,
        receipt.coverage.output_files_total,
        receipt.subject.route_map_source
    );
    eprintln!(
        "    matched {}, mismatched {}, unmeasured {}",
        receipt.coverage.routes_matched,
        receipt.coverage.routes_mismatched,
        receipt.coverage.routes_partial
    );
    for route in &receipt.routes {
        if route.state == RouteState::Match {
            continue;
        }
        eprintln!(
            "  {} {} -> {}",
            route.state.token().to_uppercase(),
            sanitize_for_human_output(&route.build_path, false),
            sanitize_for_human_output(&route.route, false)
        );
        if let Some(detail) = route.detail.as_deref() {
            eprintln!("    {}", sanitize_for_human_output(detail, false));
        }
    }
    if let Some(path) = out {
        eprintln!("  receipt:      {}", path.display());
    }
    print_caveats(&receipt.caveats);
}

// ---------------------------------------------------------------------------
// verify-deployment
// ---------------------------------------------------------------------------

/// `tirith attest verify-deployment` entry point. Returns the process exit code.
pub fn verify_deployment(args: VerifyDeploymentArgs) -> i32 {
    let receipt = match DeploymentReceipt::load_unvalidated(&args.receipt) {
        Ok(receipt) => receipt,
        Err(error) => {
            return usage(
                args.json,
                "attest verify-deployment",
                &format!(
                    "{} is not a deployment receipt: {error}",
                    args.receipt.display()
                ),
            )
        }
    };
    let verification =
        deployment_receipt::verify_deployment(&receipt, SignatureAnchor::installed());
    let exit = verification.status.exit_code();
    if args.json {
        if !write_json_stdout(
            &verification,
            "tirith attest verify-deployment: failed to write JSON",
        ) {
            return EXIT_USAGE;
        }
        return exit;
    }
    eprintln!(
        "tirith attest verify-deployment: {} (receipt {})",
        verification.status.token(),
        short_id(&verification.receipt_id)
    );
    print_signature_trust(verification.signature);
    // What the receipt is about and when it was taken. The point-in-time caveat
    // below is meaningless without the timestamp it refers to, and a receipt for
    // a staging origin must not read identically to one for production.
    eprintln!(
        "  origin:       {}",
        sanitize_for_human_output(&verification.origin, false)
    );
    eprintln!(
        "  measured:     {}",
        sanitize_for_human_output(&verification.created_at, false)
    );
    eprintln!(
        "  build:        {} ({})",
        short_id(&verification.build_receipt_id),
        verification.build_receipt_status.token()
    );
    eprintln!(
        "  routes:       {} of {} built files",
        verification.routes_requested, verification.output_files_total
    );
    eprintln!(
        "    matched {}, mismatched {}, unmeasured {}",
        verification.routes_matched, verification.routes_mismatched, verification.routes_partial
    );
    for finding in &verification.findings {
        eprintln!("  {}", sanitize_for_human_output(finding, false));
    }
    eprintln!("  {}", deployment_receipt::POINT_IN_TIME_CAVEAT);
    exit
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// The receipt's policy identity: a hash of the durable, non-secret security
/// projection, never the policy itself.
///
/// `discover_local_only` is deliberate: an attest run must not fetch a remote
/// policy while it is binding bytes.
fn policy_projection_hash() -> String {
    let cwd = std::env::current_dir()
        .ok()
        .map(|path| path.display().to_string());
    Policy::discover_local_only(cwd.as_deref()).security_projection_hash()
}

fn resolve_directory(path: &Path, flag: &str) -> Result<PathBuf, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("{flag} {} could not be read: {error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        // The tree scanner refuses a symlink anywhere inside the tree; refusing
        // it at the root too keeps the message specific instead of arriving as a
        // generic scan refusal.
        return Err(format!("{flag} {} is a symlink", path.display()));
    }
    if !metadata.is_dir() {
        return Err(format!("{flag} {} is not a directory", path.display()));
    }
    Ok(path.to_path_buf())
}

/// The first 16 bytes of a receipt id, safe over a hostile document.
///
/// Both verify commands load their receipt WITHOUT validating it, on purpose, so
/// a document that no longer stands up is reported as a finding rather than as
/// an input error. That routes an attacker-chosen `receipt_id` straight into
/// this renderer, and a naive byte slice panics when byte 16 lands inside a
/// multi-byte scalar, turning a documented `mismatch` into exit 101 and a Rust
/// backtrace. The id is also neutralized for the terminal, for the same reason.
fn short_id(id: &str) -> String {
    sanitize_for_human_output(&tirith_core::util::truncate_bytes(id, 16), false)
}

/// How many removed paths one rendered line names before it summarizes.
///
/// The prune list is bounded by the tree's entry cap rather than by anything
/// small, and a hostile tree can hold a `.git` in every directory, so the
/// terminal rendering says how many there are instead of printing all of them.
const RENDERED_EXCLUSIONS: usize = 12;

/// Render an exclusion or prune list, with an explicit marker for "nothing".
fn exclusion_line(values: &[String]) -> String {
    if values.is_empty() {
        return "nothing".to_string();
    }
    let shown = values
        .iter()
        .take(RENDERED_EXCLUSIONS)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let line = match values.len().checked_sub(RENDERED_EXCLUSIONS) {
        Some(rest) if rest > 0 => format!("{shown}, and {rest} more"),
        _ => shown,
    };
    sanitize_for_human_output(&line, false)
}

fn count_line(count: Option<usize>) -> String {
    match count {
        Some(count) => count.to_string(),
        None => "NOT BOUND".to_string(),
    }
}

/// What a freshly produced receipt can honestly say about its own signature.
///
/// Producing one proves nothing about whether it verifies, so this says only
/// that a signature was attached and names the command that checks it. The
/// verify commands are the ones that report trust.
fn signature_line(present: bool) -> &'static str {
    if present {
        "attached; the verify commands check it against the installed audit key"
    } else {
        "none; this installation has no audit signing key configured"
    }
}

/// Say what the signature ESTABLISHED, never merely that a field was populated.
///
/// Printing a warning only when the field is absent made a forged document with
/// a junk signature render as the more trustworthy of the two.
fn print_signature_trust(trust: SignatureTrust) {
    match trust {
        SignatureTrust::Verified => {
            eprintln!("  signature:    verified against the installed audit key")
        }
        SignatureTrust::Unsigned => {
            eprintln!("  signature:    none, so this receipt is hash-chained to nothing")
        }
        SignatureTrust::Uncheckable => eprintln!(
            "  signature:    PRESENT BUT UNCHECKED; no usable audit verifying key is installed"
        ),
        SignatureTrust::Rejected => {
            eprintln!("  signature:    REJECTED; treat this receipt as forged")
        }
    }
}

fn print_caveats(caveats: &[String]) {
    for caveat in caveats {
        eprintln!("  {}", sanitize_for_human_output(caveat, true));
    }
}

/// Report an input error on stderr, and as a JSON envelope when `--json` was
/// asked for, so a scripted caller gets a parseable answer either way.
fn usage(json: bool, command: &str, message: &str) -> i32 {
    eprintln!("tirith {command}: {message}");
    if json {
        // `usage` is deliberately not one of the three evidence statuses: this
        // is a bad invocation, not a finding about a build or a deployment, and
        // a scripted caller must not read it as either.
        let envelope = serde_json::json!({
            "status": "usage",
            "error": message,
        });
        // The exit code is the source of truth; a failed JSON write must not
        // change it.
        let _ = write_json_stdout(&envelope, "tirith attest: failed to write JSON");
    }
    EXIT_USAGE
}
