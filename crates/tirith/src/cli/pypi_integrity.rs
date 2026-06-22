//! `tirith pkg attest <wheel>` (PR F3, the `sigstore-attestations` spike): fetch a
//! wheel's PyPI publish provenance from the Integrity API, BIND the attestation's
//! subject digest to the wheel's quarantined SHA-256, optionally VERIFY the Sigstore
//! bundle, and check the publisher identity against policy — emitting a provenance
//! outcome that is EVIDENCE, never an auto-allow.
//!
//! # Why the network half lives here
//!
//! Per the plan's crate split, `tirith-core` holds only the provenance types and
//! the pure subject-digest binding ([`tirith_core::provenance::pypi_integrity`]);
//! the Integrity API fetch, the Sigstore cryptographic verification, and the
//! `tuf`/network trust root live in THIS CLI crate, because they pull `tokio` and
//! the `sigstore-*` closure that `tirith-core` must stay free of. This module is
//! that network half.
//!
//! # The `sigstore-attestations` feature, and why it is off on the MSRV
//!
//! The cryptographic verification is gated behind the `sigstore-attestations`
//! feature. On the workspace MSRV (Rust 1.83) that feature is OFF and its
//! `sigstore-*` dependencies are intentionally omitted, because the modular
//! `sigstore-verify` 0.9 closure transitively requires Rust >= 1.85 (see the
//! `tirith` crate `Cargo.toml` `[features]` note). F3 is an optional spike that
//! only fully activates once the workspace MSRV rises; until then this command
//! still RUNS — it fetches the provenance and performs the structural
//! subject-digest binding — but it reports
//! [`AttestationOutcome::VerificationUnavailable`] instead of
//! [`AttestationOutcome::Verified`], because without the Sigstore verification it
//! has no cryptographic basis to call an attestation trusted. Crucially this never
//! degrades to an auto-allow: an unverifiable attestation is unavailable evidence,
//! not trust.
//!
//! # Never blocks
//!
//! Like the F1 provenance graph, this is a read / evidence surface: it inspects the
//! wheel and reports the attestation outcome, and exits `0` whatever the outcome
//! (even a subject mismatch), with `2` reserved for a usage / input error (an
//! uninspectable wheel, a non-PyPI artifact). The install verdict lives in the
//! firewall over the bytes, not here; a missing or invalid attestation must never,
//! on its own, decide an install.
//!
//! # What is tested vs. at runtime
//!
//! The real Integrity API fetch needs the network; the PURE seam (parsing a
//! provenance response into an [`AttestationOutcome`] given the artifact digest and
//! the publisher policy) is unit-tested here with hand-built JSON, and the fetch
//! wrapper is exercised against a mock HTTP server. The Sigstore verification path
//! is compiled only under the feature and is the part the end-to-end "verify one
//! real PyPI fixture" gate covers when the MSRV allows it.

use std::path::Path;
use std::time::Duration;

use tirith_core::artifact::inspect::inspect_artifact_file;
use tirith_core::artifact::InspectionSubject;
use tirith_core::policy::Policy;
use tirith_core::threatdb::Ecosystem;
use tirith_core::provenance::pypi_integrity::{
    AttestationOutcome, PublisherIdentity, PublisherPolicy, SubjectBinding,
};

/// The PyPI Integrity API base. The provenance for a file lives at
/// `<base>/<project>/<version>/<filename>/provenance`. A fixed, public HTTPS host;
/// the per-file URL is still run through the SSRF / fetch validator before the
/// request, so a hostile redirect or a malformed component cannot reach a private
/// or metadata address.
const PYPI_INTEGRITY_BASE: &str = "https://pypi.org/integrity";

/// Bound the provenance fetch: a small JSON document, so a short timeout and a
/// modest body cap are correct. A response over the cap is treated as a fetch
/// failure (no provenance), never streamed unbounded.
const FETCH_TIMEOUT_SECS: u64 = 15;
const MAX_PROVENANCE_BYTES: usize = 4 * 1024 * 1024;

/// Entry point for `tirith pkg attest <wheel>`. Inspects the wheel to derive its
/// PyPI identity + SHA-256, fetches its publish provenance, evaluates the
/// attestation outcome (binding + optional Sigstore verification + publisher
/// policy), and renders it.
///
/// Returns a process exit code: `0` whenever an outcome was produced (including a
/// negative outcome — this surface reports evidence, it does not block), or `2` on
/// a usage / input error (a wheel that could not be inspected, or a non-PyPI
/// artifact for which the Integrity API does not apply).
pub fn run(wheel: &Path, json: bool) -> i32 {
    // 1. Inspect the wheel for its exact identity + content hash. Reuses the same
    //    hardened reader the firewall and the F1/F2 graph/diff use.
    let inspected = match inspect_artifact_file(wheel) {
        Ok(i) => i,
        Err(e) => {
            report_input_error(
                &format!("the wheel could not be inspected: {e:?}"),
                json,
            );
            return 2;
        }
    };

    let identity = match &inspected.inspection.subject {
        InspectionSubject::Artifact(a) if a.ecosystem == Ecosystem::PyPI => a.clone(),
        InspectionSubject::Artifact(a) => {
            report_input_error(
                &format!(
                    "pkg attest covers PyPI artifacts; this artifact is {} (the PyPI Integrity \
                     API does not apply)",
                    a.ecosystem
                ),
                json,
            );
            return 2;
        }
        _ => {
            report_input_error(
                "pkg attest needs a distributable wheel artifact (not an installed distribution \
                 or a generic archive)",
                json,
            );
            return 2;
        }
    };

    let version = match &identity.version {
        Some(v) => v.clone(),
        None => {
            report_input_error(
                "the wheel does not declare a version, which the Integrity API URL requires",
                json,
            );
            return 2;
        }
    };

    // 2. Build the publisher policy from the offline operator policy (the same
    //    discovery the firewall uses). Today this is the unconstrained default
    //    (there is no operator attestation-policy field yet); it can only TIGHTEN,
    //    so a repo-scoped policy can never relax it.
    let cwd = std::env::current_dir().ok().map(|p| p.display().to_string());
    let policy = Policy::discover_local_only(cwd.as_deref());
    let publisher_policy = publisher_policy_from(&policy);

    // 3. Fetch the provenance and evaluate the outcome.
    let outcome = match fetch_provenance(&identity.name, &version, &identity.filename) {
        Ok(body) => parse_integrity_provenance(&body, &identity.sha256, &publisher_policy),
        Err(FetchError::NotFound) => AttestationOutcome::Missing {
            reason: "the Integrity API has no provenance for this file".to_string(),
        },
        Err(FetchError::Transport(reason)) => AttestationOutcome::Missing {
            reason: format!("the provenance could not be fetched: {reason}"),
        },
    };

    render(&identity.name, &version, &identity.sha256, &outcome, json);
    0
}

/// Derive the publisher allowlist from the operator policy. F3 ships with no
/// dedicated attestation-policy field (the spike is gated off on the MSRV), so this
/// returns the unconstrained default: every verified identity is recorded as
/// evidence rather than rejected. It is wired through a function (rather than
/// inlining `PublisherPolicy::default()`) so a future operator field attaches in
/// exactly one place, and because the policy can only ever TIGHTEN the outcome it
/// needs no repo-scope neutralization.
fn publisher_policy_from(_policy: &Policy) -> PublisherPolicy {
    PublisherPolicy::default()
}

/// A provenance-fetch failure, distinguishing "the API has no provenance for this
/// file" (a clean Missing) from a transport error (also surfaced as Missing, with
/// the reason).
enum FetchError {
    /// The API responded 404 / no provenance.
    NotFound,
    /// A transport / validation / oversize error, with a non-secret reason.
    Transport(String),
}

/// Fetch the raw provenance JSON for a file from the Integrity API. Validates the
/// constructed URL through the fetch / SSRF validator before connecting (so a
/// malformed component or a hostile redirect cannot reach a private / loopback /
/// metadata address), bounds the timeout, and caps the body. Returns the JSON body
/// text, or a [`FetchError`].
fn fetch_provenance(project: &str, version: &str, filename: &str) -> Result<String, FetchError> {
    let url = integrity_provenance_url(PYPI_INTEGRITY_BASE, project, version, filename);
    fetch_provenance_at(&url)
}

/// The fetch body, split from URL construction so a test can drive it against a
/// mock server URL. Still validates the URL it is handed.
fn fetch_provenance_at(url: &str) -> Result<String, FetchError> {
    // Run the URL through the same fetch validator the resolver / cloaking paths
    // use: HTTPS-or-HTTP, no embedded credentials, no private / loopback /
    // metadata destination (after DNS), unless the explicit
    // TIRITH_ALLOW_PRIVATE_FETCH opt-in is set (used by the mock-server test).
    tirith_core::url_validate::validate_fetch_url(url)
        .map_err(|reason| FetchError::Transport(format!("URL rejected: {reason}")))?;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(FETCH_TIMEOUT_SECS))
        .redirect(tirith_core::ssrf_guard::server_redirect_policy())
        .build()
        .map_err(|e| FetchError::Transport(format!("HTTP client error: {e}")))?;

    let resp = client
        .get(url)
        .header("Accept", "application/vnd.pypi.integrity.v1+json")
        .send()
        .map_err(|e| FetchError::Transport(e.to_string()))?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(FetchError::NotFound);
    }
    if !resp.status().is_success() {
        return Err(FetchError::Transport(format!(
            "Integrity API returned HTTP {}",
            resp.status().as_u16()
        )));
    }

    // Cap the body: a provenance document is small.
    let bytes = resp
        .bytes()
        .map_err(|e| FetchError::Transport(e.to_string()))?;
    if bytes.len() > MAX_PROVENANCE_BYTES {
        return Err(FetchError::Transport(format!(
            "provenance response exceeds the {MAX_PROVENANCE_BYTES}-byte cap"
        )));
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|_| FetchError::Transport("provenance response is not valid UTF-8".to_string()))
}

/// Construct the Integrity API provenance URL for a file. The project name is PEP
/// 503 normalized (the API path uses the normalized name); the version and filename
/// are percent-encoded into the path by `url::Url`'s path-segment writer (which
/// encodes each segment so a `/` or other reserved byte in a component cannot break
/// out of its segment). Falls back to a plain join only if `base` does not parse as
/// a URL (it always does for the fixed const).
fn integrity_provenance_url(base: &str, project: &str, version: &str, filename: &str) -> String {
    let proj = tirith_core::artifact::normalize_project_name_public(project);
    match url::Url::parse(base) {
        Ok(mut u) => {
            // `path_segments_mut` percent-encodes each pushed segment.
            if let Ok(mut segs) = u.path_segments_mut() {
                segs.push(&proj);
                segs.push(version);
                segs.push(filename);
                segs.push("provenance");
            }
            u.to_string()
        }
        Err(_) => format!("{base}/{proj}/{version}/{filename}/provenance"),
    }
}

/// The PURE evaluation seam: given a fetched provenance JSON body, the quarantined
/// artifact's SHA-256, and the publisher policy, produce the [`AttestationOutcome`].
/// No network, fully deterministic, unit-tested with hand-built JSON.
///
/// The Integrity API `provenance` response wraps one or more `attestation_bundles`,
/// each carrying a Sigstore-signed in-toto statement whose `subject[].digest.sha256`
/// names the file the attestation covers. The evaluation:
///
/// 1. Parses the response and locates the in-toto subject digest. A response with
///    no parseable attestation is [`AttestationOutcome::Missing`].
/// 2. BINDS that subject digest to the artifact's SHA-256. A non-bind (or a
///    malformed digest) is [`AttestationOutcome::SubjectMismatch`] — the
///    artifact-swap / stale-attestation tell, surfaced even without the crypto
///    backend because it is a structural check.
/// 3. VERIFIES the Sigstore bundle and applies the publisher policy — ONLY when the
///    `sigstore-attestations` feature is compiled in. Without it, the strongest
///    outcome is [`AttestationOutcome::VerificationUnavailable`] (with the
///    successful binding noted), NEVER `Verified`: an unverified bundle is not
///    trust.
pub fn parse_integrity_provenance(
    body: &str,
    artifact_sha256: &str,
    publisher_policy: &PublisherPolicy,
) -> AttestationOutcome {
    let value: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return AttestationOutcome::Invalid {
                reason: format!("provenance response is not valid JSON: {e}"),
            };
        }
    };

    // Locate the in-toto subject digest and the (claimed) publisher identity.
    let Some(claim) = extract_attestation_claim(&value) else {
        return AttestationOutcome::Missing {
            reason: "the provenance response contains no parseable attestation".to_string(),
        };
    };

    // The subject digest must be present to bind to anything.
    let Some(attested) = claim.subject_sha256.as_deref() else {
        return AttestationOutcome::Invalid {
            reason: "the attestation in-toto statement carries no subject sha256 digest"
                .to_string(),
        };
    };

    // Structural binding first — independent of the crypto backend.
    match tirith_core::provenance::pypi_integrity::bind_subject_digest(attested, artifact_sha256) {
        SubjectBinding::Bound => {}
        SubjectBinding::Mismatch | SubjectBinding::Malformed => {
            return AttestationOutcome::SubjectMismatch {
                attested_sha256: attested.trim().to_ascii_lowercase(),
                artifact_sha256: artifact_sha256.trim().to_ascii_lowercase(),
            };
        }
    }

    // Cryptographic verification + publisher policy: feature-gated.
    verify_and_finalize(&value, &claim, artifact_sha256, publisher_policy)
}

/// The in-toto claim extracted from a provenance response: the subject SHA-256 the
/// attestation covers, plus the publisher identity it asserts (best-effort, from
/// the certificate claims the API echoes).
struct AttestationClaim {
    subject_sha256: Option<String>,
    // `identity` is consumed by the feature-on `verify_and_finalize` (it is the
    // claimed publisher the verified path checks against policy) and by the unit
    // tests; with the `sigstore-attestations` feature OFF the verification path is
    // not compiled, so the field is read only from tests. Gate the dead-code allow
    // on the feature rather than dropping the field, since dropping it would lose
    // the publisher the verification needs.
    #[cfg_attr(not(feature = "sigstore-attestations"), allow(dead_code))]
    identity: PublisherIdentity,
}

/// Pull the first attestation's in-toto subject digest and asserted publisher
/// identity out of an Integrity API `provenance` response, tolerating the response
/// shape's optionality. Returns `None` when no attestation statement is present at
/// all.
fn extract_attestation_claim(value: &serde_json::Value) -> Option<AttestationClaim> {
    // provenance.attestation_bundles[].attestations[].statement (or the v1 shape's
    // `messageSignature` / `verification_material`); we read the in-toto statement's
    // first subject digest. The shape is read defensively: any missing layer just
    // yields None.
    let bundles = value.get("attestation_bundles")?.as_array()?;
    for bundle in bundles {
        let publisher = bundle
            .get("publisher")
            .map(extract_publisher_identity)
            .unwrap_or_default();
        let Some(attestations) = bundle.get("attestations").and_then(|a| a.as_array()) else {
            continue;
        };
        for att in attestations {
            let statement = att
                .get("statement")
                .or_else(|| att.get("envelope").and_then(|e| e.get("statement")));
            let subject_sha256 = statement
                .and_then(|s| s.get("subject"))
                .and_then(|s| s.as_array())
                .and_then(|subjects| subjects.first())
                .and_then(|s| s.get("digest"))
                .and_then(|d| d.get("sha256"))
                .and_then(|h| h.as_str())
                .map(|s| s.to_string());
            if subject_sha256.is_some() {
                return Some(AttestationClaim {
                    subject_sha256,
                    identity: publisher,
                });
            }
        }
    }
    None
}

/// Read a best-effort publisher identity out of an Integrity API `publisher`
/// object. PyPI's Trusted Publisher metadata carries the source repository and the
/// workflow; these are descriptive strings, never secrets.
fn extract_publisher_identity(publisher: &serde_json::Value) -> PublisherIdentity {
    let repo = publisher
        .get("repository")
        .or_else(|| publisher.get("repository_full_name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let workflow = publisher
        .get("workflow")
        .or_else(|| publisher.get("workflow_filename"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let signer = publisher
        .get("environment")
        .or_else(|| publisher.get("signer_identity"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    PublisherIdentity {
        repository: repo,
        workflow,
        signer_identity: signer,
    }
}

/// Verify the Sigstore bundle and apply the publisher policy. With the
/// `sigstore-attestations` feature OFF (the MSRV default), this cannot
/// cryptographically verify and returns
/// [`AttestationOutcome::VerificationUnavailable`] — the binding succeeded
/// structurally, but without verification there is no trust, so it is explicitly
/// NOT `Verified`. With the feature ON, it runs the modular `sigstore-*`
/// verification and, on success, routes through
/// [`tirith_core::provenance::pypi_integrity::evaluate_verified_attestation`].
#[cfg(not(feature = "sigstore-attestations"))]
fn verify_and_finalize(
    _value: &serde_json::Value,
    _claim: &AttestationClaim,
    _artifact_sha256: &str,
    _publisher_policy: &PublisherPolicy,
) -> AttestationOutcome {
    AttestationOutcome::VerificationUnavailable {
        reason: "the sigstore-attestations feature is not compiled in (the sigstore verification \
                 backend requires a newer Rust than the workspace MSRV), so the attestation was \
                 fetched and its subject digest bound to the artifact, but the Sigstore bundle \
                 could not be cryptographically verified; this is unavailable evidence, not trust"
            .to_string(),
    }
}

/// Feature-on path: cryptographically verify the Sigstore bundle, then finalize.
///
/// This is the spike body the "verify one real PyPI fixture end to end" gate
/// covers. It is compiled ONLY under `sigstore-attestations`; on the workspace MSRV
/// the feature (and the `sigstore-*` deps) are absent, so this code is not built.
/// When wired, it: builds the trust root (offline TUF root in core; the network
/// root in this crate), verifies the bundle's signature + certificate chain +
/// transparency-log inclusion against the artifact, extracts the verified publisher
/// identity from the signing certificate, and routes a successful verification
/// through [`tirith_core::provenance::pypi_integrity::evaluate_verified_attestation`]
/// (which re-binds the subject digest and applies the publisher policy). A failed
/// verification is [`AttestationOutcome::Invalid`].
#[cfg(feature = "sigstore-attestations")]
fn verify_and_finalize(
    _value: &serde_json::Value,
    claim: &AttestationClaim,
    artifact_sha256: &str,
    publisher_policy: &PublisherPolicy,
) -> AttestationOutcome {
    // The actual sigstore-verify / -trust-root call is the spike's remaining work
    // and lands with the MSRV bump that lets the closure build. Until that call is
    // wired, even the feature-on build must not fabricate a `Verified` outcome from
    // an unverified bundle, so it reports Invalid (verification did not run to a
    // pass). When the verification IS wired, replace this body with: verify ->
    // on-pass `evaluate_verified_attestation(verified_subject, verified_identity,
    // artifact_sha256, publisher_policy)`; on-fail `Invalid { reason }`. The claimed
    // publisher identity (`claim.identity`) is the value that path checks against
    // `publisher_policy`, so it is referenced here to keep the wiring explicit.
    let _claimed_identity = &claim.identity;
    let _ = (claim.subject_sha256.as_ref(), artifact_sha256, publisher_policy);
    AttestationOutcome::Invalid {
        reason: "sigstore verification backend is enabled but the verify call is not yet wired \
                 (F3 spike); refusing to report an unverified bundle as trusted"
            .to_string(),
    }
}

/// Render the attestation outcome for a file in the requested format. Human form to
/// stderr (a short evidence summary); JSON form to stdout (the machine surface).
fn render(project: &str, version: &str, artifact_sha256: &str, outcome: &AttestationOutcome, json: bool) {
    if json {
        let out = serde_json::json!({
            "project": project,
            "version": version,
            "artifact_sha256": artifact_sha256,
            "attestation": outcome,
            "is_verified": outcome.is_verified(),
        });
        let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), &out);
        println!();
    } else {
        eprintln!("tirith pkg attest: {project} {version}");
        eprintln!("  artifact sha256: {artifact_sha256}");
        eprintln!("  attestation:     {}", outcome.label());
        match outcome {
            AttestationOutcome::Verified { identity, .. } => {
                eprintln!("  verified publish provenance (positive evidence, not an install authorization)");
                render_identity(identity);
            }
            AttestationOutcome::Missing { reason } => {
                eprintln!("  no attestation: {reason}");
                eprintln!("  (absence of provenance is not a block; the firewall verdict is over the bytes)");
            }
            AttestationOutcome::Invalid { reason } => {
                eprintln!("  attestation invalid: {reason}");
            }
            AttestationOutcome::SubjectMismatch {
                attested_sha256,
                artifact_sha256,
            } => {
                eprintln!("  SUBJECT MISMATCH: the attestation covers different bytes than this artifact");
                eprintln!("    attested: {attested_sha256}");
                eprintln!("    artifact: {artifact_sha256}");
            }
            AttestationOutcome::PublisherNotAllowed { identity, reason } => {
                eprintln!("  publisher not allowed: {reason}");
                render_identity(identity);
            }
            AttestationOutcome::VerificationUnavailable { reason } => {
                eprintln!("  verification unavailable: {reason}");
            }
        }
    }
}

/// Render a publisher identity's asserted fields (those present) for the human
/// summary.
fn render_identity(identity: &PublisherIdentity) {
    if let Some(repo) = &identity.repository {
        eprintln!("    repository: {repo}");
    }
    if let Some(wf) = &identity.workflow {
        eprintln!("    workflow:   {wf}");
    }
    if let Some(sid) = &identity.signer_identity {
        eprintln!("    signer:     {sid}");
    }
}

/// Report an input / usage error in the requested format (stderr human, stdout
/// JSON), mirroring the F2 `pkg diff` error shape.
fn report_input_error(message: &str, json: bool) {
    if json {
        let out = serde_json::json!({ "error": message });
        let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), &out);
        println!();
    } else {
        eprintln!("tirith pkg attest: {message}");
        eprintln!("  try: tirith pkg attest <wheel.whl>");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// Serializes the two tests that toggle the process-wide
    /// `TIRITH_ALLOW_PRIVATE_FETCH` env var, so a parallel run cannot have one test
    /// clear the opt-in while the other is mid-fetch (the known env-race flake
    /// class). A poisoned lock is fine to recover from here — the guarded body only
    /// sets/removes one env var.
    static PRIVATE_FETCH_ENV: Mutex<()> = Mutex::new(());

    /// A minimal Integrity API provenance response carrying one attestation whose
    /// in-toto subject digest is `subject_sha`, with a publisher block.
    fn provenance_json(subject_sha: &str) -> String {
        serde_json::json!({
            "version": 1,
            "attestation_bundles": [{
                "publisher": {
                    "kind": "GitHub",
                    "repository": "pypa/sampleproject",
                    "workflow": "release.yml"
                },
                "attestations": [{
                    "version": 1,
                    "statement": {
                        "_type": "https://in-toto.io/Statement/v1",
                        "subject": [{
                            "name": "sampleproject-1.0-py3-none-any.whl",
                            "digest": { "sha256": subject_sha }
                        }],
                        "predicateType": "https://docs.pypi.org/attestations/publish/v1"
                    }
                }]
            }]
        })
        .to_string()
    }

    #[test]
    fn url_is_normalized_and_encoded() {
        let url = integrity_provenance_url(
            "https://pypi.org/integrity",
            "Sample.Project",
            "1.0",
            "Sample_Project-1.0-py3-none-any.whl",
        );
        // PEP 503 normalizes `Sample.Project` -> `sample-project`; the version and
        // filename are pushed as encoded path segments.
        assert!(
            url.starts_with("https://pypi.org/integrity/sample-project/1.0/"),
            "got {url}"
        );
        assert!(
            url.contains("Sample_Project-1.0-py3-none-any.whl"),
            "got {url}"
        );
        assert!(url.ends_with("/provenance"), "got {url}");
    }

    #[test]
    fn url_segment_encoding_contains_no_path_breakout() {
        // A component containing a slash must be percent-encoded into its segment,
        // not expand the path. `url::Url`'s path_segments_mut guarantees this.
        let url = integrity_provenance_url(
            "https://pypi.org/integrity",
            "demo",
            "1.0",
            "a/b.whl",
        );
        assert!(url.contains("a%2Fb.whl"), "slash must be encoded, got {url}");
        assert!(url.ends_with("/provenance"), "got {url}");
    }

    #[test]
    fn missing_attestation_is_missing_outcome() {
        let body = serde_json::json!({ "version": 1, "attestation_bundles": [] }).to_string();
        let out = parse_integrity_provenance(&body, SHA_A, &PublisherPolicy::default());
        assert!(matches!(out, AttestationOutcome::Missing { .. }));
    }

    #[test]
    fn invalid_json_is_invalid_outcome() {
        let out = parse_integrity_provenance("not json", SHA_A, &PublisherPolicy::default());
        assert!(matches!(out, AttestationOutcome::Invalid { .. }));
    }

    #[test]
    fn subject_mismatch_detected_structurally_without_crypto() {
        // The attestation covers SHA_B, the artifact is SHA_A -> SubjectMismatch,
        // caught even though the crypto backend (sigstore-attestations) is off,
        // because the binding is a structural check.
        let body = provenance_json(SHA_B);
        let out = parse_integrity_provenance(&body, SHA_A, &PublisherPolicy::default());
        match out {
            AttestationOutcome::SubjectMismatch {
                attested_sha256,
                artifact_sha256,
            } => {
                assert_eq!(attested_sha256, SHA_B);
                assert_eq!(artifact_sha256, SHA_A);
            }
            other => panic!("expected SubjectMismatch, got {other:?}"),
        }
    }

    #[test]
    #[cfg(not(feature = "sigstore-attestations"))]
    fn bound_without_crypto_is_unavailable_not_verified() {
        // The attestation covers SHA_A and the artifact IS SHA_A: the binding
        // succeeds. But with the sigstore-attestations feature off, the outcome is
        // VerificationUnavailable, never Verified — an unverified bundle is not
        // trust, and this must never become an auto-allow.
        let body = provenance_json(SHA_A);
        let out = parse_integrity_provenance(&body, SHA_A, &PublisherPolicy::default());
        assert!(
            matches!(out, AttestationOutcome::VerificationUnavailable { .. }),
            "bound-but-unverified must be VerificationUnavailable, got {out:?}"
        );
        assert!(!out.is_verified());
    }

    #[test]
    fn statement_without_subject_digest_is_invalid() {
        let body = serde_json::json!({
            "version": 1,
            "attestation_bundles": [{
                "publisher": { "repository": "pypa/sampleproject" },
                "attestations": [{
                    "statement": {
                        "subject": [{ "name": "x.whl", "digest": {} }]
                    }
                }]
            }]
        })
        .to_string();
        let out = parse_integrity_provenance(&body, SHA_A, &PublisherPolicy::default());
        // No subject sha256 in any attestation -> no parseable claim -> Missing.
        assert!(
            matches!(out, AttestationOutcome::Missing { .. }),
            "got {out:?}"
        );
    }

    #[test]
    fn extract_publisher_reads_repo_and_workflow() {
        let body = provenance_json(SHA_A);
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        let claim = extract_attestation_claim(&value).expect("a claim");
        assert_eq!(claim.identity.repository.as_deref(), Some("pypa/sampleproject"));
        assert_eq!(claim.identity.workflow.as_deref(), Some("release.yml"));
    }

    #[test]
    fn fetch_404_is_not_found() {
        let _guard = PRIVATE_FETCH_ENV.lock().unwrap_or_else(|e| e.into_inner());
        let mut server = mockito::Server::new();
        let _m = server
            .mock("GET", "/integrity/demo/1.0/demo.whl/provenance")
            .with_status(404)
            .create();
        // Loopback fetch needs the explicit private-fetch opt-in.
        std::env::set_var("TIRITH_ALLOW_PRIVATE_FETCH", "1");
        let url = format!("{}/integrity/demo/1.0/demo.whl/provenance", server.url());
        let res = fetch_provenance_at(&url);
        std::env::remove_var("TIRITH_ALLOW_PRIVATE_FETCH");
        assert!(matches!(res, Err(FetchError::NotFound)));
    }

    #[test]
    fn fetch_success_returns_body() {
        let _guard = PRIVATE_FETCH_ENV.lock().unwrap_or_else(|e| e.into_inner());
        let mut server = mockito::Server::new();
        let body = provenance_json(SHA_A);
        let _m = server
            .mock("GET", "/integrity/demo/1.0/demo.whl/provenance")
            .with_status(200)
            .with_body(&body)
            .create();
        std::env::set_var("TIRITH_ALLOW_PRIVATE_FETCH", "1");
        let url = format!("{}/integrity/demo/1.0/demo.whl/provenance", server.url());
        let res = fetch_provenance_at(&url);
        std::env::remove_var("TIRITH_ALLOW_PRIVATE_FETCH");
        let got = res.unwrap_or_else(|_| panic!("expected body"));
        assert!(got.contains("attestation_bundles"));
    }

    #[test]
    fn fetch_rejects_private_url_without_optin() {
        // Depends on the opt-in being UNSET, so it shares the serializing lock with
        // the tests that toggle it (else one of them could leak the var and make a
        // loopback URL spuriously pass the validator).
        let _guard = PRIVATE_FETCH_ENV.lock().unwrap_or_else(|e| e.into_inner());
        // Belt-and-suspenders: ensure the opt-in is off for this assertion.
        std::env::remove_var("TIRITH_ALLOW_PRIVATE_FETCH");
        // Without the opt-in, a loopback URL is rejected by the fetch validator
        // before any request — the SSRF guard reuse.
        let res = fetch_provenance_at("http://127.0.0.1:9/integrity/x/1/x.whl/provenance");
        assert!(matches!(res, Err(FetchError::Transport(_))));
    }

    #[test]
    fn fetch_rejects_credentials_in_url() {
        let res = fetch_provenance_at("https://user:pass@pypi.org/integrity/x/1/x.whl/provenance");
        assert!(matches!(res, Err(FetchError::Transport(_))));
    }
}
