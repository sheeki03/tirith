//! PyPI attestation provenance: the portable, async-free TYPES and the
//! subject-digest BINDING (PR F3, the `sigstore-attestations` spike).
//!
//! Per the plan's crate split, `tirith-core` holds ONLY the provenance types and
//! the subject-digest binding here; the PyPI Integrity API fetch, the Sigstore
//! cryptographic verification, and the `tuf`/network trust root live in the
//! `tirith` CLI crate (`cli::pypi_integrity`), because they pull `tokio` and the
//! `sigstore-*` closure, which this crate must not. This module is the pure half:
//! it never touches the network, never runs a policy that blocks, and emits no new
//! [`crate::verdict::RuleId`].
//!
//! # Provenance evidence, never an auto-allow
//!
//! The cross-cutting contract for F3 is blunt: a present, cryptographically valid
//! attestation whose subject digest matches the quarantined artifact AND whose
//! publisher identity satisfies policy is POSITIVE provenance evidence. Its
//! ABSENCE, its invalidity, a subject-digest MISMATCH, or a publisher that fails
//! the policy allowlist is NEGATIVE evidence — but it is still only EVIDENCE. It
//! is never, on its own, a reason to install (there is nothing to auto-allow:
//! tirith already inspects the bytes and the firewall already has the verdict).
//! [`AttestationOutcome`] encodes exactly this: every non-`Verified` variant is a
//! finding a human reviews, not a gate that opens. Nothing in this module returns
//! "allow".
//!
//! # The binding is the load-bearing step
//!
//! An attestation only means something if it is bound to the bytes you are about
//! to install. PyPI's Integrity API serves a publish attestation whose Sigstore
//! bundle's in-toto statement names a SUBJECT digest. [`bind_subject_digest`]
//! compares that subject digest against the SHA-256 of the content-addressed
//! quarantine blob (the exact bytes the firewall hashed and the installer will
//! install), using a length-checked, case-insensitive, constant-time-ish hex
//! comparison so a swapped artifact with a stale attestation is caught. Without
//! this binding, a valid signature over SOME other file would be meaningless.
//!
//! # Publisher identity policy
//!
//! A valid attestation also carries WHO published it (a Trusted Publisher identity:
//! a source repository and the CI workflow that ran the publish). F3 checks that
//! identity against an operator-supplied allowlist
//! ([`PublisherPolicy`]): an unexpected repository or workflow is a
//! [`AttestationOutcome::PublisherNotAllowed`]. An EMPTY allowlist means "no
//! publisher constraint configured", which records the observed identity as
//! evidence without rejecting it (it does NOT silently allow an install — there is
//! no install decision here).

use serde::{Deserialize, Serialize};

/// The publisher identity an attestation asserts: the source repository and the CI
/// workflow that produced the signed publish, plus the certificate's signer
/// identity (the OIDC subject / SAN). All fields are descriptive strings copied
/// from the verified certificate; none is a secret. Used both to RECORD what the
/// attestation claimed and to CHECK it against [`PublisherPolicy`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublisherIdentity {
    /// The source repository the publish ran from, in `owner/repo` form when
    /// derivable from the certificate (e.g. `pypa/sampleproject`). `None` when the
    /// attestation does not assert one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// The CI workflow reference that performed the publish (e.g. a GitHub Actions
    /// `.github/workflows/release.yml` ref). `None` when not asserted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    /// The signer identity from the signing certificate (the OIDC SAN / subject,
    /// e.g. a workflow identity URI). `None` when not asserted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_identity: Option<String>,
}

impl PublisherIdentity {
    /// Whether this identity carries no asserted fields at all (an attestation that
    /// named no publisher). Such an identity cannot satisfy a non-empty policy.
    pub fn is_empty(&self) -> bool {
        self.repository.is_none() && self.workflow.is_none() && self.signer_identity.is_none()
    }
}

/// The operator's allowlist for which publishers may produce a "verified"
/// attestation outcome. A presence-aware constraint: an EMPTY policy imposes no
/// publisher requirement (the identity is recorded as evidence, not rejected),
/// while a NON-EMPTY field requires the attestation's corresponding identity field
/// to match one of the listed values exactly (case-sensitive; these are
/// repository / workflow references, not hostnames).
///
/// This is the policy projection F3 consults; it is built by the CLI from the
/// operator policy and is never repo-scoped-weakenable (it can only TIGHTEN — add
/// required publishers — so a repo cannot relax it; see the CLI wiring).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublisherPolicy {
    /// Allowed source repositories (`owner/repo`). Empty = no repository
    /// constraint.
    #[serde(default)]
    pub allowed_repositories: Vec<String>,
    /// Allowed CI workflow references. Empty = no workflow constraint.
    #[serde(default)]
    pub allowed_workflows: Vec<String>,
    /// Allowed signer identities (OIDC SAN / subject). Empty = no signer
    /// constraint.
    #[serde(default)]
    pub allowed_signer_identities: Vec<String>,
}

impl PublisherPolicy {
    /// Whether the policy imposes no publisher constraint at all (every allowlist
    /// is empty). When true, any verified identity satisfies it (recorded, not
    /// rejected).
    pub fn is_unconstrained(&self) -> bool {
        self.allowed_repositories.is_empty()
            && self.allowed_workflows.is_empty()
            && self.allowed_signer_identities.is_empty()
    }

    /// Check a verified publisher identity against this policy. Returns `Ok(())`
    /// when every CONFIGURED (non-empty) constraint is satisfied by the identity,
    /// or `Err(reason)` naming the first constraint that failed. An unconstrained
    /// policy always returns `Ok(())`. A constraint that is configured but whose
    /// identity field is absent fails (an attestation that omits the repository
    /// cannot satisfy a repository allowlist).
    pub fn check(&self, identity: &PublisherIdentity) -> Result<(), String> {
        if !self.allowed_repositories.is_empty() {
            match &identity.repository {
                Some(repo) if self.allowed_repositories.iter().any(|a| a == repo) => {}
                Some(repo) => {
                    return Err(format!(
                        "attestation repository '{repo}' is not in the allowed publisher \
                         repositories ({})",
                        self.allowed_repositories.join(", ")
                    ));
                }
                None => {
                    return Err(
                        "attestation asserts no source repository, but the policy requires one of: "
                            .to_string()
                            + &self.allowed_repositories.join(", "),
                    );
                }
            }
        }
        if !self.allowed_workflows.is_empty() {
            match &identity.workflow {
                Some(wf) if self.allowed_workflows.iter().any(|a| a == wf) => {}
                Some(wf) => {
                    return Err(format!(
                        "attestation workflow '{wf}' is not in the allowed publisher workflows ({})",
                        self.allowed_workflows.join(", ")
                    ));
                }
                None => {
                    return Err(
                        "attestation asserts no CI workflow, but the policy requires one of: "
                            .to_string()
                            + &self.allowed_workflows.join(", "),
                    );
                }
            }
        }
        if !self.allowed_signer_identities.is_empty() {
            match &identity.signer_identity {
                Some(sid) if self.allowed_signer_identities.iter().any(|a| a == sid) => {}
                Some(sid) => {
                    return Err(format!(
                        "attestation signer identity '{sid}' is not in the allowed signer \
                         identities ({})",
                        self.allowed_signer_identities.join(", ")
                    ));
                }
                None => {
                    return Err(
                        "attestation asserts no signer identity, but the policy requires one of: "
                            .to_string()
                            + &self.allowed_signer_identities.join(", "),
                    );
                }
            }
        }
        Ok(())
    }
}

/// The outcome of evaluating a PyPI attestation for one quarantined artifact. Every
/// variant is PROVENANCE EVIDENCE: `Verified` is positive evidence, every other
/// variant is negative or absent evidence. NONE of them is an install decision —
/// the contract is "never an auto-allow", and there is correspondingly no "allow"
/// or "block" variant here. The CLI renders the outcome and the firewall may fold
/// it in as context, but the install verdict comes from the byte inspection, not
/// from this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum AttestationOutcome {
    /// A present attestation whose Sigstore bundle verified, whose in-toto subject
    /// digest BOUND to the quarantined artifact's SHA-256, and whose publisher
    /// identity satisfied policy. The strongest positive evidence F3 produces.
    Verified {
        /// The publisher identity the verified attestation asserted.
        identity: PublisherIdentity,
        /// The bound subject digest (lowercase hex SHA-256), echoed for the
        /// receipt / graph.
        subject_sha256: String,
    },
    /// No attestation was available for this artifact (the Integrity API returned
    /// none, or attestations are not published for this release). Absence of
    /// evidence, NOT an allow and NOT a block.
    Missing {
        /// A short, non-secret reason (e.g. "no provenance in the Integrity API
        /// response").
        reason: String,
    },
    /// An attestation was present but its Sigstore bundle FAILED verification
    /// (signature, certificate chain, transparency log, or trust-root check did not
    /// pass). Negative evidence.
    Invalid {
        /// A short, non-secret reason for the verification failure.
        reason: String,
    },
    /// An attestation verified, but its in-toto subject digest did NOT bind to the
    /// quarantined artifact's SHA-256: the signature is over DIFFERENT bytes than
    /// the ones about to be installed. The most security-relevant negative variant
    /// (a stale-attestation / artifact-swap tell).
    SubjectMismatch {
        /// The subject digest the attestation asserted (lowercase hex).
        attested_sha256: String,
        /// The quarantined artifact's actual SHA-256 (lowercase hex).
        artifact_sha256: String,
    },
    /// An attestation verified and bound, but its publisher identity did not satisfy
    /// the operator's publisher allowlist. Negative evidence.
    PublisherNotAllowed {
        /// The publisher identity the attestation asserted.
        identity: PublisherIdentity,
        /// Why it failed the policy (which constraint).
        reason: String,
    },
    /// Attestation verification could not run because the cryptographic backend is
    /// not compiled in (the `sigstore-attestations` feature is off, which is the
    /// default on the workspace MSRV — the `sigstore-*` closure requires a newer
    /// Rust). The attestation, if any, was fetched but not verified. This is
    /// explicitly NOT `Verified` and NOT an allow: with no verification, F3 has no
    /// positive evidence, so it degrades to "unavailable", never to "trusted".
    VerificationUnavailable {
        /// A short, non-secret reason.
        reason: String,
    },
}

impl AttestationOutcome {
    /// Whether this outcome is the positive, fully-verified-and-bound case. The ONLY
    /// variant that is positive provenance evidence; every other is absent or
    /// negative. Even this `true` is NOT an install authorization — it is evidence
    /// a reviewer / receipt records.
    pub fn is_verified(&self) -> bool {
        matches!(self, AttestationOutcome::Verified { .. })
    }

    /// A short, stable label for the outcome (for receipts, the graph, the human
    /// summary). Never includes a digest or reason; those live in the variant
    /// fields.
    pub fn label(&self) -> &'static str {
        match self {
            AttestationOutcome::Verified { .. } => "verified",
            AttestationOutcome::Missing { .. } => "missing",
            AttestationOutcome::Invalid { .. } => "invalid",
            AttestationOutcome::SubjectMismatch { .. } => "subject-mismatch",
            AttestationOutcome::PublisherNotAllowed { .. } => "publisher-not-allowed",
            AttestationOutcome::VerificationUnavailable { .. } => "verification-unavailable",
        }
    }
}

/// Bind a verified attestation's in-toto SUBJECT digest to a quarantined artifact's
/// SHA-256. This is the load-bearing F3 step: it confirms the signature is over the
/// EXACT bytes tirith quarantined and will install, not some other file.
///
/// Both inputs are SHA-256 hex strings. The comparison is:
///
/// * length-checked: each must be a 64-char lowercase-or-uppercase hex string (a
///   SHA-256), else the binding cannot be trusted and returns
///   [`SubjectBinding::Malformed`];
/// * case-insensitive (an attestation may upper- or lower-case its hex);
/// * constant-time over the normalized lowercase bytes, so a near-miss digest does
///   not leak position through timing.
///
/// Returns whether the digests bind. The caller maps a non-bind to
/// [`AttestationOutcome::SubjectMismatch`].
pub fn bind_subject_digest(attested_sha256: &str, artifact_sha256: &str) -> SubjectBinding {
    let attested = match normalize_sha256_hex(attested_sha256) {
        Some(v) => v,
        None => return SubjectBinding::Malformed,
    };
    let artifact = match normalize_sha256_hex(artifact_sha256) {
        Some(v) => v,
        None => return SubjectBinding::Malformed,
    };
    if constant_time_eq(attested.as_bytes(), artifact.as_bytes()) {
        SubjectBinding::Bound
    } else {
        SubjectBinding::Mismatch
    }
}

/// The result of [`bind_subject_digest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectBinding {
    /// The attested subject digest equals the artifact's SHA-256: the attestation
    /// covers these exact bytes.
    Bound,
    /// Both digests are well-formed SHA-256 hex strings but differ: the attestation
    /// is over different bytes (an artifact swap / stale attestation).
    Mismatch,
    /// One or both inputs is not a 64-char hex SHA-256 string: the binding cannot
    /// be evaluated, so it must be treated as no-bind (never silently "bound").
    Malformed,
}

/// Normalize a candidate SHA-256 hex string to lowercase, returning `None` unless
/// it is exactly 64 hex digits. Rejecting any other shape is deliberate: a
/// truncated, prefixed (`sha256:`), or non-hex value must not be coerced into a
/// "match".
fn normalize_sha256_hex(s: &str) -> Option<String> {
    let t = s.trim();
    if t.len() != 64 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(t.to_ascii_lowercase())
}

/// A length-checked constant-time byte equality. Equal length is required by the
/// callers (both are normalized 64-char digests), but the function still guards
/// against unequal lengths by returning `false` without an early branch on
/// content. Avoids leaking the first differing position through timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Resolve the full [`AttestationOutcome`] from the pieces the CLI gathers: a
/// VERIFIED attestation's asserted subject digest + publisher identity, the
/// quarantined artifact's SHA-256, and the operator's publisher policy. This is the
/// pure decision seam — given a verified bundle, it performs the subject BINDING
/// and the publisher POLICY check in the security-correct order (bind first, since
/// a signature over the wrong bytes is the more serious failure) and returns the
/// outcome. The CLI calls this ONLY after Sigstore verification has succeeded; an
/// unverified or absent attestation is mapped by the CLI to [`AttestationOutcome::Invalid`]
/// / [`AttestationOutcome::Missing`] / [`AttestationOutcome::VerificationUnavailable`]
/// directly, never through here.
pub fn evaluate_verified_attestation(
    attested_subject_sha256: &str,
    identity: &PublisherIdentity,
    artifact_sha256: &str,
    policy: &PublisherPolicy,
) -> AttestationOutcome {
    // 1. Bind the subject digest to the quarantined bytes FIRST. A valid signature
    //    over a different file is worse than a publisher mismatch, so it is checked
    //    before policy and short-circuits.
    match bind_subject_digest(attested_subject_sha256, artifact_sha256) {
        SubjectBinding::Bound => {}
        SubjectBinding::Mismatch | SubjectBinding::Malformed => {
            return AttestationOutcome::SubjectMismatch {
                attested_sha256: attested_subject_sha256.trim().to_ascii_lowercase(),
                artifact_sha256: artifact_sha256.trim().to_ascii_lowercase(),
            };
        }
    }

    // 2. Publisher policy. An unconstrained policy records the identity as evidence
    //    without rejecting; a constrained one must be satisfied.
    if let Err(reason) = policy.check(identity) {
        return AttestationOutcome::PublisherNotAllowed {
            identity: identity.clone(),
            reason,
        };
    }

    AttestationOutcome::Verified {
        identity: identity.clone(),
        subject_sha256: artifact_sha256.trim().to_ascii_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn binding_matches_case_insensitively() {
        assert_eq!(bind_subject_digest(A, A), SubjectBinding::Bound);
        let upper = A.to_ascii_uppercase();
        assert_eq!(bind_subject_digest(&upper, A), SubjectBinding::Bound);
        assert_eq!(bind_subject_digest(A, &upper), SubjectBinding::Bound);
    }

    #[test]
    fn binding_mismatch_on_different_digest() {
        assert_eq!(bind_subject_digest(A, B), SubjectBinding::Mismatch);
    }

    #[test]
    fn binding_malformed_rejects_short_prefixed_or_nonhex() {
        // Too short.
        assert_eq!(bind_subject_digest("abc", A), SubjectBinding::Malformed);
        // A `sha256:` prefix is not a bare hex digest.
        let prefixed = format!("sha256:{}", &A[7..]);
        assert_eq!(
            bind_subject_digest(&prefixed, A),
            SubjectBinding::Malformed
        );
        // Non-hex character in an otherwise 64-char string.
        let nonhex = "z".repeat(64);
        assert_eq!(bind_subject_digest(&nonhex, A), SubjectBinding::Malformed);
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abcd", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abce"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn unconstrained_policy_accepts_any_identity() {
        let policy = PublisherPolicy::default();
        assert!(policy.is_unconstrained());
        let id = PublisherIdentity {
            repository: Some("pypa/sampleproject".into()),
            workflow: Some("release.yml".into()),
            signer_identity: None,
        };
        assert!(policy.check(&id).is_ok());
        // Even an empty identity passes an unconstrained policy.
        assert!(policy.check(&PublisherIdentity::default()).is_ok());
    }

    #[test]
    fn constrained_policy_requires_matching_repository() {
        let policy = PublisherPolicy {
            allowed_repositories: vec!["pypa/sampleproject".into()],
            ..Default::default()
        };
        // Match.
        let ok = PublisherIdentity {
            repository: Some("pypa/sampleproject".into()),
            ..Default::default()
        };
        assert!(policy.check(&ok).is_ok());
        // Wrong repo.
        let wrong = PublisherIdentity {
            repository: Some("attacker/evil".into()),
            ..Default::default()
        };
        assert!(policy.check(&wrong).is_err());
        // Missing repo cannot satisfy a repo constraint.
        assert!(policy.check(&PublisherIdentity::default()).is_err());
    }

    #[test]
    fn constrained_policy_checks_workflow_and_signer() {
        let policy = PublisherPolicy {
            allowed_workflows: vec!["release.yml".into()],
            allowed_signer_identities: vec!["https://github.com/pypa/sampleproject/.github/workflows/release.yml@refs/tags/v1".into()],
            ..Default::default()
        };
        let id = PublisherIdentity {
            repository: Some("pypa/sampleproject".into()),
            workflow: Some("release.yml".into()),
            signer_identity: Some("https://github.com/pypa/sampleproject/.github/workflows/release.yml@refs/tags/v1".into()),
        };
        assert!(policy.check(&id).is_ok());
        // A bad workflow fails even with a good signer.
        let bad_wf = PublisherIdentity {
            workflow: Some("attack.yml".into()),
            ..id.clone()
        };
        assert!(policy.check(&bad_wf).is_err());
    }

    #[test]
    fn evaluate_binds_before_policy() {
        // A subject-digest mismatch wins over a publisher mismatch: bind is checked
        // first because a signature over the wrong bytes is the more serious failure.
        let policy = PublisherPolicy {
            allowed_repositories: vec!["pypa/sampleproject".into()],
            ..Default::default()
        };
        let wrong_publisher = PublisherIdentity {
            repository: Some("attacker/evil".into()),
            ..Default::default()
        };
        // attested != artifact AND publisher is wrong -> SubjectMismatch, not
        // PublisherNotAllowed.
        let out = evaluate_verified_attestation(A, &wrong_publisher, B, &policy);
        assert!(matches!(out, AttestationOutcome::SubjectMismatch { .. }));
        assert_eq!(out.label(), "subject-mismatch");
        assert!(!out.is_verified());
    }

    #[test]
    fn evaluate_publisher_not_allowed_when_bound_but_wrong_repo() {
        let policy = PublisherPolicy {
            allowed_repositories: vec!["pypa/sampleproject".into()],
            ..Default::default()
        };
        let wrong_publisher = PublisherIdentity {
            repository: Some("attacker/evil".into()),
            ..Default::default()
        };
        // Bound (A == A) but the publisher is not allowed.
        let out = evaluate_verified_attestation(A, &wrong_publisher, A, &policy);
        match out {
            AttestationOutcome::PublisherNotAllowed { identity, .. } => {
                assert_eq!(identity.repository.as_deref(), Some("attacker/evil"));
            }
            other => panic!("expected PublisherNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_verified_when_bound_and_unconstrained() {
        let policy = PublisherPolicy::default();
        let id = PublisherIdentity {
            repository: Some("pypa/sampleproject".into()),
            workflow: Some("release.yml".into()),
            signer_identity: None,
        };
        let out = evaluate_verified_attestation(A, &id, A, &policy);
        assert!(out.is_verified());
        match out {
            AttestationOutcome::Verified {
                identity,
                subject_sha256,
            } => {
                assert_eq!(identity, id);
                assert_eq!(subject_sha256, A);
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_verified_when_bound_and_publisher_matches() {
        let policy = PublisherPolicy {
            allowed_repositories: vec!["pypa/sampleproject".into()],
            allowed_workflows: vec!["release.yml".into()],
            ..Default::default()
        };
        let id = PublisherIdentity {
            repository: Some("pypa/sampleproject".into()),
            workflow: Some("release.yml".into()),
            signer_identity: None,
        };
        let out = evaluate_verified_attestation(A, &id, A, &policy);
        assert!(out.is_verified());
    }

    #[test]
    fn outcome_serde_roundtrips_and_carries_no_secret() {
        let out = AttestationOutcome::SubjectMismatch {
            attested_sha256: A.into(),
            artifact_sha256: B.into(),
        };
        let json = serde_json::to_string(&out).unwrap();
        // Tagged on `outcome`, snake_case.
        assert!(json.contains("\"outcome\":\"subject_mismatch\""));
        let back: AttestationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, out);
    }

    #[test]
    fn missing_invalid_unavailable_are_not_verified() {
        for out in [
            AttestationOutcome::Missing {
                reason: "none".into(),
            },
            AttestationOutcome::Invalid {
                reason: "bad sig".into(),
            },
            AttestationOutcome::VerificationUnavailable {
                reason: "feature off".into(),
            },
        ] {
            assert!(!out.is_verified(), "{} must not be verified", out.label());
        }
    }
}
