//! npm registry package identity and provenance FACTS (C13).
//!
//! What this module is: a pure, async-free type layer for what an npm packument
//! ACTUALLY SAYS about a release: the tarball URL, the `dist.integrity`
//! subresource-integrity digest, the legacy `dist.shasum`, the registry
//! signature list, and the provenance attestation pointer.
//!
//! What this module deliberately is NOT: a verifier. Three limits are real and
//! are the point of the slice rather than obstacles to it.
//!
//! 1. **No signature can reach `Verified` here.** npm signs
//!    `<name>@<version>:<integrity>` with ECDSA P-256. This workspace carries
//!    `ed25519-dalek` and no P-256 implementation, and adding a curve is a
//!    dependency decision outside this slice. [`NpmVerificationState`]
//!    therefore tops out at [`NpmVerificationState::PresentUnverified`] for a
//!    present signature.
//! 2. **No attestation can be verified here.** The `sigstore-attestations`
//!    feature is deliberately empty and off because the sigstore closure needs
//!    a newer Rust than the workspace MSRV.
//!    [`NpmVerificationState::VerificationUnavailable`] is the honest terminal
//!    state, mirroring
//!    [`crate::provenance::pypi_integrity::AttestationOutcome::VerificationUnavailable`].
//! 3. **SRI can only ever be a parsed fact.** `dist.integrity` covers the
//!    tarball bytes, and Tirith does not download npm tarballs. There is
//!    nothing local to hash it against, so no binding is attempted. That is
//!    what keeps the output from claiming it inspected or contained the bytes
//!    npm will install.
//!
//! Every state below is EVIDENCE, never an authorization. Present, well-formed
//! provenance must not suppress a behavioral, ThreatDB, typosquat, or lifecycle
//! finding: a signed package is still a package.

use serde::{Deserialize, Serialize};

/// The caveat every npm identity / provenance rendering must carry, stated
/// once so the human, JSON, and receipt paths cannot drift into implying
/// different things. Lives here, in the module that established the wording,
/// so the CLI renderings and [`crate::provenance::npm`]'s receipt all quote the
/// same sentence.
pub const NPM_BYTES_NOT_BOUND_CAVEAT: &str =
    "tirith has not downloaded, inspected, or bound the tarball bytes npm will install";

/// Longest `dist.integrity` string accepted. A real SRI for one tarball is well
/// under 200 bytes even with several algorithms; the cap keeps a hostile
/// packument from turning a display field into a memory cost.
const MAX_INTEGRITY_BYTES: usize = 512;
/// Longest tarball URL retained.
const MAX_TARBALL_URL_BYTES: usize = 2048;
/// Most signature entries retained from one release record.
const MAX_SIGNATURES: usize = 8;

/// How far verification of one provenance datum got.
///
/// Mirrors the five-state model already reviewed in
/// [`crate::provenance::pypi_integrity::AttestationOutcome`], collapsed to the
/// states this crate can honestly reach.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum NpmVerificationState {
    /// The registry published no such datum for this release. Absence of
    /// evidence, not a finding and not an allow. The default: an unset state
    /// must never read as any level of verification.
    #[default]
    Missing,
    /// The datum is present and structurally well-formed, but nothing here
    /// checked it cryptographically.
    PresentUnverified,
    /// The datum is present and names a subject (a `name@version:integrity`
    /// tuple, or an in-toto subject digest) that matches the release this
    /// metadata was requested for, so it is at least ABOUT the right release.
    /// Still not cryptographically verified.
    SubjectBoundUnverified,
    /// The datum is present but the cryptographic backend needed to check it is
    /// not compiled in. Explicitly not `Verified` and explicitly not an allow.
    VerificationUnavailable,
    /// Cryptographically verified and bound to the exact subject.
    ///
    /// No code path in this crate constructs this today, and the unit tests
    /// assert that. It exists so the wire format does not have to change when a
    /// verification backend lands, and so a consumer matching on the enum is
    /// already exhaustive.
    Verified,
}

impl NpmVerificationState {
    /// A short, stable label for receipts and human output. Never claims more
    /// than the state carries.
    pub fn label(self) -> &'static str {
        match self {
            NpmVerificationState::Missing => "missing",
            NpmVerificationState::PresentUnverified => "present-unverified",
            NpmVerificationState::SubjectBoundUnverified => "subject-bound-unverified",
            NpmVerificationState::VerificationUnavailable => "verification-unavailable",
            NpmVerificationState::Verified => "verified",
        }
    }

    /// Whether this state is positive, fully-verified evidence. Even `true`
    /// would not be an install authorization.
    pub fn is_verified(self) -> bool {
        matches!(self, NpmVerificationState::Verified)
    }
}

/// A parsed subresource-integrity digest from `dist.integrity`.
///
/// Parsed, not checked. `sha512-<base64>` is the shape npm publishes; the
/// digest is retained verbatim for display and for comparison against a
/// lockfile's `integrity` for the SAME resolved version, which is the one
/// comparison that can be made without downloading anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SriDigest {
    /// Lowercase algorithm name (`sha512`, `sha384`, `sha256`).
    pub algorithm: String,
    /// The base64 digest exactly as published.
    pub digest: String,
}

impl SriDigest {
    /// Parse one SRI entry. Returns `None` for an unknown algorithm, an empty
    /// digest, a non-base64 alphabet, or anything over the size cap. Refusing
    /// to coerce a malformed value is deliberate: a half-understood digest that
    /// later "matches" nothing is worse than an absent one.
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.is_empty() || value.len() > MAX_INTEGRITY_BYTES {
            return None;
        }
        // npm publishes a single entry, but the SRI grammar allows several
        // separated by whitespace. Take the first that parses so a trailing
        // unknown algorithm cannot erase a usable one.
        for entry in value.split_ascii_whitespace() {
            let (algorithm, digest) = entry.split_once('-')?;
            let algorithm = algorithm.to_ascii_lowercase();
            if !matches!(algorithm.as_str(), "sha256" | "sha384" | "sha512") {
                continue;
            }
            if digest.is_empty()
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
            {
                continue;
            }
            return Some(SriDigest {
                algorithm,
                digest: digest.to_string(),
            });
        }
        None
    }

    /// The canonical `algorithm-digest` spelling, for display and for equality
    /// against a lockfile value.
    pub fn canonical(&self) -> String {
        format!("{}-{}", self.algorithm, self.digest)
    }
}

/// Whether a lockfile's recorded integrity agrees with the registry's, for the
/// same resolved version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockfileIntegrityAgreement {
    /// The lockfile carries no `integrity` for this entry. Not a mismatch.
    NotPresent,
    /// Both sides carry an integrity value and they are identical.
    Agrees,
    /// Both sides carry an integrity value and they differ. The lockfile pins
    /// different bytes than the registry currently publishes for that version.
    Disagrees,
}

/// The provenance facts one npm release record carries.
///
/// Every field is what the registry SAID. `#[serde(default)]` throughout
/// because this type is embedded in the disk-cached
/// [`crate::registry_api::RegistryMetadata`]; a non-defaulted addition would
/// poison every existing cache entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmDistFacts {
    /// The tarball URL, retained ONLY when it validated against the same origin
    /// the packument came from. `None` means either absent or rejected; see
    /// [`Self::tarball_url_rejected`] for the difference.
    #[serde(default)]
    pub tarball_url: Option<String>,
    /// True when a tarball URL WAS published but failed origin/SSRF validation.
    /// Kept separate from `None` so a cross-origin tarball is visible as a
    /// finding-worthy fact rather than looking like an absent field.
    #[serde(default)]
    pub tarball_url_rejected: bool,
    /// Why the tarball URL was rejected, when it was. A short, non-secret
    /// reason.
    #[serde(default)]
    pub tarball_rejection_reason: Option<String>,
    /// The parsed `dist.integrity` SRI, when present and well-formed.
    #[serde(default)]
    pub integrity_sri: Option<SriDigest>,
    /// True when `dist.integrity` WAS published but did not parse (unknown
    /// algorithm, non-base64 digest, over the size cap). Kept separate from
    /// `integrity_sri: None` for the same reason as
    /// [`Self::tarball_url_rejected`]: "Tirith could not read it" and "the
    /// registry published none" are different facts, and reporting the first as
    /// the second understates what the publisher shipped.
    #[serde(default)]
    pub integrity_unparsed: bool,
    /// True when `dist.shasum` was present. npm's legacy SHA-1 field: display
    /// status only, never presented as integrity evidence.
    #[serde(default)]
    pub legacy_shasum_present: bool,
    /// Verification state of the registry signature list (`dist.signatures`).
    #[serde(default)]
    pub signature_state: NpmVerificationState,
    /// Key ids from `dist.signatures`, for display. Bounded.
    #[serde(default)]
    pub signature_key_ids: Vec<String>,
    /// Verification state of the provenance attestations (`dist.attestations`).
    #[serde(default)]
    pub attestation_state: NpmVerificationState,
    /// The registry origin (scheme + host + port) the packument was read from.
    #[serde(default)]
    pub registry_origin: Option<String>,
}

impl NpmDistFacts {
    /// True when the record carries nothing at all worth reporting.
    pub fn is_empty(&self) -> bool {
        self == &NpmDistFacts::default()
    }

    /// Compare a lockfile-recorded integrity string against the registry's, for
    /// a caller that has already confirmed both refer to the SAME resolved
    /// version. Comparing across versions would be meaningless.
    pub fn lockfile_agreement(
        &self,
        lockfile_integrity: Option<&str>,
    ) -> LockfileIntegrityAgreement {
        let Some(lock) = lockfile_integrity.and_then(SriDigest::parse) else {
            return LockfileIntegrityAgreement::NotPresent;
        };
        let Some(registry) = self.integrity_sri.as_ref() else {
            return LockfileIntegrityAgreement::NotPresent;
        };
        if lock.canonical() == registry.canonical() {
            LockfileIntegrityAgreement::Agrees
        } else {
            LockfileIntegrityAgreement::Disagrees
        }
    }

    /// A one-line human summary. Says what is present and, explicitly, that
    /// Tirith has not bound the bytes npm will install. The caveat is part of
    /// the fact, not decoration: without it the line reads as an integrity
    /// claim.
    pub fn summary(&self) -> String {
        let integrity = match &self.integrity_sri {
            Some(sri) => format!("integrity {} (parsed, not checked)", sri.algorithm),
            // Ordered ahead of the shasum and absent arms: an unreadable value
            // is the strongest claim of the three and must not be softened into
            // either of them.
            None if self.integrity_unparsed => {
                "integrity published but unreadable (not parsed)".to_string()
            }
            None if self.legacy_shasum_present => {
                "legacy shasum only (SHA-1, display status)".to_string()
            }
            None => "no integrity published".to_string(),
        };
        format!(
            "{integrity}; signature {}; provenance {}; tirith has not downloaded or bound the \
             tarball bytes npm will install",
            self.signature_state.label(),
            self.attestation_state.label()
        )
    }
}

/// Build the signature state from a release's `dist.signatures` list.
///
/// `entry_count` is how many signature entries the record carried; `key_ids` is
/// the subset that declared a `keyid`. Both are needed: a mirror or a hostile
/// packument can publish `[{"sig": "..."}]` with no key id, and deriving the
/// state from key ids alone would report a release that DOES carry a signature
/// as [`NpmVerificationState::Missing`], whose contract is "the registry
/// published no such datum". Present-without-an-id is still present.
///
/// Caps at [`NpmVerificationState::PresentUnverified`] on purpose: there is no
/// ECDSA P-256 backend in this workspace, so nothing here can check the
/// signature over `<name>@<version>:<integrity>`.
pub fn signature_state_from_entries(
    entry_count: usize,
    key_ids: &[String],
) -> (NpmVerificationState, Vec<String>) {
    if entry_count == 0 {
        return (NpmVerificationState::Missing, Vec::new());
    }
    let retained: Vec<String> = key_ids
        .iter()
        .filter(|id| !id.trim().is_empty())
        .take(MAX_SIGNATURES)
        .map(|id| id.trim().to_string())
        .collect();
    (NpmVerificationState::PresentUnverified, retained)
}

/// Build the attestation state from the presence of `dist.attestations`.
///
/// A present attestation pointer resolves to
/// [`NpmVerificationState::VerificationUnavailable`], never `PresentUnverified`
/// and never `Verified`: the Sigstore bundle behind the pointer is not fetched
/// (fetching it would mean following a host the packument named) and could not
/// be verified if it were.
pub fn attestation_state_from_presence(present: bool) -> NpmVerificationState {
    if present {
        NpmVerificationState::VerificationUnavailable
    } else {
        NpmVerificationState::Missing
    }
}

/// Truncate a tarball URL to the retention cap, returning `None` if it exceeds
/// it. A URL that long is not a display value.
pub fn accept_tarball_url(url: &str) -> Option<String> {
    let url = url.trim();
    if url.is_empty() || url.len() > MAX_TARBALL_URL_BYTES {
        return None;
    }
    Some(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sri_parses_the_shapes_npm_publishes_and_refuses_the_rest() {
        let sri = SriDigest::parse("sha512-abc+/DEF123==").expect("well-formed sha512 SRI");
        assert_eq!(sri.algorithm, "sha512");
        assert_eq!(sri.canonical(), "sha512-abc+/DEF123==");

        assert!(
            SriDigest::parse("SHA256-abcdef").is_some(),
            "case-insensitive algorithm"
        );
        assert!(
            SriDigest::parse("md5-abcdef").is_none(),
            "unknown algorithm"
        );
        assert!(SriDigest::parse("sha512-").is_none(), "empty digest");
        assert!(SriDigest::parse("sha512").is_none(), "no separator");
        assert!(SriDigest::parse("").is_none());
        assert!(
            SriDigest::parse(&format!("sha512-{}", "a".repeat(600))).is_none(),
            "over the size cap"
        );
        // A leading unknown algorithm must not erase the usable entry.
        let multi = SriDigest::parse("md5-zzz sha512-abcdef").expect("second entry parses");
        assert_eq!(multi.algorithm, "sha512");
    }

    #[test]
    fn no_constructor_in_this_crate_can_produce_verified() {
        let (state, ids) = signature_state_from_entries(1, &["SHA256:abc".to_string()]);
        assert_eq!(state, NpmVerificationState::PresentUnverified);
        assert!(!state.is_verified());
        assert_eq!(ids, vec!["SHA256:abc"]);

        assert_eq!(
            signature_state_from_entries(0, &[]).0,
            NpmVerificationState::Missing
        );

        assert_eq!(
            attestation_state_from_presence(true),
            NpmVerificationState::VerificationUnavailable
        );
        assert_eq!(
            attestation_state_from_presence(false),
            NpmVerificationState::Missing
        );
    }

    #[test]
    fn every_verification_state_renders_a_distinct_label() {
        let states = [
            NpmVerificationState::Missing,
            NpmVerificationState::PresentUnverified,
            NpmVerificationState::SubjectBoundUnverified,
            NpmVerificationState::VerificationUnavailable,
            NpmVerificationState::Verified,
        ];
        let labels: Vec<&str> = states.iter().map(|state| state.label()).collect();
        assert_eq!(
            labels,
            vec![
                "missing",
                "present-unverified",
                "subject-bound-unverified",
                "verification-unavailable",
                "verified",
            ]
        );
        // Only the constructed `Verified` value reports itself verified, and no
        // registry parse path can produce it.
        assert_eq!(states.iter().filter(|state| state.is_verified()).count(), 1);
    }

    #[test]
    fn signature_key_ids_are_bounded() {
        let many: Vec<String> = (0..64).map(|index| format!("key{index}")).collect();
        let (state, ids) = signature_state_from_entries(many.len(), &many);
        assert_eq!(state, NpmVerificationState::PresentUnverified);
        assert_eq!(ids.len(), MAX_SIGNATURES);
        assert_eq!(ids[0], "key0");
    }

    /// A signature entry that declares no usable key id is still a signature.
    /// Reporting it as `Missing` would state that the registry published none,
    /// which is the opposite of what the packument said.
    #[test]
    fn a_signature_with_no_key_id_is_present_not_missing() {
        for key_ids in [vec![], vec!["   ".to_string()]] {
            let (state, ids) = signature_state_from_entries(1, &key_ids);
            assert_eq!(
                state,
                NpmVerificationState::PresentUnverified,
                "one entry, key ids {key_ids:?}"
            );
            assert!(ids.is_empty(), "a blank key id is not retained for display");
        }
    }

    /// `dist.integrity` that Tirith refuses to parse is not `dist.integrity`
    /// that the publisher omitted.
    #[test]
    fn an_unreadable_integrity_is_not_reported_as_an_absent_one() {
        let unreadable = NpmDistFacts {
            integrity_unparsed: true,
            ..NpmDistFacts::default()
        };
        let summary = unreadable.summary();
        assert!(summary.contains("published but unreadable"), "{summary}");
        assert!(!summary.contains("no integrity published"), "{summary}");

        // The unreadable fact outranks the legacy shasum fallback.
        let with_legacy = NpmDistFacts {
            integrity_unparsed: true,
            legacy_shasum_present: true,
            ..NpmDistFacts::default()
        };
        assert!(with_legacy.summary().contains("published but unreadable"));

        assert!(NpmDistFacts::default()
            .summary()
            .contains("no integrity published"));
    }

    #[test]
    fn lockfile_agreement_separates_absent_from_mismatched() {
        let facts = NpmDistFacts {
            integrity_sri: SriDigest::parse("sha512-aaa"),
            ..NpmDistFacts::default()
        };
        assert_eq!(
            facts.lockfile_agreement(None),
            LockfileIntegrityAgreement::NotPresent
        );
        assert_eq!(
            facts.lockfile_agreement(Some("sha512-aaa")),
            LockfileIntegrityAgreement::Agrees
        );
        assert_eq!(
            facts.lockfile_agreement(Some("sha512-bbb")),
            LockfileIntegrityAgreement::Disagrees
        );
        // No registry integrity means there is nothing to disagree with.
        assert_eq!(
            NpmDistFacts::default().lockfile_agreement(Some("sha512-bbb")),
            LockfileIntegrityAgreement::NotPresent
        );
    }

    #[test]
    fn the_summary_always_says_the_bytes_were_not_bound() {
        let facts = NpmDistFacts {
            integrity_sri: SriDigest::parse("sha512-aaa"),
            signature_state: NpmVerificationState::PresentUnverified,
            attestation_state: NpmVerificationState::VerificationUnavailable,
            ..NpmDistFacts::default()
        };
        let summary = facts.summary();
        assert!(summary.contains("parsed, not checked"), "{summary}");
        assert!(
            summary.contains("has not downloaded or bound the tarball bytes"),
            "{summary}"
        );
        // "present-unverified" and "verification-unavailable" both contain the
        // substring, so assert on the exact claims a reader could act on.
        assert!(
            !summary.contains("signature verified") && !summary.contains("provenance verified"),
            "{summary}"
        );

        let legacy = NpmDistFacts {
            legacy_shasum_present: true,
            ..NpmDistFacts::default()
        };
        assert!(legacy.summary().contains("legacy shasum only"));
    }

    #[test]
    fn oversized_tarball_urls_are_not_retained() {
        assert_eq!(
            accept_tarball_url("https://registry.example/pkg/-/pkg-1.0.0.tgz").as_deref(),
            Some("https://registry.example/pkg/-/pkg-1.0.0.tgz")
        );
        assert!(accept_tarball_url("").is_none());
        assert!(accept_tarball_url(&format!("https://x/{}", "a".repeat(4096))).is_none());
    }
}
