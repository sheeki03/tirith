//! A hardened, streaming, wheel-only ZIP reader (PR A4).
//!
//! This is the one place in tirith that opens a HOSTILE archive. A malicious
//! wheel is attacker-controlled bytes, so the reader treats every field as
//! adversarial: it streams each member through `decompressor -> real byte budget
//! -> SHA-256 -> bounded analyzer`, never trusts a declared (header) size, never
//! follows a member path out of the archive, and never recurses into a nested
//! archive.
//!
//! # Two outcome classes (the central distinction)
//!
//! Not every limitation is an attack. The reader separates them deliberately
//! ([`ArchiveOutcome`]):
//!
//! * A **hard structural violation** ([`ArchiveViolation`]) means the archive is
//!   malformed or hostile in a way no honest packaging tool produces (a `..`
//!   member, a path collision, an encrypted member, a CRC failure, conflicting
//!   `.dist-info` roots, a wheel-name/METADATA identity mismatch). The wheel is
//!   [`ArchiveOutcome::Rejected`]. The reader still continues best-effort to
//!   populate a `partial` [`ArtifactInspection`] for evidence, but the caller MUST
//!   treat a `Rejected` wheel as not-clean, never as a partial success.
//! * A **coverage limit** ([`crate::scan::CoverageGap`]) means the reader chose
//!   not to fully analyze something for resource safety (a member over the
//!   per-member cap, the total-byte budget reached, the entry-count budget
//!   reached, an undecodable compression method, a native member too large to
//!   buffer). The wheel is still [`ArchiveOutcome::Accepted`]; the gap records
//!   what was not covered so downstream coverage logic (A2's `AnalysisIncomplete`)
//!   can surface it. A coverage limit is NOT a rejection.
//!
//! Conflating the two is the bug this module exists to avoid: a zip bomb is a
//! coverage limit (we stop reading, accept, and gap it), but a traversal member
//! is a structural violation (we reject). Mixing them would either reject honest
//! large wheels or accept hostile ones.
//!
//! # Why streaming from `Read + Seek`, not a byte slice
//!
//! [`read_wheel`] takes a `Read + Seek` handle, so the CLI can pass a no-follow
//! [`std::fs::File`] WITHOUT first reading the whole (possibly multi-gigabyte)
//! artifact into memory; tests pass a [`std::io::Cursor`]. Each member is then
//! streamed, and the per-member / total / ratio budgets are enforced on the bytes
//! ACTUALLY read from the decompressor, because the declared uncompressed size in
//! the ZIP header is attacker-controlled and is never trusted as a limit.
//!
//! # Native member handoff (the contract B7 consumes)
//!
//! A native member (`.so`/`.dylib`/`.pyd`/`.node`) is where B7's deep triage runs.
//! A4 only does the PLUMBING: for a member within [`ArchiveLimits::max_member_uncompressed`]
//! it decompresses into a bounded in-memory buffer (a [`NativeMemberHandoff::Buffered`])
//! so B7 gets full random access to section/symbol/import tables; for a larger
//! member it produces a [`NativeMemberHandoff::Streaming`] view (whole-member
//! SHA-256 plus a printable-string scan) and records a [`crate::scan::CoverageGapKind::NativeTruncated`]
//! gap. The handoffs are surfaced to a [`MemberVisitor`]; B7 implements the actual
//! parsing.

use std::collections::BTreeMap;
use std::io::{Read, Seek};

use sha2::{Digest, Sha256};

use crate::artifact::{
    ArtifactFile, ArtifactFileKind, ArtifactIdentity, ArtifactInspection, GenericArchiveIdentity,
    InspectionSubject,
};
use crate::location::SubjectLocation;
use crate::scan::{CoverageGap, CoverageGapKind};
use crate::threatdb::Ecosystem;

/// Resource budgets for archive inspection. The defaults are from the plan;
/// every limit is enforced on REAL streamed bytes (never a declared header size),
/// so an attacker cannot lie in the central directory to bypass them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveLimits {
    /// Maximum number of members the reader will enumerate. Beyond this, the rest
    /// are left uninspected with a [`CoverageGapKind::EntryCountCapped`] gap (an
    /// archive with millions of tiny entries must not exhaust us).
    pub max_entries: usize,
    /// Maximum TOTAL uncompressed bytes streamed across all members before the
    /// reader stops decompressing further members (a [`CoverageGapKind::TotalBytesCapped`]
    /// gap). Independent of any single member's size.
    pub max_total_uncompressed: u64,
    /// Maximum uncompressed bytes for a SINGLE member to be analyzed. A larger
    /// member is not decompressed for content analysis (a [`CoverageGapKind::MemberTooLarge`]
    /// gap); a whole-member hash may still be taken if within the hash budget.
    pub max_member_uncompressed: u64,
    /// Maximum allowed ratio of a member's REAL streamed uncompressed bytes to its
    /// compressed size. A member whose decompression blows past this (a zip bomb)
    /// is abandoned mid-stream with a [`CoverageGapKind::CompressionRatioExceeded`]
    /// gap.
    pub max_compression_ratio: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            max_total_uncompressed: 512 * 1024 * 1024,
            max_member_uncompressed: 64 * 1024 * 1024,
            max_compression_ratio: 200,
        }
    }
}

/// The header window (2 MiB) that B7's FALLBACK magic/architecture classifier may
/// read when a native member is too large for a full buffer. This is ONLY for the
/// fallback classifier, never the principal parser; the principal parser always
/// gets the full bounded buffer ([`NativeMemberHandoff::Buffered`]) when the
/// member is within [`ArchiveLimits::max_member_uncompressed`].
pub const NATIVE_HEADER_WINDOW_BYTES: u64 = 2 * 1024 * 1024;

/// A HARD structural violation: the archive is malformed or hostile in a way an
/// honest packaging tool never produces. Any of these makes the wheel
/// [`ArchiveOutcome::Rejected`]. These are DATA, not findings: B8 / `evaluate_artifact`
/// map a violation set to user-facing findings later; A4 introduces no RuleId.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveViolation {
    /// A member path is absolute, contains a `..` traversal segment, or is not
    /// valid UTF-8 (anything [`zip::read::ZipFile::enclosed_name`] fail-closes,
    /// plus an explicit raw `..`-segment check so a path that NORMALIZES away a
    /// `..` is still caught).
    PathTraversal {
        /// The offending member name as stored in the archive (raw, debug-escaped
        /// by the caller for display).
        member: String,
    },
    /// A member path uses a backslash separator, a drive letter (`C:`), or a UNC
    /// prefix. Checked host-OS-INDEPENDENTLY on the raw name, because on a Unix
    /// host `enclosed_name` parses `C:\evil` as one harmless component.
    WindowsPathTraversal {
        /// The offending member name.
        member: String,
    },
    /// Two members normalize to the same target path under the platform's path
    /// semantics (a plain duplicate, a case-fold collision on a case-insensitive
    /// target, or a Unicode-normalization collision), so one would silently
    /// overwrite the other on extraction.
    DuplicatePath {
        /// The normalized path both members share.
        normalized: String,
        /// The first raw member name seen for this normalized path.
        first: String,
        /// The second raw member name that collided.
        second: String,
    },
    /// A member is encrypted, so its bytes cannot be inspected at all (a wheel is
    /// never legitimately encrypted).
    EncryptedMember {
        /// The encrypted member's name.
        member: String,
    },
    /// A member's decompressed bytes failed their stored CRC-32 (corruption or
    /// tampering after the central directory was written).
    CrcMismatch {
        /// The member whose CRC did not validate.
        member: String,
    },
    /// A member is a symbolic link. A wheel must not carry symlinks; one is a
    /// vector for redirecting a later read/extract out of the tree.
    SymlinkMember {
        /// The symlink member's name.
        member: String,
        /// The link target as recorded (best-effort), for evidence.
        target: String,
    },
    /// More than one conflicting `.dist-info` directory root, so the wheel has no
    /// single authoritative metadata identity.
    ConflictingDistInfo {
        /// The distinct `.dist-info` root directory names found.
        roots: Vec<String>,
    },
    /// The wheel filename's name/version disagrees with the `.dist-info`
    /// directory name/version or the METADATA `Name:`/`Version:` headers, so the
    /// archive lies about what it is.
    IdentityMismatch {
        /// A human-readable description of the disagreement.
        detail: String,
    },
    /// The archive could not be opened or a member's central-directory entry could
    /// not be read (a malformed ZIP). A structural fault: the bytes are not a
    /// well-formed archive.
    MalformedArchive {
        /// A short reason (the underlying zip error message).
        detail: String,
    },
}

/// The outcome of inspecting one archive. Either it passed every structural check
/// (and is [`Accepted`] with an inspection that may still carry coverage gaps), or
/// at least one HARD structural violation was found (and it is [`Rejected`], with
/// the violations plus a best-effort partial inspection for evidence).
///
/// [`Accepted`]: ArchiveOutcome::Accepted
/// [`Rejected`]: ArchiveOutcome::Rejected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveOutcome {
    /// The archive is structurally sound. The inspection's `coverage.gaps` may
    /// still list coverage LIMITS (oversized members, capped budgets); those are
    /// not rejections.
    Accepted(ArtifactInspection),
    /// The archive violated at least one hard structural rule. `partial` is a
    /// best-effort inspection populated for evidence; the caller MUST NOT treat it
    /// as a clean inspection.
    Rejected {
        /// Every structural violation found (the reader continues after the first
        /// so the report is complete).
        violations: Vec<ArchiveViolation>,
        /// Best-effort inspection populated while scanning, for evidence only.
        partial: ArtifactInspection,
    },
}

impl ArchiveOutcome {
    /// Whether the archive was rejected for a structural violation.
    pub fn is_rejected(&self) -> bool {
        matches!(self, ArchiveOutcome::Rejected { .. })
    }
}

/// How a NATIVE member's bytes are handed to B7's triage. A4 produces the
/// handoff; B7 consumes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeMemberHandoff {
    /// The member fit within [`ArchiveLimits::max_member_uncompressed`], so its
    /// whole decompressed body is buffered in memory for B7's random-access
    /// parser (section/symbol/import tables, TLS/init data).
    Buffered {
        /// The member location (`outer.whl!/member`).
        location: SubjectLocation,
        /// The whole decompressed member.
        bytes: Vec<u8>,
        /// The member's SHA-256 (lowercase hex) over `bytes`.
        sha256: String,
    },
    /// The member exceeded the native-parse cap, so only a streaming view is
    /// provided: the whole-member SHA-256, a bounded printable-string scan, and
    /// the leading header window for B7's fallback magic/arch classifier. The deep
    /// parse is truncated (a [`CoverageGapKind::NativeTruncated`] gap is recorded).
    Streaming {
        /// The member location.
        location: SubjectLocation,
        /// The member's SHA-256 (lowercase hex) over the full streamed body.
        sha256: String,
        /// The member's uncompressed size in bytes (streamed, not declared).
        size: u64,
        /// The leading [`NATIVE_HEADER_WINDOW_BYTES`] (or fewer) bytes for the
        /// fallback magic/architecture classifier ONLY.
        header_window: Vec<u8>,
        /// Bounded printable ASCII runs (length >= 4) found while streaming, for a
        /// best-effort string scan without buffering the whole member.
        printable_strings: Vec<String>,
    },
}

impl NativeMemberHandoff {
    /// The member location, regardless of handoff class.
    pub fn location(&self) -> &SubjectLocation {
        match self {
            NativeMemberHandoff::Buffered { location, .. } => location,
            NativeMemberHandoff::Streaming { location, .. } => location,
        }
    }
}

/// A sink the reader calls as it streams members, so a caller (B7) can consume
/// native handoffs without the reader knowing how the bytes are parsed. The
/// default no-op impl lets A4's own tests and a metadata-only caller ignore them.
pub trait MemberVisitor {
    /// Called once per native member with its handoff (buffered or streaming).
    fn on_native_member(&mut self, _handoff: NativeMemberHandoff) {}
}

/// A visitor that records every native handoff, for tests and for a caller that
/// wants to collect them. The reader still owns budget enforcement; this only
/// captures what was handed over.
#[derive(Debug, Default)]
pub struct CollectingVisitor {
    /// Every native handoff the reader produced, in member order.
    pub native: Vec<NativeMemberHandoff>,
}

impl MemberVisitor for CollectingVisitor {
    fn on_native_member(&mut self, handoff: NativeMemberHandoff) {
        self.native.push(handoff);
    }
}

/// Owned metadata for one member, read from the central directory via
/// `by_index_raw` (which never decompresses, so it is safe even for an encrypted
/// or undecodable member). Collected up front so the structural checks can run
/// before any content is streamed, and so we hold no live borrow of the archive
/// while iterating.
struct MemberMeta {
    /// Index in the archive, for re-opening to stream content.
    index: usize,
    /// The raw member name exactly as stored.
    raw_name: String,
    /// `enclosed_name` (relative, no `..`, no NUL) when the member is a safe path;
    /// `None` when it is absolute / has `..` / is non-UTF-8.
    enclosed: Option<String>,
    /// Whether the member is a directory entry.
    is_dir: bool,
    /// Whether the member is a symlink (unix mode S_IFLNK).
    is_symlink: bool,
    /// Whether the member is encrypted.
    encrypted: bool,
    /// The compression method as stored.
    compression: zip::CompressionMethod,
    /// The declared (attacker-controlled, NOT trusted as a budget) uncompressed
    /// size, used only as a hint for native-member buffering decisions before we
    /// know the real streamed size.
    declared_size: u64,
    /// The declared compressed size, for the compression-ratio guard's denominator.
    compressed_size: u64,
}

/// Inspect a wheel (or generic zip) from a `Read + Seek` handle, streaming each
/// member under [`ArchiveLimits`] and separating hard structural violations from
/// coverage limits. `outer_name` is the artifact's on-disk filename (for member
/// locations and the wheel-identity check); `outer_sha256` is the whole-archive
/// SHA-256 the CALLER computed from the same bytes (the reader does not re-read
/// the outer file). `visitor` receives native-member handoffs for B7.
///
/// Returns [`ArchiveOutcome::Rejected`] if ANY structural violation is found
/// (with a best-effort partial inspection), else [`ArchiveOutcome::Accepted`].
pub fn read_wheel<R: Read + Seek>(
    reader: R,
    outer_name: &str,
    outer_sha256: &str,
    limits: &ArchiveLimits,
    visitor: &mut dyn MemberVisitor,
) -> ArchiveOutcome {
    let mut archive = match zip::ZipArchive::new(reader) {
        Ok(a) => a,
        Err(e) => {
            // A non-archive (or truncated/corrupt) input is a structural fault: it
            // is not a well-formed archive at all. Reject with an empty partial.
            let subject = generic_subject(outer_name, outer_sha256);
            return ArchiveOutcome::Rejected {
                violations: vec![ArchiveViolation::MalformedArchive {
                    detail: e.to_string(),
                }],
                partial: ArtifactInspection::new(subject),
            };
        }
    };

    let mut violations: Vec<ArchiveViolation> = Vec::new();

    // ---- Pass 1: collect member metadata (no decompression) -------------------
    // `by_index_raw` returns a Raw reader (no CRC, no decode), so reading metadata
    // never trips an encrypted/undecodable member. We own the metadata so no live
    // borrow of `archive` survives into the content pass.
    let total_entries = archive.len();
    let mut metas: Vec<MemberMeta> = Vec::new();
    let mut entry_count_capped = false;
    for index in 0..total_entries {
        if metas.len() >= limits.max_entries {
            // Entry-count budget reached: the rest are a coverage limit, not a
            // violation. Record one gap below; stop collecting.
            entry_count_capped = true;
            break;
        }
        let file = match archive.by_index_raw(index) {
            Ok(f) => f,
            Err(e) => {
                // A member whose central-directory entry will not parse is a
                // malformed archive (structural).
                violations.push(ArchiveViolation::MalformedArchive {
                    detail: format!("member {index}: {e}"),
                });
                continue;
            }
        };
        let raw_name = file.name().to_string();
        let enclosed = file
            .enclosed_name()
            .map(|p| p.to_string_lossy().replace('\\', "/"));
        metas.push(MemberMeta {
            index,
            raw_name,
            enclosed,
            is_dir: file.is_dir(),
            is_symlink: file.is_symlink(),
            encrypted: file.encrypted(),
            compression: file.compression(),
            declared_size: file.size(),
            compressed_size: file.compressed_size(),
        });
    }

    // ---- Structural checks over the collected metadata ------------------------
    check_member_paths(&metas, &mut violations);
    check_path_collisions(&metas, &mut violations);
    check_dist_info_roots(&metas, &mut violations);

    // ---- Pass 2: stream member content under the budgets ----------------------
    let mut inspection = ArtifactInspection::new(generic_subject(outer_name, outer_sha256));
    inspection.coverage.members_total = total_entries;
    if entry_count_capped {
        inspection.coverage.gaps.push(CoverageGap {
            location: SubjectLocation::from_path(outer_name),
            kind: CoverageGapKind::EntryCountCapped,
            sha256: None,
        });
    }

    let mut total_uncompressed: u64 = 0;
    let mut total_budget_hit = false;
    // Collected dist-info identity (name/version) for the wheel-identity check.
    let mut metadata_identity: Option<(String, Option<String>)> = None;

    for meta in &metas {
        if meta.is_dir {
            // A directory entry carries no bytes; count it as "inspected" (there is
            // nothing to analyze) but produce no file/gap.
            inspection.coverage.members_inspected += 1;
            continue;
        }
        // An encrypted or symlink member is a HARD structural violation: record it
        // and never attempt to stream its bytes (we would not decrypt, and a
        // symlink member must never be followed).
        if meta.encrypted {
            violations.push(ArchiveViolation::EncryptedMember {
                member: meta.raw_name.clone(),
            });
            inspection.coverage.members_inspected += 1;
            continue;
        }
        if meta.is_symlink {
            // Best-effort: read the (short) link target bytes for evidence via the
            // raw reader, capped hard.
            let target = read_symlink_target(&mut archive, meta.index);
            violations.push(ArchiveViolation::SymlinkMember {
                member: meta.raw_name.clone(),
                target,
            });
            inspection.coverage.members_inspected += 1;
            continue;
        }

        // The location for this member uses the SAFE (enclosed) name when we have
        // one, else the raw name; either way the structural checks have flagged an
        // unsafe path already, so this is for evidence/labeling only.
        let member_label = meta
            .enclosed
            .clone()
            .unwrap_or_else(|| meta.raw_name.clone());
        let location = SubjectLocation::member(outer_name, member_label.clone());

        // Undecodable compression: only deflate/store are enabled. Record a
        // coverage gap (NOT a violation) and skip content; we still counted it.
        if !is_supported_compression(meta.compression) {
            inspection.coverage.gaps.push(CoverageGap {
                location,
                kind: CoverageGapKind::UnsupportedCompression,
                sha256: None,
            });
            continue;
        }

        // Whatever of the total-uncompressed budget remains. Recomputed each
        // member from the running total, which now ONLY ever grows (every arm
        // below debits the bytes it consumed), so a member can never read more
        // than this no matter how an earlier member finished.
        let remaining_total = limits
            .max_total_uncompressed
            .saturating_sub(total_uncompressed);

        // Per-member size cap: do not buffer a member larger than the cap for
        // full content analysis. We use the DECLARED size only as a fast pre-check
        // here; the REAL byte budget is still enforced byte-by-byte in
        // `stream_member` below, so a member that lies small but streams huge is
        // still aborted. A native member over the cap still gets a STREAMING view
        // (whole-member hash + header window + printable strings) for B7, plus a
        // `NativeTruncated` gap noting the deep parse was truncated. The streaming
        // view is bounded by `remaining_total`, and the bytes it reads are debited,
        // so an oversized native member cannot bypass the total budget either.
        if meta.declared_size > limits.max_member_uncompressed {
            let file_kind = classify_member(&member_label);
            if file_kind == ArtifactFileKind::NativeModule {
                let (handoff, consumed) =
                    stream_native_view(&mut archive, meta.index, location.clone(), remaining_total);
                total_uncompressed = total_uncompressed.saturating_add(consumed);
                if total_uncompressed >= limits.max_total_uncompressed {
                    total_budget_hit = true;
                }
                if let Some(handoff) = handoff {
                    visitor.on_native_member(handoff);
                }
                inspection.coverage.gaps.push(CoverageGap {
                    location: location.clone(),
                    kind: CoverageGapKind::NativeTruncated,
                    sha256: None,
                });
            }
            inspection.coverage.gaps.push(CoverageGap {
                location,
                kind: CoverageGapKind::MemberTooLarge,
                sha256: None,
            });
            continue;
        }

        // Total-uncompressed budget reached: stop decompressing further members.
        if total_budget_hit {
            inspection.coverage.gaps.push(CoverageGap {
                location,
                kind: CoverageGapKind::TotalBytesCapped,
                sha256: None,
            });
            continue;
        }

        // Stream the member: decompress -> real byte budget + ratio guard ->
        // SHA-256. The two byte bounds (the per-member cap and whatever remains of
        // the total budget) are passed separately so the gap kind names the BINDING
        // constraint, and the compression-ratio guard runs against the compressed
        // size. CRC is validated by the zip reader as the stream completes.
        let stream = stream_member(
            &mut archive,
            meta.index,
            limits.max_member_uncompressed,
            remaining_total,
            meta.compressed_size,
            limits.max_compression_ratio,
        );

        // EVERY arm debits the REAL bytes the member forced (`consumed`) against
        // the shared total budget and flips `total_budget_hit` once it is reached,
        // so neither a completed member, a ratio bomb, a CRC failure, an I/O error,
        // nor a budget abort can leave the total under-counted. The Complete arm's
        // `consumed` equals `bytes.len()`.
        match stream {
            MemberStream::Complete {
                bytes,
                sha256,
                consumed,
            } => {
                total_uncompressed = total_uncompressed.saturating_add(consumed);
                if total_uncompressed >= limits.max_total_uncompressed {
                    total_budget_hit = true;
                }
                let kind = classify_member(&member_label);
                inspection.files.push(ArtifactFile {
                    location: location.clone(),
                    size: bytes.len() as u64,
                    sha256: sha256.clone(),
                    kind,
                });
                inspection.coverage.members_inspected += 1;

                // Capture dist-info METADATA for the identity check.
                if metadata_identity.is_none() {
                    if let Some(id) = parse_metadata_identity(&member_label, &bytes) {
                        metadata_identity = Some(id);
                    }
                }

                // Native member: hand the buffered bytes to B7.
                if kind == ArtifactFileKind::NativeModule {
                    visitor.on_native_member(NativeMemberHandoff::Buffered {
                        location,
                        bytes,
                        sha256,
                    });
                }
            }
            MemberStream::CrcFailed { consumed } => {
                total_uncompressed = total_uncompressed.saturating_add(consumed);
                if total_uncompressed >= limits.max_total_uncompressed {
                    total_budget_hit = true;
                }
                violations.push(ArchiveViolation::CrcMismatch {
                    member: meta.raw_name.clone(),
                });
                inspection.coverage.members_inspected += 1;
            }
            MemberStream::RatioExceeded { consumed } => {
                total_uncompressed = total_uncompressed.saturating_add(consumed);
                if total_uncompressed >= limits.max_total_uncompressed {
                    total_budget_hit = true;
                }
                inspection.coverage.gaps.push(CoverageGap {
                    location,
                    kind: CoverageGapKind::CompressionRatioExceeded,
                    sha256: None,
                });
                // Count it as inspected-with-a-gap; the consumed bytes were debited
                // above so the abort cannot reset the total budget.
            }
            MemberStream::BudgetExceeded { kind, consumed } => {
                total_uncompressed = total_uncompressed.saturating_add(consumed);
                // We hit either the per-member cap or the remaining-total budget
                // mid-stream. For a native member we still want to give B7 a
                // streaming view rather than nothing, bounded by what budget is
                // left after debiting the bytes we just consumed.
                let file_kind = classify_member(&member_label);
                if file_kind == ArtifactFileKind::NativeModule {
                    let left = limits
                        .max_total_uncompressed
                        .saturating_sub(total_uncompressed);
                    let (handoff, view_consumed) =
                        stream_native_view(&mut archive, meta.index, location.clone(), left);
                    total_uncompressed = total_uncompressed.saturating_add(view_consumed);
                    if let Some(h) = handoff {
                        visitor.on_native_member(h);
                    }
                    // NativeTruncated UNCONDITIONALLY, matching the declared-oversized
                    // path: a native member reaching this arm was truncated whether or not
                    // a streaming handoff was produced (handoff is None when the total
                    // budget is already exhausted). A B8 consumer enumerating
                    // NativeTruncated gaps must see EVERY under-analyzed native module.
                    inspection.coverage.gaps.push(CoverageGap {
                        location: location.clone(),
                        kind: CoverageGapKind::NativeTruncated,
                        sha256: None,
                    });
                }
                if total_uncompressed >= limits.max_total_uncompressed {
                    total_budget_hit = true;
                }
                inspection.coverage.gaps.push(CoverageGap {
                    location,
                    kind,
                    sha256: None,
                });
                if kind == CoverageGapKind::TotalBytesCapped {
                    total_budget_hit = true;
                }
            }
            MemberStream::IoError { consumed } => {
                total_uncompressed = total_uncompressed.saturating_add(consumed);
                if total_uncompressed >= limits.max_total_uncompressed {
                    total_budget_hit = true;
                }
                inspection.coverage.gaps.push(CoverageGap {
                    location,
                    kind: CoverageGapKind::Unreadable,
                    sha256: None,
                });
                inspection.coverage.members_inspected += 1;
            }
        }
    }

    // ---- Identity: wheel filename vs dist-info dir vs METADATA ----------------
    if let Some(detail) = check_wheel_identity(outer_name, &metas, metadata_identity.as_ref()) {
        violations.push(ArchiveViolation::IdentityMismatch { detail });
    }

    // ---- Pick the subject and decide the outcome ------------------------------
    inspection.subject = decide_subject(outer_name, outer_sha256, &metas);

    if violations.is_empty() {
        ArchiveOutcome::Accepted(inspection)
    } else {
        ArchiveOutcome::Rejected {
            violations,
            partial: inspection,
        }
    }
}

/// Inspect a wheel from a `Read + Seek` handle with the default [`ArchiveLimits`]
/// and a no-op visitor (for a metadata-only caller that does not consume native
/// handoffs). A thin convenience over [`read_wheel`].
pub fn read_wheel_default<R: Read + Seek>(
    reader: R,
    outer_name: &str,
    outer_sha256: &str,
) -> ArchiveOutcome {
    struct NoopVisitor;
    impl MemberVisitor for NoopVisitor {}
    read_wheel(
        reader,
        outer_name,
        outer_sha256,
        &ArchiveLimits::default(),
        &mut NoopVisitor,
    )
}

/// Whether the on-disk name is a wheel filename. A wheel is `*.whl`; an sdist
/// `*.tar.gz` or anything else is NOT a wheel and is reported as `Unsupported`
/// by the caller (a hardened tar/gzip reader is a separate later design).
pub fn is_wheel_filename(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".whl")
}

/// The structural check for traversal / Windows-path members. `enclosed_name`
/// fail-closes absolute / `..` / non-UTF-8 paths, so a `None` enclosed name is a
/// traversal violation; we ALSO scan the raw name for backslash / drive-letter /
/// UNC (host-OS-independent, because on Unix `enclosed_name` treats `C:\x` as one
/// safe component) and for a literal `..` segment that normalization might erase.
fn check_member_paths(metas: &[MemberMeta], violations: &mut Vec<ArchiveViolation>) {
    for meta in metas {
        // Windows-style traversal is checked on the RAW name regardless of host OS.
        if has_windows_path(&meta.raw_name) {
            violations.push(ArchiveViolation::WindowsPathTraversal {
                member: meta.raw_name.clone(),
            });
        }
        // Absolute / `..` / non-UTF-8: `enclosed_name` returns None, OR the raw
        // name still contains a `..` path segment (one that normalized away).
        if meta.enclosed.is_none() || has_dotdot_segment(&meta.raw_name) {
            violations.push(ArchiveViolation::PathTraversal {
                member: meta.raw_name.clone(),
            });
        }
    }
}

/// Detect a path collision: two members whose normalized targets are equal under
/// the platform's path semantics. We normalize for BOTH a case-sensitive and a
/// case-insensitive target, and additionally apply Unicode NFC, so a case-fold or
/// Unicode-normalization collision (one member would overwrite the other on
/// extraction) is caught. Only members with a safe (enclosed) name participate;
/// an unsafe member is already a traversal violation.
fn check_path_collisions(metas: &[MemberMeta], violations: &mut Vec<ArchiveViolation>) {
    use unicode_normalization::UnicodeNormalization;
    // normalized key -> (index, raw name) of the FIRST member seen for that key.
    // We key the "already seen" decision on the member INDEX, not the raw name, so
    // two SEPARATE members with a byte-identical path are still flagged (an exact
    // duplicate is the strongest collision, and a name-equality guard would wrongly
    // suppress it).
    let mut seen: BTreeMap<String, (usize, String)> = BTreeMap::new();
    for meta in metas {
        if meta.is_dir {
            continue;
        }
        let Some(enclosed) = &meta.enclosed else {
            continue;
        };
        // Case-fold AND Unicode-normalize for the collision key: this catches a
        // plain duplicate, a case-only difference (relevant on a case-insensitive
        // target like macOS/Windows), and a Unicode-normalization difference.
        let key: String = enclosed.nfc().collect::<String>().to_lowercase();
        if let Some((first_index, first_name)) = seen.get(&key) {
            // A DIFFERENT member (different index) collided on this normalized path.
            if *first_index != meta.index {
                violations.push(ArchiveViolation::DuplicatePath {
                    normalized: key.clone(),
                    first: first_name.clone(),
                    second: meta.raw_name.clone(),
                });
            }
        } else {
            seen.insert(key, (meta.index, meta.raw_name.clone()));
        }
    }
}

/// Detect multiple conflicting `.dist-info` roots. A valid wheel has exactly one
/// `<name>-<version>.dist-info/` top-level directory; two distinct ones mean the
/// wheel has no single authoritative metadata identity.
fn check_dist_info_roots(metas: &[MemberMeta], violations: &mut Vec<ArchiveViolation>) {
    let mut roots: Vec<String> = Vec::new();
    for meta in metas {
        let name = meta.enclosed.as_deref().unwrap_or(&meta.raw_name);
        if let Some(root) = dist_info_root(name) {
            if !roots.iter().any(|r| r == &root) {
                roots.push(root);
            }
        }
    }
    if roots.len() > 1 {
        roots.sort();
        violations.push(ArchiveViolation::ConflictingDistInfo { roots });
    }
}

/// The `<name>-<version>.dist-info` top-level directory of a member path, if it is
/// inside one. `pkg-1.0.dist-info/METADATA` -> `Some("pkg-1.0.dist-info")`.
fn dist_info_root(member: &str) -> Option<String> {
    let first = member.split('/').next()?;
    if first.ends_with(".dist-info") {
        Some(first.to_string())
    } else {
        None
    }
}

/// Check the wheel-identity invariant: the wheel filename's distribution name /
/// version must agree (after PEP 503 normalization) with the `.dist-info`
/// directory name and with the METADATA `Name:`/`Version:` headers. Returns a
/// description of the FIRST disagreement, or `None` if consistent (or if a piece
/// is missing, in which case there is nothing to contradict).
fn check_wheel_identity(
    outer_name: &str,
    metas: &[MemberMeta],
    metadata_identity: Option<&(String, Option<String>)>,
) -> Option<String> {
    let wheel = parse_wheel_filename(outer_name)?;

    // dist-info directory identity, if present.
    let dist_info = metas.iter().find_map(|m| {
        let name = m.enclosed.as_deref().unwrap_or(&m.raw_name);
        dist_info_root(name).and_then(|root| parse_dist_info_dir(&root))
    });

    if let Some((di_name, di_version)) = &dist_info {
        if normalize_project_name(di_name) != normalize_project_name(&wheel.name) {
            return Some(format!(
                "wheel filename name '{}' disagrees with .dist-info directory name '{}'",
                wheel.name, di_name
            ));
        }
        if normalize_version(di_version) != normalize_version(&wheel.version) {
            return Some(format!(
                "wheel filename version '{}' disagrees with .dist-info directory version '{}'",
                wheel.version, di_version
            ));
        }
    }

    if let Some((md_name, md_version)) = metadata_identity {
        if normalize_project_name(md_name) != normalize_project_name(&wheel.name) {
            return Some(format!(
                "wheel filename name '{}' disagrees with METADATA Name '{}'",
                wheel.name, md_name
            ));
        }
        if let Some(md_version) = md_version {
            if normalize_version(md_version) != normalize_version(&wheel.version) {
                return Some(format!(
                    "wheel filename version '{}' disagrees with METADATA Version '{}'",
                    wheel.version, md_version
                ));
            }
        }
    }

    None
}

/// A parsed wheel filename: `name-version-...tags....whl`. Per PEP 427 the first
/// two `-`-separated fields are the distribution name and version (the name's own
/// internal separators are normalized to `_`, so we compare via PEP 503).
struct WheelName {
    name: String,
    version: String,
}

/// Parse `name-version-[build-]pyver-abi-platform.whl` into name + version.
/// Returns `None` for a non-wheel name or one without at least name+version.
fn parse_wheel_filename(filename: &str) -> Option<WheelName> {
    let stem = filename.strip_suffix(".whl").or_else(|| {
        // Case-insensitive `.whl`.
        if filename.to_ascii_lowercase().ends_with(".whl") {
            Some(&filename[..filename.len() - 4])
        } else {
            None
        }
    })?;
    let parts: Vec<&str> = stem.split('-').collect();
    // A wheel has at least name-version-pyver-abi-platform (5 fields), but be
    // lenient: require at least name + version.
    if parts.len() < 2 {
        return None;
    }
    Some(WheelName {
        name: parts[0].to_string(),
        version: parts[1].to_string(),
    })
}

/// Parse a `<name>-<version>.dist-info` directory name into name + version.
fn parse_dist_info_dir(root: &str) -> Option<(String, String)> {
    let stem = root.strip_suffix(".dist-info")?;
    // The LAST `-` splits name from version (a version never contains `-`, but a
    // name can after `_`-normalization; splitting on the last `-` is the wheel
    // convention).
    let idx = stem.rfind('-')?;
    let (name, version) = stem.split_at(idx);
    let version = &version[1..]; // drop the '-'
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// PEP 503 name normalization: lowercase and collapse any run of `-`, `_`, or `.`
/// into a single `-`. So `Foo.Bar_baz` and `foo-bar-baz` compare equal.
fn normalize_project_name(name: &str) -> String {
    let lowered = name.to_ascii_lowercase();
    let mut out = String::with_capacity(lowered.len());
    let mut prev_sep = false;
    for ch in lowered.chars() {
        if matches!(ch, '-' | '_' | '.') {
            if !prev_sep {
                out.push('-');
                prev_sep = true;
            }
        } else {
            out.push(ch);
            prev_sep = false;
        }
    }
    out.trim_matches('-').to_string()
}

/// Normalize a version for comparison: lowercase, trim, and (because wheel
/// filenames replace `-`/`+`/`!` and other version separators) compare loosely by
/// stripping a leading `v` and normalizing internal `_` to `.` is intentionally
/// NOT done; a wheel filename uses the version verbatim except `-` is illegal in a
/// version, so a simple lowercase trim suffices for the mismatch check.
fn normalize_version(version: &str) -> String {
    version.trim().to_ascii_lowercase()
}

/// Whether a compression method is one this build can decode (only deflate/store
/// are enabled). Anything else cannot be inspected and becomes a coverage gap.
fn is_supported_compression(method: zip::CompressionMethod) -> bool {
    matches!(
        method,
        zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
    )
}

/// Whether a raw member name uses a backslash separator, a drive-letter prefix
/// (`C:`), or a UNC prefix (`\\` or `//` lead). Checked host-OS-independently.
fn has_windows_path(name: &str) -> bool {
    if name.contains('\\') {
        return true;
    }
    // Drive letter like `C:` or `c:` as the first two chars followed by a sep or
    // end. Also any `:` is suspicious in a member path (a wheel member never has
    // a colon), so flag a drive-letter-shaped prefix.
    let bytes = name.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return true;
    }
    // A UNC path like `\\server\share` is already caught by the backslash check
    // above. A leading `//` is also not a valid relative member path (a wheel
    // member is always relative), so reject it too.
    if name.starts_with("//") {
        return true;
    }
    false
}

/// Whether a raw member name contains a `..` PATH SEGMENT (between separators, or
/// at either end), independent of normalization. `a/../b` and `..` both match;
/// `a..b` (a `..` inside a name) does not.
fn has_dotdot_segment(name: &str) -> bool {
    name.split(['/', '\\']).any(|seg| seg == "..")
}

/// Classify an archive member path into the coarse [`ArtifactFileKind`] B5 to B8
/// correlate over. Mirrors the kinds the A3 model defines; a `.pth` is its OWN
/// kind, never a binary blob.
fn classify_member(member: &str) -> ArtifactFileKind {
    let lower = member.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);

    // dist-info / egg-info metadata.
    if member.contains(".dist-info/") || member.contains(".egg-info/") {
        return ArtifactFileKind::DistInfoMetadata;
    }
    if base.ends_with(".pth") {
        return ArtifactFileKind::PthFile;
    }
    if base.ends_with(".start") {
        return ArtifactFileKind::StartFile;
    }
    if base == "sitecustomize.py" || base == "usercustomize.py" {
        return ArtifactFileKind::SiteCustomize;
    }
    if base.ends_with(".so")
        || base.ends_with(".dylib")
        || base.ends_with(".pyd")
        || base.ends_with(".node")
    {
        return ArtifactFileKind::NativeModule;
    }
    if base.ends_with(".wasm") {
        return ArtifactFileKind::WasmModule;
    }
    if base.ends_with(".py") {
        return ArtifactFileKind::PythonSource;
    }
    if base.ends_with(".sh")
        || base.ends_with(".bash")
        || base.ends_with(".ps1")
        || base.ends_with(".bat")
        || base.ends_with(".cmd")
    {
        return ArtifactFileKind::Script;
    }
    ArtifactFileKind::Other
}

/// The result of streaming one member's bytes under the budgets. EVERY variant
/// reports `consumed`: the REAL uncompressed bytes the decompressor produced for
/// this member before the stream finished or was aborted. The caller debits
/// `consumed` against the shared total-uncompressed budget in EVERY arm, so an
/// aborted member (ratio bomb, budget hit, CRC failure, I/O error) still counts
/// the work it forced, and the total budget can never be bypassed by aborting.
enum MemberStream {
    /// The whole member was read within budget; its bytes and SHA-256. `consumed`
    /// equals `bytes.len()`.
    Complete {
        bytes: Vec<u8>,
        sha256: String,
        consumed: u64,
    },
    /// The member's CRC-32 did not validate (corruption / tampering). `consumed`
    /// is the bytes decompressed before the failing final read.
    CrcFailed { consumed: u64 },
    /// The member's real streamed bytes blew past the compression-ratio limit.
    /// `consumed` is the bytes read up to and including the chunk that tripped it.
    RatioExceeded { consumed: u64 },
    /// A byte budget (per-member cap or remaining total) was hit mid-stream; the
    /// gap kind to record. `consumed` is the bytes read up to the abort.
    BudgetExceeded {
        kind: CoverageGapKind,
        consumed: u64,
    },
    /// A non-CRC I/O error occurred while reading. `consumed` is the bytes read
    /// before the error.
    IoError { consumed: u64 },
}

/// Stream one member's decompressed bytes, enforcing BOTH the per-member byte cap
/// (`member_cap`) and the remaining-total budget (`remaining_total`), plus the
/// compression ratio against `compressed_size`, and detecting a CRC failure (the
/// zip reader validates CRC as the stream completes). Reads in bounded 64 KiB
/// chunks so memory stays bounded regardless of the DECLARED size, and aborts the
/// moment a bound or the ratio is exceeded (never buffering past the limit). When
/// a byte bound is hit, the reported gap kind names the BINDING constraint
/// (`MemberTooLarge` when the per-member cap bound first, else `TotalBytesCapped`).
fn stream_member<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    index: usize,
    member_cap: u64,
    remaining_total: u64,
    compressed_size: u64,
    max_ratio: u64,
) -> MemberStream {
    let mut file = match archive.by_index(index) {
        Ok(f) => f,
        Err(e) => {
            // An UnsupportedArchive here would mean an undecodable method slipped
            // past the pre-check; treat any open error as I/O. Nothing was read.
            let _ = e;
            return MemberStream::IoError { consumed: 0 };
        }
    };

    let mut hasher = Sha256::new();
    let mut bytes: Vec<u8> = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    // The ratio guard's threshold: real bytes may not exceed compressed * ratio.
    // A stored (uncompressed) member has compressed == uncompressed, so guard with
    // at least 1 to avoid a zero threshold on an empty member.
    let ratio_limit = compressed_size.max(1).saturating_mul(max_ratio.max(1));
    // The binding byte bound and the gap kind that names it.
    let (byte_bound, bound_kind) = if member_cap <= remaining_total {
        (member_cap, CoverageGapKind::MemberTooLarge)
    } else {
        (remaining_total, CoverageGapKind::TotalBytesCapped)
    };

    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                // The zip reader surfaces a CRC mismatch as an InvalidData error
                // while finalizing the member; classify any InvalidData raised
                // here as a CRC failure (the decompression completed and the
                // checksum did not validate), independent of the exact message.
                if e.kind() == std::io::ErrorKind::InvalidData {
                    return MemberStream::CrcFailed { consumed: total };
                }
                return MemberStream::IoError { consumed: total };
            }
        };
        total = total.saturating_add(n as u64);
        // Compression-ratio guard on REAL bytes (the declared size is not trusted).
        if total > ratio_limit {
            return MemberStream::RatioExceeded { consumed: total };
        }
        if total > byte_bound {
            return MemberStream::BudgetExceeded {
                kind: bound_kind,
                consumed: total,
            };
        }
        hasher.update(&buf[..n]);
        bytes.extend_from_slice(&buf[..n]);
    }

    let digest = hasher.finalize();
    let sha256: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    MemberStream::Complete {
        bytes,
        sha256,
        consumed: total,
    }
}

/// Produce a [`NativeMemberHandoff::Streaming`] view for a native member too large
/// to buffer: stream the whole member for its SHA-256, keep the leading header
/// window and a bounded set of printable strings, but never buffer the whole body.
/// A streaming view exists PRECISELY for a member larger than the per-member
/// analysis cap, so it is NOT bounded by `max_member_uncompressed`.
///
/// Returns the streaming view (or `None` on an open/read failure or a member that
/// blows the budget) ALONG WITH the REAL bytes this call consumed, so the caller
/// debits them against the shared total-uncompressed budget. The streamed bytes
/// are bounded by `remaining_budget`: the caller passes the total budget LEFT (not
/// the full total budget), so N oversized native members can never each read the
/// whole budget. `remaining_budget` of 0 reads nothing and returns `(None, 0)`.
fn stream_native_view<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    index: usize,
    location: SubjectLocation,
    remaining_budget: u64,
) -> (Option<NativeMemberHandoff>, u64) {
    // Bound the streamed work to whatever of the total budget remains. The declared
    // size is attacker-controlled, so a member that lies small still cannot read
    // past `remaining_budget` real bytes here, and the bytes read are debited so
    // the next member sees a smaller budget.
    let cap = remaining_budget;
    // No budget left: read nothing (not even one chunk) so the total budget, once
    // exhausted, halts further native streaming entirely.
    if cap == 0 {
        return (None, 0);
    }
    let mut file = match archive.by_index(index) {
        Ok(f) => f,
        Err(_) => return (None, 0),
    };

    let mut hasher = Sha256::new();
    let mut header_window: Vec<u8> = Vec::new();
    let mut printable = PrintableScanner::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            // A CRC failure or I/O error on a streaming-view member: give up the
            // view (the member is already a coverage gap), but still report the
            // bytes we read so the caller debits them.
            Err(_) => return (None, total),
        };
        total = total.saturating_add(n as u64);
        if total > cap {
            // The member blows the remaining budget (or the per-member cap): give
            // up the view rather than read unbounded, and report what we consumed.
            return (None, total);
        }
        hasher.update(&buf[..n]);
        if (header_window.len() as u64) < NATIVE_HEADER_WINDOW_BYTES {
            let want = (NATIVE_HEADER_WINDOW_BYTES - header_window.len() as u64) as usize;
            let take = want.min(n);
            header_window.extend_from_slice(&buf[..take]);
        }
        printable.feed(&buf[..n]);
    }
    let digest = hasher.finalize();
    let sha256: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    (
        Some(NativeMemberHandoff::Streaming {
            location,
            sha256,
            size: total,
            header_window,
            printable_strings: printable.finish(),
        }),
        total,
    )
}

/// A bounded scanner extracting printable-ASCII runs (length >= 4) from a stream,
/// capping both the number of strings and total captured bytes so a hostile member
/// cannot make the string scan itself a memory DoS.
struct PrintableScanner {
    strings: Vec<String>,
    current: Vec<u8>,
    captured_bytes: usize,
}

impl PrintableScanner {
    /// Max strings retained and max total captured bytes (defense against a member
    /// that is one giant printable run).
    const MAX_STRINGS: usize = 4096;
    const MAX_CAPTURED_BYTES: usize = 1024 * 1024;
    const MIN_RUN: usize = 4;

    fn new() -> Self {
        Self {
            strings: Vec::new(),
            current: Vec::new(),
            captured_bytes: 0,
        }
    }

    fn feed(&mut self, data: &[u8]) {
        for &b in data {
            if (0x20..0x7f).contains(&b) {
                // Bound the IN-PROGRESS run directly against the global cap: count
                // both the bytes already retained and the current run's length, so
                // a single giant printable run with no separator (which never
                // flushes) cannot grow `self.current` without limit. Once the cap
                // is reached we stop appending; bytes beyond it are dropped.
                if self.captured_bytes.saturating_add(self.current.len()) < Self::MAX_CAPTURED_BYTES
                {
                    self.current.push(b);
                }
            } else {
                self.flush_current();
            }
        }
    }

    fn flush_current(&mut self) {
        if self.current.len() >= Self::MIN_RUN && self.strings.len() < Self::MAX_STRINGS {
            if let Ok(s) = String::from_utf8(std::mem::take(&mut self.current)) {
                self.captured_bytes = self.captured_bytes.saturating_add(s.len());
                self.strings.push(s);
            }
        }
        self.current.clear();
    }

    fn finish(mut self) -> Vec<String> {
        self.flush_current();
        self.strings
    }
}

/// Read a symlink member's target bytes (the link target is stored as the member
/// content) via the raw reader, hard-capped to a short length for evidence.
fn read_symlink_target<R: Read + Seek>(archive: &mut zip::ZipArchive<R>, index: usize) -> String {
    const MAX: u64 = 4096;
    let Ok(mut file) = archive.by_index_raw(index) else {
        return String::new();
    };
    let mut buf = Vec::new();
    if file.by_ref().take(MAX).read_to_end(&mut buf).is_err() {
        return String::new();
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Parse a `.dist-info/METADATA` member's `Name:`/`Version:` headers, if THIS
/// member is the METADATA file. Returns `(name, Option<version>)`.
fn parse_metadata_identity(member: &str, bytes: &[u8]) -> Option<(String, Option<String>)> {
    if !member.ends_with(".dist-info/METADATA") {
        return None;
    }
    let text = String::from_utf8_lossy(bytes);
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    for line in text.lines() {
        if line.is_empty() {
            break; // headers end at the first blank line
        }
        if let Some(rest) = line.strip_prefix("Name:") {
            let val = rest.trim();
            if !val.is_empty() {
                name = Some(val.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("Version:") {
            let val = rest.trim();
            if !val.is_empty() {
                version = Some(val.to_string());
            }
        }
    }
    name.map(|n| (n, version))
}

/// Decide the inspection subject. A wheel filename with a parseable identity and a
/// single dist-info root is an [`InspectionSubject::Artifact`]; a wheel name whose
/// dist-info we could read becomes an [`InspectionSubject::InstalledDistribution`]
/// is NOT used here (that is for installed trees, B5); a non-wheel zip is a
/// [`InspectionSubject::GenericArchive`].
fn decide_subject(outer_name: &str, outer_sha256: &str, metas: &[MemberMeta]) -> InspectionSubject {
    if is_wheel_filename(outer_name) {
        // Prefer the wheel filename identity; fall back to the dist-info dir.
        let identity = parse_wheel_filename(outer_name)
            .map(|w| (w.name, Some(w.version)))
            .or_else(|| {
                metas.iter().find_map(|m| {
                    let name = m.enclosed.as_deref().unwrap_or(&m.raw_name);
                    dist_info_root(name)
                        .and_then(|root| parse_dist_info_dir(&root))
                        .map(|(n, v)| (n, Some(v)))
                })
            });
        if let Some((name, version)) = identity {
            return InspectionSubject::Artifact(ArtifactIdentity {
                ecosystem: Ecosystem::PyPI,
                name,
                version,
                filename: outer_name.to_string(),
                sha256: outer_sha256.to_string(),
            });
        }
    }
    generic_subject(outer_name, outer_sha256)
}

/// A generic-archive subject for a non-wheel zip (or a fallback when a wheel's
/// identity could not be parsed).
fn generic_subject(outer_name: &str, outer_sha256: &str) -> InspectionSubject {
    InspectionSubject::GenericArchive(GenericArchiveIdentity {
        filename: outer_name.to_string(),
        sha256: outer_sha256.to_string(),
    })
}

/// Inspect a `.tar.gz` (or any non-wheel artifact this milestone does not handle)
/// as a single `Unsupported` coverage gap. Wheel-only milestone: a hardened
/// tar/gzip reader is a separate later design, and we must NOT claim sdist
/// coverage. The subject is a generic archive identified by the caller-supplied
/// filename and hash (we do not read the body).
pub fn unsupported_sdist(outer_name: &str, outer_sha256: &str) -> ArchiveOutcome {
    let mut inspection = ArtifactInspection::new(generic_subject(outer_name, outer_sha256));
    inspection.coverage.gaps.push(CoverageGap {
        location: SubjectLocation::from_path(outer_name),
        kind: CoverageGapKind::Unsupported,
        sha256: Some(outer_sha256.to_string()),
    });
    // Not a structural violation: an sdist is a legitimate artifact we simply do
    // not inspect yet. Accept with the coverage gap.
    ArchiveOutcome::Accepted(inspection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    /// SHA-256 of a byte slice as lowercase hex (the identity the caller passes as
    /// `outer_sha256`). Tests compute it independently of the reader.
    fn sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A builder over an in-memory zip, so each test reads like the hostile shape
    /// it constructs. Members are added with default deflate unless overridden.
    struct ZipBuilder {
        writer: ZipWriter<Cursor<Vec<u8>>>,
    }

    impl ZipBuilder {
        fn new() -> Self {
            Self {
                writer: ZipWriter::new(Cursor::new(Vec::new())),
            }
        }

        /// Add a deflate-compressed file member with the given raw name.
        fn file(mut self, name: &str, body: &[u8]) -> Self {
            self.writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            self.writer.write_all(body).unwrap();
            self
        }

        /// Add a STORED (uncompressed) file member.
        fn stored(mut self, name: &str, body: &[u8]) -> Self {
            self.writer
                .start_file(
                    name,
                    SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
                )
                .unwrap();
            self.writer.write_all(body).unwrap();
            self
        }

        /// Add a unix symlink member whose stored content is the link target.
        #[cfg(unix)]
        fn symlink(mut self, name: &str, target: &str) -> Self {
            self.writer
                .add_symlink(name, target, SimpleFileOptions::default())
                .unwrap();
            self
        }

        /// Finish and return the archive bytes.
        fn build(self) -> Vec<u8> {
            self.writer.finish().unwrap().into_inner()
        }
    }

    /// Build a minimal VALID wheel: one dist-info METADATA, one package source.
    /// Name `demo`, version `1.0`, filename `demo-1.0-py3-none-any.whl`.
    fn clean_wheel_bytes() -> Vec<u8> {
        ZipBuilder::new()
            .file("demo/__init__.py", b"print('hello')\n")
            .file(
                "demo-1.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n\nA demo.\n",
            )
            .file("demo-1.0.dist-info/WHEEL", b"Wheel-Version: 1.0\n")
            .file(
                "demo-1.0.dist-info/RECORD",
                b"demo/__init__.py,sha256=abc,15\n",
            )
            .build()
    }

    /// Helper: read a wheel from bytes with default limits, no native visitor.
    fn read_bytes(bytes: &[u8], name: &str) -> ArchiveOutcome {
        let sha = sha256_hex(bytes);
        read_wheel_default(Cursor::new(bytes.to_vec()), name, &sha)
    }

    // ---- clean wheel ----------------------------------------------------------

    #[test]
    fn clean_wheel_is_accepted_with_stable_hashes_and_artifact_subject() {
        let bytes = clean_wheel_bytes();
        let outcome = read_bytes(&bytes, "demo-1.0-py3-none-any.whl");
        let inspection = match &outcome {
            ArchiveOutcome::Accepted(i) => i,
            ArchiveOutcome::Rejected { violations, .. } => {
                panic!("a clean wheel must be Accepted, got violations: {violations:?}")
            }
        };
        // Subject is an Artifact with the wheel identity and the caller's hash.
        match &inspection.subject {
            InspectionSubject::Artifact(id) => {
                assert_eq!(id.name, "demo");
                assert_eq!(id.version.as_deref(), Some("1.0"));
                assert_eq!(id.filename, "demo-1.0-py3-none-any.whl");
                assert_eq!(id.sha256, sha256_hex(&bytes));
                assert_eq!(id.ecosystem, Ecosystem::PyPI);
            }
            other => panic!("expected Artifact subject, got {other:?}"),
        }
        // Every non-dir member is a file with a non-empty hash.
        assert_eq!(inspection.files.len(), 4);
        let init = inspection
            .files
            .iter()
            .find(|f| f.location.to_string().ends_with("demo/__init__.py"))
            .expect("the package source is a member");
        assert_eq!(init.kind, ArtifactFileKind::PythonSource);
        assert_eq!(init.sha256, sha256_hex(b"print('hello')\n"));
        assert_eq!(init.size, b"print('hello')\n".len() as u64);

        // METADATA is classified as dist-info metadata.
        assert!(inspection
            .files
            .iter()
            .any(|f| f.kind == ArtifactFileKind::DistInfoMetadata
                && f.location.to_string().ends_with("METADATA")));

        // Hashes are STABLE across re-reads.
        let again = read_bytes(&bytes, "demo-1.0-py3-none-any.whl");
        let again_inspection = match &again {
            ArchiveOutcome::Accepted(i) => i,
            ArchiveOutcome::Rejected { violations, .. } => {
                panic!("a clean wheel must be Accepted on re-read, got violations: {violations:?}")
            }
        };
        assert_eq!(again_inspection.files, inspection.files);

        // Full coverage, no gaps.
        assert!(inspection.coverage.gaps.is_empty());
        assert!(inspection.coverage.is_complete());
    }

    // ---- hard structural violations -> Rejected -------------------------------

    /// Assert that an outcome is Rejected and contains a violation matching `pred`.
    fn assert_rejected_with(
        outcome: &ArchiveOutcome,
        what: &str,
        pred: impl Fn(&ArchiveViolation) -> bool,
    ) {
        match outcome {
            ArchiveOutcome::Rejected { violations, .. } => {
                assert!(
                    violations.iter().any(pred),
                    "expected a {what} violation, got {violations:?}"
                );
            }
            ArchiveOutcome::Accepted(_) => panic!("expected Rejected for {what}, got Accepted"),
        }
    }

    #[test]
    fn dotdot_traversal_member_is_rejected() {
        let bytes = ZipBuilder::new()
            .file("../etc/passwd", b"root:x:0:0\n")
            .file("demo-1.0.dist-info/METADATA", b"Name: demo\nVersion: 1.0\n")
            .build();
        let outcome = read_bytes(&bytes, "demo-1.0-py3-none-any.whl");
        assert_rejected_with(
            &outcome,
            "path traversal",
            |v| matches!(v, ArchiveViolation::PathTraversal { member } if member.contains("passwd")),
        );
    }

    #[test]
    fn absolute_member_is_rejected() {
        let bytes = ZipBuilder::new()
            .file("/etc/cron.d/evil", b"* * * * * root sh\n")
            .build();
        let outcome = read_bytes(&bytes, "demo-1.0-py3-none-any.whl");
        assert_rejected_with(&outcome, "absolute path", |v| {
            matches!(v, ArchiveViolation::PathTraversal { .. })
        });
    }

    #[test]
    fn backslash_traversal_member_is_rejected_host_independent() {
        // On a Unix host `enclosed_name` treats `..\evil` as one safe component, so
        // the backslash check MUST be host-OS-independent.
        let bytes = ZipBuilder::new()
            .file("..\\windows\\system32\\evil.dll", b"MZ")
            .build();
        let outcome = read_bytes(&bytes, "demo-1.0-py3-none-any.whl");
        assert_rejected_with(&outcome, "backslash traversal", |v| {
            matches!(v, ArchiveViolation::WindowsPathTraversal { .. })
        });
    }

    #[test]
    fn drive_letter_member_is_rejected() {
        let bytes = ZipBuilder::new().file("C:/Windows/evil.dll", b"MZ").build();
        let outcome = read_bytes(&bytes, "demo-1.0-py3-none-any.whl");
        assert_rejected_with(
            &outcome,
            "drive-letter path",
            |v| matches!(v, ArchiveViolation::WindowsPathTraversal { member } if member.starts_with("C:")),
        );
    }

    #[test]
    fn unc_member_is_rejected() {
        let bytes = ZipBuilder::new()
            .file("\\\\server\\share\\evil", b"x")
            .build();
        let outcome = read_bytes(&bytes, "demo-1.0-py3-none-any.whl");
        // A UNC path contains backslashes, so it trips the Windows-path check.
        assert_rejected_with(&outcome, "UNC path", |v| {
            matches!(v, ArchiveViolation::WindowsPathTraversal { .. })
        });
    }

    #[test]
    fn duplicate_normalized_member_is_rejected() {
        // Two members differing only in case collide on a case-insensitive target.
        let bytes = ZipBuilder::new()
            .file("demo/Mod.py", b"a")
            .file("demo/mod.py", b"b")
            .build();
        let outcome = read_bytes(&bytes, "demo-1.0-py3-none-any.whl");
        assert_rejected_with(&outcome, "duplicate normalized path", |v| {
            matches!(v, ArchiveViolation::DuplicatePath { .. })
        });
    }

    #[test]
    fn exact_duplicate_path_is_detected_by_the_collision_check() {
        // The `ZipWriter` (and any honest archiver) refuses to write a byte-identical
        // duplicate filename, so an exact duplicate only arises from a hand-crafted
        // hostile archive. Exercise the detector directly with two members sharing
        // an identical path: it must emit a `DuplicatePath` violation. (The
        // end-to-end case-fold / Unicode collisions are covered against real
        // archives by `duplicate_normalized_member_is_rejected`.)
        let metas = vec![test_meta(0, "demo/mod.py"), test_meta(1, "demo/mod.py")];
        let mut violations = Vec::new();
        check_path_collisions(&metas, &mut violations);
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, ArchiveViolation::DuplicatePath { .. })),
            "an exact duplicate path must be a DuplicatePath violation, got {violations:?}"
        );
    }

    /// A `MemberMeta` for a safe (enclosed) file path, for detector unit tests
    /// that do not need a real archive.
    fn test_meta(index: usize, name: &str) -> MemberMeta {
        MemberMeta {
            index,
            raw_name: name.to_string(),
            enclosed: Some(name.to_string()),
            is_dir: false,
            is_symlink: false,
            encrypted: false,
            compression: CompressionMethod::Deflated,
            declared_size: 0,
            compressed_size: 0,
        }
    }

    #[test]
    fn conflicting_dist_info_roots_is_rejected() {
        let bytes = ZipBuilder::new()
            .file("demo-1.0.dist-info/METADATA", b"Name: demo\nVersion: 1.0\n")
            .file("evil-9.9.dist-info/METADATA", b"Name: evil\nVersion: 9.9\n")
            .build();
        let outcome = read_bytes(&bytes, "demo-1.0-py3-none-any.whl");
        assert_rejected_with(
            &outcome,
            "conflicting dist-info",
            |v| matches!(v, ArchiveViolation::ConflictingDistInfo { roots } if roots.len() == 2),
        );
    }

    #[test]
    fn wheel_identity_mismatch_is_rejected() {
        // The wheel filename says `demo` but the dist-info/METADATA say `evil`.
        let bytes = ZipBuilder::new()
            .file("evil-1.0.dist-info/METADATA", b"Name: evil\nVersion: 1.0\n")
            .build();
        let outcome = read_bytes(&bytes, "demo-1.0-py3-none-any.whl");
        assert_rejected_with(&outcome, "identity mismatch", |v| {
            matches!(v, ArchiveViolation::IdentityMismatch { .. })
        });
    }

    #[test]
    fn wheel_metadata_version_mismatch_is_rejected() {
        // dist-info dir agrees with the filename, but METADATA Version disagrees.
        let bytes = ZipBuilder::new()
            .file("demo-1.0.dist-info/METADATA", b"Name: demo\nVersion: 9.9\n")
            .build();
        let outcome = read_bytes(&bytes, "demo-1.0-py3-none-any.whl");
        assert_rejected_with(
            &outcome,
            "metadata version mismatch",
            |v| matches!(v, ArchiveViolation::IdentityMismatch { detail } if detail.contains("Version")),
        );
    }

    #[test]
    fn encrypted_member_is_rejected() {
        // The public write API can only produce an encrypted member with the
        // `aes-crypto` feature (not enabled here). Instead, build a plain member
        // and set bit 0 (the "encrypted" general-purpose flag) in its central
        // directory header, which is exactly the bit `ZipFile::encrypted()` reads
        // (`flags & 1`). This produces an archive the reader sees as encrypted
        // without us needing an encoder.
        let mut bytes = ZipBuilder::new().stored("demo/secret.py", b"x").build();
        set_central_dir_encrypted_bit(&mut bytes);

        let outcome = read_bytes(&bytes, "demo-1.0-py3-none-any.whl");
        assert_rejected_with(
            &outcome,
            "encrypted member",
            |v| matches!(v, ArchiveViolation::EncryptedMember { member } if member.contains("secret")),
        );
    }

    /// Set bit 0 (encrypted) of the general-purpose bit flag in EVERY central
    /// directory file header (`PK\x01\x02`). The flag word is 2 bytes at offset 8
    /// from the 4-byte signature. We patch the central directory because
    /// `ZipFile::encrypted()` reads the central-directory metadata. We do NOT
    /// touch the local header, so the content still reads as plaintext bytes (the
    /// reader rejects on the encrypted flag before any decrypt is attempted, since
    /// our reader flags an encrypted member structurally and never decompresses it).
    fn set_central_dir_encrypted_bit(bytes: &mut [u8]) {
        const CDH_SIG: [u8; 4] = [b'P', b'K', 0x01, 0x02];
        let mut i = 0;
        let mut patched = false;
        while i + 10 <= bytes.len() {
            if bytes[i..i + 4] == CDH_SIG {
                // general-purpose bit flag at offset 8..10 (little-endian).
                bytes[i + 8] |= 0x01;
                patched = true;
            }
            i += 1;
        }
        assert!(
            patched,
            "test setup: no central directory header found to patch"
        );
    }

    #[test]
    fn crc_failure_member_is_rejected() {
        // Corrupt a STORED member's CRC by patching the archive bytes: a stored
        // member's data is verbatim, so flipping a content byte AFTER the CRC was
        // computed makes the stored CRC wrong, which the reader detects on read.
        let body = b"the original member body bytes for crc test";
        let mut bytes = ZipBuilder::new().stored("demo/data.bin", body).build();

        // Find the body in the archive and flip a byte. The stored body appears
        // verbatim (no compression), so a literal search locates it.
        let needle = b"original";
        let pos = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("stored body is present verbatim");
        bytes[pos] ^= 0xff; // corrupt one byte -> CRC no longer matches

        let outcome = read_bytes(&bytes, "demo-1.0-py3-none-any.whl");
        assert_rejected_with(
            &outcome,
            "CRC mismatch",
            |v| matches!(v, ArchiveViolation::CrcMismatch { member } if member.contains("data.bin")),
        );
    }

    #[test]
    fn crc_mismatch_classified_via_invalid_data_not_substring() {
        // REGRESSION (T3.9): a corrupted member must classify as CrcMismatch via the
        // error KIND (`ErrorKind::InvalidData` raised while finalizing the member's
        // decompression), NOT via a fragile `message.contains("checksum")` match
        // coupled to the zip crate's exact wording. Corrupt the COMPRESSED bytes of
        // a DEFLATE member: the inflater surfaces this as an InvalidData error whose
        // message is a deflate decode error (no "checksum" substring), yet the
        // member must still be Rejected as a CrcMismatch. The old substring gate let
        // this fall through to an Unreadable coverage gap (Accepted).
        let body = b"deflate member body that compresses and then gets its stream smashed";
        let mut bytes = ZipBuilder::new().file("demo/blob.bin", body).build();
        corrupt_first_local_member_data(&mut bytes);

        let outcome = read_bytes(&bytes, "demo-1.0-py3-none-any.whl");
        assert_rejected_with(
            &outcome,
            "CRC mismatch (structural InvalidData classification)",
            |v| matches!(v, ArchiveViolation::CrcMismatch { member } if member.contains("blob.bin")),
        );
    }

    /// Smash the leading bytes of the FIRST local file member's COMPRESSED data,
    /// breaking the deflate stream so the inflater raises an `InvalidData` error
    /// (with a decode-error message, not a checksum message). Local file header:
    /// `PK\x03\x04`, then fixed fields, with the file-name length at offset 26 and
    /// the extra-field length at offset 28 (both u16 little-endian); the compressed
    /// data starts at `30 + name_len + extra_len`.
    fn corrupt_first_local_member_data(bytes: &mut [u8]) {
        const LFH_SIG: [u8; 4] = [b'P', b'K', 0x03, 0x04];
        let pos = bytes
            .windows(4)
            .position(|w| w == LFH_SIG)
            .expect("a local file header must be present");
        let name_len = u16::from_le_bytes([bytes[pos + 26], bytes[pos + 27]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[pos + 28], bytes[pos + 29]]) as usize;
        let data_start = pos + 30 + name_len + extra_len;
        // Flip the first few bytes of the deflate stream; this reliably breaks the
        // block structure so decoding fails (or, failing that, the CRC will not
        // match the altered output). Either way the reader sees an InvalidData kind.
        let end = (data_start + 8).min(bytes.len());
        for b in &mut bytes[data_start..end] {
            *b ^= 0xff;
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_member_is_rejected() {
        let bytes = ZipBuilder::new()
            .symlink("demo/link.so", "/etc/passwd")
            .file("demo-1.0.dist-info/METADATA", b"Name: demo\nVersion: 1.0\n")
            .build();
        let outcome = read_bytes(&bytes, "demo-1.0-py3-none-any.whl");
        assert_rejected_with(
            &outcome,
            "symlink member",
            |v| matches!(v, ArchiveViolation::SymlinkMember { target, .. } if target.contains("passwd")),
        );
    }

    #[test]
    fn non_archive_input_is_rejected_as_malformed() {
        let bytes = b"this is not a zip file at all";
        let outcome = read_bytes(bytes, "demo-1.0-py3-none-any.whl");
        assert_rejected_with(&outcome, "malformed archive", |v| {
            matches!(v, ArchiveViolation::MalformedArchive { .. })
        });
    }

    // ---- coverage limits -> Accepted with gaps --------------------------------

    #[test]
    fn entry_count_cap_is_a_gap_not_rejection() {
        let mut b = ZipBuilder::new();
        for i in 0..10 {
            b = b.file(&format!("demo/f{i}.py"), b"x");
        }
        let bytes = b.build();
        let sha = sha256_hex(&bytes);
        let limits = ArchiveLimits {
            max_entries: 3,
            ..ArchiveLimits::default()
        };
        struct NoopVisitor;
        impl MemberVisitor for NoopVisitor {}
        let outcome = read_wheel(
            Cursor::new(bytes),
            "demo-1.0-py3-none-any.whl",
            &sha,
            &limits,
            &mut NoopVisitor,
        );
        let inspection = match &outcome {
            ArchiveOutcome::Accepted(i) => i,
            other => panic!("entry-count cap must Accept, got {other:?}"),
        };
        assert!(inspection
            .coverage
            .gaps
            .iter()
            .any(|g| g.kind == CoverageGapKind::EntryCountCapped));
    }

    #[test]
    fn per_member_cap_is_a_gap_not_rejection() {
        // A single member whose declared size exceeds the per-member cap.
        let big = vec![b'a'; 4096];
        let bytes = ZipBuilder::new().stored("demo/big.bin", &big).build();
        let sha = sha256_hex(&bytes);
        let limits = ArchiveLimits {
            max_member_uncompressed: 1024,
            ..ArchiveLimits::default()
        };
        struct NoopVisitor;
        impl MemberVisitor for NoopVisitor {}
        let outcome = read_wheel(
            Cursor::new(bytes),
            "demo-1.0-py3-none-any.whl",
            &sha,
            &limits,
            &mut NoopVisitor,
        );
        let inspection = match &outcome {
            ArchiveOutcome::Accepted(i) => i,
            other => panic!("per-member cap must Accept, got {other:?}"),
        };
        assert!(inspection
            .coverage
            .gaps
            .iter()
            .any(|g| g.kind == CoverageGapKind::MemberTooLarge));
    }

    #[test]
    fn total_byte_budget_is_a_gap_not_rejection() {
        // Two members; the total budget is smaller than their sum, so the second
        // is a TotalBytesCapped gap.
        let body = vec![b'a'; 2048];
        let bytes = ZipBuilder::new()
            .stored("demo/a.bin", &body)
            .stored("demo/b.bin", &body)
            .build();
        let sha = sha256_hex(&bytes);
        let limits = ArchiveLimits {
            max_total_uncompressed: 3000, // first member (2048) fits, second pushes over
            max_member_uncompressed: 64 * 1024 * 1024,
            ..ArchiveLimits::default()
        };
        struct NoopVisitor;
        impl MemberVisitor for NoopVisitor {}
        let outcome = read_wheel(
            Cursor::new(bytes),
            "demo-1.0-py3-none-any.whl",
            &sha,
            &limits,
            &mut NoopVisitor,
        );
        let inspection = match &outcome {
            ArchiveOutcome::Accepted(i) => i,
            other => panic!("total-byte budget must Accept, got {other:?}"),
        };
        assert!(
            inspection
                .coverage
                .gaps
                .iter()
                .any(|g| g.kind == CoverageGapKind::TotalBytesCapped),
            "expected a TotalBytesCapped gap, gaps were {:?}",
            inspection.coverage.gaps
        );
    }

    #[test]
    fn compression_ratio_bomb_is_a_gap_not_rejection() {
        // A highly compressible member: many zero bytes deflate to almost nothing,
        // so the REAL uncompressed/compressed ratio is enormous. With a tiny ratio
        // limit it must be abandoned as a CompressionRatioExceeded gap.
        let bomb = vec![0u8; 1024 * 1024]; // 1 MiB of zeros, compresses tiny
        let bytes = ZipBuilder::new().file("demo/bomb.bin", &bomb).build();
        let sha = sha256_hex(&bytes);
        let limits = ArchiveLimits {
            max_compression_ratio: 2, // 1 MiB from a few-byte deflate blows past 2x
            max_member_uncompressed: 64 * 1024 * 1024,
            max_total_uncompressed: 512 * 1024 * 1024,
            ..ArchiveLimits::default()
        };
        struct NoopVisitor;
        impl MemberVisitor for NoopVisitor {}
        let outcome = read_wheel(
            Cursor::new(bytes),
            "demo-1.0-py3-none-any.whl",
            &sha,
            &limits,
            &mut NoopVisitor,
        );
        let inspection = match &outcome {
            ArchiveOutcome::Accepted(i) => i,
            other => panic!("a ratio bomb must Accept (coverage limit), got {other:?}"),
        };
        assert!(inspection
            .coverage
            .gaps
            .iter()
            .any(|g| g.kind == CoverageGapKind::CompressionRatioExceeded));
    }

    #[test]
    fn lie_about_size_is_aborted_at_the_real_byte_budget() {
        // The DECLARED (central directory) uncompressed size is attacker-controlled.
        // A hostile member lies SMALL in its header so the declared-size pre-check
        // waves it through, then streams huge. Our budget is enforced on REAL
        // streamed bytes inside `stream_member`, so it must still be aborted. We
        // build a real 1 MiB member, then patch its declared uncompressed size to a
        // tiny value (100) in the central directory so the pre-check passes and the
        // REAL-byte budget is the only thing that can catch it.
        let real = vec![b'z'; 1024 * 1024]; // 1 MiB actual content
        let mut bytes = ZipBuilder::new().stored("demo/liar.bin", &real).build();
        set_central_dir_uncompressed_size(&mut bytes, 100); // the lie

        let sha = sha256_hex(&bytes);
        let limits = ArchiveLimits {
            // The per-member cap is generous (so the DECLARED-size pre-check, which
            // sees the lie of 100, passes), but the REMAINING-TOTAL budget is tiny,
            // so the real-byte streaming guard binds and aborts the member.
            max_member_uncompressed: 512 * 1024, // > the declared lie (100), < real 1 MiB
            max_total_uncompressed: 4096,        // the real streamed bytes blow past this
            max_compression_ratio: 1_000_000_000, // never let the ratio be the trigger
            ..ArchiveLimits::default()
        };
        struct NoopVisitor;
        impl MemberVisitor for NoopVisitor {}
        let outcome = read_wheel(
            Cursor::new(bytes),
            "demo-1.0-py3-none-any.whl",
            &sha,
            &limits,
            &mut NoopVisitor,
        );
        let inspection = match &outcome {
            ArchiveOutcome::Accepted(i) => i,
            other => panic!("a size-lie must Accept with a coverage gap, got {other:?}"),
        };
        // The member must NOT appear as a fully-inspected file (we aborted it
        // mid-stream on the REAL byte budget, not the declared size).
        assert!(
            !inspection
                .files
                .iter()
                .any(|f| f.location.to_string().ends_with("liar.bin")),
            "a size-lie member must not be recorded as fully inspected"
        );
        // It is a byte-budget gap (the real bytes hit the total budget first).
        assert!(
            inspection.coverage.gaps.iter().any(|g| {
                matches!(
                    g.kind,
                    CoverageGapKind::TotalBytesCapped | CoverageGapKind::MemberTooLarge
                ) && g.location.to_string().ends_with("liar.bin")
            }),
            "the size-lie member must be a byte-budget coverage gap, gaps: {:?}",
            inspection.coverage.gaps
        );
    }

    /// Patch the uncompressed-size field (4 bytes, little-endian, at offset 24 from
    /// the `PK\x01\x02` signature) in EVERY central directory file header. This is
    /// the DECLARED size `ZipFile::size()` reports; patching it to a lie lets a test
    /// prove the reader does not trust it (the REAL streamed bytes still govern the
    /// budget). Note: if a zip64 extra field is present the real value lives there;
    /// our small synthetic members never use zip64, so the 32-bit field is the
    /// declared size.
    fn set_central_dir_uncompressed_size(bytes: &mut [u8], size: u32) {
        const CDH_SIG: [u8; 4] = [b'P', b'K', 0x01, 0x02];
        let mut i = 0;
        let mut patched = false;
        while i + 28 <= bytes.len() {
            if bytes[i..i + 4] == CDH_SIG {
                bytes[i + 24..i + 28].copy_from_slice(&size.to_le_bytes());
                patched = true;
            }
            i += 1;
        }
        assert!(
            patched,
            "test setup: no central directory header found to patch"
        );
    }

    #[test]
    fn unsupported_compression_member_is_a_gap_not_rejection() {
        // The `ZipWriter` only writes the methods it can encode (store/deflate
        // here), so a member using an undecodable method (e.g. bzip2 = 12, not in
        // this build's feature set) only comes from a hand-crafted archive. Build a
        // STORED member, then patch its compression-method field to 12 in the
        // CENTRAL DIRECTORY header (which is what `ZipFile::compression()` reads).
        // The reader records a coverage gap and SKIPS the content (it never tries to
        // decode), so the local-header method does not need patching.
        let mut bytes = ZipBuilder::new()
            .stored("demo/data.bin", b"some stored payload bytes")
            .build();
        set_central_dir_compression_method(&mut bytes, 12);

        let outcome = read_bytes(&bytes, "demo-1.0-py3-none-any.whl");
        match &outcome {
            ArchiveOutcome::Accepted(i) => {
                assert!(
                    i.coverage
                        .gaps
                        .iter()
                        .any(|g| g.kind == CoverageGapKind::UnsupportedCompression),
                    "expected an UnsupportedCompression gap, gaps: {:?}",
                    i.coverage.gaps
                );
            }
            ArchiveOutcome::Rejected { violations, .. } => {
                panic!("unsupported compression should be a gap, not Rejected: {violations:?}");
            }
        }
    }

    /// Patch the compression-method field (2 bytes, little-endian, at offset 10
    /// from the 4-byte `PK\x01\x02` signature) in EVERY central directory file
    /// header. This is the field `ZipFile::compression()` reads, so the reader sees
    /// the member as using `method` without us needing an encoder for it.
    fn set_central_dir_compression_method(bytes: &mut [u8], method: u16) {
        const CDH_SIG: [u8; 4] = [b'P', b'K', 0x01, 0x02];
        let mut i = 0;
        let mut patched = false;
        while i + 12 <= bytes.len() {
            if bytes[i..i + 4] == CDH_SIG {
                bytes[i + 10] = (method & 0xff) as u8;
                bytes[i + 11] = (method >> 8) as u8;
                patched = true;
            }
            i += 1;
        }
        assert!(
            patched,
            "test setup: no central directory header found to patch"
        );
    }

    // ---- sdist / non-wheel ----------------------------------------------------

    #[test]
    fn tar_gz_is_unsupported_not_inspected() {
        // The wheel-only milestone: a `.tar.gz` is a single Unsupported gap; we do
        // NOT claim sdist coverage. `unsupported_sdist` is the entry point.
        let outcome = unsupported_sdist("demo-1.0.tar.gz", &"a".repeat(64));
        let inspection = match &outcome {
            ArchiveOutcome::Accepted(i) => i,
            other => panic!("an sdist must Accept-with-gap, got {other:?}"),
        };
        assert!(inspection
            .coverage
            .gaps
            .iter()
            .any(|g| g.kind == CoverageGapKind::Unsupported));
        assert!(!is_wheel_filename("demo-1.0.tar.gz"));
        assert!(is_wheel_filename("demo-1.0-py3-none-any.whl"));
    }

    #[test]
    fn non_wheel_zip_is_a_generic_archive_subject() {
        let bytes = ZipBuilder::new().file("notes/readme.txt", b"hi").build();
        let outcome = read_bytes(&bytes, "bundle.zip");
        let inspection = match &outcome {
            ArchiveOutcome::Accepted(i) => i,
            other => panic!("a clean generic zip must Accept, got {other:?}"),
        };
        match &inspection.subject {
            InspectionSubject::GenericArchive(id) => {
                assert_eq!(id.filename, "bundle.zip");
                assert_eq!(id.sha256, sha256_hex(&bytes));
            }
            other => panic!("expected GenericArchive subject, got {other:?}"),
        }
    }

    // ---- native member handoff ------------------------------------------------

    #[test]
    fn native_member_below_cap_yields_a_full_buffer() {
        let native_body = b"\x7fELF\x02\x01\x01\x00 fake native module bytes for handoff";
        let bytes = ZipBuilder::new()
            .file("demo/_core.abi3.so", native_body)
            .file("demo-1.0.dist-info/METADATA", b"Name: demo\nVersion: 1.0\n")
            .build();
        let sha = sha256_hex(&bytes);
        let mut visitor = CollectingVisitor::default();
        let outcome = read_wheel(
            Cursor::new(bytes),
            "demo-1.0-py3-none-any.whl",
            &sha,
            &ArchiveLimits::default(),
            &mut visitor,
        );
        assert!(
            !outcome.is_rejected(),
            "a wheel with a native module is fine"
        );
        assert_eq!(visitor.native.len(), 1, "exactly one native handoff");
        match &visitor.native[0] {
            NativeMemberHandoff::Buffered {
                bytes,
                sha256,
                location,
            } => {
                assert_eq!(bytes.as_slice(), native_body);
                assert_eq!(sha256, &sha256_hex(native_body));
                assert!(location.to_string().ends_with("_core.abi3.so"));
            }
            NativeMemberHandoff::Streaming { .. } => {
                panic!("a small native member must be Buffered, not Streaming")
            }
        }
    }

    #[test]
    fn native_member_above_cap_yields_streaming_view_and_truncated_gap() {
        // A native member larger than the native-parse cap must be a Streaming view
        // (hash + header window + printable strings), and a NativeTruncated gap.
        let mut native_body = Vec::new();
        native_body.extend_from_slice(b"\x7fELF\x02\x01\x01\x00");
        native_body.extend_from_slice(b"PYTHON_BOOTSTRAP_STRING ");
        native_body.resize(256 * 1024, 0u8); // pad with zeros past the cap
        let bytes = ZipBuilder::new()
            .file("demo/_big.abi3.so", &native_body)
            .build();
        let sha = sha256_hex(&bytes);
        let limits = ArchiveLimits {
            // Below the member size so it cannot be buffered, but the per-member
            // analysis cap is also below so it is a coverage gap; the native view
            // is produced from the BudgetExceeded path.
            max_member_uncompressed: 1024,
            max_total_uncompressed: 512 * 1024 * 1024,
            max_compression_ratio: 1_000_000,
            ..ArchiveLimits::default()
        };
        let mut visitor = CollectingVisitor::default();
        let outcome = read_wheel(
            Cursor::new(bytes),
            "demo-1.0-py3-none-any.whl",
            &sha,
            &limits,
            &mut visitor,
        );
        let inspection = match &outcome {
            ArchiveOutcome::Accepted(i) => i,
            other => panic!("a large native member is a coverage limit, got {other:?}"),
        };
        // A coverage gap for the oversized member.
        assert!(inspection
            .coverage
            .gaps
            .iter()
            .any(|g| g.location.to_string().ends_with("_big.abi3.so")));
        // And a Streaming handoff with the full-member hash and a header window.
        assert_eq!(visitor.native.len(), 1);
        match &visitor.native[0] {
            NativeMemberHandoff::Streaming {
                sha256,
                size,
                header_window,
                printable_strings,
                ..
            } => {
                assert_eq!(sha256, &sha256_hex(&native_body));
                assert_eq!(*size, native_body.len() as u64);
                assert!(!header_window.is_empty());
                assert!(header_window.len() as u64 <= NATIVE_HEADER_WINDOW_BYTES);
                assert!(
                    printable_strings
                        .iter()
                        .any(|s| s.contains("PYTHON_BOOTSTRAP_STRING")),
                    "the printable-string scan should find embedded ASCII"
                );
            }
            NativeMemberHandoff::Buffered { .. } => {
                panic!("an above-cap native member must be Streaming, not Buffered")
            }
        }
    }

    /// A visitor that sums the REAL streamed bytes the reader reported across all
    /// native handoffs (the `Streaming.size`, or the `Buffered` body length), so a
    /// test can assert the total decompression the reader performed is bounded.
    #[derive(Default)]
    struct ByteCountingVisitor {
        streaming_count: usize,
        total_native_bytes: u64,
    }

    impl MemberVisitor for ByteCountingVisitor {
        fn on_native_member(&mut self, handoff: NativeMemberHandoff) {
            match handoff {
                NativeMemberHandoff::Streaming { size, .. } => {
                    self.streaming_count += 1;
                    self.total_native_bytes = self.total_native_bytes.saturating_add(size);
                }
                NativeMemberHandoff::Buffered { bytes, .. } => {
                    self.total_native_bytes =
                        self.total_native_bytes.saturating_add(bytes.len() as u64);
                }
            }
        }
    }

    #[test]
    fn archive_total_budget_debits_aborted_and_native_members() {
        // REGRESSION (T1.1): the shared total-uncompressed budget must be debited
        // for EVERY member, including the over-declared-cap native branch (which
        // historically called `stream_native_view` with the FULL total budget per
        // member, so N oversized native members could each read the whole budget).
        //
        // Build 5 highly-compressible `.so` members, each REAL size 100 KiB but
        // DECLARING 150 KiB (a lie patched into the central directory) so each
        // enters the over-cap native branch. With the per-member cap at 100 KiB and
        // the TOTAL budget at 200 KiB, only the first ~2 members fit the total; the
        // rest must read NOTHING once the budget is exhausted.
        const MEMBER_REAL: usize = 100 * 1024;
        const N: usize = 5;
        let body = vec![0u8; MEMBER_REAL]; // zeros: deflate to almost nothing
        let mut b = ZipBuilder::new();
        for i in 0..N {
            b = b.file(&format!("demo/_ext{i}.abi3.so"), &body);
        }
        let mut bytes = b.build();
        // Patch every member's DECLARED uncompressed size to 150 KiB (> the 100 KiB
        // per-member cap) so each takes the over-declared-cap native path. The REAL
        // streamed bytes (100 KiB) still govern what `stream_native_view` reads.
        set_central_dir_uncompressed_size(&mut bytes, 150 * 1024);
        let sha = sha256_hex(&bytes);

        let limits = ArchiveLimits {
            max_member_uncompressed: MEMBER_REAL as u64, // 100 KiB: each member is "oversized" only by its lie
            max_total_uncompressed: (2 * MEMBER_REAL) as u64, // 200 KiB: ~2 members fit
            max_compression_ratio: 1_000_000_000,        // never let the ratio be the trigger
            ..ArchiveLimits::default()
        };

        let mut visitor = ByteCountingVisitor::default();
        let outcome = read_wheel(
            Cursor::new(bytes),
            "demo-1.0-py3-none-any.whl",
            &sha,
            &limits,
            &mut visitor,
        );
        let inspection = match &outcome {
            ArchiveOutcome::Accepted(i) => i,
            other => panic!("oversized native members are a coverage limit, got {other:?}"),
        };

        // The reader STOPPED after the total budget was exhausted: the bytes it
        // actually decompressed across all native members must be within the total
        // budget plus at most one member's slack, NOT ~5 members' worth.
        assert!(
            visitor.total_native_bytes <= limits.max_total_uncompressed + MEMBER_REAL as u64,
            "total decompressed native bytes ({}) must stay within the total budget \
             plus one member's slack ({}), not ~{} members ({}); the budget was bypassed",
            visitor.total_native_bytes,
            limits.max_total_uncompressed + MEMBER_REAL as u64,
            N,
            (N * MEMBER_REAL) as u64,
        );
        // Concretely: only the first two members fit the 200 KiB budget; the rest
        // read nothing, so exactly two streaming views were produced (NOT five).
        assert_eq!(
            visitor.streaming_count, 2,
            "only the members that fit the total budget should stream a view"
        );
        // Every oversized member is still a MemberTooLarge coverage gap (the
        // structural bookkeeping is unchanged; only the budget accounting is fixed).
        let member_too_large = inspection
            .coverage
            .gaps
            .iter()
            .filter(|g| g.kind == CoverageGapKind::MemberTooLarge)
            .count();
        assert_eq!(
            member_too_large, N,
            "each oversized native member is a MemberTooLarge gap"
        );
        // And the deep parse was marked truncated for each native member.
        let native_truncated = inspection
            .coverage
            .gaps
            .iter()
            .filter(|g| g.kind == CoverageGapKind::NativeTruncated)
            .count();
        assert_eq!(
            native_truncated, N,
            "each oversized native member records a NativeTruncated gap"
        );
    }

    // ---- helper unit checks ---------------------------------------------------

    #[test]
    fn printable_scanner_bounds_single_giant_run() {
        // REGRESSION (T3.8): a single long printable run with NO separator never
        // hits `flush_current`, so `captured_bytes` (only bumped on flush) used to
        // stay 0 and the in-progress `current` grew without bound. Feed several MiB
        // of one uninterrupted printable run and assert the retained bytes stay
        // capped both DURING the stream (the in-progress run) and at finish.
        let mut scanner = PrintableScanner::new();
        let chunk = vec![b'A'; 64 * 1024]; // all printable, no separator byte
        let mut fed: u64 = 0;
        for _ in 0..64 {
            scanner.feed(&chunk); // 64 * 64 KiB = 4 MiB total, far past the 1 MiB cap
            fed += chunk.len() as u64;
            // The in-progress run must never exceed the global capture cap.
            assert!(
                scanner.current.len() <= PrintableScanner::MAX_CAPTURED_BYTES,
                "the in-progress run ({}) must stay within MAX_CAPTURED_BYTES ({})",
                scanner.current.len(),
                PrintableScanner::MAX_CAPTURED_BYTES,
            );
        }
        assert!(fed > PrintableScanner::MAX_CAPTURED_BYTES as u64);
        // At finish the retained run is flushed; the single string must still be
        // bounded by the capture cap, NOT the multi-MiB amount fed.
        let strings = scanner.finish();
        let retained: usize = strings.iter().map(|s| s.len()).sum();
        assert!(
            retained <= PrintableScanner::MAX_CAPTURED_BYTES,
            "retained printable bytes ({retained}) must stay within MAX_CAPTURED_BYTES ({})",
            PrintableScanner::MAX_CAPTURED_BYTES,
        );
    }

    #[test]
    fn pep503_name_normalization() {
        assert_eq!(normalize_project_name("Foo.Bar_baz"), "foo-bar-baz");
        assert_eq!(normalize_project_name("foo---bar"), "foo-bar");
        assert_eq!(normalize_project_name("Django"), "django");
        // Equal under normalization.
        assert_eq!(
            normalize_project_name("zope.interface"),
            normalize_project_name("zope-interface")
        );
    }

    #[test]
    fn windows_path_detection() {
        assert!(has_windows_path("a\\b"));
        assert!(has_windows_path("C:/x"));
        assert!(has_windows_path("z:\\x"));
        assert!(has_windows_path("//server/share"));
        assert!(!has_windows_path("a/b/c"));
        assert!(!has_windows_path("demo/__init__.py"));
    }

    #[test]
    fn dotdot_segment_detection() {
        assert!(has_dotdot_segment("a/../b"));
        assert!(has_dotdot_segment(".."));
        assert!(has_dotdot_segment("../x"));
        assert!(has_dotdot_segment("x/.."));
        assert!(!has_dotdot_segment("a..b")); // a `..` inside a name is fine
        assert!(!has_dotdot_segment("demo/mod.py"));
    }

    #[test]
    fn member_classification() {
        assert_eq!(
            classify_member("demo/_core.abi3.so"),
            ArtifactFileKind::NativeModule
        );
        assert_eq!(
            classify_member("demo/bootstrap.pth"),
            ArtifactFileKind::PthFile
        );
        assert_eq!(classify_member("demo/x.start"), ArtifactFileKind::StartFile);
        assert_eq!(
            classify_member("sitecustomize.py"),
            ArtifactFileKind::SiteCustomize
        );
        assert_eq!(
            classify_member("demo/mod.py"),
            ArtifactFileKind::PythonSource
        );
        assert_eq!(classify_member("demo/x.wasm"), ArtifactFileKind::WasmModule);
        assert_eq!(classify_member("demo/run.sh"), ArtifactFileKind::Script);
        assert_eq!(
            classify_member("demo-1.0.dist-info/METADATA"),
            ArtifactFileKind::DistInfoMetadata
        );
        assert_eq!(classify_member("demo/data.json"), ArtifactFileKind::Other);
    }

    #[test]
    fn wheel_filename_parsing() {
        let w = parse_wheel_filename("demo-1.0-py3-none-any.whl").unwrap();
        assert_eq!(w.name, "demo");
        assert_eq!(w.version, "1.0");
        // A build tag is tolerated (name+version are still the first two fields).
        let w = parse_wheel_filename("foo_bar-2.3.4-1-cp311-cp311-linux_x86_64.whl").unwrap();
        assert_eq!(w.name, "foo_bar");
        assert_eq!(w.version, "2.3.4");
        assert!(parse_wheel_filename("not-a-wheel.txt").is_none());
    }

    #[test]
    fn rejected_outcome_still_carries_partial_evidence() {
        // A rejected wheel must still populate `partial` with the files it could
        // read, so evidence is available even on rejection.
        let bytes = ZipBuilder::new()
            .file("demo/__init__.py", b"ok")
            .file("../escape", b"evil")
            .build();
        let outcome = read_bytes(&bytes, "demo-1.0-py3-none-any.whl");
        match &outcome {
            ArchiveOutcome::Rejected {
                partial,
                violations,
            } => {
                assert!(!violations.is_empty());
                // The benign member was still inspected into the partial.
                assert!(
                    partial
                        .files
                        .iter()
                        .any(|f| f.location.to_string().ends_with("demo/__init__.py")),
                    "partial inspection should carry the readable member as evidence"
                );
            }
            ArchiveOutcome::Accepted(_) => panic!("a traversal member must be Rejected"),
        }
    }

    #[test]
    fn archive_outcome_partial_not_readable_as_clean() {
        // REGRESSION (T3.10): the class-erasing `ArchiveOutcome::inspection()` helper
        // (which returned the inner inspection for BOTH Accepted and Rejected) is
        // gone, so a rejected wheel's `partial` evidence can NEVER be read as a clean
        // inspection. The only way to the evidence is through the `Rejected` arm; the
        // `Accepted` arm yields nothing for a rejected outcome. This is enforced at
        // compile time (there is no longer an accessor that elides the variant); the
        // assertions below pin the runtime behavior.
        let bytes = ZipBuilder::new()
            .file("demo/__init__.py", b"ok")
            .file("../escape", b"evil")
            .build();
        let outcome = read_bytes(&bytes, "demo-1.0-py3-none-any.whl");
        assert!(
            outcome.is_rejected(),
            "a traversal member must make the outcome Rejected"
        );
        // The evidence is reachable ONLY via the Rejected arm. A caller cannot get
        // an `&ArtifactInspection` without first acknowledging the rejection.
        let partial = match &outcome {
            ArchiveOutcome::Rejected { partial, .. } => partial,
            ArchiveOutcome::Accepted(_) => {
                panic!("a rejected wheel must never present as Accepted")
            }
        };
        assert!(
            partial
                .files
                .iter()
                .any(|f| f.location.to_string().ends_with("demo/__init__.py")),
            "the partial still carries readable evidence, but only behind the Rejected variant"
        );
    }

    #[test]
    fn inspection_is_serde_round_trippable() {
        // The Accepted inspection is the A3 model, which must still round-trip.
        let bytes = clean_wheel_bytes();
        let outcome = read_bytes(&bytes, "demo-1.0-py3-none-any.whl");
        let inspection = match &outcome {
            ArchiveOutcome::Accepted(i) => i,
            other => panic!("a clean wheel must be Accepted, got {other:?}"),
        };
        let json = serde_json::to_string(inspection).unwrap();
        let back: ArtifactInspection = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, inspection);
    }
}
