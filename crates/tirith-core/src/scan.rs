use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::engine::{self, AnalysisContext};
use crate::extract::ScanContext;
use crate::location::SubjectLocation;
use crate::tokenize::ShellType;
use crate::verdict::{Finding, Severity};

/// Configuration for a file scan operation.
pub struct ScanConfig {
    /// Path to scan (directory or single file).
    pub path: PathBuf,
    /// Recurse into subdirectories.
    pub recursive: bool,
    /// Severity threshold for CI failure.
    pub fail_on: Severity,
    /// Glob patterns to ignore.
    pub ignore_patterns: Vec<String>,
    /// Include only files matching these patterns (empty = include all).
    pub include_patterns: Vec<String>,
    /// Exclude files matching these patterns (applied after include).
    pub exclude_patterns: Vec<String>,
    /// Max files to scan (None = unlimited).
    pub max_files: Option<usize>,
}

/// Result of a complete scan operation.
pub struct ScanResult {
    pub file_results: Vec<FileScanResult>,
    pub scanned_count: usize,
    pub skipped_count: usize,
    pub truncated: bool,
    pub truncation_reason: Option<String>,
    /// Files skipped specifically because a rule panicked while scanning them
    /// (a subset of `skipped_count`). Surfaced separately so an incomplete scan
    /// is distinguishable from benign size/IO skips and never reads as clean.
    pub panic_files: Vec<PathBuf>,
    /// Every coverage gap (a skipped/unanalyzed file that COULD matter) with a
    /// reason. A `Panicked` gap is recorded here in ADDITION to `panic_files`
    /// (the latter preserves the existing JSON shape). An oversized priority
    /// file, an unreadable file, an unsupported artifact (`.so`/`.whl`/...), or a
    /// file too large to even hash all land here, so a `--json`/SARIF consumer can
    /// see an incomplete scan instead of reading it as clean.
    pub coverage_gaps: Vec<CoverageGap>,
}

/// Result of scanning a single file.
pub struct FileScanResult {
    pub path: PathBuf,
    pub findings: Vec<Finding>,
    pub is_config_file: bool,
}

/// The outcome of attempting to scan one file: it was analyzed, or it was
/// skipped with a recorded reason (a [`CoverageGap`]). Replaces the lossy
/// `Option<FileScanResult>` so a skip can never be silently read as "clean".
pub enum ScanFileOutcome {
    /// The file was read and analyzed.
    Scanned(FileScanResult),
    /// The file was not analyzed; the gap carries why (and a best-effort hash).
    Skipped(CoverageGap),
}

/// The outcome of a panic-guarded single-file scan: either the scan completed
/// (with its own [`ScanFileOutcome`]), or a rule panicked while scanning (also
/// a coverage gap, kind [`CoverageGapKind::Panicked`]). Replaces the
/// `Result<Option<FileScanResult>, RulePanic>` return so the panic case is a
/// first-class coverage gap rather than a bare error.
pub enum GuardedScanOutcome {
    /// The scan ran to completion (it may itself be a `Skipped` outcome).
    Completed(ScanFileOutcome),
    /// A rule panicked; the file was not fully analyzed.
    RulePanic(CoverageGap),
}

/// Why a matched file was NOT fully analyzed. Distinct from an INTENTIONAL
/// exclusion (an ignore/exclude pattern or ordinary media), which is never a
/// gap: a gap means "this could have mattered and we did not cover it".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageGapKind {
    /// File exceeds the analysis size ceiling ([`MAX_FILE_SIZE`]) but is small
    /// enough to hash within [`MAX_COVERAGE_HASH_BYTES`].
    Oversized,
    /// The file could not be opened or read (absent during a race, non-regular,
    /// symlinked final component, or a mid-read I/O error).
    Unreadable,
    /// The file was read only partially before being abandoned (reserved for the
    /// archive/streaming paths in later PRs; not produced by the generic scan).
    Truncated,
    /// A rule panicked while scanning the file.
    Panicked,
    /// A file kind with no analyzer yet (a native/artifact candidate like
    /// `.so`/`.dylib`/`.node`/`.wasm`/`.whl`). B8 adds magic dispatch into the
    /// real artifact scanner; until then these are coverage gaps, not silent drops.
    Unsupported,
    /// The file is larger than [`MAX_COVERAGE_HASH_BYTES`], so even hashing it
    /// would be unbounded; hashing was abandoned (a multi-terabyte file must not
    /// become a hashing DoS). Security-relevant regardless of extension.
    HashBudgetExceeded,
    /// An archive hit its entry-count budget ([`crate::artifact::archive::ArchiveLimits`]),
    /// so members beyond the cap were not inspected. A COVERAGE limit (the
    /// archive is `Accepted` with this gap), not a structural violation.
    EntryCountCapped,
    /// An archive reached its total-uncompressed byte budget while streaming, so
    /// the remaining members were not fully analyzed. A coverage limit, not a
    /// structural violation.
    TotalBytesCapped,
    /// An archive member's REAL streamed compression ratio exceeded the limit
    /// (a zip bomb), so the member was abandoned mid-stream. The declared
    /// uncompressed size is attacker-controlled, so this is enforced on the bytes
    /// actually read, never the declared size.
    CompressionRatioExceeded,
    /// An archive member's uncompressed size exceeds the per-member analysis cap,
    /// so it was not decompressed for analysis (a whole-member hash / streaming
    /// view may still be recorded). A coverage limit.
    MemberTooLarge,
    /// An archive member uses a compression method this build cannot decode (only
    /// deflate/store are enabled), so its content could not be inspected. A
    /// coverage limit, distinct from [`CoverageGapKind::Unsupported`] (a file
    /// KIND with no analyzer): here the bytes are simply undecodable.
    UnsupportedCompression,
    /// A native archive member was handed to the native triage as a streaming
    /// view (whole-member hash plus a printable-string scan) rather than a full
    /// random-access buffer, because it exceeds the native-parse cap; the deep
    /// native analysis is therefore truncated. A coverage limit.
    NativeTruncated,
}

impl CoverageGapKind {
    /// A short stable wire token for JSON/SARIF.
    pub fn as_str(self) -> &'static str {
        match self {
            CoverageGapKind::Oversized => "oversized",
            CoverageGapKind::Unreadable => "unreadable",
            CoverageGapKind::Truncated => "truncated",
            CoverageGapKind::Panicked => "panicked",
            CoverageGapKind::Unsupported => "unsupported",
            CoverageGapKind::HashBudgetExceeded => "hash_budget_exceeded",
            CoverageGapKind::EntryCountCapped => "entry_count_capped",
            CoverageGapKind::TotalBytesCapped => "total_bytes_capped",
            CoverageGapKind::CompressionRatioExceeded => "compression_ratio_exceeded",
            CoverageGapKind::MemberTooLarge => "member_too_large",
            CoverageGapKind::UnsupportedCompression => "unsupported_compression",
            CoverageGapKind::NativeTruncated => "native_truncated",
        }
    }
}

/// A single coverage gap: WHERE the unanalyzed subject is, WHY it was skipped,
/// and a best-effort SHA-256 (lowercase hex) for later hash lookups. `sha256` is
/// `None` when hashing failed or was skipped (e.g. [`CoverageGapKind::Unreadable`]
/// or [`CoverageGapKind::HashBudgetExceeded`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageGap {
    pub location: SubjectLocation,
    pub kind: CoverageGapKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

impl CoverageGap {
    /// The on-disk path most relevant to this gap (outer container or installed
    /// path), for the CI security-relevance and SARIF location decisions.
    pub fn primary_path(&self) -> Option<&Path> {
        self.location
            .outer_path
            .as_deref()
            .or(self.location.installed_path.as_deref())
    }
}

/// AI-specific config basenames scanned first. Generic names (settings.json)
/// are prioritized only inside a known config dir (via the parent-dir check).
const PRIORITY_BASENAMES: &[&str] = &[
    ".cursorrules",
    ".cursorignore",
    ".clinerules",
    ".windsurfrules",
    "CLAUDE.md",
    "AGENTS.md",
    "copilot-instructions.md",
    "mcp.json",
    ".mcp.json",
    "mcp_settings.json",
    "devcontainer.json",
];

/// Parent directories that make generic filenames count as priority.
const PRIORITY_PARENT_DIRS: &[&str] = &[
    ".claude",
    ".vscode",
    ".cursor",
    ".windsurf",
    ".cline",
    ".continue",
    ".github",
    ".devcontainer",
    ".roo",
];

/// Run a file scan operation.
///
/// Detection is always free (ADR-13). `max_files` is a caller-provided safety
/// cap (e.g. for resource-constrained CI), not a license gate.
pub fn scan(config: &ScanConfig) -> ScanResult {
    let collected = collect_files(
        &config.path,
        config.recursive,
        &config.ignore_patterns,
        &config.include_patterns,
        &config.exclude_patterns,
    );
    let mut files = collected.text_candidates;
    // Artifact candidates (`.so`/`.whl`/...) have no analyzer yet; each becomes
    // an `Unsupported` coverage gap so they are never silently dropped.
    let mut coverage_gaps: Vec<CoverageGap> = collected
        .artifact_candidates
        .iter()
        .map(|p| CoverageGap {
            location: SubjectLocation::from_path(p.clone()),
            kind: CoverageGapKind::Unsupported,
            sha256: hash_path_within_budget(p),
        })
        .collect();

    files.sort_by(|a, b| {
        let a_priority = is_priority_file(a);
        let b_priority = is_priority_file(b);
        match (a_priority, b_priority) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.cmp(b),
        }
    });

    let mut truncated = false;
    let mut truncation_reason = None;
    let mut skipped_count = 0;

    if let Some(max) = config.max_files {
        if files.len() > max {
            skipped_count = files.len() - max;
            files.truncate(max);
            truncated = true;
            truncation_reason = Some(format!(
                "Scan capped at {max} files ({skipped_count} skipped)."
            ));
        }
    }

    let mut file_results = Vec::new();
    let mut panic_files = Vec::new();
    for file_path in &files {
        // Panic in any rule is bounded to its file; the rest of the walk
        // continues. A panic is recorded in `panic_files` (not just folded into
        // `skipped_count`) so callers can tell an incomplete scan from benign
        // size/IO skips; it is ALSO pushed as a `Panicked` coverage gap.
        match scan_single_file_guarded(file_path) {
            GuardedScanOutcome::Completed(ScanFileOutcome::Scanned(result)) => {
                file_results.push(result)
            }
            GuardedScanOutcome::Completed(ScanFileOutcome::Skipped(gap)) => {
                skipped_count += 1;
                coverage_gaps.push(gap);
            }
            GuardedScanOutcome::RulePanic(gap) => {
                skipped_count += 1;
                panic_files.push(file_path.clone());
                coverage_gaps.push(gap);
            }
        }
    }

    ScanResult {
        scanned_count: file_results.len(),
        skipped_count,
        truncated,
        truncation_reason,
        panic_files,
        coverage_gaps,
        file_results,
    }
}

/// Maximum analyzable content size: 10 MiB. Large enough for any realistic
/// config/source file, small enough that a hostile `.git/objects/pack-*.pack`
/// (or a huge editor buffer opened via the LSP server) won't blow us up.
/// Exposed so the file-scan path here and the in-memory LSP document path
/// (`tirith` crate `cli::lsp`) enforce the SAME ceiling from one definition.
pub const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum bytes hashed for a coverage gap's SHA-256. A file BETWEEN
/// [`MAX_FILE_SIZE`] and this is too big to analyze but small enough to hash for
/// a later content-addressed lookup (an `Oversized` gap WITH a hash). A file
/// LARGER than this is abandoned with a [`CoverageGapKind::HashBudgetExceeded`]
/// gap (no hash) so a multi-terabyte payload can never become an unbounded
/// hashing DoS. Set well above [`MAX_FILE_SIZE`] (1 GiB) so the common oversized
/// case still yields a usable digest.
pub const MAX_COVERAGE_HASH_BYTES: u64 = 1024 * 1024 * 1024;

/// Classify a file of `size` bytes into the coverage-gap kind for a file that is
/// too large to analyze, deciding ONLY between [`CoverageGapKind::Oversized`]
/// (hashable) and [`CoverageGapKind::HashBudgetExceeded`] (too big to hash).
/// Pure so the budget boundary is unit-testable without a multi-gigabyte file.
fn oversized_gap_kind(size: u64, hash_budget: u64) -> CoverageGapKind {
    if size > hash_budget {
        CoverageGapKind::HashBudgetExceeded
    } else {
        CoverageGapKind::Oversized
    }
}

/// Open `path` no-follow and stream a SHA-256 within [`MAX_COVERAGE_HASH_BYTES`],
/// returning the lowercase-hex digest or `None` on ANY failure (open/read error)
/// or if the file exceeds the budget. Best-effort: a gap with no hash is still a
/// recorded gap. One open + stream from the SAME handle (no stat-then-reopen).
fn hash_path_within_budget(path: &Path) -> Option<String> {
    let file = crate::util::open_read_no_follow_capped(path, u64::MAX).ok()?;
    match crate::util::sha256_from_handle(file, MAX_COVERAGE_HASH_BYTES) {
        Ok(crate::util::HashOutcome::Digest(hex)) => Some(hex),
        Ok(crate::util::HashOutcome::BudgetExceeded) | Err(_) => None,
    }
}

/// Scan a single file and return its [`ScanFileOutcome`].
///
/// A2d — ONE handle, bounded hash. We open ONCE (no-follow, refusing a symlinked
/// final component so a planted symlink can't redirect the read outside the
/// tree), `fstat` THAT open fd, and read/hash from the SAME handle — closing the
/// stat-then-swap-then-read-a-different-file TOCTOU a path-based stat+reopen would
/// leave. Every non-analysis outcome is a typed [`CoverageGap`] (`Oversized`,
/// `HashBudgetExceeded`, `Unreadable`, `Unsupported`) rather than a silent skip,
/// so a skip can never be read as "clean".
pub fn scan_single_file(file_path: &Path) -> ScanFileOutcome {
    let location = SubjectLocation::from_path(file_path.to_path_buf());

    // An artifact candidate (`.so`/`.whl`/...) has no analyzer yet, so it is an
    // `Unsupported` coverage gap even on the DIRECT `scan --file`/single-file path.
    // It must never be read as text. Classified by extension up front (robust to a
    // non-UTF-8 filename) and hashed from the SAME open handle below, never a path
    // reopen, so the recorded digest is exactly the inode we opened.
    let is_artifact_candidate =
        classify_collected_path(file_path) == CollectedFileKind::ArtifactCandidate;

    // Open no-follow with NO byte cap so we get the handle even for an oversized
    // file (we want to classify + hash it, not reject it outright). `open` reads
    // nothing, so a multi-terabyte file is fine here; the size gate is below.
    let file = match crate::util::open_read_no_follow_capped(file_path, u64::MAX) {
        Ok(f) => f,
        Err(crate::util::OpenRegularError::NotFound) => {
            eprintln!(
                "tirith: scan: cannot read {} (not found)",
                file_path.display()
            );
            return ScanFileOutcome::Skipped(CoverageGap {
                location,
                kind: CoverageGapKind::Unreadable,
                sha256: None,
            });
        }
        Err(crate::util::OpenRegularError::NotRegularFile) => {
            eprintln!(
                "tirith: scan: skipping {} (symlink or non-regular file)",
                file_path.display()
            );
            return ScanFileOutcome::Skipped(CoverageGap {
                location,
                kind: CoverageGapKind::Unreadable,
                sha256: None,
            });
        }
        // `TooLarge` cannot occur with a `u64::MAX` cap, but classify it as
        // unreadable for totality rather than panicking.
        Err(crate::util::OpenRegularError::TooLarge)
        | Err(crate::util::OpenRegularError::Io(_)) => {
            eprintln!("tirith: scan: cannot read {}", file_path.display());
            return ScanFileOutcome::Skipped(CoverageGap {
                location,
                kind: CoverageGapKind::Unreadable,
                sha256: None,
            });
        }
    };

    // Artifact candidate: an `Unsupported` coverage gap, hashed from THIS handle
    // (never a path reopen) so the recorded digest is exactly the inode we opened.
    if is_artifact_candidate {
        let sha256 = match crate::util::sha256_from_handle(file, MAX_COVERAGE_HASH_BYTES) {
            Ok(crate::util::HashOutcome::Digest(hex)) => Some(hex),
            Ok(crate::util::HashOutcome::BudgetExceeded) | Err(_) => None,
        };
        return ScanFileOutcome::Skipped(CoverageGap {
            location,
            kind: CoverageGapKind::Unsupported,
            sha256,
        });
    }

    // Size from the OPEN fd (the inode we will read), not a fresh path stat.
    let size = match file.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            eprintln!("tirith: scan: cannot stat {}: {e}", file_path.display());
            return ScanFileOutcome::Skipped(CoverageGap {
                location,
                kind: CoverageGapKind::Unreadable,
                sha256: None,
            });
        }
    };

    // Too large to analyze: record a coverage gap (Oversized, hashed within the
    // budget; or HashBudgetExceeded with no hash for a giant file). Stream the
    // hash from THIS handle so the bytes hashed are exactly the inode we opened.
    if size > MAX_FILE_SIZE {
        let kind = oversized_gap_kind(size, MAX_COVERAGE_HASH_BYTES);
        let sha256 = match kind {
            CoverageGapKind::HashBudgetExceeded => None,
            _ => match crate::util::sha256_from_handle(file, MAX_COVERAGE_HASH_BYTES) {
                Ok(crate::util::HashOutcome::Digest(hex)) => Some(hex),
                Ok(crate::util::HashOutcome::BudgetExceeded) | Err(_) => None,
            },
        };
        eprintln!(
            "tirith: scan: skipping {} (exceeds {}B analysis limit: {})",
            file_path.display(),
            MAX_FILE_SIZE,
            kind.as_str()
        );
        return ScanFileOutcome::Skipped(CoverageGap {
            location,
            kind,
            sha256,
        });
    }

    // Within the analysis ceiling: read the content from the same handle. A
    // mid-read I/O fault is an `Unreadable` gap (not a silent skip).
    let raw_bytes = {
        use std::io::Read as _;
        let mut buf = Vec::with_capacity(size as usize);
        // `take(MAX_FILE_SIZE + 1)` guards against a post-stat grow; a file that
        // grew past the ceiling between the stat and the read is treated as
        // oversized rather than buffered unbounded.
        match (&file)
            .take(MAX_FILE_SIZE.saturating_add(1))
            .read_to_end(&mut buf)
        {
            Ok(_) if buf.len() as u64 > MAX_FILE_SIZE => {
                // Hash from the SAME open handle (matching the oversized arm
                // above), not by re-opening `file_path`: a path reopen here is a
                // TOCTOU window where a swap between the read and the reopen could
                // hash a different inode. The prior read left the cursor at EOF, so
                // rewind to the start before streaming the hash.
                use std::io::Seek as _;
                let sha256 = match (&file).seek(std::io::SeekFrom::Start(0)) {
                    Ok(_) => match crate::util::sha256_from_handle(file, MAX_COVERAGE_HASH_BYTES) {
                        Ok(crate::util::HashOutcome::Digest(hex)) => Some(hex),
                        Ok(crate::util::HashOutcome::BudgetExceeded) | Err(_) => None,
                    },
                    Err(_) => None,
                };
                eprintln!(
                    "tirith: scan: skipping {} (grew past {}B analysis limit during read)",
                    file_path.display(),
                    MAX_FILE_SIZE
                );
                return ScanFileOutcome::Skipped(CoverageGap {
                    location,
                    kind: CoverageGapKind::Oversized,
                    sha256,
                });
            }
            Ok(_) => buf,
            Err(e) => {
                eprintln!("tirith: scan: cannot read {}: {e}", file_path.display());
                return ScanFileOutcome::Skipped(CoverageGap {
                    location,
                    kind: CoverageGapKind::Unreadable,
                    sha256: None,
                });
            }
        }
    };
    let content = String::from_utf8_lossy(&raw_bytes).into_owned();

    let is_config = is_priority_file(file_path);

    let cwd = file_path
        .parent()
        .map(|p| p.display().to_string())
        .filter(|s| !s.is_empty());
    let ctx = AnalysisContext {
        input: content,
        shell: ShellType::Posix,
        scan_context: ScanContext::FileScan,
        raw_bytes: Some(raw_bytes),
        interactive: false,
        cwd: cwd.clone(),
        file_path: Some(file_path.to_path_buf()),
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: crate::clipboard::ClipboardSourceState::Unread,
    };

    let verdict = engine::analyze(&ctx);

    let policy = crate::policy::Policy::discover(cwd.as_deref());
    let mut findings = verdict.findings;
    engine::filter_findings_by_paranoia_vec(&mut findings, policy.paranoia);

    ScanFileOutcome::Scanned(FileScanResult {
        path: file_path.to_path_buf(),
        findings,
        is_config_file: is_config,
    })
}

/// Wrap `f` in `catch_unwind` for the directory walk: on panic, log a skip and
/// return `None` so the caller can record a `Panicked` coverage gap and continue.
/// Only effective in `panic = "unwind"` builds. `AssertUnwindSafe` is sound only
/// while the closure captures no mutable state used after a panic (today: `&Path`
/// + a fn pointer).
fn catch_panic_scanning<T>(file_path: &Path, f: impl FnOnce() -> T) -> Option<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => Some(v),
        Err(_) => {
            eprintln!(
                "tirith: scan: internal error scanning {} (skipped — see panic message above)",
                file_path.display()
            );
            None
        }
    }
}

/// A rule panicked while scanning a file (already reported on stderr by the
/// panic hook + [`catch_panic_scanning`]). Retained for back-compat; the guarded
/// scan now surfaces a panic as a [`CoverageGapKind::Panicked`] gap via
/// [`GuardedScanOutcome::RulePanic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RulePanic;

/// Scan a single file with the same per-file panic guard the directory walk
/// uses, for long-lived/server callers (the MCP server, `policy test`) that must
/// not crash on a crafted file. Returns a [`GuardedScanOutcome`]:
/// - `Completed(Scanned(result))` — the file was analyzed;
/// - `Completed(Skipped(gap))` — skipped with a typed reason (oversized /
///   unreadable / hash-budget);
/// - `RulePanic(gap)` — a rule panicked; the gap's kind is
///   [`CoverageGapKind::Panicked`] so the caller degrades to an error and records
///   the incompleteness instead of unwinding.
///
/// One-shot CLI `scan <file>` may use either this or [`scan_single_file`]
/// directly; the directory walk routes through here so a per-file panic becomes a
/// recorded gap rather than a process crash.
pub fn scan_single_file_guarded(file_path: &Path) -> GuardedScanOutcome {
    match catch_panic_scanning(file_path, || scan_single_file(file_path)) {
        Some(outcome) => GuardedScanOutcome::Completed(outcome),
        None => GuardedScanOutcome::RulePanic(CoverageGap {
            location: SubjectLocation::from_path(file_path.to_path_buf()),
            kind: CoverageGapKind::Panicked,
            sha256: None,
        }),
    }
}

/// Scan content from stdin (no file path).
pub fn scan_stdin(content: &str, raw_bytes: &[u8]) -> FileScanResult {
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    let ctx = AnalysisContext {
        input: content.to_string(),
        shell: ShellType::Posix,
        scan_context: ScanContext::FileScan,
        raw_bytes: Some(raw_bytes.to_vec()),
        interactive: false,
        cwd: cwd.clone(),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: crate::clipboard::ClipboardSourceState::Unread,
    };

    let verdict = engine::analyze(&ctx);

    let policy = crate::policy::Policy::discover(cwd.as_deref());
    let mut findings = verdict.findings;
    engine::filter_findings_by_paranoia_vec(&mut findings, policy.paranoia);

    FileScanResult {
        path: PathBuf::from("<stdin>"),
        findings,
        is_config_file: false,
    }
}

/// Priority if the basename is AI-specific, or the file sits in a known config dir.
fn is_priority_file(path: &Path) -> bool {
    let basename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    if PRIORITY_BASENAMES.contains(&basename) {
        return true;
    }

    if let Some(parent) = path.parent() {
        let parent_name = parent.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if PRIORITY_PARENT_DIRS.contains(&parent_name) {
            return true;
        }
    }

    false
}

/// How the directory walk classifies one regular-file entry during collection.
/// Pulled here from B8 so coverage can SEE files that were previously dropped:
/// an `ArtifactCandidate` (a native/packaging blob with no analyzer yet) becomes
/// an `Unsupported` coverage gap instead of a silent drop, while ordinary media
/// stays a non-gap `BinaryIgnored`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectedFileKind {
    /// Text-like content to scan normally.
    TextCandidate,
    /// A native/packaging artifact (`.so`/`.dylib`/`.node`/`.wasm`/`.whl`) with
    /// no analyzer yet — a coverage gap (B8 adds magic dispatch), not a drop.
    ArtifactCandidate,
    /// Ordinary media (image/audio/video/compiled-bytecode/jar) that is NOT a
    /// security artifact; intentionally ignored and never a coverage gap.
    BinaryIgnored,
}

/// The result of a collection walk: text files to scan plus artifact candidates
/// the caller turns into `Unsupported` coverage gaps. Keeping them separate (not
/// re-deriving from the path list) means the driver never has to re-classify.
struct CollectedFiles {
    text_candidates: Vec<PathBuf>,
    artifact_candidates: Vec<PathBuf>,
}

/// Collect files from a path (directory or single file).
fn collect_files(
    path: &Path,
    recursive: bool,
    ignore_patterns: &[String],
    include_patterns: &[String],
    exclude_patterns: &[String],
) -> CollectedFiles {
    if path.is_file() {
        // A directly-named single file is classified too, so pointing the walk at
        // a `.so` surfaces it as an artifact candidate rather than scanning it as
        // text. (The `scan --file` / `scan <file>` CLI paths handle a directly
        // named file separately; this branch is the directory-collection helper.)
        return match classify_collected_path(path) {
            CollectedFileKind::TextCandidate => CollectedFiles {
                text_candidates: vec![path.to_path_buf()],
                artifact_candidates: Vec::new(),
            },
            CollectedFileKind::ArtifactCandidate => CollectedFiles {
                text_candidates: Vec::new(),
                artifact_candidates: vec![path.to_path_buf()],
            },
            CollectedFileKind::BinaryIgnored => CollectedFiles {
                text_candidates: Vec::new(),
                artifact_candidates: Vec::new(),
            },
        };
    }

    if !path.is_dir() {
        eprintln!("tirith: scan: path does not exist: {}", path.display());
        return CollectedFiles {
            text_candidates: Vec::new(),
            artifact_candidates: Vec::new(),
        };
    }

    let mut collected = CollectedFiles {
        text_candidates: Vec::new(),
        artifact_candidates: Vec::new(),
    };
    collect_files_recursive(
        path,
        path,
        recursive,
        ignore_patterns,
        include_patterns,
        exclude_patterns,
        &mut collected,
    );
    collected
}

/// Enumerate every AI-CONFIG file under `root` — the instruction / config
/// surface (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.claude/*`,
/// `.cursor/rules/*`, `.mcp.json`, …) that `tirith ai snapshot|diff` track.
/// Reuses the standard scan walk (so it honors the same skip-dir / known-config-
/// dir rules), then keeps only paths [`crate::rules::aifile::is_ai_config_file`]
/// recognises. Always recursive. Returns absolute-or-`root`-relative paths
/// deduplicated and sorted for stable output (independent of the walk's order).
/// A single file `root` that is itself an AI-config file yields just that file.
/// AI-config files are always text, so only `text_candidates` is consulted.
pub fn collect_ai_config_files(root: &Path) -> Vec<PathBuf> {
    let mut files = collect_files(root, true, &[], &[], &[]).text_candidates;
    files.retain(|p| crate::rules::aifile::is_ai_config_file(p));
    files.sort();
    files.dedup();
    files
}

fn collect_files_recursive(
    root: &Path,
    dir: &Path,
    recursive: bool,
    ignore_patterns: &[String],
    include_patterns: &[String],
    exclude_patterns: &[String],
    collected: &mut CollectedFiles,
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("tirith: scan: cannot read directory {}: {e}", dir.display());
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!(
                    "tirith: scan: error reading entry in {}: {e}",
                    dir.display()
                );
                continue;
            }
        };
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Classify the entry WITHOUT following symlinks (`entry.file_type()` reports
        // the link itself, not its target). A symlink — to a directory OR a file —
        // is skipped outright so traversal can neither recurse through a symlinked
        // directory out of the tree (e.g. a planted `node_modules -> /`) nor read a
        // file through a symlink that escapes the scan root.
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(e) => {
                eprintln!(
                    "tirith: scan: cannot stat entry {}: {e} (skipped)",
                    path.display()
                );
                continue;
            }
        };
        if file_type.is_symlink() {
            continue;
        }

        if file_type.is_dir() {
            if should_skip_dir(name) && !is_known_config_dir(name) {
                continue;
            }
            if recursive || is_known_config_dir(name) {
                collect_files_recursive(
                    root,
                    &path,
                    recursive,
                    ignore_patterns,
                    include_patterns,
                    exclude_patterns,
                    collected,
                );
            }
            continue;
        }

        // Classify the file. Ordinary media (`BinaryIgnored`) is dropped here,
        // BEFORE the pattern filters — it is never a coverage gap regardless of
        // include/exclude. A `TextCandidate` or `ArtifactCandidate` falls through
        // the pattern filters; only one that PASSES every filter is collected (an
        // ignore/exclude/include miss is an INTENTIONAL exclusion, not a gap).
        let kind = classify_collected_path(&path);
        if kind == CollectedFileKind::BinaryIgnored {
            continue;
        }

        let rel_path = path
            .strip_prefix(root)
            .ok()
            .and_then(|p| p.to_str())
            .unwrap_or(name);
        if ignore_patterns
            .iter()
            .any(|pat| matches_ignore_pattern(name, pat) || matches_ignore_pattern(rel_path, pat))
        {
            continue;
        }

        // Include patterns with negation support: `!`-prefixed patterns exclude
        // from the include set. A file passes if it matches a positive include
        // (or there are none) AND matches no negated pattern.
        if !include_patterns.is_empty() {
            let mut included = false;
            let mut negated = false;
            let has_positive = include_patterns.iter().any(|p| !p.starts_with('!'));

            for pat in include_patterns {
                if let Some(stripped) = pat.strip_prefix('!') {
                    // Negation: exclude from the include set.
                    if matches_ignore_pattern(name, stripped)
                        || matches_ignore_pattern(rel_path, stripped)
                    {
                        negated = true;
                    }
                } else {
                    // Positive: file must match at least one.
                    if matches_ignore_pattern(name, pat) || matches_ignore_pattern(rel_path, pat) {
                        included = true;
                    }
                }
            }

            if negated || (has_positive && !included) {
                continue;
            }
        }

        if exclude_patterns
            .iter()
            .any(|pat| matches_ignore_pattern(name, pat) || matches_ignore_pattern(rel_path, pat))
        {
            continue;
        }

        // Final containment gate: the file's REAL location (resolving every
        // intermediate directory) must stay inside the selected scan root. The
        // per-entry symlink skip above stops a symlinked leaf or directory, but an
        // intermediate-directory symlink planted higher in the walk could still let
        // a regular leaf resolve outside `root`; `canonical_within` (fail-closed)
        // rejects that.
        if !crate::util::canonical_within(&path, root) {
            continue;
        }

        // Route by kind: a passing artifact candidate becomes an `Unsupported`
        // coverage gap (handled by the driver); a passing text candidate is
        // scanned.
        match kind {
            CollectedFileKind::ArtifactCandidate => collected.artifact_candidates.push(path),
            CollectedFileKind::TextCandidate => collected.text_candidates.push(path),
            // Filtered out above.
            CollectedFileKind::BinaryIgnored => {}
        }
    }
}

/// Directories to skip during scanning. Delegates to the shared built-in
/// build-artifact skip set so the scanner and the correlation pass agree.
fn should_skip_dir(name: &str) -> bool {
    crate::util_build_dirs::should_skip_dir(name)
}

/// Known AI config directories that should always be entered.
fn is_known_config_dir(name: &str) -> bool {
    matches!(
        name,
        ".claude"
            | ".vscode"
            | ".cursor"
            | ".windsurf"
            | ".cline"
            | ".continue"
            | ".github"
            | ".devcontainer"
            | ".roo"
    )
}

/// Native/packaging artifact extensions that have NO analyzer yet (A2) but ARE a
/// supply-chain surface, so they become `Unsupported` coverage gaps instead of
/// being silently dropped. B8 extends this into a magic-based dispatch into the
/// real artifact scanner. `.whl`/`.node` were previously read as TEXT (or, for a
/// raw `.so`/`.dylib`/`.wasm`, dropped as binary); both are now coverage gaps.
/// Native / packaging artifact extensions: executable or loadable code with no
/// text analyzer yet, so each is an `Unsupported` coverage gap rather than a
/// silent drop. A `.dll`/`.exe`/`.jar`/`.class` is loadable code too (a Windows
/// native blob, a Java archive, a compiled class), so they belong here next to
/// `.so`, not in `IGNORED_BINARY_EXTENSIONS`, where they would be dropped and
/// hidden from `require_complete`.
const ARTIFACT_EXTENSIONS: &[&str] = &[
    ".so", ".dylib", ".node", ".wasm", ".whl", ".exe", ".dll", ".jar", ".class",
];

/// Ordinary media / compiled-bytecode / generic-archive extensions that are NOT
/// a security artifact and are intentionally ignored (never a coverage gap).
/// `.svg` is deliberately NOT here: an SVG is XML text and can carry an active
/// payload (`<script>`, an `on*` event handler) or an external reference — the
/// `aifile` rules scan it for hidden / smuggled content. `.exe`/`.dll`/`.jar`/
/// `.class` are deliberately NOT here either: they are loadable code and live in
/// `ARTIFACT_EXTENSIONS` so they surface as `Unsupported` coverage gaps.
const IGNORED_BINARY_EXTENSIONS: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".mp3", ".mp4", ".wav", ".avi",
    ".mov", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".o", ".a", ".pyc",
];

/// Classify a filename for collection: an artifact candidate (a native/packaging
/// blob → `Unsupported` gap), ordinary media (`BinaryIgnored`, dropped silently),
/// or text to scan. Artifact extensions are checked FIRST so a `.so` is never
/// mistaken for ignorable media.
fn classify_collected_file(name: &str) -> CollectedFileKind {
    let name_lower = name.to_lowercase();
    if ARTIFACT_EXTENSIONS
        .iter()
        .any(|ext| name_lower.ends_with(ext))
    {
        return CollectedFileKind::ArtifactCandidate;
    }
    if IGNORED_BINARY_EXTENSIONS
        .iter()
        .any(|ext| name_lower.ends_with(ext))
    {
        return CollectedFileKind::BinaryIgnored;
    }
    CollectedFileKind::TextCandidate
}

/// Classify a path, robust to a non-UTF-8 filename. `classify_collected_file`
/// needs a `&str`, so a `to_str().unwrap_or("")` on a non-UTF-8 name would drop it
/// to `TextCandidate` and let a `.so`/`.whl` be read as text. Here a non-UTF-8 name
/// falls back to an extension-only check (the extension is almost always ASCII), so
/// an artifact is still surfaced as a coverage gap instead of silently scanned.
fn classify_collected_path(path: &Path) -> CollectedFileKind {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        return classify_collected_file(name);
    }
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let dotted = format!(".{}", ext.to_lowercase());
        if ARTIFACT_EXTENSIONS.iter().any(|e| *e == dotted) {
            return CollectedFileKind::ArtifactCandidate;
        }
        if IGNORED_BINARY_EXTENSIONS.iter().any(|e| *e == dotted) {
            return CollectedFileKind::BinaryIgnored;
        }
    }
    CollectedFileKind::TextCandidate
}

/// Match a filename against a simple glob: `*.ext`, `prefix*`, `pre*suf`,
/// `*middle*`, or exact. Patterns without `*` fall back to substring match.
pub fn matches_ignore_pattern(name: &str, pattern: &str) -> bool {
    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        match parts.as_slice() {
            [prefix, suffix] if prefix.is_empty() && !suffix.is_empty() => name.ends_with(suffix),
            [prefix, suffix] if !prefix.is_empty() && suffix.is_empty() => name.starts_with(prefix),
            [prefix, suffix] if !prefix.is_empty() && !suffix.is_empty() => {
                name.starts_with(prefix)
                    && name.ends_with(suffix)
                    && name.len() >= prefix.len() + suffix.len()
            }
            [_, _] => true,
            // Multiple wildcards: all parts must appear in order.
            _ => {
                let mut remaining = name;
                for (i, part) in parts.iter().enumerate() {
                    if part.is_empty() {
                        continue;
                    }
                    if i == 0 {
                        if !remaining.starts_with(part) {
                            return false;
                        }
                        remaining = &remaining[part.len()..];
                    } else if let Some(pos) = remaining.find(part) {
                        remaining = &remaining[pos + part.len()..];
                    } else {
                        return false;
                    }
                }
                true
            }
        }
    } else {
        name.contains(pattern)
    }
}

impl ScanResult {
    /// Check if any finding meets or exceeds the given severity threshold.
    pub fn has_findings_at_or_above(&self, threshold: Severity) -> bool {
        self.file_results
            .iter()
            .flat_map(|r| &r.findings)
            .any(|f| f.severity >= threshold)
    }

    /// Total number of findings across all files.
    pub fn total_findings(&self) -> usize {
        self.file_results.iter().map(|r| r.findings.len()).sum()
    }
}

/// Security-relevant file extensions for coverage purposes: a skipped file with
/// one of these is treated as a SECURITY-relevant gap (it could carry executable
/// or supply-chain content), so `require_complete` / a Fail action must surface
/// it. Lockfiles and workflow YAML are matched by basename/path separately.
/// `.dll`/`.exe`/`.jar`/`.class`/`.whl` are here for the same reason as `.so`: each
/// is loadable code or a packaging artifact with no analyzer yet (a `.whl` the wheel
/// reader cannot inspect is an `Unsupported` gap), so an unanalyzed one must not read
/// as clean (they are also `ARTIFACT_EXTENSIONS`, so the scan records them as
/// `Unsupported` gaps in the first place).
const SECURITY_RELEVANT_EXTENSIONS: &[&str] = &[
    ".so", ".pth", ".start", ".dylib", ".node", ".wasm", ".whl", ".sh", ".ps1", ".dll", ".exe",
    ".jar", ".class",
];

/// Lockfile / workflow basenames or path fragments that make a gap security
/// relevant regardless of extension.
fn path_is_security_relevant(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_lowercase();

    // Common ecosystem lockfiles.
    const LOCKFILES: &[&str] = &[
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "cargo.lock",
        "gemfile.lock",
        "composer.lock",
        "go.sum",
        "requirements.txt",
        "pipfile.lock",
    ];
    if LOCKFILES.contains(&name.as_str()) {
        return true;
    }

    // Workflow YAML lives under `.github/workflows/`.
    let lossy = path.to_string_lossy().replace('\\', "/").to_lowercase();
    if lossy.contains(".github/workflows/") && (name.ends_with(".yml") || name.ends_with(".yaml")) {
        return true;
    }

    false
}

/// Build the `AnalysisIncomplete` findings for a set of coverage gaps under
/// `policy` (cross-cutting invariant 1: the driver assembles the user-facing
/// finding; the gaps are the internal signals). One finding per SECURITY-relevant
/// gap whose effective action is not [`crate::policy::GapAction::Ignore`]:
/// Medium normally, High when that effective action is `Fail` (whence the action
/// derives to Block). A non-security-relevant gap (e.g. an oversized ordinary
/// text file) is still recorded in `coverage_gaps` for `--json`/SARIF but emits
/// no finding, so benign size skips do not become noise.
pub fn build_analysis_incomplete_findings(
    gaps: &[CoverageGap],
    policy: &crate::policy::Policy,
) -> Vec<Finding> {
    build_analysis_incomplete_findings_located(gaps, policy)
        .into_iter()
        .map(|(_loc, finding)| finding)
        .collect()
}

/// Like [`build_analysis_incomplete_findings`], but each returned finding is
/// paired with the EXACT [`SubjectLocation`] of the gap it was assembled from.
///
/// The driver needs this pairing to attach each finding to its own file entry:
/// matching back by a substring of the finding's `description` is wrong because
/// one gap's location string can be a PREFIX of another's (e.g. `/a/b.so` is a
/// substring of `/a/b.so.bak`), so a substring match resolves to the wrong
/// member. Carrying the location alongside the finding lets the caller resolve by
/// EXACT equality.
///
/// Each gap is finalized through `finalize_static_verdict` INDIVIDUALLY, which is
/// equivalent to finalizing the whole batch for this rule: the finalizer's passes
/// (per-rule `severity_overrides` / `action_overrides`, then a paranoia filter
/// keyed on the finding's own severity) all act per finding, none depends on how
/// many other `AnalysisIncomplete` findings are in the set. Per-gap finalization
/// is what makes the exact pairing trivially correct: a finding either survives
/// for its gap or it does not, with no cross-gap reordering to reconcile.
pub fn build_analysis_incomplete_findings_located(
    gaps: &[CoverageGap],
    policy: &crate::policy::Policy,
) -> Vec<(SubjectLocation, Finding)> {
    let mut out = Vec::new();
    for gap in gaps {
        // Cross-cutting invariant 5: route each gap's assembled finding(s) through
        // the shared static-verdict finalizer so a policy `severity_overrides` /
        // `action_overrides` on `analysis_incomplete` is honored here, exactly as
        // on every other static-verdict site (ecosystem scan, artifact
        // evaluation). AnalysisIncomplete is Medium/High, kept at the default
        // paranoia, so the paranoia pass is a no-op unless the operator raised it.
        let raw = assemble_analysis_incomplete_findings(std::slice::from_ref(gap), policy);
        if raw.is_empty() {
            continue;
        }
        let verdict = crate::escalation::finalize_static_verdict(
            raw,
            policy,
            3,
            crate::verdict::Timings::default(),
        );
        for finding in verdict.findings {
            out.push((gap.location.clone(), finding));
        }
    }
    out
}

/// Assemble the raw `AnalysisIncomplete` findings (one per security-relevant,
/// non-ignored gap) BEFORE policy override finalization. Split out so
/// [`build_analysis_incomplete_findings`] can route them through
/// `finalize_static_verdict`.
fn assemble_analysis_incomplete_findings(
    gaps: &[CoverageGap],
    policy: &crate::policy::Policy,
) -> Vec<Finding> {
    use crate::policy::GapAction;
    use crate::verdict::{Evidence, RuleId};

    let mut findings = Vec::new();
    for gap in gaps {
        if !gap_is_security_relevant(gap) {
            continue;
        }
        let action = policy.scan.action_for_gap_kind(gap.kind);
        if action == GapAction::Ignore {
            continue;
        }
        let severity = if action == GapAction::Fail {
            Severity::High
        } else {
            Severity::Medium
        };
        let location = gap.location.to_string();
        let detail = match gap.sha256.as_deref() {
            Some(hash) => format!("{} ({}); sha256={hash}", location, gap.kind.as_str()),
            None => format!("{} ({})", location, gap.kind.as_str()),
        };
        findings.push(Finding {
            rule_id: RuleId::AnalysisIncomplete,
            severity,
            title: "Scan coverage incomplete".to_string(),
            description: format!(
                "A security-relevant file was not fully analyzed ({}): {}. \
                 The result is not provably clean for this file.",
                gap.kind.as_str(),
                location
            ),
            evidence: vec![Evidence::Text { detail }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }
    findings
}

/// Whether a single coverage gap is SECURITY-relevant: a priority/config file, a
/// security-extension file (`.so`/`.pth`/...), a lockfile/workflow, OR a
/// [`CoverageGapKind::HashBudgetExceeded`] gap (a giant file is suspicious on its
/// own, so the hash budget can never hide a payload from `require_complete`).
pub fn gap_is_security_relevant(gap: &CoverageGap) -> bool {
    // A file too big to even hash is security relevant no matter the extension.
    if gap.kind == CoverageGapKind::HashBudgetExceeded {
        return true;
    }
    let Some(path) = gap.primary_path() else {
        // No on-disk path to judge (e.g. an archive member without an outer path):
        // treat as security relevant so a gap is never silently dismissed.
        return true;
    };
    if is_priority_file(path) {
        return true;
    }
    // `to_string_lossy` (not `to_str`): a non-UTF-8 file name (`café.so` carrying raw
    // Latin-1 bytes) must still match by its ASCII extension. `to_str().unwrap_or_default()`
    // would yield "" and let a security-relevant `.so`/`.dylib` gap slip past the
    // extension gate; lossy conversion preserves the ASCII extension exactly.
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default()
        .to_lowercase();
    if SECURITY_RELEVANT_EXTENSIONS
        .iter()
        .any(|ext| name.ends_with(ext))
    {
        return true;
    }
    path_is_security_relevant(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catch_panic_scanning_returns_some_on_clean_run() {
        let path = Path::new("dummy");
        let result = catch_panic_scanning(path, || 42_i32);
        assert_eq!(result, Some(42));
    }

    /// Serializes tests that mutate the global panic hook so concurrent swaps
    /// don't race each other's restore. Tolerates poisoning.
    static PANIC_HOOK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn catch_panic_scanning_returns_none_on_panic() {
        let _lock = PANIC_HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = Path::new("dummy");
        // Suppress the default panic-hook output for this intentional panic.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result: Option<i32> = catch_panic_scanning(path, || {
            panic!("simulated rule panic");
        });
        std::panic::set_hook(prev);
        assert!(result.is_none(), "panic must produce None, got {result:?}");
    }

    #[test]
    fn scan_single_file_guarded_non_panic_paths() {
        // A readable file scans to Completed(Scanned(_)); the panic arm is
        // exercised by `catch_panic_scanning_returns_none_on_panic` above.
        let tmp = tempfile::tempdir().expect("create temp dir");
        let file_path = tmp.path().join("note.md");
        std::fs::write(&file_path, "hello world").expect("write temp file");
        assert!(matches!(
            scan_single_file_guarded(&file_path),
            GuardedScanOutcome::Completed(ScanFileOutcome::Scanned(_))
        ));

        // An unreadable/missing file is a coverage gap (Unreadable), NOT a panic.
        let missing = tmp.path().join("does_not_exist.md");
        assert!(matches!(
            scan_single_file_guarded(&missing),
            GuardedScanOutcome::Completed(ScanFileOutcome::Skipped(CoverageGap {
                kind: CoverageGapKind::Unreadable,
                ..
            }))
        ));
    }

    #[test]
    fn test_file_classification() {
        // Ordinary media stays BinaryIgnored (dropped, never a gap).
        assert_eq!(
            classify_collected_file("image.png"),
            CollectedFileKind::BinaryIgnored
        );
        assert_eq!(
            classify_collected_file("archive.tar.gz"),
            CollectedFileKind::BinaryIgnored
        );
        // Native/packaging artifacts become ArtifactCandidate (→ Unsupported gap).
        assert_eq!(
            classify_collected_file("native.abi3.so"),
            CollectedFileKind::ArtifactCandidate
        );
        assert_eq!(
            classify_collected_file("pkg-1.0-py3-none-any.whl"),
            CollectedFileKind::ArtifactCandidate
        );
        assert_eq!(
            classify_collected_file("addon.node"),
            CollectedFileKind::ArtifactCandidate
        );
        assert_eq!(
            classify_collected_file("MOD.DYLIB"),
            CollectedFileKind::ArtifactCandidate
        );
        // Text-like content scans normally.
        assert_eq!(
            classify_collected_file("config.json"),
            CollectedFileKind::TextCandidate
        );
        assert_eq!(
            classify_collected_file("CLAUDE.md"),
            CollectedFileKind::TextCandidate
        );
        // SVG is XML text — it must NOT be skipped as binary, so the `aifile`
        // rules can scan it for active / hidden content.
        assert_eq!(
            classify_collected_file("logo.svg"),
            CollectedFileKind::TextCandidate
        );
        assert_eq!(
            classify_collected_file("ICON.SVG"),
            CollectedFileKind::TextCandidate
        );
    }

    #[test]
    fn test_svg_active_content_visible_in_scan() {
        // An SVG carrying a <script> must be collected (not skipped as binary)
        // and flagged by the aifile rules.
        let tmp = tempfile::tempdir().expect("create temp dir");
        let file_path = tmp.path().join("evil.svg");
        std::fs::write(
            &file_path,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><script>fetch('/x')</script></svg>"#,
        )
        .expect("write temp file");

        let result = match scan_single_file(&file_path) {
            ScanFileOutcome::Scanned(r) => r,
            other => panic!("scan should succeed, got a skip: {:?}", other_kind(&other)),
        };
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.rule_id == crate::verdict::RuleId::SvgScriptEmbedded),
            "SVG with embedded script should be flagged: {:?}",
            result.findings
        );
    }

    /// Small test helper: the gap kind of a `Skipped` outcome (for assertion
    /// messages); `None` for a `Scanned` outcome.
    fn other_kind(outcome: &ScanFileOutcome) -> Option<CoverageGapKind> {
        match outcome {
            ScanFileOutcome::Scanned(_) => None,
            ScanFileOutcome::Skipped(gap) => Some(gap.kind),
        }
    }

    #[test]
    fn test_priority_file_detection() {
        // AI-specific basenames are always priority
        assert!(is_priority_file(Path::new(".cursorrules")));
        assert!(is_priority_file(Path::new("CLAUDE.md")));
        assert!(is_priority_file(Path::new("mcp.json")));
        assert!(!is_priority_file(Path::new("README.md")));

        // Generic filenames are priority only inside known config dirs
        assert!(!is_priority_file(Path::new("settings.json")));
        assert!(!is_priority_file(Path::new("config.json")));
        assert!(is_priority_file(Path::new(".claude/settings.json")));
        assert!(is_priority_file(Path::new(".vscode/settings.json")));
        assert!(is_priority_file(Path::new(".roo/rules.md")));
    }

    #[test]
    fn test_skip_dirs() {
        assert!(should_skip_dir(".git"));
        assert!(should_skip_dir("node_modules"));
        assert!(should_skip_dir("target"));
        // New build-artifact dirs from the shared skip set.
        assert!(should_skip_dir("out"));
        assert!(should_skip_dir(".turbo"));
        assert!(should_skip_dir("coverage"));
        assert!(should_skip_dir(".expo"));
        assert!(!should_skip_dir("src"));
        assert!(!should_skip_dir(".vscode"));
    }

    #[test]
    fn test_new_build_artifact_dirs_skipped_in_walk() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let root = tmp.path();

        // A source file that must be collected.
        std::fs::write(root.join("keep.md"), "hello").unwrap();

        // Build-artifact dirs whose contents must be skipped during the walk.
        for dir in ["out", ".turbo", "coverage", ".expo"] {
            let sub = root.join(dir);
            std::fs::create_dir(&sub).unwrap();
            std::fs::write(sub.join("artifact.md"), "generated").unwrap();
        }

        let files = collect_files(root, true, &[], &[], &[]).text_candidates;
        let names: Vec<&str> = files
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
            .collect();

        assert!(names.contains(&"keep.md"), "keep.md should be collected");
        assert!(
            !names.contains(&"artifact.md"),
            "files under out/.turbo/coverage/.expo should be skipped, got {names:?}"
        );
    }

    #[test]
    fn test_known_config_dirs() {
        assert!(is_known_config_dir(".claude"));
        assert!(is_known_config_dir(".vscode"));
        assert!(is_known_config_dir(".cursor"));
        assert!(!is_known_config_dir("src"));
        assert!(!is_known_config_dir(".git"));
    }

    #[test]
    fn test_ignore_pattern_matching() {
        // Suffix glob
        assert!(matches_ignore_pattern("test.log", "*.log"));
        assert!(!matches_ignore_pattern("test.txt", "*.log"));

        // Prefix glob
        assert!(matches_ignore_pattern("test_output.txt", "test_*"));
        assert!(!matches_ignore_pattern("my_test.txt", "test_*"));

        // Contains (no wildcard — backward compatible)
        assert!(matches_ignore_pattern("my_test_file.txt", "test"));
        assert!(!matches_ignore_pattern("readme.md", "test"));

        // Prefix + suffix glob
        assert!(matches_ignore_pattern("test_file.log", "test_*.log"));
        assert!(!matches_ignore_pattern("test_file.txt", "test_*.log"));

        // Exact match
        assert!(matches_ignore_pattern("Cargo.lock", "Cargo.lock"));

        // Path-aware patterns (matched against relative paths)
        assert!(matches_ignore_pattern(".claude/settings.json", ".claude/*"));
        assert!(!matches_ignore_pattern("src/main.rs", ".claude/*"));
        assert!(matches_ignore_pattern("docs/CLAUDE.md", "*/CLAUDE.md"));
        assert!(!matches_ignore_pattern("README.md", "*/CLAUDE.md"));
    }

    #[test]
    fn test_variation_selector_visible_in_scan() {
        // Variation selector U+FE0F (EF B8 8F) in a temp dir with no policy.
        let tmp = tempfile::tempdir().expect("create temp dir");
        let file_path = tmp.path().join("test_vs.txt");
        std::fs::write(&file_path, b"A\xef\xb8\x8f").expect("write temp file");

        let result = match scan_single_file(&file_path) {
            ScanFileOutcome::Scanned(r) => r,
            other => panic!("scan should succeed, got a skip: {:?}", other_kind(&other)),
        };

        // VariationSelector is Medium, so it must survive the default paranoia filter.
        let policy = crate::policy::Policy::discover(Some(tmp.path().to_str().unwrap()));
        let mut findings = result.findings;
        crate::engine::filter_findings_by_paranoia_vec(&mut findings, policy.paranoia);

        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == crate::verdict::RuleId::VariationSelector),
            "VariationSelector should be visible in scan at default paranoia: {findings:?}"
        );
    }

    #[test]
    fn test_negated_include_patterns() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        std::fs::write(tmp.path().join("a.md"), "hello").unwrap();
        std::fs::write(tmp.path().join("b.test.md"), "world").unwrap();
        std::fs::write(tmp.path().join("c.rs"), "fn main() {}").unwrap();

        // Include *.md but exclude *.test.md via negation
        let files = collect_files(
            tmp.path(),
            false,
            &[],
            &["*.md".to_string(), "!*.test.md".to_string()],
            &[],
        )
        .text_candidates;

        let names: Vec<&str> = files
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
            .collect();
        assert!(names.contains(&"a.md"), "a.md should be included");
        assert!(
            !names.contains(&"b.test.md"),
            "b.test.md should be excluded by negation"
        );
        assert!(
            !names.contains(&"c.rs"),
            "c.rs should not match *.md include"
        );
    }

    /// F15: a SYMLINKED directory under the scan root must NOT be traversed, so a
    /// planted `subdir -> /outside` cannot pull files from outside the tree into
    /// the walk.
    #[cfg(unix)]
    #[test]
    fn symlinked_directory_is_not_traversed() {
        let root = tempfile::tempdir().expect("create scan root");
        let outside = tempfile::tempdir().expect("create outside tree");
        // A uniquely-named file OUTSIDE the scan root.
        std::fs::write(outside.path().join("escaped_unique_name.md"), "secret").unwrap();
        // A real in-tree file that SHOULD be collected.
        std::fs::write(root.path().join("inside.md"), "ok").unwrap();
        // root/link_dir -> <outside>.
        std::os::unix::fs::symlink(outside.path(), root.path().join("link_dir")).unwrap();

        let files = collect_files(root.path(), true, &[], &[], &[]).text_candidates;
        let names: Vec<&str> = files
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
            .collect();
        assert!(
            names.contains(&"inside.md"),
            "the in-tree file must be collected"
        );
        assert!(
            !names.contains(&"escaped_unique_name.md"),
            "a file reached only via a symlinked directory must not be collected: {names:?}"
        );
    }

    /// F15: a SYMLINKED file is skipped by the walk, and a direct
    /// `scan_single_file` on a symlink refuses to read THROUGH it (`O_NOFOLLOW`),
    /// so neither path discloses a file the link points at outside the tree.
    #[cfg(unix)]
    #[test]
    fn symlinked_file_is_not_read_through() {
        let root = tempfile::tempdir().expect("create scan root");
        let outside = tempfile::tempdir().expect("create outside tree");
        let target = outside.path().join("leak.md");
        std::fs::write(&target, "SECRET_LEAK_CONTENT").unwrap();
        // root/leak.md -> <outside>/leak.md.
        let link = root.path().join("leak.md");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // The walk skips the symlinked leaf entirely.
        let files = collect_files(root.path(), true, &[], &[], &[]).text_candidates;
        assert!(
            files
                .iter()
                .all(|p| p.file_name().and_then(|n| n.to_str()) != Some("leak.md")),
            "a symlinked file must not be collected by the walk: {files:?}"
        );
        // And reading the symlink path directly is refused (no read-through): a
        // symlinked final component is an `Unreadable` coverage gap, NOT a scan.
        assert!(
            matches!(
                scan_single_file(&link),
                ScanFileOutcome::Skipped(CoverageGap {
                    kind: CoverageGapKind::Unreadable,
                    ..
                })
            ),
            "scan_single_file must refuse to read through a symlinked final component"
        );
    }

    #[test]
    fn test_negation_only_include_patterns() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        std::fs::write(tmp.path().join("a.md"), "hello").unwrap();
        std::fs::write(tmp.path().join("b.test.md"), "world").unwrap();
        std::fs::write(tmp.path().join("c.rs"), "fn main() {}").unwrap();

        // Only negation patterns (no positive includes) — include everything
        // except negated patterns
        let files =
            collect_files(tmp.path(), false, &[], &["!*.test.md".to_string()], &[]).text_candidates;

        let names: Vec<&str> = files
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
            .collect();
        assert!(names.contains(&"a.md"), "a.md should be included");
        assert!(
            !names.contains(&"b.test.md"),
            "b.test.md should be excluded by negation"
        );
        assert!(
            names.contains(&"c.rs"),
            "c.rs should be included (no positive filter)"
        );
    }

    // ---- A2: coverage gaps, classification, hashing, security relevance ----

    /// An oversized priority/text file (> `MAX_FILE_SIZE`) yields an `Oversized`
    /// coverage gap whose sha256 equals an independent Rust-computed digest.
    /// NEVER shells out to `sha256sum`.
    #[test]
    fn oversized_priority_file_is_oversized_gap_with_matching_hash() {
        use sha2::{Digest, Sha256};
        let tmp = tempfile::tempdir().expect("create temp dir");
        // A PRIORITY file (CLAUDE.md) just over the analysis ceiling.
        let file_path = tmp.path().join("CLAUDE.md");
        let body = vec![b'x'; (MAX_FILE_SIZE as usize) + 16];
        std::fs::write(&file_path, &body).expect("write oversized file");

        let gap = match scan_single_file(&file_path) {
            ScanFileOutcome::Skipped(gap) => gap,
            ScanFileOutcome::Scanned(_) => panic!("an oversized file must be a coverage gap"),
        };
        assert_eq!(gap.kind, CoverageGapKind::Oversized);
        // The gap location points at the file.
        assert_eq!(
            gap.location.outer_path.as_deref(),
            Some(file_path.as_path())
        );

        // The recorded hash matches an independent digest of the whole file.
        let expected: String = Sha256::digest(&body)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(gap.sha256.as_deref(), Some(expected.as_str()));

        // And it is security-relevant (a priority file), so it drives a finding.
        assert!(gap_is_security_relevant(&gap));
    }

    /// A `.so` is classified as an artifact candidate during collection and
    /// surfaces as an `Unsupported` coverage gap (never scanned as text, never a
    /// silent drop).
    #[test]
    fn native_so_is_unsupported_coverage_gap() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        std::fs::write(tmp.path().join("keep.md"), "hello").unwrap();
        // A native extension with some bytes so it can be hashed.
        let so = tmp.path().join("payload.abi3.so");
        std::fs::write(&so, b"\x7fELF not-really-but-enough").unwrap();

        let result = scan(&ScanConfig {
            path: tmp.path().to_path_buf(),
            recursive: true,
            fail_on: Severity::Critical,
            ignore_patterns: vec![],
            include_patterns: vec![],
            exclude_patterns: vec![],
            max_files: None,
        });

        let so_gap = result
            .coverage_gaps
            .iter()
            .find(|g| g.primary_path() == Some(so.as_path()))
            .expect("the .so must be recorded as a coverage gap");
        assert_eq!(so_gap.kind, CoverageGapKind::Unsupported);
        // A `.so` IS a security-relevant extension.
        assert!(gap_is_security_relevant(so_gap));
        // The ordinary text file was still scanned (not dropped by classification).
        assert!(result
            .file_results
            .iter()
            .any(|r| r.path.file_name().and_then(|n| n.to_str()) == Some("keep.md")));
    }

    /// The hash-budget boundary: a size over `MAX_COVERAGE_HASH_BYTES` classifies
    /// as `HashBudgetExceeded` (so a giant file is never hashed unbounded), while
    /// a size within it stays `Oversized`. Tested via the pure classifier so no
    /// multi-gigabyte file is created.
    #[test]
    fn hash_budget_boundary_classifies_correctly() {
        // Use a small synthetic budget for the boundary check.
        let budget = 1024;
        assert_eq!(
            oversized_gap_kind(budget, budget),
            CoverageGapKind::Oversized,
            "exactly at the budget is hashable (Oversized)"
        );
        assert_eq!(
            oversized_gap_kind(budget + 1, budget),
            CoverageGapKind::HashBudgetExceeded,
            "one byte over the budget is HashBudgetExceeded"
        );
        // A `HashBudgetExceeded` gap is security-relevant regardless of extension.
        let gap = CoverageGap {
            location: SubjectLocation::from_path("/tmp/huge.bin"),
            kind: CoverageGapKind::HashBudgetExceeded,
            sha256: None,
        };
        assert!(
            gap_is_security_relevant(&gap),
            "a too-big-to-hash file is security relevant on its own"
        );
    }

    /// An unreadable file (here a directory passed to `scan_single_file`, which
    /// the regular-file gate rejects) yields an `Unreadable` gap with no hash.
    #[test]
    fn unreadable_path_is_unreadable_gap() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        // A directory is not a regular file: the no-follow regular-file gate
        // refuses it, which the scan classifies as Unreadable.
        let gap = match scan_single_file(tmp.path()) {
            ScanFileOutcome::Skipped(gap) => gap,
            ScanFileOutcome::Scanned(_) => panic!("a directory must not scan as a file"),
        };
        assert_eq!(gap.kind, CoverageGapKind::Unreadable);
        assert!(gap.sha256.is_none(), "an unreadable file has no hash");
    }

    /// A non-security-relevant oversized text file is recorded as a gap but emits
    /// NO `AnalysisIncomplete` finding under the default policy (so benign size
    /// skips do not become noise), while a security-relevant gap does.
    #[test]
    fn analysis_incomplete_findings_gate_on_security_relevance() {
        let policy = crate::policy::Policy::default();

        // A plain (non-priority, non-security-extension) oversized text file.
        let benign = CoverageGap {
            location: SubjectLocation::from_path("/tmp/notes.txt"),
            kind: CoverageGapKind::Oversized,
            sha256: Some("deadbeef".into()),
        };
        assert!(!gap_is_security_relevant(&benign));
        assert!(
            build_analysis_incomplete_findings(std::slice::from_ref(&benign), &policy).is_empty(),
            "a benign oversized text file emits no finding by default"
        );

        // A security-relevant gap (a `.so`) emits a Medium AnalysisIncomplete.
        let so_gap = CoverageGap {
            location: SubjectLocation::from_path("/tmp/x.so"),
            kind: CoverageGapKind::Unsupported,
            sha256: None,
        };
        let findings = build_analysis_incomplete_findings(std::slice::from_ref(&so_gap), &policy);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].rule_id,
            crate::verdict::RuleId::AnalysisIncomplete
        );
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    /// When the effective policy action for a gap class is `Fail`, the
    /// `AnalysisIncomplete` finding is High (whence the action derives to Block);
    /// an `Ignore` action suppresses the finding entirely.
    #[test]
    fn analysis_incomplete_severity_follows_policy_action() {
        use crate::policy::GapAction;
        let so_gap = CoverageGap {
            location: SubjectLocation::from_path("/tmp/x.so"),
            kind: CoverageGapKind::Unsupported,
            sha256: None,
        };

        // Fail -> High.
        let mut policy = crate::policy::Policy::default();
        policy.scan.unsupported_artifact_action = Some(GapAction::Fail);
        let findings = build_analysis_incomplete_findings(std::slice::from_ref(&so_gap), &policy);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);

        // Ignore -> no finding.
        let mut policy = crate::policy::Policy::default();
        policy.scan.unsupported_artifact_action = Some(GapAction::Ignore);
        assert!(
            build_analysis_incomplete_findings(std::slice::from_ref(&so_gap), &policy).is_empty(),
            "an ignored gap class emits no finding"
        );
    }

    /// A directly-named `.so` passed to `scan_single_file` (the `scan --file`
    /// path) is an `Unsupported` coverage gap with a best-effort hash, NOT scanned
    /// as text.
    #[test]
    fn scan_single_file_on_artifact_is_unsupported_gap() {
        use sha2::{Digest, Sha256};
        let tmp = tempfile::tempdir().expect("create temp dir");
        let so = tmp.path().join("lib.so");
        let bytes = b"\x7fELF some native bytes";
        std::fs::write(&so, bytes).unwrap();

        let gap = match scan_single_file(&so) {
            ScanFileOutcome::Skipped(gap) => gap,
            ScanFileOutcome::Scanned(_) => panic!("a .so must not be scanned as text"),
        };
        assert_eq!(gap.kind, CoverageGapKind::Unsupported);
        let expected: String = Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(gap.sha256.as_deref(), Some(expected.as_str()));
    }

    /// A directly-named single `.so` file passed to the collection helper is
    /// classified as an artifact candidate (not scanned as text).
    #[test]
    fn directly_named_artifact_file_is_artifact_candidate() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let so = tmp.path().join("lib.so");
        std::fs::write(&so, b"bytes").unwrap();
        let collected = collect_files(&so, false, &[], &[], &[]);
        assert!(
            collected.text_candidates.is_empty(),
            "a .so must not be a text candidate"
        );
        assert_eq!(
            collected.artifact_candidates,
            vec![so],
            "a directly named .so is an artifact candidate"
        );
    }

    /// A `.whl` is an `Unsupported` artifact gap AND security-relevant, so an
    /// unanalyzable wheel can't read as clean (CodeRabbit #152: `.whl` was missing
    /// from `SECURITY_RELEVANT_EXTENSIONS`).
    #[test]
    fn whl_unsupported_gap_is_security_relevant() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let whl = tmp.path().join("pkg-1.0-py3-none-any.whl");
        std::fs::write(&whl, b"PK\x03\x04 not a real wheel").unwrap();
        let gap = match scan_single_file(&whl) {
            ScanFileOutcome::Skipped(gap) => gap,
            ScanFileOutcome::Scanned(_) => panic!("a .whl must not be scanned as text"),
        };
        assert_eq!(gap.kind, CoverageGapKind::Unsupported);
        assert!(
            gap_is_security_relevant(&gap),
            "a .whl gap must be security-relevant"
        );
    }

    /// A non-UTF-8 filename with an artifact extension is still an `ArtifactCandidate`
    /// (CodeRabbit #152: a `to_str().unwrap_or("")` previously dropped it to text).
    #[test]
    #[cfg(unix)]
    fn non_utf8_artifact_name_is_classified_as_artifact() {
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::OsStr::from_bytes(b"caf\xe9.so"); // invalid UTF-8 + .so
        assert_eq!(
            classify_collected_path(std::path::Path::new(name)),
            CollectedFileKind::ArtifactCandidate
        );
    }

    /// A coverage gap whose path is a non-UTF-8 artifact name (`café.so`) is still
    /// security-relevant: the extension gate must read the name lossily, not drop it to
    /// "" via `to_str` and let it slip past `require_complete` (CodeRabbit #152).
    #[test]
    #[cfg(unix)]
    fn non_utf8_gap_path_is_security_relevant() {
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::OsStr::from_bytes(b"caf\xe9.so"); // invalid UTF-8 + .so
        let gap = CoverageGap {
            location: SubjectLocation::from_path(std::path::Path::new(name)),
            kind: CoverageGapKind::Unsupported,
            sha256: None,
        };
        assert!(
            gap_is_security_relevant(&gap),
            "a non-UTF-8 .so gap must be security-relevant"
        );
    }

    /// An artifact candidate matched by an explicit exclude pattern is an
    /// INTENTIONAL exclusion, not a coverage gap (so a repo can opt a `.so` out).
    #[test]
    fn excluded_artifact_is_not_a_gap() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        std::fs::write(tmp.path().join("keep.md"), "hi").unwrap();
        std::fs::write(tmp.path().join("vendor.so"), b"bytes").unwrap();

        let collected = collect_files(
            tmp.path(),
            true,
            &[],
            &[],
            &["*.so".to_string()], // exclude the artifact explicitly
        );
        assert!(
            collected.artifact_candidates.is_empty(),
            "an explicitly excluded .so is an intentional exclusion, not a gap"
        );
    }

    /// T2.7: `.dll`/`.exe`/`.jar`/`.class` are LOADABLE CODE, so a tree
    /// containing one records an `Unsupported` coverage gap (the same treatment as
    /// a `.so`) rather than a silent `BinaryIgnored` drop. A silent drop would make
    /// a planted native blob read as "clean" and slip past `require_complete`.
    #[test]
    fn dll_exe_jar_are_unsupported_gaps_not_clean() {
        // Each loadable-code extension classifies as an artifact candidate.
        for name in ["evil.dll", "evil.exe", "evil.jar", "evil.class"] {
            assert_eq!(
                classify_collected_file(name),
                CollectedFileKind::ArtifactCandidate,
                "{name} must be an artifact candidate, not BinaryIgnored"
            );
        }

        // A directory tree containing `evil.dll` surfaces an Unsupported gap.
        let tmp = tempfile::tempdir().expect("create temp dir");
        std::fs::write(tmp.path().join("readme.md"), "hi").unwrap();
        std::fs::write(tmp.path().join("evil.dll"), b"MZ native bytes").unwrap();

        let config = ScanConfig {
            path: tmp.path().to_path_buf(),
            recursive: true,
            fail_on: Severity::High,
            ignore_patterns: Vec::new(),
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
            max_files: None,
        };
        let result = scan(&config);

        let dll_gap = result
            .coverage_gaps
            .iter()
            .find(|g| {
                g.primary_path()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    == Some("evil.dll")
            })
            .expect("evil.dll must be recorded as a coverage gap");
        assert_eq!(
            dll_gap.kind,
            CoverageGapKind::Unsupported,
            "a .dll is an Unsupported coverage gap, not silently dropped"
        );

        // The gap is security-relevant, so `require_complete` (a Fail action) would
        // surface a finding: it must NOT read as clean.
        let mut policy = crate::policy::Policy::default();
        policy.scan.unsupported_artifact_action = Some(crate::policy::GapAction::Fail);
        let findings = build_analysis_incomplete_findings(&result.coverage_gaps, &policy);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == crate::verdict::RuleId::AnalysisIncomplete
                    && f.severity == Severity::High),
            "the .dll gap must yield a High AnalysisIncomplete finding under require_complete"
        );
    }

    /// T2.8: the grow-during-read recovery hashes from the ALREADY-OPEN handle
    /// (rewound to the start), NOT by re-opening the path. Hashing from the same
    /// fd is the TOCTOU-safety point: a path swap between the read and a reopen
    /// could otherwise substitute a different inode. This proves the recovery
    /// digests the bytes the OPEN handle holds, independent of what the path
    /// resolves to.
    #[test]
    fn grow_during_read_hashes_from_same_handle() {
        use sha2::{Digest, Sha256};
        use std::io::{Read as _, Seek as _};

        let tmp = tempfile::tempdir().expect("create temp dir");
        let path = tmp.path().join("payload.bin");
        let handle_bytes = b"the exact bytes the open handle holds";
        std::fs::write(&path, handle_bytes).unwrap();

        // Open the SAME way `scan_single_file` does, then advance the cursor to
        // mimic the grow-detection read that leaves the fd at EOF.
        let file = crate::util::open_read_no_follow_capped(&path, u64::MAX).expect("open handle");
        let mut sink = Vec::new();
        (&file)
            .take(8)
            .read_to_end(&mut sink)
            .expect("partial read");

        // SWAP the inode at `path` by atomically renaming a different file over it.
        // The open `file` fd keeps the ORIGINAL inode (its bytes survive the
        // unlink), while the PATH now resolves to NEW, different content, so a
        // path-based re-open would hash the wrong bytes. (A plain truncate-rewrite
        // of the same path would modify the same inode the fd sees, defeating the
        // test, so the swap must replace the inode.)
        let swapped_bytes = b"COMPLETELY DIFFERENT CONTENT ON DISK";
        let decoy = tmp.path().join("decoy.bin");
        std::fs::write(&decoy, swapped_bytes).unwrap();
        std::fs::rename(&decoy, &path).expect("atomic swap of the path's inode");

        // The recovery used by the grow arm: rewind the handle, hash from it.
        (&file).seek(std::io::SeekFrom::Start(0)).expect("rewind");
        let recovered = match crate::util::sha256_from_handle(file, MAX_COVERAGE_HASH_BYTES) {
            Ok(crate::util::HashOutcome::Digest(hex)) => hex,
            other => panic!("expected a digest from the handle, got {other:?}"),
        };

        let from_handle: String = Sha256::digest(handle_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let from_reopened_path: String = Sha256::digest(swapped_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            recovered, from_handle,
            "the hash must be of the bytes read from the handle"
        );
        assert_ne!(
            recovered, from_reopened_path,
            "the hash must NOT be of a re-opened path's (swapped) content"
        );
    }

    /// T2.13: when several gaps' location strings are PREFIXES of one another
    /// (`/a/b.so` is a substring of `/a/b.so.bak`), each finding still resolves to
    /// its OWN exact member: the located builder pairs every finding with the exact
    /// `SubjectLocation` of its gap, so resolution is by exact equality, not a
    /// substring of the description.
    #[test]
    fn analysis_incomplete_finding_path_resolves_nested_member() {
        let policy = crate::policy::Policy::default();
        // Both are security-relevant (`.so`), and `/a/b.so` is a CONTIGUOUS
        // substring of `/a/b.so.extra.so`, the exact prefix collision a
        // description-substring match would mislabel.
        let gap_a = CoverageGap {
            location: SubjectLocation::from_path("/a/b.so"),
            kind: CoverageGapKind::Unsupported,
            sha256: None,
        };
        let gap_b = CoverageGap {
            location: SubjectLocation::from_path("/a/b.so.extra.so"),
            kind: CoverageGapKind::Unsupported,
            sha256: None,
        };
        // Guard the premise: the first location really is a substring of the
        // second, so a `description.contains(loc)` match WOULD collide.
        assert!(
            gap_b
                .location
                .to_string()
                .contains(&gap_a.location.to_string()),
            "test premise: /a/b.so must be a substring of /a/b.so.extra.so"
        );

        let located =
            build_analysis_incomplete_findings_located(&[gap_a.clone(), gap_b.clone()], &policy);
        assert_eq!(located.len(), 2, "one finding per security-relevant gap");

        // Each finding is paired with its OWN exact location, even though
        // `/a/b.so` is a substring of `/a/b.so.extra.so`.
        let loc_a = &located[0].0;
        let loc_b = &located[1].0;
        assert_eq!(loc_a, &gap_a.location);
        assert_eq!(loc_b, &gap_b.location);
        assert_eq!(
            loc_a.outer_path.as_deref(),
            Some(std::path::Path::new("/a/b.so"))
        );
        assert_eq!(
            loc_b.outer_path.as_deref(),
            Some(std::path::Path::new("/a/b.so.extra.so"))
        );
        assert_ne!(
            loc_a, loc_b,
            "the nested member must NOT collapse onto its prefix sibling"
        );
    }
}
