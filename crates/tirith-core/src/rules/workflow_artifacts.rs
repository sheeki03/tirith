//! Cross-workflow GitHub Actions artifact-flow analysis: the Safe/Bybit-class
//! build-output trust break, where an untrusted contributor's workflow uploads
//! a build artifact and a privileged `workflow_run` consumer downloads it from
//! the triggering run and then executes, sources, PATH-mutates, publishes, or
//! deploys it.
//!
//! This is a REPOSITORY post-pass, not a per-file rule. No single workflow file
//! can prove a producer-to-consumer chain, so [`build_model`] reduces each
//! workflow to a bounded [`WorkflowModel`] and [`analyze_repository`] correlates
//! the models. `crate::scan::scan` owns the plumbing; nothing here reads the
//! filesystem or the network.
//!
//! Precision is the point. A `High` requires the FULL proven chain:
//!
//! ```text
//! fork/PR-reachable untrusted producer
//!   -> uploads an artifact under a statically known name
//!   -> privileged `workflow_run` consumer bound to the TRIGGERING run
//!   -> matching artifact identity
//!   -> execute / source / PATH-mutation / publish / deploy sink
//! ```
//!
//! Anything less is represented as INCOMPLETENESS, never guessed: an expression,
//! a wildcard, a reusable workflow, a composite action, a matrix job, an `if:`
//! condition, a download mechanism or a post-download command outside the
//! modelled tables, an artifact re-upload hop, a digest comparison whose
//! expected value cannot be placed, or a shell the analyzer cannot resolve all
//! record an unresolved note, which blocks the presence-level downgrade in
//! [`RepositoryFlowResult`] (and, where the unknown sits on the producer side,
//! the `High` as well).
//!
//! Containment is what proves an execute / source / PATH-mutation sink touched
//! the artifact's bytes, so the extraction directory has to be the REAL one:
//! `actions/download-artifact`, `dawidd6/action-download-artifact`, and
//! `gh run download` each fan every artifact of the run into its own
//! `<path>/<artifact-name>/` subdirectory unless they are given exactly one
//! artifact name.
//!
//! Every function here is total: a malformed or hostile workflow yields no
//! findings, never a panic. The parsed-YAML helpers, the untrusted-expression
//! model, and the shell resolution are reused from [`super::cifile`] rather than
//! restated, so the two surfaces cannot drift apart.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_yaml::Value;

use super::cifile;
use super::command;
use crate::tokenize::{self, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Maximum number of workflows retained for the repository post-pass.
pub const MAX_WORKFLOWS: usize = 256;

/// Maximum aggregate YAML source retained across every modelled workflow.
pub const MAX_TOTAL_WORKFLOW_BYTES: usize = 32 * 1024 * 1024;

/// Maximum aggregate step count modelled across every workflow.
pub const MAX_TOTAL_STEPS: usize = 4096;

/// Per-`run:`-body tokenizer bounds. A `run:` body is attacker-authorable text
/// on the producer side and merely long on the consumer side; both are capped so
/// one pathological body cannot dominate the post-pass.
const MAX_SEGMENTS_PER_RUN: usize = 512;
const MAX_WORDS_PER_SEGMENT: usize = 256;
const MAX_WORD_BYTES: usize = 4096;

/// Per-workflow structural bounds. YAML aliases and anchors expand during the
/// parse, so the modelled job/step/upload counts are capped independently of the
/// file size that produced them.
const MAX_JOBS_PER_WORKFLOW: usize = 512;
const MAX_UPLOADS_PER_WORKFLOW: usize = 256;
const MAX_EVENTS_PER_JOB: usize = 512;
const MAX_UNRESOLVED_NOTES: usize = 32;

/// The bounded resource whose exhaustion made a [`WorkflowModel`] partial.
///
/// A model may record more than one reason when independent structural bounds
/// are crossed. Callers that only need the legacy complete/partial distinction
/// can continue to use [`WorkflowModel::steps_truncated`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum WorkflowTruncationReason {
    /// The per-workflow job limit was exhausted before every job was visited.
    JobBudgetExhausted,
    /// The per-job retained flow-event limit was exhausted.
    EventBudgetExhausted,
    /// The caller-provided repository step allowance was exhausted.
    StepBudgetExhausted,
    /// The per-workflow retained-upload limit was exhausted.
    UploadBudgetExhausted,
}

/// Evidence text ceiling, matching the sibling workflow rules.
const EVIDENCE_CHARS: usize = 160;

/// The artifact name `actions/upload-artifact` writes when `with.name` is
/// omitted.
const DEFAULT_UPLOAD_ARTIFACT_NAME: &str = "artifact";

/// The artifact name `actions/upload-pages-artifact` writes when `with.name` is
/// omitted.
const DEFAULT_PAGES_ARTIFACT_NAME: &str = "github-pages";

/// Triggers that put a fork's / a pull request author's content into the run
/// that produces the artifact. A workflow whose only triggers are `push`,
/// `schedule`, or `workflow_dispatch` is not reachable by an untrusted
/// contributor and must never participate in a proven chain.
const FORK_REACHABLE_TRIGGERS: &[&str] = &["pull_request", "pull_request_target"];

/// `${{ }}` / script contexts that resolve to the id of the run that TRIGGERED a
/// `workflow_run` consumer. A download bound to one of these reads the untrusted
/// producer run's own output; a fixed run id or an unrelated context does not.
const TRIGGERING_RUN_MARKERS: &[&str] = &[
    "github.event.workflow_run.id",
    "context.payload.workflow_run.id",
];

/// `uses:` actions whose whole purpose is to publish or deploy what is in the
/// workspace. Kept deliberately small: each entry is a well-known action whose
/// documented effect is to ship the workspace contents outward.
const PUBLISH_DEPLOY_ACTIONS: &[(&str, SinkKind)] = &[
    ("pypa/gh-action-pypi-publish", SinkKind::Publish),
    ("softprops/action-gh-release", SinkKind::Publish),
    ("ncipollo/release-action", SinkKind::Publish),
    ("actions/deploy-pages", SinkKind::Deploy),
    ("peaceiris/actions-gh-pages", SinkKind::Deploy),
    ("jamesives/github-pages-deploy-action", SinkKind::Deploy),
];

/// How precisely an artifact name is known.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ArtifactName {
    /// A literal name, statically resolved.
    Resolved(String),
    /// The step covers EVERY artifact of the run (a `download-artifact` with no
    /// `name:`), so it matches any resolved producer name.
    All,
    /// An expression, a glob/regexp pattern, or a name this analyzer refuses to
    /// guess at.
    Unresolved,
}

/// An `actions/upload-artifact` (or `actions/upload-pages-artifact`) step.
#[derive(Debug, Clone)]
struct ArtifactUpload {
    name: ArtifactName,
    /// The step carries an `if:` this analyzer does not evaluate, so whether a
    /// fork's pull request produces this artifact AT ALL is unknown. Such an
    /// upload can never complete a proven chain; it only removes the right to
    /// claim there is none.
    conditional: bool,
    detail: String,
}

/// A download step proven to fetch artifacts from the run that triggered this
/// `workflow_run` consumer.
#[derive(Debug, Clone)]
struct ArtifactDownload {
    name: ArtifactName,
    /// Extraction directory as a normalized workspace-relative path (`""` is the
    /// workspace root). `None` when the destination is not statically knowable.
    dest: Option<String>,
    /// Whether the mechanism fans EACH artifact of the run into its own
    /// `<dest>/<artifact-name>/` subdirectory. `actions/download-artifact@v4`,
    /// `dawidd6/action-download-artifact`, and `gh run download` all do this
    /// whenever they are not given exactly one artifact name, so the bytes of
    /// artifact `X` land under `<dest>/X` and NOT under `<dest>` itself.
    per_artifact_subdir: bool,
    detail: String,
}

/// What a consumer does with the downloaded bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SinkKind {
    /// Runs a file from the workspace as a program or interpreter script.
    Execute,
    /// Dot-sources a file into the current shell.
    Source,
    /// Appends to `$GITHUB_PATH` / `$GITHUB_ENV`, which makes every LATER step
    /// resolve binaries (or read env such as `LD_PRELOAD`) from the named place.
    PathMutation,
    /// Publishes the workspace contents to a package registry or a release.
    Publish,
    /// Deploys the workspace contents to infrastructure.
    Deploy,
}

impl SinkKind {
    fn as_str(self) -> &'static str {
        match self {
            SinkKind::Execute => "execute",
            SinkKind::Source => "source",
            SinkKind::PathMutation => "PATH mutation",
            SinkKind::Publish => "publish",
            SinkKind::Deploy => "deploy",
        }
    }

    /// Whether the sink must name an operand inside the download directory.
    /// Execute / source / PATH mutation act on a NAMED path, so containment is
    /// what proves the bytes came from the artifact. Publish and deploy ship the
    /// workspace outward wholesale, so the download itself is the taint.
    fn requires_contained_operand(self) -> bool {
        matches!(
            self,
            SinkKind::Execute | SinkKind::Source | SinkKind::PathMutation
        )
    }
}

#[derive(Debug, Clone)]
struct ArtifactSink {
    kind: SinkKind,
    /// Workspace-relative operand when the sink names one.
    operand: Option<String>,
    detail: String,
}

/// Where a digest / attestation comparison read its EXPECTED value from.
#[derive(Debug, Clone)]
enum DigestSource {
    /// Outside the workspace entirely: an attestation service, a signature
    /// keyring, or a literal digest written in the workflow text. No downloaded
    /// byte can influence it.
    OutOfBand,
    /// A workspace-relative file the comparison reads the expected digests from.
    Workspace(String),
    /// A path operand this analyzer could not place (absolute, `$VAR`, or an
    /// expression). Whether the downloaded artifact wrote it is UNKNOWN, which
    /// is not the same as knowing it did not.
    Unplaceable,
}

/// What a digest comparison proves about the bytes that follow it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DigestTrust {
    /// The expected value is beyond the artifact's reach, so later use is safe.
    Trusted,
    /// The expected value lives inside the downloaded tree, so the artifact
    /// supplied both the payload and the digests it is checked against.
    SelfSupplied,
    /// Neither could be established.
    Unknown,
}

/// A digest / attestation comparison performed between a download and a sink.
#[derive(Debug, Clone)]
struct DigestVerification {
    source: DigestSource,
    detail: String,
}

impl DigestVerification {
    /// What this comparison proves relative to a download destination. A
    /// checksum file that the downloaded artifact could itself have written is
    /// worthless: it establishes nothing and must not suppress the finding.
    /// A comparison whose operand or destination cannot be placed proves
    /// nothing EITHER WAY, so it must be reported as incompleteness rather than
    /// read as a passing check.
    fn trust(&self, dest: Option<&str>) -> DigestTrust {
        match (&self.source, dest) {
            (DigestSource::OutOfBand, _) => DigestTrust::Trusted,
            (DigestSource::Workspace(path), Some(dest)) => {
                if path_under(dest, path) {
                    DigestTrust::SelfSupplied
                } else {
                    DigestTrust::Trusted
                }
            }
            _ => DigestTrust::Unknown,
        }
    }
}

/// One ordered observation inside a consumer job. Order is what makes
/// "verified BEFORE dangerous use" and "sink AFTER download" decidable.
#[derive(Debug, Clone)]
enum FlowEvent {
    Download(ArtifactDownload),
    Verify(DigestVerification),
    Sink(ArtifactSink),
    /// An `actions/upload-artifact` step. After a download it re-publishes bytes
    /// of unknown provenance under a NEW artifact identity, which this pass does
    /// not follow into the next workflow.
    Reupload,
    /// A command that ran after a download and that this analyzer does not
    /// classify. It may relocate the artifact (`tar`, `unzip`, `cp`), install it
    /// (`pip install`, `npm ci`), or do nothing at all; the point is that the
    /// analyzer cannot tell, so it must not be counted as "nothing happened".
    Unmodelled,
}

#[derive(Debug, Clone, Default)]
struct JobModel {
    events: Vec<FlowEvent>,
    /// More flow-relevant events existed than the bounded model could retain.
    /// Kept separate from `unresolved` so the repository driver also emits its
    /// typed truncation coverage gap.
    events_truncated: bool,
    /// Static resolution failed somewhere in this job (an unresolvable shell, a
    /// truncated tokenizer budget, a reusable workflow, a composite action, or a
    /// matrix leg), so the job can neither prove nor disprove a chain.
    unresolved: bool,
}

/// Which producer workflows a `workflow_run` consumer is bound to, taken from
/// `on.workflow_run.workflows`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConsumedWorkflows {
    /// Not a `workflow_run` consumer at all.
    NotAConsumer,
    /// A statically resolved set of producer workflow NAMES.
    Names(BTreeSet<String>),
    /// Absent, a glob, or an expression: the producer set is not knowable.
    Unresolved,
}

/// The bounded, parsed-once projection of one workflow file that the repository
/// post-pass correlates. Holds no file bytes: only the facts the flow analysis
/// needs plus the byte/step counts the caller charges against its budget.
#[derive(Debug, Clone)]
pub struct WorkflowModel {
    path: PathBuf,
    /// The workflow's declared `name:`, which is what a consumer's
    /// `on.workflow_run.workflows` list matches against.
    display_name: Option<String>,
    triggers: BTreeSet<String>,
    consumes: ConsumedWorkflows,
    uploads: Vec<ArtifactUpload>,
    jobs: Vec<JobModel>,
    unresolved: Vec<String>,
    step_count: usize,
    steps_truncated: bool,
    truncation_reasons: BTreeSet<WorkflowTruncationReason>,
    source_bytes: usize,
    parse_failed: bool,
}

impl WorkflowModel {
    /// The workflow's on-disk path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Steps modelled from this workflow, for the repository step budget.
    pub fn step_count(&self) -> usize {
        self.step_count
    }

    /// Source bytes this workflow contributed, for the aggregate byte budget.
    /// The bytes themselves are NOT retained.
    pub fn source_bytes(&self) -> usize {
        self.source_bytes
    }

    /// Whether any bounded job, step, or upload collection ran out part-way
    /// through this workflow, so its own model is partial.
    pub fn steps_truncated(&self) -> bool {
        self.steps_truncated
    }

    /// Exact bounded resources that made this model partial, in deterministic
    /// order. This is additive to [`WorkflowModel::steps_truncated`].
    pub fn truncation_reasons(
        &self,
    ) -> impl ExactSizeIterator<Item = WorkflowTruncationReason> + '_ {
        self.truncation_reasons.iter().copied()
    }

    /// Whether this workflow is reachable by an untrusted contributor.
    fn fork_reachable(&self) -> bool {
        FORK_REACHABLE_TRIGGERS
            .iter()
            .any(|t| self.triggers.contains(*t))
    }

    /// Whether the presence-level `workflow_run` rule fires on this workflow.
    fn is_workflow_run_consumer(&self) -> bool {
        self.triggers.contains("workflow_run")
    }

    /// Whether any modelled part of this workflow left the artifact flow
    /// unresolved. Some structural failures carry a workflow note while bounded
    /// event parsing records the uncertainty directly on the affected job.
    fn artifact_flow_unresolved(&self) -> bool {
        !self.unresolved.is_empty() || self.jobs.iter().any(|job| job.unresolved)
    }

    fn note(&mut self, note: String) {
        if self.unresolved.len() < MAX_UNRESOLVED_NOTES && !self.unresolved.contains(&note) {
            self.unresolved.push(note);
        }
    }

    fn mark_truncated(&mut self, reason: WorkflowTruncationReason) {
        self.steps_truncated = true;
        self.truncation_reasons.insert(reason);
    }
}

/// Build the bounded model for one workflow file's already-decoded content.
///
/// `step_budget` is the caller's REMAINING repository-wide step allowance; the
/// walk stops when it is exhausted and records [`WorkflowModel::steps_truncated`]
/// so the caller can turn that into a coverage gap. A file that does not parse
/// as a YAML mapping still yields a model (with `parse_failed` set) so the
/// repository pass knows a workflow existed that it could not see into.
pub fn build_model(path: &Path, content: &str, step_budget: usize) -> WorkflowModel {
    let mut model = WorkflowModel {
        path: path.to_path_buf(),
        display_name: None,
        triggers: BTreeSet::new(),
        consumes: ConsumedWorkflows::NotAConsumer,
        uploads: Vec::new(),
        jobs: Vec::new(),
        unresolved: Vec::new(),
        step_count: 0,
        steps_truncated: false,
        truncation_reasons: BTreeSet::new(),
        source_bytes: content.len(),
        parse_failed: false,
    };

    let Ok(doc) = serde_yaml::from_str::<Value>(content) else {
        model.parse_failed = true;
        model.note("workflow YAML did not parse".to_string());
        return model;
    };
    if doc.as_mapping().is_none() {
        model.parse_failed = true;
        model.note("workflow root is not a mapping".to_string());
        return model;
    }

    model.display_name = cifile::get_field(&doc, "name")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.contains("${{"));
    model.triggers = cifile::workflow_triggers(&doc);
    model.consumes = consumed_workflows(&doc, &model.triggers);

    let Some(jobs) = cifile::get_field(&doc, "jobs").and_then(Value::as_mapping) else {
        return model;
    };

    let mut remaining_steps = step_budget;
    for (index, (job_key, job)) in jobs.iter().enumerate() {
        if index >= MAX_JOBS_PER_WORKFLOW {
            model.mark_truncated(WorkflowTruncationReason::JobBudgetExhausted);
            break;
        }
        let job_name = job_key.as_str().unwrap_or("<job>").to_string();

        // A job-level `uses:` calls a reusable workflow whose upload/download/
        // sink steps live in a file this job graph does not contain.
        if let Some(reused) = cifile::get_field(job, "uses").and_then(Value::as_str) {
            model.note(format!(
                "job '{}' calls reusable workflow '{}'",
                cifile::truncate(&job_name, 60),
                cifile::truncate(reused, 80)
            ));
            model.jobs.push(JobModel {
                events: Vec::new(),
                events_truncated: false,
                unresolved: true,
            });
            continue;
        }

        let has_matrix = cifile::get_field(job, "strategy")
            .and_then(|s| cifile::get_field(s, "matrix"))
            .is_some();

        let mut job_model = JobModel::default();
        let Some(steps) = cifile::get_field(job, "steps").and_then(Value::as_sequence) else {
            model.jobs.push(job_model);
            continue;
        };

        let mut job_touches_artifacts = false;
        for step in steps {
            if remaining_steps == 0 {
                model.mark_truncated(WorkflowTruncationReason::StepBudgetExhausted);
                job_model.unresolved = true;
                break;
            }
            remaining_steps -= 1;
            model.step_count += 1;

            let uploads_before = model.uploads.len();
            let events_before = job_model.events.len();

            if let Some(uses) = cifile::get_field(step, "uses").and_then(Value::as_str) {
                match classify_uses_step(uses, step) {
                    UsesRole::Upload(upload) => {
                        job_touches_artifacts = true;
                        // Ordered, so a download followed by an upload is
                        // distinguishable from an upload that precedes it.
                        push_event(&mut job_model, FlowEvent::Reupload);
                        if model.uploads.len() < MAX_UPLOADS_PER_WORKFLOW {
                            model.uploads.push(upload);
                        } else {
                            model.mark_truncated(WorkflowTruncationReason::UploadBudgetExhausted);
                        }
                    }
                    UsesRole::CrossRunDownload(download) => {
                        job_touches_artifacts = true;
                        push_event(&mut job_model, FlowEvent::Download(download));
                    }
                    UsesRole::Sink(sink) => push_event(&mut job_model, FlowEvent::Sink(sink)),
                    UsesRole::Unresolved(reason) => {
                        job_touches_artifacts = true;
                        job_model.unresolved = true;
                        model.note(reason);
                    }
                    UsesRole::Irrelevant => {}
                }
            } else if let Some(script) = cifile::get_field(step, "run").and_then(Value::as_str) {
                match cifile::workflow_step_shell(&doc, job, step) {
                    Ok(shell) => {
                        if analyze_run_body(script, shell, &mut job_model) {
                            job_model.unresolved = true;
                        }
                    }
                    Err(reason) => {
                        job_model.unresolved = true;
                        model.note(format!(
                            "unresolved step shell: {}",
                            cifile::truncate(&reason, 90)
                        ));
                    }
                }
            }

            // A step guarded by an `if:` this analyzer does not evaluate may not
            // run on a fork's pull request at all, so a flow fact it contributes
            // is a possibility, not a fact. `if: github.event_name == 'push'` on
            // an upload step is exactly how a producer is kept off fork PRs.
            let contributed_upload = model.uploads.len() != uploads_before;
            let contributed = contributed_upload || job_model.events.len() != events_before;
            if contributed && step_condition_constrains_reachability(step) {
                job_touches_artifacts = true;
                job_model.unresolved = true;
                if contributed_upload {
                    if let Some(upload) = model.uploads.last_mut() {
                        upload.conditional = true;
                    }
                }
                model.note(format!(
                    "step in job '{}' runs under an unevaluated `if:` condition",
                    cifile::truncate(&job_name, 60)
                ));
            }
        }

        // A job-level `if:` is where the documented `workflow_run` mitigation
        // (`head_repository.full_name == github.repository`) lives, so a job the
        // analyzer cannot decide the reachability of proves nothing either way.
        if (job_touches_artifacts || !job_model.events.is_empty())
            && condition_constrains_reachability(cifile::get_field(job, "if"))
        {
            job_model.unresolved = true;
            model.note(format!(
                "job '{}' runs under an unevaluated `if:` condition",
                cifile::truncate(&job_name, 60)
            ));
        }

        // A matrix fans one job definition into legs whose artifact identity and
        // step set are per-leg. Only say so when the job actually touches the
        // artifact flow, so ordinary matrix builds stay quiet.
        if has_matrix && (job_touches_artifacts || !job_model.events.is_empty()) {
            job_model.unresolved = true;
            model.note(format!(
                "matrix job '{}' fans out per leg",
                cifile::truncate(&job_name, 60)
            ));
        }

        if job_model.events_truncated {
            model.mark_truncated(WorkflowTruncationReason::EventBudgetExhausted);
        }
        model.jobs.push(job_model);
    }

    model
}

/// `if:` conditions that cannot constrain whether a FORK's pull request reaches
/// a step or a job: the run-status gates every `workflow_run` consumer writes,
/// and the `conclusion` check GitHub's own `workflow_run` documentation shows.
/// Everything else narrows reachability by something this analyzer does not
/// evaluate, so it becomes incompleteness rather than a guess in either
/// direction.
const REACHABILITY_NEUTRAL_CONDITIONS: &[&str] =
    &["success()", "always()", "failure()", "cancelled()", "true"];

/// Whether a step's `if:` narrows reachability in a way this analyzer cannot
/// evaluate.
fn step_condition_constrains_reachability(step: &Value) -> bool {
    condition_constrains_reachability(cifile::get_field(step, "if"))
}

/// Whether an `if:` node narrows reachability in a way this analyzer cannot
/// evaluate. An absent condition constrains nothing.
fn condition_constrains_reachability(node: Option<&Value>) -> bool {
    let Some(node) = node else {
        return false;
    };
    let Some(text) = node.as_str() else {
        // A bare `if: true` always runs; any other non-string form is one this
        // analyzer does not read, so it counts as a constraint.
        return !matches!(node, Value::Bool(true));
    };
    let normalized: String = text
        .replace("${{", " ")
        .replace("}}", " ")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    // A disjunct that is neutral WIDENS the condition, so the conjunct-by-
    // conjunct reading below does not hold for `||`; refuse to decide instead.
    if normalized.contains("||") {
        return true;
    }
    !normalized.split("&&").all(|conjunct| {
        let atom = conjunct.trim_start_matches('!');
        REACHABILITY_NEUTRAL_CONDITIONS.contains(&atom)
            || atom.starts_with("github.event.workflow_run.conclusion==")
            || atom.starts_with("github.event.workflow_run.conclusion!=")
    })
}

fn push_event(job: &mut JobModel, event: FlowEvent) {
    if job.events.len() < MAX_EVENTS_PER_JOB {
        job.events.push(event);
    } else {
        job.unresolved = true;
        job.events_truncated = true;
    }
}

/// The producer workflow NAMES a `workflow_run` consumer binds to.
fn consumed_workflows(doc: &Value, triggers: &BTreeSet<String>) -> ConsumedWorkflows {
    if !triggers.contains("workflow_run") {
        return ConsumedWorkflows::NotAConsumer;
    }
    let Some(on) = cifile::workflow_on_value(doc) else {
        return ConsumedWorkflows::Unresolved;
    };
    let Some(map) = on.as_mapping() else {
        // `on: workflow_run` as a bare scalar/sequence declares no `workflows:`
        // list at all, so the producer set is unknown.
        return ConsumedWorkflows::Unresolved;
    };
    let Some(node) = map
        .iter()
        .find_map(|(k, v)| k.as_str().filter(|s| *s == "workflow_run").map(|_| v))
    else {
        return ConsumedWorkflows::Unresolved;
    };
    let Some(list) = cifile::get_field(node, "workflows") else {
        return ConsumedWorkflows::Unresolved;
    };
    let mut names = BTreeSet::new();
    let mut push = |raw: &str| -> bool {
        let value = raw.trim();
        if value.is_empty() || value.contains("${{") || value.contains(['*', '?', '[']) {
            return false;
        }
        names.insert(value.to_string());
        true
    };
    match list {
        Value::String(s) => {
            if !push(s) {
                return ConsumedWorkflows::Unresolved;
            }
        }
        Value::Sequence(items) => {
            for item in items {
                match item.as_str() {
                    Some(s) if push(s) => {}
                    _ => return ConsumedWorkflows::Unresolved,
                }
            }
        }
        _ => return ConsumedWorkflows::Unresolved,
    }
    if names.is_empty() {
        return ConsumedWorkflows::Unresolved;
    }
    ConsumedWorkflows::Names(names)
}

/// What a `uses:` step means for the artifact flow.
enum UsesRole {
    Upload(ArtifactUpload),
    CrossRunDownload(ArtifactDownload),
    Sink(ArtifactSink),
    /// The step moves flow-relevant work somewhere this analyzer cannot see.
    Unresolved(String),
    Irrelevant,
}

fn classify_uses_step(uses: &str, step: &Value) -> UsesRole {
    let raw = cifile::strip_quotes(uses).trim();
    // A repository-local composite action's own `action.yml` is not a
    // `.github/workflows/*.yml` file, so its steps are never modelled here.
    if raw.starts_with("./") || raw.starts_with("../") {
        return UsesRole::Unresolved(format!(
            "local action '{}' is not part of the workflow job graph",
            cifile::truncate(raw, 80)
        ));
    }
    let Some(parsed) = cifile::parse_uses(raw) else {
        return UsesRole::Irrelevant;
    };
    let repo = parsed.repo.to_ascii_lowercase();
    let with = cifile::get_field(step, "with");

    match repo.as_str() {
        "actions/upload-artifact" => {
            return UsesRole::Upload(ArtifactUpload {
                name: with_artifact_name(with, DEFAULT_UPLOAD_ARTIFACT_NAME),
                conditional: false,
                detail: format!("uses: {}", cifile::truncate(raw, EVIDENCE_CHARS)),
            })
        }
        "actions/upload-pages-artifact" => {
            return UsesRole::Upload(ArtifactUpload {
                name: with_artifact_name(with, DEFAULT_PAGES_ARTIFACT_NAME),
                conditional: false,
                detail: format!("uses: {}", cifile::truncate(raw, EVIDENCE_CHARS)),
            })
        }
        "actions/download-artifact" => return download_artifact_role(raw, parsed.git_ref, with),
        "dawidd6/action-download-artifact" => return dawidd6_download_role(raw, with),
        "actions/github-script" => return github_script_role(raw, with),
        // Building the artifact's own `Dockerfile` and pushing the result ships
        // the downloaded bytes outward; a build with no push does not.
        "docker/build-push-action" => {
            return match with.and_then(|w| cifile::get_field(w, "push")) {
                Some(node) if value_is_truthy(node) => UsesRole::Sink(ArtifactSink {
                    kind: SinkKind::Publish,
                    operand: None,
                    detail: format!("uses: {}", cifile::truncate(raw, EVIDENCE_CHARS)),
                }),
                _ => UsesRole::Irrelevant,
            }
        }
        _ => {}
    }

    for (action, kind) in PUBLISH_DEPLOY_ACTIONS {
        if repo == *action {
            return UsesRole::Sink(ArtifactSink {
                kind: *kind,
                operand: None,
                detail: format!("uses: {}", cifile::truncate(raw, EVIDENCE_CHARS)),
            });
        }
    }

    // An action this analyzer has no model for, handed the id of the run that
    // triggered this `workflow_run`, is a fetch of the untrusted run's output
    // through a mechanism the pass cannot follow.
    if with.is_some_and(with_binds_triggering_run) {
        return UsesRole::Unresolved(format!(
            "step '{}' reads the triggering run through an unmodelled action",
            cifile::truncate(raw, 80)
        ));
    }

    UsesRole::Irrelevant
}

/// Whether any value in a step's `with:` mapping names the triggering run's id.
fn with_binds_triggering_run(with: &Value) -> bool {
    with.as_mapping().is_some_and(|map| {
        map.values()
            .filter_map(Value::as_str)
            .any(text_binds_triggering_run)
    })
}

/// `actions/download-artifact`. Versions v3 and earlier CANNOT fetch artifacts
/// from another workflow run at all, so modelling them as the cross-run consumer
/// would report a chain that cannot happen. The discriminator used here is the
/// `run-id:` input itself: it exists only from v4 on, and only a value bound to
/// the TRIGGERING run reads the untrusted producer's output.
fn download_artifact_role(raw: &str, git_ref: &str, with: Option<&Value>) -> UsesRole {
    let Some(with) = with else {
        return UsesRole::Irrelevant;
    };
    let Some(run_id) = cifile::get_field(with, "run-id") else {
        return UsesRole::Irrelevant;
    };
    if let Some(major) = action_major_version(git_ref) {
        if major < 4 {
            // A `run-id:` on a v3-or-earlier pin is inert, not a cross-run fetch.
            return UsesRole::Irrelevant;
        }
    }
    if !binds_triggering_run(run_id) {
        return UsesRole::Irrelevant;
    }
    if !repository_is_self(with, "repository") {
        return UsesRole::Unresolved(format!(
            "download step '{}' names another repository",
            cifile::truncate(raw, 80)
        ));
    }
    let token = cifile::get_field(with, "github-token").is_some();
    let name = download_artifact_name(with, "name", "pattern");
    // `merge-multiple: true` is the documented opt-out from the per-artifact
    // subdirectory layout: every artifact is unpacked into `path` itself.
    let merged = cifile::get_field(with, "merge-multiple")
        .map(value_is_truthy)
        .unwrap_or(false);
    UsesRole::CrossRunDownload(ArtifactDownload {
        per_artifact_subdir: name == ArtifactName::All && !merged,
        name,
        dest: download_dest(with),
        detail: format!(
            "uses: {} (run-id bound to the triggering run{})",
            cifile::truncate(raw, 100),
            if token { ", github-token set" } else { "" }
        ),
    })
}

/// `dawidd6/action-download-artifact` fetches across runs by design. Only its
/// `run_id:` form is bound to the triggering run; the `workflow:` + `branch:`
/// form resolves to "the latest successful run", which is a different (and not
/// statically knowable) producer run.
fn dawidd6_download_role(raw: &str, with: Option<&Value>) -> UsesRole {
    let Some(with) = with else {
        return UsesRole::Irrelevant;
    };
    let run_id = cifile::get_field(with, "run_id").or_else(|| cifile::get_field(with, "run-id"));
    let Some(run_id) = run_id else {
        if cifile::get_field(with, "workflow").is_some() {
            return UsesRole::Unresolved(format!(
                "download step '{}' resolves a run by workflow/branch, not the triggering run",
                cifile::truncate(raw, 80)
            ));
        }
        return UsesRole::Irrelevant;
    };
    if !binds_triggering_run(run_id) {
        return UsesRole::Irrelevant;
    }
    if !repository_is_self(with, "repo") {
        return UsesRole::Unresolved(format!(
            "download step '{}' names another repository",
            cifile::truncate(raw, 80)
        ));
    }
    // `name_is_regexp: true` turns `name:` into a pattern rather than an identity.
    let regexp = cifile::get_field(with, "name_is_regexp")
        .map(value_is_truthy)
        .unwrap_or(false);
    let name = if regexp {
        ArtifactName::Unresolved
    } else {
        download_artifact_name(with, "name", "path_is_regexp_never")
    };
    UsesRole::CrossRunDownload(ArtifactDownload {
        per_artifact_subdir: name == ArtifactName::All,
        name,
        dest: download_dest(with),
        detail: format!(
            "uses: {} (run_id bound to the triggering run)",
            cifile::truncate(raw, 100)
        ),
    })
}

/// `actions/github-script` calling `listWorkflowRunArtifacts` with the
/// triggering run's id, then downloading. The script is JavaScript, not shell,
/// so the artifact identity is only claimed when the script contains a literal
/// quoted name; otherwise the identity is UNRESOLVED rather than assumed.
fn github_script_role(raw: &str, with: Option<&Value>) -> UsesRole {
    let Some(script) = with
        .and_then(|w| cifile::get_field(w, "script"))
        .and_then(Value::as_str)
    else {
        return UsesRole::Irrelevant;
    };
    let normalized: String = script
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    if !normalized.contains("listworkflowrunartifacts") {
        return UsesRole::Irrelevant;
    }
    if !TRIGGERING_RUN_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker))
    {
        return UsesRole::Unresolved(format!(
            "github-script step '{}' lists run artifacts without a triggering-run binding",
            cifile::truncate(raw, 80)
        ));
    }
    UsesRole::CrossRunDownload(ArtifactDownload {
        name: script_literal_artifact_name(script),
        // The script writes the bytes itself, so the extraction directory is
        // whatever its own filesystem calls say; do not guess one.
        dest: None,
        per_artifact_subdir: false,
        detail: format!(
            "uses: {} (listWorkflowRunArtifacts on the triggering run)",
            cifile::truncate(raw, 100)
        ),
    })
}

/// The quoted string a `github-script` body compares an artifact name against.
/// Only an equality comparison counts; anything else stays unresolved.
fn script_literal_artifact_name(script: &str) -> ArtifactName {
    let normalized: String = script.chars().filter(|c| !c.is_whitespace()).collect();
    for marker in [
        "artifact.name==",
        "artifact.name===",
        "item.name==",
        "a.name==",
    ] {
        let Some(pos) = normalized.find(marker) else {
            continue;
        };
        let rest = &normalized[pos + marker.len()..];
        let rest = rest.trim_start_matches('=');
        let quote = rest.chars().next();
        if !matches!(quote, Some('"') | Some('\'') | Some('`')) {
            continue;
        }
        let quote = quote.unwrap_or('"');
        let body = &rest[quote.len_utf8()..];
        if let Some(end) = body.find(quote) {
            let name = &body[..end];
            // The search ran over a whitespace-stripped copy, so a name that held
            // whitespace would come back mangled. Requiring it verbatim in the
            // source keeps a mangled name from matching a different artifact.
            if !name.is_empty() && !name.contains("${") && script.contains(name) {
                return ArtifactName::Resolved(name.to_string());
            }
        }
    }
    ArtifactName::Unresolved
}

/// The uploaded artifact's identity: an explicit `with.name`, else the action's
/// documented default.
fn with_artifact_name(with: Option<&Value>, default_name: &str) -> ArtifactName {
    let Some(with) = with else {
        return ArtifactName::Resolved(default_name.to_string());
    };
    match cifile::get_field(with, "name") {
        None => ArtifactName::Resolved(default_name.to_string()),
        Some(node) => literal_name(node),
    }
}

/// The downloaded artifact's identity. An absent `name:` downloads EVERY
/// artifact of the run, which covers any producer upload; a `pattern:` is a glob
/// and is never resolved into an identity.
fn download_artifact_name(with: &Value, name_key: &str, pattern_key: &str) -> ArtifactName {
    if let Some(node) = cifile::get_field(with, name_key) {
        return literal_name(node);
    }
    if cifile::get_field(with, pattern_key).is_some() {
        return ArtifactName::Unresolved;
    }
    ArtifactName::All
}

fn literal_name(node: &Value) -> ArtifactName {
    let Some(text) = node.as_str() else {
        return ArtifactName::Unresolved;
    };
    let text = cifile::strip_quotes(text).trim();
    if text.is_empty() || !cifile::github_expressions(text).is_empty() || text.contains("${{") {
        return ArtifactName::Unresolved;
    }
    ArtifactName::Resolved(text.to_string())
}

/// The extraction directory as a workspace-relative path; `""` is the workspace
/// root. `None` when the value is dynamic, absolute, or escapes the workspace.
fn download_dest(with: &Value) -> Option<String> {
    let Some(node) = cifile::get_field(with, "path") else {
        return Some(String::new());
    };
    let text = node.as_str()?;
    workspace_dir(text)
}

/// Whether an action pin's `@ref` names a major version we can read.
fn action_major_version(git_ref: &str) -> Option<u32> {
    let git_ref = git_ref.trim();
    if cifile::is_commit_sha(git_ref) {
        return None;
    }
    let stripped = git_ref.trim_start_matches(['v', 'V']);
    stripped.split('.').next()?.parse::<u32>().ok()
}

/// Whether a `run-id:` value resolves to the id of the run that triggered this
/// `workflow_run`. A literal number or an unrelated expression does not.
fn binds_triggering_run(node: &Value) -> bool {
    node.as_str().is_some_and(text_binds_triggering_run)
}

/// Whether any `${{ ... }}` expression in `text` names the triggering run's id.
fn text_binds_triggering_run(text: &str) -> bool {
    cifile::github_expressions(text).iter().any(|expr| {
        let normalized: String = expr
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        TRIGGERING_RUN_MARKERS
            .iter()
            .any(|marker| normalized.contains(marker))
    })
}

/// Whether a download step targets THIS repository. An explicit repository that
/// is not `${{ github.repository }}` points at a different artifact store, so
/// the chain is not this repository's.
fn repository_is_self(with: &Value, key: &str) -> bool {
    let Some(node) = cifile::get_field(with, key) else {
        return true;
    };
    let Some(text) = node.as_str() else {
        return false;
    };
    let normalized: String = text
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    normalized == "${{github.repository}}"
}

fn value_is_truthy(node: &Value) -> bool {
    match node {
        Value::Bool(b) => *b,
        Value::String(s) => s.trim().eq_ignore_ascii_case("true"),
        _ => false,
    }
}

// Workspace path handling

/// Normalize a shell operand into a workspace-relative path. `None` when the
/// operand is dynamic, absolute, escapes the workspace, or is not a path at all,
/// because an operand we cannot place is an operand we cannot prove came from
/// the artifact.
fn workspace_relative(operand: &str) -> Option<String> {
    let text = cifile::strip_quotes(operand).trim();
    if text.is_empty() || text.contains("${{") {
        return None;
    }
    let text = text.replace('\\', "/");
    let text = text
        .strip_prefix("$GITHUB_WORKSPACE/")
        .or_else(|| text.strip_prefix("${GITHUB_WORKSPACE}/"))
        .or_else(|| text.strip_prefix("$PWD/"))
        .or_else(|| text.strip_prefix("${PWD}/"))
        .unwrap_or(text.as_str());
    if text.starts_with('$') || text.starts_with('~') || text.starts_with('/') {
        return None;
    }
    // A Windows drive-qualified path is absolute too.
    let bytes = text.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        return None;
    }
    let mut parts = Vec::new();
    for part in text.split('/') {
        match part {
            "" | "." => {}
            ".." => return None,
            other => {
                if other.contains('$') {
                    return None;
                }
                parts.push(other);
            }
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("/"))
}

/// Like [`workspace_relative`] but for a DIRECTORY, where the workspace root
/// itself (`.`, `./`, or an empty value) is a legitimate answer.
fn workspace_dir(value: &str) -> Option<String> {
    let text = cifile::strip_quotes(value).trim();
    if text.is_empty() || text == "." || text == "./" {
        return Some(String::new());
    }
    workspace_relative(text)
}

/// Whether `operand` sits inside the download destination `dest` (`""` = the
/// workspace root, which contains every workspace-relative path).
fn path_under(dest: &str, operand: &str) -> bool {
    if dest.is_empty() {
        return true;
    }
    operand == dest || operand.starts_with(&format!("{dest}/"))
}

/// The directory a per-artifact-subdirectory download actually unpacks artifact
/// `artifact` into. `None` when the artifact name cannot be turned into one
/// directory component, because a directory we cannot name is one we cannot
/// prove anything is inside of.
fn artifact_subdir(dest: &str, artifact: &str) -> Option<String> {
    let artifact = artifact.trim();
    if artifact.is_empty()
        || artifact == "."
        || artifact == ".."
        || artifact.contains(['/', '\\', '$'])
    {
        return None;
    }
    if dest.is_empty() {
        Some(artifact.to_string())
    } else {
        Some(format!("{dest}/{artifact}"))
    }
}

// `run:` body analysis

/// Interpreter flags that make the NEXT operand an inline script rather than a
/// file path, so the step executes text from the workflow, not from an artifact.
const INLINE_SCRIPT_FLAGS: &[&str] = &[
    "-c",
    "-e",
    "-p",
    "-r",
    "--eval",
    "--command",
    "-command",
    "-encodedcommand",
    "-ec",
];

/// Walk one `run:` body in order, recording the flow events it contains.
/// Returns `true` when static resolution was incomplete anywhere in the body.
fn analyze_run_body(script: &str, shell: ShellType, job: &mut JobModel) -> bool {
    let view = crate::extract::shell_execution_view(script, shell);
    let (segments, budget) = tokenize::tokenize_bounded(
        view.as_ref(),
        shell,
        MAX_SEGMENTS_PER_RUN,
        MAX_WORDS_PER_SEGMENT,
        MAX_WORD_BYTES,
    );
    let mut incomplete =
        budget.segments_truncated || budget.words_truncated || budget.word_bytes_truncated;

    // Unmodelled commands only matter once untrusted bytes are on disk, so the
    // producer side and everything ahead of a download stay quiet.
    let mut seen_download = job
        .events
        .iter()
        .any(|event| matches!(event, FlowEvent::Download(_)));

    let mut previous_had_literal_digest = false;
    for segment in &segments {
        let raw = segment.raw.clone();
        let has_literal_digest = contains_literal_sha256(&raw);

        // A redirect into `$GITHUB_PATH` / `$GITHUB_ENV` is not a command, so it
        // is read off the segment text before any command resolution.
        let env_write = classify_env_file_write(segment);
        let env_write_classified = env_write.is_some();
        if let Some(sink) = env_write {
            push_event(job, FlowEvent::Sink(sink));
        }

        let effective = match command::resolve_effective_segment(segment, shell) {
            Ok(effective) => effective,
            Err(_) => {
                // A segment carrying only environment assignments has no command
                // to resolve; that is an absence, not an analysis failure.
                if segment.command.is_some() {
                    incomplete = true;
                }
                previous_had_literal_digest = has_literal_digest;
                continue;
            }
        };
        let Some(command_token) = effective.command.as_deref() else {
            previous_had_literal_digest = has_literal_digest;
            continue;
        };
        let name = command::normalize_cmd_base(command_token, shell);

        let mut modelled = env_write_classified;
        if let Some(verify) = classify_verify(&name, &effective, previous_had_literal_digest) {
            push_event(job, FlowEvent::Verify(verify));
            modelled = true;
        } else if let Some(download) = classify_gh_run_download(&name, &effective) {
            push_event(job, FlowEvent::Download(download));
            seen_download = true;
            modelled = true;
        } else if let Some(sink) = classify_command_sink(&name, command_token, &effective) {
            push_event(job, FlowEvent::Sink(sink));
            modelled = true;
        }

        // A command that hands the triggering run's id to something other than a
        // download mechanism this pass models (`gh api .../artifacts`, a `curl`
        // of an `archive_download_url`) still pulls the untrusted run's output
        // into the job, along a path the pass cannot follow.
        if !modelled && text_binds_triggering_run(&effective.raw) {
            incomplete = true;
        }

        // Everything else after a download is an unknown: `tar -x`, `cp`, `mv`
        // and `unzip` relocate the bytes out from under the containment test,
        // and `pip install` / `npm ci` run them. Only the provably inert
        // read-only commands are exempt.
        if !modelled
            && seen_download
            && !command_is_provably_inert_after_download(&name, &effective, shell)
        {
            push_event(job, FlowEvent::Unmodelled);
        }

        previous_had_literal_digest = has_literal_digest;
    }

    incomplete
}

/// Whether an otherwise-unmodelled command is known not to execute, relocate,
/// mutate, or publish downloaded bytes. Most entries are simple command-name
/// facts. `find` needs its own closed parser because its expression language
/// contains execution and mutation actions.
fn command_is_provably_inert_after_download(
    name: &str,
    effective: &tokenize::Segment,
    shell: ShellType,
) -> bool {
    match name {
        "find" => find_is_provably_read_only(effective, shell),
        _ => INERT_COMMANDS.contains(&name),
    }
}

/// Recognise only the read-only subset of POSIX/GNU `find`.
///
/// The expression grammar is deliberately closed. In particular, execution
/// (`-exec*`/`-ok*`), mutation (`-delete`), file-writing (`-fprint*`, `-fprintf`,
/// `-fls`), shell substitutions, and every unknown option/action return false,
/// which turns the post-download step into [`FlowEvent::Unmodelled`]. Predicate
/// operands are consumed according to their known arity, so an operand named
/// `-exec` cannot be confused with an action.
fn find_is_provably_read_only(effective: &tokenize::Segment, shell: ShellType) -> bool {
    if !matches!(shell, ShellType::Posix | ShellType::Fish)
        || effective.raw.contains("$(")
        || effective.raw.contains("<(")
        || effective.raw.contains(">(")
        || effective.raw.contains('`')
    {
        return false;
    }

    let args: Vec<String> = effective
        .args
        .iter()
        .map(|arg| command::normalize_shell_token(arg, shell))
        .collect();
    let mut index = 0usize;

    // POSIX traversal flags and GNU debug/optimisation options precede paths.
    while let Some(arg) = args.get(index).map(String::as_str) {
        match arg {
            "-H" | "-L" | "-P" => index += 1,
            "-D" => {
                if args.get(index + 1).is_none() {
                    return false;
                }
                index += 2;
            }
            _ if is_find_optimization_option(arg) => index += 1,
            _ => break,
        }
    }

    let mut in_expression = false;
    while let Some(arg) = args.get(index).map(String::as_str) {
        if !in_expression {
            if !find_expression_starts_with(arg) {
                // A leading non-option is a search root. A path whose spelling
                // starts with `-` must be written as `./-name`; otherwise find
                // itself treats it as expression syntax and so do we.
                if arg.starts_with('-') {
                    return false;
                }
                index += 1;
                continue;
            }
            in_expression = true;
        }

        if FIND_READ_ONLY_NULLARY.contains(&arg) {
            index += 1;
            continue;
        }
        if FIND_READ_ONLY_UNARY.contains(&arg) || is_find_newer_predicate(arg) {
            if args.get(index + 1).is_none() {
                return false;
            }
            index += 2;
            continue;
        }

        // This also rejects every known execution/mutation/file-writing action.
        return false;
    }

    true
}

fn find_expression_starts_with(arg: &str) -> bool {
    arg.starts_with('-') || matches!(arg, "!" | "(" | ")" | ",")
}

fn is_find_optimization_option(arg: &str) -> bool {
    let Some(level) = arg.strip_prefix("-O") else {
        return false;
    };
    !level.is_empty() && level.chars().all(|ch| ch.is_ascii_digit())
}

fn is_find_newer_predicate(arg: &str) -> bool {
    let Some(suffix) = arg.strip_prefix("-newer") else {
        return false;
    };
    suffix.len() == 2
        && suffix
            .bytes()
            .all(|kind| matches!(kind, b'a' | b'B' | b'c' | b'm' | b't'))
}

/// Read-only `find` operators, options, tests, and stdout-only actions that take
/// no operand. Side-effecting actions are intentionally absent.
const FIND_READ_ONLY_NULLARY: &[&str] = &[
    "!",
    "(",
    ")",
    ",",
    "-a",
    "-and",
    "-o",
    "-or",
    "-not",
    "-true",
    "-false",
    "-empty",
    "-readable",
    "-writable",
    "-executable",
    "-nouser",
    "-nogroup",
    "-print",
    "-print0",
    "-ls",
    "-prune",
    "-quit",
    "-depth",
    "-ignore_readdir_race",
    "-noignore_readdir_race",
    "-mount",
    "-xdev",
    "-daystart",
    "-follow",
    "-warn",
    "-nowarn",
    "-help",
    "--help",
    "-version",
    "--version",
];

/// Read-only `find` options/tests/actions that consume exactly one following
/// operand. The consumed word may itself start with `-` without becoming an
/// action.
const FIND_READ_ONLY_UNARY: &[&str] = &[
    "-name",
    "-iname",
    "-path",
    "-ipath",
    "-wholename",
    "-iwholename",
    "-lname",
    "-ilname",
    "-regex",
    "-iregex",
    "-type",
    "-xtype",
    "-context",
    "-perm",
    "-user",
    "-group",
    "-uid",
    "-gid",
    "-inum",
    "-links",
    "-size",
    "-used",
    "-amin",
    "-atime",
    "-cmin",
    "-ctime",
    "-mmin",
    "-mtime",
    "-anewer",
    "-cnewer",
    "-newer",
    "-samefile",
    "-fstype",
    "-maxdepth",
    "-mindepth",
    "-regextype",
    "-files0-from",
    "-printf",
];

/// Commands that can neither execute a downloaded file, nor point a later step
/// at one, nor move one somewhere the containment test stops seeing it, nor
/// ship the workspace outward. Deliberately a small, closed list: a command that
/// is not on it becomes [`FlowEvent::Unmodelled`], which costs the post-pass the
/// right to claim the artifact went nowhere, and nothing else.
const INERT_COMMANDS: &[&str] = &[
    // Shell keywords and builtins the tokenizer can surface in command position.
    "if",
    "then",
    "else",
    "elif",
    "fi",
    "for",
    "while",
    "until",
    "do",
    "done",
    "case",
    "esac",
    "function",
    "select",
    "local",
    "shift",
    "exit",
    "return",
    "break",
    "continue",
    "set",
    "unset",
    "export",
    "cd",
    "pushd",
    "popd",
    "true",
    "false",
    ":",
    "test",
    "[",
    "[[",
    "read",
    "wait",
    // Read-only inspection.
    "ls",
    "cat",
    "head",
    "tail",
    "wc",
    "file",
    "stat",
    "du",
    "df",
    "basename",
    "dirname",
    "realpath",
    "readlink",
    "pwd",
    "date",
    "env",
    "printenv",
    "echo",
    "printf",
    "id",
    "whoami",
    "uname",
    "hostname",
    "which",
    "command",
    "type",
    "sleep",
    "seq",
    "sort",
    "uniq",
    "cut",
    "tr",
    "grep",
    "egrep",
    "fgrep",
    "diff",
    "cmp",
    "jq",
    "yq",
    "tee",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "md5sum",
    "shasum",
    "b2sum",
    // Workspace shaping that cannot create or relocate executable content.
    "mkdir",
    "rmdir",
    "rm",
    "touch",
    "chmod",
    "chown",
];

/// Whether the text carries a literal 64-hex digest, which can only have been
/// written by the workflow author (the untrusted producer cannot edit the
/// consumer workflow on the default branch).
fn contains_literal_sha256(text: &str) -> bool {
    let mut run = 0usize;
    for byte in text.bytes() {
        if byte.is_ascii_hexdigit() {
            run += 1;
            if run >= 64 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// `echo dir >> $GITHUB_PATH` and friends.
fn classify_env_file_write(segment: &tokenize::Segment) -> Option<ArtifactSink> {
    let raw = &segment.raw;
    let names = ["$GITHUB_PATH", "${GITHUB_PATH}"];
    if !raw.contains('>') {
        return None;
    }
    let path_file = names.iter().any(|n| raw.contains(n));
    let env_file = ["$GITHUB_ENV", "${GITHUB_ENV}"]
        .iter()
        .any(|n| raw.contains(n));
    if !path_file && !env_file {
        return None;
    }
    // The value is the first word after the writing command (`echo`, `printf`).
    let operand = segment
        .args
        .iter()
        .find(|arg| !arg.starts_with('-') && !arg.starts_with('>'))
        .and_then(|arg| env_file_write_target(arg, path_file))?;
    Some(ArtifactSink {
        kind: SinkKind::PathMutation,
        operand: Some(operand),
        detail: cifile::truncate(raw, EVIDENCE_CHARS),
    })
}

/// Environment variables whose VALUE makes a later step load code, libraries, or
/// interpreter startup files from the named place. Writing any other name to
/// `$GITHUB_ENV` records data the runner never resolves anything from, so
/// `report_dir=dist/reports` is bookkeeping, not a PATH mutation.
const LOADER_ENV_VARS: &[&str] = &[
    "PATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PERL5LIB",
    "PERL5OPT",
    "RUBYLIB",
    "RUBYOPT",
    "GEM_PATH",
    "CLASSPATH",
    "JAVA_TOOL_OPTIONS",
    "BASH_ENV",
    "ENV",
    "GIT_SSH_COMMAND",
];

/// The workspace path an env-file write makes a LATER step load from.
/// `$GITHUB_PATH` takes the whole line as a directory to prepend to `PATH`.
/// `$GITHUB_ENV` takes `NAME=value`, and only a NAME the runner or an
/// interpreter resolves code from turns its value into a loader path.
fn env_file_write_target(arg: &str, github_path_file: bool) -> Option<String> {
    let arg = cifile::strip_quotes(arg).trim();
    let value = match arg.split_once('=') {
        Some((name, value)) => {
            if !LOADER_ENV_VARS
                .iter()
                .any(|known| name.trim().eq_ignore_ascii_case(known))
            {
                return None;
            }
            value
        }
        // A bare line is a directory only when it goes to `$GITHUB_PATH`; a bare
        // line in `$GITHUB_ENV` sets nothing.
        None if github_path_file => arg,
        None => return None,
    };
    // `PATH=<new>:$PATH` prepends; the entry being ADDED is the first one.
    let first = value.split(':').next().unwrap_or(value);
    workspace_relative(first)
}

/// `gh run download <triggering-run-id>` inside a `run:` step.
fn classify_gh_run_download(name: &str, effective: &tokenize::Segment) -> Option<ArtifactDownload> {
    if name != "gh" {
        return None;
    }
    let positional: Vec<&str> = effective
        .args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    if positional.first().copied() != Some("run") || positional.get(1).copied() != Some("download")
    {
        return None;
    }
    // The shell tokenizer splits `${{ github.event.workflow_run.id }}` into three
    // words, so the binding is read off the segment TEXT, not off one argv slot.
    if !text_binds_triggering_run(&effective.raw) {
        return None;
    }
    let flag_value = |long: &str, short: &str| -> Option<String> {
        if let Some(inline) = effective
            .args
            .iter()
            .find_map(|a| a.strip_prefix(&format!("{long}=")))
        {
            return Some(inline.to_string());
        }
        let index = effective
            .args
            .iter()
            .position(|a| a == long || a == short)?;
        effective.args.get(index + 1).cloned()
    };
    let artifact = match flag_value("--name", "-n") {
        Some(value) if !value.contains("${{") && !value.contains(['*', '?']) => {
            ArtifactName::Resolved(cifile::strip_quotes(&value).trim().to_string())
        }
        Some(_) => ArtifactName::Unresolved,
        None => ArtifactName::All,
    };
    let dest = match flag_value("--dir", "-D") {
        Some(value) => workspace_dir(&value),
        None => Some(String::new()),
    };
    Some(ArtifactDownload {
        // `gh run download` isolates each artifact into its own subdirectory
        // unless it is given exactly one `--name`.
        per_artifact_subdir: artifact == ArtifactName::All,
        name: artifact,
        dest,
        detail: cifile::truncate(&effective.raw, EVIDENCE_CHARS),
    })
}

/// A digest / signature / attestation comparison. There is no such primitive
/// elsewhere in the tree, so the shapes recognised here are deliberately narrow:
/// a checksum tool in CHECK mode, or a verifier whose trust anchor lives outside
/// the workspace entirely.
fn classify_verify(
    name: &str,
    effective: &tokenize::Segment,
    previous_had_literal_digest: bool,
) -> Option<DigestVerification> {
    let positional: Vec<&str> = effective
        .args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();

    // Trust anchors that no downloaded byte can influence.
    let out_of_band = match name {
        "gh" => {
            positional.first().copied() == Some("attestation")
                && positional.get(1).copied() == Some("verify")
        }
        "cosign" => matches!(
            positional.first().copied(),
            Some("verify") | Some("verify-blob")
        ),
        "gpg" | "gpgv" => effective.args.iter().any(|a| a == "--verify"),
        "openssl" => effective.args.iter().any(|a| a == "-verify"),
        _ => false,
    };
    if out_of_band {
        return Some(DigestVerification {
            source: DigestSource::OutOfBand,
            detail: cifile::truncate(&effective.raw, EVIDENCE_CHARS),
        });
    }

    if !matches!(name, "sha256sum" | "sha512sum" | "shasum" | "b2sum") {
        return None;
    }
    let checking = effective.args.iter().any(|a| {
        a == "-c"
            || a == "--check"
            || (a.starts_with('-') && !a.starts_with("--") && a.contains('c'))
    });
    if !checking {
        return None;
    }
    // `shasum -a 256 -c list.txt` carries the algorithm as a bare positional.
    let operand = positional
        .iter()
        .rev()
        .find(|a| !a.chars().all(|c| c.is_ascii_digit()))
        .copied();
    match operand {
        // `... | sha256sum -c -` is trusted only when the expected digest was a
        // literal in the workflow text, never when it was piped out of the
        // downloaded tree.
        Some("-") | None => previous_had_literal_digest.then(|| DigestVerification {
            source: DigestSource::OutOfBand,
            detail: cifile::truncate(&effective.raw, EVIDENCE_CHARS),
        }),
        // An operand this analyzer cannot place is NOT an out-of-band trust
        // anchor: `sha256sum -c "$SUMS"` and `sha256sum -c /tmp/art/SHA256SUMS`
        // may both read digests the artifact itself wrote.
        Some(path) => Some(DigestVerification {
            source: match workspace_relative(path) {
                Some(placed) => DigestSource::Workspace(placed),
                None => DigestSource::Unplaceable,
            },
            detail: cifile::truncate(&effective.raw, EVIDENCE_CHARS),
        }),
    }
}

/// Suffixes that make a bare operand a SCRIPT rather than a module or a
/// subcommand. Without this, `python -m pip install x` reads as "run the
/// workspace file `pip`" whenever the artifact landed in the workspace root.
const SCRIPT_FILE_SUFFIXES: &[&str] = &[
    ".sh", ".bash", ".zsh", ".ksh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php",
    ".lua", ".ps1", ".psm1", ".bat", ".cmd", ".jar", ".exe",
];

/// The first operand of an interpreter/source invocation, but only when it names
/// a FILE: a path with a directory component, or a bare name with a script
/// suffix. Anything else is a module name, a subcommand, or a flag value.
fn script_file_operand(effective: &tokenize::Segment) -> Option<String> {
    let raw = effective.args.iter().find(|a| !a.starts_with('-'))?;
    let operand = workspace_relative(raw)?;
    let lower = operand.to_ascii_lowercase();
    let looks_like_file = operand.contains('/')
        || SCRIPT_FILE_SUFFIXES
            .iter()
            .any(|suffix| lower.ends_with(suffix));
    looks_like_file.then_some(operand)
}

/// A dangerous sink expressed as a command.
fn classify_command_sink(
    name: &str,
    command_token: &str,
    effective: &tokenize::Segment,
) -> Option<ArtifactSink> {
    let detail = cifile::truncate(&effective.raw, EVIDENCE_CHARS);

    if matches!(name, "." | "source") || command_token == "." {
        let operand = script_file_operand(effective)?;
        return Some(ArtifactSink {
            kind: SinkKind::Source,
            operand: Some(operand),
            detail,
        });
    }

    if command::INTERPRETERS.contains(&name) {
        let inline = effective
            .args
            .iter()
            .any(|a| INLINE_SCRIPT_FLAGS.contains(&a.to_ascii_lowercase().as_str()));
        if !inline {
            if let Some(operand) = script_file_operand(effective) {
                return Some(ArtifactSink {
                    kind: SinkKind::Execute,
                    operand: Some(operand),
                    detail,
                });
            }
        }
    }

    // A program named by a workspace-relative path IS the artifact's bytes.
    if command_token.contains('/') || command_token.starts_with("./") {
        if let Some(operand) = workspace_relative(command_token) {
            return Some(ArtifactSink {
                kind: SinkKind::Execute,
                operand: Some(operand),
                detail,
            });
        }
    }

    let positional: Vec<&str> = effective
        .args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    let sub = |index: usize| positional.get(index).copied().unwrap_or_default();
    let has = |word: &str| positional.contains(&word);

    let kind = match name {
        "npm" | "pnpm" | "yarn" | "bun" => (sub(0) == "publish").then_some(SinkKind::Publish),
        "cargo" => (sub(0) == "publish").then_some(SinkKind::Publish),
        "twine" => (sub(0) == "upload").then_some(SinkKind::Publish),
        "poetry" => (sub(0) == "publish").then_some(SinkKind::Publish),
        "gem" => (sub(0) == "push").then_some(SinkKind::Publish),
        "nuget" => (sub(0) == "push").then_some(SinkKind::Publish),
        "dotnet" => (sub(0) == "nuget" && sub(1) == "push").then_some(SinkKind::Publish),
        "mvn" => has("deploy").then_some(SinkKind::Publish),
        "gradle" => (has("publish") || has("publishToMavenCentral")).then_some(SinkKind::Publish),
        "docker" => (sub(0) == "push").then_some(SinkKind::Publish),
        "gh" => matches!(
            (sub(0), sub(1)),
            ("release", "upload") | ("release", "create")
        )
        .then_some(SinkKind::Publish),
        "kubectl" => (sub(0) == "apply").then_some(SinkKind::Deploy),
        "helm" => matches!(sub(0), "upgrade" | "install").then_some(SinkKind::Deploy),
        "terraform" | "tofu" => (sub(0) == "apply").then_some(SinkKind::Deploy),
        "aws" => match (sub(0), sub(1)) {
            ("s3", "cp") | ("s3", "sync") | ("cloudformation", "deploy") => Some(SinkKind::Deploy),
            ("lambda", "update-function-code") => Some(SinkKind::Deploy),
            _ => None,
        },
        "firebase" | "vercel" | "netlify" | "wrangler" | "flyctl" | "fly" | "surge" => {
            has("deploy").then_some(SinkKind::Deploy)
        }
        "scp" => Some(SinkKind::Deploy),
        "rsync" => positional
            .iter()
            .any(|a| a.contains(':'))
            .then_some(SinkKind::Deploy),
        _ => None,
    }?;

    Some(ArtifactSink {
        kind,
        operand: None,
        detail,
    })
}

// Repository correlation

/// The outcome of the repository post-pass.
pub struct RepositoryFlowResult {
    /// One finding per consumer workflow with a fully proven chain, paired with
    /// that CONSUMER's path (the workflow an operator has to fix).
    pub findings: Vec<(PathBuf, Finding)>,
    /// `workflow_run` consumers for which the post-pass had COMPLETE visibility
    /// and proved no chain. Only these may have their presence-level
    /// `WorkflowRunTrigger` finding downgraded: every surface that cannot run
    /// this post-pass keeps the original severity.
    pub unproven_consumers: Vec<PathBuf>,
}

/// A proven producer-to-consumer chain, kept only long enough to build evidence.
struct ProvenChain<'a> {
    producer: &'a WorkflowModel,
    artifact: String,
    download: &'a ArtifactDownload,
    sink: &'a ArtifactSink,
    /// A digest comparison that DID run between the download and the sink but
    /// whose expected value came from inside the downloaded tree. It suppresses
    /// nothing, and naming it is what tells the operator their check is
    /// self-referential rather than absent.
    untrusted_verify: Option<&'a DigestVerification>,
}

/// Correlate the modelled workflows into cross-workflow artifact flows.
///
/// `coverage_complete` is the caller's statement that EVERY workflow in the tree
/// was modelled within the repository bounds. When it is false the post-pass may
/// still report a chain it proved, but it never claims the absence of one.
pub fn analyze_repository(
    models: &[WorkflowModel],
    coverage_complete: bool,
) -> RepositoryFlowResult {
    let mut result = RepositoryFlowResult {
        findings: Vec::new(),
        unproven_consumers: Vec::new(),
    };

    // A workflow we could not parse could be an untrusted producer, so its mere
    // presence removes the right to say "no chain exists".
    let global_blind_spot = models.iter().any(|m| m.parse_failed || m.steps_truncated);

    // Keep a named, fork-reachable producer in the binding set when its model is
    // unresolved even if no direct upload survived modelling. A local action or
    // reusable workflow may contain the upload; filtering it out here would turn
    // that missing visibility into a false proof that the consumer is benign.
    let producer_candidates: Vec<&WorkflowModel> = models
        .iter()
        .filter(|m| m.fork_reachable() && (!m.uploads.is_empty() || m.artifact_flow_unresolved()))
        .collect();

    // A `workflow_run` workflow that downloads a cross-run artifact and then
    // uploads one of its own re-publishes bytes of untrusted provenance under a
    // NEW identity. Following that hop would need taint propagation this pass
    // does not do, so a consumer bound to such a relay is bound to an artifact
    // whose provenance is unknown rather than known-clean.
    let mut relay_names: BTreeSet<&str> = BTreeSet::new();
    let mut unnamed_relay = false;
    for relay in models.iter().filter(|m| is_artifact_relay(m)) {
        match relay.display_name.as_deref() {
            Some(name) => {
                relay_names.insert(name);
            }
            None => unnamed_relay = true,
        }
    }

    for consumer in models.iter().filter(|m| m.is_workflow_run_consumer()) {
        let mut unresolved = !consumer.unresolved.is_empty();

        let bound: Vec<&WorkflowModel> = match &consumer.consumes {
            ConsumedWorkflows::Names(names) => {
                // A fork-reachable uploader with no `name:` key takes its name
                // from its path, which this analyzer does not reconstruct.
                if producer_candidates.iter().any(|p| p.display_name.is_none()) {
                    unresolved = true;
                }
                if unnamed_relay || names.iter().any(|n| relay_names.contains(n.as_str())) {
                    unresolved = true;
                }
                producer_candidates
                    .iter()
                    .copied()
                    .filter(|p| {
                        p.display_name
                            .as_deref()
                            .is_some_and(|name| names.contains(name))
                    })
                    .collect()
            }
            ConsumedWorkflows::Unresolved => {
                unresolved = true;
                Vec::new()
            }
            ConsumedWorkflows::NotAConsumer => Vec::new(),
        };

        if bound.iter().any(|p| {
            p.uploads.iter().any(|u| u.name == ArtifactName::Unresolved)
                || p.artifact_flow_unresolved()
        }) {
            unresolved = true;
        }

        // Index the bound producers' uploads by artifact name ONCE per consumer,
        // so the per-download lookup does not multiply the producer count by the
        // upload count by the event count. Only a RESOLVED upload name is indexed:
        // an unresolved name on either side never matches, because incompleteness
        // is represented by the unresolved notes rather than resolved by guessing.
        let mut by_artifact: std::collections::BTreeMap<&str, &WorkflowModel> =
            std::collections::BTreeMap::new();
        for producer in &bound {
            for upload in &producer.uploads {
                // A conditional upload may simply not happen on a fork's pull
                // request. Its `if:` already recorded a note on the producer, so
                // the consumer is unresolved rather than clean; what it must not
                // do is complete a chain.
                if upload.conditional {
                    continue;
                }
                if let ArtifactName::Resolved(name) = &upload.name {
                    by_artifact.entry(name.as_str()).or_insert(producer);
                }
            }
        }

        let mut chain = None;
        for job in &consumer.jobs {
            if job.unresolved {
                unresolved = true;
                continue;
            }
            if chain.is_none() {
                chain = prove_job_chain(job, &by_artifact, &mut unresolved);
            }
        }

        match chain {
            Some(chain) => result
                .findings
                .push((consumer.path.clone(), build_finding(consumer, &chain))),
            None => {
                if coverage_complete && !global_blind_spot && !unresolved {
                    result.unproven_consumers.push(consumer.path.clone());
                }
            }
        }
    }

    result
}

/// Whether a workflow forwards artifacts it fetched from another run under a new
/// identity of its own.
fn is_artifact_relay(model: &WorkflowModel) -> bool {
    model.is_workflow_run_consumer()
        && !model.uploads.is_empty()
        && model.jobs.iter().any(|job| {
            job.events
                .iter()
                .any(|e| matches!(e, FlowEvent::Download(_)))
        })
}

/// Search one consumer job for a download whose bytes reach a dangerous sink
/// with no trusted digest comparison in between.
fn prove_job_chain<'a>(
    job: &'a JobModel,
    by_artifact: &std::collections::BTreeMap<&'a str, &'a WorkflowModel>,
    unresolved: &mut bool,
) -> Option<ProvenChain<'a>> {
    for (index, event) in job.events.iter().enumerate() {
        let FlowEvent::Download(download) = event else {
            continue;
        };
        // Which producer uploads this download can be carrying. A nameless
        // download takes EVERY artifact of the run, and each one lands in its own
        // subdirectory, so each candidate has its own containment root and all of
        // them have to be tried.
        let candidates: Vec<(&'a str, &'a WorkflowModel)> = match &download.name {
            ArtifactName::Unresolved => {
                *unresolved = true;
                continue;
            }
            ArtifactName::All => by_artifact.iter().map(|(a, p)| (*a, *p)).collect(),
            ArtifactName::Resolved(wanted) => match by_artifact.get_key_value(wanted.as_str()) {
                Some((artifact, producer)) => vec![(*artifact, *producer)],
                None => continue,
            },
        };

        for (artifact, producer) in candidates {
            // `None` is an extraction directory the analyzer could not place. A
            // sink that names an operand then cannot be proven to touch the
            // artifact's bytes; a publish/deploy sink ships the workspace
            // wholesale and does not need the directory at all.
            let dest = match download.dest.as_deref() {
                Some(dest) if download.per_artifact_subdir => artifact_subdir(dest, artifact),
                other => other.map(str::to_string),
            };
            if let Some(chain) = walk_after_download(
                job,
                index,
                download,
                artifact,
                producer,
                dest.as_deref(),
                unresolved,
            ) {
                return Some(chain);
            }
        }
    }
    None
}

/// ONE ordered pass over what follows a download whose bytes are known to be
/// artifact `artifact`, extracted into `dest`.
fn walk_after_download<'a>(
    job: &'a JobModel,
    index: usize,
    download: &'a ArtifactDownload,
    artifact: &str,
    producer: &'a WorkflowModel,
    dest: Option<&str>,
    unresolved: &mut bool,
) -> Option<ProvenChain<'a>> {
    // A trusted comparison covers every later use, so it ends the walk; an
    // untrusted one is kept only as evidence that the check exists and proves
    // nothing.
    let mut untrusted_verify = None;
    for candidate in job.events.iter().skip(index + 1) {
        match candidate {
            FlowEvent::Verify(verify) => match verify.trust(dest) {
                DigestTrust::Trusted => break,
                DigestTrust::SelfSupplied => {
                    untrusted_verify.get_or_insert(verify);
                }
                // A comparison whose expected value (or whose extraction
                // directory) could not be placed proves nothing in EITHER
                // direction. Suppressing on it silently would let an attacker
                // hide behind `sha256sum -c "$SUMS"`, so it stops the walk and
                // says so.
                DigestTrust::Unknown => {
                    *unresolved = true;
                    break;
                }
            },
            FlowEvent::Sink(sink) => {
                if sink.kind.requires_contained_operand() {
                    let Some(dest) = dest else {
                        *unresolved = true;
                        continue;
                    };
                    if !sink
                        .operand
                        .as_deref()
                        .is_some_and(|operand| path_under(dest, operand))
                    {
                        continue;
                    }
                }
                return Some(ProvenChain {
                    producer,
                    artifact: artifact.to_string(),
                    download,
                    sink,
                    untrusted_verify,
                });
            }
            // The bytes leave this pass's view: re-published under a new artifact
            // identity, or handed to a command it does not model.
            FlowEvent::Reupload | FlowEvent::Unmodelled => *unresolved = true,
            FlowEvent::Download(_) => {}
        }
    }
    None
}

fn build_finding(consumer: &WorkflowModel, chain: &ProvenChain<'_>) -> Finding {
    let producer_triggers = chain
        .producer
        .triggers
        .iter()
        .filter(|t| FORK_REACHABLE_TRIGGERS.contains(&t.as_str()))
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let upload_detail = chain
        .producer
        .uploads
        .iter()
        .find(|u| u.name == ArtifactName::Resolved(chain.artifact.clone()))
        .map(|u| u.detail.clone())
        .unwrap_or_else(|| "actions/upload-artifact".to_string());

    Finding {
        rule_id: RuleId::WorkflowArtifactPoisoning,
        severity: Severity::High,
        title: "Privileged workflow consumes a build artifact produced by an untrusted run"
            .to_string(),
        description: format!(
            "The workflow '{consumer_path}' runs on `workflow_run` with the base repository's \
             read/write `GITHUB_TOKEN` and secrets, downloads the artifact '{artifact}' from the \
             run that triggered it, and then {sink}s it without comparing it against a trusted \
             expected digest. That artifact is produced by '{producer_path}', which an untrusted \
             contributor can reach through its `{producer_triggers}` trigger, so a fork's pull \
             request decides the bytes this privileged job executes or ships. This is the \
             build-output trust break: the fork never touches the privileged workflow's text, only \
             the artifact it consumes. Verify the artifact against a digest or attestation the \
             producer run cannot supply before using it, or do the privileged work in the same run \
             that built the code from a trusted ref.",
            consumer_path = consumer.path.display(),
            artifact = chain.artifact,
            sink = chain.sink.kind.as_str(),
            producer_path = chain.producer.path.display(),
            producer_triggers = if producer_triggers.is_empty() {
                "pull_request".to_string()
            } else {
                producer_triggers
            },
        ),
        evidence: vec![
            Evidence::Text {
                detail: format!(
                    "untrusted producer: {} [{}]",
                    cifile::truncate(&chain.producer.path.display().to_string(), EVIDENCE_CHARS),
                    upload_detail
                ),
            },
            Evidence::Text {
                detail: format!(
                    "privileged consumer: {}",
                    cifile::truncate(&consumer.path.display().to_string(), EVIDENCE_CHARS)
                ),
            },
            Evidence::Text {
                detail: format!("artifact: {}", cifile::truncate(&chain.artifact, 120)),
            },
            Evidence::Text {
                detail: format!("cross-run download: {}", chain.download.detail),
            },
            Evidence::Text {
                detail: format!("{} sink: {}", chain.sink.kind.as_str(), chain.sink.detail),
            },
        ]
        .into_iter()
        .chain(chain.untrusted_verify.map(|verify| Evidence::Text {
            detail: format!(
                "digest check reads a value the artifact itself supplies: {}",
                verify.detail
            ),
        }))
        .collect(),
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRODUCER: &str = r#"
name: CI
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make dist
      - uses: actions/upload-artifact@v4
        with:
          name: build
          path: dist
"#;

    fn consumer(body: &str) -> String {
        format!(
            "name: Deploy\non:\n  workflow_run:\n    workflows: [CI]\n    types: [completed]\njobs:\n  ship:\n    runs-on: ubuntu-latest\n    steps:\n{body}"
        )
    }

    const CROSS_RUN_DOWNLOAD: &str = concat!(
        "      - uses: actions/download-artifact@v4\n",
        "        with:\n",
        "          name: build\n",
        "          path: dist\n",
        "          run-id: ${{ github.event.workflow_run.id }}\n",
        "          github-token: ${{ secrets.GITHUB_TOKEN }}\n",
    );

    fn models(producer: &str, consumer_yaml: &str) -> Vec<WorkflowModel> {
        vec![
            build_model(
                Path::new(".github/workflows/ci.yml"),
                producer,
                MAX_TOTAL_STEPS,
            ),
            build_model(
                Path::new(".github/workflows/deploy.yml"),
                consumer_yaml,
                MAX_TOTAL_STEPS,
            ),
        ]
    }

    fn analyze(producer: &str, consumer_yaml: &str) -> RepositoryFlowResult {
        analyze_repository(&models(producer, consumer_yaml), true)
    }

    #[test]
    fn poisoned_pair_execute_sink_is_one_high_finding() {
        let yaml = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - run: bash ./dist/install.sh\n"
        ));
        let result = analyze(PRODUCER, &yaml);
        assert_eq!(result.findings.len(), 1, "expected exactly one finding");
        let (path, finding) = &result.findings[0];
        assert_eq!(path, Path::new(".github/workflows/deploy.yml"));
        assert_eq!(finding.rule_id, RuleId::WorkflowArtifactPoisoning);
        assert_eq!(finding.severity, Severity::High);
        let evidence = format!("{:?}", finding.evidence);
        assert!(
            evidence.contains("ci.yml"),
            "evidence names the producer: {evidence}"
        );
        assert!(
            evidence.contains("deploy.yml"),
            "evidence names the consumer: {evidence}"
        );
        assert!(
            evidence.contains("build"),
            "evidence names the artifact: {evidence}"
        );
        assert!(result.unproven_consumers.is_empty());
    }

    #[test]
    fn downloaded_report_with_no_dangerous_sink_is_not_a_finding() {
        let yaml = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - run: cat dist/coverage.json\n      - run: ls -la dist\n"
        ));
        let result = analyze(PRODUCER, &yaml);
        assert!(result.findings.is_empty(), "{:?}", result.findings);
        assert_eq!(
            result.unproven_consumers,
            vec![PathBuf::from(".github/workflows/deploy.yml")]
        );
    }

    #[test]
    fn unresolved_named_producer_without_direct_upload_blocks_downgrade() {
        let local_action = r#"
name: CI
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/build
"#;
        let reusable_workflow = r#"
name: CI
on:
  pull_request:
jobs:
  build:
    uses: ./.github/workflows/build.yml
"#;
        let yaml = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - run: cat dist/coverage.json\n"
        ));

        for producer in [local_action, reusable_workflow] {
            let result = analyze(producer, &yaml);
            assert!(result.findings.is_empty(), "{:?}", result.findings);
            assert!(
                result.unproven_consumers.is_empty(),
                "an unresolved producer bound by name may hide the upload"
            );
        }
    }

    #[test]
    fn resolved_named_producer_without_an_upload_does_not_block_downgrade() {
        let producer = r#"
name: CI
on:
  pull_request:
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: cargo fmt --check
"#;
        let yaml = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - run: cat dist/coverage.json\n"
        ));
        let result = analyze(producer, &yaml);
        assert!(result.findings.is_empty(), "{:?}", result.findings);
        assert_eq!(result.unproven_consumers.len(), 1);
    }

    #[test]
    fn unresolved_producer_that_is_not_fork_reachable_does_not_block_downgrade() {
        let producer = r#"
name: CI
on:
  push:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/build
"#;
        let yaml = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - run: cat dist/coverage.json\n"
        ));
        let result = analyze(producer, &yaml);
        assert!(result.findings.is_empty(), "{:?}", result.findings);
        assert_eq!(
            result.unproven_consumers.len(),
            1,
            "only fork-reachable producer uncertainty blocks the downgrade"
        );
    }

    #[test]
    fn artifact_name_mismatch_proves_nothing() {
        let yaml = consumer(concat!(
            "      - uses: actions/download-artifact@v4\n",
            "        with:\n",
            "          name: docs\n",
            "          path: dist\n",
            "          run-id: ${{ github.event.workflow_run.id }}\n",
            "      - run: bash ./dist/install.sh\n",
        ));
        let result = analyze(PRODUCER, &yaml);
        assert!(result.findings.is_empty());
        assert_eq!(result.unproven_consumers.len(), 1);
    }

    #[test]
    fn dynamic_producer_artifact_name_is_partial_not_high() {
        let producer = PRODUCER.replace("name: build", "name: build-${{ matrix.os }}");
        let yaml = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - run: bash ./dist/install.sh\n"
        ));
        let result = analyze(&producer, &yaml);
        assert!(result.findings.is_empty(), "{:?}", result.findings);
        assert!(
            result.unproven_consumers.is_empty(),
            "an unresolved artifact name must block the downgrade too"
        );
    }

    #[test]
    fn download_artifact_v3_cannot_fetch_across_runs() {
        let yaml = consumer(concat!(
            "      - uses: actions/download-artifact@v3\n",
            "        with:\n",
            "          name: build\n",
            "          path: dist\n",
            "          run-id: ${{ github.event.workflow_run.id }}\n",
            "      - run: bash ./dist/install.sh\n",
        ));
        let result = analyze(PRODUCER, &yaml);
        assert!(result.findings.is_empty(), "{:?}", result.findings);
    }

    #[test]
    fn fixed_run_id_is_not_bound_to_the_triggering_run() {
        let yaml = consumer(concat!(
            "      - uses: actions/download-artifact@v4\n",
            "        with:\n",
            "          name: build\n",
            "          path: dist\n",
            "          run-id: 12345\n",
            "      - run: bash ./dist/install.sh\n",
        ));
        let result = analyze(PRODUCER, &yaml);
        assert!(result.findings.is_empty(), "{:?}", result.findings);
    }

    #[test]
    fn another_repository_is_unresolved_not_proven() {
        let yaml = consumer(concat!(
            "      - uses: actions/download-artifact@v4\n",
            "        with:\n",
            "          name: build\n",
            "          path: dist\n",
            "          repository: other/repo\n",
            "          run-id: ${{ github.event.workflow_run.id }}\n",
            "      - run: bash ./dist/install.sh\n",
        ));
        let result = analyze(PRODUCER, &yaml);
        assert!(result.findings.is_empty());
        assert!(result.unproven_consumers.is_empty());
    }

    #[test]
    fn trusted_digest_comparison_suppresses_but_self_supplied_does_not() {
        let trusted = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - run: sha256sum -c checksums.txt\n      - run: bash ./dist/install.sh\n"
        ));
        assert!(
            analyze(PRODUCER, &trusted).findings.is_empty(),
            "a checksum file outside the download directory suppresses"
        );

        let self_supplied = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - run: sha256sum -c dist/checksums.txt\n      - run: bash ./dist/install.sh\n"
        ));
        assert_eq!(
            analyze(PRODUCER, &self_supplied).findings.len(),
            1,
            "a checksum file inside the artifact establishes nothing"
        );
    }

    #[test]
    fn comment_claiming_verification_suppresses_nothing() {
        let yaml = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - run: |\n          # verified upstream, checksum ok\n          bash ./dist/install.sh\n"
        ));
        assert_eq!(analyze(PRODUCER, &yaml).findings.len(), 1);
    }

    #[test]
    fn attestation_verification_suppresses() {
        let yaml = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - run: gh attestation verify dist/app --repo owner/name\n      - run: bash ./dist/install.sh\n"
        ));
        assert!(analyze(PRODUCER, &yaml).findings.is_empty());
    }

    #[test]
    fn every_sink_kind_fires_and_inert_commands_do_not() {
        let sinks = [
            "      - run: bash ./dist/install.sh\n",
            "      - run: . ./dist/env.sh\n",
            "      - run: echo dist/bin >> $GITHUB_PATH\n",
            "      - run: npm publish\n",
            "      - run: kubectl apply -f dist/k8s.yaml\n",
            "      - run: node dist/index.js\n",
        ];
        for sink in sinks {
            let yaml = consumer(&format!("{CROSS_RUN_DOWNLOAD}{sink}"));
            assert_eq!(
                analyze(PRODUCER, &yaml).findings.len(),
                1,
                "sink must fire: {sink}"
            );
        }
        for inert in [
            "      - run: ls dist\n",
            "      - run: cat dist/report.txt\n",
            "      - run: bash -c 'echo hello'\n",
        ] {
            let yaml = consumer(&format!("{CROSS_RUN_DOWNLOAD}{inert}"));
            assert!(
                analyze(PRODUCER, &yaml).findings.is_empty(),
                "inert step must not fire: {inert}"
            );
        }
    }

    #[test]
    fn interpreter_module_and_env_assignment_shapes_are_not_sinks() {
        // Each of these follows a download into the WORKSPACE ROOT, where every
        // relative operand is nominally "inside" the artifact, so only the
        // operand's shape keeps them from reading as artifact execution.
        let root_download = concat!(
            "      - uses: actions/download-artifact@v4\n",
            "        with:\n",
            "          name: build\n",
            "          run-id: ${{ github.event.workflow_run.id }}\n",
        );
        for inert in [
            "      - run: python -m pip install requests\n",
            "      - run: node --version\n",
            "      - run: echo 'FOO=bar' >> $GITHUB_ENV\n",
            "      - run: echo RELEASE=1 >> $GITHUB_ENV\n",
        ] {
            let yaml = consumer(&format!("{root_download}{inert}"));
            assert!(
                analyze(PRODUCER, &yaml).findings.is_empty(),
                "must not read as an artifact sink: {inert}"
            );
        }
        // The same env-file write DOES fire when it puts a workspace path on PATH.
        for sink in [
            "      - run: echo dist/bin >> $GITHUB_PATH\n",
            "      - run: echo \"PATH=$GITHUB_WORKSPACE/dist/bin:$PATH\" >> $GITHUB_ENV\n",
            "      - run: bash build.sh\n",
        ] {
            let yaml = consumer(&format!("{root_download}{sink}"));
            assert_eq!(
                analyze(PRODUCER, &yaml).findings.len(),
                1,
                "must read as an artifact sink: {sink}"
            );
        }
    }

    #[test]
    fn sink_before_download_is_not_a_chain() {
        let yaml = consumer(&format!(
            "      - run: bash ./dist/install.sh\n{CROSS_RUN_DOWNLOAD}"
        ));
        assert!(analyze(PRODUCER, &yaml).findings.is_empty());
    }

    #[test]
    fn sink_outside_the_download_directory_is_not_a_chain() {
        let yaml = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - run: bash ./scripts/install.sh\n"
        ));
        assert!(analyze(PRODUCER, &yaml).findings.is_empty());
    }

    #[test]
    fn trusted_push_only_producer_never_participates() {
        let producer = PRODUCER.replace("on:\n  pull_request:", "on:\n  push:");
        let yaml = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - run: bash ./dist/install.sh\n"
        ));
        let result = analyze(&producer, &yaml);
        assert!(result.findings.is_empty(), "{:?}", result.findings);
        assert_eq!(result.unproven_consumers.len(), 1);
    }

    #[test]
    fn consumer_bound_to_a_different_producer_name_is_not_a_chain() {
        let yaml = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - run: bash ./dist/install.sh\n"
        ))
        .replace("workflows: [CI]", "workflows: [Docs]");
        assert!(analyze(PRODUCER, &yaml).findings.is_empty());
    }

    #[test]
    fn wildcard_producer_list_is_partial_not_high() {
        let yaml = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - run: bash ./dist/install.sh\n"
        ))
        .replace("workflows: [CI]", "workflows: ['*']");
        let result = analyze(PRODUCER, &yaml);
        assert!(result.findings.is_empty());
        assert!(result.unproven_consumers.is_empty());
    }

    #[test]
    fn dawidd6_bound_download_is_a_recognised_consumer_shape() {
        let yaml = consumer(concat!(
            "      - uses: dawidd6/action-download-artifact@v6\n",
            "        with:\n",
            "          name: build\n",
            "          path: dist\n",
            "          run_id: ${{ github.event.workflow_run.id }}\n",
            "      - run: bash ./dist/install.sh\n",
        ));
        assert_eq!(analyze(PRODUCER, &yaml).findings.len(), 1);
    }

    #[test]
    fn dawidd6_workflow_branch_form_is_unresolved() {
        let yaml = consumer(concat!(
            "      - uses: dawidd6/action-download-artifact@v6\n",
            "        with:\n",
            "          name: build\n",
            "          path: dist\n",
            "          workflow: ci.yml\n",
            "      - run: bash ./dist/install.sh\n",
        ));
        let result = analyze(PRODUCER, &yaml);
        assert!(result.findings.is_empty());
        assert!(result.unproven_consumers.is_empty());
    }

    #[test]
    fn github_script_listing_the_triggering_run_is_a_recognised_consumer_shape() {
        let yaml = consumer(concat!(
            "      - uses: actions/github-script@v7\n",
            "        with:\n",
            "          script: |\n",
            "            const all = await github.rest.actions.listWorkflowRunArtifacts({\n",
            "              owner: context.repo.owner,\n",
            "              repo: context.repo.repo,\n",
            "              run_id: context.payload.workflow_run.id,\n",
            "            });\n",
            "            const match = all.data.artifacts.filter(a => a.name == \"build\")[0];\n",
            "      - run: unzip build.zip -d dist\n",
            "      - run: npm publish\n",
        ));
        assert_eq!(analyze(PRODUCER, &yaml).findings.len(), 1);
    }

    #[test]
    fn gh_run_download_in_a_run_step_is_a_recognised_consumer_shape() {
        let yaml = consumer(concat!(
            "      - run: gh run download ${{ github.event.workflow_run.id }} --name build --dir dist\n",
            "      - run: bash ./dist/install.sh\n",
        ));
        assert_eq!(analyze(PRODUCER, &yaml).findings.len(), 1);
    }

    #[test]
    fn reusable_workflow_consumer_is_unresolved_never_high() {
        let yaml = "name: Deploy\non:\n  workflow_run:\n    workflows: [CI]\njobs:\n  ship:\n    uses: ./.github/workflows/deploy-impl.yml\n";
        let result = analyze(PRODUCER, yaml);
        assert!(result.findings.is_empty());
        assert!(result.unproven_consumers.is_empty());
    }

    #[test]
    fn local_composite_action_step_is_unresolved() {
        let yaml = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - uses: ./.github/actions/ship\n"
        ));
        let result = analyze(PRODUCER, &yaml);
        assert!(result.findings.is_empty());
        assert!(result.unproven_consumers.is_empty());
    }

    #[test]
    fn matrix_consumer_job_is_unresolved() {
        let yaml = format!(
            "name: Deploy\non:\n  workflow_run:\n    workflows: [CI]\njobs:\n  ship:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        os: [linux, mac]\n    steps:\n{CROSS_RUN_DOWNLOAD}      - run: bash ./dist/install.sh\n"
        );
        let result = analyze(PRODUCER, &yaml);
        assert!(result.findings.is_empty());
        assert!(result.unproven_consumers.is_empty());
    }

    #[test]
    fn malformed_and_degenerate_yaml_yield_no_findings_and_no_panic() {
        for text in [
            "this: is: not: yaml: [",
            "just a scalar",
            "- a\n- b\n",
            "jobs:\n  - one\n  - two\n",
            "on:\n  workflow_run:\njobs: 7\n",
            "",
        ] {
            let model = build_model(Path::new(".github/workflows/x.yml"), text, MAX_TOTAL_STEPS);
            let result = analyze_repository(&[model], true);
            assert!(result.findings.is_empty(), "text: {text:?}");
        }
    }

    #[test]
    fn yaml_aliases_expand_once_and_still_prove_the_chain() {
        let yaml = concat!(
            "name: Deploy\n",
            "on:\n  workflow_run:\n    workflows: [CI]\n",
            "x-download: &dl\n",
            "  uses: actions/download-artifact@v4\n",
            "  with:\n",
            "    name: build\n",
            "    path: dist\n",
            "    run-id: ${{ github.event.workflow_run.id }}\n",
            "jobs:\n",
            "  ship:\n",
            "    runs-on: ubuntu-latest\n",
            "    steps:\n",
            "      - *dl\n",
            "      - run: bash ./dist/install.sh\n",
        );
        let result = analyze(PRODUCER, yaml);
        assert_eq!(result.findings.len(), 1, "alias-expanded step must resolve");
    }

    #[test]
    fn step_budget_exhaustion_blocks_the_downgrade() {
        let yaml = consumer(&format!("{CROSS_RUN_DOWNLOAD}      - run: ls dist\n"));
        let models = vec![
            build_model(
                Path::new(".github/workflows/ci.yml"),
                PRODUCER,
                MAX_TOTAL_STEPS,
            ),
            build_model(Path::new(".github/workflows/deploy.yml"), &yaml, 1),
        ];
        assert!(models[1].steps_truncated());
        assert_eq!(
            models[1].truncation_reasons().collect::<Vec<_>>(),
            vec![WorkflowTruncationReason::StepBudgetExhausted]
        );
        let result = analyze_repository(&models, true);
        assert!(result.findings.is_empty());
        assert!(
            result.unproven_consumers.is_empty(),
            "a truncated model must never claim the absence of a chain"
        );
    }

    #[test]
    fn workflow_structural_truncation_reasons_are_exact() {
        let jobs = (0..=MAX_JOBS_PER_WORKFLOW)
            .map(|index| format!(r#""job-{index}":{{"steps":[]}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let job_limited = build_model(
            Path::new(".github/workflows/jobs.json"),
            &format!(r#"{{"jobs":{{{jobs}}}}}"#),
            MAX_TOTAL_STEPS,
        );
        assert!(job_limited.steps_truncated());
        assert_eq!(
            job_limited.truncation_reasons().collect::<Vec<_>>(),
            vec![WorkflowTruncationReason::JobBudgetExhausted]
        );

        let download_step = r#"{"uses":"actions/download-artifact@v4","with":{"run-id":"${{ github.event.workflow_run.id }}"}}"#;
        let event_steps = |count: usize| {
            (0..count)
                .map(|_| download_step)
                .collect::<Vec<_>>()
                .join(",")
        };
        let at_event_limit = build_model(
            Path::new(".github/workflows/events-at-limit.json"),
            &format!(
                r#"{{"jobs":{{"consume":{{"steps":[{}]}}}}}}"#,
                event_steps(MAX_EVENTS_PER_JOB)
            ),
            MAX_TOTAL_STEPS,
        );
        assert!(!at_event_limit.steps_truncated());
        assert_eq!(at_event_limit.step_count(), MAX_EVENTS_PER_JOB);
        assert!(at_event_limit.truncation_reasons().next().is_none());

        let event_limited = build_model(
            Path::new(".github/workflows/events-over-limit.json"),
            &format!(
                r#"{{"jobs":{{"consume":{{"steps":[{}]}}}}}}"#,
                event_steps(MAX_EVENTS_PER_JOB + 1)
            ),
            MAX_TOTAL_STEPS,
        );
        assert!(event_limited.steps_truncated());
        assert_eq!(event_limited.step_count(), MAX_EVENTS_PER_JOB + 1);
        assert_eq!(
            event_limited.truncation_reasons().collect::<Vec<_>>(),
            vec![WorkflowTruncationReason::EventBudgetExhausted]
        );

        let upload_steps = (0..=MAX_UPLOADS_PER_WORKFLOW)
            .map(|index| {
                format!(
                    r#"{{"uses":"actions/upload-artifact@v4","with":{{"name":"build-{index}","path":"dist"}}}}"#
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let upload_limited = build_model(
            Path::new(".github/workflows/uploads.json"),
            &format!(r#"{{"jobs":{{"build":{{"steps":[{upload_steps}]}}}}}}"#),
            MAX_TOTAL_STEPS,
        );
        assert!(upload_limited.steps_truncated());
        assert_eq!(
            upload_limited.truncation_reasons().collect::<Vec<_>>(),
            vec![WorkflowTruncationReason::UploadBudgetExhausted]
        );
    }

    #[test]
    fn incomplete_repository_coverage_blocks_the_downgrade() {
        let yaml = consumer(&format!("{CROSS_RUN_DOWNLOAD}      - run: ls dist\n"));
        let result = analyze_repository(&models(PRODUCER, &yaml), false);
        assert!(result.unproven_consumers.is_empty());
    }

    #[test]
    fn unparsed_sibling_workflow_blocks_the_downgrade() {
        let yaml = consumer(&format!("{CROSS_RUN_DOWNLOAD}      - run: ls dist\n"));
        let mut models = models(PRODUCER, &yaml);
        models.push(build_model(
            Path::new(".github/workflows/broken.yml"),
            "a: [",
            MAX_TOTAL_STEPS,
        ));
        let result = analyze_repository(&models, true);
        assert!(result.unproven_consumers.is_empty());
    }

    #[test]
    fn unresolvable_step_shell_blocks_the_high() {
        let yaml = format!(
            "name: Deploy\non:\n  workflow_run:\n    workflows: [CI]\njobs:\n  ship:\n    runs-on: ${{{{ env.RUNNER }}}}\n    steps:\n{CROSS_RUN_DOWNLOAD}      - run: bash ./dist/install.sh\n"
        );
        let result = analyze(PRODUCER, &yaml);
        assert!(result.findings.is_empty());
        assert!(result.unproven_consumers.is_empty());
    }

    #[test]
    fn download_with_no_name_lands_each_artifact_in_its_own_subdirectory() {
        // `actions/download-artifact` with no `name:` takes every artifact of the
        // run and unpacks EACH into `<path>/<artifact-name>/`, so `build` lands
        // at `dist/build`, not at `dist`.
        let nested = consumer(concat!(
            "      - uses: actions/download-artifact@v4\n",
            "        with:\n",
            "          path: dist\n",
            "          run-id: ${{ github.event.workflow_run.id }}\n",
            "      - run: bash ./dist/build/install.sh\n",
        ));
        assert_eq!(analyze(PRODUCER, &nested).findings.len(), 1);

        let flat = consumer(concat!(
            "      - uses: actions/download-artifact@v4\n",
            "        with:\n",
            "          path: dist\n",
            "          run-id: ${{ github.event.workflow_run.id }}\n",
            "      - run: bash ./dist/install.sh\n",
        ));
        let result = analyze(PRODUCER, &flat);
        assert!(
            result.findings.is_empty(),
            "no artifact of the run can write dist/install.sh: {:?}",
            result.findings
        );

        // `merge-multiple: true` is the documented opt-out: everything is
        // unpacked into `path` itself, so the flat operand IS the artifact.
        let merged = consumer(concat!(
            "      - uses: actions/download-artifact@v4\n",
            "        with:\n",
            "          path: dist\n",
            "          merge-multiple: true\n",
            "          run-id: ${{ github.event.workflow_run.id }}\n",
            "      - run: bash ./dist/install.sh\n",
        ));
        assert_eq!(analyze(PRODUCER, &merged).findings.len(), 1);
    }

    #[test]
    fn pattern_download_is_unresolved() {
        let yaml = consumer(concat!(
            "      - uses: actions/download-artifact@v4\n",
            "        with:\n",
            "          pattern: build-*\n",
            "          path: dist\n",
            "          run-id: ${{ github.event.workflow_run.id }}\n",
            "      - run: bash ./dist/install.sh\n",
        ));
        let result = analyze(PRODUCER, &yaml);
        assert!(result.findings.is_empty());
        assert!(result.unproven_consumers.is_empty());
    }

    #[test]
    fn sha_pinned_download_action_is_still_recognised() {
        let pin = "a".repeat(40);
        let yaml = consumer(&format!(
            "      - uses: actions/download-artifact@{pin}\n        with:\n          name: build\n          path: dist\n          run-id: ${{{{ github.event.workflow_run.id }}}}\n      - run: bash ./dist/install.sh\n"
        ));
        assert_eq!(analyze(PRODUCER, &yaml).findings.len(), 1);
    }

    #[test]
    fn publish_action_step_is_a_sink() {
        let yaml = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - uses: pypa/gh-action-pypi-publish@release/v1\n"
        ));
        assert_eq!(analyze(PRODUCER, &yaml).findings.len(), 1);
    }

    // Adversarial-review regressions (C15 round 2). Each of these was a SILENT
    // wrong answer before the fix: a High for a chain that cannot happen, or a
    // downgrade to Medium for a chain the analyzer could not actually see.

    #[test]
    fn nameless_download_does_not_taint_the_trusted_checkout() {
        // GitHub's own fork-safe reporter pattern: download every artifact of the
        // triggering run into the workspace, then run a script from the trusted
        // default-branch checkout. Each artifact lands in `./<name>/`, so the
        // repository's own script is provably not the artifact's bytes.
        let yaml = consumer(concat!(
            "      - uses: actions/download-artifact@v4\n",
            "        with:\n",
            "          run-id: ${{ github.event.workflow_run.id }}\n",
            "          github-token: ${{ secrets.GITHUB_TOKEN }}\n",
            "      - run: node .github/scripts/comment.js\n",
        ));
        let result = analyze(PRODUCER, &yaml);
        assert!(
            result.findings.is_empty(),
            "a script from the trusted checkout is not the artifact: {:?}",
            result.findings
        );

        // The same download DOES prove the chain for an operand in the artifact's
        // own subdirectory.
        let poisoned = consumer(concat!(
            "      - uses: actions/download-artifact@v4\n",
            "        with:\n",
            "          run-id: ${{ github.event.workflow_run.id }}\n",
            "      - run: node ./build/index.js\n",
        ));
        assert_eq!(analyze(PRODUCER, &poisoned).findings.len(), 1);
    }

    #[test]
    fn gh_run_download_without_a_name_isolates_each_artifact() {
        let flat = consumer(concat!(
            "      - run: gh run download ${{ github.event.workflow_run.id }} --dir out\n",
            "      - run: bash ./out/install.sh\n",
        ));
        assert!(
            analyze(PRODUCER, &flat).findings.is_empty(),
            "with no --name, gh isolates each artifact into out/<name>/"
        );
        let nested = consumer(concat!(
            "      - run: gh run download ${{ github.event.workflow_run.id }} --dir out\n",
            "      - run: bash ./out/build/install.sh\n",
        ));
        assert_eq!(analyze(PRODUCER, &nested).findings.len(), 1);
    }

    #[test]
    fn a_github_env_assignment_is_a_sink_only_for_a_loader_variable() {
        // Recording where the artifact was put is bookkeeping; no later step
        // resolves anything from `report_dir`.
        for inert in [
            "      - run: echo \"report_dir=dist/reports\" >> $GITHUB_ENV\n",
            "      - run: echo \"ARTIFACT=dist/pkg/app.tgz\" >> $GITHUB_ENV\n",
        ] {
            let yaml = consumer(&format!("{CROSS_RUN_DOWNLOAD}{inert}"));
            let result = analyze(PRODUCER, &yaml);
            assert!(
                result.findings.is_empty(),
                "an ordinary env assignment is not a PATH mutation: {inert} -> {:?}",
                result.findings
            );
            assert_eq!(
                result.unproven_consumers.len(),
                1,
                "and it leaves nothing unresolved: {inert}"
            );
        }
        // A variable the loader actually reads from still fires.
        for sink in [
            "      - run: echo \"LD_PRELOAD=dist/evil.so\" >> $GITHUB_ENV\n",
            "      - run: echo \"NODE_OPTIONS=dist/preload.js\" >> $GITHUB_ENV\n",
        ] {
            let yaml = consumer(&format!("{CROSS_RUN_DOWNLOAD}{sink}"));
            assert_eq!(
                analyze(PRODUCER, &yaml).findings.len(),
                1,
                "a loader variable IS a sink: {sink}"
            );
        }
    }

    #[test]
    fn an_unevaluated_if_condition_is_partial_not_high() {
        // (a) The producer only uploads on `push`, so a fork's pull request never
        // creates the artifact this consumer would download.
        let guarded_producer = PRODUCER.replace(
            "      - uses: actions/upload-artifact@v4\n",
            "      - uses: actions/upload-artifact@v4\n        if: github.event_name == 'push'\n",
        );
        let yaml = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - run: bash ./dist/install.sh\n"
        ));
        let result = analyze(&guarded_producer, &yaml);
        assert!(
            result.findings.is_empty(),
            "a conditional upload cannot complete a chain: {:?}",
            result.findings
        );
        assert!(
            result.unproven_consumers.is_empty(),
            "nor may it be read as proof that no chain exists"
        );

        // (b) The consumer job carries the documented `workflow_run` mitigation.
        let guarded_consumer = format!(
            "name: Deploy\non:\n  workflow_run:\n    workflows: [CI]\njobs:\n  ship:\n    runs-on: ubuntu-latest\n    if: github.event.workflow_run.head_repository.full_name == github.repository\n    steps:\n{CROSS_RUN_DOWNLOAD}      - run: bash ./dist/install.sh\n"
        );
        let result = analyze(PRODUCER, &guarded_consumer);
        assert!(result.findings.is_empty(), "{:?}", result.findings);
        assert!(result.unproven_consumers.is_empty());

        // A run-status gate constrains nothing about fork reachability, so the
        // ordinary `workflow_run` idiom must still prove the chain.
        let status_gate = format!(
            "name: Deploy\non:\n  workflow_run:\n    workflows: [CI]\njobs:\n  ship:\n    runs-on: ubuntu-latest\n    if: ${{{{ github.event.workflow_run.conclusion == 'success' }}}}\n    steps:\n{CROSS_RUN_DOWNLOAD}      - run: bash ./dist/install.sh\n"
        );
        assert_eq!(analyze(PRODUCER, &status_gate).findings.len(), 1);
    }

    #[test]
    fn a_digest_check_the_analyzer_cannot_place_suppresses_nothing_silently() {
        // The checksum file is named through a variable, so whether the artifact
        // wrote it is unknown. Reading that as a passing check is how an attacker
        // hides the whole chain.
        let opaque_operand = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - run: sha256sum -c \"$SUMS\"\n      - run: bash ./dist/install.sh\n"
        ));
        let result = analyze(PRODUCER, &opaque_operand);
        assert!(result.findings.is_empty(), "{:?}", result.findings);
        assert!(
            result.unproven_consumers.is_empty(),
            "an unplaceable digest operand must block the downgrade too"
        );

        // Same for an extraction directory outside the workspace: the digest file
        // is inside the artifact, so the fork supplies payload AND digests.
        let opaque_dest = consumer(concat!(
            "      - uses: actions/download-artifact@v4\n",
            "        with:\n",
            "          name: build\n",
            "          path: /tmp/art\n",
            "          run-id: ${{ github.event.workflow_run.id }}\n",
            "      - run: sha256sum -c /tmp/art/SHA256SUMS\n",
            "      - run: npm publish\n",
        ));
        let result = analyze(PRODUCER, &opaque_dest);
        assert!(result.findings.is_empty(), "{:?}", result.findings);
        assert!(result.unproven_consumers.is_empty());
    }

    #[test]
    fn a_command_that_could_move_the_artifact_blocks_the_downgrade() {
        for relocation in [
            "      - run: tar -xzf dist/app.tar.gz -C .\n      - run: bash ./install.sh\n",
            "      - run: cp dist/install.sh ./setup.sh\n      - run: ./setup.sh\n",
            "      - run: unzip -o dist/bundle.zip -d stage\n      - run: bash stage/install.sh\n",
            "      - run: pip install dist/app-1.0-py3-none-any.whl\n",
            "      - run: bash \"$RUNNER_TEMP/art/install.sh\"\n",
        ] {
            let yaml = consumer(&format!("{CROSS_RUN_DOWNLOAD}{relocation}"));
            let result = analyze(PRODUCER, &yaml);
            assert!(
                result.unproven_consumers.is_empty(),
                "an unmodelled use of the artifact must never read as clean: {relocation}"
            );
        }
        // Provably inert reads still leave the consumer downgradable.
        let inert = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - run: cat dist/coverage.json\n      - run: ls -la dist\n"
        ));
        assert_eq!(analyze(PRODUCER, &inert).unproven_consumers.len(), 1);
    }

    #[test]
    fn find_execution_mutation_and_unknown_actions_block_the_downgrade() {
        for command in [
            "find dist -type f -exec {} +",
            "find dist -type f -execdir sh {} +",
            "find dist -type f -ok cat {} ;",
            "find dist -type f -okdir cat {} ;",
            "find dist -type f -delete",
            "find dist -type f -fprint files.txt",
            "find dist -type f -fprint0 files.bin",
            "find dist -type f -fprintf files.txt '%p\\n'",
            "find dist -type f -fls files.txt",
            "find dist -type f -unknown-action",
            "find <(bash dist/install.sh) -print",
        ] {
            let yaml = consumer(&format!("{CROSS_RUN_DOWNLOAD}      - run: {command}\n"));
            let result = analyze(PRODUCER, &yaml);
            assert!(
                result.findings.is_empty(),
                "{command}: {:?}",
                result.findings
            );
            assert!(
                result.unproven_consumers.is_empty(),
                "a side-effecting or unknown find action must block the downgrade: {command}"
            );
        }
    }

    #[test]
    fn proven_read_only_find_remains_downgradable() {
        for command in [
            "find dist -type f -print",
            "find -L dist -maxdepth 2 -name '*.json' -printf '%p\\n'",
            "find -D search -O2 dist -newermt 2024-01-01 -print0",
            "find dist -name -exec -print",
            "find dist ! -empty -a -readable -ls",
        ] {
            let yaml = consumer(&format!("{CROSS_RUN_DOWNLOAD}      - run: {command}\n"));
            let result = analyze(PRODUCER, &yaml);
            assert!(
                result.findings.is_empty(),
                "{command}: {:?}",
                result.findings
            );
            assert_eq!(
                result.unproven_consumers.len(),
                1,
                "a proven read-only find must remain inert: {command}"
            );
        }
    }

    #[test]
    fn an_unmodelled_fetch_of_the_triggering_run_blocks_the_downgrade() {
        // `gh api .../artifacts` + `curl` of an `archive_download_url` is a real
        // published download mechanism this pass does not model.
        let rest = consumer(concat!(
            "      - run: gh api /repos/${{ github.repository }}/actions/runs/${{ github.event.workflow_run.id }}/artifacts > list.json\n",
            "      - run: bash ./dist/install.sh\n",
        ));
        let result = analyze(PRODUCER, &rest);
        assert!(
            result.unproven_consumers.is_empty(),
            "{:?}",
            result.unproven_consumers
        );

        // Same for an action with no model at all handed the triggering run id.
        let action = consumer(concat!(
            "      - uses: some/other-download@v1\n",
            "        with:\n",
            "          run_id: ${{ github.event.workflow_run.id }}\n",
            "      - run: bash ./dist/install.sh\n",
        ));
        assert!(analyze(PRODUCER, &action).unproven_consumers.is_empty());
    }

    #[test]
    fn a_docker_build_and_push_of_the_workspace_is_a_sink() {
        let pushed = consumer(&format!(
            "{CROSS_RUN_DOWNLOAD}      - uses: docker/build-push-action@v6\n        with:\n          context: .\n          push: true\n"
        ));
        assert_eq!(analyze(PRODUCER, &pushed).findings.len(), 1);
    }

    #[test]
    fn an_artifact_re_upload_hop_is_partial_not_clean() {
        // A `workflow_run` relay downloads the fork's artifact and republishes it
        // under a new name, which the next consumer then executes.
        let relay = "name: Relay\non:\n  workflow_run:\n    workflows: [CI]\njobs:\n  relay:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          name: build\n          path: dist\n          run-id: ${{ github.event.workflow_run.id }}\n      - uses: actions/upload-artifact@v4\n        with:\n          name: relayed\n          path: dist\n";
        let downstream = "name: Deploy\non:\n  workflow_run:\n    workflows: [Relay]\njobs:\n  ship:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          name: relayed\n          path: dist\n          run-id: ${{ github.event.workflow_run.id }}\n      - run: bash ./dist/install.sh\n";
        let models = vec![
            build_model(
                Path::new(".github/workflows/ci.yml"),
                PRODUCER,
                MAX_TOTAL_STEPS,
            ),
            build_model(
                Path::new(".github/workflows/relay.yml"),
                relay,
                MAX_TOTAL_STEPS,
            ),
            build_model(
                Path::new(".github/workflows/deploy.yml"),
                downstream,
                MAX_TOTAL_STEPS,
            ),
        ];
        let result = analyze_repository(&models, true);
        assert!(
            result.unproven_consumers.is_empty(),
            "neither hop of a relay may be reported as chain-free: {:?}",
            result.unproven_consumers
        );

        // The same hop inside ONE consumer, across two jobs of the same run.
        let same_run = "name: Deploy\non:\n  workflow_run:\n    workflows: [CI]\njobs:\n  fetch:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          name: build\n          path: dist\n          run-id: ${{ github.event.workflow_run.id }}\n      - uses: actions/upload-artifact@v4\n        with:\n          name: staged\n          path: dist\n  ship:\n    needs: fetch\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          name: staged\n          path: dist\n      - run: bash ./dist/install.sh\n";
        assert!(analyze(PRODUCER, same_run).unproven_consumers.is_empty());
    }

    #[test]
    fn workspace_paths_reject_escapes_and_absolutes() {
        assert_eq!(
            workspace_relative("./dist/x.sh").as_deref(),
            Some("dist/x.sh")
        );
        assert_eq!(
            workspace_relative("$GITHUB_WORKSPACE/dist/x.sh").as_deref(),
            Some("dist/x.sh")
        );
        assert!(workspace_relative("/etc/passwd").is_none());
        assert!(workspace_relative("../outside").is_none());
        assert!(workspace_relative("$RUNNER_TEMP/x.sh").is_none());
        assert!(workspace_relative("${{ github.workspace }}/x").is_none());
        assert_eq!(workspace_dir(".").as_deref(), Some(""));
        assert!(path_under("", "anything/at/all"));
        assert!(path_under("dist", "dist/x"));
        assert!(!path_under("dist", "distant/x"));
    }
}
