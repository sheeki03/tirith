//! `tirith capsule run --preset untrusted-project` (C14): the fail-closed
//! recruiter-task preset.
//!
//! The threat is concrete. Someone sends you a repository and asks you to run
//! it: a take-home exercise, a "reproduce this bug" request, a demo dApp. The
//! project then reads your wallet keystore, your browser profile, your SSH keys,
//! or your shell rc, and exfiltrates or overwrites them. This preset is the one
//! command whose promise is that the project runs somewhere it cannot reach any
//! of that.
//!
//! # Fail-closed means it refuses, not that it tries hard
//!
//! Before anything is copied and before anything is spawned, the preset proves
//! the selected backend can deliver EVERY control it requires
//! ([`crate::cli::capsule::preflight_run_to_completion`], which is the same
//! reconciler the launch itself runs). If it cannot, the command refuses,
//! writes a `refused` receipt naming the specific control, and exits non-zero.
//! There is no degraded mode and no uncontained fallback: every launch here
//! passes the fail-closed degraded policy, and the source scan
//! `only_the_declared_best_effort_surfaces_name_the_degraded_policy` in
//! `crates/tirith/tests/owned_boundary_enforcement.rs` fails the build if this
//! file ever names the permissive one.
//!
//! # Where it actually works, stated plainly
//!
//! x86_64 Linux with a usable Landlock ABI, and nowhere else.
//!
//! - raw-network denial is `seccomp_supported()`, which is
//!   `cfg!(target_arch = "x86_64")`, and [`CapsuleSpec::required_coverage`]
//!   demands `network_raw_denied` unconditionally, so every non-x86_64 Linux
//!   host refuses;
//! - macOS cannot enforce a per-process memory ceiling or a process-count
//!   ceiling at all, so the preset's 2 GiB / 256-process request can never be
//!   satisfied there;
//! - the parent-owned wall-clock and combined-output supervisor that owns the
//!   two dimensions no OS backend enforces is Linux-only, so no other platform
//!   can complete the resource contract however capable its sandbox is.
//!
//! That is a correct outcome rather than a gap to paper over. Weakening
//! `required_coverage` to make more platforms "work" would turn every one of
//! those refusals into a silent, uncontained run of an attacker's repository.
//!
//! # Network is deny-all, and that is the only honest option
//!
//! `domain_proxy_enforced` is hard-coded `false` in all three OS backends, and
//! [`tirith_core::capsule::CapsuleCoverage::egress_claim_is_coherent`] forbids
//! claiming domain egress without raw-socket denial. So the preset offers no
//! `--allow-domain` and never implies one. Dependencies must be vendored or
//! pre-installed by a separate trusted transaction; this preset performs no
//! network dependency installation.
//!
//! # Why this is not the bound-CWD launcher, and what it uses instead
//!
//! [`crate::cli::capsule::run_to_completion_bound_directory`] refuses a bound cwd
//! that overlaps a writable grant. That invariant protects a real property: in
//! the bound-cwd protocol the held directory is a READ grant, so a writable grant
//! covering the same subtree would hand the child a second, PATHNAME-derived
//! authority that the descriptor-identity proof does not cover. The preset's held
//! copy has to be writable, so that protocol cannot express it.
//!
//! What the preset must NOT do is fall back to a pathname. A pathname is resolved
//! again in the child (once by `chdir`, once by `PathFd::new` inside the Landlock
//! rule), and a same-UID process that renames the copy and drops a symlink in its
//! place between the parent's identity proof and those resolutions moves the
//! write grant to whatever the symlink names. So the launch goes through
//! [`crate::cli::capsule::run_to_completion_bound_work_directory`]: the parent
//! keeps the descriptor it opened when it created the directory, the launcher
//! enters THAT descriptor with `fchdir`, and the Landlock write rule is built
//! from THAT descriptor. The pathname is still checked, and a swapped visible
//! root is still a refusal, but no decision depends on resolving it again.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use tirith_core::capsule::{
    canonicalize_and_validate_filesystem_policy, deny_default_paths, CapsuleCoverage, CapsuleSpec,
    FilesystemPolicy, ResourceLimits,
};
use tirith_core::capsule_project::{argv_digest, ProjectDiff, ProjectTree};
use tirith_core::capsule_receipt::{
    CapsuleRunCoverage, CapsuleRunDecision, CapsuleRunEvidence, CapsuleRunFacts, CapsuleRunReceipt,
    CapsuleRunStatus, CapsuleRunSubject, CapsuleTreeDigest,
};
use tirith_core::policy::Policy;
use tirith_core::redact::CompiledCustomPatterns;

/// Exit codes, matching the convention C11 established for a new command in this
/// stack, with one addition this command genuinely needs.
///
/// Tirith's decision namespace wins: a caller must be able to tell "Tirith
/// refused or terminated it" from "the project's own command failed", and
/// forwarding the child's status into slot 1 would collapse those.
pub const EXIT_OK: i32 = 0;
/// A Tirith security decision: refused before launch, terminated after it, or a
/// run whose receipt could not be recorded (a containment claim with no durable
/// record must not exit 0).
pub const EXIT_RESTRICTED: i32 = 1;
/// A usage or input error.
pub const EXIT_INPUT: i32 = 2;
/// The run was contained and Tirith is content, but the child itself exited
/// non-zero.
pub const EXIT_CHILD_FAILED: i32 = 3;

/// The only preset this command accepts.
pub const PRESET_UNTRUSTED_PROJECT: &str = "untrusted-project";

/// The exact `PATH` handed to the contained child. Fixed rather than inherited:
/// an inherited `PATH` routinely points into `$HOME`, which the preset denies,
/// and it is operator-environment-shaped input to a containment decision.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const CHILD_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Environment names forwarded from the parent by VALUE when present. Each still
/// passes the value-aware sensitive gate inside the launcher.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const FORWARDED_ENV: &[&str] = &["LANG", "LC_ALL", "TERM", "TZ"];

/// Candidate read roots the contained child needs in order to `exec` an
/// interpreter and load its shared libraries at all. Only the ones that exist on
/// this host enter the policy, and none of them can overlap the home-anchored
/// deny roots.
const INTERPRETER_READ_ROOT_CANDIDATES: &[&str] =
    &["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"];

/// The two resource dimensions the PARENT supervisor owns, because no OS backend
/// enforces either. Recorded by name in the receipt so it never reads as a
/// backend claim.
const PARENT_ENFORCED_DIMENSIONS: &[&str] = &["max_output_bytes", "wall_clock_seconds"];

/// Everything one invocation decided, in the shape the receipt and both output
/// projections need.
struct PresetOutcome {
    status: CapsuleRunStatus,
    decision: CapsuleRunDecision,
    backend_id: String,
    coverage: CapsuleRunCoverage,
    limits: ResourceLimits,
    child_exit_code: Option<i32>,
    termination_kind: Option<String>,
    reason: Option<String>,
    project_copy_materialized: bool,
    cleanup_confirmed: bool,
    project_input: Option<ProjectTree>,
    project_output: Option<ProjectTree>,
    diff: ProjectDiff,
    task_gate_binding: String,
    policy_projection_hash: String,
}

impl PresetOutcome {
    fn refused(
        backend_id: &str,
        spec: &CapsuleSpec,
        reason: String,
        context: &PresetContext,
    ) -> Self {
        PresetOutcome {
            status: CapsuleRunStatus::Refused,
            decision: CapsuleRunDecision::RefusedBeforeLaunch,
            backend_id: backend_id.to_string(),
            coverage: CapsuleRunCoverage {
                requested: spec.required_coverage(),
                achieved: CapsuleCoverage::NONE,
                parent_enforced_dimensions: parent_enforced_dimensions(),
            },
            limits: spec.resources.clone(),
            child_exit_code: None,
            termination_kind: None,
            reason: Some(reason),
            // Nothing was created, so there is nothing outstanding to clean up.
            project_copy_materialized: false,
            cleanup_confirmed: true,
            project_input: None,
            project_output: None,
            diff: ProjectDiff::default(),
            task_gate_binding: context.task_gate_binding.clone(),
            policy_projection_hash: context.policy_projection_hash.clone(),
        }
    }

    fn exit_code(&self) -> i32 {
        match self.status {
            CapsuleRunStatus::Refused => EXIT_RESTRICTED,
            CapsuleRunStatus::Partial => EXIT_RESTRICTED,
            CapsuleRunStatus::Contained => match self.child_exit_code {
                Some(0) => EXIT_OK,
                _ => EXIT_CHILD_FAILED,
            },
        }
    }
}

/// The policy-derived context every outcome carries, resolved once.
struct PresetContext {
    task_gate_binding: String,
    policy_projection_hash: String,
    denied_effects: std::collections::BTreeSet<tirith_core::effects::CommandEffectKind>,
    refusal: Option<String>,
    dlp: CompiledCustomPatterns,
}

fn parent_enforced_dimensions() -> Vec<String> {
    PARENT_ENFORCED_DIMENSIONS
        .iter()
        .map(|name| (*name).to_string())
        .collect()
}

fn interpreter_read_roots() -> Vec<PathBuf> {
    INTERPRETER_READ_ROOT_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .filter(|path| path.exists())
        .collect()
}

/// Build the preset spec for one project root and apply the task-gate ceiling.
///
/// The tightening goes through [`tirith_core::task_boundary::tighten_capsule_spec`],
/// which narrows a spec from the DENIED-EFFECT set rather than from budget
/// fields `TaskGatePolicy` does not have. It only ever removes a capability, so
/// composing it with an already-minimal preset cannot widen anything; that is
/// pinned by `tightening_the_untrusted_project_preset_never_widens_it`.
fn preset_spec(project_root: &Path, context: &PresetContext) -> CapsuleSpec {
    let mut spec = CapsuleSpec::untrusted_project(project_root, &interpreter_read_roots());
    tirith_core::task_boundary::tighten_capsule_spec(&mut spec, &context.denied_effects);
    spec
}

/// The environment the contained child receives. Everything else is stripped by
/// the launcher, and `HOME` / `TMPDIR` / `XDG_*` are set by it to the temporary
/// HOME after the survivor set is computed.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn child_environment() -> Vec<(String, String)> {
    let mut environment = vec![("PATH".to_string(), CHILD_PATH.to_string())];
    for name in FORWARDED_ENV {
        if let Ok(value) = std::env::var(name) {
            environment.push(((*name).to_string(), value));
        }
    }
    environment
}

fn resolve_task_context(argv: &[OsString]) -> PresetContext {
    use tirith_core::effects::CommandEffectKind;

    let policy = Policy::discover_local_only(None);
    let dlp = CompiledCustomPatterns::new_silent(&policy.dlp_custom_patterns);
    // The envelope describes the operation to the gate. The argv text stays
    // local to this decision; the receipt records only its digest.
    let rendered: Vec<String> = argv
        .iter()
        .map(|element| element.to_string_lossy().into_owned())
        .collect();
    let envelope = tirith_core::task_boundary::shell_envelope(&rendered.join(" "));
    let operation = tirith_core::task_boundary::BoundaryOperation {
        boundary: tirith_core::task_boundary::OwnedBoundary::CapsulePresetRun,
        envelope: &envelope,
        adapter: tirith_core::task::IngressAdapter::Unattributed,
        // True of the transition whatever the argv parses to: the preset exists
        // to let an untrusted project WRITE, inside a copy.
        boundary_effects: [CommandEffectKind::FilesystemWrite].into_iter().collect(),
    };
    let assessment = tirith_core::task_boundary::evaluate(&operation, &policy.task_gate);
    PresetContext {
        task_gate_binding: tirith_core::task_boundary::ceiling_binding(&assessment.decision),
        policy_projection_hash: policy.security_projection_hash(),
        denied_effects: assessment.enforced_denied_effects(),
        // This boundary has no approval channel, so a required approval is a
        // refusal: a gate that cannot ask is a gate that must say no.
        refusal: assessment.refusal(false).map(str::to_string),
        dlp,
    }
}

/// Entry point for `tirith capsule run`.
pub fn run(
    preset: &str,
    project: &Path,
    receipt_path: Option<&Path>,
    argv: &[OsString],
    json: bool,
) -> i32 {
    if preset != PRESET_UNTRUSTED_PROJECT {
        return input_error(
            &format!("unknown preset '{preset}'; the only preset is '{PRESET_UNTRUSTED_PROJECT}'"),
            json,
        );
    }
    if argv.is_empty() {
        return input_error(
            "no command to run; pass the exact argv after `--`, for example \
             `tirith capsule run --preset untrusted-project --project . -- npm test`",
            json,
        );
    }
    if argv[0].as_os_str().is_empty() {
        return input_error("the first argv element is empty", json);
    }
    let source = match std::fs::canonicalize(project) {
        Ok(path) => path,
        Err(error) => {
            return input_error(
                &format!("cannot resolve --project {}: {error}", project.display()),
                json,
            )
        }
    };
    if !source.is_dir() {
        return input_error(
            &format!("--project {} is not a directory", project.display()),
            json,
        );
    }

    let context = resolve_task_context(argv);
    let mut prepared = None;
    let outcome = evaluate_and_run(&source, argv, &context, receipt_path, &mut prepared);
    let receipt = build_receipt(&outcome, argv, &context.dlp);
    let recorded = match prepared.as_ref() {
        Some(prepared) => receipt.record_prepared(prepared),
        None => receipt.record(receipt_path),
    };
    emit(&outcome, &receipt, recorded, json, &context.dlp)
}

/// Everything from "the inputs parse" to "the run is over", with no output.
fn evaluate_and_run(
    source: &Path,
    argv: &[OsString],
    context: &PresetContext,
    receipt_path: Option<&Path>,
    prepared_receipt: &mut Option<tirith_core::capsule_receipt::PreparedCapsuleReceipt>,
) -> PresetOutcome {
    let probe_spec = preset_spec(source, context);
    let backend_id = crate::cli::capsule::select_backend(&probe_spec).backend_id;

    // The project itself must not BE a credential store. Checked against the
    // shared deny catalogue before anything is copied, so `--project ~` and
    // `--project ~/.ssh` refuse with the reason rather than being copied.
    let source_policy = FilesystemPolicy {
        read_roots: Vec::new(),
        write_roots: vec![source.to_path_buf()],
        deny_roots: deny_default_paths(),
    };
    if let Err(error) = canonicalize_and_validate_filesystem_policy(&source_policy) {
        return PresetOutcome::refused(
            backend_id,
            &probe_spec,
            format!(
                "--project names a path the untrusted-project preset denies by default: {error}"
            ),
            context,
        );
    }

    if let Some(reason) = &context.refusal {
        return PresetOutcome::refused(
            backend_id,
            &probe_spec,
            format!("task gate refused before any project copy: {reason}"),
            context,
        );
    }

    // Prove the host can deliver every requested control BEFORE copying an
    // untrusted repository onto the operator's disk.
    if let Err(refused) = crate::cli::capsule::preflight_run_to_completion(&probe_spec) {
        return PresetOutcome::refused(refused.backend_id, &probe_spec, refused.reason, context);
    }

    // Only after the side-effect-free deny and backend gates have passed:
    // retain the requested receipt parent before the first tree scan. An
    // in-project receipt is excluded by this exact relative path.
    let prepared = match tirith_core::capsule_receipt::PreparedCapsuleReceipt::prepare(
        receipt_path,
        Some(source),
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            return PresetOutcome::refused(
                backend_id,
                &probe_spec,
                format!("prepare capsule receipt destination: {error}"),
                context,
            )
        }
    };
    let receipt_exclusion = prepared.project_exclusion().map(Path::to_path_buf);
    *prepared_receipt = Some(prepared);

    contained_run(
        source,
        argv,
        context,
        backend_id,
        &probe_spec,
        receipt_exclusion.as_deref(),
    )
}

#[cfg(not(target_os = "linux"))]
fn contained_run(
    _source: &Path,
    _argv: &[OsString],
    context: &PresetContext,
    backend_id: &'static str,
    probe_spec: &CapsuleSpec,
    _receipt_exclusion: Option<&Path>,
) -> PresetOutcome {
    // Unreachable in practice: `preflight_run_to_completion` refuses on every
    // non-Linux host above. Kept as a hard refusal rather than a `todo!()` so a
    // future backend that satisfies the probe cannot reach an unwritten launch.
    PresetOutcome::refused(
        backend_id,
        probe_spec,
        "the untrusted-project preset has no launch path on this platform".to_string(),
        context,
    )
}

/// Finish a refusal that happened AFTER the held ephemeral directory existed.
///
/// The copy must be removed and the receipt must say whether that actually
/// happened: a refusal that quietly left an untrusted repository on the
/// operator's disk is not a clean refusal, so an unconfirmed cleanup downgrades
/// the record to `partial` rather than reporting a tidy `refused`.
#[cfg(target_os = "linux")]
fn refuse_after_creation(
    held: &mut crate::cli::capsule::HeldEphemeralDirectory,
    backend_id: &str,
    spec: &CapsuleSpec,
    reason: String,
    context: &PresetContext,
    project_input: Option<ProjectTree>,
    project_copy_materialized: bool,
) -> PresetOutcome {
    let cleaned = match held.cleanup_with_hook(|| {}) {
        Ok(()) => true,
        Err(error) => {
            eprintln!("tirith capsule run: the held project copy was preserved: {error}");
            false
        }
    };
    let mut outcome = PresetOutcome::refused(backend_id, spec, reason, context);
    // Once the project's own bytes are on disk, the receipt must not say that
    // nothing was written there, whatever else it says.
    outcome.project_copy_materialized = project_copy_materialized;
    outcome.cleanup_confirmed = cleaned;
    // Recorded even on a refusal: the copy really was made, and its digest is
    // what an operator needs to reason about what was on disk.
    outcome.project_input = project_input;
    if !cleaned {
        outcome.status = CapsuleRunStatus::Partial;
    }
    outcome
}

#[cfg(target_os = "linux")]
fn contained_run(
    source: &Path,
    argv: &[OsString],
    context: &PresetContext,
    backend_id: &'static str,
    probe_spec: &CapsuleSpec,
    receipt_exclusion: Option<&Path>,
) -> PresetOutcome {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let refuse = |reason: String| PresetOutcome::refused(backend_id, probe_spec, reason, context);

    // Same fixed sticky root, same confined-cleanup proof, and the same held
    // ephemeral directory type the capsule launcher already uses for its
    // temporary HOME. Nothing here is a second implementation of either.
    let base = match std::path::Path::new("/tmp").canonicalize() {
        Ok(path) => path,
        Err(error) => return refuse(format!("resolve fixed ephemeral root /tmp: {error}")),
    };
    let preflight_root = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&base)
    {
        Ok(handle) => handle,
        Err(error) => return refuse(format!("open cleanup preflight root: {error}")),
    };
    if let Err(error) =
        crate::cli::capsule::preflight_owned_directory_cleanup(preflight_root.as_raw_fd())
    {
        return refuse(format!(
            "prove capability-confined cleanup before creating the project copy: {error}"
        ));
    }
    let directory = match tempfile::Builder::new()
        .prefix("tirith-capsule-project-")
        .tempdir_in(&base)
    {
        Ok(directory) => directory,
        Err(error) => return refuse(format!("create the held project copy: {error}")),
    };
    if let Err(error) =
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
    {
        return refuse(format!("secure the held project copy: {error}"));
    }
    let mut held = match crate::cli::capsule::HeldEphemeralDirectory::from_tempdir(
        directory,
        backend_id,
        "capsule project copy",
    ) {
        Ok(held) => held,
        Err(refused) => return refuse(refused.reason),
    };
    let copy_root = match held.path().canonicalize() {
        Ok(path) if path == held.path() => path,
        Ok(path) => {
            let reason = format!(
                "the held project copy is not canonical: {} resolves elsewhere",
                path.display()
            );
            // The held directory exists but no project bytes were written into
            // it, so this refusal really did copy nothing.
            return refuse_after_creation(
                &mut held, backend_id, probe_spec, reason, context, None, false,
            );
        }
        Err(error) => {
            let reason = format!("resolve the held project copy: {error}");
            return refuse_after_creation(
                &mut held, backend_id, probe_spec, reason, context, None, false,
            );
        }
    };

    if let Err(error) = tirith_core::capsule_project::copy_project_tree_excluding(
        source,
        &copy_root,
        receipt_exclusion,
    ) {
        // The copier writes as it walks, so a refusal here is a refusal with an
        // arbitrary prefix of an attacker's repository already on disk.
        return refuse_after_creation(
            &mut held,
            backend_id,
            probe_spec,
            error.to_string(),
            context,
            None,
            true,
        );
    }
    let input = match tirith_core::capsule_project::inventory_project_tree_stable(&copy_root, None)
    {
        Ok(input) => input,
        Err(error) => {
            return refuse_after_creation(
                &mut held,
                backend_id,
                probe_spec,
                error.to_string(),
                context,
                None,
                true,
            )
        }
    };

    // The launch spec is the preset over the COPY, re-proved against the same
    // reconciler. The probe above answered for the source root; this answers for
    // the exact spec that will be applied.
    let spec = preset_spec(&copy_root, context);
    if let Err(refused) = crate::cli::capsule::preflight_run_to_completion(&spec) {
        return refuse_after_creation(
            &mut held,
            backend_id,
            &spec,
            refused.reason,
            context,
            Some(input),
            true,
        );
    }
    // The cleanup identity is also the launch precondition: if the visible root
    // no longer names the directory we created and copied into, refuse rather
    // than hand a swapped tree to the child.
    let identity = match held.visible_root_matches_held_identity() {
        Ok(true) => Ok(()),
        Ok(false) => Err(
            "the held project copy no longer identifies its retained directory capability"
                .to_string(),
        ),
        Err(error) => Err(format!("verify the held project copy identity: {error}")),
    };
    if let Err(reason) = identity {
        return refuse_after_creation(
            &mut held,
            backend_id,
            &spec,
            reason,
            context,
            Some(input),
            true,
        );
    }

    // The copy reaches the child as the DESCRIPTOR the parent has held since it
    // created and populated the directory, not as the pathname it proved a moment
    // ago. That is the difference between a check and a binding: a same-UID
    // rename plus symlink after this point cannot move either the child's working
    // directory or its one writable grant.
    let launched = crate::cli::capsule::run_to_completion_bound_work_directory(
        &spec,
        argv[0].as_os_str(),
        &argv[1..],
        crate::cli::capsule::BoundWorkDirectory {
            handle: held.handle(),
            canonical_root: &copy_root,
        },
        &child_environment(),
        crate::cli::capsule::DegradedPolicy::FailClosed,
    );
    let outcome = match launched {
        Ok(outcome) => outcome,
        Err(refused) => {
            return refuse_after_creation(
                &mut held,
                refused.backend_id,
                &spec,
                refused.reason,
                context,
                Some(input),
                true,
            )
        }
    };

    let output_scan = tirith_core::capsule_project::inventory_project_tree_stable(&copy_root, None);
    let (output, diff, inventory_reason) = match output_scan {
        Ok(output) => {
            let diff = tirith_core::capsule_project::diff_project_trees(&input, &output);
            (Some(output), diff, None)
        }
        Err(error) => (None, ProjectDiff::default(), Some(error.to_string())),
    };
    let copy_cleaned = match held.cleanup_with_hook(|| {}) {
        Ok(()) => true,
        Err(error) => {
            eprintln!("tirith capsule run: the held project copy was preserved: {error}");
            false
        }
    };

    let child_tree_cleaned = outcome
        .termination
        .as_ref()
        .map(|termination| termination.cleanup_confirmed)
        .unwrap_or(true);
    let cleanup_confirmed = cleanup_is_confirmed(
        copy_cleaned,
        child_tree_cleaned,
        // A launch path that did not observe the temporary HOME leaves the claim
        // unproven, which is not the same as proven true.
        outcome.ephemeral_home_cleanup_confirmed.unwrap_or(false),
    );
    let (decision, termination_kind, mut reason) = match &outcome.termination {
        Some(termination) => (
            CapsuleRunDecision::TerminatedByTirith,
            Some(format!("{:?}", termination.kind)),
            Some(termination.reason.clone()),
        ),
        None => (CapsuleRunDecision::TargetCompleted, None, None),
    };
    if let Some(inventory_reason) = inventory_reason {
        reason = Some(match reason {
            Some(reason) => format!("{reason}; output inventory failed: {inventory_reason}"),
            None => format!("output inventory failed: {inventory_reason}"),
        });
    }
    let coverage = CapsuleRunCoverage {
        requested: spec.required_coverage(),
        achieved: outcome.coverage,
        parent_enforced_dimensions: parent_enforced_dimensions(),
    };
    let contained = decision == CapsuleRunDecision::TargetCompleted
        && cleanup_confirmed
        && input.complete
        && output.as_ref().is_some_and(|output| output.complete)
        && !coverage.achieved.is_degraded_against(&coverage.requested);

    PresetOutcome {
        status: if contained {
            CapsuleRunStatus::Contained
        } else {
            CapsuleRunStatus::Partial
        },
        decision,
        backend_id: outcome.backend_id.to_string(),
        coverage,
        limits: spec.resources.clone(),
        child_exit_code: Some(outcome.exit_code),
        termination_kind,
        reason,
        project_copy_materialized: true,
        cleanup_confirmed,
        project_input: Some(input),
        project_output: output,
        diff,
        task_gate_binding: context.task_gate_binding.clone(),
        policy_projection_hash: context.policy_projection_hash.clone(),
    }
}

/// Whether every ephemeral artifact this run created was proven gone.
///
/// Three separate observations, ANDed, because the receipt's `cleanup_confirmed`
/// claims all three: the held project copy (proved by the parent's own
/// capability-relative removal), the contained process tree (proved by the
/// supervisor), and the launcher's temporary HOME (proved by the launcher). An
/// unproven one is not a small gap: it is whatever the untrusted project wrote
/// to `$HOME`, still on the operator's disk, under a receipt that says otherwise.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn cleanup_is_confirmed(
    project_copy_removed: bool,
    child_tree_reaped: bool,
    ephemeral_home_removed: bool,
) -> bool {
    project_copy_removed && child_tree_reaped && ephemeral_home_removed
}

fn tree_digest(tree: &ProjectTree) -> CapsuleTreeDigest {
    CapsuleTreeDigest {
        digest: tree.digest.clone(),
        file_count: tree.file_count,
        total_bytes: tree.total_bytes,
        complete: tree.complete,
    }
}

fn build_receipt(
    outcome: &PresetOutcome,
    argv: &[OsString],
    dlp: &CompiledCustomPatterns,
) -> CapsuleRunReceipt {
    CapsuleRunReceipt::new(CapsuleRunFacts {
        status: outcome.status,
        policy_projection_hash: outcome.policy_projection_hash.clone(),
        task_gate_binding: outcome.task_gate_binding.clone(),
        subject: CapsuleRunSubject {
            preset: PRESET_UNTRUSTED_PROJECT.to_string(),
            argv_digest: argv_digest(argv),
            argv_len: argv.len(),
            project_input: outcome.project_input.as_ref().map(tree_digest),
            project_output: outcome.project_output.as_ref().map(tree_digest),
        },
        evidence: CapsuleRunEvidence {
            backend_id: outcome.backend_id.clone(),
            platform: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
            limits: outcome.limits.clone(),
            child_exit_code: outcome.child_exit_code,
            decision: outcome.decision,
            termination_kind: outcome.termination_kind.clone(),
            reason: outcome
                .reason
                .as_deref()
                .map(|reason| bounded_reason(reason, dlp)),
            project_copy_materialized: outcome.project_copy_materialized,
            cleanup_confirmed: outcome.cleanup_confirmed,
            diff: outcome.diff.clone(),
        },
        coverage: outcome.coverage.clone(),
    })
}

/// Bound and redact any parent-generated text before it becomes durable. The
/// strings are already parent-authored and secret-free by construction, but a
/// receipt is a durable artifact and the redaction pass is not conditional on
/// believing that.
///
/// It runs the SAME operator-configured DLP patterns the terminal rendering
/// runs. A durable artifact getting weaker redaction than the transient one it
/// summarizes is exactly backwards: the file is the copy that gets shared.
/// Absolute host paths are removed separately, inside
/// [`tirith_core::capsule_receipt::CapsuleRunReceipt::new`].
fn bounded_reason(reason: &str, dlp: &CompiledCustomPatterns) -> String {
    tirith_core::redact::sanitize_provenance_text_with_compiled(reason, dlp)
}

fn input_error(message: &str, json: bool) -> i32 {
    if json {
        let value = serde_json::json!({
            "command": "capsule run",
            "preset": PRESET_UNTRUSTED_PROJECT,
            "status": "input_error",
            "message": message,
        });
        if !crate::cli::write_json_stdout(&value, "tirith capsule run: cannot write JSON output") {
            return EXIT_INPUT;
        }
    } else {
        eprintln!("tirith capsule run: {message}");
    }
    EXIT_INPUT
}

fn emit(
    outcome: &PresetOutcome,
    receipt: &CapsuleRunReceipt,
    recorded: Result<
        tirith_core::capsule_receipt::RecordedCapsuleReceipt,
        tirith_core::capsule_receipt::CapsuleReceiptError,
    >,
    json: bool,
    dlp: &CompiledCustomPatterns,
) -> i32 {
    let (receipt_path, store_path, signed, anchored, anchor_warning, receipt_error) =
        match &recorded {
            Ok(recorded) => (
                recorded
                    .requested_path
                    .as_ref()
                    .map(|path| path.display().to_string()),
                recorded
                    .store_path
                    .as_ref()
                    .map(|path| path.display().to_string()),
                recorded.signed,
                recorded.anchored,
                recorded.anchor_warning.clone(),
                None,
            ),
            Err(error) => (None, None, false, false, None, Some(error.to_string())),
        };

    // An anchor WARNING is an anchor failure: `ReceiptAnchor::Skipped` carries
    // none, so a host with no chain configured is not penalized.
    let anchor_failed = anchor_warning.is_some();
    let safe = |value: &str| tirith_core::output::sanitize_human_field_with_compiled(value, dlp);
    if json {
        let value = serde_json::json!({
            "command": "capsule run",
            "preset": PRESET_UNTRUSTED_PROJECT,
            "status": outcome.status.token(),
            "tirith_decision": outcome.decision.token(),
            "backend": outcome.backend_id,
            "platform": format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
            "child_exit_code": outcome.child_exit_code,
            "termination_kind": outcome.termination_kind,
            "reason": outcome.reason.as_deref().map(&safe),
            "cleanup_confirmed": outcome.cleanup_confirmed,
            "requested_coverage": outcome.coverage.requested,
            "achieved_coverage": outcome.coverage.achieved,
            "parent_enforced_dimensions": outcome.coverage.parent_enforced_dimensions,
            "limits": outcome.limits,
            "project_input_digest": outcome.project_input.as_ref().map(|tree| &tree.digest),
            "project_output_digest": outcome.project_output.as_ref().map(|tree| &tree.digest),
            "diff": outcome.diff,
            "receipt_id": receipt.receipt_id,
            "receipt_signed": signed,
            "receipt_anchored": anchored,
            "receipt_path": receipt_path,
            "receipt_store_path": store_path,
            "receipt_anchor_warning": anchor_warning,
            "receipt_error": receipt_error,
            "project_copy_materialized": outcome.project_copy_materialized,
            "exit_code": exit_code_with_receipt(outcome, receipt_error.is_some(), anchor_failed),
        });
        if !crate::cli::write_json_stdout(&value, "tirith capsule run: cannot write JSON output") {
            return EXIT_INPUT;
        }
        return exit_code_with_receipt(outcome, receipt_error.is_some(), anchor_failed);
    }

    match outcome.status {
        CapsuleRunStatus::Refused => {
            eprintln!(
                "tirith capsule run: {}",
                refusal_headline(outcome.project_copy_materialized)
            );
            if let Some(reason) = &outcome.reason {
                eprintln!("  {}", safe(reason));
            }
            eprintln!(
                "  The untrusted-project preset is enforceable only on x86_64 Linux with a usable \
                 Landlock ABI. It never falls back to a degraded or uncontained run."
            );
        }
        CapsuleRunStatus::Partial => {
            eprintln!("tirith capsule run: PARTIAL (contained, but the record is not clean).");
            if let Some(reason) = &outcome.reason {
                eprintln!("  {}", safe(reason));
            }
            eprintln!("  cleanup confirmed: {}", outcome.cleanup_confirmed);
        }
        CapsuleRunStatus::Contained => {
            println!(
                "tirith capsule run: CONTAINED (backend {}).",
                outcome.backend_id
            );
        }
    }
    if outcome.status != CapsuleRunStatus::Refused {
        println!(
            "  child exit: {}",
            outcome
                .child_exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "  project files changed: +{} ~{} -{}{}",
            outcome.diff.added.len(),
            outcome.diff.modified.len(),
            outcome.diff.removed.len(),
            if outcome.diff.truncated {
                " (truncated)"
            } else {
                ""
            }
        );
    }
    println!("  receipt: {}", receipt.receipt_id);
    // Paths are terminal-neutralized but NOT DLP-redacted: both are Tirith or
    // operator generated, and the content-addressed filename is a sha256 that
    // the secret-shape redactor would otherwise blank, leaving the operator
    // unable to find the file the command just wrote.
    if let Some(path) = &receipt_path {
        println!(
            "  written: {}",
            crate::cli::sanitize_for_human_output(path, false)
        );
    }
    if let Some(path) = &store_path {
        println!(
            "  stored:  {}",
            crate::cli::sanitize_for_human_output(path, false)
        );
    }
    println!(
        "  receipt is {} and {}",
        if signed {
            "ed25519-signed"
        } else {
            "unsigned (no audit signing key configured)"
        },
        if anchored {
            "anchored in the audit chain"
        } else {
            "NOT anchored in the audit chain"
        }
    );
    if let Some(warning) = &anchor_warning {
        eprintln!(
            "tirith capsule run: receipt anchor warning: {}",
            safe(warning)
        );
    }
    if let Some(error) = &receipt_error {
        eprintln!(
            "tirith capsule run: receipt could not be recorded: {}",
            safe(error)
        );
    }
    exit_code_with_receipt(outcome, receipt_error.is_some(), anchor_failed)
}

/// What the operator is told a refusal cost them.
///
/// The copier writes as it walks and then hard-refuses on the first symlink or
/// unsupported entry, which an ordinary repository trips, so the common refusal
/// is the one that happens with the copy already on disk. Printing "nothing was
/// copied" there is a false statement about the most likely case.
fn refusal_headline(project_copy_materialized: bool) -> &'static str {
    if project_copy_materialized {
        "REFUSED after the project was copied (the copy was removed; the project's command never ran)."
    } else {
        "REFUSED before launch (nothing was copied or spawned)."
    }
}

/// The command's exit code, downgraded when the receipt could not be recorded or
/// could not be anchored.
///
/// A contained run whose receipt does not exist is a containment CLAIM with no
/// durable record, and exiting 0 would tell a caller the record is there. An
/// anchor FAILURE is the same defect one step later: the receipt exists but is
/// not tamper-evident, so a later edit or deletion of it goes undetected. An
/// anchor SKIP is not a failure (no chain is configured), and does not downgrade.
fn exit_code_with_receipt(
    outcome: &PresetOutcome,
    receipt_failed: bool,
    anchor_failed: bool,
) -> i32 {
    let code = outcome.exit_code();
    if (receipt_failed || anchor_failed) && code == EXIT_OK {
        EXIT_RESTRICTED
    } else {
        code
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_child_environment_is_a_fixed_path_and_nothing_sensitive() {
        let environment = child_environment();
        let path = environment
            .iter()
            .find(|(name, _)| name == "PATH")
            .expect("PATH is always supplied");
        assert_eq!(path.1, CHILD_PATH);
        assert!(!path.1.contains("$HOME"));
        for (name, _) in &environment {
            assert!(
                tirith_core::capsule::UNTRUSTED_PROJECT_ENV_ALLOW.contains(&name.as_str()),
                "{name} is forwarded but not in the preset allow-list"
            );
        }
    }

    #[test]
    fn interpreter_read_roots_never_overlap_the_default_deny_roots() {
        let deny = deny_default_paths();
        let policy = FilesystemPolicy {
            read_roots: interpreter_read_roots(),
            write_roots: Vec::new(),
            deny_roots: deny,
        };
        // On a host whose authenticated home could not be resolved the deny set
        // is the empty poison root and validation fails closed, which is the
        // correct behaviour and not something to assert against.
        if policy
            .deny_roots
            .iter()
            .any(|root| root.as_os_str().is_empty())
        {
            return;
        }
        assert!(canonicalize_and_validate_filesystem_policy(&policy).is_ok());
    }

    #[test]
    fn exit_codes_keep_tirith_decisions_apart_from_the_child_status() {
        let base = |status, child| PresetOutcome {
            status,
            decision: CapsuleRunDecision::TargetCompleted,
            backend_id: "landlock-seccomp".to_string(),
            coverage: CapsuleRunCoverage {
                requested: CapsuleCoverage::NONE,
                achieved: CapsuleCoverage::NONE,
                parent_enforced_dimensions: parent_enforced_dimensions(),
            },
            limits: ResourceLimits::conservative(),
            child_exit_code: child,
            termination_kind: None,
            reason: None,
            project_copy_materialized: false,
            cleanup_confirmed: true,
            project_input: None,
            project_output: None,
            diff: ProjectDiff::default(),
            task_gate_binding: String::new(),
            policy_projection_hash: String::new(),
        };
        assert_eq!(
            base(CapsuleRunStatus::Contained, Some(0)).exit_code(),
            EXIT_OK
        );
        assert_eq!(
            base(CapsuleRunStatus::Contained, Some(7)).exit_code(),
            EXIT_CHILD_FAILED
        );
        assert_eq!(
            base(CapsuleRunStatus::Partial, Some(0)).exit_code(),
            EXIT_RESTRICTED
        );
        assert_eq!(
            base(CapsuleRunStatus::Refused, None).exit_code(),
            EXIT_RESTRICTED
        );

        // A contained run whose receipt could not be recorded is a containment
        // claim with no durable record, so it must not exit 0.
        let clean = base(CapsuleRunStatus::Contained, Some(0));
        assert_eq!(exit_code_with_receipt(&clean, false, false), EXIT_OK);
        assert_eq!(exit_code_with_receipt(&clean, true, false), EXIT_RESTRICTED);
        // Nor may a receipt that exists but could not be anchored: an unanchored
        // receipt is not tamper-evident, and the audited party is the one who
        // controls whether the anchor succeeds.
        assert_eq!(exit_code_with_receipt(&clean, false, true), EXIT_RESTRICTED);
        // A receipt failure never MASKS a worse outcome.
        let failing_child = base(CapsuleRunStatus::Contained, Some(7));
        assert_eq!(
            exit_code_with_receipt(&failing_child, true, true),
            EXIT_CHILD_FAILED
        );
    }

    #[test]
    fn a_refusal_after_the_copy_never_claims_nothing_was_copied() {
        assert!(refusal_headline(false).contains("nothing was copied or spawned"));
        let after_copy = refusal_headline(true);
        assert!(
            !after_copy.contains("nothing was copied"),
            "a refusal that materialized the copy must not deny it: {after_copy}"
        );
        assert!(after_copy.contains("the copy was removed"));
    }

    #[test]
    fn the_durable_reason_runs_the_operators_own_dlp_patterns() {
        // The same patterns the terminal rendering applies. The receipt is the
        // copy that gets shared, so it cannot be the one with weaker redaction.
        let dlp = CompiledCustomPatterns::new_silent(&["overlaps deny root".to_string()]);
        let redacted = bounded_reason("write allow root A overlaps deny root B", &dlp);
        assert!(
            !redacted.contains("overlaps deny root"),
            "the operator's pattern was dropped on the durable path: {redacted}"
        );
        assert!(redacted.contains("REDACTED"));
    }

    #[test]
    fn cleanup_is_only_confirmed_when_all_three_artifacts_are_proven_gone() {
        assert!(cleanup_is_confirmed(true, true, true));
        assert!(!cleanup_is_confirmed(false, true, true));
        assert!(!cleanup_is_confirmed(true, false, true));
        // The temporary HOME holds whatever the untrusted project wrote to
        // $HOME. An unproven removal is not a confirmed cleanup.
        assert!(!cleanup_is_confirmed(true, true, false));
    }
}
