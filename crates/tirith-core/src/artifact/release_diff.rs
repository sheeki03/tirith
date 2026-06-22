//! Local release differential between two versions of the SAME distribution
//! (PR F2): compare an OLD wheel against a NEW wheel and flag the structural
//! deltas that, in the live supply-chain campaign, mark a benign release turning
//! malicious. It is a COMPOSITION over already-computed inspection data, not a new
//! byte analyzer: each side is an [`ArtifactInspection`] produced by the B8
//! [`crate::artifact::inspect::inspect_artifact_file`] (which streams the wheel
//! through the A4 [`crate::artifact::archive::read_wheel`] and runs the B5/B6/B7
//! analyzers), and the diff reasons over the two inspections' files, signals, and
//! execution edges.
//!
//! # What a release anomaly is
//!
//! A new release is expected to change code; it is NOT expected to change its
//! EXECUTION SHAPE without reason. The campaign's tell is a quiet, pure-Python
//! package that, in a point release, suddenly:
//!
//! * ships a compiled extension where there was none ([`ReleaseAnomalyKind::PureToNative`]),
//! * gains an interpreter-startup hook where there was none
//!   ([`ReleaseAnomalyKind::StartupHookAdded`]),
//! * bundles a multi-megabyte JavaScript payload where there was little or none
//!   ([`ReleaseAnomalyKind::JavaScriptVolumeJump`]),
//! * changes the distribution IDENTITY it claims ([`ReleaseAnomalyKind::IdentityChanged`]),
//! * or grows a new execution capability (a `.pth`/native subprocess spawn, a
//!   network/runtime download, or a native execution entry) that the prior release
//!   did not have ([`ReleaseAnomalyKind::NewExecutionCapability`]).
//!
//! Each of these is a HEURISTIC delta: a legitimate release can add a native
//! extension or a startup hook. So the single user-facing finding
//! [`crate::verdict::RuleId::ArtifactReleaseAnomaly`] is MEDIUM severity (it
//! WARNS, the plan's "flag", and never auto-blocks); a strict policy can upgrade
//! it via `action_overrides`. The conjunction that is actually conclusive (a
//! startup hook that reaches a process spawn, a native import-execution chain) is
//! already caught at full BLOCK strength by the existing
//! `python_startup_hook_*` / `native_import_execution_chain` rules during the
//! ordinary inspection of the NEW wheel; this differential is the complementary
//! "what changed between releases" signal, deliberately not a second copy of
//! those.
//!
//! # Reuse, and the honest scope boundary
//!
//! The diff reads ONLY what the inspection already surfaces:
//! [`ArtifactInspection::files`] (kind + size + member path, the source of the
//! native / startup / JavaScript-volume deltas), [`ArtifactInspection::signals`]
//! (the [`crate::artifact::ArtifactSignalKind`] set, the source of the new
//! execution-capability delta), and the subject identity (the name, the source of
//! the identity delta). It introduces NO new extraction. Entry-point granularity
//! is intentionally NOT covered here: `entry_points.txt` is not captured onto the
//! inspection (the archive reader hands the visitor only startup hooks and the
//! RECORD), and inventing an entry-point capture path would be a new analyzer, out
//! of this unit's scope; an entry-point change that MATTERS (a console script that
//! now launches a foreign runtime) surfaces instead as a `NewExecutionCapability`
//! through the B6 cross-runtime edge/signal. The diff is local-artifact-only: it
//! compares two on-disk wheels, with no registry or network access.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::artifact::inspect::{inspect_artifact_file, ArtifactInspectError};
use crate::artifact::{
    ArtifactFileKind, ArtifactInspection, ArtifactSignalKind, InspectionSubject,
};
use crate::policy::Policy;
use crate::verdict::{Evidence, Finding, RuleId, Severity, Timings, Verdict};

/// The default JavaScript-volume threshold (bytes) above which a release that had
/// little or no bundled JavaScript and now ships a large JavaScript payload is a
/// [`ReleaseAnomalyKind::JavaScriptVolumeJump`]. 1 MiB: the campaign's bundled
/// `_index.js`-style payloads are multi-megabyte, while an honest small helper
/// script is far under this, so the threshold separates "a script" from "a
/// shipped runtime payload" without flagging trivial JS.
pub const JS_VOLUME_JUMP_BYTES: u64 = 1024 * 1024;

/// The kind of structural delta a release differential can flag. Each maps to one
/// "the execution shape changed" observation; the concrete detail is carried in
/// [`ReleaseAnomaly::detail`]. Fieldless so a set of kinds can be collected into a
/// [`BTreeSet`] for a stable, deduplicated summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseAnomalyKind {
    /// The OLD release carried no native module (`.so`/`.dylib`/`.pyd`/`.node`)
    /// and the NEW release does. A pure-Python package growing a compiled
    /// extension is the campaign's primary pivot.
    PureToNative,
    /// The OLD release carried no interpreter-startup hook (`.pth`/`.start`/
    /// `sitecustomize.py`/`usercustomize.py`) and the NEW release does. A package
    /// that newly runs code at every interpreter start is a strong tell.
    StartupHookAdded,
    /// The NEW release bundles substantially more JavaScript (by total `.js`/
    /// `.mjs`/`.cjs` member bytes) than the OLD one, crossing
    /// [`JS_VOLUME_JUMP_BYTES`] from a near-empty baseline. A Python wheel that
    /// suddenly ships a multi-megabyte JS payload is unusual.
    JavaScriptVolumeJump,
    /// The two artifacts claim DIFFERENT distribution names (PEP 503 normalized).
    /// A release of the same project keeps its name; a different name means the
    /// two are not a release pair (a possible substitution).
    IdentityChanged,
    /// The NEW release gained an execution-capability signal the OLD lacked: a
    /// `.pth`/startup subprocess spawn or network download, a native danger
    /// capability (downloader / runtime loader / process spawn / dynamic code
    /// loading), or a native execution entry. The concrete signal kinds are named
    /// in the detail.
    NewExecutionCapability,
}

impl ReleaseAnomalyKind {
    /// A short, stable label for the kind (for the finding evidence / summary).
    pub fn label(self) -> &'static str {
        match self {
            ReleaseAnomalyKind::PureToNative => "pure-to-native",
            ReleaseAnomalyKind::StartupHookAdded => "startup-hook-added",
            ReleaseAnomalyKind::JavaScriptVolumeJump => "javascript-volume-jump",
            ReleaseAnomalyKind::IdentityChanged => "identity-changed",
            ReleaseAnomalyKind::NewExecutionCapability => "new-execution-capability",
        }
    }
}

/// One flagged release delta: its kind and a human-readable detail naming the
/// concrete change (the member that appeared, the byte counts, the new signal
/// kinds). Carries no [`RuleId`]; the whole [`ReleaseDiff`] correlates into the
/// single [`RuleId::ArtifactReleaseAnomaly`] finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseAnomaly {
    /// What changed.
    pub kind: ReleaseAnomalyKind,
    /// Human-readable supporting detail, carried into the finding evidence. Names
    /// only structural facts (member paths, counts, signal kinds); never a secret.
    pub detail: String,
}

/// The result of differencing an OLD release against a NEW release: every flagged
/// anomaly, in a stable order. Empty means the two releases have the same
/// execution shape (no anomaly), which is the expected case for an honest point
/// release.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseDiff {
    /// The flagged deltas, sorted by kind then detail for determinism.
    pub anomalies: Vec<ReleaseAnomaly>,
}

impl ReleaseDiff {
    /// Whether any anomaly was flagged.
    pub fn has_anomaly(&self) -> bool {
        !self.anomalies.is_empty()
    }

    /// The set of anomaly kinds flagged (deduplicated; a kind appears once even if
    /// several details mapped to it, though the differ emits at most one anomaly
    /// per kind).
    pub fn kinds(&self) -> BTreeSet<ReleaseAnomalyKind> {
        self.anomalies.iter().map(|a| a.kind).collect()
    }

    /// Correlate the flagged anomalies into the single user-facing
    /// [`RuleId::ArtifactReleaseAnomaly`] finding, or no finding when the diff is
    /// clean. MEDIUM severity (it warns, never auto-blocks): a legitimate release
    /// can add native code or a hook, so this is a "look closer" flag, not a
    /// confirmed-malicious verdict. Every anomaly's detail is an
    /// [`Evidence::Text`] leaf; no secret or machine path is serialized.
    pub fn findings(&self) -> Vec<Finding> {
        if self.anomalies.is_empty() {
            return Vec::new();
        }
        let labels: Vec<&str> = self.anomalies.iter().map(|a| a.kind.label()).collect();
        let evidence: Vec<Evidence> = self
            .anomalies
            .iter()
            .map(|a| Evidence::Text {
                detail: a.detail.clone(),
            })
            .collect();
        vec![self.finding_from_anomalies(labels, evidence)]
    }

    /// Build the single [`RuleId::ArtifactReleaseAnomaly`] finding from the
    /// already-collected labels and evidence (the body of [`Self::findings`], split
    /// out so it is not duplicated).
    fn finding_from_anomalies(&self, labels: Vec<&str>, evidence: Vec<Evidence>) -> Finding {
        Finding {
            rule_id: RuleId::ArtifactReleaseAnomaly,
            severity: Severity::Medium,
            title: "A new release changed its execution shape versus the prior release".to_string(),
            description: format!(
                "The release differential found {} structural change(s) between the two artifacts \
                 that, in the live supply-chain campaign, mark a benign release turning malicious: \
                 {}. Each is a heuristic delta a legitimate release can sometimes have, so this \
                 warns rather than blocks; review the change and confirm it is expected before \
                 installing. A change that is conclusive on its own (a startup hook reaching a \
                 process spawn, a native import-execution chain) is flagged separately at block \
                 strength by inspecting the new wheel directly.",
                self.anomalies.len(),
                labels.join(", ")
            ),
            evidence,
            human_view: None,
            agent_view: None,
            mitre_id: Some("T1195".to_string()),
            custom_rule_id: None,
        }
    }

    /// Evaluate this diff under a policy, routing the correlated
    /// [`RuleId::ArtifactReleaseAnomaly`] finding through
    /// [`crate::escalation::finalize_static_verdict`] (cross-cutting invariant 5) so
    /// a per-rule severity / action override is honored at this verdict site. A
    /// clean diff yields an Allow. This is the single verdict seam a CLI reuses, so
    /// the finalize call is not duplicated at the call site.
    pub fn evaluate(&self, policy: &Policy) -> Verdict {
        // Tier-3 by construction (no tier-1 command gate); timings unmeasured here.
        crate::escalation::finalize_static_verdict(self.findings(), policy, 3, Timings::default())
    }
}

/// The error differencing two wheel FILES, naming which side failed so the caller
/// can report it. A diff needs BOTH sides inspected; if either is unreadable /
/// unsupported / oversize there is no shape to compare, so the diff cannot run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseDiffError {
    /// The OLD artifact could not be inspected.
    Old(ArtifactInspectError),
    /// The NEW artifact could not be inspected.
    New(ArtifactInspectError),
}

impl std::fmt::Display for ReleaseDiffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReleaseDiffError::Old(e) => write!(f, "old artifact could not be inspected: {e:?}"),
            ReleaseDiffError::New(e) => write!(f, "new artifact could not be inspected: {e:?}"),
        }
    }
}

impl std::error::Error for ReleaseDiffError {}

/// Difference two wheel FILES: inspect each via the B8
/// [`inspect_artifact_file`] (which reuses the A4 [`read_wheel`] and the B5/B6/B7
/// analyzers) and run the pure [`diff_inspections`] over the two inspections.
/// Local-artifact-only: no registry or network access. Returns the
/// [`ReleaseDiff`], or a [`ReleaseDiffError`] naming the side that could not be
/// inspected.
///
/// A structurally REJECTED wheel (a hard archive violation) is still differenced:
/// its best-effort partial inspection carries the files/signals scanned before
/// rejection, which is the right input for "what shape does this side have". The
/// rejection itself is a separate, stronger signal the inspect/firewall path
/// already surfaces; the differential does not re-derive it.
///
/// [`read_wheel`]: crate::artifact::archive::read_wheel
pub fn diff_artifact_files(old: &Path, new: &Path) -> Result<ReleaseDiff, ReleaseDiffError> {
    let old_inspected = inspect_artifact_file(old).map_err(ReleaseDiffError::Old)?;
    let new_inspected = inspect_artifact_file(new).map_err(ReleaseDiffError::New)?;
    Ok(diff_inspections(
        &old_inspected.inspection,
        &new_inspected.inspection,
    ))
}

/// The pure differential seam: compare two already-computed inspections and flag
/// the release anomalies. No I/O, fully deterministic, so it is unit-tested with
/// hand-built inspections (no real wheels needed). Emits at most one
/// [`ReleaseAnomaly`] per [`ReleaseAnomalyKind`]; the result is sorted for a
/// stable rendering regardless of input order.
pub fn diff_inspections(old: &ArtifactInspection, new: &ArtifactInspection) -> ReleaseDiff {
    let mut anomalies: Vec<ReleaseAnomaly> = Vec::new();

    // --- Identity: the two artifacts should be the same distribution. ----------
    if let (Some(old_name), Some(new_name)) = (
        subject_distribution_name(old),
        subject_distribution_name(new),
    ) {
        let old_norm = crate::artifact::normalize_project_name_public(&old_name);
        let new_norm = crate::artifact::normalize_project_name_public(&new_name);
        if old_norm != new_norm {
            anomalies.push(ReleaseAnomaly {
                kind: ReleaseAnomalyKind::IdentityChanged,
                detail: format!(
                    "the two artifacts claim different distribution names: old '{old_name}' \
                     (normalized '{old_norm}') vs new '{new_name}' (normalized '{new_norm}'); a \
                     release of the same project keeps its name"
                ),
            });
        }
    }

    // --- Pure -> native: a compiled extension where there was none. -------------
    let old_native = count_kind(old, ArtifactFileKind::NativeModule);
    let new_native_paths = member_paths_of_kind(new, ArtifactFileKind::NativeModule);
    if old_native == 0 && !new_native_paths.is_empty() {
        anomalies.push(ReleaseAnomaly {
            kind: ReleaseAnomalyKind::PureToNative,
            detail: format!(
                "the prior release shipped no native module; the new release adds {}: {}",
                new_native_paths.len(),
                join_capped(&new_native_paths, 5)
            ),
        });
    }

    // --- No-hook -> startup hook: code that now runs at interpreter start. ------
    let old_hooks = count_startup_hooks(old);
    let new_hook_paths = startup_hook_member_paths(new);
    if old_hooks == 0 && !new_hook_paths.is_empty() {
        anomalies.push(ReleaseAnomaly {
            kind: ReleaseAnomalyKind::StartupHookAdded,
            detail: format!(
                "the prior release had no interpreter-startup hook; the new release adds {}: {}",
                new_hook_paths.len(),
                join_capped(&new_hook_paths, 5)
            ),
        });
    }

    // --- No-JS -> multi-MB JS: a large bundled JavaScript payload. --------------
    let old_js = javascript_bytes(old);
    let new_js = javascript_bytes(new);
    if old_js < JS_VOLUME_JUMP_BYTES && new_js >= JS_VOLUME_JUMP_BYTES {
        anomalies.push(ReleaseAnomaly {
            kind: ReleaseAnomalyKind::JavaScriptVolumeJump,
            detail: format!(
                "the prior release bundled {old_js} byte(s) of JavaScript; the new release bundles \
                 {new_js} byte(s), crossing the {JS_VOLUME_JUMP_BYTES}-byte payload threshold"
            ),
        });
    }

    // --- New execution capability: a danger signal the prior release lacked. ----
    let old_caps = execution_capability_signals(old);
    let new_caps = execution_capability_signals(new);
    let gained: BTreeSet<ArtifactSignalKind> = new_caps.difference(&old_caps).copied().collect();
    if !gained.is_empty() {
        let names: Vec<&str> = gained.iter().map(signal_kind_label).collect();
        anomalies.push(ReleaseAnomaly {
            kind: ReleaseAnomalyKind::NewExecutionCapability,
            detail: format!(
                "the new release gained execution-capability signal(s) the prior release did not \
                 have: {}",
                names.join(", ")
            ),
        });
    }

    // Stable order: by kind (the enum's declared order), then detail.
    anomalies.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.detail.cmp(&b.detail)));
    ReleaseDiff { anomalies }
}

/// Difference two inspections and evaluate the result under a policy, routing the
/// correlated [`RuleId::ArtifactReleaseAnomaly`] finding through
/// [`crate::escalation::finalize_static_verdict`] (cross-cutting invariant 5) so a
/// per-rule severity / action override is honored at this verdict site exactly
/// like every other artifact verdict. A clean diff yields an Allow.
pub fn evaluate_release_diff(
    old: &ArtifactInspection,
    new: &ArtifactInspection,
    policy: &Policy,
) -> Verdict {
    diff_inspections(old, new).evaluate(policy)
}

// ---------------------------------------------------------------------------
// Inspection accessors (read-only; no new extraction)
// ---------------------------------------------------------------------------

/// The distribution name an inspection's subject claims, when it is a wheel
/// artifact or an installed distribution. A generic archive / lone installed file
/// has no distribution name, so identity is not compared for them.
fn subject_distribution_name(inspection: &ArtifactInspection) -> Option<String> {
    match &inspection.subject {
        InspectionSubject::Artifact(a) => Some(a.name.clone()),
        InspectionSubject::InstalledDistribution(d) => Some(d.name.clone()),
        InspectionSubject::GenericArchive(_) | InspectionSubject::InstalledFile(_) => None,
    }
}

/// How many files of a given kind the inspection carries.
fn count_kind(inspection: &ArtifactInspection, kind: ArtifactFileKind) -> usize {
    inspection.files.iter().filter(|f| f.kind == kind).count()
}

/// The member/installed paths of every file of a given kind, for the evidence
/// detail (so the operator sees WHICH file appeared).
fn member_paths_of_kind(inspection: &ArtifactInspection, kind: ArtifactFileKind) -> Vec<String> {
    let mut paths: Vec<String> = inspection
        .files
        .iter()
        .filter(|f| f.kind == kind)
        .map(|f| location_label(&f.location))
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

/// How many interpreter-startup hooks (`.pth`/`.start`/`sitecustomize`/
/// `usercustomize`) the inspection carries.
fn count_startup_hooks(inspection: &ArtifactInspection) -> usize {
    inspection
        .files
        .iter()
        .filter(|f| is_startup_hook_kind(f.kind))
        .count()
}

/// The paths of every interpreter-startup hook the inspection carries.
fn startup_hook_member_paths(inspection: &ArtifactInspection) -> Vec<String> {
    let mut paths: Vec<String> = inspection
        .files
        .iter()
        .filter(|f| is_startup_hook_kind(f.kind))
        .map(|f| location_label(&f.location))
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

/// Whether a file kind is an interpreter-startup hook.
fn is_startup_hook_kind(kind: ArtifactFileKind) -> bool {
    matches!(
        kind,
        ArtifactFileKind::PthFile | ArtifactFileKind::StartFile | ArtifactFileKind::SiteCustomize
    )
}

/// Total bytes of bundled JavaScript across the inspection's files. JavaScript is
/// not a dedicated [`ArtifactFileKind`] (a `.js` member classifies as
/// [`ArtifactFileKind::Other`]), so it is detected by the member path's extension.
/// Sums the `size` of every `.js`/`.mjs`/`.cjs` member.
fn javascript_bytes(inspection: &ArtifactInspection) -> u64 {
    inspection
        .files
        .iter()
        .filter(|f| is_javascript_path(&f.location))
        .map(|f| f.size)
        .fold(0u64, |acc, n| acc.saturating_add(n))
}

/// Whether a location's member/installed path is a JavaScript file by extension.
fn is_javascript_path(location: &crate::location::SubjectLocation) -> bool {
    let candidate = location
        .member_path
        .as_deref()
        .map(str::to_string)
        .or_else(|| {
            location
                .installed_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
        });
    let Some(path) = candidate else {
        return false;
    };
    let lower = path.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    base.ends_with(".js") || base.ends_with(".mjs") || base.ends_with(".cjs")
}

/// The set of EXECUTION-CAPABILITY signal kinds present in an inspection: the
/// `.pth`/startup spawn and network-download signals (B6) and the native danger
/// capability / execution entry (B7). These are the signals whose APPEARANCE in a
/// new release (absent from the old) is a [`ReleaseAnomalyKind::NewExecutionCapability`].
/// Coverage / uninspectable markers are deliberately excluded: a gap is not a
/// capability, and including it would flag a release that merely got harder to
/// inspect. The "runtime-download" delta the plan names is exactly the appearance
/// of [`ArtifactSignalKind::PthNetworkDownload`] / a downloader-class
/// [`ArtifactSignalKind::NativeDangerCapability`].
fn execution_capability_signals(inspection: &ArtifactInspection) -> BTreeSet<ArtifactSignalKind> {
    inspection
        .signals
        .iter()
        .map(|s| s.kind)
        .filter(|k| is_execution_capability_signal(*k))
        .collect()
}

/// Whether a signal kind is an execution-capability signal (vs a structural /
/// coverage marker). Kept as an explicit allow-list so a NEW signal kind added
/// upstream does not silently become a release-anomaly trigger without review.
fn is_execution_capability_signal(kind: ArtifactSignalKind) -> bool {
    matches!(
        kind,
        ArtifactSignalKind::PthSubprocessSpawn
            | ArtifactSignalKind::PthNetworkDownload
            | ArtifactSignalKind::NativeDangerCapability
            | ArtifactSignalKind::NativeExecutionEntry
    )
}

/// A short, stable label for a signal kind (for the evidence detail).
fn signal_kind_label(kind: &ArtifactSignalKind) -> &'static str {
    match kind {
        ArtifactSignalKind::PthSubprocessSpawn => "startup subprocess spawn",
        ArtifactSignalKind::PthNetworkDownload => "startup network download",
        ArtifactSignalKind::NativeDangerCapability => "native danger capability",
        ArtifactSignalKind::NativeExecutionEntry => "native execution entry",
        // Not an execution-capability signal; never reached via
        // `execution_capability_signals`, but kept total for safety.
        _ => "signal",
    }
}

/// Render a location for evidence (the conventional `outer.whl!/member` notation),
/// preferring the member path so the operator sees the in-wheel location.
fn location_label(location: &crate::location::SubjectLocation) -> String {
    match (&location.member_path, &location.installed_path) {
        (Some(member), _) => member.trim_start_matches('/').to_string(),
        (None, Some(installed)) => installed.to_string_lossy().into_owned(),
        (None, None) => location.to_string(),
    }
}

/// Join up to `cap` items with `, `, appending `(+N more)` when truncated, so a
/// release that adds many members yields a bounded, non-flooding detail string.
fn join_capped(items: &[String], cap: usize) -> String {
    if items.len() <= cap {
        return items.join(", ");
    }
    let shown = items[..cap].join(", ");
    format!("{shown} (+{} more)", items.len() - cap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{
        ArtifactFile, ArtifactIdentity, ArtifactSignal, EdgeConfidence, GenericArchiveIdentity,
    };
    use crate::location::SubjectLocation;
    use crate::threatdb::Ecosystem;
    use crate::verdict::Action;

    /// A wheel-artifact inspection named `name`/`version` carrying the given files
    /// and signals. The test builder for the pure differential seam (no real wheel
    /// is opened).
    fn wheel(
        name: &str,
        version: &str,
        files: Vec<ArtifactFile>,
        signals: Vec<ArtifactSignal>,
    ) -> ArtifactInspection {
        let mut insp = ArtifactInspection::new(InspectionSubject::Artifact(ArtifactIdentity {
            ecosystem: Ecosystem::PyPI,
            name: name.to_string(),
            version: Some(version.to_string()),
            filename: format!("{name}-{version}-py3-none-any.whl"),
            sha256: "a".repeat(64),
        }));
        insp.files = files;
        insp.signals = signals;
        insp
    }

    /// An [`ArtifactFile`] member of `outer` at `member` with `size` and `kind`.
    fn file(outer: &str, member: &str, size: u64, kind: ArtifactFileKind) -> ArtifactFile {
        ArtifactFile {
            location: SubjectLocation::member(outer, member),
            size,
            sha256: "b".repeat(64),
            kind,
        }
    }

    /// An [`ArtifactSignal`] of `kind` at an arbitrary member location.
    fn signal(kind: ArtifactSignalKind) -> ArtifactSignal {
        ArtifactSignal {
            kind,
            location: SubjectLocation::member("x.whl", "x/y"),
            evidence: "test".to_string(),
            confidence: EdgeConfidence::High,
        }
    }

    /// A pure-Python wheel (only a `.py` source) compared against an identical
    /// shape is clean: no anomaly, an Allow verdict.
    #[test]
    fn identical_pure_release_is_clean() {
        let old = wheel(
            "demo",
            "1.0",
            vec![file(
                "demo-1.0.whl",
                "demo/__init__.py",
                100,
                ArtifactFileKind::PythonSource,
            )],
            vec![],
        );
        let new = wheel(
            "demo",
            "1.1",
            vec![file(
                "demo-1.1.whl",
                "demo/__init__.py",
                120,
                ArtifactFileKind::PythonSource,
            )],
            vec![],
        );
        let diff = diff_inspections(&old, &new);
        assert!(!diff.has_anomaly(), "clean release should flag nothing");
        assert!(diff.findings().is_empty());
        let verdict = evaluate_release_diff(&old, &new, &Policy::default());
        assert_eq!(verdict.action, Action::Allow);
    }

    /// A pure release that grows a native `.so` flags `PureToNative` and the
    /// finding warns (Medium -> Warn) under the default policy.
    #[test]
    fn pure_to_native_flags_and_warns() {
        let old = wheel(
            "demo",
            "1.0",
            vec![file(
                "demo-1.0.whl",
                "demo/__init__.py",
                100,
                ArtifactFileKind::PythonSource,
            )],
            vec![],
        );
        let new = wheel(
            "demo",
            "1.1",
            vec![
                file(
                    "demo-1.1.whl",
                    "demo/__init__.py",
                    100,
                    ArtifactFileKind::PythonSource,
                ),
                file(
                    "demo-1.1.whl",
                    "demo/_speed.so",
                    2048,
                    ArtifactFileKind::NativeModule,
                ),
            ],
            vec![],
        );
        let diff = diff_inspections(&old, &new);
        assert!(diff.kinds().contains(&ReleaseAnomalyKind::PureToNative));
        let findings = diff.findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::ArtifactReleaseAnomaly);
        assert_eq!(findings[0].severity, Severity::Medium);
        // The detail names the added member.
        let detail = match &findings[0].evidence[0] {
            Evidence::Text { detail } => detail.clone(),
            other => panic!("expected text evidence, got {other:?}"),
        };
        assert!(
            detail.contains("demo/_speed.so"),
            "detail names the new .so: {detail}"
        );
        let verdict = evaluate_release_diff(&old, &new, &Policy::default());
        assert_eq!(verdict.action, Action::Warn);
    }

    /// A release that already had a native module and adds another does NOT flag
    /// pure-to-native (the baseline was not pure).
    #[test]
    fn native_to_more_native_does_not_flag_pure_to_native() {
        let old = wheel(
            "demo",
            "1.0",
            vec![file(
                "demo-1.0.whl",
                "demo/_a.so",
                1024,
                ArtifactFileKind::NativeModule,
            )],
            vec![],
        );
        let new = wheel(
            "demo",
            "1.1",
            vec![
                file(
                    "demo-1.1.whl",
                    "demo/_a.so",
                    1024,
                    ArtifactFileKind::NativeModule,
                ),
                file(
                    "demo-1.1.whl",
                    "demo/_b.so",
                    1024,
                    ArtifactFileKind::NativeModule,
                ),
            ],
            vec![],
        );
        let diff = diff_inspections(&old, &new);
        assert!(!diff.kinds().contains(&ReleaseAnomalyKind::PureToNative));
    }

    /// A release that adds a `.pth` startup hook flags `StartupHookAdded`.
    #[test]
    fn no_hook_to_pth_flags_startup_hook_added() {
        let old = wheel(
            "demo",
            "1.0",
            vec![file(
                "demo-1.0.whl",
                "demo/__init__.py",
                100,
                ArtifactFileKind::PythonSource,
            )],
            vec![],
        );
        let new = wheel(
            "demo",
            "1.1",
            vec![
                file(
                    "demo-1.1.whl",
                    "demo/__init__.py",
                    100,
                    ArtifactFileKind::PythonSource,
                ),
                file(
                    "demo-1.1.whl",
                    "demo/_bootstrap.pth",
                    64,
                    ArtifactFileKind::PthFile,
                ),
            ],
            vec![],
        );
        let diff = diff_inspections(&old, &new);
        assert!(diff.kinds().contains(&ReleaseAnomalyKind::StartupHookAdded));
        let detail = &diff
            .anomalies
            .iter()
            .find(|a| a.kind == ReleaseAnomalyKind::StartupHookAdded)
            .unwrap()
            .detail;
        assert!(
            detail.contains("demo/_bootstrap.pth"),
            "detail names the .pth: {detail}"
        );
    }

    /// A release whose bundled JavaScript crosses the multi-MB threshold from a
    /// near-empty baseline flags `JavaScriptVolumeJump`; a small JS file does not.
    #[test]
    fn javascript_volume_jump_threshold() {
        let old = wheel(
            "demo",
            "1.0",
            vec![file(
                "demo-1.0.whl",
                "demo/helper.js",
                200,
                ArtifactFileKind::Other,
            )],
            vec![],
        );
        // New: a multi-MB JS payload -> flags.
        let new_big = wheel(
            "demo",
            "1.1",
            vec![file(
                "demo-1.1.whl",
                "demo/_index.js",
                JS_VOLUME_JUMP_BYTES + 1,
                ArtifactFileKind::Other,
            )],
            vec![],
        );
        assert!(diff_inspections(&old, &new_big)
            .kinds()
            .contains(&ReleaseAnomalyKind::JavaScriptVolumeJump));

        // New: still small JS -> does not flag.
        let new_small = wheel(
            "demo",
            "1.1",
            vec![file(
                "demo-1.1.whl",
                "demo/helper.js",
                5000,
                ArtifactFileKind::Other,
            )],
            vec![],
        );
        assert!(!diff_inspections(&old, &new_small)
            .kinds()
            .contains(&ReleaseAnomalyKind::JavaScriptVolumeJump));
    }

    /// A release that gains a startup-network-download signal (the "new
    /// runtime-download" delta) flags `NewExecutionCapability` naming the signal.
    #[test]
    fn new_network_signal_flags_new_execution_capability() {
        let old = wheel("demo", "1.0", vec![], vec![]);
        let new = wheel(
            "demo",
            "1.1",
            vec![],
            vec![signal(ArtifactSignalKind::PthNetworkDownload)],
        );
        let diff = diff_inspections(&old, &new);
        assert!(diff
            .kinds()
            .contains(&ReleaseAnomalyKind::NewExecutionCapability));
        let detail = &diff
            .anomalies
            .iter()
            .find(|a| a.kind == ReleaseAnomalyKind::NewExecutionCapability)
            .unwrap()
            .detail;
        assert!(
            detail.contains("startup network download"),
            "names the gained signal: {detail}"
        );
    }

    /// A signal that is merely a COVERAGE marker (uninspectable), not a capability,
    /// does not flag a new execution capability.
    #[test]
    fn new_coverage_marker_does_not_flag_capability() {
        let old = wheel("demo", "1.0", vec![], vec![]);
        let new = wheel(
            "demo",
            "1.1",
            vec![],
            vec![signal(ArtifactSignalKind::NativeUninspectable)],
        );
        assert!(!diff_inspections(&old, &new)
            .kinds()
            .contains(&ReleaseAnomalyKind::NewExecutionCapability));
    }

    /// Two artifacts claiming different distribution names flag `IdentityChanged`;
    /// the same name (differing only by PEP 503 separators/case) does not.
    #[test]
    fn identity_change_uses_pep503_normalization() {
        let a = wheel("Flask", "1.0", vec![], vec![]);
        let b = wheel("requests", "1.0", vec![], vec![]);
        assert!(diff_inspections(&a, &b)
            .kinds()
            .contains(&ReleaseAnomalyKind::IdentityChanged));

        // `Flask` vs `flask` and `typing-extensions` vs `typing_extensions` are the
        // SAME normalized name -> no identity anomaly.
        let f1 = wheel("Flask", "1.0", vec![], vec![]);
        let f2 = wheel("flask", "1.1", vec![], vec![]);
        assert!(!diff_inspections(&f1, &f2)
            .kinds()
            .contains(&ReleaseAnomalyKind::IdentityChanged));

        let t1 = wheel("typing-extensions", "1.0", vec![], vec![]);
        let t2 = wheel("typing_extensions", "1.1", vec![], vec![]);
        assert!(!diff_inspections(&t1, &t2)
            .kinds()
            .contains(&ReleaseAnomalyKind::IdentityChanged));
    }

    /// A generic archive (no distribution name) does not produce an identity
    /// anomaly even when paired with a named wheel: there is no name to compare.
    #[test]
    fn generic_archive_has_no_identity_anomaly() {
        let named = wheel("demo", "1.0", vec![], vec![]);
        let mut generic =
            ArtifactInspection::new(InspectionSubject::GenericArchive(GenericArchiveIdentity {
                filename: "bundle.zip".to_string(),
                sha256: "c".repeat(64),
            }));
        generic.files = vec![];
        assert!(!diff_inspections(&named, &generic)
            .kinds()
            .contains(&ReleaseAnomalyKind::IdentityChanged));
    }

    /// A release that changes several things at once flags every applicable kind,
    /// produces ONE finding listing all of them, and the diff order is stable.
    #[test]
    fn multiple_anomalies_one_finding_stable_order() {
        let old = wheel(
            "demo",
            "1.0",
            vec![file(
                "demo-1.0.whl",
                "demo/__init__.py",
                100,
                ArtifactFileKind::PythonSource,
            )],
            vec![],
        );
        let new = wheel(
            "demo",
            "1.1",
            vec![
                file(
                    "demo-1.1.whl",
                    "demo/__init__.py",
                    100,
                    ArtifactFileKind::PythonSource,
                ),
                file(
                    "demo-1.1.whl",
                    "demo/_speed.so",
                    2048,
                    ArtifactFileKind::NativeModule,
                ),
                file(
                    "demo-1.1.whl",
                    "demo/boot.pth",
                    64,
                    ArtifactFileKind::PthFile,
                ),
            ],
            vec![signal(ArtifactSignalKind::NativeDangerCapability)],
        );
        let diff = diff_inspections(&old, &new);
        let kinds = diff.kinds();
        assert!(kinds.contains(&ReleaseAnomalyKind::PureToNative));
        assert!(kinds.contains(&ReleaseAnomalyKind::StartupHookAdded));
        assert!(kinds.contains(&ReleaseAnomalyKind::NewExecutionCapability));
        // One finding, listing every kind.
        let findings = diff.findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence.len(), diff.anomalies.len());
        // Stable order: re-running yields the identical anomaly vector.
        let diff2 = diff_inspections(&old, &new);
        assert_eq!(diff.anomalies, diff2.anomalies);
    }

    /// The finding round-trips and the diff serializes deterministically (the
    /// JSON surface the CLI renders).
    #[test]
    fn release_diff_serializes() {
        let old = wheel("demo", "1.0", vec![], vec![]);
        let new = wheel(
            "demo",
            "1.1",
            vec![file(
                "demo-1.1.whl",
                "demo/_x.so",
                10,
                ArtifactFileKind::NativeModule,
            )],
            vec![],
        );
        let diff = diff_inspections(&old, &new);
        let json = serde_json::to_string(&diff).unwrap();
        let back: ReleaseDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(back, diff);
    }

    /// A strict policy that upgrades `artifact_release_anomaly` to block turns the
    /// warn into a Block, exercising the `finalize_static_verdict` override seam.
    #[test]
    fn policy_action_override_upgrades_to_block() {
        let old = wheel("demo", "1.0", vec![], vec![]);
        let new = wheel(
            "demo",
            "1.1",
            vec![file(
                "demo-1.1.whl",
                "demo/_x.so",
                10,
                ArtifactFileKind::NativeModule,
            )],
            vec![],
        );
        let mut policy = Policy::default();
        policy.action_overrides.insert(
            RuleId::ArtifactReleaseAnomaly.to_string(),
            "block".to_string(),
        );
        let verdict = evaluate_release_diff(&old, &new, &policy);
        assert_eq!(verdict.action, Action::Block);
    }

    /// `join_capped` caps the list and appends the overflow count.
    #[test]
    fn join_capped_truncates() {
        let items: Vec<String> = (0..8).map(|i| format!("m{i}")).collect();
        let joined = join_capped(&items, 3);
        assert_eq!(joined, "m0, m1, m2 (+5 more)");
        assert_eq!(join_capped(&items[..2], 3), "m0, m1");
    }

    // -----------------------------------------------------------------------
    // I/O path: diff two REAL wheels on disk (exercises inspect_artifact_file ->
    // read_wheel end to end, the plan's `pkg diff old.whl new.whl` core).
    // -----------------------------------------------------------------------

    use std::io::Write as _;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    /// The RECORD `sha256=<base64url-no-pad>` cell for a member body.
    fn record_cell(body: &[u8]) -> String {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(body);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize());
        format!("sha256={b64}")
    }

    /// Build an in-memory wheel zip from (member, body) pairs.
    fn build_wheel_zip(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zw = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, body) in members {
            zw.start_file(*name, SimpleFileOptions::default()).unwrap();
            zw.write_all(body).unwrap();
        }
        zw.finish().unwrap().into_inner()
    }

    /// Write a wheel (name `demo`, version `ver`) carrying the given EXTRA members
    /// (beyond the dist-info), with a correct RECORD, to `<dir>/<filename>`, and
    /// return the path. The RECORD lists every non-RECORD member with its real hash
    /// so the inspection has no spurious integrity finding.
    fn write_demo_wheel(dir: &Path, ver: &str, extra: &[(&str, &[u8])]) -> std::path::PathBuf {
        let metadata =
            format!("Metadata-Version: 2.1\nName: demo\nVersion: {ver}\n\n").into_bytes();
        let wheel =
            b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
                .to_vec();

        let mut record = format!(
            "demo-{ver}.dist-info/METADATA,{},{}\ndemo-{ver}.dist-info/WHEEL,{},{}\n",
            record_cell(&metadata),
            metadata.len(),
            record_cell(&wheel),
            wheel.len(),
        );
        for (name, body) in extra {
            record.push_str(&format!("{},{},{}\n", name, record_cell(body), body.len()));
        }
        record.push_str(&format!("demo-{ver}.dist-info/RECORD,,\n"));

        let mut members: Vec<(String, Vec<u8>)> = vec![
            (format!("demo-{ver}.dist-info/METADATA"), metadata),
            (format!("demo-{ver}.dist-info/WHEEL"), wheel),
        ];
        for (name, body) in extra {
            members.push((name.to_string(), body.to_vec()));
        }
        members.push((format!("demo-{ver}.dist-info/RECORD"), record.into_bytes()));

        let refs: Vec<(&str, &[u8])> = members
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let bytes = build_wheel_zip(&refs);

        let path = dir.join(format!("demo-{ver}-py3-none-any.whl"));
        std::fs::write(&path, &bytes).unwrap();
        path
    }

    /// End to end: an OLD pure-Python wheel diffed against a NEW wheel that adds a
    /// native `.so` flags `PureToNative` over the real on-disk I/O path (this is the
    /// `tirith pkg diff old.whl new.whl` milestone repro's core).
    #[test]
    fn diff_artifact_files_flags_pure_to_native_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        // OLD: pure Python (one .py member).
        let old = write_demo_wheel(dir.path(), "1.0", &[("demo/__init__.py", b"x = 1\n")]);
        // NEW: same plus a (tiny, valid-ELF-magic) native member.
        let so_body: &[u8] = b"\x7fELF\x02\x01\x01\x00 a tiny stand-in native object body";
        let new = write_demo_wheel(
            dir.path(),
            "1.1",
            &[
                ("demo/__init__.py", b"x = 1\n"),
                ("demo/_speed.so", so_body),
            ],
        );

        let diff = diff_artifact_files(&old, &new).expect("both wheels inspect");
        assert!(
            diff.kinds().contains(&ReleaseAnomalyKind::PureToNative),
            "a pure->native release must flag PureToNative; got {:?}",
            diff.kinds()
        );
        // The verdict warns under the default policy (Medium -> Warn).
        let verdict = diff.evaluate(&Policy::default());
        assert_eq!(verdict.action, Action::Warn);
        assert!(verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::ArtifactReleaseAnomaly));
    }

    /// Two byte-distinct but shape-identical pure wheels diff clean over the I/O
    /// path (no false positive on an honest point release).
    #[test]
    fn diff_artifact_files_clean_on_honest_release() {
        let dir = tempfile::tempdir().unwrap();
        let old = write_demo_wheel(dir.path(), "1.0", &[("demo/__init__.py", b"x = 1\n")]);
        let new = write_demo_wheel(dir.path(), "1.1", &[("demo/__init__.py", b"x = 2\n")]);
        let diff = diff_artifact_files(&old, &new).expect("both wheels inspect");
        assert!(
            !diff.has_anomaly(),
            "honest release must be clean: {:?}",
            diff.anomalies
        );
    }

    /// A missing OLD artifact is a `ReleaseDiffError::Old`, not a panic.
    #[test]
    fn diff_artifact_files_missing_old_errors() {
        let dir = tempfile::tempdir().unwrap();
        let new = write_demo_wheel(dir.path(), "1.1", &[("demo/__init__.py", b"x = 1\n")]);
        let missing = dir.path().join("does-not-exist.whl");
        let err = diff_artifact_files(&missing, &new).unwrap_err();
        assert!(matches!(err, ReleaseDiffError::Old(_)), "got {err:?}");
    }
}
