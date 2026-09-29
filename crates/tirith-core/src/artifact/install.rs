//! Package-firewall install contracts that outlive contained execution.
//!
//! Contained `tirith pkg install` execution (and the approvals that fed it) is
//! disabled, so the install-from-digest planner that used to live here (the
//! pre-launch re-bind, the `approved.txt` builder, and the deny-all install
//! capsule spec) was removed. What remains is shared by live surfaces:
//!
//! * [`InstallPlanDigest`] / [`InstallPlanInputs`] and [`InstallCommand`]: the
//!   content-addressed plan identity that package approvals, the privileged
//!   approval helper, and task boundaries bind. Its serialized form is unchanged
//!   so existing approval records and receipts stay readable.
//! * [`verify_post_install_record`] (and the version-exact
//!   [`verify_post_install_record_exact`]): the D5 post-install RECORD check used
//!   by `tirith pkg verify-env`.
//! * [`discover_installed_distributions`]: the name-agnostic environment
//!   enumeration used by `tirith env graph`.
//!
//! # The D5 post-install seam
//!
//! [`verify_post_install_record`] re-reads the installed RECORD of each named
//! distribution in a target environment and folds a RECORD hash mismatch /
//! missing file / duplicate-owned path into AT MOST ONE
//! [`crate::verdict::RuleId::PythonInstalledIntegrityViolation`] finding,
//! finalised through [`crate::escalation::finalize_static_verdict`] (cross-cutting
//! invariant 5). It reuses the B5 primitives verbatim
//! ([`crate::artifact::record::verify_installed_record`] for the lenient per-file
//! check and [`crate::artifact::record::index_distribution_ownership`] for the
//! duplicate-ownership multimap), so the installed-environment semantics cannot
//! drift from the `ecosystem scan --installed` path. It is install-SCOPED: it
//! verifies only the distributions it is given (matched by PEP 503 name), never
//! the whole pre-existing environment, so a venv's unrelated pre-installed
//! packages are not re-judged.
//!
//! **Editable / conda -> no false positive.** Installed-environment drift is
//! legitimate for an editable install (a sparse RECORD, absent project files) and
//! for a non-pip installer (conda, a distro-managed or PEP 668 externally-managed
//! tree). [`verify_installed_record`] already flags both
//! ([`crate::artifact::record::InstalledRecordResult::editable`] /
//! `externally_managed`) and suppresses the missing-file signal for editable;
//! D5's fold goes further and DROPS every signal that originates from an editable
//! or externally-managed distribution before correlating, so neither can produce a
//! finding on its own. A real hash mismatch in an ordinary pip-installed
//! distribution still folds to the Medium finding.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::artifact::record::{
    index_distribution_ownership, verify_installed_record, EnvironmentLayout, FileVerification,
    OwnershipIndex,
};
use crate::artifact::{ArtifactSignal, ArtifactSignalKind, DistributionIdentity};
use crate::location::SubjectLocation;
use crate::policy::Policy;
use crate::threatdb::Ecosystem;
use crate::verdict::{Evidence, Finding, RuleId, Severity, Timings, Verdict};

/// The pinned pip command of an install plan, plus the path of the
/// `approved.txt` requirements file it reads.
///
/// Contained execution is disabled, but [`InstallPlanDigest`] still binds the
/// command semantics ([`Self::pip_install_args_without_requirements_path`]), so
/// the argv stays defined and unit testable here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallCommand {
    /// The generated `approved.txt` path. It is descriptor-cwd-relative on Unix
    /// and absolute beneath a path-pinned directory on Windows.
    pub approved_requirements_path: PathBuf,
    /// The exact dedicated directory passed to pip's `--target`. Enforcing
    /// callers bind this directory by capability at launch; the path remains in
    /// the approval semantics so changing the destination always re-binds.
    pub target_environment: PathBuf,
}

impl InstallCommand {
    /// The `python -I -m pip install ...` argument vector (everything after the
    /// interpreter path), exactly the plan's pin:
    ///
    /// `-I -m pip install --isolated --no-index --no-deps --require-hashes
    /// --no-cache-dir --no-input --disable-pip-version-check --force-reinstall
    /// --upgrade --target <dedicated-target> -r <approved.txt>`
    ///
    /// `--force-reinstall` is mandatory so pip does not silently skip a package
    /// whose version is already installed; `--no-index` + the local references
    /// in `approved.txt` keep the install fully offline; `--require-hashes` makes
    /// pip refuse any file whose content does not hash to the pinned digest;
    /// `--no-deps` because the lock is transitively complete; `--isolated` +
    /// `--no-cache-dir` so no ambient pip config / cache can redirect it;
    /// `--no-input` so the contained install never blocks on an interactive prompt;
    /// `--disable-pip-version-check` so pip skips its own network version self-check
    /// (which a deny-all spec would otherwise stall).
    ///
    /// The interpreter is invoked as `python -I -m pip` (never a PATH `pip` shim), the
    /// same hardening the D2 resolver uses; the caller supplies the resolved
    /// interpreter path as the program and these as its args.
    pub fn pip_install_args(&self) -> Vec<String> {
        let mut args = self.pip_install_args_without_requirements_path();
        args.push("-r".to_string());
        args.push(self.approved_requirements_path.display().to_string());
        args
    }

    /// The pinned install flags WITHOUT the trailing `-r <approved.txt>` (the
    /// security-relevant *semantics* of the command, with the per-run requirements
    /// path omitted). D7's [`InstallPlanDigest`] binds these so a change to the
    /// install flags re-binds the approval, while a per-run temp approved.txt path
    /// (which differs every invocation) does not perturb the digest. The full argv
    /// ([`Self::pip_install_args`]) is this plus `-r <path>`.
    pub fn pip_install_args_without_requirements_path(&self) -> Vec<String> {
        vec![
            // `-I` prevents user-site, PYTHONPATH, and current-directory imports
            // from changing which root-managed pip tree the approval attested.
            "-I".to_string(),
            "-m".to_string(),
            "pip".to_string(),
            "install".to_string(),
            "--isolated".to_string(),
            "--no-index".to_string(),
            "--no-deps".to_string(),
            "--require-hashes".to_string(),
            "--no-cache-dir".to_string(),
            "--no-input".to_string(),
            "--disable-pip-version-check".to_string(),
            "--force-reinstall".to_string(),
            // pip target installs otherwise keep pre-existing destination entries
            // even when `--force-reinstall` is present. The enforcing surface uses
            // a fresh dedicated target, and keeps this flag pinned as defense in
            // depth against a target populated after approval.
            "--upgrade".to_string(),
            "--target".to_string(),
            self.target_environment.display().to_string(),
        ]
    }
}

/// The outcome of the D5 post-install RECORD check over a contained install: the
/// finalised verdict the install gates on AFTER extraction, plus the coverage
/// counters the D6 receipt records (how many of the named distributions were
/// found and verified, how many had no RECORD at all, and how many RECORD-listed
/// files did not match their on-disk bytes).
///
/// Every field is post-extraction. The verdict carries AT MOST ONE
/// [`RuleId::PythonInstalledIntegrityViolation`] finding (cross-cutting invariant
/// 1: few user-facing findings, detail carried as evidence); a clean install
/// yields a no-finding `Allow` verdict.
#[derive(Debug, Clone)]
pub struct PostInstallIntegrity {
    /// The single finalised verdict over the just-installed distributions, via
    /// [`crate::escalation::finalize_static_verdict`]. `Allow` (no findings) when
    /// every named distribution verified, or when the only drift came from an
    /// editable / externally-managed (conda / distro) distribution.
    pub verdict: Verdict,
    /// How many of the install's named distributions were located in the target
    /// environment and had their RECORD verified.
    pub distributions_verified: usize,
    /// How many named distributions could not be located in the target
    /// environment's `site-packages` (no matching `.dist-info`). This is a coverage
    /// gap rather than proof of tampering, but enforcing callers must fail closed.
    pub distributions_not_found: usize,
    /// How many located distributions had NO RECORD file. This is a coverage gap
    /// rather than proof of tampering, but enforcing callers must fail closed.
    pub records_missing: usize,
    /// How many RECORD-listed files did not match their on-disk bytes across the
    /// verified distributions (the strong tamper signal).
    pub hash_mismatches: usize,
}

impl PostInstallIntegrity {
    /// Whether the post-install verdict blocks (a strict integrity policy upgraded
    /// the Medium finding to Block via `action_overrides`, applied inside
    /// [`crate::escalation::finalize_static_verdict`]). A convenience over
    /// `self.verdict.action`.
    pub fn is_block(&self) -> bool {
        matches!(self.verdict.action, crate::verdict::Action::Block)
    }

    /// Whether the check established complete integrity coverage for at least one
    /// expected distribution. Enforcing install/verify surfaces use this in addition
    /// to the policy-level verdict so an empty Allow cannot mean success.
    pub fn is_complete(&self) -> bool {
        self.distributions_verified > 0
            && self.distributions_not_found == 0
            && self.records_missing == 0
    }
}

/// Exact distribution identity expected from one approved wheel. Enforcing
/// installs carry the version as well as the normalized project name so a clean
/// stale `.dist-info` directory cannot satisfy verification for a different
/// wheel version. Analysis-only `verify-env` callers may leave `version` empty by
/// using [`verify_post_install_record`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExpectedInstalledDistribution {
    pub name: String,
    pub version: Option<String>,
}

/// Verify the installed RECORD of the just-installed distributions in
/// `target_environment` and fold any integrity problem into a single verdict
/// (cross-cutting invariant: "installed files verify against installed RECORD").
///
/// `installed_names` are the PEP 503-normalised distribution names the install
/// landed (one per [`crate::artifact::resolver::ResolvedArtifact`]; build them with
/// [`installed_distribution_names`]). The check is install-SCOPED: it verifies ONLY
/// the `.dist-info` directories whose project name matches one of `installed_names`,
/// never the whole pre-existing environment, so a venv's unrelated pre-installed
/// packages are not re-judged.
///
/// For the matched distributions it:
/// 1. builds a duplicate-aware [`OwnershipIndex`] across them (so a path two of the
///    just-installed distributions both claim surfaces), via the B5
///    [`index_distribution_ownership`];
/// 2. verifies each one's RECORD LENIENTLY via the B5 [`verify_installed_record`]
///    (`allow_scheme_escape = false`: the post-install check never reads outside the
///    environment);
/// 3. DROPS every signal that originated from an editable or externally-managed
///    (conda / distro) distribution (editable / conda -> no false positive), then
/// 4. correlates the surviving signals into AT MOST ONE
///    [`RuleId::PythonInstalledIntegrityViolation`] (Medium; High when corroborated
///    by a duplicate-owned path), finalised through
///    [`crate::escalation::finalize_static_verdict`] so per-rule severity / action
///    overrides and paranoia filtering apply (a strict integrity policy upgrades the
///    action to Block).
///
/// Best-effort discovery: an unreadable `site-packages` or `.dist-info` contributes
/// a "not found" count, never a panic. A clean install returns an `Allow` verdict
/// with no findings.
pub fn verify_post_install_record(
    target_environment: &Path,
    installed_names: &[String],
    policy: &Policy,
) -> PostInstallIntegrity {
    let expected: Vec<ExpectedInstalledDistribution> = installed_names
        .iter()
        .map(|name| ExpectedInstalledDistribution {
            name: name.clone(),
            version: None,
        })
        .collect();
    verify_post_install_record_exact(target_environment, &expected, policy)
}

/// Version-exact enforcing variant of [`verify_post_install_record`]. Exactly one
/// `.dist-info` directory must match every expected name/version pair. Missing,
/// stale-version-only, and duplicate matches are coverage failures.
pub fn verify_post_install_record_exact(
    target_environment: &Path,
    expected_distributions: &[ExpectedInstalledDistribution],
    policy: &Policy,
) -> PostInstallIntegrity {
    let mut result = PostInstallIntegrity {
        verdict: crate::escalation::finalize_static_verdict(
            Vec::new(),
            policy,
            3,
            Timings::default(),
        ),
        distributions_verified: 0,
        distributions_not_found: 0,
        records_missing: 0,
        hash_mismatches: 0,
    };

    // Locate exactly one `.dist-info` for each approved distribution identity.
    let mut matched: Vec<(PathBuf, PathBuf, DistributionIdentity)> = Vec::new();
    let mut integrity_signals: Vec<ArtifactSignal> = Vec::new();
    let sites = post_install_site_packages(target_environment);
    for expected in expected_distributions {
        let located = locate_installed_dist_infos(&sites, expected);
        match located.as_slice() {
            [only] => matched.push(only.clone()),
            [] => result.distributions_not_found += 1,
            duplicates => {
                result.distributions_not_found += 1;
                integrity_signals.push(ArtifactSignal {
                    kind: ArtifactSignalKind::DuplicateOwnedFile,
                    location: SubjectLocation::installed(target_environment),
                    evidence: format!(
                        "expected exactly one installed {}{} but found {} matching .dist-info directories: {}",
                        expected.name,
                        expected
                            .version
                            .as_deref()
                            .map(|version| format!("=={version}"))
                            .unwrap_or_default(),
                        duplicates.len(),
                        duplicates
                            .iter()
                            .map(|(_, path, _)| path.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    confidence: crate::artifact::EdgeConfidence::High,
                });
            }
        }
    }

    if matched.is_empty() {
        result.verdict = crate::escalation::finalize_static_verdict(
            post_install_integrity_findings(&integrity_signals),
            policy,
            3,
            Timings::default(),
        );
        return result;
    }

    // 1. Ownership index across the just-installed distributions, so a path two of
    //    them both list (the duplicate-ownership / cross-distribution split) is a
    //    signal. An editable / externally-managed distribution still participates in
    //    the index (its presence is what makes a DUPLICATE meaningful), but a
    //    duplicate signal is dropped at the fold below if BOTH owners are
    //    editable / externally-managed.
    let mut index = OwnershipIndex::new();
    let mut suppressed_dists: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for (_site, dist_info, identity) in &matched {
        index_distribution_ownership(dist_info, identity, &mut index);
    }

    // 2. Per-distribution lenient RECORD verification; collect the signals from the
    //    ordinary (non-editable, non-externally-managed) distributions only.
    for (site, dist_info, identity) in &matched {
        let record_result = verify_installed_record(
            dist_info,
            &EnvironmentLayout::for_site_packages(site.clone()),
            identity,
            false,
        );
        result.distributions_verified += 1;
        if record_result.record_missing {
            result.records_missing += 1;
        }
        for entry in &record_result.entries {
            if matches!(entry.verification, FileVerification::Mismatch { .. }) {
                result.hash_mismatches += 1;
            }
        }
        // Editable / conda -> no false positive: an editable or externally-managed
        // distribution legitimately drifts, so its per-file signals never fold into
        // a finding. Record its name so a duplicate-owned path it is a party to is
        // judged below (a duplicate is only suppressed when EVERY owner is exempt).
        if record_result.editable || record_result.externally_managed {
            suppressed_dists.insert(normalized_dist_name(identity));
            continue;
        }
        integrity_signals.extend(record_result.signals);
    }

    // 3. Duplicate-owned paths across the just-installed set -> a signal each, unless
    //    EVERY owner of the path is an editable / externally-managed distribution
    //    (then the duplicate is expected drift, not tampering).
    for (path, owners) in index.duplicates() {
        let all_exempt = owners
            .iter()
            .all(|o| suppressed_dists.contains(&normalized_dist_name_of(o)));
        if all_exempt {
            continue;
        }
        let owner_names: Vec<String> = owners.iter().map(|d| d.name.clone()).collect();
        integrity_signals.push(ArtifactSignal {
            kind: ArtifactSignalKind::DuplicateOwnedFile,
            location: SubjectLocation::installed(path_in_first_site(&matched, path.as_str())),
            evidence: format!(
                "installed path '{}' is owned by multiple just-installed distributions: {}",
                path,
                owner_names.join(", ")
            ),
            confidence: crate::artifact::EdgeConfidence::Medium,
        });
    }

    // 4. Fold the surviving signals into AT MOST ONE finding, finalised so policy
    //    overrides + paranoia apply (a strict integrity policy can force Block).
    let findings = post_install_integrity_findings(&integrity_signals);
    result.verdict =
        crate::escalation::finalize_static_verdict(findings, policy, 3, Timings::default());
    result
}

/// Discover EVERY installed distribution under a target environment, returning each
/// one's `(dist_info_dir, identity)`. Reuses the SAME [`post_install_site_packages`]
/// venv-layout enumeration the post-install check uses (so the provenance graph and
/// the integrity check see the same site roots), then lists every `<name>-<version>
/// .dist-info` in each. Unlike [`locate_installed_dist_info`], this is name-agnostic:
/// it enumerates the whole environment, for `tirith env graph` (PR F1). A malformed
/// `.dist-info` directory name is skipped; an unreadable site root contributes
/// nothing (best-effort, never panics). Results are sorted by `.dist-info` path for
/// determinism, and de-duplicated so the same distribution dir is not returned twice
/// when two enumerated site roots happen to overlap.
pub fn discover_installed_distributions(
    target_environment: &Path,
) -> Vec<(PathBuf, DistributionIdentity)> {
    let mut found: Vec<(PathBuf, DistributionIdentity)> = Vec::new();
    let mut seen: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
    for site in post_install_site_packages(target_environment) {
        let Ok(rd) = std::fs::read_dir(&site) else {
            continue;
        };
        let mut dist_infos: Vec<PathBuf> = rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.is_dir()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.ends_with(".dist-info"))
            })
            .collect();
        dist_infos.sort();
        for dist_info in dist_infos {
            if !seen.insert(dist_info.clone()) {
                continue;
            }
            if let Some((proj, version)) = dist_info_name_version(&dist_info) {
                found.push((
                    dist_info.clone(),
                    DistributionIdentity {
                        ecosystem: Ecosystem::PyPI,
                        name: proj,
                        version: Some(version),
                        dist_info_path: SubjectLocation::installed(dist_info),
                    },
                ));
            }
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

/// The `site-packages` roots under a target environment the post-install check
/// scans, mirroring the venv layouts pip installs into: `<env>/site-packages`,
/// `<env>/Lib/site-packages` (Windows venv), and `<env>/lib/python*/site-packages`
/// (POSIX venv). Only directories that exist are returned. Kept local to the
/// install edge (it enumerates a KNOWN target, not an arbitrary tree) so it does
/// not pull in the broad `ecosystem scan` filesystem walk.
fn post_install_site_packages(env: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    // pip `--target DIR` installs packages and `.dist-info` directories directly
    // in DIR. Keep that explicit-target layout alongside ordinary venv layouts.
    if env.is_dir() {
        found.push(env.to_path_buf());
    }
    for c in [
        env.join("site-packages"),
        env.join("Lib").join("site-packages"),
    ] {
        if c.is_dir() {
            found.push(c);
        }
    }
    let lib = env.join("lib");
    if let Ok(rd) = std::fs::read_dir(&lib) {
        let mut subs: Vec<PathBuf> = rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.is_dir()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("python"))
            })
            .collect();
        subs.sort();
        for s in subs {
            let sp = s.join("site-packages");
            if sp.is_dir() {
                found.push(sp);
            }
        }
    }
    found
}

/// Locate every `.dist-info` directory matching an exact expected identity across
/// the given `site-packages` roots, returning `(site, dist_info_dir, identity)`. A
/// distribution dir is `<project>-<version>.dist-info`; the project part is
/// normalised with the SAME PEP 503 normaliser used for `name`, so case / `-_.`
/// spelling differences between the wheel name and the on-disk dir name still
/// match. Enforcing callers require exactly one result; silently taking the first
/// would let a stale clean version attest different newly installed bytes.
fn locate_installed_dist_infos(
    sites: &[PathBuf],
    expected: &ExpectedInstalledDistribution,
) -> Vec<(PathBuf, PathBuf, DistributionIdentity)> {
    let mut matches = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for site in sites {
        let Ok(rd) = std::fs::read_dir(site) else {
            continue;
        };
        let mut dist_infos: Vec<PathBuf> = rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.is_dir()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.ends_with(".dist-info"))
            })
            .collect();
        dist_infos.sort();
        for dist_info in dist_infos {
            if let Some((proj, version)) = dist_info_name_version(&dist_info) {
                let name_matches =
                    crate::artifact::archive::normalize_project_name(&proj) == expected.name;
                let version_matches = expected.version.as_deref().is_none_or(|expected_version| {
                    version.trim().eq_ignore_ascii_case(expected_version.trim())
                });
                if name_matches && version_matches && seen.insert(dist_info.clone()) {
                    matches.push((
                        site.clone(),
                        dist_info.clone(),
                        DistributionIdentity {
                            ecosystem: Ecosystem::PyPI,
                            name: proj,
                            version: Some(version),
                            dist_info_path: SubjectLocation::installed(dist_info),
                        },
                    ));
                }
            }
        }
    }
    matches.sort_by(|left, right| left.1.cmp(&right.1));
    matches
}

/// Parse `<project>-<version>.dist-info` -> `(project, version)` from the directory
/// name. The project name is returned VERBATIM (the caller normalises it for the
/// match); `None` for a malformed dir name.
fn dist_info_name_version(dist_info: &Path) -> Option<(String, String)> {
    let dir = dist_info.file_name()?.to_str()?;
    let stem = dir.strip_suffix(".dist-info")?;
    let idx = stem.rfind('-')?;
    let (name, version) = stem.split_at(idx);
    let version = &version[1..];
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// The PEP 503-normalised name of a distribution identity, for the editable /
/// conda suppression set.
fn normalized_dist_name(dist: &DistributionIdentity) -> String {
    crate::artifact::archive::normalize_project_name(&dist.name)
}

/// Same as [`normalized_dist_name`] for a borrowed reference used in the duplicate
/// owner scan.
fn normalized_dist_name_of(dist: &DistributionIdentity) -> String {
    crate::artifact::archive::normalize_project_name(&dist.name)
}

/// Best-effort absolute location for a duplicate-owned path's signal: the path
/// joined under the FIRST matched site root (the signal location is for display /
/// evidence; the duplicate is a cross-distribution fact, not tied to one site).
fn path_in_first_site(matched: &[(PathBuf, PathBuf, DistributionIdentity)], rel: &str) -> PathBuf {
    matched
        .first()
        .map(|(site, _, _)| site.join(rel))
        .unwrap_or_else(|| PathBuf::from(rel))
}

/// Correlate the surviving post-install integrity signals into AT MOST ONE
/// [`RuleId::PythonInstalledIntegrityViolation`] finding (cross-cutting invariant
/// 1). Returns an empty vec when there is no signal (a clean install).
///
/// Severity is Medium by default (installed-environment drift is common). It rises
/// to High ONLY with a corroborator this post-install check can establish: a
/// duplicate-owned path across two just-installed distributions (a single file two
/// of the wheels both claim, the cross-distribution loader / payload split). A
/// strict integrity policy further upgrades the ACTION to Block via
/// `action_overrides`, applied by [`crate::escalation::finalize_static_verdict`];
/// this function does not itself force Block.
fn post_install_integrity_findings(signals: &[ArtifactSignal]) -> Vec<Finding> {
    if signals.is_empty() {
        return Vec::new();
    }
    use ArtifactSignalKind as K;

    let corroborated = signals.iter().any(|s| s.kind == K::DuplicateOwnedFile);
    let severity = if corroborated {
        Severity::High
    } else {
        Severity::Medium
    };

    // A compact evidence list: the distinct signal kinds, then each signal's detail.
    let mut kinds: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for s in signals {
        if let Ok(serde_json::Value::String(k)) = serde_json::to_value(s.kind) {
            kinds.insert(k);
        }
    }
    let mut evidence: Vec<Evidence> = vec![Evidence::Text {
        detail: format!(
            "correlated post-install integrity signals: {}",
            kinds.into_iter().collect::<Vec<_>>().join(", ")
        ),
    }];
    for s in signals {
        evidence.push(Evidence::Text {
            detail: s.evidence.clone(),
        });
    }

    let title = if corroborated {
        "Installed Python environment integrity violation (duplicate-owned path)".to_string()
    } else {
        "Installed Python environment integrity violation".to_string()
    };
    vec![Finding {
        rule_id: RuleId::PythonInstalledIntegrityViolation,
        severity,
        title,
        description: "After the contained install extracted the approved wheels, an installed \
             distribution failed a RECORD integrity check: a RECORD-listed file did not match its \
             on-disk bytes, a RECORD-listed file was missing, or a path was claimed by more than \
             one just-installed distribution. Editable installs and non-pip (conda / distro) \
             installers drift legitimately and are exempt, so this fires only on an ordinary \
             pip-installed distribution; it is Medium by default and rises with a corroborator \
             such as a duplicate-owned path. Reinstall the affected distribution from a trusted \
             source; set a strict integrity policy (action_overrides) to block on this."
            .to_string(),
        evidence,
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }]
}

// ---------------------------------------------------------------------------
// D7: the install-plan digest the operator approval binds to
// ---------------------------------------------------------------------------

/// The complete, hashable description of an install-from-digest plan that a
/// `tirith pkg approve` decision binds to (PR D7).
///
/// # Why an approval binds to a digest, not a SHA-set
///
/// An operator who approves an install is approving a WHOLE SITUATION, not just a
/// bag of artifact hashes. The same wheels installed into a different interpreter,
/// for a different platform, under a weaker policy, against an older threat-DB
/// sequence, or with a different install command is a DIFFERENT and possibly
/// dangerous operation. Binding the approval to the sorted SHA-set alone would let
/// any of those swap silently after approval. So the approval id is the content
/// hash of every binding input below (`plan_digest`), and the sorted SHA-set
/// ([`Self::artifact_set_label`]) is a human-readable DISPLAY LABEL only, never the
/// binding identity.
///
/// # The binding inputs (the plan's list)
///
/// The digest is `H(artifact hashes, normalized packages, target interpreter/env,
/// platform tags, install-command semantics, redacted policy-projection hash, DB
/// sequence, capsule backend, required coverage, expiry)`. Each is a field here; the
/// digest is the sha256 of the canonical JSON of all of them (with `plan_digest`
/// itself blanked, exactly as [`crate::receipt::ArtifactScanReceipt`] content-
/// addresses itself), through the SAME [`crate::audit::canonical_json_for_hash`] the
/// audit chain uses, so the digest is stable, order-independent over the sets it
/// sorts, and reproducible.
///
/// # Redaction
///
/// `policy_projection_hash` is [`crate::policy::Policy::security_projection_hash`]
/// (never the raw policy); `target_environment` and `interpreter` are recorded as
/// their plain paths because the digest is an operator-local binding token, not a
/// shared receipt (the receipt, [`crate::receipt::ArtifactScanReceipt`], stores no
/// paths). The digest is not persisted to a shared store by core; the CLI decides
/// where (if anywhere) to keep an approval record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallPlanDigest {
    /// The content-addressed binding id: the lowercase-hex sha256 of this struct's
    /// canonical JSON with `plan_digest` blanked. The value `tirith pkg approve`
    /// records and `tirith pkg install` re-derives and compares.
    pub plan_digest: String,
    /// Every approved artifact's sha256 (lowercase hex), sorted + de-duplicated.
    /// The bytes the install will extract.
    pub artifact_sha256: Vec<String>,
    /// The PEP 503-normalised distribution names the plan installs, sorted. Bound
    /// so a re-resolve to a different package set invalidates the approval even if a
    /// hash happens to collide in the label.
    pub normalized_packages: Vec<String>,
    /// The resolved target interpreter the install runs `python -m pip` with (its
    /// path). A different interpreter is a different operation.
    pub interpreter: String,
    /// SHA-256 of the exact interpreter bytes retained for the install. A path is
    /// not a content identity when an explicitly enrolled tool is user-writable.
    pub interpreter_sha256: String,
    /// The exact resolver executable used to produce the pinned wheel set.
    pub resolver: String,
    /// SHA-256 of the retained resolver executable bytes.
    pub resolver_sha256: String,
    /// Exact resolver version captured from the retained executable.
    #[serde(default)]
    pub resolver_version: String,
    /// Exact pip distribution version read from the bound metadata tree.
    #[serde(default)]
    pub package_manager_version: String,
    /// Canonical root-managed pip package directory selected by the interpreter.
    #[serde(default)]
    pub pip_tree_root: String,
    /// Deterministic digest over the pip package and matching dist-info trees.
    #[serde(default)]
    pub pip_tree_sha256: String,
    /// Version of the deterministic pip-tree attestation format.
    #[serde(default)]
    pub pip_tree_binding_version: u32,
    /// Maximum regular-file count accepted by the attestation algorithm.
    #[serde(default)]
    pub pip_tree_max_files: u64,
    /// Maximum aggregate regular-file bytes accepted by the attestation algorithm.
    #[serde(default)]
    pub pip_tree_max_bytes: u64,
    /// Maximum bytes accepted for any one pip-tree regular file.
    #[serde(default)]
    pub pip_tree_max_file_bytes: u64,
    /// Maximum UTF-8 bytes accepted for any pip-tree relative path.
    #[serde(default)]
    pub pip_tree_max_path_bytes: u64,
    /// Actual regular-file count incorporated into the attestation.
    #[serde(default)]
    pub pip_tree_files: u64,
    /// Actual aggregate regular-file bytes incorporated into the attestation.
    #[serde(default)]
    pub pip_tree_bytes: u64,
    /// The environment tree pip installs into (its path).
    pub target_environment: String,
    /// Stable filesystem identity of the already-existing target parent.
    #[serde(default)]
    pub target_parent_identity: String,
    /// Exact ordinary final component created beneath the bound parent.
    #[serde(default)]
    pub target_component: String,
    /// The platform tags the resolve targeted (e.g. the wheel ABI / platform tags),
    /// sorted. Empty when the resolve did not constrain them. Bound so an approval
    /// for one platform's wheels does not authorise another's.
    pub platform_tags: Vec<String>,
    /// The install-command semantics: the exact pinned pip argv
    /// ([`InstallCommand::pip_install_args`]) WITHOUT the trailing approved.txt path
    /// (which is install-run-specific), so the security-relevant flags are bound but
    /// a per-run temp path is not. A change to the install flags re-binds.
    pub install_command_semantics: Vec<String>,
    /// The redacted security-projection hash of the effective policy
    /// ([`crate::policy::Policy::security_projection_hash`]). A weaker policy after
    /// approval invalidates it.
    pub policy_projection_hash: String,
    /// The threat-DB build sequence the approval is bound to. The live DB advancing
    /// past this invalidates the approval (cross-cutting invariant 4).
    pub threat_db_sequence: u64,
    /// The capsule backend id the install must run under (`"landlock-seccomp"` /
    /// `"seatbelt"` / `"appcontainer"` / `"noop"`). An approval issued for a
    /// containing backend does not authorise a run on a NoOp host.
    pub capsule_backend: String,
    /// The per-capability coverage the install REQUIRES (the spec's
    /// [`crate::capsule::CapsuleSpec::required_coverage`]). Bound so an approval that
    /// demanded raw-network-deny cannot be redeemed against a spec that does not.
    pub required_coverage: crate::capsule::CapsuleCoverage,
    /// The task-gate ceiling in force when the plan was built
    /// ([`crate::task_boundary::ceiling_binding`]): the gate mode plus the
    /// effects it denied. Bound so an approval taken while the gate refused
    /// network egress cannot be redeemed once the operator has relaxed it, the
    /// same way `policy_projection_hash` binds the rest of the posture.
    ///
    /// It is a field of its own precisely because
    /// [`crate::policy::Policy::security_projection`] emits no `task_gate` key:
    /// the gate is the one posture dimension `policy_projection_hash` does not
    /// carry, so without this the digest would say nothing about it.
    ///
    /// `serde(default)` keeps an approval record written before this field
    /// existed loadable; its digest will simply no longer match, which is the
    /// fail-closed outcome (the operator re-approves).
    #[serde(default)]
    pub task_gate_binding: String,
    /// RFC 3339 UTC expiry. After this instant the approval is stale and
    /// [`Self::is_expired_at`] refuses it. An empty string means "no expiry"
    /// (the caller chose not to time-box it).
    pub expiry: String,
}

/// The binding inputs for an [`InstallPlanDigest`], everything except the derived
/// `plan_digest` itself. [`InstallPlanDigest::new`] takes this and stamps the hash,
/// keeping the long argument list to one named value.
#[derive(Debug, Clone)]
pub struct InstallPlanInputs {
    /// Every approved artifact's sha256 (any case / order; normalised by `new`).
    pub artifact_sha256: Vec<String>,
    /// The PEP 503-normalised distribution names (sorted by `new`).
    pub normalized_packages: Vec<String>,
    /// The resolved target interpreter path.
    pub interpreter: PathBuf,
    /// SHA-256 of the exact retained interpreter bytes.
    pub interpreter_sha256: String,
    /// The exact resolver executable path.
    pub resolver: PathBuf,
    /// SHA-256 of the exact retained resolver executable bytes.
    pub resolver_sha256: String,
    /// Exact resolver version captured from the retained executable.
    pub resolver_version: String,
    /// Exact pip distribution version read from bound metadata.
    pub package_manager_version: String,
    /// Canonical root-managed pip package directory.
    pub pip_tree_root: PathBuf,
    /// Deterministic pip package + dist-info tree digest.
    pub pip_tree_sha256: String,
    /// Pip-tree attestation format version.
    pub pip_tree_binding_version: u32,
    /// Pip-tree maximum regular-file count.
    pub pip_tree_max_files: u64,
    /// Pip-tree maximum aggregate bytes.
    pub pip_tree_max_bytes: u64,
    /// Pip-tree maximum bytes for one regular file.
    pub pip_tree_max_file_bytes: u64,
    /// Pip-tree maximum relative-path bytes.
    pub pip_tree_max_path_bytes: u64,
    /// Pip-tree actual regular-file count.
    pub pip_tree_files: u64,
    /// Pip-tree actual aggregate bytes.
    pub pip_tree_bytes: u64,
    /// The environment tree pip installs into.
    pub target_environment: PathBuf,
    /// Stable target-parent filesystem identity.
    pub target_parent_identity: String,
    /// Exact target final component.
    pub target_component: String,
    /// The platform tags the resolve targeted (sorted by `new`).
    pub platform_tags: Vec<String>,
    /// The pinned pip argv WITHOUT the trailing approved.txt path.
    pub install_command_semantics: Vec<String>,
    /// The redacted policy-projection hash.
    pub policy_projection_hash: String,
    /// The threat-DB sequence the approval binds to.
    pub threat_db_sequence: u64,
    /// The capsule backend id the install must run under.
    pub capsule_backend: String,
    /// The required per-capability coverage.
    pub required_coverage: crate::capsule::CapsuleCoverage,
    /// The task-gate ceiling this plan was built under.
    pub task_gate_binding: String,
    /// RFC 3339 UTC expiry, or empty for none.
    pub expiry: String,
}

impl InstallPlanDigest {
    /// Build a digest from its binding inputs and stamp the content-addressed
    /// `plan_digest`. The lists that have no meaningful order (artifact hashes,
    /// normalised package names, platform tags) are sorted + de-duplicated so two
    /// plans that differ only in input ordering bind to the SAME digest; the install
    /// argv is bound verbatim (its order is meaningful).
    pub fn new(inputs: InstallPlanInputs) -> Self {
        let mut artifact_sha256: Vec<String> = inputs
            .artifact_sha256
            .into_iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();
        artifact_sha256.sort();
        artifact_sha256.dedup();
        let mut normalized_packages = inputs.normalized_packages;
        normalized_packages.sort();
        normalized_packages.dedup();
        let mut platform_tags = inputs.platform_tags;
        platform_tags.sort();
        platform_tags.dedup();

        let mut digest = InstallPlanDigest {
            plan_digest: String::new(),
            artifact_sha256,
            normalized_packages,
            interpreter: inputs.interpreter.display().to_string(),
            interpreter_sha256: inputs.interpreter_sha256.to_ascii_lowercase(),
            resolver: inputs.resolver.display().to_string(),
            resolver_sha256: inputs.resolver_sha256.to_ascii_lowercase(),
            resolver_version: inputs.resolver_version,
            package_manager_version: inputs.package_manager_version,
            pip_tree_root: inputs.pip_tree_root.display().to_string(),
            pip_tree_sha256: inputs.pip_tree_sha256.to_ascii_lowercase(),
            pip_tree_binding_version: inputs.pip_tree_binding_version,
            pip_tree_max_files: inputs.pip_tree_max_files,
            pip_tree_max_bytes: inputs.pip_tree_max_bytes,
            pip_tree_max_file_bytes: inputs.pip_tree_max_file_bytes,
            pip_tree_max_path_bytes: inputs.pip_tree_max_path_bytes,
            pip_tree_files: inputs.pip_tree_files,
            pip_tree_bytes: inputs.pip_tree_bytes,
            target_environment: inputs.target_environment.display().to_string(),
            target_parent_identity: inputs.target_parent_identity,
            target_component: inputs.target_component,
            platform_tags,
            install_command_semantics: inputs.install_command_semantics,
            policy_projection_hash: inputs.policy_projection_hash,
            threat_db_sequence: inputs.threat_db_sequence,
            capsule_backend: inputs.capsule_backend,
            required_coverage: inputs.required_coverage,
            task_gate_binding: inputs.task_gate_binding,
            expiry: inputs.expiry,
        };
        digest.plan_digest = digest.compute_plan_digest();
        digest
    }

    /// The lowercase-hex sha256 of this plan's canonical JSON with `plan_digest`
    /// blanked, so the id is a stable function of the binding inputs and never of
    /// itself. Computed through [`crate::audit::canonical_json_for_hash`], the same
    /// canonicaliser the receipt + audit chain use.
    pub fn compute_plan_digest(&self) -> String {
        let mut value = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        if let Some(obj) = value.as_object_mut() {
            obj.insert(
                "plan_digest".to_string(),
                serde_json::Value::String(String::new()),
            );
        }
        let canon = crate::audit::canonical_json_for_hash(&value);
        use sha2::Digest as _;
        let mut h = sha2::Sha256::new();
        h.update(canon.as_bytes());
        let out = h.finalize();
        let mut s = String::with_capacity(64);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// Whether the stored `plan_digest` matches a recomputation over the binding
    /// inputs. `tirith pkg install` compares the operator-approved digest against
    /// the digest of the plan it is ABOUT to run; a mismatch means the situation
    /// changed (different interpreter, policy, DB sequence, ...) and the install is
    /// refused. Two digests are equivalent iff their `plan_digest` strings match
    /// (the hash binds every field), so callers compare ids.
    pub fn digest_matches(&self) -> bool {
        self.plan_digest == self.compute_plan_digest()
    }

    /// A human-readable DISPLAY LABEL for the artifact set: the sorted sha256s
    /// joined, truncated for readability. NEVER the binding identity (that is
    /// `plan_digest`); shown in the approve/install UX so an operator recognises the
    /// set without reading the full hash list.
    pub fn artifact_set_label(&self) -> String {
        if self.artifact_sha256.is_empty() {
            return "<no artifacts>".to_string();
        }
        self.artifact_sha256
            .iter()
            .map(|h| crate::util::truncate_bytes(h, 12))
            .collect::<Vec<_>>()
            .join("+")
    }

    /// Whether this approval has expired at `now_rfc3339` (an RFC 3339 timestamp).
    /// An empty `expiry` means "no expiry" and never expires. A malformed `expiry`
    /// is treated as ALREADY EXPIRED (fail closed: an approval whose expiry cannot
    /// be parsed is not trusted). A malformed `now` is also fail-closed.
    pub fn is_expired_at(&self, now_rfc3339: &str) -> bool {
        if self.expiry.is_empty() {
            return false;
        }
        let (Ok(expiry), Ok(now)) = (
            chrono::DateTime::parse_from_rfc3339(&self.expiry),
            chrono::DateTime::parse_from_rfc3339(now_rfc3339),
        ) else {
            return true;
        };
        now >= expiry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    /// The RECORD `sha256=<base64url-no-pad>` cell for a member body.
    fn record_sha256_cell(body: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(body);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize());
        format!("sha256={b64}")
    }

    // ---- the pip argv --------------------------------------------------------

    #[test]
    fn pip_install_args_are_the_pinned_flags() {
        let cmd = InstallCommand {
            approved_requirements_path: PathBuf::from("/q/txn/approved.txt"),
            target_environment: PathBuf::from("/dedicated-target"),
        };
        let args = cmd.pip_install_args();
        // The exact plan pin, in order: -I -m pip install + hardening flags + -r.
        assert_eq!(args[0], "-I");
        assert_eq!(args[1], "-m");
        assert_eq!(args[2], "pip");
        assert_eq!(args[3], "install");
        for flag in [
            "--isolated",
            "--no-index",
            "--no-deps",
            "--require-hashes",
            "--no-cache-dir",
            "--force-reinstall",
            "--upgrade",
        ] {
            assert!(args.iter().any(|a| a == flag), "missing {flag}");
        }
        // It reads the approved.txt by path as the LAST argument after `-r`.
        let r_idx = args.iter().position(|a| a == "-r").unwrap();
        assert_eq!(args[r_idx + 1], "/q/txn/approved.txt");
        assert_eq!(r_idx + 1, args.len() - 1);
        let target_idx = args.iter().position(|a| a == "--target").unwrap();
        assert_eq!(args[target_idx + 1], "/dedicated-target");
    }

    #[test]
    fn pip_install_uses_force_reinstall_so_an_existing_version_is_not_skipped() {
        // The plan calls force-reinstall out explicitly: without it pip no-ops a
        // package whose version is already installed, defeating a re-verified install.
        let cmd = InstallCommand {
            approved_requirements_path: PathBuf::from("/tmp/approved.txt"),
            target_environment: PathBuf::from("/dedicated-target"),
        };
        assert!(cmd
            .pip_install_args()
            .iter()
            .any(|a| a == "--force-reinstall"));
    }

    // ---- D5: post-install RECORD verification --------------------------------

    /// The RECORD `sha256=<base64url-no-pad>` cell for a body, as a CSV cell.
    fn record_cell(body: &[u8]) -> String {
        record_sha256_cell(body)
    }

    /// Write an installed distribution under `site`: the `.dist-info` dir, the named
    /// files on disk (relative to `site`), a RECORD listing each `(rel, optional
    /// body-for-hash)` row (a `None` body writes an empty hash/size cell), and any
    /// extra `.dist-info` files (`INSTALLER`, `direct_url.json`). Returns the
    /// `.dist-info` path.
    fn write_installed_dist(
        site: &Path,
        dist_name: &str,
        version: &str,
        files: &[(&str, &[u8])],
        record_rows: &[(&str, Option<&[u8]>)],
        extra_dist_info: &[(&str, &[u8])],
    ) -> PathBuf {
        let dist_info = site.join(format!("{dist_name}-{version}.dist-info"));
        std::fs::create_dir_all(&dist_info).unwrap();
        for (rel, body) in files {
            let p = site.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(p, body).unwrap();
        }
        for (name, body) in extra_dist_info {
            std::fs::write(dist_info.join(name), body).unwrap();
        }
        let mut record = String::new();
        for (path, body) in record_rows {
            match body {
                Some(b) => {
                    record.push_str(&format!("{path},{},{}\n", record_cell(b), b.len()));
                }
                None => record.push_str(&format!("{path},,\n")),
            }
        }
        record.push_str(&format!("{dist_name}-{version}.dist-info/RECORD,,\n"));
        std::fs::write(dist_info.join("RECORD"), record).unwrap();
        dist_info
    }

    /// A `<env>/lib/python3.11/site-packages` directory under a fresh temp env.
    fn env_with_site(tmp: &Path) -> PathBuf {
        let site = tmp.join("lib").join("python3.11").join("site-packages");
        std::fs::create_dir_all(&site).unwrap();
        site
    }

    fn finding_count(verdict: &Verdict) -> usize {
        verdict
            .findings
            .iter()
            .filter(|f| f.rule_id == RuleId::PythonInstalledIntegrityViolation)
            .count()
    }

    #[test]
    fn post_install_clean_distribution_yields_no_finding() {
        let tmp = tempfile::tempdir().unwrap();
        let site = env_with_site(tmp.path());
        let body = b"def f():\n    return 1\n";
        write_installed_dist(
            &site,
            "demo",
            "1.0",
            &[("demo/mod.py", body)],
            &[("demo/mod.py", Some(body))],
            &[],
        );
        let res = verify_post_install_record(tmp.path(), &["demo".to_string()], &Policy::default());
        assert_eq!(res.distributions_verified, 1);
        assert_eq!(res.distributions_not_found, 0);
        assert_eq!(res.hash_mismatches, 0);
        assert_eq!(
            finding_count(&res.verdict),
            0,
            "a clean install has no finding"
        );
        assert!(!res.is_block());
        assert!(res.is_complete());
    }

    #[test]
    fn post_install_record_hash_mismatch_folds_to_medium() {
        let tmp = tempfile::tempdir().unwrap();
        let site = env_with_site(tmp.path());
        // RECORD hashes the ORIGINAL bytes; the on-disk file is tampered.
        let original = b"original\n";
        write_installed_dist(
            &site,
            "demo",
            "1.0",
            &[("demo/mod.py", b"TAMPERED ON DISK\n")],
            &[("demo/mod.py", Some(original))],
            &[],
        );
        let res = verify_post_install_record(tmp.path(), &["demo".to_string()], &Policy::default());
        assert_eq!(res.hash_mismatches, 1);
        assert_eq!(
            finding_count(&res.verdict),
            1,
            "a real mismatch folds to one finding"
        );
        let f = res
            .verdict
            .findings
            .iter()
            .find(|f| f.rule_id == RuleId::PythonInstalledIntegrityViolation)
            .unwrap();
        assert_eq!(f.severity, Severity::Medium, "a bare mismatch is Medium");
    }

    #[test]
    fn post_install_editable_mismatch_is_not_a_false_positive() {
        // Editable / conda -> no FP: an editable distribution legitimately drifts, so
        // even a hash mismatch in it must NOT fold to a finding.
        let tmp = tempfile::tempdir().unwrap();
        let site = env_with_site(tmp.path());
        let original = b"original editable\n";
        write_installed_dist(
            &site,
            "demo",
            "1.0",
            &[("demo/mod.py", b"DRIFTED editable bytes\n")],
            &[("demo/mod.py", Some(original))],
            // direct_url.json marks it editable.
            &[(
                "direct_url.json",
                br#"{"url":"file:///home/me/demo","dir_info":{"editable":true}}"#,
            )],
        );
        let res = verify_post_install_record(tmp.path(), &["demo".to_string()], &Policy::default());
        // The mismatch is still COUNTED (coverage), but never produces a finding.
        assert_eq!(res.distributions_verified, 1);
        assert_eq!(
            finding_count(&res.verdict),
            0,
            "an editable distribution's drift must not fold to a finding"
        );
        assert!(!res.is_block());
    }

    #[test]
    fn post_install_conda_installer_mismatch_is_not_a_false_positive() {
        // A non-pip installer (conda / distro) legitimately diverges; its mismatch
        // must not fold to a finding either.
        let tmp = tempfile::tempdir().unwrap();
        let site = env_with_site(tmp.path());
        let original = b"original conda\n";
        write_installed_dist(
            &site,
            "demo",
            "1.0",
            &[("demo/mod.py", b"conda-rebuilt bytes\n")],
            &[("demo/mod.py", Some(original))],
            // INSTALLER names a non-pip installer.
            &[("INSTALLER", b"conda\n")],
        );
        let res = verify_post_install_record(tmp.path(), &["demo".to_string()], &Policy::default());
        assert_eq!(
            finding_count(&res.verdict),
            0,
            "a conda-installed distribution's drift must not fold to a finding"
        );
    }

    #[test]
    fn post_install_is_scoped_to_named_distributions_only() {
        // An UNRELATED, pre-installed distribution with a real mismatch must NOT be
        // verified: the install only judges the distributions it named. We install
        // `demo` cleanly and leave a tampered `other` in the same site-packages; only
        // `demo` is named, so `other`'s mismatch is never seen.
        let tmp = tempfile::tempdir().unwrap();
        let site = env_with_site(tmp.path());
        let clean = b"clean\n";
        write_installed_dist(
            &site,
            "demo",
            "1.0",
            &[("demo/mod.py", clean)],
            &[("demo/mod.py", Some(clean))],
            &[],
        );
        let original = b"original other\n";
        write_installed_dist(
            &site,
            "other",
            "2.0",
            &[("other/mod.py", b"TAMPERED other\n")],
            &[("other/mod.py", Some(original))],
            &[],
        );
        let res = verify_post_install_record(tmp.path(), &["demo".to_string()], &Policy::default());
        // Only `demo` was verified; `other`'s tamper is invisible to this install.
        assert_eq!(res.distributions_verified, 1);
        assert_eq!(res.hash_mismatches, 0);
        assert_eq!(finding_count(&res.verdict), 0);
    }

    #[test]
    fn post_install_unfound_distribution_is_a_coverage_gap_not_a_finding() {
        let tmp = tempfile::tempdir().unwrap();
        env_with_site(tmp.path());
        // Name a distribution that was never installed.
        let res =
            verify_post_install_record(tmp.path(), &["ghost".to_string()], &Policy::default());
        assert_eq!(res.distributions_not_found, 1);
        assert_eq!(res.distributions_verified, 0);
        assert!(!res.is_complete());
        assert_eq!(
            finding_count(&res.verdict),
            0,
            "a not-found dist is a coverage gap"
        );
    }

    #[test]
    fn post_install_duplicate_owned_path_corroborates_to_high() {
        // Two just-installed distributions both list the SAME installed path (the
        // cross-distribution loader/payload split): the duplicate corroborates the
        // Medium default up to High.
        let tmp = tempfile::tempdir().unwrap();
        let site = env_with_site(tmp.path());
        let shared = b"shared\n";
        write_installed_dist(
            &site,
            "alpha",
            "1.0",
            &[("shared/mod.py", shared)],
            &[("shared/mod.py", Some(shared))],
            &[],
        );
        // beta also lists the same path; the ownership index is built from RECORD
        // listings, and beta's own module is present too.
        write_installed_dist(
            &site,
            "beta",
            "1.0",
            &[("beta/mod.py", shared)],
            &[
                ("shared/mod.py", Some(shared)),
                ("beta/mod.py", Some(shared)),
            ],
            &[],
        );
        let res = verify_post_install_record(
            tmp.path(),
            &["alpha".to_string(), "beta".to_string()],
            &Policy::default(),
        );
        assert_eq!(finding_count(&res.verdict), 1);
        let f = res
            .verdict
            .findings
            .iter()
            .find(|f| f.rule_id == RuleId::PythonInstalledIntegrityViolation)
            .unwrap();
        assert_eq!(
            f.severity,
            Severity::High,
            "a duplicate-owned path across two installed distributions is High"
        );
    }

    #[test]
    fn post_install_duplicate_owned_path_suppressed_when_all_owners_exempt() {
        // If the ONLY distributions sharing a path are both editable / externally-
        // managed, the duplicate is expected drift, not tampering -> no finding.
        let tmp = tempfile::tempdir().unwrap();
        let site = env_with_site(tmp.path());
        let shared = b"shared\n";
        write_installed_dist(
            &site,
            "alpha",
            "1.0",
            &[("shared/mod.py", shared)],
            &[("shared/mod.py", Some(shared))],
            &[("INSTALLER", b"conda\n")],
        );
        write_installed_dist(
            &site,
            "beta",
            "1.0",
            &[("beta/mod.py", shared)],
            &[
                ("shared/mod.py", Some(shared)),
                ("beta/mod.py", Some(shared)),
            ],
            &[("INSTALLER", b"conda\n")],
        );
        let res = verify_post_install_record(
            tmp.path(),
            &["alpha".to_string(), "beta".to_string()],
            &Policy::default(),
        );
        assert_eq!(
            finding_count(&res.verdict),
            0,
            "a duplicate between two conda distributions is expected drift, not a finding"
        );
    }

    #[test]
    fn post_install_strict_policy_upgrades_action_to_block() {
        // A strict integrity policy (action_overrides) upgrades the Medium finding's
        // ACTION to Block, applied inside finalize_static_verdict; the fold itself
        // never forces Block.
        let tmp = tempfile::tempdir().unwrap();
        let site = env_with_site(tmp.path());
        let original = b"original\n";
        write_installed_dist(
            &site,
            "demo",
            "1.0",
            &[("demo/mod.py", b"TAMPERED\n")],
            &[("demo/mod.py", Some(original))],
            &[],
        );
        let mut policy = Policy::default();
        // action_overrides is keyed by the rule's wire string, valued "block".
        policy.action_overrides.insert(
            RuleId::PythonInstalledIntegrityViolation.to_string(),
            "block".to_string(),
        );
        let res = verify_post_install_record(tmp.path(), &["demo".to_string()], &policy);
        assert_eq!(finding_count(&res.verdict), 1);
        assert!(
            res.is_block(),
            "a strict integrity policy forces the post-install verdict to Block"
        );
    }

    #[test]
    fn post_install_matches_dist_info_with_different_name_spelling() {
        // The wheel name `typing_extensions` installs a `typing_extensions-*.dist-info`
        // dir; the name we scope by is the normalised `typing-extensions`. The match
        // must still find it (same PEP 503 normaliser both sides).
        let tmp = tempfile::tempdir().unwrap();
        let site = env_with_site(tmp.path());
        let body = b"x = 1\n";
        write_installed_dist(
            &site,
            "typing_extensions",
            "4.9.0",
            &[("typing_extensions.py", body)],
            &[("typing_extensions.py", Some(body))],
            &[],
        );
        let res = verify_post_install_record(
            tmp.path(),
            &["typing-extensions".to_string()],
            &Policy::default(),
        );
        assert_eq!(
            res.distributions_verified, 1,
            "the normalised name must match the on-disk dist-info spelling"
        );
        assert_eq!(res.distributions_not_found, 0);
    }

    #[test]
    fn exact_post_install_verifies_pip_target_directory_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let body = b"installed directly by pip --target\n";
        write_installed_dist(
            tmp.path(),
            "demo",
            "1.0",
            &[("demo.py", body)],
            &[("demo.py", Some(body))],
            &[],
        );
        let expected = [ExpectedInstalledDistribution {
            name: "demo".to_string(),
            version: Some("1.0".to_string()),
        }];
        let result = verify_post_install_record_exact(tmp.path(), &expected, &Policy::default());
        assert_eq!(result.distributions_verified, 1);
        assert!(result.is_complete());
    }

    #[test]
    fn exact_post_install_rejects_stale_version_only() {
        let tmp = tempfile::tempdir().unwrap();
        write_installed_dist(tmp.path(), "demo", "0.9", &[], &[], &[]);
        let expected = [ExpectedInstalledDistribution {
            name: "demo".to_string(),
            version: Some("1.0".to_string()),
        }];
        let result = verify_post_install_record_exact(tmp.path(), &expected, &Policy::default());
        assert_eq!(result.distributions_verified, 0);
        assert_eq!(result.distributions_not_found, 1);
        assert!(!result.is_complete());
    }

    #[test]
    fn exact_post_install_rejects_duplicate_matching_dist_info() {
        let tmp = tempfile::tempdir().unwrap();
        write_installed_dist(tmp.path(), "demo", "1.0", &[], &[], &[]);
        let nested = env_with_site(tmp.path());
        write_installed_dist(&nested, "demo", "1.0", &[], &[], &[]);
        let expected = [ExpectedInstalledDistribution {
            name: "demo".to_string(),
            version: Some("1.0".to_string()),
        }];
        let result = verify_post_install_record_exact(tmp.path(), &expected, &Policy::default());
        assert_eq!(result.distributions_verified, 0);
        assert_eq!(result.distributions_not_found, 1);
        assert_eq!(finding_count(&result.verdict), 1);
    }

    // ---- D7: InstallPlanDigest -----------------------------------------------

    /// A full set of binding inputs for a digest, every field populated so a test
    /// can mutate exactly one and observe the digest change.
    fn plan_inputs() -> InstallPlanInputs {
        InstallPlanInputs {
            artifact_sha256: vec!["b".repeat(64), "a".repeat(64)], // out of order
            normalized_packages: vec!["flask".to_string(), "click".to_string()],
            interpreter: PathBuf::from("/venv/bin/python"),
            interpreter_sha256: "c".repeat(64),
            resolver: PathBuf::from("/usr/bin/uv"),
            resolver_sha256: "d".repeat(64),
            resolver_version: "uv 1.2.3".to_string(),
            package_manager_version: "24.0".to_string(),
            pip_tree_root: PathBuf::from("/usr/lib/python3/site-packages/pip"),
            pip_tree_sha256: "e".repeat(64),
            pip_tree_binding_version: 1,
            pip_tree_max_files: 20_000,
            pip_tree_max_bytes: 256 * 1024 * 1024,
            pip_tree_max_file_bytes: 64 * 1024 * 1024,
            pip_tree_max_path_bytes: 4096,
            pip_tree_files: 120,
            pip_tree_bytes: 32_000,
            target_environment: PathBuf::from("/venv"),
            target_parent_identity: "linux-devino-v1:1:2".to_string(),
            target_component: "venv".to_string(),
            platform_tags: vec!["py3-none-any".to_string()],
            install_command_semantics: InstallCommand {
                approved_requirements_path: PathBuf::from("/q/txn/approved.txt"),
                target_environment: PathBuf::from("/venv"),
            }
            .pip_install_args_without_requirements_path(),
            policy_projection_hash: "deadbeef".repeat(8),
            threat_db_sequence: 7,
            capsule_backend: "landlock-seccomp".to_string(),
            required_coverage: crate::capsule::CapsuleSpec::locked_down().required_coverage(),
            task_gate_binding: "task_gate:v1:mode=off;denied=".to_string(),
            expiry: "2026-06-22T12:00:00+00:00".to_string(),
        }
    }

    #[test]
    fn plan_digest_is_content_addressed_and_stable() {
        let d = InstallPlanDigest::new(plan_inputs());
        // The id is the content hash with id blanked: reproducible and self-consistent.
        assert_eq!(d.plan_digest.len(), 64);
        assert!(d.digest_matches());
        assert_eq!(d.compute_plan_digest(), d.plan_digest);
        // The unordered lists were sorted + de-duplicated by `new`.
        assert_eq!(d.artifact_sha256, vec!["a".repeat(64), "b".repeat(64)]);
        assert_eq!(d.normalized_packages, vec!["click", "flask"]);
    }

    #[test]
    fn plan_digest_is_order_independent_over_the_sorted_sets() {
        // Two plans differing ONLY in the order they list artifacts / packages bind
        // to the SAME digest (the sets are sorted before hashing).
        let a = InstallPlanDigest::new(plan_inputs());
        let mut other = plan_inputs();
        other.artifact_sha256 = vec!["a".repeat(64), "b".repeat(64)]; // already sorted
        other.normalized_packages = vec!["flask".to_string(), "click".to_string()];
        let b = InstallPlanDigest::new(other);
        assert_eq!(a.plan_digest, b.plan_digest);
    }

    #[test]
    fn plan_digest_changes_when_any_bound_input_changes() {
        let base = InstallPlanDigest::new(plan_inputs());

        // Each of these is a DIFFERENT install situation and MUST re-bind the digest.
        type Mutator = Box<dyn Fn(&mut InstallPlanInputs)>;
        let mutate: Vec<(&str, Mutator)> = vec![
            (
                "different artifact hash",
                Box::new(|i: &mut InstallPlanInputs| i.artifact_sha256 = vec!["c".repeat(64)]),
            ),
            (
                "different package set",
                Box::new(|i: &mut InstallPlanInputs| {
                    i.normalized_packages = vec!["evil".to_string()]
                }),
            ),
            (
                "different interpreter",
                Box::new(|i: &mut InstallPlanInputs| {
                    i.interpreter = PathBuf::from("/other/python")
                }),
            ),
            (
                "different interpreter bytes",
                Box::new(|i: &mut InstallPlanInputs| i.interpreter_sha256 = "0".repeat(64)),
            ),
            (
                "different resolver",
                Box::new(|i: &mut InstallPlanInputs| i.resolver = PathBuf::from("/other/uv")),
            ),
            (
                "different resolver bytes",
                Box::new(|i: &mut InstallPlanInputs| i.resolver_sha256 = "0".repeat(64)),
            ),
            (
                "different resolver version",
                Box::new(|i: &mut InstallPlanInputs| i.resolver_version = "uv 9".to_string()),
            ),
            (
                "different pip version",
                Box::new(|i: &mut InstallPlanInputs| i.package_manager_version = "99".to_string()),
            ),
            (
                "different pip tree",
                Box::new(|i: &mut InstallPlanInputs| i.pip_tree_sha256 = "0".repeat(64)),
            ),
            (
                "different pip binding schema",
                Box::new(|i: &mut InstallPlanInputs| i.pip_tree_binding_version += 1),
            ),
            (
                "different pip binding limits",
                Box::new(|i: &mut InstallPlanInputs| i.pip_tree_max_file_bytes += 1),
            ),
            (
                "different target env",
                Box::new(|i: &mut InstallPlanInputs| {
                    i.target_environment = PathBuf::from("/other")
                }),
            ),
            (
                "different target parent identity",
                Box::new(|i: &mut InstallPlanInputs| {
                    i.target_parent_identity = "linux-devino-v1:9:9".to_string()
                }),
            ),
            (
                "different target component",
                Box::new(|i: &mut InstallPlanInputs| i.target_component = "other".to_string()),
            ),
            (
                "different platform tags",
                Box::new(|i: &mut InstallPlanInputs| {
                    i.platform_tags = vec!["cp311-cp311-manylinux".to_string()]
                }),
            ),
            (
                "different install command",
                Box::new(|i: &mut InstallPlanInputs| {
                    i.install_command_semantics = vec!["-m".to_string(), "pip".to_string()]
                }),
            ),
            (
                "weaker policy",
                Box::new(|i: &mut InstallPlanInputs| i.policy_projection_hash = "0".repeat(64)),
            ),
            (
                "advanced DB sequence",
                Box::new(|i: &mut InstallPlanInputs| i.threat_db_sequence = 8),
            ),
            (
                "different capsule backend",
                Box::new(|i: &mut InstallPlanInputs| i.capsule_backend = "noop".to_string()),
            ),
            (
                "weaker required coverage",
                Box::new(|i: &mut InstallPlanInputs| {
                    i.required_coverage = crate::capsule::CapsuleCoverage::NONE
                }),
            ),
            (
                "different expiry",
                Box::new(|i: &mut InstallPlanInputs| {
                    i.expiry = "2027-01-01T00:00:00+00:00".to_string()
                }),
            ),
        ];

        for (label, f) in mutate {
            let mut inputs = plan_inputs();
            f(&mut inputs);
            let changed = InstallPlanDigest::new(inputs);
            assert_ne!(
                changed.plan_digest, base.plan_digest,
                "changing the {label} must re-bind the plan digest"
            );
        }
    }

    #[test]
    fn plan_digest_install_semantics_omit_the_per_run_approved_txt_path() {
        // The bound install argv carries the security-relevant flags but NOT the
        // per-run approved.txt path, so two runs writing approved.txt to different
        // temp dirs still bind to the same digest.
        let semantics = InstallCommand {
            approved_requirements_path: PathBuf::from("/q/txn-A/approved.txt"),
            target_environment: PathBuf::from("/venv"),
        }
        .pip_install_args_without_requirements_path();
        // The flags are present; no concrete approved.txt path is.
        assert!(semantics.iter().any(|a| a == "--require-hashes"));
        assert!(semantics.iter().any(|a| a == "--no-index"));
        assert!(!semantics.iter().any(|a| a.contains("approved.txt")));
        assert!(!semantics.iter().any(|a| a == "-r"));
    }

    #[test]
    fn artifact_set_label_is_a_display_label_not_the_binding() {
        let d = InstallPlanDigest::new(plan_inputs());
        let label = d.artifact_set_label();
        // The label is the truncated sorted hashes joined; it is NOT the binding id.
        assert!(label.contains(&"a".repeat(12)));
        assert!(label.contains(&"b".repeat(12)));
        assert_ne!(label, d.plan_digest, "the label must not be the digest");
    }

    #[test]
    fn plan_digest_roundtrips_through_json() {
        let d = InstallPlanDigest::new(plan_inputs());
        let json = serde_json::to_string(&d).unwrap();
        let back: InstallPlanDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
        assert!(back.digest_matches());
    }

    #[test]
    fn plan_digest_detects_an_edited_record() {
        // An attacker who edits a saved approval (e.g. swaps the interpreter) but
        // leaves the stored digest stale is caught: digest_matches() recomputes.
        let mut d = InstallPlanDigest::new(plan_inputs());
        d.interpreter = "/attacker/python".to_string();
        assert!(
            !d.digest_matches(),
            "an edited binding field with a stale digest must not validate"
        );
    }

    #[test]
    fn plan_digest_expiry_is_fail_closed() {
        let mut d = InstallPlanDigest::new(plan_inputs()); // expiry 2026-06-22T12:00
                                                           // Before expiry: live.
        assert!(!d.is_expired_at("2026-06-22T11:59:59+00:00"));
        // At/after expiry: expired.
        assert!(d.is_expired_at("2026-06-22T12:00:00+00:00"));
        assert!(d.is_expired_at("2026-06-23T00:00:00+00:00"));
        // A malformed expiry is treated as already expired (fail closed).
        d.expiry = "not-a-timestamp".to_string();
        assert!(d.is_expired_at("2026-06-22T11:00:00+00:00"));
        // An empty expiry never expires.
        d.expiry = String::new();
        assert!(!d.is_expired_at("2030-01-01T00:00:00+00:00"));
    }
}
