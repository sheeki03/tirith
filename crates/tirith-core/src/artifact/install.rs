//! Package-firewall install contracts that outlive contained execution.
//!
//! Contained `tirith pkg install` execution (and the approvals that fed it) is
//! disabled, so the install-from-digest planner that used to live here (the
//! pre-launch re-bind, the `approved.txt` builder, the deny-all install capsule
//! spec, and the approval-bound plan digest) was removed. What remains is shared
//! by live surfaces:
//!
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

use crate::artifact::record::{
    index_distribution_ownership, verify_installed_record, EnvironmentLayout, FileVerification,
    OwnershipIndex,
};
use crate::artifact::{ArtifactSignal, ArtifactSignalKind, DistributionIdentity};
use crate::location::SubjectLocation;
use crate::policy::Policy;
use crate::threatdb::Ecosystem;
use crate::verdict::{Evidence, Finding, RuleId, Severity, Timings, Verdict};

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
}
