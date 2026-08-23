use std::io::Write;

/// Output format for commands that support human and JSON output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum HumanJsonFormat {
    #[default]
    Human,
    Json,
}

impl HumanJsonFormat {
    /// Resolve the effective format from `--format` and the `--json` alias.
    /// Returns `(format, is_json)`.
    pub fn resolve(format: Option<Self>, json_flag: bool) -> (Self, bool) {
        let resolved = if json_flag {
            Self::Json
        } else {
            format.unwrap_or(Self::Human)
        };
        (resolved, resolved == Self::Json)
    }
}

/// Output format for scan, which additionally supports SARIF.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum HumanJsonSarifFormat {
    #[default]
    Human,
    Json,
    Sarif,
}

impl HumanJsonSarifFormat {
    /// Resolve the effective format from `--format`, `--json`, and `--sarif`.
    /// Returns `(format, is_json, is_sarif)`.
    pub fn resolve(format: Option<Self>, json_flag: bool, sarif_flag: bool) -> (Self, bool, bool) {
        let resolved = if json_flag {
            Self::Json
        } else if sarif_flag {
            Self::Sarif
        } else {
            format.unwrap_or(Self::Human)
        };
        (resolved, resolved == Self::Json, resolved == Self::Sarif)
    }
}

/// `true` when `TIRITH_OFFLINE` is set truthy (`1`/`true`/`yes`/`on`,
/// case-insensitive, trimmed). The env-var half of the CLI-wide offline switch
/// that every networked command routes through, so it behaves identically.
pub(crate) fn offline_env_active() -> bool {
    std::env::var("TIRITH_OFFLINE")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Write `value` as pretty JSON + trailing newline to stdout through one locked
/// handle with fallible ops, so a broken pipe returns `false` rather than
/// panicking (a bare `println!` would). `ctx` is the stderr message on failure.
/// Returns `false` on a write failure so the caller can exit non-zero — a piped
/// consumer must not see truncated JSON paired with a success code.
pub(crate) fn write_json_stdout<T: serde::Serialize>(value: &T, ctx: &str) -> bool {
    let mut out = std::io::stdout().lock();
    if write_json_to(&mut out, value) {
        true
    } else {
        eprintln!("{ctx}");
        false
    }
}

/// Write `value` as pretty JSON + trailing newline to `out`; `false` if either
/// write fails. Factored out of [`write_json_stdout`] so the failure path is
/// unit-testable with a deliberately-failing writer.
fn write_json_to<W: Write, T: serde::Serialize>(out: &mut W, value: &T) -> bool {
    serde_json::to_writer_pretty(&mut *out, value).is_ok() && writeln!(out).is_ok()
}

/// Sanitize untrusted text for human terminal output.
///
/// Wraps [`tirith_core::mcp::output_filter::sanitize_for_display`] (which strips
/// terminal-control escapes AND deceptive / invisible Unicode), then applies the
/// newline policy for the field kind:
///
/// - `allow_multiline == false`: also strip `\n` and `\r`, so a single-line label
///   (finding title, path, manifest name) cannot break onto extra terminal rows.
/// - `allow_multiline == true`: KEEP `\n`, but RE-INDENT every continuation line
///   with a two-space prefix so an injected newline cannot forge a fake top-level
///   row that impersonates tirith's own output. The display scrub already dropped
///   any bare `\r` and kept only CRLF, so each line's trailing `\r` is trimmed and
///   the row re-joined with `\n` + indent.
///
/// Callers MUST pass only the untrusted VALUE, never a whole formatted line: the
/// display scrub removes ALL ANSI, including tirith's own severity colors.
pub fn sanitize_for_human_output(s: &str, allow_multiline: bool) -> String {
    let cleaned = tirith_core::mcp::output_filter::sanitize_for_display(s).replace('\t', "\\t");
    if allow_multiline {
        // Keep newlines but re-indent every continuation line so an injected `\n`
        // cannot fabricate a new top-level row. The display scrub already reduced
        // any `\r` to CRLF form, so trim a trailing `\r` per line before re-joining
        // with `\n` + a two-space indent.
        cleaned
            .split('\n')
            .map(|line| line.strip_suffix('\r').unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n  ")
    } else {
        // Single-line label: drop every newline / carriage return outright.
        cleaned
            .chars()
            .filter(|&c| c != '\n' && c != '\r')
            .collect()
    }
}

/// Maximum number of Unicode scalar values retained from an untrusted
/// provenance field. The trailing ellipsis, when present, is outside this
/// budget by one character.
#[cfg(test)]
pub(crate) const PROVENANCE_MAX_CHARS: usize = tirith_core::redact::PROVENANCE_MAX_CHARS;

/// Redact and terminal-neutralize an untrusted provenance text field using one
/// already-frozen custom-DLP plan. Newlines/tabs are flattened so the same
/// returned value is safe in both JSON and human one-line projections.
pub(crate) fn sanitize_provenance_text_with_compiled(
    value: &str,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> String {
    tirith_core::redact::sanitize_provenance_text_with_compiled(value, compiled)
}

/// Redact an untrusted provenance URL before it reaches any output surface.
/// Userinfo, query, and fragment are always removed. Known hosted-RPC provider
/// paths (and generic `/v2|v3/<secret-shaped-token>` paths) are reduced to a
/// non-secret prefix because API credentials commonly live in those segments.
/// The resulting value then passes through the exact text sanitizer above.
pub(crate) fn sanitize_provenance_url_with_compiled(
    value: &str,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> String {
    tirith_core::redact::sanitize_provenance_url_with_compiled(value, compiled)
}

/// A redacted, priority-bounded clone for one JSON DTO boundary. The raw
/// verdict remains available to policy, audit, and exit-code callers.
pub(crate) struct VerdictPresentation {
    pub verdict: tirith_core::verdict::Verdict,
    pub original_findings_count: usize,
    pub presented_findings_count: usize,
    pub dropped_findings_count: usize,
}

pub(crate) fn prepare_verdict_presentation(
    verdict: &tirith_core::verdict::Verdict,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> VerdictPresentation {
    let original_findings_count = verdict.findings.len();
    let retained_findings_count =
        tirith_core::verdict::retained_finding_indices_for_output(&verdict.findings).len();
    let dropped_findings_count = original_findings_count.saturating_sub(retained_findings_count);

    // Redact before truncation so a presentation boundary cannot split a
    // secret and make the configured pattern stop matching.
    let mut display = verdict.clone();
    tirith_core::redact::redact_verdict_with_compiled(&mut display, compiled);
    tirith_core::verdict::bound_verdict_for_output(&mut display);
    let presented_findings_count = display.findings.len();

    VerdictPresentation {
        verdict: display,
        original_findings_count,
        presented_findings_count,
        dropped_findings_count,
    }
}

#[cfg(test)]
mod write_json_tests {
    use super::write_json_to;

    #[test]
    fn verdict_projection_keeps_late_critical_high_and_analysis_incomplete() {
        use tirith_core::verdict::{Finding, RuleId, Severity, Timings, Verdict};

        let finding = |rule_id, severity, title: &str| Finding {
            rule_id,
            severity,
            title: title.to_string(),
            description: "bounded projection regression".to_string(),
            evidence: Vec::new(),
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        };
        let mut findings = (0..400)
            .map(|index| {
                finding(
                    RuleId::ConfigInjection,
                    Severity::Low,
                    &format!("early low {index}"),
                )
            })
            .collect::<Vec<_>>();
        findings.push(finding(
            RuleId::CredentialInText,
            Severity::High,
            "late high",
        ));
        findings.push(finding(
            RuleId::AnalysisIncomplete,
            Severity::Medium,
            "late analysis incomplete",
        ));
        findings.push(finding(
            RuleId::PrivateKeyExposed,
            Severity::Critical,
            "late critical",
        ));
        let verdict = Verdict::from_findings(findings, 3, Timings::default());
        let raw_count = verdict.findings.len();
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&[]);

        let projection = super::prepare_verdict_presentation(&verdict, &compiled);

        assert_eq!(verdict.findings.len(), raw_count);
        assert_eq!(projection.original_findings_count, raw_count);
        assert!(projection.dropped_findings_count > 0);
        for rule_id in [
            RuleId::PrivateKeyExposed,
            RuleId::CredentialInText,
            RuleId::AnalysisIncomplete,
        ] {
            assert!(
                projection
                    .verdict
                    .findings
                    .iter()
                    .any(|finding| finding.rule_id == rule_id),
                "late priority finding {rule_id} was dropped"
            );
        }
    }

    /// A writer that always fails — models a broken pipe / closed stdout.
    struct FailingWriter;
    impl std::io::Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "broken pipe",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "broken pipe",
            ))
        }
    }

    #[test]
    fn write_json_to_reports_failure_on_write_error() {
        // A failed write returns `false` so callers exit non-zero rather than
        // pairing truncated JSON with a success code.
        let mut w = FailingWriter;
        assert!(
            !write_json_to(&mut w, &serde_json::json!({"signed": true})),
            "a writer that errors must make write_json_to return false"
        );
    }

    #[test]
    fn write_json_to_succeeds_to_a_buffer() {
        let mut buf: Vec<u8> = Vec::new();
        assert!(write_json_to(&mut buf, &serde_json::json!({"ok": 1})));
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("\"ok\""));
        assert!(s.ends_with('\n'), "a trailing newline must be written");
    }

    /// R12 #B: `write_file_atomic` lands content exactly, an overwrite FULLY
    /// replaces the prior content, and no temp file is left behind.
    #[test]
    fn write_file_atomic_writes_replaces_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commands.yaml");

        super::write_file_atomic(&path, b"first: true\n", true).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first: true\n");

        // Overwrite with SHORTER content: the rename fully replaces it (a
        // truncate-in-place could leave trailing old bytes).
        super::write_file_atomic(&path, b"x\n", true).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "x\n");

        // The only directory entry is the target — the temp file was consumed.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        assert_eq!(entries.len(), 1, "no temp file left behind: {entries:?}");
        assert_eq!(entries[0], path);
    }

    /// R17 #4: `write_file_atomic` through a SYMLINK must update the link's
    /// TARGET, not clobber the link with a regular file (the fix canonicalizes a
    /// symlinked destination and writes through). Unix-only.
    #[cfg(unix)]
    #[test]
    fn write_file_atomic_through_symlink_updates_target_not_link() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        // Real config in a SEPARATE subdir to prove the temp file lands next to
        // the resolved target (same filesystem), not the link.
        let target_dir = dir.path().join("real");
        std::fs::create_dir_all(&target_dir).unwrap();
        let target = target_dir.join("config.yaml");
        std::fs::write(&target, b"old: true\n").unwrap();

        let link = dir.path().join("config.yaml");
        symlink(&target, &link).unwrap();

        super::write_file_atomic(&link, b"new: true\n", true).unwrap();

        // The TARGET holds the new content; the symlink is INTACT, not clobbered.
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new: true\n");
        let link_meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(
            link_meta.file_type().is_symlink(),
            "the destination must remain a symlink, not be clobbered by a regular file"
        );
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            target,
            "the symlink must still point at the original target"
        );
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "new: true\n");

        // No temp file left dangling in EITHER directory.
        for d in [dir.path(), target_dir.as_path()] {
            let extra: Vec<_> = std::fs::read_dir(d)
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p != &link && p != &target && p != &target_dir)
                .collect();
            assert!(
                extra.is_empty(),
                "no temp file left behind in {d:?}: {extra:?}"
            );
        }
    }

    /// A DANGLING symlink (missing target) falls back to renaming onto the link
    /// path (a regular file) — `canonicalize` can't resolve it, so the
    /// write-through path is correctly NOT taken. Unix-only.
    #[cfg(unix)]
    #[test]
    fn write_file_atomic_dangling_symlink_falls_back() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let missing_target = dir.path().join("does-not-exist.yaml");
        let link = dir.path().join("config.yaml");
        symlink(&missing_target, &link).unwrap();

        super::write_file_atomic(&link, b"data: 1\n", true).unwrap();

        // The link path holds the content as a REGULAR file (fallback path).
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "data: 1\n");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_file(),
            "a dangling symlink falls back to a regular-file write at the link path"
        );
    }

    /// R13 #K: `overwrite=false` must NOT clobber an existing file — closing the
    /// TOCTOU between an `init` caller's `exists()` check and the publish (the
    /// file survives, write reports `AlreadyExists`); `overwrite=true` replaces it.
    #[test]
    fn write_file_atomic_no_clobber_preserves_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commands.yaml");

        // No-clobber create when absent: succeeds.
        super::write_file_atomic(&path, b"original\n", false).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "original\n");

        // No-clobber write when the file EXISTS: fails AlreadyExists, untouched.
        let err = super::write_file_atomic(&path, b"clobbered\n", false)
            .expect_err("no-clobber write over an existing file must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "original\n",
            "a failed no-clobber write must leave the existing file untouched"
        );

        // overwrite=true still replaces it, and leaves no temp file behind.
        super::write_file_atomic(&path, b"forced\n", true).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "forced\n");
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        assert_eq!(entries.len(), 1, "no temp file left behind: {entries:?}");
    }

    /// The containment properties below are asserted on
    /// [`super::write_config_file_permitted`], the only contained publisher the
    /// CLI has left, with an inert default policy so the subject is the write
    /// and not the gate.
    fn inert() -> tirith_core::policy::Policy {
        tirith_core::policy::Policy::default()
    }

    #[test]
    fn contained_atomic_write_stays_beneath_root() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join(".tirith");
        std::fs::create_dir(&config).unwrap();
        let path = config.join("policy.yaml");

        super::write_config_file_permitted(
            root.path(),
            &path,
            b"safe: true\n",
            true,
            &inert(),
            true,
        )
        .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"safe: true\n");

        let outside = tempfile::tempdir().unwrap();
        let escaped = root.path().join("..").join(
            outside
                .path()
                .file_name()
                .expect("temp directory has a name"),
        );
        let err = super::write_config_file_permitted(
            root.path(),
            &escaped,
            b"escape",
            true,
            &inert(),
            true,
        )
        .expect_err("a destination outside the anchored root must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn config_write_without_a_v2_provider_fails_closed_when_provenance_is_required() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join(".tirith");
        std::fs::create_dir(&config).unwrap();
        let path = config.join("policy.yaml");
        let mut policy = inert();
        policy.task_gate.mode = tirith_core::web3_policy::TaskGateMode::Enforce;
        policy
            .task_gate
            .effects_requiring_verified_provenance
            .insert(tirith_core::effects::CommandEffectKind::FilesystemWrite);

        let error = super::write_config_file_permitted(
            root.path(),
            &path,
            b"safe: true\n",
            true,
            &policy,
            true,
        )
        .expect_err("a locally derived v1 envelope cannot satisfy verified provenance");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error
            .to_string()
            .contains("verified provenance requires a strict schema-v2 task envelope"));
        assert!(!path.exists(), "a refused write must not be published");
    }

    #[test]
    fn config_write_operation_mismatch_never_enters_replay_consumption() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let root = tempfile::tempdir().unwrap();
        let authorized_path = root.path().join("authorized-policy.yaml");
        let authorized_envelope =
            tirith_core::config_write::ConfigWritePermit::operation_envelope_for(
                root.path(),
                &authorized_path,
                b"safe\n",
                true,
                "policy-a",
                false,
            )
            .unwrap();
        let authorized_operation = tirith_core::task_boundary::BoundaryOperation {
            boundary: tirith_core::task_boundary::OwnedBoundary::ConfigWrite,
            envelope: &authorized_envelope,
            adapter: tirith_core::task::IngressAdapter::Unattributed,
            boundary_effects: Default::default(),
        };
        let pending = tirith_core::task_boundary::prepare_locally_derived_boundary_authorization::<
            tirith_core::task_boundary::ConfigWriteBoundary,
        >(
            &authorized_operation,
            &tirith_core::web3_policy::TaskGatePolicy::default(),
            &tirith_core::task_analysis::TaskAnalysisContext::default(),
        )
        .expect("prepare authorization");

        let changed_path = root.path().join("changed-policy.yaml");
        let changed_envelope =
            tirith_core::config_write::ConfigWritePermit::operation_envelope_for(
                root.path(),
                &changed_path,
                b"safe\n",
                true,
                "policy-a",
                false,
            )
            .unwrap();
        let changed_operation = tirith_core::task_boundary::BoundaryOperation {
            boundary: tirith_core::task_boundary::OwnedBoundary::ConfigWrite,
            envelope: &changed_envelope,
            adapter: tirith_core::task::IngressAdapter::Unattributed,
            boundary_effects: Default::default(),
        };
        // This closure is the only path into `consume_default`, and therefore
        // the only path that could open and write the durable replay ledger.
        let replay_writes = AtomicUsize::new(0);
        let result = super::consume_config_write_authorization_with(
            pending,
            &changed_operation,
            |pending| {
                replay_writes.fetch_add(1, Ordering::SeqCst);
                pending.consume_default(chrono::Utc::now())
            },
        );

        let error = match result {
            Ok(_) => panic!("a changed operation must fail before replay consumption"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            tirith_core::task_boundary::BoundaryAuthorizationError::EnvelopeMismatch
        ));
        assert_eq!(replay_writes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn every_config_projection_mutation_fails_before_replay_consumption() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Mutation {
            label: &'static str,
            other_root: bool,
            other_destination: bool,
            contents: &'static [u8],
            overwrite: bool,
            policy_identity: &'static str,
            policy_change: bool,
        }
        let mutations = [
            Mutation {
                label: "destination",
                other_root: false,
                other_destination: true,
                contents: b"safe\n",
                overwrite: true,
                policy_identity: "policy-a",
                policy_change: true,
            },
            Mutation {
                label: "content",
                other_root: false,
                other_destination: false,
                contents: b"changed\n",
                overwrite: true,
                policy_identity: "policy-a",
                policy_change: true,
            },
            Mutation {
                label: "overwrite mode",
                other_root: false,
                other_destination: false,
                contents: b"safe\n",
                overwrite: false,
                policy_identity: "policy-a",
                policy_change: true,
            },
            Mutation {
                label: "root identity",
                other_root: true,
                other_destination: false,
                contents: b"safe\n",
                overwrite: true,
                policy_identity: "policy-a",
                policy_change: true,
            },
            Mutation {
                label: "policy identity",
                other_root: false,
                other_destination: false,
                contents: b"safe\n",
                overwrite: true,
                policy_identity: "policy-b",
                policy_change: true,
            },
            Mutation {
                label: "PolicyChange classification",
                other_root: false,
                other_destination: false,
                contents: b"safe\n",
                overwrite: true,
                policy_identity: "policy-a",
                policy_change: false,
            },
        ];

        for mutation in mutations {
            let authorized_root = tempfile::tempdir().unwrap();
            let other_root = tempfile::tempdir().unwrap();
            let authorized_path = authorized_root.path().join("policy.yaml");
            let authorized_envelope =
                tirith_core::config_write::ConfigWritePermit::operation_envelope_for(
                    authorized_root.path(),
                    &authorized_path,
                    b"safe\n",
                    true,
                    "policy-a",
                    true,
                )
                .unwrap();
            let authorized_operation = tirith_core::task_boundary::BoundaryOperation {
                boundary: tirith_core::task_boundary::OwnedBoundary::ConfigWrite,
                envelope: &authorized_envelope,
                adapter: tirith_core::task::IngressAdapter::Unattributed,
                boundary_effects:
                    tirith_core::config_write::ConfigWritePermit::boundary_effects_for(true),
            };
            let pending =
                tirith_core::task_boundary::prepare_locally_derived_boundary_authorization::<
                    tirith_core::task_boundary::ConfigWriteBoundary,
                >(
                    &authorized_operation,
                    &tirith_core::web3_policy::TaskGatePolicy::default(),
                    &tirith_core::task_analysis::TaskAnalysisContext::default(),
                )
                .expect("prepare authorization");

            let root = if mutation.other_root {
                other_root.path()
            } else {
                authorized_root.path()
            };
            let path = if mutation.other_destination {
                root.join("other.yaml")
            } else {
                root.join("policy.yaml")
            };
            let changed_envelope =
                tirith_core::config_write::ConfigWritePermit::operation_envelope_for(
                    root,
                    &path,
                    mutation.contents,
                    mutation.overwrite,
                    mutation.policy_identity,
                    mutation.policy_change,
                )
                .unwrap();
            let changed_operation = tirith_core::task_boundary::BoundaryOperation {
                boundary: tirith_core::task_boundary::OwnedBoundary::ConfigWrite,
                envelope: &changed_envelope,
                adapter: tirith_core::task::IngressAdapter::Unattributed,
                boundary_effects:
                    tirith_core::config_write::ConfigWritePermit::boundary_effects_for(
                        mutation.policy_change,
                    ),
            };
            let replay_writes = AtomicUsize::new(0);
            let result = super::consume_config_write_authorization_with(
                pending,
                &changed_operation,
                |pending| {
                    replay_writes.fetch_add(1, Ordering::SeqCst);
                    pending.consume_default(chrono::Utc::now())
                },
            );
            let error = match result {
                Ok(_) => panic!("{}: mutation reached replay consumption", mutation.label),
                Err(error) => error,
            };
            assert!(matches!(
                error,
                tirith_core::task_boundary::BoundaryAuthorizationError::EnvelopeMismatch
            ));
            assert_eq!(
                replay_writes.load(Ordering::SeqCst),
                0,
                "{}",
                mutation.label
            );
        }
    }

    #[test]
    fn policy_file_mutators_are_byte_identical_on_real_writer_denial() {
        type Mutator = fn(&std::path::Path) -> std::io::Result<()>;
        fn context(path: &std::path::Path) -> std::io::Result<()> {
            super::context::update_policy_guard_key(path, true)
        }
        fn env(path: &std::path::Path) -> std::io::Result<()> {
            super::env_guard::update_policy_guard_key(path, true)
        }
        fn exec(path: &std::path::Path) -> std::io::Result<()> {
            super::exec::update_policy_guard_key(path, true)
        }
        fn hooks(path: &std::path::Path) -> std::io::Result<()> {
            super::hooks::update_policy_guard_key(path, true)
        }
        fn sudo_guard(path: &std::path::Path) -> std::io::Result<()> {
            super::sudo::update_policy_key(path, "context_guard_enabled", "true")
        }
        fn sudo_reason(path: &std::path::Path) -> std::io::Result<()> {
            super::sudo::update_policy_key(path, "sudo_require_reason", "true")
        }
        fn baseline(path: &std::path::Path) -> std::io::Result<()> {
            super::baseline::update_baseline_flag(path, true)
        }
        fn devcontainer(path: &std::path::Path) -> std::io::Result<()> {
            super::devcontainer::update_policy_key(path, "devcontainer_guard_enabled", "true")
        }
        fn ssh(path: &std::path::Path) -> std::io::Result<()> {
            super::ssh::update_policy_guard_key(path, true)
        }
        fn iac_guard(path: &std::path::Path) -> std::io::Result<()> {
            super::iac::update_policy_key(path, "iac_guard_enabled", "true")
        }
        fn iac_plan(path: &std::path::Path) -> std::io::Result<()> {
            super::iac::update_policy_key(path, "iac_require_plan_before_apply", "true")
        }
        fn doctor(path: &std::path::Path) -> std::io::Result<()> {
            let root = path.parent().and_then(std::path::Path::parent).unwrap();
            super::doctor::create_policy_contained(root, path, "replacement\n")
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))
        }

        let surfaces: &[(&str, Mutator)] = &[
            ("context guard", context),
            ("env guard", env),
            ("exec guard", exec),
            ("hooks guard", hooks),
            ("sudo guard", sudo_guard),
            ("sudo require-reason", sudo_reason),
            ("baseline learn", baseline),
            ("devcontainer guard", devcontainer),
            ("ssh guard", ssh),
            ("iac guard", iac_guard),
            ("iac require-plan", iac_plan),
            ("doctor policy create", doctor),
        ];
        let denied = b"task_gate:\n  mode: enforce\n  effects_denied_for_untrusted_sources: [policy_change]\n";

        for (surface, mutate) in surfaces {
            let root = tempfile::tempdir().unwrap();
            std::fs::create_dir(root.path().join(".git")).unwrap();
            let config = root.path().join(".tirith");
            std::fs::create_dir(&config).unwrap();
            let path = config.join("policy.yaml");
            std::fs::write(&path, denied).unwrap();
            let error = mutate(&path).unwrap_err();
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied,
                "{surface}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), denied, "{surface}");
        }
    }

    #[test]
    fn context_label_writer_is_byte_identical_on_real_writer_denial() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join(".tirith");
        std::fs::create_dir(&config).unwrap();
        let path = config.join("context-labels.yaml");
        let original = b"aws:prod: critical\n";
        std::fs::write(&path, original).unwrap();
        let mut policy = inert();
        policy.task_gate.mode = tirith_core::web3_policy::TaskGateMode::Enforce;
        policy
            .task_gate
            .effects_denied_for_untrusted_sources
            .insert(tirith_core::effects::CommandEffectKind::PolicyChange);

        super::write_context_labels_permitted(&path, &[("gcp:prod", "production")], &policy)
            .expect_err("the real retained label writer must be denied");

        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn retained_publisher_does_not_run_after_policy_change_deny() {
        let mut policy = inert();
        policy.task_gate.mode = tirith_core::web3_policy::TaskGateMode::Enforce;
        policy
            .task_gate
            .effects_denied_for_untrusted_sources
            .insert(tirith_core::effects::CommandEffectKind::PolicyChange);

        let retained_root = tempfile::tempdir().unwrap();
        let retained_path = retained_root.path().join("policy.yaml");
        std::fs::write(&retained_path, b"original\n").unwrap();
        let destination = tirith_core::util::ContainedAtomicFile::prepare(
            retained_root.path(),
            &retained_path,
            false,
        )
        .unwrap();
        let error = super::write_prepared_config_file_permitted(
            retained_root.path(),
            &retained_path,
            destination,
            b"changed\n",
            true,
            &policy,
            true,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read(&retained_path).unwrap(), b"original\n");
    }

    #[test]
    fn denied_parent_creating_write_leaves_namespace_absent() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join(".tirith");
        let path = config.join("policy.yaml");
        let mut policy = inert();
        policy.task_gate.mode = tirith_core::web3_policy::TaskGateMode::Enforce;
        policy
            .task_gate
            .effects_denied_for_untrusted_sources
            .insert(tirith_core::effects::CommandEffectKind::PolicyChange);

        let error = super::write_config_file_permitted_with_parent_creation(
            root.path(),
            &path,
            b"changed\n",
            true,
            &policy,
            true,
            true,
        )
        .expect_err("policy deny must happen before parent creation");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!config.exists());
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn cli_rejects_distinct_non_utf8_config_destinations() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let root = tempfile::tempdir().unwrap();
        let config = root.path().join(".tirith");
        std::fs::create_dir(&config).unwrap();
        let first = config.join(OsString::from_vec(b"policy-\x80.yaml".to_vec()));
        let second = config.join(OsString::from_vec(b"policy-\x81.yaml".to_vec()));

        assert_ne!(first, second);
        assert_eq!(first.to_string_lossy(), second.to_string_lossy());
        for path in [&first, &second] {
            let error = super::write_config_file_permitted(
                root.path(),
                path,
                b"safe: true\n",
                true,
                &inert(),
                true,
            )
            .expect_err("non-UTF-8 destinations must be rejected before authorization");
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(!path.exists());
        }
    }

    #[test]
    fn contained_atomic_write_preserves_no_clobber_semantics() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join(".tirith");
        std::fs::create_dir(&config).unwrap();
        let path = config.join("commands.yaml");

        super::write_config_file_permitted(
            root.path(),
            &path,
            b"original\n",
            false,
            &inert(),
            false,
        )
        .expect("no-clobber create must succeed when absent");
        let error = super::write_config_file_permitted(
            root.path(),
            &path,
            b"replacement\n",
            false,
            &inert(),
            false,
        )
        .expect_err("no-clobber publish must refuse an existing destination");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"original\n");

        super::write_config_file_permitted(
            root.path(),
            &path,
            b"replacement\n",
            true,
            &inert(),
            false,
        )
        .expect("overwrite still atomically replaces the destination");
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement\n");
        assert_eq!(
            std::fs::read_dir(&config).unwrap().count(),
            1,
            "successful and refused publications must leave no temp entries"
        );
    }

    #[cfg(unix)]
    #[test]
    fn contained_atomic_write_rejects_final_symlink() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let config = root.path().join(".tirith");
        std::fs::create_dir(&config).unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), b"outside").unwrap();
        let path = config.join("policy.yaml");
        symlink(outside.path(), &path).unwrap();

        super::write_config_file_permitted(root.path(), &path, b"attacker", true, &inert(), true)
            .expect_err("a repo-contained writer must refuse a final symlink");
        assert_eq!(std::fs::read(outside.path()).unwrap(), b"outside");
        assert!(std::fs::symlink_metadata(path)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn contained_atomic_write_rejects_symlinked_parent() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let config = root.path().join(".tirith");
        symlink(outside.path(), &config).unwrap();
        let path = config.join("policy.yaml");

        let err = super::write_config_file_permitted(
            root.path(),
            &path,
            b"attacker",
            true,
            &inert(),
            true,
        )
        .expect_err("a repo-contained writer must refuse an escaping parent link");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!outside.path().join("policy.yaml").exists());
    }

    #[cfg(unix)]
    #[test]
    fn contained_atomic_write_parent_swap_cannot_redirect_publication() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let config = root.path().join(".tirith");
        let held_config = root.path().join(".tirith-held");
        std::fs::create_dir(&config).unwrap();
        let path = config.join("policy.yaml");

        super::write_file_atomic_contained_with_hook(
            root.path(),
            &path,
            b"safe: true\n",
            true,
            || {
                // Swap the checked pathname only after its parent descriptor is
                // retained, deterministically exercising the old check/use gap.
                std::fs::rename(&config, &held_config)?;
                symlink(outside.path(), &config)?;
                Ok(())
            },
        )
        .expect("publication through the retained parent must remain safe");

        assert!(
            !outside.path().join("policy.yaml").exists(),
            "the replacement symlink target must remain untouched"
        );
        assert_eq!(
            std::fs::read(held_config.join("policy.yaml")).unwrap(),
            b"safe: true\n",
            "publication must stay bound to the directory opened beneath root"
        );
        assert!(
            std::fs::symlink_metadata(&config)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the replacement parent symlink must not be followed or clobbered"
        );
    }
}

/// Write `contents` to `path` atomically: a sibling temp file is written,
/// flushed, fsync'd, then renamed over `path`, so a reader (or a crash
/// mid-write) sees either the old or the complete new contents. Used by the
/// operator-facing config writers, NOT regenerable caches.
///
/// Durability (R12 #B): `sync_all()` BEFORE the rename, parent dir fsync AFTER.
///
/// Symlink destinations (R17 #4): `persist` would clobber a symlinked config, so
/// a symlink to an EXISTING target is canonicalized and written THROUGH (temp
/// file in the resolved target's dir to keep the rename atomic); a non-symlink /
/// dangling / unresolvable target falls back to renaming onto `path`.
///
/// `overwrite` (R13 #K): `true` → `persist` (replaces `dest`); `false` →
/// `persist_noclobber` (fails `AlreadyExists`), closing the TOCTOU between an
/// `init` caller's `exists()` check and this publish.
pub(crate) fn write_file_atomic(
    path: &std::path::Path,
    contents: &[u8],
    overwrite: bool,
) -> std::io::Result<()> {
    // Resolve a symlinked destination so we write THROUGH the link;
    // non-symlinks resolve to themselves.
    let dest = resolve_atomic_dest(path);
    write_file_atomic_to_dest(&dest, contents, overwrite)
}

fn consume_config_write_authorization_with<F>(
    pending: tirith_core::task_boundary::PendingBoundaryAuthorization<
        tirith_core::task_boundary::ConfigWriteBoundary,
    >,
    operation: &tirith_core::task_boundary::BoundaryOperation<'_>,
    consume: F,
) -> Result<
    tirith_core::task_boundary::TaskBoundaryPermit<tirith_core::task_boundary::ConfigWriteBoundary>,
    tirith_core::task_boundary::BoundaryAuthorizationError,
>
where
    F: FnOnce(
        tirith_core::task_boundary::PendingBoundaryAuthorization<
            tirith_core::task_boundary::ConfigWriteBoundary,
        >,
    ) -> Result<
        tirith_core::task_boundary::TaskBoundaryPermit<
            tirith_core::task_boundary::ConfigWriteBoundary,
        >,
        tirith_core::task_boundary::BoundaryAuthorizationError,
    >,
{
    if !pending.binds_operation(operation) {
        return Err(tirith_core::task_boundary::BoundaryAuthorizationError::EnvelopeMismatch);
    }
    consume(pending)
}

/// C12: publish a TIRITH-OWNED configuration file through the task gate and a
/// single-use [`tirith_core::config_write::ConfigWritePermit`].
///
/// The irreversible step is the final rename inside `commit`, so the gate runs
/// before the permit is even issued and the permit re-checks its bindings again
/// immediately before that rename. `policy_change` is the caller's own statement
/// that the mutation changes effective policy, trust, or approval configuration;
/// only the caller knows that semantic role, so it is passed as a boundary
/// effect rather than guessed from the path.
///
/// Honest scope: this covers files Tirith itself writes. A shell redirection
/// into an agent config, or any other host write that does not go through
/// Tirith, is not intercepted here.
///
/// This is the ONLY contained publisher the CLI has. There used to be an
/// ungated `write_file_atomic_contained` beside it, and every site that still
/// called it (the MCP lock, the MCP policy scaffold, the gateway's descriptor
/// re-baseline) was a Tirith-owned config write the gate silently did not cover.
/// Deleting it, rather than documenting it, is what makes that class of omission
/// a compile error instead of an audit finding.
#[cfg(test)]
pub(crate) fn write_config_file_permitted(
    root: &std::path::Path,
    path: &std::path::Path,
    contents: &[u8],
    overwrite: bool,
    policy: &tirith_core::policy::Policy,
    policy_change: bool,
) -> std::io::Result<()> {
    write_config_file_permitted_with_parent_creation(
        root,
        path,
        contents,
        overwrite,
        policy,
        policy_change,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_config_file_permitted_with_parent_creation(
    root: &std::path::Path,
    path: &std::path::Path,
    contents: &[u8],
    overwrite: bool,
    policy: &tirith_core::policy::Policy,
    policy_change: bool,
    create_parent: bool,
) -> std::io::Result<()> {
    // Make the pure policy decision before `create_parent` can materialize a
    // directory. Replay is deliberately not consumed until the retained
    // filesystem capability exists and has reconstructed the same operation.
    preflight_config_write_authorization(root, path, overwrite, policy, policy_change)?;
    let permit = tirith_core::config_write::ConfigWritePermit::prepare_owned(
        root,
        path,
        contents,
        overwrite,
        &policy.enforcement_projection_hash(),
        policy_change,
        create_parent,
    )?;
    commit_config_write_permit(permit, contents, policy)
}

/// Make the complete pure task-gate decision before a caller creates a parent,
/// opens/creates a mutation lock, or performs any other filesystem side effect.
/// The payload is intentionally empty: content is not an effect-classification
/// input, and the exact bytes/capability are authorized again after the caller
/// has safely read and rendered them. Provenance-required policy still fails
/// closed here because locally-derived ConfigWrite has no trusted v2 provider.
pub(crate) fn preflight_config_write_authorization(
    root: &std::path::Path,
    path: &std::path::Path,
    overwrite: bool,
    policy: &tirith_core::policy::Policy,
    policy_change: bool,
) -> std::io::Result<()> {
    let _pending =
        prepare_config_write_authorization(root, path, &[], overwrite, policy, policy_change)?;
    Ok(())
}

/// Preflight before a potentially parent-creating retained bind. RMW callers
/// keep the returned capability through read, render, exact authorization, and
/// publication.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_config_destination_permitted(
    root: &std::path::Path,
    path: &std::path::Path,
    overwrite: bool,
    policy: &tirith_core::policy::Policy,
    policy_change: bool,
    create_parent: bool,
) -> std::io::Result<tirith_core::util::ContainedAtomicFile> {
    preflight_config_write_authorization(root, path, overwrite, policy, policy_change)?;
    let destination = tirith_core::util::ContainedAtomicFile::prepare(root, path, create_parent)?;
    destination.lock_parent_for_mutation()?;
    Ok(destination)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_prepared_config_file_permitted(
    root: &std::path::Path,
    path: &std::path::Path,
    destination: tirith_core::util::ContainedAtomicFile,
    contents: &[u8],
    overwrite: bool,
    policy: &tirith_core::policy::Policy,
    policy_change: bool,
) -> std::io::Result<()> {
    let permit = tirith_core::config_write::ConfigWritePermit::from_prepared(
        destination,
        root,
        path,
        contents,
        overwrite,
        &policy.enforcement_projection_hash(),
        policy_change,
    )?;
    commit_config_write_permit(permit, contents, policy)
}

fn commit_config_write_permit(
    permit: tirith_core::config_write::ConfigWritePermit,
    contents: &[u8],
    policy: &tirith_core::policy::Policy,
) -> std::io::Result<()> {
    let envelope = permit.operation_envelope();
    let operation = tirith_core::task_boundary::BoundaryOperation {
        boundary: tirith_core::task_boundary::OwnedBoundary::ConfigWrite,
        envelope: &envelope,
        adapter: tirith_core::task::IngressAdapter::Unattributed,
        boundary_effects: permit.boundary_effects(),
    };
    let pending_authorization =
        prepare_config_write_authorization_from_operation(&operation, policy)?;
    commit_config_write_permit_with_operation(permit, contents, pending_authorization, &operation)
}

#[allow(clippy::too_many_arguments)]
fn prepare_config_write_authorization(
    root: &std::path::Path,
    path: &std::path::Path,
    contents: &[u8],
    overwrite: bool,
    policy: &tirith_core::policy::Policy,
    policy_change: bool,
) -> std::io::Result<
    tirith_core::task_boundary::PendingBoundaryAuthorization<
        tirith_core::task_boundary::ConfigWriteBoundary,
    >,
> {
    let envelope = tirith_core::config_write::ConfigWritePermit::operation_envelope_for(
        root,
        path,
        contents,
        overwrite,
        &policy.enforcement_projection_hash(),
        policy_change,
    )?;
    let operation = tirith_core::task_boundary::BoundaryOperation {
        boundary: tirith_core::task_boundary::OwnedBoundary::ConfigWrite,
        envelope: &envelope,
        adapter: tirith_core::task::IngressAdapter::Unattributed,
        boundary_effects: tirith_core::config_write::ConfigWritePermit::boundary_effects_for(
            policy_change,
        ),
    };
    prepare_config_write_authorization_from_operation(&operation, policy)
}

fn prepare_config_write_authorization_from_operation(
    operation: &tirith_core::task_boundary::BoundaryOperation<'_>,
    policy: &tirith_core::policy::Policy,
) -> std::io::Result<
    tirith_core::task_boundary::PendingBoundaryAuthorization<
        tirith_core::task_boundary::ConfigWriteBoundary,
    >,
> {
    tirith_core::task_boundary::prepare_locally_derived_boundary_authorization::<
        tirith_core::task_boundary::ConfigWriteBoundary,
    >(
        operation,
        &policy.task_gate,
        &tirith_core::task_analysis::TaskAnalysisContext::default(),
    )
    .map_err(config_write_gate_error)
}

fn commit_config_write_permit_with_operation(
    permit: tirith_core::config_write::ConfigWritePermit,
    contents: &[u8],
    pending_authorization: tirith_core::task_boundary::PendingBoundaryAuthorization<
        tirith_core::task_boundary::ConfigWriteBoundary,
    >,
    operation: &tirith_core::task_boundary::BoundaryOperation<'_>,
) -> std::io::Result<()> {
    if !permit.binds_publication(contents, operation) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "configuration write no longer matches its exact authorization",
        ));
    }
    let boundary_permit =
        consume_config_write_authorization_with(pending_authorization, operation, |pending| {
            pending.consume_default(chrono::Utc::now())
        })
        .map_err(config_write_gate_error)?;
    permit
        .commit_authorized(contents, boundary_permit, operation)
        .map_err(std::io::Error::from)
}

fn config_write_gate_error(
    error: tirith_core::task_boundary::BoundaryAuthorizationError,
) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!("task gate refused this configuration write: {error}"),
    )
}

/// Retain one labels-file capability across read, render, authorization, and
/// publication. Multiple labels are committed atomically (SSH alias + resolved
/// hostname therefore cannot partially succeed).
pub(crate) fn write_context_labels_permitted(
    path: &std::path::Path,
    labels: &[(&str, &str)],
    policy: &tirith_core::policy::Policy,
) -> std::io::Result<()> {
    const LABELS_FILE_READ_CAP: u64 = 1024 * 1024;
    let root = path
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "label path must be <root>/<dir>/<file>",
            )
        })?;
    let destination = prepare_config_destination_permitted(root, path, true, policy, true, true)?;
    let mut existing = std::collections::BTreeMap::<String, String>::new();
    match destination.read_capped(LABELS_FILE_READ_CAP) {
        Ok(bytes) => {
            let content = String::from_utf8(bytes).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "labels file is not valid UTF-8",
                )
            })?;
            if !content.trim().is_empty() {
                existing = serde_yaml::from_str(&content).map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("labels file is not a string-to-string YAML mapping: {error}"),
                    )
                })?;
            }
        }
        Err(tirith_core::util::OpenRegularError::NotFound) => {}
        Err(error) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("cannot read existing labels file: {error:?}"),
            ));
        }
    }
    for (key, value) in labels {
        existing.insert((*key).to_string(), (*value).to_string());
    }
    let yaml = serde_yaml::to_string(&existing).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("cannot serialize labels file: {error}"),
        )
    })?;
    write_prepared_config_file_permitted(
        root,
        path,
        destination,
        yaml.as_bytes(),
        true,
        policy,
        true,
    )
}

/// The contained publication [`write_config_file_permitted`] performs, with a
/// hook between binding the parent and publishing through it.
///
/// Test-only, and deliberately so: the hook exists to open the check/use gap on
/// purpose, and a production caller reaching this would be reaching a contained
/// write that no task gate saw. It calls the same
/// [`tirith_core::util::ContainedAtomicFile`] pair the permit calls, so the
/// containment properties it pins are the permit's own.
#[cfg(test)]
fn write_file_atomic_contained_with_hook(
    root: &std::path::Path,
    path: &std::path::Path,
    contents: &[u8],
    overwrite: bool,
    after_parent_bound: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<()> {
    // Parent creation remains the caller's responsibility, preserving the
    // previous NotFound behavior. The retained capability now spans validation,
    // tempfile creation, and atomic publication.
    let destination = tirith_core::util::ContainedAtomicFile::prepare(root, path, false)?;
    after_parent_bound()?;
    destination.write_atomic(contents, overwrite)
}

fn write_file_atomic_to_dest(
    dest: &std::path::Path,
    contents: &[u8],
    overwrite: bool,
) -> std::io::Result<()> {
    let dir = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(std::path::PathBuf::from)
        // Bare filename: keep the temp file in cwd so the rename stays on the
        // same filesystem.
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let mut tmp = tempfile::NamedTempFile::new_in(&dir)?;
    tmp.write_all(contents)?;
    // sync_all() forces data + metadata to disk BEFORE the rename publishes it.
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    if overwrite {
        tmp.persist(dest).map_err(|e| e.error)?;
    } else {
        tmp.persist_noclobber(dest).map_err(|e| e.error)?;
    }
    // fsync the parent so the new name→inode entry survives a crash. persist
    // already succeeded, so a dir-fsync failure is LOGGED, not propagated
    // (R13 #5). No-op on non-Unix.
    tirith_core::util::fsync_parent_dir_logged(dest, "atomic file write");
    Ok(())
}

/// Resolve the effective rename target for [`write_file_atomic`]: a symlink to
/// an existing target → its canonicalized target (write THROUGH the link);
/// otherwise `path` unchanged.
pub(crate) fn resolve_atomic_dest(path: &std::path::Path) -> std::path::PathBuf {
    tirith_core::util::resolve_symlink_target(path)
}

/// Reconstruct a shell command STRING from already-split argv, PRESERVING word
/// boundaries (R13b). Shell-significant args are single-quoted, safe args emitted
/// bare. Fed to the engine (`commands check`): a naive `argv.join(" ")` lets a
/// multi-word arg re-split into separate tokens and skew the verdict (e.g.
/// `git commit -m "fix; rm -rf /"` would look like a `;`-separated `rm`).
pub(crate) fn shell_join(argv: &[String]) -> String {
    // A SINGLE arg is already a complete command string (the user quoted the
    // whole command) — return it verbatim; quoting would hide its
    // pipes/URLs/substitutions from the engine. Quote-as-needed only kicks in for
    // MULTIPLE argv elements where word boundaries would otherwise be lost.
    if argv.len() == 1 {
        return argv[0].clone();
    }
    fn needs_quoting(s: &str) -> bool {
        // Bare only for a conservative shell-safe set; anything else is quoted.
        s.is_empty()
            || !s.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(
                        b,
                        b'-' | b'_' | b'.' | b'/' | b':' | b'=' | b'@' | b',' | b'+' | b'%'
                    )
            })
    }
    argv.iter()
        .map(|a| {
            if needs_quoting(a) {
                format!("'{}'", a.replace('\'', "'\\''"))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Reconstruct a command for shell-string analysis without inventing operators
/// from argv data. A single part is already a complete command and remains
/// verbatim. Multi-part reconstruction is currently proven only for POSIX;
/// other grammars must be supplied as one preformed command string.
pub(crate) fn reconstruct_shell_command(
    argv: &[String],
    shell: tirith_core::tokenize::ShellType,
) -> Result<String, &'static str> {
    if argv.len() <= 1 {
        return Ok(argv.first().cloned().unwrap_or_default());
    }
    match shell {
        tirith_core::tokenize::ShellType::Posix => Ok(shell_join(argv)),
        tirith_core::tokenize::ShellType::Fish
        | tirith_core::tokenize::ShellType::PowerShell
        | tirith_core::tokenize::ShellType::Cmd => Err(
            "multi-argument Fish/PowerShell/Cmd input cannot be reconstructed without changing shell semantics; pass one quoted command string after --",
        ),
    }
}

/// Closest candidate by Levenshtein distance, or `None` if none is within
/// `max_distance`.
pub fn suggest_closest<'a>(
    query: &str,
    candidates: &[&'a str],
    max_distance: usize,
) -> Option<&'a str> {
    candidates
        .iter()
        .map(|c| (*c, tirith_core::util::levenshtein(query, c)))
        .filter(|(_, d)| *d <= max_distance)
        .min_by_key(|(_, d)| *d)
        .map(|(c, _)| c)
}

/// Prompt for confirmation. `true` only if `--yes`, or BOTH stdin and stderr
/// are TTYs and the user types y/yes. `false` in non-interactive contexts
/// without `--yes`, so destructive operations are never silently approved.
///
/// repo-0398: checking only the prompt stream (stderr) lets a piped stdin
/// (`yes | tirith <destructive>`) answer the prompt — stderr is still the
/// user's terminal, but the "human" typing `y` is attacker-controlled input.
/// Requiring stdin to be a terminal too, as onboard's `is_tty_pair` already
/// does, closes that approval bypass.
pub fn confirm(prompt: &str, yes: bool) -> bool {
    if yes {
        return true;
    }
    if !is_terminal::is_terminal(std::io::stderr()) || !is_terminal::is_terminal(std::io::stdin()) {
        eprintln!("tirith: skipping prompt (not a TTY — use --yes to auto-approve)");
        return false;
    }
    eprint!("{prompt} [y/N] ");
    // Best-effort flush; read_line still works if it fails.
    let _ = std::io::stderr().flush();
    let mut input = String::new();
    match std::io::stdin().read_line(&mut input) {
        Ok(_) => matches!(input.trim(), "y" | "Y" | "yes" | "Yes"),
        Err(e) => {
            eprintln!("tirith: could not read confirmation input: {e}");
            false
        }
    }
}

pub mod agent;
pub mod ai;
pub mod aliases;
/// The `tirith attest` namespace (C18): point-in-time build and deployment
/// receipts. Distinct from the nested `tirith pkg attest`, which binds PyPI
/// publish attestations and is untouched by this surface.
pub mod attest;
pub mod audit;
pub mod baseline;
#[cfg(unix)]
pub mod bash_capability;
pub mod browser;
pub mod browser_audit;
pub mod browser_host;
pub mod canary;
/// Consumer-facing capsule launch surface (Stack E, unit E5): the single seam
/// `runner.rs`, `temp_run.rs`, the package-firewall install, and the gateway
/// upstream spawn route through. Selects the host backend (Landlock/seccomp,
/// Seatbelt, AppContainer, or NoOp), probes deliverable coverage, fails closed for
/// enforcing surfaces under degraded coverage, and offers both a run-to-completion
/// and a piped-stdio launch on top of one fail-closed gate.
pub mod capsule;
pub mod capsule_child;
pub mod capsule_proxy;
/// The `tirith capsule run --preset untrusted-project` surface (C14): copies an
/// untrusted project into a held ephemeral directory, launches the operator's
/// exact argv inside the fail-closed capsule seam, and emits one signed,
/// content-addressed receipt. Refuses before any copy or spawn on every host
/// that cannot deliver the preset's controls; there is no degraded fallback.
pub mod capsule_run;
/// Windows capsule executor (Stack E, unit E4): the `windows`-crate Win32 half that
/// applies a `tirith_core::capsule::windows::WindowsLaunchPlan` (AppContainer +
/// ACLs + Job Object + suspended `CreateProcessW`). `cfg(windows)`-gated so the
/// `windows` crate is only required on the Windows target; the portable planning +
/// honesty logic it consumes lives in `tirith-core` and is tested on every platform.
#[cfg(windows)]
pub mod capsule_windows;
pub mod check;
pub mod checkpoint;
pub mod clipboard;
pub mod codespaces;
pub mod command_card;
pub mod commands;
pub mod completions;
pub mod context;
pub mod daemon;
pub mod dashboard;
pub mod devcontainer;
pub mod diff;
pub mod doctor;
pub mod ecosystem;
pub mod env_guard;
pub mod exec;
pub mod explain;
pub mod fix;
pub mod gateway;
pub mod hook_event;
pub mod hooks;
pub mod hygiene;
pub mod iac;
pub mod incident;
pub mod init;
pub mod install;
pub mod intent;
pub mod lab;
pub mod lab_artifacts;
pub mod last_trigger;
pub mod license_cmd;
pub mod logs;
pub mod lsp;
pub mod manpage;
pub mod mcp;
pub mod mcp_server;
/// `tirith pkg attest-npm` (C17): resolve the operator's own npm through the
/// trusted-child mechanism, discover its exact version, and run ONLY the argv a
/// closed, fixture-backed contract table authorizes for that version, binding
/// the answer to the project's `package-lock.json` digest, its installed
/// `node_modules` inventory, and its registry hosts. Attestation evidence only:
/// a clean receipt means npm's signature check passed, never that the package
/// code is benign. The spawn / rendering half of
/// [`tirith_core::provenance::npm`].
pub mod npm_integrity;
pub mod onboard;
pub mod output_guard;
pub mod package;
pub(crate) mod package_approval_authority;
pub(crate) mod package_approval_authority_native;
pub mod paste;
pub mod path;
pub mod pending;
pub mod persistence;
/// The package-firewall CLI surface (PR D7): `tirith pkg install | verify-env |
/// approve | receipt`. Drives the D1-D6 resolve -> firewall -> re-bind -> contained
/// install -> receipt pipeline, binding an operator approval to an
/// `InstallPlanDigest`. Distinct from `tirith install` (analysis-only).
pub mod pkg;
/// Contained install-from-digest for the package firewall (PR D4, CLI half): write
/// the re-bound plan's `approved.txt`, build the pinned `python -m pip install`
/// argv, and run it through the fail-closed capsule launcher (never the uncontained
/// `ProcessInstallRunner`).
pub mod pkg_install;
pub mod policy;
pub mod preview;
pub mod prompt_status;
pub mod provenance;
/// `tirith pkg attest` (PR F3, the `sigstore-attestations` spike): fetch a wheel's
/// PyPI publish provenance from the Integrity API, bind the attestation's subject
/// digest to the wheel's quarantined SHA-256, optionally verify the Sigstore bundle
/// (feature-gated; off on the workspace MSRV), and check the publisher identity
/// against policy. Provenance evidence only: never an auto-allow, never blocks. The
/// network / `sigstore-*` half the plan keeps out of `tirith-core`.
pub mod pypi_integrity;
pub mod receipt;
pub mod rule;
pub mod scan;
pub mod score;
pub mod secret;
pub mod selfupdate;
pub mod share;
pub mod ssh;
pub mod status;
pub mod sudo;
pub mod taint;
pub mod task;
pub(crate) mod task_receipt_keys;
pub mod temp_run;
pub mod threatdb_cmd;
pub mod trust;
pub mod view;
pub mod visual_audit;
pub mod warnings;
pub mod why;
pub mod yaml;

#[cfg(unix)]
pub mod fetch;
#[cfg(unix)]
pub mod run;
pub mod setup;

#[cfg(test)]
pub(crate) mod test_harness;

#[cfg(any(test, windows))]
fn trim_wrapping_quotes(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

#[cfg(any(test, windows))]
fn parse_shim_target(contents: &str) -> Option<std::path::PathBuf> {
    contents.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        if !key.trim().eq_ignore_ascii_case("path") {
            return None;
        }
        let value = trim_wrapping_quotes(value.trim());
        if value.is_empty() {
            return None;
        }
        Some(std::path::PathBuf::from(value))
    })
}

#[cfg(any(test, windows))]
fn resolve_shim_target(path: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut sidecar = path.to_path_buf();
    sidecar.set_extension("shim");

    let contents = std::fs::read_to_string(&sidecar).ok()?;
    let target = parse_shim_target(&contents)?;
    let target = if target.is_relative() {
        sidecar.parent()?.join(target)
    } else {
        target
    };

    target.canonicalize().ok().or(Some(target))
}

/// Map (`OS`, `ARCH`) to the platform-specific npm package name under the
/// `@sheeki03/` scope. `None` on unsupported Unix targets. Mirrors
/// `npm/tirith/bin/tirith` exactly.
#[cfg(unix)]
fn npm_platform_package() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("tirith-linux-x64"),
        ("linux", "aarch64") => Some("tirith-linux-arm64"),
        ("macos", "x86_64") => Some("tirith-darwin-x64"),
        ("macos", "aarch64") => Some("tirith-darwin-arm64"),
        _ => None,
    }
}

/// If `path` is the official tirith npm wrapper
/// (`…/node_modules/tirith/bin/tirith`), resolve to the platform-package native
/// binary. The wrapper `execFileSync`s the native binary, so naive
/// `canonicalize()` makes them look like different installs and triggers a
/// false-positive shadow warning (issue #105).
#[cfg(unix)]
fn resolve_npm_wrapper_target(path: &std::path::Path) -> Option<std::path::PathBuf> {
    use std::path::Component;

    // Canonicalize FIRST — the PATH entry is typically a symlink, and the layout
    // check must run on the resolved target.
    let canonical = path.canonicalize().ok()?;

    // The last four components must be exactly `node_modules`, `tirith`, `bin`,
    // `tirith`; anything else falls through to the existing behavior.
    let components: Vec<Component> = canonical.components().collect();
    if components.len() < 4 {
        return None;
    }
    let tail = &components[components.len() - 4..];
    let expected = [
        Component::Normal("node_modules".as_ref()),
        Component::Normal("tirith".as_ref()),
        Component::Normal("bin".as_ref()),
        Component::Normal("tirith".as_ref()),
    ];
    if tail != expected {
        return None;
    }

    // `node_modules` is three parents up from `…/tirith/bin/tirith`.
    let node_modules = canonical.ancestors().nth(3)?;

    let platform = npm_platform_package()?;
    let native = node_modules
        .join("@sheeki03")
        .join(platform)
        .join("bin")
        .join("tirith");

    if !native.is_file() {
        return None;
    }
    native.canonicalize().ok()
}

fn resolve_effective_tirith_target(path: &std::path::Path) -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    if let Some(target) = resolve_shim_target(path) {
        return Some(target);
    }

    #[cfg(unix)]
    if let Some(target) = resolve_npm_wrapper_target(path) {
        return Some(target);
    }

    path.canonicalize().ok()
}

pub fn tirith_path_lookup_command() -> &'static str {
    #[cfg(unix)]
    {
        "which -a tirith"
    }
    #[cfg(not(unix))]
    {
        "where.exe tirith"
    }
}

/// Resolve all `tirith` executables on PATH without executing a PATH-selected
/// shell or lookup utility.
pub fn resolve_tirith_on_path() -> Vec<std::path::PathBuf> {
    let Some(path) = std::env::var_os("PATH") else {
        return Vec::new();
    };
    resolve_tirith_on_path_from(&path)
}

fn resolve_tirith_on_path_from(path: &std::ffi::OsStr) -> Vec<std::path::PathBuf> {
    tirith_core::path_audit::which_all_os("tirith", path)
}

/// Find `tirith` executables on PATH that aren't the current binary, deduped by
/// logical target path so duplicate PATH entries and shim aliases don't repeat.
pub fn find_shadow_binaries() -> Vec<String> {
    let our_canonical = std::env::current_exe()
        .ok()
        .and_then(|p| resolve_effective_tirith_target(&p));

    let mut seen = std::collections::HashSet::new();
    let mut shadows = Vec::new();

    for path in resolve_tirith_on_path() {
        let canonical = resolve_effective_tirith_target(&path);
        // Skip if it resolves to our own binary.
        if let (Some(ours), Some(ref theirs)) = (&our_canonical, &canonical) {
            if ours == theirs {
                continue;
            }
        }
        // Dedup by canonical path (display path for unresolvable entries).
        let key = canonical
            .map(|c| c.display().to_string())
            .unwrap_or_else(|| path.display().to_string());
        if seen.insert(key) {
            shadows.push(path.display().to_string());
        }
    }
    shadows
}

/// Process-global quiet flag, set once from the root `--quiet` / `TIRITH_QUIET`.
/// Low-value advisory lines route through [`note`]; security notices, verdicts,
/// errors, and JSON do NOT, so quiet never hides anything that matters.
static QUIET: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Whether `TIRITH_QUIET`'s value is truthy. Pure helper over the raw env value so
/// the `1`/`true` (case-insensitive) parsing is unit-testable without process globals.
fn quiet_from_env(val: Option<&str>) -> bool {
    matches!(val, Some(v) if v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Set once in `main()` right after clap parse. `--quiet` OR `TIRITH_QUIET=1/true`.
pub fn init_quiet(flag: bool) {
    let env = quiet_from_env(std::env::var("TIRITH_QUIET").ok().as_deref());
    let _ = QUIET.set(flag || env);
}

/// True when LOW-VALUE advisory output should be suppressed. Defaults to `false`
/// (fail-safe: if `init_quiet` somehow never ran, we never accidentally hide output).
pub fn is_quiet() -> bool {
    *QUIET.get().unwrap_or(&false)
}

/// Print a LOW-VALUE advisory line to stderr unless `--quiet`. Use for clean
/// "no issues" lines, tips, shadow/session footers, the onboard hint — NEVER for
/// errors, verdicts, or security notices (degraded protection / repo-policy
/// neutralization), which must always be visible.
pub fn note(msg: impl std::fmt::Display) {
    if !is_quiet() {
        eprintln!("{msg}");
    }
}

/// Read at most `max` bytes from stdin — the shared cap used by `check`/`paste`
/// when consuming piped input. Returns the raw bytes; callers decode lossily.
///
/// FAILS CLOSED on over-limit input: it reads ONE byte past `max` so an oversized
/// stream is DETECTABLE, then returns an error rather than silently truncating.
/// Silent truncation is unsafe here — a command analyzed only up to `max` could
/// drop a dangerous tail (e.g. `... | sh` after a 1 MiB prefix) and read as
/// benign. Mirrors `paste`'s explicit over-limit rejection.
pub fn read_stdin_capped(max: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut buf = Vec::new();
    std::io::stdin().take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("input exceeds the {max}-byte limit"),
        ));
    }
    Ok(buf)
}

/// Gate decision for [`warn_repo_policy_neutralized`]: emit the once-per-session notice
/// only for a REPO-scoped policy (the only untrusted scope) that actually had weakening
/// fields dropped, and only when this session hasn't been warned yet (marker absent).
/// Pure so the matrix is unit-testable without `state_dir()` I/O or process globals.
fn should_warn_neutralized(
    scope: tirith_core::policy::PolicyScope,
    neutralized_fields: &[&str],
    marker_exists: bool,
) -> bool {
    scope == tirith_core::policy::PolicyScope::Repo
        && !neutralized_fields.is_empty()
        && !marker_exists
}

fn invalid_injection_seed_message(
    context: &str,
    diagnostic: tirith_core::rules::prompt_injection::InvalidSeedDiagnostic,
) -> String {
    format!(
        "{context}: warning: injection_seeds_custom[{}] was rejected ({})",
        diagnostic.index,
        diagnostic.category.as_str()
    )
}

/// Surface already-categorical custom-seed failures through one DLP-aware,
/// single-line, invocation-bounded stderr envelope. Neither this API nor the
/// diagnostic type accepts the raw regex/error text, so callers cannot
/// accidentally echo an attacker-controlled policy value.
pub fn warn_invalid_injection_seed_diagnostics(
    context: &str,
    diagnostics: &[tirith_core::rules::prompt_injection::InvalidSeedDiagnostic],
    policy: &tirith_core::policy::Policy,
) {
    let compiled =
        tirith_core::redact::CompiledCustomPatterns::new_silent(&policy.dlp_custom_patterns);
    let mut output = tirith_core::verdict::BoundedTextBuilder::new();
    for &diagnostic in diagnostics {
        let message = invalid_injection_seed_message(context, diagnostic);
        let message = tirith_core::output::sanitize_human_field_with_compiled(&message, &compiled);
        output.push_str(&message);
        output.push_str("\n");
    }
    let output = output.finish();
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(output.as_bytes());
    let _ = stderr.flush();
}

/// Surface invalid `injection_seeds_custom` regexes once to stderr on the
/// paste/check CLI path without rendering either the regex or the compiler's
/// echoing error text.
pub fn warn_bad_injection_seeds(policy: &tirith_core::policy::Policy) {
    let (_seeds, diagnostics) =
        tirith_core::rules::prompt_injection::compile_seeds_with_safe_diagnostics(
            &policy.injection_seeds_custom,
        );
    warn_invalid_injection_seed_diagnostics("tirith", &diagnostics, policy);
}

/// Once per shell SESSION (per policy), tell the operator that a repo-scoped policy
/// had WEAKENING fields neutralized (F9 — a repo may tighten, never weaken). A repo
/// author who sets `allowlist`/`severity_overrides` otherwise gets zero feedback that
/// it was ignored. This is a SECURITY notice: printed unconditionally, NOT routed
/// through `note()`/`--quiet`. `tirith policy effective` always lists the full drop
/// set regardless of this throttle.
pub fn warn_repo_policy_neutralized(policy: &tirith_core::policy::Policy) {
    if policy.scope != tirith_core::policy::PolicyScope::Repo
        || policy.neutralized_fields.is_empty()
    {
        return;
    }
    // Throttle by SESSION id (so it re-warns in every new shell) + policy path —
    // NOT by file mtime, which would suppress the warning across new shells.
    let Some(dir) = tirith_core::policy::state_dir().map(|d| d.join("policy-weakening-warned"))
    else {
        return;
    };
    let session = tirith_core::session::resolve_session_id();
    let path_key = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        policy.path.hash(&mut h);
        format!("{:016x}", h.finish())
    };
    let marker = dir.join(format!("{session}-{path_key}"));
    if !should_warn_neutralized(policy.scope, &policy.neutralized_fields, marker.exists()) {
        return;
    }
    eprintln!(
        "tirith: this repo's .tirith/policy.yaml is tightening-only — the following \
         weakening field(s) were ignored: {}.\n  See the resolved policy with \
         `tirith policy effective`.",
        policy.neutralized_fields.join(", ")
    );
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(&marker, b"");
}

#[cfg(test)]
mod tests {
    use super::{
        invalid_injection_seed_message, parse_shim_target, quiet_from_env, resolve_shim_target,
        resolve_tirith_on_path_from, sanitize_for_human_output, shell_join,
        should_warn_neutralized,
    };
    use std::fs;
    use std::path::PathBuf;
    use tirith_core::policy::PolicyScope;

    #[test]
    fn invalid_custom_seed_message_is_indexed_and_never_accepts_raw_pattern() {
        use tirith_core::rules::prompt_injection::{
            compile_seeds_with_safe_diagnostics, InvalidSeedCategory,
        };

        let pat = "ghp_".to_string() + &"A".repeat(36);
        let secret_pattern = format!("(?P<{pat}>\nX");
        let (_compiled, diagnostics) =
            compile_seeds_with_safe_diagnostics(&["valid seed".into(), secret_pattern.clone()]);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].index, 1);
        assert_eq!(diagnostics[0].category, InvalidSeedCategory::RegexRejected);

        let message = invalid_injection_seed_message("tirith", diagnostics[0]);
        assert!(message.contains("injection_seeds_custom[1]"));
        assert!(message.contains("regex_rejected"));
        assert!(!message.contains(&secret_pattern));
        assert!(!message.contains(&pat));
        assert!(!message.contains('\n'));
    }

    #[cfg(unix)]
    #[test]
    fn tirith_path_lookup_is_in_process_and_preserves_order() {
        use std::os::unix::fs::PermissionsExt as _;

        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        for directory in [first.path(), second.path()] {
            let executable = directory.join("tirith");
            fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
            let mut permissions = fs::metadata(&executable).unwrap().permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(executable, permissions).unwrap();
        }
        let path = std::env::join_paths([first.path(), second.path()]).unwrap();
        let hits = resolve_tirith_on_path_from(&path);
        assert_eq!(
            hits,
            vec![first.path().join("tirith"), second.path().join("tirith")]
        );
    }

    #[test]
    fn shell_join_preserves_argv_boundaries() {
        let q = |v: &[&str]| shell_join(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        // A SINGLE arg is a pre-formed command string — returned VERBATIM.
        assert_eq!(q(&["curl https://x.sh | sh"]), "curl https://x.sh | sh");
        assert_eq!(q(&["$(rm -rf /)"]), "$(rm -rf /)");
        // Shell-safe args round-trip bare.
        assert_eq!(q(&["echo", "hello", "world"]), "echo hello world");
        assert_eq!(
            q(&["curl", "https://example.com/x.sh"]),
            "curl https://example.com/x.sh"
        );
        // An arg with shell-significant bytes is single-quoted so it stays one token.
        assert_eq!(
            q(&["git", "commit", "-m", "fix; rm -rf /"]),
            "git commit -m 'fix; rm -rf /'"
        );
        // Embedded single quotes escaped as '\''; empty arg shown as ''.
        assert_eq!(q(&["echo", "it's"]), "echo 'it'\\''s'");
        assert_eq!(q(&["x", ""]), "x ''");
    }

    #[test]
    fn sanitize_for_human_output_single_line_strips_newlines_and_deception() {
        // allow_multiline=false strips \n and \r entirely (single-line label).
        assert_eq!(sanitize_for_human_output("a\nb\r\nc", false), "abc");
        // The deceptive / invisible set is stripped: bidi override (U+202E),
        // zero-width (U+200B), Hangul filler (U+3164).
        assert_eq!(
            sanitize_for_human_output("a\u{202E}b\u{200B}c\u{3164}d", false),
            "abcd"
        );
        // An embedded ANSI/CSI escape is scrubbed. Callers pass only the untrusted
        // field, never tirith's own styled line, so stripping all ANSI is correct.
        assert_eq!(
            sanitize_for_human_output("a\x1b[31mred\x1b[0mb", false),
            "aredb"
        );
        assert_eq!(sanitize_for_human_output("a\x1b[2Jb", false), "ab");
        assert_eq!(sanitize_for_human_output("a\tb", false), "a\\tb");
    }

    #[test]
    fn sanitize_for_human_output_multiline_keeps_newline_but_reindents() {
        // A forged top-level row cannot be fabricated: the injected newline is
        // kept, but the continuation line is indented so it cannot impersonate a
        // new tirith output row.
        assert_eq!(
            sanitize_for_human_output("real title\nFORGED ROW", true),
            "real title\n  FORGED ROW"
        );
        // CRLF is normalized to \n + indent (the scrub keeps CRLF; the wrapper
        // trims the trailing CR before re-joining).
        assert_eq!(sanitize_for_human_output("a\r\nb", true), "a\n  b");
        // The deceptive set is still stripped in multiline mode.
        assert_eq!(sanitize_for_human_output("a\u{202E}b", true), "ab");
        // An embedded ESC sequence is scrubbed here too.
        assert_eq!(sanitize_for_human_output("x\x1b[2Jy\nz", true), "xy\n  z");
        assert_eq!(sanitize_for_human_output("x\ty", true), "x\\ty");
    }

    #[test]
    fn parse_shim_target_accepts_unquoted_values() {
        let parsed =
            parse_shim_target("path = C:\\Users\\alice\\scoop\\apps\\tirith\\current\\tirith.exe");
        assert_eq!(
            parsed,
            Some(PathBuf::from(
                "C:\\Users\\alice\\scoop\\apps\\tirith\\current\\tirith.exe"
            ))
        );
    }

    #[test]
    fn parse_shim_target_accepts_case_insensitive_quoted_values() {
        let parsed = parse_shim_target("ARGS = --help\r\nPATH = \"/tmp/tirith.exe\"\r\n");
        assert_eq!(parsed, Some(PathBuf::from("/tmp/tirith.exe")));
    }

    #[test]
    fn resolve_shim_target_uses_absolute_target_from_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("apps/tirith/current/tirith.exe");
        let shim = dir.path().join("shims/tirith.exe");

        fs::create_dir_all(real.parent().unwrap()).unwrap();
        fs::create_dir_all(shim.parent().unwrap()).unwrap();
        fs::write(&real, b"real").unwrap();
        fs::write(&shim, b"shim").unwrap();
        fs::write(
            shim.with_extension("shim"),
            format!("path = \"{}\"\n", real.display()),
        )
        .unwrap();

        assert_eq!(
            resolve_shim_target(&shim).unwrap().canonicalize().unwrap(),
            real.canonicalize().unwrap()
        );
    }

    #[test]
    fn resolve_shim_target_uses_relative_target_from_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("apps/tirith/current/tirith.exe");
        let shim = dir.path().join("shims/tirith.exe");

        fs::create_dir_all(real.parent().unwrap()).unwrap();
        fs::create_dir_all(shim.parent().unwrap()).unwrap();
        fs::write(&real, b"real").unwrap();
        fs::write(&shim, b"shim").unwrap();
        fs::write(
            shim.with_extension("shim"),
            "path = ../apps/tirith/current/tirith.exe\n",
        )
        .unwrap();

        assert_eq!(
            resolve_shim_target(&shim).unwrap().canonicalize().unwrap(),
            real.canonicalize().unwrap()
        );
    }

    #[cfg(unix)]
    mod npm_wrapper_tests {
        use super::super::{npm_platform_package, resolve_npm_wrapper_target};
        use std::fs;
        use std::os::unix::fs::symlink;

        /// Build the canonical npm layout under `root` →
        /// `Some((symlink-on-PATH, native-binary))`, or `None` on Unix targets
        /// the npm distribution doesn't ship for (so tests early-skip).
        fn build_layout(
            root: &std::path::Path,
        ) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
            let platform = npm_platform_package()?;

            let wrapper_dir = root.join("lib/node_modules/tirith/bin");
            let native_dir = root
                .join("lib/node_modules/@sheeki03")
                .join(platform)
                .join("bin");
            let bin_dir = root.join("bin");

            fs::create_dir_all(&wrapper_dir).unwrap();
            fs::create_dir_all(&native_dir).unwrap();
            fs::create_dir_all(&bin_dir).unwrap();

            let wrapper = wrapper_dir.join("tirith");
            let native = native_dir.join("tirith");
            fs::write(&wrapper, b"#!/usr/bin/env node\n// wrapper").unwrap();
            fs::write(&native, b"\x7fELF native bytes").unwrap();

            let symlinked = bin_dir.join("tirith");
            symlink(&wrapper, &symlinked).unwrap();

            Some((symlinked, native))
        }

        /// The bug path: PATH entry → symlink → wrapper. Fails without the
        /// canonicalize-first step in `resolve_npm_wrapper_target`.
        #[test]
        fn resolve_npm_wrapper_target_via_symlink_resolves_native_binary() {
            let dir = tempfile::tempdir().unwrap();
            let Some((symlinked, native)) = build_layout(dir.path()) else {
                eprintln!("skipping: npm distribution doesn't ship for this Unix target");
                return;
            };

            assert_eq!(
                resolve_npm_wrapper_target(&symlinked),
                Some(native.canonicalize().unwrap())
            );
        }

        #[test]
        fn resolve_npm_wrapper_target_resolves_native_binary_when_called_with_wrapper_path() {
            let dir = tempfile::tempdir().unwrap();
            let Some((_symlinked, native)) = build_layout(dir.path()) else {
                eprintln!("skipping: npm distribution doesn't ship for this Unix target");
                return;
            };

            let wrapper = dir.path().join("lib/node_modules/tirith/bin/tirith");
            assert_eq!(
                resolve_npm_wrapper_target(&wrapper),
                Some(native.canonicalize().unwrap())
            );
        }

        #[test]
        fn resolve_npm_wrapper_target_returns_none_when_native_missing() {
            // Wrapper layout WITHOUT the platform sibling (broken install) →
            // None, so the existing canonicalize path still warns.
            let dir = tempfile::tempdir().unwrap();
            let wrapper_dir = dir.path().join("lib/node_modules/tirith/bin");
            fs::create_dir_all(&wrapper_dir).unwrap();
            let wrapper = wrapper_dir.join("tirith");
            fs::write(&wrapper, b"wrapper").unwrap();

            assert_eq!(resolve_npm_wrapper_target(&wrapper), None);
        }

        #[test]
        fn resolve_npm_wrapper_target_ignores_non_npm_paths() {
            // Pip-style layout (outside any node_modules) → None, preserving the
            // documented PyPI conflict warning.
            let dir = tempfile::tempdir().unwrap();
            let pip_dir = dir.path().join("local/bin");
            fs::create_dir_all(&pip_dir).unwrap();
            let pip = pip_dir.join("tirith");
            fs::write(&pip, b"pip-installed").unwrap();

            assert_eq!(resolve_npm_wrapper_target(&pip), None);
        }
    }

    #[test]
    fn should_warn_neutralized_only_fires_for_repo_with_drops_and_no_marker() {
        // Repo scope + something neutralized + no session marker → warn.
        assert!(should_warn_neutralized(
            PolicyScope::Repo,
            &["allowlist"],
            false
        ));
        // Already warned this session (marker present) → silent.
        assert!(!should_warn_neutralized(
            PolicyScope::Repo,
            &["allowlist"],
            true
        ));
        // A non-repo (trusted) scope is never sanitized, so never warned — even with
        // a (would-be) drop set and no marker.
        assert!(!should_warn_neutralized(
            PolicyScope::Org,
            &["allowlist"],
            false
        ));
        // Repo scope but nothing was neutralized → nothing to report.
        assert!(!should_warn_neutralized(PolicyScope::Repo, &[], false));
    }

    #[test]
    fn quiet_from_env_recognizes_only_truthy_values() {
        for v in ["1", "true", "TRUE", "True"] {
            assert!(quiet_from_env(Some(v)), "{v:?} should be truthy");
        }
        for v in ["0", "", "yes", "false", "01", " 1"] {
            assert!(!quiet_from_env(Some(v)), "{v:?} should NOT be truthy");
        }
        assert!(!quiet_from_env(None), "unset TIRITH_QUIET is not quiet");
    }
}
