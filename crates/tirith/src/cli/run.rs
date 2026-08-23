use tirith_core::runner::{
    self, RequestedPipeInvocation, RunOptions, ScriptInputMode, ScriptInvocation,
};

pub fn run(
    url: &str,
    no_exec: bool,
    json: bool,
    capsule: bool,
    requested_pipe_invocation: Option<RequestedPipeInvocation>,
    expected_sha256: Option<String>,
) -> i32 {
    // JSON mode owns stdout as one bounded protocol envelope. Capture policy
    // diagnostics before even the early refusal path so a malformed policy can
    // never write attacker-controlled text beside that envelope.
    let _policy_diagnostic_capture = tirith_core::policy::PolicyDiagnosticCapture::start();

    // Structured stdout cannot safely coexist with an executed child's stdout.
    // This is a fixed protocol refusal with no caller-derived field, so reject
    // before full policy discovery (which may contact a remote policy service),
    // runner setup, DNS, download, or confirmation.
    if json && !no_exec {
        let empty_dlp = tirith_core::redact::CompiledCustomPatterns::new_silent(&[]);
        let error = build_run_error_json(
            "tirith run JSON output is inspection-only; pass --no-exec or omit --json before executing a remote script",
            &empty_dlp,
        );
        let _ = write_run_json(&error);
        return 1;
    }

    // Freeze one authoritative full-policy projection for every CLI-owned
    // output field. The runner may resolve its own exact analysis snapshot
    // later; this additional plan protects errors and early refusals that do
    // not carry a RunResult.
    let cwd_for_policy = std::env::current_dir()
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    let output_policy = tirith_core::policy::Policy::discover(cwd_for_policy.as_deref());
    if json {
        tirith_core::policy::freeze_captured_policy_dlp_patterns(
            &output_policy.dlp_custom_patterns,
        );
    }
    let output_dlp =
        tirith_core::redact::CompiledCustomPatterns::new_silent(&output_policy.dlp_custom_patterns);
    if !json {
        emit_run_policy_diagnostics_human(&output_dlp);
    }

    let interactive = is_terminal::is_terminal(std::io::stderr());

    // Every live path now uses the same stopped-target capsule controller. The
    // legacy `--capsule` spelling remains accepted, but omitting it no longer
    // falls back to an ordinary spawn that could run before durable execution
    // state is committed.
    let _capsule_requested = capsule;
    let verified_executor: Option<tirith_core::runner::VerifiedScriptExecutor> =
        Some(Box::new(capsuled_exec));

    let opts = RunOptions {
        url: url.to_string(),
        no_exec,
        interactive,
        expected_sha256,
        exec_fn: None,
    };

    let result = match (verified_executor, requested_pipe_invocation) {
        (Some(executor), Some(requested)) => {
            runner::run_with_verified_pipe_executor(opts, requested, executor)
        }
        (Some(executor), None) => runner::run_with_verified_executor(opts, executor),
        (None, Some(_)) => {
            Err("forced stdin execution requires the fail-closed capsule executor".to_string())
        }
        (None, None) => runner::run(opts),
    };
    match result {
        Ok(result) => {
            let presentation_patterns = tirith_core::policy::captured_policy_dlp_patterns_or(
                &output_policy.dlp_custom_patterns,
            );
            let presentation_dlp =
                tirith_core::redact::CompiledCustomPatterns::new_silent(&presentation_patterns);
            if !json {
                emit_run_policy_diagnostics_human(&presentation_dlp);
            }
            let json_ok = !json || write_run_json(&build_run_json(&result, &presentation_dlp));
            let outcome_code = run_process_outcome_code(&result, json);
            if !json_ok && outcome_code == 0 {
                1
            } else {
                outcome_code
            }
        }
        Err(e) => {
            let presentation_patterns = tirith_core::policy::captured_policy_dlp_patterns_or(
                &output_policy.dlp_custom_patterns,
            );
            let presentation_dlp =
                tirith_core::redact::CompiledCustomPatterns::new_silent(&presentation_patterns);
            if json {
                let err = build_run_error_json(&e, &presentation_dlp);
                let _ = write_run_json(&err);
            } else {
                emit_run_policy_diagnostics_human(&presentation_dlp);
                let error =
                    tirith_core::output::sanitize_human_field_with_compiled(&e, &presentation_dlp);
                eprintln!("tirith: {error}");
            }
            1
        }
    }
}

fn run_result_analysis_complete(result: &tirith_core::runner::RunResult) -> bool {
    result.analysis_complete && result.verdict.is_some()
}

fn run_process_outcome_code(result: &tirith_core::runner::RunResult, json: bool) -> i32 {
    if json && !run_result_analysis_complete(result) {
        1
    } else if result.executed || result.refused {
        result.exit_code.unwrap_or(1)
    } else {
        0
    }
}

fn build_run_json(
    result: &tirith_core::runner::RunResult,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> serde_json::Value {
    // `RunResult::verdict` is already DLP-redacted by the runner against the
    // exact policy snapshot used by analysis. Clone and priority-bound it here,
    // at the public DTO boundary, leaving the runner/audit state untouched.
    let presentation = result
        .verdict
        .as_ref()
        .map(|verdict| crate::cli::prepare_verdict_presentation(verdict, compiled));
    let original_findings_count = presentation
        .as_ref()
        .map(|projection| projection.original_findings_count)
        .unwrap_or(0);
    let presented_findings_count = presentation
        .as_ref()
        .map(|projection| projection.presented_findings_count)
        .unwrap_or(0);
    let dropped_findings_count = presentation
        .as_ref()
        .map(|projection| projection.dropped_findings_count)
        .unwrap_or(0);
    let receipt = result
        .presentation_receipt_with_compiled(compiled)
        .public_view();
    let analysis_complete = run_result_analysis_complete(result);
    let effective_action = if analysis_complete {
        presentation
            .as_ref()
            .expect("complete run result carries a verdict")
            .verdict
            .action
    } else {
        tirith_core::verdict::Action::Block
    };
    let exit_code = if analysis_complete {
        result.exit_code
    } else {
        Some(tirith_core::verdict::Action::Block.exit_code())
    };
    let executed = analysis_complete && result.executed;
    let mut value = serde_json::json!({
        // Public DTO: URL userinfo is redacted and local-machine cwd omitted.
        "receipt": receipt,
        "verdict": presentation.as_ref().map(|projection| &projection.verdict),
        "action": effective_action,
        "original_findings_count": original_findings_count,
        "presented_findings_count": presented_findings_count,
        "dropped_findings_count": dropped_findings_count,
        "analysis_complete": analysis_complete,
        "analysis_incomplete": !analysis_complete,
        "refused": result.refused,
        "executed": executed,
        "exit_code": exit_code,
    });
    append_run_policy_diagnostics(&mut value, compiled);
    tirith_core::redact::redact_json_strings(&mut value, compiled);
    tirith_core::verdict::bound_json_value_for_output(value)
}

fn build_run_error_json(
    error: &str,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> serde_json::Value {
    let error = tirith_core::redact::redact_sanitize_redact_with_compiled(error, compiled);
    let mut value = serde_json::json!({
        "action": tirith_core::verdict::Action::Block,
        "analysis_complete": false,
        "analysis_incomplete": true,
        "refused": true,
        "executed": false,
        "exit_code": 1,
        "error": error,
    });
    append_run_policy_diagnostics(&mut value, compiled);
    tirith_core::redact::redact_json_strings(&mut value, compiled);
    tirith_core::verdict::bound_json_value_for_output(value)
}

fn append_run_policy_diagnostics(
    value: &mut serde_json::Value,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) {
    let diagnostics = tirith_core::policy::drain_captured_policy_diagnostics_for_output(compiled);
    if diagnostics.is_empty() {
        return;
    }
    let count = diagnostics.len();
    let diagnostics = diagnostics
        .into_iter()
        .map(|diagnostic| diagnostic.replace(['\r', '\n', '\t'], " "))
        .map(serde_json::Value::String)
        .collect();
    if let Some(object) = value.as_object_mut() {
        object.insert("policy_diagnostics_count".to_string(), count.into());
        object.insert(
            "policy_diagnostics".to_string(),
            serde_json::Value::Array(diagnostics),
        );
    }
}

fn emit_run_policy_diagnostics_human(compiled: &tirith_core::redact::CompiledCustomPatterns) {
    for diagnostic in tirith_core::policy::drain_captured_policy_diagnostics_for_output(compiled) {
        let diagnostic =
            tirith_core::output::sanitize_human_field_with_compiled(&diagnostic, compiled);
        eprintln!("tirith run: policy diagnostic: {diagnostic}");
    }
}

fn write_run_json(value: &serde_json::Value) -> bool {
    super::write_json_stdout(value, "tirith: failed to write JSON output")
}

fn reviewed_file_capsule_spec() -> tirith_core::capsule::CapsuleSpec {
    let spec = tirith_core::capsule::CapsuleSpec::locked_down();
    #[cfg(test)]
    let spec = apply_test_capsule_override(spec);
    spec
}

fn forced_stdin_capsule_spec() -> tirith_core::capsule::CapsuleSpec {
    let spec = crate::cli::capsule::supervised_stdin_spec();
    #[cfg(test)]
    let spec = apply_test_capsule_override(spec);
    spec
}

#[cfg(test)]
#[derive(Clone)]
struct TestCapsuleOverride {
    max_output_bytes: u64,
    wall_clock_seconds: u64,
    write_root: std::path::PathBuf,
}

#[cfg(test)]
std::thread_local! {
    /// Test-only, thread-local tightening of the live `tirith run` capsule.
    /// The executor is synchronous, so this reaches the exact production
    /// `capsuled_exec` function without adding a process environment or CLI
    /// knob that an untrusted script could influence.
    static TEST_CAPSULE_OVERRIDE: std::cell::RefCell<Option<TestCapsuleOverride>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn apply_test_capsule_override(
    mut spec: tirith_core::capsule::CapsuleSpec,
) -> tirith_core::capsule::CapsuleSpec {
    TEST_CAPSULE_OVERRIDE.with(|override_cell| {
        let override_value = override_cell.borrow();
        let Some(override_value) = override_value.as_ref() else {
            return;
        };
        spec.resources.max_output_bytes = Some(override_value.max_output_bytes);
        spec.resources.wall_clock_seconds = Some(override_value.wall_clock_seconds);
        spec.filesystem
            .write_roots
            .push(override_value.write_root.clone());
    });
    spec
}

/// The contained executor for every live `tirith run` (E5). `--capsule` is a
/// legacy compatibility spelling, not an opt-in boundary. Runs the exact typed
/// interpreter invocation through the locked-down OS capsule. File mode receives
/// only the inherited sealed reviewed-script descriptor; no downloaded-script
/// pathname enters argv. Enforcing surface: fail closed when the backend cannot
/// provide the spec's required coverage.
pub(crate) fn capsuled_exec(
    invocation: &ScriptInvocation,
    reviewed_script: tirith_core::runner::ReviewedScript<'_>,
    authorizer: &mut tirith_core::runner::ExecutionAuthorizer,
) -> Result<i32, String> {
    let outcome = match invocation.input_mode {
        ScriptInputMode::File => {
            let program = invocation.resolved_executable.as_ref().ok_or_else(|| {
                "file execution reached the capsule without a trusted interpreter identity"
                    .to_string()
            })?;
            let mut spec = reviewed_file_capsule_spec();
            let (read_roots, runtime_path) = validated_stdin_runtime(program)?;
            spec.filesystem.read_roots = read_roots;
            spec.environment.allow = ["PATH", "LANG", "TERM"]
                .iter()
                .map(|name| name.to_string())
                .collect();
            crate::cli::capsule::run_to_completion_with_reviewed_file(
                &spec,
                program,
                std::ffi::OsStr::new(&invocation.interpreter),
                &invocation.args,
                reviewed_script,
                authorizer,
                Some(std::path::Path::new("/")),
                &[("PATH".to_string(), runtime_path)],
            )
        }
        ScriptInputMode::Stdin => {
            let program = invocation.resolved_executable.as_ref().ok_or_else(|| {
                "forced stdin execution reached the capsule without a trusted interpreter identity"
                    .to_string()
            })?;
            let target_argv0 = invocation
                .interpreter
                .parse::<tirith_core::runner::PipeInterpreter>()
                .map_err(|error| {
                    format!("forced stdin execution lost its closed interpreter identity: {error}")
                })?;
            let mut spec = forced_stdin_capsule_spec();
            let (read_roots, runtime_path) = validated_stdin_runtime(program)?;
            spec.filesystem.read_roots = read_roots;
            // PATH is supplied as explicit, validated child data. It is not
            // inherited from the ambient lookup that selected the interpreter.
            spec.environment.allow = ["PATH", "LANG", "TERM"]
                .iter()
                .map(|name| name.to_string())
                .collect();
            crate::cli::capsule::run_to_completion_with_stdin(
                &spec,
                program,
                target_argv0,
                &invocation.args,
                reviewed_script.bytes(),
                authorizer,
                // Stdin mode never needs the downloaded file path. A fixed
                // system-owned cwd avoids inheriting an inaccessible or
                // attacker-influenced caller directory into the capsule.
                Some(std::path::Path::new("/")),
                &[("PATH".to_string(), runtime_path)],
            )
        }
    };
    match outcome {
        Ok(outcome) => {
            eprintln!(
                "tirith run: script executed contained via '{}' [{}]",
                outcome.backend_id,
                outcome.coverage_summary()
            );
            Ok(outcome.exit_code)
        }
        Err(refused) => Err(format!(
            "capsule refused to run the script: {}",
            refused.reason
        )),
    }
}

/// Canonicalize and validate the narrow read/runtime roots for a forced stdin
/// interpreter. This deliberately avoids the former broad `/usr`, `/etc`, and
/// `/System` grants. System loader roots, standard executable directories, the
/// exact root-managed interpreter directory are the only additions.
fn validated_stdin_runtime(
    program: &tirith_core::trusted_child::TrustedExecutable,
) -> Result<(Vec<std::path::PathBuf>, String), String> {
    let mut read_roots = Vec::new();
    let mut path_dirs = Vec::new();

    let program_dir = program
        .path()
        .parent()
        .ok_or_else(|| "trusted interpreter has no parent directory".to_string())?;
    push_root_managed_runtime_root(&mut read_roots, program_dir)?;
    push_root_managed_runtime_root(&mut path_dirs, program_dir)?;

    for directory in ["/bin", "/usr/bin"] {
        push_existing_root_managed_runtime_root(&mut read_roots, directory)?;
        push_existing_root_managed_runtime_root(&mut path_dirs, directory)?;
    }

    #[cfg(target_os = "linux")]
    for root in [
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/usr/share",
        "/etc/ld.so.cache",
        "/etc/nsswitch.conf",
        "/etc/passwd",
        "/etc/group",
    ] {
        push_existing_root_managed_runtime_root(&mut read_roots, root)?;
    }

    #[cfg(target_os = "macos")]
    for root in [
        "/usr/lib",
        "/usr/share",
        "/System/Library",
        "/Library/Frameworks",
    ] {
        push_existing_root_managed_runtime_root(&mut read_roots, root)?;
    }

    let runtime_path = std::env::join_paths(path_dirs.iter()).map_err(|error| {
        format!("cannot construct validated runtime PATH for the interpreter: {error}")
    })?;
    let runtime_path = runtime_path.into_string().map_err(|_| {
        "validated runtime PATH is not valid UTF-8 and cannot enter the capsule environment"
            .to_string()
    })?;
    Ok((read_roots, runtime_path))
}

fn push_existing_root_managed_runtime_root(
    roots: &mut Vec<std::path::PathBuf>,
    candidate: &str,
) -> Result<(), String> {
    let path = std::path::Path::new(candidate);
    if path.exists() {
        push_root_managed_runtime_root(roots, path)?;
    }
    Ok(())
}

/// Add a system runtime file/directory only after its canonical target and every
/// ancestor are proven root-owned and non-group/world-writable. The bound
/// interpreter alone is insufficient if a same-UID/group writer can replace its
/// dynamic loader, shared library, PATH child, or data root after review.
fn push_root_managed_runtime_root(
    roots: &mut Vec<std::path::PathBuf>,
    candidate: &std::path::Path,
) -> Result<(), String> {
    if !candidate.is_absolute() {
        return Err(format!(
            "capsule runtime root is not absolute: {}",
            candidate.display()
        ));
    }
    let canonical = candidate
        .canonicalize()
        .map_err(|error| format!("validate runtime root {}: {error}", candidate.display()))?;
    let metadata = std::fs::metadata(&canonical)
        .map_err(|error| format!("stat runtime root {}: {error}", canonical.display()))?;
    if !(metadata.is_dir() || metadata.is_file()) {
        return Err(format!(
            "capsule runtime root is neither a file nor directory: {}",
            canonical.display()
        ));
    }
    #[cfg(unix)]
    for component in canonical.ancestors() {
        use std::os::unix::fs::MetadataExt as _;
        let component_metadata = std::fs::metadata(component).map_err(|error| {
            format!(
                "stat capsule runtime root ancestor {}: {error}",
                component.display()
            )
        })?;
        if !root_managed_metadata_is_secure(component_metadata.uid(), component_metadata.mode()) {
            return Err(format!(
                "capsule runtime root or ancestor is not root-owned and non-group/world-writable: {}",
                component.display()
            ));
        }
    }
    if !roots.contains(&canonical) {
        roots.push(canonical);
    }
    Ok(())
}

#[cfg(unix)]
fn root_managed_metadata_is_secure(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

#[cfg(test)]
mod tests {
    #[test]
    fn run_json_is_bounded_and_retains_late_critical_without_mutating_result() {
        use tirith_core::verdict::{Finding, RuleId, Severity, Timings, Verdict};

        let mut findings = (0..400)
            .map(|index| Finding {
                rule_id: RuleId::ConfigInjection,
                severity: Severity::Low,
                title: format!("low {index}"),
                description: "low detail ".repeat(2_000),
                evidence: Vec::new(),
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            })
            .collect::<Vec<_>>();
        findings.push(Finding {
            rule_id: RuleId::PrivateKeyExposed,
            severity: Severity::Critical,
            title: "late runner critical".to_string(),
            description: "must survive the DTO cap".to_string(),
            evidence: Vec::new(),
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
        let verdict = Verdict::from_findings(findings, 3, Timings::default());
        let raw_count = verdict.findings.len();
        let result = tirith_core::runner::RunResult {
            receipt: tirith_core::receipt::Receipt {
                url: "https://example.test/install.sh".to_string(),
                final_url: None,
                redirects: Vec::new(),
                sha256: "a".repeat(64),
                size: 1,
                domains_referenced: Vec::new(),
                paths_referenced: (0..2_000)
                    .map(|index| format!("/receipt-flood/{index}/{}", "x".repeat(200)))
                    .collect(),
                analysis_method: "policy-complete:sh".to_string(),
                privilege: "normal".to_string(),
                timestamp: "2026-08-09T00:00:00Z".to_string(),
                cwd: Some("/private/raw/cwd".to_string()),
                git_repo: None,
                git_branch: None,
            },
            verdict: Some(verdict),
            analysis_complete: true,
            refused: true,
            executed: false,
            exit_code: Some(1),
        };

        let patterns = vec!["C02_RUN_OUTPUT_PATTERN".to_string()];
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&patterns);
        let value = super::build_run_json(&result, &compiled);
        let pretty = serde_json::to_string_pretty(&value).unwrap();

        assert!(pretty.len() < tirith_core::verdict::MAX_PRESENTATION_BYTES);
        assert!(pretty.contains("private_key_exposed"), "{pretty}");
        assert!(pretty.contains("late runner critical"), "{pretty}");
        assert_eq!(result.verdict.as_ref().unwrap().findings.len(), raw_count);
        assert_eq!(
            value["summary"]["original_findings_count"],
            raw_count as u64
        );
        assert!(value["summary"]["dropped_findings_count"]
            .as_u64()
            .is_some_and(|count| count > 0));
        assert_eq!(value["summary"]["refused"], true);
        assert_eq!(value["summary"]["executed"], false);
        assert_eq!(value["summary"]["exit_code"], 1);
        assert_eq!(value["summary"]["action"], "block");
    }

    #[test]
    fn no_exec_block_json_keeps_action_without_claiming_live_refusal_and_scrubs_receipt() {
        use tirith_core::verdict::{Finding, RuleId, Severity, Timings, Verdict};

        let canary = "C02_RUN_RECEIPT_CANARY";
        let provider_token = "provider-token-0123456789";
        let patterns = vec![regex::escape(canary)];
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&patterns);
        let verdict = Verdict::from_findings(
            vec![Finding {
                rule_id: RuleId::PrivateKeyExposed,
                severity: Severity::Critical,
                title: "blocked body".to_string(),
                description: "no-exec still reports the body decision".to_string(),
                evidence: Vec::new(),
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }],
            3,
            Timings::default(),
        );
        let result = tirith_core::runner::RunResult {
            receipt: tirith_core::receipt::Receipt {
                url: format!(
                    "https://user:password@mainnet.infura.io/v3/{provider_token}?token={canary}#fragment"
                ),
                final_url: Some(format!(
                    "https://eth-mainnet.g.alchemy.com/v2/{provider_token}?key={canary}"
                )),
                redirects: vec![format!(
                    "https://rpc.ankr.com/eth/{provider_token}?key={canary}"
                )],
                sha256: "c".repeat(64),
                size: 1,
                domains_referenced: vec!["example.test".to_string()],
                paths_referenced: vec![format!("/private/{canary}/wallet.json")],
                analysis_method: "policy-complete:sh".to_string(),
                privilege: "normal".to_string(),
                timestamp: "2026-08-09T00:00:00Z".to_string(),
                cwd: Some(format!("/private/{canary}")),
                git_repo: Some(format!(
                    "https://user:password@github.com/org/repo?token={canary}#fragment"
                )),
                git_branch: Some(format!("branch-{canary}")),
            },
            verdict: Some(verdict),
            analysis_complete: true,
            refused: false,
            executed: false,
            exit_code: None,
        };

        let value = super::build_run_json(&result, &compiled);
        let serialized = serde_json::to_string(&value).unwrap();

        assert_eq!(value["action"], "block");
        assert_eq!(value["refused"], false);
        assert_eq!(value["executed"], false);
        assert!(!serialized.contains(canary));
        assert!(!serialized.contains(provider_token));
        assert!(!serialized.contains("user:password"));
        assert!(!serialized.contains("token="));
        assert!(!serialized.contains("#fragment"));
        assert!(serialized.contains("[REDACTED:custom]"));
    }

    #[test]
    fn receipt_json_uses_the_monotonic_nested_policy_dlp_union() {
        let canary = "C02_LATE_RUNNER_POLICY_CANARY";
        let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
        tirith_core::policy::freeze_captured_policy_dlp_patterns(&[]);
        tirith_core::policy::freeze_captured_policy_dlp_patterns(&[regex::escape(canary)]);
        let patterns = tirith_core::policy::captured_policy_dlp_patterns_or(&[]);
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&patterns);
        let result = tirith_core::runner::RunResult {
            receipt: tirith_core::receipt::Receipt {
                url: "https://example.test/install.sh".to_string(),
                final_url: None,
                redirects: Vec::new(),
                sha256: "b".repeat(64),
                size: 1,
                domains_referenced: Vec::new(),
                paths_referenced: vec![format!("/private/{canary}/wallet.json")],
                analysis_method: "policy-complete:sh".to_string(),
                privilege: "normal".to_string(),
                timestamp: "2026-08-11T00:00:00Z".to_string(),
                cwd: None,
                git_repo: None,
                git_branch: None,
            },
            verdict: Some(tirith_core::verdict::Verdict::allow_fast(
                3,
                Default::default(),
            )),
            analysis_complete: true,
            refused: false,
            executed: false,
            exit_code: None,
        };

        let serialized = serde_json::to_string(&super::build_run_json(&result, &compiled)).unwrap();
        assert!(!serialized.contains(canary), "{serialized}");
        assert!(serialized.contains("[REDACTED:custom]"), "{serialized}");
    }

    fn incomplete_no_exec_result(
        reason: &str,
        receipt_flood: bool,
    ) -> tirith_core::runner::RunResult {
        tirith_core::runner::RunResult {
            receipt: tirith_core::receipt::Receipt {
                url: "https://example.test/inspect.sh".to_string(),
                final_url: None,
                redirects: Vec::new(),
                sha256: "f".repeat(64),
                size: 1,
                domains_referenced: Vec::new(),
                paths_referenced: if receipt_flood {
                    (0..2_000)
                        .map(|index| format!("/incomplete/{index}/{}", "x".repeat(220)))
                        .collect()
                } else {
                    Vec::new()
                },
                analysis_method: format!("static-incomplete:{reason}"),
                privilege: "normal".to_string(),
                timestamp: "2026-08-10T00:00:00Z".to_string(),
                cwd: Some("/private/raw/cwd".to_string()),
                git_repo: None,
                git_branch: None,
            },
            verdict: None,
            analysis_complete: false,
            refused: false,
            executed: false,
            exit_code: None,
        }
    }

    fn assert_incomplete_no_exec_metadata(value: &serde_json::Value) {
        assert_eq!(value["action"], "block");
        assert_eq!(value["analysis_complete"], false);
        assert_eq!(value["analysis_incomplete"], true);
        assert_eq!(value["refused"], false);
        assert_eq!(value["executed"], false);
        assert_eq!(value["exit_code"], 1);
    }

    #[test]
    fn unsupported_interpreter_no_exec_json_is_block_incomplete_exit_one() {
        let patterns = vec!["C02_UNSUPPORTED_INTERPRETER_OUTPUT".to_string()];
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&patterns);
        let result = incomplete_no_exec_result("unsupported-interpreter", false);

        let value = super::build_run_json(&result, &compiled);

        assert_eq!(
            value["receipt"]["analysis_method"],
            "static-incomplete:unsupported-interpreter"
        );
        assert_incomplete_no_exec_metadata(&value);
        assert_eq!(super::run_process_outcome_code(&result, true), 1);
        assert_eq!(
            super::run_process_outcome_code(&result, false),
            0,
            "non-JSON inspection keeps its existing process-status contract"
        );
    }

    #[test]
    fn no_verdict_overrides_a_claimed_complete_flag_in_json_and_process_status() {
        let patterns = vec!["C02_NO_VERDICT_OUTPUT".to_string()];
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&patterns);
        let mut result = incomplete_no_exec_result("unsupported-interpreter", false);
        result.analysis_complete = true;

        let value = super::build_run_json(&result, &compiled);

        assert_incomplete_no_exec_metadata(&value);
        assert_eq!(super::run_process_outcome_code(&result, true), 1);
    }

    #[test]
    fn invalid_utf8_no_exec_json_and_compact_fallback_are_identically_fail_closed() {
        let patterns = vec!["C02_INVALID_UTF8_OUTPUT".to_string()];
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&patterns);
        let ordinary_result = incomplete_no_exec_result("invalid-utf8", false);
        let ordinary = super::build_run_json(&ordinary_result, &compiled);
        assert_eq!(
            ordinary["receipt"]["analysis_method"],
            "static-incomplete:invalid-utf8"
        );
        assert_incomplete_no_exec_metadata(&ordinary);

        let flooded_result = incomplete_no_exec_result("invalid-utf8", true);
        let fallback = super::build_run_json(&flooded_result, &compiled);
        let pretty = serde_json::to_string_pretty(&fallback).unwrap();

        assert!(pretty.len() < tirith_core::verdict::MAX_PRESENTATION_BYTES);
        assert_eq!(fallback["presentation_truncated"], true);
        for field in [
            "action",
            "analysis_complete",
            "analysis_incomplete",
            "refused",
            "executed",
            "exit_code",
        ] {
            assert_eq!(
                fallback["summary"][field], ordinary[field],
                "compact fallback changed incomplete-run field {field}"
            );
        }
        assert_eq!(super::run_process_outcome_code(&flooded_result, true), 1);
    }

    #[test]
    fn run_error_json_uses_frozen_dlp_before_full_envelope_cap() {
        let canary = "C02_RUN_ERROR_CANARY";
        let github = format!("ghp_{}", "a1B2c3D4".repeat(5));
        let patterns = vec![regex::escape(canary)];
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&patterns);
        let error = format!(
            "failure {}\u{200b}{} {}\u{1b}[31m{} {}",
            &canary[..9],
            &canary[9..],
            &github[..18],
            &github[18..],
            "flood".repeat(100_000)
        );

        let value = super::build_run_error_json(&error, &compiled);
        let pretty = serde_json::to_string_pretty(&value).unwrap();

        assert!(pretty.len() < tirith_core::verdict::MAX_PRESENTATION_BYTES);
        assert!(!pretty.contains(canary));
        assert!(!pretty.contains(&github));
        assert!(pretty.contains("[REDACTED:custom]"));
        assert!(pretty.contains("[REDACTED:GitHub PAT]"));
        assert_eq!(value["summary"]["action"], "block");
        assert_eq!(value["summary"]["analysis_complete"], false);
        assert_eq!(value["summary"]["analysis_incomplete"], true);
        assert_eq!(value["summary"]["refused"], true);
        assert_eq!(value["summary"]["exit_code"], 1);
    }

    #[test]
    fn run_json_captures_policy_diagnostics_inside_the_bounded_error_envelope() {
        let custom = "C02_RUN_POLICY_CANARY";
        let github = format!("ghp_{}", "a1B2c3D4".repeat(5));
        let source = format!(
            "policy-{}\u{1b}[31m{}-{}\u{200b}{}",
            &github[..18],
            &github[18..],
            &custom[..10],
            &custom[10..]
        );
        let patterns = vec![regex::escape(custom)];
        let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
        tirith_core::policy::freeze_captured_policy_dlp_patterns(&patterns);
        let _ = tirith_core::policy::Policy::load_from_yaml("[", Some(&source));
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&patterns);

        let value = super::build_run_error_json(&"runner failure ".repeat(40_000), &compiled);
        let serialized = serde_json::to_string_pretty(&value).unwrap();
        let summary = value.get("summary").unwrap_or(&value);

        assert!(serialized.len() < tirith_core::verdict::MAX_PRESENTATION_BYTES);
        assert!(!serialized.contains(&github), "{serialized}");
        assert!(!serialized.contains(custom), "{serialized}");
        assert!(!serialized.contains("\\u001b"), "{serialized}");
        assert!(!serialized.contains("\\u200b"), "{serialized}");
        assert_eq!(summary["action"], "block");
        assert_eq!(summary["analysis_complete"], false);
        assert_eq!(summary["analysis_incomplete"], true);
        assert_eq!(summary["refused"], true);
        assert!(summary["policy_diagnostics_count"]
            .as_u64()
            .is_some_and(|count| count >= 1));

        let diagnostics = if let Some(diagnostics) = value["policy_diagnostics"].as_array() {
            diagnostics
        } else {
            summary["policy_diagnostics"]
                .as_array()
                .expect("fallback retains captured diagnostics")
        };
        let diagnostic_text = diagnostics
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(diagnostic_text.contains("[REDACTED:GitHub PAT]"));
        assert!(diagnostic_text.contains("[REDACTED:custom]"));
    }

    #[cfg(target_os = "linux")]
    struct TestCapsuleOverrideGuard(Option<super::TestCapsuleOverride>);

    #[cfg(target_os = "linux")]
    impl TestCapsuleOverrideGuard {
        fn tighten(
            max_output_bytes: u64,
            wall_clock_seconds: u64,
            write_root: &std::path::Path,
        ) -> Self {
            let next = super::TestCapsuleOverride {
                max_output_bytes,
                wall_clock_seconds,
                write_root: write_root.to_path_buf(),
            };
            let previous = super::TEST_CAPSULE_OVERRIDE
                .with(|override_cell| override_cell.replace(Some(next)));
            Self(previous)
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for TestCapsuleOverrideGuard {
        fn drop(&mut self) {
            let previous = self.0.take();
            super::TEST_CAPSULE_OVERRIDE.with(|override_cell| {
                override_cell.replace(previous);
            });
        }
    }

    #[cfg(target_os = "linux")]
    struct ScriptServer {
        address: std::net::SocketAddr,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    #[cfg(target_os = "linux")]
    impl ScriptServer {
        fn start(body: &[u8]) -> Self {
            use std::io::{Read as _, Write as _};
            use std::sync::atomic::Ordering;

            let listener = std::net::TcpListener::bind("127.0.0.1:0")
                .expect("bind live-run regression server");
            listener
                .set_nonblocking(true)
                .expect("make live-run regression server nonblocking");
            let address = listener.local_addr().expect("read regression address");
            let body = body.to_vec();
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop_server = std::sync::Arc::clone(&stop);
            let thread = std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while !stop_server.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream
                                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                                .expect("bound regression request read");
                            let mut request = [0u8; 2048];
                            let _ = stream.read(&mut request);
                            write!(
                                stream,
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            )
                            .expect("write regression response head");
                            stream
                                .write_all(&body)
                                .expect("write regression response body");
                            stream.flush().expect("flush regression response");
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(error) => panic!("live-run regression server failed: {error}"),
                    }
                }
            });
            Self {
                address,
                stop,
                thread: Some(thread),
            }
        }

        fn url(&self) -> String {
            format!("http://{}/script.sh", self.address)
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for ScriptServer {
        fn drop(&mut self) {
            use std::sync::atomic::Ordering;

            self.stop.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                thread.join().expect("join live-run regression server");
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn sha256_hex(body: &[u8]) -> String {
        use sha2::{Digest as _, Sha256};

        Sha256::digest(body)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[cfg(target_os = "linux")]
    fn execute_live_stdin(body: &[u8]) -> tirith_core::runner::RunResult {
        let server = ScriptServer::start(body);
        let result = tirith_core::runner::run_with_verified_pipe_executor(
            tirith_core::runner::RunOptions {
                url: server.url(),
                no_exec: false,
                interactive: true,
                expected_sha256: Some(sha256_hex(body)),
                exec_fn: None,
            },
            tirith_core::runner::RequestedPipeInvocation {
                interpreter: tirith_core::runner::PipeInterpreter::Bash,
                args: Vec::new(),
            },
            Box::new(super::capsuled_exec),
        );
        drop(server);
        result.expect("live `tirith run` regression transaction")
    }

    #[test]
    fn run_capsule_specs_require_supervised_wall_clock_and_output_limits() {
        for (surface, spec) in [
            ("reviewed file", super::reviewed_file_capsule_spec()),
            ("forced stdin", super::forced_stdin_capsule_spec()),
        ] {
            assert_eq!(
                spec.resources.max_output_bytes,
                Some(16 * 1024 * 1024),
                "{surface} execution must carry a combined output ceiling into the supervised launcher"
            );
            assert_eq!(
                spec.resources.wall_clock_seconds,
                Some(300),
                "{surface} execution must carry a wall-clock deadline into the supervised launcher"
            );
            assert!(
                spec.required_coverage().resource_limits_enforced,
                "{surface} execution must fail closed if the requested resource contract is unavailable"
            );
        }
    }

    /// `repo-0418`: exercise the actual content-bound `tirith run` executor,
    /// including download, policy review, durable authorization, containment,
    /// and target launch. Delayed marker writes prove a killed descendant did
    /// not survive either parent-enforced ceiling; the control proves the same
    /// production entrypoint still permits an ordinary under-limit script.
    #[cfg(target_os = "linux")]
    #[test]
    fn live_run_entrypoint_enforces_wall_output_and_preserves_under_limit_execution() {
        // Live execution requires the operator to confirm on the controlling
        // terminal; a CI job has none, and the confirmation gate is deliberate.
        if std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_err()
        {
            eprintln!("skipping live `tirith run` regression: no controlling terminal");
            return;
        }

        crate::cli::test_harness::with_fake_env(false, |home, _| {
            use crate::cli::test_harness::EnvGuard;

            for directory in ["config", "data", "state", "cache"] {
                std::fs::create_dir_all(home.join(directory))
                    .expect("create isolated live-run state");
            }
            let _config = EnvGuard::set("XDG_CONFIG_HOME", &home.join("config"));
            let _data = EnvGuard::set("XDG_DATA_HOME", &home.join("data"));
            let _state = EnvGuard::set("XDG_STATE_HOME", &home.join("state"));
            let _cache = EnvGuard::set("XDG_CACHE_HOME", &home.join("cache"));
            let _policy = EnvGuard::set("TIRITH_POLICY_ROOT", home);
            let _private = EnvGuard::set(
                "TIRITH_PRIVATE_FETCH_ALLOW",
                std::path::Path::new("127.0.0.1/32"),
            );
            let _no_proxy = EnvGuard::set("NO_PROXY", std::path::Path::new("127.0.0.1,localhost"));
            let _log = EnvGuard::set("TIRITH_LOG", std::path::Path::new("0"));
            let _tirith = EnvGuard::remove("TIRITH");
            let _server_url = EnvGuard::remove("TIRITH_SERVER_URL");
            let _api_key = EnvGuard::remove("TIRITH_API_KEY");
            let _http_proxy = EnvGuard::remove("HTTP_PROXY");
            let _https_proxy = EnvGuard::remove("HTTPS_PROXY");
            let _all_proxy = EnvGuard::remove("ALL_PROXY");
            let _http_proxy_lower = EnvGuard::remove("http_proxy");
            let _https_proxy_lower = EnvGuard::remove("https_proxy");
            let _all_proxy_lower = EnvGuard::remove("all_proxy");

            let marker_root = home.join("markers");
            std::fs::create_dir(&marker_root).expect("create marker root");
            let wall_marker = marker_root.join("wall-survivor");
            let output_marker = marker_root.join("output-survivor");
            let control_marker = marker_root.join("under-limit-ran");

            let _limits = TestCapsuleOverrideGuard::tighten(1024, 1, &marker_root);

            let wall_script = format!(
                "#!/bin/bash\n(sleep 2; printf late > '{}') & wait\n",
                wall_marker.display()
            );
            let wall_started = std::time::Instant::now();
            let wall = execute_live_stdin(wall_script.as_bytes());
            assert!(wall.executed, "the authenticated target reached execution");
            assert_eq!(wall.exit_code, Some(124), "wall overage must be typed");
            assert!(
                wall_started.elapsed() < std::time::Duration::from_secs(5),
                "wall-clock supervision did not terminate promptly"
            );
            std::thread::sleep(std::time::Duration::from_millis(1250));
            assert!(
                !wall_marker.exists(),
                "a wall-clock-terminated descendant survived and wrote a marker"
            );

            let output_script = format!(
                "#!/bin/bash\n(sleep 2; printf late > '{}') & while :; do printf '0123456789abcdef'; done\n",
                output_marker.display()
            );
            let output_started = std::time::Instant::now();
            let output = execute_live_stdin(output_script.as_bytes());
            assert!(
                output.executed,
                "the authenticated target reached execution"
            );
            assert_eq!(output.exit_code, Some(125), "output overage must be typed");
            assert!(
                output_started.elapsed() < std::time::Duration::from_secs(5),
                "combined-output supervision did not terminate promptly"
            );
            std::thread::sleep(std::time::Duration::from_millis(2250));
            assert!(
                !output_marker.exists(),
                "an output-terminated descendant survived and wrote a marker"
            );

            let control_script = format!(
                "#!/bin/bash\nprintf ok\nprintf legitimate > '{}'\n",
                control_marker.display()
            );
            let control = execute_live_stdin(control_script.as_bytes());
            assert!(control.executed);
            assert_eq!(control.exit_code, Some(0));
            assert_eq!(
                std::fs::read(&control_marker).expect("read legitimate marker"),
                b"legitimate"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn root_managed_runtime_metadata_rejects_group_writable_or_non_root_inputs() {
        assert!(super::root_managed_metadata_is_secure(0, 0o040755));
        assert!(!super::root_managed_metadata_is_secure(0, 0o040775));
        assert!(!super::root_managed_metadata_is_secure(0, 0o040757));
        assert!(!super::root_managed_metadata_is_secure(501, 0o040755));
    }

    #[cfg(unix)]
    #[test]
    fn root_managed_runtime_path_rejects_a_same_uid_fixture() {
        let fixture = tempfile::tempdir().expect("runtime-root fixture");
        let mut roots = Vec::new();
        let error = super::push_root_managed_runtime_root(&mut roots, fixture.path())
            .expect_err("same-UID runtime roots must fail closed");
        assert!(
            error.contains("not root-owned"),
            "unexpected error: {error}"
        );
        assert!(roots.is_empty());
    }
}
