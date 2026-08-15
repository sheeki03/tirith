//! M11 ch2 — `tirith commands init|list|run|check`.
//!
//! A thin CLI over the repo command manifest (`.tirith/commands.yaml`,
//! [`tirith_core::commands_manifest`]). The manifest is SUPPRESSION-BOUNDED: it
//! can only suppress the Info `repo_command_unknown` annotation on an exact
//! `allowed[]` match and ELEVATE via a blocking `repo_command_dangerous_pattern`
//! on a `dangerous[]` glob; it can NEVER weaken a real engine finding. `run`
//! re-checks the resolved command through the engine, refuses a block, and
//! requires trusted acknowledgement for warnings — the manifest cannot bypass
//! detection on the execution path either.

#[cfg(any(unix, windows))]
use std::io::BufRead as _;
use std::io::Write as _;
use std::process::Command;

use tirith_core::commands_manifest::{CommandsManifest, DangerousAction, ManifestError};

struct CommandsInvocationOutput {
    cwd: String,
    output_dlp: tirith_core::redact::CompiledCustomPatterns,
    /// Keeps policy diagnostics captured for the entire invocation. Structured
    /// responses drain into one JSON object; `list`/`run` human responses drain
    /// into their one invocation-level presentation writer.
    _policy_diagnostic_capture: Option<tirith_core::policy::PolicyDiagnosticCapture>,
}

/// Resolve cwd once and freeze one authoritative full-policy DLP plan before
/// any repo-controlled manifest, shell, path, or reconstruction error reaches
/// an output boundary. JSON additionally captures policy diagnostics into its
/// one envelope. A cwd failure still gets the global/remote replacement policy
/// via `Policy::discover(None)` rather than an empty-pattern fallback.
fn prepare_commands_invocation(
    json: bool,
    subcommand: &str,
    cwd_error_exit_code: i32,
) -> Result<CommandsInvocationOutput, i32> {
    let diagnostic_capture = Some(tirith_core::policy::PolicyDiagnosticCapture::start());
    let cwd = match std::env::current_dir() {
        Ok(path) => path.display().to_string(),
        Err(error) => {
            let output_dlp = discover_commands_output_dlp(json, None);
            let wrote = emit_commands_error(
                json,
                subcommand,
                &format!("could not resolve the current working directory: {error}"),
                cwd_error_exit_code,
                Some(&output_dlp),
            );
            return Err(if wrote { cwd_error_exit_code } else { 2 });
        }
    };
    let output_dlp = discover_commands_output_dlp(json, Some(&cwd));
    // `list` and `run` defer the drain into their one invocation-level human
    // writer. Draining here would create a second independently bounded output
    // stream and let a large catalogue/verdict exceed the presentation cap.
    if !json && !matches!(subcommand, "list" | "run") {
        emit_commands_policy_diagnostics_human(subcommand, &output_dlp);
    }
    Ok(CommandsInvocationOutput {
        cwd,
        output_dlp,
        _policy_diagnostic_capture: diagnostic_capture,
    })
}

fn discover_commands_output_dlp(
    _json: bool,
    cwd: Option<&str>,
) -> tirith_core::redact::CompiledCustomPatterns {
    let policy = tirith_core::policy::Policy::discover(cwd);
    tirith_core::policy::freeze_captured_policy_dlp_patterns(&policy.dlp_custom_patterns);
    tirith_core::redact::CompiledCustomPatterns::new_silent(&policy.dlp_custom_patterns)
}

/// `tirith commands init` — write the starter `.tirith/commands.yaml`. Refuses to
/// overwrite an existing file unless `force` is set.
pub fn init(force: bool, json: bool) -> i32 {
    let invocation = match prepare_commands_invocation(json, "init", 1) {
        Ok(invocation) => invocation,
        Err(exit_code) => return exit_code,
    };

    let path = match tirith_core::commands_manifest::init_manifest_path(Some(&invocation.cwd)) {
        Some(p) => p,
        None => {
            // Broken-pipe JSON write → 2; otherwise the semantic 1.
            if !emit_commands_error(
                json,
                "init",
                "could not resolve a target directory for .tirith/commands.yaml",
                1,
                Some(&invocation.output_dlp),
            ) {
                return 2;
            }
            return 1;
        }
    };
    let Some(repo_root) = path.parent().and_then(std::path::Path::parent) else {
        if !emit_commands_error(
            json,
            "init",
            "resolved manifest path has no repository root",
            1,
            Some(&invocation.output_dlp),
        ) {
            return 2;
        }
        return 1;
    };

    if path.exists() && !force {
        if !emit_commands_error(
            json,
            "init",
            &format!(
                "{} already exists; pass --force to overwrite",
                path.display()
            ),
            1,
            Some(&invocation.output_dlp),
        ) {
            return 2;
        }
        return 1;
    }

    if let Some(parent) = path.parent() {
        // If `.tirith` is created fresh, fsync its entry in the repo root too:
        // `write_file_atomic` only fsyncs commands.yaml's parent, so a crash could
        // otherwise lose the whole `.tirith` dir despite init succeeding (CodeRabbit R13b).
        let parent_existed = parent.is_dir();
        if let Err(e) = tirith_core::util::create_dir_durable(parent) {
            if !emit_commands_error(
                json,
                "init",
                &format!("create {}: {e}", parent.display()),
                1,
                Some(&invocation.output_dlp),
            ) {
                return 2;
            }
            return 1;
        }
        if !parent_existed {
            tirith_core::util::fsync_parent_dir_logged(parent, "commands .tirith directory");
        }
    }

    // Write ATOMICALLY (temp → fsync → rename → parent fsync), not truncate-in-
    // place, so a crash can't lose or half-write the manifest. No-clobber unless
    // `--force` so a manifest created in the post-`exists()` race window survives.
    //
    // C12: the commands manifest is a Tirith-owned configuration file, so its
    // publication goes through the gated single-use permit. It governs which
    // commands are allowed, not Tirith's policy document itself, so it is not
    // flagged as a policy change.
    let operator_policy = tirith_core::policy::Policy::discover_local_only(Some(&invocation.cwd));
    if let Err(e) = super::write_config_file_permitted(
        repo_root,
        &path,
        tirith_core::commands_manifest::STARTER_MANIFEST.as_bytes(),
        force,
        &operator_policy,
        false,
    ) {
        if !emit_commands_error(
            json,
            "init",
            &format!("write {}: {e}", path.display()),
            1,
            Some(&invocation.output_dlp),
        ) {
            return 2;
        }
        return 1;
    }

    if json {
        let written =
            manifest_field_for_output(&path.display().to_string(), &invocation.output_dlp);
        let mut v = serde_json::json!({
            "written": written,
            "forced": force,
        });
        append_commands_policy_diagnostics(&mut v, &invocation.output_dlp);
        tirith_core::redact::redact_json_strings(&mut v, &invocation.output_dlp);
        let v = tirith_core::verdict::bound_json_value_for_output(v);
        // A failed JSON write must exit non-zero: the manifest WAS written, but a
        // consumer that saw truncated JSON must not also read success.
        if !super::write_json_stdout(&v, "tirith commands init: failed to write JSON output") {
            return 2;
        }
    } else {
        let path = manifest_field_for_output(&path.display().to_string(), &invocation.output_dlp);
        println!("Wrote starter command manifest to {path}");
        eprintln!("Edit it, then `tirith commands list` to review the catalogue.");
    }
    0
}

/// `tirith commands list` — print the manifest's catalogue.
pub fn list(json: bool) -> i32 {
    let invocation = match prepare_commands_invocation(json, "list", 1) {
        Ok(invocation) => invocation,
        Err(exit_code) => return exit_code,
    };

    let manifest = match CommandsManifest::discover(Some(&invocation.cwd)) {
        Ok(Some(m)) => m,
        Ok(None) => {
            if json {
                let mut v = serde_json::json!({ "manifest": null, "allowed": [], "dangerous": [] });
                append_commands_policy_diagnostics(&mut v, &invocation.output_dlp);
                tirith_core::redact::redact_json_strings(&mut v, &invocation.output_dlp);
                let v = tirith_core::verdict::bound_json_value_for_output(v);
                // A failed JSON write must surface non-zero (no truncated JSON + success).
                if !super::write_json_stdout(
                    &v,
                    "tirith commands list: failed to write JSON output",
                ) {
                    return 2;
                }
            } else if write_commands_list_human(None, &invocation.output_dlp).is_err() {
                return 2;
            }
            return 0;
        }
        Err(e) => {
            if !emit_commands_error(
                json,
                "list",
                &manifest_err(&e),
                1,
                Some(&invocation.output_dlp),
            ) {
                return 2;
            }
            return 1;
        }
    };

    if json {
        let allowed: Vec<_> = manifest
            .allowed
            .iter()
            .map(|e| {
                serde_json::json!({
                    "name": manifest_field_for_output(&e.name, &invocation.output_dlp),
                    "command": manifest_command_for_output(&e.command, &invocation.output_dlp),
                })
            })
            .collect();
        let dangerous: Vec<_> = manifest
            .dangerous
            .iter()
            .map(|e| {
                serde_json::json!({
                    "pattern": manifest_field_for_output(&e.pattern, &invocation.output_dlp),
                    "action": dangerous_action_label(e.action),
                })
            })
            .collect();
        let mut v = serde_json::json!({ "allowed": allowed, "dangerous": dangerous });
        append_commands_policy_diagnostics(&mut v, &invocation.output_dlp);
        tirith_core::redact::redact_json_strings(&mut v, &invocation.output_dlp);
        let v = tirith_core::verdict::bound_json_value_for_output(v);
        // A failed JSON write must surface non-zero (no truncated catalogue + success).
        if !super::write_json_stdout(&v, "tirith commands list: failed to write JSON output") {
            return 2;
        }
    } else if write_commands_list_human(Some(&manifest), &invocation.output_dlp).is_err() {
        return 2;
    }
    0
}

/// Render the complete human `commands list` response through one final-byte
/// budget. Repository-controlled rows are still projected one at a time, so a
/// near-cap manifest never needs a second attacker-sized presentation buffer.
fn write_commands_list_human(
    manifest: Option<&CommandsManifest>,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> std::io::Result<()> {
    write_commands_list_human_to(
        manifest,
        compiled,
        std::io::stdout().lock(),
        std::io::stderr().lock(),
    )
}

#[derive(Clone, Copy)]
enum CommandsListHumanStream {
    Diagnostics,
    Catalogue,
}

struct CommandsListHumanSink<'a, O, E> {
    stdout: O,
    stderr: E,
    stream: &'a std::cell::Cell<CommandsListHumanStream>,
}

impl<O: std::io::Write, E: std::io::Write> std::io::Write for CommandsListHumanSink<'_, O, E> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self.stream.get() {
            CommandsListHumanStream::Diagnostics => self.stderr.write(bytes),
            CommandsListHumanStream::Catalogue => self.stdout.write(bytes),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stderr.flush()?;
        self.stdout.flush()
    }
}

fn write_commands_list_human_to<O: std::io::Write, E: std::io::Write>(
    manifest: Option<&CommandsManifest>,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
    stdout: O,
    stderr: E,
) -> std::io::Result<()> {
    let stream = std::cell::Cell::new(CommandsListHumanStream::Diagnostics);
    let sink = CommandsListHumanSink {
        stdout,
        stderr,
        stream: &stream,
    };
    let mut output = tirith_core::output::HumanInvocationWriter::new(sink, false);
    write_commands_policy_diagnostics_human_to("list", compiled, &mut output)?;
    // If diagnostics alone consume the invocation budget, finish while the
    // diagnostic route is still active. The receipt belongs on stderr and
    // stdout must remain an uncontaminated (here empty) catalogue stream.
    if output.is_truncated() {
        return output.finish();
    }
    stream.set(CommandsListHumanStream::Catalogue);

    let Some(manifest) = manifest else {
        writeln!(
            output,
            "No .tirith/commands.yaml found for this repo. Run `tirith commands init` to create one."
        )?;
        return output.finish();
    };

    if manifest.allowed.is_empty() {
        writeln!(output, "allowed: (none)")?;
    } else {
        writeln!(output, "allowed:")?;
        for entry in &manifest.allowed {
            let name = manifest_field_for_output(&entry.name, compiled);
            let command = manifest_command_for_output(&entry.command, compiled);
            writeln!(output, "  {name:<16} {command}")?;
        }
    }
    if manifest.dangerous.is_empty() {
        writeln!(output, "dangerous: (none)")?;
    } else {
        writeln!(output, "dangerous:")?;
        for entry in &manifest.dangerous {
            let pattern = manifest_field_for_output(&entry.pattern, compiled);
            writeln!(
                output,
                "  {:<7} {pattern}",
                dangerous_action_label(entry.action)
            )?;
        }
    }
    output.finish()
}

/// `tirith commands run <name>` — execute the `allowed[]` command `name` after
/// re-checking it through the engine.
///
/// SECURITY: `allowed[]` only suppresses the `repo_command_unknown` annotation;
/// it does NOT make a command safe to run blindly. We re-run the resolved command
/// through the engine, REFUSE to execute on a block, and require trusted
/// acknowledgement for warnings — keeping "manifest cannot bypass detection" on
/// the execution path too.
pub fn run(name: &str, yes: bool, json: bool) -> i32 {
    let invocation = match prepare_commands_invocation(json, "run", 1) {
        Ok(invocation) => invocation,
        Err(exit_code) => return exit_code,
    };

    let manifest = match CommandsManifest::discover(Some(&invocation.cwd)) {
        Ok(Some(m)) => m,
        Ok(None) => {
            if !emit_commands_error(
                json,
                "run",
                "no .tirith/commands.yaml found for this repo (run `tirith commands init`)",
                1,
                Some(&invocation.output_dlp),
            ) {
                return 2;
            }
            return 1;
        }
        Err(e) => {
            if !emit_commands_error(
                json,
                "run",
                &manifest_err(&e),
                1,
                Some(&invocation.output_dlp),
            ) {
                return 2;
            }
            return 1;
        }
    };

    let entry = match manifest.allowed.iter().find(|e| e.name == name) {
        Some(e) => e,
        None => {
            // JSON is a structured data boundary and preserves the exact lookup
            // key/catalogue values. Human diagnostics are a terminal boundary:
            // scrub both the CLI-provided key and every repo-controlled name.
            let display_name = if json {
                name.to_string()
            } else {
                manifest_field_for_output(name, &invocation.output_dlp)
            };
            let names: Vec<String> = manifest
                .allowed
                .iter()
                .map(|entry| {
                    if json {
                        entry.name.clone()
                    } else {
                        manifest_field_for_output(&entry.name, &invocation.output_dlp)
                    }
                })
                .collect();
            if !emit_commands_error(
                json,
                "run",
                &format!(
                    "no allowed command named '{display_name}'. Available: {}",
                    if names.is_empty() {
                        "(none)".to_string()
                    } else {
                        names.join(", ")
                    }
                ),
                1,
                Some(&invocation.output_dlp),
            ) {
                return 2;
            }
            return 1;
        }
    };
    let command = entry.command.clone();

    // Re-check through the engine; refuse to run on a block (the manifest cannot
    // bypass detection). The engine also returns the policy it resolved (CodeRabbit
    // R18 #2), reused below for audit/redaction instead of a second `Policy::discover`.
    let (verdict, policy) = analyze_command(&command, Some(&invocation.cwd));
    tirith_core::policy::freeze_captured_policy_dlp_patterns(&policy.dlp_custom_patterns);
    let run_output_patterns =
        tirith_core::policy::captured_policy_dlp_patterns_or(&policy.dlp_custom_patterns);
    let run_output_dlp =
        tirith_core::redact::CompiledCustomPatterns::new_silent(&run_output_patterns);
    let stderr = std::io::stderr();
    let mut human_output = (!json).then(|| {
        tirith_core::output::HumanInvocationWriter::new(
            stderr.lock(),
            tirith_core::style::use_color_for(tirith_core::style::Stream::Stderr),
        )
    });
    let mut human_write_failed = false;
    if let Some(output) = human_output.as_mut() {
        human_write_failed |=
            write_commands_policy_diagnostics_human_to("run", &run_output_dlp, output).is_err();
    }
    if verdict.action == tirith_core::verdict::Action::Block {
        // Audit the refusal so the blocked attempt is traceable.
        let _ = tirith_core::audit::log_verdict(
            &verdict,
            &command,
            None,
            None,
            &policy.dlp_custom_patterns,
        );
        if json {
            // ONE combined JSON object (verdict + refusal), never two concatenated
            // documents. REDACT the command in the refusal message (CodeRabbit R13
            // #6): it lands in the machine-readable `error` field, so a raw command
            // would leak credentials even though `command`/`findings` are scrubbed.
            let redacted_command = manifest_command_for_output(&command, &run_output_dlp);
            let refusal = block_refusal_message(name, &redacted_command);
            // If the write fails the single-object `--json` contract is broken, so
            // report exit 2 rather than the block code (nothing reached the caller).
            let wrote = emit_run_json(
                name,
                &command,
                &verdict,
                &run_output_dlp,
                /* running */ false,
                /* refused */ true,
                Some(&refusal),
            );
            return json_refusal_exit_code(wrote, verdict.action.exit_code());
        } else {
            // Human: findings then refusal to stderr (mirroring `tirith check`).
            // Both manifest fields cross a terminal boundary and must be scrubbed;
            // execution still receives the exact raw command cloned above.
            let display_name = manifest_field_for_output(name, &run_output_dlp);
            let display_command = manifest_command_for_output(&command, &run_output_dlp);
            let refusal = block_refusal_message(&display_name, &display_command);
            let mut output = human_output
                .take()
                .expect("human commands run owns one presentation writer");
            human_write_failed |=
                render_findings_into(&verdict, &run_output_dlp, &mut output).is_err();
            let line = format!("tirith commands run: {refusal}");
            if !finish_commands_run_human(output, Some(&line), human_write_failed) {
                return 2;
            }
        }
        return verdict.action.exit_code();
    }

    // NOTE: the "command ran" audit is DEFERRED (CodeRabbit R18 #1) — written only
    // after the warn ack passes AND the spawn succeeds (see `audit_run`), so a
    // declined warn / failed spawn never records a run. The BLOCK refusal above is
    // still audited where it is.

    // A Warn/WarnAck on an allowed command must NOT be swallowed: render findings
    // like `tirith check`, then require either an explicit automation opt-in
    // (`--yes`) or an acknowledgement read from the controlling terminal. Piped
    // stdin and environment variables are never trusted as approval. In JSON mode
    // findings are folded into the one combined object below.
    if verdict.action != tirith_core::verdict::Action::Allow {
        if let Some(output) = human_output.as_mut() {
            human_write_failed |= render_findings_into(&verdict, &run_output_dlp, output).is_err();
        }

        if !yes {
            // Interactive approval is invalid if its supporting findings were
            // truncated. Finish first so the omission receipt and ANSI reset
            // are visible, then refuse without ever presenting a prompt.
            if !json {
                let output = human_output
                    .as_mut()
                    .expect("human commands run owns one presentation writer");
                human_write_failed |= output.flush().is_err();
                if output.is_truncated() || human_write_failed {
                    let output = human_output
                        .take()
                        .expect("human commands run owns one presentation writer");
                    let finished = finish_commands_run_human(output, None, human_write_failed);
                    return if finished {
                        verdict.action.exit_code()
                    } else {
                        2
                    };
                }
            }
            match confirm_warn_on_controlling_terminal(
                name,
                verdict.findings.len(),
                &run_output_dlp,
            ) {
                Ok(true) => {}
                Ok(false) => {
                    if !json {
                        let output = human_output
                            .take()
                            .expect("human commands run owns one presentation writer");
                        return if finish_commands_run_human(
                            output,
                            Some("tirith commands run: aborted by user."),
                            human_write_failed,
                        ) {
                            1
                        } else {
                            2
                        };
                    }
                    return refuse_warn_run_json(
                        name,
                        &command,
                        &verdict,
                        &run_output_dlp,
                        "aborted by user",
                        1,
                    );
                }
                Err(error) => {
                    let error = super::sanitize_for_human_output(&error, false);
                    let refusal = format!(
                        "refusing warning-producing command because trusted controlling-terminal confirmation is unavailable ({error}); rerun from an interactive terminal or pass --yes for intentional automation"
                    );
                    if !json {
                        let reason = tirith_core::redact::redact_sanitize_redact_with_compiled(
                            &refusal,
                            &run_output_dlp,
                        );
                        let line = format!("tirith commands run: {reason}.");
                        let output = human_output
                            .take()
                            .expect("human commands run owns one presentation writer");
                        return if finish_commands_run_human(output, Some(&line), human_write_failed)
                        {
                            verdict.action.exit_code()
                        } else {
                            2
                        };
                    }
                    return refuse_warn_run_json(
                        name,
                        &command,
                        &verdict,
                        &run_output_dlp,
                        &refusal,
                        verdict.action.exit_code(),
                    );
                }
            }
        }
    }

    if json {
        // SPAWN FIRST, then emit the single document reflecting the ACTUAL outcome
        // (CodeRabbit R17 #3): a `running:true` written before the spawn would lie
        // on a spawn failure. spawn fails → `running:false` + error; spawn OK →
        // `running:true`, then wait for exit.
        let spawned = match spawn_shell_command_json(&command) {
            Ok(s) => s,
            Err(e) => {
                // Never started: emit ONE `running:false` object with the error. A
                // failed write reports exit 2 (broken contract), not the spawn code 1.
                let wrote = emit_run_json(
                    name,
                    &command,
                    &verdict,
                    &run_output_dlp,
                    /* running */ false,
                    /* refused */ false,
                    Some(&format!("failed to spawn command: {e}")),
                );
                return json_refusal_exit_code(wrote, 1);
            }
        };

        // Spawn SUCCEEDED — audit the actual execution now (CodeRabbit R18 #1); a
        // declined warn / spawn failure returned above, so a non-run is never audited.
        audit_run(&verdict, &command, &policy.dlp_custom_patterns);

        // Emit the single `running:true` object. If THIS write fails the consumer
        // saw a truncated record, so KILL + reap the child and report exit 2 rather
        // than let it run to completion (round-9/15 contract).
        if !emit_run_json(
            name,
            &command,
            &verdict,
            &run_output_dlp,
            /* running */ true,
            /* refused */ false,
            None,
        ) {
            spawned.kill_and_reap();
            return 2;
        }

        // One JSON document on stdout; wait for the child and return its exit code
        // (a rare wait failure reports only to stderr to keep stdout one document).
        match spawned.wait() {
            Ok(code) => code,
            Err(e) => {
                let error = tirith_core::redact::redact_sanitize_redact_with_compiled(
                    &e.to_string(),
                    &run_output_dlp,
                );
                eprintln!("tirith commands run: failed to wait on command: {error}");
                1
            }
        }
    } else {
        // The repo controls both fields. Render a terminal-safe projection in
        // the banner while passing the untouched command to the shell below.
        let display_name = manifest_field_for_output(name, &run_output_dlp);
        let display_command = manifest_command_for_output(&command, &run_output_dlp);
        let mut output = human_output
            .take()
            .expect("human commands run owns one presentation writer");
        human_write_failed |= writeln!(
            output,
            "Running allowed command '{display_name}': {display_command}"
        )
        .is_err();
        human_write_failed |= output.flush().is_err();
        if human_write_failed {
            let _ = output.finish();
            return 2;
        }
        // SPAWN first so the audit fires only after a successful spawn (CodeRabbit
        // R18 #1): a spawn failure must not record a run.
        match build_shell_command(&command).spawn() {
            Ok(mut child) => {
                audit_run(&verdict, &command, &policy.dlp_custom_patterns);
                let exit_code = match child.wait() {
                    Ok(status) => status.code().unwrap_or(128),
                    Err(e) => {
                        let error = tirith_core::redact::redact_sanitize_redact_with_compiled(
                            &e.to_string(),
                            &run_output_dlp,
                        );
                        human_write_failed |= writeln!(
                            output,
                            "tirith commands run: failed to wait on command: {error}"
                        )
                        .is_err();
                        1
                    }
                };
                if finish_commands_run_human(output, None, human_write_failed) {
                    exit_code
                } else {
                    2
                }
            }
            Err(e) => {
                let error = tirith_core::output::sanitize_human_field_with_compiled(
                    &format!("failed to spawn command: {e}"),
                    &run_output_dlp,
                );
                let line = format!("tirith commands run: {error}");
                if finish_commands_run_human(output, Some(&line), human_write_failed) {
                    1
                } else {
                    2
                }
            }
        }
    }
}

/// Prompt for a Warn/WarnAck acknowledgement through an OS-owned controlling
/// terminal channel. This intentionally never reads process stdin: a pipeline,
/// redirected file, or caller-controlled `TIRITH_INTERACTIVE` value is not
/// operator authorization.
#[cfg(unix)]
fn confirm_warn_on_controlling_terminal(
    name: &str,
    finding_count: usize,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> Result<bool, String> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NOFOLLOW)
        .open("/dev/tty")
        .map_err(|error| format!("open /dev/tty: {error}"))?;
    let fd = tty.as_raw_fd();
    if unsafe { libc::isatty(fd) } != 1 {
        return Err("/dev/tty is not a terminal".to_string());
    }

    let foreground_group = loop {
        let group = unsafe { libc::tcgetpgrp(fd) };
        if group >= 0 {
            break group;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(format!(
                "read controlling-terminal foreground process group: {error}"
            ));
        }
    };
    if foreground_group != unsafe { libc::getpgrp() } {
        return Err("tirith is not in the controlling terminal foreground process group".into());
    }

    let display_name = manifest_field_for_output(name, compiled);
    write!(
        tty,
        "tirith: proceed with {finding_count} warning(s) and run '{display_name}'? [y/N] "
    )
    .map_err(|error| format!("write controlling-terminal prompt: {error}"))?;
    tty.flush()
        .map_err(|error| format!("flush controlling-terminal prompt: {error}"))?;

    let mut input = String::new();
    let bytes = std::io::BufReader::new(tty)
        .read_line(&mut input)
        .map_err(|error| format!("read controlling-terminal confirmation: {error}"))?;
    if bytes == 0 {
        return Err("controlling terminal closed before confirmation".to_string());
    }
    let input = input.trim();
    Ok(input.eq_ignore_ascii_case("y") || input.eq_ignore_ascii_case("yes"))
}

#[cfg(windows)]
fn confirm_warn_on_controlling_terminal(
    name: &str,
    finding_count: usize,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> Result<bool, String> {
    let input = std::fs::OpenOptions::new()
        .read(true)
        .open("CONIN$")
        .map_err(|error| format!("open Windows console input: {error}"))?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .open("CONOUT$")
        .map_err(|error| format!("open Windows console output: {error}"))?;
    if !is_terminal::is_terminal(&input) || !is_terminal::is_terminal(&output) {
        return Err("Windows console handles are not interactive terminals".to_string());
    }

    let display_name = manifest_field_for_output(name, compiled);
    write!(
        output,
        "tirith: proceed with {finding_count} warning(s) and run '{display_name}'? [y/N] "
    )
    .map_err(|error| format!("write Windows console prompt: {error}"))?;
    output
        .flush()
        .map_err(|error| format!("flush Windows console prompt: {error}"))?;

    let mut response = String::new();
    let bytes = std::io::BufReader::new(input)
        .read_line(&mut response)
        .map_err(|error| format!("read Windows console confirmation: {error}"))?;
    if bytes == 0 {
        return Err("Windows console closed before confirmation".to_string());
    }
    let response = response.trim();
    Ok(response.eq_ignore_ascii_case("y") || response.eq_ignore_ascii_case("yes"))
}

#[cfg(not(any(unix, windows)))]
fn confirm_warn_on_controlling_terminal(
    _name: &str,
    _finding_count: usize,
    _compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> Result<bool, String> {
    Err("trusted controlling-terminal confirmation is unsupported on this platform".to_string())
}

/// Refuse a warning-producing command while preserving `commands run --json`'s
/// one-object stdout contract. A write failure overrides the semantic refusal
/// code because the machine-readable contract did not reach the caller intact.
fn refuse_warn_run_json(
    name: &str,
    command: &str,
    verdict: &tirith_core::verdict::Verdict,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
    reason: &str,
    refusal_code: i32,
) -> i32 {
    let wrote = emit_run_json(
        name,
        command,
        verdict,
        compiled,
        /* running */ false,
        /* refused */ true,
        Some(reason),
    );
    json_refusal_exit_code(wrote, refusal_code)
}

/// Audit an executing allowed command run, called only AFTER the spawn succeeds
/// (CodeRabbit R18 #1) so a declined warn / failed spawn never records a run.
/// Best-effort: a write failure must not change the exit code.
fn audit_run(
    verdict: &tirith_core::verdict::Verdict,
    command: &str,
    dlp_custom_patterns: &[String],
) {
    let _ = tirith_core::audit::log_verdict(verdict, command, None, None, dlp_custom_patterns);
}

/// Map a refusal-path JSON write result to the exit code: the refusal code on a
/// clean write, else exit 2 (the broken single-object `--json` contract). Pure so
/// the contract is unit-testable without a deterministically-failing stdout.
fn json_refusal_exit_code(wrote_ok: bool, refusal_code: i32) -> i32 {
    if wrote_ok {
        refusal_code
    } else {
        2
    }
}

/// Format the block-refusal message. `command_for_display` is what the caller
/// deems safe to surface: DLP-redacted on the JSON path (it lands in the
/// machine-readable `error` field — CodeRabbit R13 #6), terminal-sanitized on
/// the human path. Pure so each caller's projection is unit-testable.
fn block_refusal_message(name: &str, command_for_display: &str) -> String {
    format!(
        "refusing to run '{name}' ({command_for_display}): tirith blocked it. \
         Inspect with `tirith commands check -- \"{command_for_display}\"`."
    )
}

/// Emit the single combined `commands run --json` object; returns whether the
/// write succeeded. The ONLY JSON writer on the `commands run` stdout path, so a
/// consumer always reads exactly one parseable object.
///
/// Shape: `{"name","command","action","findings":[...],"running":bool,
/// "refused":bool,"error":null|"..."}` (findings DLP-redacted).
fn emit_run_json(
    name: &str,
    command: &str,
    verdict: &tirith_core::verdict::Verdict,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
    running: bool,
    refused: bool,
    error: Option<&str>,
) -> bool {
    let mut v =
        build_run_json_with_compiled(name, command, verdict, compiled, running, refused, error);
    append_commands_policy_diagnostics(&mut v, compiled);
    tirith_core::redact::redact_json_strings(&mut v, compiled);
    let v = tirith_core::verdict::bound_json_value_for_output(v);
    super::write_json_stdout(&v, "tirith commands run: failed to write JSON output")
}

/// Build the `commands run --json` object. Pure (no I/O) so the redaction
/// contract is unit-testable. BOTH `findings` AND the top-level `command` are
/// DLP-scrubbed — a raw `command` would leak credentials even though `findings`
/// is redacted.
#[cfg(test)]
fn build_run_json(
    name: &str,
    command: &str,
    verdict: &tirith_core::verdict::Verdict,
    dlp_custom_patterns: &[String],
    running: bool,
    refused: bool,
    error: Option<&str>,
) -> serde_json::Value {
    // Compile the frozen policy's DLP plan exactly once, then use it for every
    // attacker/repo-controlled string in this DTO. The complete raw verdict
    // remains untouched for decision and audit callers.
    let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(dlp_custom_patterns);
    build_run_json_with_compiled(name, command, verdict, &compiled, running, refused, error)
}

fn build_run_json_with_compiled(
    name: &str,
    command: &str,
    verdict: &tirith_core::verdict::Verdict,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
    running: bool,
    refused: bool,
    error: Option<&str>,
) -> serde_json::Value {
    let presentation = crate::cli::prepare_verdict_presentation(verdict, compiled);
    let redacted_name = manifest_field_for_output(name, compiled);
    let redacted_command = manifest_command_for_output(command, compiled);
    let redacted_error = error
        .map(|value| tirith_core::redact::redact_sanitize_redact_with_compiled(value, compiled));
    let mut value = serde_json::json!({
        "name": redacted_name,
        "command": redacted_command,
        "action": presentation.verdict.action,
        "findings": presentation.verdict.findings,
        "original_findings_count": presentation.original_findings_count,
        "presented_findings_count": presentation.presented_findings_count,
        "dropped_findings_count": presentation.dropped_findings_count,
        "running": running,
        "refused": refused,
        "error": redacted_error,
    });
    tirith_core::redact::redact_json_strings(&mut value, compiled);
    tirith_core::verdict::bound_json_value_for_output(value)
}

/// Render a non-Allow verdict into the caller-owned `commands run` human
/// presentation. Findings, policy diagnostics, refusal/banner text, and the
/// deterministic omission receipt therefore share one final-byte budget.
fn render_findings_into<W: std::io::Write>(
    verdict: &tirith_core::verdict::Verdict,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
    output: &mut tirith_core::output::HumanInvocationWriter<W>,
) -> std::io::Result<()> {
    tirith_core::output::write_human_to_invocation_with_compiled(
        verdict, /* warn_only */ false, compiled, output,
    )
}

fn finish_commands_run_human<W: std::io::Write>(
    mut output: tirith_core::output::HumanInvocationWriter<W>,
    final_line: Option<&str>,
    mut write_failed: bool,
) -> bool {
    if let Some(line) = final_line {
        write_failed |= writeln!(output, "{line}").is_err();
    }
    write_failed |= output.finish().is_err();
    !write_failed
}

/// `tirith commands check -- "<cmd>"` — evaluate `cmd` against the manifest +
/// engine by delegating to `tirith check` (which wires the manifest into its
/// normal analysis). Exit code is the engine's action exit code.
pub fn check(command_parts: &[String], shell: &str, json: bool) -> i32 {
    let invocation = match prepare_commands_invocation(json, "check", 2) {
        Ok(invocation) => invocation,
        Err(exit_code) => return exit_code,
    };
    let shell_type = match shell.parse::<tirith_core::tokenize::ShellType>() {
        Ok(shell_type) => shell_type,
        Err(_) => {
            let reason = format!("unknown shell '{shell}'");
            let _ = emit_commands_error(json, "check", &reason, 2, Some(&invocation.output_dlp));
            return 2;
        }
    };
    let cmd = match super::reconstruct_shell_command(command_parts, shell_type) {
        Ok(command) => command,
        Err(reason) => {
            let _ = emit_commands_error(json, "check", reason, 2, Some(&invocation.output_dlp));
            return 2;
        }
    };
    // Reuse the exact `tirith check` path — no divergent second code path.
    super::check::run(
        &cmd, shell_type, json, /* non_interactive */ false,
        /* interactive_flag */ false, /* approval_check */ false,
        /* execution_receipt */ None, /* strict_warn */ false, /* no_daemon */ true,
        /* warn_only */ false, /* defer */ false, /* offline */ false,
        /* suggest_safe_command */ false, /* card */ None,
    )
}

/// The [`ShellType`](tirith_core::tokenize::ShellType) the safety re-check
/// tokenizes with — MUST match the shell `build_shell_command` executes
/// (`cmd /C` on Windows, deterministic POSIX `/bin/sh -c` elsewhere), else a
/// mis-tokenized pipe/operator could miss findings.
#[cfg(windows)]
const RUN_SHELL: tirith_core::tokenize::ShellType = tirith_core::tokenize::ShellType::Cmd;
#[cfg(not(windows))]
const RUN_SHELL: tirith_core::tokenize::ShellType = tirith_core::tokenize::ShellType::Posix;

/// Analyze `command` for `commands run`'s safety re-check, returning the verdict
/// AND the engine-resolved policy. Reusing that policy (CodeRabbit R18 #2) lets
/// `run()` skip a second `Policy::discover` for audit/redaction; mirrors `check.rs`.
fn analyze_command(
    command: &str,
    cwd: Option<&str>,
) -> (tirith_core::verdict::Verdict, tirith_core::policy::Policy) {
    use tirith_core::engine::{self, AnalysisContext};
    use tirith_core::extract::ScanContext;

    let ctx = AnalysisContext {
        input: command.to_string(),
        // Match the shell that runs the command (see RUN_SHELL).
        shell: RUN_SHELL,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: false,
        cwd: cwd.map(str::to_string),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::Unread,
    };
    engine::analyze_returning_policy(&ctx)
}

/// Build the platform shell command for `command`. The shell family MUST match
/// what [`analyze_command`] tokenized with ([`RUN_SHELL`]): a POSIX `sh -c` (NOT
/// `$SHELL -c`, which may be fish/csh with different semantics) on non-Windows,
/// `cmd /C` on Windows — else the re-check parses a different command than runs.
fn build_shell_command(command: &str) -> Command {
    if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(command);
        c
    } else {
        // POSIX `/bin/sh`, NOT `$SHELL`, to match `analyze_command`'s Posix analysis.
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(command);
        c
    }
}

/// A successfully-spawned `commands run --json` child plus its stdout-pump thread.
/// Separating SPAWN from WAIT (CodeRabbit R17 #3) lets the caller emit the JSON
/// document only after the spawn succeeded. Driven to completion by [`wait`]
/// (success) or [`kill_and_reap`] (write failure).
struct SpawnedJsonChild {
    child: std::process::Child,
    pump: Option<std::thread::JoinHandle<()>>,
}

impl SpawnedJsonChild {
    /// Wait for the child and join the stdout pump, returning its exit code (128
    /// if signal-killed with no code).
    fn wait(mut self) -> std::io::Result<i32> {
        let status = self.child.wait()?;
        if let Some(h) = self.pump.take() {
            // Join the pump so all output flushes before we return (the child has
            // exited, so its stdout is at EOF and the copy completes).
            let _ = h.join();
        }
        Ok(status.code().unwrap_or(128))
    }

    /// Best-effort kill + reap when the JSON write FAILED after the spawn
    /// (CodeRabbit R17 #3): a consumer that saw a truncated record must NOT have
    /// the command silently run to completion, so the spawned child is killed.
    fn kill_and_reap(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(h) = self.pump.take() {
            let _ = h.join();
        }
    }
}

/// Spawn `command` for the JSON path with its stdout PIPED to a helper thread that
/// copies it to tirith's stderr (so large output can't deadlock by filling the
/// pipe, and stdout stays one JSON document). Stderr inherited. Returns the
/// running child + pump, or the spawn error (mapped to a `running:false` object).
fn spawn_shell_command_json(command: &str) -> std::io::Result<SpawnedJsonChild> {
    use std::process::Stdio;
    let mut cmd = build_shell_command(command);
    cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());
    let mut child = cmd.spawn()?;
    let pump = child.stdout.take().map(|mut out| {
        std::thread::spawn(move || {
            pump_stdout_draining(&mut out, &mut std::io::stderr());
        })
    });
    Ok(SpawnedJsonChild { child, pump })
}

/// Forward the child's stdout (`reader`) to tirith's stderr (`writer`) to EOF.
///
/// NOT [`std::io::copy`], which stops on the first writer error: if stderr breaks
/// while the child keeps writing, stopping the read would fill the child's stdout
/// pipe and block it forever (hanging `child.wait()` — CodeRabbit R15 #4). On a
/// writer error we drop to DRAIN-ONLY: keep reading to EOF, just stop forwarding.
fn pump_stdout_draining<R: std::io::Read, W: std::io::Write>(reader: &mut R, writer: &mut W) {
    let mut buf = [0u8; 8 * 1024];
    let mut forwarding = true;
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break, // EOF — the child closed its stdout.
            Ok(n) => {
                if forwarding && writer.write_all(&buf[..n]).is_err() {
                    // Stderr is gone: stop forwarding but keep draining.
                    forwarding = false;
                }
            }
            // Retry an interrupted read; any other error means the pipe is gone.
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

/// Stable per-entry label for a `dangerous[]` action (hardcoding "block" would
/// misreport a `Warn` entry).
fn dangerous_action_label(action: DangerousAction) -> &'static str {
    match action {
        DangerousAction::Block => "block",
        DangerousAction::Warn => "warn",
    }
}

/// Safe projection for a repo-controlled manifest field shared by structured
/// and human outputs. The second redaction catches secrets that only become
/// contiguous after ANSI/invisible-control sanitization.
fn manifest_field_for_output(
    value: &str,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> String {
    tirith_core::output::sanitize_human_field_with_compiled(value, compiled)
}

/// Preserve command-specific assignment scrubbing, then apply the shared
/// redact-sanitize-redact boundary to catch split tokens and terminal controls.
fn manifest_command_for_output(
    value: &str,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> String {
    let redacted =
        tirith_core::redact::redact_sanitize_redact_command_with_compiled(value, compiled);
    tirith_core::output::sanitize_human_field_with_compiled(&redacted, compiled)
}

/// Preserve the complete manifest diagnostic until the shared output boundary
/// applies its frozen JSON DLP plan or terminal-safe human projection.
fn manifest_err(e: &ManifestError) -> String {
    format!("could not load .tirith/commands.yaml: {e}")
}

fn emit_commands_error(
    json: bool,
    subcommand: &str,
    message: &str,
    exit_code: i32,
    compiled: Option<&tirith_core::redact::CompiledCustomPatterns>,
) -> bool {
    if json {
        let value = build_commands_error_json(
            subcommand,
            message,
            exit_code,
            compiled.expect("commands JSON freezes one full-policy DLP plan"),
        );
        super::write_json_stdout(
            &value,
            &format!("tirith commands {subcommand}: failed to write JSON output"),
        )
    } else {
        let empty = tirith_core::redact::CompiledCustomPatterns::new_silent(&[]);
        let compiled = compiled.unwrap_or(&empty);
        let message = tirith_core::output::sanitize_human_field_with_compiled(message, compiled);
        let stderr = std::io::stderr();
        let mut output = tirith_core::output::HumanInvocationWriter::new(
            stderr.lock(),
            tirith_core::style::use_color_for(tirith_core::style::Stream::Stderr),
        );
        let mut failed =
            write_commands_policy_diagnostics_human_to(subcommand, compiled, &mut output).is_err();
        failed |= writeln!(output, "tirith commands {subcommand}: {message}").is_err();
        failed |= output.finish().is_err();
        !failed
    }
}

fn build_commands_error_json(
    subcommand: &str,
    message: &str,
    exit_code: i32,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> serde_json::Value {
    let error = tirith_core::redact::redact_sanitize_redact_with_compiled(message, compiled)
        .replace(['\r', '\n'], "");
    let mut value = serde_json::json!({
        "kind": "commands_error",
        "status": "error",
        "name": subcommand,
        "action": tirith_core::verdict::Action::Block,
        "analysis_complete": false,
        "analysis_incomplete": true,
        "running": false,
        "refused": true,
        "executed": false,
        "exit_code": exit_code,
        "error": error,
    });
    append_commands_policy_diagnostics(&mut value, compiled);
    tirith_core::redact::redact_json_strings(&mut value, compiled);
    tirith_core::verdict::bound_json_value_for_output(value)
}

fn append_commands_policy_diagnostics(
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
        .collect::<Vec<_>>();
    if let Some(object) = value.as_object_mut() {
        object.insert("policy_diagnostics_count".to_string(), count.into());
        object.insert(
            "policy_diagnostics".to_string(),
            serde_json::Value::Array(
                diagnostics
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
}

fn emit_commands_policy_diagnostics_human(
    subcommand: &str,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) {
    let stderr = std::io::stderr();
    let mut output = tirith_core::output::HumanInvocationWriter::new(
        stderr.lock(),
        tirith_core::style::use_color_for(tirith_core::style::Stream::Stderr),
    );
    let _ = write_commands_policy_diagnostics_human_to(subcommand, compiled, &mut output);
    let _ = output.finish();
}

fn write_commands_policy_diagnostics_human_to<W: std::io::Write>(
    subcommand: &str,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
    output: &mut tirith_core::output::HumanInvocationWriter<W>,
) -> std::io::Result<()> {
    for diagnostic in tirith_core::policy::drain_captured_policy_diagnostics_for_output(compiled) {
        let diagnostic =
            tirith_core::output::sanitize_human_field_with_compiled(&diagnostic, compiled);
        writeln!(
            output,
            "tirith commands {subcommand}: policy diagnostic: {diagnostic}"
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::RUN_SHELL;
    use tirith_core::tokenize::ShellType;

    #[test]
    fn run_shell_matches_execution_platform() {
        // F7: the re-check must tokenize with the SAME shell family
        // `build_shell_command` executes, else a mismatch can miss findings.
        #[cfg(windows)]
        assert_eq!(RUN_SHELL, ShellType::Cmd);
        #[cfg(not(windows))]
        assert_eq!(RUN_SHELL, ShellType::Posix);
    }

    /// F7: on non-Windows the analysis is Posix AND execution is hardwired to
    /// `/bin/sh`, independent of `$SHELL` (the function no longer reads it).
    #[cfg(not(windows))]
    #[test]
    fn execution_shell_is_posix_independent_of_env_shell() {
        assert_eq!(RUN_SHELL, ShellType::Posix);
        // `/bin/sh` exists on the unix runners we target.
        assert!(
            std::path::Path::new("/bin/sh").exists(),
            "the deterministic POSIX execution shell /bin/sh must exist"
        );
    }

    #[test]
    fn list_human_near_manifest_cap_has_one_deterministic_omission_receipt() {
        use tirith_core::commands_manifest::{AllowedEntry, CommandsManifest, DangerousEntry};

        let manifest = CommandsManifest {
            allowed: (0..260)
                .map(|index| AllowedEntry {
                    name: if index == 0 {
                        "build\nrow\u{1b}[31m".to_string()
                    } else {
                        format!("task-{index}")
                    },
                    command: format!("tool --label {}-{index}", "x".repeat(1_000)),
                })
                .collect(),
            dangerous: vec![DangerousEntry {
                pattern: "deploy\r*\u{202e}".to_string(),
                action: tirith_core::commands_manifest::DangerousAction::Warn,
            }],
        };
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&[]);

        let render = || {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            super::write_commands_list_human_to(
                Some(&manifest),
                &compiled,
                &mut stdout,
                &mut stderr,
            )
            .unwrap();
            assert!(stderr.is_empty());
            String::from_utf8(stdout).unwrap()
        };
        let first = render();
        let second = render();

        assert_eq!(first, second, "the omission byte receipt must be stable");
        assert!(first.len() < tirith_core::verdict::MAX_PRESENTATION_BYTES);
        assert_eq!(first.matches("[presentation truncated:").count(), 1);
        assert!(first.contains("allowed:\n"));
        assert!(
            first.contains(r"build\nrow"),
            "escaped row remains readable: {first:?}"
        );
        assert!(!first.contains('\u{1b}'));
        assert!(!first.contains('\u{202e}'));
    }

    #[test]
    fn list_human_keeps_policy_diagnostics_on_stderr_under_the_shared_budget() {
        let secret = "C02_COMMANDS_LIST_DIAGNOSTIC_SECRET";
        let split = format!("{}\u{1b}[31m{}", &secret[..16], &secret[16..]);
        let patterns = vec![regex::escape(secret)];
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&patterns);
        let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
        let _ = tirith_core::policy::Policy::load_from_yaml("[", Some(&split));
        tirith_core::policy::freeze_captured_policy_dlp_patterns(&patterns);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        super::write_commands_list_human_to(None, &compiled, &mut stdout, &mut stderr).unwrap();

        let stdout = String::from_utf8(stdout).unwrap();
        let stderr = String::from_utf8(stderr).unwrap();
        assert!(stdout.contains("No .tirith/commands.yaml found"));
        assert!(!stdout.contains("policy diagnostic"), "{stdout}");
        assert!(stderr.contains("policy diagnostic"), "{stderr}");
        assert!(!stderr.contains(secret), "{stderr}");
        assert!(!stderr.contains('\u{1b}'), "{stderr}");
    }

    #[test]
    fn list_human_diagnostic_truncation_receipt_stays_on_stderr() {
        let source = format!(
            "C02_COMMANDS_LIST_DIAGNOSTIC_FLOOD-{}",
            "x".repeat(tirith_core::verdict::MAX_PRESENTATION_BYTES * 2)
        );
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&[]);
        let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
        let _ = tirith_core::policy::Policy::load_from_yaml("[", Some(&source));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        super::write_commands_list_human_to(None, &compiled, &mut stdout, &mut stderr).unwrap();

        let stderr = String::from_utf8(stderr).unwrap();
        assert!(stdout.is_empty(), "diagnostics must not contaminate stdout");
        assert!(stderr.len() < tirith_core::verdict::MAX_PRESENTATION_BYTES);
        assert_eq!(stderr.matches("[presentation truncated:").count(), 1);
    }

    #[test]
    fn run_human_findings_and_final_line_share_one_budget() {
        use tirith_core::verdict::{Finding, RuleId, Severity, Timings, Verdict};

        let findings = (0..400)
            .map(|index| Finding {
                rule_id: RuleId::ConfigInjection,
                severity: Severity::High,
                title: format!("finding-{index}"),
                description: "detail".repeat(1_000),
                evidence: Vec::new(),
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            })
            .collect();
        let verdict = Verdict::from_findings(findings, 3, Timings::default());
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&[]);
        let mut bytes = Vec::new();
        let mut output = tirith_core::output::HumanInvocationWriter::new(&mut bytes, false);

        // Model a large earlier policy-diagnostic projection in the same
        // invocation. The bounded finding DTO alone is deliberately smaller
        // than the global presentation cap; the shared writer must still make
        // later warning details truncation visible before any prompt.
        writeln!(
            output,
            "{}",
            "diagnostic"
                .repeat((tirith_core::verdict::MAX_PRESENTATION_BYTES.saturating_sub(2_048)) / 10)
        )
        .unwrap();
        super::render_findings_into(&verdict, &compiled, &mut output).unwrap();
        assert!(
            output.is_truncated(),
            "interactive confirmation must be refused for this presentation"
        );
        assert!(super::finish_commands_run_human(
            output,
            Some("Running allowed command 'deploy': deploy --safe"),
            false,
        ));
        let rendered = String::from_utf8(bytes).unwrap();

        assert!(rendered.len() < tirith_core::verdict::MAX_PRESENTATION_BYTES);
        assert_eq!(rendered.matches("[presentation truncated:").count(), 1);
        assert!(rendered.contains("finding-0"));
    }

    /// CodeRabbit/Greptile R4 #4: on a `commands run --json` REFUSAL path, a FAILED
    /// JSON write overrides the refusal code with 2; a clean write preserves it.
    /// Factored into a pure helper since real stdout can't fail deterministically.
    #[test]
    fn json_refusal_exit_code_overrides_on_write_failure() {
        use super::json_refusal_exit_code;
        // Block-refuse path: clean write keeps the block code (1); failed → 2.
        assert_eq!(json_refusal_exit_code(true, 1), 1);
        assert_eq!(json_refusal_exit_code(false, 1), 2);
        // User-abort path passes refusal_code = 1: same contract.
        assert_eq!(json_refusal_exit_code(true, 1), 1);
        assert_eq!(json_refusal_exit_code(false, 1), 2);
        // A non-1 block action code is preserved on clean write, 2 on failure.
        assert_eq!(json_refusal_exit_code(true, 3), 3);
        assert_eq!(json_refusal_exit_code(false, 3), 2);
    }

    /// CodeRabbit R6 #1: `commands run --json` must DLP-redact the top-level
    /// `command` with the same patterns the findings use, else a raw command leaks
    /// credentials even though `findings` is scrubbed.
    #[test]
    fn run_json_redacts_top_level_command_with_custom_dlp() {
        use super::build_run_json;
        use tirith_core::verdict::{Timings, Verdict};

        // A custom DLP pattern plus a built-in-matching GitHub PAT.
        let custom = vec![r"ACME-[A-Z0-9]{6}".to_string()];
        let secret_token = "ACME-AB12CD";
        // Build the PAT at runtime (CodeRabbit R7 #7) so a `ghp_<36+>` literal
        // doesn't trip secret scanners; 40 body chars satisfy the built-in regex.
        let pat = format!("ghp_{}", "a1B2c3D4".repeat(5)); // 40 alphanumeric chars
        let command = format!("deploy --token {secret_token} --pat {pat}");

        let verdict = Verdict::allow_fast(1, Timings::default());
        let v = build_run_json(
            "deploy", &command, &verdict, &custom, /* running */ true,
            /* refused */ false, None,
        );

        let emitted = v
            .get("command")
            .and_then(|c| c.as_str())
            .expect("command field is a string");

        // The raw secret token MUST NOT appear; the redaction placeholder MUST.
        assert!(
            !emitted.contains(secret_token),
            "custom-DLP token leaked into the JSON command field: {emitted}"
        );
        assert!(
            emitted.contains("[REDACTED:custom]"),
            "custom-DLP match should be replaced with the redaction placeholder: {emitted}"
        );
        // The built-in GitHub-PAT pattern is also applied (the raw PAT is gone).
        assert!(
            !emitted.contains(pat.as_str()),
            "built-in DLP (GitHub PAT) leaked into the JSON command field: {emitted}"
        );
        // The non-secret parts of the command survive so the record stays useful.
        assert!(emitted.contains("deploy --token"), "got: {emitted}");
    }

    #[test]
    fn run_json_redacts_name_and_error_with_the_same_frozen_dlp_plan() {
        use super::build_run_json;
        use tirith_core::verdict::{Timings, Verdict};

        let canary = "C02_COMMAND_DTO_CANARY";
        let patterns = vec![regex::escape(canary)];
        let verdict = Verdict::allow_fast(1, Timings::default());
        let value = build_run_json(
            &format!("deploy-{canary}"),
            "deploy --safe",
            &verdict,
            &patterns,
            false,
            true,
            Some(&format!("failed for {canary}")),
        );
        let serialized = serde_json::to_string(&value).unwrap();

        assert!(!serialized.contains(canary));
        assert!(serialized.matches("[REDACTED:custom]").count() >= 2);
    }

    #[test]
    fn run_json_redacts_secrets_split_by_controls_in_name_and_command() {
        use super::build_run_json;
        use tirith_core::verdict::{Timings, Verdict};

        let custom = "C02_COMMAND_SPLIT_CANARY";
        let github = format!("ghp_{}", "a1B2c3D4".repeat(5));
        let split_custom = format!("{}\u{200b}{}", &custom[..11], &custom[11..]);
        let split_github = format!("{}\u{1b}[31m{}", &github[..18], &github[18..]);
        let patterns = vec![regex::escape(custom)];
        let verdict = Verdict::allow_fast(1, Timings::default());

        let value = build_run_json(
            &format!("deploy-{split_custom}"),
            &format!("deploy --label {split_custom} --pat {split_github}"),
            &verdict,
            &patterns,
            true,
            false,
            None,
        );
        let serialized = serde_json::to_string(&value).unwrap();

        assert!(!serialized.contains(custom), "{serialized}");
        assert!(!serialized.contains(&github), "{serialized}");
        assert!(!serialized.contains("\\u001b"), "{serialized}");
        assert!(!serialized.contains("\\u200b"), "{serialized}");
        assert!(serialized.contains("[REDACTED:custom]"), "{serialized}");
        assert!(serialized.contains("[REDACTED:GitHub PAT]"), "{serialized}");
    }

    fn assert_commands_early_json_error_contract(subcommand: &str, category: &str, exit_code: i32) {
        let custom_canary = format!("C02_{}_EARLY_ERROR_CANARY", subcommand.to_ascii_uppercase());
        let ghp_canary = format!("ghp_{}", "a1B2c3D4".repeat(5));
        let ghp_split = format!("{}\u{1b}[31m{}", &ghp_canary[..16], &ghp_canary[16..]);
        let custom_split = format!("{}\u{1b}[32m{}", &custom_canary[..12], &custom_canary[12..]);
        let patterns = vec![regex::escape(&custom_canary)];
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&patterns);
        let message = format!(
            "{category}\ncredential={ghp_split}; custom={custom_split}; {}",
            "error-flood"
                .repeat(tirith_core::verdict::MAX_PRESENTATION_BYTES / "error-flood".len() + 4_096)
        );

        let value = super::build_commands_error_json(subcommand, &message, exit_code, &compiled);
        let pretty = serde_json::to_string_pretty(&value).unwrap();

        assert!(pretty.len() < tirith_core::verdict::MAX_PRESENTATION_BYTES);
        assert_eq!(value["presentation_truncated"], true);
        assert!(!pretty.contains(ghp_canary.as_str()));
        assert!(!pretty.contains(custom_canary.as_str()));
        assert!(!pretty.contains("\\u001b"));
        assert_eq!(value["summary"]["kind"], "commands_error");
        assert_eq!(value["summary"]["status"], "error");
        assert_eq!(value["summary"]["name"], subcommand);
        assert_eq!(value["summary"]["action"], "block");
        assert_eq!(value["summary"]["analysis_complete"], false);
        assert_eq!(value["summary"]["analysis_incomplete"], true);
        assert_eq!(value["summary"]["running"], false);
        assert_eq!(value["summary"]["refused"], true);
        assert_eq!(value["summary"]["executed"], false);
        assert_eq!(value["summary"]["exit_code"], exit_code);
        let error = value["summary"]["error"].as_str().unwrap();
        assert!(error.contains("[REDACTED:GitHub PAT]"), "{error}");
        assert!(error.contains("[REDACTED:custom]"), "{error}");
        assert!(!error.contains('\n'));
        assert!(!error.contains('\r'));
        assert!(!error.contains('\u{1b}'));
    }

    #[test]
    fn init_early_json_errors_redact_ghp_custom_cwd_and_filesystem_text_before_cap() {
        assert_commands_early_json_error_contract("init", "cwd/create/write failure", 1);
    }

    #[test]
    fn list_early_json_errors_redact_ghp_custom_manifest_text_before_cap() {
        assert_commands_early_json_error_contract("list", "manifest parser failure", 1);
    }

    #[test]
    fn run_early_json_errors_redact_ghp_custom_manifest_and_catalog_text_before_cap() {
        assert_commands_early_json_error_contract("run", "manifest/catalog failure", 1);
    }

    #[test]
    fn check_early_json_errors_redact_ghp_custom_shell_reconstruction_and_cwd_text_before_cap() {
        assert_commands_early_json_error_contract(
            "check",
            "unknown-shell/reconstruction/cwd failure",
            2,
        );
    }

    #[test]
    fn captured_policy_diagnostics_join_the_single_bounded_json_envelope() {
        let custom = "C02_POLICY_DIAGNOSTIC_CUSTOM_CANARY";
        let github = format!("ghp_{}", "a1B2c3D4".repeat(5));
        let source = format!(
            "policy-{}\u{1b}[31m{}-{}\u{200b}{}",
            &github[..18],
            &github[18..],
            &custom[..14],
            &custom[14..]
        );
        let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
        let _ = tirith_core::policy::Policy::load_from_yaml("[", Some(&source));
        let compiled =
            tirith_core::redact::CompiledCustomPatterns::new_silent(&[regex::escape(custom)]);

        let value = super::build_commands_error_json(
            "list",
            &"manifest failure ".repeat(40_000),
            1,
            &compiled,
        );
        let serialized = serde_json::to_string_pretty(&value).unwrap();

        assert!(serialized.len() < tirith_core::verdict::MAX_PRESENTATION_BYTES);
        assert!(!serialized.contains(&github), "{serialized}");
        assert!(!serialized.contains(custom), "{serialized}");
        assert!(!serialized.contains("\\u001b"), "{serialized}");
        assert!(!serialized.contains("\\u200b"), "{serialized}");
        let summary = value.get("summary").unwrap_or(&value);
        assert!(summary["policy_diagnostics_count"]
            .as_u64()
            .is_some_and(|count| count >= 1));
        let diagnostics_owner = if value.get("summary").is_some() {
            &value
        } else {
            summary
        };
        let diagnostics = diagnostics_owner["policy_diagnostics"]
            .as_array()
            .expect("captured diagnostics must remain inside the one JSON object");
        let diagnostic_text = diagnostics
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(diagnostic_text.contains("[REDACTED:GitHub PAT]"));
        assert!(diagnostic_text.contains("[REDACTED:custom]"));
    }

    #[test]
    fn run_json_is_bounded_and_retains_late_critical_after_low_flood() {
        use super::build_run_json;
        use tirith_core::verdict::{Finding, RuleId, Severity, Timings, Verdict};

        let mut findings = (0..400)
            .map(|index| Finding {
                rule_id: RuleId::ConfigInjection,
                severity: Severity::Low,
                title: format!("low {index}"),
                description: "low-detail".repeat(2_000),
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
            title: "late critical sentinel".to_string(),
            description: "must survive priority selection".to_string(),
            evidence: Vec::new(),
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
        let verdict = Verdict::from_findings(findings, 3, Timings::default());
        let raw_count = verdict.findings.len();
        let huge_error = "envelope-flood"
            .repeat(tirith_core::verdict::MAX_PRESENTATION_BYTES / "envelope-flood".len() + 100);

        let value = build_run_json(
            "deploy",
            "deploy --safe",
            &verdict,
            &[],
            false,
            true,
            Some(&huge_error),
        );
        let pretty = serde_json::to_string_pretty(&value).unwrap();

        assert!(pretty.len() < tirith_core::verdict::MAX_PRESENTATION_BYTES);
        assert!(pretty.contains("private_key_exposed"), "{pretty}");
        assert!(pretty.contains("late critical sentinel"), "{pretty}");
        assert_eq!(
            verdict.findings.len(),
            raw_count,
            "raw decision was mutated"
        );
        assert_eq!(
            value["summary"]["original_findings_count"],
            raw_count as u64
        );
        assert!(value["summary"]["dropped_findings_count"]
            .as_u64()
            .is_some_and(|count| count > 0));
        assert_eq!(value["summary"]["running"], false);
        assert_eq!(value["summary"]["refused"], true);
    }

    /// CodeRabbit R13 #6: the block-refusal message embeds the command and lands in
    /// the machine-readable JSON `error` field, so it MUST be DLP-redacted like the
    /// sibling fields. Pins the JSON branch's redact → `block_refusal_message`.
    #[test]
    fn json_block_refusal_message_redacts_command() {
        use super::block_refusal_message;

        let custom = vec![r"ACME-[A-Z0-9]{6}".to_string()];
        let secret_token = "ACME-AB12CD";
        // Built at runtime so a `ghp_<36+>` LITERAL doesn't trip secret scanners.
        let pat = format!("ghp_{}", "a1B2c3D4".repeat(5)); // 40 alphanumeric chars
        let command = format!("deploy --token {secret_token} --pat {pat}");

        // Exactly what the JSON branch does: redact, then format the refusal.
        let redacted = tirith_core::redact::redact_command_text(&command, &custom);
        let refusal = block_refusal_message("deploy", &redacted);

        assert!(
            !refusal.contains(secret_token),
            "custom-DLP token leaked into the JSON refusal message: {refusal}"
        );
        assert!(
            !refusal.contains(pat.as_str()),
            "built-in DLP (GitHub PAT) leaked into the JSON refusal message: {refusal}"
        );
        assert!(
            refusal.contains("[REDACTED:custom]"),
            "custom-DLP match should be replaced with the redaction placeholder: {refusal}"
        );
        // The refusal still names the manifest entry and the non-secret command head.
        assert!(
            refusal.contains("refusing to run 'deploy'"),
            "got: {refusal}"
        );
        assert!(refusal.contains("deploy --token"), "got: {refusal}");
    }

    /// CodeRabbit R17 #3: a `commands run --json` SPAWN FAILURE must surface as a
    /// single object with `running:false` + an `error`, never `running:true`. A
    /// genuine spawn failure isn't portably forcible, so pin the contract at the
    /// pure `build_run_json` seam (the inverse — spawned but non-zero exit still
    /// reports `running:true` — is the companion integration test).
    #[test]
    fn run_json_spawn_failure_reports_not_running_with_error() {
        use super::build_run_json;
        use tirith_core::verdict::{Timings, Verdict};

        let verdict = Verdict::allow_fast(1, Timings::default());
        // Exactly the fields the spawn-failure branch passes to `emit_run_json`.
        let v = build_run_json(
            "deploy",
            "deploy --now",
            &verdict,
            &[],
            /* running */ false,
            /* refused */ false,
            Some("failed to spawn command: No such file or directory (os error 2)"),
        );

        assert_eq!(
            v["running"],
            serde_json::Value::Bool(false),
            "a spawn failure must report running:false, got: {v}"
        );
        assert_eq!(
            v["refused"],
            serde_json::Value::Bool(false),
            "a spawn failure is not a policy refusal, got: {v}"
        );
        assert!(
            v["error"]
                .as_str()
                .is_some_and(|s| s.contains("failed to spawn")),
            "a spawn failure must carry the spawn error string, got: {v}"
        );
        // Still a single, fully-shaped object a machine consumer can parse.
        assert_eq!(v["name"], "deploy");
        assert!(v["findings"].as_array().is_some(), "got: {v}");
    }

    /// CodeRabbit R15 #4: the pump must KEEP DRAINING the child's stdout after a
    /// stderr write error, so a child emitting lots of stdout over a broken stderr
    /// never blocks on a full pipe (hanging `child.wait()`). Driven via the generic
    /// [`super::pump_stdout_draining`] with an always-erroring writer + finite
    /// reader. Pins (1) drain-to-EOF on every write failing, (2) a working writer
    /// still receives every byte.
    #[test]
    fn pump_drains_stdout_after_stderr_write_error() {
        use super::pump_stdout_draining;
        use std::io::{self, Read, Write};

        // A reader handing out a large finite payload, counting bytes read so we
        // can prove the pump drained ALL of it.
        struct CountingReader {
            remaining: usize,
            read_total: std::rc::Rc<std::cell::Cell<usize>>,
        }
        impl Read for CountingReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.remaining == 0 {
                    return Ok(0); // EOF
                }
                let n = buf.len().min(self.remaining).min(4096);
                for b in &mut buf[..n] {
                    *b = b'x';
                }
                self.remaining -= n;
                self.read_total.set(self.read_total.get() + n);
                Ok(n)
            }
        }

        // (1) Writer that ALWAYS errors (simulates a closed/broken stderr).
        struct BrokenWriter;
        impl Write for BrokenWriter {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
        }

        // Far more than one pipe buffer — the bug would block a real child here.
        let payload = 512 * 1024;
        let read_total = std::rc::Rc::new(std::cell::Cell::new(0usize));
        let mut reader = CountingReader {
            remaining: payload,
            read_total: read_total.clone(),
        };
        pump_stdout_draining(&mut reader, &mut BrokenWriter);
        assert_eq!(
            read_total.get(),
            payload,
            "the pump must drain the child's stdout to EOF even when every stderr write fails"
        );

        // (2) A WORKING writer must still receive every byte (prior behavior).
        let read_total2 = std::rc::Rc::new(std::cell::Cell::new(0usize));
        let mut reader2 = CountingReader {
            remaining: payload,
            read_total: read_total2.clone(),
        };
        let mut sink: Vec<u8> = Vec::new();
        pump_stdout_draining(&mut reader2, &mut sink);
        assert_eq!(read_total2.get(), payload, "all stdout must be read");
        assert_eq!(
            sink.len(),
            payload,
            "a working stderr must receive every forwarded byte"
        );
        assert!(
            sink.iter().all(|&b| b == b'x'),
            "forwarded bytes must be the child's stdout unchanged"
        );
    }
}
