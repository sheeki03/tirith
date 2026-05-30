//! M11 ch2 — `tirith commands init|list|run|check`.
//!
//! A thin CLI over the repo command manifest (`.tirith/commands.yaml`,
//! [`tirith_core::commands_manifest`]). The manifest is SUPPRESSION-BOUNDED: it
//! can suppress only the Info `repo_command_unknown` annotation for an exact
//! `allowed[]` match, and ELEVATE via a blocking `repo_command_dangerous_pattern`
//! on a `dangerous[]` glob match. It can NEVER weaken a real engine finding —
//! see the module doc on `commands_manifest`.
//!
//! - `init` — write the starter manifest to `<repo>/.tirith/commands.yaml`.
//! - `list` — print the catalogued `allowed[]` / `dangerous[]` entries.
//! - `run` — look up an `allowed[]` entry by name and execute its command, but
//!   ONLY after re-checking it through the engine (an allowed entry that the
//!   engine flags High/Critical is refused — the manifest cannot bypass
//!   detection here either).
//! - `check` — evaluate an arbitrary command against the manifest + engine
//!   (delegates to `tirith check`).

use std::process::Command;

use tirith_core::commands_manifest::{CommandsManifest, DangerousAction, ManifestError};

/// `tirith commands init` — write the starter `.tirith/commands.yaml`.
///
/// Refuses to overwrite an existing file unless `force` is set (so a hand-
/// edited manifest is never clobbered by accident).
pub fn init(force: bool, json: bool) -> i32 {
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());

    let path = match tirith_core::commands_manifest::init_manifest_path(cwd.as_deref()) {
        Some(p) => p,
        None => {
            // A broken-pipe JSON write returns 2 (the JSON error never reached the
            // consumer); otherwise the semantic 1.
            if !emit_error(
                json,
                "tirith commands init",
                "could not resolve a target directory for .tirith/commands.yaml",
            ) {
                return 2;
            }
            return 1;
        }
    };

    if path.exists() && !force {
        if !emit_error(
            json,
            "tirith commands init",
            &format!(
                "{} already exists; pass --force to overwrite",
                path.display()
            ),
        ) {
            return 2;
        }
        return 1;
    }

    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            if !emit_error(
                json,
                "tirith commands init",
                &format!("create {}: {e}", parent.display()),
            ) {
                return 2;
            }
            return 1;
        }
    }

    // Write the manifest ATOMICALLY (temp-in-same-dir → fsync → rename → parent
    // fsync) rather than truncating in place: a crash mid-write must never lose
    // an existing manifest or leave a half-written one the loader then rejects.
    if let Err(e) = super::write_file_atomic(
        &path,
        tirith_core::commands_manifest::STARTER_MANIFEST.as_bytes(),
    ) {
        if !emit_error(
            json,
            "tirith commands init",
            &format!("write {}: {e}", path.display()),
        ) {
            return 2;
        }
        return 1;
    }

    if json {
        let v = serde_json::json!({
            "written": path.display().to_string(),
            "forced": force,
        });
        // A failed JSON write (e.g. broken pipe) must exit non-zero: the manifest
        // WAS written on disk, but a piped consumer that saw truncated JSON must
        // not also read a success code (mirrors command-card sign/verify).
        if !super::write_json_stdout(&v, "tirith commands init: failed to write JSON output") {
            return 2;
        }
    } else {
        println!("Wrote starter command manifest to {}", path.display());
        eprintln!("Edit it, then `tirith commands list` to review the catalogue.");
    }
    0
}

/// `tirith commands list` — print the manifest's catalogue.
pub fn list(json: bool) -> i32 {
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());

    let manifest = match CommandsManifest::discover(cwd.as_deref()) {
        Ok(Some(m)) => m,
        Ok(None) => {
            if json {
                let v = serde_json::json!({ "manifest": null, "allowed": [], "dangerous": [] });
                // A failed JSON write must surface non-zero so a piped consumer
                // never pairs truncated/absent JSON with a success exit.
                if !super::write_json_stdout(
                    &v,
                    "tirith commands list: failed to write JSON output",
                ) {
                    return 2;
                }
            } else {
                println!(
                    "No .tirith/commands.yaml found for this repo. Run `tirith commands init` to create one."
                );
            }
            return 0;
        }
        Err(e) => {
            if !emit_error(json, "tirith commands list", &manifest_err(&e)) {
                return 2;
            }
            return 1;
        }
    };

    if json {
        let allowed: Vec<_> = manifest
            .allowed
            .iter()
            .map(|e| serde_json::json!({ "name": e.name, "command": e.command }))
            .collect();
        let dangerous: Vec<_> = manifest
            .dangerous
            .iter()
            .map(|e| serde_json::json!({ "pattern": e.pattern, "action": dangerous_action_label(e.action) }))
            .collect();
        let v = serde_json::json!({ "allowed": allowed, "dangerous": dangerous });
        // A failed JSON write must surface non-zero so a piped consumer never
        // pairs a truncated catalogue with a success exit.
        if !super::write_json_stdout(&v, "tirith commands list: failed to write JSON output") {
            return 2;
        }
    } else {
        if manifest.allowed.is_empty() {
            println!("allowed: (none)");
        } else {
            println!("allowed:");
            for e in &manifest.allowed {
                println!("  {:<16} {}", e.name, e.command);
            }
        }
        if manifest.dangerous.is_empty() {
            println!("dangerous: (none)");
        } else {
            println!("dangerous:");
            for e in &manifest.dangerous {
                println!("  {:<7} {}", dangerous_action_label(e.action), e.pattern);
            }
        }
    }
    0
}

/// `tirith commands run <name>` — execute the `allowed[]` command named
/// `name`, after re-checking it through the engine.
///
/// SECURITY: being in `allowed[]` only suppresses the `repo_command_unknown`
/// annotation; it does NOT make a command safe to run blindly. We run the
/// resolved command back through `tirith check` first and REFUSE to execute if
/// the engine blocks it (a `dangerous[]` match or any real High/Critical
/// finding). This keeps the "manifest cannot bypass detection" invariant on the
/// execution path too.
pub fn run(name: &str, json: bool) -> i32 {
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());

    let manifest = match CommandsManifest::discover(cwd.as_deref()) {
        Ok(Some(m)) => m,
        Ok(None) => {
            if !emit_error(
                json,
                "tirith commands run",
                "no .tirith/commands.yaml found for this repo (run `tirith commands init`)",
            ) {
                return 2;
            }
            return 1;
        }
        Err(e) => {
            if !emit_error(json, "tirith commands run", &manifest_err(&e)) {
                return 2;
            }
            return 1;
        }
    };

    let entry = match manifest.allowed.iter().find(|e| e.name == name) {
        Some(e) => e,
        None => {
            let names: Vec<&str> = manifest.allowed.iter().map(|e| e.name.as_str()).collect();
            if !emit_error(
                json,
                "tirith commands run",
                &format!(
                    "no allowed command named '{name}'. Available: {}",
                    if names.is_empty() {
                        "(none)".to_string()
                    } else {
                        names.join(", ")
                    }
                ),
            ) {
                return 2;
            }
            return 1;
        }
    };
    let command = entry.command.clone();

    // Discover the repo policy once so the audit log redacts the command text
    // with the operator's custom DLP patterns (same as `tirith check`), and the
    // findings render below sees the same policy-derived view.
    let policy = tirith_core::policy::Policy::discover(cwd.as_deref());

    // Re-check the resolved command through the engine. The manifest CANNOT
    // bypass detection: if the engine blocks (dangerous match, High/Critical
    // finding), we refuse to run it.
    let verdict = analyze_command(&command, cwd.as_deref());
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
            // ONE combined JSON object: the verdict (action + findings) AND the
            // refusal, never two concatenated documents. (Previously
            // `render_findings` wrote a verdict JSON and `emit_error` wrote a
            // second `{"error":...}` JSON.)
            //
            // REDACT the command embedded in the refusal message (CodeRabbit R13
            // #6): this string lands in the JSON `error` field, which (like the
            // top-level `command` and the `findings`) goes to machine-readable
            // stdout and any log collector consuming it. Leaving the raw command
            // here would leak credentials / custom-DLP matches even though the
            // sibling `command`/`findings` fields are scrubbed. Use the SAME
            // built-in + custom DLP redaction as `build_run_json`.
            let redacted_command =
                tirith_core::redact::redact_command_text(&command, &policy.dlp_custom_patterns);
            let refusal = block_refusal_message(name, &redacted_command);
            // If the single-object write fails (e.g. broken pipe), the `--json`
            // contract that a machine consumer reads exactly one parseable object
            // is broken — returning the block exit code would falsely signal a
            // clean refusal even though nothing reached the caller. Report the
            // JSON-write failure instead (exit 2, the same code the
            // allow/warn-proceed write-failure path uses below).
            let wrote = emit_run_json(
                name,
                &command,
                &verdict,
                &policy.dlp_custom_patterns,
                /* running */ false,
                /* refused */ true,
                Some(&refusal),
            );
            return json_refusal_exit_code(wrote, verdict.action.exit_code());
        } else {
            // Human: surface WHY it was blocked (findings to stderr), then the
            // refusal line (also stderr) — mirroring `tirith check`. This is the
            // operator's OWN terminal (not a machine/log sink), so the refusal
            // shows the command verbatim — same as the `Running …`/abort lines.
            let refusal = block_refusal_message(name, &command);
            render_findings(&verdict, &policy.dlp_custom_patterns, json);
            emit_error(json, "tirith commands run", &refusal);
        }
        return verdict.action.exit_code();
    }

    // Audit the (allowed, non-blocked) run before executing it.
    let _ = tirith_core::audit::log_verdict(
        &verdict,
        &command,
        None,
        None,
        &policy.dlp_custom_patterns,
    );

    // A Warn/WarnAck verdict on an allowed command must NEVER be silently
    // swallowed: render its findings just like `tirith check` does. In an
    // interactive TTY, require explicit acknowledgement before running (mirrors
    // check.rs's strict-warn prompt); non-interactive callers see the findings
    // and proceed. (Block already returned above.)
    //
    // In JSON mode the findings are NOT rendered here (that would emit a
    // standalone verdict JSON); they are folded into the single combined object
    // emitted at the running/abort exit below.
    if verdict.action != tirith_core::verdict::Action::Allow {
        if !json {
            render_findings(&verdict, &policy.dlp_custom_patterns, json);
        }

        let interactive = if let Ok(val) = std::env::var("TIRITH_INTERACTIVE") {
            val == "1"
        } else {
            is_terminal::is_terminal(std::io::stderr())
        };
        if interactive {
            // Prompt always goes to stderr so stdout stays a single JSON object.
            eprint!(
                "tirith: proceed with {} warning(s) and run '{name}'? [y/N] ",
                verdict.findings.len()
            );
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).ok();
            if !matches!(input.trim(), "y" | "Y" | "yes" | "Yes") {
                if json {
                    // Declined: ONE object recording the warn verdict + that we
                    // did not run it (refused by the user). A failed write breaks
                    // the single-object `--json` contract, so report the
                    // JSON-write failure (exit 2) rather than the abort code (1) —
                    // the caller never received the abort record.
                    let wrote = emit_run_json(
                        name,
                        &command,
                        &verdict,
                        &policy.dlp_custom_patterns,
                        /* running */ false,
                        /* refused */ true,
                        Some("aborted by user"),
                    );
                    return json_refusal_exit_code(wrote, 1);
                } else {
                    eprintln!("tirith commands run: aborted by user.");
                }
                return 1;
            }
        }
    }

    if json {
        // SPAWN FIRST, then emit the single JSON document reflecting the ACTUAL
        // outcome (CodeRabbit R17 #3). Previously a `running:true` object was
        // written BEFORE the spawn, so a spawn failure (no such shell, ENOMEM,
        // …) still reported `running:true` to a machine consumer even though the
        // command never started. Now:
        //   * spawn FAILS  → one object with `running:false` + the spawn `error`.
        //   * spawn OK     → one object with `running:true`, THEN wait for exit.
        let spawned = match spawn_shell_command_json(&command) {
            Ok(s) => s,
            Err(e) => {
                // The command never started: emit ONE `running:false` object
                // carrying the spawn error. A failed JSON write breaks the
                // single-object contract (the consumer never received the
                // record), so report the write failure (exit 2) instead of the
                // semantic spawn-failure code (1) via `json_refusal_exit_code`.
                let wrote = emit_run_json(
                    name,
                    &command,
                    &verdict,
                    &policy.dlp_custom_patterns,
                    /* running */ false,
                    /* refused */ false,
                    Some(&format!("failed to spawn command: {e}")),
                );
                return json_refusal_exit_code(wrote, 1);
            }
        };

        // The spawn succeeded — the command IS running. Emit the single
        // `running:true` object. The round-9/15 abort-on-write-failure contract
        // is preserved: if THIS write fails, a `--json` consumer saw a truncated
        // record and must not have the command silently run to completion, so we
        // KILL + reap the (already-spawned) child and report the write failure
        // (exit 2) rather than waiting on it.
        if !emit_run_json(
            name,
            &command,
            &verdict,
            &policy.dlp_custom_patterns,
            /* running */ true,
            /* refused */ false,
            None,
        ) {
            spawned.kill_and_reap();
            return 2;
        }

        // One JSON document is on stdout; wait for the child and return its exit
        // code. A wait failure (extremely rare — the child is already running)
        // keeps stdout a single document by reporting only to stderr.
        match spawned.wait() {
            Ok(code) => code,
            Err(e) => {
                eprintln!("tirith commands run: failed to wait on command: {e}");
                1
            }
        }
    } else {
        eprintln!("Running allowed command '{name}': {command}");
        match run_shell_command_human(&command) {
            Ok(code) => code,
            Err(e) => {
                emit_error(
                    json,
                    "tirith commands run",
                    &format!("failed to spawn command: {e}"),
                );
                1
            }
        }
    }
}

/// Map a refusal-path JSON write result to the process exit code. On a clean
/// write the caller's refusal code (block action code, or 1 for a user abort) is
/// returned; on a write failure the single-object `--json` contract is broken
/// (the consumer never received the refusal record), so exit 2 — the same
/// JSON-write-failure code the allow/warn-proceed path returns — is reported
/// instead. Pure so the contract is unit-testable without a deterministically-
/// failing real stdout (mirrors the seam note on `cli::write_json_to`).
fn json_refusal_exit_code(wrote_ok: bool, refusal_code: i32) -> i32 {
    if wrote_ok {
        refusal_code
    } else {
        2
    }
}

/// Format the block-refusal message for manifest entry `name` running
/// `command_for_display`.
///
/// `command_for_display` is whatever the CALLER decided is safe to surface: the
/// JSON path passes the DLP-REDACTED command (the message lands in the
/// machine-readable `error` field — CodeRabbit R13 #6), the human path passes the
/// raw command (the operator's own terminal). Pure so the redaction contract on
/// the JSON path is unit-testable without spawning a process.
fn block_refusal_message(name: &str, command_for_display: &str) -> String {
    format!(
        "refusing to run '{name}' ({command_for_display}): tirith blocked it. \
         Inspect with `tirith commands check -- \"{command_for_display}\"`."
    )
}

/// Emit the single combined `commands run --json` object and return whether the
/// write succeeded. This is the ONLY JSON writer on the `commands run` stdout
/// path — every exit (block-refuse, warn-decline, allow/warn-proceed) routes
/// through it so a machine consumer always reads exactly one parseable object
/// per invocation, never two concatenated documents.
///
/// Shape: `{"name","command","action","findings":[...],"running":bool,
/// "refused":bool,"error":null|"..."}`. `findings` carries the same redacted
/// `Finding` records `tirith check` emits (DLP-redacted with the repo policy's
/// custom patterns).
fn emit_run_json(
    name: &str,
    command: &str,
    verdict: &tirith_core::verdict::Verdict,
    dlp_custom_patterns: &[String],
    running: bool,
    refused: bool,
    error: Option<&str>,
) -> bool {
    let v = build_run_json(
        name,
        command,
        verdict,
        dlp_custom_patterns,
        running,
        refused,
        error,
    );
    super::write_json_stdout(&v, "tirith commands run: failed to write JSON output")
}

/// Build the `commands run --json` object. Pure (no I/O) so the redaction
/// contract is unit-testable without a capturable stdout (mirrors the
/// `json_refusal_exit_code` seam). BOTH the `findings` AND the top-level
/// `command` are scrubbed with the same built-in + custom DLP patterns — leaving
/// the raw `command` would leak credentials / custom-DLP matches into JSON
/// stdout (and any log collector consuming it) even though `findings` is
/// redacted.
fn build_run_json(
    name: &str,
    command: &str,
    verdict: &tirith_core::verdict::Verdict,
    dlp_custom_patterns: &[String],
    running: bool,
    refused: bool,
    error: Option<&str>,
) -> serde_json::Value {
    let findings = tirith_core::redact::redacted_findings(&verdict.findings, dlp_custom_patterns);
    let redacted_command = tirith_core::redact::redact_command_text(command, dlp_custom_patterns);
    serde_json::json!({
        "name": name,
        "command": redacted_command,
        "action": verdict.action,
        "findings": findings,
        "running": running,
        "refused": refused,
        "error": error,
    })
}

/// Render a non-Allow verdict's findings the SAME way `tirith check` does so a
/// `commands run` Warn/Block surfaces its rules instead of being swallowed.
/// JSON goes to stdout (machine-readable), human output to stderr (so it does
/// not corrupt the executed command's stdout). No-op for an empty finding list.
fn render_findings(
    verdict: &tirith_core::verdict::Verdict,
    dlp_custom_patterns: &[String],
    json: bool,
) {
    if json {
        if tirith_core::output::write_json_with_suggestions(
            verdict,
            dlp_custom_patterns,
            None,
            std::io::stdout().lock(),
        )
        .is_err()
        {
            eprintln!("tirith commands run: failed to write JSON output");
        }
    } else if tirith_core::output::write_human(
        verdict,
        /* warn_only */ false,
        std::io::stderr().lock(),
    )
    .is_err()
    {
        eprintln!("tirith commands run: failed to write output");
    }
}

/// `tirith commands check -- "<cmd>"` — evaluate `cmd` against the manifest +
/// the full engine. Delegates to `tirith check`, which wires the manifest
/// (`repo_command_unknown` / `repo_command_dangerous_pattern`) into its normal
/// analysis. Exit code is the engine's action exit code.
pub fn check(cmd: &str, shell: &str, json: bool) -> i32 {
    // Reuse the exact `tirith check` path so manifest + engine semantics are
    // identical to a normal shell-hook check (no second, divergent code path).
    super::check::run(
        cmd, shell, json, /* non_interactive */ false, /* interactive_flag */ false,
        /* approval_check */ false, /* strict_warn */ false, /* no_daemon */ true,
        /* warn_only */ false, /* offline */ false,
        /* suggest_safe_command */ false, /* card */ None,
    )
}

/// The [`ShellType`](tirith_core::tokenize::ShellType) the safety re-check must
/// tokenize with: it MUST match the shell `build_shell_command` actually
/// executes (`cmd /C` on Windows, a deterministic POSIX `/bin/sh -c` elsewhere).
/// Analyzing a command with the wrong shell can mis-tokenize pipes/operators and
/// miss findings.
#[cfg(windows)]
const RUN_SHELL: tirith_core::tokenize::ShellType = tirith_core::tokenize::ShellType::Cmd;
#[cfg(not(windows))]
const RUN_SHELL: tirith_core::tokenize::ShellType = tirith_core::tokenize::ShellType::Posix;

/// Analyze `command` through the engine for `commands run`'s safety re-check.
fn analyze_command(command: &str, cwd: Option<&str>) -> tirith_core::verdict::Verdict {
    use tirith_core::engine::{self, AnalysisContext};
    use tirith_core::extract::ScanContext;

    let ctx = AnalysisContext {
        input: command.to_string(),
        // Match the shell that will actually run the command (see RUN_SHELL).
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
    };
    engine::analyze(&ctx)
}

/// Run `command` through the platform shell. Returns the child's exit code (128
/// if killed by a signal with no code).
///
/// The shell family here MUST match what [`analyze_command`] tokenized with
/// (see [`RUN_SHELL`]): the safety re-check is only sound if the engine parsed
/// the command the way the shell that runs it will. On non-Windows we therefore
/// execute via a POSIX `sh -c` (matching `ShellType::Posix`) rather than
/// `$SHELL -c` — `$SHELL` may be fish/csh, whose word-splitting and operator
/// semantics differ from POSIX, which would let the re-check parse a DIFFERENT
/// command than the one actually executed. Windows uses `cmd /C` (matching
/// `ShellType::Cmd`).
///
/// STDOUT ROUTING (CodeRabbit R9 #E): in `--json` mode tirith's stdout is exactly
/// ONE JSON document (already written before this call). If the child inherited
/// stdout, its output would append to that document and corrupt it. So in JSON
/// mode the child's stdout is REDIRECTED to tirith's stderr — the operator still
/// sees the command's output, but tirith's stdout stays pure JSON. The child's
/// own stderr is inherited in both modes. In human mode the child inherits stdout
/// normally (output goes straight to the terminal, unchanged).
fn build_shell_command(command: &str) -> Command {
    if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(command);
        c
    } else {
        // Deterministically POSIX `sh`, NOT `$SHELL`, so execution matches the
        // Posix analysis in `analyze_command`.
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(command);
        c
    }
}

/// A successfully-spawned `commands run --json` child plus its stdout-pump
/// thread. Separating SPAWN from WAIT (CodeRabbit R17 #3) lets the caller emit
/// the single JSON document only AFTER it knows the spawn succeeded — so a
/// spawn failure is reported as `running:false`+`error`, never a misleading
/// `running:true`. The child is left RUNNING; [`SpawnedJsonChild::wait`]
/// (success) or [`SpawnedJsonChild::kill_and_reap`] (JSON-write failure) drives
/// it to completion.
struct SpawnedJsonChild {
    child: std::process::Child,
    pump: Option<std::thread::JoinHandle<()>>,
}

impl SpawnedJsonChild {
    /// Wait for the child to exit and join the stdout pump, returning the child's
    /// exit code (128 if killed by a signal with no code).
    fn wait(mut self) -> std::io::Result<i32> {
        let status = self.child.wait()?;
        if let Some(h) = self.pump.take() {
            // Join the pump so all child output is flushed to stderr before we
            // return (and the thread never outlives the process). The child has
            // exited, so its stdout pipe is at EOF and the copy completes.
            let _ = h.join();
        }
        Ok(status.code().unwrap_or(128))
    }

    /// Best-effort kill + reap when the single-JSON-document write FAILED after
    /// the spawn (CodeRabbit R17 #3). The round-9/15 contract is that a `--json`
    /// consumer who saw a truncated record must NOT have the command silently run
    /// to completion; since the child is already spawned we kill it and reap it
    /// (and join the pump) so it cannot outlive tirith.
    fn kill_and_reap(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(h) = self.pump.take() {
            let _ = h.join();
        }
    }
}

/// Spawn `command` for the JSON path with its stdout PIPED to a helper thread
/// that copies it to tirith's stderr (so a large output cannot deadlock by
/// filling the pipe, and tirith's stdout stays a single JSON document). The
/// child's stderr is inherited. Returns the running child + pump on success; the
/// spawn error otherwise (the caller maps it to a `running:false` JSON object).
fn spawn_shell_command_json(command: &str) -> std::io::Result<SpawnedJsonChild> {
    use std::process::Stdio;
    let mut cmd = build_shell_command(command);
    cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());
    let mut child = cmd.spawn()?;
    let pump = child.stdout.take().map(|mut out| {
        std::thread::spawn(move || {
            // Stream child stdout → tirith's stderr on a helper thread so a large
            // output cannot deadlock by filling the pipe. See
            // [`pump_stdout_draining`] for the drain-after-stderr-error contract
            // that keeps the child from blocking when our stderr is broken.
            pump_stdout_draining(&mut out, &mut std::io::stderr());
        })
    });
    Ok(SpawnedJsonChild { child, pump })
}

/// Human-mode run: the child inherits stdout/stderr; spawn+wait combined.
/// Returns the child's exit code (128 if killed by a signal with no code).
fn run_shell_command_human(command: &str) -> std::io::Result<i32> {
    Ok(build_shell_command(command).status()?.code().unwrap_or(128))
}

/// Forward everything `reader` (the child's stdout) produces to `writer`
/// (tirith's stderr), reading to EOF.
///
/// We DELIBERATELY do not use [`std::io::copy`]: it stops on the FIRST writer
/// error. If tirith's stderr is closed/broken while the child keeps writing,
/// stopping the read would let the child's stdout pipe FILL, and the child would
/// then BLOCK forever on its next write — `child.wait()` would hang with it
/// (CodeRabbit R15 #4). Instead, on a writer error we drop to DRAIN-ONLY mode:
/// keep reading `reader` to EOF (discarding bytes), just stop forwarding. The
/// child never blocks on a full pipe, so `wait()` always returns.
fn pump_stdout_draining<R: std::io::Read, W: std::io::Write>(reader: &mut R, writer: &mut W) {
    let mut buf = [0u8; 8 * 1024];
    let mut forwarding = true;
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break, // EOF — the child closed its stdout.
            Ok(n) => {
                if forwarding && writer.write_all(&buf[..n]).is_err() {
                    // Writer (stderr) is gone: stop forwarding but keep draining
                    // so the child's pipe never fills.
                    forwarding = false;
                }
                // When `!forwarding` we discard `buf[..n]` and keep looping.
            }
            // Retry an interrupted read; any other read error means the pipe is
            // gone, so there is nothing left to drain.
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

/// Stable label for a `dangerous[]` entry's action, shared by the JSON and
/// human `list` renderers. The action is per-entry (`block` → Block, `warn` →
/// Warn); hardcoding "block" here would misreport a `DangerousAction::Warn`
/// entry.
fn dangerous_action_label(action: DangerousAction) -> &'static str {
    match action {
        DangerousAction::Block => "block",
        DangerousAction::Warn => "warn",
    }
}

/// Human-readable rendering of a manifest load error.
fn manifest_err(e: &ManifestError) -> String {
    format!("could not load .tirith/commands.yaml: {e}")
}

/// Emit an error to stderr (human) or as a JSON `{"error": ...}` object.
///
/// Returns `false` when the JSON write itself failed (broken pipe / truncated
/// output) so a `--json` caller can surface a write failure rather than pairing a
/// semantic exit code with no JSON delivered (CodeRabbit R8 #5). Human mode
/// always returns `true` — the stderr line is best-effort and not gated.
fn emit_error(json: bool, ctx: &str, msg: &str) -> bool {
    if json {
        let v = serde_json::json!({ "error": msg });
        super::write_json_stdout(&v, &format!("{ctx}: failed to write JSON output"))
    } else {
        eprintln!("{ctx}: {msg}");
        true
    }
}

#[cfg(test)]
mod tests {
    use super::RUN_SHELL;
    use tirith_core::tokenize::ShellType;

    #[test]
    fn run_shell_matches_execution_platform() {
        // F7: the `commands run` safety re-check must tokenize with the SAME
        // shell family `build_shell_command` executes: `cmd /C` on Windows, and a
        // deterministic POSIX `/bin/sh -c` (NOT `$SHELL -c`, which could be
        // fish/csh) elsewhere. A mismatch (e.g. analyze-as-Posix but run-as-fish)
        // can mis-tokenize and miss findings.
        #[cfg(windows)]
        assert_eq!(RUN_SHELL, ShellType::Cmd);
        #[cfg(not(windows))]
        assert_eq!(RUN_SHELL, ShellType::Posix);
    }

    /// F7: the resolved execution shell must match `RUN_SHELL`'s family even when
    /// `$SHELL` points at a non-POSIX shell. We can't easily introspect the
    /// `Command` built by the private `build_shell_command`, so we pin the
    /// invariant: on non-Windows the analysis is Posix AND execution is hardwired
    /// to `/bin/sh` (a POSIX shell), independent of `$SHELL`. This is a
    /// compile-time/structural guarantee — the function no longer reads `$SHELL`.
    #[cfg(not(windows))]
    #[test]
    fn execution_shell_is_posix_independent_of_env_shell() {
        // The constant the analysis uses is Posix...
        assert_eq!(RUN_SHELL, ShellType::Posix);
        // ...and `/bin/sh` exists on the unix CI/runners we target, so the
        // hardwired execution path is a real POSIX shell rather than `$SHELL`.
        assert!(
            std::path::Path::new("/bin/sh").exists(),
            "the deterministic POSIX execution shell /bin/sh must exist"
        );
    }

    /// CodeRabbit/Greptile R4 #4: on the `commands run --json` REFUSAL paths
    /// (engine-block and user-abort), a FAILED single-object JSON write must
    /// override the refusal exit code with 2 (the JSON-write-failure code) —
    /// returning the block/abort code while nothing reached the caller would
    /// falsely signal a clean refusal over a broken `--json` contract. A clean
    /// write preserves the refusal code. (The real stdout cannot be made to fail
    /// deterministically across platforms — see the `cli::write_json_to` seam
    /// note — so the exit-code decision is factored into this pure helper.)
    #[test]
    fn json_refusal_exit_code_overrides_on_write_failure() {
        use super::json_refusal_exit_code;
        // Block-refuse path: clean write keeps the block exit code (1); a failed
        // write reports the JSON-write failure (2).
        assert_eq!(json_refusal_exit_code(true, 1), 1);
        assert_eq!(json_refusal_exit_code(false, 1), 2);
        // User-abort path passes refusal_code = 1: same contract.
        assert_eq!(json_refusal_exit_code(true, 1), 1);
        assert_eq!(json_refusal_exit_code(false, 1), 2);
        // A non-1 block action code (defensive) is likewise preserved on a clean
        // write and overridden to 2 on failure.
        assert_eq!(json_refusal_exit_code(true, 3), 3);
        assert_eq!(json_refusal_exit_code(false, 3), 2);
    }

    /// CodeRabbit R6 #1: `commands run --json` must DLP-redact the top-level
    /// `command` string with the same patterns the findings use. A raw command
    /// would leak credentials / custom-DLP matches into JSON stdout (and any log
    /// collector), even though `findings` is already scrubbed.
    #[test]
    fn run_json_redacts_top_level_command_with_custom_dlp() {
        use super::build_run_json;
        use tirith_core::verdict::{Timings, Verdict};

        // A custom DLP pattern that matches an internal token shape, plus a
        // built-in-matching GitHub PAT to prove built-in patterns apply too.
        let custom = vec![r"ACME-[A-Z0-9]{6}".to_string()];
        let secret_token = "ACME-AB12CD";
        // Build the GitHub PAT at runtime (CodeRabbit R7 #7): a contiguous
        // `ghp_<36+>` LITERAL in the source trips secret scanners. 40 body chars
        // (`[A-Za-z0-9]`) still satisfy the built-in `ghp_[A-Za-z0-9]{36,}`.
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

    /// CodeRabbit R13 #6: the block-refusal message on the `commands run --json`
    /// path embeds the command, and that message lands in the JSON `error` field
    /// (machine-readable stdout / log sink). It MUST be DLP-redacted the same way
    /// the `command`/`findings` fields are — a raw secret-shaped token in the
    /// refusal would leak even though the sibling fields are scrubbed. This pins
    /// the pure construction the JSON branch uses (redact → `block_refusal_message`).
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
    /// single object with `running:false` + an `error` — NEVER the
    /// success-shaped `running:true`. The `run()` JSON branch now spawns FIRST
    /// and, on a spawn `Err`, emits exactly this object (the
    /// "shell could not be executed" path). A genuine spawn failure needs the
    /// system shell (`/bin/sh` / `cmd`) to be unspawnable, which is not portably
    /// forcible at the integration level, so we pin the machine-readable contract
    /// at the pure `build_run_json` seam the branch uses (mirroring the
    /// `json_block_refusal_message_redacts_command` seam test). The companion
    /// integration test `commands_run_json_nonzero_command_still_reports_running`
    /// proves the inverse: a shell that DID spawn but whose command exits
    /// non-zero still (correctly) reports `running:true`.
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

    /// CodeRabbit R15 #4: the `commands run --json` stdout→stderr pump must KEEP
    /// DRAINING the child's stdout after a stderr write error, so a child that
    /// emits a lot of stdout while our stderr is broken never blocks on a full
    /// pipe (which would hang `child.wait()`).
    ///
    /// The pump loop is factored into [`super::pump_stdout_draining`] over generic
    /// `Read`/`Write` so we can drive it with an always-erroring writer and a
    /// large in-memory reader — no real process, no real pipe, fully time-boxed
    /// (the reader yields EOF, so the loop cannot actually hang). We pin BOTH
    /// properties: (1) the drain reads the reader to EOF even when every write
    /// fails, and (2) a working writer still receives every byte (forwarding is
    /// unchanged from the prior `std::io::copy` behavior).
    #[test]
    fn pump_drains_stdout_after_stderr_write_error() {
        use super::pump_stdout_draining;
        use std::io::{self, Read, Write};

        // A reader that hands out a large, finite payload, counting bytes read so
        // we can prove the pump consumed ALL of it (drained to EOF).
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

        // Far more than one pipe buffer's worth — the bug would block a real child
        // here; the helper must still consume every byte.
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
