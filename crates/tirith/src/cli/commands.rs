//! M11 ch2 — `tirith commands init|list|run|check`.
//!
//! A thin CLI over the repo command manifest (`.tirith/commands.yaml`,
//! [`tirith_core::commands_manifest`]). The manifest is SUPPRESSION-BOUNDED: it
//! can only suppress the Info `repo_command_unknown` annotation on an exact
//! `allowed[]` match and ELEVATE via a blocking `repo_command_dangerous_pattern`
//! on a `dangerous[]` glob; it can NEVER weaken a real engine finding. `run`
//! re-checks the resolved command through the engine and refuses a block — the
//! manifest cannot bypass detection on the execution path either.

use std::process::Command;

use tirith_core::commands_manifest::{CommandsManifest, DangerousAction, ManifestError};

/// `tirith commands init` — write the starter `.tirith/commands.yaml`. Refuses to
/// overwrite an existing file unless `force` is set.
pub fn init(force: bool, json: bool) -> i32 {
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());

    let path = match tirith_core::commands_manifest::init_manifest_path(cwd.as_deref()) {
        Some(p) => p,
        None => {
            // Broken-pipe JSON write → 2; otherwise the semantic 1.
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
        // If `.tirith` is created fresh, fsync its entry in the repo root too:
        // `write_file_atomic` only fsyncs commands.yaml's parent, so a crash could
        // otherwise lose the whole `.tirith` dir despite init succeeding (CodeRabbit R13b).
        let parent_existed = parent.exists();
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
        if !parent_existed {
            tirith_core::util::fsync_parent_dir_logged(parent, "commands .tirith directory");
        }
    }

    // Write ATOMICALLY (temp → fsync → rename → parent fsync), not truncate-in-
    // place, so a crash can't lose or half-write the manifest. No-clobber unless
    // `--force` so a manifest created in the post-`exists()` race window survives.
    if let Err(e) = super::write_file_atomic(
        &path,
        tirith_core::commands_manifest::STARTER_MANIFEST.as_bytes(),
        force,
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
        // A failed JSON write must exit non-zero: the manifest WAS written, but a
        // consumer that saw truncated JSON must not also read success.
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
                // A failed JSON write must surface non-zero (no truncated JSON + success).
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
        // A failed JSON write must surface non-zero (no truncated catalogue + success).
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

/// `tirith commands run <name>` — execute the `allowed[]` command `name` after
/// re-checking it through the engine.
///
/// SECURITY: `allowed[]` only suppresses the `repo_command_unknown` annotation;
/// it does NOT make a command safe to run blindly. We re-run the resolved command
/// through the engine and REFUSE to execute on a block — keeping "manifest cannot
/// bypass detection" on the execution path too.
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

    // Re-check through the engine; refuse to run on a block (the manifest cannot
    // bypass detection). The engine also returns the policy it resolved (CodeRabbit
    // R18 #2), reused below for audit/redaction instead of a second `Policy::discover`.
    let (verdict, policy) = analyze_command(&command, cwd.as_deref());
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
            let redacted_command =
                tirith_core::redact::redact_command_text(&command, &policy.dlp_custom_patterns);
            let refusal = block_refusal_message(name, &redacted_command);
            // If the write fails the single-object `--json` contract is broken, so
            // report exit 2 rather than the block code (nothing reached the caller).
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
            // Human: findings then refusal to stderr (mirroring `tirith check`).
            // The operator's own terminal, so the command shows verbatim.
            let refusal = block_refusal_message(name, &command);
            render_findings(&verdict, &policy.dlp_custom_patterns, json);
            emit_error(json, "tirith commands run", &refusal);
        }
        return verdict.action.exit_code();
    }

    // NOTE: the "command ran" audit is DEFERRED (CodeRabbit R18 #1) — written only
    // after the warn ack passes AND the spawn succeeds (see `audit_run`), so a
    // declined warn / failed spawn never records a run. The BLOCK refusal above is
    // still audited where it is.

    // A Warn/WarnAck on an allowed command must NOT be swallowed: render findings
    // like `tirith check`, and require an interactive ack before running. In JSON
    // mode findings are folded into the single combined object below, not rendered
    // here (which would emit a standalone verdict JSON).
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
            // Prompt to stderr so stdout stays a single JSON object.
            eprint!(
                "tirith: proceed with {} warning(s) and run '{name}'? [y/N] ",
                verdict.findings.len()
            );
            let mut input = String::new();
            // Surface (don't swallow) a stdin read error. Fail-safe: on error
            // `input` stays empty so the match below aborts — never a "yes".
            if let Err(e) = std::io::stdin().read_line(&mut input) {
                eprintln!("tirith commands run: could not read confirmation input: {e}");
            }
            if !matches!(input.trim(), "y" | "Y" | "yes" | "Yes") {
                if json {
                    // Declined: ONE object recording the warn verdict + not-run. A
                    // failed write reports exit 2 (broken single-object contract),
                    // not the abort code 1.
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
                    &policy.dlp_custom_patterns,
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
            &policy.dlp_custom_patterns,
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
                eprintln!("tirith commands run: failed to wait on command: {e}");
                1
            }
        }
    } else {
        eprintln!("Running allowed command '{name}': {command}");
        // SPAWN first so the audit fires only after a successful spawn (CodeRabbit
        // R18 #1): a spawn failure must not record a run.
        match build_shell_command(&command).spawn() {
            Ok(mut child) => {
                audit_run(&verdict, &command, &policy.dlp_custom_patterns);
                match child.wait() {
                    Ok(status) => status.code().unwrap_or(128),
                    Err(e) => {
                        eprintln!("tirith commands run: failed to wait on command: {e}");
                        1
                    }
                }
            }
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
/// machine-readable `error` field — CodeRabbit R13 #6), raw on the human path.
/// Pure so the redaction contract is unit-testable.
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
/// contract is unit-testable. BOTH `findings` AND the top-level `command` are
/// DLP-scrubbed — a raw `command` would leak credentials even though `findings`
/// is redacted.
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

/// Render a non-Allow verdict's findings like `tirith check` does, so a Warn/Block
/// surfaces its rules. JSON → stdout, human → stderr (so it doesn't corrupt the
/// executed command's stdout). No-op for an empty list.
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
/// engine by delegating to `tirith check` (which wires the manifest into its
/// normal analysis). Exit code is the engine's action exit code.
pub fn check(cmd: &str, shell: &str, json: bool) -> i32 {
    // Reuse the exact `tirith check` path — no divergent second code path.
    super::check::run(
        cmd, shell, json, /* non_interactive */ false, /* interactive_flag */ false,
        /* approval_check */ false, /* strict_warn */ false, /* no_daemon */ true,
        /* warn_only */ false, /* offline */ false,
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

/// Human-readable rendering of a manifest load error.
fn manifest_err(e: &ManifestError) -> String {
    format!("could not load .tirith/commands.yaml: {e}")
}

/// Emit an error to stderr (human) or as a JSON `{"error": ...}` object. Returns
/// `false` only when the JSON write itself failed (CodeRabbit R8 #5); human mode
/// always returns `true`.
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
