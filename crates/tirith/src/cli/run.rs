use tirith_core::runner::{self, RunOptions};

pub fn run(
    url: &str,
    no_exec: bool,
    json: bool,
    capsule: bool,
    expected_sha256: Option<String>,
) -> i32 {
    let interactive = is_terminal::is_terminal(std::io::stderr());

    // E5: when `--capsule` is set, execute the downloaded script inside the OS
    // containment capsule (deny-network, scrubbed env, resource limits, FS confined
    // to the script's cache dir). `tirith run` is an enforcing surface here, so a
    // host whose backend cannot enforce the containment fails closed (the executor
    // returns an error) instead of running uncontained.
    let exec_fn: Option<tirith_core::runner::ScriptExecutor> = if capsule {
        Some(Box::new(capsuled_exec))
    } else {
        None
    };

    let opts = RunOptions {
        url: url.to_string(),
        no_exec,
        interactive,
        expected_sha256,
        exec_fn,
    };

    match runner::run(opts) {
        Ok(result) => {
            if json {
                #[derive(serde::Serialize)]
                struct RunOutput<'a> {
                    receipt: &'a tirith_core::receipt::Receipt,
                    executed: bool,
                    exit_code: Option<i32>,
                }
                let out = RunOutput {
                    receipt: &result.receipt,
                    executed: result.executed,
                    exit_code: result.exit_code,
                };
                if serde_json::to_writer_pretty(std::io::stdout().lock(), &out).is_err() {
                    eprintln!("tirith: failed to write JSON output");
                }
                println!();
            }

            if result.executed {
                result.exit_code.unwrap_or(1)
            } else {
                0
            }
        }
        Err(e) => {
            if json {
                let err = serde_json::json!({ "error": e });
                if serde_json::to_writer_pretty(std::io::stdout().lock(), &err).is_err() {
                    eprintln!("tirith: failed to write JSON output");
                }
                println!();
            } else {
                eprintln!("tirith: {e}");
            }
            1
        }
    }
}

/// The contained executor for `tirith run --capsule` (E5). Runs `interpreter
/// <path>` through the OS capsule: deny-network, env scrubbed, resource-limited,
/// with the script's directory readable so the interpreter can read the script
/// itself. Enforcing surface -> fail closed on degraded coverage.
fn capsuled_exec(interpreter: &str, path: &std::path::Path) -> Result<i32, String> {
    use tirith_core::capsule::CapsuleSpec;

    let mut spec = CapsuleSpec::locked_down();
    // The interpreter needs to read the cached script and the system roots that
    // hold the interpreter + its runtime. Network stays DenyAll. Credential
    // subtrees remain denied by the locked-down default.
    if let Some(parent) = path.parent() {
        spec.filesystem.read_roots.push(parent.to_path_buf());
    }
    for root in [
        "/bin",
        "/usr",
        "/lib",
        "/lib64",
        "/etc",
        "/System",
        "/private/var/select",
    ] {
        let p = std::path::PathBuf::from(root);
        if p.exists() {
            spec.filesystem.read_roots.push(p);
        }
    }
    spec.environment.allow = ["PATH", "LANG", "TERM"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    let args = vec![path.to_string_lossy().into_owned()];
    match crate::cli::capsule::run_to_completion(
        &spec,
        interpreter,
        &args,
        None,
        &[],
        crate::cli::capsule::DegradedPolicy::FailClosed,
    ) {
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
