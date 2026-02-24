use tirith_core::runner::{self, RunOptions};

pub fn run(url: &str, no_exec: bool, json: bool, expected_sha256: Option<String>) -> i32 {
    let interactive = is_terminal::is_terminal(std::io::stderr());

    let opts = RunOptions {
        url: url.to_string(),
        no_exec,
        interactive,
        expected_sha256,
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
