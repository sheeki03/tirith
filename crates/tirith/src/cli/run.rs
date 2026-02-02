use tirith_core::runner::{self, RunOptions};

pub fn run(url: &str, no_exec: bool, json: bool) -> i32 {
    let interactive = is_terminal::is_terminal(std::io::stderr());

    let opts = RunOptions {
        url: url.to_string(),
        no_exec,
        interactive,
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
                let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), &out);
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
                let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), &err);
                println!();
            } else {
                eprintln!("tirith: {e}");
            }
            1
        }
    }
}
