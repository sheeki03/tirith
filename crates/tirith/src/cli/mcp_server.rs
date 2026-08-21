use std::io::{self, BufReader};

use tirith_core::mcp::dispatcher::DispatcherOptions;

/// Run tirith as an MCP server over stdio.
///
/// `sanitize_tool_output` routes every `tools/call` and `resources/read` return
/// through the output-direction analyzer. The CLI enables it by default and
/// requires an explicit unsafe compatibility flag to turn it off.
pub fn run(sanitize_tool_output: bool) -> i32 {
    let stdin = BufReader::new(io::stdin());
    let stdout = io::stdout();
    let stderr = io::stderr();
    tirith_core::mcp::dispatcher::run_with_options(
        stdin,
        stdout,
        stderr,
        DispatcherOptions {
            sanitize_tool_output,
        },
    )
}
