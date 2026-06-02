use std::io::{self, BufReader};

use tirith_core::mcp::dispatcher::DispatcherOptions;

/// Run tirith as an MCP server over stdio.
///
/// `sanitize_tool_output` (M7 ch4, opt-in default false) routes every
/// `tools/call` return through the output-direction analyzer; when enabled the
/// dispatcher fails closed (analysis-truncation / rule-error denies).
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
