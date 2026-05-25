use std::io::{self, BufReader};

use tirith_core::mcp::dispatcher::DispatcherOptions;

/// Run tirith as an MCP server over stdio.
///
/// `sanitize_tool_output` (M7 ch4) routes every `tools/call` return through
/// the output-direction analyzer before it leaves the server. Default
/// behavior is `false` (preserves current behavior; opt-in until
/// field-tested). When enabled, the dispatcher uses `fail_mode_closed = true`
/// so an analysis-truncation or rule-error path denies rather than passes
/// through.
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
