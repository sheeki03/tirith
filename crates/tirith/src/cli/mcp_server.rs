use std::io::{self, BufReader};

/// Run tirith as an MCP server over stdio.
pub fn run() -> i32 {
    let stdin = BufReader::new(io::stdin());
    let stdout = io::stdout();
    let stderr = io::stderr();
    tirith_core::mcp::dispatcher::run(stdin, stdout, stderr)
}
