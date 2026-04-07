/// Run the `tirith hook-event` subcommand.
///
/// Logs a hook telemetry event to the audit log and always exits 0.
/// This is called by shell/Python/TypeScript hook scripts at every
/// decision point to record what happened.
pub fn run(
    integration: &str,
    hook_type: &str,
    event: &str,
    elapsed_ms: Option<f64>,
    detail: Option<&str>,
) -> i32 {
    tirith_core::audit::log_hook_event(integration, hook_type, event, elapsed_ms, detail);
    0
}
