/// Run `tirith hook-event`: log a hook telemetry event (always exits 0).
/// Called by shell/Python/TypeScript hooks at each decision point.
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
