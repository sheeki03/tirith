/// Run `tirith hook-event`: log a hook telemetry event (always exits 0).
/// Called by shell/Python/TypeScript hooks at each decision point.
pub fn run(
    integration: &str,
    hook_type: &str,
    event: &str,
    elapsed_ms: Option<f64>,
    detail: Option<&str>,
) -> i32 {
    // This hidden command accepts free-form values from third-party hook
    // scripts. Project at the CLI boundary as well as inside the core sink so
    // no future persistence/render refactor can turn its arguments into raw
    // audit material.
    let project = tirith_core::redact::redact_blocked_output;
    let integration = project(integration);
    let hook_type = project(hook_type);
    let event = project(event);
    let detail = detail.map(project);
    tirith_core::audit::log_hook_event(
        &integration,
        &hook_type,
        &event,
        elapsed_ms,
        detail.as_deref(),
    );
    0
}

#[cfg(test)]
mod tests {
    #[test]
    fn hidden_hook_event_arguments_use_the_conservative_privacy_projection() {
        let canary = format!("ghp_canary_{}", "D".repeat(30));
        let scalar = format!("{}1", "0".repeat(63));
        for value in [canary, scalar] {
            let projected = tirith_core::redact::redact_blocked_output(&value);
            assert!(!projected.contains(&value), "{projected}");
            assert!(projected.contains("REDACTED"), "{projected}");
        }
    }
}
