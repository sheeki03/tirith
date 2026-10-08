//! Direct CLI entry to the same personal setup plan used by local control.
pub fn run(
    shell: Option<&str>,
    profile: Option<&str>,
    agents: &[String],
    operation_id: Option<String>,
    dry_run: bool,
    plan_only: bool,
    json: bool,
) -> i32 {
    use super::setup::recommended::RecommendedSetup;
    use super::setup::shell_service::ShellKind;
    use tirith_core::protection_profiles::ProtectionProfile;
    let id = operation_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
    let result = (|| -> Result<serde_json::Value, String> {
        let shell = shell.map(ShellKind::parse).transpose()?;
        let profile = ProtectionProfile::parse(profile.unwrap_or("balanced"))
            .ok_or("unknown personal protection profile")?;
        if agents.iter().any(|agent| agent != "claude-code") {
            return Err("unknown selected agent".to_string());
        }
        if agents.len() > 1 {
            return Err(
                "duplicate agent selections are ambiguous; select each supported host once".into(),
            );
        }
        let cwd = std::env::current_dir().map_err(|_| "current project is unavailable")?;
        super::setup::recommended::prepare(
            &id,
            RecommendedSetup {
                shell,
                profile,
                claude_code: !agents.is_empty(),
            },
            cwd.to_str(),
            dry_run,
        )
    })();
    match result {
        Ok(value) => {
            if dry_run || plan_only {
                if json {
                    return if super::write_json_stdout(
                        &value,
                        "tirith setup: cannot write setup review",
                    ) {
                        0
                    } else {
                        1
                    };
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).unwrap_or_default()
                );
                if plan_only {
                    println!(
                        "Apply this saved review: tirith policy operation {id} --action apply"
                    );
                }
                return 0;
            }
            if !json {
                eprintln!("Applying personal setup operation {id}:");
                if let Some(steps) = value["operation"]["steps"].as_array() {
                    for step in steps {
                        eprintln!(
                            "  {}: {}",
                            tirith_core::output::sanitize_human_field(
                                step["description"].as_str().unwrap_or("Owned setup change"),
                                &[]
                            ),
                            tirith_core::output::sanitize_human_field(
                                step["target"]
                                    .as_str()
                                    .unwrap_or("[destination unavailable]"),
                                &[]
                            )
                        );
                    }
                }
                eprintln!("Open a fresh terminal after setup and run its current-shell verification handshake.");
            }
            super::profile::operation(&id, "apply", json)
        }
        Err(error) => {
            eprintln!(
                "tirith setup recommended: {}",
                tirith_core::output::sanitize_human_field(
                    &error,
                    &tirith_core::policy::captured_policy_dlp_patterns_or(&[])
                )
            );
            1
        }
    }
}
