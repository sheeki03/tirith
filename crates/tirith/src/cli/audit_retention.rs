//! CLI adapter for the same reviewed retention transaction used by local control.
pub fn segment(
    id: Option<String>,
    change: super::setup::audit_segments::SegmentChange,
    apply: bool,
    json: bool,
) -> i32 {
    let id = id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
    let cwd = std::env::current_dir()
        .ok()
        .map(|path| path.display().to_string());
    match super::setup::audit_segments::prepare(&id, change, cwd.as_deref()) {
        Ok(value) => {
            if apply {
                return super::profile::operation(&id, "apply", json);
            }
            if json {
                if !super::write_json_stdout(&value, "tirith audit: cannot write segment review") {
                    return 1;
                }
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).unwrap_or_default()
                );
                println!("Apply this saved review: tirith policy operation {id} --action apply");
            }
            0
        }
        Err(error) => {
            eprintln!(
                "tirith audit segment: {}",
                tirith_core::output::sanitize_human_field(
                    &error,
                    &tirith_core::policy::captured_policy_dlp_patterns_or(&[])
                )
            );
            1
        }
    }
}

pub fn rotate(id: Option<String>, apply: bool, json: bool) -> i32 {
    let id = id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
    let cwd = std::env::current_dir()
        .ok()
        .map(|path| path.display().to_string());
    let result = super::setup::audit_service::prepare(
        &id,
        super::setup::audit_service::AuditChange::Rotate,
        cwd.as_deref(),
    );
    match result {
        Ok(value) => {
            if apply {
                return super::profile::operation(&id, "apply", json);
            }
            if json {
                if !super::write_json_stdout(&value, "tirith audit rotate: cannot write preview") {
                    return 1;
                }
            } else {
                eprintln!("Audit rotation prepared: {id}");
                if let Some(preview) = value.get("preview").filter(|v| !v.is_null()) {
                    eprintln!(
                        "  Retain {} records ({} bytes) in private archive chunks.",
                        preview["retained_records"], preview["retained_bytes"]
                    );
                }
                eprintln!("  The active file is rotated under its writer lock. Undo is available only before additional active records.");
                eprintln!("  Apply the saved review: tirith policy operation {id} --action apply");
            }
            0
        }
        Err(error) => {
            let patterns = tirith_core::policy::captured_policy_dlp_patterns_or(&[]);
            eprintln!(
                "tirith audit rotate: {}",
                tirith_core::output::sanitize_human_field(&error, &patterns)
            );
            1
        }
    }
}
