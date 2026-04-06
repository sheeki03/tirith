pub mod audit;
pub mod check;
pub mod checkpoint;
pub mod completions;
pub mod daemon;
pub mod diff;
pub mod doctor;
pub mod explain;
pub mod gateway;
pub mod hook_event;
pub mod init;
pub mod last_trigger;
pub mod license_cmd;
pub mod manpage;
pub mod mcp_server;
pub mod paste;
pub mod policy;
pub mod receipt;
pub mod scan;
pub mod score;
pub mod threatdb_cmd;
pub mod trust;
pub mod warnings;
pub mod why;

#[cfg(unix)]
pub mod fetch;
#[cfg(unix)]
pub mod run;
pub mod setup;

/// Resolve all `tirith` executables on PATH using the shell's own command resolution.
/// Returns paths that the shell would actually execute, not just filesystem entries.
pub fn resolve_tirith_on_path() -> Vec<std::path::PathBuf> {
    let output = {
        #[cfg(unix)]
        {
            std::process::Command::new("sh")
                .args(["-c", "which -a tirith 2>/dev/null"])
                .output()
        }
        #[cfg(not(unix))]
        {
            std::process::Command::new("where.exe")
                .arg("tirith")
                .output()
        }
    };

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(std::path::PathBuf::from)
        .collect()
}

/// Find `tirith` executables on PATH that are not the current binary.
/// Deduplicates by canonical path so duplicate PATH entries don't produce repeated warnings.
pub fn find_shadow_binaries() -> Vec<String> {
    let our_canonical = std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok());

    let mut seen = std::collections::HashSet::new();
    let mut shadows = Vec::new();

    for path in resolve_tirith_on_path() {
        let canonical = path.canonicalize().ok();
        // Skip if it resolves to our own binary
        if let (Some(ours), Some(ref theirs)) = (&our_canonical, &canonical) {
            if ours == theirs {
                continue;
            }
        }
        // Dedup by canonical path (fall back to display path for unresolvable entries)
        let key = canonical
            .map(|c| c.display().to_string())
            .unwrap_or_else(|| path.display().to_string());
        if seen.insert(key) {
            shadows.push(path.display().to_string());
        }
    }
    shadows
}
