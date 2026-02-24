/// Safe runner — Unix only.
/// Downloads a script, analyzes it, optionally executes it with user confirmation.
use std::fs;
use std::io::{self, BufRead, Write};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::receipt::Receipt;
use crate::script_analysis;

pub struct RunResult {
    pub receipt: Receipt,
    pub executed: bool,
    pub exit_code: Option<i32>,
}

pub struct RunOptions {
    pub url: String,
    pub no_exec: bool,
    pub interactive: bool,
}

/// Interpreters matched by exact name only.
const ALLOWED_EXACT: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "fish", "deno", "bun", "nodejs",
];

/// Interpreter families that may have version suffixes (python3, python3.11, ruby3.2, node18, perl5.38).
/// Matches: exact name OR name + digits[.digits]* suffix.
const ALLOWED_FAMILIES: &[&str] = &["python", "ruby", "perl", "node"];

fn is_allowed_interpreter(interpreter: &str) -> bool {
    let base = interpreter.rsplit('/').next().unwrap_or(interpreter);

    if ALLOWED_EXACT.contains(&base) {
        return true;
    }

    for &family in ALLOWED_FAMILIES {
        if base == family {
            return true;
        }
        if let Some(suffix) = base.strip_prefix(family) {
            if is_valid_version_suffix(suffix) {
                return true;
            }
        }
    }

    false
}

/// Check if a suffix is a valid version string: digits (.digits)*
/// Valid: "3", "3.11", "3.2.1"
/// Invalid: "", ".3", "3.", "3..11", "evil"
fn is_valid_version_suffix(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.split('.')
        .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

pub fn run(opts: RunOptions) -> Result<RunResult, String> {
    // Check TTY requirement
    if !opts.no_exec && !opts.interactive {
        return Err("tirith run requires an interactive terminal or --no-exec flag".to_string());
    }

    // Download with redirect chain collection
    let mut redirects: Vec<String> = Vec::new();
    let redirect_list = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let redirect_list_clone = redirect_list.clone();

    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if let Ok(mut list) = redirect_list_clone.lock() {
                list.push(attempt.url().to_string());
            }
            if attempt.previous().len() >= 10 {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    let response = client
        .get(&opts.url)
        .send()
        .map_err(|e| format!("download failed: {e}"))?;

    let final_url = response.url().to_string();
    if let Ok(list) = redirect_list.lock() {
        redirects = list.clone();
    }

    const MAX_BODY: u64 = 10 * 1024 * 1024; // 10 MiB

    // Check Content-Length hint first (fast rejection)
    if let Some(len) = response.content_length() {
        if len > MAX_BODY {
            return Err(format!(
                "response too large: {len} bytes (max {} MiB)",
                MAX_BODY / 1024 / 1024
            ));
        }
    }

    // Read with cap using std::io::Read::take
    use std::io::Read;
    let mut buf = Vec::new();
    response
        .take(MAX_BODY + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read body: {e}"))?;
    if buf.len() as u64 > MAX_BODY {
        return Err(format!(
            "response body exceeds {} MiB limit",
            MAX_BODY / 1024 / 1024
        ));
    }
    let content = buf;

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let sha256 = format!("{:x}", hasher.finalize());

    // Cache
    let cache_dir = crate::policy::data_dir()
        .ok_or("cannot determine data directory")?
        .join("cache");
    fs::create_dir_all(&cache_dir).map_err(|e| format!("create cache: {e}"))?;
    let cached_path = cache_dir.join(&sha256);
    {
        use std::io::Write;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&cached_path)
            .map_err(|e| format!("write cache: {e}"))?;
        f.write_all(&content)
            .map_err(|e| format!("write cache: {e}"))?;
        // Harden legacy cache files
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
    }

    let content_str = String::from_utf8_lossy(&content);

    // Analyze
    let interpreter = script_analysis::detect_interpreter(&content_str);
    let analysis = script_analysis::analyze(&content_str, interpreter);

    // Enforce interpreter policy only when we might execute.
    if !opts.no_exec && !is_allowed_interpreter(interpreter) {
        return Err(format!(
            "interpreter '{interpreter}' is not in the allowed list",
        ));
    }

    // Detect git repo and branch
    let (git_repo, git_branch) = detect_git_info();

    // Create receipt
    let receipt = Receipt {
        url: opts.url.clone(),
        final_url: Some(final_url),
        redirects,
        sha256: sha256.clone(),
        size: content.len() as u64,
        domains_referenced: analysis.domains_referenced,
        paths_referenced: analysis.paths_referenced,
        analysis_method: "static".to_string(),
        privilege: if analysis.has_sudo {
            "elevated".to_string()
        } else {
            "normal".to_string()
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        cwd: std::env::current_dir()
            .ok()
            .map(|p| p.display().to_string()),
        git_repo,
        git_branch,
    };

    if opts.no_exec {
        receipt.save().map_err(|e| format!("save receipt: {e}"))?;
        return Ok(RunResult {
            receipt,
            executed: false,
            exit_code: None,
        });
    }

    // Show analysis summary
    eprintln!(
        "tirith: downloaded {} bytes (SHA256: {})",
        content.len(),
        crate::receipt::short_hash(&sha256)
    );
    eprintln!("tirith: interpreter: {interpreter}");
    if analysis.has_sudo {
        eprintln!("tirith: WARNING: script uses sudo");
    }
    if analysis.has_eval {
        eprintln!("tirith: WARNING: script uses eval");
    }
    if analysis.has_base64 {
        eprintln!("tirith: WARNING: script uses base64");
    }

    // Confirm from /dev/tty
    let tty = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| "cannot open /dev/tty for confirmation")?;

    let mut tty_writer = io::BufWriter::new(&tty);
    write!(tty_writer, "Execute this script? [y/N] ").map_err(|e| format!("tty write: {e}"))?;
    tty_writer.flush().map_err(|e| format!("tty flush: {e}"))?;

    let mut reader = io::BufReader::new(&tty);
    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| format!("tty read: {e}"))?;

    if !response_line.trim().eq_ignore_ascii_case("y") {
        eprintln!("tirith: execution cancelled");
        receipt.save().map_err(|e| format!("save receipt: {e}"))?;
        return Ok(RunResult {
            receipt,
            executed: false,
            exit_code: None,
        });
    }

    // Execute
    receipt.save().map_err(|e| format!("save receipt: {e}"))?;

    let status = Command::new(interpreter)
        .arg(&cached_path)
        .status()
        .map_err(|e| format!("execute: {e}"))?;

    Ok(RunResult {
        receipt,
        executed: true,
        exit_code: status.code(),
    })
}

/// Detect git repo remote URL and current branch.
fn detect_git_info() -> (Option<String>, Option<String>) {
    let repo = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string());

    let branch = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string());

    (repo, branch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowed_interpreter_sh() {
        assert!(is_allowed_interpreter("sh"));
    }

    #[test]
    fn test_allowed_interpreter_python3() {
        assert!(is_allowed_interpreter("python3"));
    }

    #[test]
    fn test_allowed_interpreter_python3_11() {
        assert!(is_allowed_interpreter("python3.11"));
    }

    #[test]
    fn test_allowed_interpreter_nodejs() {
        assert!(is_allowed_interpreter("nodejs"));
    }

    #[test]
    fn test_disallowed_interpreter_vim() {
        assert!(!is_allowed_interpreter("vim"));
    }

    #[test]
    fn test_disallowed_interpreter_expect() {
        assert!(!is_allowed_interpreter("expect"));
    }

    #[test]
    fn test_disallowed_interpreter_python_evil() {
        assert!(!is_allowed_interpreter("python.evil"));
    }

    #[test]
    fn test_disallowed_interpreter_node_sass() {
        assert!(!is_allowed_interpreter("node-sass"));
    }

    #[test]
    fn test_disallowed_interpreter_python3_trailing_dot() {
        assert!(!is_allowed_interpreter("python3."));
    }

    #[test]
    fn test_disallowed_interpreter_python3_double_dot() {
        assert!(!is_allowed_interpreter("python3..11"));
    }

    #[test]
    fn test_allowed_interpreter_strips_path() {
        assert!(is_allowed_interpreter("/usr/bin/bash"));
    }

    #[cfg(unix)]
    #[test]
    fn test_cache_write_permissions_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("test_cache");

        {
            use std::io::Write;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&cache_path).unwrap();
            f.write_all(b"test content").unwrap();
            let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
        }

        let meta = std::fs::metadata(&cache_path).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "cache file should be 0600"
        );
    }
}
