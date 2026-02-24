use std::path::{Path, PathBuf};

use crate::engine::{self, AnalysisContext};
use crate::extract::ScanContext;
use crate::tokenize::ShellType;
use crate::verdict::{Finding, Severity};

/// Configuration for a file scan operation.
pub struct ScanConfig {
    /// Path to scan (directory or single file).
    pub path: PathBuf,
    /// Recurse into subdirectories.
    pub recursive: bool,
    /// Severity threshold for CI failure.
    pub fail_on: Severity,
    /// Glob patterns to ignore.
    pub ignore_patterns: Vec<String>,
    /// Max files to scan (None = unlimited).
    pub max_files: Option<usize>,
}

/// Result of a complete scan operation.
pub struct ScanResult {
    pub file_results: Vec<FileScanResult>,
    pub scanned_count: usize,
    pub skipped_count: usize,
    pub truncated: bool,
    pub truncation_reason: Option<String>,
}

/// Result of scanning a single file.
pub struct FileScanResult {
    pub path: PathBuf,
    pub findings: Vec<Finding>,
    pub is_config_file: bool,
}

/// Known AI config file basenames (scanned first for priority ordering).
/// Only includes names specific to AI tooling — generic names like settings.json
/// are only prioritized when found inside a known config directory (handled by
/// `is_priority_path` checking the parent directory).
const PRIORITY_BASENAMES: &[&str] = &[
    ".cursorrules",
    ".cursorignore",
    ".clinerules",
    ".windsurfrules",
    "CLAUDE.md",
    "AGENTS.md",
    "copilot-instructions.md",
    "mcp.json",
    ".mcp.json",
    "mcp_settings.json",
    "devcontainer.json",
];

/// Parent directories that make generic filenames count as priority.
const PRIORITY_PARENT_DIRS: &[&str] = &[
    ".claude",
    ".vscode",
    ".cursor",
    ".windsurf",
    ".cline",
    ".continue",
    ".github",
    ".devcontainer",
    ".roo",
];

/// Run a file scan operation.
///
/// Detection is always free (ADR-13). `max_files` is a caller-provided safety
/// cap (e.g. for resource-constrained CI), not a license gate.
pub fn scan(config: &ScanConfig) -> ScanResult {
    let mut files = collect_files(&config.path, config.recursive, &config.ignore_patterns);

    // Sort: known config files first, then lexicographic
    files.sort_by(|a, b| {
        let a_priority = is_priority_file(a);
        let b_priority = is_priority_file(b);
        match (a_priority, b_priority) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.cmp(b),
        }
    });

    let mut truncated = false;
    let mut truncation_reason = None;
    let mut skipped_count = 0;

    // Apply caller-provided safety cap (not a license gate)
    if let Some(max) = config.max_files {
        if files.len() > max {
            skipped_count = files.len() - max;
            files.truncate(max);
            truncated = true;
            truncation_reason = Some(format!(
                "Scan capped at {max} files ({skipped_count} skipped)."
            ));
        }
    }

    let mut file_results = Vec::new();
    for file_path in &files {
        if let Some(result) = scan_single_file(file_path) {
            file_results.push(result);
        }
    }

    ScanResult {
        scanned_count: file_results.len(),
        skipped_count,
        truncated,
        truncation_reason,
        file_results,
    }
}

/// Scan a single file and return its results.
pub fn scan_single_file(file_path: &Path) -> Option<FileScanResult> {
    // Read file content with size cap (10 MiB)
    const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

    let metadata = match std::fs::metadata(file_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "tirith: scan: cannot read metadata for {}: {e}",
                file_path.display()
            );
            return None;
        }
    };
    if metadata.len() > MAX_FILE_SIZE {
        eprintln!(
            "tirith: scan: skipping {} ({}B exceeds {}B limit)",
            file_path.display(),
            metadata.len(),
            MAX_FILE_SIZE
        );
        return None;
    }

    let raw_bytes = match std::fs::read(file_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("tirith: scan: cannot read {}: {e}", file_path.display());
            return None;
        }
    };
    let content = String::from_utf8_lossy(&raw_bytes).into_owned();

    let is_config = is_priority_file(file_path);

    let cwd = file_path
        .parent()
        .map(|p| p.display().to_string())
        .filter(|s| !s.is_empty());
    let ctx = AnalysisContext {
        input: content,
        shell: ShellType::Posix,
        scan_context: ScanContext::FileScan,
        raw_bytes: Some(raw_bytes),
        interactive: false,
        cwd: cwd.clone(),
        file_path: Some(file_path.to_path_buf()),
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
    };

    let verdict = engine::analyze(&ctx);

    // Apply paranoia filter to scan findings
    let policy = crate::policy::Policy::discover(cwd.as_deref());
    let mut findings = verdict.findings;
    engine::filter_findings_by_paranoia_vec(&mut findings, policy.paranoia);

    Some(FileScanResult {
        path: file_path.to_path_buf(),
        findings,
        is_config_file: is_config,
    })
}

/// Scan content from stdin (no file path).
pub fn scan_stdin(content: &str, raw_bytes: &[u8]) -> FileScanResult {
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    let ctx = AnalysisContext {
        input: content.to_string(),
        shell: ShellType::Posix,
        scan_context: ScanContext::FileScan,
        raw_bytes: Some(raw_bytes.to_vec()),
        interactive: false,
        cwd: cwd.clone(),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
    };

    let verdict = engine::analyze(&ctx);

    // Apply paranoia filter to scan findings
    let policy = crate::policy::Policy::discover(cwd.as_deref());
    let mut findings = verdict.findings;
    engine::filter_findings_by_paranoia_vec(&mut findings, policy.paranoia);

    FileScanResult {
        path: PathBuf::from("<stdin>"),
        findings,
        is_config_file: false,
    }
}

/// Check if a path matches a priority config file.
/// Matches either by AI-specific basename or by being inside a known config directory.
fn is_priority_file(path: &Path) -> bool {
    let basename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    // Direct AI-specific basename match
    if PRIORITY_BASENAMES.contains(&basename) {
        return true;
    }

    // Generic filenames are priority only inside known config dirs
    if let Some(parent) = path.parent() {
        let parent_name = parent.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if PRIORITY_PARENT_DIRS.contains(&parent_name) {
            return true;
        }
    }

    false
}

/// Collect files from a path (directory or single file).
fn collect_files(path: &Path, recursive: bool, ignore_patterns: &[String]) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }

    if !path.is_dir() {
        eprintln!("tirith: scan: path does not exist: {}", path.display());
        return vec![];
    }

    let mut files = Vec::new();
    collect_files_recursive(path, recursive, ignore_patterns, &mut files);
    files
}

fn collect_files_recursive(
    dir: &Path,
    recursive: bool,
    ignore_patterns: &[String],
    files: &mut Vec<PathBuf>,
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("tirith: scan: cannot read directory {}: {e}", dir.display());
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!(
                    "tirith: scan: error reading entry in {}: {e}",
                    dir.display()
                );
                continue;
            }
        };
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Skip hidden dirs (except known config dirs) and common non-useful dirs
        if path.is_dir() {
            if should_skip_dir(name) && !is_known_config_dir(name) {
                continue;
            }
            if recursive || is_known_config_dir(name) {
                collect_files_recursive(&path, recursive, ignore_patterns, files);
            }
            continue;
        }

        // Skip binary/non-text files by extension
        if is_binary_extension(name) {
            continue;
        }

        // Apply ignore patterns
        if ignore_patterns
            .iter()
            .any(|pat| name.contains(pat.as_str()))
        {
            continue;
        }

        files.push(path);
    }
}

/// Directories to skip during scanning.
fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | "node_modules"
            | "target"
            | "__pycache__"
            | ".tox"
            | "dist"
            | "build"
            | ".next"
            | "vendor"
            | ".cache"
    )
}

/// Known AI config directories that should always be entered.
fn is_known_config_dir(name: &str) -> bool {
    matches!(
        name,
        ".claude"
            | ".vscode"
            | ".cursor"
            | ".windsurf"
            | ".cline"
            | ".continue"
            | ".github"
            | ".devcontainer"
            | ".roo"
    )
}

/// File extensions that indicate binary content (skip scanning).
fn is_binary_extension(name: &str) -> bool {
    let binary_exts = [
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp", ".mp3", ".mp4", ".wav",
        ".avi", ".mov", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".exe", ".dll", ".so",
        ".dylib", ".o", ".a", ".wasm", ".pyc", ".class", ".jar",
    ];
    let name_lower = name.to_lowercase();
    binary_exts.iter().any(|ext| name_lower.ends_with(ext))
}

impl ScanResult {
    /// Check if any finding meets or exceeds the given severity threshold.
    pub fn has_findings_at_or_above(&self, threshold: Severity) -> bool {
        self.file_results
            .iter()
            .flat_map(|r| &r.findings)
            .any(|f| f.severity >= threshold)
    }

    /// Total number of findings across all files.
    pub fn total_findings(&self) -> usize {
        self.file_results.iter().map(|r| r.findings.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_extension_skip() {
        assert!(is_binary_extension("image.png"));
        assert!(is_binary_extension("archive.tar.gz"));
        assert!(!is_binary_extension("config.json"));
        assert!(!is_binary_extension("CLAUDE.md"));
    }

    #[test]
    fn test_priority_file_detection() {
        // AI-specific basenames are always priority
        assert!(is_priority_file(Path::new(".cursorrules")));
        assert!(is_priority_file(Path::new("CLAUDE.md")));
        assert!(is_priority_file(Path::new("mcp.json")));
        assert!(!is_priority_file(Path::new("README.md")));

        // Generic filenames are priority only inside known config dirs
        assert!(!is_priority_file(Path::new("settings.json")));
        assert!(!is_priority_file(Path::new("config.json")));
        assert!(is_priority_file(Path::new(".claude/settings.json")));
        assert!(is_priority_file(Path::new(".vscode/settings.json")));
        assert!(is_priority_file(Path::new(".roo/rules.md")));
    }

    #[test]
    fn test_skip_dirs() {
        assert!(should_skip_dir(".git"));
        assert!(should_skip_dir("node_modules"));
        assert!(should_skip_dir("target"));
        assert!(!should_skip_dir("src"));
        assert!(!should_skip_dir(".vscode"));
    }

    #[test]
    fn test_known_config_dirs() {
        assert!(is_known_config_dir(".claude"));
        assert!(is_known_config_dir(".vscode"));
        assert!(is_known_config_dir(".cursor"));
        assert!(!is_known_config_dir("src"));
        assert!(!is_known_config_dir(".git"));
    }
}
