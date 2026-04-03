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
    /// Include only files matching these patterns (empty = include all).
    pub include_patterns: Vec<String>,
    /// Exclude files matching these patterns (applied after include).
    pub exclude_patterns: Vec<String>,
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
    let mut files = collect_files(
        &config.path,
        config.recursive,
        &config.ignore_patterns,
        &config.include_patterns,
        &config.exclude_patterns,
    );

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
        } else {
            skipped_count += 1;
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
fn collect_files(
    path: &Path,
    recursive: bool,
    ignore_patterns: &[String],
    include_patterns: &[String],
    exclude_patterns: &[String],
) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }

    if !path.is_dir() {
        eprintln!("tirith: scan: path does not exist: {}", path.display());
        return vec![];
    }

    let mut files = Vec::new();
    collect_files_recursive(
        path,
        path,
        recursive,
        ignore_patterns,
        include_patterns,
        exclude_patterns,
        &mut files,
    );
    files
}

fn collect_files_recursive(
    root: &Path,
    dir: &Path,
    recursive: bool,
    ignore_patterns: &[String],
    include_patterns: &[String],
    exclude_patterns: &[String],
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
                collect_files_recursive(
                    root,
                    &path,
                    recursive,
                    ignore_patterns,
                    include_patterns,
                    exclude_patterns,
                    files,
                );
            }
            continue;
        }

        // Skip binary/non-text files by extension
        if is_binary_extension(name) {
            continue;
        }

        // Apply ignore patterns against basename and relative path
        let rel_path = path
            .strip_prefix(root)
            .ok()
            .and_then(|p| p.to_str())
            .unwrap_or(name);
        if ignore_patterns
            .iter()
            .any(|pat| matches_ignore_pattern(name, pat) || matches_ignore_pattern(rel_path, pat))
        {
            continue;
        }

        // Apply include patterns with negation support.
        // Patterns prefixed with `!` act as excludes within the include set.
        if !include_patterns.is_empty() {
            let mut included = false;
            let mut negated = false;
            let has_positive = include_patterns.iter().any(|p| !p.starts_with('!'));

            for pat in include_patterns {
                if let Some(stripped) = pat.strip_prefix('!') {
                    // Negation: exclude from the include set
                    if matches_ignore_pattern(name, stripped)
                        || matches_ignore_pattern(rel_path, stripped)
                    {
                        negated = true;
                    }
                } else {
                    // Positive: file must match at least one
                    if matches_ignore_pattern(name, pat) || matches_ignore_pattern(rel_path, pat) {
                        included = true;
                    }
                }
            }

            // A file passes include if:
            // - No positive includes OR matches at least one positive include
            // - AND does not match any negated include
            if negated || (has_positive && !included) {
                continue;
            }
        }

        // Apply exclude patterns: skip matching files
        if exclude_patterns
            .iter()
            .any(|pat| matches_ignore_pattern(name, pat) || matches_ignore_pattern(rel_path, pat))
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

/// Match a filename against an ignore pattern.
/// Supports simple glob patterns: `*.ext` (suffix), `prefix*` (prefix),
/// `*middle*` (contains), and exact matches. Falls back to substring
/// matching for patterns without `*`.
pub fn matches_ignore_pattern(name: &str, pattern: &str) -> bool {
    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        match parts.as_slice() {
            // "*.ext" — suffix match
            [prefix, suffix] if prefix.is_empty() && !suffix.is_empty() => name.ends_with(suffix),
            // "prefix*" — prefix match
            [prefix, suffix] if !prefix.is_empty() && suffix.is_empty() => name.starts_with(prefix),
            // "pre*suf" — prefix + suffix match
            [prefix, suffix] if !prefix.is_empty() && !suffix.is_empty() => {
                name.starts_with(prefix)
                    && name.ends_with(suffix)
                    && name.len() >= prefix.len() + suffix.len()
            }
            // "*" alone matches everything
            [_, _] => true,
            // Fallback for multiple wildcards: all parts must appear in order
            _ => {
                let mut remaining = name;
                for (i, part) in parts.iter().enumerate() {
                    if part.is_empty() {
                        continue;
                    }
                    if i == 0 {
                        if !remaining.starts_with(part) {
                            return false;
                        }
                        remaining = &remaining[part.len()..];
                    } else if let Some(pos) = remaining.find(part) {
                        remaining = &remaining[pos + part.len()..];
                    } else {
                        return false;
                    }
                }
                true
            }
        }
    } else {
        // No wildcard: substring match (backwards compatible)
        name.contains(pattern)
    }
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

    #[test]
    fn test_ignore_pattern_matching() {
        // Suffix glob
        assert!(matches_ignore_pattern("test.log", "*.log"));
        assert!(!matches_ignore_pattern("test.txt", "*.log"));

        // Prefix glob
        assert!(matches_ignore_pattern("test_output.txt", "test_*"));
        assert!(!matches_ignore_pattern("my_test.txt", "test_*"));

        // Contains (no wildcard — backward compatible)
        assert!(matches_ignore_pattern("my_test_file.txt", "test"));
        assert!(!matches_ignore_pattern("readme.md", "test"));

        // Prefix + suffix glob
        assert!(matches_ignore_pattern("test_file.log", "test_*.log"));
        assert!(!matches_ignore_pattern("test_file.txt", "test_*.log"));

        // Exact match
        assert!(matches_ignore_pattern("Cargo.lock", "Cargo.lock"));

        // Path-aware patterns (matched against relative paths)
        assert!(matches_ignore_pattern(".claude/settings.json", ".claude/*"));
        assert!(!matches_ignore_pattern("src/main.rs", ".claude/*"));
        assert!(matches_ignore_pattern("docs/CLAUDE.md", "*/CLAUDE.md"));
        assert!(!matches_ignore_pattern("README.md", "*/CLAUDE.md"));
    }

    #[test]
    fn test_variation_selector_visible_in_scan() {
        // Write a temp file with a variation selector (U+FE0F = EF B8 8F in UTF-8)
        // into a temp directory with no local policy so paranoia is deterministic.
        let tmp = tempfile::tempdir().expect("create temp dir");
        let file_path = tmp.path().join("test_vs.txt");
        std::fs::write(&file_path, b"A\xef\xb8\x8f").expect("write temp file");

        let result = scan_single_file(&file_path).expect("scan should succeed");

        // VariationSelector is now Medium — should survive default paranoia filtering
        let policy = crate::policy::Policy::discover(Some(tmp.path().to_str().unwrap()));
        let mut findings = result.findings;
        crate::engine::filter_findings_by_paranoia_vec(&mut findings, policy.paranoia);

        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == crate::verdict::RuleId::VariationSelector),
            "VariationSelector should be visible in scan at default paranoia: {findings:?}"
        );
    }

    #[test]
    fn test_negated_include_patterns() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        std::fs::write(tmp.path().join("a.md"), "hello").unwrap();
        std::fs::write(tmp.path().join("b.test.md"), "world").unwrap();
        std::fs::write(tmp.path().join("c.rs"), "fn main() {}").unwrap();

        // Include *.md but exclude *.test.md via negation
        let files = collect_files(
            tmp.path(),
            false,
            &[],
            &["*.md".to_string(), "!*.test.md".to_string()],
            &[],
        );

        let names: Vec<&str> = files
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
            .collect();
        assert!(names.contains(&"a.md"), "a.md should be included");
        assert!(
            !names.contains(&"b.test.md"),
            "b.test.md should be excluded by negation"
        );
        assert!(
            !names.contains(&"c.rs"),
            "c.rs should not match *.md include"
        );
    }

    #[test]
    fn test_negation_only_include_patterns() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        std::fs::write(tmp.path().join("a.md"), "hello").unwrap();
        std::fs::write(tmp.path().join("b.test.md"), "world").unwrap();
        std::fs::write(tmp.path().join("c.rs"), "fn main() {}").unwrap();

        // Only negation patterns (no positive includes) — include everything
        // except negated patterns
        let files = collect_files(tmp.path(), false, &[], &["!*.test.md".to_string()], &[]);

        let names: Vec<&str> = files
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
            .collect();
        assert!(names.contains(&"a.md"), "a.md should be included");
        assert!(
            !names.contains(&"b.test.md"),
            "b.test.md should be excluded by negation"
        );
        assert!(
            names.contains(&"c.rs"),
            "c.rs should be included (no positive filter)"
        );
    }
}
