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
    /// Files skipped specifically because a rule panicked while scanning them
    /// (a subset of `skipped_count`). Surfaced separately so an incomplete scan
    /// is distinguishable from benign size/IO skips and never reads as clean.
    pub panic_files: Vec<PathBuf>,
}

/// Result of scanning a single file.
pub struct FileScanResult {
    pub path: PathBuf,
    pub findings: Vec<Finding>,
    pub is_config_file: bool,
}

/// AI-specific config basenames scanned first. Generic names (settings.json)
/// are prioritized only inside a known config dir (via the parent-dir check).
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
    let mut panic_files = Vec::new();
    for file_path in &files {
        // Panic in any rule is bounded to its file; the rest of the walk
        // continues. A panic is recorded in `panic_files` (not just folded into
        // `skipped_count`) so callers can tell an incomplete scan from benign
        // size/IO skips.
        match catch_panic_scanning(file_path, || scan_single_file(file_path)) {
            Some(Some(result)) => file_results.push(result),
            Some(None) => skipped_count += 1,
            None => {
                skipped_count += 1;
                panic_files.push(file_path.clone());
            }
        }
    }

    ScanResult {
        scanned_count: file_results.len(),
        skipped_count,
        truncated,
        truncation_reason,
        panic_files,
        file_results,
    }
}

/// Maximum analyzable content size: 10 MiB. Large enough for any realistic
/// config/source file, small enough that a hostile `.git/objects/pack-*.pack`
/// (or a huge editor buffer opened via the LSP server) won't blow us up.
/// Exposed so the file-scan path here and the in-memory LSP document path
/// (`tirith` crate `cli::lsp`) enforce the SAME ceiling from one definition.
pub const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Scan a single file and return its results.
pub fn scan_single_file(file_path: &Path) -> Option<FileScanResult> {
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
        card_ref: None,
        clipboard_source: crate::clipboard::ClipboardSourceState::Unread,
    };

    let verdict = engine::analyze(&ctx);

    let policy = crate::policy::Policy::discover(cwd.as_deref());
    let mut findings = verdict.findings;
    engine::filter_findings_by_paranoia_vec(&mut findings, policy.paranoia);

    Some(FileScanResult {
        path: file_path.to_path_buf(),
        findings,
        is_config_file: is_config,
    })
}

/// Wrap `f` in `catch_unwind` for the directory walk: on panic, log a skip and
/// return `None` so the caller bumps `skipped_count` and the walk continues.
/// Only effective in `panic = "unwind"` builds. `AssertUnwindSafe` is sound only
/// while the closure captures no mutable state used after a panic (today: `&Path`
/// + a fn pointer).
fn catch_panic_scanning<T>(file_path: &Path, f: impl FnOnce() -> T) -> Option<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => Some(v),
        Err(_) => {
            eprintln!(
                "tirith: scan: internal error scanning {} (skipped — see panic message above)",
                file_path.display()
            );
            None
        }
    }
}

/// A rule panicked while scanning a file (already reported on stderr by the
/// panic hook + [`catch_panic_scanning`]). Returned by
/// [`scan_single_file_guarded`] so callers can degrade gracefully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RulePanic;

/// Scan a single file with the same per-file panic guard the directory walk
/// uses, for long-lived/server callers (the MCP server, `policy test`) that must
/// not crash on a crafted file:
/// - `Ok(Some(result))` — the file was scanned;
/// - `Ok(None)` — skipped (too large / unreadable);
/// - `Err(RulePanic)` — a rule panicked; the caller should degrade to an error
///   instead of unwinding.
///
/// One-shot CLI `scan <file>` deliberately does NOT use this — a panic there
/// surfaces honestly as a process crash (see the directory-walk comment above).
pub fn scan_single_file_guarded(file_path: &Path) -> Result<Option<FileScanResult>, RulePanic> {
    catch_panic_scanning(file_path, || scan_single_file(file_path)).ok_or(RulePanic)
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
        card_ref: None,
        clipboard_source: crate::clipboard::ClipboardSourceState::Unread,
    };

    let verdict = engine::analyze(&ctx);

    let policy = crate::policy::Policy::discover(cwd.as_deref());
    let mut findings = verdict.findings;
    engine::filter_findings_by_paranoia_vec(&mut findings, policy.paranoia);

    FileScanResult {
        path: PathBuf::from("<stdin>"),
        findings,
        is_config_file: false,
    }
}

/// Priority if the basename is AI-specific, or the file sits in a known config dir.
fn is_priority_file(path: &Path) -> bool {
    let basename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    if PRIORITY_BASENAMES.contains(&basename) {
        return true;
    }

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

/// Enumerate every AI-CONFIG file under `root` — the instruction / config
/// surface (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.claude/*`,
/// `.cursor/rules/*`, `.mcp.json`, …) that `tirith ai snapshot|diff` track.
/// Reuses the standard scan walk (so it honors the same skip-dir / known-config-
/// dir rules), then keeps only paths [`crate::rules::aifile::is_ai_config_file`]
/// recognises. Always recursive. Returns absolute-or-`root`-relative paths
/// deduplicated and sorted for stable output (independent of the walk's order).
/// A single file `root` that is itself an AI-config file yields just that file.
pub fn collect_ai_config_files(root: &Path) -> Vec<PathBuf> {
    let mut files = collect_files(root, true, &[], &[], &[]);
    files.retain(|p| crate::rules::aifile::is_ai_config_file(p));
    files.sort();
    files.dedup();
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

        if is_binary_extension(name) {
            continue;
        }

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

        // Include patterns with negation support: `!`-prefixed patterns exclude
        // from the include set. A file passes if it matches a positive include
        // (or there are none) AND matches no negated pattern.
        if !include_patterns.is_empty() {
            let mut included = false;
            let mut negated = false;
            let has_positive = include_patterns.iter().any(|p| !p.starts_with('!'));

            for pat in include_patterns {
                if let Some(stripped) = pat.strip_prefix('!') {
                    // Negation: exclude from the include set.
                    if matches_ignore_pattern(name, stripped)
                        || matches_ignore_pattern(rel_path, stripped)
                    {
                        negated = true;
                    }
                } else {
                    // Positive: file must match at least one.
                    if matches_ignore_pattern(name, pat) || matches_ignore_pattern(rel_path, pat) {
                        included = true;
                    }
                }
            }

            if negated || (has_positive && !included) {
                continue;
            }
        }

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
///
/// `.svg` is deliberately NOT here: an SVG is XML text and can carry an
/// active payload (`<script>`, an `on*` event handler) or an external
/// reference — the `aifile` rules scan it for hidden / smuggled content.
fn is_binary_extension(name: &str) -> bool {
    let binary_exts = [
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".mp3", ".mp4", ".wav", ".avi",
        ".mov", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".exe", ".dll", ".so",
        ".dylib", ".o", ".a", ".wasm", ".pyc", ".class", ".jar",
    ];
    let name_lower = name.to_lowercase();
    binary_exts.iter().any(|ext| name_lower.ends_with(ext))
}

/// Match a filename against a simple glob: `*.ext`, `prefix*`, `pre*suf`,
/// `*middle*`, or exact. Patterns without `*` fall back to substring match.
pub fn matches_ignore_pattern(name: &str, pattern: &str) -> bool {
    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        match parts.as_slice() {
            [prefix, suffix] if prefix.is_empty() && !suffix.is_empty() => name.ends_with(suffix),
            [prefix, suffix] if !prefix.is_empty() && suffix.is_empty() => name.starts_with(prefix),
            [prefix, suffix] if !prefix.is_empty() && !suffix.is_empty() => {
                name.starts_with(prefix)
                    && name.ends_with(suffix)
                    && name.len() >= prefix.len() + suffix.len()
            }
            [_, _] => true,
            // Multiple wildcards: all parts must appear in order.
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
    fn catch_panic_scanning_returns_some_on_clean_run() {
        let path = Path::new("dummy");
        let result = catch_panic_scanning(path, || 42_i32);
        assert_eq!(result, Some(42));
    }

    /// Serializes tests that mutate the global panic hook so concurrent swaps
    /// don't race each other's restore. Tolerates poisoning.
    static PANIC_HOOK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn catch_panic_scanning_returns_none_on_panic() {
        let _lock = PANIC_HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = Path::new("dummy");
        // Suppress the default panic-hook output for this intentional panic.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result: Option<i32> = catch_panic_scanning(path, || {
            panic!("simulated rule panic");
        });
        std::panic::set_hook(prev);
        assert!(result.is_none(), "panic must produce None, got {result:?}");
    }

    #[test]
    fn scan_single_file_guarded_non_panic_paths() {
        // A readable file scans to Ok(Some(_)); the panic arm (Err(())) is
        // exercised by `catch_panic_scanning_returns_none_on_panic` above, which
        // covers the only branch that yields Err.
        let tmp = tempfile::tempdir().expect("create temp dir");
        let file_path = tmp.path().join("note.md");
        std::fs::write(&file_path, "hello world").expect("write temp file");
        assert!(matches!(scan_single_file_guarded(&file_path), Ok(Some(_))));

        // An unreadable/missing file is a benign skip: Ok(None), not Err.
        let missing = tmp.path().join("does_not_exist.md");
        assert!(matches!(scan_single_file_guarded(&missing), Ok(None)));
    }

    #[test]
    fn test_binary_extension_skip() {
        assert!(is_binary_extension("image.png"));
        assert!(is_binary_extension("archive.tar.gz"));
        assert!(!is_binary_extension("config.json"));
        assert!(!is_binary_extension("CLAUDE.md"));
        // SVG is XML text — it must NOT be skipped as binary, so the
        // `aifile` rules can scan it for active / hidden content.
        assert!(!is_binary_extension("logo.svg"));
        assert!(!is_binary_extension("ICON.SVG"));
    }

    #[test]
    fn test_svg_active_content_visible_in_scan() {
        // An SVG carrying a <script> must be collected (not skipped as binary)
        // and flagged by the aifile rules.
        let tmp = tempfile::tempdir().expect("create temp dir");
        let file_path = tmp.path().join("evil.svg");
        std::fs::write(
            &file_path,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><script>fetch('/x')</script></svg>"#,
        )
        .expect("write temp file");

        let result = scan_single_file(&file_path).expect("scan should succeed");
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.rule_id == crate::verdict::RuleId::SvgScriptEmbedded),
            "SVG with embedded script should be flagged: {:?}",
            result.findings
        );
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
        // Variation selector U+FE0F (EF B8 8F) in a temp dir with no policy.
        let tmp = tempfile::tempdir().expect("create temp dir");
        let file_path = tmp.path().join("test_vs.txt");
        std::fs::write(&file_path, b"A\xef\xb8\x8f").expect("write temp file");

        let result = scan_single_file(&file_path).expect("scan should succeed");

        // VariationSelector is Medium, so it must survive the default paranoia filter.
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
