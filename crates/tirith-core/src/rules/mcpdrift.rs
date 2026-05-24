//! MCP lockfile drift detection — file-content rule that fires when the
//! committed `.tirith/mcp.lock` no longer matches the repository's current
//! MCP-server inventory.
//!
//! This is the FileScan-path counterpart to `tirith mcp verify`. When
//! `tirith scan` walks the repository and reaches `.tirith/mcp.lock`, this
//! module parses the lockfile's recorded inventory, rebuilds the current
//! inventory from the repo's MCP config files, and emits
//! [`RuleId::McpServerDrift`] when the two differ. A pre-commit hook / CI
//! integration that runs `tirith scan` therefore catches MCP drift the same
//! way it catches an un-pinned action or a smuggled instruction.
//!
//! It runs only on the `tirith scan` FileScan path — never the exec hot
//! path — so a tier-1 PATTERN_TABLE entry is not required for reachability
//! (`tier1_scan` always returns `true` for FileScan, see `extract.rs`). The
//! module self-selects by path: only the `.tirith/mcp.lock` *target* of a
//! file scan ever triggers the inventory rebuild, so an arbitrary file with
//! the basename `mcp.lock` outside `.tirith/` is not misclassified.
//!
//! **Privacy.** The fired finding's description and evidence carry only
//! aggregate change counts and a server's *name* — never an env value, a URL
//! userinfo string, or a hash. The lockfile already strips those (see
//! `mcp_lock.rs`); this module observes the *hash* changed, never the
//! underlying secret.
//!
//! **Malformed lockfile is itself a finding.** A `.tirith/mcp.lock` that
//! does not parse cannot be diffed against the current inventory, so drift
//! cannot be verified — exactly the failure mode an attacker would use to
//! hide an MCP-surface change behind a deliberately broken lockfile. The
//! rule therefore emits a `McpServerDrift` finding (same severity as a
//! drift) when the committed lockfile is unparseable, naming the parse
//! failure without echoing any of the file's bytes. An unreadable repo
//! root, or an inventory rebuild that fails because of a malformed config
//! file, still yields zero findings — those are operational conditions, not
//! a tampered baseline.

use std::collections::HashMap;
use std::path::Path;

use crate::mcp_lock;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// `true` when `path` is the `.tirith/mcp.lock` file this rule scans.
///
/// Requires the path's basename to be `mcp.lock` AND its immediate parent
/// directory to be named `.tirith` — exactly the location
/// `tirith mcp lock` writes. A loose `mcp.lock` anywhere else in the repo is
/// not this lockfile.
pub fn is_mcp_lockfile(path: Option<&Path>) -> bool {
    let Some(path) = path else { return false };

    let Some(basename) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if basename != mcp_lock::MCP_LOCK_FILENAME {
        return false;
    }

    let Some(parent) = path.parent() else {
        return false;
    };
    parent
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n == ".tirith")
        .unwrap_or(false)
}

/// `true` when `repo_root` looks like a real repository — and therefore
/// "no MCP configs found under it" is a meaningful signal of "every locked
/// server has been removed" drift rather than "this isn't a repo, of
/// course there's nothing here".
///
/// Without this gate, scanning a bare `.tirith/mcp.lock` outside any
/// repository (e.g. a copy sitting under `/tmp/random/`) produces a
/// finding storm: `build_inventory` finds no configs, `compute_drift`
/// classifies every server in the lockfile as Removed, and the rule
/// reports drift that does not exist. The check is structurally cheap
/// (a handful of `metadata` probes) and is run only after we know
/// `file_path` already looks like `<X>/.tirith/mcp.lock`, so the cost
/// is paid only when the rule is about to fire anyway.
///
/// The check accepts the root iff at least one of:
/// 1. **The derived `repo_root` is empty / `.` (a relative path with no
///    leading components).** When the scan was driven with a relative
///    file path like `.tirith/mcp.lock`, the derived "repo root" is the
///    empty path — meaning the caller is implicitly asking us to scan
///    against the current working directory. We honor that intent
///    rather than try to re-derive it; the alternative would silently
///    suppress drift on what the caller plainly meant as "scan THIS
///    lockfile". This is also the contract the FileScan fixture path
///    depends on: a fixture's `file_path` is always relative.
/// 2. `.git` is a directory or a file under the root — the standard
///    working-tree marker; submodules and `git worktree` checkouts use
///    a `.git` *file* pointing back at the parent's `.git/` (a regular
///    file, hence the explicit `is_file()` admit);
/// 3. at least one of the known MCP discovery probes
///    ([`mcp_lock::MCP_CONFIG_RELATIVE_PATHS`]) resolves to a regular
///    file — a working MCP config alone is enough to call this a real
///    target (a `.mcp.json` outside any other repo marker is still
///    something the operator deliberately wrote).
///
/// **No `.tirith/` admit arm.** A previous version of this gate accepted
/// the root when `<repo_root>/.tirith/` existed, on the rationale that a
/// tirith-managed directory was a deliberate operator artifact. But this
/// rule self-selects on `is_mcp_lockfile(file_path)` — the scanned path
/// is `<X>/.tirith/mcp.lock`, so on any real scan path (where the scanner
/// physically read the file off disk), `<X>/.tirith/` is *guaranteed* to
/// exist. The `.tirith/` arm therefore always passed, defeating the gate's
/// own purpose: a stray `.tirith/mcp.lock` under `/tmp/random/` would
/// still produce the very finding-storm F9 was designed to suppress. The
/// remaining arms ((1) relative-path carve-out, (2) `.git/` marker, (3)
/// an actual MCP config) are each independent and *not* derivable from
/// the lockfile's own presence, so they remain meaningful signals.
///
/// The case explicitly rejected: an *absolute* path under a directory
/// that has none of (2)–(3). That's the F9 "stray `/tmp/random/.tirith/
/// mcp.lock`" failure mode.
fn looks_like_repo_root(repo_root: &Path) -> bool {
    // Admit-by-construction case 1: a relative root with no parent
    // components (the empty Path produced by `Path("foo").parent()` on a
    // single-component relative path, or `Path(".")` literal). The caller
    // pointed at a lockfile by relative path; respect that.
    if repo_root.as_os_str().is_empty() || repo_root == Path::new(".") {
        return true;
    }

    let git_path = repo_root.join(".git");
    if let Ok(meta) = std::fs::metadata(&git_path) {
        if meta.is_dir() || meta.is_file() {
            return true;
        }
    }

    for rel in mcp_lock::MCP_CONFIG_RELATIVE_PATHS {
        if let Ok(meta) = std::fs::metadata(repo_root.join(rel)) {
            if meta.is_file() {
                return true;
            }
        }
    }

    false
}

/// Run the MCP-drift rule against a file's contents.
///
/// `file_path` must be the absolute or relative path the scan walked — the
/// repo root is derived from it (`<repo>/.tirith/mcp.lock` → `<repo>`).
/// A path that is not the lockfile, or for which the repo root cannot be
/// derived, yields no findings.
///
/// `content` is the file's textual contents as the scan read them; the
/// lockfile is JSON, so a non-UTF8 body simply fails to parse and yields
/// no findings.
///
/// `trusted_mcp_servers` is `policy.scan.trusted_mcp_servers`: drift entries
/// (Added / Removed / Changed) whose server name is in that list are filtered
/// out of the drift before a finding is built. When **every** drift is for a
/// trusted server, no finding fires. When some are trusted and others are
/// not, only the untrusted ones surface.
///
/// `mcp_allowed_tools` is `policy.scan.mcp_allowed_tools`: a per-server
/// allow-list of tool names. Two effects:
///
/// * **Lockfile-side**: when the lockfile itself records a tool that is not
///   in the allowed set for a server listed in `mcp_allowed_tools`, a
///   `McpServerDrift` finding fires (severity High) naming the disallowed
///   tools. Fires alongside any other drift; never fires if no policy entry
///   exists for the server.
/// * **Drift-side**: when an Added or Changed drift introduces a tool that
///   is not in the allowed set for a server listed in `mcp_allowed_tools`,
///   the drift finding is **upgraded to High severity** (the default is
///   Medium). For `Changed`, the inspected list is `tools_added`. For
///   `Added`, the inspected list is the brand-new server's declared
///   `tools` (every tool on a new server is effectively a fresh addition
///   relative to the previous lockfile state). Drift inside the allowed
///   set keeps Medium.
pub fn check(
    content: &str,
    file_path: Option<&Path>,
    trusted_mcp_servers: &[String],
    mcp_allowed_tools: &HashMap<String, Vec<String>>,
) -> Vec<Finding> {
    if !is_mcp_lockfile(file_path) {
        return Vec::new();
    }

    // Parse the lockfile. A malformed lockfile is itself a security signal:
    // the committed baseline cannot be diffed against the current inventory,
    // so drift cannot be verified. An attacker who altered the MCP surface
    // and then corrupted the lockfile would silently bypass scan-time
    // governance if we returned no findings. Emit the same `McpServerDrift`
    // rule as a drift detection — same severity, distinct description — so
    // the safeguard tests and rule_explanations entry need no schema change.
    let lockfile = match mcp_lock::parse_lockfile(content) {
        Ok(l) => l,
        Err(e) => return vec![finding_for_unparseable_lockfile(&e)],
    };

    // Derive the repo root: `<repo>/.tirith/mcp.lock` → `<repo>`.
    let Some(repo_root) = file_path.and_then(|p| p.parent()).and_then(|p| p.parent()) else {
        return Vec::new();
    };

    // Validation: the derived repo root must look like a real repository
    // before we treat absence-of-configs as drift. Scanning `.tirith/mcp.lock`
    // outside a repo (e.g. a copy sitting under `/tmp/random/`) would
    // otherwise produce "every server removed" noise — `build_inventory`
    // probes a fixed set of MCP config paths under the derived root, finds
    // none, and `compute_drift` then flags every recorded server as Removed.
    // Require any one of:
    //   1. a `.git/` directory or file (the `.git` file form is how
    //      `git worktree` and submodule checkouts mark a working tree);
    //   2. at least one of the known MCP discovery probes physically
    //      present (so a repo without a `.git` but with a real
    //      `.mcp.json` is still gateable).
    // The previous version also admitted on a bare `.tirith/` directory,
    // but that arm was tautological for any real scan path (the lockfile we
    // are scanning lives *inside* `.tirith/`, so the directory necessarily
    // exists); see the rationale in `looks_like_repo_root`'s doc-comment.
    // If none of those are present, the scan target is not a repository in
    // any sense this rule understands; treat absence as silence, not
    // a finding storm.
    if !looks_like_repo_root(repo_root) {
        return Vec::new();
    }

    // Build the current inventory off of the repo root. `build_inventory` is
    // total (a malformed config contributes no entries) so this cannot panic
    // or error.
    let current = mcp_lock::build_inventory(repo_root);

    let drifts = mcp_lock::compute_drift(&current, &lockfile);

    // Policy: drop drift entries whose server NAME is in the trusted list.
    // The operator has accepted that server's surface as a deliberate
    // decision — drift on it should not raise a finding. If every drift is
    // for a trusted server, no drift finding fires at all.
    let drifts_after_trust = drift_filter_trusted(drifts, trusted_mcp_servers);

    let mut findings: Vec<Finding> = Vec::new();

    // Policy: scan the lockfile's own recorded tool list against
    // `mcp_allowed_tools`. Tools recorded in the lockfile that are not in
    // the policy's allowed-set for that server are a policy violation in
    // their own right — exactly the failure mode of "snuck a tool past
    // `tirith mcp lock`" the per-tool gate is designed to catch.
    //
    // **Trust does NOT apply here.** `trusted_mcp_servers` suppresses
    // *drift findings* — the operator accepts the server's surface as
    // observed. `mcp_allowed_tools` is a separate, orthogonal mechanism:
    // the per-tool allow-list the operator wrote because they want
    // exactly that list enforced. An older version of this code did
    // pass `trusted_mcp_servers` through and let trust silently override
    // the explicit allow-list; PR #121 item 8 fixes that. The trust list
    // is still passed (for backward signature stability and any future
    // re-introduction), but is no longer consulted inside the helper.
    if let Some(finding) =
        finding_for_disallowed_lockfile_tools(&lockfile, mcp_allowed_tools, trusted_mcp_servers)
    {
        findings.push(finding);
    }

    if !drifts_after_trust.is_empty() {
        // Drift severity ladder: Medium by default, upgraded to High if any
        // newly-added tool is outside the allowed set for that server.
        let severity = if any_added_tool_out_of_allowed(&drifts_after_trust, mcp_allowed_tools) {
            Severity::High
        } else {
            Severity::Medium
        };
        findings.push(finding_for_drift(&drifts_after_trust, severity));
    }

    findings
}

/// Drop drift entries whose server name is in `trusted` — operator-trusted
/// servers do not raise drift findings.
fn drift_filter_trusted(
    drifts: Vec<mcp_lock::McpDrift>,
    trusted: &[String],
) -> Vec<mcp_lock::McpDrift> {
    if trusted.is_empty() {
        return drifts;
    }
    drifts
        .into_iter()
        .filter(|d| !trusted.iter().any(|t| t == d.name()))
        .collect()
}

/// `true` when at least one drift introduces a tool that is NOT in the
/// `mcp_allowed_tools` set for that server. A server not listed in
/// `mcp_allowed_tools` is unconstrained (its drift contributes nothing
/// to the upgrade decision).
///
/// Two drift kinds carry "added tools" and both feed the severity ladder:
///
/// * **`Changed`** — the per-server `tools_added` field. A pre-existing
///   server now exposes a tool the previous lockfile state did not.
/// * **`Added`** — a brand-new server entry, whose declared `tools` list
///   is treated as a fresh set of additions against the (implicit) empty
///   previous state. Without surfacing the new server's tools here, an
///   attacker could smuggle a disallowed tool by introducing a new server
///   instead of mutating an existing one — exactly the asymmetry CodeRabbit
///   flagged (`mcp_allowed_tools` ladder must cover both paths).
///
/// **Allowed-list semantics** (same on both paths):
/// * A server unlisted in `mcp_allowed_tools` is unconstrained — its tools
///   never trigger an upgrade.
/// * A server listed with `[]` (empty allow-list) forbids *any* tool — every
///   tool the server declares triggers an upgrade.
/// * A server listed with a non-empty allow-list permits exactly those tools.
fn any_added_tool_out_of_allowed(
    drifts: &[mcp_lock::McpDrift],
    mcp_allowed_tools: &HashMap<String, Vec<String>>,
) -> bool {
    if mcp_allowed_tools.is_empty() {
        return false;
    }
    for d in drifts {
        match d {
            mcp_lock::McpDrift::Changed(entry) => {
                let Some(allowed) = mcp_allowed_tools.get(&entry.name) else {
                    continue;
                };
                for tool in &entry.tools_added {
                    if !allowed.iter().any(|a| a == tool) {
                        return true;
                    }
                }
            }
            mcp_lock::McpDrift::Added { name, tools, .. } => {
                // A brand-new server: every declared tool is effectively an
                // "added" tool relative to the previous lockfile state. The
                // same policy-set test the `Changed` arm runs applies here.
                let Some(allowed) = mcp_allowed_tools.get(name) else {
                    continue;
                };
                for tool in tools {
                    if !allowed.iter().any(|a| a == tool) {
                        return true;
                    }
                }
            }
            mcp_lock::McpDrift::Removed { .. } => {
                // A removed server's tools do not get "added" anywhere; the
                // upgrade ladder is about NEW exposure, never lost exposure.
            }
        }
    }
    false
}

/// Build a finding for lockfile-recorded tools that are not in the
/// `mcp_allowed_tools` set. Returns `None` if every recorded tool is
/// allowed (or no policy entry exists for any server).
///
/// The finding lists at most a few server names and the offending tools
/// per server; full per-server detail belongs in `tirith mcp verify`. The
/// rule fires at High severity — a recorded tool outside policy is a
/// stronger signal than ordinary drift because the lockfile was supposed
/// to have caught it.
///
/// **`trusted` is intentionally not consulted here.** The previous
/// behavior suppressed lockfile-side findings for trusted servers — but
/// that conflated two orthogonal mechanisms. `trusted_mcp_servers`
/// suppresses *drift findings* (the operator declared they accept the
/// server's surface as-is). `mcp_allowed_tools` is a *per-tool allow-list*
/// the operator wrote because they want exactly that list enforced. An
/// operator who configures both means "trust drift, but still hold this
/// server's tools to [list]"; trust must not silently override the
/// allow-list. PR #121 item 8 fixes this — the parameter remains in the
/// signature so callers don't change, but is no longer consulted. See the
/// block comment inside the loop for the full rationale.
fn finding_for_disallowed_lockfile_tools(
    lockfile: &mcp_lock::McpLockfile,
    mcp_allowed_tools: &HashMap<String, Vec<String>>,
    _trusted: &[String],
) -> Option<Finding> {
    if mcp_allowed_tools.is_empty() {
        return None;
    }

    // Collect (server_name, disallowed_tools) pairs in stable order:
    // servers in lockfile order (already sorted), tools as recorded.
    //
    // **Trust no longer bypasses an explicit allowed-tools entry.**
    // `trusted_mcp_servers` suppresses drift findings (operator accepted
    // the *surface* as-is), but `mcp_allowed_tools` is a separate,
    // orthogonal mechanism — a per-tool allow-list that the operator
    // wrote because they want exactly that list enforced. An operator
    // who lists BOTH (trusted: [foo]) AND (mcp_allowed_tools: { foo:
    // [bar] }) means "trust foo's drift, but still hold its tools to
    // [bar]". The old behavior conflated the two, silently letting
    // trust override the explicit policy — PR #121 item 8.
    //
    // The trust-bypass is still honored for servers that have NO
    // `mcp_allowed_tools` entry: trust suppresses the finding the same
    // way it suppresses drift findings, because there is no explicit
    // policy to enforce against.
    let mut offenders: Vec<(String, Vec<String>)> = Vec::new();
    for server in &lockfile.servers {
        let Some(allowed) = mcp_allowed_tools.get(&server.name) else {
            // No explicit allow-list — trust would apply if the server
            // were here, but with no policy to enforce there is nothing
            // to flag.
            continue;
        };
        // An explicit `mcp_allowed_tools` entry exists for this server.
        // Enforce it regardless of whether the operator also marked the
        // server trusted — `trusted` is intentionally not consulted on
        // this branch (see the block comment above).
        let disallowed: Vec<String> = server
            .tools
            .iter()
            .filter(|t| !allowed.iter().any(|a| a == *t))
            .cloned()
            .collect();
        if !disallowed.is_empty() {
            offenders.push((server.name.clone(), disallowed));
        }
    }

    if offenders.is_empty() {
        return None;
    }

    // Build a one-line summary plus a structured detail listing of
    // the offenders. Every name is debug-escaped (`{:?}`) so a control
    // byte inside a name cannot inject into the operator's terminal —
    // same convention as `mcp.rs::escape_name`.
    let server_count = offenders.len();
    let total_tool_count: usize = offenders.iter().map(|(_, t)| t.len()).sum();
    let summary = format!(
        "{server_count} server(s) record {total_tool_count} tool(s) outside `scan.mcp_allowed_tools`"
    );

    let mut lines: Vec<String> = Vec::with_capacity(offenders.len());
    for (name, tools) in offenders.iter().take(5) {
        let escaped_tools: Vec<String> = tools.iter().map(|t| format!("{t:?}")).collect();
        lines.push(format!(
            "  - {} → {}",
            format_args!("{name:?}"),
            escaped_tools.join(", ")
        ));
    }
    if offenders.len() > 5 {
        lines.push(format!("  - … and {} more server(s)", offenders.len() - 5));
    }
    let detail = format!(
        "MCP lockfile carries tools outside policy: {summary}.\n{}",
        lines.join("\n")
    );

    Some(Finding {
        rule_id: RuleId::McpServerDrift,
        severity: Severity::High,
        title: "MCP lockfile records tools outside `mcp_allowed_tools` policy".to_string(),
        description: format!(
            "The committed `.tirith/mcp.lock` lists MCP server tools that are not in the \
             `scan.mcp_allowed_tools` allow-list for those servers ({summary}). A tool \
             recorded in the lockfile that policy does not permit is a stronger signal \
             than ordinary drift: the lockfile was supposed to be the gating baseline, \
             and a forbidden tool reached the recorded state anyway. Either widen the \
             policy's `mcp_allowed_tools` set for the affected server(s) to admit the \
             tool intentionally, or remove the tool from the server's configuration and \
             re-run `tirith mcp lock`."
        ),
        evidence: vec![Evidence::Text { detail }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    })
}

/// Build the single drift finding from the structured drift list.
///
/// Aggregates by drift kind so the description fits in one line: "N added,
/// M removed, K changed". The first few server names are listed for
/// orientation; the full structured drift is the domain of
/// `tirith mcp verify --format json`, not the scan finding.
///
/// `severity` is the severity to emit. The default is `Medium`; the caller
/// passes `High` when policy's `mcp_allowed_tools` ladder applies (a
/// newly-added tool is outside the allowed set for its server).
fn finding_for_drift(drifts: &[mcp_lock::McpDrift], severity: Severity) -> Finding {
    let mut added = 0usize;
    let mut removed = 0usize;
    let mut changed = 0usize;
    let mut names: Vec<String> = Vec::new();
    for d in drifts {
        match d {
            mcp_lock::McpDrift::Added { .. } => added += 1,
            mcp_lock::McpDrift::Removed { .. } => removed += 1,
            mcp_lock::McpDrift::Changed(_) => changed += 1,
        }
        if names.len() < 5 {
            names.push(d.name().to_string());
        }
    }

    let summary =
        format!("{added} added, {removed} removed, {changed} changed since the lockfile was taken");
    let mut detail = format!("MCP inventory drift: {summary}.");
    if !names.is_empty() {
        let listed: Vec<String> = names.iter().map(|n| format!("{n:?}")).collect();
        let suffix = if drifts.len() > names.len() {
            format!(" first servers: {} …", listed.join(", "))
        } else {
            format!(" servers: {}", listed.join(", "))
        };
        detail.push_str(&suffix);
    }

    Finding {
        rule_id: RuleId::McpServerDrift,
        severity,
        title: "MCP server inventory has drifted from the committed lockfile".to_string(),
        description: format!(
            "The MCP servers declared in this repository's configuration files no longer \
             match `.tirith/mcp.lock` ({summary}). The change may be intentional — but it \
             is a security-relevant surface change (a server added, removed, or its \
             transport / env / declared tools / URL credentials altered) and should be \
             reviewed before commit. Run `tirith mcp diff` (informational) or \
             `tirith mcp verify` (gating) to see the exact drift, then re-run \
             `tirith mcp lock` to refresh the lockfile."
        ),
        evidence: vec![Evidence::Text { detail }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

/// Build the finding fired when `.tirith/mcp.lock` cannot be parsed.
///
/// The lockfile is the committed baseline a `tirith scan` diffs the current
/// inventory against. A baseline that doesn't parse cannot be diffed, so
/// drift cannot be verified — exactly the silent-failure mode that would
/// let an attacker hide an MCP-surface change behind a corrupted lockfile.
/// Surface it explicitly: same `RuleId` and severity as a drift finding so
/// the existing verdict / scoring / explanation paperwork stays unchanged,
/// distinct description so the operator can tell the two failure modes
/// apart.
///
/// **Privacy.** The description **does not** interpolate the underlying
/// `serde_json::Error` message. `serde_json::Error`'s `Display` impl can
/// echo the offending JSON value (`invalid type: string "...", expected
/// ...`), and `.tirith/mcp.lock` is exactly the file we redact env values
/// and URL userinfos out of (see `mcp_lock.rs`). A malformed lockfile
/// containing a secret-shaped value — an unintentionally-committed
/// credential, a partial config — would then surface that value in the
/// finding's description: a privacy leak via diagnostic. So we name the
/// failure category explicitly (`unparseable JSON`, etc.) and, when the
/// upstream variant carries them, surface only the structurally-safe
/// line/column numbers from `serde_json::Error` (both `usize`, neither
/// can echo content). [`mcp_lock::parse_lockfile`] enforces the same
/// invariant at the source by dropping the parser's message string at
/// the boundary.
fn finding_for_unparseable_lockfile(err: &mcp_lock::McpLockLoadError) -> Finding {
    // Map the lock-load error to a structured (category, optional
    // location) pair. The category names the failure plainly; the
    // location, when present, is line/column numbers only — never a
    // textual error message that could echo the lockfile's bytes.
    //
    // The schema-version case is its own arm: a lockfile written by a
    // different tirith version is a meaningfully different operator
    // situation from "the JSON is corrupt" (the file is intact and
    // structured; it just speaks an older or newer schema), so the
    // human-readable category and the title/description below name
    // that case distinctly. The two version numbers (`u32`s) are
    // safe to interpolate — neither can echo lockfile bytes.
    let (category, location): (String, Option<String>) = match err {
        mcp_lock::McpLockLoadError::NotFound => {
            // `check()` only constructs an unparseable finding from a
            // `parse_lockfile` result on content the scan already read,
            // so NotFound is not reachable here in practice. Named
            // explicitly anyway so a future caller cannot accidentally
            // surface a path string through the finding description.
            ("missing baseline file".to_string(), None)
        }
        mcp_lock::McpLockLoadError::Io { .. } => {
            // Suppress the inner io-error category — even though
            // `std::io::Error` typically does not echo file contents,
            // refusing to interpolate any io detail (even the
            // structured `kind` exposed by `mcp_lock`) removes a
            // class of future diagnostic-leak regressions. The
            // `McpLockLoadError`'s own `Display` exposes the kind
            // to the CLI surface; this rule's description is
            // strictly category-only.
            ("unreadable file".to_string(), None)
        }
        mcp_lock::McpLockLoadError::Parse { line, column } => (
            "unparseable JSON or schema mismatch".to_string(),
            Some(format!("line {line}, column {column}")),
        ),
        mcp_lock::McpLockLoadError::UnsupportedVersion { found, supported } => (
            format!(
                "incompatible lockfile schema version {found} (this tirith supports {supported})"
            ),
            None,
        ),
    };
    let location_suffix = match &location {
        Some(loc) => format!(" at {loc}"),
        None => String::new(),
    };

    // The version-mismatch case gets its own title and description so the
    // operator can distinguish "this lockfile speaks an older / newer
    // schema, refresh it" from "the JSON is corrupt, investigate before
    // regenerating". Both still emit `RuleId::McpServerDrift` with the
    // same Medium severity so existing rule_explanations / scoring /
    // safeguard paperwork is unchanged.
    let (title, description) = match err {
        mcp_lock::McpLockLoadError::UnsupportedVersion { found, supported } => (
            "MCP lockfile schema version is incompatible — drift cannot be verified".to_string(),
            format!(
                "The committed `.tirith/mcp.lock` declares schema version {found}, but this \
                 build of tirith supports version {supported}. Because the baseline cannot \
                 be loaded, this scan cannot diff it against the current MCP-server \
                 inventory — drift that would otherwise have been caught is silently \
                 undetectable. The lockfile was likely written by a different tirith \
                 release (a newer one that bumped the schema, or an older one that hasn't \
                 caught up to the current shape). Re-run `tirith mcp lock` to refresh the \
                 lockfile, or upgrade tirith to a build that understands schema version \
                 {found}."
            ),
        ),
        _ => (
            "MCP lockfile is unparseable — drift cannot be verified".to_string(),
            format!(
                "The committed `.tirith/mcp.lock` is not valid JSON or does not match the \
                 expected lockfile schema ({category}{location_suffix}). Because the baseline \
                 cannot be loaded, this scan cannot diff it against the current MCP-server \
                 inventory — drift that would otherwise have been caught is silently \
                 undetectable. The lockfile may have been tampered with, accidentally \
                 corrupted, or written by a future tirith version with an incompatible schema. \
                 Inspect `.tirith/mcp.lock` (it is a small JSON document), restore it from \
                 version control if it has been damaged, or re-run `tirith mcp lock` to \
                 refresh the baseline against the current inventory."
            ),
        ),
    };

    let detail = format!(
        "MCP lockfile `.tirith/mcp.lock` could not be loaded ({category}{location_suffix}); \
         drift cannot be verified."
    );

    Finding {
        rule_id: RuleId::McpServerDrift,
        severity: Severity::Medium,
        title,
        description,
        evidence: vec![Evidence::Text { detail }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::tempdir;

    use crate::mcp_lock::{McpInventory, McpLockfile, McpServerEntry, McpTransport};

    fn write_lockfile_for(repo: &Path, inv: &McpInventory) {
        let lockdir = repo.join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        fs::write(
            lockdir.join("mcp.lock"),
            McpLockfile::from_inventory(inv).render(),
        )
        .unwrap();
    }

    fn write_config(repo: &Path, name: &str, body: &str) {
        if let Some(parent) = Path::new(name).parent() {
            fs::create_dir_all(repo.join(parent)).unwrap();
        }
        fs::write(repo.join(name), body).unwrap();
    }

    #[test]
    fn is_mcp_lockfile_matches_exact_layout() {
        assert!(is_mcp_lockfile(Some(&PathBuf::from(".tirith/mcp.lock"))));
        assert!(is_mcp_lockfile(Some(&PathBuf::from(
            "/abs/repo/.tirith/mcp.lock"
        ))));
        // Wrong parent dir.
        assert!(!is_mcp_lockfile(Some(&PathBuf::from("subdir/mcp.lock"))));
        // Wrong basename.
        assert!(!is_mcp_lockfile(Some(&PathBuf::from(
            ".tirith/policy.yaml"
        ))));
        // No parent.
        assert!(!is_mcp_lockfile(Some(&PathBuf::from("mcp.lock"))));
        // No path.
        assert!(!is_mcp_lockfile(None));
    }

    #[test]
    fn check_returns_empty_on_non_lockfile_path() {
        // A file with the right name elsewhere must not trigger.
        let v = check(
            r#"{"format_version":4,"inventory_hash":"x","configs":[],"servers":[]}"#,
            Some(&PathBuf::from("subdir/mcp.lock")),
            &[],
            &HashMap::new(),
        );
        assert!(v.is_empty());
    }

    #[test]
    fn check_returns_empty_when_inventory_matches_lockfile() {
        // A clean repo: the lockfile we wrote matches the inventory the
        // scan will compute. No drift, no finding.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node" } } }"#,
        );
        let inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &inv);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &HashMap::new());
        assert!(findings.is_empty(), "no drift → no finding: {findings:?}");
    }

    #[test]
    fn check_fires_when_server_added_to_config_after_lockfile() {
        // Step 1: a repo with one MCP server, lockfile committed.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "a": { "command": "node" } } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        // Step 2: the user adds a second MCP server to .mcp.json (so the
        // config drifted from the lockfile).
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": {
                "a": { "command": "node" },
                "b": { "command": "deno" }
            } }"#,
        );

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &HashMap::new());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::McpServerDrift);
        assert_eq!(findings[0].severity, Severity::Medium);
        // The aggregated summary mentions the addition.
        assert!(findings[0].description.contains("1 added"));
    }

    #[test]
    fn check_fires_when_env_value_rotated() {
        // Headline integration of the env-value-hash drift signal: a
        // rotated credential surfaces as a finding when scanning the
        // (now-stale) lockfile.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "env": { "API_TOKEN": "old-credential" } } } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        // The user rotates the token.
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "env": { "API_TOKEN": "new-credential" } } } }"#,
        );

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &HashMap::new());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("1 changed"));

        // And no raw credential bytes appear in the finding.
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(!serialized.contains("old-credential"));
        assert!(!serialized.contains("new-credential"));
    }

    #[test]
    fn check_fires_when_lockfile_is_malformed_json() {
        // A malformed lockfile is itself a security signal: the committed
        // baseline cannot be diffed against the current inventory, so drift
        // cannot be verified. Returning no findings here would let an
        // attacker hide an MCP-surface change behind a deliberately broken
        // lockfile. The rule fires with the same RuleId (no schema change)
        // and severity (Medium → Warn) as a drift finding, with a distinct
        // description naming the parse failure.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node" } } }"#,
        );
        let lockdir = repo.path().join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        fs::write(lockdir.join("mcp.lock"), "{not json").unwrap();

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &HashMap::new());
        assert_eq!(
            findings.len(),
            1,
            "malformed lockfile must fire one finding"
        );
        assert_eq!(findings[0].rule_id, RuleId::McpServerDrift);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(
            findings[0].title.contains("unparseable"),
            "unparseable-lockfile title should name the failure mode: {:?}",
            findings[0].title,
        );
        assert!(
            findings[0]
                .description
                .contains("`.tirith/mcp.lock` is not valid JSON")
                || findings[0]
                    .description
                    .contains("does not match the expected lockfile schema"),
            "description should name the parse failure: {:?}",
            findings[0].description,
        );

        // The finding must not echo the lockfile's raw bytes — only the
        // parse-error metadata (line/column) is safe to surface.
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(
            !serialized.contains("{not json"),
            "raw lockfile bytes leaked into finding: {serialized}"
        );
    }

    #[test]
    fn unparseable_finding_does_not_echo_serde_json_message() {
        // Privacy invariant: `serde_json::Error`'s `Display` can include
        // the offending JSON value (`invalid type: string "...",
        // expected ...`). A `.tirith/mcp.lock` containing a
        // secret-shaped value (an accidentally-committed credential, a
        // partial config) would then surface that value through the
        // finding description. The finding must NOT carry that error
        // message — only the failure category and, optionally,
        // line/column numbers.
        let repo = tempdir().unwrap();
        let lockdir = repo.path().join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();

        // A distinctive credential-shaped value that serde_json would
        // echo if we naively used `format!("{e}")`. The JSON below is
        // syntactically valid but the wrong shape for the lockfile
        // schema — serde_json's message for this failure mode is
        // exactly the documented `invalid type: string "...",
        // expected struct ...` form.
        let secret = "ghp_LEAK_PROBE_DO_NOT_LET_THIS_INTO_THE_FINDING";
        let body = format!(r#""{secret}""#);
        fs::write(lockdir.join("mcp.lock"), &body).unwrap();

        let lock_path = lockdir.join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &HashMap::new());
        assert_eq!(findings.len(), 1);

        let f = &findings[0];
        // Direct probes on the description: the credential-shaped
        // value, the literal substrings serde_json typically uses to
        // frame the offending value, and the offending JSON content
        // (the raw body bytes) must all be absent.
        assert!(
            !f.description.contains(secret),
            "secret leaked into finding description: {}",
            f.description,
        );
        assert!(
            !f.description.contains("invalid type:"),
            "serde_json's `invalid type:` framing leaked into description: {}",
            f.description,
        );
        // We can't assert `!description.contains("expected")` outright
        // because the legitimate prose already contains the word
        // (e.g. "expected lockfile schema"). Assert the specific
        // serde_json idiom `expected struct`/`expected one of`/
        // `expected value` did not leak.
        assert!(
            !f.description.contains("expected struct"),
            "serde_json's `expected struct ...` framing leaked into description: {}",
            f.description,
        );
        assert!(
            !f.description.contains("expected value"),
            "serde_json's `expected value` framing leaked into description: {}",
            f.description,
        );
        assert!(
            !f.description.contains("expected one of"),
            "serde_json's `expected one of ...` framing leaked into description: {}",
            f.description,
        );
        assert!(
            !f.description.contains(&body),
            "raw lockfile bytes leaked into description: {}",
            f.description,
        );

        // And likewise on the full serialized finding (evidence,
        // detail, every field).
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(
            !serialized.contains(secret),
            "secret leaked into serialized finding: {serialized}"
        );
        assert!(
            !serialized.contains("invalid type:"),
            "serde_json's `invalid type:` framing leaked into serialized finding: {serialized}"
        );
        assert!(
            !serialized.contains("expected struct"),
            "serde_json's `expected struct` framing leaked into serialized finding: {serialized}"
        );

        // Sanity: the description still names the failure category and
        // (when available) the safe line/column metadata, so the
        // operator can act on the finding.
        assert!(
            f.description.contains("unparseable JSON") || f.description.contains("schema mismatch"),
            "description must still name the failure category: {}",
            f.description,
        );
    }

    #[test]
    fn check_fires_on_lockfile_with_unknown_schema_fields() {
        // A lockfile that is valid JSON but does not match the expected
        // schema (e.g. produced by a future tirith with an incompatible
        // shape, or hand-crafted by an attacker) must also surface — same
        // verification-impossible failure mode.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node" } } }"#,
        );
        let lockdir = repo.path().join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        // Valid JSON, but missing every required field.
        fs::write(lockdir.join("mcp.lock"), r#"{"unrelated":true}"#).unwrap();

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &HashMap::new());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::McpServerDrift);
        assert!(
            findings[0].title.contains("unparseable"),
            "schema mismatch is treated as unparseable: {:?}",
            findings[0].title,
        );
    }

    #[test]
    fn check_handles_lockfile_that_describes_url_userinfo_change() {
        // Lockfile records a URL with userinfo; the config changes to a
        // different userinfo. Drift fires, and the credential never appears
        // in the finding text.
        let repo = tempdir().unwrap();
        // Inventory in the lockfile: URL with userinfo "old:secretA".
        let inv = McpInventory {
            servers: vec![McpServerEntry {
                name: "s".into(),
                transport: McpTransport::Url {
                    url: "https://host.example/sse".into(),
                    userinfo_hash: Some(
                        // Doesn't matter that this is a placeholder — the
                        // current side derives a different hash from the
                        // config and the two won't compare equal.
                        "0000000000000000000000000000000000000000000000000000000000000000".into(),
                    ),
                },
                tools: vec![],
                tools_declared: true,
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        write_lockfile_for(repo.path(), &inv);
        // Current config: URL with userinfo "rotated:newcredential" — a
        // distinctive value we can substring-scan for absence below.
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "url": "https://rotated:newcredential@host.example/sse" } } }"#,
        );

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &HashMap::new());
        assert_eq!(findings.len(), 1);
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(
            !serialized.contains("rotated:newcredential"),
            "raw URL userinfo leaked into the finding: {serialized}"
        );
    }

    #[test]
    fn check_returns_empty_when_no_lockfile_layout() {
        // Path has parent and grandparent but is not `<x>/.tirith/mcp.lock`.
        let path = PathBuf::from("some/other/mcp.lock");
        let findings = check(
            r#"{"format_version":4,"inventory_hash":"x","configs":[],"servers":[]}"#,
            Some(&path),
            &[],
            &HashMap::new(),
        );
        assert!(findings.is_empty());
    }

    // -----------------------------------------------------------------------
    // Chunk 3 — policy-aware suppression: `trusted_mcp_servers` filters
    // drift entries before a finding is built, and `mcp_allowed_tools`
    // controls both the lockfile-side disallowed-tool finding and the
    // per-server drift severity ladder.
    // -----------------------------------------------------------------------

    #[test]
    fn trusted_server_suppresses_drift_finding() {
        // Lockfile records server "trusted"; current config has dropped
        // "trusted" entirely (so drift would fire by default). With
        // `trusted_mcp_servers` listing "trusted", the entire drift is
        // filtered out and no finding fires.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "trusted": { "command": "node" } } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        // Drop the trusted server from the config — the lockfile would
        // therefore record drift, but trust suppresses it.
        write_config(repo.path(), ".mcp.json", r#"{ "mcpServers": {} }"#);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let trusted = vec!["trusted".to_string()];
        let findings = check(&content, Some(&lock_path), &trusted, &HashMap::new());
        assert!(
            findings.is_empty(),
            "drift on a trusted server name must be suppressed: {findings:?}",
        );
    }

    #[test]
    fn untrusted_server_still_drifts_when_others_are_trusted() {
        // Two drifts: one for a trusted name, one for an untrusted one.
        // Only the untrusted one surfaces.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": {
                "trusted": { "command": "node" },
                "untrusted": { "command": "node" }
            } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        // Mutate both: trusted rotates command (drift), untrusted also
        // rotates command (drift).
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": {
                "trusted": { "command": "deno" },
                "untrusted": { "command": "deno" }
            } }"#,
        );

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let trusted = vec!["trusted".to_string()];
        let findings = check(&content, Some(&lock_path), &trusted, &HashMap::new());
        assert_eq!(
            findings.len(),
            1,
            "exactly one drift finding (only for the untrusted server): {findings:?}",
        );
        let f = &findings[0];
        assert_eq!(f.rule_id, RuleId::McpServerDrift);
        // The trusted server's name must NOT appear in the finding.
        let serialized = serde_json::to_string(f).unwrap();
        assert!(
            !serialized.contains("\"trusted\""),
            "trusted server's name leaked into a finding meant for the untrusted one: {serialized}",
        );
        // The untrusted name DOES appear (it's the surviving drift).
        assert!(
            serialized.contains("untrusted"),
            "untrusted server's drift should have surfaced: {serialized}",
        );
    }

    #[test]
    fn unparseable_lockfile_still_fires_even_with_trusted_servers() {
        // A malformed lockfile is itself a finding — and policy's
        // trusted-server list does NOT silence it, because the lockfile
        // could not even be parsed to know which servers it concerns.
        let repo = tempdir().unwrap();
        let lockdir = repo.path().join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        fs::write(lockdir.join("mcp.lock"), "{not json").unwrap();
        let lock_path = lockdir.join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();

        // Trust list is non-empty but the lockfile can't be parsed.
        let trusted = vec!["trusted".to_string()];
        let findings = check(&content, Some(&lock_path), &trusted, &HashMap::new());
        assert_eq!(
            findings.len(),
            1,
            "unparseable-lockfile finding must still fire"
        );
        assert!(findings[0].title.contains("unparseable"));
    }

    #[test]
    fn lockfile_recording_disallowed_tool_fires_finding() {
        // The lockfile itself records a tool that is not in the
        // `mcp_allowed_tools` set for that server. Surfaces as a High-
        // severity finding naming the offending tool.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "tools": ["read", "evil_tool"] } } }"#,
        );
        let inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &inv);

        // Policy: server "s" is allowed only "read".
        let mut allowed = HashMap::new();
        allowed.insert("s".to_string(), vec!["read".to_string()]);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        assert_eq!(
            findings.len(),
            1,
            "expected one finding for the disallowed tool: {findings:?}",
        );
        let f = &findings[0];
        assert_eq!(f.rule_id, RuleId::McpServerDrift);
        assert_eq!(f.severity, Severity::High);
        // The offending tool name appears; the allowed one does not need to.
        let serialized = serde_json::to_string(f).unwrap();
        assert!(
            serialized.contains("evil_tool"),
            "expected the disallowed tool to be named: {serialized}",
        );
    }

    #[test]
    fn lockfile_within_allowed_tools_fires_no_disallowed_finding() {
        // Every recorded tool is in the allowed set → no disallowed-tool
        // finding (and the inventory matches the lockfile, so no drift
        // finding either).
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "tools": ["read", "write"] } } }"#,
        );
        let inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &inv);

        let mut allowed = HashMap::new();
        allowed.insert(
            "s".to_string(),
            vec!["read".to_string(), "write".to_string()],
        );

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        assert!(
            findings.is_empty(),
            "every tool in policy's allowed set → no finding: {findings:?}",
        );
    }

    #[test]
    fn server_not_in_mcp_allowed_tools_is_unconstrained() {
        // A server whose name is NOT a key in `mcp_allowed_tools` is
        // unconstrained — even if it lists tools, no disallowed-tool
        // finding fires.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "other": { "command": "node",
                "tools": ["anything"] } } }"#,
        );
        let inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &inv);

        let mut allowed = HashMap::new();
        allowed.insert(
            "different-server".to_string(),
            vec!["only-this".to_string()],
        );

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        assert!(
            findings.is_empty(),
            "a server not in mcp_allowed_tools is unconstrained: {findings:?}",
        );
    }

    #[test]
    fn drift_with_disallowed_added_tool_upgrades_to_high_severity() {
        // A `Changed` drift that adds a tool not in the allowed set
        // upgrades the drift finding's severity from Medium to High.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "tools": ["read"] } } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        // Add a disallowed tool to the config.
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "tools": ["read", "evil_tool"] } } }"#,
        );

        let mut allowed = HashMap::new();
        allowed.insert("s".to_string(), vec!["read".to_string()]);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        // At least one drift finding fires; the one matching the drift
        // shape (1 changed) is High.
        let drift_finding = findings
            .iter()
            .find(|f| f.description.contains("1 changed"))
            .expect("expected a drift finding for the change");
        assert_eq!(
            drift_finding.severity,
            Severity::High,
            "drift adding a tool outside the allowed set must be High: {:?}",
            drift_finding,
        );
    }

    #[test]
    fn drift_with_only_allowed_added_tool_stays_medium() {
        // A `Changed` drift that adds a tool already in the allowed set
        // keeps the drift finding at the default Medium severity.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "tools": ["read"] } } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        // Add a tool that IS in the allowed set.
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "tools": ["read", "write"] } } }"#,
        );

        let mut allowed = HashMap::new();
        allowed.insert(
            "s".to_string(),
            vec!["read".to_string(), "write".to_string()],
        );

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        let drift_finding = findings
            .iter()
            .find(|f| f.description.contains("1 changed"))
            .expect("expected a drift finding for the change");
        assert_eq!(
            drift_finding.severity,
            Severity::Medium,
            "drift adding only allowed tools must stay Medium: {:?}",
            drift_finding,
        );
    }

    #[test]
    fn empty_allowed_tools_for_server_forbids_any_new_tool() {
        // A server listed in `mcp_allowed_tools` with an empty allow
        // list explicitly forbids ANY tool — every new tool is out-of-set.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node" } } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        // The config now declares one tool.
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "tools": ["any_tool"] } } }"#,
        );

        let mut allowed = HashMap::new();
        allowed.insert("s".to_string(), vec![]);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        // The drift finding must be High (the tool is outside the [] set).
        let drift = findings
            .iter()
            .find(|f| f.description.contains("1 changed"))
            .expect("expected a drift finding");
        assert_eq!(drift.severity, Severity::High);
    }

    // -----------------------------------------------------------------------
    // CodeRabbit follow-up — extend the `mcp_allowed_tools` severity ladder
    // to the `Added` path. A brand-new server smuggling a disallowed tool
    // must escalate the drift finding to High, mirroring the `Changed`
    // path's `tools_added` check. (Before this fix, the ladder fired only
    // on `Changed` and "added a server with a disallowed tool" silently
    // stayed at Medium.)
    // -----------------------------------------------------------------------

    #[test]
    fn added_server_with_disallowed_tool_upgrades_to_high_severity() {
        // Lockfile predates server "newcomer". The config then adds
        // "newcomer" with a tool that is NOT in its `mcp_allowed_tools`
        // entry. The drift finding for the addition must be High.
        let repo = tempdir().unwrap();
        // Step 1: lock with no servers (the baseline doesn't know about
        // "newcomer" yet).
        write_config(repo.path(), ".mcp.json", r#"{ "mcpServers": {} }"#);
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        // Step 2: a brand-new server appears in the config, exposing
        // "evil_tool" (which policy does not permit for "newcomer").
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "newcomer": { "command": "node",
                "tools": ["read", "evil_tool"] } } }"#,
        );

        let mut allowed = HashMap::new();
        allowed.insert("newcomer".to_string(), vec!["read".to_string()]);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        let drift_finding = findings
            .iter()
            .find(|f| f.description.contains("1 added"))
            .expect("expected a drift finding for the added server");
        assert_eq!(
            drift_finding.severity,
            Severity::High,
            "an Added server exposing a tool outside the allowed set must be \
             High (symmetric with the Changed-path ladder): {:?}",
            drift_finding,
        );
    }

    #[test]
    fn added_server_with_only_allowed_tools_stays_medium() {
        // A brand-new server whose every tool IS in the policy's allowed
        // set keeps the default Medium severity — the ladder must not
        // upgrade indiscriminately on Added.
        let repo = tempdir().unwrap();
        write_config(repo.path(), ".mcp.json", r#"{ "mcpServers": {} }"#);
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "newcomer": { "command": "node",
                "tools": ["read", "write"] } } }"#,
        );

        let mut allowed = HashMap::new();
        allowed.insert(
            "newcomer".to_string(),
            vec!["read".to_string(), "write".to_string()],
        );

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        let drift_finding = findings
            .iter()
            .find(|f| f.description.contains("1 added"))
            .expect("expected a drift finding for the added server");
        assert_eq!(
            drift_finding.severity,
            Severity::Medium,
            "an Added server with only allowed tools must stay Medium: {:?}",
            drift_finding,
        );
    }

    #[test]
    fn added_server_unlisted_in_mcp_allowed_tools_stays_medium() {
        // A brand-new server whose NAME does not appear in
        // `mcp_allowed_tools` is unconstrained (same semantics as the
        // Changed path's "server unlisted → no upgrade"). It surfaces as a
        // drift but stays at the default Medium.
        let repo = tempdir().unwrap();
        write_config(repo.path(), ".mcp.json", r#"{ "mcpServers": {} }"#);
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "unconstrained-newcomer": { "command": "node",
                "tools": ["anything", "goes"] } } }"#,
        );

        // Policy mentions a DIFFERENT server — the newcomer is unlisted
        // and therefore not subject to per-server constraints.
        let mut allowed = HashMap::new();
        allowed.insert(
            "different-server".to_string(),
            vec!["only-this".to_string()],
        );

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        let drift_finding = findings
            .iter()
            .find(|f| f.description.contains("1 added"))
            .expect("expected a drift finding for the added server");
        assert_eq!(
            drift_finding.severity,
            Severity::Medium,
            "an Added server unlisted in mcp_allowed_tools is unconstrained \
             and must stay Medium: {:?}",
            drift_finding,
        );
    }

    #[test]
    fn added_server_with_empty_allowed_tools_and_any_tool_is_high() {
        // A brand-new server whose `mcp_allowed_tools` entry is the empty
        // list `[]` (explicit "forbid every tool") exposing ANY tool must
        // escalate to High — mirroring the Changed-path semantics
        // documented in `empty_allowed_tools_for_server_forbids_any_new_tool`.
        let repo = tempdir().unwrap();
        write_config(repo.path(), ".mcp.json", r#"{ "mcpServers": {} }"#);
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "newcomer": { "command": "node",
                "tools": ["any_tool"] } } }"#,
        );

        let mut allowed = HashMap::new();
        allowed.insert("newcomer".to_string(), vec![]);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        let drift_finding = findings
            .iter()
            .find(|f| f.description.contains("1 added"))
            .expect("expected a drift finding for the added server");
        assert_eq!(
            drift_finding.severity,
            Severity::High,
            "an Added server under an empty `[]` allow-list exposing any tool \
             must be High: {:?}",
            drift_finding,
        );
    }

    #[test]
    fn added_server_with_no_tools_stays_medium_even_under_empty_allow_list() {
        // A brand-new server that declares NO tools — even when its
        // `mcp_allowed_tools` entry is `[]` (forbid all) — does not
        // trigger the upgrade: there is no exposed tool to flag.
        // Guards against an over-eager "Added → always High" regression.
        let repo = tempdir().unwrap();
        write_config(repo.path(), ".mcp.json", r#"{ "mcpServers": {} }"#);
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "newcomer": { "command": "node" } } }"#,
        );

        let mut allowed = HashMap::new();
        allowed.insert("newcomer".to_string(), vec![]);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);
        let drift_finding = findings
            .iter()
            .find(|f| f.description.contains("1 added"))
            .expect("expected a drift finding for the added server");
        assert_eq!(
            drift_finding.severity,
            Severity::Medium,
            "an Added server with no declared tools must stay Medium even \
             under an empty allow-list — there is no tool to violate the \
             ladder: {:?}",
            drift_finding,
        );
    }

    // -----------------------------------------------------------------------
    // Wave-end finding F1 — `UnsupportedVersion` surfaces as its own
    // category in the `finding_for_unparseable_lockfile` arm, so the
    // operator sees "this lockfile speaks an older / newer schema, refresh
    // it" rather than "the JSON is corrupt".
    // -----------------------------------------------------------------------

    #[test]
    fn unparseable_finding_version_mismatch_arm_names_versions() {
        // A v999 lockfile must surface as a `McpServerDrift` finding whose
        // title and description name the schema-version case distinctly.
        let repo = tempdir().unwrap();
        let lockdir = repo.path().join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        // Ensure the rule's repo-root validation passes by planting an
        // MCP config under the repo too (so `looks_like_repo_root`
        // succeeds — see the F9 test below).
        fs::write(repo.path().join(".mcp.json"), r#"{ "mcpServers": {} }"#).unwrap();
        fs::write(
            lockdir.join("mcp.lock"),
            r#"{ "format_version": 999, "inventory_hash": "x", "configs": [], "servers": [] }"#,
        )
        .unwrap();

        let lock_path = lockdir.join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &HashMap::new());
        assert_eq!(
            findings.len(),
            1,
            "must fire one finding for the version mismatch"
        );
        let f = &findings[0];
        assert_eq!(f.rule_id, RuleId::McpServerDrift);
        assert_eq!(f.severity, Severity::Medium);
        // Title names the version-mismatch case distinctly (not generic
        // "unparseable").
        assert!(
            f.title.contains("schema version") || f.title.contains("incompatible"),
            "title must name the schema-version case: {}",
            f.title,
        );
        // Description carries both the found and supported numbers.
        assert!(
            f.description.contains("999"),
            "description must name the found version: {}",
            f.description,
        );
    }

    // -----------------------------------------------------------------------
    // Wave-end finding F9 — `check` validates that the derived repo root
    // looks like a real repository before treating absence-of-configs as
    // drift. Scanning a stray `.tirith/mcp.lock` under `/tmp/random/` must
    // produce zero findings, not a finding storm.
    // -----------------------------------------------------------------------

    #[test]
    fn check_returns_empty_when_only_tirith_directory_present() {
        // Regression guard for CodeRabbit cid 3292118206: a previous
        // version of `looks_like_repo_root` admitted on `<repo>/.tirith/`,
        // which is *tautological* for any real scan path. The rule self-
        // selects on `is_mcp_lockfile(file_path)`, meaning the scanned
        // path is `<X>/.tirith/mcp.lock`; on any scan path that actually
        // read the lockfile off disk, `<X>/.tirith/` is *guaranteed* to
        // exist. That arm therefore always passed, defeating F9's whole
        // point — a stray `.tirith/mcp.lock` outside any repo still
        // produced the every-server-removed finding storm.
        //
        // After the fix, a derived repo root whose ONLY signal is the
        // `.tirith/` directory (no `.git`, no MCP discovery probe) must
        // NOT admit. The rule returns no findings — silence, not noise.
        let repo = tempdir().unwrap();
        // Build the lockfile path: <repo>/.tirith/mcp.lock. Creating
        // <repo>/.tirith/ here is the deliberate setup for this test —
        // it is the *only* signal under the repo root.
        let lockdir = repo.path().join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        // No `.git`, no `.mcp.json`, no other MCP discovery probe.
        // The lockfile records one server that the (empty) current
        // inventory does not — so if the gate were still tautological,
        // a drift finding would fire.
        let inv = McpInventory {
            servers: vec![McpServerEntry {
                name: "a".into(),
                transport: McpTransport::Stdio {
                    command: "node".into(),
                    args: vec![],
                    env: vec![],
                },
                tools: vec![],
                tools_declared: true,
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let body = McpLockfile::from_inventory(&inv).render();
        let lock_path = lockdir.join("mcp.lock");
        fs::write(&lock_path, &body).unwrap();

        let findings = check(&body, Some(&lock_path), &[], &HashMap::new());
        assert!(
            findings.is_empty(),
            "`.tirith/` alone is no longer a repo-root admit signal — its presence \
             on every real scan path made the gate tautological. With `.tirith/` as \
             the only marker (no `.git`, no MCP probe), the rule must produce zero \
             findings: {findings:?}",
        );
    }

    #[test]
    fn check_returns_empty_when_repo_root_has_no_markers() {
        // The F9 regression case: a `.tirith/mcp.lock` whose derived
        // repo root has NO `.git`, NO `.tirith/` admit signal, AND NO
        // MCP discovery probes. We construct this by pointing
        // `file_path` at a non-existent layout: the rule does not need
        // the file to physically exist (it takes `content` as an
        // argument), but it does derive the repo root from the path.
        // A non-existent grandparent has nothing for
        // `looks_like_repo_root` to admit on, so the rule must return
        // no findings.
        let non_existent =
            std::path::PathBuf::from("/tmp/tirith_F9_does_not_exist_xyz_xyz_xyz/.tirith/mcp.lock");
        // A well-formed (v4) lockfile body. The content is fine; it's
        // the path that should make us bail.
        let inv = McpInventory {
            servers: vec![McpServerEntry {
                name: "a".into(),
                transport: McpTransport::Stdio {
                    command: "node".into(),
                    args: vec![],
                    env: vec![],
                },
                tools: vec![],
                tools_declared: true,
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let body = McpLockfile::from_inventory(&inv).render();
        let findings = check(&body, Some(&non_existent), &[], &HashMap::new());
        assert!(
            findings.is_empty(),
            "scanning a lockfile whose derived repo root has no repo markers must \
             produce zero findings (not a finding-storm of every-server-removed): \
             {findings:?}",
        );
    }

    #[test]
    fn check_admits_when_git_marker_present() {
        // `.git/` (as a directory) is an admit signal — drift fires
        // normally. This is the most common admit case.
        let repo = tempdir().unwrap();
        fs::create_dir_all(repo.path().join(".git")).unwrap();
        // Plant a lockfile that records a server the current inventory
        // does not have.
        let lockdir = repo.path().join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        let inv = McpInventory {
            servers: vec![McpServerEntry {
                name: "a".into(),
                transport: McpTransport::Stdio {
                    command: "node".into(),
                    args: vec![],
                    env: vec![],
                },
                tools: vec![],
                tools_declared: true,
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let body = McpLockfile::from_inventory(&inv).render();
        let lock_path = lockdir.join("mcp.lock");
        fs::write(&lock_path, &body).unwrap();

        let findings = check(&body, Some(&lock_path), &[], &HashMap::new());
        assert!(
            !findings.is_empty(),
            "a `.git/` directory at the repo root must admit; drift must fire \
             normally: {findings:?}",
        );
    }

    // -----------------------------------------------------------------------
    // PR #121 item 8 — `mcp_allowed_tools` enforcement no longer bows to
    // `trusted_mcp_servers`. Trust suppresses drift findings (operator
    // accepted the surface as-is) but does NOT suppress the explicit
    // per-tool allow-list — that's a separate, orthogonal mechanism. An
    // operator who configures both means "trust drift, but still hold
    // this server's tools to [list]"; the OLD behavior conflated the two
    // and let trust silently override the allow-list.
    // -----------------------------------------------------------------------

    #[test]
    fn trusted_server_does_not_bypass_mcp_allowed_tools() {
        // The lockfile records a tool outside `mcp_allowed_tools` for the
        // ONLY server in the lockfile, AND that server is in
        // `trusted_mcp_servers`. The lockfile-side finding MUST still
        // fire — trust suppresses drift findings only, not the per-tool
        // allow-list.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "trusted": { "command": "node",
                "tools": ["read", "evil_tool"] } } }"#,
        );
        let inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &inv);

        // Policy: server "trusted" is allowed only "read" — so
        // "evil_tool" must fire the lockfile-side finding, regardless
        // of trust.
        let mut allowed = HashMap::new();
        allowed.insert("trusted".to_string(), vec!["read".to_string()]);

        let trusted = vec!["trusted".to_string()];

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &trusted, &allowed);
        let lockfile_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.title.contains("records tools outside"))
            .collect();
        assert_eq!(
            lockfile_findings.len(),
            1,
            "trusted server with an explicit mcp_allowed_tools entry must still fire the \
             disallowed-tool finding (trust suppresses drift only): {findings:?}",
        );
        let serialized = serde_json::to_string(lockfile_findings[0]).unwrap();
        assert!(
            serialized.contains("evil_tool"),
            "finding must name the offending tool: {serialized}",
        );
    }

    #[test]
    fn trusted_server_without_mcp_allowed_tools_still_silent() {
        // Trust still suppresses *when there is no explicit
        // `mcp_allowed_tools` entry for the server* — the case that
        // motivated the original trust-bypass behavior. With no
        // per-tool policy declared, there is nothing for the lockfile-
        // side check to enforce, and the drift-side trust filter does
        // its job (no finding fires).
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "trusted": { "command": "node",
                "tools": ["read", "anything"] } } }"#,
        );
        let inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &inv);

        // No `mcp_allowed_tools` entry for "trusted".
        let allowed = HashMap::new();
        let trusted = vec!["trusted".to_string()];

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &trusted, &allowed);
        assert!(
            findings.is_empty(),
            "no mcp_allowed_tools entry + trusted server → no findings: {findings:?}",
        );
    }

    #[test]
    fn both_trusted_and_untrusted_fire_lockfile_side_when_both_have_allow_lists() {
        // PR #121 item 8 — Both servers have an explicit
        // `mcp_allowed_tools` entry (here, an empty allow-list that
        // permits no tools). Trust no longer bypasses the lockfile-side
        // disallowed-tool finding for the explicit-policy case, so BOTH
        // servers' offending tools must appear.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": {
                "trusted":   { "command": "node", "tools": ["evil_tool_a"] },
                "untrusted": { "command": "node", "tools": ["evil_tool_b"] }
            } }"#,
        );
        let inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &inv);

        let mut allowed = HashMap::new();
        allowed.insert("trusted".to_string(), vec![]);
        allowed.insert("untrusted".to_string(), vec![]);

        let trusted = vec!["trusted".to_string()];

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &trusted, &allowed);
        let lockfile_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.title.contains("records tools outside"))
            .collect();
        assert_eq!(
            lockfile_findings.len(),
            1,
            "exactly one lockfile-side disallowed-tool finding (covering both servers): \
             got {findings:?}",
        );
        let serialized = serde_json::to_string(&lockfile_findings[0]).unwrap();
        assert!(
            serialized.contains("evil_tool_a"),
            "trusted server's offending tool MUST appear (explicit allow-list overrides trust): \
             {serialized}",
        );
        assert!(
            serialized.contains("evil_tool_b"),
            "untrusted server's offending tool must appear: {serialized}",
        );
    }

    // -----------------------------------------------------------------------
    // Wave-end finding F22 (PRT II-5) — the `mcp_allowed_tools` severity
    // ladder only applies to NEW exposure (Added / Changed arms, via
    // `any_added_tool_out_of_allowed`). A `Removed` drift is lost exposure,
    // not new exposure, so it must NOT trigger the High-severity upgrade
    // even when the (now-gone) server's lockfile record carries a tool
    // outside its allowed set. Pin the contract.
    // -----------------------------------------------------------------------

    #[test]
    fn removed_server_with_disallowed_tools_in_lockfile_stays_medium() {
        // Step 1: a repo declares server "s" with a tool "evil" that is
        // NOT in its `mcp_allowed_tools` allowed-set; the lockfile records
        // this state.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "tools": ["evil"] } } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        // Step 2: the user removes server "s" from .mcp.json entirely.
        // The current inventory now has no servers; against the lockfile,
        // this produces exactly one `McpDrift::Removed` entry for "s".
        write_config(repo.path(), ".mcp.json", r#"{ "mcpServers": {} }"#);

        // Policy: server "s" is allowed only "read" (so "evil" is outside
        // the allowed set). The Changed/Added arm would upgrade to High
        // for the same shape; the Removed arm must NOT.
        let mut allowed = HashMap::new();
        allowed.insert("s".to_string(), vec!["read".to_string()]);

        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);

        // The drift finding (the one whose description contains "1 removed")
        // must be present and must stay at the default Medium severity.
        let drift_finding = findings
            .iter()
            .find(|f| f.description.contains("1 removed"))
            .expect("expected a drift finding for the removed server");
        assert_eq!(
            drift_finding.severity,
            Severity::Medium,
            "a Removed drift must NOT upgrade severity from the \
             `mcp_allowed_tools` ladder — the ladder is about NEW exposure, \
             never lost exposure: {drift_finding:?}",
        );

        // The lockfile-side disallowed-tool finding fires too — the
        // lockfile still records "s" with the offending tool. That finding
        // is independent of the drift severity ladder (different code path,
        // own High severity). Pin its presence so the test reflects the
        // full per-scan output and a future refactor that accidentally
        // suppresses one of the two findings is caught.
        let lockfile_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.title.contains("records tools outside"))
            .collect();
        assert_eq!(
            lockfile_findings.len(),
            1,
            "the lockfile-side disallowed-tool finding must still fire for \
             a Removed server whose lockfile record carries a disallowed \
             tool — its code path is independent of the drift ladder: \
             {findings:?}",
        );
    }

    // -----------------------------------------------------------------------
    // Wave-end finding F23 (PRT II-6) — two findings from one scan:
    // `check` can emit BOTH the lockfile-side disallowed-tool finding
    // (`finding_for_disallowed_lockfile_tools`) AND the drift finding
    // (`finding_for_drift`) in the same call, when both conditions hold.
    // Existing tests cover each path in isolation but never the cohabitation.
    // -----------------------------------------------------------------------

    #[test]
    fn check_emits_two_findings_when_lockfile_records_disallowed_tools_and_drift_present() {
        // Setup: a repo declares server "s" with tool "read" (in the
        // allowed set) — the lockfile records this state.
        let repo = tempdir().unwrap();
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "s": { "command": "node",
                "tools": ["read"] } } }"#,
        );
        let old_inv = mcp_lock::build_inventory(repo.path());
        write_lockfile_for(repo.path(), &old_inv);

        // Now manually rewrite the lockfile so it ALSO records a
        // disallowed tool "evil" for "s" — simulating the failure mode
        // of "a tool was snuck past `tirith mcp lock`" the lockfile-side
        // check is designed to catch.
        let lock_path = repo.path().join(".tirith").join("mcp.lock");
        let lockfile_doctored = r#"{
            "format_version": 4,
            "inventory_hash": "x",
            "configs": [".mcp.json"],
            "servers": [
                {
                    "name": "s",
                    "transport": { "kind": "stdio", "command": "node", "args": [], "env": [] },
                    "tools": ["evil", "read"],
                    "source_config": ".mcp.json",
                    "hash": "deadbeef"
                }
            ]
        }"#;
        fs::write(&lock_path, lockfile_doctored).unwrap();

        // Then mutate the config: add a brand-new server "new" so a
        // drift fires alongside the lockfile-side check.
        write_config(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": {
                "s":   { "command": "node", "tools": ["read"] },
                "new": { "command": "node", "tools": ["read"] }
            } }"#,
        );

        // Policy: "s" allows only "read" (so the doctored "evil" tool is
        // outside the allowed set, firing the lockfile-side finding).
        let mut allowed = HashMap::new();
        allowed.insert("s".to_string(), vec!["read".to_string()]);

        let content = fs::read_to_string(&lock_path).unwrap();
        let findings = check(&content, Some(&lock_path), &[], &allowed);

        assert_eq!(
            findings.len(),
            2,
            "exactly two findings: the lockfile-side disallowed-tool finding \
             AND the drift finding for the brand-new server. got: {findings:?}",
        );
        // Both must be `McpServerDrift` — no new `RuleId` is introduced
        // by the dual-firing case.
        for f in &findings {
            assert_eq!(
                f.rule_id,
                RuleId::McpServerDrift,
                "both findings must use the McpServerDrift rule id: {f:?}",
            );
        }
        // Their titles must be distinct so a reader can tell them apart at
        // a glance — the lockfile-side title names policy, the drift title
        // names drift.
        let titles: std::collections::HashSet<&str> =
            findings.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(
            titles.len(),
            2,
            "the two findings must have distinct titles so they are \
             distinguishable in human / JSON output: titles={titles:?}",
        );
        // Pin the actual title content — the lockfile-side finding's
        // title references the allow-list (the canonical phrase
        // `records tools outside`), and the drift-side finding's title
        // references drift.
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("records tools outside")),
            "one of the two findings must be the lockfile-side disallowed-tool finding: {findings:?}",
        );
        assert!(
            findings.iter().any(|f| f.title.contains("drift")),
            "one of the two findings must be the drift finding: {findings:?}",
        );
    }
}
