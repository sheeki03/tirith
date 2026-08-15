//! `tirith mcp lock` / `verify` / `diff` — capture and govern the MCP servers
//! a repository declares. Local file ops only (no network, off the detection
//! hot path); discovery is repo-local (user-level configs never inventoried).
//!
//! Privacy invariant: env values and URL userinfos are never persisted or
//! committed in `mcp.lock` (only their structural presence is recorded; see
//! `mcp_lock.rs`) and never printed by `verify`/`diff`. Adding or removing a
//! secret-bearing field drifts; rotating its value intentionally does not.

use std::path::{Path, PathBuf};

use fs2::FileExt;
use tirith_core::mcp_lock::{
    self, McpDrift, McpEnvChange, McpInventory, McpLockLoadError, McpLockServer, McpLockfile,
    McpServerDriftEntry, McpToolsChangeKind, McpTransport, McpTransportChange, MCP_LOCK_FILENAME,
};
use tirith_core::policy;

/// Run `tirith mcp lock`. Builds the MCP inventory and writes
/// `<repo_root>/.tirith/mcp.lock`.
///
/// Exit codes: `0` written (including "no configs found" — an empty but valid
/// lockfile is still written so `verify` has a baseline); `1` operational
/// failure (no repo root, dir create/write failed, or JSON-write failure so a
/// piped consumer never sees truncated JSON with a success code).
pub fn lock(json: bool, allow_incomplete_configs: bool) -> i32 {
    let repo_root = match resolve_repo_root() {
        Some(r) => r,
        None => {
            report_error(
                json,
                "could not determine the repository root — run `tirith mcp lock` inside a git \
                 repository (a directory with a .git), or from a directory whose ancestor has one",
            );
            return 1;
        }
    };

    lock_for_root(&repo_root, json, allow_incomplete_configs)
}

/// Lock against an explicit repo root. Refuses to publish a trusted baseline
/// over any unreadable, ambiguous, secret-bearing, or malformed config unless
/// the operator supplies the explicit audited override.
pub(crate) fn lock_for_root(repo_root: &Path, json: bool, allow_incomplete_configs: bool) -> i32 {
    let mutation_guard = match acquire_mutation_lock(repo_root) {
        Ok(guard) => guard,
        Err(error) => {
            report_error(
                json,
                &format!("could not lock MCP baseline mutation: {error}"),
            );
            return 1;
        }
    };
    let inventory = mcp_lock::build_inventory(repo_root);
    if inventory_has_coverage_gaps(&inventory) && !allow_incomplete_configs {
        report_error(
            json,
            "refusing to write an incomplete MCP baseline: one or more supported config paths \
             were malformed or rejected. Fix the paths/declarations first; only use \
             `--allow-incomplete-configs` to record an explicitly audited gap (verification \
             will remain nonzero while the gap exists)",
        );
        if !json {
            print_coverage_inventory(&inventory);
        }
        return 1;
    }
    let lock_path = repo_root.join(".tirith").join(MCP_LOCK_FILENAME);
    let mut lockfile = McpLockfile::from_inventory(&inventory);
    let preserved_approvals = match mcp_lock::load_lockfile(&lock_path) {
        Ok(previous) => lockfile.preserve_approved_descriptors_from(&previous),
        Err(McpLockLoadError::NotFound) => 0,
        // `mcp lock` remains the repair path for a corrupt/legacy lock. A
        // baseline that cannot be authenticated by the current parser is not
        // safe to carry into the replacement.
        Err(_) => 0,
    };
    // C12: the operator policy, discovered offline. The repository whose MCP
    // servers are being baselined must not get to authorise the write that
    // baselines them, so a repo-scoped `.tirith/policy.yaml` is out of scope here
    // for the same reason it is in `tirith policy init`.
    let operator_policy = policy::Policy::discover_local_only(repo_root.to_str());
    if let Err(e) = write_lockfile(&lock_path, &lockfile, &operator_policy) {
        report_error(
            json,
            &format!("failed to write {}: {e}", lock_path.display()),
        );
        return 1;
    }
    let expected = match lockfile.render() {
        Ok(rendered) => rendered,
        Err(error) => {
            report_error(json, &format!("failed to render MCP lockfile: {error}"));
            return 1;
        }
    };
    let read_back = tirith_core::util::read_text_no_follow_capped(
        &lock_path,
        expected.len().saturating_add(1) as u64,
    );
    if !matches!(read_back, Ok(ref bytes) if bytes == expected.as_bytes()) {
        report_error(
            json,
            "written MCP lock failed exact read-back validation; refusing success",
        );
        return 1;
    }
    drop(mutation_guard);

    if json {
        if !print_json(
            repo_root,
            &lock_path,
            &inventory,
            &lockfile,
            allow_incomplete_configs && inventory_has_coverage_gaps(&inventory),
        ) {
            // Lockfile is on disk, but the caller's JSON output is broken.
            return 1;
        }
    } else {
        print_human(&lock_path, &inventory);
        if preserved_approvals > 0 {
            eprintln!(
                "tirith mcp lock: preserved {preserved_approvals} unchanged live descriptor approval(s)"
            );
        }
        if allow_incomplete_configs && inventory_has_coverage_gaps(&inventory) {
            eprintln!(
                "tirith mcp lock: warning: recorded an explicitly incomplete baseline; \
                 `tirith mcp verify` will fail until every coverage gap is resolved."
            );
        }
    }

    0
}

/// Stable-inode interprocess guard for every `.tirith/mcp.lock` mutation. The
/// data file itself is atomically replaced, so locking it would lock an obsolete
/// inode after rename; all cooperating writers instead lock this never-renamed
/// sibling across read/build/recheck/write/readback.
pub(crate) struct McpMutationGuard {
    file: std::fs::File,
}

impl Drop for McpMutationGuard {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

pub(crate) fn acquire_mutation_lock(repo_root: &Path) -> std::io::Result<McpMutationGuard> {
    let lock_dir = repo_root.join(".tirith");
    std::fs::create_dir_all(&lock_dir)?;
    let canonical_root = std::fs::canonicalize(repo_root)?;
    let canonical_dir = std::fs::canonicalize(&lock_dir)?;
    if !canonical_dir.starts_with(&canonical_root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "MCP mutation lock directory escapes repository root",
        ));
    }
    let lock_path = canonical_dir.join(".mcp-lock.mutation.lock");
    #[cfg(not(unix))]
    if std::fs::symlink_metadata(&lock_path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(std::io::Error::other(
            "refusing symlinked MCP mutation lock",
        ));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(&lock_path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(
            "MCP mutation lock is not a regular file",
        ));
    }
    file.lock_exclusive()?;
    Ok(McpMutationGuard { file })
}

/// Resolve the repository root for `mcp lock`: `TIRITH_POLICY_ROOT` (treated as
/// the repo root directly), then the `.git`-boundary walk via
/// `policy::find_repo_root`.
///
/// Deliberately NOT identical to the codebase's two other resolvers — read all
/// three before assuming a shared helper: `policy::find_repo_root` (trust
/// entries) ignores the env var; `policy::discover_local_policy_path` (`tirith
/// policy`) joins `.tirith/` onto it. They line up in the common case but
/// diverge under the trust resolver. Unifying them is a behavior change for its
/// own PR.
fn resolve_repo_root() -> Option<PathBuf> {
    if let Ok(root) = std::env::var("TIRITH_POLICY_ROOT") {
        if !root.trim().is_empty() {
            return Some(PathBuf::from(root));
        }
    }
    policy::find_repo_root(None)
}

/// Write the rendered lockfile to `<repo_root>/.tirith/mcp.lock`, creating the
/// `.tirith/` directory if needed.
///
/// C12: `mcp.lock` is a Tirith-owned configuration file. It records which MCP
/// servers and tools are approved, which is what `tirith mcp verify` gates drift
/// against and what the gateway reads for descriptor approval, so re-baselining
/// it is the same class of act as rewriting the policy. It publishes through the
/// gated permit rather than the raw contained writer for that reason; `policy` is
/// passed in so the caller owns the discovery and this stays a pure write.
///
/// The write is not flagged as a `policy_change`: it governs which servers are
/// approved, not Tirith's own policy document, matching the commands manifest.
fn write_lockfile(
    lock_path: &Path,
    lockfile: &McpLockfile,
    policy: &policy::Policy,
) -> std::io::Result<()> {
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let repo_root = lock_path
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| std::io::Error::other("MCP lock path has no repository root"))?;
    let rendered = lockfile
        .render()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    super::write_config_file_permitted(
        repo_root,
        lock_path,
        rendered.as_bytes(),
        true,
        policy,
        false,
    )
}

/// Emit the machine-readable result.
///
/// Returns `false` on a JSON-write failure so the caller can exit non-zero.
fn print_json(
    repo_root: &Path,
    lock_path: &Path,
    inventory: &McpInventory,
    lockfile: &McpLockfile,
    incomplete_override_used: bool,
) -> bool {
    #[derive(serde::Serialize)]
    struct JsonOut<'a> {
        /// Result-envelope schema version (independent of the lockfile's own).
        schema_version: u32,
        repo_root: String,
        lock_path: String,
        configs_found: usize,
        malformed_configs: &'a [String],
        /// Present-but-skipped config paths + reason — surfacing this avoids
        /// hiding a misconfigured `.mcp.json` behind an "empty lockfile".
        rejected_configs: &'a [mcp_lock::RejectedConfig],
        servers_locked: usize,
        incomplete_override_used: bool,
        lockfile: &'a McpLockfile,
    }

    let out = JsonOut {
        schema_version: 1,
        repo_root: repo_root.display().to_string(),
        lock_path: lock_path.display().to_string(),
        configs_found: inventory.configs.len(),
        malformed_configs: &inventory.malformed_configs,
        rejected_configs: &inventory.rejected_configs,
        servers_locked: lockfile.servers.len(),
        incomplete_override_used,
        lockfile,
    };

    super::write_json_stdout(&out, "tirith mcp lock: failed to write JSON output")
}

/// Render the human-readable summary. Summary → stderr; the written path →
/// stdout so it can be captured.
fn print_human(lock_path: &Path, inventory: &McpInventory) {
    if inventory.is_empty() {
        // Not an error — an empty lockfile is still written as a baseline.
        eprintln!("tirith mcp lock: no MCP configuration files found in this repository.");
        eprintln!(
            "  Looked for .mcp.json / mcp.json / mcp_settings.json and the IDE variants \
             (.vscode/, .cursor/, .windsurf/, .cline/, .amazonq/, .continue/, .kiro/)."
        );
        eprintln!("  Wrote an empty lockfile so `tirith mcp verify` has a baseline.");

        // PR #121 item 16 — `rejected_configs` does NOT count toward emptiness,
        // so surface it here or a present-but-blocked config goes unsignalled.
        if !inventory.rejected_configs.is_empty() {
            eprintln!();
            eprintln!(
                "  note: {} config path(s) were skipped during discovery and contributed no \
                 servers — review these in case a legitimately-present config was \
                 unintentionally blocked:",
                inventory.rejected_configs.len(),
            );
            for line in format_rejected_config_lines(&inventory.rejected_configs) {
                eprintln!("{line}");
            }
        }

        println!("{}", lock_path.display());
        return;
    }

    let server_count = inventory.servers.len();
    eprintln!(
        "tirith mcp lock: captured {} MCP server(s) from {} config file(s).",
        server_count,
        inventory.configs.len(),
    );

    eprintln!();
    eprintln!("  configs:");
    for cfg in &inventory.configs {
        let suffix = if inventory.malformed_configs.contains(cfg) {
            "  (unparseable — contributed no servers)"
        } else {
            ""
        };
        eprintln!("    - {cfg}{suffix}");
    }

    if server_count == 0 {
        eprintln!();
        eprintln!("  the discovered config(s) declared no MCP servers.");
    } else {
        eprintln!();
        eprintln!("  servers:");
        for server in &inventory.servers {
            eprintln!("{}", format_inventory_server_line(server));
        }
    }

    if !inventory.malformed_configs.is_empty() {
        eprintln!();
        eprintln!(
            "  warning: {} config file(s) could not be parsed and contributed no servers \
             (listed above). This baseline is incomplete and verification will remain \
             nonzero until they are fixed.",
            inventory.malformed_configs.len(),
        );
    }

    if !inventory.rejected_configs.is_empty() {
        eprintln!();
        eprintln!(
            "  warning: {} config path(s) were refused and contributed no servers. This \
             baseline is incomplete and verification will remain nonzero until they are fixed:",
            inventory.rejected_configs.len(),
        );
        for line in format_rejected_config_lines(&inventory.rejected_configs) {
            eprintln!("{line}");
        }
    }

    eprintln!();
    eprintln!("  wrote {}", lock_path.display());
    println!("{}", lock_path.display());
}

/// Render each [`mcp_lock::RejectedConfig`] as a human-summary line for `mcp
/// lock`'s `note:` block.
///
/// The `path` is debug-escaped (`{:?}`): treat it as potentially
/// attacker-shaped so a control byte (`\x1b`/`\r`/`\n`) can't rewrite the
/// operator's terminal — same convention as `escape_name`/`describe_transport`.
/// The JSON surface doesn't need this (serde_json escapes C0 bytes natively);
/// this is the human-stderr render only.
fn format_rejected_config_lines(rejected: &[mcp_lock::RejectedConfig]) -> Vec<String> {
    rejected
        .iter()
        .map(|r| {
            format!(
                "    - {:?} ({})",
                r.path,
                describe_rejection_reason(&r.reason),
            )
        })
        .collect()
}

fn inventory_has_coverage_gaps(inventory: &McpInventory) -> bool {
    !inventory.malformed_configs.is_empty() || !inventory.rejected_configs.is_empty()
}

fn print_coverage_inventory(inventory: &McpInventory) {
    if !inventory.malformed_configs.is_empty() {
        eprintln!("  malformed configs:");
        for path in &inventory.malformed_configs {
            eprintln!("    - {path:?}");
        }
    }
    if !inventory.rejected_configs.is_empty() {
        eprintln!("  rejected configs:");
        for line in format_rejected_config_lines(&inventory.rejected_configs) {
            eprintln!("{line}");
        }
    }
}

/// Render one inventory server entry under the `servers:` block of `mcp lock`'s
/// human summary. Both `name` and `source_config` are debug-escaped — they come
/// from a repo `.mcp.json` and are attacker-controllable (PR #121 item 17).
fn format_inventory_server_line(server: &mcp_lock::McpServerEntry) -> String {
    let transport = describe_transport(&server.transport);
    // Branch on `tools_declared` to distinguish three states (a real policy
    // ambiguity the lockfile resolves): omitted (runtime exposes any tool) vs
    // `"tools": []` (explicit zero-tool allowlist) vs N declared tools.
    let tools = if !server.tools_declared {
        "tools omitted — server may expose runtime tools".to_string()
    } else if server.tools.is_empty() {
        "no tools declared (explicit empty)".to_string()
    } else {
        format!("{} tool(s)", server.tools.len())
    };
    format!(
        "    - {} [{}] — {} — from {:?}",
        escape_name(&server.name),
        transport,
        tools,
        server.source_config,
    )
}

/// One-line human description of a [`mcp_lock::RejectedReason`] (used only by
/// [`print_human`]). Names the failure category without echoing arbitrary bytes.
fn describe_rejection_reason(reason: &mcp_lock::RejectedReason) -> String {
    match reason {
        mcp_lock::RejectedReason::Symlink => {
            "symlinked — discovery is repo-local, so the path is not followed".to_string()
        }
        mcp_lock::RejectedReason::NotRegularFile => {
            "not a regular file — only regular files are inventoried".to_string()
        }
        mcp_lock::RejectedReason::OutsideRepo => {
            "canonical path is outside the repository — discovery is repo-local".to_string()
        }
        mcp_lock::RejectedReason::Oversize { size_bytes } => {
            format!(
                "file too large ({size_bytes} bytes; cap is {} bytes) — refusing to read \
                 an unbounded JSON document",
                mcp_lock::MCP_CONFIG_MAX_SIZE,
            )
        }
        mcp_lock::RejectedReason::Unreadable { permission_denied } => {
            if *permission_denied {
                "could not read (permission denied)".to_string()
            } else {
                "could not read (other io error)".to_string()
            }
        }
        mcp_lock::RejectedReason::AmbiguousServerObjects => {
            "declares both mcpServers and servers — client precedence is ambiguous".to_string()
        }
        mcp_lock::RejectedReason::AmbiguousTransport => {
            "declares both url and command — client transport is ambiguous".to_string()
        }
        mcp_lock::RejectedReason::SecretBearingArgument => {
            "stdio arguments contain a credential-shaped value; use an environment reference"
                .to_string()
        }
        mcp_lock::RejectedReason::SecretBearingUrl => {
            "URL query/fragment contains a credential-shaped value; use a secret reference"
                .to_string()
        }
        mcp_lock::RejectedReason::InvalidServerEntry => {
            "contains a non-object server declaration that cannot be inventoried safely".to_string()
        }
        mcp_lock::RejectedReason::DuplicateJsonKey => {
            "contains a duplicate JSON object key with ambiguous consumer semantics".to_string()
        }
        mcp_lock::RejectedReason::InvalidServerField => {
            "contains a recognized MCP field with an invalid type or value".to_string()
        }
        mcp_lock::RejectedReason::UnsupportedServerField => {
            "contains an MCP launch field Tirith cannot reproduce exactly".to_string()
        }
    }
}

/// One-line description of a transport for the human summary.
///
/// Every attacker-controllable field (URL, command, args, env names — all from
/// a repo `.mcp.json`) is debug-escaped so control bytes (ANSI/CR/BEL) can't
/// rewrite the operator's terminal. Env values are never stored, committed, or
/// printed (the lockfile carries only a fixed presence marker); a URL's userinfo
/// is already stripped at parse time — a `(credentials in source URL)` annotation
/// shows the redaction fired without revealing the credential.
fn describe_transport(transport: &mcp_lock::McpTransport) -> String {
    match transport {
        mcp_lock::McpTransport::Url { url, userinfo_hash } => {
            // `url` is already userinfo-stripped; annotate (never echo) the
            // credential when one was declared.
            if userinfo_hash.is_some() {
                format!("url {} (credentials in source URL)", escape_name(url))
            } else {
                format!("url {}", escape_name(url))
            }
        }
        mcp_lock::McpTransport::Stdio { command, args, env } => {
            let mut desc = if args.is_empty() {
                format!("stdio {}", escape_name(command))
            } else {
                let escaped_args: Vec<String> = args.iter().map(|a| escape_name(a)).collect();
                format!("stdio {} {}", escape_name(command), escaped_args.join(" "))
            };
            if !env.is_empty() {
                let names: Vec<String> = env.iter().map(|e| format!("{:?}", e.name)).collect();
                desc.push_str(&format!(" (env: {})", names.join(", ")));
            }
            desc
        }
        mcp_lock::McpTransport::Unknown => "no transport declared".to_string(),
    }
}

/// Report an operational error, in the requested output format.
fn report_error(json: bool, message: &str) {
    report_error_for(json, "tirith mcp lock", message);
}

/// Print an error message in the requested output format, prefixed with the
/// command's name. Used by `lock` / `verify` / `diff` so each command's error
/// surface is honestly labelled.
fn report_error_for(json: bool, command: &str, message: &str) {
    if json {
        #[derive(serde::Serialize)]
        struct ErrOut<'a> {
            schema_version: u32,
            error: &'a str,
        }
        // Best-effort error envelope; the exit code is the source of truth.
        let ctx = format!("{command}: failed to write JSON output");
        let _ = super::write_json_stdout(
            &ErrOut {
                schema_version: 1,
                error: message,
            },
            &ctx,
        );
    } else {
        eprintln!("{command}: {message}");
    }
}

// `tirith mcp verify` — gating drift check

/// Run `tirith mcp verify`. Loads `.tirith/mcp.lock`, rebuilds the inventory,
/// computes drift, and reports it.
///
/// Exit codes (the CI contract): `0` no drift; `1` drift detected (output names
/// the affected servers); `2` usage error (no/unreadable lockfile or no repo
/// root) — distinct from drift so CI can tell "stale" from "nothing to verify".
pub fn verify(json: bool) -> i32 {
    let repo_root = match resolve_repo_root() {
        Some(r) => r,
        None => {
            report_error_for(
                json,
                "tirith mcp verify",
                "could not determine the repository root — run `tirith mcp verify` inside a \
                 git repository, or from a directory whose ancestor has one",
            );
            return 2;
        }
    };
    verify_for_root(&repo_root, json)
}

/// Verify against an explicit repo root. Split out so tests can drive a verify
/// against a tempdir without mutating process-wide environment variables.
pub(crate) fn verify_for_root(repo_root: &Path, json: bool) -> i32 {
    let lock_path = repo_root.join(".tirith").join(MCP_LOCK_FILENAME);
    let lockfile = match mcp_lock::load_lockfile(&lock_path) {
        Ok(l) => l,
        Err(McpLockLoadError::NotFound) => {
            report_error_for(
                json,
                "tirith mcp verify",
                &format!(
                    "no lockfile at {} — run `tirith mcp lock` first to capture a baseline",
                    lock_path.display()
                ),
            );
            return 2;
        }
        Err(e) => {
            report_error_for(
                json,
                "tirith mcp verify",
                &format!("{}: {e}", lock_path.display()),
            );
            return 2;
        }
    };

    let inventory = mcp_lock::build_inventory(repo_root);
    let drifts = mcp_lock::compute_drift(&inventory, &lockfile);
    let coverage_ok = coverage_in_sync(&inventory, &lockfile);

    if json {
        let write_ok = print_drift_json(
            "tirith mcp verify",
            repo_root,
            &lock_path,
            &lockfile,
            &inventory,
            &drifts,
        );
        return verify_exit_code(drifts.is_empty() && coverage_ok, write_ok);
    }
    print_verify_human(&lock_path, &lockfile, &inventory, &drifts);
    verify_exit_code(drifts.is_empty() && coverage_ok, true)
}

/// Decide `tirith mcp verify`'s exit code from `(in_sync, json_write_ok)`. Pure
/// so the F2 contract is unit-testable without a broken stdout pipe.
///
/// F2 contract: a JSON-write failure must NOT collapse "drift, exit 1" into
/// "usage error, exit 2". So: no-drift+ok → 0; no-drift+write-fail → 2 (the only
/// signal is broken); drift → 1 regardless of write success (drift dominates;
/// the truncated-JSON warning is on stderr already).
pub(crate) fn verify_exit_code(in_sync: bool, json_write_ok: bool) -> i32 {
    match (in_sync, json_write_ok) {
        (true, true) => 0,
        (true, false) => 2,
        (false, _) => 1,
    }
}

/// Human-readable summary for `tirith mcp verify` (stderr, one line per drift).
/// Env values and URL userinfos never appear — only the name that changed.
fn print_verify_human(
    lock_path: &Path,
    lockfile: &McpLockfile,
    inventory: &McpInventory,
    drifts: &[McpDrift],
) {
    if drifts.is_empty() && coverage_in_sync(inventory, lockfile) {
        eprintln!(
            "tirith mcp verify: inventory matches {} (no drift).",
            lock_path.display()
        );
        return;
    }

    let (added, removed, changed) = drift_kind_counts(drifts);
    eprintln!(
        "tirith mcp verify: drift detected against {} ({} added, {} removed, {} changed).",
        lock_path.display(),
        added,
        removed,
        changed,
    );
    print_drift_body(drifts);
    print_coverage_drift(lockfile, inventory);
    eprintln!();
    eprintln!("  re-run `tirith mcp lock` to refresh the lockfile once the change is intentional.");
}

// `tirith mcp diff` — informational drift report

/// Run `tirith mcp diff`. Same drift data as `verify`, informational. Always
/// exits 0 (a usage error still exits 2 so a consumer can tell "no drift" from
/// "could not check").
pub fn diff(json: bool) -> i32 {
    let repo_root = match resolve_repo_root() {
        Some(r) => r,
        None => {
            report_error_for(
                json,
                "tirith mcp diff",
                "could not determine the repository root — run `tirith mcp diff` inside a \
                 git repository, or from a directory whose ancestor has one",
            );
            return 2;
        }
    };
    diff_for_root(&repo_root, json)
}

/// Diff against an explicit repo root. Split out so tests can drive a diff
/// against a tempdir without mutating process-wide environment variables.
pub(crate) fn diff_for_root(repo_root: &Path, json: bool) -> i32 {
    let lock_path = repo_root.join(".tirith").join(MCP_LOCK_FILENAME);
    let lockfile = match mcp_lock::load_lockfile(&lock_path) {
        Ok(l) => l,
        Err(McpLockLoadError::NotFound) => {
            report_error_for(
                json,
                "tirith mcp diff",
                &format!(
                    "no lockfile at {} — run `tirith mcp lock` first to capture a baseline",
                    lock_path.display()
                ),
            );
            return 2;
        }
        Err(e) => {
            report_error_for(
                json,
                "tirith mcp diff",
                &format!("{}: {e}", lock_path.display()),
            );
            return 2;
        }
    };

    let inventory = mcp_lock::build_inventory(repo_root);
    let drifts = mcp_lock::compute_drift(&inventory, &lockfile);

    if json {
        if !print_drift_json(
            "tirith mcp diff",
            repo_root,
            &lock_path,
            &lockfile,
            &inventory,
            &drifts,
        ) {
            return 2;
        }
    } else {
        print_diff_human(&lock_path, &lockfile, &inventory, &drifts);
    }

    0
}

/// Human-readable summary for `tirith mcp diff`.
fn print_diff_human(
    lock_path: &Path,
    lockfile: &McpLockfile,
    inventory: &McpInventory,
    drifts: &[McpDrift],
) {
    if drifts.is_empty() && coverage_in_sync(inventory, lockfile) {
        eprintln!(
            "tirith mcp diff: inventory matches {} (no drift).",
            lock_path.display()
        );
        return;
    }

    let (added, removed, changed) = drift_kind_counts(drifts);
    eprintln!(
        "tirith mcp diff: drift against {} ({} added, {} removed, {} changed).",
        lock_path.display(),
        added,
        removed,
        changed,
    );
    print_drift_body(drifts);
    print_coverage_drift(lockfile, inventory);
}

fn coverage_matches_baseline(inventory: &McpInventory, lockfile: &McpLockfile) -> bool {
    inventory.malformed_configs == lockfile.malformed_configs
        && inventory.rejected_configs == lockfile.rejected_configs
}

/// Verification requires both exact baseline coverage and a currently complete
/// inventory. An explicit incomplete lock records the gap for audit/diff, but it
/// never converts that gap into a trusted success.
fn coverage_in_sync(inventory: &McpInventory, lockfile: &McpLockfile) -> bool {
    !inventory_has_coverage_gaps(inventory) && coverage_matches_baseline(inventory, lockfile)
}

fn print_coverage_drift(lockfile: &McpLockfile, inventory: &McpInventory) {
    if inventory_has_coverage_gaps(inventory) {
        eprintln!("  ! current MCP coverage is incomplete:");
        print_coverage_inventory(inventory);
    }
    if !coverage_matches_baseline(inventory, lockfile) {
        eprintln!(
            "  ! coverage metadata changed since the lock was created \
             (baseline: {} malformed/{} rejected; current: {} malformed/{} rejected)",
            lockfile.malformed_configs.len(),
            lockfile.rejected_configs.len(),
            inventory.malformed_configs.len(),
            inventory.rejected_configs.len(),
        );
    }
}

// shared drift presentation helpers (used by verify and diff)

/// Count drifts by kind: `(added, removed, changed)`. A
/// [`McpDrift::SchemaUpgradeRequired`] entry is a migration prompt, not a
/// per-server drift, so it contributes to none of the three buckets.
fn drift_kind_counts(drifts: &[McpDrift]) -> (usize, usize, usize) {
    let mut added = 0usize;
    let mut removed = 0usize;
    let mut changed = 0usize;
    for d in drifts {
        match d {
            McpDrift::Added { .. } => added += 1,
            McpDrift::Removed { .. } => removed += 1,
            McpDrift::Changed(_) => changed += 1,
            McpDrift::SchemaUpgradeRequired { .. } => {}
        }
    }
    (added, removed, changed)
}

/// Render the per-drift body — used by both `verify` and `diff`. The block
/// is identical between the two; only the headline differs.
fn print_drift_body(drifts: &[McpDrift]) {
    for d in drifts {
        match d {
            McpDrift::Removed {
                name,
                source_config,
            } => {
                eprintln!(
                    "  - removed: {} (was in {})",
                    escape_name(name),
                    source_config
                );
            }
            McpDrift::Added {
                name,
                source_config,
                ..
            } => {
                eprintln!("  + added: {} (from {})", escape_name(name), source_config);
            }
            McpDrift::Changed(entry) => {
                eprintln!(
                    "  ~ changed: {} (in {})",
                    escape_name(&entry.name),
                    entry.source_config
                );
                describe_changed_entry(entry);
            }
            McpDrift::SchemaUpgradeRequired {
                from_version,
                to_version,
            } => {
                eprintln!(
                    "  ! schema upgrade required: lockfile is at schema v{from_version}; re-lock \
                     with `tirith mcp lock` to migrate to v{to_version} and adopt the \
                     current lockfile privacy and drift semantics. Real drift, if any, is \
                     reported separately below."
                );
            }
        }
    }
}

/// Print the per-field detail of a `Changed` drift entry. Every printed name is
/// debug-escaped (`{:?}`) so a hostile server/env/tool name cannot inject
/// terminal control sequences — same treatment as `describe_transport`.
fn describe_changed_entry(entry: &McpServerDriftEntry) {
    for change in &entry.transport_changes {
        match change {
            McpTransportChange::KindChanged { previous, current } => {
                eprintln!("      - transport kind: {previous} → {current}");
            }
            McpTransportChange::UrlChanged => {
                // Both sides are userinfo-stripped; report the structural fact
                // only (the redacted bytes live in the lockfile).
                eprintln!("      - URL changed (redacted form recorded in mcp.lock)");
            }
            McpTransportChange::UserinfoAdded => {
                eprintln!("      - URL userinfo added (credential present in source URL)");
            }
            McpTransportChange::UserinfoRemoved => {
                eprintln!("      - URL userinfo removed");
            }
            McpTransportChange::UserinfoSwapped => {
                eprintln!(
                    "      - legacy URL-userinfo value-change signal (v8 no longer emits this)"
                );
            }
            McpTransportChange::CommandChanged => {
                eprintln!("      - stdio command changed");
            }
            McpTransportChange::ArgsChanged => {
                eprintln!("      - stdio args changed");
            }
            McpTransportChange::EnvChanged => {
                // Per-variable detail is printed below in `env_changes`.
            }
        }
    }

    for env in &entry.env_changes {
        match env {
            McpEnvChange::Added { name } => {
                eprintln!("      - env added: {}", escape_name(name));
            }
            McpEnvChange::Removed { name } => {
                eprintln!("      - env removed: {}", escape_name(name));
            }
            McpEnvChange::ValueHashChanged { name } => {
                eprintln!(
                    "      - legacy env-value change signal: {} (v8 no longer emits this)",
                    escape_name(name)
                );
            }
        }
    }

    if let Some(kind) = &entry.tools_change {
        let label = match kind {
            McpToolsChangeKind::Added => "added",
            McpToolsChangeKind::Removed => "removed",
            McpToolsChangeKind::Set => "changed (added + removed)",
            McpToolsChangeKind::Reordered => "reordered",
        };
        eprintln!("      - tools: {label}");
        for tool in &entry.tools_added {
            eprintln!("          + {}", escape_name(tool));
        }
        for tool in &entry.tools_removed {
            eprintln!("          - {}", escape_name(tool));
        }
    }
}

/// Debug-format a name so control bytes in a server/env/tool name render as
/// `\u{1b}` / `\n` / … and can't inject terminal control sequences.
fn escape_name(name: &str) -> String {
    format!("{name:?}")
}

/// Shared JSON output for `verify` / `diff` — identical envelope (only the exit
/// code distinguishes them). Returns `false` on a write failure.
fn print_drift_json(
    command: &str,
    repo_root: &Path,
    lock_path: &Path,
    lockfile: &McpLockfile,
    inventory: &McpInventory,
    drifts: &[McpDrift],
) -> bool {
    let (added, removed, changed) = drift_kind_counts(drifts);

    #[derive(serde::Serialize)]
    struct JsonOut<'a> {
        /// Result-envelope schema version (independent of the lockfile's own).
        schema_version: u32,
        repo_root: String,
        lock_path: String,
        /// `lock` / `verify` / `diff` — which command produced the document.
        command: &'a str,
        /// The lockfile's recorded `format_version`.
        lockfile_format_version: u32,
        drift_count: usize,
        added_count: usize,
        removed_count: usize,
        changed_count: usize,
        coverage_complete: bool,
        coverage_matches_baseline: bool,
        malformed_configs: &'a [String],
        rejected_configs: &'a [mcp_lock::RejectedConfig],
        in_sync: bool,
        drifts: &'a [McpDrift],
    }

    let out = JsonOut {
        schema_version: 1,
        repo_root: repo_root.display().to_string(),
        lock_path: lock_path.display().to_string(),
        command,
        lockfile_format_version: lockfile.format_version,
        drift_count: drifts.len(),
        added_count: added,
        removed_count: removed,
        changed_count: changed,
        coverage_complete: !inventory_has_coverage_gaps(inventory),
        coverage_matches_baseline: coverage_matches_baseline(inventory, lockfile),
        malformed_configs: &inventory.malformed_configs,
        rejected_configs: &inventory.rejected_configs,
        in_sync: drifts.is_empty() && coverage_in_sync(inventory, lockfile),
        drifts,
    };

    let ctx = format!("{command}: failed to write JSON output");
    super::write_json_stdout(&out, &ctx)
}

// `tirith mcp policy init` — scaffold a starter MCP policy

/// Run `tirith mcp policy init`. Reads `.tirith/mcp.lock` and writes
/// `.tirith/mcp-policy.yaml.example`: a (commented-out) scaffold of
/// `scan.trusted_mcp_servers` / `scan.mcp_allowed_tools` for every locked
/// server, which the operator merges into `policy.yaml` themselves. A separate
/// `.example` file lets the operator diff before integrating.
///
/// Deterministic (the lockfile is sorted by `(name, source_config)`).
/// `--format json` emits the same scaffold as a preview plus the file paths.
///
/// Exit codes: `0` written (incl. the no-lockfile case — a header-only example
/// is still written); `1` unparseable lockfile / no repo root / write failure;
/// `2` reserved usage error.
pub fn policy_init(json: bool, force: bool) -> i32 {
    let repo_root = match resolve_repo_root() {
        Some(r) => r,
        None => {
            report_error_for(
                json,
                "tirith mcp policy init",
                "could not determine the repository root — run `tirith mcp policy init` inside a \
                 git repository, or from a directory whose ancestor has one",
            );
            return 1;
        }
    };
    policy_init_for_root(&repo_root, json, force)
}

/// `policy init` against an explicit repo root. Split out so tests can drive
/// the command against a tempdir without mutating process-wide env vars.
pub(crate) fn policy_init_for_root(repo_root: &Path, json: bool, force: bool) -> i32 {
    let lock_path = repo_root.join(".tirith").join(MCP_LOCK_FILENAME);
    let example_path = repo_root.join(".tirith").join("mcp-policy.yaml.example");

    // Refuse to overwrite an existing example without --force (the operator may
    // have edited it), mirroring `tirith policy init`.
    if example_path.exists() && !force {
        report_error_for(
            json,
            "tirith mcp policy init",
            &format!(
                "{} already exists (use --force to overwrite)",
                example_path.display()
            ),
        );
        return 1;
    }

    // A missing lockfile is NOT fatal (header-only example still written); an
    // unparseable one IS, because we cannot tell what to list.
    let lockfile_opt: Option<McpLockfile> = match mcp_lock::load_lockfile(&lock_path) {
        Ok(l) => Some(l),
        Err(McpLockLoadError::NotFound) => None,
        Err(e) => {
            report_error_for(
                json,
                "tirith mcp policy init",
                &format!(
                    "{}: {e}. Run `tirith mcp lock` to refresh the lockfile before generating \
                     a policy scaffold from it.",
                    lock_path.display()
                ),
            );
            return 1;
        }
    };

    // Both forms (human YAML, JSON preview) derive from this same shape.
    let scaffold = build_policy_scaffold(lockfile_opt.as_ref());

    if let Some(parent) = example_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            report_error_for(
                json,
                "tirith mcp policy init",
                &format!("failed to create {}: {e}", parent.display()),
            );
            return 1;
        }
    }

    let yaml_body = render_policy_scaffold_yaml(&scaffold);
    // repo-0395: the scaffold lives under the repo's `.tirith/`, which a
    // malicious checkout can make a symlink. Write through the contained,
    // no-follow atomic helper so the write can never land outside the repo.
    //
    // C12: and through the gated permit, because it is a file Tirith owns under
    // `.tirith/`. It is a scaffold the operator copies, not the live policy, so
    // it is not flagged as a policy change.
    let repo_root = example_path
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."));
    let operator_policy = policy::Policy::discover_local_only(repo_root.to_str());
    if let Err(e) = super::write_config_file_permitted(
        repo_root,
        &example_path,
        yaml_body.as_bytes(),
        true,
        &operator_policy,
        false,
    ) {
        report_error_for(
            json,
            "tirith mcp policy init",
            &format!("failed to write {}: {e}", example_path.display()),
        );
        return 1;
    }

    if json {
        if !print_policy_init_json(repo_root, &lock_path, &example_path, &scaffold) {
            return 1;
        }
    } else {
        print_policy_init_human(&lock_path, &example_path, &scaffold);
    }

    0
}

/// The structured scaffold the human and JSON forms share.
#[derive(Debug, Clone, serde::Serialize)]
struct PolicyScaffold {
    /// `true` when a lockfile was found — distinguishes "empty by construction"
    /// from "every server got dropped".
    lockfile_present: bool,
    /// Servers in the lockfile's `(name, source_config)` canonical order.
    servers: Vec<PolicyScaffoldServer>,
}

/// One server entry in the policy scaffold.
#[derive(Debug, Clone, serde::Serialize)]
struct PolicyScaffoldServer {
    identity: String,
    name: String,
    source_config: String,
    tools: Vec<String>,
    live_descriptors_approved: bool,
}

/// Build the policy scaffold from a (possibly absent) lockfile. A missing
/// lockfile yields an empty `servers` list with `lockfile_present: false` (the
/// structure is still emitted). The same name can appear twice (different
/// configs); `render_policy_scaffold_yaml` dedups the trusted-servers list.
fn build_policy_scaffold(lockfile: Option<&McpLockfile>) -> PolicyScaffold {
    match lockfile {
        Some(lock) => PolicyScaffold {
            lockfile_present: true,
            servers: lock
                .servers
                .iter()
                .map(|s| {
                    let mut tools = s.tools.clone();
                    if s.descriptors_approved {
                        tools.extend(
                            s.descriptors
                                .iter()
                                .map(|descriptor| descriptor.name.clone()),
                        );
                    }
                    tools.sort();
                    tools.dedup();
                    PolicyScaffoldServer {
                        identity: s.policy_identity(),
                        name: s.name.clone(),
                        source_config: s.source_config.clone(),
                        tools,
                        live_descriptors_approved: s.descriptors_approved,
                    }
                })
                .collect(),
        },
        None => PolicyScaffold {
            lockfile_present: false,
            servers: Vec::new(),
        },
    }
}

/// Render the scaffold to its YAML on-disk form. Every entry is commented out
/// with `#` so importing the example doesn't silently widen the trust set (the
/// operator opts in, matching `tirith policy init`). Deterministic; always emits
/// a trailing newline.
fn render_policy_scaffold_yaml(scaffold: &PolicyScaffold) -> String {
    let mut s = String::new();
    s.push_str("# Tirith MCP policy scaffold (example)\n");
    s.push_str("# Generated by `tirith mcp policy init` from .tirith/mcp.lock.\n");
    s.push_str("#\n");
    s.push_str("# This is an EXAMPLE — every entry below is commented out. Copy the\n");
    s.push_str("# entries you want into `.tirith/policy.yaml` (merging under any\n");
    s.push_str("# existing `scan:` block) and uncomment them. Re-run\n");
    s.push_str("# `tirith mcp policy init --force` after refreshing the lockfile to\n");
    s.push_str("# regenerate this file from the current inventory.\n");
    s.push_str("#\n");
    s.push_str("# Documentation: https://tirith.dev/docs/policy#mcp\n");
    s.push('\n');

    if !scaffold.lockfile_present {
        s.push_str("# No `.tirith/mcp.lock` was found — run `tirith mcp lock` first to\n");
        s.push_str("# capture the inventory, then re-run this command to populate the\n");
        s.push_str("# scaffold below.\n");
        s.push('\n');
    }

    if scaffold.servers.is_empty() {
        s.push_str("# The lockfile recorded no MCP servers, so there is nothing to\n");
        s.push_str("# scaffold yet. The structure is shown below as a template:\n");
        s.push_str("#\n");
        s.push_str("# scan:\n");
        s.push_str("#   trusted_mcp_servers:\n");
        s.push_str("#     - example-server\n");
        s.push_str("#   mcp_allowed_tools:\n");
        s.push_str("#     example-server:\n");
        s.push_str("#       - tool_a\n");
        s.push_str("#       - tool_b\n");
        return s;
    }

    s.push_str("scan:\n");

    // Trust keys bind source + name + transport. A same-named declaration in a
    // different file therefore receives a distinct key and cannot inherit an
    // earlier review.
    s.push_str(
        "  # Source-qualified server identities that are trusted: every per-server MCP config\n",
    );
    s.push_str("  # finding (insecure URL, raw IP, suspicious args, wildcard tools,\n");
    s.push_str("  # duplicate name) is suppressed for these, and drift on them does\n");
    s.push_str("  # NOT raise the `mcp_server_drift` finding. Uncomment the identities\n");
    s.push_str("  # whose exact source/name/transport surface you reviewed and accepted.\n");
    s.push_str("  # trusted_mcp_servers:\n");
    for server in &scaffold.servers {
        s.push_str(&format!(
            "  #   - {}    # {:?} from {}\n",
            yaml_safe_scalar(&server.identity),
            server.name,
            yaml_safe_inline_comment(&server.source_config),
        ));
    }

    // `mcp_allowed_tools`: one allow-list per exact identity. Never union tools
    // across attacker-controlled same-name declarations.
    s.push('\n');
    s.push_str("  # Per-server allowed tools. Keys are exact MCP policy identities; the\n");
    s.push_str("  # values are the tools the server may expose. A tool the lockfile\n");
    s.push_str("  # records that is NOT in this set surfaces a finding (`mcp_server_drift`,\n");
    s.push_str("  # severity High). Drift that adds a tool outside the set upgrades\n");
    s.push_str("  # the drift finding from Medium to High. A server not listed here\n");
    s.push_str("  # is unconstrained — the gate is opt-in.\n");
    s.push_str("  # mcp_allowed_tools:\n");

    for server in &scaffold.servers {
        if server.tools.is_empty() {
            s.push_str(&format!(
                "  #   {}: []    # {:?} from {} — {}\n",
                yaml_safe_scalar(&server.identity),
                server.name,
                yaml_safe_inline_comment(&server.source_config),
                if server.live_descriptors_approved {
                    "approved live set is empty"
                } else {
                    "no static tools; live descriptors not approved"
                },
            ));
        } else {
            s.push_str(&format!(
                "  #   {}:    # {:?} from {} — {}\n",
                yaml_safe_scalar(&server.identity),
                server.name,
                yaml_safe_inline_comment(&server.source_config),
                if server.live_descriptors_approved {
                    "deduped static + approved live tools"
                } else {
                    "static declarations only; live descriptors not approved"
                },
            ));
            for tool in &server.tools {
                s.push_str(&format!("  #     - {}\n", yaml_safe_scalar(tool)));
            }
        }
    }

    s
}

// YAML safety helpers are centralized in `crate::cli::yaml`; these aliases keep
// the original names so the round-trip tests below read naturally.
#[cfg(test)]
use crate::cli::yaml::YAML_NEEDS_QUOTING_BYTES;
use crate::cli::yaml::{
    safe_inline_comment as yaml_safe_inline_comment, safe_scalar as yaml_safe_scalar,
};

/// Human-readable summary for `tirith mcp policy init`.
fn print_policy_init_human(lock_path: &Path, example_path: &Path, scaffold: &PolicyScaffold) {
    if !scaffold.lockfile_present {
        eprintln!(
            "tirith mcp policy init: no lockfile at {} — wrote a header-only scaffold.",
            lock_path.display()
        );
        eprintln!(
            "  Run `tirith mcp lock` first to capture the MCP inventory, then re-run this command."
        );
    } else {
        let server_count = scaffold.servers.len();
        let total_tool_count: usize = scaffold.servers.iter().map(|s| s.tools.len()).sum();
        eprintln!(
            "tirith mcp policy init: scaffolded {} server(s) and {} tool(s) from {}.",
            server_count,
            total_tool_count,
            lock_path.display(),
        );
        eprintln!("  Every entry is commented out — uncomment the ones you wish to declare.");
    }
    eprintln!("  wrote {}", example_path.display());
    println!("{}", example_path.display());
}

/// JSON output for `tirith mcp policy init`.
fn print_policy_init_json(
    repo_root: &Path,
    lock_path: &Path,
    example_path: &Path,
    scaffold: &PolicyScaffold,
) -> bool {
    #[derive(serde::Serialize)]
    struct JsonOut<'a> {
        schema_version: u32,
        repo_root: String,
        lock_path: String,
        example_path: String,
        lockfile_present: bool,
        server_count: usize,
        tool_count: usize,
        scaffold: &'a PolicyScaffold,
    }

    let total_tool_count: usize = scaffold.servers.iter().map(|s| s.tools.len()).sum();
    let out = JsonOut {
        schema_version: 1,
        repo_root: repo_root.display().to_string(),
        lock_path: lock_path.display().to_string(),
        example_path: example_path.display().to_string(),
        lockfile_present: scaffold.lockfile_present,
        server_count: scaffold.servers.len(),
        tool_count: total_tool_count,
        scaffold,
    };

    super::write_json_stdout(&out, "tirith mcp policy init: failed to write JSON output")
}

// `tirith mcp explain` — print one server's lockfile entry

/// Run `tirith mcp explain <server>`. Finds the named server (case-sensitive
/// exact) and prints its tools, redacted transport, env-variable names (never
/// values — only hashes are stored), and inferred capabilities.
///
/// Exit codes: `0` found and printed; `1` missing/unreadable lockfile, server
/// not found, or JSON write failure; `2` reserved usage error.
pub fn explain(server: &str, json: bool) -> i32 {
    let repo_root = match resolve_repo_root() {
        Some(r) => r,
        None => {
            report_error_for(
                json,
                "tirith mcp explain",
                "could not determine the repository root — run `tirith mcp explain` inside a \
                 git repository, or from a directory whose ancestor has one",
            );
            return 1;
        }
    };

    let lock_path = repo_root.join(".tirith").join(MCP_LOCK_FILENAME);
    let lockfile = match mcp_lock::load_lockfile(&lock_path) {
        Ok(l) => l,
        Err(McpLockLoadError::NotFound) => {
            report_error_for(
                json,
                "tirith mcp explain",
                &format!(
                    "no lockfile at {} — run `tirith mcp lock` first to capture a baseline",
                    lock_path.display()
                ),
            );
            return 1;
        }
        Err(e) => {
            report_error_for(
                json,
                "tirith mcp explain",
                &format!("{}: {e}", lock_path.display()),
            );
            return 1;
        }
    };

    // Case-sensitive exact lookup — matches every other byte-equal site in the
    // lockfile schema.
    let entry = lockfile.servers.iter().find(|s| s.name == server);
    let Some(entry) = entry else {
        let suggestions = suggest_server_names(&lockfile.servers, server);
        let msg = if suggestions.is_empty() {
            format!("server {server:?} not found in {}", lock_path.display())
        } else {
            format!(
                "server {server:?} not found in {} (did you mean: {})",
                lock_path.display(),
                suggestions.join(", ")
            )
        };
        report_error_for(json, "tirith mcp explain", &msg);
        return 1;
    };

    if json {
        if !print_explain_json(&lock_path, entry) {
            return 1;
        }
    } else {
        print_explain_human(&lock_path, entry);
    }
    0
}

/// Suggest server names close to `query`: prefix matches first (alphabetical),
/// then Levenshtein-near names within distance 3. Bounded to four total.
fn suggest_server_names(servers: &[McpLockServer], query: &str) -> Vec<String> {
    let mut prefix: Vec<&str> = servers
        .iter()
        .filter(|s| s.name.starts_with(query))
        .map(|s| s.name.as_str())
        .collect();
    prefix.sort();
    prefix.truncate(4);

    if prefix.len() >= 2 {
        return prefix.into_iter().map(escape_name).collect();
    }

    // Edit-distance suggestions for the remaining slots.
    let mut distance: Vec<(usize, &str)> = servers
        .iter()
        .filter(|s| !prefix.contains(&s.name.as_str()))
        .map(|s| {
            (
                tirith_core::util::levenshtein(query, &s.name),
                s.name.as_str(),
            )
        })
        .filter(|(d, _)| *d <= 3)
        .collect();
    distance.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
    distance.truncate(4 - prefix.len());

    let mut out: Vec<String> = prefix.into_iter().map(escape_name).collect();
    out.extend(distance.into_iter().map(|(_, n)| escape_name(n)));
    out
}

/// Stable, env-only view of a server's transport for `tirith mcp explain` —
/// without re-exposing the underlying `McpTransport`'s value-carrying form.
#[derive(serde::Serialize)]
struct TransportView<'a> {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    userinfo_present: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    args: Option<&'a [String]>,
    /// Env-variable names only — the lockfile stores only value hashes.
    #[serde(skip_serializing_if = "Option::is_none")]
    env_names: Option<Vec<&'a str>>,
}

impl<'a> TransportView<'a> {
    fn from_transport(t: &'a McpTransport) -> Self {
        match t {
            McpTransport::Url { url, userinfo_hash } => Self {
                kind: "url",
                url: Some(url),
                userinfo_present: Some(userinfo_hash.is_some()),
                command: None,
                args: None,
                env_names: None,
            },
            McpTransport::Stdio { command, args, env } => Self {
                kind: "stdio",
                url: None,
                userinfo_present: None,
                command: Some(command),
                args: Some(args.as_slice()),
                env_names: Some(env.iter().map(|e| e.name.as_str()).collect()),
            },
            McpTransport::Unknown => Self {
                kind: "unknown",
                url: None,
                userinfo_present: None,
                command: None,
                args: None,
                env_names: None,
            },
        }
    }
}

fn print_explain_json(lock_path: &Path, entry: &McpLockServer) -> bool {
    #[derive(serde::Serialize)]
    struct Out<'a> {
        schema_version: u32,
        lock_path: String,
        name: &'a str,
        source_config: &'a str,
        content_hash: &'a str,
        transport: TransportView<'a>,
        tools_declared: bool,
        tools: &'a [String],
        capabilities: Vec<&'static str>,
    }
    let caps = derive_capabilities(entry);
    let out = Out {
        schema_version: 1,
        lock_path: lock_path.display().to_string(),
        name: &entry.name,
        source_config: &entry.source_config,
        content_hash: &entry.hash,
        transport: TransportView::from_transport(&entry.transport),
        tools_declared: entry.tools_declared,
        tools: entry.tools.as_slice(),
        capabilities: caps,
    };
    super::write_json_stdout(&out, "tirith mcp explain: failed to write JSON output")
}

fn print_explain_human(lock_path: &Path, entry: &McpLockServer) {
    eprintln!(
        "tirith mcp explain: {} (from {})",
        escape_name(&entry.name),
        lock_path.display(),
    );
    eprintln!();
    eprintln!("  source config: {:?}", entry.source_config);
    eprintln!("  content hash:  {}", entry.hash);
    eprintln!();
    eprintln!("  transport:");
    match &entry.transport {
        McpTransport::Url { url, userinfo_hash } => {
            eprintln!("    kind: url");
            eprintln!("    url:  {}", escape_name(url));
            if userinfo_hash.is_some() {
                eprintln!(
                    "    (credentials in source URL — presence recorded, value never committed)"
                );
            }
        }
        McpTransport::Stdio { command, args, env } => {
            eprintln!("    kind: stdio");
            eprintln!("    command: {}", escape_name(command));
            if !args.is_empty() {
                let arg_strs: Vec<String> = args.iter().map(|a| escape_name(a)).collect();
                eprintln!("    args:    {}", arg_strs.join(" "));
            }
            if env.is_empty() {
                eprintln!("    env:     (none declared)");
            } else {
                eprintln!("    env:     (names only — values are never committed)");
                for e in env {
                    eprintln!("      - {}", escape_name(&e.name));
                }
            }
        }
        McpTransport::Unknown => {
            eprintln!("    kind: unknown — the source config declared neither url nor command");
        }
    }
    eprintln!();
    if !entry.tools_declared {
        eprintln!("  tools: (omitted in source — MCP clients treat this as \"all runtime tools\")");
    } else if entry.tools.is_empty() {
        eprintln!("  tools: (explicit empty — no tools allowed)");
    } else {
        eprintln!("  tools ({}):", entry.tools.len());
        for t in &entry.tools {
            eprintln!("    - {}", escape_name(t));
        }
    }
    eprintln!();
    let caps = derive_capabilities(entry);
    eprintln!("  capabilities (derived from the lockfile structure):");
    if caps.is_empty() {
        eprintln!("    (none inferred)");
    } else {
        for c in &caps {
            eprintln!("    - {c}");
        }
    }
}

// `tirith mcp permissions` — per-capability aggregation across all servers

/// Capability tags surfaced by `tirith mcp permissions`, derived from the
/// lockfile structure (the schema has no explicit per-server capability list).
/// Kept closed and small so the output can't drift from the data.
const CAP_NETWORK: &str = "network";
const CAP_PROCESS_SPAWN: &str = "process-spawn";
const CAP_ENV_SECRET: &str = "env-secret";
const CAP_GITHUB_API: &str = "github-api";
const CAP_OPENAI_API: &str = "openai-api";
const CAP_AWS: &str = "aws";
const CAP_RUNTIME_TOOL_WILDCARD: &str = "runtime-tool-wildcard";
const CAP_UNKNOWN_TRANSPORT: &str = "unknown-transport";

/// Derive the capability tag set for one locked server: ordered (stable) and
/// deduplicated, so two equal inputs produce a byte-identical tag list.
fn derive_capabilities(entry: &McpLockServer) -> Vec<&'static str> {
    let mut caps: Vec<&'static str> = Vec::new();
    let mut push = |c: &'static str| {
        if !caps.contains(&c) {
            caps.push(c);
        }
    };

    match &entry.transport {
        McpTransport::Url { .. } => push(CAP_NETWORK),
        McpTransport::Stdio { env, .. } => {
            push(CAP_PROCESS_SPAWN);
            for e in env {
                if env_name_is_secret_shaped(&e.name) {
                    push(CAP_ENV_SECRET);
                }
                if env_name_matches_github(&e.name) {
                    push(CAP_GITHUB_API);
                }
                if env_name_matches_openai(&e.name) {
                    push(CAP_OPENAI_API);
                }
                if env_name_matches_aws(&e.name) {
                    push(CAP_AWS);
                }
            }
        }
        McpTransport::Unknown => push(CAP_UNKNOWN_TRANSPORT),
    }

    if !entry.tools_declared {
        push(CAP_RUNTIME_TOOL_WILDCARD);
    }

    caps
}

/// `*_TOKEN` / `*_KEY` / `*_SECRET` / `*_PASSWORD` heuristic (ASCII
/// case-insensitive) — broad, over-matches, but catches the common case.
fn env_name_is_secret_shaped(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.ends_with("_TOKEN")
        || upper.ends_with("_KEY")
        || upper.ends_with("_SECRET")
        || upper.ends_with("_PASSWORD")
        || upper.ends_with("_API_KEY")
        || upper == "TOKEN"
        || upper == "API_KEY"
}

fn env_name_matches_github(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with("GITHUB_") || upper == "GH_TOKEN" || upper == "GHE_TOKEN"
}

fn env_name_matches_openai(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with("OPENAI_")
}

fn env_name_matches_aws(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with("AWS_")
}

/// Run `tirith mcp permissions`. Aggregates a per-capability view across every
/// locked server (grouped by network / stdio-process / env-secret / github-api
/// / …). `wildcards:` lists servers whose `tools` key was omitted (an MCP client
/// treats that as "any runtime tool").
///
/// Exit codes: `0` printed; `1` missing/unreadable lockfile or JSON write
/// failure; `2` reserved usage error.
pub fn permissions(json: bool) -> i32 {
    let repo_root = match resolve_repo_root() {
        Some(r) => r,
        None => {
            report_error_for(
                json,
                "tirith mcp permissions",
                "could not determine the repository root — run `tirith mcp permissions` inside \
                 a git repository, or from a directory whose ancestor has one",
            );
            return 1;
        }
    };

    let lock_path = repo_root.join(".tirith").join(MCP_LOCK_FILENAME);
    let lockfile = match mcp_lock::load_lockfile(&lock_path) {
        Ok(l) => l,
        Err(McpLockLoadError::NotFound) => {
            report_error_for(
                json,
                "tirith mcp permissions",
                &format!(
                    "no lockfile at {} — run `tirith mcp lock` first to capture a baseline",
                    lock_path.display()
                ),
            );
            return 1;
        }
        Err(e) => {
            report_error_for(
                json,
                "tirith mcp permissions",
                &format!("{}: {e}", lock_path.display()),
            );
            return 1;
        }
    };

    let aggregation = aggregate_permissions(&lockfile.servers);

    if json {
        let ok = print_permissions_json(&lock_path, &aggregation);
        if !ok {
            return 1;
        }
    } else {
        print_permissions_human(&lock_path, &aggregation);
    }
    0
}

/// One capability group: the tag and every server that declared it.
#[derive(Debug, Clone, serde::Serialize)]
struct PermissionGroup {
    capability: &'static str,
    /// Servers that declared it, sorted by name for deterministic output.
    servers: Vec<String>,
    /// Unbounded capability (`runtime-tool-wildcard` / `unknown-transport`) —
    /// surfaced in a separate `wildcards:` block.
    wildcard: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct PermissionsAggregation {
    server_count: usize,
    /// Capability groups, named first (alphabetical) then wildcards last.
    groups: Vec<PermissionGroup>,
}

fn aggregate_permissions(servers: &[McpLockServer]) -> PermissionsAggregation {
    use std::collections::BTreeMap;
    let mut by_cap: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for s in servers {
        for c in derive_capabilities(s) {
            by_cap.entry(c).or_default().push(s.name.clone());
        }
    }
    let groups: Vec<PermissionGroup> = by_cap
        .into_iter()
        .map(|(capability, mut names)| {
            names.sort();
            names.dedup();
            PermissionGroup {
                wildcard: capability_is_wildcard(capability),
                capability,
                servers: names,
            }
        })
        .collect();
    PermissionsAggregation {
        server_count: servers.len(),
        groups,
    }
}

fn capability_is_wildcard(cap: &str) -> bool {
    matches!(cap, "runtime-tool-wildcard" | "unknown-transport")
}

fn print_permissions_json(lock_path: &Path, agg: &PermissionsAggregation) -> bool {
    #[derive(serde::Serialize)]
    struct Out<'a> {
        schema_version: u32,
        lock_path: String,
        server_count: usize,
        capability_count: usize,
        groups: &'a [PermissionGroup],
    }
    let out = Out {
        schema_version: 1,
        lock_path: lock_path.display().to_string(),
        server_count: agg.server_count,
        capability_count: agg.groups.len(),
        groups: &agg.groups,
    };
    super::write_json_stdout(&out, "tirith mcp permissions: failed to write JSON output")
}

fn print_permissions_human(lock_path: &Path, agg: &PermissionsAggregation) {
    eprintln!(
        "tirith mcp permissions: {} server(s) in {}",
        agg.server_count,
        lock_path.display(),
    );
    if agg.groups.is_empty() {
        eprintln!();
        eprintln!(
            "  no capabilities inferred (the lockfile is empty or all servers have an \
unknown transport)."
        );
        return;
    }
    let (named, wildcards): (Vec<_>, Vec<_>) = agg.groups.iter().partition(|g| !g.wildcard);
    if !named.is_empty() {
        eprintln!();
        eprintln!("  capabilities:");
        for g in &named {
            eprintln!(
                "    - {} ({} server{})",
                g.capability,
                g.servers.len(),
                if g.servers.len() == 1 { "" } else { "s" },
            );
            for n in &g.servers {
                eprintln!("        - {}", escape_name(n));
            }
        }
    }
    if !wildcards.is_empty() {
        eprintln!();
        eprintln!("  wildcards / unbounded permissions:");
        for g in &wildcards {
            eprintln!(
                "    - {} ({} server{})",
                g.capability,
                g.servers.len(),
                if g.servers.len() == 1 { "" } else { "s" },
            );
            for n in &g.servers {
                eprintln!("        - {}", escape_name(n));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use tirith_core::mcp_lock::{McpEnvEntry, McpTransport};

    #[test]
    fn describe_transport_renders_each_variant() {
        // URL / command / args are debug-escaped, so the summary is the
        // Debug-quoted form (well-formed inputs round-trip with quotes).
        assert_eq!(
            describe_transport(&McpTransport::Url {
                url: "https://x.example".into(),
                userinfo_hash: None,
            }),
            r#"url "https://x.example""#
        );
        assert_eq!(
            describe_transport(&McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![],
            }),
            r#"stdio "node""#
        );
        assert_eq!(
            describe_transport(&McpTransport::Stdio {
                command: "npx".into(),
                args: vec!["-y".into(), "server".into()],
                env: vec![],
            }),
            r#"stdio "npx" "-y" "server""#
        );
        // A stdio server with env: variable names shown (debug-escaped); raw
        // values are never stored or printed.
        assert_eq!(
            describe_transport(&McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![
                    McpEnvEntry::from_raw("API_TOKEN", "secret"),
                    McpEnvEntry::from_raw("DEBUG", "1"),
                ],
            }),
            r#"stdio "node" (env: "API_TOKEN", "DEBUG")"#
        );
        assert_eq!(
            describe_transport(&McpTransport::Unknown),
            "no transport declared"
        );
    }

    #[test]
    fn describe_transport_annotates_url_with_userinfo() {
        // A redacted URL whose source declared credentials prints the
        // `(credentials in source URL)` annotation, never the credential.
        assert_eq!(
            describe_transport(&McpTransport::Url {
                url: "https://mcp.example.com/sse".into(),
                userinfo_hash: Some("deadbeef".into()),
            }),
            r#"url "https://mcp.example.com/sse" (credentials in source URL)"#
        );
        // The annotation MUST NOT contain the hash itself.
        let printed = describe_transport(&McpTransport::Url {
            url: "https://mcp.example.com/sse".into(),
            userinfo_hash: Some("supersecrethashvalue".into()),
        });
        assert!(
            !printed.contains("supersecrethashvalue"),
            "the userinfo_hash must not be printed to the operator: {printed}"
        );
        assert!(
            !printed.contains('@'),
            "the printed URL must contain no `@` (credentials would precede it): {printed}"
        );
    }

    #[test]
    fn describe_transport_escapes_control_bytes_in_env_names() {
        // A hostile env name with ANSI/newline/control bytes must NOT reach the
        // terminal raw — Debug formatting renders them as `\u{1b}`, `\n`, etc.
        let env = vec![
            McpEnvEntry::from_raw("\x1b[31mREDNAME", "ignored"),
            McpEnvEntry::from_raw("MULTI\nLINE", "ignored"),
            McpEnvEntry::from_raw("OVERWRITE\rATTACK", "ignored"),
            McpEnvEntry::from_raw("ERASE\x08", "ignored"),
        ];
        let out = describe_transport(&McpTransport::Stdio {
            command: "node".into(),
            args: vec![],
            env,
        });

        // No raw control byte may appear in the output.
        for ch in out.chars() {
            assert!(
                !ch.is_control(),
                "raw control char {:?} (U+{:04X}) leaked into the env-name summary: {out:?}",
                ch,
                ch as u32,
            );
        }
        // And the escaped forms ARE present.
        for needle in [r"\u{1b}", r"\n", r"\r", r"\u{8}"] {
            assert!(
                out.contains(needle),
                "expected escaped form {needle} in env-name summary: {out:?}"
            );
        }
    }

    #[test]
    fn describe_transport_escapes_control_bytes_in_transport_fields() {
        // URL/command/args all come from `.mcp.json` and must be debug-escaped
        // before reaching the terminal (CodeRabbit follow-up).
        let url_out = describe_transport(&McpTransport::Url {
            url: "https://evil\x1b[31m.example".into(),
            userinfo_hash: None,
        });
        for ch in url_out.chars() {
            assert!(
                !ch.is_control(),
                "raw control char {:?} (U+{:04X}) leaked into url transport line: {url_out:?}",
                ch,
                ch as u32,
            );
        }
        assert!(
            url_out.contains(r"\u{1b}"),
            "expected escaped ESC form in url transport line: {url_out:?}",
        );

        // Stdio command + args: CR in command, BEL/newline in args.
        let stdio_out = describe_transport(&McpTransport::Stdio {
            command: "evil\rcmd".into(),
            args: vec!["safe".into(), "bell\x07arg".into(), "multi\nline".into()],
            env: vec![],
        });
        for ch in stdio_out.chars() {
            assert!(
                !ch.is_control(),
                "raw control char {:?} (U+{:04X}) leaked into stdio transport line: {stdio_out:?}",
                ch,
                ch as u32,
            );
        }
        for needle in [r"\r", r"\u{7}", r"\n"] {
            assert!(
                stdio_out.contains(needle),
                "expected escaped form {needle} in stdio transport line: {stdio_out:?}",
            );
        }
    }

    #[test]
    fn format_rejected_config_lines_escapes_control_bytes_in_path() {
        // A hostile `RejectedConfig::path` with control bytes must NOT reach the
        // terminal raw when `mcp lock` renders the "rejected configs" note —
        // Debug-escaped like the env-name / server-name printers.
        let rejected = vec![
            mcp_lock::RejectedConfig {
                path: "\x1b[31mhostile-red.json".to_string(),
                reason: mcp_lock::RejectedReason::Symlink,
            },
            mcp_lock::RejectedConfig {
                path: "multi\nline.json".to_string(),
                reason: mcp_lock::RejectedReason::NotRegularFile,
            },
            mcp_lock::RejectedConfig {
                path: "overwrite\rattack.json".to_string(),
                reason: mcp_lock::RejectedReason::OutsideRepo,
            },
            mcp_lock::RejectedConfig {
                path: "erase\x08.json".to_string(),
                reason: mcp_lock::RejectedReason::Unreadable {
                    permission_denied: false,
                },
            },
        ];

        let lines = format_rejected_config_lines(&rejected);
        assert_eq!(
            lines.len(),
            rejected.len(),
            "every rejected entry must produce exactly one rendered line: \
             {lines:?}",
        );

        // No raw control byte may appear in any rendered line.
        for line in &lines {
            for ch in line.chars() {
                assert!(
                    !ch.is_control(),
                    "raw control char {:?} (U+{:04X}) leaked into a \
                     rejected-config line: {line:?}",
                    ch,
                    ch as u32,
                );
            }
        }

        // And the escaped forms ARE present.
        let joined = lines.join("\n");
        for needle in [r"\u{1b}", r"\n", r"\r", r"\u{8}"] {
            assert!(
                joined.contains(needle),
                "expected escaped form {needle} in rejected-config lines: \
                 {lines:?}"
            );
        }
    }

    /// The C12 task gate ships off, so these lockfile tests state that plainly
    /// rather than depending on whatever policy the host running them has.
    fn inert_policy() -> policy::Policy {
        policy::Policy::default()
    }

    #[test]
    fn write_lockfile_creates_tirith_dir_and_file() {
        let repo = tempdir().unwrap();
        let lock_path = repo.path().join(".tirith").join(MCP_LOCK_FILENAME);
        let inventory = mcp_lock::build_inventory(repo.path());
        let lockfile = McpLockfile::from_inventory(&inventory);

        write_lockfile(&lock_path, &lockfile, &inert_policy()).expect("write should succeed");
        assert!(lock_path.is_file(), ".tirith/mcp.lock must exist");

        let contents = fs::read_to_string(&lock_path).unwrap();
        let parsed: McpLockfile = serde_json::from_str(&contents).unwrap();
        assert_eq!(parsed, lockfile);
    }

    #[test]
    fn write_lockfile_is_idempotent() {
        let repo = tempdir().unwrap();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "s": { "command": "node" } } }"#,
        )
        .unwrap();
        let lock_path = repo.path().join(".tirith").join(MCP_LOCK_FILENAME);
        let inventory = mcp_lock::build_inventory(repo.path());
        let lockfile = McpLockfile::from_inventory(&inventory);

        write_lockfile(&lock_path, &lockfile, &inert_policy()).unwrap();
        let first = fs::read_to_string(&lock_path).unwrap();
        write_lockfile(&lock_path, &lockfile, &inert_policy()).unwrap();
        let second = fs::read_to_string(&lock_path).unwrap();
        assert_eq!(first, second, "re-writing an unchanged lockfile is stable");
    }

    #[test]
    fn write_lockfile_refuses_direct_secret_without_clobbering_existing_baseline() {
        let repo = tempdir().unwrap();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "s": { "command": "node", "args": ["server.js"] } } }"#,
        )
        .unwrap();
        let lock_path = repo.path().join(".tirith").join(MCP_LOCK_FILENAME);
        let inventory = mcp_lock::build_inventory(repo.path());
        let mut lockfile = McpLockfile::from_inventory(&inventory);
        write_lockfile(&lock_path, &lockfile, &inert_policy())
            .expect("write initial safe baseline");
        let before = fs::read(&lock_path).expect("read initial baseline");

        let probe = "ghp_DIRECT_WRITE_SECRET_NEVER_PERSIST_123456";
        lockfile.servers[0].transport = McpTransport::Stdio {
            command: "node".into(),
            args: vec![format!("--token={probe}")],
            env: vec![],
        };
        let error = write_lockfile(&lock_path, &lockfile, &inert_policy())
            .expect_err("unsafe direct transport must fail before publication");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(!error.to_string().contains(probe));
        assert_eq!(
            fs::read(&lock_path).expect("read preserved baseline"),
            before,
            "serialization refusal must preserve the previous trusted lock byte-for-byte"
        );
    }

    #[test]
    fn lock_for_root_preserves_unchanged_descriptor_approval() {
        let repo = tempdir().unwrap();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "s": { "command": "node", "args": ["server.js"] } } }"#,
        )
        .unwrap();
        let inventory = mcp_lock::build_inventory(repo.path());
        let identity = inventory.servers[0].policy_identity();
        let mut approved = McpLockfile::from_inventory(&inventory);
        mcp_lock::approve_live_descriptors(
            &mut approved,
            &inventory,
            &identity,
            "node",
            &["server.js".into()],
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &serde_json::json!({
                "tools": [{"name": "read", "inputSchema": {"type": "object"}}]
            }),
        )
        .unwrap();
        let lock_path = repo.path().join(".tirith").join(MCP_LOCK_FILENAME);
        write_lockfile(&lock_path, &approved, &inert_policy()).unwrap();

        assert_eq!(lock_for_root(repo.path(), false, false), 0);
        let refreshed = mcp_lock::load_lockfile(&lock_path).unwrap();
        assert!(refreshed.servers[0].descriptors_approved);
        assert_eq!(
            refreshed.servers[0].descriptors,
            approved.servers[0].descriptors
        );

        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "s": { "command": "node", "args": ["changed.js"] } } }"#,
        )
        .unwrap();
        assert_eq!(lock_for_root(repo.path(), false, false), 0);
        let changed = mcp_lock::load_lockfile(&lock_path).unwrap();
        assert!(!changed.servers[0].descriptors_approved);
        assert!(changed.servers[0].descriptors.is_empty());
    }

    // `tirith mcp verify` / `diff` integration tests drive the `*_for_root`
    // helpers against tempdirs so each is isolated from env-var-mutating
    // `resolve_repo_root`.

    /// Build a repo with one MCP config and a matching lockfile.
    fn repo_with_locked_mcp() -> tempfile::TempDir {
        let repo = tempdir().unwrap();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "s": { "command": "node" } } }"#,
        )
        .unwrap();
        let inventory = mcp_lock::build_inventory(repo.path());
        let lockfile = McpLockfile::from_inventory(&inventory);
        let lock_path = repo.path().join(".tirith").join(MCP_LOCK_FILENAME);
        write_lockfile(&lock_path, &lockfile, &inert_policy()).expect("write");
        repo
    }

    #[test]
    fn verify_exits_zero_when_inventory_matches_lockfile() {
        let repo = repo_with_locked_mcp();
        let code = verify_for_root(repo.path(), false);
        assert_eq!(code, 0, "no drift → exit 0");
    }

    #[test]
    fn verify_exits_one_when_server_added() {
        let repo = repo_with_locked_mcp();
        // Add a server — the inventory has now drifted.
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": {
                "s": { "command": "node" },
                "t": { "command": "deno" }
            } }"#,
        )
        .unwrap();
        let code = verify_for_root(repo.path(), false);
        assert_eq!(code, 1, "drift → exit 1");
    }

    #[test]
    fn rejected_config_refuses_lock_and_keeps_verify_nonzero_even_with_override() {
        let repo = tempdir().unwrap();
        fs::write(repo.path().join(".mcp.json"), r#"{"mcpServers":{}}"#).unwrap();

        assert_eq!(lock_for_root(repo.path(), false, false), 0);
        let lock_path = repo.path().join(".tirith").join(MCP_LOCK_FILENAME);
        let clean_baseline = fs::read(&lock_path).expect("read clean MCP baseline");
        assert_eq!(verify_for_root(repo.path(), false), 0);

        let vscode = repo.path().join(".vscode");
        fs::create_dir_all(&vscode).unwrap();
        fs::write(
            vscode.join("mcp.json"),
            r#"{"servers":{"poisoned":{"command":"node","args":["--token=plaintext"]}}}"#,
        )
        .unwrap();

        assert_eq!(
            verify_for_root(repo.path(), false),
            1,
            "a rejected supported config must make verification fail"
        );
        assert_eq!(
            lock_for_root(repo.path(), false, false),
            1,
            "ordinary lock must refuse to publish a partial trusted baseline"
        );
        assert_eq!(
            fs::read(&lock_path).unwrap(),
            clean_baseline,
            "refusal must leave the previously trusted baseline byte-identical"
        );

        assert_eq!(
            lock_for_root(repo.path(), false, true),
            0,
            "only the explicit audit override may record the coverage gap"
        );
        let incomplete = mcp_lock::load_lockfile(&lock_path).unwrap();
        assert_eq!(incomplete.rejected_configs.len(), 1);
        assert_eq!(incomplete.rejected_configs[0].path, ".vscode/mcp.json");
        assert_eq!(
            incomplete.rejected_configs[0].reason,
            mcp_lock::RejectedReason::SecretBearingArgument
        );
        assert_eq!(
            verify_for_root(repo.path(), false),
            1,
            "an exactly matching incomplete override is auditable, never trusted"
        );
    }

    #[test]
    fn verify_exits_zero_when_env_value_rotated() {
        // V8 records only env-name presence, so value rotation is intentionally
        // unobservable and does not produce drift.
        let repo = tempdir().unwrap();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "s": { "command": "node",
                "env": { "API_TOKEN": "old" } } } }"#,
        )
        .unwrap();
        let inventory = mcp_lock::build_inventory(repo.path());
        write_lockfile(
            &repo.path().join(".tirith").join(MCP_LOCK_FILENAME),
            &McpLockfile::from_inventory(&inventory),
            &inert_policy(),
        )
        .unwrap();

        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "s": { "command": "node",
                "env": { "API_TOKEN": "new" } } } }"#,
        )
        .unwrap();
        let code = verify_for_root(repo.path(), false);
        assert_eq!(code, 0, "rotated env value with same name → no drift");
    }

    #[test]
    fn verify_exits_two_when_lockfile_missing() {
        // No lockfile is a usage error, not drift.
        let repo = tempdir().unwrap();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "s": { "command": "node" } } }"#,
        )
        .unwrap();
        let code = verify_for_root(repo.path(), false);
        assert_eq!(code, 2, "missing lockfile → usage error → exit 2");
    }

    #[test]
    fn verify_exits_two_when_lockfile_malformed() {
        let repo = tempdir().unwrap();
        let lockdir = repo.path().join(".tirith");
        fs::create_dir_all(&lockdir).unwrap();
        fs::write(lockdir.join(MCP_LOCK_FILENAME), "{ not valid json").unwrap();
        let code = verify_for_root(repo.path(), false);
        assert_eq!(code, 2, "malformed lockfile → exit 2");
    }

    #[test]
    fn verify_with_json_exits_zero_when_inventory_matches() {
        let repo = repo_with_locked_mcp();
        let code = verify_for_root(repo.path(), true);
        assert_eq!(code, 0);
    }

    #[test]
    fn diff_always_exits_zero_even_when_drift_present() {
        let repo = repo_with_locked_mcp();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": {
                "s": { "command": "node" },
                "t": { "command": "deno" }
            } }"#,
        )
        .unwrap();
        let code = diff_for_root(repo.path(), false);
        assert_eq!(code, 0, "diff is informational — exit 0 even with drift");
    }

    #[test]
    fn diff_no_drift_exits_zero() {
        let repo = repo_with_locked_mcp();
        let code = diff_for_root(repo.path(), false);
        assert_eq!(code, 0);
    }

    #[test]
    fn diff_exits_two_when_lockfile_missing() {
        // No-lockfile is a usage error even for the informational verb.
        let repo = tempdir().unwrap();
        let code = diff_for_root(repo.path(), false);
        assert_eq!(code, 2);
    }

    #[test]
    fn escape_name_renders_control_bytes_safely() {
        // A name carrying a control byte must NOT reach the terminal raw.
        let escaped = escape_name("\x1b[31mEVIL");
        assert!(!escaped.contains('\x1b'), "raw ESC must not survive");
        assert!(escaped.contains("\\u{1b}"));
    }

    // `tirith mcp policy init` scaffolding.

    /// Build a repo with one stdio server declaring two tools, lockfile written.
    fn repo_with_locked_server_and_tools() -> tempfile::TempDir {
        let repo = tempdir().unwrap();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "fs": { "command": "node",
                "tools": ["read_file", "write_file"] } } }"#,
        )
        .unwrap();
        let inventory = mcp_lock::build_inventory(repo.path());
        let lockfile = McpLockfile::from_inventory(&inventory);
        let lock_path = repo.path().join(".tirith").join(MCP_LOCK_FILENAME);
        write_lockfile(&lock_path, &lockfile, &inert_policy()).expect("write");
        repo
    }

    #[test]
    fn policy_init_writes_example_file_with_lockfile_content() {
        let repo = repo_with_locked_server_and_tools();
        let code = policy_init_for_root(repo.path(), false, false);
        assert_eq!(code, 0, "policy init must succeed: exit code {code}");
        let example_path = repo.path().join(".tirith").join("mcp-policy.yaml.example");
        assert!(
            example_path.is_file(),
            ".tirith/mcp-policy.yaml.example must exist after policy init"
        );
        let body = fs::read_to_string(&example_path).unwrap();
        assert!(body.contains("fs"), "server name must appear: {body}");
        assert!(body.contains("read_file"), "tool name must appear: {body}");
        assert!(body.contains("write_file"), "tool name must appear: {body}");
        // Every entry must appear only commented out (preceded by `#`).
        for needle in ["- fs", "fs:"] {
            let lines: Vec<&str> = body
                .lines()
                .filter(|l| l.contains(needle) && !l.trim_start().starts_with('#'))
                .collect();
            assert!(
                lines.is_empty(),
                "an uncommented `{needle}` slipped into the scaffold: {lines:?}",
            );
        }
        assert!(body.contains("Tirith MCP policy scaffold"));
        assert!(body.contains("scan:"));
        assert!(body.contains("trusted_mcp_servers"));
        assert!(body.contains("mcp_allowed_tools"));
    }

    #[test]
    fn policy_init_is_deterministic_for_same_lockfile() {
        // Two runs against the same lockfile produce a byte-identical file.
        let repo = repo_with_locked_server_and_tools();
        let code = policy_init_for_root(repo.path(), false, false);
        assert_eq!(code, 0);
        let example_path = repo.path().join(".tirith").join("mcp-policy.yaml.example");
        let first = fs::read_to_string(&example_path).unwrap();

        let code = policy_init_for_root(repo.path(), false, true);
        assert_eq!(code, 0);
        let second = fs::read_to_string(&example_path).unwrap();

        assert_eq!(
            first, second,
            "policy_init must produce byte-identical output across re-runs",
        );
    }

    #[test]
    fn policy_init_refuses_to_overwrite_without_force() {
        let repo = repo_with_locked_server_and_tools();
        let code = policy_init_for_root(repo.path(), false, false);
        assert_eq!(code, 0);
        // Second run without --force must refuse (exit 1).
        let code = policy_init_for_root(repo.path(), false, false);
        assert_eq!(
            code, 1,
            "second policy_init without --force must refuse to overwrite",
        );
        let example_path = repo.path().join(".tirith").join("mcp-policy.yaml.example");
        assert!(example_path.is_file());
    }

    #[test]
    fn policy_init_overwrites_with_force() {
        let repo = repo_with_locked_server_and_tools();
        let example_path = repo.path().join(".tirith").join("mcp-policy.yaml.example");
        // Pre-create a sentinel that --force must overwrite.
        fs::create_dir_all(example_path.parent().unwrap()).unwrap();
        fs::write(&example_path, "SENTINEL").unwrap();

        let code = policy_init_for_root(repo.path(), false, true);
        assert_eq!(code, 0);
        let body = fs::read_to_string(&example_path).unwrap();
        assert!(!body.contains("SENTINEL"), "--force must overwrite");
        assert!(body.contains("Tirith MCP policy scaffold"));
    }

    #[test]
    fn policy_init_handles_missing_lockfile() {
        // No lockfile — still writes a header-only scaffold and exits 0.
        let repo = tempdir().unwrap();
        let code = policy_init_for_root(repo.path(), false, false);
        assert_eq!(code, 0, "missing lockfile must not be fatal");
        let example_path = repo.path().join(".tirith").join("mcp-policy.yaml.example");
        let body = fs::read_to_string(&example_path).unwrap();
        assert!(body.contains("Tirith MCP policy scaffold"));
        assert!(
            body.contains("No `.tirith/mcp.lock` was found"),
            "header should explain the missing-lockfile case: {body}",
        );
        assert!(!body.contains("- fs"));
    }

    #[test]
    fn policy_init_fails_on_unparseable_lockfile() {
        // An unparseable lockfile IS fatal — we cannot tell what to list.
        let repo = tempdir().unwrap();
        let lock_dir = repo.path().join(".tirith");
        fs::create_dir_all(&lock_dir).unwrap();
        fs::write(lock_dir.join(MCP_LOCK_FILENAME), "{not valid json").unwrap();
        let code = policy_init_for_root(repo.path(), false, false);
        assert_eq!(
            code, 1,
            "unparseable lockfile must fail with exit 1: {code}",
        );
    }

    #[test]
    fn policy_init_handles_lockfile_with_no_servers() {
        // A lockfile listing zero servers still emits a template form.
        let repo = tempdir().unwrap();
        let inventory = mcp_lock::build_inventory(repo.path());
        let lockfile = McpLockfile::from_inventory(&inventory);
        let lock_path = repo.path().join(".tirith").join(MCP_LOCK_FILENAME);
        write_lockfile(&lock_path, &lockfile, &inert_policy()).unwrap();
        let code = policy_init_for_root(repo.path(), false, false);
        assert_eq!(code, 0);
        let body = fs::read_to_string(repo.path().join(".tirith").join("mcp-policy.yaml.example"))
            .unwrap();
        assert!(
            body.contains("The lockfile recorded no MCP servers"),
            "scaffold should explain the empty case and emit a template: {body}",
        );
        assert!(body.contains("example-server"));
    }

    #[test]
    fn policy_init_redacts_hostile_server_name() {
        // A hostile server name must NOT inject raw bytes into the example file
        // (which would inject when the operator `cat`s it) — yaml_safe_scalar
        // quotes-and-escapes them.
        let repo = tempdir().unwrap();
        let inv = mcp_lock::McpInventory {
            servers: vec![mcp_lock::McpServerEntry {
                name: "ev\x1b[31mil\nname".into(),
                transport: mcp_lock::McpTransport::Stdio {
                    command: "node".into(),
                    args: vec![],
                    env: vec![],
                },
                tools: vec!["weird\ntool".into()],
                tools_declared: true,
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let lockfile = McpLockfile::from_inventory(&inv);
        let lock_path = repo.path().join(".tirith").join(MCP_LOCK_FILENAME);
        write_lockfile(&lock_path, &lockfile, &inert_policy()).unwrap();

        let code = policy_init_for_root(repo.path(), false, false);
        assert_eq!(code, 0);
        let body = fs::read_to_string(repo.path().join(".tirith").join("mcp-policy.yaml.example"))
            .unwrap();
        // No raw ESC / BS within any line (newline line separators are fine).
        for line in body.lines() {
            assert!(
                !line.contains('\x1b'),
                "ESC byte leaked into scaffold line: {line:?}",
            );
            assert!(
                !line.contains('\x08'),
                "BS byte leaked into scaffold line: {line:?}",
            );
        }
    }

    #[test]
    fn policy_init_json_format_outputs_structured_preview() {
        let repo = repo_with_locked_server_and_tools();
        let code = policy_init_for_root(repo.path(), true, false);
        assert_eq!(code, 0);
        let example_path = repo.path().join(".tirith").join("mcp-policy.yaml.example");
        assert!(example_path.is_file());
    }

    #[test]
    fn build_policy_scaffold_keeps_same_named_servers_separate_by_identity() {
        // Two lockfile entries with the same attacker-controlled name remain
        // distinct principals and never inherit or union one another's tools.
        let scaffold = PolicyScaffold {
            lockfile_present: true,
            servers: vec![
                PolicyScaffoldServer {
                    identity: "mcp:v1:identity-a".to_string(),
                    name: "dup".to_string(),
                    source_config: ".mcp.json".to_string(),
                    tools: vec!["a".to_string()],
                    live_descriptors_approved: true,
                },
                PolicyScaffoldServer {
                    identity: "mcp:v1:identity-b".to_string(),
                    name: "dup".to_string(),
                    source_config: ".vscode/mcp.json".to_string(),
                    tools: vec!["b".to_string()],
                    live_descriptors_approved: true,
                },
            ],
        };
        let yaml = render_policy_scaffold_yaml(&scaffold);
        let trust_lines: Vec<&str> = yaml
            .lines()
            .filter(|line| {
                line.trim_start().starts_with("#   - ") && line.contains("mcp:v1:identity-")
            })
            .collect();
        assert_eq!(
            trust_lines.len(),
            2,
            "same-named servers require distinct trusted identities: \
             got {trust_lines:?}",
        );
        assert_eq!(yaml.matches("mcp:v1:identity-a").count(), 2);
        assert_eq!(yaml.matches("mcp:v1:identity-b").count(), 2);
    }

    #[test]
    fn build_policy_scaffold_includes_approved_live_descriptor_names() {
        let inventory = mcp_lock::McpInventory {
            servers: vec![mcp_lock::McpServerEntry {
                name: "dynamic".to_string(),
                transport: McpTransport::Stdio {
                    command: "node".to_string(),
                    args: vec![],
                    env: vec![],
                },
                tools: vec!["static_read".to_string()],
                tools_declared: true,
                source_config: ".mcp.json".to_string(),
            }],
            configs: vec![".mcp.json".to_string()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let mut lock = McpLockfile::from_inventory(&inventory);
        lock.servers[0].descriptors = vec![
            mcp_lock::ToolDescriptor::from_tool_entry(&serde_json::json!({"name": "live_exec"})),
            mcp_lock::ToolDescriptor::from_tool_entry(&serde_json::json!({"name": "static_read"})),
        ];
        lock.servers[0].descriptors_approved = true;
        let scaffold = build_policy_scaffold(Some(&lock));
        assert_eq!(
            scaffold.servers[0].tools,
            vec!["live_exec".to_string(), "static_read".to_string()]
        );
        let yaml = render_policy_scaffold_yaml(&scaffold);
        assert!(yaml.contains("deduped static + approved live tools"));
        assert!(yaml.contains("live_exec"));
    }

    // Finding F2 — `verify`'s JSON-write failure must NOT collapse the drift
    // exit code (1) into a usage error (2). Truth table for `verify_exit_code`.

    #[test]
    fn verify_exit_code_drift_with_json_write_failure_preserves_drift() {
        // Drift detected AND json write failed → 1, not 2.
        assert_eq!(
            verify_exit_code(false, false),
            1,
            "drift must remain exit 1 even when JSON write failed",
        );
    }

    #[test]
    fn verify_exit_code_no_drift_with_json_write_failure_is_usage_error() {
        // Without drift, the only consumer signal (the JSON) is broken.
        assert_eq!(
            verify_exit_code(true, false),
            2,
            "no drift + JSON write failure → usage error (the only signal is broken)",
        );
    }

    #[test]
    fn verify_exit_code_happy_paths() {
        assert_eq!(verify_exit_code(true, true), 0, "no drift, write OK → 0");
        assert_eq!(verify_exit_code(false, true), 1, "drift, write OK → 1");
    }

    // Finding F17 — every YAML indicator byte forces quoting, every safe byte
    // does not.

    #[test]
    fn yaml_safe_scalar_quotes_every_indicator_byte() {
        for &b in YAML_NEEDS_QUOTING_BYTES {
            let s = format!("a{}b", b as char);
            let out = yaml_safe_scalar(&s);
            assert!(
                out.starts_with('"') && out.ends_with('"'),
                "byte 0x{b:02x} ({:?}) must force quoting: got {out:?}",
                b as char,
            );
        }
    }

    #[test]
    fn yaml_safe_scalar_does_not_quote_safe_strings() {
        for safe in &["abc", "myserver", "TOOL_NAME", "v1_2_3", "a.b.c", "fooBar"] {
            assert_eq!(
                yaml_safe_scalar(safe),
                *safe,
                "safe string {safe:?} must NOT be quoted",
            );
        }
    }

    #[test]
    fn yaml_safe_scalar_quotes_control_bytes() {
        // Control bytes are checked separately from YAML_NEEDS_QUOTING_BYTES but
        // still force quoting.
        for b in 0u8..0x20 {
            let s = format!("a{}b", b as char);
            let out = yaml_safe_scalar(&s);
            assert!(
                out.starts_with('"') && out.ends_with('"'),
                "control byte 0x{b:02x} must force quoting: got {out:?}",
            );
        }
        // DEL too.
        let s = format!("a{}b", 0x7f as char);
        let out = yaml_safe_scalar(&s);
        assert!(out.starts_with('"'));
    }

    // Finding F13 (PRT CG-2) — a scaffold rendered for a hostile name must parse
    // cleanly through `serde_yaml`, and `yaml_safe_scalar`'s output round-trips
    // byte-for-byte through a real YAML parser.

    #[test]
    fn policy_init_scaffold_yaml_parses_after_uncomment() {
        // A scaffold for a hostile name must produce valid YAML even after the
        // operator uncomments the `trusted_mcp_servers` block — guaranteed by
        // `yaml_safe_scalar`. Pin it by parsing the rendered bytes back.
        let hostile = "ev\u{1b}[31mil\nname";

        let scaffold = PolicyScaffold {
            lockfile_present: true,
            servers: vec![PolicyScaffoldServer {
                identity: hostile.to_string(),
                name: hostile.to_string(),
                source_config: ".mcp.json".to_string(),
                tools: vec!["read".to_string()],
                live_descriptors_approved: true,
            }],
        };
        let body = render_policy_scaffold_yaml(&scaffold);

        // Programmatically uncomment the `trusted_mcp_servers:` header (only the
        // canonical two-space-indented site) and each list entry underneath.
        let uncommented_header =
            body.replace("\n  # trusted_mcp_servers:", "\n  trusted_mcp_servers:");
        let uncommented: String = uncommented_header
            .lines()
            .map(|line| {
                if let Some(rest) = line.strip_prefix("  #   - ") {
                    format!("    - {rest}\n")
                } else {
                    format!("{line}\n")
                }
            })
            .collect();

        let parsed: serde_yaml::Value = serde_yaml::from_str(&uncommented).unwrap_or_else(|e| {
            panic!(
                "scaffold YAML must parse cleanly after uncommenting:\nerror: {e}\nbody:\n{uncommented}"
            )
        });

        // The loaded name must byte-equal the hostile input (no escapes leaking
        // through as literal text).
        let names = parsed
            .get("scan")
            .and_then(|s| s.get("trusted_mcp_servers"))
            .and_then(|v| v.as_sequence())
            .expect("scan.trusted_mcp_servers must be a sequence after uncomment");
        assert_eq!(names.len(), 1, "exactly one server in the list");
        let recovered = names[0]
            .as_str()
            .expect("the entry must be a string scalar");
        assert_eq!(
            recovered, hostile,
            "the round-tripped name must byte-equal the hostile input",
        );
    }

    #[test]
    fn yaml_safe_scalar_round_trips_through_yaml_parser() {
        // Table-driven: for each input, feed `yaml_safe_scalar`'s output into a
        // one-key YAML doc, parse it, assert byte-for-byte recovery. DEL
        // (`\x7f`) is the one known gap — pinned by the separate DEL test below.
        let cases: &[&str] = &[
            // YAML reserved indicators (the set centralized in
            // `YAML_NEEDS_QUOTING_BYTES`).
            ":", "#", "-", "?", ",", "[", "]", "{", "}", "&", "*", "!", "|", ">", "'", "\"", "%",
            "@", "`", // Whitespace.
            " ", "\t", // Line breakers.
            "\n", "\r",
            // Control bytes that DO round-trip (serde_json emits
            // `\u00XX`-style escapes for every byte < 0x20).
            "\0", "\x1b", // ESC
            // Multi-byte UTF-8 (Greek small letter alpha, a CJK character,
            // and an emoji).
            "α", "中", "🦀", // Empty string.
            "",   // A combination that exercises several rules at once.
            "a: # b\n",
        ];

        for input in cases {
            let scalar = yaml_safe_scalar(input);
            // Build a one-key document. The KEY is a plain ASCII identifier
            // (so we don't accidentally test the key-quoting path here);
            // only the VALUE is the rendered scalar.
            let doc = format!("k: {scalar}\n");
            let parsed: serde_yaml::Value = serde_yaml::from_str(&doc).unwrap_or_else(|e| {
                panic!(
                    "yaml_safe_scalar({input:?}) → {scalar:?} must parse as YAML:\nerror: {e}\ndoc:\n{doc}"
                )
            });
            let recovered = parsed
                .get("k")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| {
                    panic!(
                        "yaml_safe_scalar({input:?}) → {scalar:?} did not load as a string scalar.\ndoc:\n{doc}\nparsed: {parsed:?}"
                    )
                });
            assert_eq!(
                recovered, *input,
                "yaml_safe_scalar must round-trip byte-for-byte. input: {input:?} → scalar: {scalar:?} → recovered: {recovered:?}",
            );
        }
    }

    #[test]
    fn yaml_safe_scalar_round_trips_del() {
        // `yaml_safe_scalar` escapes DEL (`\x7f`) as `\u007F` so it
        // round-trips: raw DEL (what serde_json emits) is disallowed inside a
        // YAML 1.2 §5.7 double-quoted scalar.
        let scalar = yaml_safe_scalar("\x7f");
        // Still quoted (the control-byte check fires); the gap was the escape.
        assert!(
            scalar.starts_with('"') && scalar.ends_with('"'),
            "DEL must still be quoted (forces quoting): {scalar:?}",
        );
        assert!(
            !scalar.contains('\u{7f}'),
            "DEL must be escaped, not embedded as a raw byte: {scalar:?}",
        );
        let doc = format!("k: {scalar}\n");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&doc).expect(
            "DEL must round-trip through the \\u007F escape (yaml_safe_scalar's DEL post-process)",
        );
        assert_eq!(
            parsed.get("k").and_then(|v| v.as_str()),
            Some("\u{7f}"),
            "round-tripped value must byte-equal the input DEL",
        );
    }

    // PR #121 item 17 — `format_inventory_server_line` debug-escapes both the
    // server name and source_config so a hostile `.mcp.json` can't smuggle
    // ANSI/CR/BEL through the inventory printer (this site was missed).

    #[test]
    fn format_inventory_server_line_escapes_ansi_in_name_and_source() {
        let server = mcp_lock::McpServerEntry {
            name: "evil\x1b[31m".into(),
            transport: mcp_lock::McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![],
            },
            tools: vec!["read".into()],
            tools_declared: true,
            source_config: "hostile\rpath\x07.mcp.json".into(),
        };
        let line = format_inventory_server_line(&server);
        // No raw ESC / CR / BEL byte may reach the printer's output.
        assert!(
            !line.chars().any(|c| c == '\x1b'),
            "raw ESC byte must NOT appear in formatted line: {line:?}",
        );
        assert!(
            !line.chars().any(|c| c == '\r'),
            "raw CR byte must NOT appear in formatted line: {line:?}",
        );
        assert!(
            !line.chars().any(|c| c == '\x07'),
            "raw BEL byte must NOT appear in formatted line: {line:?}",
        );
        // The escaped (legible) form should still be visible.
        assert!(
            line.contains("evil"),
            "the legible portion of the name should still appear: {line}",
        );
        assert!(
            line.contains("hostile"),
            "the legible portion of source_config should still appear: {line}",
        );
    }

    // PR #121 CR follow-up — `format_inventory_server_line` distinguishes the
    // three tools states (omitted / declared empty / N entries) via
    // `tools_declared`; the pre-fix renderer collapsed omitted and explicit-empty.

    #[test]
    fn format_inventory_server_line_distinguishes_tools_states() {
        let base_transport = mcp_lock::McpTransport::Stdio {
            command: "node".into(),
            args: vec![],
            env: vec![],
        };
        // State 1: tools omitted — runtime may expose any tool.
        let omitted = mcp_lock::McpServerEntry {
            name: "srv-omitted".into(),
            transport: base_transport.clone(),
            tools: vec![],
            tools_declared: false,
            source_config: ".mcp.json".into(),
        };
        let line_omitted = format_inventory_server_line(&omitted);
        assert!(
            line_omitted.contains("tools omitted"),
            "omitted-tools state must use the 'tools omitted' phrasing: {line_omitted}",
        );
        assert!(
            line_omitted.contains("runtime tools"),
            "omitted-tools state must mention runtime tools: {line_omitted}",
        );

        // State 2: tools declared as `[]` — zero-tool allowlist.
        let empty_declared = mcp_lock::McpServerEntry {
            name: "srv-empty".into(),
            transport: base_transport.clone(),
            tools: vec![],
            tools_declared: true,
            source_config: ".mcp.json".into(),
        };
        let line_empty = format_inventory_server_line(&empty_declared);
        assert!(
            line_empty.contains("no tools declared"),
            "explicit-empty state must use the 'no tools declared' phrasing: {line_empty}",
        );
        assert!(
            line_empty.contains("explicit empty"),
            "explicit-empty state must mention 'explicit empty': {line_empty}",
        );

        // State 3: N declared tools — count is shown.
        let with_tools = mcp_lock::McpServerEntry {
            name: "srv-tools".into(),
            transport: base_transport,
            tools: vec!["read".into(), "write".into()],
            tools_declared: true,
            source_config: ".mcp.json".into(),
        };
        let line_tools = format_inventory_server_line(&with_tools);
        assert!(
            line_tools.contains("2 tool(s)"),
            "declared-tools state must show the count: {line_tools}",
        );
    }

    // PR #121 item 16 — an inventory carrying ONLY rejected_configs (no servers,
    // no parseable configs) still produces a non-empty rejected-config render.

    #[test]
    fn rejected_configs_render_even_when_inventory_is_empty() {
        let inv = McpInventory {
            servers: vec![],
            configs: vec![],
            malformed_configs: vec![],
            rejected_configs: vec![mcp_lock::RejectedConfig {
                path: ".mcp.json".to_string(),
                reason: mcp_lock::RejectedReason::Symlink,
            }],
        };
        assert!(
            inv.is_empty(),
            "test scaffold: inventory must be empty for this regression",
        );
        let lines = format_rejected_config_lines(&inv.rejected_configs);
        assert_eq!(
            lines.len(),
            1,
            "the rejection lines must still render for an otherwise-empty inventory: {lines:?}",
        );
        assert!(
            lines[0].contains(".mcp.json"),
            "the rejected path must appear in the rendered line: {}",
            lines[0],
        );
    }
}
