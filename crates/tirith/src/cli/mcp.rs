//! `tirith mcp lock` / `tirith mcp verify` / `tirith mcp diff` — capture and
//! govern the MCP servers a repository declares.
//!
//! These are the Milestone 4 (Agent & MCP governance) `mcp` subcommand group:
//! `lock` writes the deterministic inventory baseline to
//! `<repo_root>/.tirith/mcp.lock`; `verify` gates on drift (exit 1 when the
//! committed lockfile no longer matches the current inventory); `diff` shows
//! that drift informationally.
//!
//! Every command is a **local file operation**: it touches no network and is
//! entirely off the tier-1/2/3 detection hot path. `lock` writes one file
//! (`mcp.lock`); `verify` and `diff` read it. Discovery is repo-local only —
//! user-level configs (`~/.claude/`, …) are never inventoried.
//!
//! **Privacy invariant.** Env values and URL userinfos are never persisted
//! in `mcp.lock` (each is replaced with a salted hash; see `mcp_lock.rs`)
//! and they are never **printed** by `verify` / `diff` either — the human
//! and `--format json` outputs only ever name the variable / credential
//! that changed, never its value or hash.

use std::path::{Path, PathBuf};

use tirith_core::mcp_lock::{
    self, McpDrift, McpEnvChange, McpInventory, McpLockLoadError, McpLockfile, McpServerDriftEntry,
    McpToolsChangeKind, McpTransportChange, MCP_LOCK_FILENAME,
};
use tirith_core::policy;

/// Run `tirith mcp lock`.
///
/// Resolves the repository root (the `.git`-boundary walk, same as the policy
/// system), builds the MCP inventory, writes `<repo_root>/.tirith/mcp.lock`,
/// and reports honestly how many configs / servers were captured.
///
/// Exit codes:
/// * `0` — the lockfile was written (including the "no MCP configs found" case:
///   finding nothing to lock is **not** an error — an empty but valid lockfile
///   is still written so `mcp verify` has a baseline).
/// * `1` — an operational failure: the repo root could not be determined, the
///   `.tirith/` directory could not be created, or the lockfile could not be
///   written. A JSON-write failure on an otherwise-successful run also maps
///   here so a piped consumer never sees truncated JSON with a success code.
pub fn lock(json: bool) -> i32 {
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

    let inventory = mcp_lock::build_inventory(&repo_root);
    let lockfile = McpLockfile::from_inventory(&inventory);

    let lock_path = repo_root.join(".tirith").join(MCP_LOCK_FILENAME);
    if let Err(e) = write_lockfile(&lock_path, &lockfile) {
        report_error(
            json,
            &format!("failed to write {}: {e}", lock_path.display()),
        );
        return 1;
    }

    if json {
        if !print_json(&repo_root, &lock_path, &inventory, &lockfile) {
            // JSON serialization/write failed: the lockfile is on disk, but the
            // caller's output is broken — exit non-zero so a pipeline notices.
            return 1;
        }
    } else {
        print_human(&lock_path, &inventory);
    }

    0
}

/// Resolve the repository root for `mcp lock`.
///
/// Honors `TIRITH_POLICY_ROOT` first (treated as the repo root directly — so
/// a test or deliberate override can pin the root without needing a `.git/`
/// at the override path), then falls back to the `.git`-boundary walk-up from
/// the current directory via `policy::find_repo_root`.
///
/// **Not identical to the other two resolvers in the codebase — three
/// different mechanisms exist, deliberately.** A maintainer who needs to
/// touch one of these should read all three before assuming they share a
/// helper:
///
/// * `policy::find_repo_root` (used by `.tirith/trust.json` via
///   `Policy::load_trust_entries`) — raw `.git`-walk only; ignores
///   `TIRITH_POLICY_ROOT` entirely.
/// * `policy::discover_local_policy_path` (used by `tirith policy`) —
///   joins `.tirith/` onto `TIRITH_POLICY_ROOT` (so the env var points
///   at a *repo root*, and the policy file is located inside the
///   `.tirith/` subdirectory of it), then falls through to a walk-up.
/// * This function — takes `TIRITH_POLICY_ROOT` as the repo root
///   directly (so the `.tirith/` subpath is appended later when the
///   lockfile path is built); falls through to a walk-up.
///
/// The shapes line up *in the common case* — `TIRITH_POLICY_ROOT=/repo`
/// puts `mcp.lock` at `/repo/.tirith/mcp.lock` and the policy at
/// `/repo/.tirith/policy.yaml`, so the lockfile and policy land beside each
/// other in practice. They diverge under the trust resolver (which never
/// sees the env var), so a maintainer expecting strict equivalence will be
/// wrong. Unifying the three resolvers behind a single helper is a worthwhile
/// follow-up but a behavior change requiring its own PR.
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
fn write_lockfile(lock_path: &Path, lockfile: &McpLockfile) -> std::io::Result<()> {
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(lock_path, lockfile.render())
}

/// Emit the machine-readable result.
///
/// Returns `false` on a JSON-write failure so the caller can exit non-zero.
fn print_json(
    repo_root: &Path,
    lock_path: &Path,
    inventory: &McpInventory,
    lockfile: &McpLockfile,
) -> bool {
    #[derive(serde::Serialize)]
    struct JsonOut<'a> {
        /// Result-envelope schema version (independent of the lockfile's own
        /// `format_version`).
        schema_version: u32,
        repo_root: String,
        lock_path: String,
        configs_found: usize,
        malformed_configs: &'a [String],
        /// Physically-present MCP config paths that were skipped during
        /// discovery / inventory build, with the reason for each. A
        /// silent skip would hide a misconfigured `.mcp.json` (symlinked,
        /// oversized, unreadable, …) behind an "empty lockfile" result;
        /// surfacing this list makes the skip visible.
        ///
        /// Additive on the result envelope only — the lockfile's own
        /// `format_version` is unchanged (still 4).
        rejected_configs: &'a [mcp_lock::RejectedConfig],
        servers_locked: usize,
        /// The lockfile document that was written.
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
        lockfile,
    };

    super::write_json_stdout(&out, "tirith mcp lock: failed to write JSON output")
}

/// Render the human-readable summary.
///
/// The summary goes to stderr (consistent with `tirith scan` / `ecosystem
/// scan`); the written path goes to stdout so it can be captured.
fn print_human(lock_path: &Path, inventory: &McpInventory) {
    if inventory.is_empty() {
        // Honest "nothing to lock" — not an error. An empty lockfile is still
        // written so a later `mcp verify` has a baseline to diff against.
        eprintln!("tirith mcp lock: no MCP configuration files found in this repository.");
        eprintln!(
            "  Looked for .mcp.json / mcp.json / mcp_settings.json and the IDE variants \
             (.vscode/, .cursor/, .windsurf/, .cline/, .amazonq/, .continue/, .kiro/)."
        );
        eprintln!("  Wrote an empty lockfile so `tirith mcp verify` has a baseline.");

        // PR #121 item 16 — show rejected configs even when the
        // inventory is empty. [`McpInventory::is_empty`] explicitly
        // notes that `rejected_configs` does NOT count toward
        // emptiness: a repo whose only `.mcp.json` is a symlink-out /
        // oversized / unreadable would otherwise see "no configs found"
        // with no signal that a config was actually present but blocked.
        // Surface the rejection list here so the operator can see the
        // cause.
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
            "  note: {} config file(s) could not be parsed and contributed no servers \
             (listed above). This is not an error — the lockfile reflects only the \
             configs tirith could read.",
            inventory.malformed_configs.len(),
        );
    }

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

    eprintln!();
    eprintln!("  wrote {}", lock_path.display());
    println!("{}", lock_path.display());
}

/// Render each [`mcp_lock::RejectedConfig`] as the human-summary line printed
/// under `tirith mcp lock`'s `note:` block.
///
/// **The `path` is debug-escaped (`{:?}`).** The `rejected.path` carries a
/// repo-relative filename that — although today's source is the static
/// [`mcp_lock::MCP_CONFIG_RELATIVE_PATHS`] table — must be treated as
/// potentially attacker-shaped at every print site. The same convention
/// the env-name / server-name / tool-name printers (`escape_name`,
/// `describe_transport`) already apply: a name carrying `\x1b` / `\r` /
/// `\n` / any control byte would otherwise reach the operator's terminal
/// raw and could rewrite the rendering (colour injection, line erasure,
/// cursor repositioning). Debug formatting renders every control byte as
/// `\u{NN}` / `\n` / `\r` / etc. and quotes the value — costless for
/// today's static paths (they Debug back to themselves with quotes) and
/// the principled default for any future code path that introduces an
/// attacker-controlled rejection source.
///
/// The JSON surface (`print_json` and the structured `RejectedConfig`
/// serialization that flows through it) does **not** need this escape:
/// `serde_json` natively escapes every C0 control byte as a `\u00NN`
/// JSON-string escape, so a hostile path cannot inject through the JSON
/// envelope. This helper is the human-stderr render only.
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

/// Render one inventory server entry as it appears under the `servers:`
/// block of `tirith mcp lock`'s human summary.
///
/// **Both `server.name` and `server.source_config` are debug-escaped.**
/// Both originate from a `.mcp.json` checked into the repo and must be
/// treated as attacker-controllable at every print site (PR #121 item
/// 17). The codebase's stated discipline — see the comments at the top
/// of [`format_rejected_config_lines`], at [`escape_name`], and at the
/// drift / env-name printers (`describe_changed_entry`,
/// `describe_transport`) — is "every printer escapes attacker-
/// controllable strings". This site was missed before PR #121 fixed
/// it; the helper is factored out so the contract can be unit-tested
/// without driving the whole `print_human` function.
fn format_inventory_server_line(server: &mcp_lock::McpServerEntry) -> String {
    let transport = describe_transport(&server.transport);
    // Branch on `tools_declared` so the operator can distinguish three states:
    //   1. tools omitted in the source config — MCP clients treat this as
    //      "any tool the server exposes at runtime". The lockfile captures no
    //      tool list because none was declared.
    //   2. tools declared as `"tools": []` — an explicit empty allowlist. The
    //      source config intentionally allows no tools.
    //   3. tools declared with one or more entries — the normal case.
    // Without this distinction (the pre-fix code rendered cases 1 and 2 with
    // the same "all tools (none declared)" string), an operator could not
    // tell whether a server was deliberately scoped to zero tools or whether
    // the runtime would surface every tool the server exposes — a real
    // policy ambiguity that the lockfile is supposed to resolve.
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

/// One-line human description of a [`mcp_lock::RejectedReason`].
///
/// Used only by [`print_human`]; the structured variant is what the JSON
/// surface and any programmatic consumer reads. The description names the
/// failure category plainly without echoing arbitrary bytes (the
/// `size_bytes`/`permission_denied` fields are integers/booleans, safe to
/// interpolate).
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
    }
}

/// One-line description of a transport for the human summary.
///
/// A stdio server's `env` is named (the variable names only — raw values are
/// never stored anywhere, much less printed; the lockfile carries only a
/// salted hash) so a reader of `mcp lock` output can see that the server runs
/// with injected environment.
///
/// **Env names are debug-escaped before printing.** A config can declare an
/// env name containing ANSI escape sequences, newlines, or other terminal
/// control bytes (a malicious or careless config, or one round-tripped from a
/// hostile source). Printing the name verbatim would let those control bytes
/// reach the user's terminal and inject color, repositioning, or
/// line-erasure. Rust's `Debug` formatting on `&str` (`"{:?}"`) escapes every
/// control byte as a `\u{NN}` / `\n` / `\r` / etc. and quotes the value (the
/// dedicated test `describe_transport_escapes_control_bytes_in_env_names`
/// probes for the `\u{1b}` escape form to pin this contract) — the simplest
/// correct fix, applied at *every* env-name print site.
///
/// **A URL's userinfo is never printed.** The stored URL is already the
/// redacted form (`https://host/...` — the `user:token@` segment has been
/// stripped during parsing). When the source config declared a userinfo, the
/// summary prints a separate `(credentials in source URL)` annotation so the
/// reader can see that the redaction fired without revealing the credential
/// itself.
fn describe_transport(transport: &mcp_lock::McpTransport) -> String {
    match transport {
        mcp_lock::McpTransport::Url { url, userinfo_hash } => {
            // The stored `url` is already userinfo-stripped (a credential, if
            // any, has been replaced with a salted hash). The URL still came
            // from a `.mcp.json` checked into the repo and must be treated as
            // attacker-controllable — debug-escape the bytes so control chars
            // (ANSI, CR, BEL, …) cannot rewrite the operator's terminal
            // (PR #121 follow-up: every printer escapes attacker-controllable
            // strings, transport fields are no exception).
            // When `userinfo_hash` is Some, append a fixed phrase so the
            // operator can see that the source declared a credential —
            // never the credential itself.
            if userinfo_hash.is_some() {
                format!("url {} (credentials in source URL)", escape_name(url))
            } else {
                format!("url {}", escape_name(url))
            }
        }
        mcp_lock::McpTransport::Stdio { command, args, env } => {
            // Both `command` and every `args` element originated from the
            // `.mcp.json` and are hostile-by-default. Debug-format each so a
            // command/arg containing ESC / CR / BEL renders as `\u{NN}` rather
            // than reaching the terminal raw.
            let mut desc = if args.is_empty() {
                format!("stdio {}", escape_name(command))
            } else {
                let escaped_args: Vec<String> = args.iter().map(|a| escape_name(a)).collect();
                format!("stdio {} {}", escape_name(command), escaped_args.join(" "))
            };
            if !env.is_empty() {
                // Debug-format each name so control bytes (ANSI escapes,
                // newlines, …) are rendered as `\u{NN}` literals (e.g. ESC →
                // `\u{1b}`) rather than reaching the terminal. Names appear
                // quoted, which is fine for the human summary and the test
                // snapshot.
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
        // A best-effort error envelope; the exit code is the source of truth,
        // so a failure to even print this is not separately handled.
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

// ===========================================================================
// `tirith mcp verify` — gating drift check
// ===========================================================================

/// Run `tirith mcp verify`.
///
/// Loads the committed `.tirith/mcp.lock`, rebuilds the current MCP inventory,
/// computes the structured drift, and reports it. Exit codes are the contract
/// a CI integration depends on:
///
/// * `0` — no drift. The lockfile and the current inventory are identical at
///   the inventory-hash level.
/// * `1` — drift detected. The lockfile and the current inventory differ;
///   the human / JSON output names the affected servers.
/// * `2` — a *usage* error: no lockfile to verify against, the lockfile
///   cannot be read or parsed, or the repository root could not be
///   determined. Distinct from drift so a CI caller can distinguish "the
///   lockfile is stale" (1) from "there is no lockfile to verify" (2).
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

/// Verify against an explicit repo root.
///
/// Split out so tests can drive a verify against a tempdir without mutating
/// process-wide environment variables. Production `verify(...)` resolves the
/// root the same way `lock` does, then calls this.
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

    if json {
        let write_ok = print_drift_json(
            "tirith mcp verify",
            repo_root,
            &lock_path,
            &lockfile,
            &drifts,
        );
        return verify_exit_code(drifts.is_empty(), write_ok);
    }
    print_verify_human(&lock_path, &drifts);
    verify_exit_code(drifts.is_empty(), true)
}

/// Decide `tirith mcp verify`'s exit code from `(in_sync, json_write_ok)`.
///
/// Pure function so the F2 contract — a JSON-write failure must NOT
/// collapse "drift was detected, exit 1" into "usage error, exit 2" — can
/// be pinned by a unit test without simulating a broken stdout pipe.
///
/// Contract:
/// * `in_sync == true, json_write_ok == true` → 0 (no drift).
/// * `in_sync == true, json_write_ok == false` → 2: there's no drift to
///   preserve, and the consumer's only signal (the JSON payload) is
///   broken — surface it as a usage-class failure so a pipeline notices.
/// * `in_sync == false, json_write_ok == true` → 1 (drift detected).
/// * `in_sync == false, json_write_ok == false` → 1: the JSON write
///   failed, but drift IS the dominant signal — preserve it. The
///   privacy / pipe-truncation contract (a consumer never sees
///   truncated JSON paired with a success code) is satisfied by the
///   stderr write inside `write_json_stdout`; we don't need exit 2 to
///   convey it.
pub(crate) fn verify_exit_code(in_sync: bool, json_write_ok: bool) -> i32 {
    match (in_sync, json_write_ok) {
        (true, true) => 0,
        (true, false) => 2,
        (false, _) => 1,
    }
}

/// Human-readable summary for `tirith mcp verify`.
///
/// Goes to stderr (the rest of the verdict surface follows that convention),
/// with one line per drift entry. Env values and URL userinfos never appear
/// — only the name of the variable / credential that changed.
fn print_verify_human(lock_path: &Path, drifts: &[McpDrift]) {
    if drifts.is_empty() {
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
    eprintln!();
    eprintln!("  re-run `tirith mcp lock` to refresh the lockfile once the change is intentional.");
}

// ===========================================================================
// `tirith mcp diff` — informational drift report
// ===========================================================================

/// Run `tirith mcp diff`.
///
/// Same drift data as `verify`, presented as an informational diff. Always
/// exits 0 (a usage error still exits 2 so a piped consumer can distinguish
/// "no drift" from "I could not check").
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

/// Diff against an explicit repo root.
///
/// Split out so tests can drive a diff against a tempdir without mutating
/// process-wide environment variables.
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
        if !print_drift_json("tirith mcp diff", repo_root, &lock_path, &lockfile, &drifts) {
            return 2;
        }
    } else {
        print_diff_human(&lock_path, &drifts);
    }

    0
}

/// Human-readable summary for `tirith mcp diff`.
fn print_diff_human(lock_path: &Path, drifts: &[McpDrift]) {
    if drifts.is_empty() {
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
}

// ===========================================================================
// shared drift presentation helpers (used by verify and diff)
// ===========================================================================

/// Count drifts by kind: `(added, removed, changed)`.
fn drift_kind_counts(drifts: &[McpDrift]) -> (usize, usize, usize) {
    let mut added = 0usize;
    let mut removed = 0usize;
    let mut changed = 0usize;
    for d in drifts {
        match d {
            McpDrift::Added { .. } => added += 1,
            McpDrift::Removed { .. } => removed += 1,
            McpDrift::Changed(_) => changed += 1,
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
        }
    }
}

/// Print the per-field detail of a `Changed` drift entry. Every printed name
/// is **debug-escaped** (`{:?}`), so a maliciously-crafted server / env /
/// tool name containing ANSI escapes, newlines, or other terminal control
/// bytes cannot inject control sequences into the operator's terminal —
/// same treatment as `describe_transport`'s env-name handling in `lock`.
fn describe_changed_entry(entry: &McpServerDriftEntry) {
    for change in &entry.transport_changes {
        match change {
            McpTransportChange::KindChanged { previous, current } => {
                eprintln!("      - transport kind: {previous} → {current}");
            }
            McpTransportChange::UrlChanged => {
                // The stored URL changed bytes; both sides are already
                // userinfo-stripped in the lockfile, so naming the host
                // here would only echo the redacted form. The diff is the
                // structural fact; the lockfile has the bytes.
                eprintln!("      - URL changed (redacted form recorded in mcp.lock)");
            }
            McpTransportChange::UserinfoAdded => {
                eprintln!("      - URL userinfo added (credential present in source URL)");
            }
            McpTransportChange::UserinfoRemoved => {
                eprintln!("      - URL userinfo removed");
            }
            McpTransportChange::UserinfoSwapped => {
                eprintln!("      - URL userinfo changed (credential rotated)");
            }
            McpTransportChange::CommandChanged => {
                eprintln!("      - stdio command changed");
            }
            McpTransportChange::ArgsChanged => {
                eprintln!("      - stdio args changed");
            }
            McpTransportChange::EnvChanged => {
                // The per-variable detail is printed below, in `env_changes`.
                // The transport-level `EnvChanged` marker is the headline.
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
                    "      - env value changed: {} (raw value never stored or printed)",
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

/// Debug-format a name. ANSI escapes / newlines / control bytes inside a
/// server / env / tool name are rendered as `\u{1b}` / `\n` / … so a hostile
/// or careless config cannot inject terminal control sequences when a drift
/// is printed.
fn escape_name(name: &str) -> String {
    format!("{name:?}")
}

/// Shared JSON output for `verify` / `diff`. The envelope is identical so a
/// machine consumer can switch between the two with the same parser; only
/// the exit code distinguishes the gating verb (`verify`) from the
/// informational verb (`diff`).
///
/// Returns `false` on a write failure so the caller can exit non-zero.
fn print_drift_json(
    command: &str,
    repo_root: &Path,
    lock_path: &Path,
    lockfile: &McpLockfile,
    drifts: &[McpDrift],
) -> bool {
    let (added, removed, changed) = drift_kind_counts(drifts);

    #[derive(serde::Serialize)]
    struct JsonOut<'a> {
        /// Result-envelope schema version (independent of the lockfile's own
        /// `format_version`).
        schema_version: u32,
        repo_root: String,
        lock_path: String,
        /// `lock` / `verify` / `diff` — so a piped consumer can tell which
        /// command produced the document.
        command: &'a str,
        /// The lockfile's recorded `format_version` (so the consumer can
        /// react to a schema bump independently of the envelope version).
        lockfile_format_version: u32,
        /// Total drift count.
        drift_count: usize,
        added_count: usize,
        removed_count: usize,
        changed_count: usize,
        /// Whether the inventory matches the lockfile (i.e. `drift_count == 0`).
        in_sync: bool,
        /// The drift entries themselves, in stable order.
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
        in_sync: drifts.is_empty(),
        drifts,
    };

    let ctx = format!("{command}: failed to write JSON output");
    super::write_json_stdout(&out, &ctx)
}

// ===========================================================================
// `tirith mcp policy init` — scaffold a starter MCP policy
// ===========================================================================

/// Run `tirith mcp policy init`.
///
/// Reads the committed `.tirith/mcp.lock` and writes
/// `.tirith/mcp-policy.yaml.example` — a scaffold of `scan.trusted_mcp_servers`
/// and `scan.mcp_allowed_tools` entries (commented out) listing every server
/// currently locked and the tools it currently exposes. The operator copies
/// the file in, uncomments the entries they wish to declare, and merges them
/// into `.tirith/policy.yaml` themselves.
///
/// A separate `.example` file is cleaner than mutating the operator's
/// existing policy: the operator can `diff` it against their working
/// `policy.yaml` and integrate the bits they want.
///
/// Determinism: running `mcp policy init` twice against the same lockfile
/// produces a byte-identical file. The lockfile is sorted by
/// `(name, source_config)` (see `mcp_lock::McpLockfile::from_inventory`), so
/// the policy scaffold's server order is stable.
///
/// Exit codes:
/// * `0` — the example policy was written (including the "no lockfile" case —
///   a header-only example is still written so the operator has a starting
///   point; the body lists nothing because there is nothing to list yet).
/// * `1` — the lockfile is unparseable (the operator must fix or refresh it
///   before generating policy from it), the repo root cannot be determined,
///   or the example file cannot be written.
/// * `2` — usage / argument error (e.g. an unrecognized `--format` value).
///   Currently unused but reserved so future arg validation has a place to
///   land without rewriting consumers.
///
/// `--format json` emits a planned-policy preview (the same scaffold the
/// human form writes, plus the example file path and the lockfile path) so
/// a CI integration can ingest the proposed policy without reading the
/// example file off disk.
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
/// the command against a tempdir without mutating process-wide environment
/// variables.
pub(crate) fn policy_init_for_root(repo_root: &Path, json: bool, force: bool) -> i32 {
    let lock_path = repo_root.join(".tirith").join(MCP_LOCK_FILENAME);
    let example_path = repo_root.join(".tirith").join("mcp-policy.yaml.example");

    // Reject overwriting an existing example file unless --force is passed,
    // mirroring `tirith policy init`. The operator may have edited the
    // example to track their working policy.
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

    // Load the lockfile if present. A missing lockfile is NOT fatal — we
    // still generate a header-only example so the operator has a starting
    // point. A truly unparseable lockfile is fatal because we cannot tell
    // what to list.
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

    // Build the scaffold. Both forms (human YAML, JSON preview) derive from
    // this same structured shape, so they cannot drift apart.
    let scaffold = build_policy_scaffold(lockfile_opt.as_ref());

    // Ensure `.tirith/` exists.
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
    if let Err(e) = std::fs::write(&example_path, &yaml_body) {
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

/// The structured scaffold the human and JSON forms share. Each entry is one
/// server name + the tool names the lockfile recorded for it.
#[derive(Debug, Clone, serde::Serialize)]
struct PolicyScaffold {
    /// `true` when no lockfile was found — the human and JSON output report
    /// this distinctly so the operator knows the scaffold is empty by
    /// construction, not because every server got dropped.
    lockfile_present: bool,
    /// Servers in `(name, source_config)` order — the lockfile's own
    /// canonical order.
    servers: Vec<PolicyScaffoldServer>,
}

/// One server entry in the policy scaffold.
#[derive(Debug, Clone, serde::Serialize)]
struct PolicyScaffoldServer {
    name: String,
    source_config: String,
    tools: Vec<String>,
}

/// Build the policy scaffold from a (possibly absent) lockfile.
///
/// A missing lockfile yields an empty `servers` list — the YAML / JSON
/// scaffold is still emitted, with `lockfile_present: false`, so the
/// operator sees the structure even before they run `mcp lock`.
///
/// **Deduplication.** A lockfile sorts servers by `(name, source_config)`,
/// so the same name can legitimately appear twice in different configs
/// (e.g. `.mcp.json` and `.vscode/mcp.json`). The scaffold's
/// `trusted_mcp_servers` entry is a `name` only — keying off name alone
/// would emit the same name twice. The body keeps the per-config detail
/// for `mcp_allowed_tools` (one tools-list per server entry, even when
/// names repeat), but the trusted-servers commented list deduplicates by
/// name so the YAML is operator-friendly.
fn build_policy_scaffold(lockfile: Option<&McpLockfile>) -> PolicyScaffold {
    match lockfile {
        Some(lock) => PolicyScaffold {
            lockfile_present: true,
            servers: lock
                .servers
                .iter()
                .map(|s| PolicyScaffoldServer {
                    name: s.name.clone(),
                    source_config: s.source_config.clone(),
                    tools: s.tools.clone(),
                })
                .collect(),
        },
        None => PolicyScaffold {
            lockfile_present: false,
            servers: Vec::new(),
        },
    }
}

/// Render the scaffold to its YAML on-disk form.
///
/// Every server's entry is **commented out** with `#` so importing the
/// example into a working `policy.yaml` does not silently widen the
/// operator's trust set — they must uncomment what they intend to trust.
/// This matches `tirith policy init`'s convention: defaults are
/// commented; the operator opts in.
///
/// Determinism: the lockfile is already sorted, so two invocations against
/// the same lockfile produce the same bytes. A trailing newline is always
/// emitted.
fn render_policy_scaffold_yaml(scaffold: &PolicyScaffold) -> String {
    // Header — explains what the file is, how to use it, and (critically)
    // that the entries are commented out by design.
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

    // `trusted_mcp_servers`: deduplicate by name, since the same server
    // name can legitimately appear in two different source configs.
    let mut seen_names: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    s.push_str("  # Server names that are trusted: every per-server MCP config\n");
    s.push_str("  # finding (insecure URL, raw IP, suspicious args, wildcard tools,\n");
    s.push_str("  # duplicate name) is suppressed for these, and drift on them does\n");
    s.push_str("  # NOT raise the `mcp_server_drift` finding. Uncomment the names\n");
    s.push_str("  # whose surface you have reviewed and accepted.\n");
    s.push_str("  # trusted_mcp_servers:\n");
    for server in &scaffold.servers {
        if seen_names.insert(server.name.as_str()) {
            s.push_str(&format!(
                "  #   - {}    # from {}\n",
                yaml_safe_scalar(&server.name),
                yaml_safe_inline_comment(&server.source_config),
            ));
        }
    }

    // `mcp_allowed_tools`: per-server tool allow-list. Emit one entry per
    // server (keyed by name); when the same name appears twice with
    // different tool lists, prefer the union for the scaffold so the
    // operator sees every tool the lockfile records.
    s.push('\n');
    s.push_str("  # Per-server allowed tools. The keys are MCP server names; the\n");
    s.push_str("  # values are the tools the server may expose. A tool the lockfile\n");
    s.push_str("  # records that is NOT in this set surfaces a finding (`mcp_server_drift`,\n");
    s.push_str("  # severity High). Drift that adds a tool outside the set upgrades\n");
    s.push_str("  # the drift finding from Medium to High. A server not listed here\n");
    s.push_str("  # is unconstrained — the gate is opt-in.\n");
    s.push_str("  # mcp_allowed_tools:\n");

    let mut name_to_tools: std::collections::BTreeMap<&str, std::collections::BTreeSet<&str>> =
        std::collections::BTreeMap::new();
    let mut name_to_first_source: std::collections::BTreeMap<&str, &str> =
        std::collections::BTreeMap::new();
    for server in &scaffold.servers {
        let entry = name_to_tools.entry(server.name.as_str()).or_default();
        for t in &server.tools {
            entry.insert(t.as_str());
        }
        name_to_first_source
            .entry(server.name.as_str())
            .or_insert(server.source_config.as_str());
    }
    for (name, tools) in &name_to_tools {
        let source = name_to_first_source.get(name).copied().unwrap_or("");
        if tools.is_empty() {
            s.push_str(&format!(
                "  #   {}: []    # from {} — no tools declared\n",
                yaml_safe_scalar(name),
                yaml_safe_inline_comment(source),
            ));
        } else {
            s.push_str(&format!(
                "  #   {}:    # from {}\n",
                yaml_safe_scalar(name),
                yaml_safe_inline_comment(source),
            ));
            for tool in tools {
                s.push_str(&format!("  #     - {}\n", yaml_safe_scalar(tool)));
            }
        }
    }

    s
}

// M4 item 8 chunk 3 — the YAML safety helpers (`yaml_safe_scalar`,
// `yaml_safe_inline_comment`, `YAML_NEEDS_QUOTING_BYTES`) used to live as
// two byte-identical copies in this file and `cli/agent.rs`. They are now
// centralized in `crate::cli::yaml`. The thin aliases below preserve the
// original names so the round-trip tests at the bottom of this module
// (which form the most thorough round-trip suite in the repo) keep
// reading naturally without renaming every reference.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use tirith_core::mcp_lock::{McpEnvEntry, McpTransport};

    #[test]
    fn describe_transport_renders_each_variant() {
        // URL / command / args are debug-escaped through `escape_name`, so the
        // human-summary string is the Debug-quoted form. Costless for well-
        // formed inputs (they round-trip with surrounding quotes) and the
        // principled default for any future code path that introduces an
        // attacker-controllable transport string.
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
        // A stdio server with env: the variable NAMES are shown (debug-escaped
        // so a control byte inside a name cannot reach the terminal); raw
        // values are not stored anywhere, much less printed.
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
        // A redacted URL whose source declared credentials prints with a
        // fixed `(credentials in source URL)` annotation so the operator
        // can see the redaction fired — without revealing the credential
        // itself (which has been stripped from `url` and only a salted
        // hash remains).
        assert_eq!(
            describe_transport(&McpTransport::Url {
                url: "https://mcp.example.com/sse".into(),
                userinfo_hash: Some("deadbeef".into()),
            }),
            r#"url "https://mcp.example.com/sse" (credentials in source URL)"#
        );
        // The annotation MUST NOT contain the hash itself — the print
        // surface is for the human, the hash is a wire-format detail.
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
        // Finding F: a maliciously-crafted env name containing ANSI escapes /
        // newlines / control bytes must NOT inject raw control bytes into the
        // operator's terminal. Debug formatting renders them as `\u{1b}`,
        // `\n`, etc.
        let env = vec![
            // ANSI red — would colourize subsequent terminal output if printed raw.
            McpEnvEntry::from_raw("\x1b[31mREDNAME", "ignored"),
            // Multiline name — a raw print would split the summary across lines.
            McpEnvEntry::from_raw("MULTI\nLINE", "ignored"),
            // Carriage return — terminals would overwrite the current line.
            McpEnvEntry::from_raw("OVERWRITE\rATTACK", "ignored"),
            // Backspace — would erase preceding characters in the rendering.
            McpEnvEntry::from_raw("ERASE\x08", "ignored"),
        ];
        let out = describe_transport(&McpTransport::Stdio {
            command: "node".into(),
            args: vec![],
            env,
        });

        // No raw control byte may appear in the output. Iterating chars rather
        // than bytes is fine — every control codepoint is one ASCII byte.
        for ch in out.chars() {
            assert!(
                !ch.is_control(),
                "raw control char {:?} (U+{:04X}) leaked into the env-name summary: {out:?}",
                ch,
                ch as u32,
            );
        }
        // And the escaped forms ARE present — proving the names did reach the
        // formatter, they just went through Debug escaping.
        for needle in [r"\u{1b}", r"\n", r"\r", r"\u{8}"] {
            assert!(
                out.contains(needle),
                "expected escaped form {needle} in env-name summary: {out:?}"
            );
        }
    }

    #[test]
    fn describe_transport_escapes_control_bytes_in_transport_fields() {
        // CodeRabbit follow-up: the URL, command, and args fields all
        // originate from `.mcp.json` and must be debug-escaped before
        // reaching the terminal. The pre-fix code emitted them verbatim,
        // letting ANSI / CR / BEL bytes carried in a hostile config rewrite
        // the operator's rendering. Every transport-derived string now
        // goes through `escape_name` (Debug formatting).
        //
        // URL variant: ANSI red embedded in the (already userinfo-stripped)
        // URL would colourize every subsequent terminal byte if printed raw.
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

        // Stdio command + args: CR in command and BEL/newline in args. None
        // may reach the terminal raw.
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
        // CodeRabbit cid 3292118208: a hostile `RejectedConfig::path`
        // carrying ANSI escapes / newlines / control bytes must NOT inject
        // raw bytes into the operator's terminal when `tirith mcp lock`
        // renders the human-readable "rejected configs" note. Same
        // convention the env-name printer (`describe_transport`) and the
        // server/tool-name printer (`escape_name`) already apply: Debug
        // formatting renders every control byte as `\u{NN}` / `\n` / `\r` /
        // etc. and quotes the value, so no raw byte reaches stderr.
        let rejected = vec![
            // ANSI red — would colourize subsequent terminal output if
            // printed raw.
            mcp_lock::RejectedConfig {
                path: "\x1b[31mhostile-red.json".to_string(),
                reason: mcp_lock::RejectedReason::Symlink,
            },
            // Multiline path — a raw print would split the summary across
            // lines and let the second line masquerade as a different
            // diagnostic.
            mcp_lock::RejectedConfig {
                path: "multi\nline.json".to_string(),
                reason: mcp_lock::RejectedReason::NotRegularFile,
            },
            // Carriage return — terminals would overwrite the current line.
            mcp_lock::RejectedConfig {
                path: "overwrite\rattack.json".to_string(),
                reason: mcp_lock::RejectedReason::OutsideRepo,
            },
            // Backspace — would erase preceding characters in the
            // rendering.
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

        // No raw control byte may appear in any rendered line. Iterating
        // chars is fine — every control codepoint is one ASCII byte and a
        // valid char.
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

        // And the escaped forms ARE present — proving the path did reach
        // the formatter, it just went through Debug escaping. (The form
        // `r"\u{1b}"` is the literal four-char sequence Rust's Debug
        // produces for `\x1b`; same convention as the env-name test.)
        let joined = lines.join("\n");
        for needle in [r"\u{1b}", r"\n", r"\r", r"\u{8}"] {
            assert!(
                joined.contains(needle),
                "expected escaped form {needle} in rejected-config lines: \
                 {lines:?}"
            );
        }
    }

    #[test]
    fn write_lockfile_creates_tirith_dir_and_file() {
        let repo = tempdir().unwrap();
        let lock_path = repo.path().join(".tirith").join(MCP_LOCK_FILENAME);
        let inventory = mcp_lock::build_inventory(repo.path());
        let lockfile = McpLockfile::from_inventory(&inventory);

        write_lockfile(&lock_path, &lockfile).expect("write should succeed");
        assert!(lock_path.is_file(), ".tirith/mcp.lock must exist");

        let contents = fs::read_to_string(&lock_path).unwrap();
        // Round-trips back to the same lockfile.
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

        write_lockfile(&lock_path, &lockfile).unwrap();
        let first = fs::read_to_string(&lock_path).unwrap();
        write_lockfile(&lock_path, &lockfile).unwrap();
        let second = fs::read_to_string(&lock_path).unwrap();
        assert_eq!(first, second, "re-writing an unchanged lockfile is stable");
    }

    // -----------------------------------------------------------------------
    // Chunk 2 — `tirith mcp verify` / `tirith mcp diff` integration tests.
    //
    // These drive the `*_for_root` helpers against tempdir layouts so each
    // test is fully isolated and the env-var-mutating production
    // `resolve_repo_root` is not exercised here (it is covered by the
    // existing `lock` tests).
    // -----------------------------------------------------------------------

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
        write_lockfile(&lock_path, &lockfile).expect("write");
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
        // Add a new server to the config — now the inventory has drifted.
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
    fn verify_exits_one_when_env_value_rotated() {
        // Snapshot one server with an env value, then rotate the value in
        // the config: the env value-hash flips, drift fires, exit 1.
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
        )
        .unwrap();

        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "s": { "command": "node",
                "env": { "API_TOKEN": "new" } } } }"#,
        )
        .unwrap();
        let code = verify_for_root(repo.path(), false);
        assert_eq!(code, 1, "rotated env → drift → exit 1");
    }

    #[test]
    fn verify_exits_two_when_lockfile_missing() {
        // No `.tirith/mcp.lock` at all — that is a usage error, not drift.
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
        // JSON path must not regress the exit-code contract.
        let repo = repo_with_locked_mcp();
        let code = verify_for_root(repo.path(), true);
        assert_eq!(code, 0);
    }

    #[test]
    fn diff_always_exits_zero_even_when_drift_present() {
        let repo = repo_with_locked_mcp();
        // Drift the inventory.
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
        // Even for the informational verb, no-lockfile is a usage error so
        // a piped consumer can distinguish "no drift" from "nothing to diff".
        let repo = tempdir().unwrap();
        let code = diff_for_root(repo.path(), false);
        assert_eq!(code, 2);
    }

    #[test]
    fn escape_name_renders_control_bytes_safely() {
        // A server / env / tool name carrying a control byte must NOT
        // inject raw bytes into the operator's terminal — debug formatting
        // escapes them.
        let escaped = escape_name("\x1b[31mEVIL");
        assert!(!escaped.contains('\x1b'), "raw ESC must not survive");
        assert!(escaped.contains("\\u{1b}"));
    }

    // -----------------------------------------------------------------------
    // Chunk 3 — `tirith mcp policy init` scaffolding.
    // -----------------------------------------------------------------------

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
        write_lockfile(&lock_path, &lockfile).expect("write");
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
        // The server name and the tool names appear in the scaffold.
        assert!(body.contains("fs"), "server name must appear: {body}");
        assert!(body.contains("read_file"), "tool name must appear: {body}");
        assert!(body.contains("write_file"), "tool name must appear: {body}");
        // And every entry is commented out by design.
        for needle in ["- fs", "fs:"] {
            // Either appears, but only as a commented form (preceded by `#`).
            let lines: Vec<&str> = body
                .lines()
                .filter(|l| l.contains(needle) && !l.trim_start().starts_with('#'))
                .collect();
            assert!(
                lines.is_empty(),
                "an uncommented `{needle}` slipped into the scaffold: {lines:?}",
            );
        }
        // Includes the documentation header.
        assert!(body.contains("Tirith MCP policy scaffold"));
        assert!(body.contains("scan:"));
        assert!(body.contains("trusted_mcp_servers"));
        assert!(body.contains("mcp_allowed_tools"));
    }

    #[test]
    fn policy_init_is_deterministic_for_same_lockfile() {
        // Running policy_init twice against the same lockfile produces a
        // byte-identical example file. --force lets us regenerate without
        // pre-deleting.
        let repo = repo_with_locked_server_and_tools();
        let code = policy_init_for_root(repo.path(), false, false);
        assert_eq!(code, 0);
        let example_path = repo.path().join(".tirith").join("mcp-policy.yaml.example");
        let first = fs::read_to_string(&example_path).unwrap();

        let code = policy_init_for_root(repo.path(), false, true); // force overwrite
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
        // Second run without --force should fail with exit 1.
        let code = policy_init_for_root(repo.path(), false, false);
        assert_eq!(
            code, 1,
            "second policy_init without --force must refuse to overwrite",
        );
        // The example file is still the FIRST one (we didn't overwrite).
        let example_path = repo.path().join(".tirith").join("mcp-policy.yaml.example");
        assert!(example_path.is_file());
    }

    #[test]
    fn policy_init_overwrites_with_force() {
        let repo = repo_with_locked_server_and_tools();
        let example_path = repo.path().join(".tirith").join("mcp-policy.yaml.example");
        // Pre-create a sentinel that policy_init must overwrite.
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
        // No .tirith/mcp.lock — policy_init still writes a header-only
        // scaffold (the operator gets a starting point) and exits 0.
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
        // No server entries.
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
        // A lockfile that was generated against a repo with no MCP configs
        // (or all-empty MCP configs) lists zero servers. The scaffold
        // emits a template form rather than nothing — the operator still
        // gets to see what they would fill in.
        let repo = tempdir().unwrap();
        let inventory = mcp_lock::build_inventory(repo.path());
        let lockfile = McpLockfile::from_inventory(&inventory);
        let lock_path = repo.path().join(".tirith").join(MCP_LOCK_FILENAME);
        write_lockfile(&lock_path, &lockfile).unwrap();
        let code = policy_init_for_root(repo.path(), false, false);
        assert_eq!(code, 0);
        let body = fs::read_to_string(repo.path().join(".tirith").join("mcp-policy.yaml.example"))
            .unwrap();
        assert!(
            body.contains("The lockfile recorded no MCP servers"),
            "scaffold should explain the empty case and emit a template: {body}",
        );
        // The template uses an "example-server" name so the operator sees
        // the shape they should fill in.
        assert!(body.contains("example-server"));
    }

    #[test]
    fn policy_init_redacts_hostile_server_name() {
        // A server name carrying ANSI escape / newline / backspace must
        // NOT inject raw bytes into the example file (which would in turn
        // inject when the operator `cat`s the file). yaml_safe_scalar
        // quotes-and-escapes them.
        let repo = tempdir().unwrap();
        // Manually build a lockfile with a hostile name (bypass the
        // JSON parser, which would also accept escapes).
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
        write_lockfile(&lock_path, &lockfile).unwrap();

        let code = policy_init_for_root(repo.path(), false, false);
        assert_eq!(code, 0);
        let body = fs::read_to_string(repo.path().join(".tirith").join("mcp-policy.yaml.example"))
            .unwrap();
        // No raw ESC, BS, or unescaped newline-in-a-token. (Newlines as
        // line separators are fine — we check character context.)
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
        // The file is still on disk.
        let example_path = repo.path().join(".tirith").join("mcp-policy.yaml.example");
        assert!(example_path.is_file());
    }

    #[test]
    fn build_policy_scaffold_dedups_repeated_server_names_in_yaml() {
        // Two distinct lockfile entries for the same server name (a
        // legal lockfile state) must not produce two `- name` lines in
        // the `trusted_mcp_servers` block — that would be confusing
        // duplication for the operator.
        let scaffold = PolicyScaffold {
            lockfile_present: true,
            servers: vec![
                PolicyScaffoldServer {
                    name: "dup".to_string(),
                    source_config: ".mcp.json".to_string(),
                    tools: vec!["a".to_string()],
                },
                PolicyScaffoldServer {
                    name: "dup".to_string(),
                    source_config: ".vscode/mcp.json".to_string(),
                    tools: vec!["b".to_string()],
                },
            ],
        };
        let yaml = render_policy_scaffold_yaml(&scaffold);
        // Count the lines that look like `#   - dup` (a trusted-servers entry).
        let trust_lines: Vec<&str> = yaml
            .lines()
            .filter(|l| l.trim_start().starts_with("#   - dup"))
            .collect();
        assert_eq!(
            trust_lines.len(),
            1,
            "duplicate server name should appear once in trusted_mcp_servers: \
             got {trust_lines:?}",
        );
        // And the mcp_allowed_tools block lists the UNION of tools across both entries.
        assert!(yaml.contains("- a"));
        assert!(yaml.contains("- b"));
    }

    // -----------------------------------------------------------------------
    // Wave-end finding F2 — `verify`'s JSON-write failure must NOT collapse
    // the drift exit code (1) into a usage error (2). Pin the truth table
    // for `verify_exit_code`.
    // -----------------------------------------------------------------------

    #[test]
    fn verify_exit_code_drift_with_json_write_failure_preserves_drift() {
        // The bug fix: drift detected AND json write failed → 1, not 2.
        assert_eq!(
            verify_exit_code(false, false),
            1,
            "drift must remain exit 1 even when JSON write failed",
        );
    }

    #[test]
    fn verify_exit_code_no_drift_with_json_write_failure_is_usage_error() {
        // Without drift, the only signal the consumer would see is the
        // JSON payload, which is broken. Surface as usage-class failure.
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

    // -----------------------------------------------------------------------
    // Wave-end finding F17 — `yaml_safe_scalar` is byte-identical after
    // collapsing the indicator-set check into a constant. Spot-check the
    // boundaries: every indicator byte forces quoting, every safe byte
    // does not.
    // -----------------------------------------------------------------------

    #[test]
    fn yaml_safe_scalar_quotes_every_indicator_byte() {
        // Every byte in the centralized indicator list must force quoting
        // (the scalar comes back as a `"..."` quoted form, not bare).
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
        // Plain ASCII identifiers: must come back unmodified.
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
        // Control bytes are NOT in YAML_NEEDS_QUOTING_BYTES (they're
        // checked separately) — but they still force quoting.
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

    // -----------------------------------------------------------------------
    // Wave-end finding F13 (PRT CG-2) — the YAML scaffold output is never
    // parsed back in the existing tests, so a render-side bug that produced
    // structurally-broken YAML for a hostile name would be invisible. Pin
    // the contract: a scaffold rendered for a hostile name parses cleanly
    // through `serde_yaml`, and `yaml_safe_scalar`'s output for every YAML
    // special character round-trips byte-for-byte through a real YAML parser.
    // -----------------------------------------------------------------------

    #[test]
    fn policy_init_scaffold_yaml_parses_after_uncomment() {
        // A scaffold rendered for a server name carrying ANSI escapes /
        // newlines / control bytes (a hostile-but-legal name a config might
        // declare or a round-trip from an attacker-controlled source) must
        // produce structurally-valid YAML even after the operator uncomments
        // the `trusted_mcp_servers` block. `yaml_safe_scalar` is what
        // guarantees this — every special character is quoted-and-escaped —
        // and this test pins the contract by actually parsing the rendered
        // bytes back through `serde_yaml`.
        let hostile = "ev\u{1b}[31mil\nname";

        let scaffold = PolicyScaffold {
            lockfile_present: true,
            servers: vec![PolicyScaffoldServer {
                name: hostile.to_string(),
                source_config: ".mcp.json".to_string(),
                tools: vec!["read".to_string()],
            }],
        };
        let body = render_policy_scaffold_yaml(&scaffold);

        // Programmatically uncomment the `trusted_mcp_servers:` header and
        // its single list entry. The block looks like:
        //
        //   # trusted_mcp_servers:
        //   #   - "ev\u{1b}[31mil\nname"    # from .mcp.json
        //
        // We turn `\n  # trusted_mcp_servers:` into `\n  trusted_mcp_servers:`
        // (matching the render's two-space indent and the leading newline so
        // we only ever match the canonical site), then uncomment each list
        // entry directly underneath.
        let uncommented_header =
            body.replace("\n  # trusted_mcp_servers:", "\n  trusted_mcp_servers:");
        // The list-entry lines start with `  #   - ` (two-space indent +
        // `#   - ` per render). Strip the `#   ` prefix so the entry is
        // a real list item under the now-uncommented key.
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

        // The uncommented YAML must parse.
        let parsed: serde_yaml::Value = serde_yaml::from_str(&uncommented).unwrap_or_else(|e| {
            panic!(
                "scaffold YAML must parse cleanly after uncommenting:\nerror: {e}\nbody:\n{uncommented}"
            )
        });

        // And the loaded server name must byte-equal the hostile input — no
        // characters lost, no escapes leaking through as literal `\u{1b}`
        // text instead of the real ESC byte.
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
        // Table-driven: every YAML special character, every control-byte
        // class that round-trips through a YAML parser, plus multi-byte
        // UTF-8 and the empty string. For each input, feed
        // `yaml_safe_scalar`'s output into a one-key YAML document, parse
        // it, and assert the parser recovers the exact input byte-for-byte.
        //
        // **Known gap (production):** `yaml_safe_scalar` calls
        // `serde_json::to_string`, which does NOT escape DEL (`\x7f`) —
        // JSON treats it as printable, but YAML 1.2 §5.7 disallows it
        // inside a double-quoted scalar. The dedicated
        // `yaml_safe_scalar_does_not_round_trip_del_documents_known_gap`
        // test below pins that asymmetry so a future production-code fix
        // (escape DEL alongside the < 0x20 control bytes) has a regression
        // test ready to flip green.
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
        // Documents the production-code gap surfaced while landing F13:
        // `yaml_safe_scalar` uses `serde_json::to_string`, which (per the
        // JSON spec) emits DEL (`\x7f`) as the raw byte rather than a
        // `` escape. YAML 1.2 §5.7 disallows DEL inside a
        // double-quoted scalar, so the round-trip fails. The output is
        // still quoted (the `quotes_control_bytes` test pins that) — it
        // just isn't parseable.
        //
        // The fix is a one-line change in `yaml_safe_scalar` (post-process
        // the JSON output to escape DEL as `` before returning), but
        // it's behavior outside the scope of batch B (tests-only). When a
        // future production-code fix lands, this test should flip green
        // (the parse should succeed and recover DEL) — `assert!(parsed.is_err())`
        // is what makes that pivot explicit.
        let scalar = yaml_safe_scalar("\x7f");
        // The output is still quoted (forces quoting via the control-byte
        // check), proving the safety-quoting rule fires — the gap is only
        // about the escape, not the quoting.
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

    // -----------------------------------------------------------------------
    // PR #121 item 17 — `format_inventory_server_line` debug-escapes
    // both the server name and the source_config path so a hostile
    // `.mcp.json` cannot smuggle ANSI / CR / BEL / control bytes through
    // the inventory printer. Adjacent printers in this file already
    // followed this discipline; this site was missed.
    // -----------------------------------------------------------------------

    #[test]
    fn format_inventory_server_line_escapes_ansi_in_name_and_source() {
        // Server name carries an ANSI red-foreground sequence. A raw
        // print would recolour every subsequent terminal byte until the
        // next ANSI reset.
        let server = mcp_lock::McpServerEntry {
            name: "evil\x1b[31m".into(),
            transport: mcp_lock::McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![],
            },
            tools: vec!["read".into()],
            tools_declared: true,
            // Source config path with a CR + BEL — a raw print would
            // overwrite the line and beep at the operator.
            source_config: "hostile\rpath\x07.mcp.json".into(),
        };
        let line = format_inventory_server_line(&server);
        // No raw ESC byte must reach the printer's output.
        assert!(
            !line.chars().any(|c| c == '\x1b'),
            "raw ESC byte must NOT appear in formatted line: {line:?}",
        );
        // No raw CR or BEL either.
        assert!(
            !line.chars().any(|c| c == '\r'),
            "raw CR byte must NOT appear in formatted line: {line:?}",
        );
        assert!(
            !line.chars().any(|c| c == '\x07'),
            "raw BEL byte must NOT appear in formatted line: {line:?}",
        );
        // The escaped form should be visible — `escape_name` and
        // Debug-format both render control bytes as `\u{NN}` / `\x...`
        // escapes.
        assert!(
            line.contains("evil"),
            "the legible portion of the name should still appear: {line}",
        );
        assert!(
            line.contains("hostile"),
            "the legible portion of source_config should still appear: {line}",
        );
    }

    // -----------------------------------------------------------------------
    // PR #121 CR follow-up — `format_inventory_server_line` distinguishes
    // the three tools states (omitted / declared empty / declared with N
    // entries). The pre-fix renderer collapsed "omitted" and "explicit
    // empty" into the same string, which hid a real policy ambiguity:
    // "tools omitted" means the runtime may surface any tool the server
    // exposes, while `"tools": []` is an explicit zero-tool allowlist.
    // The lockfile already captures the distinction via the
    // `tools_declared` bool; the printer now branches on it.
    // -----------------------------------------------------------------------

    #[test]
    fn format_inventory_server_line_distinguishes_tools_states() {
        let base_transport = mcp_lock::McpTransport::Stdio {
            command: "node".into(),
            args: vec![],
            env: vec![],
        };
        // State 1: tools omitted in the source config — runtime may expose
        // any tool the server defines.
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

        // State 2: tools explicitly declared as `[]` — zero-tool allowlist.
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

        // State 3: tools declared with N entries — normal case, count is shown.
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

    // -----------------------------------------------------------------------
    // PR #121 item 16 — `format_rejected_config_lines` is reachable
    // (and rendered) even when the inventory is otherwise empty. The
    // helper is already covered by `format_rejected_config_lines_*`
    // tests above; this test asserts that an inventory carrying ONLY
    // rejected_configs (no servers, no parseable configs) still
    // produces a non-empty rejected-config render — pinning the
    // contract that the early-return branch of `print_human` is no
    // longer the only consumer.
    // -----------------------------------------------------------------------

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
