//! `tirith mcp lock` — generate `.tirith/mcp.lock` from a repository's MCP
//! configuration.
//!
//! This is the first command in the Milestone 4 (Agent & MCP governance) `mcp`
//! subcommand group. It captures a deterministic inventory of every MCP server
//! the repository declares — across `.mcp.json` and the IDE config variants —
//! into a lockfile at `<repo_root>/.tirith/mcp.lock`. A later `mcp verify` /
//! `mcp diff` (not yet implemented) will diff a live inventory against this
//! committed lockfile to detect drift.
//!
//! It is a **local file operation**: it touches no network, and it is entirely
//! off the tier-1/2/3 detection hot path. `mcp lock` writes one file
//! (`mcp.lock`) and reads the repo's MCP configs — nothing else.

use std::path::{Path, PathBuf};

use tirith_core::mcp_lock::{self, McpInventory, McpLockfile, MCP_LOCK_FILENAME};
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
/// Honors `TIRITH_POLICY_ROOT` first (so a test, or a deliberate override, can
/// pin the root without a `.git`), then falls back to the `.git`-boundary
/// walk-up from the current directory — the exact resolution `tirith policy`
/// and `.tirith/trust.json` use, so `mcp.lock` lands beside `policy.yaml`.
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
            let transport = describe_transport(&server.transport);
            let tools = if server.tools.is_empty() {
                "all tools (none declared)".to_string()
            } else {
                format!("{} tool(s)", server.tools.len())
            };
            eprintln!(
                "    - {} [{}] — {} — from {}",
                server.name, transport, tools, server.source_config,
            );
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

    eprintln!();
    eprintln!("  wrote {}", lock_path.display());
    println!("{}", lock_path.display());
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
/// control byte as a `\xNN` / `\n` / `\r` / etc. and quotes the value — the
/// simplest correct fix, applied at *every* env-name print site.
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
            // any, has been replaced with a salted hash); print it verbatim.
            // When `userinfo_hash` is Some, append a fixed phrase so the
            // operator can see that the source declared a credential —
            // never the credential itself.
            if userinfo_hash.is_some() {
                format!("url {url} (credentials in source URL)")
            } else {
                format!("url {url}")
            }
        }
        mcp_lock::McpTransport::Stdio { command, args, env } => {
            let mut desc = if args.is_empty() {
                format!("stdio {command}")
            } else {
                format!("stdio {} {}", command, args.join(" "))
            };
            if !env.is_empty() {
                // Debug-format each name so control bytes (ANSI escapes,
                // newlines, …) are rendered as `\xNN` literals rather than
                // reaching the terminal. Names appear quoted, which is fine
                // for the human summary and the test snapshot.
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
    if json {
        #[derive(serde::Serialize)]
        struct ErrOut<'a> {
            schema_version: u32,
            error: &'a str,
        }
        // A best-effort error envelope; the exit code (1) is the source of
        // truth, so a failure to even print this is not separately handled.
        let _ = super::write_json_stdout(
            &ErrOut {
                schema_version: 1,
                error: message,
            },
            "tirith mcp lock: failed to write JSON output",
        );
    } else {
        eprintln!("tirith mcp lock: {message}");
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
        assert_eq!(
            describe_transport(&McpTransport::Url {
                url: "https://x.example".into(),
                userinfo_hash: None,
            }),
            "url https://x.example"
        );
        assert_eq!(
            describe_transport(&McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![],
            }),
            "stdio node"
        );
        assert_eq!(
            describe_transport(&McpTransport::Stdio {
                command: "npx".into(),
                args: vec!["-y".into(), "server".into()],
                env: vec![],
            }),
            "stdio npx -y server"
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
            r#"stdio node (env: "API_TOKEN", "DEBUG")"#
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
            "url https://mcp.example.com/sse (credentials in source URL)"
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
}
