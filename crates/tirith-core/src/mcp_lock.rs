//! MCP server inventory and `.tirith/mcp.lock` lockfile generation.
//!
//! This module is the data layer behind `tirith mcp lock` (Milestone 4, Agent
//! & MCP governance). It does two things, both **local file operations off the
//! tier-1/2/3 detection hot path**:
//!
//! 1. **Inventory** ([`build_inventory`]) — given a repository root, discover
//!    the **repo-local** MCP configuration files (`mcp.json`, `.mcp.json`,
//!    `mcp_settings.json`, and the IDE variants under `.vscode/`, `.cursor/`,
//!    `.windsurf/`, `.cline/`, `.amazonq/`, `.continue/`, `.kiro/`) and parse
//!    each into a structured [`McpInventory`]: one [`McpServerEntry`] per
//!    declared MCP server, recording its name, transport descriptor, and the
//!    tool list it declares.
//!
//! 2. **Lockfile** ([`McpLockfile::from_inventory`] / [`McpLockfile::render`])
//!    — serialize that inventory into a deterministic JSON lockfile
//!    (`<repo_root>/.tirith/mcp.lock`): per server a canonical transport
//!    descriptor, the tool list, and a content hash; plus a format version and
//!    a hash over the whole inventory. [`McpLockfile::from_inventory`] sorts
//!    servers by `(name, source_config)` **before** hashing, so the lockfile
//!    and its `inventory_hash` are stable regardless of config-discovery
//!    order — a future `mcp verify` / `mcp diff` (chunk 2) can diff two
//!    lockfiles cleanly.
//!
//! **Repo-local only.** Discovery never walks into `~/.claude/` or any other
//! user-level configuration directory — only files inside the given repo root
//! are inventoried. This is the same scoping decision the policy system makes
//! with org-level lists. The guarantee is enforced, not merely structural: a
//! config path that is a symlink (or sits under a symlinked directory), or
//! whose canonicalized path escapes the repo root, is **rejected** — a
//! symlinked `.mcp.json` pointing at a user-level config is not read.
//!
//! **Malformed input is never fatal.** A configuration file that is not valid
//! JSON, or that does not carry an MCP-server object, contributes **no
//! entries** and never panics — the same "malformed → empty, no panic"
//! convention the rest of the codebase follows (see `configfile::check_mcp_*`).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Lockfile format version. Bump only on a breaking schema change so a future
/// `mcp verify` can refuse — or migrate — an older lockfile deliberately.
///
/// Version history:
/// * `1` — initial schema: per-server name, transport (`url`, or stdio
///   `command` + `args`), tools, source config, and content hash.
/// * `2` — a stdio transport now also captures the server's `env` (the
///   environment variables the config injects into the subprocess); `env` is
///   part of the per-server content hash, so an `env` change registers as
///   drift. A v1 lockfile is therefore not byte-comparable to a v2 one.
/// * `3` — env entries no longer serialize a raw value: each entry is
///   `{ name, value_hash }`, where `value_hash` is the lowercase-hex SHA-256
///   of `name || ':' || value`. An env value is commonly a credential
///   (`API_TOKEN`, `GITHUB_PERSONAL_ACCESS_TOKEN`, `OPENAI_API_KEY`, …), and
///   the lockfile is designed to be committed — persisting the value would
///   leak it. Hashing with the name as a salt still makes any value change
///   register as drift (the hash flips), so drift detection is unchanged in
///   spirit; only the *value* leaves the process, the hash does, and even a
///   low-entropy value (`1`, `true`) is not brute-forceable across servers
///   because the per-key salt makes the digest unique to (name, value). A v2
///   lockfile is therefore not byte-comparable to a v3 one.
pub const MCP_LOCK_FORMAT_VERSION: u32 = 3;

/// Basename of the lockfile, written under `<repo_root>/.tirith/`.
pub const MCP_LOCK_FILENAME: &str = "mcp.lock";

/// One environment variable a stdio MCP server is launched with, as captured
/// in the lockfile.
///
/// **The raw value is never stored.** An env value is commonly a credential
/// (`API_TOKEN`, `GITHUB_PERSONAL_ACCESS_TOKEN`, `OPENAI_API_KEY`, …) and the
/// lockfile is designed to be committed — persisting plaintext values would
/// leak secrets into version control. Instead, we record a fixed-output hash:
/// `value_hash = sha256(name || ':' || value)`. The name is the per-entry salt
/// — a low-entropy value (`1`, `true`, `production`) hashes differently under
/// each name, so a digest cannot be brute-forced once and reused across
/// servers / configs. Drift detection is unchanged in spirit: a swapped value
/// still flips `value_hash`, which still flips the per-server content hash.
///
/// Computed exactly once in [`parse_env`]; the raw value never leaves that
/// function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpEnvEntry {
    /// The environment variable's name (the key in the config's `env` object).
    pub name: String,
    /// Lowercase-hex SHA-256 of `name || ':' || value`. The colon is a fixed
    /// delimiter so an attacker cannot manufacture two `(name, value)` pairs
    /// whose concatenations collide: e.g. `("AB", "c")` hashes `"AB:c"`, not
    /// `"ABc"`, so it cannot collide with `("A", "Bc")` which hashes `"A:Bc"`.
    pub value_hash: String,
}

impl McpEnvEntry {
    /// Build an entry from a `(name, raw_value)` pair, hashing the value
    /// immediately. This is the **only** legitimate way to construct an entry
    /// from a real value, and the raw value is consumed and dropped before the
    /// function returns — it never reaches a struct field, the serializer, or
    /// the rest of the process.
    pub fn from_raw(name: &str, raw_value: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        // A fixed `:` delimiter — never legal inside an env variable name on
        // POSIX or Windows — so `(name, value)` cannot be ambiguously framed.
        hasher.update(b":");
        hasher.update(raw_value.as_bytes());
        let value_hash = hex_lower(&hasher.finalize());
        McpEnvEntry {
            name: name.to_string(),
            value_hash,
        }
    }
}

/// How an MCP server is reached. A server declares **either** a remote URL
/// (`url` transport) **or** a local subprocess (`command` + `args`); the two
/// are mutually exclusive in every known config shape, so this is an enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpTransport {
    /// A network-reachable MCP server (HTTP / SSE / streamable-HTTP). The `url`
    /// is stored verbatim — canonicalization (if any) is the diff layer's job.
    Url { url: String },
    /// A local MCP server spawned as a subprocess.
    Stdio {
        /// The executable to run.
        command: String,
        /// Arguments passed to the executable, in declared order.
        #[serde(default)]
        args: Vec<String>,
        /// Environment variables the config injects into the subprocess, as
        /// `(name, value_hash)` entries sorted by name. Security-relevant: a
        /// change to a server's `env` (a swapped credential, an added variable
        /// that alters what the server does) must register as drift, so it is
        /// part of the inventory, the lockfile schema, and the per-server
        /// hash. **Raw values are never stored** — each entry carries only a
        /// salted hash; see [`McpEnvEntry`]. An empty vec means the config
        /// declared no `env` object.
        #[serde(default)]
        env: Vec<McpEnvEntry>,
    },
    /// The server object declared neither a `url` nor a `command`. Captured
    /// rather than dropped: an MCP entry with no transport is itself a
    /// finding-worthy oddity that a later `mcp verify` should be able to see.
    Unknown,
}

/// One MCP server as declared in a repository's MCP configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerEntry {
    /// The server's declared name (the key in the `mcpServers` / `servers`
    /// object).
    pub name: String,
    /// How the server is reached.
    pub transport: McpTransport,
    /// The tools the server declares, sorted and de-duplicated for a stable
    /// hash. An empty vec means the config declared no explicit tool list
    /// (which an MCP client treats as "all tools").
    pub tools: Vec<String>,
    /// Repo-relative path of the config file this entry was parsed from.
    pub source_config: String,
}

impl McpServerEntry {
    /// A stable per-server content hash over name + transport (including a
    /// stdio server's `env`) + tools. Two entries hash identically iff they
    /// declare the same server the same way, so a future `mcp diff` can detect
    /// a changed server by hash alone.
    ///
    /// `source_config` is deliberately **excluded**: moving an unchanged server
    /// definition between two config files must not register as drift.
    ///
    /// **Collision-free framing.** Every variable-length component (each arg,
    /// each tool, each `env` name/value) is *length-prefixed* — its byte length
    /// is written before its bytes via [`hash_field`] — rather than joined by a
    /// `\0` separator. A separator-only scheme is ambiguous: `["a", "b"]` and
    /// `["ab"]` would feed the hasher the same bytes, and a value that itself
    /// contains a `\0` could forge a boundary. Length-prefixing makes the byte
    /// stream an unambiguous encoding of the structure.
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"mcp-server-v2\0");
        hash_field(&mut hasher, self.name.as_bytes());
        match &self.transport {
            McpTransport::Url { url } => {
                hasher.update(b"url\0");
                hash_field(&mut hasher, url.as_bytes());
            }
            McpTransport::Stdio { command, args, env } => {
                hasher.update(b"stdio\0");
                hash_field(&mut hasher, command.as_bytes());
                hash_field(&mut hasher, &(args.len() as u64).to_le_bytes());
                for arg in args {
                    hash_field(&mut hasher, arg.as_bytes());
                }
                hash_field(&mut hasher, &(env.len() as u64).to_le_bytes());
                for entry in env {
                    // Each env entry feeds its name AND its value_hash into the
                    // per-server hash. The `value_hash` already deterministically
                    // depends on the raw value (via `name + ':' + value`), so any
                    // value change still flips the per-server content hash —
                    // drift detection is unchanged even though no raw value is
                    // stored or hashed here.
                    hash_field(&mut hasher, entry.name.as_bytes());
                    hash_field(&mut hasher, entry.value_hash.as_bytes());
                }
            }
            McpTransport::Unknown => {
                hasher.update(b"unknown\0");
            }
        }
        hash_field(&mut hasher, &(self.tools.len() as u64).to_le_bytes());
        for tool in &self.tools {
            hash_field(&mut hasher, tool.as_bytes());
        }
        hex_lower(&hasher.finalize())
    }
}

/// Feed one length-prefixed field into a hasher: the value's byte length as a
/// little-endian `u64`, then the value's bytes. Length-prefixing every
/// variable-length component makes the hash input an unambiguous encoding —
/// no list of values can collide with a different list, and a `\0` (or any
/// byte) inside a value can never be mistaken for a field boundary.
fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// The structured inventory of every MCP server declared in a repository.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct McpInventory {
    /// Every discovered server entry, sorted by `(name, source_config)`.
    pub servers: Vec<McpServerEntry>,
    /// Repo-relative paths of the MCP config files that were discovered (every
    /// file checked, including ones that yielded no server — so the caller can
    /// honestly report "N configs, M servers").
    pub configs: Vec<String>,
    /// Repo-relative paths of config files that were discovered but could not
    /// be parsed (not valid JSON, or no MCP-server object). Informational —
    /// these are NOT an error; they simply contribute no entries.
    pub malformed_configs: Vec<String>,
}

impl McpInventory {
    /// `true` when no MCP configuration was found at all. Distinct from "found
    /// configs but they declared zero servers" — the caller words its honest
    /// output differently for the two.
    pub fn is_empty(&self) -> bool {
        self.configs.is_empty()
    }
}

/// A single server record as it appears in the on-disk lockfile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpLockServer {
    /// Server name.
    pub name: String,
    /// Canonical transport descriptor.
    pub transport: McpTransport,
    /// Declared tool list (sorted, de-duplicated).
    pub tools: Vec<String>,
    /// Repo-relative path of the config file the server was declared in.
    pub source_config: String,
    /// Per-server content hash (see [`McpServerEntry::content_hash`]).
    pub hash: String,
}

/// The `.tirith/mcp.lock` document.
///
/// JSON, deterministically ordered (servers sorted by `(name, source_config)`),
/// so re-running `tirith mcp lock` on an unchanged repository produces a
/// byte-identical file and a `git diff` of the lockfile shows exactly what
/// changed in the MCP surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpLockfile {
    /// Lockfile schema version.
    pub format_version: u32,
    /// Hash over the whole inventory — the ordered concatenation of every
    /// server's content hash. Changes iff any server is added, removed, or
    /// altered. The cheap top-level "did anything change?" check for `mcp
    /// verify`.
    pub inventory_hash: String,
    /// Repo-relative paths of the MCP config files captured, sorted.
    pub configs: Vec<String>,
    /// Every locked MCP server, sorted by `(name, source_config)`.
    pub servers: Vec<McpLockServer>,
}

impl McpLockfile {
    /// Build a lockfile from an inventory. Pure and deterministic: the same
    /// inventory always yields the same lockfile — **regardless of the order
    /// the inventory's servers happen to be in**.
    ///
    /// `build_inventory` already sorts, but `from_inventory` is a public entry
    /// point that may be handed an inventory assembled by any means (a test, a
    /// future caller, a different discovery order), so the sort is repeated
    /// here and is the load-bearing one: servers are sorted by
    /// `(name, source_config)` **before** the inventory hash is computed, so
    /// both the lockfile and its `inventory_hash` are stable.
    pub fn from_inventory(inventory: &McpInventory) -> Self {
        let mut servers: Vec<McpLockServer> = inventory
            .servers
            .iter()
            .map(|entry| McpLockServer {
                name: entry.name.clone(),
                transport: entry.transport.clone(),
                tools: entry.tools.clone(),
                source_config: entry.source_config.clone(),
                hash: entry.content_hash(),
            })
            .collect();

        // Deterministic ordering — independent of config-discovery order — so
        // the lockfile and the inventory hash below are both stable. Must
        // happen before `compute_inventory_hash`, which hashes server order.
        servers.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.source_config.cmp(&b.source_config))
        });

        let inventory_hash = compute_inventory_hash(&servers);

        let mut configs = inventory.configs.clone();
        configs.sort();
        configs.dedup();

        McpLockfile {
            format_version: MCP_LOCK_FORMAT_VERSION,
            inventory_hash,
            configs,
            servers,
        }
    }

    /// Render the lockfile to its on-disk string form: pretty JSON with a
    /// trailing newline. Deterministic — the input ordering is already fixed
    /// by [`from_inventory`].
    pub fn render(&self) -> String {
        // serde_json::to_string_pretty cannot fail for this fully-owned,
        // string-keyed structure, but handle the Result rather than unwrap so
        // a future schema change can never panic the `mcp lock` command.
        match serde_json::to_string_pretty(self) {
            Ok(mut s) => {
                s.push('\n');
                s
            }
            Err(_) => "{}\n".to_string(),
        }
    }
}

/// Hash the ordered list of per-server content hashes into one inventory hash.
fn compute_inventory_hash(servers: &[McpLockServer]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"mcp-inventory-v1\0");
    for server in servers {
        hasher.update(server.hash.as_bytes());
        hasher.update(b"\0");
    }
    hex_lower(&hasher.finalize())
}

/// Lowercase hex encoding of a byte slice. Local helper — avoids pulling in the
/// `hex` crate for one call site.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String never fails.
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Repo-root-relative MCP config locations to probe.
///
/// Mirrors `configfile::is_mcp_config_file` exactly — the bare-root JSON files
/// plus the IDE host-directory variants. Kept as an explicit list (rather than
/// a filesystem walk) so discovery is bounded, fast, and never strays outside
/// the known MCP config surface.
const MCP_CONFIG_RELATIVE_PATHS: &[&str] = &[
    // Bare repo-root MCP configs.
    "mcp.json",
    ".mcp.json",
    "mcp_settings.json",
    // IDE host-directory variants.
    ".vscode/mcp.json",
    ".cursor/mcp.json",
    ".windsurf/mcp.json",
    ".cline/mcp_settings.json",
    ".amazonq/mcp.json",
    ".continue/mcp.json",
    ".kiro/settings/mcp.json",
];

/// Discover the repo-local MCP config files that exist under `repo_root`.
///
/// Returns `(absolute_path, repo_relative_path)` pairs, sorted by the relative
/// path for determinism. Only **regular files reachable without crossing a
/// symlink, and resolving to a location inside `repo_root`**, are returned.
///
/// Discovery is strictly repo-local. Every probed path is a fixed relative
/// path joined onto `repo_root`, so the *probed* path can never escape the
/// repository — but a probed path could itself **be** a symlink (or sit under
/// a symlinked parent directory) pointing outside the repo. Following that
/// would break the "repo-local only" guarantee — a malicious or careless
/// `.mcp.json -> ~/.claude/mcp.json` symlink would pull a user-level config
/// into the inventory. So a config path is rejected when:
///
/// * it (or any ancestor up to `repo_root`) is itself a symlink — checked with
///   `symlink_metadata`, which does **not** follow the final component, so the
///   check is not subject to the TOCTOU window an `is_file()` probe has; or
/// * its canonicalized (fully symlink-resolved) path does not stay inside the
///   canonicalized `repo_root` — a defense-in-depth backstop.
pub fn discover_mcp_configs(repo_root: &Path) -> Vec<(PathBuf, String)> {
    // Canonicalize the repo root once for the containment check. If the root
    // itself cannot be canonicalized (it does not exist), no config under it
    // can be discovered anyway — return empty rather than guess.
    let canonical_root = match repo_root.canonicalize() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut found: Vec<(PathBuf, String)> = Vec::new();
    for rel in MCP_CONFIG_RELATIVE_PATHS {
        let abs = repo_root.join(rel);

        // Reject if the final component, or any directory component between
        // `repo_root` and it, is a symlink. `symlink_metadata` does not follow
        // the path it is given, so each component is inspected as-is.
        if path_crosses_symlink(repo_root, rel) {
            continue;
        }

        // The file must be a regular file (not a directory, FIFO, …). Use
        // `symlink_metadata` so a symlink that slipped past the component walk
        // is still not silently followed.
        match std::fs::symlink_metadata(&abs) {
            Ok(meta) if meta.file_type().is_file() => {}
            _ => continue,
        }

        // Defense in depth: the fully-resolved path must stay inside the
        // resolved repo root. (With the symlink-component check above this is
        // belt-and-braces, but it also catches an exotic mount/junction case.)
        match abs.canonicalize() {
            Ok(canonical) if canonical.starts_with(&canonical_root) => {}
            _ => continue,
        }

        found.push((abs, (*rel).to_string()));
    }
    found.sort_by(|a, b| a.1.cmp(&b.1));
    found
}

/// `true` if any component of `rel` — joined onto `repo_root` — is a symlink.
///
/// Walks from `repo_root` outward one component at a time, calling
/// `symlink_metadata` (which never follows the inspected path's last
/// component) on each prefix. `repo_root` itself is intentionally **not**
/// inspected: the caller chose it, and a repo legitimately reached through a
/// symlinked checkout directory must still be scannable — only symlinks
/// *inside* the repo, on the way to a config file, are rejected.
fn path_crosses_symlink(repo_root: &Path, rel: &str) -> bool {
    let mut current = repo_root.to_path_buf();
    for component in Path::new(rel).components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return true;
                }
            }
            // A component that does not exist cannot be a symlink; let the
            // caller's `symlink_metadata` on the full path handle "missing".
            Err(_) => return false,
        }
    }
    false
}

/// Build the MCP inventory for a repository.
///
/// Discovers every repo-local MCP config under `repo_root`, parses each, and
/// returns the structured [`McpInventory`]. A config that cannot be parsed is
/// recorded in [`McpInventory::malformed_configs`] and contributes no servers —
/// it is never an error and never a panic.
pub fn build_inventory(repo_root: &Path) -> McpInventory {
    let configs = discover_mcp_configs(repo_root);

    let mut inventory = McpInventory::default();

    for (abs_path, rel_path) in configs {
        inventory.configs.push(rel_path.clone());

        let content = match std::fs::read_to_string(&abs_path) {
            Ok(c) => c,
            Err(_) => {
                // Unreadable (permissions, vanished mid-walk): treat like a
                // malformed config — recorded, no entries, no panic.
                inventory.malformed_configs.push(rel_path);
                continue;
            }
        };

        match parse_mcp_config(&content, &rel_path) {
            Some(mut servers) => {
                if servers.is_empty() {
                    // Valid JSON, valid MCP shape, but zero servers declared.
                    // Not malformed — just an empty config; it still counts as
                    // a discovered config.
                } else {
                    inventory.servers.append(&mut servers);
                }
            }
            None => {
                // Not valid JSON, or no MCP-server object at all.
                inventory.malformed_configs.push(rel_path);
            }
        }
    }

    // Deterministic ordering: sort the merged server list by (name, source).
    inventory.servers.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then(a.source_config.cmp(&b.source_config))
    });
    inventory.configs.sort();
    inventory.configs.dedup();
    inventory.malformed_configs.sort();
    inventory.malformed_configs.dedup();

    inventory
}

/// Parse one MCP config file's contents into a list of server entries.
///
/// Returns:
/// * `Some(vec)` — the file is valid JSON **and** carries a recognized
///   MCP-server object (`mcpServers` or its `servers` alias). The vec may be
///   empty if that object declared no servers.
/// * `None` — the file is not valid JSON, or has no MCP-server object at all.
///   The caller records this as a malformed/non-MCP config.
///
/// Every malformed individual server object (a server whose value is not a
/// JSON object) is skipped silently rather than failing the whole file — one
/// bad entry must not discard the others.
pub fn parse_mcp_config(content: &str, source_config: &str) -> Option<Vec<McpServerEntry>> {
    let json: serde_json::Value = serde_json::from_str(content).ok()?;

    // Both shape variants: the canonical `mcpServers` and the `servers` alias.
    // `configfile::check_mcp_config` accepts exactly this pair.
    let servers_obj = json
        .get("mcpServers")
        .or_else(|| json.get("servers"))
        .and_then(|v| v.as_object())?;

    let mut entries = Vec::with_capacity(servers_obj.len());
    for (name, config) in servers_obj {
        // A server whose value is not a JSON object is malformed — skip it,
        // keep the rest.
        let obj = match config.as_object() {
            Some(o) => o,
            None => continue,
        };

        let transport = parse_transport(obj);
        let tools = parse_tools(obj);

        entries.push(McpServerEntry {
            name: name.clone(),
            transport,
            tools,
            source_config: source_config.to_string(),
        });
    }

    Some(entries)
}

/// Derive the transport descriptor from a single server object.
///
/// `url` wins over `command` if a (malformed) config declares both — a remote
/// URL is the higher-risk surface, so it is the one recorded.
fn parse_transport(obj: &serde_json::Map<String, serde_json::Value>) -> McpTransport {
    if let Some(url) = obj.get("url").and_then(|v| v.as_str()) {
        return McpTransport::Url {
            url: url.to_string(),
        };
    }

    if let Some(command) = obj.get("command").and_then(|v| v.as_str()) {
        let args = obj
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|a| a.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let env = parse_env(obj);
        return McpTransport::Stdio {
            command: command.to_string(),
            args,
            env,
        };
    }

    McpTransport::Unknown
}

/// Extract a stdio server's `env` object as `(name, value_hash)` entries,
/// sorted by name so the hash is stable regardless of JSON key order. A
/// non-string env value is hashed by its compact JSON rendering (so a numeric
/// or boolean env value — unusual but seen in real configs — is not silently
/// dropped); a missing or non-object `env` field yields an empty vec.
///
/// `env` is **security-relevant**: it is what a config injects into the MCP
/// subprocess. Capturing it means a swapped credential or an added variable
/// shows up as drift in `mcp verify` / `mcp diff` rather than passing silently.
///
/// **The raw value never leaves this function.** It is read out of the JSON
/// map into a local `String`, immediately consumed by [`McpEnvEntry::from_raw`]
/// to compute `sha256(name || ':' || value)`, and then dropped at the end of
/// the iteration step. No struct field, log line, return value, or serialized
/// output ever carries the plaintext value. This is the load-bearing security
/// invariant of the v3 lockfile format: a committed `.tirith/mcp.lock` never
/// contains a secret that was in the source `.mcp.json`.
fn parse_env(obj: &serde_json::Map<String, serde_json::Value>) -> Vec<McpEnvEntry> {
    let mut env: Vec<McpEnvEntry> = obj
        .get("env")
        .and_then(|v| v.as_object())
        .map(|map| {
            map.iter()
                .map(|(k, v)| {
                    // A string value is hashed verbatim; any other JSON value
                    // is hashed by its compact JSON form so it still contributes
                    // a deterministic per-value digest. The raw value sits in a
                    // local `String` only long enough for `from_raw` to consume
                    // it — it never reaches a struct, the serializer, the
                    // hasher's transport-level frame, or stdout.
                    let raw_value: String = match v.as_str() {
                        Some(s) => s.to_string(),
                        None => v.to_string(),
                    };
                    McpEnvEntry::from_raw(k, &raw_value)
                })
                .collect()
        })
        .unwrap_or_default();
    // Sort by name for a stable hash regardless of JSON key order.
    env.sort_by(|a, b| a.name.cmp(&b.name));
    env
}

/// Extract the declared tool list from a server object, sorted and
/// de-duplicated for a stable hash. Non-string entries in the `tools` array are
/// dropped. A missing or non-array `tools` field yields an empty vec.
fn parse_tools(obj: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let mut tools: Vec<String> = obj
        .get("tools")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    tools.sort();
    tools.dedup();
    tools
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn parse_mcp_servers_canonical_shape() {
        let content = r#"{
            "mcpServers": {
                "fs": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv"] },
                "remote": { "url": "https://mcp.example.com/sse", "tools": ["search", "fetch"] }
            }
        }"#;
        let entries = parse_mcp_config(content, ".mcp.json").expect("valid MCP config");
        assert_eq!(entries.len(), 2);

        let fs_entry = entries.iter().find(|e| e.name == "fs").unwrap();
        assert_eq!(
            fs_entry.transport,
            McpTransport::Stdio {
                command: "npx".to_string(),
                args: vec![
                    "-y".to_string(),
                    "@modelcontextprotocol/server-filesystem".to_string(),
                    "/srv".to_string(),
                ],
                env: vec![],
            }
        );
        assert!(fs_entry.tools.is_empty());
        assert_eq!(fs_entry.source_config, ".mcp.json");

        let remote = entries.iter().find(|e| e.name == "remote").unwrap();
        assert_eq!(
            remote.transport,
            McpTransport::Url {
                url: "https://mcp.example.com/sse".to_string(),
            }
        );
        // tools sorted.
        assert_eq!(remote.tools, vec!["fetch", "search"]);
    }

    #[test]
    fn parse_mcp_servers_alias_shape() {
        // The `servers` alias (some IDE configs) parses identically.
        let content = r#"{ "servers": { "a": { "command": "node", "args": ["s.js"] } } }"#;
        let entries = parse_mcp_config(content, ".vscode/mcp.json").expect("valid alias config");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "a");
        assert_eq!(
            entries[0].transport,
            McpTransport::Stdio {
                command: "node".to_string(),
                args: vec!["s.js".to_string()],
                env: vec![],
            }
        );
    }

    #[test]
    fn parse_server_with_no_transport_is_unknown() {
        // A server object declaring neither `url` nor `command` is captured
        // with an Unknown transport rather than dropped.
        let content = r#"{ "mcpServers": { "weird": { "tools": ["x"] } } }"#;
        let entries = parse_mcp_config(content, ".mcp.json").expect("valid config");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].transport, McpTransport::Unknown);
        assert_eq!(entries[0].tools, vec!["x"]);
    }

    #[test]
    fn parse_url_wins_when_both_declared() {
        // A malformed config declaring both `url` and `command`: the URL (the
        // higher-risk surface) is the one recorded.
        let content =
            r#"{ "mcpServers": { "both": { "url": "https://x.example", "command": "node" } } }"#;
        let entries = parse_mcp_config(content, ".mcp.json").unwrap();
        assert_eq!(
            entries[0].transport,
            McpTransport::Url {
                url: "https://x.example".to_string(),
            }
        );
    }

    #[test]
    fn parse_malformed_json_returns_none() {
        // Not valid JSON → None (recorded as malformed by the caller), no panic.
        for bad in [
            "{ not json",
            "",
            "{\"mcpServers\":",
            "[1,2,3]",
            "\"just a string\"",
        ] {
            assert!(
                parse_mcp_config(bad, ".mcp.json").is_none(),
                "malformed input {bad:?} must yield None"
            );
        }
    }

    #[test]
    fn parse_valid_json_without_mcp_object_returns_none() {
        // Valid JSON but no `mcpServers`/`servers` object → None.
        let content = r#"{ "someOtherKey": { "a": 1 } }"#;
        assert!(parse_mcp_config(content, "mcp.json").is_none());
    }

    #[test]
    fn parse_empty_mcp_object_is_some_empty() {
        // A valid but empty MCP object is a recognized (empty) config — Some(vec![]),
        // distinct from a malformed file.
        let content = r#"{ "mcpServers": {} }"#;
        let entries = parse_mcp_config(content, "mcp.json").expect("recognized empty config");
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_skips_non_object_server_keeps_others() {
        // One server value is a string (malformed); the other is valid. The
        // good one survives.
        let content = r#"{ "mcpServers": { "bad": "oops", "good": { "command": "node" } } }"#;
        let entries = parse_mcp_config(content, ".mcp.json").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "good");
    }

    #[test]
    fn parse_tools_drops_non_string_entries() {
        let content =
            r#"{ "mcpServers": { "s": { "command": "n", "tools": ["ok", 42, null, "ok"] } } }"#;
        let entries = parse_mcp_config(content, "mcp.json").unwrap();
        // 42 and null dropped; the duplicate "ok" de-duplicated.
        assert_eq!(entries[0].tools, vec!["ok"]);
    }

    #[test]
    fn content_hash_is_stable_and_order_independent_for_tools() {
        let a = McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec!["x".into()],
                env: vec![],
            },
            tools: vec!["alpha".into(), "beta".into()],
            source_config: ".mcp.json".into(),
        };
        // Tools are sorted on parse, so a differently-ordered-but-equal tool
        // set hashes identically.
        let b = McpServerEntry {
            tools: vec!["beta".into(), "alpha".into()],
            ..a.clone()
        };
        let mut b_sorted = b.clone();
        b_sorted.tools.sort();
        assert_eq!(a.content_hash(), b_sorted.content_hash());
    }

    #[test]
    fn content_hash_changes_when_transport_changes() {
        let base = McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![],
            },
            tools: vec![],
            source_config: ".mcp.json".into(),
        };
        let changed = McpServerEntry {
            transport: McpTransport::Url {
                url: "https://x.example".into(),
            },
            ..base.clone()
        };
        assert_ne!(base.content_hash(), changed.content_hash());
    }

    #[test]
    fn content_hash_ignores_source_config() {
        // Moving an unchanged server between two config files must not change
        // its content hash — only name/transport/tools are hashed.
        let a = McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![],
            },
            tools: vec![],
            source_config: ".mcp.json".into(),
        };
        let b = McpServerEntry {
            source_config: ".vscode/mcp.json".into(),
            ..a.clone()
        };
        assert_eq!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn lockfile_from_inventory_is_deterministic() {
        let inventory = McpInventory {
            servers: vec![
                McpServerEntry {
                    name: "zeta".into(),
                    transport: McpTransport::Stdio {
                        command: "z".into(),
                        args: vec![],
                        env: vec![],
                    },
                    tools: vec![],
                    source_config: ".mcp.json".into(),
                },
                McpServerEntry {
                    name: "alpha".into(),
                    transport: McpTransport::Url {
                        url: "https://a.example".into(),
                    },
                    tools: vec!["t".into()],
                    source_config: ".mcp.json".into(),
                },
            ],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        let lock1 = McpLockfile::from_inventory(&inventory);
        let lock2 = McpLockfile::from_inventory(&inventory);
        assert_eq!(lock1, lock2);
        assert_eq!(lock1.render(), lock2.render());
        assert_eq!(lock1.format_version, MCP_LOCK_FORMAT_VERSION);
        assert_eq!(lock1.servers.len(), 2);
    }

    #[test]
    fn lockfile_render_ends_with_newline_and_is_valid_json() {
        let inventory = McpInventory::default();
        let lock = McpLockfile::from_inventory(&inventory);
        let rendered = lock.render();
        assert!(rendered.ends_with('\n'));
        let parsed: McpLockfile =
            serde_json::from_str(&rendered).expect("rendered lockfile must round-trip");
        assert_eq!(parsed, lock);
    }

    #[test]
    fn inventory_hash_changes_when_a_server_changes() {
        let mut inventory = McpInventory {
            servers: vec![McpServerEntry {
                name: "s".into(),
                transport: McpTransport::Stdio {
                    command: "node".into(),
                    args: vec![],
                    env: vec![],
                },
                tools: vec![],
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        let hash_before = McpLockfile::from_inventory(&inventory).inventory_hash;

        // Mutate the single server's transport.
        inventory.servers[0].transport = McpTransport::Url {
            url: "https://new.example".into(),
        };
        let hash_after = McpLockfile::from_inventory(&inventory).inventory_hash;

        assert_ne!(
            hash_before, hash_after,
            "inventory hash must change when a server changes"
        );
    }

    #[test]
    fn build_inventory_finds_planted_mcp_json() {
        let repo = tempdir().unwrap();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "fs": { "command": "npx", "args": ["server"] } } }"#,
        )
        .unwrap();

        let inventory = build_inventory(repo.path());
        assert_eq!(inventory.configs, vec![".mcp.json".to_string()]);
        assert_eq!(inventory.servers.len(), 1);
        assert_eq!(inventory.servers[0].name, "fs");
        assert!(inventory.malformed_configs.is_empty());
        assert!(!inventory.is_empty());
    }

    #[test]
    fn build_inventory_empty_repo_is_empty() {
        let repo = tempdir().unwrap();
        let inventory = build_inventory(repo.path());
        assert!(inventory.is_empty());
        assert!(inventory.servers.is_empty());
        assert!(inventory.configs.is_empty());
    }

    #[test]
    fn build_inventory_records_malformed_config() {
        let repo = tempdir().unwrap();
        fs::write(repo.path().join("mcp.json"), "{ this is not json").unwrap();
        let inventory = build_inventory(repo.path());
        // The file is discovered (it counts as a config) but yields no servers
        // and is recorded as malformed.
        assert_eq!(inventory.configs, vec!["mcp.json".to_string()]);
        assert!(inventory.servers.is_empty());
        assert_eq!(inventory.malformed_configs, vec!["mcp.json".to_string()]);
        // A repo that has only a malformed config is still "non-empty" — a
        // config WAS found, the caller should report it, not say "nothing".
        assert!(!inventory.is_empty());
    }

    #[test]
    fn build_inventory_merges_multiple_configs_sorted() {
        let repo = tempdir().unwrap();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "root-server": { "command": "a" } } }"#,
        )
        .unwrap();
        fs::create_dir_all(repo.path().join(".vscode")).unwrap();
        fs::write(
            repo.path().join(".vscode/mcp.json"),
            r#"{ "servers": { "ide-server": { "command": "b" } } }"#,
        )
        .unwrap();

        let inventory = build_inventory(repo.path());
        assert_eq!(
            inventory.configs,
            vec![".mcp.json".to_string(), ".vscode/mcp.json".to_string()]
        );
        assert_eq!(inventory.servers.len(), 2);
        // Servers sorted by name: "ide-server" < "root-server".
        assert_eq!(inventory.servers[0].name, "ide-server");
        assert_eq!(inventory.servers[1].name, "root-server");
        assert_eq!(inventory.servers[0].source_config, ".vscode/mcp.json");
        assert_eq!(inventory.servers[1].source_config, ".mcp.json");
    }

    #[test]
    fn discover_mcp_configs_is_repo_local_only() {
        // A config-shaped file outside the repo root must NOT be discovered.
        let outer = tempdir().unwrap();
        fs::write(outer.path().join(".mcp.json"), r#"{ "mcpServers": {} }"#).unwrap();
        let repo = outer.path().join("repo");
        fs::create_dir_all(&repo).unwrap();
        // The repo itself has no MCP config.
        let found = discover_mcp_configs(&repo);
        assert!(
            found.is_empty(),
            "discovery must not climb out of the repo root: {found:?}"
        );
    }

    #[test]
    fn build_inventory_empty_mcp_object_counts_as_config_no_servers() {
        let repo = tempdir().unwrap();
        fs::write(repo.path().join("mcp.json"), r#"{ "mcpServers": {} }"#).unwrap();
        let inventory = build_inventory(repo.path());
        // A recognized-but-empty config: it counts as a discovered config, it
        // is NOT malformed, and it declares zero servers.
        assert_eq!(inventory.configs, vec!["mcp.json".to_string()]);
        assert!(inventory.servers.is_empty());
        assert!(inventory.malformed_configs.is_empty());
        assert!(!inventory.is_empty());
    }

    // -----------------------------------------------------------------------
    // Finding A — `from_inventory` sorts servers before hashing, so a lockfile
    // (and its inventory hash) is identical no matter what order discovery
    // happened to produce.
    // -----------------------------------------------------------------------

    #[test]
    fn from_inventory_sorts_servers_regardless_of_input_order() {
        let alpha = McpServerEntry {
            name: "alpha".into(),
            transport: McpTransport::Url {
                url: "https://a.example".into(),
            },
            tools: vec!["t".into()],
            source_config: ".mcp.json".into(),
        };
        let zeta = McpServerEntry {
            name: "zeta".into(),
            transport: McpTransport::Stdio {
                command: "z".into(),
                args: vec![],
                env: vec![],
            },
            tools: vec![],
            source_config: ".vscode/mcp.json".into(),
        };

        // Same two servers, opposite inventory order.
        let in_order = McpInventory {
            servers: vec![alpha.clone(), zeta.clone()],
            configs: vec![".mcp.json".into(), ".vscode/mcp.json".into()],
            malformed_configs: vec![],
        };
        let reversed = McpInventory {
            servers: vec![zeta, alpha],
            configs: vec![".vscode/mcp.json".into(), ".mcp.json".into()],
            malformed_configs: vec![],
        };

        let lock_a = McpLockfile::from_inventory(&in_order);
        let lock_b = McpLockfile::from_inventory(&reversed);

        // Servers land in (name, source_config) order either way.
        assert_eq!(lock_a.servers[0].name, "alpha");
        assert_eq!(lock_a.servers[1].name, "zeta");
        // The whole lockfile — including the order-sensitive inventory hash and
        // the rendered bytes — is identical regardless of discovery order.
        assert_eq!(lock_a, lock_b);
        assert_eq!(lock_a.inventory_hash, lock_b.inventory_hash);
        assert_eq!(lock_a.render(), lock_b.render());
    }

    #[test]
    fn from_inventory_sorts_by_source_config_when_names_tie() {
        // Two servers with the *same* name must order by source_config — and do
        // so deterministically whichever way the inventory listed them.
        let mk = |source: &str| McpServerEntry {
            name: "dup".into(),
            transport: McpTransport::Url {
                url: "https://x.example".into(),
            },
            tools: vec![],
            source_config: source.into(),
        };
        let forward = McpInventory {
            servers: vec![mk(".mcp.json"), mk(".vscode/mcp.json")],
            configs: vec![],
            malformed_configs: vec![],
        };
        let backward = McpInventory {
            servers: vec![mk(".vscode/mcp.json"), mk(".mcp.json")],
            configs: vec![],
            malformed_configs: vec![],
        };
        let lock_f = McpLockfile::from_inventory(&forward);
        let lock_b = McpLockfile::from_inventory(&backward);
        assert_eq!(lock_f.servers[0].source_config, ".mcp.json");
        assert_eq!(lock_f.servers[1].source_config, ".vscode/mcp.json");
        assert_eq!(lock_f, lock_b);
    }

    // -----------------------------------------------------------------------
    // Finding B — a symlinked config file (or one under a symlinked directory)
    // is rejected: discovery is repo-local, and a symlink can point anywhere.
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn discover_rejects_symlinked_config_file() {
        use std::os::unix::fs::symlink;

        // A real config lives OUTSIDE the repo.
        let outside = tempdir().unwrap();
        let outside_config = outside.path().join("evil-mcp.json");
        fs::write(
            &outside_config,
            r#"{ "mcpServers": { "evil": { "command": "node" } } }"#,
        )
        .unwrap();

        // Inside the repo, `.mcp.json` is a *symlink* pointing at it.
        let repo = tempdir().unwrap();
        symlink(&outside_config, repo.path().join(".mcp.json")).unwrap();

        // The symlinked config must NOT be discovered…
        let found = discover_mcp_configs(repo.path());
        assert!(
            found.is_empty(),
            "a symlinked .mcp.json must be rejected, not followed: {found:?}"
        );

        // …and the inventory must therefore be empty — the outside server is
        // not pulled in.
        let inventory = build_inventory(repo.path());
        assert!(
            inventory.servers.is_empty(),
            "a symlinked config must contribute no servers"
        );
        assert!(inventory.configs.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn discover_rejects_config_under_symlinked_directory() {
        use std::os::unix::fs::symlink;

        // A real `.vscode/` directory with a config lives outside the repo.
        let outside = tempdir().unwrap();
        let outside_vscode = outside.path().join("vscode-real");
        fs::create_dir_all(&outside_vscode).unwrap();
        fs::write(
            outside_vscode.join("mcp.json"),
            r#"{ "servers": { "evil": { "command": "node" } } }"#,
        )
        .unwrap();

        // Inside the repo, `.vscode` is a symlink to that outside directory.
        let repo = tempdir().unwrap();
        symlink(&outside_vscode, repo.path().join(".vscode")).unwrap();

        // `.vscode/mcp.json` resolves outside the repo via the symlinked
        // parent — it must be rejected.
        let found = discover_mcp_configs(repo.path());
        assert!(
            found.is_empty(),
            "a config reached through a symlinked directory must be rejected: {found:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn discover_still_accepts_a_plain_regular_config() {
        // Control: a plain (non-symlink) config file is still discovered — the
        // symlink rejection must not break the normal case.
        let repo = tempdir().unwrap();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{ "mcpServers": { "ok": { "command": "node" } } }"#,
        )
        .unwrap();
        let found = discover_mcp_configs(repo.path());
        assert_eq!(found.len(), 1, "a plain regular config must still be found");
        assert_eq!(found[0].1, ".mcp.json");
    }

    // -----------------------------------------------------------------------
    // Finding C — a stdio server's `env` is captured and an `env` change
    // registers as drift (it is part of the per-server content hash).
    // -----------------------------------------------------------------------

    #[test]
    fn parse_captures_stdio_env() {
        let content = r#"{
            "mcpServers": {
                "s": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": { "API_TOKEN": "secret-1", "DEBUG": "1" }
                }
            }
        }"#;
        let entries = parse_mcp_config(content, ".mcp.json").expect("valid config");
        assert_eq!(entries.len(), 1);
        // env entries are present, sorted by name, and carry hashes — not the
        // raw values. The hashes match `sha256(name || ':' || value)`.
        assert_eq!(
            entries[0].transport,
            McpTransport::Stdio {
                command: "node".to_string(),
                args: vec!["server.js".to_string()],
                env: vec![
                    McpEnvEntry::from_raw("API_TOKEN", "secret-1"),
                    McpEnvEntry::from_raw("DEBUG", "1"),
                ],
            }
        );
    }

    #[test]
    fn parse_env_is_sorted_and_handles_non_string_values() {
        // Keys come back sorted regardless of JSON order; a non-string value is
        // captured by its JSON rendering and then hashed rather than dropped.
        let content = r#"{
            "mcpServers": {
                "s": { "command": "n", "env": { "ZED": "z", "ABLE": 7 } }
            }
        }"#;
        let entries = parse_mcp_config(content, ".mcp.json").unwrap();
        match &entries[0].transport {
            McpTransport::Stdio { env, .. } => {
                // `7` becomes the compact JSON form `"7"` before hashing.
                assert_eq!(
                    env,
                    &vec![
                        McpEnvEntry::from_raw("ABLE", "7"),
                        McpEnvEntry::from_raw("ZED", "z"),
                    ]
                );
            }
            other => panic!("expected stdio transport, got {other:?}"),
        }
    }

    #[test]
    fn content_hash_changes_when_env_changes() {
        // The headline of Finding C: an `env` change must register as drift.
        let base = McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![McpEnvEntry::from_raw("API_TOKEN", "old")],
            },
            tools: vec![],
            source_config: ".mcp.json".into(),
        };
        // Same server, the env value swapped (a rotated/exfiltrated credential).
        let value_changed = McpServerEntry {
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![McpEnvEntry::from_raw("API_TOKEN", "new")],
            },
            ..base.clone()
        };
        // Same server, an extra env var added.
        let var_added = McpServerEntry {
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![
                    McpEnvEntry::from_raw("API_TOKEN", "old"),
                    McpEnvEntry::from_raw("EXTRA", "x"),
                ],
            },
            ..base.clone()
        };
        assert_ne!(
            base.content_hash(),
            value_changed.content_hash(),
            "swapping an env value must change the content hash"
        );
        assert_ne!(
            base.content_hash(),
            var_added.content_hash(),
            "adding an env var must change the content hash"
        );

        // And it flows through to the inventory hash / lockfile.
        let inv_base = McpInventory {
            servers: vec![base.clone()],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        let inv_changed = McpInventory {
            servers: vec![value_changed],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        assert_ne!(
            McpLockfile::from_inventory(&inv_base).inventory_hash,
            McpLockfile::from_inventory(&inv_changed).inventory_hash,
            "an env change must surface as a different inventory hash"
        );
    }

    #[test]
    fn lockfile_format_version_is_3() {
        // Finding E bumped the schema (env entries no longer serialize raw
        // values — only `name` + `value_hash`), so the format version is 3.
        assert_eq!(MCP_LOCK_FORMAT_VERSION, 3);
        let lock = McpLockfile::from_inventory(&McpInventory::default());
        assert_eq!(lock.format_version, 3);
    }

    #[test]
    fn lockfile_with_env_round_trips() {
        // A lockfile carrying a server with `env` must serialize and parse back
        // identically — the new schema field round-trips.
        let inventory = McpInventory {
            servers: vec![McpServerEntry {
                name: "s".into(),
                transport: McpTransport::Stdio {
                    command: "node".into(),
                    args: vec!["server.js".into()],
                    env: vec![McpEnvEntry::from_raw("TOKEN", "v")],
                },
                tools: vec![],
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        let lock = McpLockfile::from_inventory(&inventory);
        let parsed: McpLockfile =
            serde_json::from_str(&lock.render()).expect("lockfile with env must round-trip");
        assert_eq!(parsed, lock);
    }

    // -----------------------------------------------------------------------
    // Finding E — env raw values must not be persisted in the lockfile. They
    // are commonly secrets (API tokens, credentials), and `.tirith/mcp.lock`
    // is designed to be committed. The lockfile carries a salted hash only.
    // -----------------------------------------------------------------------

    /// A bag of credential-shaped (high-entropy, unique) env values we render
    /// into the lockfile in the test below; **none** of these byte sequences
    /// may appear in the rendered JSON. The values are deliberately distinctive
    /// so a substring scan over the rendered JSON cannot trip on incidental
    /// matches in field names, hashes, or other names — they are not strings
    /// any other part of the lockfile could legitimately contain.
    const ENV_LEAK_PROBES: &[(&str, &str)] = &[
        ("API_TOKEN", "ghp_supersecret_TOKEN_value_42"),
        (
            "GITHUB_PERSONAL_ACCESS_TOKEN",
            "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        ("OPENAI_API_KEY", "sk-test-DO_NOT_LEAK_THIS_VALUE"),
        ("DB_PASSWORD", "p4ssw0rd-shouldnt-leak-mY7q"),
        ("WEBHOOK_SECRET", "whsec_xyz123_zyx789_NEVER_LEAK"),
    ];

    #[test]
    fn env_raw_values_never_appear_in_rendered_lockfile() {
        // Plant a server whose env carries values that look exactly like
        // credentials — API tokens, GitHub PATs, OpenAI keys. After rendering,
        // NONE of the raw value bytes may show up.
        //
        // Note: this test deliberately uses high-entropy, distinctive values
        // (not "1" or "true"). A low-entropy value substring-matches incidental
        // parts of the JSON — `"1"` appears inside hashes, `"true"` inside
        // boolean-like keys — so probing for it would false-positive. The
        // security invariant the lockfile guarantees is that a *secret-shaped*
        // value is not persisted: that value, by construction, cannot collide
        // with any other lockfile content.
        let env: Vec<McpEnvEntry> = ENV_LEAK_PROBES
            .iter()
            .map(|(name, value)| McpEnvEntry::from_raw(name, value))
            .collect();
        let inventory = McpInventory {
            servers: vec![McpServerEntry {
                name: "secrets".into(),
                transport: McpTransport::Stdio {
                    command: "node".into(),
                    args: vec!["server.js".into()],
                    env,
                },
                tools: vec![],
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        let rendered = McpLockfile::from_inventory(&inventory).render();

        for (name, raw_value) in ENV_LEAK_PROBES {
            // The name is allowed to appear (it is what the human summary shows
            // and the schema serializes), but the raw VALUE must not — its hash
            // is recorded instead.
            assert!(
                rendered.contains(name),
                "the env name {name:?} should appear in the lockfile"
            );
            assert!(
                !rendered.contains(raw_value),
                "env raw value {raw_value:?} (for {name}) leaked into the rendered lockfile:\n{rendered}"
            );
        }
        // Every env entry exposes a `value_hash` field — the wire shape proof.
        assert!(
            rendered.contains("\"value_hash\""),
            "rendered lockfile must serialize a value_hash per env entry"
        );
        // And it must NOT carry a `value` field — the proof we did not also
        // write the raw value as a sibling of the hash. Use the exact JSON
        // field-key form `"value":` so the substring cannot collide with
        // `"value_hash":` (which contains the substring `"value"`).
        assert!(
            !rendered.contains("\"value\":"),
            "rendered lockfile must NOT carry a plaintext `value` field"
        );
    }

    #[test]
    fn parse_env_does_not_persist_raw_values() {
        // The same invariant via the JSON-config entry point (not direct struct
        // construction): a config carrying a real-looking secret must produce a
        // parsed inventory whose lockfile rendering does not contain that
        // secret byte sequence anywhere.
        let secret = "ghp_REAL_LOOKING_TOKEN_DO_NOT_LEAK";
        let content = format!(
            r#"{{
                "mcpServers": {{
                    "s": {{
                        "command": "node",
                        "env": {{ "GITHUB_PERSONAL_ACCESS_TOKEN": "{secret}" }}
                    }}
                }}
            }}"#
        );
        let entries = parse_mcp_config(&content, ".mcp.json").expect("valid config");
        assert_eq!(entries.len(), 1);

        // The parsed env entry carries the SHA-256 hash, not the raw value.
        let env = match &entries[0].transport {
            McpTransport::Stdio { env, .. } => env,
            other => panic!("expected stdio transport, got {other:?}"),
        };
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].name, "GITHUB_PERSONAL_ACCESS_TOKEN");
        assert_eq!(
            env[0].value_hash,
            McpEnvEntry::from_raw("GITHUB_PERSONAL_ACCESS_TOKEN", secret).value_hash,
            "the value hash must be sha256(name || ':' || value)"
        );

        // And the rendered lockfile that descends from this parse must not
        // carry the raw secret bytes anywhere.
        let inventory = McpInventory {
            servers: entries,
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
        };
        let rendered = McpLockfile::from_inventory(&inventory).render();
        assert!(
            !rendered.contains(secret),
            "raw secret leaked from parse_mcp_config -> McpLockfile::render():\n{rendered}"
        );
    }

    #[test]
    fn env_entry_value_hash_is_name_salted() {
        // The hash binds the name to the value, so a low-entropy value cannot
        // be brute-forced once and reused across servers: the same value `1`
        // under two different names hashes to two different digests.
        let a = McpEnvEntry::from_raw("DEBUG", "1");
        let b = McpEnvEntry::from_raw("VERBOSE", "1");
        assert_ne!(
            a.value_hash, b.value_hash,
            "the same raw value under different names must hash differently \
             (the name acts as a per-key salt)"
        );
        // And the hash is exactly sha256(name || ':' || value) — a stable,
        // documented, reproducible-by-hand scheme.
        let expected_a = {
            let mut h = Sha256::new();
            h.update(b"DEBUG:1");
            hex_lower(&h.finalize())
        };
        assert_eq!(a.value_hash, expected_a);
    }

    #[test]
    fn env_entry_hash_is_unambiguous_against_name_value_concatenation() {
        // The `:` delimiter inside `sha256(name || ':' || value)` means
        // `("AB", "c")` hashes `"AB:c"`, never the same byte stream as
        // `("A", "Bc")` (`"A:Bc"`). This is the property we get for free over
        // a no-delimiter scheme and matters for any future caller that might
        // confuse a `name+value` byte stream with our hash input.
        let ab_c = McpEnvEntry::from_raw("AB", "c");
        let a_bc = McpEnvEntry::from_raw("A", "Bc");
        assert_ne!(
            ab_c.value_hash, a_bc.value_hash,
            "the `:` delimiter must prevent name/value boundary forgery"
        );
    }

    // -----------------------------------------------------------------------
    // Finding D — the per-server hash is collision-free: a separator-delimited
    // list scheme cannot distinguish `["a","b"]` from `["ab"]` or `["a\0b"]`;
    // length-prefixing every component makes the hash input unambiguous.
    // -----------------------------------------------------------------------

    #[test]
    fn content_hash_distinguishes_ambiguous_arg_lists() {
        // The three lists below would all feed the bytes `a` `b` to a
        // `\0`-joined hasher in different framings — they must hash distinctly.
        let mk = |args: Vec<&str>| McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: args.into_iter().map(String::from).collect(),
                env: vec![],
            },
            tools: vec![],
            source_config: ".mcp.json".into(),
        };
        let two = mk(vec!["a", "b"]);
        let one_joined = mk(vec!["ab"]);
        let one_with_nul = mk(vec!["a\0b"]);

        assert_ne!(
            two.content_hash(),
            one_joined.content_hash(),
            r#"["a","b"] must not hash the same as ["ab"]"#
        );
        assert_ne!(
            two.content_hash(),
            one_with_nul.content_hash(),
            r#"["a","b"] must not hash the same as ["a\0b"]"#
        );
        assert_ne!(
            one_joined.content_hash(),
            one_with_nul.content_hash(),
            r#"["ab"] must not hash the same as ["a\0b"]"#
        );
    }

    #[test]
    fn content_hash_distinguishes_ambiguous_tool_lists() {
        // The same collision class for the `tools` list.
        let mk = |tools: Vec<&str>| McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Url {
                url: "https://x.example".into(),
            },
            tools: tools.into_iter().map(String::from).collect(),
            source_config: ".mcp.json".into(),
        };
        let two = mk(vec!["a", "b"]);
        let one_joined = mk(vec!["ab"]);
        assert_ne!(
            two.content_hash(),
            one_joined.content_hash(),
            r#"tools ["a","b"] must not hash the same as ["ab"]"#
        );
    }

    #[test]
    fn content_hash_distinguishes_ambiguous_env_pairs() {
        // Length-prefixing also disambiguates env: a key/value boundary cannot
        // be forged. {"AB": "c"} vs {"A": "Bc"} must hash distinctly. Note that
        // both layers contribute here: the salted per-entry `value_hash` (via
        // `name + ':' + value`) already differs, AND the framed encoding into
        // the per-server hash adds length prefixes around `name` and
        // `value_hash` themselves.
        let mk = |key: &str, value: &str| McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![McpEnvEntry::from_raw(key, value)],
            },
            tools: vec![],
            source_config: ".mcp.json".into(),
        };
        assert_ne!(
            mk("AB", "c").content_hash(),
            mk("A", "Bc").content_hash(),
            "env with key=AB value=c must not hash the same as key=A value=Bc"
        );
    }

    #[test]
    fn content_hash_arg_boundary_is_unambiguous_vs_command() {
        // The command/args boundary must also be framed: `command="ab"` with no
        // args must not collide with `command="a"` + args `["b"]`.
        let cmd_only = McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Stdio {
                command: "ab".into(),
                args: vec![],
                env: vec![],
            },
            tools: vec![],
            source_config: ".mcp.json".into(),
        };
        let cmd_and_arg = McpServerEntry {
            transport: McpTransport::Stdio {
                command: "a".into(),
                args: vec!["b".into()],
                env: vec![],
            },
            ..cmd_only.clone()
        };
        assert_ne!(
            cmd_only.content_hash(),
            cmd_and_arg.content_hash(),
            "the command/args boundary must be unambiguous"
        );
    }
}
