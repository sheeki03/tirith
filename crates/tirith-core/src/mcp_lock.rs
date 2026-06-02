//! MCP server inventory and `.tirith/mcp.lock` lockfile generation.
//!
//! The data layer behind `tirith mcp lock` (M4), all local file ops off the
//! detection hot path. [`build_inventory`] discovers the repo-local MCP config
//! files and parses each into an [`McpInventory`]; [`McpLockfile::from_inventory`]
//! / [`render`](McpLockfile::render) serialize it into a deterministic JSON
//! lockfile (per-server transport + tools + content hash, plus a format version
//! and an inventory hash). Servers are sorted by `(name, source_config)` BEFORE
//! hashing, so the lockfile and its `inventory_hash` are stable regardless of
//! discovery order — a clean baseline for `mcp verify` / `mcp diff`.
//!
//! **Repo-local only.** Discovery never enters `~/.claude/` or any user-level
//! dir; the guarantee is enforced, not structural: a symlinked config path (or
//! one under a symlinked dir), or one whose canonical path escapes the repo
//! root, is rejected.
//!
//! **Malformed input is never fatal:** a non-JSON / non-MCP file contributes no
//! entries and never panics (the codebase's "malformed → empty, no panic"
//! convention).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Lockfile format version. Bump only on a breaking schema change.
///
/// **Enforced at load:** [`parse_lockfile`] rejects a `format_version` other
/// than this (or v4, the migration carve-out) with a dedicated
/// [`McpLockLoadError::UnsupportedVersion`], distinct from "the JSON is corrupt"
/// so the operator gets a precise re-lock / upgrade message.
///
/// Version history (each bump makes prior lockfiles not byte-comparable):
/// * `1` — initial: name, transport, tools, source config, content hash.
/// * `2` — stdio transport captures `env`, folded into the content hash.
/// * `3` — env entries store `{ name, value_hash }` (salted SHA-256), never the
///   raw value: env values are commonly credentials and the lockfile is
///   committed. The name salt makes even a low-entropy value unforgeable across
///   servers; a value change still flips the hash (drift unchanged).
/// * `4` — the same name-salted redaction applied to a `url` transport's
///   userinfo: `https://user:token@host/` stores as `https://host/` plus a
///   `userinfo_hash`, omitted entirely when no userinfo was present.
/// * `5` — `tools_declared` folded into `content_hash`. Pre-v5 it was excluded,
///   so a `"tools": []` ↔ omitted flip silently passed drift detection. A v4
///   lockfile loaded under v5 is tagged [`LockfileSchema::LegacyV4Migration`]
///   and [`compute_drift`] returns a single [`McpDrift::SchemaUpgradeRequired`]
///   (re-lock once) instead of phantom-drifting every server.
pub const MCP_LOCK_FORMAT_VERSION: u32 = 5;

/// Basename of the lockfile, written under `<repo_root>/.tirith/`.
pub const MCP_LOCK_FILENAME: &str = "mcp.lock";

/// One environment variable a stdio MCP server is launched with, as captured in
/// the lockfile.
///
/// **The raw value is never stored** (env values are commonly credentials and
/// the lockfile is committed). Instead `value_hash = sha256(name || ':' ||
/// value)`: the name salt makes a low-entropy value hash differently per name,
/// so a digest can't be brute-forced once and reused across servers. A swapped
/// value still flips the hash, so drift detection is unchanged. Computed once in
/// [`parse_env`]; the raw value never leaves that function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpEnvEntry {
    /// The env var's name (the key in the config's `env` object).
    pub name: String,
    /// Lowercase-hex SHA-256 of `name || ':' || value`. The inner `:` is
    /// per-entry entropy, not the boundary marker (POSIX names may contain `:`);
    /// the load-bearing collision protection is the outer length-prefixed framing
    /// in [`McpServerEntry::content_hash`] via [`hash_field`].
    pub value_hash: String,
}

impl McpEnvEntry {
    /// Build an entry from `(name, raw_value)`, hashing the value immediately.
    /// The only legitimate way to construct one from a real value; the raw value
    /// is consumed and dropped before returning — it never reaches a struct
    /// field, the serializer, or the rest of the process.
    pub fn from_raw(name: &str, raw_value: &str) -> Self {
        let value_hash = salted_sha256_hex(name, raw_value);
        McpEnvEntry {
            name: name.to_string(),
            value_hash,
        }
    }
}

/// How an MCP server is reached — either a remote URL or a local subprocess
/// (mutually exclusive in every known config shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpTransport {
    /// A network-reachable MCP server (HTTP / SSE / streamable-HTTP).
    ///
    /// **The URL is stored with any userinfo (HTTP Basic Auth) stripped** —
    /// `.tirith/mcp.lock` is committed, so persisting it would leak a credential
    /// (the v3 threat model). When userinfo was present, `userinfo_hash` is
    /// `Some(sha256(server_name || ':' || userinfo))` (name-salted, folded into
    /// the content hash so a change is drift); when absent it is `None` and
    /// **omitted** from the wire, so absence is structurally distinct from
    /// presence. The stored `url` is always the canonical `url::Url::as_str()`
    /// form (both branches round-trip the parser), so adding/removing a
    /// credential doesn't surface as a spurious `UrlChanged` alongside
    /// `Userinfo*`. An unparseable URL is best-effort-stripped (`***@`) with a
    /// hash of the original userinfo bytes; a non-authority-shaped one is kept
    /// verbatim with `None`. See [`redact_url_userinfo`].
    Url {
        url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        userinfo_hash: Option<String>,
    },
    /// A local MCP server spawned as a subprocess.
    Stdio {
        /// The executable to run.
        command: String,
        /// Arguments, in declared order.
        #[serde(default)]
        args: Vec<String>,
        /// Env vars the config injects, as `(name, value_hash)` entries sorted by
        /// name. Security-relevant (a swapped credential / added variable must
        /// drift), so part of the per-server hash; raw values are never stored
        /// (see [`McpEnvEntry`]). Empty vec = no `env` object declared.
        #[serde(default)]
        env: Vec<McpEnvEntry>,
    },
    /// The server declared neither `url` nor `command`. Captured (not dropped):
    /// a transport-less MCP entry is itself a finding-worthy oddity.
    Unknown,
}

/// How a server's `tools` key appeared in the source config. The lockfile
/// collapses these into one `tools: Vec<String>`, but the distinction is useful
/// for audits (`Omitted` → MCP clients treat as "all tools"; `EmptyDeclared` →
/// "no tools"; `Invalid` → a malformed value this parser dropped). For backward
/// compat, [`McpServerEntry`] / [`McpLockServer`] track it in a sibling
/// `tools_declared: bool` rather than carrying this enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclaredTools {
    /// No `tools` key. MCP semantics: any tool the runtime exposes.
    Omitted,
    /// A `tools` key whose value was not a string array; values that parsed as
    /// strings are still captured, the rest dropped.
    Invalid(Vec<String>),
    /// `"tools": []` — an explicit "no tools" declaration.
    EmptyDeclared,
    /// A non-empty list of tool-name strings.
    Declared(Vec<String>),
}

impl DeclaredTools {
    /// Whether the source config carried a `tools` key (false only for `Omitted`).
    pub fn was_declared(&self) -> bool {
        !matches!(self, DeclaredTools::Omitted)
    }

    /// Flatten into the canonical (deduplicated, sorted) tool list the lockfile
    /// stores. `Omitted`/`EmptyDeclared` → empty vec (distinguished via
    /// `tools_declared`).
    pub fn into_canonical(self) -> Vec<String> {
        match self {
            DeclaredTools::Omitted | DeclaredTools::EmptyDeclared => Vec::new(),
            DeclaredTools::Invalid(v) | DeclaredTools::Declared(v) => v,
        }
    }
}

/// `serde(default)` for `tools_declared`: a legacy lockfile predating the field
/// deserializes as `true`, preserving the pre-change semantics.
fn default_tools_declared() -> bool {
    true
}

/// One MCP server as declared in a repository's MCP configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerEntry {
    /// The server's declared name (the key in the `mcpServers` / `servers`
    /// object).
    pub name: String,
    /// How the server is reached.
    pub transport: McpTransport,
    /// The declared tools, sorted and de-duplicated for a stable hash. Empty =
    /// either no `tools` key (MCP "all tools") or `"tools": []` — distinguish via
    /// [`Self::tools_declared`].
    pub tools: Vec<String>,
    /// Whether the source config carried a `tools` key (`false` only for
    /// [`DeclaredTools::Omitted`]; see [`DeclaredTools::was_declared`]).
    ///
    /// **Folded into [`Self::content_hash`] from v5 onward.** Pre-v5 it was
    /// excluded, so a `"tools": []` ↔ omitted flip silently passed drift
    /// detection. A v4 lockfile under v5 is tagged
    /// [`LockfileSchema::LegacyV4Migration`] and [`compute_drift`] short-circuits
    /// to a migration prompt rather than phantom-drifting. Legacy lockfiles
    /// without the field deserialize as `true`.
    #[serde(default = "default_tools_declared")]
    pub tools_declared: bool,
    /// Repo-relative path of the config file this entry was parsed from.
    pub source_config: String,
}

impl McpServerEntry {
    /// A stable per-server content hash over name + transport (incl. a stdio
    /// server's `env`) + tools, so `mcp diff` can detect a changed server by hash
    /// alone. `source_config` is excluded — moving an unchanged server between
    /// configs must not drift.
    ///
    /// **Collision-free framing:** every variable-length component is
    /// length-prefixed via [`hash_field`], not `\0`-joined — so `["a","b"]` and
    /// `["ab"]` (or a value containing `\0`) cannot collide.
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        self.feed_content_hash_common(&mut hasher);
        // `tools_declared` joined the hash in v5: folding `\x01` (declared) /
        // `\x00` (omitted) makes the `"tools": []` ↔ omitted flip register as
        // drift. (Legacy v4 lockfiles are tagged for a one-time migration prompt
        // — see [`MCP_LOCK_FORMAT_VERSION`].)
        if self.tools_declared {
            hasher.update(b"\x01");
        } else {
            hasher.update(b"\x00");
        }
        hex_lower(&hasher.finalize())
    }

    /// v4-compatible per-server hash — the same byte stream v4 computed, before
    /// `tools_declared` was folded in. Used by [`compute_drift`] for a
    /// [`LockfileSchema::LegacyV4Migration`] lockfile so the comparison runs under
    /// v4 semantics on BOTH sides: real drift (URL/command/env/tools/server
    /// changes) still surfaces alongside the migration prompt, instead of the v5
    /// short-circuit silently absorbing drift made during the migration window.
    /// The v4 `"tools": []` ↔ omitted flip stays undetected here (intentional —
    /// re-locking under v5 catches it).
    pub fn content_hash_v4(&self) -> String {
        let mut hasher = Sha256::new();
        self.feed_content_hash_common(&mut hasher);
        hex_lower(&hasher.finalize())
    }

    /// Feed every per-server hash component into `hasher` EXCEPT the trailing
    /// `tools_declared` byte. Shared by [`Self::content_hash`] (v5, appends the
    /// byte) and [`Self::content_hash_v4`] (v4, omits it) so the two never diverge
    /// on the shared prefix.
    fn feed_content_hash_common(&self, hasher: &mut Sha256) {
        hasher.update(b"mcp-server-v2\0");
        hash_field(hasher, self.name.as_bytes());
        match &self.transport {
            McpTransport::Url { url, userinfo_hash } => {
                hasher.update(b"url\0");
                hash_field(hasher, url.as_bytes());
                // Fold `userinfo_hash` in so a userinfo change drifts. A leading
                // 0/1 byte frames presence/absence so a future empty-hash
                // sentinel can't collide with a no-userinfo URL.
                match userinfo_hash {
                    Some(h) => {
                        hasher.update(b"\x01");
                        hash_field(hasher, h.as_bytes());
                    }
                    None => {
                        hasher.update(b"\x00");
                    }
                }
            }
            McpTransport::Stdio { command, args, env } => {
                hasher.update(b"stdio\0");
                hash_field(hasher, command.as_bytes());
                hash_field(hasher, &(args.len() as u64).to_le_bytes());
                for arg in args {
                    hash_field(hasher, arg.as_bytes());
                }
                hash_field(hasher, &(env.len() as u64).to_le_bytes());
                for entry in env {
                    // Feed name + value_hash; the hash already depends on the raw
                    // value, so a value change still drifts (no raw value here).
                    hash_field(hasher, entry.name.as_bytes());
                    hash_field(hasher, entry.value_hash.as_bytes());
                }
            }
            McpTransport::Unknown => {
                hasher.update(b"unknown\0");
            }
        }
        hash_field(hasher, &(self.tools.len() as u64).to_le_bytes());
        for tool in &self.tools {
            hash_field(hasher, tool.as_bytes());
        }
    }
}

/// Feed one length-prefixed field into a hasher: the byte length as a LE `u64`,
/// then the bytes. Makes the hash input an unambiguous encoding — no list can
/// collide with a different list, and an embedded `\0` can't forge a boundary.
fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Lowercase-hex SHA-256 of `salt || ':' || value` — the redaction primitive for
/// both [`McpEnvEntry::from_raw`] (salt = env name) and [`redact_url_userinfo`]
/// (salt = server name). The `:` is per-entry entropy, not the collision
/// protection (the outer length-prefixed framing in
/// [`McpServerEntry::content_hash`] is); the salt makes a low-entropy value hash
/// differently per entry, defeating a cross-server rainbow table.
pub(crate) fn salted_sha256_hex(salt: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(b":");
    hasher.update(value.as_bytes());
    hex_lower(&hasher.finalize())
}

/// Why a physically-present MCP config path was skipped during discovery rather
/// than contributing servers. Surfacing it in
/// [`McpInventory::rejected_configs`] turns a silent skip — which would let an
/// attacker swap a real `.mcp.json` for a symlink-out-of-repo and lose every
/// server it contributed — into a visible diagnostic.
///
/// Wire shape: `kind` names the variant in `snake_case`; extra fields are
/// `usize`/`u64`/`bool` only (no content / error strings), so the diagnostic
/// can't echo a sensitive lockfile body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RejectedReason {
    /// The path, or a directory between `repo_root` and it, is a symlink —
    /// refused since discovery is repo-local and a symlink could point anywhere.
    Symlink,
    /// The path exists but is not a regular file (dir/FIFO/socket/device).
    NotRegularFile,
    /// The canonical (symlink-resolved) form escapes the repo root — a
    /// defense-in-depth backstop over the per-component symlink check.
    OutsideRepo,
    /// A regular file whose size exceeds `MCP_CONFIG_MAX_SIZE`; reading an
    /// unbounded JSON doc would be a DoS surface.
    Oversize {
        /// The file's size in bytes (`fs::metadata().len()`).
        size_bytes: u64,
    },
    /// A regular file under the cap that could not be read.
    Unreadable {
        /// `true` for `PermissionDenied` (the operator-actionable case); other
        /// io errors fold into `false` (the inner string is not surfaced).
        permission_denied: bool,
    },
}

/// One rejected config path with the reason it was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedConfig {
    /// Repo-relative path of the rejected config file.
    pub path: String,
    /// Why the path was rejected.
    pub reason: RejectedReason,
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
    /// Repo-relative paths discovered but unparseable (non-JSON, or no MCP-server
    /// object). Informational, not an error — they contribute no entries.
    pub malformed_configs: Vec<String>,
    /// Physically-present config paths the discovery walk REFUSED (symlinked, not
    /// regular, escaped the repo, oversized, or unreadable), each with a
    /// structured reason. Distinct from `malformed_configs` (read but didn't
    /// parse): a rejected config was never read. In-process discovery field only,
    /// not part of the on-disk lockfile shape (no schema bump).
    pub rejected_configs: Vec<RejectedConfig>,
}

impl McpInventory {
    /// `true` when no MCP config was found at all (distinct from "found configs
    /// with zero servers"). `rejected_configs` doesn't count — a repo whose only
    /// config was rejected still reads as "no configs found", with the rejection
    /// list as the operator-visible cause.
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
    /// Declared tool list (sorted, de-duplicated). Empty when the config omitted
    /// `tools` OR declared `"tools": []` — distinguish via [`Self::tools_declared`].
    pub tools: Vec<String>,
    /// Whether the source config carried a `tools` key (see
    /// [`McpServerEntry::tools_declared`]). Legacy lockfiles without the field
    /// deserialize as `true`. Folded into [`Self::hash`] from v5 onward; a v4
    /// lockfile is tagged [`LockfileSchema::LegacyV4Migration`] for a one-time
    /// migration prompt.
    #[serde(default = "default_tools_declared")]
    pub tools_declared: bool,
    /// Repo-relative path of the config file the server was declared in.
    pub source_config: String,
    /// Per-server content hash (see [`McpServerEntry::content_hash`]).
    pub hash: String,
}

/// In-memory schema-state tag on a parsed lockfile. Never serialized; carried
/// alongside an [`McpLockfile`] so [`compute_drift`] can short-circuit a legacy
/// lockfile that needs a one-time regeneration. Set in [`parse_lockfile`] from
/// the file's `format_version`; a freshly-built lockfile is always `Current`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LockfileSchema {
    /// `format_version` matches [`MCP_LOCK_FORMAT_VERSION`]; drift runs normally.
    #[default]
    Current,
    /// `format_version: 4`: same on-disk shape as v5, but hashes were computed
    /// without `tools_declared`, so every v5-recomputed hash differs even with an
    /// unchanged inventory. [`compute_drift`] returns a single
    /// [`McpDrift::SchemaUpgradeRequired`] (re-lock once) instead of phantom drift.
    LegacyV4Migration,
}

/// The `.tirith/mcp.lock` document. JSON, deterministically ordered (servers by
/// `(name, source_config)`), so re-running `tirith mcp lock` on an unchanged repo
/// produces a byte-identical file and a clean `git diff`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpLockfile {
    /// Lockfile schema version.
    pub format_version: u32,
    /// Hash over the ordered concatenation of every server's content hash —
    /// changes iff any server is added/removed/altered. The cheap "did anything
    /// change?" check for `mcp verify`.
    pub inventory_hash: String,
    /// Repo-relative paths of the MCP config files captured, sorted.
    pub configs: Vec<String>,
    /// Every locked MCP server, sorted by `(name, source_config)`.
    pub servers: Vec<McpLockServer>,
    /// In-memory schema-state tag (`LegacyV4Migration` for a v4 file, else
    /// `Current`). Never serialized; `#[serde(skip)]` so any round-trip lands in
    /// `Current`.
    #[serde(skip)]
    pub schema_state: LockfileSchema,
}

impl McpLockfile {
    /// Build a lockfile from an inventory. Pure and deterministic regardless of
    /// the inventory's server order: the sort by `(name, source_config)` here —
    /// the load-bearing one, since this is a public entry point — happens BEFORE
    /// the inventory hash, so both the lockfile and `inventory_hash` are stable.
    pub fn from_inventory(inventory: &McpInventory) -> Self {
        let mut servers: Vec<McpLockServer> = inventory
            .servers
            .iter()
            .map(|entry| McpLockServer {
                name: entry.name.clone(),
                transport: entry.transport.clone(),
                tools: entry.tools.clone(),
                tools_declared: entry.tools_declared,
                source_config: entry.source_config.clone(),
                hash: entry.content_hash(),
            })
            .collect();

        // Sort before `compute_inventory_hash` (which hashes server order), so
        // both the lockfile and the hash are discovery-order-independent.
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
            schema_state: LockfileSchema::Current,
        }
    }

    /// Render to the on-disk form: pretty JSON with a trailing newline.
    /// Deterministic (ordering already fixed by [`from_inventory`]).
    pub fn render(&self) -> String {
        // Handle the Result (rather than unwrap) so a future schema change can
        // never panic `mcp lock`; this serialize cannot actually fail today.
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

/// Lowercase hex encoding of a byte slice (local — avoids the `hex` crate).
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Repo-root-relative MCP config locations to probe.
///
/// **Intentionally broader than `configfile::is_mcp_config_file`'s `mcp_dirs`**:
/// this list also covers `.amazonq/`, `.continue/`, and `.kiro/settings/`. The
/// asymmetry is deliberate — the lockfile is the gating baseline and must capture
/// every host dir tirith knows; the file-scan classifier expands on its own
/// cadence. A maintainer adding a host dir decides independently whether to
/// extend this list, the classifier, or both. Kept explicit (not a walk) so
/// discovery is bounded and never strays outside the known surface.
pub(crate) const MCP_CONFIG_RELATIVE_PATHS: &[&str] = &[
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

/// Discover the repo-local MCP config files under `repo_root`, returning
/// `(absolute, repo_relative)` pairs sorted by the relative path. Only regular
/// files reachable without crossing a symlink and resolving inside `repo_root`
/// are returned — a probed path that is itself a symlink (or under a symlinked
/// parent), or whose canonical form escapes the root, is rejected, so a
/// `.mcp.json -> ~/.claude/mcp.json` can't pull a user config in. The symlink
/// check uses `symlink_metadata` (no TOCTOU). Drops the rejection list — use
/// [`discover_mcp_configs_full`] for it.
pub fn discover_mcp_configs(repo_root: &Path) -> Vec<(PathBuf, String)> {
    discover_mcp_configs_full(repo_root).0
}

/// Like [`discover_mcp_configs`] but also returns the structured rejection list
/// (used by [`build_inventory`] to populate [`McpInventory::rejected_configs`]).
/// Path-level rejections only — content rejections (oversize, permission) happen
/// in [`build_inventory`] when the file is read.
pub(crate) fn discover_mcp_configs_full(
    repo_root: &Path,
) -> (Vec<(PathBuf, String)>, Vec<RejectedConfig>) {
    // Canonicalize the root once for the containment check; if it doesn't exist,
    // no config under it can be discovered — return empty (nothing to reject).
    let canonical_root = match repo_root.canonicalize() {
        Ok(r) => r,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    let mut found: Vec<(PathBuf, String)> = Vec::new();
    let mut rejected: Vec<RejectedConfig> = Vec::new();

    for rel in MCP_CONFIG_RELATIVE_PATHS {
        let abs = repo_root.join(rel);

        // Reject if any component between `repo_root` and the leaf is a symlink.
        // (A non-existent path isn't "rejected", it just isn't there.)
        if path_crosses_symlink(repo_root, rel) {
            rejected.push(RejectedConfig {
                path: (*rel).to_string(),
                reason: RejectedReason::Symlink,
            });
            continue;
        }

        // Must be a regular file; `symlink_metadata` so a leaf symlink is still
        // not followed.
        match std::fs::symlink_metadata(&abs) {
            Ok(meta) if meta.file_type().is_file() => {}
            Ok(meta) if meta.file_type().is_symlink() => {
                // A leaf-position symlink the per-component walk didn't observe.
                rejected.push(RejectedConfig {
                    path: (*rel).to_string(),
                    reason: RejectedReason::Symlink,
                });
                continue;
            }
            Ok(_) => {
                // Exists but not a regular file (dir/FIFO/socket/…) — surface it.
                rejected.push(RejectedConfig {
                    path: (*rel).to_string(),
                    reason: RejectedReason::NotRegularFile,
                });
                continue;
            }
            Err(_) => {
                // Doesn't exist — the common case; not "rejected", nothing here.
                continue;
            }
        }

        // Defense in depth: the resolved path must stay inside the resolved root
        // (also catches exotic mount/junction cases).
        match abs.canonicalize() {
            Ok(canonical) if canonical.starts_with(&canonical_root) => {}
            _ => {
                rejected.push(RejectedConfig {
                    path: (*rel).to_string(),
                    reason: RejectedReason::OutsideRepo,
                });
                continue;
            }
        }

        found.push((abs, (*rel).to_string()));
    }
    found.sort_by(|a, b| a.1.cmp(&b.1));
    rejected.sort_by(|a, b| a.path.cmp(&b.path));
    (found, rejected)
}

/// `true` if any component of `rel` (joined onto `repo_root`) is a symlink.
/// Walks outward one component at a time via `symlink_metadata`. `repo_root`
/// itself is NOT inspected — a repo reached through a symlinked checkout must
/// still be scannable; only symlinks INSIDE the repo are rejected.
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
            // A missing component can't be a symlink; the caller handles "missing".
            Err(_) => return false,
        }
    }
    false
}

/// Per-file size cap for an MCP config (1 MiB ≫ the realistic tens-of-KiB).
/// Above it the file is rejected without reading, so `tirith mcp lock` isn't a
/// DoS surface. Tighter than `scan_single_file`'s 10 MiB hot-path cap — a much
/// narrower file class.
pub const MCP_CONFIG_MAX_SIZE: u64 = 1_048_576;

/// Build the MCP inventory for a repository: discover every repo-local config
/// under `repo_root`, parse each, and return the [`McpInventory`]. An unparseable
/// config lands in [`McpInventory::malformed_configs`] (never an error/panic).
///
/// Path-level rejections (from [`discover_mcp_configs_full`]) and file-level ones
/// (oversize, permission) both flow into [`McpInventory::rejected_configs`] — one
/// "present but skipped" list regardless of which gate tripped. Size is checked
/// against [`MCP_CONFIG_MAX_SIZE`] before any read. IO errors are categorized:
/// `PermissionDenied`→`Unreadable{true}`; `NotFound`→silent (vanished mid-edit);
/// `InvalidData`→malformed; else `Unreadable{false}`.
pub fn build_inventory(repo_root: &Path) -> McpInventory {
    let (configs, rejected_from_discovery) = discover_mcp_configs_full(repo_root);

    let mut inventory = McpInventory {
        rejected_configs: rejected_from_discovery,
        ..McpInventory::default()
    };

    for (abs_path, rel_path) in configs {
        // Size pre-check. Discovery already rejected symlinks, so this is a real
        // regular file; a metadata failure here folds into the unreadable bucket.
        let size_bytes = match std::fs::metadata(&abs_path) {
            Ok(m) => m.len(),
            Err(e) => {
                inventory.rejected_configs.push(RejectedConfig {
                    path: rel_path.clone(),
                    reason: RejectedReason::Unreadable {
                        permission_denied: e.kind() == std::io::ErrorKind::PermissionDenied,
                    },
                });
                continue;
            }
        };

        if size_bytes > MCP_CONFIG_MAX_SIZE {
            inventory.rejected_configs.push(RejectedConfig {
                path: rel_path.clone(),
                reason: RejectedReason::Oversize { size_bytes },
            });
            // Oversized: rejected at the gate, never a discovered config.
            continue;
        }

        // Admitted: counts as a discovered config from here on, even if it later
        // fails to read or parse.
        inventory.configs.push(rel_path.clone());

        let content = match std::fs::read_to_string(&abs_path) {
            Ok(c) => c,
            Err(e) => {
                // Categorize so the operator can tell "can't read" from "not UTF-8".
                match e.kind() {
                    std::io::ErrorKind::NotFound => {
                        // Vanished between discovery and read (concurrent edit) —
                        // pop it off `configs`, nothing to surface.
                        inventory.configs.pop();
                    }
                    std::io::ErrorKind::PermissionDenied => {
                        inventory.rejected_configs.push(RejectedConfig {
                            path: rel_path.clone(),
                            reason: RejectedReason::Unreadable {
                                permission_denied: true,
                            },
                        });
                        // Pop: discovered structurally, but unreadable; the
                        // rejection list names it now.
                        inventory.configs.pop();
                    }
                    std::io::ErrorKind::InvalidData => {
                        // Non-UTF-8: present and attributable, just not text —
                        // keep the legacy "malformed" path.
                        inventory.malformed_configs.push(rel_path.clone());
                    }
                    _ => {
                        inventory.rejected_configs.push(RejectedConfig {
                            path: rel_path.clone(),
                            reason: RejectedReason::Unreadable {
                                permission_denied: false,
                            },
                        });
                        inventory.configs.pop();
                    }
                }
                continue;
            }
        };

        match parse_mcp_config(&content, &rel_path) {
            Some(mut servers) => {
                if servers.is_empty() {
                    // Valid but empty config — not malformed, still a discovered config.
                } else {
                    inventory.servers.append(&mut servers);
                }
            }
            None => {
                // Not valid JSON, or no MCP-server object.
                inventory.malformed_configs.push(rel_path);
            }
        }
    }

    // Deterministic ordering by (name, source).
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
        .rejected_configs
        .sort_by(|a, b| a.path.cmp(&b.path));
    inventory.rejected_configs.dedup();

    inventory
}

/// Parse one MCP config file into server entries. `Some(vec)` if it's valid JSON
/// with a recognized MCP-server object (`mcpServers` or `servers` alias; vec may
/// be empty); `None` otherwise (caller records it as malformed). A single
/// non-object server value is skipped silently — one bad entry must not discard
/// the rest.
pub fn parse_mcp_config(content: &str, source_config: &str) -> Option<Vec<McpServerEntry>> {
    let json: serde_json::Value = serde_json::from_str(content).ok()?;

    // Canonical `mcpServers` and the `servers` alias — the pair
    // `configfile::check_mcp_config` accepts.
    let servers_obj = json
        .get("mcpServers")
        .or_else(|| json.get("servers"))
        .and_then(|v| v.as_object())?;

    let mut entries = Vec::with_capacity(servers_obj.len());
    for (name, config) in servers_obj {
        // Skip a non-object server value, keep the rest.
        let obj = match config.as_object() {
            Some(o) => o,
            None => continue,
        };

        let transport = parse_transport(name, obj);
        let declared = parse_tools(obj);
        let tools_declared = declared.was_declared();
        let tools = declared.into_canonical();

        entries.push(McpServerEntry {
            name: name.clone(),
            transport,
            tools,
            tools_declared,
            source_config: source_config.to_string(),
        });
    }

    Some(entries)
}

/// Derive the transport descriptor from a server object. `url` wins over
/// `command` if both are declared (the higher-risk surface). `server_name` is the
/// per-entry salt for the URL `userinfo_hash` (see [`redact_url_userinfo`]).
fn parse_transport(
    server_name: &str,
    obj: &serde_json::Map<String, serde_json::Value>,
) -> McpTransport {
    if let Some(url) = obj.get("url").and_then(|v| v.as_str()) {
        let (redacted_url, userinfo_hash) = redact_url_userinfo(server_name, url);
        return McpTransport::Url {
            url: redacted_url,
            userinfo_hash,
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

/// Strip any HTTP Basic Auth userinfo from a URL, returning the redacted URL and
/// a salted hash of the captured userinfo.
///
/// **Security invariant (v4):** `https://user:token@host/` is stored as
/// `https://host/`; the `user:token` substring is hashed via
/// [`salted_sha256_hex`] (server name as salt) and dropped before return — a
/// committed `.tirith/mcp.lock` never contains a credential from the source.
///
/// Behavior: a clean parse with userinfo returns the stripped URL
/// (`set_username("")`/`set_password(None)`, re-serialized) plus `Some(hash)`. A
/// clean parse with no userinfo returns the CANONICAL `as_str()` form and `None`
/// — round-tripped even with nothing to redact, so the stored bytes have the same
/// shape either way and credential removal doesn't surface as a spurious
/// `UrlChanged` alongside `UserinfoRemoved`. (`https://:@host/` etc. normalize to
/// no-userinfo.) An unparseable URL is best-effort-stripped with a hash of its
/// userinfo bytes (see [`strip_userinfo_best_effort`]); a non-authority-shaped
/// one is kept verbatim with `None`.
fn redact_url_userinfo(server_name: &str, url: &str) -> (String, Option<String>) {
    let parsed = match url::Url::parse(url) {
        Ok(p) => p,
        // Unparseable: best-effort byte-scan strip (replace `scheme://...@` with
        // `***`) so a credential in a malformed-but-authority-shaped URL doesn't
        // leak into the committed lockfile; the userinfo bytes are still hashed
        // so credential add/remove drift survives. See `strip_userinfo_best_effort`.
        Err(_) => return strip_userinfo_best_effort(server_name, url),
    };

    let username = parsed.username();
    let password = parsed.password();

    // Reconstruct the literal userinfo substring (`user`, `user:password`, or
    // `:password`). `url` normalizes the all-empty `:@`/`@` forms away, so
    // `None`/`""` here means no userinfo and nothing to redact.
    let userinfo: Option<String> = match (username, password) {
        ("", None) => None,
        (u, None) => Some(u.to_string()),
        (u, Some(p)) => Some(format!("{u}:{p}")),
    };

    // No userinfo: still round-trip through `as_str()` so the stored URL has the
    // same canonical shape as the userinfo-stripped path — without this,
    // `compute_drift` would report a spurious `UrlChanged` alongside
    // `UserinfoRemoved` (e.g. `https://host` vs the locked `https://host/`).
    let Some(raw_userinfo) = userinfo else {
        return (parsed.as_str().to_string(), None);
    };

    // Name-salted SHA-256 (same scheme as `McpEnvEntry::from_raw`): the same
    // token under two servers hashes differently.
    let userinfo_hash = Some(salted_sha256_hex(server_name, &raw_userinfo));

    // Strip userinfo from the stored URL. `set_username`/`set_password` only fail
    // for authority-less schemes (which can't carry userinfo), so since we just
    // saw userinfo, both must succeed — assert rather than silently rebuild from
    // components (which would drop query/fragment and cause permanent spurious
    // `UrlChanged` drift).
    let mut parsed = parsed;
    let strip_ok = parsed.set_password(None).is_ok() && parsed.set_username("").is_ok();
    assert!(
        strip_ok,
        "url::Url invariant violated: set_username/set_password failed on a parsed URL with \
         userinfo. This branch is documented unreachable for any URL whose authority can carry \
         credentials (every authority-bearing scheme accepts set_username(\"\") / \
         set_password(None)); please file a bug against tirith with the offending URL scheme \
         (the URL itself is sensitive — do NOT include it)."
    );

    (parsed.as_str().to_string(), userinfo_hash)
}

/// Best-effort userinfo strip for a URL `url::Url::parse` rejected. Replaces the
/// segment between `scheme://` and the first `@` (before the next `/`/`?`/`#`/end)
/// with `***`, preserving the rest for diagnostics. A string not matching the
/// `scheme://...@` shape is returned verbatim — nothing to strip.
///
/// Manual byte-scan (not regex) to avoid a heavy dependency for one call site.
/// Returns `(stripped_url, Option<hash>)`: when the strip fires, the userinfo
/// bytes are hashed via the same `salted_sha256_hex(server_name, ...)` shape so
/// credential add/remove drift survives even for malformed URLs; otherwise `None`.
fn strip_userinfo_best_effort(server_name: &str, raw: &str) -> (String, Option<String>) {
    let bytes = raw.as_bytes();
    // Scheme (RFC 3986 §3.1): a letter, then letter/digit/`+`/`-`/`.`, then `://`.
    let mut scheme_end = 0usize;
    if bytes.first().is_none_or(|c| !c.is_ascii_alphabetic()) {
        return (raw.to_string(), None);
    }
    while scheme_end < bytes.len() {
        let c = bytes[scheme_end];
        if c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.') {
            scheme_end += 1;
        } else {
            break;
        }
    }
    // Must be exactly `://`.
    if scheme_end + 3 > bytes.len() || &bytes[scheme_end..scheme_end + 3] != b"://" {
        return (raw.to_string(), None);
    }
    let auth_start = scheme_end + 3;
    // Authority ends at `/`/`?`/`#`/end; find the first `@` before that.
    let mut i = auth_start;
    let mut at_pos: Option<usize> = None;
    while i < bytes.len() {
        match bytes[i] {
            b'/' | b'?' | b'#' => break,
            b'@' => {
                at_pos = Some(i);
                break;
            }
            _ => i += 1,
        }
    }
    let Some(at) = at_pos else {
        // No `@` before the boundary — nothing to strip, no signal to record.
        return (raw.to_string(), None);
    };
    // Hash the userinfo bytes (between `auth_start` and `at`) before dropping
    // them — server name as salt, mirroring `redact_url_userinfo`. An empty
    // substring (`://@host`) records `None`.
    let userinfo_bytes = &bytes[auth_start..at];
    let userinfo_hash = if userinfo_bytes.is_empty() {
        None
    } else {
        let mut hasher = Sha256::new();
        hasher.update(server_name.as_bytes());
        hasher.update(b":");
        hasher.update(userinfo_bytes);
        Some(hex_lower(&hasher.finalize()))
    };
    // Rewrite to `***` for shape consistency even when the substring is empty.
    let mut out = String::with_capacity(raw.len());
    out.push_str(&raw[..auth_start]);
    out.push_str("***");
    out.push_str(&raw[at..]);
    (out, userinfo_hash)
}

/// Extract a stdio server's `env` as `(name, value_hash)` entries, sorted by name
/// for a stable hash. A non-string value is hashed by its compact JSON form (not
/// dropped); a missing/non-object `env` yields an empty vec.
///
/// `env` is security-relevant (what the config injects into the subprocess), so
/// capturing it surfaces a swapped credential as drift. **The raw value never
/// leaves this function** (v3 invariant): consumed by [`McpEnvEntry::from_raw`]
/// and dropped, never reaching a struct/serializer/log.
fn parse_env(obj: &serde_json::Map<String, serde_json::Value>) -> Vec<McpEnvEntry> {
    let mut env: Vec<McpEnvEntry> = obj
        .get("env")
        .and_then(|v| v.as_object())
        .map(|map| {
            map.iter()
                .map(|(k, v)| {
                    // String value hashed verbatim; any other JSON value by its
                    // compact form. The raw value lives only long enough for
                    // `from_raw` to consume it.
                    let raw_value: String = match v.as_str() {
                        Some(s) => s.to_string(),
                        None => v.to_string(),
                    };
                    McpEnvEntry::from_raw(k, &raw_value)
                })
                .collect()
        })
        .unwrap_or_default();
    env.sort_by(|a, b| a.name.cmp(&b.name));
    env
}

/// Extract the declared tool list, distinguishing the four on-wire states:
/// `Omitted` (no key), `EmptyDeclared` (`"tools": []`), `Declared` (a string
/// array, sorted/de-duplicated, non-strings dropped), and `Invalid` (a `tools`
/// value that isn't an array). The lockfile collapses Omitted/EmptyDeclared,
/// preserving the distinction via `tools_declared` (PR121_FIX_LIST_TRIAGE item 7).
fn parse_tools(obj: &serde_json::Map<String, serde_json::Value>) -> DeclaredTools {
    let Some(value) = obj.get("tools") else {
        return DeclaredTools::Omitted;
    };
    let Some(arr) = value.as_array() else {
        return DeclaredTools::Invalid(Vec::new());
    };
    let mut tools: Vec<String> = arr
        .iter()
        .filter_map(|t| t.as_str().map(str::to_string))
        .collect();
    tools.sort();
    tools.dedup();
    if tools.is_empty() {
        // Empty array, or all elements non-string — both equivalent to "no
        // declarable tools".
        DeclaredTools::EmptyDeclared
    } else {
        DeclaredTools::Declared(tools)
    }
}

// ---------------------------------------------------------------------------
// Drift detection
// ---------------------------------------------------------------------------

/// How a stdio server's `env` differs from the lockfile. Each variant carries
/// only the variable's NAME — the lockfile holds only a salted hash, and drift
/// reports are printed, so a raw (possibly-credential) value must never leak. A
/// value swap surfaces as `ValueHashChanged` without being decoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpEnvChange {
    /// The server now declares an env variable that the lockfile did not.
    Added { name: String },
    /// The lockfile declared an env variable that the server no longer does.
    Removed { name: String },
    /// The variable is present on both sides but its `value_hash` differs —
    /// the underlying value changed (a rotated credential, a swapped flag).
    ValueHashChanged { name: String },
}

/// How a server's transport differs from the lockfile — the most
/// security-relevant change (a swapped URL is a redirection, a swapped command a
/// rebound subprocess). Variants record the structural shape without repeating
/// the raw URL/command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpTransportChange {
    /// The transport *kind* changed (e.g. `stdio` → `url`).
    KindChanged {
        /// Previous kind, lowercase: `"url"` / `"stdio"` / `"unknown"`.
        previous: String,
        /// Current kind.
        current: String,
    },
    /// Both `url`, stored (redacted) URL bytes differ.
    UrlChanged,
    /// Both `url`, `userinfo_hash` differs — credential added / removed / swapped.
    UserinfoAdded,
    UserinfoRemoved,
    UserinfoSwapped,
    /// Both `stdio`, command bytes differ.
    CommandChanged,
    /// Both `stdio`, arg list differs.
    ArgsChanged,
    /// Both `stdio`, env changed; per-variable detail in
    /// [`McpServerDrift::env_changes`].
    EnvChanged,
}

/// What kind of change a tool list saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpToolsChangeKind {
    /// Same tool set, different recorded order (defensive — lists are sorted on
    /// parse, so in practice `Set` fires when declared tools change).
    Reordered,
    /// One or more tools were added.
    Added,
    /// One or more tools were removed.
    Removed,
    /// Both sides have tools but the set itself differs (additions and
    /// removals together).
    Set,
}

/// One server's drift entry — the headline change plus per-field detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerDriftEntry {
    /// The server's name (the key in the config's `mcpServers` / `servers`
    /// object). Same on both sides for a `Changed` entry.
    pub name: String,
    /// Repo-relative path of the config the *current* inventory pulled the
    /// server from; for a `Removed` server, the lockfile's `source_config`.
    pub source_config: String,
    /// The transport changes detected, sorted for determinism.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transport_changes: Vec<McpTransportChange>,
    /// Per-variable env changes (stdio transport only), sorted by `name`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_changes: Vec<McpEnvChange>,
    /// What kind of tool change, if any. `None` when the tool list is byte-equal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools_change: Option<McpToolsChangeKind>,
    /// Tool names added by the current inventory, sorted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools_added: Vec<String>,
    /// Tool names removed since the lockfile was taken, sorted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools_removed: Vec<String>,
}

impl McpServerDriftEntry {
    /// `true` when the entry records no per-field changes — used to reject an
    /// empty `Changed` drift (defensive).
    fn is_empty(&self) -> bool {
        self.transport_changes.is_empty()
            && self.env_changes.is_empty()
            && self.tools_change.is_none()
            && self.tools_added.is_empty()
            && self.tools_removed.is_empty()
    }
}

/// One drift between the current inventory and the loaded lockfile. A
/// `Vec<McpDrift>` is what `mcp verify` / `mcp diff` consume, sorted
/// `SchemaUpgradeRequired` (at most one) → `Removed` → `Added` → `Changed`, each
/// by name — `Removed` first as the most security-relevant case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpDrift {
    /// A server in the lockfile is no longer in the current inventory.
    Removed {
        /// The server's name as the lockfile recorded it.
        name: String,
        /// Repo-relative source config the lockfile recorded.
        source_config: String,
    },
    /// A server in the current inventory is not in the lockfile.
    Added {
        /// The server's name.
        name: String,
        /// Repo-relative source config the current inventory found.
        source_config: String,
        /// The new server's declared tools (sorted, de-duplicated), so a policy
        /// gate (`scan.mcp_allowed_tools`) can inspect its surface — mirroring
        /// `tools_added` on `Changed`. Names only (printable/serializable).
        /// Skipped on serialization when empty (a structural extension, not a
        /// schema change), so an older drift doc round-trips with `tools: []`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tools: Vec<String>,
    },
    /// A server present on both sides changed (per-server `hash` differs); the
    /// entry holds the per-field detail.
    Changed(McpServerDriftEntry),
    /// The lockfile parses but was written with an older `format_version` whose
    /// hashing rules differ. Emitted as a single entry (re-lock once) instead of
    /// phantom-drifting every server. See [`compute_drift`].
    SchemaUpgradeRequired {
        /// The `format_version` value the lockfile carried.
        from_version: u32,
        /// The `format_version` this build of tirith writes
        /// ([`MCP_LOCK_FORMAT_VERSION`]).
        to_version: u32,
    },
}

impl McpDrift {
    /// Deterministic sort key: kind-bucket (SchemaUpgradeRequired=0, Removed=1,
    /// Added=2, Changed=3), then `(name, source_config)`. SchemaUpgradeRequired
    /// has empty name fields but there is at most one, so it can't tie.
    fn sort_key(&self) -> (u8, String, String) {
        match self {
            McpDrift::SchemaUpgradeRequired { .. } => (0, String::new(), String::new()),
            McpDrift::Removed {
                name,
                source_config,
            } => (1, name.clone(), source_config.clone()),
            McpDrift::Added {
                name,
                source_config,
                ..
            } => (2, name.clone(), source_config.clone()),
            McpDrift::Changed(entry) => (3, entry.name.clone(), entry.source_config.clone()),
        }
    }

    /// The server name this drift refers to, or `None` for the schema-wide
    /// [`McpDrift::SchemaUpgradeRequired`]. `Option` rather than an empty-string
    /// sentinel because `{"": {...}}` is a legitimate empty-name server; returning
    /// `None` keeps the schema signal from shadowing it in name-based filtering.
    pub fn name(&self) -> Option<&str> {
        match self {
            McpDrift::Removed { name, .. } => Some(name),
            McpDrift::Added { name, .. } => Some(name),
            McpDrift::Changed(entry) => Some(&entry.name),
            McpDrift::SchemaUpgradeRequired { .. } => None,
        }
    }
}

/// Compute the structured drift between the current inventory and the previously
/// written lockfile.
///
/// Fast path: if the current would-be `inventory_hash` byte-equals the lockfile's,
/// nothing changed — empty drift, no per-server work. Slow path: a merge walk
/// over the `(name, source_config)`-sorted sides emits `Added`/`Removed`, and
/// `Changed` (via `compute_changed_entry`) when a per-server `content_hash`
/// differs. `content_hash` excludes `source_config`, so moving an unchanged
/// server between configs is a non-event.
///
/// The result is sorted ([`McpDrift::sort_key`]). Privacy: entries carry only
/// names (server / env-var / tool) — the lockfile already salted-hashes env
/// values and URL userinfos, so drift sees only that a hash changed.
pub fn compute_drift(current: &McpInventory, lock: &McpLockfile) -> Vec<McpDrift> {
    // Legacy v4 migration path. A v4 lockfile's stored hashes were computed
    // without `tools_declared`, so a direct v5 comparison would phantom-drift
    // every server. We compare under v4-compatible semantics on both sides (see
    // [`McpServerEntry::content_hash_v4`]) so REAL drift stays visible across the
    // boundary — closing the window where a malicious change could otherwise slip
    // silently into the operator's `--force` regeneration — with the
    // `SchemaUpgradeRequired` prompt riding on top to re-lock once.
    if matches!(lock.schema_state, LockfileSchema::LegacyV4Migration) {
        let mut drifts = compute_drift_v4(current, lock);
        // Always emit the migration prompt (sort key `(0, "", "")` → first),
        // even when the v4 comparison is clean.
        drifts.push(McpDrift::SchemaUpgradeRequired {
            from_version: lock.format_version,
            to_version: MCP_LOCK_FORMAT_VERSION,
        });
        drifts.sort_by_key(McpDrift::sort_key);
        return drifts;
    }

    // Fast path: equal inventory hashes → nothing changed.
    let current_lock = McpLockfile::from_inventory(current);
    if current_lock.inventory_hash == lock.inventory_hash {
        return Vec::new();
    }

    // Merge walk over the `(name, source_config)`-sorted sides, O(n + m).
    let mut drifts: Vec<McpDrift> = Vec::new();
    let mut i = 0usize; // index into current_lock.servers
    let mut j = 0usize; // index into lock.servers

    while i < current_lock.servers.len() && j < lock.servers.len() {
        let cur = &current_lock.servers[i];
        let prev = &lock.servers[j];

        let key_cur = (&cur.name, &cur.source_config);
        let key_prev = (&prev.name, &prev.source_config);

        match key_cur.cmp(&key_prev) {
            std::cmp::Ordering::Less => {
                // Only on the current side → Added (tools ride along for a
                // policy gate, mirroring `tools_added` on Changed).
                drifts.push(McpDrift::Added {
                    name: cur.name.clone(),
                    source_config: cur.source_config.clone(),
                    tools: cur.tools.clone(),
                });
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                // Only in the lockfile → Removed.
                drifts.push(McpDrift::Removed {
                    name: prev.name.clone(),
                    source_config: prev.source_config.clone(),
                });
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                // Same key: differing hashes → classify the per-field change.
                if cur.hash != prev.hash {
                    if let Some(entry) = compute_changed_entry(cur, prev) {
                        drifts.push(McpDrift::Changed(entry));
                    }
                }
                i += 1;
                j += 1;
            }
        }
    }
    while i < current_lock.servers.len() {
        let cur = &current_lock.servers[i];
        drifts.push(McpDrift::Added {
            name: cur.name.clone(),
            source_config: cur.source_config.clone(),
            tools: cur.tools.clone(),
        });
        i += 1;
    }
    while j < lock.servers.len() {
        let prev = &lock.servers[j];
        drifts.push(McpDrift::Removed {
            name: prev.name.clone(),
            source_config: prev.source_config.clone(),
        });
        j += 1;
    }

    drifts.sort_by_key(McpDrift::sort_key);
    drifts
}

/// Per-server drift under v4 hashing semantics (each hash via
/// [`McpServerEntry::content_hash_v4`], which excludes `tools_declared`). Used by
/// [`compute_drift`] for a [`LockfileSchema::LegacyV4Migration`] lockfile. Returns
/// an UNSORTED vector — the caller appends the migration prompt and sorts once.
/// Walk logic is identical to the v5 slow path; only the hash function differs.
fn compute_drift_v4(current: &McpInventory, lock: &McpLockfile) -> Vec<McpDrift> {
    // Recompute v4 hashes onto a position-indexed side-table so the walk can
    // compare them without mutating the v5 hashes in `current_lock.servers`.
    let current_lock = McpLockfile::from_inventory(current);
    let current_hashes_v4: Vec<String> = current_lock.servers.iter().map(server_v4_hash).collect();
    let lock_hashes_v4: Vec<String> = lock.servers.iter().map(server_v4_hash).collect();

    // Fast path: aligned server lists with all v4 hashes equal → no real drift,
    // only the migration prompt fires.
    if current_lock.servers.len() == lock.servers.len()
        && current_hashes_v4 == lock_hashes_v4
        && current_lock
            .servers
            .iter()
            .zip(lock.servers.iter())
            .all(|(a, b)| a.name == b.name && a.source_config == b.source_config)
    {
        return Vec::new();
    }

    let mut drifts: Vec<McpDrift> = Vec::new();
    let mut i = 0usize;
    let mut j = 0usize;

    while i < current_lock.servers.len() && j < lock.servers.len() {
        let cur = &current_lock.servers[i];
        let prev = &lock.servers[j];

        let key_cur = (&cur.name, &cur.source_config);
        let key_prev = (&prev.name, &prev.source_config);

        match key_cur.cmp(&key_prev) {
            std::cmp::Ordering::Less => {
                drifts.push(McpDrift::Added {
                    name: cur.name.clone(),
                    source_config: cur.source_config.clone(),
                    tools: cur.tools.clone(),
                });
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                drifts.push(McpDrift::Removed {
                    name: prev.name.clone(),
                    source_config: prev.source_config.clone(),
                });
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                // Compare v4 hashes; `compute_changed_entry` diffs the per-field
                // detail from the structured fields (not a hash), so it works
                // identically under v4/v5 — v4 only hides the `tools_declared`
                // flip, which has no dedicated drift field anyway.
                if current_hashes_v4[i] != lock_hashes_v4[j] {
                    if let Some(entry) = compute_changed_entry(cur, prev) {
                        drifts.push(McpDrift::Changed(entry));
                    }
                }
                i += 1;
                j += 1;
            }
        }
    }
    while i < current_lock.servers.len() {
        let cur = &current_lock.servers[i];
        drifts.push(McpDrift::Added {
            name: cur.name.clone(),
            source_config: cur.source_config.clone(),
            tools: cur.tools.clone(),
        });
        i += 1;
    }
    while j < lock.servers.len() {
        let prev = &lock.servers[j];
        drifts.push(McpDrift::Removed {
            name: prev.name.clone(),
            source_config: prev.source_config.clone(),
        });
        j += 1;
    }

    drifts
}

/// Re-derive a v4-compatible per-server hash from an [`McpLockServer`] by copying
/// its fields into a transient [`McpServerEntry`] and calling `content_hash_v4`.
fn server_v4_hash(server: &McpLockServer) -> String {
    McpServerEntry {
        name: server.name.clone(),
        transport: server.transport.clone(),
        tools: server.tools.clone(),
        tools_declared: server.tools_declared,
        source_config: server.source_config.clone(),
    }
    .content_hash_v4()
}

/// Classify the field-level change between two servers sharing a
/// `(name, source_config)` but differing in `hash`. `Some(entry)` when a change
/// is found; `None` only in the defensive no-cause case (an empty `Changed` would
/// be noise).
fn compute_changed_entry(
    current: &McpLockServer,
    previous: &McpLockServer,
) -> Option<McpServerDriftEntry> {
    let mut transport_changes: Vec<McpTransportChange> = Vec::new();
    let mut env_changes: Vec<McpEnvChange> = Vec::new();

    match (&current.transport, &previous.transport) {
        (
            McpTransport::Url {
                url: cur_url,
                userinfo_hash: cur_userinfo,
            },
            McpTransport::Url {
                url: prev_url,
                userinfo_hash: prev_userinfo,
            },
        ) => {
            if cur_url != prev_url {
                transport_changes.push(McpTransportChange::UrlChanged);
            }
            match (cur_userinfo.as_deref(), prev_userinfo.as_deref()) {
                (None, None) => {}
                (Some(_), None) => {
                    transport_changes.push(McpTransportChange::UserinfoAdded);
                }
                (None, Some(_)) => {
                    transport_changes.push(McpTransportChange::UserinfoRemoved);
                }
                (Some(a), Some(b)) if a != b => {
                    transport_changes.push(McpTransportChange::UserinfoSwapped);
                }
                _ => {}
            }
        }
        (
            McpTransport::Stdio {
                command: cur_cmd,
                args: cur_args,
                env: cur_env,
            },
            McpTransport::Stdio {
                command: prev_cmd,
                args: prev_args,
                env: prev_env,
            },
        ) => {
            if cur_cmd != prev_cmd {
                transport_changes.push(McpTransportChange::CommandChanged);
            }
            if cur_args != prev_args {
                transport_changes.push(McpTransportChange::ArgsChanged);
            }
            env_changes = diff_env(cur_env, prev_env);
            if !env_changes.is_empty() {
                transport_changes.push(McpTransportChange::EnvChanged);
            }
        }
        (cur, prev) => {
            // Kind changed — encode before/after so reports can render "stdio → url".
            transport_changes.push(McpTransportChange::KindChanged {
                previous: transport_kind_name(prev).to_string(),
                current: transport_kind_name(cur).to_string(),
            });
        }
    }

    let (tools_change, tools_added, tools_removed) = diff_tools(&current.tools, &previous.tools);

    // Sort transport changes (by serialized form, stable across variant
    // additions) so equal drifts compare equal regardless of detection order.
    transport_changes
        .sort_by_key(|c| serde_json::to_string(c).unwrap_or_else(|_| format!("{c:?}")));

    let entry = McpServerDriftEntry {
        name: current.name.clone(),
        source_config: current.source_config.clone(),
        transport_changes,
        env_changes,
        tools_change,
        tools_added,
        tools_removed,
    };

    if entry.is_empty() {
        None
    } else {
        Some(entry)
    }
}

/// Lowercase short name of a transport kind, used in drift reports.
fn transport_kind_name(t: &McpTransport) -> &'static str {
    match t {
        McpTransport::Url { .. } => "url",
        McpTransport::Stdio { .. } => "stdio",
        McpTransport::Unknown => "unknown",
    }
}

/// Diff two name-sorted env lists via a merge walk (O(n + m)); returned entries
/// are sorted by `name`.
fn diff_env(current: &[McpEnvEntry], previous: &[McpEnvEntry]) -> Vec<McpEnvChange> {
    let mut out: Vec<McpEnvChange> = Vec::new();
    let mut i = 0usize;
    let mut j = 0usize;
    while i < current.len() && j < previous.len() {
        let cur = &current[i];
        let prev = &previous[j];
        match cur.name.cmp(&prev.name) {
            std::cmp::Ordering::Less => {
                out.push(McpEnvChange::Added {
                    name: cur.name.clone(),
                });
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                out.push(McpEnvChange::Removed {
                    name: prev.name.clone(),
                });
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                if cur.value_hash != prev.value_hash {
                    out.push(McpEnvChange::ValueHashChanged {
                        name: cur.name.clone(),
                    });
                }
                i += 1;
                j += 1;
            }
        }
    }
    while i < current.len() {
        out.push(McpEnvChange::Added {
            name: current[i].name.clone(),
        });
        i += 1;
    }
    while j < previous.len() {
        out.push(McpEnvChange::Removed {
            name: previous[j].name.clone(),
        });
        j += 1;
    }
    out
}

/// Diff two tool lists into (kind, added, removed). Lists are sorted on parse, so
/// a same-set/different-order case only arises from a hand-built inventory
/// (`Reordered`, recorded for completeness).
fn diff_tools(
    current: &[String],
    previous: &[String],
) -> (Option<McpToolsChangeKind>, Vec<String>, Vec<String>) {
    if current == previous {
        return (None, Vec::new(), Vec::new());
    }

    // Same set, different order → Reordered.
    let mut cur_sorted = current.to_vec();
    let mut prev_sorted = previous.to_vec();
    cur_sorted.sort();
    prev_sorted.sort();
    if cur_sorted == prev_sorted {
        return (Some(McpToolsChangeKind::Reordered), Vec::new(), Vec::new());
    }

    let cur_set: std::collections::BTreeSet<&str> = current.iter().map(|s| s.as_str()).collect();
    let prev_set: std::collections::BTreeSet<&str> = previous.iter().map(|s| s.as_str()).collect();
    let added: Vec<String> = cur_set
        .difference(&prev_set)
        .map(|s| (*s).to_string())
        .collect();
    let removed: Vec<String> = prev_set
        .difference(&cur_set)
        .map(|s| (*s).to_string())
        .collect();

    let kind = match (added.is_empty(), removed.is_empty()) {
        (false, true) => McpToolsChangeKind::Added,
        (true, false) => McpToolsChangeKind::Removed,
        _ => McpToolsChangeKind::Set,
    };
    (Some(kind), added, removed)
}

/// Load and parse a lockfile from disk. `Err` cases via [`McpLockLoadError`] so a
/// caller can present each differently: `NotFound` (no file), `Io` (present but
/// unreadable), `Parse` (invalid JSON / schema).
pub fn load_lockfile(path: &Path) -> Result<McpLockfile, McpLockLoadError> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(McpLockLoadError::NotFound);
        }
        Err(e) => {
            // Capture only the category kind, not the io-error Display (privacy —
            // see [`McpLockLoadError::Io`]).
            return Err(McpLockLoadError::Io {
                kind: McpLockIoKind::from_io_kind(e.kind()),
            });
        }
    };
    parse_lockfile(&content)
}

/// Parse a lockfile from its on-disk JSON.
///
/// **Privacy:** a failed parse captures only `serde_json::Error`'s `line`/`column`
/// (both `usize`), not its `Display` message — that can echo the offending JSON
/// value, and `.tirith/mcp.lock` carries secret-shaped data (hashes, a
/// committed credential the redaction protects). Drift detection is unaffected.
///
/// **Schema version:** `format_version` is checked against
/// [`MCP_LOCK_FORMAT_VERSION`]; a mismatch yields
/// [`McpLockLoadError::UnsupportedVersion`] (distinct from `Parse`) so the CLI can
/// offer a precise re-lock/upgrade message. A legacy v3-shape file (missing
/// fields default) is still caught here via its preserved `format_version: 3`.
///
/// **v4 → v5 migration:** a `format_version: 4` lockfile (same on-disk shape, only
/// the hashes differ) is ACCEPTED and tagged
/// [`LockfileSchema::LegacyV4Migration`]; the recompute-on-parse pass below makes
/// it v5-coherent internally, and [`compute_drift`] returns a single
/// [`McpDrift::SchemaUpgradeRequired`] (re-lock once).
///
/// **Server ordering:** `servers` is sorted by `(name, source_config)` here (the
/// `from_inventory` invariant) so [`compute_drift`]'s merge walk — which assumes
/// sorted sides — works for every caller, even a hand-edited lockfile that landed
/// out of order.
pub fn parse_lockfile(content: &str) -> Result<McpLockfile, McpLockLoadError> {
    // Two-pass parse. First pass probes ONLY `format_version` via a minimal
    // struct, so a legacy-shape file (e.g. v3 raw `value` env entries) surfaces as
    // `UnsupportedVersion`, not the misleading `Parse` a full deserialize would
    // produce by failing on the missing field first.
    #[derive(serde::Deserialize)]
    struct FormatProbe {
        format_version: u32,
    }

    // First pass: a failure here is invalid JSON or no `format_version` — real
    // `Parse` failures (line/column only; the Display can echo content).
    let probe: FormatProbe =
        serde_json::from_str(content).map_err(|e| McpLockLoadError::Parse {
            line: e.line(),
            column: e.column(),
        })?;

    // Schema-version gate, BEFORE the full deserialize. v4 is the carve-out
    // (identical on-disk shape) — accepted and tagged for migration; see the docs.
    let schema_state = match probe.format_version {
        v if v == MCP_LOCK_FORMAT_VERSION => LockfileSchema::Current,
        4 => LockfileSchema::LegacyV4Migration,
        _ => {
            return Err(McpLockLoadError::UnsupportedVersion {
                found: probe.format_version,
                supported: MCP_LOCK_FORMAT_VERSION,
            });
        }
    };

    // Second pass: full deserialize. The version is current (or v4, identical
    // shape), so any failure here is genuine corruption within the v5 schema.
    let mut lock: McpLockfile =
        serde_json::from_str(content).map_err(|e| McpLockLoadError::Parse {
            line: e.line(),
            column: e.column(),
        })?;
    lock.schema_state = schema_state;
    // Defensive sort at the parse boundary (a hand-edited lockfile could land out
    // of order) so `compute_drift`'s merge walk holds for every caller.
    lock.servers.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.source_config.cmp(&b.source_config))
    });

    // Recompute every hash from the lockfile's DATA — the deserialized
    // `hash`/`inventory_hash` are discarded, so a hand-edited lockfile that
    // forged consistent hashes can't silence drift (both `compute_drift`'s
    // fast-path short-circuit and its per-server comparison read these). Cheap
    // relative to the file IO just done.
    for server in &mut lock.servers {
        let recomputed = McpServerEntry {
            name: server.name.clone(),
            transport: server.transport.clone(),
            tools: server.tools.clone(),
            tools_declared: server.tools_declared,
            source_config: server.source_config.clone(),
        }
        .content_hash();
        server.hash = recomputed;
    }
    lock.inventory_hash = compute_inventory_hash(&lock.servers);

    Ok(lock)
}

/// Coarse category of a lockfile io failure — encoded explicitly rather than
/// carrying the non-exhaustive `std::io::ErrorKind`. Drives a category-only
/// `Display` (never the inner io string), same privacy invariant as `Parse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpLockIoKind {
    /// `PermissionDenied` — the most operator-actionable case (a mode bit).
    PermissionDenied,
    /// Any other io-error category (folded in so a new std variant isn't a break).
    Other,
}

impl McpLockIoKind {
    /// Map an `std::io::Error` to its tirith-side category.
    fn from_io_kind(kind: std::io::ErrorKind) -> Self {
        match kind {
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            _ => Self::Other,
        }
    }
}

/// Why a lockfile could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpLockLoadError {
    /// The file does not exist (caller decides whether this is fatal).
    NotFound,
    /// The file exists but cannot be read. Carries only a kind — the inner
    /// `io::Error` string can include path fragments (`os error 13: /home/...`),
    /// so it's folded out at the boundary (same privacy invariant as `Parse`).
    Io { kind: McpLockIoKind },
    /// Read but doesn't parse. Carries only line/column (both `usize`, can't echo
    /// the JSON value) — see [`parse_lockfile`]. Safe to `Display`.
    Parse { line: usize, column: usize },
    /// Parsed and schema-shaped, but `format_version` ≠ [`MCP_LOCK_FORMAT_VERSION`].
    /// Distinct from `Parse` for a precise re-lock/upgrade message; both fields
    /// are `u32`, safe to `Display`.
    UnsupportedVersion {
        /// The `format_version` value the lockfile carried.
        found: u32,
        /// The version this build of tirith supports
        /// ([`MCP_LOCK_FORMAT_VERSION`]).
        supported: u32,
    },
}

impl std::fmt::Display for McpLockLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpLockLoadError::NotFound => write!(f, "lockfile not found"),
            // Category-only — the inner io message is not surfaced (privacy).
            McpLockLoadError::Io { kind } => match kind {
                McpLockIoKind::PermissionDenied => {
                    write!(f, "could not read lockfile (permission denied)")
                }
                McpLockIoKind::Other => write!(f, "could not read lockfile (other io error)"),
            },
            // Line/column only — never the parser's message string (privacy).
            McpLockLoadError::Parse { line, column } => {
                write!(f, "could not parse lockfile (line {line}, column {column})")
            }
            McpLockLoadError::UnsupportedVersion { found, supported } => write!(
                f,
                "lockfile schema version {found} is not supported by this build of tirith \
                 (supported: {supported}); re-run `tirith mcp lock` to refresh the lockfile, \
                 or upgrade tirith to a build that understands version {found}"
            ),
        }
    }
}

impl std::error::Error for McpLockLoadError {}

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
                userinfo_hash: None,
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
        // higher-risk surface) is the one recorded. The bare-host URL is
        // canonicalized to its trailing-`/` form (the same shape it would
        // take after userinfo stripping, so removing a credential never
        // surfaces as a spurious `UrlChanged`).
        let content =
            r#"{ "mcpServers": { "both": { "url": "https://x.example", "command": "node" } } }"#;
        let entries = parse_mcp_config(content, ".mcp.json").unwrap();
        assert_eq!(
            entries[0].transport,
            McpTransport::Url {
                url: "https://x.example/".to_string(),
                userinfo_hash: None,
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
            tools_declared: true,
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
            tools_declared: true,
            source_config: ".mcp.json".into(),
        };
        let changed = McpServerEntry {
            transport: McpTransport::Url {
                url: "https://x.example".into(),
                userinfo_hash: None,
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
            tools_declared: true,
            source_config: ".mcp.json".into(),
        };
        let b = McpServerEntry {
            tools_declared: true,
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
                    tools_declared: true,
                    source_config: ".mcp.json".into(),
                },
                McpServerEntry {
                    name: "alpha".into(),
                    transport: McpTransport::Url {
                        url: "https://a.example".into(),
                        userinfo_hash: None,
                    },
                    tools: vec!["t".into()],
                    tools_declared: true,
                    source_config: ".mcp.json".into(),
                },
            ],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
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
                tools_declared: true,
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let hash_before = McpLockfile::from_inventory(&inventory).inventory_hash;

        // Mutate the single server's transport.
        inventory.servers[0].transport = McpTransport::Url {
            url: "https://new.example".into(),
            userinfo_hash: None,
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

    // Finding A — `from_inventory` sorts before hashing, so the lockfile (and its
    // inventory hash) is identical regardless of discovery order.

    #[test]
    fn from_inventory_sorts_servers_regardless_of_input_order() {
        let alpha = McpServerEntry {
            name: "alpha".into(),
            transport: McpTransport::Url {
                url: "https://a.example".into(),
                userinfo_hash: None,
            },
            tools: vec!["t".into()],
            tools_declared: true,
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
            tools_declared: true,
            source_config: ".vscode/mcp.json".into(),
        };

        // Same two servers, opposite inventory order.
        let in_order = McpInventory {
            servers: vec![alpha.clone(), zeta.clone()],
            configs: vec![".mcp.json".into(), ".vscode/mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let reversed = McpInventory {
            servers: vec![zeta, alpha],
            configs: vec![".vscode/mcp.json".into(), ".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
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
                userinfo_hash: None,
            },
            tools: vec![],
            tools_declared: true,
            source_config: source.into(),
        };
        let forward = McpInventory {
            servers: vec![mk(".mcp.json"), mk(".vscode/mcp.json")],
            configs: vec![],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let backward = McpInventory {
            servers: vec![mk(".vscode/mcp.json"), mk(".mcp.json")],
            configs: vec![],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let lock_f = McpLockfile::from_inventory(&forward);
        let lock_b = McpLockfile::from_inventory(&backward);
        assert_eq!(lock_f.servers[0].source_config, ".mcp.json");
        assert_eq!(lock_f.servers[1].source_config, ".vscode/mcp.json");
        assert_eq!(lock_f, lock_b);
    }

    // Finding B — a symlinked config (or one under a symlinked dir) is rejected:
    // discovery is repo-local, and a symlink can point anywhere.

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

    // Finding C — a stdio server's `env` is captured and an `env` change drifts
    // (it is part of the per-server content hash).

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
            tools_declared: true,
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
            rejected_configs: vec![],
        };
        let inv_changed = McpInventory {
            servers: vec![value_changed],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        assert_ne!(
            McpLockfile::from_inventory(&inv_base).inventory_hash,
            McpLockfile::from_inventory(&inv_changed).inventory_hash,
            "an env change must surface as a different inventory hash"
        );
    }

    #[test]
    fn lockfile_format_version_is_5() {
        // v5 folds `tools_declared` into the per-server `content_hash`.
        // Pre-v5 a server flipping `"tools": []` to omitted silently passed
        // drift detection because both shapes collapsed into the same
        // canonical empty `tools: Vec<String>`; v5 captures the flip in
        // the hash. v4 lockfiles are accepted at parse time and tagged
        // with `LockfileSchema::LegacyV4Migration` so `compute_drift`
        // surfaces a one-time migration prompt instead of phantom drift.
        assert_eq!(MCP_LOCK_FORMAT_VERSION, 5);
        let lock = McpLockfile::from_inventory(&McpInventory::default());
        assert_eq!(lock.format_version, 5);
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
                tools_declared: true,
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let lock = McpLockfile::from_inventory(&inventory);
        let parsed: McpLockfile =
            serde_json::from_str(&lock.render()).expect("lockfile with env must round-trip");
        assert_eq!(parsed, lock);
    }

    // Finding E — env raw values must not be persisted (they're commonly secrets
    // and the lockfile is committed); only a salted hash is stored.

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
                tools_declared: true,
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
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
            rejected_configs: vec![],
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

    // Finding D — the per-server hash is collision-free: length-prefixing every
    // component distinguishes `["a","b"]` from `["ab"]` / `["a\0b"]`.

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
            tools_declared: true,
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
                userinfo_hash: None,
            },
            tools: tools.into_iter().map(String::from).collect(),
            tools_declared: true,
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
            tools_declared: true,
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
            tools_declared: true,
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

    // Finding G — a URL transport's userinfo must not be persisted:
    // `https://user:token@host/` is stored as `https://host/` plus a salted
    // `userinfo_hash` (omitted when absent), folded into the content hash so a
    // change drifts.

    /// Credential-shaped (high-entropy, unique) URL userinfo probes. None of
    /// these byte sequences may appear in the rendered lockfile. They are
    /// distinctive on purpose so a substring scan over the rendered JSON
    /// cannot trip on incidental matches elsewhere (hashes, names, etc.).
    const URL_USERINFO_LEAK_PROBES: &[(&str, &str)] = &[
        // (declared URL, expected raw-credential substring)
        (
            "https://admin:ghp_supersecret_PAT_token_42@mcp.example.com/sse",
            "admin:ghp_supersecret_PAT_token_42",
        ),
        (
            "https://svc-account:DO_NOT_LEAK_xY7q@api.example.com:8443/v1/mcp",
            "svc-account:DO_NOT_LEAK_xY7q",
        ),
        (
            "https://bearer-only:ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@host.example/sse",
            "bearer-only:ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
    ];

    #[test]
    fn url_raw_userinfo_never_appears_in_rendered_lockfile() {
        // Plant servers whose URLs carry credential-shaped userinfo
        // (Basic Auth username:password). After rendering, NONE of the raw
        // userinfo byte sequences may show up. The salted hash is what is
        // persisted.
        let servers: Vec<McpServerEntry> = URL_USERINFO_LEAK_PROBES
            .iter()
            .enumerate()
            .map(|(i, (url, _))| {
                let server_name = format!("svc-{i}");
                let (redacted, hash) = redact_url_userinfo(&server_name, url);
                McpServerEntry {
                    name: server_name,
                    transport: McpTransport::Url {
                        url: redacted,
                        userinfo_hash: hash,
                    },
                    tools: vec![],
                    tools_declared: true,
                    source_config: ".mcp.json".into(),
                }
            })
            .collect();
        let inventory = McpInventory {
            servers,
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let rendered = McpLockfile::from_inventory(&inventory).render();

        for (declared_url, raw_credential) in URL_USERINFO_LEAK_PROBES {
            assert!(
                !rendered.contains(raw_credential),
                "raw userinfo {raw_credential:?} (from {declared_url:?}) leaked into the \
                 rendered lockfile:\n{rendered}"
            );
            // And the literal `@` userinfo boundary cannot appear inside an
            // https URL — every captured URL must have been redacted.
            assert!(
                !rendered.contains("@mcp.example.com"),
                "userinfo `@` boundary leaked into the rendered lockfile:\n{rendered}"
            );
            assert!(
                !rendered.contains("@api.example.com"),
                "userinfo `@` boundary leaked into the rendered lockfile:\n{rendered}"
            );
            assert!(
                !rendered.contains("@host.example"),
                "userinfo `@` boundary leaked into the rendered lockfile:\n{rendered}"
            );
        }
        // Every redacted URL exposes a `userinfo_hash` field — the wire
        // shape proof of the redaction.
        assert!(
            rendered.contains("\"userinfo_hash\""),
            "rendered lockfile must serialize a userinfo_hash per URL with credentials"
        );
    }

    #[test]
    fn url_with_userinfo_redacted_url_stored_in_lockfile() {
        // The redacted URL stored in the lockfile is exactly the source URL
        // with `user[:password]` stripped — host, port, path, and query all
        // preserved. Verify byte-for-byte against url::Url's normalized form
        // of the same userinfo-free URL.
        let (redacted, hash) = redact_url_userinfo(
            "svc",
            "https://user:token@host.example:8443/path/to/mcp?x=1",
        );
        assert_eq!(redacted, "https://host.example:8443/path/to/mcp?x=1");
        assert!(hash.is_some(), "userinfo present → hash is Some");

        // Username-only (no password) is still userinfo and is still redacted.
        let (redacted, hash) = redact_url_userinfo("svc", "https://only-user@host.example/path");
        assert_eq!(redacted, "https://host.example/path");
        assert!(hash.is_some());

        // Password-only (`:token@`) is also userinfo and is still redacted.
        let (redacted, hash) = redact_url_userinfo("svc", "https://:token-only@host.example/p");
        assert_eq!(redacted, "https://host.example/p");
        assert!(hash.is_some());
    }

    #[test]
    fn url_without_userinfo_stored_canonical_with_no_hash() {
        // A URL that carried no userinfo is stored in the canonical
        // `url::Url::as_str()` form (so the bytes match the shape the
        // userinfo-strip path produces) and `userinfo_hash` is None (so it
        // is omitted on serialization, not serialized as null). Two
        // categories of inputs:
        //   * `(input, expected_canonical)` for URLs `url::Url` accepts;
        //   * unparseable strings, which fall back to the byte-verbatim
        //     defensive branch.
        let parseable: &[(&str, &str)] = &[
            // Bare-host URLs gain the `url::Url`-default trailing `/`.
            ("https://x.example", "https://x.example/"),
            // URLs that are already canonical round-trip unchanged.
            ("https://mcp.example.com/sse", "https://mcp.example.com/sse"),
            (
                "https://host:8443/path/to/mcp?x=1&y=2",
                "https://host:8443/path/to/mcp?x=1&y=2",
            ),
            ("https://host.example/", "https://host.example/"),
        ];
        for (input, expected) in parseable {
            let (redacted, hash) = redact_url_userinfo("svc", input);
            assert_eq!(
                redacted, *expected,
                "a no-userinfo URL must canonicalize through url::Url::as_str(): \
                 input={input}"
            );
            assert!(
                hash.is_none(),
                "a no-userinfo URL must have userinfo_hash = None: {input}"
            );
        }

        // Unparseable strings are still held byte-verbatim — that is the
        // defensive fallback for inputs `url::Url` cannot parse.
        let (redacted, hash) = redact_url_userinfo("svc", "not a real url at all");
        assert_eq!(
            redacted, "not a real url at all",
            "an unparseable URL must fall through to the byte-verbatim branch"
        );
        assert!(hash.is_none());

        // And on serialization, `userinfo_hash` is OMITTED — not written as
        // `"userinfo_hash": null` — for a no-userinfo URL.
        let inventory = McpInventory {
            servers: vec![McpServerEntry {
                name: "s".into(),
                transport: McpTransport::Url {
                    url: "https://mcp.example.com/sse".into(),
                    userinfo_hash: None,
                },
                tools: vec![],
                tools_declared: true,
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let rendered = McpLockfile::from_inventory(&inventory).render();
        assert!(
            !rendered.contains("userinfo_hash"),
            "userinfo_hash must be omitted (not serialized as null) when no userinfo \
             is present:\n{rendered}"
        );
    }

    #[test]
    fn url_without_userinfo_canonicalization_pins_shape() {
        // Regression pin for the canonical-shape contract: a bare-host URL
        // **always** canonicalizes to the same trailing-`/` form as the
        // userinfo-stripped version. This is the load-bearing property
        // behind `mcp_verify_userinfo_removal_without_path_does_not_drift`:
        // without it, `mcp lock` stores `https://host/` and a later
        // userinfo-stripped `https://host` source would diff as
        // `UrlChanged` + `UserinfoRemoved` instead of just
        // `UserinfoRemoved`. Pinned explicitly so a future refactor cannot
        // silently bring back the byte-verbatim early-return.
        let (no_user, _) = redact_url_userinfo("s", "https://host");
        let (with_user, _) = redact_url_userinfo("s", "https://user:token@host");
        assert_eq!(no_user, "https://host/");
        assert_eq!(with_user, "https://host/");
        assert_eq!(
            no_user, with_user,
            "no-userinfo and userinfo-stripped forms of the same URL must be \
             byte-identical after redaction"
        );
    }

    #[test]
    fn url_normalized_empty_userinfo_treated_as_no_userinfo() {
        // `url::Url` parses `https://:@host/` and `https://@host/` by
        // discarding the empty userinfo. Our redaction observes
        // `username() == ""` and `password() == None`, treats it as the
        // no-userinfo case, and stores the canonical `url::Url::as_str()`
        // form (which is the userinfo-free equivalent) with no hash.
        for input in ["https://:@host.example/", "https://@host.example/"] {
            let (redacted, hash) = redact_url_userinfo("svc", input);
            assert_eq!(
                redacted, "https://host.example/",
                "an all-empty `:@` / `@` userinfo is normalized away by url::Url \
                 to the bare-host canonical form: input={input}"
            );
            assert!(
                hash.is_none(),
                "an all-empty `:@` / `@` userinfo is normalized away by url::Url \
                 and must be treated as no-userinfo: {input}"
            );
        }
    }

    #[test]
    fn url_userinfo_change_flips_per_server_hash() {
        // The drift property: same server name, same host/path, but a
        // different userinfo → the per-server content hash and therefore
        // the inventory hash must change. This is the same drift behavior
        // that an env-value change has for stdio.
        let mk = |declared_url: &str| {
            let (redacted, hash) = redact_url_userinfo("svc", declared_url);
            McpServerEntry {
                name: "svc".into(),
                transport: McpTransport::Url {
                    url: redacted,
                    userinfo_hash: hash,
                },
                tools: vec![],
                tools_declared: true,
                source_config: ".mcp.json".into(),
            }
        };
        let with_token_a = mk("https://user:tokenA@host.example/sse");
        let with_token_b = mk("https://user:tokenB@host.example/sse");
        let no_token = mk("https://host.example/sse");

        // Token swap flips the content hash.
        assert_ne!(
            with_token_a.content_hash(),
            with_token_b.content_hash(),
            "swapping the userinfo must flip the per-server content hash (drift)"
        );
        // Adding/removing the credential entirely also flips it.
        assert_ne!(
            with_token_a.content_hash(),
            no_token.content_hash(),
            "adding/removing a credential must flip the per-server content hash"
        );

        // And it propagates to the inventory hash.
        let inv_a = McpInventory {
            servers: vec![with_token_a],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let inv_b = McpInventory {
            servers: vec![with_token_b],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        assert_ne!(
            McpLockfile::from_inventory(&inv_a).inventory_hash,
            McpLockfile::from_inventory(&inv_b).inventory_hash,
            "a userinfo change must surface as a different inventory hash"
        );
    }

    #[test]
    fn url_userinfo_hash_is_name_salted() {
        // The hash binds the MCP server's name to the userinfo, so the same
        // Basic Auth token under two different servers hashes differently —
        // a low-entropy userinfo (`u:p`) is not brute-forceable across
        // servers. Same scheme `McpEnvEntry::from_raw` uses, with the
        // server's name as the per-entry salt.
        let (_, a) = redact_url_userinfo("svc-a", "https://u:p@host.example/");
        let (_, b) = redact_url_userinfo("svc-b", "https://u:p@host.example/");
        assert_ne!(
            a, b,
            "the same userinfo under different server names must hash differently \
             (the server name acts as a per-entry salt)"
        );

        // And the hash is exactly sha256(server_name || ':' || userinfo).
        let expected_a = {
            let mut h = Sha256::new();
            h.update(b"svc-a:u:p");
            hex_lower(&h.finalize())
        };
        assert_eq!(a.as_deref(), Some(expected_a.as_str()));

        // Two different userinfo strings under the SAME server name also
        // hash differently — the natural inner-collision-free property.
        let (_, c) = redact_url_userinfo("svc-a", "https://u:p2@host.example/");
        assert_ne!(
            a, c,
            "two different userinfos under the same server name must hash differently"
        );
    }

    #[test]
    fn url_userinfo_hash_delimiter_prevents_boundary_forgery() {
        // The `:` delimiter inside `sha256(server_name || ':' || userinfo)`
        // means `("AB", "c")` hashes `"AB:c"`, never the same byte stream
        // as `("A", "Bc")` (`"A:Bc"`). This is the same property that
        // motivates the `:` delimiter inside `McpEnvEntry::from_raw`.
        let (_, a) = redact_url_userinfo("AB", "https://c@host.example/");
        let (_, b) = redact_url_userinfo("A", "https://Bc@host.example/");
        assert_ne!(
            a, b,
            "the `:` delimiter must prevent server/userinfo boundary forgery"
        );
    }

    #[test]
    fn parse_mcp_config_url_with_userinfo_is_redacted() {
        // End-to-end through the JSON parser: a config that declares a URL
        // with Basic Auth produces a parsed entry whose `url` field has the
        // userinfo stripped, whose `userinfo_hash` is the expected
        // name-salted SHA-256, AND whose rendered lockfile does not contain
        // the raw userinfo bytes anywhere.
        let secret = "admin:ghp_PARSED_LEAK_PROBE_DONOTLEAK";
        let content = format!(
            r#"{{
                "mcpServers": {{
                    "github": {{
                        "url": "https://{secret}@mcp.example.com/sse",
                        "tools": ["search"]
                    }}
                }}
            }}"#
        );
        let entries = parse_mcp_config(&content, ".mcp.json").expect("valid config");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "github");
        match &entries[0].transport {
            McpTransport::Url { url, userinfo_hash } => {
                assert_eq!(
                    url, "https://mcp.example.com/sse",
                    "the stored URL must have the userinfo stripped"
                );
                let expected = {
                    let mut h = Sha256::new();
                    h.update(b"github:");
                    h.update(secret.as_bytes());
                    hex_lower(&h.finalize())
                };
                assert_eq!(
                    userinfo_hash.as_deref(),
                    Some(expected.as_str()),
                    "userinfo_hash must be sha256(server_name || ':' || userinfo)"
                );
            }
            other => panic!("expected Url transport, got {other:?}"),
        }

        // The rendered lockfile descending from this parse must not carry
        // the raw userinfo bytes anywhere.
        let inventory = McpInventory {
            servers: entries,
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let rendered = McpLockfile::from_inventory(&inventory).render();
        assert!(
            !rendered.contains(secret),
            "raw userinfo leaked from parse_mcp_config -> McpLockfile::render():\n{rendered}"
        );
    }

    #[test]
    fn parse_mcp_config_url_no_userinfo_is_unchanged() {
        // The common path: a URL declared with NO userinfo is stored in the
        // canonical `url::Url::as_str()` form (which for an already-canonical
        // input is byte-identical), and `userinfo_hash` is None (and
        // therefore omitted from the serialized lockfile).
        let content = r#"{
            "mcpServers": {
                "remote": {
                    "url": "https://mcp.example.com/sse",
                    "tools": ["search"]
                }
            }
        }"#;
        let entries = parse_mcp_config(content, ".mcp.json").expect("valid config");
        match &entries[0].transport {
            McpTransport::Url { url, userinfo_hash } => {
                assert_eq!(url, "https://mcp.example.com/sse");
                assert!(userinfo_hash.is_none());
            }
            other => panic!("expected Url transport, got {other:?}"),
        }
    }

    #[test]
    fn parse_mcp_config_url_unparseable_is_held_verbatim() {
        // A non-URL-shaped string is not safely parseable — we refuse to
        // mangle it (we cannot identify the userinfo boundary), so it is
        // stored verbatim and `userinfo_hash` is None. The captured URL
        // still flows through the lockfile (so a later `mcp verify` can
        // see the oddity).
        let content = r#"{ "mcpServers": { "weird": { "url": "not://a real url" } } }"#;
        let entries = parse_mcp_config(content, ".mcp.json").expect("valid JSON");
        match &entries[0].transport {
            McpTransport::Url { url, userinfo_hash } => {
                // The string is held verbatim — including the `not://`
                // scheme, since `url::Url` may or may not accept it across
                // versions. The important property is "we did not panic
                // and we did not invent a hash for an unparseable URL".
                assert_eq!(url, "not://a real url");
                assert!(userinfo_hash.is_none());
            }
            other => panic!("expected Url transport, got {other:?}"),
        }
    }

    #[test]
    fn lockfile_with_userinfo_round_trips() {
        // A lockfile carrying a URL transport with `userinfo_hash` must
        // serialize and parse back identically — the new schema field
        // round-trips. The `userinfo_hash` is preserved across the
        // serialize/deserialize cycle (same byte-for-byte hex string).
        let inventory = McpInventory {
            servers: vec![McpServerEntry {
                name: "s".into(),
                transport: McpTransport::Url {
                    url: "https://host.example/sse".into(),
                    userinfo_hash: Some(
                        "abc123def456abc123def456abc123def456abc123def456abc123def456abc1".into(),
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
        let lock = McpLockfile::from_inventory(&inventory);
        let parsed: McpLockfile = serde_json::from_str(&lock.render())
            .expect("lockfile with userinfo_hash must round-trip");
        assert_eq!(parsed, lock);
    }

    // Chunk 2 — drift detection. Covers every category (added, removed,
    // transport / env / tools / userinfo change) plus the empty-drift fast path.

    fn mk_inventory(servers: Vec<McpServerEntry>) -> McpInventory {
        McpInventory {
            servers,
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        }
    }

    fn stdio_server(name: &str, command: &str) -> McpServerEntry {
        McpServerEntry {
            name: name.into(),
            transport: McpTransport::Stdio {
                command: command.into(),
                args: vec![],
                env: vec![],
            },
            tools: vec![],
            tools_declared: true,
            source_config: ".mcp.json".into(),
        }
    }

    #[test]
    fn drift_is_empty_when_inventory_matches_lockfile() {
        // Headline fast-path: same inventory, same hash, no drift.
        let inv = mk_inventory(vec![stdio_server("s", "node")]);
        let lock = McpLockfile::from_inventory(&inv);
        let drifts = compute_drift(&inv, &lock);
        assert!(
            drifts.is_empty(),
            "no-drift case must yield empty: {drifts:?}"
        );
    }

    #[test]
    fn drift_detects_server_added() {
        let prev = mk_inventory(vec![stdio_server("a", "node")]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![stdio_server("a", "node"), stdio_server("b", "node")]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        assert!(matches!(
            &drifts[0],
            McpDrift::Added { name, .. } if name == "b"
        ));
    }

    #[test]
    fn drift_added_carries_new_server_tools() {
        // The Added drift surfaces the new server's tool list so a policy
        // gate (`scan.mcp_allowed_tools`) can inspect what the brand-new
        // server exposes — mirroring `tools_added` on Changed. Without
        // this, an Added server smuggling a disallowed tool would slip
        // through the severity ladder (the asymmetry CodeRabbit flagged).
        let prev = mk_inventory(vec![stdio_server("a", "node")]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![
            stdio_server("a", "node"),
            McpServerEntry {
                tools: vec!["read_file".into(), "write_file".into()],
                ..stdio_server("b", "node")
            },
        ]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Added { name, tools, .. } => {
                assert_eq!(name, "b");
                // Tools are surfaced in their canonical (sorted) order —
                // exactly the form `McpServerEntry::tools` carries.
                assert_eq!(
                    tools,
                    &vec!["read_file".to_string(), "write_file".to_string()],
                    "Added drift must carry the new server's declared tools",
                );
            }
            other => panic!("expected Added with tools, got {other:?}"),
        }
    }

    #[test]
    fn drift_added_with_no_tools_has_empty_tools_vec() {
        // A new server that declares no tools yields an empty `tools` vec
        // (not absent / null) — `compute_drift` always surfaces the list,
        // even when it's empty, so consumers can branch on length without
        // an Option dance.
        let prev = mk_inventory(vec![stdio_server("a", "node")]);
        let lock = McpLockfile::from_inventory(&prev);
        let cur = mk_inventory(vec![stdio_server("a", "node"), stdio_server("b", "node")]);
        let drifts = compute_drift(&cur, &lock);
        match &drifts[0] {
            McpDrift::Added { tools, .. } => {
                assert!(
                    tools.is_empty(),
                    "no-tools-declared server must yield an empty Added.tools vec, got {tools:?}",
                );
            }
            other => panic!("expected Added, got {other:?}"),
        }
    }

    #[test]
    fn drift_added_serialization_omits_empty_tools_field() {
        // The schema change is structural-only — when `tools` is empty
        // the field is omitted from JSON, so a drift document produced
        // by the previous version (which had no field) round-trips
        // bit-identically into the new `Added` shape with `tools: []`.
        // This is wire-shape proof that the lockfile schema (the
        // current `MCP_LOCK_FORMAT_VERSION`) is unaffected by the
        // structural `tools` extension on `McpDrift::Added`.
        let added = McpDrift::Added {
            name: "newcomer".into(),
            source_config: ".mcp.json".into(),
            tools: vec![],
        };
        let json = serde_json::to_string(&added).unwrap();
        assert!(
            !json.contains("\"tools\""),
            "an empty tools list must be omitted from JSON: {json}"
        );

        let with_tools = McpDrift::Added {
            name: "newcomer".into(),
            source_config: ".mcp.json".into(),
            tools: vec!["read".into()],
        };
        let json = serde_json::to_string(&with_tools).unwrap();
        assert!(
            json.contains("\"tools\""),
            "a non-empty tools list must be present in JSON: {json}"
        );

        // And an older drift document (without the `tools` field) parses
        // cleanly with `tools` defaulting to an empty vec — the
        // structural extension is backwards-compatible at the JSON layer.
        let legacy = r#"{"kind":"added","name":"old","source_config":".mcp.json"}"#;
        let parsed: McpDrift = serde_json::from_str(legacy).expect("legacy Added must parse");
        match parsed {
            McpDrift::Added {
                name,
                source_config,
                tools,
            } => {
                assert_eq!(name, "old");
                assert_eq!(source_config, ".mcp.json");
                assert!(
                    tools.is_empty(),
                    "missing tools field must default to empty: {tools:?}"
                );
            }
            other => panic!("expected Added, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_server_removed() {
        let prev = mk_inventory(vec![stdio_server("a", "node"), stdio_server("b", "node")]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![stdio_server("a", "node")]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        assert!(matches!(
            &drifts[0],
            McpDrift::Removed { name, .. } if name == "b"
        ));
    }

    #[test]
    fn drift_added_and_removed_sort_deterministically() {
        // Removed sorts before Added. Within each bucket, sort by name.
        let prev = mk_inventory(vec![stdio_server("zeta", "node")]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![
            stdio_server("alpha", "node"),
            stdio_server("beta", "node"),
        ]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 3);
        // Removed first.
        assert!(matches!(&drifts[0], McpDrift::Removed { name, .. } if name == "zeta"));
        // Then Added, by name.
        assert!(matches!(&drifts[1], McpDrift::Added { name, .. } if name == "alpha"));
        assert!(matches!(&drifts[2], McpDrift::Added { name, .. } if name == "beta"));
    }

    #[test]
    fn drift_detects_transport_kind_change() {
        let prev = mk_inventory(vec![stdio_server("s", "node")]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Url {
                url: "https://x.example".into(),
                userinfo_hash: None,
            },
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert_eq!(entry.name, "s");
                assert_eq!(entry.transport_changes.len(), 1);
                assert!(matches!(
                    &entry.transport_changes[0],
                    McpTransportChange::KindChanged { previous, current }
                        if previous == "stdio" && current == "url"
                ));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    // F24 (PRT II-10) — on a transport kind flip, `compute_changed_entry` records
    // ONLY `KindChanged` and drops per-variable env detail (a URL server has no
    // env), but still diffs tools across the boundary. Pinned so a refactor can't
    // silently emit misleading `EnvChanged` entries or stop diffing tools.

    #[test]
    fn drift_kind_change_stdio_to_url_drops_env_detail_but_keeps_tools_diff() {
        // Prev: a stdio server carrying TWO env vars and tools [a, b].
        let prev = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![
                    McpEnvEntry::from_raw("API_KEY", "secret"),
                    McpEnvEntry::from_raw("DEBUG", "1"),
                ],
            },
            tools: vec!["a".into(), "b".into()],
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        // Cur: same name "s", but now a URL transport (no env at all) and
        // a different tool set [b, c] — so the tools diff has both an
        // addition ("c") and a removal ("a"), proving the diff ran.
        let cur = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Url {
                url: "https://x.example".into(),
                userinfo_hash: None,
            },
            tools: vec!["b".into(), "c".into()],
            ..stdio_server("s", "node")
        }]);

        let drifts = compute_drift(&cur, &lock);
        assert_eq!(
            drifts.len(),
            1,
            "exactly one drift entry across the kind flip: got {drifts:?}",
        );
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                // transport_changes carries EXACTLY one `KindChanged`
                // entry — no extra `EnvChanged` / `UrlChanged` / etc.
                // The other variants are kind-specific and intentionally
                // do not fire across the boundary.
                assert_eq!(
                    entry.transport_changes.len(),
                    1,
                    "kind flip must record exactly one transport_change \
                     (just KindChanged): {entry:?}",
                );
                match &entry.transport_changes[0] {
                    McpTransportChange::KindChanged { previous, current } => {
                        assert_eq!(previous, "stdio", "previous kind: {entry:?}");
                        assert_eq!(current, "url", "current kind: {entry:?}");
                    }
                    other => panic!("expected KindChanged, got {other:?}"),
                }

                // env_changes is EMPTY — the two stdio env vars that the
                // lockfile recorded are NOT surfaced as per-variable
                // `Removed` entries across the kind boundary. A URL
                // transport has no concept of env, so per-variable diff
                // would be misleading.
                assert!(
                    entry.env_changes.is_empty(),
                    "env_changes must be empty across a kind flip — \
                     per-variable diff is undefined when the transport \
                     kind itself changed: {entry:?}",
                );

                // tools_added / tools_removed STILL reflect the diff
                // across the boundary. Tools are part of the server-level
                // (kind-independent) surface, so the diff runs.
                assert_eq!(
                    entry.tools_change,
                    Some(McpToolsChangeKind::Set),
                    "tools differ both ways (added c, removed a) so the \
                     kind is Set: {entry:?}",
                );
                assert_eq!(
                    entry.tools_added,
                    vec!["c".to_string()],
                    "tools_added must reflect the diff: {entry:?}",
                );
                assert_eq!(
                    entry.tools_removed,
                    vec!["a".to_string()],
                    "tools_removed must reflect the diff: {entry:?}",
                );
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_command_change() {
        let prev = mk_inventory(vec![stdio_server("s", "node")]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![stdio_server("s", "deno")]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert!(entry
                    .transport_changes
                    .iter()
                    .any(|c| matches!(c, McpTransportChange::CommandChanged)));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_args_change() {
        let prev = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec!["a.js".into()],
                env: vec![],
            },
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec!["b.js".into()],
                env: vec![],
            },
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert!(entry
                    .transport_changes
                    .iter()
                    .any(|c| matches!(c, McpTransportChange::ArgsChanged)));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_env_added() {
        let prev = mk_inventory(vec![stdio_server("s", "node")]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![McpEnvEntry::from_raw("API_TOKEN", "v")],
            },
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert!(entry
                    .transport_changes
                    .iter()
                    .any(|c| matches!(c, McpTransportChange::EnvChanged)));
                assert_eq!(entry.env_changes.len(), 1);
                assert!(matches!(
                    &entry.env_changes[0],
                    McpEnvChange::Added { name } if name == "API_TOKEN"
                ));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_env_removed() {
        let prev = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![McpEnvEntry::from_raw("API_TOKEN", "v")],
            },
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![stdio_server("s", "node")]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert_eq!(entry.env_changes.len(), 1);
                assert!(matches!(
                    &entry.env_changes[0],
                    McpEnvChange::Removed { name } if name == "API_TOKEN"
                ));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_env_value_hash_change() {
        // The headline drift property: a rotated credential surfaces as a
        // value-hash change. The raw value never appears in the drift —
        // only the variable's NAME does — exactly as it never appears in
        // the lockfile.
        let prev = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![McpEnvEntry::from_raw("API_TOKEN", "old-credential-bytes")],
            },
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![McpEnvEntry::from_raw("API_TOKEN", "new-credential-bytes")],
            },
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert_eq!(entry.env_changes.len(), 1);
                assert!(matches!(
                    &entry.env_changes[0],
                    McpEnvChange::ValueHashChanged { name } if name == "API_TOKEN"
                ));
            }
            other => panic!("expected Changed, got {other:?}"),
        }

        // And no raw credential bytes leak into the drift's serialized form.
        let serialized = serde_json::to_string(&drifts).unwrap();
        assert!(!serialized.contains("old-credential-bytes"));
        assert!(!serialized.contains("new-credential-bytes"));
    }

    #[test]
    fn drift_detects_tools_added_and_removed() {
        let prev = mk_inventory(vec![McpServerEntry {
            tools: vec!["a".into(), "b".into()],
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            tools: vec!["a".into(), "c".into()],
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert_eq!(entry.tools_change, Some(McpToolsChangeKind::Set));
                assert_eq!(entry.tools_added, vec!["c".to_string()]);
                assert_eq!(entry.tools_removed, vec!["b".to_string()]);
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_tools_only_added() {
        let prev = mk_inventory(vec![McpServerEntry {
            tools: vec!["a".into()],
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            tools: vec!["a".into(), "b".into()],
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert_eq!(entry.tools_change, Some(McpToolsChangeKind::Added));
                assert_eq!(entry.tools_added, vec!["b".to_string()]);
                assert!(entry.tools_removed.is_empty());
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_tools_only_removed() {
        let prev = mk_inventory(vec![McpServerEntry {
            tools: vec!["a".into(), "b".into()],
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            tools: vec!["a".into()],
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert_eq!(entry.tools_change, Some(McpToolsChangeKind::Removed));
                assert!(entry.tools_added.is_empty());
                assert_eq!(entry.tools_removed, vec!["b".to_string()]);
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    // F21 (PRT II-1) — pin `McpToolsChangeKind::Reordered` (and its `"reordered"`
    // tag): a same-set-different-order case only arises from a hand-built
    // inventory, so without a test both the variant and tag could be dropped.

    #[test]
    fn drift_tools_change_kind_reordered_fires_when_tool_lists_differ_only_in_order() {
        // Hand-construct two `McpServerEntry` with the same tool set in a
        // different order. We feed these directly to `compute_drift` (NOT
        // through `parse_mcp_config`, which would sort on parse and
        // collapse the difference). The framing of `content_hash` hashes
        // tools in their declared order, so the per-server hashes differ
        // and drift is computed; `diff_tools` then notices the *set* is
        // identical and emits `Reordered` rather than a spurious
        // `Added` + `Removed`.
        let prev = mk_inventory(vec![McpServerEntry {
            tools: vec!["a".into(), "b".into(), "c".into()],
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        // Same three tools, different declaration order. `from_inventory`
        // does NOT sort tools — it clones them as declared — so the order
        // survives into the lockfile snapshot of the current inventory
        // that `compute_drift` builds internally.
        let cur = mk_inventory(vec![McpServerEntry {
            tools: vec!["c".into(), "a".into(), "b".into()],
            ..stdio_server("s", "node")
        }]);

        let drifts = compute_drift(&cur, &lock);
        assert_eq!(
            drifts.len(),
            1,
            "exactly one drift entry for the single reordered server: got {drifts:?}",
        );
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert_eq!(
                    entry.tools_change,
                    Some(McpToolsChangeKind::Reordered),
                    "same set in a different order must fire Reordered: {entry:?}",
                );
                // The merge-walk emits NO added / removed when the set is
                // identical — Reordered is the *only* signal.
                assert!(
                    entry.tools_added.is_empty(),
                    "Reordered must NOT also report tools_added: {entry:?}",
                );
                assert!(
                    entry.tools_removed.is_empty(),
                    "Reordered must NOT also report tools_removed: {entry:?}",
                );

                // Pin the serialized JSON tag. `McpToolsChangeKind` is
                // serialized with `#[serde(rename_all = "snake_case")]`, so
                // `Reordered` must emit `"reordered"` — a future variant
                // rename would silently break consumers of the JSON drift
                // envelope without this assertion.
                let json = serde_json::to_string(&entry.tools_change).unwrap();
                assert_eq!(
                    json, r#""reordered""#,
                    "tools_change must serialize as the literal tag \"reordered\": got {json}",
                );
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_userinfo_added() {
        // Prev: URL with no userinfo. Cur: URL with userinfo (a credential
        // was added in the source config since the lockfile was taken).
        let prev = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Url {
                url: "https://host.example/sse".into(),
                userinfo_hash: None,
            },
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let (redacted, hash) = redact_url_userinfo("s", "https://user:token@host.example/sse");
        let cur = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Url {
                url: redacted,
                userinfo_hash: hash,
            },
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert!(entry
                    .transport_changes
                    .iter()
                    .any(|c| matches!(c, McpTransportChange::UserinfoAdded)));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_userinfo_removed() {
        let (redacted, hash) = redact_url_userinfo("s", "https://user:token@host.example/sse");
        let prev = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Url {
                url: redacted,
                userinfo_hash: hash,
            },
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Url {
                url: "https://host.example/sse".into(),
                userinfo_hash: None,
            },
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert!(entry
                    .transport_changes
                    .iter()
                    .any(|c| matches!(c, McpTransportChange::UserinfoRemoved)));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_detects_userinfo_swapped() {
        let (red_a, hash_a) = redact_url_userinfo("s", "https://user:tokenA@host.example/sse");
        let prev = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Url {
                url: red_a,
                userinfo_hash: hash_a,
            },
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let (red_b, hash_b) = redact_url_userinfo("s", "https://user:tokenB@host.example/sse");
        let cur = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Url {
                url: red_b,
                userinfo_hash: hash_b,
            },
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert!(entry
                    .transport_changes
                    .iter()
                    .any(|c| matches!(c, McpTransportChange::UserinfoSwapped)));
            }
            other => panic!("expected Changed, got {other:?}"),
        }

        // Drift carries no raw userinfo bytes — only the change classifier.
        let serialized = serde_json::to_string(&drifts).unwrap();
        assert!(!serialized.contains("tokenA"));
        assert!(!serialized.contains("tokenB"));
    }

    #[test]
    fn drift_detects_url_bytes_changed() {
        // Same kind, no userinfo on either side, URL host differs.
        let prev = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Url {
                url: "https://old.example/sse".into(),
                userinfo_hash: None,
            },
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Url {
                url: "https://new.example/sse".into(),
                userinfo_hash: None,
            },
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert!(entry
                    .transport_changes
                    .iter()
                    .any(|c| matches!(c, McpTransportChange::UrlChanged)));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn drift_sort_is_deterministic_across_inputs() {
        // The same logical drift produced from two different input orderings
        // must serialize identically.
        let prev = mk_inventory(vec![stdio_server("a", "node"), stdio_server("b", "node")]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur1 = mk_inventory(vec![stdio_server("a", "node"), stdio_server("c", "node")]);
        let cur2 = mk_inventory(vec![stdio_server("c", "node"), stdio_server("a", "node")]);
        let d1 = compute_drift(&cur1, &lock);
        let d2 = compute_drift(&cur2, &lock);
        assert_eq!(d1, d2);
    }

    #[test]
    fn drift_silent_when_unchanged_server_moves_between_configs() {
        // `content_hash` deliberately excludes `source_config` — chunk 1's
        // documented invariant — and `inventory_hash` is the ordered
        // concatenation of `content_hash`es. So moving an unchanged server
        // from one config file to another does NOT register as drift: the
        // *content* is the same, only the location changed, and the chunk-1
        // schema treated that as a non-event. The fast-path inventory_hash
        // comparison cleanly catches this and short-circuits to no drift.
        let prev = mk_inventory(vec![McpServerEntry {
            tools_declared: true,
            source_config: ".mcp.json".into(),
            ..stdio_server("s", "node")
        }]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![McpServerEntry {
            tools_declared: true,
            source_config: ".vscode/mcp.json".into(),
            ..stdio_server("s", "node")
        }]);
        let drifts = compute_drift(&cur, &lock);
        assert!(
            drifts.is_empty(),
            "moving an unchanged server between configs must be silent: {drifts:?}"
        );
    }

    #[test]
    fn drift_walk_handles_same_name_in_different_configs() {
        // A repo can legitimately declare *two* servers with the same name
        // in different config files (the lockfile sorts by
        // `(name, source_config)` to handle this). When one of those servers
        // changes its transport, only the changed entry surfaces as drift —
        // the untouched twin stays clean.
        let prev = mk_inventory(vec![
            McpServerEntry {
                tools_declared: true,
                source_config: ".mcp.json".into(),
                ..stdio_server("s", "node")
            },
            McpServerEntry {
                tools_declared: true,
                source_config: ".vscode/mcp.json".into(),
                ..stdio_server("s", "node")
            },
        ]);
        let lock = McpLockfile::from_inventory(&prev);

        let cur = mk_inventory(vec![
            // .mcp.json copy: unchanged.
            McpServerEntry {
                tools_declared: true,
                source_config: ".mcp.json".into(),
                ..stdio_server("s", "node")
            },
            // .vscode copy: command rotated.
            McpServerEntry {
                tools_declared: true,
                source_config: ".vscode/mcp.json".into(),
                ..stdio_server("s", "deno")
            },
        ]);
        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 1);
        match &drifts[0] {
            McpDrift::Changed(entry) => {
                assert_eq!(entry.name, "s");
                assert_eq!(entry.source_config, ".vscode/mcp.json");
                assert!(entry
                    .transport_changes
                    .iter()
                    .any(|c| matches!(c, McpTransportChange::CommandChanged)));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn load_lockfile_returns_not_found_when_missing() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("absent.lock");
        let err = load_lockfile(&missing).unwrap_err();
        assert_eq!(err, McpLockLoadError::NotFound);
    }

    #[test]
    fn load_lockfile_returns_parse_error_on_malformed_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(MCP_LOCK_FILENAME);
        fs::write(&path, "not json at all").unwrap();
        let err = load_lockfile(&path).unwrap_err();
        assert!(matches!(err, McpLockLoadError::Parse { .. }));
    }

    #[test]
    fn parse_error_does_not_carry_serde_json_message() {
        // Privacy invariant: `McpLockLoadError::Parse` carries ONLY
        // line/column — it must not echo the `serde_json::Error`
        // message, which can include the offending JSON value (e.g.
        // `invalid type: string "...", expected ...`). A malformed
        // `.tirith/mcp.lock` whose body looks credential-shaped must
        // not leak that body into the parse-error variant or its
        // `Display` rendering.
        let secret = "ghp_PARSE_ERROR_LEAK_PROBE_DONOTLEAK";
        // Build content that is valid JSON syntax but the WRONG TYPE
        // for the lockfile schema. serde_json's Display for this
        // failure mode is the one documented to echo the value:
        // `invalid type: string "...", expected struct ...`.
        let bad = format!(r#""{secret}""#);
        let err = parse_lockfile(&bad).unwrap_err();
        match err {
            McpLockLoadError::Parse { line, column } => {
                // Sanity: line/column are real positions, not zeros
                // forged from a stripped message.
                let _ = (line, column);
            }
            other => panic!("expected Parse, got {other:?}"),
        }
        // The Display rendering must also be free of the probe bytes.
        let displayed = parse_lockfile(&bad).unwrap_err().to_string();
        assert!(
            !displayed.contains(secret),
            "secret leaked into McpLockLoadError::Display: {displayed}"
        );
        assert!(
            !displayed.contains("invalid type"),
            "raw serde_json message leaked into Display: {displayed}"
        );
        assert!(
            !displayed.contains("expected"),
            "raw serde_json message leaked into Display: {displayed}"
        );
    }

    #[test]
    fn parse_lockfile_sorts_servers_for_compute_drift() {
        // Defensive: `compute_drift`'s slow-path merge walk requires
        // `lock.servers` to be sorted by `(name, source_config)`. A
        // hand-edited or merge-resolved lockfile with out-of-order
        // servers must still drift-compare correctly — same drift
        // report as a properly-sorted lockfile, and zero drift when
        // the only difference is order.
        let ordered = mk_inventory(vec![
            stdio_server("alpha", "node"),
            stdio_server("beta", "node"),
            stdio_server("zeta", "node"),
        ]);
        let lock_sorted = McpLockfile::from_inventory(&ordered);
        let lock_sorted_json = lock_sorted.render();

        // Build a deliberately *reversed* on-disk lockfile by serializing
        // a hand-built struct whose `servers` are in reverse name order.
        // (We bypass `from_inventory` so the bytes hit disk unsorted —
        // simulating a hand-edited or merge-conflict-resolved lockfile.)
        let mut unsorted = lock_sorted.clone();
        unsorted.servers.reverse();
        let lock_unsorted_json = serde_json::to_string_pretty(&unsorted).unwrap() + "\n";
        // The on-disk bytes really are different.
        assert_ne!(
            lock_sorted_json, lock_unsorted_json,
            "the unsorted serialization must differ from the sorted one"
        );

        // After parsing, both lockfiles must compare equal because
        // `parse_lockfile` sorts. Equality of `McpLockfile` includes
        // the `servers` Vec ordering.
        let parsed_sorted = parse_lockfile(&lock_sorted_json).expect("sorted lockfile parses");
        let parsed_unsorted =
            parse_lockfile(&lock_unsorted_json).expect("unsorted lockfile parses");
        assert_eq!(
            parsed_sorted, parsed_unsorted,
            "parse_lockfile must sort servers so two lockfiles that differ \
             only in server order compare equal"
        );

        // Drift against the same inventory: both lockfiles must yield
        // zero drift — the inventory genuinely matches.
        let cur_drifts_sorted = compute_drift(&ordered, &parsed_sorted);
        let cur_drifts_unsorted = compute_drift(&ordered, &parsed_unsorted);
        assert!(
            cur_drifts_sorted.is_empty(),
            "sorted lockfile vs identical inventory must yield zero drift: \
             {cur_drifts_sorted:?}"
        );
        assert!(
            cur_drifts_unsorted.is_empty(),
            "unsorted lockfile vs identical inventory must ALSO yield zero \
             drift after parse-time sorting; without the sort the merge \
             walk would emit spurious Added/Removed: {cur_drifts_unsorted:?}"
        );

        // And when a real drift is introduced, both lockfiles report
        // the *same* drift — the merge walk is not confused by the
        // (parsed-away) on-disk order.
        let drifted_current = mk_inventory(vec![
            stdio_server("alpha", "node"),
            // "beta" removed.
            stdio_server("zeta", "deno"), // command rotated.
        ]);
        let d_sorted = compute_drift(&drifted_current, &parsed_sorted);
        let d_unsorted = compute_drift(&drifted_current, &parsed_unsorted);
        assert_eq!(
            d_sorted, d_unsorted,
            "drift report must be identical regardless of on-disk lockfile order"
        );
        // Sanity-check that real drift is detected, not silently swallowed.
        assert!(
            d_sorted
                .iter()
                .any(|d| matches!(d, McpDrift::Removed { name, .. } if name == "beta")),
            "expected a Removed drift for `beta`: {d_sorted:?}"
        );
        assert!(
            d_sorted
                .iter()
                .any(|d| matches!(d, McpDrift::Changed(entry) if entry.name == "zeta")),
            "expected a Changed drift for `zeta`: {d_sorted:?}"
        );
    }

    #[test]
    fn load_lockfile_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(MCP_LOCK_FILENAME);
        let inv = mk_inventory(vec![stdio_server("s", "node")]);
        let lock = McpLockfile::from_inventory(&inv);
        fs::write(&path, lock.render()).unwrap();
        let loaded = load_lockfile(&path).expect("round-trip must succeed");
        assert_eq!(loaded, lock);
    }

    // F1 — `format_version` is validated on load. A non-current version (future
    // v999, or a legacy v3-shape file) is rejected with `UnsupportedVersion`,
    // distinct from `Parse` for a precise diagnostic.

    #[test]
    fn parse_lockfile_rejects_future_version_999_distinctly() {
        // A perfectly well-formed lockfile that just happens to declare
        // schema version 999. Must surface as `UnsupportedVersion`, NOT
        // `Parse` (the JSON is valid; the schema number is the failure).
        let body = r#"{
            "format_version": 999,
            "inventory_hash": "deadbeef",
            "configs": [],
            "servers": []
        }"#;
        match parse_lockfile(body) {
            Err(McpLockLoadError::UnsupportedVersion { found, supported }) => {
                assert_eq!(found, 999, "found must echo the lockfile's version");
                assert_eq!(
                    supported, MCP_LOCK_FORMAT_VERSION,
                    "supported must report this build's version"
                );
            }
            other => panic!("expected UnsupportedVersion variant, got {other:?}"),
        }
    }

    #[test]
    fn parse_lockfile_rejects_legacy_v3_shape_distinctly() {
        // A v3-shape lockfile (no `userinfo_hash` on URL transports;
        // env serialized as `{name, value_hash}` — which v3 introduced —
        // but without v4's userinfo redaction). The shape happens to
        // deserialize cleanly into the v4 struct (the URL has no
        // userinfo so `userinfo_hash` is omitted both before and after
        // the schema bump). The version check must still fire.
        let body = r#"{
            "format_version": 3,
            "inventory_hash": "abc",
            "configs": [".mcp.json"],
            "servers": [
                {
                    "name": "s",
                    "transport": {"kind": "stdio", "command": "node", "args": [], "env": []},
                    "tools": [],
                    "source_config": ".mcp.json",
                    "hash": "deadbeef"
                }
            ]
        }"#;
        match parse_lockfile(body) {
            Err(McpLockLoadError::UnsupportedVersion { found, supported }) => {
                assert_eq!(found, 3, "the legacy v3 file's version is what surfaces");
                assert_eq!(supported, MCP_LOCK_FORMAT_VERSION);
            }
            other => panic!("expected UnsupportedVersion for v3 shape, got {other:?}"),
        }
    }

    #[test]
    fn parse_lockfile_rejects_legacy_v2_shape_with_raw_env_value() {
        // A v2-shape lockfile: env entries carry raw `value` strings
        // (the pre-redaction shape) instead of v4's `value_hash`. The
        // full v4 deserializer would fail with `missing field
        // value_hash`, producing a misleading `Parse` error — but the
        // root cause is a schema-version mismatch. The two-pass parse
        // catches the version first.
        let body = r#"{
            "format_version": 2,
            "inventory_hash": "abc",
            "configs": [".mcp.json"],
            "servers": [
                {
                    "name": "s",
                    "transport": {
                        "kind": "stdio",
                        "command": "node",
                        "args": [],
                        "env": [{ "name": "API_TOKEN", "value": "secret-raw-value" }]
                    },
                    "tools": [],
                    "source_config": ".mcp.json",
                    "hash": "deadbeef"
                }
            ]
        }"#;
        match parse_lockfile(body) {
            Err(McpLockLoadError::UnsupportedVersion { found, supported }) => {
                assert_eq!(found, 2);
                assert_eq!(supported, MCP_LOCK_FORMAT_VERSION);
            }
            other => panic!("expected UnsupportedVersion for v2 raw-env shape, got {other:?}"),
        }
    }

    #[test]
    fn parse_lockfile_genuinely_missing_format_version_is_parse_error() {
        // A document with NO `format_version` field at all is not a
        // version mismatch — it's a `Parse` failure. The probe-pass
        // must surface this as `Parse`, not `UnsupportedVersion`.
        let body = r#"{ "inventory_hash": "x", "configs": [], "servers": [] }"#;
        match parse_lockfile(body) {
            Err(McpLockLoadError::Parse { .. }) => { /* expected */ }
            other => panic!("expected Parse for missing format_version, got {other:?}"),
        }
    }

    #[test]
    fn parse_lockfile_accepts_current_version() {
        // Control: a lockfile whose `format_version` equals the constant
        // parses normally. This is the regression guard — the version
        // check must NOT reject the version we actually support.
        let inv = mk_inventory(vec![stdio_server("s", "node")]);
        let lock = McpLockfile::from_inventory(&inv);
        let body = lock.render();
        let loaded = parse_lockfile(&body).expect("current version must parse");
        assert_eq!(loaded.format_version, MCP_LOCK_FORMAT_VERSION);
    }

    #[test]
    fn unsupported_version_display_is_informative_and_safe() {
        // The `Display` output for the new variant must:
        // 1. Name both `found` and `supported` so the operator can act;
        // 2. Tell them what to do (`tirith mcp lock`);
        // 3. Carry no file-content fragments (only the two `u32`s).
        let err = McpLockLoadError::UnsupportedVersion {
            found: 999,
            supported: MCP_LOCK_FORMAT_VERSION,
        };
        let msg = format!("{err}");
        assert!(msg.contains("999"), "missing `found` version: {msg}");
        assert!(
            msg.contains(&MCP_LOCK_FORMAT_VERSION.to_string()),
            "missing `supported` version: {msg}"
        );
        assert!(
            msg.contains("tirith mcp lock") || msg.contains("upgrade tirith"),
            "missing operator remediation guidance: {msg}",
        );
    }

    // v5 — `tools_declared` is folded into `content_hash`, and a v4 lockfile is
    // accepted with a `LegacyV4Migration` tag for a one-time migration prompt.

    #[test]
    fn content_hash_includes_tools_declared() {
        // A server with `tools_declared = false` (the source config
        // omitted the `tools` key) must hash differently from an
        // otherwise-identical server with `tools_declared = true`
        // (the source config carried `"tools": []`). Before v5 the two
        // hashed identically because both canonicalize to the same
        // empty `tools: Vec<String>` and `tools_declared` was excluded
        // from the per-server hash; the flip silently passed drift
        // detection. v5 folds the flag in so the flip registers.
        let omitted = McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![],
            },
            tools: vec![],
            tools_declared: false,
            source_config: ".mcp.json".into(),
        };
        let declared_empty = McpServerEntry {
            tools_declared: true,
            ..omitted.clone()
        };
        assert_ne!(
            omitted.content_hash(),
            declared_empty.content_hash(),
            "v5: tools_declared must contribute to content_hash so an \
             omitted→declared-empty flip is detected as drift",
        );
    }

    #[test]
    fn parse_lockfile_v4_triggers_migration_message() {
        // A `format_version: 4` lockfile parses cleanly — its on-disk
        // shape is identical to v5 — and `compute_drift` emits a
        // `SchemaUpgradeRequired` entry pointing the operator at
        // `tirith mcp lock --force`. When the v4 baseline ALSO matches
        // the current inventory under v4-compatible hashing (the case
        // covered here), no per-server drift fires alongside the
        // migration prompt — the operator just sees "re-lock to
        // upgrade".
        //
        // This test pins the migration *message*. The cases where real
        // drift exists alongside the migration prompt are covered by
        // `v4_lockfile_with_real_drift_reports_both_upgrade_and_drift`
        // and `v4_lockfile_clean_reports_only_upgrade` below.
        let body = r#"{
            "format_version": 4,
            "inventory_hash": "abc",
            "configs": [".mcp.json"],
            "servers": [
                {
                    "name": "s",
                    "transport": {"kind": "stdio", "command": "node", "args": [], "env": []},
                    "tools": [],
                    "source_config": ".mcp.json",
                    "hash": "deadbeef"
                }
            ]
        }"#;
        let parsed = parse_lockfile(body).expect("v4 lockfile must parse");
        assert_eq!(parsed.schema_state, LockfileSchema::LegacyV4Migration);
        assert_eq!(parsed.format_version, 4);

        // Build a current inventory matching the locked server. Under
        // v4-compatible hashing both sides match (tools_declared is
        // excluded), so only the migration entry fires.
        let inv = mk_inventory(vec![stdio_server("s", "node")]);
        let drifts = compute_drift(&inv, &parsed);

        // The migration prompt is present, with the right version pair.
        let migration = drifts
            .iter()
            .find_map(|d| match d {
                McpDrift::SchemaUpgradeRequired {
                    from_version,
                    to_version,
                } => Some((*from_version, *to_version)),
                _ => None,
            })
            .expect("v4 lockfile must surface SchemaUpgradeRequired");
        assert_eq!(migration, (4, MCP_LOCK_FORMAT_VERSION));
    }

    #[test]
    fn v4_lockfile_with_real_drift_reports_both_upgrade_and_drift() {
        // Build a v4 lockfile that records server "s" with URL
        // `https://example.com/old`. The current inventory has the
        // same server but the URL has changed to `https://example.com/new`.
        // Under the migration window, compute_drift must report BOTH:
        //   1. SchemaUpgradeRequired (the v4→v5 migration prompt)
        //   2. Changed (the real URL drift, surfaced via v4-compatible
        //      comparison so it isn't absorbed by the migration short-
        //      circuit).
        let body = r#"{
            "format_version": 4,
            "inventory_hash": "abc",
            "configs": [".mcp.json"],
            "servers": [
                {
                    "name": "s",
                    "transport": {"kind": "url", "url": "https://example.com/old"},
                    "tools": [],
                    "source_config": ".mcp.json",
                    "hash": "deadbeef"
                }
            ]
        }"#;
        let parsed = parse_lockfile(body).expect("v4 lockfile must parse");
        assert_eq!(parsed.schema_state, LockfileSchema::LegacyV4Migration);

        // Current inventory: same server name + source, different URL.
        let inv = mk_inventory(vec![McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Url {
                url: "https://example.com/new".into(),
                userinfo_hash: None,
            },
            tools: vec![],
            tools_declared: true,
            source_config: ".mcp.json".into(),
        }]);

        let drifts = compute_drift(&inv, &parsed);

        // Migration prompt fires.
        assert!(
            drifts
                .iter()
                .any(|d| matches!(d, McpDrift::SchemaUpgradeRequired { .. })),
            "expected SchemaUpgradeRequired alongside real drift: {drifts:?}",
        );

        // Real URL drift fires as a Changed entry — proving that real
        // signal is NOT absorbed by the migration short-circuit.
        let changed_entry = drifts.iter().find_map(|d| match d {
            McpDrift::Changed(entry) if entry.name == "s" => Some(entry),
            _ => None,
        });
        let entry = changed_entry.expect("real URL drift must surface alongside migration prompt");
        assert!(
            entry
                .transport_changes
                .iter()
                .any(|c| matches!(c, McpTransportChange::UrlChanged)),
            "expected UrlChanged in transport_changes: {:?}",
            entry.transport_changes,
        );
    }

    #[test]
    fn v4_lockfile_clean_reports_only_upgrade() {
        // A v4 lockfile that matches the current inventory exactly under
        // v4-compatible hashing surfaces ONLY the migration prompt — no
        // phantom Added / Removed / Changed entries.
        //
        // The `tools_declared: true` default on the parsed lockfile
        // matches the default the current inventory's `stdio_server`
        // helper uses, so both sides hash identically under
        // `content_hash_v4` (which excludes `tools_declared` anyway,
        // making this even more robust).
        let body = r#"{
            "format_version": 4,
            "inventory_hash": "abc",
            "configs": [".mcp.json"],
            "servers": [
                {
                    "name": "s",
                    "transport": {"kind": "stdio", "command": "node", "args": [], "env": []},
                    "tools": [],
                    "source_config": ".mcp.json",
                    "hash": "deadbeef"
                }
            ]
        }"#;
        let parsed = parse_lockfile(body).expect("v4 lockfile must parse");
        let inv = mk_inventory(vec![stdio_server("s", "node")]);
        let drifts = compute_drift(&inv, &parsed);

        // Exactly one entry, and it's the migration prompt.
        assert_eq!(
            drifts.len(),
            1,
            "clean v4 lockfile must produce only the migration entry: {drifts:?}",
        );
        assert!(
            matches!(&drifts[0], McpDrift::SchemaUpgradeRequired { .. }),
            "expected SchemaUpgradeRequired only, got {drifts:?}",
        );
    }

    #[test]
    fn v5_lockfile_normal_drift_unchanged() {
        // Regression check: a v5 lockfile flows through the normal
        // drift path. The v4 migration branch in compute_drift must not
        // touch it — no SchemaUpgradeRequired entry, drift mirrors the
        // pre-Item-2 v5 contract.
        let inv_before = mk_inventory(vec![stdio_server("s", "node")]);
        let lock = McpLockfile::from_inventory(&inv_before);
        let body = lock.render();
        let parsed = parse_lockfile(&body).expect("v5 lockfile must parse");
        assert_eq!(parsed.schema_state, LockfileSchema::Current);

        // Unchanged inventory → empty drift.
        let drifts_same = compute_drift(&inv_before, &parsed);
        assert!(
            drifts_same.is_empty(),
            "unchanged v5 inventory must produce no drift: {drifts_same:?}",
        );

        // Mutated inventory → real drift, no migration prompt.
        let inv_after = mk_inventory(vec![stdio_server("s", "node"), stdio_server("t", "node")]);
        let drifts_changed = compute_drift(&inv_after, &parsed);
        assert!(
            drifts_changed
                .iter()
                .any(|d| matches!(d, McpDrift::Added { name, .. } if name == "t")),
            "expected an Added drift for server t: {drifts_changed:?}",
        );
        assert!(
            !drifts_changed
                .iter()
                .any(|d| matches!(d, McpDrift::SchemaUpgradeRequired { .. })),
            "v5 drift must NOT contain SchemaUpgradeRequired: {drifts_changed:?}",
        );
    }

    #[test]
    fn mcp_drift_name_distinguishes_empty_name_server_from_schema_signal() {
        // Item 1: `McpDrift::name()` must distinguish a per-server
        // signal with `name == ""` (a real, if degenerate, MCP server
        // whose JSON object key is the empty string) from the schema-
        // wide `SchemaUpgradeRequired` signal that has no per-server
        // identity. Returning `Option<&str>` makes the two structurally
        // distinct: a name-based dedupe / filter sees the empty-name
        // server as `Some("")` and the schema signal as `None`, so they
        // cannot collide.
        let empty_name_server_drift = McpDrift::Added {
            name: String::new(),
            source_config: ".mcp.json".into(),
            tools: vec![],
        };
        let schema_signal = McpDrift::SchemaUpgradeRequired {
            from_version: 4,
            to_version: MCP_LOCK_FORMAT_VERSION,
        };

        // The two are observably distinct via `name()`.
        assert_eq!(empty_name_server_drift.name(), Some(""));
        assert_eq!(schema_signal.name(), None);
        assert_ne!(empty_name_server_drift.name(), schema_signal.name());

        // Group / dedupe-by-name does not conflate them. A naive
        // pre-Item-1 implementation that grouped by `&str` would have
        // bucketed both under `""` and lost one. The `Option<&str>`
        // signature forces the caller to handle the schema case
        // explicitly.
        let drifts = vec![empty_name_server_drift.clone(), schema_signal.clone()];
        let mut per_server_names: Vec<&str> = Vec::new();
        let mut schema_signal_seen = false;
        for d in &drifts {
            match d.name() {
                Some(n) => per_server_names.push(n),
                None => schema_signal_seen = true,
            }
        }
        assert_eq!(
            per_server_names,
            vec![""],
            "the per-server bucket must contain exactly the empty-name server",
        );
        assert!(
            schema_signal_seen,
            "the schema-wide signal must be observed via the `None` arm",
        );
    }

    #[test]
    fn parse_lockfile_v5_normal_drift_works() {
        // Regression check: a v5 lockfile still flows through the
        // normal drift path. The migration short-circuit only fires on
        // `LockfileSchema::LegacyV4Migration`.
        let inv_before = mk_inventory(vec![stdio_server("s", "node")]);
        let lock = McpLockfile::from_inventory(&inv_before);
        let body = lock.render();
        let parsed = parse_lockfile(&body).expect("v5 lockfile must parse");
        assert_eq!(parsed.schema_state, LockfileSchema::Current);
        assert_eq!(parsed.format_version, MCP_LOCK_FORMAT_VERSION);

        // No-op drift first: the same inventory must produce empty drift
        // (proving the fast-path inventory_hash short-circuit is reached).
        let drifts_same = compute_drift(&inv_before, &parsed);
        assert!(
            drifts_same.is_empty(),
            "unchanged v5 inventory must produce no drift: {drifts_same:?}",
        );

        // Now mutate the inventory and verify real drift fires.
        let inv_after = mk_inventory(vec![stdio_server("s", "node"), stdio_server("t", "node")]);
        let drifts_changed = compute_drift(&inv_after, &parsed);
        assert!(
            !drifts_changed.is_empty(),
            "mutated v5 inventory must produce drift",
        );
        assert!(
            drifts_changed
                .iter()
                .any(|d| matches!(d, McpDrift::Added { name, .. } if name == "t")),
            "expected an Added drift for server t: {drifts_changed:?}",
        );
        assert!(
            !drifts_changed
                .iter()
                .any(|d| matches!(d, McpDrift::SchemaUpgradeRequired { .. })),
            "v5 drift must NOT contain SchemaUpgradeRequired: {drifts_changed:?}",
        );
    }

    // F3 / F4 — `build_inventory` surfaces the rejection list on
    // `rejected_configs`; discovery-time and file-content rejections both flow in.

    #[cfg(unix)]
    #[test]
    fn build_inventory_records_symlink_rejection() {
        // A symlinked `.mcp.json` is rejected during discovery; the
        // rejection must surface in `rejected_configs` with reason
        // `Symlink`, not be silently dropped.
        use std::os::unix::fs::symlink;
        let outside = tempdir().unwrap();
        let outside_config = outside.path().join("evil-mcp.json");
        fs::write(
            &outside_config,
            r#"{ "mcpServers": { "evil": { "command": "node" } } }"#,
        )
        .unwrap();

        let repo = tempdir().unwrap();
        symlink(&outside_config, repo.path().join(".mcp.json")).unwrap();

        let inventory = build_inventory(repo.path());
        assert!(inventory.servers.is_empty());
        assert!(inventory.configs.is_empty());
        // The rejection is recorded with the right shape.
        let found = inventory
            .rejected_configs
            .iter()
            .find(|r| r.path == ".mcp.json")
            .expect("symlinked config must appear in rejected_configs");
        assert!(
            matches!(found.reason, RejectedReason::Symlink),
            "symlink rejection reason: got {:?}",
            found.reason,
        );
    }

    #[test]
    fn build_inventory_records_oversize_rejection() {
        // A 2 MiB `.mcp.json` (above the 1 MiB cap) is rejected without
        // being read. `rejected_configs` records the size; `configs`
        // and `servers` are unaffected (no servers contributed).
        let repo = tempdir().unwrap();
        // ~2 MiB of JSON-ish content. The exact content doesn't matter —
        // we never read past the size check.
        let big = "x".repeat((MCP_CONFIG_MAX_SIZE * 2) as usize);
        fs::write(repo.path().join(".mcp.json"), big).unwrap();

        let inventory = build_inventory(repo.path());
        assert!(
            inventory.servers.is_empty(),
            "oversized file must contribute no servers",
        );
        assert!(
            inventory.configs.is_empty(),
            "oversized file is rejected before it counts as a discovered config: {:?}",
            inventory.configs,
        );
        let found = inventory
            .rejected_configs
            .iter()
            .find(|r| r.path == ".mcp.json")
            .expect("oversize rejection must surface");
        match found.reason {
            RejectedReason::Oversize { size_bytes } => {
                assert!(
                    size_bytes > MCP_CONFIG_MAX_SIZE,
                    "size_bytes {size_bytes} must exceed cap {MCP_CONFIG_MAX_SIZE}",
                );
            }
            ref other => panic!("expected Oversize, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn build_inventory_records_permission_denied_rejection() {
        // An unreadable file (mode 000) surfaces as
        // `Unreadable { permission_denied: true }`. Skipped on Windows
        // (the test relies on POSIX file modes).
        use std::os::unix::fs::PermissionsExt;
        let repo = tempdir().unwrap();
        let cfg = repo.path().join(".mcp.json");
        fs::write(&cfg, r#"{ "mcpServers": {} }"#).unwrap();
        let mut perms = fs::metadata(&cfg).unwrap().permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&cfg, perms).unwrap();

        let inventory = build_inventory(repo.path());

        // Cleanup so the tempdir can be removed.
        let mut perms = fs::metadata(&cfg).unwrap().permissions();
        perms.set_mode(0o600);
        let _ = fs::set_permissions(&cfg, perms);

        // The file may be readable by root (CI runs as root frequently),
        // in which case there's no permission denial to test — the
        // inventory will simply parse the file. Skip the assertion in
        // that scenario rather than fail the test.
        if !inventory.rejected_configs.is_empty() {
            let found = &inventory.rejected_configs[0];
            assert_eq!(found.path, ".mcp.json");
            assert!(
                matches!(
                    found.reason,
                    RejectedReason::Unreadable {
                        permission_denied: true
                    }
                ),
                "expected Unreadable{{ permission_denied: true }}, got {:?}",
                found.reason,
            );
        }
    }

    #[test]
    fn build_inventory_silently_skips_not_found_io() {
        // A path that doesn't physically exist must be silent — discovery
        // probes a fixed set of paths and the common case is most of
        // those don't exist. The rejection list must NOT carry a
        // NotFound-style entry.
        let repo = tempdir().unwrap();
        let inventory = build_inventory(repo.path());
        assert!(inventory.rejected_configs.is_empty());
        assert!(inventory.servers.is_empty());
        assert!(inventory.configs.is_empty());
    }

    // F8 — `redact_url_userinfo` round-trips every structural URL component
    // (query, fragment) through the redaction; the old fallback dropped them.

    #[test]
    fn redact_url_userinfo_preserves_query_and_fragment() {
        // A URL with userinfo AND a query AND a fragment must come back
        // userinfo-stripped, with the query and fragment intact and the
        // host/port/path correct.
        let (redacted, hash) = redact_url_userinfo(
            "server",
            "https://user:tok@host.example:8443/api?x=1&y=2#frag",
        );
        assert_eq!(
            redacted, "https://host.example:8443/api?x=1&y=2#frag",
            "redacted URL must retain query and fragment: {redacted}",
        );
        assert!(hash.is_some(), "userinfo hash must be set");
        let hash = hash.unwrap();
        // The hash must be deterministic for these inputs (server-name salted).
        assert_eq!(
            hash,
            salted_sha256_hex("server", "user:tok"),
            "userinfo hash must use the documented salt scheme: got {hash}",
        );
    }

    #[test]
    fn redact_url_userinfo_no_userinfo_canonicalizes_path_default() {
        // A bare-host URL with no userinfo is canonicalized through
        // `url::Url`, so the trailing `/` shows up. The hash is None.
        let (redacted, hash) = redact_url_userinfo("server", "https://host.example");
        assert_eq!(redacted, "https://host.example/");
        assert_eq!(hash, None);
    }

    // PR #121 item 5 — `parse_lockfile` recomputes every hash from the data and
    // discards the deserialized ones, so a forged-hash lockfile can't silence drift.

    #[test]
    fn parse_lockfile_recomputes_hashes_and_ignores_forged_inventory_hash() {
        // Build a legitimate lockfile, then tamper with the
        // `inventory_hash` field via a JSON-level edit. After parsing,
        // the in-memory value must be the data-derived hash, NOT the
        // forgery.
        let inv = McpInventory {
            servers: vec![McpServerEntry {
                name: "s".into(),
                transport: McpTransport::Stdio {
                    command: "node".into(),
                    args: vec![],
                    env: vec![],
                },
                tools: vec!["read".into()],
                tools_declared: true,
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let lock = McpLockfile::from_inventory(&inv);
        let expected_inventory_hash = lock.inventory_hash.clone();
        let expected_server_hash = lock.servers[0].hash.clone();
        let rendered = lock.render();

        // Tamper: replace the inventory_hash and the per-server hash
        // with `f` * 64. A hostile editor could pick any plausible-
        // shaped value — what matters is that the deserialized hash
        // does not survive parsing.
        let forgery = "f".repeat(64);
        let tampered = rendered
            .replace(&expected_inventory_hash, &forgery)
            .replace(&expected_server_hash, &forgery);
        assert!(
            tampered.contains(&forgery),
            "test scaffold: tamper substitution must succeed",
        );

        let parsed = parse_lockfile(&tampered).expect("tampered lockfile must still parse");
        assert_ne!(
            parsed.inventory_hash, forgery,
            "parse_lockfile must NOT trust the deserialized inventory_hash",
        );
        assert_eq!(
            parsed.inventory_hash, expected_inventory_hash,
            "parse_lockfile must recompute inventory_hash from servers",
        );
        assert_eq!(parsed.servers.len(), 1);
        assert_ne!(
            parsed.servers[0].hash, forgery,
            "parse_lockfile must NOT trust the deserialized per-server hash",
        );
        assert_eq!(
            parsed.servers[0].hash, expected_server_hash,
            "parse_lockfile must recompute per-server hash from content",
        );
    }

    // PR #121 item 6 — the parse-failure fallback strips userinfo (→ `***`)
    // rather than storing the raw URL verbatim, even for an unparseable URL.

    #[test]
    fn redact_url_userinfo_strips_userinfo_on_parse_failure() {
        // Construct a URL string with a userinfo that doesn't parse
        // cleanly via `url::Url`. We use a control byte inside the host
        // to force the parser to fail while still leaving the
        // `scheme://user:tok@host` shape intact for the byte-scan
        // strip to recognize.
        let malformed = "https://user:token@host\x07.example/path?q=1";
        // Sanity check: `url::Url::parse` rejects this URL.
        assert!(
            url::Url::parse(malformed).is_err(),
            "test scaffold: input must be unparseable to exercise the strip-fallback",
        );

        let (redacted, hash) = redact_url_userinfo("server", malformed);
        assert!(
            !redacted.contains("user:token"),
            "userinfo must be stripped from malformed-URL output: {redacted}",
        );
        assert!(
            !redacted.contains("user"),
            "the user-half of the userinfo must be stripped too: {redacted}",
        );
        assert!(
            !redacted.contains("token"),
            "the password-half must be stripped too: {redacted}",
        );
        assert!(
            redacted.contains("***@"),
            "the strip output should mark the redacted region: {redacted}",
        );
        // The path/query are preserved for diagnostic context.
        assert!(
            redacted.contains("/path"),
            "non-credential content should be preserved: {redacted}",
        );
        // A userinfo hash IS recorded for the malformed case (CR
        // follow-up): the byte-scan strip identifies the userinfo
        // bytes between `://` and `@`, hashes them with the same
        // server-salted SHA-256 scheme the parsed path uses, and
        // stores `Some(hash)` so a later `mcp verify` notices when
        // credentials are added or removed. The hash mirrors
        // `salted_sha256_hex(server_name, userinfo)`.
        let h = hash.expect("malformed-URL strip with userinfo bytes must record a hash");
        assert_eq!(h.len(), 64, "the hash must be 64 hex chars (SHA-256)");
        assert_eq!(
            h,
            salted_sha256_hex("server", "user:token"),
            "the recorded hash must match the salted-SHA-256 scheme: {h}",
        );
    }

    #[test]
    fn strip_userinfo_best_effort_preserves_non_authority_urls() {
        let srv = "srv";
        // A URL with no `@` before the path → no userinfo to strip,
        // return verbatim and no hash (no credential bytes to fingerprint).
        assert_eq!(
            strip_userinfo_best_effort(srv, "https://host.example/path"),
            ("https://host.example/path".to_string(), None),
        );
        // A relative URL or non-URL string is not authority-shaped →
        // return verbatim, no hash.
        assert_eq!(
            strip_userinfo_best_effort(srv, "not a url at all"),
            ("not a url at all".to_string(), None),
        );
        assert_eq!(strip_userinfo_best_effort(srv, ""), ("".to_string(), None),);
        // A URL whose `@` is INSIDE the path (after the `/`) is not
        // userinfo and must not be touched.
        assert_eq!(
            strip_userinfo_best_effort(srv, "https://host.example/path@anchor"),
            ("https://host.example/path@anchor".to_string(), None),
        );
    }

    // PR #121 CR follow-up — the malformed-URL strip path hashes the userinfo
    // bytes (same `salted_sha256_hex` scheme) so credential add/remove drift stays
    // visible; otherwise two locks losing the credential would look identical.

    #[test]
    fn strip_userinfo_best_effort_records_hash_for_malformed_url_with_credentials() {
        let srv = "srv";
        // A malformed URL — `url::Url::parse` rejects URLs whose host
        // contains an unencoded space — that nevertheless carries
        // `user:token@host` in its authority position. The strip
        // rewrites to `***` AND records a hash so drift sees credential
        // presence/absence.
        let raw = "https://user:t1@host with spaces/p";
        // Sanity: this really is a malformed URL the parser rejects, so
        // this branch is reachable from `redact_url_userinfo`.
        assert!(
            url::Url::parse(raw).is_err(),
            "test relies on this URL being malformed (parser rejects host with space)"
        );
        let (stripped, hash) = strip_userinfo_best_effort(srv, raw);
        assert_eq!(stripped, "https://***@host with spaces/p");
        let h = hash.expect("strip with credentials must record a userinfo hash");
        assert_eq!(h.len(), 64, "the hash must be 64 hex chars (SHA-256)");
        // The hash must not contain any of the original credential bytes —
        // sanity check that we did not accidentally store the credential.
        assert!(
            !h.contains("user") && !h.contains("t1"),
            "hash must not echo the credential: {h}"
        );
    }

    #[test]
    fn strip_userinfo_best_effort_records_no_hash_for_empty_userinfo() {
        // The `://@host` shape — with the host being malformed enough
        // to fail `url::Url::parse` — has no userinfo bytes to
        // fingerprint. The strip still rewrites to `***` for shape
        // consistency, but the hash stays `None` because there is no
        // credential signal.
        let raw = "https://@host with spaces/p";
        assert!(
            url::Url::parse(raw).is_err(),
            "test relies on this URL being malformed"
        );
        let (stripped, hash) = strip_userinfo_best_effort("srv", raw);
        assert_eq!(stripped, "https://***@host with spaces/p");
        assert_eq!(hash, None);
    }

    #[test]
    fn strip_userinfo_best_effort_drift_signal_changes_when_credentials_change() {
        // Two locks of the same malformed URL with DIFFERENT credentials
        // must produce DIFFERENT userinfo hashes so drift comparison
        // notices the change. (The salted hash is deterministic in the
        // server-name salt + userinfo bytes; changing either flips it.)
        let raw1 = "https://user1:t1@host with spaces/x";
        let raw2 = "https://user2:t2@host with spaces/x";
        let raw3 = "https://host with spaces/x";
        for r in &[raw1, raw2, raw3] {
            assert!(
                url::Url::parse(r).is_err(),
                "test relies on each URL being malformed: {r}"
            );
        }
        let (_s1, h1) = strip_userinfo_best_effort("srv", raw1);
        let (_s2, h2) = strip_userinfo_best_effort("srv", raw2);
        assert_ne!(h1, h2, "credential change must flip the userinfo hash");
        assert!(h1.is_some() && h2.is_some());

        // And removing the credentials entirely flips Some(_) → None,
        // which is the drift signal CodeRabbit's follow-up demands.
        let (_s3, h3) = strip_userinfo_best_effort("srv", raw3);
        assert_eq!(h3, None);
        assert_ne!(h1, h3, "removing credentials must flip the userinfo hash");
    }

    // PR #121 item 7 — `parse_tools` distinguishes the on-wire shapes via
    // `DeclaredTools`, and `tools_declared` captures omitted-vs-declared.

    #[test]
    fn parse_tools_distinguishes_omitted_empty_and_declared() {
        // Omitted: no `tools` key on the server object.
        let obj_omitted: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{ "command": "node" }"#).unwrap();
        assert_eq!(parse_tools(&obj_omitted), DeclaredTools::Omitted);
        assert!(!DeclaredTools::Omitted.was_declared());

        // Empty-declared: `"tools": []`.
        let obj_empty: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{ "command": "node", "tools": [] }"#).unwrap();
        assert_eq!(parse_tools(&obj_empty), DeclaredTools::EmptyDeclared);
        assert!(DeclaredTools::EmptyDeclared.was_declared());

        // Declared with a non-empty list.
        let obj_declared: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{ "command": "node", "tools": ["read", "write"] }"#).unwrap();
        match parse_tools(&obj_declared) {
            DeclaredTools::Declared(v) => {
                assert_eq!(v, vec!["read".to_string(), "write".to_string()]);
            }
            other => panic!("expected Declared, got {other:?}"),
        }

        // Invalid shape: `"tools": "not an array"`.
        let obj_invalid: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{ "command": "node", "tools": "oops" }"#).unwrap();
        assert_eq!(
            parse_tools(&obj_invalid),
            DeclaredTools::Invalid(Vec::new())
        );
    }

    #[test]
    fn mcp_server_entry_tools_declared_round_trips_through_lockfile_for_all_three_states() {
        // Build inventories that exercise each of the three states and
        // assert that `tools_declared` round-trips through
        // `from_inventory` → render → parse_lockfile correctly.
        let mk = |name: &str, tools: Vec<String>, tools_declared: bool| McpServerEntry {
            name: name.into(),
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![],
            },
            tools,
            tools_declared,
            source_config: ".mcp.json".into(),
        };
        let inv = McpInventory {
            servers: vec![
                mk("omitted", vec![], false),
                mk("empty-declared", vec![], true),
                mk("declared", vec!["read".to_string()], true),
            ],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let body = McpLockfile::from_inventory(&inv).render();
        let parsed = parse_lockfile(&body).unwrap();
        // Sorted by name: declared, empty-declared, omitted (alpha order).
        let by_name: std::collections::HashMap<&str, &McpLockServer> = parsed
            .servers
            .iter()
            .map(|s| (s.name.as_str(), s))
            .collect();
        assert!(
            !by_name["omitted"].tools_declared,
            "omitted state must serialize as tools_declared=false",
        );
        assert!(
            by_name["empty-declared"].tools_declared,
            "empty-declared state must serialize as tools_declared=true",
        );
        assert!(
            by_name["declared"].tools_declared,
            "declared state must serialize as tools_declared=true",
        );
        // Lockfile JSON itself must carry the field so a programmatic
        // consumer can see the three states.
        assert!(
            body.contains("tools_declared"),
            "lockfile JSON must carry tools_declared field: {body}",
        );
    }

    #[test]
    fn legacy_lockfile_without_tools_declared_field_defaults_to_true() {
        // An older tirith that did not yet write `tools_declared`
        // produced lockfiles whose server entries had no such field.
        // Such lockfiles must still parse, with `tools_declared`
        // defaulting to `true` — preserving the pre-change
        // interpretation that empty `tools` was always "declared empty".
        let legacy = serde_json::json!({
            "format_version": MCP_LOCK_FORMAT_VERSION,
            "inventory_hash": "0".repeat(64),
            "configs": [".mcp.json"],
            "servers": [{
                "name": "legacy",
                "transport": {
                    "kind": "stdio",
                    "command": "node",
                    "args": [],
                    "env": []
                },
                "tools": [],
                // No `tools_declared` field.
                "source_config": ".mcp.json",
                "hash": "0".repeat(64),
            }]
        });
        let parsed = parse_lockfile(&legacy.to_string()).unwrap();
        assert_eq!(parsed.servers.len(), 1);
        assert!(
            parsed.servers[0].tools_declared,
            "legacy lockfile entries default to tools_declared=true",
        );
    }
}
