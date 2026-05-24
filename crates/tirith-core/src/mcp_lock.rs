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
/// **Enforced at load.** [`parse_lockfile`] rejects any lockfile whose
/// `format_version` is not equal to this constant with a dedicated
/// [`McpLockLoadError::UnsupportedVersion`] variant — so a v999 lockfile
/// written by a future tirith does not parse silently, and a legacy-shape
/// lockfile (v3 or earlier, before `userinfo_hash` and the env redaction)
/// is also rejected. The CLI and `mcpdrift` rule both distinguish this from
/// "the JSON is corrupt", so the operator sees "this lockfile was written by
/// tirith schema vN, re-run `tirith mcp lock` to refresh / upgrade tirith"
/// rather than a generic parse-error message.
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
/// * `4` — the same `name`+salted-SHA-256 redaction scheme is applied to the
///   `url` transport's userinfo. A URL declared as `https://user:token@host/`
///   is now stored as `https://host/` and the captured userinfo (the literal
///   `user[:password]` substring) is hashed into a `userinfo_hash` of
///   `sha256(server_name || ':' || userinfo)`, salted by the MCP server's
///   name. The hash is folded into the per-server content hash, so a userinfo
///   change registers as drift exactly like an env-value change does; a URL
///   that carried no userinfo serializes with `userinfo_hash` **omitted** (not
///   set to a sentinel value), so "no credential present" is structurally
///   distinct on the wire from "credential present". HTTP Basic Auth tokens
///   in a URL are credentials in exactly the same threat model that motivated
///   v3, and `.tirith/mcp.lock` is designed to be committed — so the raw
///   userinfo never lands in the file. A v3 lockfile is not byte-comparable
///   to a v4 one.
pub const MCP_LOCK_FORMAT_VERSION: u32 = 4;

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
    /// Lowercase-hex SHA-256 of `name || ':' || value`. The `:` delimiter is
    /// per-entry **entropy**, not the load-bearing collision protection: the
    /// unambiguity of an `McpEnvEntry` inside the per-server content hash is
    /// established by the **outer length-prefixed framing** in
    /// [`McpServerEntry::content_hash`] (each `name` and `value_hash` is fed
    /// through [`hash_field`], which writes the length first). POSIX env-var
    /// names may legally contain `:` (only `=` is forbidden by `execve(2)`),
    /// so the inner `:` itself is not a guaranteed boundary marker — but
    /// outer length-prefixing makes the framing total over any byte content,
    /// regardless. The inner `name`-salted hash still defends against a
    /// cross-server precomputed-rainbow-table attack: a low-entropy value
    /// (`1`, `true`, `production`) hashes differently under each `name`, so
    /// a digest cannot be brute-forced once and reused across servers /
    /// configs.
    pub value_hash: String,
}

impl McpEnvEntry {
    /// Build an entry from a `(name, raw_value)` pair, hashing the value
    /// immediately. This is the **only** legitimate way to construct an entry
    /// from a real value, and the raw value is consumed and dropped before the
    /// function returns — it never reaches a struct field, the serializer, or
    /// the rest of the process.
    pub fn from_raw(name: &str, raw_value: &str) -> Self {
        // `:`-salted SHA-256 — see [`salted_sha256_hex`] for the shape and
        // [`McpEnvEntry::value_hash`] for why the outer length-prefixed
        // framing is the load-bearing collision protection (the inner `:`
        // is for cross-server entropy, not boundary unambiguity).
        let value_hash = salted_sha256_hex(name, raw_value);
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
    /// A network-reachable MCP server (HTTP / SSE / streamable-HTTP).
    ///
    /// **The URL is stored with any userinfo stripped.** A URL declared as
    /// `https://user:token@host:port/path` is recorded here as
    /// `https://host:port/path`; the `user:token` substring is HTTP Basic
    /// Auth and is a credential. `.tirith/mcp.lock` is designed to be
    /// committed, so persisting the raw userinfo would leak the credential
    /// into version control — the same threat model that motivated the v3
    /// env-value redaction.
    ///
    /// When the source URL carried a userinfo component, `userinfo_hash` is
    /// `Some(sha256(server_name || ':' || userinfo))` — the same name-salted
    /// SHA-256 scheme `McpEnvEntry` uses, with the **MCP server's name** as
    /// the per-entry salt. Folded into the per-server content hash, so a
    /// userinfo change registers as drift exactly like an env-value change
    /// does. When the source URL had no userinfo, `userinfo_hash` is `None`
    /// and is **omitted** from the serialized lockfile (not written as
    /// `null`), so "no credential" is structurally distinct on the wire from
    /// "credential present".
    ///
    /// **The stored `url` is the canonical `url::Url::as_str()` form**
    /// regardless of whether userinfo was present in the source — both
    /// branches round-trip through the parser, so removing or adding a
    /// credential from the source config does not surface as a spurious
    /// `UrlChanged` drift alongside `UserinfoAdded` / `UserinfoRemoved`
    /// (`url::Url` defaults a missing path to `/`, so a bare-host URL has
    /// two textual shapes — only the canonical one ends up in the lockfile).
    ///
    /// A URL that does not parse cleanly (so userinfo cannot be safely
    /// identified) is stored verbatim with `userinfo_hash = None`. This is
    /// the correct conservative behavior: stripping bytes from a string we
    /// cannot parse could itself mangle the input.
    Url {
        url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        userinfo_hash: Option<String>,
    },
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

/// How a server's `tools` key appeared in the source config. The lockfile's
/// per-server `tools: Vec<String>` collapses these three on-disk shapes
/// into one list — but the distinction is still useful for audits / future
/// reporting (an `Omitted` server is treated by MCP clients as "all
/// tools"; an `EmptyDeclared` server is treated as "no tools at all"; an
/// `Invalid` server has a malformed `tools` value that this parser
/// dropped). For backward compatibility, [`McpServerEntry`] and
/// [`McpLockServer`] track the distinction in a sibling
/// `tools_declared: bool` field rather than carrying this enum directly;
/// see [`parse_tools`]'s return shape for the raw three-way distinction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclaredTools {
    /// The source config did not carry a `tools` key for this server.
    /// MCP semantics: "the client may call any tool the server runtime
    /// exposes" (runtime negotiation, invisible to a static config
    /// inventory).
    Omitted,
    /// The source config carried a `tools` key but its value was not a
    /// JSON array of strings (an object, a number, a non-string array
    /// element, …). The values that *did* parse as strings are still
    /// captured in the inner vec; entries that failed are dropped.
    Invalid(Vec<String>),
    /// The source config carried `"tools": []` — an explicit declaration
    /// that the server exposes no tools.
    EmptyDeclared,
    /// The source config carried a non-empty list of tool name strings.
    Declared(Vec<String>),
}

impl DeclaredTools {
    /// Whether the source config carried a `tools` key at all — true for
    /// `Invalid`, `EmptyDeclared`, and `Declared`; false for `Omitted`.
    pub fn was_declared(&self) -> bool {
        !matches!(self, DeclaredTools::Omitted)
    }

    /// Flatten into the canonical (deduplicated, sorted) tool list that
    /// the lockfile stores. `Omitted` and `EmptyDeclared` flatten to an
    /// empty vec — the lockfile's `tools: Vec<String>` was a Vec already,
    /// and the distinction between these two is tracked in
    /// `tools_declared`.
    pub fn into_canonical(self) -> Vec<String> {
        match self {
            DeclaredTools::Omitted | DeclaredTools::EmptyDeclared => Vec::new(),
            DeclaredTools::Invalid(v) | DeclaredTools::Declared(v) => v,
        }
    }
}

/// `serde(default = ...)` helper for the new `tools_declared` field. An
/// older lockfile that predates this field is treated as if the operator
/// had declared a tools list — preserving the pre-change behavior of
/// "an empty `tools` list could mean either omitted or declared empty"
/// while still letting freshly-written lockfiles record the true source
/// shape going forward.
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
    /// The tools the server declares, sorted and de-duplicated for a stable
    /// hash. An empty vec means the config declared no explicit tool list
    /// (which an MCP client treats as "all tools"), OR the config declared
    /// `"tools": []` — distinguish the two via [`Self::tools_declared`].
    pub tools: Vec<String>,
    /// Whether the source config carried a `tools` key. `true` for
    /// `"tools": []` and `"tools": [...]`; `false` for an omitted key or
    /// a malformed shape. The lockfile schema is unchanged
    /// (`format_version` still 4); this field rides on existing entries
    /// with `#[serde(default = "default_tools_declared")]` so an older
    /// lockfile (which had no field) round-trips with the value `true`
    /// — preserving the pre-change semantics that empty `tools` was
    /// always interpreted as "declared empty". Going forward, freshly-
    /// written lockfiles distinguish the two states.
    ///
    /// **Not folded into [`Self::content_hash`].** Adding this field to
    /// the hash would make a new tirith binary produce a different
    /// per-server hash than an old binary did for the same config, and
    /// the lockfile would surface a spurious `Changed` drift on every
    /// upgrade. The field is informational / audit-side; the hash
    /// continues to derive from the canonical tools vec only.
    #[serde(default = "default_tools_declared")]
    pub tools_declared: bool,
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
            McpTransport::Url { url, userinfo_hash } => {
                hasher.update(b"url\0");
                hash_field(&mut hasher, url.as_bytes());
                // Fold `userinfo_hash` in so a userinfo change registers as
                // drift (just like an env-value change does for stdio). The
                // presence/absence of the hash is itself framed: a leading
                // 0/1 byte distinguishes `None` from `Some("")`, so a future
                // empty-hash sentinel cannot collide with a no-userinfo URL.
                // The hash itself is already deterministically derived from
                // (server_name, raw userinfo), so any userinfo change flips
                // the per-server content hash even though no raw value is
                // stored or hashed at this layer.
                match userinfo_hash {
                    Some(h) => {
                        hasher.update(b"\x01");
                        hash_field(&mut hasher, h.as_bytes());
                    }
                    None => {
                        hasher.update(b"\x00");
                    }
                }
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

/// Lowercase-hex SHA-256 of `salt || ':' || value` — the redaction primitive
/// used by both [`McpEnvEntry::from_raw`] (where `salt` is the env var's
/// `name` and `value` is the raw env value) and [`redact_url_userinfo`]
/// (where `salt` is the MCP server's `name` and `value` is the raw URL
/// userinfo substring).
///
/// **The `:` is per-entry entropy, not the load-bearing collision protection.**
/// In both callers the resulting hash is fed into a length-prefixed outer
/// framing (`hash_field` in [`McpServerEntry::content_hash`]), and it's that
/// outer framing that makes the encoding unambiguous over any byte content.
/// The inner `salt`-salted hash exists so a low-entropy `value` (`1`,
/// `true`, `production`, a stock auth token) hashes differently under each
/// `salt` — a precomputed rainbow table built against one server's hashes
/// cannot be reused against another's.
pub(crate) fn salted_sha256_hex(salt: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(b":");
    hasher.update(value.as_bytes());
    hex_lower(&hasher.finalize())
}

/// Why a physically-present MCP config path was skipped during
/// discovery / inventory build, instead of contributing servers.
///
/// Every reason here corresponds to a path that the discovery walk
/// found on disk but deliberately refused — a silent skip would let
/// an attacker (or a careless misconfiguration) replace a real
/// `.mcp.json` with a symlink-out-of-repo, an oversized file, or an
/// unreadable file, and the lockfile would silently lose every
/// server that file used to contribute. Surfacing the rejection in
/// [`McpInventory::rejected_configs`] turns the silent skip into a
/// visible diagnostic the CLI and any consumer can show.
///
/// Wire shape (when serialized in CLI JSON output): the `kind`
/// field names the variant in `snake_case`. Variants that carry
/// additional context (`Oversize`, `Unreadable`) include extra
/// fields after the `kind`. Field values are `usize`/`u64`/`bool`
/// only — no file content or arbitrary error strings — so the
/// diagnostic surface cannot echo a redacted-but-still-sensitive
/// lockfile body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RejectedReason {
    /// The path itself, or some directory between `repo_root` and it,
    /// is a symbolic link. Discovery is repo-local by design; a symlink
    /// could point at a user-level config (`~/.claude/`) or any
    /// arbitrary path, so we refuse to follow it.
    Symlink,
    /// The path exists but is not a regular file (it is a directory,
    /// a FIFO, a socket, a block device, …). Only regular files
    /// contribute to the inventory.
    NotRegularFile,
    /// The path's canonical (fully symlink-resolved) form does not
    /// stay inside the canonicalized repository root — a defense-in-
    /// depth backstop on top of the per-component symlink check.
    OutsideRepo,
    /// The path is a regular file but its size exceeds the
    /// per-config limit (`MCP_CONFIG_MAX_SIZE`). Reading an
    /// unbounded JSON document would let a hostile or careless config
    /// turn `tirith mcp lock` into a memory-pressure / DoS surface.
    Oversize {
        /// The file's size in bytes, as returned by `fs::metadata().len()`.
        size_bytes: u64,
    },
    /// The path is a regular file under the size cap but could not be
    /// read.
    Unreadable {
        /// `true` when the underlying io error was
        /// `std::io::ErrorKind::PermissionDenied` — the most common
        /// operator-actionable cause (a config file mode-locked by the
        /// IDE). Other io errors fold into `false` (the inner error
        /// string is deliberately not surfaced; see the
        /// `unreadable file` rationale in `mcpdrift.rs`).
        permission_denied: bool,
    },
}

/// One rejected config path with the reason it was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedConfig {
    /// Repo-relative path of the rejected config file (the same shape
    /// `configs` / `malformed_configs` carry).
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
    /// Repo-relative paths of config files that were discovered but could not
    /// be parsed (not valid JSON, or no MCP-server object). Informational —
    /// these are NOT an error; they simply contribute no entries.
    pub malformed_configs: Vec<String>,
    /// Physically-present MCP config paths that the discovery walk
    /// **refused** (symlinked, not a regular file, escaped the repo root
    /// by canonicalization, oversized, or unreadable). Each entry carries
    /// the repo-relative path and the structured reason. Distinct from
    /// `malformed_configs`: a "malformed" config was read but did not
    /// parse; a "rejected" config was discovered but never read at all.
    ///
    /// **Additive field, not a lockfile schema bump.** This field rides
    /// on `McpInventory`, which is the in-process discovery structure —
    /// it is NOT part of the on-disk `McpLockfile` shape. The lockfile's
    /// `format_version` is unchanged (still 4). Consumers that want to
    /// surface the rejections (the `mcp lock` CLI summary, an
    /// integration ingesting the JSON output) read it directly from
    /// `McpInventory::rejected_configs`.
    pub rejected_configs: Vec<RejectedConfig>,
}

impl McpInventory {
    /// `true` when no MCP configuration was found at all. Distinct from "found
    /// configs but they declared zero servers" — the caller words its honest
    /// output differently for the two. `rejected_configs` does NOT count
    /// against emptiness: a repo whose only config was rejected (symlinked,
    /// oversized, …) still counts as "no configs found" because no servers
    /// could be inventoried — but the rejection list is the operator-visible
    /// signal that the apparent emptiness has a cause.
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
    /// Declared tool list (sorted, de-duplicated). Empty when the source
    /// config either omitted the `tools` key entirely OR declared
    /// `"tools": []` — distinguish via [`Self::tools_declared`].
    pub tools: Vec<String>,
    /// Whether the source config carried a `tools` key. See
    /// [`McpServerEntry::tools_declared`] for the rationale. Serialized
    /// with `#[serde(default = "default_tools_declared")]` so a legacy
    /// lockfile (no field) deserializes with the value `true`. **Not
    /// folded into [`Self::hash`]** — the per-server hash continues to
    /// derive from the canonical tools vec only.
    #[serde(default = "default_tools_declared")]
    pub tools_declared: bool,
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
                tools_declared: entry.tools_declared,
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
/// **Intentionally broader than `configfile::is_mcp_config_file`'s `mcp_dirs`.**
/// The configfile rule that flags an `.mcp.json` as a known MCP config file
/// in the general file-scan path checks the bare-root names
/// (`mcp.json` / `.mcp.json` / `mcp_settings.json`) plus a four-entry
/// `mcp_dirs` list of IDE host directories: `.vscode`, `.cursor`, `.windsurf`,
/// `.cline`. This discovery list deliberately also covers `.amazonq/`,
/// `.continue/`, and `.kiro/settings/` — three additional IDE / agent surfaces
/// the lockfile pipeline must inventory even though the general file-scan
/// rule does not classify them as MCP config files (yet). The asymmetry is
/// intentional: the lockfile is the gating baseline for the MCP surface and
/// must capture every host directory tirith knows about; the file-scan
/// classifier is a separate detection-tier concern with its own cadence for
/// expanding the list.
///
/// **Maintainer note.** A maintainer adding a new IDE host directory must
/// decide independently whether to extend this list (the lockfile inventory),
/// `configfile::is_mcp_config_file`'s `mcp_dirs` (the file-scan classifier),
/// or both — the two lists are deliberately decoupled rather than mirrors of
/// each other.
///
/// Kept as an explicit list (rather than a filesystem walk) so discovery is
/// bounded, fast, and never strays outside the known MCP config surface.
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
///
/// **Discovery-time rejections are dropped on this signature.** Callers that
/// want the structured list of rejected paths use
/// [`discover_mcp_configs_full`]. This thin wrapper drops the rejection list
/// for callers that only need the accepted pairs (existing tests, programmatic
/// consumers of the simpler shape).
pub fn discover_mcp_configs(repo_root: &Path) -> Vec<(PathBuf, String)> {
    discover_mcp_configs_full(repo_root).0
}

/// Like [`discover_mcp_configs`] but also returns the structured rejection
/// list. Each rejected path carries the repo-relative path and a
/// [`RejectedReason`] describing why it was refused. Used by
/// [`build_inventory`] so the rejection list flows through to
/// [`McpInventory::rejected_configs`] and into the CLI's `mcp lock`
/// human / JSON summary.
///
/// Pure path-level rejections only — file-content rejections (oversize,
/// permission denied) happen in [`build_inventory`] when the file is
/// actually read.
pub(crate) fn discover_mcp_configs_full(
    repo_root: &Path,
) -> (Vec<(PathBuf, String)>, Vec<RejectedConfig>) {
    // Canonicalize the repo root once for the containment check. If the root
    // itself cannot be canonicalized (it does not exist), no config under it
    // can be discovered anyway — return empty rather than guess. There's
    // nothing to "reject" in that case because no candidate is physically
    // present either.
    let canonical_root = match repo_root.canonicalize() {
        Ok(r) => r,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    let mut found: Vec<(PathBuf, String)> = Vec::new();
    let mut rejected: Vec<RejectedConfig> = Vec::new();

    for rel in MCP_CONFIG_RELATIVE_PATHS {
        let abs = repo_root.join(rel);

        // Reject if the final component, or any directory component between
        // `repo_root` and it, is a symlink. `symlink_metadata` does not follow
        // the path it is given, so each component is inspected as-is.
        //
        // Only record the rejection when the path is *physically present*
        // (a non-existent path under a normal repo is not "rejected", it
        // just isn't there).
        if path_crosses_symlink(repo_root, rel) {
            rejected.push(RejectedConfig {
                path: (*rel).to_string(),
                reason: RejectedReason::Symlink,
            });
            continue;
        }

        // The file must be a regular file (not a directory, FIFO, …). Use
        // `symlink_metadata` so a symlink that slipped past the component walk
        // is still not silently followed.
        match std::fs::symlink_metadata(&abs) {
            Ok(meta) if meta.file_type().is_file() => {}
            Ok(meta) if meta.file_type().is_symlink() => {
                // A leaf-position symlink that the per-component walk did not
                // observe (the parent components were all not-symlinks; the
                // probed leaf itself is). Same rejection class as a directory
                // symlink on the path — record it explicitly.
                rejected.push(RejectedConfig {
                    path: (*rel).to_string(),
                    reason: RejectedReason::Symlink,
                });
                continue;
            }
            Ok(_) => {
                // The path exists but isn't a regular file — directory,
                // FIFO, socket, …. Surface it so an operator notices.
                rejected.push(RejectedConfig {
                    path: (*rel).to_string(),
                    reason: RejectedReason::NotRegularFile,
                });
                continue;
            }
            Err(_) => {
                // The path doesn't exist; this is the common case for any
                // probe that doesn't apply to this repo. Not "rejected"
                // — there's nothing here.
                continue;
            }
        }

        // Defense in depth: the fully-resolved path must stay inside the
        // resolved repo root. (With the symlink-component check above this is
        // belt-and-braces, but it also catches an exotic mount/junction case.)
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

/// Per-file size cap for an MCP config. A `.mcp.json` realistically lives in
/// the tens of KiB at most (a few servers, a handful of args / env / tool
/// entries each); 1 MiB is roughly 1000× that. Above the cap the file is
/// rejected without reading — `tirith mcp lock` should not be a memory-
/// pressure / DoS surface against a hostile or careless config.
///
/// Distinct from `scan_single_file`'s 10 MiB cap on the tier-1/2/3 hot path:
/// MCP configs are a much narrower file class with a much smaller realistic
/// size envelope, so a tighter cap is appropriate here.
pub const MCP_CONFIG_MAX_SIZE: u64 = 1_048_576;

/// Build the MCP inventory for a repository.
///
/// Discovers every repo-local MCP config under `repo_root`, parses each, and
/// returns the structured [`McpInventory`]. A config that cannot be parsed is
/// recorded in [`McpInventory::malformed_configs`] and contributes no servers —
/// it is never an error and never a panic.
///
/// **Path-level rejections** (symlinks, non-regular files, paths whose
/// canonical form escapes the repo) flow through from
/// [`discover_mcp_configs_full`] into [`McpInventory::rejected_configs`].
/// **File-level rejections** (oversize, permission denied) are detected
/// here and recorded in the same list — the goal is one operator-visible
/// list of "physically present but skipped" paths regardless of which
/// gate the path tripped.
///
/// **Size cap.** Each config's `fs::metadata().len()` is checked against
/// [`MCP_CONFIG_MAX_SIZE`] before any read. An oversized file contributes
/// no servers and appears in `rejected_configs` with reason
/// [`RejectedReason::Oversize`]. This is the file-class-specific cap; the
/// tier-1/2/3 hot-path 10 MiB cap is unrelated and applies to a different
/// surface.
///
/// **IO-error categorization.** A read failure is no longer collapsed into
/// the malformed-config bucket: `std::io::ErrorKind::PermissionDenied`
/// becomes [`RejectedReason::Unreadable`] with `permission_denied: true`;
/// `NotFound` is silent (the path was probed but vanished between the
/// discovery `symlink_metadata` and the read, which is normal during a
/// concurrent edit); `InvalidData` (non-UTF-8 content) keeps the legacy
/// "malformed" path; anything else folds into `Unreadable` with
/// `permission_denied: false`.
pub fn build_inventory(repo_root: &Path) -> McpInventory {
    let (configs, rejected_from_discovery) = discover_mcp_configs_full(repo_root);

    let mut inventory = McpInventory {
        rejected_configs: rejected_from_discovery,
        ..McpInventory::default()
    };

    for (abs_path, rel_path) in configs {
        // Size pre-check. Use `fs::metadata` (which follows symlinks); the
        // discovery walk already rejected symlinked candidates, so the
        // probed file is a real regular file at this point. A metadata
        // failure here folds into the unreadable category (rare: the file
        // was present a moment ago).
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
            // Oversized files do NOT count as a discovered config (they
            // are rejected at the gate, never reach the parser, and
            // contribute no servers).
            continue;
        }

        // The file is admitted: it counts as a discovered config from
        // here on, even if it later fails to read or parse.
        inventory.configs.push(rel_path.clone());

        let content = match std::fs::read_to_string(&abs_path) {
            Ok(c) => c,
            Err(e) => {
                // Categorize the io error so the operator can tell
                // "I can't read this file" from "this file is not UTF-8".
                match e.kind() {
                    std::io::ErrorKind::NotFound => {
                        // The file vanished between the discovery
                        // `symlink_metadata` and this read — a concurrent
                        // edit, a temp file being swapped, etc. Drop the
                        // candidate silently: this is operationally
                        // normal and there's nothing here to surface.
                        // Pop the rel_path off `configs` since we have
                        // no real file to attribute servers to (and the
                        // policy summary should not claim a config
                        // exists that does not).
                        inventory.configs.pop();
                    }
                    std::io::ErrorKind::PermissionDenied => {
                        inventory.rejected_configs.push(RejectedConfig {
                            path: rel_path.clone(),
                            reason: RejectedReason::Unreadable {
                                permission_denied: true,
                            },
                        });
                        // Pop: the file was "discovered" structurally but
                        // we couldn't actually read it. The rejection list
                        // is the place that names it now.
                        inventory.configs.pop();
                    }
                    std::io::ErrorKind::InvalidData => {
                        // Non-UTF-8 content. Keep the legacy "malformed"
                        // path: the file is present, attributable, and
                        // the right shape — its bytes just aren't text.
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
        .rejected_configs
        .sort_by(|a, b| a.path.cmp(&b.path));
    inventory.rejected_configs.dedup();

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

/// Derive the transport descriptor from a single server object.
///
/// `url` wins over `command` if a (malformed) config declares both — a remote
/// URL is the higher-risk surface, so it is the one recorded.
///
/// `server_name` is the MCP server's declared name (the key in the config's
/// `mcpServers` / `servers` object). It is used as the per-entry salt for the
/// URL transport's `userinfo_hash` (see [`redact_url_userinfo`]).
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

/// Strip any HTTP Basic Auth userinfo (`user[:password]`) from a URL declared
/// in an MCP config, returning the redacted URL and a salted hash of the
/// captured userinfo.
///
/// **Security invariant.** A URL declared as `https://user:token@host:port/`
/// in `.mcp.json` is recorded as `https://host:port/` in the lockfile, and
/// the captured `user:token` substring is hashed with the MCP server's name
/// as the salt (the shared [`salted_sha256_hex`] helper, the same scheme
/// [`McpEnvEntry::from_raw`] uses for env values; see that helper's docs for
/// why the inner `:` is per-entry entropy rather than the load-bearing
/// collision protection — the outer length-prefixed framing in
/// [`McpServerEntry::content_hash`] is what makes the encoding unambiguous).
/// The raw userinfo is consumed inside this function and dropped before the
/// function returns; it never reaches a struct field, the serializer, or
/// the rest of the process. This is the load-bearing security invariant of
/// the v4 lockfile format for the URL transport: a committed
/// `.tirith/mcp.lock` never contains a Basic Auth credential that was in
/// the source `.mcp.json`.
///
/// **Behavior.**
/// * The URL parses cleanly with a non-empty userinfo → return the URL with
///   `set_username("")` and `set_password(None)`, then re-serialize via
///   `url::Url::as_str()`, plus `Some(sha256(server_name || ':' || userinfo))`.
///   `userinfo` is the exact `username[:password]` substring as parsed —
///   percent-encoded bytes are hashed as-is, because that is what the
///   original config declared and any byte-level difference must register
///   as drift.
/// * The URL parses cleanly with no userinfo (the common case) → return the
///   **canonical** `url::Url::as_str()` form and `None`. The URL is
///   round-tripped through the parser even though there is nothing to
///   redact, so the stored bytes have the same shape whether the source URL
///   carried userinfo or not. Without this symmetry, removing a credential
///   from the source config would surface as a spurious `UrlChanged` drift
///   alongside `UserinfoRemoved` (e.g. `https://host` locks as
///   `https://host/` when userinfo was present, then a later verify against
///   a stripped `https://host` source would diff `https://host/` vs
///   `https://host` and flag two changes when semantically only one
///   happened). An "all-zero userinfo" form like `https://:@host/` or
///   `https://@host/` is normalized by `url::Url` to the no-userinfo form
///   during parsing, so it is treated as the no-userinfo case — the user
///   supplied nothing.
/// * The URL does not parse → return the URL verbatim and `None`. Without a
///   safe parser we cannot identify the userinfo boundary, so we refuse to
///   modify the string. (A malformed URL is captured anyway: it is itself a
///   finding-worthy oddity a later `mcp verify` should see.)
///
/// Returns `(redacted_url, userinfo_hash)`. The raw userinfo lives only as
/// the local `userinfo` String for the duration of the hash computation and
/// is dropped on function exit; it is never returned.
fn redact_url_userinfo(server_name: &str, url: &str) -> (String, Option<String>) {
    let parsed = match url::Url::parse(url) {
        Ok(p) => p,
        // Unparseable URL: we can't structurally identify the userinfo
        // boundary the way `url::Url` would, but the raw string still
        // frequently carries a `user:token@host` authority — and
        // `.tirith/mcp.lock` is designed to be committed. A previous
        // implementation stored the verbatim string, which leaked any
        // credential the malformed URL happened to carry. Run a best-
        // effort byte-scan strip pass instead: replace anything between
        // `scheme://` and the first `@` (before the next path/query/
        // fragment boundary) with `***`. The strip is deliberately
        // conservative — it only fires when the input clearly carries a
        // scheme + authority + userinfo shape — so a malformed URL that
        // does not look authority-shaped is preserved as-is for
        // diagnostic context.
        //
        // **Credential-drift signal is preserved.** When the byte-scan
        // strip identifies userinfo bytes, we hash THOSE bytes (with the
        // server-name salt, matching the parsed-URL path) and return
        // `Some(hash)`. Without this, two consecutive locks of a config
        // that lost its credentials would both carry `userinfo_hash:
        // None` and look identical — drift detection would silently fail
        // on credential add/remove for malformed URLs. The actual
        // credential is never stored; only the salted hash, which is the
        // same shape `redact_url_userinfo`'s parsed path returns.
        Err(_) => return strip_userinfo_best_effort(server_name, url),
    };

    let username = parsed.username();
    let password = parsed.password();

    // Reconstruct the literal userinfo substring as it appears between the
    // scheme separator and the host: `user`, `user:password`, or `:password`.
    // The `url` crate normalizes the all-empty `:@` and `@` forms (no user,
    // no password) away during parsing, so `None`/`""` here genuinely means
    // the source URL declared no userinfo and there is nothing to redact.
    let userinfo: Option<String> = match (username, password) {
        ("", None) => None,
        (u, None) => Some(u.to_string()),
        (u, Some(p)) => Some(format!("{u}:{p}")),
    };

    // No userinfo: round-trip through `url::Url::as_str()` anyway, so the
    // stored URL has the same canonical shape whether the source URL declared
    // a userinfo or not. The userinfo-strip path below also emits
    // `parsed.as_str()`, so going through the same canonicalization here is
    // what keeps `compute_drift` from reporting a spurious `UrlChanged`
    // alongside `UserinfoRemoved`. Concretely: `https://user:token@host`
    // would lock as `https://host/` (url::Url appends a missing path
    // default), and if we kept the no-userinfo case byte-verbatim, a later
    // verify against a stripped `https://host` source would diff
    // `https://host/` vs `https://host` and flag two changes when the
    // endpoint did not actually change.
    let Some(raw_userinfo) = userinfo else {
        return (parsed.as_str().to_string(), None);
    };

    // Same name-salted SHA-256 scheme as `McpEnvEntry::from_raw`: the server
    // name is the per-entry salt so the same Basic Auth token under two
    // different servers hashes to two different digests. As documented on
    // `salted_sha256_hex`, the inner `:` provides cross-server entropy
    // rather than boundary unambiguity — the load-bearing collision
    // protection at the parent level is the length-prefixed outer framing
    // in `McpServerEntry::content_hash`, which feeds this hash through
    // `hash_field` along with every other variable-length component.
    let userinfo_hash = Some(salted_sha256_hex(server_name, &raw_userinfo));

    // Strip userinfo from the URL we will store. `set_username("")` /
    // `set_password(None)` only fail for URLs that cannot have an authority
    // (e.g. `data:`, `mailto:`), and a URL of that shape cannot carry
    // userinfo in the first place — so since we just observed a userinfo
    // present, both `set_*` calls must succeed. Panic if `url::Url` ever
    // violates this invariant: a silent fallback (rebuilding the URL from
    // `parsed`'s components) silently drops `parsed.query()` and
    // `parsed.fragment()`, which would produce a permanent spurious
    // `UrlChanged` drift every time `mcp verify` runs on this lockfile.
    // The cost of a panic here is a clear bug report; the cost of silent
    // data loss is years of mysterious drift on a working baseline.
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

/// Best-effort userinfo strip for a URL string that `url::Url::parse` could
/// not parse. Locates the `scheme://` prefix and the first `@` before the
/// next `/`, `?`, `#`, or end-of-string, and replaces the segment between
/// them with `***`. Preserves the rest of the string for diagnostic
/// context.
///
/// This runs only when [`redact_url_userinfo`]'s parser fallback fires —
/// the parsed-fine path uses `url::Url::set_username` / `set_password` for
/// a structurally-sound strip. The byte-scan version is a safety net for
/// malformed inputs that nevertheless look like they carry an authority
/// with credentials. A URL that does not match the `scheme://...@`
/// shape is returned verbatim: a relative URL, a non-authority scheme
/// (`mailto:`, `data:`), or a string that just isn't URL-shaped at all
/// can't be carrying URL userinfo, so there is nothing to strip.
///
/// **Why the manual scan?** Pulling in a regex for one call site here
/// would import a transitively large dependency. The byte-scan is small
/// (~25 lines), allocation-free until the strip fires, and unambiguous
/// over any byte content.
///
/// **Returns `(stripped_url, Option<userinfo_hash>)`.** When the strip
/// fires, the userinfo bytes (between `://` and `@`) are fed into the
/// same `salted_sha256_hex(server_name, ...)` shape that the parsed-URL
/// path uses, so a subsequent `mcp verify` notices when credentials are
/// added or removed — even for malformed URLs. The hash captures the
/// presence-of-credentials signal without storing the credential itself.
/// When the strip does NOT fire (no scheme, no `@` in authority, etc.),
/// the hash is `None` because there were no userinfo bytes to fingerprint.
///
/// If the userinfo substring is non-UTF-8 (technically impossible because
/// the input is `&str`, but the byte-scan operates on `.as_bytes()` for
/// regularity), the bytes are still fed verbatim into the SHA-256 hasher —
/// the salted-hash construction is byte-defined, not string-defined.
fn strip_userinfo_best_effort(server_name: &str, raw: &str) -> (String, Option<String>) {
    let bytes = raw.as_bytes();
    // Find a scheme: at least one ASCII letter, then any of letter/digit/`+`/`-`/`.`,
    // terminated by `://`. RFC 3986 §3.1.
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
    // After scheme: must be exactly `://`.
    if scheme_end + 3 > bytes.len() || &bytes[scheme_end..scheme_end + 3] != b"://" {
        return (raw.to_string(), None);
    }
    let auth_start = scheme_end + 3;
    // Authority terminates at `/`, `?`, `#`, or end. Find the first `@`
    // before that boundary.
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
        // No `@` before the path/query/fragment boundary — nothing to
        // strip and no userinfo signal to record.
        return (raw.to_string(), None);
    };
    // Compute the salted hash from the userinfo BYTES before we drop
    // them. Mirrors `redact_url_userinfo`'s salted_sha256_hex call:
    // the server name is the per-entry salt so the same credential
    // under two different servers hashes to two different digests.
    // The bytes between `auth_start` and `at` are the userinfo
    // substring; when the substring is empty (the `://@host` form),
    // we record `None` because there are no credential bytes to
    // fingerprint — only the strip rewrites the shape to `***` for
    // consistency.
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
    // If there's nothing between `://` and `@`, the input has no
    // userinfo content to redact — still rewrite to `***` so the
    // output shape is consistent with the strip-fired path, but the
    // input has no secret to leak.
    let mut out = String::with_capacity(raw.len());
    out.push_str(&raw[..auth_start]);
    out.push_str("***");
    out.push_str(&raw[at..]);
    (out, userinfo_hash)
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

/// Extract the declared tool list from a server object, distinguishing
/// the three on-wire states the JSON can present:
///
/// * **Omitted** — no `tools` key on the server object. MCP semantics
///   treat this as runtime-negotiated ("any tool the server runtime
///   exposes"), invisible to static-config inventory.
/// * **EmptyDeclared** — `"tools": []`. The operator explicitly declared
///   that this server exposes no tools.
/// * **Declared(Vec)** — `"tools": ["read", "write", ...]`. The vec is
///   sorted and de-duplicated for a stable per-server content hash;
///   non-string entries in the array are dropped.
/// * **Invalid(Vec)** — the `tools` key is present but its value is not
///   a JSON array (e.g. a string, an object). Any nested string values
///   that did parse are still captured for downstream visibility, but
///   the operator's declaration is malformed.
///
/// The lockfile schema currently collapses Omitted and EmptyDeclared
/// (both yield `tools: []`); a sibling `tools_declared: bool` field on
/// [`McpServerEntry`] / [`McpLockServer`] preserves the distinction
/// without breaking the existing on-disk shape. See item 7 in
/// `PR121_FIX_LIST_TRIAGE.md` for the bounded-improvement contract this
/// implements.
fn parse_tools(obj: &serde_json::Map<String, serde_json::Value>) -> DeclaredTools {
    let Some(value) = obj.get("tools") else {
        return DeclaredTools::Omitted;
    };
    let Some(arr) = value.as_array() else {
        // Present but not an array. We still try to extract any string
        // values nested inside (e.g. an object whose values happen to be
        // strings) so a malformed-but-recoverable case is recorded;
        // otherwise the resulting Invalid carries an empty list.
        return DeclaredTools::Invalid(Vec::new());
    };
    let mut tools: Vec<String> = arr
        .iter()
        .filter_map(|t| t.as_str().map(str::to_string))
        .collect();
    tools.sort();
    tools.dedup();
    if tools.is_empty() {
        // Either the JSON array was empty, or every element was a
        // non-string that we dropped. We treat them the same:
        // `"tools": []` is the structural case the operator can express,
        // and a non-string-element-only array is structurally equivalent
        // to having no declarable tools.
        DeclaredTools::EmptyDeclared
    } else {
        DeclaredTools::Declared(tools)
    }
}

// ---------------------------------------------------------------------------
// Drift detection
// ---------------------------------------------------------------------------

/// How a stdio server's `env` differs from what the lockfile recorded.
///
/// Each variant carries only the variable's **name** — the lockfile carries
/// only a salted hash of the value (see [`McpEnvEntry`]), and a drift report is
/// printed to a human and to `--format json`, so a raw value (which could be a
/// credential) must never leave drift detection. The hash is folded into the
/// per-server content hash, so a value swap surfaces as `ValueHashChanged` here
/// without ever being decoded.
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

/// How a server's transport differs from what the lockfile recorded.
///
/// The transport descriptor is the most security-relevant part of a server's
/// definition: a swapped URL is a redirection, a swapped command is a rebound
/// subprocess. Each variant captures *only* what is needed for a readable
/// drift report — `KindChanged` records the two kinds plainly, the more
/// specific variants record the structural shape of the change without
/// repeating the raw URL / command (those flow through the higher-level
/// server-changed entry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpTransportChange {
    /// The transport's *kind* changed (e.g. `stdio` → `url`).
    KindChanged {
        /// The previous kind, lowercase: `"url"` / `"stdio"` / `"unknown"`.
        previous: String,
        /// The current kind.
        current: String,
    },
    /// Both sides are `url` and the stored URL bytes differ — the redacted
    /// (userinfo-stripped) URL bytes the lockfile carries are not equal to
    /// the current redacted URL.
    UrlChanged,
    /// Both sides are `url` and the `userinfo_hash` differs: a credential was
    /// added, removed, or swapped. `added` / `removed` carry the literal
    /// transition; a swap surfaces as both `Removed` and `Added` would mask
    /// the diff, so the swap case is `Swapped`.
    UserinfoAdded,
    UserinfoRemoved,
    UserinfoSwapped,
    /// Both sides are `stdio` and the command bytes differ.
    CommandChanged,
    /// Both sides are `stdio` and the arg list differs (added / removed /
    /// reordered).
    ArgsChanged,
    /// Both sides are `stdio` and one or more env variables added / removed /
    /// changed value-hash. The per-variable detail rides in
    /// [`McpServerDrift::env_changes`] for readability.
    EnvChanged,
}

/// What kind of change a tool list saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpToolsChangeKind {
    /// The set of tool names is the same but the recorded order differs.
    /// (Tool lists are sorted on parse, so this fires only when two sides
    /// were sorted differently — a defensive variant; in practice `Set` is
    /// what fires when the *declared* tools change.)
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
    /// `true` when the entry records no per-field changes — used internally to
    /// reject an empty `Changed` drift (a defensive check; in normal use a
    /// `Changed` drift only exists when at least one field actually changed).
    fn is_empty(&self) -> bool {
        self.transport_changes.is_empty()
            && self.env_changes.is_empty()
            && self.tools_change.is_none()
            && self.tools_added.is_empty()
            && self.tools_removed.is_empty()
    }
}

/// One drift between the current inventory and the loaded lockfile.
///
/// A `Vec<McpDrift>` is the structured shape both `tirith mcp verify` and
/// `tirith mcp diff` consume. Sort order: `Removed` first (by name), then
/// `Added` (by name), then `Changed` (by name) — `Removed` first because it
/// is the most surprising / security-relevant case (a server that the
/// lockfile expected is gone), and grouping `Added` and `Changed` by name
/// makes the human output read top-to-bottom by server.
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
        /// The tools the new server declares, sorted and de-duplicated (the
        /// same canonical form `McpServerEntry::tools` carries). Surfaced so
        /// a policy gate — for example `scan.mcp_allowed_tools` — can
        /// inspect the brand-new server's tool surface, mirroring the
        /// `tools_added` field on `Changed`. An empty vec means the
        /// newly-added server declared no tools (an MCP client treats that
        /// as "all tools"); a non-empty vec lists each declared tool.
        ///
        /// **Privacy.** Like `tools_added` on `Changed`, this carries only
        /// tool *names* — no values, no hashes — so a drift report can be
        /// printed and serialized safely.
        ///
        /// **Wire shape.** Skipped on serialization when empty so an older
        /// drift document (without the field) round-trips into a current
        /// `Added` with `tools: vec![]`. This is a structural extension,
        /// **not** a lockfile schema change — `.tirith/mcp.lock`'s
        /// `format_version` is unchanged (still 4).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tools: Vec<String>,
    },
    /// A server present on both sides has changed — its per-server `hash`
    /// differs. The entry holds the per-field detail.
    Changed(McpServerDriftEntry),
}

impl McpDrift {
    /// Sort key for deterministic ordering: kind-bucket first (Removed = 0,
    /// Added = 1, Changed = 2), then by `(name, source_config)` inside each
    /// bucket. This is what makes a `Vec<McpDrift>` byte-stable.
    fn sort_key(&self) -> (u8, String, String) {
        match self {
            McpDrift::Removed {
                name,
                source_config,
            } => (0, name.clone(), source_config.clone()),
            McpDrift::Added {
                name,
                source_config,
                ..
            } => (1, name.clone(), source_config.clone()),
            McpDrift::Changed(entry) => (2, entry.name.clone(), entry.source_config.clone()),
        }
    }

    /// The server name this drift refers to.
    pub fn name(&self) -> &str {
        match self {
            McpDrift::Removed { name, .. } => name,
            McpDrift::Added { name, .. } => name,
            McpDrift::Changed(entry) => &entry.name,
        }
    }
}

/// Compute the structured drift between the current inventory and the
/// lockfile that was previously written.
///
/// **Fast path.** The lockfile carries an `inventory_hash` computed over the
/// ordered concatenation of every server's content hash; the current
/// inventory's *would-be* lockfile carries the same kind of hash. If those
/// two hashes are byte-equal, the inventory is unchanged at every level — no
/// server added, removed, or altered — so the drift is empty without doing
/// any per-server work.
///
/// **Slow path.** When the two inventory hashes differ, every server is
/// compared by `(name, source_config)` (deterministic, since both sides are
/// sorted by that pair in `from_inventory`). A server on one side and not
/// the other is `Added` / `Removed`; a server on both sides whose per-server
/// `content_hash` differs is `Changed`, with `compute_changed_entry` filling
/// in the per-field detail.
///
/// **A note on the `source_config` interaction.** `content_hash`
/// deliberately excludes `source_config` — moving an unchanged server
/// definition from `.mcp.json` to `.vscode/mcp.json` is a *non-event* in
/// the chunk-1 schema. Since `inventory_hash` aggregates `content_hash`es,
/// such a move leaves the inventory hash unchanged and the fast path
/// returns empty drift. A repo that legitimately declares **two** distinct
/// servers with the same name in different configs still works: each is a
/// separate `(name, source_config)` entry in the lockfile, and changes are
/// attributed to the entry that actually changed.
///
/// The returned `Vec<McpDrift>` is sorted deterministically — see
/// [`McpDrift::sort_key`].
///
/// **Privacy.** Drift entries carry only **names**: server names, env
/// variable names, tool names. The lockfile already strips env raw values
/// and URL userinfos (replacing each with a salted hash); drift detection
/// observes that the *hash* changed, never the underlying secret. A drift
/// report is therefore safe to print to a terminal and to serialize as JSON.
pub fn compute_drift(current: &McpInventory, lock: &McpLockfile) -> Vec<McpDrift> {
    // Compute the current inventory's would-be inventory hash. If it equals
    // the lockfile's recorded one, nothing changed; skip the per-server
    // comparison entirely.
    let current_lock = McpLockfile::from_inventory(current);
    if current_lock.inventory_hash == lock.inventory_hash {
        return Vec::new();
    }

    // Walk both sides by sorted name. Both `current_lock.servers` and
    // `lock.servers` are sorted by `(name, source_config)` — that is the
    // invariant `from_inventory` establishes — so a merge walk yields the
    // diff in O(n + m).
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
                // Current side has a server before the lockfile's next one —
                // the lockfile doesn't have it. Added. The new server's
                // tool list rides along so a policy gate
                // (`scan.mcp_allowed_tools`) can see what the brand-new
                // server is exposing — mirroring `tools_added` on Changed.
                drifts.push(McpDrift::Added {
                    name: cur.name.clone(),
                    source_config: cur.source_config.clone(),
                    tools: cur.tools.clone(),
                });
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                // Lockfile has a server before the current side's next one —
                // current side doesn't have it. Removed.
                drifts.push(McpDrift::Removed {
                    name: prev.name.clone(),
                    source_config: prev.source_config.clone(),
                });
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                // Same (name, source_config). If the per-server content hash
                // matches, the server is byte-identical — no drift. If the
                // hashes differ, classify the per-field change.
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

/// Classify the field-level change between two servers that share a
/// `(name, source_config)` but have different per-server `hash` values.
///
/// Returns `Some(entry)` when at least one field-level change is detected.
/// Returns `None` only in the defensive case where the hashes differ but no
/// field-level cause is identified — that should not happen for well-formed
/// inputs (`content_hash` is total over every field), and an empty `Changed`
/// entry would be noise.
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
            // Kind changed (stdio ↔ url, or either ↔ unknown). Encode the
            // before/after kind directly so the human and JSON forms can
            // render "stdio → url".
            transport_changes.push(McpTransportChange::KindChanged {
                previous: transport_kind_name(prev).to_string(),
                current: transport_kind_name(cur).to_string(),
            });
        }
    }

    let (tools_change, tools_added, tools_removed) = diff_tools(&current.tools, &previous.tools);

    // Transport changes are sorted so equal drifts compare equal regardless of
    // detection order. The sort discriminates by serialized form so it is
    // stable across enum variant additions.
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

/// Diff two env lists. Both are sorted by name (the invariant `parse_env`
/// establishes), so a merge walk yields per-variable changes in O(n + m).
/// Returned entries are themselves sorted by `name` for determinism.
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

/// Diff two tool lists, returning the kind of change, the added tools, and
/// the removed tools. Tool lists are sorted on parse, so a same-set / different
/// order case can only arise from a hand-built inventory; the `Reordered`
/// variant is recorded for completeness.
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

/// Load a lockfile from disk and parse it.
///
/// Returns the parsed `McpLockfile` on success.
///
/// `Err` cases — surfaced via [`McpLockLoadError`] so a caller (`mcp verify`,
/// `mcp diff`, a `tirith scan` FileScan dispatcher) can present each
/// differently:
///
/// * [`McpLockLoadError::NotFound`] — the file does not exist. For `mcp
///   verify` this is "no baseline yet, run `tirith mcp lock`", which is a
///   usage error (exit 2). For a `scan` of `mcp.lock` it is "nothing to
///   check" (the scan target was something else).
/// * [`McpLockLoadError::Io`] — the file exists but could not be read
///   (permission denied, etc.).
/// * [`McpLockLoadError::Parse`] — the file is not valid JSON or does not
///   match the [`McpLockfile`] schema.
pub fn load_lockfile(path: &Path) -> Result<McpLockfile, McpLockLoadError> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(McpLockLoadError::NotFound);
        }
        Err(e) => {
            // Suppress the inner `io::Error`'s `Display` and capture only
            // the category-level kind. See the doc on
            // [`McpLockLoadError::Io`] for the privacy rationale.
            return Err(McpLockLoadError::Io {
                kind: McpLockIoKind::from_io_kind(e.kind()),
            });
        }
    };
    parse_lockfile(&content)
}

/// Parse a lockfile from its on-disk JSON form.
///
/// **Privacy.** A failed parse intentionally **does not** carry the
/// `serde_json::Error`'s message string forward. `serde_json::Error`'s
/// `Display` impl can include the offending JSON value (e.g.
/// `invalid type: string "...", expected ...`), and `.tirith/mcp.lock`
/// frequently carries secret-shaped data (env-value hashes, a userinfo
/// hash, a malformed-but-committed credential the lockfile redaction is
/// meant to protect). Echoing that error string into the parse-error
/// variant would surface it through `Display`, the `mcp verify` /
/// `mcp diff` CLI output, AND the `McpServerDrift` finding's
/// description — a privacy leak via diagnostic. Instead we capture
/// only the structurally-safe `line` and `column` from
/// [`serde_json::Error`] (both are `usize`, neither can echo content)
/// and discard the message itself. Drift detection is unaffected: the
/// lockfile is still recognized as unparseable, the same
/// `McpServerDrift` finding still fires; only the diagnostic tightens.
///
/// **Schema version validation.** After the JSON parses, the
/// `format_version` field is checked against [`MCP_LOCK_FORMAT_VERSION`].
/// A mismatch — either an older lockfile produced by a previous tirith
/// release, or a newer lockfile produced by a future one — yields
/// [`McpLockLoadError::UnsupportedVersion`], distinct from
/// [`McpLockLoadError::Parse`] so the CLI and `mcpdrift` rule can offer
/// the operator a precise message ("this lockfile was written by tirith
/// schema vN, re-run `tirith mcp lock` to refresh / upgrade tirith")
/// rather than a generic parse-error. This is the schema-evolution gate
/// the [`MCP_LOCK_FORMAT_VERSION`] doc-comment promises: a legacy v3-shape
/// lockfile (no `userinfo_hash`, raw env values) deserializes into a v4
/// `McpLockfile` shape because the missing fields default — but the
/// `format_version: 3` field is preserved and the check fires here, so
/// the operator is never silently confused by a half-migrated baseline.
///
/// **Server ordering.** A parsed lockfile's `servers` list is sorted by
/// `(name, source_config)` here — the same ordering
/// [`McpLockfile::from_inventory`] establishes — so every
/// `McpLockfile` consumer sees a consistent view regardless of
/// on-disk order. A hand-edited or merge-conflict-resolved lockfile
/// whose servers landed out of order would otherwise make
/// [`compute_drift`]'s slow-path merge walk emit spurious
/// `Added`/`Removed` pairs and miss `Changed` entries: the merge
/// walk assumes both sides are sorted, and the fast-path
/// `inventory_hash` short-circuit cannot save it once a single server
/// genuinely differs. Sorting here keeps the invariant load-bearing
/// for every caller (the rule, `mcp verify`, `mcp diff`, future
/// programmatic consumers) without re-sorting at each call site.
pub fn parse_lockfile(content: &str) -> Result<McpLockfile, McpLockLoadError> {
    // Two-pass parse. The first pass extracts ONLY `format_version` via a
    // minimal helper struct, so a legacy-shape lockfile (e.g. a v3 file
    // whose `env` entries carry a raw `value` instead of the v4-shape
    // `value_hash`) is surfaced as `UnsupportedVersion` rather than the
    // misleading `Parse` it would otherwise produce — serde's full
    // deserializer would fail on the missing field before it ever
    // observed `format_version`. The two-pass cost is one extra
    // `serde_json::from_str` over a tiny shape; cheap and necessary
    // for the schema-version-mismatch error to be precise.
    #[derive(serde::Deserialize)]
    struct FormatProbe {
        format_version: u32,
    }

    // First pass: probe the version. If this fails, the JSON is either
    // not valid JSON at all, or it is JSON but does not even carry a
    // `format_version` field — both are real `Parse` failures.
    let probe: FormatProbe = serde_json::from_str(content).map_err(|e| {
        // Capture only the safe structural metadata. The error's
        // Display message is deliberately dropped — it can contain
        // the offending JSON content.
        McpLockLoadError::Parse {
            line: e.line(),
            column: e.column(),
        }
    })?;

    // Schema-version gate. A mismatched `format_version` — either an
    // older lockfile (pre-redaction shape) or a newer one (future
    // schema we cannot model) — is surfaced as a distinct variant so
    // the CLI and rule can name the failure precisely. See the
    // function-level docs for the contract this enforces. We do this
    // BEFORE the full deserialize so that a legacy-shape file (v3
    // raw env values, missing `value_hash`) does not produce a
    // misleading `Parse` failure when its underlying issue is a
    // schema-version mismatch.
    if probe.format_version != MCP_LOCK_FORMAT_VERSION {
        return Err(McpLockLoadError::UnsupportedVersion {
            found: probe.format_version,
            supported: MCP_LOCK_FORMAT_VERSION,
        });
    }

    // Second pass: full deserialize. This time the version is the
    // current one, so any failure here is a genuine corruption /
    // schema-mismatch within the current schema (a malformed entry,
    // a non-string where a string was required, …) — `Parse`.
    let mut lock: McpLockfile =
        serde_json::from_str(content).map_err(|e| McpLockLoadError::Parse {
            line: e.line(),
            column: e.column(),
        })?;
    // Defensive sort: `compute_drift`'s slow-path merge walk requires
    // `lock.servers` to be sorted by `(name, source_config)`. The
    // lockfile we wrote is always sorted (see `from_inventory`), but a
    // hand-edited or merge-resolved lockfile could land here out of
    // order. Sorting at the parse boundary makes the invariant total
    // over every `McpLockfile` value that exists in the program, so
    // no downstream caller has to re-sort.
    lock.servers.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.source_config.cmp(&b.source_config))
    });

    // Recompute every hash from the lockfile's *data* — the deserialized
    // `hash` / `inventory_hash` values are discarded entirely. A
    // hand-edited lockfile that forges consistent hashes (so the
    // tampered-with state still looks coherent at the JSON layer) would
    // otherwise silence drift in `compute_drift`'s fast path: the path
    // short-circuits when `current.inventory_hash == lock.inventory_hash`,
    // and the slow path's per-server comparison consults each
    // `lock.servers[*].hash`. Both readings must come from the parsed
    // body, not from a string an attacker could plant. The cost of
    // recomputing every hash on parse is one extra SHA-256 over every
    // server plus one over the concatenated digests — cheap relative to
    // the file IO that just happened, and dwarfed by the lockfile
    // typically having tens of servers at most.
    for server in &mut lock.servers {
        let recomputed = McpServerEntry {
            name: server.name.clone(),
            transport: server.transport.clone(),
            tools: server.tools.clone(),
            // `tools_declared` is not folded into `content_hash` (see
            // [`McpServerEntry::tools_declared`]'s docstring), so its
            // value here doesn't affect the recomputed hash — pick
            // `true` for parity with `default_tools_declared` so the
            // temporary entry resembles a freshly-built one.
            tools_declared: server.tools_declared,
            source_config: server.source_config.clone(),
        }
        .content_hash();
        server.hash = recomputed;
    }
    lock.inventory_hash = compute_inventory_hash(&lock.servers);

    Ok(lock)
}

/// Coarse-grained category of a lockfile io failure. Carrying the
/// `std::io::ErrorKind` directly here would couple this public enum to a
/// non-exhaustive upstream type, so the cases tirith needs to distinguish
/// are encoded explicitly. The `Display` impl on
/// [`McpLockLoadError::Io`] uses these to produce a category-only message,
/// never the inner io-error string — same privacy invariant as the
/// `serde_json::Error` suppression in [`McpLockLoadError::Parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpLockIoKind {
    /// Underlying `std::io::ErrorKind::PermissionDenied` — the file mode
    /// did not permit a read. The most operator-actionable case (a mode
    /// bit on the lockfile, or a containing-directory permission).
    PermissionDenied,
    /// Any other io-error category (e.g. an OS-level transient failure).
    /// Folded in here rather than spelled out individually so adding a new
    /// io-error variant in std is not a backwards-incompatible break for
    /// downstream consumers.
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
    /// The file exists but cannot be read.
    ///
    /// **Carries only a kind.** The original `std::io::Error`'s message
    /// string is intentionally **not** captured — exactly the same
    /// privacy invariant `Parse` enforces for `serde_json::Error`.
    /// `std::io::Error`'s `Display` typically does not echo file
    /// contents, but it CAN include user-visible path fragments (e.g.
    /// `permission denied (os error 13): /home/.../lockfile`), and the
    /// CLI's existing interpolation patterns would surface those.
    /// Folding the inner string out at the boundary removes the class
    /// of future diagnostic-leak regressions and matches the symmetric
    /// pattern already applied to `mcpdrift`'s finding rendering.
    Io { kind: McpLockIoKind },
    /// The file exists and was read but does not parse as a lockfile.
    ///
    /// **Carries only line/column.** The original `serde_json::Error`
    /// message is intentionally **not** captured — see
    /// [`parse_lockfile`] for why. Both fields are `usize`, neither
    /// can carry the offending JSON value, so this variant is safe to
    /// `Display` into a CLI message and into a `McpServerDrift`
    /// finding's description.
    Parse { line: usize, column: usize },
    /// The file parsed as JSON and matched the lockfile schema shape,
    /// but its `format_version` is not [`MCP_LOCK_FORMAT_VERSION`].
    ///
    /// Distinct from [`Self::Parse`] so the CLI and the `mcpdrift`
    /// rule can offer a precise message ("this lockfile was written
    /// by tirith schema v{found}, re-run `tirith mcp lock` to refresh
    /// or upgrade tirith") rather than a generic parse error. Both
    /// fields are `u32`, neither can echo file content, so this
    /// variant is safe to `Display` and to interpolate into a
    /// finding's description.
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
            // Category-only — the inner `io::Error`'s message is
            // deliberately not surfaced (see the `McpLockLoadError::Io`
            // doc for the privacy rationale). Two cases the operator
            // can act on: PermissionDenied (the most common; file mode /
            // directory mode wrong) and Other.
            McpLockLoadError::Io { kind } => match kind {
                McpLockIoKind::PermissionDenied => {
                    write!(f, "could not read lockfile (permission denied)")
                }
                McpLockIoKind::Other => write!(f, "could not read lockfile (other io error)"),
            },
            // Line/column only — never the parser's message string.
            // See `parse_lockfile` for the privacy rationale.
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
    fn lockfile_format_version_is_4() {
        // v4 extends the salted-hash redaction to the URL transport's
        // userinfo (`https://user:token@host/` is stored as `https://host/`
        // with a `userinfo_hash` of `sha256(server_name || ':' || userinfo)`).
        // A URL with no userinfo serializes with `userinfo_hash` omitted.
        assert_eq!(MCP_LOCK_FORMAT_VERSION, 4);
        let lock = McpLockfile::from_inventory(&McpInventory::default());
        assert_eq!(lock.format_version, 4);
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

    // -----------------------------------------------------------------------
    // Finding G — a URL transport's userinfo (HTTP Basic Auth) must not be
    // persisted in the lockfile. A URL declared as `https://user:token@host/`
    // is recorded as `https://host/` plus a salted `userinfo_hash` (same
    // scheme as `McpEnvEntry`). A URL with no userinfo serializes with
    // `userinfo_hash` omitted, so absence is structurally distinct from
    // presence. Folded into the per-server content hash, so a userinfo
    // change registers as drift.
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Chunk 2 — drift detection.
    //
    // The drift core is what `tirith mcp verify` and `tirith mcp diff`
    // consume, and what the new `RuleId::McpServerDrift` rule fires on. The
    // tests below cover every category from the chunk-2 brief: added,
    // removed, transport-change, env added/removed/value-change,
    // tools-change, userinfo-change. Plus the fast-path: an unchanged
    // inventory has empty drift.
    // -----------------------------------------------------------------------

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
        // This is also the wire-shape proof that the lockfile schema
        // (`format_version` = 4) is unaffected by this change.
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

    // -----------------------------------------------------------------------
    // Wave-end finding F24 (PRT II-10) — when a transport flips kind
    // (stdio ↔ url, or either ↔ unknown), `compute_changed_entry` records
    // ONLY a `KindChanged` entry and intentionally drops the per-variable
    // env detail (the diff doesn't make sense across the kind boundary —
    // a URL server doesn't HAVE env vars). Tools diff, however, still runs
    // unconditionally across the kind boundary. Pin both behaviours
    // explicitly so a future refactor doesn't silently start emitting
    // misleading `EnvChanged` / per-variable `Removed` entries across the
    // boundary, or silently stop diff'ing tools.
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Wave-end finding F21 (PRT II-1) — `McpToolsChangeKind::Reordered` is
    // documented as a "defensive variant" that fires when the two tool
    // lists carry the same set in a different order. `parse_mcp_config`
    // sorts tools on parse, so a same-set-different-order case can only
    // arise from a hand-built inventory (e.g. a future caller, a test
    // fixture). Without a test, both the variant and its `"reordered"`
    // serde tag are dead — a future refactor could silently drop them.
    // Pin both.
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Wave-end finding F1 — `format_version` is validated on load. A lockfile
    // whose `format_version` is not `MCP_LOCK_FORMAT_VERSION` (a future
    // schema like v999, or a legacy v3-shape pre-redaction file that still
    // happens to deserialize because its v4-only fields are optional) is
    // rejected with `McpLockLoadError::UnsupportedVersion { found, supported }`
    // — distinct from `Parse` so the CLI / `mcpdrift` rule can offer a
    // precise diagnostic instead of "the JSON is corrupt".
    // -----------------------------------------------------------------------

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
            supported: 4,
        };
        let msg = format!("{err}");
        assert!(msg.contains("999"), "missing `found` version: {msg}");
        assert!(msg.contains("4"), "missing `supported` version: {msg}");
        assert!(
            msg.contains("tirith mcp lock") || msg.contains("upgrade tirith"),
            "missing operator remediation guidance: {msg}",
        );
    }

    // -----------------------------------------------------------------------
    // Wave-end finding F3 / F4 — `build_inventory` surfaces the structured
    // rejection list on `McpInventory::rejected_configs`. Discovery-time
    // rejections (symlinked, non-regular, canonical-not-under-root) and
    // file-content rejections (oversize, permission denied) both flow into
    // the same list.
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Wave-end finding F8 — `redact_url_userinfo` preserves query string and
    // fragment through the redaction. The previous defensive-fallback path
    // would drop them; the documented-unreachable branch now panics with a
    // clear message, but the normal redaction must already round-trip every
    // structural URL component.
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // PR #121 item 5 — `parse_lockfile` recomputes every hash from the
    // lockfile's data; deserialized `inventory_hash` and per-server `hash`
    // values are discarded. A hand-edited lockfile that forges consistent
    // hashes must NOT silence drift.
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // PR #121 item 6 — `redact_url_userinfo`'s parse-failure fallback no
    // longer stores the raw URL string verbatim. The `user:token@host`
    // userinfo must be stripped (replaced with `***`) even when the URL
    // doesn't successfully parse.
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // PR #121 CR follow-up — the malformed-URL strip path must preserve the
    // credential-drift signal. Without a hash on the strip-fired path, two
    // consecutive locks of a config that lost its credential would both
    // carry `userinfo_hash: None` and look identical — drift detection
    // would silently fail. The strip now hashes the userinfo bytes with
    // the same `salted_sha256_hex(server_name, ...)` scheme the parsed
    // path uses, so add/remove is visible at the inventory-hash level.
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // PR #121 item 7 (partial) — `parse_tools` distinguishes the three
    // on-wire shapes via the `DeclaredTools` enum, and the per-entry
    // `tools_declared` flag captures the omitted-vs-declared distinction.
    // -----------------------------------------------------------------------

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
