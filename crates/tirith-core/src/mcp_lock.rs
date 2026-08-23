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

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

/// Lockfile format version. Bump only on a breaking schema change.
///
/// **Enforced at load:** [`parse_lockfile`] rejects a `format_version` other
/// than this (or v4 through v7, the migration carve-outs) with a dedicated
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
/// * `6` — captures the LIVE `tools/list` descriptors a server actually
///   advertises (description / inputSchema / outputSchema / annotations / icons),
///   each hashed via the explicit [`canonical_json`] so a re-ordered-key or
///   whitespace-only re-serialization is NOT drift but a real surface change is.
///   The new [`McpLockServer::descriptors`] is captured at runtime (the static
///   config files do not carry it), so a `tirith mcp lock` over config alone
///   produces an empty descriptor list — descriptors are populated when the
///   gateway observes a `tools/list` response. The descriptor set folds into a
///   SEPARATE [`McpLockServer::descriptor_hash`], NOT `content_hash`, so static
///   config drift is byte-for-byte unchanged from v5. A v5 lockfile under later
///   tagged [`LockfileSchema::LegacyV5Migration`]; its on-disk shape is identical
///   (the descriptor field serde-defaults to empty), so per-server static drift
///   runs normally and [`compute_drift`] adds a single
///   [`McpDrift::SchemaUpgradeRequired`] (re-lock once to capture live
///   descriptors). See [`ToolDescriptor`] / [`compute_descriptor_drift`].
/// * `7` — expands the exact Tool descriptor hash to include `title`, `execution`,
///   and `_meta`, and records the effective gateway launch fingerprint used for
///   descriptor approval. A v6 lock is accepted only as an explicit migration
///   input; it cannot authorize a live gateway until re-approved under v7.
/// * `8` — replaces the deterministic env-value and URL-userinfo SHA-256
///   commitments with a fixed structural presence marker. Secret rotation no
///   longer drifts, but adding/removing an env key or URL userinfo still does. A
///   v7 lock is accepted only as a migration input: its commitments are erased
///   in memory and the operator must re-lock before it can authorize a gateway.
pub const MCP_LOCK_FORMAT_VERSION: u32 = 8;

/// Fixed wire value for a secret-bearing field whose presence is structurally
/// relevant. It is deliberately independent of the secret, so a committed lock
/// cannot be used as an offline dictionary oracle. The historical field names
/// (`value_hash` / `userinfo_hash`) remain for wire compatibility during the v7
/// migration, but v8 accepts and emits only this value.
const SECRET_PRESENT_MARKER: &str = "present";

/// Basename of the lockfile, written under `<repo_root>/.tirith/`.
pub const MCP_LOCK_FILENAME: &str = "mcp.lock";

/// One environment variable a stdio MCP server is launched with, as captured in
/// the lockfile.
///
/// **The raw value is never stored or committed** (env values are commonly
/// credentials). In v8 the historical `value_hash` field contains only the fixed
/// `SECRET_PRESENT_MARKER`, which records that the named variable exists
/// without creating a dictionary-recoverable commitment to its value. Adding or
/// removing a name still drifts; rotating its value intentionally does not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpEnvEntry {
    /// The env var's name (the key in the config's `env` object).
    pub name: String,
    /// Fixed `SECRET_PRESENT_MARKER`. The field name is retained so legacy v7
    /// lockfiles can be migrated without a second transport shape.
    #[serde(serialize_with = "serialize_secret_presence_marker")]
    pub value_hash: String,
}

impl McpEnvEntry {
    /// Build an entry from `(name, raw_value)` without retaining or committing
    /// the value. The value argument exists because config parsing must validate
    /// that a string was declared, but it is never read.
    pub fn from_raw(name: &str, _raw_value: &str) -> Self {
        McpEnvEntry {
            name: name.to_string(),
            value_hash: SECRET_PRESENT_MARKER.to_string(),
        }
    }
}

/// Serialize a secret-presence field as the fixed v8 marker regardless of how a
/// public struct was constructed. This closes the direct-serialization path as
/// well as the normal [`McpLockfile::render`] path.
fn serialize_secret_presence_marker<S>(_value: &String, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(SECRET_PRESENT_MARKER)
}

fn serialize_optional_secret_presence_marker<S>(
    value: &Option<String>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(_) => serializer.serialize_some(SECRET_PRESENT_MARKER),
        None => serializer.serialize_none(),
    }
}

/// Refuse to serialize a URL transport that still contains credential-bearing
/// material. Config parsing normally strips URL userinfo and rejects secret
/// query/fragment values, but `McpTransport` is a public type and callers may
/// construct it directly. The serializer is therefore the final privacy
/// boundary for both `McpLockfile::render` and direct serde use.
fn serialize_commit_safe_url<S>(value: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if !transport_url_is_commit_safe(value) {
        return Err(<S::Error as serde::ser::Error>::custom(
            "refusing to serialize a secret-bearing MCP URL",
        ));
    }
    serializer.serialize_str(value)
}

/// Refuse to serialize literal credentials from a directly-constructed stdio
/// transport. Explicit environment references remain safe because the lockfile
/// records only the reference, never its resolved value.
fn serialize_commit_safe_args<S>(value: &Vec<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if args_have_secret_bearing_value(value) {
        return Err(<S::Error as serde::ser::Error>::custom(
            "refusing to serialize secret-bearing MCP arguments",
        ));
    }
    value.serialize(serializer)
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
    /// (the v3 threat model). When userinfo was present, the historical
    /// `userinfo_hash` field is `Some("present")`; when absent it is `None` and
    /// **omitted** from the wire, so absence is structurally distinct from
    /// presence without committing a verifier for the credential. The stored
    /// `url` is always the canonical `url::Url::as_str()`
    /// form (both branches round-trip the parser), so adding/removing a
    /// credential doesn't surface as a spurious `UrlChanged` alongside
    /// `Userinfo*`. An unparseable URL is best-effort-stripped (`***@`) with a
    /// presence marker; a non-authority-shaped one is kept
    /// verbatim with `None`. See [`redact_url_userinfo`].
    Url {
        #[serde(serialize_with = "serialize_commit_safe_url")]
        url: String,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            serialize_with = "serialize_optional_secret_presence_marker"
        )]
        userinfo_hash: Option<String>,
    },
    /// A local MCP server spawned as a subprocess.
    Stdio {
        /// The executable to run.
        command: String,
        /// Arguments, in declared order.
        #[serde(default, serialize_with = "serialize_commit_safe_args")]
        args: Vec<String>,
        /// Env vars the config injects, as name + fixed presence-marker entries
        /// sorted by name. Adding/removing a variable drifts; rotating its value
        /// does not. Raw values are never stored (see [`McpEnvEntry`]). Empty vec
        /// = no `env` object declared.
        #[serde(default)]
        env: Vec<McpEnvEntry>,
    },
    /// The server declared neither `url` nor `command`. Captured (not dropped):
    /// a transport-less MCP entry is itself a finding-worthy oddity.
    Unknown,
}

/// Erase any legacy or manually-constructed secret commitment while preserving
/// the structural presence signal used by v8.
fn normalize_secret_presence_markers(transport: &mut McpTransport) {
    match transport {
        McpTransport::Url { userinfo_hash, .. } => {
            if userinfo_hash.is_some() {
                *userinfo_hash = Some(SECRET_PRESENT_MARKER.to_string());
            }
        }
        McpTransport::Stdio { env, .. } => {
            for entry in env {
                entry.value_hash = SECRET_PRESENT_MARKER.to_string();
            }
        }
        McpTransport::Unknown => {}
    }
}

/// Current-format lockfiles must carry only the fixed marker. Legacy versions
/// are normalized before use; accepting an arbitrary marker in v8 would let a
/// hand-written lock reintroduce the offline dictionary oracle the bump removes.
fn has_only_current_secret_presence_markers(transport: &McpTransport) -> bool {
    match transport {
        McpTransport::Url { userinfo_hash, .. } => userinfo_hash
            .as_deref()
            .is_none_or(|marker| marker == SECRET_PRESENT_MARKER),
        McpTransport::Stdio { env, .. } => env
            .iter()
            .all(|entry| entry.value_hash == SECRET_PRESENT_MARKER),
        McpTransport::Unknown => true,
    }
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
    /// alone. `source_config` is excluded from this content digest because it is
    /// already an explicit part of the inventory and drift identity: moving an
    /// otherwise unchanged server between configs is represented as an exact
    /// `(name, source_config)` removal plus addition.
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
    /// re-locking under the current schema catches it).
    pub fn content_hash_v4(&self) -> String {
        let mut hasher = Sha256::new();
        self.feed_content_hash_common(&mut hasher);
        hex_lower(&hasher.finalize())
    }

    /// Stable policy identity for this exact configured server. Unlike the
    /// legacy name-only policy key, this binds the repo-relative source path,
    /// declared name, and transport (including env/userinfo presence).
    /// Tool declarations are intentionally excluded so an allow-list continues
    /// to constrain tool drift without changing its own lookup key.
    pub fn policy_identity(&self) -> String {
        policy_identity(&self.source_config, &self.name, &self.transport)
    }

    /// Feed every per-server hash component into `hasher` EXCEPT the trailing
    /// `tools_declared` byte. Shared by [`Self::content_hash`] (v5, appends the
    /// byte) and [`Self::content_hash_v4`] (v4, omits it) so the two never diverge
    /// on the shared prefix.
    fn feed_content_hash_common(&self, hasher: &mut Sha256) {
        hasher.update(b"mcp-server-v8\0");
        hash_field(hasher, self.name.as_bytes());
        feed_transport_hash(hasher, &self.transport);
        hash_field(hasher, &(self.tools.len() as u64).to_le_bytes());
        for tool in &self.tools {
            hash_field(hasher, tool.as_bytes());
        }
    }
}

/// Feed one canonical transport into a caller-owned hash stream. Shared by the
/// content hash and the source-qualified policy identity so their transport
/// semantics cannot drift apart.
fn feed_transport_hash(hasher: &mut Sha256, transport: &McpTransport) {
    match transport {
        McpTransport::Url { url, userinfo_hash } => {
            hasher.update(b"url\0");
            hash_field(hasher, url.as_bytes());
            // Fold only presence/absence into the hash. The stored string is a
            // fixed marker and is deliberately ignored so even a manually-built
            // struct cannot create a secret-dependent policy/hash identity.
            match userinfo_hash {
                Some(_) => {
                    hasher.update(b"\x01");
                    hash_field(hasher, SECRET_PRESENT_MARKER.as_bytes());
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
                // Feed the name and a constant presence marker. The secret value
                // never participates, preventing an offline dictionary oracle.
                hash_field(hasher, entry.name.as_bytes());
                hash_field(hasher, SECRET_PRESENT_MARKER.as_bytes());
            }
        }
        McpTransport::Unknown => {
            hasher.update(b"unknown\0");
        }
    }
}

/// Build the opaque, versioned policy key for one exact MCP server binding.
/// Length framing prevents attacker-controlled names/paths from forging field
/// boundaries. The readable name/source remain comments in generated policy.
pub fn policy_identity(source_config: &str, name: &str, transport: &McpTransport) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"tirith-mcp-policy-identity-v1\0");
    hash_field(&mut hasher, source_config.as_bytes());
    hash_field(&mut hasher, name.as_bytes());
    feed_transport_hash(&mut hasher, transport);
    format!("mcp:v1:{}", hex_lower(&hasher.finalize()))
}

/// Normalize a scanned config path to the same forward-slash repo-relative form
/// stored in `McpServerEntry::source_config`. Absolute paths require a known
/// repo root; paths containing parent/prefix components fail closed.
pub fn source_config_identity_path(path: &Path, repo_root: Option<&Path>) -> Option<String> {
    let relative = if path.is_absolute() {
        path.strip_prefix(repo_root?).ok()?
    } else {
        path
    };
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(value) => parts.push(value.to_string_lossy().into_owned()),
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => return None,
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

/// Feed one length-prefixed field into a hasher: the byte length as a LE `u64`,
/// then the bytes. Makes the hash input an unambiguous encoding — no list can
/// collide with a different list, and an embedded `\0` can't forge a boundary.
fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

// ---------------------------------------------------------------------------
// v6 — live `tools/list` descriptor capture, lock, and drift (Stack C / C3)
// ---------------------------------------------------------------------------

/// Serialize a [`serde_json::Value`] into a stable, canonical string: object keys
/// sorted lexicographically (recursively), no insignificant whitespace, and
/// numbers in their `serde_json` canonical form. This is the load-bearing
/// primitive behind descriptor hashing — two descriptors that differ ONLY in key
/// order or whitespace must hash identically (not drift), while any value-level
/// change must hash differently.
///
/// Why hand-rolled rather than `serde_json::to_string`: `serde_json` preserves a
/// `Map`'s insertion/parse order, so `{"a":1,"b":2}` and `{"b":2,"a":1}` would
/// serialize to two different strings and falsely register as drift. (The
/// crate's `preserve_order` feature is not enabled here, and even default
/// `BTreeMap` ordering is not guaranteed stable across versions for our hashing
/// contract.) We therefore walk the tree and emit keys in sorted order
/// explicitly.
///
/// Number handling: emitted via `serde_json::Number`'s own `Display`, which is
/// the parsed canonical form (`1`, `1.5`, `-0.0` → `-0.0`). We do NOT attempt to
/// re-normalize numeric spellings (`1e2` vs `100`) — `serde_json` already folds
/// integer/float representations on parse, and re-spelling risks precision loss.
/// A descriptor whose schema spells a literal differently across captures is a
/// real, surfaced change (conservative: prefer a false drift over a missed one).
pub fn canonical_json(value: &serde_json::Value) -> String {
    let mut out = String::new();
    write_canonical_json(value, &mut out);
    out
}

/// Recursive worker for [`canonical_json`]. Appends the canonical encoding of
/// `value` to `out`. Strings are escaped via `serde_json` (so control bytes,
/// quotes, and non-ASCII are encoded exactly as the parser would), keeping the
/// output valid JSON and collision-free at string boundaries.
fn write_canonical_json(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        serde_json::Value::Number(n) => {
            use std::fmt::Write as _;
            // `Number`'s Display is the canonical parsed form; write! into a
            // String never fails.
            let _ = write!(out, "{n}");
        }
        serde_json::Value::String(s) => {
            // Reuse serde_json's string escaper for an exact, valid-JSON encoding.
            // `to_string` on a `Value::String` cannot fail.
            let encoded = serde_json::Value::String(s.clone()).to_string();
            out.push_str(&encoded);
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out);
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            // Sort keys lexicographically by their bytes for a stable order
            // regardless of the map's parse/insertion order.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // Encode the key as a JSON string (escaped) then `:` then value.
                let encoded_key = serde_json::Value::String(key.clone()).to_string();
                out.push_str(&encoded_key);
                out.push(':');
                // The key came from `map.keys()`, so the lookup is always Some.
                if let Some(v) = map.get(key) {
                    write_canonical_json(v, out);
                }
            }
            out.push('}');
        }
    }
}

/// One MCP tool (or prompt) descriptor as advertised by a live `tools/list`
/// response, reduced to its security-relevant surface and a stable hash. The hash
/// is over the [`canonical_json`] of the captured fields, so a server that
/// re-orders schema keys or reformats whitespace does NOT register as drift, but
/// any material change (a swapped description, a widened `inputSchema`, a new
/// destructive annotation, a changed icon URI) does.
///
/// **Hash-only by design.** Only the tool `name` and the descriptor `*_hash` are
/// stored — never the raw description / schema text. A tool description is
/// attacker-controlled and the lockfile is committed, so persisting the full text
/// would both bloat the file and re-introduce attacker bytes into a committed,
/// rendered artifact; the hash is sufficient for exact drift. (The raw text IS
/// scanned for injection/exfil before exposure, at the gateway, every string leaf
/// of a `tools/list` / `prompts/*` response, descriptions included, is run through
/// [`crate::mcp::response_inspect::inspect_response`], but that scan feeds a
/// gateway decision, never the stored lock.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDescriptor {
    /// The tool's name (the `name` field of a `tools/list` entry). The stable
    /// identity used to pair descriptors across two locks for drift.
    pub name: String,
    /// Hash over the [`canonical_json`] of the whole captured descriptor
    /// (`title`, `description`, `inputSchema`, `outputSchema`, `annotations`,
    /// `icons`, `execution`, and `_meta`, each present-or-null), framed with the
    /// tool name. The single value drift compares.
    pub descriptor_hash: String,
}

impl ToolDescriptor {
    /// Build a descriptor from one `tools/list` entry object. Captures the
    /// complete MCP Tool fields (`title`, `description`, `inputSchema`,
    /// `outputSchema`, `annotations`, `icons`, `execution`, `_meta`) into a
    /// single canonical object and hashes it. A missing field and an explicit
    /// JSON `null` both hash as `null`; the validated live approval path rejects
    /// explicit nulls where the protocol requires a concrete type.
    ///
    /// `name` falls back to the empty string when the entry omits `name` (a
    /// malformed entry the caller still wants captured rather than dropped).
    pub fn from_tool_entry(entry: &serde_json::Value) -> Self {
        let name = entry
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        // Assemble exactly the fields we lock, in a fixed key set. `canonical_json`
        // sorts the keys, so the literal insertion order here does not matter.
        let mut captured = serde_json::Map::new();
        for field in DESCRIPTOR_HASHED_FIELDS {
            let v = entry
                .get(*field)
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            captured.insert((*field).to_string(), v);
        }
        let canonical = canonical_json(&serde_json::Value::Object(captured));
        let descriptor_hash = {
            let mut hasher = Sha256::new();
            hasher.update(b"mcp-tool-descriptor-v7\0");
            hash_field(&mut hasher, name.as_bytes());
            hash_field(&mut hasher, canonical.as_bytes());
            hex_lower(&hasher.finalize())
        };

        ToolDescriptor {
            name,
            descriptor_hash,
        }
    }
}

/// The exact field set captured into a [`ToolDescriptor`]'s hash. Fixed and
/// explicit so adding a field is a deliberate, reviewable change (and a hash
/// bump). Mirrors the MCP `Tool` shape, including UI/execution metadata.
pub(crate) const DESCRIPTOR_HASHED_FIELDS: &[&str] = &[
    "title",
    "description",
    "inputSchema",
    "outputSchema",
    "annotations",
    "icons",
    "execution",
    "_meta",
];

/// Validate the complete MCP Tool shape that v7 hashes and authorizes. Unknown
/// top-level fields are refused: silently ignoring a future execution-relevant
/// field would make the stored descriptor less complete than the live tool.
pub fn validate_tool_descriptor_entry(entry: &serde_json::Value) -> Result<&str, &'static str> {
    let object = entry.as_object().ok_or("tools_list_invalid_entry")?;
    if object.keys().any(|field| {
        !matches!(
            field.as_str(),
            "name"
                | "title"
                | "description"
                | "inputSchema"
                | "outputSchema"
                | "annotations"
                | "icons"
                | "execution"
                | "_meta"
        )
    }) {
        return Err("tools_list_unknown_descriptor_field");
    }
    let name = object
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or("tools_list_invalid_name")?;
    for field in ["title", "description"] {
        if object.get(field).is_some_and(|value| !value.is_string()) {
            return Err("tools_list_invalid_text_field");
        }
    }
    let input_schema = object
        .get("inputSchema")
        .filter(|schema| schema.is_object())
        .ok_or("tools_list_invalid_input_schema")?;
    if input_schema.get("type").and_then(serde_json::Value::as_str) != Some("object") {
        return Err("tools_list_invalid_input_schema");
    }
    crate::mcp::content::SchemaValidator::compile(input_schema)
        .map_err(|_| "tools_list_invalid_input_schema")?;
    if let Some(output_schema) = object.get("outputSchema") {
        if !output_schema.is_object()
            || output_schema
                .get("type")
                .and_then(serde_json::Value::as_str)
                != Some("object")
            || crate::mcp::content::SchemaValidator::compile(output_schema).is_err()
        {
            return Err("tools_list_invalid_output_schema");
        }
    }
    if let Some(annotations) = object.get("annotations") {
        let annotations = annotations
            .as_object()
            .ok_or("tools_list_invalid_metadata_field")?;
        if annotations.keys().any(|field| {
            !matches!(
                field.as_str(),
                "title" | "readOnlyHint" | "destructiveHint" | "idempotentHint" | "openWorldHint"
            )
        }) || annotations
            .get("title")
            .is_some_and(|value| !value.is_string())
            || [
                "readOnlyHint",
                "destructiveHint",
                "idempotentHint",
                "openWorldHint",
            ]
            .iter()
            .any(|field| {
                annotations
                    .get(*field)
                    .is_some_and(|value| !value.is_boolean())
            })
        {
            return Err("tools_list_invalid_metadata_field");
        }
    }
    if let Some(execution) = object.get("execution") {
        let execution = execution
            .as_object()
            .ok_or("tools_list_invalid_metadata_field")?;
        if execution.keys().any(|field| field != "taskSupport")
            || execution.get("taskSupport").is_some_and(|value| {
                !matches!(value.as_str(), Some("forbidden" | "optional" | "required"))
            })
        {
            return Err("tools_list_invalid_metadata_field");
        }
    }
    if object.get("_meta").is_some_and(|value| !value.is_object()) {
        return Err("tools_list_invalid_metadata_field");
    }
    if let Some(icons) = object.get("icons") {
        let icons = icons.as_array().ok_or("tools_list_invalid_icons")?;
        for icon in icons {
            let icon = icon.as_object().ok_or("tools_list_invalid_icons")?;
            if icon
                .keys()
                .any(|field| !matches!(field.as_str(), "src" | "mimeType" | "sizes" | "theme"))
                || icon
                    .get("src")
                    .and_then(serde_json::Value::as_str)
                    .filter(|src| !src.is_empty())
                    .is_none()
                || icon.get("mimeType").is_some_and(|value| !value.is_string())
                || icon
                    .get("theme")
                    .is_some_and(|value| !matches!(value.as_str(), Some("light" | "dark")))
                || icon.get("sizes").is_some_and(|value| {
                    value
                        .as_array()
                        .is_none_or(|sizes| !sizes.iter().all(serde_json::Value::is_string))
                })
            {
                return Err("tools_list_invalid_icons");
            }
        }
    }
    Ok(name)
}

/// Hash an ordered descriptor list into one per-server `descriptor_hash`.
/// Length-prefixed framing (via [`hash_field`]) so no two distinct lists collide.
/// Empty list → empty string (the "no descriptors captured" sentinel, distinct
/// from any real hash).
pub fn compute_descriptor_hash(descriptors: &[ToolDescriptor]) -> String {
    if descriptors.is_empty() {
        return String::new();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"mcp-descriptor-set-v7\0");
    hash_field(&mut hasher, &(descriptors.len() as u64).to_le_bytes());
    for d in descriptors {
        hash_field(&mut hasher, d.name.as_bytes());
        hash_field(&mut hasher, d.descriptor_hash.as_bytes());
    }
    hex_lower(&hasher.finalize())
}

/// Normalize a freshly-captured `tools/list` descriptor vector for storage:
/// de-duplicate by tool name (last write wins, matching a server that re-declares
/// a tool) and sort by name, so the stored order and the `descriptor_hash` are
/// stable regardless of the order the server listed its tools.
pub fn normalize_descriptors(mut descriptors: Vec<ToolDescriptor>) -> Vec<ToolDescriptor> {
    // De-dup by name keeping the LAST occurrence (a later entry overrides an
    // earlier same-name one). Build a name→descriptor map, then collect sorted.
    let mut by_name: std::collections::BTreeMap<String, ToolDescriptor> =
        std::collections::BTreeMap::new();
    for d in descriptors.drain(..) {
        by_name.insert(d.name.clone(), d);
    }
    by_name.into_values().collect()
}

/// Extract and normalize the descriptor list from a parsed `tools/list` RESULT
/// object (`result.tools` array). A non-array / missing `tools` yields an empty
/// vec (no panic — the "malformed → empty" convention). Each entry is reduced to
/// a [`ToolDescriptor`]; entries that are not objects are skipped.
///
/// `result` is the JSON-RPC `result` value (the object that holds `tools`), NOT
/// the whole response envelope — the caller unwraps `response["result"]` first.
pub fn descriptors_from_tools_list(result: &serde_json::Value) -> Vec<ToolDescriptor> {
    let Some(tools) = result.get("tools").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let captured: Vec<ToolDescriptor> = tools
        .iter()
        .filter(|e| e.is_object())
        .map(ToolDescriptor::from_tool_entry)
        .collect();
    normalize_descriptors(captured)
}

/// How a server's live `tools/list` descriptor surface differs between two locks
/// (the previously approved one and the freshly captured one). Each variant
/// carries only the tool NAME — descriptions can contain attacker-controlled text
/// and drift reports are rendered, so the raw description is never echoed (it is
/// represented by its hash inside the lock).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpDescriptorChange {
    /// A tool advertised in the new capture that the locked set did not have.
    ToolAdded { name: String },
    /// A tool in the locked set the new capture no longer advertises.
    ToolRemoved { name: String },
    /// A tool present on both sides whose descriptor hash changed — its
    /// description / inputSchema / outputSchema / annotations / icons were
    /// materially altered after approval.
    ToolChanged { name: String },
}

impl McpDescriptorChange {
    /// Deterministic sort key: kind-bucket (Removed=0, Added=1, Changed=2) then
    /// name. Removed first as the most security-relevant (a tool that vanished may
    /// be a server hiding capability).
    fn sort_key(&self) -> (u8, &str) {
        match self {
            McpDescriptorChange::ToolRemoved { name } => (0, name),
            McpDescriptorChange::ToolAdded { name } => (1, name),
            McpDescriptorChange::ToolChanged { name } => (2, name),
        }
    }

    /// The tool name this change refers to.
    pub fn name(&self) -> &str {
        match self {
            McpDescriptorChange::ToolAdded { name }
            | McpDescriptorChange::ToolRemoved { name }
            | McpDescriptorChange::ToolChanged { name } => name,
        }
    }

    /// Whether this change introduces a NEW or CHANGED tool that must be suspended
    /// pending re-approval (an added or changed tool exposes a surface the
    /// operator never approved). A removed tool is reported but does not gate a
    /// re-approval (there is nothing new to approve).
    pub fn requires_reapproval(&self) -> bool {
        matches!(
            self,
            McpDescriptorChange::ToolAdded { .. } | McpDescriptorChange::ToolChanged { .. }
        )
    }
}

/// Compute the descriptor drift between a previously locked descriptor set and a
/// freshly captured one. Both are normalized (sorted by name) on the way in
/// (defensively re-normalized here so a hand-built input still works). A merge
/// walk emits Added / Removed / Changed; the result is sorted via
/// [`McpDescriptorChange::sort_key`].
///
/// This is the v6 analogue of [`compute_drift`] for the LIVE descriptor surface
/// rather than the static config inventory. The caller (gateway / C4) turns a
/// non-empty result into a High [`crate::verdict::RuleId::McpServerDrift`] finding
/// via [`descriptor_drift_finding`] and suspends the added/changed tools.
pub fn compute_descriptor_drift(
    locked: &[ToolDescriptor],
    current: &[ToolDescriptor],
) -> Vec<McpDescriptorChange> {
    let locked = normalize_descriptors(locked.to_vec());
    let current = normalize_descriptors(current.to_vec());

    let mut changes: Vec<McpDescriptorChange> = Vec::new();
    let mut i = 0usize; // current
    let mut j = 0usize; // locked

    while i < current.len() && j < locked.len() {
        let cur = &current[i];
        let prev = &locked[j];
        match cur.name.cmp(&prev.name) {
            std::cmp::Ordering::Less => {
                changes.push(McpDescriptorChange::ToolAdded {
                    name: cur.name.clone(),
                });
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                changes.push(McpDescriptorChange::ToolRemoved {
                    name: prev.name.clone(),
                });
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                if cur.descriptor_hash != prev.descriptor_hash {
                    changes.push(McpDescriptorChange::ToolChanged {
                        name: cur.name.clone(),
                    });
                }
                i += 1;
                j += 1;
            }
        }
    }
    while i < current.len() {
        changes.push(McpDescriptorChange::ToolAdded {
            name: current[i].name.clone(),
        });
        i += 1;
    }
    while j < locked.len() {
        changes.push(McpDescriptorChange::ToolRemoved {
            name: locked[j].name.clone(),
        });
        j += 1;
    }

    changes.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    changes
}

/// The set of tool names that must be SUSPENDED pending re-approval after a
/// descriptor drift: every added or changed tool (a removed tool needs no
/// approval). Sorted, de-duplicated. The gateway holds these out of `tools/list`
/// responses until the operator re-approves.
pub fn tools_pending_reapproval(changes: &[McpDescriptorChange]) -> Vec<String> {
    let mut names: Vec<String> = changes
        .iter()
        .filter(|c| c.requires_reapproval())
        .map(|c| c.name().to_string())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Build the single High [`crate::verdict::RuleId::McpServerDrift`] finding for a
/// non-empty descriptor drift. Mirrors the config-drift finding shape in
/// `rules::mcpdrift` (aggregate counts + a few tool names for orientation) but
/// describes the LIVE `tools/list` surface and is always High: a server changing
/// the description/schema of a tool the operator already approved is a classic
/// post-approval rug-pull. Returns `None` for an empty change set.
///
/// **Terminal safety:** tool names are debug-escaped (`{:?}`) so a control byte in
/// a name cannot inject into a terminal — same convention as `mcp.rs::escape_name`
/// and the config-drift finding.
pub fn descriptor_drift_finding(
    server_name: &str,
    changes: &[McpDescriptorChange],
) -> Option<crate::verdict::Finding> {
    use crate::verdict::{Evidence, Finding, Severity};

    if changes.is_empty() {
        return None;
    }

    let mut added = 0usize;
    let mut removed = 0usize;
    let mut changed = 0usize;
    let mut names: Vec<String> = Vec::new();
    for c in changes {
        match c {
            McpDescriptorChange::ToolAdded { .. } => added += 1,
            McpDescriptorChange::ToolRemoved { .. } => removed += 1,
            McpDescriptorChange::ToolChanged { .. } => changed += 1,
        }
        if names.len() < 5 {
            names.push(format!("{:?}", c.name()));
        }
    }

    let summary =
        format!("{added} added, {removed} removed, {changed} changed since the descriptor lock");
    let mut detail =
        format!("MCP live tool-descriptor drift for server {server_name:?}: {summary}.");
    if !names.is_empty() {
        let suffix = if changes.len() > names.len() {
            format!(" first tools: {} …", names.join(", "))
        } else {
            format!(" tools: {}", names.join(", "))
        };
        detail.push_str(&suffix);
    }

    Some(Finding {
        rule_id: crate::verdict::RuleId::McpServerDrift,
        severity: Severity::High,
        title: "MCP server's live tool descriptors drifted from the approved lock".to_string(),
        description: format!(
            "The MCP server {server_name:?} now advertises `tools/list` descriptors that no \
             longer match the approved descriptor lock ({summary}). A tool whose description, \
             input/output schema, annotations, or icons changed after approval is a \
             post-approval surface change (a classic capability rug-pull): a tool the agent \
             was told is safe can be silently re-pointed at a destructive or exfiltrating \
             behavior. New and changed tools are suspended pending re-approval. Review the \
             change, then re-approve the server to capture the new descriptor lock."
        ),
        evidence: vec![Evidence::Text { detail }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    })
}

/// The descriptor-lock baseline a live MCP gateway compares its upstream's
/// `tools/list` against. Loaded once at gateway init from the committed
/// `<repo>/.tirith/mcp.lock`; `None` when there is no lockfile or it carries no
/// captured descriptors (see [`load_gateway_descriptor_baseline`]).
#[derive(Debug, Clone)]
pub struct GatewayDescriptorBaseline {
    /// A short label for the [`descriptor_drift_finding`] (the exact selected
    /// lock entry's human-readable server name).
    pub server_label: String,
    /// Exact source/name/transport identity this live upstream is bound to.
    pub server_identity: String,
    /// Locked transport used to prove the gateway's live upstream invocation is
    /// the same configured server before enforcing this descriptor set.
    pub transport: McpTransport,
    /// Versioned digest of the exact executable, argv, cwd, environment, and
    /// containment posture used for the operator-approved capture.
    pub launch_fingerprint: String,
    /// Only the selected server's captured `tools/list` descriptors, normalized
    /// so they pair cleanly against a freshly captured list.
    pub descriptors: Vec<ToolDescriptor>,
}

/// Descriptor-baseline failures that are distinct from a corrupt lockfile.
#[derive(Debug)]
pub enum GatewayDescriptorBaselineError {
    Lock(McpLockLoadError),
    /// Secure descriptor protection was requested but the exact upstream has no
    /// explicit operator-approved descriptor set yet.
    ApprovalRequired,
    /// More than one approved server exists and the gateway did not select one.
    IdentityRequired,
    /// The supplied identity is not present in the current lockfile.
    UnknownIdentity,
    /// A lock with incomplete config coverage cannot authorize a live upstream.
    IncompleteCoverage,
    /// The current repo-local MCP inventory no longer matches the committed lock.
    StaticInventoryDrift,
    /// The selected transport carries launch state the gateway cannot reproduce
    /// exactly (currently a non-empty configured stdio environment or non-stdio
    /// transport).
    UnsupportedLaunchBinding,
}

impl std::fmt::Display for GatewayDescriptorBaselineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lock(error) => write!(f, "{error}"),
            Self::ApprovalRequired => write!(f, "live MCP descriptors require operator approval"),
            Self::IdentityRequired => write!(
                f,
                "multiple approved MCP servers exist; select one exact policy identity"
            ),
            Self::UnknownIdentity => write!(f, "selected MCP server identity is not locked"),
            Self::IncompleteCoverage => {
                write!(f, "MCP lock records incomplete configuration coverage")
            }
            Self::StaticInventoryDrift => {
                write!(f, "MCP static inventory drifted from the committed lock")
            }
            Self::UnsupportedLaunchBinding => {
                write!(
                    f,
                    "selected MCP transport cannot be launched with an exact binding"
                )
            }
        }
    }
}

impl std::error::Error for GatewayDescriptorBaselineError {}

impl From<McpLockLoadError> for GatewayDescriptorBaselineError {
    fn from(value: McpLockLoadError) -> Self {
        Self::Lock(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorApprovalError {
    IncompleteCoverage,
    StaticInventoryDrift,
    UnknownIdentity,
    UnsupportedTransport,
    UpstreamMismatch,
    InvalidLaunchFingerprint,
    InvalidToolsList,
}

impl std::fmt::Display for DescriptorApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::IncompleteCoverage => "MCP configuration coverage is incomplete",
            Self::StaticInventoryDrift => "MCP static inventory drifted from the lock",
            Self::UnknownIdentity => "selected MCP server identity is not locked",
            Self::UnsupportedTransport => "descriptor approval requires a stdio server",
            Self::UpstreamMismatch => "live upstream command does not match the selected server",
            Self::InvalidLaunchFingerprint => {
                "live upstream launch fingerprint is missing or invalid"
            }
            Self::InvalidToolsList => "live tools/list result is malformed or ambiguous",
        };
        f.write_str(message)
    }
}

impl std::error::Error for DescriptorApprovalError {}

/// Bind a sanitized live `tools/list` result to one exact configured stdio
/// server and update the in-memory lock. The caller is responsible for an
/// atomic contained write after rechecking that its on-disk inputs did not
/// change. Raw descriptions/schemas never enter the lock: only name + canonical
/// descriptor hash are retained.
pub fn approve_live_descriptors(
    lock: &mut McpLockfile,
    current: &McpInventory,
    server_identity: &str,
    upstream_bin: &str,
    upstream_args: &[String],
    launch_fingerprint: &str,
    tools_list_result: &serde_json::Value,
) -> Result<usize, DescriptorApprovalError> {
    if launch_fingerprint.is_empty()
        || launch_fingerprint.len() != 64
        || !launch_fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(DescriptorApprovalError::InvalidLaunchFingerprint);
    }
    if !current.malformed_configs.is_empty()
        || !current.rejected_configs.is_empty()
        || !lock.malformed_configs.is_empty()
        || !lock.rejected_configs.is_empty()
    {
        return Err(DescriptorApprovalError::IncompleteCoverage);
    }
    if !compute_drift(current, lock).is_empty()
        || current.malformed_configs != lock.malformed_configs
        || current.rejected_configs != lock.rejected_configs
    {
        return Err(DescriptorApprovalError::StaticInventoryDrift);
    }

    let current_server = current
        .servers
        .iter()
        .find(|server| server.policy_identity() == server_identity)
        .ok_or(DescriptorApprovalError::UnknownIdentity)?;
    let locked_server = lock
        .servers
        .iter_mut()
        .find(|server| server.policy_identity() == server_identity)
        .ok_or(DescriptorApprovalError::UnknownIdentity)?;

    match &current_server.transport {
        McpTransport::Stdio { env, .. } if !env.is_empty() => {
            return Err(DescriptorApprovalError::UnsupportedTransport);
        }
        McpTransport::Stdio { command, args, .. }
            if command == upstream_bin && args == upstream_args => {}
        McpTransport::Stdio { .. } => return Err(DescriptorApprovalError::UpstreamMismatch),
        _ => return Err(DescriptorApprovalError::UnsupportedTransport),
    }

    let tools = tools_list_result
        .get("tools")
        .and_then(serde_json::Value::as_array)
        .ok_or(DescriptorApprovalError::InvalidToolsList)?;
    let mut names = std::collections::BTreeSet::new();
    for tool in tools {
        let name = validate_tool_descriptor_entry(tool)
            .map_err(|_| DescriptorApprovalError::InvalidToolsList)?;
        if !names.insert(name) {
            return Err(DescriptorApprovalError::InvalidToolsList);
        }
    }

    let descriptors = descriptors_from_tools_list(tools_list_result);
    let count = descriptors.len();
    locked_server.descriptor_hash = compute_descriptor_hash(&descriptors);
    locked_server.descriptors = descriptors;
    locked_server.descriptors_approved = true;
    locked_server.launch_fingerprint = launch_fingerprint.to_ascii_lowercase();
    Ok(count)
}

/// Load the descriptor-lock baseline for a live gateway from
/// `<repo_root>/.tirith/mcp.lock`.
///
/// A gateway fronts exactly one upstream MCP server. The selected policy
/// identity binds its source/name/transport, and this loader returns only that
/// principal's approved descriptor baseline. When no identity is supplied, a
/// single approved entry may be selected; multiple entries are an ambiguity
/// error rather than a cross-server union.
///
/// Returns `Ok(None)` (skip drift detection, run normally) when:
/// * `repo_root` is `None` (not inside a repo), or
/// * the lockfile is ABSENT ([`McpLockLoadError::NotFound`]), or
/// * the lockfile loaded cleanly but no locked server captured any descriptors (a
///   config-only `tirith mcp lock`, or a pre-v6 lockfile), there is no
///   live-descriptor baseline to compare to.
///
/// Returns `Err(McpLockLoadError)` (IM2) when a lockfile is PRESENT but cannot be
/// loaded, an Io error, a parse failure (a one-byte corruption / mode-flip of a
/// committed lock), or an unsupported version. The caller decides what a
/// present-but-unloadable lock means: under `fail_mode: closed` it must fail
/// closed (a committed rug-pull defense that silently turned off is exactly the
/// gap IM2 closes), and under `fail_mode: open` it degrades loudly. Collapsing
/// every error to "no baseline" (the old `.ok()?`) silently disabled drift on any
/// tamper.
///
/// The on-disk hashes are recomputed from the data on load
/// ([`parse_lockfile`]), so a hand-edited `descriptor_hash` cannot silence drift.
pub fn load_gateway_descriptor_baseline(
    repo_root: Option<&Path>,
) -> Result<Option<GatewayDescriptorBaseline>, GatewayDescriptorBaselineError> {
    load_gateway_descriptor_baseline_for(repo_root, None, false)
}

/// Load an exact server-bound descriptor baseline. `server_identity` is the
/// versioned key printed by `tirith mcp policy init`. When `require_approved` is
/// true (secure gateway profile), absence is an approval-required error rather
/// than silently disabling the rug-pull defense.
pub fn load_gateway_descriptor_baseline_for(
    repo_root: Option<&Path>,
    server_identity: Option<&str>,
    require_approved: bool,
) -> Result<Option<GatewayDescriptorBaseline>, GatewayDescriptorBaselineError> {
    let Some(repo_root) = repo_root else {
        return if require_approved {
            Err(GatewayDescriptorBaselineError::ApprovalRequired)
        } else {
            Ok(None)
        };
    };
    let path = repo_root.join(".tirith").join(MCP_LOCK_FILENAME);
    let lock = match load_lockfile(&path) {
        Ok(lock) => lock,
        // No committed lock: nothing to enforce, run normally.
        Err(McpLockLoadError::NotFound) => {
            return if require_approved {
                Err(GatewayDescriptorBaselineError::ApprovalRequired)
            } else {
                Ok(None)
            };
        }
        // A PRESENT lock that won't load is a fail-closed signal, not a silent
        // "no baseline", surface it so the gateway can refuse/suspend under
        // closed mode (IM2).
        Err(e) => return Err(e.into()),
    };

    if !lock.malformed_configs.is_empty() || !lock.rejected_configs.is_empty() {
        return Err(GatewayDescriptorBaselineError::IncompleteCoverage);
    }

    let approved: Vec<&McpLockServer> = lock
        .servers
        .iter()
        .filter(|server| server.descriptors_approved)
        .collect();
    let selected = match server_identity {
        Some(identity) => {
            let server = lock
                .servers
                .iter()
                .find(|server| server.policy_identity() == identity)
                .ok_or(GatewayDescriptorBaselineError::UnknownIdentity)?;
            if !server.descriptors_approved {
                return Err(GatewayDescriptorBaselineError::ApprovalRequired);
            }
            server
        }
        None => match approved.as_slice() {
            [] if require_approved => return Err(GatewayDescriptorBaselineError::ApprovalRequired),
            [] => return Ok(None),
            [server] => *server,
            _ => return Err(GatewayDescriptorBaselineError::IdentityRequired),
        },
    };

    // A legacy descriptor record, an empty v7 launch fingerprint, or a current
    // config that no longer matches the committed static inventory cannot
    // authorize execution. Descriptor approval is an execution grant, so these
    // are checked at the load boundary rather than left to a best-effort caller.
    if lock.schema_state != LockfileSchema::Current || selected.launch_fingerprint.is_empty() {
        return Err(GatewayDescriptorBaselineError::ApprovalRequired);
    }
    let current = build_inventory(repo_root);
    if !current.malformed_configs.is_empty() || !current.rejected_configs.is_empty() {
        return Err(GatewayDescriptorBaselineError::IncompleteCoverage);
    }
    if !compute_drift(&current, &lock).is_empty() {
        return Err(GatewayDescriptorBaselineError::StaticInventoryDrift);
    }
    match &selected.transport {
        McpTransport::Stdio { env, .. } if env.is_empty() => {}
        _ => return Err(GatewayDescriptorBaselineError::UnsupportedLaunchBinding),
    }

    let descriptors = normalize_descriptors(selected.descriptors.clone());

    Ok(Some(GatewayDescriptorBaseline {
        server_label: selected.name.clone(),
        server_identity: selected.policy_identity(),
        transport: selected.transport.clone(),
        launch_fingerprint: selected.launch_fingerprint.clone(),
        descriptors,
    }))
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
        /// A proven lower bound on the file size. The retained reader reports
        /// `MCP_CONFIG_MAX_SIZE + 1` when the exact size cannot be recovered
        /// without reopening an attacker-racy pathname.
        size_bytes: u64,
    },
    /// A regular file under the cap that could not be read.
    Unreadable {
        /// `true` for `PermissionDenied` (the operator-actionable case); other
        /// io errors fold into `false` (the inner string is not surfaced).
        permission_denied: bool,
    },
    /// Both supported top-level server maps were present. Different MCP clients
    /// choose different keys, so accepting either would let the other act as a
    /// hidden execution surface.
    AmbiguousServerObjects,
    /// A server declared both a URL and a subprocess command. Tirith cannot
    /// safely guess which transport the consuming client will execute.
    AmbiguousTransport,
    /// A stdio argument contained a high-confidence credential form (for
    /// example `--api-key VALUE`, `--token=VALUE`, or a known token prefix).
    /// No argument bytes are retained in this reason.
    SecretBearingArgument,
    /// A URL query/fragment carried a credential-shaped component that cannot
    /// be committed safely without changing the server endpoint semantics.
    /// No URL bytes are retained in this reason.
    SecretBearingUrl,
    /// At least one declared server value was not an object. Skipping it would
    /// make the lock inventory differ from clients with more permissive parsers.
    InvalidServerEntry,
    /// The JSON document contained two members with the same key in one object.
    /// Different consumers choose first-wins or last-wins semantics, so no exact
    /// launch inventory can be derived from it.
    DuplicateJsonKey,
    /// A recognized server field had the wrong JSON type or an invalid value.
    InvalidServerField,
    /// The server object contained a field Tirith does not model. Refusing the
    /// whole config is safer than locking a partial launch description.
    UnsupportedServerField,
}

/// Classify a public, directly-constructed transport before any hash or
/// lock-server record is derived from it. Parser-produced transports already
/// satisfy this invariant; keeping the check here prevents library callers from
/// bypassing the parser and turning the lockfile into a credential sink.
fn transport_commit_rejection(transport: &McpTransport) -> Option<RejectedReason> {
    match transport {
        McpTransport::Url { url, .. } if !transport_url_is_commit_safe(url) => {
            Some(RejectedReason::SecretBearingUrl)
        }
        McpTransport::Stdio { args, .. } if args_have_secret_bearing_value(args) => {
            Some(RejectedReason::SecretBearingArgument)
        }
        _ => None,
    }
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
    /// Physically-present config paths Tirith refused, either at the filesystem
    /// boundary (symlinked, non-regular, escaped, oversized, unreadable) or at the
    /// semantic boundary (ambiguous/secret-bearing declarations). Distinct from
    /// `malformed_configs`, which could not be interpreted as MCP JSON at all.
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
    /// The live `tools/list` descriptors this server advertises, captured at
    /// runtime (introduced in v6 and expanded in v7). Sorted by tool name,
    /// de-duplicated by name (last write
    /// wins). Empty for a config-only `tirith mcp lock` (the static config files
    /// do not carry descriptors) and for a v5 lockfile loaded by a later schema.
    /// Excluded from [`Self::hash`] so static config drift is unchanged from v5;
    /// folded instead into [`Self::descriptor_hash`]. Serde-defaults to empty, so
    /// a v5 lockfile (no field) deserializes cleanly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub descriptors: Vec<ToolDescriptor>,
    /// Whether an operator explicitly approved the live descriptor set. This is
    /// separate from `descriptors.is_empty()`: a legitimate server may advertise
    /// zero tools, and that empty set must still be enforceable as a baseline.
    #[serde(default, skip_serializing_if = "is_false")]
    pub descriptors_approved: bool,
    /// Hash over the ordered descriptor list (see [`compute_descriptor_hash`]).
    /// Empty when [`Self::descriptors`] is empty. Lets a caller compare the
    /// live-descriptor surface of two locks cheaply, independent of the static
    /// `hash`. Serde-defaults to empty; recomputed at parse so a hand-edited value
    /// cannot silence descriptor drift.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub descriptor_hash: String,
    /// Hash of the exact executable bytes/path, argv, effective cwd, environment,
    /// and containment mode used when live descriptors were approved. Empty for
    /// config-only and pre-v7 locks; an empty value can never authorize a gateway.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub launch_fingerprint: String,
}

impl McpLockServer {
    /// Source-qualified, transport-bound policy key for this locked server.
    pub fn policy_identity(&self) -> String {
        policy_identity(&self.source_config, &self.name, &self.transport)
    }
}

fn is_false(value: &bool) -> bool {
    !*value
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
    /// `format_version: 5`: same on-disk STATIC shape as v6 (the v6
    /// [`McpLockServer::descriptors`] field serde-defaults to empty, and
    /// `content_hash` excludes it), so per-server static drift runs identically.
    /// What v5 lacks is the live `tools/list` descriptor capture; [`compute_drift`]
    /// adds a single [`McpDrift::SchemaUpgradeRequired`] (re-lock once to record
    /// descriptors) on top of any real static drift.
    LegacyV5Migration,
    /// `format_version: 6`: static inventory semantics match v7, but descriptor
    /// hashes omit v7 Tool fields and no exact launch fingerprint was recorded.
    LegacyV6Migration,
    /// `format_version: 7`: descriptor and launch semantics are complete, but
    /// env values and URL userinfo were committed as deterministic SHA-256
    /// verifiers. Parsing erases those verifiers and recomputes v8 hashes from
    /// presence only; [`compute_drift`] requires a one-time re-lock.
    LegacyV7Migration,
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
    /// Configs that were present but could not be interpreted as MCP JSON when
    /// the baseline was created. Persisted so verification can compare coverage
    /// rather than silently trusting only the accepted subset.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub malformed_configs: Vec<String>,
    /// Structured filesystem/semantic refusals captured with the baseline.
    /// Verification always fails while a current rejection exists, even if an
    /// operator explicitly recorded it with the audited override.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected_configs: Vec<RejectedConfig>,
    /// Every locked MCP server, sorted by `(name, source_config)`.
    pub servers: Vec<McpLockServer>,
    /// In-memory schema-state tag for accepted v4-v7 migration inputs, otherwise
    /// `Current`. Never serialized; [`parse_lockfile`] restores it from the
    /// on-disk `format_version` on every supported load path.
    #[serde(skip)]
    pub schema_state: LockfileSchema,
}

/// Content-free failure from lockfile serialization. The inner serde error is
/// deliberately discarded: callers need to know that publication was refused,
/// never which attacker-controlled value triggered the privacy boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpLockRenderError;

impl std::fmt::Display for McpLockRenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MCP lockfile contains data that is unsafe to persist")
    }
}

impl std::error::Error for McpLockRenderError {}

impl McpLockfile {
    /// Build a lockfile from an inventory. Pure and deterministic regardless of
    /// the inventory's server order: the sort by `(name, source_config)` here —
    /// the load-bearing one, since this is a public entry point — happens BEFORE
    /// the inventory hash, so both the lockfile and `inventory_hash` are stable.
    pub fn from_inventory(inventory: &McpInventory) -> Self {
        let mut direct_construction_rejections = Vec::new();
        let mut servers: Vec<McpLockServer> = inventory
            .servers
            .iter()
            .filter_map(|entry| {
                if let Some(reason) = transport_commit_rejection(&entry.transport) {
                    direct_construction_rejections.push(RejectedConfig {
                        path: entry.source_config.clone(),
                        reason,
                    });
                    return None;
                }
                let mut transport = entry.transport.clone();
                normalize_secret_presence_markers(&mut transport);
                Some(McpLockServer {
                    name: entry.name.clone(),
                    transport,
                    tools: entry.tools.clone(),
                    tools_declared: entry.tools_declared,
                    source_config: entry.source_config.clone(),
                    hash: entry.content_hash(),
                    // Descriptors are captured at runtime from a live `tools/list`,
                    // not from the static config an inventory reads — empty here.
                    descriptors: Vec::new(),
                    descriptors_approved: false,
                    descriptor_hash: String::new(),
                    launch_fingerprint: String::new(),
                })
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

        let mut malformed_configs = inventory.malformed_configs.clone();
        malformed_configs.sort();
        malformed_configs.dedup();

        let mut rejected_configs = inventory.rejected_configs.clone();
        rejected_configs.extend(direct_construction_rejections);
        rejected_configs.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.reason.cmp(&b.reason)));
        rejected_configs.dedup();

        McpLockfile {
            format_version: MCP_LOCK_FORMAT_VERSION,
            inventory_hash,
            configs,
            malformed_configs,
            rejected_configs,
            servers,
            schema_state: LockfileSchema::Current,
        }
    }

    /// Carry forward an operator-approved live descriptor baseline when a
    /// normal static `mcp lock` refresh proves that the exact server record is
    /// unchanged. Approval is deliberately invalidated when the source,
    /// transport, declared tools, or any other content-hashed field changes.
    ///
    /// Legacy locks are never a source of approval: v4/v5 did not encode the
    /// explicit approval bit, v6 did not bind approval to the complete v7
    /// descriptor and launch surface, and v7 carries the retired secret
    /// commitment schema. All need fresh live approval.
    pub fn preserve_approved_descriptors_from(&mut self, previous: &Self) -> usize {
        if previous.schema_state != LockfileSchema::Current {
            return 0;
        }

        let mut preserved = 0;
        for server in &mut self.servers {
            let identity = server.policy_identity();
            let Some(old) = previous.servers.iter().find(|candidate| {
                candidate.policy_identity() == identity
                    && candidate.hash == server.hash
                    && candidate.descriptors_approved
            }) else {
                continue;
            };

            server.descriptors = old.descriptors.clone();
            server.descriptor_hash = compute_descriptor_hash(&server.descriptors);
            server.descriptors_approved = true;
            server.launch_fingerprint = old.launch_fingerprint.clone();
            preserved += 1;
        }
        preserved
    }

    /// Render the on-disk form as pretty JSON with a trailing newline.
    /// Directly-constructed secret-bearing transports are rejected by their
    /// field serializers, so persistence callers can report a real failure
    /// without ever receiving the sensitive bytes.
    pub fn render(&self) -> Result<String, McpLockRenderError> {
        let mut rendered = serde_json::to_string_pretty(self).map_err(|_| McpLockRenderError)?;
        rendered.push('\n');
        Ok(rendered)
    }
}

/// Hash the ordered source-qualified server identities and content hashes into
/// one inventory hash.
fn compute_inventory_hash(servers: &[McpLockServer]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"mcp-inventory-v2\0");
    hash_field(&mut hasher, &(servers.len() as u64).to_le_bytes());
    for server in servers {
        // Source is part of the policy principal even though it remains outside
        // the transport/content hash. The fast equality gate must not collapse
        // a move between client config files into "no drift".
        hash_field(&mut hasher, server.name.as_bytes());
        hash_field(&mut hasher, server.source_config.as_bytes());
        hash_field(&mut hasher, server.hash.as_bytes());
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

/// One discovered MCP config bound to the exact retained repository/parent
/// capabilities through which its bytes will be read. The public discovery API
/// intentionally returns only the path projection; inventory construction keeps
/// this authority alive through the capped, no-follow open and complete read.
pub(crate) struct RetainedMcpConfig {
    absolute_path: PathBuf,
    relative_path: String,
    file: crate::util::ContainedAtomicFile,
}

/// Discover the repo-local MCP config files under `repo_root`, returning
/// `(absolute, repo_relative)` pairs sorted by the relative path. Only regular
/// files reachable without crossing a symlink and resolving inside `repo_root`
/// are returned — a probed path that is itself a symlink (or under a symlinked
/// parent), or whose canonical form escapes the root, is rejected, so a
/// `.mcp.json -> ~/.claude/mcp.json` can't pull a user config in. Inventory
/// construction additionally retains a descriptor/handle-relative parent
/// authority through the capped no-follow read. Drops the rejection list — use
/// [`discover_mcp_configs_full`] for it.
pub fn discover_mcp_configs(repo_root: &Path) -> Vec<(PathBuf, String)> {
    discover_mcp_configs_full(repo_root)
        .0
        .into_iter()
        .map(|config| (config.absolute_path, config.relative_path))
        .collect()
}

/// Like [`discover_mcp_configs`] but also returns the structured rejection list
/// (used by [`build_inventory`] to populate [`McpInventory::rejected_configs`]).
/// Path-level rejections only — content rejections (oversize, permission) happen
/// in [`build_inventory`] when the file is read.
pub(crate) fn discover_mcp_configs_full(
    repo_root: &Path,
) -> (Vec<RetainedMcpConfig>, Vec<RejectedConfig>) {
    // Canonicalize the root once for the containment check; if it doesn't exist,
    // no config under it can be discovered — return empty (nothing to reject).
    let canonical_root = match repo_root.canonicalize() {
        Ok(r) => r,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    let mut found: Vec<RetainedMcpConfig> = Vec::new();
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

        // Bind the root, every directory component, and final name now; the
        // retained capability is carried into `build_inventory` and performs
        // the eventual open relative to this exact parent. A path swap after
        // discovery therefore cannot redirect the read through a new parent,
        // and a final-component symlink is refused both here and at read time.
        let retained_path = canonical_root.join(rel);
        let file =
            match crate::util::ContainedAtomicFile::prepare(&canonical_root, &retained_path, false)
            {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    let reason = if path_crosses_symlink(repo_root, rel) {
                        RejectedReason::Symlink
                    } else {
                        RejectedReason::Unreadable {
                            permission_denied: error.kind() == std::io::ErrorKind::PermissionDenied,
                        }
                    };
                    rejected.push(RejectedConfig {
                        path: (*rel).to_string(),
                        reason,
                    });
                    continue;
                }
            };

        found.push(RetainedMcpConfig {
            absolute_path: abs,
            relative_path: (*rel).to_string(),
            file,
        });
    }
    found.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
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
/// "present but skipped" list regardless of which gate tripped. The complete
/// file is opened no-follow and read through the retained parent capability with
/// a hard [`MCP_CONFIG_MAX_SIZE`] cap; growth after discovery is rejected after
/// at most one byte beyond the cap. IO errors are categorized:
/// `PermissionDenied`→`Unreadable{true}`; `NotFound`→silent (vanished mid-edit);
/// non-UTF-8→malformed; else `Unreadable{false}`.
pub fn build_inventory(repo_root: &Path) -> McpInventory {
    let (configs, rejected_from_discovery) = discover_mcp_configs_full(repo_root);

    build_inventory_from_discovered(configs, rejected_from_discovery)
}

fn build_inventory_from_discovered(
    configs: Vec<RetainedMcpConfig>,
    rejected_from_discovery: Vec<RejectedConfig>,
) -> McpInventory {
    let mut inventory = McpInventory {
        rejected_configs: rejected_from_discovery,
        ..McpInventory::default()
    };

    for config in configs {
        let rel_path = config.relative_path;
        let bytes = match config.file.read_capped(MCP_CONFIG_MAX_SIZE) {
            Ok(bytes) => bytes,
            Err(crate::util::OpenRegularError::NotFound) => continue,
            Err(crate::util::OpenRegularError::NotRegularFile) => {
                inventory.rejected_configs.push(RejectedConfig {
                    path: rel_path.clone(),
                    reason: RejectedReason::NotRegularFile,
                });
                continue;
            }
            Err(crate::util::OpenRegularError::TooLarge) => {
                // The retained reader intentionally exposes no attacker-racy
                // pathname metadata. Report the proven lower bound instead of
                // reopening by path merely to recover an exact size.
                inventory.rejected_configs.push(RejectedConfig {
                    path: rel_path.clone(),
                    reason: RejectedReason::Oversize {
                        size_bytes: MCP_CONFIG_MAX_SIZE.saturating_add(1),
                    },
                });
                continue;
            }
            Err(crate::util::OpenRegularError::Io(error)) => {
                inventory.rejected_configs.push(RejectedConfig {
                    path: rel_path.clone(),
                    reason: RejectedReason::Unreadable {
                        permission_denied: error.kind() == std::io::ErrorKind::PermissionDenied,
                    },
                });
                continue;
            }
        };

        // Admitted: counts as a discovered config from here on, even if it is
        // later classified as malformed text or JSON.
        inventory.configs.push(rel_path.clone());

        let content = match String::from_utf8(bytes) {
            Ok(content) => content,
            Err(_) => {
                inventory.malformed_configs.push(rel_path);
                continue;
            }
        };

        match parse_mcp_config_detailed(&content, &rel_path) {
            Ok(mut servers) => {
                if servers.is_empty() {
                    // Valid but empty config — not malformed, still a discovered config.
                } else {
                    inventory.servers.append(&mut servers);
                }
            }
            Err(McpConfigParseError::Malformed) => {
                // Not valid JSON, or no MCP-server object.
                inventory.malformed_configs.push(rel_path);
            }
            Err(McpConfigParseError::Rejected(reason)) => {
                // A semantic refusal is a coverage gap, not an ignorable parse
                // error. Remove it from the accepted-config set and retain only
                // the structured, non-secret reason.
                inventory.configs.pop();
                inventory.rejected_configs.push(RejectedConfig {
                    path: rel_path,
                    reason,
                });
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
    parse_mcp_config_detailed(content, source_config).ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum McpConfigParseError {
    /// Invalid JSON or no recognized server-map object.
    Malformed,
    /// Valid MCP-shaped JSON that must be refused as a security boundary.
    Rejected(RejectedReason),
}

/// JSON value deserializer that rejects duplicate object members recursively.
/// `serde_json::Value` alone is last-wins and therefore cannot prove that Tirith
/// and an MCP client interpreted the same launch document.
struct UniqueJsonValue(serde_json::Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJsonValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object members")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .map(UniqueJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::String(
            value.to_string(),
        )))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::String(value)))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::Null))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_unit()
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJsonValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(UniqueJsonValue(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(UniqueJsonValue(serde_json::Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let UniqueJsonValue(value) = object.next_value()?;
            values.insert(key, value);
        }
        Ok(UniqueJsonValue(serde_json::Value::Object(values)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictJsonError {
    Malformed,
    DuplicateObjectKey,
}

/// Parse JSON without serde_json's last-wins duplicate-member collapse. This is
/// shared with the MCP gateway so the exact bytes analyzed are never semantically
/// different from the object forwarded upstream.
pub fn parse_json_no_duplicates(content: &str) -> Result<serde_json::Value, StrictJsonError> {
    let mut deserializer = serde_json::Deserializer::from_str(content);
    let parsed = UniqueJsonValue::deserialize(&mut deserializer).map_err(|error| {
        if error.to_string().contains("duplicate JSON object key") {
            StrictJsonError::DuplicateObjectKey
        } else {
            StrictJsonError::Malformed
        }
    })?;
    deserializer.end().map_err(|_| StrictJsonError::Malformed)?;
    Ok(parsed.0)
}

/// Strict parser used by inventory construction. The public compatibility
/// wrapper above retains the historical `Option` surface, while this path keeps
/// semantic security refusals distinct from ordinary malformed JSON so lock and
/// verify can report/persist coverage honestly.
fn parse_mcp_config_detailed(
    content: &str,
    source_config: &str,
) -> Result<Vec<McpServerEntry>, McpConfigParseError> {
    let json = parse_json_no_duplicates(content).map_err(|error| match error {
        StrictJsonError::Malformed => McpConfigParseError::Malformed,
        StrictJsonError::DuplicateObjectKey => {
            McpConfigParseError::Rejected(RejectedReason::DuplicateJsonKey)
        }
    })?;

    let has_canonical = json.get("mcpServers").is_some();
    let has_alias = json.get("servers").is_some();
    if has_canonical && has_alias {
        return Err(McpConfigParseError::Rejected(
            RejectedReason::AmbiguousServerObjects,
        ));
    }
    let top = json.as_object().ok_or(McpConfigParseError::Malformed)?;
    if top
        .keys()
        .any(|field| !matches!(field.as_str(), "mcpServers" | "servers" | "$schema"))
    {
        return Err(McpConfigParseError::Rejected(
            RejectedReason::UnsupportedServerField,
        ));
    }
    if top.get("$schema").is_some_and(|schema| !schema.is_string()) {
        return Err(McpConfigParseError::Rejected(
            RejectedReason::InvalidServerField,
        ));
    }

    // Canonical `mcpServers` and the `servers` alias are both supported, but
    // never simultaneously: clients disagree on precedence, so a dual-root
    // document cannot have one trustworthy inventory.
    let servers_obj = if has_canonical {
        json.get("mcpServers")
    } else {
        json.get("servers")
    }
    .and_then(|v| v.as_object())
    .ok_or(McpConfigParseError::Malformed)?;

    let mut entries = Vec::with_capacity(servers_obj.len());
    for (name, config) in servers_obj {
        let obj = config.as_object().ok_or(McpConfigParseError::Rejected(
            RejectedReason::InvalidServerEntry,
        ))?;

        // Exact-lock mode recognizes a deliberately small launch schema. An
        // ignored header/env-file/cwd/enable flag can change what another client
        // launches while leaving Tirith's fingerprint untouched, so any
        // unmodeled member is a structured coverage refusal.
        const SUPPORTED_SERVER_FIELDS: &[&str] = &["url", "command", "args", "env", "tools"];
        if obj
            .keys()
            .any(|field| !SUPPORTED_SERVER_FIELDS.contains(&field.as_str()))
        {
            return Err(McpConfigParseError::Rejected(
                RejectedReason::UnsupportedServerField,
            ));
        }

        let transport = parse_transport(name, obj)?;
        let declared = parse_tools_strict(obj)?;
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

    Ok(entries)
}

/// Derive one unambiguous, commit-safe transport descriptor. `server_name`
/// remains in the helper boundary for call-site stability, but v8 never mixes it
/// or any secret bytes into the URL-userinfo presence marker.
fn parse_transport(
    server_name: &str,
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<McpTransport, McpConfigParseError> {
    if obj.contains_key("url") && obj.contains_key("command") {
        return Err(McpConfigParseError::Rejected(
            RejectedReason::AmbiguousTransport,
        ));
    }

    if let Some(url_value) = obj.get("url") {
        let url = url_value.as_str().filter(|url| !url.is_empty()).ok_or(
            McpConfigParseError::Rejected(RejectedReason::InvalidServerField),
        )?;
        if url_has_secret_bearing_components(url, false) {
            return Err(McpConfigParseError::Rejected(
                RejectedReason::SecretBearingUrl,
            ));
        }
        let (redacted_url, userinfo_hash) = redact_url_userinfo(server_name, url);
        return Ok(McpTransport::Url {
            url: redacted_url,
            userinfo_hash,
        });
    }

    if let Some(command_value) = obj.get("command") {
        let command = command_value
            .as_str()
            .filter(|command| !command.is_empty())
            .ok_or(McpConfigParseError::Rejected(
                RejectedReason::InvalidServerField,
            ))?;
        let args: Vec<String> = match obj.get("args") {
            None => Vec::new(),
            Some(value) => value
                .as_array()
                .filter(|args| args.iter().all(|arg| arg.is_string()))
                .ok_or(McpConfigParseError::Rejected(
                    RejectedReason::InvalidServerField,
                ))?
                .iter()
                .map(|arg| arg.as_str().expect("validated string").to_string())
                .collect(),
        };
        if args_have_secret_bearing_value(&args) {
            return Err(McpConfigParseError::Rejected(
                RejectedReason::SecretBearingArgument,
            ));
        }
        let env = parse_env_strict(obj)?;
        return Ok(McpTransport::Stdio {
            command: command.to_string(),
            args,
            env,
        });
    }

    Err(McpConfigParseError::Rejected(
        RejectedReason::InvalidServerField,
    ))
}

/// High-confidence credential classifier for commit-bound stdio arguments. It
/// deliberately accepts explicit environment references; the reference is safe
/// to commit and the resolved value stays outside the lockfile.
fn args_have_secret_bearing_value(args: &[String]) -> bool {
    for (index, arg) in args.iter().enumerate() {
        if url_has_secret_bearing_components(arg, true)
            || value_has_secret_literal(arg)
            || credential_header_has_literal(arg)
        {
            return true;
        }

        if header_flag_name(arg)
            && args
                .get(index + 1)
                .is_some_and(|value| credential_header_has_literal(value))
        {
            return true;
        }
        if let Some(header) = arg
            .strip_prefix("--header=")
            .or_else(|| arg.strip_prefix("-H="))
            .or_else(|| arg.strip_prefix("-H").filter(|value| !value.is_empty()))
        {
            if credential_header_has_literal(header) {
                return true;
            }
        }

        if let Some((key, value)) = split_assignment(arg) {
            if credential_header_has_literal(value) {
                return true;
            }
            // An arbitrary option name does not make a credential-safe sink.
            // Reject known literal token shapes on every attached RHS, not just
            // values attached to a curated list of secret-looking option names.
            if !is_env_reference(value) && value_has_secret_literal(value) {
                return true;
            }
            if secret_key_name(key) && !value.is_empty() && !is_env_reference(value) {
                return true;
            }
        }

        if secret_flag_name(arg) {
            if let Some(value) = args.get(index + 1) {
                if !is_env_reference(value) {
                    return true;
                }
            }
        }
    }
    false
}

fn split_assignment(value: &str) -> Option<(&str, &str)> {
    value
        .split_once('=')
        .or_else(|| value.strip_prefix('/').and_then(|v| v.split_once(':')))
}

fn secret_flag_name(value: &str) -> bool {
    let trimmed = value.trim_start_matches('-').trim_start_matches('/');
    !trimmed.is_empty() && !trimmed.contains(['=', ':']) && secret_key_name(trimmed)
}

fn header_flag_name(value: &str) -> bool {
    let normalized: String = value
        .trim_start_matches('-')
        .trim_start_matches('/')
        .chars()
        .filter(|character| !matches!(character, '-' | '_' | '.'))
        .flat_map(char::to_lowercase)
        .collect();
    matches!(
        normalized.as_str(),
        "h" | "header" | "headers" | "httpheader" | "httpheaders" | "requestheader"
    )
}

fn secret_key_name(value: &str) -> bool {
    let normalized: String = value
        .chars()
        .filter(|c| !matches!(c, '-' | '_' | '.'))
        .flat_map(char::to_lowercase)
        .collect();
    matches!(
        normalized.as_str(),
        "apikey"
            | "auth"
            | "key"
            | "accesstoken"
            | "accesskey"
            | "awsaccesskeyid"
            | "awssecretaccesskey"
            | "authtoken"
            | "bearertoken"
            | "gitlabtoken"
            | "token"
            | "sessiontoken"
            | "securitytoken"
            | "refreshtoken"
            | "password"
            | "passwd"
            | "secret"
            | "secretkey"
            | "clientsecret"
            | "credential"
            | "credentials"
            | "authorization"
            | "privatekey"
            | "signature"
            | "sig"
            | "xamzsignature"
            | "xamzcredential"
            | "xamzsecuritytoken"
    )
}

/// Recognize credential-bearing HTTP header syntax without retaining or
/// returning the value. Benign headers such as Accept/Content-Type remain
/// lockable; authorization, cookie, and common API-key headers must be an
/// explicit environment reference (optionally following an auth scheme).
fn credential_header_has_literal(raw: &str) -> bool {
    let Some((name, value)) = raw.split_once(':') else {
        return false;
    };
    let normalized: String = name
        .chars()
        .filter(|character| !matches!(character, '-' | '_' | '.' | ' ' | '\t'))
        .flat_map(char::to_lowercase)
        .collect();
    let sensitive = matches!(
        normalized.as_str(),
        "authorization"
            | "proxyauthorization"
            | "cookie"
            | "setcookie"
            | "xapikey"
            | "xauthtoken"
            | "xaccesstoken"
            | "xawssecuritytoken"
    );
    if !sensitive {
        return false;
    }
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    if is_env_reference(value) {
        return false;
    }
    let after_scheme = value
        .split_once(char::is_whitespace)
        .map(|(_, credential)| credential.trim());
    !after_scheme.is_some_and(is_env_reference)
}

fn is_env_reference(value: &str) -> bool {
    let trimmed = value.trim();
    let identifier = if let Some(body) = trimmed
        .strip_prefix("${")
        .and_then(|body| body.strip_suffix('}'))
    {
        body.strip_prefix("env:").unwrap_or(body)
    } else if let Some(body) = trimmed.strip_prefix("$env:") {
        body
    } else if let Some(body) = trimmed.strip_prefix('$') {
        body
    } else if let Some(body) = trimmed
        .strip_prefix('%')
        .and_then(|body| body.strip_suffix('%'))
    {
        body
    } else {
        return false;
    };

    // Accept only an actual environment-variable identifier. In particular,
    // `${anything at all}` is not proof of indirection: a credential-shaped
    // body can itself be a syntactically valid identifier, so reject known
    // literal token shapes before applying the identifier grammar.
    !looks_like_secret_literal(identifier) && valid_env_identifier(identifier)
}

fn valid_env_identifier(identifier: &str) -> bool {
    let mut chars = identifier.chars();
    chars
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn value_has_secret_literal(value: &str) -> bool {
    bounded_percent_decode(value)
        .as_deref()
        .is_none_or(looks_like_secret_literal)
}

fn looks_like_secret_literal(value: &str) -> bool {
    let value = value.trim();
    let known_prefix = [
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "glpat-",
        "npm_",
        "sk-proj-",
        "sk_live_",
        "rk_live_",
        "xoxb-",
        "xoxp-",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix) && value.len() >= prefix.len() + 12);
    if known_prefix {
        return true;
    }
    if value.starts_with("AKIA")
        && value.len() == 20
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return true;
    }
    let jwt_parts: Vec<&str> = value.split('.').collect();
    jwt_parts.len() == 3
        && jwt_parts.iter().all(|part| {
            part.len() >= 8
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        })
}

/// Detect credential-bearing URL components without returning/logging them.
/// `reject_userinfo` is true for URLs embedded in stdio arguments (which would
/// otherwise be serialized verbatim); the top-level URL transport instead
/// hashes and strips userinfo via `redact_url_userinfo`.
/// Userinfo in a URL-shaped string `url::Url::parse` refused. Only the authority
/// segment is inspected, so an ordinary `--mail=a@b.example` argument (no `//`
/// authority) is not misread as a credential.
fn raw_authority_has_userinfo(raw: &str) -> bool {
    let after_scheme = match raw.split_once("://") {
        Some((_, rest)) => rest,
        None => match raw.strip_prefix("//") {
            Some(rest) => rest,
            None => return false,
        },
    };
    after_scheme
        .split(['/', '?', '#'])
        .next()
        .is_some_and(|authority| authority.contains('@'))
}

fn url_has_secret_bearing_components(raw: &str, reject_userinfo: bool) -> bool {
    let Ok(parsed) = url::Url::parse(raw) else {
        // An unparsable URL-shaped argument still reaches the lock verbatim, so
        // the userinfo boundary has to be checked on the raw text too.
        if reject_userinfo && raw_authority_has_userinfo(raw) {
            return true;
        }
        let fragment_present = raw
            .split_once('#')
            .is_some_and(|(_, fragment)| !fragment.is_empty());
        if fragment_present {
            return true;
        }
        let query = raw
            .split_once('?')
            .map(|(_, tail)| tail.split('#').next().unwrap_or(""));
        return query.is_some_and(query_has_secret_parameter);
    };

    if reject_userinfo && (!parsed.username().is_empty() || parsed.password().is_some()) {
        return true;
    }
    if parsed
        .fragment()
        .is_some_and(|fragment| !fragment.is_empty())
    {
        return true;
    }
    parsed
        .query_pairs()
        .any(|(key, value)| query_pair_has_secret(&key, &value))
}

/// Final commit-bound URL check used by public construction and serialization.
/// `url_has_secret_bearing_components(..., true)` covers parsed URLs and
/// secret query/fragment values. The best-effort redactor additionally detects
/// userinfo in malformed-but-authority-shaped strings that `url::Url` rejects.
fn transport_url_is_commit_safe(raw: &str) -> bool {
    if url_has_secret_bearing_components(raw, true) {
        return false;
    }
    let (_, userinfo_marker) = redact_url_userinfo("", raw);
    userinfo_marker.is_none()
}

fn query_has_secret_parameter(query: &str) -> bool {
    url::form_urlencoded::parse(query.as_bytes())
        .any(|(key, value)| query_pair_has_secret(&key, &value))
}

fn query_pair_has_secret(key: &str, value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let Some(decoded_key) = bounded_percent_decode(key) else {
        return true;
    };
    let Some(decoded_value) = bounded_percent_decode(value) else {
        return true;
    };
    !is_env_reference(&decoded_value)
        && (secret_key_name(&decoded_key) || looks_like_secret_literal(&decoded_value))
}

/// Decode nested percent escapes to a fixed point with a small work bound. A
/// component that still changes after the bound (or decodes to invalid UTF-8)
/// is rejected by callers rather than treated as a clean opaque value.
fn bounded_percent_decode(value: &str) -> Option<String> {
    const MAX_DECODE_PASSES: usize = 4;
    let mut current = value.to_string();
    for _ in 0..MAX_DECODE_PASSES {
        let decoded = percent_encoding::percent_decode_str(&current)
            .decode_utf8()
            .ok()?
            .into_owned();
        if decoded == current {
            return Some(current);
        }
        current = decoded;
    }
    let next = percent_encoding::percent_decode_str(&current)
        .decode_utf8()
        .ok()?
        .into_owned();
    (next == current).then_some(current)
}

/// Strip any HTTP Basic Auth userinfo from a URL, returning the redacted URL and
/// a fixed marker recording only that userinfo was present.
///
/// **Security invariant (v8):** `https://user:token@host/` is stored as
/// `https://host/` plus `SECRET_PRESENT_MARKER`. No raw credential or
/// deterministic verifier derived from it reaches a committed lockfile.
///
/// Behavior: a clean parse with userinfo returns the stripped URL
/// (`set_username("")`/`set_password(None)`, re-serialized) plus `Some("present")`.
/// A clean parse with no userinfo returns the CANONICAL `as_str()` form and
/// `None` — round-tripped even with nothing to redact, so the stored bytes have
/// the same shape either way and credential removal doesn't surface as a
/// spurious `UrlChanged` alongside `UserinfoRemoved`. (`https://:@host/` etc.
/// normalize to no-userinfo.) An unparseable URL is best-effort-stripped with the
/// same presence marker (see [`strip_userinfo_best_effort`]); a
/// non-authority-shaped one is kept verbatim with `None`.
fn redact_url_userinfo(_server_name: &str, url: &str) -> (String, Option<String>) {
    let parsed = match url::Url::parse(url) {
        Ok(p) => p,
        // Unparseable: best-effort byte-scan strip (replace `scheme://...@` with
        // `***`) so a credential in a malformed-but-authority-shaped URL doesn't
        // leak into the committed lockfile; only presence survives. See
        // `strip_userinfo_best_effort`.
        Err(_) => return strip_userinfo_best_effort(_server_name, url),
    };

    // `url` normalizes the all-empty `:@`/`@` forms away, so this detects only
    // meaningful userinfo without reconstructing or copying its secret bytes.
    let userinfo_present = !parsed.username().is_empty() || parsed.password().is_some();

    // No userinfo: still round-trip through `as_str()` so the stored URL has the
    // same canonical shape as the userinfo-stripped path — without this,
    // `compute_drift` would report a spurious `UrlChanged` alongside
    // `UserinfoRemoved` (e.g. `https://host` vs the locked `https://host/`).
    if !userinfo_present {
        return (parsed.as_str().to_string(), None);
    }

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

    (
        parsed.as_str().to_string(),
        Some(SECRET_PRESENT_MARKER.to_string()),
    )
}

/// Best-effort userinfo strip for a URL `url::Url::parse` rejected. Replaces the
/// segment between `scheme://` and the first `@` (before the next `/`/`?`/`#`/end)
/// with `***`, preserving the rest for diagnostics. A string not matching the
/// `scheme://...@` shape is returned verbatim — nothing to strip.
///
/// Manual byte-scan (not regex) to avoid a heavy dependency for one call site.
/// Returns `(stripped_url, Option<marker>)`: when the strip fires with non-empty
/// userinfo, only the fixed presence marker survives; otherwise `None`.
fn strip_userinfo_best_effort(_server_name: &str, raw: &str) -> (String, Option<String>) {
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
    // Record only whether non-empty userinfo exists. Do not hash, copy, or decode
    // the bytes between `auth_start` and `at`: even a digest would be an offline
    // dictionary oracle for common low-entropy credentials.
    let userinfo_bytes = &bytes[auth_start..at];
    let userinfo_hash = if userinfo_bytes.is_empty() {
        None
    } else {
        Some(SECRET_PRESENT_MARKER.to_string())
    };
    // Rewrite to `***` for shape consistency even when the substring is empty.
    let mut out = String::with_capacity(raw.len());
    out.push_str(&raw[..auth_start]);
    out.push_str("***");
    out.push_str(&raw[at..]);
    (out, userinfo_hash)
}

/// Extract a stdio server's `env` as name + fixed presence-marker entries,
/// sorted by name
/// for a stable hash. Every value must be a string; accepting a different type
/// and stringifying it would not prove that another client launches the same env.
///
/// `env` is security-relevant (what the config injects into the subprocess), so
/// capturing it surfaces additions/removals. **The raw value never leaves this
/// function** (v8 invariant): [`McpEnvEntry::from_raw`] ignores it, so neither
/// the value nor a deterministic verifier reaches a struct/serializer/log.
fn parse_env_strict(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<McpEnvEntry>, McpConfigParseError> {
    let Some(value) = obj.get("env") else {
        return Ok(Vec::new());
    };
    let map = value.as_object().ok_or(McpConfigParseError::Rejected(
        RejectedReason::InvalidServerField,
    ))?;
    if !map.values().all(serde_json::Value::is_string) {
        return Err(McpConfigParseError::Rejected(
            RejectedReason::InvalidServerField,
        ));
    }
    let mut env: Vec<McpEnvEntry> = map
        .iter()
        .map(|(name, value)| McpEnvEntry::from_raw(name, value.as_str().expect("validated string")))
        .collect();
    env.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(env)
}

/// Extract the declared tool list, distinguishing the four on-wire states:
/// `Omitted` (no key), `EmptyDeclared` (`"tools": []`), `Declared` (a string
/// array, sorted/de-duplicated). A wrong type or non-string element is a coverage
/// refusal rather than being silently dropped. The lockfile collapses Omitted/EmptyDeclared,
/// preserving the distinction via `tools_declared` (PR121_FIX_LIST_TRIAGE item 7).
fn parse_tools_strict(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<DeclaredTools, McpConfigParseError> {
    let Some(value) = obj.get("tools") else {
        return Ok(DeclaredTools::Omitted);
    };
    let arr = value
        .as_array()
        .filter(|tools| tools.iter().all(serde_json::Value::is_string))
        .ok_or(McpConfigParseError::Rejected(
            RejectedReason::InvalidServerField,
        ))?;
    let mut tools: Vec<String> = arr
        .iter()
        .map(|tool| tool.as_str().expect("validated string").to_string())
        .collect();
    tools.sort();
    tools.dedup();
    if tools.is_empty() {
        // Empty array, or all elements non-string — both equivalent to "no
        // declarable tools".
        Ok(DeclaredTools::EmptyDeclared)
    } else {
        Ok(DeclaredTools::Declared(tools))
    }
}

// ---------------------------------------------------------------------------
// Drift detection
// ---------------------------------------------------------------------------

/// How a stdio server's `env` differs from the lockfile. Each variant carries
/// only the variable's NAME. Under v8, only addition/removal is observable: the
/// lockfile deliberately holds no value-dependent commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpEnvChange {
    /// The server now declares an env variable that the lockfile did not.
    Added { name: String },
    /// The lockfile declared an env variable that the server no longer does.
    Removed { name: String },
    /// Legacy serialized drift variant retained for API compatibility. V8 never
    /// emits it because value rotation is intentionally unobservable.
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
    /// Both `url`; credential presence was added or removed. `UserinfoSwapped`
    /// remains a legacy serialized variant but v8 never emits it.
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
/// differs. `content_hash` excludes `source_config`, but the merge identity does
/// not: moving an unchanged server between configs is an exact removal plus
/// addition rather than a name-only cancellation.
///
/// The result is sorted ([`McpDrift::sort_key`]). Privacy: entries carry only
/// names (server / env-var / tool). V8 records only env names and URL-userinfo
/// presence, never raw secrets or deterministic commitments to them.
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

    // Legacy v5-v7 migration path. Deserialized v7 secret commitments (and the
    // same fields inherited by v4-v6) have already been normalized to v8
    // presence markers in `parse_lockfile`, so this normal static walk preserves
    // real server/transport/env-name drift without comparing secret values. The
    // migration prompt still requires an explicit re-lock.
    if matches!(
        lock.schema_state,
        LockfileSchema::LegacyV5Migration
            | LockfileSchema::LegacyV6Migration
            | LockfileSchema::LegacyV7Migration
    ) {
        let mut drifts = compute_drift_static(current, lock);
        drifts.push(McpDrift::SchemaUpgradeRequired {
            from_version: lock.format_version,
            to_version: MCP_LOCK_FORMAT_VERSION,
        });
        drifts.sort_by_key(McpDrift::sort_key);
        return drifts;
    }

    compute_drift_static(current, lock)
}

/// The current static-inventory drift walk (no migration prompt). Factored out
/// of [`compute_drift`] so the v5-v7 migration paths can reuse the identical
/// static comparison and then append the one-time `SchemaUpgradeRequired`
/// prompt. Reads only the static `content_hash`/`inventory_hash`, never
/// descriptors (those have their own [`compute_descriptor_drift`]).
fn compute_drift_static(current: &McpInventory, lock: &McpLockfile) -> Vec<McpDrift> {
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
/// Walk logic is identical to the current slow path; only the hash function differs.
fn compute_drift_v4(current: &McpInventory, lock: &McpLockfile) -> Vec<McpDrift> {
    // Recompute v4 hashes onto a position-indexed side-table so the walk can
    // compare them without mutating the current hashes in `current_lock.servers`.
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
                // V8 records only presence, so a credential rotation is
                // intentionally unobservable and produces no drift.
                (Some(_), Some(_)) => {}
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
                // V8 records only that the name exists. A value rotation is
                // intentionally unobservable and therefore not drift.
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
    // repo-0291: the lockfile is repository-controlled — read it no-follow,
    // regular-file-only, and size-capped so a symlink to `/dev/zero` or a
    // giant file cannot hang or exhaust memory during gateway init.
    const MAX_LOCKFILE_BYTES: u64 = 4 * 1024 * 1024;
    let bytes = match crate::util::read_text_no_follow_capped(path, MAX_LOCKFILE_BYTES) {
        Ok(b) => b,
        Err(crate::util::OpenRegularError::NotFound) => {
            return Err(McpLockLoadError::NotFound);
        }
        Err(_) => {
            // Capture only the category kind, not the io-error Display (privacy —
            // see [`McpLockLoadError::Io`]). Non-regular/oversized both map to
            // the generic I/O category: the file exists but is not safely
            // loadable.
            return Err(McpLockLoadError::Io {
                kind: McpLockIoKind::from_io_kind(std::io::ErrorKind::InvalidData),
            });
        }
    };
    let content = String::from_utf8(bytes).map_err(|_| McpLockLoadError::Io {
        kind: McpLockIoKind::from_io_kind(std::io::ErrorKind::InvalidData),
    })?;
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
/// **v4-v7 → v8 migration:** a `format_version: 4`, `5`, `6`, or `7` lockfile is
/// accepted and tagged with its corresponding legacy migration state. Before any
/// hash is recomputed, every legacy env/userinfo commitment is overwritten by
/// `SECRET_PRESENT_MARKER`. [`compute_drift`] then preserves real static and
/// secret-presence drift while adding [`McpDrift::SchemaUpgradeRequired`]; the
/// lock cannot authorize a gateway until the operator re-locks under v8.
///
/// A v8 document is stricter: every present historical `value_hash` /
/// `userinfo_hash` field must equal the fixed marker. Any other string is a
/// privacy-invalid schema shape and is rejected rather than normalized.
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

    // Schema-version gate, BEFORE the full deserialize. V4 through v7 have an
    // identical-enough on-disk shape via serde defaults; they are accepted only
    // as explicitly-tagged migration inputs.
    let schema_state = match probe.format_version {
        v if v == MCP_LOCK_FORMAT_VERSION => LockfileSchema::Current,
        4 => LockfileSchema::LegacyV4Migration,
        5 => LockfileSchema::LegacyV5Migration,
        6 => LockfileSchema::LegacyV6Migration,
        7 => LockfileSchema::LegacyV7Migration,
        _ => {
            return Err(McpLockLoadError::UnsupportedVersion {
                found: probe.format_version,
                supported: MCP_LOCK_FORMAT_VERSION,
            });
        }
    };

    // Second pass: full deserialize. The version is current (or a supported
    // legacy shape), so any failure here is genuine corruption within the schema.
    let mut lock: McpLockfile =
        serde_json::from_str(content).map_err(|e| McpLockLoadError::Parse {
            line: e.line(),
            column: e.column(),
        })?;
    if schema_state == LockfileSchema::Current {
        // Reject a hand-written v8 lock carrying a deterministic commitment (or
        // arbitrary secret-shaped value) in either historical marker field.
        // Line/column zero denotes this post-deserialization schema invariant;
        // no attacker-controlled field value is retained in the error.
        if lock.servers.iter().any(|server| {
            !has_only_current_secret_presence_markers(&server.transport)
                || transport_commit_rejection(&server.transport).is_some()
        }) {
            return Err(McpLockLoadError::Parse { line: 0, column: 0 });
        }
    } else {
        // Erase deterministic v4-v7 commitments before recomputing hashes or
        // exposing the parsed lock to callers. Only structural presence remains.
        for server in &mut lock.servers {
            normalize_secret_presence_markers(&mut server.transport);
        }
    }
    lock.schema_state = schema_state;
    // Defensive sort at the parse boundary (a hand-edited lockfile could land out
    // of order) so `compute_drift`'s merge walk holds for every caller.
    lock.servers.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.source_config.cmp(&b.source_config))
    });
    lock.configs.sort();
    lock.configs.dedup();
    lock.malformed_configs.sort();
    lock.malformed_configs.dedup();
    lock.rejected_configs.sort_by(|a, b| a.path.cmp(&b.path));
    lock.rejected_configs.dedup();

    // Recompute every hash from the lockfile's DATA — the deserialized
    // `hash`/`inventory_hash`/`descriptor_hash` are discarded, so a hand-edited
    // lockfile that forged consistent hashes can't silence drift (both
    // `compute_drift`'s fast-path short-circuit and its per-server comparison read
    // these). Cheap relative to the file IO just done.
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
        // Re-normalize the descriptor list (sort + de-dup by name) and recompute
        // the descriptor hash from the data, so a forged or mis-ordered
        // `descriptor_hash` cannot silence descriptor drift either.
        server.descriptors = normalize_descriptors(std::mem::take(&mut server.descriptors));
        // Pre-approval-bit v6 lockfiles represented approval solely by a
        // non-empty descriptor vector. Preserve that safe existing baseline;
        // the explicit bit additionally lets a newly approved empty set exist.
        if lock.schema_state == LockfileSchema::LegacyV6Migration && !server.descriptors.is_empty()
        {
            server.descriptors_approved = true;
        }
        server.descriptor_hash = compute_descriptor_hash(&server.descriptors);
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
    /// Read but doesn't parse or violates a current-schema invariant. Carries
    /// only line/column (both `usize`, can't echo the JSON value); `(0, 0)` marks
    /// a post-deserialization invariant failure. See [`parse_lockfile`].
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
            // The zero sentinel is a post-deserialization privacy invariant,
            // not a source location. Keep the diagnostic specific but value-free.
            McpLockLoadError::Parse { line: 0, column: 0 } => {
                write!(f, "lockfile violates the current schema privacy invariant")
            }
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
    fn parse_server_with_no_transport_is_rejected() {
        // A server with no launch transport cannot be bound exactly.
        let content = r#"{ "mcpServers": { "weird": { "tools": ["x"] } } }"#;
        assert_eq!(
            parse_mcp_config_detailed(content, ".mcp.json"),
            Err(McpConfigParseError::Rejected(
                RejectedReason::InvalidServerField
            ))
        );
    }

    #[test]
    fn parse_rejects_url_and_command_ambiguity() {
        // Clients disagree on precedence; choosing either would let the other
        // transport become a hidden execution surface.
        let content =
            r#"{ "mcpServers": { "both": { "url": "https://x.example", "command": "node" } } }"#;
        assert_eq!(
            parse_mcp_config_detailed(content, ".mcp.json"),
            Err(McpConfigParseError::Rejected(
                RejectedReason::AmbiguousTransport
            ))
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
    fn parse_rejects_non_object_server_instead_of_locking_subset() {
        // Skipping a client-visible declaration would make the accepted subset
        // look complete, so the entire config becomes a coverage refusal.
        let content = r#"{ "mcpServers": { "bad": "oops", "good": { "command": "node" } } }"#;
        assert_eq!(
            parse_mcp_config_detailed(content, ".mcp.json"),
            Err(McpConfigParseError::Rejected(
                RejectedReason::InvalidServerEntry
            ))
        );
    }

    #[test]
    fn parse_tools_rejects_non_string_entries() {
        let content =
            r#"{ "mcpServers": { "s": { "command": "n", "tools": ["ok", 42, null, "ok"] } } }"#;
        assert_eq!(
            parse_mcp_config_detailed(content, "mcp.json"),
            Err(McpConfigParseError::Rejected(
                RejectedReason::InvalidServerField
            ))
        );
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
        let rendered = lock.render().expect("render lockfile");
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

    // Finding C — a stdio server's env names are captured and additions/removals
    // drift, without committing a verifier for each value.

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
        // Env entries are present, sorted by name, and carry only the fixed
        // structural marker — never the raw values or value-derived hashes.
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
    fn parse_env_rejects_non_string_values() {
        // Stringifying a non-string env value would not prove another client's
        // effective child environment, so the whole config is refused.
        let content = r#"{
            "mcpServers": {
                "s": { "command": "n", "env": { "ZED": "z", "ABLE": 7 } }
            }
        }"#;
        assert_eq!(
            parse_mcp_config_detailed(content, ".mcp.json"),
            Err(McpConfigParseError::Rejected(
                RejectedReason::InvalidServerField
            ))
        );
    }

    #[test]
    fn content_hash_tracks_env_names_but_not_value_rotation() {
        // V8 intentionally treats value rotation as opaque, while a change to
        // the set of injected env names remains structural drift.
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
        assert_eq!(
            base.content_hash(),
            value_changed.content_hash(),
            "rotating an env value must not create a committed verifier"
        );
        assert_ne!(
            base.content_hash(),
            var_added.content_hash(),
            "adding an env var must change the content hash"
        );

        // The value-independent behavior flows through to the inventory hash.
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
        assert_eq!(
            McpLockfile::from_inventory(&inv_base).inventory_hash,
            McpLockfile::from_inventory(&inv_changed).inventory_hash,
            "env value rotation must not change the inventory hash"
        );
    }

    #[test]
    fn lockfile_format_version_is_8() {
        // V8 retains v7's complete descriptor/launch binding and replaces
        // deterministic secret commitments with presence-only markers. V4-v7
        // lockfiles are accepted at parse time and tagged
        // with migration schema states so
        // `compute_drift` surfaces a one-time migration prompt on top of any real
        // static drift.
        assert_eq!(MCP_LOCK_FORMAT_VERSION, 8);
        let lock = McpLockfile::from_inventory(&McpInventory::default());
        assert_eq!(lock.format_version, 8);
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
            serde_json::from_str(&lock.render().expect("render lockfile with environment"))
                .expect("lockfile with env must round-trip");
        assert_eq!(parsed, lock);
    }

    // Finding E — env raw values and deterministic verifiers must not be
    // persisted; only a fixed structural marker is stored.

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
        let rendered = McpLockfile::from_inventory(&inventory)
            .render()
            .expect("render lockfile");

        for (name, raw_value) in ENV_LEAK_PROBES {
            // The name is allowed to appear, but the raw value must not. Only a
            // value-independent presence marker is recorded.
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
            rendered.contains("\"value_hash\": \"present\""),
            "rendered lockfile must serialize the fixed presence marker"
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

        // The parsed env entry carries only the fixed marker, not the raw value
        // or a deterministic hash of it.
        let env = match &entries[0].transport {
            McpTransport::Stdio { env, .. } => env,
            other => panic!("expected stdio transport, got {other:?}"),
        };
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].name, "GITHUB_PERSONAL_ACCESS_TOKEN");
        assert_eq!(env[0].value_hash, SECRET_PRESENT_MARKER);

        // And the rendered lockfile that descends from this parse must not
        // carry the raw secret bytes anywhere.
        let inventory = McpInventory {
            servers: entries,
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let rendered = McpLockfile::from_inventory(&inventory)
            .render()
            .expect("render lockfile");
        assert!(
            !rendered.contains(secret),
            "raw secret leaked from parse_mcp_config -> McpLockfile::render():\n{rendered}"
        );
    }

    #[test]
    fn env_entry_uses_value_independent_presence_marker() {
        let a = McpEnvEntry::from_raw("DEBUG", "1");
        let b = McpEnvEntry::from_raw("DEBUG", "different-secret");
        let c = McpEnvEntry::from_raw("VERBOSE", "1");
        assert_eq!(a.value_hash, SECRET_PRESENT_MARKER);
        assert_eq!(a.value_hash, b.value_hash);
        assert_eq!(a.value_hash, c.value_hash);
    }

    #[test]
    fn env_entry_serializer_cannot_persist_an_unsafe_commitment() {
        let unsafe_entry = McpEnvEntry {
            name: "TOKEN".into(),
            value_hash: "dictionary-recoverable-sha256".into(),
        };
        let rendered = serde_json::to_string(&unsafe_entry).unwrap();
        assert!(rendered.contains("\"value_hash\":\"present\""));
        assert!(!rendered.contains("dictionary-recoverable-sha256"));
    }

    #[test]
    fn direct_stdio_secret_is_rejected_before_hashing_or_rendering() {
        let probe = "ghp_DIRECT_STDIO_SECRET_NEVER_PERSIST_123456";
        let transport = McpTransport::Stdio {
            command: "node".into(),
            args: vec![format!("--token={probe}")],
            env: vec![],
        };

        let serde_error = serde_json::to_string(&transport)
            .expect_err("public transport serialization must reject a literal credential");
        assert!(!serde_error.to_string().contains(probe));

        let inventory = McpInventory {
            servers: vec![McpServerEntry {
                name: "direct-stdio".into(),
                transport,
                tools: vec![],
                tools_declared: true,
                source_config: ".mcp.json".into(),
            }],
            configs: vec![".mcp.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };
        let lock = McpLockfile::from_inventory(&inventory);
        assert!(lock.servers.is_empty());
        assert_eq!(
            lock.rejected_configs,
            vec![RejectedConfig {
                path: ".mcp.json".into(),
                reason: RejectedReason::SecretBearingArgument,
            }]
        );
        let rendered = lock.render().expect("render refusal-only lockfile");
        assert!(!rendered.contains(probe));
        assert!(rendered.contains("secret_bearing_argument"));
    }

    #[test]
    fn direct_url_credentials_are_rejected_without_echoing_values() {
        let probe = "DIRECT_URL_SECRET_NEVER_PERSIST_123456";
        let hostile_urls = [
            format!("https://user:{probe}@mcp.example.test/sse"),
            format!("https://mcp.example.test/sse?access_token={probe}"),
            format!("https://mcp.example.test/sse#{probe}"),
            format!("https://user:{probe}@[malformed-authority"),
        ];

        for (index, url) in hostile_urls.into_iter().enumerate() {
            let transport = McpTransport::Url {
                url,
                userinfo_hash: None,
            };
            let serde_error = serde_json::to_string(&transport)
                .expect_err("public transport serialization must reject URL credentials");
            assert!(!serde_error.to_string().contains(probe));

            let source = format!("config-{index}.json");
            let inventory = McpInventory {
                servers: vec![McpServerEntry {
                    name: format!("direct-url-{index}"),
                    transport,
                    tools: vec![],
                    tools_declared: true,
                    source_config: source.clone(),
                }],
                configs: vec![source.clone()],
                malformed_configs: vec![],
                rejected_configs: vec![],
            };
            let lock = McpLockfile::from_inventory(&inventory);
            assert!(lock.servers.is_empty());
            assert_eq!(
                lock.rejected_configs,
                vec![RejectedConfig {
                    path: source,
                    reason: RejectedReason::SecretBearingUrl,
                }]
            );
            let rendered = lock.render().expect("render refusal-only lockfile");
            assert!(!rendered.contains(probe));
            assert!(rendered.contains("secret_bearing_url"));
        }
    }

    #[test]
    fn direct_environment_references_and_benign_urls_remain_renderable() {
        let inventory = McpInventory {
            servers: vec![
                McpServerEntry {
                    name: "stdio".into(),
                    transport: McpTransport::Stdio {
                        command: "node".into(),
                        args: vec![
                            "--token".into(),
                            "${env:MCP_TOKEN}".into(),
                            "--header".into(),
                            "Authorization: Bearer $MCP_AUTH".into(),
                        ],
                        env: vec![],
                    },
                    tools: vec![],
                    tools_declared: true,
                    source_config: "stdio.json".into(),
                },
                McpServerEntry {
                    name: "remote".into(),
                    transport: McpTransport::Url {
                        url: "https://mcp.example.test/sse?access_token=%24%7BMCP_TOKEN%7D".into(),
                        userinfo_hash: None,
                    },
                    tools: vec![],
                    tools_declared: true,
                    source_config: "remote.json".into(),
                },
            ],
            configs: vec!["remote.json".into(), "stdio.json".into()],
            malformed_configs: vec![],
            rejected_configs: vec![],
        };

        let lock = McpLockfile::from_inventory(&inventory);
        assert_eq!(lock.servers.len(), 2);
        assert!(lock.rejected_configs.is_empty());
        let rendered = lock.render().expect("render commit-safe references");
        assert!(rendered.contains("MCP_TOKEN"));
        assert!(rendered.contains("MCP_AUTH"));
        parse_lockfile(&rendered).expect("safe direct construction must round-trip");
    }

    #[test]
    fn handcrafted_current_lock_rejects_secret_transports_content_free() {
        let probe = "HANDCRAFTED_SECRET_NEVER_ECHO_123456";
        let cases = [
            McpTransport::Stdio {
                command: "node".into(),
                args: vec!["server.js".into()],
                env: vec![],
            },
            McpTransport::Url {
                url: "https://mcp.example.test/sse".into(),
                userinfo_hash: None,
            },
        ];

        for (index, transport) in cases.into_iter().enumerate() {
            let inventory = McpInventory {
                servers: vec![McpServerEntry {
                    name: format!("server-{index}"),
                    transport,
                    tools: vec![],
                    tools_declared: true,
                    source_config: ".mcp.json".into(),
                }],
                configs: vec![".mcp.json".into()],
                malformed_configs: vec![],
                rejected_configs: vec![],
            };
            let safe = McpLockfile::from_inventory(&inventory)
                .render()
                .expect("render safe fixture");
            let mut document: serde_json::Value =
                serde_json::from_str(&safe).expect("parse safe fixture JSON");
            if index == 0 {
                document["servers"][0]["transport"]["args"] =
                    serde_json::json!([format!("--token={probe}")]);
            } else {
                document["servers"][0]["transport"]["url"] = serde_json::json!(format!(
                    "https://user:{probe}@mcp.example.test/sse?access_token={probe}#{probe}"
                ));
            }
            let hostile = serde_json::to_string_pretty(&document).expect("serialize hostile JSON");
            assert!(hostile.contains(probe));
            let error = parse_lockfile(&hostile)
                .expect_err("current lock with a raw transport credential must be rejected");
            assert_eq!(error, McpLockLoadError::Parse { line: 0, column: 0 });
            assert!(!error.to_string().contains(probe));
        }
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
        // Env names remain length-framed even though values are opaque. Distinct
        // names therefore cannot collapse to the same transport encoding.
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

    // Finding G — a URL transport's userinfo must not be persisted or committed
    // as a deterministic verifier: only URL userinfo presence is recorded.

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
        // userinfo byte sequences may show up. Only a fixed marker is persisted.
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
        let rendered = McpLockfile::from_inventory(&inventory)
            .render()
            .expect("render lockfile");

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
            rendered.contains("\"userinfo_hash\": \"present\""),
            "rendered lockfile must serialize a fixed userinfo presence marker"
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
        assert_eq!(hash.as_deref(), Some(SECRET_PRESENT_MARKER));

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
        let rendered = McpLockfile::from_inventory(&inventory)
            .render()
            .expect("render lockfile");
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
    fn url_userinfo_hash_tracks_presence_not_rotation() {
        // A credential rotation is intentionally opaque, while adding/removing
        // userinfo remains structural transport drift.
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

        // Token rotation does not create a committed verifier.
        assert_eq!(
            with_token_a.content_hash(),
            with_token_b.content_hash(),
            "rotating userinfo must not flip the per-server content hash"
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
        assert_eq!(
            McpLockfile::from_inventory(&inv_a).inventory_hash,
            McpLockfile::from_inventory(&inv_b).inventory_hash,
            "userinfo rotation must not change the inventory hash"
        );
    }

    #[test]
    fn url_userinfo_uses_value_independent_presence_marker() {
        let (_, a) = redact_url_userinfo("svc-a", "https://u:p@host.example/");
        let (_, b) = redact_url_userinfo("svc-b", "https://u:p@host.example/");
        let (_, c) = redact_url_userinfo("svc-a", "https://u:p2@host.example/");
        assert_eq!(a.as_deref(), Some(SECRET_PRESENT_MARKER));
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn url_userinfo_serializer_cannot_persist_an_unsafe_commitment() {
        let transport = McpTransport::Url {
            url: "https://host.example/".into(),
            userinfo_hash: Some("dictionary-recoverable-sha256".into()),
        };
        let rendered = serde_json::to_string(&transport).unwrap();
        assert!(rendered.contains("\"userinfo_hash\":\"present\""));
        assert!(!rendered.contains("dictionary-recoverable-sha256"));
    }

    #[test]
    fn parse_mcp_config_url_with_userinfo_is_redacted() {
        // End-to-end through the JSON parser: a config that declares a URL
        // with Basic Auth produces a parsed entry whose `url` field has the
        // userinfo stripped, whose `userinfo_hash` is the fixed presence marker,
        // AND whose rendered lockfile contains no raw userinfo bytes.
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
                assert_eq!(
                    userinfo_hash.as_deref(),
                    Some(SECRET_PRESENT_MARKER),
                    "userinfo_hash must record only structural presence"
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
        let rendered = McpLockfile::from_inventory(&inventory)
            .render()
            .expect("render lockfile");
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
        // A manually-built transport cannot carry an unsafe value into the v8
        // lock: `from_inventory` normalizes it before the round-trip.
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
        assert_eq!(
            match &lock.servers[0].transport {
                McpTransport::Url { userinfo_hash, .. } => userinfo_hash.as_deref(),
                other => panic!("expected URL transport, got {other:?}"),
            },
            Some(SECRET_PRESENT_MARKER)
        );
        let parsed: McpLockfile =
            serde_json::from_str(&lock.render().expect("render lockfile with userinfo marker"))
                .expect("lockfile with userinfo_hash must round-trip");
        assert_eq!(parsed, lock);
    }

    // Chunk 2 — drift detection. Covers additions/removals, non-secret transport
    // changes, env-name/userinfo-presence drift, and the empty-drift fast path.

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
    fn drift_ignores_env_value_rotation_under_presence_semantics() {
        // V8 has no value-derived commitment to compare, so rotating a value
        // under the same env name is intentionally a clean diff.
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
        assert!(
            drifts.is_empty(),
            "value rotation must be opaque: {drifts:?}"
        );
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
    fn drift_ignores_userinfo_rotation_under_presence_semantics() {
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
        assert!(
            drifts.is_empty(),
            "userinfo rotation must be opaque: {drifts:?}"
        );
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
    fn drift_detects_unchanged_server_moving_between_config_principals() {
        // Source config is part of the policy principal even though the
        // transport/content digest excludes it. A move must therefore retain
        // both exact identities as Removed(old source) + Added(new source).
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
        assert_eq!(drifts.len(), 2, "source move must preserve both identities");
        assert!(matches!(
            &drifts[0],
            McpDrift::Removed { name, source_config }
                if name == "s" && source_config == ".mcp.json"
        ));
        assert!(matches!(
            &drifts[1],
            McpDrift::Added { name, source_config, .. }
                if name == "s" && source_config == ".vscode/mcp.json"
        ));
    }

    #[test]
    fn duplicate_names_cannot_cancel_exact_source_drift() {
        // Regression for TIRITH-SEC-0072: the former cancellation pass looked
        // up hashes by name alone. With duplicate names it could compare the
        // first twin on each side and erase a Removed/Added pair belonging to
        // a different source principal.
        let prev = mk_inventory(vec![
            McpServerEntry {
                source_config: ".mcp.json".into(),
                ..stdio_server("same", "node")
            },
            McpServerEntry {
                source_config: ".vscode/mcp.json".into(),
                ..stdio_server("same", "deno")
            },
        ]);
        let lock = McpLockfile::from_inventory(&prev);
        let cur = mk_inventory(vec![
            McpServerEntry {
                source_config: ".mcp.json".into(),
                ..stdio_server("same", "node")
            },
            McpServerEntry {
                source_config: ".cursor/mcp.json".into(),
                ..stdio_server("same", "deno")
            },
        ]);

        let drifts = compute_drift(&cur, &lock);
        assert_eq!(drifts.len(), 2, "duplicate-name source move was erased");
        assert!(drifts.iter().any(|drift| matches!(
            drift,
            McpDrift::Removed { name, source_config }
                if name == "same" && source_config == ".vscode/mcp.json"
        )));
        assert!(drifts.iter().any(|drift| matches!(
            drift,
            McpDrift::Added { name, source_config, .. }
                if name == "same" && source_config == ".cursor/mcp.json"
        )));
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
        let lock_sorted_json = lock_sorted.render().expect("render sorted lockfile");

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
        fs::write(&path, lock.render().expect("render lockfile")).unwrap();
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
        let body = lock.render().expect("render lockfile");
        let loaded = parse_lockfile(&body).expect("current version must parse");
        assert_eq!(loaded.format_version, MCP_LOCK_FORMAT_VERSION);
    }

    #[test]
    fn parse_lockfile_rejects_non_marker_secret_fields_in_v8() {
        let unsafe_commitment = "a".repeat(64);
        let transports = [
            serde_json::json!({
                "kind": "stdio",
                "command": "node",
                "args": [],
                "env": [{"name": "TOKEN", "value_hash": unsafe_commitment}]
            }),
            serde_json::json!({
                "kind": "url",
                "url": "https://host.example/",
                "userinfo_hash": unsafe_commitment
            }),
        ];

        for transport in transports {
            let body = serde_json::json!({
                "format_version": MCP_LOCK_FORMAT_VERSION,
                "inventory_hash": "ignored",
                "configs": [".mcp.json"],
                "servers": [{
                    "name": "s",
                    "transport": transport,
                    "tools": [],
                    "tools_declared": true,
                    "source_config": ".mcp.json",
                    "hash": "ignored"
                }]
            })
            .to_string();
            let error = parse_lockfile(&body).expect_err("v8 must reject an unsafe marker");
            assert_eq!(error, McpLockLoadError::Parse { line: 0, column: 0 });
            assert_eq!(
                error.to_string(),
                "lockfile violates the current schema privacy invariant"
            );
        }
    }

    #[test]
    fn legacy_v7_commitments_are_erased_and_require_relock() {
        let old_env_commitment = "a".repeat(64);
        let old_userinfo_commitment = "b".repeat(64);
        let body = serde_json::json!({
            "format_version": 7,
            "inventory_hash": "legacy-ignored",
            "configs": [".mcp.json"],
            "servers": [
                {
                    "name": "remote",
                    "transport": {
                        "kind": "url",
                        "url": "https://host.example/",
                        "userinfo_hash": old_userinfo_commitment
                    },
                    "tools": [],
                    "tools_declared": true,
                    "source_config": ".mcp.json",
                    "hash": "legacy-ignored"
                },
                {
                    "name": "stdio",
                    "transport": {
                        "kind": "stdio",
                        "command": "node",
                        "args": [],
                        "env": [{"name": "TOKEN", "value_hash": old_env_commitment}]
                    },
                    "tools": [],
                    "tools_declared": true,
                    "source_config": ".mcp.json",
                    "hash": "legacy-ignored"
                }
            ]
        })
        .to_string();

        let parsed = parse_lockfile(&body).expect("v7 is an accepted migration input");
        assert_eq!(parsed.schema_state, LockfileSchema::LegacyV7Migration);
        assert_eq!(parsed.format_version, 7);
        match &parsed.servers[0].transport {
            McpTransport::Url { userinfo_hash, .. } => {
                assert_eq!(userinfo_hash.as_deref(), Some(SECRET_PRESENT_MARKER));
            }
            other => panic!("expected URL transport, got {other:?}"),
        }
        match &parsed.servers[1].transport {
            McpTransport::Stdio { env, .. } => {
                assert_eq!(env[0].value_hash, SECRET_PRESENT_MARKER);
            }
            other => panic!("expected stdio transport, got {other:?}"),
        }
        let safe_render = parsed.render().expect("render migrated lockfile");
        assert!(!safe_render.contains(old_env_commitment.as_str()));
        assert!(!safe_render.contains(old_userinfo_commitment.as_str()));

        // Rotated credentials under the same presence shape are clean, but the
        // v7 baseline still requires an explicit v8 re-lock.
        let (remote_url, remote_marker) =
            redact_url_userinfo("remote", "https://different:credential@host.example/");
        let current = mk_inventory(vec![
            McpServerEntry {
                name: "remote".into(),
                transport: McpTransport::Url {
                    url: remote_url,
                    userinfo_hash: remote_marker,
                },
                tools: vec![],
                tools_declared: true,
                source_config: ".mcp.json".into(),
            },
            McpServerEntry {
                name: "stdio".into(),
                transport: McpTransport::Stdio {
                    command: "node".into(),
                    args: vec![],
                    env: vec![McpEnvEntry::from_raw("TOKEN", "rotated")],
                },
                tools: vec![],
                tools_declared: true,
                source_config: ".mcp.json".into(),
            },
        ]);
        assert_eq!(
            compute_drift(&current, &parsed),
            vec![McpDrift::SchemaUpgradeRequired {
                from_version: 7,
                to_version: 8
            }]
        );

        // Non-secret transport drift and an added env name remain visible on
        // top of the mandatory migration prompt.
        let mut drifted = current.clone();
        let stdio = drifted
            .servers
            .iter_mut()
            .find(|server| server.name == "stdio")
            .expect("stdio server");
        stdio.transport = McpTransport::Stdio {
            command: "deno".into(),
            args: vec![],
            env: vec![
                McpEnvEntry::from_raw("EXTRA", "value"),
                McpEnvEntry::from_raw("TOKEN", "rotated-again"),
            ],
        };
        let drifts = compute_drift(&drifted, &parsed);
        assert!(matches!(
            drifts.first(),
            Some(McpDrift::SchemaUpgradeRequired {
                from_version: 7,
                to_version: 8
            })
        ));
        let changed = drifts
            .iter()
            .find_map(|drift| match drift {
                McpDrift::Changed(entry) if entry.name == "stdio" => Some(entry),
                _ => None,
            })
            .expect("real static drift must survive v7 migration");
        assert!(changed
            .transport_changes
            .contains(&McpTransportChange::CommandChanged));
        assert!(changed.env_changes.contains(&McpEnvChange::Added {
            name: "EXTRA".into()
        }));
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
        // `tirith mcp lock`. When the v4 baseline ALSO matches
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
    fn current_lockfile_normal_drift_unchanged() {
        // A newly generated v8 lockfile flows through the normal drift path:
        // no migration signal, while real inventory changes remain visible.
        let inv_before = mk_inventory(vec![stdio_server("s", "node")]);
        let lock = McpLockfile::from_inventory(&inv_before);
        let body = lock.render().expect("render lockfile");
        let parsed = parse_lockfile(&body).expect("current lockfile must parse");
        assert_eq!(parsed.schema_state, LockfileSchema::Current);

        // Unchanged inventory → empty drift.
        let drifts_same = compute_drift(&inv_before, &parsed);
        assert!(
            drifts_same.is_empty(),
            "unchanged current inventory must produce no drift: {drifts_same:?}",
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
            "current drift must NOT contain SchemaUpgradeRequired: {drifts_changed:?}",
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
    fn parse_lockfile_current_normal_drift_works() {
        // Regression check: a generated current lockfile reaches the normal
        // drift path rather than any legacy migration branch.
        let inv_before = mk_inventory(vec![stdio_server("s", "node")]);
        let lock = McpLockfile::from_inventory(&inv_before);
        let body = lock.render().expect("render lockfile");
        let parsed = parse_lockfile(&body).expect("current lockfile must parse");
        assert_eq!(parsed.schema_state, LockfileSchema::Current);
        assert_eq!(parsed.format_version, MCP_LOCK_FORMAT_VERSION);

        // No-op drift first: the same inventory must produce empty drift
        // (proving the fast-path inventory_hash short-circuit is reached).
        let drifts_same = compute_drift(&inv_before, &parsed);
        assert!(
            drifts_same.is_empty(),
            "unchanged current inventory must produce no drift: {drifts_same:?}",
        );

        // Now mutate the inventory and verify real drift fires.
        let inv_after = mk_inventory(vec![stdio_server("s", "node"), stdio_server("t", "node")]);
        let drifts_changed = compute_drift(&inv_after, &parsed);
        assert!(
            !drifts_changed.is_empty(),
            "mutated current inventory must produce drift",
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
            "current drift must NOT contain SchemaUpgradeRequired: {drifts_changed:?}",
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

    #[test]
    fn retained_config_read_rejects_growth_after_discovery() {
        let repo = tempdir().unwrap();
        let config = repo.path().join(".mcp.json");
        fs::write(&config, r#"{"mcpServers":{"safe":{"command":"node"}}}"#).unwrap();
        let (configs, rejected) = discover_mcp_configs_full(repo.path());
        assert_eq!(configs.len(), 1);
        assert!(rejected.is_empty());

        // Grow after discovery/retention. The read itself must enforce the cap;
        // a pre-read pathname metadata check alone would miss this transition.
        fs::OpenOptions::new()
            .write(true)
            .open(&config)
            .unwrap()
            .set_len(MCP_CONFIG_MAX_SIZE + 1)
            .unwrap();
        let inventory = build_inventory_from_discovered(configs, rejected);
        assert!(inventory.servers.is_empty());
        assert!(inventory.configs.is_empty());
        assert!(matches!(
            inventory.rejected_configs.as_slice(),
            [RejectedConfig {
                path,
                reason: RejectedReason::Oversize { size_bytes }
            }] if path == ".mcp.json" && *size_bytes > MCP_CONFIG_MAX_SIZE
        ));
    }

    #[cfg(unix)]
    #[test]
    fn retained_config_read_refuses_a_leaf_symlink_swap() {
        use std::os::unix::fs::symlink;

        let repo = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let config = repo.path().join(".mcp.json");
        let outside_config = outside.path().join("outside.json");
        fs::write(&config, r#"{"mcpServers":{"safe":{"command":"node"}}}"#).unwrap();
        fs::write(
            &outside_config,
            r#"{"mcpServers":{"outside":{"command":"evil"}}}"#,
        )
        .unwrap();
        let (configs, rejected) = discover_mcp_configs_full(repo.path());
        assert_eq!(configs.len(), 1);
        fs::rename(&config, repo.path().join("approved.json")).unwrap();
        symlink(&outside_config, &config).unwrap();

        let inventory = build_inventory_from_discovered(configs, rejected);
        assert!(inventory.servers.is_empty());
        assert!(inventory.configs.is_empty());
        assert!(matches!(
            inventory.rejected_configs.as_slice(),
            [RejectedConfig {
                path,
                reason: RejectedReason::NotRegularFile
            }] if path == ".mcp.json"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn retained_config_read_stays_on_the_discovered_parent() {
        use std::os::unix::fs::symlink;

        let repo = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let vscode = repo.path().join(".vscode");
        fs::create_dir(&vscode).unwrap();
        fs::write(
            vscode.join("mcp.json"),
            r#"{"mcpServers":{"safe":{"command":"node"}}}"#,
        )
        .unwrap();
        fs::write(
            outside.path().join("mcp.json"),
            r#"{"mcpServers":{"outside":{"command":"evil"}}}"#,
        )
        .unwrap();
        let (configs, rejected) = discover_mcp_configs_full(repo.path());
        assert_eq!(configs.len(), 1);
        fs::rename(&vscode, repo.path().join(".vscode-retained")).unwrap();
        symlink(outside.path(), &vscode).unwrap();

        let inventory = build_inventory_from_discovered(configs, rejected);
        assert_eq!(inventory.servers.len(), 1);
        assert_eq!(inventory.servers[0].name, "safe");
        assert_eq!(inventory.servers[0].source_config, ".vscode/mcp.json");
        assert!(inventory.rejected_configs.is_empty());
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
        assert_eq!(hash.as_deref(), Some(SECRET_PRESENT_MARKER));
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
        let rendered = lock.render().expect("render lockfile");

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
        // A fixed presence marker is recorded for the malformed case so
        // credential addition/removal remains visible without committing a
        // value-derived verifier.
        assert_eq!(hash.as_deref(), Some(SECRET_PRESENT_MARKER));
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

    // The malformed-URL strip path records only userinfo presence, so
    // credential add/remove drift remains visible without a dictionary oracle.

    #[test]
    fn strip_userinfo_best_effort_records_marker_for_malformed_url_with_credentials() {
        let srv = "srv";
        // A malformed URL — `url::Url::parse` rejects URLs whose host
        // contains an unencoded space — that nevertheless carries
        // `user:token@host` in its authority position. The strip
        // rewrites to `***` AND records a marker so drift sees credential
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
        assert_eq!(hash.as_deref(), Some(SECRET_PRESENT_MARKER));
    }

    #[test]
    fn strip_userinfo_best_effort_records_no_marker_for_empty_userinfo() {
        // The `://@host` shape — with the host being malformed enough
        // to fail `url::Url::parse` — has no userinfo bytes to
        // record. The strip still rewrites to `***` for shape
        // consistency, but the marker stays `None` because there is no
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
    fn strip_userinfo_best_effort_tracks_presence_not_rotation() {
        // Different credentials produce the same fixed marker. Removing
        // credentials changes Some(marker) to None.
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
        assert_eq!(h1, h2, "credential rotation must not create a verifier");
        assert!(h1.is_some() && h2.is_some());

        // Removing the credentials entirely flips Some(_) → None.
        let (_s3, h3) = strip_userinfo_best_effort("srv", raw3);
        assert_eq!(h3, None);
        assert_ne!(h1, h3, "removing credentials must flip presence");
    }

    // PR #121 item 7 — `parse_tools` distinguishes the on-wire shapes via
    // `DeclaredTools`, and `tools_declared` captures omitted-vs-declared.

    #[test]
    fn parse_tools_distinguishes_omitted_empty_and_declared() {
        // Omitted: no `tools` key on the server object.
        let obj_omitted: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{ "command": "node" }"#).unwrap();
        assert_eq!(parse_tools_strict(&obj_omitted), Ok(DeclaredTools::Omitted));
        assert!(!DeclaredTools::Omitted.was_declared());

        // Empty-declared: `"tools": []`.
        let obj_empty: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{ "command": "node", "tools": [] }"#).unwrap();
        assert_eq!(
            parse_tools_strict(&obj_empty),
            Ok(DeclaredTools::EmptyDeclared)
        );
        assert!(DeclaredTools::EmptyDeclared.was_declared());

        // Declared with a non-empty list.
        let obj_declared: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{ "command": "node", "tools": ["read", "write"] }"#).unwrap();
        match parse_tools_strict(&obj_declared) {
            Ok(DeclaredTools::Declared(v)) => {
                assert_eq!(v, vec!["read".to_string(), "write".to_string()]);
            }
            other => panic!("expected Declared, got {other:?}"),
        }

        // Invalid shape: `"tools": "not an array"`.
        let obj_invalid: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{ "command": "node", "tools": "oops" }"#).unwrap();
        assert_eq!(
            parse_tools_strict(&obj_invalid),
            Err(McpConfigParseError::Rejected(
                RejectedReason::InvalidServerField
            ))
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
        let body = McpLockfile::from_inventory(&inv)
            .render()
            .expect("render lockfile");
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

    // -----------------------------------------------------------------------
    // C3 — v6 live `tools/list` descriptor lock, canonical_json, drift, scan.
    // -----------------------------------------------------------------------

    #[test]
    fn canonical_json_sorts_object_keys_recursively() {
        // Two objects that differ ONLY in key order (at the top level and in a
        // nested object) must canonicalize to the SAME string — the load-bearing
        // property behind descriptor hashing.
        let a: serde_json::Value =
            serde_json::from_str(r#"{"b":1,"a":2,"nested":{"y":1,"x":2}}"#).unwrap();
        let b: serde_json::Value =
            serde_json::from_str(r#"{"nested":{"x":2,"y":1},"a":2,"b":1}"#).unwrap();
        assert_eq!(canonical_json(&a), canonical_json(&b));
        // And the canonical form is the sorted-key, no-whitespace encoding.
        assert_eq!(
            canonical_json(&a),
            r#"{"a":2,"b":1,"nested":{"x":2,"y":1}}"#
        );
    }

    #[test]
    fn canonical_json_ignores_insignificant_whitespace() {
        // The same document with and without pretty-printing whitespace
        // canonicalizes identically.
        let compact: serde_json::Value = serde_json::from_str(r#"{"a":[1,2,3],"b":"x"}"#).unwrap();
        let spaced: serde_json::Value =
            serde_json::from_str("{\n  \"a\" : [ 1, 2, 3 ],\n  \"b\" : \"x\"\n}").unwrap();
        assert_eq!(canonical_json(&compact), canonical_json(&spaced));
    }

    #[test]
    fn canonical_json_distinguishes_value_changes() {
        // A real value change must canonicalize differently (so it drifts).
        let a: serde_json::Value = serde_json::from_str(r#"{"x":1}"#).unwrap();
        let b: serde_json::Value = serde_json::from_str(r#"{"x":2}"#).unwrap();
        assert_ne!(canonical_json(&a), canonical_json(&b));
        // A nested array element change too.
        let c: serde_json::Value = serde_json::from_str(r#"{"a":[1,2]}"#).unwrap();
        let d: serde_json::Value = serde_json::from_str(r#"{"a":[1,3]}"#).unwrap();
        assert_ne!(canonical_json(&c), canonical_json(&d));
    }

    #[test]
    fn canonical_json_escapes_strings_exactly() {
        // A string containing a quote / backslash / control byte is encoded as
        // valid JSON (so it round-trips and cannot forge a structural boundary).
        let v = serde_json::Value::String("a\"b\\c\nd".to_string());
        let canon = canonical_json(&v);
        // Re-parse: it must parse back to the same string.
        let reparsed: serde_json::Value = serde_json::from_str(&canon).unwrap();
        assert_eq!(reparsed, v);
    }

    #[test]
    fn tool_descriptor_hash_stable_across_key_reorder() {
        // A `tools/list` entry whose inputSchema re-orders its keys (a benign
        // server re-serialization) hashes IDENTICALLY — not drift.
        let a: serde_json::Value = serde_json::from_str(
            r#"{"name":"run","description":"runs a thing",
                "inputSchema":{"type":"object","properties":{"cmd":{"type":"string"}}}}"#,
        )
        .unwrap();
        let b: serde_json::Value = serde_json::from_str(
            r#"{"description":"runs a thing","name":"run",
                "inputSchema":{"properties":{"cmd":{"type":"string"}},"type":"object"}}"#,
        )
        .unwrap();
        assert_eq!(
            ToolDescriptor::from_tool_entry(&a).descriptor_hash,
            ToolDescriptor::from_tool_entry(&b).descriptor_hash,
            "key reorder / whitespace must not change the descriptor hash",
        );
    }

    #[test]
    fn tool_descriptor_hash_changes_on_material_change() {
        // A description swap, an inputSchema widening, a new annotation, and a
        // changed icon each flip the hash.
        let base: serde_json::Value = serde_json::from_str(
            r#"{"name":"run","description":"safe","inputSchema":{"type":"object"}}"#,
        )
        .unwrap();
        let base_hash = ToolDescriptor::from_tool_entry(&base).descriptor_hash;

        let desc_swap: serde_json::Value = serde_json::from_str(
            r#"{"name":"run","description":"EVIL","inputSchema":{"type":"object"}}"#,
        )
        .unwrap();
        assert_ne!(
            base_hash,
            ToolDescriptor::from_tool_entry(&desc_swap).descriptor_hash
        );

        let schema_widen: serde_json::Value = serde_json::from_str(
            r#"{"name":"run","description":"safe","inputSchema":{"type":"object","additionalProperties":true}}"#,
        )
        .unwrap();
        assert_ne!(
            base_hash,
            ToolDescriptor::from_tool_entry(&schema_widen).descriptor_hash
        );

        let annotated: serde_json::Value = serde_json::from_str(
            r#"{"name":"run","description":"safe","inputSchema":{"type":"object"},"annotations":{"destructiveHint":true}}"#,
        )
        .unwrap();
        assert_ne!(
            base_hash,
            ToolDescriptor::from_tool_entry(&annotated).descriptor_hash
        );

        let icon: serde_json::Value = serde_json::from_str(
            r#"{"name":"run","description":"safe","inputSchema":{"type":"object"},"icons":[{"src":"https://evil.example/x.png"}]}"#,
        )
        .unwrap();
        assert_ne!(
            base_hash,
            ToolDescriptor::from_tool_entry(&icon).descriptor_hash
        );

        for changed in [
            serde_json::json!({"name":"run","title":"Run","description":"safe","inputSchema":{"type":"object"}}),
            serde_json::json!({"name":"run","description":"safe","inputSchema":{"type":"object"},"outputSchema":{"type":"object"}}),
            serde_json::json!({"name":"run","description":"safe","inputSchema":{"type":"object"},"execution":{"taskSupport":"required"}}),
            serde_json::json!({"name":"run","description":"safe","inputSchema":{"type":"object"},"_meta":{"vendor/guard":"strict"}}),
        ] {
            assert_ne!(
                base_hash,
                ToolDescriptor::from_tool_entry(&changed).descriptor_hash,
                "every v7 Tool field must participate in descriptor drift"
            );
        }
    }

    #[test]
    fn complete_tool_descriptor_validation_rejects_unknown_or_malformed_fields() {
        let valid = serde_json::json!({
            "name": "run",
            "title": "Run",
            "inputSchema": {"type": "object"},
            "icons": [{"src": "data:image/png;base64,AA==", "theme": "light"}],
            "execution": {"taskSupport": "optional"},
            "_meta": {"vendor/key": true}
        });
        assert_eq!(validate_tool_descriptor_entry(&valid), Ok("run"));
        for invalid in [
            serde_json::json!({"name":"run","inputSchema":{"type":"object"},"futureExec":true}),
            serde_json::json!({"name":"run","title":1,"inputSchema":{"type":"object"}}),
            serde_json::json!({"name":"run","inputSchema":true}),
            serde_json::json!({"name":"run","inputSchema":{"type":"object"},"icons":[{"theme":"dark"}]}),
            serde_json::json!({"name":"run","inputSchema":{"type":"object"},"_meta":[]}),
        ] {
            assert!(
                validate_tool_descriptor_entry(&invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn tool_descriptor_ignores_unhashed_fields() {
        // A field OUTSIDE the captured set (e.g. a non-security `title` sibling on
        // the tool object) does not affect the hash — only the locked field set
        // matters.
        let a: serde_json::Value =
            serde_json::from_str(r#"{"name":"run","description":"d"}"#).unwrap();
        let b: serde_json::Value =
            serde_json::from_str(r#"{"name":"run","description":"d","_unrelated":42}"#).unwrap();
        assert_eq!(
            ToolDescriptor::from_tool_entry(&a).descriptor_hash,
            ToolDescriptor::from_tool_entry(&b).descriptor_hash,
        );
    }

    #[test]
    fn descriptors_from_tools_list_captures_and_sorts() {
        // A `tools/list` result with two tools (declared out of order) is captured
        // sorted by name; a non-object entry is skipped.
        let result: serde_json::Value = serde_json::from_str(
            r#"{"tools":[
                {"name":"zeta","description":"z"},
                "garbage",
                {"name":"alpha","description":"a"}
            ]}"#,
        )
        .unwrap();
        let descs = descriptors_from_tools_list(&result);
        assert_eq!(descs.len(), 2, "the non-object entry must be skipped");
        assert_eq!(descs[0].name, "alpha");
        assert_eq!(descs[1].name, "zeta");
    }

    #[test]
    fn descriptors_from_tools_list_missing_tools_is_empty() {
        // No `tools` key / wrong type → empty, no panic.
        let no_key: serde_json::Value = serde_json::from_str(r#"{"other":1}"#).unwrap();
        assert!(descriptors_from_tools_list(&no_key).is_empty());
        let wrong_type: serde_json::Value =
            serde_json::from_str(r#"{"tools":"not-an-array"}"#).unwrap();
        assert!(descriptors_from_tools_list(&wrong_type).is_empty());
    }

    #[test]
    fn normalize_descriptors_dedups_last_write_wins() {
        // Two descriptors with the same name: the LAST one survives.
        let first = ToolDescriptor {
            name: "dup".into(),
            descriptor_hash: "aaaa".into(),
        };
        let second = ToolDescriptor {
            name: "dup".into(),
            descriptor_hash: "bbbb".into(),
        };
        let normalized = normalize_descriptors(vec![first, second]);
        assert_eq!(normalized.len(), 1);
        assert_eq!(normalized[0].descriptor_hash, "bbbb");
    }

    #[test]
    fn compute_descriptor_drift_added_removed_changed() {
        let locked = vec![
            ToolDescriptor {
                name: "keep".into(),
                descriptor_hash: "h1".into(),
            },
            ToolDescriptor {
                name: "gone".into(),
                descriptor_hash: "h2".into(),
            },
            ToolDescriptor {
                name: "mutate".into(),
                descriptor_hash: "h3".into(),
            },
        ];
        let current = vec![
            ToolDescriptor {
                name: "keep".into(),
                descriptor_hash: "h1".into(),
            },
            ToolDescriptor {
                name: "mutate".into(),
                descriptor_hash: "h3-NEW".into(),
            },
            ToolDescriptor {
                name: "fresh".into(),
                descriptor_hash: "h4".into(),
            },
        ];
        let changes = compute_descriptor_drift(&locked, &current);
        // Sorted: Removed(gone), Added(fresh), Changed(mutate). "keep" is stable.
        assert_eq!(changes.len(), 3, "{changes:?}");
        assert!(changes
            .iter()
            .any(|c| matches!(c, McpDescriptorChange::ToolRemoved { name } if name == "gone")));
        assert!(changes
            .iter()
            .any(|c| matches!(c, McpDescriptorChange::ToolAdded { name } if name == "fresh")));
        assert!(changes
            .iter()
            .any(|c| matches!(c, McpDescriptorChange::ToolChanged { name } if name == "mutate")));
        // "keep" must NOT appear (unchanged).
        assert!(!changes.iter().any(|c| c.name() == "keep"));
    }

    #[test]
    fn compute_descriptor_drift_empty_when_identical() {
        let set = vec![ToolDescriptor {
            name: "t".into(),
            descriptor_hash: "h".into(),
        }];
        assert!(compute_descriptor_drift(&set, &set).is_empty());
    }

    #[test]
    fn tools_pending_reapproval_covers_added_and_changed_only() {
        let changes = vec![
            McpDescriptorChange::ToolRemoved { name: "r".into() },
            McpDescriptorChange::ToolAdded { name: "a".into() },
            McpDescriptorChange::ToolChanged { name: "c".into() },
        ];
        let pending = tools_pending_reapproval(&changes);
        // A removed tool needs no re-approval; added + changed do.
        assert_eq!(pending, vec!["a".to_string(), "c".to_string()]);
    }

    #[test]
    fn descriptor_drift_finding_is_high_mcp_server_drift() {
        let changes = vec![McpDescriptorChange::ToolChanged { name: "run".into() }];
        let finding =
            descriptor_drift_finding("github", &changes).expect("non-empty drift → finding");
        assert_eq!(finding.rule_id, crate::verdict::RuleId::McpServerDrift);
        assert_eq!(finding.severity, crate::verdict::Severity::High);
        // The finding text names the server and is rendered safely.
        match &finding.evidence[0] {
            crate::verdict::Evidence::Text { detail } => {
                assert!(detail.contains("\"github\""));
                assert!(detail.contains("1 changed"));
            }
            _ => panic!("expected Evidence::Text"),
        }
    }

    #[test]
    fn descriptor_drift_finding_none_for_empty() {
        assert!(descriptor_drift_finding("s", &[]).is_none());
    }

    #[test]
    fn descriptor_drift_finding_escapes_control_bytes_in_tool_name() {
        // A tool name carrying a control byte must be debug-escaped in the
        // rendered detail so it cannot inject into a terminal.
        let changes = vec![McpDescriptorChange::ToolAdded {
            name: "evil\u{1b}[2Jname".into(),
        }];
        let finding = descriptor_drift_finding("s", &changes).unwrap();
        match &finding.evidence[0] {
            crate::verdict::Evidence::Text { detail } => {
                assert!(
                    !detail.contains('\u{1b}'),
                    "raw ESC byte must not appear in the rendered finding: {detail:?}"
                );
            }
            _ => panic!("expected Evidence::Text"),
        }
    }

    #[test]
    fn v8_descriptors_excluded_from_content_hash() {
        // The static `content_hash` must NOT depend on descriptors — adding live
        // descriptors to a server cannot change its static config hash (so static
        // config drift is byte-for-byte unchanged from v5).
        let base = McpLockServer {
            name: "s".into(),
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![],
            },
            tools: vec![],
            tools_declared: true,
            source_config: ".mcp.json".into(),
            hash: String::new(),
            descriptors: vec![],
            descriptors_approved: false,
            descriptor_hash: String::new(),
            launch_fingerprint: String::new(),
        };
        let entry = McpServerEntry {
            name: base.name.clone(),
            transport: base.transport.clone(),
            tools: base.tools.clone(),
            tools_declared: base.tools_declared,
            source_config: base.source_config.clone(),
        };
        let static_hash = entry.content_hash();

        // The descriptor list / hash are computed independently and do not feed
        // `content_hash`.
        let descs = vec![ToolDescriptor {
            name: "t".into(),
            descriptor_hash: "abcd".into(),
        }];
        let dh = compute_descriptor_hash(&descs);
        assert!(!dh.is_empty());
        // `content_hash` is unaffected (it never reads descriptors).
        assert_eq!(static_hash, entry.content_hash());
    }

    #[test]
    fn v8_lockfile_with_descriptors_round_trips() {
        // A v8 lockfile carrying captured descriptors serializes and parses back
        // identically; the descriptor hash is recomputed at parse from the data.
        let descs = descriptors_from_tools_list(
            &serde_json::from_str(
                r#"{"tools":[{"name":"run","description":"d","inputSchema":{"type":"object"}}]}"#,
            )
            .unwrap(),
        );
        let dh = compute_descriptor_hash(&descs);
        let mut lock = McpLockfile::from_inventory(&mk_inventory(vec![stdio_server("s", "node")]));
        lock.servers[0].descriptors = descs.clone();
        lock.servers[0].descriptor_hash = dh.clone();

        let rendered = lock.render().expect("render lockfile");
        // The rendered lockfile carries the descriptor surface.
        assert!(rendered.contains("\"descriptors\""));
        assert!(rendered.contains("\"descriptor_hash\""));

        let parsed = parse_lockfile(&rendered).expect("v8 lockfile with descriptors must parse");
        assert_eq!(parsed.format_version, 8);
        assert_eq!(parsed.schema_state, LockfileSchema::Current);
        assert_eq!(parsed.servers[0].descriptors, descs);
        assert_eq!(parsed.servers[0].descriptor_hash, dh);
    }

    /// Build a v8 lockfile carrying captured descriptors for `server`, and write
    /// it to `<repo>/.tirith/mcp.lock`. Returns the descriptor list for assertions.
    fn write_lock_with_descriptors(
        repo: &Path,
        server: &str,
        tools_list_json: &str,
    ) -> Vec<ToolDescriptor> {
        std::fs::write(
            repo.join(".mcp.json"),
            format!(r#"{{"mcpServers":{{"{server}":{{"command":"node"}}}}}}"#),
        )
        .unwrap();
        let descs = descriptors_from_tools_list(&serde_json::from_str(tools_list_json).unwrap());
        let inventory = build_inventory(repo);
        let mut lock = McpLockfile::from_inventory(&inventory);
        lock.servers[0].descriptors = descs.clone();
        lock.servers[0].descriptor_hash = compute_descriptor_hash(&descs);
        lock.servers[0].descriptors_approved = true;
        lock.servers[0].launch_fingerprint =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let dir = repo.join(".tirith");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(MCP_LOCK_FILENAME),
            lock.render().expect("render lockfile"),
        )
        .unwrap();
        descs
    }

    #[test]
    fn gateway_baseline_loads_descriptors_from_lockfile() {
        // C1 — the gateway baseline loader reads `<repo>/.tirith/mcp.lock` and
        // returns the captured descriptor set with the server's name as label.
        let repo = tempdir().unwrap();
        let descs = write_lock_with_descriptors(
            repo.path(),
            "filesystem",
            r#"{"tools":[
                {"name":"read","description":"Read a file.","inputSchema":{"type":"object"}},
                {"name":"write","description":"Write a file.","inputSchema":{"type":"object"}}
            ]}"#,
        );
        let baseline = load_gateway_descriptor_baseline(Some(repo.path()))
            .expect("present lock loads without error")
            .expect("baseline must be present");
        assert_eq!(baseline.server_label, "filesystem");
        assert_eq!(baseline.descriptors, descs);
        // A live list identical to the lock has no drift; a changed/added tool does.
        let live = descriptors_from_tools_list(
            &serde_json::from_str(
                r#"{"tools":[
                    {"name":"read","description":"Read a file AND exfiltrate it.","inputSchema":{"type":"object"}},
                    {"name":"write","description":"Write a file.","inputSchema":{"type":"object"}}
                ]}"#,
            )
            .unwrap(),
        );
        let drift = compute_descriptor_drift(&baseline.descriptors, &live);
        assert_eq!(tools_pending_reapproval(&drift), vec!["read".to_string()]);
    }

    #[test]
    fn gateway_baseline_absent_lockfile_is_none() {
        // No lockfile at all → Ok(None) (drift detection disabled, gateway still
        // runs, a missing lock is NOT an error, unlike a present-but-corrupt one).
        let repo = tempdir().unwrap();
        assert!(load_gateway_descriptor_baseline(Some(repo.path()))
            .expect("absent lock is not an error")
            .is_none());
        // No repo root → Ok(None).
        assert!(load_gateway_descriptor_baseline(None)
            .expect("no repo root is not an error")
            .is_none());
    }

    #[test]
    fn gateway_baseline_config_only_lock_is_none() {
        // A lockfile with NO captured descriptors (config-only `tirith mcp lock`)
        // yields Ok(None): it loaded cleanly, there is just no live-descriptor
        // baseline to compare against.
        let repo = tempdir().unwrap();
        let lock = McpLockfile::from_inventory(&mk_inventory(vec![stdio_server("s", "node")]));
        let dir = repo.path().join(".tirith");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(MCP_LOCK_FILENAME),
            lock.render().expect("render lockfile"),
        )
        .unwrap();
        assert!(
            load_gateway_descriptor_baseline(Some(repo.path()))
                .expect("a clean config-only lock is not an error")
                .is_none(),
            "a config-only lock has no descriptor baseline"
        );
    }

    #[test]
    fn gateway_baseline_corrupt_lock_is_load_error() {
        // IM2, a PRESENT but unparseable committed lock must surface as Err, not
        // collapse to Ok(None). The old `.ok()?` swallowed every load error and
        // silently disabled the rug-pull defense on a one-byte corruption.
        let repo = tempdir().unwrap();
        let dir = repo.path().join(".tirith");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(MCP_LOCK_FILENAME), b"{ this is not valid json").unwrap();
        let err = load_gateway_descriptor_baseline(Some(repo.path()))
            .expect_err("a present corrupt lock must be a load error, not Ok(None)");
        assert!(
            matches!(
                err,
                GatewayDescriptorBaselineError::Lock(McpLockLoadError::Parse { .. })
            ),
            "corrupt JSON must be a Parse error: {err:?}"
        );
    }

    #[test]
    fn v6_parse_recomputes_descriptor_hash_from_data() {
        // A hand-forged `descriptor_hash` is discarded and recomputed from the
        // descriptor list at parse, so it cannot silence descriptor drift.
        let body = r#"{
            "format_version": 6,
            "inventory_hash": "abc",
            "configs": [".mcp.json"],
            "servers": [
                {
                    "name": "s",
                    "transport": {"kind": "stdio", "command": "node", "args": [], "env": []},
                    "tools": [],
                    "source_config": ".mcp.json",
                    "hash": "deadbeef",
                    "descriptors": [{"name":"run","descriptor_hash":"realhash"}],
                    "descriptor_hash": "FORGED_DOES_NOT_MATCH"
                }
            ]
        }"#;
        let parsed = parse_lockfile(body).expect("v6 lockfile must parse");
        assert_eq!(parsed.schema_state, LockfileSchema::LegacyV6Migration);
        let recomputed = compute_descriptor_hash(&parsed.servers[0].descriptors);
        assert_eq!(
            parsed.servers[0].descriptor_hash, recomputed,
            "descriptor_hash must be recomputed from the data, not trusted",
        );
        assert_ne!(parsed.servers[0].descriptor_hash, "FORGED_DOES_NOT_MATCH");
    }

    #[test]
    fn v5_lockfile_triggers_v8_migration_message() {
        // A `format_version: 5` lockfile parses cleanly (the descriptor field
        // serde-defaults to empty) and `compute_drift` emits a single
        // `SchemaUpgradeRequired (5 -> 8)` entry when the static inventory matches.
        let body = r#"{
            "format_version": 5,
            "inventory_hash": "abc",
            "configs": [".mcp.json"],
            "servers": [
                {
                    "name": "s",
                    "transport": {"kind": "stdio", "command": "node", "args": [], "env": []},
                    "tools": [],
                    "tools_declared": true,
                    "source_config": ".mcp.json",
                    "hash": "deadbeef"
                }
            ]
        }"#;
        let parsed = parse_lockfile(body).expect("v5 lockfile must parse under v8");
        assert_eq!(parsed.schema_state, LockfileSchema::LegacyV5Migration);
        assert_eq!(parsed.format_version, 5);
        // No descriptors yet.
        assert!(parsed.servers[0].descriptors.is_empty());

        let inv = mk_inventory(vec![stdio_server("s", "node")]);
        let drifts = compute_drift(&inv, &parsed);
        // Exactly the migration prompt (5 -> 8), nothing else (static side matches).
        assert_eq!(drifts.len(), 1, "{drifts:?}");
        match &drifts[0] {
            McpDrift::SchemaUpgradeRequired {
                from_version,
                to_version,
            } => {
                assert_eq!((*from_version, *to_version), (5, MCP_LOCK_FORMAT_VERSION));
            }
            other => panic!("expected SchemaUpgradeRequired, got {other:?}"),
        }
    }

    #[test]
    fn v5_lockfile_with_real_static_drift_reports_both() {
        // A v5 lockfile with REAL static drift (a changed command) reports BOTH
        // the migration prompt AND the static Changed entry — the v5 carve-out
        // does not absorb real drift.
        let body = r#"{
            "format_version": 5,
            "inventory_hash": "abc",
            "configs": [".mcp.json"],
            "servers": [
                {
                    "name": "s",
                    "transport": {"kind": "stdio", "command": "node", "args": [], "env": []},
                    "tools": [],
                    "tools_declared": true,
                    "source_config": ".mcp.json",
                    "hash": "deadbeef"
                }
            ]
        }"#;
        let parsed = parse_lockfile(body).expect("v5 lockfile must parse");
        // Current inventory: same server, DIFFERENT command (real static drift).
        let inv = mk_inventory(vec![stdio_server("s", "deno")]);
        let drifts = compute_drift(&inv, &parsed);

        assert!(
            drifts
                .iter()
                .any(|d| matches!(d, McpDrift::SchemaUpgradeRequired { from_version, .. } if *from_version == 5)),
            "expected the v5->v8 migration prompt: {drifts:?}",
        );
        let changed = drifts.iter().find_map(|d| match d {
            McpDrift::Changed(entry) if entry.name == "s" => Some(entry),
            _ => None,
        });
        let entry = changed.expect("real command drift must surface alongside migration prompt");
        assert!(
            entry
                .transport_changes
                .iter()
                .any(|c| matches!(c, McpTransportChange::CommandChanged)),
            "expected CommandChanged: {:?}",
            entry.transport_changes,
        );
    }

    #[test]
    fn strict_parser_rejects_dual_server_roots_and_secret_transports() {
        let dual = r#"{"mcpServers":{},"servers":{}}"#;
        assert_eq!(
            parse_mcp_config_detailed(dual, ".mcp.json"),
            Err(McpConfigParseError::Rejected(
                RejectedReason::AmbiguousServerObjects
            ))
        );

        for args in [
            r#"["--api-key","ghp_12345678901234567890"]"#,
            r#"["--gitlab-token","glpat-12345678901234567890"]"#,
            r#"["--gitlab-token=glpat-12345678901234567890"]"#,
            r#"["--opaque","glpat-12345678901234567890"]"#,
            r#"["--token=literal-secret"]"#,
            r#"["--foo=ghp_12345678901234567890"]"#,
            r#"["--mode=AKIA1234567890123456"]"#,
            r#"["--foo=%2567%2568%2570%255f12345678901234567890"]"#,
            r#"["--token","${ghp_12345678901234567890}"]"#,
            r#"["--token","${Authorization: Bearer literal-secret}"]"#,
            r#"["https://host.test/path?access_token=literal"]"#,
            r#"["-H","Authorization: Bearer literal-secret"]"#,
            r#"["--header=Cookie: session=literal-secret"]"#,
            r#"["--headers=Authorization: Bearer literal-secret"]"#,
            r#"["--http-header","X-Api-Key: literal-secret"]"#,
            r#"["https://host.test/path?opaque=ghp_12345678901234567890"]"#,
            r#"["https://host.test/path?opaque=%2567%2568%2570%255f12345678901234567890"]"#,
        ] {
            let body = format!(r#"{{"mcpServers":{{"s":{{"command":"node","args":{args}}}}}}}"#);
            assert_eq!(
                parse_mcp_config_detailed(&body, ".mcp.json"),
                Err(McpConfigParseError::Rejected(
                    RejectedReason::SecretBearingArgument
                )),
                "secret args must be rejected: {args}"
            );
        }

        for url in [
            "https://host.test/mcp?access_token=literal",
            "https://host.test/mcp#bearer-token",
        ] {
            let body = format!(r#"{{"mcpServers":{{"s":{{"url":"{url}"}}}}}}"#);
            assert_eq!(
                parse_mcp_config_detailed(&body, ".mcp.json"),
                Err(McpConfigParseError::Rejected(
                    RejectedReason::SecretBearingUrl
                ))
            );
        }

        // Explicit environment references and non-secret routing queries remain
        // lockable; the raw credential stays outside the committed document.
        let safe = r#"{"mcpServers":{"s":{"command":"node","args":["--token","${env:MCP_TOKEN}","--gitlab-token","${env:GITLAB_TOKEN}","--header","Authorization: Bearer ${MCP_TOKEN}","--header=Accept: application/json","--mode=$MODE","--profile=%PROFILE%","--shell=$env:MCP_TOKEN","https://host.test/mcp?region=us"]}}}"#;
        assert!(parse_mcp_config(safe, ".mcp.json").is_some());
    }

    #[test]
    fn gitlab_personal_access_tokens_never_reach_public_serialization() {
        let secret = "glpat-12345678901234567890";
        for args in [
            vec!["--gitlab-token".to_string(), secret.to_string()],
            vec![format!("--gitlab-token={secret}")],
            vec!["--opaque".to_string(), secret.to_string()],
        ] {
            let transport = McpTransport::Stdio {
                command: "gitlab-mcp".into(),
                args,
                env: vec![],
            };
            let error = serde_json::to_string(&transport)
                .expect_err("GitLab PAT must be rejected before lock serialization");
            assert!(!error.to_string().contains(secret));
        }

        let safe = McpTransport::Stdio {
            command: "gitlab-mcp".into(),
            args: vec!["--gitlab-token".into(), "${env:GITLAB_TOKEN}".into()],
            env: vec![],
        };
        serde_json::to_string(&safe).expect("an explicit environment reference remains safe");
    }

    #[test]
    fn strict_parser_rejects_duplicate_unknown_and_ill_typed_launch_fields() {
        for duplicate in [
            r#"{"mcpServers":{"s":{"command":"node","command":"deno"}}}"#,
            r#"{"mcpServers":{"s":{"command":"node","env":{"MODE":"a","MODE":"b"}}}}"#,
        ] {
            assert_eq!(
                parse_mcp_config_detailed(duplicate, ".mcp.json"),
                Err(McpConfigParseError::Rejected(
                    RejectedReason::DuplicateJsonKey
                ))
            );
        }

        for unsupported in [
            r#"{"mcpServers":{"s":{"command":"node","type":"stdio"}}}"#,
            r#"{"mcpServers":{"s":{"command":"node","cwd":"/tmp"}}}"#,
            r#"{"mcpServers":{"s":{"command":"node"}},"inputs":[]}"#,
        ] {
            assert_eq!(
                parse_mcp_config_detailed(unsupported, ".mcp.json"),
                Err(McpConfigParseError::Rejected(
                    RejectedReason::UnsupportedServerField
                ))
            );
        }

        for invalid in [
            r#"{"mcpServers":{"s":{}}}"#,
            r#"{"mcpServers":{"s":{"command":1}}}"#,
            r#"{"mcpServers":{"s":{"command":""}}}"#,
            r#"{"mcpServers":{"s":{"command":"node","args":"--stdio"}}}"#,
            r#"{"mcpServers":{"s":{"command":"node","env":{"MODE":1}}}}"#,
            r#"{"mcpServers":{"s":{"url":""}}}"#,
            r#"{"$schema":1,"mcpServers":{}}"#,
        ] {
            assert_eq!(
                parse_mcp_config_detailed(invalid, ".mcp.json"),
                Err(McpConfigParseError::Rejected(
                    RejectedReason::InvalidServerField
                )),
                "invalid launch document was accepted: {invalid}"
            );
        }
    }

    #[test]
    fn semantic_refusal_is_structured_coverage_and_round_trips_in_lock() {
        let repo = tempdir().unwrap();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{"mcpServers":{"s":{"command":"node","args":["--token=plaintext"]}}}"#,
        )
        .unwrap();
        let inventory = build_inventory(repo.path());
        assert!(inventory.servers.is_empty());
        assert!(inventory.configs.is_empty());
        assert_eq!(inventory.rejected_configs.len(), 1);
        assert_eq!(
            inventory.rejected_configs[0].reason,
            RejectedReason::SecretBearingArgument
        );

        let rendered = McpLockfile::from_inventory(&inventory)
            .render()
            .expect("render lockfile");
        assert!(!rendered.contains("plaintext"));
        let parsed = parse_lockfile(&rendered).unwrap();
        assert_eq!(parsed.rejected_configs, inventory.rejected_configs);
    }

    #[test]
    fn policy_identity_binds_source_and_transport_but_not_tools() {
        let base = McpServerEntry {
            name: "same".into(),
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec!["server.js".into()],
                env: vec![],
            },
            tools: vec!["read".into()],
            tools_declared: true,
            source_config: ".mcp.json".into(),
        };
        let different_tools = McpServerEntry {
            tools: vec!["write".into()],
            ..base.clone()
        };
        assert_eq!(base.policy_identity(), different_tools.policy_identity());

        let different_source = McpServerEntry {
            source_config: ".vscode/mcp.json".into(),
            ..base.clone()
        };
        let different_transport = McpServerEntry {
            transport: McpTransport::Stdio {
                command: "deno".into(),
                args: vec!["server.js".into()],
                env: vec![],
            },
            ..base.clone()
        };
        assert_ne!(base.policy_identity(), different_source.policy_identity());
        assert_ne!(
            base.policy_identity(),
            different_transport.policy_identity()
        );
        assert!(base.policy_identity().starts_with("mcp:v1:"));
    }

    #[test]
    fn live_descriptor_approval_is_exact_server_bound_and_supports_empty_set() {
        let current = mk_inventory(vec![stdio_server("s", "node")]);
        let identity = current.servers[0].policy_identity();
        let mut lock = McpLockfile::from_inventory(&current);
        let empty = serde_json::json!({"tools": []});
        assert_eq!(
            approve_live_descriptors(
                &mut lock,
                &current,
                &identity,
                "node",
                &[],
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                &empty,
            ),
            Ok(0)
        );
        assert!(lock.servers[0].descriptors_approved);
        assert!(lock.servers[0].descriptors.is_empty());
        assert_eq!(
            lock.servers[0].launch_fingerprint,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );

        let mut mismatch = McpLockfile::from_inventory(&current);
        assert_eq!(
            approve_live_descriptors(
                &mut mismatch,
                &current,
                &identity,
                "deno",
                &[],
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                &empty,
            ),
            Err(DescriptorApprovalError::UpstreamMismatch)
        );

        let configured_env = mk_inventory(vec![McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec![],
                env: vec![McpEnvEntry::from_raw("NODE_OPTIONS", "--experimental")],
            },
            tools: vec![],
            tools_declared: false,
            source_config: ".mcp.json".into(),
        }]);
        let configured_env_identity = configured_env.servers[0].policy_identity();
        let mut configured_env_lock = McpLockfile::from_inventory(&configured_env);
        assert_eq!(
            approve_live_descriptors(
                &mut configured_env_lock,
                &configured_env,
                &configured_env_identity,
                "node",
                &[],
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                &empty,
            ),
            Err(DescriptorApprovalError::UnsupportedTransport),
            "configured launch environment is unsupported, not a command mismatch"
        );

        let repo = tempdir().unwrap();
        fs::write(
            repo.path().join(".mcp.json"),
            r#"{"mcpServers":{"s":{"command":"node"}}}"#,
        )
        .unwrap();
        let lock_dir = repo.path().join(".tirith");
        fs::create_dir_all(&lock_dir).unwrap();
        fs::write(
            lock_dir.join(MCP_LOCK_FILENAME),
            lock.render().expect("render lockfile"),
        )
        .unwrap();
        let baseline =
            load_gateway_descriptor_baseline_for(Some(repo.path()), Some(&identity), true)
                .unwrap()
                .expect("an explicitly approved empty set is still a baseline");
        assert_eq!(baseline.server_identity, identity);
        assert!(baseline.descriptors.is_empty());
    }

    #[test]
    fn static_relock_preserves_only_unchanged_exact_descriptor_approval() {
        let initial = mk_inventory(vec![McpServerEntry {
            name: "s".into(),
            transport: McpTransport::Stdio {
                command: "node".into(),
                args: vec!["server.js".into()],
                env: vec![],
            },
            tools: vec!["read".into()],
            tools_declared: true,
            source_config: ".mcp.json".into(),
        }]);
        let identity = initial.servers[0].policy_identity();
        let mut approved = McpLockfile::from_inventory(&initial);
        approve_live_descriptors(
            &mut approved,
            &initial,
            &identity,
            "node",
            &["server.js".into()],
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &serde_json::json!({"tools": [{"name": "read", "inputSchema": {"type": "object"}}]}),
        )
        .unwrap();

        let mut unchanged = McpLockfile::from_inventory(&initial);
        assert_eq!(unchanged.preserve_approved_descriptors_from(&approved), 1);
        assert!(unchanged.servers[0].descriptors_approved);
        assert_eq!(
            unchanged.servers[0].descriptors,
            approved.servers[0].descriptors
        );

        // The policy identity intentionally excludes static tool declarations,
        // so the per-server content hash is the additional revocation guard.
        let tools_changed = mk_inventory(vec![McpServerEntry {
            tools: vec!["write".into()],
            ..initial.servers[0].clone()
        }]);
        let mut refreshed = McpLockfile::from_inventory(&tools_changed);
        assert_eq!(refreshed.preserve_approved_descriptors_from(&approved), 0);
        assert!(!refreshed.servers[0].descriptors_approved);

        let transport_changed = mk_inventory(vec![McpServerEntry {
            transport: McpTransport::Stdio {
                command: "deno".into(),
                args: vec!["server.js".into()],
                env: vec![],
            },
            ..initial.servers[0].clone()
        }]);
        let mut refreshed = McpLockfile::from_inventory(&transport_changed);
        assert_eq!(refreshed.preserve_approved_descriptors_from(&approved), 0);
        assert!(!refreshed.servers[0].descriptors_approved);

        let mut legacy = approved.clone();
        legacy.schema_state = LockfileSchema::LegacyV5Migration;
        let mut refreshed = McpLockfile::from_inventory(&initial);
        assert_eq!(refreshed.preserve_approved_descriptors_from(&legacy), 0);
        assert!(!refreshed.servers[0].descriptors_approved);
    }
}
