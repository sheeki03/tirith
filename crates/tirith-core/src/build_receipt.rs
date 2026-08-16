//! Point-in-time build receipt: what one source tree and one output tree
//! contained, at one moment, on one machine (C18).
//!
//! # What this receipt is, and the honesty constraint that shapes it
//!
//! It records the exact bytes of two named trees and the surrounding facts that
//! were cheap to bind honestly: the commit, whether the working tree was dirty,
//! the lockfile digests, the policy projection hash, a redacted argv digest, and
//! the identity of the one external tool Tirith itself ran.
//!
//! It is NOT a reproducible-build claim. Tirith does not run the build, does not
//! observe the compiler, and cannot say the output was produced from the source.
//! Two receipts over the same source with different outputs are both perfectly
//! valid receipts. Every rendering surface and the receipt's own `caveats` field
//! say this, and [`BuildReceipt::validate`] refuses a receipt that dropped the
//! caveats.
//!
//! # Why the envelope is defined here
//!
//! The plan assigns a generic signed evidence envelope to a different slice
//! (`evidence_receipt.rs`, `EvidenceReceipt<T>`), which does not exist in this
//! tree. Rather than block, this module defines its own envelope with exactly
//! the field names and discipline the three shipped receipts already use
//! ([`crate::capsule_receipt::CapsuleRunReceipt`],
//! [`crate::browser_extensions::BrowserBaseline`],
//! [`crate::provenance::npm::NpmProvenanceReceipt`]): `schema`, `receipt_type`,
//! content-addressed `receipt_id`, `created_at`, `tirith_version`,
//! `engine_build_sha`, `policy_projection_hash`, `status`, `subject`,
//! `evidence`, `coverage`, `caveats`, `signature`, one canonicalizer
//! ([`crate::audit::canonical_json_for_hash`]), and one signing routine
//! ([`crate::audit::sign_canonical_bytes`]). A revived generic envelope should
//! absorb this type by substitution rather than growing a fourth copy.
//!
//! # Why it is not anchored in the audit hash chain
//!
//! The chain's receipt anchors are typed per receipt kind and mint their trust
//! capability by re-reading a receipt from a Tirith-owned directory under a
//! `0600` owner contract. A build receipt is written to an operator-chosen
//! `--out` path, which cannot satisfy that constructor, and widening a frozen
//! anchor contract belongs to the slice that owns it. So this schema is never
//! anchored, [`BuildCoverage::audit_chain_anchored`] is always `false`, and
//! [`BuildReceipt::validate`] refuses a receipt that claims otherwise. That is
//! the same call the browser-baseline and npm-provenance receipts made.
//!
//! # The tree digest
//!
//! [`scan_tree`] is the load-bearing primitive. It is modelled on the reviewed
//! `artifact::resolver::attest_pip_trees` binding (domain-separated prefix,
//! caps folded into the digest, sorted length-prefixed relative paths, mode,
//! size, no-follow open, post-open re-stat, exact-length read plus a one-byte
//! grow probe) but is cross-platform, built on
//! [`crate::util::open_read_no_follow_capped`] rather than raw `libc`, and adds
//! the case/Unicode collision check and the explicit exclusion set the build
//! surface needs.
//!
//! Every failure is a REFUSAL, never a skip. A digest over a tree that was
//! silently partial would be a receipt that says something false about bytes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::command_card::sha256_hex;
use crate::util::{open_read_no_follow_capped, HashOutcome, OpenRegularError};

/// Schema version of [`BuildReceipt`]. Bumped when a field is added or its
/// meaning changes.
pub const BUILD_RECEIPT_SCHEMA: u32 = 1;

/// Stable discriminator so a reader can tell this envelope from the capsule,
/// browser-baseline, npm-provenance, and deployment receipts that share the same
/// canonicalizer and directory.
pub const BUILD_RECEIPT_TYPE: &str = "attest_build";

/// Maximum files (and directories) one tree scan will bind. Refuses past this;
/// never truncates.
pub const MAX_TREE_FILES: usize = 100_000;

/// Maximum total file bytes one tree scan will hash. Refuses past this.
pub const MAX_TREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Maximum directory nesting a tree scan will descend. A deeper tree is a
/// resource-exhaustion shape, not a project.
pub const MAX_TREE_DEPTH: usize = 256;

/// Maximum BYTES of one normalized relative path. Bounded in bytes because the
/// bound exists to keep the serialized receipt small, and a path of multi-byte
/// scalars is several times longer than its character count.
pub const MAX_RELATIVE_PATH_BYTES: usize = 4096;

/// Maximum per-file output records carried in the receipt. The output manifest
/// is what `attest deployment` fetches from, so it is bounded independently of
/// the tree cap: a receipt is a document that gets mailed around.
pub const MAX_RECORDED_OUTPUT_FILES: usize = 4096;

/// Maximum bytes of a lockfile that will be digested.
pub const MAX_LOCKFILE_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum bytes of a tool image that will be digested for its identity.
pub const MAX_TOOL_IMAGE_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum bytes of a saved receipt that will be re-read. A receipt is a small
/// bounded record.
pub const MAX_BUILD_RECEIPT_BYTES: u64 = 16 * 1024 * 1024;

/// The directory (or submodule pointer file) pruned from SOURCE hashing at
/// EVERY depth, so a receipt binds the working tree rather than the object
/// store that can rewrite it.
///
/// It is a name rule rather than a path rule because a submodule carries its own
/// `.git` at an arbitrary depth. Applying it silently would make an entire class
/// of subtrees invisible to the digest, so [`scan_tree`] folds both the rule and
/// every path it actually pruned into the digest and returns them in
/// [`TreeScan::pruned`]. The OUTPUT tree runs under [`PrunedNames::None`]: build
/// output has no object store to protect a digest from, and a directory named
/// `.git` under it is shipped content like any other.
pub const GIT_METADATA_NAME: &str = ".git";

/// The honesty statement a build receipt may never be read without.
pub const NOT_A_REPRODUCIBILITY_CLAIM: &str =
    "this receipt records the bytes of one source tree and one output tree at one moment on one \
     machine; it is not a reproducible-build claim and does not prove the output was produced \
     from the source";

/// The second honesty statement: what running the build inside a capsule would
/// and would not add.
///
/// It names the SOURCE tree only. A capsule run builds inside an ephemeral copy
/// of the project and deletes that copy before it exits (`cli::capsule_run`
/// inventories the copy, then cleans it up, and confirmed cleanup is a
/// precondition of the contained status), so the bytes a contained run produced
/// never reach the operator's disk and can never be the `--output` tree this
/// receipt binds. Claiming the link covers both trees would be a claim no honest
/// pair of inputs can satisfy.
pub const EXECUTION_LINK_CAVEAT: &str =
    "tirith did not run the build; an execution link is verified only when a capsule run receipt \
     whose signature verifies against this installation's audit key binds THIS source tree to a \
     fully contained run whose child reached exit 0, and even then the contained run's own output \
     tree was ephemeral and is not the output tree this receipt binds";

/// Lockfile names digested from the source root, when present. A fixed list, so
/// the set of files a receipt binds is a property of the schema rather than of
/// whatever happened to be lying around.
pub const LOCKFILE_NAMES: &[&str] = &[
    "Cargo.lock",
    "Gemfile.lock",
    "Pipfile.lock",
    "bun.lockb",
    "composer.lock",
    "deno.lock",
    "go.sum",
    "npm-shrinkwrap.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "requirements.txt",
    "uv.lock",
    "yarn.lock",
];

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/// The answer a receipt carries, and the process exit code it maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestStatus {
    /// Everything the command set out to bind was bound.
    Clean,
    /// The command produced evidence but the evidence is incomplete. Never a
    /// claim that the incomplete part was fine.
    Partial,
    /// Something that was bound no longer matches, or a document failed its own
    /// integrity rules.
    Mismatch,
}

impl AttestStatus {
    /// Stable wire token, matching the serde spelling.
    pub fn token(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Partial => "partial",
            Self::Mismatch => "mismatch",
        }
    }

    /// The process exit code. Deliberately distinct from `tirith check`, which
    /// uses `3` for a warn acknowledgement; per-command codes in this repository
    /// are not shared, and every `attest` `after_help` says so.
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Clean => 0,
            Self::Mismatch => 1,
            Self::Partial => 3,
        }
    }

    /// Roll up two statuses, keeping the worse one. Mismatch outranks Partial,
    /// which outranks Clean.
    pub fn worst(self, other: Self) -> Self {
        match (self, other) {
            (Self::Mismatch, _) | (_, Self::Mismatch) => Self::Mismatch,
            (Self::Partial, _) | (_, Self::Partial) => Self::Partial,
            _ => Self::Clean,
        }
    }
}

// ---------------------------------------------------------------------------
// Tree scan
// ---------------------------------------------------------------------------

/// How permission bits are projected into the tree digest.
///
/// Recorded explicitly, and NOT folded into the digest tag, so a receipt taken
/// on one mode model and verified on another reports an honest Partial ("this
/// tree cannot be compared here") instead of a Mismatch that means nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModeModel {
    /// The unix permission bits, masked to `0o7777`.
    UnixPermissions,
    /// Windows has no permission bits, so the read-only attribute is projected
    /// onto `0o444` / `0o644`. A Windows digest is therefore comparable with
    /// another Windows digest and with nothing else.
    WindowsReadonly,
}

impl ModeModel {
    /// The model this build of Tirith produces.
    pub fn host() -> Self {
        if cfg!(unix) {
            Self::UnixPermissions
        } else {
            Self::WindowsReadonly
        }
    }

    /// Stable wire token, matching the serde spelling.
    pub fn token(self) -> &'static str {
        match self {
            Self::UnixPermissions => "unix_permissions",
            Self::WindowsReadonly => "windows_readonly",
        }
    }
}

/// The caps one scan ran under. Folded into the digest, so a digest taken under
/// looser caps can never be compared against one taken under tighter caps and
/// silently agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeLimits {
    pub max_files: usize,
    pub max_bytes: u64,
    pub max_depth: usize,
    pub max_path_bytes: usize,
}

impl Default for TreeLimits {
    fn default() -> Self {
        Self {
            max_files: MAX_TREE_FILES,
            max_bytes: MAX_TREE_BYTES,
            max_depth: MAX_TREE_DEPTH,
            max_path_bytes: MAX_RELATIVE_PATH_BYTES,
        }
    }
}

/// One regular file, as bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeFile {
    /// The `/`-normalized path relative to the scanned root.
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub mode: u32,
}

/// Which entry NAMES a scan prunes at every depth, on top of the path-relative
/// exclusion set.
///
/// Recorded per scan and folded into the digest, because the rule removes whole
/// subtrees: a digest taken with pruning on and one taken with it off describe
/// different sets of bytes and must never compare equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrunedNames {
    /// Nothing is pruned by name. What the OUTPUT tree runs under.
    None,
    /// [`GIT_METADATA_NAME`] at every depth. What the SOURCE tree runs under.
    GitMetadata,
}

impl PrunedNames {
    /// Stable token folded into the digest and rendered to an operator.
    pub fn token(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::GitMetadata => "git_metadata",
        }
    }

    fn prunes(self, name: &str) -> bool {
        match self {
            Self::None => false,
            Self::GitMetadata => name == GIT_METADATA_NAME,
        }
    }
}

/// The result of one complete tree scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeScan {
    pub digest: String,
    pub file_count: usize,
    pub directory_count: usize,
    pub total_bytes: u64,
    pub mode_model: ModeModel,
    pub limits: TreeLimits,
    pub exclusions: Vec<String>,
    /// Every path the name rule pruned, sorted. Folded into the digest and
    /// reported, so a pruned subtree can never be invisible in both the digest
    /// and the rendering at once.
    ///
    /// Bounded by construction: the rule can fire at most once per directory the
    /// walk descended into, and those directories are themselves entries under
    /// [`TreeLimits::max_files`].
    pub pruned: Vec<String>,
    pub files: Vec<TreeFile>,
}

impl TreeScan {
    /// The receipt-shaped projection: the digest plus its shape, without the
    /// per-file manifest.
    pub fn digest_record(&self) -> TreeDigest {
        TreeDigest {
            digest: self.digest.clone(),
            file_count: self.file_count,
            directory_count: self.directory_count,
            total_bytes: self.total_bytes,
            mode_model: self.mode_model,
        }
    }
}

/// The digest of one tree plus the shape that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeDigest {
    pub digest: String,
    pub file_count: usize,
    pub directory_count: usize,
    pub total_bytes: u64,
    pub mode_model: ModeModel,
}

/// Why a tree scan refused. There is no "skipped it" outcome: a silently
/// partial digest is the failure this type exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeScanError {
    /// The root does not exist, or is not a directory.
    RootUnusable(String),
    /// A symlink was found. Refused, never followed and never skipped, because
    /// a followed link digests bytes the root does not contain and a skipped
    /// one produces a digest that claims to cover a path it did not read.
    Symlink(String),
    /// An entry was neither a regular file nor a directory.
    UnsupportedEntry(String),
    /// A path component is not valid UTF-8, so it has no stable normalized
    /// spelling to sort, hash, or compare.
    NonUtf8Path(String),
    /// A normalized relative path exceeded the byte cap.
    PathTooLong(String),
    /// Two distinct paths share one case-folded, NFC-normalized, Win32-trimmed
    /// spelling. A tree that cannot round-trip through a case-insensitive or
    /// normalizing filesystem must not be bound as though it could.
    Collision { first: String, second: String },
    /// A file changed between the entry scan and the hash: rebound to another
    /// inode, grew, or was truncated.
    Changed(String),
    /// A cap was reached. The scan aborts rather than binding a prefix.
    CapExceeded(String),
    /// Any other read failure.
    Io(String),
}

impl std::fmt::Display for TreeScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RootUnusable(detail) => write!(f, "the tree root is unusable: {detail}"),
            Self::Symlink(path) => {
                write!(f, "refusing to bind a tree containing a symlink: {path}")
            }
            Self::UnsupportedEntry(path) => write!(
                f,
                "refusing to bind a tree containing a non-regular entry: {path}"
            ),
            Self::NonUtf8Path(path) => {
                write!(f, "refusing to bind a non-UTF-8 path under {path}")
            }
            Self::PathTooLong(path) => write!(f, "a relative path exceeds the byte cap: {path}"),
            Self::Collision { first, second } => write!(
                f,
                "two paths collide under case and Unicode normalization: {first} and {second}"
            ),
            Self::Changed(path) => write!(f, "{path} changed while it was being bound"),
            Self::CapExceeded(detail) => write!(f, "the tree exceeds a binding cap: {detail}"),
            Self::Io(detail) => write!(f, "the tree could not be read: {detail}"),
        }
    }
}

impl std::error::Error for TreeScanError {}

/// Domain-separation tag, so a build tree digest can never collide with the
/// capsule tree digest, the pip tree binding, or any other sha256 recorded here.
const TREE_DIGEST_TAG: &[u8] = b"tirith-build-tree-v1\0";

/// One entry as observed by the walk, before it is hashed.
struct WalkEntry {
    relative: String,
    path: PathBuf,
    directory: bool,
    mode: u32,
    size: u64,
    /// The filesystem identity the walk saw, re-checked through the open handle.
    /// `None` when the platform cannot report one from both sides.
    identity: Option<FileIdentity>,
}

/// The pair a scan compares to prove the handle it opened is the entry it
/// measured.
///
/// Unix reports `(st_dev, st_ino)`, which is exact identity. Windows has no
/// stable identity pair in std (`volume_serial_number` and `file_index` are both
/// behind the unstable `windows_by_handle` feature), so it reports the creation
/// and last-write timestamps instead: weaker, but still something a decoy inode
/// renamed over the name does not reproduce. Both sides are `Option` so a
/// platform that reports nothing is skipped rather than guessed at.
type FileIdentity = (u64, u64);

/// Bind `root` into a deterministic digest over sorted relative paths, modes,
/// sizes, and file contents.
///
/// `exclusions` are `/`-normalized paths relative to `root`; an excluded
/// directory prunes its whole subtree. `pruned` additionally removes whole
/// subtrees by entry NAME at every depth.
///
/// The exclusion set, the name rule, and every path that rule actually pruned
/// are ALL folded into the digest, so a digest cannot be reproduced under a
/// different removal set by accident and a pruned subtree cannot appear or
/// vanish without moving the digest.
pub fn scan_tree(
    root: &Path,
    exclusions: &[String],
    pruned: PrunedNames,
    limits: TreeLimits,
) -> Result<TreeScan, TreeScanError> {
    let metadata = std::fs::symlink_metadata(root)
        .map_err(|error| TreeScanError::RootUnusable(error.to_string()))?;
    if metadata.file_type().is_symlink() {
        return Err(TreeScanError::Symlink(root.display().to_string()));
    }
    if !metadata.is_dir() {
        return Err(TreeScanError::RootUnusable(
            "the tree root is not a directory".to_string(),
        ));
    }

    let mut normalized_exclusions: Vec<String> = exclusions
        .iter()
        .map(|value| value.trim_matches('/').to_string())
        .filter(|value| !value.is_empty())
        .collect();
    normalized_exclusions.sort();
    normalized_exclusions.dedup();

    // Precomputed once: the subtree prefix of every excluded directory. Built
    // outside the walk because the alternative formats a string per entry per
    // exclusion, and the walk runs up to a hundred thousand times.
    let exclusion_prefixes: Vec<String> = normalized_exclusions
        .iter()
        .map(|value| format!("{value}/"))
        .collect();

    let mut entries: Vec<WalkEntry> = Vec::new();
    let mut pruned_paths: Vec<String> = Vec::new();
    // Depth-first over an explicit stack, so a hostile tree bounds the retained
    // state by depth rather than by the widest directory.
    let mut pending: Vec<(String, PathBuf, usize)> = vec![(String::new(), root.to_path_buf(), 0)];
    while let Some((relative_dir, directory, depth)) = pending.pop() {
        let reader = std::fs::read_dir(&directory).map_err(|error| {
            TreeScanError::Io(format!("{}: {error}", display_relative(&relative_dir)))
        })?;
        for entry in reader {
            let entry = entry.map_err(|error| {
                TreeScanError::Io(format!("{}: {error}", display_relative(&relative_dir)))
            })?;
            let raw_name = entry.file_name();
            let Some(name) = raw_name.to_str() else {
                return Err(TreeScanError::NonUtf8Path(display_relative(&relative_dir)));
            };
            let relative = push_relative(&relative_dir, name);
            if pruned.prunes(name) {
                // Recorded rather than dropped: the digest folds this list, so a
                // subtree removed by the name rule still moves the digest when it
                // appears or disappears, and the scan can report what it removed.
                if relative.len() > limits.max_path_bytes {
                    return Err(TreeScanError::PathTooLong(relative));
                }
                pruned_paths.push(relative);
                continue;
            }
            if normalized_exclusions.contains(&relative)
                || exclusion_prefixes
                    .iter()
                    .any(|prefix| relative.starts_with(prefix.as_str()))
            {
                continue;
            }
            if relative.len() > limits.max_path_bytes {
                return Err(TreeScanError::PathTooLong(relative));
            }
            let path = directory.join(name);
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|error| TreeScanError::Io(format!("{relative}: {error}")))?;
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(TreeScanError::Symlink(relative));
            }
            if entries.len() >= limits.max_files {
                return Err(TreeScanError::CapExceeded(format!(
                    "more than {} entries",
                    limits.max_files
                )));
            }
            if file_type.is_dir() {
                if depth + 1 > limits.max_depth {
                    return Err(TreeScanError::CapExceeded(format!(
                        "deeper than {} directories at {relative}",
                        limits.max_depth
                    )));
                }
                entries.push(WalkEntry {
                    relative: relative.clone(),
                    path: path.clone(),
                    directory: true,
                    mode: mode_of(&metadata),
                    size: 0,
                    identity: identity_of(&metadata),
                });
                pending.push((relative, path, depth + 1));
                continue;
            }
            if !file_type.is_file() {
                return Err(TreeScanError::UnsupportedEntry(relative));
            }
            entries.push(WalkEntry {
                relative,
                path,
                directory: false,
                mode: mode_of(&metadata),
                size: metadata.len(),
                identity: identity_of(&metadata),
            });
        }
    }

    // Sorting by relative BYTES makes the digest independent of readdir order
    // and of any locale-sensitive comparison.
    entries.sort_by(|left, right| left.relative.as_bytes().cmp(right.relative.as_bytes()));

    // First-seen collision map. A case-insensitive or normalizing filesystem
    // merges these two names, so a digest that binds both is a digest of a tree
    // that cannot exist everywhere it claims to describe.
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for entry in &entries {
        let key = crate::artifact::archive::windows_collision_key(&entry.relative);
        if let Some(first) = seen.insert(key, entry.relative.clone()) {
            return Err(TreeScanError::Collision {
                first,
                second: entry.relative.clone(),
            });
        }
    }

    pruned_paths.sort();
    pruned_paths.dedup();

    let mode_model = ModeModel::host();
    let mut hasher = DigestBuilder::new(
        mode_model,
        limits,
        &normalized_exclusions,
        pruned,
        &pruned_paths,
    );
    let mut files = Vec::new();
    let mut file_count = 0usize;
    let mut directory_count = 0usize;
    let mut total_bytes = 0u64;
    for entry in &entries {
        hasher.entry_header(entry.directory, &entry.relative, entry.mode);
        if entry.directory {
            directory_count += 1;
            continue;
        }
        file_count += 1;
        total_bytes = total_bytes.saturating_add(entry.size);
        if total_bytes > limits.max_bytes {
            return Err(TreeScanError::CapExceeded(format!(
                "more than {} bytes",
                limits.max_bytes
            )));
        }
        let digest = hash_bound_file(entry, &mut hasher)?;
        files.push(TreeFile {
            path: entry.relative.clone(),
            sha256: digest,
            size: entry.size,
            mode: entry.mode,
        });
    }

    Ok(TreeScan {
        digest: hasher.finish(),
        file_count,
        directory_count,
        total_bytes,
        mode_model,
        limits,
        exclusions: normalized_exclusions,
        pruned: pruned_paths,
        files,
    })
}

/// Hash exactly the bytes the entry scan measured, refusing anything else.
///
/// Three separate races are closed here, and each one is a way a receipt could
/// otherwise bind bytes that were never in the tree:
///
/// - REBINDING: the handle is opened no-follow and then re-`stat`ed through the
///   OPEN handle, and the filesystem IDENTITY the walk recorded is compared
///   against the identity behind that handle. A name renamed onto a different
///   inode of the same length and the same mode has no other tell, so the
///   length and mode compares alone would accept it.
/// - GROWING: the open itself refuses a file already larger than the measured
///   size, the read stops at the measured size, and a one-byte probe past it
///   must return EOF.
/// - TRUNCATING: an early `read` of zero before the measured size is consumed is
///   a refusal, not a short digest.
fn hash_bound_file(entry: &WalkEntry, tree: &mut DigestBuilder) -> Result<String, TreeScanError> {
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;

    let mut handle = match open_read_no_follow_capped(&entry.path, entry.size) {
        Ok(handle) => handle,
        Err(OpenRegularError::NotFound) => {
            return Err(TreeScanError::Changed(entry.relative.clone()))
        }
        // `O_NOFOLLOW` maps a symlinked final component here, and a file that
        // grew past the measured size arrives as `TooLarge`. Both mean the entry
        // is not the thing the scan measured.
        Err(OpenRegularError::NotRegularFile) | Err(OpenRegularError::TooLarge) => {
            return Err(TreeScanError::Changed(entry.relative.clone()))
        }
        Err(OpenRegularError::Io(error)) => {
            return Err(TreeScanError::Io(format!("{}: {error}", entry.relative)))
        }
    };
    let opened = handle
        .metadata()
        .map_err(|error| TreeScanError::Io(format!("{}: {error}", entry.relative)))?;
    if !opened.is_file() || opened.len() != entry.size || mode_of(&opened) != entry.mode {
        return Err(TreeScanError::Changed(entry.relative.clone()));
    }
    // Compared only when BOTH sides reported one: on Windows std populates the
    // volume/index pair for some metadata sources and not others, and treating
    // "the platform did not say" as "the identity changed" would refuse honest
    // trees rather than rebound ones.
    if let (Some(walked), Some(opened)) = (entry.identity, identity_of(&opened)) {
        if walked != opened {
            return Err(TreeScanError::Changed(entry.relative.clone()));
        }
    }

    tree.size(entry.size);
    let mut file_hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut remaining = entry.size;
    while remaining > 0 {
        let read = handle
            .read(&mut buffer)
            .map_err(|error| TreeScanError::Io(format!("{}: {error}", entry.relative)))?;
        if read == 0 {
            return Err(TreeScanError::Changed(entry.relative.clone()));
        }
        let take = read.min(remaining as usize);
        tree.body(&buffer[..take]);
        file_hasher.update(&buffer[..take]);
        remaining -= take as u64;
        if take != read {
            return Err(TreeScanError::Changed(entry.relative.clone()));
        }
    }
    let mut extra = [0u8; 1];
    if handle
        .read(&mut extra)
        .map_err(|error| TreeScanError::Io(format!("{}: {error}", entry.relative)))?
        != 0
    {
        return Err(TreeScanError::Changed(entry.relative.clone()));
    }
    Ok(hex::encode(file_hasher.finalize()))
}

/// The streaming tree hasher. Every field is length-prefixed, so no two
/// different trees can serialize to the same byte sequence.
struct DigestBuilder {
    hasher: sha2::Sha256,
}

impl DigestBuilder {
    fn new(
        mode_model: ModeModel,
        limits: TreeLimits,
        exclusions: &[String],
        pruned: PrunedNames,
        pruned_paths: &[String],
    ) -> Self {
        use sha2::{Digest as _, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(TREE_DIGEST_TAG);
        let token = mode_model.token().as_bytes();
        hasher.update((token.len() as u64).to_be_bytes());
        hasher.update(token);
        hasher.update((limits.max_files as u64).to_be_bytes());
        hasher.update(limits.max_bytes.to_be_bytes());
        hasher.update((limits.max_depth as u64).to_be_bytes());
        hasher.update((limits.max_path_bytes as u64).to_be_bytes());
        let mut fold = |values: &[&str]| {
            hasher.update((values.len() as u64).to_be_bytes());
            for value in values {
                hasher.update((value.len() as u64).to_be_bytes());
                hasher.update(value.as_bytes());
            }
        };
        fold(&exclusions.iter().map(String::as_str).collect::<Vec<_>>());
        fold(&[pruned.token()]);
        fold(&pruned_paths.iter().map(String::as_str).collect::<Vec<_>>());
        Self { hasher }
    }

    fn entry_header(&mut self, directory: bool, relative: &str, mode: u32) {
        use sha2::Digest as _;
        self.hasher
            .update(if directory { b"D".as_slice() } else { b"F" });
        self.hasher.update((relative.len() as u64).to_be_bytes());
        self.hasher.update(relative.as_bytes());
        self.hasher.update(mode.to_be_bytes());
    }

    fn size(&mut self, size: u64) {
        use sha2::Digest as _;
        self.hasher.update(size.to_be_bytes());
    }

    fn body(&mut self, bytes: &[u8]) {
        use sha2::Digest as _;
        self.hasher.update(bytes);
    }

    fn finish(self) -> String {
        use sha2::Digest as _;
        hex::encode(self.hasher.finalize())
    }
}

#[cfg(unix)]
fn mode_of(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    metadata.permissions().mode() & 0o7777
}

/// The exact `(st_dev, st_ino)` pair, which two different inodes cannot share.
#[cfg(unix)]
fn identity_of(metadata: &std::fs::Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt as _;
    Some((metadata.dev(), metadata.ino()))
}

/// The creation and last-write timestamps.
///
/// Windows has no STABLE file-identity pair in std: `volume_serial_number` and
/// `file_index` are both behind the unstable `windows_by_handle` feature, and
/// this crate builds on stable. The timestamp pair is what is available, and it
/// is a weaker claim honestly made: a decoy inode renamed over the name carries
/// its own creation time, which the file the walk measured does not share.
#[cfg(windows)]
fn identity_of(metadata: &std::fs::Metadata) -> Option<FileIdentity> {
    use std::os::windows::fs::MetadataExt as _;
    Some((metadata.creation_time(), metadata.last_write_time()))
}

#[cfg(not(any(unix, windows)))]
fn identity_of(_metadata: &std::fs::Metadata) -> Option<FileIdentity> {
    None
}

#[cfg(not(unix))]
fn mode_of(metadata: &std::fs::Metadata) -> u32 {
    // Windows has no permission bits. Projecting the read-only attribute keeps
    // the digest sensitive to the one bit the platform does model, and
    // `ModeModel` records that this is what happened.
    if metadata.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

fn push_relative(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

fn display_relative(relative: &str) -> String {
    if relative.is_empty() {
        ".".to_string()
    } else {
        relative.to_string()
    }
}

// ---------------------------------------------------------------------------
// Surrounding facts
// ---------------------------------------------------------------------------

/// One lockfile, as bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockfileDigest {
    pub name: String,
    pub sha256: String,
    pub size: u64,
}

/// The external tool Tirith itself resolved and ran while assembling the
/// receipt. NOT the build's toolchain: Tirith does not run the build and has no
/// way to identify what did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolIdentity {
    /// The program NAME, never its path. A path names the operator's machine
    /// layout, and a receipt is a shareable document.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// The repository binding, when one could be established.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitBinding {
    /// The resolved `HEAD` commit, or `None` when git was unavailable or the
    /// root is not a repository. Never fabricated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Whether the working tree carried uncommitted or untracked changes.
    /// `None` means it could not be determined, which is not the same as clean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dirty: Option<bool>,
    /// Whether the scanned source root IS the repository root.
    ///
    /// `false` means the commit and the dirty flag describe a repository that
    /// CONTAINS the scanned tree rather than the scanned tree itself, which is
    /// what git reports from a subdirectory. Without this field a reader would
    /// take the commit as describing exactly the bytes that were digested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_is_repository_root: Option<bool>,
}

/// Digest the lockfiles present at `root`, in [`LOCKFILE_NAMES`] order.
pub fn scan_lockfiles(root: &Path) -> Vec<LockfileDigest> {
    let mut found = Vec::new();
    for name in LOCKFILE_NAMES {
        let path = root.join(name);
        let Ok(handle) = open_read_no_follow_capped(&path, MAX_LOCKFILE_BYTES) else {
            continue;
        };
        let Ok(size) = handle.metadata().map(|metadata| metadata.len()) else {
            continue;
        };
        if let Ok(HashOutcome::Digest(sha256)) =
            crate::util::sha256_from_handle(handle, MAX_LOCKFILE_BYTES)
        {
            found.push(LockfileDigest {
                name: (*name).to_string(),
                sha256,
                size,
            });
        }
    }
    found
}

/// Resolve `HEAD` and the dirty flag through the SAME hardened git envelope the
/// repository-hook inspector uses (`--no-pager`, `--no-replace-objects`, `-C`,
/// `core.hooksPath` redirected to null, no system config, no terminal prompt,
/// no credential helper, bounded time and output).
///
/// Replicating that envelope inline is a known failure mode in this repository,
/// which is why this calls the shared helper rather than building an argv.
pub fn capture_git_binding(root: &Path) -> GitBinding {
    let commit = crate::repo_hooks::run_trusted_git_bounded(
        root,
        &[
            "rev-parse".to_string(),
            "--verify".to_string(),
            "HEAD".to_string(),
        ],
        4096,
    )
    .ok()
    .and_then(|output| {
        if !output.success {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let looks_like_a_commit = (text.len() == 40 || text.len() == 64)
            && text.bytes().all(|byte| byte.is_ascii_hexdigit());
        looks_like_a_commit.then_some(text)
    });

    // Untracked files count as dirty: a build that consumed a file the commit
    // does not contain did not build the commit.
    let dirty = crate::repo_hooks::run_trusted_git_bounded(
        root,
        &["status".to_string(), "--porcelain".to_string()],
        1024 * 1024,
    )
    .ok()
    .and_then(|output| {
        output
            .success
            .then(|| !String::from_utf8_lossy(&output.stdout).trim().is_empty())
    });

    // Git answers from ANY directory inside a repository, so a `--source` that
    // is a subdirectory gets the containing repository's commit. That is git's
    // own semantics and it is not wrong, but a receipt that reported the commit
    // without reporting this would let a reader take the commit as describing
    // exactly the bytes that were digested.
    let source_is_repository_root = commit.as_ref().and(
        crate::repo_hooks::run_trusted_git_bounded(
            root,
            &["rev-parse".to_string(), "--show-toplevel".to_string()],
            64 * 1024,
        )
        .ok()
        .and_then(|output| {
            if !output.success {
                return None;
            }
            let top = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let top = std::fs::canonicalize(&top).ok()?;
            let source = std::fs::canonicalize(root).ok()?;
            Some(top == source)
        }),
    );

    GitBinding {
        commit,
        dirty,
        source_is_repository_root,
    }
}

/// Identify the one external tool this command runs. Returns an empty list when
/// no trusted git was available, rather than a fabricated entry.
pub fn capture_tool_identities() -> Vec<ToolIdentity> {
    let Some(path) = crate::repo_hooks::trusted_git_path() else {
        return Vec::new();
    };
    let sha256 = open_read_no_follow_capped(&path, MAX_TOOL_IMAGE_BYTES)
        .ok()
        .and_then(|handle| crate::util::sha256_from_handle(handle, MAX_TOOL_IMAGE_BYTES).ok())
        .and_then(|outcome| match outcome {
            HashOutcome::Digest(digest) => Some(digest),
            HashOutcome::BudgetExceeded => None,
        });
    vec![ToolIdentity {
        name: "git".to_string(),
        sha256,
    }]
}

/// Domain-separation tag for the redacted argv digest.
const ARGV_DIGEST_TAG: &[u8] = b"tirith-attest-argv-v1\0";

/// Digest the argv AFTER redaction, so a token passed on a build command line
/// cannot be recovered from the receipt and cannot be confirmed by hashing a
/// guess against it.
///
/// Redaction runs first and hashing second, in that order: hashing raw argv and
/// redacting the rendering would leave the secret bound into a durable digest.
pub fn redacted_argv_digest(argv: &[String]) -> (String, usize) {
    let mut payload: Vec<u8> = Vec::with_capacity(ARGV_DIGEST_TAG.len() + argv.len() * 16);
    payload.extend_from_slice(ARGV_DIGEST_TAG);
    payload.extend_from_slice((argv.len() as u64).to_be_bytes().as_slice());
    for element in argv {
        let redacted = crate::sensitive_assets::SensitiveAssetRegistry::redact(
            &crate::redact::redact_command_text(element, &[]),
        );
        payload.extend_from_slice((redacted.len() as u64).to_be_bytes().as_slice());
        payload.extend_from_slice(redacted.as_bytes());
    }
    (sha256_hex(&payload), argv.len())
}

// ---------------------------------------------------------------------------
// Signature trust
// ---------------------------------------------------------------------------

/// The ed25519 trust anchor a verification runs against.
///
/// Passed in rather than read from the environment at every call site, for the
/// reason the browser-baseline verifier gives: the content address and every
/// digest inside these receipts are recomputable by anyone with write access to
/// the file, so the signature is the only field a local attacker cannot forge,
/// and the anchor it is checked against has to be an explicit input a test can
/// hold still.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SignatureAnchor {
    /// The raw verifying key this installation trusts, when one is usable.
    pub verifying_key: Option<[u8; 32]>,
    /// Whether this installation is in signed mode. An unsigned document here is
    /// a STRIPPED signature, which is otherwise the cheapest forgery available.
    pub signing_expected: bool,
}

impl SignatureAnchor {
    /// The anchor this installation is configured with.
    pub fn installed() -> Self {
        Self {
            verifying_key: crate::audit::audit_verifying_key_bytes(),
            signing_expected: crate::audit::audit_signing_expected(),
        }
    }
}

/// What a receipt's signature field actually established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureTrust {
    /// A signature that verified against the installed audit key.
    Verified,
    /// No signature, on an installation that signs nothing. The document stands
    /// on its content address alone and every rendering says so.
    Unsigned,
    /// A signature is present but this installation has no usable key to check
    /// it with. An absence of evidence.
    Uncheckable,
    /// A signature that did not verify, or one that was stripped from an
    /// installation that signs. A positive statement that the document is not
    /// what it claims to be.
    Rejected,
}

impl SignatureTrust {
    /// Stable wire token, matching the serde spelling.
    pub fn token(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Unsigned => "unsigned",
            Self::Uncheckable => "uncheckable",
            Self::Rejected => "rejected",
        }
    }

    /// The status this trust level alone justifies.
    pub fn status(self) -> AttestStatus {
        match self {
            Self::Verified | Self::Unsigned => AttestStatus::Clean,
            Self::Uncheckable => AttestStatus::Partial,
            Self::Rejected => AttestStatus::Mismatch,
        }
    }
}

/// Classify one detached signature against the installed anchor, naming the
/// reason whenever the answer is anything but trusted.
///
/// `verifies` is a closure because the three receipt kinds carry the same
/// discipline over three different canonical payloads.
pub fn classify_signature(
    present: bool,
    verifies: impl FnOnce(&[u8; 32]) -> bool,
    anchor: SignatureAnchor,
    subject: &str,
) -> (SignatureTrust, Option<String>) {
    match (present, anchor.verifying_key) {
        (true, Some(key)) if verifies(&key) => (SignatureTrust::Verified, None),
        (true, Some(_)) => (
            SignatureTrust::Rejected,
            Some(format!(
                "the {subject} carries a signature that does not verify against the installed \
                 audit key; treat it as forged"
            )),
        ),
        (true, None) => (
            SignatureTrust::Uncheckable,
            Some(format!(
                "the {subject} is signed but no usable audit verifying key is installed, so the \
                 signature could not be checked"
            )),
        ),
        (false, _) if anchor.signing_expected => (
            SignatureTrust::Rejected,
            Some(format!(
                "the {subject} is unsigned but this installation signs its audit artifacts, so the \
                 signature was stripped"
            )),
        ),
        (false, _) => (SignatureTrust::Unsigned, None),
    }
}

// ---------------------------------------------------------------------------
// Execution link
// ---------------------------------------------------------------------------

/// Whether the linked capsule run receipt actually proves the build executed
/// under containment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionVerdict {
    /// A self-consistent, non-degraded capsule receipt whose signature VERIFIES
    /// binds this source tree and records a child that reached exit 0.
    Verified,
    /// Anything else, including no link at all. Purely observational: the
    /// recorded facts are still worth reading, but they prove nothing about
    /// where the build ran.
    Observed,
}

impl ExecutionVerdict {
    /// Stable wire token, matching the serde spelling.
    pub fn token(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Observed => "observed",
        }
    }
}

/// What the linked capsule receipt did and did not establish.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionLink {
    pub verdict: ExecutionVerdict,
    /// Whether a capsule receipt was asked for at all. Without it the honesty
    /// rules could not tell "no link was requested" (an ordinary build) from
    /// "a link was requested and did not stand up" (a finding).
    pub linked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule_signature: Option<SignatureTrust>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_exit_code: Option<i32>,
    /// Whether the capsule's held INPUT digest equals this source tree, in the
    /// capsule's own inventory format. `None` when it could not be compared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_digest_matches: Option<bool>,
    /// The capsule's held OUTPUT digest, recorded verbatim as an OBSERVATION.
    ///
    /// It is deliberately not compared against anything: it inventories the
    /// ephemeral project copy the contained run built in, and that copy is
    /// deleted before the run ends, so no directory on this machine can equal
    /// it. See [`EXECUTION_LINK_CAVEAT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule_output_digest: Option<String>,
    /// Every reason the verdict is not [`ExecutionVerdict::Verified`]. Empty
    /// when it is.
    pub reasons: Vec<String>,
}

impl Default for ExecutionLink {
    fn default() -> Self {
        Self {
            verdict: ExecutionVerdict::Observed,
            linked: false,
            capsule_receipt_id: None,
            capsule_status: None,
            capsule_signature: None,
            child_exit_code: None,
            input_digest_matches: None,
            capsule_output_digest: None,
            reasons: vec!["no capsule execution receipt was linked".to_string()],
        }
    }
}

/// The capsule-format inventory digest of the source tree an execution link is
/// compared against.
///
/// The capsule receipt records its held trees through
/// [`crate::capsule_project::inventory_project_tree`], which is a different
/// algorithm from [`scan_tree`] (it is deliberately tolerant, records symlink
/// and special-file markers, and excludes nothing). A link therefore cannot be
/// checked against the build tree digest directly; the comparison is made in the
/// capsule's own format, over the same directory.
///
/// `None` for an incomplete inventory: it hashes what it managed to read, and
/// equality against it would be an accident.
pub fn capsule_source_inventory(source: &Path) -> Option<String> {
    let tree = crate::capsule_project::inventory_project_tree(source);
    tree.complete.then_some(tree.digest)
}

/// Decide the execution verdict from a capsule run receipt.
///
/// Every requirement is checked, and every failed requirement is NAMED in
/// [`ExecutionLink::reasons`]. There is no short-circuit: an operator reading a
/// non-verified link should see all of what is missing, not the first thing.
///
/// The SIGNATURE is verified, not merely counted. Everything else in a capsule
/// receipt is recomputable by whoever can write the file: the content address
/// blanks the signature field on purpose, so a hand-written receipt that claims
/// a contained run and a zero exit reproduces its own `receipt_id` in twenty
/// lines. Presence alone would make the `verified` label obtainable from a file
/// no capsule ever produced.
pub fn evaluate_execution_link(
    capsule: &crate::capsule_receipt::CapsuleRunReceipt,
    source_inventory: Option<&str>,
    anchor: SignatureAnchor,
) -> ExecutionLink {
    use crate::capsule_receipt::{CapsuleRunDecision, CapsuleRunStatus};

    let mut reasons = Vec::new();
    if capsule.validate().is_err() {
        reasons.push("the capsule receipt failed its own integrity rules".to_string());
    }
    let (capsule_signature, signature_reason) = classify_signature(
        capsule.signature.is_some(),
        |key| capsule.signature_verifies(key),
        anchor,
        "capsule receipt",
    );
    if let Some(reason) = signature_reason {
        reasons.push(reason);
    }
    if capsule.status != CapsuleRunStatus::Contained {
        reasons.push(format!(
            "the capsule run status is {}, not contained",
            capsule.status.token()
        ));
    }
    if capsule
        .coverage
        .achieved
        .is_degraded_against(&capsule.coverage.requested)
    {
        reasons.push("the capsule run achieved less containment than it requested".to_string());
    }
    if !capsule.coverage.achieved.egress_claim_is_coherent() {
        reasons.push("the capsule run's egress coverage claim is incoherent".to_string());
    }
    if capsule.evidence.decision != CapsuleRunDecision::TargetCompleted {
        reasons.push(format!(
            "the capsule run decision is {}, so the target did not reach its own exit",
            capsule.evidence.decision.token()
        ));
    }
    if capsule.evidence.child_exit_code != Some(0) {
        reasons.push(match capsule.evidence.child_exit_code {
            Some(code) => format!("the contained child exited {code}"),
            None => "the capsule receipt records no child exit status".to_string(),
        });
    }

    let input_digest_matches = compare_capsule_input(
        capsule.subject.project_input.as_ref(),
        source_inventory,
        &mut reasons,
    );
    // Recorded, never compared: the capsule's output tree is the ephemeral copy
    // it built in, which no longer exists anywhere.
    let capsule_output_digest = capsule
        .subject
        .project_output
        .as_ref()
        .map(|tree| tree.digest.clone());
    if capsule_output_digest.is_none() {
        reasons.push("the capsule receipt records no output tree digest".to_string());
    }

    let verdict = if reasons.is_empty() {
        ExecutionVerdict::Verified
    } else {
        ExecutionVerdict::Observed
    };
    ExecutionLink {
        verdict,
        linked: true,
        capsule_receipt_id: Some(capsule.receipt_id.clone()),
        capsule_status: Some(capsule.status.token().to_string()),
        capsule_signature: Some(capsule_signature),
        child_exit_code: capsule.evidence.child_exit_code,
        input_digest_matches,
        capsule_output_digest,
        reasons,
    }
}

fn compare_capsule_input(
    recorded: Option<&crate::capsule_receipt::CapsuleTreeDigest>,
    local: Option<&str>,
    reasons: &mut Vec<String>,
) -> Option<bool> {
    let Some(recorded) = recorded else {
        reasons.push("the capsule receipt records no input tree digest".to_string());
        return None;
    };
    if !recorded.complete {
        reasons.push(
            "the capsule receipt's input tree digest covers less than the whole tree".to_string(),
        );
        return None;
    }
    let Some(local) = local else {
        reasons.push(
            "the source tree could not be inventoried in the capsule's format for comparison"
                .to_string(),
        );
        return None;
    };
    let matches = recorded.digest == local;
    if !matches {
        reasons.push(
            "the capsule receipt's input tree digest does not match this source tree".to_string(),
        );
    }
    Some(matches)
}

/// Read and parse a capsule run receipt from a bounded file.
pub fn load_capsule_receipt(
    path: &Path,
) -> Result<crate::capsule_receipt::CapsuleRunReceipt, String> {
    let bytes = crate::util::read_text_no_follow_capped(
        path,
        crate::capsule_receipt::MAX_CAPSULE_RECEIPT_BYTES as u64,
    )
    .map_err(|error| format!("the capsule receipt could not be read: {error:?}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("the capsule receipt is not a capsule run receipt: {error}"))
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

/// What the receipt binds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildSubject {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_tree: Option<TreeDigest>,
    /// The paths excluded from source hashing, recorded so the digest can be
    /// reproduced.
    pub source_exclusions: Vec<String>,
    /// Every path the `.git` name rule pruned from the source digest. Recorded
    /// rather than left implicit, so a reader can see which subtrees the source
    /// digest does not describe.
    #[serde(default)]
    pub source_pruned: Vec<String>,
    /// The output root as a path relative to the source root, when it is nested
    /// under it. `None` when the output tree is elsewhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_relative: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tree: Option<TreeDigest>,
    /// The paths excluded from OUTPUT hashing: the receipt destination, when it
    /// lands inside the output tree. The output scan prunes nothing by name, so
    /// this list is everything the output digest does not cover.
    #[serde(default)]
    pub output_exclusions: Vec<String>,
    /// The per-file output manifest. This is what `attest deployment` fetches
    /// from, so nothing outside it can ever be claimed as deployed.
    pub output_files: Vec<TreeFile>,
    /// Whether [`MAX_RECORDED_OUTPUT_FILES`] truncated the manifest. A truncated
    /// manifest can never carry a clean status.
    pub output_files_truncated: bool,
    #[serde(default)]
    pub git: GitBinding,
    pub lockfiles: Vec<LockfileDigest>,
    /// Digest of the REDACTED argv. The argument strings are never recorded.
    pub argv_digest: String,
    pub argv_len: usize,
}

/// What the run observed about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildEvidence {
    pub tools: Vec<ToolIdentity>,
    pub execution: ExecutionLink,
    /// The caps both scans ran under, so a reader can tell a small tree from a
    /// tree that was allowed to be small.
    pub limits: TreeLimits,
}

/// What was and was not accounted for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildCoverage {
    pub source_scanned: bool,
    pub output_scanned: bool,
    /// The refusal that stopped a scan, when one did. Present for every non-clean
    /// scan, so the coverage ledger names the gap rather than implying there is
    /// none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_refusal: Option<String>,
    /// Always `false` in this schema. See the module documentation: the audit
    /// chain's receipt anchors are typed per receipt kind and cannot accept an
    /// operator-chosen `--out` path, so this document is hash-chained to nothing
    /// and says so rather than implying tamper evidence it does not have.
    pub audit_chain_anchored: bool,
}

/// A content-addressed, optionally ed25519-signed build receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildReceipt {
    pub schema: u32,
    pub receipt_type: String,
    /// sha256 over the canonical JSON with `receipt_id` and `signature` blanked.
    pub receipt_id: String,
    pub created_at: String,
    pub tirith_version: String,
    pub engine_build_sha: String,
    /// [`crate::policy::Policy::security_projection_hash`], never the raw policy.
    pub policy_projection_hash: String,
    pub status: AttestStatus,
    pub subject: BuildSubject,
    pub evidence: BuildEvidence,
    pub coverage: BuildCoverage,
    /// The honesty statements this receipt may never be read without.
    pub caveats: Vec<String>,
    /// Whether a signature was produced. INSIDE the content address on purpose:
    /// the content hash blanks the signature field, so without this flag a
    /// signed receipt could be stripped of its signature and still pass its own
    /// integrity check as an unsigned one. With it, stripping is a mismatch.
    pub signature_present: bool,
    /// Base64 ed25519 signature over the canonical JSON with `signature`
    /// blanked, produced by the same key and routine as the audit chain.
    pub signature: Option<String>,
}

/// Everything [`BuildReceipt::new`] needs, grouped so the assembly site reads as
/// one record rather than a twelve-argument call.
#[derive(Debug, Clone)]
pub struct BuildReceiptFacts {
    pub policy_projection_hash: String,
    pub status: AttestStatus,
    pub subject: BuildSubject,
    pub evidence: BuildEvidence,
    pub coverage: BuildCoverage,
}

/// Why a receipt could not be assembled, trusted, or saved.
#[derive(Debug)]
pub enum BuildReceiptError {
    /// The receipt is not internally consistent. Raised before any write.
    Invalid(String),
    /// The document is not a build receipt at all.
    Malformed(String),
    /// Writing the receipt failed.
    Io(std::io::Error),
}

impl std::fmt::Display for BuildReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "refusing an invalid build receipt: {reason}"),
            Self::Malformed(reason) => write!(f, "not a build receipt: {reason}"),
            Self::Io(error) => write!(f, "build receipt I/O failed: {error}"),
        }
    }
}

impl std::error::Error for BuildReceiptError {}

impl BuildReceipt {
    /// Assemble, stamp the content address, and sign when a key is available.
    pub fn new(facts: BuildReceiptFacts) -> Self {
        let mut receipt = Self {
            schema: BUILD_RECEIPT_SCHEMA,
            receipt_type: BUILD_RECEIPT_TYPE.to_string(),
            receipt_id: String::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
            tirith_version: env!("CARGO_PKG_VERSION").to_string(),
            engine_build_sha: crate::receipt::engine_build_sha().to_string(),
            policy_projection_hash: facts.policy_projection_hash,
            status: facts.status,
            subject: facts.subject,
            evidence: facts.evidence,
            coverage: facts.coverage,
            caveats: vec![
                NOT_A_REPRODUCIBILITY_CLAIM.to_string(),
                EXECUTION_LINK_CAVEAT.to_string(),
            ],
            signature_present: false,
            signature: None,
        };
        // The signing attempt runs BEFORE the content address is stamped,
        // because `signature_present` is inside the address.
        let signature = {
            let mut probe = receipt.clone();
            probe.signature_present = true;
            probe.receipt_id = probe.compute_content_hash();
            crate::audit::sign_canonical_bytes(probe.signing_payload().as_bytes())
        };
        receipt.signature_present = signature.is_some();
        receipt.receipt_id = receipt.compute_content_hash();
        receipt.signature = signature;
        receipt
    }

    /// The canonical JSON the signature covers: the whole receipt with the
    /// signature blanked and the content address PRESENT, so the signature binds
    /// the content address rather than floating free of it.
    pub fn signing_payload(&self) -> String {
        self.canonical_json(false)
    }

    /// Lowercase-hex sha256 of the canonical JSON with `receipt_id` and
    /// `signature` blanked.
    pub fn compute_content_hash(&self) -> String {
        sha256_hex(self.canonical_json(true).as_bytes())
    }

    fn canonical_json(&self, blank_receipt_id: bool) -> String {
        let serialized = serde_json::to_value(self);
        debug_assert!(
            serialized.is_ok(),
            "build receipt failed to serialize; a field is not serializable"
        );
        let mut value = serialized.unwrap_or(serde_json::Value::Null);
        if let Some(object) = value.as_object_mut() {
            if blank_receipt_id {
                object.insert(
                    "receipt_id".to_string(),
                    serde_json::Value::String(String::new()),
                );
            }
            object.insert("signature".to_string(), serde_json::Value::Null);
        }
        crate::audit::canonical_json_for_hash(&value)
    }

    /// Whether the stored id still matches a recomputation over the content.
    pub fn content_hash_matches(&self) -> bool {
        self.receipt_id == self.compute_content_hash()
    }

    /// Verify the detached signature against an ed25519 public key. `false` for
    /// an absent, malformed, or non-verifying signature, so a caller cannot read
    /// "unsigned" as "verified".
    pub fn signature_verifies(&self, public_key: &[u8; 32]) -> bool {
        use base64::Engine as _;
        use ed25519_dalek::Verifier as _;

        let Some(encoded) = self.signature.as_deref() else {
            return false;
        };
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
            return false;
        };
        let Ok(signature) = ed25519_dalek::Signature::from_slice(&bytes) else {
            return false;
        };
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        key.verify(self.signing_payload().as_bytes(), &signature)
            .is_ok()
    }

    /// Every honesty invariant, checked before the receipt reaches a file.
    ///
    /// The load-bearing rule is the [`AttestStatus::Clean`] gate: a clean build
    /// receipt requires both trees to have been scanned in full, with an
    /// untruncated output manifest and no recorded refusal.
    pub fn validate(&self) -> Result<(), BuildReceiptError> {
        if self.schema != BUILD_RECEIPT_SCHEMA {
            return Err(BuildReceiptError::Invalid(format!(
                "unsupported build receipt schema {}",
                self.schema
            )));
        }
        if self.receipt_type != BUILD_RECEIPT_TYPE {
            return Err(BuildReceiptError::Malformed(
                "receipt_type is not a build receipt".to_string(),
            ));
        }
        if !self.content_hash_matches() {
            return Err(BuildReceiptError::Invalid(
                "receipt_id does not match the canonical receipt content".to_string(),
            ));
        }
        if self.signature_present != self.signature.is_some() {
            return Err(BuildReceiptError::Invalid(
                "the signature does not match what the signed content says about it".to_string(),
            ));
        }
        if self.coverage.audit_chain_anchored {
            return Err(BuildReceiptError::Invalid(
                "this schema is never audit-chain anchored, so it cannot claim to be".to_string(),
            ));
        }
        for required in [NOT_A_REPRODUCIBILITY_CLAIM, EXECUTION_LINK_CAVEAT] {
            if !self.caveats.iter().any(|caveat| caveat == required) {
                return Err(BuildReceiptError::Invalid(
                    "the receipt must carry its honesty caveats".to_string(),
                ));
            }
        }
        if self.evidence.execution.verdict == ExecutionVerdict::Verified
            && !self.evidence.execution.reasons.is_empty()
        {
            return Err(BuildReceiptError::Invalid(
                "a verified execution link cannot also record why it is not verified".to_string(),
            ));
        }
        if self.evidence.execution.verdict == ExecutionVerdict::Verified
            && !self.evidence.execution.linked
        {
            return Err(BuildReceiptError::Invalid(
                "a verified execution link requires a linked capsule receipt".to_string(),
            ));
        }
        // The manifest cap is a property of the schema, so a hand-written
        // document cannot carry a longer one and turn `attest deployment` into a
        // request amplifier.
        if self.subject.output_files.len() > MAX_RECORDED_OUTPUT_FILES {
            return Err(BuildReceiptError::Invalid(format!(
                "the output manifest carries {} entries, over the {MAX_RECORDED_OUTPUT_FILES} cap",
                self.subject.output_files.len()
            )));
        }
        if self.status == AttestStatus::Clean {
            if !self.coverage.source_scanned || !self.coverage.output_scanned {
                return Err(BuildReceiptError::Invalid(
                    "a clean receipt requires both trees to have been bound".to_string(),
                ));
            }
            if self.coverage.scan_refusal.is_some() {
                return Err(BuildReceiptError::Invalid(
                    "a clean receipt cannot record a scan refusal".to_string(),
                ));
            }
            if self.subject.output_files_truncated {
                return Err(BuildReceiptError::Invalid(
                    "a clean receipt cannot carry a truncated output manifest".to_string(),
                ));
            }
            if self.subject.source_tree.is_none() || self.subject.output_tree.is_none() {
                return Err(BuildReceiptError::Invalid(
                    "a clean receipt requires both tree digests".to_string(),
                ));
            }
            // An operator who asked for a containment link and did not get one
            // learned something, and the exit code has to carry it.
            if self.evidence.execution.linked
                && self.evidence.execution.verdict != ExecutionVerdict::Verified
            {
                return Err(BuildReceiptError::Invalid(
                    "a clean receipt cannot carry an execution link that is not verified"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Serialize for publication.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Parse and validate a build receipt document.
    pub fn parse(text: &str) -> Result<Self, BuildReceiptError> {
        let receipt: Self = serde_json::from_str(text)
            .map_err(|error| BuildReceiptError::Malformed(error.to_string()))?;
        receipt.validate()?;
        Ok(receipt)
    }

    /// Read, parse, and validate a build receipt from a bounded file.
    pub fn load(path: &Path) -> Result<Self, BuildReceiptError> {
        let receipt = Self::load_unvalidated(path)?;
        receipt.validate()?;
        Ok(receipt)
    }

    /// Read and parse without validating.
    ///
    /// Kept separate so a caller can tell "this file is not a build receipt at
    /// all" (an input error the operator must fix) from "this build receipt no
    /// longer stands up" (a finding the receipt itself must record). Collapsing
    /// the two would report a tampered receipt as a typo.
    pub fn load_unvalidated(path: &Path) -> Result<Self, BuildReceiptError> {
        let bytes = crate::util::read_text_no_follow_capped(path, MAX_BUILD_RECEIPT_BYTES)
            .map_err(|error| BuildReceiptError::Malformed(format!("{error:?}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| BuildReceiptError::Malformed(error.to_string()))
    }

    /// Validate, then write the receipt atomically at mode 0600.
    pub fn write_to(&self, path: &Path) -> Result<(), BuildReceiptError> {
        self.validate()?;
        crate::util::write_file_atomic_0600(path, self.to_json().as_bytes())
            .map_err(BuildReceiptError::Io)
    }
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

/// Everything `tirith attest build` was asked to bind.
#[derive(Debug, Clone)]
pub struct BuildRequest {
    pub source: PathBuf,
    pub output: PathBuf,
    /// Extra source-relative paths to exclude, on top of the output root. The
    /// receipt destination goes here when it lands under the source.
    pub extra_exclusions: Vec<String>,
    /// Extra OUTPUT-relative paths to exclude. The receipt destination goes here
    /// when it lands under the output tree.
    pub extra_output_exclusions: Vec<String>,
    pub execution_receipt: Option<PathBuf>,
    pub argv: Vec<String>,
    pub limits: TreeLimits,
}

/// Bind both trees and assemble the receipt.
///
/// Ordering matters: each tree is scanned with the receipt destination
/// EXPLICITLY excluded, and the source additionally with the output root
/// excluded, so a receipt can never hash itself into existence and a source
/// digest never silently absorbs build output.
///
/// The receipt destination is excluded from BOTH trees, not only the source. The
/// receipt is written after the scan, so an `--out` inside the output tree would
/// otherwise be absent at measurement time and present at every later
/// verification, and `verify-build` would report a tree that nobody touched as
/// changed.
pub fn build_receipt(request: &BuildRequest, policy_projection_hash: String) -> BuildReceipt {
    let mut refusals: Vec<String> = Vec::new();
    let output_relative = relative_under(&request.source, &request.output);

    let mut exclusions: Vec<String> = Vec::new();
    if let Some(relative) = output_relative.clone() {
        exclusions.push(relative);
    }
    exclusions.extend(request.extra_exclusions.iter().cloned());
    let output_exclusions = request.extra_output_exclusions.clone();

    let source_scan = match scan_tree(
        &request.source,
        &exclusions,
        PrunedNames::GitMetadata,
        request.limits,
    ) {
        Ok(scan) => Some(scan),
        Err(error) => {
            refusals.push(format!("source: {error}"));
            None
        }
    };
    // The output tree prunes nothing by name: a directory called `.git` under
    // build output is shipped content, and dropping it would leave bytes the
    // receipt says nothing about inside a tree it calls bound.
    let output_scan = match scan_tree(
        &request.output,
        &output_exclusions,
        PrunedNames::None,
        request.limits,
    ) {
        Ok(scan) => Some(scan),
        Err(error) => {
            refusals.push(format!("output: {error}"));
            None
        }
    };

    let mut output_files = Vec::new();
    let mut output_files_truncated = false;
    if let Some(scan) = output_scan.as_ref() {
        output_files_truncated = scan.files.len() > MAX_RECORDED_OUTPUT_FILES;
        output_files = scan
            .files
            .iter()
            .take(MAX_RECORDED_OUTPUT_FILES)
            .cloned()
            .collect();
        if output_files_truncated {
            refusals.push(format!(
                "output: the manifest was truncated at {MAX_RECORDED_OUTPUT_FILES} files"
            ));
        }
    }

    let anchor = SignatureAnchor::installed();
    let execution = match request.execution_receipt.as_deref() {
        None => ExecutionLink::default(),
        Some(path) => match load_capsule_receipt(path) {
            Ok(capsule) => evaluate_execution_link(
                &capsule,
                capsule_source_inventory(&request.source).as_deref(),
                anchor,
            ),
            Err(reason) => ExecutionLink {
                linked: true,
                reasons: vec![reason],
                ..ExecutionLink::default()
            },
        },
    };

    let (argv_digest, argv_len) = redacted_argv_digest(&request.argv);
    // A link that was asked for and did not stand up is exactly what the
    // `--execution-receipt` contract promises to report as partial. Deriving the
    // status only from the tree scans would hand a CI gate exit 0 over a capsule
    // receipt for a different project.
    let execution_unproven = execution.linked && execution.verdict != ExecutionVerdict::Verified;
    let status = if refusals.is_empty() && !execution_unproven {
        AttestStatus::Clean
    } else {
        AttestStatus::Partial
    };
    let scan_refusal = (!refusals.is_empty()).then(|| refusals.join("; "));

    BuildReceipt::new(BuildReceiptFacts {
        policy_projection_hash,
        status,
        subject: BuildSubject {
            source_tree: source_scan.as_ref().map(TreeScan::digest_record),
            source_exclusions: source_scan
                .as_ref()
                .map(|scan| scan.exclusions.clone())
                .unwrap_or(exclusions),
            source_pruned: source_scan
                .as_ref()
                .map(|scan| scan.pruned.clone())
                .unwrap_or_default(),
            output_relative,
            output_tree: output_scan.as_ref().map(TreeScan::digest_record),
            output_exclusions: output_scan
                .as_ref()
                .map(|scan| scan.exclusions.clone())
                .unwrap_or(output_exclusions),
            output_files,
            output_files_truncated,
            git: capture_git_binding(&request.source),
            lockfiles: scan_lockfiles(&request.source),
            argv_digest,
            argv_len,
        },
        evidence: BuildEvidence {
            tools: capture_tool_identities(),
            execution,
            limits: request.limits,
        },
        coverage: BuildCoverage {
            source_scanned: source_scan.is_some(),
            output_scanned: output_scan.is_some(),
            scan_refusal,
            audit_chain_anchored: false,
        },
    })
}

/// The `/`-normalized path of `child` relative to `parent`, when `child` really
/// resolves inside `parent`.
///
/// Canonicalizes BOTH sides first: symlinks are the bug path here, and a textual
/// `starts_with` on uncanonicalized paths would mistake `../source/dist` for an
/// unrelated tree, or miss a `dist` symlinked out of the source entirely.
///
/// `child` need not exist yet. The receipt destination is the reason: it is
/// excluded from the source scan precisely so it cannot hash itself into
/// existence, and at that point it has not been written.
///
/// The FINAL component is never resolved through a symlink. An operator who
/// points `--out` at a planted symlink still gets the LINK's own path excluded,
/// because that is the path the atomic rename publishes the receipt at; resolving
/// the link would exclude the attacker's chosen target instead and leave the
/// receipt inside its own source digest.
pub fn relative_under(parent: &Path, child: &Path) -> Option<String> {
    let parent = std::fs::canonicalize(parent).ok()?;
    let resolved = match (child.parent(), child.file_name()) {
        (child_parent, Some(name)) => {
            // A bare relative file name has an EMPTY parent, which canonicalizes
            // to nothing. That is the ordinary spelling of the receipt
            // destination (`--out build.receipt.json`).
            let base = match child_parent {
                Some(base) if !base.as_os_str().is_empty() => base,
                _ => Path::new("."),
            };
            std::fs::canonicalize(base).ok()?.join(name)
        }
        // No file name at all (`.`, `..`, a bare root): there is no final
        // component to protect, so resolve the whole thing.
        _ => std::fs::canonicalize(child).ok()?,
    };
    let relative = resolved.strip_prefix(&parent).ok()?;
    let text = relative.to_str()?;
    if text.is_empty() {
        return None;
    }
    Some(text.replace(std::path::MAIN_SEPARATOR, "/"))
}

// ---------------------------------------------------------------------------
// verify-build
// ---------------------------------------------------------------------------

/// The answer `tirith attest verify-build` produces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildVerification {
    pub status: AttestStatus,
    pub receipt_id: String,
    /// What the signature established, never merely whether one is present. A
    /// forged document with a junk signature must not read as the stronger
    /// document.
    pub signature: SignatureTrust,
    /// Every reason the answer is not clean. Empty when it is.
    pub findings: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_digest: Option<String>,
    /// What the receipt's own rules removed from each digest, surfaced so an
    /// exclusion set wide enough to swallow a whole tree is visible in the
    /// answer rather than only in the document.
    pub source_exclusions: Vec<String>,
    pub output_exclusions: Vec<String>,
    /// How many files each compared digest actually covers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_files: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_files: Option<usize>,
}

/// Re-bind both trees and compare them against the receipt.
///
/// The receipt supplies the caps, the exclusion set, and the mode model, so the
/// comparison is made under the same rules the original binding used. A mode
/// model this host cannot reproduce is a Partial (the trees cannot be compared
/// here), never a Mismatch (which would read as "the bytes changed").
///
/// The SIGNATURE is checked against `anchor` before anything else is believed.
/// Every other field, `receipt_id` included, is a keyless sha256 that whoever
/// can write the file can recompute, so a comparison that skipped the signature
/// would be a comparison against numbers the attacker chose.
pub fn verify_build(
    receipt: &BuildReceipt,
    source: &Path,
    output: &Path,
    anchor: SignatureAnchor,
) -> BuildVerification {
    let mut findings = Vec::new();
    let (signature, signature_reason) = classify_signature(
        receipt.signature.is_some(),
        |key| receipt.signature_verifies(key),
        anchor,
        "build receipt",
    );
    if let Some(reason) = signature_reason {
        findings.push(reason);
    }
    let mut status = signature.status();

    if let Err(error) = receipt.validate() {
        findings.push(error.to_string());
        return BuildVerification {
            status: status.worst(AttestStatus::Mismatch),
            receipt_id: receipt.receipt_id.clone(),
            signature,
            findings,
            source_digest: None,
            output_digest: None,
            source_exclusions: receipt.subject.source_exclusions.clone(),
            output_exclusions: receipt.subject.output_exclusions.clone(),
            source_files: None,
            output_files: None,
        };
    }

    let limits = receipt.evidence.limits;

    let (source_digest, source_status) = compare_tree_against(
        receipt.subject.source_tree.as_ref(),
        source,
        &receipt.subject.source_exclusions,
        PrunedNames::GitMetadata,
        limits,
        "source",
        &mut findings,
    );
    status = status.worst(source_status);
    let (output_digest, output_status) = compare_tree_against(
        receipt.subject.output_tree.as_ref(),
        output,
        &receipt.subject.output_exclusions,
        PrunedNames::None,
        limits,
        "output",
        &mut findings,
    );
    status = status.worst(output_status);

    // A receipt that was itself Partial cannot verify clean: the thing it failed
    // to bind is still unbound.
    if receipt.status != AttestStatus::Clean {
        findings.push(format!(
            "the receipt itself is {}, so this comparison covers only what it bound",
            receipt.status.token()
        ));
        status = status.worst(AttestStatus::Partial);
    }

    BuildVerification {
        status,
        receipt_id: receipt.receipt_id.clone(),
        signature,
        findings,
        source_digest,
        output_digest,
        source_exclusions: receipt.subject.source_exclusions.clone(),
        output_exclusions: receipt.subject.output_exclusions.clone(),
        source_files: receipt.subject.source_tree.as_ref().map(|t| t.file_count),
        output_files: receipt.subject.output_tree.as_ref().map(|t| t.file_count),
    }
}

/// Re-scan one tree and compare it with what the receipt recorded.
///
/// Returns the freshly computed digest (when one could be computed) and the
/// status this comparison alone justifies. A tree that could not be re-scanned
/// is Partial, never Mismatch: "I could not read it" and "the bytes changed"
/// are different claims and an operator acts on them differently.
#[allow(clippy::too_many_arguments)]
fn compare_tree_against(
    expected: Option<&TreeDigest>,
    root: &Path,
    exclusions: &[String],
    pruned: PrunedNames,
    limits: TreeLimits,
    label: &str,
    findings: &mut Vec<String>,
) -> (Option<String>, AttestStatus) {
    let Some(expected) = expected else {
        findings.push(format!("the receipt records no {label} tree digest"));
        return (None, AttestStatus::Partial);
    };
    if expected.mode_model != ModeModel::host() {
        findings.push(format!(
            "the {label} tree was bound under the {} permission model and cannot be compared on \
             this host",
            expected.mode_model.token()
        ));
        return (None, AttestStatus::Partial);
    }
    match scan_tree(root, exclusions, pruned, limits) {
        Ok(scan) => {
            let status = if scan.digest == expected.digest {
                AttestStatus::Clean
            } else {
                findings.push(format!("the {label} tree no longer matches the receipt"));
                AttestStatus::Mismatch
            };
            (Some(scan.digest), status)
        }
        Err(error) => {
            findings.push(format!("{label}: {error}"));
            (None, AttestStatus::Partial)
        }
    }
}

#[cfg(test)]
mod tests;
