//! Safe project-tree copy, inventory, digest, and bounded diff for the
//! `capsule run --preset untrusted-project` surface (C14).
//!
//! The recruiter-task threat is "someone sent me a repository and asked me to
//! run it". The preset never runs the operator's own working tree: it copies the
//! project into a held ephemeral directory and gives the contained child write
//! authority over the copy only. That copy is the whole reason this module
//! exists, and it is the one containment primitive the tree did not already
//! have.
//!
//! # Why the existing helper could not be reused
//!
//! `tirith::cli::temp_run::copy_repo_into` is a `walkdir` + `std::fs::copy`
//! loop. It SKIPS symlinks, has no byte cap, does no case or Unicode collision
//! check, and re-resolves every path by name. Silent skipping is the exact
//! failure mode a containment preset cannot tolerate: the operator would believe
//! the whole project was copied, run it, and reason about a diff of a tree that
//! never matched the input. So this copier REFUSES rather than skips.
//!
//! # What the copier guarantees
//!
//! - on unix the whole walk is fd-relative: each directory is a RETAINED
//!   `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` descriptor, and every subsequent step is
//!   `fstatat` / `openat` / `mkdirat` against that descriptor with a single safe
//!   name component. No path is ever re-resolved after it was checked, which is
//!   what closes the swap window a pathname walk leaves open: check `proj/sub`,
//!   then re-open `proj/sub` by name, and a local attacker who turns `sub` into
//!   a symlink to `~/.ssh` in between gets their credential store copied into
//!   the tree the untrusted project is about to read;
//! - on Windows the equivalent walk uses retained directory HANDLEs and
//!   `NtCreateFile` with `OBJECT_ATTRIBUTES.RootDirectory` for every child;
//!   enumeration is `NtQueryDirectoryFile` on that same handle and reparse
//!   points are refused, so there is no pathname fallback on Windows;
//! - no symlink is ever copied or followed: a symlink entry is a hard refusal,
//!   not a skip, and a component swapped into a symlink after the entry scan
//!   fails the `O_NOFOLLOW` open with `ELOOP` and is refused there too;
//! - no entry other than a regular file or a directory is accepted;
//! - a regular file with more than one link is refused. A hardlink is a second
//!   name for an inode that may live anywhere on the device, including the
//!   operator's credential store, and no walk of the project can see where the
//!   other names are. Copying one would exfiltrate a file the project root does
//!   not contain, at file granularity, past the `--project` deny-root gate;
//! - an entry on a different device from the project root is refused: a
//!   filesystem mounted inside the tree is not part of the project the operator
//!   named;
//! - every opened descriptor's `(dev, ino)` must equal the `(dev, ino)` the
//!   entry scan observed, for directories as well as files, so a name rebound to
//!   a different inode between the two calls is refused rather than copied;
//! - `readdir` clears `errno` first so a failed read can never be mistaken for
//!   the end of a directory, because a truncated listing is a silently partial
//!   copy;
//! - entry names are rejected when they are not valid UTF-8, contain a path
//!   separator or NUL, or are `.` / `..`;
//! - a case or Unicode-normalization collision inside one directory is refused
//!   (checked in-process on every platform, and again by `create_new` at the
//!   destination, so a case-insensitive destination cannot silently merge two
//!   distinct source names);
//! - `.git` is excluded at every depth, as a directory or as a submodule FILE;
//! - the copy refuses past [`MAX_PROJECT_FILES`] files, [`MAX_PROJECT_ENTRIES`]
//!   entries of every kind, or [`MAX_PROJECT_BYTES`] total bytes rather than
//!   truncating.
//!
//! # Why the walk is depth-first
//!
//! Every unvisited directory holds two open descriptors (its source and its
//! destination), so a breadth-first walk that queues all of a directory's
//! children before descending needs descriptors proportional to the WIDEST
//! directory, and dies on `RLIMIT_NOFILE` on an ordinary vendored dependency
//! tree long before any documented cap. Descending one child at a time bounds
//! the retained descriptors by [`MAX_PROJECT_DEPTH`] instead, which is a cap the
//! operator was told about. [`MAX_PROJECT_ENTRIES`] bounds the entry names held
//! along that path, so neither descriptors nor parent memory scale with a
//! hostile tree's shape.
//!
//! # Stable capsule inventory and tolerant compatibility inventory
//!
//! Capsule execution uses [`inventory_project_tree_stable`], a bounded two-pass
//! retained-capability scan. Any membership, identity, type, exact mode, size,
//! timestamp, or digest change is [`ProjectCopyError::ChangedDuringScan`], with
//! no retry. [`inventory_project_tree`] remains the tolerant compatibility API
//! used when inspecting an already-produced external tree; it marks incomplete
//! observations rather than making a containment claim from them.

use std::collections::BTreeMap;
#[cfg(unix)]
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
#[cfg(unix)]
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;

use crate::command_card::sha256_hex;
use crate::util::{open_read_no_follow_capped, HashOutcome};

/// Maximum number of files the preset will copy. Refuses past this; never
/// truncates.
pub const MAX_PROJECT_FILES: usize = 100_000;

/// Maximum total input bytes the preset will copy. Refuses past this.
pub const MAX_PROJECT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Maximum directory nesting depth accepted by the copier. A deep tree is a
/// resource-exhaustion vector, not a legitimate project shape.
pub const MAX_PROJECT_DEPTH: usize = 256;

/// Maximum entries of every kind (files, directories, and refused types) the
/// copier will observe. This is what bounds the parent memory holding entry
/// names for the path currently being walked, so one absurdly wide directory
/// cannot be turned into a parent-side allocation attack.
pub const MAX_PROJECT_ENTRIES: usize = 200_000;

/// Maximum entries reported per diff bucket before the diff declares itself
/// truncated.
pub const MAX_DIFF_ENTRIES: usize = 256;

/// Maximum BYTES of one relative path recorded in a diff bucket. Bounded in
/// bytes rather than characters because the bound exists to keep the serialized
/// receipt under [`crate::capsule_receipt::MAX_CAPSULE_RECEIPT_BYTES`], and a
/// path of multi-byte scalars is four times longer than its character count.
pub const MAX_DIFF_PATH_BYTES: usize = 256;

/// Domain-separation tag for the rolled-up tree digest, so a tree digest can
/// never be confused with any other sha256 this codebase records.
const TREE_DIGEST_TAG: &str = "tirith-capsule-tree-v1\n";

/// Domain-separation tag for the argv digest.
const ARGV_DIGEST_TAG: &str = "tirith-capsule-argv-v1\n";

/// The directory name excluded at every depth, as a directory or as the
/// submodule pointer FILE of the same name.
const EXCLUDED_NAME: &str = ".git";

/// Why the strict project copy refused. Every variant is a refusal: the copier
/// has no "skipped it" outcome, because a silently partial copy is the failure
/// this type exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectCopyError {
    /// A symlink was found in the source tree. Refused, never skipped.
    Symlink(String),
    /// An entry was neither a regular file nor a directory (fifo, socket,
    /// device, or an unnamed platform type).
    UnsupportedEntry(String),
    /// A regular file had more than one link, so its content also lives under a
    /// name the project root does not contain.
    HardLink(String),
    /// An entry name was not valid UTF-8. Refused so relative paths in the tree
    /// digest and the diff are exact rather than lossy.
    NameNotUtf8(String),
    /// An entry name contained a path separator, a NUL, or was `.` / `..`.
    UnsafeName(String),
    /// Two entries in one directory collide after case folding and Unicode
    /// normalization, so the destination cannot hold both faithfully.
    NameCollision(String),
    /// An entry resolved outside the source root, or onto another filesystem
    /// mounted inside it.
    Escape(String),
    /// The opened descriptor is not the inode the directory read observed.
    IdentityChanged(String),
    /// The retained tree changed between, or during, either of the two bounded
    /// passes. There is deliberately no retry: a tree that is being mutated is
    /// not a stable input to an execution receipt.
    ChangedDuringScan(String),
    /// The file-count cap was reached.
    FileCapExceeded,
    /// The total-entry cap was reached.
    EntryCapExceeded(String),
    /// The byte cap was reached.
    ByteCapExceeded,
    /// The nesting-depth cap was reached.
    DepthCapExceeded(String),
    /// The destination was not a usable empty directory.
    Destination(String),
    /// An underlying I/O failure, described without a host path.
    Io(String),
}

impl std::fmt::Display for ProjectCopyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Symlink(rel) => write!(
                f,
                "project entry '{rel}' is a symlink; the untrusted-project preset refuses symlinks rather than silently skipping them"
            ),
            Self::UnsupportedEntry(rel) => write!(
                f,
                "project entry '{rel}' is neither a regular file nor a directory"
            ),
            Self::HardLink(rel) => write!(
                f,
                "project file '{rel}' is a hardlink; its content also lives outside the project root, so the copy is refused rather than made"
            ),
            Self::NameNotUtf8(rel) => {
                write!(f, "project entry under '{rel}' has a non-UTF-8 name")
            }
            Self::UnsafeName(rel) => {
                write!(f, "project entry name '{rel}' is not a safe path component")
            }
            Self::NameCollision(rel) => write!(
                f,
                "project entries under '{rel}' collide after case folding and Unicode normalization"
            ),
            Self::Escape(rel) => write!(
                f,
                "project entry '{rel}' resolves outside the project root or onto another filesystem"
            ),
            Self::IdentityChanged(rel) => write!(
                f,
                "project entry '{rel}' changed identity between the directory read and the open"
            ),
            Self::ChangedDuringScan(rel) => write!(
                f,
                "project entry '{rel}' changed during the two-pass stable-tree scan"
            ),
            Self::FileCapExceeded => write!(
                f,
                "project exceeds the {MAX_PROJECT_FILES}-file copy limit; refusing rather than copying part of it"
            ),
            Self::EntryCapExceeded(rel) => write!(
                f,
                "project directory '{rel}' pushes the project past the {MAX_PROJECT_ENTRIES}-entry copy limit; refusing rather than copying part of it"
            ),
            Self::ByteCapExceeded => write!(
                f,
                "project exceeds the {MAX_PROJECT_BYTES}-byte copy limit; refusing rather than copying part of it"
            ),
            Self::DepthCapExceeded(rel) => write!(
                f,
                "project directory '{rel}' exceeds the {MAX_PROJECT_DEPTH}-level nesting limit"
            ),
            Self::Destination(reason) => {
                write!(f, "project copy destination is unusable: {reason}")
            }
            Self::Io(reason) => write!(f, "project copy failed: {reason}"),
        }
    }
}

impl std::error::Error for ProjectCopyError {}

/// What a completed strict copy moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectCopySummary {
    /// Regular files copied.
    pub file_count: usize,
    /// Directories created (excluding the destination root itself).
    pub directory_count: usize,
    /// Total bytes copied.
    pub total_bytes: u64,
}

/// The typed content marker recorded per inventory entry. Kept as a short
/// string so the rolled-up digest is stable and the JSON stays compact.
fn directory_marker() -> String {
    "d".to_string()
}

/// A bounded, order-independent inventory of one tree plus its rolled-up digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectTree {
    /// Regular files inventoried.
    pub file_count: usize,
    /// Total bytes hashed across those regular files.
    pub total_bytes: u64,
    /// Rolled-up sha256 over the sorted `relative path -> content marker` map.
    pub digest: String,
    /// `false` when a cap was hit or an entry could not be inspected, so the
    /// digest covers less than the whole tree. A receipt must not claim a
    /// faithful output digest when this is `false`.
    pub complete: bool,
    /// Sorted `relative path -> content marker`. Not serialized: it is the diff
    /// input, and a full per-file listing has no place in a receipt.
    #[serde(skip)]
    entries: BTreeMap<String, String>,
}

impl ProjectTree {
    /// Number of inventoried entries of every kind (files, directories, links,
    /// and special files).
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// The content marker recorded for one relative path, for tests and callers
    /// that need to prove an exact entry survived.
    pub fn marker(&self, relative: &str) -> Option<&str> {
        self.entries.get(relative).map(String::as_str)
    }
}

/// A bounded difference between two inventories of the same tree.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectDiff {
    /// Relative paths present only in the later inventory.
    pub added: Vec<String>,
    /// Relative paths whose content marker changed.
    pub modified: Vec<String>,
    /// Relative paths present only in the earlier inventory.
    pub removed: Vec<String>,
    /// `true` when a bucket was capped at [`MAX_DIFF_ENTRIES`] or a path was
    /// shortened to [`MAX_DIFF_PATH_CHARS`], so the diff is a sample.
    pub truncated: bool,
}

/// Copy the project at `source` into the already-created empty directory
/// `destination`, refusing anything the module documentation lists.
///
/// The destination must already exist and be an empty directory owned by the
/// caller; the preset creates it as a held ephemeral directory before calling.
pub fn copy_project_tree(
    source: &Path,
    destination: &Path,
) -> Result<ProjectCopySummary, ProjectCopyError> {
    copy_project_tree_excluding(source, destination, None)
}

/// Copy a project while excluding one exact, normalized relative file. The
/// exclusion exists for an operator-requested receipt prepared inside the
/// project before the scan; it never acts as a basename or prefix filter.
pub fn copy_project_tree_excluding(
    source: &Path,
    destination: &Path,
    excluded_relative: Option<&Path>,
) -> Result<ProjectCopySummary, ProjectCopyError> {
    let source_root = trusted_project_root(source)?;
    let destination_root = std::fs::canonicalize(destination).map_err(|error| {
        ProjectCopyError::Destination(format!("resolve copy destination: {error}"))
    })?;
    let excluded_relative = normalize_exclusion(excluded_relative)?;
    let destination_metadata = std::fs::symlink_metadata(&destination_root)
        .map_err(|error| ProjectCopyError::Destination(format!("inspect destination: {error}")))?;
    if !destination_metadata.is_dir() {
        return Err(ProjectCopyError::Destination(
            "destination is not a directory".to_string(),
        ));
    }
    let mut destination_entries = std::fs::read_dir(&destination_root)
        .map_err(|error| ProjectCopyError::Destination(format!("read destination: {error}")))?;
    if destination_entries.next().is_some() {
        return Err(ProjectCopyError::Destination(
            "destination is not empty".to_string(),
        ));
    }
    if source_root == destination_root {
        return Err(ProjectCopyError::Destination(
            "destination is the project root itself".to_string(),
        ));
    }
    if destination_root.starts_with(&source_root) {
        return Err(ProjectCopyError::Destination(
            "destination lies inside the project root".to_string(),
        ));
    }
    if source_root.starts_with(&destination_root) {
        return Err(ProjectCopyError::Destination(
            "the project root lies inside the copy destination".to_string(),
        ));
    }

    copy_tree_impl(
        &source_root,
        &destination_root,
        excluded_relative.as_deref(),
    )
}

fn normalize_exclusion(excluded: Option<&Path>) -> Result<Option<String>, ProjectCopyError> {
    let Some(excluded) = excluded else {
        return Ok(None);
    };
    if excluded.is_absolute() {
        return Err(ProjectCopyError::Io(
            "receipt exclusion must be relative to the project root".to_string(),
        ));
    }
    let mut components = Vec::new();
    for component in excluded.components() {
        match component {
            std::path::Component::Normal(name) => {
                let Some(name) = name.to_str() else {
                    return Err(ProjectCopyError::NameNotUtf8(
                        "receipt exclusion".to_string(),
                    ));
                };
                reject_unsafe_name(name, "receipt exclusion")?;
                components.push(name);
            }
            _ => {
                return Err(ProjectCopyError::UnsafeName(
                    "receipt exclusion".to_string(),
                ))
            }
        }
    }
    if components.is_empty() {
        return Err(ProjectCopyError::UnsafeName(
            "receipt exclusion".to_string(),
        ));
    }
    Ok(Some(components.join("/")))
}

/// Resolve only the one platform alias Tirith explicitly trusts. All actual
/// tree traversal still starts from a retained no-follow root capability.
fn trusted_project_root(source: &Path) -> Result<PathBuf, ProjectCopyError> {
    let absolute = if source.is_absolute() {
        source.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| ProjectCopyError::Io(format!("resolve current directory: {error}")))?
            .join(source)
    };
    Ok(trusted_platform_root_alias(&absolute))
}

/// Resolve only the platform-owned root alias Tirith explicitly trusts before
/// beginning descriptor-relative, no-follow traversal at that trusted root.
pub(crate) fn trusted_platform_root_alias(absolute: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let var = Path::new("/var");
        if absolute == var || absolute.starts_with(var) {
            let suffix = absolute.strip_prefix(var).unwrap_or(Path::new(""));
            return Path::new("/private/var").join(suffix);
        }
    }
    absolute.to_path_buf()
}

/// The fd-relative copy. Every traversal step is `openat`/`fstatat`/`mkdirat`
/// relative to a RETAINED directory descriptor with `O_NOFOLLOW`, so no
/// component is ever re-resolved by pathname after it was checked. That is the
/// difference that matters: a path-based walk revalidates `proj/sub` and then
/// re-opens `proj/sub` by name, and a local attacker who swaps `sub` for a
/// symlink to `~/.ssh` in between gets their credential store copied into the
/// tree the untrusted project is about to read. Holding the descriptor removes
/// the second resolution entirely.
#[cfg(unix)]
fn copy_tree_impl(
    source_root: &Path,
    destination_root: &Path,
    excluded_relative: Option<&str>,
) -> Result<ProjectCopySummary, ProjectCopyError> {
    copy_tree_impl_observed_excluding(
        source_root,
        destination_root,
        excluded_relative,
        &mut |_| {},
    )
}

/// One directory of the walk, holding its two descriptors and the entry names
/// still to process. A level is dropped as soon as its names are exhausted, so
/// the descriptors alive at any moment are exactly those on the path from the
/// root to the directory being visited.
#[cfg(unix)]
struct CopyLevel {
    relative: String,
    depth: usize,
    source: std::os::fd::OwnedFd,
    destination: std::os::fd::OwnedFd,
    names: std::vec::IntoIter<std::ffi::OsString>,
    collision_keys: BTreeSet<String>,
    opened: StableEntry,
}

#[cfg(any(unix, windows))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct StableEntry {
    kind: u8,
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanos: i64,
    changed_seconds: i64,
    changed_nanos: i64,
    digest: Option<String>,
}

#[cfg(any(unix, windows))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct StableSnapshot {
    root: StableEntry,
    entries: BTreeMap<String, StableEntry>,
    summary: ProjectCopySummary,
}

#[cfg(unix)]
struct ScanLevel {
    relative: String,
    depth: usize,
    source: std::os::fd::OwnedFd,
    names: std::vec::IntoIter<std::ffi::OsString>,
    collision_keys: BTreeSet<String>,
    opened: StableEntry,
}

#[cfg(all(any(unix, windows), test))]
thread_local! {
    static BETWEEN_STABLE_PASSES_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(any(unix, windows))]
fn run_between_stable_passes_hook() {
    #[cfg(test)]
    BETWEEN_STABLE_PASSES_HOOK.with(|slot| {
        if let Some(mut hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(unix)]
fn first_stable_pass(
    source_root: &std::os::fd::OwnedFd,
    excluded_relative: Option<&str>,
) -> Result<StableSnapshot, ProjectCopyError> {
    use std::os::fd::AsRawFd as _;

    let root = fd::stable_directory_facts(source_root, "")?;
    let root_device = root.device;
    let root_names = fd::read_entry_names(source_root, MAX_PROJECT_ENTRIES, "")?;
    let mut entries_seen = root_names.len();
    let mut entries = BTreeMap::new();
    let mut summary = ProjectCopySummary {
        file_count: 0,
        directory_count: 0,
        total_bytes: 0,
    };
    let mut stack = vec![ScanLevel {
        relative: String::new(),
        depth: 0,
        source: source_root.try_clone().map_err(|error| {
            ProjectCopyError::Io(format!("retain project root for stable scan: {error}"))
        })?,
        names: root_names.into_iter(),
        collision_keys: BTreeSet::new(),
        opened: root.clone(),
    }];

    while let Some(index) = stack.len().checked_sub(1) {
        let Some(raw_name) = stack[index].names.next() else {
            let level = stack.pop().expect("indexed level exists");
            let closed = fd::stable_directory_facts(&level.source, &level.relative)?;
            if closed != level.opened {
                return Err(ProjectCopyError::ChangedDuringScan(display_relative(
                    &level.relative,
                )));
            }
            continue;
        };
        let relative_dir = stack[index].relative.clone();
        let depth = stack[index].depth;
        let source_dir = stack[index].source.as_raw_fd();
        let Some(name) = raw_name.to_str() else {
            return Err(ProjectCopyError::NameNotUtf8(display_relative(
                &relative_dir,
            )));
        };
        let relative = push_relative(&relative_dir, name);
        reject_unsafe_name(name, &relative)?;
        if name == EXCLUDED_NAME || excluded_relative == Some(relative.as_str()) {
            continue;
        }
        if !stack[index].collision_keys.insert(collision_key(name)) {
            return Err(ProjectCopyError::NameCollision(display_relative(
                &relative_dir,
            )));
        }
        let component = std::ffi::CString::new(name)
            .map_err(|_| ProjectCopyError::UnsafeName(relative.clone()))?;
        let observed = fd::stat_at(source_dir, &component).map_err(|error| {
            ProjectCopyError::Io(format!("inspect project entry '{relative}': {error}"))
        })?;
        if u64::try_from(observed.st_dev).unwrap_or(u64::MAX) != root_device {
            return Err(ProjectCopyError::Escape(relative));
        }
        let kind = observed.st_mode & libc::S_IFMT;
        if kind == libc::S_IFLNK {
            return Err(ProjectCopyError::Symlink(relative));
        }
        if kind == libc::S_IFDIR {
            if depth + 1 > MAX_PROJECT_DEPTH {
                return Err(ProjectCopyError::DepthCapExceeded(relative));
            }
            let child = fd::open_directory_at(source_dir, &component)
                .map_err(|_| ProjectCopyError::ChangedDuringScan(relative.clone()))?;
            let facts = fd::stable_directory_facts(&child, &relative)?;
            if facts.device != u64::try_from(observed.st_dev).unwrap_or(u64::MAX)
                || facts.inode != observed.st_ino
            {
                return Err(ProjectCopyError::ChangedDuringScan(relative));
            }
            let names = fd::read_entry_names(
                &child,
                MAX_PROJECT_ENTRIES.saturating_sub(entries_seen),
                &relative,
            )?;
            entries_seen += names.len();
            entries.insert(relative.clone(), facts.clone());
            summary.directory_count += 1;
            stack.push(ScanLevel {
                relative,
                depth: depth + 1,
                source: child,
                names: names.into_iter(),
                collision_keys: BTreeSet::new(),
                opened: facts,
            });
            continue;
        }
        if kind != libc::S_IFREG {
            return Err(ProjectCopyError::UnsupportedEntry(relative));
        }
        if summary.file_count >= MAX_PROJECT_FILES {
            return Err(ProjectCopyError::FileCapExceeded);
        }
        let remaining = MAX_PROJECT_BYTES.saturating_sub(summary.total_bytes);
        let facts = fd::hash_file_at(source_dir, &component, &observed, &relative, remaining)?;
        summary.file_count += 1;
        summary.total_bytes = summary.total_bytes.saturating_add(facts.size);
        entries.insert(relative, facts);
    }
    let root_after = fd::stable_directory_facts(source_root, "")?;
    if root_after != root {
        return Err(ProjectCopyError::ChangedDuringScan(".".to_string()));
    }
    Ok(StableSnapshot {
        root,
        entries,
        summary,
    })
}

/// The walk, with an observer that is handed the number of RETAINED levels after
/// every descent. The retained-descriptor bound is a security-relevant resource
/// property (a copy that dies on `RLIMIT_NOFILE` is a refusal an attacker can
/// force), so it is made observable rather than argued about.
#[cfg(all(unix, test))]
fn copy_tree_impl_observed(
    source_root: &Path,
    destination_root: &Path,
    observer: &mut dyn FnMut(usize),
) -> Result<ProjectCopySummary, ProjectCopyError> {
    copy_tree_impl_observed_excluding(source_root, destination_root, None, observer)
}

#[cfg(unix)]
fn copy_tree_impl_observed_excluding(
    source_root: &Path,
    destination_root: &Path,
    excluded_relative: Option<&str>,
    observer: &mut dyn FnMut(usize),
) -> Result<ProjectCopySummary, ProjectCopyError> {
    use std::os::fd::AsRawFd as _;

    let source_fd = fd::open_directory_tree(source_root)
        .map_err(|error| ProjectCopyError::Io(format!("open project root: {error}")))?;
    let destination_fd = fd::open_directory_tree(destination_root).map_err(|error| {
        ProjectCopyError::Destination(format!("open copy destination: {error}"))
    })?;
    if !fd::read_entry_names(&destination_fd, 1, "")?.is_empty() {
        return Err(ProjectCopyError::Destination(
            "retained destination is not empty".to_string(),
        ));
    }
    let source_identity_fd = source_fd
        .try_clone()
        .map_err(|error| ProjectCopyError::Io(format!("retain project root identity: {error}")))?;
    let destination_identity_fd = destination_fd.try_clone().map_err(|error| {
        ProjectCopyError::Destination(format!("retain copy destination identity: {error}"))
    })?;
    let source_identity = fd::stable_directory_facts(&source_fd, "")?;
    let destination_identity = fd::stable_directory_facts(&destination_fd, "")?;
    if source_identity.device == destination_identity.device
        && source_identity.inode == destination_identity.inode
    {
        return Err(ProjectCopyError::Destination(
            "destination is the retained project root itself".to_string(),
        ));
    }
    // Every entry must live on this device. A filesystem mounted inside the
    // project is not part of the project the operator named, and refusing it
    // also refuses the one shape a same-device hardlink cannot take.
    let first = first_stable_pass(&source_fd, excluded_relative)?;
    run_between_stable_passes_hook();
    if !fd::visible_directory_matches(source_root, &source_fd)? {
        return Err(ProjectCopyError::ChangedDuringScan(".".to_string()));
    }
    let root_device = first.root.device;

    let mut summary = ProjectCopySummary {
        file_count: 0,
        directory_count: 0,
        total_bytes: 0,
    };
    let mut entries_seen = 0usize;
    let mut second_entries = BTreeMap::new();
    let root_names = fd::read_entry_names(&source_fd, MAX_PROJECT_ENTRIES, "")?;
    entries_seen += root_names.len();
    // Iterative, so a pathological tree cannot blow the stack before the depth
    // cap refuses it, and depth-first, so the descriptors it retains are bounded
    // by MAX_PROJECT_DEPTH rather than by the widest directory.
    let mut stack: Vec<CopyLevel> = vec![CopyLevel {
        relative: String::new(),
        depth: 0,
        source: source_fd,
        destination: destination_fd,
        names: root_names.into_iter(),
        collision_keys: BTreeSet::new(),
        opened: first.root.clone(),
    }];

    while let Some(index) = stack.len().checked_sub(1) {
        let Some(raw_name) = stack[index].names.next() else {
            let level = stack.pop().expect("indexed level exists");
            let closed = fd::stable_directory_facts(&level.source, &level.relative)?;
            if closed != level.opened {
                return Err(ProjectCopyError::ChangedDuringScan(display_relative(
                    &level.relative,
                )));
            }
            continue;
        };
        let relative_dir = stack[index].relative.clone();
        let depth = stack[index].depth;
        let source_dir = stack[index].source.as_raw_fd();
        let destination_dir = stack[index].destination.as_raw_fd();
        let Some(name) = raw_name.to_str() else {
            return Err(ProjectCopyError::NameNotUtf8(display_relative(
                &relative_dir,
            )));
        };
        let relative = push_relative(&relative_dir, name);
        reject_unsafe_name(name, &relative)?;
        if name == EXCLUDED_NAME || excluded_relative == Some(relative.as_str()) {
            continue;
        }
        if !stack[index].collision_keys.insert(collision_key(name)) {
            return Err(ProjectCopyError::NameCollision(display_relative(
                &relative_dir,
            )));
        }
        let component = std::ffi::CString::new(name)
            .map_err(|_| ProjectCopyError::UnsafeName(relative.clone()))?;

        let observed = fd::stat_at(source_dir, &component).map_err(|error| {
            ProjectCopyError::Io(format!("inspect project entry '{relative}': {error}"))
        })?;
        if u64::try_from(observed.st_dev).unwrap_or(u64::MAX) != root_device {
            return Err(ProjectCopyError::Escape(relative));
        }
        let kind = observed.st_mode & libc::S_IFMT;
        if kind == libc::S_IFLNK {
            return Err(ProjectCopyError::Symlink(relative));
        }
        if kind == libc::S_IFDIR {
            if depth + 1 > MAX_PROJECT_DEPTH {
                return Err(ProjectCopyError::DepthCapExceeded(relative));
            }
            let child_source = fd::open_directory_at(source_dir, &component)
                .map_err(|_| ProjectCopyError::ChangedDuringScan(relative.clone()))?;
            // The descriptor we will actually traverse must be the inode the
            // entry scan saw, or the name was swapped between the two calls.
            let opened = fd::stable_directory_facts(&child_source, &relative)?;
            if opened.device != u64::try_from(observed.st_dev).unwrap_or(u64::MAX)
                || opened.inode != observed.st_ino
            {
                return Err(ProjectCopyError::ChangedDuringScan(relative));
            }
            let child_names = fd::read_entry_names(
                &child_source,
                MAX_PROJECT_ENTRIES.saturating_sub(entries_seen),
                &relative,
            )?;
            entries_seen += child_names.len();
            fd::make_directory_at(destination_dir, &component, &relative)?;
            let child_destination =
                fd::open_directory_at(destination_dir, &component).map_err(|error| {
                    ProjectCopyError::Io(format!("open copied directory '{relative}': {error}"))
                })?;
            summary.directory_count += 1;
            second_entries.insert(relative.clone(), opened.clone());
            stack.push(CopyLevel {
                relative,
                depth: depth + 1,
                source: child_source,
                destination: child_destination,
                names: child_names.into_iter(),
                collision_keys: BTreeSet::new(),
                opened,
            });
            observer(stack.len());
            continue;
        }
        if kind != libc::S_IFREG {
            return Err(ProjectCopyError::UnsupportedEntry(relative));
        }

        if summary.file_count >= MAX_PROJECT_FILES {
            return Err(ProjectCopyError::FileCapExceeded);
        }
        let remaining = MAX_PROJECT_BYTES.saturating_sub(summary.total_bytes);
        let copied = fd::copy_file_at_stable(
            source_dir,
            destination_dir,
            &component,
            &observed,
            &relative,
            remaining,
        )?;
        summary.file_count += 1;
        summary.total_bytes = summary.total_bytes.saturating_add(copied.size);
        second_entries.insert(relative, copied);
    }
    let root_after = fd::stable_directory_facts(&source_identity_fd, "")?;
    if root_after != first.root
        || second_entries != first.entries
        || summary != first.summary
        || !fd::visible_directory_matches(source_root, &source_identity_fd)?
        || !fd::visible_directory_matches(destination_root, &destination_identity_fd)?
    {
        return Err(ProjectCopyError::ChangedDuringScan(".".to_string()));
    }
    Ok(summary)
}

/// Windows uses the same two-pass algorithm over NT RootDirectory-relative
/// handles. No checked pathname is re-opened during either pass.
#[cfg(windows)]
fn copy_tree_impl(
    source_root: &Path,
    destination_root: &Path,
    excluded_relative: Option<&str>,
) -> Result<ProjectCopySummary, ProjectCopyError> {
    windows_capability::copy_stable(source_root, destination_root, excluded_relative)
}

/// Unsupported targets fail closed rather than silently regressing to a
/// pathname walk.
#[cfg(not(any(unix, windows)))]
fn copy_tree_impl(
    _source_root: &Path,
    _destination_root: &Path,
    _excluded_relative: Option<&str>,
) -> Result<ProjectCopySummary, ProjectCopyError> {
    Err(ProjectCopyError::Io(
        "stable project traversal is unavailable on this platform".to_string(),
    ))
}

/// The `openat` family the unix walk is built from. Every helper takes a
/// RETAINED parent descriptor and a single safe name component; none of them
/// accepts a path, which is the property that makes a swapped component
/// unreachable rather than merely unlikely.
#[cfg(unix)]
mod fd {
    use std::ffi::CStr;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::os::unix::fs::MetadataExt as _;

    use super::{ProjectCopyError, StableEntry};

    const DIRECTORY_FLAGS: libc::c_int =
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

    /// Open an absolute, already-canonicalized directory as a capability.
    /// `O_NOFOLLOW` still applies: a canonical path has no symlink final
    /// component unless one was planted after canonicalization, and that is
    /// exactly the case to refuse.
    pub(super) fn open_directory(path: &std::path::Path) -> std::io::Result<OwnedFd> {
        use std::os::unix::ffi::OsStrExt as _;

        let raw = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::other("project path contains an interior NUL"))?;
        // SAFETY: the path buffer is NUL-terminated and lives across the call.
        let fd = unsafe { libc::open(raw.as_ptr(), DIRECTORY_FLAGS) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: open returned a fresh owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Traverse an absolute root one component at a time. This is the root
    /// analogue of `open_directory_at`: intermediate symlinks are refused too,
    /// rather than being followed by one pathname `open`.
    pub(super) fn open_directory_tree(path: &std::path::Path) -> std::io::Result<OwnedFd> {
        use std::path::Component;

        if !path.is_absolute() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "project capability root is not absolute",
            ));
        }
        let mut held = open_directory(std::path::Path::new("/"))?;
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    use std::os::unix::ffi::OsStrExt as _;
                    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "project path contains an interior NUL",
                        )
                    })?;
                    held = open_directory_at(held.as_raw_fd(), &name)?;
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "project path is not lexically normalized",
                    ))
                }
            }
        }
        Ok(held)
    }

    pub(super) fn visible_directory_matches(
        path: &std::path::Path,
        held: &OwnedFd,
    ) -> Result<bool, ProjectCopyError> {
        let visible = match open_directory_tree(path) {
            Ok(visible) => visible,
            Err(_) => return Ok(false),
        };
        let visible = stable_directory_facts(&visible, "")?;
        let held = stable_directory_facts(held, "")?;
        Ok(visible.device == held.device && visible.inode == held.inode)
    }

    fn stable_metadata(metadata: &std::fs::Metadata, kind: u8) -> StableEntry {
        StableEntry {
            kind,
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            size: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanos: metadata.ctime_nsec(),
            digest: None,
        }
    }

    pub(super) fn stable_directory_facts(
        directory: &OwnedFd,
        relative: &str,
    ) -> Result<StableEntry, ProjectCopyError> {
        let file: std::fs::File = directory
            .try_clone()
            .map_err(|error| {
                ProjectCopyError::Io(format!("retain project directory '{relative}': {error}"))
            })?
            .into();
        let metadata = file.metadata().map_err(|error| {
            ProjectCopyError::Io(format!("inspect project directory '{relative}': {error}"))
        })?;
        if !metadata.is_dir() {
            return Err(ProjectCopyError::ChangedDuringScan(
                super::display_relative(relative),
            ));
        }
        Ok(stable_metadata(&metadata, b'd'))
    }

    pub(super) fn open_directory_at(parent: i32, name: &CStr) -> std::io::Result<OwnedFd> {
        // SAFETY: `parent` is a live directory descriptor and `name` is a
        // NUL-terminated single component.
        let fd = unsafe { libc::openat(parent, name.as_ptr(), DIRECTORY_FLAGS) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: openat returned a fresh owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    pub(super) fn stat_at(parent: i32, name: &CStr) -> std::io::Result<libc::stat> {
        let mut buffer = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `parent` is live, `name` is NUL-terminated, and the output
        // buffer is writable for the whole call.
        let status = unsafe {
            libc::fstatat(
                parent,
                name.as_ptr(),
                buffer.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if status != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fstatat initialized the structure on success.
        Ok(unsafe { buffer.assume_init() })
    }

    /// Create the copied directory owner-only. `EEXIST` is reported as a
    /// collision rather than an I/O fault: on a case-insensitive destination it
    /// is exactly how two distinct source names try to become one entry.
    pub(super) fn make_directory_at(
        parent: i32,
        name: &CStr,
        relative: &str,
    ) -> Result<(), ProjectCopyError> {
        // SAFETY: `parent` is live and `name` is a NUL-terminated component.
        if unsafe { libc::mkdirat(parent, name.as_ptr(), 0o700) } != 0 {
            let error = std::io::Error::last_os_error();
            return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
                ProjectCopyError::NameCollision(relative.to_string())
            } else {
                ProjectCopyError::Io(format!("create copied directory '{relative}': {error}"))
            });
        }
        // mkdirat is subject to the process umask. With a restrictive umask the
        // new directory can therefore be mode 000, which cannot be opened for
        // the retained traversal below. Establish owner access relative to the
        // already-held parent before opening it. AT_SYMLINK_NOFOLLOW is
        // essential: if the just-created name is exchanged, chmod must never
        // reach through an attacker-provided symlink.
        let created = stat_at(parent, name).map_err(|error| {
            ProjectCopyError::Io(format!(
                "inspect copied directory '{relative}' before securing it: {error}"
            ))
        })?;
        if created.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(ProjectCopyError::ChangedDuringScan(relative.to_string()));
        }
        // SAFETY: `parent` is retained, `name` is one NUL-terminated component,
        // and AT_SYMLINK_NOFOLLOW prevents a replacement symlink from being
        // traversed.
        if unsafe { libc::fchmodat(parent, name.as_ptr(), 0o700, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return Err(ProjectCopyError::Io(format!(
                "secure copied directory '{relative}' before opening it: {}",
                std::io::Error::last_os_error()
            )));
        }
        let directory = open_directory_at(parent, name).map_err(|error| {
            ProjectCopyError::Io(format!("open copied directory '{relative}': {error}"))
        })?;
        let opened = stable_directory_facts(&directory, relative)?;
        if opened.device != u64::try_from(created.st_dev).unwrap_or(u64::MAX)
            || opened.inode != created.st_ino
        {
            return Err(ProjectCopyError::ChangedDuringScan(relative.to_string()));
        }
        // umask may clear requested bits. The copy contract is exact 0700, so
        // establish it on the opened directory capability before descent.
        if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
            return Err(ProjectCopyError::Io(format!(
                "secure copied directory '{relative}': {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Read one directory's entry names through a DUPLICATED descriptor, so the
    /// caller keeps its own capability for the `openat` calls that follow.
    ///
    /// `budget` is the number of entries the whole copy may still observe. It is
    /// enforced DURING the read rather than after it, because the point of the
    /// cap is that a hostile directory cannot make the parent allocate an
    /// unbounded listing in the first place.
    pub(super) fn read_entry_names(
        directory: &OwnedFd,
        budget: usize,
        relative: &str,
    ) -> Result<Vec<std::ffi::OsString>, ProjectCopyError> {
        use std::os::unix::ffi::OsStrExt as _;

        let read = || -> std::io::Result<Result<Vec<std::ffi::OsString>, ()>> {
            let dot = c".";
            // `dup` shares a directory offset. Opening `.` relative to the held
            // directory creates an independent stream for each pass without
            // re-resolving any path component.
            let independent = open_directory_at(directory.as_raw_fd(), dot)?;
            let mut stream = DirStream::adopt(independent)?;
            let mut names = Vec::new();
            loop {
                match stream.next_name()? {
                    Some(name) => {
                        let bytes = name.to_bytes();
                        if bytes == b"." || bytes == b".." {
                            continue;
                        }
                        if names.len() >= budget {
                            return Ok(Err(()));
                        }
                        names.push(std::ffi::OsStr::from_bytes(bytes).to_os_string());
                    }
                    None => return Ok(Ok(names)),
                }
            }
        };
        match read() {
            Ok(Ok(names)) => Ok(names),
            Ok(Err(())) => Err(ProjectCopyError::EntryCapExceeded(super::display_relative(
                relative,
            ))),
            Err(error) => Err(ProjectCopyError::Io(format!(
                "read project directory '{relative}': {error}"
            ))),
        }
    }

    /// Copy one regular file between two retained directory capabilities.
    #[cfg(test)]
    pub(super) fn copy_file_at(
        source_parent: i32,
        destination_parent: i32,
        name: &CStr,
        observed: &libc::stat,
        relative: &str,
        remaining_bytes: u64,
    ) -> Result<u64, ProjectCopyError> {
        copy_file_at_stable(
            source_parent,
            destination_parent,
            name,
            observed,
            relative,
            remaining_bytes,
        )
        .map(|facts| facts.size)
    }

    pub(super) fn hash_file_at(
        source_parent: i32,
        name: &CStr,
        observed: &libc::stat,
        relative: &str,
        remaining_bytes: u64,
    ) -> Result<StableEntry, ProjectCopyError> {
        read_file_at_stable(
            source_parent,
            None,
            name,
            observed,
            relative,
            remaining_bytes,
        )
    }

    pub(super) fn copy_file_at_stable(
        source_parent: i32,
        destination_parent: i32,
        name: &CStr,
        observed: &libc::stat,
        relative: &str,
        remaining_bytes: u64,
    ) -> Result<StableEntry, ProjectCopyError> {
        read_file_at_stable(
            source_parent,
            Some(destination_parent),
            name,
            observed,
            relative,
            remaining_bytes,
        )
    }

    fn read_file_at_stable(
        source_parent: i32,
        destination_parent: Option<i32>,
        name: &CStr,
        observed: &libc::stat,
        relative: &str,
        remaining_bytes: u64,
    ) -> Result<StableEntry, ProjectCopyError> {
        use sha2::Digest as _;
        use std::io::{Read as _, Write as _};

        // `O_NONBLOCK` so a fifo planted at this name returns immediately
        // instead of blocking on a writer; the post-open `fstat` then refuses it.
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
        // SAFETY: both parents are live and `name` is a NUL-terminated component.
        let raw = unsafe { libc::openat(source_parent, name.as_ptr(), flags) };
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            return Err(match error.raw_os_error() {
                // A component swapped into a symlink after the entry scan.
                Some(libc::ELOOP) => ProjectCopyError::ChangedDuringScan(relative.to_string()),
                Some(libc::ENOENT) => ProjectCopyError::ChangedDuringScan(relative.to_string()),
                _ => ProjectCopyError::Io(format!("open project file '{relative}': {error}")),
            });
        }
        // SAFETY: openat returned a fresh owned descriptor.
        let mut source_file = unsafe { std::fs::File::from_raw_fd(raw) };
        let metadata = source_file.metadata().map_err(|error| {
            ProjectCopyError::Io(format!("inspect opened project file '{relative}': {error}"))
        })?;
        let mut opened = stable_metadata(&metadata, b'f');
        if !metadata.is_file() {
            return Err(ProjectCopyError::ChangedDuringScan(relative.to_string()));
        }
        if opened.device != u64::try_from(observed.st_dev).unwrap_or(u64::MAX)
            || opened.inode != observed.st_ino
        {
            return Err(ProjectCopyError::ChangedDuringScan(relative.to_string()));
        }
        // Read from the OPENED inode, so the count cannot be raced after the
        // entry scan. A second link means this content is also reachable under a
        // name the walk never saw, which for a project that arrived from a
        // stranger is the operator's own credential store as often as not.
        if opened.links > 1 {
            return Err(ProjectCopyError::HardLink(relative.to_string()));
        }
        let size = opened.size;
        if size > remaining_bytes {
            return Err(ProjectCopyError::ByteCapExceeded);
        }

        let mut destination_file = if let Some(destination_parent) = destination_parent {
            let create_flags =
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            // SAFETY: the destination parent is live and `name` is a component.
            let raw = unsafe {
                libc::openat(
                    destination_parent,
                    name.as_ptr(),
                    create_flags,
                    0o600 as libc::c_uint,
                )
            };
            if raw < 0 {
                let error = std::io::Error::last_os_error();
                return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
                    ProjectCopyError::NameCollision(relative.to_string())
                } else {
                    ProjectCopyError::Io(format!("create copied file '{relative}': {error}"))
                });
            }
            // SAFETY: openat returned a fresh owned descriptor.
            let file = unsafe { std::fs::File::from_raw_fd(raw) };
            let mode = if opened.mode & 0o111 != 0 {
                0o700
            } else {
                0o600
            };
            // Source executable intent comes from this exact opened handle.
            // fchmod happens before any untrusted child can observe the tree.
            if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
                let error = std::io::Error::last_os_error();
                // SAFETY: retained parent + component, and this function alone
                // created the entry with O_EXCL.
                unsafe { libc::unlinkat(destination_parent, name.as_ptr(), 0) };
                return Err(ProjectCopyError::Io(format!(
                    "secure copied file '{relative}': {error}"
                )));
            }
            Some((destination_parent, file))
        } else {
            None
        };

        let mut hasher = super::Sha256::new();
        let mut copied = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = source_file.read(&mut buffer).map_err(|error| {
                ProjectCopyError::Io(format!("read project file '{relative}': {error}"))
            })?;
            if read == 0 {
                break;
            }
            copied = copied.saturating_add(read as u64);
            if copied > remaining_bytes {
                if let Some((parent, _)) = destination_file.take() {
                    // SAFETY: retained parent + component.
                    unsafe { libc::unlinkat(parent, name.as_ptr(), 0) };
                }
                return Err(ProjectCopyError::ByteCapExceeded);
            }
            hasher.update(&buffer[..read]);
            if let Some((_, file)) = destination_file.as_mut() {
                file.write_all(&buffer[..read]).map_err(|error| {
                    ProjectCopyError::Io(format!("copy project file '{relative}': {error}"))
                })?;
            }
        }
        if copied != size {
            if let Some((parent, _)) = destination_file.take() {
                // SAFETY: retained parent + component.
                unsafe { libc::unlinkat(parent, name.as_ptr(), 0) };
            }
            return Err(ProjectCopyError::ChangedDuringScan(relative.to_string()));
        }
        let after_metadata = source_file.metadata().map_err(|error| {
            ProjectCopyError::Io(format!("reinspect project file '{relative}': {error}"))
        })?;
        let after = stable_metadata(&after_metadata, b'f');
        if after != opened {
            if let Some((parent, _)) = destination_file.take() {
                // SAFETY: retained parent + component.
                unsafe { libc::unlinkat(parent, name.as_ptr(), 0) };
            }
            return Err(ProjectCopyError::ChangedDuringScan(relative.to_string()));
        }
        if let Some((_, file)) = destination_file.as_mut() {
            file.sync_all().map_err(|error| {
                ProjectCopyError::Io(format!("flush copied file '{relative}': {error}"))
            })?;
        }
        opened.digest = Some(format!("{:x}", hasher.finalize()));
        Ok(opened)
    }

    /// Reset `errno` so a NULL `readdir` can be classified.
    ///
    /// The symbol differs per libc, and on a platform this does not know how to
    /// clear, a stale non-zero `errno` makes the read look failed. That is the
    /// fail-closed direction: the copy refuses instead of returning a listing it
    /// cannot vouch for.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn clear_errno() {
        // SAFETY: __errno_location returns this thread's errno slot.
        unsafe { *libc::__errno_location() = 0 };
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly"
    ))]
    fn clear_errno() {
        // SAFETY: __error returns this thread's errno slot.
        unsafe { *libc::__error() = 0 };
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly"
    )))]
    fn clear_errno() {}

    /// `fdopendir` takes ownership of the descriptor it is handed, so this
    /// wrapper adopts an `OwnedFd` and releases it without a double close.
    struct DirStream(*mut libc::DIR);

    impl DirStream {
        fn adopt(fd: OwnedFd) -> std::io::Result<Self> {
            let raw = fd.as_raw_fd();
            // SAFETY: `raw` is a live directory descriptor this call takes over.
            let stream = unsafe { libc::fdopendir(raw) };
            if stream.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            // The stream owns the descriptor now; closedir will close it.
            std::mem::forget(fd);
            Ok(Self(stream))
        }

        fn next_name(&mut self) -> std::io::Result<Option<&CStr>> {
            // readdir returns NULL for both end-of-directory and error, so errno
            // is the only way to tell them apart. Clearing it first is what makes
            // "the directory ended" distinguishable from "the read failed", and
            // that distinction is load-bearing: a truncated listing would produce
            // a silently partial copy, the exact failure this module exists to
            // prevent.
            clear_errno();
            // SAFETY: the stream is live for the lifetime of this wrapper.
            let entry = unsafe { libc::readdir(self.0) };
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                return if error.raw_os_error() == Some(0) {
                    Ok(None)
                } else {
                    Err(error)
                };
            }
            // SAFETY: readdir returned a live entry owned by the stream, and the
            // borrow ends before the next readdir call.
            Ok(Some(unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }))
        }
    }

    impl Drop for DirStream {
        fn drop(&mut self) {
            // SAFETY: the stream was created by fdopendir and is closed once.
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
}

#[cfg(windows)]
mod windows_capability {
    use std::ffi::{OsStr, OsString};
    use std::io::{Read as _, Write as _};
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use std::path::{Component, Path, PathBuf};
    use std::ptr::{null, null_mut};

    use sha2::{Digest as _, Sha256};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FileIdBothDirectoryInformation, NtCreateFile, NtQueryDirectoryFile, FILE_CREATE,
        FILE_DIRECTORY_FILE, FILE_ID_BOTH_DIR_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
        FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, RtlNtStatusToDosError, HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE,
        STATUS_NO_MORE_FILES, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, OPEN_EXISTING, SYNCHRONIZE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    use super::{
        collision_key, directory_marker, display_relative, push_relative, reject_unsafe_name,
        roll_up_digest, ProjectCopyError, ProjectCopySummary, ProjectTree, StableEntry,
        StableSnapshot, EXCLUDED_NAME, MAX_PROJECT_BYTES, MAX_PROJECT_DEPTH, MAX_PROJECT_ENTRIES,
        MAX_PROJECT_FILES,
    };

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: this wrapper owns the handle exactly once.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    impl OwnedHandle {
        fn into_file(mut self) -> std::fs::File {
            let raw = self.0;
            self.0 = null_mut();
            // SAFETY: ownership transfers from this wrapper to File.
            unsafe { std::fs::File::from_raw_handle(raw) }
        }
    }

    struct DirCapability {
        handle: OwnedHandle,
        display: PathBuf,
    }

    fn io_error(operation: &str, error: std::io::Error) -> ProjectCopyError {
        ProjectCopyError::Io(format!("{operation}: {error}"))
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn safe_relative_name(name: &OsStr) -> std::io::Result<Vec<u16>> {
        let encoded = name.encode_wide().collect::<Vec<_>>();
        if encoded.is_empty()
            || (encoded.len() == 1 && encoded[0] == b'.' as u16)
            || (encoded.len() == 2 && encoded[0] == b'.' as u16 && encoded[1] == b'.' as u16)
            || encoded.iter().any(|unit| {
                *unit == 0 || *unit == b'/' as u16 || *unit == b'\\' as u16 || *unit == b':' as u16
            })
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unsafe Windows capability component",
            ));
        }
        Ok(encoded)
    }

    fn nt_open_relative(
        parent: HANDLE,
        display_parent: &Path,
        name: &OsStr,
        access: u32,
        disposition: u32,
        options: u32,
        attributes: u32,
    ) -> std::io::Result<OwnedHandle> {
        let mut encoded = safe_relative_name(name)?;
        let length = u16::try_from(encoded.len() * std::mem::size_of::<u16>()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Windows capability component is too long",
            )
        })?;
        let unicode = UNICODE_STRING {
            Length: length,
            MaximumLength: length,
            Buffer: encoded.as_mut_ptr(),
        };
        let attributes_block = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: parent,
            ObjectName: &unicode,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: null(),
            SecurityQualityOfService: null(),
        };
        let mut status_block = IO_STATUS_BLOCK::default();
        let mut handle: HANDLE = null_mut();
        // SAFETY: every pointer references live storage and RootDirectory is a
        // retained directory handle. ObjectName is one validated component.
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                access | SYNCHRONIZE,
                &attributes_block,
                &mut status_block,
                null(),
                attributes,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                disposition,
                options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                null(),
                0,
            )
        };
        if status < 0 {
            // SAFETY: translating an NTSTATUS has no memory preconditions.
            let code = unsafe { RtlNtStatusToDosError(status) };
            return Err(std::io::Error::new(
                std::io::Error::from_raw_os_error(code as i32).kind(),
                format!(
                    "open retained child {}: {}",
                    display_parent.join(name).display(),
                    std::io::Error::from_raw_os_error(code as i32)
                ),
            ));
        }
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::other(
                "NtCreateFile returned no retained handle",
            ));
        }
        Ok(OwnedHandle(handle))
    }

    fn handle_info(handle: HANDLE) -> std::io::Result<BY_HANDLE_FILE_INFORMATION> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: handle is live and info is writable.
        if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(info)
    }

    fn stable_facts(handle: HANDLE, kind: u8) -> Result<StableEntry, ProjectCopyError> {
        let info =
            handle_info(handle).map_err(|error| io_error("inspect retained handle", error))?;
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(ProjectCopyError::Symlink("retained handle".to_string()));
        }
        let is_directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        if (kind == b'd') != is_directory {
            return Err(ProjectCopyError::ChangedDuringScan(
                "retained handle".to_string(),
            ));
        }
        Ok(StableEntry {
            kind,
            device: info.dwVolumeSerialNumber as u64,
            inode: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
            mode: info.dwFileAttributes,
            links: info.nNumberOfLinks as u64,
            size: ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64,
            modified_seconds: info.ftLastWriteTime.dwHighDateTime as i64,
            modified_nanos: info.ftLastWriteTime.dwLowDateTime as i64,
            changed_seconds: info.ftCreationTime.dwHighDateTime as i64,
            changed_nanos: info.ftCreationTime.dwLowDateTime as i64,
            digest: None,
        })
    }

    impl DirCapability {
        fn open_tree(path: &Path) -> Result<Self, ProjectCopyError> {
            let mut anchor = PathBuf::new();
            let mut rest = Vec::<OsString>::new();
            let mut rooted = false;
            for component in path.components() {
                match component {
                    Component::Prefix(prefix) if !rooted => anchor.push(prefix.as_os_str()),
                    Component::RootDir if !rooted => {
                        anchor.push(component.as_os_str());
                        rooted = true;
                    }
                    Component::Normal(name) if rooted => rest.push(name.to_os_string()),
                    _ => {
                        return Err(ProjectCopyError::Io(
                            "Windows project root is not absolute and normalized".to_string(),
                        ))
                    }
                }
            }
            if !rooted {
                return Err(ProjectCopyError::Io(
                    "Windows project root has no volume root".to_string(),
                ));
            }
            let encoded = wide(&anchor);
            // SAFETY: encoded is NUL-terminated and this call returns a new
            // owned handle.
            let root = unsafe {
                CreateFileW(
                    encoded.as_ptr(),
                    FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    null_mut(),
                )
            };
            if root == INVALID_HANDLE_VALUE {
                return Err(io_error(
                    "open Windows volume root",
                    std::io::Error::last_os_error(),
                ));
            }
            let mut current = Self {
                handle: OwnedHandle(root),
                display: anchor,
            };
            stable_facts(current.handle.0, b'd')?;
            for name in rest {
                current = current.open_directory(&name)?;
            }
            Ok(current)
        }

        fn open_directory(&self, name: &OsStr) -> Result<Self, ProjectCopyError> {
            let handle = nt_open_relative(
                self.handle.0,
                &self.display,
                name,
                FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
                FILE_OPEN,
                FILE_DIRECTORY_FILE,
                FILE_ATTRIBUTE_DIRECTORY,
            )
            .map_err(|error| io_error("open project directory", error))?;
            stable_facts(handle.0, b'd')?;
            Ok(Self {
                handle,
                display: self.display.join(name),
            })
        }

        fn create_directory(&self, name: &OsStr) -> Result<Self, ProjectCopyError> {
            let handle = nt_open_relative(
                self.handle.0,
                &self.display,
                name,
                FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | FILE_GENERIC_WRITE,
                FILE_CREATE,
                FILE_DIRECTORY_FILE,
                FILE_ATTRIBUTE_DIRECTORY,
            )
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    ProjectCopyError::NameCollision(name.to_string_lossy().into_owned())
                } else {
                    io_error("create copied directory", error)
                }
            })?;
            Ok(Self {
                handle,
                display: self.display.join(name),
            })
        }

        fn open_file(&self, name: &OsStr) -> Result<OwnedHandle, ProjectCopyError> {
            nt_open_relative(
                self.handle.0,
                &self.display,
                name,
                FILE_GENERIC_READ | FILE_READ_ATTRIBUTES,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE,
                FILE_ATTRIBUTE_NORMAL,
            )
            .map_err(|error| io_error("open project file", error))
        }

        fn create_file(&self, name: &OsStr) -> Result<OwnedHandle, ProjectCopyError> {
            nt_open_relative(
                self.handle.0,
                &self.display,
                name,
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES,
                FILE_CREATE,
                FILE_NON_DIRECTORY_FILE,
                FILE_ATTRIBUTE_NORMAL,
            )
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    ProjectCopyError::NameCollision(name.to_string_lossy().into_owned())
                } else {
                    io_error("create copied file", error)
                }
            })
        }

        fn names(&self, budget: usize, relative: &str) -> Result<Vec<OsString>, ProjectCopyError> {
            const BUFFER_SIZE: usize = 64 * 1024;
            let mut buffer = vec![0u8; BUFFER_SIZE];
            let mut result = Vec::new();
            let mut restart = true;
            loop {
                let mut io_status = IO_STATUS_BLOCK::default();
                // SAFETY: the directory handle is synchronous and retained;
                // buffer and status storage are live for the whole call.
                let status = unsafe {
                    NtQueryDirectoryFile(
                        self.handle.0,
                        null_mut(),
                        None,
                        null(),
                        &mut io_status,
                        buffer.as_mut_ptr().cast(),
                        buffer.len() as u32,
                        FileIdBothDirectoryInformation,
                        false,
                        null(),
                        restart,
                    )
                };
                restart = false;
                if status == STATUS_NO_MORE_FILES {
                    break;
                }
                if status < 0 {
                    // SAFETY: pure status translation.
                    let code = unsafe { RtlNtStatusToDosError(status) };
                    return Err(io_error(
                        "enumerate retained project directory",
                        std::io::Error::from_raw_os_error(code as i32),
                    ));
                }
                let used = io_status.Information.min(buffer.len());
                if used == 0 {
                    return Err(ProjectCopyError::Io(
                        "retained Windows directory enumeration made no progress".to_string(),
                    ));
                }
                let mut offset = 0usize;
                while offset < used {
                    let name_offset = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFORMATION, FileName);
                    let record_remaining = used.saturating_sub(offset);
                    if record_remaining < name_offset + std::mem::size_of::<u16>() {
                        return Err(ProjectCopyError::Io(
                            "truncated retained Windows directory record".to_string(),
                        ));
                    }
                    // SAFETY: the kernel returned a chain of aligned directory
                    // records inside `used` bytes.
                    let info = unsafe {
                        std::ptr::read_unaligned(
                            buffer
                                .as_ptr()
                                .add(offset)
                                .cast::<FILE_ID_BOTH_DIR_INFORMATION>(),
                        )
                    };
                    if name_offset.saturating_add(info.FileNameLength as usize) > record_remaining
                        || info.FileNameLength as usize % std::mem::size_of::<u16>() != 0
                    {
                        return Err(ProjectCopyError::Io(
                            "malformed retained Windows directory record".to_string(),
                        ));
                    }
                    let units = info.FileNameLength as usize / std::mem::size_of::<u16>();
                    let name_bytes = &buffer
                        [offset + name_offset..offset + name_offset + info.FileNameLength as usize];
                    let wide_name = name_bytes
                        .chunks_exact(std::mem::size_of::<u16>())
                        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
                        .collect::<Vec<_>>();
                    debug_assert_eq!(wide_name.len(), units);
                    let name = OsString::from_wide(&wide_name);
                    if name != "." && name != ".." {
                        if result.len() >= budget {
                            return Err(ProjectCopyError::EntryCapExceeded(display_relative(
                                relative,
                            )));
                        }
                        result.push(name);
                    }
                    if info.NextEntryOffset == 0 {
                        break;
                    }
                    if info.NextEntryOffset as usize > record_remaining
                        || (info.NextEntryOffset as usize) < name_offset
                    {
                        return Err(ProjectCopyError::Io(
                            "malformed retained Windows directory chain".to_string(),
                        ));
                    }
                    offset = offset.saturating_add(info.NextEntryOffset as usize);
                }
            }
            Ok(result)
        }
    }

    struct ScanState {
        entries: std::collections::BTreeMap<String, StableEntry>,
        summary: ProjectCopySummary,
        entries_seen: usize,
        root_device: u64,
    }

    fn scan_file(
        source: &DirCapability,
        destination: Option<&DirCapability>,
        name: &OsStr,
        relative: &str,
        remaining: u64,
    ) -> Result<StableEntry, ProjectCopyError> {
        let source_handle = source.open_file(name)?;
        let mut before = stable_facts(source_handle.0, b'f')?;
        if before.links > 1 {
            return Err(ProjectCopyError::HardLink(relative.to_string()));
        }
        if before.size > remaining {
            return Err(ProjectCopyError::ByteCapExceeded);
        }
        let mut source_file = source_handle.into_file();
        let mut destination_file = destination
            .map(|destination| destination.create_file(name).map(OwnedHandle::into_file))
            .transpose()?;
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = source_file
                .read(&mut buffer)
                .map_err(|error| io_error("read retained project file", error))?;
            if read == 0 {
                break;
            }
            size = size.saturating_add(read as u64);
            if size > remaining {
                return Err(ProjectCopyError::ByteCapExceeded);
            }
            hasher.update(&buffer[..read]);
            if let Some(destination) = destination_file.as_mut() {
                destination
                    .write_all(&buffer[..read])
                    .map_err(|error| io_error("write retained project copy", error))?;
            }
        }
        if let Some(destination) = destination_file.as_mut() {
            destination
                .sync_all()
                .map_err(|error| io_error("flush retained project copy", error))?;
        }
        let after = stable_facts(source_file.as_raw_handle(), b'f')?;
        if before != after || size != before.size {
            return Err(ProjectCopyError::ChangedDuringScan(relative.to_string()));
        }
        before.digest = Some(format!("{:x}", hasher.finalize()));
        Ok(before)
    }

    fn scan_directory(
        source: &DirCapability,
        destination: Option<&DirCapability>,
        relative_dir: &str,
        depth: usize,
        excluded: Option<&str>,
        state: &mut ScanState,
    ) -> Result<(), ProjectCopyError> {
        let before = stable_facts(source.handle.0, b'd')?;
        let names = source.names(
            MAX_PROJECT_ENTRIES.saturating_sub(state.entries_seen),
            relative_dir,
        )?;
        state.entries_seen = state.entries_seen.saturating_add(names.len());
        let mut collisions = std::collections::BTreeSet::new();
        for raw_name in names {
            let Some(name) = raw_name.to_str() else {
                return Err(ProjectCopyError::NameNotUtf8(display_relative(
                    relative_dir,
                )));
            };
            let relative = push_relative(relative_dir, name);
            reject_unsafe_name(name, &relative)?;
            if name == EXCLUDED_NAME || excluded == Some(relative.as_str()) {
                continue;
            }
            if !collisions.insert(collision_key(name)) {
                return Err(ProjectCopyError::NameCollision(display_relative(
                    relative_dir,
                )));
            }
            let child_directory = source.open_directory(&raw_name);
            match child_directory {
                Ok(child) => {
                    if depth + 1 > MAX_PROJECT_DEPTH {
                        return Err(ProjectCopyError::DepthCapExceeded(relative));
                    }
                    let facts = stable_facts(child.handle.0, b'd')?;
                    if facts.device != state.root_device {
                        return Err(ProjectCopyError::Escape(relative));
                    }
                    let destination_child = destination
                        .map(|destination| destination.create_directory(&raw_name))
                        .transpose()?;
                    state.entries.insert(relative.clone(), facts);
                    state.summary.directory_count += 1;
                    scan_directory(
                        &child,
                        destination_child.as_ref(),
                        &relative,
                        depth + 1,
                        excluded,
                        state,
                    )?;
                }
                Err(ProjectCopyError::Io(_)) => {
                    if state.summary.file_count >= MAX_PROJECT_FILES {
                        return Err(ProjectCopyError::FileCapExceeded);
                    }
                    let remaining = MAX_PROJECT_BYTES.saturating_sub(state.summary.total_bytes);
                    let facts = scan_file(source, destination, &raw_name, &relative, remaining)?;
                    if facts.device != state.root_device {
                        return Err(ProjectCopyError::Escape(relative));
                    }
                    state.summary.file_count += 1;
                    state.summary.total_bytes =
                        state.summary.total_bytes.saturating_add(facts.size);
                    state.entries.insert(relative, facts);
                }
                Err(error) => return Err(error),
            }
        }
        if stable_facts(source.handle.0, b'd')? != before {
            return Err(ProjectCopyError::ChangedDuringScan(display_relative(
                relative_dir,
            )));
        }
        Ok(())
    }

    fn scan(
        source: &DirCapability,
        destination: Option<&DirCapability>,
        excluded: Option<&str>,
    ) -> Result<StableSnapshot, ProjectCopyError> {
        let root = stable_facts(source.handle.0, b'd')?;
        let mut state = ScanState {
            entries: std::collections::BTreeMap::new(),
            summary: ProjectCopySummary {
                file_count: 0,
                directory_count: 0,
                total_bytes: 0,
            },
            entries_seen: 0,
            root_device: root.device,
        };
        scan_directory(source, destination, "", 0, excluded, &mut state)?;
        if stable_facts(source.handle.0, b'd')? != root {
            return Err(ProjectCopyError::ChangedDuringScan(".".to_string()));
        }
        Ok(StableSnapshot {
            root,
            entries: state.entries,
            summary: state.summary,
        })
    }

    fn visible_matches(path: &Path, held: &DirCapability) -> Result<bool, ProjectCopyError> {
        let visible = match DirCapability::open_tree(path) {
            Ok(visible) => visible,
            Err(_) => return Ok(false),
        };
        let visible = stable_facts(visible.handle.0, b'd')?;
        let held = stable_facts(held.handle.0, b'd')?;
        Ok(visible.device == held.device && visible.inode == held.inode)
    }

    pub(super) fn copy_stable(
        source_root: &Path,
        destination_root: &Path,
        excluded: Option<&str>,
    ) -> Result<ProjectCopySummary, ProjectCopyError> {
        let source = DirCapability::open_tree(source_root)?;
        let destination = DirCapability::open_tree(destination_root)?;
        let source_identity = stable_facts(source.handle.0, b'd')?;
        let destination_identity = stable_facts(destination.handle.0, b'd')?;
        if source_identity.device == destination_identity.device
            && source_identity.inode == destination_identity.inode
        {
            return Err(ProjectCopyError::Destination(
                "destination is the retained project root itself".to_string(),
            ));
        }
        if !destination.names(1, "")?.is_empty() {
            return Err(ProjectCopyError::Destination(
                "destination is not empty".to_string(),
            ));
        }
        let first = scan(&source, None, excluded)?;
        super::run_between_stable_passes_hook();
        if !visible_matches(source_root, &source)? {
            return Err(ProjectCopyError::ChangedDuringScan(".".to_string()));
        }
        let second = scan(&source, Some(&destination), excluded)?;
        if first != second
            || !visible_matches(source_root, &source)?
            || !visible_matches(destination_root, &destination)?
        {
            return Err(ProjectCopyError::ChangedDuringScan(".".to_string()));
        }
        Ok(second.summary)
    }

    pub(super) fn inventory_stable(
        root: &Path,
        excluded: Option<&str>,
    ) -> Result<ProjectTree, ProjectCopyError> {
        let source = DirCapability::open_tree(root)?;
        let first = scan(&source, None, excluded)?;
        super::run_between_stable_passes_hook();
        if !visible_matches(root, &source)? {
            return Err(ProjectCopyError::ChangedDuringScan(".".to_string()));
        }
        let second = scan(&source, None, excluded)?;
        if first != second || !visible_matches(root, &source)? {
            return Err(ProjectCopyError::ChangedDuringScan(".".to_string()));
        }
        let entries = first
            .entries
            .into_iter()
            .map(|(relative, facts)| {
                let marker = if facts.kind == b'd' {
                    directory_marker()
                } else {
                    format!(
                        "f:{}",
                        facts.digest.expect("stable regular file has a digest")
                    )
                };
                (relative, marker)
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let digest = roll_up_digest(&entries);
        Ok(ProjectTree {
            file_count: first.summary.file_count,
            total_bytes: first.summary.total_bytes,
            digest,
            complete: true,
            entries,
        })
    }
}

fn reject_unsafe_name(name: &str, relative: &str) -> Result<(), ProjectCopyError> {
    let unsafe_name = name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0');
    if unsafe_name {
        return Err(ProjectCopyError::UnsafeName(relative.to_string()));
    }
    Ok(())
}

/// The in-process collision key: Unicode-normalized (NFKC) and case folded, so
/// `README.md` / `readme.md` and NFC / NFD spellings of one name collide on
/// every platform, not only on a case-insensitive destination.
fn collision_key(name: &str) -> String {
    name.nfkc().collect::<String>().to_lowercase()
}

fn join_relative(root: &Path, relative: &str) -> PathBuf {
    if relative.is_empty() {
        root.to_path_buf()
    } else {
        root.join(relative)
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

/// Inventory a quiescent tree through one retained root capability in exactly
/// two passes. Unlike [`inventory_project_tree`], this is the security boundary
/// used by capsule execution: mutation is an error, not a partial digest.
pub fn inventory_project_tree_stable(
    root: &Path,
    excluded_relative: Option<&Path>,
) -> Result<ProjectTree, ProjectCopyError> {
    let root = trusted_project_root(root)?;
    let excluded = normalize_exclusion(excluded_relative)?;
    #[cfg(unix)]
    {
        let held = fd::open_directory_tree(&root)
            .map_err(|error| ProjectCopyError::Io(format!("open inventory root: {error}")))?;
        let first = first_stable_pass(&held, excluded.as_deref())?;
        run_between_stable_passes_hook();
        if !fd::visible_directory_matches(&root, &held)? {
            return Err(ProjectCopyError::ChangedDuringScan(".".to_string()));
        }
        let second = first_stable_pass(&held, excluded.as_deref())?;
        if first != second || !fd::visible_directory_matches(&root, &held)? {
            return Err(ProjectCopyError::ChangedDuringScan(".".to_string()));
        }
        let entries = first
            .entries
            .into_iter()
            .map(|(relative, facts)| {
                let marker = if facts.kind == b'd' {
                    directory_marker()
                } else {
                    format!(
                        "f:{}",
                        facts.digest.expect("stable regular file has a digest")
                    )
                };
                (relative, marker)
            })
            .collect::<BTreeMap<_, _>>();
        let digest = roll_up_digest(&entries);
        Ok(ProjectTree {
            file_count: first.summary.file_count,
            total_bytes: first.summary.total_bytes,
            digest,
            complete: true,
            entries,
        })
    }
    #[cfg(not(unix))]
    {
        // Windows is implemented by the retained-handle walker below; targets
        // without either openat or Windows NT relative handles fail closed.
        stable_non_unix_inventory(&root, excluded.as_deref())
    }
}

#[cfg(windows)]
fn stable_non_unix_inventory(
    root: &Path,
    excluded_relative: Option<&str>,
) -> Result<ProjectTree, ProjectCopyError> {
    windows_capability::inventory_stable(root, excluded_relative)
}

#[cfg(not(any(unix, windows)))]
fn stable_non_unix_inventory(
    _root: &Path,
    _excluded_relative: Option<&str>,
) -> Result<ProjectTree, ProjectCopyError> {
    Err(ProjectCopyError::Io(
        "stable project inventory is unavailable on this platform".to_string(),
    ))
}

/// Inventory `root` into a bounded, order-independent tree digest.
///
/// Deliberately tolerant: this runs over a tree the contained child may have
/// written to, so a symlink, a special file, an unreadable entry, or a cap is
/// RECORDED (and clears [`ProjectTree::complete`]) rather than failing the whole
/// receipt. Directories are recorded too, so a newly created empty directory is
/// visible in the diff.
pub fn inventory_project_tree(root: &Path) -> ProjectTree {
    let mut entries: BTreeMap<String, String> = BTreeMap::new();
    let mut file_count = 0usize;
    let mut total_bytes = 0u64;
    let mut complete = true;
    let mut pending: Vec<(String, usize)> = vec![(String::new(), 0)];

    while let Some((relative_dir, depth)) = pending.pop() {
        let directory = join_relative(root, &relative_dir);
        let Ok(reader) = std::fs::read_dir(&directory) else {
            complete = false;
            continue;
        };
        for entry in reader {
            let Ok(entry) = entry else {
                complete = false;
                continue;
            };
            if entries.len() >= MAX_PROJECT_FILES {
                complete = false;
                break;
            }
            let raw_name = entry.file_name();
            let Some(name) = raw_name.to_str() else {
                complete = false;
                continue;
            };
            let relative = push_relative(&relative_dir, name);
            let path = directory.join(name);
            let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                complete = false;
                continue;
            };
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                let marker = match std::fs::read_link(&path) {
                    Ok(target) => format!("l:{}", sha256_hex(target.to_string_lossy().as_bytes())),
                    Err(_) => {
                        complete = false;
                        "l:unreadable".to_string()
                    }
                };
                entries.insert(relative, marker);
                continue;
            }
            if file_type.is_dir() {
                entries.insert(relative.clone(), directory_marker());
                if depth + 1 > MAX_PROJECT_DEPTH {
                    complete = false;
                    continue;
                }
                pending.push((relative, depth + 1));
                continue;
            }
            if !file_type.is_file() {
                entries.insert(relative, "s".to_string());
                complete = false;
                continue;
            }
            let remaining = MAX_PROJECT_BYTES.saturating_sub(total_bytes);
            let marker = match open_read_no_follow_capped(&path, remaining) {
                Ok(handle) => match crate::util::sha256_from_handle(handle, remaining) {
                    Ok(HashOutcome::Digest(digest)) => {
                        total_bytes = total_bytes.saturating_add(metadata.len());
                        file_count += 1;
                        format!("f:{digest}")
                    }
                    Ok(HashOutcome::BudgetExceeded) | Err(_) => {
                        complete = false;
                        "f:unhashed".to_string()
                    }
                },
                Err(_) => {
                    complete = false;
                    "f:unreadable".to_string()
                }
            };
            entries.insert(relative, marker);
        }
    }

    let digest = roll_up_digest(&entries);
    ProjectTree {
        file_count,
        total_bytes,
        digest,
        complete,
        entries,
    }
}

/// Roll a sorted `relative path -> marker` map into one digest. Sorting makes it
/// order-independent, and the NUL/newline framing keeps two different maps from
/// serializing to the same bytes.
fn roll_up_digest(entries: &BTreeMap<String, String>) -> String {
    let mut payload = String::with_capacity(TREE_DIGEST_TAG.len() + entries.len() * 80);
    payload.push_str(TREE_DIGEST_TAG);
    for (relative, marker) in entries {
        payload.push_str(relative);
        payload.push('\0');
        payload.push_str(marker);
        payload.push('\n');
    }
    sha256_hex(payload.as_bytes())
}

/// Bounded difference between two inventories of the same tree.
pub fn diff_project_trees(before: &ProjectTree, after: &ProjectTree) -> ProjectDiff {
    let mut diff = ProjectDiff::default();
    for (relative, marker) in &after.entries {
        match before.entries.get(relative) {
            None => push_bounded(&mut diff.added, relative, &mut diff.truncated),
            Some(previous) if previous != marker => {
                push_bounded(&mut diff.modified, relative, &mut diff.truncated)
            }
            Some(_) => {}
        }
    }
    for relative in before.entries.keys() {
        if !after.entries.contains_key(relative) {
            push_bounded(&mut diff.removed, relative, &mut diff.truncated);
        }
    }
    if !before.complete || !after.complete {
        diff.truncated = true;
    }
    diff
}

fn push_bounded(bucket: &mut Vec<String>, relative: &str, truncated: &mut bool) {
    if bucket.len() >= MAX_DIFF_ENTRIES {
        *truncated = true;
        return;
    }
    // Measured in bytes, which is what the receipt size limit is measured in. A
    // character count lets 256 four-byte scalars through as 1 KiB.
    if relative.len() > MAX_DIFF_PATH_BYTES {
        *truncated = true;
        bucket.push(crate::util::truncate_bytes(relative, MAX_DIFF_PATH_BYTES));
        return;
    }
    bucket.push(relative.to_string());
}

/// Digest the EXACT argv the preset will launch, so the receipt binds what ran
/// without recording the argument strings themselves. Each element is
/// length-prefixed, so `["ab", "c"]` and `["a", "bc"]` cannot collide.
pub fn argv_digest(argv: &[std::ffi::OsString]) -> String {
    let mut payload: Vec<u8> = Vec::with_capacity(ARGV_DIGEST_TAG.len() + argv.len() * 16);
    payload.extend_from_slice(ARGV_DIGEST_TAG.as_bytes());
    payload.extend_from_slice(argv.len().to_string().as_bytes());
    payload.push(b'\n');
    for element in argv {
        let bytes = os_str_bytes(element);
        payload.extend_from_slice(bytes.len().to_string().as_bytes());
        payload.push(b'\0');
        payload.extend_from_slice(&bytes);
        payload.push(b'\n');
    }
    sha256_hex(&payload)
}

#[cfg(unix)]
fn os_str_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt as _;
    value.as_bytes().to_vec()
}

#[cfg(not(unix))]
fn os_str_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    value.to_string_lossy().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(path, contents).expect("write fixture file");
    }

    fn empty_destination(base: &Path) -> PathBuf {
        let destination = base.join("copy");
        std::fs::create_dir(&destination).expect("create destination");
        destination
    }

    #[test]
    fn copies_a_plain_tree_and_excludes_git_at_every_depth() {
        let base = tempfile::tempdir().expect("tempdir");
        let source = base.path().join("project");
        write(&source, "README.md", "hello");
        write(&source, "src/main.rs", "fn main() {}");
        write(&source, ".git/config", "[core]");
        write(&source, "vendor/dep/.git", "gitdir: ../../.git/modules/dep");
        write(&source, "vendor/dep/lib.rs", "pub fn f() {}");
        let destination = empty_destination(base.path());

        let summary = copy_project_tree(&source, &destination).expect("copy succeeds");
        assert_eq!(summary.file_count, 3);
        assert!(destination.join("README.md").exists());
        assert!(destination.join("src/main.rs").exists());
        assert!(destination.join("vendor/dep/lib.rs").exists());
        assert!(!destination.join(".git").exists());
        assert!(!destination.join("vendor/dep/.git").exists());
        assert_eq!(
            std::fs::read_to_string(destination.join("README.md")).expect("read copy"),
            "hello",
            "the copy must be byte-faithful, not just present"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_copy_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        // The held copy sits in a shared /tmp. A world-readable copy of an
        // untrusted project is a leak in one direction and a tamper surface in
        // the other, so both the directories and the files are owner-only.
        let base = tempfile::tempdir().expect("tempdir");
        let source = base.path().join("project");
        write(&source, "src/main.rs", "fn main() {}");
        let destination = empty_destination(base.path());
        copy_project_tree(&source, &destination).expect("copy succeeds");

        // Asserted as "no group or other bits" rather than an exact mode: that
        // is the actual security property, and it stays true under any umask
        // (a umask can only CLEAR bits, never add them).
        let directory = std::fs::metadata(destination.join("src")).expect("stat dir");
        assert_eq!(directory.permissions().mode() & 0o077, 0);
        let file = std::fs::metadata(destination.join("src/main.rs")).expect("stat file");
        assert_eq!(file.permissions().mode() & 0o077, 0);
    }

    #[cfg(unix)]
    #[test]
    fn copy_modes_are_exact_and_preserve_only_executable_intent_under_umask() {
        use std::os::unix::fs::PermissionsExt as _;

        const CHILD_ENV: &str = "TIRITH_CAPSULE_PROJECT_RESTRICTIVE_UMASK_CHILD";
        if std::env::var_os(CHILD_ENV).is_none() {
            // umask is process-global, not thread-local. Run the mutation in an
            // exact child test process so this regression cannot make fixtures
            // created by parallel tests mode 000.
            let output = std::process::Command::new(
                std::env::current_exe().expect("resolve current test executable"),
            )
            .args([
                "--exact",
                "capsule_project::tests::copy_modes_are_exact_and_preserve_only_executable_intent_under_umask",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .output()
            .expect("run restrictive-umask child test");
            assert!(
                output.status.success(),
                "restrictive-umask child failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let base = tempfile::tempdir().expect("tempdir");
        let source = base.path().join("project");
        write(&source, "bin/tool", "#!/bin/sh\nexit 0\n");
        write(&source, "data.txt", "data");
        std::fs::set_permissions(
            source.join("bin/tool"),
            std::fs::Permissions::from_mode(0o6755),
        )
        .expect("source executable mode");
        std::fs::set_permissions(
            source.join("data.txt"),
            std::fs::Permissions::from_mode(0o4666),
        )
        .expect("source data mode");
        let destination = empty_destination(base.path());

        // SAFETY: serialized with the shared process-global guard and restored
        // before that guard is released.
        let previous = unsafe { libc::umask(0o777) };
        struct Restore(libc::mode_t);
        impl Drop for Restore {
            fn drop(&mut self) {
                // SAFETY: this guard still owns the shared global lock.
                unsafe { libc::umask(self.0) };
            }
        }
        let _restore = Restore(previous);
        copy_project_tree(&source, &destination).expect("copy succeeds under restrictive umask");

        assert_eq!(
            std::fs::metadata(destination.join("bin"))
                .expect("directory")
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(destination.join("bin/tool"))
                .expect("executable")
                .permissions()
                .mode()
                & 0o7777,
            0o700,
            "executable intent survives but set-id and group/other bits do not"
        );
        assert_eq!(
            std::fs::metadata(destination.join("data.txt"))
                .expect("data")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }

    #[cfg(any(unix, windows))]
    fn install_between_passes(hook: impl FnMut() + 'static) {
        BETWEEN_STABLE_PASSES_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn same_size_content_change_is_refused_without_retry() {
        let base = tempfile::tempdir().expect("tempdir");
        let source = base.path().join("project");
        write(&source, "same.bin", "AAAA");
        let destination = empty_destination(base.path());
        let changed = source.join("same.bin");
        install_between_passes(move || std::fs::write(&changed, "BBBB").expect("mutate"));

        let error = copy_project_tree(&source, &destination).expect_err("mutation refuses");
        assert!(matches!(error, ProjectCopyError::ChangedDuringScan(_)));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn visible_root_replacement_is_refused() {
        let base = tempfile::tempdir().expect("tempdir");
        let source = base.path().join("project");
        write(&source, "sub/file", "data");
        let destination = empty_destination(base.path());
        let source_for_hook = source.clone();
        install_between_passes(move || {
            let moved = source_for_hook.with_extension("moved");
            std::fs::rename(&source_for_hook, &moved).expect("move retained root");
            std::fs::create_dir(&source_for_hook).expect("plant replacement root");
        });
        let error = copy_project_tree(&source, &destination).expect_err("replacement refuses");
        assert!(matches!(error, ProjectCopyError::ChangedDuringScan(_)));
    }

    #[cfg(unix)]
    #[test]
    fn directory_mode_changes_are_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let base = tempfile::tempdir().expect("tempdir");
        let source = base.path().join("project");
        write(&source, "sub/file", "data");
        let destination = empty_destination(base.path());
        let source_for_hook = source.clone();
        install_between_passes(move || {
            std::fs::set_permissions(
                source_for_hook.join("sub"),
                std::fs::Permissions::from_mode(0o711),
            )
            .expect("change directory mode");
        });
        let error = copy_project_tree(&source, &destination).expect_err("mutation refuses");
        assert!(matches!(error, ProjectCopyError::ChangedDuringScan(_)));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn membership_add_remove_and_rename_are_all_refused() {
        for mutation in ["add", "remove", "rename"] {
            let base = tempfile::tempdir().expect("tempdir");
            let source = base.path().join("project");
            write(&source, "keep", "data");
            write(&source, "remove", "gone");
            let destination = empty_destination(base.path());
            let source_for_hook = source.clone();
            install_between_passes(move || match mutation {
                "add" => std::fs::write(source_for_hook.join("added"), "new").expect("add"),
                "remove" => std::fs::remove_file(source_for_hook.join("remove")).expect("remove"),
                "rename" => std::fs::rename(
                    source_for_hook.join("keep"),
                    source_for_hook.join("renamed"),
                )
                .expect("rename"),
                _ => unreachable!(),
            });
            let error = copy_project_tree(&source, &destination).expect_err("mutation refuses");
            assert!(
                matches!(error, ProjectCopyError::ChangedDuringScan(_)),
                "{mutation}: {error:?}"
            );
        }
    }

    #[test]
    fn receipt_exclusion_is_exact_not_a_basename_or_prefix_filter() {
        let base = tempfile::tempdir().expect("tempdir");
        let source = base.path().join("project");
        write(&source, "receipts/run.json", "old receipt");
        write(&source, "nested/run.json", "ordinary project file");
        write(&source, "receipts/run.json.extra", "ordinary sibling");
        let destination = empty_destination(base.path());

        copy_project_tree_excluding(&source, &destination, Some(Path::new("receipts/run.json")))
            .expect("copy succeeds");
        assert!(!destination.join("receipts/run.json").exists());
        assert!(destination.join("nested/run.json").exists());
        assert!(destination.join("receipts/run.json.extra").exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_var_alias_is_the_only_explicit_root_alias() {
        assert_eq!(
            trusted_project_root(Path::new("/var/folders/example")).expect("trusted alias"),
            Path::new("/private/var/folders/example")
        );
        assert_eq!(
            trusted_project_root(Path::new("/tmp/example")).expect("ordinary path"),
            Path::new("/tmp/example")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_refused_not_skipped() {
        let base = tempfile::tempdir().expect("tempdir");
        let source = base.path().join("project");
        write(&source, "real.txt", "data");
        std::os::unix::fs::symlink("real.txt", source.join("link.txt")).expect("symlink");
        let destination = empty_destination(base.path());

        let error = copy_project_tree(&source, &destination).expect_err("symlink refuses");
        assert!(matches!(error, ProjectCopyError::Symlink(ref rel) if rel == "link.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn an_escaping_symlinked_directory_is_refused() {
        let base = tempfile::tempdir().expect("tempdir");
        let source = base.path().join("project");
        write(&source, "keep.txt", "data");
        let outside = base.path().join("outside");
        std::fs::create_dir_all(&outside).expect("outside");
        std::os::unix::fs::symlink(&outside, source.join("escape")).expect("symlink");
        let destination = empty_destination(base.path());

        let error = copy_project_tree(&source, &destination).expect_err("escape refuses");
        assert!(matches!(error, ProjectCopyError::Symlink(_)));
        assert!(!destination.join("escape").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_hardlinked_file_is_refused_rather_than_copied() {
        // The attacker-authored repository carries `assets/logo.png` as a second
        // name for the operator's private key. Nothing in a walk of the project
        // can see the other name, so the only safe answer is to refuse.
        let base = tempfile::tempdir().expect("tempdir");
        let outside = base.path().join("home/.ssh");
        std::fs::create_dir_all(&outside).expect("outside");
        let secret = outside.join("id_ed25519");
        std::fs::write(&secret, "PRIVATE-KEY-BYTES").expect("write secret");

        let source = base.path().join("project");
        std::fs::create_dir_all(source.join("assets")).expect("assets");
        std::fs::hard_link(&secret, source.join("assets/logo.png")).expect("hard link");
        let destination = empty_destination(base.path());

        let error = copy_project_tree(&source, &destination).expect_err("a hardlink refuses");
        assert!(
            matches!(error, ProjectCopyError::HardLink(ref rel) if rel == "assets/logo.png"),
            "expected a hardlink refusal, got {error:?}"
        );
        assert!(
            !destination.join("assets/logo.png").exists(),
            "the smuggled content must not reach the tree the child can read"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_walk_retains_descriptors_by_depth_not_by_width() {
        // A vendored dependency tree is wide, not deep. Retaining a descriptor
        // pair per unvisited sibling exhausts RLIMIT_NOFILE on an ordinary
        // project, which an attacker can also force deliberately.
        const SIBLINGS: usize = 400;

        let base = tempfile::tempdir().expect("tempdir");
        let source = base.path().join("project");
        for index in 0..SIBLINGS {
            std::fs::create_dir_all(source.join(format!("d{index:05}/nested")))
                .expect("create sibling");
        }
        let destination = empty_destination(base.path());

        let mut peak = 0usize;
        let summary = copy_tree_impl_observed(
            &std::fs::canonicalize(&source).expect("canonical source"),
            &std::fs::canonicalize(&destination).expect("canonical destination"),
            &mut |retained| peak = peak.max(retained),
        )
        .expect("a wide tree copies");
        assert_eq!(summary.directory_count, SIBLINGS * 2);
        assert!(
            peak <= MAX_PROJECT_DEPTH,
            "retained levels ({peak}) must be bounded by the depth cap, not by the {SIBLINGS} siblings"
        );
        assert!(
            peak <= 3,
            "a two-level tree must never retain more than three levels at once, got {peak}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_listing_past_the_entry_budget_is_refused() {
        let base = tempfile::tempdir().expect("tempdir");
        let source = base.path().join("project");
        std::fs::create_dir_all(&source).expect("source");
        for index in 0..5 {
            std::fs::write(source.join(format!("f{index}")), "x").expect("write");
        }
        let canonical = std::fs::canonicalize(&source).expect("canonical");
        // A fresh descriptor per read: the reader duplicates the descriptor it is
        // given, and a duplicate shares the directory offset.
        let error = fd::read_entry_names(
            &fd::open_directory(&canonical).expect("open source"),
            2,
            "vendor",
        )
        .expect_err("the budget refuses");
        assert!(
            matches!(error, ProjectCopyError::EntryCapExceeded(ref rel) if rel == "vendor"),
            "expected an entry-cap refusal, got {error:?}"
        );
        assert_eq!(
            fd::read_entry_names(
                &fd::open_directory(&canonical).expect("reopen source"),
                5,
                ""
            )
            .expect("fits")
            .len(),
            5
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_is_refused() {
        let base = tempfile::tempdir().expect("tempdir");
        let source = base.path().join("project");
        std::fs::create_dir_all(&source).expect("source");
        let fifo = source.join("pipe");
        let name = std::ffi::CString::new(fifo.to_string_lossy().as_bytes()).expect("cstring");
        // SAFETY: the path buffer is NUL-terminated and lives across the call.
        let made = unsafe { libc::mkfifo(name.as_ptr(), 0o600) };
        if made != 0 {
            return;
        }
        let destination = empty_destination(base.path());

        let error = copy_project_tree(&source, &destination).expect_err("fifo refuses");
        assert!(matches!(error, ProjectCopyError::UnsupportedEntry(ref rel) if rel == "pipe"));
    }

    #[test]
    fn a_case_collision_is_refused() {
        let base = tempfile::tempdir().expect("tempdir");
        let source = base.path().join("project");
        write(&source, "README.md", "one");
        // A case-insensitive host cannot hold both names, so the fixture itself
        // is impossible there; the in-process key still proves the rule below.
        let second = source.join("readme.md");
        if std::fs::metadata(&second).is_ok() {
            assert_eq!(collision_key("README.md"), collision_key("readme.md"));
            return;
        }
        std::fs::write(&second, "two").expect("write second name");
        let destination = empty_destination(base.path());

        let error = copy_project_tree(&source, &destination).expect_err("collision refuses");
        assert!(matches!(error, ProjectCopyError::NameCollision(_)));
    }

    #[test]
    fn unicode_and_case_collision_keys_agree() {
        assert_eq!(collision_key("README.md"), collision_key("readme.md"));
        // NFD "e" + combining acute folds onto NFC "e-acute".
        assert_eq!(collision_key("cafe\u{0301}.txt"), collision_key("café.txt"));
        assert_ne!(collision_key("a.txt"), collision_key("b.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn the_byte_cap_refuses_rather_than_truncating() {
        use std::os::fd::AsRawFd as _;

        let base = tempfile::tempdir().expect("tempdir");
        let source = base.path().join("project");
        write(&source, "big.bin", &"x".repeat(4096));
        let destination = empty_destination(base.path());

        // The public cap is 2 GiB, so the refusal is proved against the real
        // per-file helper with a deliberately tiny remaining budget rather than
        // by materializing two gigabytes.
        let source_fd = fd::open_directory(&source).expect("open source");
        let destination_fd = fd::open_directory(&destination).expect("open destination");
        let name = std::ffi::CString::new("big.bin").expect("cstring");
        let observed = fd::stat_at(source_fd.as_raw_fd(), &name).expect("stat entry");
        let error = fd::copy_file_at(
            source_fd.as_raw_fd(),
            destination_fd.as_raw_fd(),
            &name,
            &observed,
            "big.bin",
            10,
        )
        .expect_err("byte cap refuses");
        assert_eq!(error, ProjectCopyError::ByteCapExceeded);
        assert!(
            !destination.join("big.bin").exists(),
            "a refused file must not be left partially written"
        );
    }

    #[test]
    fn the_destination_must_be_an_empty_directory_outside_the_project() {
        let base = tempfile::tempdir().expect("tempdir");
        let source = base.path().join("project");
        write(&source, "a.txt", "a");
        let inside = source.join("nested-copy");
        std::fs::create_dir_all(&inside).expect("inside");
        assert!(matches!(
            copy_project_tree(&source, &inside),
            Err(ProjectCopyError::Destination(_))
        ));

        let destination = empty_destination(base.path());
        std::fs::write(destination.join("stale"), "x").expect("stale");
        assert!(matches!(
            copy_project_tree(&source, &destination),
            Err(ProjectCopyError::Destination(_))
        ));
    }

    #[test]
    fn the_tree_digest_is_order_independent_and_location_independent() {
        let base = tempfile::tempdir().expect("tempdir");
        let first = base.path().join("first");
        let second = base.path().join("second");
        for root in [&first, &second] {
            write(root, "b.txt", "bee");
            write(root, "a.txt", "ay");
            write(root, "nested/c.txt", "see");
        }
        let left = inventory_project_tree(&first);
        let right = inventory_project_tree(&second);
        assert_eq!(left.digest, right.digest);
        assert!(left.complete);
        assert_eq!(left.file_count, 3);
    }

    #[test]
    fn the_tree_digest_changes_when_any_byte_or_path_changes() {
        let base = tempfile::tempdir().expect("tempdir");
        let root = base.path().join("tree");
        write(&root, "a.txt", "ay");
        let baseline = inventory_project_tree(&root).digest;

        write(&root, "a.txt", "ay!");
        let changed_bytes = inventory_project_tree(&root).digest;
        assert_ne!(baseline, changed_bytes);

        write(&root, "a.txt", "ay");
        std::fs::rename(root.join("a.txt"), root.join("z.txt")).expect("rename");
        let changed_path = inventory_project_tree(&root).digest;
        assert_ne!(baseline, changed_path);
    }

    #[test]
    fn the_diff_reports_added_modified_and_removed() {
        let base = tempfile::tempdir().expect("tempdir");
        let root = base.path().join("tree");
        write(&root, "keep.txt", "same");
        write(&root, "change.txt", "before");
        write(&root, "gone.txt", "bye");
        let before = inventory_project_tree(&root);

        write(&root, "change.txt", "after");
        std::fs::remove_file(root.join("gone.txt")).expect("remove");
        write(&root, "new.txt", "hi");
        let after = inventory_project_tree(&root);

        let diff = diff_project_trees(&before, &after);
        assert_eq!(diff.added, vec!["new.txt".to_string()]);
        assert_eq!(diff.modified, vec!["change.txt".to_string()]);
        assert_eq!(diff.removed, vec!["gone.txt".to_string()]);
        assert!(!diff.truncated);
    }

    #[test]
    fn the_diff_declares_truncation_past_the_entry_cap() {
        let mut before = ProjectTree {
            file_count: 0,
            total_bytes: 0,
            digest: String::new(),
            complete: true,
            entries: BTreeMap::new(),
        };
        let mut after = before.clone();
        for index in 0..(MAX_DIFF_ENTRIES + 10) {
            after
                .entries
                .insert(format!("f{index:05}"), "f:x".to_string());
        }
        before.digest = roll_up_digest(&before.entries);
        let diff = diff_project_trees(&before, &after);
        assert_eq!(diff.added.len(), MAX_DIFF_ENTRIES);
        assert!(diff.truncated);
    }

    #[test]
    fn a_diff_path_is_bounded_in_bytes_not_characters() {
        // 256 four-byte scalars is 256 characters and 1024 bytes. The bound has
        // to be the byte one, because the receipt size limit is a byte limit.
        let long = "\u{1d400}".repeat(MAX_DIFF_PATH_BYTES);
        assert_eq!(long.chars().count(), MAX_DIFF_PATH_BYTES);
        let mut bucket = Vec::new();
        let mut truncated = false;
        push_bounded(&mut bucket, &long, &mut truncated);
        assert!(
            truncated,
            "an oversize path must declare the diff truncated"
        );
        assert!(
            bucket[0].len() <= MAX_DIFF_PATH_BYTES,
            "recorded {} bytes for one diff path",
            bucket[0].len()
        );
    }

    #[test]
    fn a_maximal_diff_serializes_under_the_receipt_byte_limit() {
        // Every bucket full, every path as long as the bound allows, in the
        // widest scalars a filename can hold. The receipt carries this verbatim,
        // and a receipt that will not fit is a receipt that cannot be anchored.
        let component = "\u{1d400}".repeat(63);
        let mut before = ProjectTree {
            file_count: 0,
            total_bytes: 0,
            digest: String::new(),
            complete: true,
            entries: BTreeMap::new(),
        };
        let mut after = before.clone();
        for index in 0..MAX_DIFF_ENTRIES {
            for (tree, marker) in [(&mut before, "f:old"), (&mut after, "f:new")] {
                tree.entries.insert(
                    format!("kept{index:04}/{component}/{component}/{component}"),
                    marker.to_string(),
                );
            }
            before.entries.insert(
                format!("gone{index:04}/{component}/{component}/{component}"),
                "f:old".to_string(),
            );
            after.entries.insert(
                format!("new{index:04}/{component}/{component}/{component}"),
                "f:new".to_string(),
            );
        }
        let diff = diff_project_trees(&before, &after);
        assert_eq!(diff.added.len(), MAX_DIFF_ENTRIES);
        assert_eq!(diff.modified.len(), MAX_DIFF_ENTRIES);
        assert_eq!(diff.removed.len(), MAX_DIFF_ENTRIES);
        let serialized = serde_json::to_string_pretty(&diff).expect("serialize diff");
        assert!(
            serialized.len() < crate::capsule_receipt::MAX_CAPSULE_RECEIPT_BYTES,
            "a maximal diff serialized to {} bytes against a {}-byte receipt limit",
            serialized.len(),
            crate::capsule_receipt::MAX_CAPSULE_RECEIPT_BYTES
        );
    }

    #[test]
    fn an_incomplete_inventory_forces_a_truncated_diff() {
        let complete = ProjectTree {
            file_count: 0,
            total_bytes: 0,
            digest: String::new(),
            complete: true,
            entries: BTreeMap::new(),
        };
        let mut partial = complete.clone();
        partial.complete = false;
        assert!(diff_project_trees(&complete, &partial).truncated);
    }

    #[cfg(unix)]
    #[test]
    fn the_inventory_records_a_symlink_the_child_created() {
        let base = tempfile::tempdir().expect("tempdir");
        let root = base.path().join("tree");
        write(&root, "a.txt", "ay");
        std::os::unix::fs::symlink("a.txt", root.join("link")).expect("symlink");
        let tree = inventory_project_tree(&root);
        assert!(tree.marker("link").is_some_and(|m| m.starts_with("l:")));
        assert!(tree.marker("a.txt").is_some_and(|m| m.starts_with("f:")));
    }

    #[test]
    fn the_argv_digest_is_exact_and_boundary_sensitive() {
        let left = vec![OsString::from("ab"), OsString::from("c")];
        let right = vec![OsString::from("a"), OsString::from("bc")];
        assert_ne!(argv_digest(&left), argv_digest(&right));
        assert_eq!(argv_digest(&left), argv_digest(&left.clone()));
        assert_ne!(argv_digest(&left), argv_digest(&[]));
        assert_eq!(argv_digest(&left).len(), 64);
    }
}
