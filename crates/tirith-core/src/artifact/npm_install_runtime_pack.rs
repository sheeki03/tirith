//! Bounded runtime-closure container. It is never interpreted as a tar archive.
//! A validated container exposes only relative paths under closed overlay roots.

#[cfg(any(target_os = "linux", test))]
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{Read, Seek, SeekFrom};

use serde::{Deserialize, Serialize};

#[cfg(any(target_os = "linux", test))]
use super::digest;
use super::{NpmInstallRefusal, Result};

pub const FILE_NAME: &str = "npm-runtime.pack";
pub const MAX_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 4096;
pub const MAX_DIRECTORIES: usize = 16_384;
pub const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
#[cfg(any(target_os = "linux", test))]
const MAX_MANIFEST: usize = 1024 * 1024;
#[cfg(any(target_os = "linux", test))]
const MAGIC: &[u8; 8] = b"TIRNPM01";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    node_sha256: String,
    npm_tree_sha256: String,
    entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    executable: bool,
    size: usize,
    sha256: String,
    offset: usize,
}

#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(super) struct RuntimePackSource {
    pub path: String,
    pub executable: bool,
    pub bytes: Vec<u8>,
}

/// Every path and byte range is validated before the first entry is exposed.
/// The value owns its immutable bytes and has no serde/Clone constructor.
pub struct VerifiedNpmRuntimePack {
    bytes: Vec<u8>,
    data_offset: usize,
    manifest: Manifest,
}

pub struct NpmRuntimeEntry<'a> {
    pub path: &'a str,
    pub executable: bool,
    pub sha256: &'a str,
    pub bytes: &'a [u8],
}

impl VerifiedNpmRuntimePack {
    /// The namespace bootstrap accepts only a fully sealed retained descriptor.
    /// A read-only file or bind mount does not satisfy this constructor.
    pub fn read_sealed(mut file: File, expected_sha256: &str) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd as _;
            let required =
                libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
            // SAFETY: file owns this live descriptor; F_GET_SEALS has no pointer arguments.
            let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
            if seals < 0 || seals & required != required {
                return Err(NpmInstallRefusal::ToolClosureChanged);
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (&mut file, expected_sha256);
            Err(NpmInstallRefusal::NativeExecutionUnqualified)
        }
        #[cfg(target_os = "linux")]
        {
            let metadata = file
                .metadata()
                .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
            if !metadata.is_file() || metadata.len() > MAX_BYTES as u64 {
                return Err(NpmInstallRefusal::ResourceLimit);
            }
            file.seek(SeekFrom::Start(0))
                .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
            let mut bytes = Vec::new();
            file.take(MAX_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
            Self::decode(bytes, expected_sha256)
        }
    }

    #[cfg(any(target_os = "linux", test))]
    fn decode(bytes: Vec<u8>, expected_sha256: &str) -> Result<Self> {
        if bytes.len() > MAX_BYTES || bytes.len() < 12 {
            return Err(NpmInstallRefusal::ResourceLimit);
        }
        if !valid_sha256(expected_sha256)
            || digest(&bytes) != expected_sha256
            || &bytes[..8] != MAGIC
        {
            return Err(NpmInstallRefusal::ToolClosureChanged);
        }
        let length = u32::from_be_bytes(bytes[8..12].try_into().expect("four bytes")) as usize;
        if length > MAX_MANIFEST || length > bytes.len() - 12 {
            return Err(NpmInstallRefusal::ResourceLimit);
        }
        let data_offset = 12 + length;
        let text = std::str::from_utf8(&bytes[12..data_offset])
            .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
        let value = crate::mcp_lock::parse_json_no_duplicates(text)
            .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
        let manifest: Manifest =
            serde_json::from_value(value).map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
        if manifest.schema_version != 1
            || manifest.node_sha256 != super::tools::NODE_SHA256
            || manifest.npm_tree_sha256 != super::tools::NPM_TREE_SHA256
            || manifest.entries.is_empty()
            || manifest.entries.len() > MAX_ENTRIES
            || serde_json::to_vec(&manifest).map_err(|_| NpmInstallRefusal::ToolClosureChanged)?
                != bytes[12..data_offset]
        {
            return Err(NpmInstallRefusal::ToolClosureChanged);
        }
        let mut names = BTreeSet::new();
        let mut directories = BTreeMap::new();
        let mut end = 0usize;
        let mut previous: Option<&str> = None;
        for entry in &manifest.entries {
            if !allowed_path(&entry.path)
                || !valid_sha256(&entry.sha256)
                || previous.is_some_and(|path| path >= entry.path.as_str())
                || entry.offset != end
                || entry.size > MAX_FILE_BYTES
                || entry.size > bytes.len() - data_offset - end
            {
                return Err(NpmInstallRefusal::ToolClosureChanged);
            }
            let normalized = entry.path.to_ascii_lowercase();
            if names.contains(&normalized) || directories.contains_key(&normalized) {
                return Err(NpmInstallRefusal::ToolClosureChanged);
            }
            // Case-sensitive sorting can put A/child before the later file a.
            // Retain inferred directories as well as files, and reject aliases
            // of shared directories before exposing any materialization entry.
            let mut parent = std::path::Path::new(&entry.path).parent();
            while let Some(path) = parent {
                let path = path.to_str().expect("allowed paths are ASCII");
                if !path.is_empty() {
                    let normalized_parent = path.to_ascii_lowercase();
                    if names.contains(&normalized_parent) {
                        return Err(NpmInstallRefusal::ToolClosureChanged);
                    }
                    if let Some(previous) = directories.insert(normalized_parent, path) {
                        if previous != path {
                            return Err(NpmInstallRefusal::ToolClosureChanged);
                        }
                    }
                    if directories.len() > MAX_DIRECTORIES {
                        return Err(NpmInstallRefusal::ResourceLimit);
                    }
                }
                parent = std::path::Path::new(path).parent();
            }
            names.insert(normalized);
            previous = Some(&entry.path);
            end += entry.size;
            if digest(&bytes[data_offset + entry.offset..data_offset + end]) != entry.sha256 {
                return Err(NpmInstallRefusal::ToolClosureChanged);
            }
        }
        if data_offset + end != bytes.len() {
            return Err(NpmInstallRefusal::ToolClosureChanged);
        }
        Ok(Self {
            bytes,
            data_offset,
            manifest,
        })
    }

    pub fn entries(&self) -> impl ExactSizeIterator<Item = NpmRuntimeEntry<'_>> {
        self.manifest.entries.iter().map(|entry| NpmRuntimeEntry {
            path: &entry.path,
            executable: entry.executable,
            sha256: &entry.sha256,
            bytes: &self.bytes
                [self.data_offset + entry.offset..self.data_offset + entry.offset + entry.size],
        })
    }

    /// The independently sealed Node executable must match this binding before
    /// it is mounted into the private runtime tree or allowed to resume.
    pub fn node_sha256(&self) -> &str {
        &self.manifest.node_sha256
    }
}

#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(super) fn encode(mut sources: Vec<RuntimePackSource>) -> Result<Vec<u8>> {
    sources.sort_by(|a, b| a.path.cmp(&b.path));
    if sources.is_empty() || sources.len() > MAX_ENTRIES {
        return Err(NpmInstallRefusal::ResourceLimit);
    }
    let mut payload = Vec::new();
    let mut entries = Vec::with_capacity(sources.len());
    for source in sources {
        if source.bytes.len() > MAX_FILE_BYTES || source.bytes.len() > MAX_BYTES - payload.len() {
            return Err(NpmInstallRefusal::ResourceLimit);
        }
        entries.push(Entry {
            path: source.path,
            executable: source.executable,
            size: source.bytes.len(),
            sha256: digest(&source.bytes),
            offset: payload.len(),
        });
        payload.extend_from_slice(&source.bytes);
    }
    let manifest = serde_json::to_vec(&Manifest {
        schema_version: 1,
        node_sha256: super::tools::NODE_SHA256.into(),
        npm_tree_sha256: super::tools::NPM_TREE_SHA256.into(),
        entries,
    })
    .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
    if manifest.len() > MAX_MANIFEST || payload.len() + manifest.len() + 12 > MAX_BYTES {
        return Err(NpmInstallRefusal::ResourceLimit);
    }
    let mut bytes = Vec::with_capacity(payload.len() + manifest.len() + 12);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(manifest.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&manifest);
    bytes.extend_from_slice(&payload);
    let hash = digest(&bytes);
    VerifiedNpmRuntimePack::decode(bytes, &hash).map(|pack| pack.bytes)
}

#[cfg(any(target_os = "linux", test))]
fn valid_sha256(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(any(target_os = "linux", test))]
fn allowed_path(path: &str) -> bool {
    if path.len() > 4096
        || !path.is_ascii()
        || path.contains(['\\', ':'])
        || path.bytes().any(|byte| byte < b' ' || byte == 127)
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path.split('/').count() > 72
    {
        return false;
    }
    if path
        .strip_prefix("usr/local/lib/node_modules/npm/")
        .is_some_and(|path| !path.is_empty())
    {
        return true;
    }
    matches!(
        path,
        "usr/lib/aarch64-linux-gnu/libatomic.so.1"
            | "usr/lib/aarch64-linux-gnu/libatomic.so.1.2.0"
            | "usr/lib/aarch64-linux-gnu/libdl.so.2"
            | "usr/lib/aarch64-linux-gnu/libm.so.6"
            | "usr/lib/aarch64-linux-gnu/libstdc++.so.6"
            | "usr/lib/aarch64-linux-gnu/libstdc++.so.6.0.30"
            | "usr/lib/aarch64-linux-gnu/libgcc_s.so.1"
            | "usr/lib/aarch64-linux-gnu/libpthread.so.0"
            | "usr/lib/aarch64-linux-gnu/libc.so.6"
            | "usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"
            | "usr/lib/ld-linux-aarch64.so.1"
            | "etc/ld.so.cache"
            | "etc/passwd"
            | "etc/group"
            | "etc/nsswitch.conf"
            | "etc/hosts"
            | "etc/resolv.conf"
            | "etc/tirith-empty-openssl.cnf"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(path: &str, bytes: &[u8]) -> RuntimePackSource {
        RuntimePackSource {
            path: path.into(),
            executable: false,
            bytes: bytes.into(),
        }
    }

    #[test]
    fn pack_roundtrip_retains_exact_bounded_bytes_and_sorted_names() {
        let bytes = encode(vec![
            source("usr/local/lib/node_modules/npm/bin/npm-cli.js", b"module"),
            source("etc/ld.so.cache", b"cache"),
        ])
        .unwrap();
        let pack = VerifiedNpmRuntimePack::decode(bytes.clone(), &digest(&bytes)).unwrap();
        let entries: Vec<_> = pack.entries().collect();
        assert_eq!(entries[0].path, "etc/ld.so.cache");
        assert_eq!(entries[0].bytes, b"cache");
        assert_eq!(entries[1].bytes, b"module");
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(VerifiedNpmRuntimePack::decode(changed, &digest(&bytes)).is_err());
        let mut tail = bytes;
        tail.push(0);
        assert!(VerifiedNpmRuntimePack::decode(tail.clone(), &digest(&tail)).is_err());
    }

    #[test]
    fn pack_rejects_unapproved_paths_duplicates_and_file_parent_collisions() {
        for path in [
            "/etc/passwd",
            "etc/shadow",
            "usr/local/bin/node",
            "usr/local/lib/node_modules/npm/../escape",
            "usr/local/lib/node_modules/npm//file",
            "usr/local/lib/node_modules/npm/file:stream",
            "usr/local/lib/node_modules/npm/f\u{1b}ile",
        ] {
            assert!(encode(vec![source(path, b"x")]).is_err(), "{path}");
        }
        let base = "usr/local/lib/node_modules/npm/file";
        assert!(encode(vec![source(base, b"x"), source(base, b"y")]).is_err());
        assert!(encode(vec![
            source(base, b"x"),
            source(&base.to_ascii_uppercase(), b"y")
        ])
        .is_err());
        assert!(encode(vec![
            source(base, b"x"),
            source(&format!("{base}/child"), b"y")
        ])
        .is_err());
    }

    #[test]
    fn normalized_file_directory_collisions_refuse_in_both_sort_orders() {
        let prefix = "usr/local/lib/node_modules/npm";
        for (file, child) in [("a", "A/child"), ("A", "a/child")] {
            assert!(matches!(
                encode(vec![
                    source(&format!("{prefix}/{file}"), b"file"),
                    source(&format!("{prefix}/{child}"), b"child"),
                ]),
                Err(NpmInstallRefusal::ToolClosureChanged)
            ));
        }
        assert!(matches!(
            encode(vec![
                source(&format!("{prefix}/A/one"), b"one"),
                source(&format!("{prefix}/a/two"), b"two"),
            ]),
            Err(NpmInstallRefusal::ToolClosureChanged)
        ));
        assert!(encode(vec![
            source(&format!("{prefix}/A/one"), b"one"),
            source(&format!("{prefix}/A/two"), b"two"),
        ])
        .is_ok());
    }

    #[test]
    fn hostile_manifest_ranges_and_bindings_refuse_without_exposing_entries() {
        let original = encode(vec![source("etc/ld.so.cache", b"payload")]).unwrap();
        let length = u32::from_be_bytes(original[8..12].try_into().unwrap()) as usize;
        for change in 0..6 {
            let mut manifest: Manifest =
                serde_json::from_slice(&original[12..12 + length]).unwrap();
            match change {
                0 => manifest.entries[0].size = usize::MAX,
                1 => manifest.entries[0].offset = usize::MAX,
                2 => manifest.entries[0].size += 1,
                3 => manifest.node_sha256 = "a".repeat(64),
                4 => manifest.entries[0].sha256 = "a".repeat(64),
                _ => manifest.entries[0].path = "etc/shadow".into(),
            }
            let encoded = serde_json::to_vec(&manifest).unwrap();
            let mut bytes = MAGIC.to_vec();
            bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&encoded);
            bytes.extend_from_slice(&original[12 + length..]);
            assert!(
                VerifiedNpmRuntimePack::decode(bytes.clone(), &digest(&bytes)).is_err(),
                "case {change}"
            );
        }
        assert!(encode(vec![source(
            "etc/ld.so.cache",
            &vec![0; MAX_FILE_BYTES + 1]
        )])
        .is_err());
    }

    #[test]
    fn ordinary_readonly_file_cannot_claim_sealed_runtime_authority() {
        let file = tempfile::tempfile().unwrap();
        assert!(VerifiedNpmRuntimePack::read_sealed(file, &"a".repeat(64)).is_err());
    }
}
