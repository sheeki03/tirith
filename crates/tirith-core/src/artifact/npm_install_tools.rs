//! Retained root-managed tool binding for one characterized npm runtime.
//! Capturing these inputs performs no child execution or package installation.

use std::path::{Path, PathBuf};

use crate::trusted_child::TrustedExecutable;

use super::{NpmInstallRefusal, Result};

pub const NODE_VERSION: &str = "26.7.0";
pub const NPM_VERSION: &str = "11.19.0";
pub const NODE_PATH: &str = "/usr/local/bin/node";
pub const NPM_ROOT: &str = "/usr/local/lib/node_modules/npm";
pub const NPM_ENTRYPOINT: &str = "/usr/local/lib/node_modules/npm/bin/npm-cli.js";
pub const NODE_SHA256: &str = "9507fea66ea788dfb2bbef1380ef6ef8940697ef1de15bee62b279e6cfef035c";
pub const NPM_TREE_SHA256: &str =
    "3a34157a11136a4e01f691b297bed524edee9b8cc3bc30e34ad195b17dd8c60e";

/// This proves a tool closure only. It does not qualify native containment,
/// authorize an operation, or permit scripts/dependency resolution.
pub struct QualifiedNpmToolClosure {
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    inner: native::Binding,
}

impl QualifiedNpmToolClosure {
    pub fn capture() -> Result<Self> {
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        {
            Ok(Self {
                inner: native::Binding::capture()?,
            })
        }
        #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
        {
            Err(NpmInstallRefusal::ToolClosureUnsupported)
        }
    }

    pub fn revalidate(&self) -> Result<()> {
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        {
            self.inner.revalidate()
        }
        #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
        {
            Err(NpmInstallRefusal::ToolClosureUnsupported)
        }
    }

    pub fn program(&self) -> Result<&TrustedExecutable> {
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        {
            Ok(&self.inner.node)
        }
        #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
        {
            Err(NpmInstallRefusal::ToolClosureUnsupported)
        }
    }

    pub fn entrypoint(&self) -> &Path {
        Path::new(NPM_ENTRYPOINT)
    }

    pub fn binding_id(&self) -> &'static str {
        "node26.7.0-npm11.19.0-linux-arm64-bookworm-v1"
    }

    pub(super) fn runtime_pack(&self) -> Result<&[u8]> {
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        {
            Ok(&self.inner.runtime_pack)
        }
        #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
        {
            Err(NpmInstallRefusal::ToolClosureUnsupported)
        }
    }

    pub fn read_roots(&self) -> Vec<PathBuf> {
        // Valid only after the closed launcher has replaced BOTH roots with
        // the verified private runtime; never grant the host /etc as fallback.
        vec![PathBuf::from("/usr"), PathBuf::from("/etc")]
    }
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod native {
    use std::collections::BTreeMap;
    use std::fs::{File, Metadata};
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::util::dirfd::{file_generation, DirCapability, EntryKind, FileGeneration};

    const MAX_FILES: usize = 4096;
    const MAX_FILE_BYTES: u64 = 1024 * 1024;
    const MAX_TREE_BYTES: u64 = 32 * 1024 * 1024;
    const MAX_NODE_BYTES: u64 = 256 * 1024 * 1024;

    pub(super) struct Binding {
        pub(super) node: TrustedExecutable,
        node_file: File,
        node_generation: FileGeneration,
        npm_root: DirCapability,
        npm_generations: BTreeMap<String, FileGeneration>,
        libraries: Vec<LibraryBinding>,
        pub(super) runtime_pack: Vec<u8>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LibraryPin {
        path: String,
        canonical: String,
        sha256: String,
        size: u64,
    }
    struct LibraryBinding {
        pin: LibraryPin,
        file: File,
        generation: FileGeneration,
    }

    // Field order deliberately matches the characterized canonical JSON rows.
    #[derive(Serialize)]
    struct InventoryRow {
        path: String,
        kind: &'static str,
        size: u64,
        sha256: String,
        executable: bool,
        target: Option<String>,
    }

    impl Binding {
        pub(super) fn capture() -> Result<Self> {
            absent_preload()?;
            secure_path(Path::new(NODE_PATH))?;
            let node = TrustedExecutable::from_absolute(Path::new(NODE_PATH), &[])
                .and_then(TrustedExecutable::require_system_helper_provenance)
                .and_then(|node| node.bind_content())
                .map_err(|_| NpmInstallRefusal::ToolClosureUnsupported)?;
            let node_file =
                crate::util::open_read_no_follow_capped(Path::new(NODE_PATH), MAX_NODE_BYTES)
                    .map_err(|_| NpmInstallRefusal::ToolClosureUnsupported)?;
            let node_generation =
                file_generation(&node_file).map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
            verify_file(&node_file, &node_generation, NODE_SHA256)?;
            secure_path(Path::new(NPM_ROOT))?;
            let npm_root = DirCapability::open_root(Path::new(NPM_ROOT))
                .map_err(|_| NpmInstallRefusal::ToolClosureUnsupported)?;
            let npm_generations = inspect_npm_tree(&npm_root)?;
            let pins: Vec<LibraryPin> = serde_json::from_str(include_str!(
                "../../tests/fixtures/npm/install/node-26.7.0-arm64-libraries.json"
            ))
            .map_err(|_| NpmInstallRefusal::ToolClosureUnsupported)?;
            let mut libraries = Vec::new();
            for pin in pins {
                if Path::new(&pin.path).canonicalize().ok().as_deref()
                    != Some(Path::new(&pin.canonical))
                {
                    return Err(NpmInstallRefusal::ToolClosureUnsupported);
                }
                secure_path(Path::new(&pin.path))?;
                secure_path(Path::new(&pin.canonical))?;
                let file =
                    crate::util::open_read_no_follow_capped(Path::new(&pin.canonical), pin.size)
                        .map_err(|_| NpmInstallRefusal::ToolClosureUnsupported)?;
                let generation =
                    file_generation(&file).map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
                if generation.size != pin.size {
                    return Err(NpmInstallRefusal::ToolClosureUnsupported);
                }
                verify_file(&file, &generation, &pin.sha256)?;
                libraries.push(LibraryBinding {
                    pin,
                    file,
                    generation,
                });
            }
            let mut binding = Self {
                node,
                node_file,
                node_generation,
                npm_root,
                npm_generations,
                libraries,
                runtime_pack: Vec::new(),
            };
            binding.revalidate()?;
            binding.runtime_pack = binding.capture_runtime_pack()?;
            binding.revalidate()?;
            Ok(binding)
        }

        fn capture_runtime_pack(&self) -> Result<Vec<u8>> {
            use super::super::runtime_pack::{encode, RuntimePackSource};
            let mut entries = BTreeMap::new();
            for (relative, expected) in &self.npm_generations {
                let mut file = self
                    .npm_root
                    .open_descendant_file(relative, MAX_FILE_BYTES)
                    .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
                if file_generation(&file).ok() != Some(*expected) {
                    return Err(NpmInstallRefusal::ToolClosureChanged);
                }
                let mut bytes = Vec::new();
                (&mut file)
                    .take(MAX_FILE_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
                if bytes.len() as u64 != expected.size
                    || file_generation(&file).ok() != Some(*expected)
                {
                    return Err(NpmInstallRefusal::ToolClosureChanged);
                }
                entries.insert(
                    format!("usr/local/lib/node_modules/npm/{relative}"),
                    RuntimePackSource {
                        path: format!("usr/local/lib/node_modules/npm/{relative}"),
                        executable: file
                            .metadata()
                            .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?
                            .mode()
                            & 0o111
                            != 0,
                        bytes,
                    },
                );
            }
            for library in &self.libraries {
                let mut file = library
                    .file
                    .try_clone()
                    .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
                file.seek(SeekFrom::Start(0))
                    .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
                let mut bytes = Vec::new();
                file.take(library.pin.size + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
                if bytes.len() as u64 != library.pin.size
                    || super::super::digest(&bytes) != library.pin.sha256
                    || file_generation(&library.file).ok() != Some(library.generation)
                {
                    return Err(NpmInstallRefusal::ToolClosureChanged);
                }
                // /lib is a separately verified host alias to usr/lib. Materialize
                // both canonical and SONAME paths as separately hashed pack
                // entries for the private read-only runtime filesystem.
                let alias = library.pin.path.strip_prefix("/lib/").map_or_else(
                    || library.pin.path.trim_start_matches('/').to_owned(),
                    |name| format!("usr/lib/{name}"),
                );
                for path in [
                    library.pin.canonical.trim_start_matches('/').to_owned(),
                    alias,
                ] {
                    entries
                        .entry(path.clone())
                        .or_insert_with(|| RuntimePackSource {
                            path,
                            executable: library.pin.path != "/etc/ld.so.cache",
                            bytes: bytes.clone(),
                        });
                }
            }
            // Fixed namespace-local account/config bytes contain no host identity
            // or credentials. Namespace uid/gid 0 names the already mapped caller.
            for (path, bytes) in [
                (
                    "etc/passwd",
                    "tirith:x:0:0:Tirith isolated runtime:/nonexistent:/usr/bin/false\n",
                ),
                ("etc/group", "tirith:x:0:\n"),
                (
                    "etc/nsswitch.conf",
                    "passwd: files\ngroup: files\nhosts: files\n",
                ),
                ("etc/hosts", "127.0.0.1 localhost\n::1 localhost\n"),
                ("etc/resolv.conf", ""),
                ("etc/tirith-empty-openssl.cnf", ""),
            ] {
                entries.insert(
                    path.into(),
                    RuntimePackSource {
                        path: path.into(),
                        executable: false,
                        bytes: bytes.as_bytes().into(),
                    },
                );
            }
            encode(entries.into_values().collect())
        }

        pub(super) fn revalidate(&self) -> Result<()> {
            absent_preload()?;
            secure_path(Path::new(NODE_PATH))?;
            self.node
                .verify_identity()
                .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
            verify_file(&self.node_file, &self.node_generation, NODE_SHA256)?;
            let visible =
                crate::util::open_read_no_follow_capped(Path::new(NODE_PATH), MAX_NODE_BYTES)
                    .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
            if file_generation(&visible).ok() != Some(self.node_generation) {
                return Err(NpmInstallRefusal::ToolClosureChanged);
            }
            secure_path(Path::new(NPM_ROOT))?;
            let visible = DirCapability::open_root(Path::new(NPM_ROOT))
                .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
            if visible.identity().ok() != self.npm_root.identity().ok()
                || inspect_npm_tree(&self.npm_root)? != self.npm_generations
            {
                return Err(NpmInstallRefusal::ToolClosureChanged);
            }
            for library in &self.libraries {
                secure_path(Path::new(&library.pin.path))?;
                secure_path(Path::new(&library.pin.canonical))?;
                if Path::new(&library.pin.path).canonicalize().ok().as_deref()
                    != Some(Path::new(&library.pin.canonical))
                {
                    return Err(NpmInstallRefusal::ToolClosureChanged);
                }
                let visible = crate::util::open_read_no_follow_capped(
                    Path::new(&library.pin.canonical),
                    library.pin.size,
                )
                .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
                if file_generation(&visible).ok() != Some(library.generation) {
                    return Err(NpmInstallRefusal::ToolClosureChanged);
                }
                verify_file(&library.file, &library.generation, &library.pin.sha256)?;
            }
            Ok(())
        }
    }

    fn absent_preload() -> Result<()> {
        match std::fs::symlink_metadata("/etc/ld.so.preload") {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(NpmInstallRefusal::ToolClosureUnsupported),
        }
    }

    fn secure_metadata(metadata: &Metadata) -> Result<()> {
        if metadata.uid() != 0 || metadata.mode() & 0o6022 != 0 {
            return Err(NpmInstallRefusal::ToolClosureUnsupported);
        }
        Ok(())
    }

    fn secure_path(path: &Path) -> Result<()> {
        for component in path.ancestors() {
            let metadata = std::fs::symlink_metadata(component)
                .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
            if metadata.file_type().is_symlink() {
                if metadata.uid() != 0 {
                    return Err(NpmInstallRefusal::ToolClosureUnsupported);
                }
            } else {
                secure_metadata(&metadata)?;
                crate::trusted_child::reject_unix_extended_acl(component, metadata.is_dir())
                    .map_err(|_| NpmInstallRefusal::ToolClosureUnsupported)?;
            }
        }
        Ok(())
    }

    fn verify_file(file: &File, generation: &FileGeneration, expected: &str) -> Result<()> {
        secure_metadata(
            &file
                .metadata()
                .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?,
        )?;
        if file_generation(file).ok() != Some(*generation) || generation.links != 1 {
            return Err(NpmInstallRefusal::ToolClosureChanged);
        }
        let mut input = file
            .try_clone()
            .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
        input
            .seek(SeekFrom::Start(0))
            .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
        let (size, hash) = super::super::hash_reader(input.take(generation.size + 1))
            .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
        if size != generation.size
            || hash != expected
            || file_generation(file).ok() != Some(*generation)
        {
            return Err(NpmInstallRefusal::ToolClosureChanged);
        }
        Ok(())
    }

    fn inspect_npm_tree(root: &DirCapability) -> Result<BTreeMap<String, FileGeneration>> {
        let mut generations = BTreeMap::new();
        let mut rows = Vec::new();
        let mut directories = Vec::new();
        let mut total = 0u64;
        // The captured Node inventory is depth-first with sorted child names.
        fn walk(
            root: &DirCapability,
            prefix: &str,
            rows: &mut Vec<InventoryRow>,
            generations: &mut BTreeMap<String, FileGeneration>,
            directories: &mut Vec<(String, (u64, u64))>,
            total: &mut u64,
        ) -> Result<()> {
            if prefix.split('/').count() > 64 {
                return Err(NpmInstallRefusal::ResourceLimit);
            }
            secure_metadata(
                &root
                    .metadata()
                    .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?,
            )?;
            crate::trusted_child::reject_unix_extended_acl(root.path(), true)
                .map_err(|_| NpmInstallRefusal::ToolClosureUnsupported)?;
            let (mut entries, truncated) = root
                .read_entries(MAX_FILES)
                .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
            if truncated {
                return Err(NpmInstallRefusal::ResourceLimit);
            }
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            for entry in entries {
                let name = entry
                    .name
                    .ok_or(NpmInstallRefusal::ToolClosureUnsupported)?;
                let relative = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}/{name}")
                };
                if relative.len() > 4096 || rows.len() + directories.len() >= MAX_FILES {
                    return Err(NpmInstallRefusal::ResourceLimit);
                }
                match entry.kind {
                    EntryKind::Directory => {
                        let child = root
                            .open_child_directory(&name)
                            .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
                        directories.push((
                            relative.clone(),
                            child
                                .identity()
                                .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?,
                        ));
                        walk(&child, &relative, rows, generations, directories, total)?;
                    }
                    EntryKind::RegularFile => {
                        let file = root
                            .open_child_file(&name, MAX_FILE_BYTES)
                            .map_err(|_| NpmInstallRefusal::ToolClosureUnsupported)?;
                        let generation = file_generation(&file)
                            .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
                        secure_metadata(
                            &file
                                .metadata()
                                .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?,
                        )?;
                        crate::trusted_child::reject_unix_extended_acl(
                            &root.path().join(&name),
                            false,
                        )
                        .map_err(|_| NpmInstallRefusal::ToolClosureUnsupported)?;
                        if generation.links != 1 {
                            return Err(NpmInstallRefusal::ToolClosureUnsupported);
                        }
                        let (size, sha256) =
                            super::super::hash_reader(file.take(MAX_FILE_BYTES + 1))
                                .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
                        *total = total.saturating_add(size);
                        if *total > MAX_TREE_BYTES || size != generation.size {
                            return Err(NpmInstallRefusal::ResourceLimit);
                        }
                        let rebound = root
                            .open_child_file(&name, MAX_FILE_BYTES)
                            .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?;
                        if file_generation(&rebound).ok() != Some(generation) {
                            return Err(NpmInstallRefusal::ToolClosureChanged);
                        }
                        let executable = rebound
                            .metadata()
                            .map_err(|_| NpmInstallRefusal::ToolClosureChanged)?
                            .permissions()
                            .mode()
                            & 0o111
                            != 0;
                        rows.push(InventoryRow {
                            path: relative.clone(),
                            kind: "file",
                            size,
                            sha256,
                            executable,
                            target: None,
                        });
                        generations.insert(relative, generation);
                    }
                    _ => return Err(NpmInstallRefusal::ToolClosureUnsupported),
                }
            }
            Ok(())
        }
        walk(
            root,
            "",
            &mut rows,
            &mut generations,
            &mut directories,
            &mut total,
        )?;
        if rows.len() != 1926
            || total != 12_182_611
            || super::super::digest(
                &serde_json::to_vec(&rows)
                    .map_err(|_| NpmInstallRefusal::ToolClosureUnsupported)?,
            ) != NPM_TREE_SHA256
        {
            return Err(NpmInstallRefusal::ToolClosureUnsupported);
        }
        for (relative, identity) in directories {
            if root
                .open_descendant_directory(&relative)
                .ok()
                .and_then(|directory| directory.identity().ok())
                != Some(identity)
            {
                return Err(NpmInstallRefusal::ToolClosureChanged);
            }
        }
        for (relative, generation) in &generations {
            if root
                .open_descendant_file(relative, MAX_FILE_BYTES)
                .ok()
                .and_then(|file| file_generation(&file).ok())
                != Some(*generation)
            {
                return Err(NpmInstallRefusal::ToolClosureChanged);
            }
        }
        Ok(generations)
    }

    /// Qualification tooling only: produce fixtures from the real retained
    /// closure builder. This ignored test never starts Node or authorizes an
    /// install; the launcher must seal and validate each emitted input anew.
    #[cfg(test)]
    #[test]
    #[ignore = "requires the exact pinned ARM Node image and explicit fixture output directory"]
    fn emit_characterized_runtime_fixture() {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        let parent = std::env::var_os("TIRITH_NPM_QUALIFICATION_OUTPUT")
            .map(PathBuf::from)
            .expect("an explicit fixture output directory is required");
        assert!(parent.is_absolute());
        let parent = parent.canonicalize().unwrap();
        let captured = QualifiedNpmToolClosure::capture().unwrap();
        captured.revalidate().unwrap();
        let fixture = tempfile::Builder::new()
            .prefix("npm-qualified-runtime-")
            .tempdir_in(&parent)
            .unwrap();
        let open_output = |name: &str| {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(fixture.path().join(name))
                .unwrap()
        };
        let verify_fixture = |file: &File, expected: &str| {
            let before = file_generation(file).unwrap();
            let metadata = file.metadata().unwrap();
            assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
            assert_eq!(metadata.nlink(), 1);
            assert_eq!(metadata.mode() & 0o022, 0);
            let mut input = file.try_clone().unwrap();
            input.seek(SeekFrom::Start(0)).unwrap();
            let (bytes, actual) = super::super::hash_reader(input.take(before.size + 1)).unwrap();
            assert_eq!(bytes, before.size);
            assert_eq!(actual, expected);
            assert_eq!(file_generation(file).unwrap(), before);
        };
        let pack = captured.runtime_pack().unwrap();
        assert!(pack.len() <= super::super::runtime_pack::MAX_BYTES);
        let mut pack_file = open_output(super::super::runtime_pack::FILE_NAME);
        pack_file.write_all(pack).unwrap();
        pack_file.sync_all().unwrap();
        let pack_sha256 = super::super::digest(pack);
        pack_file
            .set_permissions(std::fs::Permissions::from_mode(0o400))
            .unwrap();
        verify_fixture(&pack_file, &pack_sha256);

        let mut node_source = captured.inner.node_file.try_clone().unwrap();
        node_source.seek(SeekFrom::Start(0)).unwrap();
        let mut node_file = open_output("node");
        let node_bytes =
            std::io::copy(&mut node_source.take(MAX_NODE_BYTES + 1), &mut node_file).unwrap();
        assert_eq!(node_bytes, captured.inner.node_generation.size);
        assert!(node_bytes <= MAX_NODE_BYTES);
        node_file.sync_all().unwrap();
        node_file
            .set_permissions(std::fs::Permissions::from_mode(0o500))
            .unwrap();
        verify_fixture(&node_file, NODE_SHA256);
        captured.revalidate().unwrap();
        let manifest = serde_json::json!({
            "schema_version": 1,
            "scope": "retained_tool_fixture_only_not_execution_qualification",
            "binding_id": captured.binding_id(),
            "node": {"filename":"node", "sha256":NODE_SHA256, "bytes":node_bytes, "version":NODE_VERSION},
            "runtime_pack": {"filename":super::super::runtime_pack::FILE_NAME, "sha256":pack_sha256, "bytes":pack.len()},
            "npm": {"version":NPM_VERSION,"tree_sha256":NPM_TREE_SHA256}
        });
        let mut metadata = open_output("fixture.json");
        metadata
            .write_all(&serde_json::to_vec_pretty(&manifest).unwrap())
            .unwrap();
        metadata.sync_all().unwrap();
        metadata
            .set_permissions(std::fs::Permissions::from_mode(0o400))
            .unwrap();
        File::open(fixture.path()).unwrap().sync_all().unwrap();
        drop((metadata, pack_file, node_file));
        let path = fixture.keep();
        println!(
            "{}",
            serde_json::json!({"fixture_directory":path,"manifest":manifest})
        );
    }
}
