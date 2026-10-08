//! Python requirement validation and resolver-tool enrollment.
//!
//! `tirith pkg approve` and `tirith pkg install` validate their request here
//! before refusing: contained package execution (the uv/pip resolve into the
//! quarantine, the approval issued for it, and the contained install that
//! redeemed it) is disabled and its code was removed. What remains:
//!
//! 1. [`validate_resolver_request_with_artifact_origins`]: an effect-free check
//!    of every requirement, index URL, and artifact origin. VCS / editable /
//!    local-path / direct-URL forms (an sdist archive can only be named as a
//!    local path or direct URL) are refused unless a [`ResolverAllowances`]
//!    field opts in ([`validate_requirement`]), and an
//!    index URL or artifact origin must be a credential-free public `https` URL.
//!    It starts no process, opens no socket, resolves no DNS, and writes nothing.
//! 2. [`enroll_resolver_tool`]: `tirith pkg trust-tool` records the digest of an
//!    explicitly named resolver executable in the private trust store. Nothing
//!    outside the enrollment self-check reads that store while contained install
//!    is disabled; the pin is kept for when it returns.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::trusted_child::TrustedExecutable;

/// Hard cap on requirement specs in one request, so a pathological input cannot
/// turn into an unbounded command line / lock.
const MAX_REQUIREMENTS: usize = 4096;

/// Hard cap on approved index URLs in one request.
const MAX_INDEX_URLS: usize = 64;

/// What the resolver is permitted to accept beyond the secure default. Every
/// field defaults to the *refusing* stance, so [`ResolverAllowances::default`] is
/// the locked-down resolver the plan calls for. A future policy layer (D3 / D7)
/// populates these from operator config; nothing here reads policy itself, and a
/// repo-scoped policy must never be able to flip one on (the policy field that
/// drives these is neutralized in `sanitize_repo_scoped`, where it is introduced).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolverAllowances {
    /// Permit `git+` / other VCS requirement forms. Default `false`.
    pub allow_vcs: bool,
    /// Permit `-e` / `--editable` requirement forms. Default `false`.
    pub allow_editable: bool,
    /// Permit a local-path requirement (`./pkg`, `/abs/pkg`, a bare existing
    /// path). Default `false`.
    pub allow_local_path: bool,
    /// Permit a direct-URL requirement (`name @ https://.../x.whl`). Default
    /// `false`. Even when permitted the URL must still be a credential-free public
    /// `https` URL.
    pub allow_direct_url: bool,
}

/// Why a resolver request or resolver-tool enrollment was refused.
#[derive(Debug)]
pub enum ResolverError {
    /// A requirement spec was rejected by [`validate_requirement`] (sdist / VCS /
    /// editable / local-path / direct-URL / embedded credential / malformed),
    /// and the governing allowance was not set.
    RejectedRequirement { spec: String, reason: String },
    /// An index URL was rejected (not HTTPS, embedded credentials, or a
    /// non-public / metadata destination per the SSRF policy).
    RejectedIndexUrl { url: String, reason: String },
    /// More requirement specs or index URLs than the bound allows.
    TooManyInputs(String),
    /// A tool was found but failed canonical ownership, path hierarchy, stable
    /// identity, or trusted installation-root provenance.
    ToolUntrusted { tool: String, reason: String },
    /// An underlying filesystem / process error.
    Io(std::io::Error),
}

impl std::fmt::Display for ResolverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolverError::RejectedRequirement { spec, reason } => {
                write!(f, "refusing requirement {spec:?}: {reason}")
            }
            ResolverError::RejectedIndexUrl { url, reason } => {
                write!(f, "refusing index url {url:?}: {reason}")
            }
            ResolverError::TooManyInputs(m) => write!(f, "too many resolver inputs: {m}"),
            ResolverError::ToolUntrusted { tool, reason } => {
                write!(f, "refusing to use resolver tool {tool:?}: {reason}")
            }
            ResolverError::Io(e) => write!(f, "resolver I/O error: {e}"),
        }
    }
}

impl std::error::Error for ResolverError {}

impl From<std::io::Error> for ResolverError {
    fn from(e: std::io::Error) -> Self {
        ResolverError::Io(e)
    }
}

/// A resolve request. Construct it from operator input and check it with
/// [`validate_resolver_request_with_artifact_origins`].
#[derive(Debug, Clone)]
pub struct ResolverRequest {
    /// Requirement specs (`requests==2.31.0`, `flask>=3,<4`, ...). Each is
    /// validated by [`validate_requirement`]; the dangerous forms are refused.
    pub requirements: Vec<String>,
    /// Approved index URLs. Empty means `--no-index` (offline / lock-only).
    /// Every URL must be a credential-free public `https` URL.
    pub index_urls: Vec<String>,
    /// What to permit beyond the secure default. Defaults to refusing everything
    /// dangerous.
    pub allowances: ResolverAllowances,
}

impl ResolverRequest {
    /// A request for a single requirement spec with no extra index and the
    /// locked-down default allowances. Convenience for callers and tests.
    pub fn single(requirement: impl Into<String>) -> Self {
        ResolverRequest {
            requirements: vec![requirement.into()],
            index_urls: Vec::new(),
            allowances: ResolverAllowances::default(),
        }
    }
}

/// Only `tirith pkg trust-tool` on Linux enrolls a user-writable resolver
/// executable, and only when its canonical name identifies the tool.
#[cfg(any(target_os = "linux", all(test, unix)))]
fn validate_resolver_tool_name(label: &str, path: &Path) -> Result<(), String> {
    // The canonical path is the trust-store key for the enrolled pin (and would
    // be carried through string argv if contained install returns). Reject the
    // whole canonical path, not merely its file name, when a UTF-8 round-trip
    // would be lossy. Otherwise distinct non-UTF-8 parent paths can collapse to
    // the same U+FFFD-containing key.
    resolver_tool_unicode_path(path)?;
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err("canonical executable has no UTF-8 file name".to_string());
    };
    let name = name
        .strip_suffix(".exe")
        .or_else(|| name.strip_suffix(".EXE"))
        .unwrap_or(name)
        .to_ascii_lowercase();
    let matches = match label {
        "uv" => name == "uv",
        "python" => {
            name == "python"
                || name.strip_prefix("python").is_some_and(|suffix| {
                    !suffix.is_empty()
                        && suffix
                            .chars()
                            .all(|character| character.is_ascii_digit() || character == '.')
                })
        }
        _ => true,
    };
    if matches {
        Ok(())
    } else {
        Err(format!(
            "canonical executable name {name:?} does not identify the requested {label} tool"
        ))
    }
}

const RESOLVER_TOOL_MAX_BYTES: u64 = 512 * 1024 * 1024;
const RESOLVER_TOOL_TRUST_MAX_BYTES: u64 = 1024 * 1024;
#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
struct ResolverToolTrustStore {
    #[serde(default)]
    pins: BTreeMap<String, String>,
}

#[cfg(windows)]
mod windows_trust_acl {
    use std::ffi::c_void;
    use std::mem::{size_of, size_of_val};
    use std::os::windows::ffi::OsStrExt as _;
    use std::path::Path;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetTokenInformation,
        IsWellKnownSid, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
        INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const EXISTING_FILE_MUTATION: u32 = 0x0000_0002
        | 0x0000_0004
        | 0x0000_0010
        | 0x0000_0100
        | 0x0001_0000
        | 0x0004_0000
        | 0x0008_0000
        | 0x1000_0000
        | 0x4000_0000;
    // A non-owner with add-file/add-directory rights on the resolver-tools
    // directory can preplant pins.json, and DELETE_CHILD can replace it.
    const TRUST_DIRECTORY_MUTATION: u32 = EXISTING_FILE_MUTATION | 0x0000_0040;
    // On a higher ancestor, add-file/add-directory creates only a sibling and
    // cannot replace the already-existing next component. Reject authority that
    // can delete that child or take control of the ancestor, while preserving
    // normal default C:\ usability for unprivileged Windows users.
    const ANCESTOR_IDENTITY_MUTATION: u32 =
        0x0000_0040 | 0x0001_0000 | 0x0004_0000 | 0x0008_0000 | 0x1000_0000;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8 = 4;
    const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 5;
    const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;
    const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u8 = 11;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ComponentRole {
        ExistingFile,
        ExecutableDirectory,
        TrustDirectory,
        Ancestor,
    }

    impl ComponentRole {
        fn mutation_mask(self) -> u32 {
            match self {
                Self::ExistingFile => EXISTING_FILE_MUTATION,
                Self::ExecutableDirectory | Self::TrustDirectory => TRUST_DIRECTORY_MUTATION,
                Self::Ancestor => ANCESTOR_IDENTITY_MUTATION,
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HierarchyKind {
        Executable,
        TrustDirectory,
    }

    fn component_role(kind: HierarchyKind, index: usize) -> ComponentRole {
        match (kind, index) {
            (HierarchyKind::Executable, 0) => ComponentRole::ExistingFile,
            // The application directory participates in the Windows DLL search
            // order. Reject untrusted file/subdirectory creation here so an
            // enrolled uv/python cannot be paired with a planted dependency.
            (HierarchyKind::Executable, 1) => ComponentRole::ExecutableDirectory,
            (HierarchyKind::TrustDirectory, 0) => ComponentRole::TrustDirectory,
            _ => ComponentRole::Ancestor,
        }
    }

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: this wrapper owns the handle returned by OpenProcessToken.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            // SAFETY: GetNamedSecurityInfoW allocated this descriptor with LocalAlloc.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }

    struct LocalSid(PSID);

    impl Drop for LocalSid {
        fn drop(&mut self) {
            // SAFETY: ConvertStringSidToSidW allocated this SID with LocalAlloc.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }

    struct SecurityContext {
        current_user_storage: Vec<usize>,
        trusted_installer: LocalSid,
    }

    impl SecurityContext {
        fn load() -> Result<Self, String> {
            let current_user_storage = current_user_sid_buffer()?;
            let sid_text: Vec<u16> =
                "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
            let mut trusted_installer = PSID::default();
            // SAFETY: sid_text is NUL-terminated and trusted_installer is a
            // valid out-pointer. The returned SID is owned by LocalSid.
            unsafe { ConvertStringSidToSidW(PCWSTR(sid_text.as_ptr()), &mut trusted_installer) }
                .map_err(|error| format!("cannot initialize TrustedInstaller SID: {error}"))?;
            Ok(Self {
                current_user_storage,
                trusted_installer: LocalSid(trusted_installer),
            })
        }

        fn current_user(&self) -> PSID {
            token_user_sid(&self.current_user_storage)
        }
    }

    fn current_user_sid_buffer() -> Result<Vec<usize>, String> {
        let mut raw_token = HANDLE::default();
        // SAFETY: raw_token is a valid out-pointer and the pseudo process handle
        // remains valid for the duration of the call.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) }
            .map_err(|error| format!("cannot open current process token: {error}"))?;
        let token = OwnedHandle(raw_token);

        let mut needed = 0_u32;
        // The sizing call is expected to fail with insufficient buffer; `needed`
        // is the authoritative allocation size.
        let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut needed) };
        if needed < size_of::<TOKEN_USER>() as u32 {
            return Err("current process token returned no usable user SID".to_string());
        }
        let words = (needed as usize).div_ceil(size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        // SAFETY: Vec<usize> provides sufficient alignment and `needed` bytes;
        // the API initializes a TOKEN_USER whose SID remains inside this buffer.
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                Some(buffer.as_mut_ptr().cast::<c_void>()),
                needed,
                &mut needed,
            )
        }
        .map_err(|error| format!("cannot read current process user SID: {error}"))?;
        Ok(buffer)
    }

    fn token_user_sid(buffer: &[usize]) -> PSID {
        // SAFETY: current_user_sid_buffer stores a successfully initialized,
        // suitably aligned TOKEN_USER at the start of the allocation.
        unsafe { (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }

    fn sid_is_privileged(sid: PSID, context: &SecurityContext) -> bool {
        let current_user = context.current_user();
        // SAFETY: all SID pointers originate from validated token/security
        // descriptor storage that outlives these calls.
        unsafe {
            EqualSid(sid, current_user).is_ok()
                || IsWellKnownSid(sid, WinLocalSystemSid).as_bool()
                || IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool()
                || EqualSid(sid, context.trusted_installer.0).is_ok()
        }
    }

    fn ace_applies_to_component(flags: u8) -> bool {
        flags & INHERIT_ONLY_ACE.0 as u8 == 0
    }

    fn validate_component(
        path: &Path,
        context: &SecurityContext,
        require_current_user_owner: bool,
        role: ComponentRole,
    ) -> Result<(), String> {
        let current_user = context.current_user();
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err("resolver trust path contains an interior NUL".to_string());
        }
        wide.push(0);

        let mut owner = PSID::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut raw_descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: wide is NUL-terminated and each output pointer is valid.
        let status = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                Some(&mut dacl),
                None,
                &mut raw_descriptor,
            )
        };
        if status.is_err() {
            return Err(format!(
                "cannot read resolver trust path owner/DACL for {}: {status:?}",
                path.display()
            ));
        }
        let _descriptor = LocalSecurityDescriptor(raw_descriptor);
        let owner_is_current_user =
            !owner.is_invalid() && unsafe { EqualSid(owner, current_user) }.is_ok();
        let owner_is_protected = !owner.is_invalid() && sid_is_privileged(owner, context);
        if !owner_is_current_user && (require_current_user_owner || !owner_is_protected) {
            return Err(format!(
                "resolver trust path {} is not owned by the current user or a protected Windows principal",
                path.display(),
            ));
        }
        if dacl.is_null() {
            return Err(format!(
                "resolver trust path {} has an unrestricted null DACL",
                path.display()
            ));
        }

        let mut acl_info = ACL_SIZE_INFORMATION::default();
        // SAFETY: dacl points into the live security descriptor and acl_info is a
        // correctly sized output buffer for AclSizeInformation.
        unsafe {
            GetAclInformation(
                dacl,
                (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
                size_of_val(&acl_info) as u32,
                AclSizeInformation,
            )
        }
        .map_err(|error| format!("cannot inspect resolver trust DACL: {error}"))?;

        for index in 0..acl_info.AceCount {
            let mut raw_ace: *mut c_void = std::ptr::null_mut();
            // SAFETY: index is within the AceCount reported for this live ACL.
            unsafe { GetAce(dacl, index, &mut raw_ace) }
                .map_err(|error| format!("cannot inspect resolver trust ACE {index}: {error}"))?;
            if raw_ace.is_null() {
                return Err(format!("resolver trust ACE {index} is null"));
            }
            // SAFETY: GetAce returned a pointer to at least an ACE_HEADER.
            let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
            // An INHERIT_ONLY ACE is a template for descendants and grants no
            // access to this component. Any effective inherited copy is checked
            // when the traversal reaches the descendant itself.
            if !ace_applies_to_component(header.AceFlags) {
                continue;
            }
            match header.AceType {
                ACCESS_ALLOWED_ACE_TYPE => {
                    if usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>() {
                        return Err(format!("resolver trust ACE {index} is truncated"));
                    }
                    // SAFETY: the size check covers ACCESS_ALLOWED_ACE, whose
                    // SidStart is the first byte of the variable-length SID.
                    let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
                    if ace.Mask & role.mutation_mask() == 0 {
                        continue;
                    }
                    let sid = PSID(std::ptr::addr_of!(ace.SidStart).cast_mut().cast::<c_void>());
                    if !sid_is_privileged(sid, context) {
                        return Err(format!(
                            "resolver trust path {} grants mutation rights to a non-owner principal",
                            path.display()
                        ));
                    }
                }
                ACCESS_ALLOWED_COMPOUND_ACE_TYPE
                | ACCESS_ALLOWED_OBJECT_ACE_TYPE
                | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                    // These layouts carry a variable SID offset and conditions.
                    // Enrollment fails closed instead of guessing whether they
                    // grant a non-owner mutation authority.
                    return Err(format!(
                        "resolver trust path {} uses an unsupported conditional/object allow ACE",
                        path.display()
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub(super) fn validate_owner_only(path: &Path) -> Result<(), String> {
        let context = SecurityContext::load()?;
        validate_component(path, &context, true, ComponentRole::ExistingFile)
    }

    fn validate_hierarchy(
        path: &Path,
        require_current_user_leaf: bool,
        kind: HierarchyKind,
    ) -> Result<(), String> {
        let canonical = path
            .canonicalize()
            .map_err(|error| format!("cannot canonicalize Windows trust path: {error}"))?;
        let context = SecurityContext::load()?;
        for (index, component) in canonical.ancestors().enumerate() {
            validate_component(
                component,
                &context,
                require_current_user_leaf && index == 0,
                component_role(kind, index),
            )?;
        }
        Ok(())
    }

    /// Validate an already-existing enrolled executable and every canonical
    /// ancestor. Higher ancestors may allow sibling creation, but not deletion
    /// or security-control of the existing next path component. The immediate
    /// application directory also rejects child creation because Windows may
    /// load dependent DLLs from beside the executable.
    pub(super) fn validate_executable_hierarchy(path: &Path) -> Result<(), String> {
        validate_hierarchy(path, false, HierarchyKind::Executable)
    }

    /// Validate the resolver-tools directory and every canonical ancestor. The
    /// leaf is current-user-owned and rejects untrusted child creation so an
    /// attacker cannot preplant or replace pins.json.
    pub(super) fn validate_trust_directory_hierarchy(path: &Path) -> Result<(), String> {
        validate_hierarchy(path, true, HierarchyKind::TrustDirectory)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn inheritance_only_ace_is_not_effective_on_current_component() {
            assert!(!ace_applies_to_component(INHERIT_ONLY_ACE.0 as u8));
            assert!(ace_applies_to_component(0));
        }

        #[test]
        fn role_selection_protects_executable_directory_but_not_distant_siblings() {
            assert_eq!(
                component_role(HierarchyKind::Executable, 0),
                ComponentRole::ExistingFile
            );
            assert_eq!(
                component_role(HierarchyKind::Executable, 1),
                ComponentRole::ExecutableDirectory
            );
            assert_eq!(
                component_role(HierarchyKind::Executable, 2),
                ComponentRole::Ancestor
            );
            assert_ne!(
                ComponentRole::ExecutableDirectory.mutation_mask() & 0x0000_0002,
                0
            );
            assert_eq!(ComponentRole::Ancestor.mutation_mask() & 0x0000_0002, 0);
            assert_eq!(
                component_role(HierarchyKind::TrustDirectory, 0),
                ComponentRole::TrustDirectory
            );
            assert_eq!(
                component_role(HierarchyKind::TrustDirectory, 1),
                ComponentRole::Ancestor
            );
        }

        #[test]
        fn normal_windows_test_executable_hierarchy_is_usable() {
            let executable = std::env::current_exe().unwrap();
            match validate_executable_hierarchy(&executable) {
                Ok(()) => {}
                // Hosted Windows runners build under a tree whose DACL grants
                // mutation rights to a non-owner principal (the runner's admin
                // group), so the running test binary legitimately fails this
                // check and there is nothing left to assert. Any OTHER refusal
                // is a real regression and still fails.
                Err(reason) if reason.contains("non-owner principal") => {
                    eprintln!("skipping: {reason}");
                }
                Err(reason) => panic!("unexpected hierarchy refusal: {reason}"),
            }
        }
    }
}

fn resolver_tool_unicode_path(path: &Path) -> Result<&str, String> {
    path.to_str().ok_or_else(|| {
        "canonical resolver executable path is not valid Unicode; non-Unicode resolver paths are refused because enrollment, argv, and PATH must preserve the exact path"
            .to_string()
    })
}

/// Versioned, injective JSON-map key for a canonical resolver path. Legacy
/// display-string keys are intentionally not consulted: `Path::display` is
/// lossy, so silently accepting those entries would preserve path collisions.
fn resolver_tool_store_key(path: &Path) -> Result<String, String> {
    let exact = resolver_tool_unicode_path(path)?;
    Ok(format!("utf8-hex-v1:{}", hex::encode(exact.as_bytes())))
}

fn resolver_tool_trust_file() -> Result<PathBuf, String> {
    let base = crate::policy::config_dir()
        .ok_or_else(|| "cannot determine the operator config directory".to_string())?;
    Ok(base.join("resolver-tools").join("pins.json"))
}

fn resolver_tool_digest(path: &Path) -> Result<String, String> {
    let handle = crate::util::open_read_no_follow_capped(path, RESOLVER_TOOL_MAX_BYTES).map_err(
        |error| format!("cannot open enrolled resolver tool without following links: {error:?}"),
    )?;
    match crate::util::sha256_from_handle(handle, RESOLVER_TOOL_MAX_BYTES)
        .map_err(|error| format!("cannot hash resolver tool: {error}"))?
    {
        crate::util::HashOutcome::Digest(digest) => Ok(digest),
        crate::util::HashOutcome::BudgetExceeded => Err(format!(
            "resolver tool exceeds the {} byte enrollment cap",
            RESOLVER_TOOL_MAX_BYTES
        )),
    }
}

/// Enrollment is deliberately narrower than ordinary executable trust. A
/// user-writable `uv` can participate in enforcement only when Linux can seal
/// the exact enrolled bytes and the image has no interpreter or dynamic-loader
/// dependency that could remain mutable outside that seal.
#[cfg(target_os = "linux")]
fn validate_static_linux_uv(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::FileExt as _;

    const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
    const ELFCLASS32: u8 = 1;
    const ELFCLASS64: u8 = 2;
    const ELFDATA2LSB: u8 = 1;
    const ELFDATA2MSB: u8 = 2;
    const PT_LOAD: u32 = 1;
    const PT_DYNAMIC: u32 = 2;
    const PT_INTERP: u32 = 3;
    const MAX_PROGRAM_HEADERS: u64 = 4096;

    let file = crate::util::open_read_no_follow_capped(path, RESOLVER_TOOL_MAX_BYTES)
        .map_err(|error| format!("cannot inspect enrolled uv image: {error:?}"))?;
    let mut ident = [0_u8; 16];
    file.read_exact_at(&mut ident, 0)
        .map_err(|error| format!("cannot read enrolled uv ELF identity: {error}"))?;
    if &ident[..4] != ELF_MAGIC {
        return Err(
            "user-writable uv enrollment requires a static native Linux ELF image; scripts and wrapper launchers are refused"
                .to_string(),
        );
    }
    let (header_len, phoff_offset, phentsize_offset, phnum_offset) = match ident[4] {
        ELFCLASS32 => (52_usize, 28_usize, 42_usize, 44_usize),
        ELFCLASS64 => (64_usize, 32_usize, 54_usize, 56_usize),
        other => return Err(format!("enrolled uv uses unsupported ELF class {other}")),
    };
    let little_endian = match ident[5] {
        ELFDATA2LSB => true,
        ELFDATA2MSB => false,
        other => {
            return Err(format!(
                "enrolled uv uses unsupported ELF byte order {other}"
            ))
        }
    };
    let mut header = vec![0_u8; header_len];
    file.read_exact_at(&mut header, 0)
        .map_err(|error| format!("cannot read enrolled uv ELF header: {error}"))?;
    let read_u16 = |offset: usize| {
        let bytes: [u8; 2] = header[offset..offset + 2]
            .try_into()
            .expect("fixed ELF header offsets are in bounds");
        if little_endian {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        }
    };
    let read_u32 = |offset: usize| {
        let bytes: [u8; 4] = header[offset..offset + 4]
            .try_into()
            .expect("fixed ELF header offsets are in bounds");
        if little_endian {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    };
    let read_u64 = |offset: usize| {
        let bytes: [u8; 8] = header[offset..offset + 8]
            .try_into()
            .expect("fixed ELF header offsets are in bounds");
        if little_endian {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        }
    };
    let phoff = if ident[4] == ELFCLASS32 {
        u64::from(read_u32(phoff_offset))
    } else {
        read_u64(phoff_offset)
    };
    let phentsize = u64::from(read_u16(phentsize_offset));
    let phnum = u64::from(read_u16(phnum_offset));
    if phnum == 0 || phnum > MAX_PROGRAM_HEADERS || !(4..=256).contains(&phentsize) {
        return Err("enrolled uv has an invalid or unbounded ELF program-header table".to_string());
    }
    let table_bytes = phentsize
        .checked_mul(phnum)
        .and_then(|bytes| phoff.checked_add(bytes))
        .ok_or_else(|| "enrolled uv ELF program-header table overflows".to_string())?;
    if table_bytes > file.metadata().map_err(|error| error.to_string())?.len() {
        return Err("enrolled uv ELF program-header table is truncated".to_string());
    }

    let mut saw_load = false;
    for index in 0..phnum {
        let offset = phoff + index * phentsize;
        let mut kind = [0_u8; 4];
        file.read_exact_at(&mut kind, offset)
            .map_err(|error| format!("cannot read enrolled uv program header: {error}"))?;
        let kind = if little_endian {
            u32::from_le_bytes(kind)
        } else {
            u32::from_be_bytes(kind)
        };
        match kind {
            PT_LOAD => saw_load = true,
            PT_DYNAMIC | PT_INTERP => {
                return Err(
                    "user-writable uv enrollment requires a fully static ELF with no interpreter or dynamic-loader dependency"
                        .to_string(),
                )
            }
            _ => {}
        }
    }
    if !saw_load {
        return Err("enrolled uv ELF has no loadable segment".to_string());
    }
    Ok(())
}

fn read_resolver_tool_trust_store(
    trust_file: &Path,
) -> Result<Option<ResolverToolTrustStore>, String> {
    let metadata = match std::fs::symlink_metadata(trust_file) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot inspect resolver-tool trust store: {error}")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("resolver-tool trust store is not a regular non-symlink file".to_string());
    }
    validate_resolver_trust_directory(
        trust_file
            .parent()
            .ok_or_else(|| "resolver-tool trust store has no parent".to_string())?,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid || metadata.mode() & 0o077 != 0 {
            return Err(
                "resolver-tool trust store must be owned by the current user and mode 0600"
                    .to_string(),
            );
        }
        crate::trusted_child::reject_unix_extended_acl(trust_file, false)?;
    }
    #[cfg(windows)]
    windows_trust_acl::validate_owner_only(trust_file)?;
    let bytes = crate::util::read_text_no_follow_capped(trust_file, RESOLVER_TOOL_TRUST_MAX_BYTES)
        .map_err(|error| format!("cannot read resolver-tool trust store: {error:?}"))?;
    let store: ResolverToolTrustStore = serde_json::from_slice(&bytes)
        .map_err(|error| format!("resolver-tool trust store is corrupt: {error}"))?;
    Ok(Some(store))
}

fn resolver_tool_pin_matches(path: &Path) -> Result<bool, String> {
    let trust_file = resolver_tool_trust_file()?;
    let Some(store) = read_resolver_tool_trust_store(&trust_file)? else {
        return Ok(false);
    };
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize resolver tool: {error}"))?;
    #[cfg(windows)]
    windows_trust_acl::validate_executable_hierarchy(&canonical)?;
    let key = resolver_tool_store_key(&canonical)?;
    let Some(expected) = store.pins.get(&key) else {
        return Ok(false);
    };
    Ok(constant_time_hex_eq(
        expected.as_bytes(),
        resolver_tool_digest(&canonical)?.as_bytes(),
    ))
}

fn constant_time_hex_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

/// Explicitly enroll a fully static, native Linux `uv` executable by canonical
/// absolute path and SHA-256 in Tirith's owner-only operator trust store. A
/// user-writable Python runtime cannot be made trustworthy by pinning only its
/// launcher, so it is rejected before any trust-store side effect. PATH
/// discovery never creates a pin implicitly.
pub fn enroll_resolver_tool(path: &Path) -> Result<PathBuf, ResolverError> {
    let executable =
        TrustedExecutable::from_absolute(path, &crate::trusted_child::ambient_denied_roots())
            .map_err(|error| ResolverError::ToolUntrusted {
                tool: path.display().to_string(),
                reason: error.to_string(),
            })?;
    let canonical = executable.path().to_path_buf();
    #[cfg(windows)]
    windows_trust_acl::validate_executable_hierarchy(&canonical).map_err(resolver_io_error)?;
    if !executable.has_system_helper_provenance() {
        #[cfg(target_os = "linux")]
        {
            validate_resolver_tool_name("uv", &canonical).map_err(|reason| {
                ResolverError::ToolUntrusted {
                    tool: canonical.display().to_string(),
                    reason: format!(
                        "user-writable enrollment can authorize only uv; Python and its runtime tree must be root-managed: {reason}"
                    ),
                }
            })?;
            validate_static_linux_uv(&canonical).map_err(|reason| {
                ResolverError::ToolUntrusted {
                    tool: canonical.display().to_string(),
                    reason,
                }
            })?;
        }
        #[cfg(not(target_os = "linux"))]
        return Err(ResolverError::ToolUntrusted {
            tool: canonical.display().to_string(),
            reason: "user-writable resolver enrollment is enforceable only for a static native uv image on Linux; this platform cannot seal the enrolled executable bytes"
                .to_string(),
        });
    }
    let store_key =
        resolver_tool_store_key(&canonical).map_err(|reason| ResolverError::ToolUntrusted {
            tool: canonical.display().to_string(),
            reason,
        })?;
    let digest = resolver_tool_digest(&canonical).map_err(resolver_io_error)?;
    executable
        .revalidate()
        .map_err(|error| ResolverError::ToolUntrusted {
            tool: canonical.display().to_string(),
            reason: format!("resolver tool changed during enrollment: {error}"),
        })?;
    let trust_file = resolver_tool_trust_file().map_err(resolver_io_error)?;
    let trust_dir = trust_file
        .parent()
        .ok_or_else(|| resolver_io_error("resolver-tool trust file has no parent"))?;
    crate::util::create_dir_durable(trust_dir).map_err(ResolverError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(trust_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(ResolverError::Io)?;
    }
    validate_resolver_trust_directory(trust_dir).map_err(resolver_io_error)?;
    // Never merge an unvalidated pre-existing file: doing so and then replacing
    // it with a fresh 0600 file would launder attacker-selected pins into trusted
    // enrollment state.
    let mut store = read_resolver_tool_trust_store(&trust_file)
        .map_err(resolver_io_error)?
        .unwrap_or_default();
    store.pins.insert(store_key, digest);
    let body = serde_json::to_vec_pretty(&store).map_err(|error| {
        resolver_io_error(format!(
            "cannot serialize resolver-tool trust store: {error}"
        ))
    })?;
    crate::util::write_file_atomic_0600(&trust_file, &body).map_err(ResolverError::Io)?;
    if !resolver_tool_pin_matches(&canonical).map_err(resolver_io_error)? {
        return Err(ResolverError::ToolUntrusted {
            tool: canonical.display().to_string(),
            reason: "resolver tool changed while validating the written enrollment pin".to_string(),
        });
    }
    Ok(canonical)
}

fn validate_resolver_trust_directory(directory: &Path) -> Result<(), String> {
    let canonical = directory
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize resolver trust directory: {error}"))?;
    for denied in crate::trusted_child::ambient_denied_roots() {
        let denied = denied.canonicalize().unwrap_or(denied);
        if canonical == denied || canonical.starts_with(&denied) {
            return Err(format!(
                "resolver trust directory {} is inside denied project/temp root {}",
                canonical.display(),
                denied.display()
            ));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let effective_uid = unsafe { libc::geteuid() };
        for component in canonical.ancestors() {
            let metadata = std::fs::metadata(component)
                .map_err(|error| format!("cannot stat {}: {error}", component.display()))?;
            if metadata.uid() != 0 && metadata.uid() != effective_uid {
                return Err(format!(
                    "resolver trust directory ancestor {} has foreign owner uid {}",
                    component.display(),
                    metadata.uid()
                ));
            }
            if metadata.mode() & 0o022 != 0 {
                return Err(format!(
                    "resolver trust directory ancestor {} is group/world writable",
                    component.display()
                ));
            }
            crate::trusted_child::reject_unix_extended_acl(component, true)?;
        }
    }
    #[cfg(windows)]
    windows_trust_acl::validate_trust_directory_hierarchy(&canonical)?;
    Ok(())
}

fn resolver_io_error(reason: impl Into<String>) -> ResolverError {
    ResolverError::Io(std::io::Error::other(reason.into()))
}

/// Split an editable-requirement option from its target.
///
/// One helper for both classifiers so they cannot drift apart. The target may
/// be attached (`-e./pkg`), joined with `=`, or the next token: pip's
/// requirements parser is optparse-backed, where the attached `-eVALUE` form is
/// standard, so an option-shaped token like `-editable-pkg` genuinely means
/// `-e ditable-pkg` to the resolver child. Tirith models what the child does,
/// so this deliberately does NOT require a delimiter — demanding one would
/// refuse `-e./pkg`, which pip accepts. The extracted target is re-validated by
/// the caller, so the VCS, direct-URL, and local-path controls still apply.
fn editable_requirement_target(trimmed: &str) -> Option<&str> {
    let lower = trimmed.to_ascii_lowercase();
    for flag in ["--editable", "-e"] {
        if lower.starts_with(flag) {
            return Some(&trimmed[flag.len()..]);
        }
    }
    None
}

/// Classify a requirement spec, refusing the forms that would build from source
/// or pull bytes from outside the approved indexes, unless the governing
/// allowance is set. Returns `Ok(())` for an acceptable
/// `name[extras][version-specifiers][; marker]` spec.
///
/// This is a *pre-flight* gate: it runs before any subprocess, so a refused
/// requirement never reaches `uv` / `pip` and a build backend never executes
/// (cross-cutting invariant 4). It is deliberately conservative; an acceptable
/// spec still goes through `uv` for full PEP 508 resolution.
pub fn validate_requirement(
    spec: &str,
    allowances: &ResolverAllowances,
) -> Result<(), ResolverError> {
    let reject = |reason: &str| {
        Err(ResolverError::RejectedRequirement {
            spec: spec.to_string(),
            reason: reason.to_string(),
        })
    };
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return reject("empty requirement");
    }
    // A control character (newline / CR / NUL / etc.) could smuggle a second
    // requirement or break the lock file; refuse outright. Horizontal tab is
    // the sole exception because PEP 508 explicitly includes it in `wsp` and
    // the lexical parser treats it exactly like a space.
    if trimmed.chars().any(|c| c != '\t' && c.is_control()) {
        return reject("requirement contains a control character");
    }
    // A requirements-file include (`-r other.txt`) or any other dashed option is
    // refused: callers pass concrete specs, and a `-r` could pull an
    // attacker-controlled file of further requirements past these checks.
    if trimmed.starts_with('-') {
        if let Some(target) = editable_requirement_target(trimmed) {
            if !allowances.allow_editable {
                return reject("editable installs (-e/--editable) are not permitted");
            }
            let target = target.trim_start_matches('=').trim();
            if target.is_empty() {
                return reject("editable requirement has no target");
            }
            // An editable allowance does not bypass the independent VCS, direct
            // URL, and local-path controls.
            return validate_requirement(target, allowances);
        }
        return reject("option-form requirements (leading '-') are not permitted");
    }

    match classify_requirement_location(trimmed).map_err(|reason| {
        ResolverError::RejectedRequirement {
            spec: spec.to_string(),
            reason,
        }
    })? {
        RequirementLocation::Named => {}
        RequirementLocation::Vcs(target) => {
            if !allowances.allow_vcs {
                return reject("VCS requirements (git+/hg+/svn+/bzr+) are not permitted");
            }
            parse_vcs_url(target).map_err(|reason| ResolverError::RejectedRequirement {
                spec: spec.to_string(),
                reason: format!("VCS URL rejected: {reason}"),
            })?;
        }
        RequirementLocation::Direct(target) => {
            if !allowances.allow_direct_url {
                return reject("direct-URL requirements (name @ url / bare url) are not permitted");
            }
            parse_network_url(target).map_err(|reason| ResolverError::RejectedRequirement {
                spec: spec.to_string(),
                reason: format!("direct URL rejected: {reason}"),
            })?;
        }
        RequirementLocation::Local => {
            if !allowances.allow_local_path {
                return reject("local-path requirements are not permitted");
            }
        }
    }
    // sdist-only requirements cannot be expressed by name alone (a `.tar.gz`
    // target is caught as a local path or direct URL above), and no resolve or
    // download runs any more. Nothing further to gate here.
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequirementLocation<'a> {
    Named,
    Vcs(&'a str),
    Direct(&'a str),
    Local,
}

/// Canonically classify the PEP 508 location portion of a requirement. The `@`
/// token has optional surrounding whitespace in PEP 508, so classification is
/// structural and never relies on the old exact `" @ "` spelling.
fn classify_requirement_location(spec: &str) -> Result<RequirementLocation<'_>, String> {
    let trimmed = spec.trim();
    let lower = trimmed.to_ascii_lowercase();

    // Packaging tools accept platform path extensions in addition to strict PEP
    // 508. Classify them before `Url::parse`, which otherwise treats `C:/pkg`
    // as a URL with scheme `c` and could bypass the local-path allowance.
    if is_local_path_requirement(trimmed)
        && (!trimmed.contains("://") || lower.starts_with("file:"))
    {
        return Ok(RequirementLocation::Local);
    }
    if is_vcs_target(&lower) {
        return Ok(RequirementLocation::Vcs(trimmed));
    }
    if let Ok(parsed) = url::Url::parse(trimmed) {
        return if parsed.scheme().eq_ignore_ascii_case("file") {
            Ok(RequirementLocation::Local)
        } else {
            Ok(RequirementLocation::Direct(trimmed))
        };
    }

    let after_name = pep508_after_name_and_extras(trimmed)?;
    if let Some(raw_target) = after_name.strip_prefix('@') {
        let raw_target = raw_target.trim();
        if raw_target.is_empty() {
            return Err("malformed PEP 508 direct reference".to_string());
        }
        let target = strip_pep508_marker(raw_target);
        if target.is_empty() {
            return Err("malformed PEP 508 direct reference".to_string());
        }
        let target_lower = target.to_ascii_lowercase();
        if is_vcs_target(&target_lower) {
            return Ok(RequirementLocation::Vcs(target));
        }
        if is_local_path_requirement(target)
            && (!target.contains("://") || target_lower.starts_with("file:"))
        {
            return Ok(RequirementLocation::Local);
        }
        if url::Url::parse(target).is_ok() {
            return Ok(RequirementLocation::Direct(target));
        }
        return Err("malformed or unsupported PEP 508 direct reference".to_string());
    }

    // `@` inside an arbitrary-equality version (`===foo@bar`) or a quoted
    // environment marker is data, not a direct-reference delimiter. Requiring
    // the delimiter immediately after the parsed name/extras is the PEP 508
    // grammar distinction the old substring matcher lacked.
    let named_tail = after_name.trim_start();
    if named_tail.is_empty()
        || named_tail.starts_with(';')
        || named_tail.starts_with('(')
        || ["===", "~=", "==", "!=", "<=", ">=", "<", ">"]
            .iter()
            .any(|operator| named_tail.starts_with(operator))
    {
        Ok(RequirementLocation::Named)
    } else {
        Err("malformed or unsupported PEP 508 requirement".to_string())
    }
}

/// Return the slice immediately after a syntactically valid PEP 508
/// distribution name and optional extras list. This is deliberately lexical:
/// it performs no filesystem or network access and preserves the remaining
/// version/direct-reference/marker text for policy classification.
fn pep508_after_name_and_extras(spec: &str) -> Result<&str, String> {
    let bytes = spec.as_bytes();
    let Some(first) = bytes.first().copied() else {
        return Err("empty requirement".to_string());
    };
    if !first.is_ascii_alphanumeric() {
        return Err("requirement has no valid distribution name".to_string());
    }
    let mut cursor = 1usize;
    while cursor < bytes.len()
        && (bytes[cursor].is_ascii_alphanumeric() || matches!(bytes[cursor], b'-' | b'_' | b'.'))
    {
        cursor += 1;
    }
    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    if bytes.get(cursor) == Some(&b'[') {
        cursor += 1;
        let extras_start = cursor;
        while cursor < bytes.len() && bytes[cursor] != b']' {
            let byte = bytes[cursor];
            if !(byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b',' | b' ' | b'\t'))
            {
                return Err("requirement extras contain an invalid character".to_string());
            }
            cursor += 1;
        }
        if cursor == extras_start || bytes.get(cursor) != Some(&b']') {
            return Err("requirement has malformed extras".to_string());
        }
        cursor += 1;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
    }
    Ok(&spec[cursor..])
}

fn is_vcs_target(lower: &str) -> bool {
    ["git+", "hg+", "svn+", "bzr+"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// A PEP 508 marker follows a direct URL after whitespace and `;`. Semicolons
/// within a URL path remain part of the URL because they are not preceded by
/// whitespace.
fn strip_pep508_marker(target: &str) -> &str {
    target
        .char_indices()
        .find_map(|(index, character)| {
            if character != ';' {
                return None;
            }
            target[..index]
                .chars()
                .next_back()
                .filter(|c| c.is_ascii_whitespace())
                .map(|_| target[..index].trim_end())
        })
        .unwrap_or(target)
}

/// Whether `spec` denotes a local path rather than a named distribution.
fn is_local_path_requirement(spec: &str) -> bool {
    let lower = spec.to_ascii_lowercase();
    if lower.starts_with("file:") {
        return true;
    }
    // Explicit relative / absolute prefixes.
    if spec.starts_with("./")
        || spec.starts_with("../")
        || spec.starts_with(".\\")
        || spec.starts_with("..\\")
        || spec == "."
        || spec == ".."
        || spec.starts_with('/')
        || spec.starts_with('~')
    {
        return true;
    }
    // Windows drive-absolute (`C:\...` / `C:/...`). A bare distribution name
    // never contains a backslash or a drive colon.
    if spec.contains('\\') {
        return true;
    }
    let bytes = spec.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        // `C:` drive prefix. (A PEP 508 name cannot contain a colon, so any
        // colon here is suspicious; the drive form is the concrete local case.)
        return true;
    }
    // Packaging-tool extensions for bare archives are local even though strict
    // PEP 508 would require a `file:` URL. Keep this lexical so validation is
    // effect-free and cannot probe attacker-chosen filesystem names.
    if [".whl", ".tar.gz", ".zip", ".tar.bz2", ".tgz"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
    {
        return true;
    }
    false
}

fn parse_network_url(raw: &str) -> Result<url::Url, String> {
    let mut parsed = url::Url::parse(raw).map_err(|e| format!("invalid URL: {e}"))?;
    if parsed.scheme() != "https" {
        return Err("resolver destinations must use HTTPS".to_string());
    }
    let Some(host) = parsed.host().map(|host| host.to_owned()) else {
        return Err("resolver destination must have a host and port".to_string());
    };
    let Some(port) = parsed.port_or_known_default() else {
        return Err("resolver destination must have a host and port".to_string());
    };
    match host {
        url::Host::Domain(domain) => {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            if domain == "localhost" || domain.ends_with(".localhost") {
                return Err("resolver destination is local-only".to_string());
            }
            parsed
                .set_host(Some(&domain))
                .map_err(|_| "resolver destination host could not be canonicalized".to_string())?;
        }
        url::Host::Ipv4(address) => {
            let address = std::net::SocketAddr::new(address.into(), port);
            if !crate::url_validate::is_public_addr(&address) {
                return Err("resolver destination is not globally reachable".to_string());
            }
        }
        url::Host::Ipv6(address) => {
            let socket = std::net::SocketAddr::new(address.into(), port);
            if !crate::url_validate::is_public_addr(&socket) {
                return Err("resolver destination is not globally reachable".to_string());
            }
        }
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("resolver URL carries embedded credentials".to_string());
    }
    Ok(parsed)
}

fn parse_vcs_url(raw: &str) -> Result<url::Url, String> {
    let (_, network_url) = raw
        .split_once('+')
        .ok_or_else(|| "VCS reference has no transport".to_string())?;
    parse_network_url(network_url)
}

/// Validate a resolver request plus explicit artifact/CDN origins without
/// starting a process, binding a socket, resolving DNS, or writing files. Every
/// requirement must pass [`validate_requirement`] (and, when a direct URL is
/// allowed, parse as a network URL), and every index URL and artifact origin
/// must parse as a credential-free network URL.
pub fn validate_resolver_request_with_artifact_origins(
    request: &ResolverRequest,
    artifact_origins: &[String],
) -> Result<(), ResolverError> {
    if request.requirements.len() > MAX_REQUIREMENTS {
        return Err(ResolverError::TooManyInputs(format!(
            "{} requirements exceeds the {MAX_REQUIREMENTS} cap",
            request.requirements.len()
        )));
    }
    if request.index_urls.len() > MAX_INDEX_URLS {
        return Err(ResolverError::TooManyInputs(format!(
            "{} index URLs exceeds the {MAX_INDEX_URLS} cap",
            request.index_urls.len()
        )));
    }
    if artifact_origins.len() > MAX_INDEX_URLS {
        return Err(ResolverError::TooManyInputs(format!(
            "{} artifact origins exceeds the {MAX_INDEX_URLS} cap",
            artifact_origins.len()
        )));
    }
    for spec in &request.requirements {
        validate_requirement(spec, &request.allowances)?;
        permitted_requirement_url(spec, &request.allowances)?;
    }
    for raw in &request.index_urls {
        parse_network_url(raw).map_err(|reason| ResolverError::RejectedIndexUrl {
            url: raw.clone(),
            reason,
        })?;
    }
    for raw in artifact_origins {
        parse_network_url(raw).map_err(|reason| ResolverError::RejectedIndexUrl {
            url: raw.clone(),
            reason: format!("artifact origin rejected: {reason}"),
        })?;
    }
    Ok(())
}

fn permitted_requirement_url(
    spec: &str,
    allowances: &ResolverAllowances,
) -> Result<Option<url::Url>, ResolverError> {
    let trimmed = spec.trim();
    if trimmed.starts_with('-') && allowances.allow_editable {
        let Some(target) = editable_requirement_target(trimmed) else {
            return Ok(None);
        };
        return permitted_requirement_url(target.trim_start_matches('=').trim(), allowances);
    }

    let location = classify_requirement_location(trimmed).map_err(|reason| {
        ResolverError::RejectedRequirement {
            spec: spec.to_string(),
            reason,
        }
    })?;
    let parsed = match location {
        RequirementLocation::Direct(target) if allowances.allow_direct_url => {
            Some(parse_network_url(target).map_err(|reason| {
                ResolverError::RejectedRequirement {
                    spec: spec.to_string(),
                    reason: format!("direct URL rejected: {reason}"),
                }
            })?)
        }
        RequirementLocation::Vcs(target) if allowances.allow_vcs => Some(
            parse_vcs_url(target).map_err(|reason| ResolverError::RejectedRequirement {
                spec: spec.to_string(),
                reason: format!("VCS URL rejected: {reason}"),
            })?,
        ),
        _ => None,
    };
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use tirith_test_support::GlobalStateGuard;

    fn validate_resolver_request(request: &ResolverRequest) -> Result<(), ResolverError> {
        validate_resolver_request_with_artifact_origins(request, &[])
    }

    /// One index URL through the full request validator.
    fn validate_index_url(url: &str) -> Result<(), ResolverError> {
        validate_resolver_request(&ResolverRequest {
            requirements: Vec::new(),
            index_urls: vec![url.to_string()],
            allowances: ResolverAllowances::default(),
        })
    }

    #[test]
    fn canonical_index_alias_and_artifact_origin_pass_validation() {
        let request = ResolverRequest {
            requirements: vec!["example==1.0".to_string()],
            index_urls: vec!["https://INDEX.Example.:443/simple".to_string()],
            allowances: ResolverAllowances::default(),
        };
        let artifact_origins = vec!["https://cdn.example/wheels".to_string()];
        validate_resolver_request_with_artifact_origins(&request, &artifact_origins).unwrap();

        let credentialed = vec!["https://user:pass@cdn.example/wheels".to_string()];
        match validate_resolver_request_with_artifact_origins(&request, &credentialed) {
            Err(ResolverError::RejectedIndexUrl { reason, .. }) => {
                assert!(reason.starts_with("artifact origin rejected:"), "{reason}");
            }
            other => panic!("expected a rejected artifact origin, got {other:?}"),
        }
    }

    #[test]
    fn whitespace_free_unapproved_direct_url_is_rejected_by_validation() {
        let request = ResolverRequest::single(
            "examplepkg@https://unapproved.example/pkg-1.0-py3-none-any.whl",
        );
        let error = validate_resolver_request(&request).unwrap_err();
        assert!(
            matches!(error, ResolverError::RejectedRequirement { .. }),
            "{error:?}"
        );
    }

    fn allow_all() -> ResolverAllowances {
        ResolverAllowances {
            allow_vcs: true,
            allow_editable: true,
            allow_local_path: true,
            allow_direct_url: true,
        }
    }

    // ---- requirement validation -------------------------------------------

    #[test]
    fn plain_named_requirements_accepted() {
        let a = ResolverAllowances::default();
        for spec in [
            "requests",
            "requests==2.31.0",
            "flask>=3,<4",
            "django[argon2]==5.0",
            "numpy==1.26.4 ; python_version >= '3.9'",
        ] {
            assert!(
                validate_requirement(spec, &a).is_ok(),
                "{spec:?} should be accepted"
            );
        }
    }

    #[test]
    fn editable_requirement_refused_by_default_allowed_with_flag() {
        let def = ResolverAllowances::default();
        for spec in ["-e .", "--editable ./pkg", "-e git+https://x/y.git"] {
            assert!(
                matches!(
                    validate_requirement(spec, &def),
                    Err(ResolverError::RejectedRequirement { .. })
                ),
                "{spec:?} should be refused by default"
            );
        }
        // With the editable allowance, the `-e` forms pass the pre-flight gate.
        assert!(validate_requirement("-e .", &allow_all()).is_ok());
    }

    #[test]
    fn vcs_requirement_refused_by_default() {
        let def = ResolverAllowances::default();
        for spec in [
            "git+https://github.com/psf/requests.git",
            "requests @ git+https://github.com/psf/requests.git",
            "svn+https://example.invalid/repo",
        ] {
            assert!(
                matches!(
                    validate_requirement(spec, &def),
                    Err(ResolverError::RejectedRequirement { .. })
                ),
                "{spec:?} should be refused"
            );
        }
        let a = ResolverAllowances {
            allow_vcs: true,
            ..Default::default()
        };
        assert!(validate_requirement("git+https://example.invalid/x.git", &a).is_ok());
    }

    #[test]
    fn direct_url_requirement_refused_by_default() {
        let def = ResolverAllowances::default();
        for spec in [
            "requests @ https://example.invalid/requests-2.31.0-py3-none-any.whl",
            "requests@https://example.invalid/requests-2.31.0-py3-none-any.whl",
            "requests @https://example.invalid/requests-2.31.0-py3-none-any.whl",
            "requests@ https://example.invalid/requests-2.31.0-py3-none-any.whl",
            "requests\t@\thttps://example.invalid/requests-2.31.0-py3-none-any.whl",
            "https://example.invalid/x-1.0-py3-none-any.whl",
        ] {
            let error = validate_requirement(spec, &def).unwrap_err();
            let ResolverError::RejectedRequirement { reason, .. } = error else {
                panic!("{spec:?} produced the wrong error: {error:?}");
            };
            assert!(
                reason.contains("direct-URL requirements"),
                "{spec:?} must be classified as a direct URL, got: {reason}"
            );
        }
    }

    #[test]
    fn malformed_at_reference_fails_closed() {
        let error =
            validate_requirement("requests@not a url", &ResolverAllowances::default()).unwrap_err();
        assert!(matches!(error, ResolverError::RejectedRequirement { .. }));
    }

    #[test]
    fn pep508_at_inside_version_or_marker_is_not_a_direct_reference() {
        let allowances = ResolverAllowances::default();
        for requirement in [
            "pkg===foo@bar",
            "pkg; implementation_name == 'a@b'",
            "pkg[security, socks]>=1.0; python_version >= '3.11'",
        ] {
            assert!(
                validate_requirement(requirement, &allowances).is_ok(),
                "{requirement:?}"
            );
        }
    }

    #[test]
    fn direct_url_allowed_still_passes_ssrf() {
        let a = ResolverAllowances {
            allow_direct_url: true,
            ..Default::default()
        };
        // A loopback / private direct URL is rejected even when direct URLs are
        // allowed. Literal addresses fail preflight; DNS names are rechecked at
        // the broker's exact connect boundary.
        let err =
            validate_requirement("x @ http://127.0.0.1/x-1.0-py3-none-any.whl", &a).unwrap_err();
        assert!(
            matches!(err, ResolverError::RejectedRequirement { .. }),
            "loopback direct URL must be refused: {err:?}"
        );
        // Plain HTTP is always rejected for resolver traffic.
        let err =
            validate_requirement("x @ http://example.com/x-1.0-py3-none-any.whl", &a).unwrap_err();
        assert!(matches!(err, ResolverError::RejectedRequirement { .. }));
    }

    #[test]
    fn local_path_requirement_refused_by_default() {
        let def = ResolverAllowances::default();
        for spec in [
            "./pkg",
            "../pkg",
            "/abs/pkg",
            "file:///abs/pkg",
            "~/pkg",
            "C:\\pkg",
            "C:/pkg",
        ] {
            assert!(
                matches!(
                    validate_requirement(spec, &def),
                    Err(ResolverError::RejectedRequirement { .. })
                ),
                "{spec:?} should be refused as a local path"
            );
        }
    }

    #[test]
    fn windows_local_path_allowance_is_applied_before_url_parsing() {
        let allowances = ResolverAllowances {
            allow_local_path: true,
            ..Default::default()
        };
        assert!(validate_requirement("C:/pkg", &allowances).is_ok());
        assert!(validate_requirement("C:\\pkg", &allowances).is_ok());
    }

    #[test]
    fn existing_cwd_path_treated_as_local() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("evil-1.0.tar.gz");
        std::fs::write(&archive, b"sdist").unwrap();
        let def = ResolverAllowances::default();
        // The absolute path to an existing file is a local path -> refused.
        let spec = archive.display().to_string();
        assert!(matches!(
            validate_requirement(&spec, &def),
            Err(ResolverError::RejectedRequirement { .. })
        ));
    }

    #[test]
    fn control_chars_and_options_refused() {
        let def = ResolverAllowances::default();
        assert!(validate_requirement("requests\n--index-url http://evil", &def).is_err());
        assert!(validate_requirement("-r other.txt", &def).is_err());
        assert!(validate_requirement("--pre", &def).is_err());
        assert!(validate_requirement("", &def).is_err());
    }

    // ---- index url validation ---------------------------------------------

    #[test]
    fn index_url_requires_https_and_public() {
        // Plain HTTP refused.
        assert!(validate_index_url("http://example.com/simple").is_err());
        // Loopback refused.
        assert!(validate_index_url("https://127.0.0.1/simple").is_err());
        assert!(validate_index_url("https://localhost/simple").is_err());
        // Cloud metadata refused.
        assert!(validate_index_url("https://169.254.169.254/simple").is_err());
        // Embedded credentials refused with the precise message.
        let err = validate_index_url("https://user:pass@example.com/simple").unwrap_err();
        match err {
            ResolverError::RejectedIndexUrl { reason, .. } => {
                assert!(reason.contains("credentials"), "{reason}");
            }
            other => panic!("expected RejectedIndexUrl, got {other:?}"),
        }
    }

    #[test]
    fn index_url_public_https_accepted() {
        // Syntax preflight performs no DNS or network I/O. Connect-time public
        // address validation belongs exclusively to the broker.
        assert!(validate_index_url("https://pypi.org/simple").is_ok());
    }

    #[test]
    fn private_ipv6_literal_is_rejected_in_effect_free_preflight() {
        let request = ResolverRequest {
            requirements: vec!["example==1.0".to_string()],
            index_urls: vec!["https://[::1]/simple".to_string()],
            allowances: ResolverAllowances::default(),
        };
        assert!(matches!(
            validate_resolver_request(&request),
            Err(ResolverError::RejectedIndexUrl { .. })
        ));
    }

    // ---- resolver-tool enrollment ------------------------------------------

    #[cfg(unix)]
    #[test]
    fn resolver_tool_enrollment_pin_binds_canonical_path_and_digest() {
        let mut environment = GlobalStateGuard::new().expect("isolate resolver enrollment");
        let host_home = environment
            .previous_env("HOME")
            .expect("resolver enrollment test requires the pre-guard HOME")
            .to_os_string();
        let root = tempfile::Builder::new()
            .prefix("tirith-resolver-enrollment-")
            .tempdir_in(PathBuf::from(host_home))
            .unwrap();
        environment.set_env("XDG_CONFIG_HOME", root.path());

        let tool_dir = root.path().join("tools");
        std::fs::create_dir(&tool_dir).unwrap();
        let tool = tool_dir.join("uv");
        write_fake_bin(&tool, "#!/bin/sh\nexit 0\n");
        let canonical = tool.canonicalize().unwrap();
        let digest = resolver_tool_digest(&canonical).unwrap();
        let trust_file = resolver_tool_trust_file().unwrap();
        std::fs::create_dir_all(trust_file.parent().unwrap()).unwrap();
        let mut store = ResolverToolTrustStore::default();
        store
            .pins
            .insert(resolver_tool_store_key(&canonical).unwrap(), digest);
        crate::util::write_file_atomic_0600(&trust_file, &serde_json::to_vec(&store).unwrap())
            .unwrap();

        assert!(resolver_tool_pin_matches(&canonical).unwrap());
        write_fake_bin(&canonical, "#!/bin/sh\nexit 7\n");
        assert!(!resolver_tool_pin_matches(&canonical).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn resolver_tool_admission_rejects_colliding_non_unicode_parent_paths() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        // Synthetic paths keep this regression portable to macOS filesystems
        // that reject invalid byte sequences at create-time. Linux and other
        // Unix filesystems can represent both paths exactly.
        let first = PathBuf::from(OsString::from_vec(b"/opt/install-\x80/python3".to_vec()));
        let second = PathBuf::from(OsString::from_vec(b"/opt/install-\x81/python3".to_vec()));

        assert_ne!(first, second);
        assert_eq!(
            first.display().to_string(),
            second.display().to_string(),
            "the regression requires two distinct paths that collide under Path::display"
        );
        for path in [&first, &second] {
            assert!(resolver_tool_store_key(path).is_err());
            let error = validate_resolver_tool_name("python", path).unwrap_err();
            assert!(error.contains("not valid Unicode"), "{error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn enrollment_rejects_insecure_existing_store_without_laundering_pins() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let _environment = ResolverEnrollmentTestEnv::new();
        // A root-managed helper reaches the trust-store validation seam on every
        // Unix platform. User-owned script uv fixtures are intentionally rejected
        // earlier by the executable-eligibility gate.
        let tool = PathBuf::from("/bin/sh");

        let trust_file = resolver_tool_trust_file().unwrap();
        std::fs::create_dir_all(trust_file.parent().unwrap()).unwrap();
        let mut attacker_store = ResolverToolTrustStore::default();
        attacker_store
            .pins
            .insert("/attacker/uv".to_string(), "00".repeat(32));
        let attacker_bytes = serde_json::to_vec_pretty(&attacker_store).unwrap();
        std::fs::write(&trust_file, &attacker_bytes).unwrap();
        std::fs::set_permissions(&trust_file, std::fs::Permissions::from_mode(0o666)).unwrap();

        let error = enroll_resolver_tool(&tool).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("owned by the current user and mode 0600"),
            "insecure pre-existing enrollment state must fail closed: {error}"
        );
        assert_eq!(
            std::fs::read(&trust_file).unwrap(),
            attacker_bytes,
            "rejected state must not be rewritten into a trusted file"
        );
        assert_ne!(
            std::fs::metadata(&trust_file).unwrap().mode() & 0o077,
            0,
            "rejected state must not be laundered to owner-only permissions"
        );
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn resolver_trust_directory_rejects_mutating_macos_acl() {
        let environment = GlobalStateGuard::new().expect("isolate resolver ACL environment");
        let host_home = environment
            .previous_env("HOME")
            .expect("resolver ACL test requires the pre-guard HOME")
            .to_os_string();
        let directory = tempfile::Builder::new()
            .prefix("tirith-resolver-acl-")
            .tempdir_in(PathBuf::from(host_home))
            .unwrap();
        let status = std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow write"])
            .arg(directory.path())
            .status()
            .unwrap();
        assert!(status.success(), "test must install a macOS extended ACL");

        let error = validate_resolver_trust_directory(directory.path()).unwrap_err();
        assert!(error.contains("ACL grants mutation"), "{error}");
    }

    // ---- fake executables (unix) -------------------------------------------

    /// Write a `0o755` shell-script "binary" at `path`. Mirrors the
    /// fake-binary pattern used elsewhere in the crate's subprocess tests.
    #[cfg(unix)]
    fn write_fake_bin(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt as _;
        let version_probe = match path.file_name().and_then(|name| name.to_str()) {
            Some("uv") => "if [ \"$1\" = \"--version\" ]; then echo 'uv 0.test'; exit 0; fi\n",
            Some(name) if name.starts_with("python") => {
                "if [ \"$1\" = \"-I\" ] && [ \"$2\" = \"-m\" ] && [ \"$3\" = \"pip\" ] && [ \"$4\" = \"--version\" ]; then echo 'pip 0.test'; exit 0; fi\n"
            }
            _ => "",
        };
        let rendered = match body.split_once('\n') {
            Some((shebang, rest)) if shebang.starts_with("#!") => {
                format!("{shebang}\n{version_probe}{rest}")
            }
            _ => format!("{version_probe}{body}"),
        };
        std::fs::write(path, rendered).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    struct ResolverEnrollmentTestEnv {
        _root: tempfile::TempDir,
        _environment: GlobalStateGuard,
    }

    #[cfg(unix)]
    impl ResolverEnrollmentTestEnv {
        fn new() -> Self {
            let mut environment =
                GlobalStateGuard::new().expect("isolate resolver public API environment");
            let host_home = environment
                .previous_env("HOME")
                .expect("resolver public API test requires the pre-guard HOME")
                .to_os_string();
            let root = tempfile::Builder::new()
                .prefix("tirith-resolver-public-api-")
                .tempdir_in(PathBuf::from(host_home))
                .unwrap();
            environment.set_env("XDG_CONFIG_HOME", root.path().join("config"));
            Self {
                _root: root,
                _environment: environment,
            }
        }
    }

    #[test]
    fn resolver_request_single_is_locked_down() {
        let r = ResolverRequest::single("requests==2.31.0");
        assert_eq!(r.requirements, vec!["requests==2.31.0".to_string()]);
        assert!(r.index_urls.is_empty());
        assert_eq!(r.allowances, ResolverAllowances::default());
        // The default allowances refuse everything dangerous.
        assert!(!r.allowances.allow_vcs);
        assert!(!r.allowances.allow_editable);
        assert!(!r.allowances.allow_local_path);
        assert!(!r.allowances.allow_direct_url);
    }

    #[test]
    fn editable_target_extraction_matches_pips_attached_form() {
        // pip's requirements parser is optparse-backed, so the attached form is
        // standard and `-e./pkg` is legitimate input. Both classifiers share one
        // helper so they cannot disagree about what the resolver child will do.
        assert_eq!(editable_requirement_target("-e"), Some(""));
        assert_eq!(editable_requirement_target("-e demo"), Some(" demo"));
        assert_eq!(editable_requirement_target("-e=demo"), Some("=demo"));
        assert_eq!(editable_requirement_target("-e./pkg"), Some("./pkg"));
        assert_eq!(
            editable_requirement_target("--editable=demo"),
            Some("=demo")
        );
        assert_eq!(editable_requirement_target("-r other.txt"), None);
        assert_eq!(editable_requirement_target("--index-url x"), None);

        // The extracted target is still re-validated, so an editable allowance
        // does not bypass the direct-URL / local-path controls.
        let denied = ResolverAllowances::default();
        assert!(
            validate_requirement("-e ./pkg", &denied).is_err(),
            "without allow_editable every -e form is refused"
        );
    }
}
