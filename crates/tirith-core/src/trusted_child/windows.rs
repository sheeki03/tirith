//! Windows implementation for trusted executable validation and child ownership.
//!
//! Selection validates the executable and its ancestor ACL/owner chain, performs
//! offline Authenticode verification, and feeds those facts into the pure policy
//! in the parent module. Execution assigns a suspended private handle-container
//! process to a kill-on-close Job Object, then creates the real process suspended
//! with that container as its parent and an exact inherited-handle list. The real
//! process is resumed only after its inherited Job membership is verified.

use super::{
    evaluate_windows_trust, spawn_reader, windows_access_mask_grants_replacement, CaptureState,
    CaptureStream, ChildOutcome, ChildSpec, ReaderMessage, WindowsExecutableSource,
    WindowsOwnerClass, WindowsTrustFacts, WindowsTrustProvenance,
};
use std::ffi::{c_void, OsStr};
use std::fs::File;
use std::mem::{size_of, ManuallyDrop};
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{FromRawHandle as _, RawHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, LocalFree, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS,
    ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE,
    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetAce, GetLengthSid, GetTokenInformation, IsValidAcl,
    IsValidSid, TokenUser, WinBuiltinAdministratorsSid, WinCreatorOwnerRightsSid,
    WinCreatorOwnerSid, WinLocalSystemSid, ACE_HEADER, ACE_INHERITED_OBJECT_TYPE_PRESENT,
    ACE_OBJECT_TYPE_PRESENT, ACL, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE,
    OWNER_SECURITY_INFORMATION, PSID, SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
    JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess,
    InitializeProcThreadAttributeList, OpenProcessToken, ResumeThread, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
};

/// Bounded post-termination verification allowance. The runtime deadline never
/// turns into an unbounded cleanup wait; failure to empty the Job within this
/// allowance becomes `CleanupError`, or `cleanup_succeeded: false` for the
/// structured timeout/output-limit outcomes.
const CLEANUP_WAIT: Duration = Duration::from_secs(2);

pub(super) fn path_is_within(path: &Path, root: &Path) -> bool {
    let mut path_components = path.components();
    for root_component in root.components() {
        let Some(path_component) = path_components.next() else {
            return false;
        };
        if !os_str_eq_ignore_case(path_component.as_os_str(), root_component.as_os_str()) {
            return false;
        }
    }
    true
}

fn os_str_eq_ignore_case(left: &OsStr, right: &OsStr) -> bool {
    let left = left.encode_wide().collect::<Vec<_>>();
    let right = right.encode_wide().collect::<Vec<_>>();
    let Ok(left_len) = i32::try_from(left.len()) else {
        return false;
    };
    let Ok(right_len) = i32::try_from(right.len()) else {
        return false;
    };
    // SAFETY: both buffers remain live for their explicit lengths; no NUL is required.
    unsafe {
        CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) == CSTR_EQUAL
    }
}

pub(super) fn validate_executable(
    path: &Path,
    source: WindowsExecutableSource,
) -> Result<WindowsTrustProvenance, String> {
    let native_image = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| {
            extension.eq_ignore_ascii_case("exe") || extension.eq_ignore_ascii_case("com")
        })
        .unwrap_or(false);
    if !native_image {
        return Err(
            "trusted Windows children must be native .exe/.com images; batch/script launchers are not executed through an ambient shell"
                .to_string(),
        );
    }
    let current_user = current_user_sid()?;
    let trusted_installer =
        string_sid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")?;
    let local_system = well_known_sid(WinLocalSystemSid)?;
    let administrators = well_known_sid(WinBuiltinAdministratorsSid)?;
    let creator_owner = well_known_sid(WinCreatorOwnerSid)?;
    let owner_rights = well_known_sid(WinCreatorOwnerRightsSid)?;
    let approved_writers = [
        current_user.sid(),
        local_system.sid(),
        administrators.sid(),
        trusted_installer.sid(),
        creator_owner.sid(),
        owner_rights.sid(),
    ];

    let mut broad_write_access = false;
    let mut owner_chain_trusted = true;
    let mut leaf_owner = WindowsOwnerClass::Other;
    let mut first = true;
    for component in ancestor_chain(path) {
        let security = path_security(&component, first, &approved_writers)?;
        if security.broad_write_access {
            broad_write_access = true;
        }
        let owner = classify_owner(
            security.owner,
            current_user.sid(),
            local_system.sid(),
            administrators.sid(),
            trusted_installer.sid(),
        );
        if first {
            leaf_owner = owner;
            first = false;
        }
        if owner == WindowsOwnerClass::Other {
            owner_chain_trusted = false;
        }
    }

    let protected_install_root = protected_roots()
        .iter()
        .any(|root| path_is_within(path, root));
    let secure_user_install = owner_chain_trusted
        && matches!(
            leaf_owner,
            WindowsOwnerClass::CurrentUser
                | WindowsOwnerClass::LocalSystem
                | WindowsOwnerClass::Administrators
                | WindowsOwnerClass::TrustedInstaller
        );
    let facts = WindowsTrustFacts {
        broad_write_access,
        leaf_owner,
        owner_chain_trusted,
        secure_user_install,
        protected_install_root,
        authenticode_trusted: authenticode_trusted(path)?,
    };
    evaluate_windows_trust(source, facts).map_err(str::to_string)
}

/// PATH inherited by a trusted child can itself select DLLs, interpreter
/// helpers, and nested tools. Keep only directories whose directory entry and
/// ancestor chain cannot be replaced by broad principals and whose owners are
/// recognized provenance principals.
pub(super) fn validate_inherited_path_dir(path: &Path) -> bool {
    let Ok(current_user) = current_user_sid() else {
        return false;
    };
    let Ok(trusted_installer) =
        string_sid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
    else {
        return false;
    };
    let Ok(local_system) = well_known_sid(WinLocalSystemSid) else {
        return false;
    };
    let Ok(administrators) = well_known_sid(WinBuiltinAdministratorsSid) else {
        return false;
    };
    let Ok(creator_owner) = well_known_sid(WinCreatorOwnerSid) else {
        return false;
    };
    let Ok(owner_rights) = well_known_sid(WinCreatorOwnerRightsSid) else {
        return false;
    };
    let approved_writers = [
        current_user.sid(),
        local_system.sid(),
        administrators.sid(),
        trusted_installer.sid(),
        creator_owner.sid(),
        owner_rights.sid(),
    ];

    for (index, component) in ancestor_chain(path).into_iter().enumerate() {
        let Ok(security) = path_security(&component, index == 0, &approved_writers) else {
            return false;
        };
        if security.broad_write_access
            || classify_owner(
                security.owner,
                current_user.sid(),
                local_system.sid(),
                administrators.sid(),
                trusted_installer.sid(),
            ) == WindowsOwnerClass::Other
        {
            return false;
        }
    }
    true
}

fn ancestor_chain(path: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut cursor = Some(path);
    while let Some(current) = cursor {
        paths.push(current.to_path_buf());
        cursor = current.parent().filter(|parent| *parent != current);
    }
    paths
}

fn protected_roots() -> Vec<PathBuf> {
    [
        "SystemRoot",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
    ]
    .into_iter()
    .filter_map(std::env::var_os)
    .filter_map(|value| PathBuf::from(value).canonicalize().ok())
    .collect()
}

struct PathSecurity {
    descriptor: *mut c_void,
    owner: PSID,
    broad_write_access: bool,
}

impl Drop for PathSecurity {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            // SAFETY: GetNamedSecurityInfoW allocated this descriptor with LocalAlloc.
            unsafe {
                let _ = LocalFree(self.descriptor);
            }
        }
    }
}

fn path_security(
    path: &Path,
    leaf: bool,
    approved_writers: &[PSID],
) -> Result<PathSecurity, String> {
    let wide = wide_nul(path.as_os_str())?;
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    // SAFETY: all out-pointers are valid for the call and `wide` is NUL-terminated.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "GetNamedSecurityInfoW failed for {}: Windows error {status}",
            path.display()
        ));
    }
    if descriptor.is_null() || owner.is_null() {
        if !descriptor.is_null() {
            // SAFETY: descriptor came from GetNamedSecurityInfoW.
            unsafe {
                let _ = LocalFree(descriptor);
            }
        }
        return Err(format!(
            "{} has no usable owner security descriptor",
            path.display()
        ));
    }
    // A null DACL grants everyone full access.
    let mut security = PathSecurity {
        descriptor,
        owner,
        broad_write_access: dacl.is_null(),
    };
    if !dacl.is_null() {
        security.broad_write_access = acl_has_untrusted_writer(dacl, leaf, approved_writers)?;
    }
    Ok(security)
}

fn acl_has_untrusted_writer(
    dacl: *const ACL,
    leaf: bool,
    approved_writers: &[PSID],
) -> Result<bool, String> {
    // SAFETY: DACL came from GetNamedSecurityInfoW and remains descriptor-owned.
    if unsafe { IsValidAcl(dacl) } == 0 {
        return Err("invalid executable path DACL".to_string());
    }
    // SAFETY: DACL came from the live security descriptor owned by PathSecurity.
    let ace_count = unsafe { (*dacl).AceCount } as u32;
    for index in 0..ace_count {
        let mut raw_ace = null_mut();
        // SAFETY: index is bounded by the ACL's own AceCount.
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(format!(
                "GetAce({index}) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: GetAce returned a pointer to an ACE_HEADER in the live DACL.
        let header = unsafe { &*(raw_ace.cast::<ACE_HEADER>()) };
        if (header.AceSize as usize) < size_of::<ACE_HEADER>() {
            return Err("truncated ACE header in executable path DACL".to_string());
        }
        if (header.AceFlags as u32) & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        let Some((mask, sid)) = allowed_ace_mask_and_sid(raw_ace, header)? else {
            continue;
        };
        if windows_access_mask_grants_replacement(mask, leaf)
            && !approved_writers
                .iter()
                .any(|approved| sid_eq(sid, *approved))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn allowed_ace_mask_and_sid(
    raw_ace: *mut c_void,
    header: &ACE_HEADER,
) -> Result<Option<(u32, PSID)>, String> {
    let ace_type = header.AceType as u32;
    match ace_type {
        ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {
            simple_allowed_ace_mask_and_sid(raw_ace, header).map(Some)
        }
        ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
            object_allowed_ace_mask_and_sid(raw_ace, header).map(Some)
        }
        // ACCESS_ALLOWED_COMPOUND_ACE_TYPE. The obsolete compound representation
        // is not expected on filesystem DACLs and has different SID semantics;
        // fail closed instead of accidentally approving it.
        4 => Err("unsupported compound allow ACE in executable path DACL".to_string()),
        // Known deny, audit, alarm, mandatory-label, resource-attribute,
        // scoped-policy, process-trust, and access-filter ACEs do not grant DACL
        // write authority by themselves.
        1..=3 | 6..=8 | 10 | 12..=21 => Ok(None),
        // Future/unknown ACE formats fail closed; never guess that a new type is
        // non-granting at an executable boundary.
        other => Err(format!(
            "unsupported ACE type {other} in executable path DACL"
        )),
    }
}

fn simple_allowed_ace_mask_and_sid(
    raw_ace: *mut c_void,
    header: &ACE_HEADER,
) -> Result<(u32, PSID), String> {
    let bytes = raw_ace.cast::<u8>();
    let sid_offset = size_of::<ACE_HEADER>() + size_of::<u32>();
    if (header.AceSize as usize) < sid_offset {
        return Err("truncated simple allow ACE".to_string());
    }
    // SAFETY: mask fits by the size check; read permits any alignment.
    let mask: u32 = unsafe { std::ptr::read_unaligned(bytes.add(size_of::<ACE_HEADER>()).cast()) };
    Ok((
        mask,
        checked_ace_sid(bytes, header.AceSize as usize, sid_offset)?,
    ))
}

fn object_allowed_ace_mask_and_sid(
    raw_ace: *mut c_void,
    header: &ACE_HEADER,
) -> Result<(u32, PSID), String> {
    let bytes = raw_ace.cast::<u8>();
    // ACCESS_ALLOWED_*_OBJECT_ACE begins ACE_HEADER, Mask, Flags, optional
    // ObjectType GUID, optional InheritedObjectType GUID, then the SID.
    let fixed = size_of::<ACE_HEADER>() + size_of::<u32>() + size_of::<u32>();
    if (header.AceSize as usize) < fixed {
        return Err("truncated object allow ACE".to_string());
    }
    // SAFETY: fixed fields fit by the AceSize check; reads permit any alignment.
    let mask = unsafe { std::ptr::read_unaligned(bytes.add(size_of::<ACE_HEADER>()).cast()) };
    let flags: u32 = unsafe {
        std::ptr::read_unaligned(bytes.add(size_of::<ACE_HEADER>() + size_of::<u32>()).cast())
    };
    let mut sid_offset = fixed;
    if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
        sid_offset += size_of::<windows_sys::core::GUID>();
    }
    if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
        sid_offset += size_of::<windows_sys::core::GUID>();
    }
    Ok((
        mask,
        checked_ace_sid(bytes, header.AceSize as usize, sid_offset)?,
    ))
}

fn checked_ace_sid(bytes: *mut u8, ace_size: usize, sid_offset: usize) -> Result<PSID, String> {
    const SID_FIXED_BYTES: usize = 8;
    if sid_offset.saturating_add(SID_FIXED_BYTES) > ace_size {
        return Err("truncated allow ACE SID".to_string());
    }
    // SID layout starts Revision, SubAuthorityCount, six-byte IdentifierAuthority.
    // SAFETY: the fixed SID prefix fits by the check above.
    let subauthority_count = unsafe { *bytes.add(sid_offset + 1) } as usize;
    let sid_bytes = SID_FIXED_BYTES
        .checked_add(
            subauthority_count
                .checked_mul(size_of::<u32>())
                .ok_or_else(|| "allow ACE SID length overflow".to_string())?,
        )
        .ok_or_else(|| "allow ACE SID length overflow".to_string())?;
    if sid_offset.saturating_add(sid_bytes) > ace_size {
        return Err("allow ACE SID extends beyond AceSize".to_string());
    }
    // SAFETY: the entire SID representation is within the ACE.
    let sid: PSID = unsafe { bytes.add(sid_offset).cast() };
    if unsafe { IsValidSid(sid) } == 0 || unsafe { GetLengthSid(sid) } as usize != sid_bytes {
        return Err("invalid allow ACE SID".to_string());
    }
    Ok(sid)
}

fn classify_owner(
    owner: PSID,
    current_user: PSID,
    local_system: PSID,
    administrators: PSID,
    trusted_installer: PSID,
) -> WindowsOwnerClass {
    if sid_eq(owner, current_user) {
        WindowsOwnerClass::CurrentUser
    } else if sid_eq(owner, local_system) {
        WindowsOwnerClass::LocalSystem
    } else if sid_eq(owner, administrators) {
        WindowsOwnerClass::Administrators
    } else if sid_eq(owner, trusted_installer) {
        WindowsOwnerClass::TrustedInstaller
    } else {
        WindowsOwnerClass::Other
    }
}

fn sid_eq(left: PSID, right: PSID) -> bool {
    !left.is_null() && !right.is_null() && unsafe { EqualSid(left, right) } != 0
}

struct SidBuffer {
    words: Vec<usize>,
    sid: PSID,
}

impl SidBuffer {
    fn sid(&self) -> PSID {
        let _keep_alive = &self.words;
        self.sid
    }
}

fn well_known_sid(sid_type: i32) -> Result<SidBuffer, String> {
    let word_count = SECURITY_MAX_SID_SIZE as usize / size_of::<usize>() + 1;
    let mut words = vec![0usize; word_count];
    let mut size = (words.len() * size_of::<usize>()) as u32;
    let sid = words.as_mut_ptr().cast();
    // SAFETY: the aligned buffer is at least SECURITY_MAX_SID_SIZE bytes.
    if unsafe { CreateWellKnownSid(sid_type, null_mut(), sid, &mut size) } == 0 {
        return Err(format!(
            "CreateWellKnownSid failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(SidBuffer { words, sid })
}

struct LocalSid(PSID);

impl LocalSid {
    fn sid(&self) -> PSID {
        self.0
    }
}

impl Drop for LocalSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: ConvertStringSidToSidW allocated this SID with LocalAlloc.
            unsafe {
                let _ = LocalFree(self.0);
            }
        }
    }
}

fn string_sid(value: &str) -> Result<LocalSid, String> {
    let wide = wide_nul(OsStr::new(value))?;
    let mut sid = null_mut();
    // SAFETY: `wide` is NUL-terminated and sid is a valid out-pointer.
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 {
        return Err(format!(
            "ConvertStringSidToSidW failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(LocalSid(sid))
}

fn current_user_sid() -> Result<SidBuffer, String> {
    let mut token = null_mut();
    // SAFETY: token is a valid out-pointer; pseudo-process handle is valid.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(format!(
            "OpenProcessToken failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let token = OwnedHandle(token);
    let mut needed = 0u32;
    // SAFETY: first call intentionally supplies no buffer to obtain its size.
    let first = unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed) };
    if first != 0
        || std::io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
    {
        return Err("GetTokenInformation did not return the required size".to_string());
    }
    let word_count = needed as usize / size_of::<usize>() + 1;
    let mut words = vec![0usize; word_count];
    // SAFETY: the aligned buffer is `needed` bytes and TOKEN_USER is its prefix.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            words.as_mut_ptr().cast(),
            (words.len() * size_of::<usize>()) as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(format!(
            "GetTokenInformation failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful TokenUser query initialized a TOKEN_USER prefix.
    let sid = unsafe { (*(words.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    Ok(SidBuffer { words, sid })
}

fn authenticode_trusted(path: &Path) -> Result<bool, String> {
    let wide = wide_nul(path.as_os_str())?;
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: null_mut(),
        pgKnownSubject: null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: null_mut(),
        pSIPClientData: null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: null_mut(),
        pwszURLReference: null_mut(),
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
        dwUIContext: 0,
        pSignatureSettings: null_mut(),
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: data points to live file info and both wide path/action outlive calls.
    let result = unsafe {
        WinVerifyTrust(
            null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: closes any state created by the verify call; return is diagnostic only.
    unsafe {
        let _ = WinVerifyTrust(
            null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        );
    }
    Ok(result == 0)
}

/// Rewrite a canonical `\\?\C:\...` directory as the plain `C:\...` form.
/// Only the prefix changes: the directory the child receives is the same one
/// the ACL and ownership checks above accepted.
fn dos_directory_for_child(path: &Path) -> PathBuf {
    use std::path::{Component, Prefix};

    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return path.to_path_buf();
    };
    match prefix.kind() {
        Prefix::VerbatimDisk(letter) => {
            let mut rebuilt = PathBuf::from(format!("{}:\\", letter as char));
            rebuilt.extend(components.filter(|component| !matches!(component, Component::RootDir)));
            rebuilt
        }
        // Verbatim UNC and device paths have no DOS equivalent to fall back to,
        // and a plain DOS prefix is already what the child wants.
        _ => path.to_path_buf(),
    }
}

pub(super) fn run(executable: &super::TrustedExecutable, spec: &ChildSpec) -> ChildOutcome {
    let mut child = match WindowsChild::launch(executable.path(), spec) {
        Ok(child) => child,
        Err(error) => return ChildOutcome::SpawnError(error),
    };
    let (sender, receiver) = mpsc::channel();
    let mut reader_workers = Vec::with_capacity(2);
    reader_workers.push((
        CaptureStream::Stdout,
        spawn_reader(
            child.stdout.take().expect("launched child owns stdout"),
            CaptureStream::Stdout,
            spec.limits.stdout_bytes,
            sender.clone(),
        ),
    ));
    reader_workers.push((
        CaptureStream::Stderr,
        spawn_reader(
            child.stderr.take().expect("launched child owns stderr"),
            CaptureStream::Stderr,
            spec.limits.stderr_bytes,
            sender,
        ),
    ));

    let deadline = Instant::now() + spec.limits.timeout;
    let mut capture = CaptureState::default();
    loop {
        while let Ok(message) = receiver.try_recv() {
            let cause = match &message {
                ReaderMessage::Complete(..) => None,
                ReaderMessage::Limit(stream) => Some(WindowsFinishCause::OutputLimit(*stream)),
                ReaderMessage::Error(stream, reason) => {
                    Some(WindowsFinishCause::ReaderError(*stream, reason.clone()))
                }
            };
            if let Err(error) = capture.record(message) {
                return finish_windows_run(
                    WindowsFinishContext {
                        child: &mut child,
                        receiver: &receiver,
                        workers: &mut reader_workers,
                        capture: &mut capture,
                    },
                    WindowsFinishCause::WaitError(error),
                );
            }
            if let Some(cause) = cause {
                return finish_windows_run(
                    WindowsFinishContext {
                        child: &mut child,
                        receiver: &receiver,
                        workers: &mut reader_workers,
                        capture: &mut capture,
                    },
                    cause,
                );
            }
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                // The direct process has completed, but a Job descendant may
                // still own a captured pipe. Empty the Job immediately, then
                // drain and join both readers under one cleanup deadline.
                return finish_windows_run(
                    WindowsFinishContext {
                        child: &mut child,
                        receiver: &receiver,
                        workers: &mut reader_workers,
                        capture: &mut capture,
                    },
                    WindowsFinishCause::DirectExit(status),
                );
            }
            Ok(None) => {}
            Err(error) => {
                return finish_windows_run(
                    WindowsFinishContext {
                        child: &mut child,
                        receiver: &receiver,
                        workers: &mut reader_workers,
                        capture: &mut capture,
                    },
                    WindowsFinishCause::WaitError(error),
                );
            }
        }
        if Instant::now() >= deadline {
            return finish_windows_run(
                WindowsFinishContext {
                    child: &mut child,
                    receiver: &receiver,
                    workers: &mut reader_workers,
                    capture: &mut capture,
                },
                WindowsFinishCause::Timeout,
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

enum WindowsFinishCause {
    DirectExit(std::process::ExitStatus),
    Timeout,
    OutputLimit(CaptureStream),
    ReaderError(CaptureStream, String),
    WaitError(String),
}

struct WindowsFinishContext<'a> {
    child: &'a mut WindowsChild,
    receiver: &'a mpsc::Receiver<ReaderMessage>,
    workers: &'a mut Vec<(CaptureStream, std::thread::JoinHandle<()>)>,
    capture: &'a mut CaptureState,
}

fn finish_windows_run(
    context: WindowsFinishContext<'_>,
    cause: WindowsFinishCause,
) -> ChildOutcome {
    let cleanup_deadline = Instant::now() + CLEANUP_WAIT;
    let tree_cleanup_succeeded = match &cause {
        WindowsFinishCause::DirectExit(_) => context.child.finish_completed_tree(cleanup_deadline),
        WindowsFinishCause::Timeout
        | WindowsFinishCause::OutputLimit(_)
        | WindowsFinishCause::ReaderError(..)
        | WindowsFinishCause::WaitError(_) => context.child.terminate_tree(cleanup_deadline),
    };
    let reader_cleanup = super::finish_reader_workers(
        context.receiver,
        context.workers,
        context.capture,
        cleanup_deadline,
    );
    let cleanup_succeeded = tree_cleanup_succeeded && reader_cleanup.is_ok();

    let output_limit = match &cause {
        WindowsFinishCause::OutputLimit(stream) => Some(*stream),
        _ => context.capture.first_limit(),
    };
    if let Some(stream) = output_limit {
        return ChildOutcome::OutputLimitExceeded {
            stream,
            cleanup_succeeded,
        };
    }
    if matches!(&cause, WindowsFinishCause::Timeout) {
        return ChildOutcome::Timeout { cleanup_succeeded };
    }

    if !cleanup_succeeded {
        let mut reasons = Vec::new();
        match &cause {
            WindowsFinishCause::ReaderError(stream, reason) => {
                reasons.push(format!("read {stream:?}: {reason}"));
            }
            WindowsFinishCause::WaitError(reason) => reasons.push(format!("wait failed: {reason}")),
            WindowsFinishCause::DirectExit(_)
            | WindowsFinishCause::Timeout
            | WindowsFinishCause::OutputLimit(_) => {}
        }
        if !tree_cleanup_succeeded {
            reasons.push("descendant Job cleanup failed".to_string());
        }
        if let Err(reason) = &reader_cleanup {
            reasons.push(reason.clone());
        }
        return ChildOutcome::CleanupError(reasons.join("; "));
    }

    match cause {
        WindowsFinishCause::ReaderError(stream, reason) => {
            return ChildOutcome::WaitError(format!("read {stream:?}: {reason}"));
        }
        WindowsFinishCause::WaitError(reason) => return ChildOutcome::WaitError(reason),
        WindowsFinishCause::DirectExit(status) => {
            if let Some((stream, reason)) = context.capture.first_error() {
                return ChildOutcome::WaitError(format!("read {stream:?}: {reason}"));
            }
            let Some((stdout, stderr)) = context.capture.take_completed() else {
                return ChildOutcome::CleanupError(
                    "capture workers completed without two bounded output buffers".to_string(),
                );
            };
            return ChildOutcome::Completed {
                status,
                stdout,
                stderr,
            };
        }
        WindowsFinishCause::Timeout | WindowsFinishCause::OutputLimit(_) => {}
    }
    ChildOutcome::CleanupError("Windows supervisor reached an invalid terminal state".to_string())
}

struct WindowsChild {
    job: OwnedHandle,
    process: OwnedHandle,
    // A suspended, never-resumed process is the private source table for the
    // child's inheritable handles. Keeping it in the same Job preserves a live
    // nominal parent until final tree cleanup without exposing inheritable
    // handles in this (potentially multi-threaded) Tirith process.
    _handle_container: OwnedHandle,
    stdout: Option<File>,
    stderr: Option<File>,
}

impl WindowsChild {
    fn launch(path: &Path, spec: &ChildSpec) -> Result<Self, String> {
        let application = wide_nul(path.as_os_str())?;
        let command_line =
            crate::capsule::windows::command_line_wide_from_parts(path.as_os_str(), &spec.args);
        let mut environment = environment_block(&spec.env)?;
        // Windows searches the current directory while loading DLLs. A caller-
        // selected working directory would therefore let an otherwise trusted
        // image load attacker-controlled code. None of the migrated callers
        // requires one, so fail closed instead of attempting to infer trust
        // from a directory ACL that may intentionally permit its owner to write.
        if spec.cwd.is_some() {
            return Err(
                "explicit Windows child cwd is disabled to prevent DLL search-path planting"
                    .to_string(),
            );
        }
        let cwd_path = path
            .parent()
            .ok_or_else(|| "trusted Windows executable has no parent directory".to_string())?
            .to_path_buf();
        if !validate_inherited_path_dir(&cwd_path) {
            return Err(format!(
                "Windows child cwd is not ACL/owner trusted: {}",
                cwd_path.display()
            ));
        }
        // The trusted path is canonical, so it carries the `\\?\` verbatim
        // prefix. CreateProcessW accepts that form, but a child that reads its
        // own working directory can reject it: cmd.exe refuses a UNC-looking
        // cwd, warns, and exits 1. Hand the child the equivalent DOS form.
        let cwd = wide_nul(dos_directory_for_child(&cwd_path).as_os_str())?;

        let job = configured_job()?;
        let helper =
            launch_suspended_handle_container(&application, &command_line, &mut environment, &cwd)?;
        // The real child will name this helper as its parent and therefore
        // inherit final Job membership atomically while still suspended.
        if unsafe { AssignProcessToJobObject(job.0, helper.process.0) } == 0 {
            let error = std::io::Error::last_os_error();
            let cleanup_succeeded = terminate_process_and_wait(helper.process.0);
            return Err(format!(
                "AssignProcessToJobObject(handle container) failed: {error}; suspended helper cleanup succeeded: {cleanup_succeeded}"
            ));
        }
        // From this point until the real CreateProcess call, every fallible
        // setup operation is guarded by bounded Job termination and a wait for
        // the suspended helper. This both future-proofs unwinding/early returns
        // and reports the cleanup result on each propagated setup error.
        let mut assigned_helper = AssignedSuspendedHelperGuard::new(job.0, helper.process.0);

        // These handles are deliberately non-inheritable in Tirith. Only
        // inheritable duplicates in the suspended helper can cross the process
        // boundary, preventing the reverse CreateProcess inheritance race.
        let (stdout_read, stdout_write) = assigned_helper.protect(local_pipe())?;
        let (stderr_read, stderr_write) = assigned_helper.protect(local_pipe())?;
        let stdin = assigned_helper.protect(local_null_input())?;
        let mut remote_handles = assigned_helper.protect(RemoteHandleSet::duplicate_into(
            helper.process.0,
            &[stdin.0, stdout_write.0, stderr_write.0],
        ))?;
        let mut inherited = assigned_helper.protect(remote_handles.as_array())?;
        let mut parent_process = helper.process.0;
        let mut attributes = assigned_helper.protect(
            ProcThreadAttributeList::with_handles_and_parent(&mut inherited, &mut parent_process),
        )?;

        // Only the private helper and, after CreateProcess, the actual child
        // retain write-side copies. The main process never marks these handles
        // inheritable, and closes its local copies before the launch window.
        drop(stdout_write);
        drop(stderr_write);
        drop(stdin);

        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = inherited[0];
        startup.StartupInfo.hStdOutput = inherited[1];
        startup.StartupInfo.hStdError = inherited[2];
        startup.lpAttributeList = attributes.as_ptr();
        let mut child_command_line = assigned_helper.protect(wide_nul_units(&command_line))?;
        let mut process_info = PROCESS_INFORMATION::default();
        // These bounded children communicate only through the three explicit
        // standard handles. Do not attach a console inherited from the nominal
        // parent: the handle container deliberately never initializes its DLLs
        // or console state. This also works when Tirith itself has no console.
        // https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
        // All remaining launch failures have explicit cleanup paths below.
        assigned_helper.disarm();
        // SAFETY: every pointer references a live NUL-terminated/mutable buffer;
        // the helper is the parent/handle source and remains suspended in `job`.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                child_command_line.as_mut_ptr(),
                null(),
                null(),
                1,
                CREATE_SUSPENDED
                    | CREATE_UNICODE_ENVIRONMENT
                    | CREATE_NO_WINDOW
                    | EXTENDED_STARTUPINFO_PRESENT,
                environment.as_mut_ptr().cast(),
                cwd.as_ptr(),
                &startup.StartupInfo,
                &mut process_info,
            )
        };
        if created == 0 {
            let error = std::io::Error::last_os_error();
            let cleanup_succeeded = terminate_job_members_and_wait(job.0, &[helper.process.0]);
            return Err(format!(
                "CreateProcessW failed: {}; handle-container cleanup succeeded: {cleanup_succeeded}",
                error,
            ));
        }
        let process = OwnedHandle(process_info.hProcess);
        let thread = OwnedHandle(process_info.hThread);

        // CreateProcess has copied the remote values into the child. Close every
        // helper-side duplicate now; DuplicateHandle(CLOSE_SOURCE) is the only
        // valid way to close a HANDLE value that belongs to another process.
        remote_handles.close_all();
        drop(attributes);

        let mut in_job = 0;
        // SAFETY: both process and Job handles are live and `in_job` is writable.
        let job_query = unsafe { IsProcessInJob(process.0, job.0, &mut in_job) };
        if job_query == 0 || in_job == 0 {
            let reason = if job_query == 0 {
                format!("IsProcessInJob failed: {}", std::io::Error::last_os_error())
            } else {
                "child did not inherit the handle container's Job".to_string()
            };
            let child_cleanup_succeeded = terminate_process_and_wait(process.0);
            let helper_cleanup_succeeded =
                terminate_job_members_and_wait(job.0, &[helper.process.0]);
            return Err(format!(
                "{reason}; suspended child cleanup succeeded: {child_cleanup_succeeded}; handle-container cleanup succeeded: {helper_cleanup_succeeded}"
            ));
        }

        // SAFETY: primary thread is still suspended and inherited the final Job.
        if unsafe { ResumeThread(thread.0) } == u32::MAX {
            let error = std::io::Error::last_os_error();
            let cleanup_succeeded =
                terminate_job_members_and_wait(job.0, &[process.0, helper.process.0]);
            return Err(format!(
                "ResumeThread failed: {error}; Job cleanup succeeded: {cleanup_succeeded}"
            ));
        }
        drop(thread);

        let SuspendedHandleContainer {
            process: helper_process,
            thread: helper_thread,
        } = helper;
        // Closing the helper thread handle does not resume it; the suspended
        // process remains alive in the Job as the child's nominal parent.
        drop(helper_thread);

        // SAFETY: ownership of each read HANDLE moves exactly once into File.
        let stdout = unsafe { File::from_raw_handle(stdout_read.into_raw() as RawHandle) };
        let stderr = unsafe { File::from_raw_handle(stderr_read.into_raw() as RawHandle) };
        Ok(Self {
            job,
            process,
            _handle_container: helper_process,
            stdout: Some(stdout),
            stderr: Some(stderr),
        })
    }

    fn try_wait(&self) -> Result<Option<std::process::ExitStatus>, String> {
        // SAFETY: process handle remains owned by self.
        match unsafe { WaitForSingleObject(self.process.0, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0u32;
                // SAFETY: code is a valid out-pointer and process has exited.
                if unsafe { GetExitCodeProcess(self.process.0, &mut code) } == 0 {
                    return Err(format!(
                        "GetExitCodeProcess failed: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                use std::os::windows::process::ExitStatusExt as _;
                Ok(Some(std::process::ExitStatus::from_raw(code)))
            }
            other => Err(format!(
                "WaitForSingleObject returned unexpected status {other:#x}: {}",
                std::io::Error::last_os_error()
            )),
        }
    }

    fn terminate_tree(&mut self, deadline: Instant) -> bool {
        if matches!(self.active_processes(), Ok(0)) {
            return true;
        }
        // SAFETY: job/process handles remain valid for both calls.
        let terminated = unsafe { TerminateJobObject(self.job.0, 1) } != 0;
        terminated && self.wait_for_empty_job(deadline)
    }

    fn finish_completed_tree(&mut self, deadline: Instant) -> bool {
        match self.active_processes() {
            Ok(0) => true,
            // A failed accounting query is not a reason to skip containment:
            // still attempt bounded Job termination, which independently
            // reports whether every member disappeared.
            Ok(_) | Err(_) => self.terminate_tree(deadline),
        }
    }

    fn wait_for_empty_job(&self, deadline: Instant) -> bool {
        loop {
            match self.active_processes() {
                Ok(0) => return true,
                Ok(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => return false,
            }
        }
    }

    fn active_processes(&self) -> Result<u32, ()> {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        // SAFETY: accounting is a valid buffer of the requested information class.
        if unsafe {
            QueryInformationJobObject(
                self.job.0,
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                null_mut(),
            )
        } == 0
        {
            Err(())
        } else {
            Ok(accounting.ActiveProcesses)
        }
    }
}

struct SuspendedHandleContainer {
    process: OwnedHandle,
    thread: OwnedHandle,
}

/// Covers the interval after the suspended helper enters the final Job and
/// before the real `CreateProcessW` call takes over with explicit failure paths.
/// A raw-handle guard is safe here because it is declared after, and therefore
/// dropped before, the owning helper and Job handles.
struct AssignedSuspendedHelperGuard {
    job: HANDLE,
    helper: HANDLE,
    armed: bool,
}

impl AssignedSuspendedHelperGuard {
    fn new(job: HANDLE, helper: HANDLE) -> Self {
        Self {
            job,
            helper,
            armed: true,
        }
    }

    fn protect<T>(&mut self, result: Result<T, String>) -> Result<T, String> {
        result.map_err(|error| {
            let cleanup_succeeded = self.cleanup();
            format!("{error}; suspended handle-container cleanup succeeded: {cleanup_succeeded}")
        })
    }

    fn cleanup(&mut self) -> bool {
        if !self.armed {
            return true;
        }
        self.armed = false;
        terminate_job_members_and_wait(self.job, &[self.helper])
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for AssignedSuspendedHelperGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.cleanup();
        }
    }
}

fn launch_suspended_handle_container(
    application: &[u16],
    command_line: &[u16],
    environment: &mut [u16],
    cwd: &[u16],
) -> Result<SuspendedHandleContainer, String> {
    let mut command_line = wide_nul_units(command_line)?;
    let startup = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..STARTUPINFOW::default()
    };
    let mut process_info = PROCESS_INFORMATION::default();
    // SAFETY: inputs are live NUL-terminated buffers. Inheritance is disabled,
    // and the primary thread cannot execute application code while suspended.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            0,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            environment.as_mut_ptr().cast(),
            cwd.as_ptr(),
            &startup,
            &mut process_info,
        )
    };
    if created == 0 {
        return Err(format!(
            "CreateProcessW(handle container) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(SuspendedHandleContainer {
        process: OwnedHandle(process_info.hProcess),
        thread: OwnedHandle(process_info.hThread),
    })
}

fn terminate_process_and_wait(process: HANDLE) -> bool {
    // Termination can report failure for an already-exited process, so the
    // bounded signaled-state check is the authoritative cleanup result.
    unsafe {
        let _ = TerminateProcess(process, 1);
        WaitForSingleObject(process, CLEANUP_WAIT.as_millis() as u32) == WAIT_OBJECT_0
    }
}

fn terminate_job_members_and_wait(job: HANDLE, processes: &[HANDLE]) -> bool {
    // All callers use this before the real child is resumed, so the listed
    // handles are the complete Job membership and no descendant can race in.
    unsafe {
        let _ = TerminateJobObject(job, 1);
    }
    processes.iter().all(|process| unsafe {
        WaitForSingleObject(*process, CLEANUP_WAIT.as_millis() as u32) == WAIT_OBJECT_0
    })
}

/// HANDLE values in this set are valid only in `process`'s handle table. They
/// must never be passed to local CloseHandle: DuplicateHandle with
/// DUPLICATE_CLOSE_SOURCE (or process termination) is the cleanup mechanism.
struct RemoteHandleSet {
    process: HANDLE,
    handles: Vec<HANDLE>,
}

impl RemoteHandleSet {
    fn duplicate_into(process: HANDLE, sources: &[HANDLE]) -> Result<Self, String> {
        let mut set = Self {
            process,
            handles: Vec::with_capacity(sources.len()),
        };
        for source in sources {
            let mut remote = null_mut();
            // SAFETY: source belongs to this process; target is the live,
            // suspended helper. The returned numeric value belongs to target.
            if unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    *source,
                    process,
                    &mut remote,
                    0,
                    1,
                    DUPLICATE_SAME_ACCESS,
                )
            } == 0
            {
                return Err(format!(
                    "DuplicateHandle into handle container failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            set.handles.push(remote);
        }
        Ok(set)
    }

    fn as_array(&self) -> Result<[HANDLE; 3], String> {
        if self.handles.len() != 3 {
            return Err("Windows child requires exactly three standard handles".to_string());
        }
        Ok([self.handles[0], self.handles[1], self.handles[2]])
    }

    fn close_all(&mut self) {
        for remote in self.handles.drain(..) {
            // SAFETY: `remote` is valid only in `process`. Microsoft documents
            // that CLOSE_SOURCE closes it regardless of the returned status.
            unsafe {
                let _ = DuplicateHandle(
                    self.process,
                    remote,
                    null_mut(),
                    null_mut(),
                    0,
                    0,
                    DUPLICATE_CLOSE_SOURCE,
                );
            }
        }
    }
}

impl Drop for RemoteHandleSet {
    fn drop(&mut self) {
        self.close_all();
    }
}

fn local_pipe() -> Result<(OwnedHandle, OwnedHandle), String> {
    let mut read = null_mut();
    let mut write = null_mut();
    // SAFETY: both handle out-pointers are valid. A null security descriptor
    // creates non-inheritable handles in this process.
    if unsafe { CreatePipe(&mut read, &mut write, null(), 0) } == 0 {
        // Defensive partial-initialization cleanup. The API normally leaves both
        // outputs null on failure, but neither non-null handle may leak.
        unsafe {
            if !read.is_null() {
                let _ = CloseHandle(read);
            }
            if !write.is_null() {
                let _ = CloseHandle(write);
            }
        }
        return Err(format!(
            "CreatePipe failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let read = OwnedHandle(read);
    let write = OwnedHandle(write);
    Ok((read, write))
}

fn local_null_input() -> Result<OwnedHandle, String> {
    let name = wide_nul(OsStr::new("NUL"))?;
    // SAFETY: `name` is NUL-terminated. Null security attributes make this
    // process's handle non-inheritable.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(format!(
            "open NUL failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(OwnedHandle(handle))
}

fn configured_job() -> Result<OwnedHandle, String> {
    // SAFETY: anonymous Job with default security.
    let job = unsafe { CreateJobObjectW(null(), null()) };
    if job.is_null() {
        return Err(format!(
            "CreateJobObjectW failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let job = OwnedHandle(job);
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: limits is fully initialized and sized for the requested class.
    if unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(format!(
            "SetInformationJobObject failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(job)
}

struct ProcThreadAttributeList {
    words: Vec<usize>,
}

impl ProcThreadAttributeList {
    fn with_handles_and_parent(
        handles: &mut [HANDLE],
        parent_process: &mut HANDLE,
    ) -> Result<Self, String> {
        let mut bytes = 0usize;
        // SAFETY: the documented sizing call uses a null list and writes bytes.
        unsafe {
            let _ = InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(format!(
                "InitializeProcThreadAttributeList sizing failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut words = vec![0usize; bytes / size_of::<usize>() + 1];
        let list: LPPROC_THREAD_ATTRIBUTE_LIST = words.as_mut_ptr().cast();
        // SAFETY: aligned buffer is at least `bytes` bytes.
        if unsafe { InitializeProcThreadAttributeList(list, 2, 0, &mut bytes) } == 0 {
            return Err(format!(
                "InitializeProcThreadAttributeList failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut attributes = Self { words };
        let list = attributes.as_ptr();
        // SAFETY: list is initialized and handles points to live HANDLE values.
        if unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(format!(
                "UpdateProcThreadAttribute(handle list) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: parent_process points to a live handle for a process with
        // PROCESS_CREATE_PROCESS access; both remain live through CreateProcess.
        if unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
                (parent_process as *mut HANDLE).cast(),
                size_of::<HANDLE>(),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(format!(
                "UpdateProcThreadAttribute(parent process) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(attributes)
    }

    fn as_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.words.as_mut_ptr().cast()
    }
}

impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        let list: LPPROC_THREAD_ATTRIBUTE_LIST = self.words.as_mut_ptr().cast();
        // SAFETY: constructors only return after successful initialization.
        unsafe { DeleteProcThreadAttributeList(list) };
    }
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn into_raw(self) -> HANDLE {
        let this = ManuallyDrop::new(self);
        this.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: handle is owned and closed exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

fn environment_block(env: &[(std::ffi::OsString, std::ffi::OsString)]) -> Result<Vec<u16>, String> {
    let mut entries = std::collections::BTreeMap::new();
    for (name, value) in env {
        let name = name
            .to_str()
            .ok_or_else(|| "Windows environment name is not Unicode".to_string())?;
        let value = value
            .to_str()
            .ok_or_else(|| "Windows environment value is not Unicode".to_string())?;
        if name.is_empty() || name.contains('=') || name.contains('\0') || value.contains('\0') {
            return Err("invalid Windows environment entry".to_string());
        }
        // Windows names are case-insensitive. Match Command's last-write-wins
        // behavior while preserving the most recent spelling.
        entries.insert(
            name.to_ascii_uppercase(),
            (name.to_string(), value.to_string()),
        );
    }
    let mut block = Vec::new();
    for (_, (name, value)) in entries {
        block.extend(OsStr::new(&format!("{name}={value}")).encode_wide());
        block.push(0);
    }
    block.push(0);
    if block.len() == 1 {
        block.push(0);
    }
    Ok(block)
}

fn wide_nul(value: &OsStr) -> Result<Vec<u16>, String> {
    let mut wide = value.encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err("Windows string contains an interior NUL".to_string());
    }
    wide.push(0);
    Ok(wide)
}

fn wide_nul_units(value: &[u16]) -> Result<Vec<u16>, String> {
    let mut wide = value.to_vec();
    if wide.contains(&0) {
        return Err("Windows string contains an interior NUL".to_string());
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};

    fn assert_not_inheritable(handle: HANDLE) {
        let mut flags = 0u32;
        // SAFETY: test owns a live handle and supplies a writable flags pointer.
        assert_ne!(unsafe { GetHandleInformation(handle, &mut flags) }, 0);
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
    }

    #[test]
    fn main_process_stdio_sources_are_never_inheritable() {
        let (read, write) = local_pipe().unwrap();
        let input = local_null_input().unwrap();

        assert_not_inheritable(read.0);
        assert_not_inheritable(write.0);
        assert_not_inheritable(input.0);
    }
}
